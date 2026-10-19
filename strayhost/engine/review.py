"""Every combination of records is decided by the LLM ("no merge without a reason").

Step 1 (links): records that share an identifier (asset ID, hostname, IP address) are
only *candidates*. The LLM is asked about each such pair of records, and only the pairs
it confirms are joined.
Step 2 (look-alikes): groups from step 1 with similar names (or no name and the same /24)
are asked about again, with a size cap of 2 groups per asset.

If the LLM is unsure, answers malformed, or a call fails, the records stay separate.
"""

from __future__ import annotations

import json
from collections import defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..data_io import get_identifiers_from_record
from . import matchers as _m
from .matchers import LLMCallBudget, Records, match_llm_adjudicated

LINK_RULES = """# Additional criteria for this batch (pairs of records with a matching identifier)
- In each pair, the two records share an asset ID, a hostname (ignoring letter case and the domain part)
  or an IP address.
- A matching asset ID, or an exact match of the normalised hostname, may on its own be judged the same
  asset unless an attribute clearly contradicts it (a different asset ID or instance ID, conflicting
  owning departments, etc.).
- A match of the IP address only: when the address of a device recorded in the ledger or EDR matches an
  address from the external scan, it may be judged the same asset if nothing contradicts it. However, a
  match on an IP listed under "Shared addresses" below is not sufficient evidence (several devices share
  it, for example through NAT). Without support from other attributes, judge as different assets.
- Shared addresses (IPs that appear on more than one record of the same list): {shared}
"""

MAX_FULL_CLIQUE = 5  # records sharing one identifier: all pairs up to this many, else a star


def identifier_links(records: Records, ids: List[str]) -> List[Tuple[int, int]]:
    index = {rid: k for k, rid in enumerate(ids)}
    by_value: Dict[str, List[str]] = defaultdict(list)
    for src, recs in records.items():
        for r in recs:
            for ident in get_identifiers_from_record(r, src):
                by_value[ident].append(r["_internal_id"])
    pairs: Set[Tuple[int, int]] = set()
    for members in by_value.values():
        members = sorted(set(members), key=lambda r: index[r])
        if len(members) < 2:
            continue
        if len(members) <= MAX_FULL_CLIQUE:
            it = combinations(members, 2)
        else:
            it = ((members[0], m) for m in members[1:])
        for a, b in it:
            i, j = index[a], index[b]
            pairs.add((min(i, j), max(i, j)))
    return sorted(pairs)


headers: List[Dict[str, Any]] = []


def _read_verdicts(path: Path, groups: List[Set[str]], step: str) -> List[Dict[str, Any]]:
    out = []
    if not path.exists():
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            if row.get("type") == "run_header":
                row["step"] = step
                headers.append(row)
                continue
            if row.get("type") != "verdict":
                continue
            row["step"] = step
            row["records_a"] = sorted(groups[row["cluster_i"]])
            row["records_b"] = sorted(groups[row["cluster_j"]])
            out.append(row)
    return out


def shared_addresses(records: Records) -> List[str]:
    """IPs that appear on more than one record of the same list (NAT, shared or reused)."""
    from .matchers import _IP_FIELD
    out = set()
    for src, recs in records.items():
        seen: Dict[str, int] = defaultdict(int)
        for r in recs:
            ip = (r.get(_IP_FIELD[src]) or "").strip()
            if ip:
                seen[ip] += 1
        out.update(ip for ip, n in seen.items() if n > 1)
    return sorted(out)


def match_all_by_llm(records: Records, llm_client: Any, out_dir: Path,
                     stats: Optional[Dict[str, Any]] = None) -> Tuple[List[Set[str]], List[Dict[str, Any]]]:
    """Return (final groups, every LLM verdict with the record IDs on each side)."""
    from .matchers import _resolve_audit_log_path

    stats = stats if stats is not None else {}
    ids = sorted((r["_internal_id"] for recs in records.values() for r in recs),
                 key=lambda x: (x.split("_")[0], int(x.split("_")[1])))
    singles = [{rid} for rid in ids]
    links = identifier_links(records, ids)

    p1 = _resolve_audit_log_path(out_dir / "llm_links.jsonl")
    p2 = _resolve_audit_log_path(out_dir / "llm_lookalikes.jsonl")
    for p in (p1, p2):
        if p.exists():
            p.unlink()
    budget = LLMCallBudget(max_calls=_m._resolve_max_llm_calls(None))  # one request budget for both steps
    cap = _m._resolve_max_candidate_pairs(None)
    if cap is not None and len(links) > cap:
        print(f"[warn] {len(links)} identifier links; only the first {cap} are asked (CAASM_LLM_MAX_CANDIDATES)")
        links = links[:cap]
    s1: Dict[str, Any] = {}
    shared = shared_addresses(records)
    _m.PROMPT_EXTRA = LINK_RULES.format(shared=", ".join(shared) if shared else "none")
    try:
        step1 = match_llm_adjudicated(records, llm_client=llm_client, base_groups=singles, candidate_pairs=links,
                                      size_cap="none", audit_log_path=out_dir / "llm_links.jsonl", stats=s1,
                                      call_budget=budget)
    finally:
        _m.PROMPT_EXTRA = ""
    verdicts = _read_verdicts(p1, singles, "link")
    s2: Dict[str, Any] = {}
    if s1.get("aborted"):
        final, step2_groups = step1, step1
    else:
        step2_groups = [set(g) for g in step1]
        final = match_llm_adjudicated(records, llm_client=llm_client, base_groups=step2_groups,
                                      audit_log_path=out_dir / "llm_lookalikes.jsonl", stats=s2, call_budget=budget)
        verdicts += _read_verdicts(p2, step2_groups, "lookalike")
    stats.update({"links_asked": len(links), "lookalikes_asked": s2.get("candidate_pairs", 0)})
    for k in ("aborted",):
        if s1.get(k) or s2.get(k):
            stats[k] = s1.get(k) or s2.get(k)
    # one combined audit file for users
    combined = _resolve_audit_log_path(out_dir / "llm_adjudications.jsonl")
    with open(combined, "w", encoding="utf-8") as f:
        for h in headers:
            f.write(json.dumps(h, ensure_ascii=False) + "\n")
        headers.clear()
        for v in verdicts:
            f.write(json.dumps(v, ensure_ascii=False) + "\n")
    for p in (p1, p2):
        if p.exists():
            p.unlink()
    return [set(g) for g in final], verdicts
