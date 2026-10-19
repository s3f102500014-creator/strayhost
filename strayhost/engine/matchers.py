"""Rule-based grouping plus LLM adjudication of look-alike groups (the LLM can only combine groups)."""

from __future__ import annotations

import hashlib
import json
import random
import os
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from .. import config
from ..data_io import normalize_hostname
from ..grouping import build_asset_groups
from ..llm_client import DailyQuotaExhaustedError, get_client
from . import merge_policy as mp
from ._text_utils import similarity_backend, similarity_ratio, subnet_24

Records = Dict[str, List[dict]]

_NAME_FIELD = {"ledger": "hostname", "edr": "asset_id_or_hostname", "asm": "domain"}
_IP_FIELD = {"ledger": "ip", "edr": "ip", "asm": "public_ip"}




def _build_id_info(records: Records) -> Dict[str, Dict[str, Optional[str]]]:
    info: Dict[str, Dict[str, Optional[str]]] = {}
    for source, recs in records.items():
        name_field = _NAME_FIELD.get(source)
        ip_field = _IP_FIELD.get(source)
        for rec in recs:
            name = normalize_hostname(rec.get(name_field)) if name_field else None
            ip = rec.get(ip_field) if ip_field else None
            info[rec["_internal_id"]] = {
                "name": name,
                "ip": ip,
                "subnet": subnet_24(ip),
                "dept": rec.get("owner_dept"),
                "source": source,
            }
    return info




_ADJUDICATION_PROMPT_SHARED_HEADER = """You are a security analyst specialising in entity resolution for IT asset management.
For each of the pairs listed below, decide whether record group A and record group B refer to
the same physical or logical asset. Apply the criteria to each pair separately.

# Background (what commonly happens in corporate IT asset data)
- IP addresses can change through DHCP reassignment or NAT. The public IP observed by ASM often
  does not match the internal IP recorded in the ledger or by EDR.
- Hostnames and FQDNs of the same asset can be written differently in different sources
  (letter case, with or without the domain part, separators, added suffixes or prefixes, truncation, etc.).
- Fields such as department, owner, IP and time can be missing. A missing value is in itself
  evidence neither for nor against the records being the same asset.
- After an asset's state changes, records with old information can remain without being updated.
- On the other hand, assets with very similar names can be different assets. Name similarity
  alone is not sufficient evidence of the same asset.

# Criteria
- Judge as the same asset when one of the identifiers (hostname, FQDN or domain name, asset ID or
  instance ID, IP address) corresponds, at least one other attribute (subnet, owning department or
  owner, communication peer, open ports, time, etc.) also supports the same asset, and no attribute
  clearly contradicts it. When the name is missing on one or both sides, apply the same criteria to
  the identifiers and attributes other than the name.
- Judge as different assets when attributes clearly contradict each other, or when there is no
  support for the same asset other than a single corresponding identifier (including name similarity).
- If the evidence is balanced and you cannot decide, judge as different assets (same_asset=false).
  A wrong merge makes a real shadow-IT finding disappear, which costs more in operation than a wrong
  split (one extra alert).
- In confidence, give your estimate of the probability that this judgement is correct, from 0.0 to 1.0.
"""

_ADJUDICATION_PROMPT_BATCH_TEMPLATE = (
    _ADJUDICATION_PROMPT_SHARED_HEADER
    + """
# Candidate pairs ({n_pairs})
For each pair in the JSON array below, decide whether record group A and record group B are the
same asset. pair_id identifies the input pair for the result; include each input pair_id exactly
once in the output (no omissions, no duplicates).

{pairs_json}

# Output format (strict. Output JSON only, with no other text. Include every pair_id above
# exactly once in the verdicts array; none may be missing)
{{
  "verdicts": [
    {{
      "pair_id": <the integer of the corresponding input pair>,
      "same_asset": true or false,
      "confidence": <confidence from 0.0 to 1.0, a number>,
      "evidence": "<a brief explanation of the reason for the judgement>"
    }}
  ]
}}
"""
)






def _batch_template() -> str:
    return _ADJUDICATION_PROMPT_BATCH_TEMPLATE


LLM_VIEW_SCHEMA: Dict[str, Tuple[str, ...]] = {
    "ledger": ("asset_id", "hostname", "ip", "fqdn", "instance_id", "owner_dept", "owner_user"),
    "edr": ("asset_id_or_hostname", "ip", "observed_at", "dest_ip", "dest_fqdn"),
    "asm": ("public_ip", "domain", "discovered_at", "open_ports", "vuln_score"),
}


def llm_view(rec: dict, source: Optional[str] = None) -> dict:
    public = {k: v for k, v in rec.items() if not str(k).startswith("_")}
    if source is None or source not in LLM_VIEW_SCHEMA:
        return public
    schema = LLM_VIEW_SCHEMA[source]
    # Only the documented columns are sent to the LLM; extra CSV columns are never sent.
    return {k: ("" if public.get(k) is None else public.get(k, "")) for k in schema}


def _records_for_ids(records: Records, ids: Sequence[str]) -> Dict[str, List[dict]]:
    id_set = set(ids)
    out: Dict[str, List[dict]] = defaultdict(list)
    for source, recs in records.items():
        for rec in recs:
            if rec["_internal_id"] in id_set:
                out[source].append(llm_view(rec, source))
    return dict(out)


def _is_rfc1918_24(subnet: Optional[str]) -> bool:
    if not subnet:
        return False
    p = subnet.split(".")
    if len(p) != 3 or not all(x.isdigit() for x in p):
        return False
    a, b = int(p[0]), int(p[1])
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)


def _generate_candidate_cluster_pairs(
    clusters: List[Set[str]],
    id_info: Dict[str, Dict[str, Optional[str]]],
    name_gray_low: float,
    max_pairs: int,
) -> List[Tuple[int, int]]:
    names = [{id_info[i]["name"] for i in c if id_info.get(i, {}).get("name")} for c in clusters]
    # Only internal (RFC 1918) /24s count: many unrelated Internet-facing hosts share a public /24.
    subnets = [{id_info[i]["subnet"] for i in c if _is_rfc1918_24(id_info.get(i, {}).get("subnet"))} for c in clusters]

    pairs: List[Tuple[float, int, int]] = []
    n = len(clusters)
    for i in range(n):
        for j in range(i + 1, n):
            best_sim = 0.0
            if names[i] and names[j]:
                best_sim = max(similarity_ratio(a, b) for a in names[i] for b in names[j])

            if best_sim >= name_gray_low:
                pairs.append((best_sim, i, j))
                continue

            subnet_overlap = bool(subnets[i] & subnets[j])
            missing_name_side = not names[i] or not names[j]
            if subnet_overlap and missing_name_side:
                pairs.append((0.0, i, j))

    pairs.sort(key=lambda t: -t[0])
    return [(i, j) for _, i, j in pairs[:max_pairs]]




DEFAULT_LLM_NAME_GRAY_LOW: float = 0.70


def _resolve_name_gray_low(explicit: Optional[float]) -> float:
    if explicit is not None:
        return explicit
    env_value = os.getenv(config.LLM_GRAY_LOW_ENV_VAR)
    if env_value is not None and env_value.strip() != "":
        return float(env_value)
    return DEFAULT_LLM_NAME_GRAY_LOW


DEFAULT_LLM_WORKERS: int = 8
_LLM_WORKERS_MIN: int = 1
_LLM_WORKERS_MAX: int = 32


def _resolve_llm_workers(explicit: Optional[int]) -> int:
    if explicit is not None:
        value = explicit
    else:
        env_value = os.getenv(config.LLM_WORKERS_ENV_VAR)
        value = int(env_value) if env_value is not None and env_value.strip() != "" else DEFAULT_LLM_WORKERS
    return max(_LLM_WORKERS_MIN, min(_LLM_WORKERS_MAX, value))


def _resolve_llm_batch_size(explicit: Optional[int]) -> int:
    if explicit is not None:
        value = explicit
    else:
        env_value = os.getenv(config.LLM_BATCH_SIZE_ENV_VAR)
        value = (
            int(env_value)
            if env_value is not None and env_value.strip() != ""
            else config.DEFAULT_LLM_BATCH_SIZE
        )
    return max(config.LLM_BATCH_SIZE_MIN, min(config.LLM_BATCH_SIZE_MAX, value))


DEFAULT_LLM_SIZE_CAP: int = 2


def _resolve_llm_size_cap(explicit: Optional[Union[int, str]]) -> Optional[int]:
    if explicit is not None:
        raw: Union[int, str] = explicit
    else:
        env_value = os.getenv(config.LLM_SIZE_CAP_ENV_VAR)
        raw = env_value if env_value is not None and env_value.strip() != "" else DEFAULT_LLM_SIZE_CAP

    if isinstance(raw, str) and raw.strip().lower() == "none":
        return None
    value = int(raw)
    if value == 0:
        return None
    if value < 0:
        raise ValueError(
            f"CAASM_LLM_SIZECAP must be an integer >= 0 or 'none' (got {value})"
        )
    return value


def _resolve_max_llm_calls(explicit: Optional[int]) -> Optional[int]:
    if explicit is not None:
        return explicit
    return config.resolve_llm_max_calls()


def _fatal_quota_error_label(reason: str) -> str:
    labels = {"spend_cap": "spending limit reached"}
    return labels.get(reason, "provider quota exhausted")


class LLMCallBudget:

    def __init__(self, max_calls: Optional[int] = None) -> None:
        self.max_calls = max_calls
        self._lock = threading.Lock()
        self._count = 0
        self.aborted_reason: Optional[str] = None

    def reserve(self) -> bool:
        with self._lock:
            if self.aborted_reason is not None:
                return False
            if self.max_calls is not None and self._count >= self.max_calls:
                self.aborted_reason = "max_calls"
                return False
            self._count += 1
            return True

    def mark_daily_quota_aborted(self, reason: str = "daily_quota") -> None:
        with self._lock:
            if self.aborted_reason is None:
                self.aborted_reason = reason

    @property
    def count(self) -> int:
        with self._lock:
            return self._count


_AUDIT_LOG_FILENAME = "llm_adjudications.jsonl"


def _resolve_audit_log_path(explicit: Optional[Path]) -> Path:
    path = explicit if explicit is not None else Path(_AUDIT_LOG_FILENAME)
    if config.is_mock_active():
        path = config.mock_suffixed_path(path)
    return path


def _pair_display_info(
    i: int, j: int, base_groups: List[Set[str]], id_info: Dict[str, Dict[str, Optional[str]]]
) -> Dict[str, Any]:
    names_i = sorted({id_info[x]["name"] for x in base_groups[i] if id_info.get(x, {}).get("name")})
    names_j = sorted({id_info[x]["name"] for x in base_groups[j] if id_info.get(x, {}).get("name")})
    sim = 0.0
    if names_i and names_j:
        sim = max(similarity_ratio(a, b) for a in names_i for b in names_j)
    return {"names_a": names_i, "names_b": names_j, "sim": sim}




def _audit_write(f: Any, **fields: Any) -> None:
    f.write(json.dumps(fields, ensure_ascii=False) + "\n")
    f.flush()




def _parse_single_verdict(result: Optional[Dict[str, Any]], confidence_threshold: float) -> Dict[str, Any]:
    same_asset_raw: Any = None
    confidence: Optional[float] = None
    evidence: Optional[str] = None
    should_merge = False

    if isinstance(result, dict):
        same_asset_raw = result.get("same_asset")
        evidence = result.get("evidence")
        raw_confidence = result.get("confidence", 0.0)
        try:
            confidence = float(raw_confidence)
        except (TypeError, ValueError):
            confidence = 0.0

        if same_asset_raw is True and confidence >= confidence_threshold:
            should_merge = True
    else:
        confidence = 0.0

    return {
        "same_asset": same_asset_raw,
        "confidence": confidence,
        "evidence": evidence,
        "should_merge": should_merge,
    }




def _build_batch_prompt(pairs: List[Tuple[int, int]], records: Records, base_groups: List[Set[str]]) -> str:
    pair_objs = []
    for local_pair_id, (i, j) in enumerate(pairs, start=1):
        group_a_records = _records_for_ids(records, base_groups[i])
        group_b_records = _records_for_ids(records, base_groups[j])
        pair_objs.append({"pair_id": local_pair_id, "group_a": group_a_records, "group_b": group_b_records})
    pairs_json = json.dumps(pair_objs, indent=2, ensure_ascii=False)
    text = _batch_template().format(n_pairs=len(pairs), pairs_json=pairs_json)
    if PROMPT_EXTRA:
        marker = "# Candidate pairs"
        text = text.replace(marker, PROMPT_EXTRA.rstrip() + "\n\n" + marker, 1)
    return text


#: Extra judging rules inserted before the pair list (set by engine.review for the link step).
PROMPT_EXTRA: str = ""


def _parse_batch_response(
    result: Any, expected_pair_ids: List[int], confidence_threshold: float
) -> Tuple[Dict[int, Dict[str, Any]], List[str]]:
    anomalies: List[str] = []
    parsed_by_id: Dict[int, Dict[str, Any]] = {}
    expected_set = set(expected_pair_ids)

    verdicts_raw: Any = None
    if isinstance(result, dict):
        verdicts_raw = result.get("verdicts")
    if not isinstance(verdicts_raw, list):
        anomalies.append(
            f"response is not of the form {{'verdicts': [...]}} (got {type(result).__name__}); "
            "all pairs in this batch are treated as different devices."
        )
        verdicts_raw = []

    for item in verdicts_raw:
        if not isinstance(item, dict):
            anomalies.append(f"verdict is not an object: {item!r}")
            continue
        raw_pair_id = item.get("pair_id")
        try:
            pair_id = int(raw_pair_id)
        except (TypeError, ValueError):
            anomalies.append(f"pair_id is not an integer: {raw_pair_id!r}")
            continue
        if pair_id not in expected_set:
            anomalies.append(f"unknown pair_id (not in this batch): {pair_id}")
            continue
        if pair_id in parsed_by_id:
            anomalies.append(f"duplicate pair_id={pair_id}; the first one is used.")
            continue

        parsed_by_id[pair_id] = _parse_single_verdict(item, confidence_threshold)

    for pair_id in expected_pair_ids:
        if pair_id not in parsed_by_id:
            anomalies.append(f"no verdict for pair_id={pair_id}; treated as different devices.")
            parsed_by_id[pair_id] = {
                "same_asset": False,
                "confidence": 0.0,
                "evidence": None,
                "should_merge": False,
                "missing_from_response": True,
            }

    return parsed_by_id, anomalies


def _adjudicate_batch(
    batch_id: int,
    indexed_pairs: List[Tuple[int, int, int]],
    records: Records,
    base_groups: List[Set[str]],
    id_info: Dict[str, Dict[str, Optional[str]]],
    client: Any,
    confidence_threshold: float,
    call_budget: "LLMCallBudget",
) -> List[Dict[str, Any]]:
    pairs = [(i, j) for (_gidx, i, j) in indexed_pairs]
    local_pair_ids = list(range(1, len(pairs) + 1))

    def _fallback_verdicts(error_message: Optional[str]) -> List[Dict[str, Any]]:
        out = []
        for (global_idx, i, j) in indexed_pairs:
            display = _pair_display_info(i, j, base_groups, id_info)
            out.append(
                {
                    "global_idx": global_idx,
                    "batch_id": batch_id,
                    "batch_size": len(indexed_pairs),
                    "i": i,
                    "j": j,
                    "names_a": display["names_a"],
                    "names_b": display["names_b"],
                    "sim": display["sim"],
                    "same_asset": None,
                    "confidence": 0.0,
                    "evidence": None,
                    "elapsed_s": 0.0,
                    "should_merge": False,
                    "error": error_message,
                }
            )
        return out

    if not call_budget.reserve():
        return _fallback_verdicts(
            "skipped: LLM request limit reached"
        )

    prompt = _build_batch_prompt(pairs, records, base_groups)
    batch_messages = [{"role": "user", "content": prompt}]

    call_start = time.perf_counter()
    error_message: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    try:
        result = client.chat_json(
            batch_messages,
            reasoning_effort=config.DEFAULT_REASONING_EFFORT,
        )
    except DailyQuotaExhaustedError as e:
        call_budget.mark_daily_quota_aborted(e.reason)
        error_message = f"[{_fatal_quota_error_label(e.reason)}] {e}"
    except Exception as e:
        error_message = str(e)
    elapsed_s_total = time.perf_counter() - call_start
    elapsed_s_per_pair = elapsed_s_total / len(pairs) if pairs else 0.0

    if error_message is not None:
        return _fallback_verdicts(error_message)

    parsed_by_id, anomalies = _parse_batch_response(result, local_pair_ids, confidence_threshold)
    if anomalies:
        for msg in anomalies:
            print(f"[WARN][llm-batch] batch_id={batch_id}: {msg}", file=sys.stderr)

    out: List[Dict[str, Any]] = []
    for local_pair_id, (global_idx, i, j) in zip(local_pair_ids, indexed_pairs):
        display = _pair_display_info(i, j, base_groups, id_info)
        parsed = parsed_by_id[local_pair_id]
        out.append(
            {
                "global_idx": global_idx,
                "batch_id": batch_id,
                "batch_size": len(indexed_pairs),
                "i": i,
                "j": j,
                "names_a": display["names_a"],
                "names_b": display["names_b"],
                "sim": display["sim"],
                "same_asset": parsed["same_asset"],
                "confidence": parsed["confidence"],
                "evidence": parsed["evidence"],
                "elapsed_s": elapsed_s_per_pair,
                "should_merge": parsed["should_merge"],
                "error": None,
                "missing_from_response": bool(parsed.get("missing_from_response", False)),
            }
        )
    return out




def match_llm_adjudicated(
    records: Records,
    llm_client: Any = None,
    name_gray_low: Optional[float] = None,
    max_candidate_pairs: Optional[Union[int, str]] = None,
    confidence_threshold: float = 0.5,
    stats: Optional[Dict[str, Any]] = None,
    audit_log_path: Optional[Path] = None,
    workers: Optional[int] = None,
    batch_size: Optional[int] = None,
    max_llm_calls: Optional[int] = None,
    call_budget: Optional["LLMCallBudget"] = None,
    size_cap: Optional[Union[int, str]] = None,
    base_groups: Optional[List[Set[str]]] = None,
    candidate_pairs: Optional[List[Tuple[int, int]]] = None,
) -> List[Set[str]]:
    """Ask the LLM about candidate pairs of groups and combine the pairs it confirms.

    base_groups: the starting groups (default: rule-based grouping). candidate_pairs:
    index pairs into base_groups to ask about (default: look-alike pairs)."""
    name_gray_low = _resolve_name_gray_low(name_gray_low)
    client = llm_client if llm_client is not None else get_client()
    if base_groups is None:
        base_groups = build_asset_groups(records)
    id_info = _build_id_info(records)
    n_workers = _resolve_llm_workers(workers)
    n_batch = _resolve_llm_batch_size(batch_size)
    if call_budget is None:
        call_budget = LLMCallBudget(max_calls=_resolve_max_llm_calls(max_llm_calls))

    max_candidate_pairs = _resolve_max_candidate_pairs(max_candidate_pairs)
    if candidate_pairs is None:
        candidate_idx_pairs = _generate_candidate_cluster_pairs(
            base_groups, id_info, name_gray_low, max_candidate_pairs
        )
    else:
        candidate_idx_pairs = [(min(i, j), max(i, j)) for i, j in candidate_pairs]
    n_candidates = len(candidate_idx_pairs)

    indexed_pairs = assign_batch_order(candidate_idx_pairs)
    batches = [indexed_pairs[k : k + n_batch] for k in range(0, n_candidates, n_batch)]
    n_requests_planned = len(batches)

    print(f"[llm] asking the LLM about {n_candidates} candidate pairs in {n_requests_planned} requests "
          f"(batch {n_batch}, {n_workers} workers)", file=sys.stderr, flush=True)

    audit_path = _resolve_audit_log_path(audit_log_path)
    audit_path.parent.mkdir(parents=True, exist_ok=True)

    resolved_size_cap = _resolve_llm_size_cap(size_cap)

    results: List[Optional[Dict[str, Any]]] = [None] * n_candidates
    progress_lock = threading.Lock()
    done_count = 0
    provisional_merge_count = 0
    cumulative_requests = 0
    aborted_reason: Optional[str] = None

    with open(audit_path, "a", encoding="utf-8") as audit_f:
        _audit_write(
            audit_f,
            type="run_header",
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            name_gray_low=name_gray_low,
            max_candidate_pairs=max_candidate_pairs,
            confidence_threshold=confidence_threshold,
            n_candidates=n_candidates,
            mock=config.is_mock_active(),
            workers=n_workers,
            batch_size=n_batch,
            n_requests_planned=n_requests_planned,
            size_cap=resolved_size_cap,
            batch_order="shuffled-sha256",
            similarity_backend=similarity_backend(),
            llm_backend=getattr(client, "backend", None),
            llm_model=getattr(client, "model", None),
        )

        executor = ThreadPoolExecutor(max_workers=n_workers)
        try:
            future_to_batch = {
                executor.submit(
                    _adjudicate_batch,
                    batch_id,
                    batch,
                    records,
                    base_groups,
                    id_info,
                    client,
                    confidence_threshold,
                    call_budget,
                ): batch
                for batch_id, batch in enumerate(batches)
            }

            for future in as_completed(future_to_batch):
                batch_pairs = future_to_batch[future]
                try:
                    batch_verdicts = future.result()
                except Exception as e:
                    batch_verdicts = []
                    for (global_idx, i, j) in batch_pairs:
                        display = _pair_display_info(i, j, base_groups, id_info)
                        batch_verdicts.append(
                            {
                                "global_idx": global_idx,
                                "batch_id": -1,
                                "batch_size": len(batch_pairs),
                                "i": i,
                                "j": j,
                                "names_a": display["names_a"],
                                "names_b": display["names_b"],
                                "sim": display["sim"],
                                "same_asset": None,
                                "confidence": 0.0,
                                "evidence": None,
                                "elapsed_s": 0.0,
                                "should_merge": False,
                                "error": str(e),
                            }
                        )

                with progress_lock:
                    for verdict in batch_verdicts:
                        results[verdict["global_idx"]] = verdict
                        done_count += 1
                        if verdict["should_merge"]:
                            provisional_merge_count += 1

                    cumulative_requests += 1
                    print(f"[llm] {done_count}/{n_candidates} pairs judged, {provisional_merge_count} judged same, "
                          f"requests {cumulative_requests}/{n_requests_planned}", file=sys.stderr, flush=True)

                    if call_budget.aborted_reason is not None and aborted_reason is None:
                        aborted_reason = call_budget.aborted_reason
                        reason_detail = {
                            "daily_quota": "the provider reported a daily quota limit",
                            "spend_cap": "the provider reported a spending limit",
                            "billing_safety": "the claude CLI did not confirm subscription credentials",
                        }.get(aborted_reason, "the CAASM_LLM_MAX_CALLS limit was reached")
                        print(f"[llm] stopping early: {aborted_reason} ({reason_detail}). "
                              f"{done_count}/{n_candidates} pairs judged; the rest are treated as 'not the same device'.",
                              file=sys.stderr, flush=True)
                        for pending_future in future_to_batch:
                            pending_future.cancel()
                        break
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        positive_edges: List[Tuple[int, int, float, float]] = [
            (verdict["i"], verdict["j"], verdict["confidence"], verdict["sim"])
            for verdict in results
            if verdict is not None and verdict["should_merge"]
        ]
        policy_result = mp.apply_merge_policy(len(base_groups), positive_edges, resolved_size_cap)

        error_count = 0
        missing_count = 0
        for verdict in results:
            if verdict is None:
                continue
            if verdict["error"] is not None:
                error_count += 1
            if verdict.get("missing_from_response"):
                missing_count += 1
            pair_key = (verdict["i"], verdict["j"])
            policy_rejected = pair_key in policy_result.rejected_pairs
            _audit_write(
                audit_f,
                type="verdict",
                cluster_i=verdict["i"],
                cluster_j=verdict["j"],
                names_a=verdict["names_a"],
                names_b=verdict["names_b"],
                sim=verdict["sim"],
                same_asset=verdict["same_asset"],
                confidence=verdict["confidence"],
                evidence=verdict["evidence"],
                elapsed_s=verdict["elapsed_s"],
                merged=bool(verdict["should_merge"]) and not policy_rejected,
                policy_rejected=policy_rejected,
                error=verdict["error"],
                batch_id=verdict["batch_id"],
                batch_size=verdict["batch_size"],
            )

    final_clusters: List[Set[str]] = []
    for comp in policy_result.components:
        ids: Set[str] = set()
        for idx in comp:
            ids |= base_groups[idx]
        final_clusters.append(ids)

    if stats is not None:
        stats["llm_calls"] = done_count
        stats["merged_pairs"] = policy_result.merges_applied
        stats["merges_applied"] = policy_result.merges_applied
        stats["merges_rejected_by_policy"] = policy_result.merges_rejected_by_policy
        stats["size_cap"] = resolved_size_cap
        stats["candidate_pairs"] = n_candidates
        stats["max_candidate_pairs"] = max_candidate_pairs
        stats["errors"] = error_count
        stats["missing_verdicts"] = missing_count
        stats["workers"] = n_workers
        stats["batch_size"] = n_batch
        stats["llm_requests"] = cumulative_requests
        if aborted_reason is not None:
            stats["aborted"] = aborted_reason

    return final_clusters


LLM_MAX_CANDIDATES_ENV_VAR = "CAASM_LLM_MAX_CANDIDATES"
DEFAULT_MAX_CANDIDATE_PAIRS = 3000


def _resolve_max_candidate_pairs(explicit: Optional[Union[int, str]]) -> Optional[int]:
    raw: Optional[Union[int, str]] = explicit
    if raw is None:
        raw = os.getenv(LLM_MAX_CANDIDATES_ENV_VAR) or DEFAULT_MAX_CANDIDATE_PAIRS
    if isinstance(raw, str):
        if raw.strip().lower() == "none":
            return None
        raw = int(raw)
    if raw < 1:
        raise ValueError(f"candidate pair limit must be >= 1 or 'none': {raw!r}")
    return int(raw)




def assign_batch_order(candidate_idx_pairs: List[Tuple[int, int]]) -> List[Tuple[int, int, int]]:
    indexed = [(idx, i, j) for idx, (i, j) in enumerate(candidate_idx_pairs)]
    order_key = hashlib.sha256(json.dumps(candidate_idx_pairs).encode("utf-8")).hexdigest()[:16]
    random.Random(order_key).shuffle(indexed)
    return indexed




