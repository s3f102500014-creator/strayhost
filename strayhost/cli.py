"""strayhost command line.

  run      reconcile ledger / EDR / ASM CSVs and report unmanaged assets
  synth    generate a synthetic, labelled dataset (three CSVs + truth.csv)
  score    compare a run's assets.json with truth.csv
  console  tickets, routing, escalation, e-mail and reports in the browser
send     send the notifications of a finished run to a webhook again
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from . import config, taxonomy
from .data_io import get_identifiers_from_record, load_all_data, normalize_hostname
from .grouping import build_asset_groups
from .rule_engine import Coverage, coverage_to_case

SOURCES = ("ledger", "edr", "asm")
CRITICAL_CASES = tuple(c for c in "ABCDEFG" if taxonomy.case_to_risk(c) == "Critical")  # C, D, G
NAME_FIELD = {"ledger": "hostname", "edr": "asset_id_or_hostname", "asm": "domain"}
IP_FIELD = {"ledger": "ip", "edr": "ip", "asm": "public_ip"}
CASE_TEXT = {
    "A": "In ledger, EDR and external scan: managed but exposed (check vulnerabilities)",
    "B": "In ledger and EDR, not externally visible: internal-only asset",
    "C": "In ledger and externally visible, but no EDR agent: unprotected asset",
    "D": "EDR and externally visible, but not in the ledger: shadow IT, high risk",
    "E": "Ledger only, not detected: retired or inactive asset",
    "F": "EDR only, not in the ledger: unmanaged internal asset",
    "G": "Externally visible only, unknown internally: typical shadow IT",
    "H": "Not observed by any source",
}


# --------------------------------------------------------------------------- run
def _cluster_sources(cluster: Set[str]) -> Coverage:
    present = {i.split("_", 1)[0] for i in cluster}
    return Coverage(ledger="ledger" in present, edr="edr" in present, asm="asm" in present)


def _shared_identifiers(cluster: Set[str], by_id: Dict[str, dict]) -> List[str]:
    count: Counter = Counter()
    for rid in cluster:
        src = rid.split("_", 1)[0]
        for ident in get_identifiers_from_record(by_id[rid], src):
            count[ident] += 1
    return sorted(k for k, v in count.items() if v >= 2)


def _asset_key(cluster: Set[str], by_id: Dict[str, dict]) -> str:
    """A key that stays the same across runs: the ledger asset ID if any, else the full
    host or domain name (not just its first label), else the IP address."""
    ids = sorted(by_id[r].get("asset_id") for r in cluster if r.startswith("ledger_") and by_id[r].get("asset_id"))
    if ids:
        return "id:" + ids[0].lower()
    fields = (("ledger", "fqdn"), ("ledger", "hostname"), ("edr", "asset_id_or_hostname"), ("asm", "domain"))
    for src, field in fields:
        names = sorted((by_id[r].get(field) or "").strip().lower() for r in cluster
                       if r.startswith(src + "_") and (by_id[r].get(field) or "").strip())
        if names:
            return "name:" + names[0]
    for src in SOURCES:
        ips = sorted(by_id[r].get(IP_FIELD[src]) for r in cluster if r.startswith(src + "_") and by_id[r].get(IP_FIELD[src]))
        if ips:
            return "ip:" + ips[0]
    return "rec:" + sorted(cluster)[0]


def _canonical_name(cluster: Set[str], by_id: Dict[str, dict]) -> str:
    """Prefer the ledger hostname, then EDR, then ASM; most frequent within a source."""
    for src in SOURCES:
        names: Counter = Counter()
        for rid in sorted(cluster):
            if rid.split("_", 1)[0] == src:
                n = normalize_hostname(by_id[rid].get(NAME_FIELD[src]))
                if n:
                    names[n] += 1
        if names:
            return names.most_common(1)[0][0]
    for src in SOURCES:
        for rid in sorted(cluster):
            if rid.split("_", 1)[0] == src and by_id[rid].get(IP_FIELD[src]):
                return by_id[rid][IP_FIELD[src]]
    return sorted(cluster)[0]


def _names(v: Any) -> str:
    if isinstance(v, (list, tuple)):
        v = [str(x) for x in v if x]
        return "/".join(v) if v else "(a record without a hostname)"
    return str(v) if v else "(a record without a hostname)"


def _write_report(assets: List[Dict[str, Any]], meta: Dict[str, Any], path: Path) -> None:
    rows = []
    for a in assets:
        cls = {"Critical": "crit", "Important": "imp"}.get(a["risk"], "")
        srcs = "".join(("L" if a["in_ledger"] else "-", "E" if a["in_edr"] else "-", "A" if a["in_asm"] else "-"))
        rows.append(
            f"<tr class='{cls}'><td>{html.escape(a['risk'])}</td><td>{a['case']}</td><td>{html.escape(a['name'])}</td>"
            f"<td><code>{srcs}</code></td><td>{len(a['record_ids'])}</td><td>{html.escape(a['why'])}</td></tr>"
        )
    counts = Counter(a["risk"] for a in assets)
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>strayhost report</title>
<style>body{{font-family:system-ui,sans-serif;margin:24px;color:#1a1a1a}}table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #e3e5e8;padding:6px 8px;text-align:left;vertical-align:top;font-size:14px}}
tr.crit td:first-child{{color:#b00020;font-weight:700}}tr.imp td:first-child{{color:#8a5a00}}code{{font-size:13px}}</style></head>
<body><h1>Asset reconciliation report</h1>
<p>Mode: <b>{html.escape(meta['mode'])}</b>. Records: {meta['n_records']}. Assets: {len(assets)}.
Critical: {counts.get('Critical', 0)}, Important: {counts.get('Important', 0)}, Informational: {counts.get('Informational', 0)}.</p>
<p>Sources column: L = ledger (CMDB), E = EDR, A = external attack-surface scan (ASM).</p>
<table><tr><th>Risk</th><th>Case</th><th>Asset</th><th>Sources</th><th>Records</th><th>Why combined</th></tr>
{''.join(rows)}</table></body></html>"""
    path.write_text(doc, encoding="utf-8")


def cmd_run(args: argparse.Namespace) -> int:
    in_dir = Path(args.input) if args.input else None
    paths = {
        "ledger": Path(args.ledger) if args.ledger else in_dir / "ledger.csv",
        "edr": Path(args.edr) if args.edr else in_dir / "edr.csv",
        "asm": Path(args.asm) if args.asm else in_dir / "asm.csv",
    }
    try:
        records = load_all_data(paths["ledger"], paths["edr"], paths["asm"])
    except UnicodeDecodeError as e:
        print(f"error: a CSV file is not UTF-8 ({e}). Save it as UTF-8 (e.g. 'CSV UTF-8' in Excel).", file=sys.stderr)
        return 2
    if records is None:
        print("error: could not read one of: " + ", ".join(str(p) for p in paths.values()), file=sys.stderr)
        return 2
    for src in SOURCES:
        rows = records[src]
        if rows and not any(get_identifiers_from_record(r, src) for r in rows):
            expected = {"ledger": "asset_id, hostname, ip", "edr": "asset_id_or_hostname, ip", "asm": "domain, public_ip"}[src]
            print(f"error: no identifiers found in {paths[src]}. Expected columns: {expected} "
                  f"(found: {', '.join(k for k in rows[0] if not k.startswith('_'))}). See README 'Input format'.",
                  file=sys.stderr)
            return 2
    by_id = {r["_internal_id"]: r for src in records.values() for r in src}
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    base_groups = build_asset_groups(records)

    use_llm = not args.no_llm and (config.llm_configured() or config.is_mock_active())
    verdicts: List[Dict[str, Any]] = []
    stats: Dict[str, Any] = {}
    exit_code = 0
    if use_llm:
        from .engine.review import match_all_by_llm
        from .llm_client import LLMNotConfiguredError, get_client

        try:
            client = get_client()
        except (LLMNotConfiguredError, OSError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        print(f"[info] LLM mode: {client!r}. Every combination of records is decided by the LLM.", file=sys.stderr)
        clusters, verdicts = match_all_by_llm(records, client, out, stats)
        n_failed = sum(1 for v in verdicts if v.get("error") and not str(v["error"]).startswith("skipped:"))
        mode = f"LLM decides every combination ({getattr(client, 'model', '?')})"
        if n_failed:
            print(f"[warn] {n_failed}/{len(verdicts)} LLM judgements failed (see 'error' in the llm_adjudications file); "
                  "those records were kept separate.", file=sys.stderr)
            stats["failed_judgements"] = n_failed
            if verdicts and n_failed == len(verdicts):
                mode = "nothing combined (LLM unreachable: every call failed)"
                exit_code = 1
    else:
        clusters = [set(g) for g in base_groups]
        why = "--no-llm given" if args.no_llm else "no LLM configured: set CAASM_LLM_BACKEND=claude-cli, or CAASM_LLM_BASE_URL and CAASM_LLM_MODEL"
        print(f"[info] rules-only mode ({why}): records that share any identifier are combined without review; "
              "this is the baseline for comparison.", file=sys.stderr)
        mode = "rules only (baseline)"
    merged_verdicts = [v for v in verdicts if v.get("merged")]
    apart_verdicts = [v for v in verdicts if v.get("same_asset") is False and not v.get("error")]

    assets: List[Dict[str, Any]] = []
    for cluster in clusters:
        cov = _cluster_sources(cluster)
        case = coverage_to_case(cov)
        risk = taxonomy.case_to_risk(case)
        reasons = []
        llm_reasons = []
        for m in merged_verdicts:
            if set(m["records_a"]) <= cluster and set(m["records_b"]) <= cluster:
                llm_reasons.append({"names_a": m.get("names_a"), "names_b": m.get("names_b"), "step": m["step"],
                                    "confidence": m.get("confidence"), "evidence": m.get("evidence")})
                reasons.append(f"LLM judged {_names(m.get('names_a'))} and {_names(m.get('names_b'))} "
                               f"to be the same device: {m.get('evidence')}")
        kept_apart = []
        for m in apart_verdicts:
            ina, inb = set(m["records_a"]) & cluster, set(m["records_b"]) & cluster
            if (ina and not set(m["records_b"]) & cluster) or (inb and not set(m["records_a"]) & cluster):
                other = m["names_b"] if ina else m["names_a"]
                if any(k["other"] == other for k in kept_apart):
                    continue
                kept_apart.append({"other": other, "confidence": m.get("confidence"), "evidence": m.get("evidence"),
                                   "step": m["step"]})
        if not use_llm:
            shared = _shared_identifiers(cluster, by_id)
            if shared:
                reasons.append("rule: same identifier(s) " + ", ".join(shared[:6]) + (" ..." if len(shared) > 6 else ""))
        if len(cluster) == 1:
            reasons.append("single record")
        recs_by_src: Dict[str, List[dict]] = defaultdict(list)
        for rid in sorted(cluster):
            recs_by_src[rid.split("_", 1)[0]].append({k: v for k, v in by_id[rid].items()})
        assets.append({
            "name": _canonical_name(cluster, by_id),
            "asset_key": _asset_key(cluster, by_id),
            "case": case,
            "risk": risk,
            "case_meaning": CASE_TEXT[case],
            "in_ledger": cov.ledger, "in_edr": cov.edr, "in_asm": cov.asm,
            "record_ids": sorted(cluster),
            "why": "; ".join(reasons),
            "llm_merges": llm_reasons,
            "kept_apart": kept_apart,
            "records": recs_by_src,
        })
    seen_keys: Counter = Counter()
    for a in sorted(assets, key=lambda x: x["record_ids"]):   # keys must be unique within a run
        seen_keys[a["asset_key"]] += 1
        if seen_keys[a["asset_key"]] > 1:
            a["asset_key"] += f"#{seen_keys[a['asset_key']]}"
    order = {"Critical": 0, "Important": 1, "Informational": 2}
    assets.sort(key=lambda a: (order.get(a["risk"], 9), a["case"], a["name"]))

    meta = {"mode": mode, "n_records": len(by_id), "n_assets": len(assets),
            "n_llm_merges": len(merged_verdicts), "n_llm_judgements": len(verdicts), 
            "llm_stats": {k: v for k, v in stats.items() if isinstance(v, (int, float, str, bool))}}
    (out / "assets.json").write_text(json.dumps({"meta": meta, "assets": assets}, ensure_ascii=False, indent=2), encoding="utf-8")
    with open(out / "assets.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["risk", "case", "name", "in_ledger", "in_edr", "in_asm", "n_records", "why"])
        for a in assets:
            w.writerow([a["risk"], a["case"], a["name"], a["in_ledger"], a["in_edr"], a["in_asm"], len(a["record_ids"]), a["why"]])
    from . import notify

    alert_client = None
    if use_llm and not config.is_mock_active() and not exit_code and not args.no_ai_alerts:
        alert_client = client
    if stats.get("aborted"):
        alert_client = None  # the LLM run stopped (limit or billing safety): use template texts
    if alert_client is not None:
        print("[info] writing alert texts with the LLM (checked against the records)", file=sys.stderr)
    notes = notify.build_notifications(assets, alert_client)
    meta["n_notifications"] = len(notes)
    meta["alert_text"] = {k: sum(1 for n in notes if n["text_source"] == k) for k in ("llm", "template")}
    (out / "notifications.json").write_text(json.dumps(notes, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "assets.json").write_text(json.dumps({"meta": meta, "assets": assets}, ensure_ascii=False, indent=2), encoding="utf-8")
    md = ["# Notifications", ""]
    for n in notes:
        md += [f"## {n['title']}", "", n["text"], ""]
        if n["kind"] == "alert":
            md += [f"Why combined: {n['why_combined']}", ""]
    (out / "alerts.md").write_text("\n".join(md), encoding="utf-8")
    _write_report(assets, meta, out / "report.html")
    if args.webhook:
        outgoing = notes + [notify.run_summary(assets, meta)]
        sent = notify.post_webhook(args.webhook, outgoing, delay=args.webhook_delay)
        print(f"sent {sent}/{len(outgoing)} messages to the webhook ({len(notes)} notifications + run summary)",
              file=sys.stderr)

    c = Counter(a["risk"] for a in assets)
    print(f"{len(by_id)} records -> {len(assets)} assets ({mode}); "
          f"Critical {c.get('Critical', 0)}, Important {c.get('Important', 0)}, Informational {c.get('Informational', 0)}; "
          f"LLM judgements {len(verdicts)}, combined {len(merged_verdicts)}")
    print(f"{len(notes)} notifications ({meta['alert_text']['llm']} alert texts by LLM)")
    print(f"wrote {out}/assets.json, assets.csv, notifications.json, alerts.md, report.html")
    if exit_code:
        print("error: the LLM could not be reached; results above are rules-only.", file=sys.stderr)
    return exit_code


# ------------------------------------------------------------------------- synth
def _publicize_asm_addresses(records: Dict[str, List[dict]]) -> None:
    """An external scan sees public addresses. The g1 generator copies internal addresses
    into ASM records. Each private address seen by ASM is replaced, in every list
    (ledger, EDR, ASM), by a fixed address from the documentation ranges 192.0.2.0/24 and
    198.51.100.0/24 -- as for an Internet-facing server whose ledger entry holds its
    public address. Addresses that only appear internally are left as they are."""
    def private(ip: str) -> bool:
        p = ip.split(".")
        if len(p) != 4 or not all(x.isdigit() for x in p):
            return False
        a, b = int(p[0]), int(p[1])
        return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)

    in_use = {r.get(f) for src, f in (("ledger", "ip"), ("edr", "ip"), ("asm", "public_ip")) for r in records.get(src, [])}
    pool = [ip for ip in [f"192.0.2.{i}" for i in range(1, 255)] + [f"198.51.100.{i}" for i in range(1, 255)]
            if ip not in in_use]
    mapping: Dict[str, str] = {}
    for r in records.get("asm", []):
        ip = (r.get("public_ip") or "").strip()
        if ip and private(ip) and ip not in mapping:
            if len(mapping) >= len(pool):
                raise SystemExit("too many Internet-facing addresses for the documentation ranges; use a smaller --n")
            mapping[ip] = pool[len(mapping)]
    for src, field in (("ledger", "ip"), ("edr", "ip"), ("asm", "public_ip")):
        for r in records.get(src, []):
            ip = (r.get(field) or "").strip()
            if ip in mapping:
                r[field] = mapping[ip]


def cmd_synth(args: argparse.Namespace) -> int:
    from .engine import generator as gen
    from .engine import generator_g2 as g2

    cfg = gen.AssetGenConfig(n=args.n, seed=args.seed, mode=args.mode)
    if args.style == "g1":
        from .engine import noise

        pop = gen.generate_population(cfg)
        records, gt = noise.apply_noise(pop.records, pop.ground_truth, p=args.p, seed=args.seed)
        _publicize_asm_addresses(records)
    else:
        records, gt = g2.generate_g2(cfg, args.p)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for src in SOURCES:
        rows = records[src]
        fields = [k for k in rows[0].keys() if not k.startswith("_")] if rows else []
        with open(out / f"{src}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)
        # load_all_data numbers rows as <source>_<row index>; the generator uses the same scheme.
        assert [r["_internal_id"] for r in rows] == [f"{src}_{i}" for i in range(len(rows))]
    with open(out / "truth.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["record_id", "true_asset", "true_case"])
        for rid, tid in sorted(gt.record_to_asset.items()):
            # the generators label devices with their own letters; write the case of Table I
            w.writerow([rid, tid, coverage_to_case(gen.ROLE_DEFS[gt.true_case_of(tid)].coverage)])
    n = sum(len(records[s]) for s in SOURCES)
    print(f"synthetic data ({args.style}): {gt.n_assets()} devices, {n} records (strength p={args.p}, seed={args.seed}) -> {out}")
    print("This data is generated, not captured from a real network.")
    return 0


# ------------------------------------------------------------------------- score
def _pairs(groups: List[Set[str]]) -> Set[frozenset]:
    out = set()
    for g in groups:
        for a, b in combinations(sorted(g), 2):
            out.add(frozenset((a, b)))
    return out


def cmd_score(args: argparse.Namespace) -> int:
    for p in (args.assets, args.truth):
        if not Path(p).exists():
            print(f"error: {p} not found (did the run finish?)", file=sys.stderr)
            return 2
    data = json.loads(Path(args.assets).read_text(encoding="utf-8"))
    pred = [set(a["record_ids"]) for a in data["assets"]]
    truth: Dict[str, str] = {}
    true_case: Dict[str, str] = {}
    with open(args.truth, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            truth[row["record_id"]] = row["true_asset"]
            true_case[row["true_asset"]] = row["true_case"]
    tgroups: Dict[str, Set[str]] = defaultdict(set)
    for rid, tid in truth.items():
        tgroups[tid].add(rid)
    pp, tp_ = _pairs(pred), _pairs(list(tgroups.values()))
    tp = len(pp & tp_)
    prec = tp / len(pp) if pp else 1.0
    rec = tp / len(tp_) if tp_ else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    # detection of high-risk devices: majority cluster of each true device has the true case
    rid_to_pred = {rid: i for i, g in enumerate(pred) for rid in g}
    pred_case = [a["case"] for a in data["assets"]]
    det = Counter()
    for tid, rids in tgroups.items():
        if true_case[tid] not in CRITICAL_CASES:
            continue
        maj = Counter(rid_to_pred[r] for r in sorted(rids) if r in rid_to_pred).most_common(1)
        ok = bool(maj) and pred_case[maj[0][0]] == true_case[tid]
        det[(true_case[tid], ok)] += 1
    print(f"mode: {data['meta']['mode']}")
    print(f"pairwise precision {prec:.3f}  recall {rec:.3f}  F1 {f1:.3f}  (record pairs placed in the same asset)")
    for c in CRITICAL_CASES:
        n = det[(c, True)] + det[(c, False)]
        if n:
            print(f"case {c} devices found with the correct case: {det[(c, True)]}/{n}")
    # Critical alerts: does each one point to a real high-risk device (once)?
    majority_of = {}
    for tid, rids in tgroups.items():
        maj = Counter(rid_to_pred[r] for r in sorted(rids) if r in rid_to_pred).most_common(1)
        if maj:
            majority_of[tid] = maj[0][0]
    real = 0
    crit_idx = [i for i, a in enumerate(data["assets"]) if a["risk"] == "Critical"]
    for i in crit_idx:
        owners = Counter(truth[r] for r in pred[i] if r in truth).most_common()
        if not owners:
            continue
        top = max(c for _, c in owners)
        owner = sorted(t for t, c in owners if c == top)[0]  # deterministic tie-break
        if true_case.get(owner) in CRITICAL_CASES and majority_of.get(owner) == i and pred_case[i] == true_case[owner]:
            real += 1
    n_true = sum(1 for t, c in true_case.items() if c in CRITICAL_CASES)
    print(f"Critical alerts: {len(crit_idx)} (one correct alert per real high-risk device: {real}; "
          f"duplicate, wrong device or wrong case: {len(crit_idx) - real}); real high-risk devices in the data: {n_true}")
    # missed: a real high-risk device none of whose records is in any Critical asset
    alerted = {truth[r] for i in crit_idx for r in pred[i] if r in truth}
    missed = sorted(t for t, c in true_case.items() if c in CRITICAL_CASES and t not in alerted)
    print(f"real high-risk devices with no Critical alert at all (missed): {len(missed)}"
          + (f" ({', '.join(missed)})" if missed else ""))
    return 0


def cmd_console(args: argparse.Namespace) -> int:
    from .console import Console, serve

    if not 0 <= args.digest_hour <= 23:
        print("error: --digest-hour must be 0-23", file=sys.stderr)
        return 2
    routing = {}
    if args.routing:
        routing = json.loads(Path(args.routing).read_text(encoding="utf-8"))
    console = Console(Path(args.data), routing=routing,
                      sla_minutes={"Critical": args.sla_critical_minutes, "Important": args.sla_important_minutes},
                      digest_hour=args.digest_hour, background_mail=True)
    srv = serve(args.port, console, open_browser=not args.no_browser)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


def cmd_send(args: argparse.Namespace) -> int:
    """Send the notifications of a finished run (its --out folder) to a webhook again."""
    from . import notify

    folder = Path(args.from_dir)
    for name in ("assets.json", "notifications.json"):
        if not (folder / name).exists():
            print(f"error: {folder / name} not found", file=sys.stderr)
            return 2
    data = json.loads((folder / "assets.json").read_text(encoding="utf-8"))
    notes = json.loads((folder / "notifications.json").read_text(encoding="utf-8"))
    outgoing = notes + [notify.run_summary(data["assets"], data["meta"])]
    sent = notify.post_webhook(args.webhook, outgoing, delay=args.webhook_delay)
    print(f"sent {sent}/{len(outgoing)} messages to the webhook ({len(notes)} notifications + run summary)",
          file=sys.stderr)
    return 0 if sent == len(outgoing) else 1


# -------------------------------------------------------------------------- main
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="strayhost", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="reconcile three CSV exports")
    r.add_argument("--input", help="directory containing ledger.csv, edr.csv, asm.csv")
    r.add_argument("--ledger", help="ledger (CMDB) CSV, instead of --input")
    r.add_argument("--edr", help="EDR CSV, instead of --input")
    r.add_argument("--asm", help="external attack-surface scan CSV, instead of --input")
    r.add_argument("--out", default="out", help="output folder (default: out)")
    r.add_argument("--no-llm", action="store_true", help="rules only, even if an LLM is configured")
    r.add_argument("--webhook", help="Slack-compatible incoming-webhook URL (or the local console: http://127.0.0.1:8765/hook)")
    r.add_argument("--webhook-delay", type=float, default=0.0, help="seconds between webhook messages")
    r.add_argument("--no-ai-alerts", action="store_true", help="use template alert texts even if an LLM is configured")
    r.set_defaults(func=cmd_run)

    for name in ("console",):
        ib = sub.add_parser(name, help="tickets, routing, escalation, e-mail and reports in the browser")
        ib.add_argument("--port", type=int, default=8765, help="port on 127.0.0.1 (default 8765)")
        ib.add_argument("--data", default="console_data", help="folder for the console's state file (default: console_data)")
        ib.add_argument("--routing", help="JSON file: e-mail addresses of departments, security team, escalation")
        ib.add_argument("--sla-critical-minutes", type=float, default=24 * 60,
                        help="escalate a Critical ticket still unresolved after this time (default 1 day)")
        ib.add_argument("--sla-important-minutes", type=float, default=72 * 60,
                        help="escalate an Important ticket still unresolved after this time (default 3 days)")
        ib.add_argument("--digest-hour", type=int, default=9, help="hour of the day for the daily digests (default 9)")
        ib.add_argument("--no-browser", action="store_true", help="do not open the browser")
        ib.set_defaults(func=cmd_console)

    s = sub.add_parser("synth", help="generate a synthetic labelled dataset")
    s.add_argument("--out", default="synthetic", help="output folder (default: synthetic)")
    s.add_argument("--n", type=int, default=60, help="number of devices")
    s.add_argument("--p", type=float, default=0.2, help="strength of renames / IP changes / replacements (0-1)")
    s.add_argument("--seed", type=int, default=0, help="random seed (default 0)")
    s.add_argument("--mode", default="balanced", choices=["balanced", "imbalanced"],
                   help="balanced: the seven cases about equally often; imbalanced: 60%% managed internal devices (case B), fewer of the others")
    s.add_argument("--style", default="g1", choices=["g1", "g2"],
                   help="g1: clean records plus noise (name variants, look-alike decoys, ...); "
                        "g2: records produced from device events (renames, DHCP, replacements, NAT)")
    s.set_defaults(func=cmd_synth)

    sc = sub.add_parser("score", help="score assets.json against truth.csv")
    sc.add_argument("--assets", required=True, help="assets.json of a run")
    sc.add_argument("--truth", required=True, help="truth.csv (record_id, true_asset, true_case)")
    sc.set_defaults(func=cmd_score)

    se = sub.add_parser("send", help="send the notifications of a finished run to a webhook again")
    se.add_argument("--from", dest="from_dir", required=True, help="the --out folder of a run")
    se.add_argument("--webhook", required=True, help="Slack-compatible webhook URL or http://127.0.0.1:8765/hook")
    se.add_argument("--webhook-delay", type=float, default=0.0, help="seconds between webhook messages")
    se.set_defaults(func=cmd_send)

    args = p.parse_args(argv)
    if args.cmd == "run" and not (args.input or (args.ledger and args.edr and args.asm)):
        p.error("run needs --input DIR or all of --ledger --edr --asm")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
