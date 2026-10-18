"""Notifications: what to tell whom, and how.

Critical assets (cases D, F, G) get one alert each, immediately. Important assets
(B, C, E) are sent as one digest. Informational assets (A) are not sent.

Alert text is written by the LLM when one is configured, from the observed records
only. Every IP address and hostname in the LLM's text is checked against those
records; if the text mentions anything that is not in them, the LLM text is not
used and the template text is sent instead (the check result is kept).
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from typing import Any, Callable, Dict, List, Set

URGENT_CASES = ("D", "F", "G")
DIGEST_CASES = ("B", "C", "E")

ACTION = {
    "D": "Install or repair the EDR agent on this host, and confirm whether it should be reachable from the Internet.",
    "F": "Find the owner, register the host in the asset ledger, and confirm whether it should be reachable from the Internet.",
    "G": "Identify who runs this Internet-facing service. If nobody owns it, take it down; otherwise register it and install EDR.",
}

ALERT_PROMPT = """You are a security analyst assisting a CISO.
An asset-reconciliation tool combined the records below into one asset and classified it as case {case}: {meaning}

Write a short alert (at most 120 words) for the security team:
- Say which source (ledger, edr, asm) observed what, quoting the concrete values from the records (hostnames, IP addresses, ports, timestamps).
- Do not mention any hostname, IP address, port or fact that is not in the records.
- End with one or two recommended actions.

Records (JSON):
{records_json}

Answer with plain text only."""

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_NAME_RE = re.compile(r"\b[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*\b")
_TIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?Z?)?\b|\b\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?Z?\b")
_NAME_FIELDS = {"hostname", "fqdn", "asset_id_or_hostname", "domain", "dest_fqdn"}
# words that look like names but are not hosts
_NOT_HOSTS = re.compile(r"^(?:cve-\d{4}-\d+|sha-?\d+|tls-?\d(?:\.\d)?|ssl-?\d(?:\.\d)?|e\.g|i\.e|etc|v?\d+(?:\.\d+)*|"
                        r"\d+(?:st|nd|rd|th)|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)-\d{1,2}|ipv[46]|x86|x64|arm64|utf-8|iso-\d+)$", re.I)


def _record_tokens(records: Dict[str, List[dict]]) -> Set[str]:
    """Values from the records. For name fields, the first label (`wks-c06f3` for
    `wks-c06f3.corp.local`) and the domain suffixes (`corp.local`) are also accepted.
    Names in the text must equal one of these exactly."""
    toks: Set[str] = set()
    for recs in records.values():
        for r in recs:
            for k, v in r.items():
                if k.startswith("_") or v in (None, ""):
                    continue
                for part in re.split(r"[\s,;]+", str(v)):
                    part = part.strip().lower().rstrip(".")
                    if not part:
                        continue
                    toks.add(part)
                    if k in _NAME_FIELDS and "." in part and not _IP_RE.fullmatch(part):
                        labels = part.split(".")
                        toks.add(labels[0])
                        for i in range(1, len(labels) - 1):  # domain suffixes, e.g. corp.example.local
                            toks.add(".".join(labels[i:]))
    return toks


def check_text_against_records(text: str, records: Dict[str, List[dict]]) -> List[str]:
    """Return IPv4 addresses and host / domain names in `text` that are not in the records.

    Checked: every dotted IPv4-like token, and every name that contains a digit or a dot
    (e.g. `wks-c06f3`, `shop7.example.com`). Exact match only. Plain words, ports and
    timestamps are not checked."""
    known = _record_tokens(records)
    unknown: Set[str] = set()
    for ip in _IP_RE.findall(text):
        if ip.lower() not in known:
            unknown.add(ip)
    stripped = _IP_RE.sub(" ", text)
    stripped = _TIME_RE.sub(" ", stripped)  # timestamps and dates are not checked
    for h in _NAME_RE.findall(stripped):
        hl = h.lower().rstrip(".")
        if not (re.search(r"\d", hl) or "." in hl) or _NOT_HOSTS.match(hl):
            continue
        m = re.fullmatch(r"([a-z0-9_-]*[a-z])\.[A-Z][a-z]+", h)
        if m:  # "open.Install": a missing space after a sentence; still check the left part
            left = m.group(1).lower()
            if re.search(r"\d", left) and left not in known:
                unknown.add(m.group(1))
            continue
        if hl not in known:
            unknown.add(h)
    return sorted(unknown)


def template_alert(asset: Dict[str, Any]) -> str:
    lines = [f"[{asset['risk']}] Case {asset['case']}: {asset['name']} — {asset['case_meaning']}"]
    for src in ("ledger", "edr", "asm"):
        for rec in asset["records"].get(src, []):
            shown = {k: v for k, v in rec.items() if not k.startswith("_") and v not in ("", None)}
            lines.append(f"- {src}: " + ", ".join(f"{k}={v}" for k, v in shown.items()))
    lines.append("Recommended: " + ACTION.get(asset["case"], "Review this asset."))
    return "\n".join(lines)


def _llm_records_view(asset: Dict[str, Any]) -> Dict[str, List[dict]]:
    """Only the documented columns are sent to the LLM (same rule as for matching)."""
    from .engine.matchers import llm_view

    return {src: [llm_view(r, src) for r in recs] for src, recs in asset["records"].items()}


def build_notifications(assets: List[Dict[str, Any]], llm_client: Any = None) -> List[Dict[str, Any]]:
    from .llm_client import DailyQuotaExhaustedError

    out: List[Dict[str, Any]] = []
    for a in assets:
        if a["case"] not in URGENT_CASES:
            continue
        text, source, check = template_alert(a), "template", None
        if llm_client is not None:
            try:
                prompt = ALERT_PROMPT.format(
                    case=a["case"], meaning=a["case_meaning"],
                    records_json=json.dumps(_llm_records_view(a), ensure_ascii=False, indent=1))
                ai = (llm_client.chat([{"role": "user", "content": prompt}]) or "").strip()
                unknown = check_text_against_records(ai, a["records"])
                check = {"unknown_mentions": unknown}
                if ai and not unknown:
                    text, source = f"[{a['risk']}] Case {a['case']}: {a['name']}\n{ai}", "llm"
                else:
                    check["rejected"] = True
                    check["llm_text"] = ai
            except DailyQuotaExhaustedError as e:  # stop using the LLM for the remaining alerts
                check = {"error": str(e)[:300]}
                print(f"[warn] LLM alert texts stopped: {e}", file=sys.stderr)
                llm_client = None
            except Exception as e:  # noqa: BLE001 - fall back to the template
                check = {"error": str(e)[:300]}
        out.append({
            "kind": "alert", "risk": a["risk"], "case": a["case"], "asset": a["name"],
            "title": f"{a['risk']}: case {a['case']} — {a['name']}",
            "text": text, "text_source": source, "check": check,
            "why_combined": a["why"], "llm_merges": a["llm_merges"], "kept_apart": a.get("kept_apart", []),
            "records": a["records"],
        })
    digest = [a for a in assets if a["case"] in DIGEST_CASES]
    if digest:
        lines = [f"{len(digest)} assets to review:"]
        for a in digest:
            lines.append(f"- case {a['case']} {a['name']}: {a['case_meaning']}")
        out.append({"kind": "digest", "risk": "Important", "case": "", "asset": "",
                    "title": f"Important: {len(digest)} assets to review", "text": "\n".join(lines),
                    "text_source": "template", "check": None, "why_combined": "", "llm_merges": [], "records": {}})
    return out


def post_webhook(url: str, notifications: List[Dict[str, Any]], delay: float = 0.0,
                 log: Callable[[str], None] = lambda m: print(m, file=sys.stderr)) -> int:
    """Send each notification as a Slack-compatible incoming-webhook message ({"text": ...}).
    Only for a localhost URL (the built-in inbox) are the details (records, reasons) attached."""
    from urllib.parse import urlsplit

    local = (urlsplit(url).hostname or "") in ("127.0.0.1", "localhost", "::1")
    sent = 0
    for n in notifications:
        msg: Dict[str, Any] = {"text": f"*{n['title']}*\n{n['text']}"}
        if local:  # record details only go to the local inbox, never to an external service
            msg["strayhost"] = n
        body = json.dumps(msg, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp.read()
            sent += 1
        except Exception as e:  # noqa: BLE001
            log(f"[warn] webhook failed for '{n['title']}': {e}")
        if delay:
            time.sleep(delay)
    return sent
