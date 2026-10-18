"""StrayHost console: tickets, routing, escalation, e-mail and reports in the browser.

    python run.py console --data console_data [--routing routing.json]
    python run.py run --input DIR --out out --webhook http://127.0.0.1:8765/hook

The console receives StrayHost's notifications on a Slack-compatible webhook (/hook) and
runs the operations described in the ICSPIS 2025 paper:

* Critical assets (cases C, D, G): one ticket per asset, an immediate e-mail to the
  security team (and the owning department, if the ledger names one).
* Important assets (cases A, E, F): tickets, and one daily digest e-mail per department.
* Informational assets (case B): only in the weekly report.
* The same asset is not notified again while its ticket is open; approved assets and
  confirmed false positives are suppressed; a resolved asset that comes back is reopened.
* Tickets that stay open past their deadline are escalated (e-mail to the escalation address).
* Analysts acknowledge, resolve, approve or mark false positives in the browser; the
  decisions are kept and applied to later runs.
* A report page (and weekly e-mail) with the asset counts and ratios.

E-mail is sent through SMTP when CAASM_SMTP_HOST is set; otherwise every message is kept
in the console's outbox (visible in the browser) and marked "not sent".

State is one JSON file in --data. The server binds to 127.0.0.1 only, accepts requests
addressed to 127.0.0.1/localhost, and accepts POST bodies only as application/json.
"""

from __future__ import annotations

import json
import os
import smtplib
import sys
import threading
import time
import webbrowser
from datetime import datetime, timedelta
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

OPEN_STATES = ("open", "acknowledged")
SUPPRESSED_STATES = ("approved", "false_positive")
ACTIONS = {"acknowledge": "acknowledged", "resolve": "resolved", "approve": "approved",
           "false_positive": "false_positive", "reopen": "open"}


def _now() -> datetime:
    return datetime.now().replace(microsecond=0)


def _iso(t: datetime) -> str:
    return t.isoformat(timespec="seconds")


def _key(asset_name: str) -> str:
    return (asset_name or "").strip().lower()


class Mailer:
    """SMTP when configured (CAASM_SMTP_HOST, _PORT, _USER, _PASSWORD, _FROM, _STARTTLS);
    otherwise messages are only recorded in the outbox."""

    def __init__(self) -> None:
        self.host = os.getenv("CAASM_SMTP_HOST", "").strip()
        self.port = int(os.getenv("CAASM_SMTP_PORT", "587"))
        self.user = os.getenv("CAASM_SMTP_USER", "")
        self.password = os.getenv("CAASM_SMTP_PASSWORD", "")
        self.sender = os.getenv("CAASM_SMTP_FROM", "strayhost@localhost")
        self.starttls = os.getenv("CAASM_SMTP_STARTTLS", "1") != "0"

    @property
    def configured(self) -> bool:
        return bool(self.host)

    def send(self, to: List[str], subject: str, body: str) -> Dict[str, Any]:
        entry = {"time": _iso(_now()), "to": to, "subject": subject, "body": body}
        if not to:
            entry.update(status="not sent", reason="no recipient address in the routing file")
            return entry
        if not self.configured:
            entry.update(status="not sent", reason="SMTP not configured (CAASM_SMTP_HOST)")
            return entry
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self.sender, ", ".join(to), subject
        msg.set_content(body)
        try:
            with smtplib.SMTP(self.host, self.port, timeout=20) as s:
                if self.starttls:
                    s.starttls()
                if self.user:
                    s.login(self.user, self.password)
                s.send_message(msg)
            entry["status"] = "sent"
        except Exception as e:  # noqa: BLE001
            entry.update(status="failed", reason=str(e)[:300])
        return entry


class Console:
    def __init__(self, data_dir: Path, routing: Optional[Dict[str, Any]] = None,
                 sla_minutes: Optional[Dict[str, float]] = None, mailer: Optional[Mailer] = None,
                 clock: Callable[[], datetime] = _now) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.data_dir / "console_state.json"
        self.routing = routing or {}
        self.sla = {"Critical": 24 * 60, "Important": 72 * 60}
        self.sla.update(sla_minutes or {})
        self.mailer = mailer or Mailer()
        self.clock = clock
        self.lock = threading.Lock()
        self.state = self._load()

    # ---------------------------------------------------------------- state
    def _load(self) -> Dict[str, Any]:
        if self.state_path.exists():
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        return {"tickets": {}, "next_id": 1, "messages": [], "outbox": [], "runs": [],
                "last_digest_day": {}, "last_weekly_report": ""}

    def _save(self) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(self.state_path)

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return json.loads(json.dumps(self.state))

    # -------------------------------------------------------------- routing
    def _addr(self, section: str, dept: str = "") -> List[str]:
        r = self.routing
        if section == "department":
            entry = (r.get("departments") or {}).get(dept) or r.get("default_department") or {}
        else:
            entry = r.get(section) or {}
        email = entry.get("email")
        return [email] if isinstance(email, str) and email else list(email or [])

    def _mail(self, to: List[str], subject: str, body: str, ticket_id: Optional[int] = None) -> None:
        entry = self.mailer.send(to, subject, body)
        entry["ticket"] = ticket_id
        self.state["outbox"].append(entry)

    # -------------------------------------------------------------- tickets
    def _history(self, t: Dict[str, Any], action: str, note: str = "", by: str = "system") -> None:
        t["history"].append({"time": _iso(self.clock()), "action": action, "by": by, "note": note})
        t["updated"] = _iso(self.clock())

    def _upsert(self, asset: str, risk: str, case: str, department: str, detail: Dict[str, Any]) -> Dict[str, Any]:
        """Returns {'ticket': t, 'event': created|reopened|updated|suppressed}."""
        k = _key(asset)
        now = _iso(self.clock())
        t = self.state["tickets"].get(k)
        if t is None:
            t = {"id": self.state["next_id"], "key": k, "asset": asset, "risk": risk, "case": case,
                 "department": department, "status": "open", "created": now, "updated": now,
                 "opened": now, "last_seen": now, "seen_count": 1, "escalations": 0, "history": [],
                 "detail": detail}
            self.state["next_id"] += 1
            self.state["tickets"][k] = t
            self._history(t, "created", f"case {case}, {risk}")
            return {"ticket": t, "event": "created"}
        t["last_seen"], t["seen_count"], t["detail"] = now, t["seen_count"] + 1, detail
        if t["case"] != case or t["risk"] != risk:
            self._history(t, "case changed", f"{t['case']} -> {case}")
            t["case"], t["risk"] = case, risk
        if t["status"] in SUPPRESSED_STATES:
            return {"ticket": t, "event": "suppressed"}
        if t["status"] == "resolved":
            t["status"], t["opened"], t["escalations"] = "open", now, 0
            self._history(t, "reopened", "seen again after it was resolved")
            return {"ticket": t, "event": "reopened"}
        return {"ticket": t, "event": "updated"}

    def receive(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """Handle one webhook message. Returns a short result for the sender."""
        with self.lock:
            msg = dict(msg)
            msg["received"] = _iso(self.clock())
            self.state["messages"].append(msg)
            d = msg.get("strayhost") or {}
            kind = d.get("kind")
            result: Dict[str, Any] = {"kind": kind or "text"}
            if kind == "alert":
                r = self._upsert(d["asset"], d["risk"], d["case"], d.get("department", ""), d)
                t = r["ticket"]
                result.update(ticket=t["id"], event=r["event"])
                if r["event"] in ("created", "reopened"):
                    to = self._addr("security") + (self._addr("department", t["department"]) if t["department"] else [])
                    self._mail(to, f"[StrayHost] {d['title']}", self._alert_body(t, d), t["id"])
            elif kind == "digest":
                events = []
                for it in d.get("items", []):
                    r = self._upsert(it["asset"], "Important", it["case"], it.get("department", ""), it)
                    events.append((r["ticket"], r["event"]))
                self._daily_digests(events)
                result["tickets"] = [t["id"] for t, _ in events]
            elif kind == "run_summary":
                self._close_missing(d)
                self.state["runs"].append({"time": msg["received"], "mode": d.get("mode"),
                                           "case_counts": d.get("case_counts", {}),
                                           "n_assets": len(d.get("assets", []))})
                self._maybe_weekly_report()
            self._save()
            return result

    def _close_missing(self, summary: Dict[str, Any]) -> None:
        """Tickets whose asset is in this run but no longer at that risk are resolved automatically."""
        now_risk = {_key(a["asset"]): a["risk"] for a in summary.get("assets", [])}
        for k, t in self.state["tickets"].items():
            if t["status"] in OPEN_STATES and k in now_risk and now_risk[k] not in ("Critical", "Important"):
                t["status"] = "resolved"
                self._history(t, "resolved", f"now {now_risk[k]} in the latest run")

    def _daily_digests(self, events: List[Any]) -> None:
        """One digest e-mail per department per day, listing its open Important tickets."""
        today = self.clock().date().isoformat()
        by_dept: Dict[str, List[Dict[str, Any]]] = {}
        for t, ev in events:
            if ev != "suppressed" and t["status"] in OPEN_STATES:
                by_dept.setdefault(t["department"] or "(no department in ledger)", []).append(t)
        for dept, ts in by_dept.items():
            if self.state["last_digest_day"].get(dept) == today:
                continue
            self.state["last_digest_day"][dept] = today
            lines = [f"{len(ts)} open Important assets for {dept} (StrayHost, {today}):", ""]
            for t in ts:
                lines.append(f"- #{t['id']} case {t['case']} {t['asset']}: {t['detail'].get('case_meaning', '')}")
            to = self._addr("department", dept if not dept.startswith("(") else "")
            self._mail(to, f"[StrayHost] Daily digest for {dept}: {len(ts)} assets", "\n".join(lines))

    def _alert_body(self, t: Dict[str, Any], d: Dict[str, Any]) -> str:
        lines = [d.get("text", ""), "", f"Ticket #{t['id']} (department: {t['department'] or 'not in ledger'})"]
        if d.get("why_combined"):
            lines.append("Why these records were combined: " + d["why_combined"])
        for k in d.get("kept_apart", [])[:5]:
            lines.append(f"Kept separate from {'/'.join(k.get('other') or []) or '(no name)'}: {k.get('evidence')}")
        return "\n".join(lines)

    # ------------------------------------------------------------- analysts
    def act(self, ticket_id: int, action: str, note: str = "", by: str = "analyst") -> Dict[str, Any]:
        if action not in ACTIONS:
            raise ValueError(f"unknown action {action!r}")
        with self.lock:
            t = next((t for t in self.state["tickets"].values() if t["id"] == ticket_id), None)
            if t is None:
                raise KeyError(ticket_id)
            t["status"] = ACTIONS[action]
            if action == "reopen":
                t["opened"], t["escalations"] = _iso(self.clock()), 0
            self._history(t, action, note, by)
            self._save()
            return t

    # ------------------------------------------------------------ escalation
    def check_escalations(self) -> List[int]:
        """Open (not acknowledged) tickets past their deadline are escalated once per deadline period."""
        out = []
        with self.lock:
            now = self.clock()
            for t in self.state["tickets"].values():
                if t["status"] != "open" or t["risk"] not in self.sla:
                    continue
                period = timedelta(minutes=self.sla[t["risk"]])
                due = datetime.fromisoformat(t["opened"]) + period * (t["escalations"] + 1)
                if now >= due:
                    t["escalations"] += 1
                    self._history(t, "escalated", f"open for more than {int(period.total_seconds() // 60) * t['escalations']} minutes")
                    to = self._addr("escalation") or self._addr("security")
                    self._mail(to, f"[StrayHost] ESCALATION #{t['id']} {t['risk']} case {t['case']} {t['asset']}",
                               f"Ticket #{t['id']} for {t['asset']} has been open since {t['opened']} without acknowledgement.\n\n"
                               + (t["detail"].get("text") or t["detail"].get("case_meaning", "")), t["id"])
                    out.append(t["id"])
            if out:
                self._save()
        return out

    # ---------------------------------------------------------------- report
    def report(self) -> Dict[str, Any]:
        with self.lock:
            return self._report()

    def _report(self) -> Dict[str, Any]:
        if True:
            runs = self.state["runs"]
            last = runs[-1] if runs else {"case_counts": {}, "n_assets": 0}
            cc = last.get("case_counts", {})
            n = max(sum(cc.values()), 1)
            tickets = list(self.state["tickets"].values())

            def mins(t: Dict[str, Any]) -> Optional[float]:
                res = [h for h in t["history"] if h["action"] in ("resolve", "resolved")]
                if not res:
                    return None
                return (datetime.fromisoformat(res[-1]["time"]) - datetime.fromisoformat(t["created"])).total_seconds() / 60
            done = [m for m in (mins(t) for t in tickets) if m is not None]
            by_dept: Dict[str, Dict[str, int]] = {}
            for t in tickets:
                if t["status"] in OPEN_STATES:
                    row = by_dept.setdefault(t["department"] or "(not in ledger)", {"Critical": 0, "Important": 0})
                    row[t["risk"]] = row.get(t["risk"], 0) + 1
            return {
                "latest_run": last.get("time"), "runs": len(runs), "assets": sum(cc.values()), "case_counts": cc,
                "healthy_ratio": round(cc.get("B", 0) / n, 3),            # managed, internal only
                "unprotected_ratio": round(cc.get("C", 0) / n, 3),        # exposed without EDR
                "shadow_it_ratio": round((cc.get("D", 0) + cc.get("F", 0) + cc.get("G", 0)) / n, 3),
                "possibly_retired_ratio": round(cc.get("E", 0) / n, 3),   # ledger only, not detected
                "open_tickets": {r: sum(1 for t in tickets if t["status"] in OPEN_STATES and t["risk"] == r)
                                 for r in ("Critical", "Important")},
                "escalated_open": sum(1 for t in tickets if t["status"] in OPEN_STATES and t["escalations"]),
                "approved": sum(1 for t in tickets if t["status"] == "approved"),
                "false_positives": sum(1 for t in tickets if t["status"] == "false_positive"),
                "resolved": sum(1 for t in tickets if t["status"] == "resolved"),
                "mean_minutes_to_resolve": round(sum(done) / len(done), 1) if done else None,
                "open_by_department": by_dept,
            }

    def _report_text(self, r: Dict[str, Any]) -> str:
        cc = r["case_counts"]
        lines = [f"StrayHost report ({r['latest_run']}, {r['assets']} assets)", "",
                 "Assets by case: " + ", ".join(f"{c} {cc.get(c, 0)}" for c in "ABCDEFG"),
                 f"Managed, internal only (B): {r['healthy_ratio']:.1%}",
                 f"Exposed without EDR (C): {r['unprotected_ratio']:.1%}",
                 f"Not in the ledger (D, F, G): {r['shadow_it_ratio']:.1%}",
                 f"Ledger only, not detected (E): {r['possibly_retired_ratio']:.1%}",
                 f"Open tickets: Critical {r['open_tickets']['Critical']}, Important {r['open_tickets']['Important']} "
                 f"(escalated {r['escalated_open']}); resolved {r['resolved']}, approved {r['approved']}, "
                 f"false positives {r['false_positives']}"]
        if r["mean_minutes_to_resolve"] is not None:
            lines.append(f"Mean time to resolve: {r['mean_minutes_to_resolve']} minutes")
        return "\n".join(lines)

    def _maybe_weekly_report(self) -> None:
        last = self.state.get("last_weekly_report")
        if last and self.clock() - datetime.fromisoformat(last) < timedelta(days=7):
            return
        self.state["last_weekly_report"] = _iso(self.clock())
        text = self._report_text(self._report())
        self._mail(self._addr("report") or self._addr("security"), "[StrayHost] Weekly report", text)


# --------------------------------------------------------------------- web
PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>StrayHost console</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--muted:#5f6368;--line:#e3e5e8;--crit:#b00020;--crit-bg:#fdecee;--imp:#8a5a00;--imp-bg:#fff6e0;--ai:#1d5faf;--ai-bg:#eef4fb;--ok:#1e6b34}
@media (prefers-color-scheme:dark){:root{--bg:#141517;--fg:#ececec;--muted:#a0a4aa;--line:#2c2f33;--crit:#ff7a8a;--crit-bg:#3a1a20;--imp:#f0c060;--imp-bg:#3a2e10;--ai:#8ab8ff;--ai-bg:#16263d;--ok:#7fd99a}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--fg)}
header{padding:12px 20px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:center;flex-wrap:wrap}
header h1{font-size:18px;margin:0}nav button{background:none;border:0;color:var(--muted);font:inherit;padding:6px 10px;cursor:pointer;border-radius:8px}
nav button.on{color:var(--fg);background:var(--ai-bg)}
main{display:grid;grid-template-columns:minmax(280px,420px) 1fr;height:calc(100vh - 57px)}
#list{border-right:1px solid var(--line);overflow:auto}#detail{overflow:auto;padding:18px 22px}
.item{padding:10px 16px;border-bottom:1px solid var(--line);cursor:pointer}.item:hover,.item.sel{background:var(--ai-bg)}
.badge{display:inline-block;font-size:12px;font-weight:700;padding:1px 8px;border-radius:10px;margin-right:6px}
.Critical{color:var(--crit);background:var(--crit-bg)}.Important{color:var(--imp);background:var(--imp-bg)}
.st{font-size:12px;color:var(--muted);margin-left:6px}.t{font-weight:600}.sub{color:var(--muted);font-size:13px}
pre{white-space:pre-wrap;font:inherit;margin:0}.box{border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:12px 0}
.ai{background:var(--ai-bg);border-color:transparent}.ai h3{color:var(--ai)}h2{font-size:18px;margin:0 0 4px}h3{font-size:14px;margin:0 0 6px}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid var(--line);padding:4px 6px;text-align:left;vertical-align:top}
.actions button{font:inherit;padding:5px 10px;margin:0 6px 6px 0;border:1px solid var(--line);background:var(--bg);color:var(--fg);border-radius:8px;cursor:pointer}
.actions input{font:inherit;padding:5px 8px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);width:60%}
.filters{padding:8px 16px;border-bottom:1px solid var(--line);display:flex;gap:8px;flex-wrap:wrap}
.filters select{font:inherit;padding:3px 6px;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px}
.empty{color:var(--muted);padding:24px}.metric{display:inline-block;margin:0 18px 10px 0}.metric b{font-size:22px;display:block}
@media (max-width:760px){main{grid-template-columns:1fr;height:auto}#list{border-right:0;max-height:45vh}}
</style></head><body>
<header><h1>StrayHost console</h1><nav>
<button data-v="tickets" class="on">Tickets</button><button data-v="outbox">E-mail</button><button data-v="report">Report</button><button data-v="feed">Notifications</button>
</nav><span class="sub" id="count"></span></header>
<main><div id="list"></div><div id="detail"><div class="empty">Select an item.</div></div></main>
<script>
let view="tickets",S=null,sel=null,fs="open",fr="all",fd="all";
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
document.querySelectorAll("nav button").forEach(b=>b.onclick=()=>{view=b.dataset.v;sel=null;document.querySelectorAll("nav button").forEach(x=>x.classList.toggle("on",x===b));render()});
function recTable(recs){let h="";for(const src of ["ledger","edr","asm"]){for(const r of (recs||{})[src]||[]){const kv=Object.entries(r).filter(([k,v])=>!k.startsWith("_")&&v!==""&&v!=null).map(([k,v])=>`${esc(k)}=${esc(v)}`).join(", ");h+=`<tr><th>${src}</th><td>${kv}</td></tr>`}}return h?`<table>${h}</table>`:""}
function tickets(){let ts=Object.values(S.tickets).sort((a,b)=>b.id-a.id);
  if(fs==="open")ts=ts.filter(t=>t.status==="open"||t.status==="acknowledged");else if(fs!=="all")ts=ts.filter(t=>t.status===fs);
  if(fr!=="all")ts=ts.filter(t=>t.risk===fr);if(fd!=="all")ts=ts.filter(t=>(t.department||"")===fd);return ts}
function render(){if(!S)return;const L=document.getElementById("list");
  const nOpen=Object.values(S.tickets).filter(t=>t.status==="open"||t.status==="acknowledged").length;
  document.getElementById("count").textContent=`${nOpen} open tickets · ${S.outbox.length} e-mails · ${S.messages.length} notifications`;
  if(view==="tickets"){const depts=[...new Set(Object.values(S.tickets).map(t=>t.department||""))].sort();
    let h=`<div class="filters"><select id="fs">${["open","all","resolved","approved","false_positive"].map(x=>`<option ${x===fs?"selected":""}>${x}</option>`).join("")}</select>
    <select id="fr">${["all","Critical","Important"].map(x=>`<option ${x===fr?"selected":""}>${x}</option>`).join("")}</select>
    <select id="fd"><option value="all">all departments</option>${depts.map(x=>`<option value="${esc(x)}" ${x===fd?"selected":""}>${esc(x||"(not in ledger)")}</option>`).join("")}</select></div>`;
    h+=tickets().map(t=>`<div class="item ${sel===t.id?"sel":""}" data-id="${t.id}"><span class="badge ${esc(t.risk)}">${esc(t.risk)}</span><span class="t">#${t.id} ${esc(t.asset)}</span><span class="st">${esc(t.status)}${t.escalations?" · escalated":""}</span><div class="sub">case ${esc(t.case)} · ${esc(t.department||"not in ledger")} · seen ${t.seen_count}× · ${esc(t.updated)}</div></div>`).join("")||`<div class="empty">No tickets.</div>`;
    L.innerHTML=h;["fs","fr","fd"].forEach(id=>document.getElementById(id).onchange=e=>{if(id==="fs")fs=e.target.value;if(id==="fr")fr=e.target.value;if(id==="fd")fd=e.target.value;render()});
    L.querySelectorAll(".item").forEach(e=>e.onclick=()=>{sel=+e.dataset.id;render()});
    if(sel!=null)showTicket(Object.values(S.tickets).find(t=>t.id===sel));}
  else if(view==="outbox"){L.innerHTML=S.outbox.map((m,i)=>`<div class="item ${sel===i?"sel":""}" data-i="${i}"><span class="t">${esc(m.subject)}</span><div class="sub">${esc(m.status)} · to ${esc((m.to||[]).join(", ")||"(no address)")} · ${esc(m.time)}</div></div>`).reverse().join("")||`<div class="empty">No e-mail yet.</div>`;
    L.querySelectorAll(".item").forEach(e=>e.onclick=()=>{sel=+e.dataset.i;render()});
    if(sel!=null){const m=S.outbox[sel];document.getElementById("detail").innerHTML=`<h2>${esc(m.subject)}</h2><div class="sub">${esc(m.status)}${m.reason?" — "+esc(m.reason):""} · to ${esc((m.to||[]).join(", ")||"(no address)")} · ${esc(m.time)}</div><div class="box"><pre>${esc(m.body)}</pre></div>`}}
  else if(view==="report"){L.innerHTML=`<div class="empty">Latest run and ticket metrics.</div>`;fetch("/api/report").then(r=>r.json()).then(r=>{const cc=r.case_counts||{};
    document.getElementById("detail").innerHTML=`<h2>Report</h2><div class="sub">latest run ${esc(r.latest_run||"-")} · ${r.runs} runs</div>
    <div class="box"><div class="metric"><b>${r.assets}</b>assets</div><div class="metric"><b>${(r.healthy_ratio*100).toFixed(1)}%</b>managed, internal only (B)</div><div class="metric"><b>${(r.unprotected_ratio*100).toFixed(1)}%</b>exposed without EDR (C)</div><div class="metric"><b>${(r.shadow_it_ratio*100).toFixed(1)}%</b>not in the ledger (D, F, G)</div><div class="metric"><b>${(r.possibly_retired_ratio*100).toFixed(1)}%</b>ledger only, not detected (E)</div></div>
    <div class="box"><h3>Assets by case</h3><table><tr>${"ABCDEFG".split("").map(c=>`<th>${c}</th>`).join("")}</tr><tr>${"ABCDEFG".split("").map(c=>`<td>${cc[c]||0}</td>`).join("")}</tr></table></div>
    <div class="box"><h3>Tickets</h3>open Critical ${r.open_tickets.Critical}, open Important ${r.open_tickets.Important}, escalated ${r.escalated_open}, resolved ${r.resolved}, approved ${r.approved}, false positives ${r.false_positives}${r.mean_minutes_to_resolve!=null?`, mean time to resolve ${r.mean_minutes_to_resolve} min`:""}
    <table><tr><th>department</th><th>Critical</th><th>Important</th></tr>${Object.entries(r.open_by_department).map(([d,v])=>`<tr><td>${esc(d)}</td><td>${v.Critical||0}</td><td>${v.Important||0}</td></tr>`).join("")}</table></div>`})}
  else{L.innerHTML=S.messages.map((m,i)=>{const d=m.strayhost||{};return `<div class="item ${sel===i?"sel":""}" data-i="${i}"><span class="badge ${esc(d.risk||"")}">${esc(d.risk||d.kind||"")}</span><span class="t">${esc(d.title||String(m.text||"").split("\n")[0])}</span><div class="sub">${esc(m.received)}</div></div>`}).reverse().join("")||`<div class="empty">Waiting for notifications.</div>`;
    L.querySelectorAll(".item").forEach(e=>e.onclick=()=>{sel=+e.dataset.i;render()});
    if(sel!=null){const m=S.messages[sel];document.getElementById("detail").innerHTML=`<div class="box"><pre>${esc(m.text)}</pre></div>`}}}
function showTicket(t){if(!t)return;const d=t.detail||{};
  let h=`<h2>#${t.id} ${esc(t.asset)}</h2><div class="sub"><span class="badge ${esc(t.risk)}">${esc(t.risk)}</span>case ${esc(t.case)} · ${esc(t.status)} · department ${esc(t.department||"not in ledger")} · opened ${esc(t.opened)} · seen ${t.seen_count}×${t.escalations?` · escalated ${t.escalations}×`:""}</div>
  <div class="box actions"><button data-a="acknowledge">Acknowledge</button><button data-a="resolve">Resolve</button><button data-a="approve">Approve (known asset)</button><button data-a="false_positive">False positive</button><button data-a="reopen">Reopen</button><br><input id="note" placeholder="note (optional)"></div>`;
  if(d.text)h+=`<div class="box"><pre>${esc(d.text)}</pre></div>`;else if(d.case_meaning)h+=`<div class="box">${esc(d.case_meaning)}</div>`;
  if(d.text_source==="llm")h+=`<div class="sub">Alert text written by the LLM; every IP address and host name in it was found in the records below.</div>`;
  if(d.llm_merges&&d.llm_merges.length)h+=`<div class="box ai"><h3>Why the LLM combined these records</h3>`+d.llm_merges.map(x=>`<p><b>${esc((x.names_a||[]).join("/")||"(no name)")}</b> + <b>${esc((x.names_b||[]).join("/")||"(no name)")}</b> (confidence ${esc(x.confidence)}): ${esc(x.evidence)}</p>`).join("")+`</div>`;
  if(d.kept_apart&&d.kept_apart.length)h+=`<div class="box"><h3>Records the LLM kept separate from this asset</h3>`+d.kept_apart.map(x=>`<p><b>${esc((x.other||[]).join("/")||"(no name)")}</b> (confidence ${esc(x.confidence)}): ${esc(x.evidence)}</p>`).join("")+`</div>`;
  const rt=recTable(d.records);if(rt)h+=`<div class="box"><h3>Observed records</h3>${rt}</div>`;
  h+=`<div class="box"><h3>History</h3><table>${t.history.map(x=>`<tr><td>${esc(x.time)}</td><td>${esc(x.action)}</td><td>${esc(x.by)}</td><td>${esc(x.note)}</td></tr>`).join("")}</table></div>`;
  const D=document.getElementById("detail");D.innerHTML=h;
  D.querySelectorAll("[data-a]").forEach(b=>b.onclick=async()=>{await fetch(`/api/tickets/${t.id}/action`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:b.dataset.a,note:document.getElementById("note").value})});poll(true)})}
async function poll(once){try{const r=await fetch("/api/state");const s=await r.json();const changed=!S||JSON.stringify(s)!==JSON.stringify(S);S=s;if(changed)render()}catch(e){}if(!once)setTimeout(poll,1500)}
poll();
</script></body></html>"""


def make_handler(console: Console):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # quiet
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj: Any) -> None:
            self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json")

        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
            return host in ("127.0.0.1", "localhost", "::1")

        def _body(self) -> Dict[str, Any]:
            if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
                raise PermissionError("Content-Type must be application/json")
            n = int(self.headers.get("Content-Length", "0"))
            if not 0 < n <= 2_000_000:
                raise ValueError("bad length")
            obj = json.loads(self.rfile.read(n).decode("utf-8"))
            if not isinstance(obj, dict):
                raise ValueError("expected a JSON object")
            return obj

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, b"forbidden", "text/plain")
            if self.path in ("/", "/index.html"):
                return self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
            if self.path == "/api/state":
                return self._json(200, console.snapshot())
            if self.path == "/api/report":
                return self._json(200, console.report())
            self._send(404, b"not found", "text/plain")

        def do_POST(self):
            if not self._host_ok():
                return self._send(403, b"forbidden", "text/plain")
            try:
                body = self._body()
            except PermissionError as e:
                return self._send(415, str(e).encode(), "text/plain")
            except Exception as e:  # noqa: BLE001
                return self._send(400, f"bad request: {e}".encode(), "text/plain")
            if self.path == "/hook":
                if not isinstance(body.get("text"), str):
                    return self._send(400, b"bad request: expected {'text': ...}", "text/plain")
                return self._json(200, console.receive(body))
            parts = self.path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["api", "tickets"] and parts[3] == "action" and parts[2].isdigit():
                try:
                    t = console.act(int(parts[2]), str(body.get("action")), str(body.get("note") or "")[:500])
                except KeyError:
                    return self._send(404, b"no such ticket", "text/plain")
                except ValueError as e:
                    return self._send(400, str(e).encode(), "text/plain")
                return self._json(200, {"id": t["id"], "status": t["status"]})
            self._send(404, b"not found", "text/plain")

    return Handler


def serve(port: int, console: Console, open_browser: bool = True, escalation_interval: float = 30.0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(console))
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    mail = "SMTP " + console.mailer.host if console.mailer.configured else "e-mail kept in the outbox (SMTP not configured)"
    print(f"StrayHost console: {url}  (webhook: {url}hook; {mail})  Ctrl+C to stop", file=sys.stderr)

    def escalate_loop():
        while True:
            time.sleep(escalation_interval)
            try:
                console.check_escalations()
            except Exception as e:  # noqa: BLE001
                print(f"[warn] escalation check failed: {e}", file=sys.stderr)
    threading.Thread(target=escalate_loop, daemon=True).start()
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    return srv
