"""A local notification inbox: a Slack-compatible webhook receiver plus a browser view.

    python run.py inbox            # http://127.0.0.1:8765/
    python run.py run --input DIR --webhook http://127.0.0.1:8765/hook

Binds to 127.0.0.1 only. Messages are kept in memory and appended to inbox.jsonl.
"""

from __future__ import annotations

import json
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List

PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>StrayHost inbox</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--muted:#5f6368;--line:#e3e5e8;--crit:#b00020;--crit-bg:#fdecee;--imp:#8a5a00;--imp-bg:#fff6e0;--ai:#1d5faf;--ai-bg:#eef4fb}
@media (prefers-color-scheme:dark){:root{--bg:#141517;--fg:#ececec;--muted:#a0a4aa;--line:#2c2f33;--crit:#ff7a8a;--crit-bg:#3a1a20;--imp:#f0c060;--imp-bg:#3a2e10;--ai:#8ab8ff;--ai-bg:#16263d}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--fg)}
header{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:baseline}
header h1{font-size:18px;margin:0}header span{color:var(--muted);font-size:13px}
main{display:grid;grid-template-columns:minmax(260px,380px) 1fr;height:calc(100vh - 53px)}
#list{border-right:1px solid var(--line);overflow:auto}#detail{overflow:auto;padding:20px 24px}
.item{padding:10px 16px;border-bottom:1px solid var(--line);cursor:pointer}.item:hover,.item.sel{background:var(--ai-bg)}
.badge{display:inline-block;font-size:12px;font-weight:700;padding:1px 8px;border-radius:10px;margin-right:6px}
.Critical{color:var(--crit);background:var(--crit-bg)}.Important{color:var(--imp);background:var(--imp-bg)}
.t{font-weight:600}.sub{color:var(--muted);font-size:13px}
pre{white-space:pre-wrap;font:inherit;margin:0}
.box{border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:12px 0}
.ai{background:var(--ai-bg);border-color:transparent}.ai h3{color:var(--ai)}
h2{font-size:18px;margin:0 0 4px}h3{font-size:14px;margin:0 0 6px}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid var(--line);padding:4px 6px;text-align:left;vertical-align:top}
.empty{color:var(--muted);padding:24px}
@media (max-width:720px){main{grid-template-columns:1fr;height:auto}#list{border-right:0;max-height:45vh}}
</style></head><body>
<header><h1>StrayHost inbox</h1><span id="count">waiting for notifications…</span></header>
<main><div id="list"></div><div id="detail"><div class="empty">Select a notification.</div></div></main>
<script>
let msgs=[],sel=-1;
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function renderList(){
  document.getElementById("count").textContent=msgs.length+" notifications";
  document.getElementById("list").innerHTML=msgs.map((m,i)=>{const d=m.strayhost||{};
    return `<div class="item ${i===sel?"sel":""}" onclick="pick(${i})"><span class="badge ${esc(d.risk)}">${esc(d.risk||"")}</span><span class="t">${esc(d.title||String(m.text||"").split("\n")[0])}</span><div class="sub">${esc(m.received)}${d.text_source==="llm"?" · written by LLM, checked":""}</div></div>`}).reverse().join("");
}
function recTable(recs){let h="";for(const src of ["ledger","edr","asm"]){for(const r of (recs||{})[src]||[]){
  const kv=Object.entries(r).filter(([k,v])=>!k.startsWith("_")&&v!==""&&v!=null).map(([k,v])=>`${esc(k)}=${esc(v)}`).join(", ");
  h+=`<tr><th>${src}</th><td>${kv}</td></tr>`}}return h?`<table>${h}</table>`:""}
function pick(i){sel=i;renderList();const m=msgs[i],d=m.strayhost||{};
  let h=`<h2>${esc(d.title||"")}</h2><div class="sub">${esc(m.received)}</div><div class="box"><pre>${esc(d.text||m.text)}</pre></div>`;
  if(d.text_source==="llm")h+=`<div class="sub">Alert text written by the LLM. Every IP address and hostname in it was found in the records below.</div>`;
  if(d.check&&d.check.rejected)h+=`<div class="box"><h3>LLM text rejected</h3><div class="sub">It mentioned values not in the records: ${esc((d.check.unknown_mentions||[]).join(", "))}. The template text is shown instead.</div></div>`;
  if(d.llm_merges&&d.llm_merges.length){h+=`<div class="box ai"><h3>Why the LLM combined these records</h3>`+d.llm_merges.map(x=>`<p><b>${esc((x.names_a||[]).join("/")||"(no name)")}</b> + <b>${esc((x.names_b||[]).join("/")||"(no name)")}</b> (confidence ${esc(x.confidence)}): ${esc(x.evidence)}</p>`).join("")+`</div>`}
  if(d.kept_apart&&d.kept_apart.length){h+=`<div class="box"><h3>Records the LLM kept separate from this asset</h3>`+d.kept_apart.map(x=>`<p><b>${esc((x.other||[]).join("/")||"(no name)")}</b> (confidence ${esc(x.confidence)}): ${esc(x.evidence)}</p>`).join("")+`</div>`}
  if(d.why_combined)h+=`<div class="box"><h3>Why combined</h3>${esc(d.why_combined)}</div>`;
  const t=recTable(d.records);if(t)h+=`<div class="box"><h3>Observed records</h3>${t}</div>`;
  document.getElementById("detail").innerHTML=h}
async function poll(){try{const r=await fetch("/api/messages");const all=await r.json();if(all.length!==msgs.length){msgs=all;renderList();if(sel<0&&msgs.length)pick(msgs.length-1)}}catch(e){}setTimeout(poll,1000)}
poll();
</script></body></html>"""


class _State:
    def __init__(self, log_path: Path) -> None:
        self.messages: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        self.log_path = log_path


def make_handler(state: _State):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # quiet
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _host_ok(self) -> bool:
            # only requests addressed to this machine by name or loopback IP (blocks DNS rebinding)
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
            return host in ("127.0.0.1", "localhost", "::1")

        def do_GET(self):
            if not self._host_ok():
                self._send(403, b"forbidden", "text/plain")
                return
            if self.path in ("/", "/index.html"):
                self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
            elif self.path == "/api/messages":
                with state.lock:
                    data = json.dumps(state.messages, ensure_ascii=False).encode("utf-8")
                self._send(200, data, "application/json")
            else:
                self._send(404, b"not found", "text/plain")

        def do_POST(self):
            if not self._host_ok():
                self._send(403, b"forbidden", "text/plain")
                return
            if self.path != "/hook":
                self._send(404, b"not found", "text/plain")
                return
            # JSON only: a web page cannot send this content type cross-site without a preflight
            if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
                self._send(415, b"Content-Type must be application/json", "text/plain")
                return
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if not 0 < n <= 2_000_000:
                    raise ValueError("bad length")
                msg = json.loads(self.rfile.read(n).decode("utf-8"))
                if not isinstance(msg, dict) or not isinstance(msg.get("text"), str):
                    raise ValueError("expected {'text': ...}")
            except Exception as e:  # noqa: BLE001
                self._send(400, f"bad request: {e}".encode(), "text/plain")
                return
            import datetime as _dt
            msg["received"] = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with state.lock:
                state.messages.append(msg)
                with open(state.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(msg, ensure_ascii=False) + "\n")
            self._send(200, b"ok", "text/plain")

    return Handler


def serve(port: int = 8765, log_path: Path = Path("inbox.jsonl"), open_browser: bool = True) -> ThreadingHTTPServer:
    state = _State(log_path)
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    print(f"StrayHost inbox: {url}  (webhook: {url}hook)  Ctrl+C to stop", file=sys.stderr)
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    return srv
