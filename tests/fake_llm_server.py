"""A tiny OpenAI-compatible server for tests. It does not run any model: it answers
"same device" for every pair it is asked about, so tests can check the HTTP path,
response parsing, merging and the explanation output without a real LLM or API key."""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _Handler(BaseHTTPRequestHandler):
    seen_auth = []
    prompts = []
    requests = 0
    fail_every = 0
    scripted = []  # list of (status, body, headers) returned before normal answers

    def log_message(self, *args):  # silence
        pass

    def do_POST(self):
        if not self.path.endswith("/chat/completions"):
            self.send_response(404); self.end_headers(); return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Handler.requests += 1
        _Handler.seen_auth.append(self.headers.get("Authorization"))
        prompt = " ".join(m["content"] for m in body["messages"])
        _Handler.prompts.append(prompt)
        if _Handler.scripted:
            status, text, headers = _Handler.scripted.pop(0)
            data = text.encode()
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if _Handler.fail_every and _Handler.requests % _Handler.fail_every == 0:
            self.send_response(400); self.end_headers(); self.wfile.write(b"bad request"); return
        ids = sorted({int(n) for n in re.findall(r'"pair_id"\s*:\s*(\d+)', prompt)})
        content = json.dumps({"verdicts": [
            {"pair_id": i, "same_asset": True, "confidence": 0.9, "evidence": "fake server: names differ only by suffix"}
            for i in ids]})
        out = json.dumps({"choices": [{"message": {"role": "assistant", "content": content}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def reset():
    _Handler.seen_auth, _Handler.prompts, _Handler.requests, _Handler.fail_every = [], [], 0, 0
    _Handler.scripted = []


def start(fail_every=0):
    _Handler.fail_every = fail_every
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/v1"
