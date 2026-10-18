#!/usr/bin/env python3
"""Stand-in for the `claude` CLI in tests: prints stream-json like `claude -p --output-format stream-json`.
Invoked under a name containing "apikey" it reports API-key billing; "nokeysource" omits the field."""
import json, os, re, sys
prompt = sys.stdin.read()
name = os.path.basename(sys.argv[0])
init = {"type": "system", "subtype": "init", "model": sys.argv[sys.argv.index("--model") + 1]}
if "nokeysource" not in name:
    init["apiKeySource"] = "ANTHROPIC_API_KEY" if "apikey" in name else "none"
print(json.dumps(init))
ids = sorted({int(n) for n in re.findall(r'"pair_id"\s*:\s*(\d+)', prompt)})
if ids:
    text = json.dumps({"verdicts": [{"pair_id": i, "same_asset": True, "confidence": 0.9, "evidence": "fake claude"} for i in ids]})
else:
    text = "The asm scan saw this host but neither the ledger nor the EDR did. Find the owner."
print(json.dumps({"type": "result", "subtype": "success", "is_error": False, "result": text}))
