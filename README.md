# StrayHost

**Three inventories. One cross-examination. The hosts nobody owns.**

Every organisation has three lists of its machines: the asset ledger (CMDB), the EDR console and an external attack-surface scan (ASM). Each one is "green". The machine an attacker will use is the one that is missing from one of them — exposed to the Internet, but not in the ledger and not running an EDR agent.

Finding it means reconciling the three lists, and they never agree: `WKS-C06F3` in one, `wks-c06f3-01.corp.local` in another, a different IP after a DHCP renewal, a public address behind NAT. StrayHost reads the three exports, lets an LLM decide which records are the same machine, classifies every asset by which lists it appears in, and **notifies you about the stray hosts — with the evidence**.

> **Status:** research prototype. Bundled data is synthetic (generated). No accuracy claim is made for real networks.

## No merge without a reason

Automatic reconciliation fails in two ways:

- **Too strict:** name variants are treated as different machines. You get a flood of false "unmanaged host" alerts.
- **Too loose:** a stray host is merged into a managed machine with a similar name. **Its alert disappears.** In asset reconciliation, a wrong merge is a missed detection.

Even "obvious" matches fail: a replaced machine inherits the old hostname, devices behind NAT share one public IP, `www.a.example` and `www.b.example` share a first label. So in StrayHost **nothing is combined unless the LLM confirmed it, with a reason**, and every doubt falls on the side that keeps a possible stray host visible:

| Rule | Why |
|---|---|
| Records that share an identifier (asset ID, hostname, IP) are only *candidates*; the LLM decides each pair | a shared IP or reused name is not proof |
| Look-alike groups (similar names, or no name and the same /24) are asked about in a second step | name variants get combined only with evidence |
| Combine only on "same device" with confidence ≥ 0.5; unsure, malformed or failed → keep separate | a wrong merge hides a stray host; a wrong split only adds an alert |
| In the look-alike step, at most 2 groups are combined into one asset | one bad answer cannot chain many machines together |
| Every judgement is logged with its reason (`llm_adjudications.jsonl`) | you can audit why two records became one |
| LLM-written alert text is checked: if it names an IPv4 address or a host/domain name (a name with a digit or a dot) that is not in the records, the text is rejected and the template text is sent | the alert does not cite addresses or hosts that were never observed |

The matching prompt tells the model to answer "different" when the evidence is balanced. In our earlier evaluation on synthetic noise-style data (10 datasets at noise level 0.2, Claude Haiku 4.5), the LLM was asked about 19,235 look-alike pairs that belonged to different devices and answered "same device" for none of them. (In that evaluation, records sharing an identifier were joined by rules without asking the LLM, and the prompt was in Japanese; StrayHost now asks the LLM about those pairs too, with an English translation of that prompt.)

## What it does

1. **Read** `ledger.csv`, `edr.csv`, `asm.csv`.
2. **Find candidates:** pairs of records that share an asset ID, hostname (ignoring case and domain) or IP address.
3. **Let the LLM decide** each candidate pair, then the look-alike groups (as above). Only confirmed pairs are combined.
4. **Classify** each asset by the lists it appears in (no LLM):

The cases and risk levels are those of the three-way reconciliation matrix in Aki et al., "Triad Integration for IT Asset Governance: AI Agent–Driven Convergence of ITAM, ASM, and EDR" (ICSPIS 2025):

| Case | Ledger (ITAM) | EDR | ASM | Situation | Risk | Notification |
|---|:-:|:-:|:-:|---|---|---|
| A | ✓ | ✓ | ✓ | managed, visible externally (check vulnerabilities) | Important | daily digest |
| B | ✓ | ✓ | | managed, internal only | Informational | weekly report |
| **C** | ✓ | | ✓ | **externally visible without EDR (unprotected)** | **Critical** | **immediate alert** |
| **D** | | ✓ | ✓ | **not in ledger, seen by EDR and externally (shadow IT)** | **Critical** | **immediate alert** |
| E | ✓ | | | ledger only, not detected (retired or inactive) | Important | daily digest |
| F | | ✓ | | not in ledger, seen by EDR (unmanaged internal) | Important | daily digest |
| **G** | | | ✓ | **externally visible only, unknown internally** | **Critical** | **immediate alert** |

5. **Notify:** one alert per Critical asset (C, D, G), written by the LLM from the observed records and checked; one digest for A, E, F. Send them to any Slack-compatible incoming webhook, or to the built-in console.

## Console: tickets, routing, escalation, e-mail, reports

`python run.py console --data console_data --routing examples/routing.json` starts a local web console (http://127.0.0.1:8765/) that receives the notifications on `/hook` and runs the operations of the paper:

| Situation | What the console does |
|---|---|
| New Critical asset (C, D, G) | opens a ticket; e-mails the security team at once, and the owning department if the ledger names one |
| Important assets (A, E, F) | open tickets; every day at `--digest-hour` (default 9), one digest e-mail per department listing its open Important tickets |
| Informational (B) | counted in the report only |
| Same asset again while its ticket is open | no new e-mail; the ticket's "seen" count goes up |
| Ticket still unresolved at its deadline (`--sla-critical-minutes`, default 1 day; `--sla-important-minutes`, default 3 days) | escalated: e-mail to the escalation address, again at every further deadline; the deadline is shown on the ticket |
| Analyst marks a ticket *approved* (known asset) or *false positive*, or adds a suppression rule (name pattern such as `lab-*`) | later alerts for those assets are not sent; the decision is kept in the ticket history |
| A resolved asset is reported again | the ticket is reopened and e-mailed again |
| A later run reports the asset as Informational, or no longer reports it | the ticket is resolved automatically (a run summary with no assets is rejected and resolves nothing) |
| Every 7 days (first after the first run) | report e-mail; the Report tab shows the assets and share per case, the share of healthy assets (B) and of potentially undetected assets (E: in the ledger but not detected), open tickets per department, tickets past their deadline and the mean time to resolve |

Tickets are kept per asset, identified by the ledger asset ID, else the full host or domain name, else the IP address (if two assets of one run would get the same key, the later one gets a `#2` suffix). The Report tab also has buttons to send the digests and the report at once.

Routing (`--routing`, see `examples/routing.json`) maps the ledger's `owner_dept` to an e-mail address and names the security, escalation and report addresses. E-mail is sent in the background through SMTP when `CAASM_SMTP_HOST` is set (`CAASM_SMTP_PORT` 587 with STARTTLS or 465 with SMTPS, certificates verified; `CAASM_SMTP_USER`, `CAASM_SMTP_PASSWORD`, `CAASM_SMTP_FROM`); otherwise every message is kept in the console's E-mail tab and marked "not sent". State (tickets, decisions, e-mail, run history) is one JSON file in `--data`, so it survives restarts. The console listens on 127.0.0.1 only and accepts requests addressed to `127.0.0.1`/`localhost`, with JSON bodies only.

## Quick start

Python 3.10+. No packages to install.

```sh
python run.py console --routing examples/routing.json  # terminal 1: console, opens http://127.0.0.1:8765/
python run.py run --input examples/demo --out out --webhook http://127.0.0.1:8765/hook   # terminal 2
python run.py score --assets out/assets.json --truth examples/demo/truth.csv
```

Without an LLM configured this runs a rules-only baseline (records sharing any identifier are combined without review), so you can see the starting point: on the bundled demo (60 devices plus 12 look-alike decoy devices, 133 records), 37 Critical alerts, of which 13 are not a single correct alert for a real high-risk device, and 1 real high-risk device gets no Critical alert at all. Then configure an LLM and run again.

Open the console's Tickets tab to see the alerts, the records behind them and the LLM's reasons.

## Demo result (one run, Claude Haiku 4.5 via the Claude CLI)

On the bundled demo data (`examples/demo`, 133 records; 28 high-risk devices in cases C, D, G, 3 of them look-alike decoys; synthetic), with the code at commit 7be4ee3, which used the Japanese matching prompt. LLM answers vary from run to run, so another run can give slightly different numbers.

| | Rules only (baseline) | StrayHost (LLM decides every combination) |
|---|---|---|
| Real high-risk devices with no Critical alert at all (missed) | 1 | **0** |
| Critical alerts | 37 | **31** |
| — one correct alert for a real high-risk device | 24 | **26** |
| — duplicate, wrong device or wrong case | 13 | **5** |
| Pairwise F1 (precision / recall) | 0.667 (0.885 / 0.535) | **0.918 (1.000 / 0.849)** |
| Pairs of different devices the LLM called "same" | – | **0 of 45** (111 judgements in total) |
| Pairs of the same device left uncombined | – | 7 of 66 (6 judged "different"; 1 judged "same" but not applied because of the 2-group cap in the look-alike step) |
| Alert texts written by the LLM and passing the check | – | 31 of 31 |

The case that matters: `shdpub-0dab3` is exposed to the Internet, runs EDR, and is **not in the ledger** (case D). Behind NAT it shares the public address 203.0.114.41 with the managed server `pub-bd82f`. The rules join the two because the IP matches, and the stray host disappears into a managed asset — no Critical alert, just a line in the digest for `pub-bd82f`. StrayHost's LLM answered (translated from Japanese) *"they have the same shared address (203.0.114.41), but the hostnames are completely different (shdpub-0dab3 vs pub-bd82f); a shared IP alone is not enough"*, kept them apart, and raised the Critical alert.

The 5 remaining imperfect alerts are also imperfect in the baseline. 3 come from old `legacy-` records that the LLM kept separate from the same device (a different IP and, where both records are dated, five years apart): two give a duplicate alert, and one gives a Critical alert for a device whose current records are case A. In the other 2, the device's records share no identifier at all (the EDR record has no hostname, or the ASM record has no domain), so neither the rules nor StrayHost has a candidate pair: the device is alerted, but as case G instead of D or C.

## Choosing the LLM

**Claude with your subscription (Claude Code CLI, no API billing):**

```sh
export CAASM_LLM_BACKEND=claude-cli          # uses `claude -p`; model: CAASM_CLAUDE_MODEL (default claude-haiku-4-5-20251001)
# The CLI runs with an empty home folder, so it cannot see your normal login.
# Create a subscription token once with `claude setup-token`, save it to a file, and point to it:
export CAASM_CLAUDE_OAUTH_TOKEN_FILE=~/.strayhost_claude_token
```

StrayHost refuses to start if `ANTHROPIC_API_KEY` (or Bedrock/Vertex settings) is set, accepts only subscription tokens (`sk-ant-oat…`) in the token file, and stops unless the CLI confirms it is using the subscription. The CLI runs without tools, MCP servers or your settings, with only a few environment variables (PATH, proxy and certificate settings). Tested with the real Claude CLI on macOS; on Linux and Windows only with a stand-in CLI in the tests.

**Any OpenAI-compatible endpoint** (OpenAI, Gemini, Ollama, vLLM, LM Studio):

```sh
export CAASM_LLM_BASE_URL=http://localhost:11434/v1   # e.g. Ollama: data stays on your machine
export CAASM_LLM_MODEL=qwen2.5:14b                    # model names are examples
export CAASM_LLM_API_KEY=...                          # if the endpoint needs one
```

On Windows PowerShell use `$env:NAME="value"`. Keys are read from the environment only and never written to output files.

**Data sent to the LLM:** the records of the pairs being judged (and of Critical assets, for alert text), limited to the columns under *Input format*. Other columns are never sent. `--no-llm` forces rules only; `--no-ai-alerts` keeps template alert texts.

**Data sent to a webhook:** the alert title and text. Record details are attached only when the webhook is the local console (`127.0.0.1`/`localhost`).

The matching prompt is an English translation of the Japanese prompt used in our evaluation; the LLM's reasons and the alert texts are in English.

## Outputs (in `--out`)

| File | Contents |
|---|---|
| `assets.json`, `assets.csv` | every asset: case, risk, records, why it was combined |
| `notifications.json`, `alerts.md` | the alerts and digest that were sent |
| `llm_adjudications.jsonl` | every LLM judgement (step `link` or `lookalike`): the records on each side, answer, confidence, reason, applied or not |
| `report.html` | table of all assets |

## Input format

| File | Columns (header row required) |
|---|---|
| `ledger.csv` | `asset_id`, `hostname`, `ip`, `fqdn`, `instance_id`, `owner_dept`, `owner_user` |
| `edr.csv` | `asset_id_or_hostname`, `ip`, `observed_at`, `dest_ip`, `dest_fqdn` |
| `asm.csv` | `public_ip`, `domain`, `discovered_at`, `open_ports`, `vuln_score` |

Rename your export's columns to these names; files must be UTF-8. If no identifier column is found the run stops with a message.

## Test it on your own kind of mess

```sh
python run.py synth --style g1 --n 60 --p 0.2 --out mydata   # clean records + noise: name variants, look-alike decoys, NAT, stale records ... (ASM addresses in documentation ranges)
python run.py synth --style g2 --n 60 --p 0.2 --out mydata2  # records produced from device events: renames, DHCP, replacements, NAT
python run.py run --input mydata --out out_mine
python run.py score --assets out_mine/assets.json --truth mydata/truth.csv
```

`score` reports pairwise precision / recall / F1, how many high-risk devices were found with the right case, how many Critical alerts are not "one correct alert for one real high-risk device" (duplicates, wrong device or wrong case), and how many real high-risk devices got no Critical alert at all.

## Settings

| Environment variable | Default | Meaning |
|---|---|---|
| `CAASM_LLM_BACKEND` | `openai` | `openai` (any OpenAI-compatible endpoint) or `claude-cli` |
| `CAASM_LLM_BASE_URL`, `CAASM_LLM_MODEL`, `CAASM_LLM_API_KEY` | – | endpoint, model, key |
| `CAASM_CLAUDE_MODEL`, `CAASM_CLAUDE_BIN`, `CAASM_CLAUDE_EFFORT`, `CAASM_CLAUDE_OAUTH_TOKEN_FILE` | `claude-haiku-4-5-20251001`, `claude`, `low`, – | Claude CLI model, path, effort, subscription token file |
| `CAASM_LLM_WORKERS` | 8 | parallel requests (1–32; use 1–2 on free tiers) |
| `CAASM_LLM_BATCH_SIZE` | 25 | pairs per request (1–25) |
| `CAASM_LLM_MAX_CALLS` | none | stop after this many requests |
| `CAASM_LLM_MAX_CANDIDATES` | 3000 | maximum pairs sent to the LLM (most similar first) |
| `CAASM_LLM_GRAY_LOW` | 0.70 | minimum name similarity for a pair to be sent |
| `CAASM_LLM_SIZECAP` | 2 | look-alike step: maximum groups combined into one asset (`none` = no cap) |
| `CAASM_LLM_TIMEOUT`, `CAASM_LLM_MAX_RETRIES` | 120 s (300 s for claude-cli), 4 | per-request timeout and retries |
| `CAASM_LLM_REASONING_EFFORT` | not sent | e.g. `low` for OpenAI-compatible reasoning models |
| `CAASM_LLM_MOCK` | – | `1` = dummy LLM for tests |

## Tests

```sh
python -m unittest discover -s tests -v
```

No real LLM is used: a local fake OpenAI-compatible server and a fake `claude` command check the request path, that nothing is combined without the LLM, size cap, key handling, rate-limit handling and the alert-text check.

## Limitations

- Candidate pairs are only those sharing an identifier or with similar names; records of one device with nothing in common (e.g. a renamed host with a new IP) are not combined.
- Asking the LLM about every candidate pair costs more requests than asking only about look-alikes (the demo needs a handful of requests; tens of thousands of records need many).
- The "no merge without a reason" design has been tried on the bundled demo data only. The 19,235-pair figure above is from our earlier evaluation of the previous design (rules join shared identifiers, the LLM decides look-alikes).
- Being conservative has a cost: the LLM sometimes keeps old (`legacy-`) records of the same device separate, inconsistently across similar cases and across runs, and may treat a missing name as a mismatch. Both produce extra alerts, not hidden ones.
- Column mapping for specific products is manual for now.
- Results on synthetic data do not establish accuracy on real networks.

## License

MIT. See `LICENSE`.
