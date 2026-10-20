# StrayHost Tool Guide

StrayHost 0.1.0 · MIT License · Izuru Aki (Toyo University) · https://github.com/s3f102500014-creator/strayhost

## 1. Description

StrayHost reconciles three asset inventories that most organisations already export — the asset ledger (CMDB), the EDR console and an external attack-surface scan (ASM) — and reports the machines that are missing from one of them, for example a host that is reachable from the Internet but is in neither the ledger nor the EDR.

The three lists rarely agree: the same machine appears under different name spellings, receives a new IP after a DHCP renewal, or shares one public address with other machines behind NAT. Combining records by matching identifiers fails in two ways. If matching is too strict, name variants become false "unmanaged host" alerts. If it is too loose, an unmanaged host is merged into a managed one and its alert disappears.

StrayHost applies one rule: **no merge without a reason**. Records that share an identifier are only candidates; a large language model (LLM) judges every candidate pair and gives a reason, and records are combined only when the LLM answers "same device" with confidence 0.5 or more. Unsure, malformed or failed answers keep the records apart, so an error adds an alert instead of hiding one.

### 1.1 Features

- **Input:** three CSV exports (column names in section 3.4). Python standard library only.
- **Matching, step 1 (link):** every pair of records that shares an asset ID, a hostname (ignoring letter case and the domain part) or an IP address is sent to the LLM in batches of up to 25 pairs. If more than five records share one identifier, each of them is paired with the first one only. The prompt lists addresses that appear on more than one record of the same list (for example a NAT address), because such a shared address alone is not evidence.
- **Matching, step 2 (look-alike):** groups with similar names (similarity 0.70 or more), or with no name and the same private /24 network, are judged the same way. At most two groups can be combined into one asset in this step.
- **Audit log:** every judgement, applied or not, is written to `llm_adjudications.jsonl` with the records on each side, the answer, the confidence and the reason.
- **Classification (no LLM):** each asset is placed in one of the seven cases of the three-way matrix in Aki et al., "Triad Integration for IT Asset Governance: AI Agent–Driven Convergence of ITAM, ASM, and EDR" (ICSPIS 2025):

| Case | Ledger | EDR | ASM | Situation | Risk | Notification |
|---|:-:|:-:|:-:|---|---|---|
| A | ✓ | ✓ | ✓ | managed, visible externally | Important | daily digest |
| B | ✓ | ✓ | | managed, internal only | Informational | weekly report |
| C | ✓ | | ✓ | externally visible without EDR | Critical | immediate alert |
| D | | ✓ | ✓ | not in ledger, seen by EDR and externally | Critical | immediate alert |
| E | ✓ | | | ledger only, not detected | Important | daily digest |
| F | | ✓ | | not in ledger, seen by EDR | Important | daily digest |
| G | | | ✓ | externally visible only, unknown internally | Critical | immediate alert |

- **Notifications:** one alert per Critical asset (C, D, G) and one digest for A, E and F, sent to any Slack-compatible incoming webhook or to the built-in console. The alert text is written by the LLM from the observed records; if it names an IPv4 address or a host or domain name (a word with a digit or a dot) that is not in the records, the template text is sent instead.
- **Console** (local web page): one ticket per asset, e-mail to the security team and to the owning department taken from the ledger, deadlines and escalation of unresolved tickets, daily digests per department, a weekly report, and analyst decisions (acknowledge, resolve, approve as a known asset, false positive, suppression rules by name pattern). Details in section 3.3.
- **LLM back ends:** Claude through the Claude Code CLI with a subscription token (no API billing), any OpenAI-compatible endpoint, or a local model server such as Ollama.
- **Evaluation tools:** a generator of synthetic labelled data and a scorer.

### 1.2 License

MIT License, Copyright (c) 2026 Izuru Aki (Toyo University). See `LICENSE`.

### 1.3 Changelog

See `CHANGELOG.md`. Version 0.1.0 (2026-10-19) is the first release.

## 2. Installation

### 2.1 Requirements

- Python 3.10 or later. No packages to install (`requirements.txt` lists none).
- A web browser for the console.
- For LLM matching, one of:
  - a Claude Pro, Max, Team or Enterprise plan and the Claude Code CLI (section 2.3);
  - an OpenAI-compatible endpoint (for example OpenAI, Gemini, vLLM or LM Studio) and its key;
  - a local model server with an OpenAI-compatible API (for example Ollama).
- Without an LLM, StrayHost runs a rules-only baseline (records sharing any identifier are combined without review).

### 2.2 Supported platforms

The automated tests (65 tests) and the README steps 1–3 run in GitHub Actions on Windows, macOS and Linux with Python 3.10 and 3.13. The Claude CLI back end has been tested with the real CLI on macOS; on Linux and Windows only with a stand-in CLI in the tests.

### 2.3 Get the code

```sh
git clone https://github.com/s3f102500014-creator/strayhost.git
cd strayhost
```

The commands in this guide use `python3` (macOS, Linux); on Windows, type `py` instead of `python3`.

### 2.4 Set up Claude (optional)

1. Install the Claude Code CLI (official instructions: https://code.claude.com/docs/en/setup), open a new terminal and check it with `claude --version`:

   ```sh
   curl -fsSL https://claude.ai/install.sh | bash        # macOS, Linux
   irm https://claude.ai/install.ps1 | iex               # Windows PowerShell
   ```

2. Create a subscription token with `claude setup-token`. It opens the browser; after you approve, it prints a token starting with `sk-ant-oat` (valid for one year) and does not save it. StrayHost runs the CLI with an empty home folder, so it cannot use your normal login; it reads this token from a file. Save it to a file only you can read:

   ```sh
   ( umask 077; printf 'Paste the token and press Enter: '; read -r t; printf '%s\n' "$t" > ~/.strayhost_claude_token )
   ```

   On Windows PowerShell: `Read-Host "Paste the token and press Enter" | Set-Content -NoNewline "$HOME\.strayhost_claude_token"`.

3. Set two environment variables before `run`:

   ```sh
   export STRAYHOST_LLM_BACKEND=claude-cli
   export STRAYHOST_CLAUDE_OAUTH_TOKEN_FILE=~/.strayhost_claude_token
   ```

   On Windows PowerShell: `$env:STRAYHOST_LLM_BACKEND="claude-cli"` and `$env:STRAYHOST_CLAUDE_OAUTH_TOKEN_FILE="$HOME\.strayhost_claude_token"`.

StrayHost refuses to start if `ANTHROPIC_API_KEY` (or Bedrock or Vertex settings) is set, accepts only subscription tokens (`sk-ant-oat…`) in the token file, and stops unless the CLI reports that it is using the subscription. The CLI runs without tools, MCP servers or your settings, and with only a few environment variables (PATH, proxy and certificate settings).

### 2.5 Set up another LLM (optional)

```sh
export STRAYHOST_LLM_BASE_URL=http://localhost:11434/v1   # e.g. Ollama: data stays on your machine
export STRAYHOST_LLM_MODEL=qwen2.5:14b                    # model names are examples
export STRAYHOST_LLM_API_KEY=...                          # if the endpoint needs one
```

On Windows PowerShell use `$env:NAME="value"`. Keys are read from the environment only and never written to output files.

## 3. Usage

### 3.1 Commands

```
python3 run.py run      reconcile three CSV exports
python3 run.py console  tickets, routing, escalation, e-mail and reports in the browser
python3 run.py send     send the notifications of a finished run to a webhook again
python3 run.py score    score assets.json against truth.csv
python3 run.py synth    generate a synthetic labelled dataset
```

**run**

| Parameter | Meaning |
|---|---|
| `--input DIR` | folder containing `ledger.csv`, `edr.csv`, `asm.csv` |
| `--ledger`, `--edr`, `--asm` | the three files, instead of `--input` |
| `--out DIR` | output folder (default `out`) |
| `--no-llm` | rules only, even if an LLM is configured |
| `--webhook URL` | Slack-compatible incoming-webhook URL, or the console: `http://127.0.0.1:8765/hook` |
| `--webhook-delay S` | seconds between webhook messages |
| `--no-ai-alerts` | template alert texts even if an LLM is configured |

**console**

| Parameter | Meaning |
|---|---|
| `--routing FILE` | JSON file with the e-mail addresses (section 3.3) |
| `--data DIR` | folder for the console's state file (default `console_data`) |
| `--port N` | port on 127.0.0.1 (default 8765) |
| `--sla-critical-minutes M` | escalate a Critical ticket still unresolved after this time (default 1 day) |
| `--sla-important-minutes M` | the same for Important tickets (default 3 days) |
| `--digest-hour H` | hour of the day for the daily digests, 0–23 (default 9) |
| `--no-browser` | do not open the browser |

**send**: `--from DIR` (the `--out` folder of a run), `--webhook URL`, `--webhook-delay S`. It sends the run's `notifications.json` and a run summary, exactly as `run --webhook` does.

**score**: `--assets FILE` (`assets.json` of a run), `--truth FILE` (`truth.csv` with `record_id`, `true_asset`, `true_case`). It prints pairwise precision, recall and F1 of the record pairs placed in the same asset; for cases C, D and G, how many devices were found with the correct case; how many Critical alerts are one correct alert for one real high-risk device and how many are duplicates, wrong devices or wrong cases; and how many real high-risk devices got no Critical alert at all.

**synth**: `--out DIR` (default `synthetic`), `--n N` number of devices (default 60), `--p P` strength of renames, IP changes and replacements 0–1 (default 0.2), `--seed N`, `--mode balanced|imbalanced`, `--style g1|g2` (g1: clean records plus noise such as name variants, look-alike decoys, NAT and stale records; g2: records produced from device events such as renames, DHCP, replacements and NAT). It writes the three CSV files and `truth.csv`.

### 3.2 Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `STRAYHOST_LLM_BACKEND` | `openai` | `openai` (any OpenAI-compatible endpoint) or `claude-cli` |
| `STRAYHOST_LLM_BASE_URL`, `STRAYHOST_LLM_MODEL`, `STRAYHOST_LLM_API_KEY` | – | endpoint, model, key |
| `STRAYHOST_CLAUDE_MODEL`, `STRAYHOST_CLAUDE_BIN`, `STRAYHOST_CLAUDE_EFFORT`, `STRAYHOST_CLAUDE_OAUTH_TOKEN_FILE` | `claude-haiku-4-5-20251001`, `claude`, `low`, – | Claude CLI model, path, effort, subscription token file |
| `STRAYHOST_LLM_WORKERS` | 8 | parallel requests (1–32) |
| `STRAYHOST_LLM_BATCH_SIZE` | 25 | pairs per request (1–25) |
| `STRAYHOST_LLM_MAX_CALLS` | none | stop after this many requests |
| `STRAYHOST_LLM_MAX_CANDIDATES` | 3000 | maximum pairs sent to the LLM (most similar first) |
| `STRAYHOST_LLM_GRAY_LOW` | 0.70 | minimum name similarity for a look-alike pair |
| `STRAYHOST_LLM_SIZECAP` | 2 | look-alike step: maximum groups combined into one asset (`none` = no cap) |
| `STRAYHOST_LLM_TIMEOUT`, `STRAYHOST_LLM_MAX_RETRIES` | 120 s (300 s for claude-cli), 4 | per-request timeout and retries |
| `STRAYHOST_LLM_REASONING_EFFORT` | not sent | e.g. `low` for OpenAI-compatible reasoning models |
| `STRAYHOST_LLM_MOCK` | – | `1` = dummy LLM for tests |
| `STRAYHOST_SMTP_HOST`, `STRAYHOST_SMTP_PORT`, `STRAYHOST_SMTP_USER`, `STRAYHOST_SMTP_PASSWORD`, `STRAYHOST_SMTP_FROM` | – , 587 | console e-mail (587 with STARTTLS or 465 with SMTPS; certificates verified) |

### 3.3 Console

The console listens on 127.0.0.1 only, accepts requests addressed to `127.0.0.1` or `localhost`, and accepts JSON bodies only. Its state (tickets, decisions, e-mail, run history) is one JSON file in `--data`, so it survives restarts.

| Situation | What the console does |
|---|---|
| New Critical asset (C, D, G) | opens a ticket; e-mails the security team at once, and the owning department if the ledger names one |
| Important assets (A, E, F) | open tickets; every day at `--digest-hour`, one digest e-mail per department |
| Informational (B) | counted in the report only |
| Same asset again while its ticket is open | no new e-mail; the ticket's "seen" count goes up |
| Ticket unresolved at its deadline | escalation e-mail, again at every further deadline |
| Ticket approved, marked false positive, or matching a suppression rule | later alerts for it are not sent |
| A resolved asset is reported again | the ticket is reopened and e-mailed again |
| A later run reports the asset as Informational, or no longer reports it | the ticket is resolved automatically |
| Every 7 days | report e-mail; the Report tab shows assets per case, the share of healthy assets (B) and of potentially undetected assets (E), open tickets per department, tickets past their deadline and the mean time to resolve |

Without `STRAYHOST_SMTP_HOST`, e-mail is kept in the E-mail tab and marked "not sent". The routing file maps the ledger's `owner_dept` to an address (`examples/routing.json`):

```json
{"security": {"email": "soc@example.com"}, "escalation": {"email": "ciso@example.com"},
 "report": {"email": "it-governance@example.com"}, "default_department": {"email": "it-helpdesk@example.com"},
 "departments": {"Sales": {"email": "sales-it@example.com"}}}
```

### 3.4 Input files

| File | Columns (header row required) |
|---|---|
| `ledger.csv` | `asset_id`, `hostname`, `ip`, `fqdn`, `instance_id`, `owner_dept`, `owner_user` |
| `edr.csv` | `asset_id_or_hostname`, `ip`, `observed_at`, `dest_ip`, `dest_fqdn` |
| `asm.csv` | `public_ip`, `domain`, `discovered_at`, `open_ports`, `vuln_score` |

Rename your export's columns to these names; files must be UTF-8. Only these columns are sent to the LLM, and only for the records being judged (and for Critical assets, for the alert text). With a hosted LLM this data leaves the machine; a local model keeps it on the machine. Only the alert title and text are sent to an external webhook; record details are attached only for the local console.

### 3.5 Output files (in `--out`)

| File | Contents |
|---|---|
| `assets.json`, `assets.csv` | every asset: case, risk, records, why it was combined |
| `notifications.json`, `alerts.md` | the alerts and the digest |
| `llm_adjudications.jsonl` | every LLM judgement (step `link` or `lookalike`) |
| `report.html` | table of all assets |

### 3.6 Examples

Start the console in one terminal and leave it running:

```sh
python3 run.py console --routing examples/routing.json
```

In a second terminal, in the same folder:

```sh
# the recorded Claude run (examples/demo/recorded_run): score it, then show it in the console
python3 run.py score --assets examples/demo/recorded_run/assets.json --truth examples/demo/truth.csv
python3 run.py send --from examples/demo/recorded_run --webhook http://127.0.0.1:8765/hook

# rules-only baseline
python3 run.py run --input examples/demo --out out_rules --no-llm
python3 run.py score --assets out_rules/assets.json --truth examples/demo/truth.csv

# with Claude (section 2.4); restart the console first with --data console_claude to see this run alone
python3 run.py run --input examples/demo --out out_claude --webhook http://127.0.0.1:8765/hook
python3 run.py score --assets out_claude/assets.json --truth examples/demo/truth.csv

# your own exports
python3 run.py run --ledger cmdb.csv --edr edr.csv --asm asm.csv --out out_mine --webhook https://hooks.slack.com/services/...

# synthetic data with the noise you expect
python3 run.py synth --style g2 --n 100 --p 0.3 --out mydata
python3 run.py run --input mydata --out out_mydata
python3 run.py score --assets out_mydata/assets.json --truth mydata/truth.csv
```

### 3.7 Result on the bundled demo data

One run with Claude Haiku 4.5 via the Claude CLI (files in `examples/demo/recorded_run`), on 133 synthetic records with 28 high-risk devices. LLM answers vary from run to run.

| | Rules only | StrayHost |
|---|---|---|
| High-risk devices with no Critical alert (missed) | 1 | 0 |
| Critical alerts | 37 | 31 |
| one correct alert per real high-risk device | 24 | 25 |
| duplicate, wrong device or wrong case | 13 | 6 |
| Pairwise F1 (precision / recall) | 0.667 (0.885 / 0.535) | 0.911 (1.000 / 0.837) |
| Pairs of different devices the LLM called "same" | – | 0 of 46 (113 judgements) |

### 3.8 Limitations

- Candidate pairs are only those sharing an identifier or with similar names; records of one device with nothing in common are not combined.
- Asking the LLM about every candidate pair costs more requests than asking only about look-alikes.
- The design has been tried on the bundled synthetic data only; no accuracy claim is made for real networks.
- The LLM sometimes keeps old records of the same device separate and may treat a missing name as a mismatch. Both produce extra alerts, not hidden ones.
- The alert-text check is conservative: any word with a digit or a dot that is not in the records makes it send the template text.
- Column mapping for specific products is manual.
