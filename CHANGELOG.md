# Changelog

## 0.1.1 — 2026-11-01

- README: step-by-step instructions for macOS, including the Python version check, choosing the Claude model by its full name (Haiku 4.5 and Opus), the expected output of the steps without an LLM, and which results are the same on every run.
- `run.py` stops with a clear message on Python older than 3.10.

## 0.1.0 — 2026-10-19

First release.

- Reconciliation of ledger (CMDB), EDR and ASM CSV exports; the LLM decides every candidate pair (records sharing an identifier, then look-alike groups) and every judgement is logged with its reason.
- Classification into the seven cases of the ICSPIS 2025 three-way matrix; Critical alerts (C, D, G) with LLM-written text checked against the records; digest for A, E, F.
- Slack-compatible webhook and a local console: tickets, department routing, deadlines and escalation, daily digests, weekly report, SMTP e-mail, analyst decisions and suppression rules.
- Back ends: Claude Code CLI with a subscription token, OpenAI-compatible endpoints, local models.
- `synth` (synthetic labelled data), `score` (pairwise F1, Critical alert correctness, missed high-risk devices) and `send` (send a finished run's notifications again).
- All settings are environment variables with the prefix `STRAYHOST_` (for example `STRAYHOST_LLM_BACKEND`).
- Bundled demo data and the output of one recorded Claude run (`examples/demo/recorded_run`).
