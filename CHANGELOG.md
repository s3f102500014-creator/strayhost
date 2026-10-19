# Changelog

## 0.1.0 — 2026-10-19

First release.

- Reconciliation of ledger (CMDB), EDR and ASM CSV exports; the LLM decides every candidate pair (records sharing an identifier, then look-alike groups) and every judgement is logged with its reason.
- Classification into the seven cases of the ICSPIS 2025 three-way matrix; Critical alerts (C, D, G) with LLM-written text checked against the records; digest for A, E, F.
- Slack-compatible webhook and a local console: tickets, department routing, deadlines and escalation, daily digests, weekly report, SMTP e-mail, analyst decisions and suppression rules.
- Back ends: Claude Code CLI with a subscription token, OpenAI-compatible endpoints, local models.
- `synth` (synthetic labelled data), `score` (pairwise F1, Critical alert correctness, missed high-risk devices) and `send` (send a finished run's notifications again).
- Bundled demo data and the output of one recorded Claude run (`examples/demo/recorded_run`).
