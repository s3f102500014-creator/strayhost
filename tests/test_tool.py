"""Offline tests. No real LLM and no API key are used.

Run: python -m unittest discover -s tests -v
"""
import csv
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import fake_llm_server  # noqa: E402
from strayhost import cli, taxonomy  # noqa: E402
from strayhost.rule_engine import Coverage, coverage_to_case  # noqa: E402

LLM_ENV = ("CAASM_LLM_BASE_URL", "CAASM_LLM_MODEL", "CAASM_LLM_API_KEY", "CAASM_LLM_MOCK", "CAASM_LLM_BACKEND",
           "CAASM_CLAUDE_BIN", "FAKE_CLAUDE_KEY_SOURCE", "ANTHROPIC_API_KEY")


def rows(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def quiet(fn, *args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = fn(*args)
    return code, out.getvalue(), err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.pop(k, None) for k in LLM_ENV}
        os.environ["CAASM_LLM_MAX_RETRIES"] = "0"
        fake_llm_server.reset()
        self.tmp = Path(tempfile.mkdtemp())
        self.data = self.tmp / "data"
        code, _, _ = quiet(cli.main, ["synth", "--out", str(self.data), "--n", "60", "--p", "0.2", "--seed", "0"])
        self.assertEqual(code, 0)

    def tearDown(self):
        for k, v in self._saved.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    def run_tool(self, name, *extra):
        out = self.tmp / name
        code, stdout, stderr = quiet(cli.main, ["run", "--input", str(self.data), "--out", str(out), *extra])
        return code, out, stdout, stderr

    def load(self, out):
        return json.loads((out / "assets.json").read_text(encoding="utf-8"))


class TestRules(unittest.TestCase):
    def test_all_eight_source_combinations(self):
        expect = {(1, 1, 0): "A", (1, 1, 1): "B", (1, 0, 0): "C", (1, 0, 1): "D",
                  (0, 1, 0): "E", (0, 1, 1): "F", (0, 0, 1): "G", (0, 0, 0): "H"}
        for (l, e, a), case in expect.items():
            self.assertEqual(coverage_to_case(Coverage(bool(l), bool(e), bool(a))), case)

    def test_high_risk_cases(self):
        crit = {c for c in "ABCDEFGH" if taxonomy.case_to_risk(c) == "Critical"}
        self.assertEqual(crit, {"D", "F", "G"})


class TestSynth(Base):
    def test_files_and_truth_alignment(self):
        for f in ("ledger.csv", "edr.csv", "asm.csv", "truth.csv"):
            self.assertTrue((self.data / f).exists(), f)
        n_rows = sum(len(rows(self.data / f"{s}.csv")) for s in ("ledger", "edr", "asm"))
        n_truth = len(rows(self.data / "truth.csv"))
        self.assertEqual(n_rows, n_truth)

    def test_deterministic(self):
        other = self.tmp / "again"
        quiet(cli.main, ["synth", "--out", str(other), "--n", "60", "--p", "0.2", "--seed", "0"])
        for f in ("ledger.csv", "edr.csv", "asm.csv", "truth.csv"):
            self.assertEqual((self.data / f).read_bytes(), (other / f).read_bytes(), f)

    def test_truth_has_no_hint_in_inputs(self):
        for s in ("ledger", "edr", "asm"):
            with open(self.data / f"{s}.csv", encoding="utf-8") as f:
                cols = next(csv.reader(f))
                self.assertFalse(any(c.startswith("_") or "true" in c.lower() for c in cols), cols)


class TestRunWithoutLLM(Base):
    def test_rules_only_when_not_configured(self):
        code, out, stdout, stderr = self.run_tool("r")
        self.assertEqual(code, 0)
        self.assertIn("rules-only mode", stderr)
        data = self.load(out)
        self.assertEqual(data["meta"]["mode"], "rules only (baseline)")
        self.assertEqual(data["meta"]["n_llm_merges"], 0)
        for f in ("assets.json", "assets.csv", "alerts.md", "report.html"):
            self.assertTrue((out / f).exists(), f)
        self.assertFalse((out / "llm_adjudications.jsonl").exists())

    def test_every_record_in_exactly_one_asset(self):
        _, out, _, _ = self.run_tool("r")
        ids = [r for a in self.load(out)["assets"] for r in a["record_ids"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), len(rows(self.data / "truth.csv")))

    def test_case_matches_sources(self):
        _, out, _, _ = self.run_tool("r")
        for a in self.load(out)["assets"]:
            srcs = {r.split("_")[0] for r in a["record_ids"]}
            cov = Coverage("ledger" in srcs, "edr" in srcs, "asm" in srcs)
            self.assertEqual(a["case"], coverage_to_case(cov))
            self.assertEqual(a["in_ledger"], "ledger" in srcs)

    def test_reasons_present(self):
        _, out, _, _ = self.run_tool("r")
        for a in self.load(out)["assets"]:
            self.assertTrue(a["why"], a["name"])
            if len(a["record_ids"]) > 1:
                self.assertIn("same identifier", a["why"])

    def test_alerts_only_critical(self):
        _, out, _, _ = self.run_tool("r")
        data = self.load(out)
        n_crit = sum(a["risk"] == "Critical" for a in data["assets"])
        self.assertEqual((out / "alerts.md").read_text(encoding="utf-8").count("## Critical:"), n_crit)

    def test_score_runs(self):
        _, out, _, _ = self.run_tool("r")
        code, stdout, _ = quiet(cli.main, ["score", "--assets", str(out / "assets.json"), "--truth", str(self.data / "truth.csv")])
        self.assertEqual(code, 0)
        self.assertIn("pairwise precision", stdout)

    def test_no_llm_flag_overrides_config(self):
        os.environ["CAASM_LLM_BASE_URL"] = "http://127.0.0.1:9/v1"
        os.environ["CAASM_LLM_MODEL"] = "x"
        code, out, _, _ = self.run_tool("r", "--no-llm")
        self.assertEqual(code, 0)
        self.assertEqual(self.load(out)["meta"]["mode"], "rules only (baseline)")

    def test_wrong_columns_are_reported(self):
        with open(self.data / "edr.csv", "w", encoding="utf-8", newline="") as f:
            f.write("Name,IP Address\nPC-1,10.0.0.1\n")
        code, _, _, stderr = self.run_tool("r")
        self.assertEqual(code, 2)
        self.assertIn("Expected columns", stderr)

    def test_non_utf8_is_reported(self):
        (self.data / "ledger.csv").write_bytes("asset_id,hostname,ip\nA-1,営業-pc,10.0.0.1\n".encode("shift_jis"))
        code, _, _, stderr = self.run_tool("r")
        self.assertEqual(code, 2)
        self.assertIn("not UTF-8", stderr)

    def test_missing_file(self):
        (self.data / "edr.csv").unlink()
        code, _, _, stderr = self.run_tool("r")
        self.assertEqual(code, 2)
        self.assertIn("could not read", stderr)


class TestRunWithLLM(Base):
    def test_nothing_is_combined_without_llm_confirmation(self):
        # the mock LLM answers "different" to everything: no record may be combined,
        # not even records that share an identifier
        os.environ["CAASM_LLM_MOCK"] = "1"
        code, out_mock, _, _ = self.run_tool("m")
        self.assertEqual(code, 0)
        assets = self.load(out_mock)["assets"]
        self.assertTrue(all(len(a["record_ids"]) == 1 for a in assets))
        self.assertEqual(len(assets), len(rows(self.data / "truth.csv")))

    def test_openai_compatible_endpoint(self):
        srv, url = fake_llm_server.start()
        try:
            os.environ.update(CAASM_LLM_BASE_URL=url, CAASM_LLM_MODEL="fake", CAASM_LLM_API_KEY="sk-test-SECRET-123")
            code, out, stdout, stderr = self.run_tool("f")
        finally:
            srv.shutdown(); srv.server_close()
        self.assertEqual(code, 0, stderr)
        data = self.load(out)
        self.assertGreater(data["meta"]["n_llm_merges"], 0)
        self.assertIn("Bearer sk-test-SECRET-123", fake_llm_server._Handler.seen_auth)
        merged = [a for a in data["assets"] if a["llm_merges"]]
        self.assertTrue(merged)
        self.assertIn("LLM judged", merged[0]["why"])
        # with an LLM that always answers "same", every rules-only asset stays inside one asset
        _, out_rules, _, _ = self.run_tool("r2", "--no-llm")
        final = {r: i for i, a in enumerate(data["assets"]) for r in a["record_ids"]}
        for a in self.load(out_rules)["assets"]:
            self.assertEqual(len({final[r] for r in a["record_ids"]}), 1)
        # the API key never reaches any output file or console output
        for f in out.iterdir():
            self.assertNotIn("SECRET", f.read_text(encoding="utf-8"), f.name)
        self.assertNotIn("SECRET", stdout + stderr)

    def test_only_lookalikes_are_sent_and_extra_columns_stay_local(self):
        rows = []
        with open(self.data / "ledger.csv", encoding="utf-8") as f:
            r = csv.DictReader(f)
            cols = r.fieldnames + ["secret_note"]
            rows = [dict(x, secret_note="DO-NOT-SEND") for x in r]
        with open(self.data / "ledger.csv", "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader(); w.writerows(rows)
        srv, url = fake_llm_server.start()
        try:
            os.environ.update(CAASM_LLM_BASE_URL=url, CAASM_LLM_MODEL="fake")
            code, out, _, stderr = self.run_tool("f")
        finally:
            srv.shutdown(); srv.server_close()
        self.assertEqual(code, 0, stderr)
        prompts = " ".join(fake_llm_server._Handler.prompts)
        self.assertNotIn("DO-NOT-SEND", prompts)
        # every judged pair has similar names (>= 0.70) or a missing name
        audit = read_jsonl(out / "llm_adjudications.jsonl")
        verdicts = [v for v in audit if v.get("type") == "verdict"]
        self.assertTrue(verdicts)
        for v in verdicts:
            if v["step"] == "lookalike":
                self.assertTrue(v["sim"] is None or v["sim"] >= 0.70 or not v["names_a"] or not v["names_b"], v)
            else:  # link step: the two records share an identifier
                from strayhost.data_io import get_identifiers_from_record
                by_id = {r["_internal_id"]: (src, r) for src, rs in __import__("strayhost.data_io", fromlist=["x"]).load_all_data(
                    self.data / "ledger.csv", self.data / "edr.csv", self.data / "asm.csv").items() for r in rs}
                (sa, ra), (sb, rb) = by_id[v["records_a"][0]], by_id[v["records_b"][0]]
                self.assertTrue(get_identifiers_from_record(ra, sa) & get_identifiers_from_record(rb, sb), v)

    def test_partial_failure_keeps_pairs_separate(self):
        srv, url = fake_llm_server.start(fail_every=2)
        try:
            os.environ.update(CAASM_LLM_BASE_URL=url, CAASM_LLM_MODEL="fake")
            code, out, _, stderr = self.run_tool("p")
        finally:
            srv.shutdown(); srv.server_close()
        self.assertEqual(code, 0, stderr)
        self.assertIn("LLM judgements failed", stderr)
        audit = read_jsonl(out / "llm_adjudications.jsonl")
        for v in audit:
            if v.get("type") == "verdict" and v.get("error"):
                self.assertFalse(v["merged"])

    def test_unreachable_llm_is_reported(self):
        os.environ.update(CAASM_LLM_BASE_URL="http://127.0.0.1:9/v1", CAASM_LLM_MODEL="x")
        code, out, _, stderr = self.run_tool("d")
        self.assertEqual(code, 1)
        self.assertIn("could not be reached", stderr)
        self.assertIn("LLM unreachable", self.load(out)["meta"]["mode"])


GEMINI_429 = ('{"error":{"code":429,"message":"You exceeded your current quota, please check your plan and billing '
              'details.","status":"RESOURCE_EXHAUSTED","details":[{"quotaId":"GenerateRequests%sPerProjectPerModel-FreeTier"},'
              '{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"1s"}]}}')


class TestLLMClient(unittest.TestCase):
    def setUp(self):
        fake_llm_server.reset()
        self.srv, self.url = fake_llm_server.start()

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close()
        fake_llm_server.reset()

    def client(self, retries=2):
        from strayhost.llm_client import LLMClient
        return LLMClient(base_url=self.url, model="fake", api_key="k", max_retries=retries)

    def ask(self, c):
        return c.chat_json([{"role": "user", "content": '"pair_id": 0'}])

    def test_per_minute_429_is_retried(self):
        fake_llm_server._Handler.scripted = [(429, GEMINI_429 % "PerMinute", {})]
        self.assertIn("verdicts", self.ask(self.client()))
        self.assertEqual(fake_llm_server._Handler.requests, 2)

    def test_retry_after_header(self):
        fake_llm_server._Handler.scripted = [(429, "slow down", {"Retry-After": "0"})]
        self.assertIn("verdicts", self.ask(self.client()))

    def test_per_day_quota_stops(self):
        from strayhost.llm_client import DailyQuotaExhaustedError
        fake_llm_server._Handler.scripted = [(429, GEMINI_429 % "PerDay", {})]
        with self.assertRaises(DailyQuotaExhaustedError) as cm:
            self.ask(self.client())
        self.assertEqual(cm.exception.reason, "daily_quota")
        self.assertEqual(fake_llm_server._Handler.requests, 1)

    def test_spending_limit_stops(self):
        from strayhost.llm_client import DailyQuotaExhaustedError
        fake_llm_server._Handler.scripted = [(429, '{"error":{"code":"insufficient_quota"}}', {})]
        with self.assertRaises(DailyQuotaExhaustedError) as cm:
            self.ask(self.client())
        self.assertEqual(cm.exception.reason, "spend_cap")

    def test_auth_error_not_retried(self):
        fake_llm_server._Handler.scripted = [(401, "bad key", {})]
        with self.assertRaises(RuntimeError):
            self.ask(self.client())
        self.assertEqual(fake_llm_server._Handler.requests, 1)

    def test_repr_hides_key(self):
        self.assertNotIn("k'", repr(self.client()))


class TestBehaviour(Base):
    def test_canonical_name_prefers_ledger(self):
        d = self.tmp / "tiny"
        d.mkdir()
        (d / "ledger.csv").write_text("asset_id,hostname,ip\nA-1,api-12,203.0.113.5\n", encoding="utf-8")
        (d / "edr.csv").write_text("asset_id_or_hostname,ip\n", encoding="utf-8")
        (d / "asm.csv").write_text("public_ip,domain\n203.0.113.5,api-11.example.com\n", encoding="utf-8")
        out = self.tmp / "tiny_out"
        code, _, _ = quiet(cli.main, ["run", "--input", str(d), "--out", str(out)])
        self.assertEqual(code, 0)
        assets = self.load(out)["assets"]
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["name"], "api-12")
        self.assertEqual(assets[0]["case"], "D")

    def test_size_cap_limits_chaining(self):
        srv, url = fake_llm_server.start()  # answers "same" for every pair
        try:
            os.environ.update(CAASM_LLM_BASE_URL=url, CAASM_LLM_MODEL="fake")
            code, out, _, stderr = self.run_tool("cap")
        finally:
            srv.shutdown(); srv.server_close()
        self.assertEqual(code, 0, stderr)
        audit = read_jsonl(out / "llm_adjudications.jsonl")
        self.assertTrue(any(v.get("policy_rejected") for v in audit if v.get("type") == "verdict"))
        _, rules_out, _, _ = self.run_tool("cap_rules", "--no-llm")
        base = {r: i for i, a in enumerate(self.load(rules_out)["assets"]) for r in a["record_ids"]}
        for a in self.load(out)["assets"]:
            self.assertLessEqual(len({base[r] for r in a["record_ids"]}), 2)

    def test_request_limit_is_not_a_failure(self):
        srv, url = fake_llm_server.start()
        try:
            os.environ.update(CAASM_LLM_BASE_URL=url, CAASM_LLM_MODEL="fake", CAASM_LLM_MAX_CALLS="1")
            code, out, _, stderr = self.run_tool("lim")
        finally:
            srv.shutdown(); srv.server_close()
            os.environ.pop("CAASM_LLM_MAX_CALLS", None)
        self.assertEqual(code, 0, stderr)
        self.assertNotIn("judgements failed", stderr)

    def test_mock_writes_separate_audit_file(self):
        os.environ["CAASM_LLM_MOCK"] = "1"
        code, out, _, _ = self.run_tool("mock")
        self.assertEqual(code, 0)
        self.assertTrue((out / "llm_adjudications_mock.jsonl").exists())
        self.assertFalse((out / "llm_adjudications.jsonl").exists())
        self.assertFalse((out / "llm_adjudications_mock_mock.jsonl").exists())


class TestClaudeCLI(Base):
    def use_fake_claude(self, name="fake_claude.py"):
        # copy and mark executable: zip extraction does not keep the executable bit
        import shutil
        os.environ["CAASM_LLM_BACKEND"] = "claude-cli"
        dst = self.tmp / name
        shutil.copy(ROOT / "tests" / "fake_claude.py", dst)
        os.chmod(dst, 0o755)
        os.environ["CAASM_CLAUDE_BIN"] = str(dst)

    def test_runs_and_writes_ai_alerts(self):
        self.use_fake_claude()
        code, out, stdout, stderr = self.run_tool("cc")
        self.assertEqual(code, 0, stderr)
        meta = self.load(out)["meta"]
        self.assertGreater(meta["n_llm_merges"], 0)
        self.assertIn("claude-haiku-4-5", meta["mode"])
        notes = json.loads((out / "notifications.json").read_text(encoding="utf-8"))
        self.assertTrue(any(n["text_source"] == "llm" for n in notes))

    def test_refuses_api_billing_env(self):
        self.use_fake_claude()
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-api-xyz"
        code, _, _, stderr = self.run_tool("cc2")
        self.assertEqual(code, 2)
        self.assertIn("subscription", stderr)
        self.assertIn("ANTHROPIC_API_KEY", stderr)

    def test_stops_on_non_subscription_credentials(self):
        self.use_fake_claude("fake_claude_apikey.py")
        code, out, _, stderr = self.run_tool("cc3")
        self.assertIn("stopping early", stderr)
        self.assertEqual(self.load(out)["meta"]["n_llm_merges"], 0)


    def test_missing_key_source_fails_closed(self):
        self.use_fake_claude("fake_claude_nokeysource.py")
        code, out, _, stderr = self.run_tool("cc4")
        self.assertIn("stopping early", stderr)
        self.assertIn("subscription", stderr)
        self.assertEqual(self.load(out)["meta"]["n_llm_merges"], 0)

    def test_child_environment_is_isolated(self):
        from strayhost.llm_client import ClaudeCLIClient
        self.use_fake_claude()
        os.environ["STRAYHOST_TEST_SECRET"] = "x"
        try:
            c = ClaudeCLIClient()
            env = c._env()
        finally:
            os.environ.pop("STRAYHOST_TEST_SECRET", None)
        self.assertNotIn("STRAYHOST_TEST_SECRET", env)
        self.assertTrue(env["HOME"].startswith(c._sandbox))
        self.assertTrue(env["CLAUDE_CONFIG_DIR"].startswith(c._sandbox))
        self.assertEqual(env["USERPROFILE"], env["HOME"])
        argv = c._argv("sys")
        for flag in ("--tools", "--strict-mcp-config", "--no-session-persistence"):
            self.assertIn(flag, argv)

    def test_bad_token_file_is_reported(self):
        self.use_fake_claude()
        tok = self.tmp / "tok"
        tok.write_text("sk-ant-api03-not-a-subscription-token", encoding="utf-8")
        os.environ["CAASM_CLAUDE_OAUTH_TOKEN_FILE"] = str(tok)
        try:
            code, _, _, stderr = self.run_tool("cc5")
        finally:
            os.environ.pop("CAASM_CLAUDE_OAUTH_TOKEN_FILE", None)
        self.assertEqual(code, 2)
        self.assertIn("subscription token", stderr)
        self.assertNotIn("not-a-subscription", stderr)


class TestInbox(unittest.TestCase):
    def setUp(self):
        import threading
        from strayhost.inbox import serve
        self.tmp = Path(tempfile.mkdtemp())
        self.srv = serve(0, self.tmp / "inbox.jsonl", open_browser=False)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close()

    def req(self, path, body=None, ctype="application/json", host=None):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {"Content-Type": ctype} if body is not None else {}
        if host:
            headers["Host"] = host
        c.request("POST" if body is not None else "GET", path, body=body, headers=headers)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data

    def test_accepts_json_and_lists_it(self):
        self.assertEqual(self.req("/hook", json.dumps({"text": "hello <b>x</b>"}))[0], 200)
        status, data = self.req("/api/messages")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)[0]["text"], "hello <b>x</b>")
        self.assertTrue((self.tmp / "inbox.jsonl").exists())

    def test_rejects_non_json_content_type(self):
        self.assertEqual(self.req("/hook", json.dumps({"text": "x"}), ctype="text/plain")[0], 415)

    def test_rejects_foreign_host_header(self):
        self.assertEqual(self.req("/api/messages", host="evil.example:8765")[0], 403)
        self.assertEqual(self.req("/hook", json.dumps({"text": "x"}), host="evil.example")[0], 403)

    def test_rejects_bad_payloads(self):
        self.assertEqual(self.req("/hook", json.dumps({"no_text": 1}))[0], 400)
        self.assertEqual(self.req("/hook", json.dumps({"text": 5}))[0], 400)

    def test_page_escapes_html(self):
        status, page = self.req("/")
        self.assertEqual(status, 200)
        self.assertIn(b"const esc=", page)


class TestStyles(Base):
    def test_g2_style_runs(self):
        d = self.tmp / "g2"
        code, _, _ = quiet(cli.main, ["synth", "--style", "g2", "--out", str(d), "--n", "40"])
        self.assertEqual(code, 0)
        out = self.tmp / "g2_out"
        code, _, _ = quiet(cli.main, ["run", "--input", str(d), "--out", str(out)])
        self.assertEqual(code, 0)
        code, stdout, _ = quiet(cli.main, ["score", "--assets", str(out / "assets.json"), "--truth", str(d / "truth.csv")])
        self.assertIn("Critical alerts", stdout)

    def test_webhook_details_only_for_localhost(self):
        from strayhost import notify
        sent = []

        class FakeResp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b"ok"

        def fake_urlopen(req, timeout=0):
            sent.append(json.loads(req.data)); return FakeResp()
        orig = notify.urllib.request.urlopen
        notify.urllib.request.urlopen = fake_urlopen
        try:
            n = [{"title": "t", "text": "x", "records": {"asm": [{"secret_col": "s"}]}}]
            notify.post_webhook("https://hooks.slack.example/abc", n)
            notify.post_webhook("http://127.0.0.1:8765/hook", n)
        finally:
            notify.urllib.request.urlopen = orig
        self.assertNotIn("strayhost", sent[0])
        self.assertIn("strayhost", sent[1])


class TestAlertCheck(unittest.TestCase):
    def test_fabricated_domains_and_ips(self):
        from strayhost.notify import check_text_against_records as check
        recs = {"ledger": [{"hostname": "PUB-B6F8E", "fqdn": "pub-b6f8e.corp.example.local", "ip": "10.20.7.251",
                            "owner_user": "sal.user5479"}],
                "asm": [{"public_ip": "192.0.2.5", "domain": "shop7.example.com", "discovered_at": "2025-06-10T23:02:00Z"}]}
        ok = ("The ledger lists pub-b6f8e (10.20.7.251) in corp.example.local, owner sal.user5479, seen Jan-30. "
              "ASM saw SHOP7.EXAMPLE.COM at 192.0.2.5 "
              "on 2025-06-10T23:02:00Z (23:02, at 00:48:00Z). See e.g. CVE-2024-1234, TLS-1.2. Then open.Install EDR.")
        self.assertEqual(check(ok, recs), [])
        for bad in ("pub-b6f8e.attacker.net", "sal.evil.com", "010.20.7.251", "EVIL.ATTACKER.NET", "db-03",
                    "web-01", "srv-9", "ftp-99"):
            self.assertEqual(check(f"Also {bad} is involved.", recs), [bad], bad)

    def test_unknown_values_are_flagged(self):
        from strayhost.notify import check_text_against_records
        recs = {"asm": [{"public_ip": "192.0.2.5", "domain": "shop7.example.com", "open_ports": "443"}]}
        self.assertEqual(check_text_against_records("ASM saw shop7.example.com at 192.0.2.5 on 443.", recs), [])
        bad = check_text_against_records("ASM saw shop7.example.com at 192.0.2.9; also db-03 is involved.", recs)
        self.assertIn("192.0.2.9", bad)
        self.assertIn("db-03", bad)

    def test_rejected_llm_text_falls_back_to_template(self):
        from strayhost.notify import build_notifications

        class Liar:
            def chat(self, messages, **kw):
                return "Host evil-99 at 10.9.9.9 is compromised."
        asset = {"case": "G", "risk": "Critical", "name": "shop7", "case_meaning": "exposed only",
                 "records": {"asm": [{"public_ip": "192.0.2.5", "domain": "shop7.example.com"}]},
                 "why": "single record", "llm_merges": []}
        n = build_notifications([asset], Liar())[0]
        self.assertEqual(n["text_source"], "template")
        self.assertTrue(n["check"]["rejected"])
        self.assertNotIn("evil-99", n["text"])


if __name__ == "__main__":
    unittest.main()
