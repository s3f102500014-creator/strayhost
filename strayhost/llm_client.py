"""Minimal OpenAI-compatible chat client (standard library only).

Works with any endpoint that implements POST {base_url}/chat/completions:
OpenAI, Google Gemini's OpenAI-compatible endpoint, Ollama (http://localhost:11434/v1),
vLLM, LM Studio, etc. The API key is read from the environment and never logged
or written to disk.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from . import config


class DailyQuotaExhaustedError(RuntimeError):
    """Raised when the provider reports a non-recoverable quota / spending limit."""

    def __init__(self, message: str, reason: str = "daily_quota") -> None:
        super().__init__(message)
        self.reason = reason


class LLMNotConfiguredError(RuntimeError):
    pass


def extract_json(text: str) -> Any:
    """Extract a JSON object from an LLM reply (handles ``` fences and leading prose)."""
    if text is None:
        raise ValueError("empty LLM response")
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    start = cleaned.find("{")
    if start == -1:
        raise ValueError(f"no JSON object in response: {cleaned[:200]!r}")
    depth = 0
    for i in range(start, len(cleaned)):
        ch = cleaned[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(cleaned[start : i + 1])
    raise ValueError(f"unbalanced JSON in response: {cleaned[:200]!r}")


def _fatal_quota_reason(body_text: str) -> Optional[str]:
    """Only limits that will not recover within minutes stop the run. Per-minute rate
    limits (HTTP 429 with a retry hint) are retried instead."""
    t = body_text.lower()
    if "perday" in t.replace("_", "").replace(" ", "") or "requests per day" in t:
        return "daily_quota"
    if "spending cap" in t or "spend cap" in t or "insufficient_quota" in t or "billing hard limit" in t:
        return "spend_cap"
    return None


def _retry_after_seconds(err: "urllib.error.HTTPError", body_text: str) -> Optional[float]:
    ra = err.headers.get("Retry-After") if err.headers else None
    if ra:
        try:
            return float(ra)
        except ValueError:
            pass
    m = re.search(r'retry(?:Delay)?["\s:]*["]?(\d+(?:\.\d+)?)s', body_text, re.I) or re.search(r"retry in (\d+(?:\.\d+)?)\s*s", body_text, re.I)
    return float(m.group(1)) if m else None


class LLMClient:
    """Thread-safe enough for the adjudicator's thread pool (no shared mutable state
    except a simple lock-protected counter)."""

    backend = config.LLM_BACKEND_NAME

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
    ) -> None:
        self.base_url = (base_url or config.llm_base_url() or "").rstrip("/")
        self.model = model or config.llm_model()
        if not self.base_url or not self.model:
            raise LLMNotConfiguredError(
                "LLM is not configured. Set CAASM_LLM_BASE_URL and CAASM_LLM_MODEL "
                "(and CAASM_LLM_API_KEY if your endpoint needs one)."
            )
        self._api_key = api_key if api_key is not None else config.llm_api_key()
        self.timeout = timeout or config.llm_timeout()
        self.max_retries = max_retries if max_retries is not None else config.llm_max_retries()
        self._json_mode_supported = True
        self._lock = threading.Lock()
        self.requests = 0

    def __repr__(self) -> str:  # never show the key
        host = urllib.parse.urlsplit(self.base_url)
        return f"LLMClient(endpoint={host.scheme}://{host.netloc}{host.path}, model={self.model!r})"

    def _post(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        req = urllib.request.Request(f"{self.base_url}/chat/completions", data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        json_mode: bool = False,
        reasoning_effort: Optional[str] = None,
        temperature: Optional[float] = None,
        **_: Any,
    ) -> str:
        payload: Dict[str, Any] = {"model": model or self.model, "messages": messages}
        if temperature is not None:
            payload["temperature"] = temperature
        if reasoning_effort:
            payload["reasoning_effort"] = reasoning_effort
        use_json = json_mode and self._json_mode_supported
        last_err: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            body = dict(payload)
            if use_json:
                body["response_format"] = {"type": "json_object"}
            try:
                with self._lock:
                    self.requests += 1
                out = self._post(body)
                return out["choices"][0]["message"]["content"] or ""
            except urllib.error.HTTPError as e:
                body_text = ""
                try:
                    body_text = e.read().decode("utf-8", "replace")
                except Exception:  # noqa: BLE001
                    pass
                last_err = RuntimeError(f"HTTP {e.code}: {body_text[:300]}")
                if e.code == 400 and use_json and "response_format" in body_text.lower():
                    self._json_mode_supported = False
                    use_json = False
                    continue
                if e.code in (401, 403, 404):
                    raise last_err
                if e.code == 429:
                    fatal = _fatal_quota_reason(body_text)
                    if fatal:
                        raise DailyQuotaExhaustedError(str(last_err), fatal)
                    wait = _retry_after_seconds(e, body_text)
                    if wait is not None and attempt < self.max_retries:
                        time.sleep(min(wait, 90))
                        continue
                elif e.code not in (408, 409) and e.code < 500:
                    raise last_err
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                last_err = RuntimeError(f"connection error: {e}")
            if attempt < self.max_retries:
                time.sleep(min(2 ** attempt, 20))
        raise last_err or RuntimeError("LLM call failed")

    def chat_json(self, messages: List[Dict[str, str]], **kwargs: Any) -> Any:
        return extract_json(self.chat(messages, json_mode=True, **kwargs))


class MockLLM:
    """Deterministic offline stand-in (CAASM_LLM_MOCK=1). Rejects every candidate pair,
    so results equal the rules-only mode. For tests only."""

    backend = "mock"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.model = "mock"

    def __repr__(self) -> str:
        return "MockLLM()"

    def chat(self, messages: List[Dict[str, str]], **kwargs: Any) -> str:
        prompt_text = " ".join(m.get("content", "") for m in messages)
        pair_ids = sorted({int(n) for n in re.findall(r'"pair_id"\s*:\s*(\d+)', prompt_text)})
        if pair_ids:
            return json.dumps(
                {"verdicts": [{"pair_id": p, "same_asset": False, "confidence": 0.0, "evidence": "mock"} for p in pair_ids]}
            )
        return json.dumps({"same_asset": False, "confidence": 0.0, "evidence": "mock"})

    def chat_json(self, messages: List[Dict[str, str]], **kwargs: Any) -> Any:
        return extract_json(self.chat(messages, **kwargs))


# ---------------------------------------------------------------------------
# Claude Code CLI backend (CAASM_LLM_BACKEND=claude-cli): runs `claude -p` with
# your Claude subscription. It refuses to run if the CLI would use pay-as-you-go
# API billing, and runs the CLI with an empty HOME, no tools and no MCP servers.
# ---------------------------------------------------------------------------
import os as _os
import shutil as _shutil
import subprocess as _subprocess
import tempfile as _tempfile

CLAUDE_CLI_SYSTEM_PROMPT = (
    "You are a data-matching assistant. Follow the user's instructions exactly. "
    "When the user asks for JSON, reply with a single JSON value only, without code fences or extra text."
)
CLAUDE_CLI_DEFAULT_MODEL = "claude-haiku-4-5-20251001"
BILLING_ENV_VARS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK",
                    "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY")
_ENV_ALLOWLIST = ("PATH", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
                  "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SYSTEMROOT", "COMSPEC", "PATHEXT", "TEMP", "TMP")
_CLAUDE_BIN_CANDIDATES = ("~/.claude/local/claude", "~/.local/bin/claude", "/opt/homebrew/bin/claude",
                          "/usr/local/bin/claude", "~/.npm-global/bin/claude")
_LIMIT_MARKERS = ("usage limit", "limit reached", "rate limit", "rate_limit", "hit your limit")


class ClaudeCLIClient:
    backend = "claude-cli"

    def __init__(self, model: Optional[str] = None, claude_bin: Optional[str] = None,
                 max_retries: Optional[int] = None, timeout: Optional[float] = None,
                 effort: Optional[str] = None, runner: Any = None) -> None:
        found = [n for n in BILLING_ENV_VARS if (_os.environ.get(n) or "").strip()]
        if found:
            raise LLMNotConfiguredError(
                "claude-cli runs on your Claude subscription only. Unset these variables first: " + ", ".join(found))
        self.model = model or _os.getenv("CAASM_CLAUDE_MODEL") or CLAUDE_CLI_DEFAULT_MODEL
        self._bin = claude_bin or _os.getenv("CAASM_CLAUDE_BIN") or _shutil.which("claude") or next(
            (p for p in map(_os.path.expanduser, _CLAUDE_BIN_CANDIDATES) if _os.path.isfile(p) and _os.access(p, _os.X_OK)),
            None)
        if not self._bin:
            raise LLMNotConfiguredError(
                "the `claude` command was not found. Run `type claude` in your terminal and set "
                "CAASM_CLAUDE_BIN to the full path it shows (if it is an alias, the path the alias points to).")
        self.max_retries = max_retries if max_retries is not None else config.llm_max_retries()
        self.timeout = timeout or float(_os.getenv("CAASM_LLM_TIMEOUT", "300"))
        self.effort = effort or _os.getenv("CAASM_CLAUDE_EFFORT", "low")
        self._runner = runner or self._run
        self._sandbox = _tempfile.mkdtemp(prefix="strayhost_claude_")
        _os.makedirs(_os.path.join(self._sandbox, "home"), exist_ok=True)
        _os.makedirs(_os.path.join(self._sandbox, "cwd"), exist_ok=True)
        self._lock = threading.Lock()
        self.requests = 0
        self._env()  # validate the token file now, not at the first call

    def __repr__(self) -> str:
        return f"ClaudeCLIClient(model={self.model!r}, effort={self.effort!r})"

    def _env(self) -> Dict[str, str]:
        env = {k: _os.environ[k] for k in _ENV_ALLOWLIST if k in _os.environ}
        home = _os.path.join(self._sandbox, "home")
        # HOME (macOS/Linux), USERPROFILE (Windows) and CLAUDE_CONFIG_DIR all point to an empty
        # folder, so the CLI cannot read your settings, memory or login files.
        env.update({"LANG": "C.UTF-8", "TZ": "UTC", "DISABLE_AUTOUPDATER": "1", "DISABLE_TELEMETRY": "1",
                    "HOME": home, "USERPROFILE": home, "CLAUDE_CONFIG_DIR": _os.path.join(home, ".claude")})
        token_file = _os.getenv("CAASM_CLAUDE_OAUTH_TOKEN_FILE")
        if token_file:
            with open(_os.path.expanduser(token_file), encoding="utf-8") as f:
                token = f.read().strip()
            if not token.startswith("sk-ant-oat"):
                raise LLMNotConfiguredError(
                    "CAASM_CLAUDE_OAUTH_TOKEN_FILE must contain a subscription token from `claude setup-token` (not an API key)")
            env["CLAUDE_CODE_OAUTH_TOKEN"] = token
        return env

    def _argv(self, system_prompt: str) -> List[str]:
        import sys as _sys
        prefix = [_sys.executable, "-X", "utf8", self._bin] if self._bin.endswith(".py") else [self._bin]  # .py: test stand-in
        return prefix + ["-p", "--model", self.model, "--system-prompt", system_prompt, "--tools", "",
                "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}', "--setting-sources", "",
                "--no-session-persistence", "--effort", self.effort, "--output-format", "stream-json", "--verbose"]

    def _run(self, argv: List[str], stdin_text: str, env: Dict[str, str]):
        return _subprocess.run(argv, input=stdin_text, capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=self.timeout, env=env, cwd=_os.path.join(self._sandbox, "cwd"))

    @staticmethod
    def _parse(stdout: str):
        init = result = None
        for line in (stdout or "").splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("type") == "system" and obj.get("subtype") == "init":
                init = obj
            elif isinstance(obj, dict) and obj.get("type") == "result":
                result = obj
        return init, result

    def chat(self, messages: List[Dict[str, str]], **_: Any) -> str:
        system = [CLAUDE_CLI_SYSTEM_PROMPT] + [m["content"] for m in messages if m.get("role") == "system"]
        body = "\n\n".join(m["content"] for m in messages if m.get("role") != "system")
        argv, env = self._argv("\n\n".join(system)), self._env()
        last = "no attempt"
        for attempt in range(self.max_retries + 1):
            with self._lock:
                self.requests += 1
            try:
                proc = self._runner(argv, body, env)
            except Exception as e:  # noqa: BLE001
                last = f"{type(e).__name__}: {e}"
            else:
                init, result = self._parse(getattr(proc, "stdout", ""))
                key_source = (init or {}).get("apiKeySource")
                if (getattr(proc, "stdout", "") or "").strip() and key_source != "none":
                    # fail closed: unknown or non-subscription credentials stop the run
                    raise DailyQuotaExhaustedError(
                        f"claude CLI did not confirm subscription credentials (apiKeySource={key_source!r}); stopped "
                        "to avoid API billing", "billing_safety")
                if result is None:
                    err = (getattr(proc, "stderr", "") or "")[-400:]
                    if any(m in err.lower() for m in _LIMIT_MARKERS):
                        raise DailyQuotaExhaustedError(f"Claude usage limit reached: {err}", "daily_quota")
                    last = f"no result (exit {getattr(proc, 'returncode', None)}): {err}"
                elif result.get("is_error") or result.get("subtype") != "success":
                    msg = str(result.get("result") or result.get("subtype") or "")
                    if any(m in msg.lower() for m in _LIMIT_MARKERS):
                        raise DailyQuotaExhaustedError(f"Claude usage limit reached: {msg[:300]}", "daily_quota")
                    last = f"CLI error: {msg[:300]}"
                elif isinstance(result.get("result"), str) and result["result"].strip():
                    return result["result"]
                else:
                    last = "empty response"
            if attempt < self.max_retries:
                time.sleep(min(2 ** (attempt + 1), 20))
        raise RuntimeError(f"claude CLI call failed: {last}")

    def chat_json(self, messages: List[Dict[str, str]], **kwargs: Any) -> Any:
        return extract_json(self.chat(messages, **kwargs))


def get_client(model: Optional[str] = None, backend: Optional[str] = None):
    if config.is_mock_active():
        return MockLLM()
    if (backend or config.llm_backend()) == "claude-cli":
        return ClaudeCLIClient(model=model)
    return LLMClient(model=model)
