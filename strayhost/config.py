"""Runtime settings for strayhost.

Everything is resolved from environment variables at call time. No credentials,
hosts or file paths are hard-coded. See README.md ("LLM settings").
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

# ---- default locations ------------------------------------------------------

# ---- LLM endpoint (OpenAI-compatible /chat/completions) ---------------------
LLM_BASE_URL_ENV_VAR = "STRAYHOST_LLM_BASE_URL"   # e.g. https://api.openai.com/v1
LLM_API_KEY_ENV_VAR = "STRAYHOST_LLM_API_KEY"
LLM_MODEL_ENV_VAR = "STRAYHOST_LLM_MODEL"
LLM_TIMEOUT_ENV_VAR = "STRAYHOST_LLM_TIMEOUT"
LLM_REASONING_EFFORT_ENV_VAR = "STRAYHOST_LLM_REASONING_EFFORT"  # optional; sent only if set
LLM_BACKEND_NAME = "openai-compatible"


def llm_base_url() -> Optional[str]:
    v = os.getenv(LLM_BASE_URL_ENV_VAR, "").strip()
    return v.rstrip("/") or None


def llm_api_key() -> Optional[str]:
    v = os.getenv(LLM_API_KEY_ENV_VAR, "").strip()
    return v or None


def llm_model() -> Optional[str]:
    v = os.getenv(LLM_MODEL_ENV_VAR, "").strip()
    return v or None


def llm_timeout() -> float:
    return float(os.getenv(LLM_TIMEOUT_ENV_VAR, "120"))


def llm_max_retries() -> int:
    return int(os.getenv("STRAYHOST_LLM_MAX_RETRIES", "4"))


def llm_backend() -> str:
    """'openai' (any OpenAI-compatible endpoint, default) or 'claude-cli'."""
    return os.getenv("STRAYHOST_LLM_BACKEND", "openai").strip().lower()


def llm_configured() -> bool:
    """True when an LLM is configured: STRAYHOST_LLM_BACKEND=claude-cli, or an OpenAI-compatible
    endpoint and model (an API key may be optional, e.g. for a local Ollama server)."""
    if llm_backend() == "claude-cli":
        return True
    return bool(llm_base_url() and llm_model())


# None = do not send reasoning_effort (many endpoints reject it).
DEFAULT_REASONING_EFFORT: Optional[str] = os.getenv(LLM_REASONING_EFFORT_ENV_VAR) or None

# ---- mock LLM (offline tests) ------------------------------------------------
LLM_MOCK_ENV_VAR = "STRAYHOST_LLM_MOCK"


def is_mock_active() -> bool:
    return os.getenv(LLM_MOCK_ENV_VAR) == "1"


def mock_suffixed_path(path: Path) -> Path:
    return path.with_name(f"{path.stem}_mock{path.suffix}")


# ---- adjudication settings ------------------------------------------------------
LLM_GRAY_LOW_ENV_VAR = "STRAYHOST_LLM_GRAY_LOW"
LLM_WORKERS_ENV_VAR = "STRAYHOST_LLM_WORKERS"
LLM_SIZE_CAP_ENV_VAR = "STRAYHOST_LLM_SIZECAP"
LLM_BATCH_SIZE_ENV_VAR = "STRAYHOST_LLM_BATCH_SIZE"
DEFAULT_LLM_BATCH_SIZE = 25
LLM_BATCH_SIZE_MIN = 1
LLM_BATCH_SIZE_MAX = 25
LLM_MAX_CALLS_ENV_VAR = "STRAYHOST_LLM_MAX_CALLS"


def resolve_llm_max_calls() -> Optional[int]:
    raw = os.getenv(LLM_MAX_CALLS_ENV_VAR)
    if raw is None or raw.strip() == "":
        return None
    return int(raw)
