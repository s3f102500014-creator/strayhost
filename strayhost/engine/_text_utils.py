"""Name similarity and subnet helpers."""

from __future__ import annotations

from typing import Optional

try:
    from rapidfuzz import fuzz as _rapidfuzz_fuzz

    _HAS_RAPIDFUZZ = True
except ImportError:
    _HAS_RAPIDFUZZ = False
    import difflib


def similarity_backend() -> str:
    if _HAS_RAPIDFUZZ:
        import rapidfuzz

        return f"rapidfuzz-{getattr(rapidfuzz, '__version__', 'unknown')}"
    return "difflib"


def similarity_ratio(a: Optional[str], b: Optional[str]) -> float:
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    if _HAS_RAPIDFUZZ:
        return _rapidfuzz_fuzz.ratio(a, b) / 100.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def subnet_24(ip: Optional[str]) -> Optional[str]:
    if not ip or not isinstance(ip, str):
        return None
    parts = ip.strip().split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return None
    return ".".join(parts[:3])
