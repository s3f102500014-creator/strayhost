"""Deterministic mapping from source coverage (ledger, EDR, ASM) to case and risk."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple


CoverageVector = Tuple[bool, bool, bool]

_COVERAGE_TO_CASE: Dict[CoverageVector, str] = {
    (True, True, False): "A",
    (True, True, True): "B",
    (True, False, False): "C",
    (True, False, True): "D",
    (False, True, False): "E",
    (False, True, True): "F",
    (False, False, True): "G",
    (False, False, False): "H",
}


@dataclass(frozen=True)
class Coverage:

    ledger: bool
    edr: bool
    asm: bool

    def as_tuple(self) -> CoverageVector:
        return (self.ledger, self.edr, self.asm)


def coverage_to_case(coverage: Coverage) -> str:
    return _COVERAGE_TO_CASE[coverage.as_tuple()]
