"""Deterministic mapping from source coverage (ledger, EDR, ASM) to case and risk."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple


CoverageVector = Tuple[bool, bool, bool]

_COVERAGE_TO_CASE: Dict[CoverageVector, str] = {
    # (ITAM ledger, EDR, ASM) -> case, as in Table I of Aki et al., ICSPIS 2025
    (True, True, True): "A",
    (True, True, False): "B",
    (True, False, True): "C",
    (False, True, True): "D",
    (True, False, False): "E",
    (False, True, False): "F",
    (False, False, True): "G",
    (False, False, False): "H",  # not observed anywhere; never produced from input records
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
