"""Case definitions (which of the three lists an asset appears in) and risk levels."""

from __future__ import annotations

from typing import Dict

RISK_MAP_DEFAULT: Dict[str, str] = {
    "D": "Critical",
    "F": "Critical",
    "G": "Critical",
    "B": "Important",
    "C": "Important",
    "E": "Important",
    "A": "Informational",
    "H": "Informational",
}


def case_to_risk(case: str) -> str:
    return RISK_MAP_DEFAULT.get(case, "Unknown")
