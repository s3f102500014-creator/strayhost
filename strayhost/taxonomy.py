"""Case definitions (which of the three lists an asset appears in) and risk levels."""

from __future__ import annotations

from typing import Dict

RISK_MAP_DEFAULT: Dict[str, str] = {  # risk levels of Aki et al., ICSPIS 2025
    "C": "Critical",
    "D": "Critical",
    "G": "Critical",
    "A": "Important",
    "E": "Important",
    "F": "Important",
    "B": "Informational",
    "H": "Informational",
}


def case_to_risk(case: str) -> str:
    return RISK_MAP_DEFAULT.get(case, "Unknown")
