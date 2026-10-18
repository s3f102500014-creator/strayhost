"""CSV loading and identifier extraction."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Dict, List, Optional, Set



def normalize_hostname(name: Optional[str]) -> Optional[str]:
    return name.split(".")[0].lower() if name and isinstance(name, str) else None


def load_local_csv(filename: Path) -> Optional[List[Dict[str, str]]]:
    try:
        with open(filename, mode="r", encoding="utf-8-sig") as infile:
            reader = csv.DictReader(infile)
            data = [row for row in reader if any(field.strip() for field in row.values())]
        return data
    except FileNotFoundError:
        return None


def load_all_data(
    ledger_csv: Path,
    edr_csv: Path,
    asm_csv: Path,
) -> Optional[Dict[str, List[Dict[str, str]]]]:
    sources = {"ledger": ledger_csv, "asm": asm_csv, "edr": edr_csv}
    all_data: Dict[str, List[Dict[str, str]]] = {}
    for name, filename in sources.items():
        data = load_local_csv(filename)
        if data is None:
            return None
        for i, record in enumerate(data):
            record["_internal_id"] = f"{name}_{i}"
        all_data[name] = data
    return all_data


def get_identifiers_from_record(record: Dict[str, str], source_type: str) -> Set[str]:
    ids: Set[Optional[str]] = set()

    if source_type == "ledger":
        ids.add(record.get("asset_id"))
        ids.add(normalize_hostname(record.get("hostname")))
        ids.add(record.get("ip"))
    elif source_type == "edr":
        ids.add(normalize_hostname(record.get("asset_id_or_hostname")))
        ids.add(record.get("ip"))
    elif source_type == "asm":
        ids.add(normalize_hostname(record.get("domain")))
        ids.add(record.get("public_ip"))

    return {str(i).strip() for i in ids if i and str(i).strip()}


