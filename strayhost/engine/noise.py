"""Noise-based synthetic data (style g1): name variations, address changes, NAT, missing fields, owner conflicts, look-alike decoy devices and stale records."""

from __future__ import annotations

import copy
import random
import re
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple

from . import generator as gen

Records = Dict[str, List[dict]]


_HEX = "0123456789abcdef"
_HEX_RUN_RE = re.compile(r"[0-9a-fA-F]{3,}")


def _typo_hostname(name: str, rng: random.Random) -> str:
    runs = list(_HEX_RUN_RE.finditer(name))
    if runs:
        run = runs[-1]
        pos = rng.randrange(run.start(), run.end())
    else:
        alnum = [i for i, ch in enumerate(name) if ch.isalnum()]
        if not alnum:
            return name + rng.choice(_HEX)
        pos = alnum[-1]
    old = name[pos]
    choices = [c for c in _HEX if c != old.lower()]
    new = rng.choice(choices)
    letters = [ch for ch in name if ch.isalpha()]
    if letters and all(ch.isupper() for ch in letters):
        new = new.upper()
    return name[:pos] + new + name[pos + 1 :]


_NAME_TRANSFORMS: Tuple[Callable[[str], str], ...] = (
    lambda s: s.upper(),
    lambda s: s.lower(),
    lambda s: f"{s}-01",
    lambda s: f"{s}.vm",
    lambda s: s.replace("-", "_"),
    lambda s: s[: max(3, len(s) - 2)],
)


def _rng_for(seed: int, name: str) -> random.Random:
    return random.Random(f"{seed}:{name}")


def _bernoulli(rng: random.Random, p: float) -> bool:
    return rng.random() < p


def _reattach_true_ids(records: Records, gt: gen.GroundTruth) -> None:
    for source, recs in records.items():
        for rec in recs:
            internal_id = rec.get("_internal_id")
            true_id = gt.record_to_asset.get(internal_id)
            if true_id is not None:
                rec["_gt_true_id"] = true_id
            rec.pop("_internal_id", None)


def _assets_records_index(records: Records, gt: gen.GroundTruth) -> Dict[str, List[Tuple[str, dict]]]:
    index: Dict[str, List[Tuple[str, dict]]] = {tid: [] for tid in gt.assets}
    for source, recs in records.items():
        for rec in recs:
            tid = rec.get("_gt_true_id")
            if tid in index:
                index[tid].append((source, rec))
    return index


def dynamic_reassignment(records: Records, gt: gen.GroundTruth, p: float, seed: int) -> None:
    rng = _rng_for(seed, "dynamic_reassignment")
    for rec in records.get("edr", []):
        if not rec.get("ip"):
            continue
        if _bernoulli(rng, p):
            octets = rec["ip"].split(".")
            if len(octets) == 4:
                new_host = rng.randint(1, 250)
                octets[-1] = str(new_host)
                rec["ip"] = ".".join(octets)


_NAME_FIELDS = {
    "ledger": ("hostname", "fqdn"),
    "edr": ("asset_id_or_hostname",),
    "asm": ("domain",),
}


def naming_variation(records: Records, gt: gen.GroundTruth, p: float, seed: int) -> None:
    for source, fields in _NAME_FIELDS.items():
        rng = _rng_for(seed, f"naming_variation:{source}")
        for rec in records.get(source, []):
            for f in fields:
                val = rec.get(f)
                if not val:
                    continue
                if _bernoulli(rng, p):
                    transform = rng.choice(_NAME_TRANSFORMS)
                    new_val = transform(val)
                    if new_val == val:
                        new_val = f"{val}-x"
                    rec[f] = new_val


_MISSINGNESS_FIELDS = {
    "ledger": ("hostname", "ip", "fqdn", "instance_id", "owner_dept", "owner_user"),
    "edr": ("asset_id_or_hostname", "ip", "observed_at", "dest_ip", "dest_fqdn"),
    "asm": ("public_ip", "domain", "discovered_at", "open_ports", "vuln_score"),
}


def field_missingness(records: Records, gt: gen.GroundTruth, p: float, seed: int) -> None:
    for source, fields in _MISSINGNESS_FIELDS.items():
        rng = _rng_for(seed, f"field_missingness:{source}")
        for rec in records.get(source, []):
            for f in fields:
                if rec.get(f) in (None, ""):
                    continue
                if _bernoulli(rng, p):
                    rec[f] = ""


def nat_translation(records: Records, gt: gen.GroundTruth, p: float, seed: int) -> None:
    rng = _rng_for(seed, "nat_translation")
    for rec in records.get("asm", []):
        if not rec.get("public_ip"):
            continue
        if _bernoulli(rng, p):
            block = rng.randint(0, 99)
            host = rng.randint(1, 250)
            rec["public_ip"] = f"203.0.{113 if block % 2 == 0 else 114}.{host}"


def owner_conflict(records: Records, gt: gen.GroundTruth, p: float, seed: int) -> None:
    rng = _rng_for(seed, "owner_conflict")
    departments = gen.DEFAULT_DEPARTMENTS
    for rec in records.get("ledger", []):
        if not rec.get("owner_dept"):
            continue
        if _bernoulli(rng, p):
            others = [d for d in departments if d != rec["owner_dept"]]
            rec["owner_dept"] = rng.choice(others) if others else rec["owner_dept"]
            rec["owner_user"] = f"{rec['owner_dept'].lower()[:3]}.user{rng.randint(1, 9999):04d}"


_DECOY_SOURCE_TO_CASE = {"ledger": "C", "edr": "E", "asm": "G"}
_DECOY_NAME_FIELD = {"ledger": "hostname", "edr": "asset_id_or_hostname", "asm": "domain"}
_DECOY_IP_FIELD = {"ledger": "ip", "edr": "ip", "asm": "public_ip"}

_DECOY_INTERNAL_DOMAIN_SUFFIX = "corp.example.local"
_DECOY_EXTERNAL_DOMAIN_SUFFIX = "example.com"


def _draw_different_last_octet(rng: random.Random, exclude: int) -> int:
    candidates = [i for i in range(1, 255) if i != exclude]
    return rng.choice(candidates)


def _independent_neighbor_ip(base_ip: Optional[str], rng: random.Random) -> Optional[str]:
    if not base_ip or not isinstance(base_ip, str):
        return None
    octets = base_ip.split(".")
    if len(octets) != 4 or not all(o.isdigit() for o in octets):
        return None
    base_last = int(octets[-1])
    new_last = _draw_different_last_octet(rng, base_last)
    return ".".join(octets[:3] + [str(new_last)])


def _build_decoy_record(
    source: str,
    decoy_hostname: str,
    decoy_ip: Optional[str],
    decoy_counter: int,
    rng: random.Random,
    used_id_numbers: Optional[set] = None,
) -> dict:
    if source == "ledger":
        dept = rng.choice(gen.DEFAULT_DEPARTMENTS)
        owner_user = f"{dept.lower()[:3]}.user{rng.randint(1, 9999):04d}"
        lo, hi = gen.LEDGER_ID_NUMBER_RANGE
        used = used_id_numbers if used_id_numbers is not None else set()
        num = rng.randrange(lo, hi)
        while num in used:
            num = rng.randrange(lo, hi)
        used.add(num)
        asset_id, instance_id = gen.ledger_ids_from_number(num)
        rec: dict = {
            "asset_id": asset_id,
            "hostname": decoy_hostname.upper(),
            "fqdn": f"{decoy_hostname.lower()}.{_DECOY_INTERNAL_DOMAIN_SUFFIX}",
            "instance_id": instance_id,
            "owner_dept": dept,
            "owner_user": owner_user,
        }
        if decoy_ip:
            rec["ip"] = decoy_ip
        return rec

    if source == "edr":
        dest_ip, dest_fqdn = gen.random_peer(rng, _DECOY_INTERNAL_DOMAIN_SUFFIX)
        rec = {
            "asset_id_or_hostname": decoy_hostname,
            "observed_at": gen.random_observation_ts(rng),
            "dest_ip": dest_ip,
            "dest_fqdn": dest_fqdn,
        }
        if decoy_ip:
            rec["ip"] = decoy_ip
        return rec

    open_ports = ",".join(str(port) for port in sorted(rng.sample(gen._COMMON_PORTS, k=rng.randint(1, 3))))
    vuln_score = round(rng.uniform(0.0, 10.0), 1)
    rec = {
        "domain": f"{decoy_hostname}.{_DECOY_EXTERNAL_DOMAIN_SUFFIX}",
        "discovered_at": gen.random_observation_ts(rng),
        "open_ports": open_ports,
        "vuln_score": vuln_score,
    }
    if decoy_ip:
        rec["public_ip"] = decoy_ip
    return rec


def neighbor_decoy(records: Records, gt: gen.GroundTruth, p: float, seed: int) -> None:
    rng = _rng_for(seed, "neighbor_decoy")
    index = _assets_records_index(records, gt)
    decoy_counter = 0
    existing_names = set()
    for src, field in _DECOY_NAME_FIELD.items():
        for rec in records.get(src, []):
            val = rec.get(field)
            if val:
                existing_names.add(str(val).split(".")[0].lower())
    used_id_numbers = set()
    for rec in records.get("ledger", []):
        aid = str(rec.get("asset_id") or "")
        if aid.startswith("AST-") and aid[4:].isdigit():
            used_id_numbers.add(int(aid[4:]))

    for true_id in sorted(gt.assets):
        asset_recs = index.get(true_id, [])
        if not asset_recs or not _bernoulli(rng, p):
            continue

        source, base_rec = rng.choice(asset_recs)
        name_field = _DECOY_NAME_FIELD[source]
        ip_field = _DECOY_IP_FIELD[source]
        base_name = base_rec.get(name_field)
        base_ip = base_rec.get(ip_field)
        if not base_name:
            continue

        decoy_true_id = f"GT-DECOY-{decoy_counter:05d}"
        decoy_case = _DECOY_SOURCE_TO_CASE[source]
        decoy_hostname = _typo_hostname(base_name.split(".")[0], rng)
        for _ in range(20):
            if decoy_hostname.lower() not in existing_names:
                break
            decoy_hostname = _typo_hostname(base_name.split(".")[0], rng)
        existing_names.add(decoy_hostname.lower())
        decoy_ip = _independent_neighbor_ip(base_ip, rng)

        decoy_rec = _build_decoy_record(source, decoy_hostname, decoy_ip, decoy_counter, rng, used_id_numbers)
        decoy_rec["_gt_true_id"] = decoy_true_id

        records.setdefault(source, []).append(decoy_rec)
        gt.assets[decoy_true_id] = gen.AssetMeta(
            true_id=decoy_true_id,
            role="neighbor_decoy",
            case=decoy_case,
            department=decoy_rec.get("owner_dept", "N/A") or "N/A",
            owner_user=decoy_rec.get("owner_user", "N/A") or "N/A",
            hostname=decoy_hostname,
            internal_ip=decoy_rec.get(ip_field, ""),
        )
        decoy_counter += 1


def _stale_timestamp(rng: random.Random) -> str:
    t = datetime(2019, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=rng.randrange(365 * 24 * 60))
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def stale_records(records: Records, gt: gen.GroundTruth, p: float, seed: int) -> None:
    rng = _rng_for(seed, "stale_records")
    index = _assets_records_index(records, gt)

    for true_id in sorted(gt.assets):
        for source in ("edr", "asm"):
            candidates = [(s, r) for s, r in index.get(true_id, []) if s == source]
            if not candidates:
                continue
            _, base_rec = candidates[0]
            if not _bernoulli(rng, p):
                continue

            stale_rec = copy.deepcopy(base_rec)
            stale_rec.pop("_internal_id", None)
            stale_rec["_gt_true_id"] = true_id

            ip_field = "ip" if source == "edr" else "public_ip"
            orig_ip = stale_rec.get(ip_field)
            if orig_ip:
                octets = str(orig_ip).split(".")
                if len(octets) == 4 and all(o.isdigit() for o in octets):
                    octets[-1] = str((int(octets[-1]) % 250) + 1)
                    stale_rec[ip_field] = ".".join(octets)
            else:
                stale_rec[ip_field] = ""

            if source == "edr":
                orig_name = stale_rec.get("asset_id_or_hostname")
                stale_rec["asset_id_or_hostname"] = f"{orig_name}-legacy" if orig_name else ""
                stale_rec["observed_at"] = _stale_timestamp(rng)
            else:
                orig_domain = stale_rec.get("domain")
                stale_rec["domain"] = f"legacy-{orig_domain}" if orig_domain else ""
                stale_rec["discovered_at"] = _stale_timestamp(rng)

            records.setdefault(source, []).append(stale_rec)


PERTURBATORS: Dict[str, Callable[[Records, gen.GroundTruth, float, int], None]] = {
    "dynamic_reassignment": dynamic_reassignment,
    "naming_variation": naming_variation,
    "field_missingness": field_missingness,
    "nat_translation": nat_translation,
    "owner_conflict": owner_conflict,
    "neighbor_decoy": neighbor_decoy,
    "stale_records": stale_records,
}

APPLY_ORDER: Tuple[str, ...] = (
    "neighbor_decoy",
    "dynamic_reassignment",
    "naming_variation",
    "field_missingness",
    "nat_translation",
    "owner_conflict",
    "stale_records",
)


def apply_noise(
    records: Records,
    ground_truth: gen.GroundTruth,
    p: float,
    seed: int = 0,
) -> Tuple[Records, gen.GroundTruth]:
    if not (0.0 <= p <= 1.0):
        raise ValueError(f"p must be in [0, 1]: {p}")

    names = list(APPLY_ORDER)
    unknown = set(names) - set(PERTURBATORS)
    if unknown:
        raise ValueError(f"unknown perturbator: {sorted(unknown)}")

    records_copy: Records = copy.deepcopy(records)
    gt_copy = copy.deepcopy(ground_truth)
    _reattach_true_ids(records_copy, gt_copy)

    for name in APPLY_ORDER:
        if name in names:
            PERTURBATORS[name](records_copy, gt_copy, p, seed)

    final_records, gt_rebuilt = gen.finalize_population(records_copy)
    gt_rebuilt.assets = gt_copy.assets
    return final_records, gt_rebuilt
