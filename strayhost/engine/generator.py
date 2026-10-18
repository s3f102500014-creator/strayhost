"""Synthetic population of devices and their ledger / EDR / ASM records."""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple

from ..rule_engine import Coverage


@dataclass(frozen=True)
class RoleDef:
    name: str
    coverage: Coverage
    prefix: str


ROLE_DEFS: Dict[str, RoleDef] = {
    "A": RoleDef("workstation", Coverage(ledger=True, edr=True, asm=False), "wks"),
    "B": RoleDef("public_server", Coverage(ledger=True, edr=True, asm=True), "pub"),
    "C": RoleDef("dormant", Coverage(ledger=True, edr=False, asm=False), "dorm"),
    "D": RoleDef("unmonitored_public_server", Coverage(ledger=True, edr=False, asm=True), "umpub"),
    "E": RoleDef("unmanaged_internal_host", Coverage(ledger=False, edr=True, asm=False), "shd"),
    "F": RoleDef("unmanaged_public_host", Coverage(ledger=False, edr=True, asm=True), "shdpub"),
    "G": RoleDef("unknown_external_asset", Coverage(ledger=False, edr=False, asm=True), "ext"),
}

CASES_ORDER: Tuple[str, ...] = ("A", "B", "C", "D", "E", "F", "G")

DEFAULT_IMBALANCED_RATIOS: Dict[str, float] = {
    "A": 0.60,
    "B": 0.15,
    "C": 0.10,
    "D": 0.05,
    "E": 0.04,
    "F": 0.03,
    "G": 0.03,
}

DEFAULT_DEPARTMENTS: Tuple[str, ...] = (
    "Sales",
    "Engineering",
    "Finance",
    "HR",
    "IT",
    "Marketing",
    "Operations",
)

_BASE_TIMESTAMP = datetime(2024, 1, 1, tzinfo=timezone.utc)


OBSERVATION_WINDOW_MINUTES: int = 30 * 24 * 60

LEDGER_ID_NUMBER_RANGE: Tuple[int, int] = (10000, 100000)


def ledger_ids_from_number(num: int) -> Tuple[str, str]:
    h = (num * 2654435761 + 0x9E3779B9) & 0xFFFFFFFF
    return f"AST-{num:05d}", f"i-{h:08x}"


_ADDR_SECOND = tuple(range(1, 21))
_ADDR_THIRD = tuple(range(0, 10))
_ADDR_HOST = tuple(range(1, 255))
ADDRESS_POOL_SIZE: int = len(_ADDR_SECOND) * len(_ADDR_THIRD) * len(_ADDR_HOST)


def _ip_from_index(k: int) -> str:
    h = len(_ADDR_HOST)
    t = len(_ADDR_THIRD)
    host = _ADDR_HOST[k % h]
    third = _ADDR_THIRD[(k // h) % t]
    second = _ADDR_SECOND[k // (h * t)]
    return f"10.{second}.{third}.{host}"


def sample_internal_ips(rng: random.Random, k: int) -> List[str]:
    return [_ip_from_index(i) for i in rng.sample(range(ADDRESS_POOL_SIZE), k)]


def random_peer(rng: random.Random, internal_domain_suffix: str) -> Tuple[str, str]:
    dest_ip = _ip_from_index(rng.randrange(ADDRESS_POOL_SIZE))
    dest_fqdn = f"peer-{rng.randrange(100000):05d}.{internal_domain_suffix}"
    return dest_ip, dest_fqdn


def random_observation_ts(rng: random.Random) -> str:
    return _ts(0, minutes_offset=rng.randrange(OBSERVATION_WINDOW_MINUTES))


@dataclass(frozen=True)
class AssetGenConfig:

    n: int = 150
    seed: int = 0
    mode: str = "balanced"
    ratios: Optional[Dict[str, float]] = None
    departments: Tuple[str, ...] = DEFAULT_DEPARTMENTS
    internal_domain_suffix: str = "corp.example.local"
    external_domain_suffix: str = "example.com"


@dataclass
class AssetMeta:

    true_id: str
    role: str
    case: str
    department: str
    owner_user: str
    hostname: str
    internal_ip: str


@dataclass
class GroundTruth:

    assets: Dict[str, AssetMeta] = field(default_factory=dict)
    true_clusters: Dict[str, Set[str]] = field(default_factory=dict)
    record_to_asset: Dict[str, str] = field(default_factory=dict)

    def true_case_of(self, true_id: str) -> str:
        return self.assets[true_id].case

    def n_assets(self) -> int:
        return len(self.assets)


@dataclass
class PopulationResult:
    records: Dict[str, List[dict]]
    ground_truth: GroundTruth
    config: AssetGenConfig


def _largest_remainder_counts(n: int, ratios: Dict[str, float], order: Tuple[str, ...]) -> Dict[str, int]:
    total_ratio = sum(ratios.get(c, 0.0) for c in order)
    if total_ratio <= 0:
        raise ValueError("sum of ratios must be > 0")
    raw = {c: n * ratios.get(c, 0.0) / total_ratio for c in order}
    counts = {c: int(raw[c]) for c in order}
    remainder = n - sum(counts.values())
    fracs = sorted(order, key=lambda c: (-(raw[c] - counts[c]), order.index(c)))
    for c in fracs[:remainder]:
        counts[c] += 1
    return counts


def _case_counts(n: int, mode: str, ratios: Optional[Dict[str, float]]) -> Dict[str, int]:
    if mode == "balanced":
        even_ratios = {c: 1.0 for c in CASES_ORDER}
        return _largest_remainder_counts(n, even_ratios, CASES_ORDER)
    if mode == "imbalanced":
        use_ratios = ratios if ratios is not None else DEFAULT_IMBALANCED_RATIOS
        return _largest_remainder_counts(n, use_ratios, CASES_ORDER)
    raise ValueError(f"unknown mode {mode!r} (balanced | imbalanced)")


def _ts(idx: int, minutes_offset: int = 0) -> str:
    t = _BASE_TIMESTAMP + timedelta(minutes=idx + minutes_offset)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


_COMMON_PORTS = (22, 80, 443, 3389, 8080, 3306, 8443, 21)


def _make_asset(
    idx: int,
    case: str,
    config: AssetGenConfig,
    rng: random.Random,
    id_number: int,
    host_suffix: str,
    internal_ip: str,
) -> Tuple[AssetMeta, Dict[str, dict]]:
    role_def = ROLE_DEFS[case]
    true_id = f"GT-{idx:05d}"
    dept = config.departments[idx % len(config.departments)]
    hostname = f"{role_def.prefix}-{host_suffix}"
    owner_user = f"{dept.lower()[:3]}.user{rng.randint(1, 9999):04d}"

    meta = AssetMeta(
        true_id=true_id,
        role=role_def.name,
        case=case,
        department=dept,
        owner_user=owner_user,
        hostname=hostname,
        internal_ip=internal_ip,
    )

    cov = role_def.coverage
    recs: Dict[str, Optional[dict]] = {"ledger": None, "edr": None, "asm": None}

    if cov.ledger:
        asset_id, instance_id = ledger_ids_from_number(id_number)
        recs["ledger"] = {
            "asset_id": asset_id,
            "hostname": hostname.upper(),
            "ip": internal_ip,
            "fqdn": f"{hostname}.{config.internal_domain_suffix}",
            "instance_id": instance_id,
            "owner_dept": dept,
            "owner_user": owner_user,
            "_gt_true_id": true_id,
        }
    if cov.edr:
        recs["edr"] = {
            "asset_id_or_hostname": hostname,
            "ip": internal_ip,
            "observed_at": random_observation_ts(rng),
            "_gt_true_id": true_id,
        }
        recs["edr"]["dest_ip"], recs["edr"]["dest_fqdn"] = random_peer(rng, config.internal_domain_suffix)
    if cov.asm:
        recs["asm"] = {
            "public_ip": internal_ip,
            "domain": f"{hostname}.{config.external_domain_suffix}",
            "discovered_at": random_observation_ts(rng),
            "open_ports": ",".join(str(p) for p in sorted(rng.sample(_COMMON_PORTS, k=rng.randint(1, 3)))),
            "vuln_score": round(rng.uniform(0.0, 10.0), 1),
            "_gt_true_id": true_id,
        }

    return meta, recs


def finalize_population(records_by_source: Dict[str, List[dict]]) -> Tuple[Dict[str, List[dict]], GroundTruth]:
    gt = GroundTruth()
    for source in ("ledger", "edr", "asm"):
        records = records_by_source.get(source, [])
        for i, rec in enumerate(records):
            true_id = rec.pop("_gt_true_id", None)
            internal_id = f"{source}_{i}"
            rec["_internal_id"] = internal_id
            if true_id is not None:
                gt.record_to_asset[internal_id] = true_id
                gt.true_clusters.setdefault(true_id, set()).add(internal_id)
    return records_by_source, gt


def generate_population(config: AssetGenConfig) -> PopulationResult:
    rng = random.Random(config.seed)

    counts = _case_counts(config.n, config.mode, config.ratios)
    case_sequence: List[str] = []
    for case in CASES_ORDER:
        case_sequence.extend([case] * counts[case])
    rng.shuffle(case_sequence)

    records_by_source: Dict[str, List[dict]] = {"ledger": [], "edr": [], "asm": []}
    assets: Dict[str, AssetMeta] = {}

    lo, hi = LEDGER_ID_NUMBER_RANGE
    id_numbers = rng.sample(range(lo, hi), len(case_sequence))
    host_suffixes = [format(v, "05x") for v in rng.sample(range(16**5), len(case_sequence))]
    internal_ips = sample_internal_ips(rng, len(case_sequence))

    for idx, case in enumerate(case_sequence):
        meta, recs = _make_asset(idx, case, config, rng, id_numbers[idx], host_suffixes[idx], internal_ips[idx])
        assets[meta.true_id] = meta
        for source, rec in recs.items():
            if rec is not None:
                records_by_source[source].append(rec)

    records_by_source, gt = finalize_population(records_by_source)
    gt.assets = assets
    return PopulationResult(records=records_by_source, ground_truth=gt, config=config)
