"""Event-based synthetic data: renames, DHCP changes, moves, replacements with name reuse, NAT and records left over from before a change."""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from . import generator as gen

Records = Dict[str, List[dict]]


WEIGHTS: Dict[str, float] = {
    "rename": 0.5,
    "dhcp": 2.0,
    "move": 0.5,
    "stale": 0.5,
    "replace": 0.5,
    "nat": 1.0,
    "asm_service_name": 1.5,
}
MISSING_WEIGHTS: Dict[str, Dict[str, float]] = {
    "ledger": {"owner_user": 1.5, "owner_dept": 1.0, "instance_id": 2.0, "fqdn": 1.0, "hostname": 0.2, "ip": 0.3},
    "edr": {"asset_id_or_hostname": 0.05, "ip": 0.3, "dest": 1.0},
    "asm": {"domain": 1.0, "open_ports": 0.3, "vuln_score": 1.0},
}
LEDGER_LAG = 0.6
ASM_DNS_LAG = 0.5
DEPT_COMMON_PEER_SHARE = 0.5
ROLE_STANDARD_SHARE = 0.7
CLOUD_NAME_SHARE = 0.3
STALE_SAME_CONFIG = 0.5
ROLE_NET_INDEX = {"web": 0, "api": 0, "vpn": 0, "mail": 0, "app": 1, "db": 2, "file": 2}

INTERNAL_DOMAIN = "corp.example.local"
EXTERNAL_DOMAIN = "example.co.jp"
NOW = datetime(2025, 6, 30, tzinfo=timezone.utc)

DEPT_CODE = {"Sales": "sls", "Engineering": "eng", "Finance": "fin", "HR": "hr", "IT": "it",
             "Marketing": "mkt", "Operations": "ops"}
SERVER_ROLES = ("web", "app", "db", "file", "mail", "api", "vpn")
PUBLIC_SERVER_ROLES = ("web", "app", "mail", "api", "vpn")
ROLE_STANDARD = {
    "web": ("80,443", "nginx", "1.24.0", "1.18.0"),
    "app": ("8080,8443", "tomcat", "9.0.80", "9.0.31"),
    "db": ("3306", "mysql", "8.0.34", "5.7.29"),
    "file": ("445", "samba", "4.18.5", "4.11.6"),
    "mail": ("25,587", "postfix", "3.7.6", "3.4.13"),
    "api": ("443", "envoy", "1.27.0", "1.14.1"),
    "vpn": ("443,500", "strongswan", "5.9.11", "5.8.2"),
    "pc": ("3389", "rdp", "10.0", "6.3"),
    "ext": ("80,443", "apache", "2.4.57", "2.4.41"),
}
_OTHER_SOFTWARE = ("apache", "nginx", "iis", "openssh", "lighttpd", "haproxy", "jetty", "caddy")
_COMMON_PORTS = (21, 22, 25, 80, 443, 445, 3306, 3389, 5432, 8080, 8443)
_SERVICE_LABELS = ("www", "shop", "vpn", "portal", "mail", "api", "app", "cdn", "my", "support")
_EXT_WORDS = ("campaign", "promo", "event", "trial", "survey", "beta", "staging", "lp", "recruit", "contest")
_ALNUM = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"


def vuln_score_of(software: str, version: str) -> float:
    h = int(hashlib.sha256(f"{software}/{version}".encode()).hexdigest()[:8], 16)
    return round((h % 101) / 10.0, 1)


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _recent(rng: random.Random) -> str:
    return _ts(NOW - timedelta(minutes=rng.randrange(30 * 24 * 60)))


def _months_ago(rng: random.Random, lo: int, hi: int) -> str:
    return _ts(NOW - timedelta(minutes=rng.randrange(lo * 30 * 24 * 60, hi * 30 * 24 * 60)))


@dataclass
class Device:
    true_id: str
    case: str
    kind: str
    role: str
    dept: str
    name: str
    ip: str
    owner_user: str
    windows: bool
    cloud: bool = False
    public_ip: Optional[str] = None
    asm_domain: Optional[str] = None
    old_name: Optional[str] = None
    old_dept: Optional[str] = None
    old_ip: Optional[str] = None
    old_owner_user: Optional[str] = None
    ledger_lagging_name: bool = False
    ledger_lagging_move: bool = False
    asm_dns_lagging: bool = False
    nat: bool = False
    edr_ip: Optional[str] = None
    events: List[str] = field(default_factory=list)


class _World:

    def __init__(self, rng: random.Random, departments: Sequence[str]):
        self.rng = rng
        self.departments = list(departments)
        self.pc_nets = {d: [f"10.{20 + i}.{k}" for k in (10, 11)] for i, d in enumerate(self.departments)}
        self.srv_nets = {d: [f"10.{20 + i}.{k}" for k in (100, 101, 102)] for i, d in enumerate(self.departments)}
        self.public_net = ["198.51.100", "192.0.2"]
        self.used_ips: set = set()
        self.nat_pool = [self.new_ip(rng.choice(self.public_net)) for _ in range(4)]
        self.used_names: set = set()
        self.next_no: Dict[Tuple[str, str], int] = {}
        self.dept_peers = {d: [self._new_peer() for _ in range(3)] for d in self.departments}

    def _new_peer(self) -> Tuple[str, str]:
        rng = self.rng
        return (f"10.{rng.randint(1, 19)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
                f"svc-{rng.randrange(100000):05d}.{INTERNAL_DOMAIN}")

    def peer(self, dept: str) -> Tuple[str, str]:
        if self.rng.random() < DEPT_COMMON_PEER_SHARE:
            return self.rng.choice(self.dept_peers[dept])
        return self._new_peer()

    def new_ip(self, net: str, unique: bool = True, exclude: Optional[str] = None) -> str:
        for _ in range(1000):
            ip = f"{net}.{self.rng.randint(1, 254)}"
            if ip == exclude:
                continue
            if not unique or ip not in self.used_ips:
                self.used_ips.add(ip)
                return ip
        raise RuntimeError("address pool exhausted")

    def numbered_name(self, prefix: str, width: int) -> str:
        key = (prefix, str(width))
        if key not in self.next_no:
            self.next_no[key] = self.rng.randint(1, 30 if width == 2 else 400)
        while True:
            n = self.next_no[key]
            self.next_no[key] += 1 if self.rng.random() < 0.7 else 2
            name = f"{prefix}-{n:0{width}d}"
            if name not in self.used_names:
                self.used_names.add(name)
                return name

    def unique_name(self, maker) -> str:
        for _ in range(1000):
            name = maker()
            if name not in self.used_names:
                self.used_names.add(name)
                return name
        raise RuntimeError("name space exhausted")


def _owner(rng: random.Random, dept: str) -> str:
    return f"{DEPT_CODE[dept]}.user{rng.randint(1, 9999):04d}"


def _make_name(world: _World, kind: str, role: str, dept: str, cloud: bool, ip: str) -> str:
    rng = world.rng
    if kind == "pc":
        return world.numbered_name(f"{DEPT_CODE[dept]}-pc", 4)
    if kind == "server":
        if cloud:
            return world.unique_name(lambda: f"ip-10-{rng.randint(0, 255)}-{rng.randint(0, 255)}-{rng.randint(1, 254)}")
        return world.numbered_name(role, 2)
    if kind == "shadow":
        return world.unique_name(lambda: rng.choice(("DESKTOP-", "LAPTOP-")) + "".join(rng.choice(_ALNUM) for _ in range(7)))
    return world.unique_name(lambda: f"{rng.choice(_EXT_WORDS)}{rng.randint(10, 99)}")


def _config_attrs(rng: random.Random, role: str, old: bool = False) -> Tuple[str, float]:
    ports, sw, ver_now, ver_old = ROLE_STANDARD[role]
    if rng.random() < ROLE_STANDARD_SHARE:
        return ports, vuln_score_of(sw, ver_old if old else ver_now)
    ps = sorted(rng.sample(_COMMON_PORTS, k=rng.randint(1, 3)))
    sw2 = rng.choice(_OTHER_SOFTWARE)
    ver = f"{rng.randint(1, 3)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}"
    return ",".join(map(str, ps)), vuln_score_of(sw2, ver)


def _p(p: float, key: str, scale: Optional[Dict[str, float]]) -> float:
    w = WEIGHTS[key] * ((scale or {}).get(key, 1.0))
    return min(1.0, p * w)


def generate_g2(config: gen.AssetGenConfig, p: float
                ) -> Tuple[Records, gen.GroundTruth]:
    if not 0.0 <= p <= 1.0:
        raise ValueError(p)
    prng = random.Random(f"G2|{config.seed}")
    world = _World(prng, config.departments)

    counts = gen._case_counts(config.n, config.mode, config.ratios)
    cases: List[str] = [c for c in gen.CASES_ORDER for _ in range(counts[c])]
    prng.shuffle(cases)
    lo, hi = gen.LEDGER_ID_NUMBER_RANGE
    id_numbers = prng.sample(range(lo, hi), len(cases))

    devices: List[Device] = []
    configs: Dict[str, Tuple[str, float]] = {}
    for idx, case in enumerate(cases):
        dept = prng.choice(world.departments)
        if case in ("A",):
            kind, role = "pc", "pc"
        elif case in ("B", "C", "D"):
            kind = "server"
            role = prng.choice(PUBLIC_SERVER_ROLES if case in ("B", "D") else SERVER_ROLES)
        elif case in ("E", "F"):
            kind, role = "shadow", "pc"
        else:
            kind, role = "ext", "ext"
        public = case in ("B", "D", "F", "G")
        cloud = case in ("B", "D") and prng.random() < CLOUD_NAME_SHARE
        if public:
            ip = world.new_ip(prng.choice(world.public_net))
        else:
            ip = world.new_ip(_internal_net(world, kind, role, dept, prng))
        name = _make_name(world, kind, role, dept, cloud, ip)
        d = Device(true_id=f"GT-{idx:05d}", case=case, kind=kind, role=role, dept=dept, name=name, ip=ip,
                   owner_user=_owner(prng, dept), windows=(kind in ("pc", "shadow")), cloud=cloud,
                   public_ip=ip if public else None)
        devices.append(d)
        configs[d.true_id] = _config_attrs(prng, role if role in ROLE_STANDARD else "ext")

    scale_tag = ""
    rng = random.Random(f"G2|{config.seed}|{p}|{scale_tag}")
    world.rng = rng

    records: Records = {"ledger": [], "edr": [], "asm": []}
    assets: Dict[str, gen.AssetMeta] = {}
    retired = 0

    for k, d in enumerate(devices):
        cov = gen.ROLE_DEFS[d.case].coverage
        if rng.random() < _p(p, "rename", None):
            d.old_name = d.name
            d.name = _make_name(world, d.kind, d.role, d.dept, d.cloud, d.ip)
            d.ledger_lagging_name = rng.random() < LEDGER_LAG
            d.asm_dns_lagging = rng.random() < ASM_DNS_LAG
            d.events.append("rename")
        if cov.ledger and rng.random() < _p(p, "move", None):
            d.old_dept, d.old_ip, d.old_owner_user = d.dept, d.ip, d.owner_user
            d.dept = rng.choice([x for x in world.departments if x != d.dept])
            if d.public_ip is None:
                d.ip = world.new_ip(_internal_net(world, d.kind, d.role, d.dept, rng))
            d.owner_user = _owner(rng, d.dept)
            d.ledger_lagging_move = rng.random() < LEDGER_LAG
            d.events.append("move")
        if d.public_ip is not None and d.case != "G" and rng.random() < _p(p, "nat", None):
            d.nat = True
            d.ip = world.new_ip(_internal_net(world, d.kind, d.role, d.dept, rng))
            d.public_ip = rng.choice(world.nat_pool)
            d.events.append("nat")
        if d.kind in ("pc", "shadow") and cov.edr and rng.random() < _p(p, "dhcp", None):
            d.edr_ip = world.new_ip(".".join(d.ip.split(".")[:3]), unique=False, exclude=d.ip)
            d.events.append("dhcp")

        assets[d.true_id] = gen.AssetMeta(true_id=d.true_id, role=gen.ROLE_DEFS[d.case].name, case=d.case,
                                          department=d.dept, owner_user=d.owner_user, hostname=d.name,
                                          internal_ip=d.ip)

        if cov.ledger:
            name_l = d.old_name if (d.old_name and d.ledger_lagging_name) else d.name
            lag_move = d.old_dept is not None and d.ledger_lagging_move
            dept_l = d.old_dept if lag_move else d.dept
            ip_l = d.old_ip if lag_move else d.ip
            user_l = d.old_owner_user if lag_move else d.owner_user
            asset_id, inst = gen.ledger_ids_from_number(id_numbers[k])
            rec = {"asset_id": asset_id, "hostname": name_l.lower(), "ip": ip_l,
                   "fqdn": f"{name_l.lower()}.{INTERNAL_DOMAIN}", "instance_id": inst,
                   "owner_dept": dept_l, "owner_user": user_l, "_gt_true_id": d.true_id}
            mw = MISSING_WEIGHTS["ledger"]
            for f in ("owner_user", "owner_dept", "fqdn", "hostname", "ip"):
                if rng.random() < min(1.0, p * mw[f]):
                    rec[f] = ""
            if not d.cloud and rng.random() < min(1.0, p * mw["instance_id"]):
                rec["instance_id"] = ""
            records["ledger"].append(rec)

        if cov.edr:
            records["edr"].append(_edr_record(world, rng, d, d.name, d.edr_ip or d.ip, d.dept, _recent(rng), p))
            if rng.random() < _p(p, "stale", None):
                past_name = d.old_name or d.name
                past_dept = d.old_dept or d.dept
                base_ip = d.old_ip or d.ip
                past_ip = (world.new_ip(".".join(base_ip.split(".")[:3]), unique=False, exclude=d.ip)
                           if d.kind in ("pc", "shadow") else base_ip)
                records["edr"].append(_edr_record(world, rng, d, past_name, past_ip, past_dept,
                                                  _months_ago(rng, 6, 24), p))
                d.events.append("stale_edr")
            if cov.ledger and d.case in ("A", "B") and rng.random() < _p(p, "replace", None):
                rid = f"GT-RETIRED-{retired:05d}"
                retired += 1
                pred_name = d.old_name or d.name
                base_ip = d.old_ip or d.ip
                pred_ip = world.new_ip(".".join(base_ip.split(".")[:3]), unique=False, exclude=d.ip)
                pred = Device(true_id=rid, case="E", kind=d.kind, role=d.role, dept=d.old_dept or d.dept,
                              name=pred_name, ip=pred_ip, owner_user=d.owner_user, windows=d.windows)
                rec = _edr_record(world, rng, pred, pred_name, pred_ip, pred.dept, _months_ago(rng, 3, 24), p)
                rec["_gt_true_id"] = rid
                records["edr"].append(rec)
                assets[rid] = gen.AssetMeta(true_id=rid, role="retired_predecessor", case="E", department=pred.dept,
                                            owner_user=pred.owner_user, hostname=pred_name, internal_ip=pred_ip)
                d.events.append("replace")

        if cov.asm:
            dns_name = d.old_name if (d.old_name and d.asm_dns_lagging) else d.name
            if rng.random() < _p(p, "asm_service_name", None):
                dns_name = world.unique_name(
                    lambda: rng.choice(_SERVICE_LABELS) + ("" if rng.random() < 0.3 else str(rng.randint(2, 99))))
                d.events.append("asm_service_name")
            cur = configs[d.true_id]
            records["asm"].append(_asm_record(rng, d, dns_name, d.public_ip, _recent(rng), cur, p))
            if rng.random() < _p(p, "stale", None):
                past_name = d.old_name or dns_name
                past_ip = d.public_ip if not d.nat else world.new_ip(rng.choice(world.public_net), unique=False)
                past_cfg = cur if rng.random() < STALE_SAME_CONFIG else \
                    _config_attrs(rng, d.role if d.role in ROLE_STANDARD else "ext", old=True)
                records["asm"].append(_asm_record(rng, d, past_name, past_ip, _months_ago(rng, 6, 24), past_cfg, p))
                d.events.append("stale_asm")

    for src in records:
        rng.shuffle(records[src])
    records, gt = gen.finalize_population(records)
    gt.assets = assets
    return records, gt


def _internal_net(world: _World, kind: str, role: str, dept: str, rng: random.Random) -> str:
    if kind == "server":
        return world.srv_nets[dept][ROLE_NET_INDEX.get(role, 0)]
    return rng.choice(world.pc_nets[dept])


def _edr_record(world: _World, rng: random.Random, d: Device, name: str, ip: str, dept: str, ts: str, p: float) -> dict:
    if d.kind == "shadow":
        shown = name.upper()[:15]
    else:
        shown = f"{name.lower()}.{INTERNAL_DOMAIN}"
    dest_ip, dest_fqdn = world.peer(dept)
    rec = {"asset_id_or_hostname": shown, "ip": ip, "observed_at": ts,
           "dest_ip": dest_ip, "dest_fqdn": dest_fqdn, "_gt_true_id": d.true_id}
    mw = MISSING_WEIGHTS["edr"]
    if rng.random() < min(1.0, p * mw["asset_id_or_hostname"]):
        rec["asset_id_or_hostname"] = ""
    if rng.random() < min(1.0, p * mw["ip"]):
        rec["ip"] = ""
    if rng.random() < min(1.0, p * mw["dest"]):
        rec["dest_ip"] = ""
        rec["dest_fqdn"] = ""
    return rec


def _asm_record(rng: random.Random, d: Device, dns_name: str, ip: Optional[str], ts: str,
                cfg: Tuple[str, float], p: float) -> dict:
    ports, vs = cfg
    rec = {"public_ip": ip or "", "domain": f"{dns_name.lower()}.{EXTERNAL_DOMAIN}", "discovered_at": ts,
           "open_ports": ports, "vuln_score": vs, "_gt_true_id": d.true_id}
    mw = MISSING_WEIGHTS["asm"]
    if rng.random() < min(1.0, p * mw["domain"]):
        rec["domain"] = ""
    if rng.random() < min(1.0, p * mw["open_ports"]):
        rec["open_ports"] = ""
    if rng.random() < min(1.0, p * mw["vuln_score"]):
        rec["vuln_score"] = ""
    return rec


