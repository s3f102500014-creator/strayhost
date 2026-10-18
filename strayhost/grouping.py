"""Rule-based grouping: records that share an identifier are joined (union-find)."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set

from .data_io import get_identifiers_from_record


class _UnionFind:

    def __init__(self, items: List[str]) -> None:
        self.parent: Dict[str, str] = {x: x for x in items}
        self.rank: Dict[str, int] = {x: 0 for x in items}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1


def build_asset_groups(all_data: Dict[str, List[dict]]) -> List[Set[str]]:
    all_records_with_source = [
        (source_name, record)
        for source_name, records in all_data.items()
        for record in records
    ]
    internal_ids = [record["_internal_id"] for _, record in all_records_with_source]
    if not internal_ids:
        return []

    uf = _UnionFind(internal_ids)

    identifier_to_ids: Dict[str, List[str]] = defaultdict(list)
    for source_name, record in all_records_with_source:
        internal_id = record["_internal_id"]
        for identifier in get_identifiers_from_record(record, source_name):
            identifier_to_ids[identifier].append(internal_id)

    for ids_sharing_identifier in identifier_to_ids.values():
        first = ids_sharing_identifier[0]
        for other in ids_sharing_identifier[1:]:
            uf.union(first, other)

    groups: Dict[str, Set[str]] = defaultdict(set)
    for internal_id in internal_ids:
        root = uf.find(internal_id)
        groups[root].add(internal_id)

    return list(groups.values())
