"""Decides which positive LLM judgements are applied (size cap on combined groups)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class MergePolicyResult:

    components: List[Set[int]]
    applied_pairs: Set[Tuple[int, int]]
    rejected_pairs: Set[Tuple[int, int]]

    @property
    def merges_applied(self) -> int:
        return len(self.applied_pairs)

    @property
    def merges_rejected_by_policy(self) -> int:
        return len(self.rejected_pairs)


def apply_merge_policy(
    base_cluster_count: int,
    positive_edges: Sequence[Tuple[int, int, float, float]],
    size_cap: Optional[int],
) -> MergePolicyResult:
    if base_cluster_count < 0:
        raise ValueError(f"base_cluster_count must be >= 0 (got {base_cluster_count})")

    parent = list(range(base_cluster_count))
    rank = [0] * base_cluster_count
    members: Dict[int, Set[int]] = {i: {i} for i in range(base_cluster_count)}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra == rb:
            return
        if rank[ra] < rank[rb]:
            ra, rb = rb, ra
        parent[rb] = ra
        members[ra] |= members[rb]
        del members[rb]
        if rank[ra] == rank[rb]:
            rank[ra] += 1

    sorted_edges = sorted(positive_edges, key=lambda e: (-e[2], -e[3], e[0], e[1]))

    applied: Set[Tuple[int, int]] = set()
    rejected: Set[Tuple[int, int]] = set()
    for i, j, _conf, _sim in sorted_edges:
        ra, rb = find(i), find(j)
        if ra == rb:
            continue
        if size_cap is not None and len(members[ra]) + len(members[rb]) > size_cap:
            rejected.add((i, j))
            continue
        union(i, j)
        applied.add((i, j))

    components: List[Set[int]] = []
    seen_roots: Set[int] = set()
    for idx in range(base_cluster_count):
        root = find(idx)
        if root not in seen_roots:
            seen_roots.add(root)
            components.append(set(members[root]))

    return MergePolicyResult(components=components, applied_pairs=applied, rejected_pairs=rejected)
