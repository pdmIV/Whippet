"""
whippet.queries — the query engine.

This is the seam that lets one set of graph algorithms drive two front-ends.
`QueryEngine` wraps an `ADGraph` and returns plain, JSON-serialisable result
objects (the dataclasses below). It does no printing and no HTTP — the text
reporter (CLI) and the Flask API both consume the same results, so the two
front-ends can never drift apart in semantics.

All wall-clock timing and the `--exhaustive` depth math live here, so both
front-ends measure and bound queries identically.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .graph import ADGraph, IGRAPH


# ── Result objects ─────────────────────────────────────────────────────────────

@dataclass
class Stats:
    backend: str
    nodes: int
    edges: int


@dataclass
class PathResult:
    """A single path src → dst as an ordered list of (node, edge_type) pairs."""
    src: str
    dst: str
    path: list[tuple[str, str]]
    hops: int
    found: bool
    elapsed_ms: float


@dataclass
class AllPathsResult:
    src: str
    dst: str
    paths: list[PathResult]
    depth: int
    depth_label: str
    exhaustive: bool
    max_paths: int
    limit_reached: bool
    elapsed_ms: float

    @property
    def count(self) -> int:
        return len(self.paths)


@dataclass
class ReachResult:
    """
    Result of a reachability sweep — either 'who can reach X' (direction="to")
    or 'what can X reach' (direction="from").

    by_distance maps hop-count → sorted list of node names (root excluded).
    total is the number of nodes reached (root excluded).
    """
    root: str
    direction: str            # "to" (reverse BFS) | "from" (forward BFS)
    by_distance: dict[int, list[str]]
    total: int
    exhaustive: bool
    hops: int
    elapsed_ms: float


@dataclass
class MembersResult:
    group: str
    members: list[str]
    elapsed_ms: float


@dataclass
class UserRow:
    name: str
    flags: list[str]


@dataclass
class SubGraph:
    """A node/edge slice ready for the visualiser to render."""
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)


# ── Engine ─────────────────────────────────────────────────────────────────────

class QueryEngine:
    """Stateless-ish query facade over an ADGraph (the graph is read-only here)."""

    def __init__(self, graph: ADGraph):
        self.g = graph

    # ── Meta ────────────────────────────────────────────────────────────────────

    @property
    def backend(self) -> str:
        return "igraph (C)" if IGRAPH else "pure-Python BFS (dict-of-sets)"

    def stats(self) -> Stats:
        return Stats(self.backend, self.g.node_count, self.g.edge_count)

    def high_value_targets(self) -> list[str]:
        return self.g.high_value_targets()

    # ── Paths ────────────────────────────────────────────────────────────────────

    def shortest_path(self, src: str, dst: str) -> PathResult:
        src, dst = src.upper(), dst.upper()
        t0 = time.perf_counter()
        path = self.g.bfs_shortest_path(src, dst)
        ms = (time.perf_counter() - t0) * 1000
        if path:
            return PathResult(src, dst, path, len(path) - 1, True, ms)
        return PathResult(src, dst, [], 0, False, ms)

    def all_paths(
        self, src: str, dst: str, *, hops: int, exhaustive: bool, max_paths: int
    ) -> AllPathsResult:
        src, dst = src.upper(), dst.upper()
        # For all-simple-paths, the exhaustive depth is the reachable-set size
        # minus one: a simple path can't revisit a node, so it can't be longer.
        if exhaustive:
            depth = max(self.g.reachable_count(src) - 1, 1)
            depth_label = f"exhaustive, ≤{depth} hops"
        else:
            depth = hops
            depth_label = f"≤{hops} hops"

        t0 = time.perf_counter()
        paths: list[PathResult] = []
        limit_reached = False
        for raw in self.g.bfs_all_paths(src, dst, max_depth=depth):
            paths.append(PathResult(src, dst, raw, len(raw) - 1, True, 0.0))
            if len(paths) >= max_paths:
                limit_reached = True
                break
        ms = (time.perf_counter() - t0) * 1000
        return AllPathsResult(
            src, dst, paths, depth, depth_label, exhaustive, max_paths,
            limit_reached, ms,
        )

    # ── Reachability ─────────────────────────────────────────────────────────────

    def _effective_hops(self, hops: int, exhaustive: bool) -> int:
        # Reachability BFS terminates when the frontier empties, so the
        # exhaustive bound is simply "more than the graph can ever traverse".
        return self.g.node_count if exhaustive else hops

    def _group_by_distance(self, dist: dict[str, int], root: str) -> tuple[dict[int, list[str]], int]:
        by_distance: dict[int, list[str]] = {}
        total = 0
        for n, d in dist.items():
            if n == root:
                continue
            by_distance.setdefault(d, []).append(n)
            total += 1
        for d in by_distance:
            by_distance[d].sort()
        return by_distance, total

    def who_can_reach(self, dst: str, *, hops: int, exhaustive: bool) -> ReachResult:
        dst = dst.upper()
        eff = self._effective_hops(hops, exhaustive)
        t0 = time.perf_counter()
        dist = self.g.can_reach(dst, max_hops=eff)
        ms = (time.perf_counter() - t0) * 1000
        by_distance, total = self._group_by_distance(dist, dst)
        return ReachResult(dst, "to", by_distance, total, exhaustive, hops, ms)

    def reachable(self, src: str, *, hops: int, exhaustive: bool) -> ReachResult:
        src = src.upper()
        eff = self._effective_hops(hops, exhaustive)
        t0 = time.perf_counter()
        dist = self.g.reachable_from(src, max_hops=eff)
        ms = (time.perf_counter() - t0) * 1000
        by_distance, total = self._group_by_distance(dist, src)
        return ReachResult(src, "from", by_distance, total, exhaustive, hops, ms)

    # ── Membership / users ───────────────────────────────────────────────────────

    def transitive(self, group: str) -> MembersResult:
        group = group.upper()
        t0 = time.perf_counter()
        members = self.g.transitive_members(group)
        ms = (time.perf_counter() - t0) * 1000
        return MembersResult(group, sorted(members), ms)

    def users(self, *, flags: set[str] | None = None, enabled_only: bool = False) -> list[UserRow]:
        rows = self.g.list_users(require_flags=flags, enabled_only=enabled_only)
        return [UserRow(name, flag_list) for name, flag_list in rows]

    # ── Visualiser support ───────────────────────────────────────────────────────

    def _node_obj(self, name: str) -> dict:
        return {
            "id": name,
            "type": self.g.node_type(name) or "Unknown",
            "high_value": self.g.is_high_value(name),
        }

    def subgraph_for(self, names) -> SubGraph:
        """Induced subgraph over `names`: those nodes plus every edge between them."""
        keep = {n.upper() for n in names if self.g.has_node(n.upper())}
        nodes = [self._node_obj(n) for n in sorted(keep)]
        edges = []
        for n in keep:
            for dst, etype in self.g.neighbors(n):
                if dst in keep:
                    edges.append({"source": n, "target": dst, "etype": etype})
        return SubGraph(nodes, edges)

    def subgraph_for_path(self, path: list[tuple[str, str]]) -> SubGraph:
        """Nodes + the specific edges that make up one path (in order)."""
        seen, nodes = set(), []
        for node, _ in path:
            if node not in seen:
                seen.add(node)
                nodes.append(self._node_obj(node))
        edges = []
        for i in range(1, len(path)):
            prev = path[i - 1][0]
            cur, etype = path[i]
            edges.append({"source": prev, "target": cur, "etype": etype})
        return SubGraph(nodes, edges)

    def neighborhood(self, focus: str, hops: int = 1) -> SubGraph:
        """BFS outward AND inward from `focus` up to `hops`; induced subgraph."""
        focus = focus.upper()
        if not self.g.has_node(focus):
            return SubGraph([], [])
        out = self.g.reachable_from(focus, max_hops=hops)
        inn = self.g.can_reach(focus, max_hops=hops)
        return self.subgraph_for(set(out) | set(inn))

    def search(self, prefix: str, limit: int = 20) -> list[str]:
        """Node-name autocomplete: prefix matches first, then substring matches."""
        q = (prefix or "").upper()
        names = self.g._props.keys()
        if not q:
            return sorted(names)[:limit]
        starts = sorted(n for n in names if n.startswith(q))
        contains = sorted(n for n in names if q in n and not n.startswith(q))
        return (starts + contains)[:limit]
