"""
whippet.graph — the in-memory, edge-typed Active Directory graph.

Pure data structure + traversal primitives (BFS/DFS). No I/O, no formatting:
the loader populates it, the QueryEngine queries it, the reporters present it.
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Iterator

from .constants import HIGH_VALUE_NAMES, USER_FLAGS

# ── Try fast C backend, fall back silently ─────────────────────────────────────
try:
    import igraph as ig
    IGRAPH = True
except ImportError:
    IGRAPH = False


# ══════════════════════════════════════════════════════════════════════════════
#  Graph data structure
# ══════════════════════════════════════════════════════════════════════════════

class ADGraph:
    """
    Directed, edge-typed, property-rich graph stored entirely in RAM.

    Core storage:
        _adj  : dict[node_id, list[(neighbor_id, edge_type)]]
        _radj : dict[node_id, list[(neighbor_id, edge_type)]]  (reverse)
        _props: dict[node_id, dict]

    node_id is the upper-cased name (e.g. "JSMITH@CORP.LOCAL") for readability.
    SIDs are resolved to names at load time; unresolved SIDs are kept as-is.

    Memory:  ~60–90 bytes per edge (Python overhead on 64-bit).
    Compare: NetworkX stores edges in nested dicts: ~150–200 bytes per edge.
             igraph stores in C arrays: ~30–40 bytes per edge.
    """

    # Re-exported for backward compatibility (cli.py references ADGraph.USER_FLAGS).
    USER_FLAGS = USER_FLAGS

    def __init__(self):
        self._adj:   dict[str, list[tuple[str, str]]] = defaultdict(list)
        self._radj:  dict[str, list[tuple[str, str]]] = defaultdict(list)
        self._props: dict[str, dict]                  = {}
        self._sid:   dict[str, str]                   = {}   # SID  → name
        self._name:  dict[str, str]                   = {}   # name → SID
        self._type:  dict[str, str]                   = {}   # name → "User"/"Computer"/...

        # Optional igraph mirror
        self._ig: "ig.Graph | None" = None
        self._ig_id_map: dict[str, int] = {}  # name → igraph vertex id

    # ── Mutation ───────────────────────────────────────────────────────────────

    def add_node(self, name: str, props: dict, node_type: str = ""):
        name = name.upper()
        self._props[name] = props
        if node_type:
            self._type[name] = node_type
        sid = props.get("objectid", "")
        if sid:
            self._sid[sid.upper()] = name
            self._name[name] = sid.upper()
        # Ensure node exists in adjacency lists
        if name not in self._adj:
            self._adj[name]  = []
            self._radj[name] = []

    def add_edge(self, src: str, dst: str, etype: str):
        src, dst = src.upper(), dst.upper()
        self._adj[src].append((dst, etype))
        self._radj[dst].append((src, etype))

    def resolve(self, sid_or_name: str) -> str:
        key = sid_or_name.upper()
        return self._sid.get(key, key)

    def node_name(self, sid_or_name: str) -> str:
        """Return display name, preferring resolved SID."""
        r = self.resolve(sid_or_name)
        return self._props.get(r, {}).get("name", r)

    # ── Introspection helpers (used by the web subgraph view) ───────────────────

    def has_node(self, name: str) -> bool:
        name = name.upper()
        return name in self._props or name in self._adj

    def node_type(self, name: str) -> str:
        """Object type tag ("User"/"Computer"/"Group"/"Domain"/"")."""
        return self._type.get(name.upper(), "")

    def is_high_value(self, name: str) -> bool:
        """Whether a node qualifies as a high-value target."""
        name = name.upper()
        props = self._props.get(name, {})
        pname = props.get("name", "").upper()
        return bool(props.get("highvalue")
                    or props.get("admincount")
                    or any(h in pname for h in HIGH_VALUE_NAMES))

    def neighbors(self, name: str, reverse: bool = False) -> list[tuple[str, str]]:
        """Outgoing (or, with reverse=True, incoming) (neighbor, edge_type) pairs."""
        adj = self._radj if reverse else self._adj
        return adj.get(name.upper(), [])

    # ── igraph mirror ──────────────────────────────────────────────────────────

    def _build_igraph(self):
        """Build an igraph.Graph mirror for bulk-analysis queries."""
        if not IGRAPH:
            return
        nodes = list(self._adj.keys())
        self._ig_id_map = {n: i for i, n in enumerate(nodes)}
        edges  = []
        etypes = []
        for src, nbrs in self._adj.items():
            for dst, etype in nbrs:
                if dst in self._ig_id_map:
                    edges.append((self._ig_id_map[src], self._ig_id_map[dst]))
                    etypes.append(etype)
        self._ig = ig.Graph(n=len(nodes), edges=edges, directed=True)
        self._ig.vs["name"]  = nodes
        self._ig.es["etype"] = etypes

    # ── BFS primitives ─────────────────────────────────────────────────────────

    def bfs_shortest_path(
        self, src: str, dst: str, reverse: bool = False
    ) -> list[tuple[str, str]] | None:
        """
        BFS shortest path from src → dst.
        Returns list of (node, edge_type) pairs representing the path,
        or None if no path exists.

        `reverse=True` traverses backward edges (useful for 'who can reach dst').
        """
        src, dst = src.upper(), dst.upper()
        adj = self._radj if reverse else self._adj

        if src not in adj and src not in self._props:
            return None
        if src == dst:
            return [(src, "")]

        # parent: node → (parent_node, edge_type)
        parent: dict[str, tuple[str, str]] = {src: ("", "")}
        queue  = deque([src])

        while queue:
            node = queue.popleft()
            for nbr, etype in adj.get(node, []):
                if nbr not in parent:
                    parent[nbr] = (node, etype)
                    if nbr == dst:
                        # Reconstruct
                        path = []
                        cur = dst
                        while cur:
                            pnode, petype = parent[cur]
                            path.append((cur, petype))
                            cur = pnode
                        path.reverse()
                        return path
                    queue.append(nbr)
        return None

    def bfs_all_paths(
        self, src: str, dst: str, max_depth: int = 8
    ) -> Iterator[list[tuple[str, str]]]:
        """
        DFS-based generator yielding ALL simple paths from src → dst up to
        max_depth hops.  Can be expensive — use max_depth conservatively.
        """
        src, dst = src.upper(), dst.upper()

        def _dfs(cur, path, visited, depth):
            if depth > max_depth:
                return
            for nbr, etype in self._adj.get(cur, []):
                if nbr in visited:
                    continue
                new_path = path + [(nbr, etype)]
                if nbr == dst:
                    yield new_path
                else:
                    yield from _dfs(nbr, new_path, visited | {nbr}, depth + 1)

        yield from _dfs(src, [(src, "")], {src}, 0)

    def reachable_from(
        self, src: str, max_hops: int = 3, edge_filter: set | None = None
    ) -> dict[str, int]:
        """
        BFS outward from src.  Returns {node → distance} for all reachable
        nodes within max_hops.  Optional edge_filter restricts traversal.
        """
        src = src.upper()
        dist   = {src: 0}
        queue  = deque([(src, 0)])

        while queue:
            node, d = queue.popleft()
            if d >= max_hops:
                continue
            for nbr, etype in self._adj.get(node, []):
                if nbr in dist:
                    continue
                if edge_filter and etype not in edge_filter:
                    continue
                dist[nbr] = d + 1
                queue.append((nbr, d + 1))
        return dist

    def can_reach(
        self, dst: str, max_hops: int = 99, edge_filter: set | None = None
    ) -> dict[str, int]:
        """
        Reverse BFS: all nodes that can reach dst within max_hops.
        More efficient than running reachable_from() from every node.
        """
        dst   = dst.upper()
        dist  = {dst: 0}
        queue = deque([(dst, 0)])

        while queue:
            node, d = queue.popleft()
            if d >= max_hops:
                continue
            for nbr, etype in self._radj.get(node, []):
                if nbr in dist:
                    continue
                if edge_filter and etype not in edge_filter:
                    continue
                dist[nbr] = d + 1
                queue.append((nbr, d + 1))
        return dist

    def transitive_members(self, group: str) -> set[str]:
        """
        Fully expand nested group membership for a target group.
        Equivalent to BloodHound's 'Transitive Object Control' query
        when traversal is limited to MemberOf edges in reverse.
        """
        group = group.upper()
        members: set[str] = set()
        queue  = deque([group])
        visited: set[str] = {group}

        while queue:
            node = queue.popleft()
            for src, etype in self._radj.get(node, []):
                if etype != "MemberOf":
                    continue
                if src not in visited:
                    visited.add(src)
                    members.add(src)
                    queue.append(src)
        return members

    def high_value_targets(self) -> list[str]:
        """Return node names that are considered high-value."""
        hvt = []
        for name, props in self._props.items():
            pname = props.get("name", "").upper()
            if (props.get("highvalue")
                    or props.get("admincount")
                    or any(h in pname for h in HIGH_VALUE_NAMES)):
                hvt.append(name)
        return hvt

    # ── User listing ────────────────────────────────────────────────────────────

    def list_users(
        self,
        require_flags: set[str] | None = None,
        enabled_only: bool = False,
    ) -> list[tuple[str, list[str]]]:
        """
        Return [(user_name, [active_flag_labels]), ...] for every user node.

        require_flags : if given, only return users that have ALL of these
                        raw property names set truthy (e.g. {"hasspn"}).
        enabled_only  : restrict to enabled accounts.

        Users are identified by the type tag the loader assigns from the
        source JSON filename — reliable, unlike property-sniffing.
        """
        results = []
        for name, props in self._props.items():
            if self._type.get(name) != "User":
                continue
            if enabled_only and not props.get("enabled"):
                continue

            active = [
                label for prop, label in self.USER_FLAGS.items()
                if props.get(prop)
            ]
            # de-dup labels (two props map to pwdNeverExpires)
            seen, deduped = set(), []
            for lab in active:
                if lab not in seen:
                    seen.add(lab)
                    deduped.append(lab)

            if require_flags:
                if not all(props.get(f) for f in require_flags):
                    continue

            results.append((name, deduped))
        return sorted(results, key=lambda x: x[0])

    def reachable_count(self, src: str) -> int:
        """
        Number of nodes reachable from src with no hop limit.
        This is the tight upper bound on the length of any simple path
        starting at src: a simple path cannot revisit a node, so it can
        traverse at most (reachable_count - 1) edges. Used to derive a
        safe --exhaustive depth without overshooting.
        """
        src   = src.upper()
        seen  = {src}
        queue = deque([src])
        while queue:
            node = queue.popleft()
            for nbr, _ in self._adj.get(node, []):
                if nbr not in seen:
                    seen.add(nbr)
                    queue.append(nbr)
        return len(seen)

    # ── Stats ──────────────────────────────────────────────────────────────────

    @property
    def node_count(self) -> int:
        return len(self._props)

    @property
    def edge_count(self) -> int:
        return sum(len(v) for v in self._adj.values())
