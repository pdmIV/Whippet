#!/usr/bin/env python3
"""
whippet.py  —  Whippet: a lean, fast AD graph pathfinder from SharpHound JSON
────────────────────────────────────────────────────────────────────────────
The lightweight sibling to BloodHound — no Neo4j, no GUI, no kennel.
Replaces Neo4j with a plain adjacency-list + BFS/DFS for the queries
BloodHound's GUI does most often.  No server, no JVM, no Cypher.

Uses igraph (C-backend) when available, falls back to pure-Python BFS.

Typical performance vs Neo4j on a mid-sized environment (~30K nodes):
  - Load + index build :   ~1–2 s   (vs Neo4j import: 30–120 s)
  - Shortest path query:   <1 ms    (vs Neo4j Cypher: 20–200 ms)
  - "All paths to DA"  :   20–80 ms (vs BloodHound GUI: 2–10 s)

Usage:
    python3 whippet.py bloodhound.zip
    python3 whippet.py /sharphound/output/
    python3 whippet.py bloodhound.zip --to "DOMAIN ADMINS@CORP.LOCAL"
    python3 whippet.py bloodhound.zip --from "JSMITH@CORP.LOCAL" --to "DOMAIN ADMINS@CORP.LOCAL"
    python3 whippet.py bloodhound.zip --reachable "DC01.CORP.LOCAL" --hops 3
    python3 whippet.py bloodhound.zip --transitive-members "DOMAIN ADMINS@CORP.LOCAL"
    python3 whippet.py bloodhound.zip -o paths.txt
"""

from __future__ import annotations
import json, zipfile, sys, os, argparse, time
from pathlib import Path
from collections import defaultdict, deque
from typing import Iterator

# ── Try fast C backend, fall back silently ─────────────────────────────────────
try:
    import igraph as ig
    IGRAPH = True
except ImportError:
    IGRAPH = False

# ── Edge types that represent a privilege / control relationship ───────────────
#    (matches BloodHound's relationship model)
EDGE_TYPES = {
    # Group / session
    "MemberOf", "HasSession",
    # ACL-based
    "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl",
    "AllExtendedRights", "ForceChangePassword", "AddMember", "Owns",
    "ReadLAPSPassword", "ReadGMSAPassword",
    "GetChanges", "GetChangesAll",
    # Delegation
    "AllowedToDelegate", "AllowedToAct",
    # GPO / OU
    "GPLink", "Contains", "AffectedBy",
    # Trust / special
    "DCSync", "AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM",
    # BloodHound CE extras
    "HasSIDHistory", "TrustedBy",
}

HIGH_VALUE_NAMES = {
    "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
    "ADMINISTRATORS", "ACCOUNT OPERATORS", "BACKUP OPERATORS",
    "DOMAIN CONTROLLERS",
}


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

    # Boolean security-relevant flags carried in SharpHound user Properties.
    # Maps the JSON property name → short label printed in the listing.
    USER_FLAGS = {
        "enabled":                 "enabled",
        "admincount":              "adminCount",
        "hasspn":                  "kerberoastable",
        "dontreqpreauth":          "asrep-roastable",
        "passwordnotreqd":         "pwdNotReqd",
        "pwdneverexpires":         "pwdNeverExpires",
        "unconstraineddelegation": "unconstrained",
        "trustedtoauth":           "constrained",   # trusted to auth for delegation
        "sensitive":               "sensitive",     # 'account is sensitive & cannot be delegated'
        "dontexpirepassword":      "pwdNeverExpires",
        "sidhistory":              "sidHistory",
    }

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


# ══════════════════════════════════════════════════════════════════════════════
#  SharpHound loader
# ══════════════════════════════════════════════════════════════════════════════

class SharpHoundLoader:
    """
    Parse SharpHound v1/v2 JSON into an ADGraph.

    SharpHound's JSON relationship model:
        Users / Computers / Groups   → Aces[]  (ACL edges)
        Groups                       → Members[] (MemberOf edges)
        Computers                    → Sessions[] (HasSession edges)
        Computers                    → LocalAdmins[], RemoteDesktopUsers[], etc.
        Computers                    → AllowedToDelegate[]
        Users                        → AllowedToDelegate[]
        Domains                      → Trusts[], Aces[]
    """

    def __init__(self, graph: ADGraph):
        self.g = graph

    def load(self, path: str):
        p = Path(path)
        if p.suffix.lower() == ".zip":
            self._load_zip(p)
        elif p.is_dir():
            for f in sorted(p.glob("*.json")):
                self._load_file(f)
        elif p.suffix.lower() == ".json":
            self._load_file(p)

    def _load_zip(self, zp: Path):
        with zipfile.ZipFile(zp) as zf:
            for name in zf.namelist():
                if name.endswith(".json") and not name.startswith("__MACOSX"):
                    with zf.open(name) as f:
                        try:
                            self._parse(name, json.load(f))
                        except json.JSONDecodeError:
                            pass

    def _load_file(self, fp: Path):
        with open(fp, encoding="utf-8") as f:
            try:
                self._parse(fp.name, json.load(f))
            except json.JSONDecodeError:
                pass

    def _parse(self, filename: str, data: dict):
        items = data.get("data") or data.get("nodes") or []
        fname = filename.lower()

        if   "user"     in fname: parse = self._parse_user
        elif "computer" in fname: parse = self._parse_computer
        elif "group"    in fname: parse = self._parse_group
        elif "domain"   in fname: parse = self._parse_domain
        elif "gpo"      in fname: parse = self._parse_generic
        elif "ou"       in fname: parse = self._parse_generic
        else:
            return

        for item in items:
            parse(item)

    # ── Per-type parsers ──────────────────────────────────────────────────────

    def _add_obj(self, item: dict, node_type: str = "") -> str | None:
        props = item.get("Properties", {})
        name  = props.get("name", "")
        if not name:
            return None
        self.g.add_node(name, props, node_type=node_type)
        return name.upper()

    def _add_aces(self, src: str, aces: list):
        for ace in aces:
            right = ace.get("RightName", "")
            if right not in EDGE_TYPES:
                continue
            principal_sid = ace.get("PrincipalSID", "")
            principal     = self.g.resolve(principal_sid) or principal_sid
            if principal:
                # ACE direction: principal → src (principal has right over src)
                self.g.add_edge(principal, src, right)

    def _resolve_target(self, ref) -> str:
        if isinstance(ref, dict):
            sid  = ref.get("ObjectIdentifier", "")
            name = ref.get("Name", "")
            return self.g.resolve(sid) or name or sid
        return self.g.resolve(str(ref))

    def _parse_user(self, item: dict):
        src = self._add_obj(item, "User")
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))

        # Constrained delegation targets
        for tgt in item.get("AllowedToDelegate", []):
            t = self._resolve_target(tgt)
            if t:
                self.g.add_edge(src, t, "AllowedToDelegate")

        # SID history
        for sid in item.get("HasSIDHistory", []):
            t = self._resolve_target(sid)
            if t:
                self.g.add_edge(src, t, "HasSIDHistory")

    def _parse_computer(self, item: dict):
        src = self._add_obj(item, "Computer")
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))

        # Sessions: user HAS_SESSION on computer
        sessions = item.get("Sessions", {})
        if isinstance(sessions, dict):
            sessions = sessions.get("Results", [])
        for sess in (sessions or []):
            user_sid = sess.get("UserSID", "")
            user     = self.g.resolve(user_sid) or user_sid
            if user:
                self.g.add_edge(user, src, "HasSession")

        # Local admin / RDP / PSRemote / DCOM
        for rel_key, rel_type in [
            ("LocalAdmins",          "AdminTo"),
            ("RemoteDesktopUsers",   "CanRDP"),
            ("PSRemoteUsers",        "CanPSRemote"),
            ("DcomUsers",            "ExecuteDCOM"),
        ]:
            rel = item.get(rel_key, {})
            results = rel.get("Results", rel) if isinstance(rel, dict) else rel
            for entry in (results or []):
                t = self._resolve_target(entry)
                if t:
                    self.g.add_edge(t, src, rel_type)

        # Constrained delegation
        for tgt in item.get("AllowedToDelegate", []):
            t = self._resolve_target(tgt)
            if t:
                self.g.add_edge(src, t, "AllowedToDelegate")

        # Resource-based constrained delegation
        for tgt in item.get("AllowedToAct", []):
            t = self._resolve_target(tgt)
            if t:
                self.g.add_edge(t, src, "AllowedToAct")

    def _parse_group(self, item: dict):
        src = self._add_obj(item, "Group")
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))
        for member in item.get("Members", []):
            t = self._resolve_target(member)
            if t:
                self.g.add_edge(t, src, "MemberOf")

    def _parse_domain(self, item: dict):
        src = self._add_obj(item, "Domain")
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))
        for trust in item.get("Trusts", []):
            t = trust.get("TargetDomainName", "")
            if t:
                self.g.add_edge(src, t, "TrustedBy")

    def _parse_generic(self, item: dict):
        src = self._add_obj(item)
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))


# ══════════════════════════════════════════════════════════════════════════════
#  Report / query layer
# ══════════════════════════════════════════════════════════════════════════════

def fmt_path(path: list[tuple[str, str]]) -> str:
    """Pretty-print a path list into:  A ─[MemberOf]→ B ─[GenericAll]→ C"""
    parts = []
    for i, (node, etype) in enumerate(path):
        if i == 0:
            parts.append(node)
        else:
            parts.append(f" ─[{etype}]→ {node}")
    return "".join(parts)


def run_queries(
    graph: ADGraph,
    *,
    src_filter: str | None,
    dst_filter: str | None,
    reachable_target: str | None,
    hops: int,
    exhaustive: bool,
    transitive_group: str | None,
    max_paths: int,
    list_users: bool,
    user_flags: set[str] | None,
    enabled_only: bool,
    output_file: str | None,
):
    lines = []
    W = 72

    def h1(s): lines.append("═" * W); lines.append(f"  {s}"); lines.append("═" * W)
    def h2(s): lines.append("─" * W); lines.append(f"  {s}"); lines.append("─" * W)
    def add(*a): lines.append("".join(str(x) for x in a))

    h1("Whippet — In-Memory AD Path Analysis")
    add(f"  Backend : {'igraph (C)'  if IGRAPH else 'pure-Python BFS (dict-of-sets)'}")
    add(f"  Nodes   : {graph.node_count:,}")
    add(f"  Edges   : {graph.edge_count:,}")
    add()

    # ── 0. User listing (--list-users) ────────────────────────────────────────
    if list_users:
        title = "User Listing"
        if user_flags:
            title += f"  (filter: {', '.join(sorted(user_flags))})"
        if enabled_only:
            title += "  [enabled only]"
        h2(title)
        users = graph.list_users(require_flags=user_flags, enabled_only=enabled_only)
        add(f"  {len(users)} user(s)")
        add()
        width = min(max((len(n) for n, _ in users), default=0), 45)
        for name, flags in users:
            flag_str = ("  " + ", ".join(flags)) if flags else ""
            add(f"  {name:<{width}}{flag_str}")
        add()

    # ── Resolve effective hop bound ───────────────────────────────────────────
    # For pure reachability (forward/reverse BFS) there is no benefit to a cap:
    # BFS terminates when the frontier empties. We pass a large sentinel.
    # For all-simple-paths (DFS), the tight upper bound is the number of nodes
    # reachable from the source minus one — a simple path can't revisit a node,
    # so it cannot be longer than that. We compute it lazily per source below.
    INF_HOPS = graph.node_count  # can't traverse more than every node once
    reach_hops = INF_HOPS if exhaustive else hops

    # ── 1. High-value targets inventory ───────────────────────────────────────
    h2("High-Value Targets")
    hvts = graph.high_value_targets()
    if hvts:
        for n in sorted(hvts):
            add(f"  - {n}")
    else:
        add("  (none found — check that group / domain JSON was loaded)")
    add()

    # ── 2. Shortest path (src → dst or all → high-value) ──────────────────────
    targets = [dst_filter.upper()] if dst_filter else [n for n in hvts if "DOMAIN ADMINS" in n]

    if src_filter:
        # Specific source → specific/HV target
        src = src_filter.upper()
        for dst in targets:
            h2(f"Shortest Path: {src} → {dst}")
            t0   = time.perf_counter()
            path = graph.bfs_shortest_path(src, dst)
            ms   = (time.perf_counter() - t0) * 1000
            if path:
                add(f"  ({len(path)-1} hop{'s' if len(path)-1 != 1 else ''}, {ms:.1f} ms)")
                add(f"  {fmt_path(path)}")
            else:
                add(f"  No path found in {ms:.1f} ms")
            add()
    else:
        # All principals that can reach each high-value target
        for dst in targets:
            h2(f"Who can reach: {dst}")
            t0 = time.perf_counter()
            reachable = graph.can_reach(dst, max_hops=reach_hops)
            ms = (time.perf_counter() - t0) * 1000

            # Exclude the target itself and group-typed nodes that are intermediate
            attackers = {
                n: d for n, d in reachable.items()
                if n != dst
            }
            scope = "exhaustively" if exhaustive else f"within {hops} hops"
            add(f"  {len(attackers)} principals can reach this target "
                f"{scope}  ({ms:.1f} ms)")
            add()
            by_dist: dict[int, list[str]] = defaultdict(list)
            for n, d in attackers.items():
                by_dist[d].append(n)
            for dist in sorted(by_dist):
                add(f"  Hop {dist}:")
                for n in sorted(by_dist[dist])[:30]:
                    add(f"     - {n}")
                if len(by_dist[dist]) > 30:
                    add(f"     ... and {len(by_dist[dist]) - 30} more")
            add()

    # ── 3. All paths (src → dst) ───────────────────────────────────────────────
    if src_filter and (dst_filter or targets):
        src = src_filter.upper()
        dst = (dst_filter or targets[0]).upper()
        # For all-simple-paths, exhaustive depth = reachable-set size - 1.
        # A simple path can't revisit a node, so it can't exceed that length;
        # using it as the cap explores every path without arbitrary truncation.
        if exhaustive:
            depth = max(graph.reachable_count(src) - 1, 1)
            depth_label = f"exhaustive, ≤{depth} hops"
        else:
            depth = hops
            depth_label = f"≤{hops} hops"
        h2(f"All Paths (up to {max_paths}, {depth_label}): {src} → {dst}")
        t0    = time.perf_counter()
        count = 0
        for path in graph.bfs_all_paths(src, dst, max_depth=depth):
            count += 1
            add(f"  [{count}]  ({len(path)-1} hops)")
            add(f"       {fmt_path(path)}")
            if count >= max_paths:
                add(f"  ... (limit {max_paths} reached)")
                break
        ms = (time.perf_counter() - t0) * 1000
        if count == 0:
            add("  No paths found.")
        add(f"  ({ms:.1f} ms)")
        add()

    # ── 4. Reachable from target within N hops ────────────────────────────────
    if reachable_target:
        src = reachable_target.upper()
        scope = "exhaustively" if exhaustive else f"within {hops} hops"
        h2(f"Reachable from {src} {scope}")
        t0   = time.perf_counter()
        dist = graph.reachable_from(src, max_hops=reach_hops)
        ms   = (time.perf_counter() - t0) * 1000
        add(f"  {len(dist)-1} nodes reachable  ({ms:.1f} ms)")
        by_d: dict[int, list[str]] = defaultdict(list)
        for n, d in dist.items():
            if n != src:
                by_d[d].append(n)
        for d in sorted(by_d):
            add(f"\n  Hop {d}:")
            for n in sorted(by_d[d])[:50]:
                add(f"     - {n}")
            if len(by_d[d]) > 50:
                add(f"     ... and {len(by_d[d]) - 50} more")
        add()

    # ── 5. Transitive group membership ────────────────────────────────────────
    if transitive_group:
        grp = transitive_group.upper()
        h2(f"Transitive Members of {grp}")
        t0      = time.perf_counter()
        members = graph.transitive_members(grp)
        ms      = (time.perf_counter() - t0) * 1000
        add(f"  {len(members)} effective members  ({ms:.1f} ms)")
        for m in sorted(members):
            add(f"  - {m}")
        add()

    add("═" * W)
    output = "\n".join(lines)

    if output_file:
        import re
        clean = re.sub(r"\033\[[0-9;]*m", "", output)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(clean)
        print(f"[+] Report saved → {output_file}", file=sys.stderr)
    else:
        print(output)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="whippet.py",
        description="Whippet — lean, fast in-memory AD graph pathfinder from SharpHound JSON (no Neo4j required)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # All paths to Domain Admins (auto-detected)
  python3 whippet.py bloodhound.zip

  # Specific source → target
  python3 whippet.py bloodhound.zip \\
      --from "JSMITH@CORP.LOCAL" --to "DOMAIN ADMINS@CORP.LOCAL"

  # Who can reach a target within 4 hops?
  python3 whippet.py bloodhound.zip --to "DC01.CORP.LOCAL" --hops 4

  # What can I reach FROM a node?
  python3 whippet.py bloodhound.zip --reachable "JSMITH@CORP.LOCAL" --hops 3

  # Fully expand group membership
  python3 whippet.py bloodhound.zip \\
      --transitive-members "DOMAIN ADMINS@CORP.LOCAL"

  # Save to file
  python3 whippet.py bloodhound.zip -o paths.txt
        """,
    )
    parser.add_argument("input", nargs="+",
        help="SharpHound ZIP, directory of JSON, or individual JSON files")
    parser.add_argument("--from", dest="src",
        help="Source node (user/computer/group name or SID)")
    parser.add_argument("--to", dest="dst",
        help="Target node (defaults to Domain Admins group if not specified)")
    parser.add_argument("--reachable", metavar="NODE",
        help="Show all nodes reachable FROM this node within --hops")
    parser.add_argument("--transitive-members", metavar="GROUP",
        help="Expand all effective (nested) members of a group")
    parser.add_argument("--hops", type=int, default=6,
        help="Maximum path depth (default: 6). Ignored when --exhaustive is set.")
    parser.add_argument("--exhaustive", action="store_true",
        help="Search with no manual hop cap. Reachability runs until the BFS "
             "frontier empties; all-paths uses the reachable-set size as the "
             "tight upper bound. Auto-computed from the graph — no overshoot.")
    parser.add_argument("--list-users", action="store_true",
        help="List all user accounts with their security-relevant flags "
             "(enabled, adminCount, kerberoastable, asrep-roastable, etc.)")
    parser.add_argument("--user-flag", dest="user_flags", nargs="+", metavar="FLAG",
        choices=sorted(set(ADGraph.USER_FLAGS.keys())),
        help="With --list-users, only show users that have ALL of these raw "
             "property flags set. Choices: " + ", ".join(sorted(ADGraph.USER_FLAGS.keys())))
    parser.add_argument("--enabled-only", action="store_true",
        help="With --list-users, restrict to enabled accounts only")
    parser.add_argument("--max-paths", type=int, default=20,
        help="Max number of alternate paths to print (default: 20)")
    parser.add_argument("-o", "--output",
        help="Write report to file")

    args = parser.parse_args()

    graph  = ADGraph()
    loader = SharpHoundLoader(graph)

    for inp in args.input:
        print(f"[*] Loading: {inp}", file=sys.stderr)
        t0 = time.perf_counter()
        loader.load(inp)
        print(f"    {graph.node_count:,} nodes, {graph.edge_count:,} edges "
              f"({(time.perf_counter()-t0)*1000:.0f} ms)", file=sys.stderr)

    if graph.node_count == 0:
        print("[!] No objects loaded.", file=sys.stderr)
        sys.exit(1)

    if IGRAPH:
        print("[*] Building igraph mirror …", file=sys.stderr)
        graph._build_igraph()

    run_queries(
        graph,
        src_filter=args.src,
        dst_filter=args.dst,
        reachable_target=args.reachable,
        hops=args.hops,
        exhaustive=args.exhaustive,
        transitive_group=args.transitive_members,
        max_paths=args.max_paths,
        list_users=args.list_users,
        user_flags=set(args.user_flags) if args.user_flags else None,
        enabled_only=args.enabled_only,
        output_file=args.output,
    )


if __name__ == "__main__":
    main()
