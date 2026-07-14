"""
whippet.report — text presentation layer.

`TextReporter` turns `QueryEngine` results into the exact same console report the
original single-file tool produced. It owns *only* formatting; every number and
path comes from the engine, so the CLI and the web GUI stay in lock-step.
"""
from __future__ import annotations

import re
import sys

from .queries import QueryEngine


def fmt_path(path: list[tuple[str, str]]) -> str:
    """Pretty-print a path list into:  A ─[MemberOf]→ B ─[GenericAll]→ C"""
    parts = []
    for i, (node, etype) in enumerate(path):
        if i == 0:
            parts.append(node)
        else:
            parts.append(f" ─[{etype}]→ {node}")
    return "".join(parts)


class TextReporter:
    """Render a full analysis report for the CLI."""

    WIDTH = 72

    def __init__(self, engine: QueryEngine):
        self.engine = engine
        self._lines: list[str] = []

    # ── line helpers ─────────────────────────────────────────────────────────────

    def _h1(self, s: str):
        W = self.WIDTH
        self._lines.append("═" * W)
        self._lines.append(f"  {s}")
        self._lines.append("═" * W)

    def _h2(self, s: str):
        W = self.WIDTH
        self._lines.append("─" * W)
        self._lines.append(f"  {s}")
        self._lines.append("─" * W)

    def _add(self, *a):
        self._lines.append("".join(str(x) for x in a))

    # ── main entry point ─────────────────────────────────────────────────────────

    def run(
        self,
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
        eng = self.engine
        self._lines = []
        add, h1, h2 = self._add, self._h1, self._h2

        stats = eng.stats()
        h1("Whippet — In-Memory AD Path Analysis")
        add(f"  Backend : {stats.backend}")
        add(f"  Nodes   : {stats.nodes:,}")
        add(f"  Edges   : {stats.edges:,}")
        add()

        # ── 0. User listing (--list-users) ────────────────────────────────────────
        if list_users:
            title = "User Listing"
            if user_flags:
                title += f"  (filter: {', '.join(sorted(user_flags))})"
            if enabled_only:
                title += "  [enabled only]"
            h2(title)
            users = eng.users(flags=user_flags, enabled_only=enabled_only)
            add(f"  {len(users)} user(s)")
            add()
            width = min(max((len(u.name) for u in users), default=0), 45)
            for u in users:
                flag_str = ("  " + ", ".join(u.flags)) if u.flags else ""
                add(f"  {u.name:<{width}}{flag_str}")
            add()

        # ── 1. High-value targets inventory ───────────────────────────────────────
        h2("High-Value Targets")
        hvts = eng.high_value_targets()
        if hvts:
            for n in sorted(hvts):
                add(f"  - {n}")
        else:
            add("  (none found — check that group / domain JSON was loaded)")
        add()

        # ── 2. Shortest path (src → dst or all → high-value) ──────────────────────
        # Default target set is every high-value node (mirrors BloodHound's
        # "Shortest Paths to High Value Targets"), not just the literal Domain
        # Admins group — DCSync targets the domain object itself, and groups
        # like Backup Operators / Account Operators are equally critical.
        targets = [dst_filter.upper()] if dst_filter else sorted(hvts)

        if src_filter:
            src = src_filter.upper()
            for dst in targets:
                h2(f"Shortest Path: {src} → {dst}")
                r = eng.shortest_path(src, dst)
                if r.found:
                    add(f"  ({r.hops} hop{'s' if r.hops != 1 else ''}, {r.elapsed_ms:.1f} ms)")
                    add(f"  {fmt_path(r.path)}")
                else:
                    add(f"  No path found in {r.elapsed_ms:.1f} ms")
                add()
        else:
            for dst in targets:
                h2(f"Who can reach: {dst}")
                r = eng.who_can_reach(dst, hops=hops, exhaustive=exhaustive)
                scope = "exhaustively" if exhaustive else f"within {hops} hops"
                add(f"  {r.total} principals can reach this target "
                    f"{scope}  ({r.elapsed_ms:.1f} ms)")
                add()
                for dist in sorted(r.by_distance):
                    bucket = r.by_distance[dist]
                    add(f"  Hop {dist}:")
                    for n in bucket[:30]:
                        add(f"     - {n}")
                    if len(bucket) > 30:
                        add(f"     ... and {len(bucket) - 30} more")
                add()

        # ── 3. All paths (src → dst) ───────────────────────────────────────────────
        if src_filter and (dst_filter or targets):
            src = src_filter.upper()
            dst = (dst_filter or targets[0]).upper()
            r = eng.all_paths(src, dst, hops=hops, exhaustive=exhaustive, max_paths=max_paths)
            h2(f"All Paths (up to {max_paths}, {r.depth_label}): {src} → {dst}")
            for i, p in enumerate(r.paths, 1):
                add(f"  [{i}]  ({p.hops} hops)")
                add(f"       {fmt_path(p.path)}")
            if r.limit_reached:
                add(f"  ... (limit {max_paths} reached)")
            if r.count == 0:
                add("  No paths found.")
            add(f"  ({r.elapsed_ms:.1f} ms)")
            add()

        # ── 4. Reachable from target within N hops ────────────────────────────────
        if reachable_target:
            src = reachable_target.upper()
            scope = "exhaustively" if exhaustive else f"within {hops} hops"
            h2(f"Reachable from {src} {scope}")
            r = eng.reachable(src, hops=hops, exhaustive=exhaustive)
            add(f"  {r.total} nodes reachable  ({r.elapsed_ms:.1f} ms)")
            for d in sorted(r.by_distance):
                bucket = r.by_distance[d]
                add(f"\n  Hop {d}:")
                for n in bucket[:50]:
                    add(f"     - {n}")
                if len(bucket) > 50:
                    add(f"     ... and {len(bucket) - 50} more")
            add()

        # ── 5. Transitive group membership ────────────────────────────────────────
        if transitive_group:
            grp = transitive_group.upper()
            h2(f"Transitive Members of {grp}")
            r = eng.transitive(grp)
            add(f"  {len(r.members)} effective members  ({r.elapsed_ms:.1f} ms)")
            for m in r.members:
                add(f"  - {m}")
            add()

        add("═" * self.WIDTH)
        output = "\n".join(self._lines)

        if output_file:
            clean = re.sub(r"\033\[[0-9;]*m", "", output)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(clean)
            print(f"[+] Report saved → {output_file}", file=sys.stderr)
        else:
            print(output)
