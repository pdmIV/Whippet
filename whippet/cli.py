"""
whippet.cli — argument parsing and the command-line entry point.

Builds the graph from SharpHound input, then either prints the text report
(default) or launches the optional browser GUI (`--serve`).
"""
from __future__ import annotations

import argparse
import sys
import time

from .graph import ADGraph, IGRAPH
from .loader import SharpHoundLoader
from .queries import QueryEngine
from .report import TextReporter


def build_parser() -> argparse.ArgumentParser:
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

  # Launch the browser visualizer (optional, needs flask)
  python3 whippet.py bloodhound.zip --serve
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

    # ── Optional browser GUI ──────────────────────────────────────────────────
    web = parser.add_argument_group("browser visualizer (optional)")
    web.add_argument("--serve", action="store_true",
        help="Launch the in-browser graph visualizer instead of printing a "
             "report. Requires flask (pip install \"whippet[web]\").")
    web.add_argument("--host", default="127.0.0.1",
        help="Host/interface for --serve (default: 127.0.0.1)")
    web.add_argument("--port", type=int, default=8000,
        help="Port for --serve (default: 8000)")
    web.add_argument("--no-browser", action="store_true",
        help="With --serve, do not auto-open a web browser")
    return parser


def _load_graph(inputs: list[str]) -> ADGraph:
    graph = ADGraph()
    loader = SharpHoundLoader(graph)
    for inp in inputs:
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
    return graph


def main(argv: list[str] | None = None):
    # Box-drawing characters are UTF-8; make sure stdout can emit them even on a
    # legacy Windows code page. This only affects encoding, not report content.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    args = build_parser().parse_args(argv)
    graph = _load_graph(args.input)
    engine = QueryEngine(graph)

    if args.serve:
        try:
            from .web.server import serve
        except ImportError:
            print("[!] The browser visualizer needs Flask, which isn't installed.",
                  file=sys.stderr)
            print('    Install it with:  pip install "whippet[web]"   (or: pip install flask)',
                  file=sys.stderr)
            sys.exit(1)
        serve(engine,
              host=args.host,
              port=args.port,
              open_browser=not args.no_browser)
        return

    TextReporter(engine).run(
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
