"""
whippet.cli — argument parsing and the command-line entry point.

Builds the graph from SharpHound input, then either prints the text report
(default) or launches the optional browser GUI (`--serve`).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import zipfile
from pathlib import Path

from .graph import ADGraph
from .loader import SharpHoundLoader
from .queries import QueryEngine
from .report import TextReporter
from .agent import AgentReporter
from .analysis import AnalysisEngine, QUERY_CATALOG


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

    parser.add_argument("--format", choices=["text", "json"], default="text",
        help="Versioned JSON output for agent consumption")
    parser.add_argument("--limit", type=int, default=20,
        help="Maximum rows per JSON collection (default: 20)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--summary", action="store_true",
        help="Compact JSON inventory and routes from --from to high-value targets")
    mode.add_argument("--node", help="Inspect an exact node name or SID as JSON")
    mode.add_argument("--search", help="Find node names by prefix or substring as JSON")
    mode.add_argument("--findings", choices=["all", *QUERY_CATALOG],
        help="Run a named evidence-based AD findings query as JSON")
    mode.add_argument("--memberships", metavar="NODE",
        help="Effective groups with shortest membership proof chains as JSON")
    mode.add_argument("--catalog", action="store_true", help="JSON query catalog and analysis coverage")
    mode.add_argument("--batch", action="store_true", help="Load once; accept JSON requests on stdin")
    mode.add_argument("--gpo-scope", metavar="GPO", help="GPO descendant scope, blocks, enforcement and remaining application checks")
    mode.add_argument("--trust-path", nargs=2, metavar=("SOURCE_DOMAIN", "TARGET_DOMAIN"), help="Directional authentication relationship path, not a compromise path")
    mode.add_argument("--triage", metavar="PRINCIPAL", help="Grouped HTB leads, effective groups and supported routes as JSON")
    mode.add_argument("--routes", action="store_true", help="Shortest routes from one or more --owned principals")
    mode.add_argument("--explain", nargs=3, metavar=("SOURCE", "TARGET", "EDGE"), help="Inspect an existing relationship and its prerequisites")
    mode.add_argument("--k-shortest", type=int, help="Ranked node-distinct paths via NetworkX; requires --from and --to (1..100)")
    parser.add_argument("--owned", action="append", default=[], help="Owned source for --routes; repeat for multiple sources")
    parser.add_argument("--avoid", action="append", default=[], help="Node to exclude from --routes; repeat as needed")
    mode.add_argument("--objects", choices=["all", "user", "computer", "group", "domain", "ou", "gpo", "container", "certificatetemplate", "enterpriseca", "rootca", "aiaca", "ntauthstore"],
        help="List objects with exact property filters as JSON")
    parser.add_argument("--where", action="append", default=[], metavar="KEY=VALUE",
        help="With --objects: exact AND filter, values parsed as JSON or strings")
    parser.add_argument("--select", nargs="+", default=["name"], metavar="PROPERTY",
        help="With --objects: properties to return (default: name)")
    parser.add_argument("--principal", help="Scope --findings to a principal and its effective groups")
    parser.add_argument("--offset", type=int, default=0, help="JSON row offset for pagination")
    parser.add_argument("--profile", choices=["supported", "potential", "raw"], default="supported",
        help="JSON path/reach relationship model (default: supported)")
    parser.add_argument("--all-paths", action="store_true",
        help="Include bounded alternate paths in a JSON --from/--to query")

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


def _load_graph(inputs):
    graph = ADGraph()
    loader = SharpHoundLoader(graph)
    t0 = time.perf_counter()
    loader.load_many(inputs)
    print(f"[*] Loaded {graph.node_count:,} nodes, {graph.edge_count:,} edges "
          f"({(time.perf_counter()-t0)*1000:.0f} ms)", file=sys.stderr)
    if graph.node_count == 0:
        raise ValueError("No objects loaded")
    for warning in loader.warnings:
        print(f"[!] {warning}", file=sys.stderr)
    return graph, loader.warnings


def _fail(args, exc):
    if args.format == "json":
        print(json.dumps({"schema_version": 1, "error": str(exc)}))
    print(f"[!] {exc}", file=sys.stderr)
    raise SystemExit(1)


def main(argv: list[str] | None = None):
    # Box-drawing characters are UTF-8; make sure stdout can emit them even on a
    # legacy Windows code page. This only affects encoding, not report content.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.hops < 0 or args.max_paths < 1 or args.limit < 1 or args.offset < 0:
        parser.error("--hops must be nonnegative; --max-paths and --limit must be positive")
    if args.summary or args.node or args.search is not None or args.findings or args.memberships or args.catalog or args.batch or args.objects or args.triage or args.routes or args.explain or args.k_shortest is not None or args.gpo_scope or args.trust_path:
        args.format = "json"
    if args.serve and args.format == "json":
        parser.error("JSON queries cannot be combined with --serve")
    if sum(bool(v) for v in (args.summary, args.node, args.search is not None, args.findings, args.memberships, args.catalog, args.batch, args.objects, args.triage, args.routes, args.explain, args.k_shortest is not None, args.gpo_scope, args.trust_path,
                            args.reachable, args.transitive_members, args.list_users)) > 1 and args.format == "json":
        parser.error("Select one JSON query mode per invocation")
    if args.all_paths and not (args.src and args.dst and args.format == "json"):
        parser.error("--all-paths requires --format json --from and --to")
    if args.all_paths and (args.summary or args.node or args.search is not None
                          or args.reachable or args.transitive_members or args.list_users
                          or args.catalog or args.findings or args.memberships or args.objects or args.triage or args.routes or args.explain or args.k_shortest or args.gpo_scope or args.trust_path):
        parser.error("--all-paths cannot be combined with another query mode")
    if (args.user_flags or args.enabled_only) and not args.list_users:
        parser.error("User filters require --list-users")
    if args.principal and not args.findings:
        parser.error("--principal requires --findings")
    if args.format == "json" and (args.src or args.dst) and any((args.node, args.search is not None,
            args.findings, args.memberships, args.catalog, args.objects, args.reachable, args.triage, args.explain, args.gpo_scope, args.trust_path,
            args.transitive_members, args.list_users)):
        parser.error("--from and --to apply only to summary or path/reach queries")
    if (args.where or args.select != ["name"]) and not args.objects:
        parser.error("--where and --select require --objects")
    if args.batch and (args.output or args.src or args.dst or args.all_paths):
        parser.error("Batch requests must supply their own queries; -o is not supported")
    if args.k_shortest is not None and (not 1 <= args.k_shortest <= 100 or not args.src or not args.dst or args.exhaustive):
        parser.error("--k-shortest requires --from, --to, count in 1..100 and a finite --hops")
    if args.routes and (not args.owned or args.src or args.exhaustive):
        parser.error("--routes requires --owned, finite --hops, and accepts --to rather than --from")
    if (args.owned or args.avoid) and not args.routes:
        parser.error("--owned and --avoid require --routes")
    try:
        graph, warnings = _load_graph(args.input)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        _fail(args, exc)
    engine = QueryEngine(graph)
    if args.batch:
        from .batch import run_batch
        run_batch(engine, args, warnings)
        return
    if args.format == "json":
        try:
            report = AgentReporter(engine, args.limit, args.offset).report(args, warnings)
            output = json.dumps(report, ensure_ascii=True, separators=(",", ":"))
            if args.output:
                Path(args.output).write_text(output + "\n", encoding="utf-8")
            else:
                print(output)
        except (OSError, ValueError) as exc:
            _fail(args, exc)
        return

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
