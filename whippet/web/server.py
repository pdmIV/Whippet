"""
whippet.web.server — optional Flask GUI backend.

Thin HTTP/JSON wrapper around `QueryEngine`. The graph is loaded once at
startup and shared read-only across requests; every endpoint just calls an
engine method and serialises the resulting dataclass. No query logic lives
here — that all stays in the engine, so the GUI and CLI never diverge.

Flask is imported lazily by the CLI, so the core tool keeps zero third-party
dependencies; this module is only reached when the user runs `--serve`.
"""
from __future__ import annotations

import os
import sys
import threading
import webbrowser
from dataclasses import asdict

from flask import Flask, jsonify, request, send_from_directory

from ..queries import QueryEngine

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


def _truthy(val: str | None) -> bool:
    return (val or "").strip().lower() in ("1", "true", "yes", "on")


def _int_arg(name: str, default: int) -> int:
    try:
        return int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default


def create_app(engine: QueryEngine) -> Flask:
    app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")

    # ── Static shell ─────────────────────────────────────────────────────────
    @app.get("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    # ── Meta ─────────────────────────────────────────────────────────────────
    @app.get("/api/stats")
    def api_stats():
        return jsonify(asdict(engine.stats()))

    @app.get("/api/hvt")
    def api_hvt():
        return jsonify({"targets": sorted(engine.high_value_targets())})

    @app.get("/api/search")
    def api_search():
        q = request.args.get("q", "")
        limit = _int_arg("limit", 20)
        return jsonify({"results": engine.search(q, limit=limit)})

    # ── Graph neighborhood (click-to-expand) ─────────────────────────────────
    @app.get("/api/graph")
    def api_graph():
        focus = request.args.get("focus", "")
        hops = _int_arg("hops", 1)
        if not focus:
            return jsonify({"error": "focus required"}), 400
        return jsonify(asdict(engine.neighborhood(focus, hops=hops)))

    # ── Paths ────────────────────────────────────────────────────────────────
    @app.get("/api/path")
    def api_path():
        src = request.args.get("from", "")
        dst = request.args.get("to", "")
        if not src or not dst:
            return jsonify({"error": "from and to required"}), 400
        exhaustive = _truthy(request.args.get("exhaustive"))
        hops = _int_arg("hops", 6)
        max_paths = _int_arg("max_paths", 20)

        shortest = engine.shortest_path(src, dst)
        allp = engine.all_paths(src, dst, hops=hops, exhaustive=exhaustive, max_paths=max_paths)

        # Build a subgraph from the union of all discovered path nodes.
        node_set: set[str] = set()
        for p in allp.paths:
            node_set.update(n for n, _ in p.path)
        if shortest.found:
            node_set.update(n for n, _ in shortest.path)
        subgraph = engine.subgraph_for(node_set)

        return jsonify({
            "shortest": asdict(shortest),
            "all": asdict(allp),
            "subgraph": asdict(subgraph),
        })

    # ── Reachability ─────────────────────────────────────────────────────────
    @app.get("/api/reach")
    def api_reach():
        node = request.args.get("node", "")
        if not node:
            return jsonify({"error": "node required"}), 400
        direction = request.args.get("dir", "from")
        exhaustive = _truthy(request.args.get("exhaustive"))
        hops = _int_arg("hops", 6)

        if direction == "to":
            res = engine.who_can_reach(node, hops=hops, exhaustive=exhaustive)
        else:
            res = engine.reachable(node, hops=hops, exhaustive=exhaustive)

        node_set = {res.root}
        for bucket in res.by_distance.values():
            node_set.update(bucket)
        subgraph = engine.subgraph_for(node_set)
        return jsonify({"reach": asdict(res), "subgraph": asdict(subgraph)})

    # ── Transitive membership ────────────────────────────────────────────────
    @app.get("/api/transitive")
    def api_transitive():
        group = request.args.get("group", "")
        if not group:
            return jsonify({"error": "group required"}), 400
        res = engine.transitive(group)
        node_set = set(res.members) | {res.group}
        subgraph = engine.subgraph_for(node_set)
        return jsonify({"members": asdict(res), "subgraph": asdict(subgraph)})

    # ── Users ────────────────────────────────────────────────────────────────
    @app.get("/api/users")
    def api_users():
        raw = request.args.get("flags", "")
        flags = {f.strip() for f in raw.split(",") if f.strip()} or None
        enabled_only = _truthy(request.args.get("enabled"))
        rows = engine.users(flags=flags, enabled_only=enabled_only)
        return jsonify({"users": [asdict(r) for r in rows]})

    return app


def serve(engine: QueryEngine, *, host: str = "127.0.0.1", port: int = 8000,
          open_browser: bool = True):
    """Run the GUI. Blocks until interrupted."""
    app = create_app(engine)
    url = f"http://{host}:{port}"
    stats = engine.stats()
    print(f"[*] Whippet GUI: {stats.nodes:,} nodes / {stats.edges:,} edges", file=sys.stderr)
    print(f"[*] Serving on {url}  (Ctrl-C to stop)", file=sys.stderr)
    if open_browser:
        # Open the browser shortly after the server starts accepting connections.
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        print("\n[*] GUI stopped.", file=sys.stderr)
