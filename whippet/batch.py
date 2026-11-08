"""Load-once newline-delimited JSON protocol for CLI orchestrators."""
import argparse
import json
import sys
import time
import uuid
from dataclasses import asdict

from .agent import AgentReporter
from .analysis import AnalysisEngine


MODES = {"summary", "node", "search", "findings", "memberships", "path",
         "reachable", "members", "users", "catalog", "objects", "triage", "routes", "explain", "ranked-paths", "gpo-scope", "trust-path"}
FIELDS = {"id", "mode", "node", "source", "target", "query", "principal",
          "hops", "limit", "offset", "profile", "object_type", "where", "select", "sources", "avoid", "edge", "count"}


def request_args(request, defaults):
    if not isinstance(request, dict) or set(request) - FIELDS:
        raise ValueError("Expected an object containing supported request fields only")
    mode = request.get("mode")
    if mode not in MODES:
        raise ValueError("Unknown mode; choose: " + ", ".join(sorted(MODES)))
    if not isinstance(request.get("id"), (str, int, type(None))) or isinstance(request.get("id"), bool):
        raise ValueError("id must be a string, integer or null")
    args = argparse.Namespace(**vars(defaults))
    for key in ("summary", "node", "search", "findings", "memberships", "reachable",
                "transitive_members", "list_users", "catalog", "objects", "src", "dst", "principal",
                "triage", "routes", "explain", "k_shortest", "gpo_scope", "trust_path"):
        setattr(args, key, None)
    args.all_paths, args.exhaustive = False, False
    if mode != "objects" and set(request) & {"object_type", "where", "select"}:
        raise ValueError("Object filters require mode objects")
    if mode != "routes" and set(request) & {"sources", "avoid"}:
        raise ValueError("sources and avoid require mode routes")
    if mode != "explain" and "edge" in request:
        raise ValueError("edge requires mode explain")
    if mode != "ranked-paths" and "count" in request:
        raise ValueError("count requires mode ranked-paths")
    for key, default, minimum in (("hops", defaults.hops, 0), ("limit", defaults.limit, 1),
                                  ("offset", defaults.offset, 0)):
        value = request.get(key, default)
        if type(value) is not int or value < minimum:
            raise ValueError(f"{key} must be an integer >= {minimum}")
        setattr(args, key, value)
    args.profile = request.get("profile", defaults.profile)
    if args.profile not in ("supported", "potential", "raw"):
        raise ValueError("profile must be supported, potential or raw")
    for key in ("node", "source", "target", "query", "principal"):
        if key in request and not isinstance(request[key], str):
            raise ValueError(f"{key} must be a string")
    required = {"node": ("node",), "memberships": ("node",), "members": ("node",),
                "reachable": ("node",), "path": ("source", "target"), "triage": ("node",),
                "explain": ("source", "target", "edge"), "ranked-paths": ("source", "target")}.get(mode, ())
    if mode == "gpo-scope": required = ("node",)
    if mode == "trust-path": required = ("source", "target")
    if any(not request.get(key) for key in required):
        raise ValueError(f"{mode} requires: {', '.join(required)}")
    allowed = {"summary": {"source", "target"}, "node": {"node"}, "search": {"query"},
               "findings": {"query", "principal"}, "memberships": {"node"},
               "path": {"source", "target"}, "reachable": {"node"},
               "members": {"node"}, "users": set(), "catalog": set(), "objects": set(),
               "triage": {"node"}, "routes": {"target"}, "explain": {"source", "target"},
               "ranked-paths": {"source", "target"}, "gpo-scope": {"node"}, "trust-path": {"source", "target"}}[mode]
    if (set(request) & {"node", "source", "target", "query", "principal"}) - allowed:
        raise ValueError(f"Fields do not apply to mode {mode}")
    if mode == "gpo-scope":
        args.gpo_scope = request["node"]
    elif mode == "trust-path":
        args.trust_path = [request["source"], request["target"]]
    elif mode == "triage":
        args.triage = request["node"]
    elif mode == "routes":
        args.routes, args.dst = True, request.get("target")
        args.owned, args.avoid = request.get("sources", []), request.get("avoid", [])
        if not args.owned or any(not isinstance(v, list) or any(not isinstance(n, str) or not n for n in v)
                                 for v in (args.owned, args.avoid)):
            raise ValueError("routes requires a nonempty sources list and an optional avoid list of node names")
    elif mode == "explain":
        if not isinstance(request["edge"], str):
            raise ValueError("edge must be a string")
        args.explain = [request["source"], request["target"], request["edge"]]
    elif mode == "ranked-paths":
        args.k_shortest = request.get("count", 5)
        if type(args.k_shortest) is not int or not 1 <= args.k_shortest <= 100:
            raise ValueError("count must be an integer in 1..100")
        args.src, args.dst = request["source"], request["target"]
    elif mode == "objects":
        where, select = request.get("where", {}), request.get("select", ["name"])
        if not isinstance(where, dict):
            raise ValueError("where must be an object")
        args.objects, args.select = request.get("object_type", "all"), select
        args.where = [key + "=" + json.dumps(value) for key, value in where.items()]
        if not args.objects or not isinstance(args.objects, str):
            raise ValueError("object_type must be a nonempty string")
    elif mode == "summary":
        args.summary, args.src, args.dst = True, request.get("source"), request.get("target")
    elif mode == "path":
        args.src, args.dst = request["source"], request["target"]
    elif mode == "findings":
        args.findings, args.principal = request.get("query", "all"), request.get("principal")
        if not args.findings:
            raise ValueError("findings query must not be empty")
    elif mode == "search":
        args.search = request.get("query", "")
    else:
        attr = {"members": "transitive_members", "users": "list_users"}.get(mode, mode)
        setattr(args, attr, True if mode in ("users", "catalog") else request["node"])
    return args


def run_batch(engine, defaults, warnings=(), stream=None, output=None):
    stream, output = stream or sys.stdin, output or sys.stdout
    analysis = AnalysisEngine(engine.g)
    session_id, request_index = uuid.uuid4().hex, 0
    if getattr(defaults, "batch_ready", False):
        from . import __version__
        print(json.dumps({"schema_version": 1, "event": "ready", "protocol_version": 1,
            "whippet_version": __version__, "session_id": session_id,
            "stats": asdict(engine.stats()), "warnings": list(warnings),
            "modes": sorted(MODES | {"ping", "shutdown"}), "max_request_characters": 65536}), file=output, flush=True)
    while True:
        line = stream.readline(65537)
        if not line:
            break
        request_id = None
        started = time.perf_counter()
        shutdown = False
        request_index += 1
        try:
            if len(line) > 65536:
                while not line.endswith("\n"):
                    line = stream.readline(65537)
                    if not line:
                        break
                raise ValueError("Request exceeds 65536 characters")
            if not line.strip():
                request_index -= 1
                continue
            request = json.loads(line)
            if isinstance(request, dict) and type(request.get("id")) in (str, int):
                request_id = request["id"]
            if isinstance(request, dict) and request.get("mode") in ("ping", "shutdown"):
                if set(request) - {"id", "mode"} or type(request.get("id")) not in (str, int, type(None)):
                    raise ValueError("Lifecycle requests accept only mode and a string/integer/null id")
                shutdown = request["mode"] == "shutdown"
                result = {"schema_version": 1, "mode": request["mode"],
                          "result": {"status": "closing" if shutdown else "ready", "stats": asdict(engine.stats())}}
            else:
                args = request_args(request, defaults)
                result = AgentReporter(engine, args.limit, args.offset, analysis=analysis).report(args, warnings)
            result["id"] = request_id
        except (ValueError, TypeError) as exc:
            result = {"schema_version": 1, "id": request_id, "error": str(exc)}
        result["batch"] = {"session_id": session_id, "request_index": request_index,
                           "elapsed_ms": (time.perf_counter() - started) * 1000}
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")), file=output, flush=True)
        if shutdown:
            break
