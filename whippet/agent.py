"""Bounded, versioned JSON reports for HARP and other CLI consumers."""
from collections import Counter, deque
from dataclasses import asdict
import json

from .queries import QueryEngine


from .analysis import AnalysisEngine, CONTEXT_EDGES
from .lab import routes, explain, handoff, route_diagnostic


class AgentReporter:
    def __init__(self, engine: QueryEngine, limit: int = 20, offset: int = 0, analysis=None):
        if limit < 1:
            raise ValueError("limit must be positive")
        if offset < 0:
            raise ValueError("offset must be nonnegative")
        self.engine, self.g, self.limit, self.offset = engine, engine.g, limit, offset
        self.analysis = analysis or AnalysisEngine(self.g)

    def bounded(self, rows):
        end = self.offset + self.limit
        return {"items": rows[self.offset:end], "total": len(rows), "offset": self.offset,
                "truncated": len(rows) > end,
                "next_offset": end if len(rows) > end else None}

    def require_node(self, name):
        node = self.g.resolve(name)
        if not self.g.has_node(node):
            raise ValueError(f"Unknown node: {name}. Use --search to find an exact name or SID.")
        return node

    def node(self, name):
        node = self.require_node(name)
        props = self.g._props.get(node, {})
        return {"id": node, "name": self.g.node_name(node),
                "objectid": self.g._name.get(node), "type": self.g.node_type(node),
                "properties": props,
                "outgoing": self.bounded([
                    {"target": n, "type": e} for n, e in sorted(self.g.neighbors(node))]),
                "incoming": self.bounded([
                    {"source": n, "type": e} for n, e in sorted(self.g.neighbors(node, reverse=True))])}

    def summary(self, src=None, dst=None, hops=6, profile="supported"):
        if hops < 0:
            raise ValueError("hops must be nonnegative")
        targets = [self.require_node(dst)] if dst else sorted(self.engine.high_value_targets())
        result = {"targets": self.bounded(targets),
                  "users": self.bounded([asdict(u) for u in self.engine.users()]),
                  "edge_counts": dict(sorted(Counter(e for _, _, e in self.g._edge_set).items())),
                  "excluded_route_edges": sorted(CONTEXT_EDGES)}
        if src:
            src = self.require_node(src)
            view = self.analysis.route_graph(profile)
            parent, distance, queue = {src: None}, {src: 0}, deque([src])
            while queue:
                current = queue.popleft()
                if distance[current] >= hops:
                    continue
                for node, edge in sorted(view.neighbors(current)):
                    if edge in CONTEXT_EDGES or node in parent:
                        continue
                    parent[node] = (current, edge)
                    distance[node] = distance[current] + 1
                    queue.append(node)
            candidates = sorted((n for n in targets if n in parent),
                                key=lambda n: (distance[n], n))
            routes = []
            for target in candidates[self.offset:self.offset + self.limit]:
                path, node = [], target
                while parent[node] is not None:
                    previous, edge = parent[node]
                    path.append(self.analysis.edge(previous, node, edge))
                    node = previous
                routes.append({"target": target, "hops": distance[target],
                               "edges": list(reversed(path))})
            result.update(source=src, hops=hops,
                          routes={"items": routes, "total": len(candidates),
                                  "offset": self.offset, "truncated": len(candidates) > self.offset + self.limit,
                                  "next_offset": self.offset + self.limit if len(candidates) > self.offset + self.limit else None},
                          reachable_nodes=len(parent) - 1)
        result["coverage"] = self.analysis.coverage()
        return result

    def report(self, args, warnings=()):
        eng = self.engine
        if args.profile in ("supported", "potential") and (args.reachable or (args.dst and not args.summary)):
            eng = QueryEngine(self.analysis.route_graph(args.profile))
        route_profile = "potential" if args.profile == "potential" else "supported"
        if args.handoff:
            mode, result = "handoff", handoff(self.analysis, args.handoff, args.lead_query, args.lead_index)
        elif args.gpo_scope:
            mode, result = "gpo-scope", {"gpo": self.require_node(args.gpo_scope),
                **self.bounded(self.analysis.policy.impacts(args.gpo_scope))}
        elif args.trust_path:
            mode, result = "trust-path", self.analysis.trusts.paths(*args.trust_path)
        elif args.triage:
            principal = self.require_node(args.triage)
            grouped = {}
            for row in self.analysis.findings(principal=principal):
                grouped.setdefault(row["query"], []).append(row)
            triage_routes = routes(self.analysis, [principal], hops=eng._effective_hops(args.hops, args.exhaustive), profile=route_profile)
            self.analysis.triage_context[principal] = {"finding_counts": {k: len(v) for k, v in grouped.items()},
                "route_total": len(triage_routes),
                "follow_up": {"mode": "triage", "node": principal, "limit": args.limit}}
            mode, result = "triage", {"principal": principal,
                "memberships": self.bounded(self.analysis.memberships(principal)),
                "findings": {key: self.bounded(rows) for key, rows in sorted(grouped.items())},
                "routes": self.bounded(triage_routes),
                "coverage": {key: self.analysis.coverage()[key] for key in
                    ("profile", "full_bloodhound_parity", "unsupported_analysis")}}
        elif args.routes:
            mode, result = "routes", {"owned": args.owned, "avoid": args.avoid,
                **self.bounded(routes(self.analysis, args.owned, args.dst, args.hops, args.avoid, profile=route_profile))}
        elif args.explain:
            mode, result = "explain", explain(self.analysis, *args.explain)
        elif args.k_shortest:
            from .ranked import ranked_paths
            mode, result = "ranked-paths", ranked_paths(self.analysis, args.src, args.dst, args.k_shortest, args.hops, profile=route_profile)
        elif args.catalog:
            mode, result = "catalog", self.analysis.coverage()
        elif args.objects:
            where = {}
            for expression in args.where:
                key, separator, value = expression.partition("=")
                if not separator or not key or key in where:
                    raise ValueError("Filters require unique nonempty KEY=VALUE expressions")
                try:
                    where[key] = json.loads(value)
                except ValueError:
                    where[key] = value
            mode, result = "objects", self.bounded(self.analysis.objects(args.objects, where, args.select))
        elif args.findings:
            mode, result = "findings", {"query": args.findings, "principal": args.principal,
                **self.bounded(self.analysis.findings(args.findings, args.principal))}
        elif args.memberships:
            mode, result = "memberships", {"principal": self.require_node(args.memberships),
                **self.bounded(self.analysis.memberships(args.memberships))}
        elif args.summary:
            mode, result = "summary", self.summary(args.src, args.dst,
                            eng._effective_hops(args.hops, args.exhaustive), profile=route_profile)
        elif args.node:
            mode, result = "node", self.node(args.node)
        elif args.search is not None:
            # Request one extra entry to report truncation without returning
            # an unbounded inventory to the model.
            rows = eng.search(args.search, limit=self.offset + self.limit + 1)
            mode, result = "search", {"items": rows[self.offset:self.offset + self.limit], "offset": self.offset,
                                      "truncated": len(rows) > self.offset + self.limit,
                                      "next_offset": self.offset + self.limit if len(rows) > self.offset + self.limit else None}
        elif args.list_users:
            mode, result = "users", self.bounded([asdict(u) for u in eng.users(
                flags=set(args.user_flags or []) or None, enabled_only=args.enabled_only)])
        elif args.transitive_members:
            group = self.require_node(args.transitive_members)
            mode, result = "members", {"group": group,
                **self.bounded(eng.transitive(group).members)}
        elif args.reachable or (args.dst and not args.src):
            node = self.require_node(args.reachable or args.dst)
            reach = (eng.reachable if args.reachable else eng.who_can_reach)(
                node, hops=args.hops, exhaustive=args.exhaustive)
            rows = [{"id": n, "hops": d} for d in sorted(reach.by_distance)
                    for n in reach.by_distance[d]]
            mode, result = "reach", {"root": reach.root, "direction": reach.direction,
                                     **self.bounded(rows)}
        elif args.src and args.dst:
            src, dst = self.require_node(args.src), self.require_node(args.dst)
            mode, result = "path", asdict(eng.shortest_path(
                src, dst, hops=None if args.exhaustive else args.hops))
            if args.profile in ("supported", "potential"):
                result["edges"] = [self.analysis.edge(result["path"][i - 1][0], node, kind)
                    for i, (node, kind) in enumerate(result["path"]) if i]
            if args.all_paths:
                result["alternatives"] = asdict(eng.all_paths(src, dst, hops=args.hops,
                    exhaustive=args.exhaustive, max_paths=args.max_paths))
        else:
            mode, result = "summary", self.summary(args.src, args.dst,
                            eng._effective_hops(args.hops, args.exhaustive), profile=route_profile)
        if mode == "routes" and not result["total"]:
            result["route_diagnostic"] = route_diagnostic(self.analysis, [self.require_node(n) for n in args.owned],
                self.require_node(args.dst) if args.dst else None, args.hops, route_profile, False, args.avoid)
        if mode == "path" and not result["found"]:
            result["route_diagnostic"] = route_diagnostic(self.analysis, [result["src"]], result["dst"],
                None if args.exhaustive else args.hops, args.profile, False)
        if mode == "ranked-paths" and not result["items"]:
            result["route_diagnostic"] = route_diagnostic(self.analysis, [result["source"]], result["target"],
                args.hops, route_profile, False)
        if mode in ("triage", "summary") and result.get("routes", {}).get("total") == 0:
            principal = result.get("principal") or result.get("source")
            result["route_diagnostic"] = route_diagnostic(self.analysis, [principal] if principal else [],
                self.require_node(args.dst) if args.dst else None, args.hops, route_profile, False)
        return {"schema_version": 1, "mode": mode, "stats": asdict(self.engine.stats()),
                "path_profile": route_profile if mode in ("summary", "triage", "routes", "ranked-paths") else args.profile,
                "warnings": list(warnings),
                "unresolved_nodes": sum(n not in self.g._props for n in self.g._adj),
                "semantics": "Collected graph relationships are leads, not verified exploitability. "
                             "Missing paths do not prove that no attack path exists.",
                "result": result}
