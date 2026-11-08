"""Ranked node-distinct paths using NetworkX's maintained Yen implementation."""


def ranked_paths(analysis, source, target, count=5, hops=6, profile="supported"):
    if type(count) is not int or not 1 <= count <= 100 or hops < 0:
        raise ValueError("Ranked paths require count in 1..100 and nonnegative hops")
    source, target = analysis.require_node(source), analysis.require_node(target)
    try:
        import networkx as nx
    except ImportError as exc:
        raise ValueError('Ranked paths require NetworkX: pip install "whippet-ad[analysis]"') from exc
    if not hasattr(analysis, "_nx_profiles"):
        analysis._nx_profiles = {}
    if profile not in analysis._nx_profiles:
        graph = nx.DiGraph()
        view = analysis.route_graph(profile)
        graph.add_nodes_from(sorted(view._adj))
        for src, dst, kind in sorted(view._edge_set):
            if not graph.has_edge(src, dst):
                graph.add_edge(src, dst, relationships=[])
            graph[src][dst]["relationships"].append(kind)
        analysis._nx_profiles[profile] = graph
    graph, rows, more = analysis._nx_profiles[profile], [], False
    try:
        for nodes in nx.shortest_simple_paths(graph, source, target):
            if len(nodes) - 1 > hops:
                break
            if len(rows) == count:
                more = True
                break
            rows.append({"nodes": nodes, "hops": len(nodes) - 1,
                "steps": [{"source": src, "target": dst,
                           "relationships": [analysis.edge(src, dst, kind)
                             for kind in graph[src][dst]["relationships"]]}
                          for src, dst in zip(nodes, nodes[1:])]})
    except nx.NetworkXNoPath:
        pass
    return {"source": source, "target": target, "items": rows, "more_paths": more,
            "ordering": "hop count; node-distinct paths; relationship choices preserved",
            "backend": "NetworkX shortest_simple_paths", "hops": hops}
