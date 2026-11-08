import contextlib
import io
import json
import unittest

from whippet import ADGraph, QueryEngine
from whippet.agent import AgentReporter
from whippet.analysis import AnalysisEngine
from whippet.batch import run_batch
from whippet.cli import build_parser, main


def fixture():
    graph = ADGraph()
    for name, kind in (("U", "User"), ("A", "Group"), ("B", "Group"),
                       ("C", "Group"), ("D", "Domain"), ("OTHER", "Domain"),
                       ("PC", "Computer"), ("DISABLED", "User")):
        graph.add_node(name, {"name": name, "objectid": "SID-" + name,
                             "enabled": name != "DISABLED", "hasspn": True}, kind)
    for src, dst, kind in (("U", "A", "MemberOf"), ("A", "B", "MemberOf"),
                           ("U", "C", "MemberOf"), ("B", "D", "GetChanges"),
                           ("C", "D", "GetChangesAll"), ("B", "OTHER", "GetChanges"),
                           ("A", "PC", "AdminTo"), ("PC", "U", "HasSession")):
        graph.add_edge(src, dst, kind)
    return graph


class AnalysisTests(unittest.TestCase):
    def test_composition_across_nested_groups(self):
        analysis = AnalysisEngine(fixture())
        self.assertIn(("D", "DCSync"), analysis.projection.neighbors("U"))
        self.assertNotIn(("OTHER", "DCSync"), analysis.projection.neighbors("U"))
        proof = analysis.edge("U", "D", "DCSync")
        self.assertTrue(proof["derived"])
        self.assertEqual(proof["evidence"][0]["membership_path"], ["U", "A", "B"])
        self.assertEqual(proof["evidence"][1]["membership_path"], ["U", "C"])

    def test_rights_on_different_domains_do_not_combine(self):
        graph = fixture()
        graph.add_edge("U", "OTHER", "GetChangesAll")
        # OTHER only composes for U, not an unrelated group with one right.
        analysis = AnalysisEngine(graph)
        self.assertIn(("OTHER", "DCSync"), analysis.projection.neighbors("U"))
        self.assertNotIn(("OTHER", "DCSync"), analysis.projection.neighbors("B"))

    def test_non_domain_rights_not_composed(self):
        graph = fixture()
        graph.add_edge("U", "PC", "GetChanges")
        graph.add_edge("U", "PC", "GetChangesAll")
        self.assertNotIn(("PC", "DCSync"), AnalysisEngine(graph).projection.neighbors("U"))

    def test_raw_graph_preserved_and_projection_cached(self):
        graph = fixture()
        before = graph._edge_set.copy()
        analysis = AnalysisEngine(graph)
        view = analysis.projection
        self.assertIs(view, analysis.projection)
        self.assertEqual(before, graph._edge_set)
        self.assertNotIn(("D", "GetChanges"), view.neighbors("B"))
        self.assertIn(("D", "GetChanges"), graph.neighbors("B"))

    def test_membership_cycles_and_sid(self):
        graph = fixture()
        graph.add_edge("B", "A", "MemberOf")
        groups = AnalysisEngine(graph).memberships("sid-u")
        self.assertEqual({r["group"] for r in groups}, {"A", "B", "C"})

    def test_findings_types_and_scope(self):
        analysis = AnalysisEngine(fixture())
        self.assertEqual([r["subject"] for r in analysis.findings("kerberoastable")], ["U"])
        scoped = analysis.findings("local-admin", "U")
        self.assertEqual(scoped[0]["membership_path"], ["U", "A"])
        self.assertEqual(analysis.findings("local-admin", "DISABLED"), [])
        self.assertEqual(len(analysis.findings("dcsync", "U")), 1)
        self.assertEqual(analysis.findings("sessions", "U")[0]["source"], "PC")

    def test_unknown_query_and_node(self):
        analysis = AnalysisEngine(fixture())
        with self.assertRaises(ValueError): analysis.findings("unknown")
        with self.assertRaises(ValueError): analysis.memberships("missing")

    def test_object_projection_and_typed_filters(self):
        analysis = AnalysisEngine(fixture())
        rows = analysis.objects("user", {"enabled": True}, ["name", "enabled"])
        self.assertEqual([r["id"] for r in rows], ["U"])
        self.assertEqual(rows[0]["properties"], {"name": "U", "enabled": True})
        self.assertEqual(analysis.objects("user", {"enabled": 1}), [])
        self.assertEqual(analysis.objects("all", {"missing": None}), [])

    def test_invalid_object_query(self):
        analysis = AnalysisEngine(fixture())
        for kwargs in ({"select": "name"}, {"object_type": "unknown"}, {"where": []}):
            with self.assertRaises(ValueError): analysis.objects(**kwargs)

    def test_summary_route_pagination(self):
        engine = QueryEngine(fixture())
        full = AgentReporter(engine).summary("U")["routes"]
        pages = [AgentReporter(engine, limit=1, offset=i).summary("U")["routes"]["items"]
                 for i in range(full["total"])]
        self.assertEqual(full["items"], [row for page in pages for row in page])

    def test_pagination_reconstructs_full_findings(self):
        engine = QueryEngine(fixture())
        rows = AnalysisEngine(engine.g).findings()
        collected = []
        for offset in range(0, len(rows), 2):
            page = AgentReporter(engine, 2, offset).bounded(rows)
            collected.extend(page["items"])
            self.assertEqual(page["total"], len(rows))
        self.assertEqual(rows, collected)
        self.assertIsNone(AgentReporter(engine, 2, len(rows)).bounded(rows)["next_offset"])

    def test_summary_uses_derived_edges_with_evidence(self):
        result = AgentReporter(QueryEngine(fixture())).summary("U", hops=1)
        route = next(r for r in result["routes"]["items"] if r["target"] == "D")
        self.assertEqual(route["edges"][0]["type"], "DCSync")
        self.assertEqual(len(route["edges"][0]["evidence"]), 2)
        self.assertFalse(result["coverage"]["full_bloodhound_parity"])

    def test_supported_vs_raw_path(self):
        reporter = AgentReporter(QueryEngine(fixture()))
        args = build_parser().parse_args(["unused", "--format", "json", "--from", "B", "--to", "D"])
        self.assertFalse(reporter.report(args)["result"]["found"])
        args.profile = "raw"
        self.assertTrue(reporter.report(args)["result"]["found"])


class BatchTests(unittest.TestCase):
    def batch(self, requests):
        defaults = build_parser().parse_args(["unused", "--batch"])
        output = io.StringIO()
        run_batch(QueryEngine(fixture()), defaults, stream=io.StringIO(requests), output=output)
        return [json.loads(line) for line in output.getvalue().splitlines()]

    def test_several_queries_one_process(self):
        rows = self.batch('\n'.join(json.dumps(r) for r in (
            {"id": 1, "mode": "catalog"}, {"id": 2, "mode": "memberships", "node": "U"},
            {"id": 3, "mode": "path", "source": "U", "target": "D"})))
        self.assertEqual([r["id"] for r in rows], [1, 2, 3])
        self.assertEqual(rows[-1]["result"]["edges"][0]["type"], "DCSync")

    def test_malformed_request_recovery(self):
        rows = self.batch('broken\n{"id":"bad","mode":"path"}\n{"mode":"catalog"}\n')
        self.assertIn("error", rows[0])
        self.assertEqual(rows[1]["id"], "bad")
        self.assertIn("error", rows[1])
        self.assertEqual(rows[2]["mode"], "catalog")

    def test_invalid_request_values(self):
        for request in ({"mode": "users", "limit": True}, {"mode": "users", "offset": -1},
                        {"mode": "users", "output": "file"}, {"mode": "node", "node": 3},
                        {"mode": "users", "source": "ignored"}, {"mode": "findings", "query": ""}):
            self.assertIn("error", self.batch(json.dumps(request))[0])

    def test_oversized_request_recovery(self):
        rows = self.batch('x' * 70000 + '\n{"mode":"catalog"}\n')
        self.assertIn("error", rows[0])
        self.assertEqual(rows[1]["mode"], "catalog")

    def test_cli_batch(self):
        from pathlib import Path
        from unittest.mock import patch
        path = str(Path(__file__).parent / "fixtures" / "order_dependent")
        output = io.StringIO()
        with patch("sys.stdin", io.StringIO('{"mode":"catalog"}\n')), contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            main([path, "--batch"])
        self.assertEqual(json.loads(output.getvalue())["mode"], "catalog")

    def test_batch_object_query(self):
        row = self.batch(json.dumps({"mode": "objects", "object_type": "user",
            "where": {"enabled": True}, "select": ["name"], "limit": 1}))[0]
        self.assertEqual(row["result"]["items"][0]["id"], "U")

    def test_invalid_object_request_recovery(self):
        for request in ({"mode": "objects", "object_type": []},
                        {"mode": "objects", "where": []},
                        {"mode": "objects", "select": "name"},
                        {"mode": "users", "where": {}}):
            self.assertIn("error", self.batch(json.dumps(request))[0])


if __name__ == "__main__":
    unittest.main()
