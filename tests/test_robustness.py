"""Regression coverage for agent output and graph correctness. Stdlib only."""
import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from whippet import ADGraph, QueryEngine, SharpHoundLoader
from whippet.agent import AgentReporter
from whippet.cli import main
from whippet.graph import SearchLimitExceeded


FIXTURE = Path(__file__).parent / "fixtures" / "order_dependent"


def graph_chain(length=3):
    g = ADGraph()
    for i in range(length):
        g.add_node(str(i), {"name": str(i), "objectid": f"SID-{i}"}, "User")
        if i:
            g.add_edge(str(i - 1), str(i), "GenericAll")
    return g


class GraphTests(unittest.TestCase):
    def test_hop_boundary(self):
        g = graph_chain()
        self.assertEqual(list(g.bfs_all_paths("0", "2", 1)), [])
        self.assertEqual(len(list(g.bfs_all_paths("0", "2", 2))), 1)
        self.assertEqual(list(g.bfs_all_paths("0", "1", 0)), [])

    def test_self_and_missing(self):
        g = graph_chain()
        self.assertEqual(list(g.bfs_all_paths("0", "0", 0)), [[("0", "")]])
        self.assertEqual(list(g.bfs_all_paths("missing", "missing", 0)), [])
        self.assertEqual(g.reachable_from("missing"), {})

    def test_deep_path_without_recursion(self):
        g = graph_chain(1200)
        self.assertEqual(len(next(g.bfs_all_paths("0", "1199", 1199))), 1200)

    def test_expansion_budget(self):
        with self.assertRaises(SearchLimitExceeded):
            list(graph_chain().bfs_all_paths("0", "2", 3, max_expansions=1))

    def test_distinct_same_type_names_and_reloading(self):
        g = ADGraph()
        ids = [g.add_node("same", {"name": "same", "objectid": f"sid-{i}"}, "User")
               for i in range(3)]
        self.assertEqual(len(set(ids)), 3)
        for i in range(3):
            self.assertEqual(g.add_node("same", {"name": "same", "objectid": f"sid-{i}"}, "User"), ids[i])
            self.assertEqual(g.resolve(f"sid-{i}"), ids[i])
        self.assertEqual(g.node_count, 3)

    def test_sid_queries(self):
        eng = QueryEngine(graph_chain())
        self.assertTrue(eng.shortest_path("sid-0", "sid-2").found)
        self.assertEqual(eng.reachable("sid-0", hops=2, exhaustive=False).total, 2)

    def test_empty_edge_filter(self):
        g = graph_chain()
        self.assertEqual(g.reachable_from("0", edge_filter=set()), {"0": 0})
        self.assertEqual(g.can_reach("2", edge_filter=set()), {"2": 0})

    def test_limit_exactness_and_validation(self):
        eng = QueryEngine(graph_chain())
        r = eng.all_paths("0", "2", hops=2, exhaustive=False, max_paths=1)
        self.assertFalse(r.limit_reached)
        eng.g.add_edge("0", "2", "GenericWrite")
        self.assertTrue(eng.all_paths("0", "2", hops=2, exhaustive=False, max_paths=1).limit_reached)
        with self.assertRaises(ValueError):
            eng.all_paths("0", "2", hops=2, exhaustive=False, max_paths=0)

    def test_shortest_path_hop_scope(self):
        eng = QueryEngine(graph_chain())
        self.assertFalse(eng.shortest_path("0", "2", hops=1).found)
        self.assertTrue(eng.shortest_path("0", "2", hops=2).found)

    def test_engine_reports_exhausted_work(self):
        # A dense component cannot reach the isolated target. Searching all
        # simple paths still has exponential work even though no path returns.
        g = ADGraph()
        for i in range(11):
            g.add_node(str(i), {"name": str(i)})
        for i in range(10):
            for j in range(10):
                if i != j:
                    g.add_edge(str(i), str(j), "GenericAll")
        result = QueryEngine(g).all_paths("0", "10", hops=10, exhaustive=True, max_paths=20)
        self.assertTrue(result.search_limited)
        self.assertEqual(result.paths, [])


class LoaderTests(unittest.TestCase):
    def test_multiple_individual_inputs(self):
        g = ADGraph()
        SharpHoundLoader(g).load_many([str(p) for p in sorted(FIXTURE.glob("*.json"))])
        self.assertTrue(QueryEngine(g).shortest_path("JSMITH@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL").found)

    def test_sequential_loads_and_deduplication(self):
        g = ADGraph()
        loader = SharpHoundLoader(g)
        for p in sorted(FIXTURE.glob("*.json")):
            loader.load(str(p))
        self.assertTrue(QueryEngine(g).shortest_path("JSMITH@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL").found)
        count = g.edge_count
        loader.load(str(FIXTURE))
        self.assertEqual(g.edge_count, count)

    def test_session_direction_metadata_and_primary_group(self):
        g = ADGraph()
        loader = SharpHoundLoader(g)
        loader._ingest([("misleading_users.json", {"meta": {"type": "computers"}, "data": [
            {"ObjectIdentifier": "C-SID", "Properties": {"name": "C"},
             "Sessions": {"Results": [{"UserSID": "U-SID"}]}, "PrimaryGroupSID": "G-SID"}]}),
            ("users.json", {"data": [{"ObjectIdentifier": "U-SID", "Properties": {"name": "U"}}]})])
        self.assertEqual(g.node_type("C"), "Computer")
        self.assertIn(("U", "HasSession"), g.neighbors("C"))
        self.assertNotIn(("C", "HasSession"), g.neighbors("U"))
        self.assertIn(("G-SID", "MemberOf"), g.neighbors("C"))

    def test_unknown_extended_right_is_not_all_rights(self):
        self.assertEqual(SharpHoundLoader(ADGraph())._normalize_right("ExtendedRight", "unknown"), "")

    def test_invalid_and_missing_inputs(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            p = Path(tmp) / "users.json"
            for content in ("not json", "[]", '{"data":[5]}', '{"data":[{"Properties":null}]}'):
                p.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    SharpHoundLoader(ADGraph()).load(str(p))
            with self.assertRaises(ValueError):
                SharpHoundLoader(ADGraph()).load(str(Path(tmp) / "missing.json"))

    def test_zip_nested_names_uppercase_suffix_and_bom(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            p = Path(tmp) / "data.zip"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("users_archive/groups.JSON", json.dumps({"meta": {"type": "groups"},
                    "data": [{"Properties": {"name": "G"}}]}).encode("utf-8-sig"))
            g = ADGraph()
            SharpHoundLoader(g).load(str(p))
            self.assertEqual(g.node_type("G"), "Group")


class AgentTests(unittest.TestCase):
    def call_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            main([str(FIXTURE), *args])
        return json.loads(out.getvalue())

    def test_summary_routes(self):
        report = self.call_cli("--summary", "--from", "JSMITH@CORP.LOCAL")
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["result"]["routes"]["items"][0]["hops"], 2)

    def test_context_edges_not_used_by_summary(self):
        g = graph_chain()
        g.add_node("domain", {"name": "domain", "highvalue": True}, "Domain")
        g.add_edge("0", "domain", "GetChangesAll")
        r = AgentReporter(QueryEngine(g)).summary("0")
        self.assertEqual(r["routes"]["total"], 0)

    def test_truncation(self):
        report = self.call_cli("--format", "json", "--list-users", "--limit", "1")
        self.assertEqual(len(report["result"]["items"]), 1)
        self.assertEqual(report["result"]["total"], 2)
        self.assertTrue(report["result"]["truncated"])

    def test_node_and_search(self):
        report = self.call_cli("--node", "JSMITH@CORP.LOCAL")
        self.assertEqual(report["result"]["type"], "User")
        self.assertTrue(self.call_cli("--search", "smith")["result"]["items"])

    def test_path_obeys_hops(self):
        report = self.call_cli("--format", "json", "--from", "JSMITH@CORP.LOCAL",
                               "--to", "DOMAIN ADMINS@CORP.LOCAL", "--hops", "1")
        self.assertFalse(report["result"]["found"])
        self.assertNotIn("alternatives", report["result"])

    def test_unknown_node_structured_error(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exc:
                main([str(FIXTURE), "--node", "missing"])
        self.assertEqual(exc.exception.code, 1)
        self.assertIn("Unknown node", json.loads(out.getvalue())["error"])

    def test_output_file(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            p = Path(tmp) / "report.json"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                main([str(FIXTURE), "--summary", "-o", str(p)])
            self.assertEqual(json.loads(p.read_text())["mode"], "summary")

    def test_invalid_numeric_option(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exc:
                main([str(FIXTURE), "--summary", "--limit", "0"])
        self.assertEqual(exc.exception.code, 2)

    def test_file_load_errors_are_structured(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exc:
                main([str(FIXTURE / "missing.json"), "--format", "json"])
        self.assertEqual(exc.exception.code, 1)
        self.assertIn("does not exist", json.loads(out.getvalue())["error"])


if __name__ == "__main__":
    unittest.main()

