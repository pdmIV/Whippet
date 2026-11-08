import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whippet import ADGraph, SharpHoundLoader, QueryEngine
from whippet.analysis import AnalysisEngine
from whippet.agent import AgentReporter
from whippet.batch import run_batch
from whippet.cli import build_parser, main
from whippet.lab import routes, explain
from whippet.ranked import ranked_paths


def lab_graph():
    g = ADGraph()
    for name, kind in (("USER", "User"), ("HELPDESK", "Group"), ("SVC", "User"),
                       ("DA", "Group"), ("PC", "Computer"), ("POLICY", "GPO")):
        g.add_node(name, {"name": name, "objectid": "SID-" + name,
                         "highvalue": name == "DA", "enabled": True,
                         "description": "Review service documentation" if name == "SVC" else ""}, kind)
    for src, dst, kind in (("USER", "HELPDESK", "MemberOf"), ("HELPDESK", "SVC", "GenericAll"),
                           ("SVC", "DA", "MemberOf"), ("USER", "PC", "ReadLAPSPassword"),
                           ("HELPDESK", "SVC", "ReadGMSAPassword"), ("SVC", "PC", "AllowedToDelegate"),
                           ("HELPDESK", "POLICY", "WriteDacl")):
        g.add_edge(src, dst, kind)
    return g


class LabTests(unittest.TestCase):
    def test_acl_finds_non_high_value_target_via_group(self):
        rows = AnalysisEngine(lab_graph()).findings("acl-control", "USER")
        row = next(r for r in rows if r["target"] == "SVC" and r["type"] == "GenericAll")
        self.assertEqual(row["membership_path"], ["USER", "HELPDESK"])

    def test_htb_findings(self):
        analysis = AnalysisEngine(lab_graph())
        for query in ("delegation", "laps", "gmsa", "descriptions", "gpo-control"):
            self.assertTrue(analysis.findings(query), query)
        self.assertEqual(analysis.findings("delegation", "USER"), [])

    def test_owned_routes_and_avoid(self):
        analysis = AnalysisEngine(lab_graph())
        self.assertEqual(routes(analysis, ["USER"])[0]["hops"], 3)
        self.assertEqual(routes(analysis, ["USER", "SVC"])[0]["source"], "SVC")
        self.assertEqual(routes(analysis, ["USER"], avoid=["SVC"]), [])
        self.assertEqual(routes(analysis, ["USER"], hops=2), [])
        with self.assertRaises(ValueError): routes(analysis, ["USER"], avoid=["USER"])

    def test_route_identity_validation(self):
        analysis = AnalysisEngine(lab_graph())
        with self.assertRaises(ValueError): routes(analysis, [])
        with self.assertRaises(ValueError): routes(analysis, ["missing"])
        self.assertEqual(routes(analysis, ["USER"], "USER", hops=0)[0]["edges"], [])

    def test_explain_requires_actual_edge(self):
        analysis = AnalysisEngine(lab_graph())
        result = explain(analysis, "sid-helpdesk", "sid-svc", "GenericAll")
        self.assertFalse(result["verified_access"])
        self.assertTrue(result["prerequisites"])
        with self.assertRaises(ValueError): explain(analysis, "USER", "DA", "GenericAll")

    def test_triage_returns_leads_per_category(self):
        args = build_parser().parse_args(["unused", "--triage", "USER", "--limit", "1"])
        result = AgentReporter(QueryEngine(lab_graph()), limit=1).report(args)["result"]
        self.assertIn("acl-control", result["findings"])
        self.assertTrue(result["findings"]["acl-control"]["truncated"])
        self.assertEqual(result["routes"]["items"][0]["target"], "DA")

    def test_raw_trust_and_gpo_metadata(self):
        g = ADGraph()
        trust = {"TargetDomainName": "OTHER", "TrustDirection": 1, "SidFilteringEnabled": True}
        link = {"GUID": "GPO-ID", "IsEnforced": False}
        SharpHoundLoader(g)._ingest([("domains.json", {"data": [{"Properties": {"name": "CORP"},
            "Trusts": [trust], "Links": [link]}]})])
        self.assertEqual(AnalysisEngine(g).findings("trusts")[0]["evidence"], trust)
        self.assertEqual(g._props["CORP"]["gpo_links"], [link])


class CertipyTests(unittest.TestCase):
    def report(self):
        return {"Certificate Authorities": {"0": {"CA Name": "LAB-CA"}},
                "Certificate Templates": {"0": {"Template Name": "UserAuth",
                    "Enabled": True, "[!] Vulnerabilities": {"ESC1": "Collector assessment"}}}}

    def test_import_reuses_assessment_without_creating_attack_edges(self):
        g = ADGraph()
        SharpHoundLoader(g)._ingest([("certipy.json", self.report())])
        self.assertEqual(g.node_count, 2)
        self.assertEqual(g.edge_count, 0)
        analysis = AnalysisEngine(g)
        finding = analysis.findings("adcs")[0]
        self.assertEqual(finding["category"], "ESC1")
        self.assertFalse(finding["principal_scope_verified"])
        self.assertEqual(finding["evidence"], "Collector assessment")
        self.assertEqual(len(analysis.objects("certificatetemplate")), 1)

    def test_principal_scope_does_not_relabel_external_assessment(self):
        g = lab_graph()
        SharpHoundLoader(g)._ingest([("certipy.json", self.report())])
        self.assertFalse(AnalysisEngine(g).findings("adcs", "USER")[0]["principal_scope_verified"])

    def test_reports_are_namespaced(self):
        g = ADGraph()
        loader = SharpHoundLoader(g)
        loader._ingest([("a/certipy.json", self.report()), ("b/certipy.json", self.report())])
        self.assertEqual(g.node_count, 4)
        loader._ingest([("a/certipy.json", self.report())])
        self.assertEqual(g.node_count, 4)

    def test_empty_and_malformed_sections(self):
        g = ADGraph()
        SharpHoundLoader(g)._ingest([("empty.json", {"Certificate Templates": 0})])
        self.assertEqual(g.node_count, 0)
        for value in ([], {"0": []}, {"0": {"Template Name": "T", "Vulnerabilities": []}}):
            with self.assertRaises(ValueError):
                SharpHoundLoader(ADGraph())._ingest([("bad.json", {"Certificate Templates": value})])

    def test_native_adcs_permissions_are_not_escalation_edges(self):
        g = ADGraph()
        SharpHoundLoader(g)._ingest([("templates.json", {"meta": {"type": "certtemplates"},
            "data": [{"ObjectIdentifier": "T-ID", "Properties": {"name": "T"},
                      "Aces": [{"PrincipalSID": "USER-SID", "RightName": "Enroll"}]}]})])
        analysis = AnalysisEngine(g)
        self.assertEqual(g.node_type("T"), "CertificateTemplate")
        self.assertEqual(analysis.findings("adcs")[0]["status"], "collected-permission")
        self.assertEqual(analysis.projection.neighbors("USER-SID"), [])

    def test_file_import_cli(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            path = Path(tmp) / "certipy.json"
            path.write_text(json.dumps(self.report()), encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                main([str(path), "--findings", "adcs"])
            self.assertEqual(json.loads(out.getvalue())["result"]["total"], 1)


@unittest.skipUnless(importlib.util.find_spec("networkx"), "optional NetworkX extra is not installed")
class RankedTests(unittest.TestCase):
    def graph(self):
        g = lab_graph()
        g.add_edge("USER", "DA", "GenericAll")
        g.add_edge("USER", "DA", "WriteDacl")
        return AnalysisEngine(g)

    def test_shortest_first_and_parallel_relationships(self):
        result = ranked_paths(self.graph(), "USER", "DA", 2)
        self.assertEqual([r["hops"] for r in result["items"]], [1, 3])
        self.assertEqual(len(result["items"][0]["steps"][0]["relationships"]), 2)
        self.assertFalse(result["more_paths"])

    def test_count_hop_and_no_path(self):
        self.assertTrue(ranked_paths(self.graph(), "USER", "DA", 1)["more_paths"])
        result = ranked_paths(self.graph(), "USER", "DA", 2, hops=1)
        self.assertEqual(len(result["items"]), 1)
        self.assertFalse(result["more_paths"])
        self.assertEqual(ranked_paths(self.graph(), "PC", "USER")["items"], [])

    def test_missing_dependency_message(self):
        import builtins
        original = builtins.__import__
        def blocked(name, *args, **kwargs):
            if name == "networkx": raise ImportError("test")
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", side_effect=blocked):
            with self.assertRaisesRegex(ValueError, "whippet-ad"):
                ranked_paths(self.graph(), "USER", "DA")


class BatchLabTests(unittest.TestCase):
    def test_new_modes_and_recovery(self):
        defaults = build_parser().parse_args(["unused", "--batch"])
        requests = [{"mode": "triage", "node": "USER"},
                    {"mode": "routes", "sources": ["USER", "SVC"], "avoid": ["PC"]},
                    {"mode": "explain", "source": "USER", "target": "HELPDESK", "edge": "MemberOf"},
                    {"mode": "routes", "sources": "USER"},
                    {"mode": "ranked-paths", "source": "USER", "target": "DA", "count": False}]
        out = io.StringIO()
        run_batch(QueryEngine(lab_graph()), defaults,
                  stream=io.StringIO('\n'.join(json.dumps(r) for r in requests)), output=out)
        rows = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([r.get("mode") for r in rows[:3]], ["triage", "routes", "explain"])
        self.assertTrue(all("error" in r for r in rows[3:]))


if __name__ == "__main__": unittest.main()
