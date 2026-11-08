import contextlib
import io
import json
import importlib.util
import tempfile
import unittest
from pathlib import Path

from whippet import ADGraph, SharpHoundLoader, QueryEngine
from whippet.analysis import AnalysisEngine
from whippet.agent import AgentReporter
from whippet.batch import run_batch
from whippet.cli import build_parser, main
from whippet.policy import PolicyAnalyzer
from whippet.trusts import TrustAnalyzer
from whippet.lab import routes, explain


def policy_graph(enforced=False, enabled=True, flags=0):
    g = ADGraph()
    for name, kind, extra in (("USER", "User", {}), ("GROUP", "Group", {}),
                             ("POLICY", "GPO", {"flags": flags, "wmifilter": "Collected WMI filter"}),
                             ("ROOT", "Domain", {}), ("OU", "OU", {"blocksinheritance": False}),
                             ("BLOCK", "OU", {"blocksinheritance": True}),
                             ("PC", "Computer", {}), ("BLOCK-PC", "Computer", {})):
        g.add_node(name, {"name": name, "objectid": "ID-" + name, **extra}, kind)
    link = {"Guid": "{ID-POLICY}", "IsEnabled": enabled}
    if enforced is not None: link["IsEnforced"] = enforced
    g._props["ROOT"]["gpo_links"] = [link]
    for src, dst, kind in (("USER", "GROUP", "MemberOf"), ("GROUP", "POLICY", "GenericAll"),
                           ("POLICY", "ROOT", "GPLink"), ("ROOT", "OU", "Contains"),
                           ("ROOT", "BLOCK", "Contains"), ("OU", "PC", "Contains"),
                           ("BLOCK", "BLOCK-PC", "Contains")):
        g.add_edge(src, dst, kind)
    return g


def trust_graph(direction=2, filtering=False, trust_type="ParentChild", transitive=True, selective=False):
    g = ADGraph()
    for name in ("A", "B", "C"):
        g.add_node(name, {"name": name, "objectid": "SID-" + name}, "Domain")
    record = {"TargetDomainName": "A", "TargetDomainSid": "SID-A", "TrustDirection": direction,
              "TrustType": trust_type, "IsTransitive": transitive}
    if filtering is not None: record["SidFilteringEnabled"] = filtering
    if selective is not None: record["SelectiveAuthentication"] = selective
    g._props["B"]["trusts"] = [record]
    return g


class PolicyTests(unittest.TestCase):
    def test_non_enforced_link_stops_at_blocked_ou(self):
        rows = PolicyAnalyzer(policy_graph()).impacts("ID-POLICY")
        self.assertEqual(next(r for r in rows if r["target"] == "PC")["scope_status"], "candidate-scope")
        self.assertEqual(next(r for r in rows if r["target"] == "BLOCK")["scope_status"], "blocked-inheritance")
        self.assertFalse(any(r["target"] == "BLOCK-PC" for r in rows))

    def test_enforced_link_crosses_block(self):
        rows = PolicyAnalyzer(policy_graph(enforced=True)).impacts()
        self.assertEqual({r["target"] for r in rows}, {"PC", "BLOCK-PC"})

    def test_disabled_link_never_produces_potential_edge(self):
        analysis = AnalysisEngine(policy_graph(enabled=False))
        self.assertTrue(all(r["scope_status"] == "disabled-link" for r in analysis.policy.impacts()))
        self.assertFalse(any(k == "PotentialGPOControl" for _, _, k in analysis.potential_projection._edge_set))

    def test_unknown_enforcement_at_block_is_explicit(self):
        rows = PolicyAnalyzer(policy_graph(enforced=None)).impacts()
        row = next(r for r in rows if r["target"] == "BLOCK-PC")
        self.assertEqual(row["scope_status"], "unknown-inheritance")
        self.assertTrue(row["conditional"])

    def test_unknown_block_setting_is_not_false(self):
        g = policy_graph()
        del g._props["OU"]["blocksinheritance"]
        row = next(r for r in PolicyAnalyzer(g).impacts() if r["target"] == "PC")
        self.assertEqual(row["scope_status"], "unknown-inheritance")

    def test_disabled_computer_section(self):
        analysis = AnalysisEngine(policy_graph(enforced=True, flags=2))
        self.assertTrue(all(r["scope_status"] == "disabled-section" for r in analysis.policy.impacts()))
        self.assertFalse(any(k == "PotentialGPOControl" for _, _, k in analysis.potential_projection._edge_set))

    def test_contradictory_enabled_flags_keep_disabled_sections_out(self):
        g = policy_graph(enforced=True, flags=2)
        g._props["POLICY"]["computerenabled"] = True
        self.assertTrue(all(r["scope_status"] == "disabled-section" for r in PolicyAnalyzer(g).impacts()))
        g = policy_graph(enabled=False)
        g._props["ROOT"]["gpo_links"][0]["Options"] = 0
        self.assertTrue(all(r["scope_status"] == "disabled-link" for r in PolicyAnalyzer(g).impacts()))

    def test_user_and_computer_flags_are_independent(self):
        g = policy_graph(enforced=True, flags=1)
        g.add_node("POLICY-USER", {"name": "POLICY-USER"}, "User")
        g.add_edge("OU", "POLICY-USER", "Contains")
        rows = PolicyAnalyzer(g).impacts()
        self.assertEqual(next(r for r in rows if r["target"] == "PC")["scope_status"], "candidate-scope")
        self.assertEqual(next(r for r in rows if r["target"] == "POLICY-USER")["scope_status"], "disabled-section")

    def test_local_link_ignores_own_ou_block(self):
        g = policy_graph()
        g._props["BLOCK"]["gpo_links"] = [{"GUID": "ID-POLICY", "IsEnforced": False}]
        rows = PolicyAnalyzer(g).impacts()
        row = next(r for r in rows if r["target"] == "BLOCK-PC")
        self.assertEqual(row["scope_status"], "candidate-scope")
        self.assertEqual(row["link_container"], "BLOCK")

    def test_link_options_are_interpreted(self):
        g = policy_graph()
        g._props["ROOT"]["gpo_links"][0]["Options"] = 3
        self.assertTrue(all(r["scope_status"] == "disabled-link" for r in PolicyAnalyzer(g).impacts()))

    def test_containment_cycle_terminates(self):
        g = policy_graph()
        g.add_edge("OU", "ROOT", "Contains")
        self.assertLess(len(PolicyAnalyzer(g).impacts()), 10)

    def test_conditional_profile_and_control_proof(self):
        analysis = AnalysisEngine(policy_graph())
        self.assertFalse(routes(analysis, ["USER"], "PC"))
        result = routes(analysis, ["USER"], "PC", profile="potential")
        edge = result[0]["edges"][-1]
        self.assertTrue(edge["conditional"])
        self.assertEqual(edge["type"], "PotentialGPOControl")
        self.assertTrue(edge["evidence"][0]["unknowns"])
        findings = analysis.findings("gpo-impact", "USER")
        self.assertEqual(findings[0]["control_evidence"][0]["membership_path"], ["USER", "GROUP"])
        self.assertFalse(explain(analysis, "POLICY", "PC", "PotentialGPOControl")["verified_access"])

    def test_legacy_containment_and_gpo_changes_ingestion(self):
        g = ADGraph()
        docs = [("groups.json", {"data": [{"ObjectIdentifier": "GRP", "Properties": {"name": "GROUP"}}]}),
                ("computers.json", {"data": [{"ObjectIdentifier": "PC-ID", "Properties": {"name": "PC"}}]}),
                ("gpos.json", {"data": [{"ObjectIdentifier": "{POL-ID}", "Properties": {"name": "POLICY"}}]}),
                ("ous.json", {"data": [{"ObjectIdentifier": "OU-ID", "Properties": {"name": "OU"},
                    "BlocksInheritance": True, "Links": [{"Guid": "POL-ID", "IsEnforced": True}],
                    "Computers": ["PC-ID"], "GPOChanges": {"AffectedComputers": [{"ObjectIdentifier": "PC-ID"}],
                        "LocalAdmins": [{"ObjectIdentifier": "GRP"}]}}]})]
        SharpHoundLoader(g)._ingest(docs)
        self.assertEqual(g._props["OU"]["blocksinheritance"], True)
        self.assertIn(("PC", "Contains"), g.neighbors("OU"))
        self.assertIn(("OU", "GPLink"), g.neighbors("POLICY"))
        analysis = AnalysisEngine(g)
        self.assertIn(("PC", "AdminTo"), analysis.projection.neighbors("GROUP"))
        self.assertEqual(analysis.edge("GROUP", "PC", "AdminTo")["collection_evidence"][0]["container"], "OU")


class TrustTests(unittest.TestCase):
    def test_authentication_direction(self):
        for direction, expected in ((1, {("B", "A")}), (2, {("A", "B")}),
                                    (3, {("A", "B"), ("B", "A")}), (0, set())):
            flows = TrustAnalyzer(trust_graph(direction=direction)).flows()
            self.assertEqual({(r["source"], r["target"]) for r in flows}, expected)

    def test_unknown_direction_and_filter_flags(self):
        g = trust_graph(direction=None, filtering=None, selective=None)
        analysis = TrustAnalyzer(g)
        self.assertEqual(analysis.flows(), [])
        self.assertTrue(analysis.records()[0]["unknowns"])
        self.assertFalse(analysis.sid_history_candidates())

    def test_receiver_filtering_is_not_reversed(self):
        analyzer = TrustAnalyzer(trust_graph(direction=1, filtering=False))
        self.assertEqual(analyzer.flows()[0]["source"], "B")
        self.assertIsNone(analyzer.flows()[0]["sid_filtering"])
        self.assertFalse(analyzer.sid_history_candidates())
        self.assertEqual(TrustAnalyzer(trust_graph()).sid_history_candidates()[0]["source"], "A")

    def test_filtered_and_external_trusts_do_not_escalate(self):
        self.assertFalse(TrustAnalyzer(trust_graph(filtering=True)).sid_history_candidates())
        self.assertFalse(TrustAnalyzer(trust_graph(trust_type="Forest")).sid_history_candidates())
        self.assertFalse(TrustAnalyzer(trust_graph(trust_type="External")).sid_history_candidates())

    def test_legacy_collector_numeric_type_enum(self):
        for kind, name, same_forest in ((0, "TreeRoot", True), (1, "ParentChild", True),
                                        (2, "CrossLink", True), (3, "External", False),
                                        (4, "Forest", False), ("4", "Forest", False), (6, "Unknown", None)):
            row = TrustAnalyzer(trust_graph(trust_type=kind)).records()[0]
            self.assertEqual(row["trust_type"], name)
            self.assertEqual(row["same_forest"], same_forest)

    def test_selective_authentication_is_preserved(self):
        analyzer = TrustAnalyzer(trust_graph(selective=True))
        result = analyzer.paths("A", "B")
        self.assertTrue(result["found"])
        self.assertTrue(result["steps"][0]["selective_authentication"])
        self.assertFalse(result["verified_access"])
        self.assertTrue(any("Allowed-to-authenticate" in x for x in analyzer.records()[0]["unknowns"]))

    def test_same_forest_multihop_and_nontransitive_boundary(self):
        for trust_type, transitive, expected in (("ParentChild", True, True), ("External", True, False),
                                                   ("ParentChild", False, False)):
            g = trust_graph()
            g._props["C"]["trusts"] = [{"TargetDomainName": "B", "TrustDirection": 2,
                "TrustType": trust_type, "IsTransitive": transitive}]
            self.assertEqual(TrustAnalyzer(g).paths("A", "C")["found"], expected)

    def test_no_implicit_reverse_or_cross_forest_chaining(self):
        analyzer = TrustAnalyzer(trust_graph(trust_type="Forest"))
        self.assertTrue(analyzer.paths("A", "B")["found"])
        self.assertFalse(analyzer.paths("B", "A")["found"])

    def test_filter_conflicts_are_not_escalation_candidates(self):
        g = trust_graph()
        g._props["B"]["trusts"][0]["TrustAttributes"] = 0x24
        analyzer = TrustAnalyzer(g)
        self.assertTrue(analyzer.records()[0]["configuration_conflicts"])
        self.assertFalse(analyzer.sid_history_candidates())

    def test_trust_candidate_profile_is_explicit(self):
        analysis = AnalysisEngine(trust_graph())
        self.assertEqual(routes(analysis, ["A"], "B"), [])
        row = routes(analysis, ["A"], "B", profile="potential")[0]
        self.assertTrue(row["edges"][0]["conditional"])
        self.assertEqual(row["edges"][0]["type"], "PotentialSIDHistory")

    def test_loader_creates_directional_context_edges(self):
        g = ADGraph()
        SharpHoundLoader(g)._ingest([("domains.json", {"data": [
            {"Properties": {"name": "A"}}, {"Properties": {"name": "B"},
             "Trusts": [{"TargetDomainName": "A", "TrustDirection": 2}]}]})])
        self.assertIn(("B", "CanAuthenticateTo"), g.neighbors("A"))
        self.assertNotIn(("A", "CanAuthenticateTo"), g.neighbors("B"))
        self.assertEqual(AnalysisEngine(g).projection.neighbors("A"), [])


class InterfaceTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec("networkx"), "optional NetworkX is not installed")
    def test_ranked_profile_caches_are_separate(self):
        from whippet.ranked import ranked_paths
        analysis = AnalysisEngine(policy_graph())
        self.assertEqual(ranked_paths(analysis, "USER", "PC")["items"], [])
        result = ranked_paths(analysis, "USER", "PC", profile="potential")
        self.assertTrue(result["items"][0]["steps"][-1]["relationships"][0]["conditional"])
        self.assertEqual(ranked_paths(analysis, "USER", "PC")["items"], [])

    def test_file_to_cli_analysis(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            folder = Path(tmp)
            data = {
                "domains": [{"ObjectIdentifier": "SID-A", "Properties": {"name": "A"}},
                            {"ObjectIdentifier": "SID-B", "Properties": {"name": "B"},
                             "Trusts": [{"TargetDomainName": "A", "TrustDirection": "Outbound", "TrustType": "ParentChild",
                                         "SidFilteringEnabled": False, "IsTransitive": True}],
                             "Links": [{"Guid": "POL", "IsEnforced": True}],
                             "ChildObjects": [{"ObjectIdentifier": "PC-ID"}]}],
                "computers": [{"ObjectIdentifier": "PC-ID", "Properties": {"name": "PC"}}],
                "gpos": [{"ObjectIdentifier": "POL", "Properties": {"name": "POLICY", "flags": 0}}]}
            for kind, rows in data.items():
                (folder / (kind + ".json")).write_text(json.dumps({"data": rows, "meta": {"type": kind}}), encoding="utf-8")
            for args, mode in ((["--gpo-scope", "POLICY"], "gpo-scope"),
                               (["--trust-path", "A", "B"], "trust-path"),
                               (["--format", "json", "--from", "POLICY", "--to", "PC", "--profile", "potential"], "path")):
                out = io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    main([str(folder), *args])
                result = json.loads(out.getvalue())
                self.assertEqual(result["mode"], mode)
                if mode != "gpo-scope": self.assertTrue(result["result"]["found"])

    def test_cli_report_modes(self):
        args = build_parser().parse_args(["unused", "--gpo-scope", "POLICY"])
        result = AgentReporter(QueryEngine(policy_graph())).report(args)
        self.assertEqual(result["mode"], "gpo-scope")
        self.assertTrue(result["result"]["items"])
        args = build_parser().parse_args(["unused", "--trust-path", "A", "B"])
        self.assertTrue(AgentReporter(QueryEngine(trust_graph())).report(args)["result"]["found"])

    def test_batch_potential_profile_and_recovery(self):
        g = policy_graph()
        defaults = build_parser().parse_args(["unused", "--batch"])
        requests = [{"mode": "gpo-scope", "node": "POLICY"},
                    {"mode": "path", "source": "USER", "target": "PC", "profile": "potential"},
                    {"mode": "trust-path", "source": "USER", "target": "PC"},
                    {"mode": "catalog"}]
        out = io.StringIO()
        run_batch(QueryEngine(g), defaults,
            stream=io.StringIO('\n'.join(json.dumps(r) for r in requests)), output=out)
        rows = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertTrue(rows[1]["result"]["found"])
        self.assertTrue(rows[1]["result"]["edges"][-1]["conditional"])
        self.assertIn("error", rows[2])
        self.assertEqual(rows[3]["mode"], "catalog")


if __name__ == "__main__": unittest.main()
