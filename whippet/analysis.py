"""Evidence-preserving AD analysis over a collected graph snapshot."""
from collections import deque

from .graph import ADGraph
from .policy import PolicyAnalyzer
from .trusts import TrustAnalyzer
from .access import assess, SessionOverlay


CONTEXT_EDGES = {"GetChanges", "GetChangesAll", "GetChangesInFilteredSet",
                 "GPLink", "Contains", "AffectedBy", "TrustedBy", "Enroll", "CanAuthenticateTo", "WriteGPLink"}
QUERY_CATALOG = {
    "acl-control": "Supported ACL rights over any target, not only high-value objects",
    "delegation": "Constrained and resource-based delegation relationships",
    "laps": "Collected ReadLAPSPassword rights",
    "gmsa": "Collected ReadGMSAPassword rights",
    "descriptions": "Nonempty account/group description text for manual review",
    "gpo-control": "Control rights on GPOs",
    "gpo-impact": "GPO scope with inheritance, enforcement and section checks; application remains conditional",
    "gpo-link-control": "WriteGPLink rights on domain/OU containers",
    "trusts": "Normalized trust directions, receiver filtering and authentication flows",
    "trust-escalation": "Conditional same-forest SID-history candidates with explicit receiver evidence",
    "adcs": "Certipy-reported findings, not independently reassessed ESC rules",
    "kerberoastable": "Enabled users with collected hasspn=true",
    "asrep-roastable": "Enabled users with collected dontreqpreauth=true",
    "unconstrained-delegation": "Enabled users/computers with unconstraineddelegation=true",
    "dcsync": "Replication rights combined directly or through nested memberships",
    "local-admin": "Collected AdminTo relationships",
    "remote-access": "Collected CanRDP, CanPSRemote, ExecuteDCOM relationships",
    "sessions": "Collected computer-to-user HasSession relationships",
    "high-value-control": "Supported ACL relationships targeting heuristic high-value objects",
}
CONTROL_EDGES = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
                 "ForceChangePassword", "AddMember", "AddSelf", "AddKeyCredentialLink",
                 "AddAllowedToAct", "WriteSPN", "WriteAccountRestrictions",
                 "AllExtendedRights", "ReadLAPSPassword", "ReadGMSAPassword"}
CONTROL_EDGES |= {"ManageCA", "ManageCertificates", "WritePKIEnrollmentFlag", "WritePKINameFlag"}


class AnalysisEngine:
    """Read-only snapshot facade. Recreate after mutating the source graph."""

    def __init__(self, graph):
        self.g = graph
        self._projection = None
        self._evidence = {}
        self._conditional_evidence = {}
        self._potential_projection = None
        self.policy = PolicyAnalyzer(graph)
        self.trusts = TrustAnalyzer(graph)
        self.overlay = SessionOverlay()
        self.triage_context = {}

    def require_node(self, node):
        node = self.g.resolve(node)
        if not self.g.has_node(node):
            raise ValueError(f"Unknown node: {node}")
        return node

    def objects(self, object_type="all", where=None, select=None):
        """Exact typed-property filtering and projection, without raw dumps."""
        types = {"all", "user", "computer", "group", "domain", "ou", "gpo", "container",
                 "certificatetemplate", "enterpriseca", "rootca", "aiaca", "ntauthstore"}
        if object_type not in types:
            raise ValueError("Unsupported object type")
        where = {} if where is None else where
        select = ["name"] if select is None else select
        if not isinstance(where, dict) or not all(isinstance(k, str) and k for k in where):
            raise ValueError("where must be an object with nonempty property names")
        if not isinstance(select, list) or not all(isinstance(k, str) and k for k in select):
            raise ValueError("select must be a list of property names")
        rows = []
        for node, props in sorted(self.g._props.items()):
            if object_type != "all" and self.g.node_type(node).lower() != object_type:
                continue
            # Missing is distinct from false, zero and explicit null.
            if not all(k in props and type(props[k]) is type(v) and props[k] == v for k, v in where.items()):
                continue
            rows.append({"id": node, "type": self.g.node_type(node),
                         "properties": {k: props[k] for k in select if k in props}})
        return rows

    def memberships(self, principal):
        """One shortest MemberOf-only proof for each effective group."""
        principal = self.require_node(principal)
        parent, queue = {principal: None}, deque([principal])
        while queue:
            node = queue.popleft()
            for target, kind in sorted(self.g.neighbors(node)):
                if kind == "MemberOf" and target not in parent:
                    parent[target] = node
                    queue.append(target)
        rows = []
        for group in sorted(set(parent) - {principal}):
            chain, node = [group], group
            while parent[node] is not None:
                node = parent[node]
                chain.append(node)
            rows.append({"group": group, "path": list(reversed(chain))})
        return rows

    @property
    def projection(self):
        """Conservative supported route graph plus derived DCSync edges."""
        if self._projection is not None:
            return self._projection
        view = ADGraph()
        # Preserve the source graph's disambiguated IDs and alias table.
        for attr in ("_props", "_type", "_sid", "_name", "_name_owner"):
            setattr(view, attr, getattr(self.g, attr).copy())
        for node in self.g._adj:
            view._adj[node] = []
            view._radj[node] = []
        for src, dst, kind in sorted(self.g._edge_set):
            if kind not in CONTEXT_EDGES:
                view.add_edge(src, dst, kind)
        domains = sorted(n for n in self.g._props if self.g.node_type(n) == "Domain")
        members_cache = {}
        for domain in domains:
            effective = {"GetChanges": {}, "GetChangesAll": {}}
            for grant, kind in sorted(self.g.neighbors(domain, reverse=True)):
                if kind not in effective:
                    continue
                if grant not in members_cache:
                    members_cache[grant] = self.g.transitive_members(grant) | {grant}
                for principal in sorted(members_cache[grant]):
                    # One deterministic supporting grant per right suffices.
                    effective[kind].setdefault(principal, grant)
            for principal in sorted(effective["GetChanges"].keys() & effective["GetChangesAll"].keys()):
                view.add_edge(principal, domain, "DCSync")
                self._evidence[(principal, domain, "DCSync")] = [
                    {"source": effective[kind][principal], "target": domain, "type": kind}
                    for kind in ("GetChanges", "GetChangesAll")]
        self._projection = view
        return view

    @property
    def potential_projection(self):
        if self._potential_projection is not None:
            return self._potential_projection
        base, view = self.projection, ADGraph()
        for attr in ("_props", "_type", "_sid", "_name", "_name_owner"):
            setattr(view, attr, getattr(base, attr).copy())
        for node in base._adj:
            view._adj[node], view._radj[node] = [], []
        for src, dst, kind in sorted(base._edge_set):
            view.add_edge(src, dst, kind)
        for row in self.policy.impacts():
            if row["target_type"] != "Computer" or not row["conditional"]:
                continue
            key = (row["gpo"], row["target"], "PotentialGPOControl")
            view.add_edge(*key)
            self._conditional_evidence.setdefault(key, []).append(row)
        for row in self.trusts.sid_history_candidates():
            key = (row["source"], row["target"], row["type"])
            view.add_edge(*key)
            self._conditional_evidence.setdefault(key, []).append(row)
        self._potential_projection = view
        return view

    def route_graph(self, profile="supported"):
        if profile == "supported": return self.projection
        if profile == "potential": return self.potential_projection
        if profile == "raw": return self.g
        raise ValueError("Unknown path profile")

    def edge(self, source, target, kind):
        self.projection
        if kind in ("PotentialGPOControl", "PotentialSIDHistory"):
            self.potential_projection
            return {"source": source, "target": target, "type": kind, "derived": True,
                    "conditional": True, "verified_access": False,
                    "evidence": self._conditional_evidence.get((source, target, kind), [])}
        proof = self._evidence.get((source, target, kind))
        result = {"source": source, "target": target, "type": kind,
                  "derived": proof is not None}
        if proof:
            memberships = {r["group"]: r["path"] for r in self.memberships(source)}
            result["evidence"] = [dict(row, membership_path=memberships.get(row["source"], [source]))
                                  for row in proof]
        if (source, target, kind) in self.g._collected_evidence:
            result["collection_evidence"] = self.g._collected_evidence[(source, target, kind)]
        return result

    def findings(self, query="all", principal=None):
        if query != "all" and query not in QUERY_CATALOG:
            raise ValueError(f"Unknown findings query: {query}")
        scope = None
        scope_paths = {}
        if principal:
            principal = self.require_node(principal)
            scope_paths = {r["group"]: r["path"] for r in self.memberships(principal)}
            scope = {principal} | scope_paths.keys()
        rows = []
        account_queries = {"kerberoastable": "hasspn", "asrep-roastable": "dontreqpreauth",
                           "unconstrained-delegation": "unconstraineddelegation"}
        for name in sorted(self.g._props):
            if scope is not None and name not in scope:
                continue
            props, node_type = self.g._props[name], self.g.node_type(name)
            if query in ("all", "descriptions") and isinstance(props.get("description"), str) and props["description"].strip():
                rows.append({"query": "descriptions", "subject": name,
                             "evidence": {"description": props["description"]}, "status": "untrusted-directory-text"})
            for category, flag in account_queries.items():
                if query not in ("all", category) or props.get("enabled") is not True:
                    continue
                if node_type not in ({"User", "Computer"} if category == "unconstrained-delegation" else {"User"}):
                    continue
                if props.get(flag) is True:
                    rows.append({"query": category, "subject": name, "evidence": {flag: True, "enabled": True}})
        if query in account_queries:
            for row in rows: row["assessment"] = assess(row, principal)
            return rows
        if query in ("all", "trusts"):
            domains = None
            if principal:
                domains = {principal}
                domain_name = self.g._props.get(principal, {}).get("domain")
                if isinstance(domain_name, str): domains.add(self.g.resolve(domain_name))
            rows.extend(r for r in self.trusts.records() if domains is None or r["local_domain"] in domains or r["target_domain"] in domains)
        if query in ("all", "trust-escalation"):
            rows.extend({"query": "trust-escalation", **r} for r in self.trusts.sid_history_candidates()
                        if scope is None or r["source"] in scope)
        if query in ("all", "gpo-impact"):
            controlled = None
            if scope is not None:
                controlled = {}
                for src, dst, kind in sorted(self.g._edge_set):
                    if src in scope and self.g.node_type(dst) == "GPO" and kind in {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns"}:
                        controlled.setdefault(dst, []).append({**self.edge(src, dst, kind),
                            "membership_path": scope_paths.get(src, [principal])})
            for impact in self.policy.impacts():
                if controlled is None or impact["gpo"] in controlled:
                    row = {"query": "gpo-impact", **impact}
                    if controlled is not None: row["control_evidence"] = controlled[impact["gpo"]]
                    rows.append(row)
        if query in ("all", "gpo-link-control"):
            rows.extend({"query": "gpo-link-control", **self.edge(src, dst, kind)}
                        for src, dst, kind in sorted(self.g._edge_set) if kind == "WriteGPLink" and (scope is None or src in scope))
        for src, dst, kind in sorted(self.projection._edge_set):
            if scope is not None and src not in scope and not (kind == "HasSession" and dst in scope):
                continue
            categories = []
            if kind == "DCSync": categories.append("dcsync")
            if kind == "AdminTo": categories.append("local-admin")
            if kind in {"CanRDP", "CanPSRemote", "ExecuteDCOM"}: categories.append("remote-access")
            if kind == "HasSession": categories.append("sessions")
            if kind in CONTROL_EDGES: categories.append("acl-control")
            if kind in {"AllowedToDelegate", "AllowedToAct"}: categories.append("delegation")
            if kind == "ReadLAPSPassword": categories.append("laps")
            if kind == "ReadGMSAPassword": categories.append("gmsa")
            if kind in CONTROL_EDGES and self.g.node_type(dst) == "GPO": categories.append("gpo-control")
            if kind in CONTROL_EDGES and self.g.is_high_value(dst): categories.append("high-value-control")
            for category in categories:
                if query in ("all", category):
                    row = {"query": category, **self.edge(src, dst, kind)}
                    if src in scope_paths:
                        row["membership_path"] = scope_paths[src]
                    rows.append(row)
        if query in ("all", "adcs"):
            from .certipy_import import reported_findings
            # Certipy assessments refer to its collection context; never claim
            # they were evaluated for a caller-specified principal.
            rows.extend(reported_findings(self.g))
            for src, dst, kind in sorted(self.g._edge_set):
                if scope is not None and src not in scope:
                    continue
                if self.g.node_type(dst) not in {"CertificateTemplate", "EnterpriseCA", "RootCA", "AIACA", "NTAuthStore"}:
                    continue
                if kind in CONTROL_EDGES or kind == "Enroll":
                    rows.append({"query": "adcs", "source": src, "target": dst, "type": kind,
                                 "status": "collected-permission", "membership_path": scope_paths.get(src),
                                 "prerequisites": ["Permission alone does not establish an ESC condition; evaluate template and CA configuration with Certipy."]})
        for row in rows:
            row["assessment"] = assess(row, principal)
        return sorted(rows, key=lambda r: (r["query"], r.get("subject", r.get("source", "")), r.get("target", ""), r.get("type", "")))

    def coverage(self):
        return {"profile": "supported-ad-v1", "full_bloodhound_parity": False,
                "access_semantics": "Graph possibility, never verified access; use handoff for one lead and next verification question",
                "live_overlay": "Session-local trusted Python API only; model-facing updates are rejected",
                "object_queries": "Exact typed property filters with selected property output",
                "derived_rules": ["DCSync: GetChanges + GetChangesAll, including nested membership"],
                "excluded_route_edges": sorted(CONTEXT_EDGES),
                "adcs": "Certipy JSON assessment import and native AD CS object inspection; no ESC derivation",
                "ranked_paths": "Optional NetworkX shortest_simple_paths",
                "policy": "GPO link scope, enforcement, blocked inheritance, section flags and collected GPOChanges rights",
                "trusts": "Directional authentication relationships, receiver flags and conditional same-forest SID-history candidates",
                "potential_profile": "Opt-in conditional GPO-to-computer and same-forest SID-history routes",
                "unsupported_analysis": ["Independent AD CS/ESC derivation", "Azure/Entra", "Full GPO RSoP/security/WMI evaluation",
                    "Automatic cross-forest exploitation inference", "full BloodHound post-processing", "live exploit verification"],
                "queries": QUERY_CATALOG}
