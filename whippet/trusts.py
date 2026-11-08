"""Directional trust interpretation with receiver-side boundary checks."""
from collections import deque

from .policy import value, flag


def direction_of(record):
    raw = value(record, "TrustDirection", "Direction")
    if type(raw) is int and raw in (0, 1, 2, 3):
        return raw
    if isinstance(raw, str):
        return {"inbound": 1, "incoming": 1, "outbound": 2, "outgoing": 2,
                "bidirectional": 3, "both": 3, "disabled": 0,
                "0": 0, "1": 1, "2": 2, "3": 3}.get(raw.lower())
    return None


def normalize(graph, local, record):
    target = value(record, "TargetDomainSid", "TargetDomainSID") or value(record, "TargetDomainName")
    if target is not None and not isinstance(target, str):
        raise ValueError("Trust target must be a domain name or SID string")
    target = graph.resolve(target or "")
    name = value(record, "TargetDomainName")
    # Prefer a loaded domain name when only a name resolves but a SID does not.
    if graph.node_type(target) != "Domain" and isinstance(name, str) and graph.node_type(name) == "Domain":
        target = graph.resolve(name)
    direction = direction_of(record)
    trust_type = value(record, "TrustType")
    # Legacy collector exports use the .NET TrustType enum, not LDAP's
    # raw trustType attribute (e.g. numeric 4 is Forest, not Unknown).
    labels = {0: "TreeRoot", 1: "ParentChild", 2: "CrossLink", 3: "External",
              4: "Forest", 5: "Kerberos", 6: "Unknown"}
    if isinstance(trust_type, str) and trust_type.isdecimal():
        trust_type = int(trust_type)
    if type(trust_type) is int:
        trust_type = labels.get(trust_type, "Unknown")
    trust_type = trust_type if isinstance(trust_type, str) else "Unknown"
    attributes = value(record, "TrustAttributes")
    if type(attributes) is not int or attributes < 0:
        attributes = None
    same_forest = flag(record, "WithinForest", "IsWithinForest")
    if same_forest is None and attributes is not None:
        same_forest = bool(attributes & 0x20)
    if same_forest is None and trust_type.lower() in ("treeroot", "parentchild", "crosslink", "shortcut", "sameforest", "intraforest"):
        same_forest = True
    if same_forest is None and trust_type.lower() in ("forest", "external"):
        same_forest = False
    filtering = flag(record, "SidFilteringEnabled", "SIDFilteringEnabled")
    selective = flag(record, "SelectiveAuthentication", "SelectiveAuthenticationEnabled")
    transitive = flag(record, "IsTransitive", "Transitive")
    if selective is None and attributes is not None:
        selective = bool(attributes & 0x10)
    if filtering is None and attributes is not None and attributes & 0x4:
        filtering = True  # Absence of quarantine does not prove filtering off.
    if transitive is None and attributes is not None and attributes & 0x1:
        transitive = False
    conflicts = []
    if same_forest is True and trust_type.lower() in ("forest", "external"):
        same_forest = None
        conflicts.append("Within-forest evidence conflicts with cross-forest/external classification")
    if attributes is not None:
        if attributes & 0x4 and filtering is False:
            filtering = True
            conflicts.append("Explicit SID-filter flag conflicts with quarantined trust attribute")
        if attributes & 0x10 and selective is False:
            selective = True
            conflicts.append("Explicit selective-auth flag conflicts with cross-organization attribute")
        if attributes & 0x1 and transitive is True:
            transitive = False
            conflicts.append("Explicit transitive flag conflicts with non-transitive attribute")
    flows = []
    if target:
        if direction in (1, 3): flows.append({"source": local, "target": target})
        if direction in (2, 3): flows.append({"source": target, "target": local})
    return {"local_domain": local, "target_domain": target, "direction": direction,
            "direction_name": {0: "disabled", 1: "inbound", 2: "outbound", 3: "bidirectional"}.get(direction, "unknown"),
            "trust_type": trust_type, "same_forest": same_forest,
            "sid_filtering_on_local_receiver": filtering,
            "selective_authentication_on_local_receiver": selective,
            "transitive": transitive, "authentication_flows": flows,
            "configuration_conflicts": conflicts, "evidence": record}


class TrustAnalyzer:
    def __init__(self, graph):
        self.g = graph
        self._rows = None

    def records(self):
        if self._rows is None:
            rows = []
            for local, props in sorted(self.g._props.items()):
                if self.g.node_type(local) != "Domain":
                    continue
                for raw in props.get("trusts", []):
                    row = normalize(self.g, local, raw)
                    conditions = list(row["configuration_conflicts"])
                    if row["direction"] is None: conditions.append("Trust direction missing or unsupported; no authentication direction inferred")
                    if row["same_forest"] is None: conditions.append("Forest boundary unknown")
                    if row["sid_filtering_on_local_receiver"] is None: conditions.append("Receiver SID filtering unknown")
                    if row["selective_authentication_on_local_receiver"] is None: conditions.append("Receiver selective authentication unknown")
                    if row["selective_authentication_on_local_receiver"] is True: conditions.append("Allowed-to-authenticate permission on the destination resource is required")
                    if row["transitive"] is None: conditions.append("Transitivity unknown; not used for multi-hop inference")
                    row.update(query="trusts", subject=local, status="interpreted-configuration",
                               unknowns=conditions, verified_access=False)
                    rows.append(row)
            self._rows = rows
        return self._rows

    def flows(self):
        rows = []
        for record in self.records():
            for flow in record["authentication_flows"]:
                is_receiver = flow["target"] == record["local_domain"]
                rows.append({**flow, "same_forest": record["same_forest"],
                             "transitive": record["transitive"], "record": record,
                             "receiver_record_collected": is_receiver,
                             "receiver_flags_known": is_receiver and record["sid_filtering_on_local_receiver"] is not None
                                 and record["selective_authentication_on_local_receiver"] is not None,
                             "sid_filtering": record["sid_filtering_on_local_receiver"] if is_receiver else None,
                             "selective_authentication": record["selective_authentication_on_local_receiver"] if is_receiver else None})
        return sorted(rows, key=lambda r: (r["source"], r["target"], not r["receiver_flags_known"]))

    def paths(self, source, target):
        source, target = self.g.resolve(source), self.g.resolve(target)
        if self.g.node_type(source) != "Domain" or self.g.node_type(target) != "Domain":
            raise ValueError("trust-path requires two loaded Domain objects")
        # Track both arrival and transit eligibility. A nontransitive shortcut
        # must not hide a longer same-forest transitive route to the same node.
        queue = deque([(source, [], {source})])
        seen = {(source, True)}
        flows = self.flows()
        while queue:
            node, path, visited = queue.popleft()
            if node == target:
                return {"source": source, "target": target, "found": True, "steps": path,
                        "semantics": "Authentication relationship path; not resource authorization or domain compromise",
                        "verified_access": False}
            for flow in flows:
                if flow["source"] != node or flow["target"] in visited:
                    continue
                can_transit = flow["same_forest"] is True and flow["transitive"] is True
                if flow["target"] != target and not can_transit:
                    continue
                # Every link in a multi-hop inference must be same-forest and
                # explicitly transitive, including the final link.
                if path and not can_transit:
                    continue
                state = (flow["target"], can_transit)
                if state in seen:
                    continue
                seen.add(state)
                queue.append((flow["target"], path + [flow], visited | {flow["target"]}))
        return {"source": source, "target": target, "found": False, "steps": [],
                "semantics": "No direct or explicitly same-forest transitive authentication path in collected data",
                "verified_access": False}

    def sid_history_candidates(self):
        rows = []
        for flow in self.flows():
            # Only receiver-side explicit evidence supports this conditional
            # same-forest technique. An outbound attack needs the other TDO.
            if flow["same_forest"] is not True or flow["sid_filtering"] is not False:
                continue
            if flow["record"]["configuration_conflicts"]:
                continue
            if self.g.node_type(flow["source"]) != "Domain" or self.g.node_type(flow["target"]) != "Domain":
                continue
            rows.append({"source": flow["source"], "target": flow["target"],
                         "type": "PotentialSIDHistory", "conditional": True, "derived": True,
                         "evidence": flow["record"]["evidence"],
                         "prerequisites": ["Control of the source domain and suitable signing/forging material",
                             "Verify destination privilege SID and actual receiver SID filtering",
                             "Evaluate selective authentication and target-resource authorization"],
                         "verified_access": False})
        return rows
