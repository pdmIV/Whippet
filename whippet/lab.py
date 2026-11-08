"""HTB-oriented routes and relationship explanations. No live operations."""
from collections import deque


GUIDANCE = {
    "CanAuthenticateTo": ("Directional trust authentication relationship", ["This does not grant resource access or domain control; evaluate receiving-domain selective authentication and authorization."]),
    "WriteGPLink": ("Modify GPO links on a container", ["Control or create a suitable GPO; validate link settings, inheritance and target filtering."]),
    "PotentialGPOControl": ("Conditional GPO-to-computer influence", ["Control the source GPO; verify enabled sections, SYSVOL rights, security/WMI filtering, refresh and actual target processing."]),
    "PotentialSIDHistory": ("Conditional same-forest SID-history escalation", ["Control the source domain; verify receiver-side filtering, target privilege SID and selective authentication."]),
    "MemberOf": ("Effective group membership", ["Verify the current logon token or refreshed authentication includes this group."]),
    "GenericAll": ("Full control over the target object", ["Choose a technique appropriate to the target type; full control of a GPO/template is not immediate host/domain control."]),
    "GenericWrite": ("Write selected target attributes", ["Inspect writable attributes and target type; this does not grant arbitrary password resets."]),
    "WriteDacl": ("Modify the target DACL", ["Verify effective ACLs and inheritance before choosing a new permission."]),
    "WriteOwner": ("Change target ownership", ["Verify ownership and resulting DACL permissions; ownership restrictions can affect the next step."]),
    "Owns": ("Own the target object", ["Verify effective WRITE_DAC rights and any owner-rights restrictions."]),
    "ForceChangePassword": ("Reset a target user's password", ["A reset changes account state; verify target identity and access consequences."]),
    "AddMember": ("Modify group membership", ["Verify membership-write rights and refresh authentication after a membership change."]),
    "AddSelf": ("Add the acting principal to a group", ["Validated self-membership rights do not imply arbitrary membership modification."]),
    "AddKeyCredentialLink": ("Potential shadow credentials", ["Verify msDS-KeyCredentialLink write access, target type, DC PKINIT support and certificate prerequisites."]),
    "WriteSPN": ("Write service principal names", ["Verify the target and effective SPN-write rights; assess authentication and ticket prerequisites."]),
    "AddAllowedToAct": ("Configure resource-based constrained delegation", ["Verify target attribute rights and control of a suitable service principal."]),
    "WriteAccountRestrictions": ("Write account restriction attributes", ["Inspect exact attribute permissions; confirm RBCD applicability rather than assuming full control."]),
    "AllowedToAct": ("Resource-based constrained delegation configuration", ["Control the source service identity; verify target service and impersonation restrictions."]),
    "AllowedToDelegate": ("Constrained delegation configuration", ["Control the source service identity; verify protocol transition, allowed SPNs, target services and protected-user restrictions."]),
    "ReadLAPSPassword": ("Read managed local administrator credentials", ["Verify attribute readability, password freshness and any Windows LAPS decryption requirement."]),
    "ReadGMSAPassword": ("Read a gMSA managed password", ["Verify effective msDS-GroupMSAMembership authorization and current password retrieval."]),
    "DCSync": ("Replication credential access", ["Verify both replication rights on the same domain and effective authenticated identity."]),
    "AdminTo": ("Local administrative access", ["Verify reachable services, local token filtering and the current credential's authentication ability."]),
    "CanPSRemote": ("Potential WinRM access", ["Verify WinRM reachability, endpoint authorization and valid credentials."]),
    "CanRDP": ("Potential RDP access", ["Verify RDP reachability, logon rights and any deny policies."]),
    "ExecuteDCOM": ("Potential DCOM access", ["Verify RPC reachability and applicable launch/access permissions."]),
    "HasSession": ("A user session was observed on a computer", ["Control the source computer first; check session freshness and credential/token protections."]),
    "GPLink": ("GPO linkage", ["Evaluate link state, inheritance, security/WMI filtering and actual affected objects."]),
    "Contains": ("Directory containment", ["Containment alone does not grant control of the child."]),
    "TrustedBy": ("Collected trust relationship", ["Inspect trust direction/type, SID filtering, selective authentication and transitivity."]),
    "Enroll": ("Certificate enrollment permission", ["Enrollment alone is not escalation; verify template flags, publication and CA enrollment permissions."]),
}


def explain(analysis, source, target, kind):
    source, target = analysis.require_node(source), analysis.require_node(target)
    if (target, kind) not in analysis.g.neighbors(source) and (target, kind) not in analysis.potential_projection.neighbors(source):
        raise ValueError("No collected or derived relationship matches that source, target and type")
    meaning, prerequisites = GUIDANCE.get(kind, ("Collected relationship", ["Verify this relationship's target-specific prerequisites."]))
    return {**analysis.edge(source, target, kind), "meaning": meaning,
            "prerequisites": prerequisites, "verified_access": False,
            "reference": "https://bloodhound.specterops.io/resources/edges"}


def routes(analysis, sources, target=None, hops=6, avoid=(), profile="supported"):
    """Multi-source BFS: one shortest supported route per target."""
    if not sources or hops < 0:
        raise ValueError("routes requires at least one owned source and nonnegative hops")
    sources = sorted({analysis.require_node(n) for n in sources})
    avoid = {analysis.require_node(n) for n in avoid}
    if avoid.intersection(sources):
        raise ValueError("An owned source cannot also be avoided")
    targets = [analysis.require_node(target)] if target else sorted(analysis.g.high_value_targets())
    parent, distance, origins = {s: None for s in sources}, {s: 0 for s in sources}, {s: s for s in sources}
    queue, view = deque(sources), analysis.route_graph(profile)
    while queue:
        node = queue.popleft()
        if distance[node] >= hops:
            continue
        for neighbor, kind in sorted(view.neighbors(node)):
            if neighbor in parent or neighbor in avoid:
                continue
            parent[neighbor], distance[neighbor], origins[neighbor] = (node, kind), distance[node] + 1, origins[node]
            queue.append(neighbor)
    rows = []
    for target in targets:
        if target not in parent:
            continue
        edges, node = [], target
        while parent[node] is not None:
            previous, kind = parent[node]
            edges.append(analysis.edge(previous, node, kind))
            node = previous
        rows.append({"source": origins[target], "target": target, "hops": distance[target], "edges": list(reversed(edges))})
    return sorted(rows, key=lambda r: (r["hops"], r["target"], r["source"]))
