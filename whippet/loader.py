"""
whippet.loader — SharpHound v1/v2 JSON → ADGraph ingestion.
"""
from __future__ import annotations

import json
import zipfile
from collections import Counter
from pathlib import Path

from .constants import EDGE_TYPES
from .graph import ADGraph
from .certipy_import import is_certipy, import_certipy
from .policy import value
from .trusts import normalize


# ══════════════════════════════════════════════════════════════════════════════
#  SharpHound loader
# ══════════════════════════════════════════════════════════════════════════════

class SharpHoundLoader:
    """
    Parse SharpHound v1/v2 JSON into an ADGraph.

    SharpHound's JSON relationship model:
        Users / Computers / Groups   → Aces[]  (ACL edges)
        Groups                       → Members[] (MemberOf edges)
        Computers                    → Sessions[] (HasSession edges)
        Computers                    → LocalAdmins[], RemoteDesktopUsers[], etc.
        Computers                    → AllowedToDelegate[]
        Users                        → AllowedToDelegate[]
        Domains                      → Trusts[], Aces[]
    """

    def __init__(self, graph: ADGraph):
        self.g = graph
        self.warnings: list[str] = []
        self._unsupported_rights = Counter()

    def load(self, path: str):
        self.load_many([path])

    def load_many(self, paths):
        """Register all input objects before resolving cross-input references."""
        docs = []
        for path in paths:
            docs.extend(self._read_path(path))
        self._ingest(docs)
        self.g.reconcile_edges()
        if self._unsupported_rights:
            self.warnings.append("Unsupported ACL rights skipped: " + ", ".join(
                f"{right} ({count})" for right, count in sorted(self._unsupported_rights.items())))
            self._unsupported_rights.clear()

    def _read_path(self, path: str):
        p = Path(path)
        if not p.exists():
            raise ValueError(f"Input does not exist: {p}")
        docs: list[tuple[str, dict]] = []
        if p.suffix.lower() == ".zip":
            docs = self._read_zip(p)
        elif p.is_dir():
            for f in sorted(f for f in p.iterdir() if f.is_file() and f.suffix.lower() == ".json"):
                docs += self._read_file(f)
        elif p.suffix.lower() == ".json":
            docs = self._read_file(p)
        else:
            raise ValueError(f"Unsupported input (expected ZIP, JSON or directory): {p}")
        return docs

    def _read_zip(self, zp: Path) -> list[tuple[str, dict]]:
        out = []
        with zipfile.ZipFile(zp) as zf:
            for name in zf.namelist():
                if name.lower().endswith(".json") and not name.startswith("__MACOSX"):
                    with zf.open(name) as f:
                        try:
                            out.append((f"{zp.resolve()}/{name}", json.load(f)))
                        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                            raise ValueError(f"Invalid JSON in {zp}:{name}: {exc}") from exc
        return out

    def _read_file(self, fp: Path) -> list[tuple[str, dict]]:
        with open(fp, encoding="utf-8-sig") as f:
            try:
                return [(str(fp.resolve()), json.load(f))]
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ValueError(f"Invalid JSON in {fp}: {exc}") from exc

    @staticmethod
    def _items_of(data: dict) -> list:
        """
        Locate the object array inside one SharpHound file. Modern SharpHound /
        BloodHound CE nest it under "data" (or "nodes"); legacy meta-version-3
        output keys it by the object-type name instead, e.g.
        {"users": [...], "meta": {"type": "users", "version": 3}}. Fall back to
        the first top-level list so an unrecognized wrapper still ingests.
        """
        if not isinstance(data, dict):
            return []
        items = data.get("data")
        if items is None:
            items = data.get("nodes")
        if items is None:
            meta_type = (data.get("meta") or {}).get("type")
            if meta_type:
                items = data.get(meta_type)
        if items is None:
            items = next((v for k, v in data.items()
                          if k != "meta" and isinstance(v, list)), None)
        return items or []

    # File-name → (object type tag, edge parser).
    def _dispatch(self, filename: str):
        kind = Path(filename).stem.lower().rsplit("_", 1)[-1]
        parsers = {
            "certtemplate": ("CertificateTemplate", self._edges_generic),
            "enterpriseca": ("EnterpriseCA", self._edges_generic),
            "rootca": ("RootCA", self._edges_generic),
            "aiaca": ("AIACA", self._edges_generic),
            "ntauthstore": ("NTAuthStore", self._edges_generic),
            "user": ("User", self._edges_user),
            "computer": ("Computer", self._edges_computer),
            "group": ("Group", self._edges_group),
            "domain": ("Domain", self._edges_domain),
            "gpo": ("GPO", self._edges_generic),
            "container": ("Container", self._edges_generic),
            "ou": ("OU", self._edges_generic),
        }
        return parsers.get(kind.rstrip("s"), (None, None))

    def _ingest(self, docs: list[tuple[str, dict]]):
        """
        Two-pass ingestion. SharpHound splits objects across files with
        cross-file references (e.g. computers.json cites group SIDs defined
        only in groups.json). Resolving SIDs eagerly during a single pass
        would leave any forward reference stuck as a raw SID — splitting one
        principal into two graph nodes. So we register every node first, then
        add edges once the SID→name table is complete.
        """
        parsed = []
        for filename, data in docs:
            if is_certipy(data):
                import_certipy(self.g, data, filename)
                continue
            if not isinstance(data, dict) or not isinstance(data.get("meta", {}), dict):
                raise ValueError(f"Invalid SharpHound document: {filename}")
            # Prefer collector metadata; archive directory names may contain
            # misleading substrings such as 'users' or 'groups'.
            kind = data.get("meta", {}).get("type")
            node_type, edger = self._dispatch(str(kind) if kind else Path(filename).name)
            if edger is None:
                self.warnings.append(f"Unsupported object type skipped: {filename}")
                continue
            items = self._items_of(data)
            if not isinstance(items, list) or any(not isinstance(i, dict) for i in items):
                raise ValueError(f"Expected object array in {filename}")
            for item in items:
                if not isinstance(item.get("Properties", {}), dict):
                    raise ValueError(f"Invalid Properties in {filename}")
                props = item.get("Properties", {})
                if not isinstance(props.get("name", ""), str) or not isinstance(
                        props.get("objectid") or item.get("ObjectIdentifier", ""), str):
                    raise ValueError(f"Invalid name or object identifier in {filename}")
                for key in ("Aces", "Members", "AllowedToDelegate", "AllowedToAct",
                            "HasSIDHistory", "Trusts", "Links", "ChildObjects", "LocalGroups", "Users", "Computers", "ChildOus"):
                    if item.get(key) is None:
                        item[key] = []
                    if not isinstance(item[key], list):
                        raise ValueError(f"Invalid {key} array in {filename}")
                for key in ("Aces", "Trusts", "Links", "LocalGroups"):
                    if any(not isinstance(v, dict) for v in item[key]):
                        raise ValueError(f"Invalid {key} entry in {filename}")
                for ace in item["Aces"]:
                    if any(not isinstance(ace.get(k) or "", str)
                           for k in ("RightName", "AceType", "PrincipalSID")):
                        raise ValueError(f"Invalid ACE fields in {filename}")
                for group in item["LocalGroups"]:
                    rows = group.get("Results") or []
                    if not isinstance(rows, list):
                        raise ValueError(f"Invalid LocalGroups results in {filename}")
                for key in ("Sessions", "PrivilegedSessions", "RegistrySessions",
                            "LocalAdmins", "RemoteDesktopUsers", "PSRemoteUsers", "DcomUsers"):
                    value = item.get(key) or []
                    rows = value.get("Results") or [] if isinstance(value, dict) else value
                    if not isinstance(rows, list) or any(not isinstance(v, dict) for v in rows):
                        raise ValueError(f"Invalid {key} results in {filename}")
            parsed.append((node_type, edger, items))

        # Pass 1 — register nodes (populate SID resolution table).
        for node_type, _edger, items in parsed:
            for item in items:
                self._add_obj(item, node_type)

        # Pass 2 — add edges, now that every SID resolves.
        for _node_type, edger, items in parsed:
            for item in items:
                edger(item)

    # ── Per-type parsers ──────────────────────────────────────────────────────

    def _add_obj(self, item: dict, node_type: str = "") -> str | None:
        props = item.get("Properties", {})
        name  = props.get("name", "")
        if not name:
            return None
        # SID location differs by format: SharpHound v2 / BloodHound CE (meta
        # version 5/6) carries it at the top level as "ObjectIdentifier";
        # legacy output put it in Properties.objectid. Normalize to objectid so
        # the graph's SID→name resolution table is populated either way.
        sid = props.get("objectid") or item.get("ObjectIdentifier", "")
        if sid and not props.get("objectid"):
            props = {**props, "objectid": sid}
        if node_type == "Domain":
            props = {**props, "trusts": item.get("Trusts") or []}
        if node_type in ("Domain", "OU", "Container"):
            props = {**props, "gpo_links": item.get("Links") or [],
                     "gpo_changes": item.get("GPOChanges") or {}}
            if "BlocksInheritance" in item:
                props["blocksinheritance"] = item["BlocksInheritance"]
        return self.g.add_node(name, props, node_type=node_type)

    # Legacy SharpHound v3 ACE vocabulary → BloodHound edge names. v3 emits
    # "Owner"/"ExtendedRight" where modern output emits "Owns" and the resolved
    # extended-right name; for ExtendedRight the specific right is in AceType.
    _EXTENDED_RIGHT_EDGES = {
        "all":                            "AllExtendedRights",
        "user-force-change-password":     "ForceChangePassword",
        "ds-replication-get-changes":     "GetChanges",
        "ds-replication-get-changes-all": "GetChangesAll",
    }

    def _normalize_right(self, right: str, ace_type: str) -> str:
        if right == "Owner":
            return "Owns"
        if right == "ExtendedRight":
            return self._EXTENDED_RIGHT_EDGES.get((ace_type or "").lower(),
                                                  "")
        return right

    def _add_aces(self, src: str, aces: list):
        for ace in aces or []:
            right = self._normalize_right(ace.get("RightName", ""),
                                          ace.get("AceType", ""))
            if right not in EDGE_TYPES:
                self._unsupported_rights[str(ace.get("RightName", ""))] += 1
                continue
            principal_sid = ace.get("PrincipalSID", "")
            principal     = self.g.resolve(principal_sid) or principal_sid
            if principal:
                # ACE direction: principal → src (principal has right over src)
                self.g.add_edge(principal, src, right)

    def _resolve_target(self, ref) -> str:
        if ref is None:
            return ""
        if isinstance(ref, dict):
            # v3 group members / local-group entries use MemberId; sessions UserId.
            sid  = (ref.get("ObjectIdentifier") or ref.get("MemberId")
                    or ref.get("UserId") or "")
            name = ref.get("Name", "")
            if not isinstance(sid, str) or not isinstance(name, str):
                raise ValueError("Invalid relationship identifier or name")
            return self.g.resolve(sid) or name or sid
        if not isinstance(ref, str):
            raise ValueError("Relationship reference must be an object or string")
        return self.g.resolve(ref)

    def _name_of(self, item: dict) -> str | None:
        """
        Edge source: the object's own node_id, as assigned during pass 1.

        Resolving via the object's SID/GUID (rather than re-uppercasing its
        display name) matters when two distinct objects share a name — e.g.
        the built-in "Users" group and the "CN=Users" container both render
        as "USERS@DOMAIN". add_node() gave the second one a disambiguated id;
        looking it up by SID here gets that same id back, so this object's
        edges land on the right node instead of merging with the other one.
        """
        props = item.get("Properties", {})
        name = props.get("name", "")
        if not name:
            return None
        sid = props.get("objectid") or item.get("ObjectIdentifier", "")
        if sid:
            nid = self.g.id_for_sid(sid)
            if nid:
                return nid
        return name.upper()

    # Well-known local group RID → BloodHound edge, for SharpHound v2's unified
    # LocalGroups[] (replaces the legacy LocalAdmins/RemoteDesktopUsers/… arrays).
    _LOCAL_GROUP_EDGES = {
        "544": "AdminTo",       # Administrators
        "555": "CanRDP",        # Remote Desktop Users
        "562": "ExecuteDCOM",   # Distributed COM Users
        "580": "CanPSRemote",   # Remote Management Users
    }

    def _edges_user(self, item: dict):
        src = self._name_of(item)
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))
        if item.get("PrimaryGroupSID"):
            self.g.add_edge(src, self.g.resolve(item["PrimaryGroupSID"]), "MemberOf")

        # Constrained delegation targets
        for tgt in item.get("AllowedToDelegate", []):
            t = self._resolve_target(tgt)
            if t:
                self.g.add_edge(src, t, "AllowedToDelegate")

        # SID history
        for sid in item.get("HasSIDHistory", []):
            t = self._resolve_target(sid)
            if t:
                self.g.add_edge(src, t, "HasSIDHistory")

    def _edges_computer(self, item: dict):
        src = self._name_of(item)
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))
        if item.get("PrimaryGroupSID"):
            self.g.add_edge(src, self.g.resolve(item["PrimaryGroupSID"]), "MemberOf")

        # BloodHound HasSession direction is computer -> user.
        for key in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
            sessions = item.get(key) or []
            if isinstance(sessions, dict):
                sessions = sessions.get("Results") or []
            for sess in sessions:
                user_sid = sess.get("UserSID") or sess.get("UserId") or ""
                user = self.g.resolve(user_sid)
                if user:
                    self.g.add_edge(src, user, "HasSession")

        # Legacy (SharpHound v1) local-membership arrays.
        for rel_key, rel_type in [
            ("LocalAdmins",          "AdminTo"),
            ("RemoteDesktopUsers",   "CanRDP"),
            ("PSRemoteUsers",        "CanPSRemote"),
            ("DcomUsers",            "ExecuteDCOM"),
        ]:
            rel = item.get(rel_key, {})
            results = rel.get("Results", []) if isinstance(rel, dict) else rel
            for entry in (results or []):
                t = self._resolve_target(entry)
                if t:
                    self.g.add_edge(t, src, rel_type)

        # SharpHound v2 unified LocalGroups[] — keyed by the local group's RID.
        for grp in (item.get("LocalGroups") or []):
            oid = str(grp.get("ObjectIdentifier", ""))
            rel_type = self._LOCAL_GROUP_EDGES.get(oid.rsplit("-", 1)[-1])
            if not rel_type:
                continue
            for entry in (grp.get("Results") or []):
                t = self._resolve_target(entry)
                if t:
                    self.g.add_edge(t, src, rel_type)

        # Constrained delegation
        for tgt in item.get("AllowedToDelegate", []):
            t = self._resolve_target(tgt)
            if t:
                self.g.add_edge(src, t, "AllowedToDelegate")

        # Resource-based constrained delegation
        for tgt in item.get("AllowedToAct", []):
            t = self._resolve_target(tgt)
            if t:
                self.g.add_edge(t, src, "AllowedToAct")

    def _edges_group(self, item: dict):
        src = self._name_of(item)
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))
        for member in item.get("Members", []):
            t = self._resolve_target(member)
            if t:
                self.g.add_edge(t, src, "MemberOf")

    def _edges_domain(self, item: dict):
        src = self._name_of(item)
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))
        for trust in item.get("Trusts", []):
            row = normalize(self.g, src, trust)
            for flow in row["authentication_flows"]:
                self.g.add_edge(flow["source"], flow["target"], "CanAuthenticateTo")
        self._edges_containment(src, item)

    # GPLink (Links[]) and Contains (ChildObjects[]) — shared by Domain / OU /
    # Container objects. GPOs carry neither field, so calling this on a GPO
    # item is a harmless no-op. Without this, GPO-abuse paths (take over a
    # GPO → it's linked to an OU/domain → that OU/domain contains a target
    # user/computer) are invisible even though "GPLink"/"Contains" are already
    # declared in EDGE_TYPES.
    def _edges_containment(self, src: str, item: dict):
        for link in item.get("Links", []) or []:
            guid = value(link, "GUID", "ObjectIdentifier") or ""
            gpo = self.g.resolve(guid) or guid
            if gpo:
                # The GPO applies its settings TO the OU/domain it's linked to.
                self.g.add_edge(gpo, src, "GPLink")
        for child in item.get("ChildObjects", []) or []:
            t = self._resolve_target(child)
            if t:
                self.g.add_edge(src, t, "Contains")
        # Legacy collectors split containment by object type.
        for key in ("Users", "Computers", "ChildOus"):
            for child in item.get(key) or []:
                t = self._resolve_target(child)
                if t:
                    self.g.add_edge(src, t, "Contains")
        changes = item.get("GPOChanges") or {}
        if not isinstance(changes, dict):
            raise ValueError("GPOChanges must be an object")
        computers = changes.get("AffectedComputers") or []
        if not isinstance(computers, list):
            raise ValueError("GPOChanges AffectedComputers must be an array")
        for key, kind in (("LocalAdmins", "AdminTo"), ("RemoteDesktopUsers", "CanRDP"),
                          ("DcomUsers", "ExecuteDCOM"), ("PSRemoteUsers", "CanPSRemote")):
            principals = changes.get(key) or []
            if not isinstance(principals, list):
                raise ValueError(f"GPOChanges {key} must be an array")
            for principal in principals:
                p = self._resolve_target(principal)
                for computer in computers:
                    c = self._resolve_target(computer)
                    if not p or not c:
                        continue
                    self.g.add_edge(p, c, kind)
                    proof = {"container": src, "collector_field": f"GPOChanges.{key}",
                             "principal": principal, "affected_computer": computer}
                    evidence = self.g._collected_evidence.setdefault((p.upper(), c.upper(), kind), [])
                    if proof not in evidence:
                        evidence.append(proof)

    def _edges_generic(self, item: dict):
        src = self._name_of(item)
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))
        self._edges_containment(src, item)
