"""
whippet.loader — SharpHound v1/v2 JSON → ADGraph ingestion.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Callable

from .constants import EDGE_TYPES
from .graph import ADGraph


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

    Loading is two-pass and therefore order-independent. Edges reference other
    objects by SID, and SID→name resolution (ADGraph.resolve) only works once
    the referenced object's node has been registered (ADGraph.add_node). A
    typical SharpHound dump sorts as computers, domains, groups, users — so
    groups, whose Members[] point at user SIDs, would otherwise be parsed
    before those users exist, leaving each membership edge stuck on a raw SID
    while the same principal is later added under its real name. That splits one
    principal into two disconnected identities and silently breaks attack-path
    traversal through group membership.

    To stay independent of file ordering, pass 1 registers every node across
    every file (populating the SID→name map); pass 2 then builds all edges, by
    which point every referenced SID resolves.
    """

    def __init__(self, graph: ADGraph):
        self.g = graph

    def load(self, path: str):
        p = Path(path)
        docs: list[tuple[str, dict]] = []
        if p.suffix.lower() == ".zip":
            docs = self._read_zip(p)
            raw = self._read_zip(p)
        elif p.is_dir():
            raw = []
            for f in sorted(p.glob("*.json")):
                docs += self._read_file(f)
        elif p.suffix.lower() == ".json":
            docs = self._read_file(p)
        self._ingest(docs)

    def _read_zip(self, zp: Path) -> list[tuple[str, dict]]:
        out = []
                rec = self._read_file(f)
                if rec:
                    raw.append(rec)
        elif p.suffix.lower() == ".json":
            rec = self._read_file(p)
            raw = [rec] if rec else []
        else:
            raw = []
        self._ingest(raw)

    # ── Raw reading (no graph mutation yet) ───────────────────────────────────

    def _read_zip(self, zp: Path) -> list[tuple[str, dict]]:
        raw: list[tuple[str, dict]] = []
        with zipfile.ZipFile(zp) as zf:
            for name in zf.namelist():
                if name.endswith(".json") and not name.startswith("__MACOSX"):
                    with zf.open(name) as f:
                        try:
                            out.append((name, json.load(f)))
                        except json.JSONDecodeError:
                            pass
        return out

    def _read_file(self, fp: Path) -> list[tuple[str, dict]]:
        with open(fp, encoding="utf-8") as f:
            try:
                return [(fp.name, json.load(f))]
            except json.JSONDecodeError:
                return []

    # File-name → (object type tag, edge parser). Node type "" for GPO/OU/generic.
    def _dispatch(self, filename: str):
        fname = filename.lower()
        if   "user"     in fname: return "User",     self._edges_user
        elif "computer" in fname: return "Computer", self._edges_computer
        elif "group"    in fname: return "Group",    self._edges_group
        elif "domain"   in fname: return "Domain",   self._edges_domain
        elif "gpo"      in fname: return "",          self._edges_generic
        elif "ou"       in fname: return "",          self._edges_generic
        return None, None

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
            node_type, edger = self._dispatch(filename)
            if edger is None:
                continue
            items = data.get("data") or data.get("nodes") or []
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
                            raw.append((name, json.load(f)))
                        except json.JSONDecodeError:
                            pass
        return raw

    def _read_file(self, fp: Path) -> tuple[str, dict] | None:
        with open(fp, encoding="utf-8") as f:
            try:
                return (fp.name, json.load(f))
            except json.JSONDecodeError:
                return None

    # ── Two-pass ingestion ────────────────────────────────────────────────────

    def _ingest(self, raw: list[tuple[str, dict]]):
        """
        Pass 1 registers every node (and its SID→name mapping) across all files;
        pass 2 builds every edge — so resolution no longer depends on the order
        the files happened to be read in.
        """
        sources = []  # (items, node_type, edge_parser)
        for filename, data in raw:
            cls = self._classify(filename)
            if cls is None:
                continue
            node_type, edge_parser = cls
            items = data.get("data") or data.get("nodes") or []
            sources.append((items, node_type, edge_parser))

        # Pass 1 — nodes only (registers every SID→name mapping).
        for items, node_type, _ in sources:
            for item in items:
                self._add_obj(item, node_type)

        # Pass 2 — edges only (every SID now resolves).
        for items, _, edge_parser in sources:
            for item in items:
                edge_parser(item)

    def _classify(self, filename: str) -> tuple[str, Callable[[dict], None]] | None:
        """Map a SharpHound filename to its (node_type, edge_parser)."""
        fname = filename.lower()
        if   "user"     in fname: return ("User",     self._edges_user)
        elif "computer" in fname: return ("Computer", self._edges_computer)
        elif "group"    in fname: return ("Group",    self._edges_group)
        elif "domain"   in fname: return ("Domain",   self._edges_domain)
        elif "gpo"      in fname: return ("",         self._edges_generic)
        elif "ou"       in fname: return ("",         self._edges_generic)
        return None

    # ── Node / edge helpers ────────────────────────────────────────────────────

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
        self.g.add_node(name, props, node_type=node_type)
        return name.upper()

    def _src_name(self, item: dict) -> str | None:
        """The upper-cased name of the object an edge originates from."""
        name = item.get("Properties", {}).get("name", "")
        return name.upper() if name else None

    def _add_aces(self, src: str, aces: list):
        for ace in aces:
            right = ace.get("RightName", "")
            if right not in EDGE_TYPES:
                continue
            principal_sid = ace.get("PrincipalSID", "")
            principal     = self.g.resolve(principal_sid) or principal_sid
            if principal:
                # ACE direction: principal → src (principal has right over src)
                self.g.add_edge(principal, src, right)

    def _resolve_target(self, ref) -> str:
        if isinstance(ref, dict):
            sid  = ref.get("ObjectIdentifier", "")
            name = ref.get("Name", "")
            return self.g.resolve(sid) or name or sid
        return self.g.resolve(str(ref))

    def _name_of(self, item: dict) -> str | None:
        """Edge source: the object's own display name (registered in pass 1)."""
        name = item.get("Properties", {}).get("name", "")
        return name.upper() if name else None

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
    # ── Per-type edge parsers (pass 2) ─────────────────────────────────────────

    def _edges_user(self, item: dict):
        src = self._src_name(item)
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))

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
        src = self._src_name(item)
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))

        # Sessions: user HAS_SESSION on computer
        sessions = item.get("Sessions", {})
        if isinstance(sessions, dict):
            sessions = sessions.get("Results", [])
        for sess in (sessions or []):
            user_sid = sess.get("UserSID", "")
            user     = self.g.resolve(user_sid) or user_sid
            if user:
                self.g.add_edge(user, src, "HasSession")

        # Legacy (SharpHound v1) local-membership arrays.
        for rel_key, rel_type in [
            ("LocalAdmins",          "AdminTo"),
            ("RemoteDesktopUsers",   "CanRDP"),
            ("PSRemoteUsers",        "CanPSRemote"),
            ("DcomUsers",            "ExecuteDCOM"),
        ]:
            rel = item.get(rel_key, {})
            results = rel.get("Results", rel) if isinstance(rel, dict) else rel
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
        src = self._src_name(item)
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))
        for member in item.get("Members", []):
            t = self._resolve_target(member)
            if t:
                self.g.add_edge(t, src, "MemberOf")

    def _edges_domain(self, item: dict):
        src = self._name_of(item)
        src = self._src_name(item)
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))
        for trust in item.get("Trusts", []):
            t = trust.get("TargetDomainName", "")
            if t:
                self.g.add_edge(src, t, "TrustedBy")

    def _edges_generic(self, item: dict):
        src = self._name_of(item)
        src = self._src_name(item)
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))
