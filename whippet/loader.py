"""
whippet.loader — SharpHound v1/v2 JSON → ADGraph ingestion.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

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
    """

    def __init__(self, graph: ADGraph):
        self.g = graph

    def load(self, path: str):
        p = Path(path)
        if p.suffix.lower() == ".zip":
            self._load_zip(p)
        elif p.is_dir():
            for f in sorted(p.glob("*.json")):
                self._load_file(f)
        elif p.suffix.lower() == ".json":
            self._load_file(p)

    def _load_zip(self, zp: Path):
        with zipfile.ZipFile(zp) as zf:
            for name in zf.namelist():
                if name.endswith(".json") and not name.startswith("__MACOSX"):
                    with zf.open(name) as f:
                        try:
                            self._parse(name, json.load(f))
                        except json.JSONDecodeError:
                            pass

    def _load_file(self, fp: Path):
        with open(fp, encoding="utf-8") as f:
            try:
                self._parse(fp.name, json.load(f))
            except json.JSONDecodeError:
                pass

    def _parse(self, filename: str, data: dict):
        items = data.get("data") or data.get("nodes") or []
        fname = filename.lower()

        if   "user"     in fname: parse = self._parse_user
        elif "computer" in fname: parse = self._parse_computer
        elif "group"    in fname: parse = self._parse_group
        elif "domain"   in fname: parse = self._parse_domain
        elif "gpo"      in fname: parse = self._parse_generic
        elif "ou"       in fname: parse = self._parse_generic
        else:
            return

        for item in items:
            parse(item)

    # ── Per-type parsers ──────────────────────────────────────────────────────

    def _add_obj(self, item: dict, node_type: str = "") -> str | None:
        props = item.get("Properties", {})
        name  = props.get("name", "")
        if not name:
            return None
        self.g.add_node(name, props, node_type=node_type)
        return name.upper()

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

    def _parse_user(self, item: dict):
        src = self._add_obj(item, "User")
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

    def _parse_computer(self, item: dict):
        src = self._add_obj(item, "Computer")
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

        # Local admin / RDP / PSRemote / DCOM
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

    def _parse_group(self, item: dict):
        src = self._add_obj(item, "Group")
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))
        for member in item.get("Members", []):
            t = self._resolve_target(member)
            if t:
                self.g.add_edge(t, src, "MemberOf")

    def _parse_domain(self, item: dict):
        src = self._add_obj(item, "Domain")
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))
        for trust in item.get("Trusts", []):
            t = trust.get("TargetDomainName", "")
            if t:
                self.g.add_edge(src, t, "TrustedBy")

    def _parse_generic(self, item: dict):
        src = self._add_obj(item)
        if not src:
            return
        self._add_aces(src, item.get("Aces", []))
