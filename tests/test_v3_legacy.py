"""
Regression test for legacy SharpHound / BloodHound meta-version-3 ingestion.

Version-3 output differs from modern SharpHound / BloodHound CE in three ways
that each silently produced an empty graph before the loader learned the format:

  1. The object array is keyed by the type name (``{"groups": [...]}``) rather
     than nested under ``"data"`` — so ``--list-users`` reported "0 nodes".
  2. Group ``Members`` reference principals via ``MemberId``, not
     ``ObjectIdentifier`` — so membership edges never resolved.
  3. ACEs use the ``"Owner"`` right and carry extended rights as
     ``RightName: "ExtendedRight"`` with the specific right in ``AceType`` —
     so ownership and DCSync-relevant control edges were dropped.

The fixtures mirror a real ``CONTROLLER.LOCAL`` capture and encode:

    JSMITH  --MemberOf-->      DOMAIN ADMINS
    JSMITH  --Owns/GenericAll--> IIS_IUSRS
    DOMAIN ADMINS  --GetChangesAll--> JSMITH   (from an ExtendedRight ACE)
"""
from __future__ import annotations

from pathlib import Path

from whippet import ADGraph, QueryEngine, SharpHoundLoader

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "v3_legacy"

JSMITH = "JSMITH@CONTROLLER.LOCAL"
DOMAIN_ADMINS = "DOMAIN ADMINS@CONTROLLER.LOCAL"
IIS_IUSRS = "IIS_IUSRS@CONTROLLER.LOCAL"
JSMITH_SID = "S-1-5-21-1-1105"


def _load() -> ADGraph:
    g = ADGraph()
    SharpHoundLoader(g).load(str(FIXTURE_DIR))
    return g


def test_type_keyed_arrays_load_nodes():
    """meta-version-3 keys the array by type name; nodes must still ingest."""
    g = _load()
    assert g.node_count >= 4
    assert g.has_node(JSMITH)
    assert g.has_node(DOMAIN_ADMINS)


def test_member_id_resolves_membership():
    """Members[].MemberId must resolve to the user, not survive as a raw SID."""
    g = _load()
    member_srcs = {src for src, etype in g.neighbors(DOMAIN_ADMINS, reverse=True)
                   if etype == "MemberOf"}
    assert JSMITH in member_srcs
    assert JSMITH_SID.upper() not in member_srcs


def test_owner_right_maps_to_owns():
    """v3 'Owner' ACE right must become the BloodHound 'Owns' edge."""
    g = _load()
    edges = {etype for _, etype in g.neighbors(JSMITH) if _ == IIS_IUSRS}
    assert "Owns" in edges
    assert "GenericAll" in edges


def test_extended_right_maps_to_dcsync_component():
    """RightName 'ExtendedRight' + AceType DS-Replication-Get-Changes-All
    must become the GetChangesAll edge (a DCSync building block)."""
    g = _load()
    da_out = {etype for _, etype in g.neighbors(DOMAIN_ADMINS)}
    assert "GetChangesAll" in da_out


def test_path_query_through_v3_graph():
    """A path query must traverse the resolved v3 membership edge."""
    result = QueryEngine(_load()).shortest_path(JSMITH, DOMAIN_ADMINS)
    assert result.found
    assert [n for n, _ in result.path] == [JSMITH, DOMAIN_ADMINS]


if __name__ == "__main__":
    test_type_keyed_arrays_load_nodes()
    test_member_id_resolves_membership()
    test_owner_right_maps_to_owns()
    test_extended_right_maps_to_dcsync_component()
    test_path_query_through_v3_graph()
    print("all v3 legacy tests passed")
