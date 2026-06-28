"""
Regression test for order-independent loading.

`whippet/loader.py` resolves SIDs to names at edge-creation time via
`ADGraph.resolve()`, which only works once the referenced object's node has been
added. A typical SharpHound directory sorts as computers, domains, groups, users
— so groups (whose Members[] reference user SIDs) are parsed before the users
they point at. A single-pass loader would store those MemberOf edges against the
raw SID, then add the same principal again under its real name, splitting one
principal into two disconnected identities and silently breaking attack-path
traversal through group membership.

These fixtures deliberately sort the users file (`z_users.json`) AFTER the
groups file (`a_groups.json`) and encode the chain:

    JSMITH  --GenericAll-->  SVC_SQL  --MemberOf-->  DOMAIN ADMINS

so a single-pass loader fails to find JSMITH → DOMAIN ADMINS while the two-pass
loader resolves the membership and the path query succeeds.
"""
from __future__ import annotations

from pathlib import Path

from whippet import ADGraph, QueryEngine, SharpHoundLoader

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "order_dependent"

JSMITH = "JSMITH@CORP.LOCAL"
SVC_SQL = "SVC_SQL@CORP.LOCAL"
DOMAIN_ADMINS = "DOMAIN ADMINS@CORP.LOCAL"
SVC_SQL_SID = "S-1-5-21-1111111111-2222222222-3333333333-1002"


def _load() -> ADGraph:
    g = ADGraph()
    SharpHoundLoader(g).load(str(FIXTURE_DIR))
    return g


def test_glob_sorts_groups_before_users():
    """Guard the precondition: the groups file must sort before the users file,
    otherwise the fixture would not exercise the order-dependent path at all."""
    names = sorted(p.name for p in FIXTURE_DIR.glob("*.json"))
    assert names.index("a_groups.json") < names.index("z_users.json")


def test_membership_edge_resolves_to_user_name():
    """The MemberOf edge must land on the resolved user name, not the raw SID."""
    g = _load()
    member_srcs = {src for src, etype in g.neighbors(DOMAIN_ADMINS, reverse=True)
                   if etype == "MemberOf"}
    assert SVC_SQL in member_srcs
    # The raw SID must NOT survive as a separate, disconnected identity.
    assert SVC_SQL_SID.upper() not in member_srcs


def test_path_query_succeeds_through_group_membership():
    """JSMITH --GenericAll--> SVC_SQL --MemberOf--> DOMAIN ADMINS must resolve."""
    engine = QueryEngine(_load())
    result = engine.shortest_path(JSMITH, DOMAIN_ADMINS)
    assert result.found, "no path found despite the membership existing"
    nodes = [node for node, _ in result.path]
    assert nodes == [JSMITH, SVC_SQL, DOMAIN_ADMINS]
    edges = [etype for _, etype in result.path[1:]]
    assert edges == ["GenericAll", "MemberOf"]


def test_transitive_members_includes_nested_user():
    """SVC_SQL must show up as an effective member of Domain Admins."""
    members = QueryEngine(_load()).transitive(DOMAIN_ADMINS).members
    assert SVC_SQL in members


if __name__ == "__main__":
    test_glob_sorts_groups_before_users()
    test_membership_edge_resolves_to_user_name()
    test_path_query_succeeds_through_group_membership()
    test_transitive_members_includes_nested_user()
    print("ok")
