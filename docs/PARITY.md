# BloodHound CLI utility target

Whippet aims to answer the practical questions an operator asks of BloodHound
through a CLI and a bounded machine interface. Full parity is not achieved in
0.6.0. Matching output formats or adding edge names alone cannot establish it.

## Current coverage

| Capability | Status | Interface / boundary |
|---|---|---|
| SharpHound AD ingestion | Partial | Users, computers, groups, domains, OUs, GPOs, containers; unsupported files/ACL rights warn |
| Node search and inspection | Implemented | `--search`, `--node`; use SID/GUID for duplicate names |
| Object/property exploration | Implemented | `--objects`, exact typed `--where`, projected `--select` |
| Effective group membership | Implemented | `--memberships` with shortest proof chains; `--transitive-members` for group expansion |
| Shortest paths and reachability | Implemented for supported model | Supported JSON profile excludes context edges; raw profile retains them |
| Alternate simple paths | Bounded | Explicit JSON `--all-paths`, hop/output/work caps |
| DCSync composition | Implemented for collected grants | GetChanges + GetChangesAll on the same loaded Domain; rights may come from different nested groups |
| Replication composition evidence | Implemented | Original grant edges and membership chains on derived shortest/summary path edges and findings |
| Common account exposure queries | Implemented | Enabled roasting and unconstrained-delegation candidates |
| Common access/control queries | Implemented | ACLs over all targets, LAPS/gMSA, delegation, sessions, local admin and remote access |
| HTB investigation workflow | Implemented | Grouped triage, multi-owned routes with avoided nodes, edge explanations |
| Ranked alternative paths | Implemented with NetworkX | Hop-ranked node-distinct paths with parallel relationship evidence |
| LLM-sized results | Implemented | Projection, per-collection limits, offsets, continuation metadata |
| Persistent CLI queries | Implemented | `--batch` NDJSON; load and derive once, query repeatedly |
| Full effective ACL/policy interpretation | Missing | No complete deny/inheritance/property-specific abuse evaluation |
| GPO analysis | Partial | Link scope, enforcement, blocked inheritance, disabled sections, imported GPOChanges rights and conditional control paths; full RSoP remains out of scope |
| Trust analysis | Partial | Directional authentication paths, receiver flags and conditional same-forest SID-history candidates; full cross-forest exploitation and resource authorization not inferred |
| AD CS assessment | Partial | Certipy findings import plus native template/CA inspection; independent ESC composition remains missing |
| Azure/Entra and OpenGraph extensions | Missing | AD collector focus only |
| Full BloodHound saved-query/Cypher coverage | Missing | Named catalog and object filtering cover a subset |
| Collection freshness/diff/history | Missing | In-memory snapshot; overlapping loads union facts |
| Measured BloodHound result equivalence | Missing | No paired real-capture differential evaluation yet |

The machine-readable version is `whippet CAPTURE --catalog`. Unsupported
analysis must remain distinguishable from a successful empty query. The catalog
states unsupported analysis categories; ingestion warnings and unresolved-node
counts describe additional gaps in the actual capture. Neither an empty query
nor `found=false` proves that no usable path exists.

## How HARP should consume it

Keep the large collector data in Whippet. Give the oracle a short summary and
only the relevant findings. Give the proxy the chosen route and its supporting
facts. Request selected properties or the next page only when needed. Keep
source IDs, edge types, composition evidence, and incomplete-result indicators
in stage handoffs. Avoid treating graph reachability as verified access.

`--batch` removes repeated loading within a session. It does not remove model
token costs by itself. Narrow queries and property projection reduce the text
sent to the model. Measure end-to-end success as well as prompt size, so omitted
facts are not incorrectly credited as an efficiency improvement.

## Acceptance gates for wider parity

1. Versioned collector fixtures for every supported object and relationship,
   including collection failures, unknown endpoints, cross-domain memberships,
   duplicate names, and overlapping snapshots.
2. Positive and negative rule fixtures for each derived edge. Verify supporting
   facts and membership chains, not just whether a path exists.
3. Differential checks against a pinned BloodHound version on the same snapshots:
   compare normalized SID/GUID nodes, typed edges, selected query sets, and path
   existence. Record exclusions and unsupported rules explicitly.
4. Add GPO, trust, and AD CS rules separately, each with its own ingestion and
   composition tests. Do not enable a relationship for supported routes solely
   because its name is recognized.
5. Evaluate HARP with raw JSON, bounded Whippet reports, and persistent focused
   queries on the same tasks. Measure tokens, latency, API cost, task completion,
   missing leads, and false leads. Include broad-query fallback trials.

Reference: BloodHound distinguishes
[traversable and non-traversable edges](https://bloodhound.specterops.io/resources/edges/traversable-edges).
Its [GetChanges documentation](https://bloodhound.specterops.io/resources/edges/get-changes)
describes composing replication rights into DCSync. Whippet implements the
documented two-right combination with collected nested memberships, not the
entire BloodHound post-processing pipeline.

For concrete HTB workflows and reused Python tools, see [the HTB guide](HTB.md).

GPO/trust behavior, conditional routing and remaining limitations are described in [the policy guide](POLICY_TRUST.md).
