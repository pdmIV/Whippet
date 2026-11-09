# Correctness and robustness review

This review covers the local loader, graph algorithms, CLI, and shared query
layer. Validation uses synthetic and existing legacy fixtures. It does not
establish complete parity with BloodHound or performance on enterprise captures.

## Fixed

| Issue | Change |
|---|---|
| Separate input files resolved references before later files registered objects | `load_many` registers objects across all inputs before creating edges |
| Repeated `load` calls left previously unresolved SIDs disconnected | Reconcile existing endpoints after each load |
| Reloading a name collision overwrote the original object | Reuse the SID's assigned node ID |
| Three objects sharing a name and type collided | Add SID-qualified fallback IDs |
| Duplicate relationships multiplied paths and statistics | Deduplicate `(source, target, type)` triples |
| HasSession pointed user to computer | Correct to computer to user, including privileged and registry sessions |
| Primary group membership was omitted | Load `PrimaryGroupSID` for users and computers |
| Metadata could be overridden by misleading filenames/archive paths | Prefer `meta.type`, recognize exact type suffixes |
| Invalid JSON disappeared silently | Fail with a filename and parse diagnostic |
| Unknown legacy extended rights became AllExtendedRights | Skip and report unsupported rights |
| Several modern ACL types were ignored | Accept AddSelf, AddAllowedToAct, AddKeyCredentialLink, WriteSPN, WriteAccountRestrictions |
| All-path traversal allowed one hop beyond the requested depth | Enforce the hop boundary, including zero hops |
| Deep exhaustive DFS could raise RecursionError | Use an iterative traversal |
| Output limits did not bound failed alternate-path searches | Stop after 100,000 edge expansions and expose incomplete status |
| An exactly full path list was always reported as truncated | Check for one additional path |
| SID arguments were not consistently resolved by queries | Resolve SID arguments in path, membership, and reach queries |
| Empty edge filters allowed all relationships | Treat an empty filter as no permitted edges |
| Exhaustive reach depth omitted unresolved endpoints | Include all adjacency nodes in the depth bound |
| Reported igraph backend even though queries used Python | Report actual BFS/DFS backend and avoid building an unused mirror on CLI startup |

Malformed wrapper/object/array structures are rejected in common ingestion paths.
UTF-8 BOMs and uppercase JSON suffixes work for file and ZIP inputs. Unsupported
document types and ACL rights are surfaced as warnings. JSON mode distinguishes
unknown exact nodes from an empty successful result.

## Relationship semantics

The [official HasSession schema](https://bloodhound.specterops.io/resources/edges/has-session)
specifies computer to user. The
[GetChanges documentation](https://bloodhound.specterops.io/resources/edges/get-changes)
explicitly identifies it as non-traversable by itself. GetChanges plus
GetChangesAll requires composition into DCSync.

The new summary excludes raw replication components, containment, GPO linkage,
and trust relationships when finding routes. It retains those facts in graph
storage for inspection. This avoids presenting those isolated relationships as
complete transitions in the summary. Existing raw graph queries retain their
broader traversal semantics.

## Remaining limitations

- This is a collected-relationship pathfinder. GenericWrite, remote access,
  sessions, and similar edges can have prerequisites that are not represented.
  Paths require operational verification.
- No full BloodHound post-processing. DCSync composition across nested groups is
  implemented in the supported profile. General effective-rights evaluation,
  Full GPO RSoP/security/WMI filtering and cross-forest exploitation,
  Independent AD CS composition and other unsupported collector object types remain incomplete. Certipy JSON findings and selected native AD CS objects are now supported.
- High-value detection includes name and adminCount heuristics. These are leads,
  not proof of current privilege. Missing collection data can hide routes.
- Conflicting snapshots of the same SID use the latest properties and a union of
  loaded edges. Reloading deduplicates edges but does not remove stale facts.
  Start with a new graph for a fresh snapshot. Bare duplicate display names
  select the first registered identity. Prefer SIDs for reliable references.
- JSON is parsed in memory. There is no archive/decompression/memory quota, and
  malformed inputs are not exhaustively fuzz tested. Use known collector data.
  Output row limits do not bound property sizes, loading time, or BFS memory.
- The optional Flask GUI remains a local convenience server. This review does
  not add authentication, GUI API-wide response caps. A separate CLI batch protocol is now available.
  Its runtime was not tested here because Flask is unavailable.
- No real HARP run, Kali WSL integration run, or enterprise-size benchmark was
  performed in this environment. Cross-process CLI calls reload the graph; batch requests reuse it.

## Validation

New regression tests use `unittest` with no dependencies:

```bash
python -m unittest discover -s tests -v
```

The pre-existing function-style regression tests can also be run with pytest:

```bash
python -m pytest -q
```

New coverage includes input ordering, sequential reloads, colliding identities,
SID lookups, ZIP/BOM handling, malformed JSON, session direction, primary groups,
hop boundaries, 1,200-node paths, work budgets, JSON schemas, errors, and files.

Validation result: 116 checks passed, consisting of 107 unittest cases and nine
existing function-style checks run through `unittest.FunctionTestCase`.
Compilation and `git diff --check` also passed. Pytest could not be installed
because package-index network access was unavailable.

NetworkX 3.7 ranked paths were tested here, including alternate ordering, parallel rights, hop limits, no-path cases and missing-dependency diagnostics. Certipy assessment import was tested on synthetic report fixtures; live Certipy execution was not performed.

GPO scope and directional trust interpretation now have dedicated positive/negative tests, including explicit conditional profile isolation, receiver-side filtering, legacy trust enums, GPOChanges import, batch queries and file-to-CLI integration. No live resultant-policy or resource-authorization check was performed.

Batch lifecycle/client tests run real subprocesses for process reuse, correlation, query-error recovery, event callbacks, clean shutdown, startup failure and response timeout. Runtime-side WSL process-tree cleanup and HARP event-log persistence remain HARP integration responsibilities. See [the handoff](HARP_BATCH_HANDOFF.md).

Whippet 0.8 adds sanitized assessment-workflow regressions for useful triage followed by an empty goal query, full one-lead handoffs, scoped live evidence, denied access, epoch invalidation, and rejection of model overlay claims. A synthetic handoff also survived the existing HARP compactor at its 3,000-character budget with proof and assessment intact. No HARP source was changed and no live target check was executed.
