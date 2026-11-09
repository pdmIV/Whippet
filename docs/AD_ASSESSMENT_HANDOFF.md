# AD assessment evidence and one-lead handoffs

Whippet 0.8.0 separates offline graph possibilities from live access evidence.
This document is intended for HARP integration chats. Only Whippet is changed;
no HARP source or session file is modified by this implementation.

## Case study and ownership

The successful Forest session was inspected locally. No credentials, credential
material, flags, or target addresses are reproduced here or in regression data.
Its relevant pattern was:

1. Triage produced useful group-derived ACL findings and several routes.
2. A later query used the same source but a different, specific goal and returned
   no route. That result did not invalidate the earlier leads.
3. An explanation marked the selected access relationship unverified.
4. A membership modification/readback preceded a privileged write that reported
   insufficient access. No authentication-refresh command was recorded between
   them. The process exit status alone did not describe the failed operation.
5. Eleven rejected proxy replies failed JSON parsing. Those failures belong to
   HARP's model action interface, not to Whippet's graph algorithms.

This evidence does not establish a single root cause for the permission failure.
It does not prove stale tickets, complete effective ACLs, successful token refresh,
or the live authorization semantics of the operation. The next useful question
was whether the exact acting principal, credential mechanism, connection/service
and effective right had been checked after the change.

Whippet addresses lead semantics, focused handoffs and empty-route explanations.
HARP owns model JSON validation/recovery, runtime selection, trusted live check
interpretation, event logging and any permissions that allow the host to update
session evidence. Changing graph output must not be described as fixing malformed
model replies.

## Lead states

Findings now carry an `assessment` object. Explanations carry it in addition to
their existing `verified_access: false`, proof, prerequisites and reference.

| Field | Meaning |
|---|---|
| `basis` | `graph-derived-possibility` or `collector-reported-possibility` |
| `live_access.status` | `unverified` for ordinary CLI/batch graph results |
| `acting_principal` | Scoped caller principal when known; a group owning a right is not itself proof of the acting authentication context |
| `unverified_prerequisites` | Target-specific prerequisites still requiring checks |
| `next_verification` | Concrete question to resolve through the selected HARP Kali runtime |

Membership readback proves at most that the directory reports membership. It
does not prove an existing connection or ticket uses the new groups. A fresh
authentication check does not prove a particular write permission. Target output,
descriptions, collector labels and model statements remain untrusted inputs. A
property or request saying `verified_access=true` never changes this assessment.

## One complete lead

```bash
whippet capture.zip --handoff 'ACTOR@LAB.HTB'
whippet capture.zip --handoff 'ACTOR@LAB.HTB' --lead-query acl-control --lead-index 0
```

Batch equivalent:

```json
{"id":"lead-1","mode":"handoff","node":"ACTOR@LAB.HTB","query":"acl-control","lead_index":0}
```

The result contains exactly one selected `lead` with its full existing evidence,
collection proof, membership path and conditional fields where applicable. The
lead's assessment is moved to the result's `assessment` field. It includes
unverified prerequisites and the next verification question. The result also
includes warnings, a compact coverage boundary, total lead count, next lead index,
overlay epoch and a focused follow-up request. `lead_index` is deterministic for
the same capture/query/principal, but is not stable across refreshed captures.
Priority is a simple category ordering, not predicted success or exploit cost.
No arbitrary claim is promoted to verified access.

The outer envelope retains its schema, warnings, unresolved-node count, stats,
profile and batch correlation metadata. Existing findings/triage collections keep
their `total`, `offset`, `truncated`, `next_offset` and proof fields. A handoff uses
`total_leads` and `next_lead_index` instead. Beyond-range indexes return `lead:null`
without claiming that no other leads exist. Use focused `findings`, `node`,
`memberships`, `explain`, or `catalog` queries for deeper details. Compact coverage
retains profile, unsupported-analysis list, excluded route edges and full-parity
status; the complete capability catalog remains available separately.

## Empty routes

Empty goal-specific routes and shortest/ranked paths now include a
`route_diagnostic`: sources, source types, goal/type, hop/profile/avoid scope,
coverage boundary, unresolved endpoints and limitations. It explicitly sets
`invalidates_prior_leads:false`. No route means no route under that query, not
no access, no viable triage lead, or no possible attack.

In batch mode, the shared analysis instance retains per-principal triage counts
and route totals as `prior_triage`. It retains counts and a follow-up request,
not a duplicate graph dump or a claim of live state. A standalone CLI invocation
has no previous process history and reports an empty prior-triage context. The
full earlier result remains in HARP's event/report storage when HARP records it.
An empty triage/summary route collection also retains findings and diagnostics.
The suggested next request is a one-lead `handoff`, not a command to change target
permissions.

## Session-local live overlay prototype

`whippet.access.SessionOverlay` is a trusted-host Python API, not an exposed
batch mode or model tool. It records observations separately from the immutable
capture and does **not** add membership or access edges to offline routes.
It can describe confirmed membership, credential changes, authenticated contexts,
and exact operation/right checks. It cannot independently authenticate an evidence
reference or parse arbitrary live output into proof.

The constructor accepts an `evidence_validator` callback. Recording is disabled
without it. The callback must attest the exact principal, target, operation,
authentication context and outcome from runtime-owned evidence. Merely checking
that a referenced file/event exists is insufficient. The callback must inspect
operation semantics, including failures embedded in an exit-zero response. Model
notes, a generic command success, and an uncorroborated output string are not
attestation. A real integration must keep this callback outside model control.

```python
from whippet.access import SessionOverlay

# trusted_validator is supplied by the host after checking runtime/session,
# observation identity, parsed outcome and scope. No implementation is implied.
analysis.overlay = SessionOverlay(evidence_validator=trusted_validator)
analysis.overlay.record(kind="membership", principal="ACTOR@LAB.HTB",
    target="OPERATORS@LAB.HTB", evidence_ref="runtime-event-membership")
analysis.overlay.record(kind="authentication", principal="ACTOR@LAB.HTB",
    auth_context="opaque-connection-id", evidence_ref="runtime-event-auth")
# Access still remains unverified until an exact access check is attested.
```

`access` records require the exact `target`, `relationship` and `auth_context`.
Membership/credential changes advance a conservative session-wide epoch and
invalidate prior authentication/access checks. A subsequent authentication alone
does not verify a right. A negative operation check yields `live-check-denied`.
Only an attested positive check after authentication can yield
`verified-live-access`, scoped to that exact tuple. Different users, services/
connections, targets, operations and epochs do not inherit that status. Encode
service, mechanism and credential generation in the host-owned opaque context ID;
never use secret values as that ID.

The trusted Python `handoff(analysis, principal, ..., auth_context=...)` can consult
this overlay. Ordinary CLI and NDJSON handoffs do not accept an authentication
context or verification claims and remain unverified. Batch `overlay-update` and
extra verification fields are rejected. There is no overlay import file, signed
attestation protocol or remote host-to-server overlay mutation channel in this
release. New analysis/process instances get new empty overlays. The prototype
therefore explores the semantics without pretending the existing HARP transport
already supplies verified observations. HARP may maintain a separate equivalent
host ledger, but integrating one is outside this Whippet-only change.

## Integration notes for a future HARP chat

- Inspect batch readiness `modes` for `handoff`; keep compatibility with older
  Whippet installations and existing focused query modes.
- The inspected HARP managed-query allowlist does not yet include `handoff`.
  A future HARP edit must add it before dispatching that mode through
  `whippet_query`; do not assume this Whippet release modified HARP.
- Keep compact handoff evidence atomic. If context limits require omission,
  retain a report reference, warn explicitly, and request a focused follow-up.
  Never silently remove prerequisite, coverage, paging or proof fields.
- Treat directory changes as a request for new live checks, not permission to
  silently refresh or rewrite offline facts. Do not scrape free-text model claims
  into a verified overlay.
- Preserve previous triage evidence after an empty specific-goal query. Goals
  need not match the controlled object shown by another useful lead.
- Fix malformed action JSON in HARP's model interface separately. A valid Whippet
  report and verified target access do not imply a valid proxy action reply.

## Validation

Sanitized synthetic regressions reproduce useful group-derived triage followed
by an empty domain-goal query, one-lead handoff with complete membership proof,
directory membership plus new authentication without write access, a denied
permission check, and scoped positive checks invalidated by a credential change.
They also reject model-supplied verification/overlay updates and confirm the
capture's edges never change. No target command is executed by these tests.

The case-study inspection is evidence of the workflow problem, not proof that a
specific ticket cache or ACL caused it. Live identity, refreshed authentication,
effective permissions, actual GPO application and live trust/resource authorization
still require checks in the selected HARP Kali runtime.
