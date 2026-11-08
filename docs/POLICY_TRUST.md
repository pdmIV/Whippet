# GPO and trust analysis

Whippet 0.6.0 adds structural policy scope, collector-computed GPO access rights,
directional trust analysis, and opt-in conditional attack paths. These extend the
HTB workflow without silently treating policy linkage or trust as verified access.

## GPO scope

```bash
whippet capture.zip --gpo-scope 'POLICY@LAB.HTB' --limit 10
whippet capture.zip --findings gpo-impact --principal 'USER@LAB.HTB'
whippet capture.zip --findings gpo-link-control --principal 'USER@LAB.HTB'
```

`--gpo-scope` accepts a loaded GPO name or GUID. It follows each link through
collected containment, recording the link container and the full containment
path. User and computer targets are distinguished. Results are paginated.

| Input / condition | Treatment |
|---|---|
| `Links[].Guid`, `GUID`, `ObjectIdentifier` | Case-insensitive link key; brace-wrapped identifiers resolve |
| `IsEnforced` / `Enforced` | Enforced links pass an OU's inheritance block |
| `IsEnabled`, `Enabled`, `IsDisabled`, `Disabled` | Explicitly disabled links produce no conditional route |
| `Options` / `LinkOptions` | Bit 1 disables the link, bit 2 enforces it |
| `blocksinheritance` or top-level `BlocksInheritance` | Stops a non-enforced inherited link at the blocked OU |
| A GPO linked directly to an OU with blocked inheritance | Its local link still applies to that OU's scope |
| Unknown enforcement at a blocked OU | Descendants remain `unknown-inheritance` candidates |
| Missing inheritance-block flag | Remains an explicit uncertainty |
| GPO `flags` / `gpoflags` or `gpostatus` | Distinguishes disabled user and computer sections |
| `userenabled`, `computerenabled` and equivalent section-enabled keys | Explicit section state is retained |
| WMI filter property | Retained as evidence; not executed or evaluated |

SharpHound/BloodHound.py normally report active links in their `Links` arrays.
The analyzer uses that collector convention when an enabled flag is absent.
Graph-only GPLink facts have less information; they cannot prove application.
`candidate-scope` means structurally eligible, not successful application.
`unknown-inheritance` means unresolved flags can change scope.
`blocked-inheritance` records a stopped OU branch, rather than listing every
descendant of the blocked branch. `disabled-link` and `disabled-section` are
excluded from conditional route construction.

All scope results retain `verified_application: false`. Full RSoP requires
security filtering, read/apply permissions, deny ACEs, WMI, sites, loopback,
policy precedence, client state and actual refresh results. Missing information
is not treated as a successful check. An empty scope only means no target was
found in the supplied collection. It does not establish that the policy has no
effect in the live domain.

Principal-scoped `gpo-impact` results include the GPO control edge and effective
membership proof. These are separate from the GPO scope facts. `WriteGPLink`
appears in `gpo-link-control` findings; it does not automatically imply control
over any GPO or create a takeover route.

## Collected GPO access changes

The loader now imports `GPOChanges.AffectedComputers` and the principal arrays
`LocalAdmins`, `RemoteDesktopUsers`, `DcomUsers`, and `PSRemoteUsers` on domain/OU/
container records. It creates `AdminTo`, `CanRDP`, `ExecuteDCOM`, and `CanPSRemote`
relationships from those collector-computed facts. They appear in normal access
findings and supported routes, with `collection_evidence` identifying the source
container, collector field, principal reference and affected computer reference.
Whippet does not parse SYSVOL or recompute the collector's GPOChanges assessment.

Legacy `Users`, `Computers`, and `ChildOus` containment arrays are also supported,
alongside modern `ChildObjects`. Reloaded facts are deduplicated. As with other
loaded edges, overlapping snapshots union facts; start a fresh process for a new
assessment rather than assume a removed policy right disappeared from memory.

## Trust direction and receiver boundaries

```bash
whippet capture.zip --findings trusts
whippet capture.zip --trust-path 'CHILD.LAB.HTB' 'LAB.HTB'
whippet capture.zip --findings trust-escalation
```

Directions are relative to the domain record containing the trust:

| TrustDirection | Authentication flow |
|---|---|
| `Inbound` / `1` | Local-domain identities toward the other domain |
| `Outbound` / `2` | Other-domain identities toward the local domain |
| `Bidirectional` / `3` | Both directions |
| `0` | No direction inferred |
| Missing / unsupported | Unknown, with no invented direction |

The loader exposes these as raw `CanAuthenticateTo` edges, excluded from
supported attack routes. This replaces the older unconditional local-to-target
`TrustedBy` construction, which ignored direction.

Normalized findings retain trust type, transitivity, forest classification,
SID filtering, selective authentication, raw attributes and original evidence.
`TrustType` numeric values use the legacy collector/.NET enum (`0` TreeRoot, `1` ParentChild,
`2` CrossLink, `3` External, `4` Forest, `5` Kerberos, `6` Unknown), not LDAP's raw `trustType`
attribute. `TrustAttributes` bits are interpreted for non-transitivity,
quarantine, forest membership and selective authentication. Missing flags remain
unknown. Contradictory boundary flags are reported, with restrictive conditions
retained instead of silently enabling an escalation candidate.

Filtering flags on a domain's trust record describe that domain as the receiver.
They must not be copied onto authentication flowing in the other direction.
Whippet marks whether a receiver record was collected and whether its filtering
flags are known. Reciprocal collection is needed to assess both boundaries.

`--trust-path` returns an authentication relationship path, not a compromise or
resource-authorization result. Direct relationships may be cross-forest or
nontransitive. Multi-hop inference requires every hop to be explicitly
same-forest and transitive. Cross-forest chains and unknown transitivity are not
expanded. Selective authentication remains a prerequisite to check at resources.
The current algorithm does not implement forest-wide name-suffix routing,
Kerberos referral policy or live authorization tests.

## Conditional route profile

```bash
whippet capture.zip --format json --from 'USER@LAB.HTB' \
  --to 'PC.LAB.HTB' --profile potential
whippet capture.zip --routes --owned 'CHILD.LAB.HTB' \
  --to 'LAB.HTB' --profile potential
```

The `potential` profile starts with the supported graph and adds:

- `PotentialGPOControl`: GPO to computer, when collected structural scope is
  eligible or uncertain. Disabled sections/links and definitely blocked branches
  do not produce an edge. Control of the source GPO and remaining application
  checks are prerequisites, rather than conclusions.
- `PotentialSIDHistory`: controlled source domain to a receiving same-forest
  domain, only when receiver-side evidence explicitly reports SID filtering off.
  Unknown/true SID filtering, external/forest trust classification, uncollected
  domain endpoints, and conflicting boundary flags do not produce an edge.
  Domain control, suitable key material, destination SID selection, selective
  authentication and resource authorization still need verification.

Both edge types carry `conditional: true`, `verified_access: false`, and their
supporting records. Same-forest SID-history analysis covers that technique only;
filtering it out does not establish that other forest escalation techniques are
impossible. No unconditional cross-forest compromise edge is invented.

The profile works with JSON paths/reachability, summaries, triage, multi-owned
routes and NetworkX ranked paths. Supported remains the default. Raw mode retains
the raw graph but does not synthesize these conditional edges. Plain text and
the optional GUI retain their existing raw-query behavior. Potential edges may
not appear in that GUI.

Batch requests:

```json
{"id":1,"mode":"gpo-scope","node":"POLICY@LAB.HTB","limit":10}
{"id":2,"mode":"trust-path","source":"CHILD.LAB.HTB","target":"LAB.HTB"}
{"id":3,"mode":"path","source":"USER@LAB.HTB","target":"PC.LAB.HTB","profile":"potential"}
```

## Validation and references

Regression coverage includes enforcement and local-link behavior, disabled
sections and links, unknown settings, cyclic containment, legacy import, collected
GPO changes, inherited control proofs, trust direction, receiver filtering,
selective authentication, nontransitive/cross-forest boundaries and conditional
profile separation. These are offline fixtures, not live RSoP or HTB equivalence
checks.

Sources: [Microsoft Group Policy processing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing),
[BloodHound GPLink](https://bloodhound.specterops.io/resources/edges/gp-link),
[Microsoft trust directions](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.trustdirection),
[BloodHound SameForestTrust](https://bloodhound.specterops.io/resources/edges/same-forest-trust),
[BloodHound CrossForestTrust](https://bloodhound.specterops.io/resources/edges/cross-forest-trust).
