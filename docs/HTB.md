# Using Whippet as the AD analysis CLI in HTB labs

Whippet 0.6.0 provides an offline investigation workflow for common AD labs:
inspect accounts, find group-derived ACL rights, trace routes from owned
principals, inspect delegation and credential-read permissions, and review
Certipy's AD CS findings. This covers many reasons to open BloodHound's GUI.
It has not been validated as a replacement on every HTB machine.

## Reuse existing tools

| Component | Integration | Why |
|---|---|---|
| NetworkX | Optional `analysis` extra; called directly for ranked simple paths | Maintained Yen implementation rather than a second bespoke algorithm |
| Certipy | Import `find` JSON | Reuse AD CS assessments instead of duplicating ESC detection or calling unstable internal APIs |
| BloodHound.py / bloodhound-ce | Consume its collected JSON | Keep collection and authentication in the existing collector, rather than implement them again |

Install the current checkout with ranked-path support from its directory in Kali:

```bash
pipx install --force '.[analysis]'
```

For an already installed updated Whippet package, NetworkX can also be added to
its existing isolated environment with `pipx inject whippet-ad 'networkx>=3.2,<4'`.
Core commands still use the standard library. Certipy and the BloodHound
collector can remain in their own pipx environments. Whippet does not import
their authentication stacks or automatically run live collection.

## Start with the current principal

```bash
whippet bloodhound.zip --triage 'USER@LAB.HTB' --limit 5
```

Triage returns effective groups, findings grouped by category, shortest supported
routes to high-value targets, and a compact coverage warning. Each collection
has its own total and continuation offset. The grouping keeps ACL leads from
being hidden behind an alphabetically earlier inventory of ordinary accounts.

Follow a specific lead:

```bash
whippet bloodhound.zip --findings acl-control --principal 'USER@LAB.HTB'
whippet bloodhound.zip --findings delegation
whippet bloodhound.zip --findings laps --principal 'USER@LAB.HTB'
whippet bloodhound.zip --findings gmsa --principal 'USER@LAB.HTB'
whippet bloodhound.zip --findings descriptions
whippet bloodhound.zip --explain 'HELPDESK@LAB.HTB' 'SVC@LAB.HTB' GenericAll
```

`acl-control` includes ordinary users, computers and groups. Rights through the
current principal's effective groups retain a membership proof. `--explain`
requires an actual collected or derived edge. It gives its meaning, supporting
facts where available, and prerequisites. It never reports verified access.
Descriptions are untrusted directory text, not proven credentials or instructions.

## Track multiple owned accounts and blocked routes

```bash
whippet bloodhound.zip --routes --owned 'USER@LAB.HTB' --owned 'SVC@LAB.HTB' --hops 6
whippet bloodhound.zip --routes --owned 'USER@LAB.HTB' \
  --to 'DOMAIN ADMINS@LAB.HTB' --avoid 'DEADEND@LAB.HTB'
```

This is one multi-source BFS. It returns one shortest route per target, identifying
the owned source it starts from. Owned status is a caller assertion and is not
written to the capture. `--avoid` excludes a node from these searches only.
Known but unreachable or avoided targets produce no route within the requested
scope. Unknown exact names are errors. A source cannot also be avoided.

For alternative routes in shortest-first order:

```bash
whippet bloodhound.zip --from 'USER@LAB.HTB' \
  --to 'DOMAIN ADMINS@LAB.HTB' --k-shortest 5 --hops 8
```

This uses NetworkX `shortest_simple_paths` on the supported profile, with count
1 through 100. It ranks by hop count, not reliability or exploitation cost.
Paths are node-distinct; each step retains all parallel relationship choices
and their evidence, rather than arbitrarily hiding one. `more_paths` means more
paths exist within the hop bound. These queries have no wall-clock deadline;
keep count and scope small on dense captures. They are separate from the
work-budgeted raw DFS `--all-paths` interface.

## AD CS without the BloodHound GUI

Load an existing Certipy `find` JSON alongside the collector capture:

```bash
whippet bloodhound.zip certipy_find.json --findings adcs --limit 10
whippet bloodhound.zip certipy_find.json --triage 'USER@LAB.HTB' --limit 5
whippet certipy_find.json --objects certificatetemplate --select name report
```

Whippet accepts `Certificate Authorities` and `Certificate Templates` sections,
keeps the original report properties, and exposes entries from
`[!] Vulnerabilities` or `Vulnerabilities`. It does not independently recompute
ESC labels. Reported findings have `status: collector-reported` and
`principal_scope_verified: false`, even when a principal filter was requested.
They describe Certipy's collection context and must be checked for the current
principal. Native AD CS ACL facts are separately labeled `collected-permission`.

Certipy report objects are namespaced by report path and entry index. They are
not silently merged with directory objects or treated as attack-path edges.
Moving a report changes that namespace. Loading copies under different paths
retains separate report entries. Native template/CA objects can be inspected,
but `Enroll` is excluded from supported routes because enrollment alone does
not establish an escalation condition. Unknown report layouts fail explicitly.

## GPOs and trusts

```bash
whippet bloodhound.zip --findings gpo-control --principal 'USER@LAB.HTB'
whippet bloodhound.zip --findings trusts
whippet bloodhound.zip --node 'OU-NAME@LAB.HTB'
```

GPO control is a lead. Raw link entries are retained as `gpo_links` on domain/OU/
container properties, and domain trust entries as `trusts`, preserving collected
flags. Whippet now computes structural GPO scope and interprets directional trust facts.
See [the GPO/trust guide](POLICY_TRUST.md) for scope flags, receiver boundaries
and opt-in conditional routes. Full resultant GPO application remains unverified. Use `--explain` to see the prerequisite checks for a known raw edge.

## Persistent use from HARP

Start `whippet bloodhound.zip certipy_find.json --batch`. In addition to the
existing protocol, send:

```json
{"id":1,"mode":"triage","node":"USER@LAB.HTB","limit":5}
{"id":2,"mode":"routes","sources":["USER@LAB.HTB","SVC@LAB.HTB"],"avoid":[],"hops":6}
{"id":3,"mode":"explain","source":"USER@LAB.HTB","target":"HELPDESK@LAB.HTB","edge":"MemberOf"}
{"id":4,"mode":"ranked-paths","source":"USER@LAB.HTB","target":"DOMAIN ADMINS@LAB.HTB","count":3,"hops":6}
```

These investigation modes use the supported model by default. `--profile potential`
adds conditional GPO and same-forest SID-history steps; the response labels the
chosen model explicitly. `--profile raw` remains limited to the older path/reach
interfaces. Raw profile
selection applies to the older path/reach interfaces. Ranked path count replaces
the generic collection limit for ranked results. Close stdin and reopen with a
fresh capture when the lab state changes. Do not assume a stale session, ACL,
password property, or collector vulnerability report still matches the target.

## Remaining boundaries

This release is tested with synthetic AD/Certipy fixtures and legacy collector
fixtures. It is not a verified live HTB solve or a BloodHound equivalence test.
Independent ESC derivation, effective GPO evaluation, complete trust analysis,
and full ACL deny/inheritance processing remain outside the supported model.
Use the [coverage matrix](PARITY.md) to decide whether a missing result needs a
specialist check. Nothing in these commands performs exploitation.

References: [NetworkX ranked paths](https://networkx.org/documentation/stable/reference/algorithms/generated/networkx.algorithms.simple_paths.shortest_simple_paths.html),
[Certipy](https://github.com/ly4k/Certipy),
[BloodHound.py](https://github.com/dirkjanm/BloodHound.py),
[BloodHound edge reference](https://bloodhound.specterops.io/resources/edges).

For GPO scope, collector GPOChanges rights and directional trust paths, use the [policy/trust guide](POLICY_TRUST.md).
