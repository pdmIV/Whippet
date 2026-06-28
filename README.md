# Whippet

**A lean, fast in-memory Active Directory graph pathfinder — the lightweight sibling to BloodHound.**

No Neo4j. No JVM. No GUI. No Cypher. No kennel. Just a single Python file that ingests the exact same SharpHound output BloodHound uses and answers the questions you actually care about — *who can reach Domain Admins, what can this account touch, how do these privileges chain* — straight from the command line on your Kali box.

```
$ python3 whippet.py BloodHound.zip --from "JSMITH@CORP.LOCAL" --to "DOMAIN ADMINS@CORP.LOCAL" --exhaustive

  All Paths (up to 20, exhaustive, ≤3 hops): JSMITH@CORP.LOCAL → DOMAIN ADMINS@CORP.LOCAL
  ────────────────────────────────────────────────────────────────────
  [1]  (2 hops)
       JSMITH@CORP.LOCAL ─[GenericAll]→ SVC_SQL@CORP.LOCAL ─[MemberOf]→ DOMAIN ADMINS@CORP.LOCAL
```

---

## Why

BloodHound is excellent, but for a lot of day-to-day work it is heavier than the problem requires. Standing up Neo4j, importing the data, opening the GUI, and clicking through *Shortest Paths to Domain Admins* is a lot of ceremony when all you want is a fast, scriptable answer you can pipe into a report.

Even a large enterprise AD is typically tens of thousands of nodes and a few hundred thousand edges — a graph that fits comfortably in a few hundred MB of RAM. Neo4j's disk-backed page cache, Bolt protocol, and Cypher parsing are overhead you don't need for the targeted traversals (shortest path, reachability, transitive membership) that make up the vast majority of BloodHound usage.

Whippet stores the whole graph in plain Python adjacency lists and answers those queries with BFS/DFS. No server to manage, no import step, and queries return in milliseconds.

| | BloodHound + Neo4j | Whippet |
|---|---|---|
| Setup | Install Neo4j, import data, open GUI | `python3 whippet.py file.zip` |
| Import (~30K nodes) | 30–120 s | 1–2 s (load + index) |
| Shortest-path query | 20–200 ms (Cypher) | < 1 ms |
| "All paths to DA" | 2–10 s (GUI) | 20–80 ms |
| Dependencies | JVM, Neo4j, browser | Python 3 stdlib (igraph optional) |
| Scriptable / pipeable | Awkward | Native |

---

## Requirements

- **Python 3.9+** — that's it. The core runs entirely on the standard library.
- **`igraph`** *(optional)* — `pip install igraph`. When present, Whippet builds a C-backed graph mirror for bulk-analysis queries (centrality, full path matrices). For the targeted BFS queries that make up most usage, the pure-Python path is already fast enough that igraph changes nothing — so don't feel obligated to install it.

No other third-party packages. Drop the file on your Kali box and run it.

---

## Input

Whippet ingests the same data BloodHound does — the JSON produced by [SharpHound](https://github.com/SpecterOps/SharpHound). It accepts:

- A **SharpHound ZIP archive** — `python3 whippet.py BloodHound.zip`
- A **directory** of extracted JSON files — `python3 whippet.py /path/to/output/`
- **Individual JSON files** — `python3 whippet.py *_users.json *_computers.json *_groups.json *_domains.json`

Both SharpHound v1 and v2 (BloodHound CE) output formats are supported. For full coverage, collect users, computers, groups, and domains — group and domain data is what lets Whippet resolve SIDs to names and identify high-value targets.

---

## Usage

```
python3 whippet.py INPUT [INPUT ...] [options]
```

Run with no query options and Whippet defaults to the most common question: every principal that can reach **Domain Admins**, plus a high-value-target inventory.

### Options

| Option | Description |
|---|---|
| `--from SRC` | Source node (user / computer / group name or SID) |
| `--to DST` | Target node (defaults to the Domain Admins group if omitted) |
| `--reachable NODE` | Show everything reachable **from** this node |
| `--transitive-members GROUP` | Fully expand nested group membership |
| `--hops N` | Maximum path depth (default: 6). Ignored when `--exhaustive` is set |
| `--exhaustive` | Search with no manual hop cap — bound is auto-computed from the graph (see below) |
| `--list-users` | List all user accounts with their security-relevant flags |
| `--user-flag FLAG [FLAG ...]` | With `--list-users`, show only users that have **all** the named flags set |
| `--enabled-only` | With `--list-users`, restrict to enabled accounts |
| `--max-paths N` | Cap the number of alternate paths printed (default: 20) |
| `-o, --output FILE` | Write the report to a file (ANSI colour stripped automatically) |

---

## Examples

**Default — who can reach Domain Admins:**
```bash
python3 whippet.py BloodHound.zip
```

**Specific attack path, exhaustively:**
```bash
python3 whippet.py BloodHound.zip \
    --from "JSMITH@CORP.LOCAL" --to "DOMAIN ADMINS@CORP.LOCAL" --exhaustive
```

**Who can reach a Domain Controller within 4 hops:**
```bash
python3 whippet.py BloodHound.zip --to "DC01.CORP.LOCAL" --hops 4
```

**What can a compromised account reach:**
```bash
python3 whippet.py BloodHound.zip --reachable "JSMITH@CORP.LOCAL" --hops 3
```

**Fully expand effective membership of a group:**
```bash
python3 whippet.py BloodHound.zip --transitive-members "DOMAIN ADMINS@CORP.LOCAL"
```

**List all users with their security flags:**
```bash
python3 whippet.py BloodHound.zip --list-users
```

**List only enabled, kerberoastable users:**
```bash
python3 whippet.py BloodHound.zip --list-users --user-flag hasspn --enabled-only
```

**Save a report to disk:**
```bash
python3 whippet.py BloodHound.zip -o paths.txt
```

---

## Features

### Queries

- **Shortest path** between any two nodes (BFS, early-exit).
- **Who can reach X** — a single reverse-BFS from the target instead of running a forward search from every principal. This is the key optimization: Whippet keeps a reverse adjacency index, so *"who can reach Domain Admins"* is one pass over the graph, not one pass per source.
- **What can X reach** — forward BFS from a source node, grouped by hop distance.
- **All simple paths** between two nodes (DFS), with output capped by `--max-paths`.
- **Transitive group membership** — full nested expansion via reverse `MemberOf` traversal.
- **High-value target inventory** — auto-flags Domain Admins, Enterprise Admins, DCs, `admincount=1` objects, and other privileged groups.

### User listing

`--list-users` decodes each account's security-relevant flags inline, so you can spot easy wins without opening the GUI:

```
  JSMITH@CORP.LOCAL   enabled, kerberoastable
  SVC_SQL@CORP.LOCAL  enabled, adminCount, kerberoastable, asrep-roastable
  BOB@CORP.LOCAL      pwdNotReqd
```

Recognized flags: `enabled`, `adminCount`, `kerberoastable` (SPN set), `asrep-roastable` (no pre-auth), `pwdNotReqd`, `pwdNeverExpires`, `unconstrained` / `constrained` delegation, `sensitive`, and `sidHistory`. Filter with `--user-flag` (AND semantics) and `--enabled-only`.

### Exhaustive search without overshoot

`--exhaustive` replaces a hand-picked `--hops` value with a bound computed from the graph itself — and the bound is exact, not a guess:

- **Reachability** (`--reachable`, "who can reach") is plain BFS, which terminates naturally when the frontier empties. There is no benefit to a hop cap; a limit could only ever cut off valid results. Exhaustive here simply means *no cap*.
- **All simple paths** is the only query with a real depth question, and computing the true longest simple path is NP-hard. But there's a tight, cheap upper bound: a simple path can't revisit a node, so it can never be longer than the number of nodes reachable from the source. Whippet computes that reachable-set size per source and uses it as the DFS depth — guaranteeing no real path is truncated, without doing unnecessary work.

One honest caveat: the *count* of simple paths can still grow combinatorially in a dense graph even when the depth bound is correct. That's inherent to enumerating all paths, not something a hop cap fixes. `--max-paths` (default 20) keeps output responsive; raise it if you want more.

---

## How it works

The graph lives in two mirrored adjacency lists:

```
_adj   : node → [(neighbor, edge_type), ...]   # forward
_radj  : node → [(neighbor, edge_type), ...]   # reverse
```

Edges are typed to match BloodHound's relationship model — `MemberOf`, `HasSession`, `GenericAll`, `WriteDacl`, `WriteOwner`, `ForceChangePassword`, `AllowedToDelegate`, `AdminTo`, `CanRDP`, `GetChanges`/`GetChangesAll`, and more. SIDs are resolved to readable names at load time, and each node is tagged with its object type (User / Computer / Group / Domain) from the source JSON.

The reverse index (`_radj`) is what makes the headline query cheap. *"Who can reach this node"* becomes a single reverse BFS — `O(V + E)` — rather than a forward search repeated from every principal — `O(V × (V + E))`.

**On memory:** storing edges as a flat `list[tuple]` costs roughly 60–90 bytes per edge. NetworkX, by comparison, nests edges in dicts at ~150–200 bytes each; igraph packs them into C arrays at ~30–40 bytes. For a 500K-edge graph that's the difference between ~30–40 MB and ~75–100 MB for the edge store alone — which is why Whippet doesn't reach for NetworkX, and only uses igraph for the bulk-analysis cases where C storage actually earns its keep.

---

## A note on companion tooling

Whippet focuses on graph traversal. If you also want a flat findings report — Kerberoastable accounts, AS-REP roasting, dangerous ACEs on high-value targets, DCSync rights, unconstrained delegation, sessions on DCs — that pairs naturally alongside it as a separate pass over the same SharpHound input.

---

## Disclaimer

Whippet is intended for authorized security assessments, red-team engagements, and defensive analysis of Active Directory environments **you own or have explicit written permission to test**. You are responsible for ensuring your use complies with all applicable laws and the terms of your engagement. The authors assume no liability for misuse.
