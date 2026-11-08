# Codex handoff: HARP-managed Whippet batch integration

This document describes Whippet 0.7.0 and the work HARP must do to manage it.
Whippet's server and reusable client are implemented. HARP runtime selection,
event-log persistence and workflow dispatch are not implemented in this repo.
Do not assume those HARP changes already exist.

## Purpose and boundary

Whippet analyzes collected AD data offline. Keep one process running for a
capture snapshot, then send focused queries. Batch mode amortizes loading and
cached analysis across requests. Narrow queries, selected properties and
pagination reduce the text supplied to the LLM. Batch mode alone does not
reduce model tokens. No disk cache, live collection or exploitation is added.

HARP must launch the process through its explicitly selected Kali runtime and
keep its stdin/stdout/stderr on that runtime's transport. Resolve capture paths
inside that runtime. Do not launch host Python to analyze a Windows copy as a
fallback, select another WSL distribution, or assume a default Kali distribution.
Use argument arrays and the existing runtime adapter, not interpolated shell
commands. This document does not prescribe an unknown HARP adapter API.

The command executed **inside the selected Kali runtime** is:

```bash
whippet /runtime/path/capture.zip --batch --batch-ready
```

Multiple positional inputs, including Certipy JSON, are accepted before the
flags. Initial CLI `--hops`, `--limit`, `--offset`, and `--profile` set defaults
for requests. Start a new process for a new snapshot/input set; existing sessions
do not notice capture modifications. Keep sessions separate across assessments.

## Lifecycle contract

1. Spawn once, with separate stdin/stdout/stderr pipes; continuously drain stderr.
2. Await the readiness JSON on stdout, with a startup deadline. The handshake
   occurs after graph loading. Failure to load exits with status 1 and a JSON
   error, not a ready event. Invalid CLI usage exits with status 2 on stderr.
3. Check `schema_version=1`, `protocol_version=1`, and a nonempty `session_id`.
4. Send one JSON object plus newline. Flush stdin. Use a unique string/integer
   `id` for every request. The server also accepts null/missing IDs for manual
   use; managed clients should always supply IDs.
5. Read exactly one JSON response per nonblank request, checking its ID and
   `batch.session_id`. Keep one request in flight per process.
6. Query errors are response objects with `error`; they do not end the session.
   Transport errors, EOF, correlation mismatch, incompatible protocol or a
   response timeout invalidate the session. Kill/close it; do not automatically
   retry or fall back to another runtime.
7. On normal completion, close stdin and wait for exit. Alternatively send
   `shutdown`, consume its acknowledgement, then wait. Enforce a grace deadline
   and terminate remaining processes using the same runtime adapter. On timeout
   under WSL/SSH, verify cleanup of the runtime-side process, not just the host
   launcher. HARP owns that transport-specific process-tree behavior.

`--batch-ready` is opt-in. Without it, existing `--batch` clients continue to
receive only replies to requests, with no unsolicited startup message. Ordinary
progress/warnings remain on stderr. Replies flush immediately. Blank lines are
ignored. Each response adds `batch.session_id`, monotonic `request_index`, and
`elapsed_ms` for request processing (excluding initial graph loading, final JSON
serialization and transport). This is server
measurement, not model latency or a client-side request deadline.

Readiness shape (additional fields may be added):

```json
{"schema_version":1,"event":"ready","protocol_version":1,"whippet_version":"0.7.0","session_id":"opaque-session-id","stats":{"backend":"pure-Python BFS/DFS","nodes":5,"edges":2},"warnings":[],"modes":["ping","objects","shutdown"],"max_request_characters":65536}
```

The modes shown above are abbreviated; the real handshake lists every supported
mode. Do not parse human-readable stderr to detect readiness. Stdout is NDJSON,
not pretty-printed JSON and not a JSON array.

## Requests and responses

```json
{"id":"health-1","mode":"ping"}
{"id":"triage-1","mode":"triage","node":"USER@LAB.HTB","limit":5}
{"id":"acl-1","mode":"findings","query":"acl-control","principal":"USER@LAB.HTB","limit":5}
{"id":"props-1","mode":"objects","object_type":"user","where":{"hasspn":true,"enabled":true},"select":["name","description"],"limit":5}
{"id":"groups-1","mode":"memberships","node":"USER@LAB.HTB","limit":5,"offset":0}
{"id":"stop-1","mode":"shutdown"}
```

`ping` returns `mode: ping`, `result.status: ready`, graph stats, the echoed ID,
and the `batch` metadata. It neither reloads nor rebuilds the graph. `shutdown`
returns `result.status: closing`, then ends the input loop. Lifecycle requests
accept only `mode` and `id`. Unsupported fields yield an error rather than
silently changing shutdown behavior.

Successful query responses retain `schema_version`, `mode`, `result`, stats,
warnings, unresolved-node count, path profile and relationship caveats.
Operational request errors have this shape:

```json
{"schema_version":1,"id":"bad-1","error":"Unknown node: MISSING","batch":{"session_id":"opaque-session-id","request_index":2,"elapsed_ms":0.1}}
```

Malformed JSON and oversized input may have `id: null`, because correlation
cannot safely be recovered. Requests are limited to 65,536 characters including
the terminating newline. Oversized lines are drained through their newline
before the next request is read. There is no universal server response byte/token
cap: `limit` caps rows per collection, not property size or all nested evidence.
Use selected properties and enforce a host-side response cap as appropriate.

## Query field map

| Mode | Query fields |
|---|---|
| `summary` | Optional `source`, `target` |
| `triage` | Required `node` principal |
| `objects` | `object_type`, `where` object, `select` property array |
| `findings` | `query` (default `all`), optional `principal` |
| `node` | Required `node` |
| `search` | `query` text (empty allowed) |
| `memberships` | Required `node` principal |
| `members` | Required `node` group |
| `users` | No per-request user-flag filters in this version; use `objects` for exact filters |
| `reachable` | Required `node`, outward traversal |
| `path` | Required `source`, `target` |
| `routes` | Required nonempty `sources` array, optional `target`, `avoid` array |
| `ranked-paths` | Required `source`, `target`, optional `count` in 1..100; requires NetworkX |
| `explain` | Required `source`, `target`, `edge` |
| `gpo-scope` | Required `node` GPO |
| `trust-path` | Required `source`, `target` domains |
| `catalog` | No query-specific fields |
| `ping`, `shutdown` | Only `id`, `mode` |

Query requests also accept `hops`, `limit`, `offset`, and `profile` where applicable.
Unknown or incompatible query-specific fields are rejected. Collection paging
uses `total`, `offset`, `truncated`, `next_offset` (search omits total). A null
`next_offset` means no later page. Ranked paths use `count` and `more_paths`
instead. There is no multi-request array, arbitrary code, request file writes,
or exhaustive/DFS-all-paths request in the batch protocol.

Profiles: `supported` is the default, `potential` adds explicitly conditional GPO
and same-forest SID-history routes, and `raw` exposes uncomposed relationships in
the older path/reach interfaces. Do not treat `found=false` as proof that no
attack exists. Retain conditional markers, prerequisites, warnings, supporting
facts and incomplete-search indicators when creating an oracle/proxy handoff.

## Event-log integration

HARP should record process start, readiness, each request before writing it,
each complete response, transport/protocol errors, and runtime cleanup/exit.
Use HARP's timestamps and assessment/runtime identifiers. Correlate requests
with `id`, replies with `batch.session_id` and `batch.request_index`.

Keep exact request/response objects in the event log under HARP's existing
artifact/log policy. Give the LLM only the useful result projection and preserved
evidence, rather than every protocol envelope. Stderr is a separate diagnostic
stream and must not be mixed into response JSON. Measure startup wall time,
request wall time, server processing time, returned bytes, and the text actually
sent to the model separately. This distinguishes load-time savings from token
savings.

## Reusable Python client

`whippet.client.BatchClient` is a standard-library reference client. It accepts
a complete argv, awaits readiness, serializes requests, checks correlation,
drains stderr into a bounded diagnostic buffer, enforces response-wait timeouts
and an 8 MiB response-character limit by default, and closes the session on
protocol/transport failure. It does not automatically retry. Each instance owns
one process and cannot be restarted; create a new instance after failure.

Example **when Python itself runs inside the selected Kali runtime**:

```python
from whippet.client import BatchClient

# Supply HARP's real event-log writer here. The callback receives dicts.
def record_event(event):
    assessment_event_log.append(event)

argv = ["whippet", capture_path_in_selected_runtime, "--batch", "--batch-ready"]
with BatchClient(argv, event_sink=record_event,
                 startup_timeout=60, request_timeout=30) as client:
    reply = client.request({"mode": "objects", "object_type": "computer",
                            "select": ["name", "operatingsystem"], "limit": 5})
    if "error" in reply:
        handle_query_error(reply["error"])
    else:
        use_selected_evidence(reply["result"])
```

`assessment_event_log`, `capture_path_in_selected_runtime`, and the handling
functions are integration placeholders, not existing HARP APIs. Callbacks emit
`whippet.batch.start`, `.ready`, `.request`, `.response`, and `.error` events.
HARP must add its own cleanup/exit event. Callback exceptions propagate; the
caller is responsible for a working persistence sink. Response-wait timeouts
are enforced on the client reader queue, not inside the graph algorithm.

A pipx installation exposes the `whippet` executable but does not make its
Python modules importable in HARP's separate Python environment. HARP may
implement this small protocol in its existing runtime adapter, or explicitly
install Whippet as an optional dependency in the environment importing this
client. Do not try to import directly from another pipx environment's private
site-packages. A host-side argv such as a selected `wsl.exe -d DISTRO -- ...`
must be constructed by HARP from its chosen runtime; this client never selects
a distribution. Host-launcher termination is not a cross-runtime cleanup guarantee.

## Acceptance checks for the HARP change

- AD-only activation; no Whippet startup on unrelated targets or absent captures.
- Exact selected-runtime use, including capture paths and cleanup on cancellation.
- One startup/readiness event for several queries and stable process/session IDs.
- Requests/responses persisted in HARP's event log and matched by ID.
- Bounded fields/pages passed to the LLM; raw collection blobs stay outside context.
- Query errors leave the session usable; timeout, EOF or malformed replies
  invalidate it without silent retries or runtime fallback.
- Fresh sessions for refreshed captures and normal closure at assessment end.
- Explicit fallback to HARP's existing analysis path if Whippet is unavailable,
  selected by HARP policy and recorded as such, rather than hidden client fallback.

Whippet tests exercise a real subprocess for reuse, projection, error recovery,
callback correlation, shutdown and timeouts. They do not establish a completed
HARP integration or a live Kali/WSL process-tree cleanup test.
