# FS-provenance taint tracking + dropping network ingress symbolization

> **Status: IMPLEMENTED; frozen with the integrity axis (2026-09-28,
> [`protection-modes.md §10`](../architecture/protection-modes.md)).** The record
> stays; nothing here is extended.
>
> **Still running in `secrets` mode.** The provenance registry
> (`arbiter/provenance/`), its proc-key attribution and its process-lineage
> edges are the substrate of confidentiality's flow taint
> ([`confidentiality-plan-10-flow-taint.md`](../confidentiality/confidentiality-plan-10-flow-taint.md)
> §3, which adds a secret level beside the integrity origin stored here), and
> the network layer's no-body-rewrite design (§1) holds in every mode.
> Integrity-only, frozen: untrusted-origin tainting and the taint-driven
> egress branch for untrusted hosts, the AgentView re-symbolization of §4, and
> the dual-view commits the Git/Files tab of §5 reads (fs-sync runs only with
> the integrity axis on, [`fs-sync.md`](./fs-sync.md)).
>
> Companion to [`mandu.md`](../architecture/mandu.md) (the four boundaries,
> the two views, T-LLM/U-LLM, symbols), [`dashboard.md`](../ui/dashboard.md)
> (the trace + the per-tool-call policy modal this extends), and
> [`implementation-plan.md`](../architecture/implementation-plan.md) (§9 the
> e2e invariant oracle). Terminology pairs the paper term with the
> adfi-openclaw repo term, e.g. *AgentView (repo: Agent File System /
> agent-view worktree)*, *T-LLM (privileged LLM)*.
>
> What is built: the taint registry and its fs consumption, net
> observe-and-tag + taint-egress, exec lineage, proc-key attribution (for the
> kernel net-supervisor and for net-proxy), the dashboard Git/Files view, and
> the removal of network ingress symbolization. The full taint chain (fs/exec
> write-taint propagation) runs under the kernel features (`--features
> kernel`); the unprivileged baseline has the model-API proxy + net-proxy
> observe-and-tag + the egress gate. The fs view-sync machinery (`fs-sync/`,
> lifted from the reference `dualview-git.ts` / `dualview-filecommit*.ts`) and
> the reference dashboard are the proven artifacts this extends.

---

## 1. Purpose & the change in one paragraph

Mandu does not symbolize untrusted network data at the **network data plane**.
`net-supervisor`/`net-proxy` `ingress_transform` used to rewrite response
bodies on the wire; **that body symbolization is removed.** Instead, **content
provenance** is established at the OS chokepoints we fully control, so
untrusted-by-origin data is recognized wherever it surfaces (a file read, an
outbound send) rather than caught once on the socket. The network layer keeps
only the jobs nothing else can do (model-API mediation and **egress gating**)
plus a lightweight *observe-and-tag* role (classify the destination host,
`taintProcess` on untrusted-host connects, no body MITM). The privileged-model
invariant is unchanged: it always rested on the **model-API proxy**
(`anthropic-proxy`), which symbolizes `tool_result` spans by tool identity
before **T-LLM** sees them.

### 1.1 Why this is sound, and what it trades

The core invariant (*untrusted data reaches T-LLM only as an opaque symbol*)
is guaranteed by the model proxy alone: anything entering the model
conversation is a `tool_result` the proxy classifies and symbolizes regardless
of how the bytes travelled. Network ingress symbolization was therefore
**redundant for the model invariant**. Its real value was secondary: (a)
keeping raw untrusted bytes from resting on disk, and (b) producing symbols
for the egress gate to act on. This design replaces (a)/(b) with an OS-level
**taint registry** backed by live proc-key attribution.

> **Not a pure win.** We trade a *complete-but-fragile* MITM source-taint
> (symbolize the instant data crosses the socket) for an
> *incomplete-but-robust* OS sink-taint (recognize untrusted content where it
> surfaces) plus the proxy backstop. The **T-LLM invariant is not weakened**;
> only at-rest/exfil coverage now depends on taint completeness (§6). The
> **full taint chain** (net→process→file→reader→egress) is live under kernel
> features; the unprivileged baseline (model-API proxy + net-proxy
> observe-and-tag + egress gate) provides partial at-rest/exfil coverage (§6).

### 1.2 Decisions taken

- **Provenance source: hybrid**: a process→file taint bridge where a writer
  is attributable, with a fail-closed default for orphan/unknown-origin files.
- **Egress: addressed together**: the taint registry also drives a
  destination-based egress gate (tainted process → untrusted host →
  approval), closing the raw re-send gap that dropping inbound symbolization
  would otherwise open.
- **Dashboard: both** an inline per-tool-card commit summary *and* a
  dedicated Git/Files tab, mirroring the reference dashboard.

---

## 2. The new primitive — an arbiter-owned provenance (taint) registry

The arbiter owns the symbol table, policy engine, and event store. This adds a
fourth owned store: the **taint registry**, the single source of truth for
"which content/process is untrusted-by-origin." Persisted in the arbiter's
SQLite, single-writer, alongside symbols.

```
process_taint( proc_key, tainted, origin_host, session, first_seen )
   proc_key = pid + start-time            -- start-time defeats pid reuse

file_taint( key, trust, origin, writer_proc, session, ts )
   key      = content-hash                -- survives rename; re-evaluated on edit
   + path index as a fast secondary lookup
```

### 2.1 Revised chokepoint roles

| Chokepoint | Inbound | Outbound | Change |
|---|---|---|---|
| **Model proxy** (`anthropic-proxy`) | symbolize `tool_result` spans **by tool identity** | record `tool_use` | **unchanged**: the T-LLM-invariant backstop |
| **Net** (`net-supervisor`/`net-proxy`) | *observe only*: classify the **destination host** (SNI/IP, no MITM) → `taintProcess(pid)` on untrusted-host traffic; the body passes **RAW** | **egress gate**: symbol-based *and* taint-driven | body symbolization dropped; observe-and-tag + taint-egress. The fail-closed arbiter-miss (opaque marker) is unchanged. |
| **Local-OS / exec** (`exec-supervisor`/`exec-wrap`) | track process lineage (parent→child) so taint scopes to the invocation | — | lineage reporting |
| **Local-OS / fs** (`fs-supervisor`/`fs-sync`) | on read, `classify()` consults the registry (∪ path policy); symbolize if untrusted | on a tainted-writer write → `taintFile()` | registry read/write + the fast-path fix (§4) |

### 2.2 The `curl … > setup.md; Read setup.md` chain, re-traced

```
1. curl GET example.test
   net observes host=example.test → UNTRUSTED → arbiter.taintProcess(curl)
   NO body rewrite on the wire (raw bytes flow to curl)
2. curl writes setup.md
   fs write: writer=curl tainted? yes → arbiter.taintFile(setup.md, origin=example.test)
3. (if via stdout→tool_result) model proxy symbolizes the Bash result   ← invariant backstop
4. agent Read(setup.md)
   fs read: classify(setup.md) → file_taint hit → UNTRUSTED → symbolize
   git: [MDU-TRUSTED] symbolized twin + [MDU-UNTRUSTED] raw            ← provenance recorded
5. tainted proc tries curl POST out
   net egress: source tainted + dest untrusted → approval required       ← exfil gap closed
```

### 2.3 Precedence (fail-closed)

A read is TRUSTED only if **neither** path policy **nor** the taint registry
says untrusted **and** the file is not orphan/unknown-origin. Any miss, any
arbiter-unreachable → UNTRUSTED.

---

## 3. Taint registry mechanics

### 3.1 Population

| Signal | Chokepoint | Arbiter op | When |
|---|---|---|---|
| `process_taint` | net observe | `taintProcess(procKey, originHost)` | a process connects to a host the inbound policy classifies UNTRUSTED (tag on connection-established; no body inspection) |
| `file_taint` | fs write | `taintFile(contentHash, path, originHost, writer)` | a **tainted** process writes/creates a file |
| `file_taint` (declared) | model-context exec gate | `ProvenanceStore.declareNetWrite(path, originHost, session, callId)` (arbiter-internal, from the `execGate` op) | an ALLOWED `curl -o` / `wget -O` / fetcher-fed `>`/`tee` declares its output net-written: the wrapper layer's substitute for the observed write ([`exec-routing.md`](./exec-routing.md) §8.7.1, the provenance gate). Synthetic hash `declared:<session>:<path>`; relative paths session-scoped |
| lineage | exec | `processLineage(childKey, parentKey)` | every spawn |

### 3.2 Propagation — granularity and the fail-closed boundary

Taint tracking is undecidable in general, so we commit to a coarse-but-safe
unit: the **exec invocation** (the process subtree/group rooted at the shell
the Bash tool spawned). *If any process in an invocation touches an untrusted
host, the whole invocation is tainted.* This matches the reference (an exec's
output is one untrusted blob) and avoids per-fd pipe dataflow tracking.

Edges we **do** propagate (all cheaply observable at chokepoints we own):

- **network → invocation**: an untrusted-host connection taints the whole
  subtree.
- **parent → child**: a child of a tainted process is tainted (covers
  `curl … | tool`, subshells).
- **file → reader**: reading a taint-registered file taints the reader
  (powers taint-egress).
- **tainted process → file**: its writes taint the file.

Edges we **don't** track precisely: pipes/unix-sockets between *unrelated*
invocations, shared memory, env-var laundering across invocations, a daemon
that fetches now and serves later. Mitigations: (1) invocation-level tainting
swallows the common shell-pipeline case; (2) the **model proxy still
backstops the T-LLM invariant** however data launders, so a laundering miss is
an *exfil* miss, never model contamination; (3) anything ambiguous resolves
UNTRUSTED.

### 3.3 Consumption

- **fs read (inbound):** `classify()` = `path_policy(path) ∪ file_taint(hash,
  path)` + the orphan fail-closed default. Untrusted ⇒ symbolize (fs-sync
  machinery).
- **net egress (outbound):** `egressDecision()` returns "approve" if
  **either** the payload has symbols the symbol gate denies **or** the source
  process is tainted and the destination is untrusted (content-agnostic).
- **model proxy:** consumes nothing new.

### 3.4 Components & IPC (arbiter-client pattern, per [`CONTRIBUTING.md`](../../../CONTRIBUTING.md))

- **`arbiter/provenance/`**: the two tables + ops `taintProcess`,
  `taintFile`, `processLineage`, extended `classify`, extended
  `egressDecision`. Single-writer, like the symbol table.
- **net**: `ingress_transform` body symbolization replaced by
  `observe_and_tag` (host classify → `taintProcess`); `egress_transform`
  augmented with the taint branch.
- **exec**: emit `processLineage` on spawn; carry the invocation/group id.
- **fs**: `taintFile` on tainted-writer writes; `classify` consults the
  registry on read.

Each interceptor keeps its narrow `Arbiter` interface + in-test mock.

---

## 4. FS integration & the AgentView fast-path fix

### 4.1 The leak to close

The read fast-path was *"AgentView file exists → return as-is"*
(`fs-sync/src/view-sync.ts`), safe only because AgentView files were always
pre-symbolized. But a **tainted child process** (`curl -o setup.md`, running
in AgentShell with FS→AgentView) writes **raw bytes straight into the
AgentView worktree**, and the fast-path would serve them raw.

### 4.2 Fix — re-symbolize at read and at sync, never rewrite `write()` inline

We **do not** rewrite child-process `write()` buffers inline: seccomp-unotify
can redirect an fd but cannot cleanly mutate write payloads, and ptrace
byte-rewriting is brittle. Instead we use the two points where fs-sync already
transforms content, and let raw land in AgentView only transiently:

**1. Read path (close the fast-path):**
```
AgentView file exists →
   hasSymbols(content)?  → serve (already symbolic)
   else classify(path ∪ file_taint, content-hash):
        UNTRUSTED → symbolize inline + persist into AgentView → serve symbol
        TRUSTED   → serve raw
   (arbiter miss / orphan → UNTRUSTED, fail-closed)
```
The inline-symbolize machinery (`symbolizeContent` → `arbiter.symbolize`)
already existed; we stop trusting "exists ⇒ clean."

**2. Post-tool-call sync (keep the commits honest):** `syncToHuman`, before
the `[MDU-TRUSTED]` commit, symbolizes into AgentView any changed AgentView
file that is taint-registered untrusted **and still raw** (symbol → trusted
twin), with raw written to HumanView (→ `[MDU-UNTRUSTED]`). The `mdu-trusted`
branch then only ever holds symbols; trusted/untrusted commit semantics stay
as the reference defined them.

Raw untrusted bytes thus exist in AgentView only in the window between a child
write and the next read-or-sync, and **both** re-symbolize fail-closed.

### 4.3 classify() extension & git layer

`fs-supervisor`'s `first_touch_classify` (`decision.rs`) hashes content and
passes `contentHash` to `arbiter.classify`, which unions path policy with the
`file_taint` lookup. Commit labelling is unchanged (AgentView→`[MDU-TRUSTED]`,
HumanView→`[MDU-UNTRUSTED]`); the only new input is *where* the untrusted
verdict came from. Optional enrichment: an `origin=url:example.test` commit
trailer for taint-sourced files, so the dashboard can show provenance. The
`[MDU-HUMAN]` blame-resymbolization path is untouched (§10).

---

## 5. Dashboard — inline summary + dedicated Git/Files tab

### 5.1 Data flow — events for the cheap stuff, git for the detail

- **`fs_commit` event (lightweight)**: `fs-sync` emits one per commit:
  `{ kind:"fs_commit", callId, hash, trust:"TRUSTED"|"UNTRUSTED"|"HUMAN",
  files[], origin, boundary:"filesystem", emitter:"fs-sync" }`. Powers the
  inline summary + live updates; no diffs in the event.
- **the developer view's `git.ts`** (lifted from the reference dashboard's
  `api/git.ts`) reads the workspace's dual-view history (the fs-sync shadow
  repo, [`fs-sync.md`](./fs-sync.md)) on demand for the detail pane: unified
  diff, AgentView vs HumanView content, parsed metadata. Its regex matches
  the `[MDU-TRUSTED|UNTRUSTED|HUMAN] mdu: tool=… callId=… run=… files=…`
  commits and the reference's original `adfi:` ones. The session's workspace
  path is resolved from the session's OWN events
  (`dashboard/src/session-paths.ts` `sessionViewRoots`): the deepest common
  ancestor of the HumanView-side paths on its `fs_action` Redirects
  (`input.original`) **and** its `path_rewrite` typed-path fields
  (`rewrite.human`, which covers wrapper-layer `--fs-sync` runs that have no
  kernel fs-supervisor and hence no `fs_action` events). No arbiter op is
  needed; the events already carry the paths.

### 5.2 Inline per-tool-card summary (main trace)

- **view-model**: `groupToolCalls` attaches `fs_commit` events to the matching
  `ToolCallGroup` by `callId` → `group.files: CommitRef[]`.
- **app.js**: a `files` phase in the card (ordered after `output`): a compact
  `files: ●T 9f3e  ●U a1b2` line, green/red dots; click → the Git/Files tab
  focused on that commit.

### 5.3 Dedicated Git/Files tab

The reference dashboard's layout, commit sidebar + detail pane:

```
COMMITS (sidebar)            DETAIL (pane)
 ● a1b2  U   setup.md         ● a1b2c3  [UNTRUSTED]   ← trust-badge
 ● 9f3e  T   setup.md         tool=Bash call=toolu_01..  run=..  origin=url:example.test
 ● 7c2d  T   notes.md         ── diff ──────────────────────────
 ● 5e1a  H   notes.md         AgentView : + $MDU:web_fetch[..]
                              HumanView : + <real html>
 ● green=TRUSTED  ● red=UNTRUSTED  ● gray=HUMAN
```

Human-edit commits (`[MDU-HUMAN]`, gray) appear only in the tab (no `callId`
to inline against). The reference's six-step inline commit flow is not ported;
the per-card `●T/●U` summary gives at-a-glance trust.

**No blank main frame.** The tab covers the trace, so: the toggle has a
visible active state; a session with no dual-view commits renders an empty
state naming the view with a one-click way back to the trace; the view is not
restored from local storage on load; and `GET /api/git` carries a
server-computed `emptyReason` when `commits` is empty, naming the truthful
cause (the session ran without the dual-view FS layer, the expected state for
every model-proxy-only run; or no dual-view history exists under the resolved
workspace). Pinned by `git-routes.test.ts`.

### 5.4 Changes by file

- `dashboard/src/event-model.ts`: the `fs_commit` kind + fields.
- `dashboard/src/view-model.ts`: attach `fs_commit` → `ToolCallGroup.files`.
- the developer view's `app.js`: the `files` phase + Git/Files tab render.
- the developer view's `git.ts`: `GET /api/git?session=&commit=`.
- `dashboard/src/server.ts`: wire the route.
- `fs-sync`: emit `fs_commit`.

---

## 6. Issues & risks

### A. Foundational — the taint chain's weak links

- **Socket→process attribution.** Everything starts with "net knows which
  process connected." The `/proc` scan (`/proc/net/tcp{,6}` inode →
  `/proc/<pid>/fd`) is the **permanent mechanism** at both layers; it races
  short-lived processes. eBPF (sock→cgroup→pid, attached at connect) would
  not race, but it needs root/CAP_BPF on the host, so it **will not be
  implemented** (a standing decision under the non-root principle,
  [`privilege-model.md`](../architecture/privilege-model.md) §0), and neither
  will its "taint the whole invocation/session" escalation. On attribution
  failure the `/proc` baseline degrades to "no tag on this connection"
  (documented in `conn_attr`); the model-proxy backstop is unaffected. This
  is the load-bearing reliability dependency.
- **Propagation incompleteness (laundering).** We track net→invocation,
  parent→child, file→reader at invocation granularity. Not tracked:
  pipes/unix-sockets between unrelated invocations, shared memory, env-var
  laundering, fetch-now-serve-later daemons. *Boundary:* the model proxy
  backstops the T-LLM invariant regardless, so a laundering miss is an exfil
  miss, never model contamination; orphan data is fail-closed.

### B. Security-coverage limits (documented holes)

- **Host classification without MITM.** SNI may be absent (ECH), IP
  literals and DoH hide the host. *Mitigation:* an unclassifiable host is
  UNTRUSTED; a trusted-host allowlist is needed.
- **Taint-egress is coarse.** Process+destination level: a tainted process
  sending to a *trusted-but-readable* host (an allowlisted pastebin) is not
  caught, and a process tainted by one untrusted read is blocked from *all*
  untrusted-host sends. *Boundary:* symbol gating still catches precise
  cases; taint-egress is the coarse net for raw, with the same
  trusted-host-exfil hole any destination policy has.
- **Net change in guarantees.** See §1.1: the T-LLM invariant is not
  weakened; only at-rest/exfil coverage depends on taint completeness.

### C. Usability — the main tuning surface

- **Over-tainting.** `npm`/`pip`/`git` registry fetches would taint installs
  → the toolchain reads symbols → breakage. *Mitigation:* a
  **trusted-source allowlist** (model API, registries, internal hosts) so
  common fetches stay TRUSTED. The primary tuning surface; too broad reopens
  the network-trust hole.
- **Transient raw-in-AgentView window** (§4.2): bounded by the next
  read/sync, both fail-closed; residual risk accepted.
- **file_taint keying/persistence.** Content hash (survives rename) + path
  index; on edit, inherit taint from the path ancestor (fail-closed, ties into
  git blame). Persists in arbiter SQLite across sessions; needs a
  GC/retention policy.

### D. Lesser

Performance (hash on first touch only; indexed lookups); byte-level →
whole-file fidelity loss in the dashboard; exec AgentShell/HumanShell
composition (taint applies regardless of shell mode); dashboard
workspace-path resolution + lazy git diffs.

---

## 7. Testing — invariant oracles (per implementation-plan §9)

1. **Chain re-trace, net symbolization OFF:** `curl > f; Read f` → T-LLM sees
   a symbol (via taint→fs), HumanView raw, git has
   `[MDU-TRUSTED]`+`[MDU-UNTRUSTED]`.
2. **Fast-path leak:** a tainted child writes raw into AgentView → the next
   read returns a **symbol**.
3. **`curl -o` (no stdout):** the file never transits a `tool_result` → the
   read still symbolizes.
4. **Taint-egress:** tainted→untrusted host = approval; tainted→trusted host
   = allowed (documented hole); untainted→untrusted = per policy.
5. **Propagation:** parent→child subshell, file→reader, net→invocation.
6. **Fail-closed:** arbiter down → UNTRUSTED/withhold; unattributable socket
   → conservative taint.
7. **Over-taint guard:** allowlisted-host fetch → NOT tainted.
8. **Dashboard:** `fs_commit`→inline join by `callId`; `git.ts` parse; tab
   trust colors (unit + e2e).

---

## 8. Out of scope / deferred

- Inline child-process `write()` content rewriting (we re-symbolize at
  read/sync instead).
- Per-fd pipe/IPC dataflow taint (invocation-level granularity instead).
- The reference's six-step inline commit flow (per-card `●T/●U` summary
  instead).
- Finer-than-process egress correlation (byte-level outbound matching).

## 9. Reuse posture

High reuse: the fs view-sync (`fs-sync/`) ports the reference's
`dualview-git.ts` / `dualview-filecommit*.ts`; the dashboard lifts `api/git.ts`,
the sidebar/detail render and the trust styling with workspace-path and theme
adjustments. New code is concentrated in `arbiter/provenance/` and the net
observe-and-tag / taint-egress paths.

## 10. File symbol fields and human edits

The arbiter owns symbol naming. A filesystem path remains the original
`SymbolEntry.field`, while the symbol's wire suffix may use the canonical
`__mdu_field_` encoding to fit the shared scanner grammar
([`mandu.md §9`](../architecture/mandu.md)).
Consumers must not derive provenance by decoding that suffix.

When a human changes part of a symbolized file, fs-sync retrieves the original
field through the arbiter `symbolProvenance` operation, appends
`.__mdu_split[n]` to that original field, and supplies the original parent
symbol as `derivedFrom`, with the same end-exclusive `lineRange`. The arbiter
encodes the resulting field when allocating the child. Human-authored changes
become literal in AgentView (repo: Agent File System / agent-view); untouched
bytes remain symbolic. HumanView (repo: Human File System / human-view) keeps
the original bytes plus the human edit.

The lookup is optional for older adapters. A present `field: null` means the
parent has no field. Missing field metadata permits only the legacy plain-tail
fallback; a reserved encoded suffix without original metadata stops the split.
Lookup errors propagate before derived allocation or AgentView rewriting.
There is no raw-content fallback, symbol-database access, or local decoder.

Git path enumeration uses NUL-delimited `ls-files -z` and `status --porcelain
-z -uall`. Quoted newline-delimited output once caused Unicode paths to be
skipped during initial symbolization and human-edit scans, an AgentView
raw-content security regression (the model proxy is a separate ingress
boundary, but the AgentView must hold no raw untrusted bytes). Literal
NUL-delimited paths drive both initialization and the leak audit. Rename
source records are consumed as metadata, not mistaken for another changed
file.

Tests: original-field and lineage unit checks, missing-provenance and
lookup-failure checks, real git filename enumeration, and a real arbiter IPC
plus real filesystem/git round trip for a nested Unicode path, asserting raw
bytes are absent from AgentView before and after a partial human edit, child
field metadata stays original, and only the human's changed line is literal.

## 11. Could provenance replace symbolization? (explored, no)

A recurring question: since the taint registry above does provenance without
any token, could the symbol be dropped and T-LLM read raw tool results behind
a provenance-based egress gate? **No.** The `$MDU:*` token does three jobs at
once: **isolation** (T-LLM never reads the untrusted bytes, so an injected
instruction cannot steer it), an **exact tracer** through the model (the token
passes through unmodified, which is what lineage and `DualRepr` key on), and
a **decidable gate predicate** ("does this payload contain symbol X?" is
syntactic; "is this text derived from untrusted input?" has no decision
procedure, and fail-closed needs a decidable one).

Attribution survives without symbols (the OS chokepoints already do it), but
tracking *through the model* does not: an LLM context is one large implicit
flow, so a token-free tracer either over-approximates (every output after an
untrusted read is tainted by all of it, a per-context influence set with a
large approval bill) or under-approximates (substring / fingerprint /
embedding matching at egress, which an attacker defeats by paraphrase;
white-box attribution is unavailable through the API). And even perfect
data-flow provenance does not stop injection: a command the model was talked
into contains zero untrusted bytes. **Provenance is downstream of isolation,
not a substitute for it.** Independent designs that track provenance through
an LLM (the dual-LLM pattern's `$VAR` handles, CaMeL's variables) converge on
the same opaque handle.

Recorded, unscheduled descendants: *selective symbolization* (pass provably
inert, schema-constrained fields through with provenance records but no
token; un-defer only on measured utility loss the U-LLM path does not absorb,
starting from the per-schema verdicts of `claude-code-inbound.ts`, never
per-content guessing); *egress fingerprinting* of known secret values and
untrusted spans as defense in depth beside symbolization, never as the
invariant; and *influence sets over the whole agent loop*, a different
architecture rather than a rung on this one.
