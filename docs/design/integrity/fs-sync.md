# fs-sync and the portable FS core: AgentView ↔ HumanView sync

> **Frozen with the integrity axis (2026-09-28)**
> ([`protection-modes.md §10`](../architecture/protection-modes.md)). The record
> stays; nothing here is extended. Everything in this document runs only
> when the integrity axis is ON (`injection`, `full`, behind
> `MANDU_EXPERIMENTAL_INTEGRITY=1`). In the default `secrets` mode (and in
> `off`) fs-sync is off by design (`fsSyncOffReason: "mode"`, §1.6 P5): there
> is no AgentView worktree, no view map (`MANDU_VIEW_MAP` is unset, so the
> proxies rewrite no paths, §1.3), and no sensitive-path gate (§1.4.1: the
> proxies run it only while a view map is active). `mandu revert` (§3.8b) is
> still a command in every mode, but it has history only for workspaces
> opened in `injection` or `full`; elsewhere it answers "no Mandu history".
> What `secrets` mode uses instead: the guard's open trap and the secret
> twins for secret paths ([`confidentiality.md`](../confidentiality/confidentiality.md)
> §7.2), the derived write label (which runs without a view map), the
> hiding of Mandu's state directory and the git object-store twins
> (confidentiality.md §7.2a, and §3.8 here), and the guard's `protect:`
> trap (§3.8b), which runs in every mode but `off`.

This document is the record of the filesystem chokepoint ② at the
cooperative (wrapper) layer under the integrity axis, in three parts:

- **§1, the portable FS core** (decision note, 2026-07-05): the chokepoint is
  proxy path-rewriting + CWD scoping + fs-sync, a userspace stack that runs
  the same way on Linux, macOS and Windows; kernel mechanisms are the
  upgrade path, not the baseline.
- **§2, the sync cadence** (built 2026-07-09): the AgentView → HumanView
  sync fires at every tool-call boundary, and human edits flow back at the
  same cadence.
- **§3, the shadow repo** (built 2026-07-19): all of fs-sync's git state
  lives in a private shadow repository beside the user's workspace, never in
  the user's own git; ignored files and `mandu revert` build on it.

Companions: [`architecture-map.md §9`](../architecture/architecture-map.md)
§② and [`architecture-map.md`](../architecture/architecture-map.md) (this fills
the "② fs × cooperative" cell); the wrapper-limits analysis it answers is
[`privilege-model.md`](../architecture/privilege-model.md) §3.1. The reference
design is [`fs-level-tracking.md`](../../adfi-reference/design/fs-level-tracking.md)
and [`human-edit-policy.md`](../../adfi-reference/design/human-edit-policy.md).

## 1. The portable FS core

### 1.1 Why this stack

The baseline has to be easy to deploy yet robust on three OSes. That rules
out every mechanism with a kernel touchpoint as the *baseline*:

| Mechanism | Linux | macOS | Windows | Deploy friction |
|---|---|---|---|---|
| **rewrite + CWD + fs-sync** | ✓ | ✓ | ✓ | none: userspace, lives in the proxy Mandu already ships |
| userns bind-mount overlay | ✓ | ✗ | ✗ | Linux-only; probe + distro matrix (Ubuntu userns AppArmor) |
| `LD_PRELOAD` (`fs-preload`) | ~ | ✗ SIP | ✗ | injection fragility; crash blast radius inside the user's own processes |
| FUSE (macFUSE / WinFsp) | ✓ | ~ kext | ~ driver | kernel drivers |
| microVM (libkrun) | ✓ | ✓ | ~ | the cross-OS *hard* tier, deferred |

Two robustness points decide it:

- **Blast radius.** The overlay's worst case is a failed launch (visible).
  The rewrite's worst case is bounded by the conservative rules of §1.3.
  Preload's worst case is misbehavior inside the user's own processes.
- **The schema work is already paid.** The context proxy must parse every
  agent family's `tool_use`/`tool_result` for symbolization regardless;
  rewriting rides the same parser and only adds "which fields are paths".

### 1.2 Division of labor (with the worked example)

Setup: HumanView `/home/user/project/webapp/` (real bytes); AgentView
worktree `~/.mandu/state/workspaces/<id>/agentview/` (untrusted spans
replaced by `$MDU:*`); the arbiter holds the symbol table; `fs-sync` keeps
the two trees in step (blame-based re-symbolization into the AgentView;
policy-gated desymbolization out).

| Component | Handles | Example |
|---|---|---|
| **CWD scoping** | every *relative* path | `Read("vendor/notes.txt")` resolves inside the AgentView worktree and returns `$MDU:9x2` |
| **proxy rewrite** | *absolute* paths **on the model wire, both directions** | the model emits `Read("/home/user/project/webapp/vendor/notes.txt")`; the proxy rewrites the prefix, so the agent opens the AgentView copy; tool_result errors naming `~/.mandu/state/workspaces/<id>/agentview/...` are reverse-mapped so T-LLM only ever sees HumanView paths |
| **fs-sync** | the *state*: two renderings of one tree | the agent's `Edit` lands in the AgentView and syncs to the HumanView (desymbolizing, policy-gated) per tool call (§2; `--no-fs-sync-eager` falls back to the post-exit sweep, which runs either way); human edits sync in (re-symbolized by blame) |
| **context backstop** | whatever slips past all three | a raw read that does happen still comes back as a `tool_result`, which is classified fail-closed and symbolized before T-LLM sees it |

U-LLM is orthogonal: `inspect_symbol` output is contained by
**re-symbolization** (it returns a fresh symbol), never by rewriting; its
channel bypasses the proxy.

### 1.3 The rewrite, precisely (conservative rules)

1. **Bidirectional prefix map**, one pair per workspace root:
   `HumanView-root ↔ AgentView-root`. Forward on response `tool_use` args;
   reverse on request `tool_result` content. Idempotent (AgentView-prefixed
   input passes through the forward map unchanged). Free-text matches are
   segment-bounded on both sides, with one direction-scoped asymmetry: in
   **reverse**, a sentence period or ellipsis right after the bare root is a
   valid boundary (`<root>. Next sentence` rewrites; `<root>.bak` never
   does), because the CLI's tool-error prose names its CWD (the worktree
   root) at sentence ends and over-mapping in reverse errs toward
   confidentiality; forward, a `Bash.command` ending in `.` can legitimately
   spell a file named `ws.`, so forward keeps the strict token rule.
2. **Field-level, registry-driven.** Rewrite only *path-typed fields* of
   agents in the supported registry (Claude Code: `file_path`/`path`/
   `notebook_path`, plus textual prefix substitution inside `Bash.command`;
   Codex: `shell` strings + `apply_patch` headers). The anthropic-proxy takes
   the list per session from the arbiter's gate surface
   (`arbiter/policy/tool-gate-surface.ts`, the `gateSurface` op): OpenCode
   `read/write/edit.filePath` + `bash.command` (+ `bash.workdir`), OpenClaw
   `read/write/edit.path` + `exec.command` (+ `exec.workdir`, the
   `apply_patch` headers); the sensitive-path gate (§1.4.1) and the derived
   on-disk label read the same table
   ([`agent-e2e-harness.md`](../testing/agent-e2e-harness.md) §7 item 7).
   **Never rewrite content-typed fields** (`Write.content`,
   `Edit.new_string`, …): this removes the use-vs-mention corruption class.
3. **Unknown tool / unknown agent ⇒ no rewrite**: fall back to CWD +
   backstop + the policy gate, and report the degraded mode.
4. **Lexical normalization before matching**: `~`, `..`, doubled
   separators; on Windows the map speaks the local dialect (drive letters,
   backslashes, case-insensitivity, UNC).
5. **Streaming**: `tool_use` args arrive as partial-JSON deltas; buffer per
   tool_use block, rewrite, re-emit as one delta. Local to the response
   relay; the upstream (auth-sensitive) request path is untouched.
6. **Sensitive-path policy gate** at the same hook: a tool_use targeting
   paths outside the workspace with no AgentView twin (`~/.ssh`, `/etc/…`)
   is deny/approve via the arbiter's data-usage policy: a *gate*, not a
   redirect (§1.4.1).
7. **Version-pinned adapter tests** per supported agent, as the context
   adapters already require.

The launcher's fs-view service runs before the context proxy and hands it
the root pair via `MANDU_VIEW_MAP` (an adopted leftover proxy keeps its own
map). The map is applied to the request AFTER symbolization, so the symbol
table keeps raw originals, and it covers tool_result content, the echoed
assistant tool_use args (the client echoes the forward-mapped form back as
history) and conversation free text: the client machine-generates user text
too (an @-mention is pre-read client-side against the AgentView CWD and
recorded as a `<system-reminder>` user block spelling the twin path, caught
by the E28 no-agentview-path-in-model oracle). Thinking blocks are never
touched (signature), and the agent's own system/env text stays as is. The
Codex walker (`openai-proxy`) maps user/assistant `message` items the same
way.

### 1.4 Honest limits (the four gap classes)

The rewrite operates on **names in text**; the filesystem enforces on
**objects at resolve time**. The residue, and what absorbs each:

| # | Gap class | Example | Absorbed by (this tier) | Closed by (later) |
|---|---|---|---|---|
| 1 | name never on the wire: runtime-computed paths and second-order opens by executed programs | `cat $(echo … \| base64 -d)`; `npm test` opening hundreds of files | context backstop (reads); **not** writes/exfil side effects | kernel `openat` trap / microVM |
| 2 | name present but not textually recognizable | `~/…`, `a/../b`, case games | lexical normalization (partial) | kernel (VFS resolves) |
| 3 | name resolves elsewhere: aliasing | a symlink planted in the AgentView pointing at raw HumanView paths | fs-sync **refuses to materialize symlinks** (P5: repo-tracked links neutralized to an inert marker at init; sync/read/write/reconcile refuse to follow links in either view) | kernel/microVM |
| 4 | name is data, not address (use-vs-mention) | a path inside `Write.content` | rule 2 of §1.3 (never rewrite content), by construction | n/a |

These are documented residue; `privilege-model.md` §3.1 states the same
boundary. The invariant survives via the backstop; the *action-side*
guarantees for classes 1–3 wait for the ladder (§1.5).

### 1.4.1 P3 decision — the sensitive-path gate (2026-07-05)

The gate answers one question at the same response-side `tool_use` hook the
prefix map owns: **may tool T touch absolute path P (mode read|write)?** It
runs only while the view map is active (the map is how the proxy knows the
workspace roots), so only with the integrity axis ON.

- **Decision in the arbiter** (`policy/fs-outbound.ts`, pure `decideFsPath`
  + IPC op `fsPathDecision`), rule order with **deny-precedence**:
  1. built-in sensitive list (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`,
     `~/.netrc`, `~/.git-credentials`, `/etc/shadow`, `/etc/sudoers`,
     agent credentials `~/.claude*` / `~/.codex`, …) → deny/approve; wins
     even over a workspace match (a workspace rooted at `~` must still gate
     `~/.ssh`);
  2. inside a workspace root (HumanView or AgentView) → allow;
  3. `DIR` trust-category allowlist (policy file; honored ONLY in allowlist
     mode: the intrinsic blocklist-empty default classifies everything
     TRUSTED, an ingress semantic that must not become an egress allow) →
     allow;
  4. **default: out-of-workspace ⇒ deny + requiresApproval** (fail-closed).
- **Deny/approve, not just deny**: the op is wrapped by the SAME
  egress-approvals queue as the network gate (entries keyed
  `fs:<tool>:<mode>` × path), so the dashboard queue and
  `resolveEgressApproval` work unchanged; a human "approve" flips the next
  identical attempt to allow.
- **Enforcement on the wire** (proxy, `src/fs-gate.ts`, SSE and buffered
  JSON): a denied `tool_use` is NOT stream-aborted and NOT morphed into text
  (both risk client compatibility); its path field is rewritten into the
  reserved namespace **`/mandu/denied/<reason>/<orig>`**. The tool then
  fails at execution (nothing exists under `/mandu`) and the session
  continues. When every path of the call was denied, the error
  `tool_result` is replaced by Mandu's notice (the path, the plain reason,
  the arbiter's reason; no byte of the tool's error forwarded), since
  2026-10-04 (confidentiality-plan-10 §11.8, "Path denials"). The original object is never touched, and the sentinel is not
  an AgentView twin. Arbiter unreachable ⇒ the same sentinel with reason
  `unreachable` (fail-closed). Each denial emits an `fs_action` event.
- **Scope** (conservative): typed path fields of registry tools, absolute
  paths and the relative ones it can place (below). `Bash.command` strings
  are the exec chokepoint's turf (documented residue here). A path field may
  hold an array (every string element gated; a denied one becomes the
  sentinel in a copy of the array); a `refs: "media"` field is read as
  OpenClaw's media references (`@path`, `MEDIA:` and `file:` URLs resolved
  to the path; http(s), `data:` and `media://` left to the net gate)
  ([`supported-agents.md`](../agents/supported-agents.md) §2.1); a patch
  tool's file headers (OpenClaw `apply_patch`, parsed by `apply-patch.ts`)
  reach the gate as synthetic fields: every header path is judged as a
  write, and a denied one refuses the whole patch instead of a sentinel. The
  view map rewrites header paths only, never a content line.
- **Relative paths** (`fs-gate.ts resolveRelative`). A relative path is
  only as checkable as its base, and the base is the agent's, not the
  proxy's:
  - **OpenCode** joins every relative path to its instance directory, fixed
    for the session (the directory it started in unless its argv names
    another). The gate surface marks it `relativeBase: "launch"`, the
    launcher names that directory in HumanView spelling (`MANDU_AGENT_CWD`,
    `agentStartDir`, only when the argv cannot have moved it; a listening
    proxy naming another base is never adopted), and the gate joins,
    normalizes and judges the absolute path like any other. Exact, because
    the agent joins the same base. The derived label keys a relative write
    on the same absolute path.
  - **Claude Code** resolves against its current working directory, which
    follows the shell's `cd`; the proxy never sees that state, and
    resolving against the launch directory would judge a different file than
    the one the tool opens, so it claims no base. Decided (2026-10-17):
    Mandu does not set Claude Code's own
    `CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR=1` (present in 2.1.302, the
    only route to a base known in advance: it puts the shell back in the
    project directory after every `Bash` call). It changes what the agent
    does for the person (a `cd` no longer carries to the next call), and it
    would not pin the base alone (`EnterWorktree` moves the session's
    directory). So this gate keeps claiming no base for Claude Code and the
    residue below stands for it (the gate is frozen with the integrity
    axis). The confidentiality axis needs no base in advance: it reads a
    Claude Code file tool's relative path at the file the agent then
    opened, as the kernel guard saw the open, and a `Bash` call's relative
    tokens in the directory the kernel says its shell started in, which is
    where the last call's `cd` or `EnterWorktree` left the session
    ([`confidentiality.md`](../confidentiality/confidentiality.md) §6,
    "The base follows the shell").
  - **OpenClaw** resolves `read` / `write` / `edit` / `apply_patch` against
    its workspace root and `exec.workdir` against the cwd its embedded
    runner `chdir()`s to. The launcher pins the workspace to the launch
    directory for the shapes whose loop runs in the launch
    (`agent-config.ts fenceOpenclawWorkspace`), so OpenClaw claims
    `"launch"` too, with `agentStartDir` set for exactly those shapes and
    only without `--agent` (a non-default agent without a workspace of its
    own works in `<launch dir>/<id>`). A Gateway client, a wrapper or an
    `--agent` launch gets no directory, so its base is unknown.
  - With **no known base**: a path that leaves the working directory (`..`
    leads after lexical normalization: `../x`, `a/../../x`) is denied
    without asking the arbiter (sentinel `/mandu/denied/unresolved/<path>`,
    rule `proxy:relative-escape`, fail-closed; the model reads that it
    should name the file absolutely). A path that stays under the working
    directory (`notes/a.md`) is NOT gated here, and this cannot be made sound
    at the proxy: under an unknown base `.ssh/id_rsa` is harmless in a
    project and a secret in `$HOME`.
  - **What backs that residue**: (1) CWD scoping (a Claude Code or OpenCode
    agent runs in the AgentView worktree, where a relative path lands on
    AgentView copies); (2) the guard's open trap
    ([`confidentiality-plan-10-flow-taint.md`](../confidentiality/confidentiality-plan-10-flow-taint.md)
    §4.1a), which performs every open itself from the tracee's own cwd or
    dirfd and judges the file actually opened, so a registered secret
    reached by any relative spelling gets its twin or `EACCES` (not under
    `--no-net-guard`, or on a host without seccomp user notification); (3)
    the secret twins of the whole-agent wrap (confidentiality.md §7.2); (4)
    the derived label, which refuses an unkeyable relative write from a high
    session; (5) the context backstop. None of these enforces the gate's
    out-of-workspace default deny for a non-secret file; that part of the
    gate covers absolute and placed paths only.
- **Gate BEFORE the forward map, on the HumanView (requested) path.** The
  sensitive list is HumanView (`~/.ssh`, …); if the forward map rewrote a
  path into its AgentView spelling first, rule 1 could never recognize it.
  So the proxy composes **gate → map**: a denied field becomes the sentinel
  (which the map leaves alone, being under no root); an allowed field is
  forward-mapped for execution. Corollary: the proxy submits **every**
  absolute path to the arbiter, in-workspace ones included, and does not
  short-circuit `withinRoots` locally, or deny-precedence for a sensitive
  path nested inside a workspace root would never run.
- **The streaming carrier is fail-closed too.** The SSE tool_use rewriter
  buffers a block until it can transform it. At abnormal termination (a
  `message_stop` with a block still open, or a stream cut mid-block) it
  NEVER releases the buffered block untransformed: a block whose assembled
  input parses is rewritten + gated and closed with a synthetic stop; one
  whose input does not parse is dropped. The per-decision arbiter await is
  bounded by a timeout, so a wedged arbiter fails closed to the
  `unreachable` sentinel rather than stalling the model turn.

### 1.5 Position on the ladder

This stack is the portable floor of the fs row. Upgrades slot in without
redesign (same arbiter, same AgentView state, different redirect point):
Linux hosts that pass a userns probe could swap the rewrite for a
**bind-mount overlay** (AgentView mounted *over* the HumanView path,
caps dropped, closing gap classes 1–3; the worktree `.git` back-pointer
needs reshaping under an overlay); the **microVM** is the eventual hard
tier on all three OSes
([`privilege-model.md §6`](../architecture/privilege-model.md)). The
launcher probes and **reports the active rung**: truth in labeling is part
of the product. (`fs-preload` is retired: in tree, wired to nothing.)

### 1.6 Implementation (phases P1–P5, all built)

1. **P1, CWD → AgentView** (the launcher's `fs-view` service): the AgentView
   worktree is seeded at session start and the agent launched inside it,
   default-on for git workspaces while integrity is ON.
2. **P2, prefix map + rewrite in `anthropic-proxy`**: response-side
   tool_use rewriting (`src/sse-rewrite.ts`, buffered-JSON twin) and
   request-side reverse mapping (`src/view-map.ts`), §1.3. Tests:
   normalization, idempotency, Windows dialect, field-level registry,
   stream chunking; e2e `test/component/view-map-rewrite.test.ts`
   (absolute-path `Read` of the untrusted file forward-maps and returns
   symbols end to end; error paths reverse-map).
3. **P3, the sensitive-path gate** (§1.4.1). e2e: a sensitive Read denied
   on the wire while a workspace Read in the same response flows;
   unreachable fails closed; JSON path parity.
4. **P4, parity in `openai-proxy` (Codex)**: the same map on the Responses
   wire (`src/view-map.ts` copies the ViewMap core with provenance;
   `src/sse-rewrite.ts`). Codex's path surface is the free-text shell
   command (`function_call.arguments.cmd` / `command` argv), the analog of
   `Bash.command`: forward-map the command of each response `function_call`
   across every argument-bearing event (delta buffered + re-emitted as one,
   `.done`, `output_item.done`, `completed`) and the `stream:false` JSON
   twin; a stream cut after the deltas but before `.done` forward-maps the
   accumulated arguments and closes the item; reverse-map
   `function_call_output` (string or array of parts) plus the echoed
   `function_call` args after symbolization. **No sensitive-path gate for
   Codex, on purpose:** the gate acts on typed path fields and Codex has
   none; free-text shell paths are the exec chokepoint's turf. Tests mirror
   the anthropic-proxy suite.
5. **P5, hardening residue**: fs-sync symlink refusal (gap class 3): the
   worktree checkout is followed by symlink neutralization (each link
   becomes an inert regular marker carrying no attacker bytes, not even the
   target string); `readForAgent`/`captureAgentWrite` throw on link paths;
   `syncToHuman` refuses to sync a path that is a link in EITHER view
   (SYMLINK conflict-log entry), so an agent-planted link can neither
   materialize its target's bytes into the HumanView nor clobber a human
   link; human-edit reconciliation skips links. Launcher truth in labeling:
   the manager reports `fs rung ACTIVE` (CWD + map + gate) when the stack is
   live and `fs rung DEGRADED` with the missing protections on the non-git
   skip or an explicit opt-out while integrity is ON. With integrity OFF
   (`secrets`, `off`) fs-sync is off by design, not opted out: the plan
   carries `fsSyncOffReason: "mode"` (`parse.ts` for a requested mode,
   `run.ts` for the effective one) and the manager reports an informational
   `fs rung off by mode: …` note (not an attention note, not a dropped rung,
   so the health chip and the posture oracle stay green).

Not built: the Linux userns overlay upgrade, Windows path-dialect work
beyond the map's normalization, the microVM tier.

## 2. The sync cadence: when AgentView → HumanView sync fires

Status: built 2026-07-09. Eager sync is **on by default** wherever fs-sync
is active (`--no-fs-sync-eager` / `MANDU_FS_SYNC_EAGER=0` opt out); the
post-exit sweep is unconditional. The two-stage commit itself (symbolized
`[MDU-TRUSTED]` snapshot → copy → desymbolize → raw `[MDU-UNTRUSTED]`) is
`fs-sync/src/view-sync.ts syncToHuman`, lifted from the reference
`adfi-filecommit-worktree.ts`; this part decides only **when it fires**.
Where the commits live is §3.

### 2.1 Why not post-exit only

The reference fired the two-stage commit in an OpenClaw `after_tool_call`
hook, once per tool call. Mandu has no in-agent hook at the FS layer, and
the first port synced once, after the agent exited. That is wrong:

1. **Provenance loss.** The blame-visible history is designed around
   per-call commit pairs (`toolName`/`callId` in the commit messages); a
   post-exit lump attributes the whole run to one `toolName:"launcher"`
   pair.
2. **HumanShell correctness.** A HumanShell exec (chokepoint ③) runs
   against the HumanView; an agent that writes a file and then runs a
   trusted command that reads it sees a stale or missing file.
3. **Staleness.** The human and the dashboard watch a tree that does not
   reflect the work in progress; R2 conflicts all surface at once, post hoc.
4. **Crash safety.** If the launcher dies mid-run, nothing was synced.

### 2.3 Decision — sync at the **tool-call boundary**, asynchronously

**Trigger:** a tool call completing. In the cooperative stack the
observable completion moment is the **`tool_result` crossing the context
proxy** on the next agent→model request: the mirror of the path rewrite
(§1.3). Rewrite on the way out; sync on the way back.

**Granularity: tool call, not `write(2)`.** One logical save is many
`write()`s plus temp-file/rename dances; syncing mid-sequence commits
half-written files and spams the history, and each sync costs two git
commits plus arbiter round trips. `syncToHuman` diffs the **whole
worktree**, so a sync after any tool_result also picks up files a `Bash`
call wrote; when nothing changed it returns before taking the lock, so
over-triggering is cheap.

**Async + coalesced, off the wire path.** The sync never adds git or
arbiter latency to the agent→model relay and never blocks on failure. At
most one sync in flight and one pending; a trigger arriving during a sync
sets the pending bit, and the pending sync runs with the *latest*
provenance. The layout commit lock serializes against `reconcileHumanEdits`
and the CLI.

**The post-exit sweep stays**, unconditional: it catches writes after the
last tool_result (an agent-spawned background process) and any triggers
lost to the best-effort channel (§2.4).

### 2.4 Trigger plumbing — options considered

| | Mechanism | Verdict |
|---|---|---|
| **A** | each context proxy runs `fs-sync-cli sync` (or a new arbiter op) after relaying a request with `tool_result` blocks | ✗ fs coupling duplicated into every proxy; a cold-start subprocess per call near the wire path; the arbiter-op variant would turn the arbiter into an fs driver |
| **B** | **a resident fs-sync watcher** subscribes to the arbiter's event stream (the `subscribe` op the dashboard uses) and coalesces a `syncToHuman` on `tool_result` events | ✅ **chosen** |
| **C** | inotify/debounce watcher on the AgentView worktree | ✗ fires mid-write, no `toolName`/`callId` provenance, platform quirks |

B covers both proxies (both emit `tool_result` events with `toolName` +
`callId`, which map 1:1 onto `WriteProvenance`), runs `ViewSync` in-process
with warm git state, and is entirely off the wire path; a dead watcher
degrades to the post-exit sweep.

**Caveat:** this uses the observability channel (one-way, best-effort) as a
trigger. That is acceptable *only* because sync-back is utility-class, like
`reply-filter`: no security property may depend on the trigger firing
(§2.5). A dropped event means a staler HumanView until the next trigger or
the sweep. A future consumer that needs a *guaranteed* per-call sync needs a
dedicated IPC op, not a hardened event bus.

As built (`fs-sync/src/eager-sync.ts`, `fs-sync-cli watch <ws> --session
<id>`, `fs-sync/src/arbiter-client.ts`): the watcher is a child process the
launcher's fs-view service spawns after `init` and stops (SIGTERM + wait,
draining the in-flight sync, §2.4a) BEFORE the post-exit sweep; its readiness is
awaited at the end of `startServices` so its start overlaps the proxies'
([`runtime-instances.md §14`](../architecture/runtime-instances.md) §2). Startup failures exit
non-zero like the other subcommands; once running, an arbiter outage warns
once and a ping loop resubscribes on recovery. The subscription is
per-session (`--session <MANDU_SCOPE_ID>`) and starts "from now" (the
session's persisted max `seq` as the cursor; history is never replayed into
triggers). An optional workspace filter for other embedders skips only a
proven mismatch. `tool_result` events carry no top-level tool name, so the
driver takes it from `output.symbols[0].tool`, falls back to the `tool_use`
event correlated by `callId`, and finally to the literal `"tool_result"`.

### 2.4a Teardown: the watcher quiesces before the sweep (2026-10-04)

The golden-path canary's sweep failed once in about 1,100 CI runs with
`…/worktrees/agentview/index.lock: File exists`. The teardown SIGTERMed
the watcher's whole process group, so a git the watcher was running died
too, and a SIGTERMed git can leave its `index.lock` behind (4 in 1,500
SIGTERMs measured with git 2.53). The sweep's commit then failed on it.

- The launcher SIGTERMs the watcher process alone
  (`DetachedHandle.stopLeader`), so a running git finishes. It then waits
  for the whole process group to empty, which covers a git that outlives
  a watcher killed before its handler was installed. A group still alive
  after the bound is SIGTERMed whole and warned about, and the sweep runs
  anyway.
- fs-sync's git calls retry about 2 s when git reports the index lock
  busy, for a sibling git that is still running (the agent's own
  `git status` in its AgentView). A git that fails on the lock has changed
  nothing, so the retry is safe. fs-sync never deletes a lock it did not
  take: a lock still there after the bound fails the call as before.

Tests: `launcher/test/component/fs-view-teardown.test.ts` (real processes)
and `fs-sync/test/unit/index-lock-retry.test.ts`.

### 2.5 Security analysis — why eager sync adds no surface

- AgentView → HumanView desymbolization is the **deep, ungated
  trusted-destination path** (`desymbolize`; humans see originals by
  design). Changing *when* it runs creates no new egress: gated egress
  (net/exec) still resolves per approved symbol via shallow `resolve`.
- **Fail-safe, not fail-closed**, the `reply-filter` class: a failed or
  skipped sync leaves the HumanView stale; symbols stay opaque; nothing can
  leak. Sync failure never blocks or kills the agent.
- `syncToHuman` step 0 (re-symbolize tainted raw in the AgentView before
  the trusted commit) runs per sync as before.
- **R2 guard unchanged**: files with uncommitted human edits are refused and
  logged, now per call. `reconcileHumanEdits` runs ahead of each eager sync
  (§2.5a); a file both sides changed in the same window remains an R2
  refusal.

### 2.5a The other direction: human edits reach a running session

**The gap.** The reference reconciled human edits at `session_start` and
`before_tool_call`. Mandu kept the first as the launch-time seed and lost
the second with the OpenClaw hook. Observed in drill scenario U27: the human
replaced an injected line in `notes.md` between two turns, the twin kept its
seed token, the agent answered a re-Read with "file unchanged", and the
model quoted the old (injected) line back.

**The trigger.** The resident `fs-sync-cli watch` process owns it:

- Every eager run is **reconcile, then sync**, in the driver's single slot
  (`eager-sync.ts`). A human-edited file is HumanView-dirty, which the sync
  R2-refuses; reconciling first records the edit so the sync can proceed.
  Both take the layout commit lock, so they are serialized in-process.
- A **human-edit clock**: `fs.watch(humanPath, {recursive})`, trailing
  debounce 400 ms, `.git` / `.mandu` / `node_modules` ignored, plus one tick
  at watcher start (for an edit between `init` and the first prompt). A
  clock tick runs a **reconcile only**: there is no tool call behind it,
  and a sync would commit the agent's pending writes under no callId. The
  reconcile diffs the HumanView against the shadow HEAD and returns at once
  when nothing diverged, so the events caused by the sync's own HumanView
  writes cost one empty run; they are deliberately not filtered (dropping
  events during a run would also drop a human edit made in that window).
  No watcher available degrades to reconciling at the `tool_result`
  cadence.
- Both slots also carry the **ignored files** (§3.4.1): the reconcile
  re-mints a changed ignored file whole, seeds a new one and drops a deleted
  one's twin; the sync writes an agent's change to an ignored path back
  under the manifest's R2 guard. The clock's `node_modules` filter matches
  the default deny list there.

**Two guards a continuous trigger needs.**

1. *Who changed it?* "Dirty against the shadow HEAD" means "not written by
   fs-sync": the human, but also any non-agent program writing the
   HumanView (a HumanShell `curl -o`, a `git pull`). `reconcileChangedFile`
   asks the provenance registry first (`fileTrust`, the oracle
   `readForAgent` and step 0 use): untrusted by origin, or an arbiter that
   cannot answer (fail-closed), means the file is symbolized **whole** and
   nothing is promoted to trusted text. This also covers a new untracked
   file, which was once copied raw.
2. *Both sides changed.* A file whose AgentView twin carries uncommitted
   agent work is not reconciled; it is logged to `conflicts.log` as R2 and
   picked up once the agent's side commits.

**The sync's own writes cannot trip it.** `syncToHuman` desymbolizes into
the HumanView (step 4) and commits to the shadow main line (step 5) inside
one lock; after it returns those paths are clean against the shadow HEAD,
and because reconcile and sync share one slot a reconcile never observes
the window between steps 4 and 5.

**The backstop is unchanged.** The proxy still symbolizes every Read of a
file that is not purely symbolic
([`read-result-rendering.md`](./read-result-rendering.md)), so a literal
line in the AgentView reaches T-LLM only inside a symbol.

Tests: `fs-sync/test/unit/eager-sync.test.ts` (order, reconcile-only clock
run, slot rules, fail-safe), `test/unit/human-edit.test.ts`
(untrusted-by-origin symbolized whole, fail-closed `fileTrust`,
both-sides-changed), and `test/integrity/eager-watch.test.ts` against a real
arbiter and watcher (the U27 regression; the anti-import test: after the
sync desymbolized an injection into the HumanView, clock ticks leave the
AgentView free of it). The live U27 scenario passed with the fix.

### 2.6 Kernel-tier note

When `fs-supervisor` drives writes natively, the analog trigger is
**`close(2)` of a write-opened fd (or `rename(2)`)**, never `write(2)`,
feeding the same coalescer. The decision logic (tool-call or
file-completion granularity, async, fail-safe) is tier-independent.

### 2.7 Test oracles

- **Unit:** the coalescer (N rapid triggers → ≤ 2 syncs; the pending sync
  carries the latest provenance); `tool_result` event → `WriteProvenance`;
  degradation (arbiter or subscription down → warn + stale, never throw).
- **E2E:** per-call round trip: agent write → tool_result trigger → the
  HumanView holds the desymbolized bytes **before** session exit; one
  `[MDU-TRUSTED]`/`[MDU-UNTRUSTED]` pair per `callId`; a human-dirty file is
  R2-skipped and logged; a trailing write with no later tool_result is
  caught by the post-exit sweep.
- **Live:** the `claude-e2e` fetch-write-read chain asserts mid-run
  HumanView materialization.

### 2.8 Rollout

Eager sync is the **default** wherever fs-sync is active;
`--no-fs-sync-eager` / `MANDU_FS_SYNC_EAGER=0` opt out of the eager rung
only, `--no-fs-sync` disables the whole rung.

## 3. The shadow repo: the tracking substrate leaves the user's git

Status: decided and built 2026-07-19. The reference layout already reserved
the `repo.git/` slot this occupies.

### 3.1 Why the in-repo substrate was wrong

Since the lift from `adfi-openclaw`, fs-sync had used the **user's own
workspace git repo** as its substrate: the `[MDU-TRUSTED]` /
`[MDU-UNTRUSTED]` pairs and `[MDU-HUMAN]` reconcile commits landed on
whatever branch the user had checked out, the trusted branch lived in the
user's refs, and the AgentView worktree was registered in the user's
`.git/worktrees/`. The visible symptom: a session whose workspace was a
project's own repository landed two empty marker commits on its main
branch. The structural hazards on any real repo:

1. **Index sweeping.** fs-sync staged only the synced paths, but
   `git commit` commits the **entire index**: anything the user (or a
   concurrent session) had staged was swallowed into an `[MDU-*]` commit.
2. **Branch scatter.** Commits landed on whatever branch was checked out at
   sync time, and were pushed wherever the user pushed.
3. **Hook exposure.** Trusted commits ran the user's commit hooks, so
   fs-sync's commit path depended on user config.
4. **Destructive revert.** `revertToWriteCycle` ran `git reset --hard` **on
   the user's branch**, dragging interleaved user commits into the reflog.

And a detection miss: "human edit" meant *dirty vs the user's HEAD*, so a
human who edited **and committed** made the edit invisible to
`reconcileHumanEdits`.

### 3.2 Decision — a shadow repo owns all tracking state

All fs-sync git state lives in a **shadow repository** at
`<stateBase>/workspaces/<workspace-id>/repo.git` (the state base is
`~/.mandu/state`, [`on-disk-layout.md`](../architecture/on-disk-layout.md)
§3), with the user's workspace as its work-tree:

- created bare, then addressed at every operation with an explicit context
  (`GIT_DIR=<...>/repo.git`, `GIT_WORK_TREE=<workspace>`,
  `cwd=<workspace>`), never via the workspace's `.git`; all of fs-sync's git
  runs hardened ([`write-protection.md §8`](../architecture/write-protection.md) §3);
- its own **index**, refs, (absent) hooks and config with a local **Mandu
  identity** (`user.name=Mandu`, `user.email=mandu@localhost`), so
  bookkeeping commits do not impersonate the human;
- a deterministic main line: `HEAD` is `refs/heads/mdu-main` (set by
  `symbolic-ref` before the first commit, immune to `init.defaultBranch`).
  The T/U pair chain, `[MDU-HUMAN]` commits and revert all operate on
  `mdu-main`;
- the `mdu-trusted` branch and the **AgentView worktree** (`agentview/`)
  hang off the shadow repo, so the registration lives in
  `repo.git/worktrees/`, not in the user's `.git`.

**The user's repository is never touched.** No commits, branches, worktree
registration, `.git/info` writes, index contention, hooks or ref moves.

**Init sequence.**

1. `git init --bare repo.git`; set the local identity and
   `symbolic-ref HEAD refs/heads/mdu-main`.
2. **Baseline snapshot**: under the shadow context, `git add -A` +
   `[MDU-TRUSTED] mdu: tool=init`, the blame base for everything after.
   `.gitignore` files are honored (git reads them from the work-tree),
   directories named `.git` are never added, nested repos become gitlinks.
   Ignored files never enter `repo.git`; they reach the AgentView as
   symbolized twins outside git (§3.4.1).
3. `git branch mdu-trusted` from the baseline; `git worktree add agentview
   mdu-trusted`; symlink neutralization (P5).
4. `seedAgentView` in the worktree, with a **re-launch fast path**: a twin
   that already holds a symbol for a HumanView file that has not diverged
   from the shadow HEAD is current and nothing is minted, but only if:
   - the arbiter still **resolves every token it holds** (one `resolve`
     read per twin per launch, `twinTokensResolve`): a symbol DB that was
     recreated would otherwise leave every twin holding a dangling token,
     opaque but useless to `inspect_symbol`;
   - the **level** its token's marker advertises (`nomodel_`,
     `localmodel_`, `anymodel_`, none for public) equals the level the
     arbiter would mint for the HumanView path today (`pathLevel` op: user
     labels first, then the catalog), so a label added, changed or removed
     after the seed reaches the AgentView on the next launch in both
     directions (security-relevant: a path labeled STRICTER after a public
     seed stops being a twin the quarantine will open). The re-mint lands on
     a fresh row (the reuse key includes the session); the marker is only
     the re-mint trigger, never a decision input (confidentiality.md §2:
     the table is authoritative). Axis OFF or an arbiter without the op
     skips the comparison.

   A diverged file, a missing twin, a twin holding raw bytes, a dangling
   token, or an IPC error re-seeds (fail toward re-minting). The checks are
   independent arbiter reads, so the seed asks about
   `SEED_CHECK_CONCURRENCY` (32) twins at a time over one pipelined client,
   then mints what is not current one file at a time in tracked order;
   each verdict equals what the sequential checks gave. A diverged file the
   seed ingests is **recorded** on the shadow main line as an
   `[MDU-TRUSTED] mdu: tool=seed` commit (not `[MDU-HUMAN]`, whose blame
   would later read these symbolized-as-untrusted lines as human-authored),
   so the divergence clears and the next launch mints nothing.
   `revertToWriteCycle` walks only `[MDU-UNTRUSTED]` main commits, so its
   pairing (§3.5) is unaffected. Without the fast path every launch
   re-symbolized the whole workspace (about 9 ms per tracked text file and
   a fresh symbol row per file per launch).

Idempotent: an existing valid shadow repo short-circuits to the worktree
check.

### 3.3 Operation mapping

Every helper in `fs-sync/src/git.ts` takes an explicit git context
(`{ cwd, env }`, the `GitExecOpts` seam):

| context | cwd | env | used for |
|---|---|---|---|
| **shadow** | `<workspace>` | `GIT_DIR=repo.git`, `GIT_WORK_TREE=<workspace>` | status/add/commit on `mdu-main`, blame, revert, branch/worktree admin |
| **agentview** | `<agentview>` | none (its `.git` file points into `repo.git/worktrees/`) | worktree status/stage/commit/reset, `ls-files` |

- `syncToHuman` steps 3/5 (the T/U pair), `updateTrustedRef`,
  `agentViewRef`, `initWorktree`/`removeWorktree` → **shadow**.
- `reconcileHumanEdits`: change detection, `blameFile`, the `[MDU-HUMAN]`
  commit → **shadow**; trusted-side ops → **agentview**.
- `revert.ts`: `listWriteCycles` / `planRevert` walk `mdu-main`;
  `revertToWriteCycle`'s `reset --hard` runs under the **shadow** context:
  it restores the work-tree files but moves only shadow refs, so to the
  user's repo a revert is ordinary working-tree modification.
- `ensureGitInfoDir` → `repo.git/info`.
- `findGitRoot` remains only for the launcher's workspace-root discovery.

**External readers.** The dashboard's git view (the developer view's `git.ts`,
the developer view's `fs-view.ts`, the `/api/git` + `/api/fs` routes) runs git
with `--git-dir` on the shadow repo, found as the AgentView root's sibling
(`dirname(agentViewRoot)/repo.git`), the layout contract
`interceptors/fs-supervisor/src/layout.rs` also models. The live
`claude-e2e` probes target the shadow repo. Everything that consumes only
the worktree *path* (the launcher, the proxies' view map, the exec-box view
binds, the Rust fs-supervisor redirect) is unaffected.

### 3.4 Semantic deltas

**Wins**

- *Human-edit detection survives user commits*: "changed" means *changed
  since fs-sync last recorded it* (dirty vs shadow HEAD).
- *Revert is non-destructive to the user's history* (§3.3).
- *AgentView git isolation*: anything in the AgentView that speaks git sees
  only shadow history and cannot reach the user's refs through the worktree
  link.
- *Attribution honesty*: bookkeeping commits are authored
  `Mandu <mandu@localhost>`.

**Accepted divergences**

- *Tracked-but-ignored files* (tracked in the user's repo yet matching
  `.gitignore`) don't enter the shadow baseline; they enter the AgentView as
  ignored-file twins (§3.4.1).
- *Object duplication*: the shadow repo stores its own copy of the tracked
  content. Alternates into the user's `.git/objects` were rejected: the
  user's `gc` does not know about shadow refs and could prune objects the
  shadow history needs.
- *The workspace's own history is invisible to blame*: shadow blame
  attributes everything to the baseline or later MDU/HUMAN commits, which is
  exactly the attribution the reconciler needs.

### 3.4.1 Ignored files in the AgentView (2026-09-28)

**Status: BUILT.** `fs-sync/src/ignored.ts` (enumeration, caps, manifest)
and `ViewSync.syncIgnoredFromHuman` / `syncIgnoredToHuman`
(`fs-sync/src/view-sync.ts`).

**The gap.** The AgentView is a checkout of a baseline that honors
`.gitignore`, so an ignored file (a `.env`, a local notes folder, a
generated report) was absent from the AI's working copy. The reference
design never had this gap (it rewrote paths per tool call, with no
git-built view); it is a side effect of the git substrate.

**What is built.**

- *Enumeration.* `git ls-files --others --ignored --exclude-standard
  --directory` in the shadow context, then a walk of each collapsed
  directory. A default deny list keeps heavy, regenerable trees out
  (`node_modules`, `.venv`, `venv`, `target`, `dist`, `build`,
  `__pycache__`, `.next`, `.cache`, `.gradle`, `.tox`, `coverage`, and
  always `.git` and `.mandu`), matched against every directory segment.
  Caps: 1 MiB per file, 2000 files, 64 MiB in all, applied in path order so
  the choice is stable. Symlinks (P5), non-regular files and binaries stay
  out. `MANDU_FS_IGNORED_DENY` adds directory names; `MANDU_FS_IGNORED=0`
  turns the feature off. (No `policy.yaml` knob: fs-sync reads no policy.)
- *Twins.* Each listed file gets a **whole-file** symbolized twin at its
  path, minted through the arbiter with the HumanView path as origin, so the
  level comes from the path's label or the secret catalog (`.env` →
  `no-model`). Every file is minted (a HumanView file is untrusted by
  default), including one that already contains a symbol-shaped string
  (`force`), so that string cannot let the rest of the file through raw. A
  registered secret also gets the whole-file symbol, NOT the arbiter's
  structured twin: the structured twin keeps the file's non-secret bytes
  (keys, comments) raw, which is right in `secrets` mode and wrong here,
  where those bytes are untrusted text in front of the model. A tracked
  `.env` is seeded the same way.
- *Outside git.* The twins are plain untracked files. The worktree's own
  `.gitignore` is itself a seeded twin (a symbol), so the worktree ignores
  nothing; `ViewSync` therefore drops every manifest path, and every path
  the HumanView's rules ignore (`git check-ignore` in the shadow context),
  from the tracked seed and sync lists. An ignored file's raw bytes never
  enter `repo.git`.
- *Manifest.* `<workspaceDir>/ignored.json`: per path the sha256 of the
  HumanView bytes and of the twin, the last enumeration's skip list, and the
  paths already reported as not written back. Re-launch fast path: a twin
  whose two hashes match, whose tokens still resolve and whose level is
  current (§3.2 step 4) is kept with no mint. With no usable manifest, a
  file already at the path whose one token resolves to exactly the
  HumanView file is adopted; any other unrecorded file there (an agent write
  not synced yet) is kept and logged as `R1`. `agentViewLeaks` audits the
  manifest paths along with the tracked files.
- *HumanView → AgentView.* `reconcileHumanEdits` runs the same pass after
  the tracked reconcile: a changed file is re-minted whole (there is no
  history to blame), a new one is seeded, a deleted one's twin is removed
  (only if the agent did not change it). A file changed in both views keeps
  the agent's version and is logged as `R1`.
- *AgentView → HumanView.* `syncToHuman` runs the tracked two-stage commit,
  then the ignored pass. An agent write (a twin whose bytes differ from the
  manifest, or a new file at an ignored path) is first re-symbolized in
  place when it is untrusted raw text (step 0, `fileTrust`, fail-closed
  UNTRUSTED), then desymbolized into the HumanView. R2 guard: the HumanView
  file must still hold the bytes the manifest recorded (absent, for a new
  file), else the write is refused and logged; a twin the agent deleted is
  deleted in the HumanView under the same guard. An agent write inside a
  denied directory or over a cap stays in the AgentView and is logged once
  per path as `IGNORED-NOT-SYNCED` in `conflicts.log`.
- *Surfaced.* `fs-sync-cli init` prints the counts and the first skipped
  paths; the launcher prints a `git-ignored path(s) are NOT in the AI's
  working copy` line naming the reasons and the manifest.

**Behavior to know.** There is no T/U commit pair for these paths, so
**`mandu revert` does not cover them**. An agent write inside a denied
directory (an `npm install` into `node_modules/`, a build into `dist/`) is
not copied back to the HumanView; it is logged. `MANDU_FS_IGNORED=0`
restores the old path (tracked two-stage commit).

**Not built (a trust-boundary change, not a sync detail):** a read-only bind
of the HumanView's heavy directories (`node_modules`, `.venv`) over the
AgentView paths inside the exec box, so builds and tests work in the
AgentView. Their contents are untrusted third-party code that boxed programs
could then read raw.

### 3.5 Empty-commit suppression — DEFERRED (revert pairing constraint)

Suppressing a T/U pair around a byte-identical sync looks free, but
`revertToWriteCycle` pairs the Nth `[MDU-UNTRUSTED]` commit on the main line
with the Nth `[MDU-TRUSTED]` commit on `mdu-trusted` **by index**
(`revert.ts`, `trustedCommits[targetNumber - 1]`). A sync whose worktree side
commits (step 1 must run, or the dirty worktree re-triggers forever) but
whose main pair is suppressed desyncs those indices, and every later revert
restores the wrong trusted ref. So the pair stays unconditional until revert
pairs by callId (or tree); the markers live in the private substrate, and a
*fully* empty sync already returns before any commit.

### 3.6 Migration of legacy in-repo workspaces

`initialize()` detects the legacy shape (the agentview worktree's `.git`
file resolves into `<workspace>/.git/worktrees/`) and migrates: (1) dirty
legacy worktree files are copied aside to
`<workspaceDir>/migration-backup-<iso-ts>/` with a loud warning; (2) in the
user's repo, `git worktree remove --force <agentview>` + `git worktree
prune`, then the legacy trusted branch is deleted (the only writes Mandu
ever makes to the user's repo, and they only remove Mandu's own residue);
(3) fresh shadow init (§3.2). Legacy `[MDU-*]` commits already in the
user's history are left alone: rewriting the user's history is the user's
call.

### 3.7 What does not change

The commit lock (`commit.lock`) and its serialization role; the R1/R2 race
guards; the P5 symlink refusals; the eager-sync cadence (§2); the CLI
surface (`init|sync|leaks|watch|history|revert <workspace> [--state-base]`);
the `agentview/` path (so the proxies' prefix map, the exec-box view binds
and the CWD rewrite are untouched); the event/provenance schema; the symbol
pipeline; the `[MDU-*]` message format. Only *where* the commits live moved.

#### 3.7a Commit tags

Commits are tagged in the `MDU` namespace: `[MDU-TRUSTED] mdu: tool=…
callId=… run=…`, `[MDU-UNTRUSTED] mdu: …`, `[MDU-HUMAN] mdu: source=human …`.
The parsers (`fs-sync/src/git.ts` `parseMduCommitMessage`,
the developer view's `git.ts` `parseMduSubject`) and the revert log walk
(`tagGrepArgs`) also read the reference's `ADFI` namespace (`adfi:` body).
The branch names are `mdu-main` and `mdu-trusted`. Spellings from before the
project rename are not read; shadow repos from then were rebuilt with the
state base move ([`mandu.md`](../architecture/mandu.md)).

### 3.8 Follow-ups (out of scope here)

- **The shadow repo's object store is readable by the agent in `full`
  mode.** `repo.git` holds the raw `mdu-main` line and the symbolized
  `mdu-trusted` line in ONE object store, and the agent's cwd IS a worktree
  of that repo, so `git show mdu-main:<file>` works with no path at all: a
  tracked (not `.gitignore`d) credential file is readable through it even
  though the file itself is twinned. (A `.gitignore`d one never enters
  `repo.git`.) Masking `repo.git` with a `--tmpfs` was rejected: the
  worktree's `.git` points into `repo.git/worktrees/`, so masking it breaks
  the agent's `git status`/`log`/`commit`, which the drills and the IPI
  ingress scenarios (a poisoned commit message via `git log`) depend on. The
  real fix is an **object-store split**: the agent-visible `repo.git` keeps
  only the `mdu-trusted` line and the worktree; the raw `mdu-main` line
  moves to a `raw.git` the agent never sees (with `objects/info/alternates`
  → `repo.git/objects` so fs-sync can still diff across the lines); and
  fs-sync commits the **twin** content, not the raw bytes, for registered
  secret paths on the trusted line (otherwise `mdu-trusted:.env` still
  leaks). Stated in [`guarantees.md`](../../guarantees.md) §3.
  **Closed for `secrets` mode** (confidentiality.md §7.2a): with integrity
  OFF there is no AgentView worktree, so the launcher hides the state
  directory, and with it every shadow repo, from the agent (on-disk-layout.md
  §4), and twins the user's OWN repository's object store in every mode.
  What remains is `full` mode's copy; the split above is the fix, and a
  revival of the axis must land it (with the git-driver escape recorded in
  protection-modes.md §10.7) before `full` ships again.
- **Lift the git-workspace gate.** fs-view's default-on is gated on "the
  workspace is a git repo", a constraint that existed because the
  workspace repo was the substrate. With the shadow repo any directory is
  trackable; widening enablement is a separate decision.

### 3.8b `mandu revert` — the verb (2026-09-25)

The write-cycle revert (`fs-sync/src/revert.ts`, from the reference's
[`revert.md`](../../adfi-reference/design/revert.md)) is reachable by the
user:

- `fs-sync-cli history <ws>` lists the write cycles (number, time, tool,
  files, whether it was a human edit); `fs-sync-cli revert <ws> --to N
  [--dry-run]` plans (`planRevert`) or performs (`revertToWriteCycle`) the
  full-state return. Both are pure git over the shadow repo and need no
  arbiter (the symbol table is append-only and unaffected).
- `mandu revert` (launcher `revert-command.ts`) targets the git root of the
  current directory and the state base: with no arguments it lists; `--to
  N` prints the plan (writes undone, files removed, files restored, "changes
  you made after it are overwritten"), asks on a terminal, and refuses
  without one unless `--yes`; `--json` gives the raw answer. The user's own
  git history is never moved; the abandoned writes stay in the shadow repo's
  reflog.
- History exists only where fs-sync tracked the workspace (`injection`,
  `full`); elsewhere `history` answers "no Mandu history" and `mandu revert`
  explains that the tracking modes are frozen.

Tests: `fs-sync/test/integrity/fs-sync-cli.test.ts` (two real write cycles,
history, a dry run changes nothing, revert removes the later file from both
views, all with a dead arbiter socket; the never-tracked refusal) and
`launcher/test/unit/revert-command.test.ts` (list, plan then confirm, no
terminal without `--yes`, decline, usage, fs-sync failure).

**The companion guard, `protect:` (opt-in, every mode but `off`).**
`policy.yaml` `protect: [~/Documents, /srv/data]` names what must not
disappear, and nothing else is judged. The launcher expands `~`, puts the
list in the guard's policy file and sets `MANDU_NET_GUARD_PROTECT=1`; the
guard traps the delete and rename families and answers EACCES when the
target, resolved on the real filesystem, is a protected path, inside one, or
an ancestor of one (both sides of a rename are checked), with a
`protected-path` event. It shares the trap and its matching with write
protection; what the trap covers today, and its residuals, are in
[`write-protection.md`](../architecture/write-protection.md) §2 and §4. No
`protect:` section: nothing changes. Tests: Rust `protected_hit` /
`delete_targets` units, arbiter validation, launcher `protectedPaths`, and
`secret-readers-live.test.sh` 4d under the real guard (a protected file and
folder survive `rm` and `mv`; an unprotected delete still works).

### 3.9 Test oracles

- **The oracle for the substrate**: a full lifecycle (init → agent write →
  sync → human edit → reconcile → revert) on a workspace *with its own git
  repo* leaves that repo's git state byte-identical: all refs,
  `git log --all`, branch list, `git worktree list`, staged index
  (`test/unit/shadow-substrate.test.ts`). Working-tree files legitimately
  change; the user's git mutating is the bug.
- The dual-view, human-edit, revert and cli suites run on the shadow
  substrate (plus non-git-workspace variants); the suites that read the
  `[MDU-*]` log assert against the shadow repo and assert the workspace log
  does NOT contain the pair.
- Dashboard: the `fs-view`, `fs-routes` and `git-routes` unit suites build
  the split shape (user repo + sibling `repo.git` + worktree); `/api/git` +
  `/api/fs` e2e against it.
- Re-launch fast path (`test/component/seed-idempotency.test.ts`): a second
  `initialize()` over a seeded workspace makes zero symbolize calls and
  leaves the twins byte-identical; a HumanView edit since the shadow HEAD, a
  twin overwritten with raw bytes and a deleted twin are each re-seeded; an
  ingested diverged file is recorded on `mdu-main` so the launch after next
  mints nothing, while the user's repo stays untouched; on a 200-file
  workspace the checks overlap (bounded by twice the concurrency) and
  exactly the obsoleted and relabeled twins re-mint. `mapPool` has its own
  unit test (`test/integrity/map-pool.test.ts`).
- Ignored files (§3.4.1): `fs-sync/test/unit/ignored.test.ts` (caps, env
  knobs, enumeration under the deny list, HumanView rules for AgentView
  paths, manifest); `fs-sync/test/component/ignored-files.test.ts` (twins
  symbolized and levelled, nothing in `repo.git` on any ref, re-launch mints
  nothing, relabel re-mints, human edit / add / delete reach the AgentView,
  agent write-back and delete under R2, untrusted raw text symbolized before
  write-back, denied-directory writes logged once, fail-closed mint,
  `force` over a symbol-shaped string, the off switch);
  `tests/integrity/ignored-files-agentview.test.ts` (real arbiter in `full`,
  production adapters: a gitignored `.env` and a labeled note reach the
  model only as tokens); `launcher/test/unit/fs-view.test.ts` (the launch
  line).
- Migration: a legacy-built fixture (worktree + trusted branch in the user
  repo) migrates on init: residue removed, dirty legacy files backed up,
  shadow repo live afterward.
