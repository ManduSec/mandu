# Mandu — Architecture Map

> The map that ties the design together with one organizing idea, so the rest
> reads as detail rather than a pile. The architecture itself (the two views,
> the four chokepoints, the hook → chokepoint mapping, the terminology) is
> [`mandu.md`](./mandu.md); start there. The details this map organizes:
> [`privilege-model.md`](./privilege-model.md) (the enforcement layers, and the
> unbuilt microVM tier in its §6), and
> [`portable-wrapper.md`](../distribution/portable-wrapper.md) /
> [`portable-wrapper.md §10`](../distribution/portable-wrapper.md)
> (the cooperative, cross-platform wrapper). §9 is how each chokepoint is
> realized, per layer and OS, with its status.

## 1. The problem this doc solves

The design spans many angles — two views (AgentView / HumanView), three OSes,
process-wrapper vs container/microVM, in-process vs out-of-process vs kernel
enforcement, four chokepoints. Listed flat, they look bewildering. They are not:
they are **three orthogonal planes**, and two of those "axes" are secretly one.
Separate them and each plane is simple.

> **One sentence: decide once, enforce anywhere.**
> One authority — the **Arbiter** — makes every trust decision; the **four
> chokepoints** are *where* it's enforced; a single **strength ladder** is *how
> hard*; the **OS** only gates which rungs of that ladder exist.

## 2. Plane 1 — WHAT is protected (policy)

Invariant, data model, and one authority. **OS-independent, mechanism-independent —
this plane never changes.**

- **Invariants.** Untrusted data reaches the privileged model (T-LLM) only as an
  opaque symbol (`$MDU:*`) — the integrity axis; and a secret reaches a model
  only as a symbol unless its level admits that model, and leaves the machine
  only when a binding or the human allows it — the confidentiality axis
  (`mandu.md` §1, [`protection-modes.md`](./protection-modes.md)).
- **Data model.** AgentView / HumanView = *one dataset, two renderings*. The agent
  sees symbols; humans and real programs see originals.
- **The authority — the Arbiter (repo: `arbiter`).** It holds the **symbol table**
  (the map between the two views) and makes every symbolize / desymbolize / classify
  / egress decision. Every enforcer is a client that defers to it. See §7 for the
  name.

## 3. Plane 2 — WHERE it's enforced (surface)

The **four chokepoints** — the *set of boundaries*, not how they're guarded. Also
OS/mechanism-independent.

| # | Chokepoint | The boundary it guards |
|---|---|---|
| ① | **context** | what the model reads (tool_results) |
| ② | **filesystem** | what the agent reads/writes on disk |
| ③ | **exec** | what commands the agent runs |
| ④ | **network** | what leaves the machine |

**Coupling (important).** ③ and ④ are not independent peers: **exec drives network
posture.** AgentShell = no network; HumanShell = network. Network enforcement is a
*consequence* of the exec/shell decision, not a separate policy — so think of exec
+ network as one **"actions"** surface with two enforcement points (see
`portable-wrapper.md` and the net/exec discussion).

## 4. Plane 3 — HOW HARD it's enforced (mechanism)

Here is the key simplification: the two axes that look separate —
*in-process / out-of-process / kernel* and *wrapper / container / microVM* — are
**one axis**. Both measure the same thing: **how far outside the agent the boundary
sits = how hard it is to bypass.** Collapse them into a single strength ladder
(the layer names of privilege-model.md §2 in brackets):

| Tier | Mechanism | Strength | Privilege | OS |
|---|---|---|---|---|
| **0 · context** [context layer] | model-API reverse proxy | always-on floor | none | any |
| **1 · in-process** | env · PATH · LD_PRELOAD | fast path — *not a boundary* | none | any (mac: SIP-limited) |
| **2 · out-of-process** [wrapper layer] | forward proxy · PATH-shim · FUSE | the cooperative floor | none | any |
| **3 · kernel** [kernel layer] | seccomp-unotify · Landlock · netns · bind-mount | hard | userns (no host root) | Linux |
| **4 · microVM** (design only) | libkrun guest (virtiofs + host NAT) | hard | KVM/HVF | Linux + macOS (+Win WHP) |

Strength rises up the ladder; **portability and privilege trade along it.** You pick
the highest rung the host allows and let lower rungs be the floor. Tier 1 is not
used as a boundary: an env-borne interposer the confined process can strip is
not one (the `LD_PRELOAD` rung, `fs-preload`, is retired).

## 5. The synthesis — one grid

Everything the design "juggles" is a single table: **rows = chokepoints (Plane 2),
columns = tiers (Plane 3), cells = the concrete mechanism.** It's legible because the
axes are orthogonal, and the **Arbiter (Plane 1) is the brain behind every cell.**

| Chokepoint ↓ / Tier → | 0 context | 2 cooperative (portable) | 3 kernel (Linux) | 4 microVM (portable-hard) |
|---|---|---|---|---|
| **① context** | model-API proxy → symbolize | *(same proxy)* | *(same proxy)* | same proxy, in-guest |
| **② filesystem** | *(path-rewrite on the wire)* | CWD → AgentView worktree + proxy path-rewrite | seccomp `openat` redirect / Landlock / secret-twin binds | virtiofs serves AgentView |
| **③ exec** | proxy exec gate | PATH-shadow shims | the exec box (bwrap + seccomp + Landlock) | in-guest, gated |
| **④ network** | — | `HTTP_PROXY` → net-proxy | `connect(2)` guard / Landlock TCP / netns-off (AgentShell) | host NAT is the only route |

The context proxy (tier 0) is one cell that spans everything — it is the always-on
policy floor. Tier 2 is the **cooperative wrapper**; tier 3 is the **Linux
kernel** hardening; tier 4 is the **microVM** for untrusted agents (not built).

## 6. Reading a configuration (the decision path)

Three questions pick your column, in order:

1. **Trusted agent?** (Claude Code, Codex → yes) → **cooperative** columns.
   Untrusted binary? → the **microVM** column.
2. **Which OS?** → gates the available rungs (kernel = Linux only; microVM =
   libkrun on Linux+macOS, WHP/WSL2 on Windows).
3. → yields the concrete per-chokepoint mechanism stack (a column of the grid).

So "Linux vs macOS vs Windows" and "wrapper vs microVM" are **not** two more axes to
reason about independently — they are just *which column of the one grid you land in.*

## 7. The name — the Arbiter

The component that owns the symbol table, the policy engine, and the event store is
the **Arbiter**: the trust root of the whole defense.

- It **holds the symbol table** — the secret map between AgentView and HumanView.
  Leak or corrupt it and the defense collapses. It is the **TCB** (trusted computing
  base) of the system.
- It is the **sole decision authority** — every interceptor (model proxy, net-proxy,
  exec-wrap, fs) defers to it for symbolize / desymbolize / classify / egress. In
  classic terms it is a **reference monitor**: mediates every security-relevant
  action, always invoked, small enough to trust.

The name captures three roles at once:
- **authority** — it decides;
- **custody** — it holds the real values behind the symbols, releasing one only on a
  positive `desymbolizationDecision` (desymbolize = *release from custody*);
- **containment** — it governs what the agent sees (AgentView) and what may cross to
  HumanView or leave the machine.

In code: `arbiter/`, `ArbiterClient`, `MANDU_ARBITER_SOCK`, and the Rust crate
`mandu-arbiter`. Which of its channels the agent's world may reach is
[`arbiter-human-plane.md`](./arbiter-human-plane.md).

## 8. Why this map makes the design simpler

- **One brain, many hands.** The Arbiter decides; the grid enforces. You never have
  to reason about policy and mechanism together.
- **Policy is stable; only the cell changes.** The invariant, the two views, and the
  four chokepoints don't move. OS and trust level only pick a *column*.
- **Five "axes" → three planes → one grid.** Two of the axes (in/out/kernel and
  wrapper/microVM) were the same strength axis; OS and trust are column selectors,
  not independent dimensions.

## 9. Chokepoint implementation

How each of the four chokepoints is realized — per tier and OS, with the
concrete component and current status. Every enforcement point decides through
the **Arbiter**.

**Status legend.** 🟢 live · 🟡 built, not yet proven with a real agent ·
⧗ needs the cross-platform port · ⚪ design only.

### 9.1 Use-case space

A use-case is `(agent, OS)`. The **agent** selects the *context* adapter (and
whether the model call is reachable at all); the **OS** selects the strongest
available *action*-chokepoint tier. Supported today: Claude Code, Codex,
OpenClaw and OpenCode on Linux, with tested version ranges in
[`supported-agents.md`](../agents/supported-agents.md). Unsupportable (the model
call happens server-side): Cursor, Copilot, Amazon Q, Windsurf, Cody. Per-agent
studies and which agents come next: [`supported-agents.md §5`](../agents/supported-agents.md).

Two patterns fall out of the per-agent studies: **new-agent cost is almost
always one context adapter** (a new wire format such as Google GenAI needs its
own proxy; agents on an Anthropic or OpenAI wire reuse the existing two);
**new-OS / harder-tier cost is the action side** (macOS is verification,
Windows is a real port — process control, `.cmd` shims, a named-pipe arbiter
IPC, the WinHTTP egress gap — and the microVM tier is an integration build).

### 9.2 ① Context — the model-input chokepoint

**Mechanism.** A base-URL-override reverse proxy on the model API. It parses the
request, classifies + **symbolizes untrusted `tool_result` spans** (→ Arbiter),
injects the handling system prompt, and parses the streaming SSE response to record
`tool_use`. No MITM / no CA — the base-URL override is enough.

**This is the agent axis** — one adapter per API family:

| Agent | API | Component | Status |
|---|---|---|---|
| Claude Code | Anthropic Messages | `interceptors/anthropic-proxy` | 🟢 |
| Codex CLI | OpenAI Responses | `interceptors/openai-proxy` (+ config splice) | 🟢 |
| OpenClaw, OpenCode | Anthropic / OpenAI via their provider config | the routed providers of `anthropic-proxy` (agent-e2e-harness.md §9); OpenClaw also has the native in-process `dualview` plugin option | 🟢 |
| Chat Completions agents (Kimi Code, nanobot, local models) | OpenAI Chat Completions | `interceptors/openai-proxy`, the `/chat/completions` route (`src/chat-wire.ts`, `src/chat-sse.ts`) | 🟡 route built; no agent provisioned yet (supported-agents.md §5.5) |
| Aider, Hermes | their providers via base-URL env | reuse the anthropic/openai proxies | 🟡 validate |
| OpenHands GUI | LiteLLM, **in-container** | base_url via conversation config; proxy must be container-reachable | ⚪ container work |
| Gemini CLI (and its successor) | Google GenAI | a `gemini-proxy` adapter | ⚪ |

**The text-delta repacker (response side, utility only).** The model streams
its reply at BPE boundaries, so a `$MDU:` token and its field (`$MDU:inspect[695b]`
| `.result`) can arrive in two text deltas. An agent TUI paints each delta
with status rows between them, and the reply filter, which must emit bytes in
order, can reassemble only contiguous bytes. At the proxy the token is still
pure text, so the proxy re-cuts the deltas: a delta whose text ends in a
possible in-flight token (`$`, `$M`…`$MDU:`, a token that may still grow, or a
lone escape `\`; `danglingTokenStart`) keeps that suffix for the same block's
next text delta. The concatenated text is byte-identical; only where it is cut
moves; a held suffix is released before any other event of its block and at
the stream's end, never swallowed. Messages wire: `sse-text-repack.ts`, which
sends a held suffix as its own `text_delta`. OpenAI wires (Chat Completions
and Responses): `text-repack.ts`, which moves text forward between
consecutive text events of the same choice or content part (a one-event
lookahead) and never adds or drops an event, because an OpenAI chunk carries
an envelope and a Responses event a `sequence_number`; a held event before
anything else (a finish, a tool call, `[DONE]`, `.output_text.done`) goes out
with all its text. Neither is a security boundary: the reply is already
symbols, and neither desymbolizes.

*The one response-side change of text: the reserve expander.* On the Messages
SSE path only, `sse-reserve-expand.ts` runs after the repacker and after the
sniffer's tap. A token whose value the arbiter's `symbolShape` says has
N ≥ 2 lines reaches the agent as an N-row reserve block when the reply filter
reports a PTY relay that paints them. A token's line is held until it ends,
and a `\n` may be inserted into the text after a mid-line block where it
would otherwise clip (reply-row-reservation.md §14). The next request
collapses the block, that break included, back to the exact token and strips
any leftover marker before `rewriteRequest` (`reserve-request.ts`).
Everything else stays byte-identical. Grammar, eligibility and security:
[`reply-row-reservation.md`](../ui/reply-row-reservation.md).

*One module, two copies.* Both model proxies read an OpenAI wire:
anthropic-proxy for the routed OpenClaw / OpenCode providers
(agent-e2e-harness.md §9), openai-proxy for Codex and Chat Completions agents,
where it runs on every Responses and Chat success stream whether or not the
exec gate or a view map rewrites it. Packages stand alone (no workspace), so,
as with `endpoint-tls.ts`, `src/text-repack.ts` is copied VERBATIM into each
and so is its unit suite `test/unit/text-repack.test.ts`; the anthropic-proxy
copy is the one to edit. The module is self-contained (no imports) and also
holds the token grammar (`danglingTokenStart`, `REPACK_HOLD_CAP`) that
`sse-text-repack.ts` imports, so every repacker cuts by one rule.
`tests/stack/text-repack-parity.test.ts` fails unless both pairs are
byte-identical, runs one table of split-token cases (tokens the arbiter's
`generate` mints, every level marker and a canonical-encoded field, split at
every boundary and one delta per character) through both packages' exports
requiring the same bytes out, and checks that the Messages repacker and the
reply filter (`TOKEN_HEAD`, `TOKEN_CONTINUATION_RE`) use the same grammar.
Tests: the shared unit suite (every two- and three-way cut of each token
shape, escaped spelling, adjacent tokens, CRLF framing, torn frames),
`test/unit/sse-text-repack.test.ts` (Messages), and in each package
`test/component/split-token-round-trip.test.ts`: a `.env` tool result in the
`secrets` shape reaches the provider only as its symbol, the provider echoes
that symbol cut at every character boundary of its answer (one chunk, and
7-byte chunks), and the agent receives the text byte-identical with the
token whole in one delta and never the raw secret, on every wire the proxy
reads (anthropic-proxy: Messages, routed Chat, routed Responses;
openai-proxy: Responses, Chat). Also `test/component/openai-route.test.ts` and
openai-proxy `test/component/text-repack.test.ts`.

*Known limit.* A token longer than `REPACK_HOLD_CAP` (256 characters from
its `$`) is treated as prose and may still be cut between deltas: only a
field name the arbiter canonical-encodes (`__mdu_field_` plus four hex digits
per UTF-16 unit, `mandu.md` §9) of about 50 characters or more (58 behind a
short tag like `Read`) gets there. The token then stays opaque on screen,
never raw.

**Tier / OS.** Tier 0 — always-on, zero privilege, **all OSes** (it's an env var +
a localhost proxy). The U-LLM path (`inspect_symbol` MCP) processes untrusted text
in quarantine and returns a re-symbolized result.

**Launcher wiring.** The `mandu` launcher **autostarts** the context proxy by
default (skipped on an explicit base-URL override or `MANDU_NO_CONTEXT_PROXY=1`;
`launcher/src/services/context-proxy.ts`), on a kernel-assigned port published
through a port file (runtime-instances.md §8). **Reuse is identity-checked:** a
proxy already listening on a pinned port is adopted ONLY when it publishes
(`GET /_mandu/identity`) the same service + arbiter socket + view-map roots as
this launch; a foreign server or another session's proxy (different arbiter →
wrong symbol table; different view map → wrong worktree/gate) is a conflict the
launcher **fails closed** on rather than routing this session's model traffic —
and its symbolization/path decisions — through the wrong daemon.

### 9.3 ② Filesystem — AgentView / HumanView

**Mechanism (by tier).**

| Tier | Mechanism | Component | Status |
|---|---|---|---|
| cooperative (all OS) | CWD → AgentView git-worktree; blame re-symbolization on sync | `fs-sync` | 🟢 in the integrity modes (frozen axis; off in `secrets`): launcher `fs-view` service, default-on for git workspaces, `--no-fs-sync` opt-out; symlink materialization refused both directions (fs-sync.md §1 P5). Sync cadence ([fs-sync.md §2](../integrity/fs-sync.md)): post-exit sweep always; eager per-`tool_result` sync by a resident watcher (`--no-fs-sync-eager` opts out), fail-safe (a dead watcher degrades to the sweep) |
| cooperative (all OS) | **proxy path-rewrite** — bidirectional HumanView↔AgentView prefix map on `tool_use`/`tool_result` (conservative, field-level) + sensitive-path policy gate | `anthropic-proxy` / `openai-proxy` | 🟢 in `anthropic-proxy` (map: `src/view-map.ts` + `src/sse-rewrite.ts`, launcher-wired via `MANDU_VIEW_MAP`; gate: arbiter `fsPathDecision` + `src/fs-gate.ts`, denied paths → `/mandu/denied/…` sentinel, approval-queued). Map parity in `openai-proxy` (Codex: textual map over the `function_call` shell command, both directions; no typed-field gate — free-text shell is the exec chokepoint's turf). See [`fs-sync.md §1`](../integrity/fs-sync.md) §4.1/§6 |
| kernel (Linux) | secret-path twins: the whole-agent bwrap wrap binds a placeholder over each secret file, or the `connect`/open guard serves the twin where no bind is possible | launcher `secret-twins`, `net-supervisor` guard | 🟢 (confidentiality.md §7.2) |
| kernel (Linux) | Landlock FS plan (read-only real FS, writable worktree + `/tmp`) | `fs-supervisor::landlock`, applied in the exec box | 🟢 |
| kernel (Linux) | seccomp-unotify `openat` redirect to the worktree | `fs-supervisor` | kernel tests 🟢; not launcher-driven |
| microVM | virtiofs serves the AgentView as the guest FS | libkrun backend | ⚪ |

The `LD_PRELOAD` interposer (`fs-preload`) is retired: in-tree and tested, wired
to nothing (privilege-model.md §2).

**Honest bound.** Cooperative CWD-scoping only redirects reads *inside* the
worktree; the **proxy path-rewrite narrows** the absolute-path hole (it catches
model-emitted literal paths, both directions), but runtime-computed paths,
second-order opens by executed programs, and aliasing remain — **backstopped by
the context chokepoint** (a file read via a tool is symbolized at the model
boundary). The kernel/microVM tiers close those for real. The decided portable
stack (rewrite + CWD + fs-sync), its conservative rules, and the gap-class
analysis: [`fs-sync.md §1`](../integrity/fs-sync.md).

### 9.4 ③ Exec — AgentShell vs HumanShell

**Mechanism (by tier).** The full routing design — *classify at the proxy, enforce
at the exec boundary* — is [`exec-routing.md`](../integrity/exec-routing.md).

| Tier | Mechanism | Component | Status |
|---|---|---|---|
| context (model API) | proxy classifies each `Bash`/shell `tool_use` (`execGate`); an `$MDU:*` in command/exec position ⇒ gate-on-the-wire `exit 77` sentinel, fail-closed; records + emits `exec_gate` | `anthropic-proxy` / `openai-proxy` | 🟢 |
| cooperative (all OS) | PATH-shadow shim per HIGH-RISK cmd (`curl,wget,nc`) → Arbiter `classifyExec`; symbol-as-command ⇒ `exit 77` | `exec-wrap` | 🟢 (bash shims); Windows `.cmd` ⧗ |
| kernel (Linux) | the exec box: bubblewrap with every unprivileged namespace, `--cap-drop ALL`, a seccomp deny-filter and the Landlock leg; AgentShell = RW AgentView / RO rest / net-off; HumanShell = net-live + HumanView | `exec-supervisor` (`--exec-box`, on by default) | 🟢 |
| microVM | everything execs in-guest (net-gated + AgentView by construction) | libkrun backend | ⚪ |

**Key coupling.** The exec decision *drives* the network posture (④): AgentShell has
no network at all. The context row gates only the symbol-as-command case (opaque
data-position symbols stay opaque — not over-blocked); the kernel tier enforces
the FS/net posture on the actual argv (`exec-routing.md` §2–§4).

### 9.5 ④ Network — egress gate

**Mechanism (by tier).**

| Tier | Mechanism | Component | Status |
|---|---|---|---|
| cooperative (all OS) | `HTTP(S)_PROXY` → forward proxy → Arbiter data-usage gate (process **taint** + destination; `desymbolizationDecision`). `NO_PROXY` excludes loopback + model hosts. Optional session-CA MITM. | `net-proxy` | 🟢 (on by default); Windows WinHTTP gap ⧗ |
| kernel (Linux) | the seccomp `connect(2)` / send guard (IP and domain aware, unprivileged) and the Landlock TCP allow-list | `net-supervisor` guard (`--net-guard`), launcher `--landlock-net` | 🟢 on by default, probe-gated |
| kernel (Linux, root) | TPROXY / nftables | `net-supervisor` | kernel tests only; host-global state, not used (privilege-model.md §0) |
| microVM | the host user-mode NAT / proxy is the guest's **only** route out | libkrun backend | ⚪ |

**Robustness.** The gate is **content-agnostic** — it decides on the *source* (a
tainted process) and the *destination* (untrusted host), not the payload, so
in-program transformation (base64, encrypt) does not defeat it. On the kernel tier,
AgentShell-net-off makes egress structurally impossible; the cooperative net-proxy
is the portable stand-in, and its real weak link is taint **attribution**, not
payload transformation.

**Launcher wiring.** The launcher autostarts the net-proxy by default
(`--no-net-proxy` opts out; `launcher/src/services/net-proxy.ts`) on a
kernel-assigned port published through the port file (`MANDU_PORT_FILE`, the
same rendezvous the model proxies use; runtime-instances.md §8). The default-on
net-proxy is **fail-closed**: any failure to start refuses the launch, since
running the session with no egress gate is not a degraded mode worth offering;
`--no-net-proxy` is the deliberate opt-out and `--best-effort` passes a
non-conflict failure with a loud line. Only a pinned `MANDU_NET_PROXY_PORT` /
`net-proxy-port` takes the reuse branch, which is **identity-checked** like ①'s:
a listener is adopted ONLY when it publishes (`GET /_mandu/identity`) the same
service + arbiter socket as this launch. A foreign server, or another
session's net-proxy (different arbiter → its egress gate consults the wrong
policy and symbol table, and approvals/events land in the wrong session), is a
**conflict the launcher fails closed on** — hard (`failClosedFatal`,
`--best-effort` cannot override). The check runs on both the reuse branch and
after starting our own child (a concurrent launch can win the bind race).

### 9.6 Summary — chokepoint × tier status

| Chokepoint ↓ / Tier → | 0 context | cooperative | kernel · Linux | microVM |
|---|---|---|---|---|
| ① context | 🟢 anthropic/openai-proxy | — | — | ⚪ |
| ② filesystem | 🟢 path-rewrite | 🟢 fs-sync (integrity modes) | 🟢 secret twins, Landlock; seccomp redirect in kernel tests | ⚪ |
| ③ exec | 🟢 exec gate | 🟢 exec-wrap | 🟢 exec box | ⚪ |
| ④ network | — | 🟢 net-proxy | 🟢 connect guard, Landlock TCP | ⚪ |

### 9.7 What the `mandu` launcher wires

Arbiter start-or-attach, the context proxy (anthropic/openai), the net-proxy,
the exec-wrap shims, the kernel-tier rungs (exec box, Landlock TCP confine,
connect guard, secret-twins wrap; each probe-gated, on by default where the
host allows, `--no-<flag>` opts out), the fs-sync AgentView CWD in the
integrity modes, the MCP config, the reply filter, and the full env
composition (context base-URL, proxy env, PATH shims, scope, teardown). The
golden path (Claude Code × Linux) is e2e-proven by
`launcher/test/component/golden-path.test.ts` (deterministic) and
`launcher-golden-path.test.ts` (real `claude`).
