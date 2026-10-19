# Mandu Implementation Plan — Target: Claude Code (Linux)

> **Status: built.** The milestone plan the first Mandu prototype followed,
> kept for its decisions and their reasons (§0–§8, §10) and for the **e2e
> invariant oracle (§9)**, which every ingress/egress path still answers to.
> Companion to [`mandu.md`](./mandu.md) (architecture) and
> [`CONTRIBUTING.md`](../../../CONTRIBUTING.md) (the reuse policy). Terminology
> pairs the paper term with the adfi-openclaw repo term, per repo convention.

---

## 0. Decisions locked

| Decision | Choice | Rationale |
|---|---|---|
| **Primary target agent** | **Claude Code** | Fastest proof of the security invariant; cleanest interposition; closest analog to OpenClaw → maximum policy reuse. |
| Open validation target | **Codex CLI** | Open-source (Rust), already uses Landlock+seccomp on Linux, second model API — proves generality. |
| Build approach | **Two parallel tracks** on a shared scaffold | Track A (model-API proxy) and Track B (FS interposition) are independent; both prove the invariant from different angles. |
| Arbiter language | **TypeScript** | Lift the evaluated symbol table + policy engine from adfi-openclaw near-verbatim. |
| Interceptor language | **Rust for kernel attachment; TS for the model proxies and the wrapper-layer chokepoints** | Kernel-touching code (seccomp-unotify, nftables/eBPF, exec supervision) wants a systems language → Rust crates. The model-API proxies (`anthropic-proxy`/`openai-proxy`) and the userspace wrapper-layer chokepoints (`net-proxy`/`exec-wrap`) are pure-userspace TS that lift the arbiter policy directly. All talk to the arbiter over the Unix socket. |

---

## 1. Why Claude Code

The whole port hinges on **recovering the structured tool boundary by interposing
the agent↔model API** (`mandu.md` §3, "key realization"). Claude Code is the
best first target on every axis that matters:

1. **Native structured tool boundary.** The Anthropic Messages API carries
   `tool_use` / `tool_result` blocks with names + arguments — exactly what
   OpenClaw's `before_tool_call` / `tool_result` hooks delivered. We recover the
   semantic boundary with zero agent cooperation.
2. **Interposition without a CA fight.** `ANTHROPIC_BASE_URL` lets us point the
   agent at a local forwarding proxy; `NODE_EXTRA_CA_CERTS` covers any TLS we
   terminate ourselves. **This dissolves hard problem #3 (cert pinning)** —
   the "MITM proxy" is really a cooperative reverse proxy.
3. **Complete context-ingress chokepoint.** *Every* tool result — file read, Bash
   output, MCP tool, web fetch — re-enters the model as a `tool_result` block in
   the next request. So symbolizing `tool_result` at the proxy (Track A) covers
   **all** ingress into T-LLM's context, regardless of source. This is why Track A
   alone proves the invariant.
4. **Clean process tree.** A single Node process whose Bash tool spawns children —
   a natural fit for the cgroup v2 scope and the exec supervisor.
5. **Closest to OpenClaw** → the policy engine, symbol table, and git-worktree
   view-sync port with the least adaptation.

**Known Claude-Code-specific caveats** (§10): closed-source (ingress audit
relies on the proxy oracle, not source reading), subscription-vs-API-key auth
affects base-URL routing, and version drift can change request shapes.

---

## 3. Shared scaffold (M0 — prerequisite for both tracks)

- **Launcher + scope.** Wrap the agent in a dedicated cgroup v2 scope
  (`systemd-run --scope --unit=mandu-<id> -- claude ...`). Scope membership
  answers, for every interceptor, "is this connection/file/exec the monitored
  agent?" — replacing OpenClaw's `isTargetSession()`.
- **Arbiter daemon.** Lift the reference implementation's symbol table, symbol
  format and policy engine into `arbiter/` (provenance headers on every lifted
  file, per the reuse policy). Expose symbolize / desymbolize / classify /
  record-tool-call over a Unix socket.

## 4. Track A — Model-API interposer (AgentView @ context)

Pure userspace; the fastest credible demo of the invariant.

- Stand up a local proxy; set `ANTHROPIC_BASE_URL` to it; forward to
  `api.anthropic.com`.
- **Request (agent→model):**
  - Inject the handling system prompt — replaces `before_prompt_build`.
  - Classify + symbolize untrusted spans in `tool_result` blocks — replaces
    `transform_tool_result`. Reuses `policy/tool-inbound.ts`,
    `policy/resolve-schema.ts`, `policy/trust-category.ts`; the active
    Claude Code spec is `arbiter/policy/claude-code-inbound.ts` (`mandu.md`
    §1.x).
- **Response (model→agent):** parse `tool_use` blocks (the agent's decisions),
  record them in the arbiter so Track B/M3 interceptors can correlate a later
  `openat` / `connect` / `execve` to a known tool decision — replaces
  `before_tool_call` (read side).
- **Acceptance:** a stored-IPI fixture's payload reaches the model request **only
  as `$MDU:*`**; the proxy oracle confirms no un-symbolized untrusted bytes
  in any model request.

## 5. Track B — FS interposition (stored-IPI block, highest reuse)

Independent of Track A; blocks stored IPI at the filesystem.

- **seccomp-unotify supervisor** (Rust): intercept `openat()` for tracked
  workspace paths and redirect to the **AgentView** git worktree. (A FUSE mount
  that symbolizes on read is the fallback option.)
- **View-sync daemon** (`fs-sync/`, TS): reconcile AgentView → HumanView; human
  edits re-symbolize via `git blame`. Reuses near-verbatim the reference
  implementation's git, file-commit (worktree and on-demand), human-edit and
  revert modules.
- **Acceptance:** an agent reading a workspace file containing a stored injection
  sees symbols; a human/non-agent reader sees the original; a round-trip edit by
  the human re-symbolizes correctly.

## 6. Convergence — M3: network + exec + data-usage policy (HumanView)

- **Net proxy:** redirect the scope's non-model traffic (model-API traffic
  excluded — handled by Track A); egress desymbolize gated by the **data usage
  policy** (outbound spec). Reuses `policy/tool-outbound.ts`,
  `policy/exec-outbound.ts`. (Ingress ended up observe-and-tag only, with no
  body symbolization: `fs-provenance.md` §1.1.)
- **Exec supervisor:** AgentShell default (net off, FS=AgentView) vs HumanShell
  (net on, FS=HumanView, argv desymbolized **only after** the data-usage check +
  command rewriting). Reuses the reference implementation's restricted-exec
  module, `policy/exec-*.ts`, `policy/untrusted-command-execution.ts`,
  `policy/shell-symbol-resolution.ts`, `policy/script-file-command-expansion.ts`
  and `exec-argv-runner.mjs`. Codex's Landlock+seccomp sandbox is a working
  reference here.

## 7. Deferred — M4: transparent U-LLM (research)

Hard problem #1a (`mandu.md` §6). The differentiating contribution, but must
not block the security-only prototype. For Claude Code specifically, the
cooperative path (#1b) is reachable *without* an SDK shim: expose
`inspect_symbol` as an **MCP tool** and steer the agent toward it via the
injected system prompt (Track A). That path is built:
`interceptors/inspect-mcp/`.

## 8. Reuse map

| Mandu module | adfi-openclaw source | Adaptation |
|---|---|---|
| `arbiter/symbol-table` | symbol table, symbol format, `symbol-formats.ts` | promote singleton → daemon |
| `arbiter/policy` | `policy/*` | runtime-agnostic, lift as-is |
| Track A symbolize | `policy/tool-inbound.ts`, `resolve-schema.ts`, `trust-category.ts` | feed Messages-API blocks |
| `fs-sync/` | git, file-commit (worktree, on-demand), human-edit, revert | swap trigger only |
| exec routing | restricted-exec, `policy/exec-*.ts`, `untrusted-command-execution.ts`, `exec-argv-runner.mjs` | drive from `execve` argv |
| dualview routing | the dual-view module | central policy decision |
| inspect_symbol | the inspect-symbol tool | expose via MCP (Claude Code) |
| e2e oracle | `test/e2e`, `evaluation/` | drive Claude Code under scope |

(The reference implementation's files are `plugin/dualview/dualview-*.ts` in
the DualView repository; older provenance headers spell them
`plugin/adfi/adfi-*.ts`.)

---

## 9. E2E invariant oracle

The model-API proxy is a perfect oracle: **assert that no un-symbolized untrusted
byte ever appears in a model request.** Port `test/e2e` + `evaluation/` fixtures
to drive Claude Code under the scope and check this property across the context,
filesystem, network, and shell — including after store-and-re-read (stored IPI).
The confidentiality form of the same oracle asserts that no un-symbolized secret
reaches a model it is not cleared for, or the network
(`tests/stack/confidentiality-oracle.test.ts`); every new ingress/egress path
ships an e2e test of that form (the integrity form is frozen with its axis,
protection-modes.md §10).

This oracle is realized at three escalating scopes: `tests/stack/` (one
hand-written cross-component e2e), `tests/conformance/` (a declarative scenario battery
over the same real-component stack), and `eval/` (the red-team + benign
**eval harness**). `eval/` carries the headline security claim: a **deterministic**
backend pushes an IPI attack corpus through the real arbiter + ingress proxy and
proves the defense *neutralizes* it (ASR contrast **NONE 100% → FULL 0%**) while
preserving benign fidelity (byte-fidelity + no-over-block — not task completion,
which the live EXACT-ANSWER tier + AgentDojo carry), and a **live** backend drives
a real Claude Code / Codex session for the real-model ASR / utility /
token+latency overhead. See `eval/README.md`.

**Breadth of the deterministic oracle.** Because every Claude Code tool result —
file read, `Bash` output, `WebFetch`/`WebSearch` page, `Grep`/`Glob` hits,
`NotebookRead` — re-enters T-LLM as a `tool_result`, one proxy oracle covers all
context ingress. `interceptors/anthropic-proxy/test/component/tool-coverage-oracle.test.ts`
exercises that breadth along the four axes an IPI attack actually varies (mirroring
the adfi attack-template / injection-vector / threat-class taxonomy), all asserting
the *same* §9 predicate:

- **tool** — the poisoned result is symbolized regardless of which tool produced it
  (the minted symbol is labelled `$MDU:<tool>[…]`);
- **framing** — html-comment, `IMPORTANT INSTRUCTIONS`, `[SYSTEM OVERRIDE]`, a Claude
  `</function_results>` delimiter escape, and a fake conversation turn are each
  neutralized (the delimiter escape never rides through raw);
- **intent** — exfiltration (`curl` / `gws gmail`), RCE (`git clone … && setup.sh`),
  and destructive sabotage (`rm -rf`) fragments never reach the model;
- **chain** — multi-step sequences (`WebFetch → Write → Read → "follow it"`, and
  `Bash(curl) → Read`) symbolize **every** untrusted `tool_result` in the request,
  not just the latest — while the agent's own (trusted) narration rides through
  verbatim (no over-block).

**The proxy's own flag and its scope.** Both proxies stamp every
`tool_result` and `tllm_call` event with `invariant.violatedInvariant`, computed
by the same predicate at emit time (`events.ts survivingResult`). It searches
only the forwarded tool results (Anthropic `oracleHaystack`, Codex
`forwardedToolOutputText`): untrusted data enters only there, so a raw value
that also occurs in the user's prompt is not a leak. Per symbolized result it
looks in two places. Its **own** forwarded block, with the proxy-authored notes
and the trusted piece a split result keeps verbatim (`keptVerbatim`: the vouched
body, a kept reminder tail, Codex's exec or MCP header) removed, must hold none
of its raw spans at any length. The **rest** of the request is searched only for
spans of at least `DISTINCTIVE_RAW_CHARS` (8) characters after trimming, which
still catches the same untrusted bytes arriving through another result while a
short output (a `wc -l` count of `9`) that also occurs in a trusted path is not
flagged. Pinned by `test/unit/oracle-scope.test.ts` and the `§9 oracle …
short/distinctive` e2e cases in both proxies, including a leaky symbolizer that
must still be flagged.

**A dropped token-budget reminder is looked for in its own block only.** The
spans searched in the rest of the request are `crossResultSpans`, which is
`mustNotSurvive` minus one span: a dropped reminder tail (`droppedTail`) that
is entirely the harness token-budget reminder
(`<system-reminder><total_tokens>N tokens left</total_tokens></system-reminder>`,
the anchored digits-only shape the arbiter's `isHarnessTokenBudgetReminder`
vouches for). Claude Code appends the same reminder, with the same count, to
every tool result of a turn. On a secret Read the tail inherits the path's
level, so the proxy drops it with the symbolized body; `secrets` mode forwards
the next, public result raw with the identical reminder, and a cross-result
search would read that as the Read's bytes surviving — a false red flag. The
reminder is harness framing with a digits-only channel, never the secret. It is
still looked for at any length in its own block, and every other span (the
body, a prose or mixed tail) stays in both scopes, so a secret's raw bytes
arriving through another result are still flagged. Pinned by
`oracle-scope.test.ts`, the `secrets §9 oracle` cases in
`invariant-oracle.test.ts` (with a forced verdict, the raw-recurrence and
prose-tail duals), and the `secrets mode` cases in
`tests/stack/confidentiality-oracle.test.ts` (the real arbiter).

The CI `tests/stack/proxy-replay.test.ts` replays a subset of these
deterministically into a real in-test arbiter so each becomes a renderable,
TEST-badged session (`replay-e2e-ipi-webfetch-rce`, `replay-e2e-ipi-bash-exfil`,
`replay-e2e-ipi-grep-sabotage`, `replay-e2e-chain-fetch-write-read`, …), and the
gated `claude-e2e.test.ts` runs a LIVE representative of
each family as real `claude -p` loops from a user prompt (`stored-ipi`,
`bash-ipi`, `chain-copy-read`, `webfetch-rce`, `chain-fetch-write-read`) plus
benign controls (`reasoning`, `benign-write-confirm`, `benign-bash-echo`) and
the **trusted-path duals** (`trusted-grep-files`, `trusted-and-untrusted`) that
assert a TRUSTED tool result reaches the model **verbatim** (un-symbolized) —
the no-over-block side of the invariant. A full catalog of every e2e test —
initial input, tool sequence, and what it asserts — is
**`docs/testing/e2e-catalog.md`**, which frames these under the `mandu-e2e`
umbrella: the real-agent live classes (`claude-e2e`, `codex-e2e`, and future
agent CLIs) plus `replay-e2e`, the deterministic no-agent sibling that runs in CI.

---

## 10. Risks specific to Claude Code

1. **Auth mode.** Subscription (OAuth) works **first-party only** — full findings
   + decision in `docs/design/agents/agent-sign-in.md §1`. It is feasible for **both**
   model channels: T-LLM via the `anthropic-proxy` *verbatim relay* (Claude Code
   forwards its bearer to `ANTHROPIC_BASE_URL`), and U-LLM via `claude -p`
   (`inspect-mcp` `CliUllmClient`). What fails is a *hand-rolled* HTTP call
   presenting a subscription token from outside Claude Code (unsupported,
   against ToS), or pointing `ANTHROPIC_BASE_URL`
   at a non-Anthropic endpoint (silent subscription bypass → 404 model-not-found).
   A Console **API key** remains a valid alternative for either channel.
2. **Closed source.** Ingress completeness can't be audited by reading source —
   rely on the proxy oracle (§9) and on cross-checking against the open Codex
   target.
3. **Version drift.** Request/transcript shapes can change across releases; the
   tested version ranges and the drift warning are in
   [`supported-agents.md`](../agents/supported-agents.md).
4. **Non-tool egress.** Telemetry, auto-update, and MCP server traffic must be
   enumerated and routed (or blocked) by the net layer (M3), not just the model
   proxy.

---

## 11. Next steps

Every milestone above is built, each as a package with its own suite
(`mandu.md` §4 "Realization status" maps box → package). Run everything with
**`scripts/test-all.sh`**; every suite is an entry of the manifest
`tests/suites.mjs` ([`test-organization.md`](../testing/test-organization.md)),
and CI runs the per-push kinds with `scripts/ci/vm-run.sh`.

**The §9 invariant is proven end-to-end.** `tests/stack/full-stack.test.ts`
boots the REAL arbiter, the REAL anthropic-proxy (against a mock upstream), and the
REAL `inspect_symbol` core (against a mock U-LLM), drives a stored-IPI
`tool_result` through the proxy, and asserts the forwarded model request carries
the payload ONLY as a `$MDU:*` token — confirmed through BOTH the arbiter
`events()` op AND the dashboard `ArbiterEventSource` + view-model. A second test
in the same file boots the proxy with an active view map and proves the
path-rewrite chain live: a follow-up request echoing the AgentView worktree (a
`Read` tool_use arg + a TRUSTED `Glob` result naming the worktree) is
reverse-mapped so T-LLM sees HumanView paths only, the proxy emits
`path_rewrite` events (typed-field + free-text-content branches) through the
real arbiter, and `toDualLanes` surfaces them on the tool step.

**The conformance suite (`tests/conformance/`)** generalizes that single hand-written
e2e into a declarative, scenario-driven battery modeled on adfi-openclaw's
unit + e2e testing. A micro-harness (`lib/harness.ts`) exposes
`buildStack({target})` — one call that boots a real `ArbiterServer` (temp
socket/db/eventDir) + the real ingress proxy (`AnthropicProxy` for `claude`,
`OpenAiProxy` for `codex`) against a mock upstream, returning handles to drive
ingress, read events, and call the arbiter's resolve/egress/exec ops. An
assertion DSL (`lib/assertions.ts`, lifted from adfi-openclaw: a `FieldMatcher`
+ per-step `assert:` kinds — `agent_sees_only_symbol`, `result_symbolized`,
`not_symbolized`, `symbol_resolves_to`, `invariant_holds`, `event_view`,
`egress_decision`, `exec_shell`, `ullm_resymbolized`) evaluates each
`scenarios/*.yaml`. The corpus (CT-01…CT-09) covers stored-IPI on both the
Claude and Codex ingress paths, per-field web trust, exec-exfil, the
untrusted-destination + symbol-as-command egress gates, exec
AgentShell/HumanShell selection, a benign-utility no-over-symbolization case,
and U-LLM re-symbolization. It is deterministic (no API key, no network).
Since the integrity freeze the corpus is the package's `npm run
test:integrity`, in the frozen lane (`scripts/test-all.sh --integrity`); `npm
test` runs only the `unit_symbolization` canary (protection-modes.md §10.5).

**What remains kernel-gated (the Rust syscall attachment).** The three OS
interceptors' *decision logic* is implemented and unit-tested with default
`cargo test`. Their **kernel attachment** — seccomp-unotify `openat()`
rewrite (`fs-supervisor`), nftables/TPROXY redirection and the `connect(2)`
guard (`net-supervisor`), and namespace/`execve` supervision
(`exec-supervisor`) — lives behind each crate's `kernel` cargo feature and
`#[ignore]`d integration tests, run without host root through unprivileged
user namespaces by `scripts/kernel-tests.sh` (privilege-model.md §1). The
build constraint (`interceptors/Cargo.toml`) is that default `cargo test` MUST
pass with no root.
