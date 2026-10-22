# Mandu — OS-level ADFI / DUALVIEW for general agents

> Goal: take the dual-view IPI defense that the paper calls **DUALVIEW** (its
> ancestor, the adfi-openclaw plugin, calls it **ADFI** — Agent Data Flow
> Integrity) and make it work for **any** agent running on a general operating
> system, not just OpenClaw. We start with **Linux**.
>
> Throughout this document we use **both vocabularies**: the paper term and the
> adfi-openclaw repo term, e.g. *AgentView (repo: Agent File System / agent-view
> worktree)*. See `docs/adfi-reference/terminology.md` and the paper,
> [arXiv:2607.03821](https://arxiv.org/abs/2607.03821). The rules every change
> follows are in [`CONTRIBUTING.md`](../../../CONTRIBUTING.md).
>
> The project was developed under the internal codename agentOS; older
> comments and commit messages use that name.

---

## 1. What we are porting

Mandu defends personal AI agents against **indirect prompt injection
(IPI)**, including **stored IPI**, by maintaining two views of the user's
environment:

- **AgentView** (repo: *Agent File System / agent-view*) — untrusted data appears
  to the agent only as opaque **symbols** (repo: `$MDU:*`). The privileged
  model — paper **T-LLM** (repo: *privileged LLM*) — therefore never reads
  attacker-controlled text and cannot be steered by it.
  Symbol names embed a **short tool tag**, not the raw tool name
  (`arbiter/symbol-table/symbol-format.ts` `shortToolTag`): an MCP name like
  `mcp__mandu-inspect__inspect_symbol` becomes `$MDU:inspect[ee19]`.
  This is readability AND correctness — the symbol grammar only admits
  `[a-zA-Z0-9_]` in the tool tag, so an un-sanitized hyphenated MCP name would
  mint a symbol the detection regex can never match (undetectable at egress,
  never desymbolized). The FULL tool name remains provenance in the symbol
  table's `tool` column and on every emitted `SymbolRef`.
  File/field suffixes likewise use a scanner-complete canonical representation
  (§9); nested paths and other non-grammar fields are encoded while the
  original field remains arbiter metadata. See also
  [fs-provenance.md §10](../integrity/fs-provenance.md).
- **HumanView** (repo: *Human File System / human-view*) — humans, non-agent
  programs, and remote services see **original** data, so the environment stays
  usable.

Mandu routes each action to one view, synchronizes the two around every
action (paper: *View Synchronization / Environment Sync*; repo: *file tracking,
two-stage commit, git-blame re-symbolization*), and governs the boundary with
two policies:

- **Data trust policy** (repo: *inbound data spec / output classification*) —
  classifies inbound data TRUSTED/UNTRUSTED and symbolizes the untrusted parts
  before the agent reads them.
- **Data usage policy** (repo: *outbound data spec*) — gates how symbols may be
  desymbolized on egress; requires human approval when an untrusted symbol would
  be used as a command/code or sent to an untrusted destination.
- **Arbiter** (repo: `arbiter`) — the trust root that owns the symbol table (the
  map between the two views), the policy engine, and the event store. Every
  interceptor defers to it; it is the reference monitor / TCB of the defense. See
  [`architecture-map.md`](./architecture-map.md) §7 for the naming rationale and
  §1–6 for the one-grid mental model.

When the agent must usefully *process* untrusted data (summarize, extract,
translate), DUALVIEW routes that work to a quarantined model — paper **U-LLM**
(repo: *quarantined LLM*) — through the `inspect_symbol` tool, which returns a
re-symbolized result so untrusted text never re-enters T-LLM.

Inbound classification of that tool's own result is the **one exception** to
the "every `mcp__*` tool result is UNTRUSTED" prefix rule. `inspect-mcp` is
part of the Mandu TCB and its *success* result is by construction already
pure-symbolic — the re-symbolized `$MDU:*` token, serialized by Claude
Code as the bare token and/or the `{"result_symbol", "model"}` JSON envelope.
Blanket-symbolizing it again produced a **double-wrap** (an opaque token
hiding an opaque token): fail-closed but pure noise that obscured the U-LLM
flow. The arbiter therefore applies a **hybrid rule**
(`arbiter/policy/claude-code-inbound.ts`, `classifyManduInspectResult`,
wired in `policy-interface.ts` `classify()` for every proxy client): TRUSTED
iff the tool name is *exactly* `mcp__mandu-inspect__inspect_symbol` **and**
the whole-result content is pure-symbolic (nothing but `$MDU:*` tokens
inside the known success envelope). Everything else fails closed UNTRUSTED —
in particular the tool's **error strings**, which can embed upstream error
bodies that may echo the raw untrusted value, and the same content shape under
any *other* MCP name (name alone is spoofable by a local MCP config; shape
alone would over-trust arbitrary servers). An explicit exact-name entry in the
inbound spec (e.g. a YAML override) still wins over the refinement, and the
policy snapshot mirrors the rule so the dashboard's policy modal stays
truthful. The full string-by-string audit of what can flow into that tool
result lives as comments on the rule itself.

**Harness text appended to a tool result.** Claude Code sometimes appends its
own `<system-reminder>` block to a tool_result's content (since CLI 2.1.x a
`<total_tokens>` budget reminder on **every** tool_result). The flattened
result is then `envelope + reminder`, and the strict shape gate above fails
closed. Loosening the gate to accept trailing reminders would open an
injection channel (a spoofed server can forge reminder text), so the gate
stays strict. Instead `anthropic-proxy` (`rewrite-request.ts`,
`splitTrailingSystemReminders`) splits complete *trailing*
`<system-reminder>` blocks off the flattened result, re-classifies the
**body alone** through the arbiter, and forwards the body raw only on a
TRUSTED verdict. The tail gets **its own arbiter verdict**: exactly one tail
shape classifies TRUSTED — the harness token-budget reminder
(`isHarnessTokenBudgetReminder`, an anchored
`<system-reminder><total_tokens>\d+ tokens left</total_tokens></system-reminder>`
grammar whose only attacker-usable payload is a number, no prose channel);
every other tail is **symbolized on its own**, minted under `system_reminder`
rather than the tool's name. The trusted-forwarding bar (an arbiter TRUSTED
verdict on the exact forwarded bytes) is unchanged for both spans, and the
implementation-plan.md §9 oracle treats only a symbolized tail as the
must-not-survive span. A body the arbiter distrusts takes the
**untrusted-body dual**: when the tail is the trusted budget shape the proxy
symbolizes the **body alone** (trailing separator whitespace kept on the
wire, not in the value) and forwards the tail verbatim — `$MDU:Read[…]` then
the reminder. Without the dual, nearly every untrusted result symbolized
*with* the reminder inside the value: T-LLM lost its budget on almost every
turn, the resolved value on HumanView surfaces carried the reminder as junk
(a one-line file became multi-line), and the same content minted a fresh
symbol every turn because the count varies. A tail the arbiter does not vouch
for still takes whole-result symbolization (a forgeable reminder never
survives raw); secret bodies take the dual too, the body symbolized with its
label.

The budget tail must not stay symbolized for a second reason: a symbolized
tail minted a fresh opaque token next to the real result symbol in every
split tool_result — a decoy. A model reading `{"result_symbol": …}` followed
by a second token answered with the decoy, and the user's reply desymbolized
to token-count plumbing instead of the answer. The neutral `system_reminder`
mint tag and a handling-prompt rule ("the `result_symbol` envelope identifies
THE result") close the same confusion for tails that stay symbolized.

The **codex analog**: codex's runtime writes a header — `Chunk ID: … / Wall
time: … / Process exited with code N / Original token count: N / Output:` —
BEFORE every `exec_command` output. Symbolizing the whole thing showed the
human that header, made a one-line output multi-line, and minted a fresh
symbol per run (the chunk id is random). `openai-proxy`
(`rewrite-request.ts splitCodexExecEnvelope`) splits the LEADING header off
and asks the arbiter about it alone; exactly that shape classifies TRUSTED
(`isCodexExecEnvelope` — hex/digits only, anchored at the start, so a forged
header inside the output lands after the real one and stays in the symbol),
and the command's bytes are symbolized alone. A header the arbiter does not
vouch for keeps whole-value symbolization.

### 1.x Claude Code inbound tool-surface map

The inbound data-trust ruleset (`arbiter/policy/claude-code-inbound.ts`, the
active default) is mapped against Claude Code's **real recorded tool
surface** — the repo's integration fixtures, conformance scenarios,
anthropic-proxy tests, and live event NDJSON, plus the published harness tool
set. Three findings shaped it:

1. **The live call shape is whole-result.** The proxies flatten every
   `tool_result` and call `classify()` with **no field path**, so a structured
   per-field schema alone can never match live (`Read` and `WebFetch` used to
   symbolize 100% of results with `fail-closed: structured schema but no
   field given`). Structured specs may carry an explicit `wholeResult` marker
   (`schema-types.ts`), resolved like any schema leaf; absent, the
   fail-closed default stands unchanged.
2. **WebFetch honors the operator URL allowlist whole-result.**
   `wholeResult: URL-data keyed off params.url` — the evaluated ADFI
   `web_fetch` semantic. The URL category's intrinsic default is
   allowlist-empty, so nothing changes until an operator explicitly allowlists
   a URL in the policy YAML; that operator-authored entry is the provenance
   for the TRUSTED grant.
3. **Read (and NotebookRead) deliberately stay fail-closed whole-result.** A
   DIR-keyed whole-result grant would trust **every** file under the DIR
   category's intrinsic blocklist-empty default, leaking the canonical
   `curl → Read` stored-IPI chain — whose only live-default backstop is this
   proxy (the fs-provenance taint registry exists but is not the live
   enforcement tier). CT-01 pins the symbolized outcome. Un-defer triggers
   (recorded on the `Read` entry): a DIR-allowlist-mode-only whole-result
   rule, or `classify()` consulting the fs-provenance `fileTrust` verdict.
   For the same reason **Grep's `output_mode=content` branch is literal
   UNTRUSTED** rather than a DIR DataSpec: under the intrinsic DIR default
   (and with `path` usually absent) matched file lines would ride through raw,
   bypassing the Read posture on the same bytes.

Tool rows, each with its provenance justification in the spec: `LS`
(TRUSTED — filesystem-namespace metadata, Glob's evaluated class),
`KillShell` (TRUSTED — harness-authored lifecycle confirmation, OpenClaw
`process.kill` precedent), `AskUserQuestion` / `ExitPlanMode` (TRUSTED —
user/harness-authored, the same trust root as the never-symbolized user
prompt), `BashOutput` (UNTRUSTED — background-shell stdout, Bash's threat
model), `Agent` / `TaskOutput` (UNTRUSTED — subagent output, Task's model),
`NotebookRead` / `SlashCommand` / `Skill` (UNTRUSTED — workspace-file
content, Read's posture; a cloned repo's poisoned skill body is stored IPI).
Anything unlisted (`ToolSearch`, `Monitor`, `Artifact`, `ListMcpResources`,
`ReadMcpResource`, …) stays fail-closed UNTRUSTED **by omission, on
purpose** — a new harness tool is mapped deliberately or not at all. With
the confidentiality axis on, such a tool's result is masked whole unless
policy.yaml `mapped_tools:` lists it (`ToolSearch`, whose result is the
tool catalog, excepted; confidentiality plan 10 §11.18).

**The Claude Code 2.1.273 battery.** The session-health `tool_surface` event
(dashboard.md §4.21) flags a session DEGRADED when the harness advertises
tools with no inbound spec. The 2.1.273 harness advertises 34 tools, 20 of
them new; each is mapped deliberately, in two classes, with its provenance on
the row (`claude-code-inbound.ts`, the "Claude Code 2.1.273 harness surface"
block); result shapes were read off the harness's own advertised tool
definitions:

- **TRUSTED — a harness-authored ack, or the agent's own write echoed back**
  (TodoWrite / KillShell's evaluated class; no channel for freshly-ingested
  bytes): `CronCreate` / `CronDelete` / `CronList` (the agent's own scheduled
  prompts), `EnterPlanMode` (the entry half of ExitPlanMode), `EnterWorktree` /
  `ExitWorktree`, `ScheduleWakeup`, `ReportFindings`, `WaitForMcpServers`
  (server NAMES only, from config — LS/Glob's names-only channel, same
  revisit trigger), `TaskCreate` / `TaskUpdate` / `TaskStop`.
- **UNTRUSTED — text this agent did not author**: `FetchInboxMessage` /
  `SendMessage` / `ListAgents` (the multi-agent mailbox: another agent's
  message, a relayed reply, other sessions' model-generated titles — a
  teammate may itself have read untrusted data, Task's model), `TaskGet` /
  `TaskList` (the shared task board a teammate can write), `Workflow`
  (subagent findings, Agent's model), `LSP` (hover/definition text is
  workspace-file bytes, Read's posture), `RemoteTrigger` (a remote system's
  reply).

A tool listed UNTRUSTED is *known* to the spec — the health chip no longer
flags it — while its ingress stays exactly as fail-closed as omission was; the
change is therefore utility-neutral on the security axis and only the TRUSTED
rows are new grants. Pinned by `arbiter/test/unit/claude-code-policy.test.ts`
(per-tool verdicts, the recorded 34-name surface fully known, near-miss names
still fail closed) and `arbiter/test/component/tool-surface.test.ts` (the same
over the real IPC: `toolSurface` + `classify`). The still-unlisted harness
tools keep the by-omission rule, so the chip keeps catching the next
release's drift.

Two supporting rules: the DIR origin category never resolves **relative**
keys against the arbiter daemon's ambient `process.cwd()` at eval time (both
modes fail closed UNTRUSTED for unanchorable keys, and absolute keys are
dot-segment-normalized so `a/../b` cannot dodge a blocklist entry —
`trust-category.ts`); and the policy snapshot renders a structured spec's
`wholeResult` rule as a `(result)` row so the dashboard modal mirrors what
`classify()` actually enforces.

**The security invariants we must preserve:**

> Untrusted data reaches the privileged model **T-LLM** only as a **symbol**, so
> attacker-controlled text can never steer the agent's tool-call decisions —
> across the context, the file system, the network, and the shell, and even
> after the data is stored and re-read (stored IPI).

The invariant is scoped to the **integrity axis ON**: the protection modes
`injection` and `full` ([protection-modes.md](protection-modes.md)). The
product's built-in default is the mode `secrets` (`int OFF × conf ON`),
chosen because confidentiality is the end-user lead feature; that default
does NOT carry the IPI defense, and user-facing copy says so. The integrity
axis is **frozen** (protection-modes.md §10): its code is kept and
smoke-tested, but the modes that turn it on run only behind an explicit
opt-in. The invariant itself is unchanged, and its oracles pin `injection` or
`full` by name (`tests/stack/protection-modes.test.ts`), with every other
suite stating its axes under `MANDU_AXES_STRICT`. The axes stay independently
switchable (`MANDU_INTEGRITY`, `MANDU_CONFIDENTIALITY`, confidentiality.md
§11) as expert overrides of the mode.

The confidentiality axis carries the dual: a secret (a registered credential,
or a file or git object labelled above `public`) reaches a model only as an
opaque symbol unless its level admits that model, and never leaves the
machine unless a binding or the human allows it
([confidentiality.md](../confidentiality/confidentiality.md) §5).

---

## 2. The core problem: OpenClaw gives one chokepoint, an OS does not

In adfi-openclaw, the defense lives entirely in **OpenClaw plugin hooks** (see
`docs/adfi-reference/design/openclaw-hook-design.md`). That single tool-call hook
delivers **three** things at once:

1. **The agent-context boundary** — what T-LLM sees, and which tool-call it
   decides (the boundary between "inside the agent" and "the environment").
2. **Tool semantics** — this call is *network* vs *file* vs *shell* vs
   *inter-agent*, so Mandu knows which view to route it to.
3. **Per-field structure** — a JSON schema, so the data trust policy can classify
   individual result fields TRUSTED/UNTRUSTED.

A general OS gives none of these for free. An arbitrary agent is just a process
making syscalls, opening sockets, and exec-ing children. **The entire porting job
is rebuilding those three properties from separate OS-level chokepoints.**

### Unifying principle

Mandu reduces to one rule:

> **Symbolize at every ingress into the trust boundary; desymbolize at every
> egress; keep a synchronized dual representation of persistent state.**

OpenClaw realizes this rule at *one* layer (the tool boundary). Mandu realizes
the *same* rule at the OS-resource boundaries. Porting therefore = **enumerate
every ingress/egress path the single tool hook used to cover, and instrument each
one**:

| Boundary | Ingress action | Egress action (desymbolize) |
|---|---|---|
| Model context | **symbolize** `tool_result` / system prompt → T-LLM ← **sole T-LLM invariant chokepoint** | tool_use args from T-LLM |
| Network | **observe-and-tag only**: classify destination host → `taintProcess` on untrusted-host traffic; body returned **RAW** (no symbolize — see `fs-provenance.md` §1.1) | HTTP request to external service (gated by data-usage policy) |
| Filesystem | file read → `classify()` (path policy ∪ taint registry); symbolize if untrusted | human / non-agent program read |
| Shell | command stdout into context (via model-proxy `tool_result`) | command argv / code execution |

The model-context boundary is the **sole** point where untrusted data is symbolized
before reaching T-LLM. The network layer does not symbolize bodies
(`fs-provenance.md` §1.1); at-rest/exfil coverage rests on the fs taint
registry + egress gate. If any ingress path to the *model context* is left
un-instrumented, untrusted data can reach T-LLM un-symbolized and the invariant
breaks. **Completeness of model-proxy ingress instrumentation is the whole
ballgame.**

### Nested symbolization and deep resolution

Because Mandu symbolizes at *multiple* independent chokepoints, symbols
**nest**: under the dual view the fs-sync AgentView twin of an untrusted file is
*already* a `$MDU:Read[..].<file>` on disk, and when the agent Reads that
twin the model-API proxy re-symbolizes the `tool_result` — a symbol whose stored
value is itself a symbol reference. (The reference implementation, with its one
chokepoint, never stacks layers; this is a Mandu-specific consequence of
decentralized enforcement.) Resolution therefore comes in two deliberate depths
(`arbiter/symbol-table/symbol-table.ts`):

- **Deep (fixpoint) — full-fidelity, ungated surfaces.** The `desymbolize` IPC
  op (fs-sync `syncToHuman` → HumanView files) and the quarantined U-LLM's
  `resolve` (`inspect_symbol`, opt-in `deep` flag) collapse the whole chain to
  the raw original. Without this, the U-LLM is handed a literal placeholder and
  every "summarize this file" degrades to describing the token — **security
  holds, utility collapses** (the §6 #1 failure shape). Deep resolution is safe
  on exactly these surfaces because neither is an egress the data-usage policy
  gates: HumanView is *supposed* to hold originals, and the quarantine has no
  exfil channel (its output re-enters T-LLM only re-symbolized). Fixpoint
  iteration is capped (depth 8 + output-size guard) so crafted cycles/blowups
  terminate with leftover symbols **kept opaque** — fail-closed toward
  symbolic. (Which channel may ask for a deep resolve, and at which levels:
  [`arbiter-human-plane.md`](./arbiter-human-plane.md) §3–§4.)
- **Shallow (single lookup) — per-symbol GATED egress.** The network egress
  paths (`net-proxy`, `net-supervisor`) and exec resolution approve each symbol
  individually via `desymbolizationDecision` *before* resolving it. These must
  stay shallow: deep resolution there would let a nested symbol's content ride
  out under the **outer** symbol's approval, bypassing the gate. A nested
  reference that survives shallow resolution egresses as an opaque token — the
  fail-closed direction.

### Symbol format

A symbol is `$MDU:<tool>[<hex hash>](.<field path>)`, for example
`$MDU:web_fetch[a1b2].text` or `$MDU:nomodel_Read[3fa9]` (the `nomodel_`/`anymodel_` markers
carry the confidentiality level). The grammar lives in one place
(`arbiter/symbol-table/symbol-format.ts`, `MDU_SYM_FORMAT`); the Rust scanner
(`interceptors/*-arbiter/src/symbols.rs`), the reply filter, the proxies' hold
and imitation guards, and every egress gate match the same prefix. A field
that is not scanner-complete is encoded (§9).

**The prefix is `$MDU:` since 2026-09-27**; under the old codename it was
`AOS:` with the leading dollar (spelled apart here because the sweep below
scans docs too). The prefix names the product, so a later rebrand would change the
wire format again; that cost was accepted. There is **no back-compat**:
nothing resolves an old-prefix token, so one that arrives in untrusted data is
plain text and is symbolized like any other
(`arbiter/test/component/retired-symbol-prefix.test.ts`,
`interceptors/reply-filter/test/unit/retired-prefix.test.ts`). The symbol DB
schema moved to v3 with it (runtime-instances.md §9a), and a repo-wide sweep
(`arbiter/test/unit/symbol-prefix-sweep.test.ts`) fails on any old-prefix
literal in the tree.

### 2.x Fail-closed needs a DEADLINE, not just a catch

Every interceptor's fail-closed answer lives in a `catch` around its arbiter
call. **A caller that never returns never reaches its catch** — so fail-closed
is only as real as the bound on the await:

- a **dead** arbiter (socket gone) errors on `connect` ⇒ the call rejects ⇒ the
  catch runs ⇒ refuse/block/stay-symbolic.
- a **wedged** arbiter (alive but unresponsive — SIGSTOPped, blocked on disk
  I/O, wedged on a poison row) holds its socket **open**. Nothing errors,
  nothing closes, and a reply is the only thing that settles a request. The
  await hangs forever and the model turn **wedges instead of failing closed**.

The bound belongs at the transport: `ArbiterClient.request()` carries a
per-call deadline (`DEFAULT_REQUEST_TIMEOUT_MS`, 5s — `discoverSecrets`, a real
filesystem walk, gets 30s), covering connect + write + reply, for **every op of
every adapter** — the proxies' ingress `classify`/`symbolize` included. Expiry
rejects, which each caller already turns into its fail-closed answer. Dually,
`ArbiterServer.close()` **destroys established connections**: Node's
`Server.close()` only stops the listener and resolves once every open
connection ends on its own, so one live client made shutdown hang forever.

Found by the confidentiality oracle: its first fail-closed test against an
unresponsive arbiter did not fail — it **hung**. Pinned by
`arbiter/test/unit/wedged-arbiter.test.ts` and the WEDGED fold of
`tests/stack/confidentiality-oracle.test.ts`, both of which hang
against an unbounded client.

**The Rust client (`interceptors/mandu-arbiter`, 2026-10-17)** carries the
same bound; until then its I/O timeout was unset, with no setter, so a wedged
arbiter held every Rust caller. `ArbiterClient::new` now gives every request
one deadline spanning connect + write + the whole reply line:
`DEFAULT_IO_TIMEOUT` (5 s, the TS default) for every op, and
`REPORT_IO_TIMEOUT` (2 s, never above the client's own) for the reports
whose loss costs no protection (`emit`, `reportExecTwins`,
`reportExecCleanVerdict`, `execCleanVerdictFor`). The client has no long poll
or stream, so no op is exempt; `with_io_timeout` / `set_io_timeout` change
the bound (`None` removes it, for a caller that must wait), and the guard's
rediscovery `hello` keeps its own 3 s. Three details the socket timeouts
alone would miss:

- the **connect** is bounded too: a wedged arbiter never accepts, each
  timed-out request leaves one more connection in its listen queue, and a
  blocking `connect` to a full queue sleeps until one is accepted. The
  client sets `SO_SNDTIMEO` before `connect`, which bounds that sleep;
- the **reply** is bounded as a whole, not per `read`: an answer trickled a
  byte at a time would otherwise renew the timeout for ever;
- a connection whose framing is in doubt (a timeout, an I/O error, a torn
  or unparsable line, a reply carrying another request's id) is **dropped,
  never reused**: the late answer would be the first line the next request
  reads. The next call dials afresh. A refusal (`ok: false`) is a whole
  exchange and keeps the connection.

Expiry is `ArbiterError::Timeout { op, after }` (`is_timeout()`), and every
caller already took any `Err` as the unreachable arbiter, so each fails
closed the way it did for a dead socket: the exec supervisor's `plan_exec`
boxes the command (AgentShell) or withholds the argv's symbols, an
escalation stays AgentShell; the guard serves an open of a registered
secret its twin, refuses a holder's connect, its agent-flow record, its
protected write, and makes an unanswered call root a holder; the fs
supervisor takes the writer as tainted; the TPROXY egress gate withholds
every symbol, its ingress is opaque. The best-effort records (the lineage
edge, `recordExecRoot`, the twin report) are lost, as for a dead socket. A
wedged arbiter costs each call its full deadline: nothing fails fast after a
first timeout, because a window of skipped calls would also drop records a
recovered arbiter could take. Pinned by `mandu-arbiter/src/timeout_tests.rs`
(a fake arbiter that accepts and never answers, answers late, trickles, or
never accepts with its queue full), the callers' unit tests, and the kernel
tests `exec_box_bin_boxes_a_humanshell_command_when_the_arbiter_hangs`
(exec-supervisor, the bin at its default deadline) and
`a_wedged_arbiter_gives_an_open_of_a_secret_its_twin_at_the_deadline`
(net-supervisor's guard: two opens, one question each, each on a fresh
connection, the second open's time between one deadline and ten). That test
times the SECOND open because a binary's first open of a secret also pays the
guard's one reading of that binary (its sha256 and content scan, once per
inode, `reader_identity`), which is no arbiter wait: for the 60+ MB test
binary, read by every guard of the parallel kernel lane at once, it took 3 to
4.4 s in CI while the question itself cost its one 300 ms deadline
(2026-10-17).

The deadline also counts the client's own time before the write: a client
thread starved past the whole deadline before it wrote the request gives up
with it unsent, the same `Timeout`, the same fail-closed branch
(`a_deadline_that_passed_before_the_write_sends_nothing`). A test that
wedges ONE op of a sequence gives that op alone the short deadline and the
rest a long one (`ArbiterClient::with_op_deadline`, a seam the `mock`
feature compiles in, never in a production build): with one 200 ms
deadline for all, a mock thread starved on a loaded CI runner answered the
`classifyExec` that `a_wedged_argv_gate_withholds_every_symbol` meant to be
answered too late, the plan failed closed to AgentShell before it reached
the wedged `resolveExecArgv`, and the test read 0 asks of it (2026-10-22;
on one CPU beside eight busy loops, 22 of 30 runs failed so, the escalation
sibling with them). Those tests prove the wedged op was the one reached
from the plan's own reason (`resolveExecArgv timed out`), not from the
mock's count alone.

---

## 3. Hook → chokepoint mapping

| DUALVIEW need | OpenClaw hook (repo) | Mandu (Linux) mechanism |
|---|---|---|
| Inject handling system prompt | `before_prompt_build` | Model-API proxy rewrites request `system` / first message |
| Symbolize agent inbound data | `transform_tool_result`, `transform_webhook_content` | **One ingress point:** model-API proxy (tool_result blocks). The network proxy does not symbolize bodies; it classifies and tags the connecting process (`taintProcess`) and gates egress — see `fs-provenance.md` §2.1. |
| Read tool-call decision / desymbolize outbound | `before_tool_call` | Model-API proxy parses `tool_use` blocks in the model response |
| File two-views + View Synchronization | file-tool path rewrite + `after_tool_call` sync | **FS interposition** (FUSE or seccomp-unotify path-rewrite) over the **existing git-worktree machinery** |
| AgentShell / HumanShell (repo: exec `RESTRICTED=1`) | `before_tool_call` exec enforcement | **Exec supervisor** (seccomp-unotify / ptrace) selecting FS + net view per command |
| Resolve symbols in user-facing replies | `message_sending` | **`interceptors/reply-filter/`** — the launcher wraps the agent (ON by default; `--no-reply-filter` / `MANDU_REPLY_FILTER=0` opts out) so its output flows through a desymbolizing stream filter (arbiter deep `desymbolize`). Piped/print runs filter through a plain pipe; interactive full-screen TUIs on a TTY are relayed through a **PTY** (`script(1)`: util-linux on Linux; BSD on macOS with a resize/signal companion, pty-relay.md), so the TUI keeps a real terminal. The filter emits eagerly (only a possible in-flight token suffix is held) and reassembles tokens hard-wrapped across rows (confidentiality.md §7); `MANDU_REPLY_FILTER_PTY=0` or a missing backend degrades to passthrough |
| Symbol table | in-process SQLite singleton | Same SQLite, promoted to an **arbiter daemon** all interceptors query |

**Key realization:** the **model-API stream gives back the structured "tool call"
that OpenClaw's hook provided.** The Anthropic / OpenAI Messages API already
carries structured `tool_use` / `tool_result` blocks with names and arguments. So
interposing the agent↔provider connection **recovers the semantic tool boundary
without an agent runtime** — we do not have to reverse-engineer raw syscalls back
into "tools." This is what makes Mandu more than a sandbox.

---

## 4. Architecture

```
                       ┌──────────────────────────────────────────┐
   cgroup v2 scope ───►│  agent process  +  all descendants        │
   (membership = the   │  (child shells, curl, python, ...)        │
    monitored agent)   └───┬───────────┬───────────┬──────────────┘
                           │           │           │
              model-API    │  files    │  network  │  exec
              traffic      │           │           │
                           ▼           ▼           ▼
        ┌──────────────────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐
        │ (1) Model-API         │ │ (3) FS   │ │ (2) Net  │ │ (4) Exec   │
        │     proxy             │ │ interpose│ │ proxy    │ │ supervisor │
        │  AgentView @ context  │ │ AgentFS/ │ │ ingress= │ │ AgentShell │
        │  symbolize tool_result│ │ HumanFS  │ │ raw+tag  │ │ /HumanShell│
        │  read tool_use        │ │ + sync   │ │ egress=  │ │            │
        └──────────┬───────────┘ └────┬─────┘ │ desymbol │ └─────┬──────┘
                   │                   │       └────┬─────┘       │
                   └──────────┬────────┴────────────┴────────────┘
                              ▼
                  ┌──────────────────────────────┐
                  │  Mandu arbiter daemon         │
                  │  - symbol table (SQLite)      │
                  │  - policy engine (reused)     │
                  │  - routing decisions          │
                  └──────────────────────────────┘
```

### 0. Process scoping — cgroup v2

Run the agent and **all** descendants in a dedicated cgroup v2 scope
(`systemd-run --scope`). Membership answers, for every interceptor, "does this
connection / file access / exec belong to the monitored agent?" (via
`SO_PEERCGROUP`, eBPF `sock_ops`, mount namespace). This replaces OpenClaw's
`isTargetSession()` gating. cgroup v2 tracks descendants, so daemonized children
can't trivially escape.

### 1. Model-API MITM proxy — AgentView at the context boundary

The agent talks to `api.anthropic.com` / `api.openai.com` / a local inference
server. Mandu points the agent's base URL at a local reverse proxy (no CA
needed for the supported agents) and parses the Messages API:

- **Request (agent→model):** apply the **data trust policy** (repo: inbound data
  spec / output classification) to `tool_result` blocks; symbolize untrusted
  spans so **T-LLM** sees `$MDU:*`. Inject the handling system prompt.
  *(= `before_prompt_build` + `transform_tool_result`.)*
- **Response (model→agent):** parse `tool_use` blocks — the agent's tool-call
  decisions. Record them so the OS interceptors below can **correlate** a
  subsequent `openat` / `connect` / `execve` to a known tool decision and route
  it. *(= `before_tool_call`, read side.)* One display-only exception
  (`reply-row-reservation.md`): a token whose value takes N ≥ 2 rows goes to
  the agent as an N-row reserve block, so its TUI lays out the rows the reply
  filter paints. The token can stand alone on its line or sit inside a
  sentence, and a line wider than the terminal counts as the rows it wraps
  to. The block holds no original, and the next request collapses it back to
  the token before T-LLM sees it. The Codex proxy does the same on the
  Responses wire.

This is the heart of Mandu: the AgentView context boundary, reconstructed at
the network layer with zero agent cooperation.

**Realized for two model APIs.** `interceptors/anthropic-proxy/` is the
**Anthropic Messages API** interposer for **Claude Code**; `interceptors/openai-proxy/`
is its sibling for the **OpenAI Responses API** (the **Codex CLI**). The Codex
proxy symbolizes untrusted `function_call_output` spans and injects the
handling prompt on the request side (symbolization is request-side only —
never on the response path); with a view map configured (fs-sync.md §1
P4) it also forward-rewrites the model→agent SSE so HumanView paths in the
model's shell commands map into the AgentView, and without one the SSE streams
back verbatim. For observability it reads the model's answer off the relayed
body passively, so a Codex session's trace shows its prompts and replies like a
Claude one. Fail-closed, with e2e coverage
(`codex-chatgpt.test.ts`, `codex-view-map.test.ts`, `codex-prompt-filter.test.ts`). Both are the
*same* most security-critical chokepoint, instantiated per provider.

**Which requests go upstream (fail-closed routes).** Each proxy parses a fixed
set of generation wires, so each sends a request to the provider only when it
can vouch for what it carries (`src/route.ts` in both packages): the parsed
wire (`POST …/v1/messages`, `POST …/responses`, and on the openai-proxy Chat
Completions, `POST …/chat/completions`, `src/chat-wire.ts`, read as the
Responses request it carries and masked with the same rewrite) is symbolized;
the Anthropic `POST /v1/messages/count_tokens`, which carries the whole
conversation, goes through the same symbolization minus the handling prompt;
a bodyless `GET`/`HEAD` (model listings, Claude Code's `HEAD /api/hello`) is
relayed; every other request is answered 403 by the proxy and never sent.
Relaying unparsed routes raw would let an agent speaking another generation
wire through the proxy (Anthropic's OpenAI-compatible `/v1/chat/completions`,
`/v1/complete`, Messages batches, Codex's older `/responses/compact`) reach
the model with its tool results unmasked — the fresh-agents VM suite found an
OpenClaw config doing exactly that (`os-test-matrix.md §10` §14.1). The
route table and the probe-verified wire of each supported agent are in each
proxy's README; `tests/stack/proxy-route-fail-closed.test.ts` pins both
proxies over the real arbiter.

Because all agent traffic funnels through this one chokepoint, the anthropic-proxy
also absorbs **transient upstream throttles** (HTTP 429 rate-limit / 529 overloaded)
with bounded retry + backoff (honoring `Retry-After`) before committing the
response — so an overloaded API surfaces to the agent as added latency, not a hard
failure on every spike. The retry is off the security path (it never alters
symbolization) and never masks a persistent throttle: after the attempt cap the
real upstream status is relayed unchanged (`ProxyOptions.retry` /
`upstreamWithRetry`).

**Each run is its own dashboard session.** The proxy stamps every
observability event's `sessionId` from the request itself: `sessionIdFor()`
honors the first present of `SESSION_ID_HEADERS` (`x-mandu-session-id`, then
`x-mandu-session`, `x-session-id`), else a fixed per-*process* fallback. The
launcher mints a unique `MANDU_SCOPE_ID` per run and tags the agent's
Anthropic requests with `x-mandu-session-id = MANDU_SCOPE_ID` through Claude
Code's official per-request header variable
(`ANTHROPIC_CUSTOM_HEADERS="x-mandu-session-id: $MANDU_SCOPE_ID"`), so the
proxy files each run as its own session and the dashboard renders one trace
per run. The `x-mandu-*` headers (session id, batch id, tenant) are read by
the proxy and **never forwarded**: both model proxies drop every `x-mandu-*`
request header before the provider on every route (`sanitizeHeaders`), so the
user's session, batch and tenant are not named to a third party.

### 2. Egress / ingress network proxy — HumanView network

Redirect the cgroup's **non-model** traffic (nftables `REDIRECT`/TPROXY, eBPF,
or a cooperative forward proxy). Network analog of `web_fetch` / `web_search`:

- **Ingress (external→agent):** classify the destination host; on an untrusted-host
  connection, best-effort `taintProcess` the connecting process so a later file write
  or outbound send is recognized as untrusted-by-origin (**observe-and-tag**). The
  response body is returned **raw** — no body rewrite. The T-LLM invariant is
  enforced **solely** at the model-API proxy (chokepoint 1), which symbolizes every
  `tool_result` span regardless of how the bytes travelled (see `fs-provenance.md`
  §1.1). At-rest/exfil coverage rests on the fs taint registry + egress gate (§6).
  Fail-closed on arbiter miss: a classify failure still substitutes an opaque marker
  rather than serving raw.
- **Egress (agent→external):** HumanView — remote endpoints need original data,
  so **desymbolize**, gated by the **data usage policy** (repo: outbound data
  spec): a symbol used as a *destination* or smuggled into a request requires
  human approval; a tainted-process send to an untrusted host is also gated.

Model-API traffic is excluded here and handled by (1) under a different policy.

This is realized two ways: `interceptors/net-supervisor/` (Rust: the kernel
TPROXY/nftables path, and the unprivileged seccomp `connect(2)` guard the
launcher runs as `mandu-net-guard`) and `interceptors/net-proxy/` (TS) for the
**cooperative wrapper-layer path** — a forward `HTTP_PROXY`/`HTTPS_PROXY`
proxy (with an optional session-CA MITM for HTTPS bodies) that runs
**unprivileged** and on by default in the launcher. Both gate the egress
symbol through the arbiter's data-usage policy; only the attachment mechanism
differs (see [`privilege-model.md`](./privilege-model.md) §2, kernel layer vs
wrapper layer).

Under the MITM the proxy re-originates each request it lets out as the
client wrote it (header order and case), apart from what it owns: one
`Host` naming the CONNECT target the gate judged, the body's real
`Content-Length`, `Accept-Encoding: identity`, no hop-by-hop headers
(`reoriginationHead`; a strict server such as nginx refuses the duplicate
Host the proxy appended until 2026-10-05, confidentiality.md §7.1).

The forward proxy refuses a request whose destination is **its own listen
address** (`isSelfDestination`) with `508 Loop Detected`, never forwarding it.
Without this guard a single request to the proxy's own port re-enters the
listener via the Host-header fallback and recurses until ephemeral ports
exhaust (a local resource-exhaustion DoS and event-log blowup: one such
request once emitted tens of thousands of `net_action` events in seconds).

Both layers also deny the launched agent's own **upload hosts** (the hosts it
would send its transcript, trace or telemetry to; supported-agents.md §5.3.4
rule 1): the launcher's per-target table (`launcher/src/upload-deny.ts`)
becomes `mandu-net-guard --deny` rules, checked before every allow, and the
net-proxy's `MANDU_NET_PROXY_DENY_HOSTS`, which answers a CONNECT or
plain-HTTP request to a listed host 403 before any dial
([exec-routing.md](../integrity/exec-routing.md) §7.5, "Deny rules").
The launcher also hands the net-proxy the AI agents' login files its
session leaves raw (`MANDU_NET_PROXY_SESSION_LOGINS`), which the proxy
sends with each fingerprint-tripwire scan, so another session's
registration of a login does not refuse the agent that runs here its own
([secret-discovery.md](../confidentiality/secret-discovery.md) §1.10). Both
values are in the proxy's identity: a launch adopts a running proxy only
when they match its own. And it hands the proxy the length of the **held
request** (`MANDU_EGRESS_HOLD_MS`, always set): the user's value, else 60 s
for an interactive session on a terminal and 0 for CI, a run whose output
is not a terminal and a one-shot (`claude -p`, `codex exec`), decided once
in `launcher/src/egress-hold.ts` from the reply filter's notion of an
interactive run; a proxy started without the launcher never holds
([egress-hold.md](../confidentiality/egress-hold.md) "The default").
With the confidentiality axis on it also sets
`MANDU_NET_PROXY_MODEL_HOST_DENY=1` (the **model-host deny**, 2026-10-18,
[agent-sdks.md](../agents/agent-sdks.md) §4): the model vendors' hosts
leave the agent's `NO_PROXY`, the connect guard denies them, and the proxy
lets each take only its listed account and sign-in paths (the whole host
refused where TLS inspection is off), so a program of the tree that calls a
model itself (a `claude` started by its full path) is refused; the switch is
in the proxy's identity too.

The proxy also supports an OPTIONAL **offline web mock** (`MANDU_NET_PROXY_MOCK_SITES`
→ a YAML `url → canned response` map; `MockSites`). A matching outbound request is
served the canned response **as the upstream** (no network) — that response flows
through the net layer **raw** and is observe-and-tagged — so a **real Claude Code
agent** can run a deterministic `fetch → write → read` loop offline while the
defense is exercised end-to-end. The model proxy symbolizes the agent's
`Bash`/`Read` `tool_result` of that content, so the T-LLM invariant still holds.
This is Mandu's realization of adfi-openclaw's per-URL fixture interception,
moved to the network chokepoint. Test/observability only; a mocked response is
classified + observe-and-tagged exactly like a real one (no invariant impact).

The same file may hold **host routes** (`hosts:`, the replay runner's per-host
catch-all, docs/testing/differential-interactive.md §28): a named host, or `*`
for every other one, whose plaintext requests and CONNECTs go to a
**loopback** test listener instead of the internet (a route to any other
address is refused when the file loads). The egress gate runs first and
unchanged, and a model host is never routed by `*` (only by a route naming
it, and only under the model-host deny, which terminates model hosts:
agent-sdks.md §4). Under MITM the body gate still
runs on the terminated request and only the re-origination dials the route,
over TLS that is still verified, against the route's own CA (`tls_ca`) for the
host's name; without MITM the blind tunnel is pointed at it. A route changes
only where a request the gate allowed is delivered, so it has no invariant
impact either; it exists so a replay never leaves the machine and its
listener records the bytes Mandu let out.

### 3. Filesystem interposition — Agent File System / Human File System + Sync

The paper already rewrites file paths into a git-worktree AgentView and syncs to
HumanView with blame-based re-symbolization (see
`docs/adfi-reference/design/fs-level-tracking.md` and
`docs/adfi-reference/design/human-edit-policy.md`). **Keep that machinery.** Only
the *trigger* moves:

- **seccomp-unotify supervisor** rewrites `openat()` paths for tracked workspaces
  to the AgentView worktree (exactly what the file-tool hook does today — only
  *who* rewrites the path changes), **or**
- a **FUSE** mount that symbolizes content on read.

Reads → symbolized (AgentView); writes → captured into AgentView; a sync daemon
reconciles to HumanView (the real on-disk files others see). Human edits
re-symbolize via `git blame`, unchanged. This is the **highest-reuse** part of
the port: the reference implementation's git, file-commit, human-edit and
revert modules (`dualview-git.ts`, `dualview-filecommit*.ts`,
`dualview-human-edit.ts`, `dualview-revert.ts`; older notes call them
`adfi-*.ts`) survive largely intact.

### 4. Exec supervisor — AgentShell vs HumanShell

When T-LLM decides `bash`/exec, the child runs in the cgroup. Route per command
(see `docs/adfi-reference/design/exec-with-symbols.md`,
`untrusted-command-execution-patterns.md`):

- **AgentShell (default):** net namespace with egress disabled, FS mapped to
  AgentView. Output is already symbolic. Safe.
- **HumanShell:** network enabled, FS mapped to HumanView, argv desymbolized —
  **only after** the data usage policy check (symbol-as-command → approval) and
  the command-rewriting rule (`python fix.py` → `python -c <file content>`),
  enforced by scanning `execve` argv.

Realized two ways: `interceptors/exec-supervisor/` (Rust, kernel ptrace/seccomp +
namespaces; the launcher's exec box) for the hard per-exec sandbox, and
`interceptors/exec-wrap/` (TS) for the **cooperative wrapper-layer path** — a
`PATH`-shadowing wrapper over a set of HIGH-RISK commands that asks the
arbiter's exec policy and refuses a symbol-as-command exec (fail-closed),
running **unprivileged** and on by default in the launcher (see
[`privilege-model.md`](./privilege-model.md) §2, wrapper layer).

### Realization status — architecture box → package

Each numbered box above is realized by a concrete package. Run the suites with
`scripts/test-all.sh` (every suite is an entry of the manifest
`tests/suites.mjs`, [`test-organization.md`](../testing/test-organization.md));
wire a live run with the `mandu` launcher. Per chokepoint × layer detail:
[`architecture-map.md`](./architecture-map.md) §9.

| § | Architecture box | Package(s) | Status |
|---|---|---|---|
| 4.0 | Process scoping — cgroup v2 scope | `launcher/` (`systemd-run --scope`, graceful no-systemd degrade) | **Implemented** |
| 4.1 | Model-API proxy — AgentView @ context (Claude Code) | `interceptors/anthropic-proxy/` (symbolize `tool_result`, inject handling prompt, record `tool_use`) | **Implemented** (userspace reverse proxy via `ANTHROPIC_BASE_URL`; live §9 oracle) |
| 4.1 | Model-API proxy — AgentView @ context (Codex CLI) | `interceptors/openai-proxy/` (symbolize OpenAI Responses `function_call_output`, inject handling prompt) | **Implemented** (userspace reverse proxy; request-side symbolize; live Codex e2e) |
| 4.2 | Egress / ingress network proxy — HumanView network | `interceptors/net-supervisor/` (Rust: kernel TPROXY + the unprivileged `connect(2)` guard) **+** `interceptors/net-proxy/` (TS wrapper-layer forward proxy, optional session-CA MITM) | **net-proxy** and the **connect guard**: live unprivileged, on by default. TPROXY attachment `kernel`-gated (root / host-global state, not used by the launcher). **Ingress posture:** observe-and-tag only — body returned raw; egress gate unchanged. |
| 4.3 | Filesystem interposition — AgentFS/HumanFS + Sync | `fs-sync/` (TS git-worktree view-sync) **+** `interceptors/fs-supervisor/` (Rust kernel: seccomp-unotify `openat()` rewrite, Landlock plans) | **Sync implemented** (integrity modes; frozen axis); fs-supervisor's seccomp `openat()` rewrite is `kernel`-gated; its Landlock plans run inside the exec box. `interceptors/fs-preload/` (an `LD_PRELOAD` interposer) is a **retired** rung: in-tree and tested, wired to nothing |
| 4.4 | Exec supervisor — AgentShell vs HumanShell | `arbiter/policy/exec-*.ts` (classify/resolve argv) **+** `interceptors/exec-supervisor/` (Rust kernel: the exec box) **+** `interceptors/exec-wrap/` (TS `PATH`-shadow, wrapper layer) | **Decision logic implemented**; **exec-wrap** and the **exec box** live unprivileged, on by default (probe-gated) |
| — | Mandu arbiter daemon — symbol table + policy + routing + event stream | `arbiter/` (Unix-socket NDJSON daemon; `mandu-arbiter` Rust client) | **Implemented** |
| — | Cooperative U-LLM path (`inspect_symbol`, §6 #1) | `interceptors/inspect-mcp/` (MCP stdio server) | **Implemented** |
| — | Policy agent surface: the agent reads the law, tests a flow, proposes typed edits (tighten applies, loosen waits for the user) | `interceptors/policy-mcp/` (MCP stdio server `mandu-policy`, mounted beside `mandu-inspect`; [design](../ui/policy-surface.md) §5.1) | **Implemented** (Claude Code, OpenCode, Codex; `--no-policy-mcp` opts out) |
| — | User-reply egress — resolve symbols in user-facing replies (`message_sending`) | `interceptors/reply-filter/` (TS wrapper CLI over the agent's output) | **Implemented** (live unprivileged, ON by default — `--no-reply-filter` opts out; pipe for print runs, PTY relay for interactive TUIs (util-linux on Linux; BSD on macOS with a resize/signal companion, pty-relay.md)). UTILITY-ONLY: degrades to passthrough (symbols stay opaque) on any arbiter failure. |
| — | Observability — the privileged Mandu dashboard | `dashboard/` (event model + `ArbiterEventSource` + API/SSE) | **Implemented** |
| — | Fleet observability + **actuator** — the SIEM (Wazuh) enforcement feed | a redacting SIEM exporter + Wazuh rules and the SIEM→arbiter lockdown callback; enterprise components, not in the public repository | **Implemented** ([design](../ui/siem-integration.md)). Ships symbolized forms + content hashes only (never `DualRepr.original`); a fleet campaign alert can `setSessionPosture(lockdown)` — Mandu as actuator, not just sensor. |
| — | Cross-component proof of the §1 invariant | `tests/stack/` (real arbiter + proxy + inspect-mcp + dashboard, in-process) | **Implemented** |
| — | Conformance suite — declarative scenarios + assertion DSL | `tests/conformance/` (real arbiter + ingress proxy vs mock upstream) | **Implemented** |
| — | Red-team ASR + benign eval (deterministic: benign fidelity; live: real utility) | `eval/` (deterministic neutralization contrast + a live real-agent backend) | **Implemented** |

The arbiter is the centralized decision point (§5): the model proxies, the
inspect-mcp server, the fs-sync daemon, and the Rust interceptors are all clients
of its symbol table + policy engine + event stream over the Unix socket.

**Privilege:** the context layer (the model proxies, the arbiter, inspect-mcp)
runs **fully unprivileged**, so the §1 invariant needs no privilege at all. The
kernel-layer rungs (the exec box, the Landlock TCP confine, the `connect(2)`
guard, the secret-twins wrap) need no host root either: they use unprivileged
user namespaces, seccomp user notification and Landlock, are on by default where
the kernel allows, and self-degrade where it does not. Their wrapper-layer
equivalents (`net-proxy`, `exec-wrap`) need nothing. The full enforcement
layering (context layer → wrapper layer → kernel layer) is in
[`privilege-model.md`](./privilege-model.md) §2.

---

## 5. Where view routing lives

Routing is **not** solely in the network proxy.

- **Decision is centralized** in the Mandu arbiter's policy engine (lifted from
  the reference implementation's `policy/*`), informed by the model-API
  proxy's view of tool semantics.
- **Enforcement is decentralized:** the network proxy routes *network* actions,
  the FS layer routes *file* actions, the exec supervisor routes *shell* actions.
  The network proxy alone cannot route a file write or a shell exec, so it cannot
  be the single home for view routing.

---

## 6. Honest hard problems (research risks)

1. **Uncooperative-agent utility gap (the U-LLM / `inspect_symbol` path).** In
   DUALVIEW the agent *cooperates* — instructed by system prompt to call
   `inspect_symbol`, routing untrusted-data processing to the quarantined
   **U-LLM**. An arbitrary agent will not. With pure symbols it would try to
   "summarize `$MDU:1`" and produce garbage — **security holds, utility
   collapses.** This is the central open problem. Two paths:
   - (a) the model-API proxy implements U-LLM **transparently** — detect a symbol
     that needs processing, run a quarantined desymbolized call, re-symbolize,
     inject. (The hard part: detecting "needs processing" without tool
     semantics.) This is the differentiating research contribution.
   - (b) ship an opt-in SDK shim for agents willing to call `inspect_symbol`.
2. **Coarser classification at the network layer.** OpenClaw classifies 21 tools
   with field-level schemas. Raw HTTP/HTML has no schema, so the data trust
   policy degrades from *schema rules* to *origin rules* (whole-body untrusted) →
   more symbolization, lower utility. The model proxy's tool_result view partly
   recovers structure.
3. **TLS trust / cert pinning.** Interposing TLS needs the agent to trust our CA;
   pinned clients break. The supported agents avoid it (a base-URL override is a
   cooperative reverse proxy); the net-proxy's optional MITM is where it applies.
4. **Free-form (ReAct-text) agents** that do not use a structured tool API lose
   the semantic boundary — fall back to OS-only heuristic correlation.
5. **Intra-process flow is untracked** (same boundary the paper accepts — it
   never tracks inside T-LLM). Safe **iff** every ingress path is symbolized; the
   porting risk is missing an ingress path (DNS, raw sockets, `mmap`'d files,
   shared memory, clipboard, X11 paste).
6. **Overhead** stacks on the paper's already-high 48–93% token overhead (FUSE
   read-time symbolization + per-syscall supervision).
7. **Symbol quality blindness.** Symbolization hides a tool result's *quality*
   along with its content: T-LLM cannot see that a fetch returned an error
   page / auth wall / the tool's own refusal, and since `inspect_symbol`
   results are always re-symbolized it cannot plausibility-check derived
   results either — the defense turns recoverable tool misuse into silent
   wrong answers. Unlike #1 this bites even a fully cooperating agent. Design
   + fixes: [`symbol-quality.md`](../integrity/symbol-quality.md)
   (handling-prompt guidance, the enum-constrained `content_kind` triage
   verdict, and request-aware provenance enrichment implemented; eager
   symbolize-time triage deferred).
8. **Symbol-twin shell blindness.** Under the fs rung an untrusted workspace
   file is one whole-file symbol in the AgentView, so a shell `grep` / `sed`
   over it returns nothing and T-LLM gets an empty result with no hint that
   the emptiness is structural — it then answers "no such file" / "the file
   is short" with confidence. A specialization of #7 where Mandu itself made
   the non-result and knows why. Design (not built):
   [`symbol-twin-shell-blindness.md`](../integrity/symbol-twin-shell-blindness.md) — a
   proxy-authored, trusted-code-derived per-call note appended outside the
   symbolized span, plus handling-prompt rule R9.

---

## 7. Recommended build order

The order the prototype was built in, and the reason: prove the invariant
before chasing utility. Three layers, highest-value-first:

1. **FS interposition over the existing git-worktree core** — highest reuse,
   lowest risk, immediately blocks stored IPI for any agent.
2. **Model-API proxy** — recovers the tool boundary and AgentView context
   symbolization; this is what makes Mandu more than a sandbox.
3. **Egress / exec routing + data usage policy** — completes HumanView and the
   approval gates.

The transparent U-LLM (problem #1a) is deferred: it is the differentiating
result but should not block a security-only prototype. The milestone record is
[`implementation-plan.md`](./implementation-plan.md).

---

## 8. Terminology cross-reference

| Paper (DUALVIEW) | adfi-openclaw repo (ADFI) | Mandu realization |
|---|---|---|
| DUALVIEW | ADFI | Mandu |
| AgentView | Agent File System / agent-view worktree | symbolized model context + AgentFS worktree |
| HumanView | Human File System / human-view | original on-disk files + desymbolized egress |
| T-LLM (privileged) | privileged LLM | model behind the model-API proxy |
| U-LLM (quarantined) | quarantined LLM / `inspect_symbol` | transparent U-LLM call or SDK shim |
| Symbol | `$MDU:*` | same symbol table (arbiter daemon) |
| Data trust policy | inbound data spec / output classification | ingress symbolization policy |
| Data usage policy | outbound data spec | egress desymbolization gate |
| View Synchronization / Environment Sync | file tracking / two-stage commit / blame re-symbolize | FS sync daemon (reused) |
| AgentShell / HumanShell | exec `RESTRICTED=1` / normal exec | exec supervisor view selection |
| tool-call hook | `before_tool_call` / `transform_tool_result` | model-API proxy + OS interceptors |

---

## 9. Canonical symbol fields

Filesystem paths used to become literal symbol suffixes such as
`$MDU:Read[5a9a].bin/report.mjs`, while the scanners stop before `/`. The table
owned the full name, but deep resolution received only a prefix. AgentView
(repo: Agent File System / agent-view) stayed symbolic and T-LLM (repo:
privileged LLM) received no raw source; U-LLM (repo: quarantined LLM) lost the
source it was meant to process. The fix changes only the token
representation.

### 9.1 Allocation rule

Canonicalize the rendered field in the default MDU format's `generate` method.
Keep ordinary scanner-complete fields unchanged: for example `result`,
`notes.md`, and `body.__mdu_split[0]`. Any other field, including nested paths,
hyphens, spaces, numeric-leading names, Unicode, and an explicitly empty field,
becomes `__mdu_field_` followed by four lowercase hexadecimal digits per UTF-16
code unit (`canonicalSymbolField`). This is injective for JavaScript strings,
including lone surrogates; UTF-8 replacement encoding would not preserve that
property.

The prefix `__mdu_field_` is reserved for new allocations. An original field
starting with it is encoded too, even when otherwise scanner-complete. Thus a
literal encoded-looking filename cannot collide with the encoding of another
field under the same tool/hash. No slash-to-underscore replacement, truncation,
hash-only field encoding, or relaxed scanner grammar is introduced. A missing
field still produces a bare token. Existing full-token allocation collision
handling remains in effect.

Only the token representation changes. `SymbolEntry.field`, origin, tool,
session/call identity, parent lineage, line range, integrity/confidentiality,
and bindings keep the original values. The arbiter's derived allocator uses the
stored parent field when appending `.__mdu_split[n]`, so its provenance does
not depend on decoding a token. The experimental composable format factory is
unchanged: it is not the deployed MDU scanner/allocator pair.

### 9.2 Consumers and compatibility

`extractFieldPath` remains a presentation operation: it strips the token prefix
and hash and returns the **wire suffix**, which may be encoded. It is not an
inverse provenance API; reading metadata from the symbol table avoids ambiguous
decoding of older literal reserved-prefix names.

An equivalent regex parser, `fieldPathOf` in `fs-sync/src/human-edit.ts`,
constructs split metadata from a token suffix. Its compatibility is handled
with authoritative parent provenance at the filesystem integration layer;
decoding an arbitrary token without its row would conflate old literal names
with new encoded names. The `symbolProvenance` IPC response includes the
original `field` for known rows: a string (including empty) or explicit null
for no field. Unknown rows omit it, preserving their response shape. An absent
field on an older server is distinguishable from a known no-field row;
consumers may retain a legacy plain-tail fallback, but must refuse to guess
encoded-tail provenance.

Persisted symbol identifiers are not rewritten, decoded on load, or assigned
new aliases. Ordinary existing names resolve unchanged. Exact lookup of a
legacy noncanonical name retains its old behavior; scanner-driven resolution
of that name retains the known limitation. Reuse requires the entire existing
name to match the active scanner. A same-key request skips a malformed legacy
name and allocates a canonical new row; subsequent requests reuse that row
normally. The old row and all existing references remain unchanged. The
replacement retains first-mint lineage and joins all matching legacy rows'
confidentiality restrictions, intersects confidential bindings, and never
raises untrusted integrity to trusted. Thus presentation repair cannot
downgrade previously escalated data. Any future migration of persisted
noncanonical identifiers requires its own explicit design and reference audit.

The confidentiality kill switch retains its existing persisted-row semantics
([confidentiality.md §11](../confidentiality/confidentiality.md#11-phasing)): OFF
ignores requested secret labels for fresh allocation keys, but valid-name reuse
and canonical replacement retain stored labels and bindings. Their wire names
may retain or render the corresponding secret marker. This metadata does not
activate OFF enforcement or add confidentiality response fields; it remains
available when the axis is enabled again.

### 9.3 Validation

Unit tests cover complete scanner matching, exact/deep resolution, ordinary-name
stability, injective reserved encodings, metadata and split lineage, persistence,
and legacy identifier preservation. Arbiter IPC e2e tests
(`arbiter/test/component/canonical-symbol-fields.test.ts`) cover
filesystem-shaped fields, nested `public`/`any-model` sources, inherited
destination restrictions, and `no-model`-source exclusion. Separate
fs-sync/model-proxy/inspection integration tests establish the actual
AgentView → quarantine → HumanView path. No policy gate is weakened; raw
untrusted values remain unavailable to T-LLM.
