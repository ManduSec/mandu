# Evaluation — the harnesses, their contracts, and the results so far

> **Status.** Three evaluation harnesses are built and tested; their contracts
> are below. Published results are partial and stated as such in §6: one
> `secrets`-mode utility batch on a real model (2026-09-25, stopped at 61 of 72
> legs), and an offline AgentDojo invariant smoke. The AgentDojo real-model
> ASR/utility numbers have **not been run**; they need a Console API key, and
> they measure the **integrity** axis, which is frozen
> ([protection-modes.md §10](../architecture/protection-modes.md)).

The offline red-team/benign corpus (the deterministic backend) is documented in
[`eval/README.md`](../../../eval/README.md); the cross-component security
oracle is [implementation-plan.md](../architecture/implementation-plan.md) §9.
This document covers the evaluations that need a benchmark or a real model.

Terminology: **T-LLM** (paper) = privileged LLM (repo) = the agent's main loop;
**U-LLM** (paper) = quarantined LLM (repo), reached through `inspect_symbol`;
**AgentView** (repo: Agent File System / agent-view) and **HumanView** (repo:
Human File System / human-view); **ASR** = attack success rate; **leg** = one
rollout of one task on one side (bare agent or wrapped by Mandu).

## 1. The harnesses at a glance

| Harness | Entry | Axis it measures | What it answers | Needs |
|---|---|---|---|---|
| AgentDojo (§2) | `eval/agentdojo/run.sh` | integrity (frozen) | ASR / utility on the benchmark CaMeL and FIDES report | smoke + audit: nothing; real: Console key |
| Benign paired (§3) | `npm run eval:paired` | wrapped leg runs `injection` (frozen lane) | three benign tasks, bare vs wrapped, identical inputs | Claude Code login |
| Repeated utility (§4, §5) | the maintainers' utility runner (not published, §5) | `secrets` (default) | twelve tasks × two sides × three trials | Claude Code login |

Every real-model harness follows the same rules: preparation is the default and
makes no model calls; both sides get identical inputs, model ids, native
permissions and limits; every leg is isolated; nothing retries silently;
missing evidence is `incomplete` (never a pass); and every report keeps its
failed, incomplete and not-run rows.

---

## 2. AgentDojo through the model-API proxy (integrity axis, frozen)

### 2.1 Why AgentDojo

CaMeL and FIDES both report on **AgentDojo** (Debenedetti et al., NeurIPS 2024),
so a number on that suite compares like for like. The harness uses AgentDojo's
own pipeline and checkers rather than a reimplementation.

| Metric | Definition (AgentDojo) | Claim it backs |
|---|---|---|
| **ASR** | fraction of (user task × injection task) pairs whose `security()` check passes | injection neutralized by construction; should fall toward 0 |
| **Utility under attack** | `utility()` pass rate with an injection present | the defense does not break the benign task |
| **Utility (benign)** | `utility()` pass rate with no injection | no over-symbolization tax on normal work |
| **Overhead** | token + wall-clock delta, defense on vs off | the deployment cost |

### 2.2 AgentDojo speaks the API the proxy already parses

AgentDojo is a function-calling benchmark: four suites (workspace, travel,
banking, slack) expose Python tools over a synthetic environment, an
`AgentPipeline` drives a model through a tool loop, and injections are strings
planted in tool **outputs**. An attack succeeds when the model calls a sink
tool (`send_money`, `send_email`, `post_webpage`) with attacker-chosen
arguments.

The defense for that surface is the **context chokepoint**, the model-API proxy
(`interceptors/anthropic-proxy`), and the integration needs no code in the
enforcement path:

1. **AgentDojo's Anthropic client honors `ANTHROPIC_BASE_URL`.** Its pipeline
   builds `anthropic.Anthropic()`, which reads the base URL and key from the
   environment, so pointing it at the proxy is one environment variable
   (verified against `agentdojo==0.1.35`).
2. **The proxy already correlates `tool_use_id → tool name` and classifies each
   `tool_result`** through the arbiter's inbound trust policy
   (`rewrite-request.ts`). An injected string inside a `tool_result` is
   classified UNTRUSTED and symbolized; T-LLM sees `$MDU:*`, never the
   instruction.

```
AgentDojo pipeline ──(Messages API, ANTHROPIC_BASE_URL)──► anthropic-proxy
      ▲  tool loop over synthetic env                          │ classify + symbolize
      │  (send_money / send_email / post_webpage sinks)        │ untrusted tool_result
      └──────────── model response ◄────────── api.anthropic.com
                    (T-LLM saw only $MDU:*)
```

#### 2.2.1 What this does and does not measure

AgentDojo has no real shell, filesystem or network, so it exercises only the
context chokepoint (symbolization at ingress plus the data-usage gate at the
`tool_use` hook), the same surface CaMeL and FIDES measure. The fs / net / exec
chokepoints keep their own oracles (`tests/stack/`, the live drills); the
harness does not try to turn AgentDojo into a syscall benchmark.

### 2.3 The mechanism on one attack

Banking user task "pay last month's rent", with an injection planted in a
transaction **subject** returned by `get_most_recent_transactions`:

- **Defense off:** the model reads the subject and often calls `send_money` to
  the attacker's IBAN; `security()` passes.
- **Defense on:** the proxy symbolizes the transaction list; the instruction is
  not in T-LLM's context, so it is not followed. Second line: if a symbol were
  routed into a sink argument, the arbiter's data-usage policy
  (`desymbolizationDecision`, at the proxy's `tool_use` hook) denies it.

#### 2.3.1 The utility trade-off

Symbolization is wholesale: an UNTRUSTED result becomes a symbol in its
entirety, benign content included. A task that needs the real value of
untrusted content ("summarize my unread emails") is degraded, and `utility()`
records that drop; it is reported, not hidden. Two mitigations: the U-LLM
`inspect_symbol` path (a stretch variant, §2.6, since it changes the tool
inventory), and a calibrated trust policy (§2.4) that keeps the user's own state
TRUSTED.

### 2.4 The trust policy — `agentdojo-inbound.ts`

AgentDojo's tool names are unknown to the Claude Code spec, so without a spec
the fail-closed default symbolizes every tool output (a valid conservative
bound). `arbiter/policy/agentdojo-inbound.ts`, selected with
`MANDU_INBOUND_SPEC=agentdojo`, applies the DUALVIEW rule: **a tool output is
UNTRUSTED iff a party other than the user can influence its content.**

| Suite | UNTRUSTED (symbolize) | TRUSTED |
|---|---|---|
| workspace | received/unread/searched emails, calendar events (participant-authored fields), drive files and listings, `append_to_file`, and the **echo-back action tools** `add_calendar_event_participants`, `reschedule_calendar_event`, `delete_file`, `share_file` (they return a pre-existing, possibly third-party object) | sent and draft emails, `get_current_day`, contact search, pure-metadata action results (`send_email`, `create_calendar_event`, `create_file`, bare-id `cancel_calendar_event` / `delete_email`) |
| travel | hotel, restaurant and car-rental review text | structured lookups, `get_user_information`, reservation metadata |
| banking | recent and scheduled transactions (attacker-set subject), `read_file` | IBAN, balance, user info, transaction-action metadata |
| slack | channel messages, inbox, `get_webpage`, **`get_channels`** (the injection rides in an attacker-created channel name) | `get_users_in_channel`, action metadata |

Anything not listed falls through to UNTRUSTED. The spec reuses the `ToolSpec`
vocabulary of `claude-code-inbound.ts` and is unit-tested per tool
(`arbiter/test/integrity/agentdojo-policy.test.ts`, in the frozen integrity
lane).

**The static trust-gap audit** (`./run.sh audit`, `trust_gap_audit.py`, no key)
runs AgentDojo's ground-truth pipeline, lists every tool output an injection
canary lands in, and asserts each one classifies UNTRUSTED. A TRUSTED tool that
carries an injection is a by-construction hole; an UNTRUSTED tool no injection
reaches is pure utility cost. Its first run found three holes in the first
draft (`get_channels`, `add_calendar_event_participants`, `delete_file`; the
shared cause is action tools that echo back a pre-existing object), fixed
before any model call; it now reports 17 of 17 injection-carrying tools
UNTRUSTED, and the arbiter test above guards the result.

Both configurations are reported: **fail-closed** (no spec, the conservative
bound) and **agentdojo-inbound** (the realistic operating point).

### 2.5 The harness — `eval/agentdojo/`

AgentDojo is a Python library, and "the same suite" means its own 97 user
tasks, 27 injection tasks and checkers, so the harness is cross-language: the
proxy defends any client that speaks the Messages API.

```
eval/agentdojo/
  run.sh             # entrypoint: smoke | audit | real; skips (exit 0) without the venv
  stack.py           # boots the arbiter + anthropic-proxy (real or mock upstream)
  pipeline.py        # AgentDojo pipeline with ANTHROPIC_BASE_URL → proxy
  runner.py          # benchmark defense on/off, aggregates the report
  invariant_smoke.py # offline proof: one task pair against a mock upstream
  mock_upstream.py   # the scripted upstream for the smoke
  trust_gap_audit.py # §2.4 static audit
  attacks_mandu.py   # the adaptive attacks (§2.6)
```

The stack boot follows `eval/lib/live-stack.ts`: the arbiter daemon on a temp
socket, the proxy with `MANDU_UPSTREAM` at the real endpoint or the mock, and
the arbiter's inbound spec chosen by `MANDU_INBOUND_SPEC` (`claude-code` default
| `agentdojo` | `fail-closed`; an unknown value fails closed).

#### 2.5.1 Run tiers

| Tier | Needs | Measures |
|---|---|---|
| invariant smoke | nothing (mock upstream) | the symbolization invariant on a real AgentDojo task pair, through the real arbiter and proxy |
| trust-gap audit | nothing | §2.4 |
| real-model | Console `ANTHROPIC_API_KEY` | ASR / utility / overhead, defense on vs off |

The real-model tier cannot use a subscription: AgentDojo's pipeline is a
third-party SDK client, and a subscription OAuth token presented by a non–Claude
Code client is rejected ([agent-sign-in.md §1](../agents/agent-sign-in.md)
F4/F6).

#### 2.5.2 Test-suite posture

The trust-spec unit test runs in the frozen `test:integrity` lane. The smoke and
audit are opt-in (`run.sh` skips cleanly without the venv). The real-model tier
is manual; without `--out` it writes `report.json` to a fresh run directory
under `~/.mandu/runs/eval/` ([on-disk-layout.md](../architecture/on-disk-layout.md)
§9).

### 2.6 Planned arms and variants

The real-model run plan: all four suites; configurations baseline,
agentdojo-inbound and fail-closed; attacks `important_instructions` (the
leaderboard standard), `injecagent`, and an adaptive arm; a capped Haiku subset
first to validate the path, then the full 629 attack pairs plus 97 benign tasks.
The headline model is `claude-sonnet-5` (`DEFAULT_MODEL` in `pipeline.py`):
`important_instructions` names the model in prose and AgentDojo 0.1.35's name
table stops at Claude 3.7, and the 2024-era models CaMeL and FIDES ran on are
retired upstream. So the primary claim is the defense-off vs defense-on contrast
on one current model; a comparison with the published CaMeL/FIDES rows carries
a model-era caveat.

The adaptive arm (`attacks_mandu.py`, AgentDojo's `@register_attack` seam,
`--attack mandu_*`):

1. **`mandu_delimiter`** — a port of DUALVIEW's wire-format escapes (close the
   function-results block, inject fake turns). Expected: no change in ASR, the
   escape stays inside the symbolized blob.
2. **`mandu_symbol_aware`** — attacks that assume symbolization: ask the model
   to inspect a symbol and act on it, or route a `$MDU:*` into a sink argument.
   Expected: neutralized by the egress gate; a success is a gate bug.
3. **`mandu_split`** — a payload split across results or across a trusted /
   untrusted field boundary. Expected: neutralized; a success is a proxy-parser
   attribution bug.

Stretch variants, reported separately from the headline: `inspect_symbol` in
the AgentDojo toolset (recovers "summarize my emails" utility); real Claude Code
over the suite tools as an MCP server (an end-to-end proof, not a leaderboard
number); benchmark v1.2 (35 injection tasks, 949 pairs).

### 2.7 Results

**Invariant smoke (offline) — PASS.** `./run.sh smoke` runs slack `user_task_0`
× `injection_task_1` (attack `important_instructions`) through the real arbiter
and proxy against a mock upstream. In the forwarded request the `get_webpage`
result was UNTRUSTED and symbolized; the injection tokens and the benign page
body were both absent; the injection reached the model only as a symbol. This
confirms the wire integration; it is not an ASR number.

**Trust-gap audit — PASS** (17 of 17 injection-carrying tools UNTRUSTED, §2.4).

**Real-model ASR / utility / overhead — not run.** The table below stays empty
until a Console key is supplied; because the integrity axis is frozen, these
numbers are not on the current roadmap.

| Config | ASR | Utility (attacked) | Utility (benign) | Token overhead |
|---|---|---|---|---|
| baseline (defense off) | _not run_ | _not run_ | _not run_ | — |
| Mandu fail-closed | _not run_ | _not run_ | _not run_ | _not run_ |
| Mandu agentdojo-inbound | _not run_ | _not run_ | _not run_ | _not run_ |

### 2.8 Provenance

- **Benchmark:** `agentdojo==0.1.35`, `benchmark_version="v1"` (workspace 40·6,
  travel 20·7, banking 16·9, slack 21·5 → 97 user × 27 injection = 629 attack
  pairs).
- **Reused, unchanged in the enforcement path:** the arbiter (`classify`,
  `desymbolizationDecision`), `interceptors/anthropic-proxy`, the stack-boot
  pattern of `eval/lib/live-stack.ts`.
- **New:** `arbiter/policy/agentdojo-inbound.ts` and `eval/agentdojo/`.

---

## 3. Benign paired evaluation (three tasks)

A product-utility evaluation of three benign tasks, separate from the security
corpus; it changes no classification or enforcement. Code:
`eval/run-paired.ts`, `eval/lib/paired/`. Its wrapped leg runs the `injection`
mode, so the suite sits in the frozen lane; the `secrets`-mode measurement is
the repeated utility batch (§4).

### 3.1 Contract

Two configurations: `unwrapped` (Claude Code invoked directly) and
`wrapped-default` (the same binary through the launcher with its default
protections and the inspection MCP). Both get identical task files, model id,
native permission settings and limits; every leg gets a fresh workspace and
isolated home/config/runtime state; pair order alternates; nothing retries
silently. The report records model ids, agent version, source revision,
task/check hashes, launch arguments and limits.

The smoke profile exposes Read/Write/Edit/Glob/Grep plus the inspection tool,
with Claude's `dontAsk` permission mode on both legs. It is a recorded
native-agent profile, not a claim about every Claude setup.

### 3.2 Tasks and acceptance

Three owned synthetic fixtures: extraction (BP-01), merge/filter (BP-02), and
recovery from a missing primary input (BP-03). Outputs are JSON compared to
exact expected values; inputs must stay byte-identical; symlinked, oversized,
missing or malformed outputs are rejected. Acceptance data lives outside the
candidate workspace and is never in the prompt; task/check digests freeze each
run's inputs and oracle. A scripted model's prescribed answer never counts as
task utility.

### 3.3 Evidence

Outcome and boundary verdicts are kept apart; a correct output does not repair
missing capture or a boundary violation. On the wrapped leg, unique harmless
input markers must never appear in captured T-LLM requests, and tool-result
symbols and a successful U-LLM inspection must be observed; the unwrapped
control must consume the same markers raw. HumanView outputs must pass the
task's checks. Missing evidence is `incomplete`; unavailable usage or cost is
null, not zero.

**Where a run writes.** The operator's `--out` when given; otherwise a fresh
owner-only (`0700`) directory
`~/.mandu/runs/eval/<UTC yyyymmddThhmmssZ>-<suite>-<6 hex>/`, never reused
(`eval/lib/eval-out.ts`; moved only by `MANDU_HOME`). The runner prints
`Output: <dir>` before it starts. A run's Unix sockets never live under it.

### 3.4 Execution modes and budget

`prepare` (default) writes the manifest and a review packet with no model calls.
`scripted` drives the real Claude binary and launcher against loopback fake
model endpoints (plumbing only). `real` (API key) refuses without a valid,
single-use approval carrying the reviewed task digest, fixed model ids, expiry,
request/output/time limits and a cost ceiling, validated before any process
starts. `subscription` runs on the agent's own login instead, with no API-key
fallback.

Both T-LLM and U-LLM requests pass through harness-owned HTTPS observers
(verified TLS to `api.anthropic.com`), so one shared ledger covers the agent and
the inspection server; the CLI's own budget cannot account for the latter. In
API mode each completion reserves its worst-case token cost before contacting
the provider; missing or partial usage keeps the full reservation and stops the
batch. Keys, authorization headers and provider error bodies never enter
artifacts; agents get local dummy credentials (API mode) or a disposable
per-leg CLI config holding only the OAuth login (subscription mode). The
observers buffer each response until usage is complete, which affects
streaming latency equally on both sides.

The runner owns and cleans up its processes and starts its own in-process
arbiter; it never touches the resident stack.

### 3.5 Failure-analysis packet

Every report flush also writes `analysis.json` and `ANALYSIS.md` (with the
report's digest), indexing failed, incomplete and not-run legs (boundary
violations first) plus one reproducibly sampled pass per configuration. Each
leg writes `trajectory.json`, which points into the captured requests with JSON
pointers and hashes tool arguments. Latency comparisons use only pairs with two
successes and complete boundary evidence. The packet is a review aid; it cannot
change a verdict.

---

## 4. Twelve-task repeated utility evaluation — the contract

**12 tasks × 2 configurations × 1 agent (Claude Code) × 3 trials = 72 legs**,
both model channels pinned to `claude-haiku-4-5-20251001`, on the agent's
own login. The wrapped side runs the launcher's shipping defaults
(`--wrapped-mode secrets` by default). Codex, protection ablations, malicious
fixtures and external-service benchmarks are out of scope.

### 4.1 Comparison rules

Identical task snapshots, model settings, native tool permissions, interaction
scripts and limits within a pair; homes, credentials, sessions, workspaces,
caches and arbiter state isolated between legs; first configuration alternated
by `(taskIndex + trialIndex) % 2`. Three trials of one task are not three
independent tasks: results are clustered by task.

### 4.2 Fixtures and acceptance

All fixtures are small project-owned examples, with no downloads or external
services. Their exact bytes, reference solutions, factual rubrics and scripted
user actions live in the runner's `utility-tasks.ts` (§5); the suite
digest covers the whole task objects and the trial schedule, and the runner also
pins the protected checker's source. The review packet (fixtures, oracles,
baseline and reference validation, 72 rows, limits) is frozen before execution;
no outcome-informed change is allowed inside a batch.

| Family | Tasks | Oracle |
|---|---|---|
| Repository understanding | RU-01 trace an entry point; RU-02 trace a setting's precedence (nullish, not truthy) in a tiny `release-kit` project | frozen factual rubric, reviewed per fact |
| Fix and extend code | CE-01 fix a dropped first record; CE-02 add `--json` across two modules | protected behavior tests; fail on the start snapshot, pass on the reference |
| Unfamiliar documentation | UD-01 framed request encoder; UD-02 option merging — each from a pinned contract file inside the task workspace (`framing-v1.md`, `options-v2.md`) | protected behavior tests |
| Transform and persist | BP-01, BP-02 (the §3 tasks, unchanged digests) | exact JSON |
| Recovery | BP-03 (missing primary); RF-02 (malformed primary, fall back to backup) | exact JSON plus observed acquisition of the primary |
| Interactive workflow | IW-01 prompt, answer, resize 100×30 → 64×24, exit; IW-02 approve one native Write and verify persistence | delivered answer on screen, exact file, clean lifecycle |

The protected checker sits outside the candidate's writable workspace, rejects
symlink and path escapes, and bounds sizes and subprocesses. Source tasks declare
writable paths; every other seeded path must stay byte-identical.

**Source markers.** Every required source file carries a unique harmless marker
(a leading comment, or an inert field) in exactly one input file, so the
evidence check can see that each required file was acquired, by Read, Grep or
Bash, and that on the wrapped side the raw marker never reached T-LLM. A marker
is a scoped probe, not proof that the whole file was processed. RF-02's
malformed primary has no marker and uses the observed-acquisition check
instead; `utility-tasks.test.ts` pins these exceptions.

**Interactive tasks** run real Claude TUIs under matched outer PTYs; headless
`-p` cannot stand in. Only the listed user actions are scripted. Every dialog
is recorded, and decided on a settled screen (two reads a settle interval apart
agree); a Write approval must match the native pending tool call and its exact
task-local path, accepted once. An unrecognized dialog stops the leg as
incomplete. The PTY fixture modes `split-trust` and `slow-trust` in
`utility-interactive.test.ts` pin the two screen races found while building it
(a half-painted trust dialog, and a trust screen still shown before its
repaint). Terminal oracles measure semantic outcome and rendering, not wording.

### 4.3 Limits

| Limit | Bound |
|---|---|
| Planned legs | 72; three first attempts per task and configuration |
| Provider requests | 1,440, shared by the T-LLM and inspection channels |
| Output tokens per completion | 4,096 |
| Headless / interactive leg | 300 s / 360 s |
| Whole batch | 8 hours |
| Automatic retries or restarts | none |
| Concurrent model legs | one |

The request cap is twelve times an observed six-leg development batch (83
requests) with headroom for coding and interaction; these are ceilings, not
targets. Actual charges are unknown and never reported as zero.

### 4.4 Reporting and completion

Report absolute completion by configuration and family, every task/trial paired
outcome, first-attempt failures, wrong answers, incomplete and not-run counts,
inspection calls, approvals, usage coverage, and latency for successful pairs.
Every failed or incomplete leg and a reproducible sample of passes is
investigated. The evaluation is complete only when all 72 legs have terminal
accounting under the frozen bounds and the review evidence is retained; a
budget stop is an incomplete batch. Product fixes suggested by a batch
are separate iterations; first-attempt outcomes are never rewritten.

---

## 5. The repeated utility runner — `eval:utility`

The runner (`eval/run-utility.ts`, `eval/lib/utility-runner/`) is the
maintainers' evidence tooling, like the agent drills: it stays in the source
repository and is not published. This section is its contract; §6 has its
results. To get access to it, for research for example, write to
hello@mandusecurity.com.

Modes `prepare`
(default, no model calls; writes the 72 pending rows and the baseline/reference
proofs) and `subscription`.

- **Identity.** Every planned row has a unique `taskId/trial-NN/side` identity
  before execution, used by paths, observer usage, outcome pairs and review
  queues. Repeated pairs are never looked up by task and side alone.
- **Launch.** `utility-config.ts` reuses the paired launch specification. Code
  and documentation tasks add native Bash for local tests, still subject to the
  normal AgentShell / HumanShell policy (a blocked test run is recorded
  friction, not a reason to relax policy). Interactive tasks use native default
  permissions; Write is not pre-allowed.
- **Stop gates.** Provider refusal, unknown usage, an exhausted limit, missing
  protection posture or essential capture, and a raw boundary-marker violation
  stop scheduling. A fully observed task mistake (no reread, failed test, wrong
  artifact) is a task failure and does not stop the batch.
- **Protected checks.** Only task inputs are staged. The checker copies the
  declared source modules into a read-only snapshot and runs a fixed driver in a
  sandbox built from the repository's own primitives: the seccomp deny-filter
  builder and Landlock applier, bubblewrap for unprivileged namespaces,
  capability dropping and a new session, plus a 96 MiB Node heap, 3 CPU s, 5 wall
  s and 256 KiB capture. A missing prerequisite is `incomplete`; there is no
  host-Node fallback. Candidate local tests never decide acceptance.
- **Review.** Facts need per-fact, evidence-linked review against exact task and
  answer digests (supported / contradicted / missing / ambiguous); keyword
  matches are not acceptance. Interactive tasks need a walkthrough of the
  recorded frames. Unreviewed is `needs-review`, never pass.
- **Interactive completion** needs the exact submitted prompt, a native
  transcript `end_turn`, no pending tool calls and a settled composer; a prompt
  echo cannot satisfy it. The disposable CLI config gets only display and
  onboarding preferences; the helper never reads or copies credentials.
- **No resume.** A new output directory is a new batch, not a continuation; the
  runner never restarts itself, and a fresh directory never resets the cap.

Unit tests cover contracts and digests, trial identities, denominators,
profiles, limits and evidence classification; e2e tests run the real protected
sandbox and local PTYs. They validate the harness, not model utility.

---

## 6. Results so far

**Repeated utility, `secrets` mode (2026-09-25) — partial.** Haiku 4.5 on both
channels, the agent's own login, wrapped side in `secrets` mode.

- 61 of 72 legs ran. The batch stopped, as designed, on an incomplete
  **unwrapped** leg (IW-01 trial 1: the interactive terminal lane did not
  start), so the two interactive tasks have no paired result and 11 legs did
  not run.
- The ten non-interactive tasks: **30 of 30 paired outcomes identical** between
  the bare agent and Mandu (21 pass, 8 needs-review, 1 fail on each side; the
  fail, RU-02 trial 1, is the same task-behavior miss on both sides).
- Cost: median leg time **20.1 s bare vs 27.4 s wrapped** (mean 21.7 vs 27.8),
  6.0 vs 6.5 model requests per leg, no approval prompts (headless), no
  quarantined-helper calls.
- Not established: silent wrong answers. The 16 `needs-review` legs (RU-01,
  RU-02, RF-02) await the per-fact review; the automatic checks cannot call an
  explanation wrong.

Three earlier attempts at that batch stopped on harness defects (the integrity
marker boundary applied in a mode without integrity, an over-long socket path,
and the mode's own fs-sync opt-out counted as a dropped protection), each fixed
before the run above. An earlier repeated batch in `injection` mode stopped
after 18 legs and is superseded.

**Benign paired (three tasks), subscription.** The first run exposed a wrapped
BP-02 failure: the merge inspection received only one of its two inputs. The
fix was product-side, [multi-input inspection](../integrity/symbol-quality.md) (§7),
with the task, inputs and checks unchanged; after it, a six-leg batch passed all
legs and all boundary checks. This is one development run, not a utility
estimate.

**AgentDojo.** Invariant smoke and trust-gap audit pass (§2.7); real-model
numbers not run.
