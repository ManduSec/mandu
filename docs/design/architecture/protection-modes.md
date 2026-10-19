# Protection modes: one knob over the two axes

Status: **BUILT 2026-09-21.** §1 is the decision, §3 and §4 the design and its
tests, §8 what was built and decided on the way, with the measured results.
**Since 2026-09-28 the integrity modes `injection` and `full` are FROZEN** (§9):
the product offers `secrets` and `off`; the two integrity modes still exist
but every entry point refuses them without `MANDU_EXPERIMENTAL_INTEGRITY=1`.
§10 is the freeze itself: what is frozen, the opt-in gate, the test lanes,
and how to revive or delete the axis. Companion docs:
[`secret-discovery.md §1`](../confidentiality/secret-discovery.md)
and
[`rootless-confinement-ubuntu-2404.md`](../confidentiality/rootless-confinement-ubuntu-2404.md)
(the reduced posture the default flip depended on).

## 1. The decision

Mandu ships to end users with **confidentiality as the lead feature**. The
product exposes four named modes over the two arbiter axes
(`arbiter/policy/confidentiality-flag.ts`, `arbiter/policy/integrity-flag.ts`):

| Mode (user-facing) | confidentiality | integrity | Role |
| --- | --- | --- | --- |
| `secrets` | ON | OFF | **the default** |
| `injection` | OFF | ON | the paper's defense alone (frozen, §9) |
| `full` | ON | ON | both (frozen, §9) |
| `off` | OFF | OFF | explicitly supported: Mandu observes, enforces nothing |

The words "confidentiality" and "integrity" stay in design docs and expert
surfaces. End-user copy uses the mode names and plain sentences ("your keys
and credentials cannot leave", "untrusted text cannot steer the agent").

**What this reversed.** Integrity used to be opt-OUT (default ON) and
confidentiality opt-IN (default OFF); `confidentiality.md` §11 had kept the
default-ON flip back behind three gates, which the companion rootless plan
answers. The security invariant is unchanged: it constrains what happens when
the integrity axis is ON, and secret symbols follow the same symbol-only rule
when the confidentiality axis is ON ([`CONTRIBUTING.md`](../../../CONTRIBUTING.md)).

**The claim narrows, and the copy must say so.** `secrets` mode stops
registered secrets from reaching the network, exec and the models their
level excludes (every model for `no-model`; every outside model for
`local-model`, which only a model declared `local: true` in `policy.yaml`
`models:` may read). It does not stop an injected instruction from exfiltrating
unlabeled data such as source code, and it does NOT mask untrusted text. Only
`injection` and `full` address that.

## 3. Work items

The axes were already tri-state at the launcher (`--[no-]confidentiality`,
`--[no-]integrity`, `MANDU_CONFIDENTIALITY`, `MANDU_INTEGRITY`; unset means
the arbiter's own default), boot-time per arbiter, and integrity OFF already
forced `fs-sync` OFF (reported as an informational note, fs-sync.md §1
P5). Both axes OFF already yielded an empty handling prompt
(`confidentiality.md` §11). The modes give these one named surface.

### 3.1 One source of truth for the defaults

The default pair lives in one table (§8.2) that every package mirrors, with a
parity test that fails if they drift: the arbiter's flag modules, the
dashboard's `config-axes.ts` and supervisor axis plumbing, and the launcher's
help text. Every test env that relied on the implicit default states its axes
explicitly (§4.1); this was done BEFORE the flip, as its own step, so the flip
could not silently turn an invariant suite into a no-op.

### 3.2 The launcher knob

- `--mode <secrets|injection|full|off>`, env `MANDU_MODE`, config key
  `mode`. Precedence stays flag > env > config > default.
- The two boolean flags remain as expert overrides. Rule: an explicit axis
  flag beats `--mode` for that axis only, and the launch banner prints the
  effective pair. A `mode` key and axis keys both present in config.toml is
  resolved the same way, never an error.
- `mandu mode [name]`: with no argument prints running and saved mode; with
  a name writes config.toml through the same surgical editor the dashboard
  uses.
- One launch line on stderr, for example
  `mandu: mode secrets (14 credential files masked)`; with flow taint the
  env-var and pinned-reader counts follow when non-zero:
  `mandu: mode secrets (14 credential files masked, 3 env vars masked,
  2 readers pinned)`. Since 2026-10-18 that is the `--verbose` form: by
  default the mode opens the launch's one banner line, with the same
  facts in short form (`mandu: secrets mode · 14 credential files, 3 env
  vars masked · dashboard … · 2 notices: \`mandu log\``; packaging.md §5
  "Launch display policy"), and the mode line is kept in the launch's log.
- `--help` lists the modes.

### 3.3 Dashboard

- The level picker shows the modes as first-class choices, `secrets` first
  and marked as the default. Every combination has a name, so there is no
  "Custom" state.
- **Alarm calibration.** "Not protected" fires only in `off` mode. In
  `secrets` mode the untrusted-content row reads `not covered` calmly, the
  same way the secrets rows read under integrity-only. The typed-`OFF`
  downgrade gate applies to any change that turns an axis off.
- The Simple-register hero and protection chip (dashboard.md §4.16, §4.18)
  use the same wording.
- SIEM rules 100224/100225 key on `config_change` axis flips; an
  integrity-OFF default install must not raise them at first boot (§8.4).

### 3.4 Per-launch arbiter, or per-session mode

A user may try `mandu --mode full claude` while another session runs in
`secrets` on the same arbiter. Axes are per arbiter, so the launch is
**refused**, naming the running mode and the way out (decision and reasons:
§8.3). Starting a second arbiter for the launch, and per-session axes inside
one arbiter, were weighed and not taken.

### 3.5 What `secrets` mode needs to be a good default

The conf-only deployment had far less live time than `full`, so three things
were verified before and after the flip (results: §8.5):

- A `secrets`-mode drill battery of everyday chores (deploy scripts, `.env`
  use, cloud CLIs, `git push` with credentials, package publishing), measuring
  task success, approvals per task and refused launches
  (the drill catalog's `util` area).
- With integrity OFF, `fs-sync` is off: label-driven features that lean on the
  AgentView twin (path-pattern labels in `policy.yaml`, derived file labels,
  the `[mandu:twin]` note) must behave sensibly or be cleanly absent.
- The handling prompt in conf-only form
  ([`handling-prompt.md`](../agents/handling-prompt.md)).

## 4. Tests (required by repo convention)

- Unit: mode → axis resolution table including overrides; config.toml editor
  round-trip with `mode`; dashboard `levelOf` for all four combos; the
  defaults parity test (arbiter, launcher, dashboard agree).
- E2E: a launch with no flags and an empty `MANDU_HOME` (no `config.toml`) runs `secrets`
  (secret symbolized, untrusted `tool_result` NOT symbolized); `--mode
  injection` and `--mode full` keep the existing invariant oracle green
  ("no un-symbolized untrusted data reaches the model"); `--mode off` emits
  an empty handling prompt and the dashboard shows the off alarm.
- The invariant e2e suites pin `full` or `injection` explicitly so the
  default flip cannot silently turn them into no-ops. **A suite that passes
  because its axis went quiet is the main regression risk of this change.**

### 4.1 The strict guard

"Make every suite state its axes" is enforced, not just done once.
`arbiter/policy/axes-strict.ts`: with `MANDU_AXES_STRICT=1`, an arbiter (or
policy) that has to fall back to the built-in default for an axis THROWS
instead. Every TS package's `npm test` script, the suite runner behind
`scripts/test-all.sh` and CI (`scripts/run-suites.mjs`, for every entry of
`tests/suites.mjs`) and the launcher's shell live tests export the variable,
and a daemon a test spawns inherits it. A suite states its axes in one of three ways:

- in-process: `stateAxes("secrets")` (or another mode) from the package's
  `test/axes.ts` (`tests/lib/axes.ts` in `tests/`) — one line after the
  imports; pins the env the in-process server and every spawned daemon read —
  or explicit `integrity` / `confidentiality` options on the `ArbiterServer`;
- a spawn site that builds its own env: `MANDU_INTEGRITY` /
  `MANDU_CONFIDENTIALITY` in that env (eval's `live-stack.ts`, the shell
  tests);
- the dashboard supervisor's shared TEST-tenant arbiter, which the ungrouped
  live suites ride: pinned in `supervisor-defs.ts` unless `MANDU_TEST_*`
  names another fold.

Making the guard strict found the conformance corpus, the eval live stack,
several integration live harnesses and that test-tenant arbiter all leaning on
the implicit default, and eval's launcher run reading the developer's real
`config.toml` (now pinned to `/dev/null` like every other e2e env).

## 8. As built (2026-09-21)

### 8.1 What landed

1. **Every suite states its axes** (§4.1).
2. **The knob.** Launcher + arbiter: `--mode`, `MANDU_MODE`, config key
   `mode`, `mandu mode [name]`, the mode line on every launch, `--help`.
   Dashboard: the named levels, the recalibrated alarm, the `mode` key in the
   surgical editor.
3. **Rootless posture:** the reduced posture of
   `rootless-confinement-ubuntu-2404.md`, a hard dependency: a default-ON
   confidentiality axis that refuses to launch on stock Ubuntu 24.04 is not
   shippable.
4. **The flip:** `DEFAULT_MODE = "secrets"` in three mirrored constants, with
   the doc sweep.

### 8.2 Where the truth lives

- `arbiter/policy/protection-mode.ts` holds the mode table and THE default.
  Both flag modules read it, so the default cannot half-move. The arbiter also
  reads `MANDU_MODE` itself (`MANDU_MODE=secrets scripts/dev-arbiter.sh`
  works with no launcher in between). An unknown mode name throws at arbiter
  start. An unrecognized AXIS value fails toward protection (ON) on both
  axes.
- `launcher/src/mode.ts` and `dashboard/src/config-axes.ts` mirror the table
  and the default (the packages ship standalone).
  `tests/stack/axis-defaults-parity.test.ts` fails on any drift: the
  default, the table, the per-package `test/axes.ts` helpers, the launcher's
  `--help` and `init` template, and byte-identical output of the two
  config.toml editors.
- Resolution is PER AXIS across flag > env > config. Inside one level an
  explicit axis beats that level's mode for that axis only. One consequence
  needed a rule of its own: an exported `MANDU_MODE` speaks for both axes, so
  `applyConfigDefaults` does not fold the file's axis keys in beside it.
- Writers keep config.toml self-consistent: writing a mode re-aligns any
  EXISTING axis line (never appends one), and a single-axis write (the
  dashboard's expert panel) renames an existing `mode` line to the resulting
  pair. Hand edits that contradict are resolved by the axis-beats-mode rule.
- The launcher acts on the EFFECTIVE pair (what the attached arbiter reports,
  else the request, else the default): integrity OFF means no fs-sync twin,
  confidentiality ON means secret confinement, even for a flagless launch that
  joins a running arbiter.
- The session records that pair: `launch_posture.protection` =
  `{mode, integrity, confidentiality, reported}`, with `reported` true only
  when the arbiter answered both axes itself. The `/dev/` trace names the mode
  from it (dashboard.md §4.2f) instead of inferring integrity from classify
  reasons, which could not tell `off` from `secrets`.

### 8.3 Decisions

- **Mode names:** `secrets`, `injection`, `full`, `off`. The dashboard shows
  them capitalized.
- **§3.4, modes differ from the running arbiter: REFUSE, no second arbiter.**
  The refusal names the running mode and the way out (`mandu mode <name>`,
  `mandu stop`, relaunch; or a dev arbiter for side-by-side). A second
  arbiter per launch was rejected on two concrete grounds. The dashboard and
  its approval inbox attach to ONE arbiter, so a `full` session on a private
  arbiter would raise egress approvals that nobody can answer from the UI. And
  two symbol DBs alternating over one workspace re-seed each other's AgentView
  twins (fs-sync's dangling-twin guard treats the other arbiter's tokens as
  unresolvable). Revisit when the dashboard can multiplex arbiters, or take
  per-session axes as their own design. Refusal is the conservative choice.
- **Typed confirmation for `off` in the CLI: no.** The command line is the
  typed intent. `mandu mode <name>` prints what stops being covered for
  every axis it turns off. The dashboard keeps its typed-OFF gate, which
  fires on every change that turns an axis off (full to secrets included).
- **Mode vocabulary in refusals.** The confinement refusal, the gated notice,
  `mandu doctor` and every secret-setup refusal in
  `launcher/src/secret-setup.ts` name `--mode off` as the way out and "modes
  secrets and full" for what protects secrets. `--[no-]confidentiality` stays
  accepted as an expert per-axis override (`--help` lists it as such) but no
  refusal or notice recommends it; a unit test in
  `launcher/test/unit/secret-setup.test.ts` drives every refusal site and
  fails if one names the axis flag.

### 8.4 Tests

- Unit: `launcher/test/unit/{mode,config-edit,mode-command}.test.ts`, the
  `--mode` cases in `parse.test.ts` and `config.test.ts`,
  `arbiter/test/unit/{protection-mode,axes-strict}.test.ts`,
  `dashboard/test/unit/config-axes-mode.test.ts` and the level/alarm suites.
- E2E: `launcher/test/component/mode.test.ts` (effective mode line, the refusal at
  flag and env level, `--help`); `tests/stack/protection-modes.test.ts`
  (per mode, a real arbiter + the real proxy, asserting what the model
  receives; `full` and `injection` pin the symbol-only invariant BY NAME; the
  built-in default must behave exactly like its named mode);
  `dashboard/test/component/config-audit-loop.test.ts` (mode writes over the real
  socket, one `config_change` per flipped axis).
- SIEM (§3.3): no axis `config_change` can be emitted without a human POST
  (`dashboard/src/server/config-axes-routes.ts` is the only emitter), so an
  integrity-OFF default install raises neither 100224 on an axis nor 100225 at
  first boot.

### 8.5 §3.5, what `secrets` mode needs to be a good default: status

- **The battery.** Six scenarios, S1 to S6 (`watch-scenarios.ts`),
  at a secrets posture; the hard claim is that no secret canary reaches the
  model in any encoding. The first live run held the canary in 6 of 6
  sessions with 0 approval prompts and 0 refused launches, but completed only
  3 of 6 tasks, which surfaced the two findings below.
- **Finding 1, the utility cost of whole-file twins.** In `secrets` mode a
  confined credential file was, inside the agent's world, a ONE-LINE symbol
  twin. Anything the agent ran that PARSES the file got the token, not the
  structure: `. ./.env` failed with `:nomodel_Read[9bbd]: command not
  found`, a script that lists the variable NAMES found none, and the profile
  names in `cloud/credentials` were not readable. The sharpest case: a
  `deploy.sh` ran with an EMPTY `API_KEY` and sent `key=` to a third party —
  no secret left, but a deploy that silently runs without its credential is a
  wrong result the user may not notice.
- **Finding 2, git sees confined files as modified.** `git status` inside
  the agent's world lists tracked secret files (` M .env`) because the
  bind-mounted twin differs from the index; a `git commit -a` by the agent
  would commit the PLACEHOLDER over the real file.
- **Twin-dependent features with fs-sync off.** Path-pattern labels and
  derived file labels apply at MINT in the arbiter and do not depend on the
  AgentView twin; the conf-only live group runs them at integrity OFF. The
  `[mandu:twin]` shell note is computed from the AgentView view map, so with
  no worktree it is cleanly absent — and therefore does not cover the SECRET
  twins either: a `grep KEY .env` that comes back empty gets no hint.
- **Handling prompt, conf-only form:** exercised by
  `protection-modes.test.ts` (a real prompt is injected in `secrets`; in `off`
  it is empty). Residue: in `off` mode both proxies still append their
  idempotency marker line (`[mandu:handling-prompt]`) to the system prompt.
  Harmless, but not strictly "observe only".

### 8.6 Still owed

- **Findings 1 and 2 share a root cause and are answered by flow taint.**
  Confidentiality enforced by replacing the DATA for the whole process tree
  breaks every legitimate consumer of the raw bytes. A per-format /
  per-command patch set was rejected as too ad hoc in favour of a FLOW-based
  design (a process may read the real secret, and what it emits afterwards is
  confined):
  [`confidentiality-plan-10-flow-taint.md`](../confidentiality/confidentiality-plan-10-flow-taint.md)
  (per-file reader list + per-app output rule; a structured twin — names raw,
  values as per-field symbols — as the zero-config baseline for files with no
  reader list; non-readers denied once a reader list exists; the strictest
  rule in a tool call's tree governs its output; a verbatim-value scan
  backstops every declassified output). Finding 1 is closed by the structured
  twins. Finding 2 is answered by the readers only for a file with a
  reader list, and only with the guard (a non-reader such as git is then
  denied, so `git commit -a` fails loudly); it stayed OPEN for the default
  file with no list, and in the mount layer for every file: git there reads
  the twin and a `git commit -a`, `git add -A` or `git stash` after any
  change records the placeholder in the user's repository (re-verified
  2026-10-09). Since 2026-10-10 the launcher says so after the session,
  with the repair, and a crashed session's commit at the next launch
  (confidentiality.md §7.2a "A placeholder in your repository"). It is
  detected, not prevented: a commit pushed in the same session is out.
- **Results after flow taint.** On the flow-taint build the battery passed 6
  of 6, with 6 of 6 canaries held, 0 approvals and 0 refused launches. A
  repeat across models (S1 to S6 × two Claude models × 3 repetitions, 36
  sessions) kept every secret canary from the model in 36 of 36 sessions and
  completed the task in 36 of 36 once a drill-runner dialog defect was fixed
  (one cell first timed out with the secret untouched).
- **The drill catalog runs in `secrets`.** The watch scenarios run at the
  secrets postures `S` and `S-mock` beside the battery's `S1`; the full-mode
  postures are the frozen lane (test-organization.md §7.2).
- **Utility on real work.** A twelve-task suite, bare vs `secrets` mode:
  every paired leg of the ten non-interactive tasks had identical outcomes;
  the price is time (median 20.1 s to 27.4 s per leg) and about 8% more model
  requests ([`evaluation.md §4`](../testing/evaluation.md)).
- **Open:** the `off`-mode handling-prompt marker (§8.5), a two-proxy change.

## 9. The integrity modes are frozen (2026-09-28)

Development continues on confidentiality only (§10). The table of §1 keeps its
four rows, and every reader of it (the arbiter, the launcher, the dashboard,
the test helpers) still knows all four names, so a running arbiter that reports
`injection` or `full` is described truthfully. What changed is who may ASK for
them: the product modes are `secrets` (still the default) and `off`
(`PRODUCT_MODES` in `launcher/src/mode.ts` and `dashboard/src/config-axes.ts`),
and a request that turns the integrity axis on is refused unless
`MANDU_EXPERIMENTAL_INTEGRITY=1` is set, at the arbiter daemon, the launch,
`mandu mode`, and `POST /api/config/axes`. A refusal, never a quiet fall back to
`secrets`. The per-package `axesEnv()` / `stateAxes()` helpers set the opt-in
for `injection` and `full`, so a suite that pins a frozen mode keeps running.
The parity test pins the opt-in's name, its accepted values and
`PRODUCT_MODES` across the three packages.

## 10. The integrity freeze: the axis stays in the tree, development stops

Status: **decision, BUILT 2026-09-28.** Mandu develops the confidentiality
axis (mode `secrets`) only. The integrity axis (the paper's prompt-injection
defense, modes `injection` and `full`) is **frozen**: kept, compiling and
smoke-tested, but no longer developed, offered or run by default. The axis
that carries on: [`confidentiality.md`](../confidentiality/confidentiality.md).

### 10.1 The decision and the alternatives

The product has led with confidentiality since the default flip (§1). Keeping
both axes at full speed makes every confidentiality change pay integrity's
cost in tests, docs and review. Three ways to stop were considered:

| Option | Why not |
| --- | --- |
| Delete integrity, keep a git tag | The shared core (symbol table, proxies, policy engine) keeps moving under confidentiality work. A revival would be a port onto a codebase that no longer fits, not a revert. |
| Move it to a long-lived branch | Rots faster than code in the tree, and every merge back is painful. |
| Leave it as it is | Nothing stops; confidentiality keeps paying for integrity. |

**Chosen: freeze in place.** The code stays where it is, a small set of
canary tests keeps it honest in the default suite, everything else moves to an
opt-in lane, the product stops offering it, and an entry point runs it only
behind an explicit opt-in. The tag `integrity-frozen-2026-09-28` marks the
last commit before the freeze.

### 10.2 What is frozen and what is shared

Much of what looks like integrity code is what `secrets` mode runs on. The
shared part stays **fully maintained**; only the integrity-only part freezes.

| Shared (maintained) | Integrity-only (frozen) |
| --- | --- |
| Symbol table, `$MDU:` symbolization, resolve / desymbolize | Inbound data-trust classification (`arbiter/policy/claude-code-inbound.ts` trust verdicts, the per-agent inbound specs, `policy.yaml` `inbound:` origins) |
| `anthropic-proxy`, `openai-proxy` wire parsing and gates | fs-sync / AgentView view sync (already forced OFF when integrity is off, `fs-sync.md §1` P5) |
| The egress gate core (`desymbolizationDecision`, approvals, Inbox) | AgentShell / HumanShell exec routing driven by untrusted symbols (`exec-routing.md`), exec-output trust and the clean box (`exec-routing.md §8`) |
| `reply-filter` | The untrusted-data sections of the handling prompt (`handling-prompt.md`) |
| The exec box, net-guard, Landlock, the guard | Untrusted-egress approval rules (release / trusted-source rules) |
| `inspect-mcp` core (confidentiality's quarantined read runs on it) | U-LLM inspection of *untrusted* data, `content_kind` triage (`symbol-quality.md`) |
| The event model, dashboard, policy surface | The `injection` / `full` modes and their live suites; the AgentDojo eval |

The integrity-only design docs live in `docs/design/integrity/` and are marked
FROZEN in the index ([`README.md`](../README.md)); they stay readable and
linkable.

### 10.3 Rules while frozen

1. **No new integrity work.** No features, no new tests beyond the canaries,
   no doc growth ([`CONTRIBUTING.md`](../../../CONTRIBUTING.md)).
2. **Shared code is designed for confidentiality.** A shared change may break
   an integrity-only path. If the fix is cheap, fix it. Otherwise move the
   failing test to the frozen lane (§10.5) and record it in §10.7.
3. **A broken canary is never skipped.** The canaries are the frozen
   feature's smoke test. If one fails and the fix is not cheap, record it in
   §10.7 **and** make the entry points refuse integrity outright (drop the
   opt-in path) until it is green again: a frozen mode that silently rots is
   worse than no mode, because someone can turn it on and trust it.
4. **Fail closed stays.** Nothing about the freeze relaxes a gate: a request
   for integrity without the opt-in is refused, never downgraded to `secrets`
   in silence (the user must learn they did not get what they asked for).

### 10.4 The opt-in gate (`MANDU_EXPERIMENTAL_INTEGRITY`)

Only an explicit `1` / `true` / `on` / `yes` opts in; a typo stays refused.
The name and semantics are mirrored in three places and pinned by
`tests/stack/axis-defaults-parity.test.ts`:
`arbiter/policy/integrity-flag.ts`, `launcher/src/mode.ts`,
`dashboard/src/config-axes.ts`.

| Surface | Without the opt-in |
| --- | --- |
| Arbiter daemon (`arbiter/ipc/server-main.ts`) | Refuses to start with integrity ON, before registering an instance: no instance dir, no `current` rendezvous, no socket, no symbol DB (`tests/stack/protection-modes.test.ts`, the real daemon; the gate's pure half in `arbiter/test/unit/integrity-flag.test.ts`). |
| Launch (`launcher/src/parse.ts`) | `--mode injection|full`, `--integrity`, `MANDU_MODE`, `MANDU_INTEGRITY` or `config.toml` asking for integrity: refused with a message naming the opt-in and this doc. |
| `mandu mode` | `mandu mode injection|full` exits 2 and leaves `config.toml` untouched; the listing shows `secrets` and `off` plus one "frozen" line, and warns when the saved mode is frozen. `--help` lists the same. |
| Dashboard API (`POST /api/config/axes`) | 403 `{frozen: true}` for any write whose RESULTING setting has integrity on: a frozen mode, `integrity: true`, or a confidentiality change while a legacy config still has integrity on (turn masking off first, so the file is never left in a state the next arbiter start refuses). Mode `secrets` / `off` and `integrity: false` always pass. `GET` carries `integrityAllowed`. |
| Product page `/` | The "Mask untrusted content" switch is hidden, unless it is still on (then it shows, so it can be turned off). |
| Developer view `/dev/rules`, the Protection block (dashboard.md §4.32) | `injection` / `full` cards hidden, except the saved one, shown disabled with a "frozen" tag; the Machinery integrity switch can go off, never on. |

**Not gated, on purpose.** `resolveIntegrityEnabled()` and an in-process
`ArbiterServer` resolve the axis exactly as before, so the frozen code and its
tests run unchanged. A launch may join an arbiter that was started with the
opt-in. The dashboard's shared **test-tenant** arbiter runs integrity ON for
the frozen live suites and opts in by name
(`dashboard/src/supervisor/supervisor-defs.ts`); the operator's live arbiter
never does. The per-package test helper `axesEnv()` / `stateAxes()` sets the
opt-in for `injection` / `full` and clears it for `secrets` / `off`.

### 10.5 Test lanes

- **Default lane** (`npm test`, `scripts/test-all.sh`): every shared and
  confidentiality test, plus the **canaries**:
  `arbiter/test/component/invariant-oracle.test.ts`,
  `arbiter/test/unit/claude-code-policy.test.ts`,
  `arbiter/test/unit/egress-gate.test.ts`,
  `tests/conformance/lib/unit_symbolization.ts`,
  `launcher/test/component/golden-path.test.ts`,
  `tests/stack/full-stack.test.ts`,
  `tests/stack/proxy-replay.test.ts`.
- **Frozen lane** (`npm run test:integrity` in each package that has one;
  `scripts/test-all.sh --integrity` runs them all; each such entry of the
  suite manifest carries `frozen: true` beside its kind, and `run-suites.mjs
  --frozen` selects them): the files whose subject is integrity-only
  behavior, in `test/integrity/` of their package (same depth as `test/unit`
  and `test/component`; in the `tests/` package, `tests/integrity/`,
  test-reorganization.md §5.3), plus the conformance corpus
  (`tests/conformance`: `run.ts`, `lib/unit_egress_gate.ts`), and the
  `fresh-agents` VM suite's `full` legs (`FRESH_AGENTS_INTEGRITY=1`,
  os-test-matrix.md §10.14). It runs **only
  when the axis is revived** (§10.6), not before releases and not on a
  schedule: a pre-release run spends maintenance on code nobody develops.
  Between revivals its state is unknown; the canaries are the only automatic
  signal.
- **Mixed files stay in the default lane** for now (their integrity half keeps
  running): `arbiter/test/component/{retired-symbol-prefix,rung3-completes,tool-surface}.test.ts`,
  `arbiter/test/unit/{egress-approvals,user-rules-gate}.test.ts`,
  `dashboard/test/unit/view-model/paired-rows.test.ts`,
  `tests/stack/{agent-gate-surface,agent-version-drift,openai-wire-routing,openclaw-dispatch}.test.ts`.
  They are split when a confidentiality change touches them.
- **Live lanes** (the maintainers' `drills:live:*`; the drills are not
  published) are opt-in already; the
  integrity ones (`drills:live:int-smoke`, `drills:live:full`, the ungrouped
  claude-e2e scenarios riding the test-tenant arbiter, the drill postures
  that launch `--mode full`) are frozen with the axis.

The agent suites, the drills, the launcher shell suites and the eval moved
their integrity forms verbatim into the frozen lane and run in `secrets` in
the default lanes ([`test-organization.md`](../testing/test-organization.md)
§7). Some default-lane suites still pin `injection` or `full` only
incidentally (for example to skip secret discovery against a silent mock
arbiter); they carry the opt-in through `axesEnv()`.

### 10.6 Reviving or deleting

- **Revive:** remove the gate (§10.4), move `test/integrity/` back, run
  `scripts/test-all.sh --integrity` and the integrity live lanes, and re-read
  §10.7 for what broke while frozen. Expect more breakage than §10.7 lists:
  the frozen lane did not run between revivals (§10.5), so §10.7 holds only
  what the canaries or a chance run found. Compare against the tag for
  anything that drifted.
- **Delete:** first gather the integrity-only modules behind one seam (one
  directory, or one flag check per chokepoint) as confidentiality work
  touches them, so deletion is one directory and not a sweep. Then delete
  `test/integrity/`, the modes and the gate together, and keep this section
  as the record.

### 10.7 Known breakage and follow-ups

Known breakage while frozen. This list is not complete: it records only what
the canaries or a chance run found.

- **Open, a sandbox escape in `full` mode.** The agent can write the shadow
  `repo.git` (a home carve-out, on-disk-layout.md §4), and fs-sync's
  unconfined `add`, `status`, `checkout`, `worktree add`, `revert` and
  `blame` still run the filter, merge and textconv DRIVERS its config names,
  which no `-c` switches off by an unknown name (write-protection.md §8.6).
  The same holds, on git 2.54 alone, for the config-based hooks its
  `commit`, `checkout` and `revert` run (2.55 and later have a switch by
  event, which the hardening forces; 2026-10-17, §8.6). fs-sync's git
  otherwise runs hardened (write-protection.md §8.3). A revival must close
  it before `full` ships again.
- **Open, a name leak in the twin note.** The Claude proxy's twin note spells
  a path the exec box hinted (`reportExecTwins`, a claim from the agent's
  tree, arbiter-human-plane.md §10.2) as the box reported it (`asTyped`,
  `twin-note.ts` `findTwinsDetailed`), so a forged hint or a shell-expanded
  file name reaches the privileged model in clear inside Mandu's note,
  against the note's own rule that no name the model did not type enters it.
  The note fires only for an untrusted result (integrity axis ON). Fix on
  revival: count hinted paths in the closing sentence instead of naming them.
- **The eval live stack** (`eval/lib/live-stack.ts`) starts its arbiter with
  integrity ON; its entries (`eval.run-live`, `eval.deterministic` — the
  AgentDojo corpus — and `eval.paired`, whose wrapped leg runs `--mode
  injection`) are in the frozen lane with the opt-in in their env.
- **The eval exfil sink is on this machine (2026-10-05).** `eval/lib/
  case-runners.ts` sends each attack's exfil to a sink on `127.0.0.2` through
  the egress proxy, which since 2026-10-05 relays nothing to this machine
  (exec-routing.md §7.5). Under `defense=full` the attack is therefore refused
  as "this machine" before the data-usage gate is the reason, so a FULL
  "blocked" no longer isolates the gate. Fix on revival: name the sink (a
  host such as `collect.evil-exfil.test`) and pass the eval stack's net-proxy
  a mock-sites host route to the sink (`MANDU_NET_PROXY_MOCK_SITES`), as the
  frozen `launcher/test/integrity/net-proxy*-live` twins now do.
- **Coverage that runs nowhere while frozen.** The differential suites run
  their wrapped side in `secrets`, so the AgentView posture (the wrapped agent
  working in the AgentView, a Write synced back) is exercised by no
  differential run; `MANDU_DIFF_MODE=injection` (`differential-driver.ts`)
  revives it. The drill scenarios that left the frozen lane lost their
  integrity checks (the poisoned file symbolized, the injection absent from
  the model, the quarantine and the twin note on untrusted files); their
  pre-move forms are in the history of `watch-scenarios.ts`. On revival,
  restore those checks under a frozen posture. The moved frozen-lane forms
  that need a login or a real model (`tests/integrity/subscription.test.ts`,
  the OpenClaw/OpenCode `inspect-extract` scenario, `agents-real`,
  `policy-setup.test.ts`, `codex-mcp.test.ts`, `codex-e2e.test.ts`) were not
  run when they moved.
- **The VM matrix's `full` legs (moved 2026-10-09).** The `fresh-agents`
  suite ran every agent a second time in `--mode full` (a poisoned
  `~/proj/notes.md`, the injection marker reaching the model only as a
  symbol) without the opt-in, so since the gate every such leg failed
  "launch exit 2". They are its step 5 and now run only with
  `FRESH_AGENTS_INTEGRITY=1` on the host, which passes
  `MANDU_EXPERIMENTAL_INTEGRITY=1` to each leg; a default run records one
  SKIP note (os-test-matrix.md §10.14, §10.14.1 item 11). Their last green
  run was before the gate (2026-09-27, Claude Code 2.1.281, Codex 0.154.0,
  OpenCode 1.18.13, OpenClaw 2026.9.6); they have not run since.
- **A frozen assertion that proves less than its name.** The frozen
  `exec-wrap-live` block does not come from the untrusted symbol but from the
  `?` in its URL (`unsupported_command: glob_unsupported`); with the symbol in
  a `--data` slot `resolveExecArgv` resolves it and curl runs, in both modes.
  It proves the command-shape refusal, not the data-usage rule; kept
  verbatim, noted in its header.

Follow-ups (not scheduled): split the mixed files of §10.5; re-pin the
remaining incidental `injection` / `full` suites inside `npm test` packages to
`secrets`; hide the product Rules page's "Trusted sources" group (integrity
rules) when no such rule exists.
