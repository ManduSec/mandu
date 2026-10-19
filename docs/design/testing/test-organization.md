# Test organization: kinds, one manifest, and the words we use

Status: decision note, ACCEPTED (2026-09-28), every build step built (§9).
One manifest, `tests/suites.mjs`, lists every suite; a runner, a CLI and a
completeness check read it; `scripts/test-all.sh`, the dashboard's test
runner, GitHub CI and the generated [`docs/testing/suites.md`](../../testing/suites.md)
all derive from it. Since 2026-10-01 the manifest sorts suites by **kind**
(what is real in a suite), not by tier (§3, §9.3). The CI pipeline that
runs the kinds is [`continuous-integration.md`](continuous-integration.md). Related:
[`protection-modes.md §10`](../architecture/protection-modes.md) (the frozen
lane), [`protection-modes.md`](../architecture/protection-modes.md) (the axes
a suite pins), [`os-test-matrix.md`](./os-test-matrix.md) (the VM matrix),
[`continuous-integration.md §12`](continuous-integration.md) (GitHub CI). How to run the suites:
[`running-tests.md`](../../testing/running-tests.md).

## 1. Why

An inventory of every suite (2026-09-28) found:

- **The list of suites was kept by hand in 16 places**: `scripts/test-all.sh`,
  15 `package.json` script blocks, the dashboard's runner, labels and
  registry, the drill catalog and a hand-written drill page, the e2e catalog,
  `tests/README.md`, the GitHub workflow, the matrix targets and three CI
  design notes.
- **They had drifted, and suites fell through**: 28 Rust tests compiled only
  under `--features kernel` and were not `#[ignore]`d, so `kernel-tests.sh
  -- --ignored` never ran them; two launcher kernel shell suites and nine
  live files were run by nothing; GitHub CI missed four suites; the drill
  catalog and the drill page disagreed on ids.
- **The words did not classify.** "live" meant a real kernel attachment, a
  real agent CLI, a real model and a human's session; "offline", "e2e",
  "smoke" and "drill" had several meanings each.
- **Hidden requirements.** Suites in the default run reached the internet,
  drove the real `claude` when one was on PATH, or self-SKIPped to green
  without a kernel-feature binary.
- **The frozen axis ran by accident.** Most fake-model agent suites and 53 of
  the 70 drills switched integrity on.

## 2. Terms

| Term | Meaning |
|---|---|
| **kind** | What is real in a suite (§3). It decides when the suite runs. Replaced **tier** (what a run needs from the host) on 2026-10-01. |
| **need** | What the host must provide (`needs`: `node`, `cargo`, `bwrap`, `userns`, `kernel`, an agent CLI, a login). The runner's host check. `kernel` is a need, never a kind. |
| **sealed** | The rule for the `unit`, `component` and `stack` kinds: the result depends only on the code under test. No network, no credential, no privilege, no program beyond node, cargo and base shell tools, no host state (the real `$HOME`, `~/.mandu`, `policy.yaml`, fixed ports, other processes). Such a suite passes on any machine, in a sandbox with no network and an empty `$HOME`, every time. |
| **drill** | A catalog scenario typed into a real agent TUI, recorded and graded (`dashboard.md` §4.22). A drill involves an agent CLI; it runs as a `live-drill` (a real model) or a `replay-drill` (a scripted one). |
| **blocking** | A red result fails the pipeline and blocks the merge or the release. Only deterministic suites block. |
| **non-blocking** | Reported, never fails the pipeline. Used for suites whose result depends on something other than the code (a real model's answer, a rate limit). Read as a trend on the dashboard; a persistent failure blocks a release through the human who checks before it. |
| **frozen lane** | Suites whose run switches the integrity axis on ([`protection-modes.md §10`](../architecture/protection-modes.md) §5), marked `frozen: true` in the manifest (any kind can carry the marker). Runs only when the integrity axis is revived: never automatically, not before releases. The canaries are the only `full` runs in between. |

**One meaning each.** **Retired as classifiers:** "live", "shipping",
"smoke", "offline", "agent-fake", "real-model" and "e2e". They stay where
they name one thing (a scenario called `interactive-smoke`, the live-drill
directory, an npm script), but no list, scope or flag uses them to
say what a suite is. The kind says that.

## 3. Kinds

Every suite has exactly one **kind**: what is real in it. This section
defines the kinds and says how the manifest and CI use them.

| Kind | What is real | When it runs |
|---|---|---|
| `unit` | one function or module | every push, **blocking** |
| `component` | one Mandu package through its real interface | every push, **blocking** |
| `stack` | several Mandu packages wired as in production; no agent | every push, **blocking** |
| `replay-drill` | a real agent CLI (`claude`, `codex`, `openclaw`, `opencode`) and real Mandu, a scripted model | every push, **blocking** |
| `sandbox` | the real sandbox (user namespaces, bwrap, Landlock, seccomp, the kernel-feature binaries), no agent | every push, **blocking** |
| `live-drill` | a real agent CLI with a real model | nightly, reported, in the lane of its credential (`credential`, §4) |
| `env` | the host decides the result: a local model server, a login, the internet, a newly released CLI | nightly, reported |
| `eval` | a Mandu feature's model output, scored against a bar | nightly or by hand, reported |
| `install` | a real install in a disposable VM (`/dev/kvm`, the network) | release tag (and by hand) |

**The drill kinds are the maintainers'.** The agent drills are the
maintainers' evidence tooling and are not published (decided 2026-10-08):
their `replay-drill` and `live-drill` entries sit in the source repository's
second manifest (§5, "Source-only rows"), so this tree's `tests/suites.mjs`
holds only the frozen integrity entries of those kinds. What the drills show
is in [`drill-results.md`](../../testing/drill-results.md). The sections
below that name drill entries describe the maintainers' runs.

**Where a per-push suite runs.** The five per-push kinds run in one pipeline.
An entry whose `needs` include **`kernel`** runs in the kernel lane of the
Linux 6.8 guest, and also nightly and on `v*` tags on a Linux 7.0 guest
(`kernel-linux-7`, continuous-integration.md §4.1): every `sandbox` entry, plus
`launcher-kernel-tier` (a `replay-drill` whose checks depend on the sandbox).
The other per-push entries run in the parallel stage. A package entry whose
`npm test` runs both its `test/unit` and its `test/component` files is one
entry of kind `component`, the kind of its most-real files.

**Native bins.** A kernel test that runs the real `mandu-net-guard` takes the
newest build that is not stale (`tests/lib/native-guard.ts`, over the
launcher's `nativeBinStaleness`) and fails, naming `scripts/build-native.sh`,
when every build is older than its sources: picking by mtime alone once ran
a release bin that predated a guard fix, a false failure that could as well
have been a false pass. `scripts/test-all.sh` therefore runs
`scripts/build-native.sh` before the runner whenever a selected entry runs
the native bins (a `replay-drill` or `sandbox` entry, or one that needs
`native-bins`: `node scripts/suites.mjs list --native-bins`), whether
`--kind` or `--only` selected it. A failed build stops the run (exit 4);
`--no-build-native` or `MANDU_TEST_BUILD_NATIVE=0` skips it. CI builds in its
own build stage. `scripts/test/test-all-native.test.sh` pins the rule.

The per-push kinds are all deterministic by construction: a red there is a
code bug. The nightly kinds run in `secrets` mode only (§4).

## 4. Flags

These flags sit beside the kind, because they cut across it:

- **`axis`**: `secrets`, `off`, `injection` or `full`, as the suite pins it
  (`stateAxes`, explicit options or env). A suite whose axis switches
  integrity on carries **`frozen: true`** whatever its kind and never runs
  automatically. The canaries named in `protection-modes.md §10` §5 are the
  exception: they stay in the per-push kinds by that note's decision.
- **`flaky: true`**: the suite never blocks. For suites that are
  deterministic in principle but fail for reasons outside the code (PTY
  timing in `differential-agents`, the `claude@latest` drift lane). The
  runner leaves them out unless `--include-flaky` is given; then a flaky
  entry runs, keeps its own red in the summary, and is left out of the run's
  result. They are not in the per-push run (today's flaky entries cannot pass
  in the CI guest); they run by hand and in the nightly, whose
  `run-suites.mjs --flaky-kinds <k,k>` adds the flaky entries of more kinds
  to a `--kind` selection. Every `flaky` entry carries a reason and a revisit
  date (§10).
- **`reported: "<reason>"`** and **`nightly: "<reason>"`**: a per-push
  kind's entry that does not block, with the reason. A `reported` entry runs
  every push and its red is left out of the run's result; a `nightly` entry
  never runs per push, and the nightly's `--flaky-kinds` takes it. Neither
  counts against the replay budget or as a per-push gate in the coverage.
  Today `nightly`: the catalog replay's whole-catalog entries
  (`integration.replay.<agent>`). No entry is `reported` since 2026-10-11,
  when the per-push subset (`integration.replay-push`, `-kernel`) began to
  block (test-reorganization.md §6.9).
- **`manual: "<reason>"`**: the suite never runs with its kind, only when
  named (`--only`, `suites.mjs run`), and a kind run reports it excluded with
  the reason. For batches that need chosen arguments and a review after, not
  a pass/fail signal: `eval.utility`, `eval.paired` (`continuous-integration.md`
  §9.7).
- **`credential: "subscription" | "api-key"`**: the nightly job that runs the
  entry, by the credential it authenticates with (`continuous-integration.md`
  §9.8). `subscription` holds only agent sign-ins (a scoped agent
  credential, and a reduced Codex sign-in when available), `api-key` only
  vendor API keys, so no guest holds a sign-in and a key. Every entry a
  nightly runs names one (the check fails one without), and its `needs` say
  which credential: `claude-login`, `chatgpt-login`, `anthropic-api-key`,
  `openai-api-key`. Today the API-key lane is the maintainers' `openclaw-headless`,
  `opencode-headless`, `codex-headless.openai-key` and
  `codex-headless.policy.openai-key`.
- **`internet: true`**: the suite reaches the public internet. It never runs
  per push (the CI sandbox has no network) and runs only when explicitly
  selected. Today: `wire-release-live`, `tls-compat`, the online retry in
  `launcher/test/component/npm-pack.test.ts`, the `claude@latest` lane.
- **`watchStore: true`** (2026-10-16): a live-drill or replay-drill entry
  that is not a `drill.*` entry but runs the live drill runner, one run per
  side (the maintainers' demo battery): `run-suites.mjs` appends `--store
  <the watch store>` to its command as it does for a drill entry
  (`recordsLive` in `scripts/suites.mjs`), so its runs land where the
  dashboard and the CI guest's results collection look
  (`continuous-integration.md` §9.9).
- **`docsLane: true`** / **`idOnly: true`**: the docs lane, what a change to
  documentation only runs instead of the per-push kinds
  (`continuous-integration.md` §5.5). `idOnly` entries are narrow re-runs of files
  their parent entry already runs, so a kind run leaves them out. The
  completeness check (§5) flags a per-push test that reads docs at run time
  and runs in no `docsLane` entry.
- **`proves`**: the properties the suite proves, from the fixed list
  `PROPERTIES` in `scripts/suites.mjs`: each a claim
  that a HARD assertion of the suite checks the property on the real path,
  in the entry's own configuration. `suites.mjs coverage` prints the
  property × kind table, and the check fails on a property no per-push suite
  above unit proves.
- **`provesNone`**: why a nightly-kind entry (live-drill, env, eval) proves
  no property, at most 300 characters (the `NO_PROVES` table in
  `tests/suites.mjs`). Every nightly-kind entry outside the frozen lane
  carries `proves` or `provesNone`, never both, so a new nightly entry is
  claimed or explained.

## 5. The manifest

**One file lists every suite: `tests/suites.mjs`.** It is a plain ES module
exporting an array, so node reads it with no dependency, comments are
allowed, and bash reaches it through a small CLI (`node scripts/suites.mjs
list --kind sandbox`). A YAML file would need a parser in every reader; JSON
allows no comments.

One entry:

```js
{
  id: "launcher.secret-readers-live",
  kind: "sandbox",
  axis: "secrets",
  cwd: "launcher",
  cmd: ["bash", "test/secret-readers-live.test.sh"],
  needs: ["kernel", "bwrap", "userns", "native-bins", "nc"],
  timeout: 300,            // seconds, enforced by the runner
  parallel: true,          // safe beside other suites (§8.4)
  gate: null,              // the env var that switches it on, when it has one
  select: null,            // a scenario subset
  flaky: null,             // or { reason: "…", since: "…", revisit: "…", revisits: 0 }
  internet: false,
  platforms: ["linux"],    // ["linux", "darwin"] for the validated macOS subset (§6.9)
  doc: "docs/design/testing/continuous-integration.md §13",
}
```

A package's whole `npm test` is one entry; a file is its own entry only when
it differs from its package's kind (its `test/kernel/` files, for example,
are a `sandbox` entry of their own). A scenario subset of a suite (a
`claude-e2e` cut, a drill setting and area) is an entry with `select`. Other
fields: `scripts` (npm aliases an entry is), `files` (extra claims),
`variantOf` (a cut of another entry's files), `canary` / `canaries`, `todo`,
`ci: { maxSkip, minPass }`, `note`, `session` (§9.2), `queueAs` (§9.1), and
`parallel: "sandbox"` (§9.1). Composite npm scripts are listed in an
`aggregates` export instead of being entries.

**The agent a live entry drives** (2026-10-15). Every `live-drill` entry
names it: `agent` is one of `claude`, `codex`, `openclaw`, `opencode`,
`opencode2` and `goose`, and its CLI is among the entry's needs; `ullm`
names another agent when that one serves as the U-LLM (the Codex policy
run's quarantined reads use the claude CLI: `agent: "codex"`, `ullm:
"claude"`). Only a frozen entry may name a list of agents. The runner asks
each named agent's CLI for its `--version` once per run and prints the
agent and the version beside the entry's result; `summary.json` carries
them as the entry's `agent`, `agentVersion` and `ullm`
(`continuous-integration.md` §6), so a result says what it ran on and a
regression can be laid against an agent's release. When any entry of a run
named its agent, the run ends with the **agent matrix**: a row per suite (a
generic suite's agent part dropped, so `drill.conf.claude` and
`drill.conf.codex` share the row `drill.conf`; an agent-only suite its own
row), a column per agent, each cell the entry's counts (`29✓`, `27✓ 1✗`,
`3∅`) or its result (`skip`, `timeout`), `—` where it did not run on that
agent. It is printed after the summary and written to the run's
`summary.md`.

**A renamed entry keeps its old id as an alias** (`aliases`, 2026-10-15):
`--only <old id>` and `node scripts/suites.mjs run <old id>` select it as
its id does, so a caller's old name keeps working; an alias is no entry's
id and no other entry's alias. The maintainers' drill entries, renamed per
agent on 2026-10-15, carry them.

**The version-drift check** (2026-10-15). `scripts/ci/agent-latest.sh
<agent> -- <command>` installs an agent's newest release into a temporary
prefix of its own (npm; Goose's GitHub release binary), puts it first on
PATH, says its version beside the pin in `scripts/ci/pins.env` (`DRIFT`
when they differ) and runs the command; the prefix goes when it ends. The
maintainers' `drill.core-latest.<agent>` entries run the core drills through
it, nightly for Claude Code and Codex and in each other agent's weekly
night, reported like every nightly kind: a red is a release Mandu does not
handle yet and gates nothing. A run that reports its agent's version on a
line of its own (`# agent-version X`, the drill runner's footer) is
recorded at that version, over the runner's probe of the CLI on PATH, so
the summary says which release the entry really ran. The developer view's
Drills › Agents page lays the pin, the last full run, the last core check
and the newest release seen side by side, per agent.

**Readers.** Everything that enumerates suites reads the manifest:

| Reader | How |
|---|---|
| `scripts/test-all.sh` | runs the manifest's entries; `--kind <k>[,<k>]`; the default is `unit,component,stack,sandbox` (§9.3) |
| the CI pipeline | the five per-push kinds per push, the nightly kinds on a schedule, the `kernel`-need entries on the Linux 7.0 guest nightly and on tags |
| GitHub CI | builds its job matrix from `list --kind unit,component,stack --platform linux --json --public` |
| the dashboard test runner | offers every entry, grouped by kind |
| the dashboard labels and registry | the session class and label come from the entry |
| docs | the generated table in `docs/testing/suites.md` |

**Running a credential lane, some agents or some drills**
(`scripts/test-all.sh`, the host form of the nightly jobs; usage in
[`running-tests.md`](../../testing/running-tests.md) §3, §4; the drill
entries these flags select exist only in the maintainers' repository):

- `--lane L` keeps the entries whose `credential` is `L`. Without `--kind`
  it is that lane's nightly selection: the kinds `live-drill,env,eval` and
  every flaky entry of the lane; `internet` entries join only with
  `--include-internet`. It holds one lane's credentials, as the CI guest
  does: `subscription` removes the API-key variables and names them;
  `api-key` removes `CLAUDE_CODE_OAUTH_TOKEN` and `MANDU_CI_CODEX_AUTH` and
  loads the secrets file when a key is unset. Outside the guest the host's
  `~/.claude` login stays visible, so one API-lane scenario whose quarantined
  read uses the claude CLI (the OpenClaw and OpenCode inspect-extract) runs on it where
  the guest skips it.
- **The lane stack.** A lane run stands up what CI's `pipeline.sh --network`
  starts beside the suites, through the same helper,
  `scripts/ci/nightly-stack.sh` (`continuous-integration.md` §9.4): a
  `secrets`-mode arbiter of the test tenant with the drill policy
  (the maintainers' `drill-policy.yaml`), spawned by `scripts/dev-arbiter.sh`
  with the run's shell as its owner (so `mandu reap` collects one a killed
  run left), exported as `MANDU_ARBITER_SOCK`, `MANDU_ADMIN_SOCK` and
  `MANDU_TENANT=test`, plus `MANDU_BIN=launcher/mandu-run.sh` and
  `MANDU_TEST_DASHBOARD=1`. Without it the `claude-e2e` cut and `codex-e2e`
  skip to green. The stack's sockets sit in a directory of their own under
  `$TMPDIR` (or `/tmp` when `$TMPDIR` is too long for `sun_path`'s 107
  bytes). test-all.sh stops the arbiter's process group when the run ends,
  on `^C`, `SIGTERM` and `SIGHUP` too; an arbiter that does not come up stops
  the run (exit 5); `--no-lane-stack` (`MANDU_TEST_LANE_STACK=0`) runs the
  lane without it. `scripts/test/test-all-lanes.test.sh` runs `test-all.sh
  --lane` and `pipeline.sh --network` against the same stubs and requires the
  suites' environment and the arbiter asked for to be equal, the sockets
  within 107 bytes, and the stack gone after a run, a `^C` and a failed
  start.
- `--agents a,b` (`claude`, `codex`, `openclaw`, `opencode`, `goose`: the
  agent registry's agents, supported-agents.md §5.7)
  keeps an entry only when every agent it drives is listed. An entry that
  names its `agent` drives that one and its `ullm` (`opencode2` counts as
  `opencode`), so `codex-headless.policy`, whose quarantined reads use the
  claude CLI, drives claude as well as codex. Any other entry's agents come
  from its needs: the agent's CLI, or its login (`claude-login` is
  claude's, `chatgpt-login` Codex's). An entry that drives none stays.
- `--drills id,id` narrows each drill entry to those catalog drills: a drill
  entry carries its drill list in `select` (`{ arg: "--ids", values }`), and
  the narrowed entry runs `drill-run.ts --ids <the ones asked for>`. A drill
  entry left with none is excluded with that reason; an id no drill entry
  runs is a usage error listing the known ones. Alone it is `--kind
  live-drill`.

**The completeness check** (`scripts/test/suites-manifest.test.mjs`, a
per-push entry) fails when:

- a test file (`**/*.test.{ts,sh,mjs}`, the `tests/` kind directories,
  `tests/conformance/lib/*.ts`, `scripts/test/*`, a matrix suite) or a
  `test*` npm script is claimed by no entry, or by two;
- an entry names a path or script that does not exist;
- an entry has no `kind`, or one outside the nine of §3;
- an entry has no `axis`, or its `axis` switches integrity on while it runs
  automatically (not `frozen: true`; the canaries excepted, by name);
- a sealed entry (`unit`, `component`, `stack`) declares a need outside
  node, cargo and base shell tools;
- a `sandbox` entry does not need `kernel`;
- an entry a nightly runs names no `credential`, or the credential does not
  match its needs;
- a `live-drill` entry names no `agent`, or names an agent (or a `ullm`)
  whose CLI is not among its needs;
- an entry's `select` does not hold exactly the scenario list it runs, or a
  drill entry has no `select`;
- the private manifest, where the tree has one, reports a problem of its own
  (its `problems(root)`, printed as `drill: …`). In the maintainers'
  repository that is the drill catalog's half of the check: the catalog's
  generated index (`drills.json`) is missing or malformed: ids unique and of
  the form `<area>-<slug>`, each drill on a known setting and frozen exactly
  when its setting is, the generated drill page present (that both are fresh
  against the TypeScript catalog is `drill-catalog.test.ts`'s check), and
  every drill's replay script fresh. The public tree has no private manifest
  and no catalog, and its check has no such half (moved out of
  `scripts/suites.mjs` on 2026-10-09);
- a test file a per-push entry runs reads the repository's docs at run time
  and no `docsLane` entry runs it (`continuous-integration.md` §5.5). The sweep
  (`docsLaneSweep` in `scripts/suites.mjs`) is a heuristic over code with
  comments stripped: a string literal that is a whole `docs/…` path, or a
  repo-root name joined with `docs` or a `*.md` name, counted only when the
  tree has that path and, in JS/TS, only in a file that also calls a
  filesystem read. Two readers no path shows are caught by their own signal:
  a VCS file listing or grep in a file that names a repo root, and a test
  that names an entry point a module declares in a `docs-reader:` comment. A
  file it flags wrongly carries a `docs-lane-exempt: <reason>` comment;
  `check` lists those as a note;
- a non-test module reads the repository's docs at run time (the same path
  heuristic, a `docsUrl("docs/…")` link not counted) and carries neither a
  `docs-reader:` marker nor a `docs-lane-exempt: <reason>`
  (`unmarkedDocsReaders`, 2026-10-17): the error names its file and line.
  Without the marker the sweep cannot see the tests that reach it.

This is the check that stops a suite from going missing again.

**Source-only rows.** The source repository can add entries in a second,
optional manifest file the runner loads when present. The public manifest
and its check work without it.

**The drill tree.** The maintainers' drills (the catalog, the live runner,
the replay engine and their library) live in a directory of the `tests`
package that the public tree does not have. Public code never names that
directory. Code that needs a drill file asks the drill-tree resolver where
the tree is, and names the file by its path under the tree's root
(`live/drill-policy.yaml`, `catalog/drills.json`). The resolver is
`scripts/drill-tree.mjs` (a module and a command: it prints the tree's path,
or exits 1 when there is none). The dashboard, which ships standalone, has
the same rule in the developer view's `drill-tree.ts`, and a unit test holds the two
equal. It answers, in order:

1. `MANDU_DRILL_TREE`: a directory, absolute or relative to the repository
   root. If it is set but is not a directory, the answer is none.
2. The `mandu.drillTree` member of `tests/package.json`: a directory relative
   to `tests/`. It cannot be absolute or contain `..`.
3. None.

The source repository declares its tree in `tests/package.json`. The public
export removes that member, together with the `drills:*` npm scripts that run
the tree's files. The public tree therefore answers none, and each reader
degrades:

- The nightly stack's arbiter runs with no policy file (`nightly-stack.sh`).
- The collector test skips the replay records' own validators.
- The dashboard's Drills page says drills are not available. Its catalog
  read reports it as the reason; `GET /api/drills/scenarios` and
  `POST /api/drills` answer 503 `{unavailable: true}` and start no runner
  (`dashboard.md` §4.22).
- The setup banner of an agent-suite session shows no repro line.

The export's `drill-path` rule fails an exported file that names the tree
anyway. It catches the tree's path from the repository root, a drill source
file named relative to `tests/`, and the same path built one segment at a
time with `join`. The runs store, which also has a `drills` directory, holds
records, not the tree, and the rule leaves it alone.

## 6. Membership

The first cut of the manifest (2026-09-28), by the tiers of that day. The
kinds the same suites have now are, entry by entry, in the generated
[`docs/testing/suites.md`](../../testing/suites.md); the sections below keep
the tier names because other notes cite them.

### 6.1 `offline`

Now the `unit`, `component` and `stack` kinds: typechecks and the aarch64
`cargo check`; every TS package's `npm test` minus the files moved to
`test/kernel/` (§8.1); eval's `lib` tests; the wrapper-layer shell suites
(`net-proxy-live`, `net-proxy-mitm-live`, `exec-wrap-live`,
`reply-filter-live`); `scripts/test/*` and the manifest check; `cargo test`
at default features; the matrix `smoke` suite. The deterministic eval (the
AgentDojo integrity corpus) is in the frozen lane (`protection-modes.md §10` §2,
§7).

### 6.2 `agent-fake`

Now `replay-drill`, all in `secrets` (§7.1): the replay drills
(`claude-code`, `codex`, `codex-view-map`, `launcher-golden-path`,
`launcher-gated-posture`); `differential` (seven scenarios × two sizes ×
normal/fullscreen, plus a real-config lane from a checked-in fixture config;
the same lane over the developer's own `~/.claude` is the `flaky`,
id-only `differential-real-config`); `replay-openclaw`, `replay-opencode`,
`replay-opencode2`, which replay the drills of `openclaw-e2e` and
`opencode-e2e` (those scripted-upstream suites retired on 2026-10-18,
test-reorganization.md §9.1); `differential-agents`
(OpenClaw, OpenCode, Codex), `flaky`.

### 6.3 `kernel`

Now `sandbox` (and the `kernel` need): the Rust `kernel` feature in full
(`cargo test --features kernel -- --include-ignored` inside the namespaces
`scripts/kernel-tests.sh` sets up); the launcher's kernel shell suites
(`net-guard-live`, `exec-box-live`, `landlock-net-live`, `secret-twins-live`,
`secret-readers-live`, `guard-death-live`); `tests/sandbox/`;
`launcher-kernel-tier` (a `replay-drill` with the `kernel` need); each
package's `test/kernel/` (§8.1).

A kernel entry whose prerequisite is missing SKIPs, and the runner compares
each entry's pass and skip **counts** against the expected ones
(`ci: { maxSkip: 0, minPass: 1 }`): a kernel run that skipped everything is
a failure, not a green.

### 6.4 `local-model`

Now `env`: `local-main-model`, `network-model`, `ollama-doctor`.

### 6.5 `real-model`

Now `live-drill` or `eval`:

- `claude-e2e` cuts, each an entry with `select`: the integrity cuts are
  frozen; `conf-smoke` (`secrets`) ran nightly until it retired on
  2026-10-18 (its drills carry it, test-reorganization.md §9.1).
- `codex-e2e` (its `stored-ipi` scenario is frozen,
  `tests/integrity/codex-e2e.test.ts`).
- `local-model`, `local-model-netns` (also `internet`).
- `subscription` and `subscription-real`: `secrets` (§7.3); they prove the
  credential relay, not integrity.
- `codex-mcp`, `policy-setup`, `policy-assistant-corpus`: `secrets` (§7.3);
  their untrusted-notes scenarios are frozen.
- The eval's live legs: `eval:utility` (the maintainers' utility runner, not
  published) is `manual` (§4). The live smoke
  (`eval.run-live`) and `eval:paired` are frozen (their wrapped legs run the
  integrity defense); see [`evaluation.md`](./evaluation.md).
- `openclaw-e2e` / `opencode-e2e` on a real upstream (`openclaw-headless`,
  `opencode-headless`).
- The `claude@latest` drift lane (`scripts/ci/claude-latest-lane.sh`):
  `flaky`, `internet`. It installs the newest `claude` into a temporary npm
  prefix of its own (removed when the lane ends;
  `MANDU_CLAUDE_LATEST_PREFIX_ROOT` moves its parent) whose `bin` leads
  `PATH` for the lane only, and refuses a prefix inside `~/.local` or npm's
  global prefix, so it never replaces a native install or an image's pin.
  `scripts/test/claude-latest-lane.test.sh` proves the prefix, the untouched
  native install, the `PATH` and the cleanup.

### 6.6 `drill`

Now `live-drill`: the drill catalog's non-frozen settings run nightly, one
entry per setting and area (`drill.<setting>.<area>`); the frozen settings
are the frozen lane (§7.2).

### 6.7 `install`

The VM matrix (`scripts/matrix/`): `fresh-install`, `fresh-agents`,
`kernel`, `all`, `wrapper` on the declared targets; `release-upgrade` by
hand; `scripts/kernel-vm.sh` as the alternate-kernel vehicle.

### 6.8 Frozen lane

Every package's `test:integrity`, the conformance corpus
(`tests/conformance` `run.ts`, `lib/unit_egress_gate.ts`), the integrity
`claude-e2e` cuts, and every entry marked `frozen: true`. It runs **only
when the integrity axis is revived** (`protection-modes.md §10` §5, §6): not per
push, not nightly, not before a release. The manifest records the lane so a
revival finds it whole; the runner selects it only with `--frozen`
(`scripts/test-all.sh --integrity` for its sealed part). The `claude-e2e`
scenario `inspect-verdict-retry` is its own `flaky` variant: about one run in
five the model does not refetch after the error verdict, the autonomous
recovery the scenario tests.

### 6.9 Platforms

`platforms` defaults to `["linux"]`. An entry is marked `["linux", "darwin"]`
when it has a real-Mac green record. The integrated selection inherits the
macOS branch's historical set (macOS 26.5.1 arm64, 2026-09-29;
`node scripts/suites.mjs list --platform darwin` lists them): the typecheck
and the whole `npm test` (unit and e2e) of launcher, reply-filter, arbiter,
anthropic-proxy, net-proxy, exec-wrap, inspect-mcp and policy-mcp (the
`DARWIN_PACKAGES` set in `tests/suites.mjs`), the dashboard's typecheck (its
`npm test` is not marked yet: the test-runner suites `manifest-runner` and
`suite-manifest` expect the Linux manifest's `sandbox` entries and Linux-only
ids, which a macOS run filters out), the darwin-only
`launcher.darwin-seatbelt` entry (the whole-agent Seatbelt profile under
`sandbox-exec`) and `launcher.darwin-git-sandbox` entry (Mandu's own git
under its Seatbelt sandbox, write-protection.md §8.5.2), both of kind `component`
(a `sandbox` entry runs in the Linux kernel lane), and the manifest's own
checks. `scripts/run-suites.mjs` (and so `scripts/test-all.sh`) keeps the current
per-run and per-entry private temporary directories. A darwin run uses a short
canonical `/private/tmp/XXXXXX/00` entry path when the inherited TMPDIR cannot
fit its sockets; the numeric child isolates each entry. The canonical `/private`
prefix counts toward macOS's 104-byte `sun_path` limit. The run directory is
removed at the end.
A direct `npm test` on a Mac should set `TMPDIR=$(mktemp -d /tmp/XXXXXX)`
first. The `replay-drill` and `sandbox` kinds, every kernel-lane entry and the
launcher's shell suites stay Linux-only: they need bwrap, user namespaces,
Landlock, seccomp or the Linux agent harness. How to
run the darwin set, and the macOS pitfalls (the symlinked `/tmp`, the socket
path limit, no `/proc`, no `setsid(1)`, `mktemp` outside `$TMPDIR`, pipes
written asynchronously):
[`development.md`, "Developing and testing on macOS"](../../development.md#developing-and-testing-on-macos).

## 7. Decisions

### 7.1 The fake-model agent suites move to `secrets`

Taken 2026-09-28, built 2026-09-29. The fake-model agent suites
(`claude-code`, `codex`, `codex-view-map`, `launcher-golden-path`,
`launcher-gated-posture`, `launcher-kernel-tier`, the differential suites)
had pinned integrity ON to prove the implementation-plan §9 oracle with a
poisoned file. They now prove the **confidentiality** invariant in `secrets`
mode. Why: the invariant that ships is confidentiality, and the per-push gate
must not depend on frozen code staying green. The canaries in
`protection-modes.md §10` §5 (`launcher/test/component/golden-path.test.ts` and
the others) are not changed.

**The fixture**, `tests/lib/conf-exfil.ts`, serves every suite. A file
whose name is in no default-secret catalog is labelled `no-model` over the
arbiter's admin channel (the user's act), or a catalog credential is written
to a throwaway HOME for the launcher's walk to register. The scripted model
reads it, then echoes whatever the read returned into a `curl` POST to a
loopback sink: an adversarial model, doing with the value what an
attacker-steered one would. Two oracles: (1) no captured model request
carries the canary, and the read's result span is one `$MDU:nomodel_…`
symbol; (2) the sink never received the canary. In-process suites also
require a sink hit carrying only the symbol (the network path is live
there); under the launcher the exfil must come back withheld by the egress
gate or refused by the connect confine (`assertLaunchedConfInvariant`).

- `claude-code`, `codex`: production proxy wiring (adapter over the real IPC
  client), HumanView reveal, dashboard level and banner; a control leg runs
  the same file unlabelled and shows both oracles fire. Known limitation:
  the proxy's per-result oracle can stamp a false violation when the secret
  Read's dropped `<total_tokens>` reminder tail recurs verbatim in the next
  tool_result (harness framing, not the secret); `claude-code` tolerates
  exactly that shape and fails on any other violation.
- `codex-view-map`: the P4 map's forward and reverse proofs on a labelled
  HumanView tree. The map is produced by fs-view, which runs only with
  integrity on; the proxy honors a map whatever the axes, so the suite pins
  the mechanism.
- `launcher-golden-path`: A a labelled file outside the workspace, B a
  registered `~/.aws/credentials`.
- `launcher-gated-posture`: every launch in `secrets`; G4 gains the exfil
  oracle.
- `launcher-kernel-tier`: the rungs as before with the fs rung off by mode,
  the credential confined via its twin; `--no-kernel` asserts the egress gate
  withholds the exfil.
- `differential`, `differential-agents`: the wrapped arbiter runs `secrets`
  (`differential-driver.ts` `DIFF_MODE`) and `notes.md`, the probe file, is
  labelled on the wrapped side, so F1-F3 keep their meaning. The scripted
  echo drops Claude Code's Read gutter and reminder tail
  (`extractEchoedContent`), because the wrapped model receives one symbol
  standing for the file's bytes (differential-interactive.md §20).

`withStack` (`lib/launcher-live.ts`) takes `mode` and gives the launch a
throwaway HOME (the secret walk would otherwise scan the developer's home)
and exposes the admin socket. The integrity forms moved verbatim to
`tests/integrity/` (the frozen lane), recorded in `protection-modes.md §10` §7.

### 7.2 Drills get secrets postures and run nightly

Taken 2026-09-28, built 2026-09-29. Drills that do not test integrity launch
in `secrets` mode and run nightly, non-blocking, with results on the
dashboard; the integrity drills and their launch settings are the frozen
lane. The drill catalog has since become one TypeScript catalog
(in the maintainers' drill suite), whose **settings** replaced the postures of this
decision:

| Posture (this decision) | Setting now | Launch |
|---|---|---|
| `S` (and `S1`) | `secrets` | `--mode secrets` |
| `S-mock` | `secrets-mock-sites` | `--mode secrets --mock-sites=…` |
| `S-raw` | `secrets-no-reply-filter` (by name only) | `--mode secrets --no-reply-filter` |
| `cc-mask` | `off-cc-mask` (by name only) | `--mode off` |
| P1, P2, P3, ctrl-raw | `frozen-full`, `frozen-full-mock-sites`, `frozen-strict-egress`, `frozen-full-no-reply-filter` | `--mode full`, with `MANDU_EXPERIMENTAL_INTEGRITY=1` added by the runner |

Drill ids are `<area>-<slug>` since 2026-10-01 (the old `U7`, `C9` are
refused).

**The review.** Each confidentiality and utility drill that sat at an
integrity posture was reviewed **statically** (no drill ran: a drill spends
the real model) and carries `review: { verdict, why, liveChecked? }`:

- **moved**: grading unchanged.
- **re-graded**: a check that assumed masked untrusted text dropped (a
  `symbolized` on a non-secret read, the injection's `raw_absent`,
  `ullm_ran` on an untrusted symbol, the AgentView twin notes); the answers
  and end states stay graded. A `no_sabotage` over injected data is soft and
  grades a followed injection WARN (`secrets` hands the injection to the
  model by design).
- **frozen**: its subject needs the integrity axis (a trust upgrade that
  passes vacuously when nothing is masked, the per-result trust split, the
  quarantine over an untrusted symbol, a declassify refused because a Read is
  untrusted, a bound-host approval that exists only when every Read is
  untrusted).

A moved or re-graded drill without a `liveChecked` date is marked "not yet
re-checked live" on the generated page and in the runner. Tests
(`drill-runner.test.ts`, `drill-catalog.test.ts`):
each setting's `--mode`; only a frozen setting carries the integrity opt-in;
no drill at a secrets setting is an integrity drill or carries a check that
assumed masking; every reviewed drill carries its review.

**A boundary of `secrets` mode, not a regression: a key only in VCS
history.** A deploy key committed and then deleted is in no catalog path, no
label, no registry and no current file, so the object twins (which cover the
committed versions of confined files) do not reach it; in `secrets` it can
reach the model raw. The invariant's definition of a secret (a registered
credential or a labelled file) does not include it. The boundary is stated
to users (`docs/guarantees.md` §3). The closure is a history scan, not
masking by shape: `mandu doctor --secrets` finds secret-shaped blobs in
every reachable commit, the reflog, the stash and the index and lists them
masked ([`secret-discovery.md`](../confidentiality/secret-discovery.md) §3);
once the human locks the gone path or the old blob (or applies the scan's
suggestion with `mandu policy suggest`), the launch's object twins hide it
and no model request holds the key (`tests/sandbox/git-history-locks.test.ts`;
[`confidentiality.md`](../confidentiality/confidentiality.md) §7.2a). The
drill for it stays frozen until its run applies the suggested rule.

**The runner's own arbiter.** Every non-frozen `drill.*` entry runs
`drill-run.ts --own-arbiter`: the suite runner pins `MANDU_POLICY_FILE` to
nothing and exports no admin socket, so without an arbiter of its own the
labelled confidentiality drills would skip and an Inbox hold would go
unanswered.

- **Started in the runner, not a manifest wrapper.** A manifest entry is an
  argv with no shell, and a wrapper would own the arbiter's lifetime from
  outside the process that dials it. In the runner the socket every reader
  dials is set once, the teardown sits in the same process's exit and signal
  handlers, and a human gets the same arbiter with the same flag.
- **What it is:** `scripts/dev-arbiter.sh` with a throwaway home, the TEST
  tenant and its admin socket, in the one mode the selected settings launch
  (`secrets`, or `off`; a frozen setting or a mix of modes is refused), with
  a copy of `drill-policy.yaml` as its policy. Axis
  variables inherited from the caller are dropped, so the mode alone states
  both axes. Its work dir is `<run dir>/arbiter`, or a temp dir when that
  socket path would be too long; then its `arbiter.log` is copied to
  `<run dir>/arbiter.log` when the run stops or the start fails
  (`keepOwnArbiterLog`).
- **A start that fails says why in the run's log.** The error carries the
  last 30 lines of the arbiter's log (dev-arbiter.sh prints them; the runner
  reads them itself from a script that did not), and
  `drill-own-arbiter.test.ts` prints a live test's whole
  `arbiter.log` to its output when it fails: its work dir is in the test's
  TMPDIR, which a CI guest discards, so the entry's log is the only copy
  (gl-8805/8811/8834 kept only the path). Those three failures were
  dev-arbiter.sh reading a start whose setsid(1) had not run yet as an exit
  (runtime-instances.md §10.2).
- **Wiring:** the runner exports `MANDU_ARBITER_SOCK`, `MANDU_ADMIN_SOCK`,
  `MANDU_TENANT=test` and `MANDU_POLICY_FILE` and hands them to every pane
  launch; `meta.json` records it.
- **Teardown:** SIGTERM to the daemon (`mandu-arbiter`) at the end of the
  run, then to the rest of its process group, SIGKILL after 10 s; the
  daemon's SIGTERM from an `exit` handler on every other way out. Never the
  group first: the tsx shim would SIGKILL a loaded daemon before it tidies
  its instance dir (runtime-instances.md §10.2). It is registered with `MANDU_OWNER_PID` = the runner, so `mandu reap`
  collects one a killed runner left.
- **Holds that re-open are answered again.** The arbiter keeps one Inbox row
  per {program, file} and, once a `once` verdict is spent, returns the same
  row to pending for the next opener (Claude Code runs several VCS processes
  over the workspace). `planHoldAnswers` (`lib/drill-arbiter.ts`) answers
  every pending row of the session, again when it re-opens.
- **One labels file:** the CI nightly stack copies the same policy file, and
  a docs-lane test (`integration.drill-labels`) keeps it equal to the
  documented block.
- **Its events outlive it.** The work dir (and its `events/`) stays with the
  run after the arbiter stops. In the CI guest, where it would be discarded,
  the pipeline carries each named session's log out with the run's record
  (`scripts/ci/live-events.mjs`, continuous-integration.md §6), so a CI live
  session has its event lanes on the host's dashboard.

Tests: `drill-arbiter-plumbing.test.ts` and
`drill-own-arbiter.test.ts` (a real arbiter through `dev-arbiter.sh`).

**The drill entries pin a model.** Every `drill.*` entry passes
`--default-model claude-haiku-4-5` (`DRILL_MODEL`, the e2e suite's base
model); the caller's `MANDU_DRILL_MODEL` overrides it. On the account default
model, safeguards paused some confidentiality drills; the runner grades such
a pause PAUSED, never a pass (test-reorganization.md §12.7).

**The run's record goes to the caller's watch store.** The suite runner pins
`MANDU_HOME` to `/dev/null/...`, so a drill run's record (`meta.json`,
`chapters.json`, the asciicasts, the report, the events) once landed in a
temp home no dashboard reads. Now `run-suites.mjs --watch-store DIR` names
the store (resolved from the caller's environment before the pins, the path
table's `live-drill-runs`, `on-disk-layout.md` §9); `test-all.sh` resolves
it before its own pin and always passes it; the dashboard's Tests drawer
appends its own store; `drill-run.ts --store DIR` puts the run dir at
`DIR/<run>`. `drill-run.ts` warns whenever the record will not be seen and
names the copy that fixes it, and the dashboard says "record missing" on a
watch session whose run is not in the store (`dashboard.md` §4.22). In the
CI guest the pipeline passes a scratch store and carries each run's record
files into the results archive (continuous-integration.md §6;
test-reorganization.md §8.1). Tests: `scripts/test/run-suites.test.mjs`,
`scripts/test/test-all-lanes.test.sh`, `drill-runner.test.ts`
(`watchRunDir`), and the dashboard's `watch-missing-record` and
`suite-manifest` tests.

### 7.3 The incidental integrity pins move to `secrets`

Taken and built 2026-09-29. After §7.1 and §7.2, fifteen entries outside the
frozen lane still pinned `injection` or `full`. Each got one of three
verdicts: **re-pin** (its assertions are confidentiality or mode-neutral
mechanics), **split** (a `secrets` form stays, the integrity-only assertions
move verbatim to the package's `test/integrity/`), or **move** wholesale to
the frozen lane. No integrity assertion was restated in `secrets`. A suite
that goes quiet in `secrets` would be the regression to fear, so each
re-pinned form mints a SECRET (a `no-model` label over the admin channel, or
a registered credential), asserts the chokepoint stops it, and runs a
control leg that shows the gate decides on the label.

| Entry | Verdict | The `secrets` form |
|---|---|---|
| `launcher.net-proxy-live` | split | the secret's symbol in an HTTP body: 403 naming `egress:secret-unbound`, nothing at the destination; control: the same secret bound to the destination is released; benign passthrough; the reap. Since 2026-10-05 the destination is a name a mock-sites host route sends to the loopback listener (the proxy relays nothing to this machine), and a leg checks the listener's own address through the proxy is refused. |
| `launcher.net-proxy-mitm-live` | split | the same legs over HTTPS through the TLS-inspecting proxy; a blind tunnel fails. |
| `launcher.exec-wrap-live` | split | `curl --data "leak=<secret symbol>"`: the shim leaves the placeholder as written and curl runs; with no egress proxy the destination gets the placeholder, never the value (confidentiality.md §7.1; before 2026-10-05, exit 77); control: a public symbol in the same slot is put back and curl runs. |
| `launcher.reply-filter-live` | re-pin | every reply mechanic on a secret's symbol (default on, nested deep resolution, fail-closed on a dead arbiter, the opt-out, the PTY relay); control: the model-facing deep `resolve` refuses it. |
| `launcher.exec-box-live` | split | the box's shared legs; a boxed command prints a secret's symbol, never its bytes, and a HumanShell `curl` carrying it is refused before it runs (77). |
| `launcher.secret-twins-live` | re-pin | the twin read inside the box, raw bytes absent, HumanView reveal, the U-LLM refusal; asserts the credential's symbol is `$MDU:nomodel_…`, so a quiet axis fails. |
| `integration.subscription` | split | a labelled file reaches the model only as one `$MDU:nomodel_…` symbol; the human reveals it. |
| `integration.subscription-real` | re-pin | its checks (the model's echo, the relayed OAuth credential) are mechanics. |
| `ci.claude-latest` | re-pin | runs the differential lane, `secrets` since §7.1. |
| `integration.openclaw-e2e`, `integration.opencode-e2e` | split | a conf posture: `secret-read-exfil`, `secret-net-exfil-blocked`, `secret-read-control`, `benign-read`, `inspect-extract` (a quarantined read of an `any-model` file), `prompt-secret` (a registered key typed into the prompt reaches the model only as its symbol). `stored-ipi`, `fs-view-writeback` and the untrusted exfil and inspect are frozen. |
| `integration.agents-real`, `integration.agents.inspect-extract` | split | the same scenarios on a real model; the conf oracles read a recording relay in front of the API. |
| `integration.launcher-real-home` | split | L1-L3 unchanged; L4/L5: the fs rung off by mode, no AgentView, the agents' config files byte-identical. |
| `integration.launcher-fixture-homes` | split | every row in `secrets`, raw bytes absent, the fs rung off by mode. |
| `integration.policy-setup` | split | POL-1 (no relaxation in force, every loosening pending) is mode-neutral; POL-2S: a labelled file the agent reads while it sets up protection reaches the model only as its symbol, and no change or proposal carries it. |
| `integration.codex-mcp` | split | CMCP-1 and CMCP-2S on Codex; CMCP-2's `inspect_symbol` leg has no `secrets` form (a quarantined read of a `no-model` symbol is refused by design). CMCP-2S skips, with the reason, where Codex's own bwrap sandbox cannot start under an AppArmor userns restriction. |
| `integration.policy-assistant-corpus` | re-pin | its oracles take no axis. |

Every launch in these suites gets a throwaway HOME and no host policy file.
The quiet-axis guard counts a `$MDU:nomodel_…` token only when its reveal
returns the canary (the handling prompt's own example tokens do not count).
With that, no entry outside the frozen lane pins `injection` or `full`
except the canaries.

The launcher shell suites' port race (§8.4) went with it: their listeners
bind port 0 and hand their ports over a port file, the launcher's net-proxy
runs on port 0, and the reap check keys on the proxy's identity, so
`net-proxy-live`, `net-proxy-mitm-live`, `exec-wrap-live` and
`reply-filter-live` are `parallel: true`. The frozen copies keep the old
`free_port` verbatim.

## 8. Fixes made during the reorganization

### 8.1 Honest tiers

Files in sealed packages that need bwrap, user namespaces or the
kernel-feature binaries moved to the package's `test/kernel/` (a sibling of
`test/component/`, so relative imports are unchanged), and each package
gained `test:kernel`; before, they self-SKIPped to green in the default run,
now they run where a skip is counted. Launcher: `claude-sandbox`,
`codex-sandbox`, `secret-bind-nesting`, `wsl-interop`, `wsl-windows-secrets`,
`bwrap-launch-notes`, the VCS object-twins test, `guard-death`,
`inspect-mcp-confine`. The integration package's kernel files are now
`tests/sandbox/` (test-reorganization.md §8). `run.test.ts` stays a component
test: its native-bin legs run shell stand-ins through the `MANDU_*_BIN`
overrides. `secret-readers-live` and `guard-death-live` left the default run
for the kernel lane; `wire-release-live` is `internet`. The kernel entries
are `parallel: true` (private arbiters, temp dirs, kernel-assigned ports)
with `ci: { maxSkip: 0, minPass: 1 }`.

### 8.2 Declared requirements

- `openclaw-e2e` and `opencode-e2e` state their axes (`MANDU_E2E_AXES`), and
  the live scripts set `MANDU_AXES_STRICT=1` like every other `npm test`.
- Eval's `npm test` excludes the live smoke, which is its own entry
  (`eval.run-live`, frozen); the pure normalizer test stays in `eval.lib`.
- `tls-compat` takes an opt-in (`MANDU_LIVE_TLS_COMPAT=1`) like every other
  live suite; `test:live:local-model-netns` sets the gate it needs.

### 8.3 Catalog drift

The hand-written drill page and the scenario catalog disagreed on ids; the
fix made the check compare them, and the single TypeScript catalog with its
generated page (§7.2) has since removed the second list altogether. The
dashboard registry badges OpenClaw's `inspect-extract` (OCl6) and registers
the `local-main-model-e2e` session class (badge LMM1); the dashboard's watch
settings are the catalog's, and a parity test keeps the copies equal. The
`models` cut lists every `modelAxis` scenario, and the manifest test
compares the list with the flags in `claude-e2e.test.ts`.

### 8.4 Running suites side by side

The runner runs suites in parallel. Each hazard is fixed, or its entry says
`parallel: false` (or `parallel: "sandbox"`, §9.1). The rules a parallel-safe
suite follows:

- **Ports.** A server binds port 0 and reports its port (the port-file
  pattern: `MANDU_PORT_FILE`, which the proxies, the dashboard supervisor's
  `port-file` readiness kind, and the launcher's adoption of the context
  proxy's published port all use). Where a port must be named before its
  server starts, or must stay dead, reserve one with `reservePort` (one
  identical copy per package: `launcher/test/lib/`, `dashboard/test/unit/`,
  `interceptors/inspect-mcp/test/helpers/`, `tests/lib/`; a stack test
  fails if the copies drift). The port is taken from the 8192 just below the
  host's ephemeral range, which the kernel never hands to a port-0 bind or a
  connect's source port; a UDP socket bound to the same number on 127.0.0.1
  claims it for the life of the process, so no two reservations share it,
  and a TCP listen there, closed at once, proves nothing listens. No suite
  binds a fixed port in that range. Pick-a-free-port-then-close is gone;
  dead-port tests take a reserved port, so they still reach their
  unreachable branch through a real refused connection.
- **Processes.** No host-wide probe (`pgrep`): a test probes the pids it
  started.
- **`$HOME` and host state.** No test writes under the real `$HOME`
  (audited by running each file with an empty temp `HOME`): npm calls get a
  `npm_config_cache` in the test's tmp dir; every launcher file that imports
  `src/run.js` imports `launcher/test/lib/private-home.ts`, which pins
  `npm_config_cache`, `MANDU_HOME`, `CLAUDE_CONFIG_DIR` and `CODEX_HOME` into
  a per-file temp dir (the launcher reads these from `process.env`, not from
  the env handed to `main()`), and `private-home.test.ts` fails a file that
  does not (nor one that runs a launch through `launcher/test/lib/launch-in-dir.ts`);
  launches set `XDG_RUNTIME_DIR` to the test's own temp dir;
  a launch is for its folder, never the runner's cwd (the package): an
  in-process launch goes through `launch-in-dir.ts`, which hands `main()`
  the env's PWD as its folder, and a spawned one gets that folder as its
  `cwd` (the launcher ignores a PWD naming another folder,
  packaging.md §1 "The launch directory");
  dashboard servers get `XDG_STATE_HOME` in their temp dir; the Rust box
  tests make their outside-`/tmp` trees under `/var/tmp` with a random
  suffix and an atomic `create_dir` (a pid is the same in every run inside a
  shared pid namespace; `bubblewrap_backend_runs_a_project_under_tmp`
  needs its project in the real `/tmp`, and a `RemoveOnDrop` guard removes
  it and its scratch file also when an assertion panics), and the Rust mock
  arbiter's socket name carries 64
  random bits and never removes an existing path. The known exception:
  `eval/lib/launcher-run.ts` and `eval/lib/paired/paired-runner.ts` need the
  real login.
- **Short socket paths.** A test that makes a Unix socket keeps its own
  prefix short (`mkdtemp("/tmp/mdu-…")` where `tmpdir()` could be long), so
  the path stays within `sun_path`'s 107 bytes.
- **Shared build dirs.** `fs-preload`'s `cargo build` and the workspace
  `cargo test` share `interceptors/target`: the runner builds once before the
  parallel stage.
- **Waits sized for a loaded guest (2026-10-07).** Under the parallel stage
  a timer fires late and a page takes seconds to render, so a wait is on a
  condition with a budget a loaded CI guest fits, never a short fixed one,
  and a "returned in time" check does not measure wall time. The dashboard's
  jsdom page waits share `dashboard/test/unit/page-wait.ts` (`waitWhile`, 60
  s; they were 2, 5 and 10 s, and a page that took 8 to 12 s to render
  failed "six waiting cards (got 0)" in pipelines 9422, 9531 and 9532). A
  served page's own 10 s poll is stubbed (the harness's `setInterval`), so
  a step that waits on what a Home poll sees, such as a service that starts
  again, stands in for it with `pollWhile` (a poll every 2 s while the page
  has not caught up, 60 s), never one poll: a lone poll can land before the
  restarted component answers on a loaded guest, and in the product the
  next poll reads again (2026-10-15: `product-files-again-pages` waited its
  60 s on one poll in pipelines 10830, 10832 and 10836; its failure message
  now lists the page's requests and the steps between them); the
  anthropic-proxy's deadline check holds an op that never answers and
  asserts it was still pending when the call returned (it asserted under
  150 ms for a 30 ms timer). A test that bounds a walk's cost (2026-10-10)
  sets its limit well under the regression it guards, not near the idle
  host's time, and checks growth rather than wall time where it can:
  `secret-extract-lists.test.ts`'s adversarial 256 KB inputs allow 5 s each
  (the regressions took 5 s to minutes) and, past 1 s, assert the full size
  takes under 3x its half size; a linear case took 1492 ms against the old
  1 s bound in pipeline 10158 (126 ms idle). The launcher's
  `launch-suggest` (2026-10-11) allows a launch 5 s past its budget and
  margin, and gives the launch that must answer from the earlier scan a
  10 s budget it must stay well under: its 300 ms and 600 ms bounds
  failed at 308 to 1058 ms (pipelines 10194, 10295, 10309), and a stall
  of 400 ms every 500 ms failed 29 of 50 runs.
- **A moment's words are read off a clock set from the moments
  (2026-10-15).** `ago` rounds to the minute, so a page clock that runs a
  fixed offset ahead of the real one says the next minute once the run is
  slow enough. `product-when-lines` set its pages 2 min 5 s ahead and
  asserted "2 minutes ago" on the session pages, which it draws last. A
  31 s run on the guest read "3 minutes ago" (master pipeline 10839), and
  so does a 30 s stall after its sessions on this host. Each page's clock
  now starts 95 s past the moment the sessions' events were all in and
  runs from when the page opens. The words then say 2 minutes until the
  sessions' own spread plus one page's draw passes 55 s, however long the
  run took before.
- **A served page's control is the one drawn now (2026-10-11).** A page
  draws a list again on its own reloads, at their own time. The inspector's
  session list, for one, reloads when its `/api/tenants` answer arrives.
  So a test queries a control again after any wait before it presses it.
  Where a step is about a redraw, the test makes the redraw itself, rather
  than hoping one lands.
  - `inspector-list-keyboard` K2 pressed a fold taken before a 20 s read.
    A reload in that read replaced the fold, so the key went to a detached
    node ("Enter closed the day", pipeline 10286).
  - K2 now draws the list again through the search box and presses the
    fold drawn then.
  - `inspector-dialog-focus` D1 took the 🛡 card's "Where each went"
    button before its Tab and Shift+Tab. A late answer (the posture
    egress.js publishes, the session's read) draws the card's body again,
    and the product keeps the focus on the button drawn at its place, so
    Shift+Tab landed on a button the test did not hold ("Shift+Tab from
    the first: the last", seven pipelines from 10252 to 10332). D1 now
    queries the button at each step and draws the body again itself
    between the keys (`mdu:posture-updated`), asserting the focus stays.
- **A wait ends on the answer it is about (2026-10-12).** A served page's
  other reads can draw what a test waits for before the answer to the
  test's own click arrives.
  - `suggested-names` waited for Not a secret's row to go, then read the
    notice that the click's answer writes. The page's first Home poll, late
    on the loaded guest, read the suggestions after the server had
    dismissed the row: the row went first and the notice was still empty
    (pipeline 10542).
  - `suggested-focus` K3 had the same wait before its focus check.
  - Both now wait for the notice too. A relay that holds the first
    `/api/home` and the dismiss answer failed the old wait every time and
    passes the new one.
  - The same pipeline's other failure was the product's
    (`product-could-not-read-why`; dashboard.md §4.25 *An older poll's
    answer never draws over a newer one*).
- **Back and Forward in jsdom wait for the URL (2026-10-11).** jsdom
  traverses the history on two chained 0 ms timers, and changes the URL
  and fires `popstate` in the second. A fixed 30 ms timer ran first after a
  stall before the first timer, so the test read the old page
  (`home-js-page-focus`, pipeline 10259). The wait is
  `waitWhile(() => location.pathname === from)`.
- **An in-process arbiter's clients take a long deadline (2026-10-18).**
  A stack test that runs the arbiter in its own process, beside jsdom and
  the dashboard, charges the page's work to every client's request timer
  (5 s by default): on a loaded runner the timer fired before the loop
  read the answer. In pipeline 11803 `inspector-pf-questions`' proxy
  refused the held message fail-closed (502 "arbiter filterPrompt
  failed"; 8 of 8 runs with 16 copies on one CPU before, 16 of 16 green
  after), and `inspector-page-focus`'s lookup of the moment an approval
  was asked answered 500, so the step was never marked (a 25 ms deadline
  gives that failure every time). Their production clients take a 60 s
  deadline (`requestTimeoutMs`, the event source's `connectTimeoutMs`), as
  `large-file-pieces` did first; a separate arbiter process, as in a
  session, never charges its work to an interceptor's timer. Each now
  prints why: the proxy's answer and its last lines, the page's note and
  every read after the press. The page's half was the product's: a
  lookup that failed said "not found" (dashboard.md §4.35 `?ask=`).
- **A served page's requests on fresh connections (2026-10-09).** jsdom
  runs the whole home.js synchronously in the test's own process, the
  DashboardServer's too, so on a loaded guest the event loop stays blocked
  for seconds; once that outlasts Node's 5 s keep-alive timeout, the page's
  first request reuses the HTML fetch's idle socket and the server's timer,
  run first, drops it under the request (`read ECONNRESET`: Home said
  "Could not check which agents are running" in pipelines 10057, 10066 and
  10069, each test over 7 s; reproduced with the test pinned to one busy
  CPU). Every jsdom fetch bridge goes through
  `dashboard/test/unit/page-fetch.ts` (`pageFetch`), so no request waits on
  an idle socket.
  - Until 2026-10-11 `pageFetch` sent `Connection: close` through the global
    fetch. That closes a socket after its request, but the pool still put
    the page's first request on the idle socket the test's own fetch of the
    HTML and home.js left a moment before. Home kept failing so in six
    pipelines (10185 to 10354), and two component files still bridged to
    the global fetch (`inspector-no-protection-service`: "the dashboard
    server did not answer", pipeline 10295).
  - The race needs the block to start in the loop's poll phase (the page's
    script runs when its fetch of home.js answers): after it the loop runs
    its timers before it reads the request.
  - The test's own fetch is on the same race when it runs right after a
    page's script: `served-page.ts` fetched each module after evaluating
    the one before ("fetch failed", pipeline 10380).
  - `pageFetch` now opens a socket of its own per request (`node:http`, no
    agent) and answers as fetch does (redirects, a gzipped body, abort).
    A file that runs a served page in jsdom (the dashboard's component
    tests, `served-page.ts`, and the stack tests that run one) fetches
    from the servers only through it. `page-fetch.test.ts` reproduces the
    race with the global fetch, proves `pageFetch` survives it, and fails
    such a dashboard file that calls the global fetch;
    `tests/stack/served-page-fetch.test.ts` fails such a stack test
    (`inspector-agent-version` read the server right after booting the
    inspector: "fetch failed", pipelines 10295 and 10308).
  - With a socket per request the answers' order changed, and
    `inspector-row-cells` failed 9 of 24 loaded runs: a read that set out
    before Block drew the row again, and the refusal's words went to the
    replaced row (the press had no focus, so `focusRefused` did not look
    for the new one). That was the product's: egress.js now draws them on
    the rows drawn now (dashboard.md §4.32 *An answer keeps the focus in
    its list*); 50 of 50 loaded runs pass.

### 8.5 Each suite's own TMPDIR (2026-10-03)

**Why.** Suites left their temp dirs behind. A default local run
(`unit,component,stack,sandbox`) left about 400 entries and 38,600 inodes in
`$TMPDIR` (the dashboard's replay and scale tests alone 35,500), plus tsx's
compile cache; on a host whose `/tmp` is a small tmpfs this exhausted the
inodes and every command failed with `ENOSPC`. Nothing noticed, because
nothing looked.

**The rule for a test.** Every temp dir or file a test makes goes under
`os.tmpdir()` (`$TMPDIR`, `${TMPDIR:-/tmp}` in shell) and is removed by the
test, also when it fails: in a `finally`, a `t.after`, a shell `trap … EXIT`,
or through the package's `tmpDir(prefix)` helper, which records the dir and
removes it when the test process exits (`dashboard/test/unit/tmp-dir.ts`,
`tests/lib/tmp-dir.ts`, `launcher/test/lib/tmp-dir.ts`,
`fs-sync/test/helpers/tmp-dir.ts`, `interceptors/net-proxy/test/tmp-dir.ts`,
`scripts/test/lib/tmp-dir.mjs`; a package that needs one adds its own copy).
A child or daemon the test started is stopped before its dir goes. A path
outside `$TMPDIR` (a socket that must stay short, a tree the exec box must
not hide) is removed the same way; the guard below only warns about it, so
review it. A SIGKILL skips every trap, so such a dir also carries a lock its
suite holds (`flock` on `.owner.lock`, which the kernel drops however the
suite dies), and the suite's next run first removes this user's dirs whose
lock nobody holds (`owned_dir` and `sweep_stale_dirs` in
`launcher/test/exec-box-live.test.sh`). A lock, not a pid: a pid read in
another PID namespace (ns-run, the CI guest) names another process. Rust
integration tests name their temp paths, sockets and IPC objects (a POSIX
shm or message queue, an abstract socket) by the pid AND a random word,
never the pid alone: the kernel lane runs each crate's tests in a PID
namespace of its own, where the same small pids come back in every crate
and every concurrent run, and a name known in advance can be taken first.
Their pipes and socketpairs are close-on-exec: libtest runs a file's tests
on threads of one process, and a descriptor without the flag leaks into
whatever another test's thread spawns. In net-supervisor every integration
file takes both from one shared module, `run_tag`, `pipe` and `socketpair`
in `interceptors/net-supervisor/tests/support/mod.rs` (`mod support;`).

A wait for something the test started has a deadline, and a test never
hangs (2026-10-17). The kernel lane's guest timeouts (pipelines 10978,
11050 and 11099) were `rust.kernel` never ending, with nothing in the log
to say why. The same module's `reap_within`, `readable_within` and
`join_within` wait `wait_limit()` (240 s, `MANDU_TEST_WAIT_S`; a passing
test takes seconds, a little over a minute in the busiest CI runs). Past
it the test fails by name: what it waited for, then every task of the
child's tree and of the test process (comm, state, kernel wait channel,
the syscall it is blocked in, from `/proc`). The child's tree is killed;
a stuck thread is left running, since a thread cannot be killed. A wait
with no one child to blame (the report of an orphan the test process
adopted, a readiness pipe of a process outside the tree, a polled
condition) uses `readable_within_tree`, `read_to_end_within` or
`until_within`: it fails the same way with the state of the test
process's whole tree and kills nothing, since a file's tests share the
process. exec-supervisor's `supervise_exec` takes the deadline itself
(`SupervisorConfig::deadline`, exec-routing.md §4.4): the kernel tests'
wrapper of the same name sets it to `wait_limit()`, and past it the crate
kills the box's tree and answers `TimedOut`, which the wrapper turns into a
`STUCK` failure with the test process's tree. A wait inside code the test
does not own and cannot hand a deadline (a `Command` that runs the exec
box or `mandu-landlock-apply`) runs under a `Watchdog` (`bounded`,
`BoundedCommand::status_bounded`): past the limit it prints the tree's
state and kills every descendant of the test process, so the wait inside
returns and the test fails by name. That kill cannot tell the stuck call's
children from another test's, so a test beside it may fail too, after the
report has named the stuck one.

Every integration file of net-supervisor, and the kernel tests of
fs-supervisor (`kernel_integration.rs`, `landlock_integration.rs`) and
exec-supervisor (`kernel_integration.rs`), which include the same module
by `#[path]`, use them (2026-10-17): every `reap` in the test process,
every hand-over of a seccomp listener, every wait for a trapped call's
notification, every join of a supervisor or a parent-side helper thread,
every blocking read of a report pipe in the test process, and the TPROXY
test's proxy (`ProxyHandle::is_finished`, then `join`). A forked child's
own waits are covered by its parent's deadline, which kills the whole
tree. Left unbounded: the one-shot probes of a system tool (`ip link set
lo up`, `python3 -c`, `bwrap --version`, `ps`), which run no supervisor
and no sandbox, and `exec_script_race.rs`, whose children only sleep a
few milliseconds and exit. A race's parent-side flipper stops through
`StopOnDrop` however the test ends. The race helpers print `RACE TIMING`
(the tracee's wall time, CPU and context switches, then how long the
flipper and the supervisor took to stop); a guarded run that takes 10 s
or more prints `SLOW GUARDED RUN`. Both show where a slow run's time went.

**The guard** (`scripts/run-suites.mjs`, so `test-all.sh` and CI alike).
Each run makes one directory, `mdu-run-XXXXXX` in the runner's own tmpdir,
and gives every entry a fresh, empty `TMPDIR` under it, `<run dir>/<n>`.
Sandboxed (CI), the entry's dir is a `--bind-rw` of `ns-run.sh` and its
`TMPDIR` is set over ns-run's; the box's `/tmp` is still its own tmpfs. When
the entry exits, its process group gets SIGTERM and up to 5 s to be gone,
then SIGKILL; then the runner lists what is left in the dir. Anything left
FAILS the entry, with the count, the inodes and the first ten names, in its
log, its console row and `junit.xml`: `left 2 entries (5 inodes) in its
TMPDIR: stray.sock, tmp.x`. The summary line names every entry that leaked.
`--tmp-leftovers warn` (`MANDU_TEST_TMP_LEFTOVERS=warn`) only reports.
Either way the dir is then removed, read-only subtrees included, and the
run's directory at the end of the run (and by an exit hook when the runner
dies before that).

- **The tools' caches** are not the suite's leak: `tsx-<uid>`,
  `node-compile-cache`, `opencode` (the opencode CLI's temp root) and Bun's
  runtime library `.bun-<uid>-<hash>.so` (a Bun-compiled CLI such as
  OpenCode 2 unpacks it at every start, `--version` included) and Claude
  Code's temp root `claude-<uid>` (`$CLAUDE_CODE_TMPDIR`, else the tmpdir,
  plus `/claude-<uid>`: its sessions' task output, made at every start,
  `--version` included; the first nightly, 2026-10-09, failed six passing
  drill and corpus entries on it) are left
  out of the count and removed with the suite's dir (the whole dir goes
  whatever is in it, so a CLI's task output never survives), so each suite compiles
  cold (about half a second for a mid-size package). A cache shared per run
  was rejected: a symlink to it would not resolve inside a box, and the old
  shared `/tmp/tsx-<uid>` grew without bound.
- **The runtime dir.** An unsandboxed entry whose environment has no
  `XDG_RUNTIME_DIR` gets a fresh one, `<run dir>/<n>.rt`, as ns-run gives
  each box one; without it the arbiter's runtime root falls back to
  `$TMPDIR/mandu`, which a session keeps by design. A caller's own
  `XDG_RUNTIME_DIR` stands.
- **Equal lengths.** `<n>` is two base-36 digits, so every entry's `TMPDIR`
  has the same length. A replay drill's plain screen prints its workspace
  path, so where a line wraps follows that length; the baseline cache key
  therefore carries `tmpdir().length` (`profileConfigHash`,
  `baseline-cache.ts`), and a baseline is reused only under
  a temp dir of the same length.
- **Forensics on red.** A red replay or differential drill keeps its
  artifacts dir on purpose (removed on PASS or WARN). Under the runner such
  an entry is red already, the leftover is added to its reason, and the dir
  goes with its `TMPDIR`. To keep them, run the file by hand, outside the
  runner.
- **Strays (2026-10-03).** A daemon started with `setsid` (or `detached`)
  leaves the entry's process group, so the group's signals miss it. Every
  entry's environment also carries `MANDU_TEST_ENTRY=<its TMPDIR>`, and
  every process it starts inherits that and the `TMPDIR`, which name a
  directory unique to this entry of this run. Once the group is gone, the
  runner reads `/proc` for this uid's processes born since the entry's
  first one that still name that directory (or its runtime dir): in
  `MANDU_TEST_ENTRY` (equal), `TMPDIR` or `XDG_RUNTIME_DIR` (under), as
  their cwd, or in an open file (a daemon that dropped its environment but
  logs there). One already on its way out (the suite stopped it just before
  exiting) gets 2 s to go; the rest get SIGTERM, 2 s, SIGKILL, and FAIL the
  entry like a leftover file, named by pid and argv: `left 2 processes
  running outside its process group (killed): 72601 (node …/tsx …), 72629
  (mandu-arbiter)`. `warn` reports them and still kills them. The match is
  exact, so no other process is touched. A sandboxed entry's box ends its
  PID namespace, so its daemons die with it, and the entry ends only once
  the box has (below, "A box still ending").
- **Strays that name nothing (2026-10-17).** A daemon that dropped its
  environment, moved its cwd and holds nothing open under the dir names
  nothing of its entry; its ancestry is the trace it cannot drop. On Linux
  the runner starts every entry under a subreaper of its own,
  `scripts/lib/subreaper.c`, built once per run with the host's `cc` into
  the run's directory (`subreaperBinary`). It marks itself
  `PR_SET_CHILD_SUBREAPER`, starts the entry as its child in a new session
  as before, and reaps every child that ends, as init would. Every orphan
  of the entry's tree is reparented to it instead of init. Once the
  entry's group is gone, any live child of the subreaper is a stray
  whatever it names (`orphan` in the scan, `adoptedBy` in
  `entryStrays`), killed and reported like the others. The subreaper names
  the entry's TMPDIR itself and is never one (`exclude`). It reports the
  entry's pid and start time, read before anything can reap the entry, then
  its exit code or signal, on a pipe (fd 3). It ends when the runner closes
  its stdin after the strays are gone, so the entry's group, its timeout
  and its exit are what they were.
- **Why C (the first two pipelines of !1667).** Node cannot call prctl(2)
  nor reap a child it did not spawn, and an interpreter above the entry is
  one of its ancestors. A python3 subreaper made
  `launcher/test/secret-readers-live.test.sh`'s refusals pass, because a
  guard that trusts a `from: python3` parent looks at every ancestor. A
  node one, exec'd from python3 for the prctl, never reaped what it
  adopted: a launcher killed by a test stayed a zombie, alive to the next
  launch's `kill -0` and to the test's (guard-death-live,
  twin-git-clean). And before the start time came from the subreaper, an
  entry that ended before the runner read its `/proc` had no start, every
  process of the uid was in the scan, and the subreaper itself was
  "found" and killed. A host without the subreaper (not Linux, no `cc`,
  or `MANDU_TEST_SUBREAPER=0`) runs the entry directly and finds strays by
  name alone.
- **A box still ending (2026-10-18).** Six sandboxed entries in four CI
  runs of 2026-10-17 (`net-proxy`, `integration.agent-sdk`, three
  differential cells, `integration.replay-openclaw`), every test passed,
  failed on `left 1 process running outside its process group (killed):
  <pid> (?)`, on a loaded host. The process was the box's init: bwrap
  returns as soon as the command exits (its init, pid 1 of the box, tells
  it the status at once), while the init, in a session of its own, still
  kills and waits for what the command left and releases the box's
  namespaces and mounts. The outer bwrap gone, the subreaper adopted it;
  already exiting, it had no command line (`?`), and past the 2 s it was
  killed and counted. `scripts/ci/ns-run.sh` now stays bwrap's parent,
  reads the init's pid from bwrap's `--info-fd` and returns only once it
  has ended (at most `NS_RUN_END_S`, 30 s, then it says so on stderr), so a
  sandboxed entry ends when its box does and what the runner finds after
  it is a real stray (`scripts/test/ci-ns-run.test.sh`, "the end of the
  box", with bare bwrap as the control).
- **Outside the TMPDIR (2026-10-03, a warning).** For an unsandboxed entry
  the runner lists `/tmp`, the caller's `$XDG_RUNTIME_DIR` with its
  `mandu`, `mandu/instances` and `mandu/human` (not an entry's own runtime
  dir), and `$HOME` before and after, and names what is new, owned by this
  uid and still there: `[run-suites] outside: …` in the log, a `⚠ OUTSIDE`
  row, a summary line. Another process of the same user (a concurrent
  entry, another session) writes there too, so it is never a failure; it
  makes the next hard-coded `/tmp` visible. A box has its own `/tmp`, home
  and runtime dir, so a sandboxed entry is not listed. The runner never
  removes anything there.
- **Not seen:** what an entry writes outside its TMPDIR and removes before
  it ends, or leaves where another process also writes (the warning above
  is the only signal), and, on a host without the subreaper, a stray that
  names nothing of the entry's.
- **Socket paths.** An entry's `TMPDIR` is about 18 bytes longer than
  `/tmp`; a test that puts a Unix socket deep under `tmpdir()` keeps its own
  prefix short (§8.4).
- **The Rust mock arbiter's sockets.** A mock kept for the whole process
  (`MockArbiter::leak()`, `interceptors/mandu-arbiter/src/mock.rs`) removes
  its socket from an `atexit` hook of the process that leaked it.
- **A drill run's temp home.** Under the pinned `MANDU_HOME` a `drill-run.ts`
  run makes its own home, `mandu-watch-home-*` in `$TMPDIR`
  (`watchManduHome`); it is removed when the run exits unless the run's
  record is inside it (no `--store`: the only copy, which the run names)
  (`dropTempHome`, `drill-launch.ts`).
- **Shell suites stop their daemons.** A live launcher suite stops its
  `setsid` arbiter with `mdu_stop_group` (`launcher/test/lib/lifeline.sh`:
  SIGTERM to the group, up to 5 s, then SIGKILL) before it removes the work
  dir, so the daemon does not outlive the suite (the first run of the stray
  check caught `net-proxy-mitm-live` and `reply-filter-live` leaving their
  arbiters shutting down, and `spawn.test.ts`'s WINCH grandchild leaving
  its `sleep`). Every live launcher suite that starts an arbiter
  (`net-proxy-live`, `net-proxy-mitm-live`, `exec-wrap-live`,
  `reply-filter-live`, `pipe-taint-live`, `derived-label-live`,
  `secret-readers-live`, `secret-twins-live`, `exec-box-live`,
  `wire-release-live`) also sets `MANDU_RUNTIME_DIR` to `$WORK/rt`, so its
  arbiter's instance registry and human-plane socket and its launches'
  scope dirs stay out of the caller's `$XDG_RUNTIME_DIR/mandu` (a pinned
  arbiter registers an instance in its runtime base too,
  `arbiter/ipc/server-main.ts`), also when the suite is SIGKILLed and no
  trap runs: what is left is in the work dir, under the entry's `TMPDIR`.
  Each one's arbiter also holds the suite's lifeline
  (`launcher/test/lib/lifeline.sh`; `scripts/dev-arbiter.sh` takes it as
  `MANDU_LIFELINE_FIFO`), so a killed suite's arbiter exits with it: one
  registered under the work dir is out of `mandu reap`'s sight. The
  lifeline FIFO is one pipe every child of the suite inherits (fd 9), so
  the net-guard suites run their guarded commands through
  `mdu_without_lifeline`, which closes it: a tainted process holding it made
  every other holder a reader of its pipe, and the guard refused clean
  commands (found on the first run of this change).
- Tests: `scripts/test/run-suites.test.mjs` (a clean entry, a leaky one with
  a read-only subtree, a red leaky one, a daemon that cleans up on SIGTERM,
  each unsandboxed and through a fake `ns-run.sh`; `warn`; the per-run dir
  gone afterwards; three `setsid` strays found by environment, cwd and an
  open file, killed, failing the entry, and only reported under `warn`;
  `entryStrays`' exact match; the outside warning), and
  `drill-runner.test.ts` (`dropTempHome`).

#### 8.5.1 The host's temp dir itself: `scripts/tmp-gc.mjs` (2026-10-18)

**Why.** Everything above keeps a run of the suite manifest clean, and
nothing kept the host's `/tmp` clean. On a shared development host whose
`/tmp` is a tmpfs of 1,048,576 inodes, the dir reached 100% of its inodes
for minutes and every write of every process failed, the agent sessions'
tools included. What filled it was not run-suites: tsx's compile cache
(`tsx-<uid>/`, about 205,000 content-hash files from tests run by hand),
the per-session scratch dirs of the coding agent's CLI
(`claude-<uid>/<cwd>/<session>/`, over 200,000 inodes, most of them of
sessions that had ended), Node's compile cache, the results dir every
run-suites run without `--out` leaves (`mandu-suites-*`), the dirs a test
run by hand leaves when it fails or is killed, the native modules a
bun-compiled CLI extracts at each start (`.<hex>-<hex>.so`, 5 to 14 MB
each) and the sockets of dead processes. A session cannot clean up
what a disk-full shell will not let it run, so the cleanup has to be a
command that is already there and that is said before the dir is full.

**The rules** (`node scripts/tmp-gc.mjs`, a dry run; `--apply` removes). It
touches only this user's entries, and only these classes, each with its
own age (nothing in the entry's whole tree modified or changed, mtime and
ctime, for that long; the thresholds are options):

| Class | What | Age (option, default) |
|---|---|---|
| `leftover` | a top-level entry named by a test leftover's prefix (`mandu-`, `mdu-`, `org.chromium.Chromium`, `shot`, `q-chrome`, `aio-stock`, `qemu_run_`, `v-`; `--prefix` adds one), a `.<hex>-<hex>.so` or a `.bun-<uid>-<hex>.so`; never a name with `cache` in it nor `mandu-<digits>` (the runtime base fallback) | `--leftover-hours` 24 |
| `tsx-cache` | a file in `tsx-<uid>/` neither read nor written for the age (atime counts: a cache file is written once and read often; relatime moves atime at most daily); a `<pid>.pipe` whose pid is gone | `--cache-hours` 24 |
| `node-cache` | a file under `node-compile-cache/` by the same age, and the dirs left empty | `--cache-hours` 24 |
| `dead-socket` | a top-level `srt-mux-<pid>-<n>.sock` whose pid is gone | none |
| `claude-session` | a session's scratch dir `claude-<uid>/<cwd slug>/<uuid>/`; then the cwd's dir once empty | `--session-hours` 48; `--live-session-hours` 168 when a live `claude` process has that cwd |

Whatever the class, an entry stays when another uid owns any inode in its
tree, when part of it is on another filesystem (a mount) or unreadable, and
when a live process of this user holds it or anything under it: its cwd or
root, an open or a mapped file (`/proc/<pid>/fd`, `/proc/<pid>/maps`), an
absolute path in its environment, or a Unix socket bound in this network
namespace (`/proc/net/unix`; a listening socket's fd names no path). A
session id held under one cwd's dir is held under every cwd's (a session
that moved into a worktree has a dir under each). Without `/proc` (macOS)
it removes nothing. The stamp `.mandu-tmp-gc-<uid>.stamp` in the root makes
`--throttle-minutes N` a no-op within N minutes of the last run.

**The inode warning.** Past 80% of the inodes (`--warn-percent`), the
script prints one line naming this user's biggest top-level entries (by
inodes, a 5 s walk) and every owner's count of top-level entries.
run-suites prints the same line first (`MANDU_TMP_WARN_PERCENT`), since a
full temp dir fails every entry with its own `ENOSPC`.

**Where it runs.** The agent sessions' start hook runs it in its `--hook`
form at most hourly: the warning, and one line with the stale count and the
command that removes it when that is 1,000 inodes or more; the removal
itself runs there only where the host's human opted in
(`MANDU_TMP_GC_APPLY=1`). Every GitLab CI job's `before_script` runs it with
`--quiet` (the warning only) on the runner host, whose `/tmp` is the same
tmpfs. A removal without a person's decision is not the default anywhere.

**At the source.** `cloud-backed-local-model.test.ts` stops the daemon it
spawned before it removes the daemon's dir (a daemon that started after all
outlived the test); `launcher/test/unit/mcp.test.ts` and
`twin-index-stat.test.ts` take their dirs from the package's `tmpDir`, so a
failing assertion no longer leaks one; a run-suites run without `--out`
prunes the older results dirs to the newest five and those of the last six
hours (§5, the results dir).
What a tool keeps for itself (the
caches, the session scratch, the extracted modules) has no source to fix in
this tree, and the failed live runs keep their dirs as evidence on purpose
(`launcher-live`): those are the pruner's.

- Tests: `scripts/test/tmp-gc.test.mjs` (the names, each class over a temp
  tree, the owner, filesystem and hold rules with an injected process
  table and then the real `/proc`, the throttle, the warning, the CLI), the
  run-suites warning in `scripts/test/run-suites.test.mjs`, and the start
  hook's use (throttled, off by default for the removal) in the agent
  workflow's own suite.

### 8.6 A suite's plumbing names its tools by path (2026-10-04)

**Why.** `integration.https-proxy-taint` failed on a dev host (Linux 7.0)
and passed in both CI guests, the Linux 7.0 guest included, on the same
commit. The host's `PATH` put `/usr/local/bin/base64` ahead of coreutils: a
pip entry point of the `codext` package, installed for a Python the host no
longer runs, which dies with `ModuleNotFoundError`. The suite's holder reads
`.env` through its reader and decodes the pipe with `base64 -d`; with the
decoder dead it sourced nothing, so its own liveness check ("BASH
control=raw") failed. The product was not involved: the reader's sends to
the unbound host were refused (403) throughout and the host saw no canary.
Before this check existed such a host would have made the oracle hold
vacuously, since a holder with an empty key leaks nothing.

**The rule.** A tool a suite's script uses as plumbing (not as its subject)
is resolved before the launch to a binary that is probed to work, and named
by its absolute path; none working is a SKIP with the reason, never a run.
`tests/lib/holder-reader.ts` `workingBase64` is the first: the first
`base64` on `PATH`, then `/usr/bin`, `/bin`, that decodes a known string.
`https-proxy-taint` and `tainted-egress` (its fixture's `READ`) use it.
Tests: `tests/stack/holder-reader-base64.test.ts` (a dead `base64` first on
`PATH` is passed over; null when none decodes, a wrong decoding included).
Left: the catalog drill `conf-transformed-leak` runs the bare `base64` the
agent typed, which is its subject; on such a host it fails until the host's
entry points are repaired (test-reorganization.md, "The dev host's
`base64`").

### 8.7 A test's own runtime dir; GNU programs on a uutils host (2026-10-09)

**Why.** On the shared dev host (Linux 7.0, Ubuntu 26.04) 81 launcher tests
failed and passed in CI. Another account had made `/tmp/mandu`, and every
test that hands the code under test an env naming no runtime dir (`parse(argv,
{})`, `gatherFacts({}, …)`, `runDashboard([], {}, …)`, `ensureArbiter` with
`process.env` and no `XDG_RUNTIME_DIR`) resolved the runtime base to that
shared name (runtime-instances.md §3b, rule 3), where the product's
ownership check refused it. The product was right; the tests were not
hermetic. Where nobody had made it, the same tests read the real
`/tmp/mandu` (a `current` link there changed their answer) or left one of
their own that refused every other account's Mandu. Four other host-only
reds had host causes too: Ubuntu 26.04 ships uutils coreutils, whose
programs are one multi-call binary that picks what to run from argv[0], so
Mandu counts each as a printer and as running code (`MULTICALL_PRINTER_DIRS`);
its bubblewrap AppArmor profile forbids a sandbox inside the bind wrap.

**The rules.**
- A launcher test that calls a function resolving the runtime base from an
  env it hands in imports that function under another name and calls it
  through `hermetic(fn, envArg)` (`launcher/test/lib/test-runtime.ts`): an
  env that names no `MANDU_RUNTIME_DIR`, `XDG_RUNTIME_DIR` or `TMPDIR` gets
  `XDG_RUNTIME_DIR=<the file's private temp dir>`, so no call site can
  forget. An env that names one is the test's choice (the rule's own tests
  pin a long `TMPDIR` to reach the `/tmp/mandu-<uid>` fallback). A test that
  spawns Mandu with `...process.env` gives it `MANDU_RUNTIME_DIR` in its temp
  dir, never the caller's real runtime dir. Checked by running the suite
  with `XDG_RUNTIME_DIR` unset and by running it with
  `MANDU_RUNTIME_DIR=/dev/null/…` (both green, 2026-10-09).
- A test whose control needs a leaf program (one binary, one program: a
  listed reader that reads the real file, an Always that names a binary)
  takes GNU's copy through `tests/lib/gnu-coreutil.ts` (`gnusha256sum`,
  `gnutee` where uutils owns the name) and SKIPs, saying so, where none is
  installed: `integration.args-code-reader`, `integration.kernel`'s
  write-protect case, `integration.reader-output-rule`'s own copy.
- `launcher.kernel`'s WSL twin test reads through the bind wrap, so it
  answers the nesting probe yes (`nestingOk`): `cat` starts no sandbox of
  its own, and on a host whose bwrap forbids nesting a guarded launch would
  otherwise drop the bind for guard-served twins and leave no wrap to run in
  (the `TypeError` of an empty `launchPrefix`).

Tests: the launcher suite itself (2,260 tests, 0 failures with
`XDG_RUNTIME_DIR` unset or the runtime dir poisoned, on a host whose
`/tmp/mandu` belongs to another account); `scripts/test/guest-registry.test.sh`.

### 8.8 A third-party agent's own crash in a control run (2026-10-10)

**Why.** `launcher.component2` went red in 19 of the 139 CI runs that ran
it on 2026-10-09 and 10-10 (the runs kept), always on one test:
`goose-real.test.ts`'s CONTROL, the run of the pinned goose 1.53.0 with no
Mandu in the path. Every one had the same
stderr: `thread 'sqlx-sqlite-worker-N' panicked at
crates/goose/src/tracing/observation_layer.rs:312:9: there is no reactor
running, must be called from the context of a Tokio 1.x runtime`, then
`panic in a destructor during cleanup` and an abort (no exit status). It is
Goose's bug. Its Langfuse layer, built when `LANGFUSE_PUBLIC_KEY` and
`LANGFUSE_SECRET_KEY` are both set, calls `tokio::spawn` from its
`on_close`. A sqlx-sqlite worker is a plain thread that holds a handle on
the caller's span, and when that handle is the last one, the span closes on
the worker, outside any Tokio runtime. Whether it is the last is a race. It
shows only inside the full per-push run: about 1,100 isolated runs of the
same control (on a host, and in the CI guest image idle, under CPU hogs and
with slow upstream and collector answers) never crashed, so the fix cannot
rest on a reproduction. It rests on the source: the panic site is in the
Langfuse layer, which Goose builds only with both keys set.

**The rule.** When a pinned third-party agent fails in a control run on its
own bug, find the trigger and leave it out of the control if what the
control proves does not need it; the legs under Mandu keep the full env and
stay strict. Retrying or skipping on the crash's signature is the fallback
for a crash with no avoidable trigger, never a first resort, and never
matches any other failure. Here the control drops the Langfuse keys
(`controlEnv`). It asserts the OTLP traces, and Langfuse sends its batch
every 5 s with no flush at exit, so the keys gave the control nothing it
checked. The Mandu leg keeps them: the launcher empties them
(`goose-delivery.test.ts`), and an upload, or this crash, under Mandu would
fail it.

Tests: `goose-real.test.ts` itself (both legs green; its control 120 runs in
the CI guest with the keys removed, 0 crashes).

### 8.9 Guard tests in one process run one at a time (2026-10-10)

**Why.** `rust.kernel` failed in 15 of 132 CI runs on one assertion,
`the_orphan_window_ends_at_the_holders_death` round (a): a process born
after a holder died was refused. The guard's orphan window was right
(exec-routing.md §7.5 (d), "One process's tree"). The guard in a Rust
kernel test is the test process itself, and the subreaper of every test
the harness runs beside it, so another test's children are, to it, a
reaper's children: orphan roots, which its rule adopts by time alone (one
born while a holder lived and alive at its death), fail-closed. Traced by
logging every holder the guard recorded, with a backtrace, in a loaded VM:
8 failures in 200 runs, every one through another test's child. A longer
wait could not have fixed it, and the failure did not depend on timing in
the round itself.

**The rule.** A test file whose tests run the guard in the test process
serializes them (`static SERIAL: Mutex<()>`, `let _serial = serial();`
first in each test), as `socket_flow_integration.rs`,
`wait_status_integration.rs` and the other guard test files already did;
`taint_gaps_integration.rs` was the one without it. A control that expects
an untainted process also keeps clear of the rule's other fail-closed
answers by construction, with condition waits rather than sleeps: round
(a)'s root starts its holder in a later clock tick than its own
(`until_past_own_start_tick`), since a holder with no recorded lineage
takes in a reaper's child born in its tick. Its assertion names what the
root holds, so a recurrence says which rule took it in. The same holds
for the crate's unit tests, which share one process too: none turns the
process's subreaper flag off (`an_orphan_inherits_from_the_holder_that_
died_while_it_lived` did, at its end, under the tests beside it that need
their orphans re-parented to it).

Tests: `rust.kernel` (taint_gaps_integration.rs: 200 of 200 runs green
after, in a VM with a CPU burner per vCPU; the file now takes 11 s
unloaded instead of 5); the tick rule's unit test
`secret_open::a_root_in_the_tick_of_a_holder_whose_lineage_is_lost_is_its_orphan`.

### 8.10 A cost bound is CPU time; a daemon is ready when it answers (2026-10-18)

**Why.** `arbiter` failed in 4 of 106 CI runs, every one in a run whose
suites took 720 s or more (a loaded host; ~500 s alone), on tests that
time the wall clock. A complexity guard ("a long command after a cd, with
thousands of labels sharing a name, stays bounded") takes ~1.6 s alone and
took 10.3 and 11.5 s against its 10 s bound with the same work; a boot
test connected as soon as the daemon's socket file appeared and was
refused (`ECONNREFUSED`): the file appears when the daemon binds, a moment
before it listens.

**The rule.** A bound that guards against a quadratic or exponential walk
measures the process's CPU time (`process.cpuUsage()`), which another
guest's load does not stretch, never `Date.now()`; such a walk is far past
the bound either way. A wall-clock bound stays only where waiting is the
thing tested (a FIFO that must not stall a read, a client answered while a
scan runs), and then as a ratio of the same run's own durations where it
can (`upload-scan-op.test.ts`'s pacing). A wall-clock check that tells a
regression by its duration (a bounded wait the code must not take) runs
again once when it is slow, every other assertion included, and fails only
when the second run is slow too: the regression is slow on every run, load
on one now and then. A test that boots a daemon connects in a retry loop
until the daemon answers or exits, not on the socket file's existence.

Fixed: `dir-change-label-raise`, `twin-comment-credentials`, `path-glob`
and `why-preview` (CPU time); `policy-file`'s two boot tests (connect
until answered); `integration.codex-sandbox-call-binding`'s clean-call
speed (the 2 s fork-exec wait; 3.5 s once in 106 runs under load), once
more when slow.

### 8.11 A start that does not come up fails; a skip comes before it (2026-10-18)

**Why.** After the shared readiness budget
([`runtime-instances.md`](../architecture/runtime-instances.md) §14.6), the
live shell suites (`net-proxy-live`, `net-proxy-mitm-live`, `exec-wrap-live`,
`reply-filter-live`, `exec-box-live`, and the ones on `dev-arbiter.sh`:
`pipe-taint-live`, `derived-label-live`, `secret-readers-live`,
`wire-release-live`) still turned an arbiter that never came up into
`SKIP: arbiter sockets never appeared` and exit 0. A hung start showed
green on a host whose entry allows skips, and on CI only the entry's
`maxSkip` said otherwise. The kernel-lane tests `own-stores-hidden`,
`secret-bind-nesting` and `wsl-windows-secrets` kept a fixed 20 s wait of
their own.

**The rule.** A suite SKIPs only on a prerequisite it checks before it starts
anything: a missing tool, kernel feature, package install or loopback alias.
Once it has started a daemon, that daemon not coming up, or refusing the
setup calls the suite makes before its first assertion, is a FAILURE (exit
1), and the failure carries the daemon's log's last lines. Every wait for a
started daemon is a condition wait on the shared budget, ended at once by
the daemon's exit, never a fixed sleep.

Fixed: the shell suites above end their wait with `abort` (`mdu_ready_why`
and `mdu_log_tail`, `scripts/lib/ready-deadline.sh`); the `dev-arbiter.sh`
callers act on its exit status (it already waits for both sockets and
prints why with the log's tail) and no longer poll a second time; the three
kernel-lane tests use `waitForPaths` and `sourceArbiterArgs`
(`launcher/test/lib/arbiter-ready.ts`). `launcher.arbiter-start-fail` runs
each live suite with `MANDU_SERVICE_READY_TIMEOUT_MS=1` and requires exit 1,
the failure line and the log's tail; a sandbox suite whose prerequisite is
missing on the host is "not reached", but only when it skipped before its
start. The frozen copies under `launcher/test/integrity/` keep the old skip
(frozen lane, §6.8).

### 8.12 A launch refuses a checkout it cannot run (2026-10-18)

**Why.** A launch from source runs each Mandu service with its own
package's tsx (the launcher's dev layout). A service package without its
`node_modules` does not stop the launch: the service dies when it is first
spawned, and a check graded on what it did not do then passes. On
2026-10-04 the exec-wrap shim of a fresh worktree died at load
(`ERR_MODULE_NOT_FOUND`) on every curl, nothing reached the sink, and the
sink checks passed. The maintainers' drill runs refused that checkout
first; every other suite that launches the stack did not.

**The package preflight.** `withStack` (`tests/lib/launcher-live.ts`), the
harness every suite that launches the real stack goes through, first
checks that each package of a service the launcher spawns
(`launcher/bundle-manifest.json` `services`) has `node_modules/tsx`
(`tests/lib/stack-preflight.ts`). A missing one is a
`MissingStackPackagesError` before anything is created: it names the
calling lane, each missing package and its `node scripts/install-deps.mjs
<package>` line. `scripts/test-all.sh` and CI install every package, so
the check costs a manifest read and a dozen stats. A harness that runs a
plain side before the launch runs the same check before it, so the
refusal comes before either side.

**The tools a scripted command runs.** A scripted tool call names its
programs by bare name, and the host's PATH decides what runs. A program
the host cannot start fails both sides of a paired run alike, and the
checks then grade the broken tool. `tests/lib/host-runnable.ts` says, from
the file alone, which program a command line's command words resolve to
on PATH and whether the kernel can start it: an ELF for another CPU with
no binfmt_misc handler, an ELF whose loader (PT_INTERP) is missing, a `#!`
interpreter that does not exist or is not executable, `#!/usr/bin/env X`
with no `X` on PATH, through a `#!` chain. Builtins, relative paths and
names not on PATH are not judged. A program that starts and then fails
(an interpreter without the module its entry point imports) is beyond a
static look. The maintainers' scripted lanes refuse such a script by
name.

Tests: `tests/stack/stack-package-preflight.test.ts` (the decision on a
stub checkout; `withStack` refusing it before it creates a file, and
bringing the stack up once it is installed) and
`tests/stack/host-runnable.test.ts` (the decision on stub files; the real
files under bash: each one refused fails to start, each one passed runs).

## 9. Build order

All built:

1. `tests/suites.mjs` with every entry, `scripts/suites.mjs` (list, filter,
   JSON) and the completeness check, blocking from the start.
2. `scripts/test-all.sh` runs from the manifest; the scenario lists moved
   out of `package.json` into the manifest, and the npm script names stayed
   (what people type does not change): each `claude-e2e` cut's npm script is
   `node ../../scripts/suites.mjs run <id>`, which runs the entry's cmd in
   its cwd with its env and exits with its code.
3. §8.1, §8.2 and §8.4.
4. Decision 1 (§7.1).
5. Decision 2 (§7.2), the review static.
6. The dashboard runner and labels read the manifest; GitHub CI builds its
   matrix from it; `docs/testing/suites.md` is generated (§9.2).
7. The CI pipeline ([`continuous-integration.md`](continuous-integration.md)) runs
   the kinds: the per-push kinds per push, the nightly kinds with every
   flaky entry on a schedule, non-blocking.

Each step shipped with its tests and doc updates
([`CONTRIBUTING.md`](../../../CONTRIBUTING.md)).

### 9.1 As built: steps 1 and 2 (2026-09-28)

**Files.** `tests/suites.mjs` (the manifest), `scripts/suites.mjs` (`list`,
`packages`, `check`, `coverage`, `doc`, `run`; importable helpers),
`scripts/run-suites.mjs` (the runner), `scripts/test/suites-manifest.test.mjs`
(the check) and `scripts/test/run-suites.test.mjs`. `node scripts/suites.mjs
check` prints the current counts.

**The runner.**

```sh
node scripts/run-suites.mjs --kind <k,k> [--only <id,id>] [--jobs N] [--kernel-jobs N] [--sandbox <wrapper>]
    [--costs FILE] [--out DIR | --keep-results N|all [--keep-results-hours H]] [--run-id ID] [--source …] [--commit SHA] [--ref REF] [--image NAME]
    [--stages-json FILE] [--strict-skips] [--include-flaky] [--flaky-kinds <k,k>] [--include-internet] [--frozen]
    [--lane subscription|api-key] [--watch-store DIR] [--failures-only] [--fail-tail N] [--fail-fast]
    [--deadline EPOCH_S] [--heartbeat S] [--dry-run]
```

- `--only` selects exactly the named entries (`*` allowed), whatever their
  kind, `flaky`, `internet` or `idOnly` flag; without it, `--kind` selects,
  the flaky and internet entries stay out unless included, and `idOnly`
  ones always. A platform mismatch always excludes.
- **Order:** the parallel stage (up to `--jobs`, default 1), then the
  `parallel: false` entries one at a time, then the kernel lane (the kernel
  entries marked `parallel: true` up to `--kernel-jobs` at a time, then the
  others one at a time); each pool longest first. Under `--sandbox` the
  kernel entries share the parallel stage's slots instead (one queue, at
  most `--kernel-jobs` kernel entries at once, a non-parallel kernel entry
  alone; continuous-integration.md §5.4). "Longest first" reads the cost table
  `tests/suite-costs.json` (seconds by entry id, each entry's median over
  the last ten green full per-push runs; `node scripts/suites.mjs costs
  <runs dir>` regenerates it from a runs directory, `costs <summary.json>`
  from one run, and `costs --private` the source-only manifest's entries'
  table, which the runner merges in where it exists; the public table names
  only public entries, so it holds in the public snapshot). `--costs FILE`
  lays a measured table over both: the CI host's own medians, which
  `vm-run.sh` brings into the guest so the order never waits on anyone
  regenerating the checked-in tables (continuous-integration.md §5.4); an
  entry the file does not name keeps its table cost. An unknown
  entry costs 30 s, and `queueAs: <seconds>` overrides the table (the
  differential long session's real-config shard, kept out of the opening
  burst: test-reorganization.md §6.9). The table only orders the queue: a
  stale one never changes whether an entry runs or how it is judged.
  `parallel: "sandbox"` marks an entry with a §8.4 hazard not yet fixed: it
  runs in the parallel stage only under `--sandbox`, alone otherwise. A
  kernel entry never runs in the sandbox, so its `parallel` is a boolean.
- With `--sandbox`, every non-kernel entry runs as `<wrapper> --chdir <abs
  cwd> [--setenv K V]... -- <cmd…>`. Every entry gets `MANDU_AXES_STRICT=1`
  and the no-policy `MANDU_POLICY_FILE`, over its own `env`.
- Each entry is its own process group with its output in `logs/<id>.log` (a
  file, not a pipe, so a leftover daemon cannot hold the run open); the
  timeout sends SIGTERM to the group, SIGKILL 10 s later, and a normal exit
  sweeps the group too. Logs are capped at 5 MiB, tail kept.
- **A timeout names what hung.** node's runner prints each file's results
  in argument order, so a log that stops at file N does not say which file
  hung. Before the SIGTERM the runner reads `/proc` and appends a report:
  the entry's process tree (pid, age, argv) and the test files still
  running (node's runner spawns one child per file whose argv names it; a
  cargo test binary names its crate; an argument with whitespace, a
  `bash -c` command line, is never a file), plus a TAP subtest opened and never
  closed and libtest's "has been running for over" lines. The entry's
  `reason` becomes `timed out after Ns; still running: <file>`. The logic is
  `scripts/lib/timeout-report.mjs`; the dashboard's test runner uses a
  byte-identical copy (dashboard.md §4.10).
- **A run's deadline** (`--deadline EPOCH_S`, 2026-10-17; the CI guest's,
  continuous-integration.md §3): no entry starts after it, and an entry
  still running is stopped as at its own timeout (the same report, a
  `timeout` result whose reason names the deadline); the run is an `error`
  and still writes its summary and logs. An entry whose own timeout is past
  the caller's limit can no longer outlive the caller with nothing written.
  `--heartbeat S` prints every S seconds the entries still running with
  their ages and timeouts: an entry's lines come only when it ends, so a
  hung one is otherwise silent.
- Counts come from node:test footers (TAP or spec), cargo `test result:`
  lines (ignored tests and a kernel test's `SKIP:` line count as skips) or a
  shell `N passed, M failed` footer. `--strict-skips` fails an entry whose
  counts break its `ci: { maxSkip, minPass }`.
- `summary.json` follows `continuous-integration.md` §6 exactly (the dashboard's
  reader refuses unknown fields); the default run id is
  `local-<UTC yyyymmddThhmmssZ>-<short sha>`.
- **What it prints.** Each finished entry: its header, its verdict and, for
  a failure, the last `--fail-tail N` lines of its log (25 by default; 0
  names the log instead); then a summary of every row. `--failures-only`
  (2026-10-15) prints only what a reader must act on: no row for an entry
  that passed or skipped, each failure with a 40-line tail (unless
  `--fail-tail` says otherwise), the summary's failed rows, one counts line
  (`FAILURES PRESENT: 1 failed, 40 passed, 3 skipped of 44 entries (2
  excluded)`, or `ALL SUITES GREEN: …`) and the results directory. It is for
  a coding agent's session, whose context pays for every line: over fifteen
  days the sessions read about 1.07M tokens of `test-all.sh`, `vm-run.sh`
  and drill output and 357k more of log tails, and about 3% of those lines
  were failure lines. `summary.json`, `junit.xml`, the logs and the exit
  code are the same in both modes; the full output stays on disk.
- **The results dir** (2026-10-18). `--out DIR` (CI's pipeline, the
  public workflow, the dashboard's Tests tab) is used as given and nothing
  else is touched. Without it (`test-all.sh`'s default, every agent's
  `--failures-only` run) the run writes to a fresh `mandu-suites-XXXXXX`
  in its `TMPDIR`, which the last line names (`results: <dir> (…; the
  newest 5 such dirs and those of the last 6h kept, --keep-results)`), and
  nothing reads it later but whoever ran it. Such a run used to leave its
  dir behind (262 in a dev host's `/tmp`, §8.5.1); now, right after it
  makes its own, it prunes this user's older ones in that `TMPDIR`: a dir
  goes only when it is outside the newest N by mtime (`--keep-results N`,
  `MANDU_TEST_KEEP_RESULTS`; default 5, `all` keeps every one) **and**
  nothing in its tree changed within the grace period
  (`--keep-results-hours H`, `MANDU_TEST_KEEP_RESULTS_HOURS`; default 6,
  0 turns it off). The grace is for the parallel agent sessions of one
  user on one host (about ten at once): each runs `test-all.sh
  --failures-only` and then reads its full logs from the dir its summary
  named, and by N alone another session's run seconds later could prune
  a just-finished dir before its session read it. A dir is a candidate
  only when it is a real directory (not a symlink) named `mandu-suites-`
  plus six characters and owned by this uid; it stays, whatever N and the
  grace say, while its run is live: each holds
  `.run-suites-owner.json` (the runner's pid and its `/proc` start time),
  and a dir whose pid is alive with the same start time (any live pid
  where the start time cannot be read) is never removed. A dir with no
  owner file (a runner from before this change) is removed only when
  nothing in it changed for an hour (or the grace, if longer). A failure to prune is one stderr
  line, never a failed run. Tests: `scripts/test/run-suites.test.mjs`
  (`parseKeep`, `parseGraceHours`, `pruneResultsDirs` over a temp tree
  with a live, a reused-pid, an owner-less recent and an owner-less idle
  dir, N and `all`, another uid; the grace: a just-finished dead-owner dir
  beyond N kept, one past the grace removed, the tree's newest file
  counted; `main` without `--out` under a temp `TMPDIR`, the variables,
  `--out`, bad values).
- Exit 0 when every entry passed or skipped, 1 otherwise, 2 on a usage
  error.

**`scripts/test-all.sh`** installs missing `node_modules` (`npm ci` where
there is a lockfile in every package `suites.mjs packages` names), builds the
native bins when needed (§3), and runs the runner. Its default is
`unit,component,stack,sandbox`; the per-push default of the pipeline adds
`replay-drill` (in the maintainers' repository, where the drill entries
are), because a developer host is not expected to carry the pinned agent
CLIs. `--scope all|shipping` remain as aliases
(`MANDU_TEST_SCOPE`). `--integrity` adds the frozen entries whose needs are
all sealed (each package's `test:integrity`, the conformance corpus), not
the frozen lane's agent, model and drill entries. Each finished entry prints
the `▶ <id> (<cmd>)` header and a `✓ PASS` / `✗ FAIL` / `∅ SKIP` verdict
line, which the dashboard's parser reads. `--failures-only`
(`MANDU_TEST_FAILURES_ONLY=1`) and `--fail-tail N` (`MANDU_TEST_FAIL_TAIL`)
pass to the runner (above); test-all.sh removes the two variables from the
suites' environment, so a suite that runs `test-all.sh` or the runner itself
prints as it always did. `scripts/ci/vm-run.sh` has no such option and needs
none: it calls the runner in the guest (through `pipeline.sh`, not
`test-all.sh`), and what it prints on the host is the guest's last
`mandu-ci:` lines and the collector's report, which is already the counts
and only the failed entries with their log paths
(continuous-integration.md §3).

**The kernel Rust entry** (`rust.kernel`) runs `scripts/kernel-tests.sh
--include-ignored`: the same namespaces, `cargo test --features kernel --
--include-ignored` per crate, so the kernel-only tests run too. The script
echoes each crate's `test result:` and `SKIP:` lines so the runner counts
tests, not crates, and keeps each crate's full cargo log where `--log-dir
DIR` or `MANDU_KERNEL_TESTS_LOG_DIR` says (CI sets it to the run's
`logs/kernel-tests/`); `scripts/test/kernel-tests.test.sh` runs it against
stub `unshare` and `cargo`. `rust.check-aarch64` skips where the aarch64
target is not installed; the release job builds arm64 anyway (`packaging.md §11`).

### 9.2 As built: step 6 (2026-09-29)

Every reader in the §5 table reads the manifest.

**Sessions.** An optional entry field, `session: { cls, file, label }`: the
TEST-session class an entry's runs mint (ids `<cls>-<scenario>-<ms>`, titles
`<cls>[<scenario>]:`), the suite file declaring its `SCENARIOS` and the label
the dashboard shows. The check validates it (a `<name>-e2e` class unique
across entries, a file that exists and that the entry claims, a non-empty
label, no other key).

**`scripts/suites.mjs`, more commands.**

```sh
node scripts/suites.mjs list [...] --unsharded   # entries as declared: a sharded entry is one row
node scripts/suites.mjs list [...] --public      # the public manifest only
node scripts/suites.mjs doc [--check]            # write docs/testing/suites.md; --check exits 1 when stale
```

`check` also fails while `docs/testing/suites.md` is missing or stale, and
the manifest test compares the committed page with the renderer
(`renderSuitesDoc`), so the page cannot drift. The page is generated from the
public manifest only.

**Every line of the page depends on one entry.** The page carries no counts
(`suites.mjs check` and `list` print them), rows are sorted by id within a
kind, and every kind keeps its heading and table even when empty. A row is a
function of its entry alone, so a three-way merge of two branches' pages is
the page of the merged manifest whenever it is clean: two branches that each
add, drop or change different entries can no longer leave the main branch
with a stale page and a red check, as count lines once did. The manifest
test pins this with `git merge-file` over rendered pages. Rejected: a merge
driver that regenerates the page (it runs only in local clients, never in a
forge's server-side merge); building the page in CI instead of checking it
in (the page would vanish from the repository browser); ignoring count lines
in the equality test (stale counts on the main branch). Residual: two new
ids adjacent in one kind still conflict, which is a rebase conflict
(regenerate with `node scripts/suites.mjs doc`, never hand-merge), not a red
main branch.

**The dashboard runner** (dashboard.md §4.10 "The suite manifest") offers
every entry, grouped by kind, read through `list --json --unsharded
--platform <platform>` in a child process (`dashboard/src/test-runs/
suite-manifest.ts`, cached on the manifest files' mtimes). An entry runs as
the manifest declares it, whole, with `MANDU_TEST_DASHBOARD=1` when it
declares a `session`. Two batches stay: `e2e` (the ungated `session`
entries' files in one process) and `all` (test-all.sh's default). The session
class and label come from the entry; the built-in copies the synchronous
paths and the npm-published bundle use are kept equal to the manifest by a
dashboard unit test. The bundle ships no manifest: the runner says "the
suite list needs a source checkout" and offers only the batches.

**GitHub CI** ([`continuous-integration.md §12`](continuous-integration.md)). A `shell` job runs
`node scripts/suites.mjs list --kind unit,component,stack --platform linux
--json --public`, keeps the entries whose command is `bash` or `node` and
that do not need cargo, and runs them all with
`node scripts/run-suites.mjs --only <ids>`.

### 9.3 As built: tiers become kinds (2026-10-01)

The first step of the move from tiers to kinds. Words and
fields only: no suite moved, and CI runs the same set in the same lanes.

| Before | After |
|---|---|
| entry field `tier` | `kind` (§3) |
| tier `offline` | `unit`, `component` or `stack` by what is real; `tls-compat` is `env` |
| tier `agent-fake` | `replay-drill` |
| tier `kernel` | `sandbox`, plus the need `kernel`; `launcher-kernel-tier` is a `replay-drill` with the `kernel` need |
| tiers `local-model`, `real-model`, `drill` | `env`, `live-drill` or `eval` by what is real |
| tier `frozen` | the entry's own kind plus `frozen: true` |
| `lane: "subscription" \| "api"` | `credential: "subscription" \| "api-key"` |
| `byHand` | `manual` |
| `--tier`, `--flaky-tiers` | `--kind`, `--flaky-kinds` |
| `--tier frozen` | `run-suites.mjs --frozen`; `scripts/test-all.sh --integrity` as before |
| `--lane api` | `--lane api-key` |
| results key `tier` (`summary.json`, JUnit) | `kind` |

The kernel lane, which the old `kernel` tier defined, is now the per-push
entries that need `kernel`. `scripts/test-all.sh` defaults to
`unit,component,stack,sandbox`; the pipeline and `vm-run.sh` default to all
five per-push kinds. Old ids, fields and flags are not kept as aliases
(test-reorganization.md §4); a retired flag such as `--tier` is a usage
error.

### 9.4 As built: package `test/e2e/` becomes `test/component/` (2026-10-02)

The first move of the package test-directory step. Every package's
`test/e2e/` moved to `test/component/`
(arbiter, dashboard, fs-sync, launcher, and the TS interceptors), keeping
its depth, so no relative import changed. Each package's `test` and
`test:component` scripts glob `test/component/*.test.ts`; the launcher's
shards are `launcher.component1` to `launcher.component3` and
`launcher.component-native-multiarch-bundle`. Eval's live smoke is
`eval/live/run-live.eval.test.ts` (a `*.live.test.ts` file takes its kind's
name, test-reorganization.md §4). `tests/integration` moved in its own
changes (stack, sandbox, drills, env; test-reorganization.md §5.3).

## 10. Open items

None open. Two settled questions, kept because other notes cite them:

- **Where the nightly kinds run** and how a nightly real-model run gets its
  login: `continuous-integration.md` §9, a scheduled job in a networked guest
  with a reduced, read-only credential and a canary that withholds any log
  or artifact holding it. The only automatic run that holds a credential.
- **Flaky budget** (`flakyBudget`, `scripts/suites.mjs`): each `flaky` entry
  carries `revisit` (the date it is next looked at) and `revisits` (how many
  it has had). `check` fails an entry without a revisit date or with
  `revisits` at 2 (a flag that outlives two revisits is a bug to fix or a
  suite to delete). A revisit date in the past is only a `note:` line: an
  unrelated push must not fail because a date passed. At a revisit, fix the
  suite and drop the flag, or bump `revisits` and set the next date.


### Fixture-home dry-run reports

The fixture-home suites compare `doctor --secrets --json` with the actual
launch's file inventory, coverage ledger and verdict. Their shared test helper
(`tests/lib/doctor-secrets-report.ts`) reads a JSON object from the launcher's
stdout and diagnostics without depending on property order: `platform` may
precede `roots`. It requires the inventory, ledger and boolean launch verdict,
so an absent or malformed report still fails the fixture oracle. The offline
regressions in `tests/stack/doctor-secrets-report.test.ts` cover both property
orders, compact and pretty JSON, surrounding diagnostics, nested objects,
escaped quotes and structurally incomplete reports. The existing frozen
integrity fixture uses the same parser as compatibility maintenance.
