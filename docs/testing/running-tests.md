# Running the tests

How to run Mandu's test suites: on your machine, in the CI guest, and the
credential lanes. The suite list itself is [suites.md](suites.md) (generated
from the manifest `tests/suites.mjs`); why the suites are organized this
way is [test-organization.md](../design/testing/test-organization.md); the CI side
is [continuous-integration.md](../design/testing/continuous-integration.md).

Two entry points run the same manifest:

| Command | Where it runs | Use it for |
|---|---|---|
| `scripts/test-all.sh` | your machine, unsandboxed | the quick loop; the credential lanes |
| `scripts/ci/vm-run.sh` | a throwaway KVM guest, each suite in its own sandbox | exactly what CI runs |

`scripts/test-all.sh` installs any missing `node_modules`, builds the native
bins when a selected suite needs them, runs the suites and prints one
PASS / FAIL / SKIP row per suite and a summary. `--dry-run` shows what would
run, and why each left-out suite is left out, without running anything.

## 1. The kinds

Every suite has one kind: what is real in it
([test-organization.md §3](../design/testing/test-organization.md)). The default
run (`scripts/test-all.sh` with no options) is `unit`, `component`, `stack`
and `sandbox`, which need no agent, model or VM.

| Kind | What is real | Spends | In CI |
|---|---|---|---|
| `unit` | one function or module | nothing | every push, blocking |
| `component` | one Mandu package through its socket, server or CLI | nothing | every push, blocking |
| `stack` | several Mandu packages wired together, no agent | nothing | every push, blocking |
| `replay-drill` | an agent CLI (`claude`, `codex`, `openclaw`, `opencode`) against a scripted model | nothing | every push, blocking (maintainers' repository only) |
| `sandbox` | the real sandbox: user namespaces, bwrap, Landlock, seccomp | nothing | every push, blocking |
| `live-drill` | an agent CLI with a real model | an agent login or an API key | nightly (maintainers' repository only) |
| `env` | whatever the host provides: a local Ollama, a login, the internet | varies | nightly |
| `eval` | a feature's model output, scored | an agent login or an API key | nightly or by hand |
| `install` | a real install in a VM (`/dev/kvm`, the network) | nothing | release tags |

The two drill kinds, `replay-drill` and `live-drill`, run only in the
maintainers' source repository. The agent drills are the maintainers'
evidence tooling and are not published; this tree holds no drill entries
except the frozen integrity ones. What the drills show is in
[drill-results.md](drill-results.md), and each claim in
[guarantees.md](../guarantees.md) names a public test you can run. To get
access to the drills, for research for example, write to
hello@mandusecurity.com.

A suite of any kind marked `frozen` switches the frozen integrity axis on.
It runs only when the axis is revived (`--integrity` adds the ones that need
no agent or model).

A suite that needs `kernel` skips (with the reason in its row) where the
host refuses unprivileged user namespaces; `--strict-skips` turns such a
skip into a failure.

Every suite runs with a fresh, empty `TMPDIR` of its own, and a suite that
leaves files there fails, naming them (`left 2 entries (40 inodes) in its
TMPDIR: …`), as does one that leaves a process running outside its process
group (a `setsid` daemon, killed and named); `--tmp-leftovers warn` only
reports them. New files a suite leaves in `/tmp`, `$HOME` or your runtime
dir show as a `⚠ OUTSIDE` warning
([`design/test-organization.md`](../design/testing/test-organization.md) §8.5).

## 2. Everyday runs

```sh
scripts/test-all.sh                          # unit + component + stack + sandbox
scripts/test-all.sh --kind unit --jobs 8     # one kind, 8 parallel-safe suites at a time
scripts/test-all.sh --only launcher,rust     # named suites ('*' allowed), whatever their kind
scripts/test-all.sh --fail-fast              # stop starting suites after the first failure
scripts/test-all.sh --out ./test-out         # keep summary.json, junit.xml and logs/
scripts/test-all.sh --failures-only          # only the failed suites, each with its log's last 40 lines
                                             #   (--fail-tail N), and a counts line; MANDU_TEST_FAILURES_ONLY=1
scripts/test-all.sh --scope shipping         # = --kind unit,component,stack (--scope all = the default;
                                             #   MANDU_TEST_SCOPE; the Docker path's commands, design/testing/docker-e2e.md §1)
node scripts/suites.mjs list                 # every suite id, by kind
```

One test file or one test by name, inside a package:

```sh
cd arbiter && npx tsx --test test/unit/secret-egress.test.ts
cd arbiter && npx tsx --test --test-name-pattern="symbolize" test/unit/*.test.ts
cd interceptors && cargo test -p fs-supervisor decide_open
```

`npm test` in a package uses `tsx`, which does not type-check; run `npm run
typecheck` too.

## 3. The credential lanes

The suites that spend a model budget are split by the credential each one
uses, named in the manifest's `credential` field
([continuous-integration.md §9.8](../design/testing/continuous-integration.md)):

| Lane | Credential | Runs |
|---|---|---|
| `subscription` | your Claude login; optionally a Codex ChatGPT sign-in; a local Ollama | the Claude real-model suites, the Ollama suites; in the maintainers' repository also the drills and Codex on a ChatGPT sign-in |
| `api-key` | vendor API keys (Anthropic, OpenAI) | in the maintainers' repository: the agent drills on a key (`openclaw-headless`, `opencode-headless`, `codex-headless.openai-key`, `codex-headless.policy.openai-key`); none in this tree |

`--lane` runs one lane. Without `--kind` it selects the `live-drill`, `env`
and `eval` kinds plus every flaky suite of the lane (`--include-internet`
adds the suites that reach the public internet). In this tree that is the
`env` suites; the drill suites named in the table, and in the notes below
(`openclaw-headless`, `opencode-headless`, the Codex end-to-end suites), are the maintainers'
(section 1).

```sh
scripts/test-all.sh --lane subscription --dry-run    # what it would run
scripts/test-all.sh --lane subscription              # on your agent's own login
MANDU_CI_CODEX_AUTH=~/.codex/auth.json scripts/test-all.sh --lane subscription
                                                     # plus Codex on your ChatGPT sign-in
scripts/test-all.sh --lane api-key                   # on your API keys
```

**One lane's credentials per run.** Several suites switch to an API key when
one is present, so a subscription run that still held a key could pass on
the wrong credential:

- `--lane subscription` removes `ANTHROPIC_API_KEY`,
  `MANDU_E2E_ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `CODEX_API_KEY` and
  `MANDU_ULLM_API_KEY` from the run's environment and prints one line naming
  what it removed (names only, never values).
- The Codex ChatGPT-sign-in suites run only when `MANDU_CI_CODEX_AUTH` names
  a Codex `auth.json`; otherwise they skip with a one-line hint. Pointing it
  at your own `~/.codex/auth.json` is safe: each run gives Codex a copy with
  the refresh token blanked, so it can neither refresh nor sign you out.
- `--lane api-key` loads the keys from the secrets file (`scripts/mandu-env.sh`,
  [continuous-integration.md §13](../design/testing/continuous-integration.md)) when they are not already set, and
  removes `CLAUDE_CODE_OAUTH_TOKEN` and `MANDU_CI_CODEX_AUTH`. A suite whose
  key is missing skips.
- **A lane brings its stack up:** a `secrets`-mode arbiter of the test tenant
  with the drill policy, and `MANDU_BIN` and `MANDU_TEST_DASHBOARD=1` for the
  suites (without them the Claude and Codex end-to-end suites skip, and the
  run looks greener than it is). It stops when the run ends, `^C` included;
  one a killed run left behind is collected by `mandu reap`. If the arbiter
  does not start, the run stops (exit 5); `--no-lane-stack` runs the lane
  without it.
- Outside the CI guest your `~/.claude` login stays visible, so in
  `--lane api-key` the quarantined read of one `openclaw-headless` /
  `opencode-headless` scenario (inspect-extract) uses it, where the CI guest skips that scenario.

## 4. Choosing agents

`--agents` keeps a suite only when every agent it needs is in the list
(`claude`, `codex`, `openclaw`, `opencode`). A suite needs an agent through
its CLI or its login: a Claude login counts as `claude`, a ChatGPT sign-in
as `codex`. A suite that drives no agent always stays.

```sh
scripts/test-all.sh --lane subscription --agents codex    # Codex suites (and no-agent ones)
```

`test-all.sh` also takes `--drills` and `--watch-store`, which narrow and
record the agent drills. In this tree they select nothing: the drills are
the maintainers' and are not published (section 1).

## 5. Exactly what CI runs

```sh
scripts/ci/vm-run.sh                              # the five per-push kinds on HEAD, in the CI image
scripts/ci/vm-run.sh --worktree --only arbiter    # your uncommitted tree, one suite
scripts/ci/vm-run.sh --commit <sha> --only <id>   # reproduce a CI failure on the image CI used
scripts/ci/vm-run.sh --shell                      # a shell in the guest, nothing runs
```

`scripts/ci/nightly.sh --lane subscription|api-key` runs a credential lane
in the same guest. The maintainers' CI runs the subscription lane nightly,
and its failures never block a merge; the api-key lane has no scheduled job
(no vendor API key is installed on a runner) and is run by hand.

**Without KVM,** `scripts/ci/pipeline.sh --host` runs the same stages on the
host, each suite in `scripts/ci/ns-run.sh`'s sandbox. One difference to know:
on Ubuntu 26.04 (AppArmor's `bwrap-userns-restrict`), a bubblewrap cannot
start inside ns-run's, so Mandu's git sandbox is off in those suites and its
tests SKIP; ns-run prints a note saying so at the top of each suite's log.
The CI guest runs them. So does such a host once `mandu setup` has installed
Mandu's own bubblewrap, which ns-run then picks. `scripts/ci/ns-run.sh
--check` shows which bubblewrap it would use and whether one nests in it
([continuous-integration.md §5.6](../design/testing/continuous-integration.md)).

## 7. Results

Each run prints where it kept its results: `summary.json`, `junit.xml`, and
one log per suite under `logs/`. A CI job keeps them in its `ci-out/`
artifact. The live suites also record their sessions, which the
dashboard's Testing section shows.

A suite that runs past its `timeout` is reported as `timeout: timed out after
Ns; still running: <file>`. Its log ends with a report the runner wrote at the
deadline, before it killed the suite: every process the suite still had (pid,
age, argv, indented as a tree) and the test files still running. For a node
suite that is the file that hung, even when the TAP stopped at an earlier
file. For a cargo suite it is the test binary. A shell suite gets the process
list only (`docs/design/testing/test-organization.md` §5). A suite run from the
dashboard's Tests drawer gets the same report in its streamed log, and the
reason shows under the run's row.

Exit codes: 0 all green, 1 a suite failed, 2 a usage error, 3 the userns gate
(`MANDU_CI_REQUIRE_USERNS=1`), 4 the native build failed.
