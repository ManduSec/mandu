# Developing Mandu

This guide is for people who build, test or change Mandu. If you only want to
use it, start with [Getting started](getting-started.md). The rules every
change follows (tests, the design-doc update, the invariants) and the legal
side of contributing are in [`CONTRIBUTING.md`](../CONTRIBUTING.md).

Contents:

1. [Build from source](#1-build-from-source)
2. [Repository layout](#2-repository-layout)
3. [The packages](#3-the-packages)
4. [Run the stack by hand](#4-run-the-stack-by-hand)
5. [Run the stack from the dashboard](#5-run-the-stack-from-the-dashboard)
6. [Tests](#6-tests)
7. [Status of the kernel layer](#7-status-of-the-kernel-layer)
8. [Where the design lives](#8-where-the-design-lives)

## 1. Build from source

You need Node 22.13.0 or newer, git and, for the native pieces, a Rust
toolchain (stable).

```sh
git clone https://github.com/mandusec/mandu.git && cd mandu
scripts/bootstrap.sh          # installs every package's deps, typechecks, builds the launcher
                              #   bundle, puts `mandu` on PATH
scripts/build-native.sh       # the native helpers: mandu-exec-box, mandu-landlock-apply, mandu-net-guard
mandu doctor                  # confirm what this host supports
```

`scripts/bootstrap.sh` is pure JavaScript (no native Node modules; the symbol
table uses `node:sqlite`). The native helpers are Rust binaries built with the
`kernel` cargo feature. A plain `cargo build` skips them silently
(`required-features = ["kernel"]`), and the launcher keeps using whatever older
binary it finds, so always rebuild them with `scripts/build-native.sh`.
It also records what each bin was built from (`<bin>.provenance.json`), and a
git worktree of the checkout with no bins of its own uses the main checkout's
bins only when that record matches the worktree's native sources byte for
byte; otherwise its launches run gated (no file guard) and say so, with the
hint to run `scripts/build-native.sh` in the worktree
(`docs/design/distribution/packaging.md` §5.2). A gated launch also makes
every other launch rebuild its sanitized git history while it runs, and
their banner names it.

There is no root `package.json` or workspace: each TypeScript package installs
and tests on its own, and the Rust crates share one Cargo workspace under
`interceptors/`.

The `mandu` on PATH (and `launcher/mandu-run.sh`, which it runs) starts the
checkout's prebuilt bundle, `launcher/dist`, while it matches the source: the
launcher and every service it starts then skip the TypeScript transpile, which
saves several seconds a launch. When a source file the bundle was built from
changes, the next launch rebuilds it first (about half a second), so there is
no build step to remember; if it cannot be rebuilt, the launch runs from source
through tsx and says so. `MANDU_FROM_SOURCE=1 mandu claude` always runs from
source (the launcher and its services through tsx). How the bundle is judged
fresh: [`design/distribution/packaging.md`](design/distribution/packaging.md)
§5.1.

API keys are not needed to run an agent (Mandu relays the agent's own login).
They are needed for real-model evaluation and some live suites, run by hand
and rarely (they cost tokens; never in CI): `node scripts/set-api-key.mjs`
asks for a key (no echo), checks it and saves it in `~/.mandu/secrets.json`;
or put them in a gitignored `secrets.local.json` (`cp secrets.example.json
secrets.local.json`). Then `source scripts/mandu-env.sh`. The full matrix of which key serves what:
[`design/testing/continuous-integration.md §13`](design/testing/continuous-integration.md).

## 2. Repository layout

```
arbiter/  fs-sync/  interceptors/  launcher/  dashboard/   the product: what ships
tests/   eval/                                          verification: cross-component e2e, sandbox, conformance, eval
packaging/{docker,homebrew}/   clients/python/            distribution: containers, Homebrew formula, the Python client
docs/  scripts/                                           design docs, user docs, dev and CI scripts
```

## 3. The packages

Mandu has one decision point and several enforcement points. The **arbiter**
decides; every other package enforces at one of the four chokepoints (model
context, network, filesystem, exec) and asks the arbiter over a Unix socket.
[How Mandu works](how-it-works.md) explains the model in plain language;
[`design/architecture/mandu.md`](design/architecture/mandu.md) §4 is the full mapping.

| Package | Lang | Chokepoint | What it is |
|---|---|---|---|
| `arbiter/` | TS | (hub) | The daemon every interceptor talks to over Unix-socket NDJSON IPC. Sole owner of the symbol table (SQLite, single writer), the policy engine (data trust, data usage, exec classification, secret labels) and the event store. Entry: `arbiter/ipc/server.ts`. |
| `launcher/` | TS | (wiring) | The `mandu` command. Starts or finds the arbiter and proxies, puts the agent in a cgroup v2 scope, wires the environment, the MCP servers and every protection layer (each on by default where the host supports it, each with a `--no-<name>` switch). Entry: `bin/mandu.mjs` → `src/run.ts`. |
| `interceptors/anthropic-proxy/` | TS | model context | Reverse proxy for the Anthropic Messages API (`ANTHROPIC_BASE_URL`), used by Claude Code, OpenCode, OpenClaw and Goose (`ANTHROPIC_HOST`). Replaces untrusted and secret spans in `tool_result`s with symbols, injects the handling prompt, records `tool_use` decisions, maps paths between the two views and gates sensitive paths. Fail-closed. |
| `interceptors/openai-proxy/` | TS | model context | The same for Codex (OpenAI Responses API): symbolizes `function_call_output` spans, maps the shell command into the AgentView. Fail-closed. |
| `interceptors/inspect-mcp/` | TS | model context | The quarantined model channel (paper: U-LLM): an MCP server exposing `inspect_symbol`, which resolves a symbol, asks a model that has no access to the agent's context, and returns the answer re-symbolized. |
| `interceptors/openclaw-inspect-plugin/` | TS | model context | The same `inspect_symbol` and `declassify_symbol` mounted as OpenClaw plugin tools (OpenClaw has no MCP client). |
| `interceptors/policy-mcp/` | TS | (policy) | MCP server that lets the agent read and test the policy and propose changes. Tightening applies at once; loosening waits for the user on the dashboard's Approvals page. |
| `interceptors/net-proxy/` | TS | network | Forward HTTP(S) proxy. Blocks or holds a request that carries an untrusted symbol to an untrusted destination, and puts a secret's real value back only on its way to a host it is bound to (TLS inspection with a per-session CA in `secrets` and `full`). Fail-closed. |
| `interceptors/cdp-relay/` | TS | (browser) | Relay on the DevTools connection between a browser agent and Chrome. What Chrome sends the agent passes the prompt filter (secrets become placeholders); a placeholder the agent types is put back only into a page whose origin may have it. Screenshots refused. Fail-closed. Not yet started by `mandu` (devtools-relay.md). |
| `interceptors/exec-wrap/` | TS | exec | `PATH` wrapper for high-risk commands (`curl`, `wget`, `nc`): refuses a command built from an untrusted symbol, otherwise runs the real binary with the resolved arguments. |
| `interceptors/reply-filter/` | TS | (user replies) | Resolves symbols in what the agent shows you, so you see the real values. Interactive TUIs are relayed through a PTY. Utility only: on any failure it passes text through unchanged (symbols stay opaque, nothing leaks). |
| `fs-sync/` | TS | filesystem | The two-view workspace: a git worktree the agent works in (AgentView) synced with your real folder (HumanView), with blame-based re-symbolization and revert. |
| `dashboard/` | TS | (UI) | The product page at `/`: protection status, Approvals, Rules, Settings, and each session's page (what the AI saw beside what really happened). Also a localhost control plane that starts the stack. The maintainers' developer view is not part of this tree (it loads into the same server where a build carries it). |
| `interceptors/` (Cargo workspace) | Rust | fs, net, exec | `exec-supervisor` (the Bubblewrap command box + seccomp + Landlock), `net-supervisor` (the seccomp connect guard and secret-file twins), `fs-supervisor` (seccomp `openat` interposition + Landlock), the retired `fs-preload` rung (in-tree, wired to nothing), the `mandu-arbiter` client crate (Apache-2.0) and `mandu-paths`, the generated copy of the path table (`scripts/paths/mandu-paths.mjs`, on-disk-layout.md §5). Decision logic is privilege-free and unit-tested; kernel attachment sits behind each crate's `kernel` feature. |
| `tests/` | TS | all | One npm package for the cross-package suites (`tests/package.json`): `tests/stack/` (the real arbiter, proxies, MCP servers and dashboard in one process, asserting the security invariant end to end), `tests/sandbox/` (the real sandbox, no agent), `tests/integrity/` (the frozen lane's copies), `tests/lib/` and `tests/fixtures/` (shared by them all: the scripted model endpoints, the launcher and child-process drivers, the agent provisioning and the confidentiality oracles), and `tests/env/` (suites that need something from the host: a local model, a login, the internet). The agent drills are the maintainers' and are not published ([drill-results.md](testing/drill-results.md)). |
| `tests/conformance/` | TS | all | Declarative scenarios (`scenarios/*.yaml`) run against the real arbiter and proxy with a mock upstream. Deterministic: no key, no network. |
| `eval/` | TS, Py | all | Red-team and benign evaluation: a deterministic backend (attack corpus, attack success rate with and without Mandu), a live backend (a real agent session) and an AgentDojo backend. |

### Conventions worth knowing before you change code

- **Interceptors never open the symbol database.** A TS package that talks to
  the arbiter defines a narrow `Arbiter` interface, an adapter over
  `arbiter/ipc/client.ts` and a mock for its tests, plus a parity test that
  builds the production wiring over a real `ArbiterServer`
  (`interceptors/anthropic-proxy/src/arbiter-client.ts` is the model).
- **Fail closed.** If the arbiter cannot be reached, an interceptor blocks,
  keeps the value symbolic or refuses the launch. Only the reply filter
  degrades to passthrough, because passing a symbol through leaks nothing.
- **Every test states its protection axes.** The built-in default mode
  (`secrets`) has the integrity axis off, so a suite that forgets to set it
  could pass for the wrong reason. `npm test` runs with `MANDU_AXES_STRICT=1`,
  which turns an unstated axis into an error. Stating `injection` or `full`
  (`stateAxes()` / `axesEnv()`) also sets the frozen axis's opt-in.
- **No test reads your own `policy.yaml`.** `npm test` (and
  `scripts/test-all.sh`) set `MANDU_POLICY_FILE` to a path that cannot
  exist, so every daemon a suite starts runs on the built-ins unless the
  test writes its own policy file and names it.
- **No test touches your Mandu home.** The same scripts pin
  `MANDU_HOME=/dev/null/mandu-test-home`, so a test that forgets to give
  itself a temporary home (and `MANDU_RUNTIME_DIR`) fails at its first write
  instead of reaching `~/.mandu`.
- **Every path comes from the path table.** Where Mandu keeps a file is one
  table, [`scripts/paths/mandu-paths.mjs`](../scripts/paths/mandu-paths.mjs);
  each package holds a generated copy (`node scripts/paths/mandu-paths.mjs
  generate`, and `check` fails on a stale one). Ask the table by entry name
  instead of spelling a path; `mandu paths` prints every location
  ([`design/architecture/on-disk-layout.md`](design/architecture/on-disk-layout.md) §5).
- **Every list of agents comes from the agent registry.** The agents the
  test tooling drives are one table,
  [`scripts/agents/agent-registry.mjs`](../scripts/agents/agent-registry.mjs);
  a list of agents in the suite manifests, the runner, the test harness,
  the dashboard, the launcher or the arbiter is that table or a named
  filter over it, and a standalone package holds a generated copy (`node scripts/agents/agent-copies.mjs
  generate`). `tests/stack/agent-registry.test.ts` fails on a hand-copied
  list ([`design/agents/supported-agents.md`](design/agents/supported-agents.md) §5.7).
- **No host root.** Every kernel mechanism Mandu uses attaches without host
  root (user namespaces, seccomp, Landlock, capability dropping), is on by
  default where the kernel supports it, and is skipped with a warning where it
  does not. Mechanisms that need host root or change global host state are out
  of scope by decision ([`design/architecture/privilege-model.md`](design/architecture/privilege-model.md) §0).

## 4. Run the stack by hand

`mandu` starts everything it needs, so this section is for debugging one
piece at a time.

```sh
mandu claude                       # the normal way: the launcher starts the arbiter and proxies
mandu --verbose claude             # print every protection layer as it comes up
mandu log                          # what the last launch said in full (its helpers' messages too)
scripts/dev-arbiter.sh             # an isolated arbiter for experiments (own DB and events;
                                   #   cleaned up by `mandu reap` when your session ends)
scripts/dev-arbiter.sh stop <work> # stop it now: its whole process group, waiting for it
                                   #   (the arbiter is one node process: the checkout's fresh
                                   #   bundle, else the source; MANDU_FROM_SOURCE=1 forces it)
MANDU_MODE=off scripts/dev-arbiter.sh
MANDU_EXPERIMENTAL_INTEGRITY=1 MANDU_MODE=full scripts/dev-arbiter.sh   # a frozen mode needs the opt-in
```

Do not start an arbiter with `setsid npx tsx … &`: that process chain cannot
be killed cleanly. Use `scripts/dev-arbiter.sh`, and `mandu reap --dry-run`
then `mandu reap` to clear stale stacks. The same pair stops a qemu guest a
killed VM test run left behind (`scripts/ci/vm-run.sh`, `scripts/matrix/run.sh`)
and removes its disks: every harness registers its guests
([`design/testing/os-test-matrix.md §10`](design/testing/os-test-matrix.md) §17.3).

Individual services, pointed at a running arbiter (by hand, `npm run serve`
still works; the launcher itself starts each one as a single node process):

```sh
cd interceptors/anthropic-proxy && MANDU_ARBITER_SOCK=… npm run serve
cd dashboard && MANDU_ARBITER_SOCK=… npm run serve     # http://127.0.0.1:4500/mandu/
```

### The launcher's environment contract

The launcher sets these for the agent and the interceptors:

| Variable | Meaning |
|---|---|
| `MANDU_SCOPE_ID` | The session id: the arbiter's session key and the dashboard's session name. |
| `MANDU_ARBITER_SOCK` | The arbiter's Unix socket. |
| `ANTHROPIC_BASE_URL` | Points the agent at the model proxy (unless you set it yourself to an undeclared endpoint, below). |
| `MANDU_UPSTREAM` | Set for the model proxy when the main model is a declared `models:` entry: that entry's `url` (unset, the proxy's upstream is the vendor; [`design/confidentiality/model-endpoints.md §1`](design/confidentiality/model-endpoints.md) §7.1, §7.2). |
| `MANDU_UPSTREAM_LOCAL` | `1` when that main model is declared `local: true`: the proxy then refuses a request for a cloud-backed model with a 400 before sending anything. |
| `MANDU_UPSTREAM_IS_BASE_URL` | `1` for a Codex main model: the openai-proxy maps Codex's `/v1/…` paths onto the declared base URL instead of appending them. |
| `MANDU_MODEL_PROXY_URL` | Set in the helper's (`inspect-mcp`) environment: the session's model-proxy origins, comma-separated. The helper refuses to send to any of them, so a `models:` entry pointing at the proxy cannot loop a `local-model` file back to the vendor. |

It honours these when set: `MANDU_HOME` (the one Mandu home; nothing in it
has its own override, [`design/architecture/on-disk-layout.md`](design/architecture/on-disk-layout.md) §9), `MANDU_ARBITER_SOCK`,
`ANTHROPIC_BASE_URL`, `MANDU_OPENAI_BASE_URL` (Codex's model base URL),
`MANDU_PROXY_HOST` / `MANDU_PROXY_PORT`, `MANDU_NO_ARBITER_AUTOSTART`,
`MANDU_ULLM_API_KEY` (or `ANTHROPIC_API_KEY`), `MANDU_ULLM_BASE_URL`,
`MANDU_ULLM_MODEL`, `MANDU_ULLM_ENDPOINT_TIMEOUT_MS` (the per-call wait for a
declared `models:` endpoint, in milliseconds; default 60000, at most
600000), `MANDU_MCP_CONFIG`, `MANDU_KEEP_SCOPE_DIR` (`1` keeps the launch's
scope dir after a clean exit, which otherwise removes it;
[`design/architecture/runtime-instances.md`](design/architecture/runtime-instances.md) §10.1).

**Which model each channel talks to** (plan 11 D2, D5, §7.1, §7.2). The
quarantined helper's default channel talks to the vendor (through the
launcher's forwarder where the launcher runs one), never through the
agent's model proxy. A call whose input is a `local-model`
symbol goes instead, directly over loopback or the network, to the first
`local: true` entry of `policy.yaml` `models:`; it is refused, never
rerouted, when none is declared or the declared one does not answer. The
agent's own main model is the vendor unless `ANTHROPIC_BASE_URL` (Claude
Code, `wire: anthropic`) or `MANDU_OPENAI_BASE_URL` (Codex,
`wire: openai-chat`) equals a declared entry's `url`; then the model proxy
stays in front of it with that `url` as `MANDU_UPSTREAM`, and the launcher
binds the session to the entry with the arbiter before any service starts.
A user-set base URL that matches no entry skips the model proxy, with a
`WARNING` at launch and a `mandu doctor` row.

Where `systemd-run` is missing, the agent runs without a cgroup scope and the
launcher says so; the other protections are unaffected.

Every protection layer and its switch (flag, `MANDU_*` variable, config key)
is listed in the user guide under
[Turning things on and off](usage.md#turning-things-on-and-off). The design
for each: network and TLS inspection in [`design/confidentiality/confidentiality.md`](design/confidentiality/confidentiality.md)
and [`design/confidentiality/confidentiality-plan-13-reader-set-labels.md §10`](design/confidentiality/confidentiality-plan-13-reader-set-labels.md); the command
box and Landlock in [`design/integrity/exec-routing.md`](design/integrity/exec-routing.md) §7; the
reply filter in [`design/ui/reply-row-reservation.md §15`](design/ui/reply-row-reservation.md);
the portable posture (`--no-kernel`) in [`design/distribution/portable-wrapper.md`](design/distribution/portable-wrapper.md).

## 5. Run the stack from the dashboard

The dashboard can supervise the arbiter and proxies, so
the whole stack runs from one place:

```sh
cd dashboard && npm run serve       # http://127.0.0.1:4500/mandu/      the product page
```

On boot it starts the arbiter and the model proxies (`DASHBOARD_AUTOSTART=0`
opts out). Each session has its page (Home lists the recent ones): what the AI
saw beside what really happened, step by step, and where each secret went.
**Settings** starts and restarts each service. The
control plane is on by default (`DASHBOARD_CONTROL=0` turns it off), binds
localhost only and requires the `X-Mandu-Control` header on mutating calls.

The dashboard binds loopback only. Exposing it on a network (a bind address,
an allow-list and an authenticator are all required, or it refuses to start)
is described in the user guide:
[The dashboard on the network](usage.md#the-dashboard-on-the-network). Behind
nginx, keep the `/mandu` prefix (`proxy_pass http://<host>:4500;` with no
trailing path), redirect `/mandu` to `/mandu/`, and turn `proxy_buffering`
off for the `/mandu/api/stream` SSE endpoint.

**The tour's screenshots.** `node scripts/tour-screenshots.mjs` redraws four
of the dashboard pictures in [Your first session](first-session.md)
(`docs/assets/tour/`: `home.png`, `session.png`, `masked-later.png`,
`approval.png`; not `sent.png`) after a change to the product
page. It runs a real arbiter and dashboard in one temp directory (HOME and
`MANDU_HOME` included, so nothing of your own Mandu is read or joined),
seeds them with the recorded tour (`dashboard/test/fixtures/tour-*.ndjson`,
fake secrets, moved to now; recorded when step 3's file was
`deploy/staging.conf`, so the script renames it to the tour's
`deploy/staging.tfvars`), a second running session it builds, and one
real pending send for the Approvals card, then drives a headless Chromium
over the DevTools protocol: 980 CSS px wide, light theme, signed in, each
picture clipped to its page region. No model call and no API key. It finds
a Playwright headless shell under `~/.cache/ms-playwright` by itself
(`--browser <path>` or `MANDU_TOUR_BROWSER` names another, and with none it
says SKIP); `--out <dir>` writes elsewhere and `--only home,approval` redraws
a subset. ImageMagick, when installed, reduces each picture to a 256-colour
palette. Needs `node scripts/install-deps.mjs tests` first.

## 6. Tests

Every suite is an entry of one manifest, [`tests/suites.mjs`](../tests/suites.mjs),
with a **kind** that says what is real in it: `unit`, `component` (one
package through its interface), `stack` (several packages wired together),
`replay-drill` (the agent CLIs against a scripted model) and `sandbox` (user
namespaces, bwrap, Landlock, seccomp, the kernel-feature binaries) run per
push; `live-drill`, `env` and `eval` need a real model and its budget and
run by hand or on a schedule; `install` runs on release.
A `frozen: true` entry is the frozen integrity lane
([`design/testing/test-organization.md`](design/testing/test-organization.md) §3).
The two drill kinds, `replay-drill` and `live-drill`, run only in the
maintainers' source repository: the agent drills are their evidence tooling
and are not published. What the drills show is in
[`testing/drill-results.md`](testing/drill-results.md); to get access to
them, for research for example, write to hello@mandusecurity.com.

```sh
scripts/test-all.sh                        # unit, component, stack, sandbox on this host, PASS/FAIL/SKIP summary
scripts/test-all.sh --kind unit --jobs 8   # one kind, parallel-safe entries 8 at a time
scripts/test-all.sh --only launcher,rust   # named entries ('*' allowed), whatever their kind
scripts/test-all.sh --fail-fast            # stop starting entries after the first failure
scripts/test-all.sh --failures-only        # print only the failed entries (each with its log's last 40 lines) and a counts line
scripts/test-all.sh --integrity            # also the frozen lane's test:integrity suites
scripts/test-all.sh --scope shipping       # = --kind unit,component,stack; --scope all = the default (the Docker path's spelling)
scripts/test-all.sh --agents codex --dry-run   # only the suites some agents need
node scripts/suites.mjs list --kind sandbox # what a kind holds (--json for machines)
node scripts/suites.mjs check              # the completeness check (also a per-push entry)
node scripts/suites.mjs run <id> [-- args] # one entry as the manifest declares it, output streamed
```

`test-all.sh` installs missing `node_modules`, then runs
`scripts/run-suites.mjs`, which writes `summary.json`, `junit.xml` and one
log per entry (`--out DIR` keeps them; otherwise the summary names a
`mandu-suites-*` directory in `$TMPDIR`, of which each run keeps your newest
five and every one that changed in the last six hours: `--keep-results N`,
`MANDU_TEST_KEEP_RESULTS`, `all`; `--keep-results-hours H`,
`MANDU_TEST_KEEP_RESULTS_HOURS`). `--failures-only` (`MANDU_TEST_FAILURES_ONLY=1`) is
the output for a coding agent's session, which pays for every line it reads:
no row for an entry that passed or skipped, each failed entry with the last
40 lines of its log (`--fail-tail N`, `MANDU_TEST_FAIL_TAIL`; 25 without
`--failures-only`), then its failed rows again, one counts line (`FAILURES
PRESENT: 1 failed, 40 passed, 3 skipped of 44 entries`) and the results
directory. What the run writes and its exit code do not change. `vm-run.sh`
takes no such option: what it prints is already the counts and the failed
entries with their log paths. The `sandbox` and `replay-drill`
entries need fresh native bins, so `test-all.sh` runs
`scripts/build-native.sh` first whenever it selects one (a run of only
`unit`, `component` and `stack` skips it; `--no-build-native` or `MANDU_TEST_BUILD_NATIVE=0` skips it when the
bins are known fresh; a failed build stops the run with exit 4). The entries
that need `kernel` SKIP, saying why, where the host refuses unprivileged user
namespaces; `--strict-skips` turns such a skip into a failure. `--agents`
and `--lane` (the model-backed suites, which need a real login or API key)
are in [`testing/running-tests.md`](testing/running-tests.md), the
guide to running the suites. A new test file or `test*` npm script needs a manifest entry (or a
glob an entry already runs): the completeness check fails otherwise.

Each entry runs with a fresh, empty `TMPDIR` of its own (under one
`mdu-run-*` directory per run, removed when the run ends), and an entry that
leaves anything there FAILS with the leftover names (`left 3 entries (812
inodes) in its TMPDIR: …`). So a test makes its temp dirs under
`os.tmpdir()` and removes them, also when it fails: in a `finally` or
`t.after`, or through its package's `tmpDir(prefix)` helper, which removes
them when the test process exits. A daemon a test starts is stopped before
the test ends: one left running outside the entry's process group (`setsid`)
is found by the TMPDIR it still names, killed, and FAILS the entry too. New
files an entry leaves in `/tmp`, `$HOME` or the caller's runtime dir are a
`⚠ OUTSIDE` warning (another process may have made them). `--tmp-leftovers
warn` (`MANDU_TEST_TMP_LEFTOVERS=warn`) only reports the failures, for
chasing one down.
The rule and its reasons: [`design/testing/test-organization.md`](design/testing/test-organization.md) §8.5.

Per package:

```sh
cd arbiter && npm install           # first time
npm test                            # unit + component (test/unit/, test/component/)
npm run test:integrity              # the frozen integrity tests (test/integrity/), where a package has them
npm run test:kernel                 # the tests that need bwrap / userns / the native bins (the launcher's
                                    #   test/kernel/; tests/sandbox/ through `npm run test:sandbox` in tests/):
                                    #   a sandbox entry, not in `npm test`
npm run typecheck                   # run this too: `npm test` uses tsx, which hides type errors
npx tsx --test test/unit/secret-egress.test.ts                           # one file
npx tsx --test --test-name-pattern="symbolize" test/unit/*.test.ts       # one test by name

cd interceptors && cargo test                          # must pass with no root
cd interceptors && cargo test -p fs-supervisor decide_open
cd interceptors && cargo clippy --workspace --all-targets -- -D warnings   # and again with --features kernel
                                                       #   (the rust.clippy suite)

node scripts/dep-audit.mjs npm      # the dependency audit: npm audit over every lockfile, then
node scripts/dep-audit.mjs cargo    #   cargo audit (needs cargo-audit); network needed, else SKIP
                                    #   (continuous-integration.md §14.2)
```

Some packages compile other packages' sources: `tests` (the package at `tests/`),
`tests/conformance` and `interceptors/openclaw-inspect-plugin` import the
arbiter, the proxies, the dashboard and others directly. Node resolves an npm
import (such as `js-yaml`) from the package that holds the importing file, so
those packages must be installed too, or `tsc` fails with "Cannot find module
'js-yaml'" in a file of another package. Each such package lists them in its
`package.json` (`"mandu": { "siblings": [...] }`), and its `pretypecheck` and
`pretest` scripts run `scripts/install-deps.mjs`, which installs the package
and every listed sibling whose `node_modules` is missing (`npm ci` where a
lockfile exists), one npm per package at a time under a per-user lock in
`$TMPDIR` (`mandu-npm-install-<uid>-<hash>.lock`). So `npm run typecheck`
works in a fresh worktree with no install step first. `MANDU_NO_AUTO_INSTALL=1` makes it only report what is
missing. `scripts.install-deps` fails when a package imports another's
sources without listing it; `node scripts/install-deps.mjs --reach <dir>`
prints what a package reaches. A package whose tests *run* another package
without importing it lists it too: the dashboard's component tests start the real
arbiter (`arbiter/ipc/server-main.ts`), so `dashboard` lists `arbiter`; and
`tests`, whose sandbox and live suites start the launcher from source,
lists every package the launcher runs from its checkout (exec-wrap's curl
shim among them: without its `node_modules` every shimmed `curl` of a suite
dies before it sends anything).

A run of the suite manifest leaves nothing behind (each suite gets its own
`TMPDIR`), but tests run by hand, tsx's and Node's compile caches and a coding
agent's per-session scratch dirs collect in `/tmp`, and a small tmpfs `/tmp`
runs out of inodes. `node scripts/tmp-gc.mjs` lists this user's stale entries
there by rule and `--apply` removes them; it never touches another user's
files or anything a live process holds, and it warns when the dir has used
80% of its inodes (so does `scripts/run-suites.mjs`). The rules and ages:
[`design/testing/test-organization.md`](design/testing/test-organization.md) §8.5.1.

Every code change ships unit and end-to-end tests. The end-to-end suite is the
security oracle: each ingress or egress path has a test asserting that no
registered secret (and, in the frozen integrity modes, no unsymbolized
untrusted data) reaches the model. The catalog of end-to-end tests and what each
asserts: [`testing/e2e-catalog.md`](testing/e2e-catalog.md).

**The integrity axis is frozen** (modes `injection` and `full`, the paper's
prompt-injection defense): kept and compiling, but no longer developed or
offered, and run only with `MANDU_EXPERIMENTAL_INTEGRITY=1`. Its tests are
split in two. A few *canaries* stay in the default `npm test` lane as the
frozen feature's smoke test; a broken canary is fixed or recorded, never
skipped. The integrity-only tests moved to `test/integrity/` in their
package (`tests/integrity/` in `tests/`) and run with `npm run test:integrity` or
`scripts/test-all.sh --integrity`, only when the axis is revived (not on
every commit, not before a release). Do not add integrity features or tests
beyond the canaries. The canary list, the rules and how to revive or delete
the axis: [`design/architecture/protection-modes.md §10`](design/architecture/protection-modes.md).

### Kernel tests, without root

The kernel attachment code (seccomp user notification, Landlock, the
Bubblewrap box) is covered by `#[ignore]`d tests that need privileges a
default `cargo test` does not take. Run them through unprivileged user
namespaces:

```sh
scripts/kernel-tests.sh             # PASS/FAIL/SKIP per crate; never needs sudo
scripts/kernel-tests.sh --include-ignored   # the kernel feature in full (the rust.kernel entry)
scripts/kernel-vm.sh                # the same tests in a disposable VM with an older kernel
```

A test whose kernel feature is missing reports SKIP, not FAIL.

On a stock Ubuntu 24.04 or newer host
(`kernel.apparmor_restrict_unprivileged_userns=1`) `unshare --user` cannot
map a uid, so `scripts/kernel-tests.sh` and the sandbox suites SKIP. The
supported way to run them on such a box is CI's own guest, which needs only
`/dev/kvm` access (the `kvm` group), no sudo and no host AppArmor change:

```sh
scripts/ci/vm-run.sh --need kernel                         # CI's kernel lane on HEAD (~1.5 min)
scripts/ci/vm-run.sh --need kernel --worktree              # your uncommitted tree
scripts/ci/vm-run.sh --need kernel --guest ubuntu-2604     # the same on Linux 7.0
```

The developer-only `mandu-dev-unshare` AppArmor grant (`sudo
scripts/apparmor/install.sh --dev-unshare`) is an opt-in alternative for
your own machine; nothing requires it.

The multi-kernel and fresh-install matrix (`scripts/matrix/run.sh`) is described
in [`design/testing/os-test-matrix.md`](design/testing/os-test-matrix.md).

### Live suites

The live suites drive a real `claude` through the full stack and need a
logged-in agent. They are opt-in (see each suite's header in `tests/env/`).
The maintainers run their `claude-e2e` drill in a containerized rig; the
drills and the rig are not in this tree
([`design/testing/docker-e2e.md`](design/testing/docker-e2e.md) §2). The
Docker image in `packaging/docker/` (`Dockerfile.ci`, run with
`scripts/ci/docker-run.sh`) runs any test kind in a container (same doc, §1).

The `local-model` drill (plan 11 §4) runs the real launcher around a real
`claude -p` on your subscription and a real local model, and checks that a
`local-model` file reaches your own model and never the vendor:

```sh
cd tests && MANDU_LIVE_LOCAL_MODEL=1 npm run test:env:local-model
```

It needs an Ollama serving `llama3.2` on `127.0.0.1:11434`
(`ollama pull llama3.2`) and SKIPs, saying why, without it. Knobs:
`MANDU_LIVE_LOCAL_MODEL_URL` (the Ollama origin),
`MANDU_LIVE_LOCAL_MODEL_NAME` (the model), `MANDU_LIVE_LOCAL_MODEL_MODE`
(`secrets`, the default, or the frozen `full`, which also needs
`MANDU_EXPERIMENTAL_INTEGRITY=1`); the rest are in the test file's header
(`tests/env/local-model.test.ts`).

The same drill with the declared model on another machine (confidentiality
plan 12): two network namespaces on this host, no root, the model behind a
TLS relay on the peer and held to `perimeter:`, `claude` reaching Anthropic
through slirp4netns. Needs `slirp4netns` and `openssl` besides the above:

```sh
cd tests && MANDU_LIVE_LOCAL_MODEL=1 npm run test:env:local-model-netns
```

Its sibling runs the same Ollama as the agent's MAIN model (plan 11 phase 3,
`ANTHROPIC_BASE_URL` at a declared `wire: anthropic` entry) and checks the
model proxy stays in front and nothing reaches the vendor. It needs an Ollama
that serves the Anthropic Messages API (0.14 or newer) and costs no vendor
budget:

```sh
cd tests && MANDU_LIVE_LOCAL_MAIN_MODEL=1 npm run test:env:local-main-model
```

The agent drills (recorded tmux runs of the real TUIs, the differential
harness) are the maintainers' evidence tooling: they stay in the source
repository, and the maintainers run them for each release and publish the
results with it ([`testing/drill-results.md`](testing/drill-results.md);
access: §6 above).

### CI and running what CI runs

CI boots one throwaway KVM guest per pipeline, with no network and no shared
filesystem, and runs the per-push kinds in it; each entry that does not need `kernel` runs in
its own namespace sandbox inside the guest
([`design/testing/continuous-integration.md`](design/testing/continuous-integration.md)). The same
command runs it on your machine:

```sh
scripts/ci/vm-run.sh                              # the five per-push kinds on HEAD, in the CI image
scripts/ci/vm-run.sh --worktree --only arbiter    # your uncommitted tree, one manifest entry
scripts/ci/vm-run.sh --commit <sha> --only <id>   # reproduce a CI failure on the image CI used
scripts/ci/vm-run.sh --shell                      # a shell in the guest (serial console), nothing runs
scripts/ci/vm-run.sh --selftest                   # the VM plumbing only (about 15 s)
scripts/ci/vm-run.sh --dry-run                    # print the job file and the qemu command
scripts/ci/pipeline.sh --host --kind unit,component,stack   # no KVM: the same stages on this host (not equivalent for kernel)
```

The model-backed kinds (`live-drill`, `env`, `eval`; in this tree, the `env`
suites) run in the same guest,
with a network, through `scripts/ci/nightly.sh`, which uses a real login or
API key and spends its budget; `--canary-credential` rehearses the whole
credential path with synthetic credentials instead.

It needs `/dev/kvm` (the `kvm` group), `qemu-system-x86_64` and `qemu-img`;
the first run for a new set of lockfiles or pins builds the image
(`scripts/ci/vm-image.sh`, a few minutes, network, and on Ubuntu 24.04
Mandu's granted bwrap plus `slirp4netns` to keep that one networked boot off
the host's loopback). Results, including a failed or broken run, land in
`${MANDU_HOME:-~/.mandu}/runs/ci/<run>/`, which the
dashboard's CI section reads. The pieces:

| File | Role |
|---|---|
| `scripts/ci/vm-run.sh` | host side: the disks, qemu, the timeout, then the collector |
| `scripts/ci/vm-image.sh` | builds or finds the image for a tree's key (`--key` prints it) |
| `scripts/ci/pipeline.sh` | the run, in the guest or with `--host`: build, then `scripts/run-suites.mjs` |
| `scripts/ci/ns-run.sh` | the per-entry sandbox (bubblewrap: user/PID/IPC/UTS/net namespaces, a private checkout, an empty `$HOME`) |
| `scripts/ci/collect-results.mjs` | reads the guest's results tar as untrusted input into the runs directory |
| `scripts/ci/replay-retention.mjs` | the replay store's retention (newest 300 runs, ~4.5 GiB, plus pinned and recent; the collector runs it, `--dry-run` by hand) |
| `scripts/ci/pins.env` | node, rust, the agent CLIs, the base image, the sandbox's bubblewrap |
| `scripts/ci/guest/` | what the image runs: `provision.sh` once, `boot.sh` via `mandu-ci.service` every boot |
| `scripts/ci/nightly.sh` | the model-backed kinds: `vm-run.sh` with `--network` and a credential (`scripts/ci/credential.mjs`) |
| `scripts/ci/port-bridge.mjs` | the one host port a networked guest reaches (the host's Ollama) |

### Developing and testing on macOS

macOS runs the wrapper layer: the launcher's posture there is `read-blocked`
(Seatbelt denies reads of registered secret files) rather than Linux's
confined secret twins, and nothing in the kernel layer exists on a Mac
([`design/portable-wrapper-cross-platform.md`](design/distribution/portable-wrapper.md),
[`design/confidentiality.md`](design/confidentiality/confidentiality.md) §7.3). The suites
marked for darwin in the manifest inherit the macOS branch's historical green set; this integration needs a
fresh Mac run
([`design/test-organization.md`](design/testing/test-organization.md) §6.9):

```sh
node scripts/suites.mjs list --platform darwin --ids   # what runs here
scripts/test-all.sh                                    # on a Mac, selects exactly those
```

That is the typecheck and whole `npm test` of launcher, reply-filter,
arbiter, anthropic-proxy, net-proxy, exec-wrap, inspect-mcp and policy-mcp,
the dashboard's typecheck (its `npm test` stays Linux-only for now: its
test-runner suites expect the Linux manifest's `sandbox` entries), plus the
darwin-only `launcher.darwin-seatbelt` entry (the Seatbelt profile run under
`sandbox-exec`) and `launcher.darwin-git-sandbox` (Mandu's own git under its
Seatbelt sandbox, write-protection.md §8.5.2). On a Mac the launcher's and the
arbiter's own git runs inside that sandbox in every suite that does not set
`MANDU_GIT_SANDBOX=0`; run the suites outside any other Seatbelt profile
(`sandbox-exec` does not nest), or the git sandbox is simply absent and
`launcher.darwin-git-sandbox` SKIPs. `cargo test`, the `sandbox` kind (and
the maintainers' `replay-drill` kind) and the launcher's shell suites are
Linux-only.

`scripts/run-suites.mjs` preserves a private directory per run and per
entry. On macOS a long inherited TMPDIR falls back to short canonical entry
paths such as `/private/tmp/XXXXXX/00`, including the `/private` prefix in the
104-byte socket budget. Every run's temporary directory is removed at the
end. A direct `npm test` should use a short directory such as
`TMPDIR=$(mktemp -d /tmp/XXXXXX)`; remove it after the run.

Pitfalls a test written on Linux meets on a Mac (each found by the first
macOS CI run that reached the suites, 2026-10-09):

- **No `/proc`.** Read a process table with `ps -A -o pid=,ppid=,comm=`
  (macOS prints the full path in `comm`), or gate the test on
  `existsSync("/proc/self")`. Another process's environment cannot be read at
  all (`ps -E` shows none), so whatever a Linux test learns from
  `/proc/<pid>/environ` is unknown there.
- **No `setsid(1)`, no `ps -o sid`, no `date +%N`.** These are util-linux,
  procps and GNU coreutils. Use perl's `POSIX::setsid` where a session is
  needed; a test that drives the Linux shell suites' helpers probes for them
  and SKIPs. A shell loop that waits on one of them must be bounded, or the
  missing tool turns into a hang the size of the suite's timeout.
- **`mktemp -d` with no template ignores `$TMPDIR`.** It makes its directory
  in the per-user temp dir from `confstr`, outside the entry's TMPDIR: name
  the template, `mktemp -d "$TMPDIR/tmp.XXXXXX"`.
- **A pipe is written asynchronously.** `process.exit()` cuts off what stdout
  still holds (a `--json` document stopped at 8 KiB). The CLI exits through
  `exitAfterFlush` (`launcher/src/exit-flush.ts`); a test helper that prints
  and exits needs the same.
- **Platform defaults differ.** A test of Linux logic passes the platform
  explicitly (`platform: "linux"`) rather than relying on `process.platform`;
  a path the product picks per platform (Claude Code's managed files under
  `/Library/Application Support/ClaudeCode`) comes from the same function in
  the test.
- **`/bin/sh` adds `SHLVL` and `__CF_USER_TEXT_ENCODING`** to a child's
  environment (it is a trampoline to bash).

No CI runs on macOS: GitHub's macOS runners cost ten times its Linux ones
on a private repository, so the maintainers run this set on a Mac by hand
([`design/continuous-integration.md`](design/testing/continuous-integration.md) §12,
"When GitHub runs"), before a release and after a change to the darwin code
(the platform layer and the Seatbelt profile under `launcher/src/`, the PTY
relay, the runtime directory, the launch and its teardown, the darwin tests,
`bootstrap.sh` and the runner):

```sh
bash scripts/bootstrap.sh --no-shim       # every package's deps, then typecheck (macOS ships bash 3.2)
out=$(mktemp -d /tmp/XXXXXX)
scripts/test-all.sh --out "$out"          # summary.json, junit.xml, logs/<entry>.log
```

Run it from a terminal outside any other Seatbelt profile (above), and read
an entry's whole log under `$out/logs/` when the console's tail is not
enough.

**Run tests in a scratch environment.** The e2e suites start daemons, write
registries under the runtime base and, in places, under `HOME`. On a
workstation that also runs Mandu, point them at a throwaway tree:

```sh
S=$(mktemp -d /tmp/mdu.XXXX)
T=$(mktemp -d /tmp/XXXXXX)
mkdir -p "$S/home" "$S/rt"
printf '[user]\n\tname = Mandu Test\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = master\n' > "$S/home/.gitconfig"
cd launcher && env -u XDG_RUNTIME_DIR HOME="$S/home" TMPDIR="$T" MANDU_RUNTIME_DIR="$S/rt" npm test
rm -rf "$S" "$T"
```

Run from inside a Claude Code session, also unset its `CLAUDECODE` and
`CLAUDE_CODE_*` variables so the suites see what CI sees.

Keep that base short. A Unix socket path holds at most 103 bytes on macOS
(107 on Linux), and the default `TMPDIR` (`/var/folders/…/T/`, about 50
bytes) leaves little room for the socket paths tests make under it.

**`/tmp` is not `/tmp`.** `/tmp`, `/var` and `/etc` are symlinks into
`/private`. `os.tmpdir()`, `mkdtemp` and `$TMPDIR` hand out the symlinked
spelling; `realpath`, `process.cwd()`, the path Node gives the main module
(`import.meta.url`) and anything the kernel reports use `/private/…`. So:

- Compare paths after resolving both sides. The CLI and MCP entry guards
  compare realpaths (`launcher/src/entrypoint.ts`), so `node /tmp/…/mandu.mjs`
  and a checkout behind a symlink still start; the exec-box staging check
  resolves the deepest existing ancestor of a path that does not exist yet.
- In a test whose code under test returns realpaths, build the fixture under
  `realpathSync(mkdtempSync(…))`, as a real `HOME` (`/Users/<you>`) already is.
- Seatbelt path filters match only the canonical spelling:
  `(deny file-read* (literal "/tmp/x"))` does not stop `cat /tmp/x`. The
  launcher denies both the registered path and its realpath.

**No `/proc`.** Process probes that read `/proc` on Linux ask the OS
another way on darwin: a process's command line comes from
`ps -ww -o args=` (the symbol-DB owner lock's pid-reuse check, `mandu reap`,
the dashboard's Replace guard), and the dashboard finds which process holds a
Unix socket with `lsof -U`; both are unprivileged for your own processes.
Per-connection attribution in net-proxy and exec-wrap's lineage keys have no
darwin source and degrade to "unknown" and a bare pid, off the security path.
The reply-filter's PTY relay uses BSD `script(1)`.

## 7. Status of the kernel layer

The model-context chokepoint is pure userspace and is the one the security
invariant rests on; the integration suite proves it end to end.

The kernel layer adds depth, all without host root, each piece probe-gated:

- **Command box** (`mandu-exec-box`): Bubblewrap with new PID, IPC, UTS and
  cgroup namespaces, a new session (no TIOCSTI), all capabilities dropped,
  nested user namespaces disabled, a seccomp deny-filter and Landlock inside.
- **Connect guard and secret twins** (`mandu-net-guard`): seccomp user
  notification on `connect(2)` for the whole agent, and placeholder copies of
  credential files served to every program that is not an allowed reader.
- **Landlock** (kernel 5.13 and later for files, 6.7 and later for TCP ports):
  confines the whole agent tree to an allowed port set, and the command box to
  a read-only view with the AgentView writable.

On a test host with kernel 6.8 (Landlock ABI 4) every kernel test runs
and passes through `scripts/kernel-tests.sh`. Known residue is tracked in
[`design/architecture/privilege-model.md`](design/architecture/privilege-model.md) §1 and
[`design/architecture/architecture-map.md §9`](design/architecture/architecture-map.md).

## 8. Where the design lives

- [`design/README.md`](design/README.md): the index of every design doc, by
  area, with its status.
- [`design/architecture/mandu.md`](design/architecture/mandu.md): the architecture. Read it first.
- [`design/architecture/architecture-map.md`](design/architecture/architecture-map.md): one grid that
  ties the design docs together.
- [`adfi-reference/`](adfi-reference/): the design of DualView (adfi-openclaw),
  the OpenClaw plugin Mandu generalizes.
- [`formal/`](formal/README.md): working drafts of a formal model of the
  guarantees (not authoritative; the design docs and the code are).

Design decisions go in `docs/design/` in the same change as the code; a change
that lands without its doc update is incomplete.

