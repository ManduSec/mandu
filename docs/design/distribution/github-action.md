# The Mandu GitHub Action (design)

> Status: **BUILT 2026-10-21** in this repository
> (`packaging/github-action/`): a composite action that runs Claude Code
> (`claude -p`) or Codex (`codex exec`) under `mandu` in a workflow, with an
> unattended policy and a job summary. **Not published**: the Marketplace
> needs a repository of its own (§8, steps for a maintainer). Not yet run on
> a GitHub-hosted runner with a real model: the end-to-end test drives the
> action's run step with a stand-in model on this machine (§7). User docs:
> [`docs/github-action.md`](../../github-action.md).
> Companions: [`packaging.md`](packaging.md) (the npm package the action
> installs), [`rootless-confinement-ubuntu-2404.md`](../confidentiality/rootless-confinement-ubuntu-2404.md)
> (what a stock Ubuntu 24.04 gives Mandu without root),
> [`egress-hold.md`](../confidentiality/egress-hold.md) "The default" (no
> hold in CI), [`continuous-integration.md`](../testing/continuous-integration.md)
> §12 (Mandu's own tests on GitHub's runners).

## 1. The job

A workflow that runs an AI agent (a review bot, a fix-the-build job, a
release-notes writer) runs it next to the job's real credentials: the
repository secrets the workflow puts in the environment, a `.env` the build
writes, the cloud credentials an earlier step configured, the token the
checkout left behind. Nobody watches the run, so nobody can answer an
approval, and nobody sees what the agent sent to its model vendor or to
the network until it is in a log.

The action keeps Mandu's one invariant there: a secret reaches the model
only as a placeholder, and its real value leaves the runner only for a
host a rule binds it to. What it adds over `mandu claude` on a laptop is
only what CI changes: who answers (nobody, §4), where the rules come from
(the repository and the workflow, §5) and where the person reads what
happened (the job summary, §6).

## 2. What a GitHub-hosted runner gives Mandu

Learned from Mandu's own CI on the same runners
([`continuous-integration.md`](../testing/continuous-integration.md) §12.2)
and the rootless work for Ubuntu 24.04:

| Need | On `ubuntu-24.04` | Consequence |
|---|---|---|
| Unprivileged user namespaces | refused: the image sets `kernel.apparmor_restrict_unprivileged_userns=1` | no bind layer, no `exec-box` sandbox namespace, but the whole-agent **guard** needs only `no_new_privs` (seccomp user notification), so the posture is `confined` by the guard alone, with no root ([`rootless-confinement-ubuntu-2404.md`](../confidentiality/rootless-confinement-ubuntu-2404.md) §0.1, §0.2) |
| The guard's binary | in the npm package (`dist/native/linux-x64/`, [`packaging.md`](packaging.md) §5) | nothing to build; `require-confinement` (on by default) refuses a run where it would not attach (§4) |
| Node ≥ 22.13 | the image's default Node is older | the action sets up Node 22 (`actions/setup-node`, the pin Mandu's own workflows use) |
| Landlock, seccomp | the runner kernel has both | the TCP confine and the guard come up as on a desktop |
| bubblewrap | not installed | Codex's own command sandbox is a bubblewrap; without a profile that grants it a namespace every Codex command fails ([`codex-sandbox.ts`](../../../launcher/src/codex-sandbox.ts)). `setup: auto` runs `mandu setup --yes` for Codex (§4.3) |
| Root | passwordless `sudo` | used only for the optional `mandu setup`, never at run time (§4.3) |

So a safe action needs no root: the claim holds on the guard alone, which
is the stock posture on every Ubuntu 24.04 machine. The non-root principle
([`privilege-model.md`](../architecture/privilege-model.md) §0) is kept:
the sysctl that would lift the restriction host-wide is not touched.

## 3. Wrap the vendors' actions, or replace the run step: replace

How agents run in Actions today: `anthropics/claude-code-action` (a Bun
program that installs Claude Code, drives it through the Agent SDK, posts
PR comments through its own MCP server, pushes branches, and takes
`path_to_claude_code_executable`, `claude_args`, `settings` and an
`ANTHROPIC_BASE_URL` from the job's env) and `openai/codex-action` (installs
`@openai/codex`, starts `codex-responses-api-proxy` holding the API key, and
runs `codex exec` under a `safety-strategy` that by default drops sudo for
the rest of the job; read 2026-10-21).

**Decision (2026-10-21): the action replaces the run step.** It installs
`@mandusec/mandu` and the agent CLI and runs `mandu claude -p` or `mandu
codex exec` itself. Why not wrap:

- **A base-URL wrap protects the model wire only.** Pointing the vendor
  action's `ANTHROPIC_BASE_URL` at a Mandu model proxy started in an
  earlier step masks registered values in tool results, but the agent and
  its programs would still run outside the launcher: the job's environment
  raw (the repository secrets), credential files readable, no guard, no
  egress gate on the agent's own commands. That is the half Mandu exists to
  add.
- **A shim through `path_to_claude_code_executable`** (an executable that
  runs `mandu claude "$@"`) would put Claude Code under the launcher, but
  the vendor action's comment server and its git pushes then run inside
  the session too, needing the GitHub token's real value at hosts and in
  forms (git's Basic auth) this version does not bind, and its "show full
  output" path prints the stream the session left masked or, with the reply
  filter on, the real values. It is the likely next step (§9) once a live
  run on a runner shows which of its calls need which binding.
- **`codex-action` cannot be wrapped from outside**: its key proxy, its
  user switch and its sudo drop all assume it starts `codex` itself.
- **A composite action has no post step**, so a wrap could not write the
  summary after the vendor's step without a second step of the user's.

What this costs: the vendor actions' GitHub glue (trigger phrases, tracking
comments, inline review comments, branch pushes) is not reproduced. A
workflow posts the agent's answer itself from `result-file` (which holds
placeholders, never values, §4.1).

## 4. The run (`run.mjs`, `lib/command.mjs`, `lib/inputs.mjs`)

`action.yml` has three steps: set up Node, install Mandu and the agent
(`npm install -g @mandusec/mandu@<mandu-version>` and the agent's npm
package at `agent-version`, default the newest Mandu tested, §8), and run
`run.mjs`. Every input reaches `run.mjs` as `MANDU_ACTION_<NAME>` through
the step's `env`, never pasted into a shell script (a test checks both,
§7): an input such as the prompt can carry text from a pull request.

`run.mjs`, in order: check the inputs (a bad input is a refusal, exit 2,
with an `::error` annotation and a summary saying the run did not start);
refuse a persisted checkout credential (§5.3); decide the policy text
(§5.1) and write the run's `policy.yaml` (§5.2); `mandu setup` when asked
(§4.3); launch; run `mandu doctor --secrets --json` against the same
workspace and environment while the run's services still answer; read
the run's event log; stop the services (`mandu stop`); write the summary,
the annotations and the step outputs; exit.

### 4.1 The launch

```
mandu --no-reply-filter --require-confinement claude -p <prompt> <agent-args…>
mandu --no-reply-filter --require-confinement codex exec <agent-args…> <prompt>
```

- **`--no-reply-filter`.** On a desktop the reply filter puts the real
  value back in what the person at the terminal reads. In CI that terminal
  is the job log, which everyone with read access to the repository can
  open (everyone, for a public one), and GitHub masks only the values it
  was given as secrets: a `.env` value or a cloud key would be printed in
  the clear. So the log, `result-file` and anything the workflow posts from
  it keep the placeholders. The user docs say so.
- **`--require-confinement`** (input, default on): a `gated` launch, where a
  program the agent runs could read a secret file raw, is refused before
  the agent starts.
- **`agent-args`** pass through unchanged (a shell-like split that expands
  nothing, or a JSON array). Tool permissions are the user's: `mandu
  claude` starts Claude Code in `--permission-mode default` unless a mode is
  chosen ([`usage.md`](../../usage.md), "Run your agent"), and in `-p` mode
  that refuses a tool needing permission, so a workflow names its tools
  (`--allowedTools Bash,Read,Edit` or a permission mode).
- stdin is `/dev/null`; stdout goes to the log and `result-file`. The
  agent's output can carry text from a pull request or an issue, so it is
  printed between `::stop-commands::<random token>` and `::<token>::`: the
  runner reads no workflow command (an annotation, a mask, an output) in it.

### 4.2 Nobody to approve: every ask fails closed at once

The launch's environment sets, over anything the job set:

| Variable | Value | Effect |
|---|---|---|
| `MANDU_MODE` | `secrets` | the product default, stated, so a self-hosted runner's config cannot turn protection off |
| `MANDU_EGRESS_HOLD_MS` | `0` | a request carrying a placeholder to a host no rule allows is refused at once (403, nothing sent); the egress hold already defaults to 0 under `CI` ([`egress-hold.md`](../confidentiality/egress-hold.md) "The default") |
| `MANDU_SECRETS_ASK_TIMEOUT` | `1` (ms) | a reader not on a file's list, or a change to a file that runs later, is refused instead of waiting a minute for an answer |
| `MANDU_REPLY_FILTER` | `0` | as `--no-reply-filter` (§4.1) |
| `MANDU_HOME`, `MANDU_POLICY_FILE` | under a fresh `mandu-*` folder in `$RUNNER_TEMP` | the run's own policy, placeholder table and event log, outside the workspace the agent edits |
| `MANDU_RUNTIME_DIR` | a fresh `mktemp -d /tmp/mdu-gha-XXXXXX` (0700, 19 bytes), removed at the end | the run's own services, never another Mandu's on a self-hosted runner. Not under `$RUNNER_TEMP`: the services' Unix sockets live there, and the launcher refuses a runtime dir over 44 bytes (107 usable `sun_path` bytes less the arbiter's instance-socket suffix, `runtime-base.ts` `instanceBaseProblem`); a runner's `/home/runner/work/_temp/…`, a self-hosted runner's deep work dir or a long `TMPDIR` goes over it (the first MR pipeline of this action failed so, 2026-10-21). `MANDU_HOME` holds no socket and stays under `$RUNNER_TEMP`. The job's own `XDG_RUNTIME_DIR` is left alone |
| `CI` | kept, else `true` | Mandu's CI rules (no update check, no hold) |

A refused send is reported three ways: the agent sees Mandu's refusal note
in its tool result (as on a desktop), the step gets one `::error`
annotation per host (`Mandu blocked a send: DEPLOY_TOKEN to paste.example
(1 request): no binding allows it, and nobody approves in CI`), and the
summary's Sends table lists it (§6). With `fail-on-blocked` (default on)
the step then fails even when the agent exited 0: a blocked send in an
unattended job is either an attack or a missing binding, and both need a
person. The approval card the arbiter files stays in that run's (discarded)
store; nobody can answer it.

### 4.3 `mandu setup` on a runner

`setup: auto` (the default) runs `mandu setup --yes` for Codex only, after
`apt-get install bubblewrap` when no `bwrap` is on PATH: Codex's own command
sandbox needs Mandu's bubblewrap and its AppArmor profile on Ubuntu 24.04
(§2). Claude Code is `confined` by the guard alone and does not need it;
`setup: true` runs it for Claude Code too (the bind layer, a second
implementation of the same twins). It needs passwordless sudo: GitHub's
hosted runners have it; elsewhere `auto` skips it with a note and `true`
refuses. This is the one-time administrator step the rootless design
allows (`rootless-confinement-ubuntu-2404.md` §0.3), on a machine that is
discarded with the job; no run-time path depends on it.

## 5. The rules (`lib/policy.mjs`)

### 5.1 Which policy file to trust

The rules come from, in order: the `policy` input (inline YAML in the
workflow file), else `policy-file` (default `.github/mandu/policy.yaml`,
used when it exists), else none (Mandu's built-in catalog and the
environment mask, with every send of a secret blocked except a key to its
own issuer, [`usage.md`](../../usage.md) "Placeholders where values were").

A policy file is only as trustworthy as the commit it comes from: a rule
that binds a secret to a host is the one thing that lets a value leave.
On `pull_request_target` and on comment triggers the workflow file is the
base branch's, but a workflow may check out the pull request's head; a
file read from that checkout would be the contributor's. So
`policySource` reads the file at the commit the workflow runs for
(`GITHUB_SHA`):

1. HEAD is `GITHUB_SHA` (the usual checkout, `pull_request`'s merge commit
   included), or there is no `GITHUB_SHA` (outside Actions): the
   workspace's file.
2. Otherwise `git show <GITHUB_SHA>:<file>` when that commit is in the
   clone.
3. Otherwise a refusal, naming both commits and the ways out: the `policy`
   input, fetching the commit, or `trust-workspace-policy: true`.

A same-repository `pull_request` runs the workflow file of the pull request
itself, so its author already controls the job; the rule above adds
nothing there and takes nothing away. A fork's `pull_request` gets no
secrets from GitHub at all. A copy of the file the agent edits during the
run changes nothing: the run's policy is written once, outside the
workspace, before the launch, and a loosening the agent proposes through
Mandu's own tools waits for an approval nobody gives.

### 5.2 The action's own rules: `bindings` and `mask-env`

`bindings` (`NAME: host, host`, one per line) is how a workflow says where
a repository secret in the job's environment may go. Mandu's policy binds
an environment variable to hosts only through `env.sources`
([`usage.md`](../../usage.md), the `env:` block), whose entries fetch a
value at launch. So each binding becomes an `env.sources` entry whose
source is the job's own value:

```yaml
env:
  sources:
    - name: "DEPLOY_TOKEN"
      source: "cmd:printenv DEPLOY_TOKEN"
      bindings: ["deploy.example.com"]
```

The launcher runs the source outside the agent's world
([`env-sources.ts`](../../../launcher/src/env-sources.ts)), the arbiter
registers the value as a secret with exactly those hosts (a sourced name is
always a secret, whatever its name says), and the agent's environment gets
only the placeholder. The net-proxy then puts the value back on the way to
a bound host, anywhere in the request, HTTPS included through its session
CA, and refuses every other host. `mask-env` adds names under
`env.secrets` for variables Mandu would not recognize by name or value.

The action ships no YAML library, so it never parses the user's file: the
generated `env:` section is appended when the file has no top-level `env:`
of its own (a column-0 key scan), and a file that has one is refused with
"put the bindings in its env.sources", as is a flow-style document. Every
name is checked as a variable name and every host with the policy
validator's own host shape before anything is written; values are written
as JSON strings, which YAML reads as the same strings.

A `cmd:printenv` source is a reuse, not a new mechanism; a dedicated
`env:<NAME>` source scheme would read better in a hand-written file and is
left as an open question (§9).

### 5.3 The checkout's own token

`actions/checkout` keeps the job's `GITHUB_TOKEN` for later git commands
by default, as an `http.<url>.extraheader` (`AUTHORIZATION: basic …`) in
the git config or in a file the config includes. Mandu's catalog does not
know that key, and the value is base64 of the token, so neither the
environment mask nor a registered value's fingerprint would catch `git
config --list` printing it into a tool result. The run refuses before
anything starts when `git config --includes --name-only --get-regexp
'^http\..*\.extraheader$'` finds one (names only: the value is never read
into the action), unless `allow-persisted-credentials: true`. The fix it
prints: `persist-credentials: false`, and the token through the job's env
and `bindings`. Teaching the catalog this key (a placeholder in the config
the agent reads, the real header for git alone) would remove the refusal;
§9.

## 6. The job summary (`lib/summary.mjs`)

The summary is the visible value: an unattended run that worked shows
nothing otherwise. It is Markdown appended to `$GITHUB_STEP_SUMMARY`, with
the same facts as JSON in `report-file`:

- one line: the agent and its version, the mode, the secrets posture, the
  agent's exit, where the rules came from;
- **Masked from the model**: each environment variable by name, each
  credential file by its path (relative to the workspace or `~`) and level,
  and how many tool results reached the model with a secret replaced;
- **Sends**: per host, blocked (with the secrets' names and the request
  count) or sent with the real value to a bound host, and the way out for
  a blocked one.

**Names and hosts, never values.** The arbiter's event log is the source
of truth for what happened, but it carries the original side of every
masked span (`DualRepr.original`, a placeholder's `value` and `origin`), so
the reader takes a fixed set of fields from a fixed set of events and
keeps a string only when it matches a shape that cannot hold a value; the
rest is dropped, not escaped:

| Fact | From | Kept when |
|---|---|---|
| agent, mode, posture | the launcher's `launch_posture` | a known word, a version shape |
| masked variables | the same event's `mandu: environment: N secret variables masked (…)` line, else the doctor's `env.masked` | a variable name |
| masked files | `mandu doctor --secrets --json` (names only by contract) | a path with no control character |
| masked tool results | the model proxy's `symbolize` events, once per call | a count |
| blocked / sent | the net-proxy's `net_action` (`blocked` with `withheld`, `forwarded` with `resolved`) | a host name; a placeholder name (`$MDU:<level>_<tool>[<hash>].<field>`), shown as its variable or key name |
| the agent's exit | the launcher's `session_exit` | an integer |

The doctor runs after the launch, while the run's services still answer,
so it lists what a launch in that workspace masks; a file the agent created
during the run is listed too. The renderer escapes every name into a code
span (`|` and backticks cannot break the table). A unit test plants raw
values in every field the event model carries them in and checks that none
reaches the report, the summary or the annotations.

Outputs: `exit-code` (the agent's; 2 when refused), `masked`, `blocked`,
`sent` (counts), `result-file`, `report-file`.

## 7. Tests

| What | File | Kind |
|---|---|---|
| inputs (each one, each bad value), the argument split, bindings and name lists | `packaging/github-action/test/inputs.test.mjs` | unit (`github-action`) |
| the policy source (each case of §5.1), the column-0 key scan, the assembly and its refusals | `test/policy.test.mjs` | unit |
| the report from events shaped as a real run writes them, raw values planted everywhere the event model carries them, the rendering, the annotations | `test/summary.test.mjs` | unit |
| the launch argv, the fixed environment, the setup decision, the step status, the runtime dir within 44 bytes for a deep `RUNNER_TEMP` and `TMPDIR` | `test/command.test.mjs` | unit |
| `action.yml` against the code: every input mapped, no expression inside a `run:` script, the `mandu-version` default equal to the tree's version (and `scripts/set-version.sh` moving it), the agent pins equal to the newest tested ([`agent-versions.ts`](../../../launcher/src/agent-versions.ts)), the `setup-node` pin equal to the repository's workflows' | `test/action-yml.test.mjs` | unit |
| **e2e**: `run.mjs` as a workflow runs it: the real launcher from source on PATH, autostarting the real arbiter, model proxy and net-proxy, around a stand-in `claude` ([`tests/lib/fake-claude-cli.mjs`](../../../tests/lib/fake-claude-cli.mjs), the Messages wire and a Bash tool) driven by the scripted model, the net-proxy's host routes pointing `deploy.example` and `paste.example` at loopback listeners. A repository secret bound by `bindings` and a `.env` in the checkout: no request the model received carries either raw value; the bound host gets the real token; the other gets nothing; the step fails for it with the annotation; the log, `result-file` and the summary carry no value; the summary names both secrets and both hosts. Twice: at this host's posture and with the guard off (`gated`, a runner with no native bins), where only the model side keeps the file. Also the two refusals before any launch: a persisted checkout credential, and a policy file in a checkout that is not the workflow's commit; the action's 44-byte bound equal to the launcher's constants; the run's runtime dir removed. Passes under a deep `TMPDIR` (the CI guest's) | `tests/stack/github-action.test.ts` | stack (`integration`) |

No live model and no GitHub runner: the stand-in model and the loopback
sites keep the e2e offline and keyless, and the posture on a real
`ubuntu-24.04` runner is the stock guard-only one §2 describes. A workflow
that runs the action on GitHub would need a model key (or a stand-in
model the action does not ship), so none is added; the first live run is
a maintainer's step (§8).

## 8. Versions and publishing to the Marketplace

**Pins.** `mandu-version` defaults to the version of the tree the action
came from; `scripts/set-version.sh` moves it with every other manifest,
and `action-yml.test.mjs` fails when they differ. The agents default to
the newest version Mandu tested (`TESTED_AGENT_VERSIONS` max); the same
test fails when the range moves without the action. `agent-version: none`
uses an agent already on PATH.

**Publishing (not done; a maintainer's steps).** GitHub lists an action
in the Marketplace only from a public repository with `action.yml` at its
root, and the listing name must be unique:

1. Create the public repository (proposed `ManduSec/mandu-action`) under
   the organization, with the same license.
2. Copy `packaging/github-action/` to its root: `action.yml`, `run.mjs`,
   `lib/`, `test/` (the tests that read files outside the folder, the
   version and pin checks of `action-yml.test.mjs`, stay here; the rest run
   there with `node --test`). Add a README for the listing that points to
   [`docs/github-action.md`](../../github-action.md).
3. Run it once on that repository's own workflow with a real model key in
   a repository secret, on `ubuntu-24.04`, for each agent: the posture is
   `confined`, the summary appears, a send to an unbound host is blocked.
   Check `--allowedTools` for Claude Code and `--full-auto` for Codex.
4. Tag `v0.2.0-beta.7` (the action's version follows Mandu's) and a moving
   major tag (`v0`), draft a release, tick "Publish this Action to the
   GitHub Marketplace", pick the categories (Security, Code review), and
   accept the Marketplace agreement (an organization owner, once).
5. From then on, each Mandu release copies the folder again and moves the
   tags (a step in [`packaging.md`](packaging.md) §11's release list once
   the repository exists). Until then a workflow can use the action from
   this repository's tree: `uses: ManduSec/mandu/packaging/github-action@<tag>`.

## 9. Open questions and known gaps

- **Wrap mode for `claude-code-action`** (§3): a `claude` shim for
  `path_to_claude_code_executable` and a separate summary step, after a
  live run shows which of its calls need which binding.
- **git and `gh` with the job's token.** A `ghs_` token is bound to
  `api.github.com` by its issuer rule (the `Authorization` header only), so
  `gh api` and REST calls work; `git push` over HTTPS sends the token in
  Basic auth (base64), where a placeholder cannot be put back, so a push
  from inside the session needs a design (the same as the persisted
  header's, §5.3).
- **An `env:<NAME>` source scheme** in place of `cmd:printenv NAME` (§5.2).
- **Docker**: `secrets` mode refuses the agent's programs the docker socket
  ([`usage.md`](../../usage.md), Unix sockets); a workflow that needs it
  lists it under `unix_sockets: allow` in its policy, which lets a program
  start containers outside Mandu's view.
- **Other runners**: self-hosted runners without passwordless sudo, ARM
  runners (the package ships arm64 bins; untested in a job), macOS runners
  (the Seatbelt posture, `read-blocked`; not a target of this version).
