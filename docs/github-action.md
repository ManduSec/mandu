# Run your agent in GitHub Actions under Mandu

A workflow that runs Claude Code or Codex runs it next to your real
credentials: the repository secrets you put in the job's environment, a
`.env` your build writes, the cloud keys an earlier step set up. Nobody
watches the run. The Mandu action runs the agent under Mandu there, so the
model sees each of those secrets only as a placeholder, and the real value
leaves the runner only for a host you bound it to. A send to any other
host is blocked, and the job summary lists what was kept from the model and
what was blocked or sent.

`secrets` mode, the one the action runs, does not mask untrusted text: a
pull request or an issue the agent reads still reaches the model as it is.
What Mandu keeps is your secrets.

The action lives in this repository for now (`packaging/github-action/`);
it is not in the GitHub Marketplace yet.

## A first workflow

```yaml
name: fix the build
on: workflow_dispatch

jobs:
  agent:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false        # required, see below
      - uses: ManduSec/mandu/packaging/github-action@v0.2.0-beta.7
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
        with:
          agent: claude
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          prompt: Find why the staging deploy fails and fix it.
          agent-args: --allowedTools Bash,Read,Edit
          bindings: |
            DEPLOY_TOKEN: deploy.example.com
```

What happens:

- The agent's environment holds a placeholder for `DEPLOY_TOKEN`
  (`$MDU:nomodel_Env[…].DEPLOY_TOKEN`), and so does everything the model
  is sent. A `curl -H "Authorization: Bearer $DEPLOY_TOKEN"
  https://deploy.example.com/…` the agent runs leaves with the real token,
  filled in on the way out.
- The same token in a request to any other host is refused, nothing is
  sent, and the step fails with `Mandu blocked a send: DEPLOY_TOKEN to
  <host>`. Nobody can approve a send in CI, so a host the agent really
  needs goes into `bindings`.
- Secrets Mandu finds on its own are masked too: variables whose name or
  value says secret (`*_TOKEN`, `*_SECRET*`, `*PASSWORD`, `*_API_KEY`, a
  key in a known format, …; [User guide](usage.md#protection-modes-what-mandu-enforces)),
  `.env` files and the usual credential files in the checkout and the
  runner's home. A secret no binding names goes nowhere, except a key sent
  to its own issuer's API host (a GitHub token to `api.github.com`, a
  Stripe key to `api.stripe.com`, in the `Authorization` header only).
- The job log and the agent's answer (`result-file`) show placeholders,
  never values: anyone who can read the repository can read the log.

Codex works the same way: `agent: codex`, `openai-api-key: …`, and for
example `agent-args: --full-auto`.

## The job summary

Every run adds a summary to the job's page:

```
Mandu: what the AI did not see
Claude Code 2.1.295 · mode secrets · secrets confined · exit 0 · policy: .github/mandu/policy.yaml

Masked from the model
| Secret         | Where                | Rule                              |
| DEPLOY_TOKEN   | environment variable | sent only where a binding allows  |
| .env           | file                 | no AI may read it                 |

Sends
| Result                           | Host               | Secrets      | Requests |
| blocked                          | paste.example      | DEPLOY_TOKEN | 1        |
| sent with the real value (bound) | deploy.example.com | DEPLOY_TOKEN | 1        |
```

It holds names and hosts only, never a value. The same facts are in the
`report-file` output as JSON, and the counts in the `masked`, `blocked` and
`sent` outputs.

## Your rules

The rules come from the first of:

1. the `policy` input, a [`policy.yaml`](usage.md#secrets-in-policyyaml-who-may-read-what-and-what-leaves)
   written in the workflow file;
2. the `policy-file` input, default `.github/mandu/policy.yaml` when it
   exists;
3. none: Mandu's built-in rules.

The action adds `bindings` and `mask-env` to them. A policy file that has
its own `env:` section takes its bindings there instead (`env.sources`,
with `source: "cmd:printenv NAME"`), and the action says so.

**Where the file is read from.** A rule that binds a secret to a host is
what lets it leave, so the file is read from the commit the workflow runs
for. If your workflow checks out another commit (on `pull_request_target`,
or a comment trigger that checks out the pull request), the action reads
the file from the workflow's commit with git, and refuses when that commit
is not in the clone. Give the rules in the `policy` input there (the
workflow file is your base branch's), or set `trust-workspace-policy: true`
if the checkout is yours.

## The checkout's token

`actions/checkout` keeps the job's token in the git config for later git
commands unless you set `persist-credentials: false`. Any program the
agent runs could print it (`git config --list`), and Mandu does not mask
that entry yet, so the action refuses to run while it is there. Check out
with `persist-credentials: false`, and give the agent a token through the
environment instead (`GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}` for `gh api`:
a GitHub token goes to `api.github.com` without a binding of yours). A `git push` from inside the
agent's session does not work yet with a masked token; push from a later
step of the workflow.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `agent` | `claude` | `claude` (runs `claude -p`) or `codex` (runs `codex exec`) |
| `prompt` / `prompt-file` | | the task, or a file in the repository that holds it |
| `agent-args` | | extra arguments for the agent, a shell-like string or a JSON array; nothing is expanded |
| `bindings` | | `NAME: host, host`, one per line: where a variable's real value may go |
| `mask-env` | | more variable names to mask |
| `policy` / `policy-file` | `.github/mandu/policy.yaml` if present | your rules (above) |
| `trust-workspace-policy` | `false` | read `policy-file` from a checkout that is not the workflow's commit |
| `require-confinement` | `true` | refuse to run where a program the agent runs could read a secret file raw |
| `fail-on-blocked` | `true` | fail the step when a send was blocked |
| `allow-persisted-credentials` | `false` | run although the checkout kept its token in the git config |
| `setup` | `auto` | run `mandu setup` first (needs passwordless sudo, as GitHub's runners have): `auto` does it for Codex, whose own command sandbox needs it on Ubuntu 24.04 |
| `working-directory` | `.` | where the agent works |
| `summary`, `verbose` | `true`, `false` | the job summary; every protection layer in the log |
| `mandu-version` | this release | the `@mandusec/mandu` version installed from npm |
| `agent-version` | the newest Mandu tested | the agent's npm version; `none` uses the one on PATH |
| `node-version` | `22` | Mandu needs Node 22.13 or later |
| `anthropic-api-key`, `claude-code-oauth-token`, `openai-api-key` | | the agent's login; Mandu masks it from the agent's programs |

Outputs: `exit-code` (the agent's; `2` when the run was refused before it
started), `masked`, `blocked`, `sent`, `result-file`, `report-file`.

## Good to know

- **Runners.** GitHub's `ubuntu-24.04` runners: the secrets are confined by
  Mandu's guard with no root (the same as on a stock Ubuntu desktop). Other
  Linux runners work where the [requirements](getting-started.md) hold; macOS
  and Windows runners are not supported by the action.
- **Tool permissions are yours.** Claude Code in `-p` mode refuses a tool
  that needs permission, so name the tools it may use
  (`--allowedTools …`) or a permission mode in `agent-args`.
- **Docker** from inside the agent is refused in `secrets` mode (the socket
  would let a program start containers outside Mandu's view); see
  `unix_sockets:` in the [User guide](usage.md#secrets-in-policyyaml-who-may-read-what-and-what-leaves).
- **What the action does not do** that the vendors' own actions do: answer
  `@claude` comments, post review comments, push branches. Post the agent's
  answer from `result-file` in a later step.

Design and the reasons behind each choice:
[`design/distribution/github-action.md`](design/distribution/github-action.md).
