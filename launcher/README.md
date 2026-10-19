# Mandu

*Your agent sees the wrapper, never the filling.*

Mandu lets you run Claude Code or Codex next to your real keys and
credentials: the AI works with placeholders for your secrets, while you still
see the real values in your terminal.

`mandu demo` shows it on your own machine, offline, with no API key.

## Install

```sh
npm install -g @mandusec/mandu      # needs Node 22.13 or newer
```

No Node, or an older one? The installer fetches a pinned Node for Mandu alone
and needs no `sudo`:

```sh
curl -fsSL https://raw.githubusercontent.com/mandusec/mandu/main/scripts/install.sh | sh
```

## Quickstart

```sh
mandu doctor     # check this machine: Node, git, your agent and its login, how your secrets are protected
mandu claude     # Claude Code, protected (anything after `claude` goes to Claude as usual)
mandu codex      # Codex, protected
```

Mandu uses your agent's own login and needs no API key of its own. Log in the
usual way first (run `claude` once and log in; for Codex, set `CODEX_API_KEY` or
`OPENAI_API_KEY`, since `mandu codex` does not use a `codex login` sign-in yet). The first
launch starts everything it needs and prints one line with the mode it runs
in, plus the address of the dashboard where requests that need your OK wait.

`mandu --help` lists the commands and options. `alias claude="mandu claude"` in your shell
profile makes every Claude Code session protected.

## Modes

Mandu has one main setting, the mode. Out of the box it runs `secrets`.

| Mode | What it means for you |
|---|---|
| `secrets` (the default) | Credential files (`.env`, `~/.aws/credentials`, SSH keys, any file you mark secret) and secret-named environment variables reach the AI only as placeholders. Programs that need the real value (`psql`, `aws`, `ssh`, `git`) still get it, and anything that would carry a secret to a place it does not belong needs your OK. |
| `injection` (preview) | Web pages, files from outside and tool output are masked before the AI reads them, so instructions hidden in them cannot steer it. |
| `full` (preview) | Both of the above. |
| `off` | Nothing is enforced; Mandu only records what happens. |

**What `secrets` mode does not do:** it does not mask untrusted text. A web
page, an issue comment or a file from someone else reaches the AI as written,
so an instruction hidden in it (a prompt injection) can still steer the agent,
for example into sending out your source code, which is not a registered
secret. If your agent reads content you do not trust, use `full`.

```sh
mandu mode                 # the running mode and the saved one
mandu mode full            # save a mode, then `mandu stop` and launch again
mandu --mode full claude   # one launch only
```

The `injection` and `full` modes are preview until their benchmark results are
published.

## Requirements

`mandu doctor` checks all of these and says what to fix.

- **Node.js 22.13 or newer** and **git**. Node programs the AI runs need
  22.21 or newer (or 24.5 or newer) on your PATH to get your secrets on their
  web requests.
- **Your agent:** Claude Code (`npm install -g @anthropic-ai/claude-code`) or
  Codex, logged in.
- **Linux x64** is the supported platform; **Linux arm64 (aarch64)** is
  included but not yet tested on arm64 hardware. The package includes the small
  native guard that keeps your credential files away from every program the
  agent runs, so a stock Ubuntu 24.04 is fully protected with no `sudo`
  (`mandu doctor` reports `posture: confined`). WSL2 works as Linux but is not
  yet tested; WSL1 cannot protect credential files.
- Elsewhere (another architecture, or a host without the guard) Mandu still
  keeps your secrets from the AI and checks what leaves your machine, but a
  program the agent runs could open your credential files (`posture: gated`);
  `--require-confinement` refuses to launch in that case.

## Learn more

- [Getting started](https://github.com/mandusec/mandu/blob/main/docs/getting-started.md): a ten-minute walk-through, from install to your first protected session.
- [Guide](https://github.com/mandusec/mandu/blob/main/docs/usage.md): every command and setting, in plain language.
- [Guarantees](https://github.com/mandusec/mandu/blob/main/docs/guarantees.md): what is guaranteed, what is not, and how to check it on your machine.
- [How Mandu works](https://github.com/mandusec/mandu/blob/main/docs/how-it-works.md): the model behind the placeholders. Mandu implements DualView ([arXiv:2607.03821](https://arxiv.org/abs/2607.03821)), which follows Prompt Flow Integrity ([arXiv:2503.15547](https://arxiv.org/abs/2503.15547)).
- [Source](https://github.com/mandusec/mandu): the code, the design record and how to contribute.

Built by Mandu Security. Licensed under the Apache License, Version 2.0.
