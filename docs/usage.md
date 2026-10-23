# Using Mandu

The user guide: every command, setting and flag. New to Mandu? Start with
[Getting started](getting-started.md), a ten-minute walk-through.

Mandu runs your AI coding agent (Claude Code, Codex, OpenCode, OpenClaw or Goose)
so that your credentials reach the AI only as placeholders. You run your
agent as before, with `mandu` in front.

Contents:
[Install](#install) ·
[Run your agent](#run-your-agent) ·
[Protection modes](#protection-modes-what-mandu-enforces) ·
[Secrets in `policy.yaml`](#secrets-in-policyyaml-who-may-read-what-and-what-leaves) ·
[What Mandu is doing for you](#what-mandu-is-doing-for-you) ·
[Everyday commands](#everyday-commands) ·
[Turning things on and off](#turning-things-on-and-off) ·
[The dashboard on the network](#the-dashboard-on-the-network) ·
[Troubleshooting](#troubleshooting) ·
[Where Mandu keeps its files](#where-mandu-keeps-its-files) ·
[Uninstall](#uninstall) ·
[Good to know](#good-to-know)

---

## Install

```sh
npm install -g @mandusec/mandu     # Node 22.13 or newer
```

No native build, no configuration. Without Node 22.13, use the installer
that each [release](https://github.com/ManduSec/mandu/releases/latest)
carries: download its three files and run `sh install.sh` in their folder;
with the GitHub CLI:

```sh
gh release download -R ManduSec/mandu -p '*' --clobber && sh install.sh
```

The script is the release's own copy: it names that release's package and
its SHA-256, and installs nothing if the file does not match.

It uses your Node when it is 22.13 or newer, otherwise downloads a pinned
Node (checksum-verified) just for Mandu, installs the package into
`~/.local/share/mandu`, and puts `mandu` in `~/.local/bin`. No `sudo`.
If the Node it was installed with goes away later (say, `nvm uninstall`),
`mandu` runs on whatever `node` is on your PATH instead.
`sh install.sh --dry-run` shows the plan first; `--package <file.tgz>`
installs a release tarball. On macOS with Homebrew, the formula
(`packaging/homebrew/mandu.rb`) does the same over Homebrew's Node.

From a source checkout, `scripts/bootstrap.sh` puts the same `mandu` on your
PATH ([Developing Mandu](development.md#1-build-from-source)).

**Updates.** Once a day a launch asks GitHub whether a newer Mandu is out,
and when one is, it keeps a notice with the command that installs it (the
launch's line counts it; `mandu log` shows it):

```
mandu: ! Mandu 0.2.0 is out (you have 0.2.0-beta.3); to update: curl -fsSL https://github.com/ManduSec/mandu/releases/download/v0.2.0/install.sh | sh
```

The line says **with SECURITY fixes** when a release since yours fixes a
security problem, and then the launch prints it on the terminal too: update
then. The launch never waits for the check: it
prints what the previous check found (so the first launch after an install
prints nothing) and asks again in the background. `mandu doctor` asks every
time and shows your version and the answer under "Installed".

After an update, the Mandu services still running in the background are the
old version's. The next launch checks: when no other `mandu` session is
running, it restarts them as the new version (one line says so); when one is,
it stops and asks you to run it again once that session ends, or to restart
the services now with `mandu stop --stack <dir>` (which ends that session's
protection). It never works with services of another version, nor with
another build of the same version (a source checkout at another commit, or
an install beside a checkout): the services report a fingerprint of their
code, and the launch treats another build the way it treats an older
version, naming both builds when it stops. When a systemd service runs the
old services (a dashboard you set up as a service from a source checkout),
stopping them would only start them again, so the launch stops and names
that service and two ways on: turn a leftover service off
(`systemctl --user disable --now <unit>`), or, to keep the service, run
this mandu beside it as a second Mandu
(`MANDU_HOME=~/.mandu-own MANDU_RUNTIME_DIR=<runtime folder>-own mandu …`;
see "Where Mandu keeps its files"). The second Mandu has its own rules and
history: copy your `policy.yaml` and `config.toml` into `~/.mandu-own` to
keep your rules. `mandu version` shows all of
this before you launch (Troubleshooting, "Which mandu is this?").

What is sent: one HTTPS request to `api.github.com` for the list of Mandu
releases, with no version, no account, no session and nothing about your
machine or your files; GitHub sees your IP address, as for any download.
It is made by Mandu itself, not by the agent, and fails silently when you
are offline (or while the release list is not public). The answer is kept in
`~/.mandu/cache/update-check.json`. It runs only for an installed `mandu` at a
terminal, never in CI (`CI` set) or from a source checkout. Turn it off with
`MANDU_UPDATE_CHECK=0`, or `update-check = false` in `~/.mandu/config.toml`.

**Requirements:** Node 22.13.0 or newer (`node:sqlite` is unflagged from 22.13), `git`, and your agent (`claude` — install with
`npm install -g @anthropic-ai/claude-code`). Run `mandu doctor` any time to
check. Node programs the AI runs (a script, a dev server) need more: the
`node` on your PATH must be 22.21 or newer, or 24.5 or newer, for Mandu to
fill your secrets in on their web requests (see Troubleshooting).

> **On Ubuntu, including 24.04: no `sudo` is needed.** Mandu installs and
> runs as your user. The package ships the small native guard that hands
> every program the agent runs a placeholder when it opens one of your
> credential files, so on a stock Ubuntu 24.04 your secrets are **confined**
> from the very first launch (`mandu doctor` says "credential files are
> protected (posture: confined, by the guard alone)"). The postures you can see:
>
> | Your secrets are… | What it means |
> | --- | --- |
> | **confined** | Programs the agent runs see placeholders of your credential files, except the readers allowed for one (`ssh` and `ssh-add` for your SSH keys by default, and programs you vouch for with `prints: nothing`), which get the real file and may connect only where it is bound. `cat ~/.aws/credentials` shows a placeholder. |
> | **read-blocked** | Programs the agent runs cannot open your credential files at all (macOS). |
> | **gated** | The AI model never sees your keys and Mandu checks what leaves your machine, but a program the agent runs could still open your credential files. Only when the guard is missing or turned off (another platform, a package built without it, `--no-net-guard`). With bubblewrap but no guard the files still get placeholders at launch, but one your system replaces while the agent runs is readable, so it is not called confined. |
>
> **On macOS** (new; tested on one arm64 Mac): `mandu claude` runs at
> posture **read-blocked**. One Seatbelt profile around the agent and
> everything it starts makes a read of your credential files fail, keeps
> Mandu's own state unreadable, refuses changes to files that run later (on
> Linux the Inbox asks you first; macOS cannot hold a change, so it refuses),
> lets TCP reach only Mandu's proxies and ports 443 and 22, refuses the Unix
> sockets of host services such as docker, and refuses `open`, `osascript` and
> `launchctl`. The launch prints what it applied. Mandu's runtime files live
> in a private `/tmp/mandu-<uid>` (macOS's own temporary folder has too long a
> path for a Unix socket). macOS cannot start an agent's own sandbox inside
> Mandu's, so Mandu turns Claude Code's or Codex's own sandbox off for the
> session and says so ([Troubleshooting](#troubleshooting)).
>
> Optional, once: `mandu setup` installs Mandu's own copy of bubblewrap
> (`/usr/lib/mandu/bin/bwrap`) and an AppArmor permission for that copy
> only, so it can also mount the placeholders over the files (a second
> layer). The agent's own sandboxes (Codex's, the read-only command sandbox)
> still start inside it, and nothing else on the machine changes. It shows
> exactly what it will install, asks, and asks for your password for that
> single step. `mandu setup --print` shows everything without changing
> anything; `mandu setup --uninstall` undoes it.

---

## Run your agent

Put `mandu` in front of how you normally start your agent:

```sh
mandu claude                         # interactive Claude Code, protected
mandu claude -p "summarize ./notes.md"
mandu codex                          # Codex, protected
```

Anything after the agent name is passed straight through to the agent. The first
run starts everything it needs (the arbiter, the model proxy, the egress
proxy) automatically; there's nothing to launch yourself.

**Not logged in yet?** Mandu uses your agent's own login and never logs you
in itself. For Claude Code, log in once the usual way (run `claude` on its own
and log in, or `claude /login`), or set `ANTHROPIC_API_KEY`. For Codex, run
`codex login` once on its own (a ChatGPT plan, or a saved key), or set
`CODEX_API_KEY` or `OPENAI_API_KEY` to an OpenAI API key; a key variable wins
when both exist. On a ChatGPT sign-in, `mandu codex` passes Codex's own
sign-in through its model proxy to the ChatGPT backend, with the same masking
as for the API ([how](design/agents/agent-sign-in.md)); Mandu never stores or
refreshes it. A `mandu codex` session with neither is refused before anything
starts, with that fix. `mandu doctor` shows whether a login was found, and a
launch prints one warning line when it finds none (it only checks that the
usual login file or variable exists; it never reads them).

**Claude Code asks before it acts, as it does without Mandu.** Mandu turns
off Claude Code's non-essential network traffic (telemetry, error reports),
which also stops it fetching its feature flags. Without them, Claude Code
would start in its `auto` permission mode, where its own classifier
approves commands for you. So `mandu claude` starts it with
`--permission-mode default`, the mode it starts in without Mandu, unless
you chose a mode yourself:

- `--permission-mode …` or `--dangerously-skip-permissions` on the command
  line, or
- `"permissions": {"defaultMode": "…"}` in a Claude Code settings file it
  reads (`~/.claude/settings.json`, the project's `.claude/settings.json` or
  `.claude/settings.local.json`, your administrator's managed settings, or
  your own `--settings`).

Then your choice stands. To use auto mode under Mandu, run `mandu claude
--permission-mode auto` or set `"defaultMode": "auto"`. A program built on
the Claude Agent SDK gets the same unless it sets `permissionMode`, and so
does a `claude` you start inside a session, from the shell of `mandu --
bash` or a script, when you start it in the folder you launched from (in
another folder Mandu has not read that folder's settings, so it leaves the
mode to Claude Code).

**Codex's command sandbox on Linux.** Codex runs every shell command in its own sandbox, and by default that
sandbox has no network. That also cuts off Mandu's checks, so even a `curl`
with a key you bound to its host could not run. `mandu codex` therefore
turns the sandbox's network on, and every launch says so:

```
mandu: ! Codex's commands may use the network (Mandu decides where they connect); --no-codex-shell-network keeps Codex's default
```

Mandu's guard then decides where each command may connect, your secrets
still reach commands only as placeholders, and they leave only for the
hosts they are bound to. Files Mandu does not treat as secret (your source
code, say) can now be sent out by a command, as they can under
`mandu claude`. Mandu leaves the network as you set it when you set it
yourself: on Codex's command line (`-c sandbox_workspace_write.network_access=…`),
in your Codex config files (`~/.codex/config.toml`, a profile's file, a
project's `.codex/config.toml`), or through your administrator's
`/etc/codex` files. It also leaves it off when its own guard is not running
(`--no-net-guard`, the `off` mode). To keep Codex's
default every time, put `codex-shell-network = false` in
`~/.mandu/config.toml`.

On macOS, Mandu normally turns Codex's own sandbox off when applying its
whole-agent Seatbelt profile, because those profiles cannot nest, and says
so at launch. The Linux-only `--no-codex-shell-network` option does not
restore that sandbox or turn command networking off; Mandu's Seatbelt
network rules still apply. Explicit sandbox choices and administrator/user
policies keep their existing handling.

**Goose and OpenCode (OpenCode 1 and OpenCode 2) are a preview.** `mandu
goose` and `mandu opencode` run with every protection, but Mandu was tested
less with them than with Claude Code and Codex, so each launch keeps a
notice saying so (counted on the launch's line, in full in `mandu log`,
printed with `--verbose`):

```
mandu: ! Goose support is a preview: tested less than Claude Code and Codex; report problems at https://github.com/mandusec/mandu/issues
```

`MANDU_PREVIEW_NOTICE=0`, or `preview-notice = false` in
`~/.mandu/config.toml`, drops the notice. `mandu doctor` marks a preview
agent's version row too, and the dashboard shows a **Preview** tag by the
agent's name, with a link to report a problem
([details](design/agents/supported-agents.md)).

**Run a shell instead of an agent.** A shell runs as a plain command with every
protection on, which is the quick way to see masking for yourself:

```sh
mandu -- bash                                  # a protected shell
mandu --no-reply-filter -- bash -c 'cat ~/.aws/credentials'   # the placeholder a program gets
mandu --target shell -- python3 check.py       # any other command needs --target shell
```

(Without `--no-reply-filter`, placeholders in the output are resolved back to the
real values on your screen, as they are in an agent's replies.) Only programs
that read `ANTHROPIC_BASE_URL` (such as `claude`) send their
model calls through Mandu from inside that shell; the launch says so. Codex,
OpenClaw, OpenCode and Goose started from the shell are not covered, so start an agent
as `mandu <agent>`. Any other program name without `--target` is refused,
because Mandu cannot tell whether it is an agent.

**Run a program built on an agent SDK.** A program of your own that uses the
Claude Agent SDK or the Codex SDK starts Claude Code or Codex underneath. Run
it with the agent it starts as `--target`, and the language runtime first:

```sh
mandu --target claude -- node app.js     # @anthropic-ai/claude-agent-sdk
mandu --target codex  -- node app.js     # @openai/codex-sdk
mandu --target claude -- python3 app.py  # the Python claude-agent-sdk
```

Everything Mandu does for `mandu claude` or `mandu codex` applies to the agent
your program starts, even when your program passes the SDK an `env` of its
own: Mandu keeps its settings on every agent a Node or Python program
starts, also one the SDK starts under another name or as a script (`node
cli.js`) and one a shell command string names (`exec("codex …")`), and
refuses to start an agent it cannot protect (a `codex` under `--target
claude`, one told to use another model provider, one started through
`docker` or `ssh`), so your program gets an error instead of an unprotected
agent. The launch says `SDK route ACTIVE`. Good to know:

- One launch protects one kind of agent. A program that uses both SDKs needs
  two launches.
- Placeholders are turned back into real values only in what your program
  prints in the terminal. A program that serves the agent's answers over
  HTTP shows its users the placeholders.
- Mandu's own tools (`inspect_symbol`, `declassify_symbol`, the policy tools)
  are not added to an SDK's agent, and the agent the SDK bundles is not
  checked against the tested versions.
- Not supported: the **Python Codex SDK** (its `codex app-server` refuses
  to start under Mandu; use the TypeScript Codex SDK under Node). Under
  `--target codex`, a program run with Bun or Deno, or with `python3 -I`,
  `-E` or `-S`, is refused; under `--target claude` it runs with a warning,
  and only what reaches Claude Code through its environment protects it.
- Not routed: an agent a shell command string starts by its full path
  (`exec("/opt/x/codex …")`) and a renamed CLI started without the SDK.
  Such an agent cannot reach its model either: the program's model calls
  to the vendor (`api.anthropic.com`, `platform.claude.com`,
  `api.openai.com`, `chatgpt.com`) are refused at the network, so it fails
  instead of sending what it read. Only its account and sign-in calls there
  pass. Not covered: an agent an SDK runs on another machine or in a
  container (`spawnClaudeCodeProcess`) without starting a program here.
  Details: [`design/agents/agent-sdks.md`](design/agents/agent-sdks.md).

**Run a browser agent.** An agent that drives Chrome over its debugging
connection (jev-ultrafast, browser-use, the Playwright and Chrome DevTools
MCP servers) reads pages as text and sends what it read to its model. Let
Mandu start the agent's Chrome:

```sh
mandu --browser -- <the agent's command>
```

Mandu then sits between the agent and Chrome. A secret Mandu knows that a
page shows (a key from your `.env` on a cloud console, say) reaches the
agent, and its model, as a placeholder; the placeholder the agent types
into a page becomes the real value only on a site that secret is bound to.
The Chrome window keeps showing the real page. The agent is given Mandu's
address in `BU_CDP_URL` and `MANDU_BROWSER_CDP_URL` (point an agent's own
setting at it, such as browser-use's `cdp_url`) and cannot reach Chrome's
own port. Screenshots are refused for now, so a browser agent must work
from page text. A key that first appears on a page (a "create API key"
page) is not masked yet.

The Chrome Mandu starts sends its own traffic through Mandu too, so a
script the agent runs in a page cannot send a secret the page shows to a
site it is not bound to. It keeps its own profile in Mandu's folder (sign
in to the sites the agent uses once, and they stay signed in), opens a
window when there is a display (headless otherwise, or with
`MANDU_BROWSER_HEADLESS=1`), and is Google Chrome or Chromium from your
`PATH` unless `MANDU_BROWSER_BIN` names another. One session's Chrome at a
time.

To use a Chrome you started yourself instead, give Mandu its debugging
address (its own profile: Chrome refuses debugging on the default one).
Mandu masks what the agent reads there the same way, but that Chrome's
traffic does not go through Mandu:

```sh
google-chrome --remote-debugging-port=9222 --user-data-dir="$HOME/.mandu-chrome"
mandu --browser-cdp http://127.0.0.1:9222 -- <the agent's command>
```

jev-ultrafast calls two model services itself: TypeSafe and, for typing
text, an OpenAI-compatible service such as OpenRouter. Put their keys in
Mandu's secrets file (`~/.mandu/secrets.json`, mode 600):

```json
{ "typesafe_api_key": "…", "openrouter_api_key": "sk-or-…" }
```

Each key reaches jev as a placeholder, and Mandu puts it back only in
requests to its own service (`api.typesafe.ai`, `openrouter.ai`). Then run
jev from its folder:

```sh
mandu --browser -- sh -c \
  'TEXT_MODEL_API_KEY="$OPENROUTER_API_KEY" TEXT_MODEL_BASE_URL=https://openrouter.ai/api/v1 \
   TEXT_MODEL=inception/mercury-2.5 exec uv run jev "<task>"'
```

Details: [`design/agents/devtools-relay.md`](design/agents/devtools-relay.md).

**Want `claude` itself to always be protected?** Add an alias:

```sh
alias claude="mandu claude"          # add to ~/.bashrc / ~/.zshrc
```

**In GitHub Actions.** The Mandu action runs `claude -p` or `codex exec`
under Mandu in a workflow: the job's secrets reach the model only as
placeholders, a secret goes only to the hosts you bind it to (`bindings:
DEPLOY_TOKEN: deploy.example.com`), every send that would need your OK is
blocked at once (nobody answers in CI), the log keeps placeholders, and the
job summary lists what was masked and what was blocked or sent. See
[Run your agent in GitHub Actions](github-action.md).

---

## Protection modes: what Mandu enforces

Mandu has one main setting, the **mode**. Out of the box it runs `secrets`.

| Mode | What it means for you |
|---|---|
| **`secrets`** (the default) | Your keys and credentials cannot leave. Credential files (`.env`, `~/.aws/credentials`, ssh keys, a config file Mandu finds a password or token in, anything you lock) reach the AI only as a placeholder, and so do the values of a text, PDF or Office document Mandu recognises as a personal one (a bank statement, a payslip, a tax return, a lab report, an ID, your house codes: the AI reads its labels, not its values), and a command or request that carries one to a destination it is not meant for is stopped until you approve it. Everything else works as usual. |
| **`off`** | Nothing is enforced. Mandu only records what happens, so you can look at the trace. |

**What `secrets` mode does not do.** It stops registered secrets from
reaching the network, commands and the AI, except a host you bound a secret
to (`bindings` below), which receives it. It does not stop an instruction
hidden in a web page from making the agent send out something that is *not*
a registered secret, such as your source code, nor from making it send a
secret to a host you bound it to, in any part of the request: a host that
publishes what it receives (GitHub, an issue tracker, a package registry)
would publish it. So bind a secret only to a host you would trust with it in
any request.

**Frozen modes.** Two more modes, `injection` and `full`, mask untrusted
content (web pages, files from outside, tool output) so that instructions
hidden in it have nothing to act through: the paper's prompt-injection
defense. They are frozen and experimental. They run only with
`MANDU_EXPERIMENTAL_INTEGRITY=1` set; without it every entry point refuses
them (`--mode`, `mandu mode`, `MANDU_MODE`, `config.toml`, the dashboard),
and a refused launch names the opt-in. Why, and what "frozen" means:
[`design/architecture/protection-modes.md §10`](design/architecture/protection-modes.md).

```sh
mandu mode                 # show the running mode and the saved one
mandu mode secrets         # save a mode for every future session
mandu --mode off claude    # one launch only
```

The mode is read once, when the Mandu background service starts. After
`mandu mode <name>`, run `mandu stop` and launch again to apply it. If you
pass `--mode` while a service is already running in a different mode, Mandu
refuses and tells you which mode is running, instead of quietly running the
wrong one. Every launch prints one line before the agent starts: the mode it
really runs under, what it masks, where the dashboard is, and how many
notices (pieces of advice) it kept for `mandu log`:

```
mandu: secrets mode · 14 credential files, 3 env vars masked · dashboard http://127.0.0.1:4500/ (sign in with your Mandu dashboard account) · 1 notice: `mandu log`
```

A problem that weakens protection is never only counted: each one prints a
short `mandu: WARNING: …` line under it, ending ``(more: `mandu log`)``.
`mandu log` shows the notices and warnings in full, and every protection as
it came up; `--verbose` prints all of that on the terminal instead, with the
mode line (`mandu: mode secrets (14 credential files masked, 3 env vars
masked)`) and the dashboard line.

When the agent exits, the session's last line says what Mandu kept from the
AI in it, with the same counts as the dashboard's Home page:

```
mandu: in this session: 2 secrets masked before the AI saw them (DB_PASSWORD in ~/proj/.env and the file ~/.aws/credentials) · 1 send with a real value filled in (api.stripe.com) · details: `mandu dashboard`
```

It names each secret by its name and file and each send by its host, never
a value. A session that touched no secret ends with `mandu: no secret came
up in this session, so Mandu had nothing to mask`; one in `off` mode says
protection was off and that Mandu masked nothing. Where Mandu cannot keep
the agent away from its own controls (no file guard and no bubblewrap that
can make a user namespace, the launch's "GATED" line), it cannot check what
the session recorded, and the line says so instead of counting: ``mandu:
Mandu could not check this session's record (on this computer the agent
could reach Mandu's own controls), so it shows no count · why: `mandu
doctor` and `mandu log` ``. The line goes to stderr
after the agent (and its screen) is gone, so it never mixes into what the
agent prints, such as `claude -p --output-format json`. It needs a running
dashboard (the one `mandu` starts with its services); without one, or if it
does not answer within a few seconds, there is no line. `--no-session-summary`
(or `MANDU_SESSION_SUMMARY=0`) turns it off.

The first launch after a session without protection (`--mode off`,
`--no-net-guard`) has ended takes a few seconds longer in a large
repository: Mandu checks your git history again, since that session could
have changed Mandu's saved copies of it. It says so in one line before the
wait, above the launch's line:

```
mandu: ! an earlier Mandu session without protection has ended, so Mandu is re-checking the git history of 2 repositories (slower this once)
```

Two things are masked in `secrets` mode. **Credential files** reach the agent
as a *structured twin*: the file's own keys with each secret value Mandu
recognizes replaced by a placeholder (`STRIPE_KEY=$MDU:nomodel_Read[9bbd].STRIPE_KEY`), so `. ./.env`
works, a program still finds its file where it looks for it, and the real value is put back only on
its way to a host you have bound it to. Mandu recognizes a value by its
key's name, as a URL's password or a known credential format, and in a
list (an MCP server's `args`, or a command line in one item such as `sh -c
"curl -s -u admin:… -H 'Authorization: Bearer …'"`) by the flag before it
(`--api-key`, `--token`, `--auth`, `-H`), as the password of `-u
user:password` or after `docker login -p`, or by its name (`PGPASSWORD=…`);
a switch before such a flag (`-s`, `--verbose`) changes nothing, and nor
does a word that only names a program, such as a path or an image
(`--datadir /var/lib/mysql --password …`, `docker run mcp/mysql --password
…`). psql's and mysql's `--password` alone and docker's `-u` stay as written
only where that program is the command itself. A short
word under an ordinary key stays as written, as does a secret with no flag
or name before it (`cargo login …`); a file in which Mandu finds no secret
value it can hide in place (none at all, or one only in a list) is one
placeholder ([guarantees.md §3](guarantees.md#3-what-is-not-guaranteed)
lists what is recognized; `mandu why <file>` says which form a file
gets). For a session started with another HOME (`HOME=/tmp/x mandu
claude`), `mandu why` in your own terminal also reads the file as that
session does: the newest running session's HOME, or the one `--session
<id>` names, and it prints which (`home  also judged under /tmp/x, …`).

**A JSON, YAML, TOML, INI or XML file you label gets the same per-key copy,
and that is a known gap.** If the file has one key whose name looks
secret, only the values Mandu recognizes become placeholders; every other
value reaches the AI as written, through the AI's Read of the file and
through any command that does not name the file. Label a `return.yaml`
holding `ssn`, `wages` and `password`, and the AI sees the `ssn` and the
`wages`. A planned copy that makes every value of a labelled data file a
placeholder closes this
([confidentiality plan 16](design/confidentiality/confidentiality-plan-16-document-twins-writeback.md),
§1.2 and §3). Until then, give the entry an `extract:` pattern that
matches every value (`extract: ':[ \t]*(.+)'` for a `key: value` YAML
file), or keep the data in a file Mandu hides whole, such as a `.txt` or
`.csv` file; a different `level` or a `readers:` list does not change the
copy the AI reads. Run `mandu why <file>`: "keeps the file's structure"
means the gap applies, "a whole-file placeholder" means it does not
([guarantees.md §3](guarantees.md#3-what-is-not-guaranteed)). Three configuration files keep their own text where it is public
and mask everything else: in `~/.ssh/config` a `ProxyCommand` stays only
when it is plain `ssh -W` or a known relay (`nc`, `socat`, `cloudflared`,
`aws ssm`, …) with no credential, and every `SetEnv` value and every
comment becomes a placeholder. Any other command (a `ProxyCommand` off that list, any
`LocalCommand`, `RemoteCommand`, `KnownHostsCommand` or `Match exec`) is
withheld: a host that relies on it fails inside the agent, and ssh prints
why there instead of running it (see "A withheld ssh command" under
What you will see in `secrets` mode, below); in `pip.conf` only
pip's own settings stay, and an index URL keeps its host but not a token
(or a GUID) in its path, and its password is a placeholder Mandu fills in on
the way to that index (see below); in `~/.git-credentials` each line must be one URL,
whose password and any non-plain user name are masked. **Environment variables** whose name
says secret (`*_TOKEN`, `*_SECRET`, `*PASSWORD` such as `PGPASSWORD`, `*_PWD`
such as `MYSQL_PWD`, `*_PAT`, `*_API_KEY`, Terraform's `TF_TOKEN_*`, a
`*_WEBHOOK_URL` or `*_WEBHOOK` such as `SLACK_WEBHOOK`, …), any value that is
a URL with a password, and any value holding a key in a known format (a
GitHub, GitLab, Stripe, Slack, Anthropic, npm or AWS key, a private key
block, also inside a JSON string such as a Google Cloud service-account key,
or flattened onto one line), whatever the variable's name and however long
the value, reach the agent the same way. A `*_PWD` other than `MYSQL_PWD`
that holds a directory (`HOST_PWD=/home/you/proj`, `ORIG_PWD`) is a path,
not a password, and stays as it is. These variables are never masked, in any
launch whichever agent runs, so the AI can read them: `ANTHROPIC_API_KEY`,
`ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_CUSTOM_HEADERS` (which can carry an
`Authorization` or `x-api-key` header; under `mandu claude` and a shell launch
Mandu sets it itself), `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY` and
`CODEX_API_KEY`, the agents' sign-in variables, and Mandu's own `MANDU_*`
variables. Exempt a variable of yours with `env: { exempt: [...] }` only if
the AI may read it. `--no-env-secrets` (config `env-secrets = false`) leaves
the environment alone.

**AI agents' login files.** The login of each agent a session runs stays
readable to it, and its egress proxy lets the agent use it with its own
services (a token refresh, an MCP server's token), even after another
session masked that file: Claude Code's (`~/.claude/.credentials.json`,
`~/.claude.json`) under `mandu claude`, a plain command and `mandu
openclaw`, and under `mandu goose` or `mandu opencode` while Mandu's AI
helper runs `claude` (neither `ANTHROPIC_API_KEY` nor `MANDU_ULLM_API_KEY`
set, and no `--no-mcp`); Codex's `~/.codex/auth.json` under `mandu codex`
and `mandu openclaw` (OpenClaw reads both); OpenCode's `auth.json` under
`mandu opencode`. Another agent's login is a credential file like the
rest: under `mandu claude`, Codex's `~/.codex/auth.json` reaches the
agent's programs as a placeholder copy (also where `CODEX_HOME` moves it),
its key is refused to any host by the egress proxy, and the launch says so
in one line. An agent of that other kind started inside the session (a
Codex MCP server under Claude Code, say) then cannot log in, and it would
not be protected by Mandu anyway. To keep it working, set
`MANDU_OTHER_AGENT_LOGINS=raw` (config `other-agent-logins = "raw"`): those
files stay readable, that agent can use them with its own services in the
session, and their values are still masked in what reaches the AI.

**MCP and editor config files.** An MCP config whose servers hold a
credential (a token in a server's `env`, a bearer in its `headers`, a
database URL's password in its `args`) is protected with no label of
yours: `.mcp.json`, `~/.claude.json`, Codex's `~/.codex/config.toml`
(and the one `CODEX_HOME` points to), `~/.cursor/mcp.json` and
`.cursor/mcp.json`, `.vscode/mcp.json` and VS Code's user `mcp.json`,
Claude Desktop's and Windsurf's configs, OpenCode's `opencode.json`
(`~/.config/opencode/` and a project's), Goose's
`~/.config/goose/config.yaml`, Gemini CLI's `settings.json` (`~/.gemini/`
and a project's `.gemini/`), Zed's `settings.json`, and Continue's
`config.yaml` and `.continue/mcpServers/` blocks. The AI
sees each value as a placeholder however it reads the file. The config of
the agent you launch stays readable to it, so your MCP servers start and
log in as without Mandu: Claude Code's `~/.claude.json` and the project's
`.mcp.json` under `mandu claude`, Codex's `config.toml` under `mandu codex`,
OpenCode's `opencode.json` under `mandu opencode`, Goose's `config.yaml`
under `mandu goose` (the launch says so in one line per file). The other programs the agent
runs read the project's `.mcp.json` as a placeholder copy (where the guard
runs), and every other MCP config always. An HTTP server's `Authorization`
credential goes only to the host its own entry's `url` names; from the
placeholder copy of an editor's config in your home, the egress proxy puts
it back there. A config that only names variables (`"GITHUB_TOKEN":
"${GITHUB_TOKEN}"`, OpenCode's `{env:VAR}`, Continue's
`${{ secrets.X }}`, Gemini CLI's `$VAR`) is left as it is. `mandu why <file>` names the rule.
What this does not cover, such as a stdio server that runs commands with
its token in its environment: guarantees.md §3, "MCP servers hold their
tokens".

`mandu doctor --secrets --target <agent>` shows what a launch of that agent
masks, and `mandu why ~/.codex/auth.json` says where a login stays raw.
Each agent's own data (`~/.claude`, `~/.codex`, …) stays as it is in every
session.

To put a masked value back into an HTTPS request the proxy has to read the
request, so in `secrets` mode the egress proxy **inspects TLS** with a
per-session certificate authority that the agent's tools are told to trust
(`curl`, node, python, git). A tool that pins its own certificate will fail
through the proxy; `--no-net-proxy-mitm` (config `net-proxy-mitm = false`) turns
inspection off, and masked values then cannot leave over HTTPS at all.

The dashboard's Settings page shows the same setting as the Protection on/off
switch: on is `secrets`, off is `off`. (The frozen masking of untrusted content
has no switch there; turning protection on or off also turns a leftover one
off.) The developer view's Protection block
(its Rules page, `/dev/rules`; the "Protection: <level>" line at the top of
every developer-view page links there) shows `secrets` and `off`, plus a
frozen mode only when it is the saved one.

On a machine without unprivileged user namespaces (a stock Ubuntu 24.04) the
Mandu guard serves the credential placeholders itself, so `secrets`
launches **confined** with nothing to install. Only when the guard is
missing too does the launch fall to the weaker **gated** posture, which says
so loudly; see Troubleshooting.

### What you will see in `secrets` mode

- **The launch line.** Every launch prints what it really runs, for
  example `mandu: secrets mode · 14 credential files, 3 env vars masked ·
  dashboard …` (`--verbose`: `mandu: mode secrets (14 credential files
  masked, 3 env vars masked, 2 readers pinned)`). If the walk over your home
  had to leave something out (a folder deeper than four levels, more than
  256 credential files, an unreadable file), the launch keeps a notice (the
  line counts it) that says so, names the folders that hold most of the deep
  ones (`in ~/project/app (216), … and 15 more elsewhere`) and points at
  `mandu doctor --secrets`: `mandu log` shows it, the `WARNING: mandu:
  secrets NOT covered by the walk` block that names them. The
  walk skips Mandu's own folder (`~/.mandu`, or `$MANDU_HOME`): the copies
  it keeps of your workspace are already placeholders, and the dry run lists
  them as such.
- **Placeholders where values were.** A credential file the agent reads shows
  its own keys with each secret value Mandu recognizes replaced: `STRIPE_KEY=$MDU:nomodel_Read[9bbd].STRIPE_KEY`.
  You, in the terminal, see the real value; the AI and the programs it runs
  see the placeholder. This is the same for every kind of secret: a `.env`
  value, a key in `~/.aws/credentials` and a masked environment variable all
  print as their real value in your terminal. To see what the AI saw, launch
  with `--no-reply-filter`. A placeholder is put back only on its way to a host
  the secret belongs to (`bindings` below), or after you approve it. A host
  you bound gets the real value wherever the placeholder sits in the request
  (its address, body or any header). A registry or index login Mandu binds
  on its own (the `~/.npmrc` token, a `pip.conf` or `PIP_INDEX_URL`
  password, at the host that file or variable names) is put back only in
  the request's `Authorization` header: the same placeholder in a request's
  body (an `npm publish` description), its address or another header gets
  the request refused, whatever you approved. A key whose own format
  names the service that issued it is bound to that service the same
  narrow way, with no card, even with no `bindings` of yours: a Stripe key
  (`sk_live_…`, `sk_test_…`, `rk_…`) to `api.stripe.com` and
  `files.stripe.com`, a GitHub token (`ghp_…`, `gho_…`, `ghu_…`, `ghs_…`,
  `github_pat_…`) to `api.github.com` and `uploads.github.com`, a Notion
  token (`ntn_…`) to `api.notion.com`, an OpenAI key (`sk-proj-…`,
  `sk-svcacct-…`, `sk-admin-…`) to `api.openai.com`, a Slack token
  (`xoxb-…`, `xoxp-…`) to `slack.com`, an npm token (`npm_…`) to
  `registry.npmjs.org`, a PyPI token (`pypi-…`) to `upload.pypi.org`, a
  Hugging Face token (`hf_…`) to `huggingface.co` and
  `router.huggingface.co`, a SendGrid key (`SG.…`) to `api.sendgrid.com`:
  that exact host only (not a look-alike such as `api-stripe.com`, nor a
  host under it), over HTTPS, in the `Authorization` header only. Anywhere
  else in the request, at any other host, or over plain HTTP it asks you as
  before. `issuer_bindings` below turns it off. A
  change to a file's `bindings` applies to the placeholders the AI already
  holds, from the moment the change is in force: a host you add receives the
  real value, a host you remove no longer does. A host Mandu binds on its
  own is not yours to remove there: taking the registry out of your
  `~/.npmrc` label's `bindings` leaves the token bound to that registry,
  in the `Authorization` header only, as if you had never named it.
- **A secret in your own prompt.** If you paste a key Mandu registered (from
  a credential file or a masked environment variable) into what you type,
  the AI receives its placeholder instead; you keep seeing the real value in
  your terminal. A short or simple value you type yourself (under 12 characters,
  or as repetitive as `postgres`) is left as typed, so ordinary words are
  never hidden. Nothing else in your prompt is changed unless you ask for it
  (`secrets` mode does not mask untrusted text): [Checking your own
  prompt](#checking-your-own-prompt) below turns on more checks, such as
  keys Mandu has not registered, card numbers or your project names.
- **Programs that read the real file.** A program allowed to read a
  credential (`ssh` and `ssh-add` for your keys, by default, or a program
  whose entry carries your word, `prints: nothing`, below) gets the real
  bytes, and everything it prints reaches the AI as one placeholder. The
  tool result then carries a note the AI can read: `[mandu:secret] masked:
  deploy read ~/proj/.env; you see a symbol, and the user does not see this output
  unless your reply quotes the symbol (they then see its real value).`
  Your agent may show a command collapsed, so to see that output, ask the
  AI to show it to you: its reply then carries the placeholder, and your
  terminal shows the real text in its place. For a
  program whose output you want the AI to use, such as a database client,
  set `output: clear` on that program's entry in the file's `readers:`
  below. It is about that one file: deploy cleared for `~/proj/.env` is still
  masked when it prints another secret file, and a command whose programs
  hold several secret files is shown only when every one of them clears its
  reader. A registered value that shows up verbatim in such output is still
  masked.
- **A withheld ssh command.** When the
  agent's ssh reaches a command Mandu left out of `~/.ssh/config`, ssh
  prints, in the tool output the AI reads and can tell you about:

  ```
  mandu: ~/.ssh/config line 12: ProxyCommand withheld from the programs the agent runs, so ssh cannot reach this host from inside the agent.
  mandu: why: Mandu cannot vouch for this command. Its text may hold a secret, and running it would run code holding one. The command is not shown.
  mandu: way out: use ProxyJump or plain ssh -W; or move the command into a script Mandu can pin and let ssh read the real file (mandu why ~/.ssh/config shows how); or run this ssh outside the agent.
  ```

  The command itself is never printed (it may hold a password).
  `mandu why ~/.ssh/config` and the dashboard's *Why?* on that file list
  every withheld line with the way out in full: use `ProxyJump` (or plain
  `ssh -W`, or a known relay) instead; or move the command into a script
  the agent cannot change and let ssh read the real file (in `policy.yaml`,
  `readers: [ssh]` and `others: twin` on `~/.ssh/config`; ssh then sends only
  to the hosts that file is bound to), pinning the script with its
  interpreter (`{ app: bash, script: /opt/tools/proxy.sh }`) as the reader
  of any secret it opens itself; or run that ssh outside the agent. Mandu
  does not widen what it keeps: a command it cannot read stays out.
- **A program that is not allowed.** Once a file has an allow-list, any
  other program gets `Permission denied` and the note says which file and
  the way out. A well-known consumer that is not yet on the list is *held*:
  the dashboard's Approvals page shows "Claude Code's program `ssh-add` wants to read a secret
  file: `id_ed25519`" with Allow once / Always allow / Block (and, if you allow
  it, a browser notification), the program waits up to 60 s for your answer, and a standing
  allow is remembered in `policy.yaml`.
- **A tool Mandu does not know.** The result of a tool Mandu has no
  mapping for (an MCP server it could not tie to your agent's config, such
  as a remote one; a tool a plugin adds; a tool a new agent release adds or
  renames) reaches the AI as one placeholder, whatever the session read: no
  check of Mandu's can see what such a tool returns. The tool result says
  so: `[mandu:secret] masked: Mandu has no mapping for the tool
  mcp__linear__search_issues, so its whole result is hidden from the AI: it
  may carry a secret no check of Mandu's can see. To let it through, list
  mcp__linear__search_issues (or mcp:linear for every tool of that MCP
  server) under mapped_tools: in policy.yaml`. Your agent still shows you the
  tool's real result where it shows tool output, and the AI's reply shows
  the real text where it quotes the placeholder (the placeholder is
  `no-model`: no model reads it, Mandu's quarantined helper included). If you trust the tool, add it to
  `mapped_tools:` (below);
  its results then reach the AI as any tool Mandu knows. A local MCP server
  your agent's config names (Claude Code, Codex) is mapped already, and so
  are your agent's own tools and Mandu's.
- **The command sandbox edits your project.** Inspection commands such as
  `cat`, `grep`, `sed` and `sort` run in a sandbox with no network where
  the rest of the machine is read-only. Your project folder (where you
  launched) stays writable there, so in-place edits such as `sed -i` and
  `sort -o` work as they do without Mandu. A credential file inside the
  project still shows only its placeholder to those commands.

### Secrets in `policy.yaml`: who may read what, and what leaves

`~/.mandu/policy.yaml` is the law the arbiter applies live (the
dashboard edits it for you; hand edits are picked up within seconds). A hand
edit that makes your rules stricter, or only changes comments, applies at
once. A hand edit that loosens anything (a new reader, a binding, an allow
rule, a trusted origin, a model entry, a weaker label) does not apply until
you approve it once on the dashboard's Approvals page, which shows "policy.yaml was
changed on disk and would loosen N rule(s)" and lists what it would let:
any program on this computer that can write the file, the agent included,
could have made that edit. Not now keeps your current rules and writes them
back to the file (the change you declined stays on its card in Approvals), so the
file always says what Mandu enforces, after a restart too. The one exception
is start-up: an edit made while Mandu was not running, that you were never
asked about, applies when Mandu starts. While such an edit waits, the
dashboard's Rules page lists the rules in force and says a change waits;
your agent can still lock files, `mandu policy suggest` and the dashboard can
still apply what Mandu found, Undo under Rule changes in Approvals still
works, a reader you listed is still pinned on its first open, and the
dashboard can still move its older rules into the file: Mandu makes the
change to the rules in force and to the file, keeps your edit in the file,
and asks you about it again on a fresh card. A change to a rule your
waiting edit changes too (an Undo, a pin on that file) waits until you
decide that edit; a pin is made at the reader's next open. Whenever Mandu
writes a change into the file (all of these, a lock the agent asks for,
the developer view's apply), your comments and layout stay as you wrote
them; a line the change rewrites keeps the comment at its end. A
request Approvals still shows that your rules already say (you made the
same change by hand) is closed on its own. The parts that concern secrets:

```yaml
version: 1
paths:                                      # your credential files (the catalog finds the usual ones by itself)
  - path: ~/proj/deploy.token
    level: no-model                         # no-model: no AI may read it; any-model: any AI may read it when it asks. Either way it is sent only to its bindings
    readers:                                # programs that get the REAL bytes (pinned by path + hash on first use, from a system copy only); everyone else is denied
      - { app: deploy, prints: nothing, output: clear }   # prints: nothing = your word that deploy keeps the file out of what it prints; output: clear = the AI sees what deploy prints after reading THIS file (a leaked value is still masked)
    bindings: ["db.internal:5432"]          # hosts the value may travel to; a program holding the bytes may connect only there, directly or through Mandu's proxy, HTTPS too (holding two secrets: only where both may go)
  - path: ~/.aws/credentials
    level: no-model
    readers:
      - { app: aws, prints: nothing, output: mask, mask: ["AKIA[0-9A-Z]{16}"] }   # aws is not on Mandu's checked list: your word lets it read; only matching spans of its output are masked
      # bash, node, python and other programs that run code are no readers at all, unless pinned with their script (below)
  - path: ~/ws/app/.env
    level: no-model
    readers: [{ app: docker-compose, prints: nothing }]   # name the program that needs the file; a shell or an interpreter (bash, node, python3) named alone admits nothing
    others: twin                            # default once readers exist: deny. `twin` gives non-readers the placeholder file instead
    values:                                 # per value, for a file of several keys: a value goes only to its own hosts
      STRIPE_KEY: { bindings: [api.stripe.com] }
      "AWS_*": { bindings: [amazonaws.com] }   # * matches any run of the name; a host covers the hosts under it, "*.amazonaws.com" only those under it, "host:443" that port only (no port: every port)
  - path: ~/.ssh/id_ed25519
    level: no-model
    readers:
      - { app: ssh, from: git }             # only an ssh that git started reads the key; an ssh the agent runs itself does not
  - path: "**/*.pem"                        # gitignore-style patterns work too
    level: no-model
  - path: ~/notes/contract.md
    level: any-model                        # any AI may read it when it asks (a quarantined summary, or a logged read into the conversation); it is sent nowhere
    recursive: false
  - path: ~/notes/board-minutes.md
    level: local-model                      # only your own model may read it (models: below); no outside model, and it may not leave
models:                                     # models you or your organization run (see "Use your own model" below); every model NOT listed counts as an outside model
  - name: ollama
    url: http://127.0.0.1:11434
    wire: openai-chat                       # anthropic (the default) or openai-chat (Ollama, vLLM, LM Studio; any OpenAI-compatible server)
    model: llama3.2
    local: true                             # you declare it; Mandu never decides from the address
sensitivity_labels:                         # Office documents' Purview / MIP labels, and the level Mandu SUGGESTS for them (see "Documents with a sensitivity label" below)
  - id: 9fbde396-1a24-4c79-8edf-9254a0f35055   # the label's GUID
    site: 5b3c2d4e-1111-4222-8333-444455556666 # optional: your tenant's GUID; another tenant's label with the same id is not mapped
    name: Highly Confidential               # your words, shown in the review
    level: no-model
  - id: 1e4f7c2a-3b5d-4e6f-8a9b-0c1d2e3f4a5b
    name: General
    level: public                           # mapped, and suggests nothing
prompt_filters:                             # checks on what YOU type (see "Checking your own prompt" below)
  filters:
    key-shapes: on                          # keys Mandu does not know (GitHub, AWS, private keys, ...)
    my-patterns: on                         # a pattern pack of yours, by its name
  actions:
    secret.shape: redact                    # the default for anything found: the AI reads [redacted: ...]
    pii.payment-card: block                 # the prompt is not sent at all
protect: [~/Documents, ~/src]               # no program the agent runs may delete or rename these (or their parents)
issuer_bindings:                            # a key whose format names its issuer goes to that issuer's API host without asking (on by default; see "Placeholders where values were" above)
  issuers_off: [stripe]                     # these issuers' keys ask you instead (stripe, github, notion, openai, slack, npm, pypi, huggingface, sendgrid)
  values_off: ["PROD_*"]                    # and these values (a .env key or an environment variable; * matches any run). `issuer_bindings: false` turns it all off
mapped_tools:                               # tools whose results the AI may read although Mandu has no mapping for them (see "A tool Mandu does not know" above)
  - mcp:notes                               # every tool of the MCP server `notes`, however the agent spells it
  - mcp__linear__search_issues              # one tool, by the name the agent gives it
  - crm__*                                  # every tool whose name starts so
ssh_agent:                                  # who may use your ssh-agent ($SSH_AUTH_SOCK); without this section, any program may
  readers: [ssh-add, { app: ssh, from: git }]
unix_sockets:                               # Unix sockets the agent's programs may reach beyond Mandu's short list (secrets mode)
  allow: [~/.local/run/helper.sock, "@my-helper"]   # a socket file or a folder of sockets; "@name" is an abstract socket ("@pfx*" a prefix). Adding one loosens
write_protect:                              # files the agent's programs may not change (every mode but off)
  deny: [~/bin]                             # refused, like Mandu's own files
  ask: [~/.config/nvim/init.lua]            # held until you answer in Approvals, like ~/.bashrc
  unprotect: [~/.gitconfig]                 # drop one of the built-in "runs later" files (a loosening); Mandu's own files cannot be dropped
remote_mounts:                              # network or FUSE mounts (NFS, SMB, sshfs, ...): while one is visible, a reader you named gets the placeholder (secrets mode)
  trust_lookups: [{ mount: /home, type: nfs4 }]   # its server may see the names a program holding a secret looks up there, so readers get the real file again; a loosening (writes there still need a binding)
env:                                        # environment variables (names matching *_TOKEN, *_SECRET*, *PASSWORD, *_PWD, *_PAT, *_API_KEY, *_WEBHOOK …, and values holding a key in a known format, are masked by default)
  secrets: ["MYCO_*"]                       # also mask these
  exempt: ["CI_TOKEN"]                      # never mask these
  sources:                                  # fill a variable at launch from a keystore or a command
    - name: GH_TOKEN
      source: "cmd:gh auth token"           # or keyring:<service>/<account>, or op://<vault>/<item>/<field>
      bindings: [api.github.com]            # sent there without asking, anywhere in the request
```

Every protected file answers two questions, and each has its own key.
**Which AI may read it** is `level`: `public` (not secret), `any-model`
(any model, the vendor's included, when the AI asks: it first sees a
placeholder, and Mandu's quarantined helper reads the file for it, or the
AI reads it into the conversation, which is logged), `local-model` (only a
model you or your organization run, on this computer or on your
organization's network, and declared under `models:`) and `no-model` (no
model; only you and the programs you name). This answer is a hard limit:
no approval lets a model the level does not admit read the file; only
changing the level does. **Where it may be sent** is `bindings`: the hosts
that get the real value without asking. None of the three secret levels
lets the content leave your machine for any other host unless you allow it
when Mandu asks; a program that read two secrets may send only where both
may go. When such a program's request goes through Mandu's proxy to a host
not all of its files may go to, the request is refused (the program gets a
403) and the question waits in **Approvals**. The card names every file the
program holds, where each may go now, and which ones are in the way.
*Allow once* lets the program's next send to that host go; *Allow this
session* lets that session's programs holding exactly those files send
there until the session ends; *Block* refuses it. For each file in the
way there is one *Always*, "Always: add hooks.slack.com to .env", which
adds that host to that file's rule in `policy.yaml` and to no other file's;
the send goes without asking once every file may go there, and until then
the card says which files are left. A copy of a secret file is named by the
files it was made from, and its *Always* changes their rules. A file whose
rule covers a whole folder with its own readers, or a rule still kept only
on the Rules page from before rules lived in `policy.yaml`, has no *Always*
there: change it under Rules. A connection that does not go through the
proxy (one the guard sees go straight out) is still refused without a
question. A file that holds several keys (a `.env`) may bind each one on its
own under `values:`, keyed by the name its placeholder carries
(`$MDU:nomodel_Read[…].STRIPE_KEY`; `*` matches any run of the name, and a
name also covers its parts, so `DATABASE_URL` covers
`DATABASE_URL.password`). Each value's placeholder is then sent as the real
value only to that value's hosts, never to another value's; a value with no
entry takes the file's `bindings`; when several entries name one value, it
goes only where all of them allow. A program that opened the whole file
holds every value, so it may connect only where every value may go: in the
example above, nowhere without asking. Adding a host under `values:` is a
loosening, so it waits for you in Approvals like any other. A program
holding such a file has no *Always* for it on that card: add the host
under `values:` instead.
A `local-model` file is read by no model at all until you declare
your own model: [Use your own model](#use-your-own-model-eg-ollama) below
walks through it. The dashboard and `mandu why` name the levels "No AI",
"Your own AI only", "Any AI, when it asks" and "Not secret".

**After the AI reads a secret into the conversation.** When the AI reads
an `any-model` (or, with your own model, `local-model`) file's content into
the conversation (`declassify_symbol`), anything it writes afterwards may
be derived from that content, in its own words, which no placeholder marks.
So for the rest of that session a request to a host the content is bound to
still goes through, and any other request (a web fetch, a web search) and
every shell command (Mandu cannot tell whether a command sends anything)
is stopped and waits for you in **Approvals**. The card names the agent,
the files or keys the session read, and the host or the exact command, and
says the request may carry text derived from what was read. *Allow once*
lets that one request, or one run of that exact command, through when the
agent tries again; the next one asks again. *Block* refuses it for the rest
of the session without asking again. There is no *Always allow* on these
cards: an answer covers one session only, and never another. The agent is
told it was stopped and that you were asked, so it tells you and tries
again after you answer. Where Mandu's guard runs (Linux, the `confined`
posture), an allowed command runs as a program that read those files does:
it may connect only to the hosts they are bound to, and the files it
writes are marked secret, so the next session reads them masked. Without
the guard the card says the command runs with the network your agent's
commands normally have and that its files are not marked: read the command
on the card before you allow it. When such a command tries another host,
its request is stopped and a card asks you, as for the agent's own
request to that host ("… ran a command that wants to connect to …"): the
command holds data from what the session read, so the card says that
*Allow once* lets the next try through, once. The agent is told you were
asked; when it runs the command again after your answer, that one
connection goes, and the try after it asks again. *Block* stops the
session's requests to that host for good.

**A network or FUSE mount turns real reads off.** A program that holds a
secret sends every file name it looks up on an NFS, SMB or sshfs mount
(any FUSE file system, an automount point) to that mount's server, and
Mandu cannot check each lookup. So while such a mount is visible, a
program you named as a reader gets the placeholder copy instead of the real
file. The launch names the mounts (`mandu: network or FUSE mount visible to
the AI's programs: /home (nfs4 from nas:/home)…`), and `mandu doctor` lists
them under "Your secrets". If your home is on NFS and you trust its server
with the names, list the mount under `remote_mounts: trust_lookups:` (its
mount point and type, as the launch prints them); that is a loosening, so
a hand edit waits for your OK like any other. Binding the secret to
the mount (`bindings: ["mount:nfs4:nas:/home"]`) works too, and also lets
the program write there. A share from the virtual machine's host or from
Windows under WSL (virtiofs, 9p over virtio, `/mnt/c`) does not count.

You do not have to write `paths:` by hand. On the dashboard's Rules page,
**Your rules** lists the files, folders and patterns that have a rule of
yours, as a tree, one row each. A row says what the rule covers, then has
two menus, one per question. **Which AI may read it** has the four labels,
from strictest to loosest: No AI, Your own AI only, Any AI, when it asks,
Not secret; pick another to change the rule, or "Remove my rule". **Where
it may be sent** has Needs your OK (the default: every send asks you, but for a key sent to its own issuer's API host, above),
Listed hosts without asking (the hosts show as chips under it; Edit, or
choosing it, opens the row with the hosts field, then press Update) and Not
secret, which is the same choice as in the first menu. Under a rule's name,
*Opens it* says which programs may open the real file: `ssh` (checked by
Mandu), a program you vouched for with `prints: nothing` (your word), or
none, so programs get a masked copy; add one in policy.yaml. The **⋯** at the end of a row opens the rest under it: where the
label comes from, the hosts to add or change (then press Update), its lines
in policy.yaml, and what the rules say about it (which programs get the real
file, where it may be sent, which programs have read it).

**Find a rule**, beside the heading, narrows Your rules to the rows that
mention what you type: a file by its path (`~/proj/.env`), the programs that
may open it or the hosts it may be sent to; a sending rule by its host or
file; a connection by its address or port. The folders on the way to each
match open, and the count reads "3 of 27". It only hides rows on the page:
Changes to save still lists and saves every waiting change. Escape or Clear
empties it, and it is empty again whenever you come back to Rules.

**Add a rule** opens a file browser: your own files one folder at a time,
each file or folder with the same label menu, showing the label a read gets
today. A label it gets from somewhere else (a folder, a pattern, a built-in
secret) reads "(inherited)", with where it came from under the name ("From
your rule on ~/proj", "Built in: SSH keys", "Written by the AI after it read
a secret"). Its *Where it may be sent* shows greyed, with a ring for a
dot: hold the pointer on it to read which rule it follows. Change that
rule, or give the file a label of its own in the first menu. A folder with rules inside says so. Tick several rows and the bar
under the list labels them together. On a phone the menu sits under the
name. Your choices wait under Changes to save, kept at the bottom of the
window; however many wait, the list scrolls inside it and Discard and Save
stay in view. Save writes them to
`paths:` as one change you can undo under Rule changes in Approvals. A folder covers
everything inside it, except files with a rule of their own. A change that
makes protection weaker (a built-in secret made "Not secret", a secret made
readable by the AI, a rule removed) is listed for you to check before it is
saved, with an optional reason kept with the change. You can also type a path, a
file that does not exist yet, or a pattern such as `**/.env`; a pattern
shows which files it would match before you choose it. While changes wait
to be saved, the explorer says what they would do to the files under them
("Changes the label of 12 files, 3 of them less protected"), and the
question before a weaker change names those files, so marking a folder "Not
secret" shows you the `.env` or key inside it first. A rule you choose for
a symlink is written on the file it points to as well. Rules made on this
page before it wrote `paths:` can be moved there with one button, unchanged.
The explorer lists names only and never opens a file. It is shown to your
dashboard session only, not to other programs on this computer.

**Who may get your secrets**, under Your rules, reads the same file rules
the other way round, in three tabs. **Programs**: for each program a rule
names (`deploy`, `ssh`, `python3 running ~/proj/report.py`), the files it
opens raw and how each lets it (checked by Mandu, or your word,
`prints: nothing`), the ones it gets a masked copy of, the ones it never
gets because it prints or runs what it reads (a database shell), and the
ones it is refused; then any other program. **Hosts**: for each host on a
rule, the files whose real value goes there without asking; any other host
gets no secret without a rule or your OK. **AI**: what any AI (your agent's
and Mandu's helper) reads as written, may read when it asks, or always
sees masked, and the same for each AI of your own listed in Settings,
Models. It covers your rules (policy.yaml and the labels made on the page),
not the built-in protections or your answers. It changes nothing: press a
file to open its rule under Your rules, and change it with that row's
menus.

**Keys Mandu found**, a section of its own on the Rules page (open it with
Review), lists keys Mandu found that no rule covers yet: a deploy key that was committed and later deleted, a token that once
sat in a file that is harmless now, or a key in a file you have now, such as
`deploy/staging.tfvars`. Press **Scan for keys** to scan the files and the git
history of the projects your agents worked in (or type a folder to scan
another project). Tick **Also look in your home folder** to also read the
files there that are named like settings or keys (on macOS it skips
`~/Library`, `~/.Trash`, `~/Pictures`, `~/Music` and `~/Movies`). The scan runs inside
Mandu's protection service and sends the page only file names, commit ids,
the kind of key, its line and its first characters, never the key. A file
your rules already protect is not opened. Each suggestion waits under Changes to save,
ticked, labeled "No AI"; untick one to skip it, and Save
applies the ticked ones, each as its own change you can undo. A file only
git history still holds is greyed and tagged "only in git history"; old
versions of a file that is harmless now sit under that file (this version of
Mandu cannot hide old versions yet, so those rows say so and cannot be
ticked). A key in a file you have now is an ordinary row; the AI stops
seeing that file from the next time an agent starts. On macOS a launch
hides no git history: a rule makes a file you have now unreadable to the
AI, but its committed versions stay readable, and each row found in git
history says so. Open a row to see what the scan found and when (or on
which line), and the lines Save adds to `policy.yaml`.
**Not a secret** tells Mandu to stop suggesting it. A key that was committed
was exposed: a rule keeps the AI from reading it from now on (on macOS, only
in the file as it is now), but you should
still replace it. For a key in a file you have now, replace it if an AI
session read that file before. When the scan finds something, the Approvals
page shows one card, such as "Mandu found N possible keys in this project's
files and git history", that opens this view.

To keep one program away from a file, name the programs that may read it.
There is no block list: a list of what may *not* read a file would leave
every other program with the bytes, which is the fail-open reading of the
same wish. With `readers:` set, an unlisted program is refused; `others: twin`
gives it the placeholder copy instead, without asking you first even when it is
a program known to use that file. The AI's own process is never a reader.

A program on the list gets the real bytes only when Mandu knows it keeps
them out of what it prints: `ssh` and `ssh-add`, the programs checked not
to print a file they are pointed at.
Any other program you name reads the placeholder copy, and Mandu says so
beside the entry ("reads the placeholder copy") and in `mandu why <file>`.
If you know a program of yours keeps the file's contents out of what it
prints, writes and sends, say so with `prints: nothing`:

```yaml
paths:
  - path: ~/proj/.env
    level: no-model
    readers: [{ app: deploy, prints: nothing }]
```

That is your word, not something Mandu checks. It is separate from
`output:`: `deploy` reads the real file and what it prints still reaches
the AI masked unless you also write `output: clear`. With prompting on for
every program, a program Mandu does not know is held in Approvals with a
warning that it may pass on what it reads; *Always allow* writes `prints:
nothing` for you. An answer you gave before 2026-10-04 to the older
question, which did not say that, is asked again. `git` and its credential
helper print what they read, so they never get the real file; `aws`, `gh`,
`docker`, `kubectl` and `helm` are not on the list yet (nobody has checked
them), so they read their credentials as the placeholder, which logs in
where Mandu's proxy inspects HTTPS (`gh`) and fails where it cannot (`aws`
signs with the key, `kubectl` and `helm` trust only the cluster's
certificate, `docker`'s daemon logs in outside the session): add `prints:
nothing` for the one you trust. `psql` and `pg_restore` print files when
asked (`psql -f`, `\i` or `\copy … from` a file, `pg_restore` writing a dump
out as SQL), and so do `mysql`, `mariadb` and the other SQL shells (`source`,
`\!`, a `pager=` in `~/.my.cnf`), so they never get the real file, your word
or not: a login from `~/.pgpass` or `~/.my.cnf` fails under Mandu (no
database protocol has a placeholder release on the wire). A login with
`PGPASSWORD` or `MYSQL_PWD` fails too: Mandu masks them like any password
variable, as it masks `DB_PASSWORD` or the password in a
`postgres://user:password@…` `DATABASE_URL`. The ways out, for Postgres and
MySQL alike:

- A login over the local socket that needs no password: Postgres's `peer`
  authentication, MySQL's `auth_socket` or MariaDB's `unix_socket` plugin.
  Add the socket's folder (often `/var/run/postgresql`, or `/run/mysqld`)
  under `unix_sockets: allow:`.
- A program of yours other than these shells that logs in itself, named as
  a reader of the password file with `prints: nothing` (your word that it
  keeps the password out of what it prints), and the database in that
  file's `bindings:`, since a program holding the real password may connect
  only there:

  ```yaml
  paths:
    - path: ~/.pgpass                       # or ~/.my.cnf
      level: no-model
      readers: [{ app: nightly-report, prints: nothing }]   # your program, never psql or mysql
      bindings: ["db.internal:5432"]        # over the local socket: "unix:/var/run/postgresql" (and that folder under unix_sockets: allow:)
  ```

  Without `prints: nothing` it reads the placeholder copy, and the login
  fails.
- `env: { exempt: [PGPASSWORD] }` (or `MYSQL_PWD`) in `policy.yaml`, which
  hands the agent the password as it is, so the AI can read it.

`pg_dump` and `mysqldump` are not on the checked list either; add `prints:
nothing` for one if you trust it.

Name the program that needs the file, never a shell, an interpreter or a
program that prints the file (below). A
`bash`, `node` or `python3` reader would run whatever script the agent
writes, so such an entry lets **no** program read the file:
`readers: [bash]` does not admit `bash -c '. .env; ./deploy.sh'`, and
`readers: [python3]` does not admit `python3 -c 'open(".env")'`, nor any
`python3` run that is not a pinned script. The same goes for launchers such
as `env`, `xargs`, `awk`, `make`, `tmux` or `valgrind`, for editors (`vim`,
`emacs`, `nano`, …: `vim -c`, a modeline or a vimrc runs commands), and for
clients that run a command they are given (`ftp`'s `!cmd`, `aria2c
--on-download-complete`, `wget --use-askpass`, `lftp`, `sftp`, `rclone`),
and for build tools that run their build file's code (`cmake`, `ninja`,
`go`, `cargo`, `gradle`, the TeX engines, …), under a versioned name too
(`php8.5`, `lua5.4`). `cargo` therefore reads `~/.cargo/credentials` as
the placeholder: while Mandu's proxy inspects the session's HTTPS (the
default in `secrets` mode) it puts the token back on the way out; with
`MANDU_WIRE_TWIN=0`, or TLS inspection off, `cargo publish` fails its
login instead. A
copy of one of these programs under another name is still that program,
even pinned by path and hash: `cp /usr/bin/python3 ~/bin/mytool` listed as
`{ app: mytool, path: ~/bin/mytool, sha256: … }` lets no program read the
file, since Mandu hashes the shells, interpreters and launchers installed
on your machine and recognizes a byte-identical copy anywhere; `mandu why`
says "mytool is a copy of python3.12". An interpreter that is no such copy
(a `pyenv` python, an `nvm` node, a static `busybox`, renamed `mytool`) is
recognized by its content: the program that runs it finds the interpreter's
own command-line entry in the file (for python, perl, ruby, node, lua,
LuaJIT, Tcl, Java, PHP, R, julia, guile, Racket, bun, deno, PowerShell,
the `dotnet` host, elvish, nushell, BusyBox, toybox, bash, zsh, dash, ksh
(ksh93 and OpenBSD's), mksh, posh, yash, fish, tcsh and csh), and such a
run is refused too. A program built with `bun build --compile` is bun to
Mandu, so it reads no secret raw either. So is a printer or a launcher of
GNU coreutils, findutils, util-linux, diffutils, sed, grep or tar that is
no such copy (another version, a static build, renamed `mytool`): it
carries its package's own text, and reads the file as any printer does,
even with `prints: nothing` on its entry (the checksum tools, such as
`sha256sum`, stay readers). Mandu never asks you about such a run
either (the code it runs is the agent's, and you would be approving code
nobody showed you). The arbiter's log, the dashboard ("admits nothing" beside
the entry) and `mandu why <file>` point at the entry and say what to write
instead. Do one of these instead:

- name the program that actually needs the file (`aws`,
  `docker-compose`, with `prints: nothing`), the usual answer;
- pin your own script with its interpreter, as below.

Do not name a program that prints or copies the file either. `cat`,
`head`, `tail`, `less`, `base64`, `xxd`, `od`, `strings`, `sed`, `awk`,
`grep`, `sort`, `cut`, `tr`, `diff`, `cp`, `dd`, `tee`, `rsync`, `tar`,
`gzip`, `zip`, `jq`, `yq`, `envsubst`, `openssl`, `gpg`, `busybox` and the
like hand the file's bytes to whatever reads their output, which can be
the AI's own code (`cat .env | python3 -c '…'`), and that code could leak
the value through what Mandu does not follow, such as the names of files
it creates. So such an entry lets **no** program read the
file, even pinned by path and hash: `readers: [cat]` gives `cat` the
placeholder copy (or `Permission denied` without `others: twin`), and
`. <(cat .env)` or `eval "$(cat .env)"` hands your shell the placeholder,
not the value. Mandu never asks you about such a program, and an *Always*
answer does not count for one. The dashboard marks the entry
"(admits nothing)", and the arbiter's log and `mandu why <file>` say why.
On a host whose coreutils is a single program (Ubuntu 26.04's), every
coreutils program counts as one of these, `wc` and `sha256sum` included.
The same goes for a launcher or a printer under the name a distribution
gives it (`gnucat`, `gnuenv`, `gtimeout`, `uu-env`), for `toybox`, and for
`nc`, `ncat`, `netcat` and `socat`, which can run a program they are given.
So do programs that print a file through an option although printing is
not their job: `file -f .env` prints every line of `.env` as a name it
cannot open, and `date -f`, `wc --files0-from=`, a compiler's `-E` or
`@file`, `nroff`, `man -l` and gettext's `msgcat` do the same, so
`readers: [file]` gives `file` the placeholder.
Programs that fetch or copy a URL or a file count as printers too, since
they print a local file as readily (`curl file:///…/.env`, `wget`, `scp`,
`sftp`, `rclone`, `gio`, `lynx -dump`): `readers: [curl]` gives `curl` the
placeholder. `curl` still logs in with your `~/.netrc` while Mandu's proxy
inspects the session's HTTPS (the default in `secrets` mode): it sends the
placeholder and the proxy puts the password back on the way out; with
`MANDU_WIRE_TWIN=0`, or TLS inspection off, a `curl --netrc` or `wget`
login fails instead. A placeholder on the command line works the same way:
after `. ./.env`, a `curl` to `https://api.stripe.com/v1/customers` given
`$STRIPE_KEY` as its HTTP Basic user (`-u`) runs with the placeholder in its
arguments (Mandu never writes a secret's
real value into a command line), and the proxy puts the value in only in a
request to a host the file is bound to (`bindings:`, above); to any other
host the request waits in Approvals and curl gets a 403. `git` is one too (since 2026-10-04): `git diff
--no-index /dev/null .env`, `git grep --no-index` and `git config -f`
print any file it is pointed at, so `readers: [git]` gives `git` the
placeholder, and `git credential-store` (the helper behind
`credential.helper=store`) reads the placeholder copy of
`~/.git-credentials`. Under the proxy's TLS inspection `git push` over
HTTPS still logs in, as `curl` does; with `MANDU_WIRE_TWIN=0`, or TLS
inspection off, it fails. Over SSH nothing changes: `ssh` (list it as `{
app: ssh, from: git }` to admit only the ssh that git starts) reads the key,
not `git`. A copy of one of these programs under another name is
still one, even pinned by path and hash: Mandu recognizes a byte-identical
copy of a printer installed on your machine. And an old question about such
a program still waiting in Approvals is removed (Mandu drops it when it
starts and whenever it lists the queue); answering it from a stale page is
refused with the reason, as the answer would change nothing, and allows
nothing.
The `ssh_agent:` readers follow both rules too: a
program there that prints, relays or runs code (`socat`, `nc`, `openssl`,
`env`, `bash`) never reaches your ssh-agent, nor does a copy of one under
another name (by its hash, as for files, or an interpreter by its content:
Debian's `perl5.40.1` is `perl`); name `ssh`, `ssh-add` or `git`. Mandu's
arbiter is asked about each program that connects there, so while it is
down your ssh-agent is refused to the agent's programs.
The full list is in the design notes
([confidentiality plan 13](design/confidentiality/confidentiality-plan-13-reader-set-labels.md), §3 D8).
What to do instead: name the program that uses the secret (`aws`, your own
tool, with `prints: nothing`), which reads the file itself, or pin your own script with
its interpreter, as below.

npm is the one built-in case: it runs as `node`, so it reads `~/.npmrc`
through the placeholder copy Mandu fills in on the way to the registry; an
`.npmrc` that copy cannot serve (a `cafile`, your own proxy, a session
without Mandu's HTTPS proxy) leaves npm unauthenticated under Mandu: remove
that setting, or run that npm command yourself. pip is the same: it runs as
`python3` and reads the placeholder copy of `pip.conf`, and Mandu fills in an
index password on the way to that index.

When the program that needs the file is your own script, name the script
with its interpreter: `readers: [{ app: python3, script: /opt/tools/report.py }]`.
That entry admits `python3` only while it runs exactly that file: the script
and every folder above it must be out of your user's reach (as under `/opt`
or `/usr`, owned by root), it must be named by its absolute path (`python3
-I /opt/tools/report.py`, not `cd /opt/tools; python3 report.py`), the
interpreter must not load per-user code (python with `-I` or `-s`, so your
`~/.local` site-packages is not read; node with `--no-global-search-paths`;
zsh with `-f`), and nothing may be tracing it. Inline code (`python3 -c`,
`node -e`, `bash -c`), a module (`python3 -m`), a copy of the script
elsewhere, or an interpreter variable Mandu was not launched with is not that
reader. The first use pins the interpreter and the script's hash; a changed
script asks to be pinned again. Such an entry may carry `output: clear` or
`mask` like any other program's, and the output is then shown only while the
script ran no other program in the tool call (a program it starts could be
one the agent put on the `PATH`). Python, node, the POSIX shells and perl can
be pinned this way; ruby cannot (its per-user gem folder loads code).

When you answer a hold in Approvals, the card names the program's full path, and
your answer holds for that file as it is: allowing `/usr/bin/deploy` allows no
other program called `deploy`, and a rebuilt `deploy` asks once more. For an
interpreter the card names the script too ("python3 running
/opt/tools/report.py"), and your answer holds for that script only: another
script, a changed one, or `python3 -c` asks again. A shell running the
agent's own command ("bash running its own code") is asked about each change
it makes to a protected file, and offers no *Always*.

An answer given before Mandu named programs this way (before October 2,
2026, a card that named only `psql` or `nano`), or one about a program that
prints what it reads, applies to nothing now. Approvals › *Answered earlier*
and the Rules page say so on that answer ("This answer no longer applies: …")
and offer no change to it; a question of that kind still waiting is dropped,
and Mandu asks again about the program's file.

A name in `readers:` (and a well-known program reading its own file, such as
`ssh` and your key) becomes a pin the first time it is used, but only
from a program the agent could not have written: one whose file and folders
your user cannot change, as under `/usr/bin`. A program of that name in your
project, in `/tmp` or in your own `~/.local/bin` asks you first in
Approvals instead (with `--secrets-ask=never` it is refused). A reader started
with `LD_PRELOAD`, `LD_LIBRARY_PATH` or another loader variable, or an
interpreter started with its own (`PYTHONPATH`, `NODE_OPTIONS`, …), set to
anything other than what Mandu was launched with, is not that program: it
gets the placeholder copy or `Permission denied`, without a question. The
same holds for `from:` (the parent must be the real program) and for the
`ssh_agent:` readers. A `from:` parent is a program started inside the
Mandu session: whatever started `mandu` itself (a `python3` or `node`
running your IDE's or notebook's terminal) is never one, and neither is a
parent that has exited (its children have lost it).

A reader is also not that program when its command line or environment
hands it code to run: `git -c alias.x='!…'`, `git -c
core.pager=…` or `GIT_SSH_COMMAND` with anything but plain `ssh`, `ssh -o
ProxyCommand=…` / `LocalCommand` / `KnownHostsCommand` / a PKCS#11 or
security-key library / `-F <file>`, `scp -S`, `sftp -b`, `psql -f` or a
`\` meta-command in `psql -c`, `less +…` or `LESSOPEN`, `sed` with an `e`
command (run `sed --sandbox` to keep it a reader), `tar
--to-command` / `--checkpoint-action=exec` / `-I`, `rsync -e` with anything
but plain `ssh`. Such a run gets the placeholder copy or `Permission
denied`, without a question; the same program with a plain command line
still reads. If you used a `ProxyCommand` on the command line to reach a
host with a key Mandu protects, put it in `~/.ssh/config` (Mandu asks you
before the agent changes that file) or use `-J` / `ProxyJump`. Editors,
debuggers and tracers (`vim`, `nvim`, `ex`, `emacs`, `ed`, `gdb`,
`strace`, `sqlite3`, …) run code they load or are given, like a shell, so
naming one alone admits nothing, and a change one makes to a file Mandu
protects is asked about each time.

A file a reader writes carries the secret's level, and no reader list: if
a reader copies `.env` to `copy.txt` (your own tool; `cp` itself is no
reader, as above), every other program (the AI's
own included) reads `copy.txt` as a placeholder, also after `mv copy.txt
other.txt` or `ln`, and in later sessions, and a program holding the copy may
send it nowhere but Mandu's proxy. A program that already holds the original
(a reader, or a program a reader started) reads the copy as it is, unless
it is a program that prints or copies files, which gets the copy's
placeholder. To use such a copy, name its reader under
`paths:` like any file, or clear its label in the dashboard. While Mandu's
arbiter cannot be reached, a program's read of a file changed in this session
is refused rather than left unchecked.

npm needs no real `~/.npmrc` in most setups. When every token in the file is
written for a registry (`//registry.npmjs.org/:_authToken=…`, `_auth`, or a
`username` with its `_password`), npm, yarn and pnpm read the placeholder
copy, and Mandu's egress proxy puts the token or password back only in
HTTPS requests to that registry, and only in their `Authorization` header
(the same placeholder in a request's body, address or another header gets
the request refused). A plain `http://` request gets nothing, even
to that registry, unless the same file declares it as an `http://` registry
(`registry=http://…` or `@scope:registry=http://…`). So `npm` and the MCP servers you start with `npx`
hold no secret, and their output reaches the AI as usual. A token not written
for a registry, your own proxy or CA settings in the file, or a registry in
`NO_PROXY` keeps npm off the placeholder: since 2026-10-04 npm then reads
the placeholder copy too, unless you vouch for npm's script with `prints:
nothing` (npm is not a program Mandu has checked), when it reads the real
file and its output is masked. `MANDU_WIRE_TWIN=0` turns this off for a launch. If Mandu's
protection service restarts during a session, npm keeps reading the
placeholder copy; nothing carries over to a later launch. `npm login` and
`npm config set` change only the placeholder copy while Mandu runs; run them
outside Mandu.

pip works the same way with a private index. When `index-url` or
`extra-index-url` in your `~/.config/pip/pip.conf` (or `~/.pip/pip.conf`), or
the `PIP_INDEX_URL` / `PIP_EXTRA_INDEX_URL` you launch with, carries a
password (`https://user:password@pypi.example.com/simple`), pip reads a
placeholder in its place, and Mandu's egress proxy puts the password back
only in requests to that index's host, only in their `Authorization` header,
over the index URL's own scheme: an
`https://` index's password never travels in plain HTTP, even to that host.
A request carrying the placeholder to any other host is refused. An index on
an IPv6 address (`https://user:password@[2001:db8::1]:8443/simple`) works
the same way: the password goes back only to that address, however it is
written (`[2001:DB8:0::1]` is the same address); one written with a zone id
(`[fe80::1%25eth0]`) gets no release. pip trusts Mandu's proxy through the
`REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE` the launch sets; a `cert =` or
`proxy =` of your own in `pip.conf`, or the index in `NO_PROXY`, sends pip
around Mandu's proxy or makes it distrust it, and the login fails (the
password is never sent). A `pip.conf` in your project (not your home) gets no
such release: the agent can write it.

A sourced variable never exists in the clear in the agent's world: Mandu
reads it when you launch (a keyring or 1Password unlock prompts in your
terminal), and the agent gets a placeholder that is put back only on its
way to the bound hosts. If the source fails, the launch says so and falls
back to the variable from your shell, masked. The value is read once per
launch; a token that expires mid-session needs a relaunch.

An environment-variable secret reaches every program as a placeholder and is
put back only on its way to a bound host over the wire; a signing credential
that a program must hold (`AWS_SECRET_ACCESS_KEY` for a signed request)
should stay in its file, where a reader can get the bytes.

#### Use your own model (e.g. Ollama)

A file labeled `local-model` may be read by a model you or your organization run and by
no outside model. When the AI asks its quarantined helper to summarize such
a file, the helper sends it to your model instead of the vendor's, and the
answer comes back to the AI as a placeholder it can put in its reply but
cannot read (you see the real answer). The AI's own main model reads the
file only if that model is your own too ("Your own model as the AI's
main model" below). This works in
`secrets` mode.

1. **Run the model server on this machine only.** Install
   [Ollama](https://ollama.com) and keep it listening on `127.0.0.1`
   (`OLLAMA_HOST=127.0.0.1 ollama serve`, or Ollama's service, which listens
   there by default), not `0.0.0.0`. How to set up a server you call your own
   (one user, no request history, no telemetry, no cloud models) is in
   [guarantees.md](guarantees.md) §3.
2. **Load a model:** `ollama pull llama3.2`.
3. **Declare it in `policy.yaml`:**

   ```yaml
   models:
     - name: ollama                 # your name for it, shown by mandu doctor and the dashboard
       url: http://127.0.0.1:11434  # the server's base URL (Mandu adds the API path; a trailing /v1 is dropped)
       wire: openai-chat            # openai-chat (Ollama, vLLM, LM Studio) or anthropic (the default)
       model: llama3.2              # required for openai-chat
       local: true                  # you declare it; Mandu never decides from the address
   ```

   The keys are exactly `name`, `url`, `wire`, `model`, `local`,
   `token_env`, `helper`, `allow_plain_http` and `tls`; any other key stops the
   file from loading. Without `model:`,
   an `openai-chat` entry loads, but the helper refuses every call with
   `your declared model 'ollama' is unusable: … a model id is required`. An
   entry without `local: true` counts as an outside model. If the server
   wants a bearer token, add `token_env: OLLAMA_BEARER`: the NAME of an
   environment variable, never the token itself (the file refuses a value
   that is not a variable name). Set the variable in the shell that runs
   `mandu` (`OLLAMA_BEARER=… mandu claude`). Mandu treats it as a secret: the
   agent sees only a placeholder, the helper gets the real value for
   `local: true` entries only, and only that model's host receives it. Leave
   `token_env` out when the server needs no token (a default Ollama does
   not).

   **A model on another machine** (a vLLM, TGI or LiteLLM server on your
   organization's network) must be reached over `https` when it says
   `local: true`: files labeled `local-model` go to it, and plain http would
   carry them across the network unencrypted. A plain `http://` url to
   another machine stops the file from loading with `'<name>' is on another
   machine and would receive local-model files in the clear`. Put the server
   behind https, or reach it through a tunnel on this machine
   (`ssh -N -L 18000:127.0.0.1:8000 gpu-box`, then
   `url: http://127.0.0.1:18000`). For a lab server on a network you trust,
   you can accept the risk for that one entry with `allow_plain_http: true`;
   every launch then prints a `WARNING` naming it, and `mandu doctor` marks
   it ✗. The setting covers only the helper: a main model
   (`ANTHROPIC_BASE_URL`) on another machine still has to use https.

   When the server's certificate comes from your organization's own CA, or
   you want to be sure it is that server and no other, say so under `tls:`:

   ```yaml
   models:
     - name: corp-vllm
       url: https://llm.ml.corp.example/v1
       wire: openai-chat
       model: Qwen/Qwen3-32B
       local: true
       token_env: CORP_LLM_TOKEN
       tls:
         ca_file: /etc/ssl/corp/root-ca.pem         # trusted for this server only
         pin_sha256: [ "<base64 SHA-256 of the server key's SPKI>" ]   # any one in the chain matches
         client_cert: ~/.mandu/corp-llm.crt  # for a server that requires mutual TLS
         client_key: ~/.mandu/corp-llm.key   # a file path; the key never goes in policy.yaml
   ```

   Every key is optional; `client_cert` and `client_key` go together, and
   the key must have no passphrase. A pin is what
   `openssl x509 -in server.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`
   prints; list two during a key rotation. The files are checked when the
   policy file loads (each must exist and parse, the key must match the
   certificate), and the checks run in every TLS handshake to the server:
   the helper's, the model proxy's when the entry is your main model, and
   `mandu doctor`'s, which says "TLS checked (your CA, a pinned key, a
   client certificate)" or why it was refused. The key file is treated as a
   secret: the agent sees a placeholder in its place.

   To hold every model you call local on another machine to your
   organization's own networks, list them under `perimeter:`:

   ```yaml
   perimeter:
     networks: [ 10.0.0.0/8, 172.16.0.0/12, "fd00:1234::/32" ]
     domains:  [ corp.example ]      # words only: doctor and Settings say "on your organization's network"
   ```

   With `networks` present, the name of each such entry must resolve only to
   addresses inside those networks. Mandu resolves the name once per
   connection, checks every address it got, and connects to a checked one
   (keeping the name for the certificate check), so a DNS answer that moved
   the name elsewhere sends nothing. The launch refuses an entry whose name
   resolves outside (`resolves to 203.0.113.9, outside perimeter.networks`),
   a policy file naming a literal address outside does not load, and
   `mandu doctor` shows a ✓ or ✗ row for each entry. The rule does not apply
   to a model on this computer or to an outside model. `domains` checks
   nothing: a name ending in your domain can still resolve anywhere.

   **Models your organization sets.** An administrator can install files
   under `/etc/mandu/policy.d/` (any `*.yaml`, read in name order when the
   protection service starts and again within a few seconds of a change)
   with `models:`, `perimeter:` and `models_locked: true` (and
   `sensitivity_labels:`, the organization's label mapping; a user's
   mapping of the same label can raise its level, never lower it), in the
   same format as `policy.yaml` (use absolute paths under `tls:`: a `~/`
   path means the home of whoever runs Mandu):

   ```yaml
   # /etc/mandu/policy.d/10-corp.yaml
   models:
     - name: corp-vllm
       url: https://llm.ml.corp.example/v1
       wire: openai-chat
       model: Qwen/Qwen3-32B
       local: true
       tls: { ca_file: /etc/ssl/corp/root-ca.pem }
   perimeter:
     networks: [ 10.0.0.0/8 ]
   models_locked: true
   ```

   Their entries come before yours, and Settings shows them as "Set by your
   administrator". Without the lock, an entry of the same name in your
   `policy.yaml` changes theirs. With it, you can remove one of theirs
   (Settings' Remove writes `- { name: corp-vllm, disabled: true }` to your
   file, and *Bring back* removes that line again) or add an outside model,
   and nothing else: adding a model of your own, or changing their entry's
   url, tls, local, helper or allow_plain_http, is refused with "set by
   your administrator (/etc/mandu/policy.d/10-corp.yaml)". Their
   `perimeter: networks:` holds with or without the lock: yours may narrow
   it, not widen it.

   Their settings win. If they change while your `policy.yaml` has
   something they now refuse (a model of your own when a lock arrives, say),
   your line stays in the file but is not used; Settings lists it under
   "Not in use, because your administrator's settings take priority", and
   `mandu doctor` shows a ✗ row for it. Mandu still starts. A file there
   that cannot be used stops the protection service from starting; one
   that breaks while it runs is ignored and the settings read before stay
   in force, and doctor and Settings say so.

   **The bubblewrap your organization picks.** The same files may set
   `bwrap_path: /opt/bubblewrap/bin/bwrap` (one absolute path on its own
   line), like Claude Code's managed `sandbox.bwrapPath`: Mandu then runs
   that bubblewrap in place of the one on PATH (for the mount layer, the
   command box, the git sandbox and the prompt-filter plugins; `mandu
   setup` copies it, and its folder goes first on the agent's PATH, so give
   it a folder of its own). It counts only when the file, the binary and
   every folder above each are owned by root and writable by no one else;
   a file someone else could write is ignored. One that is set but cannot
   be used means no bubblewrap at all, never the one on PATH instead: every
   launch says why, `mandu doctor` shows a ✗ row, and `mandu setup` stops
   with the same reason. No setting of your
   own, and no environment variable, can name a bubblewrap.
4. **Label a file:** `level: local-model` under `paths:`, or "Your own
   model only" in a row's label menu on the dashboard's Rules page
   (offered once a model of your own is declared).
5. **Relaunch the agent.** The helper's network access is fixed when the
   agent starts: its sandbox may connect only to the ports of the models
   declared at that moment. After adding or changing `models:`, stop the
   agent and launch it again (the arbiter picks up the file by itself).
6. **Check it:** `mandu doctor` shows a "Your own models (policy.yaml
   models:)" section, for example

   ```text
   Your own models (policy.yaml models:)
     ✓ ollama: http://127.0.0.1:11434 (openai-chat, model llama3.2, your own model): reachable, llama3.2 is listed
   ```

   A ✗ row says what is wrong: `not reachable; start the model server, or
   fix the url in policy.yaml`, or `llama3.2 is not listed at …/v1/models;
   load it on the server (for Ollama: ollama pull llama3.2)`. Then ask the
   agent to summarize the file. In the dashboard, that step of the story
   says "Read by your own model (ollama)."

Declaring a model counts as loosening your rules, so if Mandu is running
when you add the lines of step 3 by hand, approve the change on the
dashboard's Approvals page (see above).

Steps 3 and 6 can also be done in the dashboard: Settings › Models adds,
edits and removes an entry (it asks you first, then writes the same
`models:` lines to policy.yaml), and its "Test connection" button runs the
same checks as `mandu doctor`. A running agent still needs the relaunch of
step 5 to use a change.

If your model is not running, the helper refuses and says so; it never asks
another model instead. A model that loads slowly the first time (a large
Ollama model can take a minute) may need a longer wait:
`MANDU_ULLM_ENDPOINT_TIMEOUT_MS=180000 mandu claude` (the default is 60000).
Mandu controls where the bytes go (the address you named, and nowhere
else); what that server does with them is yours to decide, so `mandu
doctor` warns when a model you called local is not on this machine or a
private network.

**Your own model as the AI's main model.** For Claude Code, declare a
server or gateway that speaks the Anthropic Messages API with
`wire: anthropic` and launch with `ANTHROPIC_BASE_URL` set to exactly its
`url`, for example
`ANTHROPIC_BASE_URL=http://127.0.0.1:4000 mandu claude`. Mandu keeps its
model proxy in front of that model, so masking stays on, and when the
entry is `local: true` the AI may read a `local-model` file into the
conversation with `declassify_symbol` (logged, and the session is then
marked as holding secret data, exactly as for `any-model`). A model on
another machine must be reached over https.

Codex works the same way through its own base URL. Declare the server with
`wire: openai-chat` and its OpenAI base URL (usually ending in `/v1`), then
launch with `MANDU_OPENAI_BASE_URL` set to exactly that URL, for example
`MANDU_OPENAI_BASE_URL=http://127.0.0.1:11434/v1 mandu codex -m gpt-oss:20b`.
Mandu keeps its model proxy in front of it and forwards Codex's requests to
that base. The server must speak the OpenAI Responses API (`/v1/responses`),
which is what Codex sends. Not every server does (Ollama 0.9.6 answers 404
there); `curl -s <url>/responses -d '{}'` shows whether yours has the route.
The helper adds its API path (`/v1/chat/completions`, or `/v1/messages`
for `wire: anthropic`) to an entry's `url` after dropping one trailing
`/v1`, so the Codex entry can serve the helper too. When you declare more
than one `local: true` entry, mark the one the helper should use with
`helper: true` (at most one entry, and only a `local: true` one; the file
refuses anything else). Without the mark the helper uses the first
`local: true` entry in the list. Give the helper's entry a `model:`
(without one, the helper refuses every call to an `openai-chat` entry and
asks an `anthropic` entry for `claude-haiku-4-5`). For one Ollama serving a
Codex main model and a smaller helper model:

```yaml
models:
  - name: codex-main
    url: http://127.0.0.1:11434/v1   # exactly MANDU_OPENAI_BASE_URL
    wire: openai-chat
    model: gpt-oss:20b
    local: true
  - name: ollama-helper
    url: http://127.0.0.1:11434
    wire: openai-chat
    model: llama3.2
    local: true
    helper: true                     # the helper reads local-model files with this one
```

`mandu doctor` adds `the helper uses it` to that entry's row, and Settings ›
Models sets the mark with "Read my own-model files with this one".
`codex --oss` and `--local-provider` stay refused under Mandu, because they
bypass its proxy; the declared base URL is the supported route. `codex
--remote` and `codex agents` are refused too: they connect to a Codex
background server that Mandu did not start and does not protect. So are the
subcommands that start or manage such a server, `codex remote-control`,
`codex app-server` and `codex exec-server`, and `codex debug app-server`,
whose model turn would skip Mandu's proxy. Mandu runs Codex without that
server (`--no-daemon`), so the "agents" entry is missing from its footer.
`codex cloud` is refused as well: it runs the task on OpenAI's machines.

Under Mandu, Codex's own uploads are switched off: analytics, the feedback
report, OpenTelemetry export, the update check, and ChatGPT apps and
connectors, because an app that asks for a file makes Codex upload that
file to ChatGPT outside Mandu's model proxy. On a ChatGPT sign-in the launch
says so in one line. A `-c` or `--enable apps` of yours that turns one back
on is refused.

A base URL you did not declare (`ANTHROPIC_BASE_URL` or
`MANDU_OPENAI_BASE_URL` matching no entry) still skips Mandu's model proxy:
the launch warns, and the AI's model then sees what the proxy would have
masked. Every main model that is not a declared `local: true` entry counts
as an outside model, so `declassify_symbol` refuses a `local-model` file
there.

A cloud model is never your own model. Ollama runs models whose tag is or
ends in `cloud` (`gpt-oss:120b-cloud`, `glm-4.6:cloud`) on its vendor's
servers, behind the same `127.0.0.1:11434` as its local models. A `models:`
entry that names one with `local: true` stops the policy file from loading,
and when your main model is a local entry, the AI's request for a cloud
model is refused (`API Error: 400 … mandu: refusing model …`) and nothing
is sent; pick a local model with `claude --model <name>` or
`ANTHROPIC_MODEL`. `mandu doctor` lists the cloud models your local server
offers.

### Checking your own prompt

What you type reaches the AI as you typed it, with one exception that is on
by default: a secret Mandu already holds (a registered key, a masked
environment variable) becomes its placeholder. You can ask Mandu to check
your prompt for more under `prompt_filters:` in `policy.yaml`. The checks
you turn on also cover the text your agent adds on its own (reminders,
project instructions, a title request that quotes your prompt); there a
`block` hides the finding instead of refusing your agent's request, and a
registered secret is always hidden.

Each check is a **filter**, and nothing it finds acts until you say what to
do with it:

- `registered-value` (on by default): the secrets Mandu already holds.
- `key-shapes` (off by default): credentials by their format, even ones
  Mandu has never seen: GitHub, GitLab, AWS, OpenAI and Anthropic keys,
  private keys, passwords in URLs, `API_TOKEN=...` assignments.
- a **pack**: a file of your own patterns and words in
  `~/.mandu/prompt-filters/` (or your organization's, in
  `/etc/mandu/prompt-filters.d/`), switched on by its name.

What happens to a finding is its category's action:

| Action | What the AI receives |
|---|---|
| `log` | your text as typed; the finding is only recorded |
| `redact` (the default) | `[redacted: <category>]`; nothing is stored |
| `mask` | a placeholder; you still see the original, and the AI can use the placeholder in a command, like any secret |
| `block` | nothing: the prompt is refused and your agent shows why. The refused message stays in your agent's conversation; when you send your next message it goes along with the finding replaced by `[blocked: <category>]` |

A category matches by its beginning: `secret.shape: block` covers
`secret.shape.github-token`. An exception lets a finding through:

```yaml
prompt_filters:
  exceptions:
    - { category: pii.email, match: "*@example.com" }
```

A pack is a YAML file:

```yaml
# ~/.mandu/prompt-filters/mine.yaml
pack: my-patterns
version: 1
patterns:
  - id: card
    category: pii.payment-card
    regex: '\b(?:\d[ -]?){13,19}\b'
    check: luhn                             # also kr-rrn-checksum, iban
keywords:
  - category: acme.codename
    words: [falcon, osprey]                 # whole words, any case
```

Its regular expressions use RE2 syntax (no back-references or look-around),
which cannot hang on a long prompt. A list of words your organization keeps
confidential can be stored hashed instead of in plain text (`salt:` and
`hashes:`, docs/design/confidentiality/confidentiality-plan-15-prompt-filter.md §4.2). The
developer dashboard's Prompt filters panel (`/dev/rules`) shows what is on, who
set it, and a test bench that shows what the AI would receive for a text you
paste. In `off` mode every filter only records.

If your organization sets a filter or an action with `locked: true` in
`/etc/mandu/policy.d/`, you cannot weaken it; Mandu says which file set it.
When the locked action is `ask`, you answer each held message on its own:
the Approvals card offers Send as written, Send masked and Cancel the
message for that message only, and Mandu asks again the next time a message
holds it (an answer for the rest of the session is refused, and so is
letting such a finding through for the session: the note under your
message offers it for that message only, and says why).

Approvals › *Answered earlier* lists each answer to a held message by what
went to the AI: "Sent as written", "Sent masked, or cancelled", "Sent as
written for the session". An answer about one message has no button to
change it (that message already went); an answer for the session has *Send
masked instead* or *Send as written instead*, which changes it for the rest
of that session.

**Why is there a placeholder in my conversation?** When a reply or your
agent's history shows a `$MDU:…` where you typed something, ask about it,
quoted so your shell leaves it alone:

```sh
mandu why '$MDU:localmodel_prompt_filter[1a2b]'
```

It says that part of your own message was hidden from the AI, which filter
found it and as what (the category), what Mandu did (hidden, held for your
answer and how you answered, let through), the session and the model
request, and the policy that decides that category now. It then gives the
ways out: let it through for that message or for the rest of the session
(that message only under your organization's locked `ask`) on the dashboard (the note under your message, or the developer view's Prompt
filters › Recent findings; a message still held waits in the Inbox), change
the category's action, or add an exception (Settings › Prompt filters, or
`policy.yaml`). A secret Mandu already holds has no such
way out: it may only go where that secret's own rule allows (`mandu why
<file>` says where). `mandu why` never shows the hidden text; you typed it
and still have it in your terminal. Run it in your own terminal: from inside
the agent it only says which part of Mandu made the placeholder. It looks in
the placeholder's own session and the 24 most recent ones; for a message in
an older session, name it: `mandu why '$MDU:…' --session <id>` (the
dashboard's History lists your sessions). The developer view asks the same beside a
masked value (*why masked?* in a session's Secrets tab); when it finds no
message that carried it, it says how many sessions it looked in and offers
your sessions to look in instead.

**A model of your own as a filter.** A pack can also name a **plugin**: a
program Mandu runs on its own for each new prompt, such as a classifier
that asks a model on your machine which parts are personal or confidential.
Mandu ships one; this writes its pack (it pins `node` and the classifier by
their SHA-256):

```sh
mandu policy classifier-pack > ~/.mandu/prompt-filters/local-classifier.yaml
```

Then turn it on with a model you declared `local: true` (for example
Ollama's `http://127.0.0.1:11434`):

```yaml
prompt_filters:
  filters:
    local-classifier: { on: true, endpoint: ollama }
```

The classifier reads your prompt, so its model must be your own (`local:
true`) or inside your organization's perimeter; any other is refused. It
never sees a secret Mandu already holds, it can reach that model and nothing
else, and it reads nothing in your home folder. It checks the text your
agent adds too. A small local model takes a second or more per new piece
of text (the first one after the model loads takes longer), and it reads a
long message in overlapping pieces of 6000 characters, so a name or phrase
of up to 1000 characters is never cut in two; an answer that
does not come within the pack's `deadline_ms`, or a plugin that cannot run,
blocks the prompt unless you set `on_error: pass` on its switch. Re-run the
command after upgrading `node` or Mandu: a pin that no longer matches blocks
too.

A plugin of your own is pinned the same way: its pack lists the program,
the script and every other file it loads (`modules:`, each with its
SHA-256; [plan 15 §13.5](design/confidentiality/confidentiality-plan-15-prompt-filter.md)),
and the plugin can read nothing else of the folder it was installed in.

---

## What Mandu is doing for you

Which of these are active depends on the mode. The first four rows are the
untrusted-text defense, active only in the frozen `injection` and `full`
modes (see [Frozen modes](#protection-modes-what-mandu-enforces)); the
secrets row is `secrets`; the last row is always on.

| What | What it means for you |
|---|---|
| **Model input** | Untrusted tool output (files, web pages) reaches the model as a placeholder, not raw, so injections can't give instructions. |
| **Your files** | The agent works in a dual-view copy; your real files are synced back cleanly, and sensitive paths are gated. |
| **The network** | Outbound requests carrying untrusted data to untrusted hosts need your approval. Where the kernel supports it, the whole agent is also confined to an allowed set of TCP ports (this part is on in every mode). |
| **Commands** | High-risk commands (`curl`/`wget`/`nc`) built from untrusted data are refused, and read-only inspection commands (`cat`/`grep`/`sed`/…) run inside a no-network sandbox. |
| **Your secrets** | Credential files are replaced, inside the agent's world, by placeholders. A placeholder is turned back into the real value only on its way to a destination the secret is bound to, or after you approve it. |
| **Your replies** | When the agent shows you results, placeholders are resolved back to the real values: *you* see the truth, the model saw the placeholder. |
| **Files that run later** | The agent cannot change Mandu's own settings, records or programs. A change to a file that runs later outside Mandu (your shell startup files, systemd user services, autostart entries, `~/.ssh/authorized_keys` and `~/.ssh/config`, your git settings, the repository's hooks) waits while the dashboard's Approvals page asks you; no answer within a minute means no. The card names the program by its path, and your answer holds for that program file only: another copy or build of it is asked again, and the program run with code the agent could have planted (`LD_PRELOAD` and the like) is refused. `mandu why <file>` lists your answers. On in every mode but `off`, wherever the guard runs. |

You don't configure any of this to get started. Anything your machine can't
support (an old kernel, a missing tool) is skipped with a clear warning instead
of blocking your session; use the `--no-…` flags below to turn a protection off
deliberately. One exception: if the network egress gate cannot start, the
launch is refused rather than run with no gate, and the message names
`--no-net-proxy` for running without it on purpose. In `secrets` mode (the
default) the agent works in your folder directly; the dual-view copy belongs
to the frozen `injection` and `full` modes.

---

## Everyday commands

```sh
mandu mode          # the protection mode: running and saved (mandu mode <name> saves one)
mandu doctor        # what Mandu needs, whether it is running, and what it enforces on this machine
mandu doctor --secrets   # dry run: which files and variables a launch would mask, what it would leave raw, keys left in git history, and whether it would start (add --json)
mandu scan          # which of your secrets your agents already sent to the AI, from their transcripts on this computer and how (--show <n> for one in full, --open for the dashboard's Scan page, --share, --json)
mandu policy suggest     # keys in this project (its git history and its files) your policy misses: review the rule for each and apply it
mandu policy classifier-pack   # print the pack that turns on Mandu's own prompt classifier (a model of yours checks what you type)
mandu why ~/.pgpass      # why one file is (or isn't) a secret, who may read it, where it may go
mandu why .env --to api.example.com   # ... and what a send of it there would do
mandu why api.example.com             # which secrets may go to a host, and whether a launch can reach it
mandu why '$MDU:localmodel_prompt_filter[1a2b]'   # where a placeholder came from (quote it): a part of your prompt the filter hid, and how to let it through
mandu revert        # list what the agent wrote here; mandu revert --to N undoes the later writes (asks first; frozen injection/full modes only)
mandu dashboard     # open the dashboard: protection status, what needs your OK, rules; History opens each session: what the AI saw, what really happened
mandu log           # what the last launch said in full: each notice, each warning, each protection layer (--list; a session id; --timings: how long each step took)
mandu status        # is Mandu running, the dashboard URL, leftovers from ended sessions (--verbose: every service)
mandu version       # which mandu this is (where, version, commit), other mandu installs and old services in its way, each with its fix (--json)
mandu stop          # stop the background services (add --all to include launchers; --stack <runtime dir> for one stack only)
mandu init          # write a config file you can edit (see below)
mandu setup         # Ubuntu only, optional, once: add the bind-mount layer (and the userns the command sandbox wants)
```

Every command answers `--help` with its options and does nothing else, e.g.
`mandu setup --help`.

`mandu log` shows what a launch said that its one line on the terminal did
not: each protection layer as it came up, each notice and each warning in
full, and the messages of Mandu's helpers while the agent ran (never the
agent's own output). With no argument it is the latest launch; `mandu log
<session id>` picks one (a prefix will do), `mandu log --list` lists the
kept ones (the last 20, newest first) and `mandu log --path` prints the
file's path, so `tail -f "$(mandu log --path)"` follows a running session.
The logs are in `launch-logs/` in Mandu's state folder (`mandu paths`),
readable by you alone, and hold nothing the terminal would not have shown
with `--verbose`.

A launch that feels slow? `mandu log --timings` shows how long each step
of the last five launches took (starting the services, setting up the
placeholder copies, the agent's own run, the clean-up after it), side by
side with their median, so you can see which step grew, and what the
whole launch cost Mandu: its own CPU time, the git commands it ran and
the sandboxes it made for them. Add a session id for one launch. A
`--verbose` launch prints the same breakdown when it ends, with each
step's CPU time and git commands beside it.

`mandu doctor --secrets` is the one to run before you trust a machine: it
walks your home and workspace exactly as a launch does, starts no agent,
prints every credential file it would mask (with the real path of a
symlinked one), the environment variable names it would mask, and a "Not
covered" list of what a launch leaves raw and why. It exits non-zero when a
launch would refuse, with the reason. Add `--target <agent>` (`claude`,
`codex`, `opencode`, `goose`, `openclaw`, `shell`) to see one agent's
launch: the logins it runs on stay raw, another agent's login is in the
list of what would be masked (or listed as left readable under
`MANDU_OTHER_AGENT_LOGINS=raw`), and `--no-mcp` with it matches a launch
with `--no-mcp`; without `--target` every agent's login is listed as left
raw.

It also scans the git history of the repository you run it in for keys
that were committed, including ones deleted since: a private key, a token
in a known format (GitHub, GitLab, AWS, Anthropic, OpenAI, Slack, Stripe,
Google, npm, PyPI, Hugging Face), a password in a URL, a credential
assignment, or a deleted file named like a credential file (`.env`,
`id_rsa`). Each is listed masked (`sk-ant-…`, `DB_PASSWORD=…`, never the
value) with its path, the commit that added it and what would close it:
a key only in history reaches the AI raw through `git log -p`, so rotate
it; a key in a file that still exists is hidden with its whole history once
you protect the file (on macOS protecting it makes the file unreadable, but
its committed versions stay readable: a macOS launch hides no history). The
scan reads at most 256 MiB of file versions in 60 seconds and says what it
skipped (`MANDU_HISTORY_SCAN_MAX_MB`, `MANDU_HISTORY_SCAN_BLOB_MAX_KB`,
`MANDU_HISTORY_SCAN_TIMEOUT_S` change the caps); `--no-history` skips it.
It changes nothing.

`mandu scan` looks back instead: which of your secrets your agents have
already sent to the AI. Your agents keep every session's messages on your
computer: Claude Code in `~/.claude/projects`, Codex in `~/.codex/sessions`,
OpenCode in `~/.local/share/opencode/opencode.db`, Goose in
`~/.local/share/goose/sessions` (and its log of the last requests in
`~/.local/state/goose/logs`), OpenClaw in `~/.openclaw/agents` (each where
the agent's own variables put it: `CLAUDE_CONFIG_DIR`, `CODEX_HOME`,
`XDG_DATA_HOME`, `XDG_STATE_HOME`, `GOOSE_PATH_ROOT`,
`OPENCLAW_STATE_DIR`). It also reads two agents Mandu does not run yet:
Gemini CLI in `~/.gemini/tmp/<project>/chats` (under `GEMINI_CLI_HOME`)
and Copilot CLI in `~/.copilot/session-state` (under `COPILOT_HOME`). For
Cursor it only counts the chats (its editor's and its `cursor-agent`
CLI's) and says so, `N Cursor chats not read`: Cursor keeps them in a
format that is not documented and has changed often, so no reader could
be trusted with them. For an agent Mandu does not run, the report says
so rather than what Mandu would have done, and names the agents it runs
(`mandu claude`, `mandu codex`, …). The scan reads the parts of them that
went to the model (what a tool read or printed, what you typed or pasted,
what the AI wrote, never an agent's own local copy of a tool's output)
and reports, with no value shown:

- **your secrets**: a value from a credential file Mandu finds on this
  computer, or from a secret-named variable in your environment, found in a
  session, with the file it lives in, how it got there (the agent read the
  file, a command printed it, it was in your message) and when. These are
  the ones to change where they were issued;
- **values that look like keys** (`sk-…`, `ghp_…`, `AKIA…`) but are in no
  file now: an old key, someone else's, or a test value. The report counts
  them in one line by prefix (`sk-… ×190 · ghp_… ×24 · …`); `--all` lists
  each. One that reads as made up (a word like `test` or `fake` between
  dashes, `sk-proj-test-…`; one character eight times in a row; a
  straight run like `abcdefgh` or `1234567890`; a vendor's documented
  example key) is listed apart as looking like a test value and not
  counted as leaked: each such rule is one a real key's random body
  practically never meets, and your own secrets are never marked;
- values only named like a secret (`DB_PASSWORD=…`) and a password in a
  URL, which is where a project's own test values show up: a count, and
  `--all` lists them;
- **what the agents sent on**: under each of your secrets, one line
  names where a command or a tool sent it, per way (`also sent over HTTP
  to …`, `over ssh to …`, `with git to …`, `by a script to …`, `to an
  MCP server's tool …`; `through its variable` when the AI saw only
  `$STRIPE_KEY`, `tried` for a host where every send failed or was
  refused). `--all` lists every send: each secret a `curl`, `wget`,
  HTTPie or `xh` command, or a web fetch, sent to a host outside this
  computer; an `ssh`, `scp`, `sftp` or `rsync` command sent to its host
  (in the command, or in a here-document or a command piped into it); a
  `git push`, `clone`, `fetch`, `pull` or `remote add` with the
  credential in its URL (`https://x-access-token:…@github.com/…`) or in an
  `http.extraheader`; a `python3 -c`, `node -e` or `python3 - <<EOF`
  script that calls an HTTP library with a URL written into it; and an
  MCP tool's input (the tool is where it went: Mandu cannot see where the
  server sent it on). Each as its value or through a variable that holds
  it (`$STRIPE_KEY`, `os.environ['STRIPE_KEY']`). Hosts the scan cannot
  tie to the key's own service come first, marked worth a look (a key
  with no recognisable format sent to its own company's API lands here
  too), then the MCP tools, then the keys sent to their own service (a
  Stripe key to `api.stripe.com`). A script run from a file, or a file
  copied whole over ssh, is not read: the record holds only the command. Under each host are the
  URLs it went to there (up to five), with the path shown and any
  password in the URL and every query value masked
  (`https://hooks.vendor.dev/in?k=$STRIPE_KEY&src=…`; a variable is
  shown, as it holds no value). Each says whether the
  command ran, failed, was refused or was stopped by Mandu. What a program
  sent by itself (a CLI's own login) is not in the agents' records, so it
  is not here;
- **riskier sessions**: how many ran with the agent's permission prompts
  off (Claude Code's `bypassPermissions`, Codex with approvals `never` and
  no sandbox, Goose's `auto` mode, its default, an OpenCode session whose
  own rules allow every tool, Copilot CLI in its allow-all mode; OpenClaw
  and Gemini CLI do not record it), and in how many
  of those one of your secrets leaked to the AI,
  and how many printed your whole environment to the AI (`env`,
  `printenv`, `export -p`, not a lookup like `env | grep PATH`).

The report is short. On a home with two secrets a session leaked:

```
mandu scan · 2 sessions · Claude Code, Codex · 1 Oct – 2 Oct
Nothing was sent anywhere; no secret value is shown.

✗ 2 of your secrets leaked to the AI

  1  DB_PASSWORD   ~/shop/.env
     1 session, 1 Oct · a command printed it, the AI wrote it
  2  STRIPE_KEY   ~/shop/.env
     1 session, 1 Oct · the agent read the file
     also sent over HTTP to api.stripe.com · tried hooks.vendor.dev (through its variable)

  → Rotate these 2 now, where they were issued.

! 3 more key-shaped values leaked (not in your files now: old
  keys, someone else's, or test values)
  ghp_… ×1 · sk-proj-… ×1 · xoxb-… ×1

! Risky sessions
  1 ran with permission prompts off (in 1, one of your secrets leaked)
  1 printed your whole environment to the AI

1 session ran while Mandu ran (by time): there the AI may have seen a placeholder; 1 finding above was seen only there.

✓ With Mandu, these 3 secrets stay safe: the AI sees only a $MDU:… placeholder, and your agent still does its work.
  Protect your agents:  mandu claude  (or mandu codex)
  One in full:          mandu scan --show 1   Everything: mandu scan --all
  Dashboard:            run mandu dashboard and open Scan
```

Each of your secrets is one entry: its name and file, how many sessions
and when, the ways it got there (you pasted it, a command printed it, the
agent read the file, the AI wrote it, the agent attached it, a tool
returned it; the three most common), and when one command is all it
took, that command, masked and cut to its first 40 characters or so,
at the end of an argument (a long path keeps its start and its file
name: `cat ~/.config/some-cli/…/credential.json`). On
a terminal the report is in colour (red for what leaked, yellow for the
warnings); piped, or with `NO_COLOR` set, it is plain, and
`FORCE_COLOR=1` turns colour on anyway. `--json` and `--share` never
have colour. The terminal report and `--show` say *leaked to the AI*;
`--share`, `--json`, the kept report, `mandu doctor` and the dashboard
say *reached the AI*.

`mandu scan --all` prints the long report. There each finding is
numbered and told step by step, from the record: where
the secret lived, what the agent did (the command it ran, the file it
read, or the page it fetched: "The agent fetched:  https://…") with the
date, the project and the agent, that the output with the secret in it
left your computer in the agent's next request to its model provider,
what came next (the AI wrote it out again, a command sent it on), and,
for your own secrets, what Mandu would have done:

```
  1. accessToken in ~/.config/some-cli/credential.json
     19 Oct · ~/project/app · Claude Code
       The agent ran:  cat ~/.config/some-cli/credential.json
       The output, with the secret in it, went to the AI: it left this computer in Claude Code's next request to Anthropic.
     With Mandu, the AI would have seen a placeholder ($MDU:…) where the secret is in that output; the command itself would still have run.
```

The provider is the one the session's record names, else the one the
agent's own settings point it at: Claude Code with Bedrock, Vertex or
Foundry turned on, or an `ANTHROPIC_BASE_URL` elsewhere, in its
`settings.json` or your environment, or Codex with another
`model_provider` or an `openai_base_url` in its `config.toml`, is told as
"the model provider" rather than Anthropic or OpenAI. For Codex that
includes a project's own `.codex/config.toml` (from the repository's root
down to the session's folder) when your `~/.codex/config.toml` trusts the
project, as Codex reads it; today's Codex ignores the provider settings
there, an older one may not have, so the scan counts them only to say
"the model provider", never to say OpenAI. The scan reads those settings only to
tell which; none of them is shown.

A command, or a fetched URL, is shown with every value it holds masked:
your secrets by name (`PGPASSWORD=‹DB_PASSWORD› psql …`), keys by their
prefix (`sk_live_…`), and anything named like a secret, a password or a
key in a URL (`?key=…`) or a long random-looking run as `…`. Only its first line is shown (a
here-document's body never is), cut at 240 characters. In the long
report the values that look like keys get the same story for the first
three, then a row each with up to three examples: the project and the
command are usually what tell a test fixture from a real key. The
numbers are the same in both reports: your secrets first, as the short
report lists them, then the values that look like keys, then the rest.
`mandu scan --show 3` prints finding 3 in full: every way it got there
with up to ten examples, the number of projects, the dates, and where a
command sent it, by host with the URLs (it scans
again, so a session written in between can move the numbers).

A value that is in a credential file but is not a credential (a version, a
checksum) is not reported. A session that ran while Mandu ran the same
agent is counted in one closing line: there the record on disk can show a
value the AI saw as a placeholder. A finding seen only in sessions Mandu
served (known by the id of each answer) is not counted as leaked;
`--all` lists those. It reads at most 16 GiB in 5 minutes, newest sessions first,
and says what it left unread (`--since 30d` or `--since 2026-09-01` reads
less; `MANDU_TRANSCRIPT_SCAN_TIMEOUT_S`, `MANDU_TRANSCRIPT_SCAN_MAX_MB`
change the caps). It changes no transcript, writes no rule and connects to
nothing outside this computer: an agent's database is opened read-only
in a way that never holds the agent up, so the scan can run while the
agent does (on Node 22.13 or 22.14 a stopped agent's database is counted
as unreadable instead, since that Node cannot open it without touching
it; Node 22.15 or later reads it). `--share` prints a sentence with the counts
alone, to post if you like; `--json` gives the raw report.

It keeps its last report, the same names, files, masks, hosts and counts it
printed and never a value, in `~/.mandu/state/last-scan.json` (`0600`), so
you can come back to it:

- the dashboard's **Home** shows a card under its counts: how many of your
  secrets left this computer in your agents' requests before Mandu, the
  first few by name and file, the sends worth a look, and `mandu scan` to
  run it again (with no scan yet, how to run one);
- the dashboard's **Scan** page (*Scan* in the top bar, `/scan`, also
  linked from that card and from History) shows the whole report. Each finding tells how the secret left:
  where it lives, what the agent ran or read (the command with every
  secret in it shown masked), when, in which project and with which agent,
  that it went to the AI in the agent's request to its provider, what
  happened next (the AI wrote it out again, a command sent it on to a
  host), and what Mandu would have done instead; whether a session ran
  with Mandu is a small note under it. **Details and examples** opens the
  examples, the dates and the projects. The long list of values that only
  look like keys starts folded, with a box to find one;
- `mandu doctor` prints one line from it, such as `Last scan (19 Oct): 2 of
  your secrets reached the AI in sessions without Mandu (mandu scan to check again)`.

The report's last line says where to see it (the `Dashboard:` row of the
short report; `--all` and `--show` end with a sentence). With your
dashboard running, it is the address of its Scan page (`This report is in
your dashboard too: http://127.0.0.1:40123/scan`, followed by `(sign in
with your Mandu dashboard account)`, or `(no account yet; set one: mandu
dashboard --set-password)` when it has none yet); with none, the
command that opens it (`This report is kept for your dashboard: run mandu
dashboard and open Scan.`, or `npx @mandusec/mandu dashboard` when you
ran the scan through npx). The scan
starts no dashboard itself unless you ask with `--open`. `mandu dashboard` opens even if you have
never run an agent with Mandu: it starts the dashboard alone, not Mandu's
protection, and its Home then says **Protection is off: no agent runs with
Mandu.**, with the command that starts it (`mandu claude` or `mandu codex`).
The dashboard picks up Mandu as soon as you start an agent with it.

`mandu scan --open` (with `--all` or `--show <n>` too) goes one step
further: after the report it opens the dashboard's Scan page in your
browser, starting the dashboard first, as `mandu dashboard` would, when
none of yours is running (it then keeps running after the scan, as it does
after `mandu dashboard`). It says what it did on one line:

```text
Opened the dashboard's Scan page: http://127.0.0.1:40123/scan
Started the dashboard and opened its Scan page: http://127.0.0.1:40123/scan
```

with the same `(sign in …)` note as the report's last line when the
dashboard asks for a sign-in: the browser is given the page's plain
address, never a password or a sign-in link, so it shows the dashboard's
sign-in page first. The browser is the one `BROWSER` names when you set it
(a command; `%s` in it is replaced by the address, else the address is
added at the end), else `open` on macOS, `wslview` (or Windows' `start`)
under WSL, and `xdg-open` on Linux with a display. With no browser to open,
as in an SSH session or on a machine with no screen, it tries none and
prints the address instead:

```text
The dashboard's Scan page: http://127.0.0.1:40123/scan
No browser here: open this URL on your computer
Over SSH, forward its port first: ssh -L 40123:127.0.0.1:40123 <this machine>
```

(the last line only over SSH; `<this machine>` stands for the name you
reach the machine by). A browser that will not start leaves the address
printed the same way. None of this changes the scan's exit status. `--open`
does not go with `--json` or `--share`, which are outputs for a program and
for pasting.

When Mandu is running as you scan, each file of yours whose key reached
the AI and that no rule protects yet becomes a suggestion under Rules ›
Files and folders › Suggested ("Suggested by mandu scan"), and the report
says so. Mandu reads the file itself first and suggests it only when it
finds a credential there under the key the scan named; it never suggests
an agent's own login file. Nothing changes until you save it.

While secret protection is on, the arbiter also keeps a list of the git
repositories on your machine that a lock may concern: the ones you launch
in or scan, the ones holding a file you labelled, and the ones a background
look through your home finds (at most 5 folders deep and 256 of them,
skipping `node_modules`, caches and Mandu's own folders, and on macOS
`~/Library`, `~/.Trash`, `~/Pictures`, `~/Music` and `~/Movies` except
where a label of yours reaches into them). For each it works out, in the
background, which old versions your labels lock, by git id, so that a lock
can later follow a key into every repository that holds it, clones
included; for now a launch on Linux still hides history only in the
repositories it prepares (your workspace and the ones holding a protected
or labelled file), and it reuses this work to start faster. A launch on
macOS hides no history: it only warns which of its repositories keep a
locked version readable. It reads file names and git ids only, never file
contents, and runs no program a repository configures.
`MANDU_LOCK_RESOLUTION=on-demand` in the arbiter's environment keeps it to
the repositories you launch in.

`mandu policy suggest` is how you close what that scan finds. It scans the
same history and the files in this folder (or in each `--root <dir>` and
the repository holding it; `--home` adds your home folder's configuration
files, such as `*.toml`, `*.env` or a name with `token` in it, and on
macOS skips `~/Library`, `~/.Trash`, `~/Pictures`, `~/Music` and
`~/Movies`), and turns each key your policy does not cover into a rule
that hides it from the AI. Files your policy already protects are not
opened. It then shows you one screen per rule: the rule in plain words,
the evidence (the file, the commits for a key in the history, what the key
looks like, masked), what applying it hides, and the advice to rotate the
key, which a rule cannot undo. For a key found in a file on disk
(`deploy/staging.tfvars`, say), the rule hides that file from the next
launch; rotate the key if an AI session read the file before. On macOS a
launch hides no git history: a rule makes a file you have now unreadable to
the AI, but its committed versions stay readable, and the review and the
apply step say so for each key found in git history. Press `a` to
apply the rule (it only ever adds protection, and you can undo it from the
dashboard, under Rule changes in Approvals), `s` to skip it, `p` to see the exact `policy.yaml`
lines, `q` to stop. Nothing is applied unless you press `a`.
`--dry-run` shows the screens and applies nothing (so does running it
without a terminal), `--json` prints the suggestions for scripts, and
`--apply-all` applies every one after you type `apply` to confirm (it
refuses without a terminal). Applying needs Mandu to be running with secret
protection on; without it the command still scans and shows, and says so.

**Documents with a sensitivity label.** If your organization labels Office
files with Microsoft Purview (the labels Word, Excel and PowerPoint show,
such as "Highly Confidential"), Mandu can turn a label into a suggestion.
You say which label means what, under `sensitivity_labels:` in
`policy.yaml` (above) or in the dashboard (Settings › Sensitivity labels):
the label's id, a name in your words, and a level. The scan then reads the
label of each `.docx`, `.xlsx`, `.pptx` (and their macro and template
forms) under the folder, and suggests a rule for each file whose label you
mapped above `public`: "Make ~/proj/q3-board.docx a secret hidden from the
AI: its sensitivity label is Highly Confidential". It reads only the label
(the label's id and your tenant's id, never the document's text or the
label's name as the file spells it); a document Purview encrypted is counted,
not read. A scan looks at no more than 2,000 Office files and reads no more
than 32 MB of them; the terminal, the dashboard's Scan line and Settings,
Sensitivity labels say how many it left unchecked, and how many it could
not read. A rule at `no-model`
applies from here like any other; a rule at
`any-model` or `local-model` lets the AI (or your own model) read the file,
which only you can approve, in the dashboard (on macOS any level above
`public` keeps the file from every program the AI runs). Until you map a label, no
Office file is opened at launch; `mandu policy suggest` and the dashboard's
Scan still count them and say how many files carry a label you have not
mapped, and Settings › Sensitivity labels lists each one with its file count
so you can name it and pick a level. A label changed or removed in Office
later does not lower a rule you applied. Your administrator can map labels
for everyone in `/etc/mandu/policy.d/` (below); your own mapping can raise
theirs, never lower it.

A suggestion you skip stays waiting, in the next run and in the dashboard's
Rules page (Keys Mandu found). To say a finding is **not a secret**,
use the dashboard: that answer takes protection away, so the terminal, which
talks to Mandu on the same channel the AI's programs can reach, cannot give
it. When suggestions are waiting for the project you launch in (its
repository's history or its files), the launch prints one line saying how
many and where to review them
(`MANDU_SUGGEST_AT_LAUNCH=0` turns that check off; it never delays a launch
by more than about two seconds and never stops one).

**Asking a model to shape the rules (experimental).** Keys are found by
Mandu's own checks, never by a model. A model can help with the rest: from
the file and folder **names** (never what the files hold) it can spot a
folder of client contracts or HR records and propose one rule for it.
`mandu policy suggest --model names` runs the scans, then shows you exactly
what would be sent ("This sends 38 file and folder names from 1 folder to
Claude (claude -p) (Anthropic, outside this computer) …"), what was left out
(names your policy protects, anything under a protected folder, names that
look like a key, your home folder's path), and asks: `v` lists every line
that would be sent, `y` sends it, anything else sends nothing. The model it
uses is the one the helper uses (an Anthropic API key, else your `claude`
login), or a model declared in `policy.yaml` with `--endpoint <name>`. What
comes back is only a choice among the names it was shown and a reason from
a fixed list; each becomes a rule that hides that folder or file from the AI,
reviewed like the others ("suggested by your model …"). Without a terminal,
`--dry-run --json` prints the preview and its digest, and `--yes-send
<digest>` sends exactly that. It is not offered yet: set
`MANDU_EXPERIMENTAL_POLICY_MODEL=1` to try it.

**Asking your own model to read documents (experimental).** `mandu policy
suggest --model contents` asks a model of your own (one declared under
`models:` in `policy.yaml` with `local: true`, such as Ollama on this
computer; `--endpoint <name>` picks one when you have several) to read the
start of your documents (`.md`, `.txt`, `.rst`, `.org`, `.tex`, `.csv`,
`.tsv`, `.rtf`, `.html`, and the text of Word, Excel and PowerPoint files:
`.docx`, `.xlsx`, `.pptx` and their macro and template forms; at most the
first 16 KB of each, at most 200 files) and flag the sensitive ones:
contracts, HR records, customer lists and the like. From an Office file it
sends only the visible text Mandu takes out of it (a document's body, a
workbook's text cells, a deck's slides), never the file itself; it skips an
encrypted one and any that carries a sensitivity label, mapped or not. It
never sends a file your policy protects, a file under a protected folder,
or a file that holds something that looks like a key anywhere in it, and it
refuses before reading anything when the model is not one of your own
(an outside model, or a "local" entry that names a cloud model). The
preview says "This sends the text of 41 files (380 KB) to your own model
ollama (this computer)"; `v` lists the files and their sizes (never their
text), `y` sends, anything else sends nothing; `--dry-run --json` and
`--yes-send <digest>` work as above. Each answer becomes a rule on that one
file: "No AI" can be applied here; any other level ("Your own AI
only", "Any AI, when it asks") is applied only by you, in the dashboard. A document that asks to be called public can at worst keep
itself from being suggested; it cannot lower any rule. Not offered yet
either (the same variable). The dashboard's Keys Mandu found has the same
choice ("Ask a model too": Off, Names only, Contents), with the same
preview before Send. `mandu doctor` says what each would use.

`mandu why` answers one question from the same policy the protection
service enforces, naming the rule that decided: the built-in catalog, your
label in `policy.yaml`, or a file a secret-holding session wrote. It shows
what the AI sees in the file's place, which programs read the real file,
and where a value may be sent. Given a placeholder (`mandu why '$MDU:…'`,
quoted so your shell leaves it alone), it says where that placeholder came
from. It changes nothing and shows no values. For a file over 256 KiB, or
when asked about many changed files in a few seconds, it says what the
AI's copy depends on instead of counting the values it masks. When a change that would
change the answer waits for your OK in Approvals (a loosening edit of
`policy.yaml`, a request from your agent, a key Mandu's scan found), it
says so, and what the file would become if you approved it; until you
answer, the lines above it are what Mandu enforces. With no Mandu running
it starts a temporary one that reads what Mandu keeps (your remembered
answers, the changes waiting in Approvals, the rules in force while an edit
of `policy.yaml` waits) without changing it, and answers as Mandu would once
started; it says so. When it cannot read that (no Mandu has run here yet, or
another Mandu version wrote it), it reads `policy.yaml` as written, so a
change still waiting for your OK reads as if it were in force and your
remembered answers are not consulted; it says that too.

`mandu doctor` is worth running once: it says in plain words what Mandu
enforces on this machine, which kernel guards are installed, and it will never
claim kernel-level enforcement it doesn't have. On macOS it says the kernel
guards are Linux only (there is nothing to install or build), names the
Seatbelt profile that keeps programs the agent runs from reading your
credential files (posture `read-blocked`), and marks with a ✗ an agent
sandbox that cannot start inside it (see Troubleshooting). `mandu doctor
--live` works on macOS too: it runs the PTY check through macOS's own
`script`, and it does not count the Linux-only guards against the launch.

When Mandu blocks a command, the message says what was blocked, why, and
what you can do, then a `detail:` line with the internal reason. A command
that only needs your OK (running a program fetched from the web, sending a
secret somewhere new) waits on the dashboard's Approvals page (`mandu dashboard`); the
message says so only when there is something there to answer.

---

## Turning things on and off

**Per run** — flags go *before* the agent name:

```sh
mandu --no-net-proxy claude       # don't gate outbound network this run
mandu --no-exec-wrap claude       # don't gate curl/wget/nc this run
mandu --landlock-net-strict claude  # strictest network: block direct 443/22 too
mandu --no-reply-filter claude    # don't resolve placeholders in replies
mandu --no-fs-sync claude         # don't use the dual-view worktree (raw folder)
```

Common flags:

| Flag | Effect |
|---|---|
| `--no-net-proxy` | turn OFF the network egress gate (on by default). If the gate cannot start, the launch is refused rather than run without it; this flag is the deliberate way to launch anyway |
| `--no-exec-wrap` | turn OFF command gating for curl/wget/nc (on by default) |
| `--no-exec-box` | turn OFF the read-only command sandbox (on by default) |
| `--no-landlock-net` | turn OFF the whole-agent TCP port confine (on by default, needs kernel ≥ 6.7) |
| `--landlock-net-strict` | strictest network: also block direct 443 (TLS) and 22 (ssh) — expect `git push` over ssh and direct fetchers to need exceptions |
| `--no-reply-filter` | leave placeholders unresolved in what you see |
| `--no-session-summary` | don't print the line that says what Mandu kept from the AI when the session ends. Env: `MANDU_SESSION_SUMMARY=0` |
| `--no-codex-shell-network` | Linux `mandu codex`: keep the network of Codex's own command sandbox off, as Codex has it by default (see "Codex's command sandbox" under [Run your agent](#run-your-agent)). Env: `MANDU_CODEX_SHELL_NETWORK=0`; config: `codex-shell-network = false` |
| `--no-fs-sync` | run in your real folder instead of a dual-view copy |
| `--browser` | start a Chrome for a browser agent, behind Mandu and with its traffic through Mandu's egress check; see "Run a browser agent" under [Run your agent](#run-your-agent). Env: `MANDU_BROWSER=1` (`MANDU_BROWSER_BIN` picks the Chrome, `MANDU_BROWSER_HEADLESS=1` hides its window) |
| `--browser-cdp <url>` | put Mandu between a browser agent and the Chrome at that debugging address on this machine (`http://127.0.0.1:9222`); see "Run a browser agent" under [Run your agent](#run-your-agent). Env: `MANDU_BROWSER_CDP` |
| `--no-policy-mcp` | don't give the agent the rule tools (`mandu_policy_read` / `_test` / `_propose`; `MANDU_POLICY_MCP=0`). With them, an agent can lock files at once, and anything that loosens protection waits for you on the dashboard's Approvals page. Claude Code, OpenCode and Codex (on Codex the servers ride `-c mcp_servers.*` overrides with the tools pre-approved) |
| `--best-effort` | launch even if an explicitly requested protection (or the egress gate) can't start (loud warning) |
| `--verbose` | print every protection layer as it comes up, and every notice and warning in full, on the terminal. By default a launch prints one line (the mode, what it masks, the dashboard, how many notices it kept, for example ``mandu: secrets mode · 14 credential files masked · dashboard http://127.0.0.1:4500/ · 2 notices: `mandu log` ``), then one short `mandu: WARNING: …` line per problem that weakens protection; everything else goes to the launch's log, which `mandu log` shows (the last 20 launches are kept, readable by you alone; the dashboard shows the protections too). Env: `MANDU_VERBOSE=1` |
| `--require-confinement` | refuse to launch if your secrets can't be **confined** on this machine (default: launch **gated** with a notice). Config: `require-confinement = true`, recommended for managed deployments |

A note on strict mode: the model-inspection helper (the "U-LLM") normally needs
direct network access, but Mandu runs a small loopback forwarder outside the
confine so it keeps working even when direct 443 is blocked. If the forwarder
can't run, Mandu warns and the helper falls back to its direct connection.

In `secrets` mode the agent's programs can reach only a few
local services by Unix socket: Mandu itself, name lookup, logging, your
ssh-agent and gpg-agent, and your Wayland or X11 display, plus anything they
start themselves. The rest (the desktop bus, `systemd-run --user`, docker, a
tmux server you already run) is refused, because each can start a program
outside Mandu that reads your real files. So desktop notifications, the
keyring and some `xdg-open` routes do not work from the agent. If you run
your agent inside tmux, a `tmux` command it runs is refused too (the
session page says Mandu kept it from reaching a local program's socket),
since it would reach the tmux server you started outside Mandu. Add a socket
for a run with `MANDU_UNIX_ALLOW=/path/to/app.sock mandu claude` (a
directory allows every socket in it), or turn the list off with
`MANDU_UNIX_POLICY=0`.

A program the agent runs that tries to change one of the files that run
later (the "Files that run later" row above) pauses until you answer in
Approvals: allow once, always allow that program for that file, or block. The
wait lasts a minute (`MANDU_SECRETS_ASK_TIMEOUT` in milliseconds sets it);
then the change is refused and its card in Approvals stays, so your later answer
applies to the next try. The card says which it is: "is waiting for your answer
now" while the program waits, "stopped waiting" once it gave up, and then tell
the agent to try again after you answer. `MANDU_WRITE_PROTECT=0 mandu claude` turns this
protection, and the refusal of changes to Mandu's own files, off for a run.

A request that carries a secret's placeholder to a place it may not go
files a card in Approvals. When you run the agent at a terminal (`mandu
claude`, `mandu codex`, …), the request waits up to a minute while you
answer: *Allow once* or *Always allow* sends it with the real value, *Send
without it* sends it with `[hidden by Mandu]` where the secret was, and
*Block* stops it. The agent's command then simply finishes, with no second
try. No answer in time means it is stopped, and the card stays for the next
try. A file Mandu protects value by value (a `.env`, a bank statement with a
placeholder on each line) is one card per place it goes when the request
carries several of its values: your answer covers every value of that file,
and *Allow once* covers that one request only. A request with one value of
it asks about that value by name. Two files in one request are two cards, and the request waits
for both. Where nobody is likely watching (`claude -p`, `codex exec`, output
piped to a file or a program, CI) the request is stopped at once instead,
and your answer applies to the agent's next try. `MANDU_EGRESS_HOLD_MS` (or
`egress-hold-ms` in `~/.mandu/config.toml`) sets the wait in milliseconds
for every session, at most five minutes; `MANDU_EGRESS_HOLD_MS=0` never
waits. Keep the wait shorter than the agent's own command limit (two
minutes for Claude Code's Bash tool).

Cloud metadata addresses (`169.254.169.254` and the other cloud credential
endpoints) and link-local addresses are always blocked, whatever your other
network settings say. On a cloud VM this stops the agent from fetching the
machine's own cloud credentials. If your agent really needs the instance role,
launch with `MANDU_NET_ALLOW_METADATA=1 mandu claude`.

**Permanently** — set defaults in a config file so you don't repeat flags:

```sh
mandu init          # writes ~/.mandu/config.toml
```

Then edit it — every line is a commented default you can change (the network
and command protections are already on, so you'd edit these to turn one *off*):

```toml
# reply-filter = true
net-proxy = false           # turn the network egress gate off permanently
# exec-wrap = true
# exec-box = true           # read-only command sandbox
# landlock-net = true       # whole-agent TCP port confine (kernel >= 6.7)
# landlock-net-strict = false   # also block direct 443/22
# dashboard-port = 0        # unset = reuse your running dashboard, else a free port
```

Precedence is **command-line flags > environment variables > this file > built-in
defaults** — so a flag always wins for a single run, and the file sets your
baseline.

---

## The dashboard on the network

`mandu dashboard` (and the stack a launch starts) listens on **127.0.0.1
only**. Signed in, the dashboard shows the real values behind the
placeholders, so the shipped default exposes nothing to your network, and no
remote address is allowed in by default.

Which port: `mandu dashboard` first looks for a dashboard you already run
and prints its address. If there is none it starts one on a free port and
prints that address; a second person on the same machine gets their own. Set
`DASHBOARD_PORT` (or `dashboard-port` in the config file) to pin a port; if
something that is not your Mandu dashboard already holds it, the command
says so instead of pointing you there. A dashboard you run yourself
(`npm run serve` in `dashboard/`, a systemd unit) still defaults to 4500.

**Signing in.** The dashboard shows the real values Mandu kept from the AI,
so every page of it asks you to sign in first, with your **dashboard
account**: one username and password, the same wherever the dashboard runs.
Until you make one, the dashboard shows nothing but a page that says how
(`mandu dashboard --set-password`), and the launch line says "no account
yet; set one: mandu dashboard --set-password". This matters because the
programs your agent runs are on the same computer: they can reach the
dashboard's port, and without your sign-in they get nothing from it.
Signed in, a secret on an agent's page (a step that read it, its card under
*Your secrets*) has a **Show the real value** button: one click shows that
one value, only to you, and "Hide it again" takes it off the page.

**Your dashboard account.** One username and password for every page of
the dashboard, the same wherever it runs (on this computer, or reached
through a tunnel or a reverse proxy). Make it, or change its password, in
your own terminal:

```sh
mandu dashboard --set-password
```

It asks for a username and for the password twice, without showing what you
type. `mandu dashboard` and `mandu setup` offer to make one when there is
none yet, too. Mandu keeps
only a scrambled form of the password (a salted scrypt hash) in
`~/.mandu/state/dashboard-account.json`, readable by you alone; the
password itself is written nowhere. A running dashboard uses the new
account at once and signs every browser out.

Opening the dashboard then shows a page with **Username** and **Password**. Type them there, not in
the address bar: the address never needs to hold them. You stay signed in
in that browser for up to 7 days (12 hours if you leave it unused), or
until the dashboard restarts; **Settings › Dashboard account › Sign out**
ends it. After five wrong tries within a minute, the page asks you to wait
30 seconds (longer if it goes on) before it checks again. A script can send
the same username and password as HTTP Basic credentials (`curl -u you
http://127.0.0.1:4500/api/home` asks for the password).

Programs your agent runs under Mandu can neither read nor change the account
file. A program of yours that runs outside Mandu could, as it could any of
your files: if the dashboard sees the file change while it runs, it signs
everyone out and Home says so. If that was not you, run `mandu dashboard
--set-password` again. A dashboard started with `DASHBOARD_BASIC_AUTH`
moves that username and password into the account the first time and says
so; you can then remove the line. `DASHBOARD_PASSWORD` and the one-time
sign-in links of earlier releases are gone: the account replaces both.

The dashboard answers only to its own address: `127.0.0.1`, `localhost` or
`[::1]` at its port. A request that names any other host is refused (421), so
a web page you visit cannot reach it by pointing its own name at your
computer. Behind a reverse proxy or a tunnel that forwards its public name,
list that name in `DASHBOARD_SERVER_NAMES` (comma-separated; `name:port` for
one port only).

To reach it from another machine, make your dashboard account first
(`mandu dashboard --set-password`), then say these explicitly:

```sh
DASHBOARD_HOST=0.0.0.0                     # the wide bind
DASHBOARD_ALLOW_HOSTS=proxy.example.org     # who may connect (comma-separated hosts or IPs; everyone else gets 403)
DASHBOARD_SERVER_NAMES=dash.example.org     # the name browsers use for it, when that is not this machine's address
```

A non-loopback bind with no account
refuses to start. Put
these in the environment of whatever starts the dashboard (a systemd user
unit's `EnvironmentFile`, mode 600, is the usual place).

---

## Troubleshooting

- **Which mandu is this?** (an install that does not behave like the version
  you installed, or a bug report) — run `mandu version`. (The dashboard's
  Settings › About Mandu shows the version alone, with links to this guide
  and the issue tracker.) It prints the file
  your shell ran and the file it resolves to, how Mandu is installed (the
  npm package, or a source checkout), its version and its commits (the
  source repository's and the public repository's), and then what could make
  it act like another Mandu, each with its fix:
  - another `mandu` on your PATH, such as the shim a from-source install left
    in `~/.local/bin`, whether it runs instead of this one or waits behind
    it (after removing one, run `hash -r` in open shells);
  - the background services, compared with this mandu: another version or
    another build is named with the folder its code runs from, and a systemd
    service that keeps old services alive is named with
    `systemctl --user disable --now <unit>`, or, to keep that service, the
    command that runs this mandu beside it as a second Mandu;
  - `MANDU_DEV_REPO`, `MANDU_LAYOUT` or `MANDU_FROM_SOURCE` left in your shell
    by a source install: they make even the npm `mandu` run its services
    from that source tree;
  - a global npm install that is not the `mandu` you are running.

  `mandu version --json` is the same report for a bug report, and
  `mandu --version` is still the one line `mandu <version>`. `mandu doctor`
  shows the commit and the same problems among its checks. An npm package
  built before 0.2.0-beta.7 says its commit is "not recorded".
- **`Node … is too old`** — Mandu needs Node 22.13.0 or newer (an older 22.x
  still has `node:sqlite` behind a flag). Install it with `nvm install 22` (or
  your package manager) and try again.
- **`Node v22.13.0 on your PATH is too old for Mandu`** (a launch line, and a
  ✗ row in `mandu doctor`) — Node programs the AI runs use the `node` on your
  PATH, and a Node older than 22.21 (or 24.0 to 24.4 for `http`/`https`, or
  any 23.x) ignores the setting that sends their web requests through Mandu.
  Nothing leaks: they only ever hold placeholders. But Mandu cannot fill your
  real secrets in for them, so their logins fail (a 401 from an API the
  program should be signed in to). Mandu itself still runs. Fix: upgrade the
  `node` on your PATH to 22.21 or newer, or 24.5 or newer (`nvm install 22`
  or `nvm install 24`), then start a new session. npm is not affected.
- **`mandu.db … was written by a different Mandu version`** — the
  arbiter's database (`~/.mandu/state/mandu.db`) carries a schema version and a
  file from another release is refused rather than misread. Do what the
  message says: `mandu stop --all`, delete the file (and its `-wal`/`-shm`
  siblings), relaunch. Secret-file labels you declared under `policy.yaml`
  `paths:` survive, and so do labels saved from the dashboard's file browser
  (it writes `paths:`); labels made in the developer view, and past
  approvals, do not.
- **`The arbiter refused to start: policy file … is invalid`** — the
  arbiter will not run a `policy.yaml` it cannot read exactly, rather than
  run different rules from the ones in the file. The log named on the next
  line (`(log: …)`) lists every problem, for example `paths[0].level: must
  be public | any-model | local-model | no-model (got "secret")`. An arbiter that is already
  running when you edit the file keeps the rules it had and logs the
  problem; fix the file and it reloads by itself.
- **`service 'context-proxy' was requested but failed to start … not ready
  within 30 s`** (or the same for `net-proxy`, or `arbiter did not come
  up`) — the service Mandu started did not answer in time, so Mandu refused
  to launch rather than run the agent without it. The wait is 30 s and
  longer when the machine is busy; on a machine that is slower still, set
  `MANDU_SERVICE_READY_TIMEOUT_MS` (milliseconds, e.g. `120000`). When the
  message says `it exited with code …` instead, the service failed: its log
  is named at the end of the message.
- **`WARNING: mandu: this session's file guard is not believed: another
  Mandu launch can reach Mandu's own controls: pid 4242 (session …, mode
  off)`** — another agent runs through Mandu with no file guard and no
  mount layer (started with `--mode off`, or `--no-net-guard` on a machine
  without the mount layer). Its programs can reach the channel your
  session's guard reports on, so until it ends Mandu trusts none of those
  reports: in this session secret files open as placeholders, writes to
  protected files are refused, and shell output is masked once the session
  has read a secret. Nothing is let through; work fails instead. Fix: stop
  that launch (the pid and session are in the message, and on the
  dashboard's Home page), or start it again with its file guard on (drop
  `--mode off` / `--no-net-guard`; `mandu doctor` says whether this computer
  can run the guard). When that launch already runs, the warning is the
  last thing Mandu prints before your agent starts. One that appears while
  a full-screen agent runs may be drawn over by it; the dashboard's Home
  page shows the same notice. When it ends this session prints `this session's file
  guard is believed again`, and after your agent exits a recap names the
  time it was not. Rerun what failed in between.
- **`dashboard … refusing to bind`** — you set `DASHBOARD_HOST` to a
  non-loopback address without authentication. See "The dashboard on the
  network" below.
- **Codex: every command fails with `bwrap: loopback: Failed RTM_NEWADDR`**
  (or "No permissions to create a new namespace"). Codex's own sandbox needs
  bubblewrap, which a stock Ubuntu does not ship; this happens without Mandu
  too. Run `sudo apt install bubblewrap`, then `mandu setup`: under
  `mandu codex`, Codex then uses Mandu's own bubblewrap. (Codex run on its
  own on Ubuntu 24.04 also needs Ubuntu's bubblewrap profile, from the
  `apparmor-profiles` package; 26.04 has it already.) `mandu doctor` shows a
  Codex sandbox row, and `mandu codex` prints one warning line while it is
  broken.
- **macOS: `mandu: Claude Code's own sandbox is OFF for this session` (or
  Codex's).** Claude Code and Codex can run each command in their own macOS
  sandbox, and macOS cannot start a sandbox inside Mandu's (the one that
  blocks your credential files): every command would fail with
  `sandbox_apply: Operation not permitted`. So when Mandu's profile wraps the
  launch, Mandu turns the agent's own sandbox off for that session and prints
  one line saying so. Mandu's profile still keeps your credential files from
  those commands (in mode `secrets`; mode `off` blocks none, and the line
  says so), but the agent's own limits on where they write and connect do
  not apply, and Claude Code's Bash asks for permission as usual. Mandu
  changes no settings file: it passes the setting on the command line
  (`--settings` for Claude Code, `-c sandbox_mode="danger-full-access"` for
  Codex). It leaves the sandbox on, with a `WARNING` that the agent's
  commands will fail, when:
  - you ask for it on that run (`mandu codex --sandbox workspace-write`, or a
    `--settings` that turns Claude Code's sandbox on), or pass Claude Code's
    `--settings` as a file (Mandu does not copy a settings file onto the
    command line; pass it inline);
  - your organization's managed settings require it;
  - Claude Code's sandbox read rules (`sandbox.credentials`,
    `sandbox.filesystem.denyRead`, `Read(...)` deny rules,
    `blockReadsOutsideWorkingDirectories`) protect files or variables Mandu
    does not. Label those files in Mandu's policy instead. The WARNING says
    what to do with rules a label cannot cover: list the files of a folder
    or glob, write a relative path as an absolute one, or remove an entry
    for a file that does not exist or lies outside your home folder and the
    launch folder;
  - Claude Code's sandbox is turned on by, or its settings include, a
    source Mandu cannot read (an administrator's policy helper, or
    `--managed-settings` / `--project-config-root` on that run);
  - your Codex config relies on it: a permission profile of your own
    (`default_permissions` naming one, or a `[permissions…]` table), in any
    of Codex's config files, a project's `.codex/config.toml` included, or
    the network proxy feature, which wraps every command anyway. Pass
    `--disable network_proxy` to turn the proxy off for that run.

  `mandu codex --remote` runs the session's commands on that app server,
  outside Mandu's profile, whatever else the run asks for, and the launch
  says so. A bare `codex app-server` gets the off line too, but a client
  that picks a sandbox for a thread overrides it, and that thread's commands
  then fail.

  Turning Codex's sandbox off also makes Codex record the project as trusted
  in `~/.codex/config.toml`. `mandu doctor` shows what a launch would do.
- **`mandu: WARNING — Mandu's own bubblewrap (…) is not the system's (…)`.**
  Every launch compares Mandu's copy of bubblewrap
  (`/usr/lib/mandu/bin/bwrap`, installed by `mandu setup`) with the system's
  and prints both versions when they differ: bubblewrap was updated after
  `mandu setup`, and the copy does not follow updates. Run `mandu setup`
  again to refresh it.
- **OpenClaw: every turn fails `requires a positive maxTokens value for
  anthropic/<model>`.** The model is not in your OpenClaw's own catalog (2026.7.1
  no longer lists `claude-sonnet-4-5`; without Mandu the same OpenClaw answers
  `Unknown model`). Pick a listed model (`openclaw models list --all --provider
  anthropic`), or add the model under `models.providers.anthropic.models` in
  `~/.openclaw/openclaw.json` with its `maxTokens` and `contextWindow`. Mandu
  keeps those entries; it ignores a `baseUrl`, `api` or `headers` set on one,
  because every Anthropic model goes through Mandu.
- **`refusing to launch openclaw with model …`** (or `opencode`). Under
  Mandu, OpenClaw and OpenCode run the models Mandu routes through its model
  proxy: Anthropic models, OpenAI models (`openai/…`), and an
  OpenAI-compatible provider you declare. For OpenClaw, declare it under
  `models.providers.<id>` with its `baseUrl` and `api: "openai-completions"`
  or `"openai-responses"`; for OpenCode, use a `provider.<id>` with
  `npm: "@ai-sdk/openai-compatible"` and `options.baseURL`. The base URL
  must be `https://`, or `http://` to this machine. A model from any other
  provider would get tool results unmasked, so the launch is refused; the
  message names the setting (for example
  `agents.defaults.model.fallbacks[0]`) and why its provider is not routed.
  Change it, pass `--model anthropic/…`, or run the agent without Mandu.
  OpenCode signed in to OpenAI with a ChatGPT account is refused too,
  because that login sends requests to chatgpt.com itself; sign in with an
  API key instead. For OpenClaw, `refusing … with no model configured` means
  OpenClaw would fall back to its own default, which depends on the release:
  `openclaw config set agents.defaults.model.primary anthropic/claude-sonnet-4-6`.
  Mandu reads `~/.openclaw/openclaw.json` as JSON5, as OpenClaw does
  (comments, unquoted keys and trailing commas are fine). Mandu also reads
  the files it pulls in with `$include`, the way OpenClaw does, and checks the
  models in them too. A file that does not parse is refused, and so is an
  include OpenClaw would refuse (outside the config directory, missing, or
  circular). Active Memory's recall model
  (`plugins.entries.active-memory.config.model`) must be one Mandu routes
  too. Inside a session, `/model` offers only the providers Mandu routes.
  With OpenClaw's `openai` provider routed, its image generation, speech and
  transcription through that provider are refused, so those tools fail
  under Mandu.
- **`refusing to launch Claude Code …`**. Claude Code's model traffic must
  go through Mandu's model proxy. With `CLAUDE_CODE_USE_BEDROCK`,
  `_VERTEX` or `_FOUNDRY` (or `ANTHROPIC_UNIX_SOCKET`) set, it would talk to
  that provider directly: unset it to run under Mandu. With
  `--settings <file>`, Claude Code would read that file instead of Mandu's
  routing: pass the settings inline (`--settings '{…}'`) or put them in
  `.claude/settings.local.json`. Managed settings from your administrator
  that point Claude Code at another endpoint cannot be overridden, so the
  launch stops and names the file. A line `… sets env.ANTHROPIC_BASE_URL;
  under Mandu it does not apply` is not an error: your own settings file
  names another endpoint, and Mandu keeps the session on its proxy. To use
  your own endpoint, set `ANTHROPIC_BASE_URL` in the environment and
  declare it under `models:` in `policy.yaml`. A `claude` you or the AI
  start inside a session (from the shell of `mandu -- bash`, a script, a
  hook) gets the same routing, and the same causes stop it with
  `mandu: refusing to start … claude: …` and exit status 126. `the claude
  shim's preload is missing … reinstall Mandu` means the installed package
  lacks a file that routing needs: with `claude` on your `PATH`, Mandu does
  not start the session rather than let a `claude` inside it run unrouted.
- **`refusing to launch OpenCode …`** (or `could not read its version`).
  Mandu supports OpenCode 1 (npm `opencode-ai`, tested with 1.18.13 to
  1.18.35) and OpenCode 2 (npm `@opencode/cli`, tested with 2.0.23 to
  2.0.26). It must read the version to know which one it starts, because
  OpenCode 2 has to be started with a private server of its own
  (`--standalone`; by default it would join
  a background service that keeps its own settings, and its requests would
  reach the model without going through Mandu). So a version Mandu cannot
  read, OpenCode 2's `0.0.0-…` prereleases and any other major are refused.
  Both install a command named `opencode`: check which one is first on your
  `PATH` with `opencode --version`. `MANDU_OPENCODE2=0` turns OpenCode 2 off
  (`refusing to launch OpenCode 2.…: MANDU_OPENCODE2=0 turns OpenCode 2
  off`); unset it to run OpenCode 2 again. (`MANDU_EXPERIMENTAL_OPENCODE2`,
  the switch OpenCode 2 needed before it was supported, does nothing now.)
- **`OpenCode — this project's plugins … are left out`** and
  **`OpenCode — your own OpenCode plugins and custom tools are left out of
  this session`**. A plugin or custom tool runs inside OpenCode and can put
  anything OpenCode holds into what it sends the AI, which Mandu does not
  check. In `secrets` mode none runs: not the project's (its `.opencode/`
  folders `plugin`, `plugins`, `tool`, `tools`, or a `plugin` list in its
  `opencode.json` or `tui.json`), and not your own (the same folders in
  `~/.config/opencode/` and `~/.opencode/`, or npm plugins such as
  oh-my-opencode that your global `opencode.json` names). OpenCode 2 starts
  without them; OpenCode 1 starts with its own "no external plugins" switch
  (`OPENCODE_PURE=1`). The line names each file. To run them anyway (a
  warning says they are not checked): `MANDU_OPENCODE_PROJECT_PLUGINS=1`
  for the project's, `MANDU_OPENCODE_GLOBAL_PLUGINS=1` for yours. A change
  the agent makes to a plugin folder or to your OpenCode settings files
  waits for you in Approvals; when OpenCode itself changes your settings
  (a settings save, its plugin manager), the same question comes up: answer
  *Allow once*.
- **`refusing OpenCode in mode secrets: this project brings OpenCode code`**
  or **`… your OpenCode folders hold a custom tool`** (OpenCode 1). Its "no
  external plugins" switch does not cover custom tools, so OpenCode 1 is
  refused where one would load and the files are named. Remove or move the
  tool, use OpenCode 2 (which starts without it), or start with the opt-in
  above. With `MANDU_OPENCODE_PROJECT_PLUGINS=1` alone, OpenCode 1 is also
  refused when you have plugins of your own (it can run every plugin or
  none): set `MANDU_OPENCODE_GLOBAL_PLUGINS=1` too.
- **``refusing `opencode serve` ``** (or `service`, `pair`, `api`, `acp`,
  `--server`, or a management command such as `session` or `auth`).
  OpenCode 2 under Mandu runs its TUI, `run` and `mini` only, each with its
  own private server; a command that joins or drives another OpenCode
  server is refused, with what to do instead. OpenCode 1 under Mandu runs
  its TUI and `run` only: `serve`, `web`, `attach`, `run --attach`, `acp`,
  `pr`, `github` and its management commands (`auth` / `providers`, `mcp`,
  `agent`, `session`, `export`, `import`, `db`, `models`, `stats`,
  `plugin`, `debug`, `upgrade`, `uninstall`, `completion`) are refused the
  same way, and so are the TUI's `--port`, `--hostname` and `--mdns`, which
  open its built-in server to other clients. Run the management commands
  without `mandu`.
- **`refusing OpenCode 2 in mode secrets: …`**. In `secrets` mode OpenCode 2
  runs only where Mandu's kernel connect guard, its write-protect guard and
  its OpenCode config lockdown all run (Linux), because otherwise a program
  the agent runs could reach OpenCode 2's own server. The message names what
  is missing and the fix; or run it with `--mode off` (observing only), or
  use OpenCode 1. Under Mandu, OpenCode 2 reads its configuration once at
  launch (an edit applies at the next launch), and skills in a project's
  `.claude/` or `.agents/` folder do not load (your home ones do).
- **``refusing `goose …` ``** or **`refusing to launch goose: …`**. Mandu
  supports Goose (tested with 1.53.0 to 1.54.0; a newer Goose gets the
  version warning). `mandu goose` runs `goose session`, and
  `mandu goose run …`, `mandu goose review`,
  `mandu goose run --recipe <file>` and `mandu goose acp` (as the command
  your editor starts for Goose) work; `serve`, `gateway`, `schedule`,
  `acp --enable-scheduler`, `--container`, `--sub-recipe`, code mode
  (`code_execution`) and the management commands (`configure`, `session
  export`, `recipe`, …) are refused, because they run the agent, or send
  what it saw, outside Mandu. Under `mandu goose acp`, Goose runs its
  commands and file edits itself instead of in your editor's terminal, the
  editor's provider picker can only choose the provider Mandu started Goose
  with (another choice answers with an error), Goose Desktop's own requests are refused, and the
  editor shows the real values where the model wrote placeholders
  (`$MDU:…`), as your terminal does (`--no-reply-filter` keeps the
  placeholders).
  Mandu reads a recipe before it starts Goose: a recipe that names another
  provider (or a provider filled in from a parameter), has `sub_recipes`
  or turns on `code_execution` is refused, and so is a recipe name Mandu
  cannot find on disk (one Goose would download from
  `GOOSE_RECIPE_GITHUB_REPO`): give the recipe's `.yaml` or `.json` path.
  Goose's built-in `anthropic`, `openai`, `litellm`, `openrouter`,
  `ollama`, `xai` and `tetrate` providers are routed: a
  `GOOSE_PROVIDER` or `GOOSE_SUBAGENT_PROVIDER` naming another provider (in
  your environment or `config.yaml`), or `--provider`, is refused, and so
  is a routed provider at an address Mandu cannot forward to (plain
  `http://` to another machine, such as an Ollama on another computer, a
  URL with a query string or a password, an `OPENAI_BASE_PATH` that ends in
  neither `chat/completions` nor `responses`, or a `LITELLM_BASE_PATH` that
  does not end in `chat/completions`); the message names the setting.
  Switching provider during a session (`/model --provider …`) works only
  for the provider Mandu started Goose with; another answers with an error
  and nothing is sent to it. On Ollama, a model that writes its tool calls
  as text (`<function=…>`) instead of using Ollama's tool calls gets its
  answer cut off with a `mandu` error, because Goose would run that text
  without Mandu's checks. A resumed session
  (`--resume` / `-r`) runs on the provider Mandu routes, not the one saved
  with it: Mandu adds `--provider anthropic` (or `openai`), because a
  session started outside Mandu on another provider would otherwise send
  its history there; set `GOOSE_MODEL` if that session's model belongs to
  another provider. Under
  Mandu, Goose's telemetry, Langfuse and OpenTelemetry exports and its
  prompt classifier are switched off.
- **Goose: `Configuration value not found: ANTHROPIC_API_KEY`** (or `OPENAI_API_KEY`), after
  `mandu: WARNING — Goose would read its key from the system keyring`.
  `goose configure` saved your key in the system keyring, and on Linux Mandu
  keeps the agent away from the keyring (it is reached over the desktop
  session bus, which can also start programs outside Mandu's protection).
  Set `ANTHROPIC_API_KEY` (`OPENAI_API_KEY` on Goose's openai provider, `OPENROUTER_API_KEY`, `XAI_API_KEY`, `TETRATE_API_KEY` or `LITELLM_API_KEY` on those), or save the key in Goose's own file once, without
  Mandu: `GOOSE_DISABLE_KEYRING=1 goose configure`. Under Mandu, Goose
  reads a placeholder from that file (`~/.config/goose/secrets.yaml`, or
  `config/secrets.yaml` under `GOOSE_PATH_ROOT`), and Mandu's model proxy
  puts your real key into the request it sends to Anthropic or OpenAI, so
  no program the agent runs can read the key; the launch prints `mandu:
  <file> is a placeholder in Goose's world`. When Goose's provider is on
  another machine than Anthropic's or OpenAI's (a custom `OPENAI_HOST`), on
  its litellm, openrouter, ollama, xai or tetrate provider, or
  with `MANDU_AUTH_SUBSTITUTION=0`, Goose reads the real file instead (the
  launch calls it the agent's own key file). Either way the AI sees its
  values only as placeholders. Other values in that file (an extension's
  token) are placeholders to Goose too; set `MANDU_AUTH_SUBSTITUTION=0` if
  an extension needs one. `mandu: WARNING — no Goose login found` means none of the
  three places holds a key. `mandu: WARNING — no login found for Goose's
  subagents` means `GOOSE_SUBAGENT_PROVIDER` puts the subagents on the
  other provider and nothing holds that provider's key: set the variable
  the line names (`OPENAI_API_KEY` or `ANTHROPIC_API_KEY`). `mandu doctor`'s
  `goose login` row (and its `goose subagent login` row) says which place
  Goose would use; it asks the keyring (on macOS the login Keychain, which
  Mandu leaves reachable) only whether Goose's entry exists, never for the
  key.
- **OpenClaw: `tools.exec.host "node" … is not used for this run`.** Under
  Mandu, OpenClaw runs commands on this machine. A configured `node` exec
  host would send them to a paired device, outside Mandu's sandbox, so the
  run config drops it and OpenClaw's default (`auto`) applies. Run openclaw
  without mandu to use a paired device.
- **OpenClaw: `memory search runs on keywords only under Mandu`.** OpenClaw's
  memory search sends the text of your memory files (`MEMORY.md`,
  `memory/*.md`) to an embedding provider, OpenAI by default, directly and not
  through Mandu. Under Mandu the embeddings are off and `memory_search` ranks
  by keywords; an explicit `local` provider (embeddings computed on this
  machine) is kept. The warning names the setting Mandu overrode. On OpenClaw
  releases before 2026.6.35, or when Mandu cannot read the version, the
  memory tools are off instead (`memory tools are off under Mandu`), and so
  is a third-party memory plugin such as `memory-lancedb`. To use them, run
  openclaw without Mandu.
- **OpenClaw: `mandu openclaw` opens the chat.** With no subcommand, Mandu
  starts `openclaw chat`, the coding agent. OpenClaw's own setup assistant
  (what a bare `openclaw` starts) does not run under Mandu; run `openclaw`
  without Mandu to set it up.
- **OpenClaw: `OpenClaw works in <folder> for this session`.** Under `mandu
  openclaw` (`chat`, and `terminal`, `tui --local`, `agent --local`), OpenClaw's
  workspace is the folder you started it in, not `~/.openclaw/workspace`. Its
  file tools start there, and it reads that folder's `AGENTS.md`,
  `USER.md`, `MEMORY.md` and similar files into the model's context. A
  protected file among them reaches the model as a placeholder. OpenClaw
  does not create its starter files (`SOUL.md`, `IDENTITY.md`, …) in your
  project. If you set your own workspace, a second line names it; it still
  applies when you run openclaw without Mandu, and under `mandu openclaw
  gateway`.
- **OpenClaw does not install: `Node.js >=24.16.0 … is required`.** OpenClaw
  2026.9.3 and later need Node 24; `nvm install 24` (Mandu runs on it too).
- **`claude not on PATH`** — install the agent: `npm install -g @anthropic-ai/claude-code`.
  Run `mandu doctor` to confirm.
- **`Not logged in` / `no Claude Code login found`** — the agent has no login
  on this machine. Run `claude` once on its own and log in (or `claude
  /login`), or set `ANTHROPIC_API_KEY`; for Codex, run `codex login` once
  on its own, or set `CODEX_API_KEY` or `OPENAI_API_KEY`. `mandu doctor`
  shows a `login:` row per agent. If you
  log in some other way (an `apiKeyHelper`, the macOS Keychain), the warning
  can be ignored.
- **An agent started inside another agent's session cannot log in** (a
  `codex` under `mandu claude` answers 401, or a `claude` under `mandu
  codex` says it is not logged in), after `mandu: …: Codex's login, a
  placeholder copy in this session`. Mandu gives another agent's login the
  same placeholder copy as any credential file. Launch that agent as
  `mandu codex` (or `mandu claude`) instead, or set
  `MANDU_OTHER_AGENT_LOGINS=raw` to leave other agents' logins readable and
  usable in the session. Under `mandu openclaw`, Claude Code's and Codex's
  logins stay readable (OpenClaw's `claude-cli` and `codex-cli` profiles and
  its Codex harness read them).
- **`mandu: refusing to start Codex: …`** — Codex has nothing to sign in
  with: run `codex login` once on its own (a ChatGPT plan), or set
  `CODEX_API_KEY` or `OPENAI_API_KEY` (or put it in `secrets.local.json`,
  which the launcher loads). With `MANDU_OPENAI_BASE_URL` pointing Codex at
  your own model server, only a key variable works: set the key that server
  expects (your ChatGPT sign-in is never sent to another server). `codex
  login`, `codex mcp` and `--version` always run. Background:
  [agent-sign-in.md §2](design/agents/agent-sign-in.md).
- **`cannot infer the target agent from '…'`** — Mandu runs a known agent
  (`claude`, `codex`, `openclaw`, `opencode`) or a shell by name. For a
  script that starts an agent, pass `--target <agent>`; for any other plain
  command, `--target shell`.
- **A folder isn't a git repo** — the dual-view workspace of the frozen
  `injection` and `full` modes needs `git`; without it
  Mandu runs in your real folder and says so. That's fine for a quick task;
  install `git` for the full protection.
- **`secrets are GATED, not confined`** — the native guard is not running
  on this machine (another platform, a package built without the guard, or
  you turned it off with `--no-net-guard`, `MANDU_NET_GUARD=0` or
  `net-guard = false`). Mandu still works; `mandu doctor` names the cause
  and the fix. With bubblewrap available, the notice adds that a mount
  layer still puts placeholders over your credential files: that layer
  misses a file your system replaces while the agent runs, which is why the
  guard is required for `confined`. `--require-confinement` refuses such a
  launch.
- **`WARNING: mandu: bubblewrap on this host follows symlinks while it sets
  up a sandbox (CVE-2026-87766) (/usr/bin/bwrap, version 0.11.1)`** (and a
  ✗ row in `mandu doctor`). Mandu tested the bubblewrap it runs and it has
  this bug (upstream fixed it in 0.12.0). The line names the binary and its
  version. Only a warning: the launch goes ahead and the guard still hands
  out placeholders by path. A variant, **`bubblewrap 0.11.1 (/usr/bin/bwrap)
  reports a version older than 0.12.0 … and Mandu could not test this build
  itself`**, means the test could not start a sandbox here (its reason is in
  brackets), so the build may be affected. The version number does not
  settle it either way: distributions backport the fix without changing the
  version, and have removed a backport again (Ubuntu shipped it in
  `0.9.0-1ubuntu0.2` and `0.11.1-1ubuntu0.2`, and dropped it in the
  `ubuntu0.3` update of each). Check the installed build instead: its
  changelog must name CVE-2026-87766 (Debian, Ubuntu: `apt changelog
  bubblewrap`; Fedora: `rpm -q --changelog bubblewrap`), or run `mandu
  doctor` where bubblewrap can create a user namespace (on Ubuntu, after
  `mandu setup`), which tests it. Fix: a bubblewrap with the fix, the distro
  package when it ships one (Debian, Ubuntu: `sudo apt update && sudo apt
  install --only-upgrade bubblewrap`; Fedora: `sudo dnf upgrade
  bubblewrap`), or bubblewrap 0.12.0 or newer, which an administrator can
  name with `bwrap_path` ("The bubblewrap your organization picks" under [Use your own model](#use-your-own-model-eg-ollama)). When the line names
  `/usr/lib/mandu/bin/bwrap` (Mandu's own copy, from `mandu setup`), run
  `mandu setup` again after the upgrade: the copy does not follow the
  package. Then run `mandu doctor`, which tests the result.
- **Which bubblewrap Mandu runs.** Your distribution's: Mandu ships no
  bubblewrap and downloads none (Claude Code and Codex do the same). It is
  Mandu's own copy where `mandu setup` installed one, else your
  administrator's `bwrap_path` (see above), else the first `bwrap` on your PATH
  outside the folder you launch in. A `bwrap` in that folder, or reached
  through a PATH entry inside it (`.`, a relative entry, a project `bin/` or
  `node_modules/.bin`), is never run: an agent can write there. None found
  counts as bubblewrap not installed (`sudo apt install bubblewrap` or `sudo
  dnf install bubblewrap`; on Ubuntu 24.04 and later, then `mandu setup`),
  and one that cannot create a user namespace is reported as such: the
  launch and `mandu doctor` test it by starting one, never by its presence.
  With Mandu's file guard running, secrets stay `confined` either way; only
  the second, mount layer needs bubblewrap. The command box looks for its
  own the same way, each time it runs a command, and also skips a `bwrap`
  in the command's folder and in the project.
- **A boxed command fails with `mandu: no bubblewrap outside the working
  directory on PATH; the command box will not run one from the workspace`**
  (exit status 126). The command box found no bubblewrap on the agent's
  PATH outside the command's folder and the project, so it ran nothing:
  not the command, and not a `bwrap` it found inside them. Install your
  distribution's bubblewrap (`sudo apt install bubblewrap` or `sudo dnf
  install bubblewrap`), or remove from PATH the entry that hides it.
- **`mandu: WARNING — your administrator's bubblewrap cannot be used: …`**
  (`mandu doctor` shows it as a ✗ row, and `mandu setup` stops with
  `cannot upgrade this host: your administrator's bubblewrap cannot be
  used: …`). A `bwrap_path:` in a file under `/etc/mandu/policy.d/` names
  a binary that is missing, or one (or a folder above it, or the file
  itself) that is not root's alone. Mandu then runs no other bubblewrap in
  its place, so installing one changes nothing; the guard still protects
  your secrets. Ask your administrator to fix the file.
- **`N places were not searched for secrets`** (with `--verbose`: `secrets NOT
  covered by the walk`) — the launch found credential files it
  could not mask: deeper than four folders under your home, beyond the
  256-file cap, or unreadable. Move them up, or lock the folder in the
  dashboard so it is walked as a unit; `mandu doctor --secrets` lists them.
  Several lines in that listing are benign and never in the warning: `Mandu
  state directory not walked`, `AgentView copy already masked by fs-sync`,
  folders deep inside package managers' caches (`~/.cargo/registry`,
  `~/go/pkg/mod`, `~/.m2/repository`, …: `skipped package caches`), and
  sockets named like a secret (an ssh-agent socket under `~/.ssh`).
- **A program says `Permission denied` on a credential file** — that file has
  an allow-list and the program is not on it, or it was started with a
  loader or interpreter variable (`LD_PRELOAD`, `PYTHONPATH`, …) that Mandu
  was not launched with. The tool result's `[mandu:secret] denied:` note
  names the file and the reason; add the program under `readers:` in
  `policy.yaml`, or answer the hold in Approvals if it is a well-known consumer.
- **`mandu: during this session the agent changed <file>`**, or a change to
  `.env` is gone after the session (Linux) — a program the agent runs writes
  to a protected file's placeholder copy, not to the file: the write works
  during the session and is discarded at its end. The line names each file
  the session changed (never what was written) and says what became of the
  real file, which Mandu compares with what it read at launch: unchanged,
  also changed during the session (a program allowed to read it raw wrote
  it, or you edited it meanwhile: look at it before you apply the change),
  or not readable. When the session's folder is kept (the agent exited with
  an error, `--id`, `MANDU_KEEP_SCOPE_DIR`) the line says the copy stays
  there until `mandu reap`. Make the change yourself, outside the agent.
  If Mandu itself was killed before the session ended, `mandu reap` prints
  the same names (`the session … ended before Mandu could say so: …`) before
  it removes the session's folder. `sed -i` or an editor's save of such a
  file fails with `Device or resource busy` (or `Permission denied` under
  the file guard alone) for the same reason. Run tools that save a login or
  a setting into a protected file (`npm login`, `npm config set`, git's
  `store` credential helper, `goose configure`) outside Mandu.
- **`WARNING: mandu: git in the agent's session recorded Mandu's placeholder
  copy of a protected file`** — git in the session read a protected file as
  its placeholder copy, and a `git commit -a`, `git add -A`, `git add -f` or
  `git stash` put that copy into your repository in place of the file (for a
  file git tracks, after the agent changed the copy: an unchanged copy looks
  unmodified to git in the session, see the next item). What
  git recorded is the placeholder, not your secret. Run the commands the
  warning lists, outside a Mandu session, in that repository, in the order it
  lists them: first `git restore --staged -- <file>` for a file that is only
  staged (`git rm --cached -f -- <file>` on a branch with no commit yet),
  then, for a placeholder in your checked-out commit, `git rm --cached -f --
  <file>` and `git commit --amend --no-edit --allow-empty` (a new commit
  instead when it was already pushed; the warning prints which). They only
  take the placeholder out: none adds your file on disk to git or brings back
  a version of it from another commit or branch. Afterwards git no longer
  tracks a file taken out of a commit this way, even if it did before the
  session (nor a staged one your checked-out commit does not hold). If it
  belongs in git, check what the file on disk holds and add it back yourself
  (what you add is your real file; Mandu prints no command that puts it back);
  if not, list it in `.gitignore`. An older commit that holds the placeholder
  is named, and rewriting it is your decision. The unstaging comes first
  because the commit takes everything staged; check `git status` before it. Do
  not run `git checkout`, `git restore` without `--staged`, `git reset --hard`
  or `git stash` on the file first: each can write the placeholder over your
  real file. To avoid it, keep protected files out of git. `.gitignore` alone
  does not do that for a file git already tracks: stop tracking it first (`git
  rm --cached -- <file>`, outside a Mandu session; the commit after that
  removes it from the repository, and from a collaborator's checkout at their
  next pull), then list it in `.gitignore`. Or ask the agent to add only the
  files it changed (`git add <file>`). (A session that crashed is checked at
  the next launch, which prints the same warning, naming the earlier session,
  and checks it again after its own agent exits.)
- **While a session runs, your own `git status` shows a protected file as
  modified (` M .env`), and `git diff` shows nothing** — expected, for a
  protected file git tracks. So that git in the session sees that file
  unmodified (and `git rebase`, `git stash`, `git filter-branch` work
  there, and a `git commit -a` leaves the file out), Mandu stores the
  placeholder copy's size and times in your repository's index, git's
  record of which files changed; it never stores any content there. git
  keeps one such record for both sides, so git outside the session (your
  terminal, your editor) now finds your real file's size different and
  lists it as modified without reading it. While the session runs, your
  own `git rebase` and `git filter-branch` in that repository refuse ("You
  have unstaged changes"). Your `git stash` runs but stashes nothing for the
  file, and like `git reset --hard`, `git restore .`, `git checkout -- .`
  or an editor's "Discard changes", it rewrites the file with its committed
  content, which is the same content (Mandu does this only for a file that
  matches its last commit). That is harmless: Mandu's file guard keeps the
  agent on the placeholder copy of the rewritten file. Mandu does this only
  where that guard runs; without it (`mandu doctor` says why), git in the
  session sees the file modified instead. `git add` of the file stores the
  same content (and the agent's git then sees the file modified). When the
  session ends, Mandu puts your index back and `git status` is clean again;
  if Mandu was killed first, the next launch (or `mandu reap`) puts it back
  and says so (`put back the index stat of a protected file an earlier
  session left`). If the session stopped tracking the file (say the agent
  removed it from git history) and `.gitignore` does not name it, Mandu
  says so when the session ends: add it to `.gitignore`, or a later `git
  add -A` commits your real file.
- **`deploy.sh` ran but its output came back as one placeholder** — a program
  that read a secret is treated as holding it, so its whole output is masked
  for the AI (you see it in full). That is by design; if the AI needs the
  output, set `output: clear` on that program's entry in the file's
  `readers:` (never for a shell or an interpreter). If it is still masked,
  the command also held another secret file whose entry does not clear it.
  A program-wide `apps:` rule clears nothing (the arbiter's log and the
  dashboard's policy editor show a warning naming the entry to write).
- **`mandu doctor`: `files labeled local-model are read by no model until
  you declare your own model in policy.yaml`** — you labeled a file
  `local-model` and `policy.yaml` has no `models:` entries. Nothing leaks:
  the helper refuses (`… is local-model: this datum is readable only by your
  own model and none is declared in policy.yaml models:`) and the AI works
  with the placeholder. Declare your model, then relaunch:
  [Use your own model](#use-your-own-model-eg-ollama).
- **The helper says `your declared model '<name>' did not answer (…)`** —
  the model server is not running, its `url` is wrong, or it took longer
  than the wait. The file was not sent to any other model, and never is.
  Start the server (`ollama serve`) and check the "Your own models" rows of
  `mandu doctor`; for a slow first load, raise
  `MANDU_ULLM_ENDPOINT_TIMEOUT_MS`. If you declared the model after the
  agent started, relaunch it: the helper may connect only to the models
  declared at launch.
- **`WARNING: mandu: Mandu's model proxy is skipped because
  ANTHROPIC_BASE_URL (…) is not declared in policy.yaml models:`** (or
  `MANDU_OPENAI_BASE_URL`) — you pointed the agent at a model yourself and
  no `models:` entry matches it, so Mandu does not put its model proxy in
  front, and that model reads file contents and tool results unprotected.
  Declare it with `wire: anthropic` (Claude Code) or `wire: openai-chat`
  (Codex), a `url` spelled exactly like the variable (`localhost` and
  `127.0.0.1` do not match each other), and `local: true` if it is your
  own model.
- **`refusing to launch: policy.yaml declares a cloud model as
  local: true`**, or the policy file does not load with `… runs on the
  vendor's servers (a cloud model), so '<name>' cannot be local: true` — the
  entry names a model that runs on the vendor's servers (an Ollama tag that
  is or ends in `cloud`). Name a model that runs on your machine, or remove
  `local: true`.
- **`refusing to launch: your main model http://… (…, declared in
  policy.yaml models:) is plain http on another machine`** — Mandu's model
  proxy sends the conversation over plain http only to this machine. Put
  the model behind https, or run it on this machine.
- **Something's stuck / a stale service** — `mandu status` shows what's running,
  `mandu stop` clears the background services.
- **"Is it actually protecting me?"** — run `mandu dashboard`. Before your
  first agent session, the home page shows a setup card: what the current
  mode protects (in `secrets`, untrusted content is not masked), how to start
  an agent, how to mark a secret, and `mandu doctor`. The home page
  says it in one sentence, and each agent's Details page lists what it read and
  what was masked or blocked. For the evidence, "Detailed trace" opens the
  developer view, where masked content shows up as a placeholder on the
  agent's lane while the original stays on the human lane. A "detailed
  trace" link under one step (or after "N more steps are not shown here.")
  opens the developer view at that step, marked. Where the page leaves
  something out (earlier turns, a long turn's steps, more secrets), **Show
  them** draws the rest on the page itself. Or run `mandu doctor` for the
  summary.

---

## Where Mandu keeps its files

In one folder in your home directory, `~/.mandu`, that only you can open.
Nothing is uploaded anywhere. In `secrets` mode (the default) the agent can
neither read nor change anything in it; `off` only watches and hides
nothing. `mandu paths` lists every location below with what it holds,
whether it exists yet and its mode (`--json` gives the same list as data),
and `mandu doctor` warns when other users on the machine can open any of it.
A location that is a link to something that is not there (a moved folder on
a disk that is not mounted) shows as a "broken link" in `mandu paths`,
`mandu doctor` and the dashboard.
The dashboard's home page shows the same list, under "Where your data lives".

Mandu creates every folder in `~/.mandu` as `0700` and every file as `0600`
(owner only); when it finds the folder, `state/` or `events/` open to other
users, it tightens them and says so once.

| Location | Mode | What is there |
|---|---|---|
| `~/.mandu/` | `0700` | Mandu's folder: your settings at the top, Mandu's own data in the folders below |
| `~/.mandu/config.toml` | `0600` | your default settings (written by `mandu init` and `mandu mode`) |
| `~/.mandu/policy.yaml` | `0600` | your rules: which files, hosts and models count as secret |
| `~/.mandu/packs/`, `~/.mandu/pack-keys/` | `0700` | rule packs you installed, and the keys of the publishers you trust |
| `~/.mandu/prompt-filters/` | `0700` | your pattern packs for checking your own prompt |
| `~/.mandu/secrets.json` | `0600` | API keys for Mandu's developer tools (developers) |
| `~/.mandu/dashboard.env` | `0600` | settings for a dashboard that runs as a service, including its login password |
| `~/.mandu/state/` | `0700` | Mandu's lasting data; deleting it loses your approvals and history |
| `~/.mandu/state/mandu.db` | `0600` | the placeholder table (which `$MDU:` placeholder stands for which real value) and your approvals |
| `~/.mandu/state/mandu-test.db` | `0600` | the same, for Mandu's own tests |
| `~/.mandu/state/workspaces/` | `0700` | Mandu's copies of the projects you ran it in |
| `~/.mandu/state/object-walks/` | `0700` | notes from checking your git history for protected files |
| `~/.mandu/state/paired-approvals/` | `0700` | one-time approvals for evaluation runs (developers) |
| `~/.mandu/state/dashboard-account.json` | `0600` | your dashboard account: its username and a scrambled form (a scrypt hash) of its password, never the password (`mandu dashboard --set-password`) |
| `~/.mandu/state/launch-logs/` | `0700` | what each launch said: its notices, warnings, protection layers and helper messages, one `0600` file per launch, the last 20 kept (`mandu log` shows the latest) |
| `~/.mandu/state/last-scan.json` | `0600` | the last `mandu scan`: which of your secrets reached the AI, by name and file, with hosts, dates and counts, never a value (the dashboard's Home and Scan page, `mandu doctor`) |
| `~/.mandu/events/` | `0700` | the session history the dashboard shows, kept 90 days; it includes the real values behind placeholders (`events/test/`: Mandu's own tests) |
| `~/.mandu/runs/` | `0700` | test and evaluation results (developers): `test-runs.json` and `test-runs/` (the dashboard's test runs and their results), `drills/` (the maintainers' drill records), `ci/`, `matrix/`, `eval/` |
| `~/.mandu/dev/docker-e2e-home/` | `0700` | logins for Mandu's container tests (developers) |
| `~/.mandu/cache/` | `0700` | files Mandu can rebuild; safe to delete: `object-twins/` (copies of your git data with the protected files taken out), `update-check.json` (the answer of the last check for a newer Mandu release, see [Updates](#install)) and `ci/` (virtual machine images for Mandu's CI, developers) |

`runs/` and `dev/` appear only on a developer's machine, the first time a
developer tool writes there. Outside the folder:

| Location | Mode | What is there |
|---|---|---|
| `/run/user/<uid>/mandu/` | `0700` | running services and per-session files (a session that ends cleanly removes its own; `mandu reap` collects the rest); cleared when the machine restarts (`$XDG_RUNTIME_DIR/mandu`; without `XDG_RUNTIME_DIR`, your own `mandu-<uid>` folder under `$TMPDIR` or `/tmp`, private to you, so no other account on the machine can claim the name first) |
| `~/.local/share/mandu/` | `0755` | the installed program, if you used `install.sh`; also `exec-box/`, a copy of the command sandbox's helper, made when the runtime folder above is under `/tmp` |
| `~/.local/bin/mandu` | | the `mandu` command, if you used `install.sh` |

The placeholder table and the event log hold your real values, which is why
the folder is yours only and hidden from the agent.

**Moving it.** Set `MANDU_HOME` to keep the whole folder somewhere else, on a
local disk (the database does not work over NFS). It moves everything in the
folder at once; nothing in it has a variable of its own. Outside the folder,
`MANDU_RUNTIME_DIR` moves the runtime folder, and `install.sh` takes
`MANDU_PREFIX` and `MANDU_BIN_DIR`. A second runtime folder is a second
Mandu (a test copy, say); while the first one runs, the second needs a
Mandu folder of its own too (`MANDU_HOME`), because only one Mandu at a
time writes a folder's database (the second one's start is refused).
`mandu stop` normally stops every copy you run.
When its environment points at a second copy (through `MANDU_RUNTIME_DIR`, or
an `XDG_RUNTIME_DIR` or `TMPDIR` other than your login session's),
`mandu stop` refuses if it would also reach another one. It then names the
two choices: `--stack <runtime folder>` for that copy only, or
`--every-stack` for all.

**Backing up.** Stop Mandu (`mandu stop --all`), then copy `~/.mandu`; you
can leave out `cache/`.

**Removing it.** Remove the program ([Uninstall](#uninstall)), then
`rm -rf ~/.mandu`. The runtime folder goes away at the next restart.

The design: [on-disk-layout.md](design/architecture/on-disk-layout.md).

---

## Uninstall

End your agent sessions first, so that anything in flight is synced back to
your folders, then:

```sh
mandu stop --all                   # stop the background services
mandu setup --uninstall            # only if you ran `mandu setup`
npm uninstall -g @mandusec/mandu   # if you installed with npm
rm -rf ~/.local/share/mandu ~/.local/bin/mandu    # if you installed with install.sh
```

If you installed with npm, also remove `~/.local/share/mandu/exec-box` if it
exists (a copy of the command sandbox's helper, made when the runtime folder
is under `/tmp`).

Your settings, rules and history stay behind in `~/.mandu` until you remove
it: `rm -rf ~/.mandu`. The per-session files left in `/run/user/<uid>/mandu`
(a session that failed or was killed keeps its own) go away at the next
reboot, or now with `mandu reap`. The full list is in
[Where Mandu keeps its files](#where-mandu-keeps-its-files).

---

## Good to know

- Mandu never needs an API key to *run your agent* — it relays your existing
  Claude Code / Codex login.
- Protection is **cooperative** (userspace) at the model API and the proxies,
  plus the native guard, the command sandbox and Landlock where the kernel
  allows them, all without root. `mandu doctor` always tells you which parts
  are live on your machine, and [`docs/guarantees.md`](guarantees.md) says
  in plain words what is guaranteed and what is not.
- To go back to running your agent unprotected, just drop the `mandu` prefix.
