# Getting started

This walk-through takes about ten minutes. At the end your agent runs under
Mandu, you have seen a secret reach the AI only as a placeholder, and you know
where to approve the requests Mandu holds for you.

You need:

- **Linux** (x64). Ubuntu 24.04 and 26.04 are tested; nothing needs `sudo`.
  Or **macOS** with Claude Code (new; tested on one arm64 Mac): the steps are
  the same, except that a program the agent runs cannot read a credential file
  at all instead of seeing a placeholder (posture `read-blocked`, see
  [Using Mandu](usage.md#install)). Node from Homebrew works: `brew install node@22`.
- **Node.js 22.13 or newer** and **git**. (No Node? Step 1 has an installer
  that brings its own.) Node programs the AI runs need Node 22.21 or newer
  (or 24.5 or newer) on your PATH to get your secrets on their web requests;
  `mandu doctor` checks it.
- **Your agent, installed and logged in**: Claude Code (`claude`, run it once
  and log in) or Codex (`codex login` once, with a ChatGPT plan or a saved
  key, or an OpenAI API key in `CODEX_API_KEY` or `OPENAI_API_KEY`). Mandu
  uses the agent's own login and needs no API key of its own.
- **For Codex on Ubuntu: bubblewrap.** Codex runs its commands in its own
  bubblewrap sandbox, which a stock Ubuntu does not ship, and every command
  fails without it (with or without Mandu): `sudo apt install bubblewrap`,
  then `mandu setup` (Mandu's own bubblewrap, which `mandu codex` gives
  Codex). `mandu doctor` tells you when this is missing.
- **Your distribution's bubblewrap, with the CVE-2026-87766 fix, where you
  have bubblewrap.** Mandu ships no bubblewrap and downloads none: like
  Claude Code and Codex, it runs your distribution's (`sudo apt install
  bubblewrap`, `sudo dnf install bubblewrap`), and never a `bwrap` inside
  the folder you launch in. Builds without the fix follow symlinks while
  they set up a sandbox. Mandu still works with one and says so on each
  launch that uses it; `mandu doctor` tests the one Mandu runs (its version
  number alone does not tell: distributions backport the fix and have
  removed it again) and names the upgrade
  ([Troubleshooting](usage.md#troubleshooting)).

## 1. Install

With Node 22.13 or newer:

```sh
npm install -g @mandusec/mandu
```

No Node, or an older one? Each
[release](https://github.com/ManduSec/mandu/releases/latest) also carries an
installer that brings its own. Download its three files into one folder,
`mandusec-mandu-<version>.tgz`, `SHA256SUMS` and `install.sh`, and in that
folder run:

```sh
sh install.sh
```

With the [GitHub CLI](https://cli.github.com/) both steps are one line:

```sh
gh release download -R ManduSec/mandu -p '*' --clobber && sh install.sh
```

`install.sh` installs for your user only, with no `sudo`: it uses your Node when it is
22.13 or newer and otherwise downloads one for Mandu alone (checksum-checked),
puts the package under `~/.local/share/mandu`, and `mandu` in `~/.local/bin`.
The script names its release's package and that package's SHA-256, and
installs nothing if the file does not match. To update, do the same with the
newer release.

Or by hand, with your own Node 22.13+, in the same folder:

```sh
sha256sum -c SHA256SUMS                 # prints "...tgz: OK"
npm install -g ./mandusec-mandu-*.tgz
```

Check that it is on your PATH:

```sh
mandu --version
```

## 2. Check your machine

```sh
mandu doctor
```

`doctor` checks Node, git, your agent and its login, and which protection
layers your kernel supports. Each row says what to fix if something is
missing. The line to look for is the secrets posture:

- **confined**: programs the agent runs get placeholders instead of your
  credential files. This is what you want, and what a stock Ubuntu gives you.
- **gated**: the AI still never sees your keys, but a program the agent runs
  could open a credential file. `doctor` names the cause.

## 3. Watch the demo

```sh
mandu demo
```

The demo runs the real Mandu components against a stand-in AI, offline, with
no key. It makes a throwaway project with a fake Stripe key in `.env`, then
plays three steps with Claude Code's requests and again with Codex's:

```
Claude Code ────────────────────────────────────────────────
 1  The agent reads .env
      the AI got      STRIPE_KEY=‹hidden›
                      DEBUG=1
      you see         STRIPE_KEY='sk_live_demo_fake_unyk4shpfj6t9qte'
                      DEBUG=1
 2  The agent uses the key (curl to api.stripe.com, where it may go)
      sent            api.stripe.com got the real key, filled in on the way out ✓
 3  …and tries to send it somewhere else (paste.example)
      stopped         nothing was sent to paste.example;
                      in a real session the dashboard asks you ✓
Codex ──────────────────────────────────────────────────────
 1 · 2 · 3            the same three steps, through Codex  ✓ ✓ ✓

✓ The AI never got the key. It went only to api.stripe.com, and you saw it.
```

That is the whole idea: the AI works with placeholders (`‹hidden›` here),
you see the real values, and the key still works, but only where it may go.
The two web hosts are stand-ins on your machine too, so nothing leaves it.
`mandu demo --verbose` also shows what runs underneath; steps 2 and 3 need
`curl` and `openssl`.

Codex reads `.env` with its shell (`cat .env`), and Mandu shows a shell
command's output key by key only when its guard watched the command run. On
a machine without the guard (macOS, or a Linux build without it), Codex's
step 1 shows `‹hidden› (the whole file)` and the line under it says why; the
key stays hidden either way.

## 4. See it on your own files

In a scratch folder, make a fake secret and read it through Mandu, once as
the AI's programs see it and once as you see it:

```sh
mkdir -p ~/mandu-try && cd ~/mandu-try && git init -q
printf 'STRIPE_KEY=sk_live_fake_123456\nDEBUG=1\n' > .env

mandu --no-reply-filter -- bash -c 'cat .env'    # what a program the agent runs gets
mandu -- bash -c 'cat .env'                      # what you see on your screen
```

The first command prints a placeholder (`$MDU:nomodel_Read[…]…`) where the values
were; the second prints the file as it is, because the reply filter resolves
placeholders for you. `--no-reply-filter` is only for looking; leave the
filter on for real work.

The first launch starts Mandu's background service and prints a line such as:

```
mandu: secrets mode · 14 credential files, 3 env vars masked · dashboard http://127.0.0.1:38121/ · 1 notice: `mandu log`
```

A notice is advice; the launch is protected either way. `mandu log` shows
what the launch said in full. For example, `mandu: ! 382 places were not
searched for secrets: folders more than 4 levels deep, in ~/project/app
(301), … and 12 more elsewhere` means Mandu found folders or files it could
not check (here, very deep directory trees in your checkouts); run `mandu
doctor --secrets` for the full list and what to do about each. A problem
that weakens protection is never only counted: it prints its own short
`mandu: WARNING: …` line under the launch's line. `--verbose` prints
everything on the terminal instead.

## 5. Run your agent

Put `mandu` in front of how you usually start your agent. Everything after the
agent's name is passed through unchanged.

```sh
cd ~/mandu-try
mandu claude            # or: mandu codex
```

With Codex the launch also prints `mandu: ! Codex's commands may use the
network …`: Codex runs its commands in a sandbox with no network, which
would stop the `curl` below before Mandu could check it, so `mandu codex`
turns that network on and Mandu decides where each command may connect
([details](usage.md#run-your-agent)).

Ask it something that touches the secret, for example *"What is in .env? Use
the Stripe key to list my customers with curl."* You will see the real value
in the agent's answer; the model only ever received the placeholder. The
`curl` request is sent to `api.stripe.com` only if the key is bound to that
host (see step 7); otherwise Mandu stops it and asks for your OK on the
dashboard (step 6). After *Allow once*, ask the agent to run it again.
[Your first session](first-session.md) walks through this, and what the
dashboard shows at each step, for each agent.

To protect every session without thinking about it, add an alias to your
shell profile:

```sh
alias claude="mandu claude"
```

## 6. Open the dashboard

Every `mandu claude` prints the dashboard's address before the agent starts,
as a sign-in link in its launch line:

```text
mandu: secrets mode · 14 credential files masked · dashboard http://127.0.0.1:41234/login?ticket=… (the link signs this browser in, once)
```

Open that link to sign in; the browser stays signed in until the dashboard
restarts. Each link works once. For a new one, run this in your own terminal:

```sh
mandu dashboard
```

It prints the address and a `sign in (this link works once): …` line. Only
your own terminal can get a link: the agent, and anything it runs, cannot (see
[the dashboard](usage.md#the-dashboard-on-the-network) for why). Without
signing in you can look around, but Allow, Block and rule changes answer
"Sign in first".

The dashboard (local only, on `127.0.0.1`) shows:

- **Home**: whether you are protected, and what each agent read, ran and was
  stopped from doing.
- **Approvals**: requests waiting for your OK, such as a secret about to be sent
  to a host it is not bound to, or a program asking to read a secret file.
  Answer with *Allow once*, *Always allow* or *Block*; a secret inside a
  request can also be answered *Send without it*, which sends that one request
  with `[hidden by Mandu]` in the secret's place. The browser can notify
  you when something arrives.
- **Rules**: your secret files and folders, where each secret may go, and the
  protection mode.

## 7. Tell Mandu where a secret may go

Mandu recognizes the usual credential files by itself. To say where a secret
is allowed to travel, or to mark a file secret that it does not know about, use the
dashboard's Rules page, or edit `~/.mandu/policy.yaml`:

```yaml
version: 1
paths:
  - path: ~/mandu-try/.env
    level: no-model
    bindings: [api.stripe.com]      # the real value may be sent here, and nowhere else without asking
```

*Always allow* on an Approvals card does the same for one key and one
host, without editing the file: the Rules page lists your answer under
*Where data may go*. A hand edit to `policy.yaml` that adds a binding, or
otherwise protects less, waits on Approvals until you allow it, because any
program that can write the file could have made the change; one that
protects more applies at once. `mandu why ~/mandu-try/.env` shows how Mandu treats a file and which
rule decided. The user guide has the full format:
[Secrets in `policy.yaml`](usage.md#secrets-in-policyyaml-who-may-read-what-and-what-leaves).
`no-model` is one of four levels; `any-model` and `local-model` (only a model
you or your organization run, such as Ollama on this computer or vLLM on your
network) let a model read a file you choose, and are explained there.

## 8. Choose a mode

The default mode, `secrets`, protects your credentials. It does **not**
protect against instructions hidden in web pages or other people's files
(prompt injection). The other mode, `off`, enforces nothing and only records
what happens:

```sh
mandu mode          # show the running mode and the saved one
mandu mode off      # save another mode
mandu stop          # the mode applies from the next start
mandu claude
```

The modes that mask untrusted content, `injection` and `full` (the paper's
prompt-injection defense), are frozen and experimental: they run only with
`MANDU_EXPERIMENTAL_INTEGRITY=1` set, and every entry point refuses them
otherwise ([why](design/architecture/protection-modes.md)).
[What Mandu guarantees](guarantees.md) says exactly what each mode covers.

## Next steps

- [User guide](usage.md): every command, setting and flag, and troubleshooting.
- [How Mandu works](how-it-works.md): what happens behind the scenes.
- [What Mandu guarantees](guarantees.md): the promises, the limits, and how
  to check them on your machine.

To stop using Mandu for a session, start the agent without the `mandu`
prefix. To remove it entirely, see [Uninstall](usage.md#uninstall).
