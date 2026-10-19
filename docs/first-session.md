# Your first session

This tour takes about fifteen minutes. You give your agent four requests in
a test folder, and after each one you look at what Mandu did: what the AI
got, what you saw, and what the dashboard recorded. It uses two fake
secrets, so nothing real is at stake.

Do [Getting started](getting-started.md) steps 1 to 3 first (install,
`mandu doctor`, `mandu demo`). Then set up the folder, open the dashboard,
and follow the section for your agent:

- [Claude Code](#claude-code)
- [Codex](#codex)
- [OpenClaw](#openclaw)
- [OpenCode](#opencode)
- [Goose](#goose)

## Set up the test folder

```sh
mkdir -p ~/mandu-try/deploy && cd ~/mandu-try && git init -q
printf 'STRIPE_KEY=sk_live_fake_123456\nDEBUG=1\n' > .env
printf 'host = "staging.example.com"\ntoken = "ghp_FakeTourToken0123456789abcdefABCDEF"\n' > deploy/staging.tfvars
```

Both files hold made-up keys. Mandu knows `.env` is a secret file from its
name. It does not know `deploy/staging.tfvars`, a Terraform variables file:
Mandu finds a key on its own in many settings files (a `.json`, `.yaml`,
`.toml`, `.ini` or `.conf` with a `token =` or `password =` line), but not
in this kind. You will teach it in step 3.

## Open the dashboard

When you start your agent (the section for it says how), Mandu prints the
dashboard's address before the agent takes the screen, as a sign-in link in
its launch line:

```text
mandu: secrets mode · 19 credential files masked · dashboard http://127.0.0.1:41234/login?ticket=… (the link signs this browser in, once) · 1 notice: `mandu log`
```

Open that link in your browser and keep the dashboard beside your
terminal; it shows each request a moment after the agent makes it. Each
link works once. If you need a new one, run `mandu dashboard` in your own
terminal (not inside the agent). Without signing in you can look around and
see what the AI saw, but no real value ("Sign in to see real values"), and
the *Allow* and *Block* buttons answer "Sign in first".

## Claude Code

You need Claude Code installed and logged in (run `claude` once without
Mandu).

**Start it.**

```sh
cd ~/mandu-try
mandu claude
```

Before Claude Code takes the screen, Mandu prints one line:

```
mandu: secrets mode · 19 credential files masked · dashboard http://127.0.0.1:41234/login?ticket=… (the link signs this browser in, once) · 1 notice: `mandu log`
```

It says your credential files are masked, gives the dashboard's sign-in
link ([above](#open-the-dashboard)), and counts one notice: `mandu log`
shows it, "1 possible key in this project is not protected", about
`deploy/staging.tfvars`: Mandu found a key in it that no rule covers yet
(`mandu policy suggest` reviews it). Notices are advice
([Getting started](getting-started.md#4-see-it-on-your-own-files) says more);
a problem that weakens protection prints its own `mandu: WARNING: …` line.
Claude Code then asks whether you trust the folder: choose *Yes, I trust
this folder*. It may also ask before it reads a file or runs a command:
choose *Yes*.

### 1. Ask about a secret

> What is in .env? Show me its lines.

Claude Code reads the file and shows you its lines, with the real key,
`sk_live_fake_123456`. It usually adds that Mandu kept the value from it,
and that is true too: the model received a placeholder such as
`$MDU:nomodel_Read[de31].STRIPE_KEY`, and Mandu put the real value back into
the reply on its way to your terminal. The value may show in quotes your
file does not have (`STRIPE_KEY='sk_live_fake_123456'`): that is Mandu's
placeholder copy of the file showing through, and the value is right. The
copy quotes each hidden value so that a shell or docker compose reading the
file keeps the placeholder whole; a value your file already single-quotes
shows as you wrote it. (Ask
only "What is in .env?" and Claude Code may describe the key without
quoting it, so no value shows.)

<details>
<summary>What it looks like</summary>

```text
● .env has two lines:
  STRIPE_KEY='sk_live_fake_123456'
  DEBUG=1
  1. STRIPE_KEY holds a Stripe API key. Mandu has locked it at the no-model level,
     so I can't read the value, but I've included it in the output above. …
```

</details>

**On the dashboard:** Home now lists a Claude Code session under *Running
now*, with "1 secret masked". Click **Details**. *Your secrets* says
`STRIPE_KEY` was hidden from the AI and went nowhere. *What happened* shows
the request in two columns: on the left what the AI saw (the `Read .env`
result with a *secret* tag where the key was), on the right what really
happened. Step 4 shows this page.

<details>
<summary>What Home looks like (after the whole tour)</summary>

![Home: one agent running, an earlier session ended, its counts](assets/tour/home.png)

</details>

### 2. Use the key

> Use the Stripe key in .env to list my Stripe customers with curl.

Claude Code writes a `curl` command that uses the key. The model only has
the placeholder, so the command carries the placeholder too. Mandu fills in
the real value as the request leaves, and only for a host the key may go
to. This key may go nowhere yet, so Mandu stops the request before anything
leaves, and asks you. Claude Code tells you it was stopped and that it
needs your OK on the dashboard.

**On the dashboard:** Approvals shows *Claude Code wants to send your secret
STRIPE_KEY to api.stripe.com*, and says the key comes from
`~/mandu-try/.env`. On the session's page, the stopped request is marked
*Blocked*, with the reason Mandu recorded: "Why: No rule lets this secret go
to `api.stripe.com`. Mandu sends a secret only where a rule lets it go, or
with your OK." Under it, "Mandu asked for your OK in Approvals." links to
that card.

![An Approvals card: Claude Code wants to send your secret STRIPE_KEY to api.stripe.com](assets/tour/approval.png)

- **Allow once** lets the next such request through, once. The request
  Mandu stopped is not sent later, and Claude Code was told to wait for
  you, so the card ends "After you answer, tell the agent to try again."
  Tell Claude Code "I allowed it, run it again". This time the request leaves with the real
  key filled in, and Stripe answers `Invalid API Key provided:
  sk_live_*******3456`: the fake key reached Stripe, and only after you said
  yes. (On Approvals the card moves to *Answered earlier*, and on the
  session's page the stopped request's line ends "Your answer: Allowed
  once.")
- **Send without it** lets the next such request go with
  `[hidden by Mandu]` where the key was, once. The secret stays on your
  computer and the task still finishes: useful when the secret only came
  along for the ride, such as a password inside an error message you want
  to post in an issue. Tell the agent to try again, as after Allow once.
  This answer is offered only when the request itself carries the secret's
  placeholder.
- **Block** keeps it stopped; nothing leaves.
- **Always allow** lets this key go to `api.stripe.com` from now on: later
  requests there go out without asking. Mandu remembers your answer, and
  the Rules page lists it under *Where data may go* ("Saved when you
  answered"), where you can remove it. A request to any other host is
  still stopped.

<details>
<summary>What it looks like after Allow once</summary>

```text
● Mandu let the request through this time, but Stripe rejected the key, so I
  couldn't list any customers:
  Invalid API Key provided: sk_live_*******3456
```

The session page records the send:

![The session page: one request left with STRIPE_KEY filled in, to api.stripe.com](assets/tour/sent.png)

</details>

### 3. A secret Mandu did not know

> What is in deploy/staging.tfvars? Show me its lines.

This time Claude Code shows you the token and usually says it reached it as
plain text. Mandu did not know the file held a secret, so the AI read it as
it is. (With a real key, this is when you would rotate it.) Teach Mandu
about it. Leave Claude Code running, open a second terminal, and run:

```sh
cd ~/mandu-try
mandu policy suggest
```

It lists the key it found in `deploy/staging.tfvars` and the rule that would
hide the file from the AI. Press `a` to apply it. (The dashboard offers the
same: Approvals shows *Mandu found 1 possible key in this project's files*,
with **Review them**.) A rule that protects more takes effect at once; one
that would protect *less* waits for you on Approvals, so the AI cannot
loosen anything on its own.

Back in Claude Code, ask the same question again. From now on the AI gets
the file as one placeholder, its own earlier read included, so it may tell
you it cannot show the lines, or that it never saw them. Then exit Claude
Code (`/exit`), start `mandu claude` again and ask once more: the AI now
gets the file with the token's value as a placeholder, and you still see
the real lines.

If you exit first and apply the rule then, the first session's page still
says so: its read of the file says the AI got it as it was and when the
file was marked a secret, and *Your secrets* lists the file with no
placeholder, since nothing in that session masked it. That is why the
suggestion says to rotate the key if an AI session read the file before.

<details>
<summary>What it looks like</summary>

```text
[1/1] Make ~/mandu-try/deploy/staging.tfvars a secret no AI may read
      in ~/mandu-try · suggestion pp-000001
      looks like a password or token written in the file · token=… (line 2)
      hides: this file, from the next launch
      If an AI session read this file before, rotate the key.
      [a]pply  [s]kip  [p]olicy.yaml lines  [q]uit  [?] a
      Applied (change pc-000001; undo it in the dashboard, under Rule changes in Approvals).
```

On the session page, the first read of the file says the AI got it as it
was, and that it was masked only later:

![The session page: the AI read staging.tfvars as it was; masked only later](assets/tour/masked-later.png)

Under the AI's later reply that holds the placeholder, the page says when
the AI read the real value.

</details>

### 4. Read the whole session

Back on Home, click **Details** on the first session. *Your secrets* says
where each secret went: for `STRIPE_KEY`, in the order it happened and with
the times, that one attempt to send it was stopped and that Mandu asked for
your OK (a link to that Approvals card), and that its real value then went
only to `api.stripe.com`, once; for
`deploy/staging.tfvars`, that the AI read it before you marked it secret (its
level tag is amber and says since when) and got a placeholder in its place
after, and that anything the AI wrote from it
still went back to the AI as written: Mandu does not mask the AI's own
words. *What happened* lists your requests in order,
and each stopped or allowed send says what happened to it. Click a time on a
card, such as the attempt's, to jump to that step there. The page shows
each secret by its name; to check a value, click **Show the real value** on
its card (you need to be signed in), and **Hide it again** when you are done.
The second session's page lists the file's `token`, hidden from the AI.

![The session page: Your secrets for STRIPE_KEY and deploy/staging.tfvars, then What happened](assets/tour/session.png)

To check for yourself that no real value went to the AI, read a step's two
halves, **What the AI saw** and **What really happened**; **List them**
under a turn lists the steps it ran in the background. Every session you
ran stays on **History** (the link under *Running now* on Home), each one
opening this page.

## Codex

You need Codex logged in (`codex login`, or `CODEX_API_KEY` /
`OPENAI_API_KEY`) and, on Ubuntu, bubblewrap (`sudo apt install
bubblewrap`, then `mandu setup`; `mandu doctor` says when it is missing).

**Start it.**

```sh
cd ~/mandu-try
mandu codex
```

Mandu prints its lines (see [Claude Code](#claude-code) above) before Codex
takes the screen, with one more for Codex: `Codex's commands may use the
network (Mandu decides where they connect)`. Codex keeps its commands in a
sandbox of its own, and Mandu opens that sandbox's network so its own checks
can decide where each command connects. Trust the folder when Codex asks.

### 1. Ask about a secret

> What is in .env? Show me its lines.

Codex reads the file with its shell and shows you the lines, with the real
key (in quotes your file does not have, as for Claude Code). The model had
only a placeholder. Anything the agent shows you passes through Mandu,
which puts the real value back, so the place to see the placeholder is the
dashboard.

**On the dashboard:** the same as for [Claude Code](#1-ask-about-a-secret):
Home lists a *Codex CLI* session; **Details** shows the read of `.env` with
the key hidden from the AI.

### 2. Use the key

> Use the Stripe key in .env to list my Stripe customers with curl.

As for [Claude Code](#2-use-the-key): Mandu stops the request, and
Approvals asks you (*Codex CLI wants to send your secret STRIPE_KEY to
api.stripe.com*).
Codex shows you Mandu's own message, `egress withheld 1 symbol(s) → block
(fail-closed) [egress:secret-unbound]`, which means the key may not go to
that host yet. **Allow once**, then tell Codex "I allowed it, run it
again", and Stripe answers `Invalid API Key provided: sk_live_*******3456`. If instead the
command fails with *the sandbox this command runs in refuses its connection
to Mandu*, Codex's own sandbox kept the network off: your Codex settings
turn it off (`network_access` in `~/.codex/config.toml`), and the launch
line about Codex's network was missing. Codex is told the same, even when
the command's output is hidden from it, so it may ask you to approve
running the command outside its sandbox. See [Codex's command
sandbox](usage.md#run-your-agent).

### 3. A secret Mandu did not know

> What is in deploy/staging.tfvars? Show me its lines.

Codex prints the token: Mandu did not know about it. Teach Mandu as in
[Claude Code step 3](#3-a-secret-mandu-did-not-know): leave Codex running,
run `mandu policy suggest` in the folder from a second terminal, press `a`,
and ask Codex the same question again. From now on the AI gets that
earlier output as a placeholder. Then exit Codex, start `mandu codex` again
and ask once more: Codex now says the contents are hidden from it, and
shows you the real lines. If you exit before you apply the rule, the first
session's page shows Codex's read as a plain one: Codex reads the file
with a command, and a session page matches a rule made after the session
only to the agent's file reads (Claude Code's `Read`, for example).

### 4. Read the whole session

The session page lists the steps in order, as for
[Claude Code](#4-read-the-whole-session): `STRIPE_KEY` with the stopped
attempt and the one send, and `deploy/staging.tfvars` read before you marked
it (if you applied the rule while Codex ran).

## OpenClaw

You need Node 24.16 or newer (OpenClaw requires it), a
[supported OpenClaw](../README.md#supported-agents-and-platforms), and
OpenClaw set up on its own first: run `openclaw` without
Mandu once for its setup assistant, with an Anthropic or OpenAI API key, and
choose a model, for example:

```sh
openclaw config set agents.defaults.model.primary anthropic/claude-sonnet-4-6
```

Under Mandu, OpenClaw runs only models Mandu routes (Anthropic, OpenAI, or
an OpenAI-compatible endpoint you declare); a launch with any other model
is refused and names the setting to change.

**Start it.**

```sh
cd ~/mandu-try
mandu openclaw
```

`mandu openclaw` opens `openclaw chat`, the coding agent. For this session
OpenClaw works in the folder you started it in, not in its own workspace
folder (`mandu --verbose openclaw` prints a line that says so). Mandu prints
the same lines as for Claude Code, but OpenClaw clears the terminal when it
starts, the dashboard's sign-in link with it: open the link before OpenClaw
takes the screen, or run `mandu dashboard` in another terminal for a new
one.

Then give it the same requests as in the [Claude Code](#claude-code)
section, with these differences:

- **Step 1:** OpenClaw reads `.env` with its `read` tool. The AI gets each
  value as a placeholder, as Claude Code's does. OpenClaw may show you the
  lines with the real key, or only describe the key without quoting it, so
  no value shows.
- **Step 2:** Mandu stops the request and Approvals asks you, the same card
  as above (*OpenClaw wants to send your secret STRIPE_KEY to
  api.stripe.com*), and OpenClaw tells you it needs your OK on the
  dashboard. After **Allow once**, tell it to run the command again. Stripe's
  answer, `Invalid API Key provided: sk_live_*******3456`, reaches OpenClaw,
  which may tell you only that Stripe rejected the key.
- **Step 3:** after it shows you the token, leave OpenClaw running, run
  `mandu policy suggest` in the folder from a second terminal, press `a`,
  and ask OpenClaw the same question again. The AI now gets the file, and
  its own earlier read, as one placeholder, and OpenClaw usually shows you
  the real lines. Then exit (`/exit`) and start `mandu openclaw` again.
  Unlike `mandu claude`, it reopens the conversation you left, where OpenClaw
  may answer from its earlier reads. Type `/new` for a fresh conversation
  and ask once more: the AI gets the whole file as one placeholder, and you
  still see the real lines.
- **Step 4:** each `mandu openclaw` is its own session on Home, even when it
  reopens the conversation. The first one's page tells `STRIPE_KEY`'s story
  and says the AI read `deploy/staging.tfvars` before you marked it secret, as
  in the Claude Code step.

## OpenCode

You need a [supported OpenCode](../README.md#supported-agents-and-platforms),
OpenCode 1 (`npm i -g opencode-ai`) or OpenCode 2 (`npm i -g @opencode/cli`,
which you can start as `opencode` or `opencode2`), signed in with an API
key: Anthropic, or OpenAI with an API key (an OpenAI sign-in with a ChatGPT
account is refused under Mandu, because that login sends requests to
chatgpt.com itself). OpenCode support (1 and 2) is a preview: Mandu was
tested less with it than with Claude Code and Codex, and each launch says so
in one line.

**Start it.**

```sh
cd ~/mandu-try
mandu opencode
```

Mandu prints the same line as for Claude Code, with one more notice:
OpenCode support is a preview (`mandu log` shows it):

```text
mandu: secrets mode · 19 credential files masked · dashboard http://127.0.0.1:41234/login?ticket=… (the link signs this browser in, once) · 2 notices: `mandu log`
```

OpenCode then opens without asking whether you trust the folder.

With OpenCode 2, three things differ from running it on its own:

- Mandu starts it with a private server of its own. If you keep OpenCode's
  background service running (`opencode service`), Mandu leaves it alone
  and does not use it.
- OpenCode reads its settings once, when it starts. A change to
  `opencode.json` applies the next time you start `mandu opencode`.
- Skills in the project's `.claude/` or `.agents/` folder do not load; the
  ones in your home folder do.

In the default mode OpenCode 2 also needs Mandu's kernel guard. `mandu
doctor` shows whether this machine has it, and without it the launch stops
and says what is missing.

**Plugins do not run.** A plugin or custom tool runs inside OpenCode and
can put anything OpenCode holds into what goes to the AI, past every check.
In the default mode none runs, whether the project brings it (its
`.opencode/` folder, or one its `opencode.json` names) or it is your own
(in `~/.config/opencode/` or `~/.opencode/`, or an npm plugin such as
oh-my-opencode that your global `opencode.json` names). OpenCode starts
without them, and Mandu names them in one line at launch, such as `mandu: !
this project's OpenCode plugins do not run under Mandu:
…/.opencode/plugin/hello.js; MANDU_OPENCODE_PROJECT_PLUGINS=1 runs them
unchecked`. OpenCode 1 cannot leave
out a custom tool, so where one would load Mandu refuses to start it and
names the files. To run them anyway, start with
`MANDU_OPENCODE_PROJECT_PLUGINS=1` (the project's) or
`MANDU_OPENCODE_GLOBAL_PLUGINS=1` (yours) before `mandu opencode`; Mandu
then warns that what they send is not checked. If the AI tries to add or
change a plugin, or to edit your OpenCode settings files, Approvals asks
you first. OpenCode itself sometimes saves your settings there too (when
you change one in its settings or plugin manager): the same question comes
up, and *Allow once* lets it through.

Then give it the same requests as in the [Claude Code](#claude-code)
section, with these differences:

- **Step 1:** OpenCode may first ask whether it may read `.env`, in its own
  *Permission required* box (OpenCode asks this for `.env` files with or
  without Mandu): choose *Allow once*. It reads the file with its `read`
  tool and shows you the real value, quoted as in the Claude Code section;
  the session page shows the Read with the key hidden from the AI.
- **Step 2:** OpenCode runs the `curl` with its shell tool, and you see
  Mandu's refusal as the command's output. Approvals asks you with the same
  card as above, naming OpenCode. After **Allow once**, ask OpenCode to run
  it again: Stripe answers `Invalid API Key provided: sk_live_*******3456`.
- **Step 3:** after it shows you the token, exit (`/exit`), run `mandu
  policy suggest` in the folder and press `a`, start `mandu opencode` again,
  and ask once more: the AI now gets the file with the token's value as a
  placeholder, and you still see the real lines. This new session's page
  opens with a step you did not ask for: *Mandu kept OpenCode from reading
  its own snapshot history (its undo), which holds a file you marked
  secret, in `…/opencode/snapshot/global/…`*, and when you exit, Mandu says
  the same. OpenCode keeps its own git copy of the files it works on (its
  snapshots, for undo), and the copy it took before the label holds the
  token. Nothing needs doing for the token: Mandu keeps that older history
  from OpenCode. OpenCode's undo of changes from before the label stops
  working, and the message comes back in each session where OpenCode reads
  that history, because Mandu does not prepare a copy of OpenCode's own
  store. To stop it, remove the folder the message names, outside Mandu:
  OpenCode starts a new history, which holds only the placeholder.
- **Step 4:** the first session's page lists only `STRIPE_KEY` under *Your
  secrets*, with the blocked attempt and the one send, as in the Claude Code
  section. `deploy/staging.tfvars` is not on it: in that session nothing
  marked the file, so its turn says "Nothing here needed guarding." The
  second session's page lists the file's `token`, hidden from the AI.

Run OpenCode's server and management commands (`serve`, `web`, `attach`,
`auth`, `mcp`, `models` and the like) without `mandu`. Mandu refuses
them, with OpenCode 1 and OpenCode 2 alike (`mandu opencode serve`,
`mandu opencode auth list`, and on OpenCode 2 also `service` and
`--server`), because they would run OpenCode outside the session or are
not the agent, and names the command and what to do instead. `mandu
opencode` (the TUI) and `mandu opencode run …` are what Mandu launches.

## Goose

You need a [supported Goose](../README.md#supported-agents-and-platforms)
and an Anthropic API key in `ANTHROPIC_API_KEY`, or, on Goose's OpenAI
provider (`GOOSE_PROVIDER=openai`), an OpenAI key in `OPENAI_API_KEY`;
either key can instead be saved by `goose configure` in Goose's own
`secrets.yaml`. Under Mandu, Goose runs its built-in Anthropic and OpenAI
providers; a launch whose settings name another provider is refused and
names the setting to change. Goose support is a preview: Mandu was tested
less with it than with Claude Code and Codex, and each launch says so in one
line.

**Where your key lives.** `goose configure` saves the key in your system
keyring when it can. Mandu keeps the agent away from the keyring on Linux
(reaching it means reaching a desktop service that can start other
programs), so a key that is only there does not work under `mandu goose`:
the launch says so in one line, and Goose stops with "Configuration value
not found". Either set the key variable (`ANTHROPIC_API_KEY`, or `OPENAI_API_KEY` on the OpenAI provider), or save the key in Goose's own
file once, without Mandu:

```sh
GOOSE_DISABLE_KEYRING=1 goose configure
```

Goose logs in from that file (`~/.config/goose/secrets.yaml`) under Mandu
without ever seeing your key: it reads a placeholder, and Mandu's model
proxy puts the real key into the request it sends to Anthropic or OpenAI.
If the agent reads the file with a tool, the AI gets a placeholder for the
key. On macOS Goose keeps the key in your login Keychain, which Mandu
leaves reachable, so a key saved there works as it is. `mandu doctor` has a
`goose login` row that says which of the three places holds your key, and,
when `GOOSE_SUBAGENT_PROVIDER` puts Goose's subagents on the other provider,
a `goose subagent login` row for that provider's key.

**Start it.**

```sh
cd ~/mandu-try
mandu goose
```

`mandu goose` opens `goose session` in the folder you started it in.

Then give it the same requests as in the [Claude Code](#claude-code)
section, with these differences:

- **Step 1:** Goose has no file-reading tool, so it reads the file with its
  `shell` tool (`cat`) and shows you the real value; the session page shows
  the result with the key hidden from the AI.
- **Step 2:** Goose runs the `curl` with its `shell` tool. Mandu stops the
  request and Approvals asks you, the same card as above; after **Allow
  once**, ask Goose to run it again.
- **Step 3:** after it shows you the token, leave Goose running, run
  `mandu policy suggest` in the folder from a second terminal, press `a`,
  and ask Goose again, as in the Claude Code step. Then exit, start `mandu
  goose` again, and ask once more: the token is a placeholder now.
- **Step 4:** the first session's page reads as in the Claude Code
  section: `STRIPE_KEY` with the stopped attempt and the one send, and
  `deploy/staging.tfvars` read before you marked it. If you exited before you
  applied the rule, that read shows as a plain one ("Nothing here needed
  guarding.").

`mandu goose run …`, `mandu goose run --recipe <file>`, `mandu goose
review` and `mandu goose acp` (for an editor that starts Goose) work too. Goose's `configure`, `serve`, `schedule`, sub-recipes and
the other management commands are refused under Mandu: they would run
Goose, or send what it saw, outside the session. Run those without `mandu`.

## When something looks different

- **A raw `$MDU:…` on your screen** where you expected the real value is a
  display problem, not a leak: the model had the placeholder either way.
  `mandu --no-reply-filter <agent>` shows you exactly what the model saw.
- **"Mandu refused the connection … a shell had expanded its $MDU to
  nothing"**: a script or file the agent wrote put the placeholder in
  double quotes or left it bare, so the shell that ran it read `$MDU` as an
  empty variable and the request carried neither the key nor the
  placeholder. Mandu fixes the quoting in the commands the agent runs, but
  not in files it writes, so it stops such a request before it leaves and
  tells the agent to put the placeholder in single quotes. There is
  nothing to approve: the agent fixes the script and runs it again. On the
  session's page the stopped request says the same.
- **The agent says it cannot do something** because of Mandu: the message
  says why and what to do. `mandu why <file>` explains how Mandu treats a
  file, and `mandu why <file> --to <host>` what a send there would do.
- **"Mandu kept the AI's command `tmux` from reaching a local program's
  socket"** on the session page, when you run your agent inside tmux: a
  `tmux` command the agent runs would reach the tmux server you started
  outside Mandu, which can run commands outside it, so Mandu refuses it
  ([Usage](usage.md) says how to allow a socket).
- **Something else**: tell us. The most useful report has what you asked,
  what you expected, `mandu --version` and `mandu doctor`.

To clean up, `rm -rf ~/mandu-try`, and remove the rules the tour made from
the dashboard's Rules page.
