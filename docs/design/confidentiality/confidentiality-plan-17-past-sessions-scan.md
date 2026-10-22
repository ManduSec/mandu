# Plan 17: the past-sessions scan (`mandu scan`)

> **Status: phase 1 built (2026-10-21)**, Claude Code and Codex, with the
> riskier sessions (§3 item 10) and the secrets commands sent over HTTP
> (item 11); phase 2's exact join to Mandu's sessions (item 6), each
> finding's story with redacted examples (§1, item 4), and the kept
> report, the dashboard's Home card and Scan page, `mandu doctor`'s line
> and the suggestions (items 12, 13), built 2026-10-21; **phase 2's
> readers built (2026-10-21)**: OpenCode (1.x and 2.x), Goose and OpenClaw
> (§4); and (2026-10-21) the story's provider from the agents' own
> settings, a web fetch's URL in the story (§3 item 4) and the Scan page
> in the dashboard's top bar; **phase 3 built (2026-10-21)**: Gemini CLI
> and Copilot CLI read, Cursor's chats counted only, agents Mandu does
> not run (§4); **the compact default report (2026-10-22)**: one short
> entry per secret, colour on a terminal, "leaked" in the terminal's
> words, the long form under `--all` (§2); **the other sends
> (2026-10-22)**: over ssh, with git, by an inline script and in an MCP
> tool's input (§3 item 11, *Beyond HTTP*), the key-shaped values that
> look like test values marked and not counted (item 14), and the compact
> report's command cut at an argument or path boundary (§2). A
> read-only, offline scan of the transcripts an agent already keeps on
> disk, for secrets that have already reached a model. Builds on the
> git-history scan ([`secret-discovery.md`](secret-discovery.md) §3), whose
> detector and report rules it reuses. Code:
> `arbiter/policy/transcript-scan.ts` (Claude Code's and Codex's readers,
> the scanner, the file layer), `arbiter/policy/transcript-readers.ts`
> (OpenCode's, Goose's and OpenClaw's readers),
> `arbiter/policy/transcript-stores.ts` (their stores, SQLite read-only),
> `arbiter/policy/transcript-unwrapped.ts` (phase 3: Gemini CLI's and
> Copilot CLI's readers and stores, Cursor's count),
> `arbiter/policy/transcript-acts.ts` (the tool calls and session habits,
> the sends), `arbiter/policy/transcript-test-values.ts` (item 14),
> `arbiter/policy/transcript-redact.ts` (what an example may show),
> `arbiter/policy/transcript-providers.ts` (where the agents' settings send
> their requests),
> the arbiter op `scanAgentTranscripts`, `launcher/src/scan-command.ts`;
> phase 2: `launcher/src/scan-kept.ts` (the kept report, doctor's line),
> `dashboard/src/view-model/last-scan.ts` (Home's card, the Scan page),
> `arbiter/policy/transcript-suggestions.ts` and the op `suggestFromScan`.

## 1. The question

Every other part of Mandu works from the next session on. A person deciding
whether to install it cannot see the risk: a leak to the AI provider makes
no error and leaves no trace on their screen. But the agents leave a trace
on disk. Claude Code writes every request's messages to
`~/.claude/projects/<project>/<session>.jsonl` (a subagent's to
`<session>/subagents/*.jsonl`), Codex to
`~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`, and OpenCode, Goose and
OpenClaw keep their own session stores (the catalog already labels them
`no-model`: `secret-catalog.ts` `OPENCODE_DATA_SHAPE_RE`,
`GOOSE_DATA_SHAPE_RE`; the table of agent stores in supported-agents.md
§2.3). A key that is in the sent part of a record was in a request to the
model.

So the question: **which of my secrets have my agents already sent to the
AI, when, and how?** Answered on the person's own machine, from their own
history, before they install anything else.

The reader is someone who runs Claude Code, Codex or another agent
*without* Mandu and has never used it (decided 2026-10-21, on the first
report's feedback). The report shows them that their secrets already left
the machine, and exactly how, as a story told from the record for each
finding: where the secret lived; what the agent did (the command it ran,
redacted, or the file it read), with the date, the project and the agent;
that the output, with the secret in it, left the computer in the agent's
next request to its model provider (Anthropic for Claude Code, OpenAI for
Codex, "the model provider" when the record or the settings point
elsewhere); what came next when the record shows it (the AI wrote it out
again, a command sent it on over the network or to an MCP tool); and,
for the person's own secrets,
what Mandu would have done instead. Sessions that ran with Mandu are a
footnote, not a column.

The terminal report is short and direct (the maintainer, 2026-10-22: the
long one was "difficult to interpret"; "3 secrets reached AI -> 3 secrets
leaked to AI"; "easier and yet simpler"). By default it gives each of
your secrets one entry (its name and file, sessions, the ways it got
there, the one command when one is all it took, the hosts a command sent
it to), the key-shaped values one line, the riskier sessions, and what to
run; the stories are `--all`'s and `--show`'s. Its words are "leaked to
the AI", in the terminal report and `--show` only: `--share` (a text the
person posts), `--json`, the kept report, `mandu doctor` and the
dashboard keep "reached the AI" (the maintainer chose "CLI report only").
"Leaked" is never said of what the record cannot show leaked: a finding
seen only in sessions under Mandu (the AI saw a placeholder) is not in
the count, one seen only by time is counted with a footnote, as before,
and a send through the secret's variable is said to be one ("through its
variable"), not a value the AI had.

## 2. What it is

```
$ npx @mandusec/mandu scan
mandu scan · 828 sessions · Claude Code, Codex · 29 Sep – 21 Oct
Nothing was sent anywhere; no secret value is shown.

✗ 2 of your secrets leaked to the AI

  1  accessToken   ~/.config/some-cli/credential.json
     1 session, 19 Oct · a command printed it: cat ~/.config/some-cli/credential.json
  2  STRIPE_KEY   ~/shop/.env
     3 sessions, last 19 Oct · the agent read the file, a command printed it
     also sent over HTTP to api.stripe.com · tried hooks.vendor.dev (through its variable)

  → Rotate these 2 now, where they were issued.

! 276 more key-shaped values leaked (not in your files now: old
  keys, someone else's, or test values)
  sk-… ×190 · sk_live_… ×31 · ghp_… ×24 · AKIA… ×12 · xoxb-… ×7 · …
  12 more values named like a secret (DB_PASSWORD=…, a password in a URL): mandu scan --all

! Risky sessions
  371 ran with permission prompts off (in 1, one of your secrets leaked)
  8 printed your whole environment to the AI

87 sessions ran while Mandu ran (by time): there the AI may have seen a placeholder; 54 findings above were seen only there.

✓ With Mandu, these 3 secrets stay safe: the AI sees only a $MDU:… placeholder, and your agent still does its work.
  Protect your agents:  mandu claude  (or mandu codex)
  One in full:          mandu scan --show 1   Everything: mandu scan --all
  Dashboard:            http://127.0.0.1:4500/scan
```

The layout is the maintainer's (2026-10-22). Each of your secrets is one
entry: its name, its file (dim), its sessions and last date, the ways it
got there in short words, most first, three at most (you pasted it, a
command printed it, the agent read the file, the AI wrote it, the agent
attached it, a tool returned it), and when one way and one command is
all the record shows, that command as the arbiter redacted it, its first
line cut near 40 characters at an argument's end, never inside one
(`shortCommand`, 2026-10-22: the cut used to fall mid-path): a path or
URL the cut falls in keeps its head and its last part with `…` between
(`cat ~/.config/some-cli/…/credential.json`; up to 10 characters past
the cut when only the head and the last part are left), else it is cut
after a `/`; a long word with no `/` is dropped whole, or, when it is all
there is, cut after a separator and never inside a `‹NAME›` mask; ` …`
where anything after was left out. A command or tool that sent the
secret on is one yellow line under it, per way, in this order: `over
HTTP to`, `over ssh to`, `with git to`, `by a script to`, `to an MCP
server's tool` (item 11) (the hosts the scan cannot tie to the key
first; "tried" a host where every send failed or was refused, a way
that only tried after the ways that went; "through its variable" when
no send carried the value itself); every send in full is `--all`'s.
The key-shaped values are one line by their masked prefix with how
many values each (five, then `…`), those that look like test values
(item 14) one dim line, `N more look like test values (…), not counted:
mandu scan --all`, the values named like a secret a count. The numbers
are `numberedFindings`'s: your secrets 1 to k as listed, then the
key-shaped values, those that look like test values, the values named
like a secret and what Mandu kept, which `--all` lists under the same
numbers, so `--show <n>` always means the same finding. Nothing found of
yours: `✓ None of your secrets leaked to the AI`, the rest as before.

Colour (term-style.ts, shared with `mandu demo`) only when stdout is a
terminal, `NO_COLOR` is unset (no-color.org) and `TERM` is not `dumb`;
a non-empty `FORCE_COLOR` other than `0` forces it, as Node reads it.
Red the leaked secrets' headline and numbers, yellow the warnings, dim
the files and footnotes, cyan the commands, bold the headline. Never in
`--json` or `--share`, nor a pipe. The colours wrap the same text, so a
pipe reads the report the terminal shows.

`mandu scan --all` is the long form, every finding's story (§1):

```
$ mandu scan --all
mandu scan: read 812 Claude Code and 16 Codex sessions on this computer (29 Sep to 21 Oct).
Nothing left this computer, and no secret's value is shown below.

2 of your secrets leaked to the AI:

  1. accessToken in ~/.config/some-cli/credential.json
     19 Oct · ~/project/app · Claude Code
       The agent ran:  cat ~/.config/some-cli/credential.json
       The output, with the secret in it, went to the AI: it left this computer in Claude Code's next request to Anthropic.
     With Mandu, the AI would have seen a placeholder ($MDU:…) where the secret is in that output; the command itself would still have run.

  2. STRIPE_KEY in ~/shop/.env
     3 sessions, 1 Oct to 19 Oct, 2 projects (the agent read the file in 2, a command printed it in 1). The newest:
     19 Oct · ~/shop · Claude Code
       The agent read:  ~/shop/.env
       The file's content, with the secret in it, went to the AI: it left this computer in Claude Code's next request to Anthropic.
       A command also sent it on over the network, to api.stripe.com, hooks.vendor.dev (listed below).
     With Mandu, the agent would have read a placeholder ($MDU:…) where the secret is, and the AI would have seen only that.

They are still where they were found: change them where they were issued.

276 more values look like keys and leaked to the AI, but are not in your files now (an old key, someone else's, or a test value; the project and command tell which):

  3. sk-…
     39 sessions, 29 Sep to 19 Oct, 6 projects (a command printed it in 36, the agent read the file in 5). The newest:
     19 Oct · ~/project/app · Claude Code
       The agent ran:  sed -n 1,140p tests/fixtures/keys.ts
       The output, with the key in it, went to the AI: it left this computer in Claude Code's next request to Anthropic.
  …
  6. ghp_…
     1 session, 2 Oct · it was in your message · Codex
       2 Oct · ~/repo · it was in your message to the agent (typed, pasted, or a ! command's output).
  …

With Mandu, a key like these is masked when it is in a file or variable Mandu protects; one it does not hold reaches the AI as before.

12 values named like a secret (DB_PASSWORD=…, a password in a URL):
  279. DB_PASSWORD=…
  …

Secrets the agents sent on (curl, wget, HTTPie, xh, a web fetch; ssh, scp, sftp, rsync; git with a credential in its URL; a python, node, ruby or perl one-liner's HTTP call; an MCP tool's input):

  To a host Mandu cannot tie to the key's own service (worth a look):
    STRIPE_KEY in ~/shop/.env → hooks.vendor.dev
        1 session, 19 Oct · curl · the command used its variable, so the AI saw only the name · Claude Code · it failed or was refused

  To the key's own service:
    STRIPE_KEY in ~/shop/.env → api.stripe.com
        2 sessions, last 19 Oct · curl · the command used its variable, so the AI saw only the name · Claude Code

Riskier sessions:
  371 sessions ran with the agent's permission prompts off: every command ran without asking you (in 1 of them one of your secrets leaked to the AI).
  8 sessions printed your whole environment to the AI (env, printenv, …): every variable in it, secrets too, went into the request.

87 sessions ran while Mandu ran (by time): there the AI may have seen a placeholder where the record on disk shows the value. 54 of the findings above were seen only in such sessions.

To keep your secrets from the AI from now on: mandu claude (or mandu codex).
To share the counts, with no value, path or name: mandu scan --share
To see one finding in full (every way it got there, up to 10 examples each): mandu scan --show <n>, n from 1 to 290
```

Each finding is numbered. Your own secrets each get the whole story (§1);
so do the first three key-like values, and the rest of that tier a row
with up to three example lines (the project and the command are what
tell a test fixture from a real key). A finding seen only in sessions
under Mandu (the exact join, item 6) is not counted as leaked: one
closing line counts those, and `--all` lists them.

```
$ mandu scan --show 3
mandu scan: finding 3 of 290. No secret's value is shown below.

3. sk-…: a key-shaped value, leaked to the AI (in no file now)
   39 sessions, 29 Sep to 19 Oct, 6 projects: ~/project/app, ~/project/app/.claude/worktrees/…, … · Claude Code
   34 without Mandu, 5 while Mandu ran (by time only, so there the AI may have seen a placeholder)

   A command printed it, in 36 sessions; the newest 10:
     19 Oct · ~/project/app · Claude Code
       The agent ran:  sed -n 1,140p tests/fixtures/keys.ts
     18 Oct · ~/project/app · Claude Code · while Mandu ran (by time only)
       The agent ran:  node --test test/unit/egress.test.ts
     …
     Each time, the key left this computer in the agent's next request: Claude Code's to Anthropic.

   The agent read the file, in 5 sessions:
     …
```

`--all` lists every finding (up to three example lines a row), `--show <n>` one
finding in full, `--since 30d` (or a date) reads less, `--json` gives the
raw report (`--json --show <n>` the one finding), `--share` a sentence
with the counts alone. A number names a finding of the scan that prints
it: `--show` scans again, so a session written in between can move the
numbers (the saved last scan, phase 2, keeps them).

## 3. Decisions

1. **A report, not a fix.** The scan reads and reports, like the git-history
   scan (secret-discovery.md §3.2 item 1). It changes no transcript, rotates
   nothing, records no found label and writes no policy. Since phase 2 it
   does write two things of Mandu's own, never the person's: it keeps its
   last report (item 12), and, when a Mandu is running, it names the files
   of "your secrets" to it, which files a proposal for each one no rule
   covers (item 13). A proposal is not policy: only the person's Save makes
   it a rule.

2. **Nothing leaves the machine; no value is printed.** The scan opens no
   network connection: no model call, no key check against its issuer (a
   check would itself send the key), no telemetry. A finding carries what a
   git-history finding carries: a detector kind and its fixed mask (the
   format's public prefix at most, `sk-ant-…`; an assignment's name,
   `DB_PASSWORD=…`), never a character of a value's body, and no length or
   hash. For a value found on disk, the name it has there and its file. A
   value is told from another across sessions by an HMAC under a key made
   for one scan, held in the scanning process's memory only.
   `findSecretValues` (secret-detectors.ts) gives the scanner the values
   with the same rules, masks and order as `detectSecretShapes`, kept apart
   so the history scan's pinned fingerprint does not move; a unit test holds
   the two to the same output.

3. **What counts as "reached the AI".** Only the parts of a record the agent
   puts in its requests (each reader states its rule):
   - Claude Code: a `user` record's `message.content` (the person's text,
     each `tool_result` with the name of the `tool_use` it answers), an
     `assistant` record's text, thinking and `tool_use` input, and three
     attachments (`file`: its path and content; `edited_text_file`:
     `snippet`; `queued_command`: `prompt`). Never `toolUseResult` (Claude
     Code's local copy of a tool's full output), the other attachments
     (prompt snapshots, tool lists, token counts) or the request-debug
     records.
   - Codex: `response_item` payloads (messages, tool calls' input, tool
     outputs with the call's name). Never `event_msg` (the local event log),
     encrypted reasoning, or `compacted` records (their retained context
     repeats messages already sent earlier in the session).

   The rules of the agents phase 2 added were read off each agent's own
   code that builds its requests (OpenCode 1.18.13's
   `MessageV2.toModelMessages`, OpenCode 2.0.26's projection of session
   messages into a request, Goose 1.53.0's provider formats and its
   message metadata, OpenClaw's pi-agent `convertToLlm`), not off docs:
   - OpenCode 1.x (`message` and `part` rows): a user message's text parts
     unless `ignored` (a `synthetic` part, such as an attached file's
     content, as context); an assistant message's text and reasoning, each
     tool part's `state.input`, and its result: a completed call's
     `state.output` (unless `state.time.compacted`: the agent sends a fixed
     line), a failed call's `state.error`, an interrupted call's
     `state.metadata.output`. An assistant message that ended in an error is
     left out, as OpenCode leaves it out. Never `state.metadata` otherwise
     (the tool's local record: a shell's full output), `state.title`, the
     message's own data, step, snapshot, patch or file parts.
   - OpenCode 2.x (`session_message` rows by `seq`): a `user` row's text,
     its skills' text and its text files' content; a `synthetic`, `skill`
     or `system` row's text; a `shell` row's command and output (the
     person's `!` command) unless it ran in the background; a
     `location-switched` row's directory; an `assistant` row's text,
     reasoning, each tool's `state.input` and result (`state.content`'s
     text, a failed call's `state.error.message`); a completed `compaction`
     row's `summary`. Never a row's `metadata`, a tool's `state.metadata` or
     `providerState`, a compaction's `recent` (it repeats earlier messages),
     model or agent switches, media. Its shell output files
     (`shell/<hash>/sh_<id>.out`) are the full output kept locally: what
     the model got is the tool's result in the database, so they are not
     read as sent (a later `read` of one is a tool result like any other).
     A session with 2.x rows is read from them; a 2.x database migrated
     from 1.x keeps the 1.x rows too, which are then not read again.
   - Goose (`sessions.db` `messages`, the older `sessions/<id>.jsonl`):
     messages the agent can see (not `metadata.agentVisible: false`, the
     ones a summary replaced); in each, text, thinking, a tool request's
     `toolCall.value.arguments` and a tool response's result items whose
     `annotations.audience` includes the model; a user message the person
     never sees (`userVisible: false`: the `<turn-context>` of time and
     working directory Goose 1.53.0 adds to each turn) is context, not the
     person's message. Never an item for the
     person only (the shell's formatted copy of its output),
     `structuredContent`, `redactedThinking`, images, the confirmation
     prompts, `actionRequired` or `systemNotification` items, or the
     session's own columns (name, recipe, extension data, model config).
     The request log (`logs/llm_request.*.jsonl`) holds the last requests
     whole: every string of a record's `input` was sent (the system prompt
     and the tool list as context, the messages by role), a later record's
     `data` is the model's answer; never `model_config`, `usage` or an
     `error` record. It is a record of many sessions' requests, so its
     findings count it as one session and the sessions read do not.
   - OpenClaw (`agents/<id>/sessions/<session>.jsonl`, and 9.x's
     `agents/<id>/agent/openclaw-agent.sqlite` `transcript_events`, the same
     entries): a `message` entry by role (a user's text; an assistant's
     text, thinking and each `toolCall`'s `arguments`; a `toolResult`'s text
     content; a `bashExecution`'s command and output unless
     `excludeFromContext`; a `custom` message's content; a branch or
     compaction summary), a `custom_message` entry's content, a
     `compaction` or `branch_summary` entry's summary. Never a tool
     result's `details` (the tool's local record), a message's `details` or
     `display`, a `custom` entry's `data`, model and thinking-level
     changes, labels or session info. The `<session>.trajectory.jsonl`
     beside a session (2026.7 and later, its run trace: each run's compiled
     context, system prompt and tool list among it) is not a session and
     is not read; it still counts as a transcript file, so a known value is
     never taken from it (`isRunTrace`; found on the stores the agent wrote,
     §6).

   Phase 3's agents, which Mandu does not run (§4), the same way, read off
   their own code (Gemini CLI 0.29.7, 0.53.1 and 0.65.0's
   `GeminiChat.sendMessageStream` and `recordCompletedToolCalls`; Copilot
   CLI 0.0.343, 0.0.373 and 1.0.44's `processEventForState`, which 1.0.79
   and 1.0.101 moved into native code, held there by the same strings and
   the event schema they ship):
   - Gemini CLI (`chats/session-*.jsonl` from 0.39, an older whole-file
     `session-*.json`): every line of the file is read, not the view a
     resume rebuilds, as a message rewound or a result masked later was
     still sent before. A `user` message's `content` is the parts sent: its
     text the person's (a `!` command's output among it), the files an
     `@path` attached (after the agent's `--- Content from referenced files
     ---` marker, each with its path) and the agent's `<session_context>`
     turn as context, a `functionResponse` part as the tool's result; a
     `gemini` message's `content` (text, functionCall `args`), its
     `thoughts` and each `toolCalls[].args` the model wrote, each
     `toolCalls[].result` the functionResponse parts sent back; `$set`'s
     `messages` (0.39 to 0.63) and `$patch` updates (0.64 on) the same way.
     Never `displayContent` (the person's raw query), a call's
     `resultDisplay` (the person's copy: an edit's diff holds a whole file
     the model may never have read), `description`, `displayName`, the
     `info` / `warning` / `error` notices, `tokens`, `summary`,
     `memoryScratchpad`, media. Not read: `logs.json` and `shell_history`
     (the person's typed lines, kept for recall), `tool-outputs/` (a long
     output in full, of which only the head and tail went to the model),
     `/chat save` checkpoints and edit checkpoints (they repeat the
     session's history), the activity log.
   - Copilot CLI (`session-state/<id>/events.jsonl` from 0.0.385, the flat
     `session-state/<id>.jsonl` before it): `user.message`'s
     `transformedContent` (the prompt as sent, with its date and reminders)
     or, without one, `content`; an attached file is only named there, its
     content read by a tool; `assistant.message`'s `content`,
     `reasoningText` and each `toolRequests[].arguments`, and
     `assistant.reasoning`'s `content`; `tool.execution_complete`'s
     `result.content` (or `error.message` for a call that failed) unless
     `isUserRequested` (the person's own `!` command, which the agent
     leaves out of the request); `system.message`, `system.notification`
     and `skill.invoked`'s `content` as context;
     `session.compaction_complete`'s `summaryContent`; a
     `session.handoff`'s text `context`. A subagent's events (`agentId`)
     went to its own model and are read the same way. Never
     `result.detailedContent` (the person's copy: a whole diff),
     `result.contents`, `toolTelemetry`, `tool.execution_start` (its
     arguments repeat the request's), `tool.user_requested`, the
     `permission.*`, `hook.*` and `session.info` / `warning` / `error` /
     `shutdown` events, `reasoningOpaque` or `encryptedContent`, a binary
     asset. Not read: `session-store.db` (an index that repeats the turns),
     `checkpoints/*.md` (compaction summaries the events already hold),
     `command-history-state.json` (the person's typed lines), the logs, and
     the oldest `history-session-state/*.json` (before 0.0.343, which
     imported and removed them).

   The same readers give each session's tool calls (item 10, with the
   shell tools of item 11: OpenCode's `bash` and `shell`, Goose's `shell`
   and `developer__shell`, OpenClaw's `exec`, Gemini CLI's
   `run_shell_command`, Copilot CLI's `bash` and `powershell`; the fetches
   OpenCode's `webfetch`, OpenClaw's and Copilot CLI's `web_fetch` (its
   `url`) and Gemini CLI's `web_fetch` (the URLs in its `prompt`)) with how
   each ended: Gemini CLI's `cancelled` (refused when its answer is the
   person's "no", `User denied execution`, or the rest of a batch they
   declined), `error`, its shell's `Exit Code: N`; Copilot CLI's
   `success: false` (refused for `The user rejected this tool call`, a
   rule's or a hook's denial, codes `rejected` / `denied`), its shell's
   `shellExecution.exitCode` or `<exited with exit code N>`; OpenCode's
   `state.status` (an error is refused when it is a permission rejection),
   a shell's non-zero `metadata.exit`; Goose's error result or `isError`,
   its shell's `Command exited with code N`, its decline text; OpenClaw's
   `isError` and its exec approval's refusal. Prompts off: Goose's session
   `goose_mode` of `auto` (its default: no tool asks); an OpenCode session
   whose own stored rules allow every permission on every pattern with no
   `ask` after it (OpenCode keeps its config's defaults out of the session,
   so a session only the config let run without prompts is not counted);
   OpenClaw keeps its approval settings in its config, not the session, so
   none is counted; Gemini CLI records no approval mode (`--yolo`,
   `--approval-mode`) anywhere, so none is counted; Copilot CLI from 1.0.79
   records a change to allow-all (`session.permissions_changed`: 1.0.79's
   `allowAllPermissions`, 1.0.101's `mode: "allow-all"`, the mode
   `--yolo` / `--allow-all` sets) or a request made under it, counted;
   `--allow-all-tools` or `--allow-tool` rules alone are never recorded,
   so not counted. A child session (OpenCode's `parent_id`, Goose's
   `parent_session_id`) counts with its parent, as a Claude Code subagent
   does, and so does a Gemini CLI subagent's chat
   (`chats/<parent id>/<id>.jsonl`). For the story (item 4) each text
   carries its tool call (its command or file shown through
   `redactShown`), the project is the session's directory (OpenCode's
   `directory`, Goose's `working_dir`, OpenClaw's session `cwd`, Gemini
   CLI's project folder's `.project_root` marker, or the path
   `projects.json` maps to it or whose sha256 names an older folder, and a
   subagent's `directories`; Copilot CLI's `session.start` `context.cwd`),
   and the provider is the one the record names (OpenCode's `providerID`,
   Goose's `provider_name`, OpenClaw's assistant `provider`): `anthropic` or
   `openai` by name, any other as `other`, and `other` when the record
   names none; Gemini CLI's `gemini-*` models as `google` (the Gemini API
   or Vertex), another model as `other`; Copilot CLI as `github` (its
   requests go to GitHub Copilot's service, whatever model serves them),
   `other` for a session that names a provider of its own (`providerId`).
   Neither keeps the provider's response id (Gemini CLI keeps none, Copilot
   CLI the request's ids), and Mandu runs neither, so their sessions are
   all without Mandu (item 6).

4. **How it got there**, from the record around the hit: the agent read the
   file (Read, Grep, Glob), a command printed it (a shell tool's result), a
   tool returned it, it was in the person's message, the AI wrote it out
   (its text, thinking or a tool call's input), or the agent attached it.

   **And what the agent did, as examples** (2026-10-21, the maintainer's
   "a command printed it: can you show the command?"). Each finding keeps
   `examples` (at most 3, newest first, one per session; when none of
   those went without Mandu and an older text did, that one takes the
   last place, even from a session already shown: a resumed session's
   part outside Mandu, item 6) and `examplesByHow` (at most 10 a way, the detail of
   `--show`; on the first 500 findings), each a `ScanExample`: `at`,
   `agent`, `how`, `command` (for a command's output, the shell command of
   the call whose result held the value, matched by the call's id as
   transcript-acts.ts matches them, through `shellCommandsOf`; for the AI
   writing it out, the command it wrote it into), `file` (the file read,
   attached or written, home as `~`), `url` (for a web fetch, `WebFetch`,
   `webfetch` or `web_fetch`: the URL whose page held the value, or the
   one the AI wrote it into, `fetchedUrlOf`; redacted like a command, so a
   query's secrets and a URL's password are masked: "The agent fetched:
   https://…?key=…"), `tool`, `project` (the session's working directory),
   `mandu` (the `ManduStatus` of the request that carried it, else the
   session's final one, item 6) and `provider`. A
   finding also carries `projectCount` (distinct projects; `projects`
   lists five) and `sentToHosts` (the hosts of item 11 it was sent to).

   **The provider** (`transcript-providers.ts`, 2026-10-21) is a kind
   only, `anthropic`, `openai` or `other`, and the report says "the model
   provider" for `other`. What the session's record names wins where it
   names a provider (Codex's `model_provider`, OpenCode's `providerID`,
   Goose's `provider_name`, OpenClaw's `provider`; a Claude Code model not
   named `claude-*` is `other`). Else the agent's own settings pick: Codex's
   `config.toml` (under `CODEX_HOME`) `model_provider`, the active
   `profile`'s if one is set, is `other` unless its
   `model_providers.<id>.base_url` is OpenAI's. Else the agent's own
   provider (Anthropic for Claude Code, OpenAI for Codex). And the settings
   can send the agent's own provider's requests elsewhere, which makes a
   record naming it `other` too: Claude Code's `CLAUDE_CODE_USE_BEDROCK`,
   `_VERTEX` or `_FOUNDRY` on, or an `ANTHROPIC_BASE_URL` off
   `anthropic.com`, in the `env` block of its `settings.json` (under
   `CLAUDE_CONFIG_DIR`), of the managed settings
   (`/etc/claude-code/managed-settings.json`, macOS's
   `/Library/Application Support/ClaudeCode/managed-settings.json`), of
   the session's project `.claude/settings.json` or
   `.claude/settings.local.json`, or in the environment (a `claude-*` model
   names a model, not where it was served); Codex's `OPENAI_BASE_URL`, its
   `config.toml`'s `openai_base_url` (or a `model_providers.openai.base_url`)
   off `openai.com`.

   **A Codex project's own config** (2026-10-22). Codex reads a
   `.codex/config.toml` in each directory from the project root down to
   its working directory, the closer one winning; the root is the nearest
   directory up holding one of the user's `project_root_markers` (`.git`
   by default; none found, the working directory alone), and a layer is
   read only when the user's `config.toml` trusts it
   (`projects."<dir>".trust_level = "trusted"` for that directory, else
   for the root; a directory's own `untrusted` wins over a trusted root, and
   a trusted folder above the root does not reach in). This was probed on
   Codex 0.162 with `codex doctor` over a throwaway `CODEX_HOME`. The same
   probe showed that Codex 0.162 ignores the provider keys in a project's
   layer (`model_provider`, `model_providers`, `profile`, `profiles`,
   `openai_base_url`: "Ignored unsupported project-local config keys …
   set them in your user-level config.toml"). An older Codex may have read
   them, and a past session may have run on one, so the scan reads a
   session's trusted layers the same way (the user's `config.toml` under
   them) and counts only what turns the answer away from OpenAI, never
   back to it: another provider is a pick (it decides a record that names
   none; a record names the provider its session used), and an
   `openai_base_url` off `openai.com` sends the built-in provider elsewhere
   (a record naming `openai` would not show it). A project's layer that
   names the user's own off-OpenAI provider, or OpenAI, changes nothing.
   Without a trusted project in the user's `config.toml` no layer is looked
   for.

   The op reads these
   files read-only (a regular file of at most 1 MiB, each project folder
   once per agent); the managed settings and the arbiter's own variables only for
   its own HOME, as item 7's directory variables. Nothing read leaves the
   module but the kind: no URL, host, provider id or setting is in the
   answer. These are today's settings, not the session's, so they are read
   the cautious way: a flag that might be on is on, a URL that does not
   parse is elsewhere, and when unsure the answer is `other`. A session
   that ran on OpenAI before the config moved to a gateway still says
   OpenAI, as its record names it.

   **A command can hold the very value, or other secrets**, so before any
   of it leaves the arbiter it goes through `redactShown`
   (`arbiter/policy/transcript-redact.ts`), and so do the file and the
   project: (1) every value the scan knows, longest first: the known
   values (the credentials of item 5, and the other values of the same
   files that read as random) as `‹NAME›`; (2) every `findSecretValues`
   hit, as its mask (`sk_live_…`) or `…`; (3) by the command's own words,
   whatever the value looks like: a URL's password, a secret-named
   assignment, option, JSON key or header (`FOO_TOKEN=…`, `--password …`,
   `"api_key": "…"`, `X-Api-Key: …`), an `Authorization` scheme's
   credential (`Bearer …`), curl's `-u user:…`; a variable (`$NAME`) is
   kept, it holds no value; (4) a fail-closed guard: a token of 20 or
   more characters that reads as random (`looksLikeSecretValue`, not a
   name of words and numbers) or a base64 run becomes `…`. Then
   whitespace is collapsed, only the first line is kept (a
   here-document's body, a script's later lines and a quoted value's
   continuation are dropped, marked `…`) and the text is cut at 240
   characters. A last check runs the detector and the known values over
   the result; should anything remain, only the first word is shown. What
   it cannot cover: a value with no format, in no file now, not named like
   a secret and too short or plain for the guard (`mysql -phunter2`), and
   a value written in pieces or encoded; those are no findings either, as
   the scan cannot see them as secrets. The guard also masks what only
   looks random (a git hash, a folder named by a random id). `--share`
   stays counts only: no example, command or path.

5. **Two tiers, by confidence.**
   - *Your secrets*: values found on this computer now, matched exactly.
     They come from the arbiter's own files (`arbiter/policy/transcript-known.ts`),
     split into values by the extractor, and from the secret-named
     variables of the arbiter's environment (`envSecretSpan`). The files
     are the discovery walk's of the home, run to `SCAN_MAX_FILES` (4096,
     not a launch's 256: the scan binds nothing), and, read by their own
     places whatever the walk's caps did: every agent's login files
     (`agentLoginPaths`, all agents: a launch leaves them raw), every
     credential store the catalog names under the home (`SECRET_PREFIXES`:
     `~/.config/gh/hosts.yml`, `~/.config/glab-cli/config.yml`, `~/.netrc`,
     …; a folder walked to depth 3, at most 128 files of it, shallowest
     first, never an agent's own store, each file still secret by the path
     rules and the labels in force, so a person's `public` label wins), and
     the person's systemd user units (`~/.config/systemd/user`, their
     drop-ins and the `EnvironmentFile=` each names under the home): an
     `Environment=` assignment read by the environment's rules
     (`Environment=HTTPS_PROXY=http://user:pass@127.0.0.1:3128` gives
     `HTTPS_PROXY.password`), and a URL's password or a vendor key anywhere
     else in the unit. A proxy's password is a credential even on
     `127.0.0.1`: the proxy holds the way out (and often the upstream's
     own login), the agent can print the unit (`systemctl --user cat`),
     and the report's advice is the same, change it. These are the scan's
     only: no unit file becomes a twin or a found label. Discovery masks a
     whole `.env` to fail closed, so a file's values include version pins
     and checksums; a value counts only when its own name reads as a
     credential (`token`, `secret`, `password`, `api_key`, `auth`, …) or
     the value has a vendor's format, and never when it is a stand-in by
     the detector's own test (`knownIsCredential`, `isStandIn`). The first
     run (§5) is why: without the rule, 37 of 39 such findings were pins
     and digests of one CI file. A hand check on 2026-10-22 found three
     ways a live key was reported only as *looks like a key*, each fixed:
     the walk stopped at its 256 files before `~/.config` (a home whose
     folders sorting first hold many catalog matches), the walk's 200
     skip records were filled before the agents' logins (which come last)
     were named, and the stand-in test was the word test alone (a random
     body holding `xxxx` or `dummy` by chance), which the detector had
     already stopped using. A second look the same day, on the same
     machine, found two more, also fixed: the file budget
     (`KNOWN_MAX_TOTAL_BYTES`) counted the walk's own files, so a large
     walk could use it up before a store read by its place (the walk's
     files are bounded by the walk's caps and no longer count); and a
     newer GitLab token (`glpat-<body>.01.<id>`) was cut at its first dot
     by the detector, so the same text reported the person's token as
     known and a piece of it as a second key (the detector now takes the
     whole token, and a shape that found only a piece of a known value in
     the same text is not reported again). What it does not count as
     known, rightly: a piece of a key cut short in the output (a 31 of
     40 character piece of a GitHub CLI token, the rest only in the
     record's local copy) is still found by its shape, as what reached
     the AI. A known value counts in every session whose
     sent text holds it, whichever way it went (item 4's `how`), and each
     session's mark (item 6) says where the AI saw only a placeholder.
   - *Looks like a key*: `detectSecretShapes`' vendor formats in no file
     now. Values only named like a secret (`DB_PASSWORD=…`) and URL
     passwords are counted and listed with `--all`: they are where a
     project's own test values show up.

6. **Sessions under Mandu are joined by response id (OpenCode: by its
   session id), else marked by time.** Under Mandu the record on disk is the agent's local copy, not
   the request: the model proxy masks a tool result on its way out, so a
   raw value can be on disk and never have reached the model. The agents'
   transcripts keep the provider's id for each response: Claude Code's
   assistant records `message.id` (`msg_…`; also `requestId`, the HTTP
   request's id, not used), Codex 0.159 and later a `token_usage_record`
   per response with `response_id` (`resp_…`; its `response_item` ids are
   item ids, some made by the client). The other agents' stores, read off
   each agent's own code (OpenClaw 2026.7 and 9.9, OpenCode 1.18.13 and
   2.0.26, Goose 1.53.0):
   - OpenClaw: an assistant message's `responseId`, in its JSONL and in
     9.x's `transcript_events`, set by its transports from
     `message_start`'s `message.id` (`msg_…`), the first Chat chunk's `id`
     (`responseId ||= chunk.id`, `chatcmpl-…`) or `response.created`'s
     `response.id` (`resp_…`);
   - OpenCode 2.x: an assistant row's `providerState`, the step's provider
     metadata, holds `responseId` on the Responses API (`resp_…`) and
     Gemini; none from Chat Completions or Anthropic;
   - OpenCode 1.x keeps none (its step-finish part holds the tokens and
     cost only; the AI SDK's response id is never stored);
   - Goose: an assistant message's id (`messages.message_id`, an older
     JSONL line's `id`, the request log's `data.id`) is the provider's
     (`msg_…` from `message_start`, the Chat chunks' `chatcmpl-…`, the
     Responses API's `resp_…`), except where the provider sent none and
     Goose made one up (`msg_<uuid>`, `msg_<session>_<uuid>`, its
     migration's `msg_<session>_<n>`), which is not read. Goose's request
     log is one record of many sessions (§4), so an id there marks the
     findings of the log as a whole.

   **OpenCode's session id** (2026-10-22). Where OpenCode keeps no
   response id it is still joined exactly, by the one id its requests and
   its store share. Probed in the CI guest (OpenCode 1.18.13 and 2.0.23,
   each on the Anthropic wire, an `@ai-sdk/openai-compatible` Chat
   Completions provider and an `@ai-sdk/openai` Responses provider, against
   a scripted local endpoint that logged every request's headers and body;
   every id-shaped token of each request was then looked for in the
   `opencode.db` the run left), and confirmed in each binary's bundled
   code:
   - 1.18.13 sends, with every model request to any provider but its own
     `opencode*` ones, `X-Session-Id` and `x-session-affinity` = the
     session's id (`ses_…`, `Identifier.ascending("session")`; a subagent's
     request also `x-parent-session-id`); to its own `opencode*` providers
     `x-opencode-session` (the same id), `x-opencode-project`,
     `x-opencode-client` and `x-opencode-request` (the user message's id,
     the only per-request id, not sent to any other provider). The
     Responses wire's body also carries `prompt_cache_key` = the session's
     id. No body field on the Anthropic or Chat wire carries an id (no
     `metadata.user_id`, no `user`, no `prompt_cache_key`);
   - 2.0.23 sends, with every request on all three wires,
     `x-opencode-session-id` = the session's own id, and
     `x-opencode-session`, `x-session-affinity` and `X-Session-Id` (the
     same id in the probe; its code derives them from the session, so a
     subagent's may name its root), `x-opencode-project` (the project's
     hash) and `x-opencode-client`; also `traceparent` / `b3`, a trace id
     it never stores;
   - both keep the session's id as the session's row id (1.x `session.id`,
     2.x `session_v2.id`) and on every message row (`session_id`); no
     message or part id, nothing per request, reaches a request on any of
     the probed providers.

   So the id is per session, not per request, and the join takes the
   request's time with it (below). It is opaque: a time-ordered id
   OpenCode made, already sent to the provider with every request, never
   a credential.

   The model proxies record the same
   id on the exchange's existing `tllm_call` event, as `model.responseId`:
   the anthropic-proxy from the stream's `message_start` (`message.id`) or
   a JSON body's `id`, the openai-proxy's passive sniffer from the first
   `response.*` event's `response.id` or a JSON body's `id`. On the Chat
   Completions wires (the anthropic-proxy's routed `openai`-family
   providers, which OpenClaw, OpenCode and Goose use, and the openai-proxy's
   Chat route) and the anthropic-proxy's routed Responses wire, the id is
   read off what the agent is sent, after the gates (`response-id.ts`, one
   module in both proxies): the first chunk's `id` that has one, the first
   `response.*` event's `response.id`, or a buffered body's `id`. The gate
   holds a call's fragments back and releases them as one chunk, so the
   first chunk the agent gets need not be the provider's first; reading
   after the gate records the id the agent kept. No new event
   and nothing else from the response: about 45 bytes per model call, one
   per response the agent got, side calls (titles, quota probes) included.
   The id is read off the bytes as relayed and changes nothing that is
   forwarded; a failed emit loses the id and nothing else, like any event.
   Only a short run of id characters is kept (`[A-Za-z0-9_-]{8,128}`).
   The anthropic-proxy, which every OpenCode wire goes through (the
   Messages wire and the routed `openai`-family providers), also records
   the request's OpenCode session id as `model.agentSessionId`
   (`agentSessionIdOf`, events.ts): the first present of
   `x-opencode-session-id` (2.x, the session's own id), `X-Session-Id`
   (1.x) and `x-opencode-session`, kept only in OpenCode's shape
   (`ses_[A-Za-z0-9]{8,120}`), so no other value a header holds can reach
   the event; the headers go upstream unchanged. The openai-proxy, Codex's
   and Kimi Code's, sees no OpenCode request and records none. About 45
   bytes more per OpenCode call; observability only, like the response id.
   `manduWindowsFrom` reads each Mandu session's agent and time
   (`launch_posture`'s `target` and `ts`, `session_exit`) and its recorded
   ids, response ids and agent session ids (a file over 64 MiB, or past
   1 GiB of event files in all, gives none). Each transcript session is
   then one of three
   (`ManduStatus`, `TranscriptScanner.sessionMandu`):
   - `under`: one of its ids (an OpenCode session: its own id) is in
     Mandu's records for that agent: exact, whatever the clocks say;
   - `without`: no Mandu session of the agent overlaps it, or it keeps ids
     and every overlapping Mandu session recorded ids of that kind (an
     OpenCode session: agent session ids), none of them its own (a
     parallel session outside Mandu);
   - `by-time`: it overlaps a Mandu session and no id settles it (the
     transcript keeps none, or the Mandu session is an older Mandu's whose
     events carry none). This is the old mark, kept as a fallback.

   A subagent's file joins its parent's session; the strongest mark wins.
   The answer counts `sessionsUnderMandu` and `sessionsByTime` in all;
   `duringMandu` stays their sum for older readers; the rest ran without
   Mandu.

   **Per request, not per session** (2026-10-22). A session resumed under
   Mandu after a start outside it holds both: what it sent before the
   resume reached the model raw. So a finding (and a send) is joined per
   text: each text a reader yields carries the request it went in
   (`SentText.turn`, `Turns` in transcript-readers.ts), and the request
   takes the id of the response that answered it: what the person, a tool
   or an attachment put in a request is answered by the next response the
   record keeps; what the model wrote goes with its own response (the value
   was in the model's context there). Per agent: Claude Code's next
   assistant `message.id` (another record of the same message, Claude Code
   writes one per content block, answers nothing new, so a tool's result
   written between two of them waits for the next response; a
   `<synthetic>` message is none); Codex's next `token_usage_record`
   `response_id` (Codex writes a response's output items before it, so
   they take it too); OpenClaw's next assistant `responseId`; OpenCode 2's
   next assistant row's `providerState.responseId` (a step's tool results
   went in the next step's request); OpenCode 1.x's next assistant message
   (one step, one request; no id, so it closes the request without one);
   Goose's next assistant message id (one
   Goose made up answers without an id); Goose's request log, one request
   and its answer per file, the answer's `data.id` (read off the files
   Goose 1.53.0 wrote, §6). A tool call takes its own
   response's id (`ToolCall.responseId`, transcript-acts.ts), for the sends.
   A text is then (`TranscriptScanner.requestMark`):
   - `under` when its request's response id is in Mandu's records, unless
     the text is older than the Mandu session that recorded it (typed
     outside Mandu, then answered only after the resume: it went out raw
     first);
   - `under` when its request carried the agent's session id (OpenCode's,
     `Turn.sessionId`, which the OpenCode readers give every request of
     the session) and a Mandu session that recorded that id ran at the
     text's time: the id names the session, not the request, so the time
     tells a resumed session's parts apart, before the resume and after
     Mandu's session ended both going out raw. A call (a send) takes the
     session's id with its own time;
   - else marked at its own time: `without` where every Mandu session it
     overlaps recorded ids of the kind the record keeps (or none
     overlaps), `by-time` beside an older Mandu's session or, for a
     request no response answered (the session's last), where it overlaps
     a Mandu session;
   - a text of no known request, or of a record that keeps no ids
     (Gemini CLI, Copilot CLI), takes
     its session's mark as before.

   A finding counts as under Mandu in a session only when every text that
   carried it there was, by time when the weakest of them is by time, and
   else without: `sessionsUnderMandu`, `sessionsByTime` and `duringMandu`
   per finding and per send count those, so they never exceed the
   finding's `sessions`; the answer's own counts stay per session (a
   resumed session counts under Mandu there). Each example's `mandu` is
   its own text's mark, so a resumed session can show its newer example
   under Mandu and, as the one without Mandu, an older one of its part
   outside it. Joined by id: Claude Code, Codex, OpenClaw, Goose, and
   OpenCode 2 on the Responses API or Gemini; by OpenCode's session id
   and the time: OpenCode 1.x, and OpenCode 2 on Chat Completions or
   Anthropic; by time only: any session whose Mandu session predates the
   recorded ids (the session ids: 2026-10-22).

7. **Where it runs.** Transcript contents are secret bytes, so the scan runs
   in an arbiter, as the read-only data-plane op `scanAgentTranscripts
   {home, eventsDir?, since?}`. `mandu scan` always starts a throwaway
   arbiter for it (doctor-secrets.ts `throwawayArbiter`), so a scan of
   gigabytes never holds up a live session's arbiter, and it works with no
   Mandu running, macOS and WSL2 included. The op never takes values to
   look for from its caller: a caller's value would make it an oracle for
   "was this ever sent". Its answer is the same class of metadata the
   git-history scan returns on the data plane.

8. **Bounded, and honest about it.** Files newest first; at most 5 minutes
   and 16 GiB (`MANDU_TRANSCRIPT_SCAN_TIMEOUT_S`,
   `MANDU_TRANSCRIPT_SCAN_MAX_MB`), files over 512 MiB counted, not read.
   What a cap left unread is counted and printed. No cache yet: the first
   run read 3.4 GB in 53 s (§5), so a cache waits until a measured need.

9. **`--share` is the only output meant to leave the machine, and the
   person sends it.** Counts only: no path, mask, name or project. There is
   no upload and no opt-in telemetry.

10. **The riskier sessions**, counted, not listed (`transcript-acts.ts`).
    Each reader also gives the session's tool calls with how each ended
    (failed, refused at the prompt, stopped by Mandu, from the result's
    `is_error`, the refusal text, an exit code in Codex's output forms, or
    Mandu's `mandu_fail_closed` answer) and whether its prompts were off:
    Claude Code's `permissionMode: "bypassPermissions"` on any record, a
    Codex `turn_context` with `approval_policy: "never"` and a
    `danger-full-access` sandbox. Of the prompts-off sessions, those in
    which one of your secrets reached the AI are counted again. An
    environment dump is a shell call that ran (not failed or refused) with
    a command that prints every variable (`env` and `printenv` with flags
    only, `export` / `export -p`, `set` alone, `declare -x`, `cat` of a
    process's `environ`), not narrowed by a filter (`grep`, `awk`, `wc`, …)
    whose pattern names no secret word: `env | grep PATH` is a lookup,
    `env | grep -i token` is not. The command is split into pipelines the
    way the shell splits it (quotes, `$(…)` and a here-document's body kept
    whole), so a script that a here-document writes is not read as run.
    Codex 0.160's code-mode `exec` tool is read through the `cmd:` strings
    of its `tools.exec_command` calls.

11. **What commands sent over HTTP**, and where (`httpRequestsOf`,
    `sentTo`). The narrow, checkable case only: a pipeline whose program
    is an HTTP client (`curl`, `wget`, HTTPie, `xh`) and that names an
    `http(s)://` URL, and a web fetch's URL (`WebFetch`). The secrets in
    it are the scan's own: a known value by value, a known value through
    a variable the command expands (`$STRIPE_KEY`, matched only to a
    variable-style upper-case name, never a config key's `token`), and a
    vendor-shaped value, and a variable named like a secret
    (`envSecretNameMatches`) whose value is in no file the scan read,
    listed by its name (`$STRIPE_SECRET_KEY`), its service hinted by the
    name (`STRIPE_*` to `*.stripe.com`). A value printed by an earlier command, or a
    here-document's body, is not read as sent: only the client's pipeline
    counts, with `\`-continued lines joined. Hosts of this computer, its
    private network and names kept for tests (`localhost`, `10.…`, a name
    with no dot, `.local`, `.test`, `example.com`) are left out. Each host
    is then one of two: **the key's own service**, when the key's format
    names it (a Stripe key to `*.stripe.com`, a GitHub token to
    `*.github.com` or a `github.` host) or the file and key that hold it
    name the host (a CLI's `hosts.<host>.token`); or **a host Mandu cannot
    tie to the key**. The second is not a verdict: a key with no format
    sent to its own company's API lands there too; the report says "worth
    a look", lists those first, and says for each whether the command held
    the value (the AI wrote it out) or a variable (the AI saw only the
    name), and whether it ran, failed, was refused or was stopped by
    Mandu. What a program sent by itself (a CLI's own login, a script's
    config) is not in the record, so it is not in the report. No list of
    "bad" hosts is kept.

    Each send also names the URLs at its host (`urls`, 2026-10-22; the
    first five distinct), so a row tells which endpoint, not only which
    company: `transcript-redact.ts` `shownUrl` keeps the scheme, host and
    path, masks the URL's credentials (`https://…@host`, a token as the
    user too), every query value whatever its name (`?page=…&token=…`; a
    variable such as `?k=$STRIPE_KEY` is kept, as it holds no value) and a
    fragment (`#…`), then runs `redactShown` over it (a known value in the
    path by its mask, a detector's hit by its own, a random-looking part as
    `…`) and cuts it at 160 characters. Stricter than a web fetch's URL in
    an example, whose query keeps a value no secret's name marks: a send's
    URL is where a secret went, and its query is where a value most often
    rides. The report lists them under the host, `--show <n>` lists the
    finding's sends with theirs, and the kept scan and the Scan page carry
    them (item 12).

    **Beyond HTTP** (2026-10-22, the maintainer: "keep doing the leftover
    jobs for mandu scan"; `sendsOf`, transcript-acts.ts). Four more ways a
    call sends a value on, each read from the record alone and only where
    it is sound; each send carries its `channel` (`http`, `ssh`, `git`,
    `script`, `mcp`; absent from an older arbiter's answer and kept scan,
    which were all `http`) beside `via` (the program), so the shape only
    grew. A send is one (secret, channel, destination); the secrets in it
    are found as in the HTTP rule (a known value by value; a known or
    secret-named variable; a vendor-shaped value), with one difference:
    a shell command's variables are those this computer's shell expands
    (`parsePipeline`: not in single quotes, not in a here-document whose
    delimiter is quoted), so `ssh prod 'echo $HOME'` sends no `$HOME` of
    this computer's.
    - **ssh** (`ssh`, `scp`, `sftp`, `rsync`): the host is ssh's
      destination (its first word past the options and their values,
      `user@` and a port dropped) or the remote `host:path` / `host::module`
      / `scp://` / `rsync://` words of `scp` and `rsync`. What went: the
      words of the pipeline up to and including the program and every
      here-document among them (`cat <<EOF | ssh prod`, `ssh prod 'bash
      -s' <<'EOF'`, `printf %s $KEY | ssh …`); a command after it gets the
      remote's output, not this computer's input, and is left out. A name
      with no dot other than `localhost` is kept (an `ssh` destination with
      no dot is usually a `Host` of `~/.ssh/config`, a remote machine);
      this computer, its private network and the test names are left out
      as for HTTP. Not covered: a file copied whole (`scp ~/shop/.env
      prod:`) sends the file's secrets, but the scan would have to tie the
      path to the known file at the session's directory; left for later.
    - **git** (`push`, `clone`, `fetch`, `pull`, `ls-remote`, and `remote
      add` / `set-url`, which keep the URL for every later fetch and push):
      the user part of each `http(s)://` URL (`https://x-access-token:…@`,
      a token as the user) goes to that URL's host; an `http.extraheader`
      given with `-c` (`AUTHORIZATION: bearer …`, `basic <base64>`, which is
      decoded to look in and never shown) goes to every `http(s)` URL the
      command names, or the one its key names
      (`http.https://host/.extraheader`). A URL's password is reported here
      (the `url-password` shape), as the credential is exactly what went;
      the HTTP rule leaves it out. Not covered: a credential with no URL
      in the command (`git -c http.extraheader=… push origin`: the
      remote's URL is in `.git/config`, not the record), a credential
      helper, `GIT_ASKPASS`, ssh keys.
    - **an inline script** (`python3 -c`, `node -e` / `-p`, `bun -e`,
      `deno eval`, `ruby -e`, `perl -e`, or a here-document fed to an
      interpreter that names no script file: `python3 - <<EOF`, `cat <<EOF
      | node`): only when the script calls an HTTP library (Python's
      `requests`, `urllib`, `http.client`, `httpx`, `aiohttp`; JavaScript's
      `fetch`, `axios`, `http(s).request`, `got`, `undici`; Ruby's
      `Net::HTTP`, `URI.open`, `HTTParty`, `Faraday`; Perl's `LWP`,
      `HTTP::Tiny`) AND names a literal `http(s)://` URL; that URL's host
      is where it went. What went is what the script holds: a value
      written into it, a `$NAME` the shell expands into it, a variable it
      reads by name (`os.environ['X']`, `os.getenv`, `process.env.X`,
      `ENV['X']`, `$ENV{X}`, `Deno.env.get`). The record cannot follow a
      value through the script's own variables, so a script that holds a
      secret and calls a literal URL is counted as sending it there: the
      maintainer's line, "only where the URL and the secret are both
      literally present (no guessing)". Not covered: a script run from a
      file (`python3 send.py`: its text is not in the record), one written
      by a here-document and run later (tying the two would be a guess), a
      URL the script builds.
    - **an MCP tool's input**: a call whose tool is `mcp__<server>__<tool>`
      (Claude Code's name for an MCP tool, and Codex's) sent every string
      of its input to that server; the destination is the tool, shown as
      "an MCP server's tool `<name>`", never as a host (it is not in
      `sentToHosts`, and the story's "over the network" never names it).
      It is always one Mandu cannot tie to the key: the server's name is
      the person's choice, and the server may run on this computer or
      elsewhere and send it anywhere; the report lists these apart, worth
      a look. No variable is read there (an MCP input is not a shell's).
      Not covered: OpenCode, Goose, Gemini CLI and Copilot CLI name an MCP
      tool like their own tools (`<server>_<tool>`, `<extension>__<tool>`),
      so the record cannot tell one apart without guessing, and OpenClaw
      has no MCP client.

12. **The last report is kept** (phase 2, 2026-10-21; `scan-kept.ts`).
    Where: a file in Mandu's state folder, `~/.mandu/state/last-scan.json`
    (the path table's `last-scan`, 0600 in the 0700 `state/`, which the
    agent can neither read nor write, on-disk-layout.md §4), written whole
    (a temporary file renamed over the last) by the command after the
    throwaway arbiter answered. Not the running arbiter's database: the
    scan runs with no Mandu running (item 7), on a first `npx` before any
    install, and a report that waited for a stack would be lost then; the
    dashboard and doctor run as the person and read the file directly.
    What: the op's answer, which carries no value, length or hash (item
    2), copied field by field (`keepScan`; the dashboard reads it again
    the same way, `parseLastScan`): when it ran, `--since`, the range, the
    sessions per agent, each finding (kind, mask, name, file, counts,
    agents, dates, how, projects, and the optional fields other phase-2
    parts add: `sessionsUnderMandu` / `sessionsByTime`, `projectCount`,
    `sentToHosts`, the `examples` (the scan gives 3) and `examplesByHow`
    (at most 10 per way, kept for the first 500 findings), each example a
    time, an agent, how, a command with every secret in it already
    replaced by its mask (`transcript-redact.ts`), a file read, a web
    fetch's URL masked the same way, a tool, a project, the provider), the
    totals' Mandu split, the sends with their
    hosts and masked URLs (five, each cut to 160 characters), the riskier
    sessions' counts, the caps, and what the running Mandu answered of
    item 13. A field the answer carries beyond these is not written, a
    string is cut and its control characters dropped; at most 2000
    findings and 500 sends (the rest counted). Every run that answered
    with the axis ON replaces it, `--json` and `--share` too.
    Its readers:
    - **Home** (dashboard.md §4.25ai): a card under the hero's counts,
      led by "N of your secrets left this computer in your agents'
      requests" (your secrets with a session not known to be under Mandu;
      a session only marked by time counts, item 6 being a mark), the way
      to stop it (`mandu claude`), the first three by name and file, the
      sends worth a look, a rule waiting, and `mandu scan`; with no
      report, how to run one;
    - **the Scan page** (`/scan`, from that card and History): the whole
      report, each finding as the story of how it left (where it lives,
      what the agent ran or read with when, project and agent, that it
      went to the AI in the agent's request to its provider, what came
      next, what Mandu would have done instead), the Mandu status a
      footnote, the examples behind a fold;
    - **`mandu doctor`**: one line under "Your secrets", `Last scan (19
      Oct): 2 of your secrets reached the AI in sessions without Mandu (mandu scan to
      check again)`, or a hint to run one.
    A scan that could not run keeps the last report as it was.

    **The report says where to see it** (2026-10-22, the maintainer:
    "when running mandu scan, it should show the dashboard link"). The
    terminal report and `--show <n>` end with one line, once the report
    was kept (never `--json` or `--share`, whose output is the answer or a
    text to post): with a dashboard of this user running (its registry
    entry, `live-dashboards.ts`), `This report is in your dashboard too:
    http://127.0.0.1:40123/scan`, its Scan page under its own base path,
    with ` (sign in with its password)` (` (sign in with your Mandu
    dashboard account)` for the dashboard account, dashboard.md §6.z,
    since 2026-10-22) when the dashboard asks for its
    password before any page (its registry entry's `signInMode`,
    `password` or `basic-auth`: the bare URL answered "Unauthorized" to
    the maintainer on a stack behind `DASHBOARD_BASIC_AUTH`, 2026-10-22;
    a one-time link does not get past a Basic-auth challenge, so none is
    offered);
    with none, `This report is kept for your dashboard: run mandu
    dashboard and open Scan.`, spelled `npx @mandusec/mandu dashboard` when
    the scan itself ran through npx (npm exec's `npm_command=exec` /
    `npm_lifecycle_event=npx`, for the `mandu` bin it ran:
    `scan-command.ts` `ranThroughNpx`). `--show` links the page, not the
    finding: the page has no address per finding. The scan does not start
    a dashboard unless asked (`--open`, below): it is a one-shot command,
    and nothing else one-shot starts a server; it prints the command
    instead.

    **`mandu scan --open` opens the Scan page** (2026-10-22, the
    maintainer). After the report (the compact one, `--all` or `--show
    <n>`; refused with `--json` and `--share`, exit 2: those are outputs
    for a program and for pasting) and the throwaway arbiter's stop, the
    command finds this user's live dashboard (registered, pid alive, port
    answering), else starts one exactly as `mandu dashboard` does: the
    same function (`subcommands.ts` `ensureDashboard`, which `runDashboard`
    prints from and `dashboardForScan` hands the scan through the
    dispatcher, so `scan-command.ts` imports nothing of `subcommands.ts`),
    a free port, resident (`MANDU_OWNER_PID=none`), `DASHBOARD_AUTOSTART=0`
    with no arbiter; for one it started, its registry entry once it
    registers, which says whether it asks for a sign-in first. Then the
    page's plain URL goes to the default browser (`browser-open.ts`):
    `BROWSER` first (its first `:`-separated command, `%s` replaced by the
    URL or the URL appended), else `open` on macOS (not over SSH: it would
    show on the Mac's own screen), under WSL `wslview` when on the PATH
    else `cmd.exe /c start "" <url>` (cmd's metacharacters `^`-escaped; a
    URL with a space, quote, `%` or `!` is not handed to cmd), else
    `xdg-open` with `DISPLAY` or `WAYLAND_DISPLAY`. Started detached, its
    output ignored, the command waits for the start only. One line says
    what happened: `Opened the dashboard's Scan page: <url>` or `Started
    the dashboard and opened its Scan page: <url>`, with the Dashboard
    line's ` (sign in …)` note. No browser here (no display, or a Mac over
    SSH): nothing is tried; the URL (`The dashboard's Scan page: <url>`),
    `No browser here: open this URL on your computer`, and over SSH
    (`SSH_CONNECTION`) with a loopback dashboard `Over SSH, forward its
    port first: ssh -L <port>:127.0.0.1:<port> <this machine>` (no real
    host is named). A browser that fails to start: the URL line, and the
    reason on stderr. A dashboard that would not start: its reason, and
    nothing opened. None of it changes the exit code: the report is out.
    **No credential reaches the browser's argv** (which `ps` shows every
    user): the plain Scan URL only, never a one-time sign-in link minted
    for it; a dashboard that asks for a sign-in shows its own page there.
    Tests: `launcher/test/unit/browser-open.test.ts` (the decision per
    platform and environment, the real detached spawn), the `--open`
    cases of `launcher/test/unit/scan-command.test.ts` and
    `subcommands.test.ts` (`dashboardForScan`), and the stack test
    `tests/stack/scan-open.test.ts` (the real launcher with `BROWSER` a
    recorder: a dashboard started and registered, the recorder given
    exactly the Scan URL and nothing secret, a second `--open` reusing
    it).

    **`mandu dashboard` opens where Mandu never ran.** Most scan users ran
    only `npx @mandusec/mandu scan`: no arbiter, no session. Until
    2026-10-22 `mandu dashboard` refused there ("arbiter socket … is absent
    — start a session first"), so the line above pointed at a command that
    failed. Now, with no arbiter at the rendezvous and none pinned, it
    starts the dashboard anyway with `DASHBOARD_AUTOSTART=0` (opening a page
    is not starting protection), pins no socket (the dashboard dials the
    `current` rendezvous itself and joins the arbiter the first `mandu
    claude` starts, `server-main.ts`), and says "Mandu is not running, so
    it protects no agent now: start yours with mandu claude (or mandu
    codex). The dashboard shows your last scan under Scan.". Its Home says
    "Protection is off: no agent runs with Mandu." (dashboard.md §4.25,
    *Protection is off when nothing runs*), its scan card and Scan page
    say the secrets left in sessions without Mandu. A pinned
    `MANDU_ARBITER_SOCK` that is absent is still refused, naming it.
    Tests: `launcher/test/unit/scan-command.test.ts` (the line in each
    case, the npx detection), `launcher/test/unit/subcommands.test.ts`
    (the dashboard with no arbiter), and the stack test
    `tests/stack/scan-dashboard-link.test.ts` (the real launcher's scan,
    dashboard and scan again in a home where Mandu never ran).

13. **Found secrets become plan 14 suggestions** (phase 2, 2026-10-21;
    `transcript-suggestions.ts`, the op `suggestFromScan`). After keeping
    the report, the command asks the running Mandu (the arbiter answering
    `hello` at the person's socket with the secrets axis on, never the
    throwaway) with the files of "your secrets" and their key names:
    absolute paths and names, never a value, at most 64 files; "your
    environment" is no file and is left out. With no Mandu running, nothing
    is filed and the report is kept without it; the next scan with Mandu
    running files them. The running arbiter believes no claim: it reads each
    file itself (a regular file under the named HOME, opened without
    following a link, at most 4 MiB), refuses an agent's own login or data
    (`agentFileOf`, `isAgentAuthPath`: a lock there breaks the agent, and a
    launch keeps them raw on purpose) and Mandu's own folder, and keeps a
    file only when its own extractor reads a credential
    (`knownIsCredential`) under one of the named keys. The generator
    (`suggestPastSessionEdits`) drops a file the catalog or a label already
    protects (the walk's coverage check) and makes one `lock-path` at
    `no-model` per file, source `past-sessions`, finding key
    `past-sessions:path:<literal path>`, `rotate: true` (the key did
    leave), its evidence the names and the scan's session count and last
    date. Filing is plan 14 §5.1's, as the model's suggestions file
    (`fileModelSuggestions`): requested by `mandu:scan`, deduplicated by
    finding key and by every subject (one suggestion per file across the
    sources), a dismissal blocks it for good, the per-folder cap shared.
    `repoRoot` is the nearest work tree above the file below HOME, else
    its folder, never HOME, so a key in `~/.config` is no project's in the
    launch's count. On the data plane: what any caller can make it do is
    file a tightening proposal for a file under HOME that holds a
    credential, which the workspace scan already does for a root the
    caller names; the counts on it are the caller's (the scan's), shown as
    such. The person applies it as any suggestion (plan 14 §5.2); the
    report and doctor say a rule waits. The common case files nothing: a
    project `.env` is the catalog's, and a CLI config the content tier
    labels at launch is covered once a launch has labelled it.

14. **A key-shaped value that looks like a test value is marked**
    (2026-10-22; `transcript-test-values.ts` `looksLikeTestValue`). The
    detector already drops the obvious stand-ins (`EXAMPLE`, `xxxx`,
    `placeholder`, `${VAR}`, one character repeated: `isStandIn`); this
    marks what passes it and still reads as made up: a test word (`test`,
    `fake`, `mock`, `dummy`, `sample`, `demo`, `fixture`, `bogus`,
    `invalid`, `notreal`, `placeholder`, `example`) set off by separators
    on both sides, in lower or upper case (`sk-proj-test-…`), one
    character eight times in a row (a digit ten), a straight run of eight
    letters or ten digits (`abcdefgh`, `1234567890`), a unit of two to
    eight characters repeated over sixteen, a body of sixteen or more of
    four characters or fewer, or one of the example keys vendors publish
    (Slack's documentation's bot token, the API key of Google's Maps
    samples). The arbiter decides from the value when it first finds it;
    the finding (and a send of it) carries `looksLikeTest: true`, never
    the reason, and no character of the value.
    A real key must never be hidden by it, so each rule is one a random
    body essentially never meets: the separators make a test word in a
    random `[A-Za-z0-9_-]` body under once in ten million keys even over
    Anthropic's 93 characters (and impossible in a body with no
    separators, GitHub's or AWS's); the runs, units and narrow bodies are
    each under once in a billion (the digit thresholds are ten, as a
    Slack token's ids are digits only); a word inside a random run
    (`k3Jtest9Qm…`) or in mixed case is not a mark; Stripe's `sk_test_`
    keys are real keys of its test mode, and the detector does not take
    them anyway. The unit test draws thousands of random bodies of every
    vendor format and none is marked. Only the key-shaped group can be
    marked: never one of the person's own secrets (a value found in their
    files, whatever it looks like), never a value named like a secret, a
    URL's password or a private key; the launcher, the kept scan and the
    dashboard drop a mark on anything else.
    The terminal report lists the marked values apart and does not count
    them as leaked: one dim line in the compact report, their own group in
    `--all` ("look like keys, but read as test values … the project and
    command tell for sure"), their own words in `--show`, and `--share`
    leaves them out of its count; a send of one says "(looks like a test
    value)". The kept scan carries the mark; the dashboard reads it back
    and shows nothing of it yet.

## 4. Agents, in order

| Agent | Store | Phase |
|---|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl` (under `CLAUDE_CONFIG_DIR` when set) | 1, built |
| Codex | `~/.codex/sessions/**/rollout-*.jsonl` (under `CODEX_HOME` when set) | 1, built |
| OpenCode | `opencode.db` (1.x and 2.x) under `$XDG_DATA_HOME/opencode` (default `~/.local/share/opencode`); the shell output files are local copies, not read as sent (§3 item 3) | 2, built |
| Goose | `sessions/sessions.db`, older `sessions/*.jsonl` (its data directory), `logs/llm_request.*.jsonl` (its state directory): `<GOOSE_PATH_ROOT>/data` and `/state` when set, else `$XDG_DATA_HOME/goose` and `$XDG_STATE_HOME/goose`, and macOS's `~/Library/Application Support/Block.goose` | 2, built |
| OpenClaw | `agents/<id>/sessions/*.jsonl` and 9.x's `agents/<id>/agent/openclaw-agent.sqlite`, under `OPENCLAW_STATE_DIR` (default `~/.openclaw`) | 2, built |
| Gemini CLI (Mandu does not run it) | `tmp/<project>/chats/session-*.jsonl` (0.39 on), older `session-*.json`, a subagent's `chats/<parent>/*.jsonl`, under `<GEMINI_CLI_HOME>/.gemini` (default `~/.gemini`) | 3, built: read |
| Copilot CLI (Mandu does not run it) | `session-state/<id>/events.jsonl`, older flat `session-state/<id>.jsonl`, under `COPILOT_HOME` (default `~/.copilot`), and before 1.0.44 `$XDG_STATE_HOME/.copilot` when that was set (a folder its move left as a link is read once) | 3, built: read |
| Cursor (Mandu does not run it) | the editor's `User/globalStorage/state.vscdb` (under `$XDG_CONFIG_HOME`, default `~/.config`, `Cursor` or `cursor`; macOS `~/Library/Application Support/Cursor`) and the `cursor-agent` CLI's `chats/<hash>/<chat>/store.db` (under `CURSOR_CONFIG_DIR`, else `$XDG_CONFIG_HOME/cursor` when set, else `~/.cursor`) | 3, built: counted, not read |

Each store is where the agent's own environment puts it, as the launcher
finds it (`transcriptSources`); the op takes those variables from the
arbiter's environment only for its own HOME, so a scan of another home
(a test's) reads that home's defaults. A transcript the scan reads is
never also a place a known value is taken from (discovery walks
OpenClaw's store like any other folder). Mandu's sessions of these agents
are their time windows (item 6, by the launch's target) and the response
ids their proxy recorded; the readers note the ids each store keeps
(item 6: OpenClaw's and Goose's always, OpenCode 2's on the Responses API
and Gemini), and OpenCode's session id, which every one of its requests
carried (a session whose store keeps no response id, OpenCode 1.x and
OpenCode 2 on Chat Completions or Anthropic, is joined on it and the
time).

**Reading an agent's database.** The arbiter is the single writer of its
own database (`db/sqlite.ts`); an agent's database is the agent's, maybe
open in a running session, so the scan opens it read-only in a way that
neither changes it nor holds the agent up (`openAgentStore`):
- no write-ahead log in use (no `-wal`, or an empty one: the agent is not
  running, or the database is in rollback mode): `immutable=1`, so SQLite
  takes no lock and creates no file, and a writer that starts meanwhile is
  never blocked; everything committed is in the main file;
- a `-wal` with content and its `-shm` (the agent is running, or stopped
  without a checkpoint): the newest messages are only in the WAL, so it is
  opened `mode=ro` as a WAL reader. In WAL mode a reader and the writer
  never block each other; the connection writes neither the database nor
  the WAL and creates no file, and the one thing it touches is its
  read-mark in the `-shm` wal-index, as every reader of a WAL database
  does. If that open fails it falls back to `immutable`.
`mode=ro` with no `-wal`/`-shm` present would create both (probed), which
is why that case is immutable. Both modes are SQLite URI filenames, which
`node:sqlite` opens from Node 22.15 (probed on 22.15.0, 22.16.0, 22.22.1;
`sqliteUriFilenames` probes once at run time). Node 22.13, Mandu's floor,
takes the URI as a plain name and has no immutable open; a plain read-only
open of a database with no WAL in use creates its `-wal` and `-shm` there
too (probed), and of a rollback one takes a lock. So on 22.13 and 22.14
only a database whose WAL is in use is read (a plain read-only path is
then a WAL reader that creates nothing); a stopped agent's database is
counted as unreadable, and Node 22.15 or later reads it. No copy is made: a copy would put the
transcript's bytes in a second place on disk. An immutable read of a file
being checkpointed can meet a torn page; that session counts as
unreadable. A database's sessions are the scan's units: each is sized by
its rows (the per-file cap applies to it) and timed by its newest message
(`--since`, newest first).

Phase 3 is deliberate: the scan is most useful for agents Mandu does not
wrap yet, because it shows the person the same risk there.

**Phase 3 (built 2026-10-21).** Each format was read off the agent's own
shipped code, across the releases that could be seen, and read only where
it holds:
- **Gemini CLI is read.** It is open source, and its chat record's fields
  (`MessageRecord`, `ToolCallRecord`, `thoughts`, `tokens`) are the same in
  0.29.7 (2026-02), 0.53.1 (2026-07) and 0.65.0 (2026-10). The file moved
  from a whole JSON object rewritten on each message to a JSONL log in
  0.39 (2026-04), its updates from `$set.messages` snapshots to `$patch`
  lines in 0.64, and its project folders from a sha256 to a name in 0.29;
  the reader takes each. It has no version field: a file is told by its
  extension and its first line. Before 0.44 some turns that were sent are
  in no file (the session context, `!` output, the tool-response turn,
  which is only a call's `result`), so a finding there can be missed,
  never invented.
- **Copilot CLI is read.** Its `events.jsonl` envelope (`id`, `timestamp`,
  `parentId`, `type`, `data`) and the fields the reader takes are the same
  from 0.0.343 (2025-10) to 1.0.101 (2026-10), fields only added; it ships
  the event schema (`schemas/session-events.schema.json`), and
  `session.start` carries `version: 1`. Since 1.0.79 its projection of
  events into messages is native code; the reader's rule comes from the
  JavaScript of 0.0.343, 0.0.373 and 1.0.44, held by the same strings and
  the schema in 1.0.79 and 1.0.101. Copilot CLI's own secret filter masks
  its logs, never this file, so the record holds the raw values.
- **Cursor is counted, not read.** Its editor keeps agent chats in
  `state.vscdb`'s `cursorDiskKV`, undocumented and versioned only by an
  informal `_v`, and the layout changed at least four times in two years
  (per-workspace `ItemTable` keys, then `composerData:` with the
  conversation inline in 2024-12, then headers and `bubbleId:` rows, a new
  mechanism in 1.7.44 in 2025-10, `agentKv:` blobs in 2.5 to 3.16); a bubble
  holds what the person typed while Cursor's server builds the prompt, so
  even a working reader would not see what was sent. The `cursor-agent`
  CLI's `store.db` (two tables, the same from 2025-08 to 2026-10) holds
  server-written protobuf blobs, readable only with Cursor's vendored
  descriptors and broken by any renumbering. A fragile reader would be
  wrong without saying so, so neither is read: the scan counts the
  editor's chats (the `cursorDiskKV` keys in the exact range
  `composerData:` to `composerData;`, no value read, the database opened
  through `openAgentStore`) and the CLI's chat stores (its `store.db`
  files, a subagent's among them), and the report says "N Cursor chats not
  read". The answer carries the count as `notRead` (`{cursor: N}`), kept
  in the last report; a database that cannot be opened counts as
  unreadable. Its plaintext `agent-transcripts/*.jsonl` (since about
  2026-02, a derived view whose path already changed once) and its
  `ai-tracking` database are not read either.
- **The ids** of these agents are the registry's second table
  (`scripts/agents/agent-registry.mjs` `SCAN_ONLY_AGENTS`:
  `gemini`, `copilot`, `cursor`, with `read`), in the generated copies the
  scan's types are built on (`TranscriptAgent`), never a copy
  (supported-agents.md §5.7).
- **The report is honest about them.** For a secret whose story is in one
  of these agents, the last step says "Mandu does not run Gemini CLI yet,
  so there it could not have kept the secret from the AI" instead of what
  Mandu would have done; the closing line says "Mandu does not run Gemini
  CLI and Copilot CLI yet; the agents it runs: mandu claude, mandu codex,
  …" (each `mandu <agent>` of the registry), and the promise "To keep your
  secrets from the AI from now on: mandu claude" is printed only when the
  scan read an agent Mandu runs. The dashboard's Home card and Scan page
  say the same (`last-scan.ts`), and `--show` adds it under the
  with-Mandu lines.

## 5. The first run, and what is next

**Phase 0 (2026-10-21)**, on a maintainer's machine, with consent: 812
Claude Code sessions (subagents counted with their parent) and 16 Codex
sessions, 3.4 GB, read in 53 s.
- *Your secrets*: 2, both real and both printed by a command: a CLI's
  access token and a coding agent login's access token kept for CI. Before
  the credential-name rule (§3 item 5) the tier also held 37 version pins
  and image digests from one CI pins file.
- *Looks like a key*: about 280, almost all the test fixtures of the
  machine's own work (a security tool's development machine is the worst
  case for this tier).
- 87 sessions ran while Mandu ran the same agent; before the time windows
  (item 6), a `$MDU:` placeholder in the text was the mark, and on a
  machine that develops Mandu that marked half of all sessions.
- *Riskier sessions* (item 10, 815 + 16 sessions): 371 with prompts off and
  8 environment dumps. A first count that took any `env` or `printenv` in
  a command found 40; the rest were lookups (`env | grep PATH`) and
  scripts a here-document wrote.
- *HTTP sends* (item 11): 925 requests to hosts outside the machine; none
  held one of the 6 credentials on disk now or a key-shaped value. Four
  sends of a secret by its variable's name: two Stripe variables to
  `api.stripe.com` (one stopped by Mandu), and a `$TOKEN` to two
  container registries, which the scan cannot tie to a service. Before
  names alone counted, the report was empty: the `.env` those variables
  came from is gone. A first count that paired every secret in a command
  with every host in it found 213 pairs, nearly all test values sent to
  `localhost`.

**Phase 1 (built):** the readers, the scanner, the op, `mandu scan`, the
tests below, the user guide (usage.md, "Everyday commands").

**Phase 1b (built):** the riskier sessions (item 10) and the HTTP sends
(item 11), in the narrow scope the maintainer chose (2026-10-21): HTTP
clients and web fetches only, two kinds of host. Then (2026-10-22) the
rest of item 11, *Beyond HTTP*: `ssh`, `scp`, `sftp`, `rsync`; git with
a credential in its URL or header; an inline script's HTTP call to a
literal URL; MCP tools' inputs (Claude Code's and Codex's). Still not
covered, each said where it is ruled out: a file copied whole over ssh,
a git credential with no URL in the command, a script run from a file,
MCP calls of the agents that do not name them apart.

**Phase 2:** the other wrapped agents; the model proxies record response
ids so a session under Mandu is known exactly (item 6, built 2026-10-21
for Claude Code and Codex: `tllm_call`'s `model.responseId`, the
three-way status, the time mark kept only where no id settles it; then
the Chat Completions and routed Responses wires and the OpenClaw, Goose
and OpenCode 2 readers, the same day; OpenCode's session id, 1.x and 2.x
on every wire, 2026-10-22); each
finding told as a story with its examples, redacted (§1, §2, item 4,
built 2026-10-21: `examples`, `examplesByHow`, `mandu scan --show <n>`;
on this machine's last three days, 64 sessions and 241 findings, the
detector and the guard find nothing in the report); built 2026-10-21 too
(items 12, 13): the last report kept; the
dashboard's Home shows it under "secrets masked before the AI saw them"
and a Scan page (`/scan`) shows it whole, each finding as the story of how
it left the computer, with its examples; found secrets no rule covers
become plan 14 suggestions; `mandu doctor` prints one line from it. Then
(2026-10-21) the story's provider from the agents' own settings
(`settings.json`, `config.toml`; item 4), a web fetch's URL in the story
(item 4), and the Scan page in the top bar as its sixth link, the links two
rows of three below 500 px (dashboard.md §4.25 *Scan joins the links*);
Home's card and History link it too. **Phase 3 (built
2026-10-21):** agents Mandu does not wrap (§4): Gemini CLI and Copilot
CLI read, Cursor's chats counted.

## 6. Tests

- **The readers against real record shapes**:
  `arbiter/test/fixtures/transcripts/` holds the record shapes of real
  Claude Code 2.1.305 and Codex 0.160 transcripts with every value removed,
  made by `scripts/transcript-shapes.mjs` (keys and types kept; ids, times,
  paths, tool names and text replaced; at most two records of each kind).
  The unit test marks every text field and checks that the fields a reader
  yields are exactly the sent ones of item 3 and never a local-only one.
  Re-run the script on newer transcripts when an agent's format changes.
  The script also reads an agent's SQLite store (opened immutable), one
  record per row of the tables the scan reads. No real OpenCode, Goose or
  OpenClaw 9.x session was on the machine phase 2 was built on, so their
  fixtures (`opencode-1.18.13`, `opencode-2.0.26`, `goose-1.53.0`,
  `goose-sessions-legacy`, `goose-request-log`, `openclaw-2026.7`,
  `openclaw-2026.9.9`) come from stores written in each agent's own schema
  (the DDL and record shapes copied from its code) holding one record of
  every kind that code writes, then through the same script; OpenClaw's
  JSONL starts from a captured session. They stay, for the kinds of record
  a short session never writes (an ignored part, a compaction, a failed
  reply, a hidden message, the older Goose JSONL), beside the real stores
  below.
- **The readers against real stores** (2026-10-22): the stores in
  `arbiter/test/fixtures/transcripts/real/` were written by the agents'
  own binaries: OpenCode 1.18.13 and 2.0.23, Goose 1.53.0 (its
  `sessions.db` and its request log, one file per request) and OpenClaw
  2026.7.1-2 (JSONL) as the CI guest image pins them, and OpenClaw 2026.9.9
  (its SQLite store), installed from npm into the guest for the run.
  `tests/transcript-fixtures/generate.ts` drives each one, with a private
  home, against a scripted local Anthropic Messages endpoint (no API key,
  no live model): the shell tool runs a command that prints a fake
  `sk-ant-mdufixture-…` key (built from two pieces, so the command does not
  hold it), the file tool (Goose: its shell) reads a `.env` holding another
  and a plain value, then a closing text; every response carries its own
  `msg_01MduFixture…` id. Each store is copied out as the format above (a
  database's rows of the tables the scan reads, a JSONL store's lines), the
  temporary home, workspace, host and user names replaced, and
  `manifest.json` records each agent's version, its store's place and its
  run; OpenClaw's run trace is listed, not copied. Regenerate on a version
  bump with `scripts/ci/vm-run.sh --worktree --network --exec 'bash
  tests/transcript-fixtures/guest-run.sh'` (the network is for OpenClaw
  9.x's npm install; `MANDU_FIXTURE_OPENCLAW9_VERSION` picks it) and copy
  the run's `artifacts/release/transcripts` over the directory. The reader
  suite reads each through the store layer with every copy of a planted
  value tagged by its field: the command's output counted as command
  output and the file as a file read (Goose: both its shell's output), the
  person's prompt as theirs, the response ids and each text's request's
  (OpenClaw's and Goose's, its request log's too,
  none from either OpenCode on the Anthropic wire), and never a local-only
  copy (OpenCode 1.x's `state.metadata.output`, `preview` and `display`,
  Goose's `structuredContent`, OpenClaw 9.x's `details`). OpenClaw masks a
  key-shaped value in every tool result before its model sees it and
  keeps only the mask (`sk-ant…Nb4C`), so the planted keys are not counted
  for it, their masks are. The store suite scans a home holding all of
  them (OpenCode 1.x and 2.x in one database, as a migrated one keeps
  both) for the planted values as known ones, and checks every store is
  left as it was. Driving the real agents found three reader faults, fixed
  with this: OpenClaw's `<session>.trajectory.jsonl` was read as a second
  session (now `isRunTrace`, §3); Goose's `<turn-context>` was counted
  as the person's message (now context); Goose's request log yielded a
  tool call's `status` as text (now structure).
- **Unit** (`transcript-readers.test.ts`): the same marked-field check for
  each of those fixtures, the database ones turned back into SQLite files
  and read through the store layer; how each text got there; an ignored
  part, a compacted output, a failed reply, a background shell, Goose's
  person-only copy and hidden messages, OpenClaw's `details` never read;
  each agent's tool calls, how each ended and whether prompts were off,
  and their shell and fetch tools seen by `isEnvDump` and
  `httpRequestsOf`.
- **The phase-3 readers** (`transcript-unwrapped.test.ts`): no Gemini CLI,
  Copilot CLI or Cursor store was on the machine phase 3 was built on
  (`~/.copilot` held only process logs), so the fixtures `gemini-0.65.0`,
  `gemini-0.29.7` (a whole-file chat: its header, then each message) and
  `copilot-1.0.101` come from files written in each agent's own record
  shapes (copied from its code and its event schema) holding one record of
  every kind it writes, then through `scripts/transcript-shapes.mjs`
  (which reads a whole-file `.json` and keeps the `$set` / `$patch` keys).
  The same marked-field check over each, laid out where the agent keeps
  it and read through the store layer; how each text got there with
  literal records (an `@file`'s content with its path, the session
  context, a functionResponse matched to its call through the id the agent
  sends, `transformedContent` over the displayed copy, the person's own
  `!` command left out, a subagent's events); each call's end, prompts off
  (Copilot's allow-all, never Gemini's), the shell and fetch tools seen by
  `isEnvDump` and `httpRequestsOf`; each store's place under the agents'
  variables, a Gemini subagent with its parent, a project from its marker
  or its hash, Copilot's linked older folder read once; Cursor's chats
  counted by key (no value) and by file, the database unchanged, one that
  is not a database said, never a session read.
- **Unit** (`transcript-stores.test.ts`): a live WAL database read through
  its WAL while its writer keeps writing, a closed one immutable with no
  file created, a rollback one whose writer is never blocked, a store that
  is not a database counted as unreadable; each store's place under the
  agents' variables; a transcript never a source of known values; the
  scan over a home holding every store (a child session with its parent,
  the request log not a session, `--since` and the per-file cap per
  session, the stores byte for byte the same afterwards); the Mandu
  windows of the new agents.
- **Unit** (`transcript-known.test.ts`): the GitHub CLI's `hosts.yml` in
  both layouts (gh 2.x with `users:`, the flat one before 2.40), a two-host
  glab `config.yml` as glab writes it (comments, a template host's empty
  token, a proxy URL's password), each a credential; a live key whose
  random body holds `xxxx` counts, a stand-in does not; a systemd unit's
  `Environment=` values, a URL password in `ExecStart=`, its
  `EnvironmentFile=` and that file's values; the file list over a temp
  home with nothing from the walk (every store and agent login by its
  place, a `.wants` link once, a store's cap, never an agent's store or a
  transcript, a `public` verdict honoured); a known value counted in each
  of four sessions. **Component** (`transcript-scan-op.test.ts`): a home
  whose walk a launch's caps cut short (480 files in `~/.aws`, 210
  folders below the depth cap) still knows its GitHub CLI and glab
  tokens, Claude Code's login and the project's key.
- **Unit** (`transcript-scan.test.ts`, `scan-command.test.ts`): how each
  text got there; one secret across sessions and a subagent with its parent;
  `knownIsCredential` (a pin, a digest and a belt value without a format
  are not credentials); the Mandu windows; the response ids each reader
  keeps and the join (exact in, exact out, the time fallback, a subagent
  re-filed with its parent; ids from event files, not from a quoted id,
  within the caps); the caps counted; no value,
  8-character run or hash in the answer; `findSecretValues` against
  `detectSecretShapes`; the report's words, `--share` holding no path,
  mask or name, the exit codes. The examples (item 4): the command of the
  call a result answers (both agents, by call id), the command the AI
  wrote a value into, the file read, the project and provider, three
  newest with one without Mandu kept, ten a way, a subagent's mark
  reaching its parent's example, the hosts a secret was sent to, and no
  8-character run of a value planted in commands, outputs and
  here-documents. The report: each how's story and what Mandu would have
  done, the key-like rows (three stories, then one example line, three
  with `--all`), the Mandu footnote and the findings Mandu kept, the
  numbers, `--show` and its exit codes.
- **Unit** (`transcript-redact.test.ts`): `redactShown` by each step (a
  vendor key, a known value by its name, a value its name or scheme
  marks, a URL's password, a URL query's value under a secret's name, a
  variable kept), one line, 240 characters, a here-document's body
  dropped, the guard (a random run masked; a path, a flag and a word of
  names kept), and fake keys planted in ten commands and six fetched URLs'
  queries never leaving an 8-character run.
- **Unit** (`transcript-providers.test.ts`): Claude Code's flags and base
  URL (a flag that is off, a look-alike domain), a settings file's `env`
  block, Codex's `model_provider`, a profile's, a provider's `base_url`,
  `OPENAI_BASE_URL`; the record winning where it names a provider and the
  settings making the agent's own `other`; the user's `settings.json`
  under `CLAUDE_CONFIG_DIR`, the managed settings only for this HOME,
  `config.toml` under `CODEX_HOME`; a project's settings read once per
  folder; real files answered with kinds only, never a URL, host or
  provider id; the scanner's example provider from each. In
  `transcript-scan.test.ts`, a web fetch's example: the fetch whose page
  held a key, the fetch the AI wrote keys into, its URL masked, no
  8-character run in the answer.
- **Unit** (`transcript-acts.test.ts`): each call's end in both agents'
  forms, prompts off and on, the shell commands of each shell tool
  (Codex's code-mode `exec` too), the pipeline split (quotes, `$(…)`, a
  here-document), which commands are environment dumps and which are
  lookups, and the scanner's counts with a subagent counted with its
  parent.
- **Unit** (`transcript-sends.test.ts`): which parts of a call are HTTP
  requests and which are not (a value an earlier command printed, a
  here-document, a client with no URL), continued lines, the hosts left
  out, `sentTo` for formats, self-hosted installs, a file naming its host
  and a look-alike domain, and the scanner's sends: by value and by
  variable, how each ended, no value in the answer. Beyond HTTP
  (2026-10-22): `parsePipeline` (words over lines, the variables this
  shell expands, a here-document with its command); `ssh`, `scp`, `sftp`
  and `rsync` with their hosts and what their pipeline fed them (not a
  command after them); git with a credential in its URL or header (a
  Basic one decoded), and nothing for `git push origin main`, a clone with
  no credential, a header with no URL, a commit message; an inline
  script's HTTP call, and nothing for a script that only prints, builds
  its URL, runs from a file or is written by a here-document; an MCP
  tool's input, also over the real record shape of Claude Code's MCP
  calls (`claude-code-2.1.305.jsonl`) with a key planted in one; the
  scanner's sends with their channel, `ssh localhost` left out, the git
  URL masked, `sentToHosts` without the MCP tool.
- **Unit** (`transcript-test-values.test.ts`): each rule of item 14
  marks what it names, the near misses do not (a word in a random run,
  no separator, mixed case, seven in a row, nine digits), only the
  vendor formats can be marked, and thousands of random bodies of every
  vendor format are never marked; the scanner marks a test-looking value
  and its send, never one of the person's own (`transcript-sends.test.ts`).
- **The launcher** (`scan-command.test.ts`, `scan-kept.test.ts`): the
  path-aware cut (a path by its middle, a cut after a `/`, never half a
  word or a mask); the yellow line per way, `--all`'s MCP group between
  the hosts and the own services, `--show`'s header; an older answer's
  sends read as HTTP; the test values listed apart, numbered after the
  leaks, not in `--share`'s count, a mark on one of your secrets never
  read; the kept scan keeps `channel` and `looksLikeTest`, an unknown
  channel and a mark on a known secret dropped. The dashboard's reader
  (`last-scan.test.ts`) reads both back and names an MCP tool as one,
  never as a host.
- **End to end** (`tests/stack/transcript-scan-sends.test.ts`): the
  launcher's production call against a real arbiter over a home whose
  Claude Code session wrote a `.env` key into an `ssh` command and an MCP
  tool's input, pushed with a token's variable in a git URL, posted a key
  from a `python3 - <<'EOF'` script's `os.environ`, cloned with a key in
  no file, and wrote an `sk-proj-test-…` value into a command; and did
  four things that are not sends (`ssh localhost`, `git push origin main`,
  a script that only prints, a script written and not run). Every send is
  reported with its channel and destination, none of the four is; the
  compact report's line per way, `--all`'s groups, `--show`'s header; the
  test value apart and not counted; the kept scan's `channel` and
  `looksLikeTest` read back by the dashboard's reader; no 8-character run
  of a planted value in `--json`, the report, `--all`, `--show`, the kept
  scan or the arbiter's log; nothing connected but the arbiter's socket.
- **The op** (`transcript-scan-op.test.ts`): a value the caller passes is
  never looked for; bad arguments refused; nothing scanned with the axis
  OFF; the arbiter's directory variables not applied to another home.
- **End to end** (`tests/stack/transcript-scan.test.ts`): the launcher's
  production call against a real arbiter over a fixture home finds the read
  `.env` key with its file and how, not the local-only copy, not the
  version pin, and marks the session under Mandu; no 8-character run of a
  planted value in the report, `--json`, `--share` or the arbiter's log;
  every socket connect in the process is the arbiter's. The fixture's
  session ran with prompts off and printed its environment: both are
  counted and said. It also sends the key through its variable to its
  own service and, failing, to another host: both are listed, the other
  host first. It prints a `.env` password with `grep` and writes it, a
  Slack token and an OpenAI key (in a here-document) into commands: each
  finding's story shows the command with every value masked
  (`PGPASSWORD=‹DB_PASSWORD› psql …`, `Bearer …`, `<<'EOF' …`), the read
  file and the provider, the JSON carries the examples' exact shape, and
  `--show`, `--show --json` and `--all` hold no 8-character run of a
  planted value either. Another holds the GitHub CLI's `hosts.yml` (gh
  2.x, `users:`, a second host), a two-host glab `config.yml` and a
  systemd user unit with a proxy URL's password, printed in four Claude
  Code sessions and pasted in a Codex one: all five values are known with
  their file and key, the second glab host's in all four of its sessions,
  none again by its shape, and no 8-character run of one in `--json`, the
  report, `--all`, `--show` or the arbiter's log. A third test sends one exchange through each real model
  proxy (production arbiter wiring) and scans transcripts that keep those
  ids: both sessions are under Mandu exactly, and a Claude Code session
  at the same time whose id Mandu never saw is not. Another does the same
  on the Chat Completions wire: an OpenClaw and a Goose exchange through
  the anthropic-proxy's routed provider, and an OpenClaw JSONL and a Goose
  `sessions.db` that keep those ids: both are under Mandu exactly, a
  parallel OpenClaw session is not, and the openai-proxy's Chat route
  records its id too; the two proxies' `response-id.ts` and its suite are
  pinned byte-identical. Another sends an OpenCode 1.x exchange (Messages
  wire, `X-Session-Id`) and a 2.x one (a routed Chat wire,
  `x-opencode-session-id`) through the real anthropic-proxy and scans an
  `opencode.db` that keeps no response id: both sessions are under Mandu
  exactly, a parallel 1.x session at the same time is not, not even by
  time. The proxies' own
  unit tests read the id from SSE and JSON and keep no ill-formed one; on
  the Chat and routed Responses wires (`response-id.test.ts`, the
  `chat-completions` and `openai-route` component tests) also however the
  stream is cut, none for an error answer, the bytes relayed unchanged,
  and the id the agent got when the gate held the first chunk back. The
  reader suite (`transcript-readers.test.ts`) reads each store's ids off
  the fixtures (OpenClaw's JSONL and database, OpenCode 2, Goose's
  database, older JSONL and request log; none for OpenCode 1.x), never a
  user row's, a tool's or one Goose made up, and OpenCode's session id on
  every request of the real 1.18.13 and 2.0.23 stores (none of another
  shape). The proxy's unit and `openai-route` tests take the session id
  off each header OpenCode uses, 2.x's own id first, none of another
  shape, the headers reaching the provider unchanged; the scanner's unit
  test joins a resumed OpenCode session per request at its time (before
  the resume and after Mandu's session ended: without), a parallel one
  without and one beside an older Mandu by time.
  The real CLI with
  its throwaway arbiter runs over the same home, inside a network namespace
  with no route where the kernel lets an unprivileged user make one. A
  fourth test runs the same production path over a home holding the other
  agents' stores: an OpenCode 2 `opencode.db` with its WAL in use (its
  shell result printed a `.env` key, its tool's local metadata held
  another, its own rules allowed every tool), a Goose `sessions.db` (its
  `auto` mode, a person-only copy of a shell's output) and an OpenClaw
  session whose web fetch put the key in a URL to another host (a result's
  `details` held the other). The key is reported for OpenCode and OpenClaw
  with the commands redacted and the provider each record names, the
  local copies are not, the OpenCode session is under Mandu by time and
  both prompts-off sessions are counted, the fetch is listed and its story
  names the URL with the key masked, nothing holds an 8-character run of
  a planted value, and every store is byte for byte the same afterwards
  (the `-shm` wal-index aside). A fifth runs over a home whose Claude Code
  `settings.json` turns Bedrock on and whose Codex `config.toml` picks a
  gateway: the story says "the model provider" for Claude Code and for a
  Codex session whose record names none, OpenAI for one whose record names
  `openai`; Claude Code's web fetches name their URLs (the keys the AI
  wrote into one masked) in the report, the kept scan and a real
  dashboard's `/api/scan`; and no 8-character run of a planted value, and
  nothing of the settings (the gateway's host, the provider id, the
  region), is in any answer or the arbiter's log. A sixth runs it
  over a home holding the stores of agents Mandu does not run: a Gemini CLI
  chat whose shell result printed a `.env` key (its display copy held
  another), a Copilot CLI session in allow-all mode whose command printed it
  (its detailed copy held another) and whose web fetch sent it on, and
  Cursor's editor database (WAL in use) and CLI store, each holding a key.
  The key is reported for both with the command redacted and their
  providers (Google, GitHub), the local copies and Cursor's keys are not,
  the prompts-off session and the send are counted, "3 Cursor chats not
  read" is said and kept, the report says Mandu does not run them and makes
  no promise for them, nothing holds an 8-character run of a planted value,
  and every store is byte for byte the same.
- **The kept report** (`launcher/test/unit/scan-kept.test.ts`): only the
  named fields kept (the agents Mandu does not run and `notRead` too), examples cut to 10, control characters dropped, the
  optional phase-2 fields kept when present; the file at 0600 read back the
  same, a foreign file read as none; doctor's line in each case and its row;
  the files named to the running Mandu; `keepLastScan` with no Mandu, with
  one, through its failure and a failed write; no 8-character run of a
  planted value kept even when the answer carried one in a field not kept.
- **The suggestions** (`arbiter/test/unit/transcript-suggestions.test.ts`,
  `arbiter/test/component/suggest-from-scan-op.test.ts`): the claims'
  shape; only a credential under a named key makes a candidate; outside
  HOME, an agent's login, Mandu's folder, a link and a file with no
  credential refused, each with its reason; the catalog's `.env` covered;
  one `past-sessions` suggestion, filed once, applied on the data socket
  into policy.yaml; axis OFF files nothing; no value in any reply, the log,
  the events, the database or policy.yaml.
- **The dashboard** (`dashboard/test/unit/view-model/last-scan.test.ts`,
  `dashboard/test/unit/ui/home-js-scan.test.ts`, the suggestions view
  model): Home's card before and after a scan; each finding's story steps,
  footnote and detail panel, with and without the optional fields; the
  tiers, the long one folded with its filter and Show more; an agent
  Mandu does not run (its story's last step, the way to stop it naming the
  agents Mandu runs, the chats not read); every agent
  the scan reads by name and in order (sessions, past sessions, a story's
  agent and provider), in the kept file too; markup in a
  command stays text; product vocabulary only; no value on either page.
- **End to end** (`tests/stack/transcript-scan-kept.test.ts`): the
  launcher's production path with the scan in one real arbiter and the
  suggestions in a second (the running Mandu's) over a fixture home; the
  report's line, the kept file, doctor's line, a real dashboard's
  `/api/home`, `/api/scan` and `/api/suggestions` (the CLI config's
  past-sessions row, applied by Save on the admin channel) all show it, and
  no 8-character run of a planted value is in any of them, either
  arbiter's log, the running one's database or policy.yaml.

## 7. Decided questions

Decided 2026-10-22 by the maintainer; each is reopened only if what it
rests on changes.

1. **No smaller entry point for now.** `npx @mandusec/mandu scan` fetches
   the whole package (about 17 MB unpacked, Node 22.13). A scan-only
   package is revisited if the first run's size turns out to keep people
   from running it.
2. **No scrub of the local transcripts.** The provider already has the
   requests, rewriting an agent's store can break resume, and it would be
   the scan's only write: the scan stays read-only.
3. **No tail.** The git-history scan's rule holds for both scans: no
   character of a value's body is shown, not even the last four. Two keys
   of one service are told apart by where each was found.
