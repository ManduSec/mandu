# Mandu: `mandu demo` (design)

> Companion to [`packaging.md`](./packaging.md) §7 (the M4 UX layer this is the
> last piece of). Status: **BUILT 2026-09-27** (one Claude Code step, the
> hiding half only); **REDONE 2026-10-05**: Claude Code and Codex, three
> scenes each (hide, use, stop), in plain words; the agent's commands run
> under the whole-agent guard where the host has it (§3 "The guard"), so
> Codex's `cat .env` reaches the AI per key. The attack-contrast demo (an
> injection run with and without Mandu, ending at the dashboard trace) is
> not built; §9 keeps it as the deferred extension.

## 1. The one job

`mandu demo` shows, in a few seconds and with no API key, no agent login and
no network, what the product does in the `secrets` mode it ships with
([`protection-modes.md`](../architecture/protection-modes.md)): **your agent
works with your secrets without ever seeing them.** For each agent (Claude
Code, then Codex), on that agent's own wire, three scenes:

1. **The agent reads `.env`.** The AI gets the key only as a placeholder
   (`‹hidden›` on screen); you see the real value.
2. **The agent uses the key** (`curl` to `api.stripe.com`, the host the key
   is bound to). The request leaves with the real key filled in on the way
   out.
3. **…and tries to send it somewhere else** (`paste.example`). The request
   is stopped before anything leaves, and Mandu raises an approval for you.

The first version showed only scene 1, for an anonymous Claude-shaped step,
with the internals up front (the services' start lines, raw `$MDU:`
placeholders, byte counts). The maintainer's verdict (2026-10-05): it must
show both agents, name them, show the *useful* half (the agent can still use
the key, where it may go) and not only the hiding, and read in plain words.

Every line comes from the real defense, not canned output: what the AI got is
the request body the real model proxy forwarded, captured at the model end;
what you see is the real reply filter's output; "sent" is what a stand-in
`api.stripe.com` received from the real egress proxy; "stopped" is the real
egress gate's refusal and the approval row the real arbiter raised; the
agent's commands run under the real whole-agent guard (`mandu-net-guard`)
wherever this host runs it. The run exits 0 only when every check holds (§6).

```sh
mandu demo                    # both agents (about 3 s installed, 7 s from a checkout)
mandu demo --agent codex      # one agent: claude or codex
mandu demo --verbose          # also what runs underneath
mandu demo --keep             # keep the throwaway folder: logs, every model request
```

What it deliberately does NOT show: an attack. There is no injected
instruction; scene 3 is the user's own request ("paste the key to
paste.example"), stopped because the key is not bound there. `secrets` mode
does not mask untrusted text (protection-modes.md §1), and the demo says
nothing that suggests it does.

## 2. What the user sees

The default output (the installed bundle, 2026-10-05):

```
Mandu demo: your agent works with your secrets without ever seeing them
  A throwaway project with a fake Stripe key. The AI is a local stand-in:
  no API key, no login, and nothing leaves this machine.

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

Next: try it with your own agent → https://github.com/mandusec/mandu/blob/main/docs/first-session.md
```

- **Plain words.** The default output never says "arbiter", "proxy", "reply
  filter" or `$MDU:`, and shows no byte count or timing (a unit test sweeps
  it). A placeholder the AI got shows as `‹hidden›`; the quotes around the
  value on "you see" are the screen's own (Mandu's placeholder copy quotes the
  value, and the reply filter puts the real value inside them).
- **The second agent folds into one line** when all its checks hold and its
  step 1 showed the keys (it is the same three steps on another wire); any
  failed check prints it in full, the failing step marked `✗ failed` with
  the reason, and so does a step 1 that got the whole file (below).
  `--agent codex` alone prints Codex in full.
- **Scene 3 says "in a real session the dashboard asks you"**, not a URL:
  the demo runs no dashboard, and the approval row it checks lives in the
  throwaway sandbox's arbiter. A dashboard link that leads nowhere would be
  worse than none.
- **It prints as it goes:** each scene's lines appear when the scene is done,
  so a recording carries the real timings. Colors only on a TTY that allows
  them (`NO_COLOR`, `TERM=dumb` and a pipe get none).
- **The pointer** is the public URL of [`first-session.md`](../../first-session.md)
  (`docs-url.ts`), which works for an installed user who has no `docs/`.

`--verbose` adds what runs underneath as dimmed `·` lines: each service as it
starts with its time, the `.env` registration, the guard (its bin, or why
there is none), and per scene the placeholder
the AI got, how many requests (and bytes) the model received, the command the
agent ran and whether it ran under the guard, what the bound host received (`Authorization: Basic …`, the real
key), the egress gate's answer (`egress withheld 1 symbol(s) → block
(fail-closed) [egress:secret-unbound]`) and the Approvals row (`egr-1 …
pending, asked 2 time(s)`: Codex's attempt bumps the row Claude Code's
raised). Every agent prints in full under `--verbose`.

**Codex's scene 1 is per key under the guard, and says why when it is
not.** Codex reads `.env` with its shell (`cat .env`), not a file tool, and
the arbiter shows a shell result per key (the exec-output twin rule,
[plan 10](../confidentiality/confidentiality-plan-10-flow-taint.md) §11.8)
only on evidence: the guard recorded the call's process tree and no process
in it opened a secret raw. The text alone is never enough: a program that
read the real bytes could choose which piece of the copy to print. So the
demo runs every command the agent runs inside the real guard, as a launch
does (§3 "The guard"); the guard reports the call's shell on the arbiter's
human plane, the model proxy binds the call to it, and Codex's step 1
reads `STRIPE_KEY=‹hidden›` / `DEBUG=1` like Claude Code's (the proxy's
`twin:` note to the model is left off the screen, shown under `--verbose`).
Where the host has no guard, the proxy masks the whole output, as `mandu
codex` does on that host, and the screen says why in plain words, under
`‹hidden› (the whole file)`:

| No guard because | The line under it |
|---|---|
| not Linux (the guard is seccomp user notification) | `the keys show only under Mandu's guard, which is Linux only` |
| no `mandu-net-guard` bin resolves (a checkout that never ran `scripts/build-native.sh`, a package without its native bins) | `…, not built on this machine` |
| `MANDU_NET_GUARD=0`, the launch's own opt-out | `…, turned off (MANDU_NET_GUARD=0)` |
| the bin ran but could not attach (`--skip-unsupported` ran the command unguarded: no status file) | `…, which this kernel cannot run` |

Codex is then printed in full rather than folded into "the same three
steps" (its step 1 was not the same), and the run still exits 0: hiding the
whole file is the fail-closed answer, not a failure.

**No recording (2026-10-19).** The README carried an animated recording of
this run (`docs/assets/demo.cast` and `demo.svg`, rendered with
`svg-term-cli`) until 2026-10-19, when the README was shortened for the
release; the recording was dropped with it and the README now only names
`mandu demo`. The homepage's agent demos are separate videos.

## 3. The run, step by step (`launcher/src/demo/`)

| Step | What runs | Code |
|---|---|---|
| sandbox | a fresh `mandu-demo-XXXXXX` under `$TMPDIR` (or `/tmp` when a long `$TMPDIR` would overflow a socket path, §5); a fake project with a `.env` whose key is minted per run; the sandbox's own `policy.yaml` labels that `.env` `no-model` and binds it to `api.stripe.com` | `sandbox.ts`, `fixture.ts` |
| model | a stand-in capture server on `127.0.0.1:0`, both model APIs (§4) | `stand-in-model.ts` |
| arbiter | the real arbiter (`Layout.daemon("arbiter")`), its symbol DB, event store, policy file and runtime dir inside the sandbox, pinned to `secrets` | `demo.ts` |
| the agent's copy | the demo asks the arbiter to register `.env` (`registerSecret`, as a launch's secret setup does) and writes the placeholder copy it answers (`STRIPE_KEY='$MDU:nomodel_Read[h].STRIPE_KEY'`) into `agent-view/`, the project as the agent sees it. A real session mounts that copy over the file (confidentiality.md §7.2); the demo keeps it beside the original | `demo.ts` |
| sites | three HTTPS listeners on `127.0.0.1` (§4a): `api.stripe.com`, `paste.example`, and a catch-all | `stand-in-sites.ts` |
| egress | the real net-proxy (`Layout.daemon("net-proxy")`) with TLS inspection on (`MANDU_NET_PROXY_MITM=1`, its session CA in the sandbox) and host routes to the listeners (`MANDU_NET_PROXY_MOCK_SITES`), resolving over the arbiter's human plane like a launch's | `demo.ts` |
| per agent | its real model proxy: anthropic-proxy for Claude Code, openai-proxy for Codex (`Layout.daemon`), port 0 + port file, `MANDU_UPSTREAM` = the stand-in | `demo.ts` `runAgent` |
| guard | per agent, once its model proxy has a port: the whole-agent guard's wrap and policy file, built as a launch builds them (below); none where the host has no guard (§2) | `guard.ts`, `demo.ts` `runAgent` |
| per scene | the demo plays the agent: it sends the user's prompt on the agent's wire, runs the ONE tool call the model answers with (Claude Code: `Read` of `.env` returns the agent's copy in Read's numbered rendering, `Bash` runs its command; Codex: the `exec` cell's command), sends the result back, and reads the model's reply. Commands run as `sh -c <command>` in `agent-view/`, with the session's `HTTPS_PROXY` and the egress CA (`CURL_CA_BUNDLE`), as a launch gives the agent's programs, inside the guard when there is one | `demo.ts` `runScene`, `executeCall` |
| reply | scene 1's reply goes to the real reply filter (`Layout.replyFilter()`, pipe mode) around `cat <reply>`, the path an agent's stdout takes, with the human-plane socket from `hello` (`MANDU_ARBITER_HUMAN_SOCK`, `arbiter-human-plane.md`) | `demo.ts` |
| checks | §6; exit 0 only when all hold | `demo.ts` |

The wires (`fixture.ts`):

- **Claude Code**: the Messages API, the `Read` and `Bash` tools, streamed
  `tool_use` blocks (`input_json_delta`), `tool_result` in Read's
  `     1→line` rendering.
- **Codex** (codex-cli ≥ 0.154, [`supported-agents.md`](../agents/supported-agents.md)
  §6): the Responses API, the battery as an `additional_tools` item (no
  top-level `tools`), the shell call as a `custom_tool_call` named `exec`
  whose JavaScript cell calls `tools.exec_command({cmd, workdir, …})`, the
  result as a `custom_tool_call_output` array of text parts (the `Script
  completed / Wall time / Output:` envelope, then the output).

The commands are the ones a real agent wrote on the tour
([`first-session.md`](../../first-session.md) step 2): `set -a; . ./.env;
set +a; curl -sS -u "$STRIPE_KEY:" https://api.stripe.com/v1/customers`, and
the same key in a POST to `https://paste.example/new`. The sourced `.env` is
the placeholder copy, so curl's argv holds the placeholder; the value goes in
only on the wire, after the binding check (confidentiality.md §7.1). The
demo runs only its own three commands: a tool call that comes back
different fails the scene, it is never run.

**The guard** (`guard.ts`). A launch wraps the whole agent in
`mandu-net-guard` (exec-routing.md §7.5; net-guard-setup.ts), the seccomp
user-notification supervisor that traps the agent tree's connects and opens,
serves a registered secret's twin at `open()`, and reports each exec, open
and lineage edge to the arbiter on its human plane (plan 13 D9: reports on
the data socket are claims and release nothing). The demo has no agent
binary to wrap, so it wraps each command the agent runs in the same guard,
with a stand-in agent between them, and takes everything else from the
launch's own code:

- the bin: `findDemoGuard`, Linux only, the launch's resolver
  (`resolveNativeBin`: the installed package's prebuilt bin, a checkout's
  `interceptors/target/`, the `MANDU_NET_GUARD_BIN` override) and the
  launch's opt-out (`MANDU_NET_GUARD=0`); a stale bin's warning is shown
  under `--verbose`;
- the wrap: `computeNetGuardSpecs` (the agent's model proxy port and the
  egress proxy port on loopback, DNS, the agent's API host, the default
  `:443`/`:22` fallback) and `planNetGuard` (`--skip-unsupported`), the
  session proxy ports (`MANDU_NET_GUARD_PROXY_PORTS`) and the status file
  (`MANDU_NET_GUARD_STATUS`, guard-death.ts);
- the policy file (`MANDU_NET_GUARD_SECRETS`, `run/guard-policy-<agent>.json`):
  `guardPolicyBase` (guard-policy-file.ts) with the agent's session (the
  key its model proxy files calls under, so the arbiter binds the call to
  the guard's record) and the secret entry `applySecretTwins` writes (the
  real `.env`, the agent's copy as its twin, `no-model`), and the human-plane
  wall `applyHumanPlaneDeny` writes (`unixDeny`: `humanPlaneDirs` of the
  human socket and the demo's runtime base, `demoHumanPlaneDirs`);
- the human plane: the guard finds it from the data socket's `hello`, as in
  a launch, and believes it only under arbiter-human-plane.md §5.2's checks,
  the walled directory among them (2026-10-17: without the `unixDeny` above
  the guard reported on the data socket and Codex's scene 1 failed as one
  placeholder); the commands get no `MANDU_ARBITER_HUMAN_SOCK`. The offline
  run (a network namespace) keeps the arbiter and the guard in one pid
  namespace, so the guard's `SO_PEERCRED` check sees the arbiter.

The stand-in agent is `node -e AGENT_RUNNER <command>`, the policy's
`agentExe` (the node the demo runs on): it runs the command as `sh -c
<command>`, so the guard sees the shell as the agent's own child, which is
the call root a real agent's shell is (plan 13 D7, `rootSignaturesOfArgv`),
and prints the shell's exit, stdout and stderr as one JSON line, so the
guard's own stderr never mixes into the tool result (in a launch it goes to
the terminal). After each command the demo reads the status file: the guard
writes it only once it supervises the tree, so its absence means it ran the
command unguarded, and the screen says so (§2). A guard that cannot set up
at all (no JSON line back) ends the run (`✗ the demo could not run`), never
a silent fallback. The commands still run in `agent-view/` (the bind-mount
posture: the copy at the path the agent reads); the guard adds the evidence,
and would serve the twin by descriptor to any process of the tree that
opened the real `.env`. No root and no host-global state: seccomp user
notification needs only `no_new_privs` (the non-root principle).

Services start through `Layout.daemon` and the lifeline-carrying primitive
(`startDetachedCmd`), so the same code runs from a checkout (its own fresh
bundle, or `node --import <tsx>` over the source, packaging.md §5.1) and from
the installed bundle (`node dist/<name>.mjs`); the bundle needs no new entry
(the demo is part of `mandu.mjs`, and the arbiter, both model proxies,
net-proxy and reply-filter bundles already ship). The services are stopped
and the sandbox removed at the end, on failure too, and on Ctrl-C; the
lifeline stops them if the demo itself dies.

**A comment line in the fake `.env`.** The fake `.env` is a comment
(`# fake values, made up by mandu demo`), the key and `DEBUG=1`
(`fixture.ts` `envFileText`). The arbiter's value backstop raises a tool
result that carries a registered secret, or any line of 24 characters or
more of one (`egress-fingerprint.ts` `MIN_LINE_FINGERPRINT_LEN`), to the
secret's level. The registered value of a `.env` is the whole file, so the
comment was such a line, and the placeholder copy carries it: until
2026-10-05 the agent's Read of the copy was masked whole
(`$MDU:nomodel_Read[…]`) instead of showing the keys, and the demo left the
comment out. A line the file's own placeholder copy carries as it is, with no
secret in it, is no fingerprint now (confidentiality-plan-10-flow-taint.md
§11.8, "a twin line is no fingerprint"), so Claude Code's scene 1 shows the
comment and each key, the key a placeholder (§10).

**Signals (^C-safe cleanup).** During the run a SIGINT or SIGTERM aborts it:
stop the services, remove the sandbox (unless `--keep`), exit 130. Once
cleanup starts, from that abort or from the normal end, the demo applies the
launcher's teardown policy through the same guard
(`launcher/src/teardown-signals.ts` `createTeardownGuard`,
portable-wrapper.md §2.1 "Teardown signals"): SIGINT is ignored, the first
press prints one plain line (`mandu demo: cleaning up …; ^C is ignored until
that is done. To end it now: kill <pid>`), and SIGTERM keeps its default
action. The guard is armed before the run-time handler comes off, so SIGINT
never has its default action in between; otherwise a ^C during cleanup
(including a second ^C during an abort's cleanup) would kill the demo inside
the synchronous sandbox removal and leave the sandbox behind.

**The services exit before the sandbox goes (2026-10-09).** Each service's
stop SIGTERMs its process group and waits for its process to exit
(`stopAndWait`; the group is SIGKILLed after 10 s), and the sandbox is
removed only after the last one. A service still shutting down writes into
the sandbox: the arbiter appends to its event log, whose directory it
re-creates when it is missing, and checkpoints its symbol DB. The stop used
to signal only, so on a loaded CI guest the arbiter's last events landed
after the removal and left the sandbox behind (the launcher's component
`demo.test.ts`, "the sandbox is removed on a failed run too"; traced on an
idle host, the arbiter appended events 15 ms before the removal began and
exited 25 ms after it ended, the first `rmdir` of the root failing with
`ENOTEMPTY`).

## 4. Offline and keyless: the stand-in model and the loopback transport

The model end is `stand-in-model.ts`, a capture server on `127.0.0.1`
answering `/v1/messages` (Anthropic) and `/v1/responses` (OpenAI); every
other path gets a 404. It records each forwarded body with its wire and plays
a fixed script: a request whose last turn is one of the demo's prompts gets
that scene's one tool call; a request whose last turn is a tool result gets
a short text reply. Scene 1's reply repeats the file as the request showed it
(placeholders and all, minus Mandu's `[mandu:…]` note), the only way a real
model can refer to a value it was shown as a placeholder. It never contacts
anything and never sees a key.

For the real proxies to reach it, each proxy's upstream fetcher allows plain
HTTP **only** to a literal loopback address (`127.0.0.0/8` or `::1`; the name
`localhost` is refused, since a hosts file can point it anywhere); `https:`
is TLS as in every real deployment, anything else is refused per request with
nothing sent (`upstreamTransport` in each proxy's `src/proxy.ts`, pinned by
each one's `test/unit/upstream-transport.test.ts`).

## 4a. Offline: the stand-in sites and the egress routes

`stand-in-sites.ts` starts three HTTPS/1.1 listeners on `127.0.0.1`, each
recording every request's head and body as received: `api.stripe.com` (it
answers like Stripe's list endpoint, an empty list), `paste.example`, and
"elsewhere". Their certificate (one leaf for both names) is signed by a
throwaway CA the demo mints with the `openssl` CLI (the commands adapted from
net-proxy `ca.ts`).

The net-proxy is started with a `hosts:` routes file
([`mock-sites.ts`](../../../interceptors/net-proxy/src/mock-sites.ts)): a
route per stand-in host and the catch-all `*` for every other host, all to
loopback (the parser refuses any other target). The gate runs first,
unchanged; a request it lets out is re-originated to the route instead of
the internet, over TLS the proxy still verifies, against the demo's CA, for
the host's own name. So the `api.stripe.com` listener holds exactly the bytes
a real Stripe would have received, and nothing the gate lets out can leave the
machine. curl itself never resolves a name: it talks only to the proxy
(`HTTPS_PROXY`, with `NO_PROXY` empty), and the routes dial literal
`127.0.0.1` addresses.

**Proof.** `launcher/test/component/demo.test.ts` runs the whole demo inside
a network namespace that holds only `lo` (`bwrap --unshare-net`, else
`unshare -rn`; skipped where unprivileged user namespaces are not allowed),
after checking that `/proc/net/dev` there lists `lo` alone; every check
passes. Within the run, the catch-all listener receiving anything fails the
demo ("a request reached a host outside the demo").

Scenes 2 and 3 need `curl` and `openssl`. Without either, they print
`skipped  this step needs curl, not found` (or openssl), the egress proxy is
not started, scene 1 still runs and checks, and the result line says that
steps 2 and 3 need them (exit 0).

## 5. Isolation (non-negotiable)

- **The user's HOME is never touched.** Every demo process runs under an env
  built from an allow-list of the caller's (PATH, locale, terminal, node
  options), never a copy of it: its own `HOME`, every `XDG_*` root, `TMPDIR`,
  its own `MANDU_HOME` (no `config.toml` in it), `MANDU_POLICY_FILE`,
  `MANDU_RUNTIME_DIR` and `MANDU_ARBITER_SOCK`. A running Mandu stack, an
  exported `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`, an OAuth token or the
  caller's `HTTPS_PROXY` cannot reach the demo's services or its curl.
- **The mode is pinned**, as a name and as the axis pair (`MANDU_MODE=secrets`,
  `MANDU_CONFIDENTIALITY=1`, `MANDU_INTEGRITY=0`), whatever the user's config
  says.
- **A fake, fresh key.** `sk_live_demo_fake_<16>`, a random suffix per run (a
  passing run cannot be canned), deliberately off the real token grammars
  (Stripe's `sk_live_` + 24 or more alphanumerics; the underscores break the
  run), so a published recording never trips a secret scanner.
- **Socket paths** stay under the 104-byte `sun_path` bound. The longest is
  the arbiter's human-plane socket, `<sandbox>/run/mandu/human/<instance
  id>.sock` (an instance id is at most 39 characters); `pickTempBase` budgets
  for it and falls back to `/tmp`. (Until 2026-10-05 it budgeted only for
  `run/a.sock`, and a `$TMPDIR` of about 40 characters or more made the
  arbiter refuse to start.)
- No npm update check (`NPM_CONFIG_UPDATE_NOTIFIER=false`) and no node compile
  cache (`NODE_DISABLE_COMPILE_CACHE=1`: it is flushed at exit and raced the
  sandbox removal).

## 6. The checks (what exit 0 means)

Per agent, per scene, from the real components' output:

| Scene | Check | Failure line |
|---|---|---|
| every | no form of the key (the value, or the Basic credential curl builds from it) in any request body the model received | the AI received the real key |
| 1 | the `.env` read reached the model with a `$MDU:` placeholder in it | the AI was not given a placeholder for the key |
| 1 | the reply filter's output holds the real key | your screen did not show the real key |
| 1 | a shell read the guard served (its status file) reached the AI per key, not as one whole-file placeholder | the AI got the whole file, not each key, under Mandu's guard |
| 2 | `api.stripe.com` received the request, every `Authorization` exactly `Basic base64(<key>:)` (as curl sends `-u "$KEY:"`), and no `$MDU:` anywhere in what it received | api.stripe.com received nothing / did not receive the real key exactly / received a placeholder |
| 3 | `paste.example` received nothing | paste.example received the request |
| 3 | a pending Approvals row for `paste.example` was raised or bumped in the arbiter (`egressApprovals`) | no approval was raised for you |
| run | the catch-all listener received nothing | a request reached a host outside the demo |

A step that cannot run at all (a service that does not start, a proxy that
answers non-200, a tool call the demo did not script) ends the run with
`✗ the demo could not run: …` and exit 1, after the same cleanup.

## 7. Tests

- `launcher/test/unit/demo.test.ts`: the sandbox env (every store and every
  file the demo writes inside the sandbox; nothing inherited that could leak,
  the caller's proxy and CA variables included; the mode pinned; the socket
  budget with the human-plane socket), the fixture (a fresh, off-grammar key;
  no long non-secret `.env` line; the policy binding; `‹hidden›`), both wires
  (Claude Code's Messages and Read/Bash, Codex's `additional_tools` / `exec`
  cell / output array; the stand-in's SSE parses back into the call), the
  stand-in model's script for both wires, the stand-in sites (routes all
  loopback; a real TLS request recorded, when openssl is there), the
  rendering (the exact plain layout and no internals in it, `--verbose`
  lines, a failed and a skipped step, the folded second agent, the result and
  pointer lines, NO_COLOR / TERM=dumb / a pipe), the options, and the
  orchestration over fakes: the services wired as a launch wires them, the
  agents' commands on the session's egress proxy, every command inside the
  guard as the agent's child (its wrap, policy file and session per agent),
  each no-guard reason (Linux only, not built, turned off, a kernel it
  cannot attach on) shown under the whole file with Codex unfolded, a guard
  that served the read but the AI got the whole file (exit 1), a guard that
  cannot set up (exit 1); the guard pieces alone (`findDemoGuard`,
  `wholeFileWhy` in plain words, `agentGuard` against the launch's
  `guardPolicyBase` and allow rules, `guardServed`, the stand-in runner run
  for real); `--agent`, `--verbose`,
  `--keep`, missing curl/openssl, failures to start, and one sabotage per
  check (a leaking proxy on each wire, a reply filter that does not restore,
  no release at the bound host, an unbound send that gets through, no
  approval), each exit 1 with its reason; the signals over a fake emitter.
- `launcher/test/component/demo.test.ts`: the real CLI, real services, a real
  curl, offline: from source (both agents, the default output: plain words,
  Codex folded, no color on a pipe; no time budget, since from source each
  service transpiles on start and the run's time follows the CI guest's
  load, a 53 s run on 2026-10-11) and from a freshly built bundle as
  `node dist/mandu.mjs --verbose`, under 30 s (the bound host received exactly
  `Basic base64(<key>:)` from each agent; the gate's refusal; one Approvals
  row asked twice). Both read every model request back from the kept sandbox
  (`run/model-requests.jsonl`) and assert no form of the key and no caller
  key in any, the right wire per agent, and the `.env` read as a minted
  placeholder (Claude Code's Read of the copy as keys with field
  placeholders; Codex's `cat .env` as keys with field placeholders and the
  `twin:` note where this host runs the guard, probed apart from the demo by
  attaching it once, else as one placeholder with the plain why line); the
  guard's status file per Codex step; nothing written to the caller's HOME and no demo process
  left (by its arbiter socket in `/proc/*/environ`). The sabotage runs use
  the real services with one dependency broken: the model proxy bypassed
  with no placeholder copy (each agent), a reply filter that prints the raw
  reply, a net-proxy without the human-plane socket, a policy that binds
  `paste.example` too, and (where the host runs the guard) a guard whose
  reports go to the data socket only (an explicit human socket that is the
  data socket): it still serves the tree, the arbiter takes its reports as
  claims, Codex's read stays whole, and the run fails on the new check, so
  the release rests on the guard's attested record and not on the text;
  each exits 1 naming the failed check. A run with `MANDU_NET_GUARD=0`
  passes with Codex's read whole, the why line, and Codex in full. The offline run
  (§4a) and the ^C run (a slow cleanup pressed with ^C every few ms until the
  sandbox is gone: exit 0 on its own, sandbox removed, no service left)
  complete it.

## 8. CLI surface

```
mandu demo [--agent claude|codex] [--verbose] [--keep]
  --agent    run one agent's steps (default: both)
  --verbose  also show what runs underneath: services, placeholders, requests
  --keep     keep the throwaway folder afterwards (the logs, every model
             request in run/model-requests.jsonl, the fake project and the
             agent's copy)
```

Dispatched as a reserved subcommand (bare form only), like `status`/`doctor`/
`why`: `mandu -- demo` still launches a program named "demo".

## 9. Deferred: the attack-contrast demo

A stronger demo: one canned injection attack (the eval corpus,
`eval/corpus/attacks/*.yaml`) run twice, without and with Mandu
(`injection`/`full` mode), ending at the trace in the dashboard, with a live
arm driving the user's own Claude Code. It is not built: an attack demo needs
a contained attacker sink, a clear "without Mandu" arm and trace
deep-linking, and it demonstrates the integrity axis, which the default mode
leaves off and which is frozen. If it is
built later, reuse the eval backends (`eval/lib/run-deterministic.ts`,
`run-live.ts`) and containment (`live-stack.ts`, `fake-upstreams.ts`) rather
than new attack logic, keep the stand-ins and sandbox from this build, and do
not import `eval/lib/oracle.ts` into the launcher at runtime (its js-yaml
import does not bundle).

## 10. Found while building it (2026-10-05)

- **A long comment line masks a `.env` Read whole** (§3): the value backstop
  treated every line of 24 or more characters of a registered file as a
  secret line, including a comment, and the placeholder copy carries the
  comment verbatim. Fail-closed, but the agent then saw one placeholder for
  the whole file instead of its keys. Fixed 2026-10-05
  (confidentiality-plan-10-flow-taint.md §11.8, "a twin line is no
  fingerprint"): a line the file's own placeholder copy carries, with no
  secret in it, is no fingerprint; the demo's `.env` has its comment back.
- **The human-plane socket and a long `$TMPDIR`** (§5): fixed in
  `pickTempBase`.
- **Codex's `cat .env` is masked whole without the guard** (§2): by design
  (the exec-output twin rule needs the guard's record of the process tree).
  The first build ran no guard, so Codex always showed the whole file; the
  agent's commands now run under the real guard where the host has it, and
  Codex shows the keys (§3 "The guard").
