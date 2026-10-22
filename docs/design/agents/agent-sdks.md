# Programs built on an agent SDK

Status: built 2026-10-05 for the TypeScript SDKs (the Claude Agent SDK and
the Codex SDK) and the Python Claude Agent SDK; 2026-10-17 closed the gaps
left after !698 (§3.1 to §3.4: the Python hook, the PATH shims, the CLI
known by its command line, the launch refusal) and turned the Python Codex
SDK from an unrouted warning into a refusal (§5); 2026-10-18 routed a
`claude` the session itself starts by name, under every claude or shell
launch (§3.5, a leak until then); the same day moved the route out of the
environment into a file the agent cannot write (§3.6: a route forged in
`MANDU_SDK_ROUTE` was applied, a leak until then). The user-facing form is
in [`usage.md`](../../usage.md), "Run a program built on an agent SDK".

Companies that put an agent inside their own product build on an agent SDK
rather than on the CLI: the Claude Agent SDK (npm
`@anthropic-ai/claude-agent-sdk`, PyPI `claude-agent-sdk`) or the Codex SDK
(npm `@openai/codex-sdk`, PyPI `openai-codex`). Each SDK starts the real CLI
underneath, so the CLI's routing could apply. This note records how the SDKs
start it (read from their published sources), what that breaks, and the
launcher's SDK route that closes it.

## 1. How the SDKs start the CLI (verified 2026-10-05)

Read from the packages themselves: `@anthropic-ai/claude-agent-sdk` 0.3.289
(bundling Claude Code 2.1.289), `@openai/codex-sdk` 0.160.0 (bundling
`@openai/codex` 0.160.0), `claude-agent-sdk` 0.2.163 and `openai-codex`
0.160.0 on PyPI.

| SDK | Child it starts | Binary | Environment | Where the model base URL comes from |
|---|---|---|---|---|
| Claude Agent SDK (TS) | `claude --output-format stream-json --input-format stream-json …` | the bundled native `claude` from `@anthropic-ai/claude-agent-sdk-<os>-<arch>[-musl]` (`pathToClaudeCodeExecutable` overrides) | `process.env`, or the `env` option, which REPLACES it (documented: "not merged"); `NODE_OPTIONS` is deleted | `ANTHROPIC_BASE_URL` in that environment |
| Codex SDK (TS) | `codex exec --experimental-json [--config k=v …] [resume <id>]` | the bundled native `codex` from `@openai/codex-<os>-<arch>` (`codexPathOverride` overrides) | `process.env`, or the `env` option, which REPLACES it | Codex's provider config only: `-c model_provider=…`; the SDK's `baseUrl` becomes `--config openai_base_url=…`, `apiKey` becomes `CODEX_API_KEY` |
| Claude Agent SDK (Python) | the same `claude` command line | the bundled `_bundled/claude` (`cli_path` overrides) | `os.environ` MERGED with the `env` option | `ANTHROPIC_BASE_URL` |
| Codex SDK (Python) | `codex [--config …] app-server --listen stdio://` | the bundled binary of `openai-codex-cli-bin` (`codex_bin` overrides) | `os.environ` merged with the `env` option | Codex's provider config only |

Codex reads no environment variable for its provider (no
`OPENAI_BASE_URL`; checked again on 0.160.0). `openai_base_url` re-points
only Codex's built-in `openai` provider: with `-c model_provider=mandu` in
force a request still goes to the Mandu provider's `base_url`, and without
it the request goes to `openai_base_url` (probed both ways on 0.160.0).

## 2. The supported shape

```sh
mandu --target claude -- node app.js     # an app on the Claude Agent SDK
mandu --target codex  -- node app.js     # an app on the Codex SDK
mandu --target claude -- python3 app.py  # an app on the Python Claude Agent SDK
```

`--target` is required: a language runtime is never inferred as an agent
(agent-e2e-harness.md §9.1), and the target decides which model proxy runs.
One launch serves one SDK's agent; a program that drives both Claude Code
and Codex needs two launches.

What applies to the host program and everything it starts, as for `mandu
claude` / `mandu codex`: the model proxy and its gates (keyed on the
target's tool names: claude-code or Codex), the session header
(`ANTHROPIC_CUSTOM_HEADERS` for Claude; the Codex proxy keys its session per
launch), the secret twins and masked environment variables, the egress
proxy and its TLS inspection, the net guard and Landlock, exec-wrap and the
exec box, and the reply filter on the host's own standard output.

What does not: the agent-binary checks that read argv[0] (the tested-version
check, the login check, the `--mcp-config` and Codex `-c` MCP splices, the
Claude sandbox settings overlay, Codex's `--no-daemon`). So the SDK's bundled
CLI version is not compared with the tested range (an unknown tool still
fails closed), and Mandu's MCP tools (`inspect_symbol`,
`declassify_symbol`, the policy tools) are not mounted in the SDK's agent.
The reply filter resolves placeholders only in what the host prints; a host
that serves its agent's answers over HTTP shows its users placeholders
(utility only: nothing leaks).

## 3. The SDK route

Two SDK behaviors would break that routing:

1. **The `env` option replaces the child's environment** (both TypeScript
   SDKs). An app that passes `env: { ANTHROPIC_API_KEY: … }` without
   spreading `process.env` drops `ANTHROPIC_BASE_URL`, the proxy and CA
   variables and `MANDU_*`: the CLI calls its vendor directly, past the model
   proxy, and a labelled file it reads reaches the model raw.
2. **Codex takes its provider only from its own command line**, which the
   Codex SDK builds. Nothing the launcher puts on the host's argv reaches it
   (before this change `mandu --target codex -- node app.js` spliced `-c` after
   `node`, which is node's own `--check`, so the launch did not start).

The launcher therefore loads a preload into the host's Node
(`launcher/src/sdk-route-preload.cjs`, `NODE_OPTIONS=--require=…`) with the
launch's route (`launcher/src/sdk-route.ts`, composed last in `run.ts` from
the whole env delta), which the preload reads from a file the agent cannot
write, beside the launch's own copy of it (§3.6). The preload hooks
`ChildProcess#spawn` (every asynchronous start: `spawn`, `execFile`, `exec`,
`fork`, ESM imports included) and the synchronous `spawnSync`,
`execFileSync` and `execSync`. For every child:

- the routing variables are put back with the launch's values (a host value
  for one of them, such as its own `ANTHROPIC_BASE_URL`, is overridden), the
  shim directories return to the head of `PATH`, and the preload stays in
  `NODE_OPTIONS`, so a Node grandchild is routed too. Only what the host
  process itself received is forced: the human-plane socket, which the
  reply filter keeps to itself, is never named in the route, and a masked
  secret variable keeps the host's own value;
- a `codex` child gets the provider splice at every command level, the
  placement `codex-argv.ts` `codexSpliceOverrides` uses, with `env_key` chosen
  by the key the child carries (`OPENAI_API_KEY`, else `CODEX_API_KEY`, else
  the sign-in provider), followed by Codex's own uploads off
  (`CODEX_UPLOADS_OFF`: analytics, feedback, OpenTelemetry export, ChatGPT
  apps, the update check; supported-agents.md §6.6). A Codex command line
  Mandu refuses as a launch (a re-pointed provider, `--oss`, a server
  subcommand, `--remote`, `cloud`, a `-c` or `--enable` that turns one of
  those uploads back on) throws instead of starting. A child already
  carrying the splice (the npm `codex` launcher passing its argv on) is left
  alone;
- a `claude` child gets the launch's routing in its last `--settings` as
  well (`claude-route.ts`, supported-agents.md §2.5): Claude Code applies
  every settings source's `env` over its environment, so the SDK's own
  `settings` option or a settings file its `settingSources` loads could
  re-point it. The routing is merged into the SDK's inline `--settings`
  (else added); a `settings` given as a file path, a cloud provider switch
  and `ANTHROPIC_UNIX_SOCKET` throw instead of starting;
- an agent child's routing is the LAUNCH's alone (2026-10-18): the route
  carries every routing variable with the launch's own value
  (`SdkRoute.launchRouting`: claude-route.ts `claudeRouteEnv` of the agent's
  whole environment, `""` where the launch sets none, the cloud switches
  off; run.ts refuses the launch if it differs from the agent's
  environment). A `claude` child's last `--settings` imposes exactly those
  values and its routing variables are put back to them, one the launch does
  not set removed; a `codex` child's proxy variables likewise (its provider
  and base URL are the `-c` splice, which the launcher computed). The child's
  own environment, which the host program chooses, is never read for them:
  a host that adds `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`, adds to
  `NO_PROXY`, or changes `ANTHROPIC_BASE_URL` / `CLAUDE_CODE_API_BASE_URL`
  is overwritten silently, as the `claude` shim does (§3.5,
  `routedClaudeArgs`, the one copy both apply). Overwriting, not refusing,
  as !1859 chose: an SDK `env` that spreads `process.env` and adds a
  corporate proxy is a benign, common shape, and the child then reaches
  nothing but the launch's route, so a refusal would only break such hosts
  without protecting more. A route that carries no launch values (hand-built
  or from another version) refuses every agent child;
- a `claude` child that runs a session gets `--permission-mode default`
  unless it chose a mode: the SDK's `permissionMode` (passed as
  `--permission-mode`), or `permissions.defaultMode` in its `settings` or in
  a settings scope it reads (`claude-permission-rule.cjs`, the one copy of
  the rule, which the launch applies too; supported-agents.md §2 "Claude
  Code's permission mode under Mandu"). Without feature flags,
  which the launch turns off, Claude Code would otherwise start in `auto`.
  The route carries which scopes set a mode for the launch's folder and user
  config dir (`SdkRoute.claudeMode`); a child started elsewhere is left
  alone;
- an agent CLI the launch does not route throws instead of starting: a
  `codex` under a claude or shell launch, a `claude` under a codex launch.

A throw from `spawn` is the fail-closed answer: the SDK reports the error to
the host and nothing reaches a model. If the preload file is missing, the
launch is refused.

**Which launches get the route** (`sdkRouteApplies`): a claude, codex or
shell launch whose argv[0] is a language runtime (`node`, `npx`, `tsx`,
`python3`, `uv`, `bun`, `deno`, …; `types.ts hostRuntimeOf`, which tells
Node, Python and the others apart), and a claude or codex launch whose
argv[0] is a wrapper (`./run-app.sh`, `env node app.js`), since the Node
program inside it is the same host. Never the agent binary itself (it keeps
its own routing; a Bun-built `claude` has no use for a Node preload), and
never a POSIX shell (the live oracles' stand-in for an agent). A language
runtime never receives Codex's `-c` splice (`codexOverridesReach`). The
launch prints `mandu: SDK route ACTIVE …` for a Node or Python host and a
wrapper; a Bun or Deno host under the claude or shell target prints what
is and is not routed, with `WARNING` (§3.4 has the codex target).

### 3.1 Which children are agent CLIs (2026-10-17)

The preload's `agentOf` decides, for every child, before anything else:

- **By name**: an executable called `claude` or `codex`, wherever it lives
  (`pathToClaudeCodeExecutable`, `codexPathOverride` included).
- **By the script a JS runtime runs**: `node`, `bun` or `deno` running a
  script named `claude` / `codex` (the npm `.bin` links, `bin/codex.js`),
  or a `cli.js` whose package is `@anthropic-ai/claude-code` or
  `@anthropic-ai/claude-agent-sdk` (by its `package.json`, else its path).
  This is the Claude Agent SDK's `executable` with a `.js`, `.mjs`, `.ts`
  or `.tsx` `pathToClaudeCodeExecutable`: `node [executableArgs] cli.js
  …`. The routing goes after the script; the runtime's own options are
  skipped by a table of the options that take a separate value
  (`RUNTIME_VALUE_FLAGS`). A missed entry makes a value look like the
  script, which is then no agent: the child falls to the next rule, never
  to an unrouted start of a known agent.
- **By the SDKs' own command line**: Claude Code's stream-json protocol
  both ways (`--output-format stream-json` and `--input-format
  stream-json`, which both Claude SDKs always pass and nothing else
  speaks) is a Claude Code under any name; `exec … --experimental-json`
  (the TypeScript Codex SDK) or `app-server` (the Python one) after any
  `-c` is a Codex under any name. So the SDKs' bundled or pointed-at CLI
  is routed even renamed.
- **Started through another program**: a child that is no agent itself but
  whose arguments name `claude` / `codex` followed by that SDK command line
  (`docker exec -i ctr claude --output-format stream-json …`, `ssh host
  codex exec --experimental-json`, `env claude …`): the CLI would run in a
  container, on another host or behind a wrapper Mandu does not read.
  Refused. This is the Claude Agent SDK's `spawnClaudeCodeProcess` when it
  starts a local program (§4). A Node child (its own preload decides its
  children), a Python child (its hook does) and a shell (the PATH shims
  meet what it names, §3.3) are not judged by this rule.

An agent environment variable is deliberately not a signal: the SDKs' own
markers (`CLAUDE_CODE_ENTRYPOINT=sdk-ts`, `CODEX_INTERNAL_ORIGINATOR_OVERRIDE`)
are inherited by every command the agent itself runs, so a `git` it starts
would be taken for the agent.

### 3.2 Python hosts: the Python hook (2026-10-17)

Python loads no Node preload, so before this a Python host's agent kept
only what the SDK passed through: the Python Claude Agent SDK merges its
`env` option over `os.environ`, so an `env={"ANTHROPIC_BASE_URL": …}` sent
Claude Code's turns, a labelled file it read among them, straight to the
vendor, and a settings source could re-point it as well. **This was a
leak**, not a utility gap: a model call and a secret reached the network
unrouted.

The launcher now puts its own copy of `sdk-route-python/sitecustomize.py`
(a bundle asset), `<scope run dir>/sdk-route/python/`, first on PYTHONPATH
(the folder holds nothing else), so every Python in the tree imports its
`sitecustomize` at startup; the copy reads the route from the folder above
it (§3.6). It hooks `subprocess.Popen._execute_child`, the one place every
Python start goes through (`subprocess.*`, and the `asyncio` and `anyio`
subprocesses both SDKs use):

- every child gets the route's environment back (`route_env`, the
  preload's `routeEnv` mirrored; a parity test holds them equal), with the
  Python hook first on PYTHONPATH and the Node preload in NODE_OPTIONS, so
  a Node grandchild and a Python grandchild are routed too (the Node
  preload keeps PYTHONPATH the same way: `SdkRoute.pythonPath`);
- a child that may be an agent (by name, a JS runtime, or arguments
  naming one or carrying an SDK command line) is decided by the preload
  itself: the hook runs `node sdk-route-preload.cjs --decide` (the
  launch's copy, which reads the same route file) with the launcher's own
  Node (`SdkRoute.node`) and takes its answer, so there is one copy of the
  decision. A refusal, or any failure to decide, raises
  `ManduRouteRefused` (a `PermissionError`) and the child never starts:
  fail-closed;
- a `sitecustomize` the Python already had (a distribution's, a virtual
  environment's) is loaded after it.

Not covered by the hook: `os.posix_spawn`, `os.exec*`, `os.spawn*` and
`pty.spawn` called directly (neither SDK does; an agent CLI such a start
finds by name still meets the PATH shims), and a Python started with `-I`,
`-E` or `-S`, which does not import `sitecustomize` (§3.4).

### 3.3 The PATH shims (2026-10-17)

A child started through a shell command string (`exec("codex …")`,
`shell: true`, Python's `shell=True`) is a shell: its environment was
restored but its argv never read, so a `codex` it named ran with no Mandu
provider (and a `claude` without the `--settings` overlay). The launch now
writes `<scope run dir>/sdk-shims/claude` and `…/codex` (`writeSdkShims`;
the folder is write-protected for the agent, §3.6), puts that folder first
on the host's PATH, and the route puts it first on every child's PATH
(`SdkRoute.pathPrefix[0]`). Each shim is a two-line `sh` script that runs
the launch's copy of the preload (named by full path in the shim) with its
`--exec` entry and the launcher's Node: it finds the real CLI
further down PATH (past the shim folder), routes or refuses it as
`routeSpawn` would, and `execve`s it in place (`process.execve`, Node ≥
22.15; older Node runs it as a child, passing signals on and its exit
status back). The route is the file beside that copy (§3.6); a shim that
finds none there refuses (it would run unrouted), and a route in its
environment is never read. Applying the route twice is a no-op (a routed `codex`
is left alone, the `--settings` merge and the permission mode are
idempotent), so a child the preload already routed by name and that PATH
then resolves to the shim is unchanged.

A shim needs no `node` on PATH: it runs the launcher's Node by absolute path,
and the whole-agent Landlock wrap leaves the real filesystem readable and
executable (fs-supervisor `ACCESS_FS_RO`), so the shim and that Node run
under it. One place the shims are not seen: inside the command box
(exec-box), when the scope run dir lies under `/tmp` (no
`XDG_RUNTIME_DIR`) and the integrity axis is on, since that box mounts a
fresh `/tmp` (with it off the box shows the agent's own `/tmp`,
exec-routing.md §7.2); a shell there
skips the missing PATH entry and finds the real CLI, which runs with the
box's network off, so no model traffic leaves.

The shims also cover a Bun or Deno host's start by name (`spawn("codex")`),
a Python start the hook does not see, and a wrapper script's `codex`.
They do not cover a shell string that gives the CLI's full path
(`exec("/opt/x/codex …")`): §4.

The shims above exist only for a launch the route serves; every other
claude or shell launch gets a `claude` shim of its own (§3.5).

### 3.4 Hosts the route cannot reach (2026-10-17)

Bun and Deno read neither NODE_OPTIONS nor PYTHONPATH; a Python started
with `-I`, `-E` or `-S` skips `sitecustomize`. Under `--target codex` such
a host's codex would certainly run with no Mandu provider (Codex takes its
provider only from its argv), so the launch is refused at parse
(`sdkHostRefusal`; the `-I` / `-E` / `-S` read covers clusters such as
`-IB` and stops at the script, `-c` or `-m`). Under `--target claude` the
environment still routes the SDK's default start (the variables are
inherited, and an `ANTHROPIC_API_KEY` the launch masks is a placeholder
only the proxy puts back, agent-sign-in.md §3.8), and the PATH shims meet a
start by name, so the launch runs and the note says, with `WARNING`, that a
`claude` given its own `env` or settings, or any `codex`, started by its
full path is not routed (since 2026-10-18 such a CLI's model calls are
refused at the transport: §4, "The model-host deny"). Whether to refuse
these hosts under claude too is the maintainer's call (§4).

The preload is plain CommonJS with no dependency, shipped as a bundle asset
(`bundle-manifest.json` `assets`, `Layout.asset`). Its Codex argv logic
mirrors `codex-argv.ts`; a parity unit test holds the splice, the
uploads-off list and the refusal equal over a corpus, including attached short settings (`-ckey=value` and
`-c=key=value`). Provider overrides in those spellings are refused before
either an asynchronous or synchronous SDK child starts.

### 3.5 The `claude` shim of every other claude or shell launch (2026-10-18)

A claude or shell launch the route does not serve (`mandu claude`, `mandu
-- bash`) gets one shim of its own in the same folder, `sdk-shims/claude`,
first on the agent's PATH, written when a real `claude` is on PATH
(`writeClaudeShim`; a missing preload or permission-mode rule then refuses
the launch). It runs the preload's `--claude` entry, which routes a
`claude` the session starts by name (from that shell, a script, a git hook,
the agent's own Bash tool) exactly as the launch routes `mandu claude`
(`claudeShimSpawn`, over `routedClaudeArgs`, the one copy the SDK route's
`routeClaude` applies too, both with the launch's values: the shim's baked
into it, the SDK route's in `SdkRoute.launchRouting`, §3), then `execve`s
the real `claude`:

- the launch's routing overlay (claude-route.ts `claudeRouteEnv` of the
  agent's environment: the base URL at the model proxy, the session header,
  the egress proxy variables, `NO_PROXY`, `""` where the launch sets none,
  the cloud switches off) is baked into the shim (its folder, `sdk-shims/`,
  is write-protected for the agent, §3.6; the launch checks the baked values equal
  the agent's environment and refuses otherwise), put back in the child's
  environment (a routing variable the launch does not set is removed), and
  imposed in its last `--settings`, merged into its own inline one;
- a `--settings` FILE, a cloud provider switch or `ANTHROPIC_UNIX_SOCKET`
  in its environment refuses the start (exit 126, nothing sent);
- the permission-mode rule (supported-agents.md §2).

**Why (2026-10-18, a leak until then).** Until !1850 the session's own
`claude` got no shim at all, and the first form of this shim applied only
the permission mode. Claude Code applies the `env` block of every settings
source over its environment (2.1.302, read in the bundle:
`applyConfigEnvironmentVariables` assigns the global config's, then the
user, project and local settings', then the last `--settings`' `env` to
`process.env`, and the API client reads `process.env.ANTHROPIC_BASE_URL`;
project settings may set it, only a short list of host keys is
project-blocked). So a nested `claude` whose user `settings.json` names a
gateway (a common setup), whose project gets a `.claude/settings.local.json`
the agent writes, or which the agent starts as `ANTHROPIC_BASE_URL=… claude`,
sent its requests, with the tool results it read, straight to that
endpoint. Nothing outer stopped it: the connect guard admits the model host
on :443 for the whole agent tree (and every :443 in the default posture),
the egress proxy passes a model host through as a blind tunnel judged only
by the sender's taint, and a nested `claude` holds no secret by that
measure (it reads the placeholder files). What leaked depends on the
posture: everything the model proxy alone masks (in `confined`, a
registered value copied into an unlabelled file, the value-only release of
guarantees.md §2; in `gated`, every file it reads raw). Measured with the
real Claude Code 2.1.302 against a scripted model (`claude-settings-route.test.ts`, §6):
the registered value reached the model raw before, as a symbol after.

**Started by its full path.** A `claude` started by its full path
(`~/.local/share/claude/versions/…/claude -p …`), or with a PATH that skips
the shim, keeps only its environment's routing, which the caller can
change (`env -u ANTHROPIC_BASE_URL /path/to/claude`, or a settings file).
Until 2026-10-18 it then reached the model directly (a leak). Since then the
transport refuses it: the model-host deny (§4, "The model-host deny")
answers its `/v1/messages` with a 403 from the egress proxy, and its direct
dial of the model host is refused by the connect guard. It still starts,
signs in and fails at its first model call; only a `claude` that reaches
the model through Mandu's model proxy can work.

`mandu claude` starts the real `claude` by path, past the shim (the launch
applies the overlay and the rule to its own command line).

**The quarantined `claude -p` (2026-10-19).** inspect_symbol's U-LLM is a
`claude` the session starts too: the inspect server, which runs in the
agent's world, spawns it. It must keep its own channel, the U-LLM
forwarder (never the model proxy: the instrumented T-LLM path), so the
launch resolves the CLI past `sdk-shims/` before the services start
(`realExecutable`, run.ts; `Ullm.binaryPath`) and writes the path into the
inspect server's entry as `MANDU_ULLM_BINARY_PATH`; the server spawns that
path, never the bare name (a malformed value refuses the quarantine,
fail-closed). Until then the shim caught it by name and re-pointed it at the
model proxy, whose port the inspect server's network confine
(inspect-net-confine.ts) refuses, so on Linux every quarantined call hung
to its 60 s timeout: the 2026-10-18 nightly's 23 of 23 in the CI guest, and
its agents declassified the any-model files instead. Without that confine
(macOS, a kernel without Landlock TCP rules) the call would have gone
through the model proxy. `tests/stack/inspect-ullm-shim.test.ts` holds it
under a real `mandu claude` (red before: the U-LLM's base URL was the
proxy's and the shim's `--settings` reached it).

### 3.6 Where the route lives: a file the agent cannot write (2026-10-18)

Until this change the route rode the environment variable
`MANDU_SDK_ROUTE`: the launch set it on the host, a hooked parent put it back
on every child, and the PATH shims, the preload and the Python hook read it
from their own environment. A shell does not put it back, so a host the
model steers could forge it in a shell string, `MANDU_SDK_ROUTE='{…}' claude
-p …` (the `claude` PATH shim), or start a Node or Python that way
(`MANDU_SDK_ROUTE='{…}' node host.js`, whose preload then routes every
child by it), and the forged route's `launchRouting`, `env` and Codex
provider were applied as given: a model base URL or a proxy of the host's
choosing, the request with the tool results it carried sent there. **This
was a leak** (measured with the stand-in `claude` of
`nested-claude-route.test.ts`, §6: both requests reached the capture server
the forged route named).

Now the route never travels in the environment:

- the launch writes `<scope run dir>/sdk-route/` afresh (`writeSdkRouteDir`):
  the route as `route.json`, beside copies of the preload, its
  permission-mode rule (which it requires from beside itself) and the
  Python hook (`python/sitecustomize.py`), copied from the bundle;
  `SdkRoute.require` and `SdkRoute.pythonPath` name these copies, so
  NODE_OPTIONS and PYTHONPATH load them;
- each copy reads the route from beside itself (the preload from its
  `__dirname`, the Python hook from the folder above its `__file__`), a
  path nothing in the environment can redirect; the PATH shims name the
  preload copy by full path, baked in at launch, as the §3.5 `claude` shim
  bakes its routing;
- both folders, `sdk-route/` and `sdk-shims/`, are on the write-protect list
  as Mandu's own files (`sdkRouteWriteProtect`; write-protection.md §2): the
  whole-agent guard refuses every write, rename and removal there on Linux,
  and the macOS profile carries the same entries. Before this the §3.3 and
  §3.5 shims were said to be write-protected with the scope run dir, which
  no entry covered; the agent could replace them;
- `MANDU_SDK_ROUTE` is ignored everywhere and removed from every child the
  hooks route (a stale or forged value goes no further). Ignored rather than
  compared with the file: no Mandu component sets it any more, so any value
  is the host's own;
- fail-closed: a launch's copy whose route file is missing or unreadable
  refuses every agent child (the preload: a `ManduRouteRefused` throw from
  `spawn`; the Python hook: every child that may be an agent; the shim and
  `--decide`: a refusal) and starts any other child unchanged. The bundle's
  own preload, with no route beside it, routes nothing as a preload (it
  still serves the §3.5 `claude` shim's `--claude` entry, whose route is
  baked into that shim). The Python hook's `--decide` request carries only
  the Python process's own values of the route's variables, which narrow
  the route as `effectiveRoute` does for a Node host; an agent child's
  routing stays the file's `launchRouting`.

A host that loads a preload of its own (its own file in NODE_OPTIONS, a
copy it wrote with a route beside it) is running its own code, not Mandu's
hook: the full-path class of §4, closed only at the transport.

**Where nothing holds the folder.** The write-protect list needs the
whole-agent guard (Linux) or the Seatbelt profile (macOS): in the `gated`
posture (no guard, or `--no-net-guard`), on a Mac without `sandbox-exec`,
with `MANDU_WRITE_PROTECT=0`, and in `off` mode, the two folders are as
writable as the rest of the scope run dir, so the agent can rewrite
`route.json` or a shim and the next agent CLI started through them takes
its route. That adds nothing to what such a launch already leaves open: an
agent CLI started by its full path with an environment of the agent's
choosing (§3.5 "Not covered", §4). The environment variable, the cheap
form any shell string could use, is closed in every posture.

## 4. Bypasses examined

| Way around the proxy | Closed? |
|---|---|
| TS SDK `env` option replacing the child's environment | Closed: the routing variables are forced back on every child. |
| A host `ANTHROPIC_BASE_URL` pointing the Claude child at the vendor | Closed: the launch's value wins. |
| A host that hands its agent child a routing variable the launch does not set (`HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` in front of the model proxy, a `NO_PROXY` addition, `CLAUDE_CODE_API_BASE_URL`) | Closed (2026-10-18): an agent child's routing is the launch's values alone (`SdkRoute.launchRouting`, §3); the host's is overwritten in the child's environment and the `claude` overlay. Was a leak: the preload built a `claude` child's `--settings` overlay from the child's own environment, so a proxy the host added there (where the launch set none, as under `--no-net-proxy`, or one the launch does not set at all, such as `ALL_PROXY`, the lower-case spellings or `CLAUDE_CODE_API_BASE_URL`) was pinned into the last settings layer, where it wins, and the request with the tool results it carried went through that proxy before the model proxy masked them; a `codex` child kept such a proxy in its environment. Measured with a stand-in `claude` that honours the proxy variables (`nested-claude-route.test.ts`, §6). |
| Codex SDK not routed at all (no `-c` reaches the child; `node -c` broke the launch) | Closed: the preload splices the provider into the child's own argv. |
| Codex SDK `baseUrl` (`openai_base_url`) | Inert under the Mandu provider (probed); without the route it re-pointed the built-in provider. |
| Codex SDK `config` re-pointing `model_provider` / `model_providers.*`, `--oss` | Refused: the start throws. |
| `codexPathOverride` / `pathToClaudeCodeExecutable` | Covered: the check is the executable's name (`codex`, `claude`), wherever it lives. |
| A Codex SDK `apiKey` | Relayed as `CODEX_API_KEY` through the Mandu provider (`env_key`), never sent around the proxy. |
| A codex started from a shell command string (`exec("codex …")`, `shell: true`) | Closed (2026-10-17) for a CLI the string names by name: the PATH shims route or refuse it (§3.3). Was a leak: the codex ran with no Mandu provider. Open: a string that gives the CLI's full path (`exec("/opt/x/codex …")`); its environment is restored, its argv is not read. Since 2026-10-18 it reaches no model on its own: the model-host deny refuses its model calls at the transport (below, "The model-host deny"). |
| `claude` run as `node cli.js` (`executable` + a `.js` path) | Closed (2026-10-17): known by its script (§3.1), routed after it (`--settings`, permission mode). Before, only its environment was restored, so a settings source could re-point it. |
| A CLI under another name | Closed (2026-10-17) for one the SDKs start: known by the SDKs' command line (§3.1). Open: a renamed CLI started with any other command line (`my-claude -p hi`): its environment is restored, so a Claude Code stays routed unless a settings source re-points it, and a renamed codex is not routed. Recognising it by its content was rejected (reading every child's executable on every start, and spoofable). Since 2026-10-18 it reaches no model on its own: the model-host deny refuses its model calls at the transport (below, "The model-host deny"). |
| Claude Agent SDK `spawnClaudeCodeProcess` | Closed (2026-10-17) when it starts a local program: a local `claude` is routed as any child; a CLI it starts through another program (`docker exec`, `ssh`, `env`) is refused (§3.1). Open by construction: a spawner that starts no program here (a VM or container API reached over the network) runs the CLI outside the launch, on files that are not this machine's; the host's own traffic to that service is judged by the egress proxy like any other. |
| A settings overlay carrying `env.ANTHROPIC_BASE_URL` (the SDK's `settings` / `extraArgs`, or a settings file the SDK's `settingSources` loads) | Closed (2026-10-07): the preload puts the launch's routing in the child's last `--settings`, merged into the SDK's own inline one, so no settings source re-points it; a `settings` given as a file path, a cloud provider switch and `ANTHROPIC_UNIX_SOCKET` refuse the start. `mandu claude` gets the same (supported-agents.md §2.5). |
| A `claude` the session itself starts by name (`mandu -- bash`'s shell, a script, the agent's Bash under `mandu claude`) whose settings file, or command-line environment, re-points `ANTHROPIC_BASE_URL` | Closed (2026-10-18): the session's `claude` shim routes it as `mandu claude` is routed (§3.5). Was a leak: it went to that endpoint with what it read. One started by its full path or past the shim keeps its own routing, and since 2026-10-18 its model calls are refused at the transport (below, "The model-host deny"; live: the real 2.1.302 by full path with `ANTHROPIC_BASE_URL` removed got the 403). |
| Python Claude Agent SDK `env` option with its own `ANTHROPIC_BASE_URL` | Closed (2026-10-17): the Python hook puts the launch's routing back and the `--settings` overlay on (§3.2). Was a leak. |
| Python Codex SDK (`codex app-server` with no Mandu provider) | Fail-closed (2026-10-17): the start is refused (§5). Was a leak behind a `WARNING`. |
| Bun or Deno running the host | Under `--target codex`: the launch is refused (§3.4). Under `--target claude` or `shell`: the environment routes the SDK's default start, the PATH shims meet a start by name; a full-path `claude` given its own `env` or settings is not routed (the launch says so with `WARNING`), and since 2026-10-18 its model calls are refused at the transport (below). |
| Python with `-I`, `-E` or `-S` | Under `--target codex`: refused (§3.4). Elsewhere: as Bun (the hook is skipped). |
| A route forged in an environment that crosses a program neither hook sees (a shell string `MANDU_SDK_ROUTE='{…}' claude …`, or a Node or Python started that way) | Closed (2026-10-18): the shims and the hooks read the route from the launch's own file beside the preload and Python hook copies, which the agent cannot write, never from `MANDU_SDK_ROUTE`, which is ignored and removed from every child (§3.6). Was a leak: the forged route (its `env`, `launchRouting` or Codex provider) was applied as given, and the request went to the base URL or proxy it named (`nested-claude-route.test.ts`, §6). Open where nothing write-protects the route's folder (`gated`, `--no-net-guard`, a Mac without `sandbox-exec`, `MANDU_WRITE_PROTECT=0`): the agent can rewrite the file, no more than the full-path rows above already allow there (where the model-host deny holds there, below, a CLI so re-pointed at the vendor is refused like a full-path one). |

**The model-host deny (2026-10-18, the maintainer's decision).** The open
rows share one cause: a CLI the route cannot see by name or command line,
started by a program that loads neither hook. Each still reaches its vendor
only over a model host, so the transport closes them: whenever the
confidentiality axis is on and the egress proxy runs, every program in the
agent's tree may call a model vendor's host only for the account, sign-in
and gated upload calls listed for it; anything else there is refused before
any byte is sent (an ALLOW-list, fail-closed: a new endpoint breaks a
feature, it never leaks). Mandu's own model proxies run outside the tree
and dial the vendor themselves, and the agent's routed model calls go to
them by base URL (loopback, in `NO_PROXY`), so neither is touched.

Until this change the launch sent the model hosts around the egress proxy
(`NO_PROXY`, `sessionNoProxy`), the connect guard admitted the target's
API host on :443 for the whole tree (net-guard.ts), and the egress proxy
passed a model host through as a blind tunnel. A `claude` started by its
full path with `ANTHROPIC_BASE_URL` removed therefore sent its requests,
with what it had read, straight to `api.anthropic.com` (a leak:
`tests/stack/model-host-deny.test.ts` received the model call, the secret
in it in clear, on the old code).

What the launch does now (`launcher/src/model-host-deny.ts`):

- the egress proxy gets `MANDU_NET_PROXY_MODEL_HOST_DENY=1`
  (services/net-proxy.ts; part of its reuse key, published in its
  identity), and judges a model host by the request's path
  (`interceptors/net-proxy/src/model-host-paths.ts`): on the TLS-inspected
  leg, where a model host is now terminated like any other host, and on
  the plain leg. The path is the one the client sent, before any
  normalization; a dot segment, an escape (`%`), a `;`, a `\`, a fragment
  (`#`) or an empty segment is refused whatever the list says (so is a
  placeholder, whose brackets no allowed path holds, so no value put back
  can turn a path into another; the path actually sent is judged again
  all the same). An allowed request then runs the inspected leg's whole
  gate (the per-symbol gate, the verbatim tripwire, the sender's taint), as
  any other host's;
- the model hosts leave the tree's `NO_PROXY` (and the inspect server's),
  so a client that honours the proxy variables reaches them only there;
- the connect guard drops its `tcp:<api host>:443` allowance and denies
  every model host on every port (`--deny`, checked before any allow), so a
  client that dials one around the egress proxy is refused at connect;
- the U-LLM forwarder starts in every posture (the quarantined U-LLM
  reaches its vendor through the launcher, outside the tree).

**The hosts.** `api.anthropic.com` and `api.openai.com` (and the hosts
under them), `platform.claude.com` (it answers the Messages API: an
unauthenticated `POST /v1/messages` there returns the API's own
`authentication_error`, probed 2026-10-18) and `chatgpt.com` (the ChatGPT
backend serves Codex's model turns). Not `claude.ai`: it shares
`api.anthropic.com`'s address but answered the same probe with its web
challenge, and Claude Code calls nothing there directly (2.1.302: every
`CLAUDE_AI_ORIGIN` use is a link shown to the user). Not `auth.openai.com`
(Codex's sign-in refresh, no model). Not a host the user adds with
`MANDU_MODEL_HOSTS` (their own model servers keep the blind tunnel). Another
vendor's model endpoint is a destination like any other: the egress gate
and the tripwire judge it.

**The allow-list, with its evidence** (each entry names its source in
`MODEL_HOST_RULES`):

| Host | Allowed paths | Read from |
|---|---|---|
| `api.anthropic.com` | `/api/hello`; `/api/oauth/{profile,validate,usage,account/settings,account/grove_notice_viewed,claude_cli/roles,claude_cli/create_api_key}`; `/api/claude_cli_profile`, `/api/claude_cli/bootstrap`; `/api/claude_code/{settings,policy_limits,organizations/metrics_enabled}`, `/api/claude_code_grove`, `/api/claude_code_penguin_mode`, `/api/organization/claude_code_first_token_date`; `/api/model_selector/*`, `/api/organizations/*/model_selector/*`; the feature flags `/api/eval/*`, `/api/eval-authed/*`, `/api/features/*`; WebFetch's `/api/web/domain_info`; the connectors list `/v1/mcp_servers`; the gated uploads `/v1/design/mcp`, `/api/artifacts/mcp` (and its `upload/**`), the Artifact pages service's `/api/frame/<family>` families | Claude Code 2.1.302, strings of the binary (`BASE_API_URL` is `https://api.anthropic.com`); `/v1/mcp_servers` seen live |
| `platform.claude.com` | `/v1/oauth/token` (the sign-in's exchange and refresh, `TOKEN_URL`), `/docs/**`, `/llms.txt` | Claude Code 2.1.302 |
| `api.openai.com` | none: every URL Codex 0.162.0 names there is the provider's base, which Mandu routes to the openai-proxy | codex-cli 0.162.0, strings of the binary |
| `chatgpt.com` | `/backend-api/wham/{usage,accounts/check,settings/user,config/bundle}`, `/backend-api/ps/plugins/**`, `/backend-api/plugins/{featured,export/curated}` | the ChatGPT-backend calls recorded in full at a stub (agent-sign-in.md §2.8 item 4) and reviewed in supported-agents.md §6.6, checked against codex-cli 0.162.0 |

Refused, among others: every Messages, Complete, count-tokens, batches,
Files and models path; the remote sessions, environments and agents
(`/v1/code/**`, `/v1/sessions/**`, `/v1/environments/**`, `/v1/agents/**`,
`/v1/session_ingress/**`: a model runs there on what is sent); voice
(`/api/ws/speech_to_text/…`); Claude Code's telemetry, feedback and shared
transcripts (`/api/event_logging/**`, `/api/claude_code/metrics`,
`/api/claude_cli_feedback`, `/api/claude_code_shared_session_transcripts`;
the launch turns nonessential traffic off anyway); Codex's model turns
(`/backend-api/codex/responses`), cloud tasks (`/backend-api/wham/tasks`),
apps MCP (`/backend-api/ps/mcp`, off under Mandu), analytics (off under
Mandu) and every ChatGPT web path.

**The live run (2026-10-18).** `mandu claude -p` on the subscription
(OAuth, no API key), model haiku, one prompt and one Bash call that ran the
real 2.1.302 binary by its full path with `ANTHROPIC_BASE_URL` removed: the
session answered and its tool call ran; the nested `claude` got `API Error:
403 POST /v1/messages on model host api.anthropic.com is refused`; two
model requests in all, both through the model proxy. Every call the two
Claude Codes made to a model host was in the egress proxy's log:
`GET /v1/mcp_servers` twice (allowed) and the nested `POST /v1/messages`
(refused); nothing needed was refused. A `mandu --target shell` run with
the proxy variables unset showed the guard refusing a direct connect to
`api.anthropic.com` and `chatgpt.com`. Not seen live: the interactive TUI's
start, the sign-in refresh (the token was fresh) and Codex (no live Codex
run); their entries rest on the binaries and the recorded calls above.

**Where it holds (the posture matrix).** "Through the proxy" is a program
that honours `HTTPS_PROXY` (Claude Code, Codex, curl, Node with
`NODE_USE_ENV_PROXY`); "direct" one that unsets or ignores it.

| Posture | Through the proxy | Direct |
|---|---|---|
| Linux, confidentiality on, TLS inspection on, connect guard on (the default `secrets` launch) | each request judged by path; model calls 403 | refused at connect (guard `--deny`) |
| TLS inspection off (`--no-net-proxy-mitm`, or no session CA could be minted) | a model host is refused whole at the CONNECT (no path can be read, fail-closed); the agent's own calls there fail too (account, usage, and the sign-in refresh, so a long session ends when its token expires); the launch says so | refused at connect |
| No connect guard (`--no-net-guard`, `MANDU_NET_GUARD=0`, `--no-kernel`, no guard bin, seccomp unavailable) | judged by path | **open**: the port-only Landlock wrap admits any `:443` in its non-strict default (`--landlock-net-strict` denies 443 wholesale and closes it) |
| macOS (the Seatbelt profile confines TCP by port) | judged by path | **open** in the non-strict default, as above |
| `--no-net-proxy` (the egress gate turned off) | no deny: the model hosts stay in `NO_PROXY` and the guard admits the API host, as before | as before (open) |
| `off` mode (confidentiality off) | no deny, as before | as before |

The shared addresses: the guard denies by resolved address, and
`api.anthropic.com`, `platform.claude.com` and `claude.ai` answer on one
address, `chatgpt.com` and `api.openai.com` on Cloudflare's. A direct dial
to another site on one of those addresses is refused too; through the
egress proxy (which the guard sees only as its loopback port) nothing else
changes.

## 5. Not supported yet

- **The Python Codex SDK.** Until 2026-10-17 its `codex app-server` ran
  with no Mandu provider behind a launch `WARNING`: a leak, since its turns,
  with tool results unmasked, went to the vendor. The Python hook (§3.2) now
  sees the start, and the preload refuses it with its own reason
  (`stdioAppServer`): fail-closed, the SDK raises and nothing reaches a
  model. A listening `app-server` keeps the server refusal `mandu codex`
  gives (codex-argv.ts). The provider splice alone would not make it
  routable: `app-server` takes a thread's `config` overrides and model
  provider over its JSON-RPC protocol (`thread/start`, `newConversation`),
  which no argv carries, so a client could re-point a thread past the
  `-c` the splice puts on its command line. Supporting it needs either a
  relay that reads that stdio protocol and refuses a provider or upload
  override (as codexRefusal does for argv), or a probe showing the
  protocol cannot override a `-c model_provider`; both need runs against
  `app-server` itself (a scripted model is enough, no live one).
- **Mandu's MCP tools in an SDK's agent.** An app can mount them through
  the SDK's own MCP options; the launcher does not.

## 6. Tests

- `launcher/test/unit/sdk-route.test.ts`: which launches get the route, the
  composed route (never the human-plane socket, never a masked variable),
  `routeSpawn` (env restored and overridden, the Codex splice per auth,
  refusals, the unrouted agent), and the parity of the preload's Codex argv
  logic with `codex-argv.ts` and of its Claude settings overlay with
  `claude-route.ts`.
  Since 2026-10-17 also: `agentOf` and `scriptIndex` (by name, by script,
  by the SDKs' command line, wrapped), `routeSpawn` on `node cli.js`, a
  renamed CLI and a stdio `app-server`, the route's deliveries
  (`pathPrefix`, `pythonPath`, `node`, `sdkRouteEnv`), the shim script,
  `sdkHostRefusal` / `pythonSkipsSiteHook`, and the notes.
  Since 2026-10-18 also: `launchRouting` (claudeRouteEnv of the inherited
  environment under the delta, kept by `effectiveRoute`), a `claude`
  child whose environment adds `HTTPS_PROXY` / `ALL_PROXY` / lower-case
  proxies, changes `ANTHROPIC_BASE_URL` or widens `NO_PROXY` getting the
  launch's values in its environment and exactly them in its overlay (with
  and without an egress proxy, with and without the SDK's own inline
  settings), a `codex` child's proxy variables put back, and a route
  without launch values refusing every agent child. Red before (the host's
  values were in the overlay).
- `launcher/test/component/sdk-route.test.ts`: the hooks in a real Node with
  stand-in CLIs (ESM `spawn`, `execFileSync`, `spawnSync`, a shell string),
  and `mandu --target codex|claude -- node host.mjs` through `main()`.
- `launcher/test/component/sdk-route-gaps.test.ts` (2026-10-17): the PATH
  shims (a shell string's `codex` routed under a codex route, refused under
  a claude one, a shim with no route refused, a `claude` by name over a
  host base URL), `node cli.js`, a renamed CLI and a `docker exec`-wrapped
  one in a real Node, the Python hook in a real `python3` (an `env`
  override of `ANTHROPIC_BASE_URL`, `asyncio`, `codex app-server` and
  `codex exec`, a shell string, a plain child), the parity of its
  `route_env` with `routeEnv`, and through `main()`: `--target claude --
  python3`, `--target codex -- python3` with `app-server` (refused, never
  ran), `--target codex -- node` with a shell-string codex (spliced by the
  shim), `--target codex --no-net-proxy -- node` whose host hands its codex
  its own proxies (removed; red before, 2026-10-18), and `--target codex --
  bun` (refused at parse). The Python legs self-skip without `python3` ≥
  3.8.
- The route's source (2026-10-18, §3.6): the unit `sdk-route` holds the
  route folder's paths and its write-protect entries, `writeSdkRouteDir`
  refusing a route that names hooks outside its folder, `sdkRouteEnv`
  without the route, `routeEnv` removing a route from the child's
  environment, and `routeSpawn` with no route refusing an agent child and
  starting any other. The component `sdk-route-gaps` stages the folder as a
  launch does (`test/lib/sdk-route-stage.ts`) for every hook leg, and adds:
  a route forged in `MANDU_SDK_ROUTE` for a shell string's `claude` (the
  PATH shim) and for a Node started that way, every routing value at
  another port, ignored (the launch's base URL, overlay and proxy reach the
  claude); the same for a Python host; a shim, a Node host and a Python
  hook whose route file is gone refusing the agent child, a forged route
  notwithstanding. Red before (the forged base URL reached the claude).
  `tests/stack/nested-claude-route.test.ts` adds the forging SDK host
  through the real launcher, model proxy and arbiter: nothing reaches the
  capture server the forged route names, both reads reach the model through
  the proxy as symbols; red before (the requests went to the capture
  server). `tests/sandbox/sdk-route-protected.test.ts`, under the real
  guard: the host can change neither the route file, its folder, the hook
  copies nor the shims, a file elsewhere in the scope run dir is written,
  and its claude is still routed; red without the write-protect entries.
- `launcher/test/component/claude-permission-mode.test.ts` (2026-10-18):
  the `claude` shim of a claude or shell launch the route does not serve
  (supported-agents.md §2), the permission mode around its routing
  `--settings`; the unit `sdk-route` holds its script, its route
  (`claudeShimRoute` equals `claudeRouteEnv`, `parseClaudeShimRoute`
  refuses a partial one), `claudeShimSpawn` (a re-pointed environment put
  back, the launch's values in the last `--settings`, its own inline one
  merged, the refusals, idempotent) and its parity with `claude-route.ts`
  over the corpus.
- `tests/stack/nested-claude-route.test.ts` (2026-10-18, §3.5): a stand-in
  `claude` that resolves its base URL as Claude Code does, started by name
  under `mandu -- sh` and from the agent's Bash under `mandu claude`, through
  the real model proxy and arbiter in `secrets`: user settings, an
  agent-written `.claude/settings.local.json`, `ANTHROPIC_BASE_URL=…` with
  `NO_PROXY` emptied, and another `CLAUDE_CONFIG_DIR` each pointing straight
  at a model the agent can reach; the labelled `.env` and an unlabelled log
  holding its value reach the model only as symbols, through the proxy; a
  `--settings` file and a Bedrock switch are refused with no request; a
  no-Mandu control shows the stand-in goes around. Red before the shim
  routed (the log's value reached the model). Since 2026-10-18 the
  stand-in honours the proxy variables as Claude Code does (`NO_PROXY`,
  then the scheme's proxy, then `ALL_PROXY`), and one more leg runs an SDK
  host (`mandu --target claude --no-net-proxy -- node host.js`) that starts
  it by full path with `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY` at a
  capture server the agent can reach: nothing reaches the capture server,
  and both reads reach the model through the proxy as symbols. Red before
  (the request, with the tool result the model proxy had not yet masked,
  went to the capture server). The replay drill
  `claude-settings-route.test.ts` runs the same with the real Claude Code
  (a nested `claude -p` from the agent's Bash), also red before.
- `tests/stack/inspect-ullm-shim.test.ts` (2026-10-19, §3.5 "The
  quarantined `claude -p`"): under a real `mandu claude` a stand-in
  `claude` reads an any-model file through the model proxy, gets its
  symbol, starts the inspect server of its `--mcp-config` as Claude Code
  does and calls inspect_symbol; every quarantined start (the extraction
  and the content-kind classifier) ran as the CLI by its path, with the
  entry's base URL (the forwarder), never the proxy's, and no `--settings`;
  the answer came back as a symbol. Red before (both starts went through
  the shim: the proxy's base URL and its `--settings`). Unit:
  `launcher/test/unit/mcp.test.ts` (the entry's `MANDU_ULLM_BINARY_PATH`),
  inspect-mcp `server-main.test.ts` (a relative or foreign path refuses)
  and `cli-ullm-client.test.ts` (the path is spawned for its own CLI only).
- `agent-sdk.test.ts` (`integration.agent-sdk`): host
  programs on the pinned SDKs (`tests/fixtures/agent-sdk-host`) under the
  real launcher against a scripted model, in `secrets`: a labelled file
  reaches the model only as `$MDU:` (as documented, with the `env` /
  base-URL bypass shapes, and with the SDK's `settings` and a project
  settings file both pointing `ANTHROPIC_BASE_URL` straight at a model the
  agent can reach), the arbiter stopped mid-run fails closed, and a
  control leg shows the bypass shapes without Mandu hand the model the raw
  bytes. The fixture installs without the per-platform binaries
  (`.npmrc omit=optional`), so CI runs the SDKs against the `claude` and
  `codex` on PATH; `npm ci --include=optional` there runs the bundled ones.
- The model-host deny (§4, 2026-10-18):
  `interceptors/net-proxy/test/unit/model-host-paths.test.ts` (the hosts;
  every model path refused on every host, whatever the method or query; the
  listed calls allowed; absolute-form targets; a dot segment, an escape, a
  `;`, a `\` or an empty segment refused below an allowed prefix; no entry
  admits a Messages or Responses path; every entry names its evidence);
  `test/component/model-host-deny.test.ts` (a real proxy with TLS
  inspection and the real curl: `/v1/messages`, platform.claude.com's
  Messages API, the ChatGPT model turn and a `--path-as-is` dot-segment
  walk refused with nothing reaching the loopback vendors, the listed calls
  reaching them; TLS inspection off refusing every model host's CONNECT;
  the plain leg; the identity); `launcher/test/unit/model-host-deny.test.ts`
  (the proxy's switch by axis and its reuse key, `NO_PROXY` for the agent
  and the inspect server, the guard's `--deny` rules and the dropped
  allowance, the launch note with TLS inspection off);
  `tests/stack/model-host-deny.test.ts` (the real net-proxy as a launch
  starts it, the launch's composed environment, a stand-in `claude` at an
  absolute path that follows only its environment: with `ANTHROPIC_BASE_URL`
  removed or at the vendor its `/v1/messages` gets 403 and the loopback
  vendor receives nothing, its `/api/oauth/profile` passes, and the routed
  call reaches Mandu's model proxy; the launcher's host list equal to the
  proxy's). Red on the code before (the vendor received the model call with
  the secret in it in clear).
