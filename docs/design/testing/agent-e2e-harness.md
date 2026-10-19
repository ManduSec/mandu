# Mandu — the multi-agent live e2e harness (OpenClaw · OpenCode)

> How the `claude-e2e` live environment generalizes to a third and fourth
> agent, and the provisioning facts each one needs. Companion to
> [`supported-agents.md §5`](../agents/supported-agents.md) (which agents are *defendable*),
> [`docker-e2e.md`](./docker-e2e.md) §2 (the containerized rig), and
> [`docs/testing/suites.md`](../../testing/suites.md) (the suite manifest).
>
> **Status: SHIPPED.** Provisioning is source- and probe-verified for both
> agents; both suites run end to end across all four chokepoints plus the U-LLM
> channel, and the launcher wraps both agents (§9).
>
> **Pinned to `secrets` (2026-09-29, `test-organization.md` §7.1).** The
> original integrity-form scenarios (`stored-ipi` asserting
> `symbol-reaches-model` and `raw-injection-absent`, `fs-view-writeback`,
> `net-exfil-blocked`, `inspect-extract`) moved verbatim to the frozen lane
> (`tests/integrity/{openclaw,opencode}-e2e.test.ts`). The per-push suites
> prove the confidentiality invariant with the `conf-exfil` fixture on the
> shared runner (`confScenarios`, the `conf` scenario field):
> `secret-read-exfil` (a `no-model`-labelled file reaches the model as ONE
> symbol, and the scripted `exec` / `bash` curl of what was read delivers only
> that symbol to a loopback sink), `secret-net-exfil-blocked` (the same upload
> through the net-proxy to an untrusted host is blocked, the secret symbol
> withheld: the network chokepoint in `secrets`), `secret-read-control` (the
> file unlabelled reaches model and sink raw: the oracles can fire),
> `benign-read` (an ordinary file rides verbatim, not symbolized),
> `reasoning`, `inspect-extract` as the quarantined read of an `any-model`
> file (the answer re-enters as an `anymodel_` symbol naming its parent, the
> file's values never reach the T-LLM wire;
> [`confidentiality.md`](../confidentiality/confidentiality.md) §3.3), and
> `prompt-secret` (a key and `DB_PASSWORD=postgres` registered as the
> launcher registers the environment, the prompt types both; the model
> receives the key only as its own symbol and `as postgres` as typed, and the
> human plane restores the typed text; the `promptSecrets` scenario field,
> `lib/agent-prompt-checks.ts`; the claude-code and codex replay suites carry
> the same leg as their `LIVE prompt filter` test). The oracles read the bytes
> the model endpoint received: the fake's captured requests, or a recording
> relay in front of the real API (`MANDU_TEST_UPSTREAM=real`).
>
> **The per-push entries retired (2026-10-18, `test-reorganization.md`
> §9.1).** The scripted-upstream form ran per push as
> `integration.openclaw-e2e`, `integration.opencode-e2e` and
> `integration.opencode2-e2e` until a week of its scenarios' drills replaying
> per push (each agent's TUI through the launcher, blocking) had passed; the
> oracles no replay check holds are written down there with where each is
> held. The two files still run on a real upstream (`openclaw-headless`,
> `opencode-headless` and their `.inspect` entries), and the scripted form by
> hand.
>
> **Four real defects were found by running these, not by writing them** — the
> case for extending coverage to more agents rather than assuming the
> machinery generalizes:
>
> | defect | where | why it was invisible before |
> |---|---|---|
> | `git status --porcelain` collapses an untracked directory to one `dir/` entry, so `syncToHuman` did `readFileSync` on a directory and threw `EISDIR` | `fs-sync/src/git.ts` | Claude Code's scenarios never created a subdirectory in the workspace |
> | OpenCode spawns MCP servers with `environment` REPLACING the parent env, so the quarantine's `claude -p` had no `PATH`/`HOME` and never ran | `agent-posture.ts` (`inspectMcpEnv`; then in `anthropic-agent-runner.ts`) | the tool mounted, appeared in `tools[]`, and was called — only the `ullm_call` event was missing |
> | `tools.profile` is an allowlist over the FINAL tool list, so a plugin tool outside the profile loads and is then filtered out before the model sees it | `agent-provision.ts` (`tools.alsoAllow`) | the plugin logged "registered" and the request's `tools[]` silently lacked it |
> | an embedded arbiter client kept the HOST's event loop alive, so `openclaw agent --local` finished its turn and then hung forever | `arbiter/ipc/client.ts` (`unref`) | only visible as a wall-clock timeout with a complete, correct result already printed |

---

## 1. Why this doc exists

`claude-e2e.test.ts` and `codex-e2e.test.ts` are **structural forks**: two
copies of `runScenario`, two skip gates, two batch-id blocks. That was
defensible at N=2; at N=4 it is not.

The harness answers it in the **narrowest** way that survives N=4: the parts
that genuinely differ per agent (binary, argv, env, config files, reply
extraction) are extracted into ONE pure, unit-tested module —
`tests/lib/agent-provision.ts` — and everything else keeps
using the already-shared oracle library. `runScenario` is still per-suite,
because the *scenario shapes* differ per agent's tool surface (that part of the
catalog's argument was correct). What is no longer duplicated is the part that
was pure boilerplate and pure per-agent fact.

The decisive design consequence of §2: **no new wire adapter is needed.** Both
OpenClaw and OpenCode speak genuine Anthropic Messages, so both ride the
existing `anthropic-proxy` unchanged; no Chat-Completions adapter is on this
path (the launcher later routed OpenAI-family providers through the same proxy,
§9).

---

## 2. Per-agent provisioning facts (probe-verified 2026-08-05)

Both agents were driven against a scripted local `/v1/messages` endpoint with a
throwaway HOME/state dir. Both completed a turn and exited 0.

### 2.1 OpenClaw

| Axis | Fact |
|---|---|
| One-shot invocation | `openclaw agent --local --agent main --session-id <id> -m '<prompt>' --json --timeout <s>` — a real single-turn mode. **`--local` is mandatory**: without it the CLI tries the gateway daemon first and only *falls back* to embedded, which is non-deterministic for a harness. |
| Entry point | npm `openclaw` (2026.7.1-2) — or run the in-repo checkout with no install: `node <openclaw-checkout>/openclaw.mjs`. |
| Base-URL override | `openclaw.json` → `models.providers.anthropic.baseUrl`. **No `ANTHROPIC_BASE_URL`.** |
| Env-drivability | `${VAR}` substitution is applied to every string value at config load, so one static config + per-run env works. **Verified for `baseUrl` AND `headers`.** |
| Session header | `models.providers.anthropic.headers` → `{"x-mandu-session-id": "${MANDU_SESSION_ID}"}`. Arbitrary headers, unlike Claude Code's one-header limit. |
| Isolation | `OPENCLAW_HOME`, `OPENCLAW_STATE_DIR`, `OPENCLAW_CONFIG_PATH`, `OPENCLAW_AGENT_DIR` — a real `CODEX_HOME`-grade lever. Probe wrote nothing to the real `~/.openclaw`. |
| Wire | `anthropic-messages`, `stream: true`, `x-api-key` + `anthropic-version: 2023-06-01`. → **anthropic-proxy, unchanged.** |
| Model calls per turn | **one** (no title-generation side call — unlike Claude Code and OpenCode). |
| Tools | `read` `write` `edit` `apply_patch` `exec` `process` `web_search` `web_fetch` `memory_*` `sessions_*` `browser` `canvas` `message` `cron` `gateway` `nodes` `agents_list` `image` `tts`. Profiles: `minimal` / `coding` / `messaging` / `full`. |
| Exec defaults | `host: "sandbox"`, `security: "deny"` — **must** be set to `host: "gateway"`, `security: "full"` or the shell tool never runs on the host. |
| CWD | `process.chdir(effectiveWorkspace)` per run, from `agents.defaults.workspace` — a real per-run CWD lever (this corrects `supported-agents.md §5` §2.1). |
| MCP | **NOT SUPPORTED.** No MCP client; ACP explicitly rejects `mcpServers`. → `inspect_symbol` cannot be mounted as MCP; it must ship as a plugin tool (`api.registerTool`), exactly as the reference plugin already does. **The U-LLM scenarios are therefore out of scope for the OpenClaw suite's first cut.** |

Two traps:

- **Header values are NOT env-var-name indirection.** The `resolveConfigValue`
  env-name behavior documented for `apiKey` does *not* survive the
  `openclaw.json` → `models.json` projection for headers: a bare
  `"MANDU_SESSION_ID"` arrives on the wire as the literal string
  `MANDU_SESSION_ID`. Use `${MANDU_SESSION_ID}` (config substitution).
- **Never let the API key look like an OAuth token.** `pi-ai` branches on
  `isOAuthToken(apiKey)` and, on that branch, swaps to `authToken`, adds Claude
  Code identity headers, and injects a `"You are Claude Code…"` system block —
  silently changing the very context the suite asserts on. Use an `sk-ant-`
  shaped dummy.

### 2.2 OpenCode

| Axis | Fact |
|---|---|
| One-shot invocation | `opencode run --format json -m <provider>/<model> '<prompt>'` — non-interactive is the *default* for `run`; exits when the session goes idle. |
| Entry point | npm `opencode-ai` (1.18.13). Ships a bundled `bun` runtime. |
| Base-URL override | `opencode.json` → `provider.<id>.options.baseURL`. **`ANTHROPIC_BASE_URL` is NOT honored.** |
| Env-drivability | `{env:VAR}` substitution over the raw config text before parsing — works in any string value. |
| Session header | `provider.<id>.options.headers` — spread verbatim into the SDK factory. **Verified on the wire.** |
| Isolation | `XDG_CONFIG_HOME` / `XDG_DATA_HOME` / `XDG_CACHE_HOME` / `XDG_STATE_HOME` + `OPENCODE_TEST_HOME` + `OPENCODE_CONFIG`. |
| Wire | `npm: "@ai-sdk/anthropic"` → POSTs `/v1/messages` in genuine Anthropic Messages. → **anthropic-proxy, unchanged.** Also sets `anthropic-beta: interleaved-thinking-…,fine-grained-tool-streaming-…` on every request; the proxy must tolerate it. |
| Model calls per turn | **two** — a title-generation side call lands first, then the main agentic call. The oracle must not race past the title call (the same shape claude-e2e handles). |
| Tools | `bash` `read` `glob` `grep` `edit` `write` `task` `webfetch` `todowrite` `websearch` `skill` `apply_patch` (+ `question`, `lsp`, `execute`, `plan_exit` conditionally). |
| Permissions | `OPENCODE_PERMISSION='{"*":"allow"}'` — merged *over* file config. The cleanest analogue of `--permission-mode bypassPermissions`. `--auto` on the CLI does the same. |
| MCP | Supported: `mcp.<name> = {type:"local", command:[…], environment, timeout}`. Tools surface to the model as **`<server>_<tool>`** (single underscore) — so `inspect_symbol` becomes `mandu-inspect_inspect_symbol`. Default timeout 5000 ms — raise it for a cold `inspect_symbol` start. |
| Hermeticity | `OPENCODE_DISABLE_MODELS_FETCH=1` is **required**, else every run hits models.dev over the network. Also `OPENCODE_DISABLE_AUTOUPDATE=1`. OpenCode also reads the host's `~/.claude/CLAUDE.md`, `~/.claude/skills` and `~/.agents/skills` from HOME (1.18.13): the e2e and replay lanes give it a private HOME (+ `OPENCODE_TEST_HOME`); the watch runner keeps the user's HOME and sets `OPENCODE_DISABLE_CLAUDE_CODE=1` + `OPENCODE_DISABLE_EXTERNAL_SKILLS=1` instead. |
| Process model | `run` dispatches its "server" **in-process** over a synthetic fetch — one PID, full env inheritance, nothing extra to reap. |

**OpenCode 2 is not this table.** npm `@opencode/cli` (2.0, GA 2026-09-11)
installs the same `opencode` command, still reads `OPENCODE_CONFIG` /
`OPENCODE_CONFIG_CONTENT` and normalizes the V1 keys above, but by default
`run` joins a **background service** (not in-process) that runs the model
calls and tools with its own configuration, and its tools are renamed
(`shell`, `path`). The launcher supports it by default since 2026-10-05
([supported-agents.md](../agents/supported-agents.md) §2.3; `MANDU_OPENCODE2=0`
turns it off) with `--standalone` forced (a private server, its child) and
the server shapes refused, in `secrets` only with its guards in force
(§2.3.1). Its confidentiality e2e through the real launcher is the catalog
replay, `MANDU_REPLAY_OPENCODE=2` (`integration.replay-opencode2`;
supported-agents.md §2.3 item 5, differential-interactive.md §28.6). This
harness provisions it too, §2.2.1.

#### 2.2.1 OpenCode 2 in this harness (2026-10-06)

`MANDU_E2E_OPENCODE=2` runs the same `opencode-e2e` scenarios on the pinned
2.x (`opencode2` on PATH or `MANDU_OPENCODE_V2_BIN`; the CI guest's 2.0.23),
the entry `integration.opencode2-e2e`, per push until 2026-10-18 (its drills
replay per push as `integration.replay-opencode2`).
`agent-provision.ts` `opencode2Provisioner` is 1.x's with four changes:

| Axis | Fact (2.0.23, run against this harness's stack) |
|---|---|
| One-shot invocation | `opencode2 run --standalone --format json --model mandu/<model> --auto '<prompt>'`. `--standalone` is what the launcher forces too: a private in-process server, never the user's background service (which outlives the run). `--format json` keeps 1.x's NDJSON `type:"text"` parts, so `extractReply` is shared. |
| Isolation | 1.x's private XDG dirs and HOME, and `OPENCODE_TEST_HOME`, which is where 2.x looks for `~/.claude` and `~/.agents` (it has neither of 1.x's `OPENCODE_DISABLE_*` switches). No `OPENCODE_PERMISSION` (gone in 2.x): `--auto` approves. |
| MCP | The V1 `mcp.<name>` above is normalized, but to CODE MODE: its tools exist only inside `execute`. So the inspect server is written in 2.x's spelling, `mcp.servers.<name>` with `codemode: false` and `timeout: {startup, catalog, execution}` (the launcher's `opencodeV2McpServer`), and `execute` is denied (`permissions`, the launcher's `OPENCODE_DENY_EXECUTE`): the request then offers neither `execute` nor its catalog. |
| Tools | `shell{command, workdir, timeout, background}` and `read{path, offset, limit}`; the scripted model speaks them (`opencode-e2e.test.ts` `readInput`, `SHELL`). The inbound spec is the same `opencode` one (opencode-inbound.ts reads both). |

All seven scenarios that run pass on 2.0.23 with their 1.x oracles
(reasoning, benign-read, the conf trio, prompt-secret, prompt-policy).
`inspect-extract` SKIPs on 2.x with its reason: a one-shot `run` sends its
first requests WITHOUT waiting for its MCP servers (measured: the inspect
tool, a tsx server, appears in the tools only from a request about five
seconds in; this scenario's two quick calls never see it, "No tool named
mandu-inspect_inspect_symbol is currently available"). The quarantine on
2.x is proven through the launcher and the TUI, which waits for a typed
prompt (`integration.replay-opencode2`'s `conf-quarantine-any-model`).

**Known upstream hang** ([anomalyco/opencode#17516](https://github.com/anomalyco/opencode/issues/17516), open):
`opencode run` can fail to exit after tool calls. The harness already has the
right hammer — `runChildToExit` settles on `exit` and SIGKILLs the process group
— but this makes the wall-clock timeout **load-bearing, not belt-and-braces**.

### 2.2b Goose (probe-verified 2026-10-05)

| Axis | Fact |
|---|---|
| One-shot invocation | `goose run --no-session --output-format json -t '<prompt>'`: one JSON document of the run's messages after a short banner; exits 0. |
| Entry point | One Rust binary (`aaif-goose/goose`, formerly `block/goose`); the CI guest pins 1.53.0 (`scripts/ci/pins.env`). |
| Base-URL override | Env alone: `GOOSE_PROVIDER=anthropic` + `ANTHROPIC_HOST=<proxy>` (an env var named as the uppercase config key outranks `config.yaml`). **`ANTHROPIC_BASE_URL` is NOT honored.** |
| Session header | None Mandu can set: Goose sends its own `agent-session-id: <yyyymmdd>_<N>`. The run's session is the proxy's own key, as for Codex. |
| Isolation | `GOOSE_PATH_ROOT` (config, data, state), `GOOSE_DISABLE_KEYRING=1`, a throwaway `HOME`. |
| Wire | `POST /v1/messages`, `stream: true`; no `GET /v1/models` at start. A tool-less title call per session. Every tool result is a plain string. |
| Tools | `shell` `write` `edit` `tree` `analyze` `read_image` `delegate` `load` `load_skill` `apps__*` `extensionmanager__*`; no read and no fetch tool. |
| MCP | `--with-extension '<name>:ENV=… cmd args'` on `session` / `run`; tools surface as **`<name>__<tool>`** (`mandu-inspect__inspect_symbol`). Goose 1.53.0 opens with MCP `server/discover` and falls back to `initialize` on a JSON-RPC error. |
| Uploads | Off in every run (`GOOSE_UPLOADS_OFF_ENV` in `agent-provision.ts`, the launcher's values): PostHog, Langfuse, OTLP, the classifiers. `goose-uploads.test.ts` proves it, with a control run that does upload. |

The provisioner is `gooseProvisioner`; the replay suite
`goose-e2e.test.ts` runs the seven `confScenarios` in
`secrets` against the real binary and the scripted upstream
(`integration.goose-e2e`).

### 2.3 What this buys

| | Claude Code | Codex | OpenClaw | OpenCode |
|---|---|---|---|---|
| Wire | Anthropic Messages | OpenAI Responses | **Anthropic Messages** | **Anthropic Messages** |
| Proxy | anthropic-proxy | openai-proxy | **anthropic-proxy** | **anthropic-proxy** |
| Override | env | argv config-splice | config file (`${VAR}`) | config file (`{env:VAR}`) |
| Custom headers | 1 only (packed) | none (proxy `sessionKey`) | **arbitrary** | **arbitrary** |
| MCP / U-LLM | yes | yes (unbuilt) | **no — plugin only** | **yes** |

### 2.3b Three things the build found that the source study did not

None is visible from reading the agents' docs:

1. **OpenClaw header values are NOT env-var-name indirection** (above): the
   single most likely thing to break on a version bump. Use `${VAR}`.
2. **The lifted `openclaw` trust spec is unsafe for a live OpenClaw CLI.** It
   grants `read: TRUSTED` wholesale — correct only under the reference plugin's
   FS view-sync. Reusing it here would forward a poisoned file's bytes raw to
   the model. Hence the separate `openclaw-agent` spec (§4) and the unit test
   that fails if the two are ever merged.
3. **A benign-looking stderr line that is NOT a failure.** Every OpenClaw run
   prints `Failed to read config … ReferenceError: Cannot access
   'ANTHROPIC_MODEL_ALIASES' before initialization`. The config **is** applied —
   the captured request carries our `baseUrl`, our header, and our model. It is
   an upstream circular-import bug on a swallowed, best-effort
   context-window-priming path (`primeConfiguredContextWindows`). Do not chase
   it; do not "fix" it by changing the config.

### 2.4 Reproducing the probes

The probes are one-shot provisioning experiments, not tests, and are not kept
in the repo (the suites are the durable form). The shape is: a ~60-line fake `/v1/messages` server that captures every request
and replies with a one-shot SSE text message, then each agent driven at it under
`env -i` with only the isolation vars set. Anyone re-verifying a version bump
should redo exactly that, and check three things: exit code 0, a captured
request to `/v1/messages`, and the `x-mandu-session-id` header arriving with
the *resolved* value.

---

## 3. The seam: `agent-provision.ts`

One module, no I/O in the decision path, mirroring the repo's kernel-gated Rust
discipline — **the decision logic is pure and unit-tested; the enactment
(writing files, spawning) is the caller's**.

```ts
export type LiveAgentId = "claude" | "openclaw" | "opencode";

export interface ProvisionInput {
  agentHome: string;      // throwaway HOME/state root for this run
  workspace: string;      // the agent's CWD
  proxyUrl: string;       // http://127.0.0.1:<ephemeral>
  sessionId: string;      // <class>-<scenario>-<ts>
  batchId: string;
  model: string;
  prompt: string;
  timeoutMs: number;
  mcp?: { name: string; command: string[] };   // ignored where unsupported
}

export interface Provisioned {
  binary: string;
  argv: string[];
  env: Record<string, string>;
  files: Array<{ path: string; content: string }>;  // caller writes these
  unsupported: string[];                            // e.g. ["mcp"] for openclaw
}

export interface AgentProvisioner {
  id: LiveAgentId;
  inboundSpec: InboundSpecId;
  sessionClass: string;             // "openclaw-e2e"
  provision(input: ProvisionInput): Provisioned;
  extractReply(stdout: string): string;
}
```

`extractReply` is where the output formats diverge and is the other thing worth
sharing: Claude's `--output-format text` is the raw stdout; OpenCode's
`--format json` is NDJSON whose `type:"text"` parts concatenate to the reply;
OpenClaw's `--json` is a single JSON document shaped
`{payloads:[{text,mediaUrl}], meta:{…}}`. All three are pure string→string, so
all three are unit-tested against **captured** fixtures with no agent installed.

**`extractReply` returns `{text, extracted}`, and the flag is not decoration.**
A parser that falls back to the whole raw stdout when it cannot find the reply
still matches every `reply-achieves` regex (the raw envelope *contains* the
reply text), so a completely broken parser once produced a green suite. The
fallback is right (never crash the
harness on a surprise envelope) but it must be *distinguishable from success*,
so the runner now emits a blocking `reply-extracted` fidelity check. This is the
same class as the confidentiality audit's "chokepoint wired to a posture nobody
runs": a degradation that cannot be seen is a defect, not a safety margin.

**What is deliberately NOT abstracted:** the scenario list, the oracle
selection, and `runScenario` itself. Those differ because the agents' tool
surfaces differ (OpenClaw has no MCP → no U-LLM scenarios; OpenCode's `bash`
vs OpenClaw's `exec` vs Claude's `Bash`), and a single `runScenario` would need
an `if (agent)` at every one of those axes.

**The shared runner's module layout.** The OpenClaw / OpenCode
runner is `tests/lib/anthropic-agent-runner.ts` (`runAgentScenario`,
`activateSpecFor`), the one import surface the suites use: it re-exports the
names of the modules it was split into, all in the same `lib/` directory:
`agent-scenario.ts` (the scenario types, `INJECTION`, `UPSTREAM_TIER`),
`agent-fake-script.ts` (the fake tier's scripted model: `LAST_TOOL_RESULT`, the
turn counter, `startFakeUpstream`), `agent-conf-scenarios.ts` (`confScenarios`
and the sink host), `agent-conf-checks.ts` (the conf verdicts) and
`agent-posture.ts` (the fs-sync repo wrapper, the net-proxy bridge and catalog,
the inspect-mcp mount).

---

## 4. Per-agent trust specs, and the process-global problem

Trust classification is keyed on tool NAME, and the three agents disagree:
`Read`/`Bash`/`WebFetch` (Claude) vs `read`/`exec`/`web_fetch` (OpenClaw) vs
`read`/`bash`/`webfetch` (OpenCode). The active spec is a **process-global**
(`setActiveInboundSpec`, chosen once at arbiter boot from
`$MANDU_INBOUND_SPEC`). A shared arbiter booted `claude-code` therefore
fails-closed (UNTRUSTED) for every OpenClaw/OpenCode tool.

Fail-closed is *safe* — it over-symbolizes, so the security invariant still
holds — but it destroys the trusted-verbatim utility proofs, and a suite that
can only ever assert "everything was symbolized" is not proving much.

**Resolution, without touching the arbiter's global:** each new suite boots its
own **private in-process arbiter**, exactly the pattern the `CONF-*` scenarios
already use — private socket, private symbol DB, but events written into the
*shared* arbiter's event dir so the dashboard still sees the session. Because
node's test runner gives each test FILE its own process, the module-global spec
set by `openclaw-e2e.test.ts` cannot leak into `opencode-e2e.test.ts` or into
the shared daemon.

**Session-keyed specs** (§7 item 1) are the production answer: the arbiter keeps a
session→spec binding registry beside the process-global active spec
(`arbiter/policy/tool-inbound.ts` — `SessionSpecs` /
`resolveInboundSpecId`), set over the wire by the new **`setSessionSpec`** IPC
op and consulted by `classify` via a new optional `ClassifyRequest.sessionKey`
(the same identity `symbolize` already carries — the launcher's
`MANDU_SESSION_KEY` / scopeId, which both proxies now thread into every
classify). Resolution is fallback-layered and fail-closed at every miss: an
unbound or absent session resolves against the process-global boot spec
(byte-identical to the pre-binding behavior); an UNKNOWN spec id in
`setSessionSpec` binds the empty `"fail-closed"` spec (every tool UNTRUSTED)
rather than leaving the session on another agent's TRUSTED grants; and after
an arbiter restart (the map is in-memory) a formerly-bound foreign session
falls back to the global spec, where its tool names miss every entry and
over-symbolize. The `mcp__` prefix rule and the outbound
`destinationKind` maps follow the same per-session resolution (inbound and
outbound are always switched together). Production wiring: setting
`MANDU_INBOUND_SPEC` on a **proxy** process makes it self-bind its
`MANDU_SESSION_KEY` at boot (`anthropic-proxy/src/server-main.ts`) — the
same env var that, on the arbiter's own process, still sets the global spec.
YAML `tools:` overrides and `policySnapshot` stay keyed to the global spec by
design (a session bound to the same id sees the merged view; per-session
snapshot plumbing waits for a consumer).

**The bindings belong to one arbiter** (2026-10-09). Each `ArbiterServer` owns
a `SessionSpecs` registry: its `setSessionSpec` binds there, it hands the same
object to every engine it builds (`createEngineBackedPolicy`'s `sessionSpecs`,
so a policy rebuild keeps the bindings) and to each session-keyed lookup it
makes itself (the gate surface, the unknown-tool health check, the
unmapped-tool mapping), and its `close()` clears it. Bind-once
([policy-surface.md](../ui/policy-surface.md) §2.6) holds for the registry's
life: the first binding wins, the same spec again is a no-op, another spec is
refused and changes nothing, and nothing unbinds a single session; the
registry enforces this itself, beneath the handler's check, which also refuses
a session that has classified traffic. The bindings are in memory, as before:
not in the arbiter DB, so a restarted arbiter binds from scratch and a session
it did not bind falls back to the boot spec (over-symbolization). The
bindings used to be a map in the policy module, which outlived the server
that made them: the in-process arbiters of one test process shared it, and on
2026-10-09 the differential lane's OpenCode arbiter refused the session key
OpenClaw's arbiter had bound earlier in the process, so its anthropic-proxy
exited at startup (a second arbiter could also have resolved a session by
another's binding). The module keeps a process registry
(`processSessionSpecs`) only as the default for direct callers of the pure
lookups (unit tests, embedders of the bare engine); no server reads or
writes it, and an embedder that injects its own engine passes the server the
registry that engine was built with (`ArbiterServerOptions.sessionSpecs`;
without it the injected engine never sees the server's bindings and falls
back to the boot spec). Two other module-level
singletons have the same per-process shape but hold no per-session state: the
law in force (`compiled-policy.ts`) and the admin layer (`admin-layer.ts`),
each SET by the server that starts last rather than accumulated; moving them
onto the instance is a separate change, and a production arbiter is one per
process.

The suites deliberately KEEP the private-arbiter pattern (proven, zero blast
radius, and it exercises the fallback path); the session-keyed mechanism is
proven by `arbiter/test/integrity/session-spec.test.ts` (one arbiter, four sessions,
divergent verdicts on the same tool name over the real IPC) and the
session-keyed section of `multi-agent-policy.test.ts`; its scope by
`arbiter/test/unit/session-spec-registry.test.ts` (two registries, each lookup
following the one it is handed) and `arbiter/test/component/session-spec-scope.test.ts`
(two real arbiters in one process bind the same key to different specs and
each classifies by its own; bind-once within one, across a policy rebuild;
close releases).

`arbiter/policy/opencode-inbound.ts` is new. The `openclaw` spec already exists
(lifted from the reference implementation) and its names were re-verified
against the current OpenClaw tool catalog.

---

## 5. Two run modes — host and docker

Both agents get the same two modes Claude Code has. Neither mode is the
"real" one; they answer different questions.

The `secrets`-mode suites themselves (`openclaw-e2e`, `opencode-e2e`) are
agent drills: they run in the maintainers' source repository and are not
published, so the commands of this section are the maintainers'. Their
frozen integrity copies are public (`tests/integrity/`); what the drills
show is in [`drill-results.md`](../../testing/drill-results.md). To get
access to the drills, for research for example, write to
hello@mandusecurity.com.

### 5.1 Host mode

Requires: the agent binary resolvable, the shared dashboard arbiter socket,
`MANDU_TEST_DASHBOARD=1`. Same gate shape as `claude-e2e` — the suite SKIPs
with a precise reason rather than failing when a precondition is absent.

Each suite has its own npm script in the maintainers' `tests/` package.

Binary resolution is explicit and env-overridable, because neither agent is
reliably on PATH:

| Agent | Order |
|---|---|
| OpenCode | `$MANDU_OPENCODE_BIN` → `opencode` on PATH |
| OpenClaw | `$MANDU_OPENCLAW_BIN` → `openclaw` on PATH → `node $MANDU_OPENCLAW_SRC/openclaw.mjs` |

The OpenClaw source fallback runs a built OpenClaw checkout (with its
`node_modules`) at `$MANDU_OPENCLAW_SRC` with no install.

### 5.2 Docker mode (the reproducible path)

Same rationale as the maintainers' containerized rig for `claude-e2e`
(`docker-e2e.md` §2): the live suites otherwise run only on a
hand-configured box. The rig's image gains `opencode-ai` and `openclaw` as
pinned npm globals alongside `@anthropic-ai/claude-code`, and its compose file
gains one service per agent (`openclaw-e2e`, `opencode-e2e`), so a run in the
maintainers' repository is one `docker compose … run` command. The rig runs
only the drills, so like them it is not published.

The source-overlay contract is unchanged — source-only edits need no rebuild;
only lockfile/rig/agent-version changes do.

**Credentials differ from the Claude rig in a way that matters.** The `claude`
service bind-mounts real OAuth credentials because its live tier talks to
`api.anthropic.com` on the user's subscription. The two new suites default to a
**scripted fake upstream**, so they need no credentials at all and cost no
budget — which is why they could run in the per-push `replay-drill` kind
(`test-organization.md` §3) rather than the nightly `live-drill` kind, as
they did until their drills' replay took that place on 2026-10-18.
Pointing them at a real upstream is a deliberate opt-in
(`MANDU_TEST_UPSTREAM=real`), and only then do they need a key: an Anthropic
**API key** (`MANDU_E2E_ANTHROPIC_API_KEY` or `ANTHROPIC_API_KEY`,
`sk-ant-api…`), which the harness puts on the hop to the real API in place of
the agents' dummy key (their configs keep the dummy, so the context they send
is the fake tier's). Without one the real tier SKIPs with that reason; a
subscription token cannot serve, since OpenClaw's OAuth branch injects a
Claude Code system block into the graded context (`continuous-integration.md`
§9.7).

**A real model may decline (2026-10-07).** On the real tier the model, not a
script, decides whether to read and send. The first live run of
`integration.agents-real` (Haiku 4.5, `secret-read-exfil` on both agents)
called no tool at all: the model declined the request as an exfiltration,
even when the prompt said it was a gate check with a canary. Its two checks
that need a minted symbol (`conf-level-on-event`, `conf-human-reveal`) had
read FAIL on a gate that never ran; on the real tier a run whose model called
no tool now grades them WARN ("gate not exercised"), as the drill runner
grades a declined gate. The wire and sink checks stay hard, and a run that
called a tool and minted no symbol still FAILs (`tests/stack/agent-conf-checks.test.ts`).
The real tier also logs each scenario's tool calls and the model's reply as
the model wrote it (symbols unresolved), so a declined turn reads as one.

---

## 6. Badges and dashboard identity

New session classes `openclaw-e2e` / `opencode-e2e` with badge prefixes
**`OCl`** / **`OCo`** (`E`, `C`, `Re` are taken; the two agents share a leading
`O`, so a two-letter discriminator is needed).

One real bug this surfaces: `deriveAgentKind` infers the agent from the *proxy
emitter* — `anthropic-proxy` ⇒ `"claude"`. With three agents on the
anthropic-proxy that inference is now wrong for two of them. It is fixed to
consult the **session-id class first** (authoritative when present) and fall
back to the emitter only for non-test traffic, where the old behavior was the
only available signal and remains correct.

---

## 7. Deliberate scope boundaries + follow-ups

Named so they are debt, not silence. Items 1–4 and 7 are built; 5 and 6
stand.

1. **Session-keyed inbound specs** (§4) — BUILT: the `setSessionSpec` op,
   `ClassifyRequest.sessionKey`, proxy self-bind via `MANDU_INBOUND_SPEC`;
   one arbiter serves mixed agents.
2. **U-LLM / `inspect_symbol` for OpenClaw** — BUILT as the plugin-tool port
   `interceptors/openclaw-inspect-plugin/` (§8; OpenClaw has no MCP), with
   OpenCode's MCP mount beside it. The two mounts spell the SAME tool three
   different ways (`mcp__mandu-inspect__inspect_symbol`,
   `mandu-inspect_inspect_symbol`, bare `inspect_symbol`), so recognition is
   one exact-name set, `arbiter/policy/inspect-tool.ts`. That set is the
   load-bearing part: a missed spelling is *safe* (the envelope fail-closes and
   symbolizes) but DOUBLE-WRAPS the answer — the model gets a symbol whose
   content is another symbol, which is precisely the utility the quarantine
   exists to provide, silently gone.
   `arbiter/test/integrity/inspect-result-shapes.test.ts` runs the REAL
   classifier against the ACTUAL bytes each mount emits, because each mount's
   own suite can only test against a replica of the grammar.
3. **Interactive/TUI + reply-filter differential coverage** — BUILT: the
   differential harness has an `AgentDriverProfile` seam
   (`differential-profiles.ts`) with OpenClaw and OpenCode profiles and a
   `differential-agents.test.ts` lane (in the maintainers' repository).
   Per-agent facts, the wrapped-leg config-file base-URL decision, the
   scenario matrix, and the sanctioned self-skips (OpenCode exit-code parity,
   P2-without-node:sqlite, read-antifidelity's F1) are in
   `docs/testing/differential-interactive.md` §13. Remains: OpenClaw's
   gateway sits outside the launcher's kernel-rung wrap (the gateway-family
   topology limit, §13.3 — kin to item 5), and OpenCode has no screen-level
   F1 scenario (its read tool_result envelope is inherently multi-line,
   §13.4).
4. **fsSync / view-sync posture and net-egress scenarios** — BUILT for both
   agents and both chokepoints (`fs-view-writeback`, `net-exfil-blocked`, now
   in the frozen lane). The machinery was agent-agnostic; the *runner* was
   not, and three things had to be built:
   - **A multi-turn scripted model.** The fake tier could script exactly ONE
     tool call per scenario (`hasToolResult → final text` matched first and
     unconditionally), which makes read→send, read→write and read→inspect
     inexpressible. Steps now fire on the tool_result COUNT — a
     symbolization-invariant discriminator, so the script cannot behave
     differently when the defense is working — and `LAST_TOOL_RESULT` lets step
     N+1 carry whatever step N actually returned (the symbol on the defended
     path; raw bytes if symbolization ever regressed, which the oracles then
     catch).
   - **The postures themselves** in the shared runner: view sync + P2 ViewMap +
     `syncToHuman`, and the net-proxy with `HTTP_PROXY` routing.
   - **`netEgressBlockSink` REQUIRES `fsSync`**, structurally: only under the
     twin is the payload a real symbol *on disk*, so uploading the FILE carries
     it. Without that the agent uploads raw bytes, the gate has nothing to
     withhold, and the scenario goes green having proven nothing.
5. **OpenClaw's native plugin chokepoint** — OpenClaw is the one agent where the
   context chokepoint can sit *inside* the process (the DUALVIEW plugin) rather
   than at the proxy. This harness deliberately tests the **proxy** path, so the
   result is comparable with the other three agents. Plugin-path coverage is a
   separate, additive suite.
6. **Version pinning.** OpenCode's `dev` branch carries a v2 provider config
   (`npm` moves under `api.package`, headers under `request.headers`). v1.18.13
   parses the v1 shape we emit, but the pin is load-bearing — re-verify §2.2 on
   any major bump.
7. **The per-agent gate surface — BUILT (2026-09-27).** Session-keyed specs
   (item 1) made CLASSIFICATION per agent, but the proxy's model-context GATES
   stayed keyed on Claude Code's names: the exec gate read `Bash.command`, the
   net gate and session watermark `WebFetch`/`WebSearch`, the sensitive-path
   gate, the derived on-disk label and the view map `Read.file_path` and kin,
   and the exec-output legs (plan 10 `callTaint`, the symbol-twin note) and the
   handling prompt's exec capability `Bash`. Under `mandu opencode` /
   `mandu openclaw` none of them fired: a live OpenCode drill sent
   `bash -c "$MDU:bash[…]"` with no exec gate decision, and in the default
   `secrets` mode (integrity OFF) an OpenCode `bash` result that read a secret
   was never taint-checked. The invariant itself held in `injection`/`full`
   (the shell result is UNTRUSTED under both agents' specs, so it was
   symbolized; an unresolved `$MDU:` in a shell expands to nothing), so the
   exposure was the gates' OWN protections: exec-position symbols, symbol
   egress in a fetch URL, the HIGH-session network block, sensitive paths, and
   the `secrets`-mode shell leg.

   **The fix:** the arbiter owns one gate table per agent next to its inbound
   spec (`arbiter/policy/tool-gate-surface.ts`: `exec` tool → command field,
   `execOutput`, `net` tool → destination + symbol field, `paths` tool →
   fields + mode), keyed by the same `InboundSpecId`, and answers it per
   session over a new read-only IPC op, **`gateSurface`**, with the SAME
   resolution classification uses (bound spec, else the global one). The proxy
   caches it per session (30 s, `src/gate-surface.ts`) and passes it to every
   gate. Names and fields were read OFF THE WIRE (the `tools[]` of a real
   request, opencode 1.18.32 / openclaw 2026.6.35; pinned by
   `arbiter/test/fixtures/agent-tool-schemas-2026-09-27.json`): OpenCode
   `bash.command`, `webfetch.url`, `websearch.query` (registry-conditional,
   off on that wire: pinned by a static read of the 1.18.13 binary,
   `opencode-websearch-2026-10-17.json`, and by OpenCode 2.0.23's capture),
   `read/write/edit.filePath`,
   `glob/grep.path`; OpenClaw `exec.command`, `process` (exec output),
   `web_fetch.url`, `web_search.query`, `read/write/edit.path` (+ the
   `file_path` alias).

   Two more parts since (supported-agents.md §2.1): `dispatch` (a tool that
   runs another tool, OpenClaw's `tool_call`, gated as the tool it runs) and
   `refuse` (tool → reason: OpenClaw's `terminal`, `automations`/`cron`,
   `gateway`, `plugins`, `secrets`, `portal` and `nodes` act outside every
   Mandu chokepoint, so the proxy replaces the call's input with
   `{action: "mandu-refused: <why>"}`, which the tool's own schema rejects).
   An arbiter that predates either part answers none, and the proxy applies
   the union's.

   **OpenCode 2 (2026-10-05, supported-agents.md §2.3).** One `opencode`
   table serves both generations: OpenCode 2.0.23's wire
   (`arbiter/test/fixtures/opencode2-tool-surface-2026-10-05.json`, the
   `tools[]` and every tool's result) adds `shell.command` (exec and exec
   output, `shell.workdir` a path read), `read/write/edit.path` beside 1.x's
   `filePath`, the `execute` code-mode tool as a refusing dispatcher, and
   three refused forms (`refuseArgs`): `shell{background}`,
   `subagent{background}` (their output returns later as a user text, past
   every tool_result leg) and `subagent{model}`. A refused form's rule
   compares a boolean as "true" / "false", so `background: false` passes.
   Proof: `arbiter/test/unit/{tool-gate-surface,opencode2-inbound}.test.ts`,
   `interceptors/anthropic-proxy/test/component/opencode2-gates.test.ts`,
   `tests/stack/opencode2-gate-surface.test.ts` (`secrets` mode, the real
   arbiter, the production adapter, an unreachable arbiter).

   **The residue fields (supported-agents.md §2.1).** Three
   optional shapes close the paths and destinations the first tables missed:
   - a net entry's **`alsoDestinations`**: further fields naming where the
     call goes, each a URL string or an array of them (OpenClaw `browser.url`,
     the fallback for `targetUrl`; `image.image` / `image.images`;
     `view_image.path` / `view_image.paths`). The session leg asks once per
     distinct host, plus the primary field's destination (or none), the
     per-symbol leg judges each string at its own host, and a block rewrites
     every such field present (or refuses the whole input under `block:
     "refuse"`);
   - a path entry's values may be **arrays** (every string element gated, a
     denied one becomes the sentinel in a copy of the array; the derived label
     reads string fields only), and **`refs: "media"`** reads them as
     OpenClaw's media references (`@`, `MEDIA:` and `file:` forms resolved to
     the path, http(s) / `data:` / `media://` skipped for the net gate);
     `exec.workdir` and OpenCode `bash.workdir` are path reads, and a denied
     workdir also blocks the command;
   - a **`patch`** table (tool → `{field, format: "apply-patch"}`; OpenClaw
     `apply_patch.input`): the proxy parses the file headers with a port of
     OpenClaw's parser (`src/apply-patch.ts`), puts every header path to the
     sensitive-path gate as a write and every written one to the derived
     label, and the view map moves header paths only;
   - an **`upload`** table (tool → an `UploadKind`; Claude Code's
     `DesignSync: "claude-design-sync"`, 2.1.292), for a tool that reads a
     local file itself and sends it off the machine: `upload-gate.ts` runs
     the net legs over every string the call sends (at `claude.ai`),
     refuses a plan without an absolute `localDir`, and puts every
     `files[].localPath` to the arbiter's `fileUploadDecision`; any block
     refuses the whole call (supported-agents.md §2, "Claude Code
     2.1.292"). Claude Code's interactive Artifact tools are on it too
     (2026-10-09): `Artifact: "claude-artifact"` (a publish's `file_path`,
     `files` sources against an absolute `root`, `file_paths`),
     `ArtifactData: "claude-artifact-data"` (`file_path`,
     `writes[].file_path`) and `ArtifactComments: "claude-artifact-comments"`
     (the net legs only); a path relative to the working directory refuses
     the call (`proxy:upload-relative-path`; supported-agents.md §2, "Claude
     Code 2.1.295"). OpenClaw's senders are on it since 2026-10-17:
     `message: "openclaw-message"` (every media source OpenClaw reads,
     `attachments[]` included, asked with no host: a chat channel is no host
     a binding can name), `view_image` / `image` / `pdf` / the generators:
     `"openclaw-media"` (their media path fields, asked `toModel`: a file at
     `any-model` may go) and `browser: "openclaw-browser-upload"` (an
     upload's `paths`); a relative reference is placed against the launch
     directory where the surface has `relativeBase` and the launcher named
     it, else refused (supported-agents.md §2.1, "Tools that send a local
     file"). An arbiter that predates the table answers none, and the
     proxy applies the union's;
   - a **`replyMedia`** kind (`"openclaw-media-lines"` on OpenClaw's table,
     2026-10-17): the agent attaches the files a `MEDIA:` line of the
     model's REPLY TEXT names, with no tool call. The proxy reads every
     response's text (`reply-media.ts`, `reply-media-stream.ts`; Messages,
     Chat Completions and Responses, streamed or buffered), judges each
     canonical line's references with `fileUploadDecision` (no host, tool
     `MEDIA`) and neutralizes every other place a directive could form
     after OpenClaw strips markup (supported-agents.md §2.1, "Files named in
     the reply"). A resolved surface always carries the field (`null` for
     an agent without it), so an arbiter that predates it (the field
     absent) gets the union's, which reads every reply.

   Fail-closed rules: a further destination the gate cannot read (neither a
   string nor an array) blocks the call, so does a call naming more than 20
   hosts, a patch that does not parse or touches a denied path is refused
   whole (`{action: "mandu-refused: <why>"}`, which fails `apply_patch`'s
   required `input`), and an arbiter that predates the `patch` table answers
   none, so the proxy applies the union's (every other malformed part still
   rejects the whole answer). Proof: `arbiter/test/unit/tool-gate-surface.test.ts`,
   `interceptors/anthropic-proxy/test/unit/{apply-patch,net-gate,fs-gate,view-map,gate-surface}.test.ts`,
   `interceptors/anthropic-proxy/test/component/openclaw-gate-residue.test.ts` and
   `tests/stack/openclaw-gate-residue.test.ts` (`secrets` mode,
   the real arbiter, the production adapter, and an unreachable arbiter).

   **The relative base (fs-sync.md §1.4.1).** A surface's
   optional **`relativeBase: "launch"`** says the agent resolves a relative
   path in a gated field against the directory it started in (OpenCode; and
   OpenClaw, whose workspace the launcher pins there for the local shapes).
   The proxy then joins it to `MANDU_AGENT_CWD` (the HumanView start
   directory the launcher names, `agentStartDir`, only when the agent's argv
   cannot have moved it; a listening proxy naming another base is not reused) and gates the
   absolute path, and the derived label keys a relative write there. Absent
   (Claude Code, the union, an older arbiter), or no directory named (an
   OpenCode argv that moves it, an OpenClaw Gateway / wrapper / `--agent`
   launch): the base is unknown,
   a relative path escaping it with `..` is denied (`proxy:relative-escape`),
   one under it is not gated at the proxy. Any other value rejects the whole
   answer. The media providers' reference arrays (`pdf.pdfs`,
   `*_generate.images`, `video_generate.videos` / `audioRefs`) are path
   fields and further destinations in the same change.

   **Fail-closed defaults.** A spec with no gate table (`fail-closed`, the
   AgentDojo specs, an unknown id bound fail-closed) gets the UNION of every
   agent's table, never less than Claude Code's. If the arbiter predates the op,
   answers a malformed shape (any bad part rejects the whole answer), or does
   not answer within 3 s, the proxy falls back to the SAME union for that
   request (a mirror of the arbiter's table in `src/gate-surface.ts`, pinned
   equal by a parity test) and asks again next time: an OpenCode / OpenClaw
   session keeps its gates exactly when the arbiter misbehaves, and for a
   Claude Code session the union is a no-op (the names it adds are lowercase /
   snake_case and never appear on Claude Code's wire). Claude Code's table
   stays the per-gate default for a caller that passes no surface, also
   pinned to the arbiter's.

   **Proof:** `tests/stack/agent-gate-surface.test.ts` (real
   arbiter, real IPC, the PRODUCTION adapter; per agent: ingress symbolized,
   the symbol in command position → exit-77 sentinel, in the fetch URL →
   blocked host, a sensitive read path → `/mandu/denied`; the union default;
   an arbiter without the op still gates OpenCode `bash`; proxy fallback ↔
   arbiter union and proxy ↔ arbiter Claude table parity), the parity suite's new
   `gateSurface` leg, `interceptors/anthropic-proxy/test/component/agent-gate-surface.test.ts`
   (exec, `callTaint` masking and the twin note on OpenCode `bash`, each with a
   Claude-surface control; a throwing / malformed / absent `gateSurface` still
   gates `bash`), and the unit suites on both sides.

## 8. The OpenClaw plugin U-LLM channel

Closes §7 item 2: `interceptors/openclaw-inspect-plugin/` mounts `inspect_symbol`
for OpenClaw as a **native plugin tool**.

### 8.1 Why a plugin, not MCP

OpenClaw has no MCP client (its ACP path explicitly rejects `mcpServers`), so
the inspect-mcp stdio server — how Claude Code and OpenCode mount the U-LLM
channel — cannot attach. OpenClaw's own extension point is the plugin API
(`api.registerTool`), the same mechanism the reference DUALVIEW plugin uses for
its `inspect_symbol` (`adfi-openclaw/plugin/dualview/index.ts`). This package is
therefore a **reverse lift**: the OpenClaw *shape* (registrar scaffold, the
`AnyAgentTool` object, the module/manifest format) comes from the reference,
while the *security core stays Mandu's own*
`interceptors/inspect-mcp/src/inspect-symbol.ts` — `inspectSymbol()` (resolve
via arbiter → quarantined U-LLM → **re-symbolize** → emit, fail-closed) is
imported and called with the same deps the MCP server injects
(`ArbiterClientAdapter` over the real arbiter IPC client, `ullm-client.ts`, a
per-process `triageCache`). Only the mount layer is new; there is no second
U-LLM caller and no path around re-symbolization. One enabling refactor: the
pure U-LLM transport selection moved out of inspect-mcp's `server-main.ts`
(which sets `process.title` at import — unimportable from inside the OpenClaw
gateway) into the side-effect-free `src/ullm-config.ts`; `server-main`
re-exports it unchanged.

### 8.2 Module + manifest format (loader facts, probe-verified)

- `openclaw.plugin.json` is **mandatory** and must carry both `id`
  (`mandu-inspect`) and `configSchema` — the loader hard-fails "missing
  config schema" otherwise (`openclaw-src/src/plugins/manifest.ts`,
  `loader.ts`). Plugin config comes from `plugins.entries.<id>.config` and is
  JSON-schema-validated *before* `register()` runs.
- The module loads through **jiti**, so a raw `.ts` entry works —
  `package.json` carries `"main": "index.ts"` +
  `"openclaw": {"extensions": ["./index.ts"]}` (mirroring the reference).
  Cross-package `./x.js` → `x.ts` specifier resolution under jiti is verified
  (the reference plugin itself relies on it); the plugin's imports into
  `../inspect-mcp/src/` load fine at mount time.
- The default export is a definition object; `register(api)` must be
  **synchronous** — the loader *ignores* async registration (a returned
  promise only warns). Hence the wiring split: config resolution + U-LLM
  transport selection are sync-and-throwing at register (a throw fails the
  plugin load **loudly** — the fail-closed misconfiguration behavior), while
  the arbiter IPC connect is lazy-on-first-call; an unreachable arbiter makes
  the tool return a refusal (never run symbol-less), and a failed connect is
  retried on the next call.
- **`contracts.tools` (OpenClaw ≥ 2026.6).** A plugin tool loads only when the
  manifest declares it: `"contracts": {"tools": ["inspect_symbol"]}`. Without
  it, 2026.6.35 logged `inspect_symbol registered` and then dropped the tool
  from the model's list (`tools.profile … allowlist contains unknown entries`),
  so the U-LLM channel silently vanished (probe 2026-09-27). The 2026.3 loader
  ignores the key. Pinned by the plugin's `manifest.test.ts`.

### 8.3 Mounting for a one-shot `openclaw agent --local` run

```jsonc
{
  "plugins": {
    "load": { "paths": ["<repo>/interceptors/openclaw-inspect-plugin"] },
    "entries": {
      "mandu-inspect": {
        "enabled": true,
        "config": {
          "arbiterSock": "<arbiter UDS path>",   // or env MANDU_ARBITER_SOCK
          "scopeId": "<MANDU_SCOPE_ID>",       // must match the proxy's scope
          "ullmMode": "cli",                      // auto | api | cli
          "ullmBinary": "claude"
        }
      }
    }
  }
}
```

`plugins.load.paths` discovery gives origin `config` ⇒ enabled by default
(`config-state.ts resolveEnableState`) — but if `plugins.allow` is non-empty it
must include `mandu-inspect` (the allow check outranks `entries.*.enabled`).
Every config key falls back to env: `MANDU_ARBITER_SOCK`, `MANDU_SCOPE_ID`,
`MANDU_ULLM_{MODE,BINARY,MODEL,BASE_URL,FORWARDER,API_KEY}`. Two
**deliberate divergences** from inspect-mcp's env contract: the U-LLM base URL
and API key are read only from the dedicated `MANDU_ULLM_*` names, never the
host process's `ANTHROPIC_BASE_URL` / `ANTHROPIC_API_KEY` — the plugin runs
*inside* the gateway, where those are the instrumented proxy and the T-LLM
credential (a dummy in this harness). `assertNonProxyBaseUrl`'s loopback
refusal and `CliUllmClient.buildChildEnv`'s env scrub stay on the path
unchanged.

**The non-optional-registration gotcha:** `api.registerTool(factory,
{optional: true})` — what the reference does — silently *filters the tool out*
unless the run's effective tool allowlist names it
(`openclaw-src/src/plugins/tools.ts isOptionalToolAllowed`), which under this
harness's `tools.profile` config would drop `inspect_symbol` with no error.
The plugin registers with **no options** (non-optional), so the tool always
reaches the model's `tools[]`.

### 8.4 The result-shape contract (what the arbiter may trust)

The arbiter trusts an inspect result only in the pure-symbolic success shape
(`claude-code-inbound.ts isPureSymbolicInspectResult`). OpenClaw tools have no
`structuredContent`, so the plugin returns **two text blocks** —
`[the bare $MDU:* token][the JSON envelope
{result_symbol, model, content_kind, next_step?}]` — which pi-ai forwards
verbatim as `tool_result` content blocks and the proxy flattens to
`<token>{json}`: exactly accepted form 3 of the existing grammar. `next_step`
appears only for failure kinds and stays **byte-identical** to
`inspect-symbol.ts NEXT_STEP_BY_KIND` (exact-match gated). Error/refusal
results are a single prose block — deliberately **not** trusted-shaped, so
they stay on the fail-closed symbolize path. The unit suite asserts all of
this against a local replica of the arbiter grammar (a drift tripwire).

The bare name **`inspect_symbol`** (OpenClaw plugin tools have no
`mcp__<server>__` prefix) is recognized by the exact-name set in
`arbiter/policy/inspect-tool.ts` and mapped spec-independently
(`tool-inbound.ts getToolInboundSpec`), so it reaches the same pure-symbolic
shape rule as the MCP spellings under every inbound spec.

### 8.5 `declassify_symbol` on OpenCode and OpenClaw (2026-09-29)

Rung 3, the in-context read (`confidentiality.md` §4, the session watermark),
is mounted for both agents with Claude Code's semantics unchanged, because
the arbiter makes every decision and neither mount adds one:

| Agent | Mount | Name the model sees |
|---|---|---|
| Claude Code | inspect-mcp stdio server | `mcp__mandu-inspect__declassify_symbol` |
| OpenCode | the same server (`mcp.mandu-inspect`, `type: "local"`) | `mandu-inspect_declassify_symbol` |
| OpenClaw | the plugin (`interceptors/openclaw-inspect-plugin/src/declassify-tool.ts`) | `declassify_symbol` |

- **One relay.** `interceptors/inspect-mcp/src/declassify-symbol.ts` is the
  relay the MCP server and the plugin tool both call (it moved there,
  unchanged, from `mcp-server.ts`). It asks the arbiter's `declassifySymbol`
  op and returns the value only on an explicit allow, as one text block: a
  one-line `[DECLASSIFIED …]` notice, a blank line, the value. Refusals,
  a missing op and an arbiter error return an error with no content. There
  is no fallback to `resolve`.
- **The arbiter decides**, as for Claude Code (`declassify.ts`): an untrusted,
  `no-model`, or (under an external model) `local-model` datum is refused
  with no approval path; in a session that has ingested untrusted data the
  read is queued for the human (`model_context:in-context-read` in the
  approval queue) and a human "no" is a refusal; an allowed read raises the
  session watermark to the datum's level before the value is handed over.
- **The result reaches the model unmasked** through the server's release
  check (`server.ts declassifyResultTrusted`), which is keyed on the tool
  name set in `inspect-tool.ts` (all three spellings above) and on the value
  the arbiter released to that session. The inbound mapping is
  spec-independent (`tool-inbound.ts getToolInboundSpec`): each spelling
  resolves to the same whole-result UNTRUSTED object Claude Code's `mcp__`
  fallback gives, so the tool is not "unknown" on the session-health chip,
  and the input scan for labeled paths stays on for all three.
- **A release's session is the Mandu scope, and only it, on every mount.**
  The arbiter raises the watermark on the session the call names and the
  model proxy gates the launcher's scope, so a release watermarked on any
  other session would leave the gated one looking clean while the model
  holds the secret: a silent leak. `declassify_symbol` therefore refuses,
  before the arbiter is asked (nothing queued, nothing released), when the
  scope is missing: on OpenClaw without `scopeId` / `MANDU_SCOPE_ID`, and on
  the inspect-mcp stdio server (Claude Code, OpenCode, Codex) without a
  non-blank `MANDU_SCOPE_ID` (it must not fall back to the session
  `"inspect-mcp"` and release under it). The
  relay (`declassify-symbol.ts`) refuses an absent or blank session and the
  server's fallback name alike.
- **`inspect_symbol` keeps its fallback, deliberately.** Without a scope the
  stdio server files an inspect under `"inspect-mcp"`
  (`inspect-symbol.ts INSPECT_FALLBACK_SESSION`) and the OpenClaw plugin under
  OpenClaw's session key. An inspect releases nothing to the model (its
  answer comes back as a symbol and keeps the source's label), so a missing
  scope only mis-files its events and re-symbolized result; refusing it would
  cost the quarantine and buy no confidentiality. The launcher always sets
  the scope, so the fallback is for hand-run servers.
- **OpenClaw's allowlist.** The manifest's `contracts.tools` names both
  tools, and the launcher's wrap config (and the harness builder) lifts both
  through `tools.alsoAllow`.
- **Agent-level prompts differ.** Claude Code's launcher pre-allows only
  `inspect_symbol`, so Claude Code also asks before each `declassify_symbol`
  call. OpenCode runs MCP tools without asking at its default permissions and
  OpenClaw has no per-call prompt for plugin tools. That prompt is the
  agent's, not Mandu's: the human gate that matters is the arbiter's approval
  queue, which is identical on all three.
- **Tests.** `interceptors/inspect-mcp/test/unit/declassify-symbol.test.ts`
  (the relay), `interceptors/openclaw-inspect-plugin/test/unit/declassify-tool.test.ts`
  (the plugin tool), `arbiter/test/unit/tool-surface.test.ts` (the mapping),
  and `tests/stack/declassify-agents.test.ts`: each agent's
  production mount (the real stdio server for OpenCode, the real registrar
  and arbiter client for OpenClaw) over a real arbiter and the real model
  proxy, covering a read the human approves, one the human denies, an
  unreachable arbiter, and a stdio server started with no (or a blank)
  `MANDU_SCOPE_ID`, which refuses while the same server with the scope
  releases.
- **Probed on the real agents (2026-09-29, scripted upstream, no model):**
  with the channel mounted, opencode 1.18.32 advertised
  `mandu-inspect_declassify_symbol` and openclaw 2026.6.35 advertised
  `declassify_symbol` in the request's `tools[]`, each beside its
  `inspect_symbol`.
- **Not yet run live.** The drills conf-declassify-refused-untrusted,
  conf-declassify-confines-session and conf-derived-label-next-session are
  runnable on both agents and flagged "not yet run live" until a live model
  run grades them (that needs an API key). The runner prints the flag at the
  start of a run, and the dashboard's Drills picker shows it per agent
  (dashboard.md §4.22, "Not yet run live").
- **Where the per-agent facts live.** Which drills an agent cannot run, and
  which it can but no live model has graded there, are the drills' own data
  in the drill catalog's area files: each drill's
  `agents.openclaw` / `agents.opencode` (`true`, or the reason it cannot run
  there) and `live.unverified.<agent>`. What stays in the per-agent target
  modules is per check kind, not per drill: `*_UNOBSERVABLE`, the checks
  whose evidence the agent cannot produce (graded SKIP).

### 8.6 OpenClaw 2026.9.x: Tool Search, the runtime-context message, its own redaction (2026-10-09)

Three changes in OpenClaw 2026.9.x (found on 2026.9.6 and 2026.9.9; the CI
pin 2026.7.1-2 has none of them) broke this harness and the replay lanes:

- **Tool Search hides plugin tools.** 2026.9.x turns Tool Search on by default
  (`tools.toolSearch` unset reads as mode `tools`): every catalog-eligible
  tool other than the core coding primitives is moved behind `tool_search` /
  `tool_describe` / `tool_call`, plugin tools included (the run logs
  `tool-search: cataloged N tools behind compact prompt surface`). A call to
  `inspect_symbol` by name then fails `Tool inspect_symbol not found`, and the
  handling prompt names the tool by that name. A user would hit it, so the fix
  is the plugin's: both tools carry `catalogMode: "direct-only"`, the field
  OpenClaw's own `computer` tool uses (src/agents/tool-search.ts
  `shouldCatalogTool`), which keeps a tool model-visible by its own name.
  Releases without Tool Search ignore the field. (A `tool_call` of a cataloged
  tool is gated as its inner tool either way: supported-agents.md §2.1.)
- **The runtime-context message.** After the typed prompt, 2026.9.x sends a
  user message of its own that is only a `<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>>`
  … `<<<END_OPENCLAW_INTERNAL_CONTEXT>>>` block (active exec sessions,
  subagents). The replay engine took it for the latest user text and failed
  every OpenClaw replay with "matches no prompt step". The engine now cuts
  those blocks out of a user text (replay-engine.ts
  `stripOpenclawInternalContext`): only the exact delimiters, each alone on
  its line, nested as OpenClaw nests them. OpenClaw escapes the delimiters in
  typed text, so nothing typed is cut, and no other agent's text changes. The
  recorder reads requests through the same function.
- **OpenClaw redacts key-shaped values itself.** 2026.9.x masks key-shaped
  values in every tool result before the model sees it
  (`redactModelVisibleToolPayloadText`, mode `tools`, no off switch): the conf
  scenarios' `PARTNER_API_TOKEN=sk-live-<canary>` reached the wire, and so
  Mandu, as `sk-liv…<last 4>`. Mandu then symbolized the redacted text, so the
  human reveal returned it (`conf-human-reveal` failed), and the control leg's
  canary never reached the model or the sink. This is OpenClaw's own masking,
  in-process and before the wire, so Mandu can neither cause nor undo it. The
  conf scenarios' OpenClaw spelling seeds a value OpenClaw leaves alone
  (`ConfToolSpelling.fileBody`), so the label is again the only thing that
  protects it. A second rule masks by NAME, not shape (measured 2026-10-09
  on 2026.9.9 with a scripted model and no Mandu): the `read` tool's result
  for a dotenv path (`.env`, `.env.*`, `*.env`) has every secret-named
  assignment masked (`API_KEY=***`, `DB_PASSWORD=hunter…521B`) whatever the
  value looks like; the same file through `exec cat` and the same lines in
  another file are not. 2026.7.1-2 masks neither. So no fixture value keeps
  a check on a `read` of `.env` exercised on 2026.9, and the drills that do
  that are not replayed on OpenClaw from 2026.9 on (`replay.skipFrom`).

## 9. The launcher wrap: `--target openclaw|opencode` (SHIPPED 2026-08-06)

The harness (§3) always provisioned these agents correctly — it writes each
agent's OWN config file. The *launcher* did not: `mandu -- openclaw agent …`
inferred target `claude` (any non-codex argv[0] did) and composed an
`ANTHROPIC_BASE_URL` env delta both agents are probe-verified to IGNORE
(§2.1/§2.2 — config-file routed). Every rung came up, nothing failed, no
`tool_result` was ever symbolized: a protected-looking session that was not
protected. This section is the product-side close of that gap
(`launcher/src/services/agent-config.ts`; differential-interactive.md §13.6).

**The contract.** `--target` accepts all four agents; inference recognizes
exactly the four known basenames and REFUSES anything else, naming the escape
hatch (`--target …`). A wrong guess is the one shape the launcher must never
produce, so there is no default. (A POSIX shell is the one non-agent
basename inferred, as the plain-command `shell` target; see §9.1.)

**Delivery per target** (types.ts `wireOf` — claude/openclaw/opencode share
the anthropic-proxy, codex the openai-proxy):

| target | routing delivery |
|---|---|
| claude | env `ANTHROPIC_BASE_URL` + packed one-header session id (unchanged) |
| codex | `-c` argv splice (unchanged) |
| openclaw | generated config via `OPENCLAW_CONFIG_PATH` |
| opencode | generated config via `OPENCODE_CONFIG` |

**Wrap-mode config, not hermetic-mode.** Adapted from §3's builders with the
differences the wrap demands:

- the user's OWN config (the agent's own resolution order: env override, else
  `~/.openclaw/openclaw.json` / `~/.config/opencode/opencode.json`) is read
  and deep-merged UNDER our routing override — model choice, credentials and
  settings survive; an unparseable user config (OpenClaw's are JSON5) degrades
  to ours-only with a loud warning for OpenCode (protection intact,
  convenience lost), and REFUSES the launch for OpenClaw, whose built-in
  default model without that config is not routed (below);
- NO dummy key is injected — the agent authenticates exactly as unwrapped;
- opencode overrides the BUILT-IN `anthropic` provider's `options`
  (baseURL/headers) instead of minting a custom provider, so the user's
  `anthropic/<model>` selection keeps working. PROBE-VERIFIED 2026-08-06 in
  the CI container (opencode 1.18.13): both the title side call and the
  agentic call landed on the override URL with our session header, model
  preserved. (The harness's custom-provider choice remains right for ITS
  hermetic tier — §2.2's rationale.)
- the U-LLM inspect channel mounts in each agent's own spelling: the §8
  plugin block (+ `tools.alsoAllow`) for OpenClaw, the inspect-mcp server in
  the config's `mcp` section for OpenCode. No workspace `.mcp.json` is
  written for either (no agent reads it). A missing plugin dir degrades
  loudly (utility-class); `--no-mcp` drops the channel as for claude.
- OpenClaw's override names `api: "anthropic-messages"` (without it 2026.6.35
  infers `openai-completions` and POSTs `/chat/completions`) and carries the
  user's own `models.providers.anthropic.models` entries, cleaned to the
  fields that describe a model (`openclawUserAnthropicModels`: id, name,
  limits, cost, reasoning, input, params, compat, …). A per-model `baseUrl`,
  `api` or `headers` wins over the provider's (probe-verified on 2026.6.35
  and 2026.7.1: an entry's `baseUrl` sent the turn there), so they are
  dropped with one `WARNING` line. The launcher adds no entries of its own
  and keeps no model table: OpenClaw's catalog supplies the limits for a
  catalog model, and an entry would replace that metadata (on 2026.3.12 an
  entry turned extended thinking off). The override never writes
  `models: []`, which would replace the user's list wholesale.

  **Why a user's entries matter (`os-test-matrix.md §10` §14.1).** A model outside OpenClaw's catalog runs only when listed with its
  limits. Probed on 2026.3.12, 2026.6.35, 2026.7.1 and 2026.9.6 against a
  scripted model, unwrapped (a CONNECT stand-in for api.anthropic.com) and
  under the override: for `claude-sonnet-4-5`, which 2026.6.35 and later no
  longer list, unwrapped OpenClaw answers "Unknown model", while under the
  override 2026.6.35 resolves it with default limits and 2026.7.1 fails every
  turn "Anthropic Messages transport requires a positive maxTokens value".
  Catalog models (`claude-sonnet-4-6`, `claude-opus-4-8`) send the same
  `max_tokens` and `thinking` wrapped and unwrapped on every version (one
  exception: 2026.9.6 adds a `thinking.block_binding` field only toward the
  official endpoint).

**Every model must be routed.** The base override points only the agent's
`anthropic` provider at the proxy, so a model from any other provider would go
straight to that provider with tool results unmasked.
Probe-verified with a URL-logging stand-in model (OpenClaw 2026.7.1, OpenCode
1.18.13 and 1.18.32): `mandu --mode full` with `openai/gpt-5.5` (OpenClaw) or
`-m openai/gpt-5` (OpenCode) delivered `function_call_output: "# notes\n
IPIMARKER…"` raw while the banner said "untrusted text masked"; and OpenClaw
with no model configured ran its built-in default, `openai/gpt-5.5` on 2026.6
and later (`anthropic/claude-opus-4-6` on 2026.3.12), straight to
`https://api.openai.com/v1/responses` under the default posture (the connect
guard's permissive fallback admits any `:443` host, and `NO_PROXY` lists
api.openai.com) — the probes that motivated this section. In `secrets` mode a registered credential file still reached
the model as its twin: the file layer does not depend on the route. The same
class as the Codex `exec -c` bypass (`codex-argv.ts`). Three layers close it:

- **Launch refusal** (`launcher/src/agent-model-route.ts`, run.ts right after
  parse, before anything starts). Every model the agent can run from its own
  config and argv must name a provider Mandu routes (`anthropic`, or an
  OpenAI-family provider, "Other providers through the model proxy" below):
  OpenClaw's primary,
  fallbacks, per-agent, sub-agent, heartbeat, compaction and memory-flush
  models (every `model` key under `agents`, aliases resolved through
  `agents.defaults.models`; `memorySearch.model` is an embedding id and is
  skipped), Active Memory's recall model
  (`plugins.entries.active-memory.config.model` and `.modelFallback`, which
  read the conversation) and `agent --model` (which replaces the configured
  primary; `-m` is OpenClaw's message flag); OpenCode's `model`,
  `small_model`, `agent.*.model`, `mode.*.model` and `-m/--model`. OpenClaw
  with no model configured, or with a config the launcher cannot read, is
  refused too: its built-in default depends on the release. The config is
  read as JSON5 (`launcher/src/services/json5.ts`, no runtime dependency), as
  OpenClaw reads it, with its `$include` files resolved the way OpenClaw
  resolves them (`launcher/src/services/openclaw-include.ts`):
  a path relative to the file that names it, inside the config directory or
  an `OPENCLAW_INCLUDE_ROOTS` root (lexically and after symlinks), a regular
  file of at most 2 MiB with one link, at most 10 nested levels, no cycle;
  an array merges left to right, sibling keys merge over the included
  object, objects recurse and arrays concatenate. An include OpenClaw would
  refuse makes the config unreadable, so the launch is refused, naming the
  include; the resolver is stricter in two places (an `OPENCLAW_INCLUDE_ROOTS`
  entry that is neither absolute nor `~`-relative admits nothing, and a
  `__proto__` key anywhere is refused). The per-run config is written
  RESOLVED, with no `$include` left: a relative include would not resolve
  from the scope run dir, and the run then uses exactly the config the check
  read, so a detail read differently can cost a setting but never let a
  model around the check. Differential check against OpenClaw 2026.7.1 and
  2026.9.6 (`openclaw config get` / `config validate`): the
  same resolved models for a split config, and the same refusals (outside
  the directory, hardlink, cycle, missing file, sibling keys beside a
  non-object include); a symlink whose target stays inside is accepted by
  both. The refusal names each offending reference and where it came
  from. A wrapper argv under `--target` is not checked, as for Codex.
- **OpenCode fence.** The override sets `enabled_providers: ["anthropic"]`
  (plus each routed OpenAI-family provider, below),
  and delivers it with the anthropic endpoint in `OPENCODE_CONFIG_CONTENT`
  too (merged over the user's own value). OpenCode ranks a project's
  `opencode.json` / `.opencode/opencode.json` ABOVE the `OPENCODE_CONFIG`
  file: a repository's own config re-pointed `provider.anthropic.options.
  baseURL` and every turn left through it, around the proxy (probe-verified
  on 1.18.13 and 1.18.32; the fresh-agents leg with such a project file
  fails without the env var and passes with it). `OPENCODE_CONFIG_CONTENT`
  outranks the project config: a project that re-enables `openai` and a
  custom `@ai-sdk/anthropic` provider stayed fenced, and a fenced model fails
  before any request. So an unset OpenCode model is provably routed and is
  not refused. OpenCode 2 ranks provider RULES the other way (the lowest
  layer's rule wins) and lets a model's own endpoint beat its provider's:
  the 2.x fence and the checks that make it hold are in
  supported-agents.md §2.3 part 4.
- **OpenClaw fence.** The run config's `agents.defaults.models` (OpenClaw's
  allowlist for `/model` and session overrides) is narrowed to
  `{"anthropic/*": {}}` (plus `"<id>/*"` for each routed OpenAI-family
  provider, below) and the user's own entries for those providers, on the
  merged doc (`fenceOpenclawModelAllowlist`), for a model switched
  mid-session. Probed: 2026.6.35 and 2026.7.1 refuse `--model openai/gpt-5.5`
  ("is not allowed for agent main") and swap a non-anthropic primary for an
  allowed model; 2026.9.6 refuses the override but runs a non-anthropic
  primary; 2026.3.12 does not enforce the allowlist and runs normally with
  it. The refusal is therefore the guarantee; the fence narrows what a
  session can switch to.

**Other providers through the model proxy (BUILT).** The
refusal above stays for every provider Mandu cannot read, and an
OpenAI-family provider is now ROUTED instead. The wire APIs, read from the
published packages (`@openclaw/ai` 2026.9.6, OpenCode 1.18.32):

- OpenClaw's built-in `openai` provider speaks the Responses API
  (`api: "openai-responses"`); an OpenAI-compatible provider speaks Chat
  Completions (`api: "openai-completions"`); the ChatGPT login provider
  (`openai-codex`, `openai-chatgpt-responses`) speaks to chatgpt.com, also
  over a WebSocket.
- OpenCode's built-in `openai` provider speaks the Responses API
  (`@ai-sdk/openai`); an `@ai-sdk/openai-compatible` provider speaks Chat
  Completions. Its request base URL is the provider's `options.baseURL`,
  else the model's own API URL (so the provider option wins for every model
  of the provider).
- Goose's built-in `openai` provider (1.53.0, captured; supported-agents.md
  §5.6 "The openai provider") picks the wire per model on its default base
  path `v1/chat/completions`: the Responses API for gpt-5 / gpt-6 /
  o-series, Chat Completions otherwise; a custom base path pins one.

**Where it is gated: the anthropic-proxy, not the openai-proxy.** The
openai-proxy's gates are Codex's (`exec_command` / `cmd`, the JS script
cell), and every gate for OpenClaw's and OpenCode's tools (the per-session
gate surface, the `tool_call` dispatcher, the refused-tool and refused-form
tables, the exec / stdin / net / path / derived-label gates, the exec-output
legs and the unmapped-command backstop) lives in the anthropic-proxy, which
the launcher already runs for these sessions. So that proxy reads the two
OpenAI wires too, under one prefix, `/_mandu/openai/<provider id>`, and ONE
gate implementation serves every wire: a table added for OpenClaw is
enforced on all three by construction, with no mirrored copy to drift. The
parity oracle is `tests/stack/openai-wire-routing.test.ts`
(one table of calls gated over the Messages wire, Chat Completions and the
Responses API by the same proxy; the agent receives the same input on all
three).

- **Request** (`interceptors/anthropic-proxy/src/openai-wire.ts`). The
  OpenAI body is read as a Messages SHADOW: every tool result
  (`role: "tool"`, `function_call_output`) as a `tool_result` block, every
  call (`tool_calls[]`, `function_call`) as a `tool_use` block with its
  arguments parsed, the system text as `system` blocks, user and assistant
  text for the trusted-context haystack. `rewriteRequest`, the view map's
  reverse pass and the net-gate history run on the shadow unchanged; `apply`
  writes what they changed back onto a clone of the agent's own body by
  position (a result's content, a call's arguments, and a user text the
  prompt filter rewrote: a registered value as its symbol) and puts the
  handling
  prompt in the first system message (Chat) or `instructions` (Responses: a
  `previous_response_id` continuation does not inherit instructions). Every
  other field goes upstream as the agent sent it. Fail-closed (400, nothing
  sent) on a shape it does not read: a message role, an input item type
  (`custom_tool_call_output`, `local_shell_call_output`, …), a non-text
  system part; and on a tool the PROVIDER runs (a non-function `tools`
  entry such as `web_search` or `mcp`, `web_search_options`, OpenRouter's
  `plugins`, an `:online` model), whose results enter the model's context
  where no gate sees them. Two wire facts shaped it: OpenClaw's Chat
  transport sends a tool's IMAGES in the next user message ("Image(s) from
  tool result #N (name):"), so a user message right after tool results that
  carries a non-text part is read as that result's continuation (its parts
  join the result, which the rewrite then masks whole, and are dropped from
  the user message); and a Responses continuation carries results whose
  calls are not in the request, so the proxy remembers every call it
  released (by call id, bounded) and classifies the result as that tool.
  The operation may follow one `/v1` (`…/v1/chat/completions`,
  `…/v1/responses`): Goose keeps its default path so that it picks the
  wire per model, so its route's upstream is the provider's host and the
  `/v1` rides the path.
- **Response** (`openai-sse.ts`). A call's arguments arrive in pieces
  (`choices[].delta.tool_calls[]` by `index`; `function_call_arguments.delta`
  by item), and the agent acts on the assembled call, so each call is HELD
  until whole, gated by the SAME per-exchange transform the Messages wire
  uses (`toolInputTransform`), and released once: Chat as one synthetic
  chunk before the finishing chunk, Responses as the announcement (under the
  released name), one delta and `.done` (numbered from the upstream's own
  `sequence_number`s when it numbers its events: Goose's reader rejects an
  event without one), with every snapshot
  (`.output_item.done`, `.completed`) carrying the same gated arguments. The
  released arguments are always the canonical serialization of what the gate
  read, never the model's own bytes (an agent whose JSON reader differs from
  `JSON.parse` on a duplicate key could otherwise run what the gate did not
  see). Arguments that are not a JSON object rename the call
  `mandu_refused_unreadable_call` (no agent has it); a name that changes
  mid-stream, an unparseable chunk, or an output item a routed agent would
  execute that is not a function call (a custom, local-shell, computer or
  MCP call, which the request never declared) ends the stream with an error
  event. A buffered answer is gated whole, and one that does not parse is a
  502, never relayed. Released calls are recorded with the arbiter
  (`recordToolCall`) for the OS interceptors, as on the Messages wire.
- **Response text** (`text-repack.ts`, one module shared verbatim with
  openai-proxy). A `$MDU:` token
  split across two streamed text deltas (Chat `choices[0].delta.content`,
  Responses `response.output_text.delta` per item and content part) reaches
  the agent whole in one delta, as on the Messages wire
  (architecture-map.md §9 ①, "The text-delta repacker"). After the
  call gate; text byte-identical; no event added or dropped.
- **Routing** (`launcher/src/agent-model-route.ts` `agentModelPlan`,
  `services/agent-config.ts`, `services/context-proxy.ts`). A model is
  routed when its provider is: OpenClaw's built-in `openai` (base
  `https://api.openai.com/v1`) or a `models.providers.<id>` with a `baseUrl`
  and `api` `openai-completions` / `openai-responses`; OpenCode's built-in
  `openai` or a `provider.<id>` on `@ai-sdk/openai` / `@ai-sdk/openai-compatible`
  with a base URL. A base URL is https, or plain http only to a literal
  loopback address (the proxy's fetcher enforces the same rule). Only the
  providers some model reference names are routed. The run config points
  each at `<proxy>/_mandu/openai/<id>` with Mandu's session headers (OpenClaw:
  `baseUrl`, the `api` pinned, the user's model entries cleaned of `baseUrl`
  / `api` / `headers` as for anthropic; OpenCode: `options.baseURL`, in the
  file and in `OPENCODE_CONFIG_CONTENT`), and the fences admit exactly the
  routed providers (OpenClaw's allowlist `"<id>/*"`, OpenCode's
  `enabled_providers`). Goose's `openai` is routed by env instead
  (`launcher/src/goose-route.ts`): `OPENAI_HOST=<proxy>/_mandu/openai/openai`
  and `OPENAI_BASE_PATH`, the upstream resolved from the user's
  `OPENAI_HOST` / `OPENAI_BASE_URL` / `OPENAI_BASE_PATH` the way Goose
  resolves them. The proxy gets the real base URLs as
  `MANDU_OPENAI_UPSTREAMS` (plan-derived, explicitly unset otherwise; a
  listening proxy on a pinned port is never adopted, its routes being
  unknown), drops `x-mandu-*` headers before the provider, relays the
  agent's own credential, and refuses any other path under the prefix
  (`/embeddings`, the legacy `/completions`, a provider it was not given).
  Refused at launch: every other provider (named, with why), an OpenClaw
  provider with no `api` or `baseUrl`, and OpenCode signed in to OpenAI with
  a ChatGPT account (read from its auth.json): that login's fetch override
  rewrites Chat Completions requests to chatgpt.com whatever the base URL.
- **Tests.** `interceptors/anthropic-proxy/test/unit/{openai-wire,openai-sse}.test.ts`,
  `test/component/openai-route.test.ts` (the real proxy, a mock arbiter: masking,
  exec / dispatcher / refused tool / `host: node` gated on the Chat wire, a
  bash call on the Responses wire, a continuation, a symbol token split
  across text deltas on both wires, and every refusal with the provider
  receiving nothing); `launcher/test/unit/agent-model-route.test.ts`,
  `agent-config.test.ts`, `context-proxy.test.ts`; `launcher/test/component/agent-model-route.test.ts`
  (routed launches and refusals through `main()`);
  `tests/stack/openai-wire-routing.test.ts` (the real
  arbiter and the production adapter: injection mode on Chat, `secrets` on
  Responses, and the three-wire parity table). Goose's:
  `launcher/test/component/goose-openai-real.test.ts` (the real goose on
  both wires through `main()`) and `tests/stack/goose-openai-route.test.ts`
  (supported-agents.md §5.6).
- **Residue.** A routed OpenAI provider's other endpoints (OpenClaw's image
  generation, speech, transcription through `openai`) hit the prefix and are
  refused, so those tools fail under Mandu when that provider is routed (they
  are net-gated tools already, §2.1 of supported-agents.md). Providers
  with their own SDK (Google, Bedrock, Mistral's, xAI's) need a wire reader
  each and stay refused.

**OpenClaw embeddings fence** (`fenceOpenclawMemorySearch`, agent-config.ts). OpenClaw's
memory search embeds the memory files (`MEMORY.md`, `memory/*.md`) and each
query through its embedding provider, OpenAI by default, straight to that
provider. Probed with a URL-logging stand-in on 2026.3.12, 6.35,
7.1, 8.2 and 9.6 (every release, not only 2026.9): a `memory_search` call
sent the memory text verbatim to `/v1/embeddings`. Mandu routes only the
Anthropic model provider, so the run config switches the embeddings off:
every memory-search object in the merged doc gets `provider: "none"` and
`fallback: "none"` (an explicit `local` provider keeps its embeddings, which
stay on the machine), and `memory_search` ranks by keywords. OpenClaw
rejects a key its release does not know, so the spelling follows the
probed version (`plan.agentVersion`, from the launch's version check):
`memory.search` on 2026.8.1 and later, `agents.defaults.memorySearch` on
2026.6.35 through 2026.7.x (7.35 is the last); before 2026.6.35
(2026.3.12's provider enum has no `"none"`), for a version the launch could
not read, and for a prerelease of either boundary, the memory plugin slot is
set to `"none"` instead (accepted by every release from 2026.3.12 to
2026.9.6), which unloads the memory tools. A third-party memory plugin
(`memory-lancedb` embeds through its own config) has its slot set to
`"none"` on every release. Legacy `memorySearch` objects are fenced on
2026.8+ too, because OpenClaw's startup migration would carry their
provider to `memory.search`. A user's own embedding setting is named in a
WARNING line; the default provider is switched off quietly (a `--verbose`
line). With the fence, the same probe made no embeddings request on any of
the five releases, and `memory_search` still found the memory text by
keyword on 6.35, 7.1, 8.2 and 9.6.

**Fail-closed where it must be.** For these targets the generated file IS the
model-context chokepoint wiring, so a config WRITE failure is
`failClosedFatal` — `--best-effort` cannot bless it (unlike a dead proxy port,
a missing config leaves the agent fully functional and fully unprotected).
`composeLaunch` carries the same guard as a last line: a config-routed plan
with no `agentConfig` refuses to compose. And composeLaunch deliberately does
NOT set `ANTHROPIC_BASE_URL` for these targets: OpenClaw's plugin-mounted
quarantine child inherits the AGENT env, and a proxy-pointing base URL there
would poison the U-LLM channel.

**Known limits, stated:** OpenClaw's
gateway-family topology limit (§13.3 of the differential doc) applies to the
kernel rungs regardless of target plumbing; and the landlock-net BIND gap
(differential-interactive.md §13.6) still bites OpenCode's TUI under
`--landlock-net`.

Tests: `launcher/test/unit/{parse,agent-config,env-compose,manager}.test.ts`
(refusal, builders, merge, fail-closed) and
`launcher/test/component/agent-config-delivery.test.ts` (the REAL `main()` per
target: config written into the scope run dir, delivered via the target's env
var, session header + inspect mount present, user config merged, no base-URL
leak; the user's OpenClaw model entries kept with every per-model endpoint
field stripped); `launcher/test/{unit,e2e}/agent-model-route.test.ts` (the
refusal rules; stand-in `openclaw` / `opencode` binaries never start and a
counting upstream sees nothing on a refused launch, and a routed launch
carries both fences; JSON5 configs, `$include` resolved (a split config's
openai model refused by name, a missing or escaping include refused, a split
anthropic config launched with the run config resolved) and Active Memory's
model); `launcher/test/unit/openclaw-include.test.ts` (the resolver on real
files: merge order, relative paths, roots, symlinks, hardlinks, size, cycles,
depth, `__proto__`);
`launcher/test/unit/json5.test.ts` (the reader, matched case for case against
the `json5` package when written); `launcher/test/component/openclaw-memory-fence.test.ts`
(the REAL `main()` with a stand-in `openclaw` answering `--version`: the
embeddings switch in each release's spelling, also for a setting in an
`$include` file; the plugin slot where the version is old or unread).

### 9.0 OpenClaw interactive: `mandu openclaw chat`, never a Gateway client

`openclaw tui` is a Gateway CLIENT: the agent loop (model calls and tools)
runs in the Gateway process, which read its own config at start and never sees
the routing file this launcher writes. On a normal OpenClaw host a Gateway is
often already running (by default on port 18789), so
`mandu openclaw tui` would confine only the chat window while the agent kept
talking to the real endpoint with raw tool results — a session that looks
protected and protects nothing. The launcher therefore accepts an ALLOWLIST of
OpenClaw shapes and refuses everything else before anything launches
(`launcher/src/openclaw-argv.ts`, called from `parse.ts`;
`test/unit/openclaw-argv.test.ts`), per the fail-closed rule:

| Shape | Verdict | Why |
|---|---|---|
| `chat`, `terminal`, `tui --local` | allowed | the embedded runtime: the agent loop inside the launcher's child (the supported interactive shape, OpenClaw ≥ 2026.6) |
| `agent --local` | allowed | the one-shot embedded runtime (the e2e harness) |
| `gateway`, `gateway run` | allowed | the Gateway itself runs in the foreground under the wrap, so it is confined and routed |
| `--help`, `-h`, `--version`, `-V`, `help` | allowed | print and exit |
| `tui`, `agent` without `--local`, `acp`, `acp client` | refused; `MANDU_OPENCLAW_GATEWAY_CLIENT=1` opens them | Gateway clients (`acp` is an ACP stdio bridge to the Gateway WebSocket; `acp client` spawns one). The opt-in is for a Gateway that was itself started under Mandu; the differential harness sets it (it wraps the TUI only, on purpose, §13.3 of the differential doc) |
| bare `openclaw` | runs as `openclaw chat` | bare `openclaw` starts onboarding (no authored config) or Crestodian, neither routed; a bare `mandu openclaw` means the coding agent, so parse.ts appends `chat` after any global flags (`openclawDefaultArgv`); help and version pass unchanged, and the refusal stays for a caller that skips the mapping |
| `crestodian` | refused | the setup and repair assistant: a TUI whose model planner falls back to the Claude Code CLI or the Codex app-server harness, and which can install plugins and start or restart the Gateway service; not a shape whose model traffic this launch routes |
| `gateway start/restart/install/call/…` | refused | the Gateway SERVICE (systemd/launchd) or a running Gateway, outside the wrap |
| `--container` / `OPENCLAW_CONTAINER` | refused | runs the CLI inside a Podman/Docker container, outside the wrap |
| anything else (`config`, `models`, `plugins`, `infer`, `message`, …) | refused | management or one-off commands with no reason to run under Mandu; run them without `mandu` |

`--profile` / `--dev` stay allowed: `OPENCLAW_CONFIG_PATH` (the routing file)
still wins over both (probed). An argv the launcher cannot read as OpenClaw (a
wrapper script with `--target openclaw`) is not checked: `--target` is the
user vouching for the wrapper, the same contract every wrapper target has.

Two more local-mode facts (2026.6.35): `tools.exec.mode: "ask"` does not
prompt in the TUI, the approval registers with the Gateway at `gateway.port`
(with none listening the command fails; with the user's Gateway on 18789 it
would have gone THERE); and `agents.defaults.workspace: "."` resolves against
the launch CWD, i.e. the AgentView twin, while an unset workspace falls back
to OpenClaw's own `~/.openclaw/workspace` (outside the project and its twin).
The watch runner's OpenClaw profile (`drill-target-openclaw.ts`, in the
maintainers' drill suite) runs exactly this shape.

### 9.1 Plain commands: the `shell` target

**Problem.** `mandu --help` promised `mandu -- <command…>` for "any
command", but `mandu -- bash -c …` died on the §9 refusal ("cannot infer
the target agent from 'bash'"). A fresh user running a shell over fake
secrets to watch them get masked is a real use, not a mistake.

**Options weighed.** (i) a default for non-agent commands, or (ii) narrowing
the help to what worked. A blanket default for *every* unknown argv[0] would
reopen exactly the §9 hole: `my-claw-wrapper` or `node openclaw.mjs` IS an
agent, and any default that is not its own routing leaves it talking to the
real endpoint. So the decision is (i), scoped so it cannot guess wrong:

- **Inference covers POSIX shells only** (`sh bash dash zsh ksh mksh ash
  fish`, `parse.ts SHELL_BASENAMES`). A shell binary is never itself an
  agent. Interpreters (`node`, `python`, …) are deliberately absent. Every
  other unknown basename still REFUSES, and the refusal now names both
  escape hatches: `--target <agent>` and `--target shell`.
- **`--target shell` is the explicit opt-in** for any other plain command
  (`mandu --target shell -- python3 check.py`). Typed by a person who has
  said it is not an agent, so nothing is guessed.

**What the `shell` target wires.** Every OS-level rung exactly as for an
agent target (arbiter, secret twins + env masking, net-proxy, net guard,
Landlock, exec-box/exec-wrap shims, fs-sync under integrity, reply filter).
Model routing is claude's ENV delivery (`wireOf` → anthropic-proxy):
`ANTHROPIC_BASE_URL` + the packed session header, so a `claude` or an
Anthropic SDK started inside the shell reaches the model through the proxy.
No agent argv splice (they are claude-binary-gated), no codex `-c`
override, no config file. `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` is
defaulted as for claude (an explicit user value wins), since a `claude`
started from the shell is the same client. This is the SAME env delta the live oracles have
always composed with `--target claude -- bash …`. A language runtime under
the `shell` target (`--target shell -- node x.js`) also gets the SDK route
([agent-sdks.md](../agents/agent-sdks.md)): a claude a Node program starts
keeps this env routing even with an environment of its own, and a codex it
starts refuses to start rather than run unrouted.

**Fail-closed, unchanged.** An unreachable arbiter still refuses the launch;
a context proxy that fails to start aborts it as for claude (only
`--best-effort` launches anyway, with `ANTHROPIC_BASE_URL` at a closed port, so
calls fail loudly, never raw); the refusal for non-shell unknowns stands.

**Truth in labeling.** What env routing cannot reach is said at every shell
launch, in one line carrying the `WARNING` marker so the compact TTY display
prints it in full (`env-compose.ts shellTargetNote`, emitted by the coop-env
backend, kept in launch.log and the `launch_posture` event): model calls go
through Mandu only for programs that read `ANTHROPIC_BASE_URL`; codex,
openclaw and opencode started from the shell are NOT routed, and the line
says to start an agent as `mandu <agent>`. The dashboard's agent-kind
derivation counts only known agent targets, so a `shell` session is not
badged as an agent. Not done, deliberately: starting the openai-proxy as
well and exporting `OPENAI_BASE_URL` (Codex routes by `-c` config, not that
variable, so it would not route Codex; a second proxy is a second port in
every net rung for no agent it protects).

Tests: `launcher/test/unit/parse.test.ts` (shell inference, interpreter
refusal, `--target shell`, every help launch form parses),
`launcher/test/unit/env-compose.test.ts` (env delta = the claude stand-in's,
no splice, the note and its attention marker) and
`launcher/test/component/run.test.ts` (the real `main()`: `mandu -- bash`
launches with the proxy base URL, the note and non-essential traffic off; `python3` refuses; an
unreachable arbiter refuses the shell target too).
