# Mandu as an OpenClaw plugin, beside a resident service

**Status (2026-10-25):** built: steps 1 to 4 of §4: the attachment session
and the posture by coverage (§3.3, §3.4); `mandu serve` with its proxy pool,
the declared sessions, their secret registration without a launch, their
attachment registration, the "weaken + warn" surfaces and the reap rules
(§3.2); the plugin (§7: the manifest, the attachment config, the
`before_tool_call` tamper policy and the `message_sending` reply check, in
`interceptors/openclaw-inspect-plugin/`); and `mandu openclaw
install|uninstall` with its `mandu doctor` check and the service URL
contract (§8); the dashboard's Plugins page (§3.2, dashboard.md §4.25aj);
and step 5, the test lane (§9): a real OpenClaw Gateway
loads the plugin and fires both hooks on 2026.3.12, 2026.7.1-2, 2026.9.9
and 2026.10.7 per push, and on the newest release in the nightly; and the
service's timer check that each attached config still routes through
Mandu, said loudly when it does not (§3.6); and Route 1 (§8.1): every
provider of the user's config whose wire the proxy reads (Anthropic
Messages, OpenAI Responses and Chat Completions, OpenAI-compatible services
included; Google Gemini since 2026-10-25; Ollama's native chat API since
2026-10-26) is routed through the session's proxy to that provider's own
address, and one it cannot read is refused unless the user leaves it as it
is by name. The facts in §2
were read from the published OpenClaw packages 2026.9.9 (the top tested
version, `supported-agents.md`) and 2026.10.7 (the latest); the lane has
since run what the plugin relies on. And (2026-10-26) the opt-in
confined-commands tier (§10): `mandu openclaw install --sandbox` makes
Mandu the Gateway's sandbox backend, so every command and file tool of the
agent runs in a Mandu-confined box, on 2026.7.1-2, 2026.9.9 and 2026.10.7
(2026.3.12 has no sandbox backend seam and refuses the config). And
(2026-10-26) the first live run (§9): the lane's legs and the tier's on a
real model, a ChatGPT sign-in through the pool on 2026.10.7, all passed.
Mode `secrets`; the plugin has no integrity behaviour.

## 1. Why

`mandu openclaw` runs OpenClaw inside the wrapper: `chat`, `tui --local`,
`agent --local` and a foreground `gateway [run]` that dies with the launch.
It refuses the Gateway as a service (`gateway start|install|…`), because a
daemon Gateway never reads the per-run config that routes its model calls
through the proxy, so it would look protected and protect nothing
(`supported-agents.md` §2.1). But a resident Gateway, answering on Telegram
or WhatsApp around the clock, is how most people run OpenClaw.

For them Mandu attaches the other way round: a resident Mandu service, and a
plugin inside their Gateway. The trade is stated up front (§5): the model
context keeps today's guarantee, and the file, exec and egress guarantees of
the wrapper do not come along.

## 2. What OpenClaw offers a plugin (2026.9.9 and 2026.10.7)

The hook set is the same in both versions (2026.10.7 dropped two
skill-proposal hooks we do not use).

| Seam | What it can do | Identity it gets |
|---|---|---|
| `before_tool_call` | rewrite params, block, require approval; fails closed on a throw or a 15 s timeout | agentId, sessionKey, runId, toolCallId, `requester{channel, accountId, senderId, …}` |
| `registerAgentToolResultMiddleware` | replace a tool result before the same turn's model call; a throw or bad output becomes "Tool output unavailable due to post-processing error." (fails closed); text blocks cut at 100,000 characters | agentId, sessionId, sessionKey, runId; no channel |
| `message_sending`, `reply_payload_sending` | rewrite or cancel an outgoing reply; an error is logged and skipped (fails open) | destination (`to`, channel, account, conversation), sessionKey |
| `before_model_resolve` | pick another configured provider or model id | agent context |
| `before_prompt_build` | add system context | agent context |
| `after_tool_call`, `llm_input`, `llm_output` | observe only (`llm_input` gets a clone, fire-and-forget) | |
| `tool_result_persist`, `before_message_write` | rewrite the transcript write, not what the model sees | agentId, sessionKey |

Three things matter for the design:

- **A tool result can be rewritten in the same turn** through the middleware,
  the stock form of the fork hook DualView relied on. It needs
  `contracts.agentToolResultMiddleware` in the manifest and an explicit
  enable, and it covers OpenClaw-runtime tools only (Codex-native tools are
  relayed for observation).
- **No seam sets a base URL per session.** A provider's `baseUrl` and
  `headers` come from `openclaw.json` (what `mandu openclaw` writes per run
  today) or from a plugin-registered provider, whose runtime hooks see the
  agentId at most.
- **The conversation hooks need consent.** An installed plugin needs
  `plugins.entries.<id>.hooks.allowConversationAccess: true` for
  `before_model_resolve`, `before_prompt_build` and `llm_*`. Installing goes
  through a capability review that lists the declared hooks and contracts;
  `openclaw.compat.pluginApi` is a semver floor checked at install.

## 3. The design

### 3.1 The model context stays at the proxy

The plugin does **not** symbolize. Model requests go to Mandu's model proxy,
through the provider `baseUrl` the installer writes into `openclaw.json`,
exactly as under `mandu openclaw` today. Reasons:

- **Completeness.** The proxy sees every byte the model gets: tool results,
  the user's message (the prompt filter), the bootstrap files OpenClaw loads
  without a tool call, compaction and other side calls. The middleware sees
  OpenClaw-runtime tool results only.
- **One symbolizer.** A second one in the Gateway would mean two places to
  keep equal and an ordering question; the proxy is the one the e2e suites
  prove.
- **Fail-closed by position.** If the Gateway or the plugin misbehaves, the
  request still crosses the proxy; if the proxy is down, the model call
  fails.

The middleware stays available as a later second layer (§6).

### 3.2 `mandu serve`: the service, with one proxy per attachment session

Today the launcher starts a model proxy per launch, bound to its session by
its environment, on a lifeline to the launch. The plugin needs one that
outlives any launch. `mandu serve` is that service: the resident arbiter and
dashboard (the stack, which already runs resident) plus a **pool of
proxies, one per attachment session**, each started with the same
environment a launch gives it today (session key, inbound spec
`openclaw-agent`, tenant, secret posture) and a stable port.

A pool, not one proxy that reads the session from each request: the proxy
binds its session once at boot and every gate call uses it, so the pool
reuses that code unchanged. A header-chosen session would let any local
process that reaches the port speak as another session and ride its
releases.

Pieces: a shipped user unit (systemd; launchd later) and
`mandu serve install|start|stop|status`; health from the proxies' existing
identity endpoint; an upgrade that waits for idle sessions, as the stack
restart does today; reap rules for sessions with no owner pid.

**Built (2026-10-25), without the pool**
([`runtime-instances.md`](../architecture/runtime-instances.md) §4.1d):

- `mandu serve install|start|stop|status|upgrade|uninstall`. The unit is
  `mandu.service`, a systemd **user** unit rendered for the installing
  mandu (its node, its layout's dashboard daemon), whose main process is the
  dashboard as the arbiter's supervisor, exactly the resident stack a
  launch's autostart runs. A launch attaches to it as to any resident stack;
  the auto-detection of §4.1a–c finds it, and its refusals name `mandu serve
  upgrade` for it.
- The upgrade does not wait by default: under a live `mandu` session it
  rewrites the unit file, restarts nothing and says so (exit 3), the
  launch's own deferral; `--wait` waits for the sessions to end, `--force`
  restarts now. Starting the service also replaces a stack already running
  outside it (a launch's autostart) only when no session uses it.
- macOS refuses with "not yet"; a host without a systemd user manager
  refuses with what to use instead.

**Built (2026-10-25): the pool.**

- **Where it runs: the dashboard, the unit's main process** (keyed on
  `MANDU_SERVE=1`; `dashboard/src/supervisor/attachment-pool.ts`, wired in
  `server-main.ts` once the supervised arbiter is up). Judged against a
  process of its own under the unit: the dashboard already supervises the
  arbiter, reads its human socket from `hello` (`Supervisor.arbiterHumanSock`)
  and spawns the anthropic-proxy in every layout (`Supervisor.serviceSpawn`:
  an install's bundle, a checkout's bundle while fresh, else the source). A
  separate process would need a second unit (and `serve` verbs for it) or the
  dashboard spawning the launcher anyway, and would still have to stop and
  restart with the stack. The pool stops on the dashboard's exit paths (its
  signal handler, its self-restart, its exit when its arbiter does), and its
  proxies hold a lifeline to it (`MANDU_LIFELINE=stdin`), so a SIGKILLed
  dashboard leaves no proxy serving. The pieces the launcher and the
  dashboard share are one module copied byte for byte
  (`attachment-contract.ts`: the session, the port-file contract, the
  declared file; `scripts/copies/module-copies.mjs`, with `safe-file.ts`).
- **The declared sessions** live in the Mandu home,
  `state/serve-attachments.json` (the path table's `serve-attachments`, 0600):
  `{version: 2, attachments: [{kind: "openclaw-plugin", agent, session,
  port, config?, providers?, unprotected?}]}` (version 1, before Route 1, is
  read too; `providers` and `unprotected` are Route 1's, §8.1: each routed
  provider's id, wire, upstream and original entry, base URLs only; a URL
  with a user, a password, a query or a fragment makes the entry unusable, so
  the session is not served). `mandu serve attach openclaw [--agent <id>] [--port <n>]` adds one
  (a free port picked at declaration when none is named: the stable port) and
  waits for its proxy; `mandu serve detach openclaw [--agent <id>]` removes it.
  The pool reads the file every 2 s. One command for the user: `mandu openclaw
  install` declares its agent's session when the service's pool runs (its
  record `<runtime>/attachments/pool.json` names a live pid) and waits up to
  30 s for the proxy, then writes `openclaw.json`; a refusal takes back a
  declaration it added; `mandu openclaw uninstall` removes it again. The
  per-launch proxy path is unchanged.
- **Per session, in order** (each a fail-closed gate on the next): (0) its
  secret files registered (below); (1) the attachment registered,
  `beginAttachment {sessionId, kind: "openclaw-plugin", coverage:
  ATTACHMENT_COVERAGE["openclaw-plugin"]}` on the human socket, renewed every
  20 s; (2) the proxy started with a launch's environment for the session
  (`MANDU_ARBITER_SOCK`, the human socket, `MANDU_SESSION_KEY=<session>`,
  `MANDU_INBOUND_SPEC=openclaw-agent`, tenant `live`, secret posture `gated`;
  the upstream keys from the service's own environment: `MANDU_UPSTREAM`,
  `MANDU_UPSTREAM_LOCAL`, `MANDU_UPSTREAM_TLS`, `MANDU_UPSTREAM_IS_BASE_URL`,
  `MANDU_OPENAI_UPSTREAMS`, `MANDU_OPENAI_TEXT_CALLS`, `MANDU_GOOGLE_UPSTREAMS`
  (`POOL_UPSTREAM_KEYS`),
  which win over the supervisor's spawn-form default (api.anthropic.com; the
  fresh-VM leg's 401 before this); `mandu serve install` carries
  `MANDU_UPSTREAM` and `MANDU_UPSTREAM_LOCAL` into the unit, never an
  upstream URL with credentials, and the rest go in a drop-in; over them,
  the declared providers' own addresses (Route 1, §8.1,
  `declaredUpstreamEnv`): the Anthropic-wire provider's as `MANDU_UPSTREAM`
  (dropping the environment's `MANDU_UPSTREAM_LOCAL` / `_TLS`, which speak of
  its upstream), each OpenAI-wire provider's in `MANDU_OPENAI_UPSTREAMS` and
  each Gemini-wire provider's in `MANDU_GOOGLE_UPSTREAMS`, each
  Ollama-wire provider's in `MANDU_OLLAMA_UPSTREAMS`, a
  built-in one with no address of its own at the environment's address for
  it, else its own; the environment decides only what no declared provider
  does; a launch's
  other plan-derived keys, the view map, the agent directory, the TLS
  inspection claim, explicitly unset)
  on the declared port when it is free, else any; (3) once it listens and its
  identity names the session and the service's arbiter, the contract's port
  file. Registering before the proxy starts (the brief said "when its proxy is
  up") means a proxy never listens on the Gateway's route unregistered.
- **Fail closed.** No registration, no proxy. A `renewed: false` registers
  again at once; when that fails, or the arbiter has not answered for a whole
  lease, the proxy is stopped and its port file removed, and the session
  starts over. A proxy that exits loses its port file at once (so `mandu
  openclaw install` and the doctor see it down) and is restarted with a
  backoff (1 s doubling to 30 s, reset after a minute up); its registration
  stays, since the Gateway's programs still reach the human socket while the
  proxy is down (ending it would believe forged guard reports meanwhile).
  Stopping (undeclared, or the service stopping): the port file, then the
  proxy, then `endAttachment`, then the folder.
- **Secrets without a launch.** A launch registers the secret files it
  finds (the registry is account-wide); a user who runs OpenClaw only as a
  resident Gateway may never launch, and the proxy would then have nothing to
  swap. So the pool runs the launcher's `mandu serve register-secrets --agent
  <id> --json` (`launcher/src/serve-secrets.ts`; the dashboard does not import
  the launcher): the arbiter's `discoverSecrets` with the options a launch of
  OpenClaw walks with (`launchDiscoverOptions`, target `openclaw`), over HOME
  plus the agent's workspace from `openclaw.json` when it lies outside HOME,
  then `registerSecret` per file over the human socket, through the launch's
  own adapter (`socketSecretArbiter`). Before the attachment is registered,
  again every 10 minutes and at every start of the service (so `mandu serve
  upgrade` and a restart pick up new files). A failure before the first
  registration keeps the session unregistered and unserved; a failed rerun
  stops the proxy until a rerun succeeds (the attachment stays: the Gateway
  still runs). Unlike a launch, nothing is twinned or mounted (the Gateway's
  programs read real files: the gap) and no environment variable is
  registered (the Gateway's environment is not the service's). The counts go
  into the session's pool record and `mandu serve status`. The registration
  also answers the agent's workspace it resolved, which the pool gives the
  session's proxy as `MANDU_AGENT_CWD` (2026-10-26): OpenClaw's tools take
  workspace-relative paths (`read memo/brief.md`), and without the base a
  path label or a binding keyed on the file's real path never matched, so a
  `public` label was ignored (the shape rule masked the file) and a
  declassified file's bound host was refused as unbound (the live drills
  found both on Route 1, conf-public-label-wins and turn 3 of
  conf-declassify-confines-session; the plugin lane's
  `openclaw-plugin-drill-session` test pins it).
- **"Weaken + warn"** (the maintainer, 2026-10-25): a live plugin session
  counts as an unwalled launch (§3.3), and every surface says so with the way
  out (run the Gateway under `mandu openclaw gateway`, or `mandu serve stop`;
  `mandu openclaw uninstall` for good): `mandu serve status` (each session's
  port, health, registration, secret count and posture `gated` / gap
  `openclaw-plugin` with the gap's sentence, then two `warning:` lines),
  `mandu serve attach` and `mandu openclaw install`, `mandu doctor` (section
  "Mandu service attachments"), a confined launch's banner
  (`concurrentLaunchNotice`, from `beginLaunch`'s `others`) and its
  human-plane watch (`exposureLostLines`, `exposureChangedLine`, the recap:
  "a plugin session is running", with `ATTACHMENT_EXPOSURE_FIX` instead of the
  `--mode off` fix), the dashboard's Home notice (its headline, sentence
  and fix parts name the Gateway and the two commands), and the dashboard's
  Plugins page (below).
- **The dashboard's Plugins page** (2026-10-25, dashboard.md §4.25aj):
  `/plugins` on the product page, fed by `GET /api/plugins`
  (`dashboard/src/server/plugin-routes.ts`, `view-model/plugins.ts`), which
  reads what `mandu serve status` reads: the declared file, the pool's
  records (this process's own pool when the dashboard is the service's, else
  a live pid in `<runtime>/attachments/pool.json`), each port file and the
  proxy's identity, and the arbiter's attachments. A card per attached
  agent under "Mandu in OpenClaw": its state (attached, starting, lapsed,
  not answering, detached, the service stopped), the agent and session,
  the proxy answering, registered and since when, the secret files, the
  posture `gated` with the gap's sentence, the cost while it runs with the
  fix Home gives, and links to its session page and History; no port. A
  host not attached shows its set-up (`mandu serve install` while the
  service is not running, then `mandu openclaw install`, then `openclaw
  gateway restart`); a stopped service says so and how to start it. The
  page knows OpenClaw only; OpenShell's place is marked in its host list
  for when it has an attachment kind. A lost route (§3.6), from the
  attachment's newest believed record as Home reads it, turns the card red
  with what changed and Home's fix (`ROUTE_FIX_PARTS`). The session
  page of `openclaw:main` draws its masked read with Show the real value:
  the pool proxy's records are claims (the attachment exposes the human
  plane), so the reveal reads an attachment session's own records once the
  arbiter's believed registration names it one (dashboard.md §4.25aj).
- **Reap.** Each session's folder holds the pool's record (`pool.json`: the
  dashboard's pid, the proxy's pid, the secret counts). `mandu reap` leaves
  every folder whose dashboard is alive (by its title) alone; once it is gone,
  a proxy still running there is stopped after its title confirms it, then the
  folder and the pool's record go. Retention otherwise: the attachment is a
  60 s lease in the arbiter, the folders live as long as the pool, and the
  declared list (the user's intent) until `detach` or `uninstall`
  (runtime-instances.md §4.1d). `<runtime>/attachments/` is on the runtime
  registry list (`runtime-registry.ts`), so a confined launch's agent can
  neither rewrite a port file nor forge a pool record: the macOS profile and
  the Linux guard deny writes there (`tests/sandbox/write-protect-registry`).
- **Tests.** Unit: `dashboard/test/unit/supervisor/attachment-pool.test.ts`
  (the proxy environment, backoff, reconcile, port; the order over fake
  effects, every fail-closed branch), `launcher/test/unit/attachment-contract.test.ts`,
  `serve-attachments.test.ts` (attach/detach, the status and doctor rows, the
  secret registration against a mock arbiter), `reap-attachments.test.ts`,
  the watch and Home wording. Component: `launcher/test/component/serve-pool.test.ts`
  (the unit under a fake systemd on temp dirs: attach, the secret file under
  HOME registered with no launch, the port file 0600 in 0700 naming the
  session, the believed `gated` / `openclaw-plugin` posture record, the watch
  line, `status`, a killed proxy, detach, stop ending the attachment) and
  `openclaw-install.test.ts` (one command, a refusal undeclares). Stack:
  `tests/stack/serve-pool-invariant.test.ts` (the pool's production form, the
  real launcher, arbiter and proxy: a credentials file registered only by the
  service reaches the model as a placeholder, conf-exfil's verdict; without
  the registration it leaks, which the test was checked to catch).

### 3.3 The attachment session

A session is `openclaw:<agentId>` (sanitized to the arbiter's session-id
form), one per configured OpenClaw agent: the static provider headers can
name the agent, not a conversation (§2). The Gateway's sessionKey reaches
the plugin's hooks and is recorded in events, so the session page can still
tell conversations apart.

The service registers it with a new arbiter op, the attachment form of
`beginLaunch`: no pid, the declared coverage, and *not walled*. The
registration comes from the service (outside the Gateway) over the human
socket. The plugin itself talks to the data socket only, so what it emits is
a claim, never a believed event.

Built (2026-10-25; arbiter `ipc/server.ts`, `policy/cache-seals.ts`,
arbiter-human-plane.md §10.1.2):

- **The ops.** `beginAttachment {sessionId, kind, coverage}`,
  `renewAttachment {token}`, `endAttachment {token}`, all three human plane
  (refused on the data socket). `kind` is `openclaw-plugin`; the session id
  must be `openclaw:<name>` and shaped like a scope id, so an attachment can
  never name a launch's session (`attachmentSessionId` builds it from the
  agent id: other characters become `-`). The arbiter decides the posture
  from the coverage with the same function the launcher uses (§3.4) and
  accepts only `gated` with the kind's own gap: a coverage that would
  confine, or that names a host's gap, is refused.
- **Never walled, never guarded, never confined.** While an attachment is
  live it counts as an unwalled, unconfined launch: the human plane is
  exposed (every attested report on the human socket is a claim), no cache
  seal is honoured, and its end rotates the epoch. Its session is never
  guarded. The cost is real and lasts as long as the service runs: a
  confined `mandu claude` on the same machine loses its guard's attestation
  meanwhile (secret opens get placeholders, protected writes are refused,
  shell output is masked once it read a secret), and every launch rebuilds
  its enforcement caches. That is the truth of the deployment (the
  Gateway's programs do reach the human socket and the Mandu home), so the
  fail-closed side wins; the human-plane watch, the dashboard and Home name
  the attachment as the cause.
- **Lifetime: a lease.** 60 s from the registration or the last renewal
  (the service renews at a third of it); a lapsed lease ends it like a
  gone launcher, and `renewAttachment` then answers `renewed: false`, so
  the service registers again. A lease, not the registering connection: it
  needs no connection held open (the launcher's calls dial per request), and
  it survives an arbiter restart (a row counts until its deadline, never
  past one lease from when the restarted arbiter first saw it; a shutdown
  with one live is not clean), so a restart never ends the exposure early. Not a pid: the service is no ancestor of the Gateway. One
  attachment per session; a second registration replaces the first.
- **The posture record.** The arbiter writes the session's `launch_posture`
  itself (emitter `arbiter`, `target: openclaw`, `secrets: {posture: gated,
  gap: openclaw-plugin}`, `humanPlaneWalled: false`, the coverage), believed
  when the registration was attested (stored as a claim when the plane was
  already exposed, e.g. a second Gateway's registration). While the
  attachment is live, no `emit` of a `launch_posture` for its session is
  taken from the data socket or the exposed human socket, and the dashboard
  prefers a believed posture record over a claimed one written earlier.
- **`mandu scan` knows plugin sessions.** Each registration's period
  (start, last renewal, end; a lapsed lease ends at its last renewal) is
  kept in the arbiter's store, and the scan marks the Gateway's OpenClaw
  transcripts under Mandu by the response ids the session's proxy recorded
  inside a period, by time where it recorded none: the raw tool output
  OpenClaw keeps is a value the model saw as a placeholder, not a leak.
  Only the three human-plane ops write the periods, never an emit
  (confidentiality-plan-17-past-sessions-scan.md §3 item 6, *Attachment
  sessions*; `tests/stack/transcript-scan-attachment`).

### 3.4 Posture from coverage

The posture names and sentences come from one function
(`confinement-posture.ts`). An attachment session has no host facts; it
declares what it covers:

| Chokepoint | OpenClaw plugin |
|---|---|
| model context | the proxy (full) |
| files | none (real files; output masked only when it reaches the model) |
| exec | policy only (`before_tool_call`) |
| egress | none (a program's own connections are unchecked) |
| replies | the plugin (`message_sending`) |
| Mandu's own state | readable by the Gateway's programs |

That is `gated` with a gap of its own (`openclaw-plugin`), shown in the
launch-equivalent output of `mandu serve status`, in `mandu doctor`, and on
the session page. The coverage type gets its first producer here; the
wrapper's host facts derive into it (the deferral recorded with the
posture's unification).

Built (2026-10-25, `launcher/src/confinement-posture.ts`): `Coverage` has
one row per chokepoint above; `resolvePosture(coverage)` decides, from the
files row (a covered files row stands only beside a walled own state, by
type); `hostCoverage(facts)` is the wrapper's row, so `resolveHostPosture`
is `resolvePosture(hostCoverage(facts))` and answers exactly what it did;
`ATTACHMENT_COVERAGE["openclaw-plugin"]` is the row above. The gap is an
`AttachmentGap`, not a host gap. `gated`'s sentence promises an egress
check the plugin does not make, so the gap has its own (`postureSentence`):
the model sees your secrets masked, but the programs OpenClaw runs read real
files, connect anywhere unchecked and can read Mandu's own records, and
keeping Mandu on is a rule, not a wall. The notice says "in this OpenClaw
Gateway" where a host gap says "on this host", and offers no one-command
fix (the confined form, `mandu openclaw gateway`, is in the cause). The
module ships byte for byte in the dashboard (which reads its sentences from
it instead of a hand mirror) and in the arbiter (which decides an
attachment's posture by it), through `scripts/copies/module-copies.mjs`.
`mandu serve status` and `mandu doctor` show it (§3.2).

A route the service found lost (§3.6, 2026-10-25) takes rows away: the
model context row may be `none` (model calls around the proxy, or a config
that cannot be read), and the exec and replies rows `none` (the plugin no
longer loaded); `attachmentCoverage(kind, lost)` builds it. `resolvePosture`
reads the model context first: not the proxy, the posture is `gated` with a
`RouteGap`, `model-route-lost`, whose sentence and cause say the AI may now
read secrets as they are and name the two-command fix; with the model
context still covered, the files row decides as before. An attachment may
declare its kind's coverage or less, never more
(`attachmentCoverageProblem`, the arbiter's rule at `beginAttachment` and
`updateAttachment`).

### 3.5 Replies

A reply goes to a chat, not a local terminal, so it is egress. The plugin's
`message_sending` hook asks the arbiter to put real values back only where a
rule binds that destination (channel, account, conversation); otherwise the
placeholder stays. The hook fails open, which is safe here: on an error the
reply keeps its placeholders.

**What is built (2026-10-25): placeholders always stay.** No arbiter op
decides a release for a chat destination. The reply filter's deep
`desymbolize` serves the human at their own terminal and is a human-plane op,
as is `resolve`; the plugin holds only the data socket (§3.3), where both
are refused. The egress gate's bindings (`desymbolizationDecision`,
`sessionEgressDecision`, host bindings) name hosts, not a channel, account
or conversation, and the proxy's `message` / `conversations_send` gates
treat a chat send as a destination no gate can check. So the hook runs with
a release seam (`ReplyReleaser`, `src/hook-arbiter.ts`) whose only
implementation releases nothing, and every placeholder goes out as is.

What the hook does today, in order (`src/reply-policy.ts`):

1. It scans the reply with the arbiter's verbatim-leak tripwire
   (`egressFingerprintScan`, a data-plane op), with the destination `""`: a
   chat is no host, so no host binding admits it. A registered secret
   *value* in the reply (a model that was given it, e.g. through
   `declassify_symbol`) cancels the reply (`{cancel: true}`): the hits name
   the placeholder, never where the value sits, so it cannot be masked back.
   The scan runs with `scope: "reply"`: a `no-model` command output the
   proxy masked whole (a row kept by its lines, e.g. a path-rule output no
   recorder narrowed, which on Route 1 is every one) counts in a reply only
   by its secrets: a line that carries a credential shape or is the
   output's whole value, while a registered value (its own row, and a
   twin's) trips as ever, also inside a line. The output's ordinary lines
   (a meeting title a script printed beside a token) are no fingerprint
   there: no model saw them through the masked row (rung 3 refuses the
   level), so a reply that repeats one is no leak of it (the over-cancel of
   demo-notion-token, live 2026-10-26). An output of a lower level keeps
   every line (a model it admits saw it), and so does an outbound request
   (a program may move the output's bytes as they are). `arbiter/test/component/reply-scope-tripwire.test.ts`.
2. Otherwise the reply is sent unchanged.

A failed or slow scan (3 s) sends the reply unchanged: the original carries
placeholders, and the tripwire is the backstop, not the guarantee (the
guarantee is the proxy, §3.1). Each reply that carried a placeholder or
tripped leaves an `egress_decision` event (`emitter: openclaw-plugin`,
placeholder names and counts, never text). `reply_payload_sending` is not
registered: with nothing to rewrite, `message_sending` covers the same text.

**The op a release needs** (not added; the arbiter's ops are another
change's area): `replyRelease`, on the data socket,

```
{op: "replyRelease", sessionKey, destination: {channel, accountId?, conversationId?, to, threadId?}, text}
→ {text, released: string[], kept: string[]}
```

The arbiter substitutes only the placeholders whose value a human-written
rule binds to that destination (a new binding kind, `chat:<channel>[:<account>[:<conversation>]]`,
beside the host bindings) and leaves every other one. Since the caller is
in the Gateway, among the agent's programs, a value it releases is a value
any program there could ask for by naming the same destination: such a
binding declassifies those values to the Gateway's user, and the policy
editor has to say so.

### 3.6 Tamper: a policy, not a boundary

The plugin runs inside the Gateway process, and the agent's programs run as
the same user: they can edit `openclaw.json` (drop the plugin, point the
provider elsewhere), stop the service, or read `~/.mandu`. `before_tool_call`
refuses the obvious attempts (a tool call naming those paths or stopping the
service), and the service checks on a timer that `openclaw.json` still
routes through its proxy and says so loudly when it does not. An obfuscated
`bash -c` passes. This is the largest gap against the wrapper and is stated
in the posture sentence, not hidden. Running the Gateway itself under
`mandu openclaw gateway` remains the confined form.

**What is built (2026-10-25)** (`src/tamper-policy.ts`, pure). The hook
reads every string of a tool call's params (nested, bounded) and the host's
`derivedPaths` hint, for every tool, and blocks
(`{block: true, blockReason}`) on any of three rules:

| Rule | Refuses | Passes (near misses) |
|---|---|---|
| `mandu-state` | `~/.mandu` (also `$HOME`, `${HOME}`, the home spelled out), `$MANDU_HOME`, `$MANDU_RUNTIME_DIR`, `$XDG_RUNTIME_DIR/mandu`, the service's unit files, and every path in the config's `manduPaths` plus the arbiter socket | `~/.mandu-notes`, `~/notes/mandu.txt`, `grep mandu` |
| `openclaw-config` | `openclaw.json`, the resolved config path and the other `.json`/`.json5` files beside it (its includes), `OPENCLAW_CONFIG_PATH` / `OPENCLAW_STATE_DIR` / `OPENCLAW_INCLUDE_ROOTS`, the state directory as a whole and its `extensions/`, `openclaw config set\|unset\|patch`, `openclaw configure\|onboard\|setup\|reset\|uninstall`, `openclaw plugins disable\|uninstall\|remove` | `~/.openclaw/workspace/…`, `openclaw config get`, `openclaw plugins list` |
| `mandu-service` | `mandu serve stop\|uninstall\|disable`, `mandu stop`, `mandu reap`, `mandu mode <x>`, `systemctl … stop\|disable\|mask\|kill … mandu`, `launchctl … unload\|bootout\|… mandu`, `pkill`/`killall … mandu`, `kill $(pgrep … mandu)` | `mandu serve status\|start`, `systemctl --user status\|restart mandu…`, `mandu doctor` |

It needs no arbiter (an unreachable arbiter changes nothing here), and
OpenClaw fails the hook closed. A refusal leaves a `tool_use` event with the
rule (`openclaw:tamper:<rule>`) and no arguments. The unit tests pin each
rule's positives, its near misses, and that an obfuscated spelling (`cd ~ &&
cat .mandu/…`, a base64 pipe) passes: a policy against obvious attempts,
not a boundary.

**The service's route check: built (2026-10-25)** (`dashboard/src/
supervisor/attachment-pool.ts`, step 7 of its header). What it closes: an
edit that drops the plugin or points the Anthropic provider elsewhere no
longer goes unseen; it does not stop the edit (nothing the same user runs
can be stopped from writing the user's file). Since Route 1 (§8.1) it
judges every provider the install routed, and a provider added since, the
same way (the declaration's `providers` and `unprotected` go to
`attachState`); a declaration without providers keeps the Anthropic-only
judgement. Since 2026-10-25 it judges the model fence too (§8.1, the
declaration's `allowlist`; "The model fence" below).

- **What it reads.** Each declared session's OpenClaw config: the one `mandu
  openclaw install` recorded in the declaration (`config`, an absolute path,
  written after the install's write, or when it found nothing to change),
  else the service's own `$OPENCLAW_CONFIG_PATH` / `$OPENCLAW_STATE_DIR` /
  `~/.openclaw/openclaw.json`. It is read as OpenClaw reads it (JSON5, every
  `$include` resolved, a symlink followed) by the reader `mandu openclaw
  install` and its doctor check use (`launcher/src/services/
  openclaw-config-read.ts`, with `json5.ts` and `openclaw-include.ts`,
  copied byte for byte into `dashboard/src/openclaw/` through the copy
  table), and judged by the doctor's own functions, moved into the shared
  `attachment-contract.ts`: `attachState`, then `routeVerdict` against the
  session's serving proxy URL (else its declared port's). The verdict:
  routed, or lost with each problem named (`plugin-absent`,
  `plugin-disabled`, `plugin-not-attached`, `route-direct`,
  `route-elsewhere`, `model-bypass`, `model-fence`, `unreadable`,
  `route-unverified`) and what they lose (the model context; the plugin's
  policy and reply check; an unreadable file loses both, fail closed). While
  an Azure OpenAI provider is routed the check also reads the Gateway's
  environment (`openclaw-gateway-env.ts`, copied beside the config reader;
  model-wires.md §9.1): AZURE_OPENAI_BASE_URL or AZURE_OPENAI_RESOURCE_NAME
  set for it is `route-direct`, an environment it cannot read
  `route-unverified` (the model context lost, fail closed). The models a config names are
  read by `openclaw-model-refs.ts`, moved out of `agent-model-route.ts` and
  copied beside the contract, so the check, the install and the wrapper
  read them one way.
- **The model fence** (decided 2026-10-25; `attachment-contract.ts`
  `modelFenceHoles`, against the declaration's `allowlist`). OpenClaw lets
  a session switch its model (`/model`, the `session_status` tool, a
  subagent's model through `sessions_spawn`, cron) to any model its
  allowlist admits, and to any model at all when there is none (§8.1). So
  a hole in the fence is one switch, by the model or by a user's `/model`,
  away from a model whose calls do not cross the proxy. Each hole is a
  `model-fence` problem and loses the model context (`model-route-lost`,
  the red card), like a provider added since the install, which is the
  same kind of path (open, not yet taken):

  | Shape | Hole | On which OpenClaw |
  |---|---|---|
  | the allowlist the install wrote is gone or empty (`fence-gone`) | any model, a catalog provider the config never names among them | every release |
  | the user's own allowlist, recorded as the fence (an empty `allowlist`), gone (`fence-gone`) | the same | every release |
  | a key of a provider Mandu neither routes nor was told to leave, `*/*` included (`fence-unrouted`) | a switch to it goes to that provider directly | every release |
  | an openrouter wildcard key while openrouter is routed (`openrouter-wildcard`) | before 2026.3.22 the literal model `*`, which OpenClaw does not know and sends to openrouter.ai | before 2026.3.22 |
  | an openrouter model the allowlist or the config names (a primary, a fallback, Active Memory's) that `models.providers.openrouter.models` does not list (`openrouter-unlisted`) | before 2026.3.22 sent straight to openrouter.ai, whatever the route | before 2026.3.22 |

  And a configured model of a provider neither routed nor left (a catalog
  provider: `agents.defaults.model.fallbacks: ["mistral/…"]`) joins the
  providers added since the install (`route-direct`): the default and the
  fallbacks are always allowed, so no fence stops them.

  *Why the openrouter shapes are a lost route on every release.* From
  2026.3.22 OpenClaw sends an openrouter model it does not know to the
  provider's own `baseUrl`, the proxy's route, so there an unlisted model
  or a wildcard crosses Mandu: it is a fence that no longer has the shape
  the install writes and would refuse (an install over it refuses or takes
  the key back), not a leak. But the check reads the file, not the Gateway:
  it cannot tell which OpenClaw runs (an upgrade or a downgrade changes
  nothing in the file, and a version a program wrote into it proves
  nothing), and a warning would leave the session page saying the AI sees
  placeholders while one `/model` defeats it on 2026.3.x. So it fails
  closed, as the install does; the words name the release
  ("OpenClaw before 2026.3.22 sends …"), so a user on a later one reads
  why. No shape is a weaker warning: each one the check reports opens a
  path around the proxy on at least one release Mandu cannot rule out.

  *What is not a hole.* A key the install recorded removed while the
  allowlist keeps others narrows the fence (more switches refused, none
  opened); a key of a routed provider (`openai/gpt-5.5`); a key of a
  provider the user left unprotected (their choice, recorded); openrouter's
  shapes when openrouter itself is left. A declaration from before the fence
  (no `allowlist`) is not held to one: the check cannot tell a fence removed
  from one never written; a second install writes it. The other holes are
  still judged there.

  *The fix takes the fence back.* A second `mandu openclaw install` writes
  the fence again when it is gone (planModelFence, as before), and over a
  config a fenced install wrote (the declaration records an `allowlist`)
  it removes each key added since that opens a hole (`fenceKeysToReclaim`:
  a key of a provider it does not route and the user does not leave, now
  or at the earlier install; an openrouter wildcard or unlisted key while
  openrouter is declared) and says so, as it routes a changed provider
  back to its recorded address: install refuses each such key, so on a
  fenced config it was added after the install. Adopting one on purpose
  takes `--leave-unprotected <provider>` (or listing the openrouter model).
  An unlisted openrouter model the config itself names cannot be taken
  back: the install refuses, naming the model to list. The declaration
  records an empty `allowlist` when the user's own allowlist is the fence,
  so its removal is judged too.
- **When.** Every 30 s and on every change: an `fs.watch` on the folders of
  the config and of each file it includes (a folder, not the file: the
  installer and editors replace the file by rename), settled 250 ms. Why
  30 s: the watch reports an edit at once where it works; the timer is the
  floor where it does not (a network file system, a folder that cannot be
  watched), and the cost is one small file read per session per tick. A
  check also runs before each registration (so a service that starts with
  the route already lost never registers it as covered), when a proxy
  starts serving, and when the declaration's `config` changes in place.
- **Armed or pending.** A route is "lost" only once armed: the install
  recorded the config, or this pool saw it routed. Before (a `mandu serve
  attach` with no install yet) a config with no route is "pending", a quiet
  line in `mandu serve status`, never an alarm.
- **When lost, said loudly.** (1) The service log: one `ROUTE LOST` line
  per change with every problem and the fix. (2) The pool record
  (`<runtime>/attachments/<session>/pool.json`, `route: {state, problems,
  config, since, checkedAt}`), which `mandu serve status` (the session's
  line says ROUTE LOST, and a `✗` problem line names what changed) and
  `mandu doctor` (section "Mandu service attachments": a ✗ with the fix)
  read. (3) The coverage the session declares loses its rows
  (confinement-posture.ts `attachmentCoverage`: `modelContext: none` for a
  route around the proxy, `exec`/`replies: none` for the plugin gone),
  sent with `updateAttachment` on the arbiter's admin channel; the arbiter
  decides by `resolvePosture`, where a model context that is not the proxy
  decides first (`gated`, gap `model-route-lost`, its own sentence and
  cause: never the claim that the AI sees them masked), and records a BELIEVED `launch_posture` on
  the session's stream carrying `attachmentRoute`. The dashboard takes an
  attachment's newest believed record, so the session page stops saying the
  AI sees your secrets masked, and Home shows a loud card naming the session, what
  changed and the fix (dashboard.md §4.25x1). The fix everywhere: `mandu
  openclaw install` again, then `openclaw gateway restart`. The user's
  config is never written by the check.
- **When back.** The next check that finds it routed logs it, writes the
  record and sends the full coverage again: a new believed record with the
  kind's own gap, and the card is gone.
- **The honest limit.** A Gateway reads its config when it starts and keeps
  it until it restarts. So the check reports the FILE, not what the running
  Gateway uses: an edit that drops the route takes effect only at the
  Gateway's next restart (until then its model calls still cross the
  proxy, and the notice is a warning ahead of it); a file put back before
  that restart never took effect; and a Gateway that restarted while the
  file was bypassed runs without Mandu until it restarts again after the
  fix, which is why the fix names `openclaw gateway restart`. A file
  changed and changed back between two ticks where the watch does not work
  goes unseen. The check, the declaration and the pool record are all files
  the agent's programs can write (the Mandu home and the runtime folder are
  readable and writable by the user's programs here): a policy against
  obvious edits, not a boundary, like the plugin's own rules. What it
  cannot forge is the believed record: the arbiter takes `updateAttachment`
  as believed only on the admin channel, never on the exposed human socket,
  so no program in the Gateway can mark a lost route restored on the
  session page or Home.
- **Tests.** Unit: `launcher/test/unit/openclaw-route-check.test.ts` (each
  lost-route shape, includes, JSON5, unreadable files, recovery, the
  declared `config`, the pool record and the status and doctor rows; each
  fence shape, what is not a hole, the user's own fence, the doctor's row,
  and the second install's reclaim),
  `dashboard/test/unit/view-model/plugins.test.ts` (the fence's words on
  the Plugins page: model references whole, no path or port),
  `launcher/test/unit/posture-coverage.test.ts` (the coverage loss and its
  posture, the arbiter's "kind's coverage or less" rule),
  `dashboard/test/unit/supervisor/attachment-pool.test.ts` (the check over
  real temp files and the real watch: lost over the admin channel, back, a
  service that starts lost, the human-socket fallback, pending until
  armed; the fence removed and widened, and a fence recorded again judged
  at once), `dashboard/test/unit/view-model/attachment-route.test.ts` (the
  newest believed record, the Home card), `arbiter/test/unit/
  attachment-session.test.ts` (`updateAttachment`: believed on admin, a
  claim on the exposed human socket, refused on data and for a dead
  token). Component: `launcher/test/component/serve-route-check.test.ts`
  (the real service under a fake systemd on a temp HOME: `mandu openclaw
  install`, an edit that points the provider elsewhere, the believed
  `model-route-lost` record in the event stream and the ✗ in `mandu serve
  status`, then a second install clears both; then the model allowlist
  deleted, then widened with a key of a provider Mandu does not route: the
  `model-fence` problem in status, both doctor readings and the believed
  record, and a third install takes the fence back key for key). The real
  OpenClaw lane's fence leg (§9, `[fence 2026.3.12]`) checks that the route
  check finds no hole in the fence the Gateway then enforces, and finds
  each way of opening it the leg drives.

## 4. Build order

1. **The attachment session and posture by coverage** (arbiter op, the
   coverage type and gap, the dashboard's sentences). Unit tests over the
   op and the decision table. *Built 2026-10-25* (§3.3, §3.4):
   `arbiter/test/unit/attachment-session.test.ts`,
   `launcher/test/unit/posture-coverage.test.ts`, the dashboard's
   session-health and human-plane units, and
   `tests/stack/attachment-session.test.ts` (a real arbiter's two sockets
   and the dashboard's event source).
2. **`mandu serve`** with the proxy pool, the unit and its subcommands.
   The service registers each session with `beginAttachment` over the
   human socket and renews it every 20 s. *Built 2026-10-25* (§3.2).
3. **The plugin package** (built, §7, §8: the inspect plugin folded in, the manifest's
   `compat` and `activation`), `mandu openclaw install` writing the plugin
   entry and the provider route, and a doctor check that the route holds.
4. **Replies and the tamper policy** (§3.5, §3.6; built, §7).
5. **The test lane:** the multi-agent harness already drives OpenClaw
   against an in-process arbiter and proxy; its provisioner is pointed at
   the plugin and the service, and the confidentiality oracle (no raw
   secret in a model request or at an unbound host) grades it. *Built
   2026-10-25* (§9): the per-push lane on a real Gateway, in-process on
   every version and through the pool on one. *The bypass oracle is built
   (2026-10-26, §9 "The bypass oracle")*: on every lane version, every
   provider Mandu routes, by Route 1 and by the wrapper, a real Gateway in
   a network namespace whose only way out is the proxy, every connection
   recorded.
   *Its fresh-install form is built (2026-10-25)*: the `fresh-openclaw-plugin`
   matrix suite (os-test-matrix.md §10.20) installs OpenClaw 2026.9.9 on a
   clean Ubuntu guest, onboards it, runs its Gateway as a systemd user
   service and attaches Mandu from a checkout exactly as `docs/usage.md`
   says. Until the pool lands it asserts the install's refusal. Against the
   pool's branch the whole leg passed (the read masked, the `~/.mandu` call
   refused, the reply's placeholder kept) once the pool's proxy took the
   service's `MANDU_UPSTREAM`, which it does not yet (os-test-matrix.md §10.20.1 item 7).

## 5. Guarantees against the wrapper

| | `mandu openclaw` (wrapper) | plugin + `mandu serve` | plugin + `mandu serve` + `--sandbox` (§10) |
|---|---|---|---|
| A secret reaches the model only as a placeholder | yes (the proxy) | yes (the same proxy) | yes (the same proxy; the box's commands and file tools read placeholders before it) |
| A protected file is unreadable to the agent's programs | `confined` hosts | no | the commands and OpenClaw's file tools: yes (a placeholder copy); other plugins' tools, MCP servers: no |
| A secret leaves only to a bound host | yes (the egress gate) | no for the programs' own connections | the commands: yes (the box's guard admits only the egress proxy); other plugins, MCP, the browser: no |
| Replies show real values only where bound | the terminal (reply filter) | the chat (`message_sending`) | the chat (`message_sending`) |
| The agent cannot switch Mandu off | yes, the wall | no, a policy (§3.6) | from a command: yes (Mandu's folder hidden, the config and the plugin read-only in the box); from elsewhere in the Gateway: a policy |
| A confined launch beside it keeps its guard believed | yes | no: while the service runs the human plane is exposed (§3.3) | no (the attachment beside it is unchanged) |

## 6. Open

- The exposure cost (§3.3): every confined launch on the machine loses its
  guard's attestation while an attachment is live. Lifting it needs a wall
  between the Gateway's programs and the human socket, which same-uid
  processes outside any sandbox do not have; running the Gateway under
  `mandu openclaw gateway` is the form without it.
- **Route 1's limits (§8.1).** A second Anthropic-wire address in one
  session (a MiniMax- or Kimi-style `anthropic-messages` provider beside
  Anthropic's own) cannot be routed: the proxy has one Messages upstream. A
  per-provider Messages route, as the OpenAI wires have, would lift it; it is
  a wire-side change, left to the shared proxy core. Google's Gemini wire is
  routed since 2026-10-25 and Ollama's native chat API since 2026-10-26
  (model-wires.md); Vertex AI and Bedrock are not (`PROVIDER_WIRES` is the
  seam).
- **Closed 2026-10-25: the openrouter bypass and the switch around the
  proxy** (a security regression, supported-agents.md §2.1 "The openrouter
  bypass"). OpenClaw 2026.3.12 and 2026.3.13 (not "before 2026.9": 2026.3.22
  and later honour the base URL) send an `openrouter` model neither their
  catalog nor the provider's `models` list knows to openrouter.ai, whatever
  the route. Install wrote no model allowlist, and with none OpenClaw's
  `sessions.patch` takes any model: on a real 2026.3.12 Gateway the model's
  own `sessions_spawn` onto an unlisted openrouter model was accepted and the
  child's turn went to openrouter.ai; a catalog provider the config never
  names (`/model google/…`, a subagent on it) went around the proxy on every
  release. Install now writes the model fence (§8.1) and judges the user's
  own allowlist; the wrapper lists every openrouter model a run can reach
  and narrows its allowlist to them on the releases that bypass, and its
  launch refuses a run file that would still leave one
  (`agent-config.ts` `fenceOpenclawOpenrouter`, `openclawOpenrouterLeaks`).
  *Closed 2026-10-25 as well:* the route check judges the fence (§3.6, "The
  model fence"): an allowlist removed or widened after the install (by the
  user, or by a program) is a `model-fence` problem, a lost model context
  on Home, the Plugins page, `mandu serve status` and `mandu doctor`, and a
  second install takes the fence back. Left: a declaration from before the
  fence is not held to one (a second install writes it), and the check reads
  the file, not the Gateway's version, so the openrouter shapes count on
  2026.3.22 and later too (fail closed).

- Per-conversation sessions: would need a per-session provider route the
  plugin can set; none exists today (§2).
- The middleware as a second layer under the proxy, for a deployment where
  the proxy route is lost (§3.6): it would turn a lost route from a silent
  leak into masked tool results.
- Whether MCP and client tools pass through the middleware (unchecked).
- **A paraphrase in a high session's reply (a gap, flagged).** After a
  `declassify_symbol` release raises the session's watermark, the proxy's
  session leg blocks the `message` tool in that session, but a plain reply
  is not a tool call: `message_sending` checks it only for the registered
  value verbatim (the tripwire), not with `sessionEgressDecision`, which
  would refuse every reply of a high session and has no approval path in a
  chat. A model that rephrases a released value can send the paraphrase to
  the chat. The wrapper has the same shape at the terminal, where the reader
  is the human; in a chat the reader may not be. Closing it needs either the
  `replyRelease` op (§3.5) to carry the session leg, or a per-chat binding.
- The release op (`replyRelease`, §3.5) and its binding kind.
- **A refusal the model cannot read** (found by the lane, §9). When a
  refused call's command names a secret path (`cat ~/.mandu/…`), the model
  proxy masks OpenClaw's result for that call whole, as it masks every
  output of a command that names a secret file (confidentiality.md §7.1):
  the model is told the output is hidden and not to assume it worked,
  instead of the plugin's refusal. Fail-closed (nothing ran, nothing
  leaked), but the agent cannot tell a refusal from a hidden result. The
  proxy cannot see that the call never ran; a fix would have the plugin
  mark its refusal in a form the proxy recognizes and lets through.

## 7. The plugin as built (steps 3-4, plugin side)

The package keeps its path and its id (`mandu-inspect`, which the per-run
config of `mandu openclaw` names); its manifest name is now "Mandu".

- **Manifest.** `activation: {onStartup: true, onCapabilities: ["tool",
  "hook"]}` (2026.10.x loads a plugin at Gateway start only when it says so,
  and the hooks need that); `contracts.tools` names the two tools and
  nothing else (no `agentToolResultMiddleware`). `package.json#openclaw`
  carries `compat.pluginApi: ">=2026.3.12"` and `install.minHostVersion:
  ">=2026.3.12"`, the floor of the tested range: 2026.9.9 and later check
  `pluginApi` against the host at install and at discovery (an unsatisfied
  range skips the plugin); older loaders ignore the key. OpenClaw has no
  manifest field for typed hooks: they are registered with `api.on`, and a
  test pins that exactly `before_tool_call` and `message_sending` are, and
  no hook that needs `hooks.allowConversationAccess`.
- **The attachment config.** `attachment: true` (written by the installer)
  turns the two hooks on; without it the plugin is what `mandu openclaw`
  mounts today, tools only. In an attachment the hooks register before the
  tools, and a missing U-LLM transport drops `inspect_symbol` with an error
  instead of failing the load (the hooks must stay). `agentId` (default
  `main`) and `manduPaths` (the Mandu home and runtime dir, for the tamper
  policy) are the other two keys; `scopeId` defaults to `openclaw:<agentId>`.
- **Identity.** A hook's session is `openclaw:<agentId>` of the agent its
  context names (before_tool_call's `agentId`; for a reply, the agent in the
  Gateway's sessionKey `agent:<id>:…`, since `message_sending` gets no
  agentId), else the configured one. The agent id is normalized by
  OpenClaw's own rule, whose output always fits the arbiter's session-id
  form. Every event carries the Gateway's sessionKey under `openclaw`.
  The arbiter's `attachmentSessionId` (§3.3) keeps case and maps an empty
  name to `default`; given the OpenClaw-normalized id (lower case, never
  empty), it builds the same `openclaw:<agentId>`, so the service registers
  a session by the normalized id.
- **The arbiter.** One lazy, unref'd connection to the data socket, shared by
  the tools and the hooks; the hooks speak through a narrow `HookArbiter`
  (`egressFingerprintScan`, `emit`) with an adapter, a mock, and a parity
  test over a real ArbiterServer (`tests/stack/openclaw-plugin-parity`).
- **Tests.** Unit: the tamper rules, the reply decision, the session rule,
  the manifest. Component: the hooks through the real registrar on a fake
  OpenClaw api against a mock arbiter (`test/component/attachment-hooks`).
  Stack: `tests/stack/openclaw-plugin-reply` runs a real arbiter, the real
  proxy for `openclaw:main` and the plugin's production wiring: the model
  never gets the secret, a reply to an unbound chat keeps the placeholder
  and never the value, a reply with the value is cancelled, and with the
  arbiter gone the reply still carries only the placeholder. A real
  OpenClaw: the plugin lane (§9).

## 8. `mandu openclaw install` and the service URL contract

**The contract** (`launcher/src/openclaw-attach.ts`; `mandu serve` writes,
the installer and the doctor read):

```
<runtime>/attachments/<session>/anthropic-proxy.port
```

`<runtime>` is Mandu's runtime dir (`$MANDU_RUNTIME_DIR`, else
`$XDG_RUNTIME_DIR/mandu`, …, the arbiter's), `<session>` the attachment
session (`openclaw:main`; a session id has no `/`). The file holds the
decimal port of the session's model proxy and a newline. It is a regular
file the user owns that neither group nor others can write, in a directory
created 0700, written atomically once the proxy listens on 127.0.0.1 and
removed when it stops. The proxy answers `GET /_mandu/identity` with
`{mandu: true, service: "anthropic-proxy", sessionKey: <session>,
arbiterSock}`: the installer adopts the port only when that matches (a
non-Mandu server, another Mandu service or another session's proxy on the
port is refused), and takes `arbiterSock` for the plugin's config, so the
plugin and the proxy share one arbiter. The pool names a session, and
registers it with `beginAttachment`, by the OpenClaw-normalized agent id
(`attachmentSessionId("openclaw-plugin", normalizeAgentId(id))`), which is
the session the installer and the plugin compute
(`tests/stack/openclaw-attach-session-parity` holds the three equal). The service keeps a session's port
across restarts when it is free, so the route written into `openclaw.json`
stays valid; when it cannot, `mandu doctor` reports the route stale and a
second `mandu openclaw install` moves it.

**Install** (`launcher/src/openclaw-install-command.ts`). `mandu openclaw
install [--agent <id>] [--leave-unprotected <id>[,<id>…]]` checks, writing
nothing until all pass: the plugin directory exists (a source checkout
ships it); the user's config (`$OPENCLAW_CONFIG_PATH`, else
`$OPENCLAW_STATE_DIR/openclaw.json`, else `~/.openclaw/openclaw.json`)
exists and parses as JSON5 with its `$include`s resolved; plugins are not
off and the plugin not denied (a denied plugin is a user's own choice only
in a file Mandu was never installed in: where Mandu's marks are in it, the
plugin entry or the session header, or the service recorded it, the
declaration's `config`, it is a route LOST since, §3.6, and install takes it
back: the deny entry goes, the backup keeps it; plugins switched off as a
whole stay a refusal either way, turning them on loads every other plugin);
every provider is one Route 1 routes, or one the user names in
`--leave-unprotected` (§8.1); and the service proxy of `openclaw:<agent>`
serves the providers it routes: the install declares the session with its
routes (the pool restarts the proxy when they change) and waits until the
port file is trusted, the proxy answers as the session's, and the session's
pool record names the providers key of the routes it declared
(`providersKey`; otherwise it says `mandu serve start`). Without a pool
record (a service from before it, a test's stand-in) nothing says where the
proxy forwards, so a provider with an address of its own is refused there
(`mandu serve upgrade`). Any refusal after the declaration puts the
declaration back as it was. It then plans the edit on the main file only
(`planInstall`): `plugins.load.paths` gains the plugin directory;
`plugins.entries.mandu-inspect` is enabled with `{arbiterSock, scopeId:
<session>, attachment: true, agentId, manduPaths: [Mandu home, runtime
dir]}`; `plugins.allow` names it if the user keeps an allowlist;
`tools.alsoAllow` gains the two tools; each routed provider gets `baseUrl`
(the service proxy for the Anthropic wire, its `/_mandu/openai/<id>` route
for an OpenAI wire), `api` (the wire the proxy reads), the headers
`x-mandu-session-id` / `x-mandu-tenant: live` merged into its own, and its
model entries keep only the fields that describe a model; its key and other
headers stay as they are. No conversation access is granted. The planned
file, includes resolved again, must pass the route check's own verdict
(`routeVerdict` over `attachState` with the declared routes: the plugin
enabled, every routed provider at its route, no model around it, no
provider unaccounted for); else nothing is written. The file is backed up
beside itself (`<file>.mandu-backup-<time>`, never over one) and replaced
atomically with its own mode; a symlinked config is written through to its
target. A run that would change nothing writes nothing. A JSON5 file is
saved as plain JSON (the data kept, the comments only in the backup). The
report lists each provider with its route and the address it goes on to,
and each one left unprotected.

**Uninstall** removes what install added and recognizes as Mandu's (the
entry, a load path ending in `openclaw-inspect-plugin`, the allowlist name,
the two tools), with the same backup, and puts every provider the
declaration recorded back exactly as it was before the install: its
`baseUrl` and `api` (or their absence), its `headers` object (Mandu's
`x-mandu-*` headers go), its `models` list (or none), and no entry at all
for a provider install created; a provider whose route the user moved since
keeps the user's address (only Mandu's headers go). An install, then an
uninstall, gives the file back key for key (dropped model fields excepted:
the backup keeps them); the unit test runs that over every provider shape
through the declared file and back. An Anthropic route from before Route 1,
which no record names, is undone by the old rule (the loopback `baseUrl`
beside the session header goes, and a provider install created from
nothing, `{api: "anthropic-messages", models: []}`, goes with a `models`
block that held only it: found by the fresh-install VM leg, os-test-matrix.md
§10.20); another provider still at a Mandu route with no record keeps that
address, loses Mandu's headers, and is named, with the backup to restore it
from.

### 8.1 Route 1: every provider whose wire the proxy reads

Built 2026-10-25 (`launcher/src/openclaw-providers.ts` `planProviders`, the
declaration's `providers`, the pool's `declaredUpstreamEnv`). Before it the
install routed `anthropic` alone, to the address in the service's
environment, and refused a config that could run any other model.

**Which proxy.** One per session, the anthropic-proxy the pool already
runs. It reads the Anthropic Messages wire at `/v1/messages`, the two
OpenAI wires at `/_mandu/openai/<provider>/…` (`chat/completions`,
`responses`) with a base URL per provider (`MANDU_OPENAI_UPSTREAMS`,
anthropic-proxy route.ts), and Google's Gemini wire at
`/_mandu/google/<provider>/…` (`models/{model}:streamGenerateContent`,
`MANDU_GOOGLE_UPSTREAMS`, since 2026-10-25, model-wires.md §4), and Ollama's
native chat API at `/_mandu/ollama/<provider>/api/chat`
(`MANDU_OLLAMA_UPSTREAMS`, since 2026-10-26, model-wires.md §8), and OpenClaw's
`azure-openai-responses` and `openai-chatgpt-responses` apis on the
Responses route (`…/responses?api-version=…` with an `api-key`, and
`…/codex/responses` with the ChatGPT sign-in's bearer; since 2026-10-26,
model-wires.md §9), through the
same gates: the routes the wrapper
gives OpenClaw's OpenAI-family providers (supported-agents.md §4,
"Non-Anthropic models"), where OpenClaw's gate-surface tables live.
`MANDU_OPENAI_UPSTREAMS` is that proxy's, not the Codex openai-proxy's,
which forwards to one upstream and carries Codex's tables, so no second
proxy, port file or lifeline per session: the contract's
`anthropic-proxy.port` serves every routed provider.

**Which providers** (`planProviders`, pure). The built-ins every OpenClaw has
(`anthropic`, `openai`), every `models.providers.<id>` of the config with its
includes resolved, and every provider a configured model names (agents'
models, fallbacks, Active Memory's; an alias resolved). Each is:

- **routed** when its `api` (a built-in's own when it names none:
  `anthropic-messages`, `openai-responses`, `google-generative-ai` for the
  built-in `google`, `ollama` for the built-in `ollama` and `ollama-cloud`)
  is one the proxy reads and its
  address one the proxy sends to (https, or plain http to a literal loopback
  address; no user, password, query or fragment: base URLs only, never a
  credential). The upstream recorded is that address without a trailing
  slash, path kept (`https://openrouter.ai/api/v1`); a built-in with no
  `baseUrl` of its own (or Anthropic's spelled out) records null, its
  built-in address, which the service's environment may set (a test's
  stand-in model, an operator's gateway). The built-in `openai` is routed
  even when no model names it, so a `/model` switch to it mid-session still
  crosses Mandu. The built-in `google` is routed when the config declares
  it or a model names it, at `/_mandu/google/google` (its address, null,
  is Google's `https://generativelanguage.googleapis.com/v1beta`, or the
  service environment's `MANDU_GOOGLE_UPSTREAMS` entry); it is not added
  when nothing names it, so an earlier install's declaration does not turn
  into a lost route on upgrade (a `/model google/…` switch on such a config
  is refused by the model fence below, like any catalog provider the config
  never names; a reinstall after naming it routes it). The built-in
  `ollama` and `ollama-cloud` the same way, at `/_mandu/ollama/<id>` (their
  addresses, null, are a local Ollama's `http://127.0.0.1:11434` and
  `https://ollama.com`, or the service environment's
  `MANDU_OLLAMA_UPSTREAMS` entry); an Ollama address is recorded without a
  trailing `/v1`, as OpenClaw joins `/api/chat` to it. Every lane version
  joins it to the configured `baseUrl` (model-wires.md §8.1), so no version
  is refused for this wire. An
  `azure-openai-responses` provider (it must name its `baseUrl`) records
  the address OpenClaw itself would call: a `*.openai.azure.com` or
  `*.cognitiveservices.azure.com` address with no path (or `/openai`) is
  `…/openai/v1`. An `openai-chatgpt-responses` provider (a ChatGPT
  sign-in; the built-in `openai` names no `baseUrl` there) records
  `https://chatgpt.com/backend-api/codex` for the backend, any spelling of
  it, and any other base as is (OpenClaw's two transports join `/responses`
  or `/codex/responses` to it; the proxy takes either, model-wires.md §9).
  A ChatGPT sign-in on the built-in `openai` whose entry names no `api` is
  routed as `openai-responses` (its built-in wire): OpenClaw then refuses
  the turn ("Configured openai authentication is not compatible with the
  selected model route", seen on 2026.7.1-2 to 2026.10.7 for the opposite
  pairing) or the provider refuses the bearer; nothing is sent around
  Mandu. Naming `api: "openai-chatgpt-responses"` before the install
  routes it to the ChatGPT backend.
- **one Mandu cannot route**, with why: a wire it cannot read (the Gemini
  CLI login, Bedrock, OpenClaw 2026.3's `openai-codex-responses`: the seam
  the wire readers extend, `PROVIDER_WIRES`),
  Vertex AI (below: OpenClaw 2026.3.x ignores its `baseUrl`), GitHub
  Copilot (below: OpenClaw ignores its `baseUrl`), an Azure provider
  whose `baseUrl` is an Azure AI Foundry OpenAI-v1 endpoint
  (`*.services.ai.azure.com/…/openai/v1`: OpenClaw calls it with the plain
  OpenAI client, and behind the route it would switch to the Azure client),
  an Azure provider while install sees `AZURE_OPENAI_BASE_URL` or
  `AZURE_OPENAI_RESOURCE_NAME` set (in the config's `env` block, its own
  environment, or OpenClaw's dotenv files: OpenClaw's Azure client reads
  them before the provider's `baseUrl`, so every Azure call would go there
  around the route; the running Gateway's own environment and its systemd
  user unit included, model-wires.md §9.1; the route check reports the same
  later as a lost route, or `route-unverified` where it cannot read them),
  no `api`, no `baseUrl`, an address it does not send to (`localhost` is a
  name a hosts file can point anywhere), a credential in the URL, a catalog
  provider only a model names, or a second Anthropic-wire address: the proxy
  has one Messages upstream, so every Anthropic-wire provider of a session
  must name the `anthropic` provider's address (a per-provider Messages route
  would lift it; left to the shared wire core, §6). And OpenClaw's built-in
  `openrouter` with a model the config names, or a key of the user's model
  allowlist names, that `models.providers.openrouter.models` does not list
  (under OpenClaw's id: `openrouter/<id>` for an id with no `/`), or an
  openrouter wildcard in the allowlist: OpenClaw 2026.3.12 and 2026.3.13
  send a model neither their catalog nor that list knows straight to
  `https://openrouter.ai/api/v1`, whatever the provider's `baseUrl` (found
  by the lane's Route 1 leg; read from `resolveModelWithRegistry`; 2026.3.22
  and later honour the `baseUrl`, supported-agents.md §2.1 "The openrouter
  bypass"), an allowlist key is exact there (`openrouter/*` is the model
  `*`), and Mandu can read neither OpenClaw's catalog nor which OpenClaw the
  Gateway will run. A key of the allowlist counts as a model the config
  names for every provider: its provider is judged like a configured
  model's (a switch to it is a `/model` away).

**Vertex AI** (decided 2026-10-26; model-wires.md §4.1). OpenClaw's
`google-vertex` provider, or any provider with api `google-vertex`, is
refused by install (`VERTEX_ROUTE1_WHY`) unless left unprotected. The proxy
reads Vertex (at its root, where OpenClaw's transport sends it), and the
wrapper routes it, but only on OpenClaw 2026.7.1 and later: 2026.3.12, the
plugin's `compat.pluginApi` floor, sends Vertex calls to Google's regional
host whatever the `baseUrl` (pi-ai's google-vertex provider takes no base
URL), and install cannot tell which OpenClaw the Gateway runs, the same
position as the openrouter rule above, with no config shape that closes it.
It stays out of `PROVIDER_WIRES` until the plugin's floor passes 2026.7.1 or
the Gateway's release can be known at install, and the pool's proxy unsets
`MANDU_VERTEX_UPSTREAMS` whatever the service's environment says
(`poolProxyEnv`), so no pool proxy serves Vertex. Anthropic's Claude on Vertex
is a separate provider (`anthropic-vertex`, an external plugin) on another
wire (`rawPredict`), not routed.

**GitHub Copilot** (decided 2026-10-26, `openclaw-model-refs.ts`
`openclawRouteIgnoredWhy`). OpenClaw's `github-copilot` provider (any case)
is refused on every release, whatever its `api` and `baseUrl`, by install and
by the wrapper (agent-model-route.ts): OpenClaw's bundled github-copilot
plugin swaps the model's address at run time for the one its Copilot sign-in
answers with (its `prepareRuntimeAuth`), and the run applies that address
OVER the configured one. Read from the published releases (each tarball's
dist, never run): 2026.3.12 and 2026.3.13 trade the GitHub token for a
Copilot token (`api.github.com/copilot_internal/v2/token`) and keep the
configured `baseUrl`; from 2026.3.22 `prepareRuntimeAuth` returns a
`baseUrl` too (the token's `proxy-ep`, e.g. `api.individual.githubcopilot.com`,
through 2026.7.1-2; by 2026.9.9 the `endpoints.api` of
`api.github.com/copilot_internal/user`, which must be an https
`*.githubcopilot.com` host), and the run sets it on the model over the
configured one (read on 2026.3.22, inline; on 2026.7.1-2, 2026.9.9 and
2026.10.7, `applyPreparedRuntimeAuthToModel`: `preparedAuth.baseUrl ??
model.baseUrl`; every release probed between returns the `baseUrl`).
Measured 2026-10-26 on the real binaries in a CI guest (`openclaw agent
--local` with `github-copilot/gpt-4o`, the provider's `baseUrl` at a local
recorder, GitHub and Copilot scripted behind an `HTTPS_PROXY` that
terminates TLS with a throwaway CA; no real account): 2026.7.1-2, 2026.9.9
and 2026.10.7 sent the turn to `api.individual.githubcopilot.com/chat/completions`
and the recorder saw nothing; 2026.3.12 (its Copilot token cached, since its
own fetch does not take `HTTPS_PROXY`) sent it to the `baseUrl`. So a route Mandu wrote into the provider's
`baseUrl` would be dropped and the conversation, raw tool results included,
sent to `*.githubcopilot.com` around the proxy. Mandu cannot tell which
release the Gateway runs, and the endpoint must be https to a GitHub-trusted
host, so no route can be pinned; the provider can only be left unprotected
on purpose. Before this rule both routes took a declared
`models.providers.github-copilot` with an OpenAI `api` and a `baseUrl` as
routed (a SECURITY REGRESSION found by this reading, closed 2026-10-26): a
declaration that records it is a lost route in the route check
(`route-direct`, "go around Mandu whatever its route"), and install refuses
it (`hard`) until `mandu openclaw uninstall` has put its own address back.
The sign-in itself (the GitHub token to `api.github.com`) carries no model
context and was never routed.

Install refuses while any provider cannot be routed, naming each with why and
where a model names it, unless `--leave-unprotected` names every such one: it
is then left exactly as it is, its calls never cross Mandu, and the
declaration records it (`unprotected`), so the route check counts it as the
user's choice and `mandu serve status` / `mandu doctor` list it as not
protected. A name that is not a provider of the config is a refusal; one Mandu
routes anyway is noted. A provider already at a Mandu route with no record of
its own address cannot be left (`hard`: it would fail every call): its
`baseUrl` goes back first.

**Tool calls written as text (2026-10-26).** OpenClaw's LM Studio and xAI
providers (and any provider plugin using its plain-text tool-call compat
layer) RUN a tool call the model writes in its reply text, which the answer
gate never sees; measured on the lane's real 2026.7.1-2, 2026.9.9 and 2026.10.7 Gateways
with either provider routed. The session's proxy ends such a reply on every
OpenAI-family route of an OpenClaw session, whatever the provider's id
(model-wires.md §10); the plugin lane's text-call legs hold it on every
version.

**A second install.** A provider at Mandu's route keeps its record (its
address and its original entry), so the run changes nothing. A provider
whose address changed after the install (the user, or one of the agent's
programs, §3.6) is routed back to the recorded address, not the new one, and
the report says so: re-pointing a provider is how a program would send its
model's context elsewhere, so adopting a new address takes `mandu openclaw
uninstall`, then install. An Anthropic route from before Route 1, which no
record names, is Anthropic's own address (that install refused any other).

**The pool** (§3.2): the declaration's providers decide the proxy's
upstreams over the service's environment (`declaredUpstreamEnv`), a change
of them restarts the proxy (`reconcilePlan` compares `providersKey`), and the
session's pool record names the key the running proxy was started with,
which install waits for. A version 1 declaration, or `mandu serve attach`
before any install, has no providers: the environment decides, as before.

**The route check** (§3.6) judges every routed provider: each one's
`baseUrl` must name its route at the serving proxy (`providerRoutes`), its
models must carry no endpoint of their own, and a provider the config gained
after the install that is neither routed nor left unprotected is a lost
route (`route-direct`, "added after the install"), since its calls go around
Mandu; so is a provider a configured model names that is neither (a catalog
provider), and the model fence below is judged too (`model-fence`).
`anthropic` left unprotected is not judged. Without recorded
providers (an install before Route 1) the Anthropic route alone is judged,
as before. The doctor and the pool decide by the same functions over the
same declaration; status lists each session's providers and where each goes.

**The model fence** (`openclaw-providers.ts` `planModelFence`; decided
2026-10-25 with the openrouter bypass, supported-agents.md §2.1). OpenClaw
switches a session's model mid-session through `/model`, the
`session_status` tool, `sessions_spawn` (a subagent's model, through
`sessions.patch`) and cron's `payload.model`. With no model allowlist
(`agents.defaults.models`) `sessions.patch` and cron take any model
(measured on 2026.3.12: a spawn onto an unlisted openrouter model was
accepted and its turn went to openrouter.ai), so a switch could reach a
provider Mandu does not route, or the openrouter bypass. So when the user
keeps no allowlist, install writes one: `<id>/*` for each provider it
routes and each the user left unprotected, the openrouter models
`models.providers.openrouter.models` lists by their exact key (never
`openrouter/*`: before 2026.3.22 a key is exact and that one is the model
`*`), and every model the config names of those providers by its exact key
(a release that reads keys exactly can still switch among them; the
default and fallbacks are always allowed). OpenClaw then refuses any other
model ("is not allowed", measured on 2026.3.12 for `session_status` and
`sessions_spawn`). A user's own allowlist is left as it is: its keys are
judged above (each provider routed or left, each openrouter key listed).
The keys install added are recorded in the declaration (`allowlist`, model
references only), so a second install recomputes the fence (adding a newly
routed provider's key, dropping one whose provider went) and uninstall
removes exactly them, leaving a key the user added since. Install's
post-check refuses when a file the config includes would hide the fence.
On a 2026.3.x Gateway, where a wildcard key is not a wildcard, the fence
narrows `/model` to the listed and configured models: the cost of closing
the bypass. The declaration records an empty `allowlist` when the user's own
allowlist is the fence (absent: an install before the fence). The route
check holds the config to the fence (§3.6, "The model fence"): the allowlist
removed, a key of a provider Mandu does not route, an openrouter wildcard or
an unlisted openrouter model is a lost model context, and a second install
takes the fence back (written again; a key added since that opens a hole
removed, `fenceKeysToReclaim`).

**What the user keeps.** The provider's key (`apiKey`, an auth profile) and
headers stay in `openclaw.json` and travel with OpenClaw's request: the proxy
forwards them to the provider's own address and the declaration never holds
one. A provider OpenClaw itself sends headers for (its openrouter provider's
`HTTP-Referer`) sends them as it always does.

**Tests.** Unit: `launcher/test/unit/openclaw-providers.test.ts` (each
provider shape, includes, the refusals and their reasons, the Messages rule,
the openrouter rule, a second install and a lost route, install then
uninstall byte for byte over every shape through the declared file),
`openclaw-route-check.test.ts` (each routed provider's route, one added
since, one left on purpose, the declared file's routes and its credential
refusal), `dashboard/test/unit/supervisor/attachment-pool.test.ts` (the
upstream environment, the restart on a changed provider list, the route
check of an OpenRouter-style provider). Component:
`launcher/test/component/openclaw-install.test.ts` (refused by name with
nothing written or declared, `--leave-unprotected`, an address no pool record
vouches for, a credential in a base URL, the built-in `openai` routed and
recorded, the wait for the declared providers' proxy; the model fence
written, recorded and removed, a user's allowlist left, an unlisted
openrouter key or a wildcard in it refused; GitHub Copilot refused by name,
nothing written, left untouched with `--leave-unprotected`). The openrouter rule and the
fence per version shape: `launcher/test/unit/openclaw-openrouter-fence.test.ts`.
GitHub Copilot: `openclaw-providers.test.ts` (every spelling refused, a
catalog-only one, one an earlier install routed `hard`),
`openclaw-route-check.test.ts` (a declared Copilot route is lost whatever
its `baseUrl`), `agent-model-route.test.ts` (the wrapper refuses it).
Stack:
`tests/stack/serve-pool-invariant.test.ts`, its Route 1 test: the pool's
production form with an OpenRouter-style provider declared, a scripted Chat
Completions model at its own address with a base path, the service's
environment naming other addresses: every request reaches the provider's
own address with its key and header, the credentials file the service
registered reaches it only as its placeholder, and the exfil the model
scripts carries only that. The lane's Route 1 leg (§9).
**The daemon Gateway refusal** stays: `mandu openclaw gateway
start|install|…` protects nothing under the wrapper. Its advice now names
the attachment, and says it is done when the plugin is installed
(`supported-agents.md` §2.1).

**The doctor check** (`mandu doctor`, section "OpenClaw service Gateway"),
shown only when the config shows the plugin or a Mandu route: the plugin
enabled and in attachment mode; every routed provider's calls going to the
session's running service proxy (one ✓ naming them; a ✗ with `mandu serve
start` when it is down, one ✗ per provider whose route points elsewhere or
nowhere and per provider added since the install, with `mandu openclaw
install`; §8.1); the providers left unprotected (a ✗ naming them); model
entries with their own endpoint; each hole in the model fence (a ✗ each,
§3.6); and the line that this is a policy, not a
boundary. Its fix for a lost route is the route check's (§3.6): `mandu
openclaw install`, then `openclaw gateway restart`; both decide by the same
`attachState` + `routeVerdict` over the same reader, so the doctor's own
read and the service's never disagree on one file. The service's timer
check of the route is §3.6 (built).

**One agent per route.** The provider route is global in `openclaw.json`,
so install routes one agent's session (`--agent`, default `main`). A Gateway
with several agents sends every agent's model calls through that one
session's proxy: still masked (the proxy symbolizes every request), but
attributed to one session, and a release in one agent raises the shared
session's watermark. Per-agent routes need per-agent providers and model
references, left open with per-conversation sessions (§6).

**Tests.** Unit: `launcher/test/unit/openclaw-attach.test.ts` (the contract,
the plans, the refusals, the state), `doctor-openclaw-attach.test.ts`, the
refusal wording in `openclaw-argv.test.ts`. Component:
`launcher/test/component/openclaw-install.test.ts` over a temp HOME and a
real identity endpoint (refusal with nothing written, backup, preserved
content and includes, idempotence, a moved service, `$OPENCLAW_CONFIG_PATH`,
a symlinked config, uninstall). Stack:
`tests/stack/openclaw-attach-session-parity.test.ts` (the launcher's session
rule equals the plugin's; the plugin reads the written config as that
session's attachment).

## 9. The test lane (step 5)

Built 2026-10-25: the drill suite's OpenClaw plugin lane,
`integration.openclaw-plugin-gateway` (`replay-drill`, per push, blocking),
and its drift form `integration.openclaw-plugin-gateway-latest` (`env`,
nightly, reported). A real agent CLI against a scripted model: no API key,
no network.

**The stack, per version.** What `mandu serve` and `mandu openclaw install`
set up, the service half in process:

- a real arbiter on the `secrets` axes; the session `openclaw:main`
  registered with `beginAttachment` on the human socket (kind
  `openclaw-plugin`, its coverage, §3.3) and bound to the `openclaw-agent`
  spec as the pool's proxy binds it at boot;
- the real model proxy for that session in its production wiring (data and
  human clients), in front of a scripted model;
- `openclaw gateway run` in the foreground in a temporary HOME, its
  `openclaw.json` carrying the plugin entry and provider route exactly as
  `planInstall` writes them (a unit test holds the two equal), plus a test
  chat channel whose only side is the legacy `outbound.sendText` adapter,
  recording each message it is sent. `message_sending` runs on the
  Gateway's outbound delivery to a channel and on no other path, and every
  shipped channel needs a network service or a source checkout, so the
  lane brings its own;
- each turn driven through the Gateway by its own client, `openclaw agent
  --agent main --deliver --reply-channel <test chat> --reply-to <chat>`.

**What it asserts, per version.**

| | Evidence |
|---|---|
| The plugin loaded | OpenClaw's runtime report (`plugins inspect mandu-inspect --runtime --json`; 2026.3.x has only `plugins info --json`, which counts the hooks without naming them): status `loaded`, enabled, exactly `before_tool_call` and `message_sending`; and the registration line in the Gateway log. A silently skipped plugin fails here. |
| A secret read | the scripted model reads a labelled (no-model) file: its next request carries only the placeholder, and the exfil it then scripts carries only that (the shared launched-run oracle). |
| A kept reply | the final reply names the placeholder: the chat receives the placeholder, never the value; the plugin's `kept` event names the chat. |
| Tamper | calls naming `~/.mandu`, `openclaw.json` and `mandu serve stop` come back refused (OpenClaw hands the model the plugin's refusal, or the proxy's mask of it, §6), the Gateway log shows each refusal, the commands never ran (a marker file each would have written is absent), the refused read returned none of the config, and one tamper event each reached the arbiter as a claim; a benign exec in the same turn ran. |
| A cancelled reply | a reply carrying a registered value: the plugin's `cancelled` event, and nothing of that turn in the chat. |

A version below `compat.pluginApi` must be refused by OpenClaw instead;
none of the lane's versions is.

**The versions.** The pin (`OPENCLAW_VERSION`, 2026.7.1-2) and
`OPENCLAW_PLUGIN_LANE_VERSIONS` in `scripts/ci/pins.env`: 2026.3.12 (the
`compat.pluginApi` floor), 2026.9.9 (the top tested version) and 2026.10.7
(the newest). The CI guest installs each beside the pin, on the agent node,
as `openclaw-<version>`, so a missing one is a failure there; elsewhere the
lane takes `MANDU_OPENCLAW_LANE_BINS=<version>=<path>:…` or
`openclaw-<version>` on PATH and skips a version it cannot find. 2026.10.7
needs node 24.22.1, so the agent node moved there. The hand-run docker rig
(`packaging/docker/Dockerfile.ci`) installs the pin only: there the lane
skips the other three. The drift form installs the newest release on the
agent node (`scripts/ci/agent-latest.sh openclaw`) and runs the lane on it
alone.

**What it found.**

- The plugin loads and both hooks fire on all four versions; no plugin or
  installer change was needed. `message_sending` runs only when a reply is
  delivered to a channel: a CLI turn without `--deliver` reaches none (the
  fresh-install leg's note, os-test-matrix.md §10.20), which is why the
  lane delivers every turn to its test chat.
- The drift check could not run the newest OpenClaw: `agent-latest.sh`
  installed it with the PATH's npm and ran it on the PATH's node, which is
  Mandu's (22.x), and every OpenClaw since 2026.7 refuses that node. It now
  installs and runs OpenClaw on the agent node.
- The refusal of a call that names a secret path reaches the model masked
  (§6, "A refusal the model cannot read").
- OpenClaw quirks the lane works around, none a Mandu defect: 2026.3.12
  keeps one session per agent whatever `--session-id` says, drops every
  character but letters and digits from tool call ids, and warns on every
  run that the entry's id differs from the hint its package name gives
  (`openclaw-inspect-plugin`); 2026.9.9 and later warn that a plugin loaded
  from a path is unverified, and load it; 2026.7.1-2 refuses
  `claude-sonnet-4-5` behind any provider `baseUrl` (`usage.md`), so the
  lane's model is `claude-haiku-4-5`.

**The pool variant** (2026-10-25, once the pool landed). One more test
runs the same Gateway and oracle on 2026.9.9 through `mandu serve`'s pool in
its production form (`servicePool`, as `tests/stack/serve-pool-invariant.test.ts`
starts it): the declared session, the pool's own attachment registration,
the real anthropic-proxy process it spawns for `openclaw:main`, found
through the port file of the service URL contract (§8). The other versions
keep the in-process proxy: the pool is the same on every OpenClaw.

**The Route 1 leg** (2026-10-25, §8.1). On the same one version, a third
test gives the Gateway an OpenRouter-style provider as its primary
(`openrouter`, `api: "openai-completions"`, its own `baseUrl` with a path,
its own `apiKey` and a header of the user's), in front of a scripted Chat
Completions model (`tests/lib/fake-chat-completions.ts`). `mandu openclaw
install`'s own plan records it (`planProviders`) and writes its route
(`planInstall`); the pool, given that declaration, starts the session's
proxy with the provider's address as its upstream (the service's
environment names a dead Anthropic address). The model reads a labelled
file. Asserted: every request reached the provider's own address (its base
path, its key and header untouched), the read reached it only as its
placeholder, and the chat got the placeholder, never the value. Run
locally on 2026.3.12 and 2026.9.9 before it landed. It found OpenClaw
2026.3.12 sending a model of its built-in `openrouter` provider that
neither its catalog nor the provider's `models` list knows to
`https://openrouter.ai/api/v1` whatever the `baseUrl` (the first run's
request never reached the proxy); install now refuses such a model unless
it is listed (§8.1), and the leg's model is listed.

**The model-fence leg** (2026-10-25, §8.1 "The model fence"). On 2026.3.12
only (the release with the openrouter bypass), when the lane finds it: the
same OpenRouter-style provider with its one listed model as the primary, no
allowlist of the user's, and install's own plan with the fence
(`planProviders`, `planModelFence`, `planInstall`); the Gateway's
`HTTPS_PROXY` is a recording proxy that refuses every CONNECT, and the
route points at the scripted model directly (the model proxy is the Route 1
leg's). The model calls `sessions_spawn` and then `session_status` with an
openrouter model the install did not list. Asserted: OpenClaw answers each
"not allowed", the next turn runs on the listed model at the route, and
nothing went toward openrouter.ai. Run locally with the fence off, the
spawn was accepted and its child's turn left as `CONNECT openrouter.ai:443`.

**The bypass oracle** (2026-10-26, model-wires.md §11). The legs above each
prove one provider on one route; every bypass found so far (the 2026.3.12
OpenRouter model, Copilot's sign-in endpoint, Azure's endpoint variables)
was found by hand. `integration.openclaw-bypass-oracle` (`replay-drill`,
per push, blocking; the drill suite's `openclaw-bypass-oracle.test.ts`)
records where a real OpenClaw's connections go, without its cooperation:
the Gateway and every client turn run in an *egress box* (a user, network,
mount and PID namespace made without host root, loopback only), whose one
way out is a bridge to the Mandu proxy's port; a catch-all listener on 80,
443 and every scripted upstream's own port and a DNS stub record every
other dial with its name, SNI or HTTP request line (model-wires.md §11 has
the recorder, its three tiers and the judge).

*Coverage from the routing tables.* The drill suite's `openclaw-bypass-matrix.ts`
judges each of OpenClaw's twelve `api` kinds (and Copilot and Vertex by
their ids) with the production code itself: Route 1 by `planProviders`
(`PROVIDER_WIRES`, the Copilot and Vertex refusals), the wrapper by
`openclawProviderVerdict`. Every routed cell must have a leg; a wire added
to either table without one fails the matrix check, per push, as "routed
but unproven"; a leg on a refused cell fails as stale. Today:

| Wire | Route 1 | Wrapper |
|---|---|---|
| anthropic-messages, openai-completions, openai-responses, google-generative-ai, ollama | a turn on every version | a turn on every version |
| azure-openai-responses, openai-chatgpt-responses | a turn from 2026.7; on 2026.3.12 refused by OpenClaw's own config schema (the Gateway does not start), nothing leaves | the same |
| google-vertex (OpenClaw's own provider) | refused by install (2026.3.x ignores its `baseUrl`) | a turn from 2026.7.1; on 2026.3.12 the launch is refused naming the release, nothing leaves |
| bedrock-converse-stream, google-interactions, pi-messages, github-copilot (the api, and the id whatever its api) | refused by install, with the reason | refused by the launch, with the reason |
| OpenClaw's CLI backends, `claude-cli/…` and `codex-cli/…` (the vendor's own CLI runs the turn) | refused by install (no `models.providers` entry to route) | refused by the launch |

*Per version, two runs.* Route 1: one user config with one provider per
routed wire and one OpenClaw agent per provider, install's own plan
(`planProviders`, `planModelFence`, `planInstall`), the pool's real proxy
for `openclaw:main`, the plugin loaded; one model turn per agent. Wrapper:
the same providers under `mandu openclaw gateway run` (the real launcher,
its own proxy on a port the box bridges, its `openclaw` a shim that runs the
real one in the box); the same turns, each driven as Mandu supports a
client of a Gateway started under it, `mandu openclaw agent` with
`MANDU_OPENCLAW_GATEWAY_CLIENT=1` (its own launch and proxy). Plus a
fallback leg: one client whose config names a dead Gateway port. Each
scripted upstream sits outside the box, reachable only through a proxy.

*OpenClaw's gateway-client fallback* (found 2026-10-26, pipelines 13470 and
13487). `openclaw agent` without `--local` runs a turn itself, in the client
process, with the client's own config, when its Gateway call fails: 2026.3.12
on any error (`agentCliCommand`: "Gateway agent failed; falling back to
embedded"), 2026.7.1-2 on a lost connection, an auth failure or a timeout
("EMBEDDED FALLBACK"); 2026.9.9 and 2026.10.7 did not fall back on a refused
connection. The wrapper leg first drove raw `openclaw agent` clients, and
twice on 2026.3.12 a Gateway call failed under the CI guest's load and the
client ran the turn itself, straight at the provider's own address (the box
named the dialer `openclaw-agent`, OpenClaw's process title for that CLI,
not the `openclaw-gateway` the wrapper runs). Not a bypass of the wrapper's
route: the wrapped Gateway sent nothing around it. But it is a real
exposure of a client run without Mandu against a Gateway run under it: that
client's own run reads the user's unrouted config. Under Route 1 the same
fallback reads the routed config install wrote, and stays on the route.
Under `mandu openclaw agent` it reads the launch's routed run config: the
fallback leg proves it (on 2026.3.12 and 2026.7.1-2 the client runs the turn
itself and the call reaches the upstream through that launch's proxy;
2026.9.9 and 2026.10.7 exit instead). The leg retries a turn the client ran
itself (at most twice) and fails a run in which no turn reached the Gateway.
Driving those clients under Mandu found one more thing: with
`OPENCLAW_GATEWAY_TOKEN` in the environment of both launches, 2026.3.12 and
2026.7.1-2 (which read the variable before the config) refused every client
with "gateway token mismatch", so every turn fell back. The cause: the
environment mask gave both launches the token's placeholder (the same one:
an environment secret is minted once per value), but the run config kept
the user's literal `gateway.auth.token`, which the Gateway expected. Fixed
2026-10-27 (confidentiality plan 10 §11.4, "OpenClaw's Gateway credentials:
one stable placeholder"): each launch writes the same placeholder over the
config's Gateway credentials and over a `--token` / `--password` on its
command line (or refuses the launch when it cannot), so no OpenClaw process
of a Mandu launch holds the real token; the lane keeps the token in every launch's environment and
config and asserts no client is refused it, on every version. The cost: a
client outside Mandu holding the real token cannot connect to a Gateway
under Mandu.

*The oracle.* (1) Utility: every routed provider's upstream received its
turn through the proxy (a green run with no model call fails). (2) The box's
verdict: no bypass (a dial to an upstream's own port, a model-API host or a
model-API path) and no unknown egress. (3) The negative control, in every
Route 1 run: one more provider whose installed route is reverted to its own
address (a test-only edit, what a release that ignores the `baseUrl` does);
its turn must be reported as a bypass, and its upstream must receive
nothing. On 2026.3.12 a second control drives the real bug: an OpenRouter
model the config does not list, with the install's fence removed (test-only),
whose turn goes to openrouter.ai; on the strongest box tier the oracle
reports it by name and SNI.

*What it found* (2026-10-26, the CI guest's `netns+caps` box with the peek
certificate, every lane version). No model call left around the proxy on
any version, by either route; the two controls went red as they must (on
2026.3.12 with the fence off, the box read the unlisted model's
`POST https://openrouter.ai/api/v1/chat/completions` from the Gateway
itself). Below a leg's floor, 2026.3.12 refused the Azure and ChatGPT apis
in its config schema and the wrapper refused the Vertex launch, with
nothing leaving. About seven minutes for the four versions. Every
other connection the Gateways made is named, with the program that dialed
(the box reads the client socket's owner from `/proc`):

- `registry.npmjs.org` (OpenClaw's update check) and
  `telemetry.openclaw.ai` (`GET /api/latest-version`): named benign.
- `claude auth status --json`, which the Gateway's spawn broker runs at
  start and per turn on 2026.9.9 and 2026.10.7 to learn whether its
  `claude-cli` backend has a Claude Code sign-in: the CLI dials
  `api.anthropic.com` (Claude Code's `HEAD /api/hello`), often exiting
  before its connection is read, so the box names it by the lookup it made
  (the DNS stub reads the asking socket's owner too). The CLI also makes
  itself non-dumpable part way through its start, which hid its socket
  from `/proc` in about one run in six (MR !2566's pipeline went red on
  it, 2026-10-26); the box now names such a holder by the set of hidden
  processes it must be one of, all of them `claude auth status` (model-wires.md
  §11). An auth check, no
  conversation: named benign by its command line, and a model-API path from
  it would still fail, as would a connection whose address another program
  also looked up. A model on that backend is refused by both routes (the
  matrix row above).
- `GET https://openrouter.ai/api/v1/models` under the wrapper on 2026.9.9
  (OpenClaw's catalog of an `openrouter` provider): a bodiless read of a
  model catalog, reported as provider-side, not failed.
- 2026.10.7 refuses `agents.list` (moved to the keyed `agents.entries`, with
  `agents.ownership: "explicit"` for a roster and no `default` marker), and
  warns that the install's model fence `agents.defaults.models` is legacy
  (it still loads; `agents.defaults.modelPolicy.allow` is the new key, which
  matters to the fence only on 2026.3.12-13, the releases with the
  openrouter bypass).

*What it cannot see* is model-wires.md §11's list: no packet capture (a
dial to a port outside the catch ports is refused, not recorded), IPv6 only
`::1`; on a host whose AppArmor policy denies capabilities in a user
namespace the box has no port below 1024, so a dial to a provider's 443 is
refused unattributed and only the utility control turns it red; with no
namespace at all the in-process fallback blocks nothing and the test says so.

*Clients of a Gateway under Mandu* (2026-10-26). The gateway-client fallback
above leaves a residual Mandu cannot close from the wrapper: a plain
`openclaw agent` or `openclaw tui` against `mandu openclaw gateway run` runs
a failed turn itself on the user's own, unrouted `openclaw.json`. What was
weighed: OpenClaw has no switch to turn the fallback off (2026.7.1-2's
`agentCliCommand` falls back on any `GatewayTransportError`, 2026.3.12 on any
error); routing the user's own config is what Route 1 does
(`mandu openclaw install`, under which the same fallback stays on the route),
and the wrapper by design never edits it; `mandu doctor` cannot tell which
client a user will run. So the launch says it, one line before the Gateway
starts (`openclaw-argv.ts` `openclawGatewayClientNotice`: the channels and
`mandu openclaw agent` / `tui` with `MANDU_OPENCLAW_GATEWAY_CLIENT=1` are
protected, a plain client is not), `docs/usage.md` says it, and the
oracle's wrapper leg asserts the line is in the launch's output. A user who
wants every client covered attaches Mandu with Route 1 instead.

**The first live run** (2026-10-26, on the maintainer's go). The drill
suite's live harness runs the lane's legs on a real model: OpenClaw
2026.10.7's built-in `openai` provider on a ChatGPT sign-in (`api:
"openai-chatgpt-responses"`, no `baseUrl`, a `token` auth profile holding
only the sign-in's access token, never its refresh token), routed by
install's own plan through `mandu serve`'s pool to
`https://chatgpt.com/backend-api/codex`, with a recording relay (bodies
only, no header) between the proxy and the backend. Model
`gpt-5.6-luna`; five sessions; every leg passed:

- **secret**: the model called `read` on the labelled file and received
  `$MDU:nomodel_read[…]`; no request it received carried the value;
- **reply**: the chat received the placeholder (`openclaw:reply:unbound`);
- **leak**: asked to join two halves of a registered value, the model wrote
  it; `message_sending` cancelled the reply (`openclaw:reply:fingerprint`)
  and the chat received nothing;
- **the tier** (§10): `cat` of the labelled file ran in the box (seccomp
  filter, Mandu's home hidden, the egress proxy) and reached the model as a
  placeholder; the same file through `cat *.md`, a command that names no
  secret file, reached it as the box twin's placeholder (the proxy masked
  nothing); asked to POST the file to an unbound host, the model sent the
  placeholder, the egress proxy answered 403, nothing arrived, and the reply
  reached the chat.

The bearer passed through the proxy as sent (§9.2 of model-wires.md); the
run dirs held none of the sign-in's tokens. Found, none a leak: OpenClaw's
memory plugin asks the `openai` provider for embeddings at the route, which
the proxy refuses (403), so its memory sync fails under a ChatGPT sign-in
(the backend serves no embeddings either); the turns ran on OpenClaw's
embedded runtime, not the native Codex harness, since the route's
`baseUrl` is a custom endpoint; and the value a cancelled reply carried is
still printed to the `openclaw agent` caller's own terminal (not a channel,
§3.5).

**The drill catalog on the plugin** (2026-10-26). The live drill runner
takes the plugin as two targets of its own, `openclaw-plugin` (Route 1)
and `openclaw-plugin-sandbox` (the tier of §10): one resident Gateway per
drill with the plugin attached through `mandu serve`'s pool, on the run's
own arbiter, the turns through `openclaw agent --deliver` to a test chat,
graded on the attachment's (and the box's) events, the chat and the
model wire (the drill runner doc §3.16). Each drill says which tier
covers it (`Drill.plugin`, with the reason): Route 1 does not cover the
egress gate on the agent's own programs, the guard's holds, a declassified
session's confinement and a secret that is only an environment variable
(§5: the commands run on the host); the sandbox tier does not cover the
holds (the launch's ask mode, which the box never takes) nor a Gateway
environment variable (never passed to the box), and neither covers a value
registered through a launch's environment. Route 1 runs 42 of OpenClaw's
58 live drills, the sandbox tier 54. The first runs (2026-10-26, OpenClaw 2026.10.7, `gpt-5.6-luna` on a
ChatGPT sign-in; the drill runner doc §3.16 has the table and every red's
cause): Route 1 30 PASS, 11 WARN, 1 FAIL of 42; the sandbox tier 43 PASS,
9 WARN, 2 FAIL of 54; no raw secret reached the model, a chat or the
network. They found one product gap, fixed: relative tool paths and path
labels (§3.2, `MANDU_AGENT_CWD`). One utility over-block found there is
fixed: the reply tripwire matched a masked command output's row line by
line, so a harmless reply repeating one of its lines was cancelled; a reply
now counts such a row only by its secrets (§3.5). A second is fixed too: on
the tier, a HIGH session's `web_fetch` (which stays in the Gateway, §10.5)
to the declassified file's bound host asked (`session:high-tainted-bound`)
where the wrapper sent it. The taint came from Mandu's own prompt filter:
OpenClaw's side call repeated a line of the memo, and the filter's mask of
it was minted untrusted, though the integrity axis is off. Such a mint is
trusted under `secrets` now (confidentiality.md §9, the table's note), so
both tiers release the bound host.

## 10. Confined commands: Mandu as OpenClaw's sandbox backend

**Status (2026-10-26): built.** The plugin's opt-in tier: `mandu openclaw
install --sandbox` (Linux) makes Mandu the Gateway's sandbox backend, so
every command the agent runs and every file OpenClaw's own tools touch run
in a box Mandu confines. It closes the largest gap of §5 for what the agent
runs, without running the Gateway itself under the wrapper. Mode `secrets`;
no integrity behaviour.

### 10.1 The seam

OpenClaw hands each command and each file-tool operation of a sandboxed
session to a sandbox backend. Docker is built in; NVIDIA's OpenShell plugs
in the same way, through `registerSandboxBackend(id, {factory})` from
`openclaw/plugin-sdk/sandbox`. A feasibility probe (2026-10-26, on
2026.10.7, with 2026.9.9's code read) settled the contract, and the lane
(§10.8) now runs it on every lane version:

- **Registration.** No published types, no runtime check of the plugin's
  origin (OpenClaw logs "can't verify where this plugin came from" and
  loads it). The registry is a process-global map, **last writer wins**.
  The seam exists from 2026.7 (2026.7.1-2 has it); 2026.3.12 has neither the
  SDK module nor `sandbox.backend` in its config schema, which is strict,
  so a Gateway given the tier's config refuses to start (fail closed: no
  command runs anywhere).
- **The factory**, once per sandbox scope (`scope: "agent"`, so once per
  agent), with the session and scope keys, the workspace folders and the
  sandbox config, returns a handle (`SandboxBackendHandle`):
  `buildExecSpec({command, workdir, env, usePty})` → `{argv, env, cwd,
  stdinMode}`, which OpenClaw spawns exactly (background runs, the
  `process` tool and its stdin, the same child; 2026.7.1-2's spec has no
  `cwd`, which the relay does not need); `runShellCommand({script, args,
  stdin})` for OpenClaw's own small scripts (its process cleanup scans
  `/proc` for a marker through it); `finalizeExec` after each command;
  `createFsBridge({sandbox})` for read, write, edit, `ls`, `apply_patch`
  and the rest, else OpenClaw's default bridge.
- **The config.** `agents.defaults.sandbox.{mode, backend, scope,
  workspaceAccess}` (and per agent). `mode: "all"`: `non-main` leaves the
  main chat on the host. A sandboxed session gets OpenClaw's fixed tool
  policy (`tools.sandbox.tools`): its default allowlist leaves out the chat
  tool, the web tools and every plugin tool (Mandu's `inspect_symbol`
  included), and its default denylist holds the host-side tools (browser,
  canvas, nodes, the Gateway tool, automations, the channel tools);
  `alsoAllow` adds to the allowlist and lifts a matching default deny.
  `workspaceAccess: "rw"` keeps every path what it is on the host.
- **The escapes** run on the host whatever the backend: `tools.elevated`
  (`/elevated on`), `tools.exec.host: "gateway"` (or `"node"`), and an
  operator's `sessions.patch sandboxMode: "off"`. A model asking for
  `host: "gateway"` on its own was refused.

### 10.2 The box: a Mandu launch

The box is not a second sandbox. It is a `mandu --target shell` launch of
the launcher this install runs (`Layout.launcherArgv`: the package's bin, or
a checkout's `launcher/mandu-run.sh`), whose program is the plugin's box
host (`box/host.mjs`), so the launcher's own machinery confines everything
the host starts, exactly as it confines the programs of `mandu claude` on
the `secrets` axes: the secret twins (a labelled or registered file reads
as its placeholder copy, served by the guard or the bind), the network
guard (a connection reaches only the session's egress proxy, which puts a
value back only at a host a binding names and refuses or keeps the
placeholder elsewhere), Mandu's home hidden and its runtime registries
write-protected, the human plane walled, no root. The plugin
(`src/sandbox/box.ts`) adds to the launch:

- `--no-reply-filter`: a command's output goes to the model, which must
  see placeholders (the filter would put values back for a person);
- `--require-own-confinement` (new, launcher `parse.ts`): refuse where this
  launch cannot be confined (no guard, no user namespace) instead of the
  default `gated` degrade, while the attachment beside it only warns
  (`--require-confinement` would refuse because of it, §3.3);
- `--write-protect <path>` (new, repeatable): the OpenClaw config (the file,
  the file it links to, its includes), the state folder's `extensions/` and
  the plugin itself, refused to the box as `policy.yaml write_protect.deny`
  entries are (write-protection.md §5);
- an environment taken from the Gateway's by a short allowlist (`PATH`,
  `HOME`, the locale, `TERM`, `TMPDIR`, `XDG_*`, and of Mandu's own only
  where things are and which build runs: `MANDU_HOME`, `MANDU_RUNTIME_DIR`,
  `MANDU_TENANT`, `MANDU_POLICY_FILE`, the layout and native-bin overrides,
  never a mode or an opt-out switch such as `MANDU_NET_GUARD=0`): the
  Gateway's own provider keys and channel tokens do not belong to the
  commands, as they do not reach a Docker sandbox; `MANDU_ARBITER_SOCK` (the
  attachment's arbiter) and `MANDU_NO_ARBITER_AUTOSTART=1` (the service
  supervises that arbiter; with it down the launch refuses rather than
  start a second stack).

One box per agent workspace, started on first use (the first command waits
for the launch, a few seconds) and kept for the Gateway's life: the host's
stdin is a pipe from the plugin, its lifeline, so a Gateway gone ends the
host and the launch with it; a box that ends is started again by the next
command. The box is its own Mandu session (a `shell` launch), not the
attachment's `openclaw:<agent>`: its posture record, its guard's records
and its egress decisions are that launch's.

**Ready only when confined.** The host's first stdout line reports what it
sees of its own world (`box/policy.mjs` `boxFactsProblems`): the `Seccomp:`
mode of `/proc/self/status` (2: the guard's filter), whether a file the
plugin found in the Mandu home opens (it must not), whether the launch gave
it an egress proxy (`HTTPS_PROXY`) and whether the guard names the proxy's
port (`MANDU_NET_GUARD_PROXY_PORTS`). A box that falls short is stopped and
refused, as is a launch that refuses, exits or takes longer than two
minutes; a failed start is not retried for five seconds.

### 10.3 The handle

`src/sandbox/backend.ts`, registered asynchronously: the registrar is
synchronous (OpenClaw ignores a returned promise), and the SDK module does
not exist before 2026.7, so it is imported after `register` returns; where
it is missing the plugin logs why the tier is off and its hooks and tools
load as before.

- **buildExecSpec.** The plugin prepares the command with the box host over
  its Unix socket (in a private folder under the Gateway's temp dir): the
  text, the folder, OpenClaw's environment, whether a terminal was asked.
  The host answers with a one-time ticket (good for a minute). The argv
  OpenClaw spawns is the exec relay (`box/relay.mjs`) under the Gateway's
  own node, with the socket and the ticket; its environment is `PATH`,
  `HOME`, `LANG`, `TERM`, `TZ` only. The relay presents the ticket, then
  streams: its stdin to the command, the command's stdout and stderr back,
  its exit status (128 + n for a signal) as its own. A signal it receives
  goes to the command's process group; the relay killed outright closes
  the socket, and the host kills the group. The command, its folder and its
  environment never appear in an argv.
- **The command's world** (host side, `box/policy.mjs`): `/bin/sh -c
  <command>`, under `script(1)` when a terminal was asked; the box's own
  environment, with OpenClaw's on top except a name the launch masked (a
  placeholder), a protected name the box sets (the proxy and CA variables,
  `NODE_OPTIONS`, the model routes, `KUBECONFIG`, `HOME`) or any `MANDU_*`;
  `PATH` is the box's with OpenClaw's new folders appended. `HOME` stays the
  user's: OpenClaw gives a sandboxed command the workspace as `HOME`, as a
  container has no home of the user's, but the box runs on the user's files,
  where a program finds its config and a credential file reads as its
  placeholder copy.
- **runShellCommand**: the same, without a ticket (the plugin is the
  client), output collected; a nonzero exit throws unless `allowFailure`.
- **createFsBridge**: §10.4.
- **Refused in the factory** (fail closed, OpenClaw reports the tool
  failed): not Linux; `workspaceAccess` other than `rw` (the bridge's paths
  are the host's, and a read-only workspace is not something the box
  enforces for commands).

### 10.4 The file bridge

Without a bridge of the backend's own, OpenClaw's default bridge reads a
file with the Gateway's own `fs` on the host: a labelled file's real bytes
would go to the model, masked only by the model proxy after the fact, and
an `edit` would write a text patched from those real bytes into the box,
where it lands in the placeholder copy with the values in it. So the
backend brings its own (`src/sandbox/fs-bridge.ts`), and every operation
runs IN THE BOX, by the host (`box/host.mjs` `fs`: realpath, stat, read,
readdir, write, mkdirp, remove, rename, copy), inside OpenClaw's mounts (the
workspace, the agent's workspace, the skills and resources read-only; a
path outside them, or a link out of them, is refused in the box). The host
is the launch's agent executable (node), which the guard always serves the
twin. A read of a labelled file is its placeholder copy, exactly what `cat`
prints; a write of an unprotected file lands on it.

**A write to a protected file** (the box's view differs from the real
bytes) is the one operation that runs outside. `edit` reads, patches and
writes the whole file back, so the text it writes is the twin's with the
model's change: written as is it would put placeholders over the user's
values, and written into the copy alone (what a command's write does) the
change would be lost. The bridge writes the real file instead
(`src/sandbox/write-back.ts`, pure), under one rule: a line of the written
text that carries one of the file's OWN placeholders must be, byte for
byte, a line of the twin, and is written as that line of the real file;
every other line is written as the model wrote it. So a value goes back
only to the line it came from: the model can keep, drop, duplicate or move
a whole line holding a value, and change every other line, but cannot carry
a value into a line of its own making (a URL, a command, another key),
where a program the person runs later would read it (a confused deputy:
plan 16 §4.7's risk, here closed by construction). Another file's
placeholder stays the placeholder text. The twin must map the real file
line for line (each twin line's text outside its placeholders is the real
line's, a quoted placeholder `KEY='$MDU:…'` counting with its quotes);
otherwise, and for a whole-file placeholder, only a write that carries none
of its placeholders goes through. The real file is replaced atomically
(a temp file in its folder, its mode kept, a file with other hard links
refused), only inside a writable mount, with the folder above re-checked
right before; then the model's text goes into the copy, so the box keeps
reading what the model wrote. A refusal says why and leaves both as they
were. The values never leave their file and nothing of them reaches the
model. This is narrower than plan 16's write-back (no new file gets values,
no value moves) and needs no arbiter op: the bridge runs in the Gateway,
which holds the real file already.

### 10.5 What moves into the box, what stays on the host

| In the box | On the Gateway's host (as without the tier) |
|---|---|
| every `exec` command and its children, background runs | the Gateway process and the plugin |
| OpenClaw's file tools: `read`, `write`, `edit`, `ls`, `apply_patch`, … | other plugins' tools (`group:plugins`, re-allowed) and MCP servers |
| OpenClaw's own sandbox scripts (process cleanup) | the browser, canvas, nodes, the Gateway tool, automations (OpenClaw's sandbox keeps them denied) |
| | `tools.elevated` and `tools.exec.host: gateway` (install turns both off; doctor flags them) |
| | memory and session tools, the chat tool (they act through the Gateway) |

### 10.6 Install, uninstall, doctor, the route check

`launcher/src/openclaw-sandbox.ts` (pure) and `openclaw-install-command.ts`:

- **Install** (`--sandbox`; a later plain install keeps the tier,
  `--no-sandbox` takes it out). Refused, writing nothing, off Linux, without
  unprivileged user namespaces (`probeUserns`, the reason named), or when
  this Mandu cannot name its launcher. It writes `agents.defaults.sandbox`
  `{…the user's own keys, mode: "all", backend: "mandu", scope: "agent",
  workspaceAccess: "rw"}`, `tools.sandbox.tools.alsoAllow` += `message`,
  `group:web`, `group:plugins`, `tools.elevated.enabled: false`, removes a
  `tools.exec.host` of `gateway` or `node`, and the plugin entry's `sandbox`
  block `{launcher, writeProtect, statusFile}`. Its post-check runs the
  doctor's own judgement (`sandboxTierProblems`) over the edited file with
  its includes resolved: an include or the agent's own entry
  (`agents.list[]` / `agents.entries`) that overrides a key refuses the
  install. What the install replaced is recorded at its first install in the
  declaration (`serve-attachments.json`, the entry's `sandbox.original`:
  the whole sandbox block, `alsoAllow`, `elevated`, `exec.host`; config
  only, no value).
- **Uninstall and `--no-sandbox`** put each value back as it was (the
  user's Docker sandbox settings included); a sandbox the user moved to
  another backend since is theirs. Without a record only Mandu's own
  values go and elevated stays off.
- **The doctor** (`gatherOpenclawAttach` → `sandboxRows`) and **the
  service's route check** (`attachment-pool.ts`, every 30 s and on every
  change, beside the route) judge, by `sandboxTierProblems`
  (`attachment-contract.ts`, shared): the mode not `all`, the backend not
  `mandu`, `tools.exec.host` `gateway`/`node`, elevated not off (each a
  command possibly outside the box: `unconfined`); `workspaceAccess` not
  `rw`, the tool gate missing an entry (utility). And **last writer wins**:
  the plugin checks every 30 s that the factory OpenClaw holds for `mandu`
  is its own (`getSandboxBackendFactory`), logs loudly when it is not, and
  writes `<runtime>/attachments/<session>/openclaw-sandbox.json`
  `{version, pid, checkedAt, sdk, registered, ours}`; a fresh record from a
  live Gateway saying `ours: false` is `backend-replaced`, `registered:
  false` is `backend-missing`. The pool logs `SANDBOX LOST` and records
  `sandbox: {state, problems, checkedAt}` in its pool record, which `mandu
  serve status` and the doctor's service section print with the fix
  (`mandu openclaw install --sandbox`, then `openclaw gateway restart`).
  The attachment's coverage and posture are unchanged: they never claimed
  the box (the Gateway itself stays unconfined).

### 10.7 Fail closed

| What fails | What happens |
|---|---|
| not Linux, no user namespaces | install refuses; a config written by hand: the factory throws, no command runs |
| OpenClaw before 2026.7 | the Gateway refuses the config (schema); the plugin logs the tier off |
| the launch refuses (no guard, no bwrap, the arbiter down) or exits | the box is not ready: buildExecSpec, runShellCommand and every bridge call throw; OpenClaw reports the tool failed |
| the box reports itself unconfined | stopped and refused, as above |
| the box dies mid-session | the relay cannot connect: exit 126, "the command did not run"; the next call starts a new box |
| a used, unknown or expired ticket | refused by the host, exit 126 |
| the arbiter goes down while the box runs | the launch's own fail-closed behaviour (twins, a refused egress) |
| a protected file's write that cannot be put back | refused with the reason; the file and its copy unchanged |
| another plugin takes `mandu` | reported loudly (log, status file, doctor, the pool); not prevented (§10.9) |

### 10.8 Tests

- Unit: `test/unit/box-wire.test.ts` (the frame codec, the environment
  merge, the argv, the root check, the facts), `test/unit/write-back.test.ts`
  (each write-back shape: a change put back byte for byte, CRLF, a moved or
  duplicated line, every confused-deputy shape refused, another file's
  placeholder, a whole-file twin, misalignment, ambiguity, the quoted dotenv
  twin), `launcher/test/unit/openclaw-sandbox.test.ts` (install and
  uninstall key for key, the record, every problem kind in both roster
  forms, the status's freshness, the pool record, the doctor rows, the
  refusal), `parse.test.ts` (the two launcher flags).
- Component: the plugin's `test/component/sandbox-backend.test.ts` (the host
  and the relay as plain processes against a fake OpenClaw caller: the
  registration through a fake seam, buildExecSpec's argv spawned as OpenClaw
  spawns it, stdin, exit, signals, a killed relay killing its command,
  runShellCommand, the bridge's operations and mounts, the write-back, and
  every fail-closed branch), `launcher/test/component/openclaw-install-sandbox.test.ts`
  (refusals writing nothing, install, a plain re-install, `--no-sandbox`
  and uninstall giving the user's settings back, the post-check, the doctor
  facts and a replaced backend).
- Sandbox kind: `tests/sandbox/openclaw-box.test.ts`: the plugin's
  ManduBox over the REAL launcher, guard and egress proxy beside a real
  arbiter with an attachment live: confined facts; a labelled `.env` reads
  as its placeholder through a command and the bridge; the placeholder
  refused at an unbound host and the value delivered only at the bound one;
  a direct connection refused; Mandu's folder unreadable and unwritable and
  a `--write-protect` path unchangeable; the bridge's edit putting the value
  back; with the arbiter gone the box does not come up and the relay runs
  nothing.
- The drill suite's `integration.openclaw-sandbox-backend` (per push): a
  real Gateway per lane version with the tier as install writes it, a
  scripted model, no key, no network. Per version: a command runs in the
  box (the guard's filter, the egress proxy); a labelled file read by `cat`
  (its copy shows the box's view) and by OpenClaw's `read` reaches the
  model only as its placeholder; the placeholder posted to an unbound host
  is refused (403) and to the file's bound host the value arrives there
  only; the reply reaches the chat with the placeholder (the tool gate lets
  the turn finish); commands spelled past the tamper policy cannot read or
  write Mandu's folder nor change `openclaw.json` or the plugin; `edit` of a
  labelled `.env` changes its line with the real value put back byte for
  byte, and the box reads the edit with the value still a placeholder. On
  2026.3.12, the Gateway refuses the config. One more test: a second plugin
  registering `mandu` after Mandu's is reported (`backend-replaced`).

### 10.9 Frictions and risks

- **Latency.** The first command of a Gateway's life waits for the launch
  (about 3 to 7 s on the hosts measured); later ones cost a node relay
  start (tens of ms). A per-command launch, the simplest reuse, was
  measured at 2 to 7 s a command and rejected (OpenClaw's file tools make
  several calls an operation).
- **What stays on the host** (§10.5) is the attachment's old exposure:
  other plugins, MCP servers, the browser and nodes read and send as the
  user; their results reach the model masked by the proxy. The exposure
  cost of §3.3 is unchanged (the Gateway still reaches the human socket).
- **A protected file's edit is narrower than the user may expect**: a value
  line cannot be edited (the model does not know the value), only kept,
  dropped or moved whole; a whole-file placeholder (a key file) cannot be
  edited at all. A command's write to a protected file lands in the copy,
  as in the wrapper (the session's end names it).
- **The write-back's residual race**: the real file is written by the
  Gateway with the folder above re-checked just before; a program in the
  box that swaps that folder for a link in the instant between could point
  the write elsewhere inside the user's files (never at the model or the
  network); the alignment check makes a useful target unlikely.
- **The socket and the status file are reachable**: a program in the box
  can connect to the box's own socket and run more commands in the box
  (nothing it could not run already); the status file is the Gateway's
  claim (a plugin in the same process can forge it, or patch OpenClaw's
  registry outright): the last-writer check catches an honest collision,
  not a malicious plugin, which already runs as the user.
- **`HOME` differs from Docker's**: commands see the user's home (with its
  placeholders), not the workspace OpenClaw would give a container.
- **Variables the user set for the sandbox** (`sandbox.docker.env`) reach the
  box as written; a registered secret's value there is masked in the
  model's view by the proxy, an unregistered one is the user's choice, as
  under Docker.
- **The terminal** (`usePty`): a command gets one through `script(1)`
  where it exists, without its window size; elsewhere it runs on pipes.
