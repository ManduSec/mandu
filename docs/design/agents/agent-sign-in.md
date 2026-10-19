# Agent sign-in through Mandu

> **Status.** §1 (Claude): findings + decision record, implemented; it
> refines [`mandu.md`](../architecture/mandu.md) §4.1 (model-API proxy) and
> the `interceptors/inspect-mcp` README (U-LLM transports). §2 (Codex):
> decision note, **option 2 BUILT 2026-09-30**: `mandu codex` runs on the
> user's own `codex login` (a ChatGPT plan, or a saved key) when no key
> variable is set, with the openai-proxy relaying the sign-in to the ChatGPT
> backend under the same masking as the API; verified live on the real
> backend (§2.10). §3 (an agent's own key file, put back at the model
> proxy): decision note, **built for Goose's `secrets.yaml`** 2026-10-07.
>
> Related: [`supported-agents.md`](./supported-agents.md) (the tested
> versions), [`portable-wrapper.md`](../distribution/portable-wrapper.md)
> §9.3 (the Codex config splice), [`continuous-integration.md §13`](../testing/continuous-integration.md).

How an agent's own login (a Claude Pro/Max subscription, a `codex login`
ChatGPT sign-in, or a saved key) reaches the model through Mandu. One rule
covers both agents: **the agent stays the client and the model proxy is a
relay.** The agent sends its own credential to the proxy, the proxy passes it
to a fixed upstream unchanged, and Mandu never stores, refreshes or originates
a request with it. A hand-rolled call that presents a lifted subscription
token is never made. One narrow exception (§3): a static key the agent reads
from a twinned file reaches the proxy as a placeholder, and the proxy puts
the real key back in the auth header to the provider the launch bound it to.

Terminology: **T-LLM** (paper) = privileged LLM (repo) = the agent's main
loop. **U-LLM** = quarantined LLM = the isolated model that *processes*
untrusted data behind `inspect_symbol`. See `mandu.md` §8.

## 1. Claude: subscription auth across the two model channels

**TL;DR.** Running Mandu on a Claude **subscription** (Pro/Max OAuth, *no* API
key) is feasible, because the two model channels use the subscription in two
*different* first-party ways. The **T-LLM** channel works because
`anthropic-proxy` is a transparent relay and *Claude Code itself* owns the
credential. The **U-LLM** channel works because it shells out to `claude -p`,
which is *also* first-party Claude Code. What is **not** feasible is a
hand-rolled HTTP call that presents the subscription OAuth token from a
non-Claude-Code client: that path is not a supported use and is against the
terms of service. Both working channels are implemented.

### 1.1 The question

Many users run Claude Code on a **Pro/Max subscription** (browser `/login` →
OAuth credential in `~/.claude/.credentials.json`), not a Console **API key**.
Mandu needs the model twice:

- **T-LLM**: the agent's own turns, routed through `anthropic-proxy`
  (`ANTHROPIC_BASE_URL` → loopback) so untrusted `tool_result` spans are
  symbolized before the privileged model sees them.
- **U-LLM**: the quarantined `inspect_symbol` call that reads the *raw*
  untrusted data and returns a re-symbolized result (`interceptors/inspect-mcp`).

Can **both** run on the subscription, with no API key? The two channels are
*not* symmetric, so they are answered separately.

### 1.2 Findings (external)

| # | Finding | Consequence for Mandu | Source |
|---|---------|-------------------------|--------|
| F1 | Claude Code **forwards the subscription OAuth bearer to whatever `ANTHROPIC_BASE_URL` is set** to. (Filed as a *security* concern: it "leaks" the credential to the custom URL.) | This is the *enabling* behavior for a transparent relay: a loopback proxy receives the bearer and can forward it unchanged upstream. | [claude-code#23022](https://github.com/anthropics/claude-code/issues/23022) |
| F2 | Pointing `ANTHROPIC_BASE_URL` at a **non-Anthropic** endpoint silently bypasses the subscription → `404 model not found` even with a valid Max sub. | The proxy must forward to the **real** `api.anthropic.com` and not rewrite the model/auth. A relay is safe; a translating gateway is not. | [claude-code#23022](https://github.com/anthropics/claude-code/issues/23022) |
| F3 | A gateway that simply **forwards the client `Authorization` header** to `api.anthropic.com` keeps the subscription working (documented LiteLLM pattern, `forward_client_headers_to_llm_api: true`). | Confirms the transparent-relay design is a known-good pattern. | [LiteLLM: Claude Code Max Subscription](https://docs.litellm.ai/docs/tutorials/claude_code_max_subscription) |
| F4 | A call **originated** outside Claude Code with a subscription credential is not a supported use (F7) and is brittle by nature: the client must reproduce request details it does not own. | **Do not hand-roll a subscription HTTP call for the U-LLM.** Use `claude -p` (first-party) or a real API key. | F7 |
| F5 | Some `400` responses on subscription requests are **deterministic**, not transient: the same request fails the same way every time. | **Never retry a 400**: the proxy's retry set is 429/529 only, and any future retrying layer in front of a subscription call excludes 4xx. The U-LLM is tool-less anyway (security), and offers no tools on any subscription call. | [hermes-agent#15080](https://github.com/NousResearch/hermes-agent/issues/15080) |
| F6 | Third-party tools that presented subscription credentials while imitating Claude Code were blocked (OpenCode, OpenClaw). | Imitating Claude Code is not a route Mandu takes. Being *actually* Claude Code (`claude -p`) is the only supported one. | [zbuild: OpenCode blocked](https://www.zbuild.io/resources/news/opencode-blocked-anthropic-2026) |
| F7 | **Policy (Feb 2026):** subscription OAuth is prohibited *outside Claude Code / Claude.ai*; third-party tools must use Console API keys. | The transparent T-LLM relay (Claude Code stays the client → real API) and the `claude -p` U-LLM (is Claude Code) are first-party. A hand-rolled subscription call is squarely in the banned zone. Recorded as an explicit assumption. | [alternativeto](https://alternativeto.net/news/2026/2/anthropic-officially-bans-using-subscription-authentication-for-third-party-claude-use) |
| F8 | A subscription request whose system prompt no longer starts with the client's own blocks fails. | The proxy relays the client's own requests only and never originates a call. It **APPENDS** its handling prompt after the caller's system blocks, never prepends, so `system[0..n]` reaches the provider byte-identical (this also preserves the prompt-cache prefix). Oracle: `test/component/subscription-auth.test.ts` (request-shape test). | this repo |

The throughline: **the subscription only works first-party.** Anything that
*is* Claude Code (the relayed main loop; a `claude -p` child) is fine. Anything
that merely *impersonates* it is unsupported and against the terms.

### 1.3 Decision: two channels, two first-party uses

| Channel | Auth | Transport | Who owns the credential / refresh | Status |
|---------|------|-----------|-----------------------------------|--------|
| **T-LLM** | Subscription **or** key | `anthropic-proxy` **verbatim relay** → `api.anthropic.com` | **Claude Code** (proxy is a passive relay) | ✅ implemented |
| **U-LLM** (default, no key) | Subscription | **`claude -p`** subprocess (`CliUllmClient`) | **`claude -p`** = first-party Claude Code | ✅ implemented |
| **U-LLM** (key present) | Console API key | direct `POST /v1/messages` with `x-api-key` (`AnthropicUllmClient`) | the configured key | ✅ implemented |

#### 1.3.1 T-LLM: transparent relay

`anthropic-proxy` (`interceptors/anthropic-proxy/src/proxy.ts`) forwards to
`https://api.anthropic.com` and relays every non-symbolized path **verbatim**, so
the subscription bearer Claude Code sends (F1) reaches the real API unchanged (F3).
Claude Code owns OAuth refresh; the proxy never touches it. Three invariants:

- **Never normalize the auth header.** Pass through exactly what Claude Code
  sends. (The one set of headers the relay drops is Mandu's own `x-mandu-*`,
  read by the proxy for session correlation and never sent to the provider;
  mandu.md §4.1.) A relay that "helpfully" rewrites the auth header would
  break the request Claude Code shaped.
- **429/529 are the expected failure mode, not auth.** The subscription tier has
  5-hour + weekly rolling caps, so sustained 429s are normal. The proxy
  absorbs 429/529 with bounded jittered backoff honoring `Retry-After`
  (`upstreamWithRetry`, `RETRYABLE_STATUS = {429, 529}`; `mandu.md` §4.1). **400
  must never be added to that set** (F5 is deterministic), and any future
  retrying layer in front of an OAuth-shaped call excludes 4xx.
- **Never displace the native system prefix.** The handling prompt is
  **appended** (`rewrite-request.ts`), keeping `system[0..n]` byte-identical
  to what Claude Code sent (F8). If requests fail through the proxy while the
  same agent works without it, suspect a change to the request's shape before
  rate limits.

#### 1.3.2 U-LLM: `claude -p`, because it *is* Claude Code

`interceptors/inspect-mcp/src/ullm-client.ts` `CliUllmClient` spawns
`claude -p --model <m> --output-format json --tools ""` in a **clean temp cwd**,
reusing the user's login, no API key. Because it is genuinely Claude Code, it
sidesteps **all** of F4 to F7: self-managed refresh, legitimate first-party
use. Its isolation:

- **Clean temp cwd** → the child never loads the project `.mcp.json`, so it cannot
  recursively register this very inspect server (`buildChildEnv` + `mkdtemp`).
- **`--tools ""`** → no tool use possible; a prompt injection in the data has no
  capability to act and never reaches T-LLM (`inspect-symbol.ts`,
  `QUARANTINE_SYSTEM_PROMPT`).
- **Loopback base URL stripped** → an inherited `127.0.0.1` `ANTHROPIC_BASE_URL`
  (the parent's proxy) is deleted from the child env, so the quarantined call hits
  the **real** endpoint and is never routed back through T-LLM's symbolizing path
  (`assertNonProxyBaseUrl` for api mode; `buildChildEnv` for cli mode).
- **No stray key bills the API.** `buildChildEnv()` also deletes
  `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN`, and `buildCliArgs` pins
  `--setting-sources project,local` so a user-global `apiKeyHelper` is
  excluded (only project/local settings load, and those are absent in the
  fresh temp cwd). Both outrank OAuth in Claude Code's auth order, so without
  this a stray key, token or `apiKeyHelper` would silently bill the **API**
  instead of the subscription. Auth is read independently of settings, so
  OAuth still works. Asserted in
  `interceptors/inspect-mcp/test/unit/cli-ullm-client.test.ts`.

#### 1.3.3 U-LLM: API-key mode is key-only by design

`AnthropicUllmClient` sends **`x-api-key`** with a real Console key and refuses a
loopback base URL. It must **never** be fed a subscription OAuth token: that path
is the unsupported one (F4, F6, F7), and api mode is exactly the
"originated HTTP call" not to hand-roll. Selector (`selectUllmConfig`):
key present → `api`; else `claude`/`codex` on `PATH` → `cli`; else **fail-closed**.

### 1.4 Known costs

- **Shared rate budget.** Every cli-mode `inspect_symbol` spends the **same**
  Max 5-hour/weekly quota as T-LLM, adding to the 429 pressure the proxy rides
  out (§1.3.1). For heavy-inspection workloads, run the U-LLM in **api mode
  with a cheap Console key** (`claude-haiku-4-5`) to isolate its budget: the
  U-LLM is the low-stakes channel, so a small metered key is a reasonable
  trade.

### 1.5 Prior art and sources

- **LiteLLM**: a gateway that forwards the OAuth `Authorization` header to the
  real API (`forward_client_headers_to_llm_api`); the closest match to the
  T-LLM relay. [tutorial](https://docs.litellm.ai/docs/tutorials/claude_code_max_subscription)
- **Meridian** (`rynfar/meridian`): bridges Claude Max into third-party tools
  by wrapping the official Claude Code SDK `query()`. The same idea as the
  `claude -p` choice: originate via *first-party* machinery, not a hand-rolled
  token. [repo](https://github.com/rynfar/meridian)
- claude-code#23022 (`ANTHROPIC_BASE_URL` overrides OAuth/subscription creds),
  hermes-agent#15080 (a deterministic 400), the zbuild report (third-party
  clients blocked) and the alternativeto report (the Feb 2026 policy):
  linked in §1.2.
- Claude Code authentication & env-vars:
  https://code.claude.com/docs/en/authentication

## 2. Codex on a ChatGPT sign-in

### 2.1 The problem

A Codex user signed in with `codex login` (a ChatGPT plan) could not use
Mandu before option 2. With no `OPENAI_API_KEY` / `CODEX_API_KEY` set,
`codex exec` replied on the ChatGPT sign-in, while `mandu codex exec` started
the whole stack and then failed inside Codex with `Missing environment
variable: OPENAI_API_KEY`, and `mandu doctor` reported the login as found.
Nothing leaked: Codex stopped before sending a request, and the launcher
refuses a user override that would re-point Codex at its built-in provider
(`codex-argv.ts`), so there was no path around the proxy.

### 2.2 Why: how Codex authenticates a provider

The launcher routes Codex by splicing a custom provider into its argv
(`env-compose.ts`):

```
-c model_provider=mandu
-c model_providers.mandu={name="mandu",base_url="http://127.0.0.1:<port>/v1",wire_api="responses",env_key="OPENAI_API_KEY"}
```

(`env_key` is `CODEX_API_KEY` when only that variable is set, `parse.ts`.)

**Source.** Codex's `ModelProviderInfo` (openai/codex, `codex-rs`) has
`env_key` ("environment variable that stores the user's API key for this
provider") and `requires_openai_auth` ("does this provider require an OpenAI
API key or ChatGPT login token?"). The built-in `openai` provider sets
`requires_openai_auth: true` and picks its base URL from the sign-in:
`https://chatgpt.com/backend-api/codex` for a ChatGPT sign-in,
`https://api.openai.com/v1` for a key; a configured `base_url` overrides
both. The 0.159.1 binary carries the same field names (`requires_openai_auth`,
`supports_websockets`, `chatgpt_base_url = "https://chatgpt.com/backend-api/"`,
the `ChatGPT-Account-Id` header).

**Probe.** A local stub on 127.0.0.1 recorded each request's method, path,
header names, and for `authorization` only the scheme, first six characters
and length (never a token, never a body value beyond `model`, `stream`,
`store`, `include`), and answered 400, so nothing reached OpenAI. `codex exec`
ran with a real ChatGPT sign-in, or with a throwaway `CODEX_HOME` holding a
dummy saved key, and a test provider pointed at the stub
(`request_max_retries=0`, `stream_max_retries=0`):

| Provider shape | Sign-in | What Codex did |
|---|---|---|
| `env_key="OPENAI_API_KEY"`, no variable | ChatGPT | `Missing environment variable: OPENAI_API_KEY`, no request |
| same, no variable | saved key (`codex login --with-api-key`) | the same error: the saved key is not used either |
| `env_key` + `requires_openai_auth=true`, no variable | ChatGPT | the same error: `env_key` wins |
| `env_key` + `requires_openai_auth=true`, variable set | ChatGPT | `POST /v1/responses`, `Bearer sk-…` (the variable), no ChatGPT headers |
| `requires_openai_auth=true`, no `env_key` | ChatGPT | `GET <base>/models?client_version=0.159.1` (three times), then `POST <base>/responses`, each with `Authorization: Bearer eyJ…` (a JWT, 1745 characters) and `chatgpt-account-id` |
| same, `OPENAI_API_KEY` set in the environment | ChatGPT | the same: a bare `OPENAI_API_KEY` is ignored, the sign-in is used |
| same | saved key | `POST <base>/responses` with `Bearer sk-…` (the saved key); no `/models` call |

The ChatGPT-mode `POST …/responses` carried `accept: text/event-stream`,
`originator: codex_exec`, `session-id`, `thread-id`, `x-client-request-id`,
`x-codex-window-id`, `x-codex-turn-metadata`, `x-codex-beta-features:
remote_compaction_v2`, `x-openai-internal-codex-responses-lite: true`, and a
body with `model`, `input`, `tool_choice`, `parallel_tool_calls`, `reasoning`,
`store: false`, `stream: true`, `include: ["reasoning.encrypted_content"]`,
`prompt_cache_key`, `text`, `client_metadata`.

**Refresh.** Codex refreshes the ChatGPT sign-in itself
(`codex-rs/login/src/auth/manager.rs`): proactively when `last_refresh` is
older than 8 days, and once on a 401 (reload from disk, then refresh, then one
retry). It posts the refresh token to `https://auth.openai.com/oauth/token`
and writes the new tokens and `last_refresh` back to `auth.json`. The access
token lives 240 hours. A 400 triggers no refresh; a 401 would.

**Conclusion.** With an `env_key` provider only a key *variable* works: a
ChatGPT sign-in and a saved key are both ignored. A provider with
`requires_openai_auth = true` and no `env_key` uses either, sending the
sign-in's own credential to our base URL.

### 2.3 Option 1: say so, and refuse what cannot run (narrowed by option 2)

Option 1 shipped first and is now narrowed by option 2 (§2.6): the refusal
answers only "no key and no sign-in", or "no key" for the user's own base
URL.

- **Launch.** `codexKeyRefusal` refuses a `mandu codex` launch of the real
  `codex` binary that would start a model session (no subcommand, a prompt,
  `exec`/`e`, `review`, `resume`, `fork`; `codex-argv.ts codexTalksToModel`)
  when it cannot run, before any service starts. One line: what is wrong,
  the fix (`codex login`, or `CODEX_API_KEY` / `OPENAI_API_KEY`; for a model
  declared under `models:`, the key that server expects), and a pointer
  here. It refuses only what Codex itself could not run. `codex login`,
  `mcp`, `--version`, `--help` and a `--target codex` wrapper are never
  refused. It never falls back to Codex's built-in provider (that would send
  the turns around the model proxy).
- **Doctor.** `agent-login.ts` reports the Codex login by existence only: the
  file is never opened.
- **Tests.** `launcher/test/unit/agent-login.test.ts` (the states, the
  refusal matrix, no value in any message), `doctor.test.ts` (the rows),
  `test/component/doctor-login.test.ts` (a fixture `auth.json` through the
  real CLI: the file's contents never printed) and
  `test/component/codex-routing.test.ts` (a stand-in `codex` under a fixture
  `CODEX_HOME`). The routing e2e pins its `CODEX_HOME` so the host's own
  sign-in never changes a result.

### 2.4 Option 2: relay the ChatGPT sign-in, first-party

The Claude answer carries over: **Codex stays the client, the proxy is a
relay.** Claude Code forwards its subscription bearer to `ANTHROPIC_BASE_URL`
and the anthropic-proxy passes it to the real API unchanged (§1.2 F1, F3);
nothing is lifted or originated. For Codex:

1. **The provider.** When no key variable is set, the launcher splices
   `model_providers.mandu={name="mandu",base_url="http://127.0.0.1:<port>/v1",wire_api="responses",requires_openai_auth=true,supports_websockets=false}`
   (no `env_key`). Codex then sends its own sign-in to the proxy: the ChatGPT
   bearer and `chatgpt-account-id`, or a saved key (§2.2). With a key variable
   the provider keeps `env_key`. A declared main model (`MANDU_OPENAI_BASE_URL`
   matching `models:`) keeps the `env_key` shape too: its server wants its
   own key, not an OpenAI sign-in. `supports_websockets=false` keeps the
   transport on HTTP SSE, which the proxy parses; the built-in provider may
   use a WebSocket.
2. **The upstream, per request, from a fixed pair.** The openai-proxy sends a
   request that carries `chatgpt-account-id` to
   `https://chatgpt.com/backend-api/codex`, and any other to
   `https://api.openai.com/v1`, with the base-URL path mapping it already has
   (`upstreamRequestPath`, `MANDU_UPSTREAM_IS_BASE_URL`): `/v1/responses` →
   `/backend-api/codex/responses`, `/v1/models` → `/backend-api/codex/models`.
   Both origins are constants in the proxy; nothing the agent sends can name
   another host. A declared main model (`MANDU_UPSTREAM_IS_BASE_URL`) disables
   the switch: its upstream is the only one, and a request carrying
   `chatgpt-account-id` there is refused (403, never sent), since its bearer
   is the user's ChatGPT session. As built (`proxy.ts` `chooseUpstream`,
   `CHATGPT_UPSTREAM_BASE`): the switch reads the headers actually
   forwarded; `MANDU_CHATGPT_UPSTREAM` replaces the ChatGPT base the way an
   ambient `MANDU_UPSTREAM` replaces the API origin (tests point either at a
   stand-in; the same loopback-only plain-HTTP rule applies); a test that
   injects one transport and no ChatGPT one sends both kinds to it, so a test
   never reaches `chatgpt.com`.
3. **Unchanged: what the proxy does to the body.** `route.ts` still decides
   what may go upstream (`responses` symbolized, a bodyless `GET /models`
   relayed, everything else refused 403); the Responses rewrite symbolizes
   tool outputs on the way up and the SSE reply is read on the way down,
   exactly as for a key. `reasoning.encrypted_content` items are opaque and
   pass as they are.
4. **Headers.** Forwarded as for a key (`sanitizeHeaders`: hop-by-hop and
   `x-mandu-*` dropped), which keeps `authorization`, `chatgpt-account-id`,
   `originator` and the `x-codex-*` headers the backend expects. The proxy
   never logs `authorization` or `chatgpt-account-id`, and never puts either in
   an event.
5. **Who owns the sign-in.** Codex, alone. The proxy holds the bearer only for
   the life of one request and never stores, refreshes or originates with it;
   no copy of `auth.json` is made anywhere; the launcher never opens it. The
   refresh (8 days, or on a 401) is Codex's own call to `auth.openai.com`,
   through the agent's egress like Claude Code's own OAuth refresh. The proxy
   never makes up a 401 (an invented 401 would trigger a needless refresh);
   upstream statuses pass through.

### 2.5 The invariant

- **To the model.** The ChatGPT backend is an outside model, the same class as
  `api.openai.com`: a secret reaches it only as `$MDU:` unless its level admits
  that model. The rewrite that enforces this is the one already in the path;
  option 2 changes the destination, not the rewrite. The e2e oracle runs on
  both upstreams (§2.7).
- **Fail-closed.** An upstream the proxy cannot vouch for is never chosen: the
  pair is fixed, a request the route does not recognize is refused, and an
  unreachable arbiter keeps the existing fail-closed behavior. If
  `chatgpt-account-id` appears on a request meant for a declared main model,
  the proxy refuses it (403) and sends nothing: that server never receives
  the sign-in, and the header cannot re-point the proxy.
- **To the network.** The proxy runs outside the agent's world, so its own
  connection to `chatgpt.com` is not the agent's egress. `chatgpt.com` does
  **not** join `MODEL_HOST_SUFFIXES` (net-proxy's model-host exclusion) or the
  net guard's admitted model hosts: Codex's other ChatGPT-backend traffic
  (`chatgpt_base_url`: cloud tasks, plans, usage) keeps going through the
  agent's egress gate, where a symbol is not turned back into the secret for
  an unbound destination. Only the model turns take the relay. Since
  2026-10-18 (the model-host deny, agent-sdks.md §4) that gate also judges
  `chatgpt.com` by path: only the account, usage and plugin calls Codex
  makes there directly pass (cloud tasks and the model turn itself are
  refused to the agent's programs), and the connect guard denies a direct
  dial of it.
- **The provider override stays refused.** A user `-c model_provider=openai`
  (the built-in provider would talk to `chatgpt.com` directly with no rewrite)
  is still refused by `codex-argv.ts`.

### 2.6 What the user sees

- A model session with neither a key variable nor an `auth.json` is refused
  ("no sign-in"); a ChatGPT sign-in or a saved key launches. With the user's
  own base URL (`MANDU_OPENAI_BASE_URL`, declared under `models:` or not) the
  provider keeps `env_key`, so there a missing key variable is still refused,
  and the sign-in is never sent.
- The doctor row reads `✓ codex login: signed in (<path>); mandu codex
  passes it through its model proxy`. Whether the sign-in is ChatGPT or a
  saved key is told apart only from the request headers at run time, so the
  doctor never opens the file.
- `docs/usage.md` and `continuous-integration.md §13` say a `codex login` works, and which
  upstream it uses; `supported-agents.md` records the Codex versions the
  ChatGPT relay was verified on.

### 2.7 Tests

- **Unit (launcher):** `test/unit/env-compose.test.ts` (the provider shape
  per case: key variable, sign-in only, the user's base URL, a declared main
  model; `requires_openai_auth=true` and `supports_websockets=false` exactly
  when intended, no `env_key` in the sign-in shape), `parse.test.ts`
  (`codexAuth`), `agent-login.test.ts` (a sign-in is `found`; the refusal
  matrix, with and without the user's own server; no value in any message),
  `doctor.test.ts` (the rows).
- **Unit (openai-proxy):** `test/unit/chatgpt-upstream.test.ts`, over real
  loopback listeners for both upstreams: the choice per header, the path
  mapping for `/responses` and `/models`, the sign-in's headers relayed as
  sent, the tool output symbolized on the ChatGPT path, fail-closed with the
  arbiter failing, a declared model refusing a sign-in (403) and sending
  nothing, an upstream 401 passed through (never made up), no bearer or
  account id in any event or log line, and the injected-transport rule.
- **E2E (launcher):** `test/component/codex-routing.test.ts` (a stand-in `codex`
  under a fixture `CODEX_HOME`: the sign-in provider at every command level,
  the file untouched and never printed; the user's own server refused;
  neither login refused with both fixes) and `doctor-login.test.ts`.
- **E2E (tests/stack, offline):** `tests/stack/codex-chatgpt-relay.test.ts`:
  a ChatGPT-shaped upstream (answers only a JWT-shaped bearer with
  `chatgpt-account-id` under `/backend-api/codex/`) and an API-shaped one
  behind the real proxy and a real arbiter; a labelled file reaches either
  only as `$MDU:`, each request lands on its own upstream, no credential in
  the session's events, and an unreachable arbiter fails closed on the
  ChatGPT path.
- **Agent-fake:** `integration.codex-chatgpt`
  (`codex-chatgpt.test.ts`): the real `codex` CLI with the
  launcher's own sign-in provider (`codexProviderToml`) and a fixture
  `CODEX_HOME` holding a synthetic reduced sign-in (unsigned JWT-shaped
  tokens, `refresh_token: ""`), the scripted Responses fake as the backend:
  every turn takes `/backend-api/codex/responses` with the sign-in's bearer
  and account id, the labelled file reaches it only as a symbol, the exfil
  carries only the symbol, and Codex never refreshes (the fixture is
  byte-identical afterwards). Codex's own backend calls outside the model
  turns (analytics, plugins, the apps MCP) carry none of the workspace: not
  the secret Codex read, not the prompt, not the workspace path, and at
  least one analytics POST arrived, so the check is not vacuous (§2.8 item
  4). Hermetic: Codex's other ChatGPT-backend calls go to the fake through
  `chatgpt_base_url`, its refresh endpoint through
  `CODEX_REFRESH_TOKEN_URL_OVERRIDE`, anything else to a dead proxy. Passes
  on codex-cli 0.144.1 (the CI pin until 2026-10-09) and 0.159.1.
- **Real-model lane:** the `codex-e2e` and `codex-mcp` suites in their
  ChatGPT form (`integration.codex-headless`, `integration.codex-headless.policy`;
  `integration.codex-e2e-chatgpt` and `codex-mcp-chatgpt` until
  2026-10-15), and the drill catalog on Codex (`drill.<area>.codex`), all on
  `MANDU_CODEX_AUTH=chatgpt`,
  `tests/lib/codex-auth.ts`: a reduced copy of the sign-in in the
  run's own `CODEX_HOME`, no key, the launcher's sign-in provider, both real
  upstreams in the proxy; offline test `tests/stack/codex-auth-lib.test.ts`).
  The credential is a dedicated CI account whose full sign-in stays outside
  the test guest; the guest gets only a reduced copy (`refresh_token: ""`,
  which 0.159.1 requires over an absent field), so nothing in the guest can
  refresh or rotate it.

### 2.8 Open questions, and what was learned

1. **Terms.** Claude's relay rests on the client staying Claude Code (§1.2
   F7). The same holds here: the client stays Codex, which sends its own
   sign-in; Mandu adds no client of its own. What OpenAI's own documentation
   says (read 2026-09-30; a record of the sources, not a legal reading; the
   question stays open):
   - **The relay.** Codex's authentication page documents this very
     configuration: a custom provider that is an LLM proxy still reaching
     OpenAI's models sets `requires_openai_auth = true` so Codex sends its
     ChatGPT sign-in to it (https://learn.chatgpt.com/docs/auth). That is
     the provider `mandu codex` writes (§2.4 item 1).
   - **Which terms apply.** With a ChatGPT sign-in, the ChatGPT Terms of Use
     (or the business agreement of an Enterprise, Education or Business
     workspace) apply to what Codex and ChatGPT exchange (same page). Those
     terms forbid extracting data or output "automatically or
     programmatically" and sharing an account's credentials
     (https://openai.com/policies/row-terms-of-use/). An OpenAI maintainer
     asked whether a modified Codex on a ChatGPT sign-in complies pointed
     only to those terms (https://github.com/openai/codex/discussions/8338).
   - **CI on a ChatGPT sign-in.** OpenAI documents it
     (https://learn.chatgpt.com/docs/auth/ci-cd-auth) while calling an API
     key "the right way to authenticate automation". Its conditions: trusted
     private runners only, never a public or open-source repository's CI;
     one `auth.json` per runner or per serialized job stream, never shared
     across concurrent jobs or machines; keep the refreshed file for the
     next run. The real-model lane (§2.7) meets them: a private runner, one
     host file refreshed under a lock, a guest copy that cannot refresh, a
     dedicated CI account. Public CI never runs it.
2. **Compaction** (answered for 0.159.1): the binary carries no
   `responses/compact` path; its remote compaction (`remote_compaction_v2`,
   `compact_remote_v2.rs`) goes through `/responses`, which the route masks.
   Live on the real backend, with a `secrets` arbiter, every upstream request
   recorded, and `model_auto_compact_token_limit=16000` so a six-command
   session (`cat .env` holding a canary, four `seq` dumps, `cat .env` again)
   compacts early: Codex compacted four times and finished. Every compaction
   was a `POST …/responses` through the proxy (`x-codex-turn-metadata`
   `request_kind: "compaction"`) with the handling prompt prepended and the
   `.env` output as a symbol. None went through `chatgpt_base_url`. The
   canary was in no request body and no response, and the model's summary
   carried the symbols forward, so the compacted history stays masked.
3. **`/models`** (answered): once `/models` answers, the ChatGPT-mode
   `POST …/responses` carries `tools`, and the model comes from the
   backend's listing.
4. **Other ChatGPT-backend traffic** (0.159.1 and 0.144.1, a synthetic
   sign-in, every backend call recorded in full at a stub): on every `codex
   exec` Codex calls, with the sign-in's bearer,
   `backend-api/ps/plugins/{list,installed,suggested/codex}`,
   `backend-api/plugins/featured`, `backend-api/wham/accounts/check`,
   `backend-api/wham/settings/user`,
   `backend-api/codex/analytics-events/events` (POST) and the apps MCP
   `backend-api/ps/mcp` (POST), plus `ab.chatgpt.com/otlp/v1/metrics`. None
   takes the relay: they are the agent's own egress, under the egress gate
   (§2.5). With a token the backend rejects, a 401 from any of them makes
   Codex try a refresh (a reduced sign-in's empty refresh token fails that
   cleanly). **What they carry:** no workspace content.
   `analytics-events/events` posts `codex_thread_initialized`,
   `codex_command_execution_event` and `codex_turn_event`: ids
   (installation, thread, turn, response), the client and OS versions, the
   model, the sandbox and approval settings, counts (tool calls, commands and
   their kinds), token counts, timings and the exit code. No prompt, no
   command text, no output, no path. The `ps/mcp` POST is the MCP
   `initialize` handshake. The GETs carry query strings only. The
   `ab.chatgpt.com` metrics were not read on the wire (TLS); the binary names
   them `codex.api_request`, `codex.tool.call`, `codex.turn.token_usage` and
   similar counters and durations. The agent-fake suite (§2.7) pins this: a
   Codex upgrade that starts shipping workspace content outside the model
   turns fails it. `-c analytics.enabled=false` stops the analytics POSTs;
   Mandu does not set it, since they carry nothing the invariant covers.
   **The model turns' own metadata.** Every `/responses` request (on a key
   too, not only a sign-in) carries an `x-codex-turn-metadata` header: the
   workspace's absolute path, its git remotes' URLs, the HEAD commit hash
   and whether the tree has changes. Codex strips a remote URL's
   credentials first (`https://oauth2:<token>@host/…` arrives as
   `https://host/…`, checked). A path, a remote and a hash are not secrets
   Mandu labels, so this is recorded, not masked.
5. **The CI credential**: a dedicated CI account (§2.7).
6. **The backend's answer has no content-type** (FIXED). `POST
   …/codex/responses` answers 200, chunked, with no `content-type`; Codex
   reads the body as SSE anyway. A stream reader keyed on the header relays
   that stream verbatim: no exec gate, no path map, no token repacker, no
   `tllm_call` (the request-side masking was unaffected: what reached the
   model was still symbolized). Found by the live `codex-e2e` run in the
   ChatGPT form. Fix: a 2xx Responses answer that is not JSON is read as the
   event stream Codex reads it as, whatever its header says (`proxy.ts`
   forwardAndStream); pinned by `test/component/exec-gate.test.ts` ("NO
   content-type"). The offline stand-in upstreams sent `text/event-stream`,
   which is why they missed it.

### 2.10 Live verification (codex-cli 0.159.1)

No key variable, a real ChatGPT sign-in, the real backend: `mandu codex exec
"Reply with exactly: hi"` replied `hi` (provider `mandu`, the model from the
backend's `/models`), and a run that `cat`s a `.env` holding a dummy password
ran the command while the model received its output as
`$MDU:nomodel_exec_command[…]` and answered with that symbol. The backend
accepted the rewritten request (the handling prompt prepended to
`instructions`, a symbolized `function_call_output`).

`codex-e2e` in the ChatGPT form (a reduced copy of the sign-in, a `secrets`
arbiter): `reasoning` and `benign-exec` pass every assertion. On this model
Codex runs a shell command inside its code-mode script cell
(`custom_tool_call` `exec` calling `tools.exec_command`,
[supported-agents.md](./supported-agents.md) §6), whose output the proxy
symbolizes like any other (`$MDU:exec_command[…]`). `stored-ipi` fails its
integrity checks, as it does on a key: it needs the frozen integrity axis,
and `secrets` does not mask untrusted text.

### 2.11 The quarantined model on Codex: `codex exec`, cut down (2026-10-04)

A Codex session's `inspect_symbol` runs its quarantined model (paper U-LLM,
repo: quarantined LLM) as a `codex exec` child of the inspect server
(`interceptors/inspect-mcp/src/ullm-client.ts` `codexQuarantineArgs`), the
Codex twin of §1.3.2's `claude -p`: it signs in from the agent's own
`CODEX_HOME` (the launcher names it in the inspect server's entry,
`services/mcp.ts`, since Codex hands a stdio MCP server a fixed environment
without it), so no key is needed. Until 2026-10-04 every call failed before
it started: `codex exec` refuses a directory that is no trusted repository
("Not inside a trusted directory and --skip-git-repo-check was not
specified"), and the child runs in a fresh temp directory. The model then
fell back to `declassify_symbol` (the live Codex runs of
`test-reorganization.md` §6.4).

`codex exec` is a whole agent, so the call is cut down to a model call:

- **No tool runs.** `--disable` of every tool feature Codex has had since
  0.136 (`shell_tool`, `unified_exec`, `apps`, `plugins`, `multi_agent`,
  `browser_use`, `computer_use`, `image_generation`, `hooks`, `goals`,
  `tool_suggest`; an unknown name is an error, so a renamed feature fails
  the call closed), `-c features.<x>=false` for the newer ones an older
  Codex does not know (`code_mode_host`, `view_image`, `sleep_tool`,
  `skill_search`), `-s read-only` and `approval_policy="never"`, no web
  search. Measured on 0.136.0, 0.144.1 (the CI pin until 2026-10-09) and 0.160.0 against a
  stand-in backend whose first answer calls every tool on a marker file (a
  code-mode cell running `exec_command`, `shell`, `exec_command`,
  `view_image`): no call read it (`test/component/codex-ullm-cli.test.ts`).
  One residue: before 0.160 `view_image` has no switch, so it stays; it
  reads only what the agent's world shows, where a labelled file is its
  symbol.
- **No context but the quarantine's.** The quarantine prompt replaces
  Codex's own instructions (`model_instructions_file`, a file in the temp
  directory), and the environment context, the apps and
  collaboration-mode instructions, project docs and bundled skills are
  off. The user message (the instruction and the data) is read from stdin
  (`-`), never argv, where any process of the user could read it.
- **No user config, no session file.** `--ignore-user-config` and
  `--ignore-rules` (the user's MCP servers, provider, hooks, exec policy);
  `--ephemeral`, so the data is never written under `CODEX_HOME`; the
  child's `TMPDIR` is the call's own temp directory, so what Codex leaves
  there (its sandbox's mount-target directory) is removed with it.
- **The vendor's own endpoint.** With no user config the provider is Codex's
  built-in one, so the child reaches OpenAI's endpoint (the ChatGPT backend
  on a sign-in) directly, never the openai-proxy: the launcher routes the
  agent's Codex there by argv overrides this child does not see, an
  inherited `OPENAI_BASE_URL` is dropped from its environment, and Codex
  hands the inspect server no `HTTPS_PROXY` (plan 10 §11.13.1).
- **Through the launcher's forwarder** (2026-10-04). With the landlock-net
  wrap on (the default) the launcher runs the U-LLM forwarder in its Codex
  form (`launcher/src/services/ullm-forwarder.ts`, `codexRelayRoute`) and
  the child's provider points at it (`-c model_provider="mandu_ullm"`,
  base `<forwarder>/v1`, `requires_openai_auth=true`, websockets off:
  `codexForwarderProvider`), so Codex sends its own sign-in to the relay,
  which forwards it verbatim and stores nothing. The relay carries a model
  call only (`POST /v1/responses`, `GET /v1/models`; anything else 403,
  nothing sent) to one of a fixed pair chosen per request as the
  openai-proxy chooses: the ChatGPT backend's Codex base when the request
  carries `chatgpt-account-id`, else `https://api.openai.com`; an `http:`
  upstream only on a literal loopback (a stand-in). It is NOT the
  openai-proxy: no arbiter, no rewrite. The inspect server's network
  confine then admits the forwarder's port and not :443, and
  `--landlock-net-strict` keeps a working Codex quarantine (live: run
  `watch-20261003T223443`, `conf-quarantine-any-model` PASS with :443 and
  :22 denied). `MANDU_ULLM_OPENAI_UPSTREAM` / `MANDU_ULLM_CHATGPT_UPSTREAM`
  point the pair at a stand-in (a replay's quarantine model, a recording
  relay). The child's other backend traffic (usage events; a token refresh)
  does not ride the relay: usage events are off (`analytics.enabled=false`)
  and the refresh is the agent's own Codex's (the two share `CODEX_HOME`).
  Without the wrap (`--no-landlock-net`) the child dials the vendor itself
  on :443. Tests: `launcher/test/unit/ullm-forwarder.test.ts`,
  `manager.test.ts`, `tests/stack/codex-ullm-forwarder.test.ts` (the real
  forwarder and the real `codex` on a synthetic ChatGPT sign-in and on a
  key).
- **The model.** Codex's own default unless `MANDU_ULLM_MODEL` names one:
  the built-in default id is a Claude model, which Codex cannot serve.
- **Errors.** A failed call reports Codex's stderr only, never its stdout:
  that stream holds the model's (untrusted) answer, and the error text
  reaches the agent's model.

Live (codex-cli 0.160.0, `gpt-5.6-luna`, a ChatGPT sign-in, `secrets`, run
`watch-20261003T215146`): `conf-quarantine-any-model` answered from the
quarantine (two `ullm_call` events, the amount and the notice period on
screen, the canary in no model request), and `conf-public-summary` passed
through it (no `declassify_symbol` this time). The live runner's recording
relay (`--capture-model`) sits in front of the Anthropic-bound quarantine
only, so a Codex quarantine call is not on record yet (recording one also
needs the recorder to read a Responses-wire quarantine call as a side
call). A replay answers it: the drill replay points the forwarder's OpenAI
pair at its quarantine endpoint (`replay-engine.ts` `quarantineEnv`), which
answers the Responses wire on both paths (`quarantineReply`), so the
quarantine drills replay on Codex too.

## 3. The agent's own key, put back at the model proxy (2026-10-07)

> **Status.** Decision note, **built for Goose's `secrets.yaml`** (the
> `anthropic` and `openai` providers) and, since 2026-10-11, **for Claude
> Code's `ANTHROPIC_API_KEY`** in the environment (§3.8) and **Codex's saved
> key** in `auth.json` (§3.9) and **Goose's Chat Completions providers and
> key variables** (§3.10). The grant survives an arbiter restart while its
> launch lives (§3.2 item 4). The other agents' key files are assessed in
> §3.6.

### 3.1 The problem

§1 and §2 keep one rule: the agent sends its own credential and the proxy
relays it. For a credential the agent reads from a file, that rule needs the
raw file in the agent's world. Under `mandu goose`, Goose's
`~/.config/goose/secrets.yaml` (its saved provider key) is such a file:
since 2026-10-06 it is the agent's own key file, registered but not twinned
([`supported-agents.md`](./supported-agents.md) §5.6.1). What protects it
then: the file is a registered secret (a tool output that carries the key
reaches the model masked), it is in `SENSITIVE_PATHS` (a tool's read of it
asks first), and the net-proxy's verbatim tripwire refuses the key in a
request to a host it is not bound to. What does not: the bytes are in the
agent's world, so a program the agent runs can hold the real key, and what
it does with it outside a mediated channel (a covert channel, a write into a
place no label reaches, a read the human approved) is beyond those checks.

Twinning the file broke the login (§5.6.1, measured): Goose sent the
placeholder as its key, and the provider answered 401.

### 3.2 Decision: twin the file, put the key back in the auth header only

The agent's world holds the twin, as for any catalog secret: Goose reads
`ANTHROPIC_API_KEY: $MDU:nomodel_Read[h].ANTHROPIC_API_KEY` and sends that
placeholder as its key. The model proxy, on the request it forwards to the
provider the launch routed, replaces the placeholder with the real key in
the authentication header and nowhere else. The agent's processes never hold
the raw key.

Nothing new decides the release. It is the egress gate's existing
bound-destination release
([`confidentiality.md`](../confidentiality/confidentiality.md) §3.2,
`egress:secret-bound-trusted`), asked by one more caller:

1. **The binding: an auth grant from the launch.** The launcher knows the
   host it routes each provider to (the context proxy's upstream). Before the
   secret setup it tells the arbiter, on the **human plane**, which field of
   which key file authenticates to which host (`registerAuthGrant {path,
   grants: [{field, host, https}]}`): for Goose, `ANTHROPIC_API_KEY` to the
   anthropic upstream's host and `OPENAI_API_KEY` to the openai route's host,
   each only when the launch routes that provider. The arbiter keeps the
   grant in memory, and the bindings law keeps that field bound to that host
   (current-bindings.ts rule 1, beside a field's own wire grant:
   confidentiality.md §2.1). Only the granted field gets the binding, never
   the file's base row or its other fields. A grant is a release, so the op is
   a `HUMAN_PLANE_OPS` member: from the data socket the agent could bind its
   key to a host of its own.
2. **The ask, per request.** For each request it forwards, the proxy reads
   exactly two headers: `x-api-key` when its whole value is one placeholder,
   and `authorization` when it is `Bearer <placeholder>`. For that symbol it
   asks what the net-proxy asks before it puts a value back on the wire
   (net-proxy `egress.ts`), both on the human plane:
   `desymbolizationDecision {symbol, boundary: "network", destination: <the
   upstream's host>, scheme, positions: ["authorization"]}` and, on allow,
   the shallow `resolve`. An auth grant is a binding Mandu makes, not the
   user, so the gate releases the key only for the `authorization` position
   (`egress:secret-wire-position`, 2026-10-09,
   [plan 10 §11.13.1](../confidentiality/confidentiality-plan-10-flow-taint.md)).
   The value replaces the placeholder in that header. The body, the URL and
   every other header are untouched: the model's context still holds only
   the symbol. A resolved value with a control character or a line break is
   not used (no header injection).
3. **Where the binding may point.** The launcher grants only a host where the
   model proxy is the only thing that releases: the two vendor API hosts
   (`api.anthropic.com`, `api.openai.com`; the net-proxy passes model hosts
   through without releasing anything, and the agent reaches them directly
   through `NO_PROXY`; under the model-host deny, since 2026-10-18 with the
   confidentiality axis on, the agent's programs reach them only through
   the net-proxy's inspected leg and only on the listed account and sign-in
   paths, where item 2's rule may put the key back in the `Authorization`
   header for its own vendor's host, never on a model path:
   agent-sdks.md §4) and a loopback address (a local model server; a
   launched net-proxy refuses this machine). A binding to any other host (a
   custom `OPENAI_HOST` on another machine, a declared remote main model)
   would also let the net-proxy's wire release put the key into any request
   the agent sends that host, its body included, where that host's model
   could read it (until 2026-10-09; since then the net-proxy puts such a
   key back in the `Authorization` header only, item 2's rule, and the
   launcher's rule stands). Such a launch gets no grant, and the file keeps
   the §5.6.1 posture (Goose's own key file, read raw). The rule is all or
   nothing per launch: every provider the launch routes must be grantable
   and the grant must be recorded, or the file is not twinned, so a launch
   never twins a key Goose then cannot use. `MANDU_AUTH_SUBSTITUTION=0`
   keeps the §5.6.1 posture too.
4. **Lifetime.** The grant lives as long as the arbiter, and across its
   restart as long as the launch that made it (2026-10-11). The launcher
   sends its pid with the grant; the arbiter keeps the grant in memory and
   writes it to `mandu.db` (table `auth_grants`, beside the symbol rows it
   binds) with that pid and the pid's start time. A restarted arbiter takes
   back the grants whose launcher is still running (the same pid with the
   same start time, the liveness test of the cache-seal launches), and its
   first bindings sync applies them, so a live session's key keeps working.
   A grant whose launcher is gone, or whose pid now belongs to another
   process, is not taken back (its row is pruned at the next write): the
   bindings sync drops the binding and the provider answers 401 until the
   next launch, the old fail-closed rule. A grant sent without a pid (an
   older launcher), or whose pid the arbiter cannot see (another pid
   namespace), stays in memory only. Within one arbiter's life grants
   accumulate (two launches routing to two hosts bind the field to both);
   each one is a vendor or loopback host.

   *Why the store cannot widen the key's exposure.* A row holds the file's
   path, the field's name, the host, the scheme flag and the launcher's pid:
   never the key. The key is where it already was, the user's file and the
   symbol row the registration persisted in the same `mandu.db`, which the
   agent can neither read nor write in `secrets` mode. The row only decides
   whether an existing binding survives the restart, toward the same vendor
   or loopback host the live launch already granted; it releases nothing the
   gate did not release before the restart. The proxy's first request on the
   connection the old arbiter dropped is refused fail-closed (502) and the
   agent's retry redials, as for any restart.

### 3.3 Failure is a 401, never a raw send

Every failure leaves the placeholder in the header, and the provider refuses
it:

| Case | What is sent | Why |
|---|---|---|
| the upstream's host is not bound (a route the launch did not grant, the grant of an ended launch after a restart) | the placeholder | the gate answers `egress:secret-unbound` and files one Inbox ask for that symbol and host (memoized); a human's *Allow* there declassifies the key for that host |
| no human plane, the arbiter unreachable, an op missing | the placeholder | `resolve` is never asked on the data socket |
| an unknown symbol, a `resolve` that answers null | the placeholder | nothing to put back |
| the placeholder anywhere else (another header, the body, the URL) | as written | the release reads two header shapes only |
| a key granted for https, a plain-http upstream | the placeholder | the wire scheme rule (`egress:secret-https-only`); only a loopback grant may be plain http |

The proxy never makes up a 401 (§2.4 item 5). Goose's own retry on 401 gets
the same answer.

### 3.4 Both wires, streaming, both proxies

- **Both wires of the anthropic-proxy.** The Messages path (`x-api-key`) and
  the OpenAI routes it serves under `/_mandu/openai/<id>` (Goose's `openai`
  provider, `Authorization: Bearer`), each against its own upstream's host.
  A bodyless relay (`GET /v1/models`) gets the same treatment.
- **Streaming.** The substitution runs once, on the request headers, before
  the send; the retry on 429/529 reuses them. The SSE answer is not touched.
- **The openai-proxy (Codex).** The same step, against the same two ops
  (§3.9, 2026-10-11): `Authorization: Bearer <placeholder>` on a request the
  proxy sends to its API origin (or a declared main model), never on a
  ChatGPT sign-in's request. `auth-substitution.ts` is copied verbatim
  between the two proxies (a unit test keeps the copies equal).
- **Logging.** The proxy logs that it put a key back (header name and host,
  once per symbol and host), never the value; no event carries a header.

### 3.5 What it removes, and what it does not

**Removed.** The raw key is no longer in the agent's world. No program the
agent starts, under any name and through any channel, can read it from that
file; a tool's read of the file, an approved one included, gets the twin.

**Not removed.**

- *A confused deputy.* Anything in the agent's world can send a request
  through the model proxy carrying the placeholder, and the proxy
  authenticates it. The key can be **used**, on the user's account, but only
  toward the bound host and only through the proxy's routes (which mask tool
  results and gate tool calls as for any turn). It cannot be **read**: the
  provider's answer does not carry it.
- *The proxy and the provider.* The proxy holds the key for one request; the
  provider receives it, as without Mandu.
- *The file's other values.* An extension's token in the same file is a
  placeholder too, as the file is under every other agent; it is released
  only where a label binds it (the wire release,
  [`confidentiality-plan-10-flow-taint.md`](../confidentiality/confidentiality-plan-10-flow-taint.md)
  §11.5). A Goose extension that needs it raw fails;
  `MANDU_AUTH_SUBSTITUTION=0` is the way back.
- *A key saved during the session.* `goose configure` inside the session
  sees the twin, not the real file: a key it writes there is discarded with
  the twin when the session ends (the launcher then names the file,
  [`confidentiality-plan-10-flow-taint.md`](../confidentiality/confidentiality-plan-10-flow-taint.md)
  §4.1), and one it saves by renaming a new file over it is refused.
- *The keyring.* Unchanged: Mandu does not reach it (§5.6.1 item 2).

### 3.6 Which agents' key files this can cover

The method needs three things: the agent reads a **static** key, sends it
**only** in an auth header to the routed provider, and never parses or
refreshes it. A token the agent refreshes itself fails the first: the
refresh would send the placeholder to the vendor's OAuth host (no grant
there, and the model proxy is not on that path), and the new tokens would be
written into the twin, raw in the agent's world, while the real file goes
stale (since 2026-10-09 the launcher names such a file when the session
ends, plan 10 §4.1, but the tokens are still lost with the twin). The proxy
would have to run the refresh and own the store, which means originating
requests with the user's sign-in (§1.3 refuses that).

| Agent | Store | Feasible? |
|---|---|---|
| Goose | `secrets.yaml`, `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | **yes, built** (both routed providers) |
| Goose | `secrets.yaml` and the environment: the Chat Completions providers' keys (`OPENROUTER_API_KEY`, `XAI_API_KEY`, `TETRATE_API_KEY`, `LITELLM_API_KEY`), and `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` as variables | **yes, built** (§3.10) |
| Goose | the system keyring | no: on Linux Mandu keeps the agent off the session bus; on macOS the Keychain stays the agent's, and Mandu never reads the key (§5.6.1) |
| Claude Code | `~/.claude/.credentials.json` (the subscription's OAuth access and refresh tokens) | **no**: Claude Code refreshes the access token itself, outside the base URL, and writes the new pair back to the file |
| Claude Code | `ANTHROPIC_API_KEY` in the environment | **yes, built** (§3.8) |
| Claude Code | `apiKeyHelper`; `ANTHROPIC_AUTH_TOKEN`; `CLAUDE_CODE_OAUTH_TOKEN` | not built: a helper's output would need its own capture; `ANTHROPIC_AUTH_TOKEN` is a gateway's bearer, sent where `ANTHROPIC_BASE_URL` points (around the proxy unless declared); `CLAUDE_CODE_OAUTH_TOKEN` is the subscription's sign-in, which §1 relays untouched |
| Codex | `~/.codex/auth.json` holding a saved key (`codex login --with-api-key`, sent as `Bearer sk-…`, §2.2) | **yes, built** (§3.9, Linux) |
| Codex | `OPENAI_API_KEY` / `CODEX_API_KEY` in the environment | **yes, built** (§3.11) |
| Codex | `auth.json` holding a ChatGPT sign-in | **no**: Codex reads the account and plan from the ID token itself, and refreshes through `auth.openai.com`, writing back to the file (§2.2) |
| OpenCode | `~/.local/share/opencode/auth.json`, `"type": "api"` entries | yes in principle (one key per provider); under `mandu opencode` the file is left raw today (`AGENT_LOGIN_FILES`; twinned under every other agent) |
| OpenCode | the same file, `"type": "oauth"` entries | **no**: refreshed by OpenCode |
| OpenClaw | its saved provider profiles | the same split (an API-key profile yes, an OAuth profile no); not measured. Its `claude-cli` and `codex-cli` profiles and its Codex harness read Claude Code's and Codex's own logins, so `mandu openclaw` leaves both raw (secret-discovery.md §1.10) |

### 3.8 Claude Code's key in the environment (2026-10-11)

Claude Code reads `ANTHROPIC_API_KEY` from its environment and sends it as
`x-api-key` to `ANTHROPIC_BASE_URL`, the model proxy. Until now the
variable was exempt from the env-var mask (plan 10 §11.4: the agent's own
login by name), so every program the agent ran could read the key. It now
takes the same route as Goose's file, through the environment:

1. **The grant.** Before the env-var mask the launcher grants, on the human
   plane, the variable to the anthropic upstream's host
   (`registerAuthGrant {env: "ANTHROPIC_API_KEY", grants: [{field:
   "ANTHROPIC_API_KEY", host, https}], pid}`, `agent-key-grant.ts`
   `registerClaudeKeyGrant`). The host rule is §3.2 item 3's: the proxy's
   upstream must be `api.anthropic.com` over https or this machine's
   loopback (a declared local main model). Not granted, and the variable
   left raw as before: another target, no `ANTHROPIC_API_KEY`, the axis
   off, `MANDU_AUTH_SUBSTITUTION=0`, `--no-env-secrets`, no proxy, an
   undeclared `ANTHROPIC_BASE_URL` (the turns skip the proxy), any other
   upstream, or a grant the arbiter did not record. The arbiter keeps an
   env grant under the origin `env:NAME` (the variable's row), with a field
   that must be the variable's own name, and persists it like a file's
   (item 4).
2. **The mask.** The env-var step sends the variable with `agentKey: true`.
   The arbiter masks an exempt agent-credential name only when it holds a
   grant for it (`EnvSecretRules.agentKeys`, exact names only); else the
   exemption stands and the agent keeps a key it can use, so a launch never
   masks a key Claude Code then cannot use. Claude Code's environment holds
   `$MDU:nomodel_Env[h].ANTHROPIC_API_KEY`; the row is bound to the granted
   host (current-bindings.ts rule 3: the law's hosts, the value's wire host,
   and now the grant's hosts, in both directions).
3. **The put-back.** Unchanged from §3.2 item 2: the anthropic-proxy finds
   `x-api-key: <placeholder>`, asks the gate on the human plane for the
   `authorization` position, and puts the key back in that header only. The
   binding is Mandu's (not in the law), so `egress:secret-wire-position`
   keeps the key out of a body, a URL or another header; the wire scheme
   rule reads the env grant too (an https grant never goes over plain HTTP).
4. **The U-LLM.** The quarantined model (inspect-mcp) in API mode took the
   same key from its server entry (`.mcp.json`, OpenCode's config,
   OpenClaw's plugin config), a file in the agent's world. Where the
   launcher's U-LLM forwarder runs (the default, with the landlock-net
   wrap: exec-routing.md §7.1), the entry now carries a random stand-in
   (`mandu-ullm-key-<hex>`, fresh per launch) and the forwarder, in the
   launcher's process, puts the launcher's own copy of the key back in
   `x-api-key` on `POST /v1/messages` only, toward its fixed upstream (https
   or a literal loopback stand-in). This holds for every target and for
   `MANDU_ULLM_API_KEY` as well. No arbiter op is involved: the launcher
   already holds the key, and the U-LLM channel stays off the instrumented
   proxy. Where no forwarder runs (`--no-landlock-net`, a kernel without
   the wrap, macOS, a forwarder that failed to start) the entry carries the
   key raw, as before: the U-LLM dials the endpoint itself.
5. **The subscription.** A Claude Code signed in with its subscription and
   no `ANTHROPIC_API_KEY` is not touched (no grant, nothing masked). With
   both, Claude Code uses the variable, as without Mandu, and the variable
   now holds the placeholder.

**Why it cannot widen the key's exposure.** The key goes where it went
before, to the anthropic upstream in `x-api-key`, now from the proxy
instead of from the agent; the gate releases it nowhere else (no other
host, no other position, no plain HTTP). The env row's value is in
`mandu.db`, where the arbiter keeps every masked variable's value, which
the agent can neither read nor write in `secrets` mode. The grant row
holds no value (item 4 of §3.2). The U-LLM stand-in is random, not derived
from the key. What the agent's world held raw before (the variable, the
U-LLM's server entry) now holds placeholders, so the key can be **used**
through the proxy (and through the forwarder, on its model call) but not
**read**: the confused deputy of §3.5, toward the same hosts.

**The API-key dialog.** Claude Code's interactive start asks whether to use
a custom API key it has not seen ("Detected a custom API key in your
environment", default *No*), keyed by the key's last 20 characters in
`.claude.json` (`customApiKeyResponses`). The placeholder's differ from the
key's, so every interactive launch asked again (measured: the replay drills'
turns all waited on it). The launcher carries the human's answer over
(`claude-trust.ts` `inheritApiKeyApproval`, in `$CLAUDE_CONFIG_DIR` or the
home): when the key's suffix is approved, or rejected, the placeholder's is
added to the same list; a key never answered is left alone, so the dialog
appears as it would for the key. It reads only suffixes Claude Code already
wrote and writes only the placeholder's. `claude -p` never asks.

**What remains.** Nothing of the U-LLM's key: `MANDU_ULLM_API_KEY` is kept
out of the agent's environment since 2026-10-11 (§3.11).

### 3.9 Codex's saved key (2026-10-11)

`codex login --with-api-key` saves the key in `$CODEX_HOME/auth.json`
(`{"OPENAI_API_KEY": "sk-…", "tokens": null, …}`), and Codex sends it as
`Authorization: Bearer` to the provider Mandu splices in when no key
variable is set (the sign-in provider, §2.2). Under `mandu codex` the file
was left raw (the walk keeps the launched agent's login out,
secret-discovery.md §1.10). Now, on Linux:

1. **The grant.** The launcher reads the file (in the human's world) and,
   when it holds a saved key and no ChatGPT tokens, grants `OPENAI_API_KEY`
   of that path to the openai-proxy's API origin (`registerCodexKeyGrant`):
   `api.openai.com` over https or this machine's loopback, by §3.2 item 3's
   rule. Not granted (the file stays raw, as before): another target or a
   program not named `codex`, macOS (a confined file is read-blocked there,
   not twinned, and Codex could not read its login), the axis off,
   `MANDU_AUTH_SUBSTITUTION=0`, no proxy, a key variable (Codex then sends
   the variable, not the file), the user's own `MANDU_OPENAI_BASE_URL`, any
   other upstream, a ChatGPT sign-in (refreshed by Codex itself, §3.6), or
   the AI helper's `codex exec` with no U-LLM forwarder (item 4).
2. **The twin.** The secret setup registers and twins the file although the
   walk left it out (`grantedLoginFiles`): Codex reads
   `"OPENAI_API_KEY": "$MDU:nomodel_Read[h].OPENAI_API_KEY"` and sends that
   placeholder. The human's file is never written.
3. **The put-back.** The openai-proxy's step (§3.4) on the request to the
   API origin, on the human plane, for the `authorization` position. A
   request carrying `chatgpt-account-id` (a ChatGPT sign-in, sent to the
   ChatGPT base) is never asked about.
4. **The AI helper.** The quarantined `codex exec` (§2.11) reads the same
   twinned file. Its U-LLM forwarder (Codex form) learns the placeholder
   after the twins (`setApiKey`) and replaces a `Bearer <placeholder>` with
   the launcher's own copy of the key on a request it relays to the API
   origin, never toward the ChatGPT base. Where no forwarder runs, the
   launch grants nothing, so the helper keeps a key it can use.

The saved-file twin component tests disable the kernel guard and therefore
require bubblewrap with working unprivileged user namespaces for the twin
bind. They skip explicitly when that capability is absent (including GitHub's
restricted runners); the environment-key, opt-out and ChatGPT cases still run.
This is a test prerequisite, not a change to runtime fallback or protection.

The launch says it: `mandu: <auth.json> is a placeholder in Codex's world;
the model proxy puts its key back in the auth header to <host> only`.

**Why it cannot widen the key's exposure.** As §3.8's: the key goes where
Codex sent it, the API origin, now from the proxy (and the forwarder)
instead of from Codex, and only in the auth header; the grant row holds no
value; the symbol row was already in `mandu.db` for every other agent's
launch (the file is a catalog secret twinned under every agent but Codex).
What Codex's world held raw now holds the placeholder.

**What remains.** A `codex login` run inside the session writes into the
twin, which ends with the session (plan 10 §4.1 names the file then). This
session's net-proxy still treats the file as Codex's raw login
(`sessionLogins`): its verbatim tripwire does not fire on the key, which
the agent's world no longer holds.

### 3.10 Goose's Chat Completions providers and key variables (2026-10-11)

Goose routes five more providers through the anthropic-proxy's OpenAI
routes (`/_mandu/openai/<id>`, supported-agents.md §5.6.4): `litellm`,
`openrouter`, `ollama`, `xai` and `tetrate`. The proxy side was already
generic (each route's own upstream is the destination, §3.4); the launch
side now grants them:

1. **The file.** `gooseKeyGrantPlan` grants each routed provider's key
   field of `secrets.yaml` to its upstream's host when that is the
   provider's own API host over https (`openrouter.ai`, `api.x.ai`,
   `api.router.tetrate.ai`) or this machine's loopback. LiteLLM is a proxy
   server the user runs, with no vendor host: loopback only. Ollama takes no
   key and asks for nothing (a launch routing only Ollama grants nothing).
   The all-or-nothing rule of §3.2 item 3 stands: one ungrantable routed
   provider, and the file keeps the agent's-own-key-file posture. Linux
   only, for every provider (2026-10-11): macOS read-blocks a confined file
   (the Seatbelt profile has no twin), so a granted `secrets.yaml` would be
   unreadable to Goose itself; there the file keeps the §5.6.1 posture.
2. **The variables.** Goose reads a provider's key from its variable before
   its file. `gooseEnvKeyGrantPlans` grants each routed provider's key
   variable that is set (the five's, and `ANTHROPIC_API_KEY` /
   `OPENAI_API_KEY`) through the environment form of §3.8, one variable at
   a time: a provider whose host is not grantable leaves its own variable
   raw, as before. A granted variable is sent to the env-var mask (an
   exempt name with `agentKey`, the five's by their `_API_KEY` shape),
   masked, and bound to its grant's host.

The launch says which: `mandu: <NAME> is a placeholder in Goose's
environment; the model proxy puts the key back in the auth header to <host>
only`, beside the file's line.

**Why it cannot widen the key's exposure.** The same as §3.8: each key
goes only to its own provider's host, only in the auth header, from the
proxy; a vendor host is granted only over https, and a remote LiteLLM is
never granted, since a binding there would let the net-proxy's wire release
send the key to a host the user chose by name only (§3.2 item 3).

### 3.11 Codex's key variables, and Mandu's own helper key (2026-10-11)

**Codex on a key variable.** With `OPENAI_API_KEY` or `CODEX_API_KEY` set,
Mandu's provider names the variable as `env_key` (§2.2) and Codex sends it
as `Bearer` to the openai-proxy. Both names were exempt from the env-var
mask (plan 10 §11.4). Now `codexEnvKeyGrantPlans` grants each of them that
is set to the openai-proxy's API origin (`api.openai.com` over https, or
loopback: §3.2 item 3's rule), the env-var step sends it with `agentKey`,
and the arbiter masks it; the openai-proxy's step (§3.4, §3.9 item 3) puts
the key back as `Bearer` toward that origin, never on a ChatGPT sign-in's
request. Not granted, and left raw as before: a sign-in launch
(`codexAuth: "sign-in"`, §3.9), a program not named `codex`, the axis off,
`MANDU_AUTH_SUBSTITUTION=0`, `--no-env-secrets`, no proxy, the user's own
`MANDU_OPENAI_BASE_URL`, any other upstream, or a grant not recorded. Any
platform: a variable needs no twin. The AI helper's `codex exec` (§2.11)
does not use these variables (its provider has no `env_key`, and Codex
hands a stdio MCP server a fixed environment without them), so the
forwarder's Codex form needs nothing new for them.

**`MANDU_ULLM_API_KEY`.** The AI helper's own key is read by the launcher
(`parse.ts`), which hands the helper what it needs through the helper's
own entry: the forwarder's stand-in, or the key where no forwarder runs
(`.mcp.json`, OpenCode's config, OpenClaw's plugin config, whose
`ullmApiKey` wins over the variable). Nothing in the agent's process tree
reads the variable, but as `MANDU_*` routing the mask exempted it, so it
reached the agent raw. The launcher now drops it from the agent's
environment (`LAUNCHER_ONLY_ENV`, `withoutLauncherOnlyEnv`, beside the
human-plane socket), on the direct and the systemd paths alike. The
proxies and the forwarder are the launcher's own children and keep it. A
`mandu` launched from inside the session no longer inherits it: that
nested launch's helper uses `ANTHROPIC_API_KEY` or the CLI, as for any
launch without the variable.

### 3.12 Model services a program calls itself (2026-10-18)

Some agents call a model service that no Mandu model proxy fronts, from
their own process: jev-ultrafast posts every step to TypeSafe's decision
model (`https://api.typesafe.ai/v1/systemone`, a proprietary wire, URL
hardcoded) and its optional text helper to an OpenAI-compatible endpoint
(OpenRouter in its example), each with `Authorization: Bearer <key>`
([devtools-relay.md §6.3](devtools-relay.md)). Their keys,
`TYPESAFE_API_KEY` and `OPENROUTER_API_KEY`, were masked by name
(`*_API_KEY`, plan 10 §11.4) and bound nowhere, so every request asked for
approval.

Now the launcher grants each one set in the launch environment to its
provider's own API host (`PROVIDER_KEY_HOSTS` in
`launcher/src/agent-key-grant.ts`: `api.typesafe.ai`, `openrouter.ai`),
on the human plane, before the env-var step (`registerProviderKeyGrants`,
in every launch). It is not an agent key: the variable is masked as before,
without `agentKey`, and the grant only binds its row (rule 3). The release
is then the egress proxy's ordinary one, under the two wire rules a
grant-bound credential keeps (plan 10 §11.13.1): over https only, and only
in the request's Authorization header. Anywhere else, the other provider's
host included, it asks. Not granted: the axis off,
`MANDU_AUTH_SUBSTITUTION=0`, `--no-env-secrets`, and under `mandu goose` a
provider Goose routes (that variable is Goose's own key, §3.10). A grant
not recorded (no human plane, an error) leaves the key masked and unbound,
with one warning line.

**The placeholders in the request (2026-10-18, found by the first live jev
run).** What jev sends TypeSafe is the page text it read through the
DevTools relay, so it carries the placeholders of the page's secrets. The
egress gate treated each as a secret leaving for a host it is not bound to
(`egress:secret-unbound`) and refused the request: every step of a page that
showed a known secret was blocked, though nothing secret was in it. An
opaque placeholder is exactly what a model is meant to read; the model
proxies send one to Claude or Codex every turn. So the egress proxy is now
started with the providers' hosts as **model services**
(`MANDU_NET_PROXY_MODEL_SERVICES`, set by the launcher from
`PROVIDER_KEY_HOSTS`, always, so an ambient value cannot widen it; net-proxy
`egress.ts` `GateInput.modelService`, both legs). In a request to one, a
placeholder anywhere but the Authorization header leaves as it is: never
asked about (so no approval card per step), never resolved, never withheld;
the forwarded event lists it as `keptOpaque`. Unchanged: the
Authorization header's placeholder is decided as before (the key put back
under the wire rules, and refused when it also sits elsewhere in the
request); the tripwire still refuses a raw registered value; any other host
still refuses the placeholder. `MANDU_MODEL_HOSTS` is not the same thing: a
host there is passed through unread, with no key put back and no tripwire.

The secrets file names both (`typesafe_api_key`, `openrouter_api_key`,
`scripts/secrets-to-env.mjs`), so a key kept there never passes through
the person's shell. A copy of the placeholder under another variable name
(jev reads the helper's key from `TEXT_MODEL_API_KEY`) is released the same
way: the egress proxy judges the placeholder, not the variable.

Tests: `launcher/test/unit/browser-cdp.test.ts` (the plans and their
switches, the registration and its warnings, never the value),
`scripts/test/secrets-to-env.test.mjs` (the two names),
`tests/stack/provider-key-grant.test.ts` (a real arbiter: each key released
at its own host in the auth header over https only, refused at the other
provider's, in a body and over plain HTTP; without the human plane, masked
and asking), net-proxy `test/unit/egress.test.ts` (the model-service gate:
only the header's placeholder asked about, the rest kept as written; the
host match) and `tests/stack/model-service-egress.test.ts` (the launcher's
grants, a real arbiter and a real NetProxy on its TLS-inspected leg: a page
secret's placeholder reaches the service as written beside the put-back
key; a raw value, the key outside the header, another host and a proxy
without the list are refused, and nothing reaches the host).

**Live** (2026-10-18, jev-ultrafast `main`, Browser Harness 0.1.13,
headless Chromium 153): `mandu --browser-cdp` on a local "project settings"
page that shows a `.env`'s Stripe key, task "rename the project to
mandu-demo and save". Before the model-service rule: TypeSafe's first
request refused (`egress:secret-unbound`). After: done in 3.7 s, three
TypeSafe decisions and one OpenRouter call, each `200`, each with its key
put back and the page key sent as its placeholder; the page text jev read
held `$MDU:nomodel_Read[…].STRIPE_SECRET_KEY` where the page showed the key.

**The handling note (2026-10-19).** Under a DevTools relay a Chat
Completions call to a model service also gets Mandu's handling note as its
first system message, after the gate and the tripwire passed it
([devtools-relay.md §6.5](devtools-relay.md)), so a browser agent's model
knows what the placeholders in its pages are.

### 3.7 Tests

`arbiter/test/unit/auth-grant.test.ts` (the grant kept by the bindings law in
both directions, on the granted field alone, dropped with the arbiter's
memory, the scheme rule; the persisted grant taken back after a restart
while its launcher lives, never for a gone launcher or a reused pid, never
without a pid, the row holding no value, the gone rows pruned), `interceptors/anthropic-proxy/test/unit/auth-substitution.test.ts`
(the two header shapes, every other place untouched, every failure keeping
the placeholder, a value with a line break refused),
`launcher/test/unit/agent-key-grant.test.ts` (which launches are granted,
and to which host), `launcher/test/component/goose-auth-substitution.test.ts`
(the REAL goose through `main()`: the scripted upstream receives the real
key in `x-api-key` while a shell in the agent's world reads only the
placeholder from the file, and no model request carries the key) and
`tests/stack/auth-substitution.test.ts` (a real ArbiterServer and the
production adapter, `secrets` mode: the key leaves only in the auth header to
the granted host, on both wires; an ungranted host, a grant sent on the data
socket and a gone arbiter each send the placeholder; no request body carries
the key; an arbiter restarted under the live launch puts the key back again,
and an ended launch's grant is not taken back; Claude Code's variable masked
only with the env grant, put back only in an auth header to the granted
host, across a restart too). For §3.8 also: `auth-grant.test.ts` (the
`agentKeys` rule, the env row bound by rule 3 in both directions, the
scheme and the auth-header position, the env grant persisted),
`launcher/test/unit/agent-key-grant.test.ts` (`claudeKeyGrantPlan` and
`registerClaudeKeyGrant`), `secret-setup.test.ts` (`agentKey` sent for a
granted variable only), `ullm-forwarder.test.ts` (`restoreUllmKey`: the
stand-in on the model call only; the relay end to end), `manager.test.ts`
(the stand-in in the inspect entry only once the relay is live),
`claude-trust.test.ts` (the API-key dialog's answer carried over, or left
alone), and
`launcher/test/component/claude-env-key.test.ts` (the real launcher, arbiter
and proxy: the agent's environment and its MCP config hold placeholders,
the scripted upstream receives the real key from the proxy and from the
forwarder, no request body carries it, the opt-out keeps the raw variable;
and the REAL `claude -p`, self-skipped without the binary, authenticating
with the placeholder it holds). For §3.9: `interceptors/openai-proxy/test/unit/auth-substitution.test.ts`
(the copy kept equal, the Bearer put back toward the API origin only, a
ChatGPT sign-in's request never asked about, the adapter on the human
plane), `agent-key-grant.test.ts` (`codexKeyGrantPlan`, `codexSavedKey`,
`codexTwinPlaceholder`, `registerCodexKeyGrant`), `secret-setup.test.ts`
(`grantedLoginFiles` twinned), `ullm-forwarder.test.ts`
(`restoreCodexBearer`, `setApiKey` toward the API origin only),
`tests/stack/auth-substitution.test.ts` and `proxy-real-client-parity.test.ts`
(the openai-proxy's production wiring over a real arbiter), and
`launcher/test/component/codex-saved-key.test.ts` (the real launcher: a
stand-in `codex` reads the twin and the upstream receives the real key; the
opt-out; a ChatGPT sign-in left alone; the REAL `codex exec`, self-skipped
without the binary, authenticating with the placeholder it reads). For
§3.10: `agent-key-grant.test.ts` (each compat provider's host, Ollama,
LiteLLM loopback only, the per-variable env grants), `secret-setup.test.ts`
(a granted routed variable sent, an ungranted one kept out),
`auth-grant.test.ts` (a shape-masked variable bound to its grant's host),
and `launcher/test/component/goose-auth-substitution.test.ts` (the REAL
goose: OpenRouter's key from `secrets.yaml` and from its variable put back
as `Bearer`; `ANTHROPIC_API_KEY` and `OPENROUTER_API_KEY` placeholders in
Goose's environment, read by a shell). For §3.11: `agent-key-grant.test.ts`
(`codexEnvKeyGrantPlans`, `registerCodexEnvKeyGrants`,
`withoutLauncherOnlyEnv`), `auth-grant.test.ts` (the two names masked only
with a grant; `MANDU_ULLM_API_KEY` never an agent key),
`codex-saved-key.test.ts` (a stand-in `codex` and the REAL `codex exec` on
`OPENAI_API_KEY`: placeholders in the environment, the real key at the
upstream) and `claude-env-key.test.ts` (`MANDU_ULLM_API_KEY` absent from the
agent's environment and its MCP config, put back by the forwarder on the
helper's call).
