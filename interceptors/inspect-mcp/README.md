# inspect-mcp — the cooperative U-LLM path (`inspect_symbol` MCP tool)

Mandu **M4** (`docs/design/architecture/implementation-plan.md` §7, `docs/design/architecture/mandu.md`
§6 #1). This is the **quarantined** path that lets a cooperating agent usefully
*process* untrusted data — summarize / extract / translate — **without**
de-symbolizing it into the privileged model's (paper **T-LLM**) context.

DUALVIEW routes untrusted-data processing to a quarantined model (paper
**U-LLM** / repo: *quarantined LLM*) through `inspect_symbol`, which returns a
**re-symbolized** result so untrusted text never re-enters T-LLM. For Claude
Code the cooperative path is to expose `inspect_symbol` as an **MCP tool** and
steer the agent toward it via the handling system prompt the Track A model-API
proxy injects.

## The flow

`inspect_symbol(symbol, instruction)` (core: `src/inspect-symbol.ts`):

1. **Resolve** `symbol` → raw value via arbiter `resolve`. Unknown / non-symbol → **refuse**.
2. **Quarantined U-LLM call** (`src/ullm-client.ts`): a fresh, isolated model call
   with **NO** T-LLM history, **NO** T-LLM system prompt, and **NO** tools —
   `system` = a fixed "you are a quarantined data processor" prompt, `user` =
   `instruction` + the raw value. Two transports (see **U-LLM transports** below):
   a direct Anthropic Messages API call, or a fresh `claude -p` / `codex exec`
   subprocess that reuses the user's logged-in auth.
3. **Re-symbolize** the U-LLM result via arbiter `symbolize` — the result that
   returns to T-LLM is again an **opaque symbol**.
4. **Emit** a `ullm_call` event (view `Quarantine`) via arbiter `emit`, carrying
   both representations (the desymbolized value the U-LLM saw + the symbols).

```
T-LLM ──inspect_symbol($MDU:x, "summarize")──► MCP server
                                                       │ arbiter.resolve($MDU:x) → raw
                                                       │ U-LLM.complete(quarantine sys + raw)  ← isolated, tool-less
                                                       │ arbiter.symbolize(raw U-LLM reply) → $MDU:y
                                                       │ arbiter.emit(ullm_call, view=Quarantine)
T-LLM ◄────────────── $MDU:y ───────────────────┘   (NEVER the raw reply)
```

## U-LLM transports (`MANDU_ULLM_MODE`)

The quarantined channel has **two** transports, selected by `MANDU_ULLM_MODE`
(the pure selector is `selectUllmConfig` in `src/server-main.ts`):

- **`api`** — `AnthropicUllmClient`: a **direct** Anthropic Messages API call.
  Requires `ANTHROPIC_API_KEY`. Honors `ANTHROPIC_BASE_URL`, but **refuses** a
  loopback base URL (`assertNonProxyBaseUrl`) — the U-LLM must hit the real
  endpoint, never the Mandu anthropic-proxy.
- **`cli`** — `CliUllmClient`: a fresh **`claude -p`** (or **`codex exec`**)
  subprocess that **reuses the user's logged-in Claude Code auth — no separate API
  key**. The child runs in its own session/process, a **clean temp cwd** (so it
  never loads the project `.mcp.json` that would recursively register this very
  inspect server), with **all tools disabled** (`--tools ""` for claude). It
  **forces the real endpoint**: an inherited loopback `ANTHROPIC_BASE_URL` (e.g. a
  `127.0.0.1` anthropic-proxy the parent set) is **stripped** from the child env so the
  quarantined call is never routed back through T-LLM's path. It also
  **scrubs `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN`** from the child env and
  pins **`--setting-sources project,local`** (excludes user settings), so the
  quarantined call is guaranteed to use the **logged-in subscription** — a stray
  key/token or a user-global `apiKeyHelper` cannot override it (all outrank OAuth
  in Claude Code's auth order). The `codex exec` child is cut down the same
  way (`codexQuarantineArgs`): no tool feature, a read-only sandbox, no user
  config or exec-policy rules, no session file (`--ephemeral`), the
  quarantine prompt as its model instructions (a file in the temp cwd), the
  data on stdin, Codex's built-in provider (never the openai-proxy), and
  `--skip-git-repo-check` (the temp cwd is no repository); see
  `docs/design/agents/agent-sign-in.md` §2.11.
- **`auto`** (default) — key present → `api`; else a `claude`/`codex` binary on
  `PATH` → `cli`; else **fail closed**. So Mandu **no longer hard-requires
  `ANTHROPIC_API_KEY`**: a user already logged in to Claude Code gets a working
  quarantined channel with no extra credential.

`MANDU_ULLM_BINARY` (`claude`|`codex`|`auto`) hints the cli binary; `auto` picks
codex for OpenAI/`gpt-`/`o*` model ids, else claude (the adfi prefix rule).
Provenance: the subprocess shape + CLI output parsing are lifted from
adfi-openclaw's `adfi-inspect-symbol.ts` (`invokeCLI` / `parseClaudeCliJson` /
`parseCodexCliJsonl`).

## Declared model endpoints (Plan 11, `local-model`)

A `$MDU:localmodel_*` symbol is readable only by the user's own model: an
endpoint `policy.yaml` `models:` declares `local: true`
(`docs/design/confidentiality/model-endpoints.md §1` D5).

- **Routing.** Any `localmodel_` input sends the WHOLE call (multi-input stays
  all-or-nothing) to the helper's model (the `local: true` endpoint marked
  `helper: true`, else the first declared `local: true` one; an entry url
  ending in `/v1` is dialed without it doubled) and names it on
  every resolve (`resolve(symbol, {deep: true, endpoint})`); the content-kind
  triage runs on the same endpoint. Otherwise the default U-LLM, unchanged
  (no `endpoint` on the resolve).
- **The list comes from the arbiter** (`modelEndpoints` op), never from env.
  No local endpoint declared, an arbiter without the op, or a failing op:
  refused before any resolve, with the by-design wording. Nothing ever falls
  back to the default U-LLM, which is external.
- **Clients.** `wire: openai-chat` uses `OpenAiChatUllmClient` (one
  `POST {url}/v1/chat/completions`, system + one user message, no tools;
  optional bearer from `process.env[tokenEnv]`). `wire: anthropic` uses
  `AnthropicUllmClient` at the endpoint's url (keyless unless `tokenEnv`).
  Error strings from a declared endpoint never quote its response body.
- **Loopback guard.** `assertNonProxyBaseUrl` also accepts the declared
  endpoints' origins, minus the forwarder's and any model-proxy address
  (`MANDU_MODEL_PROXY_URL`, comma-separated; the OpenClaw plugin adds the
  host's `ANTHROPIC_BASE_URL`). A declared endpoint at either address is
  refused before a byte moves.
- **Events.** Every `ullm_call` carries `endpoint: {name, location}`; the
  default U-LLM is `{name: "default", location: "external"}`.

## Security invariant (critical)

> The U-LLM result MUST be re-symbolized before returning. Raw untrusted text
> must never be returned to T-LLM un-symbolized.

This module is **fail-closed**. If arbiter `resolve` / `symbolize` / `emit` or the
U-LLM call fails — or if `symbolize` returns a non-symbol — the call is **refused**
(an error string with no raw text), never a raw result. The quarantined call
carries no T-LLM context and offers no tools, so a prompt injection inside the
data cannot reach T-LLM or call back into the agent's tools.

### Inbound classification of this tool's result (no double-wrap)

The **success** result is by construction pure-symbolic: the content text is the
re-symbolized `$MDU:*` token and `structuredContent` is
`{ result_symbol, model }`. Claude Code serializes that into the `tool_result`,
and the arbiter's inbound data-trust policy classifies it with a **hybrid rule**
(`arbiter/policy/claude-code-inbound.ts`, `classifyManduInspectResult`):
TRUSTED iff the tool name is *exactly* `mcp__mandu-inspect__inspect_symbol`
**and** the content matches the pure-symbolic success shape — so the model-API
proxy does not re-symbolize the already-opaque token into a double-wrapped
symbol. **Error results are intentionally NOT trusted**: their strings can embed
upstream error bodies (HTTP 4xx/5xx body, CLI stderr) that may echo the raw
untrusted value the transport consumed, so they stay symbolized (fail-closed).
The success shape is a **contract**: adding any new key or free-text value to
the success result re-enables the (harmless) double-wrap until that policy rule
is updated in the same change — see the SHAPE CONTRACT comment in
`src/mcp-server.ts`.

## Layout

```
src/
  inspect-symbol.ts   the lift-able core: resolve → U-LLM → re-symbolize → emit
  ullm-client.ts      the quarantined-model seam (UllmClient) + AnthropicUllmClient
                        (api mode) + CliUllmClient (cli mode: claude -p / codex exec)
                        + OpenAiChatUllmClient (declared openai-chat endpoints)
  ullm-config.ts      pure transport selection + the declared-endpoint factory
  arbiter-client.ts    narrow Arbiter interface (resolve/symbolize/emit) + adapter
  event-model.ts      local mirror of the ullm_call subset of the dashboard schema
  mcp-server.ts       hand-rolled MCP stdio JSON-RPC (initialize/tools.list/tools.call)
  server-main.ts      deployment wiring + selectUllmConfig (api/cli/auto selector)
test/
  helpers/            MockArbiter + MockUllm
  unit/               inspect-symbol + mcp-server suites
  component/          the stdio server against two mock HTTP model endpoints
```

## Configuring Claude Code to use this server

Run the server under the Mandu cgroup scope with the arbiter socket. The
quarantined channel needs **either** a logged-in `claude`/`codex` on `PATH`
(`cli` mode — no key) **or** an `ANTHROPIC_API_KEY` (`api` mode); `auto` (the
default) picks whichever is available and fails closed if neither is:

```jsonc
// .mcp.json (or `claude mcp add`)
{
  "mcpServers": {
    "mandu-inspect": {
      "command": "tsx",
      "args": ["interceptors/inspect-mcp/src/server-main.ts"],
      "env": {
        "MANDU_ARBITER_SOCK": "/run/mandu/arbiter.sock",
        "MANDU_ULLM_MODE": "auto",               // auto (default) | cli | api
        // cli mode (default when no key): reuses the user's Claude Code login —
        //   NO ANTHROPIC_API_KEY needed. api mode: set ANTHROPIC_API_KEY below.
        // "ANTHROPIC_API_KEY": "sk-ant-...",       // only for api mode
        "MANDU_ULLM_MODEL": "claude-haiku-4-5",  // optional
        "MANDU_SCOPE_ID": "mandu-<id>"         // optional, for event correlation
      }
    }
  }
}
```

Claude Code exposes the tool as `mcp__mandu-inspect__inspect_symbol`. The
Track A model-API proxy's handling system prompt should instruct T-LLM to call
it whenever it needs to understand the content behind a `$MDU:*` symbol.

> **Note:** `ANTHROPIC_BASE_URL` for this server should point at the **real**
> Anthropic endpoint, *not* the Mandu model-API MITM proxy — the U-LLM is a
> separate quarantined channel and must not be routed back through T-LLM's path.

## Provenance

`src/inspect-symbol.ts` lifts its logic from
`https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/dualview-inspect-symbol.ts`
(resolve → quarantined model → re-symbolize; `INSPECT_SYMBOL_PROMPT`; the
`_invokeLLM` test seam). Mandu changes only *where the hooks attach*: symbol
resolution + re-symbolization move to the arbiter IPC, the quarantined model
becomes an injectable `UllmClient`, and the audit becomes a `ullm_call` event.
`arbiter-client.ts` mirrors `interceptors/anthropic-proxy/src/arbiter-client.ts`.
`event-model.ts` mirrors `dashboard/src/event-model.ts` (read-only).
```
