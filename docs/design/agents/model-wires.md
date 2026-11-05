# Model wires: one gate core, a thin adapter per wire

**Status (2026-10-26):** built. The core/adapter split (§2) is the
anthropic-proxy's relay loop over `src/wire-adapter.ts` (the adapters) and
`src/wire-shadow.ts` (the shared shadow builder); the Google Gemini wire (§4)
is `src/gemini-wire.ts` and `src/gemini-sse.ts`; Ollama's native chat API
(§8, 2026-10-26) is `src/ollama-wire.ts` and `src/ollama-ndjson.ts`, routed
for OpenClaw in the launcher and in Route 1, the real OpenClaw on every lane
version against a scripted Ollama; the routing (§5) is in the
launcher for OpenClaw, OpenCode and Goose, and in `mandu serve`'s OpenClaw
plugin route (Route 1). The real goose 1.53.0, OpenCode 1.18.13 and an
OpenClaw 2026.9.9 Gateway with the plugin run through it against a scripted
Gemini upstream (§6). Vertex AI's Gemini models (OpenClaw's `google-vertex`)
ride the same adapter at the proxy's root (§4.1, 2026-10-26), routed by the
wrapper on OpenClaw 2026.7.1 and later and refused by Route 1. OpenClaw's
`azure-openai-responses` and `openai-chatgpt-responses` apis ride the
existing Responses adapter, each with its own path, query and key header
(§9, 2026-10-26). AWS Bedrock is not supported (§7). The bypass oracle
(§11, 2026-10-26) records where a real OpenClaw's model calls go, in a
network namespace whose only way out is the proxy, for every routed wire by
both routes on every lane version. Mode `secrets`; nothing here adds
integrity behaviour.

## 1. Why

A model API is a *wire*: the shape of one request and its answer. Mandu's model
proxies read these today:

| Wire | Read by | How |
|---|---|---|
| Anthropic Messages | `interceptors/anthropic-proxy` | natively (`rewrite-request.ts`, `sse-rewrite.ts`) |
| OpenAI Chat Completions, Responses API (and OpenClaw's Azure OpenAI and ChatGPT sign-in apis, §9) | `interceptors/anthropic-proxy` (OpenClaw, OpenCode, Goose) | as a Messages *shadow* (`openai-wire.ts`, `openai-sse.ts`) |
| Google Gemini | `interceptors/anthropic-proxy` (OpenClaw, OpenCode, Goose) | as a Messages shadow (`gemini-wire.ts`, `gemini-sse.ts`; §4) |
| Ollama's native chat API (`/api/chat`, NDJSON) | `interceptors/anthropic-proxy` (OpenClaw) | as a Messages shadow (`ollama-wire.ts`, `ollama-ndjson.ts`; §8) |
| OpenAI Responses API, Chat Completions | `interceptors/openai-proxy` (Codex, Kimi) | natively, Chat as a Responses shadow (`chat-wire.ts`, `chat-sse.ts`) |

Every new wire is a new way for a tool's output to reach the model, so every
new wire is a place the invariant can break. Copying a proxy's gates for each
wire would put the same security decision in several files that drift apart.
The maintainer's direction (2026-10-25) is the sustainable one: the gates are
written once, and a wire is a thin adapter onto them.

## 2. The split

**The core** is everything that decides, written once, protocol-neutral by
construction because it runs on one canonical request shape (the Messages
request, `messages-types.ts`):

- the request rewrite (`rewriteRequest`): the classify and symbolize calls to
  the arbiter, the secret taint of a call's process tree, the value backstop,
  the prompt filter (its protocol-neutral half is `prompt-filter-core.ts`), the
  handling prompt, the trusted-context haystack, the fail-closed refusals
  (`RewriteRefusal`, 502 and nothing sent);
- the tool-call gate (`toolInputTransform`): the per-session gate surface, the
  dispatcher unwrap, the refused-tool tables, the exec / stdin / net / path /
  derived-label gates, the forward view map;
- the view map's reverse pass and the net-gate history over the shadow;
- the relay loop: the upstream call with the agent's own key put back
  (`auth-substitution.ts`), the chained rewriter, the rule that a rewriter fault
  ends the relay (nothing ungated goes out after it), the observability events;
- the text-delta token repacker's grammar and its hold-and-move algorithm
  (`text-repack.ts`, the abstract `TextRepacker`);
- the `MEDIA:` reply gate (`reply-media-stream.ts`, the generic
  `ReplyMediaFilter`).

**An adapter** is what reads one wire, and only that. Its contract
(`wire-adapter.ts`):

| Part | What it does |
|---|---|
| route | which paths under the provider prefix are this wire (`classify…Route` in `route.ts`) |
| `requestRefusal(body)` | a request that must not go at all: a tool the provider runs, a provider-side fetch, cached content; 400, nothing sent |
| `shadow(body)` → `{shadow, apply}` | the Messages request the core reads (every tool result a `tool_result`, every call a `tool_use`, the system text, the user text), and `apply(gated)` that writes what the core changed back onto a clone of the agent's own body by position. Every byte the adapter does not read goes upstream as sent. A shape it cannot vouch for is an error (400, nothing sent) |
| `gateJson` / `streamRewriter` | the answer: every tool call through the core's gate before the agent sees it, buffered or streamed; a frame it cannot read ends the stream (fail-closed) |
| `textRepacker()` | which events carry a run of reply text, so the core's repacker can move a split `$MDU:` token forward whole |
| `replyWire` / `gateJsonReply` | the same reading for the `MEDIA:` reply gate |
| `responseIdWire` | where the answer's id is, for `mandu scan`'s join (null: the wire's answers carry none, Ollama's) |
| `toolNames(body)` (optional) | the tool names the request declares, as sent, when the answer gate reads a call's name the way the agent maps it (Ollama, §8.3) |
| `errorBody(status, message)` | the error shape this wire's clients print |

The shadow is the proven pattern: `openai-wire.ts` has read the two OpenAI
wires this way since 2026-09-28 (agent-e2e-harness.md §9, "Other providers
through the model proxy"), and the openai-proxy reads Chat Completions onto
its Responses core the same way (`chat-wire.ts`). What this note adds is the
named contract and one relay loop over it, so the third wire is an adapter and
not a third copy of `onOpenAiRequest` / `forwardOpenAi`.

**The openai-proxy** keeps its own Responses-shaped core for now: its gates are
Codex's (`exec_command`, the JS script cell) and its rewrite reads the
Responses request natively. Folding it onto the same core (its Responses wire
as one more adapter, its Codex gate surface as one more surface table) is the
later step of making Mandu pluggable; the copy table
(`scripts/copies/module-copies.mjs`) keeps what both already share identical
until then (`text-repack.ts`, `response-id.ts`, `prompt-filter-core.ts`,
`auth-substitution.ts`, …).

## 3. Where the Gemini adapter lives

**Decision: a wire inside the anthropic-proxy**, served under its own provider
prefix `/_mandu/google/<provider id>`, beside `/_mandu/openai/<provider id>`.

- The agents that speak Gemini through a configurable endpoint are OpenClaw
  (its `google-generative-ai` api), OpenCode (`@ai-sdk/google`) and Goose (its
  `google` provider). All three already route to the anthropic-proxy, and every
  gate for their tools lives there. Reading Gemini there means the gate a table
  adds for OpenClaw is enforced on four wires by construction.
- One service: the launcher already starts that proxy for these sessions, and
  `mandu serve`'s pool already starts one per attachment session with its port
  in `anthropic-proxy.port`. No new package, port file, identity probe or
  lifeline.
- No new copies. The only shared modules touched are ones already in the copy
  table (`text-repack.ts` gains the Gemini run reader, `response-id.ts` the
  Gemini id, `auth-substitution.ts` the `x-goog-api-key` header).

Rejected: **a wire in the openai-proxy** (its gates are Codex's; Codex does not
speak Gemini, and OpenClaw's tables would have to be copied there); **the core
extracted as a copy-table group used by a small gemini package** (the core is
the request rewrite and the gates, well over ten thousand lines tied to the
agents' gate surfaces: a byte copy of it is the duplication this note exists to
avoid, and a third service is one more thing for the launcher and the pool to
start, identify and reap).

## 4. The Gemini wire

Read from the published clients (unpacked, read only): `@openclaw/ai`
2026.10.7 (`google-messages`, `google-shared`, `google-provider-stream`, over
`@google/genai`), `@ai-sdk/google` 2.0.106 (the `ai-v5` line OpenCode 1.18
bundles), and Goose's `google` provider and format (goose-providers
`google.rs`, goose-provider-types `formats/google.rs`). All three send the key
in `x-goog-api-key`, stream with `:streamGenerateContent?alt=sse`, and read
the answer as SSE.

### 4.1 Routes

Under `/_mandu/google/<id>`, with an optional API version (`/v1beta`, `/v1`,
`/v1alpha`) before the operation (Goose joins `v1beta/models/…` to its host;
OpenClaw and the AI SDK put `/v1beta` in the base URL):

| Request | Route |
|---|---|
| `POST …/models/{model}:generateContent` | gated, buffered answer |
| `POST …/models/{model}:streamGenerateContent` | gated; `alt=sse` streams SSE, without it the JSON-array stream is read whole and gated |
| the same under Vertex AI's `…/projects/{p}/locations/{l}/publishers/google/models/{model}` | gated the same way (the OAuth bearer passes as sent) |
| a bodyless `GET` / `HEAD` (`/models` listing) | relayed |
| anything else (`:countTokens`, `:embedContent`, `:batchGenerateContent`, `cachedContents`, `files`, `/interactions`, a provider not routed) | 403, never sent |

`:countTokens` carries the whole conversation; none of the three clients calls
it on the agent path, so it is refused rather than masked.

**Vertex AI at the root** (2026-10-26, route.ts `classifyVertexRoute`).
OpenClaw's `google-vertex` api is the Gemini wire on Vertex resource paths,
but its transport keeps only the ORIGIN of the provider's `baseUrl` (its
`resolveGoogleVertexBaseOrigin` sets `url.pathname = ""`; a `baseUrl` with
`{location}` in it is replaced by Google's own host), so the request arrives
at the proxy's root with no provider id:

| Request | Route |
|---|---|
| `POST /v1/projects/{p}/locations/{l}/publishers/google/models/{m}:streamGenerateContent` (`/v1beta1` too) | gated by the Gemini adapter; `alt=sse` streams |
| the same with `:generateContent` | gated, buffered answer |
| a bodyless `GET` / `HEAD` under `/v1/projects/{p}/locations/{l}` | relayed |
| another publisher (Anthropic's Claude on Vertex is `publishers/anthropic/…:rawPredict`, OpenClaw's separate `anthropic-vertex` provider, not routed), another operation, a location that is not a region name (`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`), a session that routes no Vertex provider | 403, never sent |

A session routes at most one Vertex provider (`MANDU_VERTEX_UPSTREAMS`, one
entry: provider id → its own address, of which the origin is kept, or null).
The request goes to that address, or, with null, to Google's own Vertex host
for the path's location, picked as OpenClaw picks it (`vertexOrigin`:
`global` → `aiplatform.googleapis.com`, `us` / `eu` →
`aiplatform.<l>.rep.googleapis.com`, a region → `<l>-aiplatform.googleapis.com`):
only a plain region name reaches a host name, so the path cannot steer the
proxy anywhere else.

What each OpenClaw does with a `google-vertex` model (read from the
published dists, 2026-10-26; measured on the real binaries where noted, §6):

| OpenClaw | Vertex calls go to | Mandu |
|---|---|---|
| 2026.3.12 | Google's regional host, whatever the `baseUrl`: pi-ai's google-vertex provider builds `new GoogleGenAI({vertexai: true, project, location})` with no base URL (pi-ai 0.57.1) | refused (the wrapper names the release; Route 1 always) |
| 2026.3.13 to 2026.4.27 | not read: no Vertex transport of OpenClaw's own yet (the library's) | refused by the wrapper |
| 2026.4.29 to 2026.6.x | the origin of the `baseUrl` (the google plugin's own Vertex transport, read only) | refused by the wrapper (not measured) |
| 2026.7.1-2, 2026.9.9, 2026.10.7 | the origin of the `baseUrl` (measured: `openclaw-vertex-real.test.ts`) | routed by the wrapper |

The model calls only: OpenClaw's own token fetch (ADC: an `authorized_user`
refresh to `oauth2.googleapis.com/token`, or google-auth-library for a
service account or the metadata server) is a sign-in that carries no model
context, and stays direct.

### 4.2 The request as a shadow

| Gemini | Shadow |
|---|---|
| `systemInstruction.parts[].text` | `system` text blocks; the handling prompt is appended as one more part (on a Gemma model, which takes no system instruction, it opens the first user turn instead) |
| a `user` content's `text` parts | user text (the prompt filter may rewrite a registered value into its symbol) |
| a `user` content's `inlineData` parts | the user's own media, sent as is, unless it is a tool's media (below) |
| a `model` content's `text` parts | assistant text |
| a `model` content's `thought: true` parts, and every `thoughtSignature` | not read, never written: they round-trip byte-identical (Gemini 3 requires the current turn's signatures back as it sent them) |
| `functionCall {id?, name, args}` | `tool_use` with the args object; `apply` writes changed args back (the view map's reverse pass, the net-gate history) |
| `functionResponse {id?, name, response, parts?}` | `tool_result` (below) |
| `tools[].functionDeclarations[]` (`parameters` or `parametersJsonSchema`) | the tool list (the handling prompt's capabilities). Google's JSON reader takes a single value for a repeated field as a list of one, and Goose 1.53.0 sends `tools` as ONE Tool object (captured from the binary), so `tools` and `functionDeclarations` are read either way and the provider-side-tool check runs on both forms; `contents` and `parts`, which the shadow writes back by position, must be lists |

**A function response's text.** The clients wrap the tool's text in an object:
OpenClaw `{"output": text}` or `{"error": text}`, the AI SDK `{"name", "content":
text}` (a JSON result as `content`), Goose `{"content": {"text": text}}`. When
the response has exactly one string leaf (a top-level `name` equal to the
call's name is not counted), that string is the result's text and the masked
text is written back into the same leaf, so the provider sees the same shape
with the symbol in it. Any other response is read as its canonical JSON (as
the Chat wire reads a JSON tool result) and written back as the masked JSON
when it still parses to an object, else as `{"output": masked}`.

**A tool's media.** A function response's `parts` (inline media, Gemini 3), an
`inlineData` part in the same content as function responses (the AI SDK's
legacy form), and the `inlineData` parts of a `user` content directly after a
run of function responses (OpenClaw's "Tool result image:" turn for older
models) are the tool's output: they join that tool result in the shadow, which
the rewrite then masks whole, and `apply` drops them from the body. A user's
own media in that exact position is masked too, the fail-closed direction. A
text part in a content that carries function responses is read as the tools'
output as well (the AI SDK's legacy form writes a tool part it cannot map as a
text part there): it joins the response before it, is judged with it, and
moves into it. A function response in a `model` turn, or a function call in
a `user` turn, is refused: it would pass unread.

**Correlation.** A function call without an `id` gets a positional one in the
shadow; a function response without one is matched to the first unanswered
call of the same name in the turn before it. A response that matches no call
is classified as an unknown tool (UNTRUSTED). The answer side (§4.3) gives every
call an id, so the agents echo it back.

**Fail-closed (400, nothing sent).** A content role other than `user`, `model`
(and the old `function`); a part key the adapter does not know, or one spelled
twice (`functionResponse` and `function_response`: the API accepts both
spellings, so the adapter reads both and refuses the pair); `fileData` anywhere
(the provider fetches the file into the context, where no gate sees it);
`executableCode` / `codeExecutionResult`; a non-text system part; any `tools`
entry other than `functionDeclarations` (`googleSearch`, `codeExecution`,
`urlContext`, `fileSearch`, `googleMaps`, `retrieval`, `computerUse`, MCP
servers: they run at the provider); `cachedContent` (context Mandu never saw);
streamed function-call arguments (`streamFunctionCallArguments`).

### 4.3 The answer

Gemini sends a function call whole inside one part (no argument fragments),
so each streamed chunk is gated in place, with no hold: every `functionCall`
goes through the core's gate, its `args` replaced by the canonical
serialization of what the gate released (arguments that are not an object
rename the call to `mandu_refused_unreadable_call`, a tool no agent has), and a
call without an `id` is given one. Text parts are reported for the `tllm_call`
event; thought parts, `thoughtSignature`, model `inlineData`, usage and
grounding metadata pass untouched. Fail-closed: a chunk that does not parse, a
`functionCall` with `partialArgs` / `willContinue`, an `executableCode` or
`codeExecutionResult` part, or a part key the adapter does not know ends the
stream with an error event; a buffered answer that cannot be read is a 502.

**Split tokens.** The repacker reads a chunk as a text run when it has one
candidate whose content is one plain `text` part (no `thought`, no signature);
the run is the candidate index, and a `finishReason` ends it. A `$MDU:` token
split across two chunks moves forward whole; every other chunk relays
verbatim. The `MEDIA:` reply gate reads the same runs.

The proxy never desymbolizes the answer, as on the other wires: placeholders
reach the agent as placeholders, and the reply filter shows the human the
originals.

### 4.4 Credentials

The key passes through: the `x-goog-api-key` header, or a `key=` query
parameter, goes upstream as the agent sent it and is never logged (every log
line names the path without its query). When the agent's key file is twinned,
the agent sends a placeholder; `x-goog-api-key: <placeholder>` is a third
header shape, beside `x-api-key` and `authorization: Bearer`, that the proxy
puts the real key back into, for the routed host only (agent-sign-in.md §3). A placeholder in `key=` is not put back: the provider
answers 401 (nothing raw is sent). Vertex AI's OAuth bearer passes as sent
(`authorization: Bearer ya29…`, with `x-goog-user-project`), as does a
Vertex express-mode key in `x-goog-api-key`; neither is logged. A launch that
routes OpenClaw's `google-vertex` leaves `GOOGLE_CLOUD_API_KEY` (the express
key OpenClaw reads) unmasked, as `googleRoutedKeyVars` does for Gemini keys.
An ADC file under a wrapper launch is the twin like any credential file (the
token refresh then fails, nothing raw is sent): Vertex with ADC under the
wrapper needs the key form until that file is left to the agent (§10).

## 5. Routing

The launcher routes a Gemini provider the way it routes an OpenAI-family one
(`launcher/src/agent-model-route.ts`): the route gains the api
`google-generative-ai`, the agent's provider base URL points at
`<proxy>/_mandu/google/<id>`, and the proxy is told each routed provider's real
base URL in `MANDU_GOOGLE_UPSTREAMS` (a JSON object, provider id → base URL;
malformed refuses the proxy's start, as `MANDU_OPENAI_UPSTREAMS` does;
`routeUpstreamsEnv` splits a launch's routes into the two tables). The
proxy's own refusals on these routes are in Google's error shape
(`{"error":{"code","message","status"}}`), which the three clients print.

- **OpenClaw:** the built-in `google` provider (upstream
  `https://generativelanguage.googleapis.com/v1beta`) and any
  `models.providers.<id>` with `api: "google-generative-ai"` and a `baseUrl`.
  OpenClaw's own `google-vertex` provider (api `google-vertex` or none) is
  routed too (2026-10-26, §4.1): its `baseUrl` points at the proxy's origin
  and its address goes to the proxy in `MANDU_VERTEX_UPSTREAMS` (the origin
  of the user's `baseUrl`; none, or one with `{location}`, is Google's own
  hosts), on OpenClaw 2026.7.1 and later only (`openclawVertexVersionRefusal`:
  an older release, or one the launch cannot read, is refused before anything
  starts, naming it). Another id with api `google-vertex` is refused (the
  proxy serves one Vertex provider, and only the bundled plugin's transport
  for that id is measured), as are `google-gemini-cli` and `google-interactions`.
  So does the `github-copilot` provider on any wire (2026-10-26): OpenClaw
  sends its calls to the endpoint its Copilot sign-in answers with, whatever
  the `baseUrl` (openclaw-plugin.md §8.1, "GitHub Copilot").
- **OpenCode:** the built-in `google` provider and any `provider.<id>` on
  `@ai-sdk/google` (its `options.baseURL`, default the same upstream). Vertex
  (`@ai-sdk/google-vertex`) stays refused.
- **Goose:** its `google` provider, by env as for its other routed providers
  (`GOOGLE_HOST` pinned at the proxy route, the user's own host as the
  upstream).

**`mandu serve`'s OpenClaw plugin route (openclaw-plugin.md §8.1, built
2026-10-25):** `google-generative-ai` is one of the declaration's
`PROVIDER_WIRES`; install writes a Gemini provider's `baseUrl` as
`<proxy>/_mandu/google/<id>` on the session's model proxy (whose port is in
`anthropic-proxy.port`, as for every wire), and the pool hands the proxy each
declared Gemini provider's own address in `MANDU_GOOGLE_UPSTREAMS`
(`declaredUpstreamEnv`); the route check, `mandu doctor`, `mandu serve
status` and uninstall treat it as any routed provider. Vertex AI is NOT one
of the declaration's wires: install refuses `google-vertex` (or any provider
with that api) unless left unprotected, because OpenClaw 2026.3.x, inside
the plugin's `compat.pluginApi` floor, sends Vertex calls to Google whatever
the `baseUrl`, and install cannot tell which OpenClaw the Gateway runs
(openclaw-plugin.md §8.1, "Vertex AI").

**OpenClaw's Azure OpenAI and ChatGPT sign-in apis** (§9): the wrapper
and Route 1 route a `models.providers.<id>` with `api:
"azure-openai-responses"` or `"openai-chatgpt-responses"` (the built-in
`openai` with no `baseUrl` on the latter) at `<proxy>/_mandu/openai/<id>`,
in `MANDU_OPENAI_UPSTREAMS` with the base OpenClaw itself would call (§9);
both are `PROVIDER_WIRES` of the declaration, and the route check, `mandu
doctor`, `mandu serve status` and uninstall treat them as any routed
provider.

**The agent's key.** A launch that routes a Gemini provider leaves the
agent's own Google key variable unmasked (`googleRoutedKeyVars`: OpenCode's
`GOOGLE_GENERATIVE_AI_API_KEY` and `GEMINI_API_KEY`, OpenClaw's
`GEMINI_API_KEY`), as the arbiter leaves `ANTHROPIC_API_KEY` and
`OPENAI_API_KEY` and the Goose launch its routed provider's: masked, the
agent sent the placeholder and the provider would refuse every turn (found
by the real OpenCode run).

## 6. Tests

- `interceptors/anthropic-proxy/test/unit/gemini-wire.test.ts`: the request
  walk per part type and per client fixture (OpenClaw, OpenCode, Goose),
  write-back into the same leaf, a tool's media masked with its result,
  thought parts and signatures byte-identical, correlation without ids,
  snake_case spellings, every refusal, `MANDU_GOOGLE_UPSTREAMS`;
- `gemini-sse.test.ts`: the answer gate (canonical args, a minted id, an
  unreadable call renamed, a chunk without calls byte-identical, every
  unreadable shape ending the stream), the JSON-array stream, the token
  repacker across split chunks, the reply gate's reading;
- `route.test.ts`, `response-id.test.ts`, `auth-substitution.test.ts`: the
  routes, the answer's id, the `x-goog-api-key` put-back;
- `test/component/gemini-route.test.ts`: the real proxy against a scripted
  Gemini upstream over SSE, the JSON-array stream and a buffered answer (the
  request masked, the calls gated and recorded, a split token whole, the key
  never logged; the arbiter failing, an unrouted provider, an unread
  operation, a provider-side tool, a file by URI and an unreadable answer
  each send nothing or relay nothing ungated);
- the real binaries against a scripted Gemini upstream:
  `launcher/test/component/goose-compat-real.test.ts` (goose 1.53.0, its
  `google` provider), `launcher/test/component/opencode-gemini-real.test.ts`
  (OpenCode 1.18.13, `@ai-sdk/google`) and the OpenClaw plugin lane's
  Gemini leg (an OpenClaw 2026.9.9 Gateway through `mandu serve`'s pool):
  every turn through the proxy on the client's own path, the labelled file
  only as a placeholder; `tests/stack/serve-pool-invariant.test.ts` (the
  pool's proxy for a declared Gemini provider, the exfil sink);
- `tests/stack/gemini-wire-secrets.test.ts`: a registered secret in a tool
  result, in each client's wrapper, reaches the scripted Gemini model only as
  its placeholder, through the production adapter over a real
  `ArbiterServer` in `secrets` axes; with the arbiter gone, 502 and nothing
  sent;
- Vertex AI (§4.1): `route.test.ts` (`classifyVertexRoute`, `vertexOrigin`),
  `gemini-wire.test.ts` (`MANDU_VERTEX_UPSTREAMS`),
  `test/component/vertex-route.test.ts` (the real proxy at its root against
  a scripted Vertex per origin: the response masked at Google's host for the
  location or the session's own address, the bearer as sent and never
  logged, calls gated; no Vertex route, another publisher, an unread
  operation, a location that is not a region, a provider-side tool, the
  arbiter failing each send nothing), `tests/stack/vertex-wire-secrets.test.ts`
  (a registered secret in a Vertex function response reaches the model only
  as its placeholder over a real `ArbiterServer` in `secrets` axes; the
  arbiter gone or no Vertex route, nothing sent), and
  `launcher/test/component/openclaw-vertex-real.test.ts`: the real `openclaw
  agent --local` under the real launcher on every OpenClaw it finds (the CI
  guest's pin 2026.7.1-2, and 2026.3.12, 2026.9.9, 2026.10.7), its
  `google-vertex` provider at a scripted Vertex model: from 2026.7.1 every
  request crosses the proxy on OpenClaw's own Vertex path (the bypass
  oracle: a request without the proxy's handling prompt or with Mandu's
  session header still on it, or a CONNECT toward a Google host through the
  recording `HTTPS_PROXY`, fails it), the labelled file only as a
  placeholder; 2026.3.12 refused before the launch, the model untouched;
- the launcher: `agent-model-route.test.ts`, `opencode-v2-config.test.ts`,
  `agent-config.test.ts`, `goose-compat-providers.test.ts` (which providers
  route, where each points, the two upstream tables).

## 7. AWS Bedrock

Not supported, left as a TODO: SigV4 signs the request body, so a masked body
would need re-signing with the user's AWS keys.

## 8. The Ollama wire

**Built 2026-10-26** (`src/ollama-wire.ts`, `src/ollama-ndjson.ts`, the
`OLLAMA_ADAPTER` in `wire-adapter.ts`). Ollama's own chat API, `POST
/api/chat`, which OpenClaw's built-in `ollama` provider (and `ollama-cloud`,
and any provider with `api: "ollama"`) speaks. Ollama's OpenAI-compatible
endpoint (`/v1/chat/completions`) was already the Chat adapter's; this is the
native one.

### 8.1 What OpenClaw sends

Read from the published releases the real-OpenClaw lane runs (unpacked, read
only; the `ollama` provider's `convertToOllamaMessages`,
`buildOllamaChatRequest`, `createConfiguredOllamaStreamFn` and its model
discovery):

| | 2026.3.12 | 2026.7.1-2 | 2026.9.9 | 2026.10.7 |
|---|---|---|---|---|
| chat at `<baseUrl minus a trailing /v1>/api/chat` | yes | yes | yes | yes |
| base URL | `models.providers.<id>.baseUrl`, else the model's, else `http://127.0.0.1:11434` | the same (`ollama-cloud`: `https://ollama.com`) | the same | the same |
| a call's `id` / a result's `tool_call_id` | none / none | sent / none (`tool_name` only) | sent / sent | sent / sent |
| a tool's images | dropped | dropped | `images` on the tool message | the same |
| assistant `thinking`, `truncate`, `shift`, `think` | no | `think` | yes | yes |
| tool-name alias (`tool_call` → `openclaw_tool_call`) | no | no | no | yes |
| a call written as text in the reply is RUN | no | yes | yes | yes |

Every request is `{model, messages, stream: true, tools?, options, …}` with
messages `system` / `user {content, images?}` / `assistant {content,
thinking?, tool_calls?: [{id?, function: {name, arguments: object}}]}` /
`tool {content, images?, tool_call_id?, tool_name?}`; the answer is NDJSON,
one `{model, created_at, message: {content, thinking?, tool_calls?}, done,
done_reason?, …}` per line, `done: true` last (`stream: false`: one object).

**The base URL is honoured on every one of the four** (no bypass like
OpenRouter's, supported-agents.md §2.1): the chat, the model discovery
(`GET /api/tags`, `POST /api/show {model}`), the run preflight (`GET
/api/tags`) and a configured local service's health check all join their
path to the configured `baseUrl`. With no `models.providers.ollama` at all,
OpenClaw's implicit discovery probes `http://127.0.0.1:11434` (a listing, no
conversation); the routing below always writes the entry, so the chat
follows it. Other Ollama calls OpenClaw makes are not the model's
conversation and are refused at the route, never sent: `POST /api/pull`
(onboarding), `POST /api/embed` (memory search with Ollama embeddings at the
provider's address: refused, so that memory search fails rather than send
the indexed text unmasked), `/api/web_search` (the Ollama web-search
plugin at the provider's address). OpenClaw's node-inference tool talks to a
paired node's own Ollama, not the provider; its prompt is the model's tool
input (gated) and its answer a tool result (masked).

### 8.2 Routes

Under `/_mandu/ollama/<id>`:

| Request | Route |
|---|---|
| `POST …/api/chat` | gated; NDJSON streamed unless `stream: false` (one object, buffered) |
| `POST …/api/show` | relayed only when its body names one model (`{model}` or `{name}`, optional `verbose`) and nothing else: a model lookup, no conversation (`ollamaShowRefusal`); any other body 403 |
| a bodyless `GET` / `HEAD` (`/api/tags`, `/api/version`, `/api/ps`) | relayed |
| anything else (`/api/generate`, `/api/embed`, `/api/embeddings`, `/api/pull`, `/api/push`, `/api/create`, `/api/copy`, `/api/delete`, `/api/blobs/…`, `/api/web_search`, `/v1/…`, a provider not routed) | 403, never sent |

The proxy's own refusals are in Ollama's error shape (`{"error": "…"}`),
which OpenClaw prints.

### 8.3 The request as a shadow

| Ollama | Shadow |
|---|---|
| a `system` message's `content` | `system` text; the handling prompt is appended to the last system message that opens the conversation (a model's chat template may read only one), or is a system message of its own at the head |
| a `user` message's `content` | user text (the prompt filter may rewrite a registered value into its symbol) |
| a `user` message's `images` | the user's own media, sent as is; right after a run of tool messages they are read as the tools' (a client that moves a tool's images into the next user turn): they join the last result, masked with it, and leave the body (the fail-closed direction) |
| an `assistant` message's `content` | assistant text; its `thinking` is never read nor written |
| `tool_calls[]` `{id?, function: {name, arguments}}` | `tool_use` with the arguments object; `apply` writes changed arguments back |
| a `tool` message | `tool_result`: its `content` the text, its `images` join it (masked whole with it, then dropped from the body) |
| `tools[].function` | the tool list (the handling prompt's capabilities) |

**Correlation.** A call without an `id` gets a positional one in the shadow.
A `tool` message with a `tool_call_id` answers that call (a call from a turn
outside the request is put back from the proxy's call memory); one without
answers the first unanswered call of its `tool_name` (any name when it has
none) in the assistant message before it, which is the order OpenClaw writes
results in; one that matches nothing is an unknown tool's (UNTRUSTED). This
is exact on 2026.9 and later (ids both ways, and the answer side gives every
call an id) and positional before; positional pairing relies on OpenClaw
writing a turn's results in call order, which every release does.

**Tool names.** OpenClaw 2026.10.7 renames, on this wire only, a tool whose
name is part of a tool-call envelope (`<tool_call>`, `[TOOL_CALLS]`, …) to
`openclaw_<name>`: the Tool Search dispatcher `tool_call` goes out as
`openclaw_tool_call`, and the system prompt tells the model to use it. And
from 2026.7.1 it runs a call named `functions.<tool>`, `function_<tool>`,
`tools/<tool>`, … as `<tool>` when that is a declared tool. The gates key on
the agent's own names, so read naively the dispatcher's inner calls and a
`functions.exec` would pass as unknown tools, ungated. The adapter reads
every name as OpenClaw maps it (`canonicalToolName`, against the request's
declared names) in the shadow and in the answer gate; the wire name goes
back to the agent unchanged.

**Fail-closed (400, nothing sent).** A top-level field the chat API does not
take (`prompt`, `system`, `template`, `context`, `suffix`, `images`, `raw`:
`/api/generate`'s, whose content the shadow would not read); a role other
than `system`, `user`, `assistant`, `tool`; a message field Mandu does not
know, or one on a role that does not carry it (tool calls on a user message,
images on an assistant or system message, `tool_name` off a tool message);
`content` that is not a string; call arguments that are not an object; an
unknown field on a call; a `tools` entry that is not a function.

### 8.4 The answer

Ollama sends a tool call whole inside one line, so each line is gated in
place, with no hold: every `tool_calls[]` entry goes through the core's gate
under its canonical name, its `arguments` replaced by what the gate released
(arguments that are not an object rename the call to
`mandu_refused_unreadable_call`; a JSON string is read as OpenClaw 2026.10
reads one), and a call without an `id` is given one. Reply text is reported
for the `tllm_call` event; `thinking`, usage, timing and the `done` fields
pass untouched; an `{"error": …}` line passes as sent. Ollama answers carry
no response id (`responseIdWire: null`).

**A tool call written as text.** OpenClaw 2026.7.1 and later wrap every
Ollama stream in a plain-text tool-call compat layer that RUNS a call the
model writes in its reply text (`[tool]` then a JSON payload, `[tool:tool]`,
`<function=tool>…</function>`, the Harmony `commentary to=tool code {…}`,
each at the start of a line). No gate sees such a call. The answer gate ends
the stream with an error line as soon as the reply text opens one
(`textCallStart`: `<function=`, `[tool:`, a Harmony header, or `[name]`
naming a declared tool), before the line that completes it is relayed and
before the `done` line, without which OpenClaw runs nothing of the turn.
Stricter than OpenClaw (which also wants the payload and skips Markdown
code): a reply that only looked like a call fails, the fail-closed
direction.

**Fail-closed.** A line that does not parse or is not an object, a
`message` field Mandu does not read, content or thinking that is not a
string, `tool_calls` that is not a list, an unknown call field, or a call
written as text ends the stream with `{"error": "mandu: …"}` and nothing
after it (no `done` line reaches the agent, so OpenClaw fails the turn); a
buffered answer that cannot be read is a 502.

**Split tokens.** The repacker (`OllamaTextRepacker`, text-repack.ts with
NDJSON framing) reads a line as text when its `message.content` is a string
and it carries no tool call, thinking text, images or logprobs; one run per
answer, the `done` line ends it. The `MEDIA:` reply gate (`OLLAMA_WIRE`)
reads the same run.

### 8.5 Routing

The launcher's route gains the api `ollama` (`agent-model-route.ts`): the
built-in `ollama` (upstream `http://127.0.0.1:11434`) and `ollama-cloud`
(`https://ollama.com`), and any `models.providers.<id>` with `api: "ollama"`
and a `baseUrl` (an entry for `ollama` / `ollama-cloud` without an `api`
is that wire, as in OpenClaw). The upstream is the base URL without a
trailing `/v1`, as OpenClaw joins `/api/chat`. The agent's provider points at
`<proxy>/_mandu/ollama/<id>`, and the proxy is told each routed provider's
address in `MANDU_OLLAMA_UPSTREAMS` (malformed refuses the proxy's start).
The address rule is every route's: https, or plain http to a literal
loopback address, so a LAN Ollama at `http://192.168.…` is refused with why
(a remote Ollama behind https is routed). A launch that routes an Ollama
provider leaves `OLLAMA_API_KEY` unmasked (`ollamaRoutedKeyVars`), as for
the other wires' keys.

**`mandu serve`'s OpenClaw plugin route (openclaw-plugin.md §8.1):** `ollama`
is one of the declaration's `PROVIDER_WIRES`; install writes an Ollama
provider's `baseUrl` as `<proxy>/_mandu/ollama/<id>` on the session's model
proxy, the pool hands the proxy each declared Ollama provider's address in
`MANDU_OLLAMA_UPSTREAMS` (a built-in's null address: the service
environment's entry, else its own), and the route check, `mandu doctor`,
`mandu serve status` and uninstall treat it as any routed provider. The
built-in `ollama` / `ollama-cloud` is routed when the config declares it or a
model names it.

### 8.6 Tests

- `interceptors/anthropic-proxy/test/unit/ollama-wire.test.ts`: the request
  walk per message type and per release's shape (2026.3.12 without ids,
  2026.7.1, 2026.10.7), write-back, correlation (ids, `tool_name`, position,
  the call memory), a tool's images masked with its result, the system
  prompt's placement, the tool-name aliases, every refusal, `/api/show`'s
  check, `MANDU_OLLAMA_UPSTREAMS`;
- `ollama-ndjson.test.ts`: the answer gate (released arguments, a minted id,
  the aliased dispatcher and `functions.exec` gated as the tool they run, an
  unreadable call renamed, a line without calls byte-identical, each text-call
  form ending the stream before `done`, every unreadable shape), the
  buffered answer, the token repacker across split lines, the reply gate's
  reading; `route.test.ts`: the routes;
- `test/component/ollama-route.test.ts`: the real proxy against a scripted
  Ollama upstream over NDJSON and a buffered answer (the request masked, the
  calls gated and recorded, a split token whole, a text call ending the
  stream; the arbiter failing, an unrouted provider, each refused endpoint,
  `/api/generate`'s fields on a chat, a lookup carrying more than a model,
  an unreadable answer: nothing sent or nothing ungated relayed);
- `tests/stack/ollama-wire-secrets.test.ts`: a registered secret in a tool
  message, in each release's shape (positional correlation included), and
  with an image, reaches the scripted Ollama model only as its placeholder,
  through the production adapter over a real `ArbiterServer` in `secrets`
  axes; with the arbiter gone, 502 and nothing sent;
- the real OpenClaw binaries: the plugin lane's Ollama leg, on EVERY lane
  version (2026.3.12, 2026.7.1-2, 2026.9.9, 2026.10.7): an OpenClaw Gateway with its
  built-in `ollama` provider routed by install's plan through `mandu serve`'s
  pool to a scripted Ollama (`tests/lib/fake-ollama.ts`), the labelled file
  only as a placeholder, every request at the provider's own address;
- the launcher: `agent-model-route.test.ts`, `agent-config.test.ts`,
  `secret-setup.test.ts`, `openclaw-providers.test.ts` (install and
  uninstall exact), the pool's `attachment-pool.test.ts`.

### 8.7 Found while building it

- **OpenClaw runs a tool call written as text on several wires**, not only
  Ollama's (§8.4): its LM Studio and xAI providers wrap their streams in the
  same compat layer, and both were routed on the Chat / Responses adapter,
  which did not end a reply that writes a call. Found here, fixed in §10.
- The tool-name alias (§8.3) is on this wire only (OpenClaw's
  `extensions/ollama`); the other wires carry the agent's own names.

## 9. OpenClaw's Azure OpenAI and ChatGPT sign-in apis

Two more OpenClaw apis are the Responses wire at another address, with the
SAME adapter (`RESPONSES_ADAPTER`) and gates under `/_mandu/openai/<id>`;
what differs is the path, a query, the key header and the body's encoding.
Read from the published clients (unpacked, read only): `@openclaw/ai`
2026.7.1-2, 2026.9.9 and 2026.10.7 (`azure-openai-responses`,
`openai-chatgpt-responses`, over `openai` 6.45 / 7.20 / 7.27), and
OpenClaw's own `openai-chatgpt-provider` and `transport-policy`.

| api | OpenClaw sends | Route | Upstream recorded |
|---|---|---|---|
| `azure-openai-responses` | `POST <baseUrl>/responses?api-version=<v>` (the `AzureOpenAI` client; `/responses` is not a deployment path, so no `/deployments/<d>`; `v` defaults to `v1`, `AZURE_OPENAI_API_VERSION` sets it), the key in `api-key` (or an Entra bearer), `store: false`, the deployment as `model` | `responses`, the query in `rest` | the `baseUrl`, normalized as OpenClaw does: a `*.openai.azure.com` / `*.cognitiveservices.azure.com` address with no path or `/openai` is `…/openai/v1` |
| `openai-chatgpt-responses` (a ChatGPT sign-in) | two transports. The agent's turns (OpenClaw's OpenAI-SDK transport, 2026.7.1-2 to 2026.10.7, measured by the lane): `POST <base>/responses`, the base canonicalized to `https://chatgpt.com/backend-api/codex` for any chatgpt.com address. @openclaw/ai's own ChatGPT transport: `POST <base>/codex/responses` (`/responses` after a base ending in `/codex`), `Authorization: Bearer <OAuth JWT>`, `chatgpt-account-id`, `originator`, `OpenAI-Beta`, `session_id`; `store: false`, `instructions`, `include: ["reasoning.encrypted_content"]`, `text.verbosity`; the body zstd-compressed for the built-in `openai` provider; a WebSocket tried first | `responses` on `…/responses` and `…/codex/responses`; below an upstream ending in `/codex`, `/codex/responses` is sent as `/responses` (route.ts `upstreamRest`), so both transports reach the URL OpenClaw itself would call | `https://chatgpt.com/backend-api/codex` for any chatgpt.com address and for the built-in `openai` with no `baseUrl`; a base ending in `/codex/responses` cut to its `/codex`; any other as is |

Every other part of the body is the Responses request §2 already reads:
`reasoning` items (their `encrypted_content` included) pass byte-identical,
`instructions` gains the handling prompt.

### 9.1 Where each version sends

| OpenClaw | Azure (`azure-openai-responses`) | ChatGPT (`openai-chatgpt-responses`) |
|---|---|---|
| 2026.3.12 | not in the config schema (the Gateway refuses such a config; nothing is sent) | not in the schema (its ChatGPT api is `openai-codex-responses`, not routed) |
| 2026.7.1-2, 2026.9.9, 2026.10.7 | the provider's `baseUrl`, UNLESS `AZURE_OPENAI_BASE_URL` or `AZURE_OPENAI_RESOURCE_NAME` is set: `resolveAzureConfig` reads them first, and every Azure call goes there | the provider's `baseUrl` (a custom one is kept by `normalizeCodexTransportFields`; only a native api.openai.com / chatgpt.com address is canonicalized) |

**The Azure endpoint variables are a bypass**, closed on both routes:

- the wrapper (`mandu openclaw`) pins `AZURE_OPENAI_BASE_URL` at the
  route in the agent's environment (`writeAgentConfig`): OpenClaw's config
  `env` block and its dotenv files never replace a set variable, so every
  Azure call reaches the proxy. A config whose `env` sets either variable is
  refused (OpenClaw could read it before the launch's value is seen), and so
  is a second Azure provider (one variable serves all of them);
- Route 1 cannot set the Gateway's environment, so it reads it
  (`services/openclaw-gateway-env.ts`, closed 2026-10-26; the residual this
  section first left open). For the Gateway whose config is the session's:
  the running Gateway's own environment, `/proc/<pid>/environ` (every
  process of this user that is an OpenClaw Gateway, `openclaw … gateway
  [run|start]` or OpenClaw's `openclaw-gateway` title, whose
  OPENCLAW_CONFIG_PATH / OPENCLAW_STATE_DIR / HOME resolve to that config:
  same uid, no privilege); its systemd user unit
  (`openclaw-gateway*.service` in the user's unit directory), running or
  not, its `Environment=` and `EnvironmentFile=` (the next start); OpenClaw's
  dotenv files (`<config dir>/.env`, `~/.openclaw/.env`,
  `$OPENCLAW_STATE_DIR/.env`, `~/.config/openclaw/gateway.env`), which
  OpenClaw loads where the variable is unset (an environ is the environment
  at exec, without them); and the config's own `env` block. Only names and
  where they are set are kept, never a value.
  - **install** refuses an Azure provider while any of these, or install's
    own environment, sets either variable;
  - **the service's route check** (every 30 s and on each config edit),
    **`mandu doctor`** and **`mandu serve status`** report the route lost
    (`route-direct`, naming the variable and where it is set: "calls of Azure
    OpenAI provider azure go to AZURE_OPENAI_BASE_URL (the running Gateway's
    environment, pid 4242) instead of the route") while an Azure provider is
    routed, the same loss as a provider pointed away from the proxy;
  - **not verified is not routed.** Where a running Gateway's environment
    cannot be read (no /proc: a host that is not Linux; a Gateway process
    whose environ is unreadable), the answer is `route-unverified`, which
    loses the model context (fail closed), and install refuses the Azure
    provider. No Gateway running and no unit is verified with nothing set:
    a Gateway started later is read at the next check.

**An Azure AI Foundry OpenAI-v1 endpoint** (`*.services.ai.azure.com` or
`*.api.cognitive.microsoft.com` ending in `/openai/v1`) is refused: OpenClaw
calls it with the plain OpenAI client (a bearer, no `api-version`), and with
the route's loopback address it would choose the Azure client instead, so
the provider would get a request shaped for another endpoint.

### 9.2 Credentials

The Azure key passes through in `api-key`. When the agent's key is twinned,
the agent sends a placeholder: `api-key: <placeholder>` is a fourth header
shape (beside `x-api-key`, `x-goog-api-key` and `authorization: Bearer`)
the proxy puts the real key back into, for the routed host only
(`auth-substitution.ts`, agent-sign-in.md §3); never logged. A wrapper
launch that routes an Azure provider leaves `AZURE_OPENAI_API_KEY`
unmasked (`azureRoutedKeyVars`), as for Gemini's key variables: OpenClaw
reads it when the provider names no `apiKey`. The ChatGPT sign-in's OAuth
bearer passes as sent: OpenClaw reads the account id out of the JWT before
it sends anything, so a placeholder would never leave it, and the proxy
does not mint or refresh it. OpenClaw accepts the built-in `openai` on this
api only with a subscription auth profile (an OAuth or token sign-in;
"Configured openai authentication is not compatible with the selected model
route" otherwise, 2026.7.1-2 to 2026.10.7), so the real-binary legs (§9.4)
run the transport on a provider of the user's own id with a static bearer,
and the built-in's zstd body is proven by the proxy suites.

### 9.3 What the proxy adds

- **A compressed body** (`request-encoding.ts`): OpenClaw's ChatGPT
  transport sends `content-encoding: zstd` for the built-in `openai`
  provider. The proxy decodes it (zstd, gzip, deflate, br; at most the
  proxy's body limit), gates the JSON and sends it decoded with no
  `content-encoding`. An encoding it cannot undo is 415, a body that does
  not decode 400, one past the limit 413; nothing is sent. zstd needs
  Node.js 22.15 or later, Mandu's floor since 2026-10-26 (packaging.md;
  it was 22.13, as was the CI guest's): below it, a from-source run, every
  zstd body is 415, so the wrapper and install
  refuse the built-in `openai` on a ChatGPT sign-in up front, and `mandu
  doctor` says why (`chatgptZstdProblem`), instead of a session whose every
  turn is refused. Another provider id on the ChatGPT api is not
  compressed.
- **Two paths, one URL** (`upstreamRest`): see the table above.
- **No socket.** @openclaw/ai's ChatGPT transport tries a WebSocket to
  `ws://<base>/codex/responses` first. Node hands an upgrade with no
  listener to the request handler as a plain `GET`, which the routes relay;
  so every request with an `upgrade` header under a wire prefix is refused
  (403), and OpenClaw falls back to SSE (`transport: "auto"`; a user who
  pins `websocket` gets an error, never a socket). A relayed socket would
  carry frames no adapter reads.
- The answer is the Responses SSE §2 reads; the backend's `response.done`
  is gated as `response.completed` is.

### 9.4 Tests

- `interceptors/anthropic-proxy/test/unit/route.test.ts` (`/codex/responses`,
  the `api-version` query, the paths not read, `upstreamRest`), `auth-substitution.test.ts`
  (`api-key`), `request-encoding.test.ts` (every coding, the refusals);
- `test/component/azure-chatgpt-route.test.ts`: the real proxy against a
  scripted upstream, each api's request as OpenClaw sends it (the masked
  result, the key put back for the routed host only and never logged, the
  bearer as sent, the zstd body sent decoded, the upgrade refused, the
  arbiter failing and an unknown encoding sending nothing);
- `tests/stack/azure-chatgpt-wire-secrets.test.ts`: a registered secret in a
  tool result reaches both models only as its placeholder through the
  production adapter over a real `ArbiterServer` (`secrets` axes); with the
  arbiter gone, 502 and nothing sent;
- the launcher: `agent-model-route.test.ts` (verdicts, the upstream
  normalization, the env-block and two-Azure refusals, the key variable),
  `agent-config.test.ts` (the pinned `AZURE_OPENAI_BASE_URL`),
  `openclaw-providers.test.ts` and `test/component/openclaw-install.test.ts`
  (routed with their real upstream recorded, uninstall exact, the endpoint
  variables in a `.env` or install's environment refused; a real process
  standing in for a running Gateway with the variable, and a systemd user
  unit fixture, refused at install and lost in the doctor's verdict);
- the Gateway's environment: `launcher/test/unit/openclaw-gateway-env.test.ts`
  (the reader over a fake /proc, unit directory and dotenv files: this
  config's Gateway only, other users and programs ignored, no /proc or an
  unreadable environ not verified, never a value),
  `openclaw-route-check.test.ts` (`route-direct` and `route-unverified`),
  dashboard `attachment-pool.test.ts` (the route check lost, routed, then
  not verified);
- the real OpenClaw Gateway against a scripted Responses upstream: the
  plugin lane's `route1-azure` and `route1-chatgpt` (a provider of its
  own id on the ChatGPT transport, §9.2) legs, on every lane
  version from 2026.7 (2026.7.1-2, 2026.9.9, 2026.10.7) through `mandu
  serve`'s pool: every request on the api's own path with its key or
  bearer as sent and none around the proxy, the labelled file only as its
  placeholder; and `route1-azure-env` on the same versions: the Gateway
  started with AZURE_OPENAI_BASE_URL in its own environment, the pool's
  route check (its pool record) reports the route lost, naming it.
- a real model (2026-10-26, by hand, on the maintainer's go): OpenClaw
  2026.10.7's built-in `openai` on a ChatGPT sign-in (a `token` auth
  profile: the sign-in's access token only) through the pool to the real
  backend, the plugin lane's legs live (openclaw-plugin.md §9, "The first
  live run"): every turn on `/codex/responses`, the backend accepting the
  bearer the proxy passed through as sent, a WebSocket tried first and
  refused, the labelled file only as its
  placeholder. So the built-in on this api runs on a token sign-in, not
  only on a provider of the user's own id (§9.2).

## 10. Tool calls written as text

**Found and fixed 2026-10-26** (a security regression on routes already
routed; `src/text-calls.ts`, `openai-sse.ts` `lineTextCalls`). OpenClaw has a
plain-text tool-call compat layer (`createPlainTextToolCallCompatWrapper`,
its `tool-call-repair` scanners) that turns a tool call the model WRITES in
its reply text into a real tool call, and runs it. It wraps the streams of
its LM Studio provider (`lmstudio`; the wrapper checks the provider id) and
its xAI provider (`xai`, alias `x-ai`), both measured running such a call on
2026.7.1-2, 2026.9.9 and 2026.10.7 (not on 2026.3.12), and its Ollama provider (§8.1, from 2026.7.1), and the plugin SDK
exports it to any third-party provider plugin. The line forms it runs, at the
start of a line outside Markdown code, naming a declared tool: `[tool]` then
a JSON payload and `[/tool]` or `[END_TOOL_REQUEST]`; `[tool:tool] {…}`;
`<function=tool>…</function>`; the Harmony `<|channel|>commentary to=tool
code<|message|>{…}` (or without the channel marker).

No gate sees such a call: the answer gate reads `tool_calls` / function-call
items, and the text passed as text. `lmstudio` (at `http://127.0.0.1:1234/v1`,
a loopback address) and `xai` were routed on the Chat / Responses adapter
whenever declared with a `baseUrl`, in the wrapper and in Route 1. **Measured
on the real binaries** (the plugin lane's text-call legs, a scripted model
answering `[tool:exec] {"command":"touch <marker>"}`, before the fix):
OpenClaw 2026.7.1-2, 2026.9.9 and 2026.10.7, with either provider routed
through the pool's proxy, RAN the exec (the marker file appeared) and the proxy recorded
no tool call for it. An exec the gate would have refused (a symbol in
command position, a secret file to the network) would have run the same way.

**The fix.** On an OpenClaw session's routes the answer gate ends a reply
whose text opens such a call (`textCallStart`: `<function=`, `[tool:`, a
Harmony header, or `[name]` naming a declared tool, at a line start) with the
wire's error event, before the event that completes the opening and before
the finish (`[DONE]`, `response.completed`), so OpenClaw never holds a whole
call and the turn fails. Over Chat Completions and the Responses API,
streamed (each text delta, per choice / content part, a split opening caught
on the delta that completes it) and in every snapshot that carries a whole
text (`.output_text.done`, a content part, an output item, the completed
response: an upstream that sends no deltas); a buffered answer carrying one
is a 502.

**Keyed on the agent, not the provider id.** OpenClaw decides by which
plugin owns the provider (its id or an alias, normalized), and a third-party
provider plugin may wrap a provider of any id; a provider id table would be
one release behind. So the stop applies to every OpenAI-family route of a
session whose gate surface is OpenClaw's (`openclaw-agent`), and of one the
arbiter did not name (the union surface, fail-closed); an OpenCode or Goose
session's routes are unchanged (they run no such call; Goose's own
`<function=` form keeps its per-route `MANDU_OPENAI_TEXT_CALLS`).

**The accepted false positive.** Stricter than OpenClaw: the opening is
enough (no payload), Markdown code is not skipped, and with no tool list any
`[name]` counts. A reply line that begins with `<function=`, `[tool:`,
`commentary to=` or a declared tool's name in brackets (`[read]`) in prose
ends the turn with an error the user sees; a footnote (`[1]`), a bracket
mid-line or an undeclared `[note]` passes.

**Not covered here.** The Gemini and Messages wires: no bundled OpenClaw
provider on them wraps its stream (2026.10.7); a third-party provider plugin
on those wires that did would not be stopped. The Ollama wire's answer gate
(§8.4) reads the same grammar from `text-calls.ts`, on every session.

Tests: `test/unit/text-calls.test.ts` (every form, split openings, prose,
both wires streamed and buffered, the snapshots), `test/component/
openai-text-calls.test.ts` (the real proxy: providers `lmstudio`, `xai` and
another id on an OpenClaw session, the union surface, an OpenCode session
unchanged), `tests/stack/openai-text-calls.test.ts` (a real ArbiterServer
binding the session's spec, `secrets` axes), and the plugin lane's
text-call legs on every lane version (red before the fix on 2026.7.1-2,
2026.9.9 and 2026.10.7 for both providers; 2026.3.12 never ran it; green
after on all four).

## 11. The bypass oracle

Every wire above is only as good as the route that puts a provider's calls
on it. Each bypass found so far was a model call that silently skipped the
proxy, and each was found by hand: OpenClaw 2026.3.12 sends an OpenRouter
model it does not know to openrouter.ai whatever the `baseUrl`
(openclaw-plugin.md §8.1, "The model fence"); `github-copilot` replaces the
`baseUrl` with the endpoint its sign-in answers with (refused, §8.1); the
Azure client reads its endpoint variables before the `baseUrl` (§9.1). The
bypass oracle (2026-10-26) is the test that catches the next one without a
person looking for it: it records where a real OpenClaw's connections go,
for every provider Mandu claims to route, by both routes, on every version
the lane runs (openclaw-plugin.md §9, "The bypass oracle", has the legs).

**The recorder** (`tests/lib/egress-box.ts`, `egress-box-host.mjs`): the
program under test runs in an *egress box*, a private network namespace
with only loopback, made without host root. The box host, inside it, holds
the only ways out: one bridge per allowed port (the Mandu proxy's), which
pipes to a unix socket the test forwards to the real proxy; a catch-all
listener on 80, 443 and every scripted upstream's own port, which records
the address dialed, the name it was looked up by, the TLS SNI or the HTTP
request line and Host, and answers nothing useful; and a DNS stub that
answers every name with an address of its own on loopback and records the
query. With `openssl` on the host the catch-all also terminates TLS with a
throwaway certificate that only the programs in the box are told to accept
(`NODE_TLS_REJECT_UNAUTHORIZED=0` in their environment), so a dial to a
provider's 443 is recorded with its request line and the head of its body,
not only its SNI. Each catch-all connection also names the program that
dialed: the client socket's owner, found through `/proc/net/tcp` and
`/proc/<pid>/fd`, with its parents' command lines; each DNS query names
the program that asked the same way (`/proc/net/udp`), which names a
program that dials and exits before its connection is read. The box reads
the owner while the client still waits on it (before it answers the
ClientHello or the query), asking again a few times over ~170 ms. A
process that made itself non-dumpable (Claude Code's CLI does, part way
through its start) has a `/proc/<pid>/fd` the box cannot read: when no
readable process holds the socket, the holder is one of those hidden
processes, and the box records that candidate set; the judge accepts it as
benign only when every candidate is a program named benign. Such a
process's own `cmdline` reads empty too (as does any process past releasing
its memory on the way out), so the box keeps the command line of every
process it has seen, by pid and start time, from a 25 ms sweep of `/proc`
and from every lookup it makes; a candidate it never saw stays unnamed, and
fails. A connection
for which nothing at all can be named stays a bypass, with the box's
reason. It does not depend on the program's cooperation: it sees every
process in the namespace, Node or not, children included. Three tiers, the
strongest the host allows, always printed:

| Tier | Made with | What it sees |
|---|---|---|
| `netns+caps` | `unshare` (user, net, mount, PID namespaces); the programs in a nested user namespace as the invoking user, with no capability | every IPv4 address routed to loopback (`ip route add local 0.0.0.0/0 dev lo`), so a dial to any address on a catch port is recorded; the DNS stub on port 53; the hosts file holds only localhost, so each model-API lookup reaches the stub; TLS read with the peek certificate |
| `netns` | `bwrap`, no capabilities (Ubuntu's AppArmor userns restriction allows bubblewrap only) | loopback only; the hosts file maps every known model-API host to an address of its own; no port below 1024: a dial to a provider's 443 is refused (nothing leaves) but not attributed |
| `inproc` | no namespace: `NODE_OPTIONS=--require egress-inproc.cjs` and `HTTPS_PROXY` at a refusing recorder | Node's `net`/`tls`/`dns` in each Node process that loads it; blocks nothing. The weak fallback, said in the test output |

The CI guest gives `netns+caps` (its kernel allows unprivileged user
namespaces, `kernel.apparmor_restrict_unprivileged_userns=0`, and a nested
one inside the suite's own sandbox). A developer host with Ubuntu's
restriction gets `netns`.

**The judge** (`judgeEgress`, pure): a bridged connection on a proxy port is
the route. A connection to a scripted upstream's own port (the provider's
address, dialed around the proxy), to a model-API host (by name, SNI or
Host: `MODEL_API_HOSTS` and the tenant or region families, Azure, Vertex,
Bedrock, Copilot), or carrying a model-API path is a **bypass**, with one
exception read in full: a GET, HEAD or OPTIONS with no body on a path that
names no model API (a model catalog, a connectivity probe) is
**provider-side**, reported and not failed, since it carries no
conversation. Anything less certain (a POST, a body, a TLS session whose
request was not read) stays a bypass. Anything else is **unknown** egress,
which fails too unless the test names its host, or the dialing program's
command line, benign with a reason: fail-closed. A benign host that carries
a turn's text fails as well, and a benign program's model-API path is
still a bypass. A DNS query for a model-API host is
reported; followed by a connect, the connect is the bypass.

**What it proves, with the utility control.** The oracle also requires that
every routed provider's scripted upstream received the turn through the
proxy, so a run with no model call is a failure, and a model call a release
sent elsewhere shows either as a bypass or, where the dial was refused
unrecorded, as a turn that never reached its upstream. A negative control
in every Route 1 run reverts one installed route to the provider's own
address (what a release that ignores the `baseUrl` does) and requires the
oracle to report it.

**What it cannot see.** On `netns+caps`, a dial to a port outside the catch
ports is refused, not recorded (there is no packet capture); IPv6 has only
`::1`; the bridge carries whatever the program sends to the proxy's port,
which the proxy itself judges. A release that sent the conversation BOTH
through the route and, as a copy, to an unlisted port would be refused on
the copy and pass. On `netns`, a dial to a provider's port 443 is refused
unattributed (the utility control is what turns it red). On `inproc`,
nothing is blocked and only Node is seen.

## 12. Next

- The openai-proxy on the same core (§2).
- Gemini's `:countTokens` through the mask, if an agent needs it.
- Vertex AI with ADC under the wrapper: the ADC file left readable to
  OpenClaw (as Goose's own key file is to Goose) so its token refresh works;
  and Route 1 for Vertex, if the plugin's floor rises past 2026.3.x or the
  Gateway's release becomes knowable at install.
- The Gemini CLI and the Antigravity CLI: both reach only a Gemini endpoint,
  so this wire is the half of their support that lives in the proxy
  (supported-agents.md §5.5).
