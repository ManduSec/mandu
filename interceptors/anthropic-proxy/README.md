# anthropic-proxy — Mandu Track A (Model-API MITM proxy)

The **AgentView context boundary**, reconstructed at the network layer. A pure
userspace TypeScript HTTP reverse proxy the agent (Claude Code) points at via
`ANTHROPIC_BASE_URL`. It forwards to `https://api.anthropic.com` but transforms
the Anthropic **Messages API** (`POST /v1/messages`) to enforce the Mandu
security invariant:

> Untrusted data reaches the privileged model (**T-LLM**) only as an opaque
> symbol (`$MDU:*`), so attacker-controlled text can never steer the
> agent's tool-call decisions.

See `docs/design/architecture/mandu.md` §1–§3 and `docs/design/architecture/implementation-plan.md` §4
(Track A) + §9 (invariant oracle). This package is **pure userspace** — it does
**not** open the symbol-table DB; the arbiter (`arbiter/`) is the single owner and
the proxy calls it over its Unix-socket NDJSON IPC.

## What it does

### Request (agent → model) — the security-critical path
1. Parse the JSON body `{ model, system, messages, tools, stream?, ... }`.
2. Build a correlation map `tool_use_id → {name, input}` from `tool_use` blocks
   in prior **assistant** messages of this request.
3. For every `tool_result` block (in user messages), look up its originating
   tool `name` + `input`, derive an `origin` hint (Read→`file_path`,
   WebFetch→`url`, Bash→`command`, …), and call arbiter
   `classify({tool, value, boundary:"model_context", origin, params:input})`.
   If **UNTRUSTED**, call arbiter `symbolize(...)` and **replace** the content
   with the returned symbol token.
4. Inject the handling system prompt from arbiter `handlingPrompt()` as a
   prepended `system` block so T-LLM treats symbols as opaque (idempotent across
   turns via a marker).
5. Forward the rewritten request upstream.

### Response (model → agent)
6. Pass the upstream bytes through to the client **unchanged**, while a
   hand-rolled SSE parser reconstructs each `tool_use` block (`name` +
   accumulated `input_json_delta` JSON) and calls arbiter `recordToolCall(...)`
   so the OS interceptors (Track B / M3) can later correlate an `openat` /
   `connect` / `execve` to a known tool decision. The non-streaming JSON
   response shape is handled too.

### Which requests go upstream (`src/route.ts`, fail-closed)

The proxy sends a request to the provider only when it can vouch for what it
carries:

| Request | What happens |
|---|---|
| `POST /v1/messages` | symbolized, as above |
| `POST /v1/messages/count_tokens` | the same symbolization, without the handling prompt (Claude Code counts its context per category, e.g. `/context`, and the prompt would inflate each count); no events, no turn |
| bodyless `GET` / `HEAD` (e.g. `/v1/models`, Claude Code's `HEAD /api/hello`) | relayed verbatim, arbiter not consulted |
| under `/_mandu/openai/<provider>` (an OpenClaw or OpenCode OpenAI-family provider the launcher routed, agent-e2e-harness.md §9) | `POST …/chat/completions` and `POST …/responses` gated by the same code as `/v1/messages` (`src/openai-wire.ts`); a bodyless `GET`/`HEAD` relayed; anything else, or a provider the launcher did not route, refused with 403 |
| anything else (`/v1/chat/completions`, `/chat/completions`, `/v1/complete`, `/v1/messages/batches`, `/v1/files`, a `GET` with a body, …) | **refused** with 403 `{"error":{"type":"mandu_fail_closed","message":"mandu: refusing POST /v1/chat/completions: …"}}`, never sent |

Until 2026-09-27 everything but `POST /v1/messages` was relayed raw, so an
agent speaking another generation wire through `ANTHROPIC_BASE_URL` reached
the model with its tool results unmasked, and count_tokens sent secret values
to the provider (os-test-matrix.md §10.14.1). Probe-verified wires
(2026-09-27): Claude Code 2.1.283 sends `HEAD /api/hello`, `POST
/v1/messages?beta=true` and, for `/context`, a dozen count_tokens; OpenCode
1.18.32 and OpenClaw 2026.6.35 (with `api: "anthropic-messages"`) send only
`POST /v1/messages`. OpenClaw without `api` sends `/chat/completions` and now
stops with the refusal message instead of reaching the model raw.

### Observability events (best-effort, off the security path)

For each `/v1/messages` exchange the proxy ALSO emits canonical `ManduEvent`
records (shape mirrored locally in `src/events.ts` from
`dashboard/src/event-model.ts`) to the arbiter via `emit(event)`
(`{op:"emit", event}` → `{seq}`) so the dashboard can render the dual-view
trace. Per exchange it emits:

- **`tllm_call`** — `model`, an input `DualRepr` of the forwarded (symbolized)
  prompt summary + the symbols it carries, output = the assistant text + the
  `tool_use` names parsed from the response, and
  `invariant.violatedInvariant` computed from the §9 oracle predicate
  (`survivingUntrusted`): did any un-symbolized untrusted span survive in the
  forwarded prompt?
- **`tool_result`** (per result) — `output` `DualRepr` with `original` = the raw
  content and `symbolized` = the symbol token (when untrusted; `differs` true);
  `symbols` populated; `policy.trust`.
- **`symbolize`** (per minted symbol) — input = the raw value, output = the
  symbol, with provenance (tool/origin/value).
- **`tool_use`** (per tool_use parsed from the SSE or JSON response) — name +
  input.

`sessionId` is taken from a request header (`x-mandu-session-id` /
`x-mandu-session` / `x-session-id`, sanitized) else a stable per-process
fallback; `turn` increments per exchange within a session. Every `x-mandu-*`
header is read here and dropped before the provider, on every route
(2026-09-29; the native Messages path used to forward them).

Emission is **best-effort and OFF the security path**: every emit is wrapped
(`safeEmit`) so a failed or slow emit can never block or fail a request, never
weakens the symbolization invariant, and never feeds data back toward T-LLM. The
raw (untrusted) `original` values events carry go ONLY to the arbiter's
privileged event log / dashboard — never upstream. If the arbiter build predates
the `emit` op, the adapter degrades to a no-op (it does **not** fail closed —
unlike `handlingPrompt` / `recordToolCall`, emission is not security-relevant).

## Fail-closed (critical)

If the arbiter is unreachable, or `classify` / `symbolize` / `handlingPrompt`
errors, the proxy **refuses** the request (HTTP 502, body
`{"error":{"type":"mandu_fail_closed",...}}`) and forwards **nothing** — it
never downgrades to passing un-symbolized untrusted content upstream. An
unparseable Messages body is also refused (400), and so is every route the
proxy cannot mask (403, above). `recordToolCall` failures on
the response side are logged but **non-fatal**: recording is for OS-interceptor
correlation, not the symbolization invariant, and the bytes already reached the
client unchanged.

## Layout

| Path | Purpose |
|---|---|
| `src/proxy.ts` | The HTTP reverse-proxy server: read body, rewrite request, forward, stream response while sniffing `tool_use`. Injectable upstream (`UpstreamFetcher`). |
| `src/rewrite-request.ts` | The security-critical request transform: correlation map, classify+symbolize per `tool_result`, handling-prompt injection. Throws `RewriteRefusal` (→ fail-closed) on arbiter error. |
| `src/sse-parser.ts` | Hand-rolled SSE parser reconstructing `tool_use` (name + accumulated input JSON) from the streamed response; plus `extractToolUsesFromJson` for the non-streaming path. Observe-only. |
| `src/events.ts` | Local `ManduEvent` builder (mirrors `dashboard/src/event-model.ts`; no dashboard dep) + the reusable §9 oracle predicate `survivingUntrusted`. Constructs `tllm_call` / `tool_result` / `symbolize` / `tool_use` events the proxy emits best-effort. |
| `src/arbiter-client.ts` | The narrow `Arbiter` interface the proxy depends on (incl. `emit(event)→{seq}` + a local `getSymbolPattern`), plus `ArbiterClientAdapter` bridging the real `arbiter/ipc/client.ts`. Decouples the proxy from the arbiter so tests use a mock. |
| `src/messages-types.ts` | The subset of the Anthropic Messages API the proxy parses (permissive, passthrough-preserving). |
| `src/server-main.ts` | Deployment entry point: wires the real arbiter client adapter + listens. The only file that imports the sibling arbiter package. |
| `test/helpers/mock-arbiter.ts` | In-memory `Arbiter` with fail-closed-by-default classify, `$MDU:*`-shaped symbolize, and failure injection. |
| `test/helpers/mock-upstream.ts` | Fake Anthropic upstream (`UpstreamFetcher`) that captures the forwarded body + returns canned SSE/JSON; SSE fixture builders. |
| `test/unit/rewrite-request.test.ts` | Correlation, untrusted→symbol, trusted passthrough, prompt injection, fail-closed. |
| `test/unit/sse-parser.test.ts` | `tool_use` reconstruction incl. chunk-split deltas, multi-block, truncation, non-streaming. |
| `test/unit/proxy.test.ts` | Full HTTP path over a loopback socket: forwarded-body symbolization, streaming passthrough + record, non-streaming record, fail-closed 502/400, bodyless-GET relay. |
| `test/unit/events.test.ts` | Observability emission: `tllm_call` (`violatedInvariant:false`, symbol in input repr, raw in `original`), `symbolize`/`tool_result` dual-repr, `tool_use` from SSE/JSON, sessionId/turn derivation, and the proof that a THROWING emit does not fail the request or weaken the invariant (best-effort, off the security path). |
| `test/component/invariant-oracle.test.ts` | The plan §9 oracle: a stored-IPI fixture's payload never appears un-symbolized in the forwarded upstream body. |
| `src/route.ts` · `test/unit/route.test.ts` · `test/component/route-fail-closed.test.ts` | Which requests may go upstream: refused wires send nothing (a counting upstream sees zero requests); count_tokens arrives only symbolized. |
| `src/cloud-model.ts` · `test/unit/cloud-model.test.ts` · `test/component/cloud-model-local-upstream.test.ts` | A cloud-backed model name at a declared local upstream (`MANDU_UPSTREAM_LOCAL=1`) is refused with a 400 and sends nothing (plan 11 §8 item 3). |

## Run

```sh
npm install
npm run typecheck     # tsc --noEmit
npm test              # unit + component (mock arbiter + mock upstream; no key, no net)
npm run test:unit
npm run test:component

# deployment (real arbiter over its Unix socket):
MANDU_ARBITER_SOCK=/run/mandu/arbiter.sock npm run serve
# then point the agent at it:
export ANTHROPIC_BASE_URL=http://127.0.0.1:8788
```

Env for `serve`: `MANDU_ARBITER_SOCK` (required), `MANDU_PROXY_PORT` (8788),
`MANDU_PROXY_HOST` (127.0.0.1), `MANDU_UPSTREAM`
(`https://api.anthropic.com`; may carry a base path; plain `http://` only to
a loopback address, see below), `MANDU_UPSTREAM_LOCAL` (`1` = the upstream
is a main model declared `local: true`, see below), `MANDU_SESSION_KEY`,
`MANDU_HANDLING_MODE`.

**TLS:** for local use the agent talks to the proxy over plain
`http://127.0.0.1:<port>` via `ANTHROPIC_BASE_URL`. TLS termination /
`NODE_EXTRA_CA_CERTS` is a deployment concern (managed deployments, plan §10),
not needed for the tests.

**Upstream transport** (`proxy.ts` `upstreamTransport`, 2026-09-27). The
proxy → model leg is TLS for every real deployment: an `https:` origin uses
`node:https`. A plain `http:` origin is accepted ONLY when its host is a
LITERAL loopback address (`127.0.0.0/8` or `::1`); that is the offline
`mandu demo`, whose stand-in model is a capture server on this machine
(`docs/design/distribution/mandu-demo.md` §4). Every other origin (any other host, the
name `localhost`, which a hosts file can point anywhere, or another scheme)
is refused per request with a 502 and **nothing is sent**, so the model
conversation never crosses a network in the clear. Before this, any `http:`
origin failed with Node's "Protocol not supported", and tests that needed a
local upstream minted a self-signed cert and disabled TLS verification
(`NODE_TLS_REJECT_UNAUTHORIZED=0`). Pinned by
`test/unit/upstream-transport.test.ts`.

**Upstream base path** (plan 11 phase 3). `MANDU_UPSTREAM` may carry a path
(`http://127.0.0.1:4000/anthropic`); it prefixes every request path, exactly
as the agent would have with that base URL. The launcher sets it when a
user-set `ANTHROPIC_BASE_URL` is a model declared under policy.yaml `models:`
(the proxy then stays in front of that model instead of being skipped), and
rewrites a declared `localhost` to `127.0.0.1` so the loopback rule above
holds. Pinned by `test/unit/upstream-transport.test.ts`.

**Cloud models at a local upstream** (plan 11 §8 item 3). Ollama serves
cloud-backed models (`gpt-oss:120b-cloud`, `glm-4.6:cloud`, any tag that is or
ends in `cloud`) through the same loopback API as the models it runs itself,
and relays requests for them to ollama.com. When the declared main model is
`local: true`, the launcher also sets `MANDU_UPSTREAM_LOCAL=1`, and the proxy
answers a `POST /v1/messages` or count_tokens request whose `model` is
cloud-backed (`src/cloud-model.ts`) with a 400
`{"type":"error","error":{"type":"invalid_request_error","message":"mandu: refusing model …"}}`
before any arbiter call, sending nothing upstream. A 400, not the fail-closed
502: Claude Code retries a 5xx, and shows a 400's message once. The predicate
is mirrored from `arbiter/policy/cloud-model.ts`, which also refuses such a
model on a `local: true` `models:` entry at policy load. Pinned by
`test/unit/cloud-model.test.ts` and `test/component/cloud-model-local-upstream.test.ts`
(a real loopback upstream that records zero connections).

## Integration with the real arbiter

The proxy is written against the narrow `Arbiter` interface; `src/server-main.ts`
wires `ArbiterClientAdapter` over the real `arbiter/ipc/client.ts`. The two
security-relevant ops this proxy needs — `handlingPrompt` and `recordToolCall` —
have landed on the arbiter; the adapter bridges the real client's
`handlingPrompt(mode?) → string` into the proxy's `{prompt}` shape. If a arbiter
build predates either op, the adapter throws → the proxy fails closed.

The proxy also calls the arbiter's observability `emit(event) → {seq}` op (also
landed). Because emission is best-effort / off the security path, the adapter
bridges the real client's `emit(event) → number` into the proxy's `{seq}` shape
and, if a arbiter build predates the op, degrades to a no-op (`seq:-1`) rather
than failing closed.
