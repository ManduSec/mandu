# openai-proxy — Mandu Track A (OpenAI Responses-API MITM proxy)

The **AgentView context boundary** for the **Codex CLI** (the open-source second
target), reconstructed at the network layer. A pure userspace TypeScript HTTP
reverse proxy the Codex CLI points at via a custom `model_provider` `base_url`.
It forwards to `https://api.openai.com`, or, for a request made on a ChatGPT
sign-in (one carrying `chatgpt-account-id`), to the ChatGPT backend's Codex
base `https://chatgpt.com/backend-api/codex`; both are fixed in the proxy, and
the sign-in's bearer is relayed as Codex sent it, never stored or refreshed
([`agent-sign-in.md §2`](../../docs/design/agents/agent-sign-in.md)). Either
way it transforms the OpenAI **Responses API** (`POST .../responses`) to
enforce the Mandu security invariant:

> Untrusted data reaches the privileged model (**T-LLM**) only as an opaque
> symbol (`$MDU:*`), so attacker-controlled text can never steer the
> agent's tool-call decisions.

This is the OpenAI/Codex sibling of `interceptors/anthropic-proxy` (Anthropic/Claude
Code). It is **simpler**: **symbolization is request-side only** — the proxy never
symbolizes on the response path. Without a view map it streams the model→agent
bytes back **verbatim**; with one ([fs-portable-core](../../docs/design/integrity/fs-sync.md)
P4) the SSE passes through a conservative `function_call`-argument path rewriter
(`src/sse-rewrite.ts`) so HumanView paths in the model's shell commands map into
the AgentView. The `tllm_call` event it emits carries a readable `▸ role`
transcript of the forwarded request and the model's answer, which a passive
reader takes off the relayed body without changing a byte (`src/transcript.ts`).

## What it does

### Request (agent → model) — the security-critical path
1. Parse the JSON body. Codex (codex 0.136, `wire_api="responses"`) POSTs to
   `{base_url}/responses` with keys `model, instructions, input, tools,
   tool_choice, parallel_tool_calls, reasoning, store, stream, include,
   prompt_cache_key, client_metadata`. `instructions` is the system-prompt
   string; `input[]` holds the conversation items.
2. Build a correlation map `call_id → {name, arguments}` from `function_call`
   items in `input[]`.
3. **THE UNTRUSTED INGRESS:** for every `function_call_output` item (the raw
   stdout of the agent's shell tool re-entering context), look up its
   originating `function_call`, derive an `origin` hint (the shell command from
   `arguments.cmd`), and call arbiter
   `classify({tool, value:output, boundary:"model_context", origin, params})`.
   If **UNTRUSTED**, call arbiter `symbolize(...)` and **replace** the item's
   `output` field with the returned symbol token.
4. Prepend the handling system prompt from arbiter `handlingPrompt()` to
   `instructions` (idempotent across turns via a `[mandu:handling-prompt]`
   marker — Codex resends the full `instructions` every turn).
5. Forward the rewritten request upstream.

Codex's shell tool is `exec_command` with params `{cmd:string}`; it runs
`/bin/bash -lc '<cmd>'` in the workspace. Unknown / unmapped tool names classify
UNTRUSTED under the arbiter's fail-closed default, so the command output is
symbolized regardless.

### Response (model → agent)
No response-side **symbolization** ever happens in this proxy. Without a view
map, the upstream SSE bytes pass through to the client **unchanged**. With one
(fs-sync.md §1.3, P4), the SSE runs through `ResponsesArgsRewriter`
(`src/sse-rewrite.ts`): absolute HumanView path prefixes inside the model's
`function_call` command string are forward-mapped into the AgentView (argument
deltas are buffered per item and re-emitted consistently across the four
argument-bearing events). Conservative by construction: unparseable or unchanged
arguments re-emit the original bytes; every non-argument event passes through
verbatim. The request side gains the matching **reverse** map (AgentView →
HumanView in `function_call_output` text and echoed `function_call` args, after
symbolization).

### Which requests go upstream (`src/route.ts`, fail-closed)

| Request | What happens |
|---|---|
| `POST …/responses` | symbolized, as above |
| `POST …/chat/completions` | read as the Responses request it carries and symbolized the same way (`src/chat-wire.ts`); the answer's tool calls gated (`src/chat-sse.ts`); see below |
| bodyless `GET` / `HEAD` (the `/models` listing) | relayed verbatim, arbiter not consulted |
| anything else (`/responses/compact`, `/responses/input_tokens`, `/completions`, `/embeddings`, `/files`, `/realtime/calls`, a `GET` with a body, …) | **refused** with 403 `{"error":{"type":"mandu_fail_closed","message":"mandu: refusing POST /v1/completions: …"}}`, never sent |

Until 2026-09-27 every non-`responses` path was relayed raw (the sibling of the
anthropic-proxy gap, os-test-matrix.md §10.14.1). Codex 0.154 sends only
`POST /v1/responses` through a routed provider, its auto-compaction included
(probe-verified 2026-09-27 with `model_auto_compact_token_limit`, under the
provider name `mandu` and under `OpenAI`); `/responses/compact` is an older
compaction endpoint whose body is a whole transcript, so it is refused rather
than relayed. WebSocket upgrades are not served (the routed provider does not
enable Codex's websocket transport).

**Mandu's own headers stay home.** On every forwarded request (both routes and
the relay) the proxy drops each `x-mandu-*` header (`x-mandu-session-id`,
`-batch-id`, `-tenant`) after reading it: the provider, which may be a third
party on the Chat route, has no use for them (2026-09-29; before, they were
forwarded). The agent's own headers, its credential included, go as sent.

### The Chat Completions route (2026-09-29)

`POST …/chat/completions` is the wire of Kimi Code, Aider, the OpenHands CLI,
nanobot and most local-model servers (docs/design/agents/supported-agents.md §5.5). It has
the Responses route's guarantees:

- **Request** (`src/chat-wire.ts`). The body is read as a Responses request
  (the *shadow*): each assistant `tool_calls[]` entry a `function_call`, each
  `role:"tool"` message a `function_call_output`, the user / assistant text as
  messages, the tools as function tools. The same `rewriteRequest` masks it
  (secret results as secret symbols in `secrets`; untrusted results too when
  the integrity axis is on), and only what it changed is written back onto the
  agent's body: a tool message's content, a call's arguments (the view map),
  and the handling prompt, prefixed to the first system message (or a new
  one). Fields the reader does not know (`reasoning_content`, sampling
  options, the user's own images) go as sent.
- **Refused with 400, nothing sent**: a tool message with a non-text part (a
  tool's image would pass the mask), the `function` role, an unknown role, the
  legacy `functions` / `function_call`, a non-function tool, provider-side
  fetching (`web_search_options`, OpenRouter `plugins`, an `:online` model),
  an unparseable body. An arbiter failure is a 502, nothing sent.
- **Response** (`src/chat-sse.ts`). Tool-call fragments are held until the
  choice finishes, then each call is gated by the same arguments transform as
  the Responses wire (the exec gate, the forward path map) and released once,
  canonically serialized; unreadable arguments are refused while the exec gate
  is on. Every call is a `tool_use` event; the text goes through the token
  repacker. A 2xx answer that cannot be read is a 502, never relayed.
- Tests: `test/unit/{chat-wire,chat-sse,route}.test.ts`,
  `test/component/chat-completions.test.ts`, `test/component/route-fail-closed.test.ts`;
  over the real arbiter, `tests/stack/proxy-route-fail-closed.test.ts`.

## Fail-closed (critical)

If the arbiter is unreachable, or `classify` / `symbolize` / `handlingPrompt`
errors, the proxy **refuses** the request (HTTP 502, body
`{"error":{"type":"mandu_fail_closed",...}}`) and forwards **nothing** — it
never downgrades to passing un-symbolized untrusted content upstream. An
unparseable Responses body is also refused (400), and so is every route the
proxy cannot mask (403, above).

## Layout

| Path | Purpose |
|---|---|
| `src/proxy.ts` | The HTTP reverse-proxy server: read body, rewrite request, forward, stream the response back (through the SSE path rewriter when a view map is set, verbatim otherwise). Injectable upstream (`UpstreamFetcher`). |
| `src/rewrite-request.ts` | The security-critical request transform: correlation map, classify+symbolize per `function_call_output`, handling-prompt injection into `instructions`. Throws `RewriteRefusal` (→ fail-closed) on arbiter error. |
| `src/view-map.ts` | The bidirectional HumanView↔AgentView prefix map (fs-sync.md §1.3, P4). Core copied from the proven `anthropic-proxy/src/view-map.ts`; the Codex adapters are **textual** (every path lives in the free-text shell command string — there are no typed path fields, hence no sensitive-path gate here). |
| `src/sse-rewrite.ts` | `ResponsesArgsRewriter` — forward-maps `function_call` command args in the model→agent SSE (buffers deltas per item, rewrites at `.done`, rewrites item snapshots in place). |
| `src/unmapped-upload.ts` · `src/unmapped-upload-core.ts` · `test/unit/unmapped-upload.test.ts` | The unmapped upload leg (2026-10-17; supported-agents.md §2, "The upload residuals", item 4): every local path in a call of a tool Codex does not ship (an MCP server's, called directly or from a code cell) goes to the arbiter's `fileUploadDecision` in its unmapped form; a held one becomes a path that names no file (a cell is replaced whole by the sentinel cell), an upload after a possible writer of the same response is withheld. The core is byte-equal with the anthropic-proxy's copy (pinned by the unit test). |
| `src/events.ts` | Best-effort `ManduEvent` builders (`tllm_call` / `tool_result` / `symbolize`), mirroring the dashboard schema field-for-field so Codex sessions render in the dual-view trace. Off the security path (`safeEmit`). |
| `src/responses-types.ts` | The subset of the OpenAI Responses API the proxy parses (permissive, passthrough-preserving). |
| `src/arbiter-client.ts` | The narrow `Arbiter` interface the proxy depends on (`classify` / `symbolize` / `handlingPrompt` / `emit`) + `ArbiterClientAdapter` bridging the real `arbiter/ipc/client.ts`. Decouples the proxy from the arbiter so tests use a mock. |
| `src/server-main.ts` | Deployment entry point: wires the real arbiter client adapter + listens. The only file that imports the sibling arbiter package. |
| `test/helpers/mock-arbiter.ts` | In-memory `Arbiter` with fail-closed-by-default classify, `$MDU:*`-shaped symbolize, and failure injection. |
| `test/helpers/mock-upstream.ts` | Fake Responses upstream (`UpstreamFetcher`) that captures the forwarded body + returns canned bytes. |
| `test/unit/rewrite-request.test.ts` | Correlation, untrusted→symbol, trusted passthrough, prompt injection (idempotent), fail-closed, forged/empty output, helpers. |
| `test/unit/proxy.test.ts` | Full HTTP path over a loopback socket: forwarded-body symbolization, verbatim response passthrough, fail-closed 502/400, bodyless-GET relay. |
| `src/route.ts` · `test/unit/route.test.ts` · `test/component/route-fail-closed.test.ts` | Which requests may go upstream: refused wires send nothing (a counting upstream sees zero requests). |
| `test/unit/chatgpt-upstream.test.ts` | Which upstream (`chooseUpstream`): a ChatGPT sign-in to the ChatGPT base, anything else to the API, a declared main model the only upstream (a sign-in there refused, 403); the path mapping, the relayed headers, no credential in events or logs. |
| `test/unit/view-map.test.ts` / `test/unit/proxy-view-map.test.ts` / `test/unit/sse-rewrite.test.ts` | The P4 map core, its wiring through the proxy (both directions), and the SSE rewriter's buffer-and-re-emit behavior. |
| `test/unit/events.test.ts` | The event builders (shape, DualRepr, surviving-untrusted refs). |
| `test/component/invariant-oracle.test.ts` | The Track-A invariant oracle for the OpenAI/Codex wire shape. |
| `test/component/view-map-rewrite.test.ts` | End-to-end P4 rewrite through the HTTP proxy against the fake upstream. |

## Run

```sh
npm install
npm run typecheck     # tsc --noEmit
npm test              # unit (mock arbiter + mock upstream; no key, no net)

# deployment (real arbiter over its Unix socket):
MANDU_ARBITER_SOCK=/run/mandu/arbiter.sock npm run serve
# then point Codex at it:
#   -c 'model_providers.mandu={name="mandu",base_url="http://127.0.0.1:8789/v1",wire_api="responses",env_key="OPENAI_API_KEY"}'
```

Env for `serve`: `MANDU_ARBITER_SOCK` (required), `MANDU_PROXY_PORT` (8789),
`MANDU_PROXY_HOST` (127.0.0.1), `MANDU_UPSTREAM` (`https://api.openai.com`),
`MANDU_SESSION_KEY`, `MANDU_HANDLING_MODE`, `MANDU_VIEW_MAP` (optional P4
HumanView↔AgentView root pairs, JSON — set by the launcher's fs-view service),
`MANDU_ARBITER_HUMAN_SOCK` (the arbiter's human plane, for reply row
reservation's `symbolShape` / `sessionRelay` only; absent = no reservation),
`MANDU_REPLY_RESERVE` (`0` = kill switch) and `MANDU_REPLY_RESERVE_MAX` (row
cap, 2..200, default 40).

**Reply row reservation** (`docs/design/ui/reply-row-reservation.md` §11.7). When
the reply filter relays the session through a PTY and paints reserve blocks, a
`$MDU:` token whose value takes more than one screen row reaches Codex as an
N-row reserve block (`src/sse-reserve-expand.ts`, chained after the text
repacker): the `output_text` deltas and every snapshot (`output_text.done`,
`content_part.done`, `output_item.done`, `response.completed`) carry the same
expanded text; no event is invented or dropped. The next request collapses the
block back to the token in the assistant's `output_text` and strips any
leftover marker from every other text part (`src/reserve-request.ts`), so the
model never reads the row count. The grammar, layout and eligibility modules
(`reserve-block.ts`, `reserve-layout.ts`, `reserve-context.ts`) are verbatim
copies of the anthropic-proxy's.

**Upstream transport** (`proxy.ts` `upstreamTransport`, 2026-09-27; the same
rule as anthropic-proxy's). The proxy → model leg is TLS for every real
deployment: an `https:` origin uses `node:https`. A plain `http:` origin is
accepted ONLY when its host is a LITERAL loopback address (`127.0.0.0/8` or
`::1`): a stand-in model on this machine, which is how the fresh-agents VM
suite drives a real Codex with no key (`docs/design/testing/os-test-matrix.md §10`
§14). Every other origin (any other host, the name `localhost`, which a hosts
file can point anywhere, or another scheme) is refused per request with a 502
and **nothing is sent**. Before this, any `http:` origin failed with Node's
"Protocol not supported". Pinned by `test/unit/upstream-transport.test.ts`.

## Provenance / ground truth

The Codex wire shape this proxy targets was spiked against a REAL `codex` 0.136.0
process on this host (headless `codex exec`, `wire_api="responses"`). Verified
facts baked in:

- `wire_api` MUST be `"responses"` (codex 0.136 dropped `"chat"`); Codex POSTs to
  `{base_url}/responses` (path contains `/v1/responses`).
- The shell tool is `exec_command` with params `{cmd:string}`.
- Turn 2's untrusted ingress is the `output` field of each `function_call_output`
  item; the matching `function_call` carries `{name:"exec_command",
  arguments:'{"cmd":"…"}'}` from which we recover the `origin` command.

The live end-to-end proofs (real `codex exec` processes, no API key) live in
the maintainers' replay drills (not published): `codex-chatgpt.test.ts` (a labelled workspace
file read through this proxy + the real arbiter reaches the upstream only as a symbol),
`codex-prompt-filter.test.ts` (a secret in the human's prompt) and `codex-view-map.test.ts` (the P4 map, both
directions, against a real codex process), with the fake Responses upstream at
`tests/lib/fake-responses.ts` (SSE event sequences ported
verbatim from the verified spike). `codex-e2e.test.ts` is the real-model class
(costs OpenAI budget; see `docs/testing/e2e-catalog.md` §2c).

## Not built yet (Codex-track gaps)

- **U-LLM path**: `inspect-mcp`'s `inspect_symbol` is not wired for Codex.
  Buildable — Codex speaks MCP — just not built; processing untrusted content on
  the Codex track currently has no quarantined-model channel.
- **Live-model dual-view coverage**: the P4 map is live-proven against a fake
  upstream, but the `codex-e2e` real-model suite does not yet run an
  fsSync/dual-view scenario.

Permanent by Codex's design (not gaps to close): no trusted tool channel (only
`exec_command` → everything fail-closed UNTRUSTED), and no sensitive-path gate at
this proxy (no typed path fields to gate — shell-string paths are the exec
chokepoint's turf, fs-sync.md §1.4.1).
```
