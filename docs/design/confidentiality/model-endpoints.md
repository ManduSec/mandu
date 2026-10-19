# Model endpoints: which models may read a `local-model` file

> **Status: BUILT (2026-09-27/28).** Part 1 (the `local-model` level,
> declared models, a declared main model for Claude Code and Codex, editing
> in Settings) is complete, with its live drill passing in `secrets` and
> `full`. Part 2 (models on the organization's network: TLS rules, endpoint
> identity, `perimeter:`, the administrator's layer) is built through its
> phase 4. Not built: several clearance tiers (§2.2 D7) and a
> launcher-side endpoint forwarder (§2.2 D3).
>
> **How code cites this document.** Part 1 was written as *plan 11* and
> Part 2 as *plan 12*, and the code and tests cite them that way: plan 11
> §N is §1.N here and plan 12 §N is §2.N; *plan 11 D1–D8* are the
> decisions in §1.2, *plan 12 D1–D7* those in §2.2, and *plan 12 F1–F7*
> the findings in §2.1. Plan 11's phase 3 (its §5) is §1.7.1.
>
> **Vocabulary.** Levels `public ⊑ any-model ⊑ local-model ⊑ no-model`
> ([`confidentiality.md`](./confidentiality.md) §2), the token `$MDU:`, and
> two model axes: **role** (paper T-LLM / repo: the privileged model that
> acts, the agent's main model; paper U-LLM / repo: the quarantined helper
> behind `inspect_symbol` that reads) and **location** (external: a
> vendor's endpoint; local: a model inside the trust boundary that the
> operator or the organization declared, §2.2 D1).

**Goal.** A deployment that runs an external frontier model *and* a model
of its own can label a file so that its own model may process it and the
external model never sees it, byte or paraphrase, with the same fail-closed
character the other secret levels have. Combined with a file's `readers:`
([`confidentiality-plan-10-flow-taint.md`](./confidentiality-plan-10-flow-taint.md)),
this also gives "my own model and these programs, nobody else". The model
may run on this computer or on the organization's network; Part 2 makes the
second case as safe a destination as the first.

---

## 1. The `local-model` level and declared models

### 1.1 The gap

Before this design the confidentiality axis knew one model principal, "the
provider", and both model channels Mandu operates went to it: the T-LLM
upstream behind the model proxy and the U-LLM of `inspect-mcp` (`claude -p`,
or `api.anthropic.com` with a key). Three consequences for a user who also
ran a model of their own:

1. **No level said "my own model only".** `any-model` grants the external
   model a read (rung 3, `declassify_symbol`, with approval and a
   watermark); `no-model` refuses the local model too.
2. **A local helper was reachable only by accident, with no clearance
   attached.** `assertNonProxyBaseUrl` (`interceptors/inspect-mcp/src/ullm-client.ts`)
   rejects every loopback base URL except the launcher's forwarder, so that
   the quarantine never loops back through the instrumented T-LLM path, and
   the arbiter still saw one principal.
3. **The helper spoke one wire.** `AnthropicUllmClient` posts to
   `/v1/messages`; Ollama and vLLM serve OpenAI-style
   `/v1/chat/completions`.

The first is the security decision; the other two are plumbing, kept apart
so the decision can be tested without any model server.

### 1.2 Decisions

#### D1. One new level, and the total order stays total

```
public ⊑ any-model ⊑ local-model ⊑ no-model
```

| Level | Restricts | May be read by |
|---|---|---|
| `public` | nothing | anyone |
| `any-model` | {outside} | every model, the human, readers |
| `local-model` | {outside, external models} | **declared local models**, the human, readers |
| `no-model` | {outside, every model} | the human, readers |

Each restriction set strictly contains the previous one, so every rule that
folds levels keeps working unchanged: `maxConfidentiality` (the watermark,
the derived-file label, the exec-lineage fold), "an unknown value parses as
`no-model`" (an older build reading a `local-model` row treats it as
`no-model`, the fail-closed direction), and the default-secret catalog,
which mints only `public` and `no-model`. Nothing ever defaults to
`local-model`, as nothing defaults to `any-model`.

**Why one point and not a clearance relation.** The realistic deployment
has two model principals, one external and one local. A single added level
covers it while the axis stays a total order, which keeps fail-closed
unambiguous and the watermark a `max`. Compartments and several distinct
remote clearances stay out (§2.2 D7; `confidentiality.md` §13.5).

**Wire marker.** `$MDU:localmodel_<tool>[hash]`, beside `nomodel_` and
`anymodel_`. `shortToolTag` reserves the three prefixes so a real tool name
cannot forge one; every decision still reads the table row. The marker
exists so the handling prompt can teach a different move per level (D7).

#### D2. Model endpoints are declared in `policy.yaml`; undeclared means external

```yaml
models:
  - name: ollama
    url: http://127.0.0.1:11434
    wire: openai-chat          # anthropic (default) | openai-chat
    model: llama3.2
    local: true
    helper: true               # optional: the helper's model among several local entries (D5)
    token_env: OLLAMA_TOKEN    # optional: the variable holding a bearer token
```

- The list is **law**, so it lives in `policy.yaml` beside `paths:` and
  `apps:` (the arbiter enforces it live; the dashboard renders it), not in
  `config.toml`.
- **Every endpoint not on the list is external**: the T-LLM upstream, the
  default helper (`claude -p` or `api.anthropic.com`) and the launcher's
  helper forwarder (a verbatim relay to Anthropic). `local: true` is never
  inferred from an address: a LiteLLM on `127.0.0.1` can forward to a cloud
  vendor.
- **With no `local: true` entry, `local-model` behaves as `no-model` at
  every model** and like it everywhere else (still releasable at a bound
  destination, still readable by named readers). Labeling a file before
  declaring a model loses nothing and leaks nothing.
- **The model proxy's own address and the forwarder's are never local.**
  Declaring the proxy local would send `local-model` bytes to the external
  T-LLM. Because one arbiter serves many sessions and each session's proxy
  binds port 0, the arbiter never knows those addresses; the refusal lives
  where they are known: the launcher refuses a launch whose `local: true`
  entry resolves to its own proxy or forwarder (every loopback spelling is
  one host; names are resolved), and inspect-mcp refuses to send to any
  origin in `MANDU_MODEL_PROXY_URL` or the forwarder's.
- **`MANDU_ULLM_BASE_URL` is not a declaration.** It selects the default
  helper's transport, which stays external unless its origin equals a
  declared `local: true` entry. A declared endpoint is dialed directly, so
  the forwarder never becomes a way to reach a model without declaring it.
- **`token_env`.** The token never goes in `policy.yaml`; the validator
  refuses a value that is not a variable name. The arbiter registers every
  declared `token_env` name as an environment secret bound to the hosts of
  the entries that name it (`modelTokenBindings`), so the agent's
  environment holds only its symbol; the launcher writes the real value into
  the inspect-mcp entry's own environment, for `local: true` entries only
  (`localModelTokens`). Residue, the same as the helper's own API key: the
  value sits in the helper's config, which a program in the agent's world
  can read; it is a registered secret, so it reaches no model raw. Pinned by
  `tests/stack/model-token-env.test.ts`.

#### D3. Where a `local-model` datum may go, per surface

| Surface | `no-model` | `local-model` | `any-model` |
|---|---|---|---|
| Model-context ingress (both proxies) | symbolize, `nomodel_` | symbolize, `localmodel_` | symbolize, `anymodel_` |
| Rung 2, `inspect_symbol` (the helper) | refused | **admitted only at a `local: true` endpoint**; refused at an external one, the default helper included | admitted at any endpoint |
| Rung 3, `declassify_symbol` (into the T-LLM's context) | refused, no approval path | **refused unless the session's main model is a declared local endpoint** (§1.7.1); then as `any-model`: logged, approval when the session is untrusted-tainted, watermark at `local-model` | allowed and logged; approval only when the session is untrusted-tainted (§9 rule 2 of confidentiality.md); watermark |
| Network egress | bound destinations only | same | same |
| Readers, output rules, exec withholding, derived-file labels | plan 10 | unchanged (one more value in the same fold) | unchanged |
| Reply filter (the human) | original | original | original |

- **The rung-2 result inherits `local-model`.** "Summarize contract.md" ends
  with the local model having read the contract, the T-LLM holding
  `$MDU:localmodel_inspect[…]`, and the human reading the summary in the
  terminal. Neither reaches the external vendor.
- **Nesting follows admission.** Inside a quarantined resolve, a nested
  symbol is expanded only if *its* level is admitted at *this* endpoint: a
  `local-model` token inside an `any-model` file stays opaque at the
  external helper and expands at the local one. Rung 3 follows the same
  rule (§1.6): a nested symbol opens into the T-LLM's context only when its
  own rung-3 decision allows it, and each one opened raises the watermark.

#### D4. The arbiter decides per endpoint; the client names the endpoint

`resolve(deep)` carries `endpoint: <name>`. The arbiter looks the name up in
its own registry, derives the location (`external` when absent or
undeclared) and admits by one pure function in
`arbiter/symbol-table/confidentiality.ts`:

```ts
admits(location, level):
  public       → true
  any-model    → true
  local-model  → location === "local"
  no-model     → false
```

A `deep` resolve with no `endpoint` is external. `decideDeclassify` (rung 3)
takes the session's T-LLM location the same way and refuses `local-model`
under an external one with a by-design message.

The arbiter cannot see where `inspect-mcp` sends the bytes it returns;
`inspect-mcp` is in the trusted base for that reason. What changes is that
its promise is now per endpoint, and the parity e2e asserts it on real
wires (§1.4).

#### D5. `inspect-mcp` routes each call to an endpoint

- **Selection.** Any `localmodel_` input routes the whole call to the
  helper's model: the `local: true` entry marked `helper: true`, else the
  first `local: true` entry (`helperEndpoint` in `inspect-symbol.ts`);
  otherwise the default helper. Multi-input stays all-or-nothing: mixing
  `local-model` and `any-model` inputs sends all of them to the local
  endpoint, which `any-model` permits. `helper: true` is admitted on at most
  one entry, and only a `local: true` one; Settings moves the mark in one
  approved change.
- **An entry's url may end in `/v1`.** The clients drop one trailing `/v1`
  before adding the API path (`endpointApiBase` in `ullm-config.ts`), so one
  entry can serve both a Codex main model and the helper.
- **No local endpoint declared** while a `localmodel_` input is present:
  refuse before any resolve, with a by-design message ("readable only by
  your own model and none is declared; route the symbol instead, do not
  retry").
- **Endpoint list source.** `inspect-mcp` reads the declared endpoints from
  the arbiter (the `modelEndpoints` op), never from its own environment.
- **The loopback refusal stays** and accepts, besides the forwarder, the
  declared endpoints the arbiter returned, minus any matching the proxy or
  forwarder address.
- **A second client**, `OpenAiChatUllmClient`, for `wire: openai-chat`: one
  `POST …/v1/chat/completions` with the fixed quarantine system prompt and a
  single user turn, no tools, no history. Ollama, vLLM, TGI, SGLang, NIM and
  LiteLLM speak it. No triage call runs at a `local: true` endpoint (a small
  local model's triage verdict made the main model abandon correct answers;
  §1.8 item 1).
- **Errors never quote a response body**, because error strings reach the
  T-LLM and a server that echoes its request would return the bytes. A
  failing declared endpoint (refused connection, timeout, error status, bad
  JSON) refuses with its own by-design text and never falls back to the
  default helper; `MANDU_ULLM_ENDPOINT_TIMEOUT_MS` bounds the wait (§1.8
  item 4).
- **Network confine.** The launcher adds only the helper's entry's port,
  pinned to its host, to the agent world's TCP set (`landlock-net.ts`,
  `net-guard-law.ts`; `helperEndpointPorts`). A declared external endpoint
  gets nothing: inspect-mcp never dials one. `inspect-mcp` itself runs under
  a nested Landlock TCP ruleset of only the forwarder port (or 443) and that
  entry's port (§1.8 item 5). If the arbiter does not answer at launch, no
  endpoint port is added and inspect-mcp refuses on its own.
- **The guard's secret index carries the real level**, so the guard's
  `[mandu:secret]` note and the events name `local-model` where the user
  wrote it. The open decision does not depend on the level.

#### D6. What the operator sees

- **`mandu doctor`:** one row per declared model (name, address, wire,
  reachable, whether the named model is listed at `/v1/models`, cloud-backed
  models a local server offers), placement grading for a model on another
  machine (§2.2 D6), and, when files are labeled `local-model` but no
  `local: true` entry exists, "read by no model until you declare your own
  model". That row also names labels made on the Rules page or by an import
  (the arbiter's `pathLabels` op), which a scan of the policy file cannot see.
- **Dashboard:** the Rules page's level choice "Secret, your own models
  only", offered when a local endpoint is declared; Settings › Models lists,
  adds, edits, removes and tests entries (§1.7.3;
  [`dashboard.md`](../ui/dashboard.md) §4.25l).
- **Events:** the `ullm_call` event carries `endpoint = {name, location,
  placement}`, so the lineage view shows which model read a datum.

#### D7. The handling prompt teaches the third move

Beside `nomodel_` ("route it, no model reads it") and `anymodel_` ("prefer
`inspect_symbol`; `declassify_symbol` only when you must act on it"):
`localmodel_` is "readable only by the user's own model: `inspect_symbol`
routes there by itself; `declassify_symbol` is refused" — or, in a session
whose main model is a declared local one, that `declassify_symbol` works for
the level (still after `inspect_symbol`). Rendered only when the
confidentiality axis is ON and an inspect tool exists.

#### D8. "Block this one program" is answered by the allow-list

A file that names `readers:` gives every other program `EACCES` (or the
placeholder under `others: twin`). A denylist ("these programs may not,
everyone else gets the bytes") is the fail-open reading of the same wish and
is not added. "Block `curl` from `.env`" is written as the readers `.env`
does have ([`usage.md`](../../usage.md)).

### 1.3 What is not claimed

- **What the declared server does with the bytes.** A `local: true` endpoint
  is a cleared reader in the sense a plan 10 reader program is: Mandu
  confines what reaches it and what comes back (a labeled symbol), not the
  server's own behavior. A server that logs to a cloud service, or forwards
  (a LiteLLM route, an alias of a cloud model), is the operator's claim.
- **Injection through the local model.** A local model in the helper role
  sees untrusted bytes and returns a symbol; a weaker model is likelier to
  be steered, and its steering has nowhere new to go.
- **Main models outside one shape.** The main model counts as local only
  when the agent is pointed at a declared entry through its own base URL
  (§1.7.1, §1.7.2). Every other main model, an undeclared base URL included,
  is external toward `local-model`.

### 1.4 Tests

Pure decisions under unit tests, the wiring under e2e over the real
components, the live check gated behind an environment variable. Every suite
states its axes.

| Layer | Test | Asserts |
|---|---|---|
| arbiter unit | `confidentiality.test.ts` | the 4-level lattice, parse (unknown ⇒ `no-model`), `admits` as a 4×3 table plus undeclared |
| arbiter unit | `symbol-format-level.test.ts` | `localmodel_` minted, reserved, mapped back |
| arbiter unit | `policy-file-validate.test.ts` | the `models:` schema, `level: local-model` |
| arbiter unit | `session-watermark.test.ts` | rung 3: `local-model` refused under an external main model, admitted with watermark under a local one |
| arbiter e2e | `cleared-model-endpoints.test.ts` | `resolve(deep)` over a real `ArbiterServer`: refused with no endpoint and at an external one, admitted at a local one; nesting follows admission; after a hot reload that withdraws `local: true`, renames or removes the entry, the old name is refused |
| inspect-mcp unit | `quarantined-read-levels.test.ts`, `openai-chat-ullm-client.test.ts`, `local-endpoint-unreachable.test.ts` | routing, the by-design refusal, the second client's request shape (no history, no tools), every failure refuses without quoting a body |
| integration e2e | `tests/stack/cleared-endpoint-parity.test.ts` | production wiring, two mock endpoints: a `local-model` file's bytes appear on the local wire and never on the external one or the T-LLM wire; the result is `localmodel_` |
| integration e2e | `cleared-endpoint-hot-reload.test.ts` | after an edit that withdraws `local: true`, an earlier `localmodel_` symbol is refused, the endpoint sees nothing, the default helper sees nothing |
| sandbox | `endpoint-added-mid-session.test.ts`, launcher `inspect-mcp-confine.test.ts` | an endpoint declared after launch is refused in-kernel (`EACCES`), nothing moves to the default helper |
| integration e2e | `confidentiality-oracle.test.ts`, `labeled-document-use-cases.test.ts` | the `local-model` rows (× trusted/untrusted × declared/undeclared); use cases 3 and 4 |
| launcher unit | `landlock-net`, `net-guard`, `net-guard-law`, `inspect-net-confine`, `model-endpoints`, `doctor-models` | only the helper's port, pinned; the proxy/forwarder refusal; doctor rows |
| live (gated) | `tests/env/local-model.test.ts` (`MANDU_LIVE_LOCAL_MODEL=1 npm run test:env:local-model` in `tests/`) | the real launcher around `claude -p` against a local Ollama, with recording relays on the vendor wire, the default-helper wire and the declared model: a `local-model` document with a canary and an injection, committed with an uncommitted edit, is summarized; verdict in `tests/lib/local-model-oracle.ts`. Passing in `secrets` and `full` (§1.8 item 1) |
| live (gated) | `tests/env/ollama-doctor.test.ts` (`MANDU_LIVE_OLLAMA=1`) | doctor's real probe against a local Ollama |
| drill (replay, and live on the host's Ollama) | the demo drill `demo-local-health-summary` (2026-10-16) | use case 3 through each agent's real CLI under the launcher: a `local-model` blood-test report summarised through `inspect_symbol` at the declared model; the cloud model never reads a distinctive line, the local model's wire carries the report and the default helper's does not; the plain agent (the control) sends the report to the cloud model. In a replay the declared model is a recording stub at the drill's `<LOCAL_MODEL>` url |

### 1.5 Phasing

Phase 0 (the level, `admits`, the schema, the markers) carried the whole
security content; phases 1 and 2 (routing, the second client, doctor,
dashboard, events) were the product; phase 3, the main model as a declared
endpoint, is §1.7.1.

### 1.6 Rung 3 completes (five fixes found on the way)

Two defects in the existing rung 3, both failing toward the symbol (utility
gaps, not leaks), fixed 2026-09-27:

- **A declassified result was re-symbolized.** With the integrity axis on,
  the `declassify_symbol` result fell under the generic `mcp__*` ⇒
  UNTRUSTED inbound rule, so the model received a symbol instead of the
  content the arbiter had just released. The arbiter now records each
  release per session (symbol → value, in memory), and `classify` trusts a
  `declassify_symbol` result only when it is exactly that value for that
  session: the Mandu tool by exact name, the whole result, the symbol named
  in the tool's own input, the value alone or after inspect-mcp's one-line
  notice. Anything else keeps the policy's verdict.
- **An approved read could not complete.** The retry queued the same
  question again. The handler now consults the human verdict
  (`consultPriorVerdict`) when approval is what stands in the way: approved
  completes the read (a `once` answer is spent), declined refuses without
  asking again.

Pinned by `arbiter/test/component/rung3-completes.test.ts` and
`tests/stack/rung3-through-proxy.test.ts` (production proxy wiring, both
modes, with look-alike controls).

A third, the confidentiality-axis twin of the first, fixed 2026-10-04 (found
by the live drill `conf-derived-label-next-session`, run 2026-10-03, in
`secrets`):

- **A declassified read released a symbol.** The launcher registers a
  labeled file, the agent Reads its AgentView twin (whose bytes are the
  registered row's token), and the proxy symbolizes that Read result again,
  so the symbol the model holds stands for another symbol. `declassifySymbol`
  resolved one level, so the model received the banner and then the inner
  `$MDU:anymodel_Read[…]`: a granted read gave it nothing (the terminal
  still showed the text, through the reply filter, which is why
  `conf-declassify-confines-session`'s terminal check passed). The release
  now resolves nested symbols, and nesting follows admission as for rung 2
  (D3): a nested symbol opens only when its own rung-3 decision in this
  session allows it (its level admits this T-LLM, its integrity is trusted,
  the session needs no approval for it); a `no-model` token, an untrusted
  one, or a `local-model` one under an external model stays opaque. Each
  one opened raises the session's watermark with its level and bindings
  before the value is handed over, and the reported watermark is the
  highest. In an untrusted-tainted session (integrity axis on) a nested
  symbol the human did not approve stays opaque, even when its wrapper was
  approved. The released value is what the session's grant records, so the
  integrity-axis trust rule above matches it unchanged.

Pinned by `arbiter/test/component/rung3-nested.test.ts` (double-wrapped
release, nested `no-model` and untrusted tokens left opaque, the
bindings intersection of two opened files) and
`tests/stack/rung3-nested-through-proxy.test.ts` (production proxy and
inspect-mcp wiring, `secrets`: the cleared model of the session reads the
file; another session's Read is still a symbol; the session's egress to an
unbound host asks and the tripwire catches the text).

Two more, the same drill again, fixed 2026-10-18 (the nightly of 2026-10-17
replayed it red on every agent that mounts the tool):

- **A declassified read was masked by its own input.** `declassify_symbol`
  is a tool no session spec maps, so every string of its input is read for
  a labelled path (plan 10 §11.11). The model's `reason` names the file it
  is declassifying ("loading content from memo/brief.md"), and since the
  label-root text scan of 2026-10-17 a relative mention matches a label
  wherever the call runs. The released value was classified at the file's
  level and masked again, so the model got a fresh token. `classify` now
  gives the exact grant (the match above, on either axis) a `public` level
  at the model door: the session's watermark already holds the file's level
  and bindings. A result that is not exactly the grant keeps the raise, and
  the value backstop still skips Mandu's own quarantine tools.
- **On Claude Code the grant never matched.** Claude Code appends its
  token-budget reminder to every tool_result, and the whole result is
  classified with it, so "exactly the value" failed. With the integrity
  axis on, the proxy's split of a trailing reminder re-asked for the body
  alone and the body matched. With a raised level that split is never
  tried, because a secret body is never forwarded raw. The match now sees
  past a tail that is exactly the budget shape
  (`claude-code-inbound.ts withoutHarnessBudgetTail`, the same digits-only
  shape the inbound policy trusts) and nothing else.

Pinned by `rung3-nested.test.ts` (the grant with a relative and an
absolute mention is released, with or without the budget tail; another
session, another symbol, appended or prefixed text, any other tail and a
look-alike tool keep the raise), `tests/stack/declassify-agents.test.ts`
(OpenCode and OpenClaw through the production proxy: the grant reaches the
model, a padded result is masked) and
`tests/stack/rung3-nested-through-proxy.test.ts` (Claude Code's shape, the
budget tail included: the grant reaches the model, a padded tail does not).

### 1.7 As built

| Piece | Where |
|---|---|
| Lattice, `admits`, `confidentialityRank` | `arbiter/symbol-table/confidentiality.ts` |
| Marker `localmodel_`, reserved prefixes | `arbiter/symbol-table/symbol-format.ts`; fs-sync's copy in `fs-sync/src/arbiter-client.ts` |
| `models:` schema, compile, `modelLocation` | `policy-file-validate.ts` (`checkModels`), `load-policy.ts`, `compiled-policy.ts` |
| `resolve(deep, endpoint)`, `modelEndpoints` op | `arbiter/ipc/server.ts`, `protocol.ts`, `client.ts` |
| Rung 3 refusal, watermark at the datum's level | `arbiter/policy/declassify.ts` |
| Handling prompt block | `arbiter/symbol-table/handling-prompt.ts` |
| Routing, `OpenAiChatUllmClient`, endpoint guard | `interceptors/inspect-mcp/src/inspect-symbol.ts`, `ullm-client.ts`, `ullm-config.ts` |
| Confine ports, launch refusals, guard index level, doctor rows | `launcher/src/model-endpoints.ts`, `landlock-net-setup.ts`, `net-guard-setup.ts`, `secret-setup.ts`, `doctor.ts` |
| Level choice, Settings › Models | `dashboard/src/view-model/model-endpoints.ts`, `dashboard.md` §4.25l |

#### 1.7.1 The main model as a declared endpoint (Claude Code)

**Why.** A user-set `ANTHROPIC_BASE_URL` makes the launcher point the agent
straight at it and skip the model proxy ("the user brings their own
endpoint"), so a Claude Code pointed at a local model would run with no
symbolization at all. For a declared endpoint the proxy now stays.

**Selection.** The main model is a declared endpoint in exactly one shape:
an Anthropic-wire target launched with a user-set `ANTHROPIC_BASE_URL`
equal to a `models:` entry with `wire: anthropic` (scheme, host, port and
path compared after normalization; a query or fragment never matches). The
launcher keeps the model proxy, gives it that URL as its upstream
(`MANDU_UPSTREAM`; a declared `localhost` becomes `127.0.0.1`, because the
proxy speaks plain http only to a literal loopback address) and points the
agent at the proxy. A plain-http entry on another machine refuses the
launch. An **undeclared** base URL keeps the skip, with a `WARNING` at every
launch (`undeclaredBaseUrlWarning`), a `mandu doctor` row and a limit stated
in [`guarantees.md`](../../guarantees.md): refusing the launch or proxying
every user-set URL were the alternatives, and the warning keeps an
existing setup working while saying it is unprotected.

**The binding.** Before starting any service the launcher records the
session's main model with the arbiter: `setSessionUpstream {sessionKey,
endpoint: <name> | null}` (null = the agent's default vendor). The arbiter
stores the name, never the location (`arbiter/policy/session-upstreams.ts`,
table `session_upstreams`), and derives the location from the law in force
at each decision, so a policy edit that drops `local: true` closes rung 3
for running sessions too. The op is data-plane, so a process inside the
agent can call it, and a forged "my main model is local" would let a
`local-model` datum into an outside vendor's context. Three rules close
that:

- **bind-once**: the first binding wins; the same one again is a no-op; a
  different one is refused;
- **refused after traffic**: a session that has classified traffic or holds
  a watermark cannot be bound, and the launcher binds before any service
  starts, so a late first binding is never the launcher's;
- **persisted**: the row survives an arbiter restart.

The launcher binds `null` for every session it does not route to a declared
model, so the first binding of every launched session is the launcher's. A
session no launcher started is unbound and reads as external.

**Rung 3 and the prompt.** `decideDeclassify` receives the session's
location (`tllmLocationOf`); a `local-model` datum under a local main model
follows the `any-model` path. The proxy sends its session key with the
`handlingPrompt` request so the `localmodel_` block can say which applies.

Pinned by `arbiter/test/unit/session-upstreams.test.ts`,
`arbiter/test/component/session-upstream.test.ts`, the launcher's
`run.test.ts`, `tests/stack/local-main-model.test.ts`, and live by
`tests/env/local-main-model.test.ts` (`MANDU_LIVE_LOCAL_MAIN_MODEL=1`: the
real launcher and `claude -p` against a declared `wire: anthropic` entry in
front of a local Ollama; the session bound `local`, the vendor trap saw
nothing, the subscription token was on no wire).

#### 1.7.2 The same for Codex

- **Which entry.** `MANDU_OPENAI_BASE_URL` is matched by the same
  normalized equality against `wire: openai-chat` entries only
  (`selectTllmEndpoint(url, endpoints, "openai")`). No new wire: an
  OpenAI-compatible server serves Chat Completions (the helper's wire) and
  Responses (Codex's) under one base URL, and `local` is a claim about the
  server, not the API. A server without `/v1/responses` fails the request
  upstream, and nothing leaks.
- **The proxy.** The openai-proxy starts with the entry as `MANDU_UPSTREAM`,
  `MANDU_UPSTREAM_IS_BASE_URL=1` and `MANDU_UPSTREAM_LOCAL`; with base-URL
  semantics it replaces the request path's leading `/v1` with the entry's
  path (`upstreamRequestPath`). A `local: true` upstream refuses a
  cloud-backed model with a 400 before any arbiter call
  (`interceptors/openai-proxy/src/cloud-model.ts`, §1.8 item 3).
- **The prompt** names the session on `handlingPrompt`, as for Claude Code.
- **Refusals and warnings** name the Codex knob: plain http off this machine
  refuses the launch, an undeclared URL keeps the skip with a `WARNING`
  naming `MANDU_OPENAI_BASE_URL`, `mandu doctor` has a row, and the
  `codex --oss` / `--local-provider` refusal points at the declared route.
- **Arbiter:** unchanged (the binding is by entry name).

Pinned by the launcher's `run.test.ts`, `model-endpoints.test.ts` and
`doctor-models.test.ts`; openai-proxy `upstream-transport`,
`rewrite-request`, `cloud-model` and `local-main-model-upstream` tests;
`tests/stack/local-main-model-codex.test.ts` (including an external Codex
main model receiving the document only as `$MDU:localmodel_…`) and
`cloud-model-parity.test.ts`. A live Codex run against a local server is
not written yet; every wire in the Codex path is exercised over real
sockets.

#### 1.7.3 Dashboard editing

Settings › Models adds, edits, removes and tests an entry
([`dashboard.md`](../ui/dashboard.md) §4.25l).

- **One grammar.** The ops `add-model`, `update-model` (replaces the named
  entry whole), `remove-model` and `restore-model` join the policy edit
  grammar ([`policy-surface.md §8`](../ui/policy-surface.md) §4.1)
  and are checked only by `checkModels` on the result, so every rule holds
  for an edit as for a hand-written file. Only Settings › Models sends them:
  the agent's policy tool and the Describe box are neither offered nor
  allowed them (the arbiter refuses a model op from the data plane and from
  `requestedBy: "assistant"`, fail-closed; §4.3a there). They can still read
  the declared models.
- **Every change is a relaxation.** An added or edited `local: true` entry
  opens `local-model` reads to its address; a removed entry can leave a
  user-set base URL undeclared, which skips the proxy at the next launch. So
  the delta has no tightening form for `models`: the dashboard applies after
  the person's confirm, with a warning when a `local: true` address is not
  on this machine or a local network.
- **An update names the entry as it was read (2026-10-18).** The form is
  filled from the list the page read, and `update-model` replaces the entry
  whole, carrying over what the form does not edit (`tls`, and the fields
  of an entry whose helper mark moves). So the save sends the entry's
  version (the snapshot's `modelVersions`, a keyed hash of the entry,
  [`policy-surface.md`](../ui/policy-surface.md) §8.4.6 "An item-level
  version"), and the arbiter refuses it, nothing written, once that entry
  changed since; a change to another entry does not refuse it. Before it, a
  change to the same entry landing between the page's read and the save
  (a hand edit, another tab) was overwritten with what was read before it.
  The preview gate still judges every loosening.
- **Test connection** runs doctor's checks by entry name, with the
  `token_env` value read server-side for the listing only; a parity test
  pins it to doctor.
- **Launch-time pieces stay launch-time.** The arbiter hot-reloads the list,
  but a running session's confine ports and main-model binding do not move;
  the page says a running agent needs a restart.
- **Main model shown.** The agent page names the session's main model when
  it is bound to a declared entry.

### 1.8 Closed items and residues

A survey of model-routing products found none that ships this level's
combination, and five things this design had to prove or close. All are
closed.

| # | Item | As built |
|---|---|---|
| 1 | **Every channel asserted together.** Output-only audits miss a large share of violations (AgentLeak reports 41.7 %), so the live drill checks the vendor wire, the default-helper wire, the events, exec output (`git diff` / `git show` of the committed document and its older version), derived files and an injection inside the document, in one run. | `tests/env/local-model.test.ts`, passing in `secrets` and `full`, with the `any-model` control through the default helper. The drill found two defects, both fixed: a small local model's triage verdict made the main model abandon correct answers (no triage at a `local: true` endpoint now), and a labeled file committed to git reached the model through `git diff` (fixed by the arbiter's value backstop, `arbiter/policy/egress-fingerprint.ts`). The raw bytes in git objects are now hidden from the agent by the object-store twins ([`confidentiality.md`](./confidentiality.md) §7.2a, which lists what remains); the drill's transcript check is hard (`agent-transcript-canary-absent`). |
| 2 | **A user-set base URL skipped the proxy.** | A declared model keeps the proxy (§1.7.1); an undeclared one warns at every launch, in doctor and in `guarantees.md`. |
| 3 | **Cloud-backed "local" models.** Ollama serves `<model>:cloud` tags from ollama.com behind the same loopback API, so a correctly declared `local: true` endpoint can still send the bytes off the host. | One pure predicate, `isCloudBackedModel` (`arbiter/policy/cloud-model.ts`: `cloud` as a `-`/`_`/`.` word of the tag or at the end of the name, case-insensitive, `@digest` ignored), mirrored in the launcher and both model proxies and pinned to one table by `tests/stack/cloud-model-parity.test.ts`. Policy load refuses a `local: true` entry naming one (a hot reload keeps the law in force); the launch refuses it (`CloudLocalModelError`); with a declared local main model the proxy answers a request for a cloud model with a 400 `invalid_request_error` before any arbiter call (400 because Claude Code retries a 5xx); doctor marks it ✗ and lists the cloud models a local server offers. **Residue by design:** a name without the word is not proven local (a server can alias any name); `local: true` remains the operator's claim. The hardening checklist (loopback bind, single user, no history, no telemetry, no cloud models) is in `guarantees.md` §3. |
| 4 | **A declared endpoint that fails must refuse.** The shipped routers' documented defaults are fail-open (`on_error: allow`). | §1.2 D5: refuse with the endpoint's own text, never route to the default helper; `test/unit/local-endpoint-unreachable.test.ts` and the real-socket legs of `test/component/local-endpoint-routing.test.ts`. |
| 5 | **"Bytes go only to the declared endpoint" enforced by the kernel**, not only by `assertNonProxyBaseUrl`. | The launcher wraps the inspect-mcp server command in `mandu-landlock-apply --net-only`: CONNECT only to the forwarder's port (else 443) and the helper's entry's port, never the model proxy, the egress proxy or 22; probe-gated, and strict once the probe passed (no `--skip-unsupported`: a wrong probe answer, a kept one included, stops inspect-mcp at the applier with exit 71 instead of running it unconfined; packaging.md §5.4), `--no-landlock-net` opts out; every writer of the MCP entry carries it (MCP config, Codex splice, OpenCode config). The connect guard performs every allowed connect itself and so bypassed a nested Landlock TCP ruleset; it now runs those connects on a mirror of the tracee's nested layers (`launcher/src/inspect-net-confine.ts`, `net-supervisor/src/landlock_mirror.rs`; pinned by the launcher `inspect-mcp-confine` e2e and `guard_integration.rs`). |

**Two directions for later designs.**

- **The routing key is provenance, not content.** A per-request content
  "sensitivity router" leaks on "no PII ⇒ not sensitive" and fails open by
  default. This level routes by where the bytes came from, decided once per
  file and followed through copies (plan 10), with the unknown case strict.
  Automation belongs in a labeling pipeline that only proposes labels for a
  human to approve: a classifier proposes, policy enforces, and a false
  negative costs a missed proposal, never a leak
  ([`confidentiality-plan-14-policy-suggestions.md`](./confidentiality-plan-14-policy-suggestions.md)
  phase 4).
- **Utility on a labeled file is capped by the architecture.** The local
  model here is a one-shot reader (the bytes, a task, no tools, no history)
  and the T-LLM orchestrates blind: enough for summarize, extract, answer,
  classify and a report the human reads, not for "edit the private module".
  What would move that is a confined sub-agent in the local model's role,
  with tools over the labeled files (AgentView filesystem, no network) and
  only its symbolized outcome returned to the T-LLM. A utility table at
  several local model sizes, against both the unprotected frontier model and
  `no-model`, is the number to publish before any claim about it.

### 1.9 A slow local model and the agents' MCP limits (2026-10-17)

**The gap.** Claude Code moves an MCP tool call that is still running
after 120 s to the background in an interactive session: the model gets
"MCP tool … is still running after 120s. It was moved to the background
as task …" as the tool result, and the real answer arrives later as a
task notification. `inspect_symbol` at a local model on a CPU runs about
that long. In the second live demo battery (Claude Code 2.1.295, the
blood-test demo at qwen2.5:32b) the calls took 89 s and 102 s, and the
take whose call ran past 120 s ended its turn with "the summary is still
being generated"; the user saw no summary in that turn.

**The knob.** The window is the environment variable
`CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS` (milliseconds; 0 turns the
auto-background off). Read off the Claude Code binary (2.1.295, the CI
pin, and 2.1.302: the variable overrides the 120 s default, capped only
by the timer maximum) and measured on both with a stand-in MCP tool that
answers after 5 s: at 1500 ms the model gets the "moved to the
background" text, at 60000 ms it gets the answer. `claude -p` has no
auto-background unless `CLAUDE_AUTO_BACKGROUND_TASKS` is set; the TUI has
it on.

**The same class on the other agents.** The live demo runs on Codex and
OpenCode lost the summary the same way, at a different limit each:

- *Codex*: "your declared model 'drill-local' did not answer (U-LLM request
  timed out after 60000ms)". Codex hands a stdio MCP server only the env in
  its entry, and the `mandu-inspect` entry carried no
  `MANDU_ULLM_ENDPOINT_TIMEOUT_MS`, so inspect-mcp kept its 60 s; Codex's
  own per-call limit (`tool_timeout_sec`, 60 s by default) would have cut a
  longer wait anyway.
- *OpenCode*: "MCP error -32001: Request timed out". The launcher gave every
  OpenCode MCP server 30 s, and OpenCode's server timeout bounds each tool
  call.

**The U-LLM timeout** (`launcher/src/ullm-timeout.ts`). The launcher decides
one per launch: the user's `MANDU_ULLM_ENDPOINT_TIMEOUT_MS` when valid (read
with inspect-mcp's own rule: a positive integer of milliseconds, at most
10 min), else 240 s when `models:` declare a `local: true` endpoint (a cold
32B load on a CPU took about 200 s), else none (inspect-mcp's 60 s, the
entry as before). It goes into the `mandu-inspect` entry every agent gets,
so Codex and Goose hand it to the server too. The longest one
`inspect_symbol` call can take is then twice that (the summary and at most
one retry; no triage runs at a local endpoint, §1.8 item 1) plus 60 s,
and each agent's limit for that server alone is raised to it: Codex's
`mcp_servers.mandu-inspect.tool_timeout_sec` (whole seconds), OpenCode's
`timeout` (V1) or `timeout.execution` (V2), never under the 30 s cold-start
bound. A longer timeout only waits longer: a timeout is a refusal, never a
fallback to another model.

**The rule for Claude Code** (`launcher/src/claude-mcp-background.ts`). A
Claude Code launch whose `models:` declare a `local: true` endpoint sets
`CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS` in the agent's environment to that
bound: 540 s with the local default, 13 min at the demo's 6 min timeout.
The launch says so in one line. A value the user set stands, larger,
smaller or 0: the launcher only fills an unset variable, and Claude Code
applies a settings file's `env` block over its environment, so a value
set there wins too. Launches without a local model get no window. The
window is the session's, so the user's other MCP servers get
it as well; it only decides when a long call is moved to the background.

**Why it is safe.** Utility only: each limit decides whether the answer
reaches the model in the same turn (or at all), and the answer is the same
re-symbolized result either way; nothing about what the model may read
changes.

**Tests.** `launcher/test/unit/ullm-timeout.test.ts` (the U-LLM timeout,
the entry's env, Codex's and OpenCode's limits in both spellings),
`launcher/test/unit/claude-mcp-background.test.ts` (the window, the user's
value kept, which launches get it); the drill suite's
`codex-mcp-tool-timeout` (the real `codex exec` under the production
overrides: a 65 s call answers past Codex's 60 s default and the server
saw the entry's 240 s; a 2 s `tool_timeout_sec` cuts a 5 s call) and
`opencode-mcp-timeout` (the real `opencode run` with the production entry:
a 35 s call answers; without a U-LLM timeout the 30 s cuts it, the demo's
-32001), both with the stand-in tool as `inspect_symbol`; and the drill
suite's
`claude-mcp-auto-background` (the real launcher and `claude -p` against a
scripted model, with the user's own `--mcp-config` naming the stand-in
tool, `tests/lib/slow-mcp-server.mjs`: with a local model declared the
answer is the tool result of the same turn; the user's own 1500 ms
stands, and the same call is moved to the background; no local model,
nothing set). Passing on 2.1.295 and 2.1.302.

## 2. Models on the organization's network

In an organization, the model that may read a `local-model` file is usually
an open-weight model served by vLLM, TGI, SGLang, NIM or a LiteLLM gateway
on the internal network, not a model on the user's own computer. Part 2
makes such an endpoint as trustworthy a destination as a loopback one: the
bytes never cross a network in the clear unless the operator says so for
one entry, the endpoint's identity is checked by more than DNS, its address
can be held to the organization's own networks, and the organization can
own the list so that neither a user nor an injected agent can widen it.

### 2.1 The gap

Part 1 already let the operator declare a model on another machine:
`local: true` is a declaration never inferred from the address, the network
confine pins the helper's non-loopback host as written
(`helperEndpointGuardSpecs`), the `openai-chat` wire is what internal model
servers speak, `token_env` carries a gateway's token, and a declared main
model may be on another machine over `https`. What had been designed around
"the model runs on this computer":

| # | Finding | Kind |
|---|---|---|
| F1 | **The helper sent `local-model` bytes over plain http to a remote host**, while the main-model path refused the same URL (plain http only to a literal loopback address). The two roles disagreed about the same entry. | security, fixed first |
| F2 | **A remote endpoint's identity rested on DNS plus the default trust store.** On loopback the kernel guarantees who answers; over a network nothing pinned the server's key, there was no per-endpoint CA for an internal PKI and no client certificate for a mutual-TLS gateway. The connect guard resolves a host rule at each connect, so its pin follows whatever DNS says. | security |
| F3 | **The declaration was the user's.** When the organization's data is at stake, nothing let it own the list. | enterprise |
| F4 | **The words said "this computer"** ("one you run yourself", "a computer you control", "would leave this machine"), which an employee whose company runs the model reads as "not my case". | product copy |
| F5 | **Doctor distrusted every DNS name**, yet an internal endpoint is almost always a name; it never resolved the name. | operator UX |
| F6 | **A corporate CA was lost under TLS inspection.** With the egress proxy's inspection on, `mitmTrustEnv` set `NODE_EXTRA_CA_CERTS` to the session CA alone and `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`, `CARGO_HTTP_CAINFO`, `AWS_CA_BUNDLE`, `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE` and `CURL_CA_BUNDLE` to the system bundle plus the session CA, so a user who had pointed any of them at a corporate CA lost it in the agent's world. Fail-closed (TLS refused), a utility bug, not a leak. | utility |
| F7 | **One added point on the order.** An organization has at least three model principals: an on-prem cluster, a private tenancy at a cloud vendor under zero data retention, and the public vendor API. | design, deferred (D7) |

### 2.2 Decisions

#### D1. `local` means inside the trust boundary; placement is derived, never declared

The location `local` means **a model inside the trust boundary that the
operator, or the organization (D5), declared**; it no longer implies "this
computer". Every endpoint gets a **placement**, derived from its URL
(`endpointPlacement`, `arbiter/policy/model-placement.ts`, mirrored in the
launcher, inspect-mcp and the dashboard and pinned by
`model-placement-parity.test.ts`):

| Placement | When | What proves the destination |
|---|---|---|
| `host` | the host is loopback (`localhost`, `*.localhost`, 127.0.0.0/8, `::1`, the unspecified addresses) | the kernel: only this machine answers |
| `network` | any other host | the transport rules of D2 to D4 |

Placement is computed, not written, because it only ever adds requirements.
`admits` does not change: placement decides **how an endpoint must be
reached**, not **what it may read**.

**Names kept.** `local: true`, `local-model` and `localmodel_` are
redefined, not renamed: the marker is in every stored symbol and the key in
every existing `policy.yaml`. A rename (`internal-model`, `org-model`) would
cost a second vocabulary migration for accuracy alone; it is worth
revisiting together with D7, which would rename the axis anyway.

#### D2. A `network` endpoint is reached over TLS, in both roles

A `local: true` entry with `network` placement must use `https` (closes F1):

- **Policy load** refuses `local: true` + `http:` + a non-loopback host
  (`checkModels`): "`<name>` is on another machine and would receive
  local-model files in the clear; use https, or reach it through a loopback
  tunnel (`ssh -L`)". A hot reload with the refusal keeps the law in force.
- **The helper** refuses the same URL per call before any resolve
  (`assertDeclaredEndpointUrl`), a belt for an older arbiter.
- **The launch** refuses it too (`PlainHttpLocalModelError`).
- **The main model** keeps its hard rule: plain http only to a literal
  loopback address.

**One opt-out, for the helper only.** A lab's model server on a trusted
segment without TLS is a real case, and a tunnel per box pushes operators to
drop `local: true` altogether, so an entry may say so explicitly:

```yaml
models:
  - name: lab-vllm
    url: http://10.0.3.7:8000/v1
    wire: openai-chat
    model: Qwen/Qwen3-32B
    local: true
    allow_plain_http: true   # local-model files cross the network unencrypted
```

- It lets only the quarantined helper send `local-model` bytes to that one
  entry over plain http; a whole conversation is more than one file, so the
  main model keeps the hard rule.
- On an `https:` entry it is refused as meaningless.
- Adding it is a `models` change and so a relaxation a human applies; the
  delta says "files labeled local-model may be sent to it unencrypted".
- It is never quiet: a launch `WARNING`, a ✗-graded doctor row, "Not
  encrypted" in Settings, and the fact on the `ullm_call` event.
- It rides the `modelEndpoints` wire as `allowPlainHttp`, present only when
  true, so an older arbiter that never sends it leaves the helper refusing.

A non-local entry keeps accepting `http:`: nothing Mandu starts dials it.

#### D3. Endpoint identity: per-endpoint CA, key pins, client certificate

A `models:` entry may carry `tls:`, honoured wherever Mandu itself dials the
entry (the helper, the model proxy's upstream for a declared main model,
doctor and Test connection):

```yaml
models:
  - name: corp-vllm
    url: https://llm.ml.corp.example/v1
    wire: openai-chat
    model: Qwen/Qwen3-32B
    local: true
    token_env: CORP_LLM_TOKEN
    tls:
      ca_file: /etc/ssl/corp/root-ca.pem       # trusted for THIS endpoint only
      pin_sha256: [ "<base64 SHA-256 of the server key's SPKI>" ]  # any one matches
      client_cert: ~/.mandu/corp-llm.crt
      client_key: ~/.mandu/corp-llm.key
```

- **`ca_file`** joins the bundled roots for this endpoint's connections
  only, so a corporate root does not become trusted for every host, and the
  helper no longer depends on `NODE_EXTRA_CA_CERTS` (F6).
- **`pin_sha256`**: base64 SHA-256 hashes of the server's
  SubjectPublicKeyInfo (the HPKP format). A chain that validates but carries
  no pinned key is refused. A list, so a planned rotation can name both
  keys.
- **`client_cert` / `client_key`** for a gateway that requires mutual TLS.
  Paths only. The arbiter marks a declared client key `no-model` and
  `discoverSecrets` walks it as a root of its own, so the key file is a
  placeholder in the agent's world wherever it lives; the launcher hands the
  helper the key's bytes (`MANDU_MODEL_CLIENT_KEYS`, `localModelClientKeys`).
  Residue, as for `token_env`: the helper runs in the agent's world, so a
  program there that can read the helper's configuration can find the
  material; it reaches no model raw.
- **Validation.** Each path must exist and parse at load (PEM for the CA and
  certificate, a private key for `client_key`); a pin must decode to 32
  bytes; paths are absolute or start with `~/`; `tls:` on `http:` is refused.
- **One implementation.** The connection-time checks are one module,
  `endpoint-tls.ts`, copied verbatim into inspect-mcp, both model proxies,
  the launcher and the dashboard (`endpoint-tls-parity.test.ts` requires the
  five copies to be byte-identical): the extra CA joins Node's bundled roots
  for that connection, `checkServerIdentity` runs Node's host check and then
  the pins over the whole chain, and the client pair is presented. Node's
  `tls` provides all of it; no new dependency. The helper uses its own https
  agent for such an entry (never the egress proxy); a declared main model's
  `tls` reaches the proxy as `MANDU_UPSTREAM_TLS`, and the proxy refuses to
  start on a setting it cannot use. Under TLS 1.3 a server's refusal of a
  missing client certificate arrives after the client's handshake completes,
  so the doctor probe waits a moment (`settleMs`) before reporting success.
- **The egress proxy is bypassed for these connections.** Node honours
  `HTTPS_PROXY`, and a helper request to a declared model on another machine
  would otherwise go through the egress proxy, which would decrypt the
  `local-model` bytes and dial with its own trust store. The helper's
  `NO_PROXY` names every non-loopback local endpoint whenever the session
  has an egress proxy.

**Not built: a launcher-side endpoint forwarder.** A per-endpoint loopback
relay in the launcher (outside the agent's world, like the helper
forwarder) would hold the token and client key where no agent-world program
can read them and give both roles one TLS path. It costs a new service, a
reserved address per endpoint and a confine rule. It becomes worth building
for a deployment whose key or token authorises more than this one model, or
at the first bug caused by the helper and the proxy checking TLS
differently.

#### D4. `perimeter:` holds a network endpoint to the organization's networks

```yaml
perimeter:
  networks: [ 10.0.0.0/8, 172.16.0.0/12, "fd00:1234::/32" ]
  domains:  [ corp.example ]       # informational: doctor and the dashboard use it
```

- **When `perimeter.networks` is present**, a `local: true` endpoint with
  `network` placement must resolve, **at every connection**, only to
  addresses inside it. `perimeterLookup` (in `endpoint-tls.ts`) resolves
  once with every family, refuses when any address is outside or the answer
  is empty, and hands the connection an address from the checked list, with
  the original name kept as the TLS server name; there is no second lookup
  to race (DNS rebinding). `checkLiteralHost` covers a literal-address host.
  The refusal names the address and the section.
- **At load**, a `local: true` `network` entry whose url is a literal
  address outside the networks is refused (`arbiter/policy/model-perimeter.ts`).
  **At launch**, the launcher resolves each such endpoint and refuses the
  launch on an address outside (`PerimeterLocalModelError`), so the operator
  hears about it before a task fails. Doctor and Test connection grade the
  perimeter from the addresses they resolved and never hand-shake with an
  address outside.
- **When absent**, TLS hostname verification already defeats a spoofed DNS
  answer; the perimeter adds a check of the operator's claim against the
  organization's own boundary (a name that moved to a cloud host, a typo
  that names a public host). It earns most in the administrator's layer
  (D5).
- **The connect guard stays a belt.** Its host rule keeps pinning the name
  per connect and is not widened to the perimeter's networks, which would
  open the endpoint's port to every host in the organization.
- **`domains:` is not enforcement**: a name suffix proves nothing about
  where it resolves. It lets doctor and the dashboard say "on your
  organization's network".
- The arbiter compiles the section onto the endpoints
  (`ModelEndpoint.perimeter` on a `local: true` `network` entry,
  `orgDomain`), so no op changes. The policy delta has a `perimeter` facet:
  dropping the networks or admitting a network outside the old list relaxes;
  adding or narrowing tightens; `domains` changes nothing.

#### D5. The organization can own `models:` and `perimeter:`

A second, read-only policy layer: every `*.yaml` under
`/etc/mandu/policy.d/` (`ADMIN_POLICY_DIR`), read by the arbiter before the
user's `policy.yaml`. The path is a build-time constant, never an
environment variable a session could set; the `ArbiterServer` option
`adminPolicyDir` is the test build's override. An organization's
configuration management installs it; Mandu needs no privilege to read it
([`privilege-model.md`](../architecture/privilege-model.md) §0 is about
what Mandu needs, not how an organization deploys files).

- **What it may set:** `version`, `models:`, `perimeter:` and
  `models_locked: true`. Other sections stay the user's. (Later keys:
  `sensitivity_labels:`, `prompt_filters:`, and `bwrap_path:`, the
  bubblewrap Mandu runs in place of the one on PATH, whose form the arbiter
  checks and which the launcher reads only from root-owned files naming a
  root-owned binary: rootless-confinement-ubuntu-2404.md §0.7.)
- **Reading** (`installAdminLayer`, `arbiter/policy/admin-layer.ts`): files
  in name order, `models` and `perimeter` validated with the user file's own
  rules; a name set twice, a `perimeter` in two files or a `disabled` entry
  is an error (`AdminLayerError`), and a broken layer at start refuses the
  start.
- **Merging** (`effectiveModels`, inside `compilePolicy`, so every compile
  sees it): the administrator's entries first, marked with their file; a
  user entry of the same name replaces one; a user `{ name, disabled: true }`
  removes one.
- **The lock** (`adminLockProblems`, in `validatePolicyDocument`, which
  every writer passes): with `models_locked: true` a user `local: true`
  entry, or a change to an administrator's entry's `url`, `tls`, `local`,
  `helper` or `allow_plain_http`, is refused with "set by your administrator
  (`<file>`)". Removing an administrator's entry (a narrowing) and adding a
  non-local entry (never dialed) are allowed. `models_locked` in the user's
  file is refused.
- **The perimeter is narrow-only, with or without the lock.** It is a fact
  about the organization, not a model default: a user `perimeter.networks`
  must lie inside the administrator's.
- **The administrator wins a conflict, and says so.** The arbiter polls the
  directory's signature (each file's name, size, mtime and inode) and on a
  change reads the layer again and rebuilds the law from the same user
  document (audited as a `policy_change` with `via: "admin"`); a layer that
  cannot be used keeps the one in force and is reported as `admin.refused`.
  A user file that conflicts with a new layer (a lock arrives, the perimeter
  narrows) is not refused: its conflicting entries stay in the file but are
  not in force, and the arbiter, doctor and Settings name them
  (`admin.conflicts`). A start is never refused over a conflict (a fleet
  lock must not stop every user who had a model of their own); a write is
  refused only for a conflict it adds.
- **Every writer honours it.** Settings › Models, a hand edit, a raw
  document apply and an admin-channel proposal all pass the same check. The
  edit grammar: `remove-model` of an administrator's entry writes the
  `disabled` marker, `restore-model` drops it ("Bring back" in Settings),
  `add-model` of its name is refused (use `update-model`, which the lock
  then judges).
- **Wire:** `ModelEndpoint.adminFile` and `locked`; `modelEndpoints` adds
  `admin: { files, locked }`; `policyDocument` adds `admin` with the entries
  as written; the snapshot adds `modelsAdmin`.

**What it does and does not stop.** It stops the user, the policy agent and
an injected agent from widening the list through Mandu's own surfaces. It
does not stop an employee with a shell who runs a modified Mandu or points
the agent past it; that needs a managed device or enforcement at the model
gateway, and is outside this design and outside `guarantees.md`.

**Open and enterprise.** The layered read and the lock serve a single user
too (the policy agent cannot widen a list the user locked) and are in the
open repository. Distribution, signing and fleet reporting of the layer
belong to the enterprise edition ([`licensing.md`](../distribution/licensing.md)).

**Known limit.** An administrator's `tls:` paths starting `~/` expand
against the home of the user running the arbiter; a layer written for many
users should use absolute paths.

#### D6. What the operator and the user see

- **Level choice:** "Secret, your own models only: only models you or your
  organization run, on this computer or on your organization's network, and
  listed in Settings › Models." The dashboard's plain-vocabulary sweep
  checks that "you run yourself" and "computer you control" do not return.
- **Settings › Models:** "Your own model: it runs on this computer, or on a
  server your organization controls." Each row shows its placement ("On
  this computer", or "On your network: `llm.ml.corp.example`, TLS checked
  with your CA, a pinned key and a client certificate"), "only at addresses
  in …" under a perimeter, "Not encrypted" for `allow_plain_http`, and "Set
  by your administrator" with no *Edit* (Remove stays) for an administrator's
  entry, plus the conflicts and the perimeter in force with who set it. The
  form does not edit `tls:` and carries an entry's `tls` through an update.
- **Launch refusals** say "would leave your trust boundary".
- **`mandu doctor`** resolves a name before grading it (`addressReach`,
  mirrored in the dashboard and pinned by `model-probe-parity.test.ts`):

  | Situation | Row |
  |---|---|
  | `host` placement | ✓ on this computer |
  | `network`, https, inside `perimeter` (or, with none, only private or link-local addresses) | ✓ on your network, with the TLS facts |
  | `network`, a public address, no perimeter | · hint: list the network under `perimeter:` if this is a private-link endpoint |
  | `network`, an address outside `perimeter`, or a name that does not resolve | ✗ with the address or "does not resolve here" |
  | `network`, pin not matched or TLS fails | ✗ with the reason (no response body quoted) |
  | `allow_plain_http` | ✗ plain http to another machine, allowed by `allow_plain_http` |
  | the administrator's layer | the files, whether models are locked, one ✗ row per conflict or refused re-read; an administrator's entry says "ask your administrator (`<file>`)" |

- **Events:** `ullm_call`'s `endpoint` carries `placement` and `plainHttp`.

#### D7. Several clearance tiers: the shape, written down, not built

An organization that clears its on-prem cluster for everything and its
private cloud tenancy for personal data but not its most sensitive files
needs more than one point between `any-model` and `no-model`. The shape that
keeps the axis a total order:

```
public ⊑ any-model ⊑ <named tiers, ordered by the policy> ⊑ no-model
models[].clears: <level>          # replaces local: true (local: true ≡ clears: local-model)
admits(endpoint, level) = rank(level) ≤ rank(endpoint.clears)
```

It touches every place that folds levels, the marker set, the handling
prompt, the level choice and the dashboard glossary, which is why it is not
built speculatively. Compartments (per project, per business unit) are a
lattice, not an order, and stay out of scope. It becomes worth building for
a deployment that needs a private-tenancy endpoint cleared for some
`local-model` data and not the rest.

### 2.3 Threats, and which rule answers each

| Attacker capability | Closed by |
|---|---|
| On the LAN path, reads plain http | D2 (both roles, at load, launch and call); **not closed** for an entry marked `allow_plain_http` (helper only, loud everywhere) |
| Spoofs DNS or ARP toward a public-CA https endpoint | TLS hostname verification; D4 if the forged address is outside the perimeter |
| Holds a mis-issued certificate from the internal CA, or the CA itself | D3 `pin_sha256` |
| The declared name moves to a host outside the organization | D4 `perimeter.networks`, at launch and at every connection |
| An injected agent, through the policy agent, declares its own server `local: true` | refused: the policy agent cannot propose model edits (§1.7.3); a human's Settings edit is a relaxation; under `models_locked` the user's own edit is refused too (D5) |
| The declared server itself forwards to a cloud | **not closed**: the operator's claim (§1.3, §1.8 item 3); D5 makes it the organization's claim rather than the user's |
| An employee with a shell runs a modified Mandu | **not closed**: outside the threat model (D5) |

### 2.4 What is not claimed

Everything §1.3 does not claim still holds. In addition:

- **A private address is not proof of anything.** Placement and the
  perimeter check where the bytes are sent, not who operates the machine.
- **The administrator's layer is not tamper-proof** against the local user
  (D5).
- **An `allow_plain_http` entry** sends `local-model` files across the
  network unencrypted, by the operator's explicit choice (D2).
- **Helper credentials are in the agent's world** (D3 residue) until the
  endpoint forwarder is built.

### 2.6 Tests

Every suite states its axes. Pure decisions under unit tests; wiring under
e2e over the real components; the production-wiring parity test for every
new arbiter op or forwarded field ([`CONTRIBUTING.md`](../../../CONTRIBUTING.md),
the arbiter-client pattern). Certificates are minted per run by the openssl
CLI (`tls-fixtures.ts`, self-SKIP without it; no key is committed).

| Layer | Test | Asserts |
|---|---|---|
| arbiter unit | `policy-file-validate` models cases, `model-perimeter.test.ts`, `admin-layer.test.ts` | plain http to a remote `local: true` refused (IPv4, IPv6, name) unless `allow_plain_http`; `tls:` validation; perimeter syntax, the literal refusal and the delta; the administrator's layer: reading, every problem with its file, merge, each lock case, narrow-only perimeter, one helper, `restore-model`, re-read on the poll, tolerate at start and for writes |
| launcher unit | `model-endpoints`, `env-compose`, `doctor-models` | placement for every loopback spelling; the perimeter launch check over a fixture resolver (all inside, one outside, empty answer refused); the user's CA files survive TLS inspection; each doctor row |
| inspect-mcp unit and e2e | endpoint guard, `endpoint-tls`, `local-endpoint-routing` | per-call refusal of plain http before any resolve; an https server with a private CA: no `ca_file` refused with zero document bytes on the wire, `ca_file` served, wrong pin refused, right pin served, mutual TLS without and with `client_cert`; the perimeter lookup |
| both proxies, e2e | `upstream-tls` | a declared main model over https with the same TLS cases and the perimeter (outside by literal or by a name's answer: zero requests) |
| integration e2e | `plain-http-local-endpoint.test.ts`, `model-placement-parity.test.ts`, `endpoint-tls-parity.test.ts`, `tls-endpoint-wiring.test.ts`, `model-probe-parity.test.ts`, `admin-model-layer.test.ts` | the mirrors agree; production wiring of the TLS checks; every reader sees the administrator's layer, the helper uses the administrator's model, Settings and an admin-channel proposal that would break the lock are refused with nothing written, and a lock that arrives under a running arbiter moves the helper with nothing sent to the user's model |
| sandbox | `tests/sandbox/perimeter-netns.test.ts` | two network namespaces joined by a veth pair inside one unprivileged user namespace (`tests/lib/netns.ts`; the peer answers on an inside and an outside address), names from a hosts file in a private mount namespace: a name resolving outside, or with one of two addresses outside, is refused by the launch check, the helper and the model proxy with zero requests, and the peer's log shows every request on the inside address |
| live (gated) | `local-model.test.ts` leg `local-model-netns` (`MANDU_LIVE_LOCAL_MODEL=1 npm run test:env:local-model-netns`) | the whole local-model drill, run as the ordinary user in a nested user namespace with the internet through slirp4netns, the declared model on the peer behind a TLS relay with `tls.ca_file` and `perimeter.networks` set: every check of the local-model leg, plus every request to the declared model arrived on the peer's inside address over TLS |

### 2.8 Settled points

1. `local-model`, `local: true` and `localmodel_` are redefined, not
   renamed (D1).
2. A plain-http opt-out exists for the helper only, per entry, loud
   everywhere; the main model keeps its hard https rule (D2).
3. The administrator's layer is in the open repository; its distribution
   and signing are enterprise (D5).
4. The endpoint forwarder is not built; the `token_env`-style residue for
   the client key is accepted (D3).
5. F6 is fixed for every trust variable, not only Node's: for each variable
   `mitmTrustEnv` sets, the file the user had set is merged with the
   session CA into the file handed out (`writeUserTrustFiles`,
   `launcher/src/services/net-proxy.ts`). Every session CA has the same name,
   so each leaf explicitly carries its issuer key id (`authorityKeyIdentifier`,
   net-proxy `ca.ts`), allowing a client with several session CAs in its bundle
   to choose the right one; OpenSSL 4.0 no longer adds this by default.
6. The network legs are tested in unprivileged network namespaces on one
   host rather than two VM guests (§2.6).
7. The administrator's perimeter is narrow-only, with or without the lock;
   `models_locked` is about the models list (D5).
8. The administrator wins a conflict, says so, and never refuses a start
   over one (D5).

### 2.9 As built

The pieces are named in each decision above. In one place:

| Piece | Where |
|---|---|
| Placement, plain-http rule | `arbiter/policy/model-placement.ts` (`endpointPlacement`, `isPlainHttpToNetwork`) and its mirrors; `checkModels`; inspect-mcp `assertDeclaredEndpointUrl`; launcher `PlainHttpLocalModelError` |
| User CA files under inspection | `launcher/src/services/net-proxy.ts` (`writeUserTrustFiles`), `env-compose.ts` (`mitmTrustEnv`) |
| `tls:` | `arbiter/policy/model-tls.ts`; `endpoint-tls.ts` (five verbatim copies: inspect-mcp, both proxies, launcher, dashboard) |
| `perimeter:` | `arbiter/policy/model-perimeter.ts`; `perimeterLookup` / `checkLiteralHost` in `endpoint-tls.ts`; launcher `PerimeterLocalModelError` |
| Administrator's layer | `arbiter/policy/admin-layer.ts` (`installAdminLayer`, `readAdminLayer`, `reloadAdminLayer`, `effectiveModels`, `adminLockProblems`, `layerProblems`), `policy-file-validate.ts` |
| Copy, doctor, Settings | `launcher/src/doctor.ts`, `dashboard/public/`, `dashboard/src/view-model/model-endpoints.ts`, `dashboard/src/endpoint-tls.ts` |
