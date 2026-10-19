# tests — Mandu's cross-package suites

One npm package (`tests/package.json`, one `tests/node_modules`) for every
suite that wires several Mandu packages together, laid out by kind
(`docs/design/testing/test-reorganization.md` §5.3):

```
tests/stack/            stack: several real packages wired as in production, a scripted model
tests/sandbox/          sandbox: the real sandbox, no agent (integration.kernel's files;
                        launcher/ holds the three sandbox suites that are entries of their own)
tests/env/              env: the host decides (a local model server, a login, the internet)
tests/integrity/        the frozen integrity lane's copies (protection-modes.md §10)
tests/lib/              shared helpers (the check library, axes.ts, netns, exit-guard, ...)
tests/fixtures/         shared fixtures
tests/conformance/      a package of its own: the declarative conformance corpus
```

The maintainers' agent drills (the live-drill and replay-drill kinds: a real
agent CLI on a real or a scripted model) are kept in the source repository and
are not published.

The rest of this file is about the stack suites.

## stack — the §9 invariant, proven across REAL components

Each Mandu package ships its own component suite that proves the security invariant
against **mocks** at its own seam (e.g. the anthropic-proxy oracle drives the real
proxy against a mock arbiter + mock upstream). `tests/stack/` is the one place where
the **real** components are wired together in a single process and the
`docs/design/architecture/implementation-plan.md` §9 invariant —

> No un-symbolized untrusted byte ever reaches the privileged model (T-LLM).

— is asserted **end-to-end**, observed through the components that did *not* do
the symbolizing.

The package owns **no product sources**: it imports the sibling packages directly
(`arbiter/`, `interceptors/anthropic-proxy/`, `interceptors/inspect-mcp/`,
`dashboard/`) and reuses their test helpers (`MockUpstream`, `MockUllm`).

## What the e2e wires (all REAL except the two leaf I/O seams)

```
   POST /v1/messages (stored-IPI tool_result)
            │
            ▼
   AnthropicProxy (REAL) ──ArbiterClientAdapter──► ArbiterServer (REAL, temp socket)
            │                                   - symbol table (temp SQLite)
            │ forward (symbolized)              - data-trust policy (engine)
            ▼                                   - event store (temp NDJSON dir)
   MockUpstream (canned SSE)                          ▲          ▲
                                                      │ emit()   │ events()/subscribe
                                  inspectSymbol (REAL)┘          │
                                   │ MockUllm (canned reply)     │
                                   ▼                             │
                            re-symbolize → arbiter         ArbiterEventSource (REAL)
                                                            → toLaneModel / invariantStatus (REAL)
```

The only mocks are the two outermost I/O leaves that would otherwise need a
network/API key: the **upstream Anthropic endpoint** (`MockUpstream`) and the
**quarantined U-LLM** (`MockUllm`). Everything between them — the arbiter daemon,
its symbol table + policy engine + event store, the anthropic-proxy data path, the
inspect-mcp core, and the dashboard's arbiter-backed event source + view-model —
is the real shipped code.

## What it asserts

1. **Proxy egress (the §9 predicate):** the request body the proxy forwards
   upstream contains the stored-IPI payload **only** as a `$MDU:Read[...]`
   token — never verbatim, no raw fragment, with the handling system prompt
   injected. The **real arbiter** minted the symbol and round-trips it back to the
   original bytes via `resolve()`.
2. **Arbiter `events()`:** a `tllm_call` with `invariant.violatedInvariant ===
   false`; a `tool_result` whose `DualRepr` has the **symbol** in `symbolized`
   and the **raw payload** in `original` (`differs === true`), classified
   `UNTRUSTED`.
3. **Dashboard read-back:** the same events read through the dashboard's
   `ArbiterEventSource` over the same socket, pushed through the **pure**
   view-model: `invariantStatus` is `holds:true / level:"ok"` and `toLaneModel`
   puts the events in the **AgentView** lane with the `tllm_call` tagged `T-LLM`
   and not violated.
4. **U-LLM round-trip (inspect-mcp):** the real `inspectSymbol` core inspects the
   minted symbol against the real arbiter with a mock U-LLM; the returned result is
   a **new opaque symbol** (never the raw reply), the quarantined call saw the raw
   value **without** any T-LLM system prompt, and a `ullm_call` event lands in the
   **Quarantine** lane with the invariant still holding.

## Integration mismatch reconciled here

The anthropic-proxy's `ArbiterClientAdapter` is typed against a `RealArbiterClient`
whose `emit(event)` resolves to `{ seq }`, whereas the real arbiter IPC client
resolves to the **bare** `seq` number. The two agree at runtime (the proxy treats
`emit` as fire-and-forget and ignores the result) but differ statically. The test
bridges this explicitly in `modelProxyRealClient(...)` rather than casting it
away — reconciling cross-package contracts is exactly what an integration package
is for. (inspect-mcp's adapter already expects the bare-number `emit`, so the real
client satisfies it directly.)

## Run

```sh
cd tests && npm test        # or npm run typecheck
```

Both first run `scripts/install-deps.mjs`, which installs this package and the
sibling packages it imports (`"mandu.siblings"` in `package.json`) wherever
their `node_modules` is missing: their npm imports (such as `js-yaml` in the
arbiter) resolve from their own package, not this one
(`docs/development.md`, "Per package").

or, from the repo root, as part of the full suite:

```sh
scripts/test-all.sh
```

`test-all.sh` runs the `unit`, `component`, `stack` and `sandbox` kinds of the
suite manifest (`tests/suites.mjs`, `docs/design/testing/test-organization.md`);
run the package's scripts from `tests/`. `stack/` is its `integration`
entry, kind `stack`; `sandbox/` is `integration.kernel`
(`npm run test:sandbox`); `integrity/` is `integration.integrity`
(`npm run test:integrity`, the frozen lane). The files under
`env/` and `sandbox/launcher/` are entries of their own, by what is real in
them (as are the maintainers' drills: the scripted-model agent suites are
`replay-drill`, every CI push, in the CI guest; codex-e2e `live-drill`; the
claude-e2e secrets cut retired on 2026-10-18, its drills carry it): the launcher real-home suites
(`sandbox/launcher/`) `sandbox`, the Ollama suites (`env/`) `env`, and the
watch drills `live-drill` (those run nightly, `docs/design/testing/continuous-integration.md` §9, or
by hand). The integrity cuts (`drills:live:int-smoke`, `drills:live:full`) are
the frozen lane (`frozen: true`).
`node scripts/suites.mjs list --kind <kind>` names every entry.

## The live fold groups (int×conf posture matrix)

The claude live battery is grouped by the two axis switches (integrity =
the classic IPI defense; confidentiality = the secret lattice —
`docs/design/confidentiality/confidentiality.md` §11/§12). A shared arbiter's posture is fixed
at boot, so each group declares what it EXPECTS and the suite's **posture
guard** (`MANDU_E2E_EXPECT_CONF` / `MANDU_E2E_EXPECT_INT`, checked against
the arbiter's `hello()`) hard-FAILS — never skips — on a mismatch: a fold that
silently ran at the wrong posture is the "posture nobody runs" trap.

| Group (npm script) | Posture | Scenarios |
| --- | --- | --- |
| `drills:live:int-smoke` | int ON, conf OFF (expects it) | `stored-ipi`, `exec-symbol-command-blocked`, `net-exfil-blocked`, `inspect-extract` — one per chokepoint (fold 1 essentials) |
| `drills:live:full` | int ON, conf ON (expects it of the shared arbiter; CONF privates run int ON) | every E-scenario (fold 3, live) + every `CONF-*` (fold 4; `CONF-danger-cell-declassify` is the §9 int×conf composition cell and self-skips under `CONF_INT=0`; `CONF-declassify-grant-taints` self-skips at int ON, where its read is untrusted and hits the danger cell) |
| `drills:live:agent` | posture-agnostic (no EXPECT) | the whole scenario list at whatever posture the shared arbiter runs — the dashboard "Run e2e" default |

The conf-only group (`drills:live:conf-smoke`: nine `CONF-*` scenarios, each
on a private conf-ON arbiter at int OFF) retired on 2026-10-18 after seven
nights of the drill catalog's conf drills on Claude Code, which carry its
scenarios (`docs/design/testing/test-reorganization.md` §9.1).

The `CONF-*` scenarios are the TS port of the RETIRED bash suite
(`launcher/test/confidentiality-live.test.sh`, deleted 2026-07-16 after parity
pipeline #6398 ran both stacks green — docs/design/confidentiality/confidentiality.md §12);
each boots its own in-process conf-ON `ArbiterServer` (+ private symbol DB)
and writes events into the SHARED arbiter's event dir so the dashboard still
sees the sessions.

## Live-suite parallelism (claude-e2e / codex-e2e)

The live scenario suites run their scenarios through a bounded eager-start
pool (`lib/pool.ts`) instead of strictly one after another —
node:test runs a file's top-level tests sequentially, and each scenario is a
real network-bound agent run, so serial wall-clock was the sum of all
scenarios (~20–30 min). The `test()` registrations stay top-level and
sequential (each awaits its pre-started result), so the TAP stream the
dashboard TestRunner parses is unchanged.

| Env | Default | Meaning |
| --- | --- | --- |
| `MANDU_E2E_CONCURRENCY` | `4` | Print-driver scenarios in flight at once (both suites). `1` restores strict serial. |
| `MANDU_E2E_INTERACTIVE_CONCURRENCY` | `1` | Interactive-driver (PTY/TUI) scenarios in flight at once — serial by default because they are graded on keystroke/idle timing windows. |
| `MANDU_E2E_MODELS` | *(none)* | claude-e2e MODEL MATRIX: comma-separated slugs (`sonnet`, `opus`) the `modelAxis` scenarios ALSO run on, as `<scenario>@<model>` runs. Unset ⇒ base model (haiku) only ⇒ the suite is byte-identical to the pre-matrix one. An unknown slug throws (a typo that silently ran nothing would look exactly like a green matrix). |

### The model matrix (`MANDU_E2E_MODELS`)

```sh
npm run drills:live:models   # the six modelAxis scenarios × haiku + sonnet + opus (18 runs)
```

Every scenario runs on **haiku** (the base): the full battery's job is *breadth
over the defense*, which is enforced in the proxy and therefore model-invariant,
so paying a bigger model's price for it buys nothing. Only the six `modelAxis`
scenarios fan out, because only they probe something a model can actually move:

| Scenario | What a bigger model can move |
| --- | --- |
| `reasoning` | That the model works through the proxy **at all** — the subscription (OAuth) request-shape check rejects a foreign block at `system[0]` on the **main-loop** models but *not* on haiku (`rewrite-request.ts`), so haiku-only live coverage structurally cannot exercise it. |
| `stored-ipi` | §9 + no-sabotage: does *this* model leak or obey the injection. |
| `untrusted-file-lookup` | Can it finish the job holding an opaque symbol, or does it fabricate a plausible value. |
| `inspect-extract` | Does it reach for the quarantined U-LLM (`inspect_symbol`) at all. |
| `exec-symbol-command-blocked` | Does it put a symbol in command position — the exec gate can only fire if it does. |
| `interactive-reply-filter-live` | The one interactive slot: adaptive thinking changes the **streaming cadence** (a long silent pause, then a burst) that the reply-filter's PTY egress holds tokens across. The other interactive scenarios prove PTY/relay *plumbing*, which no model touches. |

Security oracles are **identical** across models by design — security is
structural and should be model-*invariant*, so a leak on opus that haiku never
showed is a **finding**, not a tolerance to widen. Utility is the half that
legitimately varies by tier.

The bigger models run adaptive thinking, so a turn opens with a long *silent*
pause; every deadline (child budget, `node:test` timeout, the interactive
driver's per-turn wait) is scaled by `ModelSpec.timeoutScale`. Without that, an
opus turn outruns the driver's 30 s window, is recorded as never having
completed, and the oracle goes vacuous or red for a **timing** reason that looks
like a defense finding.

Fable is deliberately out (10×/2× haiku's input/output price; its distinctive
shapes — always-on thinking, `refusal` as a 200 with empty content, `fallback`
blocks — suit a frozen replay fixture better than real budget on every run).

Why 4, not #cores: the scenarios are network-bound; the ceiling is the shared
Claude subscription's rate-limit (429) tolerance — the CLI retries with
backoff, which pushes against each scenario's fixed child timeout. Raise it
incrementally and watch for 429-driven timeouts. What makes parallelism sound:
every scenario has its own session id, proxies on ephemeral ports, and tmp
workspace; oracles read events per session; `MDUASSERT` lines self-identify
`class[scenario]`, so the dashboard attributes them correctly even from
interleaved stdout.

## The plan 11 local-model drill (`local-model-e2e`)

`env/local-model.test.ts` is the live half of plan 11
(docs/design/confidentiality/model-endpoints.md §1.4, §1.7.1, §1.8 row 1): the REAL launcher (what `mandu` runs) around a REAL `claude -p`,
a file labeled `local-model`, and a `models:` entry declaring this host's
Ollama `local: true`. Recording relays in front of Anthropic and the Ollama
let the oracle (`lib/local-model-oracle.ts`) judge the vendor wire
itself. Two legs: LM1 `local-model` (your own model reads the file, the vendor
never receives its bytes) and LM2 `any-model` (the control: the default helper
under its network confine). Catalog entry: docs/testing/e2e-catalog.md §2e.

```sh
cd tests
MANDU_LIVE_LOCAL_MODEL=1 npm run test:env:local-model                        # the drill
MANDU_LIVE_LOCAL_MODEL=1 MANDU_TEST_DASHBOARD=1 npm run test:env:local-model  # ...and show it in the dashboard
MANDU_LIVE_LOCAL_MODEL=1 MANDU_LIVE_LOCAL_MODEL_MODE=full npm run test:env:local-model  # full mode
```

Prerequisites (each missing one SKIPs both legs with the reason):

- `MANDU_LIVE_LOCAL_MODEL=1` (it costs two subscription sessions, each a few
  T-LLM requests on the live suites' base model, haiku);
- Linux, `claude` on PATH, logged in with a subscription
  (`~/.claude/.credentials.json`, or under `$CLAUDE_CONFIG_DIR`);
- `npm install` in `launcher/`;
- an Ollama at `MANDU_LIVE_LOCAL_MODEL_URL` (default `http://127.0.0.1:11434`)
  with `MANDU_LIVE_LOCAL_MODEL_NAME` (default `llama3.2`) pulled
  (`ollama pull llama3.2`). The gate warms the model first; a cold load takes
  about a minute.

The drill starts its own private arbiter with its own policy file (the test
tenant), so it never reads or writes your `~/.config/mandu/policy.yaml`. With
`MANDU_TEST_DASHBOARD=1` the events land in the event dir of the arbiter at
`MANDU_ARBITER_SOCK` (else the account's shared one), so the sessions appear in
the dashboard under **Testing** as `local-model-e2e-<leg>-<ms>` with LM1 / LM2
badges. The dashboard's ▶ Run drawer runs it as its own suite, **▶ Run local
model** (host only, not part of the `e2e` battery). Other knobs
(`MANDU_LIVE_LOCAL_MODEL_TLLM`, `_KEEP`, `_UNTRACKED`) are in the file header;
a failed run keeps its artifacts (wire records, events, launcher output) under
the run's `/tmp/mandu-lm-*/drill-artifacts/`. Its offline half,
`stack/local-model.test.ts`, runs in every `npm test`.
