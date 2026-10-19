# Mandu conformance suite

A declarative, scenario-driven **conformance test suite** for Mandu. It boots
the **real** components in-process — a `ArbiterServer` on a temp Unix socket, the
real Track A ingress proxy (`AnthropicProxy` for Claude, `OpenAiProxy` for Codex)
pointed at a **mock upstream** — and asserts the docs/design §9 symbolization
invariant plus the data-trust / data-usage / exec policies through the
components that did **not** do the symbolizing. It is **deterministic**: no API
key, no network (the proxies forward to a mock upstream; the U-LLM is mocked).

## Provenance

This suite is modeled on **adfi-openclaw**'s unit + e2e testing:

- The micro-runner (`lib/harness.ts`: `test` / `testAsync` / `summary` + the
  ANSI palette + the bold-cyan section headers) mirrors the ergonomics of
  `adfi-openclaw/test/helpers.ts`, and `buildStack(opts)` is the Mandu analog
  of adfi's `buildMockApi(opts)` (one call → a fully-wired, offline system
  under test + handles to drive and observe it).
- The assertion DSL (`lib/assertions.ts`: the `FieldMatcher` + the per-step
  `assert: <kind>` table) is lifted from
  `adfi-openclaw/test/lib/assertions.ts`. Where adfi evaluates steps against an
  audit log + filesystem/git, Mandu evaluates them against the live components
  (the forwarded model request, the arbiter symbol table + policy ops, the
  emitted `ManduEvent`s, and the dashboard view-model).
- The scenario format (`scenarios/*.yaml`) mirrors `adfi-openclaw/test/e2e`'s
  declarative `id / name / tags / assertions: [...]` YAML shape (here:
  `target` + an `ingress | egress | exec | ullm` drive + the assertion list).

The in-process arbiter + proxy wiring (the `modelProxyRealClient` bridge, the
temp socket/db/eventDir, polling `events()` back through the dashboard
`ArbiterEventSource`) is the pattern proven in
`tests/stack/full-stack.test.ts`, generalized so any YAML scenario can
drive it.

## Assertion DSL (step kinds)

| step kind                  | adfi analog                       | Mandu surface it checks |
|----------------------------|-----------------------------------|---------------------------|
| `agent_sees_only_symbol`   | `AgentNoUntrusted`                | the FORWARDED model request carries no raw untrusted byte, only `$MDU:*` |
| `result_symbolized`        | `ToolSymbolized`                  | the ingress result was replaced by a `$MDU:*` token |
| `not_symbolized`           | `ToolInbound` trust:`trusted`     | a TRUSTED field/tool passes through (no over-symbolization) — via `arbiter.classify` |
| `symbol_resolves_to`       | `SymbolResolved`/`SymbolAllocated`| `arbiter.resolve(sym)` returns the original bytes |
| `invariant_holds`          | the §9 oracle                     | the emitted `tllm_call` has `invariant.violatedInvariant === false` (+ dashboard `invariantStatus`) |
| `event_view`               | (dashboard lane render)           | the event lands in the expected dashboard lane via `toLaneModel` |
| `egress_decision`          | `ToolOutbound` / data-usage gate  | `arbiter.desymbolizationDecision(...)` → `allow` / `requires_approval` |
| `exec_shell`               | exec classification               | `arbiter.classifyExec(...)` → `AgentShell` / `HumanShell` |
| `ullm_resymbolized`        | the U-LLM invariant               | `inspectSymbol` returns a NEW symbol, never the raw U-LLM reply |

## Scenario corpus

- **CT-01** stored-IPI in a Read result is symbolized (Claude).
- **CT-02** stored-IPI via a Codex `function_call_output` is symbolized.
- **CT-03** multi-field web result: trusted `status` NOT symbolized, untrusted body symbolized.
- **CT-04** exec-exfil: Bash output symbolized so the model cannot read it.
- **CT-05** untrusted-destination egress → `requires_approval` (the data-usage gate).
- **CT-06** a symbol used as a command → `requires_approval`.
- **CT-07** exec classification: AgentShell by default, HumanShell when it needs the real world.
- **CT-08** benign utility: agent-authored (TRUSTED) content is NOT symbolized.
- **CT-09** U-LLM re-symbolization: `inspect_symbol` returns a new symbol, never the raw reply.

## Run

```sh
cd tests/conformance
npm install
npm run typecheck
npm test          # the canary: lib/unit_symbolization.ts
npm run test:integrity   # FROZEN lane: run.ts (scenarios) + lib/unit_egress_gate.ts
```

The scenario corpus and the egress-gate suite exercise the integrity axis,
which is frozen (`docs/design/architecture/protection-modes.md §10`); they run in the opt-in
`test:integrity` lane. Either command exits non-zero on any failed scenario
assertion or unit case.
