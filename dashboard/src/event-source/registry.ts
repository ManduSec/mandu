/**
 * event-source/registry — e2e test-session identification (the canonical test
 * registry + per-class badge numbers) and per-session derivations for the
 * sidebar (label, agent kind, assertion verdicts). Extracted VERBATIM from
 * src/event-source.ts in the event-source decomposition; see the barrel for the
 * module map.
 */

import {
  type ManduEvent, type AssertionCheck, HISTORY_FIDELITY_ASSERTS,
} from "../event-model.js";
import { firstUserPrompt, truncateLabel } from "../transcript.js";
import type { SessionLabelFrom, SessionRef } from "./contract.js";
import { AGENTS, type Agent } from "../generated/agents.js";

/** Mandu e2e TEST session-id classes (the run sets its id via
 *  `x-mandu-session-id`, or — for the header-less Codex CLI — the openai-proxy
 *  `sessionKey`). `claude-e2e-*` is a REAL `claude -p` loop from a user prompt;
 *  `codex-e2e-*` is the same but a REAL `codex exec` loop (Codex CLI, openai-proxy);
 *  `replay-e2e-*` is a deterministic canned-transcript replay. The dashboard badges
 *  all as test traffic AND surfaces which class. Keep in sync with the e2e
 *  harnesses (tests/stack/, tests/env/ and the maintainers' drills). */
export const TEST_SESSION_CLASSES = [
  "claude-e2e",
  "codex-e2e",
  // `openclaw-e2e` / `opencode-e2e` are REAL `openclaw agent --local` /
  // `opencode run` loops. Both speak Anthropic Messages, so both ride the same
  // anthropic-proxy as claude-e2e — which is exactly why deriveAgentKind can no
  // longer infer the agent from the emitter alone (see it below).
  "openclaw-e2e",
  "opencode-e2e",
  // `goose-e2e` is a REAL `goose run` loop (goose-e2e.test.ts):
  // Anthropic Messages through the anthropic-proxy, keyed by the proxy's own
  // session key (Goose sends no session header).
  "goose-e2e",
  "replay-e2e",
  // `local-model-e2e` is the plan 11 LIVE drill
  // (tests/env/local-model.test.ts): the REAL launcher
  // around a REAL `claude -p`, with a `models:` entry naming this host's Ollama.
  // Its private arbiter and the launcher both run as the test tenant, so the
  // stamp files its sessions under Testing; the class names the suite.
  "local-model-e2e",
  // `local-main-model-e2e` is the plan 11 phase 3 LIVE drill
  // (tests/env/local-main-model.test.ts): the REAL
  // launcher around a REAL `claude -p` whose MAIN model is this host's Ollama.
  // One scenario, `main-model`; its sessions are `local-main-model-e2e-main-model-<ms>`.
  "local-main-model-e2e",
  // `browser-jev-e2e` is the live browser drill (the drill suite's
  // browser-jev): the real jev-ultrafast in a real Chromium behind the
  // DevTools relay, on its own arbiter whose events land in the dashboard's
  // store when the dashboard runs it (dashboard.md §4.10.7).
  "browser-jev-e2e",
] as const;
/** Back-compat: older runs minted a plain `e2e-<name>` id (no class). */
export const TEST_SESSION_PREFIX = "e2e-";

/** Coarse, id-derived session annotations for the sidebar: `["test", <class>]`
 *  for a classed e2e run, `["test"]` for a legacy `e2e-` id, else undefined (so a
 *  normal SessionRef stays minimal). */
export function sessionTags(id: string): string[] | undefined {
  for (const cls of TEST_SESSION_CLASSES) {
    if (id.startsWith(cls + "-")) return ["test", cls];
  }
  return id.startsWith(TEST_SESSION_PREFIX) ? ["test"] : undefined;
}

/**
 * Canonical e2e test registry → stable PER-CLASS badge numbers. Each class
 * counts its own sequence under its own prefix (TEST_CLASS_BADGE): replay-e2e
 * → `Re1…`, claude-e2e → `E1…`, codex-e2e → `C1…` — so a badge names both the
 * suite and the scenario at a glance (2026-07-10; formerly one global `T<n>`
 * sequence). KEEP IN SYNC with the `SCENARIOS` arrays in
 * tests/stack/proxy-replay.test.ts and
 * {claude,codex}-e2e.test.ts (a scenario added there must
 * be appended here, or it simply renders without a number).
 *
 * Numbers are POSITIONAL WITHIN THE CLASS (index-in-class + 1), so entries are
 * never removed or reordered — a scenario RETIRED from its suite keeps its row
 * (marked below) so historical sessions keep their badge and later numbers
 * never shift. New scenarios are APPENDED to their class block.
 */
const TEST_REGISTRY: ReadonlyArray<{ cls: string; name: string }> = [
  { cls: "replay-e2e", name: "ipi-text" }, //             Re1
  { cls: "replay-e2e", name: "ipi-image" }, //            Re2
  { cls: "replay-e2e", name: "ipi-mixed" }, //            Re3
  { cls: "replay-e2e", name: "ipi-webfetch-rce" }, //     Re4
  { cls: "replay-e2e", name: "ipi-bash-exfil" }, //       Re5
  { cls: "replay-e2e", name: "ipi-grep-sabotage" }, //    Re6
  { cls: "replay-e2e", name: "chain-fetch-write-read" }, // Re7
  { cls: "claude-e2e", name: "greeting" }, //      E1 RETIRED 2026-07-08 (⊂ reasoning)
  { cls: "claude-e2e", name: "reasoning" }, //     E2
  { cls: "claude-e2e", name: "benign-write-confirm" }, // E3
  { cls: "claude-e2e", name: "benign-bash-echo" }, //     E4
  { cls: "claude-e2e", name: "stored-ipi" }, //    E5
  { cls: "claude-e2e", name: "bash-ipi" }, //      E6
  { cls: "claude-e2e", name: "grep-sabotage" }, // E7 RETIRED 2026-07-08 (⊂ bash-ipi live + replay-e2e Re6)
  { cls: "claude-e2e", name: "chain-copy-read" }, //      E8
  { cls: "claude-e2e", name: "webfetch-rce" }, //  E9
  { cls: "claude-e2e", name: "chain-fetch-write-read" }, // E10
  { cls: "claude-e2e", name: "trusted-glob" }, //  E11 RETIRED 2026-07-08 (⊂ trusted-and-untrusted + trusted-grep-files)
  { cls: "claude-e2e", name: "trusted-grep-files" }, //   E12
  { cls: "claude-e2e", name: "trusted-and-untrusted" }, // E13
  // Appended (not inserted in suite-array order) so existing badge numbers never
  // shift — see the header note. In the live SCENARIOS array `inspect-summarize`
  // sits between chain-copy-read and webfetch-rce; here it trails as E14 by the
  // stable-number convention.
  { cls: "claude-e2e", name: "inspect-summarize" }, //    E14
  // Exact-answer TIGHT-utility scenarios (2026-07-10): meaningful work whose
  // answer exists only on the untrusted side, delivered CORRECTLY (hard oracle).
  { cls: "claude-e2e", name: "count-security" }, //       E15
  { cls: "claude-e2e", name: "inspect-extract" }, //      E16
  // APPENDED (sits after trusted-grep-files in the SCENARIOS array, but numbered
  // E17 by the stable-append convention): the UNTRUSTED dual of E12 — the answer
  // value lives in symbolized file content, delivered via the untrusted round-trip.
  { cls: "claude-e2e", name: "untrusted-file-lookup" }, // E17
  // More tight-utility shapes (2026-07-10): the U-LLM must COMPARE/select (not
  // just extract), and a HARD fs writeback-fidelity check on the untrusted round-trip.
  { cls: "claude-e2e", name: "inspect-compare" }, //      E18
  { cls: "claude-e2e", name: "untrusted-writeback" }, //  E19
  // Exec-routing scenarios (2026-07-10): in the SCENARIOS array they sit in the
  // benign block (after benign-bash-echo), but numbering here is append-only.
  { cls: "claude-e2e", name: "exec-symbol-command-blocked" }, // E20
  { cls: "claude-e2e", name: "exec-curl-run-blindspot" }, //    E21
  // Interactive-driver scenarios (2026-07-11): the first non-headless rows —
  // a real interactive `claude` TUI under the reply-filter PTY relay, driven by
  // interactive-driver.ts. Driver is a SCENARIO
  // property, not a class, so ids and badges stay in this one sequence. Every
  // interactive scenario is named `interactive-*` (suite naming rule), so the
  // session id says the driver at a glance; E23/E24 were RENAMED in place the
  // same day they landed (typeahead-ipi / reply-filter-live → the prefixed
  // spellings) — positions, and so badges, are unchanged; sessions minted
  // under the few-hours-old unprefixed spelling render without a badge.
  { cls: "claude-e2e", name: "interactive-smoke" }, //    E22
  { cls: "claude-e2e", name: "interactive-typeahead-ipi" }, //     E23
  { cls: "claude-e2e", name: "interactive-reply-filter-live" }, // E24
  // Verdict-driven recovery (2026-07-12, symbol-quality.md §4 Fix B live): the
  // mock serves a 503 notice first and the real page on the retry (then_body);
  // the content_kind verdict is the only way the agent can learn to refetch.
  { cls: "claude-e2e", name: "inspect-verdict-retry" }, // E25
  // Interactive U-LLM coverage (2026-07-12): the interactive dual of inspect-extract
  // and the only interactive scenario exercising inspect_symbol under the PTY relay
  // (needed --mcp-config wired into the interactive driver). KEEP IN SYNC with
  // claude-e2e.test.ts SCENARIOS.
  { cls: "claude-e2e", name: "interactive-inspect-extract" }, // E26
  // P3 sensitive-path gate, live (2026-07-12): a Glob at a denied absolute path
  // is gated to the /mandu/denied/… sentinel, and the CLI's error prose then
  // names the CWD (the AgentView root) — which the reverse ViewMap must keep out
  // of T-LLM's context. Registered late (sessions minted before this row render
  // unbadged). KEEP IN SYNC with claude-e2e.test.ts SCENARIOS.
  { cls: "claude-e2e", name: "fs-denied-cwd-note" }, // E27
  // NETWORK egress kill-switch, live (2026-07-14): a symbol bound for an untrusted
  // host is BLOCKED by the net-proxy egress gate (403, withheld) — the data-symbol
  // network egress the deterministic net-proxy e2e proves, now against a real agent
  // (the last uncovered egress path on the integrity side). KEEP IN SYNC with
  // claude-e2e.test.ts SCENARIOS.
  { cls: "claude-e2e", name: "net-exfil-blocked" }, // E28
  // The confidentiality class (2026-07-16): the CONF-* scenarios, ported from
  // the bash confidentiality-live suite + 3 TS-only additions. Names carry NO
  // ordinal (the badge IS the number — an ordinal in the name goes stale the
  // moment a scenario is inserted or retired); each runs against a PRIVATE
  // conf-ON arbiter. Sessions minted under the pre-rename `CONF-<i>-<slug>`
  // spellings render unbadged (the E23/E24 precedent). KEEP IN SYNC with
  // claude-e2e.test.ts SCENARIOS.
  { cls: "claude-e2e", name: "CONF-catalog-strict" }, //           E29
  { cls: "claude-e2e", name: "CONF-quarantine-summary" }, //       E30
  { cls: "claude-e2e", name: "CONF-danger-cell-declassify" }, //   E31
  { cls: "claude-e2e", name: "CONF-watermark-egress-deny" }, //    E32
  { cls: "claude-e2e", name: "CONF-cross-session-label" }, //      E33
  { cls: "claude-e2e", name: "CONF-public-label-override" }, //    E34
  { cls: "claude-e2e", name: "CONF-strict-quarantine-refused" }, // E35
  { cls: "claude-e2e", name: "CONF-bound-host-release" }, //       E36
  { cls: "claude-e2e", name: "CONF-high-session-exec-gated" }, //  E37
  { cls: "claude-e2e", name: "CONF-secret-not-exfiltrated" }, //   E38
  { cls: "claude-e2e", name: "CONF-declassify-grant-taints" }, //  E39
  // Per-file discrimination (2026-07-16): one workspace, all three levels at
  // once — the audit's mixed-labels gap. KEEP IN SYNC as above.
  { cls: "claude-e2e", name: "CONF-mixed-workspace" }, //          E40
  // §9 rule 1(b) live (2026-07-16): a HIGH + untrusted-tainted session loses
  // even its bound-destination release. KEEP IN SYNC as above.
  { cls: "claude-e2e", name: "CONF-tainted-bound-blocked" }, //    E41
  // The agentdojo-* family (2026-07-17): one benign "read my data" task per
  // AgentDojo suite (workspace/banking/travel/slack), whose untrusted content
  // carries a sink injection; symbolization drives AgentDojo's ASR→0 at the
  // context chokepoint (docs/design/testing/evaluation.md §2.2). KEEP IN SYNC with
  // claude-e2e.test.ts SCENARIOS.
  { cls: "claude-e2e", name: "agentdojo-workspace-email" }, //     E42
  { cls: "claude-e2e", name: "agentdojo-banking-transaction" }, // E43
  { cls: "claude-e2e", name: "agentdojo-travel-review" }, //       E44
  { cls: "claude-e2e", name: "agentdojo-slack-message" }, //       E45
  // Exec-output-trust TDD pair (2026-07-19; docs/design/integrity/exec-routing.md §8).
  // Born RED BY DESIGN the same day; §4 rung 1 (the exact-match upgrade)
  // shipped hours later, so E46 is now an ordinary battery row (a benign
  // echo-back must ride to the model UN-symbolized), while E47 stays
  // future-gated red (needs §4 rungs 2–3 + the §5 boxed posture;
  // MANDU_E2E_FUTURE=exec-output-trust opts it in, so its sessions appear
  // only from deliberate TDD runs). KEEP IN SYNC with
  // claude-e2e.test.ts SCENARIOS.
  { cls: "claude-e2e", name: "exec-trust-echo-unsymbolized" }, //  E46
  { cls: "claude-e2e", name: "exec-trust-derived-chain" }, //      E47
  // Symbol-twin shell note (2026-09-18; docs/design/integrity/symbol-twin-shell-blindness.md §8).
  { cls: "claude-e2e", name: "twin-shell-note" }, //              E48
  { cls: "claude-e2e", name: "twin-shell-note-cd" }, //           E49
  // ── codex-e2e (C1–): the Codex CLI sibling of claude-e2e, real `codex exec`
  // through the openai-proxy. Its scenarios are the Track-A-appropriate subset
  // (Codex's only tool is `exec_command`, so file reads are shell `cat` and all
  // shell output is UNTRUSTED → symbolized; no ViewMap/fsSync/U-LLM path). KEEP IN
  // SYNC with codex-e2e.test.ts SCENARIOS. */
  { cls: "codex-e2e", name: "reasoning" }, //     C1
  { cls: "codex-e2e", name: "benign-exec" }, //   C2
  { cls: "codex-e2e", name: "stored-ipi" }, //    C3
  // OpenClaw (docs/design/testing/agent-e2e-harness.md). `OCl`/`OCo` rather than a
  // single letter: both agents start with "O", so one letter cannot discriminate.
  { cls: "openclaw-e2e", name: "reasoning" }, //             OCl1
  { cls: "openclaw-e2e", name: "benign-read" }, //           OCl2
  { cls: "openclaw-e2e", name: "stored-ipi" }, //            OCl3
  { cls: "openclaw-e2e", name: "fs-view-writeback" }, // OCl4
  { cls: "openclaw-e2e", name: "net-exfil-blocked" }, //     OCl5
  { cls: "openclaw-e2e", name: "inspect-extract" }, //       OCl6 (registered 2026-09-29; the scenario is older)
  // The secrets re-pin (2026-09-29, test-organization.md §7.3): OCl3-OCl5 left
  // for the frozen copy (tests/integrity/openclaw-e2e.test.ts); the conf legs.
  { cls: "openclaw-e2e", name: "secret-read-exfil" }, //         OCl7
  { cls: "openclaw-e2e", name: "secret-net-exfil-blocked" }, //  OCl8
  { cls: "openclaw-e2e", name: "secret-read-control" }, //       OCl9
  { cls: "openclaw-e2e", name: "prompt-secret" }, //             OCl10 (plan 15, 2026-10-02)
  { cls: "openclaw-e2e", name: "prompt-policy" }, //             OCl11 (plan 15 phase 2, 2026-10-02)
  // OpenCode
  { cls: "opencode-e2e", name: "reasoning" }, //             OCo1
  { cls: "opencode-e2e", name: "benign-read" }, //           OCo2
  { cls: "opencode-e2e", name: "stored-ipi" }, //            OCo3
  { cls: "opencode-e2e", name: "fs-view-writeback" }, // OCo4
  { cls: "opencode-e2e", name: "net-exfil-blocked" }, //     OCo5
  { cls: "opencode-e2e", name: "inspect-extract" }, //       OCo6
  // The secrets re-pin (2026-09-29, test-organization.md §7.3): OCo3-OCo5 left
  // for the frozen copy (tests/integrity/opencode-e2e.test.ts); the conf legs.
  { cls: "opencode-e2e", name: "secret-read-exfil" }, //         OCo7
  { cls: "opencode-e2e", name: "secret-net-exfil-blocked" }, //  OCo8
  { cls: "opencode-e2e", name: "secret-read-control" }, //       OCo9
  { cls: "opencode-e2e", name: "prompt-secret" }, //             OCo10 (plan 15, 2026-10-02)
  { cls: "opencode-e2e", name: "prompt-policy" }, //             OCo11 (plan 15 phase 2, 2026-10-02)
  // Goose (2026-10-05, supported-agents.md §5.6). KEEP IN SYNC with
  // goose-e2e.test.ts SCENARIOS.
  { cls: "goose-e2e", name: "reasoning" }, //                G1
  { cls: "goose-e2e", name: "benign-read" }, //              G2
  { cls: "goose-e2e", name: "secret-read-exfil" }, //        G3
  { cls: "goose-e2e", name: "secret-net-exfil-blocked" }, // G4
  { cls: "goose-e2e", name: "secret-read-control" }, //      G5
  { cls: "goose-e2e", name: "prompt-secret" }, //            G6
  { cls: "goose-e2e", name: "inspect-extract" }, //          G7
  // local-model-e2e (2026-09-28): the plan 11 live drill's two legs. KEEP IN
  // SYNC with the SCENARIOS descriptor in
  // tests/env/local-model.test.ts.
  { cls: "local-model-e2e", name: "local-model" }, //        LM1
  { cls: "local-model-e2e", name: "any-model" }, //          LM2
  // local-main-model-e2e (2026-09-29): the plan 11 phase 3 live drill's one
  // scenario. KEEP IN SYNC with the session id in
  // tests/env/local-main-model.test.ts.
  { cls: "local-main-model-e2e", name: "main-model" }, //    LMM1
  // browser-jev-e2e (2026-10-18): the browser drill's four tasks. KEEP IN
  // SYNC with its SCENARIOS (the drill suite's browser-jev).
  { cls: "browser-jev-e2e", name: "settings-rename" }, //    BJ1
  { cls: "browser-jev-e2e", name: "integration-paste" }, //  BJ2
  { cls: "browser-jev-e2e", name: "support-unbound" }, //    BJ3
  { cls: "browser-jev-e2e", name: "field-value" }, //        BJ4
];

/** Per-class badge prefix: the class is legible from the badge itself
 *  (Re6 = replay, E6 = live claude e2e, C2 = live codex e2e). An unknown class
 *  (future suite not yet mapped) falls back to the legacy `T` + GLOBAL index
 *  rather than colliding with an existing class sequence. */
const TEST_CLASS_BADGE: Record<string, string> = {
  "replay-e2e": "Re",
  "claude-e2e": "E",
  "codex-e2e": "C",
  "openclaw-e2e": "OCl",
  "opencode-e2e": "OCo",
  "goose-e2e": "G",
  "local-model-e2e": "LM",
  "local-main-model-e2e": "LMM",
  "browser-jev-e2e": "BJ",
};

/**
 * Split a classed e2e test session id (`<class>-<scenario>-<ts>`) into its
 * class + scenario name — the key that joins the session onto a test-runner
 * per-case result (session-batches.ts buildSidebarSections). Undefined for
 * non-test / legacy `e2e-*` ids.
 *
 * MODEL MATRIX (claude-e2e, 2026-07-12): a scenario run on a non-base model is
 * keyed `<scenario>@<model>` (`reasoning@sonnet`) on every surface — the TAP
 * title, the MDUASSERT lines, and this session id. So two fields come back, and
 * they are NOT interchangeable:
 *   - `scenario` — the FULL run key, `@model` included. This is the TAP join
 *     key: the test-runner's case carries the same suffixed key, and joining on
 *     a stripped name would collapse a scenario's whole matrix row onto one
 *     case (every model's session showing the same run's verdict).
 *   - `base` — the scenario name alone. This is the REGISTRY key: badges are
 *     per-scenario, not per-run, so `reasoning` and `reasoning@sonnet` both
 *     render as E2. Looking the badge up under the suffixed key would leave
 *     every matrix session unbadged.
 * A base-model run has no suffix, so `base === scenario` and every historical
 * id parses exactly as it did before the matrix existed.
 */
export function parseTestSessionId(
  id: string,
): { cls: string; scenario: string; base: string; model?: string } | undefined {
  for (const cls of TEST_SESSION_CLASSES) {
    const prefix = cls + "-";
    if (!id.startsWith(prefix)) continue;
    // Strip the class prefix and a trailing `-<unix-ms timestamp>` (≥10 digits).
    const scenario = id.slice(prefix.length).replace(/-\d{10,}$/, "");
    const at = scenario.lastIndexOf("@");
    if (at <= 0) return { cls, scenario, base: scenario };
    return { cls, scenario, base: scenario.slice(0, at), model: scenario.slice(at + 1) };
  }
  return undefined;
}

/** The badge for the registry entry at global index `idx`: per-class prefix +
 *  1-based position within that class (Re4 / E13 / C2). */
function badgeAt(idx: number): string {
  const { cls } = TEST_REGISTRY[idx]!;
  const prefix = TEST_CLASS_BADGE[cls];
  if (!prefix) return `T${idx + 1}`; // unmapped future class: legacy global badge
  let nInClass = 0;
  for (let i = 0; i <= idx; i++) if (TEST_REGISTRY[i]!.cls === cls) nInClass++;
  return `${prefix}${nInClass}`;
}

/** The stable per-class badge (`Re<n>`/`E<n>`/`C<n>`) for a registered
 *  (cls, scenario) pair, or undefined when the pair is not in the registry.
 *  This is the badge every surface shows (sidebar, test-setup banner, spec
 *  browser). */
export function registryTestNumber(cls: string, scenario: string): string | undefined {
  const idx = TEST_REGISTRY.findIndex((t) => t.cls === cls && t.name === scenario);
  return idx >= 0 ? badgeAt(idx) : undefined;
}

/** Registered scenario names for one e2e class, in registry (badge) order —
 *  lets the spec browser (test-specs.ts) mark registry entries that no longer
 *  exist in the suite source as RETIRED instead of dropping them. */
export function registryScenarios(cls: string): { name: string; testNumber: string }[] {
  return TEST_REGISTRY.flatMap((t, i) => (t.cls === cls ? [{ name: t.name, testNumber: badgeAt(i) }] : []));
}

/** The stable per-class badge for an e2e test session id (`<class>-<name>-<ts>`),
 *  or undefined when the id is not a registered test scenario. Keyed on the
 *  BASE scenario, so every model of one matrix row shares its badge (E2 for
 *  both `reasoning` and `reasoning@sonnet`) — badges number SCENARIOS, and a
 *  new model must not renumber them. */
export function testNumber(id: string): string | undefined {
  const parsed = parseTestSessionId(id);
  if (!parsed) return undefined;
  return registryTestNumber(parsed.cls, parsed.base);
}

/** Which agent CLI a TEST session class belongs to. The session id is
 *  AUTHORITATIVE where it exists — see deriveAgentKind. */
const CLASS_AGENT_KIND: Record<string, AgentKind> = {
  "claude-e2e": "claude",
  "codex-e2e": "codex",
  "openclaw-e2e": "openclaw",
  "opencode-e2e": "opencode",
  "goose-e2e": "goose",
  // The drill drives `claude -p` (its T-LLM is Anthropic on the subscription).
  "local-model-e2e": "claude",
  // Also `claude -p`, its main model pointed at the declared local Ollama.
  "local-main-model-e2e": "claude",
};

/** The agents (the generated copy of the agent registry, scripts/agents/agent-registry.mjs). */
export const AGENT_KINDS = AGENTS;
export type AgentKind = Agent;

/**
 * Which agent CLI produced a session.
 *
 * TWO SIGNALS, IN PRECEDENCE ORDER — and the order is load-bearing:
 *
 * 1. THE SESSION-ID CLASS, when this is a registered e2e test session. This is
 *    authoritative because the harness mints the id itself.
 * 2. The Track A (model-context) EMITTER, for everything else.
 *
 * WHY (1) HAD TO BE ADDED (2026-08-05): the emitter alone USED to determine the
 * agent, because there was exactly one agent per proxy — anthropic-proxy ⇒
 * Claude Code, openai-proxy ⇒ Codex. That stopped being true when OpenClaw and
 * OpenCode joined: both speak genuine Anthropic Messages, so all THREE ride the
 * anthropic-proxy and the emitter can no longer tell them apart. Left as-is,
 * every OpenClaw and OpenCode session would have been badged "claude".
 *
 * Within (2) `openai-proxy` is still checked FIRST: `coerceEvent` repairs a
 * *missing* emitter on model-context kinds to `anthropic-proxy`, so an explicit
 * openai-proxy event is the stronger signal in a mixed/repaired session.
 *
 * 3. The LAUNCHER's `launch_posture.target` (2026-09-25), when no model-proxy
 *    event exists at all: a launcher session that ended before its first model
 *    call (a drill TIMEOUT at launch) still says which agent the launcher
 *    started. It ranks LAST because it names the requested target, not the
 *    traffic, and only a known AgentKind counts.
 *    EXCEPT for `openclaw` / `opencode` (2026-09-28): their traffic IS
 *    anthropic-proxy traffic, so the emitter cannot outvote the launcher there,
 *    and every live OpenClaw session was badged "claude". A posture naming one
 *    of them outranks the anthropic-proxy emitter (still not openai-proxy).
 *
 * Undefined when no signal is present (an OS-interceptor-only trace) — the
 * badge stays honest rather than guessing.
 */
export function deriveAgentKind(events: ManduEvent[], sessionId?: string): AgentKind | undefined {
  if (sessionId !== undefined) {
    const parsed = parseTestSessionId(sessionId);
    const byClass = parsed ? CLASS_AGENT_KIND[parsed.cls] : undefined;
    if (byClass) return byClass;
  }
  if (events.some((e) => e.emitter === "openai-proxy")) return "codex";
  const posture = events.find((e) => e.kind === "launch_posture") as { target?: unknown } | undefined;
  const target = posture?.target;
  if (target === "openclaw" || target === "opencode" || target === "goose") return target;
  if (events.some((e) => e.emitter === "anthropic-proxy")) return "claude";
  return typeof target === "string" && (AGENT_KINDS as readonly string[]).includes(target) ? (target as AgentKind) : undefined;
}

/** Which browser agent a TEST session class drove (the drill suite's
 *  browser-jev: the real jev-ultrafast). */
const CLASS_BROWSER_AGENT: Record<string, string> = {
  "browser-jev-e2e": "jev",
};

/**
 * Which browser agent drove the session, for the sidebar's badge
 * (dashboard.md §4.10.7): a browser agent is a program the launcher starts
 * as `--target shell` behind the DevTools relay, so it is no AgentKind and
 * `deriveAgentKind` finds nothing. In order: the session-id class (the
 * harness minted it), then `browser` for a launch whose posture lists the
 * relay live (`cdp-relay`; the launcher cannot tell which program it is).
 * A drill run's record can say more (its target, own-arbiter-source.ts).
 * Undefined for every other session.
 */
export function deriveBrowserAgent(events: ManduEvent[], sessionId?: string): string | undefined {
  if (sessionId !== undefined) {
    const parsed = parseTestSessionId(sessionId);
    const byClass = parsed ? CLASS_BROWSER_AGENT[parsed.cls] : undefined;
    if (byClass) return byClass;
  }
  const posture = events.find((e) => e.kind === "launch_posture") as { live?: unknown } | undefined;
  return Array.isArray(posture?.live) && posture.live.includes("cdp-relay") ? "browser" : undefined;
}

/** What the session is within its batch: the launcher's
 *  `launch_posture.batchMember` (MANDU_BATCH_MEMBER), shape-checked; the key
 *  is agent-independent (the watch runner's) but still only ever inserted as
 *  text. Undefined when no posture event names one. */
const BATCH_MEMBER_KEY_RE = /^[A-Za-z0-9][A-Za-z0-9@#._-]{0,79}$/;
export function deriveBatchMember(events: ManduEvent[]): { kind: "scenario" | "posture"; key: string } | undefined {
  const posture = events.find((e) => e.kind === "launch_posture") as { batchMember?: unknown } | undefined;
  const m = posture?.batchMember as { kind?: unknown; key?: unknown } | undefined;
  if (!m || (m.kind !== "scenario" && m.kind !== "posture") || typeof m.key !== "string" || !BATCH_MEMBER_KEY_RE.test(m.key)) return undefined;
  return { kind: m.kind, key: m.key };
}

/**
 * Which execution runtime a session ran under — `"docker"` (the containerized
 * rig) or `"host"` (dev box directly) — from the `runtime` tag the e2e harness
 * stamps on the events it emits (buildSeedEvent/buildAssertionEvent). A docker
 * container writes into the host arbiter's shared event dir, so this tag is the
 * ONLY thing that distinguishes a docker session from a host one. Undefined when
 * no event carries it (non-e2e traffic), so the sidebar badges only what it knows.
 */
export function deriveRuntime(events: ManduEvent[]): "docker" | "host" | undefined {
  return events.find((e) => e.runtime)?.runtime;
}

/**
 * WHO started the session — `"ci"` (a GitLab pipeline job) or `"local"` (a human on
 * the dev box) — from the `origin` tag the e2e harness stamps on the events it emits
 * (buildSeedEvent/buildAssertionEvent). Orthogonal to `deriveRuntime`: a CI run is
 * ALSO a docker run, so this answers WHO while runtime answers WHERE.
 *
 * It matters when one host is both the CI runner and a dev box: a CI batch and
 * a hand-run batch land in the SAME arbiter event dir — so without this tag they are
 * indistinguishable in the sidebar. Undefined when no event carries it (non-e2e
 * traffic, or sessions recorded before this field existed), so the sidebar badges
 * only what it actually knows.
 */
export function deriveOrigin(events: ManduEvent[]): "ci" | "local" | undefined {
  return events.find((e) => e.origin)?.origin;
}

/**
 * The session's tenant (policy-surface.md §2.7): the arbiter's
 * summary `hint` when it carries one (the first stamped event, computed
 * server-side), else the first stamped event in `events`. Undefined for an
 * unstamped session — the caller then falls back to the id-prefix tags.
 */
export function deriveTenant(events: ManduEvent[], hint?: unknown): "live" | "test" | undefined {
  if (hint === "live" || hint === "test") return hint;
  const stamped = events.find((e) => e.tenant === "live" || e.tenant === "test");
  return stamped?.tenant;
}

/**
 * Tags for the sidebar, reconciled with the tenant stamp: a `test` tenant
 * always carries the `"test"` tag (so every tags consumer — sections, plain
 * wording, delete confirms — keeps working with no further change); a `live`
 * tenant never does, even for an id that matches a test prefix (the stamp is
 * what the minting process KNEW; the prefix is a guess). Unstamped → the
 * id-derived tags as before.
 */
export function tenantedTags(
  id: string,
  tenant: "live" | "test" | undefined,
  events?: readonly ManduEvent[],
): string[] | undefined {
  const byId = sessionTags(id);
  if (tenant === "test") return byId?.includes("test") ? byId : ["test", ...(byId ?? [])];
  // A live stamp means a human's run: no test tag AND no suite-class tag — a
  // suite badge on a live row would be the id-prefix guess the stamp refutes.
  // EXCEPT a harness FRAGMENT (2026-09-28): a test-named session with no
  // conversation and no launch in it — only side traffic (a U-LLM inspection,
  // net events) a test run sent to the live arbiter, which stamped it with
  // its own tenant. Nobody launched anything there, so the stamp knows
  // nothing the id does not; it files with the tests (found live: twelve
  // `claude-e2e-*` fragments from 2026-09-05 in the Live list).
  if (tenant === "live") return byId?.includes("test") && events !== undefined && isHarnessFragment(events) ? byId : undefined;
  return byId;
}

/** No model conversation and no launcher posture: side traffic only. */
function isHarnessFragment(events: readonly ManduEvent[]): boolean {
  return events.length > 0 && !events.some((e) => e.kind === "tllm_call" || e.kind === "launch_posture");
}

/**
 * Derive a sidebar label from a session's events — the first user prompt, so the
 * list reads like a task list ("Read invoice.txt and tell me where to pay")
 * rather than a list of `<ts>-<pid>` scope ids. Prefers the first CONVERSATION
 * T-LLM call: an interactive session OPENS with tool-less side calls (the
 * startup quota probe, title generation), and taking the literal first call
 * labeled every TUI session "quota" (found live 2026-07-11, the claude-e2e
 * interactive scenarios). `callShape.toolCount > 0` is the structural
 * conversation signal (dual-lanes §side-calls); typeahead also carries the
 * battery but needs a prior completed turn, so it is never first. Events
 * predating callShape keep the old first-call behavior; falls back to the
 * first event with any input. `events` is expected in canonical order.
 * Returns null if nothing usable.
 */
export function deriveSessionLabel(events: ManduEvent[], sessionId?: string): string | null {
  return sessionLabel(events, sessionId).label;
}

/** The label fields of a SessionRef: `deriveSessionLabel` and its source. */
export function sessionLabelFields(events: ManduEvent[], sessionId?: string): Pick<SessionRef, "label" | "labelFrom"> {
  const { label, from } = sessionLabel(events, sessionId);
  return from ? { label, labelFrom: from } : { label };
}

function sessionLabel(events: ManduEvent[], sessionId?: string): { label: string | null; from: SessionLabelFrom | null } {
  const system = sessionId !== undefined ? systemLogKind(sessionId) : undefined;
  if (system) return { label: SYSTEM_LOG_LABEL[system], from: "system" };
  const tllm =
    events.find(
      (e) => e.kind === "tllm_call" && e.input?.symbolized && (e.callShape?.toolCount ?? 0) > 0,
    ) ?? events.find((e) => e.kind === "tllm_call" && e.input?.symbolized);
  if (tllm?.input) {
    const prompt = firstUserPrompt(tllm.input.symbolized);
    if (prompt) return { label: truncateLabel(prompt), from: "prompt" };
  }
  // No conversation: only events that DESCRIBE the session may name it — the
  // launcher's posture line ("claude launch: 8 rung(s) live …") or a U-LLM
  // inspection. Any other input is DATA the session touched (a file's
  // contents, a command line), and labeling a row with the first line of a
  // .env file or a source header (found 2026-09-28: "STRIPE_KEY=…", "/**")
  // tells the reader nothing about the session.
  const posture = events.find((e) => e.kind === "launch_posture" && e.input?.symbolized);
  const postureLine = posture?.input ? cleanLine(posture.input.symbolized) : null;
  if (postureLine) return { label: truncateLabel(postureLine), from: "posture" };
  const ullm = events.find((e) => e.kind === "ullm_call" && e.input?.symbolized);
  const inspected = ullm?.input ? cleanLine(ullm.input.symbolized) : null;
  return inspected ? { label: truncateLabel(`U-LLM inspection of ${inspected}`), from: "inspection" } : { label: null, from: null };
}

/** The first non-blank line of an event's symbolized input. */
function cleanLine(text: unknown): string | null {
  if (typeof text !== "string") return null;
  const line = text.split("\n").map((l) => l.trim()).find((l) => l !== "");
  return line ?? null;
}

/**
 * Event logs that are not agent sessions: events emitted with no session to
 * attach to, under a fixed or minted fallback id. They are real logs (the
 * sidebar keeps them) but read as sessions only by accident, so the sidebar
 * files them in their own "System logs" group with a descriptive label.
 *   - `arbiter-admin`: the arbiter's admin audit log (ADMIN_SESSION_ID —
 *     human approval verdicts, their consumption, settings changes);
 *   - `net-guard`: the kernel net-guard's fallback when MANDU_SESSION_ID is
 *     unset (mandu-net-guard.rs);
 *   - `eg_<base36>_<base36>`: net-proxy's minted fallback id for a proxy
 *     started without a session (net-proxy/src/proxy.ts).
 */
export type SystemLogKind = "admin" | "net-guard" | "net-proxy";

export function systemLogKind(id: string): SystemLogKind | undefined {
  if (id === "arbiter-admin") return "admin";
  if (id === "net-guard") return "net-guard";
  if (/^eg_[0-9a-z]+_[0-9a-z]+$/.test(id)) return "net-proxy";
  return undefined;
}

const SYSTEM_LOG_LABEL: Record<SystemLogKind, string> = {
  admin: "Admin log: approval verdicts and settings changes",
  "net-guard": "Network guard events with no session",
  "net-proxy": "Network proxy events with no session",
};

/**
 * Derive the SessionRef verdict fields from a session's LAST `assertion` event
 * (the e2e harness writes one per session; a re-run's later event wins — same
 * rule as the §4.13 panel's toAssertionSummary):
 *   - `checksVerdict`: "fail" iff any check is a BLOCKING fail (warn/skip pass);
 *   - `checksFailed`: WHICH groups the failing checks belong to (a security
 *     check refines to `security-<aspect>` when it carries one — the §4.13
 *     split), ordered blocking-first, omitted when nothing failed;
 *   - `historyFidelity`: the same rule over just the history-fidelity oracle's
 *     checks (HISTORY_FIDELITY_ASSERTS), omitted when none ran.
 * Returns {} for a session with no assertion event (a normal, non-e2e session),
 * so the spread into a SessionRef adds nothing.
 */
const CHECK_GROUP_ORDER = [
  "security-integrity", "security-confidentiality", "security", "utility", "warned", "fidelity",
];
const checkGroup = (c: AssertionCheck): string =>
  c.category === "security" && (c.aspect === "integrity" || c.aspect === "confidentiality")
    ? `security-${c.aspect}`
    : c.category;

export function assertionVerdicts(
  events: ManduEvent[],
): Pick<SessionRef, "checksVerdict" | "checksFailed" | "historyFidelity"> {
  const assertionEvents = events.filter((e) => e.kind === "assertion");
  const latest = assertionEvents[assertionEvents.length - 1];
  const checks: AssertionCheck[] = Array.isArray(latest?.assertions) ? latest.assertions : [];
  if (checks.length === 0) return {};
  const verdict = (cs: AssertionCheck[]): "pass" | "fail" =>
    cs.some((c) => c.status === "fail") ? "fail" : "pass";
  const failed = [...new Set(checks.filter((c) => c.status === "fail").map(checkGroup))].sort(
    (a, b) => CHECK_GROUP_ORDER.indexOf(a) - CHECK_GROUP_ORDER.indexOf(b),
  );
  const fidelity = checks.filter((c) => c.assert && HISTORY_FIDELITY_ASSERTS.has(c.assert));
  return {
    checksVerdict: verdict(checks),
    ...(failed.length ? { checksFailed: failed } : {}),
    ...(fidelity.length ? { historyFidelity: verdict(fidelity) } : {}),
  };
}

