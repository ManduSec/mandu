/**
 * live-shared — the harness plumbing every LIVE claude suite needs: the
 * arbiter→anthropic-proxy bridge, the real-upstream forwarder, and the shared
 * gate constants. Extracted VERBATIM from claude-e2e.test.ts, where it was
 * duplicated into the (since-retired) claude-interactive probe — one copy, N callers.
 *
 * Mandu (tests/). Pure plumbing: no test logic, no scenario knowledge.
 */

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Readable } from "node:stream";

import { ArbiterClient } from "../../arbiter/ipc/client.js";
import type { UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import type { ArbiterClientAdapter as AnthropicProxyArbiterAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import type { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";

import { mintBatchId } from "./batch-id.js";
import { resolveRuntimeBase } from "../../arbiter/ipc/runtime-base.js";

/** The real Anthropic endpoint — the proxy's upstream, and the U-LLM's base. */
export const REAL_UPSTREAM = "https://api.anthropic.com";

/** A T-LLM the live claude suites can drive (`claude --model <id>`). */
export interface ModelSpec {
  /** Id-safe short name: the `@<slug>` suffix on a matrix run's key + session id. */
  slug: string;
  /** The exact `--model` argument (NEVER a date-suffixed variant). */
  id: string;
  /** Fan out ONLY to `driver: "interactive"` scenarios: the model a human
   *  actually runs the TUI with, whose prompt-compliance and thinking cadence
   *  are what the interactive oracles exist to see — bounded to the four
   *  interactive scenarios because of its price (Fable). */
  interactiveOnly?: boolean;
  /**
   * Wall-clock multiplier for every deadline this model's runs sit behind — the
   * child-process budget, the node:test timeout, and the interactive driver's
   * per-turn wait.
   *
   * NOT a nicety. The bigger models run adaptive thinking, so a turn opens with
   * a long SILENT pause before the first token. Left at haiku's budgets, an opus
   * turn blows the driver's 30s turnTimeoutMs, the run records fewer
   * conversation turns than it typed, and the oracle goes VACUOUS or red for a
   * timing reason that says nothing about the defense — the worst kind of red,
   * because it looks like a finding.
   */
  timeoutScale: number;
}

/**
 * The models the claude-e2e MODEL MATRIX can drive, base first.
 *
 * WHY A MATRIX AT ALL — the defense is enforced in the proxy, so most of it is
 * model-INdependent and re-running the whole battery per model would just
 * re-prove the same TypeScript at 3-5× the cost. Three things are NOT:
 *   1. the subscription (OAuth) request-shape check, which rejects a foreign
 *      block at system[0] — enforced on the MAIN-LOOP models (sonnet/opus),
 *      NOT on haiku (rewrite-request.ts appends the handling prompt for exactly
 *      this reason). Haiku-only live coverage can never exercise it;
 *   2. the wire shape: adaptive thinking puts `thinking` content blocks in the
 *      response stream that sse-rewrite.ts must pass through untouched while it
 *      rewrites tool_use block indices;
 *   3. the model's BEHAVIOUR under the handling prompt — does it treat a symbol
 *      as opaque rather than fabricating a plausible value, does it reach for
 *      inspect_symbol, does it still finish the task with an opaque symbol in
 *      hand. Security should be model-INVARIANT (it is structural); utility is
 *      the part that legitimately varies by tier, and that is the result worth
 *      having.
 * So only `modelAxis` scenarios fan out (claude-e2e.test.ts), and only headless
 * ones plus the single interactive scenario whose oracle a model can actually
 * move (interactive-reply-filter-live: adaptive thinking changes the STREAMING
 * CADENCE — a long silent pause then a burst — which is what the reply-filter's
 * PTY egress holds tokens across; haiku's steady stream may never produce the
 * timing that breaks it).
 *
 * Fable was deliberately absent until 2026-09-05 (10×/2× haiku's input/output
 * price; its distinctive shapes — always-on thinking, `refusal` stop_reason as
 * a 200 with empty content, `fallback` blocks — are covered by the frozen
 * replay fixture). It is now in the matrix as INTERACTIVE-ONLY: it is the
 * model the developer actually runs the TUI with, and the interactive
 * oracles (side-call classification, typeahead, the PTY relay under an
 * adaptive-thinking cadence, the U-LLM round-trip) are exactly what a model's
 * prompt compliance moves — so it fans out to the four interactive scenarios
 * and nothing else (the headless breadth stays on haiku).
 */
export const CLAUDE_MODELS: readonly ModelSpec[] = [
  { slug: "haiku", id: "claude-haiku-4-5", timeoutScale: 1 },
  { slug: "sonnet", id: "claude-sonnet-5", timeoutScale: 2 },
  { slug: "opus", id: "claude-opus-4-8", timeoutScale: 3 },
  { slug: "fable", id: "claude-fable-5-1", timeoutScale: 4, interactiveOnly: true },
];

/** The model EVERY scenario runs on — the full battery's breadth is about the
 *  DEFENSE, not the model, so it stays on the cheapest one. Its runs keep the
 *  historical un-suffixed key/session-id shape (`claude-e2e-<name>-<ts>`). */
export const BASE_MODEL: ModelSpec = CLAUDE_MODELS[0]!;

/**
 * Parse MANDU_E2E_MODELS (comma-separated slugs) into the EXTRA models the
 * `modelAxis` scenarios fan out to. The base model always runs, so it is
 * dropped here even if named; unset/empty ⇒ no extras ⇒ today's behaviour byte
 * for byte. An UNKNOWN slug throws rather than being skipped: a typo that
 * silently ran nothing would look exactly like a green matrix.
 */
export function extraModelsFromEnv(raw: string | undefined): ModelSpec[] {
  const want = (raw ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);
  const out: ModelSpec[] = [];
  for (const slug of want) {
    const spec = CLAUDE_MODELS.find((m) => m.slug === slug);
    if (!spec) {
      throw new Error(
        `MANDU_E2E_MODELS: unknown model "${slug}" — known slugs: ` +
          CLAUDE_MODELS.map((m) => m.slug).join(", "),
      );
    }
    if (spec.slug === BASE_MODEL.slug) continue; // always runs; not an "extra"
    if (!out.some((m) => m.slug === spec.slug)) out.push(spec);
  }
  // Registry order, so a run key / session id sorts predictably in the sidebar.
  return CLAUDE_MODELS.filter((m) => out.some((o) => o.slug === m.slug));
}

/** The bit of a suite's Scenario the matrix needs. Kept structural so this stays
 *  a PURE module a CI test can import — the suite files register live tests and
 *  start their pool at module scope, so they can never be imported for a helper. */
export interface MatrixScenario {
  name: string;
  modelAxis?: boolean;
  /** "interactive" scenarios drive a real TUI; a model marked
   *  `interactiveOnly` fans out to those alone (see CLAUDE_MODELS). */
  driver?: string;
}

/** One unit of work: a scenario driven on ONE model. */
export interface MatrixRun<S extends MatrixScenario> {
  /** The run key. See claude-e2e.test.ts `Run` for the three surfaces it joins. */
  name: string;
  scenario: S;
  model: ModelSpec;
}

/**
 * Expand scenarios into runs: every scenario on BASE_MODEL, plus a `modelAxis`
 * scenario once per extra model.
 *
 * The base run keeps the BARE scenario name as its key — that is what makes the
 * matrix additive rather than a migration: with no extras selected, every run
 * key, TAP title, session id and dashboard badge is byte-identical to the
 * pre-matrix suite.
 */
export function runsFor<S extends MatrixScenario>(
  scenarios: readonly S[],
  extra: readonly ModelSpec[],
): MatrixRun<S>[] {
  return scenarios.flatMap((scenario) => [
    { name: scenario.name, scenario, model: BASE_MODEL },
    ...(scenario.modelAxis
      ? extra
          .filter((model) => !model.interactiveOnly || scenario.driver === "interactive")
          .map((model) => ({ name: `${scenario.name}@${model.slug}`, scenario, model }))
      : []),
  ]);
}

/** Bridge the real arbiter IPC client to the anthropic-proxy's narrow Arbiter. */
export function anthropicBridge(
  client: ArbiterClient,
): ConstructorParameters<typeof AnthropicProxyArbiterAdapter>[0] {
  return {
    connect: () => client.connect(),
    classify: (req) => client.classify(req as never) as never,
    symbolize: (args) => client.symbolize(args),
    handlingPrompt: (mode?: string, capabilities?: { inspect?: boolean; policyTools?: boolean; exec?: boolean }) =>
      client.handlingPrompt(mode as never, capabilities),
    recordToolCall: (args) => client.recordToolCall(args),
    // Required once the proxy runs with a ViewMap (fsSync scenarios): the P3
    // sensitive-path gate asks the arbiter about EVERY absolute typed path, and
    // an absent op fails closed into /mandu/denied/unreachable sentinels —
    // every Write in the AgentView would be denied.
    fsPathDecision: (req) => client.fsPathDecision(req as never) as never,
    // Phase-0 exec gate (exec-routing.md §3): the proxy submits every Bash
    // command to this op. It is OPTIONAL on the Arbiter interface, so OMITTING it
    // typechecks but makes the proxy adapter fail CLOSED at runtime ("op not yet
    // landed") — blocking EVERY Bash command in the live harness. Forward it to
    // the real client so the exec gate actually runs against the arbiter.
    execGate: (req) => client.execGate(req as never) as never,
    // The SESSION-WATERMARK ops (Plan 8 net gate + Plan 9 on-disk label). Also
    // OPTIONAL on the interface — and omitting them does NOT fail closed, it makes
    // the adapter report "arbiter predates the watermark" and the gate NO-OP. So a
    // confidentiality scenario added here would find the network gate and the
    // derived-label hook silently DEAD, exactly the "wired to a posture nobody
    // runs" class the whole confidentiality suite exists to catch. Forward them so
    // the watermark is reachable the moment the axis is on.
    sessionEgressDecision: (req) => client.sessionEgressDecision(req as never) as never,
    labelWrittenPath: (req) => client.labelWrittenPath(req as never) as never,
    // The exec box's symbol-twin hints (symbol-twin-shell-blindness.md §4.1b).
    // OPTIONAL on the interface and UTILITY-ONLY — omitting it does not fail
    // closed, it silently makes the v2 note DEAD (the adapter reports "no
    // hints"), which is exactly what the first E49 run found (2026-09-18):
    // the box reported, the proxy never asked. Forward it.
    execTwinsFor: (command) => client.execTwinsFor(command),
    emit: async (event) => ({ seq: await client.emit(event as never) }),
    scanSecretValues: (text) => client.scanSecretValues(text),
    // the prompt filter (confidentiality-plan-15 §3.2), as the real client has it
    filterPrompt: (args: Parameters<ArbiterClient["filterPrompt"]>[0]) => client.filterPrompt(args),
    // The per-agent gate surface (gate-surface.ts), positional as the real
    // client takes it. OPTIONAL on the interface: omitting it does not fail
    // closed, it makes the proxy fall back to the UNION of every agent's
    // table, whose spec places no user text as the human's (plan 15 §3.1),
    // so the prompt filter's human segment, and its prompt floor, were dead
    // under this bridge (found 2026-10-02 by the prompt-secret scenarios:
    // postgres masked in the human's own text on OpenClaw and OpenCode).
    gateSurface: (sessionKey?: string) => client.gateSurface(sessionKey),
    close: () => client.close(),
  };
}

/** Bridge the real arbiter IPC client to the openai-proxy's narrow Arbiter —
 *  the codex twin of anthropicBridge, one copy for every codex suite. The
 *  security ops on the adapter interface are OPTIONAL (so the deployed adapter
 *  can fail closed against an older arbiter build), which means a bridge that
 *  omits one still typechecks but blocks at runtime — keep this the single
 *  place that enumerates them. */
export function openaiBridge(
  client: ArbiterClient,
): ConstructorParameters<typeof OpenAiProxyArbiterAdapter>[0] {
  return {
    connect: () => client.connect(),
    classify: (req) => client.classify(req as never) as never,
    symbolize: (args) => client.symbolize(args),
    handlingPrompt: (mode?: string, capabilities?: { inspect?: boolean; policyTools?: boolean; exec?: boolean }) =>
      client.handlingPrompt(mode as never, capabilities),
    // Phase-0 exec gate (exec-routing.md §3): the openai-proxy submits each
    // Codex shell/local_shell command to this op; if absent the adapter fails
    // CLOSED and EVERY shell command is rewritten to the block sentinel.
    execGate: (req) => client.execGate(req as never) as never,
    // The adapter expects `emit(event)` → `{seq}`; the real IPC client's emit
    // resolves the BARE seq number. Without the wrap the adapter degrades to a
    // no-op and no Codex events reach the arbiter / dashboard.
    emit: async (event) => ({ seq: await client.emit(event as never) }),
    // The prompt filter (plan 15 §3.2): without it the adapter throws and the
    // proxy refuses EVERY request with a 502 ("refusing to forward the prompt
    // unfiltered"): codex-e2e on codex 0.160 failed every turn (2026-10-07).
    filterPrompt: (args) => client.filterPrompt(args as never) as never,
    close: () => client.close(),
  };
}

/** An UpstreamFetcher that forwards to a real origin (http or https). */
export function realForwarder(origin: string): UpstreamFetcher {
  const url = new URL(origin);
  const isHttps = url.protocol === "https:";
  return async ({ method, path, headers, body }) => {
    const mod = isHttps ? await import("node:https") : await import("node:http");
    return new Promise((resolve, reject) => {
      const r = mod.request(
        { protocol: url.protocol, hostname: url.hostname, port: url.port ? Number(url.port) : isHttps ? 443 : 80, method, path, headers: { ...headers, host: url.host } },
        (up) => resolve({ status: up.statusCode ?? 502, headers: up.headers, body: up as unknown as Readable }),
      );
      r.on("error", reject);
      r.end(body);
    });
  };
}

/** Is a `claude` binary on PATH? (Gate shared by every live claude suite.) */
export const CLAUDE_AVAILABLE = (() => {
  try {
    return spawnSync("claude", ["--version"], { encoding: "utf8", timeout: 15000 }).status === 0;
  } catch {
    return false;
  }
})();

// Runtime-instances resolution (runtime-instances.md; mirrors arbiter/ipc/instance.ts
// resolveArbiterSock): explicit env → the promoted `current` rendezvous → legacy path.
// The base follows the one runtime-base rule (runtime-instances.md §3b): on
// macOS the per-user TMPDIR is too long, so it is the private /tmp/mandu-<uid>.
const MANDU_BASE = resolveRuntimeBase(process.env).base;
export const SHARED_ARBITER_SOCK =
  process.env["MANDU_ARBITER_SOCK"] ??
  (existsSync(join(MANDU_BASE, "current", "arbiter.sock"))
    ? join(MANDU_BASE, "current", "arbiter.sock")
    : join(MANDU_BASE, "arbiter.sock"));

// ── The POSTURE GUARD (the int×conf fold groups) ──────────────────────────────
// A grouped live run (drills:live:int-smoke / drills:live:full) proves a SPECIFIC
// cell of the int×conf matrix, and the cell is decided by env the SHARED
// arbiter was booted with — not by anything this suite controls. A group run
// against the wrong posture would go green while proving a different fold:
// exactly the "chokepoint wired to a posture nobody runs" class. So when a
// group declares an expectation (MANDU_E2E_EXPECT_CONF / _INT, "0"|"1"), the
// suite probes the arbiter's `hello` posture fields and HARD-FAILS on any
// mismatch — including an arbiter too old to report posture, and (in the
// caller) an arbiter that is missing entirely. A skip here would be the same
// silent-green trap the guard exists to close.

/** The posture a grouped run expects of the SHARED arbiter. */
export interface ExpectedPosture {
  conf?: boolean;
  int?: boolean;
}

/** Parse MANDU_E2E_EXPECT_CONF / MANDU_E2E_EXPECT_INT ("0"|"1"; unset or
 *  empty = no expectation). Returns null when neither is set (ungrouped runs
 *  keep today's behavior: whatever posture the shared arbiter happens to run). */
export function expectedPostureFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): ExpectedPosture | null {
  const parse = (v: string | undefined): boolean | undefined =>
    v === undefined || v === "" ? undefined : v === "1";
  const conf = parse(env["MANDU_E2E_EXPECT_CONF"]);
  const int = parse(env["MANDU_E2E_EXPECT_INT"]);
  if (conf === undefined && int === undefined) return null;
  return { ...(conf !== undefined ? { conf } : {}), ...(int !== undefined ? { int } : {}) };
}

/** Probe the arbiter at `sock` and throw unless its hello() posture matches.
 *  The client's per-op deadline makes a wedged arbiter fail closed here too. */
export async function assertArbiterPosture(
  sock: string,
  expect: ExpectedPosture,
): Promise<void> {
  const client = new ArbiterClient(sock);
  try {
    await client.connect();
    const hello = await client.hello();
    const check = (
      axis: "confidentiality" | "integrity",
      expected: boolean | undefined,
      actual: boolean | undefined,
    ) => {
      if (expected === undefined) return;
      if (actual === undefined) {
        throw new Error(
          `posture guard: the arbiter at ${sock} predates posture reporting ` +
            `(hello() has no '${axis}' field) but this run EXPECTS ${axis}=${expected} — ` +
            `an unknown posture must not pass as the right one. Update/restart the arbiter.`,
        );
      }
      if (actual !== expected) {
        throw new Error(
          `posture guard: this run EXPECTS ${axis}=${expected} but the arbiter at ${sock} ` +
            `runs ${axis}=${actual} — refusing to run the wrong fold silently. ` +
            `Restart the arbiter with the right MANDU_${axis === "integrity" ? "INTEGRITY" : "CONFIDENTIALITY"}.`,
        );
      }
    };
    check("confidentiality", expect.conf, hello.confidentiality);
    check("integrity", expect.int, hello.integrity);
  } finally {
    client.close();
  }
}

/** Batch id shared by every scenario of one suite process, so the dashboard
 *  sidebar groups them as one batch. "Run e2e" sets MANDU_BATCH_ID (its
 *  runId); a standalone run mints a per-process `YYYYMMDD-HHMM-<4hex>` id
 *  (batch-id.ts — it names the kept fsSync workspace dir, so it is built to be
 *  read in a path). Forwarded to the proxy as x-mandu-batch-id. */
export const BATCH_ID = process.env["MANDU_BATCH_ID"] || mintBatchId();

/** Execution runtime this suite process runs under, stamped on every emitted
 *  event so the dashboard can badge sessions/batches docker-vs-host. The
 *  dashboard's docker-mode TestRunner sets MANDU_E2E_RUNTIME=docker on the
 *  container; unset (host runs / dev box) → "host". See docs/design/testing/docker-e2e.md §2. */
export const E2E_RUNTIME: "docker" | "host" =
  process.env["MANDU_E2E_RUNTIME"] === "docker" ? "docker" : "host";

/** WHO started this suite process, stamped on every emitted event so the dashboard
 *  can badge a batch "CI" and a human can tell at a glance whether a red batch was
 *  a pipeline or their own run. Orthogonal to E2E_RUNTIME (a CI run is also a
 *  docker run — that one says WHERE, this says WHO).
 *
 *  Explicit MANDU_E2E_ORIGIN wins; otherwise fall back to `$CI`, which GitLab
 *  sets to "true" in every job. The fallback is what keeps this honest: a new CI
 *  job that forgets the explicit var still gets badged, rather than silently
 *  masquerading as a local run. See docs/design/testing/docker-e2e.md §1.6. */
export const E2E_ORIGIN: "ci" | "local" =
  process.env["MANDU_E2E_ORIGIN"] === "ci" || process.env["CI"] === "true" ? "ci" : "local";
