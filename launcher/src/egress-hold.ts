/**
 * egress-hold — the launcher's default for the net-proxy's held request
 * (docs/design/confidentiality/egress-hold.md "The default", 2026-10-17).
 *
 * The net-proxy can keep a request whose only obstacle is an unanswered
 * Approvals card waiting for the human's answer (`MANDU_EGRESS_HOLD_MS`,
 * interceptors/net-proxy egress.ts `EgressHold`). Holding only helps when a
 * person is there to answer: in a run nobody watches, every unanswered card
 * would keep the agent's command waiting for nothing. So the launcher decides
 * once, here, and hands the proxy its answer in its environment; the proxy's
 * own default stays 0 (off), so a proxy started without the launcher never
 * holds.
 *
 *   1. `MANDU_EGRESS_HOLD_MS` set (non-empty; config `egress-hold-ms`): that
 *      value, passed as is (0 included: off). The proxy parses and caps it.
 *   2. CI (`runsInCi`, the update check's own test): 0.
 *   3. stdout not a terminal (piped, captured, an editor's ACP stream): 0.
 *   4. a known one-shot invocation (`claude -p`, `codex exec`, `openclaw
 *      agent`, `opencode run`): 0.
 *   5. otherwise, an interactive session on a terminal: 60 s.
 *
 * Steps 3 and 4 are the reply filter's own notion of an interactive run
 * (interceptors/reply-filter/src/print-mode.ts `decideMode`: stdout is a TTY
 * and the command is not a known print-mode invocation → the PTY relay), so a
 * session holds exactly when its reply is relayed as a live TUI.
 *
 * Holding releases nothing (egress-hold.md "What it does not widen"): every
 * outcome is the one the same request, sent again after the answer, gets. The
 * choice here changes only how long a refusal may take, never what is sent.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code. `oneShotRun` is
 * a pure copy of print-mode.ts step 4 (independent TS package roots);
 * test/unit/egress-hold.test.ts checks the two agree.
 */
import { runsInCi } from "./update-check.js";

type Env = Record<string, string | undefined>;

/** The net-proxy's variable (server-main.ts reads it). */
export const EGRESS_HOLD_ENV = "MANDU_EGRESS_HOLD_MS";
/** The hold of an interactive session (ms): below Claude Code's 120 s Bash
 *  limit, long enough to read a card and answer it. */
export const INTERACTIVE_EGRESS_HOLD_MS = 60_000;
/** The proxy's cap (net-proxy egress.ts EGRESS_HOLD_MAX_MS; the test pins
 *  the two equal). */
export const EGRESS_HOLD_MAX_MS = 300_000;

/** What the launcher hands the net-proxy, and why. */
export interface EgressHoldChoice {
  /** The `MANDU_EGRESS_HOLD_MS` value the proxy gets. */
  ms: string;
  /** `explicit`: the user's value; `interactive`: the 60 s default;
   *  `unattended`: off because nobody is likely watching. */
  source: "explicit" | "interactive" | "unattended";
  /** One phrase for the verbose line. */
  why: string;
}

function basename(p: string): string {
  const parts = p.split("/");
  return parts[parts.length - 1] ?? "";
}

function firstSubcommand(cmd: readonly string[]): string | null {
  for (const arg of cmd.slice(1)) if (!arg.startsWith("-")) return arg;
  return null;
}

// PROVENANCE: copied from interceptors/reply-filter/src/print-mode.ts
// decideMode step 4 (the known print-mode invocations); keep them together.
/** The agent command is a known one-shot (linear output, nobody at a
 *  prompt): the phrase naming it, or null. Pure. */
export function oneShotRun(cmd: readonly string[]): string | null {
  const base = basename(cmd[0] ?? "");
  if (base === "claude" && cmd.some((a) => a === "-p" || a === "--print")) return "claude print mode (-p/--print)";
  if (base === "codex" && firstSubcommand(cmd) === "exec") return "codex exec";
  if (base === "openclaw" && firstSubcommand(cmd) === "agent") return "openclaw agent";
  if (base === "opencode" && firstSubcommand(cmd) === "run") return "opencode run";
  return null;
}

/** The launcher's hold for this launch (the rules above). Pure. */
export function launcherEgressHold(input: { env: Env; argv: readonly string[]; stdoutIsTTY: boolean }): EgressHoldChoice {
  const raw = (input.env[EGRESS_HOLD_ENV] ?? "").trim();
  if (raw !== "") return { ms: raw, source: "explicit", why: `${EGRESS_HOLD_ENV}=${raw}` };
  if (runsInCi(input.env)) return { ms: "0", source: "unattended", why: "CI" };
  if (!input.stdoutIsTTY) return { ms: "0", source: "unattended", why: "the output is not a terminal" };
  const oneShot = oneShotRun(input.argv);
  if (oneShot !== null) return { ms: "0", source: "unattended", why: `a one-shot run (${oneShot})` };
  return { ms: String(INTERACTIVE_EGRESS_HOLD_MS), source: "interactive", why: "an interactive session on a terminal" };
}

/** The launch line's clause for a hold, "" when there is none (a value the
 *  proxy reads as 0 included). Pure. */
export function egressHoldClause(choice: EgressHoldChoice): string {
  const n = Number(choice.ms);
  if (!Number.isFinite(n) || n <= 0) return "";
  const s = Math.max(1, Math.round(Math.min(n, EGRESS_HOLD_MAX_MS) / 1000));
  return ` (a request waiting on an Approvals card is held up to ${s} s for your answer: ${choice.why})`;
}
