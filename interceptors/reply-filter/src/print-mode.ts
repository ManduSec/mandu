/**
 * print-mode — the pure TTY-safety decision for the user-reply egress wrapper.
 *
 * Filtering interposes a PIPE on the agent's stdout, which is exactly right
 * when stdout is already a pipe (captured / scripted runs) but BREAKS a
 * full-screen interactive TUI that needs a real TTY (interactive `claude`).
 * With the launcher enabling the reply filter BY DEFAULT, this module decides
 * per invocation — from observable facts only — HOW to interpose:
 *
 *   - "pipe"        → classic filtering: the child's stdout is a pipe through
 *                     the desymbolizer. Right for piped/captured runs and for
 *                     known PRINT-mode invocations on a TTY.
 *   - "pty"         → PTY relay: the child runs under `script(1)` (util-linux
 *                     on Linux, BSD on macOS: pty-relay.ts, bsd-relay.ts)
 *                     so it keeps a REAL terminal (full-screen TUIs work,
 *                     resize/raw-mode/exit codes propagate) while script's
 *                     stdout — the relayed session — flows through the
 *                     desymbolizer. Right for interactive runs on a TTY.
 *   - "passthrough" → zero interposition (symbols stay opaque; nothing leaks —
 *                     this is a UTILITY-ONLY surface). The fallback when the
 *                     relay is disabled or unavailable.
 *
 * Decision order:
 *   1. force (env MANDU_REPLY_FILTER_FORCE=1, read by the CALLER and passed
 *      in) → "pipe". The escape hatch for tests / setups where the caller
 *      knows a pipe on stdout is fine.
 *   2. ptyOverride "1" (env MANDU_REPLY_FILTER_PTY=1) → "pty" even when
 *      stdout is not a TTY (tests / nested relays).
 *   3. stdout NOT a TTY (piped / captured) → "pipe". A pipe is exactly where
 *      the filter works; nothing downstream expected a TTY anyway.
 *   4. stdout IS a TTY → "pipe" for KNOWN PRINT-mode invocations:
 *        - a `claude` command in print mode: basename(argv[0]) === "claude"
 *          AND `-p` / `--print` appears anywhere in argv. Deliberately simple
 *          heuristic (we do not model claude's full flag grammar): a `-p`
 *          consumed by some nested construct would over-match, but
 *          mis-filtering a print run only costs TTY-ness on output that
 *          prints linearly anyway.
 *        - a `codex` command whose FIRST SUBCOMMAND (first non-flag arg after
 *          argv[0]) is `exec`.
 *        - an `openclaw` command whose first subcommand is `agent` (the
 *          one-shot `openclaw agent --local … -m '<prompt>'` turn — linear
 *          output; the TUI is the separate `openclaw tui` subcommand).
 *        - an `opencode` command whose first subcommand is `run` (the
 *          one-shot `opencode run …` — non-interactive by design; the TUI is
 *          the flagless default command, which stays on the PTY relay).
 *      A source-checkout OpenClaw launched as `node openclaw.mjs agent …`
 *      is NOT recognized (basename is `node`) and takes the PTY relay — the
 *      same accepted limitation any interpreter-launched agent has here.
 *   5. anything else on a TTY (an interactive TUI) → "pty", unless
 *      ptyOverride "0" (env MANDU_REPLY_FILTER_PTY=0) opts the relay out →
 *      "passthrough" (the pre-relay behavior: a broken TUI is worse than
 *      opaque symbols, and passthrough leaks nothing).
 *
 * The caller (run.ts) still degrades "pty" → "passthrough" when the relay
 * backend is unavailable (no vetted backend on this platform, no `script` on
 * PATH, or a stdin BSD script cannot start on). Only stdout is consulted
 * here; whether a non-TTY stdin should pick "pipe" is an open question
 * (docs/design/agents/pty-relay.md §4).
 *
 * PURE on purpose: src/run.ts executes main() at module load, so tests must
 * never import it. run.ts reads process.stdout.isTTY and the env and passes
 * them in; this module touches no process state.
 */

/** How the wrapper interposes on the child's output. */
export type ReplyFilterMode = "pipe" | "pty" | "passthrough";

export interface FilterDecision {
  mode: ReplyFilterMode;
  /** Human-readable why — surfaced on stderr by the wrapper's note(). */
  reason: string;
}

export interface DecideModeOpts {
  /** MANDU_REPLY_FILTER_FORCE=1 at the call site → always pipe-filter. */
  force?: boolean;
  /** MANDU_REPLY_FILTER_PTY at the call site: "1" forces the PTY relay,
   *  "0" disables it (interactive TUIs fall back to passthrough). */
  ptyOverride?: string;
}

/** POSIX basename of an argv[0] path ("" stays ""). */
function basename(p: string): string {
  const parts = p.split("/");
  return parts[parts.length - 1] ?? "";
}

/** First non-flag argument after argv[0] (the CLI subcommand), or null. */
function firstSubcommand(cmd: string[]): string | null {
  for (const arg of cmd.slice(1)) {
    if (!arg.startsWith("-")) return arg;
  }
  return null;
}

/**
 * Decide how the wrapper should interpose on the child's output. Env knobs are
 * read by the CALLER and passed in — this function stays pure.
 */
export function decideMode(
  cmd: string[],
  stdoutIsTTY: boolean,
  opts: DecideModeOpts = {},
): FilterDecision {
  if (opts.force) {
    return {
      mode: "pipe",
      reason: "MANDU_REPLY_FILTER_FORCE=1 — pipe filtering forced",
    };
  }
  if (opts.ptyOverride === "1") {
    return {
      mode: "pty",
      reason: "MANDU_REPLY_FILTER_PTY=1 — PTY relay forced",
    };
  }
  if (!stdoutIsTTY) {
    return {
      mode: "pipe",
      reason: "stdout is not a TTY (piped/captured run) — a pipe is where the filter works",
    };
  }
  const base = basename(cmd[0] ?? "");
  if (base === "claude" && cmd.some((a) => a === "-p" || a === "--print")) {
    return {
      mode: "pipe",
      reason: "claude PRINT-mode run (-p/--print) on a TTY — linear output, safe to pipe",
    };
  }
  if (base === "codex" && firstSubcommand(cmd) === "exec") {
    return {
      mode: "pipe",
      reason: "codex exec run on a TTY — linear output, safe to pipe",
    };
  }
  if (base === "openclaw" && firstSubcommand(cmd) === "agent") {
    return {
      mode: "pipe",
      reason: "openclaw agent one-shot run on a TTY — linear output, safe to pipe",
    };
  }
  if (base === "opencode" && firstSubcommand(cmd) === "run") {
    return {
      mode: "pipe",
      reason: "opencode run one-shot on a TTY — linear output, safe to pipe",
    };
  }
  if (opts.ptyOverride === "0") {
    return {
      mode: "passthrough",
      reason:
        `'${base || "(empty)"}' is interactive on a TTY and MANDU_REPLY_FILTER_PTY=0 ` +
        "disables the PTY relay — the TUI keeps the real TTY untouched (symbols stay opaque)",
    };
  }
  return {
    mode: "pty",
    reason:
      `'${base || "(empty)"}' is not a known print-mode invocation on a TTY — ` +
      "PTY relay: the child keeps a real terminal while its output is desymbolized " +
      "(MANDU_REPLY_FILTER_PTY=0 opts out)",
  };
}
