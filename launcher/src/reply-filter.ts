/**
 * reply-filter — compose the user-reply egress filter into the launch
 * (packaging.md §5; mandu-run.sh reply-filter block). Default-on wrapper that
 * desymbolizes the agent's stdout for the human. In the serial form it is
 * prepended as the launch prefix, so it is the direct parent of the security
 * wrappers and the agent yet still inside the scope/env prefixes; it reads its
 * sockets from the composed env and degrades to passthrough by itself if the
 * arbiter is unreachable.
 *
 * UTILITY-ONLY (the inverse of the enforcement gates): if the wrapper's own
 * runtime is missing we drop it and run the agent bare — never hard-fail the
 * launch. A symbol shown raw leaks nothing, so degrading is safe.
 *
 * EARLY START (packaging.md §5.3): by default the filter's node process is
 * started alongside the session's services (prestartReplyFilter), loads its
 * modules while they come up, and is handed the agent at the end over a
 * socket pair on its fd 3 (interceptors/reply-filter/src/handoff.ts). The
 * filter then runs the launch scope's prefix itself, so the chain below it is
 * the serial form's. A launch that stops first ends it (ReplyFilterSlot); a
 * filter that is gone at the hand-off is replaced by a fresh one, and when
 * that fails too the agent runs without a filter (utility-only, as above).
 * MANDU_REPLY_FILTER_PRESTART=0 keeps the serial form.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code; mirrors the bash
 * launcher's `cmd=("$reply_filter_tsx" "$reply_filter_main" "--" "${cmd[@]}")`.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import type { Socket } from "node:net";
import { HUMAN_SOCK_ENV } from "./human-plane.js";
import { childExit, type AdoptedChain } from "./spawn.js";
import type { LaunchPlan, LaunchMutation } from "./types.js";
import type { Layout } from "./services/layout.js";

/** What the launch hands the filter besides its command (applyReplyFilter's
 *  answer). */
export interface ReplyFilterWiring {
  /** The `--mandu-output-format=` value. */
  outputFormat: ReplyOutputFormat;
  /** The filter's own variables (the human-plane socket). In the hand-off
   *  form neither the agent's env nor the scope's --setenv carries them. */
  filterEnv: Record<string, string>;
}

/**
 * Wire the reply filter into the launch when `plan.replyFilter` is on and its
 * runtime is present; null otherwise. Serial form (the default here): prepend
 * the wrapper to `mut.launchPrefix` and put its variables in `mut.env`.
 * `handOff`: the filter was started early, so nothing is prepended and the
 * human-plane socket stays out of `mut.env` (it travels in the hand-off).
 * Injectable `exists`/`warn` for tests.
 */
export function applyReplyFilter(
  plan: LaunchPlan,
  layout: Layout,
  mut: LaunchMutation,
  exists: (p: string) => boolean = existsSync,
  warn: (m: string) => void = (m) => console.error(m),
  opts: { handOff?: boolean } = {},
): ReplyFilterWiring | null {
  if (!plan.replyFilter) return null;
  const rf = layout.replyFilter();
  if (!exists(rf.requiredFile)) {
    warn(
      `mandu: reply-filter runtime unavailable (${rf.requiredFile}) — running WITHOUT it ` +
      `(symbols in the reply stay opaque; pass --no-reply-filter to silence).`,
    );
    return null;
  }
  // Determine framing before security prefixes hide argv[0]. The wrapper
  // consumes this validated option before --; it is neither inherited via env
  // nor forwarded to the security supervisor/agent.
  const outputFormat = launcherReplyOutputFormat(plan.argv);
  // The human-plane socket (arbiter-human-plane.md): the filter resolves the
  // agent's tokens there, and deletes the variable from its child's env
  // (interceptors/reply-filter), so the agent never inherits it. None
  // reported ⇒ none set, and the filter passes tokens through.
  const filterEnv: Record<string, string> = plan.arbiterHumanSock ? { [HUMAN_SOCK_ENV]: plan.arbiterHumanSock } : {};
  // Goose prints the model's reply raw at column 0 and leaves the wrap to
  // the terminal (reply-row-reservation.md §17): the filter reports that
  // rule, so the proxy counts reserved rows by it and the filter paints by
  // it. OpenCode's wrap is unmodelled (`none`: v1 heads only, §35). Every
  // other agent lays its reply out by word wrap (the default).
  Object.assign(filterEnv, replyWrapRuleEnv(plan.target), replyTabOriginEnv(plan.target));
  if (!opts.handOff) {
    mut.launchPrefix = [...rf.tokens, `--mandu-output-format=${outputFormat}`, "--", ...mut.launchPrefix];
    Object.assign(mut.env, filterEnv);
  }
  Object.assign(mut.env, rf.env);
  // Truth-in-labeling (matches the other rungs' LIVE banners): announce that the
  // human-reply egress is wired, so the posture is readable from stderr and the
  // live oracle can assert it. Absent under --no-reply-filter (early return above).
  warn("reply-filter LIVE — the agent's stdout is desymbolized for the human (opaque symbols resolved to originals)");
  return { outputFormat, filterEnv };
}

// PROVENANCE: mirrors interceptors/reply-filter/src/reserve-block.ts
// WRAP_RULE_ENV (independent TS package roots); test/unit/reply-filter.test.ts
// pins the name.
/** The filter's wrap-rule variable (reply-row-reservation.md §17). */
export const REPLY_WRAP_RULE_ENV = "MANDU_REPLY_WRAP_RULE";

/** The filter's wrap-rule variable for a target: `terminal` for Goose, whose
 *  TUI prints its reply raw and leaves the wrap to the terminal (§17.1);
 *  `none` for OpenCode, whose renderer breaks a word at its punctuation and
 *  lays the reply out narrower than Ink (no layout models it, so the filter
 *  asks for v1 heads only: differential-interactive.md §35); nothing for
 *  every other target (Ink's word wrap, the filter's default). Pure. */
export function replyWrapRuleEnv(target: LaunchPlan["target"]): Record<string, string> {
  if (target === "goose") return { [REPLY_WRAP_RULE_ENV]: "terminal" };
  if (target === "opencode") return { [REPLY_WRAP_RULE_ENV]: "none" };
  return {};
}

// PROVENANCE: mirrors interceptors/reply-filter/src/reserve-block.ts
// TAB_ORIGIN_ENV (independent TS package roots); test/unit/reply-filter.test.ts
// pins the name.
/** The filter's TAB-origin variable (reply-row-reservation.md §19.7). */
export const REPLY_TAB_ORIGIN_ENV = "MANDU_REPLY_TAB_ORIGIN";

/** The filter's TAB-origin variable for a target: `content` for Claude
 *  Code, whose renderer expands each TAB in its reply itself, counting the
 *  stops from the left edge of the text the TAB is in (Claude Code 2.1.295
 *  and later, §19.7); nothing for every other target (the screen's column 0,
 *  the filter's default: Codex leaves its stops on the screen's grid, Goose
 *  prints at column 0). Pure. */
export function replyTabOriginEnv(target: LaunchPlan["target"]): Record<string, string> {
  return target === "claude" ? { [REPLY_TAB_ORIGIN_ENV]: "content" } : {};
}

// ── early start (packaging.md §5.3) ─────────────────────────────────────────

// PROVENANCE: mirrors interceptors/reply-filter/src/handoff.ts (independent TS
// package roots); test/unit/reply-filter-prestart.test.ts checks the parity.
/** The flag that starts the filter in its early form, waiting on fd 3. */
export const HANDOFF_FLAG = "--mandu-handoff-fd=3";
/** The filter's answer to a hand-off it took. */
export const HANDOFF_ACK = "ok\n";
/** How long the hand-off waits for that answer (the filter is loaded and
 *  idle by then; this only bounds a stuck process). */
export const HANDOFF_ACK_TIMEOUT_MS = 10_000;
/** How long an abort waits for the filter to end before SIGKILL. */
export const ABORT_GRACE_MS = 2_000;

/** One hand-off (handoff.ts parseHandoff is its reader). */
export interface ReplyFilterHandoff {
  /** The serial form's command after `--`: the security wrappers, then the agent. */
  cmd: string[];
  /** The launch scope's prefix, run by the filter in front of what it spawns. */
  outer: string[];
  env: Record<string, string | undefined>;
  cwd: string;
  outputFormat: ReplyOutputFormat;
}

/** The hand-off line. Pure. Drops unset variables (JSON has no undefined). */
export function handoffLine(h: ReplyFilterHandoff): string {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(h.env)) if (v !== undefined) env[k] = v;
  return JSON.stringify({ v: 1, cmd: h.cmd, outer: h.outer, env, cwd: h.cwd, outputFormat: h.outputFormat }) + "\n";
}

/** Whether this launch starts the filter early: the filter is on, its
 *  runtime is present, and MANDU_REPLY_FILTER_PRESTART is not "0". Pure. */
export function wantsPrestart(
  plan: Pick<LaunchPlan, "replyFilter">,
  layout: Layout,
  env: Record<string, string | undefined>,
  exists: (p: string) => boolean = existsSync,
): boolean {
  return plan.replyFilter && env["MANDU_REPLY_FILTER_PRESTART"] !== "0" && exists(layout.replyFilter().requiredFile);
}

/** A reply filter started early and waiting for its agent. */
export interface PrestartedReplyFilter {
  readonly child: ChildProcess;
  /** Spawned in its own session (the launch's scope plan said `detached`). */
  readonly detached: boolean;
  /** When it was spawned (Date.now() ms): the agent tree's age floor once
   *  adopted (spawn.ts AdoptedChain.spawnedAtMs). */
  readonly spawnedAtMs: number;
  /** Its exit status, taken from the spawn on (spawn.ts childExit). */
  readonly exit: Promise<number>;
  /** Hand it the agent. True once it answered: the chain is then its to run
   *  (runAgent adopts it). False: it is gone or did not answer, and it has
   *  been ended. Once only. */
  handOff(h: ReplyFilterHandoff): Promise<boolean>;
  /** End a filter that was never handed an agent: close its channel (it
   *  exits on the end of file), SIGKILL after ABORT_GRACE_MS, and wait for it. */
  abort(): Promise<void>;
}

export interface PrestartOpts {
  /** The scope plan's `detached` (the flag runAgent spawns the chain with). */
  detached: boolean;
  /** Where it starts; the hand-off moves it to the agent's directory. */
  cwd: string;
  /** Its environment until the hand-off replaces it whole. */
  env: Record<string, string | undefined>;
  /** Injectable for tests. */
  spawnFn?: typeof spawn;
  abortGraceMs?: number;
  ackTimeoutMs?: number;
}

/** Start the filter's process in its early form. Null when it cannot be
 *  spawned at all (the launch then wires the serial form). */
export function prestartReplyFilter(layout: Layout, opts: PrestartOpts): PrestartedReplyFilter | null {
  const rf = layout.replyFilter();
  const spawnFn = opts.spawnFn ?? spawn;
  let child: ChildProcess;
  const spawnedAtMs = Date.now();
  try {
    child = spawnFn(rf.tokens[0]!, [...rf.tokens.slice(1), HANDOFF_FLAG], {
      cwd: opts.cwd,
      env: { ...opts.env, ...rf.env },
      // The real terminal, as the serial form had it (the filter reads and
      // writes none of it before the hand-off), plus the channel on fd 3.
      stdio: ["inherit", "inherit", "inherit", "pipe"],
      detached: opts.detached,
    });
  } catch {
    return null;
  }
  const exit = childExit(child);
  let ended = false;
  void exit.then(() => { ended = true; });
  const channel = (child.stdio[3] ?? null) as Socket | null;
  // A write to a filter that just died must not throw out of the launcher.
  channel?.on("error", () => {});
  let used = false;

  const endIt = async (): Promise<void> => {
    channel?.destroy();
    if (ended) return;
    // Before the hand-off it has no children: its pid is all there is.
    const timer = setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* gone */ } }, opts.abortGraceMs ?? ABORT_GRACE_MS);
    try { await exit; } finally { clearTimeout(timer); }
  };

  return {
    child,
    detached: opts.detached,
    spawnedAtMs,
    exit,
    async handOff(h) {
      if (used) throw new Error("reply filter: handed off twice");
      used = true;
      if (ended || channel === null || child.pid === undefined) { await endIt(); return false; }
      const answered = await new Promise<boolean>((resolve) => {
        let buf = "";
        const done = (ok: boolean): void => {
          clearTimeout(timer);
          channel.removeListener("data", onData);
          channel.removeListener("close", onClose);
          resolve(ok);
        };
        const onData = (chunk: Buffer | string): void => {
          buf += chunk.toString();
          if (buf.includes(HANDOFF_ACK)) done(true);
        };
        const onClose = (): void => done(buf.includes(HANDOFF_ACK));
        const timer = setTimeout(() => done(false), opts.ackTimeoutMs ?? HANDOFF_ACK_TIMEOUT_MS);
        channel.on("data", onData);
        channel.on("close", onClose);
        channel.write(handoffLine(h));
      });
      if (!answered) { await endIt(); return false; }
      channel.destroy();
      return true;
    },
    async abort() {
      if (used) return;
      used = true;
      await endIt();
    },
  };
}

/**
 * The launch's hold on an early-started filter: whatever ends the launch
 * before its agent runs ends the filter too (run.ts main's `finally`); the
 * hand-off takes it out of the slot first.
 */
export class ReplyFilterSlot {
  private pre: PrestartedReplyFilter | null = null;
  set(p: PrestartedReplyFilter | null): void { this.pre = p; }
  get started(): boolean { return this.pre !== null; }
  /** The filter, now the caller's to hand off or end. */
  take(): PrestartedReplyFilter | null {
    const p = this.pre;
    this.pre = null;
    return p;
  }
  /** End a filter nobody took (a launch that stopped before its agent). */
  async abort(): Promise<void> {
    await this.take()?.abort();
  }
}

/**
 * Hand the agent to the early-started filter. If it is gone, or was spawned
 * with another `detached` than the scope plan's, start a fresh one and hand
 * it off at once; if that fails too, null: the caller runs the chain without
 * a filter (utility-only, symbols stay opaque) after the WARNING this prints.
 */
export async function handOffReplyFilter(
  pre: PrestartedReplyFilter | null,
  h: ReplyFilterHandoff,
  detached: boolean,
  fresh: () => PrestartedReplyFilter | null,
  warn: (m: string) => void = (m) => console.error(m),
): Promise<AdoptedChain | null> {
  if (pre !== null) {
    if (pre.detached === detached && await pre.handOff(h)) return { child: pre.child, exit: pre.exit, spawnedAtMs: pre.spawnedAtMs };
    await pre.abort();
  }
  const again = fresh();
  if (again !== null && await again.handOff(h)) return { child: again.child, exit: again.exit, spawnedAtMs: again.spawnedAtMs };
  warn(
    "WARNING: mandu: the reply filter could not be started — running WITHOUT it " +
    "(symbols in the reply stay opaque; pass --no-reply-filter to silence).",
  );
  return null;
}

// PROVENANCE: copied from interceptors/reply-filter/src/output-format.ts;
// independent TS package roots require a local pure copy. Cross-package unit
// coverage checks parity. Always inspect the ORIGINAL plan.argv, never wrappers.
/** Explicit structured stdout selection, independent of the pipe/PTY decision. */
type ReplyOutputFormat = "text" | "json" | "stream-json" | "passthrough";

// Skip known value-taking options so their values cannot impersonate format flags.
// Unknown flag grammars are not inferred; ambiguous explicit formats pass through.
const REQUIRED_VALUE_FLAGS = new Set([
  "--model", "--fallback-model", "--system-prompt", "--append-system-prompt",
  "--system-prompt-file", "--append-system-prompt-file", "--input-format",
  "--json-schema", "--permission-mode", "--max-turns", "--max-budget-usd",
  "--mcp-config", "--settings", "--setting-sources", "--session-id",
  "--agent", "--agents", "--tools", "--allowedTools",
  "--allowed-tools", "--disallowedTools", "--disallowed-tools", "--add-dir",
]);
// Claude Code 2.1.267 local --help: these values are optional. An adjacent
// option (especially --output-format) is not their value.
const OPTIONAL_VALUE_FLAGS = new Set([
  "--cloud", "--debug", "-d", "--from-pr", "--prompt-suggestions",
  "--remote-control", "--resume", "-r", "--teleport", "--worktree", "-w",
]);

export function launcherReplyOutputFormat(cmd: readonly string[]): ReplyOutputFormat {
  if (cmd[0]?.split("/").pop() !== "claude") return "text";
  let format: string | undefined;
  for (let i = 1; i < cmd.length; i++) {
    const arg = cmd[i]!;
    if (arg === "--") break;
    if (REQUIRED_VALUE_FLAGS.has(arg)) { i++; continue; }
    if (OPTIONAL_VALUE_FLAGS.has(arg)) {
      if (cmd[i + 1] !== undefined && !cmd[i + 1]!.startsWith("-")) i++;
      continue;
    }
    if (arg === "--output-format" || arg.startsWith("--output-format=")) {
      const value = arg === "--output-format" ? cmd[++i] : arg.slice("--output-format=".length);
      if (format !== undefined || value === undefined || value.startsWith("--")) return "passthrough";
      format = value;
    }
  }
  if (format === undefined || format === "text") return "text";
  return format === "json" || format === "stream-json" ? format : "passthrough";
}
