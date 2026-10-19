/**
 * gate — the pure exec-chokepoint decision logic (arbiter-driven, exec-free).
 *
 * Given the observed argv for a shadowed HIGH-RISK command, ask the arbiter:
 *   1. classifyExec(argv, cwd) → which shell view the command runs in. Network
 *      tools (curl/wget/nc) genuinely need the real network, so we hint
 *      needsNetwork:true → HumanShell, where the argv WILL be desymbolized.
 *   2. resolveExecArgv(argv, shell) → the argv to actually run + any approvals.
 *
 * The verdict:
 *   - If resolveExecArgv returns ANY approvals (a symbol-as-command/arg the
 *     egress gate withheld, or an unsupported command shape) → BLOCK. The agent
 *     only ever holds symbols, so a $MDU:* token sitting where it would be
 *     desymbolized into a command/arg is exactly the injected-exfil signal.
 *   - Else → ALLOW with the arbiter's RESOLVED argv (data-position symbols already
 *     desymbolized safely in-slot). A SECRET's placeholder is never resolved:
 *     it stays in the argv as written and the command runs, so the real value
 *     can only go in at the network chokepoint, after the binding check
 *     (confidentiality.md §7.1; until 2026-10-05 it blocked as `secret_symbol`,
 *     which the arbiter now returns only if a secret row would be resolved).
 *   - A arbiter error (unreachable / rejected op) → BLOCK (fail-closed). We NEVER
 *     fall through to running the raw command on a arbiter failure.
 *
 * This module is exec-free + pure over an `ExecArbiter`, so the unit tests drive
 * it with a mock and assert the gate without spawning anything.
 */

import type { ExecArbiter, ExecApprovalItem } from "./arbiter-client.js";

export interface GateDecision {
  /** "allow" → run the resolved argv; "block" → refuse (fail-closed). */
  action: "allow" | "block";
  /** The argv to exec when action==="allow" (arbiter-resolved). */
  argv: string[];
  /** Human-readable reason (the block message / audit line). */
  reason: string;
  /** The approvals that caused a block (empty on allow / arbiter-error block). */
  approvals: ExecApprovalItem[];
}

/** Summarize the approval items into a compact reason string for the user. */
function summarizeApprovals(approvals: ExecApprovalItem[]): string {
  return approvals
    .map((a) => {
      const syms = a.symbols.length ? ` [${a.symbols.join(", ")}]` : "";
      return `${a.kind}: ${a.reason}${syms}`;
    })
    .join("; ");
}

/** Why one approval item blocked the command, and what the person can do,
 *  in the plain words of the dashboard product page. Accurate to what exists:
 *  an exec-wrap block has no pending approval to answer (the arbiter files
 *  none for an exec), so the way forward is a plain rewrite or a run outside
 *  the agent; a secret's way out is a network request, where the dashboard
 *  Inbox does ask. */
function plainApproval(a: ExecApprovalItem): { why: string; next: string } {
  switch (a.kind as string) {
    case "unsupported_command": {
      const syntax = /\(([^()]*)\)\s*$/.exec(a.reason)?.[1];
      return {
        why: `the command carries a placeholder for protected data and uses shell syntax Mandu cannot check safely${syntax ? ` (${syntax})` : ""}, so Mandu will not put the real value in`,
        next: "write it as one plain command (no pipes, redirects, $( ), { } or wildcards) and Mandu fills the value in where it is allowed to go; otherwise run it yourself, outside the agent",
      };
    }
    case "symbol_as_command":
      return {
        why: "text from an untrusted source (a placeholder) would run as a command or as code, which Mandu never does",
        next: "if you trust that text, run the command yourself, outside the agent",
      };
    case "secret_symbol":
      return {
        why: "the command line carries a placeholder for a secret, and Mandu never writes a secret's real value into a command line",
        next: "a secret leaves only inside a network request to a site it may go to (`mandu why <file>` lists them); any other site asks for your OK on the dashboard's Approvals page (`mandu dashboard`)",
      };
    default:
      return { why: "Mandu rules do not allow it", next: "`mandu dashboard` lists the rules" };
  }
}

/**
 * The block message when the wrapper cannot reach the arbiter at all. Still a
 * block (the caller exits 77, nothing runs); only the reason differs:
 *
 * - `EPERM` or `EACCES` on the dial is a refusal, not a dead service: a
 *   sandbox's syscall filter refusing `connect(2)` (`EPERM`), or an access
 *   rule on the socket (`EACCES`: its file mode, an LSM). The message says
 *   so instead of sending the person to `mandu status` for a service that is
 *   running.
 * - Codex's own command sandbox is named when it is the one
 *   (`where.codexNetworkOff`: Codex sets `CODEX_SANDBOX_NETWORK_DISABLED=1`
 *   in every command it runs with the sandbox's network off, read on
 *   codex-cli 0.162.0). Its seccomp filter refuses every `connect`, Unix
 *   sockets included (supported-agents.md §6.4), so the command could not
 *   have reached the network there either; the message says that the
 *   command itself was not the problem and names both ways out: running it
 *   outside Codex's sandbox (Codex's `require_escalated`, which asks the
 *   user) or the setting that opens the sandbox's network. The variable is
 *   the agent's to set, so it chooses only these words: nothing runs either
 *   way, and the model's `blocked:` line comes from the arbiter's own record
 *   of Codex's sandbox, never from this text (confidentiality plan 10
 *   §11.8, "Blocked commands").
 * - anything else: the service is not answering.
 *
 * Pure.
 */
export function unreachableMessage(
  cmdName: string,
  sock: string,
  err: { code?: unknown; message?: unknown },
  where: { codexNetworkOff?: boolean } = {},
): string {
  const detail = `detail: arbiter unreachable at ${sock}: ${String(err.message ?? err)}`;
  const head = `blocked ${cmdName}, nothing ran: the sandbox this command runs in refuses its connection to Mandu`;
  const unchecked = "so the command cannot be checked, and a checked command never runs unchecked";
  if ((err.code === "EPERM" || err.code === "EACCES") && where.codexNetworkOff === true) {
    return (
      `${head}: it is Codex's own sandbox, whose network is off, ${unchecked}. ` +
      "The command itself was not the problem, and it could not have reached the network from there either. " +
      "To run it, ask to run it outside Codex's sandbox (sandbox_permissions \"require_escalated\"; the user is asked first), " +
      "or set Codex's `sandbox_workspace_write.network_access = true`, which opens both " +
      "(`mandu codex` sets it unless your Codex config sets it or `--no-codex-shell-network` keeps it off). " +
      detail
    );
  }
  if (err.code === "EPERM") {
    return (
      `${head} (a sandbox's filter, not a stopped service; Codex's own sandbox does this while its network is off), ${unchecked}. ` +
      "The command itself was not the problem. Run it where that sandbox lets it reach Mandu's socket " +
      "(for Codex: `sandbox_workspace_write.network_access = true`, which `mandu codex` sets unless your Codex config sets it " +
      "or `--no-codex-shell-network` keeps it off). " +
      detail
    );
  }
  if (err.code === "EACCES") {
    return (
      `${head}, or the socket's permissions do (not a stopped service), ${unchecked}. ` +
      "The command itself was not the problem. Run it where it may reach Mandu's socket. " +
      detail
    );
  }
  return `blocked ${cmdName}, nothing ran: the Mandu service is not answering, and a checked command never runs unchecked (\`mandu status\` shows the service). ${detail}`;
}

/**
 * The block message the person sees (stderr of the blocked command, which
 * the model reads too): what was blocked, why, and what to do, then the
 * machine reason unchanged on a `detail:` line (the audit form, and what the
 * tests and a bug report key on).
 */
export function blockMessage(cmdName: string, decision: GateDecision): string {
  const lines = [`blocked ${cmdName}, nothing ran.`];
  const seen = new Set<string>();
  for (const a of decision.approvals) {
    const { why, next } = plainApproval(a);
    if (seen.has(why)) continue;
    seen.add(why);
    lines.push(`  why: ${why}.`, `  what to do: ${next}.`);
  }
  if (decision.approvals.length === 0) lines.push("  why: Mandu could not check the command, so it did not run it.");
  lines.push(`  detail: ${decision.reason}`);
  return lines.join("\n");
}

/**
 * Decide whether to run the shadowed command `argv` (BLOCK fail-closed otherwise).
 *
 * @param arbiter  the (real or mock) arbiter surface.
 * @param argv    the full observed argv ([cmdName, ...args]).
 * @param cwd     the command's working directory.
 */
export async function decideExec(
  arbiter: ExecArbiter,
  argv: string[],
  cwd: string,
): Promise<GateDecision> {
  // FAIL CLOSED: any arbiter error → block. We do NOT run the raw command.
  let shell;
  try {
    const classified = await arbiter.classifyExec({
      argv,
      cwd,
      // curl/wget/nc are network tools: they genuinely need the real network, so
      // route them to HumanShell, where resolveExecArgv applies the data-usage
      // check and (only then) desymbolizes data-position symbols. In AgentShell
      // the argv would be returned symbolic and run as-is — a raw $MDU:*
      // token on the command line, which is not what we want for a real exec.
      // (A secret's token does stay on the command line in HumanShell too: the
      // session's egress proxy puts its value in, at a bound host only.)
      needsNetwork: true,
    });
    shell = classified.shell;
  } catch (err) {
    return {
      action: "block",
      argv,
      reason: `arbiter classifyExec failed (fail-closed): ${(err as Error).message}`,
      approvals: [],
    };
  }

  let resolved;
  try {
    resolved = await arbiter.resolveExecArgv({ argv, shell });
  } catch (err) {
    return {
      action: "block",
      argv,
      reason: `arbiter resolveExecArgv failed (fail-closed): ${(err as Error).message}`,
      approvals: [],
    };
  }

  // Any required/withheld approval means a symbol must be desymbolized to run but
  // the egress gate withheld it (symbol-as-command/arg, or an unsupported shape).
  if (resolved.approvals.length > 0) {
    return {
      action: "block",
      argv,
      reason: summarizeApprovals(resolved.approvals),
      approvals: resolved.approvals,
    };
  }

  // Clean: run the arbiter's resolved argv (data-position symbols already
  // desymbolized safely in-slot; symbol-free commands pass through unchanged).
  return {
    action: "allow",
    argv: resolved.argv,
    reason: resolved.reason,
    approvals: [],
  };
}
