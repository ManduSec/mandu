/**
 * exec-gate — the model-context-layer exec decision (Mandu-new, no reference
 * origin; the design is exec-routing.md §3).
 *
 * The model proxies (interceptors/anthropic-proxy, interceptors/openai-proxy) see
 * a shell command as the model WROTE it: with `$MDU:*` tokens exactly where
 * untrusted `tool_result` data was spliced in, and BEFORE any shell expansion.
 * That is the earliest legible layer for the exec boundary. Nothing is
 * desymbolized here, so a command carrying a symbol is already opaque — echoing or
 * piping it emits the literal token, which re-enters symbolized (the E4 property).
 *
 * The ONE case opacity is lost by construction is an untrusted symbol in a
 * COMMAND / code-execution position (`$SYM`, `sh -c $SYM`, `python -c $SYM`, a
 * code heredoc): a downstream interpreter that desymbolized-then-ran it would turn
 * untrusted data into executed code. That — and only that — is what this gate
 * BLOCKS. Data-position symbols (`grep foo $SYM | wc -l`) stay opaque and are the
 * respective egress chokepoint's job; NOT over-blocking them is a first-class
 * requirement (it keeps the count-security / inspect-* utility scenarios working).
 *
 * Composition (pure, exec-free — unit-tested with no daemon):
 *   - block  : detectUntrustedCommandExecutionPatterns(command, {action:"block"})
 *              — the SAME detector the exec-supervisor + the `asCommand` egress
 *              gate use, so the proxy and the exec boundary agree by construction.
 *   - evasion: NON-blocking signals recorded for Phase 1 shell-routing + the
 *              dashboard — an absolute-path invocation of a known network tool
 *              (bypasses the exec-wrap PATH shim) and inline `VAR=`/`env` prefixes.
 *              These do NOT block on their own (no untrusted data is implicated,
 *              and legitimate absolute-path use is common).
 *   - shell/identifier: classifyExec with no resource hints — informational
 *              (AgentShell default), so the event/record shows what the command
 *              WOULD route to.
 */

import { ruleRef, type RuleRef } from "./rule-ref.js";
import { basename, tokenize } from "./exec-identifier.js";
import { classifyExec, type ExecShell } from "./exec-classify.js";
import { detectUntrustedCommandExecutionPatterns } from "./untrusted-command-execution.js";
import { requoteShellPlaceholders } from "./shell-placeholder-quoting.js";

export type ExecGateDecision = "allow" | "block";

export type ExecGateEvasionKind = "absolute_path_net_tool" | "env_prefix_override";

export interface ExecGateEvasion {
  kind: ExecGateEvasionKind;
  /** The offending token (e.g. "/usr/bin/curl", "PATH=/usr/bin"). */
  evidence: string;
}

export interface ExecGateRequest {
  /** The raw shell command as the model wrote it (symbols still opaque). */
  command: string;
  /** Working directory the command would run in (for classifyExec identity). */
  cwd?: string;
}

export interface ExecGateResult {
  /** Decision provenance (rule-ref.ts; policy-surface.md §9.3). */
  ruleRef?: RuleRef;
  decision: ExecGateDecision;
  reason: string;
  /** Symbols implicated in a command/code-position match (the block cause). */
  symbols: string[];
  /** Non-blocking evasion signals (recorded for Phase 1 routing + the UI). */
  evasion: ExecGateEvasion[];
  /** The shell the command WOULD route to (informational; AgentShell default). */
  shell: ExecShell;
  /** Canonical command identity (script/binary basename), or null. */
  identifier: string | null;
  /** The approval-queue entry id, set iff the PROVENANCE gate (exec-output-
   * trust.md §7a; the server-side wrap in ipc/server.ts) blocked pending a
   * human verdict — the same field the fs / net gates expose. */
  approvalId?: string;
  /** The net-fetched program text the provenance gate decided on: the path
   * (`(stdin)` for a `curl | bash` pipe) and the host its bytes came from. */
  programText?: { path: string; originHost: string };
  /** ALLOW only: the command with every secret placeholder the agent's shell
   * would expand (`"…$MDU:…"`, unquoted, an expanding here-document)
   * requoted so the program receives it whole (shell-placeholder-quoting.ts;
   * confidentiality.md §7, "A placeholder the agent's shell would expand").
   * The model proxies deliver it in place of the command to a SHELL tool.
   * Absent when nothing needs requoting or the parse is unsure. It inserts
   * only `'` and `\` next to a placeholder the model wrote: nothing is
   * resolved, so the egress gates still decide every release. */
  requoted?: string;
}

/** Network tools whose absolute-path invocation bypasses the exec-wrap PATH shim.
 * Kept in sync with the exec-wrap default shadow set (curl/wget/nc) plus the
 * classic exfil neighbours. Used for evasion RECORDING only — never to block. */
const NET_TOOLS: ReadonlySet<string> = new Set<string>([
  "curl", "wget", "nc", "ncat", "netcat", "telnet", "socat",
]);

/** A token is a leading `VAR=value` env assignment (before the command word). */
function isEnvAssignment(token: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(token);
}

/**
 * Collect non-blocking evasion signals from the command's tokens: absolute-path
 * invocations of known network tools (bypass the PATH shim), and inline
 * `VAR=`/`env`/`PATH=` prefixes (env scrubbing that could re-point PATH). Scans
 * every command word after a control operator so `a && /usr/bin/curl …` is seen.
 */
function detectEvasion(command: string): ExecGateEvasion[] {
  const out: ExecGateEvasion[] = [];
  const seen = new Set<string>();
  const push = (kind: ExecGateEvasionKind, evidence: string): void => {
    const key = `${kind}:${evidence}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, evidence });
  };
  const tokens = tokenize(command);
  // Control operators that begin a fresh command word (so we re-scan the head of
  // each sub-command, not just the first). `env` and leading `VAR=` also shift
  // the command word rightward.
  let atCommandHead = true;
  for (const token of tokens) {
    if (token === "&&" || token === "||" || token === "|" || token === ";" || token === "&") {
      atCommandHead = true;
      continue;
    }
    if (atCommandHead) {
      if (isEnvAssignment(token)) {
        push("env_prefix_override", token);
        continue; // still at the command head (assignment precedes the command)
      }
      if (basename(token) === "env") {
        push("env_prefix_override", token);
        // `env` is followed by more VAR=/command tokens; stay scanning at head.
        continue;
      }
      // The command word: flag an absolute-path net tool.
      if (token.startsWith("/") && NET_TOOLS.has(basename(token))) {
        push("absolute_path_net_tool", token);
      }
      atCommandHead = false;
    }
  }
  return out;
}

/**
 * Decide whether a shell command may be handed to the agent (block only the
 * untrusted-symbol-in-command-position case), and report the classification +
 * evasion signals. Pure; never throws.
 */
export function execGate(req: ExecGateRequest): ExecGateResult {
  const command = req.command;
  const classified = classifyExec({ argv: tokenize(command), cwd: req.cwd });
  const evasion = detectEvasion(command);

  const matches = detectUntrustedCommandExecutionPatterns(command, { action: "block" });
  if (matches.length > 0) {
    const symbols = [...new Set(matches.flatMap((m) => m.symbols))];
    const kinds = [...new Set(matches.map((m) => m.patternId))].join(", ");
    return {
      decision: "block",
      reason:
        "untrusted symbol used in command/execution position " +
        `(${kinds}) → cannot execute untrusted data as code`,
      ruleRef: ruleRef("exec:symbol-in-command"),
      symbols,
      evasion,
      shell: classified.shell,
      identifier: classified.identifier,
    };
  }

  const requote = requoteShellPlaceholders(command);
  return {
    decision: "allow",
    reason:
      evasion.length > 0
        ? "no symbol in command position; allowed (evasion signals recorded)"
        : "no symbol in command position; allowed",
    ruleRef: ruleRef("exec:no-symbol-in-command"),
    symbols: [],
    evasion,
    shell: classified.shell,
    identifier: classified.identifier,
    ...(requote ? { requoted: requote.command } : {}),
  };
}
