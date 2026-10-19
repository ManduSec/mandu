/**
 * exec-gate — proxy-side enforcement of the model-context exec gate (Phase 0,
 * exec-routing.md §3).
 *
 * Mandu Track A (interceptors/anthropic-proxy). At the SAME response-side
 * tool_use hook as the P3 fs gate (fs-gate.ts), a `Bash`/shell tool_use's
 * command STRING is submitted to the arbiter's `execGate` op. fs-gate handles
 * typed PATH fields and deliberately skips Bash.command ("the exec chokepoint's
 * turf"); this module is that chokepoint at the model-context layer. The verdict
 * is enforced ON THE WIRE, exactly like fs-gate's denied path sentinel:
 *
 *   allow  → the command passes through unchanged (data-position symbols stay
 *            opaque — NOT over-blocked, so grep/wc-over-untrusted utility works).
 *   block  → the command field is rewritten to a benign, side-effect-free FAILING
 *            command `echo '<message>' 1>&2; exit 77` (exit 77 mirrors
 *            exec-wrap's BLOCK_EXIT_CODE). The agent runs THAT; the real command
 *            never executes, its non-zero exit rides back, the session continues.
 *            No stream abort, no client-compat risk; the rewrite string is a
 *            STATIC policy message (no AgentView paths, no raw untrusted bytes),
 *            so it adds no reverse-map / leak surface.
 *   arbiter unreachable / timeout → the SAME block sentinel (reason
 *            `unreachable`). The gate FAILS CLOSED (the repo invariant); it never
 *            falls through to the raw command.
 *
 * SCOPE: only the command field of a command-bearing tool (EXEC_COMMAND_FIELDS).
 * The arbiter blocks ONLY an untrusted `$MDU:*` in command/execution
 * position; everything else is allowed. Unlike fs-gate this needs NO view map
 * (no workspace roots), so it is active even on a non-git / no-worktree launch.
 */

import type { Arbiter, ExecGateDecision, ExecGateEvasion, RuleRef } from "./arbiter-client.js";
import { commandLikeFields } from "./unmapped-exec.js";

/** Tools whose input carries a shell command STRING → gated here (not fs-gate).
 * Claude Code's exec tool is `Bash` with a `command` field. The DEFAULT only:
 * the proxy passes the session agent's own table (gate-surface.ts). */
export const EXEC_COMMAND_FIELDS: Record<string, string> = {
  Bash: "command",
};

/** Exit code the block sentinel uses. Mirrors exec-wrap's BLOCK_EXIT_CODE so a
 * gate refusal is distinguishable from the command's own non-zero exits. */
export const EXEC_BLOCK_EXIT_CODE = 77;

/**
 * Fail-closed ceiling for a single arbiter execGate call. The gate runs on the
 * SSE relay chain; a wedged-but-connected arbiter would otherwise hang the model
 * turn. On timeout the command is treated exactly like an unreachable arbiter —
 * the block sentinel — so a wedged link can only BLOCK, never stall (same
 * rationale + default as fs-gate.ts DEFAULT_GATE_TIMEOUT_MS).
 */
export const DEFAULT_EXEC_GATE_TIMEOUT_MS = 5000;

/** Reject with `message` if `p` has not settled within `ms`, else settle with
 * `p`. Not unref'd — it is the fail-closed safety valve and MUST fire even if it
 * is momentarily the only thing on the loop. Cleared as soon as `p` settles. */
function withTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(message)), ms);
    p.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e as Error); },
    );
  });
}

/**
 * The block reason in plain words, for the person reading the agent's
 * transcript (the model reads it too). Keyed on the arbiter's reason text;
 * the raw reason still follows as `detail:` so nothing is lost. Points at the
 * dashboard's Approvals page ONLY when the arbiter filed an approval (`→
 * pending`): a policy block has nothing there to answer.
 */
export function plainBlockWords(reason: string): string {
  // A HIGH session's command (confidentiality.md §4, "The human half",
  // 2026-10-11): the arbiter filed an Approvals row naming this exact
  // command, or the user blocked it for this session.
  if (/^HIGH SESSION/.test(reason) && /→ pending$/.test(reason)) {
    return "this session has read a secret, and Mandu cannot prove this command stays off the network, so Mandu stopped it and asked the user on its Approvals page (mandu dashboard). Tell the user, and run the same command again after they answer: if they allowed it, it runs once";
  }
  if (/^HIGH SESSION/.test(reason) && /human-denied/.test(reason)) {
    return "this session has read a secret, and the user blocked this command for this session; do not retry it";
  }
  if (/→ pending$/.test(reason)) {
    return "running it needs your OK: answer it on the dashboard's Approvals page (mandu dashboard), then try again";
  }
  if (/human-denied/.test(reason)) return "you said no to running this earlier";
  if (/untrusted symbol used in command/.test(reason)) {
    return "it would run text from an untrusted source (a placeholder) as a command, which Mandu never does; if you trust that text, run the command yourself, outside the agent";
  }
  if (/^HIGH SESSION/.test(reason)) {
    return "this session has read a secret, and Mandu cannot prove this command stays off the network; start a new session for work that needs it";
  }
  if (/arbiter unreachable/.test(reason)) {
    return "the Mandu service is not answering, so the command could not be checked (mandu status shows the service)";
  }
  return "Mandu rules do not allow it (the dashboard lists them: mandu dashboard)";
}

/** The notice the block sentinel prints: Mandu's own words (the plain reason,
 * then the arbiter's), every single quote stripped so it can sit inside the
 * sentinel's single quotes. */
export function blockNoticeText(reason: string): string {
  return `mandu-exec-gate: blocked, nothing ran: ${plainBlockWords(reason)}. detail: ${reason}`.replace(/'/g, "");
}

/** Build the benign failing command a blocked command field is rewritten to.
 * Single-quoted message ⇒ no shell interpretation of its contents; any single
 * quote in the reason is stripped so the quoting can never be broken out of. */
export function blockSentinelCommand(reason: string): string {
  return `echo '${blockNoticeText(reason)}' 1>&2; exit ${EXEC_BLOCK_EXIT_CODE}`;
}

/** How many delivered notices {@link ExecGateNotices} keeps (oldest out). A
 *  forgotten notice only costs utility: its result is classified as before. */
export const EXEC_GATE_NOTICES_MAX = 1024;

/**
 * The block notices this proxy delivered, by tool_use id (confidentiality
 * plan 10 §11.8, "The exec gate's own notice"). The sentinel's result is the
 * notice the proxy composed, printed back by `echo`, but the classify verdict
 * cannot tell: its path scan reads the sentinel command, and a notice that
 * says "secret" matches the catalog's `*secret*` shape, so the model got one
 * opaque `$MDU:nomodel_Bash[…]` and never learned why its command failed
 * (live run, 2026-10-03). The request side forwards the notice in clear only
 * when the tool_result is EXACTLY what the sentinel prints
 * ({@link gateNoticeResult}); any other byte keeps the result on the
 * classify path. In memory only: a restarted proxy has no record, and the
 * result is classified as before (fail-closed).
 */
export class ExecGateNotices {
  private readonly notices = new Map<string, string>();

  remember(callId: string | undefined, notice: string | undefined): void {
    if (!callId || !notice) return;
    this.notices.delete(callId);
    this.notices.set(callId, notice);
    while (this.notices.size > EXEC_GATE_NOTICES_MAX) {
      const oldest = this.notices.keys().next().value;
      if (oldest === undefined) break;
      this.notices.delete(oldest);
    }
  }

  noticeFor(callId: string): string | undefined {
    return this.notices.get(callId);
  }
}

/**
 * The text to forward for a gated call's tool_result body, or null when the
 * body is not exactly the sentinel's output. `body` is the result text with
 * the harness's trailing `<system-reminder>` blocks already split off. Two
 * renderings match, each whole: the notice alone, and Claude Code's failing
 * Bash form `Exit code 77\n<notice>`; trailing whitespace (echo's newline)
 * is ignored. The return value is built from `notice`, never from `body`, so
 * no byte the agent's shell produced is forwarded by this path.
 */
export function gateNoticeResult(body: string, notice: string): string | null {
  const text = body.replace(/\s+$/, "");
  if (text === notice) return notice;
  const framed = `Exit code ${EXEC_BLOCK_EXIT_CODE}\n${notice}`;
  if (text === framed) return framed;
  return null;
}

/** The gate's outcome for one command-bearing tool_use. */
export interface ExecGateOutcome {
  tool: string;
  field: string;
  /** The command the model wrote (symbolized; unchanged on allow). */
  command: string;
  decision: "allow" | "block";
  reason: string;
  /** Symbols implicated in a command/code-position block (empty on allow). */
  symbols: string[];
  /** Non-blocking evasion signals recorded for Phase 1 routing + the UI. */
  evasion: ExecGateEvasion[];
  shell: string;
  identifier: string | null;
  /** The failing command the field was rewritten to (set iff decision==="block"). */
  sentinel?: string;
  /** The notice that sentinel prints (set iff decision==="block"). */
  notice?: string;
  /** Decision provenance (policy-surface.md §9.3). */
  ruleRef?: RuleRef;
  /** The queued approval id when the provenance gate blocked pending a human
   * (exec-routing.md §8.7a) — rides to the `exec_action` event so the
   * dashboard can pair the sentinel with its inbox row. */
  approvalId?: string;
  /** The net-fetched program text the provenance gate decided on. */
  programText?: { path: string; originHost: string };
  /** The command delivered in place of `command` on an allow: each secret
   * placeholder the shell would expand requoted (set iff the field was
   * rewritten; see gateExecToolUse's `requote`). */
  requoted?: string;
}

export interface ExecGateResult {
  /** The (possibly rewritten) input — a fresh object when the command was blocked. */
  input: Record<string, unknown>;
  /** The gate outcome, or null when this tool carries no command field (nothing
   *  to gate — Bash's siblings fall to fs-gate / the view map). */
  outcome: ExecGateOutcome | null;
}

/**
 * Apply the exec gate to one tool_use input. Returns `{input, outcome:null}`
 * when the tool has no command field. NEVER throws: an arbiter error/timeout is
 * enforced as a block sentinel (fail-closed), not propagated.
 */
export async function gateExecToolUse(
  toolName: string,
  input: unknown,
  opts: {
    arbiter: Pick<Arbiter, "execGate">;
    cwd?: string;
    /** The session this command belongs to. LOAD-BEARING since Plan 8 — see
     *  ExecGateRequest.sessionKey. */
    sessionKey?: string;
    /** The tool_use id of this command's tool_use block — see
     *  ExecGateRequest.callId (the clean-verdict correlation leg). */
    callId?: string;
    log?: (msg: string) => void;
    /** Per-decision fail-closed timeout (ms). Default DEFAULT_EXEC_GATE_TIMEOUT_MS. */
    arbiterTimeoutMs?: number;
    /** The session agent's shell tools → command field (gate-surface.ts
     *  GateSurface.exec: `bash.command` on opencode, `exec.command` on
     *  openclaw). Default EXEC_COMMAND_FIELDS (Claude Code). */
    commandFields?: Readonly<Record<string, string>>;
    /** Deliver the arbiter's `requoted` command on an allow (confidentiality.md
     *  §7, "A placeholder the agent's shell would expand"): set where the
     *  field is a command a SHELL runs (the session's exec tools), never for
     *  text typed into a process. */
    requote?: boolean;
  },
): Promise<ExecGateResult> {
  const fields = opts.commandFields ?? EXEC_COMMAND_FIELDS;
  const field = Object.prototype.hasOwnProperty.call(fields, toolName) ? fields[toolName] : undefined;
  if (!field) return { input: input as Record<string, unknown>, outcome: null };
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { input: input as Record<string, unknown>, outcome: null };
  }
  const src = input as Record<string, unknown>;
  const command = src[field];
  if (typeof command !== "string" || command === "") {
    return { input: src, outcome: null };
  }

  let decision: ExecGateDecision | null = null;
  let unreachable: string | null = null;
  const timeoutMs = opts.arbiterTimeoutMs ?? DEFAULT_EXEC_GATE_TIMEOUT_MS;
  try {
    decision = await withTimeout(
      // sessionKey is LOAD-BEARING (Plan 8): the arbiter tightens exec in a HIGH
      // session, and cannot tell without it. Omitting it made the high-session
      // exec block dead in the real stack while every arbiter-side test passed.
      opts.arbiter.execGate({ command, cwd: opts.cwd, sessionKey: opts.sessionKey, callId: opts.callId }),
      timeoutMs,
      `arbiter execGate timed out after ${timeoutMs}ms — fail closed`,
    );
  } catch (err) {
    unreachable = (err as Error).message;
  }

  // Allow: pass through unchanged (data-position symbols stay opaque), except
  // that a secret placeholder the shell would expand to nothing (`"$MDU:…"`,
  // unquoted) is delivered requoted, so the program receives it whole and the
  // egress gates see it. Only `'` and `\` are inserted beside a placeholder
  // the model wrote; nothing is resolved.
  if (decision && decision.decision === "allow") {
    const requoted = opts.requote === true && typeof decision.requoted === "string" && decision.requoted !== "" && decision.requoted !== command
      ? decision.requoted
      : undefined;
    if (requoted !== undefined) opts.log?.(`exec-gate: requoted a placeholder in ${toolName}.${field} so the shell keeps it whole`);
    return {
      input: requoted !== undefined ? { ...src, [field]: requoted } : src,
      outcome: {
        ...(requoted !== undefined ? { requoted } : {}),
        tool: toolName, field, command,
        decision: "allow", reason: decision.reason,
        symbols: decision.symbols, evasion: decision.evasion,
        shell: decision.shell, identifier: decision.identifier,
        ...(decision.ruleRef ? { ruleRef: decision.ruleRef } : {}),
        // A human-APPROVED net-fetched program text still names what it was.
        ...(decision.programText ? { programText: decision.programText } : {}),
      },
    };
  }

  // Block (policy) or unreachable (fail-closed): rewrite the command field.
  const reason = decision
    ? decision.reason
    : `arbiter unreachable (${unreachable}) — fail closed`;
  const sentinel = blockSentinelCommand(reason);
  const out = { ...src, [field]: sentinel };
  opts.log?.(`exec-gate: BLOCKED ${toolName}.${field} (${reason})`);
  return {
    input: out,
    outcome: {
      tool: toolName, field, command,
      decision: "block", reason,
      symbols: decision?.symbols ?? [],
      evasion: decision?.evasion ?? [],
      shell: decision?.shell ?? "AgentShell",
      identifier: decision?.identifier ?? null,
      sentinel,
      notice: blockNoticeText(reason),
      ruleRef: decision?.ruleRef ?? { source: "fail-closed", id: "proxy:arbiter-unreachable" },
      ...(decision?.approvalId ? { approvalId: decision.approvalId } : {}),
      ...(decision?.programText ? { programText: decision.programText } : {}),
    },
  };
}

/** Is this an MCP tool (Claude Code's `mcp__<server>__<tool>`) that is not
 *  one of the session's own shells? Those are the tools the command-like
 *  gate below covers (plan 10 §11.13, MCP command tools). */
export function isMcpCommandCandidate(toolName: string, commandFields: Readonly<Record<string, string>>): boolean {
  return toolName.startsWith("mcp__") && !Object.prototype.hasOwnProperty.call(commandFields, toolName);
}

/**
 * The exec gate for an MCP tool whose input carries a command-like field
 * (`command`, `cmd`, `script`, `code`, `argv`, …; unmapped-exec.ts, the same
 * detection plan 10 §11.11/§11.12 use): EVERY such field is submitted to the
 * arbiter's `execGate`, exactly as a Bash command is, so a HIGH session (or an
 * untrusted symbol in command position) blocks an MCP `run_command` the way it
 * blocks Bash. On a block, an arbiter that does not answer, or a field whose
 * shape the gate cannot read (an object, an array with a non-string), EVERY
 * command-like field is replaced by the block sentinel (`["/bin/sh", "-c",
 * sentinel]` for an argv array): a shell runs the sentinel, any other
 * interpreter rejects it, and the model's command never runs. Allow leaves the
 * input untouched. Returns `outcome: null` when the input has no such field.
 * NEVER throws.
 */
export async function gateCommandLikeToolUse(
  toolName: string,
  input: unknown,
  opts: {
    arbiter: Pick<Arbiter, "execGate">;
    sessionKey?: string;
    callId?: string;
    log?: (msg: string) => void;
    arbiterTimeoutMs?: number;
  },
): Promise<ExecGateResult> {
  const fields = commandLikeFields(input);
  if (fields.length === 0) return { input: input as Record<string, unknown>, outcome: null };
  const src = input as Record<string, unknown>;
  const timeoutMs = opts.arbiterTimeoutMs ?? DEFAULT_EXEC_GATE_TIMEOUT_MS;
  let allowed: { field: string; command: string; decision: ExecGateDecision } | null = null;
  let blocked: { field: string; command: string; decision: ExecGateDecision | null; reason: string } | null = null;
  for (const f of fields) {
    if (f.text === null) {
      blocked = { field: f.key, command: JSON.stringify(src[f.key]), decision: null, reason: `the ${f.key} field is not a command the gate can read — fail closed` };
      break;
    }
    try {
      const d = await withTimeout(
        opts.arbiter.execGate({ command: f.text, sessionKey: opts.sessionKey, callId: opts.callId }),
        timeoutMs,
        `arbiter execGate timed out after ${timeoutMs}ms — fail closed`,
      );
      if (d.decision !== "allow") { blocked = { field: f.key, command: f.text, decision: d, reason: d.reason }; break; }
      allowed ??= { field: f.key, command: f.text, decision: d };
    } catch (err) {
      blocked = { field: f.key, command: f.text, decision: null, reason: `arbiter unreachable (${(err as Error).message}) — fail closed` };
      break;
    }
  }
  if (!blocked) {
    const a = allowed!;
    return {
      input: src,
      outcome: {
        tool: toolName, field: a.field, command: a.command, decision: "allow", reason: a.decision.reason,
        symbols: a.decision.symbols, evasion: a.decision.evasion, shell: a.decision.shell, identifier: a.decision.identifier,
        ...(a.decision.ruleRef ? { ruleRef: a.decision.ruleRef } : {}),
      },
    };
  }
  const sentinel = blockSentinelCommand(blocked.reason);
  const out: Record<string, unknown> = { ...src };
  for (const f of fields) out[f.key] = f.shape === "argv" ? ["/bin/sh", "-c", sentinel] : sentinel;
  opts.log?.(`exec-gate: BLOCKED ${toolName}.${blocked.field} (${blocked.reason})`);
  const d = blocked.decision;
  return {
    input: out,
    outcome: {
      tool: toolName, field: blocked.field, command: blocked.command, decision: "block", reason: blocked.reason,
      symbols: d?.symbols ?? [], evasion: d?.evasion ?? [], shell: d?.shell ?? "AgentShell", identifier: d?.identifier ?? null,
      sentinel,
      notice: blockNoticeText(blocked.reason),
      ruleRef: d?.ruleRef ?? { source: "fail-closed", id: d === null && blocked.reason.startsWith("arbiter unreachable") ? "proxy:arbiter-unreachable" : "proxy:command-unreadable" },
      ...(d?.approvalId ? { approvalId: d.approvalId } : {}),
    },
  };
}
