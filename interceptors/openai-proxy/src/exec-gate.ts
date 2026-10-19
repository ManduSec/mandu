/**
 * exec-gate — proxy-side enforcement of the Phase-0 model-context exec gate for
 * the Codex track (exec-routing.md §3; the openai-proxy twin of the
 * anthropic-proxy's exec-gate.ts).
 *
 * Codex emits its shell tool as a `function_call` whose `arguments` is a JSON
 * string carrying a command under a CODEX_COMMAND_KEYS key — EITHER a plain
 * string OR an argv array (`["bash","-lc","<script>"]`). This module extracts
 * the command TEXT, submits it to the arbiter's `execGate`, and — on a block —
 * rewrites the arguments JSON so the command becomes a benign, side-effect-free
 * failing command `echo '<message>' 1>&2; exit 77` (exit 77 mirrors exec-wrap's
 * BLOCK_EXIT_CODE), shaped back into whatever the command key held:
 *
 *   command: "<script>"                → command: "<sentinel>"
 *   command: ["bash","-lc","<script>"] → command: ["bash","-lc","<sentinel>"]
 *   command: ["curl", url]             → (blocked only if argv[0] is a symbol)
 *                                        command: ["/bin/sh","-c","<sentinel>"]
 *
 * FAIL-CLOSED: an arbiter error/timeout is enforced as the same block sentinel,
 * never a fall-through to the raw command. ALLOW leaves the arguments untouched
 * (data-position symbols stay opaque — not over-blocked).
 */

import type { Arbiter, ExecGateDecision, ExecGateEvasion } from "./arbiter-client.js";
import { commandLikeFields } from "./unmapped-exec.js";

/** Command keys Codex uses inside function_call arguments. Mirrors view-map.ts
 * CODEX_COMMAND_KEYS so the gate and the path-map agree on where the command is. */
export const CODEX_COMMAND_KEYS: readonly string[] = ["cmd", "command"];

/** Exit code the block sentinel uses (mirrors exec-wrap's BLOCK_EXIT_CODE). */
export const EXEC_BLOCK_EXIT_CODE = 77;

/** Fail-closed ceiling for a single arbiter execGate call (see the anthropic
 * twin / fs-gate.ts for the rationale). */
export const DEFAULT_EXEC_GATE_TIMEOUT_MS = 5000;

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
  // command, or the user blocked it for this session. Keep in step with the
  // anthropic-proxy's exec-gate.ts.
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
  // A code cell the unmapped upload leg held whole (unmapped-upload.ts; the
  // openai-proxy only: the anthropic-proxy holds a path, never a cell).
  if (/^mandu-upload-gate: /.test(reason)) {
    return "a call in this code cell would send a local file Mandu holds, so the cell did not run (the detail says which file and why)";
  }
  if (/arbiter unreachable/.test(reason)) {
    return "the Mandu service is not answering, so the command could not be checked (mandu status shows the service)";
  }
  return "Mandu rules do not allow it (the dashboard lists them: mandu dashboard)";
}

/** Build the benign failing command a blocked command is rewritten to. Single-
 * quoted message ⇒ no shell interpretation; single quotes stripped from the
 * reason so the quoting cannot be broken out of. */
export function blockSentinelCommand(reason: string): string {
  return `echo '${blockNoticeText(reason)}' 1>&2; exit ${EXEC_BLOCK_EXIT_CODE}`;
}

/** The notice the block sentinel prints: Mandu's own words (the plain
 * reason, then the arbiter's), every single quote stripped so it can sit
 * inside the sentinel's single quotes. */
export function blockNoticeText(reason: string): string {
  return `mandu-exec-gate: blocked, nothing ran: ${plainBlockWords(reason)}. detail: ${reason}`.replace(/'/g, "");
}

/** How many delivered notices {@link ExecGateNotices} keeps (oldest out). A
 *  forgotten notice only costs utility: its result is classified as before. */
export const EXEC_GATE_NOTICES_MAX = 1024;

/**
 * The block notices this proxy delivered, by call id (confidentiality plan 10
 * §11.8, "The exec gate's own notice"; the anthropic-proxy twin). The classify
 * verdict on the sentinel's output reads the sentinel command for paths, and
 * a notice saying "secret" matches the catalog's `*secret*` shape, so without
 * this record Codex got one `$MDU:nomodel_exec_command[…]` and never learned
 * why its command failed. The request side forwards the notice in clear only
 * when the output is EXACTLY Codex's runtime header plus the notice
 * (rewrite-request.ts gateNoticeOutput). In memory only: a restarted proxy
 * has no record, and the output is classified as before (fail-closed).
 */
export class ExecGateNotices {
  private readonly notices = new Map<string, { notice: string; wholeCell: boolean }>();

  /** `wholeCell`: the proxy replaced the call's WHOLE code-mode cell by the
   *  sentinel cell (script-cell.ts `blockSentinelCell`), so the cell runs
   *  nothing but the sentinel (plan 10 §11.8; the !545 leftover, 2026-10-09). */
  remember(callId: string | undefined, notice: string | undefined, opts: { wholeCell?: boolean } = {}): void {
    if (!callId || !notice) return;
    this.notices.delete(callId);
    this.notices.set(callId, { notice, wholeCell: opts.wholeCell === true });
    while (this.notices.size > EXEC_GATE_NOTICES_MAX) {
      const oldest = this.notices.keys().next().value;
      if (oldest === undefined) break;
      this.notices.delete(oldest);
    }
  }

  noticeFor(callId: string): string | undefined {
    return this.notices.get(callId)?.notice;
  }

  /** Was `callId`'s whole cell replaced by the sentinel cell? */
  wholeCell(callId: string): boolean {
    return this.notices.get(callId)?.wholeCell === true;
  }
}

/** Interpreter inline-code flag inside an argv array (`-c`, `-lc`, `-e`, …): a
 * single-dash cluster containing `c` or `e`. The element AFTER it is code. */
function isInlineCodeFlag(token: string): boolean {
  return /^-[A-Za-z]*[ce][A-Za-z]*$/.test(token);
}

/** Minimal shell-quote so a reconstructed command string keeps argv boundaries
 * (only used to hand a direct-argv command to the arbiter's string detector). */
function shquote(s: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, "'\\''")}'`;
}

/** Codex's shell tools (codex-cli 0.136 to 0.162, rewrite-request.ts
 *  EXEC_TOOL_NAMES minus the other agents' names and the code-mode `exec`):
 *  a string command is run by the user's shell (`-lc`). */
export const CODEX_SHELL_TOOLS: ReadonlySet<string> = new Set(["exec_command", "shell_command", "shell"]);

/** POSIX-family shells whose `-c` payload is shell text (an argv `shell`
 *  call's code element is requoted only for one of these). */
const POSIX_SHELLS: ReadonlySet<string> = new Set(["sh", "bash", "zsh", "dash", "ash", "ksh", "mksh"]);

/** What a command key held + the command TEXT to classify. */
interface ExtractedCommand {
  key: string;
  /** The command text handed to the arbiter's string detector. */
  text: string;
  /** Rebuild the command value with the sentinel substituted for the code. */
  toSentinel: (sentinel: string) => unknown;
  /** Rebuild the command value with `code` in place of the shell text; null
   *  when the value is not shell text (a direct argv: nothing expands it). */
  withShellText: ((code: string) => unknown) | null;
}

/** Extract the command from a parsed function_call arguments object, or null. */
function extractCommand(obj: Record<string, unknown>): ExtractedCommand | null {
  for (const key of CODEX_COMMAND_KEYS) {
    const v = obj[key];
    if (typeof v === "string" && v !== "") {
      return { key, text: v, toSentinel: (s) => s, withShellText: (s) => s };
    }
    if (Array.isArray(v) && v.every((el) => typeof el === "string")) {
      const arr = v as string[];
      const flagIdx = arr.findIndex(isInlineCodeFlag);
      if (flagIdx >= 1 && flagIdx + 1 < arr.length) {
        // `["bash","-lc","<script>", …]` — the script is the code element.
        const codeIdx = flagIdx + 1;
        const rebuild = (s: string): string[] => arr.map((el, i) => (i === codeIdx ? s : el));
        const shell = (arr[0]!.split("/").pop() ?? "");
        return {
          key,
          text: arr[codeIdx]!,
          toSentinel: rebuild,
          withShellText: flagIdx === 1 && POSIX_SHELLS.has(shell) ? rebuild : null,
        };
      }
      // Direct argv (`["curl", url]`): the "command" is argv[0]. Reconstruct a
      // quoted string so the arbiter can spot a symbol in command position;
      // on block, run the sentinel via a fresh shell.
      return {
        key,
        text: arr.map(shquote).join(" "),
        toSentinel: (s) => ["/bin/sh", "-c", s],
        withShellText: null,
      };
    }
  }
  return null;
}

/** The gate's outcome for one function_call. */
export interface ExecGateOutcome {
  key: string;
  command: string;
  decision: "allow" | "block";
  reason: string;
  symbols: string[];
  evasion: ExecGateEvasion[];
  shell: string;
  identifier: string | null;
  sentinel?: string;
  /** The notice that sentinel prints (set iff decision==="block"). */
  notice?: string;
  /** The shell text delivered in place of `command` on an allow (set iff
   *  the arguments were rewritten by the requote). */
  requoted?: string;
}

export interface ExecGateArgsResult {
  /** The rewritten arguments JSON string, or null when unchanged (allow / no
   * command / unparseable — conservative: caller re-emits the original bytes). */
  arguments: string | null;
  /** The gate outcome, or null when there was no command to gate. */
  outcome: ExecGateOutcome | null;
}

/**
 * Gate one Codex function_call `arguments` JSON string. Returns the rewritten
 * arguments (on block) or null (allow / nothing to gate). NEVER throws: an
 * arbiter error/timeout is enforced as a block sentinel (fail-closed).
 */
export async function gateFunctionCallArguments(
  argumentsJson: string,
  opts: {
    arbiter: Pick<Arbiter, "execGate">;
    cwd?: string;
    /** The session this command belongs to. LOAD-BEARING since Plan 8: the
     *  arbiter tightens exec in a HIGH session and cannot tell without it. */
    sessionKey?: string;
    log?: (msg: string) => void;
    arbiterTimeoutMs?: number;
    /** The function_call's call_id (plan 13 D9 follow-up): the arbiter
     *  records the call's gate time and command under it (human socket). */
    callId?: string;
    /** The function's name: the requote below applies to a Codex shell tool
     *  only (CODEX_SHELL_TOOLS). */
    toolName?: string;
    /** Deliver the arbiter's `requoted` command on an allow (confidentiality.md
     *  §7, "A placeholder the agent's shell would expand"). Set for the
     *  function calls Codex runs and a code cell's exec_command literals (the
     *  same tool, re-encoded as JSON into the cell), never for the gate of a
     *  cell as one command. */
    requote?: boolean;
  },
): Promise<ExecGateArgsResult> {
  if (typeof argumentsJson !== "string" || argumentsJson.trim() === "") {
    return { arguments: null, outcome: null };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(argumentsJson);
  } catch {
    return { arguments: null, outcome: null }; // conservative: cannot parse → no gate
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { arguments: null, outcome: null };
  }
  const obj = parsed as Record<string, unknown>;
  const extracted = extractCommand(obj);
  // Every OTHER command-like field (plan 10 §11.13, MCP command tools: an MCP
  // tool's `script`, `code`, `argv`, … , or a key in another case) is gated as
  // the shell command is; a shape the gate cannot read is a block.
  const extras = commandLikeFields(obj).filter((f) => f.key !== extracted?.key);
  if (!extracted && extras.length === 0) return { arguments: null, outcome: null };

  const timeoutMs = opts.arbiterTimeoutMs ?? DEFAULT_EXEC_GATE_TIMEOUT_MS;
  const targets: Array<{ key: string; text: string | null }> = [
    ...(extracted ? [{ key: extracted.key, text: extracted.text }] : []),
    ...extras.map((f) => ({ key: f.key, text: f.text })),
  ];
  let allowed: ExecGateOutcome | null = null;
  let requotedText: string | undefined;
  let blocked: { key: string; command: string; decision: ExecGateDecision | null; reason: string } | null = null;
  for (const t of targets) {
    if (t.text === null) {
      blocked = { key: t.key, command: JSON.stringify(obj[t.key]), decision: null, reason: `the ${t.key} field is not a command the gate can read — fail closed` };
      break;
    }
    let decision: ExecGateDecision | null = null;
    let unreachable: string | null = null;
    try {
      decision = await withTimeout(
        opts.arbiter.execGate({ command: t.text, cwd: opts.cwd, sessionKey: opts.sessionKey, ...(opts.callId ? { callId: opts.callId } : {}) }),
        timeoutMs,
        `arbiter execGate timed out after ${timeoutMs}ms — fail closed`,
      );
    } catch (err) {
      unreachable = (err as Error).message;
    }
    if (decision && decision.decision === "allow") {
      allowed ??= {
        key: t.key, command: t.text,
        decision: "allow", reason: decision.reason,
        symbols: decision.symbols, evasion: decision.evasion,
        shell: decision.shell, identifier: decision.identifier,
      };
      if (extracted && t.key === extracted.key && typeof decision.requoted === "string" && decision.requoted !== "" && decision.requoted !== t.text) {
        requotedText = decision.requoted;
      }
      continue;
    }
    blocked = { key: t.key, command: t.text, decision, reason: decision ? decision.reason : `arbiter unreachable (${unreachable}) — fail closed` };
    break;
  }

  if (!blocked) {
    // A secret placeholder the shell would expand to nothing (`"$MDU:…"`,
    // unquoted) is delivered requoted, so the program receives it whole and
    // the egress gates see it (confidentiality.md §7). Shell text of a Codex
    // shell tool only; only `'` and `\` are inserted, nothing is resolved.
    const rebuild = opts.requote === true && opts.toolName !== undefined && CODEX_SHELL_TOOLS.has(opts.toolName)
      ? extracted?.withShellText ?? null
      : null;
    if (rebuild && extracted && requotedText !== undefined && allowed) {
      opts.log?.(`exec-gate: requoted a placeholder in function_call.${extracted.key} so the shell keeps it whole`);
      return {
        arguments: JSON.stringify({ ...obj, [extracted.key]: rebuild(requotedText) }),
        outcome: { ...allowed, requoted: requotedText },
      };
    }
    return { arguments: null, outcome: allowed };
  }

  // Block or unreachable: rewrite EVERY command-like field to the sentinel.
  const { reason, decision } = blocked;
  const sentinel = blockSentinelCommand(reason);
  const out: Record<string, unknown> = { ...obj };
  if (extracted) out[extracted.key] = extracted.toSentinel(sentinel);
  for (const f of extras) out[f.key] = f.shape === "argv" ? ["/bin/sh", "-c", sentinel] : sentinel;
  opts.log?.(`exec-gate: BLOCKED function_call.${blocked.key} (${reason})`);
  return {
    arguments: JSON.stringify(out),
    outcome: {
      key: blocked.key, command: blocked.command,
      decision: "block", reason,
      symbols: decision?.symbols ?? [],
      evasion: decision?.evasion ?? [],
      shell: decision?.shell ?? "AgentShell",
      identifier: decision?.identifier ?? null,
      sentinel,
      notice: blockNoticeText(reason),
    },
  };
}
