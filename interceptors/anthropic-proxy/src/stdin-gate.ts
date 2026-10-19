/**
 * stdin-gate — the exec gate for text a tool TYPES into a running process
 * (supported-agents.md §2.1; the table is GateSurface.stdin, owned by the
 * arbiter's tool-gate-surface.ts).
 *
 * OpenClaw's `process` tool writes into the stdin of a background `exec`
 * session: `write{data}`, `paste{text}` and `send-keys{literal, hex, keys}`
 * (bash-tools.ts in 2026.7.1 and 2026.9.6). The session is whatever `exec`
 * started, often a shell or a REPL, so the typed text runs as commands that
 * no exec gate saw: the command gate (an untrusted symbol in command
 * position) and, in a high session, the net-capability gate that blocks
 * every shell command both stood aside. This module reads each typed stream
 * the way OpenClaw builds it and puts it through the SAME arbiter `execGate`
 * op as a shell command:
 *
 *   - `data` and `text`, each as written (a bracketed paste adds only the
 *     paste markers);
 *   - `literal` + the `hex` bytes + the encoded `keys`, concatenated in that
 *     order (encodeKeySequence). A key token is encoded as OpenClaw does for
 *     the parts that matter to a command reader: one character is itself,
 *     `^X` is its control character, `Enter` / `Return` is CR, `Tab` /
 *     `Space` / `BSpace` their characters, any other named key an ESC (a
 *     cursor or function key edits the line, it types no word), and an
 *     unknown token is sent literally, as OpenClaw sends it.
 *
 * Any stream the gate blocks, a malformed field (a non-string `data`, a
 * non-array `keys`), an unreachable arbiter or more than
 * STDIN_GATE_MAX_BYTES of typed text refuses the WHOLE call: the proxy sends
 * `{action: "mandu-refused: <why>"}`, which 2026.9.6's action enum rejects
 * and 2026.7.1 answers "Unknown action", so nothing is typed. No callId is
 * passed: the stdin text is not a process the exec supervisor will spawn,
 * so it must not become one's clean-verdict correlation.
 *
 * Pure except for the arbiter call; never throws.
 */

import type { Arbiter } from "./arbiter-client.js";
import { gateExecToolUse, type ExecGateOutcome } from "./exec-gate.js";
import type { StdinKind } from "./gate-surface.js";

/** Typed text past this many bytes in one call is refused unread. */
export const STDIN_GATE_MAX_BYTES = 1024 * 1024;

const NAMED: Record<string, string> = { enter: "\r", return: "\r", tab: "\t", space: " ", bspace: "\x7f", backspace: "\x7f" };
const OTHER_NAMED = /^(escape|esc|up|down|right|left|home|end|pageup|pgup|ppage|pagedown|pgdn|npage|insert|ic|delete|del|dc|btab|f[0-9]{1,2}|kp.+)$/;

/** One key token as the bytes OpenClaw would send (see the header). */
export function encodeKeyToken(raw: string): string {
  const token = raw.trim();
  if (token === "") return "";
  if (token.length === 2 && token.startsWith("^")) {
    const c = token.charAt(1).toUpperCase();
    if (c >= "@" && c <= "_") return String.fromCharCode(c.charCodeAt(0) - 64);
    if (c === "?") return "\x7f";
  }
  let base = token;
  while (base.length > 2 && base[1] === "-" && "cmsCMS".includes(base[0]!)) base = base.slice(2);
  const lower = base.toLowerCase();
  if (Object.prototype.hasOwnProperty.call(NAMED, lower)) return NAMED[lower]!;
  if (OTHER_NAMED.test(lower)) return "\x1b";
  return base;
}

function hexByte(raw: string): number | null {
  const lower = raw.trim().toLowerCase();
  const n = lower.startsWith("0x") ? lower.slice(2) : lower;
  return /^[0-9a-f]{1,2}$/.test(n) ? Number.parseInt(n, 16) : null;
}

const isStrArray = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");
const present = (v: unknown): boolean => v !== undefined && v !== null;

/** The text streams a call types, each with the field(s) it came from; a
 *  string naming the malformed field when the input cannot be read. Pure. */
export function typedStreams(kind: StdinKind, input: unknown): Array<{ field: string; text: string }> | string {
  void kind; // one kind today: openclaw-process
  if (!input || typeof input !== "object" || Array.isArray(input)) return [];
  const o = input as Record<string, unknown>;
  const out: Array<{ field: string; text: string }> = [];
  for (const f of ["data", "text"]) {
    if (!present(o[f])) continue;
    if (typeof o[f] !== "string") return f;
    if (o[f] !== "") out.push({ field: f, text: o[f] as string });
  }
  if (present(o["literal"]) && typeof o["literal"] !== "string") return "literal";
  if (present(o["hex"]) && !isStrArray(o["hex"])) return "hex";
  if (present(o["keys"]) && !isStrArray(o["keys"])) return "keys";
  const bytes: number[] = [];
  for (const h of (o["hex"] as string[] | undefined) ?? []) {
    const b = hexByte(h);
    if (b !== null) bytes.push(b);
  }
  const keys = ((o["keys"] as string[] | undefined) ?? []).map(encodeKeyToken).join("");
  const seq = Buffer.concat([Buffer.from((o["literal"] as string | undefined) ?? ""), Buffer.from(bytes), Buffer.from(keys)]).toString("utf8");
  if (seq !== "") out.push({ field: "literal+hex+keys", text: seq });
  return out;
}

export interface StdinGateResult {
  /** null: the tool types nothing on this surface, or this call types
   *  nothing. */
  outcome:
    | null
    | { decision: "allow"; checked: ExecGateOutcome[] }
    | { decision: "block"; field: string; reason: string; gate: ExecGateOutcome | null };
}

/** Gate every stream a stdin tool types. NEVER throws: an arbiter error is a
 *  block (gateExecToolUse fails closed). */
export async function gateStdinToolUse(
  name: string,
  input: unknown,
  opts: {
    stdinTools: Readonly<Record<string, StdinKind>>;
    arbiter: Pick<Arbiter, "execGate">;
    sessionKey?: string;
    log?: (msg: string) => void;
    arbiterTimeoutMs?: number;
  },
): Promise<StdinGateResult> {
  if (!Object.prototype.hasOwnProperty.call(opts.stdinTools, name)) return { outcome: null };
  const streams = typedStreams(opts.stdinTools[name]!, input);
  if (typeof streams === "string") {
    return { outcome: { decision: "block", field: streams, reason: `the ${streams} field is not text Mandu can check — fail closed`, gate: null } };
  }
  if (streams.length === 0) return { outcome: null };
  const total = streams.reduce((n, s) => n + Buffer.byteLength(s.text), 0);
  if (total > STDIN_GATE_MAX_BYTES) {
    return { outcome: { decision: "block", field: streams[0]!.field, reason: `${total} bytes of typed text exceeds the gate's bound (${STDIN_GATE_MAX_BYTES}) — fail closed`, gate: null } };
  }
  const checked: ExecGateOutcome[] = [];
  for (const s of streams) {
    const eg = await gateExecToolUse(name, { command: s.text }, {
      arbiter: opts.arbiter,
      commandFields: { [name]: "command" },
      ...(opts.sessionKey !== undefined ? { sessionKey: opts.sessionKey } : {}),
      ...(opts.log ? { log: opts.log } : {}),
      ...(opts.arbiterTimeoutMs !== undefined ? { arbiterTimeoutMs: opts.arbiterTimeoutMs } : {}),
    });
    if (!eg.outcome) continue;
    const gate = { ...eg.outcome, field: s.field };
    if (gate.decision === "block") return { outcome: { decision: "block", field: s.field, reason: gate.reason, gate } };
    checked.push(gate);
  }
  return { outcome: { decision: "allow", checked } };
}
