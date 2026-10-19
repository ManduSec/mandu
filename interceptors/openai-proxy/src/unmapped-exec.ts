/**
 * unmapped-exec — the command a tool call carries when the gate surface does
 * not know the tool as a shell (confidentiality-plan-10-flow-taint.md §11.12).
 *
 * The exec-output legs (callTaint, the `[mandu:secret]` note) ask the arbiter
 * for the process tree behind a SHELL result, and only the gate surface's
 * `execOutput` tools are shells. A tool nobody mapped (a plugin's exec, an MCP
 * server's `run_command`, an eval tool) can run a command whose tree read a
 * secret raw (a listed reader such as `psql`) and hand its output back with no
 * tree lookup at all. The backstop: a call whose input carries a command-like
 * field is asked about too, with `unmappedTool` set. The arbiter answers only
 * for a tool the session's spec does not know (with the axis on), from the
 * tree the guard tied to the command, else from every raw secret read of the
 * session; the caller only ever RAISES the result's level on that answer.
 *
 * A MIRROR of interceptors/anthropic-proxy/src/unmapped-exec.ts (no cross-package
 * import); each package's unit test pins the same key list.
 *
 * Pure and total: never throws.
 */

/** Input keys that name a command, script or code to run (compared
 *  case-insensitively, top level only; a dispatcher's inner input is
 *  unwrapped before this is asked). */
export const COMMAND_LIKE_KEYS: readonly string[] = [
  "command", "cmd", "commandline", "command_line", "cmdline",
  "script", "shell", "bash", "code", "argv",
];

const KEYS = new Set(COMMAND_LIKE_KEYS);

/** Quote one argv element for the arbiter's tokenizer (exec-signature.ts):
 *  bare when it has no shell-significant byte, else single-quoted. */
function quoteArg(a: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, `'"'"'`)}'`;
}

/** The command text of an argv array, joined so the arbiter's signature
 *  tokenizer splits it back into the same elements. */
export function argvCommandText(argv: readonly unknown[]): string | null {
  if (argv.length === 0 || !argv.every((a) => typeof a === "string")) return null;
  return (argv as string[]).map(quoteArg).join(" ");
}

/** The first command-like field's text: a non-empty string, or an argv array
 *  of strings joined. Null when the input names no command. */
export function commandLikeText(input: unknown): string | null {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return null;
  for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
    if (!KEYS.has(k.toLowerCase())) continue;
    if (typeof v === "string" && v.trim() !== "") return v;
    if (Array.isArray(v)) {
      const joined = argvCommandText(v);
      if (joined !== null && joined.trim() !== "") return joined;
    }
  }
  return null;
}

/** One command-like field of a tool's input, as the response-side exec gate
 *  reads it (plan 10 §11.13, MCP command tools). `text` is the command to
 *  gate: the string, or an argv array joined; null when the value is a shape
 *  the gate cannot read (an object, an array with a non-string), which the
 *  gate treats as a block. Booleans, numbers and empty values are not a
 *  command (`shell: true` is a flag). */
export interface CommandLikeField {
  key: string;
  text: string | null;
  shape: "string" | "argv" | "other";
}

/** Every command-like top-level field of an input, in input order. */
export function commandLikeFields(input: unknown): CommandLikeField[] {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return [];
  const out: CommandLikeField[] = [];
  for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
    if (!KEYS.has(k.toLowerCase())) continue;
    if (typeof v === "string") {
      if (v.trim() !== "") out.push({ key: k, text: v, shape: "string" });
    } else if (Array.isArray(v)) {
      if (v.length === 0) continue;
      const joined = argvCommandText(v);
      out.push(joined !== null && joined.trim() !== "" ? { key: k, text: joined, shape: "argv" } : { key: k, text: null, shape: "other" });
    } else if (v !== null && typeof v === "object") {
      out.push({ key: k, text: null, shape: "other" });
    }
  }
  return out;
}

const RANK: Readonly<Record<string, number>> = { public: 0, "any-model": 1, "local-model": 2, "no-model": 3 };

/** The stricter of two confidentiality levels (arbiter confidentiality.ts's
 *  lattice). Absent = public; an unknown value ranks strictest (fail-closed,
 *  a level minted by a newer arbiter). A taint only ever raises a verdict. */
export function stricterLevel(current: string | undefined, raised: string): string {
  const rank = (l: string | undefined): number => (l === undefined || l === "" ? 0 : RANK[l] ?? 3);
  return rank(current) >= rank(raised) && current !== undefined ? current : raised;
}
