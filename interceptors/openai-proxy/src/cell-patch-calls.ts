/**
 * cell-patch-calls — the `tools.apply_patch(…)` calls of a Codex code-mode
 * cell whose patch is a literal, so the cell's `tool_use` record names the
 * files each patch touches (dashboard.md §4.25b, "A patch in a code cell").
 *
 * Mandu-new (no reference origin). WHY: in code mode (codex ≥ 0.154) the
 * model edits files from inside an `exec` cell, `await
 * tools.apply_patch("*** Begin Patch …")`, and the proxy reported a cell by
 * its `tools.exec_command({…})` literals only (script-cell.ts), so a patch in
 * a cell was no call on the dashboard and its files went unnamed. Each patch
 * call found here is reported as `apply_patch({"input": <patch>})`, the shape
 * of Codex's JSON and freeform patch records (sse-rewrite.ts freeformCalls),
 * under the cell's call id.
 *
 * OBSERVABILITY ONLY: this reader names files for the dashboard and decides
 * nothing. The gate reads the cell itself (script-cell.ts, mcp-cell.ts,
 * cell-guard.ts), never this. It is CONSERVATIVE all the same: a patch is
 * reported only when its text is certain from the source alone —
 *
 *   tools.apply_patch("…")  / ('…') / (`…` with no `${…}` hole)
 *   tools["apply_patch"](…) the same, by a string member
 *   tools.apply_patch({input: "…"})  a one-field object (`input`, `patch`,
 *                           `patchText`) whose value is such a literal
 *   tools.apply_patch(p)    where `p` is bound ONCE, `const p = <literal>`,
 *                           at the top level, before the call, and the name
 *                           appears nowhere else but as such an argument or
 *                           after a `.` (so nothing can shadow or rebind it;
 *                           a live model writes this form, test-reorganization
 *                           §8, "Code-mode cells as a live model writes them")
 *
 * Anything computed (a concatenation, a template with a hole, a call, a name
 * bound twice or by `let`, an alias of `tools`) reports nothing. The source is
 * read by a small JavaScript lexer that knows strings, templates (holes
 * nested), comments and regular expressions; where JavaScript itself needs
 * more than the previous token to tell a regular expression from a division
 * (a `/` after `)` or `}`), the WHOLE cell reports nothing, so a call is never
 * read out of a string or a comment.
 *
 * Pure and total: never throws.
 */

/** The nested tool this module reads, and the name its calls report. */
export const CELL_PATCH_TOOL = "apply_patch";

/** The one-field object forms' field names (patch-files.ts PATCH_FIELDS). */
const OBJECT_FIELDS: ReadonlySet<string> = new Set(["input", "patch", "patchText"]);

/** Bounds: past these, the cell is not read (a record only). */
const MAX_CELL_CHARS = 512 * 1024;

type Tok =
  | { t: "ident"; v: string; nl: boolean }
  | { t: "punct"; v: string; nl: boolean }
  /** A string or a template with no hole: its value. */
  | { t: "str"; v: string; nl: boolean }
  /** A template with holes, a piece of one, a number or a regex: no value. */
  | { t: "other"; v: string; nl: boolean };

class GiveUp extends Error {}
const giveUp = (): never => { throw new GiveUp(); };

/** JavaScript's line terminators and the other white space the lexer skips
 *  (built from code points, so this source holds no raw terminator). */
const LINE_END: ReadonlySet<string> = new Set(["\n", "\r", String.fromCharCode(0x2028), String.fromCharCode(0x2029)]);
const SPACE: ReadonlySet<string> = new Set([" ", "\t", "\f", "\v", String.fromCharCode(0xa0), String.fromCharCode(0xfeff)]);
const IDENT_START = /[A-Za-z_$]/;
const IDENT_PART = /[A-Za-z0-9_$]/;
/** Words after which a `/` starts a regular expression, not a division. */
const REGEX_AFTER_WORDS: ReadonlySet<string> = new Set([
  "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
  "case", "do", "else", "yield", "await",
]);
const SIMPLE_ESCAPES: Readonly<Record<string, string>> = {
  n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", v: "\v",
};

/** The escape at `src[at]` (a backslash): [its value, index past it], with
 *  JavaScript's meaning; an octal escape (a syntax error in a module) gives
 *  up. */
function readEscape(src: string, at: number): [string, number] {
  const n = src[at + 1];
  if (n === undefined) return giveUp();
  if (n in SIMPLE_ESCAPES) return [SIMPLE_ESCAPES[n]!, at + 2];
  if (n === "\r") return ["", src[at + 2] === "\n" ? at + 3 : at + 2]; // a line continuation
  if (n === "\n") return ["", at + 2];
  if (n === "0" && !/[0-9]/.test(src[at + 2] ?? "")) return ["\0", at + 2];
  if (/[0-9]/.test(n)) return giveUp();
  if (n === "x") {
    const hex = src.slice(at + 2, at + 4);
    if (!/^[0-9a-fA-F]{2}$/.test(hex)) giveUp();
    return [String.fromCharCode(parseInt(hex, 16)), at + 4];
  }
  if (n === "u") {
    if (src[at + 2] === "{") {
      const close = src.indexOf("}", at + 3);
      const hex = close < 0 ? "" : src.slice(at + 3, close);
      if (!/^[0-9a-fA-F]{1,6}$/.test(hex) || parseInt(hex, 16) > 0x10ffff) giveUp();
      return [String.fromCodePoint(parseInt(hex, 16)), close + 1];
    }
    const hex = src.slice(at + 2, at + 6);
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) giveUp();
    return [String.fromCharCode(parseInt(hex, 16)), at + 6];
  }
  return [n, at + 2]; // `\'`, `\"`, `` \` ``, `\\`, `\$`, any other character as itself
}

/** A `"…"` or `'…'` literal at `src[at]`: [value, index past it]. */
function readString(src: string, at: number): [string, number] {
  const q = src[at]!;
  let i = at + 1;
  let out = "";
  while (i < src.length) {
    const c = src[i]!;
    if (c === q) return [out, i + 1];
    if (c === "\n" || c === "\r") giveUp();
    if (c !== "\\") { out += c; i++; continue; }
    const [v, j] = readEscape(src, i);
    out += v;
    i = j;
  }
  return giveUp();
}

/** A template piece from `at`: [its text, index past it, a `${` follows]. */
function readTemplatePiece(src: string, at: number): [string, number, boolean] {
  let i = at;
  let out = "";
  while (i < src.length) {
    const c = src[i]!;
    if (c === "`") return [out, i + 1, false];
    if (c === "$" && src[i + 1] === "{") return [out, i + 2, true];
    if (c === "\\") {
      const [v, j] = readEscape(src, i);
      out += v;
      i = j;
      continue;
    }
    if (c === "\r") { out += "\n"; i += src[i + 1] === "\n" ? 2 : 1; continue; }
    out += c;
    i++;
  }
  return giveUp();
}

/** A `/…/flags` literal at `src[at]`: the index past it. */
function skipRegex(src: string, at: number): number {
  let i = at + 1;
  let inClass = false;
  while (i < src.length) {
    const c = src[i]!;
    if (c === "\n" || c === "\r") giveUp();
    if (c === "\\") { i += 2; continue; }
    if (inClass) { if (c === "]") inClass = false; i++; continue; }
    if (c === "[") { inClass = true; i++; continue; }
    if (c === "/") {
      let j = i + 1;
      while (j < src.length && IDENT_PART.test(src[j]!)) j++;
      return j;
    }
    i++;
  }
  return giveUp();
}

/** Does a `/` after `prev` start a regular expression? null: JavaScript
 *  needs more than one token to say (after `)` or `}`). */
function regexAfter(prev: Tok | undefined): boolean | null {
  if (prev === undefined) return true;
  if (prev.t === "punct") return prev.v === ")" || prev.v === "}" ? null : prev.v !== "]" && prev.v !== "++" && prev.v !== "--";
  if (prev.t === "ident") return REGEX_AFTER_WORDS.has(prev.v);
  if (prev.t === "other" && prev.v === "${") return true; // a hole's start
  return false; // after a literal: a division
}

/** The cell's tokens; throws GiveUp where it cannot be sure. */
function tokenize(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  let nl = false;
  // One entry per open template hole: the `{` opened inside it and not yet
  // closed, so the `}` that ends the hole is told from an object's.
  const holes: number[] = [];
  const push = (tok: Tok, to: number): void => { out.push(tok); nl = false; i = to; };
  const template = (at: number, opening: boolean): void => {
    const [v, j, hole] = readTemplatePiece(src, at);
    if (opening && !hole) { push({ t: "str", v, nl }, j); return; }
    push({ t: "other", v: "`", nl }, j);
    if (hole) { holes.push(0); out.push({ t: "other", v: "${", nl: false }); }
  };
  while (i < src.length) {
    const c = src[i]!;
    if (SPACE.has(c)) { i++; continue; }
    if (LINE_END.has(c)) { nl = true; i++; continue; }
    if (c === "/" && src[i + 1] === "/") {
      while (i < src.length && !LINE_END.has(src[i]!)) i++;
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      const end = src.indexOf("*/", i + 2);
      if (end < 0) giveUp();
      if ([...src.slice(i + 2, end)].some((ch) => LINE_END.has(ch))) nl = true;
      i = end + 2;
      continue;
    }
    if (c === "/") {
      const re = regexAfter(out[out.length - 1]);
      if (re === null) giveUp();
      if (re) { push({ t: "other", v: "/re/", nl }, skipRegex(src, i)); continue; }
      push({ t: "punct", v: "/", nl }, i + 1);
      continue;
    }
    if (c === "`") { template(i + 1, true); continue; }
    if (c === "{" && holes.length > 0) { holes[holes.length - 1]!++; push({ t: "punct", v: "{", nl }, i + 1); continue; }
    if (c === "}" && holes.length > 0) {
      if (holes[holes.length - 1] === 0) { holes.pop(); template(i + 1, false); continue; }
      holes[holes.length - 1]!--;
      push({ t: "punct", v: "}", nl }, i + 1);
      continue;
    }
    if (c === '"' || c === "'") {
      const [v, j] = readString(src, i);
      push({ t: "str", v, nl }, j);
      continue;
    }
    if (IDENT_START.test(c) || c === "\\" || c.charCodeAt(0) > 0x7f) {
      // A name; one with an escape or a non-ASCII letter is not read.
      let j = i + 1;
      while (j < src.length && IDENT_PART.test(src[j]!)) j++;
      if (c === "\\" || c.charCodeAt(0) > 0x7f || src[j] === "\\" || (src.charCodeAt(j) > 0x7f)) giveUp();
      push({ t: "ident", v: src.slice(i, j), nl }, j);
      continue;
    }
    if (c >= "0" && c <= "9" || (c === "." && /[0-9]/.test(src[i + 1] ?? ""))) {
      let j = i + 1;
      while (j < src.length && (/[0-9A-Za-z_.]/.test(src[j]!) || (/[eE]/.test(src[j - 1]!) && /[+-]/.test(src[j]!) && !/^0[xX]/.test(src.slice(i, j))))) j++;
      push({ t: "other", v: src.slice(i, j), nl }, j);
      continue;
    }
    if (c === "?" && src[i + 1] === "." && !/[0-9]/.test(src[i + 2] ?? "")) { push({ t: "punct", v: "?.", nl }, i + 2); continue; }
    // The punctuators this reader tells apart: `=>`, `==`/`===` (never a
    // binding's `=`), and `++`/`--` (after which a `/` divides).
    const two = src.slice(i, i + 2);
    if (two === "=>" || two === "++" || two === "--") { push({ t: "punct", v: two, nl }, i + 2); continue; }
    if (two === "==") { const w = src[i + 2] === "=" ? 3 : 2; push({ t: "punct", v: src.slice(i, i + w), nl }, i + w); continue; }
    // Any other punctuator, one character at a time: what it means is not
    // read, only that it is no string, name or bracket boundary.
    push({ t: "punct", v: c, nl }, i + 1);
  }
  if (holes.length > 0) giveUp();
  return out;
}

/** The index of the bracket closing the one at `open`, or -1. */
function closing(toks: readonly Tok[], open: number): number {
  let depth = 0;
  for (let k = open; k < toks.length; k++) {
    const tok = toks[k]!;
    if (tok.t !== "punct") continue;
    if (tok.v === "(" || tok.v === "[" || tok.v === "{") depth++;
    else if (tok.v === ")" || tok.v === "]" || tok.v === "}") {
      depth--;
      if (depth === 0) return k;
      if (depth < 0) return -1;
    }
  }
  return -1;
}

/** Words that bind the name after them. */
const BINDERS: ReadonlySet<string> = new Set(["const", "let", "var", "function", "class"]);

const isP = (tok: Tok | undefined, v: string): boolean => tok?.t === "punct" && tok.v === v;
const isMember = (tok: Tok | undefined): boolean => isP(tok, ".") || isP(tok, "?.");

/** One patch call found: the token span of its argument. */
interface PatchCall { argFrom: number; argTo: number }

/** Every `tools.apply_patch(` / `tools["apply_patch"](` call: its argument
 *  tokens (between the parentheses). */
function patchCallSites(toks: readonly Tok[]): PatchCall[] {
  const out: PatchCall[] = [];
  for (let k = 0; k < toks.length; k++) {
    const tok = toks[k]!;
    if (tok.t !== "ident" || tok.v !== "tools" || isMember(toks[k - 1])) continue;
    let open: number;
    if (isP(toks[k + 1], ".") && toks[k + 2]?.t === "ident" && toks[k + 2]!.v === CELL_PATCH_TOOL) open = k + 3;
    else if (isP(toks[k + 1], "[") && toks[k + 2]?.t === "str" && toks[k + 2]!.v === CELL_PATCH_TOOL && isP(toks[k + 3], "]")) open = k + 4;
    else continue;
    if (!isP(toks[open], "(")) continue;
    const close = closing(toks, open);
    if (close < 0) continue;
    out.push({ argFrom: open + 1, argTo: close });
  }
  return out;
}

/** A literal argument's patch text: one string token, or a one-field object
 *  `{input: <string>}` (a trailing comma allowed). */
function literalPatch(toks: readonly Tok[], from: number, to: number): string | null {
  const span = toks.slice(from, to);
  if (span.length === 1 && span[0]!.t === "str") return span[0]!.v;
  if (span.length < 5 || span.length > 6 || !isP(span[0], "{") || !isP(span[span.length - 1], "}")) return null;
  const key = span[1]!;
  if (!((key.t === "ident" || key.t === "str") && OBJECT_FIELDS.has(key.v)) || !isP(span[2], ":") || span[3]!.t !== "str") return null;
  if (span.length === 6 && !isP(span[4], ",")) return null;
  return span[3]!.v;
}

/** The literal a name stands for: bound once, `const <name> = <literal>`, at
 *  the top level before `before`, ending the statement; every other mention
 *  of the name an apply_patch argument (`args`) or a member after a `.`. */
function boundLiteral(toks: readonly Tok[], name: string, before: number, args: ReadonlySet<number>): string | null {
  let binding = -1;
  let depth = 0;
  for (let k = 0; k < toks.length; k++) {
    const tok = toks[k]!;
    if (tok.t === "punct") {
      if (tok.v === "(" || tok.v === "[" || tok.v === "{") depth++;
      else if (tok.v === ")" || tok.v === "]" || tok.v === "}") depth--;
      continue;
    }
    if (tok.t !== "ident" || tok.v !== name) continue;
    if (isMember(toks[k - 1]) || args.has(k)) continue;
    const prev = toks[k - 1];
    if (binding < 0 && depth === 0 && prev?.t === "ident" && prev.v === "const" && isP(toks[k + 1], "=") && k < before) {
      binding = k;
      continue;
    }
    return null; // any other mention could bind, rebind or shadow it
  }
  if (binding < 0) return null;
  const value = toks[binding + 2];
  const after = toks[binding + 3];
  if (value?.t !== "str") return null;
  // The statement ends there: a `;`, the cell's end, or a line break before
  // a name that starts a statement (ASI; a line starting with an operator,
  // a bracket or a template would continue the expression).
  const ends = after === undefined || isP(after, ";") || (after.nl && after.t === "ident" && after.v !== "in" && after.v !== "instanceof");
  return ends ? value.v : null;
}

/**
 * The patch calls of a code-mode cell whose patch text is certain, in source
 * order, each as Codex's patch record: `{name: "apply_patch", argsJson:
 * {"input": <patch>}}`. Empty for a cell with none, or one this reader cannot
 * be sure of.
 */
export function cellPatchCalls(src: string): Array<{ name: string; argsJson: string }> {
  if (typeof src !== "string" || src.length > MAX_CELL_CHARS || !src.includes(CELL_PATCH_TOOL)) return [];
  let toks: Tok[];
  try {
    toks = tokenize(src);
  } catch {
    return [];
  }
  // A cell that binds its own `tools` calls something else by that name.
  const bindsTools = toks.some((tok, k) => {
    if (tok.t !== "ident" || tok.v !== "tools" || isMember(toks[k - 1])) return false;
    const prev = toks[k - 1];
    return (prev?.t === "ident" && BINDERS.has(prev.v)) || isP(toks[k + 1], "=") || isP(toks[k + 1], "=>");
  });
  if (bindsTools) return [];
  const sites = patchCallSites(toks);
  // The positions where a bare name is a whole patch argument.
  const nameArgs = new Set(sites.filter((s) => s.argTo === s.argFrom + 1 && toks[s.argFrom]!.t === "ident").map((s) => s.argFrom));
  const out: Array<{ name: string; argsJson: string }> = [];
  for (const s of sites) {
    let patch = literalPatch(toks, s.argFrom, s.argTo);
    if (patch === null && nameArgs.has(s.argFrom)) patch = boundLiteral(toks, toks[s.argFrom]!.v, s.argFrom, nameArgs);
    if (patch !== null && patch.trim() !== "") out.push({ name: CELL_PATCH_TOOL, argsJson: JSON.stringify({ input: patch }) });
  }
  return out;
}
