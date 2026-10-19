/**
 * mcp-cell — when a Codex `exec` script cell is nothing but ONE literal call to
 * an MCP tool (or an `ALL_TOOLS` listing, bare or filtered), so the request rewrite may
 * classify its result as that tool's, exactly as it classifies the namespaced
 * `function_call` to the same tool (confidentiality-plan-10-flow-taint.md
 * §11.13).
 *
 * Mandu Track A (interceptors/openai-proxy). Codex's code mode wraps every
 * nested tool call in a JavaScript cell (supported-agents.md §6); on the
 * ChatGPT backend the MCP calls ride only that wire. A cell with no
 * `tools.exec_command({…})` literal used to be classified as an unknown tool
 * whose input is its whole source, so the policy tools' results were masked
 * by what the SOURCE mentioned, while the namespaced call to the same tool
 * passed.
 *
 * ALLOW-LIST, NOT DENY-LIST. The cell is tokenized by a strict tokenizer and
 * parsed by a tiny recursive-descent grammar; anything the grammar does not
 * name refuses (returns null), and a refused cell keeps the fail-closed
 * handling it had (plan 10 §11.11 on its source, §11.12 as `exec`). The
 * grammar, informally:
 *
 *   cell   := stmt ((";" | line break) stmt)* ";"*
 *   stmt   := "const" NAME "=" (call | list) | call | "text" "(" expr ")"
 *   call   := "await" "tools" ("." MCP | "[" "\"MCP\"" "]") "(" object ")"
 *   expr   := call | ref | list
 *           | "JSON" "." "stringify" "(" (call | ref | list) ("," "null" ("," INT)?)? ")"
 *   ref    := NAME (("." | "?.") FIELD | ("[" | "?.[") INT "]")*
 *   object := a JSON-like literal: identifier or string keys (never computed,
 *             shorthand or `__proto__`), string / number / true / false / null
 *             / array / object values
 *   list   := ("ALL_TOOLS" | LISTNAME) lstep*
 *   lstep  := "." ("filter" | "find" | "findIndex" | "some" | "every" | "map") "(" arrow ")"
 *           | "." "slice" "(" INT ("," INT)? ")" | "." "join" "(" STRING? ")"
 *           | ("." | "?.") LFIELD | "[" INT "]"
 *   arrow  := (P | "(" P ")") "=>" value       (one parameter, no block body)
 *   value  := `||` `??` `&&`, one `===` `!==` `==` `!=`, `!`, string `+` over
 *             P, string / number / true / false / null / template literals
 *             (holes are values), `( value )`, `{ KEY: value, … }`,
 *             `[ value, … ]`, member steps (LFIELD, `[INT]`), the methods
 *             toLowerCase / toUpperCase / trim / includes / startsWith /
 *             endsWith / indexOf, and REGEX ".test" "(" value ")"
 *
 * with: exactly ONE call in an MCP cell (none in a listing cell, and a cell
 * never mixes the two); MCP = `mcp__<server>__<tool>`; the one bound NAME is
 * bound before use and is not a name the grammar reads or a reserved word
 * (LISTNAME is that NAME bound to a list); a FIELD is never a name a
 * built-in prototype of a JSON value defines (so a step reads the tool's own
 * data, and nothing is ever called on it); an LFIELD is a FIELD or `name`,
 * `description`, `length`; P is the arrow's own parameter, the only name an
 * arrow reads.
 *
 * The filtered listing (plan 10 §11.13; codex-cli 0.160 tells the model to
 * "filter `ALL_TOOLS` by `name` and `description`" to find deferred MCP
 * tools): every value it computes comes from `ALL_TOOLS` and the cell's own
 * literals through pure built-ins, so its output is a function of the bare
 * listing, which already qualifies.
 *
 * The other precondition — each cell runs in a FRESH isolate, so `tools`,
 * `text` and `JSON` are the host's own and no earlier cell redefined them —
 * is read off the request's own `exec` tool description (cellsAreIsolated).
 *
 * Pure and total: never throws.
 */

/** The phrase codex's `exec` tool description carries when every cell is a
 *  fresh V8 isolate (codex-cli 0.159.1: "Evaluates the provided JavaScript
 *  code in a fresh V8 isolate as an async module."). */
export const ISOLATED_CELL_PHRASE = "fresh V8 isolate";

/** The custom tool whose cells this module reads (codex's code mode). */
export const CODE_MODE_TOOL = "exec";

/** The nested shell the grammar identifies (script-cell.ts
 *  SCRIPT_EXEC_FUNCTIONS, the same one name). */
const SHELL_TOOLS: ReadonlySet<string> = new Set(["exec_command"]);

export type McpCell =
  | { kind: "mcp"; name: string; args: Record<string, unknown> }
  | { kind: "listing" };

/**
 * Does the request's tool battery say each `exec` cell runs in a fresh
 * isolate? `tools` is the flattened battery (responses-types.ts
 * advertisedTools). False when the tool is absent or its description does not
 * carry the phrase: a codex that keeps state across cells turns the rule off.
 */
export function cellsAreIsolated(tools: readonly unknown[]): boolean {
  if (!Array.isArray(tools)) return false;
  return tools.some((t) => {
    if (!t || typeof t !== "object") return false;
    const r = t as { type?: unknown; name?: unknown; description?: unknown };
    return r.type === "custom" && r.name === CODE_MODE_TOOL && typeof r.description === "string" && r.description.includes(ISOLATED_CELL_PHRASE);
  });
}

// ── tokenizer ────────────────────────────────────────────────────────────────

type Tok =
  | { t: "ident"; v: string; nl: boolean }
  | { t: "punct"; v: string; nl: boolean }
  | { t: "str"; v: string; nl: boolean }
  | { t: "num"; v: string; nl: boolean }
  /** A regular expression literal (`/…/flags`): only ever the receiver of
   *  `.test(…)` in a listing's arrow function. */
  | { t: "regex"; v: string; nl: boolean }
  /** A template literal's text: `full` (no hole), or the pieces around its
   *  `${…}` holes (`head` before the first, `middle` between two, `tail`
   *  after the last); each hole's tokens sit between its pieces. */
  | { t: "tmpl"; v: string; part: "full" | "head" | "middle" | "tail"; nl: boolean };

class Refuse extends Error {}
const refuse = (why: string): never => { throw new Refuse(why); };

const IDENT_START = /[A-Za-z_$]/;
const IDENT_PART = /[A-Za-z0-9_$]/;
const NUMBER_RE = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/;
const SIMPLE_ESCAPES: Readonly<Record<string, string>> = {
  '"': '"', "'": "'", "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v",
};
/** Bounds: a cell longer than this is not the small call this rule is for. */
const MAX_CELL_CHARS = 64 * 1024;
const MAX_DEPTH = 32;
/** U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR (built from code
 *  points so the source holds no raw terminator). */
const LS = String.fromCharCode(0x2028);
const PS = String.fromCharCode(0x2029);

function tokenize(src: string): Tok[] {
  if (src.length > MAX_CELL_CHARS) refuse("cell too long");
  // JavaScript line terminators that are not ASCII would end a `//` comment
  // in V8 but not here: refused anywhere, so the two never disagree.
  if (src.includes(LS) || src.includes(PS)) refuse("a non-ASCII line terminator");
  const out: Tok[] = [];
  let i = 0;
  let nl = false;
  // One entry per open template hole (`${`): the `{` opened inside it and not
  // yet closed, so the `}` that ends the hole is told from an object's.
  const holes: number[] = [];
  const punct = (v: string, width: number): void => {
    out.push({ t: "punct", v, nl });
    nl = false;
    i += width;
  };
  /** A template piece from `at` (just past its opening backtick, or past the
   *  brace that closes a hole), pushed as a token. */
  const templatePiece = (at: number, opening: boolean): void => {
    const [v, j, hole] = readTemplatePiece(src, at);
    const part = opening ? (hole ? "head" : "full") : (hole ? "middle" : "tail");
    out.push({ t: "tmpl", v, part, nl });
    nl = false;
    if (hole) holes.push(0);
    i = j;
  };
  while (i < src.length) {
    const c = src[i]!;
    if (c === " " || c === "\t") { i++; continue; }
    if (c === "\n" || c === "\r") { nl = true; i++; continue; }
    if (c === "/" && src[i + 1] === "/") {
      while (i < src.length && src[i] !== "\n" && src[i] !== "\r") i++;
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      const end = src.indexOf("*/", i + 2);
      if (end < 0) refuse("an unterminated comment");
      if (/[\n\r]/.test(src.slice(i + 2, end))) nl = true;
      i = end + 2;
      continue;
    }
    if (c === "/") {
      // The grammar has no division, so a `/` is a regular expression where
      // JavaScript reads one (after an operator or an opening bracket) and
      // is refused anywhere else: the two never disagree on where it ends.
      if (!regexMayStart(out[out.length - 1])) refuse("an operator");
      const [v, j] = readRegex(src, i);
      out.push({ t: "regex", v, nl });
      nl = false;
      i = j;
      continue;
    }
    if (c === "`") { templatePiece(i + 1, true); continue; }
    if (c === "{" && holes.length > 0) { holes[holes.length - 1]!++; punct("{", 1); continue; }
    if (c === "}" && holes.length > 0) {
      if (holes[holes.length - 1] === 0) { holes.pop(); templatePiece(i + 1, false); continue; }
      holes[holes.length - 1]!--;
      punct("}", 1);
      continue;
    }
    if (IDENT_START.test(c)) {
      let j = i + 1;
      while (j < src.length && IDENT_PART.test(src[j]!)) j++;
      if (src[j] === "\\") refuse("an escape in an identifier");
      out.push({ t: "ident", v: src.slice(i, j), nl });
      nl = false;
      i = j;
      continue;
    }
    if (c === '"' || c === "'") {
      const [v, j] = readString(src, i);
      out.push({ t: "str", v, nl });
      nl = false;
      i = j;
      continue;
    }
    if (c === "-" || (c >= "0" && c <= "9")) {
      const m = NUMBER_RE.exec(src.slice(i));
      if (!m) refuse("not a decimal number");
      const j = i + m![0].length;
      if (j < src.length && /[A-Za-z0-9_$.\\]/.test(src[j]!)) refuse("a number followed by a name or a dot");
      out.push({ t: "num", v: m![0], nl });
      nl = false;
      i = j;
      continue;
    }
    if (c === "?") {
      // `?.` is optional chaining only when no digit follows (`a?.5:1` is a
      // conditional); `??` (never `??=`) is a listing's fallback; any other
      // `?` is an operator the grammar does not have
      if (src[i + 1] === "." && !/[0-9]/.test(src[i + 2] ?? "")) { punct("?.", 2); continue; }
      if (src[i + 1] === "?" && src[i + 2] !== "=") { punct("??", 2); continue; }
      refuse("an operator");
    }
    // A listing's arrow functions (`=>`), comparisons, `!`, `&&`, `||` and
    // string `+`; never an assignment form (`+=`, `&&=`, …) or `++`.
    if (c === "=") {
      if (src.startsWith("===", i)) { punct("===", 3); continue; }
      if (src[i + 1] === "=") { punct("==", 2); continue; }
      if (src[i + 1] === ">") { punct("=>", 2); continue; }
      punct("=", 1);
      continue;
    }
    if (c === "!") {
      if (src.startsWith("!==", i)) { punct("!==", 3); continue; }
      if (src[i + 1] === "=") { punct("!=", 2); continue; }
      punct("!", 1);
      continue;
    }
    if ((c === "&" || c === "|") && src[i + 1] === c && src[i + 2] !== "=") { punct(c + c, 2); continue; }
    if (c === "+" && src[i + 1] !== "+" && src[i + 1] !== "=") { punct("+", 1); continue; }
    if (c === "." && /[0-9]/.test(src[i + 1] ?? "")) refuse("a number with no integer part");
    if ("(){}[].,:;".includes(c)) {
      out.push({ t: "punct", v: c, nl });
      nl = false;
      i++;
      continue;
    }
    refuse(`the character ${JSON.stringify(c)}`);
  }
  if (holes.length > 0) refuse("an unterminated template");
  return out;
}

/** A `"…"` or `'…'` literal starting at `src[at]`: [value, index past it]. */
function readString(src: string, at: number): [string, number] {
  const q = src[at]!;
  let i = at + 1;
  let out = "";
  while (i < src.length) {
    const c = src[i]!;
    if (c === q) return [out, i + 1];
    if (c === "\n" || c === "\r") refuse("a line break in a string");
    if (c !== "\\") { out += c; i++; continue; }
    const [v, j] = readEscape(src, i);
    out += v;
    i = j;
  }
  return refuse("an unterminated string");
}

/** The escape at `src[at]` (a backslash) in a string or a template:
 *  [its value, index past it]. Only the simple escapes, `\0` (not before a
 *  digit), `\xHH` and `\uHHHH`; anything else refuses. */
function readEscape(src: string, at: number): [string, number] {
  const n = src[at + 1];
  if (n === undefined) return refuse("an unterminated string");
  if (n in SIMPLE_ESCAPES) return [SIMPLE_ESCAPES[n]!, at + 2];
  if (n === "0") {
    if (/[0-9]/.test(src[at + 2] ?? "")) refuse("an octal escape");
    return ["\0", at + 2];
  }
  if (n === "x") {
    const hex = src.slice(at + 2, at + 4);
    if (!/^[0-9a-fA-F]{2}$/.test(hex)) refuse("a bad \\x escape");
    return [String.fromCharCode(parseInt(hex, 16)), at + 4];
  }
  if (n === "u") {
    const hex = src.slice(at + 2, at + 6);
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) refuse("a \\u escape other than \\uHHHH");
    return [String.fromCharCode(parseInt(hex, 16)), at + 6];
  }
  return refuse("an escape the grammar does not take");
}

/** One template piece from `at` (past the opening backtick, or past the
 *  brace that closes a hole): [its text, index past it, whether a `${`
 *  hole follows]. A string's escapes plus `` \` ``, `\$`, `\{` and `\}`; a
 *  raw line break is text (CR LF read as LF, as JavaScript does). */
function readTemplatePiece(src: string, at: number): [string, number, boolean] {
  let i = at;
  let out = "";
  while (i < src.length) {
    const c = src[i]!;
    if (c === "`") return [out, i + 1, false];
    if (c === "$" && src[i + 1] === "{") return [out, i + 2, true];
    if (c === "\\") {
      const n = src[i + 1];
      if (n === "`" || n === "$" || n === "{" || n === "}") { out += n; i += 2; continue; }
      const [v, j] = readEscape(src, i);
      out += v;
      i = j;
      continue;
    }
    if (c === "\r") { out += "\n"; i += src[i + 1] === "\n" ? 2 : 1; continue; }
    out += c;
    i++;
  }
  return refuse("an unterminated template");
}

/** Where JavaScript reads a `/` as the start of a regular expression: first,
 *  or after an operator, an opening bracket or a template hole's start. After
 *  a name, a literal or a closing bracket it is a division (and `}` is
 *  ambiguous): the caller refuses those. */
function regexMayStart(prev: Tok | undefined): boolean {
  if (prev === undefined) return true;
  if (prev.t === "punct") return prev.v !== ")" && prev.v !== "]" && prev.v !== "}";
  if (prev.t === "tmpl") return prev.part === "head" || prev.part === "middle";
  return false;
}

/** The flags taken, each at most once (V8 also knows `v`, whose class syntax
 *  differs: left out, so this scanner and V8 read one grammar). */
const REGEX_FLAGS_RE = /^(?!.*(.).*\1)[dgimsuy]*$/;

/** A `/…/flags` literal starting at `src[at]`: [its source, index past it].
 *  It ends where ECMAScript's RegularExpressionLiteral ends (a backslash
 *  takes the next character; a `/` inside a `[…]` class does not end it);
 *  refused when V8 would not compile it. */
function readRegex(src: string, at: number): [string, number] {
  let i = at + 1;
  let inClass = false;
  while (i < src.length) {
    const c = src[i]!;
    if (c === "\n" || c === "\r") refuse("a line break in a regular expression");
    if (c === "\\") {
      const n = src[i + 1];
      if (n === undefined || n === "\n" || n === "\r") refuse("an unterminated regular expression");
      i += 2;
      continue;
    }
    if (inClass) { if (c === "]") inClass = false; i++; continue; }
    if (c === "[") { inClass = true; i++; continue; }
    if (c === "/") {
      const body = src.slice(at + 1, i);
      let j = i + 1;
      while (j < src.length && IDENT_PART.test(src[j]!)) j++;
      if (src[j] === "\\") refuse("an escape after a regular expression");
      const flags = src.slice(i + 1, j);
      if (body === "" || !REGEX_FLAGS_RE.test(flags)) refuse("a regular expression V8 would not take");
      try { new RegExp(body, flags); } catch { refuse("a regular expression V8 would not compile"); }
      return [`/${body}/${flags}`, j];
    }
    i++;
  }
  return refuse("an unterminated regular expression");
}

// ── parser ───────────────────────────────────────────────────────────────────

/** Names the grammar itself reads, plus JavaScript's reserved and restricted
 *  words: never a binding (a binding named `text` would turn `text(…)` into a
 *  call of the tool's result). */
const UNBINDABLE: ReadonlySet<string> = new Set([
  "tools", "text", "JSON", "ALL_TOOLS", "stringify",
  "await", "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do",
  "else", "enum", "export", "extends", "false", "finally", "for", "function", "if", "import", "in",
  "instanceof", "new", "null", "return", "super", "switch", "this", "throw", "true", "try", "typeof",
  "var", "void", "while", "with", "yield", "let", "static", "implements", "interface", "package",
  "private", "protected", "public", "as", "async", "of", "get", "set", "from",
  "undefined", "NaN", "Infinity", "eval", "arguments", "globalThis",
]);

/** The built-in prototypes a JSON value (or a function reached through one)
 *  inherits from: a member step whose name any of them defines reads the
 *  runtime, not the tool's data, and is refused. */
const BUILTIN_PROTOS: readonly object[] = [Object.prototype, Array.prototype, String.prototype, Number.prototype, Boolean.prototype, Function.prototype];

function isOwnDataField(name: string): boolean {
  if (name.startsWith("__")) return false;
  return !BUILTIN_PROTOS.some((p) => name in p);
}

/** The array methods a listing step may call, each with one arrow function
 *  (`ALL_TOOLS.filter(t => …)`); plus `slice(i, j)` and `join("sep")`,
 *  read apart. All pure: they read the array and return a new value. */
const LISTING_ARROW_METHODS: ReadonlySet<string> = new Set(["filter", "find", "findIndex", "some", "every", "map"]);

/** A listing entry's fields (`{ name, description }`, as codex's `exec`
 *  description documents `ALL_TOOLS`) and an array's or string's length:
 *  data, though Function.prototype defines `name` and `length`. */
const LISTING_FIELDS: ReadonlySet<string> = new Set(["name", "description", "length"]);

/** The methods an arrow body may call, with how many arguments: pure
 *  String.prototype (and, on an array, Array.prototype) readers. A regular
 *  expression literal's `.test(…)` is read apart. */
const STRING_METHODS: ReadonlyMap<string, number> = new Map([
  ["toLowerCase", 0], ["toUpperCase", 0], ["trim", 0],
  ["includes", 1], ["startsWith", 1], ["endsWith", 1], ["indexOf", 1],
]);

const MCP_NAME_RE = /^mcp__[A-Za-z0-9_$]+?__[A-Za-z0-9_$]+$/;
const IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

/** A tool identifier the rule accepts: `mcp__<server>__<tool>`, both parts
 *  non-empty, as codex normalizes it. */
export function isMcpToolIdentifier(name: string): boolean {
  if (!IDENT_RE.test(name) || !MCP_NAME_RE.test(name)) return false;
  const rest = name.slice("mcp__".length);
  const sep = rest.indexOf("__");
  return sep > 0 && sep + 2 < rest.length;
}

class Parser {
  private i = 0;
  calls: Array<{ name: string; args: Record<string, unknown> }> = [];
  listings = 0;
  /** The cell's one `const`: a tool call's result, or a listing. */
  private bound: { name: string; kind: "call" | "listing" } | null = null;
  /** The parameter of the arrow function being read (never nested). */
  private param: string | null = null;

  constructor(private readonly toks: Tok[]) {}

  private peek(k = 0): Tok | undefined { return this.toks[this.i + k]; }
  private isP(v: string, k = 0): boolean { const t = this.peek(k); return !!t && t.t === "punct" && t.v === v; }
  private isI(v: string, k = 0): boolean { const t = this.peek(k); return !!t && t.t === "ident" && t.v === v; }
  private expectP(v: string): void { if (!this.isP(v)) refuse(`expected "${v}"`); this.i++; }
  private expectI(v: string): void { if (!this.isI(v)) refuse(`expected ${v}`); this.i++; }

  cell(): void {
    if (this.toks.length === 0) refuse("an empty cell");
    let first = true;
    while (this.i < this.toks.length) {
      if (this.isP(";")) { this.i++; continue; }
      // a statement needs a separator before it: `;` (consumed above, so the
      // previous token is one) or a line break (automatic semicolon insertion)
      if (!first && !this.toks[this.i]!.nl && !(this.toks[this.i - 1]?.t === "punct" && this.toks[this.i - 1]!.v === ";")) {
        refuse("two statements with no separator");
      }
      this.statement();
      first = false;
    }
  }

  private statement(): void {
    if (this.isI("const")) {
      this.i++;
      const t = this.peek();
      if (!t || t.t !== "ident" || UNBINDABLE.has(t.v)) refuse("a binding name the grammar does not take");
      if (this.bound !== null) refuse("a second binding");
      this.i++;
      this.expectP("=");
      // bound only after its initializer: the name is not visible inside it
      if (this.isI("ALL_TOOLS")) {
        this.listing();
        this.bound = { name: t!.v, kind: "listing" };
      } else {
        this.call();
        this.bound = { name: t!.v, kind: "call" };
      }
      return;
    }
    if (this.isI("await")) { this.call(); return; }
    if (this.isI("text")) {
      this.i++;
      this.expectP("(");
      this.expr(true);
      this.expectP(")");
      return;
    }
    refuse("a statement the grammar does not take");
  }

  private call(): void {
    this.expectI("await");
    this.expectI("tools");
    let name: string;
    let dotted = false;
    if (this.isP(".")) {
      this.i++;
      const t = this.peek();
      if (!t || t.t !== "ident") refuse("a tool name");
      name = t!.v;
      this.i++;
      dotted = true;
    } else if (this.isP("[")) {
      this.i++;
      const t = this.peek();
      if (!t || t.t !== "str") refuse("a computed tool name");
      name = t!.v;
      this.i++;
      this.expectP("]");
    } else {
      return refuse("tools used other than as tools.<name>");
    }
    // The shell only in the dotted spelling the exec gate's literal scanner
    // reads (script-cell.ts), so an exact cell's exec calls are the ones the
    // gate sees, one for one (§11.13, closed path (a)).
    const isExec = dotted && SHELL_TOOLS.has(name);
    if (!isExec && !isMcpToolIdentifier(name)) refuse("a tool that is neither an MCP tool nor tools.exec_command");
    this.expectP("(");
    if (!this.isP("{")) refuse("an argument that is not an object literal");
    const args = this.object(0);
    this.expectP(")");
    this.calls.push({ name, args });
  }

  /** text()'s or JSON.stringify()'s argument. */
  private expr(allowStringify: boolean): void {
    if (this.isI("await")) { this.call(); return; }
    if (this.isI("ALL_TOOLS")) { this.listing(); return; }
    if (allowStringify && this.isI("JSON")) {
      this.i++;
      this.expectP(".");
      this.expectI("stringify");
      this.expectP("(");
      this.expr(false);
      if (this.isP(",")) {
        this.i++;
        this.expectI("null");
        if (this.isP(",")) {
          this.i++;
          const t = this.peek();
          if (!t || t.t !== "num" || !/^(?:[0-9]|10)$/.test(t.v)) refuse("an indent other than 0..10");
          this.i++;
        }
      }
      this.expectP(")");
      return;
    }
    if (this.isP("(")) {
      // `(await tools.exec_command({…})).output`: the call, parenthesized,
      // then its own data's steps
      this.i++;
      this.call();
      this.expectP(")");
      this.steps();
      return;
    }
    const t = this.peek();
    if (!t || t.t !== "ident" || this.bound === null || t.v !== this.bound.name) refuse("a name the cell did not bind");
    this.i++;
    if (this.bound!.kind === "listing") this.listingSteps();
    else this.steps();
  }

  /**
   * `ALL_TOOLS` and its steps (plan 10 §11.13, "the filtered listing"). Every
   * value a listing computes comes from `ALL_TOOLS` (the battery's own
   * metadata) and the cell's literals: the steps are the pure built-in
   * array methods below, each arrow function reads only its parameter, and
   * nothing in it can call a tool, `load`, or any other global.
   */
  private listing(): void {
    this.expectI("ALL_TOOLS");
    this.listings++;
    this.listingSteps();
  }

  private listingSteps(): void {
    for (;;) {
      const m = this.isP(".") ? this.peek(1) : undefined;
      if (m?.t === "ident" && this.isP("(", 2)) {
        if (LISTING_ARROW_METHODS.has(m.v)) {
          this.i += 3;
          this.arrow();
          this.expectP(")");
          continue;
        }
        if (m.v === "slice") {
          this.i += 3;
          this.smallInt();
          if (this.isP(",")) { this.i++; this.smallInt(); }
          this.expectP(")");
          continue;
        }
        if (m.v === "join") {
          this.i += 3;
          if (!this.isP(")")) {
            const s = this.peek();
            if (!s || !(s.t === "str" || (s.t === "tmpl" && s.part === "full"))) refuse("a separator that is not a string literal");
            this.i++;
          }
          this.expectP(")");
          continue;
        }
        return refuse("a method the listing grammar does not take");
      }
      if (this.isP(".") || this.isP("?.")) { this.i++; this.listingField(); continue; }
      if (this.isP("[")) { this.index(); continue; }
      return;
    }
  }

  /** A data member of a listing entry: its own fields, `name`, `description`
   *  and `length` (which Function.prototype also defines, so the tool-result
   *  steps refuse them), never a built-in method or `__…`. */
  private listingField(): void {
    const f = this.peek();
    if (!f || f.t !== "ident" || !(LISTING_FIELDS.has(f.v) || isOwnDataField(f.v))) refuse("a member the grammar does not take");
    this.i++;
  }

  private smallInt(): void {
    const t = this.peek();
    if (!t || t.t !== "num" || !/^-?(?:0|[1-9][0-9]{0,5})$/.test(t.v)) refuse("an argument that is not a small integer");
    this.i++;
  }

  /** `x => body` or `(x) => body`: one parameter, an expression body. */
  private arrow(): void {
    let paren = false;
    if (this.isP("(")) { paren = true; this.i++; }
    const p = this.peek();
    if (!p || p.t !== "ident" || UNBINDABLE.has(p.v) || p.v === this.bound?.name) refuse("a parameter the grammar does not take");
    this.i++;
    if (paren) this.expectP(")");
    this.expectP("=>");
    if (this.isP("{")) refuse("an arrow function with a block body");
    this.param = p!.v;
    this.arrowValue(0);
    this.param = null;
  }

  // An arrow body: `||` `??` < `&&` < comparison < `!` < `+` < member steps
  // and the listed methods < a primary. No call but those methods, no name
  // but the parameter.
  private arrowValue(d: number): void {
    if (d > MAX_DEPTH) refuse("an expression nested too deep");
    this.vAnd(d);
    while (this.isP("||") || this.isP("??")) { this.i++; this.vAnd(d); }
  }

  private vAnd(d: number): void {
    this.vCmp(d);
    while (this.isP("&&")) { this.i++; this.vCmp(d); }
  }

  private vCmp(d: number): void {
    this.vNot(d);
    if (this.isP("===") || this.isP("!==") || this.isP("==") || this.isP("!=")) { this.i++; this.vNot(d); }
  }

  private vNot(d: number): void {
    if (this.isP("!")) { this.i++; this.vNot(d + 1); return; }
    this.vAdd(d);
  }

  private vAdd(d: number): void {
    this.vPost(d);
    while (this.isP("+")) { this.i++; this.vPost(d); }
  }

  private vPost(d: number): void {
    const regex = this.peek()?.t === "regex";
    this.vPrimary(d);
    if (regex) {
      // a regular expression is only ever tested against a value
      this.expectP(".");
      this.expectI("test");
      this.expectP("(");
      this.arrowValue(d + 1);
      this.expectP(")");
      return;
    }
    for (;;) {
      const m = this.isP(".") ? this.peek(1) : undefined;
      if (m?.t === "ident" && this.isP("(", 2)) {
        const arity = STRING_METHODS.get(m.v);
        if (arity === undefined) refuse("a method the listing grammar does not take");
        this.i += 3;
        for (let k = 0; k < arity!; k++) {
          if (k > 0) this.expectP(",");
          this.arrowValue(d + 1);
        }
        this.expectP(")");
        continue;
      }
      if (this.isP(".") || this.isP("?.")) { this.i++; this.listingField(); continue; }
      if (this.isP("[")) { this.index(); continue; }
      return;
    }
  }

  private vPrimary(d: number): void {
    const t = this.peek();
    if (!t) return refuse("a missing value");
    if (t.t === "str" || t.t === "num" || t.t === "regex") { this.i++; return; }
    if (t.t === "tmpl") {
      this.i++;
      if (t.part === "full") return;
      if (t.part !== "head") refuse("a template piece out of place");
      for (;;) {
        this.arrowValue(d + 1);
        const n = this.peek();
        if (!n || n.t !== "tmpl" || (n.part !== "middle" && n.part !== "tail")) return refuse("an unterminated template");
        this.i++;
        if (n.part === "tail") return;
      }
    }
    if (t.t === "ident") {
      if (t.v === "true" || t.v === "false" || t.v === "null" || (this.param !== null && t.v === this.param)) { this.i++; return; }
      return refuse("a name the arrow function does not bind");
    }
    if (this.isP("(")) { this.i++; this.arrowValue(d + 1); this.expectP(")"); return; }
    if (this.isP("{")) {
      // `({ name: t.name, … })`: plain keys, never computed, shorthand or
      // `__proto__`
      this.i++;
      const seen = new Set<string>();
      while (!this.isP("}")) {
        const k = this.peek();
        if (!k || (k.t !== "ident" && k.t !== "str") || k.v === "__proto__" || seen.has(k.v)) refuse("a key the grammar does not take");
        seen.add(k!.v);
        this.i++;
        this.expectP(":");
        this.arrowValue(d + 1);
        if (this.isP(",")) { this.i++; continue; }
        if (!this.isP("}")) refuse("expected , or }");
      }
      this.i++;
      return;
    }
    if (this.isP("[")) {
      this.i++;
      while (!this.isP("]")) {
        if (this.isP(",")) refuse("an array hole");
        this.arrowValue(d + 1);
        if (this.isP(",")) { this.i++; continue; }
        if (!this.isP("]")) refuse("expected , or ]");
      }
      this.i++;
      return;
    }
    return refuse("a value the grammar does not take");
  }

  /** Member steps over a tool's result: own-data names and small indices. */
  private steps(): void {
    for (;;) {
      if (this.isP(".") || this.isP("?.")) {
        const optional = this.isP("?.");
        this.i++;
        if (optional && this.isP("[")) { this.index(); continue; }
        const f = this.peek();
        if (!f || f.t !== "ident" || !isOwnDataField(f.v)) refuse("a member the grammar does not take");
        this.i++;
        continue;
      }
      if (this.isP("[")) { this.index(); continue; }
      return;
    }
  }

  private index(): void {
    this.expectP("[");
    const t = this.peek();
    if (!t || t.t !== "num" || !/^(?:0|[1-9][0-9]{0,5})$/.test(t.v)) refuse("an index that is not a small integer");
    this.i++;
    this.expectP("]");
  }

  private object(depth: number): Record<string, unknown> {
    if (depth > MAX_DEPTH) refuse("a literal nested too deep");
    this.expectP("{");
    const out: Record<string, unknown> = {};
    const seen = new Set<string>();
    while (!this.isP("}")) {
      const k = this.peek();
      if (!k || (k.t !== "ident" && k.t !== "str")) refuse("a key that is not a name or a string");
      if (k!.v === "__proto__" || seen.has(k!.v)) refuse("a __proto__ or repeated key");
      this.i++;
      this.expectP(":");
      seen.add(k!.v);
      out[k!.v] = this.value(depth + 1);
      if (this.isP(",")) { this.i++; continue; }
      if (!this.isP("}")) refuse("expected , or }");
    }
    this.i++;
    return out;
  }

  private array(depth: number): unknown[] {
    if (depth > MAX_DEPTH) refuse("a literal nested too deep");
    this.expectP("[");
    const out: unknown[] = [];
    while (!this.isP("]")) {
      if (this.isP(",")) refuse("an array hole");
      out.push(this.value(depth + 1));
      if (this.isP(",")) { this.i++; continue; }
      if (!this.isP("]")) refuse("expected , or ]");
    }
    this.i++;
    return out;
  }

  private value(depth: number): unknown {
    const t = this.peek();
    if (!t) return refuse("a missing value");
    if (t.t === "str") { this.i++; return t.v; }
    if (t.t === "num") { this.i++; return Number(t.v); }
    if (t.t === "ident") {
      if (t.v === "true") { this.i++; return true; }
      if (t.v === "false") { this.i++; return false; }
      if (t.v === "null") { this.i++; return null; }
      return refuse("a name as a value");
    }
    if (this.isP("{")) return this.object(depth);
    if (this.isP("[")) return this.array(depth);
    return refuse("a value the grammar does not take");
  }
}

/**
 * Parse a cell under the allow-list grammar. The verdict: an MCP cell (the
 * tool and its parsed arguments), a listing cell, or a refusal with the
 * reason (for tests and the proxy log; never shown to the model).
 */
export function parseMcpCell(src: unknown): { cell: McpCell } | { refused: string } {
  const r = parseCell(src);
  if ("refused" in r) return r;
  const { calls, listings } = r;
  if (calls.some((c) => SHELL_TOOLS.has(c.name))) return { refused: "a shell call" };
  if (calls.length === 1 && listings === 0) return { cell: { kind: "mcp", name: calls[0]!.name, args: calls[0]!.args } };
  if (calls.length === 0 && listings > 0) return { cell: { kind: "listing" } };
  if (calls.length > 1) return { refused: "more than one tool call" };
  if (calls.length === 1) return { refused: "a tool call and a tool listing" };
  return { refused: "no tool call" };
}

/** A whole cell under the grammar: every tool call it makes (in order) and
 *  how many times it reads `ALL_TOOLS`, or a refusal. Every call is
 *  IDENTIFIED: an MCP tool or `tools.exec_command`, each with its literal
 *  object; nothing else in the cell can run anything (plan 10 §11.13). */
export function parseCell(src: unknown): { calls: Array<{ name: string; args: Record<string, unknown> }>; listings: number } | { refused: string } {
  if (typeof src !== "string") return { refused: "not a string" };
  try {
    const p = new Parser(tokenize(src));
    p.cell();
    return { calls: p.calls, listings: p.listings };
  } catch (err) {
    if (err instanceof Refuse) return { refused: err.message };
    return { refused: "parser error" };
  }
}

/** The arguments of the ONE `tools.exec_command` call of a cell that makes no
 *  other call and reads no listing, under the grammar; null otherwise (the
 *  cell's exec calls are then not identified exactly, §11.13 path (a)). */
export function exactExecCall(src: unknown): Record<string, unknown> | null {
  const r = parseCell(src);
  if ("refused" in r || r.listings !== 0 || r.calls.length !== 1 || !SHELL_TOOLS.has(r.calls[0]!.name)) return null;
  return r.calls[0]!.args;
}

/** Does the grammar identify every call of the cell (any number of MCP and
 *  `tools.exec_command` calls, each with its literal)? The response-side gate
 *  gates such a cell literal by literal; any other cell as a whole. */
export function cellCallsIdentified(src: unknown): boolean {
  return !("refused" in parseCell(src));
}

/** The qualifying cell, or null (keep the fail-closed handling). */
export function qualifyMcpCell(src: unknown): McpCell | null {
  const r = parseMcpCell(src);
  return "cell" in r ? r.cell : null;
}
