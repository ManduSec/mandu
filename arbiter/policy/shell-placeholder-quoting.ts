/**
 * shell-placeholder-quoting — keep a secret placeholder whole through the
 * agent's shell (Mandu-new, no reference origin; the design is
 * confidentiality.md §7, "A placeholder the agent's shell would expand").
 *
 * A secret reaches the model as a placeholder such as
 * `$MDU:nomodel_Read[de31].STRIPE_KEY`, and the model routes it by writing it
 * where the value belongs: `curl -H "Authorization: Bearer $MDU:…" https://…`.
 * In double quotes, unquoted, or in a here-document whose delimiter is not
 * quoted, every shell reads `$MDU` as a variable: it expands to nothing and
 * the program gets `:nomodel_Read[de31].STRIPE_KEY`, which no egress gate
 * recognizes. The request then goes out with neither the value nor the
 * placeholder: no leak, but no substitution at a bound host and no approval
 * at an unbound one either, and the model reads a 401 with no hint why
 * (found on the first-session tour, 2026-10-11). zsh does worse: it reads
 * `$MDU:a…` and `$MDU:l…` as history modifiers on `$MDU` (`:a` absolute
 * path, `:l` lower case), and an unquoted `[de31]` as a glob that fails the
 * whole command ("no matches found").
 *
 * {@link requoteShellPlaceholders} rewrites the command so each such
 * placeholder reaches the program as written, in the form every POSIX shell,
 * zsh and fish read literally:
 *
 *   - unquoted                        → `'$MDU:…'` (also no glob);
 *   - inside `"…"` or `$"…"`          → `\$MDU:…`;
 *   - in an expanding here-document    → `\$MDU:…`;
 *   - inside `'…'`, `$'…'`, a quoted here-document, or already escaped
 *     (`\$MDU:…`)                     → unchanged.
 *
 * WHAT IT CANNOT LEAK. The only bytes it inserts are `'` and `\` next to a
 * placeholder the model itself wrote; it never resolves a placeholder and
 * reads no table. The command it returns carries the same placeholder the
 * model wrote, which is exactly what the model gets by single-quoting it
 * itself: the value is released only by the egress gates, at a host the
 * placeholder is bound to or with the human's OK. A placeholder the shell
 * would have expanded to nothing now reaches those gates instead of
 * vanishing, which is the point.
 *
 * WHAT IT TOUCHES. Only secret-labelled placeholders (a level marker after
 * the prefix: `nomodel_`, `localmodel_`, `anymodel_`); an unlabelled
 * untrusted-data symbol is left to the frozen integrity exec path. The
 * parse is deliberately small: a command it cannot read with confidence (a
 * backquote, an unclosed quote or substitution, a `)` it cannot place, a
 * here-document cut short) is left unchanged, which is the behavior before
 * this module. A misread can only misplace the inserted `'` or `\` next to
 * the placeholder, never move or resolve it.
 *
 * Pure; never throws.
 */

import { getActiveFormat, levelFromSymbolName } from "../symbol-table/index.js";

/** One requoted placeholder: where it was, how it was written. */
export interface RequotedPlaceholder {
  /** The placeholder text, as the model wrote it. */
  symbol: string;
  /** The context the shell would have read it in. */
  context: "unquoted" | "double-quoted" | "here-document";
}

export interface ShellPlaceholderRequote {
  /** The command with every listed placeholder requoted. */
  command: string;
  requoted: RequotedPlaceholder[];
}

/** A `$(…)` body or the command itself (`closer: null`), or a `"…"` string. */
type Frame = { kind: "code"; closer: ")" | null; parens: number } | { kind: "dq" };

interface PendingHeredoc {
  delimiter: string;
  stripTabs: boolean;
  expands: boolean;
}

interface Edit {
  start: number;
  end: number;
  text: string;
}

/** Thrown inside the scan when the command is past what it reads safely. */
class Unreadable extends Error {}

/** Characters that end an unquoted word (a here-document delimiter too). */
const WORD_BREAK = new Set([" ", "\t", "\n", ";", "&", "|", "(", ")", "<", ">"]);
/** `$` followed by one of these is a special parameter (`$$`, `$?`, `$1`, …). */
const SPECIAL_PARAM = /[$!#?\-@*0-9]/;

/** A secret-labelled placeholder starting exactly at `i`, or null. */
function placeholderAt(command: string, i: number): string | null {
  const fmt = getActiveFormat();
  if (!command.startsWith(fmt.prefix, i)) return null;
  const sticky = new RegExp(fmt.pattern.source, "y");
  sticky.lastIndex = i;
  const m = sticky.exec(command);
  if (!m || m.index !== i) return null;
  return levelFromSymbolName(m[0]) === "public" ? null : m[0];
}

/** Index just past the `}` closing a `${` that starts at `i` (`$` at i). */
function skipBraced(command: string, i: number): number {
  let depth = 0;
  for (let j = i + 1; j < command.length; j++) {
    const c = command[j]!;
    if (c === "\\") { j++; continue; }
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return j + 1;
    }
  }
  throw new Unreadable("unclosed ${");
}

/** Index just past the `'` closing a `$'…'` whose `'` is at `i`. */
function skipAnsiC(command: string, i: number): number {
  for (let j = i + 1; j < command.length; j++) {
    const c = command[j]!;
    if (c === "\\") { j++; continue; }
    if (c === "'") return j + 1;
  }
  throw new Unreadable("unclosed $'");
}

/**
 * Read a here-document operator's delimiter word starting at `i` (after
 * `<<` / `<<-` and any blanks). Returns the delimiter as the shell compares
 * it (quotes removed) and whether any part of it was quoted.
 */
function readDelimiter(command: string, i: number): { delimiter: string; quoted: boolean; end: number } {
  let delimiter = "";
  let quoted = false;
  let j = i;
  while (j < command.length && !WORD_BREAK.has(command[j]!)) {
    const c = command[j]!;
    if (c === "'" || c === "\"") {
      const close = command.indexOf(c, j + 1);
      if (close < 0) throw new Unreadable("unclosed quote in a here-document delimiter");
      delimiter += command.slice(j + 1, close);
      quoted = true;
      j = close + 1;
      continue;
    }
    if (c === "\\" && j + 1 < command.length) {
      delimiter += command[j + 1];
      quoted = true;
      j += 2;
      continue;
    }
    if (c === "$" || c === "`") throw new Unreadable("an expansion in a here-document delimiter");
    delimiter += c;
    j++;
  }
  if (delimiter === "") throw new Unreadable("a here-document with no delimiter");
  return { delimiter, quoted, end: j };
}

/**
 * Read the bodies of the pending here-documents, which start at `i` (just
 * past the newline that ends their operator's line). Requotes placeholders
 * in an expanding body. Returns the index after the last body.
 */
function readHeredocBodies(
  command: string,
  i: number,
  pending: PendingHeredoc[],
  edits: Edit[],
  requoted: RequotedPlaceholder[],
): number {
  let pos = i;
  for (const h of pending) {
    for (;;) {
      if (pos >= command.length) return command.length; // the shell ends a cut-short body at the end of input
      const nl = command.indexOf("\n", pos);
      const lineEnd = nl < 0 ? command.length : nl;
      const line = command.slice(pos, lineEnd);
      const compared = h.stripTabs ? line.replace(/^\t+/, "") : line;
      if (compared === h.delimiter) {
        pos = nl < 0 ? command.length : nl + 1;
        break;
      }
      if (h.expands) {
        for (let j = pos; j < lineEnd; j++) {
          const c = command[j]!;
          if (c === "\\") { j++; continue; }
          if (c !== "$") continue;
          const sym = placeholderAt(command, j);
          if (sym === null) continue;
          edits.push({ start: j, end: j + 1, text: "\\$" });
          requoted.push({ symbol: sym, context: "here-document" });
          j += sym.length - 1;
        }
      }
      pos = nl < 0 ? command.length : nl + 1;
    }
  }
  return pos;
}

function scan(command: string): ShellPlaceholderRequote {
  const edits: Edit[] = [];
  const requoted: RequotedPlaceholder[] = [];
  const stack: Frame[] = [{ kind: "code", closer: null, parens: 0 }];
  let pending: PendingHeredoc[] = [];
  let wordStart = true;
  let i = 0;
  while (i < command.length) {
    const frame = stack[stack.length - 1]!;
    const c = command[i]!;
    const next = command[i + 1];

    if (frame.kind === "dq") {
      if (c === "\"") { stack.pop(); i++; continue; }
      if (c === "\\") { i += 2; continue; }
      if (c === "`") throw new Unreadable("a backquote");
      if (c === "\n" && pending.length > 0) throw new Unreadable("a here-document body inside a quoted string");
      if (c === "$") {
        if (next === "(") { stack.push({ kind: "code", closer: ")", parens: 0 }); i += 2; wordStart = true; continue; }
        if (next === "{") { i = skipBraced(command, i); continue; }
        if (next !== undefined && SPECIAL_PARAM.test(next)) { i += 2; continue; }
        const sym = placeholderAt(command, i);
        if (sym !== null) {
          edits.push({ start: i, end: i + 1, text: "\\$" });
          requoted.push({ symbol: sym, context: "double-quoted" });
          i += sym.length;
          continue;
        }
      }
      i++;
      continue;
    }

    // Code: the command itself or a `$(…)` body.
    if (c === "\n") {
      i++;
      wordStart = true;
      if (pending.length > 0) {
        i = readHeredocBodies(command, i, pending, edits, requoted);
        pending = [];
      }
      continue;
    }
    if (WORD_BREAK.has(c) && c !== "(" && c !== ")" && c !== "<") { i++; wordStart = true; continue; }
    if (c === "#" && wordStart) {
      const nl = command.indexOf("\n", i);
      i = nl < 0 ? command.length : nl;
      continue;
    }
    if (c === "\\") { i += 2; wordStart = false; continue; }
    if (c === "'") {
      const close = command.indexOf("'", i + 1);
      if (close < 0) throw new Unreadable("an unclosed single quote");
      i = close + 1;
      wordStart = false;
      continue;
    }
    if (c === "\"") { stack.push({ kind: "dq" }); i++; wordStart = false; continue; }
    if (c === "`") throw new Unreadable("a backquote");
    if (c === "(") { frame.parens++; i++; wordStart = true; continue; }
    if (c === ")") {
      if (frame.parens > 0) frame.parens--;
      else if (frame.closer === ")") stack.pop();
      else throw new Unreadable("a ) with nothing open");
      i++;
      wordStart = true;
      continue;
    }
    if (c === "<") {
      if (next === "<" && command[i + 2] === "<") { i += 3; wordStart = true; continue; } // here-string: a plain word follows
      if (next === "<") {
        let j = i + 2;
        const stripTabs = command[j] === "-";
        if (stripTabs) j++;
        while (command[j] === " " || command[j] === "\t") j++;
        const d = readDelimiter(command, j);
        pending.push({ delimiter: d.delimiter, stripTabs, expands: !d.quoted });
        i = d.end;
        wordStart = true;
        continue;
      }
      i++;
      wordStart = true;
      continue;
    }
    if (c === "$") {
      wordStart = false;
      if (next === "'") { i = skipAnsiC(command, i + 1); continue; }
      if (next === "\"") { stack.push({ kind: "dq" }); i += 2; continue; }
      if (next === "(") { stack.push({ kind: "code", closer: ")", parens: 0 }); i += 2; wordStart = true; continue; }
      if (next === "{") { i = skipBraced(command, i); continue; }
      if (next !== undefined && SPECIAL_PARAM.test(next)) { i += 2; continue; }
      const sym = placeholderAt(command, i);
      if (sym !== null) {
        edits.push({ start: i, end: i + sym.length, text: `'${sym}'` });
        requoted.push({ symbol: sym, context: "unquoted" });
        i += sym.length;
        continue;
      }
      i++;
      continue;
    }
    wordStart = false;
    i++;
  }
  if (stack.length !== 1) throw new Unreadable("an unclosed quote or substitution");
  let out = "";
  let cursor = 0;
  for (const e of edits) {
    out += command.slice(cursor, e.start) + e.text;
    cursor = e.end;
  }
  out += command.slice(cursor);
  return { command: out, requoted };
}

/**
 * The command with every secret placeholder the shell would expand requoted
 * so the program receives it as written (see the module header), or null
 * when there is nothing to requote or the command is past what the parse
 * reads with confidence (it then runs as the model wrote it).
 */
export function requoteShellPlaceholders(command: string): ShellPlaceholderRequote | null {
  if (typeof command !== "string" || !command.includes(getActiveFormat().prefix)) return null;
  try {
    const r = scan(command);
    return r.requoted.length > 0 ? r : null;
  } catch {
    // Unreadable (or anything unforeseen): the command runs as written.
    return null;
  }
}
