/**
 * services/json5 — a JSON5 reader for the agents' own config files.
 *
 * WHY: OpenClaw reads `openclaw.json` as JSON5 (comments, trailing commas,
 * unquoted keys, single-quoted strings), and its docs write every example
 * that way. The launcher read it with JSON.parse, so a hand-edited config
 * was "unreadable": the model check refused the launch (agent-model-route.ts)
 * and the routing merge dropped the user's settings. OpenCode's JSONC
 * (comments, trailing commas) is a subset, so the same reader serves it.
 *
 * Why not the `json5` package: the launcher ships with no runtime
 * dependencies (package.json), and this reader only feeds a decision that
 * fails closed (a file it cannot parse is still refused). It implements the
 * JSON5 grammar (https://spec.json5.org): `//` and `/* *\/` comments,
 * trailing commas, ECMAScript identifier keys, single-quoted strings, line
 * continuations and the extra escapes (`\x`, `\v`, `\0`, `\u`), hex numbers,
 * leading/trailing decimal points, an explicit `+`, Infinity and NaN.
 * Identifier keys are limited to ASCII letters, digits, `_` and `$` plus
 * `\u` escapes; a config key outside that set is refused, never guessed at.
 * A `__proto__` key is kept as an own property (JSON.parse behaviour).
 */

export class Json5Error extends Error {
  constructor(message: string, readonly line: number, readonly column: number) {
    super(`${message} at line ${line} column ${column}`);
  }
}

const WS = new Set([" ", "\t", "\n", "\r", "\v", "\f", " ", "﻿", " ", " "]);
const ID_START = /[A-Za-z_$]/;
const ID_PART = /[A-Za-z0-9_$]/;

/** Parse a JSON5 document. Throws Json5Error on anything the grammar rejects. */
export function parseJson5(text: string): unknown {
  let i = 0;

  const fail = (msg: string, at = i): never => {
    let line = 1, col = 1;
    for (let k = 0; k < at && k < text.length; k++) {
      if (text[k] === "\n") { line++; col = 1; } else col++;
    }
    throw new Json5Error(msg, line, col);
  };

  const skip = (): void => {
    for (;;) {
      const c = text[i];
      if (c !== undefined && WS.has(c)) { i++; continue; }
      if (c === "/" && text[i + 1] === "/") {
        i += 2;
        while (i < text.length && text[i] !== "\n" && text[i] !== "\r" && text[i] !== " " && text[i] !== " ") i++;
        continue;
      }
      if (c === "/" && text[i + 1] === "*") {
        const end = text.indexOf("*/", i + 2);
        if (end < 0) fail("unterminated comment");
        i = end + 2;
        continue;
      }
      return;
    }
  };

  const hex = (n: number): number => {
    const s = text.slice(i, i + n);
    if (s.length !== n || !/^[0-9A-Fa-f]+$/.test(s)) fail("bad hex escape");
    i += n;
    return parseInt(s, 16);
  };

  const escape = (): string => {
    const c = text[i++];
    switch (c) {
      case "b": return "\b";
      case "f": return "\f";
      case "n": return "\n";
      case "r": return "\r";
      case "t": return "\t";
      case "v": return "\v";
      case "0":
        if (/[0-9]/.test(text[i] ?? "")) fail("octal escape");
        return "\0";
      case "x": return String.fromCharCode(hex(2));
      case "u": return String.fromCharCode(hex(4));
      case "\r": if (text[i] === "\n") i++; return "";
      case "\n": case " ": case " ": return "";
      case undefined: return fail("unterminated string");
      default:
        if (/[1-9]/.test(c)) fail("octal escape", i - 1);
        return c;
    }
  };

  const string = (): string => {
    const quote = text[i++];
    let out = "";
    for (;;) {
      const c = text[i];
      if (c === undefined) fail("unterminated string");
      if (c === quote) { i++; return out; }
      if (c === "\n" || c === "\r") fail("newline in string");
      if (c === "\\") { i++; out += escape(); continue; }
      out += c;
      i++;
    }
  };

  const identifier = (): string => {
    let out = "";
    const part = (first: boolean): boolean => {
      const c = text[i];
      if (c === "\\") {
        if (text[i + 1] !== "u") fail("bad identifier escape");
        i += 2;
        const ch = String.fromCharCode(hex(4));
        if (!(first ? ID_START : ID_PART).test(ch)) fail("bad identifier escape", i - 6);
        out += ch;
        return true;
      }
      if (c !== undefined && (first ? ID_START : ID_PART).test(c)) { out += c; i++; return true; }
      return false;
    };
    if (!part(true)) fail(`unexpected ${JSON.stringify(text[i] ?? "end of input")}`);
    while (part(false)) { /* consume */ }
    return out;
  };

  const number = (): number => {
    const start = i;
    let sign = 1;
    if (text[i] === "+" || text[i] === "-") { if (text[i] === "-") sign = -1; i++; }
    if (text.startsWith("Infinity", i)) { i += 8; return sign * Infinity; }
    if (text.startsWith("NaN", i)) { i += 3; return NaN; }
    if (text[i] === "0" && (text[i + 1] === "x" || text[i + 1] === "X")) {
      i += 2;
      const m = /^[0-9A-Fa-f]+/.exec(text.slice(i));
      if (!m) fail("bad hex number");
      i += m![0].length;
      return sign * parseInt(m![0], 16);
    }
    const m = /^(?:(?:0|[1-9][0-9]*)(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?/.exec(text.slice(i));
    if (!m) fail("bad number", start);
    i += m![0].length;
    if (ID_PART.test(text[i] ?? "")) fail("bad number", start);
    return sign * Number(m![0]);
  };

  const value = (depth: number): unknown => {
    if (depth > 512) fail("nesting too deep");
    skip();
    const c = text[i];
    if (c === "{") {
      i++;
      const obj: Record<string, unknown> = {};
      skip();
      if (text[i] === "}") { i++; return obj; }
      for (;;) {
        skip();
        const k = text[i] === '"' || text[i] === "'" ? string() : identifier();
        skip();
        if (text[i] !== ":") fail("expected ':'");
        i++;
        Object.defineProperty(obj, k, { value: value(depth + 1), enumerable: true, writable: true, configurable: true });
        skip();
        if (text[i] === ",") { i++; skip(); if (text[i] === "}") { i++; return obj; } continue; }
        if (text[i] === "}") { i++; return obj; }
        fail("expected ',' or '}'");
      }
    }
    if (c === "[") {
      i++;
      const arr: unknown[] = [];
      skip();
      if (text[i] === "]") { i++; return arr; }
      for (;;) {
        arr.push(value(depth + 1));
        skip();
        if (text[i] === ",") { i++; skip(); if (text[i] === "]") { i++; return arr; } continue; }
        if (text[i] === "]") { i++; return arr; }
        fail("expected ',' or ']'");
      }
    }
    if (c === '"' || c === "'") return string();
    if (c !== undefined && /[0-9+\-.]/.test(c)) return number();
    for (const [word, v] of [["true", true], ["false", false], ["null", null]] as const) {
      if (text.startsWith(word, i) && !ID_PART.test(text[i + word.length] ?? "")) { i += word.length; return v; }
    }
    if (text.startsWith("Infinity", i) || text.startsWith("NaN", i)) return number();
    return fail(c === undefined ? "unexpected end of input" : `unexpected ${JSON.stringify(c)}`);
  };

  const out = value(0);
  skip();
  if (i < text.length) fail("unexpected text after the document");
  return out;
}
