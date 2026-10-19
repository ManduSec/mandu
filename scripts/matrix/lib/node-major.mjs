#!/usr/bin/env node
// node-major — which Node major a fresh-agents guest installs
// (docs/design/testing/os-test-matrix.md §10.14, "Versions").
//
// The README's Node 22, unless the chosen OpenClaw's own `engines.node` rules
// it out; then the lowest of 24, 26 whose current release (nodejs.org's
// dist/index.json) satisfies that range.
//
//   node-major.mjs <engines range, may be empty> <path to dist/index.json>
//
// Prints the major on stdout and exits 0, always: an unreadable index or a
// range this parser does not know falls back to 22 with one line on stderr.
// Self-contained on purpose. It once loaded npm's own `semver` from `npm root
// -g`, which is not where Debian's and Ubuntu's npm keep it
// (/usr/share/nodejs), so on such a host it silently picked 22 for an
// OpenClaw that needs 24 (2026-10-08).
import { readFileSync } from "node:fs";

export const DEFAULT_MAJOR = "22";
export const CANDIDATES = ["22", "24", "26"];

const cmp = (a, b) => (a[0] - b[0]) || (a[1] - b[1]) || (a[2] - b[2]);

/** "24.16.0" / "v24.16.0" → [24, 16, 0]; null for anything else (a
 *  prerelease, a build tag): Node's release index has neither. */
export function parseVersion(v) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(String(v).trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

// A partial version ("24", "24.16", "24.x", "*"): the numbers given, and how
// many there are (x, X and * count as absent).
function partial(s) {
  const m = /^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?$/.exec(s);
  if (!m) throw new Error(`unparseable version '${s}'`);
  const parts = [];
  for (const p of m.slice(1)) {
    if (p === undefined || /^[xX*]$/.test(p)) break;
    parts.push(Number(p));
  }
  return parts;
}
const pad = (p) => [p[0] ?? 0, p[1] ?? 0, p[2] ?? 0];
// The first version above every one a partial names: 24 → 25.0.0, 24.16 → 24.17.0.
const bumpAt = (p, i) => (i < 0 ? null : pad([...p.slice(0, i), p[i] + 1]));

/** One comparator set (space-separated, ANDed) → [[op, version], …]. */
function comparators(set) {
  const out = [];
  const hy = /^(\S+)\s+-\s+(\S+)$/.exec(set);
  if (hy) {
    const lo = partial(hy[1]), hi = partial(hy[2]);
    out.push([">=", pad(lo)]);
    if (hi.length === 3) out.push(["<=", hi]);
    else if (hi.length > 0) out.push(["<", bumpAt(hi, hi.length - 1)]);
    return out;
  }
  // npm allows a space between an operator and its version (">= 24").
  for (const tok of set.replace(/(>=|<=|>|<|=|\^|~)\s+/g, "$1").split(/\s+/).filter(Boolean)) {
    const m = /^(>=|<=|>|<|=|\^|~)?(.+)$/.exec(tok);
    const op = m[1] ?? "", p = partial(m[2]);
    if (p.length === 0) { if (op === "<" || op === ">") out.push(["<", [0, 0, 0]]); continue; }
    if (op === "^") {
      const i = p.findIndex((n) => n !== 0);
      out.push([">=", pad(p)]);
      out.push(["<", bumpAt(p, i < 0 ? p.length - 1 : i)]);
    } else if (op === "~") {
      out.push([">=", pad(p)]);
      out.push(["<", bumpAt(p, p.length >= 2 ? 1 : 0)]);
    } else if (op === "" || op === "=") {
      out.push([">=", pad(p)]);
      if (p.length === 3) out.push(["<=", p]); else out.push(["<", bumpAt(p, p.length - 1)]);
    } else if (op === ">") {
      out.push(p.length === 3 ? [">", p] : [">=", bumpAt(p, p.length - 1)]);
    } else if (op === "<=") {
      out.push(p.length === 3 ? ["<=", p] : ["<", bumpAt(p, p.length - 1)]);
    } else {
      out.push([op, pad(p)]); // >= and < on a partial: its zero-padded form
    }
  }
  return out;
}

/** Whether `version` satisfies an npm-style `range`: `||` alternatives of
 *  space-separated comparators (`>=`, `>`, `<=`, `<`, `=`), caret, tilde,
 *  x-ranges and hyphen ranges. Throws on syntax it does not know. */
export function satisfies(version, range) {
  const v = parseVersion(version);
  if (!v) throw new Error(`unparseable version '${version}'`);
  const test = (op, w) => {
    const c = cmp(v, w);
    return op === ">=" ? c >= 0 : op === ">" ? c > 0 : op === "<=" ? c <= 0 : op === "<" ? c < 0 : c === 0;
  };
  return String(range).split("||").map((s) => s.trim()).some((set) => comparators(set).every(([op, w]) => test(op, w)));
}

/** The major to install for an OpenClaw `engines.node` range, given the
 *  release index (newest first, as nodejs.org lists it). */
export function pickNodeMajor(range, releases) {
  if (!range || !String(range).trim()) return DEFAULT_MAJOR;
  const latest = (m) => (releases.find((r) => typeof r?.version === "string" && r.version.startsWith(`v${m}.`)) || {}).version;
  return CANDIDATES.find((m) => latest(m) && satisfies(latest(m), range)) ?? DEFAULT_MAJOR;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [range = "", index] = process.argv.slice(2);
  let pick = DEFAULT_MAJOR;
  try {
    if (range.trim()) pick = pickNodeMajor(range, JSON.parse(readFileSync(index, "utf8")));
  } catch (e) {
    console.error(`fresh-agents: node major defaults to ${DEFAULT_MAJOR} (${e.message})`);
  }
  console.log(pick);
}
