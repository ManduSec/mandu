/**
 * write-back — what OpenClaw's file tools may write to a protected file
 * through Mandu's fs bridge (docs/design/agents/openclaw-plugin.md §10.4).
 * PURE. Mandu-new (no reference origin).
 *
 * Inside the box a protected file reads as its placeholder copy (the twin,
 * `T`); the real file (`R`) holds the values. OpenClaw's `edit` reads the
 * file, patches the text and writes the whole file back (`W`), so `W` is the
 * twin's text with the model's change: writing it as is would put
 * placeholders over the user's real values, and writing it into the twin
 * alone (what a command's write does) would lose the change. The bridge
 * writes the real file instead, with each of the file's own values put back
 * byte for byte, under one rule:
 *
 *   A line of `W` that carries one of the file's OWN placeholders must be,
 *   byte for byte, a line of the twin; it is written as that line of the real
 *   file. Every other line of `W` is written as the model wrote it.
 *
 * So a value goes back only to the line it came from: the model can keep,
 * drop, duplicate or move a whole line holding a value, and change every
 * other line, but it cannot carry a value into a line of its own making (a
 * URL, a command, another key), where a program the person runs later would
 * read it (a confused deputy: the model cannot read the value, but it could
 * still place it). A placeholder of ANOTHER file stays the placeholder text
 * (nothing of another file is put back). The value never leaves its file.
 *
 * Refused (the real file and its twin left as they were, the tool told why):
 *   - a line with an own placeholder that is not a twin line (an edit inside
 *     a protected value's line, or a value moved into a new line);
 *   - a twin line that stands for different real lines (ambiguous);
 *   - a twin whose lines do not match the real file's one for one (a
 *     whole-file placeholder, a value over several lines), unless the write
 *     changes nothing or carries none of the file's placeholders;
 *   - a twin with no placeholder at all that differs from the real file
 *     (Mandu cannot tell what it stands for);
 *   - more than WRITE_BACK_MAX bytes.
 */

import { PLACEHOLDER_RE } from "../reply-policy.js";

/** The largest real file, twin or write the bridge writes back (plan 16 §3.6's bound). */
export const WRITE_BACK_MAX = 8 * 1024 * 1024;

export type WriteBackPlan =
  /** The file is not protected (the box reads the real bytes): write `W` in the box. */
  | { kind: "plain" }
  /** `W` is the twin itself: nothing changes. */
  | { kind: "unchanged" }
  /** Write `bytes` to the real file, and `W` to the twin. */
  | { kind: "restore"; bytes: Buffer; restoredLines: number }
  | { kind: "refuse"; reason: string };

/** The file's own placeholders: every one its twin carries. */
export function ownPlaceholders(twin: string): Set<string> {
  const out = new Set<string>();
  for (const m of twin.matchAll(PLACEHOLDER_RE)) out.add(m[0].replace(/\.+$/, ""));
  return out;
}

function hasOwn(line: string, own: ReadonlySet<string>): boolean {
  for (const m of line.matchAll(PLACEHOLDER_RE)) if (own.has(m[0].replace(/\.+$/, ""))) return true;
  return false;
}

/**
 * Decide a bridge write of `written` to a file whose box view is `twin` and
 * whose real bytes are `real`. Text is read as UTF-8 for the placeholders;
 * the real lines are copied as bytes.
 */
export function planWriteBack(twin: Buffer, real: Buffer, written: Buffer): WriteBackPlan {
  if (twin.equals(real)) return { kind: "plain" };
  if (written.equals(twin)) return { kind: "unchanged" };
  if (twin.length > WRITE_BACK_MAX || real.length > WRITE_BACK_MAX || written.length > WRITE_BACK_MAX) {
    return { kind: "refuse", reason: `the file is over ${WRITE_BACK_MAX} bytes` };
  }
  const tText = twin.toString("utf8");
  const own = ownPlaceholders(tText);
  if (own.size === 0) {
    return { kind: "refuse", reason: "its protected form carries no placeholder Mandu can map back to the real file" };
  }
  const wText = written.toString("utf8");
  const tLines = tText.split("\n");
  const wLines = wText.split("\n");
  const rLines = splitBytes(real);
  const wCarriesOwn = wLines.some((l) => hasOwn(l, own));
  if (tLines.length !== rLines.length || !tLines.every((t, i) => lineAligns(t, rLines[i]!.toString("utf8")))) {
    if (!wCarriesOwn) return { kind: "restore", bytes: written, restoredLines: 0 };
    return { kind: "refuse", reason: "its protected values do not sit one per line, so they cannot be put back line by line" };
  }
  const out: Buffer[] = [];
  let restored = 0;
  for (const line of wLines) {
    if (!hasOwn(line, own)) { out.push(Buffer.from(line, "utf8")); continue; }
    const at: number[] = [];
    tLines.forEach((t, i) => { if (t === line) at.push(i); });
    if (at.length === 0) {
      return { kind: "refuse", reason: "a line that holds a protected value was changed, or a protected value was moved into a new line" };
    }
    const first = rLines[at[0]!]!;
    if (at.some((i) => !rLines[i]!.equals(first))) {
      return { kind: "refuse", reason: "a line that holds a protected value appears more than once with different values" };
    }
    out.push(first);
    restored++;
  }
  const nl = Buffer.from("\n");
  const parts: Buffer[] = [];
  out.forEach((b, i) => { if (i > 0) parts.push(nl); parts.push(b); });
  return { kind: "restore", bytes: Buffer.concat(parts), restoredLines: restored };
}

/**
 * Does twin line `t` stand for real line `r`? Its text outside the
 * placeholders must be the real line's, in order: a line without one is the
 * real line itself; a line with them starts and ends as the real line does
 * and keeps its literal pieces between. A twin that fails this for any line
 * is not a line-for-line rendering of the file (the mapping would guess).
 * A placeholder the twin quoted (`KEY='$MDU:…'`, the structured twin's
 * shell-safe form of a dotenv value) counts with its quotes, which the real
 * line need not have.
 */
const TOKEN_SRC = PLACEHOLDER_RE.source;
const QUOTED_TOKEN_RE = new RegExp(`'(?:${TOKEN_SRC})'|"(?:${TOKEN_SRC})"|(?:${TOKEN_SRC})`);
export function lineAligns(t: string, r: string): boolean {
  const pieces = t.split(QUOTED_TOKEN_RE);
  if (pieces.length === 1) return t === r;
  const first = pieces[0]!;
  const last = pieces[pieces.length - 1]!;
  if (!r.startsWith(first) || !r.endsWith(last) || r.length < first.length + last.length) return false;
  let at = first.length;
  const end = r.length - last.length;
  for (const mid of pieces.slice(1, -1)) {
    if (mid === "") continue;
    const i = r.indexOf(mid, at);
    if (i < 0 || i + mid.length > end) return false;
    at = i + mid.length;
  }
  return true;
}

/** Split bytes on `\n`, as String.split does (a trailing newline gives a last empty part). */
function splitBytes(b: Buffer): Buffer[] {
  const out: Buffer[] = [];
  let start = 0;
  for (let i = 0; i < b.length; i++) {
    if (b[i] === 0x0a) { out.push(b.subarray(start, i)); start = i + 1; }
  }
  out.push(b.subarray(start));
  return out;
}
