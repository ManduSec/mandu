/**
 * view-model/secret-note — what the proxy's `[mandu:secret]` note on a tool
 * result says Mandu did (plan 10 §11.8; dashboard.md §4.25b "A refused read
 * is a block, not a mask").
 *
 * Mandu-new (no reference origin). WHY: when the guard refuses a program's
 * open of a secret file, no gate event records it: the proxy releases the
 * program's own output with a `denied:` or `held:` line. The session page
 * (agent-page.ts) and the inspector's projection (dual-lanes.ts, read by
 * session-counts.ts and dev/js/app.js) both read the note with this one rule,
 * so the two front-ends count the same steps as blocked. Pure; counts only,
 * never a program, a path or a value.
 *
 * `maskCause` also reads why a command's output was masked whole (the
 * session page's "What really happened", dashboard.md §4.25b *A command's
 * masked output says why*): the files the command names or a program of it
 * read, and those programs. Names and paths, still never a value.
 */

/** Lines that tell the AI Mandu refused something and mask nothing
 *  (rewrite-request.ts `buildSecretNote`): a connection refused
 *  (`refused:`), a program's open of a secret file refused (`denied:`), or
 *  held for the person's OK until nobody answered in time (`held:`). */
const REFUSED_NOTE_RE = /^\[mandu:secret\] (?:refused|denied|held): /;
const READ_REFUSED_RE = /^\[mandu:secret\] denied: /;
const READ_HELD_RE = /^\[mandu:secret\] held: /;

function noteLines(note: string | null | undefined): string[] {
  return (note ?? "").split("\n").map((l) => l.trim()).filter((l) => l !== "");
}

/** The note says something was masked: any line of it but a refusal. A note
 *  of refusals only is not a mask (a blocked curl's result, a program refused
 *  a secret file: its own output, released); any other form keeps the masked
 *  reading. */
export function noteMasks(note: string | null | undefined): boolean {
  return noteLines(note).some((l) => !REFUSED_NOTE_RE.test(l));
}

/** A step's refused reads of secret files: `denied` refused outright,
 *  `held` held for the person's OK (an Approvals row was filed) until nobody
 *  answered in time. */
export interface ReadRefusals {
  denied: number;
  held: number;
}

/** The reads of secret files a note says Mandu refused, when that is its
 *  only news: null for a note that masks or names no refused read. */
export function readRefusals(note: string | null | undefined): ReadRefusals | null {
  if (noteMasks(note)) return null;
  const lines = noteLines(note);
  const denied = lines.filter((l) => READ_REFUSED_RE.test(l)).length;
  const held = lines.filter((l) => READ_HELD_RE.test(l)).length;
  return denied + held ? { denied, held } : null;
}

/** What Mandu did, in the product's words: the session page's step note
 *  (agent-page.ts `refusedReadNote`) and the inspector's tool card
 *  (paired-rows.ts `refusedRead`). */
export function refusedReadWords({ denied, held }: ReadRefusals): string {
  const reads = denied + held;
  const without = reads === 1 ? "so the AI got the command's output without it." : "so the AI got the command's output without them.";
  if (!held) return reads === 1 ? `Mandu stopped a program from reading a secret file, ${without}` : `Mandu stopped ${reads} reads of secret files, ${without}`;
  if (!denied) {
    return `${reads === 1 ? "Mandu held a program's read of a secret file" : `Mandu held ${reads} reads of secret files`} and asked for your OK. Nobody answered in time, ${without}`;
  }
  return `Mandu stopped ${reads} reads of secret files, ${without} ${held === 1 ? "One" : held} of them waited for your OK, and nobody answered in time.`;
}

/** Why the proxy masked a command's whole output, as its note told the AI
 *  (rewrite-request.ts, byte-identical in both proxies): the command NAMES
 *  secret files (`pathDerivedLine`, confidentiality.md §7.1 "the
 *  path-derived note"; `paths`, the model's own command tokens, empty when
 *  the note names none), or programs in its tree READ secret files
 *  (`buildSecretNote`'s plan 10 line; `apps` as recorded, `files` absolute).
 *  Paths and program names only, never a value. */
export type MaskCause =
  | { kind: "names"; paths: string[] }
  | { kind: "read"; apps: string[]; files: string[] };

const NAMES_RE = /^\[mandu:secret\] masked: the command names (?:a secret file \((.+)\)|secret files \((.+)\)|a secret file), so its whole output is hidden from you\b/;
const READ_RE = /^\[mandu:secret\] masked: (.*?) read (.+); you see a symbol, and the user does not see this output\b/;

/** The note's reason for a whole-output mask, its first such line; null for
 *  a note with neither form (a refusal, a twin, a listed reader's release,
 *  the fail-closed and session forms, a wording this rule does not know):
 *  the page then keeps its own words, so a changed note never makes a
 *  wrong claim. Lists split as the proxy joins them (`, `); a file only
 *  before an absolute path, so a name holding `, ` stays whole there. */
export function maskCause(note: string | null | undefined): MaskCause | null {
  for (const l of noteLines(note)) {
    const n = NAMES_RE.exec(l);
    if (n) return { kind: "names", paths: n[1] !== undefined ? [n[1]] : n[2] !== undefined ? n[2].split(", ").filter((p) => p !== "") : [] };
    const r = READ_RE.exec(l);
    if (r) return { kind: "read", apps: r[1]!.split(", ").filter((a) => a !== ""), files: r[2]!.split(/, (?=[/~])/).filter((f) => f !== "") };
  }
  return null;
}
