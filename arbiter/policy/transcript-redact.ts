/**
 * transcript-redact — a command, a path or a tool name from a past session,
 * made safe to show (plan 17 §3 item 4,
 * docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md).
 *
 * The scan shows, for each finding, an example of what the agent did: the
 * command whose output held the value, the command the AI wrote it into, the
 * file it read. A command can hold the very value, or other secrets. So
 * before any of it leaves the arbiter, every value the scan knows is
 * replaced by its mask:
 *
 *   1. the known values (the person's own secrets found on disk now, and the
 *      long random-looking values of the same files), longest first, by the
 *      mask the scanner gives each (`‹STRIPE_KEY›`);
 *   2. every value `findSecretValues` finds (the detector of the git-history
 *      scan: vendor formats, `credential-assignment`, `url-password`, a
 *      private key), by its mask (`sk_live_…`), or `…` where the mask is
 *      not the value's own prefix;
 *   3. by the command's own words, whatever the value looks like: a URL's
 *      password, a URL query's value under a secret's name (`?key=…`,
 *      `&sig=…`, `?access_token=…`), a secret-named assignment or option (`FOO_TOKEN=…`,
 *      `--password …`, `"api_key": "…"`), an `Authorization` scheme's
 *      credential (`Bearer …`), curl's `-u user:…`; a variable (`$NAME`) is
 *      kept, as it holds no value;
 *   4. a fail-closed guard on what is left: a long token that reads as
 *      random (`looksLikeSecretValue`), or a base64 run, becomes `…`.
 *
 * Then whitespace is collapsed, only the first line is kept (a here-document's
 * body, a script's later lines and a quoted value's continuation are
 * dropped, with `…` for them) and the text is cut at {@link MAX_SHOWN}
 * characters. A last check runs the detector and the known values over the
 * result once more; should anything remain, only the command's first word is
 * shown.
 *
 * A URL a send went to (item 11) is shown by {@link shownUrl}: stricter
 * first, every query value and the URL's credentials masked whatever their
 * names, then the same steps, cut at {@link MAX_URL_SHOWN}.
 *
 * What it cannot cover: a value with no format, in no file now, not named
 * like a secret and short or plain enough to pass the guard (`mysql
 * -phunter2`), and a value written in pieces or encoded (`"sk_" "live_…"`,
 * base64 of a key with no `=`). Those are not findings either: the scan
 * cannot see them as secrets at all.
 *
 * Pure. PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no
 * reference origin).
 */
import { findSecretValues, looksLikeSecretValue } from "./secret-detectors.js";

/** The longest text shown, in characters, `…` included. */
export const MAX_SHOWN = 240;

/** A value the scan knows, with the mask it is shown as. */
export interface RedactValue {
  value: string;
  mask: string;
}

/** Words a secret's name holds (an assignment, an option, a JSON key, a
 *  header). Wider than the detector's assignment rule: a value here is
 *  masked whatever its length or look. */
const SECRET_NAME = String.raw`[A-Za-z0-9_.-]*(?:secret|token|passw(?:or)?d|passwd|pwd|passphrase|api[_-]?key|access[_-]?key|private[_-]?key|auth|credential|cookie|session[_-]?(?:key|id)|bearer|signature|[_-]key)[A-Za-z0-9_.-]*`;

/** A value as the shell or JSON writes it: a quoted string, or a run with
 *  no space or quote. */
const VALUE = String.raw`(?:"(?:[^"\\\n]|\\.)*"|'[^'\n]*'|[^\s"'` + "`" + String.raw`;|&)]+)`;

const isVariable = (v: string): boolean => /^["']?\$/.test(v);
const masked = (v: string): boolean => /^["']?(?:…|‹[^›]*›)/.test(v);

/** Keep a value's quotes around the mask, so the command still reads. */
function maskValue(v: string): string {
  // An Authorization scheme's word: its credential has a rule of its own.
  if (isVariable(v) || masked(v) || v === "" || v === '""' || v === "''" || /^(?:Bearer|Basic|Token|Digest)$/.test(v)) return v;
  const q = v[0] === '"' || v[0] === "'" ? v[0] : "";
  return `${q}…${q}`;
}

/** The rules of step 3, in order. Each replaces a value its words name. */
const WORD_RULES: ReadonlyArray<[RegExp, (m: string, ...g: string[]) => string]> = [
  // A URL's password: scheme://user:pass@host.
  [/\b([a-z][a-z0-9+.-]{1,15}:\/\/[^\s:/@'"`]*:)([^\s@/'"`]+)@/gi, (_m, a, p) => `${a}${isVariable(p!) ? p : "…"}@`],
  // An Authorization scheme's credential: Bearer xxx, Basic xxx, token xxx.
  [/\b(Bearer|Basic|Token|Digest)(\s+)([^\s"'`,;]+)/g, (_m, s, sp, v) => `${s}${sp}${isVariable(v!) ? v : "…"}`],
  // curl's -u / --user user:password.
  [/(\s(?:-u|--user|--proxy-user)(?:\s+|=)["']?[^\s:"']*:)([^\s"']+)/g, (_m, a, v) => `${a}${isVariable(v!) || v === "" ? v : "…"}`],
  // A secret-named option with its value: --token xxx, --password=xxx, -H "X-Api-Key: xxx" (the header's own rule below).
  [new RegExp(String.raw`(\s--?${SECRET_NAME})(=|\s+)(${VALUE})`, "gi"), (_m, f, sep, v) => (v!.startsWith("-") ? `${f}${sep}${v}` : `${f}${sep}${maskValue(v!)}`)],
  // A URL query's or fragment's value under a short name a secret goes by
  // there: ?key=xxx, &sig=xxx, #code=xxx (the longer names are the next rule's).
  [/([?&#;](?:key|apikey|sig|code|pass|pw|auth)=)([^&#\s"'`]+)/gi, (_m, n, v) => `${n}${isVariable(v!) ? v : "…"}`],
  // A secret-named assignment, JSON key or header: NAME=xxx, NAME: xxx, "api_key": "xxx".
  // Not a variable's use (`"$STRIPE_KEY:"`): what follows it is no value of its.
  [new RegExp(String.raw`(?<![A-Za-z0-9_$\{])(["']?${SECRET_NAME}["']?)(\s*[:=]\s*)(${VALUE})`, "gi"), (_m, n, sep, v) => `${n}${sep}${maskValue(v!)}`],
];

/** A name made of words and numbers (`node-v22.13.0-linux`,
 *  `transcript-scan.test.ts`): each part between `-`, `_` and `.` a
 *  lower-case word, a number or a version. */
const wordy = (s: string): boolean => s.split(/[-_.]/).every((p) => /^(?:[a-z]+|v?\d+)$/.test(p));

/** Is one part random enough to mask? */
const randomPart = (p: string): boolean => p.length >= 20 && looksLikeSecretValue(p) && !wordy(p);

/** Step 4's guard over one token (split at spaces, quotes and the shell's
 *  and JSON's punctuation). */
function guardToken(tok: string): string {
  if (tok.length < 16 || masked(tok) || tok.startsWith("$")) return tok;
  // A base64 run (a key, a blob), slashes included.
  if (/^[A-Za-z0-9+/]{24,}={0,2}$/.test(tok) && /[A-Z]/.test(tok) && /[a-z]/.test(tok) && /[0-9]/.test(tok)) return "…";
  // A path or a URL is read part by part: a random-looking part is masked.
  if (tok.includes("/")) return tok.split("/").map((p) => (randomPart(p) ? "…" : p)).join("/");
  return randomPart(tok) ? "…" : tok;
}

function guard(text: string): string {
  return text.replace(/[^\s"'`=:,;()[\]{}<>|&]+/g, guardToken);
}

/** Steps 1 to 3 over the whole text. */
function replaceKnown(text: string, values: readonly RedactValue[]): string {
  let out = text;
  for (const v of values) if (v.value.length >= 6 && out.includes(v.value)) out = out.split(v.value).join(v.mask);
  // Each hit's value by its mask; again, as a replacement can join a line.
  for (let pass = 0; pass < 3; pass++) {
    const hits = findSecretValues(out);
    if (hits.length === 0) break;
    for (const h of hits.sort((a, b) => b.value.length - a.value.length)) {
      const prefix = h.preview.endsWith("…") ? h.preview.slice(0, -1) : "";
      const mask = prefix !== "" && h.value.startsWith(prefix) ? h.preview : "…";
      out = out.split(h.value).join(mask);
    }
  }
  for (const [re, fn] of WORD_RULES) out = out.replace(re, fn as (m: string, ...g: string[]) => string);
  return out;
}

/** Is anything the scan knows still in `text`? */
function stillHolds(text: string, values: readonly RedactValue[]): boolean {
  return values.some((v) => v.value.length >= 6 && text.includes(v.value)) || findSecretValues(text).length > 0;
}

/** One line, whitespace collapsed, at most {@link MAX_SHOWN} characters. */
function oneLine(text: string): string {
  const joined = text.replace(/\\\r?\n[ \t]*/g, " ").trim();
  const lines = joined.split(/\r?\n|\u2028|\u2029/);
  let head = lines[0]!.replace(/\s+/g, " ").trim();
  if (lines.slice(1).some((l) => l.trim() !== "")) head = `${head} …`;
  return head.length > MAX_SHOWN ? `${head.slice(0, MAX_SHOWN - 1).trimEnd()}…` : head;
}

/**
 * A command (or a path) from a session, safe to show: every value of
 * `values` and every value the detector or the command's own words mark as
 * secret replaced by its mask, the first line only, at most
 * {@link MAX_SHOWN} characters. Never holds a value it knows: when its last
 * check finds one, only the first word is returned. Pure.
 */
export function redactShown(text: string, values: readonly RedactValue[] = []): string {
  const sorted = [...values].sort((a, b) => b.value.length - a.value.length);
  // The whole text first (a value can sit across the cut), then the line.
  const line = oneLine(replaceKnown(text, sorted));
  const out = guard(replaceKnown(line, sorted));
  if (!stillHolds(out, sorted)) return out;
  const first = /^[A-Za-z0-9_./~-]{1,40}/.exec(out)?.[0];
  return first !== undefined && !stillHolds(first, sorted) ? `${first} …` : "…";
}

/** The longest URL a send shows, in characters, `…` included. */
export const MAX_URL_SHOWN = 160;

/** A query's `name=value` with its value masked; a variable (`$KEY`) and an
 *  empty value kept, a part with no name masked whole. */
function maskQueryPart(p: string): string {
  if (p === "") return p;
  const i = p.indexOf("=");
  const v = i < 0 ? p : p.slice(i + 1);
  const kept = v === "" || /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(v);
  return i < 0 ? (kept ? p : "…") : `${p.slice(0, i + 1)}${kept ? v : "…"}`;
}

/**
 * The URL a request went to, safe to show: its credentials (`user:pass@`,
 * a token as the user) and every query value masked whatever its name
 * (`?page=…&token=…`, a variable kept), a fragment as `#…`, the scheme,
 * host and path kept; then {@link redactShown} over it (a known value, a
 * detector's hit or a random-looking part of the path masked), and cut at
 * {@link MAX_URL_SHOWN} characters. Pure.
 */
export function shownUrl(url: string, values: readonly RedactValue[] = []): string {
  const m = /^([a-z][a-z0-9+.-]*:\/\/)([^/?#\s]*@)?([^/?#\s]*)([^?#\s]*)(\?[^#\s]*)?(#\S*)?/i.exec(url.trim());
  const shaped = m === null ? url : `${m[1]}${m[2] !== undefined ? "…@" : ""}${m[3]}${m[4]}${m[5] !== undefined ? `?${m[5].slice(1).split("&").map(maskQueryPart).join("&")}` : ""}${m[6] !== undefined && m[6] !== "#" ? "#…" : ""}`;
  const out = redactShown(shaped, values);
  return out.length > MAX_URL_SHOWN ? `${out.slice(0, MAX_URL_SHOWN - 1)}…` : out;
}

/** A tool's name as shown: an identifier only. */
export function shownToolName(name: string | undefined): string | undefined {
  return name !== undefined && /^[A-Za-z0-9_.:-]{1,64}$/.test(name) && !looksLikeSecretValue(name) ? name : undefined;
}
