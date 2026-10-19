/**
 * secret-detectors — the content detectors every Mandu secret scan shares
 * (confidentiality-plan-14-policy-suggestions.md §3.1, §13.2): the
 * credential formats, the placeholder filter, the entropy test, git's binary
 * test and the detector's fingerprint.
 *
 * Built in phase 1 inside secret-history-scan.ts (the S1 git-history scan,
 * docs/design/confidentiality/secret-discovery.md §3.2 item 5) and lifted out, unchanged, in
 * phase 3 for the S2 workspace scan (secret-workspace-scan.ts).
 * secret-history-scan.ts re-exports every name here, so no import broke.
 *
 * THE FINGERPRINT MUST NOT MOVE WHEN THIS FILE MOVES. `historyDetectorFingerprint`
 * hashes the SOURCE TEXT of the functions below (`String(fn)`) and keys the
 * history scan's on-disk cache (secret-history-cache.ts): a changed value
 * makes every repository's next scan read every blob again. The code was
 * moved byte for byte, and `secret-detectors.test.ts` pins the value. Edit
 * a rule only on purpose, and then update the pin in the same change.
 *
 * Tuned for PRECISION (§3.1): a false positive costs the person a click, a
 * detector that cries wolf gets ignored. Every hit is MASKED: the format's
 * public prefix at most, an assignment's name, a URL's host, or a key
 * block's header; never a character of the value's body, its length or a
 * hash of it. Pure: no I/O, no clock.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { createHash } from "node:crypto";
import { crc32 } from "node:zlib";

// ── The shapes and the hit type ─────────────────────────────────────────────

/** The credential formats the content detector knows. */
export type SecretShape =
  | "private-key"
  | "aws-access-key-id"
  | "aws-secret-key"
  | "github-token"
  | "gitlab-token"
  | "anthropic-key"
  | "openai-key"
  | "slack-token"
  | "stripe-key"
  | "google-api-key"
  | "npm-token"
  | "pypi-token"
  | "huggingface-token"
  | "url-password"
  | "credential-assignment";

/** One content hit, MASKED: never a character of the value's body. */
export interface ShapeHit {
  shape: SecretShape;
  /** 1-based line of the blob the value starts on. */
  line: number;
  /** A fixed mask: the format's public prefix at most, then `…`
   *  (`sk-ant-…`, `AKIA…`, `DB_PASSWORD=…`, `postgres://…:…@db.host`, or
   *  a key block's BEGIN header line followed by `…`). */
  preview: string;
}

// ── Pure: the detector ──────────────────────────────────────────────────────

/** A value that holds a stand-in word or template syntax (documentation,
 *  templates, CI variables, Mandu's own symbols). Pure. The WORD test
 *  only: the detector's rules ask {@link isStandIn}, which forgives a word
 *  a long random value holds by chance. */
export function isPlaceholder(v: string): boolean {
  return /example|changeme|change_me|placeholder|dummy|redacted|replace[_-]?me|your[_-]?(api[_-]?)?(key|token|secret|password)|xxxx|\*\*\*|\.\.\.|<[^>]*>|\$\{|\{\{|%\(|\$MDU:/i.test(v)
    || v.startsWith("$")
    || /^(.)\1+$/.test(v);
}

/** The stand-in WORDS of {@link isPlaceholder} (not its template syntax). */
const STAND_IN_WORDS = /example|changeme|change_me|placeholder|dummy|redacted|replace[_-]?me|your[_-]?(api[_-]?)?(key|token|secret|password)|xxxx/gi;

/** The stand-in words short enough for a random body to hold by chance:
 *  `xxxx` (any case, ~3.6 in 100,000 36-character base62 bodies) and
 *  `dummy` (~0.1 in 100,000). A longer word (`example`, `redacted`,
 *  `placeholder`) turns up in a random body less than once in 10^9, so in
 *  a value it is a person's (AWS's documentation writes `…EXAMPLEKEY`
 *  inside random-looking values). */
const CHANCE_WORDS = /^(?:x{4}|dummy)$/i;

/** Is `v` a stand-in, not a credential? Template syntax (`${X}`, `<token>`,
 *  `***`, `...`, `$MDU:`), a leading `$`, one character repeated, or a
 *  stand-in word other than `xxxx`/`dummy` always is. A value holding
 *  `xxxx` or `dummy` is one unless the word sits INSIDE a random run and
 *  what remains is still a long random value: each occurrence has a letter
 *  or digit on both sides (a person writes `-dummy-`, `_xxxx`, `…-xxxx`; a
 *  random body puts no separator around it), and without the words 16+
 *  characters, at least two thirds of the value, 3 bits a character. The
 *  word test alone dropped the real keys whose random body held such a
 *  word (~4.5 in 100,000) for every format but GitHub's checksummed tokens
 *  (fixed 2026-10-02, secret-discovery.md §3.2 item 5). Implies
 *  {@link isPlaceholder}, so the detector only widens. Pure. */
export function isStandIn(v: string): boolean {
  if (!isPlaceholder(v)) return false;
  if (/\*\*\*|\.\.\.|<[^>]*>|\$\{|\{\{|%\(|\$MDU:/.test(v) || v.startsWith("$") || /^(.)\1+$/.test(v)) return true;
  // Six x in a row is a person's mask (a random body: ~3 in 10^8).
  if (/x{6}/i.test(v)) return true;
  const words = new RegExp(STAND_IN_WORDS.source, "gi");
  for (let m = words.exec(v); m !== null; m = words.exec(v)) {
    if (!CHANCE_WORDS.test(m[0])) return true;
    if (!/[A-Za-z0-9]/.test(v[m.index - 1] ?? "") || !/[A-Za-z0-9]/.test(v[m.index + m[0].length] ?? "")) return true;
  }
  const rest = v.replace(words, "");
  return !(rest.length >= 16 && rest.length * 3 >= v.length * 2 && entropy(rest) >= 3.0);
}

/** Shannon entropy in bits per character. Pure. */
export function entropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Long and mixed enough to be a credential rather than code or prose: a
 *  letter, 12+ characters, not a stand-in ({@link isStandIn}), entropy of
 *  at least 3 bits a character, and a digit OR, with none, letters that
 *  read as random rather than as words ({@link randomLetters}). A digit was
 *  required until 2026-10-02, which missed `DB_PASSWORD=` with a
 *  letters-only password (secret-discovery.md §3.2 item 5). Pure. */
export function looksLikeSecretValue(v: string): boolean {
  return v.length >= 12 && /[A-Za-z]/.test(v) && !isStandIn(v) && entropy(v) >= 3.0 && (/[0-9]/.test(v) || randomLetters(v));
}

/** A value with no digit that still reads as random rather than as a word,
 *  an identifier, a path or prose: 16+ characters, none of the separators
 *  those use (`.`, `_`, `-`, `:`, `/`, a space, brackets, quotes), both
 *  cases, 3.5 bits a character, and short case runs. An identifier's words
 *  run 3+ letters each (`getSecretTokenValue`: 3, 6, 5, 5;
 *  `XMLHttpRequestUpload`: 3, 4, 7, 6); a random mix of cases runs about 2
 *  (`hJkqWzPmvXrTbnLs`). A one-case passphrase is not taken (it reads as
 *  words to this test). Pure. */
export function randomLetters(v: string): boolean {
  if (v.length < 16 || !/^[A-Za-z+=!@%^*~?&]+$/.test(v) || !/[a-z]/.test(v) || !/[A-Z]/.test(v)) return false;
  if (entropy(v) < 3.5) return false;
  const runs = v.match(/[A-Z]+(?![a-z])|[A-Z]?[a-z]+/g) ?? [];
  const letters = runs.reduce((n, r) => n + r.length, 0);
  const vowels = (v.match(/[aeiou]/gi) ?? []).length;
  return runs.length > 0 && letters * 2 < runs.length * 7 && vowels * 10 < letters * 3;
}

interface LineRule {
  shape: SecretShape;
  re: RegExp;
  /** The value (matched, never shown). */
  value: (m: RegExpExecArray) => string;
  /** The mask: a fixed public part of the format, or a name, and `…`
   *  where the value was. */
  preview: (m: RegExpExecArray) => string;
  ok?: (value: string) => boolean;
}

const prefixRule = (shape: SecretShape, re: RegExp, shownLen: (v: string) => number, ok?: (v: string) => boolean): LineRule => ({
  shape, re,
  value: (m) => m[1]!,
  preview: (m) => `${m[1]!.slice(0, shownLen(m[1]!))}…`,
  ...(ok ? { ok } : {}),
});
/** A vendor-prefixed value (`hf_…`, `glpat-…`, `sk_live_…`): not a
 *  placeholder, and a letter and EITHER a digit OR, with no digit, 3+ bits a
 *  character. The prefix is the evidence; a digit is not. The rule once
 *  demanded a digit (`/[0-9]/` alone), which dropped every real Hugging
 *  Face token (`hf_` + 34 LETTERS, its documented format), 3.3% of 20-char
 *  GitLab tokens, 1.5% of 24-char Stripe keys and 0.19% of any 36-char
 *  alphanumeric body: a key the detector missed reached the policy model's
 *  view (confidentiality-plan-14 §14.13, the security fix of 2026-10-01).
 *  The entropy floor keeps a no-digit run like `ghp_aaaa…` out; a random
 *  body of 20+ characters never falls under it. Only widens the old rule
 *  (secret-detectors.test.ts proves it by property). Pure. */
const mixed = (v: string): boolean =>
  /[A-Za-z]/.test(v) && !isStandIn(v) && (/[0-9]/.test(v) || entropy(v) >= 3.0);

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/** GitHub's own check on its prefixed tokens (`ghp_`, `gho_`, `ghu_`,
 *  `ghs_`, `ghr_`): 30 random characters, then the CRC-32 of those 30
 *  (IEEE, as zlib computes it) in base62 over `0-9A-Za-z`, most significant
 *  first, zero-padded to 6 (GitHub, "Behind GitHub's new authentication
 *  token formats", 2021; checked against published test tokens,
 *  secret-discovery.md §3.2 item 5). A match is a token GitHub's format
 *  minted (a chance match is 1 in 2^32), so it is taken even when a
 *  placeholder pattern takes its random part (`xxxx`, `dummy`: 2.75 real
 *  tokens in 100,000, which `mixed` dropped). It always holds a digit (the
 *  checksum's first character is 0-4), so the old digit rule never missed a
 *  real one; it missed a `gh*_` value with no digit and no valid checksum,
 *  which `mixed` now takes. Fine-grained `github_pat_` tokens (22 base62,
 *  `_`, 59 base62) are not covered: GitHub has published no checksum for
 *  that layout, and no scanner validates one (checked 2026-10-02), so a
 *  guessed check could only be wrong; they take `mixed`, whose stand-in
 *  test since forgives an `xxxx`/`dummy` inside a random run for every
 *  format (`isStandIn`). Pure. */
export function githubTokenChecksumOk(token: string): boolean {
  const m = /^gh[pousr]_([A-Za-z0-9]{30})([A-Za-z0-9]{6})$/.exec(token);
  if (m === null) return false;
  let n = crc32(m[1]!);
  let sum = "";
  for (let i = 0; i < 6; i++) {
    sum = BASE62[n % 62]! + sum;
    n = Math.floor(n / 62);
  }
  return sum === m[2];
}
/** A GitHub prefixed token: GitHub's checksum, or else the `mixed` rule. */
const githubTokenOk = (v: string): boolean => githubTokenChecksumOk(v) || mixed(v);
/** An assignment's name as shown: only when it reads as an identifier, never
 *  when it could itself be part of a credential. */
const nameShown = (name: string): string =>
  name.length <= 40 && /^[A-Za-z_][A-Za-z0-9_.-]*$/.test(name) && !looksLikeSecretValue(name) ? name : "credential";

/** The one-line formats, most specific first: a span of the line an
 *  earlier rule claimed is not reported again by a later one. */
const LINE_RULES: readonly LineRule[] = [
  prefixRule("anthropic-key", /(?<![A-Za-z0-9_-])(sk-ant-[A-Za-z0-9_-]{20,})/g, () => 7, mixed),
  prefixRule("openai-key", /(?<![A-Za-z0-9_-])(sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})/g,
    (v) => (/^sk-(?:proj|svcacct|admin)-/.exec(v)?.[0].length ?? 3), mixed),
  prefixRule("github-token", /(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{36,255})(?![A-Za-z0-9_])/g, () => 4, githubTokenOk),
  prefixRule("github-token", /(?<![A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{60,255})(?![A-Za-z0-9_])/g, () => 11, mixed),
  prefixRule("gitlab-token", /(?<![A-Za-z0-9_-])(glpat-[A-Za-z0-9_-]{20,})/g, () => 6, mixed),
  prefixRule("slack-token", /(?<![A-Za-z0-9_-])(xox[abposr]-[A-Za-z0-9-]{10,})/g, () => 5, mixed),
  prefixRule("stripe-key", /(?<![A-Za-z0-9_])((?:sk|rk)_live_[A-Za-z0-9]{20,})/g, () => 8, mixed),
  prefixRule("google-api-key", /(?<![A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/g, () => 4, (v) => !isStandIn(v)),
  prefixRule("npm-token", /(?<![A-Za-z0-9_])(npm_[A-Za-z0-9]{36})(?![A-Za-z0-9_])/g, () => 4, mixed),
  prefixRule("pypi-token", /(?<![A-Za-z0-9_-])(pypi-AgE[A-Za-z0-9_-]{50,})/g, () => 5, (v) => !isStandIn(v)),
  prefixRule("huggingface-token", /(?<![A-Za-z0-9_])(hf_[A-Za-z0-9]{34,})(?![A-Za-z0-9_])/g, () => 3, mixed),
  prefixRule("aws-access-key-id", /(?<![A-Z0-9])((?:AKIA|ASIA)[0-9A-Z]{16})(?![A-Z0-9])/g, () => 4, (v) => !isStandIn(v)),
  {
    shape: "aws-secret-key",
    re: /(aws_secret_access_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi,
    value: (m) => m[2]!,
    preview: (m) => `${m[1]!.toLowerCase()}=…`,
    ok: (v) => !isStandIn(v),
  },
  {
    // The host is where to rotate, not the secret; the user name is not shown.
    shape: "url-password",
    re: /\b([a-z][a-z0-9+.-]{1,15}):\/\/([^\s:/@'"`]+):([^\s@/'"`]{3,})@([A-Za-z0-9.-]+)/gi,
    value: (m) => m[3]!,
    preview: (m) => `${m[1]!.toLowerCase()}://…:…@${m[4]!}`,
    ok: (v) => !isStandIn(v) && !/^(pass(word)?|pwd|secret|token)$/i.test(v),
  },
  {
    shape: "credential-assignment",
    // A name starts at a non-word character, or right after a string
    // escape (`"…\nAPI_TOKEN=…"` names API_TOKEN, not nAPI_TOKEN).
    re: /(?:(?<=\\[nrt])|(?<![A-Za-z0-9_\\]))([A-Za-z0-9_.-]{0,40}(?:secret|token|passw(?:or)?d|passphrase|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key)[A-Za-z0-9_.-]{0,40})["']?\s*[:=]\s*["']?([A-Za-z0-9_\-+/=.~!@%^*:?&]{12,})/gi,
    value: (m) => m[2]!,
    preview: (m) => `${nameShown(m[1]!)}=…`,
    ok: (v) => looksLikeSecretValue(v),
  },
];

/** A PEM or OpenSSH private-key block: the header, optional RFC 1421
 *  headers (an encrypted PEM's `Proc-Type:`), then key material. A header
 *  alone (documentation) is not one. */
const PRIVATE_KEY_RE = /-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY( BLOCK)?-----\r?\n(?:[A-Za-z-]+: [^\n]*\r?\n)*\r?\n?([A-Za-z0-9+/=]{40,})/g;

/** Lines longer than this (minified bundles, data) are not matched line by
 *  line; private keys are matched over the whole text regardless. */
const MAX_LINE = 10_000;

/** A defensive last check on a mask: should it ever hold eight characters
 *  of the value's body (past a format prefix), only the shape is shown. */
function safePreview(preview: string, value: string, shape: SecretShape): string {
  const body = value.length > 12 ? value.slice(value.length - 8) : "";
  return body !== "" && preview.includes(body) ? `${shape}…` : preview;
}

/** Hits reported per blob. */
const DETECT_MAX_HITS = 10;

/** Every credential-shaped value in `text`, MASKED (no value, no length),
 *  at most `maxHits`, one per (shape, value). Pure. */
export function detectSecretShapes(text: string, opts: { maxHits?: number } = {}): ShapeHit[] {
  const max = opts.maxHits ?? DETECT_MAX_HITS;
  const hits: ShapeHit[] = [];
  const seen = new Set<string>();
  const lineStarts: number[] = [0];
  for (let i = text.indexOf("\n"); i >= 0; i = text.indexOf("\n", i + 1)) lineStarts.push(i + 1);
  const lineOf = (idx: number): number => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >>> 1;
      if (lineStarts[mid]! <= idx) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
  const add = (shape: SecretShape, value: string, preview: string, at: number): void => {
    const key = `${shape}\0${value}`;
    if (seen.has(key) || hits.length >= max) return;
    seen.add(key);
    hits.push({ shape, line: lineOf(at), preview: safePreview(preview, value, shape) });
  };

  PRIVATE_KEY_RE.lastIndex = 0;
  for (let m = PRIVATE_KEY_RE.exec(text); m !== null && hits.length < max; m = PRIVATE_KEY_RE.exec(text)) {
    add("private-key", m[3]!, `-----BEGIN ${m[1] ?? ""}PRIVATE KEY${m[2] ?? ""}-----…`, m.index);
  }

  for (let li = 0; li < lineStarts.length && hits.length < max; li++) {
    const start = lineStarts[li]!;
    const nl = text.indexOf("\n", start);
    const line = text.slice(start, nl < 0 ? text.length : nl);
    if (line.length > MAX_LINE || line.length < 12) continue;
    const claimed: Array<[number, number]> = [];
    for (const rule of LINE_RULES) {
      rule.re.lastIndex = 0;
      for (let m = rule.re.exec(line); m !== null; m = rule.re.exec(line)) {
        const a0 = m.index;
        const b0 = m.index + m[0].length;
        if (claimed.some(([a, b]) => a0 < b && b0 > a)) continue;
        const value = rule.value(m);
        if (rule.ok && !rule.ok(value)) continue;
        claimed.push([a0, b0]);
        add(rule.shape, value, rule.preview(m), start + a0);
      }
    }
  }
  return hits;
}

/** One credential-shaped value in a text, by position: [start, end) in
 *  UTF-16 code units of the VALUE (an assignment's value, a URL's password,
 *  a whole private-key block through its END line). For the prompt filter's
 *  `key-shapes` filter (confidentiality-plan-15 §4.1), which must replace
 *  the span; the scans keep {@link detectSecretShapes}, whose masked
 *  previews never carry a position. */
export interface ShapeSpan {
  shape: SecretShape;
  start: number;
  end: number;
}

/** The value groups' positions need the `d` flag; one clone per rule. */
const SPAN_RULES: ReadonlyArray<{ rule: LineRule; re: RegExp; group: number }> = LINE_RULES.map((rule) => ({
  rule,
  re: new RegExp(rule.re.source, `${rule.re.flags}d`),
  // The value is the last capture group of every rule (`value` reads it).
  group: rule.shape === "aws-secret-key" || rule.shape === "credential-assignment" ? 2 : rule.shape === "url-password" ? 3 : 1,
}));

/** The END line that closes a private-key block. */
const PRIVATE_KEY_END_RE = /-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g;

/** Every credential-shaped value in `text` with its position, by the same
 *  rules and checks as {@link detectSecretShapes} (same precedence: a span a
 *  more specific rule claimed is not reported again), every occurrence, at
 *  most `maxHits`. A private key spans its block from the BEGIN line to the
 *  END line (to the end of the text when there is none). Pure. Kept apart
 *  from `detectSecretShapes` so the history scan's fingerprint (the source
 *  text of that function) does not move. */
export function locateSecretShapes(text: string, opts: { maxHits?: number } = {}): ShapeSpan[] {
  const max = opts.maxHits ?? 1000;
  const out: ShapeSpan[] = [];
  PRIVATE_KEY_RE.lastIndex = 0;
  for (let m = PRIVATE_KEY_RE.exec(text); m !== null && out.length < max; m = PRIVATE_KEY_RE.exec(text)) {
    PRIVATE_KEY_END_RE.lastIndex = m.index + m[0].length;
    const end = PRIVATE_KEY_END_RE.exec(text);
    const stop = end === null ? text.length : end.index + end[0].length;
    out.push({ shape: "private-key", start: m.index, end: stop });
    PRIVATE_KEY_RE.lastIndex = stop;
  }
  const inKey = (a: number, b: number): boolean => out.some((s) => s.shape === "private-key" && a < s.end && b > s.start);
  let start = 0;
  while (start <= text.length && out.length < max) {
    const nl = text.indexOf("\n", start);
    const line = text.slice(start, nl < 0 ? text.length : nl);
    if (line.length <= MAX_LINE && line.length >= 12) {
      const claimed: Array<[number, number]> = [];
      for (const { rule, re, group } of SPAN_RULES) {
        re.lastIndex = 0;
        for (let m = re.exec(line); m !== null && out.length < max; m = re.exec(line)) {
          const a0 = m.index;
          const b0 = m.index + m[0].length;
          if (claimed.some(([a, b]) => a0 < b && b0 > a)) continue;
          const value = rule.value(m);
          if (rule.ok && !rule.ok(value)) continue;
          claimed.push([a0, b0]);
          const at = (m as RegExpExecArray & { indices?: Array<[number, number] | undefined> }).indices?.[group];
          if (!at) continue;
          if (inKey(start + at[0], start + at[1])) continue;
          out.push({ shape: rule.shape, start: start + at[0], end: start + at[1] });
        }
      }
    }
    if (nl < 0) break;
    start = nl + 1;
  }
  return out.sort((a, b) => a.start - b.start || b.end - a.end);
}

/** Bump when what the detector reports changes in a way its code below does
 *  not show (the fingerprint covers the code itself). */
export const HISTORY_DETECTOR_VERSION = 1;

let detectorPrint: string | null = null;

/** The detector's fingerprint, part of the scan cache's key: its version,
 *  every rule (pattern, flags, value, mask and check), the key-block
 *  pattern, and the code of every function a verdict on a blob depends on.
 *  Any edit of the detector changes it, and a changed fingerprint rescans
 *  every blob once (secret-discovery.md §3.2 item 8). Pure. */
export function historyDetectorFingerprint(): string {
  if (detectorPrint === null) {
    detectorPrint = createHash("sha256").update(JSON.stringify([
      HISTORY_DETECTOR_VERSION,
      PRIVATE_KEY_RE.source, PRIVATE_KEY_RE.flags, MAX_LINE,
      LINE_RULES.map((r) => [r.shape, r.re.source, r.re.flags, String(r.value), String(r.preview), String(r.ok ?? "")]),
      [detectSecretShapes, safePreview, isPlaceholder, isStandIn, randomLetters, entropy, looksLikeSecretValue, mixed, githubTokenChecksumOk, githubTokenOk, nameShown, prefixRule, isBinaryBlob].map(String),
      BASE62, STAND_IN_WORDS.source, STAND_IN_WORDS.flags, CHANCE_WORDS.source, CHANCE_WORDS.flags,
      DETECT_MAX_HITS,
    ])).digest("hex");
  }
  return detectorPrint;
}

/** git's binary test: a NUL in the first 8000 bytes. Pure. */
export function isBinaryBlob(content: Buffer): boolean {
  return content.subarray(0, 8000).includes(0);
}
