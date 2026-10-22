/**
 * transcript-test-values — does a key-shaped value the scan found read as a
 * test value rather than a key (plan 17 §3 item 14,
 * docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md)?
 *
 * The detector (secret-detectors.ts `isStandIn`) already drops the obvious
 * stand-ins: `EXAMPLE` (AWS's documented example key ID, which ends in it), `xxxx`,
 * `placeholder`, `changeme`, `${VAR}`, one character repeated. What passes
 * it and still reads as made up is what this marks: a test word set off by
 * separators (`sk-test-…`, `sk-ant-api03-fake-…`), in lower or upper
 * case, a long run of one character (an AWS key ID of sixteen zeros), a straight
 * run (`abcdefgh`, `1234567890`), a short unit repeated
 * (`abcdabcdabcdabcd`), a long body of four characters or fewer, or one of
 * the example keys vendors publish in their documentation.
 *
 * A real key must never be marked: a mark moves a value out of the count
 * of leaks. So each rule is one a random body essentially never meets. The
 * test words need a separator on both sides and one case (`-test-` sits at
 * a given place of a random `[A-Za-z0-9_-]` body about once in 10^10; over
 * the longest body, Anthropic's 93 characters, and every word, under once
 * in ten million keys; a body with no separators, GitHub's or AWS's, never
 * holds one). One character repeated needs eight (ten for a digit), a
 * straight run eight letters or ten digits (a Slack token's ids are
 * digits only), the repeated unit sixteen characters, the four-character
 * body sixteen (once in 10^10 for the narrowest alphabet, AWS's 36): each
 * under once in a billion keys. A word inside a random run (`k3Jtest9Qm…`),
 * a mixed-case `TeSt`, or `sk_test_` alone (Stripe's test mode keys are
 * real keys, and the detector does not take them anyway) is not a mark.
 * The unit test draws thousands of random bodies of every vendor format
 * and marks none. And only a key-shaped value is ever marked: never one of
 * the person's own secrets (a value found in their files), never a value
 * named like a secret, a URL's password or a private key.
 *
 * Pure. PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no
 * reference origin).
 */
import type { SecretShape } from "./secret-detectors.js";

/** Example keys vendors publish in their documentation, which the detector
 *  takes for keys: Slack's API documentation's bot token and the API key of
 *  Google's Maps samples. Split so no scanner of this repository reads them
 *  as keys. */
const DOCUMENTED: ReadonlySet<string> = new Set([
  "xox" + "b-17653672481-19874698323-pdFZKVeTuE8sk7oOcBrzbqgy",
  "AI" + "zaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe",
]);

/** The words a person writes into a made-up key, in lower case or in
 *  upper case (a mixed-case run is a random body's). */
const TEST_WORDS = ["test", "tests", "testing", "fake", "mock", "dummy", "sample", "demo", "fixture", "bogus", "invalid", "notreal", "not-a-real", "placeholder", "example"];
const wordsRe = (words: readonly string[]): RegExp => new RegExp(`(?:^|[-_.])(?:${words.join("|")})(?:[-_.]|$)`);
const TEST_WORD_RES: readonly RegExp[] = [wordsRe(TEST_WORDS), wordsRe(TEST_WORDS.map((w) => w.toUpperCase()))];

/** A straight run: each character one more (or one less) than the last,
 *  within one case of letters (eight in a row) or the digits (ten, `9` to
 *  `0` counting as a step, as in `1234567890`: a Slack token's ids are
 *  digits only, where a shorter run turns up by chance). */
function straightRun(s: string): boolean {
  let up = 1;
  let down = 1;
  const cls = (c: string): number => (/[0-9]/.test(c) ? 0 : /[a-z]/.test(c) ? 1 : /[A-Z]/.test(c) ? 2 : -1);
  for (let i = 1; i < s.length; i++) {
    const c = cls(s[i]!);
    const same = c >= 0 && c === cls(s[i - 1]!);
    let d = s.charCodeAt(i) - s.charCodeAt(i - 1);
    if (c === 0 && Math.abs(d) === 9) d = -Math.sign(d);
    up = same && d === 1 ? up + 1 : 1;
    down = same && d === -1 ? down + 1 : 1;
    if (Math.max(up, down) >= (c === 0 ? 10 : 8)) return true;
  }
  return false;
}

/**
 * Does this key-shaped value read as a test value? `shape` and `preview`
 * are the detector's (the preview's prefix is the format's, so the rules
 * read the body after it). False for any shape but the vendor formats.
 * Pure.
 */
export function looksLikeTestValue(value: string, shape: SecretShape, preview: string): boolean {
  if (shape === "private-key" || shape === "credential-assignment" || shape === "url-password") return false;
  if (DOCUMENTED.has(value)) return true;
  const prefix = preview.endsWith("…") ? preview.slice(0, -1) : "";
  const body = prefix !== "" && value.startsWith(prefix) ? value.slice(prefix.length) : value;
  // The body's start counts as set off only where the prefix ends with a
  // separator (`sk-`, `ghp_`), not after `AKIA` or `AIza`.
  const head = prefix === "" || /[-_.]$/.test(prefix) ? body : `\u0000${body}`;
  if (TEST_WORD_RES.some((re) => re.test(head))) return true;
  // One character eight times in a row (a digit ten times).
  if (/([^0-9])\1{7,}|([0-9])\2{9,}/.test(body)) return true;
  if (straightRun(body)) return true;
  // A unit of two to eight characters, repeated over sixteen or more.
  for (const m of body.matchAll(/(.{2,8}?)\1{3,}/g)) if (m[0].length >= 16) return true;
  // Four characters or fewer make up a long body.
  return body.length >= 16 && new Set(body).size <= 4;
}
