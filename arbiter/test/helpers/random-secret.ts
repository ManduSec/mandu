/**
 * random-secret — random credential bodies for the scan tests, assembled at
 * run time so no test file holds a credential-shaped literal.
 *
 * A body is drawn from the 62 alphanumerics and drawn again until it is a
 * value the detectors take (arbiter/policy/secret-detectors.ts): a letter
 * AND a digit (`looksLikeSecretValue`), no placeholder run
 * (`isPlaceholder`: `xxxx`, `dummy`, …) and, from 12 characters, 3 bits a
 * character (the assignment rule's floor). A plain draw of 36 has no digit
 * 0.19% of the time; the detector once dropped such a vendor-prefixed value
 * and a scan test filed one finding short (CI job gl-7778-12993:
 * dashboard-suggestions filed 2, not 3; secret-discovery.md §3.4). That was a
 * real miss for formats without GitHub's checksum (every Hugging Face
 * token: 34 letters), fixed 2026-10-01: a prefixed value no longer needs a
 * digit, and secret-detectors.test.ts pins the no-digit case with fixed
 * values. The helper still draws a digit for the assignment rule
 * (`looksLikeSecretValue` takes a letters-only value only when it reads as
 * random, 2026-10-02) and no placeholder run (the detector forgives an
 * `xxxx`/`dummy` inside a random run since 2026-10-02, `isStandIn`, but not
 * one at the body's edge; the helper keeps clear of both). The rule is spelled
 * out here, not taken from `looksLikeSecretValue`, so a detector that
 * turned stricter fails the tests instead of bending their fixtures.
 */
import { randomBytes } from "node:crypto";
import { entropy, isPlaceholder } from "../../policy/secret-detectors.js";

/** `n` random alphanumerics, with a letter and a digit, no placeholder run,
 *  and 3+ bits a character from 12 characters on (n ≥ 2). */
export function randomSecretBody(n: number): string {
  if (!Number.isInteger(n) || n < 2) throw new Error(`randomSecretBody: ${n} is too short for a letter and a digit`);
  for (let tries = 0; tries < 1000; tries++) {
    let s = "";
    while (s.length < n) s += randomBytes(64).toString("base64").replace(/[^A-Za-z0-9]/g, "");
    s = s.slice(0, n);
    if (/[A-Za-z]/.test(s) && /[0-9]/.test(s) && !isPlaceholder(s) && (n < 12 || entropy(s) >= 3.0)) return s;
  }
  throw new Error(`randomSecretBody: no ${n}-character draw passed in 1000 tries`);
}
