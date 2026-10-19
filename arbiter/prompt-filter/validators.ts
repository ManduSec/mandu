/**
 * validators — the named checks a pattern pack may put after a regex
 * (confidentiality-plan-15-prompt-filter.md §4.2: `check: luhn`). Built in
 * and named: a pack cannot ship code. A match the check refuses is not a
 * finding. Pure. Mandu-new (no reference origin).
 */

/** The digits of `s`, in order (separators such as spaces and dashes dropped). */
function digitsOf(s: string): string {
  return s.replace(/[^0-9]/g, "");
}

/** The Luhn (mod 10) check of payment-card numbers: 12 to 19 digits. */
export function luhn(s: string): boolean {
  const d = digitsOf(s);
  if (d.length < 12 || d.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let n = d.charCodeAt(d.length - 1 - i) - 48;
    if (i % 2 === 1) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
  }
  return sum % 10 === 0;
}

/** The Korean resident registration number's check digit (13 digits,
 *  weights 2..9,2..5, check = (11 - sum mod 11) mod 10). Numbers issued
 *  since October 2020 carry no check digit; this check is for the older
 *  form a pack names it for. */
export function krRrnChecksum(s: string): boolean {
  const d = digitsOf(s);
  if (d.length !== 13) return false;
  const w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
  let sum = 0;
  for (let i = 0; i < 12; i++) sum += (d.charCodeAt(i) - 48) * w[i]!;
  return (11 - (sum % 11)) % 10 === d.charCodeAt(12) - 48;
}

/** The IBAN check (ISO 13616, mod 97 = 1): two letters, two digits, then
 *  11 to 30 letters and digits; spaces ignored. */
export function iban(s: string): boolean {
  const v = s.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(v)) return false;
  const moved = v.slice(4) + v.slice(0, 4);
  let rem = 0;
  for (const c of moved) {
    const n = c >= "A" && c <= "Z" ? String(c.charCodeAt(0) - 55) : c;
    for (const ch of n) rem = (rem * 10 + (ch.charCodeAt(0) - 48)) % 97;
  }
  return rem === 1;
}

/** Every built-in check, by the name a pack uses. */
export const VALIDATORS: Readonly<Record<string, (s: string) => boolean>> = Object.freeze({
  luhn,
  "kr-rrn-checksum": krRrnChecksum,
  iban,
});

export const VALIDATOR_NAMES: readonly string[] = Object.keys(VALIDATORS);
