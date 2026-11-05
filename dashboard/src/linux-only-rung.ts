/**
 * linux-only-rung — which launch lines are about a LINUX-ONLY layer's
 * absence (bubblewrap, Landlock, the connect guard), for the product
 * page's count of protections that did not start (dashboard.md §4.21 *On
 * the product page*): off Linux such a layer is not part of the platform's
 * protection, so its line counts for nothing.
 *
 * A display copy of the launcher's `isLinuxOnlyRungLine`
 * (launcher/src/doctor-live.ts), which makes the same call for `mandu
 * doctor`; the dashboard does not import the launcher. The stack test
 * `linux-only-rung-parity.test.ts` keeps the two equal over real launch
 * lines in both wordings. Pure.
 */

/** The default-on layers that exist only on Linux, matched on their launch
 *  lines in the older wording ("… is not built … proceeding WITHOUT it")
 *  and the newer ("… Linux only …") alike. */
export const LINUX_ONLY_RUNG_RES: readonly RegExp[] = [
  /\bexec-box\b|mandu-exec-box/,
  /\blandlock-net\b|whole-agent TCP confine|mandu-landlock-apply/,
  /\bnet-guard\b|connect-guard|mandu-net-guard/,
  /inspect_symbol network confine/,
];

/** What makes the line a Linux-only absence and not a failure of a macOS
 *  layer: a Linux native bin, bubblewrap, a user namespace, the Landlock
 *  kernel feature, or the words "Linux only". */
const LINUX_CAUSE_RE = /mandu-(?:exec-box|landlock-apply|net-guard)\b|\bbwrap\b|bubblewrap|\bLandlock\b|user namespaces|\bLinux only\b/;
/** …and never a line about the macOS mechanism itself (a Seatbelt layer
 *  that failed is a real drop, whatever name it shares). */
const MAC_MECHANISM_RE = /Seatbelt|sandbox-exec/;

/** A launch line about a Linux-only layer's absence (either wording). */
export function isLinuxOnlyRungLine(line: string): boolean {
  return LINUX_ONLY_RUNG_RES.some((re) => re.test(line)) && LINUX_CAUSE_RE.test(line) && !MAC_MECHANISM_RE.test(line);
}
