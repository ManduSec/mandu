/**
 * model-placement — where a declared model endpoint sits, derived from its URL
 * (model-endpoints.md §2 D1, D2).
 *
 * `local: true` means "inside the trust boundary", on this computer or on the
 * organization's network. What proves the destination differs:
 *   - `host`    the host is a loopback spelling: only this machine answers
 *               (the kernel is the proof);
 *   - `network` any other host (a private or public address, a name): the
 *               transport rules prove it, so such an endpoint must be reached
 *               over https unless the entry says `allow_plain_http: true`
 *               (D2, the maintainer's opt-out, honoured by the helper only).
 * Placement is computed, never written in policy.yaml: it only ever adds
 * requirements.
 *
 * MIRROR of launcher/src/model-endpoints.ts (`isLoopbackHost`,
 * `endpointPlacement`) and interceptors/inspect-mcp/src/ullm-client.ts
 * (`endpointPlacement`); tests/stack/model-placement-parity.test.ts
 * pins the three to one table. Change them together. Pure.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */

export type ModelPlacement = "host" | "network";

/** Lowercase, strip IPv6 brackets and a trailing dot, unwrap `::ffff:a.b.c.d`
 *  (the URL parser prints it as `::ffff:7f00:1`). */
function normalizeHost(host: string): string {
  let h = host.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h.endsWith(".")) h = h.slice(0, -1);
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h);
  if (mapped) {
    const hi = parseInt(mapped[1]!, 16);
    const lo = parseInt(mapped[2]!, 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  const dotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(h);
  if (dotted) return dotted[1]!;
  return h;
}

/** Hosts that reach THIS machine's loopback listeners: `localhost` and any
 *  `*.localhost` (RFC 6761), 127.0.0.0/8, `::1`, and the unspecified
 *  addresses 0.0.0.0 and `::` (a Linux connect(2) delivers them locally). */
export function isLoopbackHost(host: string): boolean {
  const h = normalizeHost(host);
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "::1" || h === "::" || h === "0:0:0:0:0:0:0:1") return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m) return false;
  const o = m.slice(1).map(Number);
  return o.every((n) => n <= 255) && (o[0] === 127 || o.every((n) => n === 0));
}

/** The placement of an endpoint URL, or null when it does not parse as an
 *  http(s) URL with a host. */
export function endpointPlacement(url: string): ModelPlacement | null {
  let u: URL;
  try { u = new URL(url); } catch { return null; }
  if ((u.protocol !== "http:" && u.protocol !== "https:") || u.hostname === "") return null;
  return isLoopbackHost(u.hostname) ? "host" : "network";
}

/** Does this URL send in the clear to another machine (http, `network`)? */
export function isPlainHttpToNetwork(url: string): boolean {
  let u: URL;
  try { u = new URL(url); } catch { return false; }
  return u.protocol === "http:" && endpointPlacement(url) === "network";
}
