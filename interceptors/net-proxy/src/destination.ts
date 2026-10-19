/**
 * destination — the destination every release and binding decision of the
 * egress proxy is asked for: the host the proxy dials AND its port, always
 * stated (plan 10 §11.13.1, confidentiality.md §2.1, 2026-10-17).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 *
 * The binding rule (host-bindings.ts) lets a destination that names no port
 * match a binding with a port: the caller did not say. The proxy always
 * knows the port it dials, so it says it: the TLS-inspected leg and the
 * blind tunnel the CONNECT target's port, the plain-HTTP leg the URL's port
 * or its scheme's default (80, or 443 for an absolute-form `https://` URL).
 * Until 2026-10-17 the inspected leg and the tunnel stated the CONNECT host
 * alone and the plain leg dropped a default port, so a credential bound or
 * granted to `registry.example:8443` (or `[2001:db8::1]:8443`) was also put
 * back at port 443 of the same host. A binding with no port still admits
 * every port (unchanged).
 *
 * Pure.
 */
import { isIP } from "node:net";

/** `host:port`, an IPv6 address bracketed (`[2001:db8::1]:8443`). A host
 *  that already carries brackets keeps them. Pure. */
export function statedDestination(host: string, port: number): string {
  const h = !host.startsWith("[") && isIP(host) === 6 ? `[${host}]` : host;
  return `${h}:${port}`;
}

/** The stated destination of a plain-HTTP leg request: the absolute URL's
 *  host and its port, or the scheme's default (80; 443 for `https:`). The
 *  host as written when the URL does not parse (no port to add: the binding
 *  rule then judges the host as it always did). Pure. */
export function forwardDestination(dest: { host: string; absoluteUrl: string }): string {
  let u: URL;
  try {
    u = new URL(dest.absoluteUrl);
  } catch {
    return dest.host;
  }
  const port = u.port !== "" ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
  return statedDestination(u.hostname, port);
}
