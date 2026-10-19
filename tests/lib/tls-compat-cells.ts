/**
 * tls-compat-cells — the pure half of the TLS-inspection compatibility matrix
 * (tests/env/tls-compat.test.ts; docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md §10.2).
 *
 * Some cells depend on how the client was built or which version is
 * installed, not on Mandu: the matrix derives those expectations here, from
 * the client's own `--version` text, instead of hard-coding one host's
 * answer. No I/O; unit-tested in tests/stack/tls-compat-cells.test.ts.
 */
import { nodeHonorsEnvProxy, type NodeProxyApi } from "../../launcher/src/node-floor.js";

/** SERVED: through the inspecting proxy, trusted the session CA. BYPASS: never
 *  used the proxy. REFUSED: reached the proxy, rejected its certificate. */
export type Cell = "SERVED" | "BYPASS" | "REFUSED";

/**
 * Does a Node of this version route `api` through HTTPS_PROXY when
 * NODE_USE_ENV_PROXY=1 (fetch from v24.0.0 / v22.21.0, http/https from
 * v24.5.0 / v22.21.0; 23.x never)? ONE copy, the launcher's, which `mandu
 * doctor` and the launch notice use too (launcher/src/node-floor.ts), so the
 * matrix and the warning cannot disagree.
 */
export { nodeHonorsEnvProxy, parseNodeVersion, type NodeProxyApi } from "../../launcher/src/node-floor.js";

/** The cell a Node `api` request lands in under the launcher's variables:
 *  SERVED when this Node honours NODE_USE_ENV_PROXY for it, else BYPASS (it
 *  goes around the proxy; NODE_EXTRA_CA_CERTS is moot then). */
export function nodeEnvProxyCell(version: string, api: NodeProxyApi): Cell {
  return nodeHonorsEnvProxy(version, api) ? "SERVED" : "BYPASS";
}

/** The TLS library a client was built with, as far as SSL_CERT_FILE goes. */
export type TlsBackend = "openssl" | "gnutls";

/** wget's TLS library from `wget --version` (its feature line names
 *  `+ssl/openssl` or `+ssl/gnutls`); null when it names neither. */
export function wgetTlsBackend(versionText: string): TlsBackend | null {
  if (/\+ssl\/openssl\b/i.test(versionText)) return "openssl";
  if (/\+ssl\/gnutls\b/i.test(versionText)) return "gnutls";
  return null;
}

/** What `wget` does with SSL_CERT_FILE: an OpenSSL build loads OpenSSL's
 *  default verify paths, which read it (SERVED); a GnuTLS build (Ubuntu
 *  26.04's) reads the system store only and rejects the session CA (REFUSED,
 *  via `tls_rejected`). Unknown build ⇒ null (the caller declares the row
 *  build-dependent). */
export function wgetCell(versionText: string): Cell | null {
  const b = wgetTlsBackend(versionText);
  return b === "openssl" ? "SERVED" : b === "gnutls" ? "REFUSED" : null;
}

/** cargo's libcurl from `cargo -vV`, e.g.
 *  `libcurl: 8.4.0-DEV (sys:0.4.68+curl-8.4.0 vendored ssl:OpenSSL/1.1.1u)`
 *  (rustup's build: a vendored libcurl over OpenSSL) or a distro build
 *  linked to the system libcurl (`system ssl:GnuTLS/…`). */
export function cargoLibcurl(vV: string): { vendored: boolean; backend: TlsBackend | null } | null {
  const line = /^libcurl:.*$/m.exec(vV)?.[0];
  if (!line) return null;
  const backend = /ssl:OpenSSL/i.test(line) ? "openssl" : /ssl:GnuTLS/i.test(line) ? "gnutls" : null;
  return { vendored: /\bvendored\b/.test(line), backend };
}

/** The cell `cargo` lands in WITHOUT CARGO_HTTP_CAINFO (only SSL_CERT_FILE
 *  points at the session CA). A vendored libcurl over OpenSSL (rustup's) has
 *  no compiled-in CA file, so OpenSSL's default verify paths, which read
 *  SSL_CERT_FILE, apply: SERVED. A GnuTLS libcurl ignores the variable:
 *  REFUSED. A system OpenSSL libcurl usually has a compiled-in CA bundle,
 *  which wins over SSL_CERT_FILE, but that is the distro's build choice:
 *  null (build-dependent), as for anything `cargo -vV` does not name. */
export function cargoNoCainfoCell(vV: string): Cell | null {
  const c = cargoLibcurl(vV);
  if (!c) return null;
  if (c.backend === "gnutls") return "REFUSED";
  if (c.backend === "openssl" && c.vendored) return "SERVED";
  return null;
}

/** The cell a client's request landed in, from the proxy events it caused:
 *  any `forwarded` ⇒ SERVED; other events ⇒ REFUSED; none ⇒ BYPASS. */
export function cellOf(actions: readonly string[]): Cell {
  return actions.includes("forwarded") ? "SERVED" : actions.length > 0 ? "REFUSED" : "BYPASS";
}

/** Did the request fail only in transport (the proxy could not reach the
 *  upstream: every event is `forward_error`)? That says nothing about the
 *  client's cell, so the matrix retries such a row once. */
export function transportOnly(actions: readonly string[]): boolean {
  return actions.length > 0 && actions.every((a) => a === "forward_error");
}
