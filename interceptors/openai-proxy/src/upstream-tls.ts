/**
 * upstream-tls — `MANDU_UPSTREAM_TLS` (set by the launcher when the session's
 * main model is a declared `models:` entry with `tls:` or a `perimeter`,
 * confidentiality plan 12 D3 and D4) into the proxy's `upstreamTls` option.
 * The value is the entry's compiled `tls` as JSON (absolute paths and pins),
 * plus `perimeter` (CIDRs) when the arbiter attached one; the connection then
 * goes only to an address inside those networks. This process runs outside the
 * agent's world, so it reads the files itself, the client key included.
 * Fail-closed: a value that does not parse, or a file that cannot be used,
 * THROWS, and the proxy does not start (the launch then refuses), rather than
 * dialing the model without the checks. Unset or empty: no option.
 */
import { asTlsConfig, hasTlsConfig, loadTlsMaterial, type TlsMaterial } from "./endpoint-tls.js";

export function upstreamTlsFromEnv(raw: string | undefined, read?: (p: string) => string): { upstreamTls?: TlsMaterial } {
  if (raw === undefined || raw.trim() === "") return {};
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error("MANDU_UPSTREAM_TLS is not JSON; refusing to reach the main model without its tls checks"); }
  const cfg = asTlsConfig(parsed);
  if (cfg === null) throw new Error("MANDU_UPSTREAM_TLS is not a tls setting this proxy can read; refusing to reach the main model without its tls checks");
  if (!hasTlsConfig(cfg)) return {};
  return { upstreamTls: loadTlsMaterial(cfg, read ? { read } : {}) };
}
