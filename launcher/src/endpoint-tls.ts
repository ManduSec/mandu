/**
 * endpoint-tls — how Mandu checks a declared model endpoint's identity when it
 * dials it: policy.yaml `models[].tls`
 * (docs/design/confidentiality/model-endpoints.md §2 D3).
 *
 *   - `ca_file`     added to Node's bundled roots for THIS endpoint's
 *                   connections only (never to the process's store);
 *   - `pin_sha256`  after the chain and the host name verify, at least one
 *                   certificate in the chain must carry one of the pinned
 *                   SubjectPublicKeyInfo hashes (base64 SHA-256, the HPKP
 *                   format), or the connection is refused;
 *   - `client_cert` / `client_key`  presented to a server that asks;
 *   - `perimeter`   policy.yaml `perimeter.networks` (plan 12 D4), for a
 *                   `local: true` endpoint on another machine: the name is
 *                   resolved ONCE, every address must be inside one of the
 *                   networks, and the connection goes to a checked address
 *                   with the original name kept for SNI and the host-name
 *                   check (no second lookup for a rebinding answer to race).
 *                   Not a TLS setting, but a check made at the same moment,
 *                   so it lives here and also covers a plain http endpoint.
 * A refusal happens in the lookup or the handshake, before a byte of the
 * request is sent.
 *
 * ONE MODULE, FIVE COPIES. The packages that dial an endpoint ship standalone
 * and cannot import each other, so this file is copied VERBATIM to
 *   interceptors/inspect-mcp/src/endpoint-tls.ts      (the helper)
 *   interceptors/anthropic-proxy/src/endpoint-tls.ts  (a declared main model)
 *   interceptors/openai-proxy/src/endpoint-tls.ts     (a declared Codex main model)
 *   launcher/src/endpoint-tls.ts                      (mandu doctor)
 *   dashboard/src/endpoint-tls.ts                     (Settings › Test connection)
 * and tests/stack/endpoint-tls-parity.test.ts fails unless the
 * five are byte-identical. Change the copy in inspect-mcp and copy it out.
 *
 * Node built-ins only. PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
import { createHash } from "node:crypto";
import * as dns from "node:dns";
import { readFileSync } from "node:fs";
import * as http from "node:http";
import * as https from "node:https";
import { BlockList, isIP } from "node:net";
import * as tls from "node:tls";

/** The compiled `tls` of a `models:` entry, as the arbiter serves it. */
export interface EndpointTlsConfig {
  caFile?: string;
  pinSha256?: readonly string[];
  clientCert?: string;
  clientKey?: string;
  /** The endpoint's `perimeter` (CIDRs), when the arbiter attached one. */
  perimeter?: readonly string[];
}

/** The bytes the checks use, read once per client. */
export interface TlsMaterial {
  ca?: string;
  pins?: readonly string[];
  cert?: string;
  key?: string;
  perimeter?: readonly string[];
}

/** Does the config ask for anything? */
export function hasTlsConfig(c: EndpointTlsConfig | undefined | null): c is EndpointTlsConfig {
  return !!c && (!!c.caFile || (c.pinSha256?.length ?? 0) > 0 || !!c.clientCert || !!c.clientKey || (c.perimeter?.length ?? 0) > 0);
}

/** Does the material check the server's identity (anything TLS-only)? */
export function hasIdentityChecks(m: TlsMaterial): boolean {
  return !!m.ca || (m.pins?.length ?? 0) > 0 || !!m.cert || !!m.key;
}

/** `a.b.c.d/n`, `x::/n`, or a bare address: [address, prefix, family] or null. */
function parseCidr(s: unknown): [string, number, "ipv4" | "ipv6"] | null {
  if (typeof s !== "string") return null;
  const m = /^([^/\s]+)(?:\/(\d{1,3}))?$/.exec(s.trim());
  if (!m) return null;
  const address = m[1]!.replace(/^\[|\]$/g, "");
  const v = isIP(address);
  if (v === 0) return null;
  const max = v === 4 ? 32 : 128;
  const prefix = m[2] === undefined ? max : Number(m[2]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > max) return null;
  return [address, prefix, v === 4 ? "ipv4" : "ipv6"];
}

/** An IPv4-mapped IPv6 address (`::ffff:10.0.0.1`) as its IPv4 form. */
function unmapAddress(address: string): string {
  const a = address.toLowerCase().replace(/^\[|\]$/g, "");
  const dotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  if (dotted) return dotted[1]!;
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(a);
  if (hex) {
    const hi = parseInt(hex[1]!, 16);
    const lo = parseInt(hex[2]!, 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return a;
}

/** Is this address inside one of the networks? A malformed one is not. */
export function inNetworks(address: string, networks: readonly string[]): boolean {
  const a = unmapAddress(address);
  const v = isIP(a);
  if (v === 0) return false;
  const bl = new BlockList();
  for (const n of networks) {
    const c = parseCidr(n);
    if (c) bl.addSubnet(c[0], c[1], c[2]);
  }
  return bl.check(a, v === 4 ? "ipv4" : "ipv6");
}

/** The refusal for an address outside the perimeter (or no address at all). */
export class PerimeterError extends Error {
  readonly code = "MANDU_OUTSIDE_PERIMETER";
  constructor(readonly host: string, readonly address: string | null) {
    super(address === null
      ? `${host} resolves to no address, so it cannot be checked against perimeter.networks`
      : address === host
        ? `${host} is outside perimeter.networks`
        : `${host} resolves to ${address}, outside perimeter.networks`);
    this.name = "PerimeterError";
  }
}

type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void;
/** The shape of `dns.lookup` this module calls (injectable in tests). */
export type BaseLookup = (hostname: string, options: dns.LookupAllOptions, callback: (err: NodeJS.ErrnoException | null, addresses: dns.LookupAddress[]) => void) => void;

const systemLookupAll: BaseLookup = (hostname, options, callback) => dns.lookup(hostname, options, callback);

/**
 * A `lookup` for net/tls/http connections that holds them to the networks:
 * one resolution, every address checked (all families, whatever the caller
 * asked for), then the caller's answer drawn from the checked list. An
 * address outside, or an empty answer, is a {@link PerimeterError} and no
 * connection is made. Node skips `lookup` for a literal address: check
 * those with {@link checkLiteralHost}.
 */
export function perimeterLookup(networks: readonly string[], base: BaseLookup = systemLookupAll) {
  return (hostname: string, options: dns.LookupOptions | number | undefined, callback: LookupCallback): void => {
    const opts: dns.LookupOptions = typeof options === "number" ? { family: options } : (options ?? {});
    base(hostname, { all: true }, (err, list) => {
      if (err) { callback(err, ""); return; }
      const outside = list.find((a) => !inNetworks(a.address, networks));
      if (list.length === 0 || outside) { callback(new PerimeterError(hostname, outside?.address ?? null), ""); return; }
      const fam = opts.family === 4 || opts.family === "IPv4" ? 4 : opts.family === 6 || opts.family === "IPv6" ? 6 : 0;
      const usable = fam === 0 ? list : list.filter((a) => a.family === fam);
      if (usable.length === 0) { callback(Object.assign(new Error(`${hostname} has no IPv${fam} address`), { code: "ENOTFOUND" }), ""); return; }
      if (opts.all) callback(null, usable);
      else callback(null, usable[0]!.address, usable[0]!.family);
    });
  };
}

/** A literal-address host against the networks (Node never looks one up).
 *  A name returns null: the lookup checks it. */
export function checkLiteralHost(host: string, networks: readonly string[] | undefined): PerimeterError | null {
  if (!networks || networks.length === 0) return null;
  const bare = host.replace(/^\[|\]$/g, "");
  if (isIP(unmapAddress(bare)) === 0) return null;
  return inNetworks(bare, networks) ? null : new PerimeterError(bare, bare);
}

/** Resolve a host and check it (the launch check, doctor, Test connection):
 *  the addresses, or the refusal. Never throws. */
export function checkHostInPerimeter(host: string, networks: readonly string[], base: BaseLookup = systemLookupAll): Promise<{ ok: true; addresses: string[] } | { ok: false; reason: string; address: string | null }> {
  const lit = checkLiteralHost(host, networks);
  if (lit) return Promise.resolve({ ok: false, reason: lit.message, address: lit.address });
  const bare = host.replace(/^\[|\]$/g, "");
  if (isIP(unmapAddress(bare)) !== 0) return Promise.resolve({ ok: true, addresses: [bare] });
  return new Promise((resolve) => {
    perimeterLookup(networks, base)(bare, { all: true }, (err, list) => {
      if (err) {
        const e = err as { address?: string | null; message?: string };
        resolve({ ok: false, reason: err instanceof PerimeterError ? err.message : `${bare} does not resolve (${e.message ?? err})`, address: err instanceof PerimeterError ? err.address : null });
      } else resolve({ ok: true, addresses: (list as dns.LookupAddress[]).map((a) => a.address) });
    });
  });
}

/** Accept one `tls` object from the wire, or null (strict: the paths feed
 *  file reads and the pins a security check). */
export function asTlsConfig(x: unknown): EndpointTlsConfig | null {
  if (x === null || typeof x !== "object" || Array.isArray(x)) return null;
  const r = x as Record<string, unknown>;
  const out: EndpointTlsConfig = {};
  for (const k of ["caFile", "clientCert", "clientKey"] as const) {
    if (r[k] === undefined) continue;
    if (typeof r[k] !== "string" || !(r[k] as string).startsWith("/")) return null;
    out[k] = r[k] as string;
  }
  if (r["pinSha256"] !== undefined) {
    const pins = r["pinSha256"];
    if (!Array.isArray(pins) || pins.length === 0 || !pins.every((p) => typeof p === "string" && /^[A-Za-z0-9+/]{43}=$/.test(p))) return null;
    out.pinSha256 = [...(pins as string[])];
  }
  if (r["perimeter"] !== undefined) {
    const nets = r["perimeter"];
    if (!Array.isArray(nets) || nets.length === 0 || !nets.every((n) => parseCidr(n) !== null)) return null;
    out.perimeter = [...(nets as string[])];
  }
  if ((out.clientCert === undefined) !== (out.clientKey === undefined)) return null;
  return out;
}

/**
 * Read the files a config names. `keyPem` stands in for reading `clientKey`
 * (the helper runs where the key file is masked, so the launcher hands it the
 * key's bytes). Throws, naming the field, when a file cannot be read or a
 * key is not a PEM private key: the caller refuses the endpoint.
 */
export function loadTlsMaterial(
  c: EndpointTlsConfig,
  opts: { keyPem?: string; read?: (p: string) => string } = {},
): TlsMaterial {
  const read = opts.read ?? ((p: string) => readFileSync(p, "utf8"));
  const file = (field: string, p: string): string => {
    try { return read(p); } catch { throw new Error(`tls.${field}: cannot read ${p}`); }
  };
  const out: TlsMaterial = {};
  if (c.caFile) out.ca = file("ca_file", c.caFile);
  if (c.pinSha256 && c.pinSha256.length > 0) out.pins = [...c.pinSha256];
  if (c.perimeter && c.perimeter.length > 0) out.perimeter = [...c.perimeter];
  if (c.clientCert && c.clientKey) {
    out.cert = file("client_cert", c.clientCert);
    const key = opts.keyPem ?? file("client_key", c.clientKey);
    if (!/-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/.test(key)) {
      throw new Error("tls.client_key: the key's bytes are not a PEM private key here");
    }
    out.key = key;
  }
  return out;
}

/** base64 SHA-256 of a DER SubjectPublicKeyInfo: the pin format. */
export function spkiSha256(der: Buffer): string {
  return createHash("sha256").update(der).digest("base64");
}

/** The pin of every certificate in a peer's chain, leaf first. */
export function chainPins(cert: tls.PeerCertificate): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  let c: tls.DetailedPeerCertificate | undefined = cert as tls.DetailedPeerCertificate;
  while (c && c.pubkey && !seen.has(c.fingerprint256)) {
    seen.add(c.fingerprint256);
    out.push(spkiSha256(c.pubkey));
    c = c.issuerCertificate;
  }
  return out;
}

/** The TLS error for a chain that verified but carries no pinned key. */
export class PinMismatchError extends Error {
  readonly code = "MANDU_PIN_MISMATCH";
  constructor() {
    super("the server's key is not one of the pinned keys (tls.pin_sha256)");
    this.name = "PinMismatchError";
  }
}

/** checkServerIdentity: Node's host-name check first, then the pins. */
export function makeCheckServerIdentity(pins?: readonly string[]): (host: string, cert: tls.PeerCertificate) => Error | undefined {
  return (host, cert) => {
    const err = tls.checkServerIdentity(host, cert);
    if (err) return err;
    if (pins && pins.length > 0 && !chainPins(cert).some((p) => pins.includes(p))) return new PinMismatchError();
    return undefined;
  };
}

/** Options for tls.connect / https.request / an https.Agent. With a
 *  perimeter, a `lookup` that checks every address (a literal-address host
 *  is not looked up: {@link checkLiteralHost}). */
export function tlsOptions(m: TlsMaterial, base?: BaseLookup): tls.ConnectionOptions {
  return {
    ...(m.ca ? { ca: [...tls.rootCertificates, m.ca] } : {}),
    ...(m.cert && m.key ? { cert: m.cert, key: m.key } : {}),
    checkServerIdentity: makeCheckServerIdentity(m.pins),
    ...(m.perimeter && m.perimeter.length > 0 ? { lookup: perimeterLookup(m.perimeter, base) as unknown as tls.ConnectionOptions["lookup"] } : {}),
  };
}

/** A refusal in words (no response body, no certificate dump). */
export function tlsFailureWords(err: unknown): string {
  const e = err as { code?: string; message?: string } | null;
  const code = e?.code ?? "";
  const msg = String(e?.message ?? err ?? "");
  if (code === "MANDU_PIN_MISMATCH") return "the server's key is not one of the pinned keys (tls.pin_sha256)";
  if (code === "MANDU_OUTSIDE_PERIMETER") return msg;
  if (code === "ERR_TLS_CERT_ALTNAME_INVALID") return "the server's certificate does not name this host";
  if (code === "CERT_HAS_EXPIRED") return "the server's certificate has expired";
  if (/UNABLE_TO_VERIFY|SELF_SIGNED|UNABLE_TO_GET_ISSUER/.test(code)) {
    return "the server's certificate is not trusted (add your organization's CA as tls.ca_file)";
  }
  if (/certificate required|CERTIFICATE_REQUIRED|alert number 116/i.test(`${code} ${msg}`) ||
      /handshake failure|alert number 40/i.test(msg)) {
    return "the server refused the connection during the handshake (does it require a client certificate? tls.client_cert)";
  }
  return `TLS failed (${code || msg.split("\n")[0] || "unknown error"})`;
}

type FetchInit = { method?: string; headers?: Record<string, string> | Headers; body?: string; signal?: AbortSignal | null };

/**
 * A `fetch` over node:https with the endpoint's checks, for a client that
 * takes an injectable fetch (the helper's two wires). Its own agent, so the
 * checks run on every connection it makes and the process's proxy variables
 * are not consulted (a declared local model is dialed directly, never through
 * the egress proxy). https, or plain http when the material holds only a
 * perimeter (an `allow_plain_http` entry).
 */
export function tlsFetch(m: TlsMaterial, base?: BaseLookup): typeof fetch {
  const agent = new https.Agent({ keepAlive: false, ...tlsOptions(m, base) } as https.AgentOptions);
  const plain = new http.Agent({ keepAlive: false, ...(m.perimeter && m.perimeter.length > 0 ? { lookup: perimeterLookup(m.perimeter, base) } : {}) } as http.AgentOptions);
  const f = (input: string | URL | Request, init: FetchInit = {}): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && !hasIdentityChecks(m))) {
      return Promise.reject(new Error(`tls: ${url.protocol} is not https`));
    }
    const outside = checkLiteralHost(url.hostname, m.perimeter);
    if (outside) return Promise.reject(outside);
    const mod = url.protocol === "https:" ? https : http;
    const headers: Record<string, string> = {};
    if (init.headers instanceof Headers) init.headers.forEach((v, k) => { headers[k] = v; });
    else if (init.headers) Object.assign(headers, init.headers);
    return new Promise<Response>((resolve, reject) => {
      const req = mod.request(url, { method: init.method ?? "GET", headers, agent: url.protocol === "https:" ? agent : plain, ...(init.signal ? { signal: init.signal } : {}) }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("error", reject);
        res.on("end", () => {
          const h = new Headers();
          for (const [k, v] of Object.entries(res.headers)) {
            if (v === undefined) continue;
            h.set(k, Array.isArray(v) ? v.join(", ") : v);
          }
          const status = res.statusCode ?? 502;
          const bodyless = status === 204 || status === 304 || (status >= 100 && status < 200);
          resolve(new Response(bodyless ? null : Buffer.concat(chunks), { status, statusText: res.statusMessage ?? "", headers: h }));
        });
      });
      req.on("error", reject);
      if (init.body !== undefined) req.write(init.body);
      req.end();
    });
  };
  return f as unknown as typeof fetch;
}

/** One TLS handshake with the checks (doctor and the dashboard probe):
 *  ok, or the reason in words. Never throws. Under TLS 1.3 the client's side
 *  of the handshake completes before the server has checked a client
 *  certificate, so a refusal for a missing one arrives just after; the probe
 *  waits a moment (`settleMs`) after the handshake for it. */
export function probeTls(host: string, port: number, m: TlsMaterial, timeoutMs = 3000, settleMs = 300, base?: BaseLookup): Promise<{ ok: true } | { ok: false; reason: string }> {
  const outside = checkLiteralHost(host, m.perimeter);
  if (outside) return Promise.resolve({ ok: false, reason: outside.message });
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: { ok: true } | { ok: false; reason: string }): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(v);
    };
    const bare = host.replace(/^\[|\]$/g, "");
    const socket = tls.connect({ host: bare, port, ...(/^[\d.]+$|:/.test(bare) ? {} : { servername: bare }), ...tlsOptions(m, base) }, () => {
      const settle = setTimeout(() => finish({ ok: true }), settleMs);
      settle.unref?.();
    });
    socket.on("close", () => finish({ ok: false, reason: "the server closed the connection during the handshake (does it require a client certificate? tls.client_cert)" }));
    socket.on("error", (e) => finish({ ok: false, reason: tlsFailureWords(e) }));
    const timer = setTimeout(() => finish({ ok: false, reason: "no TLS answer in time" }), timeoutMs);
    timer.unref?.();
  });
}
