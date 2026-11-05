/**
 * java-trust — let a JVM in the session use the egress proxy and trust its
 * certificate authority (docs/design/confidentiality/kube-wire-release.md §5).
 *
 * Mandu-new (no reference origin).
 *
 * Java reads no proxy or CA variable (plan 13 §10.2: bypass). It reads
 * `JAVA_TOOL_OPTIONS`, which every JVM picks up, so the session sets there:
 *
 *   - `-Djavax.net.ssl.trustStore=<file> -Djavax.net.ssl.trustStoreType=PKCS12`:
 *     a trust store holding the same certificates as the session's combined
 *     bundle (the system CAs and the session CA), written here at launch with
 *     no JVM start: a PKCS#12 file of certificate bags, each marked trusted
 *     for Java (Oracle's trusted-key-usage attribute), unencrypted and with
 *     no integrity MAC, which JDK 18+ (and 11.0.12+, 8u301+) loads with no
 *     password. An older JVM refuses the file and keeps refusing the proxy:
 *     a utility failure, nothing leaks (it only ever held placeholders);
 *   - `-Dhttps.proxyHost/-Dhttps.proxyPort` and `-Dhttp.proxyHost/-Dhttp.proxyPort`:
 *     the session proxy, with `-Dhttp.nonProxyHosts` from NO_PROXY.
 *
 * The user's own JAVA_TOOL_OPTIONS come after these, so a `-D` of theirs
 * (their own trust store) wins, as the other trust variables keep the user's
 * file (plan 13 §10.2). Every JVM prints `Picked up JAVA_TOOL_OPTIONS: …` to
 * stderr; `MANDU_JAVA_TRUST=0` leaves JAVA_TOOL_OPTIONS alone.
 */

/** PEM certificate blocks of a bundle, as DER. Non-certificate blocks are
 *  skipped. Pure. */
export function pemCertificates(bundle: string): Buffer[] {
  const out: Buffer[] = [];
  const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  for (const m of bundle.matchAll(re)) {
    const der = Buffer.from(m[1]!.replace(/\s+/g, ""), "base64");
    if (der.length > 0) out.push(der);
  }
  return out;
}

// ── DER ────────────────────────────────────────────────────────────────────

function len(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), len(content.length), content]);
}

const seq = (...parts: Buffer[]): Buffer => tlv(0x30, Buffer.concat(parts));
const set = (...parts: Buffer[]): Buffer => tlv(0x31, Buffer.concat(parts));
const octets = (b: Buffer): Buffer => tlv(0x04, b);
const explicit0 = (b: Buffer): Buffer => tlv(0xa0, b);

function oid(dotted: string): Buffer {
  const arcs = dotted.split(".").map(Number);
  const body: number[] = [40 * arcs[0]! + arcs[1]!];
  for (const arc of arcs.slice(2)) {
    const chunk: number[] = [];
    let v = arc;
    do { chunk.unshift(v & 0x7f); v = Math.floor(v / 128); } while (v > 0);
    for (let i = 0; i < chunk.length - 1; i++) chunk[i] = chunk[i]! | 0x80;
    body.push(...chunk);
  }
  return tlv(0x06, Buffer.from(body));
}

function bmpString(s: string): Buffer {
  const b = Buffer.alloc(s.length * 2);
  for (let i = 0; i < s.length; i++) b.writeUInt16BE(s.charCodeAt(i), i * 2);
  return tlv(0x1e, b);
}

const OID_DATA = "1.2.840.113549.1.7.1";
const OID_CERT_BAG = "1.2.840.113549.1.12.10.1.3";
const OID_X509_CERT = "1.2.840.113549.1.9.22.1";
const OID_FRIENDLY_NAME = "1.2.840.113549.1.9.20";
/** Oracle's "trusted key usage" bag attribute: what makes Java read a
 *  certificate bag as a trusted certificate entry. */
const OID_ORACLE_TRUSTED_KEY_USAGE = "2.16.840.1.113894.746875.1.1";
const OID_ANY_EXTENDED_KEY_USAGE = "2.5.29.37.0";

/**
 * A PKCS#12 trust store of `certs` (DER), each a trusted certificate entry
 * for Java under the alias `mandu-<n>`: certificate bags in one unencrypted
 * data ContentInfo, no MAC (RFC 7292 §4; password-less, JDK 18+). Pure.
 */
export function javaTrustStore(certs: readonly Buffer[]): Buffer {
  const bags = certs.map((der, i) => seq(
    oid(OID_CERT_BAG),
    explicit0(seq(oid(OID_X509_CERT), explicit0(octets(der)))),
    set(
      seq(oid(OID_FRIENDLY_NAME), set(bmpString(`mandu-${i + 1}`))),
      seq(oid(OID_ORACLE_TRUSTED_KEY_USAGE), set(oid(OID_ANY_EXTENDED_KEY_USAGE))),
    ),
  ));
  const safeContents = seq(...bags);
  const authSafe = seq(seq(oid(OID_DATA), explicit0(octets(safeContents))));
  return seq(tlv(0x02, Buffer.from([3])), seq(oid(OID_DATA), explicit0(octets(authSafe))));
}

// ── JAVA_TOOL_OPTIONS ──────────────────────────────────────────────────────

/** NO_PROXY as Java's `http.nonProxyHosts` (`|`-separated, `*` wildcards): a
 *  `.suffix` or `*.suffix` entry becomes `*.suffix`, a bare name stays (and
 *  its subdomains are added, as curl reads it), a port is dropped, `*` alone
 *  is kept; loopback is always there. Pure. */
export function javaNonProxyHosts(noProxy: string): string {
  const out: string[] = [];
  const add = (h: string): void => { if (h !== "" && !out.includes(h)) out.push(h); };
  for (const raw of noProxy.split(",")) {
    let h = raw.trim().toLowerCase();
    if (h === "") continue;
    if (h === "*") { add("*"); continue; }
    // A bare IPv6 address (two colons or more) is bracketed, as Java writes
    // one; a port is dropped from a name or a bracketed address.
    if (!h.startsWith("[") && (h.match(/:/g) ?? []).length > 1) { add(`[${h}]`); continue; }
    h = h.replace(/:\d+$/, "");
    if (h.startsWith("*.")) { add(h); continue; }
    if (h.startsWith(".")) { add(`*${h}`); continue; }
    add(h);
    if (!/^[\d.]+$/.test(h) && !h.startsWith("[") && !h.includes("/")) add(`*.${h}`);
  }
  for (const h of ["localhost", "127.*", "[::1]"]) add(h);
  return out.join("|");
}

/** A value for `-D…=` that a JVM's option tokenizer keeps whole: no
 *  whitespace or quote in it (null otherwise). */
function plainValue(v: string): string | null {
  return /^[^\s"']+$/.test(v) ? v : null;
}

/**
 * The session's JAVA_TOOL_OPTIONS: the trust store and the proxy, then the
 * user's own options (whose `-D` wins). Null when a value would need quoting
 * (a path with a space: the JVM's tokenizer would split it). Pure.
 */
export function javaToolOptions(args: {
  trustStore: string;
  proxy: { host: string; port: number };
  noProxy: string;
  user?: string;
}): string | null {
  const store = plainValue(args.trustStore);
  const nonProxy = plainValue(javaNonProxyHosts(args.noProxy));
  if (store === null || nonProxy === null) return null;
  const host = args.proxy.host;
  const own = [
    `-Djavax.net.ssl.trustStore=${store}`,
    "-Djavax.net.ssl.trustStoreType=PKCS12",
    `-Dhttps.proxyHost=${host}`, `-Dhttps.proxyPort=${args.proxy.port}`,
    `-Dhttp.proxyHost=${host}`, `-Dhttp.proxyPort=${args.proxy.port}`,
    `-Dhttp.nonProxyHosts=${nonProxy}`,
  ];
  const user = (args.user ?? "").trim();
  return user === "" ? own.join(" ") : `${own.join(" ")} ${user}`;
}
