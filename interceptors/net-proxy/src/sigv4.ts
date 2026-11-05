/**
 * sigv4 — AWS Signature Version 4 for the egress proxy's re-signing release
 * (docs/design/confidentiality/aws-sigv4-resign.md).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference
 * origin). The algorithm is AWS's published one ("Create a signed AWS API
 * request", the SigV4 test suite); the canonical forms below are the ones
 * the SDKs build (botocore, the JavaScript SDK v3), checked against
 * botocore-made signatures in test/unit/sigv4.test.ts.
 *
 * In the agent's world `aws` and the SDKs sign with the PLACEHOLDER of the
 * secret access key (the masked `~/.aws/credentials`, or a masked
 * `AWS_SECRET_ACCESS_KEY`). The proxy
 *
 *   1. finds which placeholder signed the request, by recomputing the
 *      signature with each signing-key placeholder the arbiter lists
 *      (`matchSignature`): a match is proof the request was signed by that
 *      placeholder, over exactly these bytes;
 *   2. has the gate decide that placeholder like any other (position
 *      `signature`: the value is a key the proxy signs with, never a byte of
 *      the request);
 *   3. signs the request it forwards (the released access key id and
 *      session token in place) with the real key, in the same canonical form
 *      that matched (`resignedAuthorization`), so AWS reads it as the SDK
 *      meant it.
 *
 * The real key never enters the request: only an HMAC made with it does.
 *
 * Pure (node:crypto only).
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

/** The one algorithm the release signs with. SigV4a (`AWS4-ECDSA-P256-SHA256`)
 *  is refused (open, aws-sigv4-resign.md §6). */
export const SIGV4_ALGORITHM = "AWS4-HMAC-SHA256";

/** A parsed SigV4 `Authorization` header value. */
export interface SigV4Authorization {
  algorithm: string;
  /** The access key id as written (a placeholder in the agent's world). */
  accessKey: string;
  /** `YYYYMMDD`, region, service: the credential scope. */
  date: string;
  region: string;
  service: string;
  /** Lowercase, in the order written. */
  signedHeaders: string[];
  /** Lowercase hex. */
  signature: string;
}

const AUTH_RE = /^\s*(AWS4-[A-Z0-9-]+)\s+(.*)$/;

/**
 * Parse `AWS4-HMAC-SHA256 Credential=<id>/<date>/<region>/<service>/aws4_request,
 * SignedHeaders=a;b, Signature=<hex>`. The scope is the last four `/`
 * pieces of the Credential; what comes before them is the access key id.
 * Null for anything else. Pure.
 */
export function parseSigV4Authorization(value: string): SigV4Authorization | null {
  const m = AUTH_RE.exec(value);
  if (!m) return null;
  const fields = new Map<string, string>();
  for (const part of m[2]!.split(",")) {
    const eq = part.indexOf("=");
    if (eq < 0) return null;
    const k = part.slice(0, eq).trim();
    if (fields.has(k)) return null;
    fields.set(k, part.slice(eq + 1).trim());
  }
  const cred = fields.get("Credential");
  const signed = fields.get("SignedHeaders");
  const sig = fields.get("Signature");
  if (cred === undefined || signed === undefined || sig === undefined || fields.size !== 3) return null;
  const pieces = cred.split("/");
  if (pieces.length < 5 || pieces[pieces.length - 1] !== "aws4_request") return null;
  const [date, region, service] = pieces.slice(-4, -1) as [string, string, string];
  const accessKey = pieces.slice(0, -4).join("/");
  if (accessKey === "" || !/^\d{8}$/.test(date) || region === "" || service === "") return null;
  if (!/^[0-9a-f]{64}$/i.test(sig)) return null;
  const signedHeaders = signed.split(";").map((h) => h.trim().toLowerCase());
  if (signedHeaders.some((h) => h === "")) return null;
  return { algorithm: m[1]!, accessKey, date, region, service, signedHeaders, signature: sig.toLowerCase() };
}

/** Every value of header `name` (any case), in the order sent. */
function headerValues(headers: Record<string, string | string[] | undefined>, name: string): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(headers)) {
    if (v == null || k.toLowerCase() !== name) continue;
    for (const one of Array.isArray(v) ? v : [v]) out.push(one);
  }
  return out;
}

/** The request's ONE `Authorization` header when it is SigV4-shaped
 *  (`AWS4-…`), else null; two Authorization headers are `ambiguous`. */
export function sigv4AuthorizationOf(
  headers: Record<string, string | string[] | undefined>,
): { raw: string; parsed: SigV4Authorization | null } | "ambiguous" | null {
  const values = headerValues(headers, "authorization");
  const aws = values.filter((v) => /^\s*AWS4-/i.test(v));
  if (aws.length === 0) return null;
  if (values.length !== 1) return "ambiguous";
  return { raw: values[0]!, parsed: parseSigV4Authorization(values[0]!) };
}

/** The request as SigV4 reads it. */
export interface SigV4Request {
  method: string;
  /** Absolute (`https://host/p?q`) or origin form (`/p?q`), as sent. */
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  /** The Host value to sign with (the one sent upstream); absent → the
   *  request's own Host header. */
  host?: string;
}

/** The URL's path and query exactly as written (no decoding, no URL parser:
 *  it would normalize what the SDK signed). */
export function rawPathAndQuery(url: string): { path: string; query: string } {
  let rest = url;
  const scheme = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i.exec(rest);
  if (scheme) rest = rest.slice(scheme[0].length);
  const hash = rest.indexOf("#");
  if (hash >= 0) rest = rest.slice(0, hash);
  const q = rest.indexOf("?");
  const path = q >= 0 ? rest.slice(0, q) : rest;
  return { path: path === "" ? "/" : path, query: q >= 0 ? rest.slice(q + 1) : "" };
}

/** How an SDK wrote the canonical URI and query string. AWS's own reading of
 *  them is the service's; the SDK's is what its signature covers, so the
 *  proxy re-signs in the form that matched. */
export interface CanonicalForm {
  /** `raw`: the path as sent (S3); `encoded`: each byte outside
   *  `A-Za-z0-9-_.~/` percent-encoded again (the double encoding of the
   *  other services); `normalized`: dot segments and empty segments
   *  removed first (botocore, the JavaScript SDK). */
  uri: "raw" | "encoded" | "normalized";
  /** `raw`: the pairs as written, sorted, each `k=v` (botocore); `strict`:
   *  decoded and encoded again by RFC 3986 (the JavaScript SDK, the spec). */
  query: "raw" | "strict";
}

/** The forms tried, the most common first. */
export const CANONICAL_FORMS: readonly CanonicalForm[] = [
  { uri: "normalized", query: "raw" },
  { uri: "raw", query: "raw" },
  { uri: "normalized", query: "strict" },
  { uri: "raw", query: "strict" },
  { uri: "encoded", query: "raw" },
  { uri: "encoded", query: "strict" },
];

/** Percent-encode every byte outside RFC 3986's unreserved set (and `/` when
 *  `keepSlash`), upper-case hex. Pure. */
export function awsUriEncode(text: string, keepSlash: boolean): string {
  let out = "";
  for (const byte of Buffer.from(text, "utf8")) {
    const c = String.fromCharCode(byte);
    if (/[A-Za-z0-9\-_.~]/.test(c) || (keepSlash && c === "/")) out += c;
    else out += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

/** botocore's `remove_dot_segments`: `.` and empty segments dropped, `..`
 *  pops, the leading and trailing slash kept. */
function removeDotSegments(path: string): string {
  if (path === "") return "";
  const out: string[] = [];
  for (const seg of path.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") out.pop();
    else out.push(seg);
  }
  const first = path.startsWith("/") ? "/" : "";
  const last = path.endsWith("/") && out.length > 0 ? "/" : "";
  return first + out.join("/") + last;
}

function canonicalUri(path: string, form: CanonicalForm["uri"]): string {
  if (form === "raw") return path === "" ? "/" : path;
  const p = form === "normalized" ? removeDotSegments(path) || "/" : path;
  return awsUriEncode(p, true);
}

/** Code-unit order, as Python and the SDKs sort ASCII. */
function byString(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function canonicalQuery(query: string, form: CanonicalForm["query"]): string | null {
  if (query === "") return "";
  const pairs = query.split("&").map((p) => {
    const eq = p.indexOf("=");
    return eq < 0 ? [p, ""] as [string, string] : [p.slice(0, eq), p.slice(eq + 1)] as [string, string];
  });
  if (form === "raw") {
    pairs.sort((a, b) => byString(a[0], b[0]) || byString(a[1], b[1]));
    return pairs.map(([k, v]) => `${k}=${v}`).join("&");
  }
  const enc: Array<[string, string]> = [];
  for (const [k, v] of pairs) {
    if (k === "" && v === "") continue;
    try {
      enc.push([awsUriEncode(decodeURIComponent(k), false), awsUriEncode(decodeURIComponent(v), false)]);
    } catch {
      return null; // a malformed escape: this form cannot read it
    }
  }
  enc.sort((a, b) => byString(a[0], b[0]) || byString(a[1], b[1]));
  return enc.map(([k, v]) => `${k}=${v}`).join("&");
}

/** One canonical header value: every value trimmed, runs of spaces made one,
 *  joined by commas. */
function canonicalHeaderValue(values: readonly string[]): string {
  return values.map((v) => v.trim().replace(/\s+/g, " ")).join(",");
}

export function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/** The payload hash the signature covers: `x-amz-content-sha256` as sent when
 *  there is one (S3 signs that header's value, a hash or a mode), else the
 *  body's SHA-256. */
export function payloadHashOf(req: Pick<SigV4Request, "headers" | "body">): string {
  const stated = headerValues(req.headers, "x-amz-content-sha256");
  if (stated.length > 0) return stated[0]!.trim();
  return sha256Hex(req.body);
}

/** The canonical request (AWS: "Create a canonical request"), or null when
 *  the form cannot read the query. */
export function canonicalRequest(req: SigV4Request, auth: SigV4Authorization, form: CanonicalForm): string | null {
  const { path, query } = rawPathAndQuery(req.url);
  const q = canonicalQuery(query, form.query);
  if (q === null) return null;
  // In the order SignedHeaders lists them (the SDK sorted them).
  const lines = auth.signedHeaders.map((name) => {
    const values = name === "host" && req.host !== undefined ? [req.host] : headerValues(req.headers, name);
    return `${name}:${canonicalHeaderValue(values)}\n`;
  });
  return [
    req.method.toUpperCase(),
    canonicalUri(path, form.uri),
    q,
    lines.join(""),
    auth.signedHeaders.join(";"),
    payloadHashOf(req),
  ].join("\n");
}

/** The derived signing key for one scope. */
export function signingKey(secret: string, date: string, region: string, service: string): Buffer {
  const k1 = createHmac("sha256", `AWS4${secret}`).update(date).digest();
  const k2 = createHmac("sha256", k1).update(region).digest();
  const k3 = createHmac("sha256", k2).update(service).digest();
  return createHmac("sha256", k3).update("aws4_request").digest();
}

/** The request's `x-amz-date` (`YYYYMMDDTHHMMSSZ`) when it is one, on the
 *  scope's date; else null (no SDK leaves it out). */
export function amzDateOf(req: Pick<SigV4Request, "headers">, auth: SigV4Authorization): string | null {
  const v = headerValues(req.headers, "x-amz-date");
  if (v.length !== 1) return null;
  const d = v[0]!.trim();
  return /^\d{8}T\d{6}Z$/.test(d) && d.startsWith(auth.date) ? d : null;
}

/** The signature `secret` makes over `req` in `form`, or null when the
 *  request cannot be signed (no `x-amz-date`, a query the form cannot read). */
export function sigv4Signature(req: SigV4Request, auth: SigV4Authorization, secret: string, form: CanonicalForm): string | null {
  const when = amzDateOf(req, auth);
  if (when === null) return null;
  const cr = canonicalRequest(req, auth, form);
  if (cr === null) return null;
  const scope = `${auth.date}/${auth.region}/${auth.service}/aws4_request`;
  const toSign = `${SIGV4_ALGORITHM}\n${when}\n${scope}\n${sha256Hex(cr)}`;
  return createHmac("sha256", signingKey(secret, auth.date, auth.region, auth.service)).update(toSign).digest("hex");
}

function sameHex(a: string, b: string): boolean {
  const x = Buffer.from(a, "hex");
  const y = Buffer.from(b, "hex");
  return x.length === 32 && y.length === 32 && timingSafeEqual(x, y);
}

/**
 * The candidate (a signing-key placeholder) and canonical form whose
 * signature over `req` is the one the request carries, or null when none
 * is. The first match wins; two candidates cannot both match (HMAC). Pure.
 */
export function matchSignature(
  req: SigV4Request,
  auth: SigV4Authorization,
  candidates: readonly string[],
): { secret: string; form: CanonicalForm } | null {
  if (auth.algorithm !== SIGV4_ALGORITHM) return null;
  for (const form of CANONICAL_FORMS) {
    // One canonical request per form, then one HMAC chain per candidate.
    const cr = canonicalRequest(req, auth, form);
    const when = amzDateOf(req, auth);
    if (cr === null || when === null) continue;
    const scope = `${auth.date}/${auth.region}/${auth.service}/aws4_request`;
    const toSign = `${SIGV4_ALGORITHM}\n${when}\n${scope}\n${sha256Hex(cr)}`;
    for (const secret of candidates) {
      const sig = createHmac("sha256", signingKey(secret, auth.date, auth.region, auth.service)).update(toSign).digest("hex");
      if (sameHex(sig, auth.signature)) return { secret, form };
    }
  }
  return null;
}

/** The `Authorization` value with its Signature replaced (everything else,
 *  the released access key id included, as it stands). */
export function resignedAuthorization(value: string, signature: string): string {
  return value.replace(/(Signature=)[0-9a-fA-F]{64}/, `$1${signature}`);
}

/**
 * What the request's `x-amz-content-sha256` says of its payload:
 *   - `absent`: no header (the body's hash is signed);
 *   - `hashed`: a SHA-256 hex (S3: the header is signed, and must be the
 *     body's hash);
 *   - `unsigned`: `UNSIGNED-PAYLOAD`;
 *   - `streaming-unsigned`: `STREAMING-UNSIGNED-PAYLOAD-TRAILER` (aws-chunked
 *     framing, chunks unsigned: the CLI's uploads since 2025);
 *   - `streaming-signed`: an aws-chunked body whose every chunk carries a
 *     signature made with the key (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD…`) or
 *     SigV4a's (`STREAMING-AWS4-ECDSA-…`): refused (open, §6);
 *   - `other`: anything else (refused).
 */
export type PayloadMode = "absent" | "hashed" | "unsigned" | "streaming-unsigned" | "streaming-signed" | "other";

export function payloadModeOf(headers: Record<string, string | string[] | undefined>): PayloadMode {
  const v = headerValues(headers, "x-amz-content-sha256");
  if (v.length === 0) return "absent";
  if (v.length > 1) return "other";
  const s = v[0]!.trim();
  if (/^[0-9a-f]{64}$/i.test(s)) return "hashed";
  if (s === "UNSIGNED-PAYLOAD") return "unsigned";
  if (s === "STREAMING-UNSIGNED-PAYLOAD-TRAILER") return "streaming-unsigned";
  if (s.startsWith("STREAMING-AWS4-")) return "streaming-signed";
  return "other";
}

/** `host`, `host:port` or `[v6]:port` with the scheme's default port
 *  dropped and the case folded, for comparing a signed Host with the one
 *  the proxy sends. */
export function normalHost(value: string, scheme: "http" | "https"): string {
  const v = value.trim().toLowerCase().replace(/\.$/, "");
  const dflt = scheme === "https" ? ":443" : ":80";
  return v.endsWith(dflt) ? v.slice(0, -dflt.length) : v;
}
