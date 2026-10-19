/**
 * model-tls — policy.yaml `models[].tls`: how Mandu checks a declared model
 * endpoint's identity when it dials it
 * (model-endpoints.md §2 D3).
 *
 * On loopback the kernel guarantees who answers; over a network nothing but
 * TLS does, and the default trust store plus DNS is a weak answer for an
 * internal endpoint. An entry may therefore name:
 *   - `ca_file`      a PEM bundle added to the default store for THIS
 *                    endpoint's connections only (a corporate root never
 *                    becomes trusted for every host);
 *   - `pin_sha256`   base64 SHA-256 hashes of a SubjectPublicKeyInfo (the
 *                    HPKP format): a chain that validates but carries none of
 *                    them is refused; a list, so a rotation can list both keys;
 *   - `client_cert` / `client_key`  a client certificate for a gateway that
 *                    requires mutual TLS. Paths only: the key never goes in
 *                    policy.yaml, and the key FILE is masked in the agent's
 *                    world like any secret file (`modelClientKeyPaths`, used by
 *                    the arbiter's secret discovery and label lookup).
 *
 * Validation reads the files (the arbiter runs as the user, on the same host
 * as everything that dials the endpoint): each must exist and parse, the
 * certificate and key must match, and a pin must decode to 32 bytes. `tls:`
 * on an `http:` url is refused as meaningless. What this module never does
 * is dial anything: the checks at connection time live beside each client
 * (inspect-mcp, both model proxies, doctor, the dashboard probe).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { X509Certificate, createPrivateKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, normalize } from "node:path";

import type { ModelEndpointEntry } from "./load-policy.js";

export const TLS_KEYS = ["ca_file", "pin_sha256", "client_cert", "client_key"] as const;

/** The compiled form: absolute paths, pins as written. */
export interface ModelTls {
  readonly caFile?: string;
  readonly pinSha256?: readonly string[];
  readonly clientCert?: string;
  readonly clientKey?: string;
}

/** `~/x` → `<home>/x`; an absolute path normalized; anything else null. */
export function expandTlsPath(p: string, home: string = process.env["HOME"] || homedir()): string | null {
  if (p === "~" || p.startsWith("~/")) return normalize(join(home, p.slice(1)));
  return isAbsolute(p) ? normalize(p) : null;
}

/** Every PEM certificate block in `text`. */
function pemCertificates(text: string): string[] {
  return text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
}

/** A pin is base64 of exactly 32 bytes (a SHA-256). */
export function isSha256Pin(v: unknown): v is string {
  if (typeof v !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(v)) return false;
  return Buffer.from(v, "base64").length === 32;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Validate one entry's `tls:` (called by the validator's `checkModels`).
 * Problems are pushed to `out`, each naming the field; `read` is injectable
 * for tests. Never throws.
 */
export function checkModelTls(
  entry: Record<string, unknown>,
  here: string,
  out: string[],
  read: (p: string) => string = (p) => readFileSync(p, "utf8"),
  home?: string,
): void {
  if (!("tls" in entry)) return;
  const tls = entry.tls;
  const at = `${here}.tls`;
  if (!isPlainObject(tls)) {
    out.push(`${at}: must be a mapping of { ca_file?, pin_sha256?, client_cert?, client_key? }`);
    return;
  }
  for (const k of Object.keys(tls)) {
    if (!(TLS_KEYS as readonly string[]).includes(k)) out.push(`${at}: unknown key '${k}' (expected ca_file, pin_sha256, client_cert, client_key)`);
  }
  let url: URL | null = null;
  try { url = typeof entry.url === "string" ? new URL(entry.url) : null; } catch { url = null; }
  if (url !== null && url.protocol === "http:") {
    out.push(`${at}: the url is plain http, so there is no TLS to check; use an https url or remove tls`);
  }
  const fileAt = (k: "ca_file" | "client_cert" | "client_key"): { path: string; text: string } | null => {
    if (!(k in tls)) return null;
    const v = tls[k];
    if (typeof v !== "string" || v === "") { out.push(`${at}.${k}: must be a file path`); return null; }
    const p = expandTlsPath(v, home);
    if (p === null) { out.push(`${at}.${k}: must be an absolute path or start with ~/ (got ${JSON.stringify(v)})`); return null; }
    let text: string;
    try { text = read(p); } catch { out.push(`${at}.${k}: cannot read ${p}`); return null; }
    return { path: p, text };
  };
  const ca = fileAt("ca_file");
  if (ca !== null) {
    const certs = pemCertificates(ca.text);
    if (certs.length === 0) out.push(`${at}.ca_file: ${ca.path} holds no PEM certificate`);
    for (const c of certs) {
      try { new X509Certificate(c); } catch { out.push(`${at}.ca_file: ${ca.path} holds a certificate that does not parse`); break; }
    }
  }
  if ("pin_sha256" in tls) {
    const pins = tls.pin_sha256;
    if (!Array.isArray(pins) || pins.length === 0) {
      out.push(`${at}.pin_sha256: must be a non-empty list of base64 SHA-256 hashes`);
    } else {
      pins.forEach((p, i) => {
        if (!isSha256Pin(p)) out.push(`${at}.pin_sha256[${i}]: must be the base64 of a 32-byte SHA-256 (44 characters ending in =)`);
      });
    }
  }
  const cert = fileAt("client_cert");
  const key = fileAt("client_key");
  if (("client_cert" in tls) !== ("client_key" in tls)) {
    out.push(`${at}: client_cert and client_key go together (a client certificate needs its key, and a key its certificate)`);
  }
  let x509: X509Certificate | null = null;
  if (cert !== null) {
    const first = pemCertificates(cert.text)[0];
    try { x509 = first ? new X509Certificate(first) : null; } catch { x509 = null; }
    if (x509 === null) out.push(`${at}.client_cert: ${cert.path} holds no certificate that parses`);
  }
  if (key !== null) {
    let pk: ReturnType<typeof createPrivateKey> | null = null;
    try { pk = createPrivateKey(key.text); } catch (e) {
      const encrypted = /passphrase|encrypted/i.test(String((e as Error)?.message ?? ""));
      out.push(`${at}.client_key: ${key.path} is not ${encrypted ? "an unencrypted" : "a"} private key${encrypted ? " (a key with a passphrase is not supported)" : ""}`);
    }
    if (pk !== null && x509 !== null && !x509.checkPrivateKey(pk)) {
      out.push(`${at}: client_key does not match client_cert`);
    }
  }
}

/** The compiled `tls` of one entry: absolute paths, only the fields given.
 *  undefined when there is none (or nothing usable; the validator refused
 *  such a file already). */
export function compileModelTls(e: Pick<ModelEndpointEntry, "tls">, home?: string): ModelTls | undefined {
  const t = e.tls;
  if (!isPlainObject(t)) return undefined;
  const path = (v: unknown): string | undefined => (typeof v === "string" ? expandTlsPath(v, home) ?? undefined : undefined);
  const out: { caFile?: string; pinSha256?: string[]; clientCert?: string; clientKey?: string } = {};
  const caFile = path(t.ca_file);
  if (caFile) out.caFile = caFile;
  if (Array.isArray(t.pin_sha256)) {
    const pins = t.pin_sha256.filter(isSha256Pin);
    if (pins.length > 0) out.pinSha256 = pins;
  }
  const clientCert = path(t.client_cert);
  const clientKey = path(t.client_key);
  if (clientCert && clientKey) { out.clientCert = clientCert; out.clientKey = clientKey; }
  return Object.keys(out).length > 0 ? Object.freeze(out) : undefined;
}

/** The client key files the declared endpoints name (plan 12 D3): secret
 *  files, masked in the agent's world like any other. */
export function modelClientKeyPaths(models: ReadonlyArray<{ tls?: ModelTls }>): string[] {
  const out: string[] = [];
  for (const m of models) {
    const k = m.tls?.clientKey;
    if (k && !out.includes(k)) out.push(k);
  }
  return out;
}
