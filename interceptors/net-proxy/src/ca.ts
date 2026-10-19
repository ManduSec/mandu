/**
 * ca — a dependency-free, openssl-CLI-backed session-local Certificate Authority
 * for the egress proxy's OPT-IN MITM mode (src/mitm.ts).
 *
 * MITM mode terminates TLS so the egress gate can inspect HTTPS REQUEST BODIES
 * (today a CONNECT tunnel is blind, so a `$MDU:*` smuggled in an HTTPS body
 * is invisible to the gate). To terminate TLS we must present a cert the agent
 * trusts for the target host — so we mint a session-local CA and, per host, a leaf
 * cert signed by it. The launcher then tells the agent to trust this CA via
 * NODE_EXTRA_CA_CERTS / CURL_CA_BUNDLE.
 *
 * ZERO npm deps (CONTRIBUTING.md hard constraint): certs are minted with the host's
 * `openssl` CLI via `node:child_process` (synchronous at setup / first-touch). No
 * node-forge / @peculiar. If openssl is absent we throw a clear error and the
 * proxy/launcher degrades to non-MITM.
 *
 * SECURITY NOTE: the CA private key is session-local (under a temp/state dir) and
 * is the trust anchor the agent is told to trust. It must NOT outlive / escape the
 * session. The launcher owns the dir's lifecycle.
 */

import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { isIP } from "node:net";

/** The minted CA material (paths + in-memory PEM bytes). */
export interface CaMaterial {
  /** Path to the CA cert PEM (what the agent is told to trust). */
  certPath: string;
  /** Path to the CA private key PEM. */
  keyPath: string;
  /** The CA cert PEM bytes (for SecureContext / event logging). */
  certPem: string;
  /** The CA private key PEM bytes. */
  keyPem: string;
  /** The directory all CA + leaf material lives under. */
  dir: string;
}

/** A minted leaf cert for one host (key + cert PEM, cached on disk). */
export interface LeafMaterial {
  host: string;
  keyPem: string;
  certPem: string;
}

const CA_KEY = "mandu-egress-ca.key";
const CA_CERT = "mandu-egress-ca.pem";
/** Validity windows. The CA is session-local but we give it a few years so a
 * reused state dir keeps working; leaves are short-lived (still ample). */
const CA_DAYS = 3650; // ~10 years
const LEAF_DAYS = 825; // CA/B-forum leaf max; comfortable for a session

/** Run openssl, surfacing a clear error if the binary is missing. */
function openssl(args: string[], opts: { input?: Buffer; cwd?: string } = {}): Buffer {
  try {
    return execFileSync("openssl", args, {
      input: opts.input,
      cwd: opts.cwd,
      stdio: ["pipe", "pipe", "pipe"],
      maxBuffer: 8 * 1024 * 1024,
    });
  } catch (err) {
    const e = err as NodeJS.ErrnoException & { stderr?: Buffer };
    if (e.code === "ENOENT") {
      throw new Error(
        "openssl CLI not found on PATH — MITM mode needs it to mint a session-local CA. " +
          "Install openssl, or run without --net-proxy-mitm (plain --net-proxy blind-tunnels HTTPS).",
      );
    }
    const stderr = e.stderr ? e.stderr.toString("utf8") : e.message;
    throw new Error(`openssl ${args[0]} failed: ${stderr.trim()}`);
  }
}

/** True iff the host `openssl` CLI is available. Lets callers degrade BEFORE
 * minting (the launcher uses an equivalent shell check). */
export function opensslAvailable(): boolean {
  try {
    execFileSync("openssl", ["version"], { stdio: ["ignore", "ignore", "ignore"] });
    return true;
  } catch {
    return false;
  }
}

/** Why `dir` is not this uid's private directory (a real dir, not a link,
 *  owned by this uid, no group/other bits), or null. */
export function caDirProblem(dir: string): string | null {
  let st;
  try { st = lstatSync(dir); } catch (e) { return `cannot be checked (${(e as Error).message})`; }
  if (st.isSymbolicLink()) return "is a symlink";
  if (!st.isDirectory()) return "is not a directory";
  const uid = typeof process.getuid === "function" ? process.getuid() : st.uid;
  if (st.uid !== uid) return `is owned by uid ${st.uid}, not by you (uid ${uid})`;
  if ((st.mode & 0o077) !== 0) return `is shared (mode ${(st.mode & 0o777).toString(8)})`;
  return null;
}

/** The standalone default CA dir (a launch always names one in its private
 *  scope run dir): a per-uid name in TMPDIR, checked by ensureCa. */
export function defaultCaDir(tmp: string): string {
  const uid = typeof process.getuid === "function" ? process.getuid() : 0;
  return join(tmp, `mandu-egress-mitm-ca-${uid}`);
}

/**
 * Ensure a session-local CA exists under `dir`. IDEMPOTENT: if both the key and
 * cert are already present we reuse them (so a reused state dir doesn't re-mint /
 * invalidate an already-trusted CA). Otherwise mint a self-signed EC CA cert
 * (CN "Mandu egress CA", CA_DAYS validity).
 *
 * EC (prime256v1) keeps the openssl invocation tiny and fast and is broadly
 * trusted by node/curl. Returns the cert path + in-memory key/cert bytes.
 */
export function ensureCa(dir: string): CaMaterial {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dir, 0o700);
  } catch {
    /* not ours: caDirProblem below refuses it */
  }
  // The CA key signs every certificate the agent's tools trust. A dir another
  // account made first (the standalone default sits in the shared TMPDIR) or a
  // link it planted could hand the proxy that account's key, or read ours:
  // only a real directory of this uid with no group/other bits is used.
  const problem = caDirProblem(dir);
  if (problem !== null) throw new Error(`the egress CA dir ${dir} ${problem}; refusing to keep a CA key there`);
  const keyPath = join(dir, CA_KEY);
  const certPath = join(dir, CA_CERT);

  if (existsSync(keyPath) && existsSync(certPath)) {
    return {
      certPath,
      keyPath,
      certPem: readFileSync(certPath, "utf8"),
      keyPem: readFileSync(keyPath, "utf8"),
      dir,
    };
  }

  // 1. EC private key for the CA.
  openssl(["ecparam", "-genkey", "-name", "prime256v1", "-out", keyPath]);
  try {
    chmodSync(keyPath, 0o600);
  } catch {
    /* best-effort key perms */
  }

  // 2. Self-signed CA cert via an EXPLICIT -config (NOT -addext / -subj). This is
  //    load-bearing: on OpenSSL 1.1.1 `req -x509 -addext …` MERGES our extensions
  //    with the system openssl.cnf's default `[v3_ca]` (x509_extensions), emitting
  //    DUPLICATE basicConstraints + a spurious authorityKeyIdentifier — which makes
  //    the cert fail chain-building ("unable to get local issuer certificate"). A
  //    self-contained config with our own `[v3_ca]` and no default x509_extensions
  //    produces a single, clean CA cert that leaves verify against.
  const caCnfPath = join(dir, "ca.cnf");
  writeFileSync(
    caCnfPath,
    [
      "[req]",
      "distinguished_name = dn",
      "x509_extensions = v3_ca",
      "prompt = no",
      "[dn]",
      "CN = Mandu egress CA",
      "O = Mandu",
      "[v3_ca]",
      "basicConstraints = critical,CA:TRUE",
      "keyUsage = critical,keyCertSign,cRLSign",
      "subjectKeyIdentifier = hash",
      "",
    ].join("\n"),
    "utf8",
  );
  openssl([
    "req",
    "-x509",
    "-new",
    "-nodes",
    "-key",
    keyPath,
    "-sha256",
    "-days",
    String(CA_DAYS),
    "-config",
    caCnfPath,
    "-out",
    certPath,
  ]);

  return {
    certPath,
    keyPath,
    certPem: readFileSync(certPath, "utf8"),
    keyPem: readFileSync(keyPath, "utf8"),
    dir,
  };
}

/** Sanitize a host into a filesystem-safe cache filename (no path traversal). */
function leafBase(host: string): string {
  return host.replace(/[^a-zA-Z0-9._-]/g, "_");
}

/**
 * Mint (or load from cache) a leaf cert for `host`, signed by the session CA.
 *
 * CACHING: each host is minted ONCE — `<dir>/leaves/<host>.{key,pem}` is reused on
 * the next touch. (Per-host minting is the perf cost of MITM; the cache amortizes
 * it across a session — see the README/report caveat.)
 *
 * The leaf carries a SAN: dNS=<host>, or IP=<host> when `host` is a literal IP
 * (TLS clients validate the SAN, not the CN). Uses a tiny extfile so we can set
 * SAN without an openssl.cnf. Returns the leaf key + cert PEM.
 */
export function leafForHost(ca: CaMaterial, host: string): LeafMaterial {
  const leavesDir = join(ca.dir, "leaves");
  mkdirSync(leavesDir, { recursive: true });
  const base = join(leavesDir, leafBase(host));
  const keyPath = `${base}.key`;
  const certPath = `${base}.pem`;

  if (existsSync(keyPath) && existsSync(certPath)) {
    return { host, keyPem: readFileSync(keyPath, "utf8"), certPem: readFileSync(certPath, "utf8") };
  }

  // 1. Leaf EC key.
  openssl(["ecparam", "-genkey", "-name", "prime256v1", "-out", keyPath]);
  try {
    chmodSync(keyPath, 0o600);
  } catch {
    /* best-effort */
  }

  // 2. CSR for the host.
  const csrPath = `${base}.csr`;
  openssl(["req", "-new", "-key", keyPath, "-subj", `/CN=${host}`, "-out", csrPath]);

  // 3. extfile carrying the SAN (dNS or IP) + leaf usage. TLS verification keys on
  //    the SAN, so this is the load-bearing bit. The key identifiers are written
  //    out, not left to openssl's defaults: OpenSSL 3's `x509 -req` adds them, 4.0
  //    does not. Every session CA has the same name, so a client that trusts
  //    several (a merged trust bundle, an earlier session's CA) finds the issuer
  //    by the leaf's authorityKeyIdentifier; without it a wrong pick fails as
  //    "certificate signature failure" (measured 2026-10-01, OpenSSL 4.0.3).
  // An IPv6 literal's CONNECT target is bracketed (`[2001:db8::1]`): its
  // SAN is the bare address (plan 10 §11.13.1, 2026-10-17).
  const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  const sanLine = isIP(bare) ? `IP:${bare}` : `DNS:${host}`;
  const extPath = `${base}.ext`;
  writeFileSync(
    extPath,
    [
      "basicConstraints=CA:FALSE",
      "keyUsage=digitalSignature,keyEncipherment",
      "extendedKeyUsage=serverAuth",
      `subjectAltName=${sanLine}`,
      "subjectKeyIdentifier=hash",
      "authorityKeyIdentifier=keyid",
      "",
    ].join("\n"),
    "utf8",
  );

  // 4. Sign the CSR with the CA → the leaf cert.
  openssl([
    "x509",
    "-req",
    "-in",
    csrPath,
    "-CA",
    ca.certPath,
    "-CAkey",
    ca.keyPath,
    "-CAcreateserial",
    "-days",
    String(LEAF_DAYS),
    "-sha256",
    "-extfile",
    extPath,
    "-out",
    certPath,
  ]);

  return { host, keyPem: readFileSync(keyPath, "utf8"), certPem: readFileSync(certPath, "utf8") };
}
