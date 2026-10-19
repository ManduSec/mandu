/**
 * lib/tls — mint a self-signed TLS cert for the eval's fake upstreams.
 *
 * Extracted verbatim from run-live.ts (agent-legibility split, behavior-preserving).
 * The fakes serve HTTPS only (the proxy forwards over HTTPS), so each live case
 * mints a short-lived self-signed cert via the openssl CLI. Not public API — the
 * barrel imports these back for depsAvailable + the runLive orchestration.
 */

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

export interface TlsMaterial {
  cert: Buffer;
  key: Buffer;
}

/** Is the openssl CLI available (needed to mint the fake's TLS cert)? */
export function opensslAvailable(): boolean {
  try {
    return spawnSync("openssl", ["version"], { encoding: "utf8", timeout: 10_000 }).status === 0;
  } catch {
    return false;
  }
}

/** Mint a self-signed cert/key into `dir`, returning the PEM material. */
export function mintSelfSignedCert(dir: string): TlsMaterial {
  const certPath = join(dir, "fake-cert.pem");
  const keyPath = join(dir, "fake-key.pem");
  const r = spawnSync(
    "openssl",
    [
      "req", "-x509", "-newkey", "rsa:2048",
      "-keyout", keyPath, "-out", certPath,
      "-days", "1", "-nodes",
      "-subj", "/CN=mandu-eval-fake-upstream",
    ],
    { encoding: "utf8", timeout: 20_000 },
  );
  if (r.status !== 0) throw new Error(`openssl could not mint a fake cert: ${r.stderr ?? r.stdout}`);
  return { cert: readFileSync(certPath), key: readFileSync(keyPath) };
}
