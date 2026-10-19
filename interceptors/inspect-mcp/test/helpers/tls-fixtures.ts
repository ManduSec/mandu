/**
 * tls-fixtures — throwaway certificates for the plan 12 D3 tests, minted with
 * the openssl CLI into a temp directory (nothing is committed: no private key
 * lives in the repository). `mintTlsFixtures()` returns null when openssl is
 * not on PATH, and the caller self-SKIPs.
 *
 * What it mints:
 *   - `ca`      a root CA, and `server` (key + cert, SAN 127.0.0.1 and
 *               localhost, or the `serverSans` given) signed by it;
 *   - `otherCa` an unrelated root (the "wrong CA" case);
 *   - `clientCa` a root that signs `client` (key + cert) for mutual TLS;
 *   - `serverPin` / `caPin` / `otherPin`: base64 SHA-256 of each SPKI.
 *
 * PROVENANCE: NEW Mandu test code. Copied as-is into the packages that need
 * it (each package tests standalone).
 */
import { execFileSync } from "node:child_process";
import { X509Certificate, createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface TlsFixtures {
  dir: string;
  caCert: string; caCertPem: string;
  serverCert: string; serverKey: string; serverCertPem: string; serverKeyPem: string;
  otherCaCert: string;
  clientCaCert: string; clientCaCertPem: string;
  clientCert: string; clientKey: string; clientCertPem: string; clientKeyPem: string;
  /** A second client key that does not match `clientCert`. */
  strayKey: string;
  serverPin: string; caPin: string; otherPin: string;
  cleanup: () => void;
}

function openssl(args: string[], cwd: string): void {
  execFileSync("openssl", args, { cwd, stdio: "ignore" });
}

export function spkiPin(pem: string): string {
  const der = new X509Certificate(pem).publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("base64");
}

/** `serverSans`: the server certificate's names, as openssl spells them
 *  (`DNS:llm.corp.example`, `IP:10.77.0.2`). Default 127.0.0.1 and localhost. */
export function mintTlsFixtures(opts: { serverSans?: string[] } = {}): TlsFixtures | null {
  try { execFileSync("openssl", ["version"], { stdio: "ignore" }); } catch { return null; }
  const dir = mkdtempSync(join(tmpdir(), "mandu-tls-fx-"));
  try {
    const root = (name: string, cn: string): void =>
      openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.pem`, "-days", "2", "-subj", `/CN=${cn}`,
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], dir);
    const leaf = (name: string, ca: string, cn: string, ext: string): void => {
      openssl(["req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", `/CN=${cn}`], dir);
      writeFileSync(join(dir, `${name}.ext`), ext);
      openssl(["x509", "-req", "-in", `${name}.csr`, "-CA", `${ca}.pem`, "-CAkey", `${ca}.key`, "-CAcreateserial", "-out", `${name}.pem`, "-days", "2", "-extfile", `${name}.ext`], dir);
    };
    root("ca", "Mandu Test CA");
    root("other-ca", "Mandu Other CA");
    root("client-ca", "Mandu Client CA");
    const sans = opts.serverSans ?? ["IP:127.0.0.1", "DNS:localhost"];
    leaf("server", "ca", "localhost", `subjectAltName=${sans.join(",")}\nextendedKeyUsage=serverAuth\n`);
    leaf("client", "client-ca", "mandu-client", "extendedKeyUsage=clientAuth\n");
    openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "stray.key"], dir);
    const f = (n: string): string => join(dir, n);
    const text = (n: string): string => readFileSync(f(n), "utf8");
    return {
      dir,
      caCert: f("ca.pem"), caCertPem: text("ca.pem"),
      serverCert: f("server.pem"), serverKey: f("server.key"), serverCertPem: text("server.pem"), serverKeyPem: text("server.key"),
      otherCaCert: f("other-ca.pem"),
      clientCaCert: f("client-ca.pem"), clientCaCertPem: text("client-ca.pem"),
      clientCert: f("client.pem"), clientKey: f("client.key"), clientCertPem: text("client.pem"), clientKeyPem: text("client.key"),
      strayKey: f("stray.key"),
      serverPin: spkiPin(text("server.pem")), caPin: spkiPin(text("ca.pem")), otherPin: spkiPin(text("other-ca.pem")),
      cleanup: () => rmSync(dir, { recursive: true, force: true }),
    };
  } catch {
    rmSync(dir, { recursive: true, force: true });
    return null;
  }
}
