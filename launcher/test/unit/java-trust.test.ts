/**
 * java-trust — the session's JVM trust store and JAVA_TOOL_OPTIONS
 * (docs/design/confidentiality/kube-wire-release.md §5): the PKCS#12 file
 * (read back by openssl and, where installed, by keytool), NO_PROXY in
 * Java's spelling, the options and their order, and the env composer's use.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { javaNonProxyHosts, javaToolOptions, javaTrustStore, pemCertificates } from "../../src/java-trust.js";
import { composeLaunch } from "../../src/env-compose.js";
import type { LaunchPlan } from "../../src/types.js";

const has = (cmd: string): boolean => spawnSync("sh", ["-c", `command -v ${cmd}`], { stdio: "ignore" }).status === 0;
// macOS ships /usr/bin/keytool as a stub that only says no Java runtime is
// installed; there is one when /usr/libexec/java_home finds it.
const KEYTOOL = has("keytool") && (process.platform !== "darwin" || spawnSync("/usr/libexec/java_home", [], { stdio: "ignore" }).status === 0);
const OPENSSL = has("openssl");

/** Two self-signed CA certificates, minted by openssl. */
function twoCerts(dir: string): string {
  let bundle = "";
  for (const n of ["one", "two"]) {
    const r = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-subj", `/CN=mandu-test-${n}`, "-days", "2",
      "-keyout", join(dir, `${n}.key`), "-out", join(dir, `${n}.pem`)], { stdio: "ignore" });
    assert.equal(r.status, 0);
    bundle += spawnSync("cat", [join(dir, `${n}.pem`)], { encoding: "utf8" }).stdout;
  }
  return bundle;
}

test("pemCertificates: only CERTIFICATE blocks, as DER", () => {
  const der = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]);
  const pem = `x\n-----BEGIN CERTIFICATE-----\n${der.toString("base64")}\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n`;
  assert.deepEqual(pemCertificates(pem), [der]);
  assert.deepEqual(pemCertificates("nothing here"), []);
});

test("the trust store: openssl reads every certificate back, and keytool lists each as a trusted entry", { skip: !OPENSSL && "openssl unavailable" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-java-trust-"));
  try {
    const store = join(dir, "t.p12");
    writeFileSync(store, javaTrustStore(pemCertificates(twoCerts(dir))));
    const o = spawnSync("openssl", ["pkcs12", "-in", store, "-nokeys", "-passin", "pass:", "-nomacver", "-info"], { encoding: "utf8" });
    assert.equal(o.status, 0, o.stderr);
    assert.equal((o.stdout.match(/BEGIN CERTIFICATE/g) ?? []).length, 2);
    assert.match(o.stdout, /mandu-test-one/);
    if (KEYTOOL) {
      const k = spawnSync("keytool", ["-list", "-keystore", store, "-storetype", "PKCS12", "-storepass", "x"], { encoding: "utf8" });
      assert.equal(k.status, 0, k.stdout + k.stderr);
      assert.match(k.stdout, /contains 2 entries/);
      assert.equal((k.stdout.match(/trustedCertEntry/g) ?? []).length, 2);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("javaNonProxyHosts: NO_PROXY in Java's spelling, loopback always", () => {
  assert.equal(javaNonProxyHosts("127.0.0.1,localhost,::1,.corp.example,*.svc,api.openai.com:443,*"),
    "127.0.0.1|localhost|*.localhost|[::1]|*.corp.example|*.svc|api.openai.com|*.api.openai.com|*|127.*");
  assert.equal(javaNonProxyHosts(""), "localhost|127.*|[::1]");
});

test("javaToolOptions: the trust store and the proxy first, the user's options last (theirs win); null for a path the JVM would split", () => {
  const base = { trustStore: "/run/ca/mandu-java-truststore.p12", proxy: { host: "127.0.0.1", port: 3128 }, noProxy: "localhost" };
  assert.equal(javaToolOptions(base),
    "-Djavax.net.ssl.trustStore=/run/ca/mandu-java-truststore.p12 -Djavax.net.ssl.trustStoreType=PKCS12 " +
    "-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=3128 -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=3128 " +
    "-Dhttp.nonProxyHosts=localhost|*.localhost|127.*|[::1]");
  assert.match(javaToolOptions({ ...base, user: "-Xmx1g -Djavax.net.ssl.trustStore=/mine.p12" })!, / -Xmx1g -Djavax\.net\.ssl\.trustStore=\/mine\.p12$/);
  assert.equal(javaToolOptions({ ...base, trustStore: "/run/my ca/t.p12" }), null);
});

test("composeLaunch: JAVA_TOOL_OPTIONS only with inspection, the trust store and the proxy", () => {
  const plan = (over: Partial<LaunchPlan>): LaunchPlan => ({
    target: "claude", argv: ["claude"], scopeId: "sid", tenant: "live",
    arbiterSock: "/run/mandu/arbiter.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu",
    eventDir: "/run/mandu/sid/events", cwd: "/work", humanCwd: "/work", noContextProxy: true, fsSync: false,
    basePath: "/usr/bin:/bin", proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [], requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: true, replyFilter: true, bestEffort: false, ...over,
  });
  const on = { netProxy: { host: "127.0.0.1", port: 3128 }, mitmCaCert: "/ca/mandu-egress-ca.pem", mitmJava: { trustStore: "/ca/mandu-java-truststore.p12", userOptions: "-Xss2m" } };
  const { env } = composeLaunch(plan(on));
  assert.match(env["JAVA_TOOL_OPTIONS"]!, /^-Djavax\.net\.ssl\.trustStore=\/ca\/mandu-java-truststore\.p12 .*-Dhttps\.proxyPort=3128 .*-Dhttp\.nonProxyHosts=127\.0\.0\.1\|.* -Xss2m$/);
  assert.equal(composeLaunch(plan({ ...on, mitmJava: undefined })).env["JAVA_TOOL_OPTIONS"], undefined);
  assert.equal(composeLaunch(plan({ ...on, mitmCaCert: undefined })).env["JAVA_TOOL_OPTIONS"], undefined);
});
