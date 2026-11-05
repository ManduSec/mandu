/**
 * kubeconfig — what Mandu reads in a kubeconfig so kubectl and helm work
 * from its twin (docs/design/confidentiality/kube-wire-release.md): the
 * token's wire host, the `*-data` encoding, the session overlay, and the
 * upstream profile the proxy dials a cluster with.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  decodedPem,
  isKubeconfigPath,
  kubeOverlay,
  kubeServerAuthority,
  kubeTokenWire,
  kubeconfigPublicValues,
  kubeUpstream,
  parseKubeconfig,
} from "../../policy/kubeconfig.js";
import { extractSecretSpans, renderStructuredTwin, encodeToken } from "../../policy/secret-extract.js";
import { valueFingerprints } from "../../policy/egress-fingerprint.js";

const PEM_CA = "-----BEGIN CERTIFICATE-----\nMIIBcaFAKEcaBYTES\n-----END CERTIFICATE-----\n";
const PEM_CERT = "-----BEGIN CERTIFICATE-----\nMIIBclientCERT\n-----END CERTIFICATE-----\n";
const PEM_KEY = "-----BEGIN EC PRIVATE KEY-----\nMHcKEYbytesKUBE\n-----END EC PRIVATE KEY-----\n";
const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");

/** A kubeconfig: `prod` (token user), `secure` (client-certificate user),
 *  `other` (a second token), `plain` (http). */
function config(extra = ""): string {
  return [
    "apiVersion: v1",
    "clusters:",
    "- name: prod",
    "  cluster:",
    `    certificate-authority-data: ${b64(PEM_CA)}`,
    "    server: https://K8S.example.test:6443/",
    "- name: secure",
    "  cluster:",
    "    server: https://mtls.example.test",
    "    tls-server-name: api.internal",
    "- name: plain",
    "  cluster:",
    "    server: http://plain.example.test:8080",
    "- name: v6",
    "  cluster:",
    "    server: https://[2001:db8::1]:6443",
    "contexts:",
    "- name: prod", "  context: {cluster: prod, user: admin}",
    "- name: secure", "  context: {cluster: secure, user: certuser}",
    "- name: plain", "  context: {cluster: plain, user: plainuser}",
    "- name: v6", "  context: {cluster: v6, user: v6user}",
    "current-context: prod",
    "users:",
    "- name: admin", "  user:", "    token: tok-admin-123456",
    "- name: certuser", "  user:", `    client-certificate-data: ${b64(PEM_CERT)}`, `    client-key-data: ${b64(PEM_KEY)}`,
    "- name: plainuser", "  user:", "    token: tok-plain-123456",
    "- name: v6user", "  user:", "    token: tok-v6-1234567",
    extra,
  ].join("\n");
}

test("the path and the server authority: https only, the port stated, a v6 host bracketed", () => {
  assert.ok(isKubeconfigPath("/home/u/.kube/config"));
  assert.ok(!isKubeconfigPath("/home/u/.kube/config.bak"));
  assert.equal(kubeServerAuthority("https://K8S.example.test:6443/"), "k8s.example.test:6443");
  assert.equal(kubeServerAuthority("https://rancher.example/k8s/clusters/c-1"), "rancher.example:443");
  assert.equal(kubeServerAuthority("https://[2001:DB8::1]:6443"), "[2001:db8::1]:6443");
  assert.equal(kubeServerAuthority("http://plain.example.test:8080"), null);
  assert.equal(kubeServerAuthority("https://u:p@host"), null);
  assert.equal(kubeServerAuthority("not a url"), null);
});

test("a token's wire host is the one https server its contexts name; none for http, several, or none", () => {
  const cfg = parseKubeconfig(config())!;
  const w = kubeTokenWire(cfg);
  assert.equal(w.get("tok-admin-123456"), "k8s.example.test:6443");
  assert.equal(w.get("tok-plain-123456"), null);
  assert.equal(w.get("tok-v6-1234567"), "[2001:db8::1]:6443");
  // The admin user also on the secure cluster: two servers, no wire host.
  const two = parseKubeconfig(config("- name: extra\n  user: {}\n").replace("- name: plain\n  context: {cluster: plain, user: plainuser}", "- name: plain\n  context: {cluster: secure, user: admin}"))!;
  assert.equal(kubeTokenWire(two).get("tok-admin-123456"), null);
  // A user no context names: no wire host.
  const lone = parseKubeconfig("users:\n- name: x\n  user:\n    token: tok-lone-1234567\n")!;
  assert.equal(kubeTokenWire(lone).get("tok-lone-1234567"), null);
  assert.equal(parseKubeconfig("- just\n- a list\n"), null);
  assert.equal(parseKubeconfig(": not yaml :\n  - ["), null);
});

test("decodedPem: strict base64 of a PEM block only", () => {
  assert.equal(decodedPem(b64(PEM_CA)), PEM_CA);
  assert.equal(decodedPem("LS0tkey"), null);
  assert.equal(decodedPem(b64("not a pem")), null);
  assert.equal(decodedPem(`${b64(PEM_CA)}\n`), PEM_CA, "surrounding whitespace is the YAML's");
});

test("the twin: *-data fields are base64 of the placeholder (client-go still loads it), the token a bearer wire credential to its cluster", () => {
  const c = config();
  const x = extractSecretSpans("/h/.kube/config", c);
  const byKey = new Map(x.spans.map((s) => [s.key.replace(/__\d+$/, ""), s]));
  const ca = x.spans.find((s) => s.key === "clusters.cluster.certificate-authority-data")!;
  assert.equal(ca.encoded, "base64");
  assert.equal(ca.value, PEM_CA, "the span's value is the PEM the program decodes");
  const key = x.spans.find((s) => s.key.endsWith("client-key-data"))!;
  assert.equal(key.encoded, "base64");
  assert.equal(key.value, PEM_KEY);
  const admin = x.spans.find((s) => s.value === "tok-admin-123456")!;
  assert.deepEqual(admin.wire, { host: "k8s.example.test:6443", scheme: "bearer", httpsOnly: true });
  assert.equal(x.spans.find((s) => s.value === "tok-plain-123456")!.wire, undefined, "an http cluster's token is put back nowhere");
  assert.ok(byKey.size > 0);
  const twin = renderStructuredTwin(c, x.spans, (s) => `$MDU:nomodel_Read[ab12].${s.key}`);
  for (const secret of [PEM_KEY, b64(PEM_KEY), "tok-admin-123456"]) assert.ok(!twin.includes(secret));
  assert.ok(twin.includes(`client-key-data: ${encodeToken(`$MDU:nomodel_Read[ab12].${key.key}`, "base64")}`));
  // The same reading under another name is plain YAML keys.
  assert.equal(extractSecretSpans("/h/other.yaml", c).spans.find((s) => s.value === "tok-admin-123456")!.wire, undefined);
});

test("the overlay: each https cluster without its trust keys or a proxy of the user's; client-certificate users without their certificate and key", () => {
  const twin = config().replace("    server: https://mtls.example.test\n", "    server: https://mtls.example.test\n    insecure-skip-tls-verify: true\n")
    + "- name: proxied\n  user: {}\n";
  const withProxy = twin.replace("- name: v6\n  cluster:\n", "- name: v6\n  cluster:\n    proxy-url: http://corp-proxy:3128\n");
  const ov = kubeOverlay(withProxy)!;
  assert.deepEqual(ov.clusters.map((c) => c.name), ["prod", "secure"], "no http cluster, none with the user's proxy");
  assert.deepEqual(ov.clusters[0]!.cluster, { server: "https://K8S.example.test:6443/" });
  assert.deepEqual(ov.clusters[1]!.cluster, { server: "https://mtls.example.test" }, "tls-server-name and insecure-skip-tls-verify dropped");
  assert.deepEqual(ov.users, [{ name: "certuser", user: {} }]);
  assert.equal(kubeOverlay("clusters:\n- name: p\n  cluster: {server: http://x}\n"), null);
  assert.equal(kubeOverlay("{{ not yaml"), null);
});

test("the upstream profile: the cluster's own CA, tls-server-name, insecure, and the one client-certificate user of that server", () => {
  const files: Record<string, string> = { "/h/.kube/ca.pem": PEM_CA, "/h/.kube/certs/c.pem": PEM_CERT, "/h/.kube/certs/c.key": PEM_KEY };
  const opts = { dir: "/h/.kube", readFile: (p: string) => files[p] ?? null };
  assert.deepEqual(kubeUpstream(config(), "k8s.example.test:6443", opts), { ca: PEM_CA, insecure: false });
  assert.deepEqual(kubeUpstream(config(), "mtls.example.test:443", opts), { servername: "api.internal", insecure: false, client: { cert: PEM_CERT, key: PEM_KEY } });
  assert.equal(kubeUpstream(config(), "k8s.example.test:443", opts), null, "another port is another server");
  assert.equal(kubeUpstream(config(), "evil.example:443", opts), null);
  // File references, relative to the kubeconfig's folder.
  const byFile = "clusters:\n- name: f\n  cluster:\n    server: https://f.example\n    certificate-authority: ca.pem\n"
    + "contexts:\n- name: f\n  context: {cluster: f, user: u}\nusers:\n- name: u\n  user:\n    client-certificate: certs/c.pem\n    client-key: /h/.kube/certs/c.key\n";
  assert.deepEqual(kubeUpstream(byFile, "f.example:443", opts), { ca: PEM_CA, insecure: false, client: { cert: PEM_CERT, key: PEM_KEY } });
  // An unreadable key: no client certificate, and why.
  const noKey = byFile.replace("/h/.kube/certs/c.key", "/nowhere.key");
  const p = kubeUpstream(noKey, "f.example:443", opts)!;
  assert.equal(p.client, undefined);
  assert.match(p.clientWhy!, /could not be read/);
  // Two client-certificate users on one server: none presented.
  const two = config("- name: cert2\n  user:\n    client-certificate-data: " + b64(PEM_CERT) + "\n    client-key-data: " + b64(PEM_KEY) + "\n")
    .replace("current-context: prod", "- name: secure2\n  context: {cluster: secure, user: cert2}\ncurrent-context: prod");
  const amb = kubeUpstream(two, "mtls.example.test:443", opts)!;
  assert.equal(amb.client, undefined);
  assert.match(amb.clientWhy!, /2 users/);
  // Two clusters with that server that disagree on trust: no profile.
  const clash = config().replace("- name: plain\n  cluster:\n    server: http://plain.example.test:8080", "- name: prod2\n  cluster:\n    server: https://k8s.example.test:6443\n    insecure-skip-tls-verify: true");
  assert.equal(kubeUpstream(clash, "k8s.example.test:6443", opts), null);
});

// live-clients.md §3.3 (2026-10-25): the real kubectl against a cluster at
// https://10.201.0.2:6443 was refused by the §4 tripwire: the server URL (and
// a random-looking namespace) read as credential-shaped bare tokens of the
// file's row, and kubectl sends both in every request.
const LIVE = [
  "apiVersion: v1", "kind: Config",
  "clusters:", "- name: live", "  cluster:", "    server: https://10.201.0.2:6443", `    certificate-authority-data: ${b64(PEM_CA)}`,
  "users:", "- name: token-user", "  user:", "    token: eyJhbGciOiJSUzI1NiIsImtpZCI6IkxJVkUifQ.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQifQ.c2lnTElWRTEyMzQ1Njc4OWFiY2RlZg",
  "contexts:", "- name: token", "  context:", "    cluster: live", "    user: token-user", "    namespace: mdu-live-ed8562c7",
  "current-context: token", "",
].join("\n");

test("kubeconfigPublicValues: the names, the server URL, the namespace; a URL with a user, password or query is no public value", () => {
  const pub = kubeconfigPublicValues(LIVE);
  for (const v of ["live", "token-user", "token", "https://10.201.0.2:6443", "mdu-live-ed8562c7"]) assert.ok(pub.includes(v), v);
  assert.ok(!pub.some((v) => v.startsWith("eyJ")), "never the token");
  const withCreds = LIVE.replace("server: https://10.201.0.2:6443", "server: https://admin:s3cretPW@10.201.0.2:6443").replace("cluster: live\n    user", "cluster: live\n    user");
  assert.ok(!kubeconfigPublicValues(withCreds).some((v) => v.includes("s3cretPW")));
  assert.ok(!kubeconfigPublicValues(LIVE.replace("server: https://10.201.0.2:6443", "server: https://10.201.0.2:6443/?t=abc")).some((v) => v.includes("?t=")));
  assert.deepEqual(kubeconfigPublicValues("not: [a kubeconfig"), []);
});

test("a kubeconfig's server URL and namespace are no pieces of its row; its token still is", () => {
  const x = extractSecretSpans("/home/u/.kube/config", LIVE);
  const twinText = renderStructuredTwin(LIVE, x.spans, (s) => `$MDU:nomodel_Read[abcd].${s.key}`);
  const secrets = x.spans.map((s) => s.value);
  const token = x.spans.find((s) => s.key.endsWith("token"))!.value;
  const before = valueFingerprints(LIVE, 0, { bareTokens: true, twin: { text: twinText, secrets } });
  assert.ok(before.includes("https://10.201.0.2:6443"), "the URL was a piece (the bug this guards)");
  const after = valueFingerprints(LIVE, 0, { bareTokens: true, twin: { text: twinText, secrets, publicTokens: kubeconfigPublicValues(LIVE) } });
  for (const p of after) {
    assert.ok(!"https://10.201.0.2:6443/api/v1/namespaces/mdu-live-ed8562c7/pods?limit=500".includes(p), `a request to the cluster holds piece ${p}`);
  }
  assert.ok(after.some((p) => p.includes(token)), "the token stays a piece");
});
