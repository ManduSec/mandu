/**
 * kube-overlay — the session KUBECONFIG file (docs/design/confidentiality/
 * kube-wire-release.md §3): its text, its place in KUBECONFIG, and when the
 * launch writes none.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { spawnSync } from "node:child_process";
import { createPrivateKey, X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { kubeOverlayText, mintStandInClientCert, sessionKubeconfig, writeLaunchKubeOverlay, type KubeOverlayEntries } from "../../src/kube-overlay.js";

const ENTRIES: KubeOverlayEntries = {
  clusters: [{ name: "prod", cluster: { server: "https://k8s.example:6443", extensions: [] } }],
  users: [{ name: "certuser", user: {} }],
};

test("the overlay text: each cluster with the session CA and the session proxy, users as given, no contexts", () => {
  const doc = JSON.parse(kubeOverlayText(ENTRIES, "/run/ca/mandu-egress-ca.pem", "http://127.0.0.1:3128"));
  assert.deepEqual(doc, {
    apiVersion: "v1", kind: "Config",
    clusters: [{ name: "prod", cluster: { server: "https://k8s.example:6443", extensions: [], "certificate-authority": "/run/ca/mandu-egress-ca.pem", "proxy-url": "http://127.0.0.1:3128" } }],
    users: [{ name: "certuser", user: {} }],
    contexts: [],
  });
});

test("sessionKubeconfig: the overlay first; the user's list kept; none when it leaves ~/.kube/config out", () => {
  assert.equal(sessionKubeconfig(undefined, "/home/u", "/run/o.json"), "/run/o.json:/home/u/.kube/config");
  assert.equal(sessionKubeconfig("", "/home/u", "/run/o.json"), "/run/o.json:/home/u/.kube/config");
  assert.equal(sessionKubeconfig("/home/u/.kube/extra:/home/u/.kube/config", "/home/u", "/run/o.json"), "/run/o.json:/home/u/.kube/extra:/home/u/.kube/config");
  assert.equal(sessionKubeconfig("/work/kubeconfig", "/home/u", "/run/o.json"), null);
});

test("writeLaunchKubeOverlay: written beside the session CA when the home kubeconfig is twinned and the arbiter gives entries", async () => {
  const writes: Array<[string, string]> = [];
  const asked: string[] = [];
  const base = {
    home: "/home/u", twinned: ["/home/u/.aws/credentials", "/home/u/.kube/config"], caCertPath: "/run/s/ca/mandu-egress-ca.pem",
    netProxy: { host: "127.0.0.1", port: 3128 }, userKubeconfig: undefined,
    askOverlay: async (path: string) => { asked.push(path); return { overlay: ENTRIES, reason: "1 cluster" }; },
    write: (p: string, t: string) => { writes.push([p, t]); },
  };
  const r = await writeLaunchKubeOverlay(base);
  assert.equal(r.kubeconfig, "/run/s/ca/kube-overlay.json:/home/u/.kube/config");
  assert.match((r as { note: string }).note, /1 cluster of ~\/\.kube\/config/);
  assert.deepEqual(asked, ["/home/u/.kube/config"]);
  assert.equal(writes[0]![0], "/run/s/ca/kube-overlay.json");
  assert.match(writes[0]![1], /"proxy-url": "http:\/\/127\.0\.0\.1:3128"/);

  const notTwinned = await writeLaunchKubeOverlay({ ...base, twinned: ["/home/u/.aws/credentials"] });
  assert.equal(notTwinned.kubeconfig, null);
  const none = await writeLaunchKubeOverlay({ ...base, askOverlay: async () => ({ overlay: null, reason: "no https cluster the overlay can route" }) });
  assert.deepEqual(none, { kubeconfig: null, why: "no https cluster the overlay can route" });
  const otherList = await writeLaunchKubeOverlay({ ...base, userKubeconfig: "/work/kc" });
  assert.equal(otherList.kubeconfig, null);
  assert.equal(writes.length, 1, "nothing written when there is no overlay");
});

// live-clients.md §3.3: a certificate user with no credential at all makes
// the real kubectl prompt "Please enter Username:" on stdin, which fails
// every command run without a terminal. The overlay gives it a stand-in.
test("a certificate user's overlay entry holds the session's stand-in client certificate; none made, none written, and the note says so", async () => {
  const standIn = { cert: "/run/s/ca/kube-stand-in-client.pem", key: "/run/s/ca/kube-stand-in-client.pem" };
  const doc = JSON.parse(kubeOverlayText(ENTRIES, "/run/s/ca/mandu-egress-ca.pem", "http://127.0.0.1:3128", standIn));
  assert.deepEqual(doc.users, [{ name: "certuser", user: { "client-certificate": standIn.cert, "client-key": standIn.key } }]);
  const writes: string[] = [];
  const dirs: string[] = [];
  const base = {
    home: "/home/u", twinned: ["/home/u/.kube/config"], caCertPath: "/run/s/ca/mandu-egress-ca.pem",
    netProxy: { host: "127.0.0.1", port: 3128 }, userKubeconfig: undefined,
    askOverlay: async () => ({ overlay: ENTRIES, reason: "1 cluster" }),
    write: (_p: string, t: string) => { writes.push(t); },
    mintStandIn: (dir: string) => { dirs.push(dir); return standIn; },
  };
  const r = await writeLaunchKubeOverlay(base);
  assert.deepEqual(dirs, ["/run/s/ca"], "made beside the session CA");
  assert.match(writes[0]!, /"client-key": "\/run\/s\/ca\/kube-stand-in-client\.pem"/);
  assert.doesNotMatch((r as { note: string }).note, /no stand-in/);
  const failed = await writeLaunchKubeOverlay({ ...base, mintStandIn: () => null });
  assert.match((failed as { note: string }).note, /no stand-in client certificate could be made/);
  assert.doesNotMatch(writes[1]!, /client-key/);
  // A file with no certificate user needs none.
  dirs.length = 0;
  await writeLaunchKubeOverlay({ ...base, askOverlay: async () => ({ overlay: { ...ENTRIES, users: [] }, reason: "1 cluster" }) });
  assert.deepEqual(dirs, []);
});

test("mintStandInClientCert: a certificate and a key client-go can load, the key 0600, made once", { skip: spawnSync("openssl", ["version"]).status !== 0 ? "no openssl" : false }, () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-kube-standin-"));
  try {
    const a = mintStandInClientCert(dir);
    assert.ok(a);
    const cert = new X509Certificate(readFileSync(a.cert));
    assert.match(cert.subject, /CN=mandu-kube-stand-in/);
    const key = createPrivateKey(readFileSync(a.key));
    assert.ok(cert.checkPrivateKey(key), "the key is the certificate's");
    assert.equal(statSync(a.key).mode & 0o777, 0o600);
    // Not named like a key file: the session's catalog would serve kubectl
    // a placeholder copy (arbiter secret-catalog.ts shape:private-key-file).
    assert.doesNotMatch(a.key, /\.(key|p12|pfx|jks|keystore|ppk|kdbx)$|(^privkey|[._-]key)\.pem$/i);
    assert.deepEqual(mintStandInClientCert(dir), a, "the second call finds the first's");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
