/**
 * live-kube-clients — kubectl and helm through the session proxy
 * (docs/design/confidentiality/kube-wire-release.md) measured with the REAL
 * clients against a REAL cluster under a launched session
 * (docs/design/testing/live-clients.md §3): until now its tests used the
 * loopback fake API servers of tests/stack/kube-wire-release.test.ts.
 *
 * The cluster (tests/lib/live-kube.ts liveKube): the CI guest's k3s fixture
 * at 10.201.0.2 (`scripts/ci/vm-run.sh --fixture k3s`), or any cluster off
 * this machine whose admin kubeconfig MANDU_LIVE_KUBECONFIG names. Set up
 * outside the session with the admin kubeconfig, as the human would: a
 * namespace of the run's own, a service account `agent` with the `admin`
 * role in it and a token for it (the bearer-token user), the admin's own
 * client certificate (the client-certificate user), and in a second
 * namespace a decoy pod behind a NodePort that prints every request it gets.
 *
 * The launch HOME's `~/.kube/config` holds the cluster's CA, the token and
 * the certificate and key, with a context for each user. The real launcher
 * in `secrets` around the stand-in `claude` (tests/lib/live-clients.ts) has
 * the agent run the real kubectl (auth whoami, apply, wait, get, a watch,
 * logs -f, exec with and without stdin, port-forward) and helm (install a
 * one-ConfigMap chart, list) on both contexts, then send the token's
 * placeholder to the node's kubelet port and to the decoy.
 *
 * Asserted: each command does what it does without Mandu; the token's
 * placeholder is withheld anywhere but its own API server (and the decoy's
 * log holds no token); THE ORACLE: neither the token nor the client key (in
 * any of secretForms' spellings, the key's PEM body too) in any request the
 * model received, in what the agent's world saw, in the session's events or
 * in the launch's output; the HOME file unchanged.
 *
 * Self-SKIPs without a cluster (outside the CI guest's k3s fixture, or with
 * an API server on this machine, which the proxy never dials), kubectl,
 * helm or curl, or the guard.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { get as httpGet } from "node:http";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";
import { caseExit, runLaunch, secretForms, type LiveLaunch } from "../../lib/live-clients.js";
import { kubeCases, liveKube, onThisMachine } from "../../lib/live-kube.js";

stateAxes("secrets"); // the confidentiality axis: a credential never reaches a model or an unbound host

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = join(HERE, "..", ".."); // tests/
const GUARD = pickGuard(resolve(PKG_ROOT, "..", "interceptors", "target"));
const KUBE = process.platform === "linux" ? liveKube() : "Linux only";

interface AdminView {
  server: string;
  caData: string;
  certData: string;
  keyData: string;
}

/** The admin kubeconfig's current cluster and user, read by kubectl itself. */
function adminView(admin: string, env: NodeJS.ProcessEnv): AdminView | string {
  const r = spawnSync("kubectl", ["--kubeconfig", admin, "config", "view", "--raw", "--minify", "-o", "json"], { encoding: "utf8", env });
  if (r.status !== 0) return `kubectl config view failed: ${r.stderr.trim().slice(0, 200)}`;
  const j = JSON.parse(r.stdout) as { clusters: Array<{ cluster: Record<string, string> }>; users: Array<{ user: Record<string, string> }> };
  const c = j.clusters[0]?.cluster ?? {};
  const u = j.users[0]?.user ?? {};
  if (!c["server"] || !c["certificate-authority-data"]) return "the admin kubeconfig's cluster has no server or certificate-authority-data";
  if (!u["client-certificate-data"] || !u["client-key-data"]) return "the admin kubeconfig's user has no client-certificate-data / client-key-data (the suite's certificate user)";
  return { server: c["server"], caData: c["certificate-authority-data"], certData: u["client-certificate-data"], keyData: u["client-key-data"] };
}

const skip = process.platform !== "linux" ? "Linux only"
  : typeof KUBE === "string" ? KUBE
    : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
      : false;

test("the real kubectl and helm work on a real cluster with a token and a client certificate, and neither reaches the model, the agent's world or an unbound host", { skip, timeout: 1_200_000 }, async () => {
  const kube = KUBE as Exclude<typeof KUBE, string>;
  const dir = mkdtempSync(join(tmpdir(), "mdu-lkc-"));
  // kubectl's cache and config outside any HOME of the session's.
  const env = { ...process.env, HOME: dir, KUBECACHEDIR: join(dir, "kcache") };
  const kc = (args: string[], input?: string): string => {
    const r = spawnSync("kubectl", ["--kubeconfig", kube.admin, ...args], { encoding: "utf8", env, input, timeout: 240_000 });
    if (r.status !== 0) throw new Error(`kubectl ${args.join(" ")}: ${(r.stderr || r.stdout).trim().slice(0, 1000)}`);
    return r.stdout;
  };
  const view = adminView(kube.admin, env);
  if (typeof view === "string") { rmSync(dir, { recursive: true, force: true }); assert.fail(view); }
  const server = new URL(view.server);
  if (onThisMachine(server.hostname)) {
    rmSync(dir, { recursive: true, force: true });
    assert.fail(`the cluster's API server ${server.host} is on this machine: the session proxy never dials it (kube-wire-release.md §8); give a cluster off this machine`);
  }
  const tag = randomBytes(4).toString("hex");
  const ns = `mdu-live-${tag}`;
  const decoyNs = `mdu-decoy-${tag}`;
  const decoyPort = 30000 + (randomBytes(2).readUInt16BE() % 2700);
  const pfPort = 20000 + (randomBytes(2).readUInt16BE() % 10000);
  let keep = false;
  try {
    // ── the human's setup, outside the session ──────────────────────────
    kc(["create", "namespace", ns]);
    kc(["create", "namespace", decoyNs]);
    kc(["-n", ns, "create", "serviceaccount", "agent"]);
    kc(["-n", ns, "create", "rolebinding", "agent-admin", "--clusterrole=admin", `--serviceaccount=${ns}:agent`]);
    const token = kc(["-n", ns, "create", "token", "agent", "--duration=2h"]).trim();
    assert.match(token, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, "a service-account token");
    kc(["apply", "-f", "-"], [
      "apiVersion: v1", "kind: Pod", `metadata: {name: decoy, namespace: ${decoyNs}, labels: {app: decoy}}`,
      "spec:", "  terminationGracePeriodSeconds: 0", "  containers:",
      `  - {name: c, image: "${kube.image}", imagePullPolicy: IfNotPresent, command: [sh, -c, 'while true; do printf "HTTP/1.0 200 OK\\r\\nContent-Length: 6\\r\\n\\r\\ndecoy\\n" | nc -l -p 8080; echo ---; done']}`,
      "---",
      "apiVersion: v1", "kind: Service", `metadata: {name: decoy, namespace: ${decoyNs}}`,
      `spec: {type: NodePort, selector: {app: decoy}, ports: [{port: 8080, targetPort: 8080, nodePort: ${decoyPort}}]}`,
      "",
    ].join("\n"));
    kc(["-n", decoyNs, "wait", "--for=condition=Ready", "pod/decoy", "--timeout=180s"]);

    const kubeconfig = [
      "apiVersion: v1", "kind: Config",
      "clusters:", "- name: live", "  cluster:", `    server: ${view.server}`, `    certificate-authority-data: ${view.caData}`,
      "users:",
      "- name: token-user", "  user:", `    token: ${token}`,
      "- name: cert-user", "  user:", `    client-certificate-data: ${view.certData}`, `    client-key-data: ${view.keyData}`,
      "contexts:",
      "- name: token", "  context:", "    cluster: live", "    user: token-user", `    namespace: ${ns}`,
      "- name: cert", "  context:", "    cluster: live", "    user: cert-user", `    namespace: ${ns}`,
      "current-context: token", "",
    ].join("\n");
    const keyPem = Buffer.from(view.keyData, "base64").toString("utf8");
    const secrets: Record<string, string[]> = {
      token: secretForms(token),
      "client key": [...secretForms(view.keyData), ...keyPem.split("\n").filter((l) => l.length >= 40 && !l.startsWith("-----"))],
    };
    const launch: LiveLaunch = {
      name: "kube",
      files: { ".kube/config": kubeconfig },
      cases: kubeCases({ ns, image: kube.image, nodeHost: server.hostname, decoyPort, pfPort }),
      env: { MDU_FAKE_CLAUDE_CMD_TIMEOUT_MS: "200000" },
    };
    // The user's side of port-forward: while the launch runs, GET the
    // forwarded port from outside the agent's world until the pod answers.
    let forwarded = "";
    const poll = setInterval(() => {
      if (forwarded !== "") return;
      const req = httpGet({ host: "127.0.0.1", port: pfPort, path: "/", timeout: 1000 }, (res) => {
        let body = "";
        res.on("data", (d: Buffer) => { body += d.toString("utf8"); });
        res.on("end", () => { if (/hello-from-pod/.test(body)) forwarded = body; });
      });
      req.on("error", () => {});
      req.on("timeout", () => req.destroy());
    }, 250);
    let l: Awaited<ReturnType<typeof runLaunch>>;
    try {
      l = await runLaunch(launch, join(dir, "scratch"));
    } finally {
      clearInterval(poll);
    }
    const decoyLog = (() => { try { return kc(["-n", decoyNs, "logs", "decoy"]); } catch (e) { return `(no log: ${(e as Error).message})`; } })();
    for (const [name, text] of Object.entries(l.cases)) console.error(`live-kube-clients ${name}: exit=${caseExit(text)} ${text.trim().split("\n").slice(0, 3).join(" | ").slice(0, 300)}`);
    console.error(`live-kube-clients decoy log: ${decoyLog.trim().split("\n").length} line(s)`);

    keep = true; // until every assertion below holds
    const diag = `\n--- launch (exit ${l.code}) ---\n${l.outTail.slice(-5000)}\n--- cases ---\n${Object.entries(l.cases).map(([k, v]) => `[${k}]\n${v}`).join("\n")}\n--- decoy ---\n${decoyLog.slice(-2000)}`;
    assert.equal(l.code, 0, `the launch failed${diag}`);
    assert.ok(l.guardLive, `the guard did not engage${diag}`);
    const c = l.cases;
    const ok = (name: string, re: RegExp): void => {
      assert.equal(caseExit(c[name]!), 0, `${name} failed${diag}`);
      assert.match(c[name]!, re, `${name}${diag}`);
    };
    assert.match(c["kube-twin"]!, /token: "?\$MDU:/, "the kubeconfig twin holds the token's placeholder");
    assert.match(c["kube-twin"]!, /^KUBECONFIG=\S+:/m, "KUBECONFIG lists the session's overlay first");
    ok("kube-whoami-token", new RegExp(`^system:serviceaccount:${ns}:agent$`, "m"));
    ok("kube-whoami-cert", /^system:admin$/m);
    ok("kube-apply", /pod\/ticker created[\s\S]*pod\/web created/);
    ok("kube-wait", /pod\/ticker condition met[\s\S]*pod\/web condition met|pod\/web condition met[\s\S]*pod\/ticker condition met/);
    ok("kube-get", /^pod\/ticker\npod\/web$/m);
    ok("kube-get-cert", /^pod\/ticker\npod\/web$/m);
    ok("kube-watch", /^ticker\s/m);
    ok("kube-logs-f", /^tick-\d+\ntick-\d+\ntick-\d+$/m);
    ok("kube-exec", /^exec-ok 42$/m);
    ok("kube-exec-cert", /^cert-exec-ok$/m);
    ok("kube-exec-stdin", /^from-stdin$/m);
    ok("kube-port-forward", /Handling connection for \d+/);
    assert.match(forwarded, /hello-from-pod/, `the forwarded port answered with the pod's page${diag}`);
    assert.notEqual(caseExit(c["kube-port-forward-in-session"]!), 0, `an agent program reached a loopback port that is not a session service${diag}`);
    assert.match(c["kube-port-forward-in-session"]!, /Permission denied|Couldn't connect/);
    ok("kube-token-own-api", /"major": "1"/);
    ok("helm-install", /hello-from-helm/);
    ok("helm-list", /"name":"mdu-live"[^}]*"status":"deployed"/);
    ok("helm-list-cert", /^mdu-live$/m);
    assert.match(c["kube-token-kubelet"]!, /code=403/, `the token's placeholder at the kubelet's port is withheld${diag}`);
    assert.doesNotMatch(c["kube-token-decoy"]!, /^decoy$/m, `the decoy answered a request carrying the token's placeholder${diag}`);

    // ── THE ORACLE ────────────────────────────────────────────────────────
    assert.ok(l.model.some((b) => b.includes('"tool_result"')), "the agent sent its tool results to the model");
    assert.ok(l.model.some((b) => b.includes("$MDU")), "the model got placeholders");
    const where: Array<[string, string]> = [
      ["a request the model received", l.model.join("\n")],
      ["what the agent's world saw", Object.values(l.cases).join("\n")],
      ["the session's events", l.events],
      ["the launch's output", l.outTail],
      ["the decoy (an unbound host)", decoyLog],
    ];
    for (const [name, forms] of Object.entries(secrets)) {
      for (const f of forms) for (const [w, text] of where) assert.ok(!text.includes(f), `the ${name} in ${w}`);
    }
    assert.equal(l.homeAfter[".kube/config"], kubeconfig, "~/.kube/config unchanged");
    keep = false;
  } finally {
    spawnSync("kubectl", ["--kubeconfig", kube.admin, "delete", "namespace", ns, decoyNs, "--wait=false"], { env, stdio: "ignore", timeout: 60_000 });
    if (keep) console.error(`live-kube-clients: kept ${dir}`);
    else rmSync(dir, { recursive: true, force: true });
  }
});
