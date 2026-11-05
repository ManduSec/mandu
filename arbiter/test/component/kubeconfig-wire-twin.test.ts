/**
 * kubeconfig-wire-twin.test.ts — kube-wire-release.md §2 over the real IPC:
 * kubectl and helm read the launch HOME's `~/.kube/config` as its twin, with
 * no ask, once a launcher built the session's KUBECONFIG overlay from it
 * (`kubeOverlay`) for a session whose proxy inspects TLS
 * (`registerWireRelease`).
 *
 * Found by the live kubectl run (docs/design/testing/live-clients.md §3.3,
 * 2026-10-25): kubectl is a known consumer of the file and not a vetted
 * reader, so decideSecretOpen ASKED for the raw file; a session with nobody
 * to answer held kubectl's open for the ask's timeout and then refused it
 * (`permission denied`), and an answered Allow would have handed kubectl the
 * raw token the wire release exists to keep out of the agent's world.
 *
 *   - before the overlay (or in a session whose proxy nobody vouched for):
 *     kubectl is asked, as before (the twin needs the overlay to work);
 *   - after it: kubectl and helm get the twin, no taint, no approval row;
 *   - cat (a printer) gets the twin throughout.
 *
 * Mandu-new test. Axes stated: `secrets` (confidentiality on, integrity off).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const TOKEN = "kubeTok_WIRETWIN_canary_9d2f";
const S = "sess-kube-wire";
const KUBECONFIG = [
  "apiVersion: v1", "kind: Config",
  "clusters:", "- name: c", "  cluster:", "    server: https://k8s.example:6443",
  "users:", "- name: u", "  user:", `    token: ${TOKEN}`,
  "contexts:", "- name: x", "  context:", "    cluster: c", "    user: u",
  "current-context: x", "",
].join("\n");

test("kubectl and helm read the HOME kubeconfig's twin, unasked and untainted, once the session's overlay is built; before it they are asked", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-kube-wire-"));
  const home = join(dir, "home");
  mkdirSync(join(home, ".kube"), { recursive: true });
  const file = join(home, ".kube", "config");
  writeFileSync(file, KUBECONFIG, { mode: 0o600 });
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${JSON.stringify(file)}\n    level: no-model\n`);
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "human", "h.sock");
  const s = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath: policy });
  await s.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const h = new ArbiterClient(humanSock); await h.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  const open = (procKey: string, exe: string, session = S) =>
    h.decideSecretOpen({ path: file, exe, isAgent: false, exeSystem: true, openerEnv: [], procKey, session, ask: "known" });
  try {
    const reg = await h.registerSecret({ path: file, home, sessionKey: S });
    assert.ok(reg.symbol && reg.twin, reg.reason);
    assert.ok(!reg.twin!.includes(TOKEN), "the twin holds no token");

    // Before the overlay: a known, unvetted consumer is asked.
    await h.registerWireRelease(S, true);
    const before = await open("kubectl-0", "/usr/bin/kubectl");
    assert.equal(before.verdict, "ask", before.reason);
    assert.equal((await open("cat-0", "/usr/bin/cat")).verdict, "twin", "a printer reads the twin");

    // The launcher builds the overlay (kube-overlay.ts): the twin, unasked.
    const ov = await h.kubeOverlay(file, home);
    assert.ok(ov.overlay, ov.reason);
    for (const [k, exe] of [["kubectl-1", "/usr/bin/kubectl"], ["helm-1", "/usr/local/bin/helm"]] as const) {
      const d = await open(k, exe);
      assert.equal(d.verdict, "twin", `${exe}: ${d.reason}`);
      assert.match(d.reason, /served its twin: the session KUBECONFIG overlay routes its clusters through the session proxy/);
      assert.equal((await data.processSecretTaint(k)).level, null, `${exe} holds no raw byte`);
    }
    // No approval was raised for the overlay's opens.
    const pending = await admin.egressApprovals("pending");
    assert.equal(pending.filter((e) => /kubectl-1|helm-1/.test(JSON.stringify(e))).length, 0);
    // A session whose proxy nobody vouched for: asked, as before.
    assert.equal((await open("kubectl-2", "/usr/bin/kubectl", "sess-other")).verdict, "ask");
    // The session's proxy no longer inspects: asked again.
    await h.registerWireRelease(S, false);
    assert.equal((await open("kubectl-3", "/usr/bin/kubectl")).verdict, "ask");
  } finally {
    data.close(); h.close(); admin.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
