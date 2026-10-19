/**
 * home-rule-change-waiting.test — Home's hero counts the rule changes
 * waiting, as the Approvals badge does, across the REAL components
 * (dashboard.md §4.25, the verdict ladder's `waiting`). Mandu-new.
 *
 * Until 2026-10-18 the hero counted questions alone: with one rule change
 * waiting it stayed green ("Your secrets are guarded.") over "Approvals
 * waiting (1)" and a badge of 1.
 *
 * A real ArbiterServer (`secrets` axes), a real `policyPropose` from a
 * session (a relaxation, so it waits for the human), and a real
 * DashboardServer over the production adapter (`makeApprovalsArbiter`, whose
 * `policyProposals` forwarding has its own parity test,
 * dashboard-policy-proposals-parity):
 *
 *   R1  the served /api/home says "A rule change is waiting for you." with
 *       "Your rules stay as they are until you answer." and the Secrets
 *       disclosure, and its count is the listing's;
 *   R2  the served product page (its own index.html and home.js in jsdom)
 *       draws the hero amber, and the number it says equals the badge's;
 *   R3  the oracle: the hero (and the whole /api/home) carries neither the
 *       proposal's file, its hosts nor its reason, nor the secret's value;
 *   R4  approved over the dashboard's real route, the hero is green again
 *       and the badge is gone.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = `1791880000-${process.pid}`;
const KEY_VALUE = `sk_live_homeRuleChangeCanary_${process.pid}_0000`;
const HOST = "hooks.rule-change-canary.example";
const REASON = "the deploy hook needs the key, homeRuleChangeReasonCanary";

test("a rule change waiting turns Home's hero amber with the badge's count, says no proposal's words, and approved over the real route it is green again (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-home-rule-change-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const env = join(home, "proj", ".env");
  writeFileSync(env, `DEPLOY_KEY=${KEY_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - { path: "${env}", level: no-model }\n`);
  const dataSock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath, policyPollMs: 0, adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const data = new ArbiterClient(dataSock);
  await data.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter,
    policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const homeVm = async (): Promise<{ vm: HomeVM; body: string }> => {
    const r = await pageFetch(`${base}/api/home`, { headers: { Cookie: ADMIN_COOKIE } });
    const body = await r.text();
    assert.equal(r.status, 200, body);
    return { vm: JSON.parse(body) as HomeVM, body };
  };
  try {
    // Nothing waits yet: the Secrets hero.
    const before = (await homeVm()).vm;
    assert.equal(before.protection.level, "secrets");
    assert.equal(before.verdict, "secrets-only");

    // The agent's session asks to let the secret go to a new host: a
    // relaxation, so it waits for the human.
    const asked = await data.policyPropose({ edits: [{ op: "lock-path", path: env, level: "no-model", bindings: [HOST] }], sessionKey: SESSION, reason: REASON });
    assert.ok("proposalId" in asked && asked.proposalId, `it waits for the human: ${JSON.stringify(asked)}`);
    const id = String(asked.proposalId);

    // R1: the served /api/home.
    const { vm, body } = await homeVm();
    assert.deepEqual(vm.waiting, [], "no question waits");
    assert.equal(vm.verdict, "waiting");
    assert.equal(vm.headline, "A rule change is waiting for you.");
    assert.equal(vm.sentence, "Your rules stay as they are until you answer. Untrusted content is not masked in this mode.");
    assert.equal(vm.ruleChangesWaiting, 1);
    const listed = JSON.parse(await (await pageFetch(`${base}/api/policy/proposals?status=pending`, { headers: { Cookie: ADMIN_COOKIE } })).text()) as { proposals: Array<{ id: string }> };
    assert.deepEqual(listed.proposals.map((p) => p.id), [id], "the hero counts what Approvals lists");

    // R3: the oracle. Home carries a count, never the proposal's words.
    for (const leak of [HOST, REASON, "homeRuleChangeReasonCanary", env, "~/proj/.env", id]) {
      assert.ok(!body.includes(leak), `/api/home carries no proposal text: ${leak}`);
    }
    assert.ok(!body.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: /api/home carries the secret's value");
    assert.doesNotMatch(body, /\$MDU/, "the product's home carries no token");

    // R2: the served page, once both reads settle: amber, and its number is the badge's.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    await servedProductPage(base, "/", (doc: Doc) => doc.getElementById("hero").dataset.verdict === "waiting" && doc.getElementById("nav-approvals-count").textContent === "1", (doc: Doc) => {
      assert.equal(doc.getElementById("hero-headline").textContent, "A rule change is waiting for you.");
      assert.equal(doc.getElementById("hero-sentence").textContent, "Your rules stay as they are until you answer. Untrusted content is not masked in this mode.");
      assert.equal(doc.getElementById("nav-approvals-count").hidden, false);
      assert.equal(doc.getElementById("home-waiting-title").textContent, "Approvals waiting (1)");
      const hero = doc.getElementById("hero").textContent;
      for (const leak of [HOST, REASON, env, KEY_VALUE]) assert.ok(!hero.includes(leak), `the drawn hero carries no proposal text: ${leak}`);
      assert.ok(!doc.body.textContent.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: the rendered page carries the secret's value");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // R4: approved over the dashboard's real route, the hero is green again.
    const ok = await pageFetch(`${base}/api/policy/proposals/${id}`, { method: "POST", body: JSON.stringify({ verdict: "approved" }), headers: { ...CSRF_ADMIN, "content-type": "application/json" } });
    assert.equal(ok.status, 200, await ok.text());
    const after = (await homeVm()).vm;
    assert.equal(after.verdict, "secrets-only");
    assert.equal(after.headline, "Your secrets are guarded.");
    assert.equal(after.ruleChangesWaiting, 0);
    await servedProductPage(base, "/", (doc: Doc) => doc.getElementById("hero").dataset.verdict === "secrets-only", (doc: Doc) => {
      assert.equal(doc.getElementById("hero-headline").textContent, "Your secrets are guarded.");
      assert.equal(doc.getElementById("nav-approvals-count").hidden, true, "no badge once nothing waits");
    }, { headers: { Cookie: ADMIN_COOKIE } });
  } finally {
    await dashboard.close();
    wired?.close();
    data.close();
    await arbiter.close();
    resetCurrentPolicyForTests();
    rmSync(tmp, { recursive: true, force: true });
  }
});
