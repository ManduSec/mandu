/**
 * wide-change-why — a wide rule change says what it opens, across the REAL
 * components (dashboard.md §4.25 *A wide change says what is open*).
 * Mandu-new.
 *
 * Until 2026-10-19 the foot of every wide change on Approvals read "This
 * change has no limit on one side.", the code's own wording, beside the
 * Type ALLOW field: it said neither which side was open nor why the word
 * was asked. A real ArbiterServer (secrets) holds a policy.yaml with a
 * `.env` holding a value; the agent's own channel asks the real
 * policyPropose op for two wide changes, held for the person. A real
 * DashboardServer over the production adapter serves Approvals (its own
 * index.html and home.js in jsdom, signed in):
 *
 *   W1  the connect to any address: the foot reads "This lets your agent's
 *       programs connect to any address. Type ALLOW if you mean it.";
 *   W2  the send to anywhere: the foot names its source and "anywhere";
 *   W3  the gate is as before: each card's Allow stays off until ALLOW is
 *       typed (whole, in any case), and the server still flags each change
 *       wide;
 *   W4  Allow with ALLOW typed records the answer: the connect change is
 *       approved and leaves the pending list; Not now on the other denies it;
 *   W5  the oracle: no page or answer read here carries the file's value or
 *       a minted token.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
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
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const VALUE = `sk_live_wideWhyCanary_${process.pid}_0`;
/** A minted token. */
const TOKEN = /\$MDU:[A-Za-z_][A-Za-z0-9_-]*\[[0-9a-f]{4,8}\]/;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

test("Approvals over the real arbiter: a wide change's foot names what it opens; Allow still waits for ALLOW and records the answer", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-wide-why-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const env = join(home, ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, ["version: 1", "paths:", `  - { path: "${env}", level: no-model }`, ""].join("\n"));
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const agent = new ArbiterClient(socketPath);
  await agent.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath, HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const signedIn = { Cookie: ADMIN_COOKIE };
  const noValue = (body: string, where: string) => {
    assert.ok(!body.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the file's value`);
    assert.doesNotMatch(body, TOKEN, `${where} carries no token`);
  };
  const pending = async (): Promise<Array<{ id: string; overBroad: boolean; status: string }>> => {
    const r = await pageFetch(`${base}/api/policy/proposals?status=pending`, { headers: CSRF_ADMIN });
    const body = await r.text();
    assert.equal(r.status, 200, body.slice(0, 200));
    noValue(body, "the pending rule changes");
    return (JSON.parse(body) as { proposals: Array<{ id: string; overBroad: boolean; status: string }> }).proposals;
  };
  try {
    const connect = await agent.policyPropose({ edits: [{ op: "allow-connect", host: "*" }], reason: "reach the API", sessionKey: "s-wide" });
    assert.ok(!connect.applied && "proposalId" in connect, `a wide change waits for the person: ${JSON.stringify(connect)}`);
    const send = await agent.policyPropose({ edits: [{ op: "release", from: { host: "docs.python.org" }, to: { host: "*" }, mode: "allow" }], reason: "share the docs", sessionKey: "s-wide" });
    assert.ok(!send.applied && "proposalId" in send, `a wide send waits for the person: ${JSON.stringify(send)}`);
    // W3: the server flags both wide, as before.
    assert.deepEqual((await pending()).map((p) => [p.id, p.overBroad]).sort(), [[connect.proposalId, true], [send.proposalId, true]].sort());

    const card = (doc: Doc, id: string) => doc.querySelector(`#approvals-proposals [data-id="${id}"]`);
    await servedProductPage(base, "/approvals", (doc: Doc) => !!card(doc, connect.proposalId) && !!card(doc, send.proposalId), async (doc: Doc) => {
      const win = doc.defaultView;
      const foot = (id: string) => card(doc, id).querySelector(".wide-why").textContent.replace(/\s+/g, " ").trim();
      // W1, W2: what each opens, in its row's words.
      assert.equal(foot(connect.proposalId), "This lets your agent's programs connect to any address. Type ALLOW if you mean it.");
      assert.equal(foot(send.proposalId), "This lets masked data from docs.python.org be sent anywhere. Type ALLOW if you mean it.");
      assert.match(card(doc, connect.proposalId).querySelector(".proposal-rows").textContent, /connect to any address/, "the row says the same place");
      assert.doesNotMatch(doc.body.textContent, /no limit on one side/, "the code's own wording is gone");
      noValue(doc.body.textContent, "the rendered Approvals page");
      // W3: Allow waits for the whole word (in any case since *The typed
      // ALLOW takes any case*).
      for (const id of [connect.proposalId, send.proposalId]) {
        const c = card(doc, id);
        const allow = c.querySelector(".proposal-allow");
        const input = c.querySelector(".proposal-confirm");
        assert.equal(allow.disabled, true, `${id}: Allow is off before the word`);
        input.value = "ALLO";
        input.dispatchEvent(new win.Event("input"));
        assert.equal(allow.disabled, true, `${id}: the word must be typed whole`);
      }
      // W4: Allow with ALLOW typed records the answer.
      const c = card(doc, connect.proposalId);
      const input = c.querySelector(".proposal-confirm");
      input.value = "ALLOW";
      input.dispatchEvent(new win.Event("input"));
      const allow = c.querySelector(".proposal-allow");
      assert.equal(allow.disabled, false, "ALLOW typed: Allow turns on");
      allow.click();
      await waitWhile(() => !!card(doc, connect.proposalId));
      assert.equal(card(doc, connect.proposalId), null, "the answered card leaves the page");
      const notNow = ([...card(doc, send.proposalId).querySelectorAll("button")] as Doc[]).find((b) => b.textContent === "Not now");
      notNow.click();
      await waitWhile(() => !!card(doc, send.proposalId));
      noValue(doc.body.textContent, "the rendered Approvals page after the answers");
    }, { headers: signedIn, css: "" });

    assert.deepEqual(await pending(), [], "both answers were recorded");
    const all = await pageFetch(`${base}/api/policy/proposals`, { headers: CSRF_ADMIN });
    const allBody = await all.text();
    noValue(allBody, "every rule change");
    const statuses = new Map((JSON.parse(allBody) as { proposals: Array<{ id: string; status: string }> }).proposals.map((p) => [p.id, p.status]));
    assert.equal(statuses.get(connect.proposalId), "approved", "Allow approved the connect change");
    assert.equal(statuses.get(send.proposalId), "denied", "Not now denied the send");
  } finally {
    await dashboard.close();
    wired.close();
    agent.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
