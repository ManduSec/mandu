/**
 * rules-follow-change.test — an open Rules page shows a rule change made
 * elsewhere within one Home poll, across the REAL components (dashboard.md
 * §4.25 *Rules follows a change made elsewhere*). Mandu-new.
 *
 * Until 2026-10-28 Rules read your rules when it opened and never on a
 * poll: a file your agent made "No AI" through its policy tools, or an
 * Always allow given in another tab, stayed missing until a reload.
 *
 * Here a real ArbiterServer runs at the `secrets` axes with a policy.yaml on
 * disk and a registered `.env`; a real DashboardServer over the production
 * adapter (`makeApprovalsArbiter`) serves the Rules page, signed in, in
 * jsdom over the served page and script (served-page.ts):
 *
 *   R1  the agent tightens a rule over the data socket, as the policy tools
 *       do (a file made "No AI"): applied at once; the next poll draws its
 *       row on the open page, with the line "Your rules changed since this
 *       page was read." and its link to the change, and no navigation;
 *   R2  an Always allow given over the real approvals route (another tab's
 *       answer): the next poll draws its row, kept in Rules;
 *   R3  the oracle: no secret value in any response body the page read or
 *       in the DOM, and no token (`$MDU`) in the DOM.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests());

const KEY_VALUE = "sk_" + "live_rulesFollowStackCanary000000001";
const SESSION = `1791500000-${process.pid}`;

test("an open Rules page shows the agent's tightening and an Always allow given elsewhere within one poll (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-follow-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "ws", "deploy"), { recursive: true });
  const notes = join(home, "ws", "notes.md");
  const staging = join(home, "ws", "deploy", "staging.tfvars");
  const env = join(home, "ws", ".env");
  writeFileSync(notes, "notes\n");
  writeFileSync(staging, "region = \"eu\"\n");
  writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - { path: "${notes}", level: any-model }\n`);
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath, policyPollMs: 0, adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const agent = new ArbiterClient(sock); await agent.connect();
  const guard = new ArbiterClient(humanSock); await guard.connect();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  try {
    // A send question waits before the page opens (it is no rule yet).
    const reg = await agent.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const asked = await guard.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: "api.stripe.com", sessionKey: SESSION, scheme: "https" });
    assert.equal(asked.allow, false);
    const askId = String((asked as { approvalId?: string }).approvalId);
    assert.ok(askId.length > 0, "a question is filed");

    const bodies: string[] = [];
    await servedProductPage(base, "/rules", (doc) => /notes\.md/.test(doc.getElementById("page-rules").textContent), async (doc) => {
      const w = doc.defaultView;
      Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
      const homes = () => w.__homes as number;
      const poll = async () => {
        const n = homes();
        doc.dispatchEvent(new w.Event("visibilitychange"));
        await waitWhile(() => homes() <= n);
        await new Promise((r) => setTimeout(r, 50));
      };
      const page = () => doc.getElementById("page-rules").textContent as string;
      const line = () => doc.getElementById("rules-changed");
      w.__stayed = true;
      // The first poll after the page's own read gives the version it drew.
      await poll();
      assert.equal(line().hidden, true, "nothing changed yet");
      assert.doesNotMatch(page(), /staging\.tfvars/);

      // R1: the agent's tightening, applied at once.
      const r = await agent.policyPropose({ edits: [{ op: "lock-path", path: staging, level: "no-model" }], sessionKey: SESSION, reason: "keep the staging vars from the AI" });
      assert.ok("applied" in r && r.applied && r.changeId, `a tightening is applied at once: ${JSON.stringify(r)}`);
      await poll();
      await waitWhile(() => !/staging\.tfvars/.test(page()) || line().hidden);
      assert.match(line().textContent, /^Your rules changed since this page was read\. It shows them now\./);
      const link = line().querySelector("a");
      assert.ok(link, "the line links the change");
      assert.equal(link.textContent, "See the change in Approvals");
      assert.equal(link.getAttribute("data-ask"), r.changeId, "at the agent's change");
      assert.equal(w.__stayed, true, "no navigation: the same page");
      assert.match(w.location.pathname, /\/rules$/);

      // R2: an Always allow over the real approvals route.
      const always = await pageFetch(`${base}/api/egress/approvals/${askId}/approve`, { method: "POST", headers: { ...CSRF_ADMIN, Cookie: ADMIN_COOKIE } });
      assert.equal(always.status, 200, await always.text());
      await poll();
      await waitWhile(() => !/api\.stripe\.com/.test(doc.getElementById("rules-list").textContent));
      const row = [...doc.querySelectorAll("#rules-list .row")].find((x: any) => /api\.stripe\.com/.test(x.textContent)) as any;
      assert.match(row.textContent, /Always allowed/);

      // R3: the oracle over the DOM.
      const dom = doc.documentElement.outerHTML as string;
      assert.ok(!dom.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: the key's value is in the page");
      assert.doesNotMatch(doc.body.textContent, /\$MDU/, "no token in the page's text");
      assert.equal(w.__stayed, true);
    }, {
      headers: { Cookie: ADMIN_COOKIE },
      beforeScripts: (w) => {
        // Count the Home answers, and keep every body the page read.
        w.__homes = 0;
        const fetchIt = w.fetch;
        w.fetch = (url: string, init: unknown) => fetchIt(url, init).then((res: { json: () => Promise<unknown> }) => {
          const json = res.json;
          return { ...res, json: () => json().then((b) => { bodies.push(JSON.stringify(b)); if (String(url).endsWith("/api/home")) w.__homes++; return b; }) };
        });
      },
    });
    // R3: the oracle over every response body the page read.
    assert.ok(bodies.length > 5, "the page read its rules");
    for (const b of bodies) assert.ok(!b.includes(KEY_VALUE), `CONFIDENTIALITY VIOLATION: a response carries the key's value: ${b.slice(0, 200)}`);
  } finally {
    await dashboard.close();
    wired.close();
    guard.close();
    agent.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
