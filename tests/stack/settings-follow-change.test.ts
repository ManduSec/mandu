/**
 * settings-follow-change.test — an open Settings page shows a sensitivity
 * label and a model changed elsewhere within one Home poll, across the REAL
 * components (dashboard.md §4.25 *Settings follows a change made
 * elsewhere*; queue item #238). Mandu-new.
 *
 * Until 2026-11-04 Settings read its policy cards when it opened and after
 * its own changes, never on a poll: a label given a level, or a model added,
 * in a second window stayed missing until a reload, and the person learned
 * of it only from a refused Save.
 *
 * Here a real ArbiterServer runs at the `secrets` axes with a policy.yaml on
 * disk and a registered key; a real DashboardServer over the production
 * adapter (`makeApprovalsArbiter`) serves the Settings page, signed in, in
 * jsdom over the served page and script (served-page.ts):
 *
 *   C1  another window maps a sensitivity label (the admin channel, as its
 *       Settings would): the next poll draws the label at its level on the
 *       open page, with the line "Your sensitivity labels changed since this
 *       page was read." and no navigation; Models says nothing;
 *   C2  another window adds a model (asked, then approved, as a Settings
 *       change that loosens protection is): the next poll draws its row,
 *       with the Models line;
 *   C3  the oracle: no secret value in any response body the page read or
 *       in the DOM, and no token (`$MDU`) in the DOM.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_" + "live_settingsFollowStackCanary0000001";
const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const GEN = "0e4c2b8a-3b1d-4f5e-9a6b-7c8d9e0f1a2b";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const labelRow = (doc: Doc, id: string) => [...doc.querySelectorAll("#settings-labels .label-row")].find((r: Doc) => r.dataset.id === id);
const modelRow = (doc: Doc, name: string) => [...doc.querySelectorAll("#settings-models .model-row")].find((r: Doc) => r.dataset.name === name);

test("an open Settings page shows a label mapped and a model added in another window within one poll (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-settings-follow-"));
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "sensitivity_labels:",
    `  - { id: "${HC}", name: Highly Confidential, level: local-model }`,
    "",
  ].join("\n"));
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
    log: () => {},
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath); await data.connect();
  const admin = new ArbiterClient(adminSock); await admin.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  /** Another window's Settings: a change applied on the admin channel,
   *  approved when it asks, as that window's "… anyway" would. */
  const elsewhere = async (edits: unknown[]) => {
    const r = await admin.policyPropose({ edits, requestedBy: "settings" });
    if (r.applied) return;
    assert.ok("proposalId" in r, JSON.stringify(r));
    const done = await admin.resolvePolicyProposal(r.proposalId, "approved", "human:settings");
    assert.ok(done.changeId, JSON.stringify(done));
  };
  try {
    await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    const bodies: string[] = [];
    const ready = (doc: Doc) => !!labelRow(doc, HC) && !doc.getElementById("model-open").hidden;
    await servedProductPage(base, "/settings", ready, async (doc) => {
      const w = doc.defaultView;
      Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
      const homes = () => w.__homes as number;
      const poll = async () => {
        const n = homes();
        doc.dispatchEvent(new w.Event("visibilitychange"));
        await waitWhile(() => homes() <= n);
        await new Promise((r) => setTimeout(r, 50));
      };
      const line = (card: string) => doc.getElementById(card + "-changed");
      w.__stayed = true;
      // The first poll after the page's own reads gives the version they drew.
      await poll();
      for (const card of ["models", "labels", "prompt"]) assert.equal(line(card).hidden, true, `${card}: nothing changed yet`);
      assert.equal(labelRow(doc, GEN), undefined);

      // C1: a label mapped in another window.
      await elsewhere([{ op: "map-sensitivity-label", id: GEN, name: "General", level: "no-model" }]);
      await poll();
      await waitWhile(() => !labelRow(doc, GEN) || line("labels").hidden);
      assert.equal(labelRow(doc, GEN).querySelector("select.label-level").value, "no-model", "drawn at its level");
      assert.equal(line("labels").textContent, "Your sensitivity labels changed since this page was read. It shows them now.");
      assert.equal(line("models").hidden, true, "Models did not change: no line");
      assert.equal(doc.getElementById("labels-notice").hidden, true, "the notice place is left to the page's own changes");
      assert.equal(w.__stayed, true, "no navigation: the same page");
      assert.match(w.location.pathname, /\/settings$/);

      // C2: a model added in another window.
      assert.equal(modelRow(doc, "lab"), undefined);
      await elsewhere([{ op: "add-model", name: "lab", url: "http://127.0.0.1:11434", local: true }]);
      await poll();
      await waitWhile(() => !modelRow(doc, "lab") || line("models").hidden);
      assert.equal(line("models").textContent, "Your models changed since this page was read. It shows them now.");
      assert.equal(w.__stayed, true);

      // C3: the oracle over the DOM.
      const dom = doc.documentElement.outerHTML as string;
      assert.ok(!dom.includes(KEY), "CONFIDENTIALITY VIOLATION: the key's value is in the page");
      assert.doesNotMatch(doc.body.textContent, /\$MDU/, "no token in the page's text");
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
    // C3: the oracle over every response body the page read.
    assert.ok(bodies.length > 5, "the page read its cards");
    for (const b of bodies) assert.ok(!b.includes(KEY), `CONFIDENTIALITY VIOLATION: a response carries the key's value: ${b.slice(0, 200)}`);
  } finally {
    await dashboard.close();
    wired.close();
    admin.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
