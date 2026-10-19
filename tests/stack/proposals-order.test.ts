/**
 * proposals-order.test — a read of Approvals' rule-change lists asked
 * before your answer never draws over it, across the REAL components
 * (dashboard.md §4.25 *A read asked before your answer to a rule change
 * never draws over it*). Mandu-new.
 *
 * *Rule changes your agent asked for* is read by every Home poll and by the
 * read after an Allow; *Rule changes* (the history) by every poll on
 * Approvals and after an Undo. Until 2026-10-12 the answer that came LAST
 * drew, even when its read was asked first: on a slow network a request you
 * allowed came back as waiting, with live Allow and Not now, and a change
 * you undid got its Undo back. Here a real ArbiterServer runs at the
 * `secrets` axes with two files policy.yaml makes `no-model`; the agent asks
 * (over the data socket) to let each be sent to a host, which waits for the
 * human, and locks a third file, which it may do on its own (an undoable
 * change). A real DashboardServer reaches it over the production adapter
 * (`makeApprovalsArbiter`), and the served Approvals page (its own
 * index.html and home.js in jsdom, signed in) reaches the dashboard through
 * a relay that holds one answer back (tests/lib/holding-relay.ts):
 *
 *   P1  a poll's read of the requests is held; Allow on the first request:
 *       the server approves it, and the read after the answer draws only
 *       the other one;
 *   P2  the held read (both waiting) comes: the answered request is never
 *       drawn again, no live Allow or Not now for it, the badge counts one;
 *   P3  a poll's history read is held; Undo on the agent's lock: the server
 *       undoes it, and the read after the Undo says "Undone";
 *   P4  the held read (Undo still on) comes: the row still says "Undone"
 *       with no Undo;
 *   P5  no unhandled rejection; the oracle: no page or answer read here
 *       carries a file's value or a token.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { holdingRelay } from "../lib/holding-relay.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const ENV_VALUE = "proposalsOrderStackEnvValue000000001";
const CONF_VALUE = "proposalsOrderStackConfValue00000002";
const LOCK_VALUE = "proposalsOrderStackLockValue00000003";
const SESSION = "proposals-order-session";
const PENDING = "/api/policy/proposals?status=pending";
// The page asks for one more than it draws (dashboard.md §4.25 *Past the
// newest 20*): its Show more is offered when that one came.
const CHANGES = "/api/policy/changes?limit=21";
/** How long a page is given to draw a held answer it must drop: a page
 *  that draws it changes the list within this, a page that drops it never
 *  does. */
const SETTLE_MS = 1500;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const cards = (doc: Doc): Doc[] => [...doc.querySelectorAll("#approvals-proposals .proposal")];
const cardOf = (doc: Doc, id: string) => cards(doc).find((c) => c.dataset.id === id);
const rowOf = (doc: Doc, id: string) => [...doc.querySelectorAll("#approvals-rule-history .row")].find((r: Doc) => r.dataset.id === id);
const button = (root: Doc, label: string) => root && [...root.querySelectorAll("button")].find((b: Doc) => b.textContent === label);
const liveAnswers = (doc: Doc): Doc[] => [...doc.querySelectorAll("#approvals-proposals button")].filter((b: Doc) => !b.disabled);
const badge = (doc: Doc): string => doc.getElementById("nav-approvals-count").textContent;
/** A poll, as a return to the tab makes one (the page's 10 s poll is inert here). */
const poll = (doc: Doc) => doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
/** Press a button the way a keyboard does: the focus on it first. */
function press(b: Doc): void {
  assert.ok(b && !b.disabled, "the button is drawn and on");
  b.focus();
  b.click();
}

test("Approvals over the real arbiter: a read asked before your Allow or Undo never draws the request as waiting again nor the Undo back; no secret anywhere", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-proposals-order-"));
  const home = join(tmp, "home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const env = join(repo, ".env");
  const conf = join(repo, "deploy.conf");
  const lock = join(repo, "notes.txt");
  writeFileSync(env, `DB_PASSWORD=${ENV_VALUE}\n`);
  writeFileSync(conf, `API_TOKEN=${CONF_VALUE}\n`);
  writeFileSync(lock, `${LOCK_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n  - path: ${conf}\n    level: no-model\n`);
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
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
  const port = await dashboard.listen(0);
  const relay = await holdingRelay(port);
  const bodies: string[] = [];
  const read = async (path: string) => {
    const r = await pageFetch(`http://127.0.0.1:${port}${path}`, { headers: CSRF_ADMIN });
    const text = await r.text();
    bodies.push(text);
    assert.equal(r.status, 200, `${path}: ${text}`);
    return JSON.parse(text);
  };
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const rendered: string[] = [];
  try {
    // The agent asks to let each file be sent to a host: both wait for you.
    const first = await data.policyPropose({ edits: [{ op: "lock-path", path: env, level: "no-model", bindings: ["api.stripe.com"] }], sessionKey: SESSION, reason: "deploy needs it" });
    const second = await data.policyPropose({ edits: [{ op: "lock-path", path: conf, level: "no-model", bindings: ["api.github.com"] }], sessionKey: SESSION, reason: "ci needs it" });
    assert.ok("proposalId" in first && "proposalId" in second, `each binding waits for the human: ${JSON.stringify([first, second])}`);
    const firstId = String(first.proposalId);
    const secondId = String(second.proposalId);
    // The agent locks a third file on its own: a change you can undo.
    const locked = await data.policyPropose({ edits: [{ op: "lock-path", path: lock, level: "no-model" }], sessionKey: SESSION });
    assert.ok(locked.applied && "changeId" in locked && locked.changeId, `a tightening applies at once: ${JSON.stringify(locked)}`);
    const lockId = String(locked.changeId);

    const ready = (doc: Doc) => cards(doc).length === 2 && !!button(rowOf(doc, lockId), "Undo");
    await servedProductPage(relay.base, "/approvals", ready, async (doc: Doc) => {
      const keep = () => rendered.push(doc.documentElement.outerHTML);
      assert.equal(badge(doc), "2", "two requests wait");
      keep();

      // P1: a poll's read of the requests is held; Allow on the first.
      const before = relay.holdNext(PENDING);
      poll(doc);
      assert.equal(await before.asked, 200, "the poll's read was answered with both waiting, and held");
      press(button(cardOf(doc, firstId), "Allow"));
      await waitWhile(() => !!cardOf(doc, firstId));
      assert.equal(cardOf(doc, firstId), undefined, "the read after the answer draws without it");
      assert.ok(cardOf(doc, secondId), "the other still waits");
      assert.deepEqual((await read(PENDING)).proposals.map((p: { id: string }) => p.id), [secondId], "the server approved it");
      assert.match(readFileSync(policyPath, "utf8"), /api\.stripe\.com/, "the Allow is in policy.yaml");
      assert.equal(badge(doc), "1");
      keep();

      // P2: the held read, both waiting, comes, and is dropped.
      await before.release();
      await waitWhile(() => !cardOf(doc, firstId), SETTLE_MS);
      assert.equal(cardOf(doc, firstId), undefined, "the answered request is never drawn as waiting again");
      assert.deepEqual(liveAnswers(doc).map((b: Doc) => b.closest(".proposal").dataset.id), [secondId, secondId], "only the other request's Allow and Not now are live");
      assert.equal(badge(doc), "1", "the badge never counts it again");
      keep();

      // P3: a poll's history read is held; Undo on the agent's lock.
      const older = relay.holdNext(CHANGES);
      poll(doc);
      assert.equal(await older.asked, 200, "the poll's history read was answered with Undo on, and held");
      press(button(rowOf(doc, lockId), "Undo"));
      await waitWhile(() => !/Undone$/.test(rowOf(doc, lockId)?.textContent ?? ""));
      assert.match(rowOf(doc, lockId).textContent, /Undone$/, "the read after the Undo says so");
      assert.equal(button(rowOf(doc, lockId), "Undo"), undefined);
      const lockRow = (await read(CHANGES)).changes.find((c: { id: string }) => c.id === lockId);
      assert.equal(lockRow?.undoable, false, "the server undid it");
      keep();

      // P4: the held read, Undo still on, comes, and is dropped.
      await older.release();
      await waitWhile(() => !button(rowOf(doc, lockId), "Undo"), SETTLE_MS);
      assert.match(rowOf(doc, lockId).textContent, /Undone$/, "it still says Undone");
      assert.equal(button(rowOf(doc, lockId), "Undo"), undefined, "no Undo on a change already undone");
      keep();
    }, { headers: { Cookie: ADMIN_COOKIE } });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // P5: the oracle on every page drawn and every answer read above.
    assert.equal(rendered.length, 5);
    for (const text of [...rendered, ...bodies]) {
      for (const value of [ENV_VALUE, CONF_VALUE, LOCK_VALUE]) assert.ok(!text.includes(value), "no file's value in a page or an answer");
      assert.doesNotMatch(text, /\$MDU/, "nor a token");
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await relay.close();
    await dashboard.close();
    data.close();
    wired?.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
