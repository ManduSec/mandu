/**
 * waiting-line-rule-change.test — a list with no question never says
 * "Nothing is waiting for you." while a rule change your agent asked for
 * waits, across the REAL components (dashboard.md §4.25 *An empty list
 * never says nothing waits over a rule change*). Mandu-new.
 *
 * The nav badge and Home's "Approvals waiting (N)" count the questions and
 * the rule changes; the questions list's empty line knew only the
 * questions. Until 2026-10-12 Home read "Approvals waiting (1)", then
 * "Nothing is waiting for you.", and Approvals drew the request's live
 * Allow / Not now with "Nothing is waiting for you." under it. Here a real
 * ArbiterServer runs at the `secrets` axes with two files policy.yaml makes
 * `no-model`; the agent asks (over the data socket) to let one be sent to a
 * host, which waits for the human. A real DashboardServer reaches it over
 * the production adapter (`makeApprovalsArbiter`), and the served product
 * page (its own index.html and home.js in jsdom, signed in) draws:
 *
 *   W1  Home: "Approvals waiting (1)", the line "No question is waiting for
 *       you." and the link "1 rule change your agent asked for is in
 *       Approvals"; never "Nothing is waiting";
 *   W2  Approvals: the request's card, and under it the same line;
 *   W3  Not now: the server records it, the card goes, the badge is 0 and
 *       the line reads "Nothing is waiting for you.";
 *   W4  with the focus on that line (as an answer's landing leaves it), the
 *       agent asks again: the next poll draws the new request and the line
 *       "No question is waiting for you.", which keeps the focus;
 *   W5  no unhandled rejection; the oracle: no page or answer read here
 *       carries a file's value or a token.
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
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const ENV_VALUE = "waitingLineStackEnvValue000000000001";
const CONF_VALUE = "waitingLineStackConfValue00000000002";
const SESSION = "waiting-line-session";
const PENDING = "/api/policy/proposals?status=pending";
const NOTHING = "Nothing is waiting for you.";
const NO_QUESTION = "No question is waiting for you.";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const cards = (doc: Doc): Doc[] => [...doc.querySelectorAll("#approvals-proposals .proposal")];
const cardOf = (doc: Doc, id: string) => cards(doc).find((c) => c.dataset.id === id);
const button = (root: Doc, label: string) => root && [...root.querySelectorAll("button")].find((b: Doc) => b.textContent === label);
const line = (doc: Doc, list: string) => doc.getElementById(list).querySelector(".empty");
const badge = (doc: Doc): string => (doc.getElementById("nav-approvals-count").hidden ? "0" : doc.getElementById("nav-approvals-count").textContent);
/** A poll, as a return to the tab makes one (the page's 10 s poll is inert here). */
const poll = (doc: Doc) => doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));

test("Home and Approvals over the real arbiter: the questions list says no question waits while a rule change does, never 'Nothing'; no secret anywhere", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-waiting-line-"));
  const home = join(tmp, "home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const env = join(repo, ".env");
  const conf = join(repo, "deploy.conf");
  writeFileSync(env, `DB_PASSWORD=${ENV_VALUE}\n`);
  writeFileSync(conf, `API_TOKEN=${CONF_VALUE}\n`);
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
  const base = `http://127.0.0.1:${port}`;
  const bodies: string[] = [];
  const read = async (path: string) => {
    const r = await pageFetch(`${base}${path}`, { headers: CSRF_ADMIN });
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
    // The agent asks to let .env be sent to a host: it waits for you.
    const first = await data.policyPropose({ edits: [{ op: "lock-path", path: env, level: "no-model", bindings: ["api.stripe.com"] }], sessionKey: SESSION, reason: "deploy needs it" });
    assert.ok("proposalId" in first && first.proposalId, `the binding waits for the human: ${JSON.stringify(first)}`);
    const firstId = String(first.proposalId);

    const ready = (doc: Doc) => doc.getElementById("home-waiting-title").textContent === "Approvals waiting (1)" && !!line(doc, "home-waiting");
    await servedProductPage(base, "/", ready, async (doc: Doc) => {
      const keep = () => rendered.push(doc.documentElement.outerHTML);

      // W1: Home.
      assert.equal(badge(doc), "1", "the badge counts the rule change");
      assert.equal(doc.getElementById("home-waiting-title").textContent, "Approvals waiting (1)");
      assert.equal(line(doc, "home-waiting").textContent, NO_QUESTION);
      assert.equal(doc.querySelector("#home-waiting .more").textContent, "1 rule change your agent asked for is in Approvals");
      assert.doesNotMatch(doc.getElementById("home-waiting-block").textContent, /Nothing is waiting/, "never 'Nothing' under a count of 1");
      keep();

      // W2: Approvals.
      doc.querySelector('#nav [data-page-link="approvals"]').click();
      await waitWhile(() => !cardOf(doc, firstId));
      assert.ok(button(cardOf(doc, firstId), "Not now"), "the request's card, with its answers");
      assert.equal(line(doc, "approvals-waiting").textContent, NO_QUESTION, "the questions list under it");
      keep();

      // W3: Not now.
      const notNow = button(cardOf(doc, firstId), "Not now");
      notNow.focus();
      notNow.click();
      await waitWhile(() => !!cardOf(doc, firstId) || line(doc, "approvals-waiting")?.textContent !== NOTHING);
      assert.equal(cardOf(doc, firstId), undefined, "answered: its card is gone");
      assert.deepEqual((await read(PENDING)).proposals, [], "the server recorded the answer");
      assert.equal(badge(doc), "0");
      assert.equal(line(doc, "approvals-waiting").textContent, NOTHING, "nothing waits any more");
      keep();

      // W4: the focus on the line, as an answer's landing leaves it; the
      // agent asks again, and the next poll reads it.
      const old = line(doc, "approvals-waiting");
      old.setAttribute("tabindex", "-1");
      old.focus();
      assert.equal(doc.activeElement, old);
      const second = await data.policyPropose({ edits: [{ op: "lock-path", path: conf, level: "no-model", bindings: ["api.github.com"] }], sessionKey: SESSION, reason: "ci needs it" });
      assert.ok("proposalId" in second && second.proposalId, `the second binding waits too: ${JSON.stringify(second)}`);
      const secondId = String(second.proposalId);
      poll(doc);
      await waitWhile(() => !cardOf(doc, secondId) || line(doc, "approvals-waiting")?.textContent !== NO_QUESTION);
      assert.ok(cardOf(doc, secondId), "the new request is drawn");
      assert.equal(line(doc, "approvals-waiting").textContent, NO_QUESTION, "and the line under it says no question waits");
      assert.notEqual(line(doc, "approvals-waiting"), old, "the line was drawn again");
      assert.equal(doc.activeElement, line(doc, "approvals-waiting"), "the line keeps the focus, never <body>");
      assert.equal(badge(doc), "1");
      keep();
    }, { headers: { Cookie: ADMIN_COOKIE } });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // W5: the oracle on every page drawn and every answer read above.
    assert.equal(rendered.length, 4);
    for (const text of [...rendered, ...bodies]) {
      for (const value of [ENV_VALUE, CONF_VALUE]) assert.ok(!text.includes(value), "no file's value in a page or an answer");
      assert.doesNotMatch(text, /\$MDU/, "nor a token");
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    data.close();
    wired?.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
