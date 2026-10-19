/**
 * own-rule-change-waiting.test — a rule change you asked for that is left
 * waiting is never credited to your agent, across the REAL components
 * (dashboard.md §4.25 *A rule change you asked for is never credited to
 * your agent*). Mandu-new.
 *
 * The product page's writes propose on the admin channel and approve at
 * once (`applyAsHuman`). When policy.yaml changes on disk just before the
 * approval, the arbiter refuses it as stale and the request stays waiting
 * ("(the proposal is still pending)"). Until 2026-10-15 Approvals drew it
 * as "You wants to change a rule", with the page's own note under "Your
 * agent says" and the heading "Rule changes your agent asked for", and
 * Home linked it as "1 rule change your agent asked for is in Approvals".
 *
 *   a real ArbiterServer (`secrets` axes, no poll, so a hand edit is
 *   noticed at the next write) locking ~/notes/id_rsa and ~/.env no-model;
 *   a real DashboardServer over the production adapter
 *   (`makeApprovalsArbiter`); the served product page (its own index.html
 *   and home.js in jsdom), signed in:
 *
 *   O1  a hand edit lands, then a rule's menu removes the id_rsa lock
 *       (confirm, then the confirmed write): 409, still pending; the
 *       arbiter recorded it as the Rules page's (`rules-page`);
 *   O2  Approvals: "Rule changes waiting for you", "You want to change a
 *       rule", the note "Changed on the Rules page (remove)" under "Note";
 *       nothing in the block says "your agent";
 *   O3  Home: "1 rule change waits for you in Approvals";
 *   O4  the agent asks too (data socket): its card reads as before ("Your
 *       agent wants to change a rule", "Your agent says"), yours as in O2;
 *       Home: "2 rule changes wait for you in Approvals";
 *   O5  Not now on yours: the heading is "Rule changes your agent asked
 *       for" again, Home "1 rule change your agent asked for is in
 *       Approvals"; the lock is still in policy.yaml;
 *   O6  no unhandled rejection; the oracle: no rendered page or answer
 *       carries a locked file's value, the admin token or the session
 *       secret.
 *
 * Axes: secrets (stated). What is under test is the served script and the
 * view model over the arbiter's record.
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
import { ADMIN_COOKIE, ADMIN_OPTS, ADMIN_TOKEN, CSRF_ADMIN, SESSION_SECRET } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY_VALUE = `OWN_RULE_CHANGE_WAITING_KEY_${process.pid}_7d1a`;
const ENV_VALUE = `OWN_RULE_CHANGE_WAITING_ENV_${process.pid}_52be`;
const AGENT = "own-rule-change-agent";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const cards = (doc: Doc): Doc[] => [...doc.querySelectorAll("#approvals-proposals .proposal")];
const head = (doc: Doc): string => doc.querySelector("#approvals-proposals-block h2").textContent;
const sentence = (card: Doc): string => card.querySelector(".ask-sentence").textContent;
const label = (card: Doc): string => card.querySelector(".agent-says .proposal-k").textContent;
const said = (card: Doc): string => card.querySelector(".agent-says-text").textContent;
const homeLink = (doc: Doc): string => doc.querySelector("#home-waiting .more")?.textContent ?? "(no line)";

test("a rule change the Rules page left waiting reads as yours on the served Approvals and Home, an agent's as before (real arbiter, adapter and server; secrets axes)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-own-rule-change-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "notes"), { recursive: true });
  const key = join(home, "notes", "id_rsa");
  const env = join(home, ".env");
  writeFileSync(key, `${KEY_VALUE}\n`);
  writeFileSync(env, `API_TOKEN=${ENV_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${key}\n    level: no-model\n  - path: ${env}\n    level: no-model\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc, "the production adapter has the secrets and policy surfaces");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const pages: string[] = [];
  const answers: string[] = [];
  const call = async (method: string, path: string, body?: unknown): Promise<{ status: number; data: Doc }> => {
    const r = await pageFetch(`${base}${path}`, {
      method, headers: { ...CSRF_ADMIN, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const text = await r.text();
    answers.push(text);
    return { status: r.status, data: JSON.parse(text) };
  };
  /** The served product page at `path`, once `ready`; every answer it reads is kept for the oracle. */
  const page = (path: string, ready: (doc: Doc) => boolean, fn: (doc: Doc) => void | Promise<void>) =>
    servedProductPage(base, path, ready, async (doc: Doc) => {
      const w = doc.defaultView;
      const fetch0 = w.fetch;
      w.fetch = async (url: string, init?: RequestInit) => {
        const r = await fetch0(url, init);
        return { ...r, json: async () => { const v = await r.json(); answers.push(JSON.stringify(v)); return v; } };
      };
      await fn(doc);
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });
  const unhandled: unknown[] = [];
  const onUnhandled = (e: unknown) => { unhandled.push(e); };
  process.on("unhandledRejection", onUnhandled);
  try {
    // O1: the rule's menu asks to confirm; the person's editor saves
    // policy.yaml; the confirmed write is refused as stale, the request left.
    const id = `lock:${key}`;
    const asked = await call("POST", "/api/policy/rules/change", { id, action: "remove" });
    assert.equal(asked.status, 200, JSON.stringify(asked.data));
    assert.equal(asked.data.confirm, true, "removing a lock loosens: the page confirms first");
    writeFileSync(policyPath, readFileSync(policyPath, "utf8") + "# a note written by hand\n");
    const refused = await call("POST", "/api/policy/rules/change", { id, action: "remove", expected: asked.data.expected });
    assert.equal(refused.status, 409, JSON.stringify(refused.data));
    assert.match(String(refused.data.error), /still pending/, "the arbiter keeps the request waiting");
    const listed = await call("GET", "/api/policy/proposals?status=pending");
    assert.equal(listed.data.proposals.length, 1);
    const yours = listed.data.proposals[0];
    assert.equal(yours.reason, "Changed on the Rules page (remove)", "the Rules page asked");
    assert.equal(yours.headline, "You want to change a rule");
    assert.equal(yours.byAgent, false, "not the agent");

    // O2: Approvals.
    await page("/approvals", (doc) => cards(doc).length === 1, (doc) => {
      assert.equal(head(doc), "Rule changes waiting for you");
      const [card] = cards(doc);
      assert.equal(sentence(card), "You want to change a rule");
      assert.equal(label(card), "Note");
      assert.equal(said(card), "Changed on the Rules page (remove)");
      assert.doesNotMatch(doc.getElementById("approvals-proposals-block").textContent, /your agent|You wants/i);
    });
    // O3: Home.
    await page("/", (doc) => homeLink(doc) !== "(no line)", (doc) => {
      assert.equal(homeLink(doc), "1 rule change waits for you in Approvals");
    });

    // O4: the agent asks too, over the data socket.
    const theirs = await data.policyPropose({ edits: [{ op: "release", to: { host: "paste.example" }, mode: "allow" }], reason: "upload the notes", sessionKey: AGENT });
    assert.ok("proposalId" in theirs && !theirs.applied, `the agent's loosening waits: ${JSON.stringify(theirs)}`);
    await page("/approvals", (doc) => cards(doc).length === 2, (doc) => {
      assert.equal(head(doc), "Rule changes waiting for you");
      const agentCard = cards(doc).find((c) => c.dataset.id === theirs.proposalId);
      const ownCard = cards(doc).find((c) => c.dataset.id === yours.id);
      assert.equal(sentence(agentCard), "Your agent wants to change a rule", "an agent's request reads as before");
      assert.equal(label(agentCard), "Your agent says");
      assert.equal(said(agentCard), "upload the notes");
      assert.equal(sentence(ownCard), "You want to change a rule");
      assert.equal(label(ownCard), "Note");
    });
    await page("/", (doc) => homeLink(doc) !== "(no line)", (doc) => {
      assert.equal(homeLink(doc), "2 rule changes wait for you in Approvals");
    });

    // O5: Not now on yours, from the page.
    await page("/approvals", (doc) => cards(doc).length === 2, async (doc) => {
      const own = cards(doc).find((c) => c.dataset.id === yours.id);
      const notNow = [...own.querySelectorAll("button")].find((b: Doc) => b.textContent === "Not now") as Doc;
      notNow.focus();
      notNow.click();
      await waitWhile(() => cards(doc).length !== 1);
      assert.equal(cards(doc)[0].dataset.id, theirs.proposalId);
      assert.equal(head(doc), "Rule changes your agent asked for", "only the agent's request waits");
      assert.equal(label(cards(doc)[0]), "Your agent says");
    });
    await page("/", (doc) => homeLink(doc) !== "(no line)", (doc) => {
      assert.equal(homeLink(doc), "1 rule change your agent asked for is in Approvals");
    });
    assert.ok(readFileSync(policyPath, "utf8").includes(key), "Not now left the lock in policy.yaml");

    // O6: no unhandled rejection; the oracle.
    assert.deepEqual(unhandled, [], "no unhandled rejection");
    for (const [what, text] of [["a rendered page", pages.join("\n")], ["an answer", answers.join("\n")]] as const) {
      for (const value of [KEY_VALUE, ENV_VALUE]) assert.ok(!text.includes(value), `${what} carries a locked file's value`);
      assert.ok(!text.includes(ADMIN_TOKEN), `${what} carries the admin token`);
      assert.ok(!text.includes(SESSION_SECRET), `${what} carries the session secret`);
    }
    assert.ok(pages.length === 6 && answers.length > 6, "(the pages were drawn and the answers read)");
  } finally {
    process.off("unhandledRejection", onUnhandled);
    data.close();
    await dashboard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
