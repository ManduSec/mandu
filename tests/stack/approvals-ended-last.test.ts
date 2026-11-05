/**
 * approvals-ended-last.test — the questions an agent waits on come first, and
 * those from sessions that have ended go under their own heading, across the
 * REAL components (dashboard.md §4.25 *A question from a session that has
 * ended*). Mandu-new.
 *
 * Questions never expire, so one left when its session ended stays listed,
 * newest first. Until 2026-10-25 Home drew the first three in that order, so
 * the newest question, from a session that had just ended, took a place
 * above an older one a running agent still waited on.
 *
 * A real ArbiterServer (`secrets` axes) holds two questions about a labelled
 * secret: first from a running session, then (the newest) from a session
 * whose launcher records its REAL `session_exit`.
 *
 *   A1  /api/home lists both, newest first, the ended one marked
 *       `askerEnded`; the count is two;
 *   A2  the served Home draws the running session's question first;
 *   A3  the served Approvals draws it first, then *From sessions that have
 *       ended* with its line, then the ended one without its own sentence;
 *       the badge counts both;
 *   A4  the oracle: no answer nor page carries the secret's value or a token;
 *   A5  the ended card is short there (dashboard.md §4.25 *An ended question
 *       is short on Approvals*, 2026-10-30): no cells, a What each answer
 *       does button that opens them in place, with no secret value in them;
 *       the live card keeps its cells; `/approvals/<ended id>` draws it full;
 *   A6  that agent is gone, so neither the ended card's opened cells nor its
 *       full card say "tell the agent to try again" (dashboard.md §4.34
 *       *After you answer*, 2026-10-31); the live card still does.
 *
 * A second case holds five questions, three from running sessions and two
 * from sessions that have ended (2026-10-28):
 *
 *   M1  the served Home draws the three running ones, and its link to the
 *       rest says they are from sessions that have ended, in the words of
 *       the Approvals heading: "2 more questions in Approvals, all from
 *       sessions that have ended";
 *   M2  the oracle, as A4.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer, type ApprovalsArbiter } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { emitLauncherEvent, sessionExitEvent } from "../../launcher/src/services/observe.js";

stateAxes("secrets");

const KEY_VALUE = "sk_" + "live_endedLastStackCanary00000000000001";
const RUNNING = "1791200200-419";
const ENDED = "1791200300-420";

test("a running agent's question comes first on Home and Approvals; one from a session that has ended goes under its own heading (secrets axes, explicit)", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-ended-last-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(socketPath); await gate.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const approvalsArbiter: ApprovalsArbiter = {
    egressApprovals: (status) => admin.egressApprovals(status),
    resolveEgressApproval: (approvalId, approve, scope) => admin.resolveEgressApproval(approvalId, approve, scope),
  };
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  try {
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    await admin.setPathLabel({ path: env, confidentiality: "no-model", bindings: ["api.stripe.com"], recursive: false });
    const ask = async (session: string, host: string): Promise<string> => {
      const reg = await gate.registerSecret({ path: env, sessionKey: session });
      const sym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
      assert.ok(sym, `the key has its own symbol: ${JSON.stringify(reg)}`);
      const asked = await gate.desymbolizationDecision({ symbol: sym!, boundary: "network", destination: host, sessionKey: session, scheme: "https" });
      assert.equal((asked as { requiresApproval?: boolean }).requiresApproval, true, `${host} asks`);
      return String((asked as { approvalId?: string }).approvalId);
    };
    // The running session asks first; the newest question is from the
    // session that then ends.
    const liveId = await ask(RUNNING, "evil.example");
    await new Promise((r) => setTimeout(r, 20));
    const endedId = await ask(ENDED, "other.example");
    assert.notEqual(liveId, endedId);
    assert.ok(await emitLauncherEvent(socketPath, sessionExitEvent({ scopeId: ENDED, code: 0, durationMs: 4_000 }), humanPath), "the launcher's emit lands");

    // A1: the server lists both, newest first, the ended one marked.
    let vm = (await (await pageFetch(`${base}/api/home`)).json()) as HomeVM;
    for (let i = 0; i < 400 && !vm.waiting.some((a) => a.askerEnded); i++) {
      await new Promise((r) => setTimeout(r, 25));
      vm = (await (await pageFetch(`${base}/api/home`)).json()) as HomeVM;
    }
    assert.deepEqual(vm.waiting.map((a) => [a.id, !!a.askerEnded]), [[endedId, true], [liveId, false]], "newest first, as the server lists them");
    assert.equal(vm.window.waiting, 2);

    // A2: Home draws the running session's question first.
    await servedProductPage(base, "/", (doc) => doc.querySelectorAll("#home-waiting .ask").length === 2, (doc) => {
      const ids = [...doc.querySelectorAll("#home-waiting .ask")].map((c: { dataset: { id: string } }) => c.dataset.id);
      assert.deepEqual(ids, [liveId, endedId], "the question an agent waits on first");
      assert.equal(doc.querySelector("#home-waiting .ask-group-head"), null, "Home has no heading");
      assert.match(doc.querySelector(`#home-waiting .ask:last-of-type .ask-ended`)?.textContent ?? "", /The agent that asked has ended/, "Home's ended card keeps its sentence");
      assert.equal(doc.getElementById("home-waiting-title").textContent, "Approvals waiting (2)");
    });

    // A3: Approvals: the running one, the heading and its line, the ended one.
    await servedProductPage(base, "/approvals", (doc) => doc.querySelectorAll("#approvals-waiting .ask").length === 2, (doc) => {
      const list = doc.getElementById("approvals-waiting");
      const kids = [...list.children].map((c: { dataset: { id?: string }; className: string }) => c.dataset.id ?? c.className);
      assert.deepEqual(kids, [liveId, "ask-group-head", endedId]);
      assert.equal(list.querySelector(".ask-group-head h3").textContent, "From sessions that have ended");
      assert.equal(list.querySelector(".ask-group-head p").textContent, "No agent is waiting on these now. Your answer decides what happens the next time an agent asks the same.");
      assert.equal(list.querySelector(".ask-ended"), null, "the ended card leaves its own sentence to the heading");
      assert.equal(doc.getElementById("nav-approvals-count").textContent, "2", "the badge counts both");
      // A5: the ended card is short, the live one full.
      const card = (id: string) => list.querySelector(`.ask[data-id="${id}"]`);
      assert.equal(card(liveId).querySelectorAll(".ask-detail .k").length, 3, "the live card keeps its cells");
      assert.equal(card(liveId).querySelector(".ask-more"), null);
      assert.equal(card(endedId).querySelector(".ask-detail"), null, "the ended card has no cells");
      const more = card(endedId).querySelector(".ask-sub .ask-more");
      assert.equal(more?.textContent, "What each answer does");
      assert.equal(more.getAttribute("aria-expanded"), "false");
      assert.deepEqual([...card(endedId).querySelectorAll(".ask-actions button")].map((b: { textContent: string }) => b.textContent),
        [...card(liveId).querySelectorAll(".ask-actions button")].map((b: { textContent: string }) => b.textContent), "the same answers as the full card");
      more.click();
      assert.equal(more.getAttribute("aria-expanded"), "true");
      assert.equal(more.textContent, "Hide");
      assert.equal(card(endedId).querySelectorAll(".ask-detail .k").length, 3, "pressed, its cells open in place");
      // A6: the opened cells never ask the person to tell a gone agent anything.
      assert.match(card(liveId).querySelector(".ask-detail").textContent, /tell the agent to try again/i, "the live card still says it");
      assert.doesNotMatch(card(endedId).querySelector(".ask-detail").textContent, /try again/i, "the ended card's cells do not");
      assert.match(card(endedId).querySelector(".ask-detail").textContent, /Mandu refused this one, so nothing was sent\.$/, "the rest of the cell stays");
      assert.match(card(endedId).querySelector(".ask-link")?.getAttribute("href") ?? "", new RegExp(`/agents/${ENDED}`), "with the agent link");
      // A4: the rendered page, the opened cells too.
      const page = doc.body.textContent;
      assert.ok(!page.includes(KEY_VALUE), "the rendered page carries no secret value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    });

    // A5: a link to the ended question draws its card full, marked.
    await servedProductPage(base, `/approvals/${endedId}`, (doc) => doc.querySelectorAll("#approvals-waiting .ask").length === 2, (doc) => {
      const card = doc.querySelector(`#approvals-waiting .ask[data-id="${endedId}"]`);
      assert.ok(card.classList.contains("expanded"), "full");
      assert.ok(card.classList.contains("focus"), "marked");
      assert.equal(card.querySelectorAll(".ask-detail .k").length, 3);
      assert.equal(card.querySelector(".ask-more"), null);
      // A6: the full card neither.
      assert.doesNotMatch(card.querySelector(".ask-detail").textContent, /try again/i, "the ended card's full cells do not say to try again");
      assert.ok(!doc.body.textContent.includes(KEY_VALUE), "the rendered page carries no secret value");
    });

    // A4: the answers.
    const body = await (await pageFetch(`${base}/api/home`)).text();
    assert.ok(!body.includes(KEY_VALUE), "/api/home carries no secret value");
    assert.doesNotMatch(body, /\$MDU/, "nor a token");
  } finally {
    await dashboard.close();
    gate.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("Home's link to the questions it does not show says they are from sessions that have ended (secrets axes, explicit)", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-ended-more-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(socketPath); await gate.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const approvalsArbiter: ApprovalsArbiter = {
    egressApprovals: (status) => admin.egressApprovals(status),
    resolveEgressApproval: (approvalId, approve, scope) => admin.resolveEgressApproval(approvalId, approve, scope),
  };
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  try {
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    await admin.setPathLabel({ path: env, confidentiality: "no-model", bindings: ["api.stripe.com"], recursive: false });
    const ask = async (session: string, host: string): Promise<string> => {
      const reg = await gate.registerSecret({ path: env, sessionKey: session });
      const sym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
      assert.ok(sym, `the key has its own symbol: ${JSON.stringify(reg)}`);
      const asked = await gate.desymbolizationDecision({ symbol: sym!, boundary: "network", destination: host, sessionKey: session, scheme: "https" });
      assert.equal((asked as { requiresApproval?: boolean }).requiresApproval, true, `${host} asks`);
      return String((asked as { approvalId?: string }).approvalId);
    };
    // Three running sessions ask, then two that end: the newest two are the
    // ended ones, so the server lists them first.
    const live: string[] = [];
    for (let i = 0; i < 3; i++) live.push(await ask(`1791200400-${430 + i}`, `live${i}.example`));
    const endedKeys = ["1791200500-440", "1791200500-441"];
    for (const [i, key] of endedKeys.entries()) {
      await ask(key, `ended${i}.example`);
      assert.ok(await emitLauncherEvent(socketPath, sessionExitEvent({ scopeId: key, code: 0, durationMs: 4_000 }), humanPath), "the launcher's emit lands");
    }
    let vm = (await (await pageFetch(`${base}/api/home`)).json()) as HomeVM;
    for (let i = 0; i < 400 && vm.waiting.filter((a) => a.askerEnded).length < 2; i++) {
      await new Promise((r) => setTimeout(r, 25));
      vm = (await (await pageFetch(`${base}/api/home`)).json()) as HomeVM;
    }
    assert.equal(vm.waiting.length, 5);
    assert.equal(vm.waiting.filter((a) => a.askerEnded).length, 2, "two from sessions that have ended");

    // M1: Home's three are the running ones; its link counts the ended rest.
    await servedProductPage(base, "/", (doc) => doc.querySelectorAll("#home-waiting .ask").length === 3, (doc) => {
      const ids = [...doc.querySelectorAll("#home-waiting .ask")].map((c: { dataset: { id: string } }) => c.dataset.id);
      assert.deepEqual([...ids].sort(), [...live].sort(), "the three running sessions' questions");
      const link = doc.querySelector("#home-waiting > a.more:not([data-ask])");
      assert.equal(link?.textContent, "2 more questions in Approvals, all from sessions that have ended");
      assert.equal(link?.getAttribute("data-page-link"), "approvals", "it still opens Approvals");
      assert.equal(doc.getElementById("home-waiting-title").textContent, "Approvals waiting (5)");
      // M2: the rendered page.
      const page = doc.body.textContent;
      assert.ok(!page.includes(KEY_VALUE), "the rendered page carries no secret value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    });
    const body = await (await pageFetch(`${base}/api/home`)).text();
    assert.ok(!body.includes(KEY_VALUE), "/api/home carries no secret value");
    assert.doesNotMatch(body, /\$MDU/, "nor a token");
  } finally {
    await dashboard.close();
    gate.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
