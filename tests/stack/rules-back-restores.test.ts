/**
 * rules-back-restores e2e — Back to Rules returns to where you were, not the
 * page's top (dashboard.md §4.25 *Back and Forward keep your place*), across
 * the REAL components: a real ArbiterServer in `secrets`, the net-proxy wired
 * as production wires it (`new ArbiterClientAdapter(new ArbiterClient(sock))`),
 * and the real dashboard over the arbiter with the production approvals
 * adapter (`makeApprovalsArbiter`), signed in, in a real headless Chromium.
 * Mandu-new.
 *
 * Until 2026-10-22 Rules started at its top on every Back: an answer's *See
 * what the agent was doing*, followed from far down the page, came back
 * 1,400 px above the row you had opened.
 *
 * The seed: a registered secret's send to a host no rule binds it to is
 * stopped, and Always allowed over the real route, so Rules lists the answer.
 * Then, at 1280 px:
 *
 *   R1  the answer's row opened, its *See what the agent was doing* scrolled
 *       down the screen and followed; the session's page opens;
 *   R2  the browser's Back: Rules within 3 px of where it was, and the link
 *       still on the screen;
 *   R3  a top-bar link to Rules (from Home) opens it at its top;
 *   R4  the oracle: the page Chromium drew carries neither the value nor a
 *       token.
 *
 * Self-SKIPs without a Chromium (probeBrowser: MANDU_TOUR_BROWSER,
 * CHROME_PATH, a Playwright headless shell).
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm test  (tests/)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  Cdp: { connect(url: string): Promise<Cdp> };
};
const chromium = tour.probeBrowser({});

const KEY_VALUE = `sk_live_rulesBackCanary_${process.pid}_00000`;
const SESSION = "1791400000-494";
const URL_OUT = "http://collector.example/upload";

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

test("in a real Chromium at 1280 px: Back from an answer's See what the agent was doing lands Rules within 3 px of where you were, the link on screen; a link opens Rules at its top (secrets axes, explicit)", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-back-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const adminPath = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminPath, humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const netClient = new ArbiterClient(socketPath);
  await netClient.connect();
  const netHuman = new ArbiterClient(humanPath);
  const wire: string[] = [];
  const proxy = new NetProxy({
    arbiter: new ArbiterClientAdapter(netClient as unknown as RealArbiterClient, netHuman),
    sessionId: SESSION,
    forwarder: async ({ url }) => {
      wire.push(url);
      return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
    },
    log: () => {},
  });
  const proxyPort = await proxy.listen(0);
  const gate = new ArbiterClient(socketPath); await gate.connect();
  const admin = new ArbiterClient(adminPath); await admin.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminPath }));
  assert.ok(wired, "the production approvals adapter");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const { proc, wsUrl } = await tour.startBrowser(chromium as string, join(tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  try {
    // ── The seed: a stopped send, Always allowed ────────────────────────────
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const stopped = await viaProxy(proxyPort, URL_OUT, `k=${keySym}`);
    assert.equal(stopped.status, 403, `the send is stopped: ${stopped.body}`);
    assert.deepEqual(wire, [], "nothing went out");
    const row = (await admin.egressApprovals("pending")).find((a) => a.symbol === keySym);
    assert.ok(row, "the stop queued a question");
    const id = row!.id;
    const allow = await pageFetch(`${base}/api/egress/approvals/${id}/approve`, { method: "POST", headers: CSRF_ADMIN });
    assert.equal(allow.status, 200);

    // ── Chromium, signed in, at 1280 px ────────────────────────────────────
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const send = (method: string, params: object = {}) => cdp.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    };
    const until = async (what: string, expression: string) => {
      let ok = false;
      for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((r) => setTimeout(r, 100))) {
        try { ok = await evaluate(expression); } catch { /* navigating */ }
      }
      assert.ok(ok, what);
    };
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Network.enable");
    const eq = ADMIN_COOKIE.indexOf("=");
    await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });
    await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 600, deviceScaleFactor: 1, mobile: false });
    await send("Page.navigate", { url: `${base}/rules` });

    // ── R1: the answer's row opened, its link followed from down the page ───
    const answerRow = `[...document.querySelectorAll("#rules-list .row[data-rule]")].find((r) => r.getAttribute("data-rule") === ${JSON.stringify("answer:" + id)})`;
    const link = `${answerRow}?.nextElementSibling?.querySelector("a.ask-link")`;
    await until("Rules lists the answer", `!document.getElementById("page-rules").hidden && !!${answerRow} && document.fonts.status === "loaded"`);
    await evaluate(`${answerRow}.querySelector(".file-more").click(), true`);
    await until("the row opened, its link under it", `!!${link}`);
    assert.equal(await evaluate(`${link}.textContent`), "See what the agent was doing");
    // The link 450 px down the screen, as far as the page lets it be, then a
    // pause past the page's own save of the scroll.
    await evaluate(`window.scrollTo(0, ${link}.getBoundingClientRect().top + window.scrollY - 450), true`);
    await new Promise((r) => setTimeout(r, 500));
    const before = await evaluate(`({ y: window.scrollY, top: ${link}.getBoundingClientRect().top, height: document.documentElement.scrollHeight })`);
    assert.ok(before.y > 100, `down the page (${before.y} of ${before.height} px)`);
    await evaluate(`${link}.click(), true`);
    await until("the session's page shown", `!document.getElementById("page-agent").hidden && location.pathname.startsWith("/agents/")`);

    // ── R2: Back, Rules where it was ────────────────────────────────────────
    await evaluate(`history.back(), true`);
    await until("Rules back", `!document.getElementById("page-rules").hidden && location.pathname === "/rules" && !!${link}`);
    await new Promise((r) => setTimeout(r, 800)); // past every read Back made
    const back = await evaluate(`({ y: window.scrollY, top: ${link}.getBoundingClientRect().top, focus: document.activeElement === document.querySelector("#page-rules h1"), body: document.body.innerText })`);
    assert.ok(Math.abs(back.y - before.y) <= 3, `Rules within 3 px of where it was: ${back.y}, was ${before.y}`);
    assert.ok(back.top >= 0 && back.top < 600, `the link on the screen (${back.top} px down)`);
    assert.equal(back.focus, true, "the focus on the page's heading");

    // ── R3: a link starts fresh ─────────────────────────────────────────────
    await evaluate(`document.querySelector('#nav [data-page-link="home"]').click(), true`);
    await until("Home shown", `!document.getElementById("page-home").hidden`);
    await evaluate(`document.querySelector('#nav [data-page-link="rules"]').click(), true`);
    await until("Rules shown", `!document.getElementById("page-rules").hidden && !!${answerRow}`);
    await new Promise((r) => setTimeout(r, 800));
    assert.equal(await evaluate(`window.scrollY`), 0, "a top-bar link opens Rules at its top");

    // ── R4: the oracle ──────────────────────────────────────────────────────
    assert.ok(!back.body.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: the Rules page carries the key's value");
    assert.doesNotMatch(back.body, /\$MDU:/, "the Rules page carries a token");
  } finally {
    cdp.close();
    await tour.stopProc(proc);
    await dashboard.close();
    await proxy.close();
    netClient.close(); netHuman.close();
    gate.close(); admin.close();
    wired.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
