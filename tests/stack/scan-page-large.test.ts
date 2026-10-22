/**
 * scan-page-large e2e — the Scan page over a scan at about a real machine's
 * scale, in a real browser (dashboard.md §4.25ai *A long scan, in pages*).
 * Mandu-new.
 *
 * A REAL DashboardServer over a kept `mandu scan` record of 918 findings
 * and 5 sends (the dashboard's large-scan fixture: the shape of a real scan
 * of 834 sessions, every value fake, plus a planted value in fields the
 * record never has) in a temp MANDU_HOME, and a REAL headless Chromium
 * (Playwright's headless shell; none found: the test skips) signed in with
 * the dashboard's one-time admin link:
 *
 *   L1  the page draws within its budget, from a head under 200 kB (the
 *       whole page was 2.8 MB): each section's count, its first 25 rows,
 *       no row's examples;
 *   L2  opening the folded tier and pressing Show more reads its next page
 *       (`/api/scan/section/named?after=25`), and the rows follow on;
 *   L3  *Find one* asks the server and finds a row the head never sent;
 *   L4  a row's *Details and examples* reads its examples
 *       (`/api/scan/item/<id>`) and draws them;
 *   L5  the oracle: no 8-character run of the planted value in the page.
 *
 * Axes: secrets (stated; display only: the dashboard reads a kept report,
 * no arbiter, no model). No kernel layer.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import type { ChildProcess } from "node:child_process";

import { DashboardServer } from "../../dashboard/src/server.js";
import type { EventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { largeScanRecord } from "../../dashboard/test/unit/view-model/large-scan-fixture.js";
import { chromiumBinary, READY, startChromium, stopChromium } from "../lib/chromium.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

// Assembled at run time: this file holds no credential-shaped literal.
const PLANT = `${"sk" + "_live_"}LargeScanPage0123456789ab`;
const BIN = chromiumBinary();
/** The first draw's budget, from the click to the sections drawn: about
 *  30 ms here and 110 to 200 ms before the paging on a fast host; a loaded
 *  CI runner gets room. */
const FIRST_DRAW_BUDGET_MS = 3_000;
/** The head's budget: about 111 kB on this fixture (2.8 MB before). */
const HEAD_BUDGET_BYTES = 200_000;

const noSessions = {
  async listSessions() { return []; },
  async readEvents() { return []; },
  subscribe() { return () => {}; },
  close() {},
} as unknown as EventSource;

/** A DevTools client over Node's built-in WebSocket. */
async function devtools(wsUrl: string) {
  const ws = new WebSocket(wsUrl);
  await new Promise<void>((resolve, reject) => {
    ws.addEventListener("open", () => resolve(), { once: true });
    ws.addEventListener("error", () => reject(new Error(`no DevTools at ${wsUrl}`)), { once: true });
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const waiting = new Map<number, (m: any) => void>();
  ws.addEventListener("message", (ev) => {
    const m = JSON.parse(String(ev.data));
    if (typeof m.id === "number") waiting.get(m.id)?.(m);
  });
  let id = 1;
  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    send(method: string, params: Record<string, unknown> = {}): Promise<any> {
      const my = id++;
      return new Promise((resolve) => { waiting.set(my, resolve); ws.send(JSON.stringify({ id: my, method, params })); });
    },
    close: () => ws.close(),
  };
}

let tmp = "";
after(() => { if (tmp) rmSync(tmp, { recursive: true, force: true }); });

test("the Scan page over a real-scale scan: drawn within budget from a small head, the rest read when opened, no value", { skip: BIN === null ? "no headless Chromium (Playwright's headless shell) on this host" : false, timeout: 120_000 }, async () => {
  tmp = mkdtempSync(join(tmpdir(), "mdu-scan-large-"));
  const home = join(tmp, "home");
  const mh = join(tmp, "mh");
  mkdirSync(join(mh, "state"), { recursive: true });
  mkdirSync(home, { recursive: true });
  writeFileSync(join(mh, "state", "last-scan.json"), JSON.stringify(largeScanRecord({ plant: PLANT })), { mode: 0o600 });
  const dash = new DashboardServer({ source: noSessions, fileBrowserHome: home, configEnv: { HOME: home, MANDU_HOME: mh }, log: () => {}, ...ADMIN_OPTS });
  const base = `http://127.0.0.1:${await dash.listen(0)}`;
  const profile = join(tmp, "chrome");
  let chrome: ChildProcess | null = null;
  let page: Awaited<ReturnType<typeof devtools>> | null = null;
  try {
    const started = await startChromium(BIN!, profile, `${base}${dash.adminLoginPath()}`);
    chrome = started.proc;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let target: any = null;
    for (let i = 0; i < 50 && target === null; i++) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const list = (await (await fetch(`http://127.0.0.1:${started.port}/json/list`)).json()) as any[];
      target = list.find((p) => p.type === "page") ?? null;
      if (target === null) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(target, "the page is listed");
    page = await devtools(target.webSocketDebuggerUrl);
    const p = page;
    const evaluate = async (expression: string): Promise<unknown> => (await p.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true })).result?.result?.value;
    const until = async (expression: string, what: string, ms = 15_000): Promise<void> => {
      const end = performance.now() + ms;
      while (performance.now() < end) {
        if (await evaluate(expression) === true) return;
        await new Promise((r) => setTimeout(r, 10));
      }
      assert.fail(`the page never showed ${what}`);
    };
    /** The page's reads of the Scan routes so far: path and body bytes. */
    const reads = async (): Promise<Array<{ path: string; bytes: number }>> => JSON.parse(String(await evaluate(
      `JSON.stringify(performance.getEntriesByType("resource").filter((e) => /\\/api\\/scan/.test(e.name)).map((e) => ({ path: new URL(e.name).pathname + new URL(e.name).search, bytes: e.decodedBodySize })))`)));
    const sec = (id: string) => `document.querySelector('[data-section="${id}"]')`;

    // Signed in (the link sets the session, then Home loads); History links the Scan page.
    await until(`${READY} && location.pathname === "/"`, "Home after the sign-in link");
    await p.send("Page.navigate", { url: `${base}/history` });
    await until(`${READY} && location.pathname === "/history" && !!document.querySelector('a[data-page-link="scan"]')`, "History");

    // ── L1: the first draw, from the head ──
    const t0 = performance.now();
    await evaluate(`document.querySelector('a[data-page-link="scan"]').click()`);
    await until(`document.querySelectorAll("#scan-sections .scan-section").length === 5 && ${sec("named")}.querySelectorAll(".scan-item").length === 25`, "the Scan page's sections");
    const firstDraw = performance.now() - t0;
    assert.ok(firstDraw < FIRST_DRAW_BUDGET_MS, `drawn in ${firstDraw.toFixed(0)} ms (budget ${FIRST_DRAW_BUDGET_MS})`);
    const head = (await reads()).filter((r) => r.path === "/api/scan");
    assert.equal(head.length, 1);
    assert.ok(head[0]!.bytes > 0 && head[0]!.bytes < HEAD_BUDGET_BYTES, `the head is ${head[0]!.bytes} B (budget ${HEAD_BUDGET_BYTES})`);
    assert.match(String(await evaluate(`${sec("named")}.querySelector("h2").textContent`)), /Values named like a secret \(635\)/);
    assert.equal(await evaluate(`document.querySelectorAll(".scan-detail").length`), 0, "no row's examples before it opens");
    assert.equal((await reads()).length, 1, "nothing read past the head");

    // ── L2: open the folded tier, Show more reads its next page ──
    await evaluate(`${sec("named")}.querySelector("details.scan-fold > summary").click()`);
    await until(`${sec("named")}.querySelector("details.scan-fold").open`, "the tier open");
    assert.equal(await evaluate(`${sec("named")}.querySelector(".scan-section-body > button.btn").textContent`), "Show 25 more");
    await evaluate(`${sec("named")}.querySelector(".scan-section-body > button.btn").click()`);
    await until(`${sec("named")}.querySelectorAll(".scan-item").length === 50`, "the next 25 rows");
    assert.ok((await reads()).some((r) => r.path.startsWith("/api/scan/section/named?after=25&rev=")), "the next page was read");
    const ids = (await evaluate(`JSON.stringify([...${sec("named")}.querySelectorAll(".scan-item")].map((r) => r.dataset.id))`)) as string;
    assert.equal(new Set(JSON.parse(ids)).size, 50, "each row once");

    // ── L3: Find one asks the server, over the whole section ──
    await evaluate(`(() => { const i = ${sec("named")}.querySelector("input.scan-filter"); i.value = "DB_PASSWORD_634="; i.dispatchEvent(new Event("input")); })()`);
    await until(`${sec("named")}.querySelectorAll(".scan-item").length === 1`, "the one match");
    assert.equal(await evaluate(`${sec("named")}.querySelector(".scan-item .scan-item-title").textContent`), "DB_PASSWORD_634=…");
    assert.ok((await reads()).some((r) => r.path.startsWith("/api/scan/section/named?after=0&q=db_password_634%3D")), "the query went to the server");

    // ── L4: a row's examples, read when opened ──
    await evaluate(`${sec("named")}.querySelector(".scan-item details.scan-more > summary").click()`);
    await until(`!!${sec("named")}.querySelector(".scan-item .scan-detail .scan-examples li")`, "the row's examples");
    assert.ok((await reads()).some((r) => /^\/api\/scan\/item\/f\d+\?rev=/.test(r.path)), "the row's examples were read");

    // ── L5: the oracle ──
    const text = String(await evaluate("document.body.innerText"));
    for (let i = 0; i + 8 <= PLANT.length; i++) {
      const piece = PLANT.slice(i, i + 8);
      if (piece !== "sk_live_") assert.ok(!text.includes(piece), `the page holds "${piece}" of the planted value`);
    }
  } finally {
    page?.close();
    await stopChromium(chrome, profile);
    await dash.close();
  }
});
