/**
 * scan-back-restores e2e — Back to the Scan page returns to where you were,
 * with the sections and rows you had opened (dashboard.md §4.25 *Back and
 * Forward keep your place*, *Scan*; §4.25ai *A long scan, in pages*), in a
 * real browser. Mandu-new.
 *
 * Until 2026-10-29 (#228) a Back to Scan landed at its top, every fold
 * closed, 25 rows a section: on the maintainer's 918 findings, a person who
 * had opened the long tier, pressed Show more and opened a row had to do it
 * all again for the next finding.
 *
 * A REAL DashboardServer over the dashboard's large-scan fixture (the shape
 * of a real scan of 834 sessions, every value fake, plus a planted value in
 * fields the record never has) in a temp MANDU_HOME, and a REAL headless
 * Chromium at 1280 px (Playwright's headless shell; none found: the test
 * skips), signed in with the dashboard's one-time admin link:
 *
 *   S1  the folded tier "named" opened, Show more pressed (50 rows), row 31's
 *       *Details and examples* opened and its examples drawn, the row
 *       scrolled 300 px down the screen; the top bar's Rules link followed;
 *   S2  the browser's Back: the tier open, 50 rows (its next page read
 *       again), the row's fold open with its examples, the page within 3 px
 *       of where it was and the row at its height on the screen;
 *   S3  a top-bar link to Scan opens it at its top, the tier folded, 25 rows;
 *   S4  the oracle: no 8-character run of the planted value in the page.
 *
 * Axes: secrets (stated; display only: the dashboard reads a kept report,
 * no arbiter, no model). No kernel layer.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ChildProcess } from "node:child_process";

import { DashboardServer } from "../../dashboard/src/server.js";
import type { EventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { largeScanRecord } from "../../dashboard/test/unit/view-model/large-scan-fixture.js";
import { chromiumBinary, READY, startChromium, stopChromium } from "../lib/chromium.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

// Assembled at run time: this file holds no credential-shaped literal.
const PLANT = `${"sk" + "_live_"}ScanBackPlace0123456789ab`;
const BIN = chromiumBinary();

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

test("in a real Chromium at 1280 px: Back to the Scan page reopens the tier, reads the rows you had, reopens the row's Details and lands within 3 px; a link opens it at its top; no value", { skip: BIN === null ? "no headless Chromium (Playwright's headless shell) on this host" : false, timeout: 120_000 }, async () => {
  tmp = mkdtempSync(join(tmpdir(), "mdu-scan-back-"));
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
    const evaluate = async (expression: string): Promise<unknown> => {
      const r = await p.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.result?.exceptionDetails) throw new Error(`page script failed: ${r.result.exceptionDetails.exception?.description ?? r.result.exceptionDetails.text}`);
      return r.result?.result?.value;
    };
    const until = async (expression: string, what: string, ms = 15_000): Promise<void> => {
      const end = Date.now() + ms;
      while (Date.now() < end) {
        try { if (await evaluate(expression) === true) return; } catch { /* navigating */ }
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.fail(`the page never showed ${what}`);
    };
    const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
    /** The page's reads of the Scan routes so far, by path. */
    const reads = async (): Promise<string[]> => JSON.parse(String(await evaluate(
      `JSON.stringify(performance.getEntriesByType("resource").filter((e) => /\\/api\\/scan/.test(e.name)).map((e) => new URL(e.name).pathname + new URL(e.name).search))`)));
    const named = `document.querySelector('#scan-sections [data-section="named"]')`;
    const rows = `${named}.querySelectorAll(".scan-item").length`;

    await p.send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 720, deviceScaleFactor: 1, mobile: false });
    await until(`${READY} && location.pathname === "/"`, "Home after the sign-in link");
    await p.send("Page.navigate", { url: `${base}/scan` });
    await until(`${READY} && location.pathname === "/scan" && !!${named} && ${rows} === 25 && document.fonts.status === "loaded"`, "the Scan page");

    // ── S1: the tier opened, Show more, a row's Details, then a link away ──
    await evaluate(`${named}.querySelector("details.scan-fold > summary").click()`);
    await until(`${named}.querySelector("details.scan-fold").open`, "the tier open");
    await evaluate(`${named}.querySelector(".scan-section-body > button.btn").click()`);
    await until(`${rows} === 50`, "the next 25 rows");
    const id = String(await evaluate(`${named}.querySelectorAll(".scan-item")[30].dataset.id`));
    const row = `[...${named}.querySelectorAll(".scan-item")].find((r) => r.dataset.id === ${JSON.stringify(id)})`;
    await evaluate(`${row}.querySelector("details.scan-more > summary").click()`);
    await until(`!!${row}.querySelector(".scan-detail .scan-examples li")`, "the row's examples");
    await evaluate(`window.scrollTo(0, ${row}.getBoundingClientRect().top + window.scrollY - 300), true`);
    await pause(500); // past the page's own save of the scroll
    const before = await evaluate(`({ y: window.scrollY, top: ${row}.getBoundingClientRect().top, height: document.documentElement.scrollHeight })`) as { y: number; top: number; height: number };
    assert.ok(before.y > 2000, `far down the page (${before.y} of ${before.height} px)`);
    assert.ok(Math.abs(before.top - 300) <= 1, `the row 300 px down the screen (${before.top})`);
    const readsBefore = (await reads()).length;
    await evaluate(`document.querySelector('#nav [data-page-link="rules"]').click(), true`);
    await until(`!document.getElementById("page-rules").hidden && location.pathname === "/rules"`, "Rules");

    // ── S2: Back, the Scan page as you left it ──
    await evaluate(`history.back(), true`);
    await until(`!document.getElementById("page-scan").hidden && location.pathname === "/scan" && !!${row}?.querySelector(".scan-detail .scan-examples li")`, "the Scan page with the row's examples");
    await pause(800); // past every read Back made
    const back = await evaluate(`({ y: window.scrollY, top: ${row}.getBoundingClientRect().top, open: ${named}.querySelector("details.scan-fold").open, rows: ${rows}, more: ${row}.querySelector("details.scan-more").open, opened: document.querySelectorAll("#scan-sections details.scan-more[open]").length })`) as { y: number; top: number; open: boolean; rows: number; more: boolean; opened: number };
    assert.equal(back.open, true, "the tier is open again");
    assert.equal(back.rows, 50, "the rows you had drawn");
    assert.equal(back.more, true, "the row's Details and examples is open again");
    assert.equal(back.opened, 1, "no other row's");
    const again = (await reads()).slice(readsBefore);
    assert.equal(again.filter((r) => r === "/api/scan").length, 1, `the head read once: ${JSON.stringify(again)}`);
    assert.equal(again.filter((r) => r.startsWith("/api/scan/section/named?after=25&rev=")).length, 1, `its next page read once: ${JSON.stringify(again)}`);
    assert.equal(again.filter((r) => r.startsWith(`/api/scan/item/${id}?rev=`)).length, 1, `the row's examples read once: ${JSON.stringify(again)}`);
    assert.ok(Math.abs(back.y - before.y) <= 3, `the Scan page within 3 px of where it was: ${back.y}, was ${before.y}`);
    assert.ok(Math.abs(back.top - before.top) <= 3, `the row at its height on the screen: ${back.top}, was ${before.top}`);
    const text = String(await evaluate("document.body.innerText"));

    // ── S3: a link starts fresh ──
    await evaluate(`document.querySelector('#nav [data-page-link="home"]').click(), true`);
    await until(`!document.getElementById("page-home").hidden`, "Home");
    await evaluate(`document.querySelector('#nav [data-page-link="scan"]').click(), true`);
    await until(`!document.getElementById("page-scan").hidden && !!${named} && ${rows} === 25`, "the Scan page by its link");
    await pause(500);
    assert.equal(await evaluate(`window.scrollY`), 0, "a top-bar link opens Scan at its top");
    assert.equal(await evaluate(`${named}.querySelector("details.scan-fold").open`), false, "the tier folded");
    assert.equal(await evaluate(`document.querySelectorAll("#scan-sections details.scan-more[open]").length`), 0, "no row open");

    // ── S4: the oracle ──
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
