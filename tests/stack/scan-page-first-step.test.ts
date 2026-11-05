/**
 * scan-page-first-step e2e — the Scan page before any scan leads with its
 * one step, one block gap under the sentence, in a real browser (dashboard.md
 * §4.25ai *Before any scan, the step comes first*, 2026-10-26). Mandu-new.
 *
 * Until 2026-10-26 a person who opened Scan before running one met the
 * intro sentence, about 100 px of nothing (the empty sections still took
 * their place in the page's column), the "from now on" line, and last, in
 * the dim note style, "Run it in a terminal: mandu scan". A REAL
 * DashboardServer over a temp MANDU_HOME with no `last-scan.json` serves the
 * product page to a REAL headless Chromium (Playwright's headless shell;
 * none found: the test skips) at 1280×900, signed in with the one-time
 * admin link:
 *
 *   S1  before any scan: the step ("Run it in a terminal: mandu scan", with
 *       its Copy), then "This page shows what it found when it finishes.",
 *       then the "from now on" line, in that order in the document and on
 *       the screen; the step's top within 40 px of the sentence's bottom;
 *       the step at the body's size and color, not the note's; the empty
 *       sections not drawn;
 *   S2  a scan kept (written and renamed into place, as the launcher keeps
 *       it): on the next Home poll the page draws its findings, the step
 *       and its line are gone, and "Run it again: mandu scan" closes the
 *       page under the "from now on" line, as before;
 *   S3  the oracle: no 8-character run of a planted value (in a field the
 *       record never has) is on the page.
 *
 * Axes: secrets (stated; display only: the dashboard reads a kept report,
 * no arbiter, no model). No kernel layer.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ChildProcess } from "node:child_process";

import { DashboardServer } from "../../dashboard/src/server.js";
import type { EventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { chromiumBinary, READY, startChromium, stopChromium } from "../lib/chromium.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

// Assembled at run time: this file holds no credential-shaped literal.
const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8NbStep`;
const BIN = chromiumBinary();
const NONE_HEADLINE = "Did your agents already send a secret to the AI?";

const noSessions = {
  async listSessions() { return []; },
  async readEvents() { return []; },
  subscribe() { return () => {}; },
  close() {},
} as unknown as EventSource;

function record(): unknown {
  return {
    version: 1, ranAt: "2026-10-26T09:00:00.000Z", sessions: { "claude-code": 5 }, duringMandu: 0, known: 1,
    secret: STRIPE, // not a field of the record: dropped when read
    findings: [{
      kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, sessions: 2, agents: ["claude-code"],
      last: "2026-10-19T10:00:00.000Z", how: { "command-output": 2 }, projects: ["~/shop"], duringMandu: 0, raw: STRIPE,
    }],
    dropped: 0, capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 },
    sends: [], sendsDropped: 0, suggestions: null,
  };
}

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

test("the Scan page before any scan: its step first, one block gap under the sentence, then the way to stop it; once a scan is kept, as before; no value", { skip: BIN === null ? "no headless Chromium (Playwright's headless shell) on this host" : false, timeout: 120_000 }, async () => {
  tmp = mkdtempSync(join(tmpdir(), "mdu-scan-step-"));
  const home = join(tmp, "home");
  const mh = join(tmp, "mh");
  mkdirSync(join(mh, "state"), { recursive: true }); // no last-scan.json: no scan kept
  mkdirSync(home, { recursive: true });
  const scanFile = join(mh, "state", "last-scan.json");
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
    const evaluate = async (expression: string): Promise<unknown> => (await p.send("Runtime.evaluate", { expression, returnByValue: true })).result?.result?.value;
    const until = async (expression: string, what: string): Promise<void> => {
      for (let i = 0; i < 150; i++) {
        if (await evaluate(expression) === true) return;
        await new Promise((r) => setTimeout(r, 100));
      }
      assert.fail(`the page never showed ${what}`);
    };
    await until(`${READY} && location.pathname === "/"`, "Home after the sign-in link");
    await p.send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });

    // The facts the assertions read, from the drawn page.
    const facts = `JSON.stringify((() => {
      const box = (id) => { const e = document.getElementById(id); const r = e.getBoundingClientRect(); return { top: r.top, bottom: r.bottom, shown: getComputedStyle(e).display !== "none", text: e.textContent }; };
      const style = (id) => { const s = getComputedStyle(document.getElementById(id)); return { size: s.fontSize, color: s.color }; };
      const end = document.getElementById("scan-end");
      return {
        sentence: box("scan-sentence"), step: box("scan-step"), note: box("scan-step-note"), stop: box("scan-stop"), again: box("scan-again"),
        sections: box("scan-sections"),
        order: [...end.children].filter((e) => getComputedStyle(e).display !== "none").map((e) => e.id),
        stepStyle: style("scan-step"), noteStyle: style("scan-step-note"), body: { size: getComputedStyle(document.body).fontSize, color: getComputedStyle(document.body).color },
        copy: document.querySelector("#scan-step .run-code button")?.getAttribute("aria-label") ?? null,
        stepCode: document.querySelector("#scan-step code")?.textContent ?? null,
        items: document.querySelectorAll('#scan-sections [data-section="yours"] .scan-item').length,
        text: document.body.innerText,
      };
    })())`;
    const read = async () => JSON.parse(String(await evaluate(facts)));

    // ── S1: before any scan ──
    await p.send("Page.navigate", { url: `${base}/scan` });
    await until(`${READY} && location.pathname === "/scan" && document.getElementById("scan-headline").textContent === ${JSON.stringify(NONE_HEADLINE)} && !document.getElementById("scan-step").hidden`, "the Scan page before any scan");
    const none = await read();
    assert.deepEqual(none.order, ["scan-step", "scan-step-note", "scan-stop"], "the step, its line, then the way to stop it");
    assert.equal(none.stepCode, "mandu scan");
    assert.match(none.step.text, /^Run it in a terminal: mandu scan/);
    assert.equal(none.copy, "Copy mandu scan", "#118's Copy came along (127.0.0.1 is a secure context)");
    assert.equal(none.note.text, "This page shows what it found when it finishes.");
    assert.match(none.stop.text, /^To keep your secrets from the AI from now on, start your agent with mandu claude/);
    assert.ok(none.step.top < none.note.top && none.note.top < none.stop.top, `drawn in that order (${none.step.top} < ${none.note.top} < ${none.stop.top})`);
    const gap = none.step.top - none.sentence.bottom;
    assert.ok(gap >= 0 && gap <= 40, `the step is one block gap under the sentence (${gap} px; was about 100)`);
    assert.equal(none.sections.shown, false, "the empty sections take no room");
    assert.equal(none.again.shown, false);
    assert.equal(none.stepStyle.size, none.body.size, "the step at the body's size");
    assert.equal(none.stepStyle.color, none.body.color, "and its color, not dim");
    assert.notEqual(none.stepStyle.size, none.noteStyle.size, "not the note's size");

    // ── S2: a scan kept; the next Home poll draws it ──
    writeFileSync(`${scanFile}.tmp`, JSON.stringify(record()), { mode: 0o600 });
    renameSync(`${scanFile}.tmp`, scanFile);
    await evaluate(`document.dispatchEvent(new Event("visibilitychange")), true`);
    await until(`document.getElementById("scan-headline").textContent !== ${JSON.stringify(NONE_HEADLINE)} && document.querySelectorAll('#scan-sections [data-section="yours"] .scan-item').length > 0`, "the kept scan after a Home poll");
    const kept = await read();
    assert.ok(kept.items > 0, "the findings draw");
    assert.equal(kept.sections.shown, true);
    assert.equal(kept.step.shown, false, "the step is gone");
    assert.equal(kept.note.shown, false, "and its line");
    assert.doesNotMatch(kept.text, /shows what it found when it finishes/);
    assert.deepEqual(kept.order, ["scan-stop", "scan-again"], "as before: the way to stop it, then Run it again");
    assert.match(kept.again.text, /^Run it again: mandu scan/);
    assert.ok(kept.stop.top < kept.again.top);

    // ── S3: the oracle ──
    for (const text of [none.text, kept.text]) {
      for (let i = 0; i + 8 <= STRIPE.length; i++) {
        const piece = STRIPE.slice(i, i + 8);
        if (piece !== "sk_live_") assert.ok(!text.includes(piece), `the page holds "${piece}" of the planted value`);
      }
    }
  } finally {
    page?.close();
    await stopChromium(chrome, profile);
    await dash.close();
  }
});
