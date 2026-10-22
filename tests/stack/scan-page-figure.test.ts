/**
 * scan-page-figure e2e — the Scan page's colors and figure in a real browser
 * (dashboard.md §4.25ai *Color with meaning*, *The figure*). Mandu-new.
 *
 * A REAL DashboardServer over a kept `mandu scan` record (a temp MANDU_HOME,
 * the record as the launcher keeps it, plus a planted value in a field the
 * record never has), and a REAL headless Chromium (Playwright's headless
 * shell; none found: the test skips) signed in with the dashboard's one-time
 * admin link, with reduced motion asked for:
 *
 *   P1  at 360 px (a phone): the headline is red with its ✗; the figure's two
 *       rows, without Mandu (red) and with it (green), each drawn in the
 *       TALL layout (the wide one hidden), its labels the finding's file,
 *       agent and provider; the With row's internet is not red; the green
 *       line; no horizontal scroll; the lanes do not move;
 *   P2  at 1280 px: the WIDE layout instead, the steps in three columns;
 *   P3  the sections and rows carry their tone and their word ("Reached the
 *       AI"), the small flow ends on the real value in red;
 *   P4  the oracle: no 8-character run of the planted value in the page.
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
import { chromiumBinary, READY, startChromium, stopChromium } from "../lib/chromium.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

// Assembled at run time: this file holds no credential-shaped literal.
const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8NbFig`;
const BIN = chromiumBinary();

const noSessions = {
  async listSessions() { return []; },
  async readEvents() { return []; },
  subscribe() { return () => {}; },
  close() {},
} as unknown as EventSource;

function record(): unknown {
  return {
    version: 1, ranAt: "2026-10-22T09:00:00.000Z", sessions: { "claude-code": 12 }, duringMandu: 0, known: 2,
    secret: STRIPE, // not a field of the record: dropped when read
    findings: [
      {
        kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, sessions: 2, agents: ["claude-code"],
        last: "2026-10-19T10:00:00.000Z", how: { "command-output": 2 }, projects: ["~/shop"], duringMandu: 0, sessionsUnderMandu: 0, sessionsByTime: 0, raw: STRIPE,
        examples: [{ at: "2026-10-19T10:00:00.000Z", agent: "claude-code", how: "command-output", command: "cat .env", project: "~/shop", mandu: "without", provider: "anthropic" }],
      },
      { kind: "github-token", preview: "ghp_…", sessions: 1, agents: ["claude-code"], how: { "your-message": 1 }, projects: ["~/demo"], duringMandu: 0 },
    ],
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

test("the Scan page in a real browser: red for what left, green with Mandu, the figure tall on a phone and wide on a desktop, no value", { skip: BIN === null ? "no headless Chromium (Playwright's headless shell) on this host" : false, timeout: 120_000 }, async () => {
  tmp = mkdtempSync(join(tmpdir(), "mdu-scan-fig-"));
  const home = join(tmp, "home");
  const mh = join(tmp, "mh");
  mkdirSync(join(mh, "state"), { recursive: true });
  mkdirSync(home, { recursive: true });
  writeFileSync(join(mh, "state", "last-scan.json"), JSON.stringify(record()), { mode: 0o600 });
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
    // Signed in (the link sets the session, then Home loads).
    await until(`${READY} && location.pathname === "/"`, "Home after the sign-in link");
    await p.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });

    // The facts the assertions read, from the drawn page.
    const facts = `JSON.stringify((() => {
      const vis = (e) => !!e && getComputedStyle(e).display !== "none";
      const rows = [...document.querySelectorAll("#scan-figure .scan-fig-row")];
      const lane = document.querySelector("#scan-figure .sf-lane");
      return {
        scroll: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        headColor: getComputedStyle(document.getElementById("scan-headline")).color,
        bad: getComputedStyle(document.documentElement).getPropertyValue("--bad").trim(),
        headMark: !!document.querySelector("#scan-headline .tone-mark svg"),
        rows: rows.map((r) => ({
          row: r.dataset.row, tone: r.dataset.tone,
          tall: vis(r.querySelector("svg.sf-t")), wide: vis(r.querySelector("svg.sf-w")),
          labels: [...r.querySelectorAll(vis(r.querySelector("svg.sf-t")) ? "svg.sf-t text.sf-lbl" : "svg.sf-w text.sf-lbl")].map((t) => t.textContent),
          netRed: !!r.querySelector("svg.sf-w .sf-net:not(.sf-net-calm)"),
          steps: getComputedStyle(r.querySelector(".scan-fig-steps")).gridTemplateColumns.split(" ").length,
        })),
        safe: document.querySelector("#scan-figure .scan-safe")?.textContent ?? null,
        laneAnim: lane ? getComputedStyle(lane).animationName : null,
        yours: document.querySelector('[data-section="yours"]')?.dataset.tone,
        looks: document.querySelector('[data-section="looks"]')?.dataset.tone,
        badge: document.querySelector('[data-section="yours"] .scan-badge')?.textContent,
        flowEnd: document.querySelector('[data-section="yours"] .scan-flow .sf-chip-bad')?.textContent,
        text: document.body.innerText,
      };
    })())`;
    const scanAt = async (width: number) => {
      await p.send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 500 });
      await p.send("Page.navigate", { url: `${base}/scan` });
      await until(`${READY} && location.pathname === "/scan" && document.querySelectorAll("#scan-figure .scan-fig-row").length === 2`, `the Scan page's figure at ${width} px`);
      return JSON.parse(String(await evaluate(facts)));
    };

    // ── P1: a phone ──
    const phone = await scanAt(360);
    assert.equal(phone.scroll, 0, "no horizontal scroll at 360 px");
    assert.ok(phone.headMark, "the headline's ✗");
    assert.ok(phone.bad.length > 0);
    assert.deepEqual(phone.rows.map((r: { row: string; tone: string }) => [r.row, r.tone]), [["without", "bad"], ["with", "ok"]]);
    for (const r of phone.rows) {
      assert.equal(r.tall, true, `${r.row}: the tall layout on a phone`);
      assert.equal(r.wide, false);
      assert.deepEqual(r.labels, ["~/shop/.env", "Claude Code", "Anthropic"]);
      assert.equal(r.steps, 1, "the steps one under another");
    }
    assert.deepEqual(phone.rows.map((r: { netRed: boolean }) => r.netRed), [true, false], "the internet is red only without Mandu");
    assert.match(phone.safe ?? "", /^With Mandu, this secret stays safe: the AI sees only its mask, and your agent still does its work\.$/);
    assert.equal(phone.laneAnim, "none", "reduced motion: the lanes hold still");

    // ── P2: a desktop ──
    const desk = await scanAt(1280);
    assert.equal(desk.scroll, 0);
    for (const r of desk.rows) {
      assert.equal(r.wide, true, `${r.row}: the wide layout on a desktop`);
      assert.equal(r.tall, false);
      assert.deepEqual(r.labels, ["~/shop/.env", "Claude Code", "Anthropic"]);
      assert.equal(r.steps, 3, "the steps in three columns, under the file, the agent and the model");
    }

    // ── P3: the tones of the sections and rows ──
    assert.equal(desk.yours, "bad");
    assert.equal(desk.looks, "warn");
    assert.equal(desk.badge, "Reached the AI");
    assert.equal(desk.flowEnd, "Anthropic’s AI got the real value");

    // ── P4: the oracle ──
    for (const text of [phone.text, desk.text]) {
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
