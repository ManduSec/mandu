/**
 * history-scan-line e2e — History's line on the sessions your agents ran
 * without Mandu follows Home's scan card, in a real browser (dashboard.md
 * §4.25ai *History's scan line*, 2026-10-27). Mandu-new.
 *
 * Until 2026-10-27 the line was fixed in the page, "Sessions your agents ran
 * without Mandu: what the last scan found", also on a computer where no scan
 * had run. A REAL ArbiterServer (secrets) and a REAL DashboardServer over
 * the production adapter serve History to a REAL headless Chromium
 * (Playwright's headless shell; none found: the test skips) at 390×844,
 * signed in with the one-time admin link:
 *
 *   H1  no `mandu scan` kept: the line says `mandu scan` reads them, with its
 *       Copy, links how it works, and never says "the last scan found";
 *   H2  a scan kept while History is open (the record as the launcher keeps
 *       it, with one finding, plus a planted value in fields the record
 *       never has): the next Home poll draws the card's headline as the
 *       link, with its ✗ and its `when`; no horizontal scroll at 390 px;
 *   H3  the link opens the Scan page;
 *   H4  the oracle: no 8-character run of the planted value on either page,
 *       nor in `/api/home`.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import type { ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { chromiumBinary, READY, startChromium, stopChromium } from "../lib/chromium.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const BIN = chromiumBinary();
// Assembled at run time: this file holds no credential-shaped literal.
const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6HistoryScanLine`;
const WIDTH = 390;
const HEIGHT = 844;

function record(): unknown {
  return {
    version: 1, ranAt: "2026-10-22T09:00:00.000Z", sessions: { "claude-code": 12 }, duringMandu: 0, known: 2,
    secret: STRIPE, // not a field of the record: dropped when read
    findings: [
      {
        kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, sessions: 2, agents: ["claude-code"],
        last: "2026-10-19T10:00:00.000Z", how: { "command-output": 2 }, projects: ["~/shop"], duringMandu: 0, raw: STRIPE,
        examples: [{ at: "2026-10-19T10:00:00.000Z", agent: "claude-code", how: "command-output", command: "cat .env", project: "~/shop", mandu: "without", provider: "anthropic" }],
      },
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

function noValue(where: string, text: string): void {
  for (let i = 0; i + 8 <= STRIPE.length; i++) {
    const piece = STRIPE.slice(i, i + 8);
    if (piece !== "sk_live_") assert.ok(!text.includes(piece), `${where} carries "${piece}"`);
  }
}

let tmp = "";
after(() => {
  resetCurrentPolicyForTests("claude-code");
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

test("History's scan line at 390 px: how to run a scan before any, the kept scan's headline after one (drawn by the poll), its link opens the Scan page, no value", { skip: BIN === null ? "no headless Chromium (Playwright's headless shell) on this host" : false, timeout: 120_000 }, async () => {
  tmp = mkdtempSync(join(tmpdir(), "mdu-history-scan-"));
  const home = join(tmp, "home");
  const mh = join(tmp, "mh"); // no state/last-scan.json yet: no scan kept
  mkdirSync(join(mh, "state"), { recursive: true });
  mkdirSync(home, { recursive: true });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\npaths: []\n");
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
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc, "the production adapter has the secrets and policy surfaces");
  const dash = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { HOME: home, MANDU_HOME: mh, MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
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
      target = list.find((x) => x.type === "page") ?? null;
      if (target === null) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(target, "the page is listed");
    page = await devtools(target.webSocketDebuggerUrl);
    const p = page;
    const evaluate = async (expression: string): Promise<unknown> => (await p.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true })).result?.result?.value;
    // Up to 25 s: a scan kept meanwhile shows on the next 10 s poll.
    const until = async (expression: string, what: string): Promise<void> => {
      for (let i = 0; i < 250; i++) {
        if (await evaluate(expression) === true) return;
        await new Promise((r) => setTimeout(r, 100));
      }
      assert.fail(`the page never showed ${what}`);
    };
    await until(`${READY} && location.pathname === "/"`, "Home after the sign-in link");
    await p.send("Emulation.setDeviceMetricsOverride", { width: WIDTH, height: HEIGHT, deviceScaleFactor: 1, mobile: true });
    const facts = async () => JSON.parse(String(await evaluate(`JSON.stringify((() => {
      const line = document.getElementById("history-scan");
      const a = line.querySelector('a[data-page-link="scan"]');
      return {
        text: line.textContent.replace(/\\s+/g, " ").trim(),
        code: line.querySelector(".run-code > code")?.textContent ?? null,
        copy: line.querySelector(".run-code > button.run-copy")?.getAttribute("aria-label") ?? null,
        link: a ? a.textContent.trim() : null, href: a ? a.getAttribute("href") : null,
        mark: !!line.querySelector(".tone-mark svg"), tone: line.dataset.tone,
        scroll: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        page: document.body.innerText,
      };
    })())`)));

    // ── H1: no scan kept ──
    await p.send("Page.navigate", { url: `${base}/history` });
    await until(`${READY} && location.pathname === "/history" && !!document.querySelector("#history-scan .run-code")`, "History's line with `mandu scan`");
    const none = await facts();
    assert.equal(none.code, "mandu scan");
    assert.equal(none.copy, "Copy mandu scan", "the command has its Copy");
    assert.match(none.text, /^Sessions your agents ran without Mandu are not listed here\. mandu scan(?:Copy)? reads them and shows which of your secrets already went to the AI\. How it works\.$/);
    assert.doesNotMatch(none.text, /last scan found/);
    assert.equal(none.link, "How it works");
    assert.equal(none.href, "/scan");
    assert.equal(none.scroll, 0, `no horizontal scroll at ${WIDTH} px`);

    // ── H2: a scan kept while History is open ──
    writeFileSync(join(mh, "state", "last-scan.json"), JSON.stringify(record()), { mode: 0o600 });
    await until(`!!document.querySelector("#history-scan .tone-mark")`, "the kept scan's headline on the next poll");
    const kept = await facts();
    assert.equal(kept.link, "1 of your secrets left this computer in your agents' requests");
    assert.match(kept.text, /^Sessions your agents ran without Mandu: 1 of your secrets left this computer in your agents' requests\. Scanned [^.]+ · 12 past sessions\.$/);
    assert.equal(kept.code, null, "no command once a scan ran");
    assert.ok(kept.mark, "the ✗ beside the headline");
    assert.equal(kept.tone, "bad");
    assert.equal(kept.href, "/scan");
    assert.equal(kept.scroll, 0, `the long headline wraps at ${WIDTH} px: no horizontal scroll`);
    const api = String(await evaluate(`fetch("/api/home").then((r) => r.text())`));
    assert.match(api, /"headline":"1 of your secrets left/, "the page's words are the server's");

    // ── H3: the link opens the Scan page ──
    await evaluate(`document.querySelector('#history-scan a[data-page-link="scan"]').click(), true`);
    await until(`location.pathname === "/scan" && !document.getElementById("page-scan").hidden && !!document.getElementById("scan-headline")?.textContent`, "the Scan page after the link");
    const scanText = String(await evaluate("document.body.innerText"));
    assert.match(scanText, /1 of your secrets left this computer/);

    // ── H4: the oracle ──
    noValue("History (no scan)", none.page);
    noValue("History (a scan kept)", kept.page);
    noValue("the Scan page", scanText);
    noValue("/api/home", api);
  } finally {
    page?.close();
    await stopChromium(chrome, profile);
    await dash.close();
    await arbiter.close();
  }
});
