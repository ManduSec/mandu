/**
 * rules-builtin-one-column — Rules › Built-in protections is one list read
 * top to bottom, in a real headless Chromium over the REAL components
 * (dashboard.md §4.25z *Rules page: the built-in protections follow the
 * mode*). Mandu-new.
 *
 * Until 2026-10-29 the list was a `.plain-list`, two columns wider than
 * 760 px: in the Secrets mode, under the Which files item (the whole row),
 * "Keys and secret files leave this computer…" and "Untrusted content is
 * not masked in this mode…" sat side by side, read left to right, and
 * before the files were read the third sentence sat beside an empty cell.
 *
 * A real ArbiterServer (`secrets`) with a `.env` at `no-model` in
 * policy.yaml, a real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`), and a headless Chromium driven over the
 * DevTools protocol (scripts/tour-screenshots.mjs), signed in, on Rules:
 *
 *   C1  at 1280 and 900 px, every `#builtin-list > li` starts at the same
 *       left edge, and each starts below the bottom of the one before it, in
 *       source order (so no two share a top), the companies' item last;
 *   C2  the same with the Which files and Which companies folds open: the
 *       next sentence starts below the open fold;
 *   C3  every item is as wide as the list, which keeps the card's width (no
 *       cap: the folds' own lists of kinds and companies still lay out as
 *       two columns across it, as before);
 *   C4  the oracle: no page drawn here carries the `.env`'s value or a
 *       token.
 *
 * Self-SKIPs without a Chromium (scripts/tour-screenshots.mjs probeBrowser:
 * MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell, or one on
 * PATH). Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

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

const ENV_VALUE = `builtinOneColumnEnvValue_${process.pid}_0001`;
const WIDTHS = [1280, 900];

interface Item { words: string; cls: string; left: number; width: number; top: number; bottom: number }
interface Measured { items: Item[]; listWidth: number; cardWidth: number; kinds: string; companies: string }
/** Every item's box, the list's and its card's content widths, and the
 *  folds' own lists' columns. Window px. */
const MEASURE = `(() => {
  const list = document.getElementById("builtin-list");
  const card = list.parentElement, cs = getComputedStyle(card);
  const cols = (sel) => { const e = list.querySelector(sel); return e ? getComputedStyle(e).gridTemplateColumns : ""; };
  return {
    items: [...list.children].map((li) => {
      const r = li.getBoundingClientRect();
      return { words: li.textContent.slice(0, 48), cls: li.className, left: r.left, width: r.width, top: r.top, bottom: r.bottom };
    }),
    listWidth: list.getBoundingClientRect().width,
    cardWidth: card.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight),
    kinds: cols(".builtin-kinds"), companies: cols(".issuer-list"),
  };
})()`;

test("Rules › Built-in protections is one column read top to bottom, folds open or closed, its folds' lists still two columns, in a real Chromium over the real arbiter and dashboard; no value on the page (secrets axes)", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 240_000,
}, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-builtin-one-column-"));
  const repo = join(tmp, "home", "proj");
  mkdirSync(repo, { recursive: true });
  const env = join(repo, ".env");
  writeFileSync(env, `DB_PASSWORD=${ENV_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n`);
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
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    fileBrowserHome: join(tmp, "home"),
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  let proc: unknown = null;
  let cdp: Cdp | null = null;
  const pages: string[] = [];
  try {
    const started = await tour.startBrowser(browser as string, join(tmp, "chrome"), process.env);
    proc = started.proc;
    cdp = await tour.Cdp.connect(started.wsUrl);
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const s = (method: string, params: object = {}) => cdp!.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const r = await s("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    };
    await s("Page.enable");
    await s("Runtime.enable");
    await s("Network.enable");
    const eq = ADMIN_COOKIE.indexOf("=");
    await s("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });
    const settle = () => evaluate("new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(() => r(true), 200))))");

    /** Each item starts at the first one's left edge and below the bottom of
     *  the one before it; the companies' item is last. */
    const oneColumn = (m: Measured, at: string) => {
      const [first, ...rest] = m.items;
      assert.ok(first, `${at}: the list has items`);
      for (const [i, it] of rest.entries()) {
        const before = m.items[i]!;
        assert.ok(Math.abs(it.left - first.left) <= 1, `${at}: "${it.words}" starts at the list's left edge (${JSON.stringify(m.items)})`);
        assert.ok(it.top >= before.bottom - 1, `${at}: "${it.words}" starts below "${before.words}", not beside it (${JSON.stringify(m.items)})`);
      }
      assert.equal(m.items.at(-1)!.cls, "builtin-issuers", `${at}: the companies' item is last`);
    };

    for (const width of WIDTHS) {
      await s("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: false });
      await s("Page.navigate", { url: `${base}/rules` });
      let ok = false;
      for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((r) => setTimeout(r, 100))) {
        try {
          // The Secrets mode's three sentences, Which files read (home?files=1), and the companies.
          ok = await evaluate(`document.readyState === "complete" && document.fonts.status === "loaded"
            && document.querySelectorAll("#builtin-list > li").length === 4
            && !!document.querySelector("#builtin-list > li.builtin-files details")
            && !!document.querySelector("#builtin-list > li.builtin-issuers details")`);
        } catch { /* navigating */ }
      }
      assert.ok(ok, `${width}px: Rules draws the Secrets mode's built-in protections with both folds`);
      await settle();
      pages.push(await evaluate("document.documentElement.outerHTML + document.body.innerText"));

      // C1: folds closed.
      const closed = await evaluate(MEASURE) as Measured;
      assert.match(closed.items[0]!.words, /^Keys and secret files reach the AI masked/);
      assert.match(closed.items[2]!.words, /^Untrusted content is not masked in this mode/);
      oneColumn(closed, `${width}px, folds closed`);
      // C3: one width for every item, the card's.
      assert.ok(Math.abs(closed.listWidth - closed.cardWidth) <= 1, `${width}px: the list keeps the card's width (${closed.listWidth} of ${closed.cardWidth})`);
      const itemWidth = closed.listWidth - 20; // the list's padding-left, where the bullets sit
      for (const it of closed.items) assert.ok(Math.abs(it.width - itemWidth) <= 1, `${width}px: "${it.words}" is as wide as the list (${it.width} of ${itemWidth})`);

      // C2: folds open.
      await evaluate(`[...document.querySelectorAll("#builtin-list > li > details")].forEach((d) => { d.open = true; }), true`);
      await settle();
      const open = await evaluate(MEASURE) as Measured;
      oneColumn(open, `${width}px, folds open`);
      assert.ok(open.items[1]!.top > closed.items[1]!.top + 50, `${width}px: the open Which files fold pushes the next sentence down`);
      // C3: the folds' own lists keep two columns.
      for (const [what, cols] of [["Which files' kinds", open.kinds], ["Which companies", open.companies]]) {
        assert.equal(cols!.trim().split(/\s+/).length, 2, `${width}px: ${what} is still two columns (${cols})`);
      }
      pages.push(await evaluate("document.documentElement.outerHTML + document.body.innerText"));
    }

    // C4: the oracle.
    assert.equal(pages.length, WIDTHS.length * 2, "every page was read");
    for (const p of pages) {
      assert.ok(!p.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: .env's value on a page");
      assert.doesNotMatch(p, /\$MDU:/, "nor a token");
    }
  } finally {
    cdp?.close();
    if (proc) await tour.stopProc(proc);
    await dashboard.close();
    wired?.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
