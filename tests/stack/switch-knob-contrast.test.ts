/**
 * switch-knob-contrast e2e — an on/off switch's knob reads at least 3:1 on
 * its track, on and off, light and dark (dashboard.md §4.25k *A switch's
 * knob reads 3:1 on its track*), across the REAL components: a real
 * ArbiterServer in `secrets` with a registered `.env`, and the real
 * dashboard over the PRODUCTION adapter (`makeApprovalsArbiter`), signed
 * in, its served pages and styles in a real headless Chromium. Mandu-new.
 *
 * Until 2026-10-29 the knob was always white: in the dark theme it read
 * 2.15:1 on the green "on" track and 2.93:1 on the grey "off" one, under
 * WCAG 2.1 SC 1.4.11's 3:1 for the part that shows a control's state.
 *
 *   S1  Settings › Protection, as the saved setting draws it: on (no
 *       config.toml), then off (`mode = "off"`);
 *   S2  History's *Only sessions where Mandu stepped in*, with one session
 *       on record (an empty History draws no switch): off, then on
 *       (`?only=stepped-in`);
 *   S3  each in the stored `mandu.theme` light and dark: the computed
 *       `backgroundColor` of `.knob` reads ≥ 3:1 on its `.switch`'s; the
 *       light knob is still white;
 *   S4  the oracle: no drawn page carries the key or the admin token.
 *
 * The native checkboxes (`accent-color: var(--ok)`) are drawn by Chromium
 * itself, and their edge is not in any computed style: the test reports
 * their accent color as a diagnostic and asserts nothing of them.
 *
 * Self-SKIPs without a Chromium (probeBrowser: MANDU_TOUR_BROWSER,
 * CHROME_PATH, a Playwright headless shell). The rule as the stylesheets
 * write it, in every palette: dashboard/test/unit/ui/css-switch-knob.test.ts.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm test  (tests/)
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { emitLauncherEvent, sessionExitEvent } from "../../launcher/src/services/observe.js";
import { ADMIN_COOKIE, ADMIN_OPTS, ADMIN_TOKEN } from "../../dashboard/test/unit/admin-session.js";
import { contrastRatio } from "../../dashboard/test/unit/ui/css-flatten.js";
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

const KEY = `sk_live_switchKnobCanary_${process.pid}_4Hc8Wq`;
const SESSION = "1791300000-216";

const dirs: string[] = [];
const closers: Array<() => Promise<void>> = [];
after(async () => {
  for (const c of closers.reverse()) await c();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

test("in a real Chromium: every switch's knob reads 3:1 at the least on its track, on and off, light and dark (secrets axes, explicit)", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-switch-knob-"));
  dirs.push(tmp);
  const home = join(tmp, "home");
  const manduHome = join(tmp, "mandu-home");
  mkdirSync(join(home, "proj"), { recursive: true });
  mkdirSync(manduHome, { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath: join(tmp, "policy.yaml"), policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(socketPath);
  await gate.connect();
  const env = join(home, "proj", ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY}\n`);
  const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
  assert.ok(reg.symbol || reg.twin, `the .env is registered: ${JSON.stringify(reg)}`);
  // One session on record: an empty History draws no search and no switch.
  assert.ok(await emitLauncherEvent(socketPath, sessionExitEvent({ scopeId: SESSION, code: 0, durationMs: 4_000 }), humanPath), "the launcher's emit lands");
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production adapter is wired");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, secretsArbiter: wired.secrets,
    postureArbiter: wired.posture, auditArbiter: wired.audit,
    fileBrowserHome: home, configEnv: { MANDU_HOME: manduHome, HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  closers.push(async () => { await dashboard.close(); gate.close(); wired.close(); await arbiter.close(); });

  const { proc, wsUrl } = await tour.startBrowser(chromium as string, join(tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  try {
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
    await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
    await send("Page.navigate", { url: `${base}/settings` });
    await until("the page loads", `document.readyState === "complete"`);

    /** Each switch as a page draws it: the page, the switch, its state, and
     *  what the stack must hold first. */
    const cases = [
      { what: "Settings › Protection, on", url: "/settings", id: "switch-protection", checked: true, saved: null },
      { what: "Settings › Protection, off", url: "/settings", id: "switch-protection", checked: false, saved: 'mode = "off"\n' },
      { what: "History's stepped-in filter, off", url: "/history", id: "history-only", checked: false, saved: null },
      { what: "History's stepped-in filter, on", url: "/history?only=stepped-in", id: "history-only", checked: true, saved: null },
    ];
    let measured = 0;
    for (const c of cases) {
      if (c.saved) writeFileSync(join(manduHome, "config.toml"), c.saved);
      for (const theme of ["light", "dark"] as const) {
        await evaluate(`localStorage.setItem("mandu.theme", ${JSON.stringify(theme)}), true`);
        await send("Page.navigate", { url: base + c.url });
        const sw = `document.getElementById(${JSON.stringify(c.id)})`;
        // Settings' switch is held (disabled) until the page has read the
        // saved setting; History's shows once its page is the one drawn.
        await until(`${theme}, ${c.what}: the switch is drawn in its state`,
          `document.readyState === "complete" && !!${sw} && ${sw}.getClientRects().length > 0 && !${sw}.disabled && ${sw}.getAttribute("aria-checked") === "${c.checked}"`);
        assert.equal(await evaluate(`document.documentElement.getAttribute("data-theme")`), theme, `${theme}: the stored choice pins the theme`);
        // The track's color eases over 120 ms: read it once it has settled.
        await new Promise((r) => setTimeout(r, 300));
        const got = await evaluate(`(() => {
          const s = ${sw};
          return { track: getComputedStyle(s).backgroundColor, knob: getComputedStyle(s.querySelector(".knob")).backgroundColor };
        })()`) as { track: string; knob: string };
        const ratio = contrastRatio(got.knob, got.track);
        t.diagnostic(`${theme}, ${c.what}: knob ${got.knob} on track ${got.track}, ${ratio.toFixed(2)}:1`);
        assert.ok(ratio >= 3, `${theme}, ${c.what}: the knob ${got.knob} reads ${ratio.toFixed(2)}:1 on its track ${got.track}, under 3:1`);
        if (theme === "light") assert.equal(got.knob, "rgb(255, 255, 255)", `light, ${c.what}: the knob is still white`);
        else assert.equal(got.knob, "rgb(31, 33, 38)", `dark, ${c.what}: the knob is the panel's color`);
        measured += 1;

        if (c.url === "/settings") {
          // Reported, not asserted: the native checkboxes Chromium draws
          // (every page's markup is in the document, drawn or not).
          const boxes = await evaluate(`[...document.querySelectorAll('.choice input[type="checkbox"]')].map((b) => b.id + " " + getComputedStyle(b).accentColor)`) as string[];
          t.diagnostic(`${theme}, the page's checkboxes (accent-color): ${boxes.join("; ") || "none drawn"}`);
        }
        // ── S4: the oracle ──
        const body = await evaluate(`document.body.innerText + document.documentElement.outerHTML`) as string;
        assert.ok(!body.includes(KEY), `CONFIDENTIALITY VIOLATION: ${theme}, ${c.what}: the page shows the key`);
        assert.ok(!body.includes(ADMIN_TOKEN), `${theme}, ${c.what}: the page carries the admin token`);
      }
    }
    assert.equal(measured, 8, "four switches, each in both themes");
  } finally {
    cdp.close();
    await tour.stopProc(proc);
  }
});
