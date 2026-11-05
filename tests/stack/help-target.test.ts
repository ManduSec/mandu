/**
 * help-target.test — a "?" help button is a 24 px target that stops short of
 * the link before it, in a real headless Chromium over the REAL components
 * (dashboard.md §4.25u *A help button is a 24 px target*). Mandu-new.
 *
 * Until 2026-10-28 every help button was an 18 × 18 px circle, and on Home's
 * counts line the "?" of *What masked means* sat 3 px after the link "N
 * secrets masked before the AI saw them": a tap a few pixels off the "?"
 * opened the session or History instead of the note. Here a real
 * ArbiterServer (`secrets`) whose event store holds the recorded
 * first-session tour (dashboard/test/fixtures/tour-1791164083-1418381.ndjson,
 * fake secrets, its times moved so it ended a minute ago), with a registered
 * `.env` whose key its real egress gate stops at a host no rule binds it to,
 * so one question waits; a real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`); and a headless Chromium driven over the DevTools
 * protocol (scripts/tour-screenshots.mjs), signed in. At 1280 and 390 px:
 *
 *   T1  Home's counts line: the "?" after the masked count's link. The area
 *       where `document.elementFromPoint` returns the button (walked out
 *       from its centre a pixel at a time) is at least 24 × 24 px, its four
 *       corners and 2 px outside the circle toward the link included; it
 *       overlaps no link or button of the page, and the link's own last
 *       pixel is still the link;
 *   T2  a real mouse click 2 px outside the circle, toward the link, opens
 *       the note (`aria-expanded="true"`) and the page stays Home;
 *   T3  the same for *What the AI has now ?* on the Approvals card;
 *   T4  the oracle: no page drawn here carries the key, the tour's fake
 *       values or a token.
 *
 * Self-SKIPs without a Chromium (scripts/tour-screenshots.mjs probeBrowser:
 * MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell, or one on
 * PATH). Axes: secrets (stated).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, ADMIN_TOKEN, SESSION_SECRET } from "../../dashboard/test/unit/admin-session.js";
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
  FAKE_VALUES: string[];
};
const browser = tour.probeBrowser({});

const ID = "1791164083-1418381";
const FIXTURE = join(REPO, "dashboard", "test", "fixtures", `tour-${ID}.ndjson`);
const KEY_VALUE = `sk_live_helpTargetCanary_${process.pid}_7c1d`;
const SESSION = `help-target-${process.pid}`;
const WIDTHS = [1280, 390];

/**
 * The help button `sel` names, and the area where a point hits it: walked
 * out from the circle's centre a pixel at a time along both axes, then its
 * four corners and the point 2 px outside the circle toward the link before
 * it, if any. Every link and button of the page whose box meets that area
 * is listed, and the link's own last pixel is read back.
 */
const probe = (sel: string) => `(() => {
  const btn = document.querySelector(${JSON.stringify(sel)});
  if (!btn) return null;
  btn.scrollIntoView({ block: "center" });
  const r = btn.getBoundingClientRect();
  const cx = (r.left + r.right) / 2, cy = (r.top + r.bottom) / 2;
  const on = (x, y) => { const e = document.elementFromPoint(x, y); return !!e && (e === btn || btn.contains(e)); };
  const walk = (dx, dy) => { let d = 0; while (d < 40 && on(cx + (d + 1) * dx, cy + (d + 1) * dy)) d += 1; return d; };
  // A point at x hits a box spanning [left, right): the last point on is a pixel short of its right edge.
  const hit = { left: cx - walk(-1, 0), right: cx + walk(1, 0) + 1, top: cy - walk(0, -1), bottom: cy + walk(0, 1) + 1 };
  const corners = [[hit.left + 0.5, hit.top + 0.5], [hit.right - 0.5, hit.top + 0.5], [hit.left + 0.5, hit.bottom - 0.5], [hit.right - 0.5, hit.bottom - 0.5]].map(([x, y]) => on(x, y));
  const box = (b) => ({ left: b.left, right: b.right, top: b.top, bottom: b.bottom });
  const meets = [];
  for (const o of document.querySelectorAll("a, button, input, select, summary, label")) {
    if (o === btn || btn.contains(o)) continue;
    for (const b of o.getClientRects()) {
      if (b.width && b.height && b.left < hit.right + 1 && b.right > hit.left - 1 && b.top < hit.bottom + 1 && b.bottom > hit.top - 1) {
        meets.push(o.tagName + ":" + (o.textContent || "").trim().slice(0, 50) + " " + JSON.stringify(box(b)));
      }
    }
  }
  // The link the button follows (Home's count): its last line box.
  const holder = btn.closest(".help").parentElement;
  const link = [...holder.querySelectorAll("a")].pop() || null;
  let toward = null, linkEnd = null, gap = null;
  if (link) {
    const last = [...link.getClientRects()].pop();
    const ly = (last.top + last.bottom) / 2;
    const e = document.elementFromPoint(last.right - 1, ly);
    linkEnd = !!e && (e === link || link.contains(e));
    toward = on(r.left - 2, cy);
    gap = r.left - last.right;
  }
  return { circle: box(r), hit, corners, meets, link: link && link.textContent.trim(), toward, linkEnd, gap, x: r.left - 2, y: cy, path: location.pathname };
})()`;
interface Probe {
  circle: { left: number; right: number; top: number; bottom: number };
  hit: { left: number; right: number; top: number; bottom: number };
  corners: boolean[]; meets: string[]; link: string | null; toward: boolean | null; linkEnd: boolean | null; gap: number | null;
  x: number; y: number; path: string;
}

test("a help button's hit area is 24 × 24 px and stops short of the link before it; a click at its edge opens its note, on Home's counts line and an Approvals card, in a real Chromium over the real arbiter and dashboard (secrets axes)", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 240_000,
}, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-help-target-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const eventDir = join(tmp, "events");
  mkdirSync(eventDir, { recursive: true });
  const events = readFileSync(FIXTURE, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { ts: string });
  const shift = Date.now() - 60_000 - Date.parse(events.at(-1)!.ts);
  writeFileSync(join(eventDir, `${ID}.ndjson`), events.map((e) => JSON.stringify({ ...e, ts: new Date(Date.parse(e.ts) + shift).toISOString() })).join("\n") + "\n");
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir, policyPath: join(tmp, "policy.yaml"), policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(socketPath);
  await gate.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production adapter is wired");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, secretsArbiter: wired.secrets,
    postureArbiter: wired.posture, auditArbiter: wired.audit,
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home"), HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  let proc: unknown = null;
  let cdp: Cdp | null = null;
  const pages: string[] = [];
  try {
    // One question waits: the key of a registered `.env`, at a host no rule binds it to.
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const symbol = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(symbol, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const d = await gate.desymbolizationDecision({ symbol, boundary: "network", destination: "api.stripe.com", sessionKey: SESSION, scheme: "https" });
    assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "the gate asks");

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
    const settle = () => evaluate("new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(() => r(true), 150))))");
    const open = async (path: string, ready: string, at: string) => {
      await s("Page.navigate", { url: base + path });
      let ok = false;
      for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((r) => setTimeout(r, 100))) {
        try { ok = await evaluate(`document.readyState === "complete" && document.fonts.status === "loaded" && (${ready})`); } catch { /* navigating */ }
      }
      assert.ok(ok, `${at}: the page drew`);
      await settle();
    };
    const click = async (x: number, y: number) => {
      for (const type of ["mousePressed", "mouseReleased"]) await s("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1 });
      await settle();
    };
    const check = (p: Probe | null, at: string): Probe => {
      assert.ok(p, `${at}: the help button is drawn`);
      const w = p.hit.right - p.hit.left, h = p.hit.bottom - p.hit.top;
      assert.ok(w >= 24 && h >= 24, `${at}: a tap lands on the button over at least 24 × 24 px, not ${w} × ${h} (circle ${JSON.stringify(p.circle)})`);
      assert.deepEqual(p.corners, [true, true, true, true], `${at}: each corner of that area is the button`);
      assert.deepEqual(p.meets, [], `${at}: that area meets no other link or button`);
      return p;
    };

    for (const width of WIDTHS) {
      await s("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 640 });

      // T1, T2: Home's counts line.
      const HOME_HELP = "#hero-facts .help-btn";
      await open("/", `!!document.querySelector(${JSON.stringify(HOME_HELP)})`, `Home at ${width}px`);
      const at = `Home's counts line at ${width}px`;
      const p = check(await evaluate(probe(HOME_HELP)) as Probe | null, at);
      assert.match(p.link ?? "", /masked before the AI saw/, `${at}: the "?" follows the masked count's link`);
      assert.equal(p.toward, true, `${at}: 2 px outside the circle toward the link is the button`);
      assert.equal(p.linkEnd, true, `${at}: the link's last pixel is still the link`);
      await click(p.x, p.y);
      assert.equal(await evaluate(`document.querySelector(${JSON.stringify(HOME_HELP)}).getAttribute("aria-expanded")`), "true", `${at}: a click at its edge opens the note`);
      assert.equal(await evaluate("location.pathname"), p.path, `${at}: and the page stays Home`);
      pages.push(await evaluate("document.documentElement.outerHTML + document.body.innerText"));

      // T3: What the AI has now ? on the Approvals card.
      const ASK_HELP = "#approvals-waiting .ask .ask-detail .help-btn";
      await open("/approvals", `!!document.querySelector(${JSON.stringify(ASK_HELP)})`, `Approvals at ${width}px`);
      const ap = `What the AI has now on Approvals at ${width}px`;
      const q = check(await evaluate(probe(ASK_HELP)) as Probe | null, ap);
      const r = q.circle;
      await click(r.left - 2, (r.top + r.bottom) / 2);
      assert.equal(await evaluate(`document.querySelector(${JSON.stringify(ASK_HELP)}).getAttribute("aria-expanded")`), "true", `${ap}: a click 2 px outside the circle opens the note`);
      assert.equal(await evaluate("location.pathname"), q.path, `${ap}: and the page stays Approvals`);
      pages.push(await evaluate("document.documentElement.outerHTML + document.body.innerText"));
    }

    // T4: the oracle.
    assert.equal(pages.length, WIDTHS.length * 2, "every page was read");
    for (const page of pages) {
      assert.ok(!page.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: the key's value on a page");
      for (const v of tour.FAKE_VALUES) assert.ok(!page.includes(v), `CONFIDENTIALITY VIOLATION: the tour's ${v} on a page`);
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
      assert.ok(!page.includes(ADMIN_TOKEN) && !page.includes(SESSION_SECRET), "no credential on a page");
    }
  } finally {
    cdp?.close();
    if (proc) await tour.stopProc(proc);
    await dashboard.close();
    gate.close();
    wired?.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
