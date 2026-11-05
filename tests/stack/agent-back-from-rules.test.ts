/**
 * agent-back-from-rules e2e — a session's page opened from Rules has a back
 * link that says "Back to Rules" and returns to where you were on Rules
 * (dashboard.md §4.25ad *The back link names where you came from*, §4.25
 * *Back and Forward keep your place*), across the REAL components: a real
 * ArbiterServer in `secrets` and the real dashboard over it with the
 * production approvals and secrets adapters (`makeApprovalsArbiter`), signed
 * in, in a real headless Chromium. Mandu-new.
 *
 * Until 2026-10-29 (#196) the link knew only Home, History and Approvals:
 * opened from Rules › Files made from your secrets › "this session", it read
 * "Back to home" and, pressed, went Home, dropping your place on a page some
 * 2,300 px tall.
 *
 * The seed (as rules-made-from-secrets.test.ts): a session reads a memo
 * labelled `any-model` as it was, so it is HIGH, and its Write is labelled;
 * Rules › Files made from your secrets lists the file, with "this session".
 * Then, at 1280 and at 390 px:
 *
 *   A1  Rules opened, the card shown, its "this session" scrolled down the
 *       screen and followed; the session's page opens, its back link reads
 *       "Back to Rules" and links /rules;
 *   A2  the back link pressed: Rules within 3 px of where it was, no entry
 *       added (it is Back), the link still on the screen;
 *   A3  the oracle: neither page Chromium drew carries the memo or a token.
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
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
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

const MEMO = `Acme pays $4,200,000 on 2026-09-30. MEMO_CANARY_196_${process.pid}`;
const SESSION = "1791500000-196";

test("in a real Chromium at 1280 and 390 px: a session opened from Rules › Files made from your secrets reads \"Back to Rules\", and pressing it lands Rules within 3 px of where you were (secrets axes, explicit)", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-agent-back-rules-"));
  const home = join(tmp, "home");
  const app = join(home, "app");
  mkdirSync(app, { recursive: true });
  mkdirSync(join(home, "memos"), { recursive: true });
  const memo = join(home, "memos", "q3.md");
  const summary = join(app, "summary.md");
  writeFileSync(memo, MEMO);
  writeFileSync(summary, "a summary\n");

  const socketPath = join(tmp, "arbiter.sock");
  const adminPath = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminPath, humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const admin = new ArbiterClient(adminPath); await admin.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminPath }));
  assert.ok(wired?.secrets, "the production secrets adapter");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter,
    secretsArbiter: wired.secrets,
    policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const { proc, wsUrl } = await tour.startBrowser(chromium as string, join(tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  try {
    // ── The seed: a HIGH session's Write ────────────────────────────────────
    await admin.setPathLabel({ path: join(home, "memos"), confidentiality: "any-model", bindings: [] });
    const s = await admin.symbolizeFull({ tool: "Read", value: MEMO, field: "content", origin: memo, integrity: "trusted", sessionKey: SESSION });
    assert.equal((await admin.declassifySymbol({ symbol: s.symbol, sessionKey: SESSION })).allowed, true);
    assert.equal((await admin.sessionState(SESSION)).high, true, "the session read a secret as it was");
    const wrote = await admin.labelWrittenPath({ sessionKey: SESSION, path: summary, tool: "Write" });
    assert.equal(wrote.labeled, true, JSON.stringify(wrote));

    // ── Chromium, signed in ─────────────────────────────────────────────────
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

    const link = `[...document.querySelectorAll("#made-from-list .made-from-row")].find((r) => r.getAttribute("data-path") === ${JSON.stringify(summary)})?.querySelector("a.made-from-session")`;
    for (const width of [1280, 390]) {
      await send("Emulation.setDeviceMetricsOverride", { width, height: 600, deviceScaleFactor: 1, mobile: width < 600 });
      await send("Page.navigate", { url: `${base}/rules` });

      // ── A1: the card's "this session", followed from down the page ───────
      await until(`${width}: Rules lists the file`, `!document.getElementById("page-rules").hidden && !document.getElementById("made-from-block").hidden && document.fonts.status === "loaded"`);
      await evaluate(`document.getElementById("made-from-open").click(), true`);
      await until(`${width}: the card shows the file and its session`, `!!${link}`);
      assert.equal(await evaluate(`${link}.textContent`), "this session");
      // The link 450 px down the screen, as far as the page lets it be, then a
      // pause past the page's own save of the scroll.
      await evaluate(`window.scrollTo(0, ${link}.getBoundingClientRect().top + window.scrollY - 450), true`);
      await new Promise((r) => setTimeout(r, 500));
      const before = await evaluate(`({ y: window.scrollY, top: ${link}.getBoundingClientRect().top, height: document.documentElement.scrollHeight })`);
      assert.ok(before.y > 100, `${width}: down the page (${before.y} of ${before.height} px)`);
      await evaluate(`${link}.click(), true`);
      await until(`${width}: the session's page shown`, `!document.getElementById("page-agent").hidden && location.pathname === ${JSON.stringify(`/agents/${SESSION}`)}`);
      const back = await evaluate(`(() => { const a = document.getElementById("agent-back"); return { text: a.textContent, href: a.getAttribute("href"), entries: history.length, body: document.body.innerText }; })()`);
      assert.equal(back.text, "Back to Rules", `${width}: the back link names Rules`);
      assert.equal(back.href, "/rules", `${width}: and links it, for a new tab`);

      // ── A2: the back link pressed, Rules where it was ────────────────────
      await evaluate(`document.getElementById("agent-back").click(), true`);
      await until(`${width}: Rules back`, `!document.getElementById("page-rules").hidden && location.pathname === "/rules" && !!${link}`);
      await new Promise((r) => setTimeout(r, 800)); // past every read Back made
      const after = await evaluate(`({ y: window.scrollY, top: ${link}.getBoundingClientRect().top, entries: history.length, body: document.body.innerText })`);
      assert.ok(Math.abs(after.y - before.y) <= 3, `${width}: Rules within 3 px of where it was: ${after.y}, was ${before.y}`);
      assert.ok(after.top >= 0 && after.top < 600, `${width}: the link on the screen (${after.top} px down)`);
      assert.equal(after.entries, back.entries, `${width}: it is Back: no entry added`);

      // ── A3: the oracle ───────────────────────────────────────────────────
      for (const [page, body] of [["session", back.body], ["Rules", after.body]] as const) {
        assert.ok(!body.includes("MEMO_CANARY_196") && !body.includes("4,200,000"), `CONFIDENTIALITY VIOLATION: the ${page} page carries the memo (${width} px)`);
        assert.doesNotMatch(body, /\$MDU:/, `the ${page} page carries a token (${width} px)`);
      }
    }
  } finally {
    cdp.close();
    await tour.stopProc(proc);
    await dashboard.close();
    admin.close();
    wired.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
