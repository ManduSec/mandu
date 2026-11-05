/**
 * protection-off-typed.test — Settings › Protection: turning protection off
 * asks on the page, and the word OFF counts in any case, across the REAL
 * components (dashboard.md §4.25 *Turning protection off asks on the page,
 * and OFF takes any case*). Mandu-new.
 *
 * Until 2026-10-25 the switch asked with the browser's own `window.prompt`
 * and took only the exact text `OFF`: "off", "Off" (a phone keyboard) or
 * "OFF " (autocomplete) left protection on and said nothing. Here a real
 * ArbiterServer runs at the `secrets` axes with a labelled secret file, a
 * real DashboardServer reaches it over the production adapter
 * (`makeApprovalsArbiter`) and keeps its config.toml in a scratch
 * MANDU_HOME, and the page is signed in:
 *
 *   P1  the switch, pressed, opens the box in the Protection row and posts
 *       nothing;
 *   P2  "of" keeps Turn off off and shows the hint; Enter posts nothing and
 *       config.toml is unchanged; Escape closes the box, the focus back on
 *       the switch, still On;
 *   P3  "off" (lower case) and Enter: config.toml says `mode = "off"`, and
 *       the row reads Off;
 *   P4  in Chromium, at 390 px and 1280 px: the box and its buttons fit the
 *       row, the page has no sideways scroll, and the box is at least 16 px;
 *   P5  the oracle: no page text carries the labelled value or a token.
 *
 * Once in jsdom over the served page and script (served-page.ts), and once
 * in a real headless Chromium over the DevTools protocol
 * (scripts/tour-screenshots.mjs, as settings-notify-off.test does), which
 * self-SKIPs without a Chromium (probeBrowser). Axes: secrets (stated; the
 * arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { offBox, typeInOffBox, enterInOffBox } from "../../dashboard/test/unit/ui/protect-off.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { withTeardown } from "../lib/teardown.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const KEY_VALUE = `sk_live_offTypedCanary_${process.pid}_00000000`;
const SETTLE_MS = 500;
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ASK = "Turning this off lets your secrets leave this computer. Type OFF to turn it off.";
const HINT = "Type the word OFF to turn protection off.";
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  removeProfile: (dir: string) => void;
  Cdp: { connect(url: string): Promise<Cdp> };
};
const browser = tour.probeBrowser({});

/** A fresh stack: the arbiter (secrets axes) with a labelled secret file,
 *  the dashboard over the production wiring with its config.toml in a
 *  scratch MANDU_HOME. `config()` is that file, or null before a write. */
async function stack() {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-protection-off-typed-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const mhome = join(tmp, "mhome");
  mkdirSync(mhome);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const env = join(home, "proj", ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  await admin.setPathLabel({ path: env, confidentiality: "no-model", bindings: [], recursive: false });
  admin.close();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, fileBrowserHome: home,
    configEnv: { MANDU_HOME: mhome, MANDU_POLICY_FILE: policyPath }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const configPath = join(mhome, "config.toml");
  return {
    tmp, base,
    config: (): string | null => (existsSync(configPath) ? readFileSync(configPath, "utf8") : null),
    close: async () => {
      await dashboard.close();
      wired.close();
      await arbiter.close();
      tour.removeProfile(tmp); // the browser's profile is in it: stopProc has ended its whole group
    },
  };
}

function oracle(what: string, text: string) {
  assert.ok(!text.includes(KEY_VALUE), `CONFIDENTIALITY VIOLATION: ${what} carries the labelled value`);
  assert.doesNotMatch(text, /\$MDU/, `${what} carries no token`);
}
const OFF_LINE = /^mode = "off"$/m;

test("served page: the switch asks in its row; \"of\" saves nothing, \"off\" and Enter save off (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const s = await stack();
  try {
    const ready = (doc: any) => doc.getElementById("switch-protection").getAttribute("aria-checked") === "true" && !doc.getElementById("switch-protection").disabled;
    await servedProductPage(s.base, "/settings", ready, async (doc) => {
      const w = doc.defaultView;
      let prompted = 0;
      w.prompt = () => { prompted++; return "OFF"; };
      const sw = doc.getElementById("switch-protection");
      const before = s.config();
      // P1
      sw.focus();
      sw.click();
      const box = offBox(doc)!;
      assert.ok(box, "the box opens");
      assert.equal(box.box.querySelector("p").textContent, ASK);
      assert.equal(doc.activeElement, box.input);
      // P2
      typeInOffBox(doc, "of");
      assert.equal(box.turnOff.disabled, true, "\"of\" does not count");
      assert.equal(box.hint.hidden, false);
      assert.equal(box.hint.textContent, HINT);
      enterInOffBox(doc);
      await new Promise((r) => setTimeout(r, SETTLE_MS));
      assert.equal(s.config(), before, "config.toml is unchanged");
      box.input.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
      assert.equal(offBox(doc), null, "Escape closes the box");
      assert.equal(doc.activeElement, sw, "the focus is back on the switch");
      assert.equal(sw.getAttribute("aria-checked"), "true", "still on");
      // P3
      sw.click();
      typeInOffBox(doc, "off");
      enterInOffBox(doc);
      await waitWhile(() => doc.querySelector("#settings-protect-row .name").textContent !== "Off");
      assert.equal(doc.querySelector("#settings-protect-row .name").textContent, "Off");
      assert.match(s.config() ?? "", OFF_LINE, "config.toml says off");
      assert.equal(offBox(doc), null, "the answer closed the box");
      assert.equal(prompted, 0, "the browser prompt is never used");
      // P5
      oracle("the served page", doc.body.textContent);
    }, { headers: { Cookie: ADMIN_COOKIE } });
  } finally {
    await s.close();
  }
});

test("in a real Chromium at 390 px: \"of\" saves nothing, \"off\" and Enter save off; the box fits the row at 390 and 1280 px (secrets axes, explicit)", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const s = await stack();
  const { proc, wsUrl } = await tour.startBrowser(browser as string, join(s.tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  await withTeardown(async () => {
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
    const key = async (k: "Enter" | "Escape") => {
      const code = k === "Enter" ? 13 : 27;
      await send("Input.dispatchKeyEvent", { type: "keyDown", key: k, code: k, windowsVirtualKeyCode: code, ...(k === "Enter" ? { text: "\r" } : {}) });
      await send("Input.dispatchKeyEvent", { type: "keyUp", key: k, code: k, windowsVirtualKeyCode: code });
    };
    /** The switch, focused and pressed with Enter as a keyboard does. */
    const pressSwitch = async () => {
      await evaluate(`(() => { const b = document.getElementById("switch-protection"); b.scrollIntoView({ block: "center" }); b.focus(); return true; })()`);
      await key("Enter");
    };
    const BOX = `document.getElementById("settings-protect-confirm")`;
    const state = () => evaluate(`(() => {
      const box = ${BOX};
      const input = box.querySelector("input");
      const turnOff = [...box.querySelectorAll("button")].find((b) => b.textContent === "Turn off");
      const hint = box.querySelector(".confirm-hint");
      return { open: !box.hidden, focusedInput: !!input && document.activeElement === input,
        focusedSwitch: document.activeElement === document.getElementById("switch-protection"),
        turnOffOn: !!turnOff && !turnOff.disabled, hint: hint && !hint.hidden ? hint.textContent : null,
        name: document.querySelector("#settings-protect-row .name").textContent,
        checked: document.getElementById("switch-protection").getAttribute("aria-checked"), text: document.body.innerText };
    })()`);
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Network.enable");
    await send("Page.addScriptToEvaluateOnNewDocument", { source: `window.__prompted = 0; window.prompt = () => { window.__prompted++; return "OFF"; };` });
    const eq = ADMIN_COOKIE.indexOf("=");
    await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: s.base, httpOnly: true, sameSite: "Strict" });
    await send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
    await send("Page.navigate", { url: s.base + "/settings" });
    await until("/settings: the switch reads On", `(() => { const b = document.getElementById("switch-protection"); return !!b && !b.disabled && b.getAttribute("aria-checked") === "true"; })()`);
    const texts: string[] = [];
    const before = s.config();

    // P4: the box and its buttons fit the row, at a phone's width and wide.
    for (const width of [390, 1280]) {
      await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 500 });
      await pressSwitch();
      await until(`${width}px: the box opens`, `!${BOX}.hidden`);
      const g = await evaluate(`(() => {
        const r = (x) => { const b = x.getBoundingClientRect(); return { l: b.left, r: b.right, t: b.top, b: b.bottom }; };
        const box = ${BOX};
        const buttons = [...box.querySelectorAll("button")];
        return { row: r(document.getElementById("settings-protect-row")), box: r(box), input: r(box.querySelector("input")),
          buttons: buttons.map(r), labels: buttons.map((b) => b.textContent),
          font: parseFloat(getComputedStyle(box.querySelector("input")).fontSize),
          scroll: document.scrollingElement.scrollWidth, inner: window.innerWidth };
      })()`);
      const inside = (a: any, b: any) => a.l >= b.l - 0.5 && a.r <= b.r + 0.5;
      assert.deepEqual(g.labels, ["Turn off", "Cancel"], `${width}px`);
      assert.ok(inside(g.box, g.row), `${width}px: the box inside the row ${JSON.stringify(g)}`);
      for (const x of [g.input, ...g.buttons]) assert.ok(inside(x, g.box), `${width}px: the field and buttons inside the box ${JSON.stringify(g)}`);
      assert.ok(g.scroll <= g.inner, `${width}px: no sideways scroll ${JSON.stringify(g)}`);
      assert.ok(g.font >= 16, `${width}px: the box is at least 16 px, so iOS does not zoom ${JSON.stringify(g)}`);
      await key("Escape");
      await until(`${width}px: Escape closes the box`, `${BOX}.hidden`);
    }
    await send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });

    // P2: "of" does not count.
    await pressSwitch();
    await until("the box opens", `!${BOX}.hidden && document.activeElement === ${BOX}.querySelector("input")`);
    await send("Input.insertText", { text: "of" });
    await key("Enter");
    await new Promise((r) => setTimeout(r, SETTLE_MS));
    const wrong = await state();
    texts.push(wrong.text);
    assert.deepEqual({ open: wrong.open, turnOffOn: wrong.turnOffOn, hint: wrong.hint, checked: wrong.checked },
      { open: true, turnOffOn: false, hint: HINT, checked: "true" }, "\"of\": Turn off stays off, the hint says why");
    assert.equal(s.config(), before, "config.toml is unchanged");
    await key("Escape");
    await until("Escape closes the box", `${BOX}.hidden`);
    const closed = await state();
    assert.equal(closed.focusedSwitch, true, "the focus is back on the switch");
    assert.equal(closed.checked, "true", "still on");

    // P3: "off", lower case, and Enter.
    await pressSwitch();
    await until("the box opens again", `!${BOX}.hidden && document.activeElement === ${BOX}.querySelector("input")`);
    await send("Input.insertText", { text: "off" });
    await until("\"off\" counts", `!${BOX}.querySelector("button").disabled`);
    await key("Enter");
    await until("the row reads Off", `document.querySelector("#settings-protect-row .name").textContent === "Off"`);
    const done = await state();
    texts.push(done.text);
    assert.equal(done.open, false, "the answer closed the box");
    assert.equal(done.focusedSwitch, true, "the focus is on the switch");
    assert.equal(done.checked, "false");
    assert.match(s.config() ?? "", OFF_LINE, "config.toml says off");
    assert.equal(await evaluate("window.__prompted"), 0, "the browser prompt is never used");

    // P5: the oracle.
    for (const t of texts) oracle("a page", t);
  }, () => cdp.close(), () => tour.stopProc(proc), () => s.close());
});
