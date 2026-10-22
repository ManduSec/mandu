/**
 * product-code-copy e2e — a fenced block in the agent's reply has a Copy
 * button on the product's session page (dashboard.md §4.25b *A code block
 * has a Copy button*), across the REAL components: a real ArbiterServer in
 * `secrets` whose event store holds the recorded first-session tour
 * (dashboard/test/fixtures/tour-1791164083-1418381.ndjson, fake secrets, its
 * times moved so it ended a minute ago), and the real dashboard reading it
 * over a real ArbiterEventSource.
 *
 * Until 2026-10-22 the page had no copy control, and in a headless Chromium
 * at 390 px the tour's "Run it again" reply showed only
 * "`! curl -v https://api.stripe.com/v`" of its command: 570 of its 856 px
 * were out of the box.
 *
 *   C1  the session page's read carries the reply's fenced command whole
 *       and the `.env` block with STRIPE_KEY as a chip, never the key;
 *   C2  a real headless Chromium at 390 px, the clipboard granted
 *       (`Browser.grantPermissions`): the command's box is cut; its Copy
 *       sits beside the box, above its first line, and stays put when the
 *       box scrolls; pressed, it reads "Copied", keeps the focus, and
 *       `navigator.clipboard.readText()` is the whole command;
 *   C3  the oracle: the `.env` block (a chip) has no button, no Copy is
 *       drawn in Your secrets or beside a revealed box, every Copy on the
 *       page pressed in turn never puts the key on the clipboard, and the
 *       page never shows it.
 *
 * The Chromium half self-SKIPs without a Chromium (probeBrowser:
 * MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell).
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm test  (tests/)
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { stateAxes } from "../lib/axes.js";

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

const ID = "1791164083-1418381";
const FIXTURE = join(REPO, "dashboard", "test", "fixtures", `tour-${ID}.ndjson`);
/** The fixture's fake key, as its .env holds it. */
const KEY = "FAKE-STRIPE-KEY";
/** The command the agent asks the person to run in its "Run it again" reply. */
const CMD = `! curl -v https://api.stripe.com/v1/customers -G -d limit=1 -u "$(grep STRIPE_KEY .env | cut -d\\' -f2):"`;

const dirs: string[] = [];
const closers: Array<() => Promise<void>> = [];
after(async () => {
  for (const c of closers.reverse()) await c();
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

let stack: { base: string; page: AgentPageVM } | null = null;
/** The recorded tour in a real arbiter's store, read by the real dashboard. */
async function start() {
  if (stack) return stack;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-code-copy-"));
  dirs.push(tmp);
  const eventDir = join(tmp, "events");
  mkdirSync(eventDir, { recursive: true });
  const events = readFileSync(FIXTURE, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { ts: string });
  const shift = Date.now() - 60_000 - Date.parse(events.at(-1)!.ts);
  writeFileSync(join(eventDir, `${ID}.ndjson`), events.map((e) => JSON.stringify({ ...e, ts: new Date(Date.parse(e.ts) + shift).toISOString() })).join("\n") + "\n");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
  const sock = join(tmp, "arbiter.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir, policyPath, policyPollMs: 0, log: () => {},
    confidentiality: true, integrity: false,
  });
  await arbiter.listen();
  const home = join(tmp, "home");
  mkdirSync(home);
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock }), configEnv: { MANDU_HOME: home }, fileBrowserHome: "/home/user", log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  closers.push(async () => { await dashboard.close(); await arbiter.close(); });
  // The event source connects to the arbiter on its own: 503 until then.
  let page: AgentPageVM | undefined;
  for (let i = 0; i < 100 && !page?.found; i++) {
    const r = await fetch(`${base}/api/home/agent?session=${ID}`);
    if (r.status === 200) page = (await r.json()) as AgentPageVM;
    else await new Promise((res) => setTimeout(res, 50));
  }
  assert.ok(page?.found, "the recorded session is on the page");
  stack = { base, page: page! };
  return stack;
}

const words = (parts: { kind: string; text: string; name?: string }[]) => parts.map((p) => (p.kind === "masked" ? `[${p.name ?? p.text}]` : p.text)).join("");

test("the session page's read carries the reply's fenced command whole and the .env block with the key as a chip, never the key (secrets axes, explicit)", { timeout: 60_000 }, async () => {
  const { base, page } = await start();
  const replies = page.story.filter((t) => t.reply).map((t) => words(t.reply!.parts));
  assert.ok(replies.some((r) => r.includes("```\n" + CMD + "\n```")), "a reply holds the command in a fenced block");
  assert.ok(replies.some((r) => /```\nSTRIPE_KEY='\[[^\]]+\]'\nDEBUG=1\n```/.test(r)), "the .env block holds the key as a chip");
  for (const url of [`/api/home/agent?session=${ID}`, "/api/home", `/agents/${ID}`]) {
    const body = await (await fetch(base + url)).text();
    assert.ok(!body.includes(KEY), `CONFIDENTIALITY VIOLATION: ${url} carries the key`);
  }
});

test("in a real Chromium at 390 px: the cut-off command's Copy puts the whole command on the clipboard; a masked block, Your secrets and a revealed box have none, and the key never reaches the clipboard", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const { base } = await start();
  const tmp = mkdtempSync(join(tmpdir(), "mandu-code-copy-cdp-"));
  dirs.push(tmp);
  const { proc, wsUrl } = await tour.startBrowser(chromium as string, join(tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  try {
    await cdp.send("Browser.grantPermissions", { origin: base, permissions: ["clipboardReadWrite", "clipboardSanitizedWrite"] });
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const send = (method: string, params: object = {}) => cdp.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true, userGesture: true });
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
    // The clipboard answers only a focused page.
    await send("Emulation.setFocusEmulationEnabled", { enabled: true });
    await send("Emulation.setDeviceMetricsOverride", { width: 390, height: 900, deviceScaleFactor: 1, mobile: true });
    await send("Page.navigate", { url: `${base}/agents/${ID}` });
    const cmdBlock = `[...document.querySelectorAll("#agent-story pre.code-block")].find((p) => p.textContent.includes("limit=1 -u"))`;
    await until("the command's block is drawn", `!!${cmdBlock} && document.fonts.status === "loaded"`);
    await evaluate(`${cmdBlock}.scrollIntoView({ block: "center" }), true`);

    // ── C2: the box is cut; its Copy sits beside it, above its text ───────
    const place = () => evaluate(`(() => {
      const pre = ${cmdBlock};
      const btn = pre.parentElement.querySelector("button.code-copy");
      const b = btn && btn.getBoundingClientRect();
      const p = pre.getBoundingClientRect();
      return {
        wrapped: pre.parentElement.classList.contains("code-wrap"), inPre: !!pre.querySelector("button"),
        role: pre.getAttribute("role"), name: pre.getAttribute("aria-label"),
        hidden: pre.scrollWidth - pre.clientWidth, text: pre.textContent,
        btn: b && { left: b.left, top: b.top, right: b.right, bottom: b.bottom }, label: btn && btn.textContent,
        firstLine: p.top + parseFloat(getComputedStyle(pre).borderTopWidth) + parseFloat(getComputedStyle(pre).paddingTop),
        page: document.documentElement.scrollWidth, view: document.documentElement.clientWidth,
      };
    })()`);
    const before = await place();
    assert.equal(before.text, CMD, "the block holds the whole command");
    assert.ok(before.hidden > 100, `the box is cut at 390 px (${before.hidden} px out of it)`);
    assert.ok(before.wrapped && !before.inPre, "the button is beside the box, not in it");
    assert.equal(before.role, "group");
    assert.equal(before.name, "Code");
    assert.equal(before.label, "Copy");
    assert.ok(before.btn.bottom <= before.firstLine, `the button is above the first line (${before.btn.bottom} > ${before.firstLine})`);
    assert.ok(before.page <= before.view, `no sideways scroll on the page (${before.page} > ${before.view})`);
    await evaluate(`(${cmdBlock}.scrollLeft = 10000), true`);
    const scrolled = await place();
    assert.deepEqual(scrolled.btn, before.btn, "the button stays put when the box scrolls");

    await evaluate(`(() => { const b = ${cmdBlock}.parentElement.querySelector("button.code-copy"); b.focus(); b.click(); return true; })()`);
    await until("the button reads Copied", `${cmdBlock}.parentElement.querySelector("button.code-copy").textContent === "Copied"`);
    assert.equal(await evaluate(`document.activeElement === ${cmdBlock}.parentElement.querySelector("button.code-copy")`), true, "the focus stays on the button");
    assert.equal(await evaluate(`${cmdBlock}.parentElement.querySelector(".code-copy-said").textContent`), "Copied", "its status says so");
    assert.equal(await evaluate("navigator.clipboard.readText()"), CMD, "the clipboard holds the whole command, the part out of the box too");

    // ── C3: the oracle ────────────────────────────────────────────────────
    const o = await evaluate(`(() => {
      const blocks = [...document.querySelectorAll("#agent-story pre.code-block")];
      const masked = blocks.filter((p) => p.querySelector(".mask-chip"));
      return {
        masked: masked.length, maskedEnv: masked.some((p) => /^STRIPE_KEY='/.test(p.textContent)),
        maskedButtons: masked.filter((p) => p.parentElement.querySelector("button.code-copy")).length,
        secrets: document.querySelectorAll("#agent-secrets button.code-copy").length,
        besideHidden: [...document.querySelectorAll("pre.hidden-text")].filter((p) => p.parentElement.querySelector("button.code-copy")).length,
        notBlock: [...document.querySelectorAll("button.code-copy")].filter((b) => !b.parentElement.querySelector(":scope > pre.code-block")).length,
        buttons: document.querySelectorAll("button.code-copy").length,
      };
    })()`);
    assert.ok(o.masked > 0 && o.maskedEnv, "the .env block with its chip is drawn");
    assert.equal(o.maskedButtons, 0, "a block holding a chip has no Copy");
    assert.equal(o.secrets, 0, "no Copy in Your secrets");
    assert.equal(o.besideHidden, 0, "no Copy beside a revealed box");
    assert.equal(o.notBlock, 0, "every Copy is a code block's");
    for (let i = 0; i < o.buttons; i++) {
      await evaluate(`document.querySelectorAll("button.code-copy")[${i}].click(), true`);
      await new Promise((r) => setTimeout(r, 100));
      const held = (await evaluate("navigator.clipboard.readText()")) as string;
      assert.ok(!held.includes(KEY), `CONFIDENTIALITY VIOLATION: Copy ${i} put the key on the clipboard`);
    }
    assert.ok(!(await evaluate("document.body.innerText")).includes(KEY), "CONFIDENTIALITY VIOLATION: the page shows the key");
  } finally {
    cdp.close();
    await tour.stopProc(proc);
  }
});
