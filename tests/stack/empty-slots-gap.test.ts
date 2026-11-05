/**
 * empty-slots-gap e2e — an empty slot takes no room: Home's scan card with
 * no secret to list, and a phone's session step with no tag (dashboard.md
 * §4.25ai *Home's card*, §4.25b *On a phone*, 2026-10-29). Mandu-new.
 *
 * Until 2026-10-29 two empty elements still took their place: Home's list
 * of top secrets (`#home-scan-top`, a flex `<ul>` with an 8 px top margin)
 * stayed laid out when empty, before any scan and after one where nothing
 * left, so "Run it in a terminal" sat 14 px under the sentence where every
 * other line of the card has 6; and on a phone (≤ 760 px) a reply or an
 * untagged step's empty tag slot wrapped onto a second grid row of its own,
 * so its words had 12 px above and 24 below. A REAL ArbiterServer in
 * `secrets` holds the recorded first-session tour
 * (dashboard/test/fixtures/tour-1791164083-1418381.ndjson, fake secrets);
 * a REAL DashboardServer over a real ArbiterEventSource, its MANDU_HOME
 * holding the kept scan or none, serves the product page to a REAL headless
 * Chromium (Playwright's headless shell; none found: the test skips),
 * signed in with the one-time admin link:
 *
 *   G1  Home, no scan kept: the empty list is not drawn, and "Run it in a
 *       terminal" is one line's margin under the sentence;
 *   G2  a kept scan where nothing left: the same, under "Run it again";
 *   G3  a kept scan where a secret left: the list is drawn, its margin
 *       under the sentence as before;
 *   G4  the tour's session page at 390 px: every reply and untagged step has
 *       as much room under its words as above them (within 2 px), every
 *       tagged step keeps its tag drawn on a row under its words; at
 *       1280 px the tag slot stays in its third column;
 *   G5  the oracle: no 8-character run of a planted value (in a field the
 *       scan record never has) nor the tour's fake key is on any page read.
 *
 * Axes: secrets (stated). No kernel layer.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ChildProcess } from "node:child_process";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { chromiumBinary, READY, startChromium, stopChromium } from "../lib/chromium.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const BIN = chromiumBinary();
const ID = "1791164083-1418381";
const FIXTURE = join(REPO, "dashboard", "test", "fixtures", `tour-${ID}.ndjson`);
/** The tour's fake key, as its .env holds it. */
const KEY = "FAKE-STRIPE-KEY";
// Assembled at run time: this file holds no credential-shaped literal.
const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8NbSlot`;
const NONE_HEADLINE = "Did your agents already send a secret to the AI?";

/** A kept `mandu scan`: `left` findings sent in sessions without Mandu. */
function record(left: boolean): unknown {
  return {
    version: 1, ranAt: "2026-10-26T09:00:00.000Z", sessions: { "claude-code": 5 }, duringMandu: left ? 0 : 1, known: 1,
    secret: STRIPE, // not a field of the record: dropped when read
    findings: [{
      kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, sessions: left ? 2 : 1, agents: ["claude-code"],
      last: "2026-10-19T10:00:00.000Z", how: { "command-output": 2 }, projects: ["~/shop"], duringMandu: left ? 0 : 1, sessionsUnderMandu: left ? 0 : 1, raw: STRIPE,
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

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

/** Home's scan card as drawn: each line's box, and the list's. */
const CARD = `JSON.stringify((() => {
  const box = (id) => { const e = document.getElementById(id); const r = e.getBoundingClientRect(); const s = getComputedStyle(e); return { top: r.top, bottom: r.bottom, shown: s.display !== "none" && !e.hidden, margin: parseFloat(s.marginTop), items: e.children.length }; };
  const lines = [...document.getElementById("home-scan-body").children].filter((e) => getComputedStyle(e).display !== "none" && !e.hidden).map((e) => e.id);
  const after = lines[lines.indexOf("home-scan-sentence") + 1];
  return { headline: document.getElementById("home-scan-headline").textContent, sentence: box("home-scan-sentence"), top: box("home-scan-top"), again: box("home-scan-again"),
    next: after ? { id: after, ...box(after) } : null, prev: lines.indexOf("home-scan-top") > 0 ? box(lines[lines.indexOf("home-scan-top") - 1]) : null, lines, text: document.body.innerText };
})())`;

/** Every story step's words against its box, and where its tag slot sits. */
const STEPS = `JSON.stringify([...document.querySelectorAll("#agent-story .step.wide, #agent-story .half-body")].filter((s) => s.offsetParent !== null).map((s) => {
  const r = s.getBoundingClientRect(); const cs = getComputedStyle(s);
  const what = s.querySelector(":scope > .what").getBoundingClientRect();
  const last = s.lastElementChild; const lr = last.getBoundingClientRect();
  return { cls: s.className, above: what.top - r.top - parseFloat(cs.paddingTop), below: r.bottom - parseFloat(cs.paddingBottom) - what.bottom,
    tag: last.classList.contains("tag") ? { shown: getComputedStyle(last).display !== "none" && lr.height > 0, under: lr.top >= what.bottom - 1, left: lr.left - what.left } : null,
    slot: last.classList.contains("tag") ? null : getComputedStyle(last).display,
    icons: [...s.querySelectorAll(":scope > .ic")].map((i) => getComputedStyle(i).display) };
}))`;

test("an empty slot takes no room: Home's scan card with no secret to list, and a phone's untagged session steps (secrets axes, explicit)", { skip: BIN === null ? "no headless Chromium (Playwright's headless shell) on this host" : false, timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-empty-slots-"));
  dirs.push(tmp);
  // The recorded tour, its times moved so it ended a minute ago.
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
  const mh = join(tmp, "mh");
  mkdirSync(join(mh, "state"), { recursive: true }); // no last-scan.json: no scan kept
  mkdirSync(home, { recursive: true });
  const scanFile = join(mh, "state", "last-scan.json");
  const keep = (rec: unknown) => {
    writeFileSync(`${scanFile}.tmp`, JSON.stringify(rec), { mode: 0o600 });
    renameSync(`${scanFile}.tmp`, scanFile);
  };
  const dash = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock }), fileBrowserHome: home, configEnv: { HOME: home, MANDU_HOME: mh }, log: () => {}, ...ADMIN_OPTS });
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
      for (let i = 0; i < 300; i++) {
        if (await evaluate(expression) === true) return;
        await new Promise((r) => setTimeout(r, 100));
      }
      assert.fail(`the page never showed ${what} (headline: ${String(await evaluate(`document.getElementById("home-scan-headline")?.textContent`))})`);
    };
    const texts: string[] = [];
    await until(`${READY} && location.pathname === "/"`, "Home after the sign-in link");

    // ── G1–G3: Home's scan card, at a desktop's width and a phone's ──
    const card = async (headline: string) => {
      await until(`document.getElementById("home-scan-headline").textContent.endsWith(${JSON.stringify(headline)})`, `the scan card saying "${headline}"`);
      const c = JSON.parse(String(await evaluate(CARD)));
      texts.push(c.text);
      return c;
    };
    const poll = () => evaluate(`document.dispatchEvent(new Event("visibilitychange")), true`);
    for (const width of [1280, 390]) {
      await p.send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 760 });
      rmSync(scanFile, { force: true });
      await poll();
      const none = await card(NONE_HEADLINE);
      assert.equal(none.top.items, 0);
      assert.equal(none.top.shown, false, `${width} px, no scan: the empty list is not drawn`);
      assert.deepEqual(none.lines, ["home-scan-sentence", "home-scan-again"]);
      assert.match(String(await evaluate(`document.getElementById("home-scan-again").textContent`)), /^Run it in a terminal: mandu scan/);
      const gap0 = none.again.top - none.sentence.bottom;
      assert.ok(Math.abs(gap0 - none.again.margin) <= 1, `${width} px, no scan: "Run it in a terminal" is its own margin (${none.again.margin} px) under the sentence, not ${gap0} px`);

      keep(record(false));
      await poll();
      const clean = await card("None of your secrets left this computer in your agents' requests");
      assert.equal(clean.top.items, 0);
      assert.equal(clean.top.shown, false, `${width} px, nothing left: the empty list is not drawn`);
      const again = String(await evaluate(`document.getElementById("home-scan-again").textContent`));
      assert.match(again, /^Run it again: mandu scan/);
      // The line under the sentence (the green "safe" line, when the
      // server sends one) is its own margin under it, no more.
      assert.ok(clean.next !== null && clean.next.id !== "home-scan-top", `a line under the sentence (${clean.lines.join(", ")})`);
      const gap1 = clean.next.top - clean.sentence.bottom;
      assert.ok(Math.abs(gap1 - clean.next.margin) <= 1, `${width} px, nothing left: #${clean.next.id} is its own margin (${clean.next.margin} px) under the sentence, not ${gap1} px`);
      assert.ok(clean.again.top > clean.next.top);

      keep(record(true));
      await poll();
      const leaked = await card("1 of your secrets left this computer in your agents' requests");
      assert.ok(leaked.top.items > 0, "the secret that left is listed");
      assert.equal(leaked.top.shown, true, `${width} px, a secret left: the list is drawn`);
      const gap2 = leaked.top.top - leaked.prev.bottom;
      assert.ok(Math.abs(gap2 - leaked.top.margin) <= 1, `${width} px: the list is its own margin (${leaked.top.margin} px) under the line above it, as before (${gap2} px)`);
      assert.ok(leaked.top.bottom < leaked.again.top);
    }

    // ── G4: the tour's session page ──
    const steps = async (width: number) => {
      await p.send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 760 });
      await p.send("Page.navigate", { url: `${base}/agents/${ID}` });
      await until(`${READY} && location.pathname === "/agents/${ID}" && document.querySelectorAll("#agent-story .step.wide").length > 3 && document.fonts.status === "loaded"`, `the tour's session page at ${width} px`);
      texts.push(String(await evaluate("document.body.innerText")));
      return JSON.parse(String(await evaluate(STEPS))) as Array<{ cls: string; above: number; below: number; tag: { shown: boolean; under: boolean; left: number } | null; slot: string | null; icons: string[] }>;
    };
    const phone = await steps(390);
    const untagged = phone.filter((s) => s.tag === null);
    const tagged = phone.filter((s) => s.tag !== null);
    assert.ok(untagged.length >= 3, `the tour has replies and untagged steps (${untagged.length})`);
    assert.ok(untagged.some((s) => /\breply\b/.test(s.cls)), "a reply among them");
    assert.ok(tagged.length >= 1, `and a tagged step (${tagged.length})`);
    for (const s of untagged) {
      assert.equal(s.slot, "none", `390 px, ${s.cls}: the empty tag slot is not drawn`);
      assert.ok(Math.abs(s.below - s.above) <= 2, `390 px, ${s.cls}: as much room under its words as above them (${s.above} above, ${s.below} below)`);
    }
    for (const s of tagged) {
      assert.equal(s.tag!.shown, true, `390 px, ${s.cls}: its tag is drawn`);
      assert.equal(s.tag!.under, true, `390 px, ${s.cls}: on a row under its words`);
      assert.ok(Math.abs(s.tag!.left) <= 1, `390 px, ${s.cls}: in the words' column`);
    }
    for (const s of phone) assert.ok(s.icons.length > 0 && s.icons.every((d) => d !== "none"), `390 px, ${s.cls}: its icon is drawn`);
    const wide = await steps(1280);
    for (const s of wide) {
      if (s.tag === null) assert.notEqual(s.slot, "none", `1280 px, ${s.cls}: the slot keeps its column`);
      else assert.ok(s.tag.left > 0 && !s.tag.under, `1280 px, ${s.cls}: the tag beside the words, as before`);
    }

    // ── G5: the oracle ──
    for (const text of texts) {
      assert.ok(!text.includes(KEY), "CONFIDENTIALITY VIOLATION: a page shows the tour's key");
      for (let i = 0; i + 8 <= STRIPE.length; i++) {
        const piece = STRIPE.slice(i, i + 8);
        if (piece !== "sk_live_") assert.ok(!text.includes(piece), `a page holds "${piece}" of the planted value`);
      }
    }
  } finally {
    page?.close();
    await stopChromium(chrome, profile);
    await dash.close();
    await arbiter.close();
  }
});
