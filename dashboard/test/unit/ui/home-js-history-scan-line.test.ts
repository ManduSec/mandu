/**
 * home-js-history-scan-line — History's line on the sessions your agents ran
 * without Mandu (public/js/home.js renderHistoryScan; dashboard.md §4.25ai
 * *History's scan line*), in jsdom over the shared fetch stub
 * (home-js-fixtures.ts), from the server's own card (view-model/last-scan.ts
 * homeScanCard), as Home draws it:
 *
 *   - no scan kept: `mandu scan` with its Copy and a link to how it works,
 *     never "the last scan found";
 *   - a kept scan where one of your secrets left: the card's headline as the
 *     link to the Scan page (under the base path), its `when`, the ✗;
 *   - a kept scan where none left: the "None of your secrets …" headline, no ✗;
 *   - an answer without `scan` (an older server), or a Home read that
 *     failed: the neutral line, a plain link to the Scan page;
 *   - a poll with the same card leaves the line as it is (the same node);
 *     a changed card draws it again;
 *   - server words are text, never markup; no 8-character run of a planted
 *     value is on the page.
 * Axes: none (display only). Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { home, load, tick } from "./home-js-fixtures.js";
import { homeScanCard, type LastScanWire } from "../../../src/view-model/last-scan.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

// Assembled at run time: this file holds no credential-shaped literal.
const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8HistLine`;

function record(left: boolean): LastScanWire {
  return {
    version: 1, ranAt: "2026-10-21T09:00:00.000Z", sessions: { "claude-code": 3 }, duringMandu: 0, known: 2,
    findings: left ? [{
      kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, sessions: 2, agents: ["claude-code"],
      first: "2026-10-01T10:00:00.000Z", last: "2026-10-19T10:00:00.000Z", how: { "command-output": 2 }, projects: ["~/shop"], duringMandu: 0,
      examples: [{ at: "2026-10-19T10:00:00.000Z", agent: "claude-code", how: "command-output", command: `echo ${STRIPE}`, project: "~/shop", mandu: "without" }],
    }] : [],
    dropped: 0, capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 },
    sends: [], sendsDropped: 0, suggestions: null,
  } as LastScanWire;
}

/** History at /mandu/history over `homeVm`, with a clipboard. */
function open(homeVm: unknown, routes: Record<string, unknown> = {}) {
  const page = load({ url: "http://127.0.0.1:4500/mandu/history", homeVm, routes, before: (w: Doc) => {
    Object.defineProperty(w.navigator, "clipboard", { configurable: true, value: { writeText: () => w.Promise.resolve() } });
  } });
  assert.equal(page.err, null);
  return page;
}
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}
const line = (doc: Doc) => doc.getElementById("history-scan");
const flat = (s: string) => s.replace(/\s+/g, " ").trim();
function noValue(doc: Doc): void {
  const text = doc.body.textContent as string;
  for (let i = 0; i + 8 <= STRIPE.length; i++) {
    const piece = STRIPE.slice(i, i + 8);
    if (piece !== "sk_live_") assert.ok(!text.includes(piece), `the page shows "${piece}"`);
  }
}

test("the page's own first state is the neutral line, not a claim of what a scan found", () => {
  const { doc } = open({ ...home(), scan: homeScanCard(null) });
  // Before the first read answers (the script has run, the fetch has not).
  assert.equal(flat(line(doc).textContent), "Sessions your agents ran without Mandu: the Scan page.");
  assert.doesNotMatch(line(doc).textContent, /last scan found/);
});

test("no scan kept: the line says `mandu scan` reads them, with its Copy, and links how it works", async () => {
  const { doc } = open({ ...home(), scan: homeScanCard(null) });
  await tick(40);
  const p = line(doc);
  assert.equal(flat(p.textContent.replace("Copy", "")), "Sessions your agents ran without Mandu are not listed here. mandu scan reads them and shows which of your secrets already went to the AI. How it works.");
  assert.doesNotMatch(p.textContent, /last scan found/);
  const run = p.querySelector(".run-code");
  assert.ok(run, "the command as a run-code");
  assert.equal(run.querySelector(":scope > code").textContent, "mandu scan");
  assert.equal(run.querySelector(":scope > button.run-copy").getAttribute("aria-label"), "Copy mandu scan");
  const a = p.querySelector('a[data-page-link="scan"]');
  assert.equal(a.textContent, "How it works");
  assert.equal(a.getAttribute("href"), "/mandu/scan");
  assert.equal(p.querySelector(".tone-mark"), null);
  assert.equal(p.dataset.tone, "");
});

test("a kept scan where one of your secrets left: the card's headline links the Scan page under the base path, its when, the ✗", async () => {
  const card = homeScanCard(record(true));
  const { doc } = open({ ...home(), scan: card });
  await tick(40);
  const p = line(doc);
  assert.equal(flat(p.textContent), `Sessions your agents ran without Mandu: ${card.headline}. ${card.when}.`);
  assert.equal(card.headline, "1 of your secrets left this computer in your agents' requests");
  assert.equal(card.when, "Scanned 21 Oct · 3 past sessions");
  const a = p.querySelector('a[data-page-link="scan"]');
  assert.equal(flat(a.textContent), card.headline);
  assert.equal(a.getAttribute("href"), "/mandu/scan");
  assert.ok(a.querySelector(".tone-mark svg"), "the ✗ beside the headline");
  assert.equal(p.dataset.tone, "bad");
  assert.equal(p.querySelector("code"), null, "no command once a scan ran");
  noValue(doc);
});

test("a kept scan where none left: the 'None of your secrets …' headline, no ✗", async () => {
  const card = homeScanCard(record(false));
  const { doc } = open({ ...home(), scan: card });
  await tick(40);
  const p = line(doc);
  assert.match(card.headline, /^None of your secrets left this computer/);
  assert.equal(flat(p.querySelector('a[data-page-link="scan"]').textContent), card.headline);
  assert.equal(flat(p.textContent), `Sessions your agents ran without Mandu: ${card.headline}. ${card.when}.`);
  assert.equal(p.querySelector(".tone-mark"), null);
  assert.equal(p.dataset.tone, "ok");
});

test("an answer without `scan` (an older server): the neutral line, a plain link to the Scan page", async () => {
  const { doc } = open(home());
  await tick(40);
  const p = line(doc);
  assert.equal(flat(p.textContent), "Sessions your agents ran without Mandu: the Scan page.");
  assert.equal(p.querySelector("a").getAttribute("href"), "/mandu/scan");
  assert.equal(p.querySelector("code"), null);
});

test("a Home read that fails: the neutral line again, not the last answer's claim", async () => {
  let failing = false;
  const { doc } = open({ ...home(), scan: homeScanCard(record(true)) }, {
    "GET home": () => (failing ? { status: 500, body: { error: "boom" } } : { status: 200, body: { ...home(), scan: homeScanCard(record(true)) } }),
  });
  await tick(40);
  assert.match(line(doc).textContent, /1 of your secrets left/);
  failing = true;
  await poll(doc);
  assert.equal(flat(line(doc).textContent), "Sessions your agents ran without Mandu: the Scan page.");
});

test("a poll with the same card leaves the line as it is; a changed card draws it again", async () => {
  let vm: unknown = { ...home(), scan: homeScanCard(null) };
  const { doc } = open(vm, { "GET home": () => vm });
  await tick(40);
  const code = line(doc).querySelector("code");
  assert.ok(code);
  await poll(doc);
  assert.equal(line(doc).querySelector("code"), code, "the same node: not drawn again");
  // A scan kept meanwhile: the next poll draws its headline.
  vm = { ...home(), scan: homeScanCard(record(true)) };
  await poll(doc);
  assert.equal(line(doc).querySelector("code"), null);
  assert.match(line(doc).textContent, /1 of your secrets left this computer/);
  const a = line(doc).querySelector("a");
  await poll(doc);
  assert.equal(line(doc).querySelector("a"), a, "the same card: the same link node");
});

test("the card's words are text, never markup", async () => {
  const card = { ...homeScanCard(record(true)), headline: "<img src=x onerror=alert(1)> left", when: "<b>Scanned</b>" };
  const { doc } = open({ ...home(), scan: card });
  await tick(40);
  const p = line(doc);
  assert.equal(p.querySelector("img"), null);
  assert.equal(p.querySelector("b"), null);
  assert.match(p.textContent, /<img src=x onerror=alert\(1\)> left\. <b>Scanned<\/b>\./);
});
