/**
 * home-js-protection-not-running — Settings › Protection says once that
 * Mandu is not running, with its start commands as code with Copy
 * (dashboard.md §4.25 *Protection is off when nothing runs*, *Said once*;
 * queue item #234).
 *
 * Until 2026-11-02 the row said it twice, in two voices, where Mandu never
 * ran (a person who ran `mandu scan` and then `mandu dashboard`):
 *
 *   Saved as on. Mandu is not running now, so no agent is protected. It
 *   starts with your first agent: mandu claude (or mandu codex).
 *   Stopped. It starts again by itself when you next start an agent with
 *   mandu. [Start]
 *
 * the commands in plain words, which Home draws as code with Copy. Now:
 *
 *   P1  the Protection sentence holds the commands as <code>, each with its
 *       Copy (which writes exactly the command), joined " or ";
 *   P2  the service line under it is "Stopped." and Start, with no sentence;
 *   P3  a stopped service while Mandu runs (`notRunning` unset) keeps its
 *       sentence;
 *   P4  a crashed or adopted service keeps its words while Mandu is not
 *       running;
 *   P5  a poll that ends `notRunning` brings the sentence back, and the
 *       Protection sentence says what runs; one that starts it drops it.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub (home-js-fixtures.ts). Axes: none (display only).
 * Mandu-new.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";
import { ADOPTED_PARTS, ADOPTED_SENTENCE } from "../../../src/view-model/service-summary.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const URL = "http://127.0.0.1:4500/mandu/settings";
const AGAIN = "It starts again by itself when you next start an agent with mandu.";
const summary = (over: Record<string, unknown> = {}) => ({ summary: {
  available: true, state: "stopped", name: "Stopped", since: null, sentence: AGAIN,
  action: { label: "Start", path: "control/arbiter/start", confirm: null }, helperNote: null,
  ...over,
} });
const CRASHED = { state: "crashed", name: "Stopped unexpectedly", sentence: "Press Start, or start an agent with mandu." };
const ADOPTED = { state: "running", name: "Running", sentence: ADOPTED_SENTENCE, sentenceParts: ADOPTED_PARTS, since: null, action: null };
/** What `/api/home` answers where Mandu is not running at all. */
const offHome = (over: Record<string, unknown> = {}) => home({
  verdict: "off", headline: "Protection is off: no agent runs with Mandu.", sentence: "",
  protection: { level: "unknown", configured: "secrets", connected: false, notRunning: true },
  waitingKnown: false, waiting: [], answered: [], agents: [], history: { total: 0 },
  ...over,
});
/** Mandu runs, protection on, no agent: Home's answer with an arbiter. */
const onHome = () => home({ protection: { level: "secrets", configured: "secrets", connected: true } });
const AXES_ON = { ok: true, effective: { integrity: false, confidentiality: true }, effectiveMode: "secrets" };

/** Settings with a clipboard (so each command gets its Copy), its home
 *  answer and service summary each a function of the test's state. */
function open(homeVm: unknown, sum: unknown) {
  const wrote: string[] = [];
  const page = load({ url: URL, homeVm, routes: { "GET control/summary": sum, "GET config/axes": AXES_ON }, before: (w: Doc) => {
    Object.defineProperty(w.navigator, "clipboard", { configurable: true, value: { writeText: (t: string) => (wrote.push(t), w.Promise.resolve()) } });
  } });
  assert.equal(page.err, null);
  return { ...page, wrote };
}
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(60);
}
const sentence = (doc: Doc) => doc.getElementById("settings-protect-text");
const line = (doc: Doc) => doc.getElementById("settings-service-main");
/** The text with each Copy (and its status) left out: what is read. */
function words(node: Doc): string {
  const c = node.cloneNode(true);
  for (const b of c.querySelectorAll("button.code-copy, .code-copy-said")) b.remove();
  return c.textContent;
}
const codes = (node: Doc): string[] => [...node.querySelectorAll("code")].map((c: Doc) => c.textContent);

test("P1, P2: where Mandu is not running, the Protection sentence holds the commands as code with Copy, and the service line says only Stopped, with Start", async () => {
  const { doc, wrote } = open(offHome({ start: ["mandu claude", "mandu codex"] }), summary());
  await tick(60);
  assert.equal(words(sentence(doc)), "Saved as on. Mandu is not running now, so no agent is protected. It starts with your first agent: mandu claude or mandu codex.");
  assert.deepEqual(codes(sentence(doc)), ["mandu claude", "mandu codex"], "P1: the commands as code");
  const copies = [...sentence(doc).querySelectorAll(".run-code > button.code-copy")] as Doc[];
  assert.deepEqual(copies.map((b) => b.getAttribute("aria-label")), ["Copy mandu claude", "Copy mandu codex"], "P1: each with its Copy");
  copies[1].click();
  await tick();
  assert.deepEqual(wrote, ["mandu codex"], "P1: Copy writes exactly the command");

  assert.equal(line(doc).textContent, "Stopped. Start", "P2: Stopped and Start, no sentence");
  assert.doesNotMatch(doc.getElementById("settings-protection-block").textContent, /It starts again by itself/);
  const btn = line(doc).querySelector("button");
  assert.equal(btn.textContent, "Start", "P2: Start stays the way to run Mandu with no agent");
  assert.ok(btn.classList.contains("service-btn"));
  assert.equal(line(doc).lastElementChild, btn, "P2: in its place, at the end of the line");
});

test("P1: one command (the agents the scan found) is one code with its Copy", async () => {
  const { doc } = open(offHome({ start: ["mandu goose"] }), summary());
  await tick(60);
  assert.equal(words(sentence(doc)), "Saved as on. Mandu is not running now, so no agent is protected. It starts with your first agent: mandu goose.");
  assert.deepEqual(codes(sentence(doc)), ["mandu goose"]);
  assert.equal(sentence(doc).querySelectorAll("button.code-copy").length, 1);
});

test("P3: a stopped service while Mandu runs keeps its sentence, and the Protection sentence has no command", async () => {
  const { doc } = open(onHome(), summary());
  await tick(60);
  assert.equal(line(doc).textContent, `Stopped. ${AGAIN} Start`);
  assert.deepEqual(codes(sentence(doc)), []);
});

test("P4: a crashed or adopted service keeps its words while Mandu is not running", async () => {
  const crashed = open(offHome(), summary(CRASHED));
  await tick(60);
  assert.equal(line(crashed.doc).textContent, "Stopped unexpectedly. Press Start, or start an agent with mandu. Start");
  const adopted = open(offHome(), summary(ADOPTED));
  await tick(60);
  assert.equal(words(line(adopted.doc)), `Running. ${ADOPTED_SENTENCE}`);
  assert.deepEqual(codes(line(adopted.doc)), ["mandu stop"]);
});

test("P5: a poll that ends notRunning brings the service sentence back; one that begins it drops it, the line follows with no new summary", async () => {
  const page = open(offHome(), summary());
  const { doc } = page;
  await tick(60);
  assert.equal(line(doc).textContent, "Stopped. Start");
  // The summary stays the same throughout, so the service poll
  // (followServices) draws nothing: the Home poll's follow draws the line.

  page.setHome(onHome());
  await poll(doc);
  assert.equal(line(doc).textContent, `Stopped. ${AGAIN} Start`, "Mandu runs: the sentence is back");
  assert.doesNotMatch(sentence(doc).textContent, /not running/, "the Protection sentence says what runs");
  assert.deepEqual(codes(sentence(doc)), []);

  page.setHome(offHome());
  await poll(doc);
  assert.equal(line(doc).textContent, "Stopped. Start", "not running again: said once");
  assert.deepEqual(codes(sentence(doc)), ["mandu claude", "mandu codex"]);
});
