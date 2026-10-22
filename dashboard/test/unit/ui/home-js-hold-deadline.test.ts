/**
 * home-js-hold-deadline.test — a held message's card says how long its
 * request still waits, then that it went with the default (dashboard.md
 * §4.34 *A held message's deadline*), on the PRODUCT page (public/js/home.js)
 * in jsdom over the shared fetch stub (home-js-fixtures.ts), with the page's
 * clock (`Date.now`) and its one-second timer held by the test.
 *
 * The arbiter holds the AI's request 30 s by default, then sends it with the
 * part masked (prompt-filter holds.ts); the card said only "for a short
 * while", and kept saying it waits after the message went. Pins: the line
 * counts down from the route's time left; at 0 it says the message went,
 * at `firstSeen` + the route's total, announced once (`role="status"`); a
 * hold first read past its deadline says so at once, unannounced; `redact`
 * says "removed"; a poll's redraw keeps the count; a null holds read draws
 * no line; the timer stops when no counting line is drawn.
 *
 * Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { ASK, home, load, tick } from "./home-js-fixtures.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const T0 = Date.parse("2026-10-22T05:00:10.000Z");
const FIRST_SEEN = T0 - 10_000;
const PROMPT_ASK = {
  ...ASK, id: "egr-7", family: "prompt",
  sentence: [{ kind: "text", text: "Claude Code wants to send your message to the AI. It holds " }, { kind: "code", text: "acme.codename" }, { kind: "text", text: "." }],
  actions: [{ approve: true, scope: "once", prompt: "send", label: "Send as written" }],
};
const hold = (over: Record<string, unknown> = {}) => ({
  approvalId: "egr-7", session: "s1", category: "acme.codename", filterId: "acme-dlp", span: "falconridge",
  fallback: "mask", firstSeen: FIRST_SEEN, lastSeen: T0, timeoutMs: 20_000, onceOnly: false, ...over,
});

/** The page with the holds route answering `holds()`; its clock at
 *  `clock.now`, its one-second timers kept in `later`. */
function open(holds: () => unknown, url?: string, waiting: unknown[] = [PROMPT_ASK]) {
  const clock = { now: T0 };
  const later: Array<() => void> = [];
  const page = load({
    ...(url ? { url } : {}),
    homeVm: home({ waiting }),
    routes: { "GET prompt-filters/holds": () => holds() },
    before: (w: Doc) => {
      w.Date.now = () => clock.now;
      const st = w.setTimeout;
      w.setTimeout = (fn: () => void, ms?: number, ...a: unknown[]) => (ms === 1000 ? (later.push(fn), 0) : st(fn, ms, ...a));
    },
  });
  /** `ms` on, then the timer that is due. */
  const pass = (ms: number) => {
    clock.now += ms;
    for (const f of later.splice(0)) f();
  };
  return { ...page, clock, later, pass };
}
const lineOf = (doc: Doc, where = "#home-waiting") => doc.querySelector(`${where} .ask-hold`);
const words = (x: Doc) => String(x.textContent).replace(/\s+/g, " ").trim();

async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

test("the line counts down from the route's time left, then says the message went masked at firstSeen + the total, announced once", async () => {
  const { doc, later, pass } = open(() => ({ timeoutMs: 30_000, holds: [hold()] }));
  await tick();
  const line = lineOf(doc);
  assert.ok(line, "the card has the line");
  assert.equal(line.previousElementSibling.className, "ask-found", "under It found");
  assert.equal(words(line), "The request to the AI waits 20 more seconds for your answer, then goes with that part masked.");
  assert.equal(line.getAttribute("role"), null, "no live region while it counts");
  assert.equal(later.length, 1, "one timer");

  const count = line.querySelector(".ask-hold-left");
  const node = count.firstChild;
  pass(1000);
  assert.match(words(line), /waits 19 more seconds/);
  pass(4000);
  assert.match(words(line), /waits 15 more seconds/);
  assert.equal(lineOf(doc), line, "the tick writes the line, never redraws the card");
  assert.equal(count.firstChild, node, "only the count's text node is written");
  pass(14_000);
  assert.match(words(line), /waits 1 more second for/);

  pass(1000);
  assert.equal(line.getAttribute("role"), "status", "the turn to the past is announced");
  assert.match(words(line), /^No answer came within 30 seconds, so your message went to the AI with that part masked at .+\. Your answer applies the next time the agent sends it\.$/);
  const at = line.querySelector("time.when");
  assert.equal(at.getAttribute("datetime"), new Date(FIRST_SEEN + 30_000).toISOString(), "the moment is firstSeen + the route's total");
  assert.equal(later.length, 0, "no counting line drawn: the timer stops");
});

test("a hold first read past its deadline says it went at once, unannounced; redact says removed; a total of 2 minutes says minutes", async () => {
  const past = open(() => ({ timeoutMs: 30_000, holds: [hold({ timeoutMs: 0 })] }));
  await tick();
  const line = lineOf(past.doc);
  assert.match(words(line), /^No answer came within 30 seconds, so your message went to the AI with that part masked at /);
  assert.equal(line.getAttribute("role"), null, "nothing changed in front of the person: no announcement");
  assert.equal(past.later.length, 0, "no timer for a line that does not count");

  const redact = open(() => ({ timeoutMs: 120_000, holds: [hold({ fallback: "redact", timeoutMs: 5_000 })] }));
  await tick();
  assert.equal(words(lineOf(redact.doc)), "The request to the AI waits 5 more seconds for your answer, then goes with that part removed.");
  redact.pass(5_000);
  assert.match(words(lineOf(redact.doc)), /^No answer came within 2 minutes, so your message went to the AI with that part removed at /);
});

test("a poll's redraw keeps the count: the route's stale time left never sets it back", async () => {
  const { doc, pass, setHome } = open(() => ({ timeoutMs: 30_000, holds: [hold()] }));
  await tick();
  const card = doc.querySelector('#home-waiting .ask[data-id="egr-7"]');
  pass(6000);
  assert.match(words(lineOf(doc)), /waits 14 more seconds/);
  // The ask changed (asked again), so the poll draws the card anew; the
  // route still says 20 s left.
  setHome(home({ waiting: [{ ...PROMPT_ASK, count: 2, askedAt: T0 + 5000 }] }));
  await poll(doc);
  assert.notEqual(doc.querySelector('#home-waiting .ask[data-id="egr-7"]'), card, "the card was drawn anew");
  assert.match(words(lineOf(doc)), /waits 14 more seconds/, "the count did not restart");
  pass(14_000);
  assert.equal(lineOf(doc).getAttribute("role"), "status", "a line drawn counting announces its turn, also after a redraw");
});

test("Approvals' full card has the line too; a null holds read draws none; the timer stops once no hold is drawn", async () => {
  const appr = open(() => ({ timeoutMs: 30_000, holds: [hold()] }), "http://127.0.0.1:4500/mandu/approvals");
  await tick();
  assert.match(words(lineOf(appr.doc, "#approvals-waiting")), /^The request to the AI waits 20 more seconds/);
  assert.ok(lineOf(appr.doc), "Home's short card of the same hold is drawn too, hidden");
  appr.pass(20_000);
  for (const where of ["#approvals-waiting", "#home-waiting"]) {
    assert.equal(lineOf(appr.doc, where).getAttribute("role"), "status", `${where}: each counting line announces its own turn`);
  }

  const none = open(() => ({ status: 404, body: {} }));
  await tick();
  assert.equal(none.doc.querySelector("#home-waiting .ask-found").textContent, "", "as today");
  assert.equal(lineOf(none.doc), null, "no line");
  assert.equal(none.later.length, 0, "no timer");

  // An older route with no deadline: the found text, no line.
  const old = open(() => ({ holds: [{ approvalId: "egr-7", span: "falconridge" }] }));
  await tick();
  assert.equal(old.doc.querySelector("#home-waiting .ask-found").textContent, "It found: falconridge");
  assert.equal(lineOf(old.doc), null);

  // The card answered elsewhere: the next poll draws no card and the
  // pending tick does not arm another.
  const gone = open(() => ({ timeoutMs: 30_000, holds: [hold()] }));
  await tick();
  assert.equal(gone.later.length, 1);
  gone.setHome(home({ waiting: [] }));
  await poll(gone.doc);
  assert.equal(lineOf(gone.doc), null);
  gone.pass(1000);
  assert.equal(gone.later.length, 0, "the timer stopped");
});
