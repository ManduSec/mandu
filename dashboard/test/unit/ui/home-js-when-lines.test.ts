/**
 * home-js-when-lines.test — dashboard.md §4.25u *A moment keeps its number
 * with its word*. Until 2026-10-15 a moment's words could break anywhere:
 * headless Chromium drew History's running row at 1280 px as "running now,
 * started 1" over "minute ago" (the 150 px time column), and the session
 * page's header at 390 px as "… ended Oct 15, 15:31 · 2" over "minutes ago".
 * Now a compact row's relative words (`time.ago`) stay on one line, and a
 * moment that says both (`whenNode`) is written in two parts that each stay
 * on one line, so the line breaks only between them. The text is the same.
 *
 *   W1  whenNode: the session page's header (ended and running) and a
 *       question card on Home write their moment as "Oct 15, 15:31 ·" and
 *       "2 minutes ago" with one space between, the text as before;
 *   W2  the poll says each moment again in the same two parts, in the same
 *       <time>, an hour on;
 *   W3  Home's and History's rows keep the relative words alone in their
 *       `time.ago`, after "started " or "ended ";
 *   W4  app.css: `time.ago`, `.when-at` and `.when-ago` never wrap, at every
 *       width; the <time> of a moment and the row's time column still do,
 *       so the line can break between the parts and before the moment.
 *
 * §4.25u *A row's moment keeps its verb* (2026-10-17): History's running row
 * then read "running now, started" over "1 minute ago" in its 150 px column.
 * The verb's last word and the moment are now one `.when-phrase`:
 *
 *   W5  History's running row is "running now, " then the phrase "started
 *       1 minute ago"; an ended row and Home's rows are the phrase alone;
 *       the poll keeps the phrase and says the time again inside it;
 *   W6  app.css: `.when-phrase` is an inline box no wider than its line
 *       that may wrap inside, at every width.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { AGENT, ASK, CLOCK, PUB, home, load, tick } from "./home-js-fixtures.js";
import { declValue, flattenCss, mentions, stripComments } from "./css-flatten.js";

const HISTORY_URL = "http://127.0.0.1:4500/mandu/history";
const AGENT_URL = "http://127.0.0.1:4500/mandu/agents/s1";
const iso = (ms: number) => new Date(ms).toISOString();
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const poll = async (doc: any) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };

/** A whenNode <time>: exactly its two parts with one space between, and
 *  their words. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parts(t: any): [string, string] {
  assert.ok(t, "a moment is drawn");
  const nodes = [...t.childNodes] as { nodeType: number; className?: string; textContent: string }[];
  assert.deepEqual(nodes.map((x) => (x.nodeType === 1 ? `<${x.className}>` : JSON.stringify(x.textContent))), ["<when-at>", '" "', "<when-ago>"],
    `the clock time and the relative words, one space between: ${t.outerHTML}`);
  const [at, ago] = [nodes[0]!.textContent, nodes[2]!.textContent];
  assert.match(at, new RegExp(`^${CLOCK} ·$`), "the clock time keeps its dot");
  assert.equal(t.textContent, `${at} ${ago}`, "the text reads as one");
  return [at, ago];
}

test("W1: a moment that says both is written in two parts, the text as before (§4.25u)", async () => {
  const NOW = Date.now();
  // The session page's header, ended: "ran 36 seconds, ended Oct 15, 15:31 · 2 minutes ago".
  const ended = load({ url: AGENT_URL, routes: { "GET home/agent?session=s1": { ...AGENT, running: false, startedAt: iso(NOW - 2 * 60_000 - 36_000), lastAt: iso(NOW - 2 * 60_000) } } });
  await tick();
  const line = ended.doc.querySelector("#agent-sub .agent-when");
  assert.deepEqual(parts(line.querySelector("time.when"))[1], "2 minutes ago");
  assert.match(line.textContent, new RegExp(`^ran 36 seconds, ended ${CLOCK} · 2 minutes ago, in ~/ws$`));
  // Running: "running now, started Oct 15, 15:28 · 5 minutes ago".
  const running = load({ url: AGENT_URL, routes: { "GET home/agent?session=s1": { ...AGENT, running: true, startedAt: iso(NOW - 5 * 60_000), lastAt: iso(NOW) } } });
  await tick();
  const runLine = running.doc.querySelector("#agent-sub .agent-when");
  assert.equal(parts(runLine.querySelector("time.when"))[1], "5 minutes ago");
  assert.match(runLine.textContent, new RegExp(`^running now, started ${CLOCK} · 5 minutes ago, in ~/ws$`));
  // A question card on Home: "… Oct 15, 15:32 · 1 minute ago."
  const asked = load({ homeVm: home({ waiting: [{ ...ASK, askedAt: NOW - 60_000 }] }) });
  await tick();
  const sub = asked.doc.querySelector("#home-waiting .ask .ask-sub");
  assert.equal(parts(sub.querySelector("time.when"))[1], "1 minute ago");
  assert.match(sub.textContent, new RegExp(`${CLOCK} · 1 minute ago\\.`));
  // The datetime stays the moment's own.
  assert.equal(sub.querySelector("time.when").getAttribute("datetime"), iso(NOW - 60_000));
});

test("W2: the poll says each moment again in the same two parts, in the same <time> (§4.25u)", async () => {
  const NOW = Date.now();
  const { doc, window } = load({ url: AGENT_URL, routes: { "GET home/agent?session=s1": { ...AGENT, running: false, startedAt: iso(NOW - 3 * 60_000), lastAt: iso(NOW - 60_000) } } });
  await tick();
  const t = doc.querySelector("#agent-sub time.when");
  assert.equal(parts(t)[1], "1 minute ago");
  const realNow = window.Date.now;
  window.Date.now = () => realNow() + 3_600_000;
  try {
    await poll(doc);
  } finally {
    window.Date.now = realNow;
  }
  assert.equal(doc.querySelector("#agent-sub time.when"), t, "the moment is the one drawn");
  assert.equal(parts(t)[1], "1 hour ago", "its relative words say the time now, in their own part");
});

test("W3: Home's and History's rows keep the relative words alone in their time.ago (§4.25u)", async () => {
  const NOW = Date.now();
  const row = (id: string, over: Record<string, unknown>) => ({
    id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", state: "idle",
    stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null, ...over,
  });
  const rows = [row("r1", { state: "running", startedAt: iso(NOW - 60_000), lastAt: iso(NOW) }), row("e1", { startedAt: iso(NOW - 3 * 3_600_000), lastAt: iso(NOW - 2 * 3_600_000) })];
  const { doc } = load({ extensions: "", url: HISTORY_URL, homeVm: home(), routes: { "GET home/history": { total: 2, rows, next: null } } });
  await tick();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const when = (id: string) => doc.querySelector(`#history-list .row.agent[data-session="${id}"] .agent-when`) as any;
  assert.ok(when("r1") && when("e1"), "History drew both rows");
  for (const [id, before, words] of [["r1", "running now, started ", "1 minute ago"], ["e1", "ended ", "2 hours ago"]] as const) {
    const line = when(id).firstElementChild;
    const t = line.querySelector("time.ago");
    assert.equal(t.children.length, 0, "the relative words are one text");
    assert.equal(t.textContent, words);
    assert.equal(line.textContent, before + words, "the words before it are outside it, where the line may break");
  }
  // Home's Running now: the same line.
  const homePage = load({ homeVm: home({ agents: [{ ...rows[0], stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 } }] }) });
  await tick();
  const started = homePage.doc.querySelector('.row.agent[data-session="r1"] .agent-started');
  assert.ok(started, "Home drew the running row");
  assert.equal(started.querySelector("time.ago").textContent, "1 minute ago");
  assert.equal(started.textContent, "started 1 minute ago");
});

test("W4: app.css keeps each part of a moment on one line at every width, and lets the line break between them (§4.25u)", () => {
  const rules = flattenCss(stripComments(readFileSync(join(PUB, "app.css"), "utf8")));
  for (const sel of ["time.ago", ".when-at", ".when-ago"]) {
    const own = rules.filter((r) => r.media === null && r.selectors.includes(sel) && declValue(r.block, "white-space") !== null);
    assert.ok(own.some((r) => declValue(r.block, "white-space") === "nowrap"), `${sel} stays on one line`);
    for (const r of rules.filter((x) => x.selectors.some((s) => mentions(s, sel)) && declValue(x.block, "white-space") !== null)) {
      assert.equal(declValue(r.block, "white-space"), "nowrap", `"${r.selectors.join(", ")}"${r.media ? ` in ${r.media}` : ""} lets ${sel} wrap`);
    }
  }
  // The moment itself and the cells around it wrap: the line breaks between
  // the parts, and before the moment's phrase ("running now," over "started
  // 1 minute ago", W5/W6).
  for (const sel of ["time.when", ".when", ".agent-when", ".agent-started", ".agent-ended"]) {
    for (const r of rules.filter((x) => x.selectors.some((s) => mentions(s, sel)))) {
      assert.notEqual(declValue(r.block, "white-space"), "nowrap", `"${r.selectors.join(", ")}"${r.media ? ` in ${r.media}` : ""} keeps the whole of ${sel} on one line`);
    }
  }
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Node = any;
/** A row's moment line: its parts, a text as its JSON and an element as
 *  `<class>`; and its phrase's. */
function lineParts(line: Node): { line: string[]; phrase: string[] } {
  const show = (x: Node) => (x.nodeType === 1 ? `<${x.className}>` : JSON.stringify(x.textContent));
  const phrase = line.querySelector(".when-phrase");
  assert.ok(phrase, `the line has its phrase: ${line.outerHTML}`);
  return { line: [...line.childNodes].map(show), phrase: [...phrase.childNodes].map(show) };
}

test("W5: a row's moment keeps its verb: History's running row breaks after \"running now,\", not after \"started\" (§4.25u)", async () => {
  const NOW = Date.now();
  const row = (id: string, over: Record<string, unknown>) => ({
    id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", state: "idle",
    stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null, ...over,
  });
  const rows = [row("r1", { state: "running", startedAt: iso(NOW - 60_000), lastAt: iso(NOW) }), row("e1", { startedAt: iso(NOW - 3 * 3_600_000), lastAt: iso(NOW - 2 * 3_600_000) })];
  const { doc, window } = load({ extensions: "", url: HISTORY_URL, homeVm: home(), routes: { "GET home/history": { total: 2, rows, next: null } } });
  await tick();
  const when = (id: string): Node => doc.querySelector(`#history-list .row.agent[data-session="${id}"] .agent-when`).firstElementChild;
  assert.deepEqual(lineParts(when("r1")), { line: ['"running now, "', "<when-phrase>"], phrase: ['"started "', "<ago>"] },
    "the line may break after \"running now,\"; \"started\" goes with its moment");
  assert.equal(when("r1").textContent, "running now, started 1 minute ago", "the text is the same");
  assert.deepEqual(lineParts(when("e1")), { line: ["<when-phrase>"], phrase: ['"ended "', "<ago>"] }, "a one-word verb: the phrase is the whole line");
  assert.equal(when("e1").textContent, "ended 2 hours ago");
  // The poll says the time again inside the same phrase.
  const phrase = when("r1").querySelector(".when-phrase");
  const realNow = window.Date.now;
  window.Date.now = () => realNow() + 3_600_000;
  try {
    await poll(doc);
  } finally {
    window.Date.now = realNow;
  }
  assert.equal(when("r1").querySelector(".when-phrase"), phrase, "the phrase is the one drawn");
  assert.equal(phrase.textContent, "started 1 hour ago", "its moment says the time now");
  // Home's rows: the phrase alone.
  const homePage = load({ homeVm: home({ agents: [{ ...rows[0], stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 } }] }) });
  await tick();
  const started = homePage.doc.querySelector('.row.agent[data-session="r1"] .agent-started');
  assert.deepEqual(lineParts(started), { line: ["<when-phrase>"], phrase: ['"started "', "<ago>"] });
  assert.equal(started.textContent, "started 1 minute ago");
});

test("W6: app.css draws a .when-phrase as an inline box no wider than its line, wrapping inside, at every width (§4.25u)", () => {
  const rules = flattenCss(stripComments(readFileSync(join(PUB, "app.css"), "utf8")));
  const own = rules.filter((r) => r.media === null && r.selectors.includes(".when-phrase"));
  assert.ok(own.some((r) => declValue(r.block, "display") === "inline-block"), "an inline box: the line breaks before it, not inside it");
  assert.ok(own.some((r) => declValue(r.block, "max-width") === "100%"), "no wider than its line, so it never runs past its column");
  for (const r of rules.filter((x) => x.selectors.some((sel) => mentions(sel, ".when-phrase")))) {
    const where = `"${r.selectors.join(", ")}"${r.media ? ` in ${r.media}` : ""}`;
    assert.notEqual(declValue(r.block, "white-space"), "nowrap", `${where} keeps the phrase on one line even where it is wider than its column`);
    const display = declValue(r.block, "display");
    if (display !== null) assert.equal(display, "inline-block", `${where} draws the phrase as ${display}`);
    const max = declValue(r.block, "max-width");
    if (max !== null) assert.equal(max, "100%", `${where} lets the phrase be ${max} wide`);
  }
});
