/**
 * home-js-rules-warning-once.test — dashboard.md §4.25p *A warning is said
 * once*. An opened rule in Your rules says the rule's warning in full in its
 * left column (`.rule-warn`, from the policy panel), and until 2026-10-16
 * *What the rules say* said it again as its Warning line (from the why
 * route): the same 51 words twice in one row, at every width. Now:
 *
 *   O1  an opened rule says its warning once, in its left column; the box
 *       draws the route's other lines, in order;
 *   O2  a your-own-AI rule's warning (the no-own-model sentence, then the
 *       readers' one) still leaves out the box's line it holds;
 *   O3  only what the row says, and only a Warning line: a warning worded
 *       differently, or a rule with none, keeps the box's line, and a line
 *       of another term stays even when the warning holds its words;
 *   O4  Add a rule's browser (its rows carry no rule) keeps the box's line,
 *       so its row says the warning once too;
 *   O5  the box's redraws keep it: answered after the row opened, and read
 *       again after a failed read.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter and dashboard,
 * tests/stack/rules-warning-once.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { FILES_URL, WS_LIST, list, load, opened, openRow, tick, treeRow } from "./home-js-fixtures.js";

const RULES = "http://127.0.0.1:4500/mandu/rules";
const PATH = "/home/u/ws/.env";
const WHY_ROUTE = `GET files/why?path=${encodeURIComponent(PATH)}`;
const PRINTERS = "psql, cat print or copy what they read to whatever reads their output, which can be the AI's own code, so they read nothing here: each gets the masked copy (or is refused), even pinned. Name the program that uses the secret instead (e.g. pg_dump, aws), not one that prints it.";
const NO_OWN = "No AI of your own is listed, so no AI reads this file. Add one in Settings › Models.";
const DOWN = { status: 503, body: { error: "the arbiter is not reachable", tenant: "live", unreachable: true } };

/** The why route's lines for the file, the Warning among them. */
const LINES = [
  { term: "Where the label comes from", text: "Your rule (~/ws/.env)" },
  { term: "Programs that get the real file", text: "psql (admits nothing), ssh (only when git starts it), cat (admits nothing)" },
  { term: "Warning", text: PRINTERS },
  { term: "What the AI sees of their output", text: "Masked as a whole, for every program above." },
  { term: "Any other program", text: "Is refused." },
  { term: "May be sent to", text: "Nowhere without your OK." },
];
const whyOf = (lines: Array<{ term: string; text: string }>) => ({ why: { path: PATH, display: "~/ws/.env", label: { level: "no-model", words: "No AI", source: "yours", from: "Your rule", bindings: [] }, off: false, lines } });
const said = (lines: Array<{ term: string; text: string }>) => lines.map((l) => `${l.term}: ${l.text}`);
const WITHOUT_WARNING = said(LINES.filter((l) => l.term !== "Warning"));

function panelWith(warning: string | undefined, level = "no-model") {
  return { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [{
    id: `lock:${PATH}`, kind: "lock", subject: PATH, reach: null, hits: null, covers: "exact", level, bindings: [], effect: "x",
    actions: { remove: true, flip: null },
    plain: { subject: PATH, reach: "this file only", effect: "No AI", opens: "ssh (checked by Mandu) may open the real file." },
    ...(warning === undefined ? {} : { warning }),
  }] } };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
/** The opened row's box, as `term: text` lines. */
const boxLines = (row: Doc): string[] => ([...row.querySelectorAll(".file-why dt")] as Doc[]).map((dt) => `${dt.textContent}: ${dt.nextElementSibling.textContent}`);
/** The opened row's left column's warnings. */
const leftWarnings = (row: Doc): string[] => ([...row.querySelectorAll(".file-detail-main .rule-warn")] as Doc[]).map((w) => w.textContent);
/** How often the row says `sentence`. */
const times = (row: Doc, sentence: string) => row.textContent.split(sentence).length - 1;

async function openRule(doc: Doc) {
  treeRow(doc, /ws\/\.env$/).querySelector(".file-more").click();
  await tick();
  const row = doc.querySelector("#files-tree .file-detail");
  assert.ok(row, "the rule's row is open");
  return row;
}

test("O1: an opened rule says its warning once, in its left column; What the rules say draws the route's other lines, in order", async () => {
  const { doc } = load({ url: RULES, routes: { "GET policy/panel": panelWith(PRINTERS), [WHY_ROUTE]: whyOf(LINES) } });
  await tick();
  const row = await openRule(doc);
  assert.deepEqual(leftWarnings(row), [PRINTERS], "said in full beside the rule's controls, as before");
  assert.deepEqual(boxLines(row), WITHOUT_WARNING, "the box: every other line of the route, in order");
  assert.equal(times(row, PRINTERS), 1, "the opened row says it once");
  assert.equal(treeRow(doc, /ws\/\.env$/).querySelector(".file-warn-mark").getAttribute("aria-label"), PRINTERS, "the row's mark still names it");
});

test("O2: a your-own-AI rule's joined warning leaves out the box's line it holds, and says each sentence once", async () => {
  const { doc } = load({ url: RULES, routes: { "GET policy/panel": panelWith(`${NO_OWN} ${PRINTERS}`, "local-model"), [WHY_ROUTE]: whyOf(LINES) } });
  await tick();
  const row = await openRule(doc);
  assert.deepEqual(leftWarnings(row), [`${NO_OWN} ${PRINTERS}`]);
  assert.deepEqual(boxLines(row), WITHOUT_WARNING);
  assert.equal(times(row, PRINTERS), 1);
  assert.equal(times(row, NO_OWN), 1);
});

test("O3: only what the row says, and only a Warning line: another wording or no warning keeps the box's line; a line of another term stays", async () => {
  const other = PRINTERS.replace("psql, cat print", "psql print");
  for (const [warning, why] of [[other, "worded otherwise (another judgment of the same readers)"], [undefined, "the panel saw nothing to warn about"]] as const) {
    const { doc } = load({ url: RULES, routes: { "GET policy/panel": panelWith(warning), [WHY_ROUTE]: whyOf(LINES) } });
    await tick();
    const row = await openRule(doc);
    assert.deepEqual(boxLines(row), said(LINES), `${why}: the box keeps every line`);
    assert.equal(times(row, PRINTERS), 1, `${why}: the box says it, once`);
  }
  // An older server words a reader by its name alone; the warning holds
  // those words, and the line is not a warning, so it stays.
  const named = [{ term: "Programs that get the real file", text: "psql, cat" }, { term: "Warning", text: PRINTERS }];
  const { doc } = load({ url: RULES, routes: { "GET policy/panel": panelWith(PRINTERS), [WHY_ROUTE]: whyOf(named) } });
  await tick();
  const row = await openRule(doc);
  assert.deepEqual(boxLines(row), ["Programs that get the real file: psql, cat"]);
});

test("O4: Add a rule's browser keeps the box's Warning line: its row has no rule, so the box is where it is said", async () => {
  const { doc } = load({ url: FILES_URL, storage: { "mandu.files.folder": "/home/u/ws" }, routes: {
    "GET policy/panel": panelWith(PRINTERS), [list("/home/u/ws")]: WS_LIST, [WHY_ROUTE]: whyOf(LINES),
  } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  openRow(doc, /^\.env/);
  await tick();
  const row = doc.querySelector("#files-list .file-detail");
  assert.ok(row, "the browser's row is open");
  assert.deepEqual(leftWarnings(row), [], "no rule of its own here");
  assert.deepEqual(boxLines(row), said(LINES));
  assert.equal(times(row, PRINTERS), 1);
});

test("O5: the box keeps it across its redraws: answered after the row opened, and read again after a failed read", async () => {
  // Answered later: the row draws "Reading the rules…", then the answer.
  let answer: (v: unknown) => void = () => {};
  const late = new Promise((r) => { answer = r; });
  const slow = load({ url: RULES, routes: { "GET policy/panel": panelWith(PRINTERS), [WHY_ROUTE]: () => late } });
  await tick();
  const waiting = await openRule(slow.doc);
  assert.match(waiting.querySelector(".file-why").textContent, /Reading the rules…/);
  answer(whyOf(LINES));
  await tick();
  const answered = slow.doc.querySelector("#files-tree .file-detail");
  assert.deepEqual(boxLines(answered), WITHOUT_WARNING, "the answer drawn in place leaves it out");
  assert.equal(times(answered, PRINTERS), 1);

  // A failed read, then the service comes back and the open box asks again.
  let up = false;
  const { doc, calls } = load({ url: RULES, routes: {
    "GET home": () => (up ? undefined : DOWN),
    "GET policy/panel": panelWith(PRINTERS),
    [WHY_ROUTE]: () => (up ? whyOf(LINES) : DOWN),
  } });
  await tick();
  const failed = await openRule(doc);
  assert.ok(failed.querySelector(".file-why .ask-error"), "the read failed");
  const asked = calls.filter((c) => c.url.includes("/api/files/why")).length;
  up = true;
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick();
  assert.equal(calls.filter((c) => c.url.includes("/api/files/why")).length, asked + 1, "asked again once");
  const again = doc.querySelector("#files-tree .file-detail");
  assert.deepEqual(boxLines(again), WITHOUT_WARNING, "read again, it still leaves it out");
  assert.equal(times(again, PRINTERS), 1);
});
