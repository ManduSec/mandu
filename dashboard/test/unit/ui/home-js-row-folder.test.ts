/**
 * home-js-row-folder.test — dashboard.md §4.25 *Agents, not sessions*, *The
 * folder stays in sight*. A session row's first line under Running now,
 * Earlier and History says what you asked, then " in ~/folder", the folder
 * being what tells two sessions of one agent apart. Until 2026-10-30 the
 * line was one ellipsized text, so on a 390 px phone a prompt of about 40
 * characters already cut the folder away. Now:
 *
 *   F1  a row with a folder draws the prompt in its own span, " in ", then
 *       the folder's code (a left-to-right bdi inside); the line's words,
 *       its title and the names of its Details and Waiting links are as
 *       before, on Home (Running now, Earlier) and History alike;
 *   F2  a row with no folder draws the line as before: one text, no " in ";
 *   F3  app.css: the line is a one-line flex in which the prompt shrinks
 *       and is ellipsized, " in " keeps its spaces, and the folder never
 *       shrinks, is capped at half the line and is cut at its start (right
 *       to left), and print leaves the line as on screen.
 *
 * The layout itself (the folder's box inside the line at 390 and 1280 px)
 * is proved in real Chromium by the stack test long-name-breaks.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { PUB, home, load, tick } from "./home-js-fixtures.js";
import { declValue, flattenCss, stripComments } from "./css-flatten.js";
import { waitWhile } from "../page-wait.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const LONG = "What is in deploy/staging.tfvars? Show me its lines and say which of them the staging servers still read today.";
const agent = (id: string, over: Record<string, unknown> = {}) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/projects/shop", startedAt: new Date(Date.now() - 3 * 3_600_000).toISOString(), lastAt: new Date(Date.now() - 3_600_000).toISOString(), state: "idle",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null, ...over,
});
const ROWS = [
  agent("run", { state: "running", title: LONG, waiting: 1 }),
  agent("long", { title: LONG }),
  agent("short", { title: "Fix it", cwd: "/home/u/api" }),
  agent("none", { title: LONG, cwd: null }),
];
const lineOf = (doc: El, id: string) => doc.querySelector(`.row.agent[data-session="${id}"] .agent-what > .sub`);
const childClasses = (x: El) => [...x.childNodes].map((n: El) => (n.nodeType === 1 ? `${n.localName}.${n.className}` : "#text"));

/** F1 and F2 on the rows a page drew. */
function checkRows(doc: El, where: string): void {
  for (const [id, prompt, folder] of [["run", LONG, "~/projects/shop"], ["long", LONG, "~/projects/shop"], ["short", "Fix it", "~/api"]] as const) {
    const line = lineOf(doc, id);
    assert.ok(line, `${where}: row ${id} is drawn`);
    assert.equal(line.className, "sub prompt-line", `${where} ${id}: the prompt's line with its folder`);
    assert.deepEqual(childClasses(line), ["span.prompt-text", "span.prompt-in", "code.prompt-folder"], `${where} ${id}: the prompt, " in ", the folder`);
    assert.equal(line.querySelector(".prompt-text").textContent, prompt, `${where} ${id}: the whole prompt stays in the page`);
    assert.equal(line.querySelector(".prompt-in").textContent, " in ");
    const bdi = line.querySelector("code.prompt-folder > bdi");
    assert.ok(bdi, `${where} ${id}: the folder is isolated`);
    assert.equal(bdi.getAttribute("dir"), "ltr", `${where} ${id}: left to right inside its right-to-left box`);
    assert.equal(bdi.textContent, folder);
    assert.equal(line.textContent, `${prompt} in ${folder}`, `${where} ${id}: the line reads as before`);
    assert.equal(line.title, `${prompt} — ${folder.replace("~", "/home/u")}`, `${where} ${id}: the whole prompt and folder on hover`);
    const details = doc.querySelector(`.row.agent[data-session="${id}"] > a.right`);
    assert.equal(details.getAttribute("aria-label"), `Details: Claude Code, ${prompt} in ${folder}`, `${where} ${id}: Details is named as before`);
  }
  const waits = doc.querySelector('.row.agent[data-session="run"] a.agent-waiting-link');
  assert.ok(waits, `${where}: the running row's question is linked`);
  assert.match(waits.getAttribute("aria-label"), new RegExp(`: Claude Code, ${LONG.replace(/[.?]/g, "\\$&")} in ~/projects/shop$`), `${where}: its link is named by the row as before`);
  // ── F2 ──
  const none = lineOf(doc, "none");
  assert.equal(none.className, "sub ellipsis", `${where}: no folder, the line as before`);
  assert.deepEqual(childClasses(none), ["#text"], `${where}: one text`);
  assert.equal(none.textContent, LONG);
  assert.equal(none.querySelector("code"), null, `${where}: no folder, no " in " one`);
  assert.equal(none.title, LONG);
}

test("F1, F2: Home's rows (Running now, Earlier) keep the prompt and the folder apart, with the line's words, title and names as before; no folder, as before", async () => {
  const { doc, err } = load({ homeVm: home({ waiting: [], agents: ROWS }) });
  assert.equal(err, null);
  await tick();
  assert.ok(doc.querySelector('#home-agents .row.agent[data-session="run"]'), "the running row is under Running now");
  assert.ok(doc.querySelector('#home-earlier .row.agent[data-session="long"]'), "an ended row is under Earlier");
  checkRows(doc, "Home");
});

test("F1, F2: History's rows draw the same line", async () => {
  const { doc, err } = load({ extensions: "", url: "http://127.0.0.1:4500/mandu/history", homeVm: home({ waiting: [] }), routes: { "GET home/history": { total: ROWS.length, rows: ROWS, next: null } } });
  assert.equal(err, null);
  await waitWhile(() => doc.querySelectorAll("#history-list .row.agent").length < ROWS.length);
  checkRows(doc, "History");
});

test("F3: app.css cuts the prompt, keeps ' in ' and the folder, caps the folder at half the line and cuts it at its start; print keeps it", () => {
  const css = stripComments(readFileSync(join(PUB, "app.css"), "utf8"));
  const rules = flattenCss(css);
  const rule = (sel: string) => {
    const r = rules.find((x) => x.selectors.includes(sel) && x.media === null);
    assert.ok(r, `${sel} has its rule`);
    return (prop: string) => declValue(r.block, prop);
  };
  const line = rule(".prompt-line");
  assert.equal(line("display"), "flex", "the line lays its parts side by side");
  assert.equal(line("white-space"), "nowrap", "on one line");
  assert.equal(line("min-width"), "0");
  assert.equal(line("overflow"), "hidden", "nothing runs past it");
  const prompt = rule(".prompt-text");
  assert.equal(prompt("min-width"), "0", "the prompt may shrink below its words");
  assert.match(prompt("flex") ?? "", /^0 1 /, "it is what shrinks");
  assert.equal(prompt("overflow"), "hidden");
  assert.equal(prompt("text-overflow"), "ellipsis", "cut with …");
  const inWord = rule(".prompt-in");
  assert.equal(inWord("flex"), "none");
  assert.equal(inWord("white-space"), "pre", "its spaces stay at the edges of its box");
  const folder = rule(".prompt-folder");
  assert.equal(folder("flex"), "none", "the folder never shrinks below its width while it fits");
  assert.equal(folder("max-width"), "50%", "at most half the line");
  assert.equal(folder("overflow"), "hidden");
  assert.equal(folder("text-overflow"), "ellipsis");
  assert.equal(folder("direction"), "rtl", "a longer folder is cut at its start, its last names kept");
  for (const r of flattenCss(css).filter((x) => x.media?.includes("print"))) {
    for (const sel of r.selectors) {
      assert.ok(!/prompt-(line|text|in|folder)/.test(sel), `print leaves the line as on screen: ${sel}`);
    }
  }
});
