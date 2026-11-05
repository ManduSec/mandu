/**
 * css-empty-slots — an empty slot takes no room: Home's list of top secrets
 * when it lists none, and on a phone a session step's empty tag slot
 * (dashboard.md §4.25ai *Home's card*, §4.25b *On a phone*). Mandu-new.
 *
 * `#home-scan-top` (a flex `<ul>` with an 8 px top margin) stayed laid out
 * when `renderHomeScan` emptied it, before any scan and after one where
 * nothing left; and at 760 px and below a step's grid drops to two columns,
 * so a reply's or an untagged step's empty trailing `<span>` wrapped onto a
 * row of its own and added the 12 px gap under the words.
 *
 *   E1  Home drawn in jsdom under the 1280 and 390 px styles: an empty
 *       `#home-scan-top` (no scan; a scan where nothing left) computes
 *       `display: none`; one listing a secret does not;
 *   E2  the session page under the 390 px styles: every `.step.wide` and
 *       `.half-body` whose last child is an empty span has it hidden; a
 *       tagged step's `.tag` and every `.ic` stay shown;
 *   E3  under the 1280 px styles nothing in the story is hidden: the slot
 *       keeps its third column.
 * The layout itself is measured in headless Chromium by the stack test
 * empty-slots-gap; jsdom has none.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { AGENT, PUB, home, load, tick } from "./home-js-fixtures.js";
import { resolveCssVars, stylesAt } from "./css-flatten.js";
import { homeScanCard, type LastScanWire } from "../../../src/view-model/last-scan.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** The product page's own styles, as index.html links them. */
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");

/** A kept scan: one known secret, sent in a session without Mandu or not. */
function record(left: boolean): LastScanWire {
  return {
    version: 1, ranAt: "2026-10-21T09:00:00.000Z", sessions: { "claude-code": 3 }, duringMandu: left ? 0 : 1, known: 1,
    findings: [{
      kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, sessions: 1, sessionsUnderMandu: left ? 0 : 1, agents: ["claude-code"],
      last: "2026-10-19T10:00:00.000Z", how: { "command-output": 1 }, projects: ["~/shop"], duringMandu: left ? 0 : 1,
    }],
    dropped: 0, capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 },
    sends: [], sendsDropped: 0, suggestions: null,
  } as LastScanWire;
}

/** A page drawn in jsdom under the styles of a `width` px window. */
async function drawn(width: number, opts: Parameters<typeof load>[0]) {
  const { doc, err } = load(opts);
  assert.equal(err, null);
  const sheet = doc.createElement("style");
  sheet.textContent = resolveCssVars(stylesAt(CSS, width));
  doc.head.append(sheet);
  await tick(40);
  return { doc, display: (e: El) => doc.defaultView.getComputedStyle(e).display as string };
}

test("E1: Home's list of top secrets is not drawn while it lists none, and is when it lists one", async () => {
  for (const width of [1280, 390]) {
    for (const [what, rec, listed] of [["no scan", null, false], ["nothing left", record(false), false], ["a secret left", record(true), true]] as const) {
      const { doc, display } = await drawn(width, { homeVm: { ...home(), scan: homeScanCard(rec) } });
      const top = doc.getElementById("home-scan-top");
      assert.equal(doc.getElementById("home-scan").hidden, false, `${what}: the card is drawn`);
      assert.equal(top.children.length > 0, listed, `${what}: ${listed ? "a secret listed" : "nothing listed"}`);
      if (listed) assert.equal(display(top), "flex", `${width} px, ${what}: the list is drawn`);
      else assert.equal(display(top), "none", `${width} px, ${what}: the empty list takes no room`);
      assert.notEqual(display(doc.getElementById("home-scan-again")), "none", `${width} px, ${what}: Run it stays`);
    }
  }
});

/** The session page's story rows: each grid and its children's display. */
async function story(width: number) {
  const { doc, display } = await drawn(width, { url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": AGENT } });
  const rows = [...doc.querySelectorAll("#agent-story .step.wide, #agent-story .half-body")] as El[];
  assert.ok(rows.length > 0, "the story is drawn");
  return { rows, display };
}

test("E2: on a phone an empty trailing tag slot is hidden; a tag and every icon stay shown", async () => {
  const { rows, display } = await story(390);
  const empty = rows.filter((r) => r.lastElementChild.tagName === "SPAN" && r.lastElementChild.childNodes.length === 0);
  const tagged = rows.filter((r) => r.lastElementChild.classList.contains("tag"));
  assert.ok(empty.some((r) => r.classList.contains("reply")), "a reply with an empty slot");
  assert.ok(empty.some((r) => r.classList.contains("plain")), "an ordinary step with one");
  assert.ok(empty.some((r) => r.classList.contains("half-body")), "a split reply's half with one");
  assert.ok(tagged.some((r) => r.classList.contains("blocked")), "a blocked step with its tag");
  for (const r of empty) assert.equal(display(r.lastElementChild), "none", `${r.className}: its empty slot is hidden`);
  for (const r of tagged) assert.notEqual(display(r.lastElementChild), "none", `${r.className}: its tag is shown`);
  for (const r of rows) {
    const ic = r.querySelector(":scope > .ic");
    assert.ok(ic, `${r.className}: an icon`);
    assert.notEqual(display(ic), "none", `${r.className}: its icon is shown`);
    assert.notEqual(display(r.querySelector(":scope > .what")), "none", `${r.className}: its words are shown`);
  }
});

test("E3: in a wide window nothing in a step is hidden: the slot keeps its column", async () => {
  for (const width of [1280, 761]) {
    const { rows, display } = await story(width);
    for (const r of rows) {
      for (const child of r.children) assert.notEqual(display(child), "none", `${width} px, ${r.className}: ${child.className || child.tagName} is drawn`);
    }
  }
});
