/**
 * home-js-rules-policy-file.test — Rules says where your rules file is, and
 * when Mandu refused your last edit to it (dashboard.md §4.25 *Rules says
 * where your rules file is*; the banner of policy-surface.md §2.1).
 *
 * Until 2026-10-25 a hand edit of policy.yaml the protection service found
 * not valid was refused, the last version that worked stayed in force, and
 * the product page said nothing: Rules looked as before, so a person who
 * typed a lock for `~/.ssh` with a mistake believed the folder protected.
 * Only the developer view drew a banner. The panel carries the file's state
 * as `policyFile`; now Rules draws it:
 *
 *   F1  refused, with two problems: the line above Your rules, in the
 *       warning box, names the file with `~`, says since when, and lists
 *       each problem in the words of the page (`problemWords`); the note
 *       under the intro is hidden;
 *   F2  refused, with seven problems: the first five, the fifth followed by
 *       ", and 2 more"; no time when `refusedAt` is null;
 *   F3  a problem holding markup lands as text, never as HTML;
 *   F4  in force: a dim note under the intro of Your rules, "Saved in
 *       ~/.mandu/policy.yaml. Mandu also reads your hand edits to it.";
 *   F5  no file yet: "Your rules will be saved in … when you add one.";
 *   F6  no `policyFile`, or one with no path: nothing is drawn;
 *   F7  a read of Rules that changed nothing leaves the line as drawn
 *       (sameAsDrawn); a read where the file is fixed takes it away.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub (home-js-fixtures.ts); across the real arbiter and
 * dashboard, tests/stack/rules-policy-file-refused.test.ts. Axes: none
 * (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { RULES_PANEL, load, tick } from "./home-js-fixtures.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const RULES = "http://127.0.0.1:4500/mandu/rules";
const PATH = "/home/u/.mandu/policy.yaml";
const AT = new Date(2026, 9, 25, 14, 5).getTime();
const PROBLEM_1 = 'paths[0].path: pattern "/home/u/.ssh/**": unknown level "no-modle"';
const PROBLEM_2 = "paths[1].level: must be one of public, any-model, local-model, no-model";

const fileState = (over: Record<string, unknown>) => ({ path: PATH, found: true, valid: true, problems: [], loadedAt: AT - 60_000, refusedAt: null, ...over });
const panel = (policyFile: unknown) => ({ panel: { ...RULES_PANEL.panel, policyFile } });
function rulesWith(policyFile: unknown) {
  return load({ url: RULES, routes: { "GET policy/panel": panel(policyFile) } });
}

const refused = (doc: Doc) => doc.getElementById("rules-refused");
const note = (doc: Doc) => doc.getElementById("rules-file");
const items = (doc: Doc) => [...refused(doc).querySelectorAll("li")].map((li: Doc) => li.textContent);
const LEAD_HEAD = "Your last edit to ~/.mandu/policy.yaml has a mistake, so Mandu is still using the last version that worked";
const LEAD_TAIL = ". Your rules below are the ones in force. Fix the file and save it; Mandu reads it again within seconds.";
/** The refused line without its list. */
const lead = (doc: Doc) => [...refused(doc).childNodes].filter((c: Doc) => c.nodeName !== "UL").map((c: Doc) => c.textContent).join("");

test("F1: a refused edit says so above Your rules, names the file with ~, says since when, and lists each problem in the words of the page", async () => {
  const { doc, err } = rulesWith(fileState({ valid: false, problems: [PROBLEM_1, PROBLEM_2], refusedAt: AT }));
  assert.equal(err, null);
  await tick();
  const box = refused(doc);
  assert.equal(box.hidden, false, "the refused line shows");
  assert.equal(box.getAttribute("role"), "status");
  assert.ok(box.classList.contains("rules-off"), "in the warning box of the Rules lines");
  assert.equal(box.previousElementSibling.id, "rules-pending", "beside the other lines above the cards");
  assert.equal(lead(doc), `${LEAD_HEAD} (since Oct 25, 14:05)${LEAD_TAIL}`);
  assert.equal(box.querySelector("code").textContent, "~/.mandu/policy.yaml", "the file as a name");
  const time = box.querySelector("time");
  assert.equal(time.getAttribute("datetime"), new Date(AT).toISOString(), "the moment of the refusal, as the page writes moments");
  assert.deepEqual(items(doc), ['~/.ssh/**: unknown level "no-modle"', "must be one of public, any-model, local-model, no-model"], "each problem in the words of the page");
  assert.equal(note(doc).hidden, true, "no note under the intro while the edit is refused");
  // Your rules still lists the rules in force.
  assert.ok(doc.querySelector("#rules-list .row, #files-tree .row"), "the rules in force are drawn");
});

test("F2: seven problems show the first five, the fifth followed by \", and 2 more\"; no refusedAt, no time", async () => {
  const seven = Array.from({ length: 7 }, (_, i) => `paths[${i}].level: problem number ${i + 1}`);
  const { doc } = rulesWith(fileState({ valid: false, problems: seven, refusedAt: null }));
  await tick();
  assert.deepEqual(items(doc), ["problem number 1", "problem number 2", "problem number 3", "problem number 4", "problem number 5, and 2 more"]);
  assert.equal(lead(doc), LEAD_HEAD + LEAD_TAIL, "no since when the moment is not known");
  assert.equal(refused(doc).querySelector("time"), null);
});

test("F3: a problem holding markup lands as text", async () => {
  const { doc } = rulesWith(fileState({ valid: false, problems: ["line 3: unexpected <b>bold</b> <img src=x onerror=alert(1)>"], refusedAt: AT }));
  await tick();
  assert.deepEqual(items(doc), ["line 3: unexpected <b>bold</b> <img src=x onerror=alert(1)>"]);
  assert.equal(refused(doc).querySelector("b, img"), null, "no element from the problem");
});

test("F4: a file in force: a dim note under the intro of Your rules names it", async () => {
  const { doc } = rulesWith(fileState({}));
  await tick();
  assert.equal(refused(doc).hidden, true);
  const n = note(doc);
  assert.equal(n.hidden, false);
  assert.ok(n.classList.contains("dim") && n.classList.contains("note"));
  assert.equal(n.textContent, "Saved in ~/.mandu/policy.yaml. Mandu also reads your hand edits to it.");
  assert.equal(n.querySelector("code").textContent, "~/.mandu/policy.yaml");
  assert.equal(n.previousElementSibling.textContent, "Your rules are checked first, then the built-in protections.", "under the intro");
  // A file outside the home folder is named as it is.
  const other = rulesWith(fileState({ path: "/etc/mandu/policy.yaml" }));
  await tick();
  assert.equal(note(other.doc).textContent, "Saved in /etc/mandu/policy.yaml. Mandu also reads your hand edits to it.");
});

test("F5: no file yet: the note says where your rules will be saved", async () => {
  const { doc } = rulesWith(fileState({ found: false }));
  await tick();
  assert.equal(refused(doc).hidden, true);
  assert.equal(note(doc).textContent, "Your rules will be saved in ~/.mandu/policy.yaml when you add one.");
});

test("F6: no policyFile, or one with no path: nothing is drawn", async () => {
  for (const policyFile of [undefined, null, fileState({ path: null }), fileState({ path: null, valid: false, problems: [PROBLEM_2] })]) {
    const { doc } = rulesWith(policyFile);
    await tick();
    assert.equal(refused(doc).hidden, true, `${JSON.stringify(policyFile)}: no refused line`);
    assert.equal(note(doc).hidden, true, `${JSON.stringify(policyFile)}: no note`);
    assert.equal(refused(doc).firstChild, null);
    assert.equal(note(doc).firstChild, null);
  }
});

test("F7: a read that changed nothing leaves the line as drawn; a read with the file fixed takes it away", async () => {
  let state: unknown = fileState({ valid: false, problems: [PROBLEM_1], refusedAt: AT });
  const { doc } = load({ url: RULES, routes: { "GET policy/panel": () => panel(state) } });
  await tick();
  const first = refused(doc).querySelector("li");
  assert.ok(first, "drawn");
  const go = (page: string) => doc.querySelector(`#nav a[data-page-link="${page}"]`).click();
  go("home");
  await tick();
  go("rules");
  await tick();
  assert.equal(refused(doc).querySelector("li"), first, "the same node: not drawn again");
  // A later reload that was refused again moves the moment: drawn again.
  state = fileState({ valid: false, problems: [PROBLEM_1], refusedAt: AT + 60_000 });
  go("home");
  await tick();
  go("rules");
  await tick();
  assert.notEqual(refused(doc).querySelector("li"), first, "drawn again for the new refusal");
  assert.match(lead(doc), /\(since Oct 25, 14:06\)/);
  // Fixed: the line goes and the note names the file.
  state = fileState({ loadedAt: AT + 120_000 });
  go("home");
  await tick();
  go("rules");
  await tick();
  assert.equal(refused(doc).hidden, true, "fixed: the refused line goes");
  assert.equal(note(doc).textContent, "Saved in ~/.mandu/policy.yaml. Mandu also reads your hand edits to it.");
});
