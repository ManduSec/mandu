/**
 * home-js-pending-focus.test — on the product page's Rules, Changes to save
 * and *Move them into policy.yaml* keep the keyboard focus (dashboard.md
 * §4.25 *Changes to save keeps the focus*).
 *
 * Until 2026-10-11 Save turned itself off while the changes were on their
 * way and the bar hid itself once they were saved, Discard hid the bar under
 * its own button, and Drop and Skip drew the list again under theirs: each
 * left a screen reader on <body>. *Move them into policy.yaml* went off and
 * was drawn away the same way, and a refused move wrote its words into
 * Changes to save, hidden while nothing waits: it said nothing. Now:
 *
 *   - the bar gone (saved, discarded, the last change dropped): the Your
 *     rules heading, where the notice says what was saved;
 *   - a change dropped or skipped while others wait: the bar's heading,
 *     never another row's button;
 *   - a weaker change asked about first: the question, never Save anyway;
 *   - a refusal: Save, on again, described by the refusal's words;
 *   - a move: the Your rules heading; a refused move says why in its own
 *     box, and its button gets the focus back, described by those words;
 *   - a press made without the focus in the bar, or a focus moved elsewhere
 *     meanwhile, moves nothing.
 *
 * jsdom keeps the focus of a control turned off, or hidden, so `press`
 * drops it to <body> as Chromium does (home-js-rules-focus.test.ts). Drives
 * the PRODUCT page script (public/js/home.js) in jsdom over the shared fetch
 * stub (home-js-fixtures.ts). Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, FILES_ROUTES } from "./home-js-fixtures.js";
import { suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** Enter on a button that the change turns off: it has the focus, the click
 *  acts, and while the change is on its way (its POST held) the button is
 *  off and the browser has dropped its focus to <body>. `meanwhile` runs
 *  before the answer comes. */
async function press(btn: Doc, meanwhile: () => void = () => {}): Promise<void> {
  const window = btn.ownerDocument.defaultView;
  const real = window.fetch;
  let open: () => void = () => {};
  const gate = new Promise<void>((r) => { open = r; });
  window.fetch = (url: string, init: Doc = {}) => (init.method === "POST" ? gate.then(() => real(url, init)) : real(url, init));
  btn.focus();
  btn.click();
  await tick(3);
  assert.equal(btn.disabled, true, "the change turns its button off while it is on its way");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
  assert.equal(btn.ownerDocument.activeElement, btn.ownerDocument.body);
  meanwhile();
  window.fetch = real;
  open();
}
const focused = (doc: Doc) => doc.activeElement;
const heading = (doc: Doc) => doc.getElementById("rules-title");
const bar = (doc: Doc) => doc.getElementById("files-pending");
const saveBtn = (doc: Doc) => doc.getElementById("files-save");
const dropOf = (doc: Doc, display: string) => [...doc.querySelectorAll("#files-pending-list button")].find((b: Doc) => b.getAttribute("aria-label") === `Drop the change to ${display}`);
const shown = (x: Doc) => !!x && x.isConnected && !x.closest("[hidden]");

const change = (name: string, level: string) => ({
  path: `/home/u/ws/${name}`, display: `~/ws/${name}`, level, bindings: [], recursive: false, before: "Like any other file", target: null,
});
const TWO = JSON.stringify([change("notes.md", "no-model"), change("todo.md", "no-model")]);
const ONE = JSON.stringify([change("notes.md", "no-model")]);

/** The Rules page with changes waiting, and a save route. */
function waiting(storage: string, labels: unknown) {
  const saves: Doc[] = [];
  const page = load({ url: FILES_URL, storage: { "mandu.files.pending": storage }, routes: { ...FILES_ROUTES,
    "POST files/labels": (b: Doc) => (saves.push(b), typeof labels === "function" ? labels(b) : labels),
  } });
  return { ...page, saves };
}

test("Changes to save: Save gives the focus to the Your rules heading once the bar is gone, where the notice says what was saved", async () => {
  const { doc, saves } = waiting(ONE, { applied: true, changeId: "pc-000011", page: 0 });
  await tick();
  assert.equal(shown(saveBtn(doc)), true);
  await press(saveBtn(doc));
  await tick(30);
  assert.equal(saves.length, 1);
  assert.equal(bar(doc).hidden, true, "saved: nothing waits");
  assert.equal(focused(doc), heading(doc), "the Your rules heading, never <body>");
  assert.equal(doc.getElementById("rules-notice").firstChild.textContent, "1 change saved.");
});

test("Changes to save: a weaker change gives the focus to the question, never Save anyway; Save anyway then gives it to the heading", async () => {
  const { doc, saves } = waiting(ONE, (b: Doc) => (b.expected
    ? { applied: true, changeId: "pc-000012", page: 0 }
    : { applied: false, confirm: true, expected: ["k"], loosens: [{ subject: "~/ws/notes.md", detail: "Becomes Not secret." }] }));
  await tick();
  await press(saveBtn(doc));
  await tick(30);
  const question = doc.querySelector("#files-confirm > p");
  assert.equal(shown(question), true, "a weaker change asks first");
  assert.equal(saveBtn(doc).textContent, "Save anyway");
  assert.equal(focused(doc), question, "the question, which says what the change does");
  assert.notEqual(focused(doc), saveBtn(doc), "a second Enter loosens nothing");
  assert.equal(question.getAttribute("tabindex"), "-1", "a line, not a Tab stop");
  await press(saveBtn(doc));
  await tick(30);
  assert.deepEqual(saves[1].expected, ["k"], "sent back with what was shown");
  assert.equal(bar(doc).hidden, true);
  assert.equal(focused(doc), heading(doc));
});

test("Changes to save: a refused Save gives the focus back to Save, described by the refusal's words; so does a 409 after the question", async () => {
  let n = 0;
  const { doc } = waiting(ONE, (b: Doc) => (++n === 1
    ? { status: 403, body: { error: "Sign in first: open the admin link." } }
    : b.expected ? { status: 409, body: { error: "Your rules changed while you were deciding. Nothing was changed. Try again." } }
    : { applied: false, confirm: true, expected: ["k"], loosens: [] }));
  await tick();
  await press(saveBtn(doc));
  await tick(30);
  const words = doc.getElementById("lock-error");
  assert.match(words.textContent, /Sign in first/);
  assert.equal(shown(words), true);
  assert.equal(saveBtn(doc).disabled, false, "on again");
  assert.equal(focused(doc), saveBtn(doc), "the button pressed");
  assert.equal(saveBtn(doc).getAttribute("aria-describedby"), "lock-error", "described by the refusal's words");
  assert.equal(bar(doc).hidden, false, "the changes still wait");

  await press(saveBtn(doc));
  await tick(30);
  assert.equal(focused(doc), doc.querySelector("#files-confirm > p"));
  await press(saveBtn(doc));
  await tick(30);
  assert.match(words.textContent, /changed while you were deciding/);
  assert.equal(saveBtn(doc).textContent, "Save changes", "asked again on the next Save");
  assert.equal(focused(doc), saveBtn(doc), "Save, though it reads otherwise now");
});

test("Changes to save: Drop gives the focus to the bar's heading while changes still wait, never the other row's Drop; the last one, to the Your rules heading", async () => {
  const { doc } = waiting(TWO, {});
  await tick();
  const first = dropOf(doc, "~/ws/notes.md");
  first.focus();
  first.click();
  assert.equal(first.isConnected, false, "the list was drawn again");
  const h3 = bar(doc).querySelector("h3");
  assert.equal(focused(doc), h3, "the bar's heading");
  assert.equal(h3.textContent, "Changes to save 1");
  assert.equal(doc.querySelectorAll("#files-pending-list li").length, 1);
  const last = dropOf(doc, "~/ws/todo.md");
  last.focus();
  last.click();
  assert.equal(bar(doc).hidden, true);
  assert.equal(focused(doc), heading(doc), "the bar is gone: the Your rules heading");
});

test("Changes to save: Discard gives the focus to the Your rules heading, never the hidden bar", async () => {
  const { doc, saves } = waiting(TWO, {});
  await tick();
  const discard = doc.getElementById("files-discard");
  discard.focus();
  discard.click();
  assert.equal(bar(doc).hidden, true, "nothing waits");
  assert.equal(focused(doc), heading(doc), "not Discard, hidden with the bar");
  assert.equal(saves.length, 0);
});

test("Changes to save: Skip on a suggestion of Mandu's gives the focus to the bar's heading while a change still waits", async () => {
  const REPO = "/home/u/proj";
  const key: SuggestionWire = {
    id: "pp-000001", kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: "k-1", source: "git-history", repoRoot: REPO,
    edits: [{ op: "lock-path", path: `${REPO}/deploy/id_rsa`, level: "no-model" }],
    sentence: "Make ~/proj/deploy/id_rsa a secret no AI may read (only in git history)",
    evidence: { paths: ["deploy/id_rsa"], blobs: ["a".repeat(40)], historyOnly: true, findings: [] },
    impact: { historicalVersions: 2, workingTreeChanges: false, files: [] },
    historyOnly: true, rotate: true, applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
  } as SuggestionWire;
  const { doc } = load({ url: FILES_URL, storage: { "mandu.files.pending": ONE }, routes: { ...FILES_ROUTES,
    "GET suggestions": { suggestions: suggestionRows([key], "/home/u", "linux"), count: 1, scan: null },
  } });
  await tick();
  doc.getElementById("suggest-open").click();
  await tick();
  const skip = [...doc.querySelectorAll("#files-pending-list button")].find((b: Doc) => b.getAttribute("aria-label") === "Skip the suggestion for id_rsa");
  assert.ok(skip, "the ticked suggestion waits in the bar");
  skip.focus();
  skip.click();
  assert.equal(doc.querySelectorAll("#files-pending-list li").length, 1, "skipped");
  assert.equal(focused(doc), bar(doc).querySelector("h3"));
});

test("Move them into policy.yaml: the move gives the focus to the Your rules heading; a refused move says why in its box, and its button keeps the focus, described", async () => {
  let moved = false;
  let refuse = true;
  const pageRule = { path: "/home/u/ws/.env", levelClass: "strict", modelOk: false, scope: "exact", pattern: false, bindings: [], source: "user" };
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES,
    "GET secrets": () => ({ panel: { labels: moved ? [{ ...pageRule, source: "policy-file" }] : [pageRule] } }),
    "POST files/move-page-rules": () => (refuse ? { status: 403, body: { error: "Sign in first: open the admin link." } } : (moved = true, { moved: 1, changeId: "pc-000013" })),
  } });
  await tick();
  const box = doc.getElementById("files-move");
  assert.equal(shown(box), true);
  assert.equal(bar(doc).hidden, true, "nothing waits to be saved");
  const move = box.querySelector("button");

  await press(move);
  await tick(30);
  const words = box.querySelector(".ask-error");
  assert.ok(words, "the refusal is said in the move's own box");
  assert.match(words.textContent, /Sign in first/);
  assert.equal(shown(words), true, "where it is seen, not in the hidden Changes to save");
  assert.equal(doc.getElementById("lock-error").textContent, "");
  assert.equal(move.disabled, false, "on again");
  assert.equal(focused(doc), move, "the button pressed");
  assert.equal(move.getAttribute("aria-describedby"), words.id, "described by the refusal's words");

  refuse = false;
  await press(move);
  await tick(30);
  assert.equal(box.hidden, true, "moved: no page rules left");
  assert.match(doc.getElementById("rules-notice").textContent, /Moved 1 rule into policy\.yaml\./);
  assert.equal(focused(doc), heading(doc), "the Your rules heading, never <body>");
});

test("Changes to save: a press made without the focus in the bar, or a focus moved elsewhere meanwhile, moves nothing", async () => {
  const { doc } = waiting(ONE, { applied: true, changeId: "pc-000014", page: 0 });
  await tick();
  const add = doc.getElementById("rules-add");
  add.focus();
  saveBtn(doc).click();
  await tick(30);
  assert.equal(bar(doc).hidden, true, "saved");
  assert.equal(focused(doc), add, "a click with the focus elsewhere leaves it there");

  // A browser that does not focus a clicked button: the focus was nowhere.
  const mouse = waiting(TWO, {});
  await tick();
  dropOf(mouse.doc, "~/ws/notes.md").click();
  mouse.doc.getElementById("files-discard").click();
  assert.equal(mouse.doc.getElementById("files-pending").hidden, true, "dropped and discarded");
  assert.equal(focused(mouse.doc), mouse.doc.body, "a press without the focus takes none");

  const again = waiting(ONE, { applied: true, changeId: "pc-000015", page: 0 });
  await tick();
  const there = again.doc.getElementById("rules-add");
  await press(saveBtn(again.doc), () => there.focus());
  await tick(30);
  assert.equal(again.doc.getElementById("files-pending").hidden, true);
  assert.equal(focused(again.doc), there, "a focus moved meanwhile stays");
});
