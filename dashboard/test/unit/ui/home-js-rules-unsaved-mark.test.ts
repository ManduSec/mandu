/**
 * home-js-rules-unsaved-mark.test — the top bar's Rules link says, on every
 * page, how many levels chosen on Rules wait to be saved (dashboard.md
 * §4.25n *The top bar says when Rules has changes not saved*).
 *
 * Until 2026-10-25 a level chosen on Rules ("No AI" for `~/shop/.env`)
 * waited in *Changes to save* at the bottom of Rules, kept in this browser
 * across pages and reloads, and nothing outside Rules said so: a person who
 * went Home believed the file protected while the AI still read it as
 * before. Now:
 *
 *   U1  a change kept from before shows "1" in the Rules link on Home at
 *       start, the link named and titled "Rules, 1 change not saved";
 *   U2  choosing a level on Rules shows it, a second "2 changes not saved";
 *       Save changes, answered, hides it and the name goes back to the
 *       link's word;
 *   U3  Discard hides it; so does the last row's Drop (one dropped of two
 *       leaves "1");
 *   U4  Mandu's ticked suggestions alone, which wait in the same bar, show
 *       no mark: they are proposals the person has not acted on;
 *   U5  a refused Save keeps it: nothing was saved.
 *
 * And while Mandu refuses your last edit to policy.yaml (2026-10-27, #215;
 * dashboard.md §4.25 *An edit to policy.yaml Mandu refused*, *The top bar
 * says so on every page*), the same slot shows "!" in a warn ring:
 *
 *   U6  a Home answer with `policyFile: { valid: false, path }`, drawn on
 *       Approvals, shows "!" (class `refused`), the link named and titled
 *       "Rules, Mandu did not take your last edit to policy.yaml";
 *   U7  a later answer with the file valid hides it, so does one with no
 *       `policyFile` or no path; a failed poll keeps it as drawn; the same
 *       answer leaves it as drawn (sameAsDrawn);
 *   U8  with 2 levels waiting the slot shows "!" and the name says both;
 *       once the file is valid again the slot is "2" with #106's name; a
 *       change kept or chosen meanwhile keeps the refusal in the slot;
 *   U9  the name never holds a problem's words or the file's text, even
 *       on Rules, whose refused line lists the problems.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub (home-js-fixtures.ts). Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick, FILES_URL, FILES_ROUTES, RULES_PANEL, dot } from "./home-js-fixtures.js";
import { suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const change = (name: string, level: string) => ({
  path: `/home/u/ws/${name}`, display: `~/ws/${name}`, level, bindings: [], recursive: false, before: "Like any other file", target: null,
});
const ONE = JSON.stringify([change("notes.md", "no-model")]);
const TWO = JSON.stringify([change("notes.md", "no-model"), change("todo.md", "no-model")]);

/** The Rules link's mark as the page draws it: its text, or null while hidden,
 *  and the link's accessible name and title (null: none of its own). */
function mark(doc: Doc): { text: string | null; name: string | null; title: string | null } {
  const m = doc.getElementById("nav-rules-unsaved");
  const link = m.parentElement;
  assert.equal(link.getAttribute("data-page-link"), "rules", "the mark sits in the Rules link");
  return { text: m.hidden ? null : m.textContent, name: link.getAttribute("aria-label"), title: link.getAttribute("title") };
}
const NONE = { text: null, name: null, title: null };
const said = (k: number) => {
  const words = `Rules, ${k} ${k === 1 ? "change" : "changes"} not saved`;
  return { text: String(k), name: words, title: words };
};
const dropOf = (doc: Doc, display: string) => [...doc.querySelectorAll("#files-pending-list button")].find((b: Doc) => b.getAttribute("aria-label") === `Drop the change to ${display}`);

test("U1: a change kept from before shows on Home at start: \"Rules 1\", named \"Rules, 1 change not saved\"", async () => {
  const { doc, err } = load({ storage: { "mandu.files.pending": ONE } });
  assert.equal(err, null);
  await tick();
  assert.equal(doc.querySelector('#nav a[aria-current="page"]').getAttribute("data-page-link"), "home", "on Home");
  assert.deepEqual(mark(doc), said(1));
  assert.equal(doc.getElementById("nav-rules-unsaved").className, "unsaved-mark");
  // Nothing kept: no mark, and the link is named by its word.
  const none = load({});
  await tick();
  assert.deepEqual(mark(none.doc), NONE);
  // A damaged entry starts empty, and shows nothing.
  const bad = load({ storage: { "mandu.files.pending": "{not json" } });
  await tick();
  assert.deepEqual(mark(bad.doc), NONE);
});

test("U2: choosing a level on Rules shows the mark; a second makes it 2; Save changes, answered, hides it", async () => {
  const saves: Doc[] = [];
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES,
    "POST files/labels": (b: Doc) => (saves.push(b), { applied: true, changeId: "pc-000021", page: 0 }),
  } });
  await tick();
  assert.deepEqual(mark(doc), NONE);
  doc.getElementById("rules-add").click();
  await tick();
  dot(doc, /README/, "no-model");
  assert.deepEqual(mark(doc), said(1), "one level chosen");
  dot(doc, /^\.env/, "any-model");
  assert.deepEqual(mark(doc), said(2), "two");
  // The same file chosen again is still one change.
  dot(doc, /README/, "local-model");
  assert.deepEqual(mark(doc), said(2));
  doc.getElementById("files-save").click();
  await tick(30);
  assert.equal(saves.length, 1, "saved");
  assert.equal(doc.getElementById("files-pending").hidden, true);
  assert.deepEqual(mark(doc), NONE, "saved: nothing waits");
});

test("U3: Discard hides the mark; Drop of one of two leaves 1, the last Drop hides it", async () => {
  const discard = load({ url: FILES_URL, storage: { "mandu.files.pending": TWO }, routes: FILES_ROUTES });
  await tick();
  assert.deepEqual(mark(discard.doc), said(2));
  discard.doc.getElementById("files-discard").click();
  await tick();
  assert.deepEqual(mark(discard.doc), NONE, "discarded");

  const { doc } = load({ url: FILES_URL, storage: { "mandu.files.pending": TWO }, routes: FILES_ROUTES });
  await tick();
  dropOf(doc, "~/ws/notes.md").click();
  await tick();
  assert.deepEqual(mark(doc), said(1), "one dropped of two");
  dropOf(doc, "~/ws/todo.md").click();
  await tick();
  assert.deepEqual(mark(doc), NONE, "the last dropped");
});

test("U4: Mandu's ticked suggestions alone wait in the bar but show no mark", async () => {
  const wire: SuggestionWire = {
    id: "pp-000001", kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: "k-1", source: "git-history", repoRoot: "/home/u/proj",
    edits: [{ op: "lock-path", path: "/home/u/proj/deploy/id_rsa", level: "no-model" }],
    sentence: "Make ~/proj/deploy/id_rsa a secret no AI may read",
    evidence: { paths: ["deploy/id_rsa"], blobs: ["a".repeat(40)], historyOnly: false,
      findings: [{ blob: "a".repeat(40), paths: ["deploy/id_rsa"], firstCommit: "1111111", lastCommit: "2222222", inHead: true, inIndex: true, stillPresent: true,
        detectors: [{ kind: "content-shape", rule: "private-key", mask: "(key block header)…", words: "private key", line: 1 }] }] },
    impact: { historicalVersions: 0, workingTreeChanges: false, files: [] },
    historyOnly: false, rotate: true, applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
  } as SuggestionWire;
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET suggestions": { suggestions: suggestionRows([wire], "/home/u", "linux"), count: 1, scan: null } } });
  await tick();
  doc.getElementById("suggest-open").click();
  await tick();
  assert.equal(doc.getElementById("files-pending").hidden, false, "the suggestion waits in Changes to save");
  assert.equal(doc.getElementById("files-pending-count").textContent, "1");
  assert.deepEqual(mark(doc), NONE, "but it is no change the person chose");
  // A level chosen beside it counts alone.
  doc.getElementById("rules-add").click();
  await tick();
  dot(doc, /README/, "no-model");
  assert.equal(doc.getElementById("files-pending-count").textContent, "2");
  assert.deepEqual(mark(doc), said(1));
});

test("U5: a refused Save keeps the mark: nothing was saved", async () => {
  const { doc } = load({ url: FILES_URL, storage: { "mandu.files.pending": ONE }, routes: { ...FILES_ROUTES,
    "POST files/labels": { status: 403, body: { error: "Sign in first: open the admin link." } },
  } });
  await tick();
  doc.getElementById("files-save").click();
  await tick(30);
  assert.match(doc.getElementById("lock-error").textContent, /Sign in first/);
  assert.deepEqual(mark(doc), said(1));
});

// ── policy.yaml refused (#215) ────────────────────────────────────────────────

const POLICY_PATH = "/home/u/.mandu/policy.yaml";
const REFUSED = { valid: false, path: POLICY_PATH, problemCount: 2, refusedAt: Date.now() - 60_000 };
const VALID = { valid: true, path: POLICY_PATH, problemCount: 0, refusedAt: null };
const REFUSED_WORDS = "Rules, Mandu did not take your last edit to policy.yaml";
const REFUSED_MARK = { text: "!", name: REFUSED_WORDS, title: REFUSED_WORDS };
const APPROVALS_URL = "http://127.0.0.1:4500/mandu/approvals";
const cls = (doc: Doc) => doc.getElementById("nav-rules-unsaved").className;

/** A page whose Home answer the test sets (`vm`), or fails (`fail`). */
function polled(opts: { url?: string; storage?: Record<string, string>; routes?: Record<string, unknown> } = {}) {
  const state: { vm: unknown; fail: boolean } = { vm: home({ policyFile: REFUSED }), fail: false };
  const page = load({ url: opts.url ?? APPROVALS_URL, storage: opts.storage, routes: { ...opts.routes, "GET home": () => (state.fail ? { status: 500, body: {} } : state.vm) } });
  const poll = async () => { page.doc.dispatchEvent(new page.window.Event("visibilitychange")); await tick(); };
  return { ...page, state, poll };
}

test("U6: a refused policy.yaml shows \"!\" in the Rules link on Approvals, named \"Rules, Mandu did not take your last edit to policy.yaml\"", async () => {
  const { doc, err } = polled();
  assert.equal(err, null);
  await tick();
  assert.equal(doc.querySelector('#nav a[aria-current="page"]').getAttribute("data-page-link"), "approvals", "on Approvals");
  assert.deepEqual(mark(doc), REFUSED_MARK);
  assert.equal(cls(doc), "unsaved-mark refused", "the warn ring's own class");
  // Home's card follows the same condition (on Home, where it is drawn).
  const onHome = load({ homeVm: home({ policyFile: REFUSED }) });
  await tick();
  assert.equal(onHome.doc.getElementById("home-policy-refused").hidden, false);
  assert.deepEqual(mark(onHome.doc), REFUSED_MARK, "and the mark on Home too");
});

test("U7: a valid file hides the mark, so does an answer with no policyFile or no path; a failed poll keeps it; the same answer leaves it as drawn", async () => {
  const { doc, state, poll } = polled();
  await tick();
  assert.deepEqual(mark(doc), REFUSED_MARK);
  const drawnText = doc.getElementById("nav-rules-unsaved").firstChild;
  state.vm = home({ policyFile: { ...REFUSED } });
  await poll();
  assert.equal(doc.getElementById("nav-rules-unsaved").firstChild, drawnText, "the same answer: left as drawn (sameAsDrawn)");
  state.fail = true;
  await poll();
  assert.equal(doc.getElementById("top-status").textContent.includes("Not connected"), true, "the poll failed");
  assert.deepEqual(mark(doc), REFUSED_MARK, "a failed poll says nothing about the file: the mark stays");
  state.fail = false;
  state.vm = home({ policyFile: VALID });
  await poll();
  assert.deepEqual(mark(doc), NONE, "valid: gone");
  assert.equal(cls(doc), "unsaved-mark", "and the warn ring's class with it");
  for (const policyFile of [undefined, null, { ...REFUSED, path: "" }, { ...REFUSED, valid: "false" }]) {
    state.vm = home({ policyFile: REFUSED });
    await poll();
    assert.deepEqual(mark(doc), REFUSED_MARK, "refused again: it comes back");
    state.vm = home({ policyFile });
    await poll();
    assert.deepEqual(mark(doc), NONE, `${JSON.stringify(policyFile)}: no named file refused, no mark`);
  }
});

test("U8: with 2 levels waiting and the file refused the slot shows \"!\" and the name says both; valid again, the slot is \"2\" with #106's name", async () => {
  const both = `${REFUSED_WORDS}, 2 changes not saved`;
  const { doc, state, poll } = polled({ storage: { "mandu.files.pending": TWO } });
  await tick();
  assert.deepEqual(mark(doc), { text: "!", name: both, title: both }, "the refusal wins the slot; the name says both");
  assert.equal(cls(doc), "unsaved-mark refused");
  state.vm = home({ policyFile: VALID });
  await poll();
  assert.deepEqual(mark(doc), said(2), "valid again: the count and its own name");
  assert.equal(cls(doc), "unsaved-mark");
  state.vm = home({ policyFile: REFUSED });
  await poll();
  assert.deepEqual(mark(doc), { text: "!", name: both, title: both });

  // On Rules: a change chosen while the file is refused keeps "!" in the
  // slot (the list's own redraw keeps the last answer's word), the name counts it.
  const rules = polled({ url: FILES_URL, routes: FILES_ROUTES });
  await tick();
  assert.deepEqual(mark(rules.doc), REFUSED_MARK);
  rules.doc.getElementById("rules-add").click();
  await tick();
  dot(rules.doc, /README/, "no-model");
  const one = `${REFUSED_WORDS}, 1 change not saved`;
  assert.deepEqual(mark(rules.doc), { text: "!", name: one, title: one });
  rules.doc.getElementById("files-discard").click();
  await tick();
  assert.deepEqual(mark(rules.doc), REFUSED_MARK, "discarded: the refusal alone");
});

test("U9: the link's name never holds a problem's words or the file's text, even on Rules, whose refused line lists them", async () => {
  const problem = 'paths[0].level: unknown level "no-modle"';
  const panel = { panel: { ...RULES_PANEL.panel, policyFile: { path: POLICY_PATH, found: true, valid: false, problems: [problem], loadedAt: REFUSED.refusedAt - 60_000, refusedAt: REFUSED.refusedAt } } };
  const { doc } = polled({ url: FILES_URL, storage: { "mandu.files.pending": ONE }, routes: { ...FILES_ROUTES, "GET policy/panel": panel } });
  await tick(30);
  assert.match(doc.getElementById("rules-refused").textContent, /no-modle/, "Rules' refused line lists the problem");
  const words = `${REFUSED_WORDS}, 1 change not saved`;
  assert.deepEqual(mark(doc), { text: "!", name: words, title: words });
  const link = doc.getElementById("nav-rules-unsaved").parentElement;
  for (const said of [link.getAttribute("aria-label"), link.getAttribute("title"), link.textContent]) {
    assert.ok(!said.includes("no-modle") && !said.includes("paths[0]"), `no problem's words: ${said}`);
    assert.ok(!said.includes(POLICY_PATH) && !said.includes("~/.mandu"), `no path: ${said}`);
  }
});
