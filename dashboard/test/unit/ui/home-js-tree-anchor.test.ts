/**
 * home-js-tree-anchor.test — on the product page's Rules, a label chosen in
 * Your rules keeps its menu on screen (dashboard.md §4.25n *A label chosen
 * keeps its menu on screen*).
 *
 * Every choice in the tree (a label, where it may be sent, ⋯, Remove my
 * rule, Update) draws the tree again from nothing (home.js renderLabeled:
 * `clear(host)`, then every row anew). On a phone the tree is longer than
 * the window, and Chrome's scroll anchoring kept its anchor on a node inside
 * it, a node each redraw removes: measured in a headless Chromium at 390×844
 * over a real arbiter with six file rules, a label chosen in the fourth rule
 * moved the page up 360px (400 with a change already waiting) at once, and
 * the menu, which keeps the focus, ended below the window. 1280×800 held.
 * Taking the tree out of anchoring (`overflow-anchor: none`, which leaves
 * out its whole subtree) holds the page still; the bar's own code
 * (trackBarRoom) then lifts the menu above Changes to save. Nothing else is
 * taken out: Sending data's list, drawn again after its answer, keeps its
 * menu in place by anchoring (measured), and so does the rest of the page.
 *
 * jsdom lays out nothing and does not anchor, so this pins the stylesheet
 * rule and the reason for it: each choice draws its control again inside
 * the box the rule names. Drives the PRODUCT page script (public/js/home.js)
 * over the shared fetch stub (home-js-fixtures.ts). Axes: none (display
 * only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { load, tick, FILES_URL, FILES_ROUTES, PUB, menuOf, treeRow } from "./home-js-fixtures.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const fileRule = (path: string, level: string, bindings: string[] = []) => ({
  id: `lock:${path}`, kind: "lock", subject: path, effect: "x", reach: null, hits: null, covers: "exact", bindings, level,
  actions: { remove: true, flip: null },
  plain: { subject: path, reach: "this file only", effect: "x" },
});
const PANEL = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [
  fileRule("/home/u/ws/deploy.token", "no-model"),
  fileRule("/home/u/ws/README.md", "any-model"),
  fileRule("/home/u/ws/notes.md", "no-model", ["api.example.com"]),
  { id: "r-0001", kind: "release-allow", subject: "api.example.com", effect: "sending allowed", reach: "from any source to api.example.com", hits: 2, actions: { remove: true, flip: "block" } },
] } };

function rules() {
  return load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET policy/panel": PANEL } });
}

/** The page's stylesheets, comments dropped, as `selector { body }` rules. */
function rulesOf(file: string): Array<{ sel: string; body: string }> {
  const css = readFileSync(join(PUB, file), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
  return [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({ sel: m[1]!.trim(), body: m[2]!.trim() }));
}
/** Every rule of the product page that sets overflow-anchor. */
const anchorRules = () => [...rulesOf("mandu.css"), ...rulesOf("app.css")].filter((r) => /overflow-anchor/.test(r.body));
/** The rule that takes a box out of scroll anchoring. */
function outOfAnchoring(): string {
  const none = anchorRules().filter((r) => /overflow-anchor:\s*none/.test(r.body));
  assert.equal(none.length, 1, "one rule takes a box out of scroll anchoring");
  return none[0]!.sel;
}

/**
 * Act on `control` and return the box it was drawn in that is still in the
 * page: the old control (and the row it sat in) are gone, drawn again.
 */
async function drawnAgainIn(control: Doc, act: () => void): Promise<Doc> {
  const above: Doc[] = [];
  for (let p = control.parentElement; p; p = p.parentElement) above.push(p);
  act();
  await tick();
  assert.equal(control.isConnected, false, "the control was drawn again from nothing, not changed in place");
  const kept = above.find((p) => p.isConnected);
  assert.ok(kept, "some box it sat in is still in the page");
  return kept;
}
const change = (doc: Doc, sel: Doc, value: string) => {
  sel.value = value;
  sel.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
};

test("the stylesheet takes Your rules' tree, and nothing else, out of scroll anchoring", async () => {
  const all = anchorRules();
  assert.deepEqual(all.map((r) => `${r.sel} { ${r.body.replace(/;$/, "")} }`), [".files-tree { overflow-anchor: none }"],
    "one rule, on the tree: its nodes are replaced at every choice, so an anchor there is always one about to go");
  const { doc, err } = rules();
  assert.equal(err, null);
  await tick();
  const sel = outOfAnchoring();
  assert.deepEqual([...doc.querySelectorAll(sel)].map((x: Doc) => x.id), ["files-tree"], "it names the tree alone");
  // The rest of the page anchors as before: neither the window nor Sending
  // data's list (drawn again after its answer, it keeps its menu in place by
  // anchoring), nor any box around them.
  const list = doc.getElementById("rules-list");
  assert.ok(list.querySelector("select.effect-select"), "Sending data's list has its menu");
  for (let p = list; p; p = p.parentElement) assert.equal(p.matches(sel), false, `${p.tagName}#${p.id} keeps anchoring`);
});

test("a label or a sending choice in a tree row draws its menu again inside the box the stylesheet takes out of anchoring, and the menu keeps the focus", async () => {
  const { doc } = rules();
  await tick();
  const sel = outOfAnchoring();
  const tree = doc.getElementById("files-tree");
  // Which AI may read it.
  const label = menuOf(treeRow(doc, /^README/));
  label.focus();
  const k1 = await drawnAgainIn(label, () => change(doc, label, "no-model"));
  assert.equal(k1, tree, "the tree is the box drawn again");
  assert.equal(k1.matches(sel), true, "and the stylesheet takes it out of anchoring");
  assert.equal(doc.getElementById("files-pending").hidden, false, "the choice waits in Changes to save");
  assert.equal(doc.activeElement, menuOf(treeRow(doc, /^README/)), "the row's menu, drawn again, keeps the focus");
  // Where it may be sent: Not secret.
  const send = treeRow(doc, /^deploy\.token/).querySelector("select.send-select");
  assert.equal(send.disabled, false);
  send.focus();
  const k2 = await drawnAgainIn(send, () => change(doc, send, "public"));
  assert.equal(k2, tree);
  assert.equal(doc.activeElement, treeRow(doc, /^deploy\.token/).querySelector("select.send-select"), "the sending menu, drawn again, keeps the focus");
});

test("⋯, Remove my rule and Update in an opened tree row are drawn again inside the same box", async () => {
  const { doc } = rules();
  await tick();
  const sel = outOfAnchoring();
  const tree = doc.getElementById("files-tree");
  // ⋯ opens the row under it.
  const more = treeRow(doc, /^notes\.md/).querySelector(".file-more");
  more.focus();
  const k1 = await drawnAgainIn(more, () => more.click());
  assert.equal(k1, tree);
  assert.ok(tree.querySelector(".file-detail"), "the row is open");
  // Update, with a host added: the label waits with the new hosts.
  const to = doc.getElementById("lock-to");
  to.value = "api.example.com, b.example.com";
  const update = doc.getElementById("files-to-update");
  assert.ok(update, "Update is offered for a secret label of your own");
  update.focus();
  const k2 = await drawnAgainIn(update, () => update.click());
  assert.equal(k2, tree);
  assert.match(doc.getElementById("files-pending-list").textContent, /notes\.md/);
  // Remove my rule.
  const remove = doc.getElementById("files-unset");
  assert.ok(remove, "Remove my rule is offered");
  remove.focus();
  const k3 = await drawnAgainIn(remove, () => remove.click());
  assert.equal(k3, tree);
  assert.equal(k3.matches(sel), true);
});
