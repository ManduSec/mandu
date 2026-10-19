/**
 * home-js-pending-hosts.test — dashboard.md §4.25u *A waiting change names
 * each host*. Until 2026-10-16 the Rules page said a change waiting to be
 * saved, and what Save asks about, with the hosts as plain text: *Will be:
 * … (not saved)* under a row's name and in the opened row, *Changes to
 * save* (both halves), its *Show the files* rows and Save's two lists.
 * Headless Chromium broke "alerts-" / "eu.example.com" there at 1280 px and
 * "deploy-" / "hooks.example.com" at 720 px, while Approvals and the opened
 * row's *May be sent to* draw each host as its own code, kept whole up to
 * 24 characters. Now:
 *
 *   W1  a change made in the opened row (Update): *Will be* in the row and
 *       in the opened row, and *Changes to save* (the label before and the
 *       one after), draw each host as a code; one of at most 24 characters
 *       in a `.name-fit` that holds the comma after it (never a nowrap
 *       `.code-whole`: these columns can be narrower than 24 characters of
 *       code), a longer one a plain code; the words exactly as before; the page
 *       keeps the label before as its level and hosts, and sends the
 *       server only the change;
 *   W2  a change kept from an older page (no level or hosts before), or
 *       one whose words are not its level and hosts: the label before is
 *       its words, as written;
 *   W3  *Show the files*: each row with parts names each host as a code;
 *       an older server's row (no parts) is its words;
 *   W4  Save's question: a loosening with `detailParts` and each file that
 *       becomes less protected name each host as a code, the words exactly
 *       the detail; a loosening without parts is its words;
 *   W5  data is never markup: a host holding tags is text in a code;
 *   W6  app.css: a `.name-fit` is a box no wider than its line, so its name
 *       wraps inside it only when the column is narrower than the name, and
 *       these lines wrap a long name anywhere.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter and dashboard,
 * tests/stack/rules-pending-hosts-whole.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { PUB, load, tick, treeRow } from "./home-js-fixtures.js";
import { declValue, flattenCss, stripComments } from "./css-flatten.js";

const RULES = "http://127.0.0.1:4500/mandu/rules";
const PATH = "/home/u/ws/app/.env";
const PENDING = "mandu.files.pending";
/** 24 characters and 21 (kept whole), and 29 (past the bound, wraps). */
const HOOKS = "deploy-hooks.example.com";
const ALERTS = "alerts-eu.example.com";
const S3 = "s3.eu-central-1.amazonaws.com";
const BEFORE = ["api.stripe.com", HOOKS];
const AFTER = [...BEFORE, ALERTS, S3];
const words = (hosts: readonly string[]) => `No AI; may be sent to ${hosts.join(", ")}`;

type Part = { kind: "text" | "code"; text: string };
const t = (text: string): Part => ({ kind: "text", text });
const c = (text: string): Part => ({ kind: "code", text });
const parts = (hosts: readonly string[]): Part[] => [t("No AI; may be sent to "), ...hosts.flatMap((h, i) => (i ? [t(", "), c(h)] : [c(h)]))];

function panelWith(rule: Record<string, unknown>) {
  return { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [{
    kind: "lock", reach: null, hits: null, covers: "exact", level: "no-model", effect: "x",
    actions: { remove: true, flip: null }, ...rule,
  }] } };
}
const PANEL = panelWith({ id: `lock:${PATH}`, subject: PATH, bindings: BEFORE, plain: { subject: PATH, reach: "this file only", effect: words(BEFORE) } });

/** Each code under `node`: its text; one of at most 24 characters is kept
 *  whole in a .name-fit, a longer one is a plain code; none is a nowrap
 *  .code-whole. */
function drawnNames(node: any): string[] {
  return [...node.querySelectorAll("code")].map((x: any) => {
    const short = x.textContent.length <= 24;
    assert.equal(x.className, "", `${x.textContent}: a plain code`);
    assert.equal(x.parentElement.classList.contains("name-fit"), short, `${x.textContent}: ${short ? "kept whole in its .name-fit" : "past the bound, on its own"}`);
    return x.textContent;
  });
}
/** The .name-fit of each short host followed by ", ": the comma is in it. */
function commasHeld(node: any, hosts: readonly string[]): void {
  hosts.forEach((h, i) => {
    if (h.length > 24 || i === hosts.length - 1) return;
    const fit = [...node.querySelectorAll(".name-fit")].find((f: any) => f.querySelector("code").textContent === h) as any;
    assert.equal(fit?.textContent, `${h},`, `${h}: the comma after it is in its box, so it never starts a line`);
  });
}

test("W1: a change made with Update says each host as code in Will be and in Changes to save, short ones kept whole, the words as before", async () => {
  const { doc, calls } = load({ url: RULES, routes: { "GET policy/panel": PANEL, "POST files/impact": { impact: null, page: 0 } } });
  await tick();
  treeRow(doc, /app\/\.env$/).querySelector(".file-more").click();
  await tick();
  const to = doc.getElementById("lock-to");
  assert.equal(to.value, BEFORE.join(", "));
  to.value = AFTER.join(", ");
  doc.getElementById("files-to-update").click();
  await tick();
  const will = `Will be: ${words(AFTER)} (not saved)`;
  const row = treeRow(doc, /app\/\.env$/).querySelector(".file-pending");
  const open = doc.querySelector("#files-tree .file-detail .file-pending");
  for (const [where, line] of [["the row", row], ["the opened row", open]] as const) {
    assert.ok(line, `${where} says what it will be`);
    assert.equal(line.textContent, will, `${where}: the words as before`);
    assert.deepEqual(drawnNames(line), AFTER, `${where}: each host its own code`);
    commasHeld(line, AFTER);
  }
  const li = doc.querySelector("#files-pending-list li");
  assert.equal(li.textContent, `~/ws/app/.env ${words(BEFORE)} → ${words(AFTER)} Drop`, "Changes to save: the words as before");
  assert.deepEqual(drawnNames(li), ["~/ws/app/.env", ...BEFORE, ...AFTER], "the file, the hosts before and after, each a code");
  assert.deepEqual(drawnNames(li.querySelector(".dim")), BEFORE, "the label before names its hosts as code");
  assert.deepEqual(drawnNames(li.querySelector("strong")), AFTER, "the label after names its hosts as code");
  commasHeld(li.querySelector("strong"), AFTER);
  // Kept as the label before was (its level and hosts); sent as the change only.
  const kept = JSON.parse(doc.defaultView.localStorage.getItem(PENDING));
  assert.equal(kept[0].before, words(BEFORE));
  assert.equal(kept[0].beforeLevel, "no-model");
  assert.deepEqual(kept[0].beforeHosts, BEFORE);
  const asked = calls.filter((x) => x.url.endsWith("/api/files/impact")).at(-1)!;
  assert.deepEqual(asked.body, { changes: [{ path: PATH, level: "no-model", bindings: AFTER, recursive: false }], folder: "~" }, "the server gets the change, nothing the page keeps for its words");
});

test("W2: a change kept from an older page, or whose words are not its level and hosts, keeps the label before as written", async () => {
  const old = { path: PATH, display: "~/ws/app/.env", level: "no-model", bindings: AFTER, recursive: false, file: true, before: words(BEFORE), target: null };
  const other = { ...old, path: "/home/u/ws/b.env", display: "~/ws/b.env", before: "No AI", beforeLevel: "no-model", beforeHosts: [HOOKS] };
  const { doc } = load({ url: RULES, storage: { [PENDING]: JSON.stringify([old, other]) }, routes: { "GET policy/panel": PANEL, "POST files/impact": { impact: null, page: 0 } } });
  await tick();
  const [a, b] = [...doc.querySelectorAll("#files-pending-list li")] as any[];
  assert.equal(a.querySelector(".dim").textContent, `${words(BEFORE)} → `);
  assert.equal(a.querySelector(".dim code"), null, "no level kept: the words before as written");
  assert.deepEqual(drawnNames(a.querySelector("strong")), AFTER, "the label after is the change itself: its hosts as code");
  assert.equal(b.querySelector(".dim").textContent, "No AI → ");
  assert.equal(b.querySelector(".dim code"), null, "words that are not its level and hosts: as written");
});

const impactOf = (files: unknown[]) => ({ impact: { scanned: 1, truncated: false, changed: files.length, weaker: files.length, files, decidedBy: {} }, page: 0 });
const ROW = { path: PATH, display: "~/ws/app/.env", before: words(BEFORE), after: words(AFTER), weaker: true };
const NEW_ROW = { ...ROW, beforeParts: parts(BEFORE), afterParts: parts(AFTER) };
const WAITING = JSON.stringify([{ path: PATH, display: "~/ws/app/.env", level: "no-model", bindings: AFTER, recursive: false, file: true, before: words(BEFORE), beforeLevel: "no-model", beforeHosts: BEFORE, target: null }]);

test("W3: Show the files names each host as code; an older server's row is its words", async () => {
  for (const [row, coded] of [[NEW_ROW, true], [ROW, false]] as const) {
    const { doc } = load({ url: RULES, storage: { [PENDING]: WAITING }, routes: { "GET policy/panel": PANEL, "POST files/impact": impactOf([row]) } });
    await tick();
    const li = doc.querySelector("#files-impact .impact-files li");
    assert.ok(li, "the file is listed");
    assert.equal(li.textContent, `~/ws/app/.env ${words(BEFORE)} → ${words(AFTER)}`, "the words as before");
    assert.deepEqual(drawnNames(li), coded ? ["~/ws/app/.env", ...BEFORE, ...AFTER] : ["~/ws/app/.env"], coded ? "each host a code" : "an older server: the words as text");
  }
});

test("W4: Save's question names each host as code in what a change becomes and in the files it reaches; a line without parts is its words", async () => {
  const detail = `Becomes ${words(AFTER)}, which lets more reach an AI or leave this computer than now.`;
  const detailParts = [t("Becomes "), ...parts(AFTER), t(", which lets more reach an AI or leave this computer than now.")];
  const merged = detailParts.reduce<Part[]>((out, p) => { const last = out.at(-1); if (p.kind === "text" && last?.kind === "text") last.text += p.text; else out.push({ ...p }); return out; }, []);
  const { doc } = load({ url: RULES, storage: { [PENDING]: WAITING }, routes: {
    "GET policy/panel": PANEL, "POST files/impact": impactOf([NEW_ROW]),
    "POST files/labels": { applied: false, confirm: true, expected: [`paths\u0000${PATH}`, "page\u0000/home/u/ws/old"], impact: impactOf([NEW_ROW]).impact, loosens: [
      { subject: "~/ws/app/.env", detail, detailParts: merged },
      { subject: "~/ws/old", detail: "Loses its own rule. A folder rule above it, or the built-in secrets, decide there again." },
    ] },
  } });
  await tick();
  doc.getElementById("files-save").click();
  await tick();
  assert.equal(doc.getElementById("files-confirm").hidden, false, "Save asks first");
  const [first, second] = [...doc.querySelectorAll("#files-confirm-list li")] as any[];
  assert.equal(first.textContent, `~/ws/app/.env ${detail}`, "the words exactly the detail");
  assert.deepEqual(drawnNames(first), ["~/ws/app/.env", ...AFTER], "the file and each host its own code");
  commasHeld(first, AFTER);
  const long = [...first.querySelectorAll("code")].find((x: any) => x.textContent === S3) as any;
  assert.equal(long.parentElement, first, "the 29-character host, past the bound, is not in a box");
  assert.equal(second.textContent, "~/ws/old Loses its own rule. A folder rule above it, or the built-in secrets, decide there again.");
  assert.deepEqual(drawnNames(second), ["~/ws/old"], "a line naming no host: its words");
  const file = doc.querySelector("#files-confirm-files li");
  assert.equal(file.textContent, `~/ws/app/.env ${words(BEFORE)} → ${words(AFTER)}`);
  assert.deepEqual(drawnNames(file), ["~/ws/app/.env", ...BEFORE, ...AFTER], "each file that becomes less protected names its hosts as code");
});

test("W5: a host holding tags is drawn as text inside its code, never as markup", async () => {
  const evil = "<img src=x onerror=alert(1)>";
  const waiting = JSON.stringify([{ path: PATH, display: "~/ws/app/.env", level: "no-model", bindings: [evil], recursive: false, file: true, before: words([evil]), beforeLevel: "no-model", beforeHosts: [evil], target: null }]);
  const row = { ...ROW, before: words([evil]), after: words([evil]), beforeParts: parts([evil]), afterParts: parts([evil]) };
  const { doc } = load({ url: RULES, storage: { [PENDING]: waiting }, routes: {
    "GET policy/panel": PANEL, "POST files/impact": impactOf([row]),
    "POST files/labels": { applied: false, confirm: true, expected: ["k"], loosens: [{ subject: "<b>s</b>", detail: `Becomes ${words([evil])}.`, detailParts: [t("Becomes No AI; may be sent to "), c(evil), t(".")] }] },
  } });
  await tick();
  doc.getElementById("files-save").click();
  await tick();
  for (const sel of ["#files-pending-list", "#files-impact", "#files-confirm-list"]) {
    const box = doc.querySelector(sel);
    assert.equal(box.querySelector("img, b"), null, `${sel} holds no markup`);
    assert.ok([...box.querySelectorAll("code")].some((x: any) => x.textContent === evil), `${sel} names the host as text in a code`);
  }
});

test("W6: app.css draws a .name-fit as a box no wider than its line, its name wrapping inside only past the column, and wraps a long name in these lines anywhere", () => {
  const rules = flattenCss(stripComments(readFileSync(join(PUB, "app.css"), "utf8")));
  const own = (sel: string) => rules.filter((r) => r.media === null && r.selectors.includes(sel));
  assert.ok(own(".name-fit").some((r) => declValue(r.block, "display") === "inline-block"), ".name-fit is one box, so the comma in it never starts a line");
  assert.ok(own(".name-fit").some((r) => declValue(r.block, "max-width") === "100%"), ".name-fit is never wider than its line");
  assert.ok(own(".name-fit > code").some((r) => declValue(r.block, "overflow-wrap") === "anywhere"), "a name wider than its column wraps inside the box");
  for (const r of rules.filter((x) => x.selectors.some((sel) => sel.includes("name-fit")))) {
    assert.notEqual(declValue(r.block, "white-space"), "nowrap", "the box keeps a name whole by moving it, never by running past the column");
  }
  for (const sel of [".files-pending-list code", ".file-pending code", ".impact-files code", ".files-confirm code"]) {
    assert.ok(own(sel).some((r) => declValue(r.block, "overflow-wrap") === "anywhere"), `${sel} wraps a long name rather than run past its column`);
  }
  assert.ok(own("code.code-whole").some((r) => declValue(r.block, "white-space") === "nowrap"), "elsewhere code.code-whole stays on one line");
});
