/**
 * css-dim-ink — the words the product page marks secondary (`.dim`: a
 * caption, a note, a status line, an empty list, where a label comes from)
 * read as secondary wherever they are (dashboard.md §4.25k *Secondary words
 * read as secondary*). Mandu-new.
 *
 * Until 2026-10-16 app.css had no page-wide `.dim` rule, only scoped ones:
 * a row's (`.row .dim`, `--ink-4`), the first-run card's commands and an
 * answer's outcome (`--ink-3`). So a `.dim` anywhere else drew in its
 * parent's ink, mostly the full `--ink`. A headless Chromium over a real
 * arbiter and dashboard (Rules with Add a rule, Keys Mandu found and every
 * row opened; Approvals with a wide rule change; Home, History, Settings)
 * found these in the full ink: Approvals' wide-change foot (then "This
 * change has no limit on one side.", since 2026-10-19 what the change
 * opens, §4.25 *A wide change says what is open*), Your rules' Patterns and Places captions and its empty line, an
 * opened rule's "Your rule, this file only" and where it came from, Add a
 * rule's "This folder:", Keys Mandu found's not-offered line and empty
 * list, Describe's status. A folder's count of its rules ("5 rules") and
 * the ticked bar's note took `--ink-2` from their parents.
 *
 *   D1  every `.dim` with words on Rules (Your rules with a pattern, a
 *       folder of rules and an opened rule; Add a rule; Keys Mandu found),
 *       Approvals (a wide rule change) and Home, light and dark: in a row
 *       it is `--ink-4`, anywhere else `--ink-3`, the note's ink; never the
 *       full or the second ink. The places the probe found are among them;
 *   D2  the rule is page-wide: a `.dim` put in the page, its top bar, any
 *       of its pages or a card reads `--ink-3`, and anywhere in a row
 *       `--ink-4`, on a wide window and on a phone, so a later line needs
 *       no rule of its own;
 *   D3  every `.dim` reads at least 4.5:1 (WCAG AA) on the ground under
 *       it, in both themes: outside a row (`--ink-3`) and, since the
 *       faintest ink was darkened on 2026-10-17 (§4.25k *The faintest ink
 *       reads too*), a row's own times and counts (`--ink-4`) too.
 *
 * jsdom draws nothing, but it runs the cascade and inherits `color` as a
 * browser does, so a `.dim` no rule names reads its parent's ink here too.
 * Across the real arbiter and dashboard: tests/stack/dim-ink.test.ts.
 * Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { FILES_ROUTES, FILES_URL, PUB, load, tick } from "./home-js-fixtures.js";
import { contrastRatio, perSelector, resolveCssVars, stylesAt } from "./css-flatten.js";
import { modelPickerVM } from "../../../src/view-model/suggestion-model.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
type Theme = "light" | "dark";

/** The product page's own styles, as index.html links them. */
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");

/** The theme's token, as the page resolves it (`--ink-3: #…`). */
function token(name: string, theme: Theme): string {
  const probe = resolveCssVars(`${CSS}\n.token-probe { --probe: var(${name}); }`, theme);
  return /\.token-probe \{ --probe:\s*([^;]+);/.exec(probe)![1]!.trim();
}
/** A color as jsdom computes it (`rgb(…)`), whatever the stylesheet wrote. */
function computedColor(doc: El, value: string): string {
  const p = doc.createElement("i");
  p.style.color = value;
  doc.body.append(p);
  const out = doc.defaultView.getComputedStyle(p).color;
  p.remove();
  return out;
}
/** The page `width` px wide in `theme`, with a sheet holding its styles. */
function styled(doc: El, theme: Theme, width = 1280): void {
  let sheet = doc.getElementById("dim-ink-styles");
  if (!sheet) {
    sheet = doc.createElement("style");
    sheet.id = "dim-ink-styles";
    doc.head.append(sheet);
  }
  sheet.textContent = perSelector(resolveCssVars(stylesAt(CSS, width), theme));
}
/** The four inks of `theme`, as jsdom computes them, by name. */
function inks(doc: El, theme: Theme): Map<string, string> {
  return new Map(["--ink", "--ink-2", "--ink-3", "--ink-4"].map((t) => [computedColor(doc, token(t, theme)), t]));
}
/** Every `.dim` the page draws with words in it. */
const drawn = (doc: El): El[] => ([...doc.querySelectorAll(".dim")] as El[]).filter((e) => !e.closest("[hidden]") && e.textContent.trim());
/** In a row: a row's own times and counts, `.row .dim`. */
const inRow = (e: El): boolean => !!e.parentElement.closest(".row");
const words = (e: El): string => e.textContent.trim().replace(/\s+/g, " ");

const SUGGESTIONS = { suggestions: [], count: 0, scan: null, model: modelPickerVM(false, []) };
/** A file rule row as policy-panel.ts serves it (home-js-explorer.test.ts). */
const lockRow = (path: string, covers: "subtree" | "exact" | "pattern") => ({
  id: `lock:${path}`, kind: "lock", subject: path, effect: "x", reach: null, hits: null, covers, bindings: [], level: "no-model",
  actions: { remove: true, flip: null },
  plain: { subject: path, reach: covers === "pattern" ? "every matching file" : covers === "subtree" ? "and everything inside" : "this file only", effect: "No AI" },
});
/** Your rules with a pattern (the Patterns and Places captions), rules in
 *  ~/ws (a folder that counts them) and one elsewhere. */
const PANEL = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [
  lockRow("**/ws-*/memo/**", "pattern"),
  lockRow("/home/u/ws/.env", "exact"),
  lockRow("/home/u/ws/a", "subtree"),
  lockRow("/home/u/ws/b", "subtree"),
  lockRow("/etc/app.conf", "exact"),
] } };
const WIDE = {
  id: "pp-000001", status: "pending", requester: "Your agent", createdAt: Date.now() - 60_000,
  rows: [[{ kind: "text", text: "Let your agent's programs connect to " }, { kind: "code", text: "*" }]],
  wouldLet: [[{ kind: "text", text: "Your agent's programs could connect to " }, { kind: "code", text: "*:443" }]],
  capped: false, overBroad: true, reason: "probe",
  overBroadWhy: [[{ kind: "text", text: "This lets your agent's programs connect to any address." }]],
};

/** Rules with Keys Mandu found and Add a rule opened, and /etc/app.conf's
 *  row opened. */
async function rulesPage(): Promise<El> {
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET suggestions": SUGGESTIONS, "GET policy/panel": PANEL } });
  await tick();
  doc.getElementById("suggest-open").click();
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  const row = ([...doc.querySelectorAll("#files-tree .row.file-rule")] as El[]).find((r) => /app\.conf/.test(r.textContent));
  assert.ok(row, "Your rules lists /etc/app.conf");
  row.querySelector(".file-more").click();
  await tick();
  assert.ok(doc.querySelector("#files-tree .file-detail"), "its row is opened");
  return doc;
}
/** Approvals with a wide rule change waiting. */
async function approvalsPage(): Promise<El> {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { "GET policy/proposals?status=pending": { proposals: [WIDE] } } });
  await tick();
  assert.ok(doc.querySelector("#approvals-proposals .proposal-confirm"), "the wide change is drawn");
  return doc;
}
async function homePage(): Promise<El> {
  const { doc } = load({});
  await tick();
  return doc;
}

/** The secondary lines the Chromium probe found in the full or second ink,
 *  as these pages draw them. */
const FOUND: Array<[string, RegExp]> = [
  ["Rules", /^apply to every file that matches$/],
  ["Rules", /^a rule inside a folder rule is more specific, so it wins for its own files$/],
  ["Rules", /^\d+ rules$/],
  ["Rules", /^Your rule, this file only$/],
  ["Rules", /^This folder:$/],
  ["Rules", /^Asking a model to suggest rules is not offered yet: it is still being tested\.$/],
  ["Rules", /^No suggestions\. Press Scan for keys/],
  ["Approvals", /^This lets your agent's programs connect to any address\. Type ALLOW if you mean it\.$/],
];

test("D1: every .dim with words reads --ink-4 in a row and --ink-3 anywhere else, never the full or the second ink, light and dark", async () => {
  const pages: Array<[string, El]> = [["Rules", await rulesPage()], ["Approvals", await approvalsPage()], ["Home", await homePage()]];
  for (const theme of ["light", "dark"] as const) {
    const seen: Array<[string, string, string]> = [];
    for (const [name, doc] of pages) {
      styled(doc, theme);
      const ink = inks(doc, theme);
      for (const e of drawn(doc)) {
        const got = ink.get(doc.defaultView.getComputedStyle(e).color) ?? doc.defaultView.getComputedStyle(e).color;
        const want = inRow(e) ? "--ink-4" : "--ink-3";
        assert.equal(got, want, `${theme}, ${name}: "${words(e).slice(0, 60)}" (${e.className}, in ${e.parentElement.className || e.parentElement.id}) reads ${want}`);
        seen.push([name, words(e), got]);
      }
    }
    for (const [page, text] of FOUND) {
      const hit = seen.find(([p, w]) => p === page && text.test(w));
      assert.ok(hit, `${theme}: ${page} draws ${text}`);
      assert.equal(hit[2], "--ink-3", `${theme}: ${page}'s ${text} reads the note's ink`);
    }
    assert.ok(seen.some(([p, , ink]) => p === "Home" && ink === "--ink-4"), `${theme}: a row's times stay the fainter ink`);
  }
});

test("D2: the rule is page-wide: a .dim in any page, the top bar or a card reads --ink-3, and in a row --ink-4, wide and on a phone", async () => {
  const doc = await rulesPage();
  const places = [doc.body, doc.getElementById("top"), doc.getElementById("top-status"), ...doc.querySelectorAll("section[data-page]"), ...doc.querySelectorAll(".card")] as El[];
  assert.ok(places.length >= 10, "the page, its top bar, every page and the cards");
  for (const [theme, width] of [["light", 1280], ["dark", 1280], ["light", 390], ["dark", 390]] as const) {
    styled(doc, theme, width);
    const ink = inks(doc, theme);
    for (const place of places) {
      const line = doc.createElement("span");
      line.className = "dim";
      line.textContent = "a later line";
      // In a row: its own line, and one in a column of it (Home's counts).
      const row = doc.createElement("div");
      row.className = "row";
      const inside = line.cloneNode(true);
      const column = doc.createElement("div");
      column.className = "agent-what";
      const deeper = line.cloneNode(true);
      column.append(deeper);
      row.append(inside, column);
      place.append(line, row);
      const where = place.id || place.className;
      assert.equal(ink.get(doc.defaultView.getComputedStyle(line).color), "--ink-3", `${theme}, ${width}px: a .dim in ${where} reads the note's ink`);
      assert.equal(ink.get(doc.defaultView.getComputedStyle(inside).color), "--ink-4", `${theme}, ${width}px: a .dim in a row of ${where} reads a row's ink`);
      assert.equal(ink.get(doc.defaultView.getComputedStyle(deeper).color), "--ink-4", `${theme}, ${width}px: and in a column of the row`);
      line.remove();
      row.remove();
    }
  }
});

/** The color of the nearest ground under `e`: the first ancestor (or
 *  itself) with a background color of its own, else the page's. */
function groundOf(e: El): string {
  const win = e.ownerDocument.defaultView;
  for (let n = e; n; n = n.parentElement) {
    const bg = win.getComputedStyle(n).backgroundColor;
    if (bg && bg !== "transparent" && !/^rgba\([^)]*,\s*0\)$/.test(bg)) return bg;
  }
  return win.getComputedStyle(e.ownerDocument.body).backgroundColor;
}

test("D3: every .dim, a row's (--ink-4) as well, reads at least 4.5:1 on the ground under it, light and dark", async () => {
  const pages: Array<[string, El]> = [["Rules", await rulesPage()], ["Approvals", await approvalsPage()], ["Home", await homePage()]];
  for (const theme of ["light", "dark"] as const) {
    let checked = 0;
    let rows = 0;
    for (const [name, doc] of pages) {
      styled(doc, theme);
      for (const e of drawn(doc)) {
        const ratio = contrastRatio(doc.defaultView.getComputedStyle(e).color, groundOf(e));
        assert.ok(ratio >= 4.5, `${theme}, ${name}: "${words(e).slice(0, 60)}"${inRow(e) ? " (in a row)" : ""} reads ${ratio.toFixed(2)}:1`);
        checked++;
        if (inRow(e)) rows++;
      }
    }
    assert.ok(checked >= FOUND.length, `${theme}: ${checked} lines checked`);
    assert.ok(rows > 0, `${theme}: a row's times and counts are among them (${rows})`);
  }
});
