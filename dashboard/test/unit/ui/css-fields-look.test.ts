/**
 * css-fields-look — every text box and menu the product page draws has the
 * page's field look (dashboard.md §4.25r *Every field has the page's look*).
 * Mandu-new.
 *
 * Until 2026-10-16 three of them had no look of their own, so the browser
 * drew them: square, with its grey inset border, and a grey box in the dark
 * theme. They were Keys Mandu found's scan box, its "Ask a model too" menu,
 * and the ALLOW box of a wide rule change. A headless Chromium over a real
 * arbiter and dashboard read the other 29 fields on Rules, Settings and
 * Approvals with an 8 px radius (10 for the text area), a 1 px border in the
 * line color, and the page's background or the card's. The scan view's
 * empty status line also kept the browser's 15 px margins inside a flex
 * column, so the list started 50 px under the model line where the view's
 * gap is 10. The line under the menu read "Asking a model to suggest rules:
 * not offered yet: asking a model is still being tested."
 *
 *   E1  every text box, search box, text area and menu in the page, light
 *       and dark: Rules with its rows and Keys Mandu found opened (which
 *       holds every field of the page's markup), and Approvals with a wide
 *       rule change and its ALLOW box. Each has a radius, a 1 px solid
 *       border in the line color, and one of the page's own backgrounds
 *       (a menu that cannot be changed has the held one, --panel-2); the
 *       ALLOW box is as high as the buttons beside it;
 *   E2  the scan box is drawn as Add a rule's filter box beside it on the
 *       page, and the model menus as Settings' choice menu;
 *   E3  the scan box and the ALLOW box show the accent ring when focused,
 *       as Add a rule's boxes do;
 *   E4  the scan view's lines take no margin of their own, so its gap
 *       spaces them;
 *   E5  the not-offered line is one sentence, drawn as the server words
 *       it;
 *   E6  on a phone the menu, now as wide as Settings' (215 px), goes under
 *       "Ask a model too", which stays on one line: the label wraps as a
 *       line of two items and the menu is never wider than it. In Chromium
 *       at 320 px master broke the words over two lines beside a 177 px
 *       menu, and the wider menu alone would have made three and run 4 px
 *       past the card.
 *
 * jsdom draws nothing, and a property no rule sets reads empty, as the
 * browser's own look would. So "the browser draws it" here is "the page's
 * styles set no radius, border or background on it". The Chromium numbers
 * above come from the run's probe. Across the real arbiter and dashboard:
 * tests/stack/fields-look.test.ts. Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { FILES_ROUTES, FILES_URL, PUB, load, tick } from "./home-js-fixtures.js";
import { flattenCss, perSelector, resolveCssVars, stripComments, stylesAt } from "./css-flatten.js";
import { modelPickerVM } from "../../../src/view-model/suggestion-model.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** The product page's own styles, as index.html links them. */
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
/** A field: a text or search box, a text area, a menu. */
const FIELDS = 'input[type="text"], input[type="search"], textarea, select';

/** The theme's token, as the page resolves it (`--line: #…`). */
function token(name: string, theme: "light" | "dark"): string {
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

/** The page at 1280 px in `theme`, with a sheet holding its styles. */
function styled(doc: El, theme: "light" | "dark", width = 1280): void {
  const sheet = doc.createElement("style");
  sheet.textContent = perSelector(resolveCssVars(stylesAt(CSS, width), theme));
  doc.head.append(sheet);
}

const SUGGESTIONS = { suggestions: [], count: 0, scan: null, model: modelPickerVM(false, []) };
const WIDE = {
  id: "pp-000001", status: "pending", requester: "Your agent", createdAt: Date.now() - 60_000,
  rows: [[{ kind: "text", text: "Let your agent's programs connect to " }, { kind: "code", text: "*" }]],
  wouldLet: [[{ kind: "text", text: "Your agent's programs could connect to " }, { kind: "code", text: "*:443" }]],
  capped: false, overBroad: true, reason: "probe",
};

/** Rules with Add a rule's folder and Keys Mandu found opened. */
async function rulesPage(theme: "light" | "dark"): Promise<El> {
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET suggestions": SUGGESTIONS } });
  await tick();
  doc.getElementById("suggest-open").click();
  await tick();
  styled(doc, theme);
  return doc;
}
/** Approvals with a wide rule change waiting: its ALLOW box is drawn. */
async function approvalsPage(theme: "light" | "dark"): Promise<El> {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { "GET policy/proposals?status=pending": { proposals: [WIDE] } } });
  await tick();
  assert.ok(doc.querySelector("#approvals-proposals .proposal-confirm"), "the wide change draws its ALLOW box");
  styled(doc, theme);
  return doc;
}
const nameOf = (f: El): string => f.id || `.${String(f.className).split(" ")[0]}`;

test("E1: every text box and menu on the page has a radius, a 1px border in the line color and the page's background, light and dark", async () => {
  for (const theme of ["light", "dark"] as const) {
    const doc = await rulesPage(theme);
    const wide = await approvalsPage(theme);
    const line = computedColor(doc, token("--line", theme));
    const grounds = new Set(["--bg", "--panel", "--panel-2"].map((t) => computedColor(doc, token(t, theme))));
    const fields = [...doc.querySelectorAll(FIELDS), ...wide.querySelectorAll("#approvals-proposals .proposal-confirm")] as El[];
    const names = fields.map(nameOf);
    for (const must of ["describe-text", "lock-path", "files-filter", "suggest-root", "suggest-model-tier", "suggest-model-own", "model-name", "model-wire", "prompt-exception-kind", "prompt-exception-match", ".proposal-confirm"]) {
      assert.ok(names.includes(must), `${theme}: the page has ${must}`);
    }
    const bare: string[] = [];
    for (const f of fields) {
      const cs = f.ownerDocument.defaultView.getComputedStyle(f);
      const look = { radius: cs.borderRadius, width: cs.borderTopWidth, style: cs.borderTopStyle, color: cs.borderTopColor, ground: cs.backgroundColor };
      const ok = /^(8|10)px$/.test(look.radius) && look.width === "1px" && look.style === "solid" && look.color === line && grounds.has(look.ground);
      if (!ok) bare.push(`${nameOf(f)} ${JSON.stringify(look)}`);
    }
    assert.deepEqual(bare, [], `${theme}: these fields have no look of the page's (the browser would draw them)`);
    const box = wide.querySelector("#approvals-proposals .proposal-confirm");
    const allow = ([...wide.querySelectorAll("#approvals-proposals button")] as El[]).find((b) => b.textContent === "Allow");
    const height = (el: El) => wide.defaultView.getComputedStyle(el).height;
    assert.equal(height(box), height(allow), `${theme}: the ALLOW box is as high as the buttons beside it`);
  }
});

test("E2: the scan box is drawn as Add a rule's filter box, and the model menus as Settings' choice menu", async () => {
  for (const theme of ["light", "dark"] as const) {
    const doc = await rulesPage(theme);
    const win = doc.defaultView;
    const look = (el: El) => {
      const cs = win.getComputedStyle(el);
      return { radius: cs.borderRadius, border: [cs.borderTopWidth, cs.borderTopStyle, cs.borderTopColor].join(" "), ground: cs.backgroundColor, color: cs.color, pad: [cs.paddingLeft, cs.paddingRight].join(" "), height: cs.height };
    };
    assert.deepEqual(look(doc.getElementById("suggest-root")), look(doc.getElementById("files-filter")), `${theme}: the scan box is the filter box's twin`);
    // Settings' choice menu: a prompt filter's action, in its row.
    const row = doc.createElement("div");
    row.className = "row service prompt-kind";
    const menu = doc.createElement("select");
    menu.className = "prompt-action";
    row.append(menu);
    doc.querySelector("#settings-prompt-kinds").append(row);
    for (const id of ["suggest-model-tier", "suggest-model-own"]) assert.deepEqual(look(doc.getElementById(id)), look(menu), `${theme}: ${id} is drawn as Settings' choice menu`);
  }
});

test("E3: the scan box and the ALLOW box show the accent ring when focused, as Add a rule's boxes", () => {
  const rules = flattenCss(stripComments(CSS)).filter((r) => r.media === null);
  const ring = (selector: string) => rules.filter((r) => r.selectors.includes(selector)).map((r) => r.block.replace(/\s+/g, " ").trim());
  const want = ring('.files-tools input[type="search"]:focus');
  assert.equal(want.length, 1, "Add a rule's filter box has one focus rule");
  assert.match(want[0]!, /outline: 2px solid var\(--accent\)/);
  assert.deepEqual(ring('.files-suggest-bar input[type="text"]:focus'), want, "the scan box has the same ring");
  assert.deepEqual(ring(".proposal-confirm:focus"), want, "the ALLOW box has the same ring");
});

test("E4: the scan view's lines take no margin of their own: an empty status line adds no space under the model line", async () => {
  const doc = await rulesPage("light");
  const view = doc.getElementById("files-suggested-view");
  assert.equal(doc.defaultView.getComputedStyle(view).gap, "10px", "the view's gap spaces its lines");
  // A browser gives a paragraph 1em above and below unless a rule says
  // otherwise, and a flex column does not collapse them; jsdom gives it
  // none, so the rules are read: each paragraph that is one of the view's
  // lines is named by a rule that sets its margin to 0.
  const rules = flattenCss(stripComments(CSS)).filter((r) => r.media === null && /(^|;)\s*margin\s*:\s*0\s*(;|$)/.test(r.block.trim()));
  const lines = ([...view.children] as El[]).filter((c) => c.tagName === "P");
  assert.deepEqual(lines.map((p) => p.id), ["suggest-model-status", "suggest-error"], "the view's own lines: the model run's status and the error");
  for (const p of lines) assert.ok(rules.some((r) => r.selectors.some((sel) => p.matches(sel))), `${p.id}: a rule sets its margin to 0`);
  assert.equal(doc.getElementById("suggest-model-status").textContent, "", "the status line is empty until a run says something");
});

test("E5: not offered, the line under the menu is one sentence, as the server words it", async () => {
  const doc = await rulesPage("light");
  const line = doc.getElementById("suggest-model-why").textContent;
  assert.equal(line, "Asking a model to suggest rules is not offered yet: it is still being tested.");
  assert.equal(line, modelPickerVM(false, []).hint, "the page draws the server's words");
  assert.equal((line.match(/:/g) ?? []).length, 1, "one colon: no sentence inside a sentence");
});

test("E6: on a phone the model menu goes under \"Ask a model too\", which stays on one line, and is never wider than its line", async () => {
  for (const width of [1280, 390, 320]) {
    const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET suggestions": SUGGESTIONS } });
    await tick();
    doc.getElementById("suggest-open").click();
    await tick();
    styled(doc, "light", width);
    const win = doc.defaultView;
    const label = doc.querySelector(".suggest-model .suggest-model-pick");
    assert.equal(label.firstChild.textContent.trim(), "Ask a model too", "the label's words come first");
    assert.ok(label.contains(doc.getElementById("suggest-model-tier")), "the menu is inside its label");
    const cs = win.getComputedStyle(label);
    assert.deepEqual([cs.display, cs.flexWrap, cs.maxWidth], ["inline-flex", "wrap", "100%"], `${width}px: the words and the menu wrap as two items, never inside the words`);
    assert.equal(win.getComputedStyle(doc.getElementById("suggest-model-tier")).maxWidth, "100%", `${width}px: the menu is never wider than its line`);
  }
});
