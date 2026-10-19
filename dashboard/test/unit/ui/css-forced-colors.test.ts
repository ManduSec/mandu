/**
 * css-forced-colors — under a forced palette (Windows' contrast themes, a
 * browser's own colors) the product page still draws its Protection switch,
 * its current page and its picked tab, and the inspector every picked thing
 * (dashboard.md §4.25k *Forced colors*). Mandu-new.
 *
 * In forced-colors mode the browser draws every color a page sets in the
 * person's palette and keeps only system colors (`Canvas`, `ButtonText`,
 * `Highlight`, …); a fill it draws in the page's own color. Until
 * 2026-10-14 neither stylesheet had a forced-colors rule, and a headless
 * Chromium with the mode emulated drew:
 *   - Settings › Protection's on/off switch not at all (the track and its
 *     knob are fills: both became the page's color), on or off;
 *   - Rules › Who may get your secrets' three tabs alike (each tab's
 *     `transparent` edge was drawn in the text color, the picked one's too);
 *   - the top bar's current page by its weight alone (its fill was gone).
 * Now app.css draws each in system colors inside `@media (forced-colors:
 * active)`: the switch an outlined track with its knob, filled in
 * `Highlight` when on; the picked tab alone has an edge, in `Highlight`;
 * the current page is underlined in `Highlight`. Words are never set on a
 * `Highlight` fill: the browser draws the page's color behind every word
 * (the probe's first try, a filled current page, lost its word).
 *
 * The inspector (dev/dashboard.css) drew each picked thing by its fill:
 * the same Chromium found its current page, picked session tab, Files tab,
 * Replay | Live and Runs | Matrix segment marked by their weight alone, and
 * the open session, the picked step and the picked row of the Rules,
 * Settings and Tests menus drawn exactly as the others (Runs | Matrix is
 * Drills' menu since 2026-10-16, a row list edged like Tests') (every one's
 * `transparent` edge was drawn). Now the picked one is underlined in
 * `Highlight` where it has no edge of its own (or one its group shares),
 * else it alone has an edge, in `Highlight`, the others' in `Canvas`.
 *
 * jsdom applies no media query and forces nothing, so this unwraps the
 * forced block (css-flatten `stylesAt(…, { forcedColors: true })`) and
 * forces the sheet's other colors as a browser does (`forcedColorsModel`),
 * then reads what is drawn. The browser itself is the run's Chromium probe.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

import { PUB } from "./home-js-fixtures.js";
import { devPagesDir, NO_DEV_PAGES } from "./dev-pages.js";
import { declValue, flattenCss, forcedColorsModel, isSystemColor, perSelector, resolveCssVars, splitValue, stripComments, stylesAt } from "./css-flatten.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** The developer view's pages; null in a tree without them (dev-pages.ts). */
const DEV = devPagesDir();
/** A developer-view file's text, empty without the developer view. */
const readDev = (file: string): string => (DEV ? readFileSync(join(DEV, file), "utf8") : "");
const read = (dir: string, file: string): string => readFileSync(join(dir, file), "utf8");
const PRODUCT_CSS = `${read(PUB, "mandu.css")}\n${read(PUB, "app.css")}`;
const INSPECTOR_CSS = `${read(PUB, "mandu.css")}\n${readDev("dashboard.css")}`;
const SHEETS: Array<[string, string]> = [["mandu.css", read(PUB, "mandu.css")], ["app.css", read(PUB, "app.css")], ...(DEV ? [["dev/dashboard.css", readDev("dashboard.css")] as [string, string]] : [])];
const FORCED = /\(forced-colors:\s*active\)/;
const isForced = (media: string | null): boolean => !!media && FORCED.test(media);
/** A selector that draws a control's state: checked, picked, current, pressed. */
const STATE = /\[aria-(checked|selected|current|pressed)\b|\.selected\b|:checked\b/;
/** The properties whose colors a forced palette replaces. */
const COLOR_PROP = /^(color|background(-color)?|border(-(top|right|bottom|left))?(-color)?|border-color|outline(-color)?|text-decoration(-color)?|fill|stroke|box-shadow)$/;
/** The inspector marks a picked thing with a class too: `.active` (a
 *  session, a step, a Files tab, a commit, a segment) and `.sel`. */
const DEV_STATE = new RegExp(`${STATE.source}|\\.(active|sel)\\b`);
/** The state rules of app.css that need no forced-colors rule, and why. */
const DRAWN_ELSEWHERE: Record<string, string> = {
  ".row.file.selected": "the row's own checkbox is ticked, and the browser draws a checkbox in the palette",
};

/** The product page's static markup with its styles as a browser applies
 *  them at `width` px: under a forced palette (the model), or not. */
function productPage(width: number, forced: boolean): { doc: El; win: El; close: () => void } {
  const dom = new JSDOM(read(PUB, "index.html"));
  const doc = dom.window.document;
  const css = resolveCssVars(stylesAt(PRODUCT_CSS, width, { forcedColors: forced }));
  const sheet = doc.createElement("style");
  sheet.textContent = forced ? forcedColorsModel(css) : css;
  doc.head.append(sheet);
  return { doc, win: dom.window, close: () => dom.window.close() };
}

/** What jsdom computes for a system color (its own fixed palette). */
function sys(win: El, name: string): string {
  const probe = win.document.createElement("i");
  probe.style.color = name;
  win.document.body.append(probe);
  const v = win.getComputedStyle(probe).color as string;
  probe.remove();
  return v;
}

/** The colors a declared value names (the words a forced palette replaces). */
const colorWords = (value: string): string[] => splitValue(value).filter((w) =>
  isSystemColor(w) || /^(#[0-9a-f]{3,8}|(rgba?|hsla?|color-mix)\(.*\)|var\(.*\)|transparent|white|black)$/i.test(w));

test("app.css: every state drawn by a color has a forced-colors rule of its own", () => {
  const rules = flattenCss(stripComments(read(PUB, "app.css")));
  const forcedSels = new Set(rules.filter((r) => isForced(r.media)).flatMap((r) => r.selectors));
  const needs = rules.filter((r) => !isForced(r.media)).flatMap((r) => {
    const colored = r.block.split(";").some((d) => COLOR_PROP.test(d.split(":")[0]!.trim().toLowerCase()));
    return colored ? r.selectors.filter((s) => STATE.test(s)) : [];
  });
  // Not vacuous: the switch, the picked tab and the current page are found.
  for (const sel of ['.switch[aria-checked="true"]', '.by-who-tabs [role="tab"][aria-selected="true"]', '#nav a[aria-current="page"]']) {
    assert.ok(needs.includes(sel), `the sweep finds ${sel}`);
  }
  for (const sel of new Set(needs)) {
    if (DRAWN_ELSEWHERE[sel]) continue;
    assert.ok(forcedSels.has(sel), `${sel} draws its state with a color, which a forced palette replaces: it needs a rule in @media (forced-colors: active)`);
  }
  for (const sel of Object.keys(DRAWN_ELSEWHERE)) assert.ok(needs.includes(sel), `the exception ${sel} still exists`);
});

test("a forced-colors block holds only system colors, and no other rule uses one", () => {
  let forcedRules = 0;
  for (const [sheet, css] of SHEETS) {
    for (const r of flattenCss(stripComments(css))) {
      for (const decl of r.block.split(";")) {
        const colon = decl.indexOf(":");
        if (colon === -1) continue;
        const prop = decl.slice(0, colon).trim().toLowerCase();
        const words = colorWords(decl.slice(colon + 1));
        if (isForced(r.media) && COLOR_PROP.test(prop)) {
          for (const w of words) assert.ok(isSystemColor(w), `${sheet} ${r.selectors.join(", ")} { ${prop} }: "${w}" is not a system color, and a forced palette replaces it`);
        }
        if (!isForced(r.media)) {
          for (const w of words) assert.ok(!isSystemColor(w), `${sheet} ${r.selectors.join(", ")} { ${prop} }: the system color ${w} outside a forced-colors block draws the OS palette in a themed page`);
        }
      }
      if (isForced(r.media)) forcedRules += 1;
    }
  }
  assert.ok(forcedRules >= 7, "the product page's forced-colors rules are found");
});

test("a selection-color fill never holds words: the browser draws the page's color behind each word", () => {
  let fills = 0;
  for (const [dir, sheet] of [[PUB, "app.css"], ...(DEV ? [[DEV, "dashboard.css"]] : [])] as Array<[string, string]>) {
    const dom = new JSDOM(read(dir, "index.html"));
    const doc = dom.window.document;
    for (const r of flattenCss(stripComments(read(dir, sheet))).filter((x) => isForced(x.media))) {
      const fill = declValue(r.block, "background") ?? declValue(r.block, "background-color");
      if (!fill || !/^(highlight|selecteditem|accentcolor|mark)$/.test(fill)) continue;
      for (const sel of r.selectors) {
        // Each element that can take this state, whatever state it has now.
        const els = [...doc.querySelectorAll(sel.replace(/\[[^\]]*\]/g, ""))] as El[];
        assert.ok(els.length > 0, `${sheet} ${sel} matches the page's markup`);
        for (const el of els) assert.equal(el.textContent.trim(), "", `${sheet} ${sel} is filled with ${fill}: it must hold no words`);
        fills += 1;
      }
    }
    dom.window.close();
  }
  assert.ok(fills >= 1, "the switch's fill is found");
});

test("forced colors: the Protection switch is drawn, off and on, and its knob stays where it is", () => {
  for (const width of [1280, 390]) {
    const { doc, win, close } = productPage(width, true);
    const sw = doc.getElementById("switch-protection");
    const knob = sw.querySelector(".knob");
    const look = (checked: boolean): Record<string, string> => {
      sw.setAttribute("aria-checked", String(checked));
      const s = win.getComputedStyle(sw);
      const k = win.getComputedStyle(knob);
      return { edge: `${s.borderTopWidth} ${s.borderTopStyle} ${s.borderTopColor}`, fill: s.backgroundColor, knob: k.backgroundColor, top: k.top, left: k.left };
    };
    const off = look(false);
    const on = look(true);
    const canvas = sys(win, "Canvas");
    assert.deepEqual(off, { edge: `1px solid ${sys(win, "ButtonText")}`, fill: sys(win, "ButtonFace"), knob: sys(win, "ButtonText"), top: "2px", left: "2px" }, `${width} px, off: an outlined track, its knob on the left`);
    assert.deepEqual(on, { edge: `1px solid ${sys(win, "Highlight")}`, fill: sys(win, "Highlight"), knob: sys(win, "HighlightText"), top: "2px", left: "20px" }, `${width} px, on: filled in the selection color, its knob on the right`);
    assert.notEqual(on.fill, canvas, "on is a fill the page does not have");
    assert.notEqual(off.knob, off.fill, "off: the knob is seen on its track");
    assert.notEqual(on.knob, on.fill, "on: the knob is seen on its track");
    // Held or turned off, it is dimmed as it is without forced colors.
    sw.setAttribute("aria-disabled", "true");
    assert.equal(win.getComputedStyle(sw).opacity, "0.5", "a held switch is dimmed");
    close();
  }
  // The knob's pixels are the same without forced colors: its offsets there
  // are the forced ones plus the forced 1px edge.
  const { doc, win, close } = productPage(1280, false);
  const sw = doc.getElementById("switch-protection");
  const knob = sw.querySelector(".knob");
  assert.equal(win.getComputedStyle(sw).borderTopStyle, "none", "without forced colors the switch has no edge, as before");
  for (const [checked, left] of [[false, "3px"], [true, "21px"]] as const) {
    sw.setAttribute("aria-checked", String(checked));
    assert.deepEqual([win.getComputedStyle(knob).top, win.getComputedStyle(knob).left], ["3px", left], `without forced colors, ${checked ? "on" : "off"}: the knob as before`);
  }
  close();
});

test("forced colors: only the picked tab of Who may get your secrets has an edge, and every tab keeps its height", () => {
  for (const width of [1280, 390]) {
    const { doc, win, close } = productPage(width, true);
    const tabs = [...doc.querySelectorAll('.by-who-tabs [role="tab"]')] as El[];
    assert.equal(tabs.length, 3);
    const plain = productPage(width, false);
    const height = (w: El, el: El): number => {
      const s = w.getComputedStyle(el);
      return parseFloat(s.paddingBottom) + (s.borderBottomStyle === "none" ? 0 : parseFloat(s.borderBottomWidth));
    };
    const plainTab = plain.doc.querySelector('.by-who-tabs [role="tab"]');
    for (const picked of tabs) {
      for (const t of tabs) t.setAttribute("aria-selected", String(t === picked));
      for (const t of tabs) {
        const s = win.getComputedStyle(t);
        const edge = s.borderBottomStyle !== "none" && parseFloat(s.borderBottomWidth) > 0 && s.borderBottomColor !== sys(win, "Canvas");
        assert.equal(edge, t === picked, `${width} px, ${picked.id} picked: ${t.id} ${t === picked ? "has" : "has no"} edge`);
        if (t === picked) assert.equal(s.borderBottomColor, sys(win, "Highlight"), "the picked tab's edge is the selection color");
        assert.equal(height(win, t), height(plain.win, plainTab), `${width} px: ${t.id} keeps its height (padding and edge)`);
      }
    }
    plain.close();
    close();
  }
});

test("forced colors: the top bar's current page is underlined in the selection color, the others are not", () => {
  const { doc, win, close } = productPage(1280, true);
  const links = [...doc.querySelectorAll("#nav a")] as El[];
  assert.equal(links.length, 5, "Home, Approvals, Rules, Settings and History");
  for (const current of links) {
    for (const a of links) {
      if (a === current) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
    for (const a of links) {
      const s = win.getComputedStyle(a);
      if (a === current) {
        assert.equal(s.textDecorationLine, "underline", `${a.textContent.trim()} is the current page: underlined`);
        assert.equal(s.textDecorationColor, sys(win, "Highlight"));
        assert.equal(s.textDecorationThickness, "2px");
      } else {
        assert.notEqual(s.textDecorationLine, "underline", `${a.textContent.trim()} is not the current page`);
      }
      assert.ok([sys(win, "Canvas"), "rgba(0, 0, 0, 0)"].includes(s.backgroundColor), `${a.textContent.trim()}: its words sit on the page's color`);
    }
  }
  close();
});

// ── The inspector (dev/dashboard.css) ────────────────────────────────────────

/** The inspector's state rules that need no forced-colors rule, and why. */
const DEV_DRAWN_ELSEWHERE: Record<string, string> = {
  ".sys-entry.sel": "the system log's entry of the step picked in the rail: an outline, which the browser keeps (in the palette's text color), and no other entry has one",
  ".pr-row.sel": "the trace's row of the step picked in the rail: an outline around its cells, which the browser keeps, and no other row has one",
};

/** A selector up to the compound that holds its state
 *  (`.session.active .s-label` → `.session.active`). */
function statePart(sel: string, state: RegExp): string {
  const parts = sel.trim().split(/\s+/);
  return parts.slice(0, parts.findIndex((p) => state.test(p)) + 1).join(" ");
}

test("dev/dashboard.css: every picked state drawn by a color has a forced-colors rule of its own", { skip: NO_DEV_PAGES }, () => {
  const rules = flattenCss(stripComments(readDev("dashboard.css")));
  const forcedSels = rules.filter((r) => isForced(r.media)).flatMap((r) => r.selectors);
  const needs = new Set(rules.filter((r) => !isForced(r.media)).flatMap((r) => {
    const colored = r.block.split(";").some((d) => COLOR_PROP.test(d.split(":")[0]!.trim().toLowerCase()));
    return colored ? r.selectors.filter((s) => DEV_STATE.test(s)).map((s) => statePart(s, DEV_STATE)) : [];
  }));
  // Not vacuous: each picked state the Chromium survey found is swept.
  for (const sel of ['.page-nav a[aria-current="page"]', ".session.active", ".tc-item.active", ".git-tab.active", ".git-commit.active",
    ".seg-switch [data-kind].active", ".sub-menu a[aria-current]", ".sub-nav a[aria-current=\"page\"]", ".git-scope-btn.active",
    '.session-tabs [role="tab"][aria-selected="true"]', '.tests-menu a[aria-current="page"]']) {
    assert.ok(needs.has(sel), `the sweep finds ${sel}`);
  }
  for (const sel of needs) {
    if (DEV_DRAWN_ELSEWHERE[sel]) continue;
    // Its own rule, or the rule of the thing a page-wide qualifier names
    // (`body.tenant-test .page-nav a[…]` is the page row's current page).
    assert.ok(forcedSels.some((f) => f === sel || sel.endsWith(` ${f}`)), `${sel} draws a picked state with a color, which a forced palette replaces: it needs a rule in @media (forced-colors: active)`);
  }
  for (const sel of Object.keys(DEV_DRAWN_ELSEWHERE)) assert.ok(needs.has(sel), `the exception ${sel} still exists`);
});

/** The inspector's markup, with the rows its script draws (sessions, steps,
 *  commits, the commits' scope; their classes as app.js draws them, words
 *  aside), and its styles as a browser applies them at `width` px: under a
 *  forced palette (the model), or not. */
function inspectorPage(width: number, forced: boolean): { doc: El; win: El; close: () => void } {
  const dom = new JSDOM(readDev("index.html"));
  const doc = dom.window.document;
  doc.getElementById("session-list")!.innerHTML = [1, 2, 3].map((i) =>
    `<div class="session" data-id="s${i}"><div class="s-main" role="button" tabindex="0"><div class="s-label">Session ${i}</div></div></div>`).join("");
  doc.getElementById("step-list")!.innerHTML = ["k-you", "k-guard", "k-reply"].map((k, i) =>
    `<button type="button" class="tc-item rail-item ${k}" data-id="t${i}"><span class="tc-title">Step ${i}</span></button>`).join("");
  doc.getElementById("git-commit-list")!.innerHTML = `<div class="git-scope">${["this", "all"].map((s) =>
    `<button type="button" class="git-scope-btn" data-scope="${s}">${s}</button>`).join("")}</div>` + ["mine", "mine", "other"].map((m, i) =>
    `<div class="git-commit ${m}" data-hash="h${i}" role="button" tabindex="0"><span class="h7">h${i}</span><span class="subj">Commit ${i}</span></div>`).join("");
  const css = resolveCssVars(stylesAt(INSPECTOR_CSS, width, { forcedColors: forced }));
  const sheet = doc.createElement("style");
  // One rule per selector: jsdom gives a selector list the specificity of
  // its strongest member, a browser each its own (the Tests menu's picked
  // row drops the list's line by a rule of equal specificity, later).
  sheet.textContent = perSelector(forced ? forcedColorsModel(css) : css);
  doc.head.append(sheet);
  return { doc, win: dom.window, close: () => dom.window.close() };
}

/** Picks `picked` of `els` as the page's script does. */
type Pick = (els: El[], picked: El) => void;
const byAttr = (attr: string, on: string, off: string | null): Pick => (els, picked) => {
  for (const e of els) {
    if (e === picked) e.setAttribute(attr, on);
    else if (off === null) e.removeAttribute(attr);
    else e.setAttribute(attr, off);
  }
};
const byClass = (also?: Pick): Pick => (els, picked) => {
  for (const e of els) e.classList.toggle("active", e === picked);
  also?.(els, picked);
};
/** Each picked state of the inspector: underlined, or edged. */
const UNDERLINED: Array<[string, string, Pick]> = [
  ["the page row", "#page-nav a", byAttr("aria-current", "page", null)],
  ["the session tabs", '#session-tabs [role="tab"]', byClass(byAttr("aria-selected", "true", "false"))],
  ["Files' tabs", ".git-tabs .git-tab", byClass(byAttr("aria-selected", "true", "false"))],
  ["Replay | Live", "#drill-kind [data-kind]", byClass(byAttr("aria-checked", "true", "false"))],
  ["the commits' scope", ".git-scope-btn", byClass(byAttr("aria-pressed", "true", "false"))],
];
const EDGED: Array<[string, string, Pick]> = [
  ["the sessions list", "#session-list .session", byClass()],
  ["the step rail", "#step-list .tc-item", byClass()],
  ["the commits", "#git-commit-list .git-commit", byClass(byAttr("aria-current", "true", null))],
  ["Rules' menu", "#rules-menu a", byAttr("aria-current", "location", null)],
  ["Settings' menu", "#settings-menu a", byAttr("aria-current", "location", null)],
  ["Tests' menu", ".tests-menu:not(.drills-menu) a", byAttr("aria-current", "page", null)],
  ["Drills' menu", ".drills-menu a", byAttr("aria-current", "page", null)],
];
const underlined = (win: El, el: El): boolean => {
  const s = win.getComputedStyle(el);
  return s.textDecorationLine === "underline" && s.textDecorationColor === sys(win, "Highlight") && s.textDecorationThickness === "2px";
};
const edges = (win: El, el: El): string[] => {
  const s = win.getComputedStyle(el);
  return [s.borderTopColor, s.borderRightColor, s.borderBottomColor, s.borderLeftColor];
};

test("inspector, forced colors: the current page, the picked tab and the picked segment are underlined in the selection color, the others are not", { skip: NO_DEV_PAGES }, () => {
  for (const width of [1280, 390]) {
    const { doc, win, close } = inspectorPage(width, true);
    for (const [name, sel, pick] of UNDERLINED) {
      const els = [...doc.querySelectorAll(sel)] as El[];
      assert.ok(els.length >= 2, `${name}: its markup is found`);
      for (const picked of els) {
        pick(els, picked);
        for (const e of els) {
          assert.equal(underlined(win, e), e === picked, `${width} px, ${name}: "${e.textContent.trim()}" ${e === picked ? "is picked: underlined" : "is not underlined"}`);
          assert.notEqual(win.getComputedStyle(e).backgroundColor, sys(win, "Highlight"), `${name}: no word on a selection-color fill`);
        }
      }
    }
    close();
  }
});

test("inspector, forced colors: only the open session, the picked step, commit and menu row have an edge, in the selection color", { skip: NO_DEV_PAGES }, () => {
  for (const width of [1280, 390]) {
    const { doc, win, close } = inspectorPage(width, true);
    const [canvas, text, hi] = [sys(win, "Canvas"), sys(win, "CanvasText"), sys(win, "Highlight")];
    for (const [name, sel, pick] of EDGED) {
      const els = [...doc.querySelectorAll(sel)] as El[];
      assert.ok(els.length >= 3, `${name}: its markup is found`);
      for (const picked of [els[0], els[els.length - 1]]) {
        pick(els, picked);
        for (const e of els) {
          const label = `${width} px, ${name}: "${e.textContent.trim()}"`;
          if (e === picked) {
            assert.deepEqual(edges(win, e), [hi, hi, hi, hi], `${label} is picked: its edge is the selection color`);
          } else {
            // A step's left bar is its kind, drawn as the palette draws it.
            const left = name === "the step rail" ? text : canvas;
            assert.deepEqual(edges(win, e), [canvas, canvas, canvas, left], `${label} is not picked: no edge is seen`);
          }
          assert.equal(underlined(win, e), false, `${label}: an edge, not a line`);
          assert.notEqual(win.getComputedStyle(e).backgroundColor, hi, `${label}: no selection-color fill`);
        }
      }
    }
    close();
  }
});

test("inspector: the forced-colors rules move nothing, and without forced colors nothing is underlined or edged in the selection color", { skip: NO_DEV_PAGES }, () => {
  const box = (win: El, el: El): string => {
    const s = win.getComputedStyle(el);
    return ["Top", "Right", "Bottom", "Left"].map((side) => `${s[`border${side}Width`]} ${s[`border${side}Style`]} ${s[`padding${side}`]}`).join(" | ");
  };
  for (const width of [1280, 390]) {
    const forced = inspectorPage(width, true);
    const plain = inspectorPage(width, false);
    const hi = sys(plain.win, "Highlight");
    for (const [name, sel, pick] of [...UNDERLINED, ...EDGED]) {
      const f = [...forced.doc.querySelectorAll(sel)] as El[];
      const p = [...plain.doc.querySelectorAll(sel)] as El[];
      pick(f, f[0]);
      pick(p, p[0]);
      for (let i = 0; i < f.length; i++) {
        assert.equal(box(forced.win, f[i]), box(plain.win, p[i]), `${width} px, ${name} #${i}: the same edges' widths and padding, forced or not`);
        assert.equal(plain.win.getComputedStyle(p[i]).textDecorationLine === "underline", false, `${width} px, ${name} #${i}: not underlined without forced colors`);
        assert.equal(edges(plain.win, p[i]).includes(hi), false, `${width} px, ${name} #${i}: no selection-color edge without forced colors`);
      }
    }
    forced.close();
    plain.close();
  }
});
