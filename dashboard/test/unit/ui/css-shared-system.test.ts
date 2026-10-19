/**
 * css-shared-system.test.ts — the ONE visual system of both front-ends
 * (dashboard.md §4.25k). public/mandu.css holds the tokens, type and bare
 * elements; the product page (public/app.css) and the /dev/ inspector
 * (dev/dashboard.css) both load it first and define no palette of their own,
 * so the two pages cannot drift apart again.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { JSDOM } from "jsdom";
import { contrastRatio, declValue, flattenCss, resolveCssVars, stripComments } from "./css-flatten.js";
import { devPagesDir, NO_DEV_PAGES } from "./dev-pages.js";

const PKG = process.cwd();
const SHARED = readFileSync(join(PKG, "public", "mandu.css"), "utf8");
const APP_CSS = readFileSync(join(PKG, "public", "app.css"), "utf8");
/** The developer view's pages; null in a tree without them (dev-pages.ts):
 *  its halves of the checks then read nothing and its own checks skip. */
const DEV = devPagesDir();
const DEV_CSS = DEV ? readFileSync(join(DEV, "dashboard.css"), "utf8") : "";
const PUB_HTML = readFileSync(join(PKG, "public", "index.html"), "utf8");
const DEV_HTML = DEV ? readFileSync(join(DEV, "index.html"), "utf8") : "";
const DEV_JS = DEV ? readdirSync(join(DEV, "js")).map((f) => readFileSync(join(DEV, "js", f), "utf8")).join("\n") : "";

/** Custom properties DECLARED in a stylesheet (`--name:`). */
function declared(css: string): Set<string> {
  return new Set([...stripComments(css).matchAll(/(--[a-z0-9-]+)\s*:/g)].map((m) => m[1]!));
}
/** The declarations inside the first block that follows `prelude`. */
function blockAfter(css: string, prelude: string): Map<string, string> {
  const src = stripComments(css);
  const at = src.indexOf(prelude);
  assert.ok(at >= 0, `mandu.css has a ${prelude} block`);
  const open = src.indexOf("{", at);
  const close = src.indexOf("}", open);
  return new Map([...src.slice(open + 1, close).matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)].map((m) => [m[1]!, m[2]!.trim()]));
}

test("both pages load the shared stylesheet before their own", () => {
  const pub = PUB_HTML.indexOf('href="mandu.css"');
  assert.ok(pub >= 0 && pub < PUB_HTML.indexOf('href="app.css"'), "product: mandu.css, then app.css");
  const dev = DEV_HTML.indexOf('href="../mandu.css"');
  if (DEV) assert.ok(dev >= 0 && dev < DEV_HTML.indexOf('href="dashboard.css"'), "inspector: ../mandu.css, then dashboard.css");
});

test("neither page defines a palette of its own: the color tokens live only in mandu.css", () => {
  const palette = ["--bg", "--panel", "--line", "--ink", "--accent", "--ok", "--warn", "--bad", "--sym", "--sans", "--mono"];
  for (const [name, css] of [["app.css", APP_CSS], ["dashboard.css", DEV_CSS]] as const) {
    const own = declared(css);
    for (const t of palette) assert.ok(!own.has(t), `${name} redeclares ${t}`);
  }
  assert.doesNotMatch(stripComments(DEV_CSS), /\.theme-(?!select\b)[a-z-]+/, "the retired theme-* palettes are gone from the inspector");
  for (const retired of ["--fg", "--fg2", "--fg3", "--bg2", "--bg3", "--border", "--green", "--red", "--blue", "--yellow", "--amber"]) {
    const re = new RegExp(`var\\(${retired}(?![\\w-])`);
    assert.doesNotMatch(DEV_CSS, re, `dashboard.css still reads the retired ${retired}`);
    assert.doesNotMatch(DEV_JS, re, `dev/js still reads the retired ${retired}`);
  }
});

test("every token the inspector reads is defined (shared, or one of its own layout vars)", { skip: NO_DEV_PAGES }, () => {
  // The layout vars the scripts measure: app.js (--col-l, --col-mid,
  // --topbar-h), sub-menus.js (--sub-menu-h, the phone's sub-menu row) and
  // drill-matrix.js (--dm-head1, the first header row's height).
  const known = new Set([...declared(SHARED), ...declared(DEV_CSS), "--col-l", "--col-mid", "--topbar-h", "--sub-menu-h", "--dm-head1"]);
  const used = new Set([...(stripComments(DEV_CSS) + DEV_JS).matchAll(/var\((--[a-z0-9-]+)/g)].map((m) => m[1]!));
  const missing = [...used].filter((t) => !known.has(t));
  assert.deepEqual(missing, [], `undefined tokens: ${missing.join(", ")}`);
});

test("dark mode: the system-following set and the pinned data-theme set are identical", () => {
  const light = blockAfter(SHARED, ":root {");
  const system = blockAfter(SHARED, ':root:not([data-theme="light"])');
  const pinned = blockAfter(SHARED, ':root[data-theme="dark"]');
  assert.deepEqual([...system], [...pinned], "the two dark blocks must not drift");
  for (const [k] of system) assert.ok(light.has(k), `dark ${k} has a light value`);
  const colors = [...light.keys()].filter((k) => !["--sans", "--mono", "--radius", "--radius-sm"].includes(k));
  for (const k of colors) assert.ok(system.has(k), `light ${k} has a dark value`);
});

// Text on a filled color reads in both themes (§4.25k, 2026-10-14). Until
// then the Approvals count on both pages was a fixed white on --warn: 5.09:1
// in the light theme, 2.23:1 on the dark theme's light amber.
const PAGES = [["app.css", APP_CSS], ["dashboard.css", DEV_CSS]] as const;
/** Every value a block declares for `prop` (declValue keeps the last). */
function values(block: string, prop: string): string[] {
  return block.split(";").map((d) => [d.slice(0, d.indexOf(":")).trim().toLowerCase(), d.slice(d.indexOf(":") + 1).trim().toLowerCase()] as const)
    .filter(([p]) => p === prop).map(([, v]) => v);
}

test("contrastRatio is WCAG 2's ratio, over hex and the rgb() jsdom computes", () => {
  assert.equal(contrastRatio("#fff", "#000"), 21);
  assert.equal(contrastRatio("#000000", "rgb(255, 255, 255)"), 21, "the same either way round");
  assert.equal(contrastRatio("#777", "#777"), 1);
  assert.equal(contrastRatio("#ffffff", "#e0a24a").toFixed(2), "2.23", "white on the dark theme's amber");
  assert.equal(contrastRatio("#ffffff", "#a35d00").toFixed(2), "5.09", "white on the light theme's");
  assert.equal(contrastRatio("rgb(31, 33, 38)", "rgba(224, 162, 74, 1)").toFixed(2), "7.24", "the panel's ink on the dark amber");
  assert.equal(contrastRatio("color(srgb 1 1 1)", "#000").toFixed(2), "21.00", "an opaque color-mix() as jsdom computes it");
  assert.throws(() => contrastRatio("color(srgb 0 0 0 / 0.5)", "#fff"), /cannot read/, "a see-through mix is never guessed");
  assert.throws(() => contrastRatio("rgba(0, 0, 0, 0.5)", "#fff"), /cannot read/, "a see-through color is never guessed");
  assert.throws(() => contrastRatio("white", "#fff"), /cannot read/);
});

test("a text color is a token, never a fixed color that reads in one theme only (§4.25k)", () => {
  const fixed = /#[0-9a-f]{3,8}\b|\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch)\(|\b(?:white|black)\b/;
  let n = 0;
  for (const [name, css] of PAGES) {
    for (const r of flattenCss(stripComments(css))) {
      for (const v of values(r.block, "color")) {
        n += 1;
        const where = `${name} ${r.selectors.join(", ")}: color: ${v}`;
        assert.match(v, /^(?:var\(|color-mix\(|inherit$|currentcolor$|transparent$)/, `${where} is not a token`);
        assert.doesNotMatch(v, fixed, `${where} holds a fixed color`);
      }
    }
  }
  assert.ok(n > 100, `both pages' text colors are read (${n})`);
});

test("text on a filled color reads in both themes, 4.5:1 at the least: the Approvals count too (§4.25k)", () => {
  const light = blockAfter(SHARED, ":root {");
  const dark = new Map([...light, ...blockAfter(SHARED, ':root[data-theme="dark"]')]);
  // The tokens a box is filled with: the inks and the colors, not the
  // panels, lines and tints that text normally sits on.
  const FILLS = ["--ink", "--ink-2", "--ink-3", "--ink-4", "--accent", "--accent-ink", "--ok", "--warn", "--bad", "--code-ink", "--sym", "--pink", "--purple", "--cyan"];
  const token = (v: string): string | null => /^var\((--[a-z0-9-]+)\)$/.exec(v)?.[1] ?? null;
  const checked: string[] = [];
  for (const [name, css] of PAGES) {
    for (const r of flattenCss(stripComments(css))) {
      const fill = token(declValue(r.block, "background") ?? declValue(r.block, "background-color") ?? "");
      const color = declValue(r.block, "color");
      if (!fill || !FILLS.includes(fill) || color === null) continue;
      for (const [theme, t] of [["light", light], ["dark", dark]] as const) {
        const ink = token(color) ? t.get(token(color)!) : color;
        assert.ok(ink, `${name} ${r.selectors.join(", ")}: ${color} has a ${theme} value`);
        const ratio = contrastRatio(ink!, t.get(fill)!);
        assert.ok(ratio >= 4.5, `${name} ${r.selectors.join(", ")} (${theme}): ${color} on var(${fill}) reads ${ratio.toFixed(2)}:1, under 4.5:1`);
      }
      checked.push(...r.selectors);
    }
  }
  for (const sel of [".count", ...(DEV ? [".area-badge"] : []), ".btn.primary"]) {
    assert.ok(checked.includes(sel), `${sel} is one of the filled rules checked`);
  }
});

// The faintest ink reads too (§4.25k, 2026-10-17). Until then --ink-4 (times,
// cell labels, column heads) read 2.97 to 3.43:1 in the light theme and 3.29
// to 4.18:1 in the dark, and the light --ok on its tint 4.16:1.
/** The plain grounds text is drawn on: the page, a card, an opened row, a code chip. */
const GROUNDS = ["--panel", "--panel-2", "--bg", "--code-bg"];
const themes = (): Array<[string, Map<string, string>]> => {
  const light = blockAfter(SHARED, ":root {");
  return [["light", light], ["dark", new Map([...light, ...blockAfter(SHARED, ':root[data-theme="dark"]')])]];
};

test("the faintest ink and the light tinted chips read 4.5:1 at the least, in both themes (§4.25k)", () => {
  for (const [theme, t] of themes()) {
    const at = (ink: string, ground: string): number => contrastRatio(t.get(ink)!, t.get(ground)!);
    for (const g of GROUNDS) {
      assert.ok(at("--ink-4", g) >= 4.5, `${theme}: --ink-4 on ${g} reads ${at("--ink-4", g).toFixed(2)}:1, under 4.5:1`);
    }
    assert.ok(at("--ok", "--ok-bg") >= 4.5, `${theme}: --ok on --ok-bg reads ${at("--ok", "--ok-bg").toFixed(2)}:1`);
    assert.ok(at("--bad", "--bad-bg") >= 4.5, `${theme}: --bad on --bad-bg reads ${at("--bad", "--bad-bg").toFixed(2)}:1`);
    if (theme === "dark") assert.ok(at("--warn", "--warn-bg") >= 4.5, `dark: --warn on --warn-bg reads ${at("--warn", "--warn-bg").toFixed(2)}:1`);
    // The one gap the doc names (*Not covered*): the light amber stays as the
    // top bar's count pins it. A palette change that fixes it updates this line.
    else assert.equal(at("--warn", "--warn-bg").toFixed(2), "4.45", "light: --warn on --warn-bg, the named open gap");
    // The two steps stay apart: --ink-4 is the fainter one in each theme.
    const step3 = at("--ink-3", "--panel");
    const step4 = at("--ink-4", "--panel");
    assert.ok(step3 > step4, `${theme}: --ink-3 (${step3.toFixed(2)}:1) reads stronger than --ink-4 (${step4.toFixed(2)}:1)`);
    const lighter = contrastRatio(t.get("--ink-3")!, "#000000") > contrastRatio(t.get("--ink-4")!, "#000000");
    assert.equal(lighter, theme === "dark", `${theme}: --ink-3 is ${theme === "dark" ? "lighter" : "darker"} than --ink-4`);
  }
});

test("every app.css rule drawn in --ink-4 reads 4.5:1 on its own fill, or on every plain ground (§4.25k)", () => {
  const token = (v: string): string | null => /^var\((--[a-z0-9-]+)\)$/.exec(v)?.[1] ?? null;
  const swept: string[] = [];
  for (const r of flattenCss(stripComments(APP_CSS))) {
    if (declValue(r.block, "color") !== "var(--ink-4)") continue;
    const own = token(declValue(r.block, "background") ?? declValue(r.block, "background-color") ?? "");
    for (const [theme, t] of themes()) {
      for (const g of own && t.has(own) ? [own] : GROUNDS) {
        const ratio = contrastRatio(t.get("--ink-4")!, t.get(g)!);
        assert.ok(ratio >= 4.5, `app.css ${r.selectors.join(", ")} (${theme}): --ink-4 on ${g} reads ${ratio.toFixed(2)}:1, under 4.5:1`);
      }
    }
    swept.push(...r.selectors);
  }
  for (const sel of [".ask-detail .k", ".proposal-k", ".muted", ".row .dim", ".turn-head .time", ".files-heads", ".host-chip.from"]) {
    assert.ok(swept.includes(sel), `${sel} is one of the --ink-4 rules swept`);
  }
});

// A session on more than one day names its days (§4.25, the per-agent page,
// 2026-10-19): the line before each day's first turn sits on the page, between
// the cards, in the note's ink.
test("the session page's day line reads 4.5:1 on every plain ground, in both themes (§4.25)", () => {
  const rules = flattenCss(stripComments(APP_CSS)).filter((r) => r.selectors.includes(".story-day"));
  const color = rules.map((r) => declValue(r.block, "color")).find((v) => v !== null);
  assert.equal(color, "var(--ink-3)", "the note's ink");
  for (const [theme, t] of themes()) {
    for (const g of GROUNDS) {
      const ratio = contrastRatio(t.get("--ink-3")!, t.get(g)!);
      assert.ok(ratio >= 4.5, `.story-day (${theme}): --ink-3 on ${g} reads ${ratio.toFixed(2)}:1, under 4.5:1`);
    }
  }
});

test("the Approvals count, drawn with each page's served styles: unchanged in the light theme, readable in the dark (§4.25k)", () => {
  const pages = [
    { name: "product", html: PUB_HTML, css: `${SHARED}\n${APP_CSS}`, id: "nav-approvals-count" },
    ...(DEV ? [{ name: "inspector", html: DEV_HTML, css: `${SHARED}\n${DEV_CSS}`, id: "area-approvals-count" }] : []),
  ];
  for (const p of pages) {
    for (const theme of ["light", "dark"] as const) {
      const dom = new JSDOM(p.html.replace(/<script\b[\s\S]*?<\/script>/g, ""));
      const doc = dom.window.document;
      const style = doc.createElement("style");
      style.textContent = resolveCssVars(p.css, theme);
      doc.head.append(style);
      const badge = doc.getElementById(p.id)!;
      badge.hidden = false;
      badge.textContent = "3";
      const cs = dom.window.getComputedStyle(badge);
      if (theme === "light") {
        assert.deepEqual([cs.color, cs.backgroundColor], ["rgb(255, 255, 255)", "rgb(163, 93, 0)"], `${p.name}: white on the amber, as before`);
      } else {
        assert.equal(cs.backgroundColor, "rgb(224, 162, 74)", `${p.name}: the dark theme's amber (resolveCssVars read the dark set)`);
      }
      const ratio = contrastRatio(cs.color, cs.backgroundColor);
      assert.ok(ratio >= 4.5, `${p.name} (${theme}): the count reads ${ratio.toFixed(2)}:1 (${cs.color} on ${cs.backgroundColor})`);
      dom.window.close();
    }
  }
});

test("fonts: every family the tokens name is self-hosted in public/fonts, licensed, and in NOTICE", () => {
  const src = stripComments(SHARED);
  const faces = [...src.matchAll(/@font-face\s*\{([^}]*)\}/g)].map((m) => m[1]!);
  assert.ok(faces.length > 0, "mandu.css declares @font-face rules");
  const families = new Set<string>();
  for (const face of faces) {
    const fam = /font-family:\s*"([^"]+)"/.exec(face)?.[1];
    const url = /src:\s*url\((fonts\/[a-z0-9-]+\.woff2)\)\s*format\("woff2"\)/.exec(face)?.[1];
    assert.ok(fam && url, `a face names its family and one local woff2: ${face.trim().slice(0, 80)}`);
    assert.match(face, /font-display:\s*swap/, `${url}: text renders in the fallback while the font loads`);
    assert.match(face, /unicode-range:/, `${url}: outside its subset the system face takes over`);
    const file = join(PKG, "public", url);
    assert.ok(existsSync(file) && statSync(file).size > 1000, `${url} is vendored`);
    families.add(fam);
  }
  for (const token of ["--sans", "--mono"]) {
    const first = new RegExp(`${token}:\\s*"([^"]+)"`).exec(src)?.[1];
    assert.ok(first && families.has(first), `${token}'s first family (${first}) has a @font-face`);
  }
  const fontDir = readdirSync(join(PKG, "public", "fonts"));
  for (const fam of families) {
    const slug = fam.toLowerCase().replace(/\s+/g, "-");
    assert.ok(fontDir.includes(`LICENSE-${slug}.txt`), `${fam}: its OFL license ships beside the files`);
    assert.match(readFileSync(join(PKG, "public", "fonts", `LICENSE-${slug}.txt`), "utf8"), /SIL Open Font License/);
  }
  assert.match(readFileSync(join(PKG, "..", "NOTICE"), "utf8"), /dashboard\/public\/fonts\//, "NOTICE lists the vendored fonts");
  // No page reaches a font CDN: the dashboard is loopback-first and offline.
  for (const [name, text] of [["mandu.css", SHARED], ["app.css", APP_CSS], ["dashboard.css", DEV_CSS], ["index.html", PUB_HTML], ["dev/index.html", DEV_HTML]] as const) {
    assert.doesNotMatch(text, /fonts\.googleapis|fonts\.gstatic|@import\s+url\(\s*["']?https?:/, `${name} loads no remote font`);
  }
});

test("one sans family: no serif face, no italic face, no slanted text on either page (§4.25k)", () => {
  const faces = [...stripComments(SHARED).matchAll(/@font-face\s*\{([^}]*)\}/g)].map((m) => m[1]!);
  const families = new Set(faces.map((f) => /font-family:\s*"([^"]+)"/.exec(f)?.[1]));
  assert.deepEqual([...families].sort(), ["IBM Plex Mono", "IBM Plex Sans"], "Plex Sans for words, Plex Mono for data");
  for (const face of faces) assert.match(face, /font-style:\s*normal/, "no italic face is vendored");
  for (const [name, css] of [["mandu.css", SHARED], ["app.css", APP_CSS], ["dashboard.css", DEV_CSS]] as const) {
    const src = stripComments(css);
    assert.doesNotMatch(src, /font-style:\s*(italic|oblique)/, `${name}: emphasis is weight, never a slanted face`);
    assert.doesNotMatch(src, /\bserif\b(?<!sans-serif)|Georgia|Times/, `${name}: no serif family anywhere`);
  }
  assert.match(stripComments(SHARED), /em, i, cite, dfn, var, address \{ font-style: normal; \}/, "the browser's default italics are turned off");
});

test("type floor: no inspector text under 11px, no product text under 12px", { skip: NO_DEV_PAGES }, () => {
  const sizes = (css: string) => [...stripComments(css).matchAll(/font-size:\s*([0-9.]+)px/g)].map((m) => Number(m[1]));
  const devSmall = sizes(DEV_CSS).filter((n) => n < 11);
  assert.deepEqual(devSmall, [], "dashboard.css: 11px is the dense-data floor");
  const appSmall = sizes(APP_CSS).filter((n) => n < 12);
  assert.deepEqual(appSmall, [], "app.css: 12px is the product floor");
});

test("inspector headings and tabs wear the product's look; long symbol names wrap", { skip: NO_DEV_PAGES }, () => {
  const rules = flattenCss(stripComments(DEV_CSS)).filter((r) => r.media === null);
  const lastValue = (selector: string, prop: string): string | null => {
    let v: string | null = null;
    for (const r of rules) if (r.selectors.includes(selector)) v = declValue(r.block, prop) ?? v;
    return v;
  };
  for (const h of [".inline-panel h3", ".drawer-body h3"]) {
    assert.notEqual(lastValue(h, "text-transform"), "uppercase", `${h}: sentence case, not small capitals`);
    assert.equal(lastValue(h, "color"), "var(--ink)", `${h}: ink, not a grey label`);
  }
  assert.equal(lastValue("h3 .readonly-note", "font-style"), "normal", "a heading's aside reads upright");
  for (const tab of [".git-tab"]) {
    assert.equal(lastValue(tab, "border"), "none", `${tab}: the borderless top-bar tab`);
    assert.equal(lastValue(tab, "border-radius"), "var(--radius-sm)");
    assert.equal(lastValue(`${tab}.active`, "background"), "var(--line)", `${tab}: the selected tab is a filled pill`);
  }
  // A name breaks only between its parts (dashboard.md §4.5, 2026-10-19):
  // the cells no longer break anywhere; the inspector cuts a name into
  // one-line .name-parts (a token longer than 40 after its "]" and dots),
  // so a 150-char symbol name still wraps inside the panel.
  assert.notEqual(lastValue("#symbol-table td", "overflow-wrap"), "anywhere", "a symbol table cell no longer breaks a name at a letter");
  assert.equal(lastValue(".name-part", "white-space"), "nowrap", "a part stays on one line");
  assert.equal(lastValue(".name-part", "display"), "inline-block", "a line may end between two parts, so a 150-char symbol name wraps inside the panel");
  assert.equal(lastValue(".drawer-title", "min-width"), "0", "a long dialog title wraps instead of pushing the close button out");
});
