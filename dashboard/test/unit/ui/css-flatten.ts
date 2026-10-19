/**
 * css-flatten.ts — tiny brace-aware CSS flattener shared by the text-level
 * CSS contract tests (css-inspector-contract, css-dialog-contract). Extracted
 * verbatim from css-register-contract.test.ts (now css-inspector-contract) when the dialog contract needed
 * the same machinery.
 *
 * dashboard.css is hand-written (no preprocessor), so a full CSS parser is
 * overkill: strip comments, then walk the text brace-aware. One level of
 * at-rule nesting is supported — rules inside @media/@supports blocks are
 * emitted flattened (tagged with the enclosing prelude); @keyframes bodies
 * are skipped, because their inner "selectors" are animation offsets, not
 * elements. Selector lists are comma-split and whitespace-normalized so a
 * grouped rule yields one entry per selector.
 *
 * `resolveCssVars` is for the tests that apply a stylesheet in jsdom and read
 * computed borders (the product page's empty states) or colors, in the light
 * theme or the dark; `contrastRatio` reads two colors' WCAG ratio (text on a
 * filled color in both themes, dashboard.md §4.25k). `lengthPx` and
 * `railFit` read a box's geometry off the declared numbers (the inspector's
 * sticky step rail against the top bar and the page's end). `stylesAt` is
 * the stylesheet a browser applies at one width, its width queries
 * unwrapped (jsdom applies none: the inspector's Files tab on a phone), and
 * on request its reduce-motion or forced-colors blocks too (§4.25k);
 * `forcedColorsModel` is what a browser in forced-colors mode keeps of it.
 */

export interface FlatRule {
  /** Individual selectors of the rule, comma-split, whitespace collapsed. */
  selectors: string[];
  /** Raw declaration block text (the part between the braces). */
  block: string;
  /** Enclosing at-rule prelude (e.g. "@media (max-width: 760px)"), or null. */
  media: string | null;
}

export function stripComments(css: string): string {
  return css.replace(/\/\*[\s\S]*?\*\//g, " ");
}

export function flattenCss(css: string, media: string | null = null): FlatRule[] {
  const out: FlatRule[] = [];
  let i = 0;
  while (i < css.length) {
    const open = css.indexOf("{", i);
    if (open === -1) break;
    // Drop any statement at-rules (e.g. "@import …;") glued before the selector.
    const prelude = (css.slice(i, open).split(";").pop() ?? "").trim();
    // Scan to the matching close brace (handles one nested level and beyond).
    let depth = 1;
    let j = open + 1;
    while (j < css.length && depth > 0) {
      if (css[j] === "{") depth += 1;
      else if (css[j] === "}") depth -= 1;
      j += 1;
    }
    const body = css.slice(open + 1, j - 1);
    if (prelude.startsWith("@")) {
      if (/^@(media|supports)\b/.test(prelude)) {
        out.push(...flattenCss(body, prelude.replace(/\s+/g, " ")));
      }
      // other at-rules (@keyframes, @font-face): skipped on purpose.
    } else if (prelude.length > 0) {
      out.push({
        selectors: prelude.split(",").map((s) => s.replace(/\s+/g, " ").trim()).filter(Boolean),
        block: body,
        media,
      });
    }
    i = j;
  }
  return out;
}

/** Value of `prop` in a declaration block (last one wins, like the cascade). */
export function declValue(block: string, prop: string): string | null {
  let value: string | null = null;
  for (const decl of block.split(";")) {
    const colon = decl.indexOf(":");
    if (colon === -1) continue;
    if (decl.slice(0, colon).trim().toLowerCase() === prop) {
      value = decl.slice(colon + 1).trim().toLowerCase();
    }
  }
  return value;
}

/** The stylesheet text with each `var(--name)` replaced by its value in the
 *  first `:root` block (mandu.css: the light theme), or, for `"dark"`, that
 *  block overlaid with the `:root[data-theme="dark"]` one (the dark set,
 *  which css-shared-system keeps identical to the one that follows the
 *  system). jsdom does not expand a
 *  shorthand that holds a `var()`, so `border: 1px dashed var(--line)` reads
 *  as no border at all; a test of which frames the page draws resolves the
 *  tokens first. An unknown name keeps its fallback, or stays as written. */
export function resolveCssVars(css: string, theme: "light" | "dark" = "light"): string {
  const src = stripComments(css);
  const tokens = new Map<string, string>();
  const read = (open: number): void => {
    if (open < 0) return;
    const body = src.slice(src.indexOf("{", open) + 1, src.indexOf("}", open));
    for (const m of body.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)) tokens.set(m[1]!, m[2]!.trim());
  };
  read(src.search(/:root\s*\{/));
  if (theme === "dark") {
    const dark = src.search(/:root\[data-theme="dark"\]\s*\{/);
    if (dark < 0) throw new Error("resolveCssVars: the stylesheet has no dark set");
    read(dark);
  }
  let out = src;
  // A token may name another (`--x: var(--y)`): a few passes reach the end.
  for (let pass = 0; pass < 4; pass += 1) {
    out = out.replace(/var\((--[a-z0-9-]+)\s*(?:,\s*([^()]*))?\)/g, (all, name: string, fallback?: string) =>
      tokens.get(name) ?? fallback?.trim() ?? all);
  }
  return out;
}

/** Does `sel` mention `target` as a whole simple selector (not a prefix)? */
export function mentions(sel: string, target: string): boolean {
  const esc = target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`${esc}(?![\\w-])`).test(sel);
}

/** A declared value split at its top-level spaces, so a shorthand's parts
 *  keep their `calc(…)` / `var(…)` whole: `calc(a + b) 16px var(--x)` is
 *  three parts. */
export function splitValue(value: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let part = "";
  for (const c of value.trim()) {
    if (c === "(") depth += 1;
    else if (c === ")") depth -= 1;
    if (/\s/.test(c) && depth === 0) {
      if (part) out.push(part);
      part = "";
    } else part += c;
  }
  if (part) out.push(part);
  return out;
}

/** A declared length in px, for the tests that check where a box can sit
 *  from the stylesheet's own numbers (jsdom does no layout; the step rail,
 *  dashboard.md §4.33): `Npx`, `Nvh`, a unitless 0, `var(--name, fallback)`
 *  and `calc()` / parentheses over + and -. `vh` is the window's height,
 *  `vars` each custom property's value (an unknown one takes its fallback).
 *  Anything else throws: a number the test cannot read is never guessed. */
export function lengthPx(expr: string, env: { vh: number; vars: Record<string, string> }): number {
  let s = expr.trim();
  for (let pass = 0; /var\(/.test(s); pass += 1) {
    if (pass > 8) throw new Error(`lengthPx: var() does not resolve in ${expr}`);
    s = s.replace(/var\((--[a-z0-9-]+)\s*(?:,\s*([^()]*))?\)/g, (_all, name: string, fallback?: string) => {
      const v = env.vars[name] ?? fallback?.trim();
      if (v === undefined) throw new Error(`lengthPx: ${name} has no value in ${expr}`);
      return v;
    });
  }
  const tokens = s.replace(/calc\(/g, "(").match(/\d+(?:\.\d+)?(?:px|vh)?|[()+-]|\S+/g) ?? [];
  let i = 0;
  const term = (): number => {
    const t = tokens[i++];
    if (t === "(") {
      const v = sum();
      if (tokens[i++] !== ")") throw new Error(`lengthPx: unbalanced ${expr}`);
      return v;
    }
    const m = /^(\d+(?:\.\d+)?)(px|vh)?$/.exec(t ?? "");
    if (!m || (!m[2] && Number(m[1]) !== 0)) throw new Error(`lengthPx: cannot read "${t}" in ${expr}`);
    return m[2] === "vh" ? (Number(m[1]) * env.vh) / 100 : Number(m[1]);
  };
  const sum = (): number => {
    let v = term();
    while (tokens[i] === "+" || tokens[i] === "-") v = tokens[i++] === "+" ? v + term() : v - term();
    return v;
  };
  const v = sum();
  if (i !== tokens.length) throw new Error(`lengthPx: cannot read ${expr}`);
  return v;
}

/** Where the Trace tab's sticky step rail can sit (§4.33), read off a
 *  stylesheet's declared values (jsdom does no layout) for a window `vh` px
 *  tall under a `topbar` px bar: its top while the page scrolls, its bottom
 *  at the most, and the page's end, where the trace's layout ends when the
 *  page is scrolled to its end (#main's bottom padding above the window's
 *  foot). A rail whose bottom passes that line is pushed up with the
 *  layout there, its top under the bar. The base (non-@media) rules, last
 *  one winning; the phone's rail is static. */
export function railFit(cssText: string, vh: number, topbar: number): { top: number; bottom: number; pageEnd: number } {
  const rules = flattenCss(stripComments(cssText)).filter((r) => r.media === null);
  const last = (sel: string, prop: string): string | null =>
    rules.filter((r) => r.selectors.includes(sel)).map((r) => declValue(r.block, prop)).filter((v) => v !== null).at(-1) ?? null;
  if (last(".step-rail", "position") !== "sticky") throw new Error("railFit: the rail is not sticky");
  const vars: Record<string, string> = { "--topbar-h": `${topbar}px` };
  const mainEnd = last("#main", "--main-end");
  if (mainEnd !== null) vars["--main-end"] = mainEnd;
  const px = (prop: string, v: string | null): number => {
    if (v === null) throw new Error(`railFit: no ${prop}`);
    return lengthPx(v, { vh, vars });
  };
  const pad = splitValue(last("#main", "padding") ?? "0");
  const bottomPad = last("#main", "padding-bottom") ?? (pad.length >= 3 ? pad[2]! : pad[0]!);
  const top = px("top", last(".step-rail", "top"));
  return { top, bottom: top + px("max-height", last(".step-rail", "max-height")), pageEnd: vh - px("padding-bottom", bottomPad) };
}

/** The rules of `css` a browser applies at a viewport `width` px wide, as
 *  one stylesheet with no width query left: the rules outside any at-rule
 *  and, in place, each `@media` block whose every condition is a
 *  `max-width` or `min-width` that holds at that width, unwrapped. A block
 *  with any other condition (`prefers-color-scheme`, `@supports`) is left
 *  out, so the theme is the light one. jsdom applies no width query, so a
 *  test of the phone's layout applies `stylesAt(css, 390)` (the Files tab,
 *  dashboard.md §4.12). With `reducedMotion`, a
 *  `(prefers-reduced-motion: reduce)` condition holds too: the page as a
 *  system set to reduce motion draws it (§4.25k). With `forcedColors`, a
 *  `(forced-colors: active)` one: the page under a forced palette (§4.25k;
 *  `forcedColorsModel` then forces its colors). Comments and the
 *  at-rules `flattenCss` skips are not kept. */
export function stylesAt(css: string, width: number, opts: { reducedMotion?: boolean; forcedColors?: boolean } = {}): string {
  const holds = (media: string): boolean => {
    const m = /^@media (.+)$/.exec(media);
    return !!m && m[1]!.split(/\s+and\s+/).every((part) => {
      if (opts.reducedMotion && /^\(prefers-reduced-motion:\s*reduce\)$/.test(part.trim())) return true;
      if (opts.forcedColors && /^\(forced-colors:\s*active\)$/.test(part.trim())) return true;
      const q = /^\((max|min)-width:\s*(\d+(?:\.\d+)?)px\)$/.exec(part.trim());
      return !!q && (q[1] === "max" ? width <= Number(q[2]) : width >= Number(q[2]));
    });
  };
  return flattenCss(stripComments(css))
    .filter((r) => r.media === null || holds(r.media))
    .map((r) => `${r.selectors.join(", ")} {${r.block}}`)
    .join("\n");
}

/** `css` with each rule written once per selector. jsdom drops a whole rule
 *  when one selector of its list names a pseudo-element
 *  (`*, *::before, *::after`), where a browser applies the others, and it
 *  gives a list the specificity of its strongest selector, where a browser
 *  gives each its own; split, each applies as in a browser (the cascade is
 *  the same: specificity is per selector, and the order is kept). */
export function perSelector(css: string): string {
  return flattenCss(stripComments(css))
    .flatMap((r) => r.selectors.map((sel) => (r.media ? `${r.media} { ${sel} {${r.block}} }` : `${sel} {${r.block}}`)))
    .join("\n");
}

/** The WCAG 2 contrast ratio of two opaque colors, each `#rgb`, `#rrggbb`,
 *  `rgb(r, g, b)` or `color(srgb r g b)` (what jsdom computes, the latter for
 *  a `color-mix()` such as an opened row's ground): 1 to 21, text needs 4.5 (AA). The
 *  tests of text on a filled color in both themes (dashboard.md §4.25k).
 *  A color it cannot read throws: a ratio is never guessed. */
export function contrastRatio(a: string, b: string): number {
  const rgb = (c: string): number[] => {
    const v = c.trim().toLowerCase();
    const hex = /^#([0-9a-f]{3}|[0-9a-f]{6})$/.exec(v)?.[1];
    if (hex) {
      const h = hex.length === 3 ? [...hex].map((d) => d + d).join("") : hex;
      return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
    }
    const m = /^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*1(?:\.0*)?\s*)?\)$/.exec(v);
    if (m) return [m[1], m[2], m[3]].map(Number);
    const srgb = /^color\(srgb\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*(?:\/\s*1(?:\.0*)?\s*)?\)$/.exec(v);
    if (srgb) return [srgb[1], srgb[2], srgb[3]].map((x) => Number(x) * 255);
    throw new Error(`contrastRatio: cannot read the color "${c}"`);
  };
  const lum = (c: string): number => {
    const [r, g, b] = rgb(c).map((x) => {
      const s = x / 255;
      return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
  };
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
}

/** The CSS system colors (CSS Color 4 §6.2): the palette's own, the only
 *  colors a browser keeps under forced colors. Lower case. */
export const SYSTEM_COLORS: readonly string[] = [
  "canvas", "canvastext", "linktext", "visitedtext", "activetext", "buttonface", "buttontext", "buttonborder",
  "field", "fieldtext", "highlight", "highlighttext", "selecteditem", "selecteditemtext", "mark", "marktext",
  "graytext", "accentcolor", "accentcolortext",
];
/** The properties a browser forces under forced colors (CSS Color Adjust 1
 *  §3.1) that the two stylesheets set: their colors, and the shadows. */
const FORCED_PROPS = /^(color|background(-color)?|border(-(top|right|bottom|left))?(-color)?|border-color|outline(-color)?|text-decoration(-color)?|column-rule(-color)?|caret-color|accent-color|fill|stroke|box-shadow|text-shadow)$/;
/** Words of a value that name a color: a function, a hex, or a keyword. */
const COLOR_WORD = /^(#[0-9a-f]{3,8}|(rgba?|hsla?|hwb|lab|lch|oklab|oklch|color|color-mix)\(.*\)|var\(.*\)|transparent|white|black|red|green|blue|gray|grey|orange|yellow|purple|silver|navy)$/i;

/** Is `value` (one word, or a whole declared value) a system color? */
export function isSystemColor(value: string): boolean {
  return SYSTEM_COLORS.includes(value.trim().toLowerCase());
}

/** A model of what a browser in forced-colors mode draws of `css` (CSS
 *  Color Adjust 1 §3.1), for jsdom, which forces nothing. Give it the
 *  sheet as `stylesAt(…, { forcedColors: true })` and `resolveCssVars`
 *  leave it. Every color a rule gives a forced property is the palette's
 *  instead, unless it is a system color, which the browser keeps: a fill
 *  (`background`) becomes `Canvas`, the page's own color, so it is drawn
 *  and not seen (`none` and `transparent` stay, as the browser keeps a
 *  fill's alpha); any other color, a `transparent` edge too (Chromium draws
 *  it), becomes `CanvasText`. Box and text shadows are dropped. Widths,
 *  styles, positions and weights stay. A model, not the browser: it gives
 *  a button or a link no palette pair of its own, and draws no backplate
 *  behind words (the browser draws the page's color there). */
export function forcedColorsModel(css: string): string {
  const force = (prop: string, value: string): string => {
    if (prop === "box-shadow" || prop === "text-shadow") return "none";
    const fill = prop === "background" || prop === "background-color";
    return splitValue(value).map((w) => {
      if (isSystemColor(w) || /^(currentcolor|inherit|initial|unset|none)$/i.test(w)) return w;
      if (fill && /^transparent$/i.test(w)) return w;
      if (!COLOR_WORD.test(w)) return w;
      return fill ? "Canvas" : "CanvasText";
    }).join(" ");
  };
  return flattenCss(stripComments(css)).map((r) => {
    const block = r.block.split(";").map((decl) => {
      const colon = decl.indexOf(":");
      if (colon === -1) return decl;
      const prop = decl.slice(0, colon).trim().toLowerCase();
      if (!FORCED_PROPS.test(prop)) return decl;
      const raw = decl.slice(colon + 1).trim();
      const important = /\s*!important$/i.exec(raw)?.[0] ?? "";
      return ` ${prop}: ${force(prop, raw.slice(0, raw.length - important.length))}${important}`;
    }).join(";");
    const rule = `${r.selectors.join(", ")} {${block}}`;
    return r.media ? `${r.media} { ${rule} }` : rule;
  }).join("\n");
}
