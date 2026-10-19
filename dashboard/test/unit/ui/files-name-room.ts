/**
 * files-name-room.ts — the name column of Rules' file rows, from the
 * stylesheet's own numbers (dashboard.md §4.25p *The name keeps its room*).
 * Shared by the unit test (`css-files-name-room.test.ts`, the stylesheet on
 * disk) and the stack test (`tests/stack/rules-name-room.test.ts`, the
 * served one).
 *
 * jsdom lays out nothing, so the width a row's `minmax(0, 1fr)` name
 * column gets in a window `w` px wide is computed here: #main (border-box,
 * its `max-width`) less its side padding, the card's padding and border,
 * the Add a rule panel's for the browser, the list's border and the row's
 * side padding, then less the row's fixed tracks and gaps. The model is the
 * page frame as the stylesheet writes it (px, vw and clamp()); anything
 * else it meets throws, so a frame change fails a test rather than
 * drifting. Checked against a headless Chromium: Your rules 298.94 px and
 * the browser 216.94 px at 1001 px, Your rules 41.34 px at 721 px under the
 * old 720 px query.
 *
 * Where a row has two such tracks (the middle layout, 2026-10-15: the name
 * across both, the two menus side by side under it), each gets half of
 * what is left: the width of each menu's column. Checked against the same
 * Chromium: the browser's columns are 257.45 px at 801 px.
 */
import { declValue, flattenCss, stripComments } from "./css-flatten.js";

/** The least a file row's name column may have beside its menus. */
export const NAME_MIN = 200;

/** Each list of file rows: its row's selector, the selector that pads it,
 *  and the padded boxes it sits in inside its card, outermost first. */
export const FILE_LISTS = [
  { list: "Your rules", row: ".row.file-rule", pad: ".row.file-rule", boxes: [] as string[] },
  { list: "Add a rule's browser", row: ".row.file:not(.up)", pad: ".row.file", boxes: [".lock-form"] },
  { list: "Keys Mandu found", row: ".row.file:not(.up)", pad: ".row.file", boxes: [] as string[] },
] as const;
export type FileList = (typeof FILE_LISTS)[number];

/** The top-level parts of a value, parens balanced (`a clamp(b, c, d) e`). */
function parts(value: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const c of value.trim()) {
    if (c === "(") depth++;
    if (c === ")") depth--;
    if (depth === 0 && /\s/.test(c)) { if (cur) out.push(cur); cur = ""; } else cur += c;
  }
  if (cur) out.push(cur);
  return out;
}
/** A length in px at window width `w`: px, vw and clamp() of those. */
export function px(expr: string, w: number): number {
  const s = expr.trim();
  const clamp = /^clamp\((.+),(.+),(.+)\)$/.exec(s);
  if (clamp) return Math.min(Math.max(px(clamp[2]!, w), px(clamp[1]!, w)), px(clamp[3]!, w));
  const m = /^(\d+(?:\.\d+)?)(px|vw)$/.exec(s);
  if (m) return m[2] === "px" ? Number(m[1]) : (Number(m[1]) * w) / 100;
  if (s === "0") return 0;
  throw new Error(`files-name-room: cannot read the length "${expr}"`);
}
/** The left and right of a `padding` shorthand, in px. */
export function sidePadding(value: string, w: number): number {
  const p = parts(value);
  const right = p.length === 1 ? p[0]! : p[1]!;
  const left = p.length === 4 ? p[3]! : right;
  return px(left, w) + px(right, w);
}
/** The width of a `border` shorthand (`1px solid var(--line)`), in px. */
function borderWidth(value: string): number {
  const m = /^(\d+(?:\.\d+)?)px\b/.exec(value.trim());
  if (!m) throw new Error(`files-name-room: not a border in px: "${value}"`);
  return Number(m[1]);
}
/** Does a width query hold in a window `width` px wide? As css-flatten's
 *  stylesAt reads one: every other query does not. */
function holds(media: string, width: number): boolean {
  const m = /^@media (.+)$/.exec(media);
  return !!m && m[1]!.split(/\s+and\s+/).every((part) => {
    const q = /^\((max|min)-width:\s*(\d+(?:\.\d+)?)px\)$/.exec(part.trim());
    return !!q && (q[1] === "max" ? width <= Number(q[2]) : width >= Number(q[2]));
  });
}

/** The least each menu's column has where the two menus sit side by side
 *  under the name: at least what the wide layout gives it beside the name
 *  (its 240 px and 230 px tracks, 220 and 250 until 2026-10-17), so the
 *  middle layout cuts no menu that the wide one draws whole. Both columns
 *  are alike, so both need the larger; 250 px, as before, is more. */
export const MENU_MIN = 250;

/** The wide layout's two menu tracks beside the name: the first menu
 *  (which AI may read it), then the second (where it may be sent). */
export const WIDE_MENUS = ["240px", "230px"] as const;

/** The row keeps its menus beside the name (its wide tracks). */
export function wideTracks(tracks: string[]): boolean {
  return WIDE_MENUS.every((t) => tracks.includes(t));
}
/** The row puts its two menus side by side under the name: two
 *  `minmax(0, 1fr)` tracks (spaces dropped), the name across both. */
export function middleTracks(tracks: string[]): boolean {
  return tracks.filter((t) => t === "minmax(0,1fr)").length === 2;
}

/** The model over the product page's stylesheet text `css` (mandu.css and
 *  app.css, as index.html links them). */
export function fileNameRoom(css: string) {
  const bySelector = new Map<string, Array<{ block: string; media: string | null }>>();
  for (const r of flattenCss(stripComments(css))) for (const s of r.selectors) bySelector.set(s, [...(bySelector.get(s) ?? []), r]);
  /** The value of `prop` for exactly `selector` in a window `width` px
   *  wide: the last declaration the cascade reaches (each selector read
   *  here is declared under one spelling, so order decides). */
  const at = (width: number, selector: string, prop: string): string => {
    const found = (bySelector.get(selector) ?? []).filter((r) => r.media === null || holds(r.media, width)).map((r) => declValue(r.block, prop)).filter((v): v is string => v !== null);
    if (found.length === 0) throw new Error(`files-name-room: ${selector} declares no ${prop} at ${width}px`);
    return found[found.length - 1]!;
  };
  /** The width of #main's content box, the page's column, in a window
   *  `w` px wide (the session page's tiles span it: tiles-rows.ts). */
  const pageColumn = (w: number): number => {
    if (at(w, "*", "box-sizing") !== "border-box") throw new Error("files-name-room: the model needs every box sized border-box");
    return Math.min(w, px(at(w, "#main", "max-width"), w)) - sidePadding(at(w, "#main", "padding"), w);
  };
  /** The width of a row's content box in a window `w` px wide. */
  const rowContent = (l: FileList, w: number): number => {
    let width = pageColumn(w);
    for (const box of [".card", ...l.boxes]) width -= sidePadding(at(w, box, "padding"), w) + 2 * borderWidth(at(w, box, "border"));
    width -= 2 * borderWidth(at(w, ".table", "border"));
    return width - sidePadding(at(w, l.pad, "padding"), w);
  };
  /** The row's tracks at `w` (spaces in a track dropped), and the width
   *  of each of its `minmax(0, 1fr)` tracks: what the fixed tracks and the
   *  gaps leave, shared out. */
  const columns = (l: FileList, w: number): { tracks: string[]; fr: number } => {
    const tracks = parts(at(w, l.row, "grid-template-columns").replace(/,\s+/g, ","));
    const fr = tracks.filter((t) => t === "minmax(0,1fr)");
    if (fr.length === 0) throw new Error(`files-name-room: ${l.list} has no name column at ${w}px: ${tracks.join(" ")}`);
    const fixed = tracks.filter((t) => t !== "minmax(0,1fr)").reduce((s, t) => s + px(t, w), 0);
    const gaps = (tracks.length - 1) * px(at(w, l.pad, "gap"), w);
    return { tracks, fr: (rowContent(l, w) - fixed - gaps) / fr.length };
  };
  /** The row's tracks at `w`, and its name column's width: a row with one
   *  `minmax(0, 1fr)` track (the wide layout, or the menus stacked under
   *  the name). */
  const nameColumn = (l: FileList, w: number): { tracks: string[]; name: number } => {
    const c = columns(l, w);
    if (c.tracks.filter((t) => t === "minmax(0,1fr)").length !== 1) throw new Error(`files-name-room: ${l.list} has no one name column at ${w}px: ${c.tracks.join(" ")}`);
    return { tracks: c.tracks, name: c.fr };
  };
  /** Every window from 320 to 1600 px where `l` keeps its columns, with
   *  its name column there. */
  const wideWindows = (l: FileList): Array<{ w: number; name: number; tracks: string[] }> => {
    const out: Array<{ w: number; name: number; tracks: string[] }> = [];
    for (let w = 320; w <= 1600; w++) {
      const c = columns(l, w);
      if (wideTracks(c.tracks)) out.push({ w, ...nameColumn(l, w) });
    }
    return out;
  };
  /** Every window from 320 to 1600 px where `l` puts its two menus side
   *  by side under the name, with each menu's column there. */
  const middleWindows = (l: FileList): Array<{ w: number; menu: number; tracks: string[] }> => {
    const out: Array<{ w: number; menu: number; tracks: string[] }> = [];
    for (let w = 320; w <= 1600; w++) {
      const c = columns(l, w);
      if (middleTracks(c.tracks)) out.push({ w, menu: c.fr, tracks: c.tracks });
    }
    return out;
  };
  return { at, pageColumn, rowContent, columns, nameColumn, wideWindows, middleWindows };
}

/** Each menu choice's words in px, as a headless Chromium draws them in
 *  the menus' 13 px IBM Plex Sans with the served fonts (canvas
 *  measureText, 2026-10-17): [regular, medium]. A closed menu shows its
 *  chosen words in its box less its side padding (its dot and its arrow),
 *  and cuts them with an ellipsis where they need more. A choice the page
 *  shows that is not here fails M2: measure it and add it. */
export const MENU_WORDS: Readonly<Record<string, readonly [number, number]>> = {
  "No rule": [42, 43],
  "Remove my rule": [92, 96],
  "No AI": [32, 33],
  "Your own AI only": [96, 101],
  "Your own AI only (none listed)": [171, 178],
  "Any AI, when it asks": [115, 121],
  "Not secret": [61, 61],
  "No AI (inherited)": [95, 98],
  "Your own AI only (inherited)": [159, 166],
  "Any AI, when it asks (inherited)": [178, 186],
  "Not secret (inherited)": [124, 126],
  "Needs your OK": [85, 88],
  "Listed hosts without asking": [157, 161],
  "Per value": [54, 56],
};

/** What each closed menu can show, by the weight it shows it at (home.js
 *  labelPick, sendPick, perValuePick; app.css draws an inherited choice
 *  regular, `.label-pick[data-from] select`, else medium). The first menu:
 *  the rule of the person's own, a change waiting, or none (medium; "(none
 *  listed)" when no model of your own is listed), or the label it inherits
 *  (regular). The second menu: a rule of the person's own (medium), or
 *  the choice of an inherited label, greyed, with no "(inherited)"
 *  (regular; "Listed hosts without asking (inherited)" needed 278 px and
 *  was cut until 2026-10-19). */
export const MENU_CHOICES = {
  label: {
    medium: ["No rule", "Remove my rule", "No AI", "Your own AI only", "Your own AI only (none listed)", "Any AI, when it asks", "Not secret"],
    regular: ["No AI (inherited)", "Your own AI only (inherited)", "Any AI, when it asks (inherited)", "Not secret (inherited)"],
  },
  send: {
    medium: ["No rule", "Needs your OK", "Listed hosts without asking", "Not secret", "Per value"],
    regular: ["Needs your OK", "Listed hosts without asking", "Not secret", "Per value"],
  },
} as const;

/** The width a closed menu needs to show each of `choices` whole at
 *  `weight`: the longest plus `padding`. */
export function menuNeeds(choices: readonly string[], weight: "regular" | "medium", padding: number): number {
  return Math.max(...choices.map((c) => {
    const w = MENU_WORDS[c];
    if (!w) throw new Error(`files-name-room: no measured width for the menu choice "${c}"`);
    return w[weight === "regular" ? 0 : 1];
  })) + padding;
}
