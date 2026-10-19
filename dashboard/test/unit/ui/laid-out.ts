/**
 * laid-out — an inspector page laid out in jsdom the way a browser lays it
 * out, for the sub-menus' scroll spy (dev/js/sub-menus.js, dashboard.md
 * §4.34). jsdom lays out nothing: every box is at 0 and the window never
 * scrolls. `layOut` gives each section its top on the page (by id), and the
 * window and the page a height. A jump (scrollIntoView, block start) then
 * moves the page as a browser does: the section goes to the top of the
 * window, under its scroll margin, unless the page ends first. A `scroll`
 * event fires only when the page moved. The person's own scroll (`hand`)
 * comes from an input, as in a browser: a `wheel` first, whether or not the
 * page can move.
 *
 * The spy's line and where a jump lands are read from --topbar-h, and jsdom
 * reads no stylesheet, so both use its fallback (41px): the line is at
 * 41 + 24, and a section lands at 41 + 12 (the window's room above what it
 * scrolls into view, html's scroll-padding-top, 41 + 8, and the section's
 * own 4px margin; a desktop has no sub-menu row, inspector-topbar-room
 * .test.ts). The tops below were measured in
 * headless Chromium at 1280×800 over the served tour session. Chromium's top
 * bar is 56px, so each top is taken 12px lower here.
 * Used by dev-product-words.test.ts and tests/stack/inspector-sub-menu-mark.
 *
 * `layOutRows` lays a phone's sub-menu rows out sideways too, for the row
 * that shows its marked entry (inspector-sub-menu-row.test.ts,
 * tests/stack/inspector-sub-menu-row).
 */

export const SCROLL_MARGIN = 41 + 12;
export const VIEWPORT = 800;
/** Settings at 1280×800: the page is 1227px high, so its last four sections never reach the top. */
export const SETTINGS_PAGE = {
  page: 1227,
  tops: { "control-panel": 64, "sandbox-panel": 141, "protection-machinery-panel": 779, "dashboard-panel": 960, "appearance-panel": 1037, "slides-panel": 1100 } as Record<string, number>,
};
/** Rules at 1280×800: 3274px high, so Audit trail and Test a flow never reach the top. */
export const RULES_PAGE = {
  page: 3274,
  tops: { "protection-panel": 64, "rules-answers": 1077, "rules-yours": 1197, "rules-builtin": 1364, "prompt-filters-panel": 1698, "secrets-panel": 2322, "rules-audit-panel": 2860, "rules-test-panel": 3010 } as Record<string, number>,
};

/** A phone (390×844): the sub-menu is one row, 46px high, that sticks under
 *  an 82px bar, and the window keeps the row's room too, so a section lands
 *  under the row (inspector-topbar-room.test.ts). The tops were measured in
 *  headless Chromium over the served tour session, each taken 41px higher
 *  (82 - 41: jsdom's bar keeps its fallback). Used by
 *  tests/stack/inspector-topbar-room. */
export const PHONE_VIEWPORT = 844;
export const PHONE_ROW = 46;
export const RULES_PHONE = {
  page: 4780 - 41,
  tops: { "protection-panel": 117, "rules-answers": 1770, "rules-yours": 1908, "rules-builtin": 2127, "prompt-filters-panel": 2661, "secrets-panel": 3359, "rules-audit-panel": 4055, "rules-test-panel": 4204 } as Record<string, number>,
};
export const SETTINGS_PHONE = {
  page: 2058 - 41,
  tops: { "control-panel": 117, "sandbox-panel": 227, "protection-machinery-panel": 1416, "dashboard-panel": 1745, "appearance-panel": 1839, "slides-panel": 1902 } as Record<string, number>,
};

export interface LaidOut {
  /** The person's own scroll to `to`, clamped as a browser clamps it. */
  hand(to: number): void;
  /** Where the page is scrolled to. */
  y(): number;
  /** The furthest the page scrolls. */
  max: number;
}

/** Lay out window `w`: `tops` by element id (any other element is at the
 *  page's top), a `viewport`-high window over a `page`-high page.
 *  `jumped` hears each scrollIntoView's element id; a jump puts its section
 *  `landing` px under the window's top (a desktop's by default). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function layOut(w: any, tops: Record<string, number>, viewport: number, page: number, jumped?: (id: string) => void, landing = SCROLL_MARGIN): LaidOut {
  const doc = w.document;
  let y = 0;
  const max = page - viewport;
  const moveTo = (to: number): void => {
    const next = Math.max(0, Math.min(max, to));
    if (next === y) return;
    y = next;
    w.dispatchEvent(new w.Event("scroll"));
  };
  Object.defineProperty(w, "scrollY", { configurable: true, get: () => y });
  Object.defineProperty(doc.documentElement, "clientHeight", { configurable: true, get: () => viewport });
  Object.defineProperty(doc.documentElement, "scrollHeight", { configurable: true, get: () => page });
  w.Element.prototype.getBoundingClientRect = function (this: { id: string }) {
    const top = (tops[this.id] ?? 0) - y;
    return { top, bottom: top + 40, left: 0, right: 0, width: 0, height: 40, x: 0, y: top };
  };
  w.Element.prototype.scrollIntoView = function (this: { id: string }) {
    jumped?.(this.id);
    moveTo((tops[this.id] ?? 0) - landing);
  };
  const hand = (to: number): void => {
    doc.documentElement.dispatchEvent(new (w.WheelEvent ?? w.Event)("wheel", { bubbles: true, deltaY: to - y }));
    moveTo(to);
  };
  return { hand, y: () => y, max };
}

/** A phone's sub-menu rows (390×844) as headless Chromium lays them out
 *  over the served tour session: 370px wide, 10px from the window's left,
 *  each entry's offset in its row and its width (2px apart). Rules' row is
 *  895px long and Settings' 647px, so both scroll sideways. */
export const ROW_LEFT = 10;
export const ROW_WIDTH = 370;
export const RULES_ROW: Record<string, [number, number]> = {
  level: [0, 163], answers: [165, 155], yours: [322, 95], "built-in": [419, 118],
  "prompt-filters": [539, 111], secrets: [652, 75], audit: [729, 80], test: [811, 84],
};
export const SETTINGS_ROW: Record<string, [number, number]> = {
  services: [0, 79], sandbox: [81, 127], axes: [210, 113], dashboard: [325, 125], appearance: [452, 93], docs: [547, 100],
};

export interface LaidOutRows {
  /** Each sideways scroll a script gave a row (scrollLeft), by menu id. */
  writes: Array<{ id: string; left: number }>;
  /** How far the row of `menuId` is scrolled. */
  left(menuId: string): number;
  /** The person's own swipe of a row (no write heard). */
  swipe(menuId: string, to: number): void;
  /** True when the entry of `key` is whole in the part of its row shown. */
  whole(menuId: string, key: string): boolean;
  /** The furthest the row of `menuId` scrolls. */
  room(menuId: string): number;
  /** The rows' width from now on (a window resized). */
  resize(width: number): void;
}

/** Lay out the sub-menu rows of window `w` sideways, `rows` by menu id, each
 *  entry by its key: the row's box (`width` wide), its scroll width and the
 *  entries' boxes, moved by the row's scroll, which is clamped to its ends
 *  as a browser clamps it. A row its entries fit in does not scroll, as a
 *  menu beside the sections does not. Call it after layOut, whose boxes it
 *  keeps for every other element. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function layOutRows(w: any, rows: Record<string, Record<string, [number, number]>>, width = ROW_WIDTH): LaidOutRows {
  const at = new Map<string, number>();
  let view = width;
  const length = (id: string): number => Math.max(view, ...Object.values(rows[id]!).map(([l, wd]) => l + wd));
  const room = (id: string): number => length(id) - view;
  const rowId = (x: El): string | null => (x && x.id && rows[x.id] ? x.id : null);
  const proto = w.HTMLElement.prototype;
  const below = w.Element.prototype.getBoundingClientRect;
  w.Element.prototype.getBoundingClientRect = function (this: El) {
    const box = below.call(this);
    if (rowId(this)) return { ...box, left: ROW_LEFT, right: ROW_LEFT + view, width: view, x: ROW_LEFT };
    const menu = this.matches("a[data-sub-key]") ? this.closest("nav.sub-menu") : null;
    const e = rowId(menu) ? rows[menu.id]![this.dataset.subKey] : undefined;
    if (!e) return box;
    const left = ROW_LEFT + e[0] - (at.get(menu.id) ?? 0);
    return { ...box, left, right: left + e[1], width: e[1], x: left };
  };
  const move = (id: string, to: number): void => { at.set(id, Math.max(0, Math.min(room(id), Number(to) || 0))); };
  const writes: LaidOutRows["writes"] = [];
  Object.defineProperty(proto, "scrollLeft", {
    configurable: true,
    get(this: El) { const id = rowId(this); return id ? (at.get(id) ?? 0) : 0; },
    set(this: El, v: number) { const id = rowId(this); if (id) { writes.push({ id, left: v }); move(id, v); } },
  });
  Object.defineProperty(proto, "clientWidth", { configurable: true, get(this: El) { return rowId(this) ? view : 0; } });
  Object.defineProperty(proto, "clientLeft", { configurable: true, get() { return 0; } });
  Object.defineProperty(proto, "scrollWidth", { configurable: true, get(this: El) { const id = rowId(this); return id ? length(id) : 0; } });
  return {
    writes,
    left: (id) => at.get(id) ?? 0,
    swipe: move,
    whole: (id, key) => {
      const e = rows[id]![key]!;
      const left = e[0] - (at.get(id) ?? 0);
      return left >= 0 && left + e[1] <= view;
    },
    room,
    resize: (n) => { view = n; for (const id of at.keys()) move(id, at.get(id)!); },
  };
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
