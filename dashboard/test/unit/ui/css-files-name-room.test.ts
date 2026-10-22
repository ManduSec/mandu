/**
 * css-files-name-room — on Rules, a file row's name keeps its room
 * (dashboard.md §4.25p *The name keeps its room*). Mandu-new.
 *
 * Three lists draw file rows: Your rules (`#files-tree`, `.row.file-rule`),
 * Add a rule's browser (`#files-list`, `.row.file`) and Keys Mandu found
 * (`#files-suggested-list`, `.row.file`). Each row is a grid of the name
 * and two fixed menus (240 px and 230 px; 220 and 250 until 2026-10-17,
 * M2), and until 2026-10-15 the menus
 * went under the name only at 720 px and below. A headless Chromium
 * measured the name column of Your rules at 41 px in a 721 px window, 114 px
 * at 800 and 188 px at 880; the browser's, in its padded Add a rule panel,
 * had none at 721 and 32 px at 800. Names and their *Opens it* line were
 * drawn a letter or two per line. Now every file row puts its menus under
 * the name up to 1000 px, and wider than that the name has at least 200 px
 * in every list. From 801 to 1000 px (2026-10-15, the middle layout) the
 * two menus sit side by side under the name, each in half of the row:
 * stacked, a rule there was about 2.5 times as tall as beside the name
 * (Chromium, six rules: 1298 px at 860 px, 506 px at 1001 px; 920 px at
 * 860 px now). At 800 px and below they stack as before.
 *
 * jsdom has no layout, so:
 *   N1  the geometry, from the stylesheet's own numbers (`#main`'s side
 *       padding and max-width, the card's and the Add a rule panel's
 *       padding and border, the list's border, each row's padding, gap and
 *       tracks): at every window width where a file row keeps its columns,
 *       the name column of each list is at least 200 px, and the columns
 *       are kept on a wide window;
 *   N2  the narrow rules of the file rows are in two width queries: the
 *       heads, the captions, the middle layout and the opened parts in one
 *       (1000 px), the stacked menus in a narrower one after it, so each
 *       layout changes together in the three lists;
 *   N3  the page as an 860 px window draws the three lists in the middle
 *       layout (the heads hidden, the name across the row, each menu in
 *       its own column under it with its caption), an 800 px window stacks
 *       the menus, and a 1001 px window keeps the columns;
 *   M1  the geometry again: wherever the menus sit side by side, each
 *       menu's column in every list is at least as wide as the wide
 *       layout gives a menu beside the name (250 px), so the middle layout
 *       cuts no menu the wide one draws whole; the browser's is the
 *       tightest, 257 px at 801 px, and would be 221 px at 721 px;
 *   M2  beside the name, each menu's column shows every choice it can
 *       show whole (Chromium's widths of the words, files-name-room.ts
 *       MENU_WORDS): the first menu's 240 px fits "Your own AI only (none
 *       listed)" and "Any AI, when it asks (inherited)" (236 px each with
 *       the padding), which the 220 px column before 2026-10-17 cut; the
 *       second menu's 230 px fits "Listed hosts without asking" (219 px),
 *       and so, greyed for an inherited label, with no "(inherited)"
 *       (215 px; 278 px with the word, cut until 2026-10-19); and every
 *       choice the page shows in the three lists is measured.
 * The layout itself is the runs' Chromium probes (before and after: the
 * name column of each list at 721 to 1100 px; the rows' heights and the
 * menus' columns at 721 to 1001 px).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { FILES_ROUTES, FILES_URL, PUB, load, tick } from "./home-js-fixtures.js";
import { declValue, flattenCss, resolveCssVars, stripComments, stylesAt } from "./css-flatten.js";
import { FILE_LISTS, MENU_CHOICES, MENU_MIN, MENU_WORDS, NAME_MIN, WIDE_MENUS, fileNameRoom, menuNeeds, middleTracks, px, sidePadding, wideTracks } from "./files-name-room.js";
import { suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** The product page's own styles, as index.html links them. */
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
const ROOM = fileNameRoom(CSS);

test("N1: wherever a file row keeps its columns, its name has at least 200 px in every list, and a wide window keeps the columns", () => {
  // The model against the run's Chromium probe (1001 px, after).
  assert.equal(Math.round(ROOM.nameColumn(FILE_LISTS[0], 1001).name), 299, "Your rules at 1001 px: Chromium measured 298.94 px");
  assert.equal(Math.round(ROOM.nameColumn(FILE_LISTS[1], 1001).name), 217, "the browser at 1001 px: Chromium measured 216.94 px");
  for (const l of FILE_LISTS) {
    const windows = ROOM.wideWindows(l);
    assert.ok(windows.length > 0, `${l.list}: some window keeps the columns`);
    for (const { w, name, tracks } of windows) {
      assert.ok(name >= NAME_MIN, `${l.list}: in a ${w}px window the name column is ${name.toFixed(1)}px beside the menus (${tracks.join(" ")}); it needs ${NAME_MIN}px, else the menus go under the name`);
    }
    assert.ok(wideTracks(ROOM.nameColumn(l, 1280).tracks), `${l.list}: a 1280px window keeps the menus beside the name`);
    assert.ok(!wideTracks(ROOM.nameColumn(l, 390).tracks), `${l.list}: a phone puts the menus under the name`);
  }
});

test("N2: the heads, the captions, the middle layout and the opened parts go narrow in one width query; the stacked menus in a narrower one after it", () => {
  const rules = flattenCss(stripComments(CSS));
  /** The width queries holding `selector`'s `prop: value`, with each
   *  rule's place in the sheet. */
  const where = (selector: string, prop: string, value: string): Array<{ media: string; at: number }> =>
    rules.flatMap((r, at) => (r.selectors.includes(selector) && declValue(r.block, prop) === value ? [{ media: String(r.media), at }] : []));
  /** Each rule declared once, all in one width query: that query, and
   *  where its rules sit in the sheet. */
  const oneQuery = (what: string, decls: Array<[string, string, string]>): { media: string; first: number; last: number } => {
    const found = decls.map(([s, p, v]) => {
      const f = where(s, p, v);
      assert.equal(f.length, 1, `${what}: ${s} { ${p}: ${v} } is declared once: ${JSON.stringify(f)}`);
      return f[0]!;
    });
    assert.deepEqual([...new Set(found.map((f) => f.media))], [found[0]!.media], `${what}: one width query for all: ${JSON.stringify(decls.map(([s], i) => `${s} @ ${found[i]!.media}`))}`);
    return { media: found[0]!.media, first: Math.min(...found.map((f) => f.at)), last: Math.max(...found.map((f) => f.at)) };
  };
  const middle = oneQuery("the middle layout", [
    [".files-heads", "display", "none"],
    [".q-cap", "display", "block"],
    [".row.file-rule", "grid-template-columns", "minmax(0, 1fr) minmax(0, 1fr) 32px"],
    [".row.file:not(.up)", "grid-template-columns", "20px minmax(0, 1fr) minmax(0, 1fr) 32px"],
    [".row.file-rule > .file-cell", "grid-column", "1 / 3"],
    [".row.file:not(.up) > .file-cell", "grid-column", "2 / 4"],
    [".row.file-rule > .q-cell", "grid-column", "1"],
    [".row.file-rule > .q-cell + .q-cell", "grid-column", "2"],
    [".row.file > .q-cell", "grid-column", "2"],
    [".row.file > .q-cell + .q-cell", "grid-column", "3"],
    [".row.file > .label-chip", "grid-column", "2"],
    [".row.file > .file-hosts", "grid-column", "3"],
    [".row.file-rule .file-more", "grid-column", "3"],
    [".row.file .file-more", "grid-column", "4"],
    [".file-detail", "grid-template-columns", "minmax(0, 1fr)"],
    ["#files-list .file-detail", "grid-template-columns", "minmax(0, 1fr)"],
    [".files-suggested .file-detail", "padding-left", "16px"],
  ]);
  const stacked = oneQuery("the stacked menus", [
    [".row.file-rule", "grid-template-columns", "minmax(0, 1fr) 32px"],
    [".row.file:not(.up)", "grid-template-columns", "20px minmax(0, 1fr) 32px"],
    [".row.file-rule > .file-cell", "grid-column", "1"],
    [".row.file:not(.up) > .file-cell", "grid-column", "2"],
    [".row.file-rule > .q-cell", "grid-column", "1 / -1"],
    [".row.file-rule > .q-cell + .q-cell", "grid-column", "1 / -1"],
    [".row.file > .q-cell", "grid-column", "2 / -1"],
    [".row.file > .q-cell + .q-cell", "grid-column", "2 / -1"],
    [".row.file > .label-chip", "grid-column", "2 / -1"],
    [".row.file > .file-hosts", "grid-column", "2 / -1"],
    [".row.file-rule .file-more", "grid-column", "2"],
    [".row.file .file-more", "grid-column", "3"],
  ]);
  assert.equal(middle.media, "@media (max-width: 1000px)", "the middle layout starts below 1001 px, where the name has its 200 px beside the menus");
  const m = /^@media \(max-width: (\d+)px\)$/.exec(stacked.media);
  assert.ok(m && Number(m[1]) < 1000, `the stacked menus are in a narrower width query: ${stacked.media}`);
  assert.ok(stacked.first > middle.last, "the stacked menus come after the middle layout, so they win where both queries hold");
});

// ── N3: the page at 860, 800 and 1001 px ─────────────────────────────────────

const lockRow = (path: string, covers: "subtree" | "exact", effect = "No AI") => ({
  id: `lock:${path}`, kind: "lock", subject: path, effect: "x", reach: null, hits: null, covers, bindings: [],
  level: effect === "Any AI, when it asks" ? "any-model" : "no-model", actions: { remove: true, flip: null },
  plain: { subject: path, reach: covers === "subtree" ? "and everything inside" : "this file only", effect },
});
const PANEL = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [
  lockRow("/home/u/proj", "subtree"),
  lockRow("/home/u/proj/deploy/staging.conf", "exact", "Any AI, when it asks"),
  lockRow("/home/u/proj/notes/contract.md", "exact"),
] } };
const KEY: SuggestionWire = {
  id: "pp-000001", kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: "workspace:path:/home/u/proj/services/api/app.conf", source: "workspace", repoRoot: "/home/u/proj",
  edits: [{ op: "lock-path", path: "/home/u/proj/services/api/app.conf", level: "no-model" }],
  sentence: "Make ~/proj/services/api/app.conf a secret no AI may read",
  evidence: { paths: ["services/api/app.conf"], blobs: [], historyOnly: false,
    findings: [{ blob: "", paths: ["services/api/app.conf"], firstCommit: null, lastCommit: null, inHead: false, inIndex: false, stillPresent: true,
      detectors: [{ kind: "content-shape", rule: "github-token", mask: "ghp_…", words: "GitHub token", line: 2 }] }] },
  impact: { historicalVersions: 0, workingTreeChanges: true, files: ["services/api/app.conf"] },
  historyOnly: false, rotate: false, applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
} as SuggestionWire;

/** Rules with all three lists drawn (Add a rule and Keys Mandu found
 *  opened), the page's styles as a `width` px window applies them. */
async function rulesAt(width: number): Promise<El> {
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET policy/panel": PANEL, "GET suggestions": { suggestions: suggestionRows([KEY], "/home/u", "linux"), count: 1, scan: null } } });
  await tick();
  doc.getElementById("rules-add").click();
  doc.getElementById("suggest-open").click();
  await tick();
  const sheet = doc.createElement("style");
  sheet.textContent = resolveCssVars(stylesAt(CSS, width));
  doc.head.append(sheet);
  return doc;
}
/** Each list's rows: the row's tracks, the columns its name takes, and
 *  where its label sits: per menu cell (Your rules, the browser) the
 *  columns it takes and whether its caption shows, or the columns a
 *  suggestion's label chip and hosts take (Keys Mandu found). */
function drawn(doc: El): Record<string, Array<{ tracks: string; name: string; label: string[] }>> {
  const win = doc.defaultView;
  const col = (e: El): string => win.getComputedStyle(e).gridColumn || "auto";
  const out: Record<string, Array<{ tracks: string; name: string; label: string[] }>> = {};
  for (const [name, sel] of [["tree", "#files-tree .row.file-rule"], ["browser", "#files-list .row.file:not(.up)"], ["found", "#files-suggested-list .row.file.suggested"]] as const) {
    out[name] = ([...doc.querySelectorAll(sel)] as El[]).map((r) => {
      assert.ok(!/grid/.test(r.getAttribute("style") ?? ""), `${name}: no inline tracks, the stylesheet decides`);
      const cells = ([...r.querySelectorAll(":scope > .q-cell")] as El[]).map((c) => `${col(c)} caption ${win.getComputedStyle(c.querySelector(".q-cap")).display}`);
      const chips = ([...r.querySelectorAll(":scope > .label-chip, :scope > .file-hosts")] as El[]).map((c) => `${c.classList.contains("label-chip") ? "chip" : "hosts"} ${col(c)}`);
      return { tracks: win.getComputedStyle(r).gridTemplateColumns, name: col(r.querySelector(":scope > .file-cell")), label: [...cells, ...chips] };
    });
    assert.ok(out[name]!.length > 0, `${name}: rows are drawn`);
  }
  return out;
}

test("N3: at 860 px the three lists put the name across the row and the two menus side by side under it, each with its caption; at 800 px each menu goes on its own line; the heads are hidden in both; at 1001 px the columns are kept", async () => {
  const middle = await rulesAt(860);
  const mw = middle.defaultView;
  assert.equal(mw.getComputedStyle(middle.querySelector(".files-heads")).display, "none", "860px: the heads are hidden; each menu has its caption");
  const m = drawn(middle);
  for (const r of m.tree!) assert.deepEqual(r, { tracks: "minmax(0, 1fr) minmax(0, 1fr) 32px", name: "1 / 3", label: ["1 caption block", "2 caption block"] }, "860px: Your rules' name spans both menus' columns, and each menu has its own column under it, with its caption");
  for (const r of m.browser!) assert.deepEqual(r, { tracks: "20px minmax(0, 1fr) minmax(0, 1fr) 32px", name: "2 / 4", label: ["2 caption block", "3 caption block"] }, "860px: the browser's likewise, after the tick box");
  for (const r of m.found!) assert.deepEqual(r, { tracks: "20px minmax(0, 1fr) minmax(0, 1fr) 32px", name: "2 / 4", label: ["chip 2", "hosts 3"] }, "860px: a found key's label goes under its name, in the first menu's column");
  for (const c of middle.querySelectorAll("#files-tree .row.file-rule > .q-cell, #files-list .row.file > .q-cell")) assert.equal(mw.getComputedStyle(c).alignSelf, "start", "860px: the two cells' tops line up, so their captions do");
  for (const b of middle.querySelectorAll("#files-tree .row.file-rule > .file-more, #files-list .row.file > .file-more")) assert.equal(mw.getComputedStyle(b).gridRow, "1", "860px: ⋯ stays on the name's line");

  const narrow = await rulesAt(800);
  const win = narrow.defaultView;
  assert.equal(win.getComputedStyle(narrow.querySelector(".files-heads")).display, "none", "800px: the heads are hidden; each menu has its caption");
  const n = drawn(narrow);
  for (const r of n.tree!) assert.deepEqual(r, { tracks: "minmax(0, 1fr) 32px", name: "1", label: ["1 / -1 caption block", "1 / -1 caption block"] }, "800px: Your rules' menus go under the name, each across the row with its caption");
  for (const r of n.browser!) assert.deepEqual(r, { tracks: "20px minmax(0, 1fr) 32px", name: "2", label: ["2 / -1 caption block", "2 / -1 caption block"] }, "800px: the browser's menus go under the name, each across the row after the tick box");
  for (const r of n.found!) assert.deepEqual(r, { tracks: "20px minmax(0, 1fr) 32px", name: "2", label: ["chip 2 / -1", "hosts 2 / -1"] }, "800px: a found key's label goes under its name");

  const wideDoc = await rulesAt(1001);
  const w2 = wideDoc.defaultView;
  assert.equal(w2.getComputedStyle(wideDoc.querySelector(".files-heads")).display, "grid", "1001px: the heads name the columns");
  const d = drawn(wideDoc);
  for (const r of d.tree!) assert.deepEqual(r, { tracks: "minmax(0, 1fr) 240px 230px 32px", name: "auto", label: ["auto caption none", "auto caption none"] }, "1001px: Your rules keeps its columns");
  for (const r of d.browser!) assert.deepEqual(r, { tracks: "20px minmax(0, 1fr) 240px 230px 32px", name: "auto", label: ["auto caption none", "auto caption none"] }, "1001px: the browser keeps its columns");
  for (const r of d.found!) assert.deepEqual(r, { tracks: "20px minmax(0, 1fr) 240px 230px 32px", name: "auto", label: ["chip auto", "hosts auto"] }, "1001px: Keys Mandu found keeps its columns");
});

test("M1: wherever the two menus sit side by side under the name, each menu's column in every list is at least as wide as beside the name (250 px); every window from 801 to 1000 px does it, in all three lists", () => {
  // The model against the run's Chromium probe (801 px, after).
  assert.equal(Math.round(ROOM.columns(FILE_LISTS[0], 801).fr * 10) / 10, 298.5, "Your rules at 801 px: Chromium measured 298.5 px per menu");
  assert.equal(Math.round(ROOM.columns(FILE_LISTS[1], 801).fr * 10) / 10, 257.5, "the browser at 801 px: Chromium measured 257.5 px per menu");
  for (const l of FILE_LISTS) {
    const windows = ROOM.middleWindows(l);
    assert.deepEqual([windows[0]?.w, windows.at(-1)?.w, windows.length], [801, 1000, 200], `${l.list}: the menus sit side by side from 801 to 1000 px, one width rule for the three lists`);
    for (const { w, menu, tracks } of windows) {
      assert.ok(menu >= MENU_MIN, `${l.list}: in a ${w}px window each menu's column is ${menu.toFixed(1)}px (${tracks.join(" ")}); it needs ${MENU_MIN}px, else the menus go on their own lines`);
    }
    for (const w of [390, 800]) assert.ok(!middleTracks(ROOM.columns(l, w).tracks) && !wideTracks(ROOM.columns(l, w).tracks), `${l.list}: at ${w}px each menu goes on its own line`);
  }
});

// ── M2: beside the name, each menu says its words whole ─────────────────────

test("M2: beside the name, the first menu's column shows every label whole, \"Your own AI only (none listed)\" and \"Any AI, when it asks (inherited)\" included, and the second menu's every choice, a rule of your own or greyed and inherited; every choice shown is measured", async () => {
  const [labelTrack, sendTrack] = WIDE_MENUS;
  for (const l of FILE_LISTS) {
    for (const w of [1001, 1280, 1600]) {
      const { tracks } = ROOM.nameColumn(l, w);
      assert.ok(wideTracks(tracks), `${l.list}: ${w}px keeps the menus beside the name`);
      const pad = sidePadding(ROOM.at(w, ".label-pick select", "padding"), w);
      assert.equal(pad, 58, "a menu's side padding: its dot on the left, its arrow on the right");
      for (const weight of ["medium", "regular"] as const) {
        const need = menuNeeds(MENU_CHOICES.label[weight], weight, pad);
        assert.ok(need <= px(labelTrack, w), `${l.list} at ${w}px: the first menu needs ${need}px to show its ${weight} choices whole; its column is ${labelTrack}`);
      }
      for (const weight of ["medium", "regular"] as const) {
        const need = menuNeeds(MENU_CHOICES.send[weight], weight, pad);
        assert.ok(need <= px(sendTrack, w), `${l.list} at ${w}px: the second menu needs ${need}px to show its ${weight} choices whole; its column is ${sendTrack}`);
      }
    }
  }
  assert.equal(menuNeeds(["Your own AI only (none listed)"], "medium", 58), 236, "Chromium drew that menu 236 px wide");

  // Every choice the page shows in the three lists is one of these, at
  // the weight it is shown at.
  assert.equal(ROOM.at(1280, ".label-pick select", "font-weight"), "500", "a menu shows its choice medium");
  assert.equal(ROOM.at(1280, ".label-pick[data-from] select", "font-weight"), "400", "an inherited choice regular");
  const doc = await rulesAt(1001);
  let n = 0;
  for (const s of doc.querySelectorAll("select.label-select") as Iterable<El>) {
    const shown = s.options[s.selectedIndex].textContent as string;
    const pick = s.closest(".label-pick");
    const inherited = pick.hasAttribute("data-from");
    assert.ok(shown in MENU_WORDS, `the menu choice "${shown}" has a measured width (files-name-room.ts MENU_WORDS)`);
    if (s.classList.contains("send-select")) {
      assert.ok((MENU_CHOICES.send[inherited ? "regular" : "medium"] as readonly string[]).includes(shown), `"${shown}" is a choice of the second menu`);
    } else {
      assert.ok((MENU_CHOICES.label[inherited ? "regular" : "medium"] as readonly string[]).includes(shown), `"${shown}" is a choice of the first menu`);
    }
    n++;
  }
  assert.ok(n >= 4, `the lists draw menus: ${n}`);
});

// ── H1: Add a rule's browser names its menus (§4.25p, 2026-10-22) ──────────

/** Where each track of a grid starts, from its content box's left edge
 *  `left` px into the panel, its content `width` and its `gap`: the fixed
 *  tracks as written, the `minmax(0, 1fr)` ones sharing what is left. */
function trackStarts(tracks: string[], left: number, width: number, gap: number, w: number): number[] {
  const fr = tracks.filter((t) => t === "minmax(0,1fr)");
  const fixed = tracks.filter((t) => t !== "minmax(0,1fr)").reduce((sum, t) => sum + px(t, w), 0);
  const share = (width - fixed - (tracks.length - 1) * gap) / fr.length;
  const out: number[] = [];
  let x = left;
  for (const t of tracks) { out.push(x); x += (t === "minmax(0,1fr)" ? share : px(t, w)) + gap; }
  return out;
}

test("H1: wider than 1000 px, Add a rule's browser has heads whose second and third start within 2 px of its rows' two menus (1001 and 1280 px); at 860 px they are hidden and each menu shows its caption", async () => {
  const browser = FILE_LISTS[1];
  const border = (sel: string, w: number): number => Number(/^(\d+(?:\.\d+)?)px\b/.exec(ROOM.at(w, sel, "border"))![1]);
  const headTracks = (w: number): string[] => ROOM.at(w, ".files-heads.browse-heads", "grid-template-columns").replace(/,\s+/g, ",").split(/\s+/);
  for (const w of [1001, 1280]) {
    // The panel's content box, which holds the heads and the list.
    let panel = ROOM.pageColumn(w);
    for (const box of [".card", ".lock-form"]) panel -= sidePadding(ROOM.at(w, box, "padding"), w) + 2 * border(box, w);
    const headPad = sidePadding(ROOM.at(w, ".files-heads", "padding"), w);
    const heads = trackStarts(headTracks(w), headPad / 2, panel - headPad, px(ROOM.at(w, ".files-heads", "gap"), w), w);
    const row = ROOM.columns(browser, w);
    const rowLeft = border(".table", w) + sidePadding(ROOM.at(w, browser.pad, "padding"), w) / 2;
    const rows = trackStarts(row.tracks, rowLeft, ROOM.rowContent(browser, w), px(ROOM.at(w, browser.pad, "gap"), w), w);
    assert.equal(heads.length, rows.length, `${w}px: a head per column of the row (${headTracks(w).join(" ")} over ${row.tracks.join(" ")})`);
    assert.ok(wideTracks(row.tracks), `${w}px: the rows keep their menus beside the name`);
    for (const [i, what] of [[2, "Which AI may read it"], [3, "Where it may be sent"]] as const) {
      assert.ok(Math.abs(heads[i]! - rows[i]!) <= 2, `${w}px: "${what}" starts at ${heads[i]!.toFixed(1)}px, its menu at ${rows[i]!.toFixed(1)}px`);
    }
  }
  const wide = await rulesAt(1280);
  const ww = wide.defaultView;
  const heads = wide.getElementById("files-list-heads");
  assert.equal(heads.hidden, false, "1280px: the browser lists rows, so its heads show");
  assert.equal(ww.getComputedStyle(heads).display, "grid");
  assert.equal(ww.getComputedStyle(heads).gridTemplateColumns, "20px minmax(0, 1fr) 240px 230px 32px", "1280px: the browser rows' own tracks, the tick box first");
  for (const c of wide.querySelectorAll("#files-list .q-cap")) assert.equal(ww.getComputedStyle(c).display, "none", "1280px: the heads name the menus, not captions");
  const middle = await rulesAt(860);
  const mw = middle.defaultView;
  assert.equal(mw.getComputedStyle(middle.getElementById("files-list-heads")).display, "none", "860px: the browser's heads are hidden");
  const caps = [...middle.querySelectorAll("#files-list .row.file .q-cap")] as El[];
  assert.ok(caps.length >= 2);
  for (const c of caps) assert.equal(mw.getComputedStyle(c).display, "block", "860px: each menu shows its caption");
});
