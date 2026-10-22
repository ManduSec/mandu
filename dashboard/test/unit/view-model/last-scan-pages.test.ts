/**
 * last-scan-pages — the Scan page in pages (dashboard.md §4.25ai *A long
 * scan, in pages*), over a record at about a real machine's scale
 * (large-scan-fixture.ts: 918 findings, 5 sends):
 *
 *   - the head keeps the headline, the figure and every section's heading,
 *     tone and count, and only its first SCAN_PAGE_ROWS rows, without their
 *     examples or filter words: a small fraction of the whole page;
 *   - a section's pages follow on from `after` to the end, each row once;
 *     the query matches over the whole section (rows the head never sent),
 *     trimmed and in lower case, with its own count and pages;
 *   - a row's examples by its id; an id or a section the page does not
 *     have (a path among them) is none;
 *   - no 8-character run of a planted value is in any part.
 * Axes: none (display only; the record is a `secrets`-mode scan). Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseLastScan, scanPageVM } from "../../../src/view-model/last-scan.js";
import { SCAN_PAGE_ROWS, scanAfter, scanHead, scanItemDetail, scanQuery, scanSectionPage, type ScanSectionPage } from "../../../src/view-model/last-scan-pages.js";
import { largeScanRecord } from "./large-scan-fixture.js";

const PLANT = `${"sk" + "_live_"}PagedScan0123456789abcdef`;
const rec = parseLastScan(JSON.parse(JSON.stringify(largeScanRecord({ plant: PLANT }))))!;
const page = scanPageVM(rec);
const bytes = (x: unknown): number => Buffer.byteLength(JSON.stringify(x));

function noValue(where: string, x: unknown): void {
  const text = JSON.stringify(x);
  for (let i = 0; i + 8 <= PLANT.length; i++) {
    const piece = PLANT.slice(i, i + 8);
    if (piece !== "sk_live_") assert.ok(!text.includes(piece), `${where} holds "${piece}" of the planted value`);
  }
}

test("the head: every section's heading, tone and count, its first rows without examples or filter words; a fraction of the whole page", () => {
  const head = scanHead(page, "rev-1");
  assert.equal(head.rev, "rev-1");
  assert.equal(head.pageRows, SCAN_PAGE_ROWS);
  assert.equal(head.headline, page.headline);
  assert.deepEqual(head.figure, page.figure);
  assert.deepEqual(head.sections.map((s) => s.id), page.sections.map((s) => s.id));
  for (const [k, s] of head.sections.entries()) {
    const whole = page.sections[k]!;
    assert.equal(s.heading, whole.heading);
    assert.equal(s.tone, whole.tone);
    assert.equal(s.total, whole.items.length);
    assert.equal(s.items.length, Math.min(SCAN_PAGE_ROWS, whole.items.length));
    assert.equal(s.next, whole.items.length > SCAN_PAGE_ROWS ? SCAN_PAGE_ROWS : null);
    assert.deepEqual(s.items.map((i) => i.id), whole.items.slice(0, SCAN_PAGE_ROWS).map((i) => i.id));
    for (const i of s.items) {
      assert.ok(!("detail" in i) && !("filter" in i), `${i.id}: no examples, no filter words`);
      assert.ok(i.story.length > 0 && typeof i.badge === "string");
    }
  }
  const named = head.sections.find((s) => s.id === "named")!;
  assert.equal(named.total, 635);
  assert.ok(bytes(head) * 10 < bytes(page), `the head (${bytes(head)} B) is under a tenth of the whole page (${bytes(page)} B)`);
  assert.ok(bytes({ scan: head }) < 200_000, `the head stays under 200 kB (${bytes({ scan: head })})`);
  // With no scan, no rev (nothing to page).
  assert.equal(scanHead(scanPageVM(null), "rev-1").rev, null);
  noValue("the head", head);
});

test("a section's pages: from `after` to the end, each row once, `next` null at the end", () => {
  const whole = page.sections.find((s) => s.id === "looks")!;
  const seen: string[] = [];
  let after: number | null = 0;
  let pages = 0;
  while (after !== null) {
    const p: ScanSectionPage = scanSectionPage(page, "looks", { after })!;
    assert.equal(p.total, whole.items.length);
    assert.equal(p.q, "");
    for (const i of p.items) assert.ok(!("detail" in i) && !("filter" in i));
    seen.push(...p.items.map((i) => i.id));
    after = p.next;
    pages++;
    noValue(`looks page ${pages}`, p);
  }
  assert.deepEqual(seen, whole.items.map((i) => i.id));
  assert.equal(pages, Math.ceil(whole.items.length / SCAN_PAGE_ROWS));
  // Past the end: no rows, no next.
  assert.deepEqual(scanSectionPage(page, "looks", { after: 10_000 }), { id: "looks", items: [], total: whole.items.length, next: null, q: "" });
});

test("the filter's query: over the whole section (rows the head never sent), trimmed and lower case, with its own count and pages", () => {
  const named = page.sections.find((s) => s.id === "named")!;
  // The last row of the section: far past the head's first page.
  const last = named.items[named.items.length - 1]!;
  const word = last.title.toUpperCase();
  const p = scanSectionPage(page, "named", { q: `  ${word}  ` })!;
  assert.equal(p.q, last.title.toLowerCase());
  assert.ok(p.items.some((i) => i.id === last.id), "the last row is found");
  assert.equal(p.total, named.items.filter((i) => i.filter.includes(p.q)).length);
  // A broad query pages like the section.
  const broad = scanSectionPage(page, "named", { q: "project" })!;
  assert.ok(broad.total > SCAN_PAGE_ROWS);
  assert.equal(broad.items.length, SCAN_PAGE_ROWS);
  assert.equal(broad.next, SCAN_PAGE_ROWS);
  const second = scanSectionPage(page, "named", { q: "project", after: broad.next! })!;
  assert.notEqual(second.items[0]!.id, broad.items[0]!.id);
  // Nothing matches: none, no next.
  const none = scanSectionPage(page, "named", { q: "nothing-like-it" })!;
  assert.deepEqual([none.items.length, none.total, none.next], [0, 0, null]);
  assert.equal(scanQuery("x".repeat(500)).length, 200, "a query is cut at 200 characters");
});

test("a row's examples by its id; a section or an id the page does not have is none, a path among them", () => {
  const first = page.sections.find((s) => s.id === "yours")!.items[0]!;
  const d = scanItemDetail(page, first.id)!;
  assert.deepEqual(d, { id: first.id, detail: first.detail });
  assert.ok(d.detail.groups.length > 0);
  const send = page.sections.find((s) => s.id === "sends-other")!.items[0]!;
  assert.equal(scanItemDetail(page, send.id)!.id, send.id);
  for (const id of ["f99999", "x1", "", "../last-scan.json", "/etc/passwd", "f1/../f2", "f-1", "F1"]) assert.equal(scanItemDetail(page, id), null, JSON.stringify(id));
  for (const id of ["nope", "", "../yours", "__proto__", "constructor"]) assert.equal(scanSectionPage(page, id), null, JSON.stringify(id));
  // A section the page lacks (no Mandu-kept findings here): none.
  assert.equal(scanSectionPage(page, "kept"), null);
  for (const s of page.sections) for (const i of s.items) noValue(`${i.id}'s examples`, scanItemDetail(page, i.id));
});

test("`after` reads a whole number from 0, anything else as 0", () => {
  assert.equal(scanAfter("25"), 25);
  assert.equal(scanAfter(null), 0);
  for (const v of ["-1", "1e3", "abc", "2.5", "99999999", " 3"]) assert.equal(scanAfter(v), 0, v);
});
