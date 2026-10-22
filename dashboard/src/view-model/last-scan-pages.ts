/**
 * last-scan-pages — the Scan page in pages (dashboard.md §4.25ai *A long
 * scan, in pages*): `/api/scan` sends the head of the page, and the rest
 * comes when it is opened.
 *
 * A real scan of 834 sessions made the whole page one 3 MB answer: 918
 * rows, each with its story, its examples and the words its filter
 * matches, of which the page draws 25 a section and every row's examples
 * only when its *Details and examples* opens. The head keeps what the page
 * draws first: the headline, the figure, the notes, each section's heading,
 * sentence, tone and count, and its first `SCAN_PAGE_ROWS` rows without
 * their examples (`detail`) or filter words (`filter`). A section's further
 * rows (`scanSectionPage`, also the filter's server-side query) and one
 * row's examples (`scanItemDetail`) are read from the same view model,
 * so the pages tell nothing the whole page did not: no value, ever (the
 * kept record has none, last-scan.ts).
 *
 * Pure. Mandu-new (no reference origin).
 */
import type { ScanItemVM, ScanPageVM, ScanSectionVM } from "./last-scan.js";

/** The rows a section shows at first, and each Show more adds. The page's
 *  own SCAN_PAGE_ROWS (public/js/home.js) takes it from the head. */
export const SCAN_PAGE_ROWS = 25;
/** The longest filter query read (the page's box takes 200 characters). */
export const SCAN_QUERY_MAX = 200;

/** A row as a page of the Scan page sends it: no examples, no filter words. */
export type ScanRowVM = Omit<ScanItemVM, "detail" | "filter">;

/** A section's head: its first rows, its count and where the next page starts. */
export interface ScanSectionHeadVM extends Omit<ScanSectionVM, "items"> {
  items: ScanRowVM[];
  /** All its rows. */
  total: number;
  /** The `after` of its next page, or null when the head holds every row. */
  next: number | null;
}

/** The head of the Scan page (`/api/scan`). */
export interface ScanHeadVM extends Omit<ScanPageVM, "sections"> {
  sections: ScanSectionHeadVM[];
  /** Which kept scan these rows are of: a page or a row asked of another
   *  (a scan kept since) is refused, so ids never point at another scan's
   *  rows. Opaque; null with no scan. */
  rev: string | null;
  /** The rows a page of a section holds. */
  pageRows: number;
}

/** One page of a section's rows (`/api/scan/section/<id>`). */
export interface ScanSectionPage {
  id: ScanSectionVM["id"];
  items: ScanRowVM[];
  /** The rows that match (all of them without a query). */
  total: number;
  /** The `after` of the next page, or null. */
  next: number | null;
  /** The query it answered, as read (trimmed, lower case), or "". */
  q: string;
}

export const SECTION_IDS: ReadonlySet<string> = new Set<ScanSectionVM["id"]>(["yours", "looks", "named", "kept", "sends-other", "sends-own"]);
/** A row's id as findingItem / sendItem make it: never a path. */
export const ITEM_ID = /^[fs]\d{1,6}$/;

/** A row without what the head leaves for later. */
export function scanRow(item: ScanItemVM): ScanRowVM {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { detail, filter, ...row } = item;
  return row;
}

/** The head from the whole page. Pure. */
export function scanHead(page: ScanPageVM, rev: string | null, rows = SCAN_PAGE_ROWS): ScanHeadVM {
  return {
    ...page,
    rev: page.ran ? rev : null,
    pageRows: rows,
    sections: page.sections.map((s) => ({
      ...s,
      items: s.items.slice(0, rows).map(scanRow),
      total: s.items.length,
      next: s.items.length > rows ? rows : null,
    })),
  };
}

/** The filter's query as the server reads it: trimmed, lower case, cut at
 *  SCAN_QUERY_MAX ("" for none). */
export function scanQuery(q: string | null | undefined): string {
  return (q ?? "").trim().toLowerCase().slice(0, SCAN_QUERY_MAX);
}

/** The `after` of a page: a whole number from 0, else 0. */
export function scanAfter(v: string | null | undefined): number {
  if (v === null || v === undefined || !/^\d{1,7}$/.test(v)) return 0;
  return Number(v);
}

/** One page of a section: its rows from `after`, those whose words hold
 *  `q` when there is one (the page's *Find one*, over the whole section);
 *  null for a section the page does not have. Pure. */
export function scanSectionPage(page: ScanPageVM, id: string, opts: { after?: number; q?: string; rows?: number } = {}): ScanSectionPage | null {
  if (!SECTION_IDS.has(id)) return null;
  const sec = page.sections.find((s) => s.id === id);
  if (sec === undefined) return null;
  const q = scanQuery(opts.q);
  const rows = opts.rows ?? SCAN_PAGE_ROWS;
  const after = Math.max(0, Math.floor(opts.after ?? 0));
  const matched = q === "" ? sec.items : sec.items.filter((i) => i.filter.includes(q));
  const items = matched.slice(after, after + rows).map(scanRow);
  return { id: sec.id, items, total: matched.length, next: after + rows < matched.length ? after + rows : null, q };
}

/** One row's examples (its *Details and examples*), or null for an id the
 *  page does not have. Pure. */
export function scanItemDetail(page: ScanPageVM, id: string): { id: string; detail: ScanItemVM["detail"] } | null {
  if (!ITEM_ID.test(id)) return null;
  for (const s of page.sections) {
    const item = s.items.find((i) => i.id === id);
    if (item !== undefined) return { id, detail: item.detail };
  }
  return null;
}
