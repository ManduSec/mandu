/**
 * server/scan-routes — the Scan page's reads (dashboard.md §4.25ai *A long
 * scan, in pages*): the head of the page, a page of a section's rows (the
 * filter's query too), and one row's examples, over the last `mandu scan`
 * the launcher kept.
 *
 * `LastScanCache` reads the kept record once per version of the file: a
 * `stat` per request, and the read, the field checks and the view model
 * again only when the file's identity (inode, size, mtime, ctime) changed.
 * Before it, every Home poll and every Scan page read parsed the whole file
 * again (1.3 MB on a machine of 834 sessions) and the page built all of it.
 *
 * The routes sit behind the same gates as `/api/scan` (server.ts handle:
 * the source-IP and Host checks, the sign-in gate, read-gate.ts `open`):
 * they serve parts of the same view model, which holds no value (the kept
 * record has none). A row is named by its id (`f12`, `s3`), never a path,
 * and a section by its name; anything else is a 404. Mandu-new.
 */
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import type { ServerResponse } from "node:http";
import { parseLastScan, scanPageVM, type LastScanWire, type ScanPageVM } from "../view-model/last-scan.js";
import { scanAfter, scanHead, scanItemDetail, scanSectionPage, type ScanHeadVM } from "../view-model/last-scan-pages.js";
import { json } from "./http-util.js";

interface Entry {
  key: string;
  rec: LastScanWire | null;
  page?: ScanPageVM;
  head?: ScanHeadVM;
}

/** The kept record, its view models built once per version of the file. */
export class LastScanCache {
  private entry: Entry | null = null;
  /** How many times the file was read and parsed (a test reads it). */
  reads = 0;

  constructor(private readonly path: () => string) {}

  /** The file's identity now: "" when there is none to read. */
  private keyNow(): string {
    try {
      const st = statSync(this.path(), { bigint: true });
      if (!st.isFile()) return "";
      return `${st.dev}:${st.ino}:${st.size}:${st.mtimeNs}:${st.ctimeNs}`;
    } catch {
      return "";
    }
  }

  private current(): Entry {
    const key = this.keyNow();
    if (this.entry !== null && this.entry.key === key) return this.entry;
    let rec: LastScanWire | null = null;
    if (key !== "") {
      this.reads++;
      try {
        rec = parseLastScan(JSON.parse(readFileSync(this.path(), "utf8")));
      } catch {
        rec = null;
      }
    }
    this.entry = { key, rec };
    return this.entry;
  }

  /** The kept record, or null. */
  record(): LastScanWire | null {
    return this.current().rec;
  }

  /** The whole Scan page (the pages are cut from it). */
  page(): ScanPageVM {
    const e = this.current();
    return (e.page ??= scanPageVM(e.rec));
  }

  /** Which version of the file the page is of: opaque, never the path. */
  rev(): string {
    return createHash("sha256").update(this.current().key).digest("base64url").slice(0, 16);
  }

  /** The head of the Scan page. */
  head(): ScanHeadVM {
    const e = this.current();
    return (e.head ??= scanHead(this.page(), this.rev()));
  }
}

/** A `rev` that is not the kept scan's now: the page reads it again. */
function staleRev(cache: LastScanCache, params: URLSearchParams, res: ServerResponse): boolean {
  const rev = params.get("rev");
  if (rev === null || rev === "" || rev === cache.rev()) return false;
  json(res, 409, { error: "the scan changed: read the page again", changed: true });
  return true;
}

/** GET /api/scan: the head of the Scan page (§4.25ai), or the way to run
 *  one (`ran: false`). Read-only, metadata only. */
export function apiScan(cache: LastScanCache, res: ServerResponse): void {
  json(res, 200, { scan: cache.head() });
}

/** GET /api/scan/section/<id>?after=&q=&rev=: a page of a section's rows,
 *  those matching `q` when given (the page's *Find one*). */
export function apiScanSection(cache: LastScanCache, id: string, params: URLSearchParams, res: ServerResponse): void {
  if (staleRev(cache, params, res)) return;
  const page = scanSectionPage(cache.page(), id, { after: scanAfter(params.get("after")), q: params.get("q") ?? "" });
  if (page === null) return json(res, 404, { error: "no such section" });
  json(res, 200, page);
}

/** GET /api/scan/item/<id>?rev=: one row's examples. */
export function apiScanItem(cache: LastScanCache, id: string, params: URLSearchParams, res: ServerResponse): void {
  if (staleRev(cache, params, res)) return;
  const item = scanItemDetail(cache.page(), id);
  if (item === null) return json(res, 404, { error: "no such row" });
  json(res, 200, item);
}

/** The Scan page's paged routes: `[kind, id]` of a path, or null. */
export function scanRouteOf(urlPath: string): ["section" | "item", string] | null {
  const m = /^\/api\/scan\/(section|item)\/([^/]+)$/.exec(urlPath);
  return m ? [m[1] as "section" | "item", m[2]!] : null;
}
