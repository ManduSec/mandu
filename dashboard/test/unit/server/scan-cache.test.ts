/**
 * scan-cache — the kept scan read once per version of its file
 * (server/scan-routes.ts `LastScanCache`; dashboard.md §4.25ai *A long
 * scan, in pages*):
 *
 *   - unchanged, the file is read and the page built once, however many
 *     reads ask (before, every Home poll and Scan read parsed it again);
 *   - a scan kept since (rewritten in place, or replaced by a rename, as the
 *     launcher keeps it) is read again, and its `rev` changes;
 *   - no file, or one that does not read as a record: none, and a file
 *     that appears later is read;
 *   - the route matcher names only `section/<x>` and `item/<x>`.
 * Axes: none (display only; the record is a `secrets`-mode scan). Mandu-new test.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, renameSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LastScanCache, scanRouteOf } from "../../../src/server/scan-routes.js";
import { largeScanRecord } from "../view-model/large-scan-fixture.js";

const dir = mkdtempSync(join(tmpdir(), "mdu-scan-cache-"));
after(() => rmSync(dir, { recursive: true, force: true }));

test("unchanged, the file is read and the page built once; a scan kept since is read again with a new rev", () => {
  const file = join(dir, "a.json");
  writeFileSync(file, JSON.stringify(largeScanRecord({ known: 1, looks: 30, named: 30 })));
  const cache = new LastScanCache(() => file);
  const head1 = cache.head();
  const rev1 = cache.rev();
  for (let i = 0; i < 20; i++) {
    assert.equal(cache.head(), head1, "the same head object: not built again");
    assert.equal(cache.record()?.findings.length, 61);
    cache.page();
  }
  assert.equal(cache.reads, 1, "read once");
  assert.equal(head1.rev, rev1);
  assert.match(rev1, /^[A-Za-z0-9_-]{16}$/, "opaque, never the path");

  // Rewritten in place (another size, a later mtime).
  writeFileSync(file, JSON.stringify(largeScanRecord({ known: 2, looks: 30, named: 30 })));
  utimesSync(file, new Date(), new Date(Date.now() + 5_000));
  assert.equal(cache.record()?.findings.length, 62);
  assert.equal(cache.reads, 2);
  assert.notEqual(cache.rev(), rev1);
  assert.notEqual(cache.head(), head1);

  // Replaced by a rename (a new inode), the size the same.
  const tmp = join(dir, "a.json.tmp");
  writeFileSync(tmp, JSON.stringify(largeScanRecord({ known: 2, looks: 30, named: 30 })));
  const rev2 = cache.rev();
  renameSync(tmp, file);
  cache.record();
  assert.equal(cache.reads, 3, "a renamed-in file is a new version");
  assert.notEqual(cache.rev(), rev2);
});

test("no file, or one that is not a record: none; a file that appears later is read", () => {
  const file = join(dir, "b.json");
  const cache = new LastScanCache(() => file);
  assert.equal(cache.record(), null);
  assert.equal(cache.head().ran, false);
  assert.equal(cache.head().rev, null);
  assert.equal(cache.reads, 0, "no file: nothing to read");
  writeFileSync(file, "{ not json");
  assert.equal(cache.record(), null);
  assert.equal(cache.reads, 1);
  cache.record();
  assert.equal(cache.reads, 1, "a bad file is not read again until it changes");
  writeFileSync(file, JSON.stringify(largeScanRecord({ known: 1, looks: 0, named: 0 })));
  utimesSync(file, new Date(), new Date(Date.now() + 10_000));
  assert.equal(cache.head().ran, true);
});

test("the route matcher: section/<x> and item/<x> only", () => {
  assert.deepEqual(scanRouteOf("/api/scan/section/looks"), ["section", "looks"]);
  assert.deepEqual(scanRouteOf("/api/scan/item/f12"), ["item", "f12"]);
  for (const p of ["/api/scan", "/api/scan/section", "/api/scan/section/", "/api/scan/item/a/b", "/api/scan/other/x", "/api/scans/item/f1"]) assert.equal(scanRouteOf(p), null, p);
});
