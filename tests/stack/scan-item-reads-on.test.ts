/**
 * scan-item-reads-on — a session card's link to one of your secrets on the
 * Scan page opens that row even past the section's first page, across the
 * REAL components (dashboard.md §4.25ai *A session card opens its row*).
 * Mandu-new.
 *
 * Until 2026-11-03 the page looked for the row among the drawn rows only:
 * for anyone whose scan found more than 25 of their secrets, a link from
 * the 26th on opened the page at its top, no row open and no word why.
 * Here a real ArbiterServer runs at the `secrets` axes and a real
 * DashboardServer serves the product page over a kept scan of 30 of your
 * secrets (the first in a real `.env` beside its value):
 *
 *   R1  `/scan?item=f27` (the 28th, past the head's 25): the served page
 *       (its own index.html and home.js in jsdom, fetching from that
 *       server) reads the section on once, then opens that row's fold,
 *       reads its examples and gives it the focus; nothing is said under
 *       the headline;
 *   R2  `/scan?item=f40` (a row the list does not have, as after a newer
 *       scan): the page reads to the section's end and says so under the
 *       headline; no row is opened;
 *   R3  the oracle: the planted value and no `$MDU:` token in either
 *       drawn page.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { manduPath } from "../../dashboard/src/generated/mandu-paths.js";
import type { LastScanWire } from "../../dashboard/src/view-model/last-scan.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

// Assembled at run time: this file holds no credential-shaped literal.
const KEY_VALUE = "sk_" + `live_scanReadsOnStackCanary${process.pid}00000000`;
const MISSING = "That secret is not in the last scan's list any more. A newer scan may have changed it.";

/** A kept scan as the launcher writes it: names, files, masks and counts,
 *  never a value. `n` of your secrets, each in its own project's `.env`. */
function record(n: number): LastScanWire {
  return {
    version: 1, ranAt: "2026-11-02T09:00:00.000Z", sessions: { "claude-code": 40 }, duringMandu: 0, known: n, dropped: 0,
    capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 }, suggestions: null,
    findings: Array.from({ length: n }, (_, i) => ({
      kind: "known", preview: `KEY_${i} in ~/p${i}/.env`, source: { path: `~/p${i}/.env`, name: `KEY_${i}` }, sessions: 1,
      agents: ["claude-code"], how: { "read-file": 1 }, projects: [`~/p${i}`], duringMandu: 0,
      first: "2026-10-20T10:00:00.000Z", last: "2026-10-21T10:00:00.000Z",
      examples: [{ at: "2026-10-21T10:00:00.000Z", agent: "claude-code", how: "read-file", file: `~/p${i}/.env`, project: `~/p${i}`, mandu: "without" }],
    })),
  };
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

test("a link to one of your secrets past the Scan page's first 25 rows opens that row; one the list does not have says so", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-scan-reads-on-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "p0"), { recursive: true });
  writeFileSync(join(home, "p0", ".env"), `KEY_0=${KEY_VALUE}\n`);
  const manduHome = join(tmp, "mandu-home");
  mkdirSync(manduHome, { recursive: true });
  const configEnv = { MANDU_HOME: manduHome };
  const scanFile = manduPath("last-scan", configEnv, home);
  mkdirSync(dirname(scanFile), { recursive: true });
  writeFileSync(scanFile, JSON.stringify(record(30)));
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    fileBrowserHome: home,
    configEnv,
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const until = async (cond: () => boolean, what: string): Promise<void> => {
    const t0 = Date.now();
    while (!cond() && Date.now() - t0 < 10_000) await sleep(20);
    assert.ok(cond(), what);
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const oracle = (doc: any): void => {
    const page = doc.body.textContent as string;
    assert.ok(!page.includes(KEY_VALUE.slice(3)), "R3: no value on the page");
    assert.doesNotMatch(page, /\$MDU:/, "R3: no token on the page");
  };
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rows = (doc: any) => doc.querySelectorAll('[data-section="yours"] .scan-item').length;
    await servedProductPage(base, "/scan?item=f27", (doc) => rows(doc) > 0, async (doc) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const row = (): any => doc.querySelector('.scan-item[data-id="f27"]');
      await until(() => !!row() && doc.activeElement === row() && !!row().querySelector(".scan-detail"), "R1: the 28th row drawn, open, read and focused");
      assert.equal(rows(doc), 30, "R1: the section read on to its end page");
      assert.equal(row().querySelector("details.scan-more").open, true);
      assert.match(row().textContent, /KEY_27/);
      assert.equal(doc.getElementById("scan-item-missing").hidden, true, "R1: nothing said");
      oracle(doc);
    });
    await servedProductPage(base, "/scan?item=f40", (doc) => rows(doc) > 0, async (doc) => {
      const line = doc.getElementById("scan-item-missing");
      await until(() => !line.hidden, "R2: the line under the headline");
      assert.equal(line.textContent, MISSING);
      assert.equal(line.getAttribute("role"), "status");
      assert.equal(rows(doc), 30, "R2: read to the section's end");
      assert.equal(doc.querySelectorAll("details.scan-more[open]").length, 0, "R2: no row opened");
      oracle(doc);
    });
  } finally {
    await dashboard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
