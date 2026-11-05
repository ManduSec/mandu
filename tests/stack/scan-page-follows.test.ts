/**
 * scan-page-follows — the Scan page shows a scan kept while it is open,
 * without a reload, across the REAL components (dashboard.md §4.25ai, *The
 * Scan page follows a new scan*). Mandu-new.
 *
 * Until 2026-10-26 the page read `GET /api/scan` once when opened and again
 * only after a failed read: with no scan kept the server still answers 200
 * (the way to run one), so after `mandu scan` Home's card showed the result
 * while the Scan page in the same tab kept saying "Run it in a terminal:
 * mandu scan". Here a real ArbiterServer runs at the `secrets` axes and a
 * real DashboardServer over a real ArbiterEventSource serves the product
 * page with a temp Mandu home that holds no `last-scan.json`:
 *
 *   F1  `/api/home`'s scan card carries the kept scan's `rev`, the one
 *       `/api/scan` sends: null with none kept, an opaque 16 characters
 *       once one is, another after a second scan; never the file's path;
 *   F2  the served Scan page (its own index.html and home.js in jsdom,
 *       fetching from that server) opens on "Did your agents already send
 *       a secret to the AI?"; a scan is kept (written and renamed into
 *       place, as the launcher keeps it); on the next Home poll the page
 *       draws its headline, with no navigation, and a status line says so;
 *       a poll after it reads nothing more; a second scan is followed too;
 *   F3  the oracle: the planted secret's value and no `$MDU:` token is in
 *       any answer body or the drawn page.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { manduPath } from "../../dashboard/src/generated/mandu-paths.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import type { LastScanWire } from "../../dashboard/src/view-model/last-scan.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

// Assembled at run time: this file holds no credential-shaped literal.
const KEY_VALUE = "sk_" + `live_scanFollowsStackCanary${process.pid}00000000`;
const NONE_HEADLINE = "Did your agents already send a secret to the AI?";

/** A kept scan as the launcher writes it: names, files, masks and counts,
 *  never a value. `secrets` findings of a key in `~/shop/.env`. */
function record(ranAt: string, secrets: number): LastScanWire {
  return {
    version: 1, ranAt, sessions: { "claude-code": 4 }, duringMandu: 0, known: secrets, dropped: 0,
    capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 }, suggestions: null,
    findings: Array.from({ length: secrets }, (_, i) => ({
      kind: "known", preview: `KEY_${i} in ~/shop/.env`, source: { path: "~/shop/.env", name: `KEY_${i}` }, sessions: 2,
      agents: ["claude-code"], how: { "read-file": 2 }, projects: ["~/shop"], duringMandu: 0,
      first: "2026-10-20T10:00:00.000Z", last: "2026-10-21T10:00:00.000Z",
    })),
  };
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

test("the Scan page follows a scan kept while it is open: none, then one, then another, at the next Home poll, with no value on the way", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-scan-follows-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "shop"), { recursive: true });
  writeFileSync(join(home, "shop", ".env"), `KEY_0=${KEY_VALUE}\n`);
  const manduHome = join(tmp, "mandu-home");
  mkdirSync(manduHome, { recursive: true });
  const configEnv = { MANDU_HOME: manduHome };
  const scanFile = manduPath("last-scan", configEnv, home);
  mkdirSync(dirname(scanFile), { recursive: true });
  /** Kept as the launcher keeps it: written aside, renamed into place. */
  const keep = (rec: LastScanWire): void => {
    writeFileSync(`${scanFile}.tmp`, JSON.stringify(rec));
    renameSync(`${scanFile}.tmp`, scanFile);
  };
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
  const bodies: string[] = [];
  /** F1: the card's rev and the Scan head's, read as the page reads them. */
  const revs = async (): Promise<{ card: string | null | undefined; head: string | null; ran: boolean }> => {
    const h = await (await pageFetch(`${base}/api/home`)).text();
    const s = await (await pageFetch(`${base}/api/scan`)).text();
    bodies.push(h, s);
    const card = (JSON.parse(h) as HomeVM).scan;
    const head = (JSON.parse(s) as { scan: { rev: string | null; ran: boolean } }).scan;
    return { card: card?.rev, head: head.rev, ran: card?.ran === true };
  };
  try {
    const none = await revs();
    assert.equal(none.card, null, "F1: no scan kept: the card names that state (null), as /api/scan does");
    assert.equal(none.head, null);

    await servedProductPage(base, "/scan", (doc) => doc.getElementById("scan-headline").textContent === NONE_HEADLINE, async (doc) => {
      const w = doc.defaultView;
      const status = doc.getElementById("scan-followed");
      const href = w.location.href;
      const poll = (): void => { doc.dispatchEvent(new w.Event("visibilitychange")); };
      const headline = (): string => doc.getElementById("scan-headline").textContent;
      const until = async (cond: () => boolean, what: string): Promise<void> => {
        const t0 = Date.now();
        while (!cond() && Date.now() - t0 < 10_000) await sleep(20);
        assert.ok(cond(), what);
      };
      assert.equal(status.hidden, true);
      // Before any scan the way to run one is the page's first step (§4.25ai *Before any scan, the step comes first*).
      assert.match(doc.getElementById("scan-step").textContent, /Run it in a terminal: mandu scan/);
      assert.equal(doc.getElementById("scan-step-note").textContent, "This page shows what it found when it finishes.");

      // F2: `mandu scan` keeps one; the next Home poll shows it here.
      keep(record("2026-10-26T09:00:00.000Z", 3));
      const one = await revs();
      assert.equal(one.ran, true);
      assert.match(one.card ?? "", /^[A-Za-z0-9_-]{16}$/, "F1: opaque");
      assert.equal(one.card, one.head, "F1: the card's rev is /api/scan's");
      poll();
      await until(() => headline() === "3 of your secrets left this computer in your agents' requests", "F2: the page drew the kept scan");
      assert.equal(w.location.href, href, "no navigation");
      assert.equal(status.hidden, false);
      assert.equal(status.getAttribute("role"), "status");
      assert.equal(status.textContent, "A new scan finished. This page shows it.");
      assert.match(doc.getElementById("scan-again").textContent, /Run it again: mandu scan/);
      assert.equal(doc.getElementById("scan-step-note").hidden, true, "the line under the step is gone once a scan is kept");
      assert.equal(doc.querySelectorAll('[data-section="yours"] .scan-item').length, 3);
      // The same scan: a poll draws nothing again (the section stays the same node).
      const section = doc.querySelector('[data-section="yours"]');
      poll();
      await sleep(300);
      assert.equal(doc.querySelector('[data-section="yours"]'), section, "the same scan: not drawn again");

      // A second scan, followed too.
      keep(record("2026-10-26T10:00:00.000Z", 1));
      const two = await revs();
      assert.notEqual(two.card, one.card, "F1: another scan, another rev");
      assert.equal(two.card, two.head);
      poll();
      await until(() => headline() === "1 of your secrets left this computer in your agents' requests", "F2: the page followed the second scan");
      assert.equal(w.location.href, href);
      assert.equal(doc.querySelectorAll('[data-section="yours"] .scan-item').length, 1);

      // F3 on the drawn page.
      const page = doc.body.textContent as string;
      assert.ok(!page.includes(KEY_VALUE.slice(3)), "F3: no value on the page");
      assert.doesNotMatch(page, /\$MDU:/, "F3: no token on the page");
      assert.ok(!page.includes(scanFile), "never the kept file's path");
    });
    // F3 on every answer read, and F1's no path.
    for (const b of bodies) {
      assert.ok(!b.includes(KEY_VALUE.slice(3)), "F3: no value in an answer");
      assert.doesNotMatch(b, /\$MDU:/, "F3: no token in an answer");
      assert.ok(!b.includes(scanFile), "the rev never carries the path");
    }
  } finally {
    await dashboard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
