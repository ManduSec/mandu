/**
 * scan-page-unread — a Scan page that cannot be read says only that, across
 * the REAL components (dashboard.md §4.25ai, *A Scan page that cannot be
 * read says only that*). Mandu-new.
 *
 * Until 2026-10-29 a Scan page drawn once and opened again while its read
 * failed kept the last read's tone (the plain headline in red or green)
 * and its closing lines ("1 file that holds them has no rule yet", "from
 * now on", "Run it again") under "The last scan could not be read.". Here
 * a real ArbiterServer runs at the `secrets` axes and a real
 * DashboardServer over a real ArbiterEventSource serves the product page,
 * with a temp Mandu home whose `last-scan.json` names a planted key:
 *
 *   U1  the served Scan page (its own index.html and home.js in jsdom,
 *       fetching from that server) draws the kept scan: red, its findings,
 *       Run it again;
 *   U2  Home, then the DashboardServer stops, then Scan again: the page
 *       shows the plain headline with no tone and no mark, and the failure
 *       sentence; the block of closing lines is hidden and empty, and no
 *       finding, note or figure is drawn;
 *   U3  the oracle: the planted value and no `$MDU:` token is in any answer
 *       body or the drawn page.
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
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

// Assembled at run time: this file holds no credential-shaped literal.
const KEY_VALUE = "sk_" + `live_scanUnreadStackCanary${process.pid}00000000`;
const HEADLINE = "2 of your secrets left this computer in your agents' requests";
const PLAIN = "What your agents already sent to the AI";

/** A kept scan as the launcher writes it: names, files, masks and counts,
 *  never a value; one file with no rule yet, so the page says so. */
function record(): LastScanWire {
  return {
    version: 1, ranAt: "2026-10-28T09:00:00.000Z", sessions: { "claude-code": 4 }, duringMandu: 0, known: 2, dropped: 0,
    capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 }, suggestions: { pending: 1, filed: 1, covered: 0 },
    findings: Array.from({ length: 2 }, (_, i) => ({
      kind: "known", preview: `KEY_${i} in ~/shop/.env`, source: { path: "~/shop/.env", name: `KEY_${i}` }, sessions: 2,
      agents: ["claude-code"], how: { "read-file": 2 }, projects: ["~/shop"], duringMandu: 0,
      first: "2026-10-20T10:00:00.000Z", last: "2026-10-21T10:00:00.000Z",
    })),
  };
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

test("a Scan page that cannot be read again shows only the plain headline and why, nothing of the last read, with no value on the way", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-scan-unread-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "shop"), { recursive: true });
  writeFileSync(join(home, "shop", ".env"), `KEY_0=${KEY_VALUE}\nKEY_1=${KEY_VALUE}x\n`);
  const manduHome = join(tmp, "mandu-home");
  mkdirSync(manduHome, { recursive: true });
  const configEnv = { MANDU_HOME: manduHome };
  const scanFile = manduPath("last-scan", configEnv, home);
  mkdirSync(dirname(scanFile), { recursive: true });
  writeFileSync(scanFile, JSON.stringify(record()));
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
  let stopped = false;
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const bodies: string[] = [];
  try {
    for (const path of ["/api/home", "/api/scan"]) bodies.push(await (await pageFetch(`${base}${path}`)).text());

    await servedProductPage(base, "/scan", (doc) => doc.getElementById("scan-headline").textContent === HEADLINE, async (doc) => {
      const page = doc.getElementById("page-scan");
      const end = doc.getElementById("scan-end");
      const lines = ["scan-suggested", "scan-stop", "scan-again"].map((id) => doc.getElementById(id));
      const until = async (cond: () => boolean, what: string): Promise<void> => {
        const t0 = Date.now();
        while (!cond() && Date.now() - t0 < 10_000) await sleep(20);
        assert.ok(cond(), what);
      };
      // U1: the kept scan, drawn.
      assert.equal(page.dataset.tone, "bad");
      assert.equal(end.hidden, false);
      assert.match(lines[0].textContent, /no rule yet/);
      assert.match(lines[2].textContent, /Run it again: mandu scan/);
      assert.equal(doc.querySelectorAll('[data-section="yours"] .scan-item').length, 2);

      // U2: Home, the dashboard stops, Scan again.
      doc.querySelector('#nav [data-page-link="home"]').click();
      await until(() => page.hidden && doc.getElementById("home-scan-open").hidden === false, "U2: Home with its scan card");
      await dashboard.close();
      stopped = true;
      doc.getElementById("home-scan-open").click();
      const sentence = doc.getElementById("scan-sentence");
      await until(() => !page.hidden && /^The last scan could not be read\./.test(sentence.textContent), "U2: the failure is said");
      assert.equal(doc.getElementById("scan-headline").textContent, PLAIN, "U2: the plain headline");
      assert.equal(page.dataset.tone, undefined, "U2: no tone it cannot back");
      assert.equal(doc.querySelector("#scan-headline .tone-mark"), null, "U2: no mark");
      assert.equal(end.hidden, true, "U2: no closing lines");
      assert.deepEqual(lines.map((l: { textContent: string }) => l.textContent), ["", "", ""], "U2: nothing stale in the text");
      assert.equal(doc.getElementById("scan-sections").hidden, true);
      assert.equal(doc.querySelector("#scan-sections .scan-item"), null, "U2: no finding");
      assert.equal(doc.getElementById("scan-figure").hidden, true);
      assert.equal(doc.getElementById("scan-notes").hidden, true);
      assert.doesNotMatch(page.textContent, /no rule yet|from now on|Run it again/);

      // U3 on the drawn page.
      const text = doc.body.textContent as string;
      assert.ok(!text.includes(KEY_VALUE.slice(3)), "U3: no value on the page");
      assert.doesNotMatch(text, /\$MDU:/, "U3: no token on the page");
    });
    // U3 on every answer read.
    for (const b of bodies) {
      assert.ok(!b.includes(KEY_VALUE.slice(3)), "U3: no value in an answer");
      assert.doesNotMatch(b, /\$MDU:/, "U3: no token in an answer");
    }
  } finally {
    if (!stopped) await dashboard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
