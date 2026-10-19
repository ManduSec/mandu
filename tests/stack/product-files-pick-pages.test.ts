/**
 * product-files-pick-pages.test — Go to a file, and Show in its folder, open
 * its row in the file browser under Rules › Add a rule when the file is past
 * its folder's first page, across the REAL components (dashboard.md §4.25m
 * *Browsing*). Mandu-new.
 *
 * The listing answers 500 entries a page, folders first and then by name.
 * Until 2026-10-15 a picked entry was looked for on the first page only: in a
 * folder of 500 folders no file was opened, it stayed behind Show more, and
 * Show in its folder gave the focus to the path box. Here a real
 * ArbiterServer runs at the `secrets` axes with a policy.yaml rule on a file
 * past the first page, and a real DashboardServer reaches it over the
 * production adapter (`makeApprovalsArbiter`, with its secrets surface, as
 * server-main wires it). The served product page (its own index.html and
 * home.js in jsdom, signed in) over a real folder of 500 folders and three
 * files:
 *
 *   G1  Go to ~/big/zeta-2.env: the folder is shown down to its second page,
 *       read once each, with the file's row opened and its rule on it;
 *   G2  Show in its folder on the file's Your rules row: the same, and the
 *       focus on the row's ⋯;
 *   G3  no unhandled rejection in the page; the oracle: no rendered page
 *       carries the labelled file's value or a token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const KEY_VALUE = `sk_live_pickPagesCanary_${process.pid}_0001`;
const DIRS = 500; // d000 … d499: the whole first page

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (doc: any, sel: string): string => doc.querySelector(sel)?.textContent ?? "";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const fileRows = (doc: any): any[] => [...doc.querySelectorAll("#files-list .row.file:not(.up)")];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const openRow = (doc: any) => doc.querySelector("#files-list .row.file.open") as any;

test("Go to a file and Show in its folder open its row past the folder's first page (real arbiter, production adapter, dashboard, served page)", { timeout: 240_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-pick-pages-"));
  const home = join(tmp, "home");
  const big = join(home, "big");
  mkdirSync(big, { recursive: true });
  for (let i = 0; i < DIRS; i++) mkdirSync(join(big, `d${String(i).padStart(3, "0")}`));
  // Files sort after every folder: all three are on the second page.
  writeFileSync(join(big, "notes.md"), "nothing secret\n");
  writeFileSync(join(big, "zeta-1.env"), "NOTHING=secret\n");
  const key = join(big, "zeta-2.env");
  writeFileSync(key, `DEPLOY_KEY=${KEY_VALUE}\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${key}\n    level: no-model\n`);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath: policy, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets, "the production adapter has the secrets surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policy },
    log: () => {}, ...ADMIN_OPTS,
  });
  const port = await dashboard.listen(0);
  const base = `http://127.0.0.1:${port}`;
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const rendered: string[] = [];
  // Every listing the page asks for, as it asks (the query after `files/list?`).
  const listings: string[] = [];
  const reads = (query: string) => listings.filter((q) => q === query).length;
  const FIRST = `path=${encodeURIComponent(big)}`;
  const SECOND = `path=${encodeURIComponent(big)}&offset=500`;
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const ready = (doc: any) => text(doc, "#files-tree").includes("zeta-2.env");
    await servedProductPage(base, "/rules", ready, async (doc) => {
      const keep = () => rendered.push(doc.body.textContent ?? "");
      doc.getElementById("rules-add").click();
      await waitWhile(() => !fileRows(doc).some((r) => r.textContent.includes("big/")));
      assert.ok(fileRows(doc).some((r) => r.textContent.includes("big/")), "the browser opens on the home folder");

      // G1: Go to a file on the second page.
      const input = doc.getElementById("lock-path");
      input.focus();
      input.value = "~/big/zeta-2.env";
      doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
      await waitWhile(() => !openRow(doc), 20_000);
      assert.equal(openRow(doc)?.getAttribute("data-path"), key, "the file's row is opened");
      assert.equal(fileRows(doc).length, 503, "the folder down to the page the file is on");
      assert.match(openRow(doc).textContent, /Your rule/, "with its rule on it");
      assert.equal(input.value, "~/big/", "the box reads its folder");
      assert.equal(reads(FIRST), 1, "the first page once");
      assert.equal(reads(SECOND), 1, "the second once");
      keep();

      // G2: Show in its folder on the file's Your rules row.
      doc.getElementById("files-home").click();
      await waitWhile(() => fileRows(doc).length > 10 || !fileRows(doc).some((r) => r.textContent.includes("big/")));
      assert.ok(fileRows(doc).length < 10, "the home folder is shown again");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const treeRow = [...doc.querySelectorAll("#files-tree .row.file-rule")].find((r: any) => r.textContent.includes("zeta-2.env")) as any;
      treeRow.querySelector(".file-more").click();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const show = [...doc.querySelectorAll("#files-tree button")].find((b: any) => b.textContent === "Show in its folder") as any;
      assert.ok(show, "the opened rule has Show in its folder");
      show.focus();
      show.click();
      await waitWhile(() => !openRow(doc), 20_000);
      assert.equal(openRow(doc)?.getAttribute("data-path"), key, "the file's row is opened");
      assert.equal(fileRows(doc).length, 503);
      await waitWhile(() => doc.activeElement === show);
      assert.equal(doc.activeElement, openRow(doc).querySelector(".file-more"), "the focus on its ⋯");
      assert.equal(reads(FIRST), 2, "the folder read again, once");
      assert.equal(reads(SECOND), 2);
      keep();
    }, {
      headers: { Cookie: ADMIN_COOKIE },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      beforeScripts: (w: any) => {
        // The harness's own bridge (through pageFetch), counted on the way.
        const served = w.fetch;
        w.fetch = (url: string, init?: unknown) => {
          const at = url.indexOf("/api/files/list?");
          if (at >= 0) listings.push(url.slice(at + "/api/files/list?".length));
          return served(url, init);
        };
      },
    });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // G3: the oracle on every page drawn above.
    assert.equal(rendered.length, 2);
    for (const page of rendered) {
      assert.ok(!page.includes(KEY_VALUE), "no rendered page carries the labelled file's value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
