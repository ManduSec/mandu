/**
 * product-complete-pages.test — Tab completion on the path box under
 * Rules › Add a rule knows the whole folder, not its first page, across the
 * REAL components (dashboard.md §4.25m *Typed paths and Tab completion*).
 * Mandu-new.
 *
 * The listing answers 500 entries a page, folders first and then by name.
 * Until 2026-10-15 completion read the first page only, so in a folder of
 * 500 folders no file could be completed, and a name a folder and a file
 * share completed to the folder. Here a real ArbiterServer runs at the
 * `secrets` axes with a policy.yaml rule on a file past the first page, and
 * a real DashboardServer reaches it over the production adapter
 * (`makeApprovalsArbiter`, with its secrets surface, as server-main wires
 * it). The served product page (its own index.html and home.js in jsdom,
 * signed in) types in its path box over a real folder of 500 folders and
 * three files:
 *
 *   T1  a folder not shown: Tab completes `~/big/zet` to `~/big/zeta-`, a
 *       name past row 500, reading the folder's two pages once each;
 *   T2  `~/big/not` completes to `~/big/notes` (the folder notes and the
 *       file notes.md), never `~/big/notes/`; the suggestions list both;
 *       a third Tab reads nothing more;
 *   T3  the folder shown, after Show more: Tab reads nothing and completes
 *       from the rows read;
 *   T4  no unhandled rejection in the page; the oracle: no rendered page
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

const KEY_VALUE = `sk_live_completePagesCanary_${process.pid}_0001`;
const DIRS = 499; // d000 … d498, with notes/: 500 folders, the whole first page

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (doc: any, sel: string): string => doc.querySelector(sel)?.textContent ?? "";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const fileRows = (doc: any): any[] => [...doc.querySelectorAll("#files-list .row.file:not(.up)")];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const suggestions = (doc: any): string[] => [...doc.querySelectorAll("#files-suggest option")].map((o: any) => o.value);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const filesMore = (doc: any) => doc.querySelector("#files-list .files-more") as any;
/** Tab at the end of `value`, as a person presses it; waits for the box to change. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function tab(doc: any, value: string): Promise<string> {
  const input = doc.getElementById("lock-path");
  input.value = value;
  input.setSelectionRange(value.length, value.length);
  const e = new doc.defaultView.KeyboardEvent("keydown", { key: "Tab", cancelable: true });
  input.dispatchEvent(e);
  assert.equal(e.defaultPrevented, true, "Tab stays in the path box");
  await waitWhile(() => input.value === value, 20_000);
  return input.value;
}

test("Tab on the path box completes names past a folder's first page, and a name a folder and a file share to their shared start (real arbiter, production adapter, dashboard, served page)", { timeout: 240_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-complete-pages-"));
  const home = join(tmp, "home");
  const big = join(home, "big");
  mkdirSync(big, { recursive: true });
  for (let i = 0; i < DIRS; i++) mkdirSync(join(big, `d${String(i).padStart(3, "0")}`));
  mkdirSync(join(big, "notes"));
  // Files sort after every folder: all three are on the second page.
  writeFileSync(join(big, "notes.md"), "nothing secret\n");
  writeFileSync(join(big, "zeta-1.env"), "NOTHING=secret\n");
  writeFileSync(join(big, "zeta-2.env"), `DEPLOY_KEY=${KEY_VALUE}\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(big, "zeta-2.env")}\n    level: no-model\n`);
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
  const FIRST = `path=${encodeURIComponent("~/big")}`;
  const SECOND = `path=${encodeURIComponent(big)}&offset=500`;
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const ready = (doc: any) => text(doc, "#files-tree").includes("zeta-2.env");
    await servedProductPage(base, "/rules", ready, async (doc) => {
      const keep = () => rendered.push(doc.body.textContent ?? "");
      doc.getElementById("rules-add").click();
      await waitWhile(() => !fileRows(doc).some((r) => r.textContent.includes("big/")));
      assert.ok(fileRows(doc).some((r) => r.textContent.includes("big/")), "the browser opens on the home folder");
      keep();

      // T1: a folder not shown; a name past row 500.
      assert.equal(await tab(doc, "~/big/zet"), "~/big/zeta-", "the two zeta files are past the first page");
      assert.deepEqual(suggestions(doc), ["~/big/zeta-1.env", "~/big/zeta-2.env"]);
      assert.equal(reads(FIRST), 1, "the first page once");
      assert.equal(reads(SECOND), 1, "the next once");

      // T2: a folder and a file share the name.
      assert.equal(await tab(doc, "~/big/not"), "~/big/notes", "never notes/: notes.md is there too");
      assert.deepEqual(suggestions(doc), ["~/big/notes/", "~/big/notes.md"]);
      assert.equal(await tab(doc, "~/big/zeta-2"), "~/big/zeta-2.env");
      assert.equal(reads(FIRST) + reads(SECOND), 2, "later Tabs in the folder read nothing");
      keep();

      // T3: the folder shown, to its end by Show more: Tab reads nothing.
      doc.getElementById("lock-path").value = "~/big/";
      doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
      await waitWhile(() => fileRows(doc).length < 500 || !filesMore(doc));
      assert.equal(fileRows(doc).length, 500, "500 entries a page");
      filesMore(doc).click();
      await waitWhile(() => fileRows(doc).length < 503);
      assert.equal(fileRows(doc).length, 503);
      assert.match(fileRows(doc).find((r) => r.textContent.includes("zeta-2.env"))!.textContent, /Your rule/, "the rule shows on its file");
      const before = listings.length;
      assert.equal(await tab(doc, "~/big/zeta-1"), "~/big/zeta-1.env");
      assert.equal(listings.length, before, "Tab reads nothing: the browser read both pages");
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

    // T4: the oracle on every page drawn above.
    assert.equal(rendered.length, 3);
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
