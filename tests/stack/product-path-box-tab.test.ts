/**
 * product-path-box-tab.test — Tab in the path box under Rules › Add a rule
 * finishes the name being typed and otherwise moves the focus on, across
 * the REAL components (dashboard.md §4.25m *Tab moves on*). Mandu-new.
 *
 * Until 2026-10-15 the box kept every Tab without Shift while its text
 * ended at the caret or the selection; it always holds the folder shown,
 * so the keyboard could not leave it but backwards
 * (home-js-files-tab-moves-on.test.ts M1-M8). A Tab the box keeps is one
 * whose keydown is defaultPrevented; any other moves the focus on. Here a
 * real ArbiterServer runs at the `secrets` axes with a policy.yaml rule on
 * a file, and a real DashboardServer reaches it over the production adapter
 * (`makeApprovalsArbiter`, with its secrets surface, as server-main wires
 * it). The served product page (its own index.html and home.js in jsdom,
 * signed in) over a real folder of three files and a folder of one; the
 * page's own fetch is wrapped to count its listing reads.
 *
 *   T1  after Go, and on the way in (the whole text selected), Tab moves on
 *       and reads nothing;
 *   T2  a name that completes from the folder shown keeps the Tab and is
 *       finished, reading nothing; the next Tab moves on;
 *   T3  `~/proj/config/` is not filled in with its one name, and a folder's
 *       name typing added is taken by Tab without it; a pattern moves on;
 *   T4  a folder that cannot be listed: the first Tab waits for the real
 *       listing's refusal and stays, the second moves on, reading nothing;
 *   T5  no unhandled rejection in the page; the oracle: no rendered page
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

const KEY_VALUE = `sk_live_pathBoxTabCanary_${process.pid}_0001`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (doc: any, sel: string): string => doc.querySelector(sel)?.textContent ?? "";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const fileRows = (doc: any): any[] => [...doc.querySelectorAll("#files-list .row.file:not(.up)")];

test("Tab in the path box finishes a name, and otherwise moves the focus on (real arbiter, production adapter, dashboard, served page)", { timeout: 240_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-path-box-tab-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  mkdirSync(join(proj, "config"), { recursive: true });
  writeFileSync(join(proj, "config", "db.yaml"), "host: localhost\n");
  writeFileSync(join(proj, "notes.md"), "nothing secret\n");
  writeFileSync(join(proj, "zeta-1.env"), "NOTHING=secret\n");
  const key = join(proj, "zeta-2.env");
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
  // Every listing the page asks for (the query after `files/list?`), and those answered.
  const listings: string[] = [];
  const answered: string[] = [];
  const GONE = `path=${encodeURIComponent("~/gone")}`;
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const ready = (doc: any) => text(doc, "#files-tree").includes("zeta-2.env");
    await servedProductPage(base, "/rules", ready, async (doc) => {
      const keep = () => rendered.push(doc.body.textContent ?? "");
      const input = doc.getElementById("lock-path");
      /** Tab on the box as it stands (`at`: the selection); true when the box keeps it. */
      const press = (at?: [number, number]) => {
        input.focus();
        input.setSelectionRange(...(at ?? [input.value.length, input.value.length]));
        const e = new doc.defaultView.KeyboardEvent("keydown", { key: "Tab", cancelable: true });
        input.dispatchEvent(e);
        return e.defaultPrevented as boolean;
      };
      doc.getElementById("rules-add").click();
      await waitWhile(() => !fileRows(doc).some((r) => r.textContent.includes("proj/")));
      input.focus();
      input.value = "~/proj";
      doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
      await waitWhile(() => !fileRows(doc).some((r) => r.getAttribute("data-path") === key), 20_000);
      assert.equal(input.value, "~/proj/", "Go leaves the folder's path in the box");
      keep();
      const shownReads = listings.length;

      // T1: after Go, and on the way in.
      assert.equal(press(), false, "after Go, Tab moves on");
      assert.equal(press([0, input.value.length]), false, "on the way in, Tab moves on");
      assert.equal(input.value, "~/proj/");

      // T2: a name that completes from the folder shown.
      input.value = "~/proj/zeta-2";
      assert.equal(press(), true, "the box keeps the Tab");
      await waitWhile(() => input.value === "~/proj/zeta-2", 20_000);
      assert.equal(input.value, "~/proj/zeta-2.env");
      assert.equal(press(), false, "the next Tab moves on");
      assert.equal(listings.length, shownReads, "the shown folder's names: no listing read");

      // T3: no name started; a folder's name typing added; a pattern.
      input.value = "~/proj/config/";
      assert.equal(press(), false, "no name is started: Tab moves on");
      assert.equal(input.value, "~/proj/config/", "never ~/proj/config/db.yaml");
      input.value = "~/proj/con";
      input.setSelectionRange(10, 10);
      input.dispatchEvent(new doc.defaultView.InputEvent("input", { inputType: "insertText", data: "n" }));
      await waitWhile(() => input.value === "~/proj/con", 20_000);
      assert.equal(input.value, "~/proj/config/", "typing adds the folder's name, selected");
      assert.equal(press([10, 14]), true, "Tab takes what typing added");
      assert.deepEqual([input.selectionStart, input.selectionEnd], [14, 14], "the caret after it");
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(input.value, "~/proj/config/", "nothing inside it filled in");
      assert.equal(listings.length, shownReads, "and no listing read");
      input.value = "**/*.env";
      assert.equal(press(), false, "a pattern: Tab moves on");

      // T4: a folder that cannot be listed.
      input.value = "~/gone/x";
      assert.equal(press(), true, "its names are not read yet: the box keeps the Tab");
      await waitWhile(() => !answered.includes(GONE), 20_000);
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(input.value, "~/gone/x");
      assert.equal(press(), false, "the second Tab on the same text moves on");
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(listings.filter((q) => q === GONE).length, 1, "read once");
      keep();
    }, {
      headers: { Cookie: ADMIN_COOKIE },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      beforeScripts: (w: any) => {
        // The harness's own bridge (through pageFetch), counted on the way.
        const served = w.fetch;
        w.fetch = (url: string, init?: unknown) => {
          const at = url.indexOf("/api/files/list?");
          const query = at >= 0 ? url.slice(at + "/api/files/list?".length) : null;
          if (query === null) return served(url, init);
          listings.push(query);
          return served(url, init).then((r: unknown) => { answered.push(query); return r; });
        };
      },
    });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // T5: the oracle on every page drawn above.
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
