/**
 * product-files-pick-own-read.test — in the file browser under Rules › Add a
 * rule, a file asked for with Show in its folder is opened by that read only,
 * across the REAL components (dashboard.md §4.25m *Browsing*, *A pick is its
 * read's own*). Mandu-new.
 *
 * Show in its folder opens the file's folder with its row picked. Until
 * 2026-10-15 the pick waited in the page's state when its read got no
 * answer, or when another read overtook it, and the next listing of that
 * folder opened the row unasked (in a folder of more than 500 entries,
 * reading the folder on to it too: home-js-files-pick-pages.test.ts K9-K12).
 * Here a real ArbiterServer runs at the `secrets` axes with a policy.yaml
 * rule on a file, and a real DashboardServer reaches it over the production
 * adapter (`makeApprovalsArbiter`, with its secrets surface, as server-main
 * wires it). The served product page (its own index.html and home.js in
 * jsdom, signed in) over a real folder of three files; the page's own fetch
 * is wrapped to count its listing reads, to give one no answer and to hold
 * one. The folder is small on purpose: this file runs beside the other
 * stack files, and the defect needs no second page.
 *
 *   P1  Show in its folder whose read gets no answer: the page says so; Go
 *       to ~/proj then shows the folder with nothing opened;
 *   P2  Show in its folder, and Go to ~/proj before its read answers: the
 *       Go's listing, nothing opened, and the late answer draws nothing;
 *   P3  no unhandled rejection in the page; the oracle: no rendered page
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

const KEY_VALUE = `sk_live_pickOwnReadCanary_${process.pid}_0001`;
const FILES = 3; // notes.md, zeta-1.env, zeta-2.env

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (doc: any, sel: string): string => doc.querySelector(sel)?.textContent ?? "";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const fileRows = (doc: any): any[] => [...doc.querySelectorAll("#files-list .row.file:not(.up)")];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const openRow = (doc: any) => doc.querySelector("#files-list .row.file.open") as any;

test("a file asked for with Show in its folder is opened by that read only, never by a later Go (real arbiter, production adapter, dashboard, served page)", { timeout: 240_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-pick-own-read-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
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
  // Every listing the page asks for, as it asks (the query after `files/list?`).
  const listings: string[] = [];
  const reads = (query: string) => listings.filter((q) => q === query).length;
  // Show in its folder reads the folder as the rule writes it (absolute); Go as typed.
  const PICKED = `path=${encodeURIComponent(proj)}`;
  const TYPED = `path=${encodeURIComponent("~/proj")}`;
  // The next read of PICKED: given no answer, or held until released.
  let next: "none" | "fail" | "hold" = "none";
  // Set inside the page's fetch, so not narrowed to its first value.
  let release = null as (() => void) | null;
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const ready = (doc: any) => text(doc, "#files-tree").includes("zeta-2.env");
    await servedProductPage(base, "/rules", ready, async (doc) => {
      const keep = () => rendered.push(doc.body.textContent ?? "");
      const input = doc.getElementById("lock-path");
      const go = async (path: string, shown: () => boolean) => {
        input.focus();
        input.value = path;
        doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
        await waitWhile(() => !shown(), 20_000);
      };
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const showButton = () => [...doc.querySelectorAll("#files-tree button")].find((b: any) => b.textContent === "Show in its folder") as any;
      const showInFolder = () => {
        if (!showButton()) {
          // The rule's ⋯ opens it; it stays open after a Show in its folder.
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const treeRow = [...doc.querySelectorAll("#files-tree .row.file-rule")].find((r: any) => r.textContent.includes("zeta-2.env")) as any;
          treeRow.querySelector(".file-more").click();
        }
        const show = showButton();
        assert.ok(show, "the opened rule has Show in its folder");
        show.focus();
        show.click();
      };
      doc.getElementById("rules-add").click();
      await waitWhile(() => !fileRows(doc).some((r) => r.textContent.includes("proj/")));
      assert.ok(fileRows(doc).some((r) => r.textContent.includes("proj/")), "the browser opens on the home folder");
      const inProj = () => fileRows(doc).length === FILES && fileRows(doc).some((r) => r.getAttribute("data-path") === key);

      // P1: Show in its folder whose read gets no answer, then Go to the folder.
      next = "fail";
      showInFolder();
      const note = doc.getElementById("files-note");
      await waitWhile(() => note.hidden, 20_000);
      assert.match(note.textContent, /could not reach its own server/, "the page says the read got no answer");
      assert.equal(reads(PICKED), 1, "the folder was asked for once");
      await go("~/proj", inProj);
      assert.ok(inProj(), "Go shows the folder");
      assert.equal(openRow(doc), null, "nothing is opened");
      assert.equal(reads(TYPED), 1);
      keep();

      // P2: Show in its folder, and Go to the same folder before its read answers.
      doc.getElementById("files-home").click();
      await waitWhile(() => inProj());
      next = "hold";
      showInFolder();
      await waitWhile(() => release === null);
      await go("~/proj", inProj);
      assert.ok(inProj(), "the Go's listing is shown");
      assert.equal(openRow(doc), null, "nothing is opened");
      release!();
      await new Promise((r) => setTimeout(r, 200));
      assert.ok(inProj());
      assert.equal(openRow(doc), null, "and the late answer draws nothing");
      assert.equal(reads(PICKED), 2);
      assert.equal(reads(TYPED), 2);
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
          if (query !== null) listings.push(query);
          if (query === PICKED && next === "fail") {
            next = "none";
            return Promise.reject(new TypeError("fetch failed"));
          }
          if (query === PICKED && next === "hold") {
            next = "none";
            const held = new Promise<void>((r) => (release = r));
            return held.then(() => served(url, init));
          }
          return served(url, init);
        };
      },
    });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // P3: the oracle on every page drawn above.
    assert.equal(rendered.length, 2);
    for (const page of rendered) {
      assert.ok(!page.includes(KEY_VALUE), "no rendered page carries the labelled file's value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    }
  } finally {
    release?.();
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
