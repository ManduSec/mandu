/**
 * product-files-again-pages.test — the file browser under Rules › Add a
 * rule reads a folder again where it stands as far as it was shown, across
 * the REAL components (dashboard.md §4.25m *The browser follows a return*).
 * Mandu-new.
 *
 * A folder is listed 500 entries at a time, and Show more reads the next
 * page. Until 2026-10-15 the read again after the protection service came
 * back asked for the first page only: the rows a Show more brought went,
 * with the labelled file among them, and "Show more" came back. Here a
 * real ArbiterServer runs at the `secrets` axes with a policy.yaml rule on
 * a file that sorts past the first page, and a real DashboardServer
 * reaches it over the production adapter (`makeApprovalsArbiter`, with its
 * secrets surface, as server-main wires it). The served product page (its
 * own index.html and home.js in jsdom, signed in) stays open on Rules with
 * the browser in a folder of 521 entries while the service stops and
 * starts under it:
 *
 *   A1  running: the browser lists 500 entries and offers Show more;
 *   A2  the service stops; Go lists the folder without labels and Show
 *       more brings the last 21, all "Label unknown"; a row past the first
 *       page is ticked and another has the focus;
 *   A3  the service starts again on the same sockets; the poll after it
 *       answers reads the folder again as far as it was shown (the test
 *       polls every 2 s, as the page's own 10 s poll would; pollWhile): all 521 rows, no Show
 *       more, the labelled file past the first page shows "Your rule", the
 *       tick and the focus stay;
 *   A4  no unhandled rejection in the page; the oracle: no rendered page
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
import { pollWhile, waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const KEY_VALUE = `sk_live_filesAgainPagesCanary_${process.pid}_0001`;
const FILES = 520; // f000.txt … f519.txt, with zz-deploy.token: 521 entries, 500 a page
const ALL = FILES + 1;
const NOTE_DOWN = "Labels could not be read. The protection service is not running. Start it under Settings, or try again in a moment. You can still choose rules.";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (doc: any, sel: string): string => doc.querySelector(sel)?.textContent ?? "";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const note = (doc: any): string | null => (doc.getElementById("files-note").hidden ? null : text(doc, "#files-note"));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const fileRows = (doc: any): any[] => [...doc.querySelectorAll("#files-list .row.file:not(.up)")];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rowFor = (doc: any, name: string) => fileRows(doc).find((r: any) => r.querySelector(".file-name").textContent.startsWith(name));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const unknown = (doc: any): number => doc.querySelectorAll("#files-list .label-chip.unknown").length;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const filesMore = (doc: any) => doc.querySelector("#files-list .files-more") as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const go = (doc: any) => doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));

test("the file browser reads a folder again as far as it was shown when the service comes back: the rows past the first page stay (real arbiter, production adapter, dashboard, served page)", { timeout: 240_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-files-pages-"));
  const home = join(tmp, "home");
  const big = join(home, "big");
  mkdirSync(big, { recursive: true });
  for (let i = 0; i < FILES; i++) writeFileSync(join(big, `f${String(i).padStart(3, "0")}.txt`), "nothing secret\n");
  // Sorts after every f…: on the second page.
  writeFileSync(join(big, "zz-deploy.token"), `${KEY_VALUE}\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(big, "zz-deploy.token")}\n    level: no-model\n`);
  // One protection service, then another on the same sockets, as a start
  // from a terminal or Settings brings it back.
  const serve = () => new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath: policy, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  let arbiter = serve();
  await arbiter.listen();
  let arbiterOpen = true;
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
  // Every request the page made, with when it was asked and answered, and
  // the steps between them: a failure says what the page saw (CI only).
  const t0 = Date.now();
  const trail: string[] = [];
  const mark = (step: string) => trail.push(`${Date.now() - t0} ms  -- ${step}`);
  const seen = () => `\npage requests (ms since start):\n${trail.slice(-40).join("\n")}`;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const traceFetch = (w: any) => {
    const viaPage = w.fetch;
    w.fetch = (url: string, init?: { method?: string }) => {
      const at = Date.now() - t0;
      const what = `${init?.method ?? "GET"} ${String(url).replace(/^https?:\/\/[^/]+/, "")}`;
      return viaPage(url, init).then(
        (r: { status: number }) => (trail.push(`${at}-${Date.now() - t0} ms  ${what} -> ${r.status}`), r),
        (e: unknown) => (trail.push(`${at}-${Date.now() - t0} ms  ${what} threw ${String(e)}`), Promise.reject(e)),
      );
    };
  };
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const ready = (doc: any) => text(doc, "#files-tree").includes("zz-deploy.token");
    await servedProductPage(base, "/rules", ready, async (doc) => {
      // The page reads again when it is shown (its 10 s poll is inert here).
      const poll = () => doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
      const keep = () => rendered.push(doc.body.textContent ?? "");

      // A1: the browser in the big folder, its first page.
      doc.getElementById("rules-add").click();
      await waitWhile(() => !doc.querySelector("#files-list .row.file"));
      (doc.getElementById("lock-path") as { value: string }).value = "~/big/";
      go(doc);
      await waitWhile(() => !rowFor(doc, "f000.txt"));
      assert.equal(fileRows(doc).length, 500, "500 entries a page");
      assert.equal(filesMore(doc).textContent, `Show more (${ALL - 500} more)`);
      assert.equal(note(doc), null);
      keep();

      // A2: the service stops; Go lists the folder without labels; Show more.
      mark("A2: the service stops");
      await arbiter.close(); arbiterOpen = false;
      poll();
      await waitWhile(() => text(doc, "#hero-headline") !== "Not connected.");
      go(doc);
      await waitWhile(() => note(doc) === null);
      assert.equal(note(doc), NOTE_DOWN);
      filesMore(doc).focus();
      filesMore(doc).click();
      await waitWhile(() => fileRows(doc).length < ALL);
      assert.equal(fileRows(doc).length, ALL);
      assert.equal(filesMore(doc), null);
      assert.equal(unknown(doc), ALL, "every label unknown, never ordinary");
      const box = rowFor(doc, "f510.txt").querySelector("input[type=checkbox]");
      box.checked = true;
      box.dispatchEvent(new doc.defaultView.Event("change"));
      assert.match(text(doc, "#files-selected"), /1 item ticked/);
      rowFor(doc, "f505.txt").querySelector(".file-tick").focus();
      keep();

      // A3: the service starts again; the poll that sees it reads the
      // folder again. A lone poll can land before the restarted service
      // answers on a loaded guest, where the page's next poll reads again.
      arbiter = serve();
      await arbiter.listen(); arbiterOpen = true;
      mark("A3: the service is back; polls until the folder is read again");
      const polls = await pollWhile(() => note(doc) !== null || unknown(doc) > 0, () => { mark("poll"); poll(); });
      mark(`A3 wait over after ${polls} polls: hero "${text(doc, "#hero-headline")}", ${unknown(doc)} unknown labels`);
      assert.equal(note(doc), null, `the note goes, with no click${seen()}`);
      assert.equal(unknown(doc), 0, "the labels are back, past the first page too");
      assert.equal(fileRows(doc).length, ALL, "the rows Show more brought stay");
      assert.equal(filesMore(doc), null, "no Show more: the folder is shown to its end");
      assert.match(rowFor(doc, "zz-deploy.token").textContent, /Your rule/, "the rule is shown on its file, past the first page");
      assert.equal(rowFor(doc, "f510.txt").querySelector("input[type=checkbox]").checked, true, "the tick stays");
      assert.match(text(doc, "#files-selected"), /1 item ticked/);
      assert.equal(doc.activeElement, rowFor(doc, "f505.txt").querySelector(".file-tick"), "the focus stays on its row");
      keep();
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: traceFetch });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // A4: the oracle on every page drawn above.
    assert.equal(rendered.length, 3);
    for (const page of rendered) {
      assert.ok(!page.includes(KEY_VALUE), "no rendered page carries the labelled file's value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    if (arbiterOpen) await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
