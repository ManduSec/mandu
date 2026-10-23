/**
 * product-files-back.test — the file browser under Rules › Add a rule says
 * a stopped protection service in the page's words, and reads its folder
 * again when the service or the dashboard comes back, across the REAL
 * components (dashboard.md §4.25 *What could not be read is read again*,
 * §4.25m). Mandu-new.
 *
 * Until 2026-10-10, with the service stopped, the browser's note carried
 * the failed dial as the route got it ("… did not answer (connect ENOENT
 * /…/arbiter.sock)"), and once the service, or the dashboard, came back
 * the note and every row's "Label unknown" stayed until another folder was
 * opened. Here a real ArbiterServer runs at the `secrets` axes with a
 * policy.yaml rule on a file, and a real DashboardServer reaches it over
 * the production adapter (`makeApprovalsArbiter`, with its secrets surface,
 * as server-main wires it). The served product page (its own index.html
 * and home.js in jsdom, signed in) stays open on Rules with the browser in
 * the project folder while the components stop and start under it:
 *
 *   F1  running: the browser lists the folder with its labels: the file
 *       with the rule shows "Your rule"; no note;
 *   F2  the service stops; Go reads the folder: the note says the service
 *       is not running, with the link to Settings, never a socket path;
 *       the rows' labels are unknown; a row is ticked and a path typed;
 *   F3  the service starts again on the same sockets; the poll after it
 *       answers reads the folder again (the test polls every 2 s, as the
 *       page's own 10 s poll would; pollWhile): no note, the labels are back, the
 *       tick and the typed path stay;
 *   F4  the dashboard server stops (no poll sees it) and Go gets no
 *       answer: the note says so; a new dashboard starts on the same port,
 *       and the next poll that answers reads the folder again: no note;
 *   F5  no unhandled rejection in the page; the oracle: no rendered page
 *       carries the labelled file's value or a token.
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

stateAxes("secrets");

const KEY_VALUE = "sk_" + "live_productFilesBackStackCanary0001";
const NOTE_DOWN = "Labels could not be read. The protection service is not running. Start it under Settings, or try again in a moment. You can still choose rules.";
const GONE = "The dashboard could not reach its own server. Refresh in a moment.";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (doc: any, sel: string): string => doc.querySelector(sel)?.textContent ?? "";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const note = (doc: any): string | null => (doc.getElementById("files-note").hidden ? null : text(doc, "#files-note"));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rowFor = (doc: any, name: string) => [...doc.querySelectorAll("#files-list .row.file:not(.up)")]
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  .find((r: any) => r.querySelector(".file-name").textContent.startsWith(name)) as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const unknown = (doc: any): number => doc.querySelectorAll("#files-list .label-chip.unknown").length;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const go = (doc: any) => doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));

test("the file browser says a stopped service in the page's words and reads its folder again when the service, then the dashboard, comes back (real arbiter, production adapter, dashboard, served page)", { timeout: 240_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-files-back-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, "deploy.token"), `${KEY_VALUE}\n`);
  writeFileSync(join(proj, "notes.txt"), "nothing secret\n");
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(proj, "deploy.token")}\n    level: no-model\n`);
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
  // One dashboard, then another on the same port, as a restart brings it back.
  const dash = () => new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policy },
    log: () => {}, ...ADMIN_OPTS,
  });
  let dashboard = dash();
  const port = await dashboard.listen(0);
  let dashboardOpen = true;
  const base = `http://127.0.0.1:${port}`;
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const rendered: string[] = [];
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const ready = (doc: any) => text(doc, "#files-tree").includes("deploy.token");
    await servedProductPage(base, "/rules", ready, async (doc) => {
      // The page reads again when it is shown (its 10 s poll is inert here).
      const poll = () => doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
      const keep = () => rendered.push(doc.body.textContent ?? "");
      const notes: string[] = [];
      const watch = new doc.defaultView.MutationObserver(() => notes.push(text(doc, "#files-note")));
      watch.observe(doc.getElementById("files-note"), { childList: true, subtree: true, characterData: true });

      // F1: the browser in the project folder, its labels read.
      doc.getElementById("rules-add").click();
      await waitWhile(() => !doc.querySelector("#files-list .row.file"));
      (doc.getElementById("lock-path") as { value: string }).value = "~/proj/";
      go(doc);
      await waitWhile(() => !rowFor(doc, "deploy.token"));
      assert.match(rowFor(doc, "deploy.token").textContent, /Your rule/, "the rule is shown on its file");
      assert.equal(note(doc), null);
      keep();

      // F2: the service stops; Go reads the folder.
      await arbiter.close(); arbiterOpen = false;
      poll();
      await waitWhile(() => text(doc, "#hero-headline") !== "Not connected.");
      go(doc);
      await waitWhile(() => note(doc) === null);
      assert.equal(note(doc), NOTE_DOWN);
      const links = [...doc.querySelectorAll("#files-note a")].map((a) => [a.textContent, a.getAttribute("data-page-link")]);
      assert.deepEqual(links, [["Start it under Settings", "settings"]]);
      assert.equal(unknown(doc), 2, "the labels are unknown, never ordinary");
      const box = rowFor(doc, "notes.txt").querySelector("input[type=checkbox]");
      box.checked = true;
      box.dispatchEvent(new doc.defaultView.Event("change"));
      assert.match(text(doc, "#files-selected"), /1 item ticked/);
      (doc.getElementById("lock-path") as { value: string }).value = "~/proj/no";
      keep();

      // F3: the service starts again; the poll that sees it reads again
      // (a lone poll can land before the restarted service answers).
      arbiter = serve();
      await arbiter.listen(); arbiterOpen = true;
      await pollWhile(() => note(doc) !== null || unknown(doc) > 0, poll);
      assert.equal(note(doc), null, "the note goes, with no click");
      assert.equal(unknown(doc), 0, "the labels are back");
      assert.match(rowFor(doc, "deploy.token").textContent, /Your rule/);
      assert.equal(rowFor(doc, "notes.txt").querySelector("input[type=checkbox]").checked, true, "the tick stays");
      assert.match(text(doc, "#files-selected"), /1 item ticked/);
      assert.equal((doc.getElementById("lock-path") as { value: string }).value, "~/proj/no", "the typed path stays");
      keep();

      // F4: the dashboard stops with no poll to see it; Go gets no answer.
      await dashboard.close(); dashboardOpen = false;
      go(doc);
      await waitWhile(() => note(doc) !== GONE);
      assert.equal(note(doc), GONE);
      keep();
      dashboard = dash();
      await dashboard.listen(port); dashboardOpen = true;
      // The polls that answer, after no poll that failed.
      await pollWhile(() => note(doc) !== null, poll);
      assert.equal(note(doc), null, "the note goes once the dashboard answers");
      assert.match(rowFor(doc, "deploy.token").textContent, /Your rule/);
      keep();
      watch.disconnect();
      assert.ok(notes.every((t) => !/ENOENT|ECONNREFUSED|\.sock\b/.test(t)), `never a socket in the note: ${JSON.stringify(notes)}`);
      assert.doesNotMatch(rendered.join("\n"), /fetch failed|Failed to fetch/, "never the browser's words");
    }, { headers: { Cookie: ADMIN_COOKIE } });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // F5: the oracle on every page drawn above.
    assert.equal(rendered.length, 5);
    for (const page of rendered) {
      assert.ok(!page.includes(KEY_VALUE), "no rendered page carries the labelled file's value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    if (dashboardOpen) await dashboard.close();
    if (arbiterOpen) await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
