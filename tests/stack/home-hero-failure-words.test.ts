/**
 * home-hero-failure-words.test — Home's hero says why it cannot check in
 * words, across the REAL components (dashboard.md §4.25, *The hero says why
 * in words*). Mandu-new.
 *
 * Until 2026-10-10 the hero put the failed request's own text in its
 * sentence: "The protection service is not running, so nothing can be
 * checked (home → 503). …" with the service stopped (a normal state between
 * agents), and "The dashboard could not reach its own server (fetch
 * failed). …" in the browser's words (Chrome "Failed to fetch") with the
 * dashboard gone. Here a real ArbiterServer runs at the `secrets` axes and a
 * real DashboardServer reads it over a real ArbiterEventSource; the served
 * product page (its own index.html and home.js in jsdom) stays open while
 * the components stop under it:
 *
 *   H1  both running: the hero reads the home, not "Not connected.";
 *   H2  the arbiter stops; the page's next read (the server's 503
 *       `unreachable`) says "The protection service is not running, so
 *       nothing can be checked. Start it under Settings, or refresh in a
 *       moment.", its one link opening Settings, with no request, status or
 *       dial in it;
 *   H3  the dashboard server stops too; the page's next read never gets an
 *       answer and says "The dashboard could not reach its own server.
 *       Refresh in a moment.", without what the fetch threw;
 *   H4  the oracle: no rendered page carries the labelled file's value or a
 *       token, nor does a notification the page raised;
 *   H5  with a session recorded as running and notifications granted, the
 *       stop raises exactly one "Mandu: the protection service stopped"
 *       (dashboard.md §4.25 *Notifications*); the dashboard going too adds
 *       none.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const KEY_VALUE = "sk_live_homeHeroFailureWordsStackCanary01";
/** What the request, its status or a failed fetch would say, which the hero must not. */
const RAW = /→|\bhome\b|\b50\d\b|fetch|ENOENT|ECONNREFUSED|\.sock\b|arbiter/i;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (doc: any, id: string): string => doc.getElementById(id)?.textContent ?? "";

test("Home's hero says why it cannot check in words: the service stopped, then the dashboard gone (real arbiter, dashboard, served page)", { timeout: 240_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-hero-failure-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const data = new ArbiterClient(socketPath); await data.connect();
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    fileBrowserHome: home,
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  let arbiterOpen = true;
  let dashboardOpen = true;
  try {
    // A labelled secret file, for the oracle: no page below may carry it.
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    await admin.setPathLabel({ path: env, confidentiality: "no-model", bindings: [], recursive: false });
    // A running agent (H5): its session has just talked to the model.
    await data.emit({ id: "run-1", sessionId: "hero-running", ts: new Date().toISOString(), kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy" } as never);
    // The browser's notifications, granted and recorded (H5).
    const notes: { title: string; body: string }[] = [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const recordNotes = (w: any) => {
      function N(this: { close: () => void }, title: string, o: { body: string }) { notes.push({ title, body: o.body }); this.close = () => {}; }
      (N as unknown as { permission: string }).permission = "granted";
      w.Notification = N;
    };
    const noteText = () => notes.map((n) => `${n.title} ${n.body}`).join("\n");

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const connected = (doc: any) => text(doc, "hero-headline") !== "Checking…" && !!doc.querySelector('#home-agents .row.agent[data-session="hero-running"]'); // the first read drew the hero and the running agent
    await servedProductPage(base, "/", connected, async (doc) => {
      // H1: both running, the hero reads the home.
      assert.notEqual(doc.getElementById("hero").dataset.verdict, "unknown", text(doc, "hero-sentence"));
      assert.notEqual(text(doc, "hero-headline"), "Not connected.");
      assert.ok(doc.querySelector('#home-agents .row.agent[data-session="hero-running"]'), "the agent is listed as running");
      assert.equal(notes.length, 0, "nothing to tell yet");
      // The page reads again when it is shown (its 10 s poll is inert here).
      const readAgain = () => doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));

      // H2: the protection service stops under the open page.
      admin.close();
      await arbiter.close();
      arbiterOpen = false;
      readAgain();
      await waitWhile(() => text(doc, "hero-headline") !== "Not connected.");
      assert.equal(text(doc, "hero-headline"), "Not connected.");
      const down = text(doc, "hero-sentence");
      assert.equal(down, "The protection service is not running, so nothing can be checked. Start it under Settings, or refresh in a moment.");
      assert.doesNotMatch(down, RAW, "no request, status or dial in the sentence");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const links = [...doc.querySelectorAll("#hero-sentence a")] as any[];
      assert.deepEqual(links.map((a) => [a.textContent, a.getAttribute("href"), a.getAttribute("data-page-link")]), [["Start it under Settings", "/settings", "settings"]]);
      assert.equal(text(doc, "top-status"), "Not connected");
      // H4 on this page.
      assert.ok(!doc.body.textContent.includes(KEY_VALUE), "the page carries no secret value");
      assert.doesNotMatch(doc.body.textContent, /\$MDU/, "nor a token");
      // H5: the stop under a running agent, told once; H4 on its words.
      assert.deepEqual(notes.map((n) => n.title), ["Mandu: the protection service stopped"]);
      assert.equal(notes[0]!.body, "Your agent's requests are blocked until it runs again. Open Settings to start it.");
      assert.ok(!noteText().includes(KEY_VALUE), "the notification carries no secret value");
      assert.doesNotMatch(noteText(), /\$MDU/, "nor a token");
      assert.doesNotMatch(noteText(), RAW, "nor a request, status or dial");
      // A second poll with the service still stopped says nothing.
      readAgain();
      await new Promise((r) => setTimeout(r, 500));
      assert.equal(notes.length, 1, noteText());

      // H3: the dashboard server goes too; the next read gets no answer.
      await dashboard.close();
      dashboardOpen = false;
      readAgain();
      await waitWhile(() => text(doc, "hero-sentence") === down);
      const gone = text(doc, "hero-sentence");
      assert.equal(gone, "The dashboard could not reach its own server. Refresh in a moment.");
      assert.doesNotMatch(gone, RAW, "not what the fetch threw");
      assert.equal(doc.querySelector("#hero-sentence a"), null, "nothing to open");
      assert.equal(text(doc, "hero-headline"), "Not connected.");
      // H4 on this page.
      assert.ok(!doc.body.textContent.includes(KEY_VALUE), "the page carries no secret value");
      assert.doesNotMatch(doc.body.textContent, /\$MDU/, "nor a token");
      // H5: the next failed polls say nothing.
      assert.equal(notes.length, 1, noteText());
    }, { beforeScripts: recordNotes });
  } finally {
    if (dashboardOpen) await dashboard.close();
    data.close();
    if (arbiterOpen) { admin.close(); await arbiter.close(); }
    rmSync(tmp, { recursive: true, force: true });
  }
});
