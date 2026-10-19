/**
 * home-poll-order.test — a Home poll's answer that comes after a newer
 * poll's is dropped, across the REAL components (dashboard.md §4.25 *An
 * older poll's answer never draws over a newer one*). Mandu-new.
 *
 * Home polls overlap: the read when the page opens, the 10 s poll, a return
 * to the tab, the read after an answer. Until 2026-10-12 whichever answered
 * LAST drew the page, even when it was asked first. On a slow network the
 * read the page opened with answered after a poll that already knew the
 * protection service had stopped: the page went back to its connected
 * state, and Settings › Prompt filters, which says the service is not
 * running only while the latest Home poll knows it, said "The protection
 * service did not answer." (master pipeline 10542,
 * product-could-not-read-why, after a 60 s wait). Here a real ArbiterServer
 * runs at the `secrets` axes, a real DashboardServer reaches it over the
 * production adapter (`makeApprovalsArbiter`), and the served product page
 * (its own index.html and home.js in jsdom, signed in) reaches the
 * dashboard through a relay that holds one `/api/home` answer back
 * (tests/lib/holding-relay.ts):
 *
 *   O1  the page's first Home read is held; the service stops, and the
 *       next poll says it is not running;
 *   O2  the held answer (from before the stop) comes: the hero still says
 *       the service is not running, Settings › Prompt filters says so with
 *       the link, never "did not answer", and Settings › Protection cannot
 *       say what runs;
 *   O3  a poll made while the service is down is held; the service comes
 *       back and the next poll lists the prompt filters again;
 *   O4  the held answer (the service not running) comes: the page stays
 *       connected, its lists stay drawn;
 *   O5  no unhandled rejection; the oracle: no rendered page carries the
 *       labelled file's value or a token.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { holdingRelay } from "../lib/holding-relay.js";

stateAxes("secrets");

const KEY_VALUE = "sk_live_homePollOrderStackCanary00001";
const DOWN_LINKED = "The protection service is not running. Start it under Settings, or try again in a moment.";
const DOWN_HERO = "The protection service is not running, so nothing can be checked. Start it under Settings, or refresh in a moment.";
const NOT_REACHABLE = "Saved as on. The protection service is not reachable, so Mandu cannot say what is on now.";
/** How long a page is given to draw a held answer it must drop: a page
 *  that draws it changes the hero within this, a page that drops it never
 *  does. */
const SETTLE_MS = 1500;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (doc: any, sel: string): string => doc.querySelector(sel)?.textContent ?? "";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const promptKinds = (doc: any): number => doc.querySelectorAll("#settings-prompt-kinds .prompt-kind").length;
/** Open a page of the product as its nav does. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const visit = (doc: any, page: string) => doc.querySelector(`[data-page-link="${page}"]`)
  .dispatchEvent(new doc.defaultView.MouseEvent("click", { bubbles: true, cancelable: true, button: 0 }));

test("a Home poll that answers after a newer one is dropped: the page keeps the newer answer when the service stops and when it comes back (real arbiter, production adapter, dashboard, served page)", { timeout: 240_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-poll-order-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  // One protection service, then another on the same sockets, as a start
  // from a terminal or the developer view brings it back.
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
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policy },
    log: () => {}, ...ADMIN_OPTS,
  });
  const relay = await holdingRelay(await dashboard.listen(0));
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const rendered: string[] = [];
  try {
    // A labelled secret file, for the oracle: no page below may carry it.
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const admin = new ArbiterClient(adminSock);
    await admin.connect();
    await admin.setPathLabel({ path: env, confidentiality: "no-model", bindings: [], recursive: false });
    admin.close();
    const stop = async () => { await arbiter.close(); arbiterOpen = false; };
    const start = async () => { arbiter = serve(); await arbiter.listen(); arbiterOpen = true; };

    // O1: the first Home read is held; Settings reads without it.
    const first = relay.holdNext("/api/home");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const settingsRead = (doc: any) => promptKinds(doc) > 0;
    await servedProductPage(relay.base, "/settings", settingsRead, async (doc) => {
      // The page reads again when it is shown (its 10 s poll is inert here).
      const poll = () => doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
      const keep = () => rendered.push(doc.body.textContent ?? "");
      assert.equal(await first.asked, 200, "the first read was answered while the service ran, and held");
      assert.equal(text(doc, "#hero-headline"), "Checking…", "nothing drawn from it yet");
      keep();
      await stop();
      poll();
      await waitWhile(() => text(doc, "#hero-headline") !== "Not connected.");
      assert.equal(text(doc, "#hero-sentence"), DOWN_HERO);

      // O2: the held answer from before the stop comes, and is dropped.
      await first.release();
      await waitWhile(() => text(doc, "#hero-headline") === "Not connected.", SETTLE_MS);
      assert.equal(text(doc, "#hero-headline"), "Not connected.", "the older answer never draws over the newer one");
      assert.equal(text(doc, "#hero-sentence"), DOWN_HERO);
      assert.equal(text(doc, "#top-status"), "Not connected");
      visit(doc, "home");
      visit(doc, "settings");
      await waitWhile(() => promptKinds(doc) > 0 || text(doc, "#settings-prompt-kinds") === "");
      assert.equal(text(doc, "#settings-prompt-kinds"), DOWN_LINKED, "Prompt filters says the service is not running, never \"did not answer\"");
      await waitWhile(() => text(doc, "#settings-protect-text") !== NOT_REACHABLE);
      assert.equal(text(doc, "#settings-protect-text"), NOT_REACHABLE, "Protection never says what the older answer said runs");
      keep();

      // O3: a poll made while the service is down is held; the service
      // comes back and the next poll lists the prompt filters again.
      const stale = relay.holdNext("/api/home");
      poll();
      assert.equal(await stale.asked, 503, "answered while the service was down, and held");
      await start();
      poll();
      await waitWhile(() => text(doc, "#hero-headline") === "Not connected." || !promptKinds(doc));
      assert.notEqual(text(doc, "#hero-headline"), "Not connected.", text(doc, "#hero-sentence"));
      assert.ok(promptKinds(doc) > 0, "the prompt filters are listed again");
      const level = text(doc, "#top-status");
      assert.match(level, /^Protection (on|off)/);
      keep();

      // O4: the held answer (the service not running) comes, and is dropped.
      await stale.release();
      await waitWhile(() => text(doc, "#hero-headline") !== "Not connected.", SETTLE_MS);
      assert.notEqual(text(doc, "#hero-headline"), "Not connected.", "the older failure never draws over the newer answer");
      assert.equal(text(doc, "#top-status"), level);
      assert.ok(promptKinds(doc) > 0, "the prompt filters stay listed");
      keep();
      assert.doesNotMatch(rendered.join("\n"), /did not answer|fetch failed|Failed to fetch/, "never the route's words for a failed dial, nor the browser's");
    }, { headers: { Cookie: ADMIN_COOKIE } });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // O5: the oracle on every page drawn above.
    assert.equal(rendered.length, 4);
    for (const page of rendered) {
      assert.ok(!page.includes(KEY_VALUE), "no rendered page carries the secret value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await relay.close();
    await dashboard.close();
    if (arbiterOpen) await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
