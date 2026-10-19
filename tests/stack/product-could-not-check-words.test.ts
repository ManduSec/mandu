/**
 * product-could-not-check-words.test — the product page's could-not lines
 * name the cause the page knows, across the REAL components (dashboard.md
 * §4.25 *Empty states*, *A could-not line names the cause the page knows*).
 * Mandu-new.
 *
 * Until 2026-10-10 every list that could not be read said "The protection
 * service may be unreachable.": with the service stopped, where the hero
 * already said it was not running, and with the dashboard server gone too,
 * under a hero that said the dashboard could not reach its own server. Rules
 * then offered "You can still add a rule", whose file browser opened empty
 * over an unhandled `fetch failed`. Here a real ArbiterServer runs at the
 * `secrets` axes with a policy.yaml rule, a real DashboardServer reads it
 * over a real ArbiterEventSource, and the served product page (its own
 * index.html and home.js in jsdom, signed out) stays open while the
 * components stop under it:
 *
 *   C1  both running: Rules lists the rule, Settings › Models reads;
 *   C2  the arbiter stops: Home's two lines say "The protection service is
 *       not running." (the hero above has the link); Approvals' Waiting
 *       line says it with "Start it under Settings" a link, Answered
 *       earlier without; Rules › Your rules and Settings › Models say it
 *       with the link, Rules still offers "add a rule";
 *   C3  the dashboard server stops too: every one of those lines says "The
 *       dashboard could not reach its own server. Refresh in a moment.",
 *       Rules offers no "add a rule", and Add a rule's file browser says
 *       the same in its note; no unhandled rejection in the page;
 *   C4  the oracle: no rendered page carries the labelled file's value or a
 *       token.
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

const KEY_VALUE = "sk_live_productCouldNotCheckStackCanary01";
const DOWN = "The protection service is not running.";
const DOWN_LINKED = "The protection service is not running. Start it under Settings, or try again in a moment.";
const GONE = "The dashboard could not reach its own server. Refresh in a moment.";
const START = [["Start it under Settings", "/settings"]];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (doc: any, sel: string): string => doc.querySelector(sel)?.textContent ?? "";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const links = (doc: any, ...ids: string[]) => ids.flatMap((id) => [...doc.querySelectorAll(`${id} a`)]).map((a: any) => [a.textContent, a.getAttribute("href")]);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const buttons = (doc: any, id: string) => [...doc.querySelectorAll(`${id} button`)].map((b: any) => b.textContent);
/** Open a page of the product as its nav does. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const visit = (doc: any, page: string) => doc.querySelector(`[data-page-link="${page}"]`)
  .dispatchEvent(new doc.defaultView.MouseEvent("click", { bubbles: true, cancelable: true, button: 0 }));

test("the product page's could-not lines name the cause it knows: the service stopped, then the dashboard gone (real arbiter, dashboard, served page)", { timeout: 240_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-could-not-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(home, "proj", "deploy.token")}\n    level: no-model\n`);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    policyPath: policy, policyPollMs: 0,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policy },
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  let arbiterOpen = true;
  let dashboardOpen = true;
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const rendered: string[] = [];
  try {
    // A labelled secret file, for the oracle: no page below may carry it.
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    await admin.setPathLabel({ path: env, confidentiality: "no-model", bindings: [], recursive: false });

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const connected = (doc: any) => text(doc, "#hero-headline") !== "Checking…";
    await servedProductPage(base, "/", connected, async (doc) => {
      // The page reads again when it is shown (its 10 s poll is inert here).
      const readAgain = () => doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
      const keep = () => rendered.push(doc.body.textContent ?? "");

      // C1: both running; Rules lists the rule, Settings › Models reads.
      assert.notEqual(text(doc, "#hero-headline"), "Not connected.", text(doc, "#hero-sentence"));
      visit(doc, "rules");
      await waitWhile(() => !text(doc, "#files-tree").includes("deploy.token"));
      assert.match(text(doc, "#files-tree"), /deploy\.token/, "the rule is listed");
      visit(doc, "settings");
      await waitWhile(() => text(doc, "#settings-models") === "");
      assert.doesNotMatch(text(doc, "#settings-models"), /could not be read/);
      visit(doc, "home");

      // C2: the protection service stops under the open page.
      admin.close();
      await arbiter.close();
      arbiterOpen = false;
      readAgain();
      await waitWhile(() => text(doc, "#hero-headline") !== "Not connected.");
      assert.match(text(doc, "#hero-sentence"), /^The protection service is not running, so nothing can be checked\./);
      assert.equal(text(doc, "#home-waiting"), `Could not check for waiting questions. ${DOWN}`);
      assert.equal(text(doc, "#home-agents"), `Could not check which agents are running. ${DOWN}`);
      assert.deepEqual(links(doc, "#home-waiting", "#home-agents"), [], "the hero above has the link");
      keep();
      visit(doc, "approvals");
      await waitWhile(() => !/^\/approvals$/.test(doc.defaultView.location.pathname));
      assert.equal(text(doc, "#approvals-waiting"), `Could not check for waiting questions. ${DOWN_LINKED}`);
      assert.deepEqual(links(doc, "#approvals-waiting"), START);
      assert.equal(text(doc, "#approvals-answered"), `Could not check your earlier answers. ${DOWN}`);
      keep();
      visit(doc, "rules");
      await waitWhile(() => !text(doc, "#files-tree").startsWith("Your rules could not be read."));
      assert.equal(text(doc, "#files-tree"), `Your rules could not be read. ${DOWN_LINKED} You can still add a rule.`);
      assert.deepEqual(links(doc, "#files-tree"), START);
      assert.deepEqual(buttons(doc, "#files-tree"), ["add a rule"], "the file browser works without the service");
      keep();
      visit(doc, "settings");
      await waitWhile(() => !text(doc, "#settings-models").startsWith("The model list could not be read."));
      assert.equal(text(doc, "#settings-models"), `The model list could not be read. ${DOWN_LINKED}`);
      assert.deepEqual(links(doc, "#settings-models"), START);
      keep();
      visit(doc, "home");

      // C3: the dashboard server goes too; no read gets an answer.
      await dashboard.close();
      dashboardOpen = false;
      readAgain();
      await waitWhile(() => text(doc, "#hero-sentence") !== GONE);
      assert.equal(text(doc, "#hero-sentence"), GONE);
      assert.equal(text(doc, "#home-waiting"), `Could not check for waiting questions. ${GONE}`);
      assert.equal(text(doc, "#home-agents"), `Could not check which agents are running. ${GONE}`);
      keep();
      visit(doc, "approvals");
      await waitWhile(() => !/^\/approvals$/.test(doc.defaultView.location.pathname));
      assert.equal(text(doc, "#approvals-waiting"), `Could not check for waiting questions. ${GONE}`);
      assert.equal(text(doc, "#approvals-answered"), `Could not check your earlier answers. ${GONE}`);
      assert.deepEqual(links(doc, "#approvals-waiting", "#approvals-answered"), [], "nothing to open");
      keep();
      visit(doc, "rules");
      await waitWhile(() => text(doc, "#files-tree") !== `Your rules could not be read. ${GONE}`);
      assert.equal(text(doc, "#files-tree"), `Your rules could not be read. ${GONE}`);
      assert.deepEqual(buttons(doc, "#files-tree"), [], "no add a rule without the dashboard");
      // Add a rule at the top of the page still opens the file browser,
      // which says why it lists nothing.
      doc.getElementById("rules-add").click();
      await waitWhile(() => doc.getElementById("files-note").hidden);
      assert.equal(doc.getElementById("lock-form").hidden, false);
      assert.equal(text(doc, "#files-note"), GONE);
      keep();
      visit(doc, "settings");
      await waitWhile(() => text(doc, "#settings-models") !== `The model list could not be read. ${GONE}`);
      assert.equal(text(doc, "#settings-models"), `The model list could not be read. ${GONE}`);
      keep();
      assert.doesNotMatch(rendered.join("\n"), /may be unreachable|fetch failed|Failed to fetch/, "never the hedge where the cause is known, nor the browser's words");
    });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // C4: the oracle on every page drawn above.
    assert.ok(rendered.length >= 8);
    for (const page of rendered) {
      assert.ok(!page.includes(KEY_VALUE), "no rendered page carries the secret value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    if (dashboardOpen) await dashboard.close();
    if (arbiterOpen) { admin.close(); await arbiter.close(); }
    rmSync(tmp, { recursive: true, force: true });
  }
});
