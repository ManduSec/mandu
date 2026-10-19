/**
 * product-service-back.test — when the protection service comes back, the
 * product page's Rules and Settings read again what they could not read,
 * across the REAL components (dashboard.md §4.25 *Empty states*, *What could
 * not be read is read again when the service comes back*). Mandu-new.
 *
 * Until 2026-10-10 Rules and Settings read their lists only when opened.
 * With the service started again under an open page (from a terminal, the
 * developer view or another tab), the hero said the secrets were guarded
 * while Rules › Your rules and Settings › Models said "… The protection
 * service may be unreachable.", and Sensitivity labels still said the
 * service was not running, until the page was opened again. Here a real
 * ArbiterServer runs at the `secrets` axes with a policy.yaml rule, and a
 * real DashboardServer reaches it over the production adapter
 * (`makeApprovalsArbiter`). The served product page (its own index.html and
 * home.js in jsdom, signed in) stays open while the arbiter stops, and a new
 * one then starts on the same sockets:
 *
 *   B1  running: Rules lists the rule; Settings lists the models, the
 *       sensitivity labels and the prompt filters;
 *   B2  the service stops with Rules open: Your rules says it is not
 *       running; it comes back, and within one poll Rules lists the rule,
 *       never the hedge on the way;
 *   B3  the same on Settings: Models, Sensitivity labels and Prompt
 *       filters say the service is not running (Prompt filters said "did
 *       not answer" until 2026-10-10, its route's words for the failed
 *       dial); it comes back, and within one poll each lists again;
 *   B4  no unhandled rejection in the page; the oracle: no rendered page
 *       carries the labelled file's value or a token.
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

stateAxes("secrets");

const KEY_VALUE = "sk_live_productServiceBackStackCanary0001";
const DOWN_LINKED = "The protection service is not running. Start it under Settings, or try again in a moment.";
const MODELS_LISTED = /^No models listed\./;
const LABELS_LISTED = /^Mandu lists here the sensitivity labels it finds/;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (doc: any, sel: string): string => doc.querySelector(sel)?.textContent ?? "";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const promptKinds = (doc: any): number => doc.querySelectorAll("#settings-prompt-kinds .prompt-kind").length;
/** Open a page of the product as its nav does. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const visit = (doc: any, page: string) => doc.querySelector(`[data-page-link="${page}"]`)
  .dispatchEvent(new doc.defaultView.MouseEvent("click", { bubbles: true, cancelable: true, button: 0 }));
/** What `ids` showed at each change while the page is open. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function watch(doc: any, ids: string[]): { seen: string[]; stop: () => void } {
  const seen: string[] = [];
  const obs = new doc.defaultView.MutationObserver(() => { for (const id of ids) seen.push(doc.getElementById(id).textContent); });
  for (const id of ids) obs.observe(doc.getElementById(id), { childList: true, subtree: true, characterData: true });
  return { seen, stop: () => obs.disconnect() };
}

test("the product page reads Rules and Settings again when the protection service comes back (real arbiter, production adapter, dashboard, served page)", { timeout: 240_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-service-back-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(home, "proj", "deploy.token")}\n    level: no-model\n`);
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
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
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

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const connected = (doc: any) => text(doc, "#hero-headline") !== "Checking…";
    await servedProductPage(base, "/", connected, async (doc) => {
      // The page reads again when it is shown (its 10 s poll is inert here).
      const poll = () => doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
      const keep = () => rendered.push(doc.body.textContent ?? "");
      const down = async () => { await stop(); poll(); await waitWhile(() => text(doc, "#hero-headline") !== "Not connected."); };

      // B1: running; every list reads.
      assert.notEqual(text(doc, "#hero-headline"), "Not connected.", text(doc, "#hero-sentence"));
      visit(doc, "rules");
      await waitWhile(() => !text(doc, "#files-tree").includes("deploy.token"));
      assert.match(text(doc, "#files-tree"), /deploy\.token/, "the rule is listed");
      visit(doc, "settings");
      await waitWhile(() => !MODELS_LISTED.test(text(doc, "#settings-models")) || !LABELS_LISTED.test(text(doc, "#settings-labels")) || !promptKinds(doc));
      assert.match(text(doc, "#settings-models"), MODELS_LISTED);
      assert.match(text(doc, "#settings-labels"), LABELS_LISTED);
      assert.ok(promptKinds(doc) > 0, "the prompt filters are listed");
      keep();
      visit(doc, "home");

      // B2: the service stops with Rules open, then comes back.
      await down();
      visit(doc, "rules");
      await waitWhile(() => text(doc, "#files-tree") !== `Your rules could not be read. ${DOWN_LINKED} You can still add a rule.`);
      assert.equal(text(doc, "#files-tree"), `Your rules could not be read. ${DOWN_LINKED} You can still add a rule.`);
      keep();
      await start();
      const onRules = watch(doc, ["files-tree"]);
      poll(); // one poll
      await waitWhile(() => !text(doc, "#files-tree").includes("deploy.token"));
      onRules.stop();
      assert.match(text(doc, "#files-tree"), /deploy\.token/, "the rule is listed again, with no visit");
      assert.notEqual(text(doc, "#hero-headline"), "Not connected.");
      assert.ok(!onRules.seen.some((t) => /may be unreachable/.test(t)), `never the hedge on the way: ${JSON.stringify(onRules.seen)}`);
      keep();

      // B3: the same on Settings.
      visit(doc, "home");
      await down();
      visit(doc, "settings");
      await waitWhile(() => !text(doc, "#settings-models").startsWith("The model list could not be read.") || text(doc, "#settings-labels") !== DOWN_LINKED || text(doc, "#settings-prompt-kinds") !== DOWN_LINKED);
      assert.equal(text(doc, "#settings-models"), `The model list could not be read. ${DOWN_LINKED}`);
      assert.equal(text(doc, "#settings-labels"), DOWN_LINKED);
      assert.equal(text(doc, "#settings-prompt-kinds"), DOWN_LINKED, "the same words as its siblings");
      assert.equal(promptKinds(doc), 0);
      keep();
      await start();
      const onSettings = watch(doc, ["settings-models", "settings-labels", "settings-prompt-kinds"]);
      poll(); // one poll
      await waitWhile(() => !MODELS_LISTED.test(text(doc, "#settings-models")) || !LABELS_LISTED.test(text(doc, "#settings-labels")) || !promptKinds(doc));
      onSettings.stop();
      assert.match(text(doc, "#settings-models"), MODELS_LISTED, "the model list reads again, with no visit");
      assert.equal(doc.getElementById("model-open").hidden, false, "Add a model is offered again");
      assert.match(text(doc, "#settings-labels"), LABELS_LISTED, "the sensitivity labels read again");
      assert.ok(promptKinds(doc) > 0, "the prompt filters read again");
      assert.ok(!onSettings.seen.some((t) => /may be unreachable/.test(t)), `never the hedge on the way: ${JSON.stringify(onSettings.seen)}`);
      keep();
      assert.doesNotMatch(rendered.join("\n"), /fetch failed|Failed to fetch/, "never the browser's words");
    }, { headers: { Cookie: ADMIN_COOKIE } });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // B4: the oracle on every page drawn above.
    assert.equal(rendered.length, 5);
    for (const page of rendered) {
      assert.ok(!page.includes(KEY_VALUE), "no rendered page carries the secret value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    if (arbiterOpen) await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
