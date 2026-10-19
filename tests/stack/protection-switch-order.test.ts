/**
 * protection-switch-order.test — Settings › Protection: a read of the saved
 * setting asked before your flip never draws the switch as it was, across
 * the REAL components (dashboard.md §4.25 *A read asked before your change
 * never draws over it*). Mandu-new.
 *
 * The switch shows the setting saved in config.toml (`GET /api/config/axes`),
 * read each time Settings opens and by Rules; a flip posts the new one and
 * draws its answer. Until 2026-10-12 the answer that came last drew, even
 * when its read was asked first: on a slow network, turning protection off
 * drew Off, then a read from before the flip drew On again with "Keys and
 * secret files leave this computer only where a rule or your OK allows.",
 * while config.toml said off. Here a real ArbiterServer runs at the
 * `secrets` axes, a real DashboardServer reaches it over the production
 * adapter (`makeApprovalsArbiter`) and keeps its config.toml in a scratch
 * MANDU_HOME, and the served product page (its own index.html and home.js
 * in jsdom, signed in) reaches the dashboard through a relay that holds one
 * answer back (tests/lib/holding-relay.ts):
 *
 *   S1  the saved setting is on, and the switch says On;
 *   S2  Settings opens again and its read of the setting (on) is held;
 *       the switch is turned off (typed OFF): the dashboard saves off, and
 *       the switch says Off while the service still runs on;
 *   S3  the held read comes: the switch stays Off, and the dashboard still
 *       says off;
 *   S4  the same the other way: a held read (off), the switch turned on,
 *       the held read comes, and the switch stays On;
 *   S5  no unhandled rejection; the oracle: no page or answer read here
 *       carries a labelled file's value, and no page drawn carries a token.
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
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { holdingRelay } from "../lib/holding-relay.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const KEY_VALUE = "sk_live_protectionSwitchOrderStack00001";
const AXES_READ = "/api/config/axes";
const ON_WORDS = "Keys and secret files leave this computer only where a rule or your OK allows.";
const STILL_ON = "Still on until the protection service restarts: keys and secret files leave this computer only where a rule or your OK allows.";
/** How long a page is given to draw a held answer it must drop: a page
 *  that draws it changes within this, a page that drops it never does. */
const SETTLE_MS = 1500;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const protectSwitch = (doc: Doc) => doc.getElementById("switch-protection");
/** The Protection row as drawn: the switch, its name, the sentence under it. */
const protectRow = (doc: Doc) => ({
  checked: protectSwitch(doc)?.getAttribute("aria-checked"),
  name: doc.querySelector("#settings-protect-row .name")?.textContent,
  text: doc.getElementById("settings-protect-text")?.textContent,
});
/** Open a page of the product as its nav does. */
const visit = (doc: Doc, page: string) => doc.querySelector(`[data-page-link="${page}"]`)
  .dispatchEvent(new doc.defaultView.MouseEvent("click", { bubbles: true, cancelable: true, button: 0 }));
/** Press the switch the way a keyboard does: the focus on it first. */
function press(doc: Doc): void {
  const sw = protectSwitch(doc);
  assert.ok(sw && !sw.disabled, "the switch is drawn and on");
  sw.focus();
  sw.click();
}

test("Settings › Protection over the real dashboard: a read of the setting asked before your flip never draws the switch as it was; no secret anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-protection-switch-order-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
  const port = await dashboard.listen(0);
  const relay = await holdingRelay(port);
  const bodies: string[] = [];
  /** What the dashboard says is saved, read past the relay. */
  const saved = async (): Promise<string> => {
    const r = await pageFetch(`http://127.0.0.1:${port}${AXES_READ}`, { headers: { Cookie: ADMIN_COOKIE } });
    const text = await r.text();
    bodies.push(text);
    assert.equal(r.status, 200, text);
    return (JSON.parse(text) as { effectiveMode: string }).effectiveMode;
  };
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

    // ── S1: the saved setting is on ─────────────────────────────────────────
    assert.equal(await saved(), "secrets", "nothing saved yet: the default is on");
    const drawnOn = (doc: Doc) => protectRow(doc).text === ON_WORDS;
    await servedProductPage(relay.base, "/settings", drawnOn, async (doc: Doc) => {
      const keep = () => rendered.push(doc.documentElement.outerHTML);
      assert.deepEqual(protectRow(doc), { checked: "true", name: "On", text: ON_WORDS });
      keep();

      // ── S2: Settings' read is held; the switch is turned off ──────────────
      const before = relay.holdNext(AXES_READ);
      visit(doc, "home");
      visit(doc, "settings");
      assert.equal(await before.asked, 200, "Settings' read was answered (on), and held");
      doc.defaultView.prompt = () => "OFF";
      press(doc);
      await waitWhile(() => protectRow(doc).checked !== "false");
      assert.deepEqual(protectRow(doc), { checked: "false", name: "Off", text: STILL_ON }, "the flip's answer is drawn");
      assert.equal(await saved(), "off", "the dashboard saved off");
      keep();

      // ── S3: the held read comes, and is dropped ───────────────────────────
      await before.release();
      await waitWhile(() => protectRow(doc).checked === "false", SETTLE_MS);
      assert.deepEqual(protectRow(doc), { checked: "false", name: "Off", text: STILL_ON }, "never drawn On again over the setting you saved");
      assert.equal(doc.activeElement, protectSwitch(doc), "the focus stays on the switch");
      assert.equal(await saved(), "off");
      keep();

      // ── S4: the other way ─────────────────────────────────────────────────
      const offRead = relay.holdNext(AXES_READ);
      visit(doc, "home");
      visit(doc, "settings");
      assert.equal(await offRead.asked, 200, "Settings' read was answered (off), and held");
      press(doc);
      await waitWhile(() => protectRow(doc).checked !== "true");
      assert.deepEqual(protectRow(doc), { checked: "true", name: "On", text: ON_WORDS }, "the flip's answer is drawn");
      assert.equal(await saved(), "secrets", "the dashboard saved on");
      await offRead.release();
      await waitWhile(() => protectRow(doc).checked === "true", SETTLE_MS);
      assert.deepEqual(protectRow(doc), { checked: "true", name: "On", text: ON_WORDS }, "never drawn Off again over the setting you saved");
      keep();
    }, { headers: { Cookie: ADMIN_COOKIE } });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // S5: the oracle on every page drawn and every answer read above.
    assert.equal(rendered.length, 4);
    for (const text of [...rendered, ...bodies]) assert.ok(!text.includes(KEY_VALUE), "no labelled value in a page or an answer");
    for (const text of rendered) assert.doesNotMatch(text, /\$MDU/, "no token in a page drawn");
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await relay.close();
    await dashboard.close();
    wired?.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
