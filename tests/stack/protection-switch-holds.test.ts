/**
 * protection-switch-holds.test — Settings › Protection: the switch holds
 * while its change is on its way, across the REAL components (dashboard.md
 * §4.25 *The switch holds while its change is on its way*). Mandu-new.
 *
 * A flip posts the new setting to `POST /api/config/axes` and draws its
 * answer. Until 2026-10-13 the switch stayed live while that POST was out:
 * a second press posted again, and while turning protection off it asked
 * for the typed OFF again, although the person had confirmed. Here a real
 * ArbiterServer runs at the `secrets` axes, a real DashboardServer reaches
 * it over the production adapter (`makeApprovalsArbiter`) and keeps its
 * config.toml in a scratch MANDU_HOME, and the served product page (its own
 * index.html and home.js in jsdom, signed in) reaches the dashboard through
 * a relay that holds the answer to the POST back (tests/lib/holding-relay.ts):
 *
 *   S1  the saved setting is on, and the switch says On;
 *   S2  the switch is turned off (typed OFF) and the answer is held: the
 *       dashboard saved off; the switch is held (aria-disabled), keeps the
 *       focus and still says On; two more presses ask nothing and post
 *       nothing; Settings opened again reads off and draws it, still held,
 *       and a press there posts nothing;
 *   S3  the answer comes: the switch is live again, says Off, and has the
 *       focus; one POST reached the dashboard and one question was asked;
 *   S4  turning it on, pressed twice: one POST, the dashboard saved on, and
 *       the switch says On once the answer comes;
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

const KEY_VALUE = "sk_" + "live_protectionSwitchHoldsStack000001";
const AXES = "/api/config/axes";
const ON_WORDS = "Keys and secret files leave this computer only where a rule or your OK allows.";
const STILL_ON = "Still on until the protection service restarts: keys and secret files leave this computer only where a rule or your OK allows.";
/** How long a press is given to post: a page that posts again does so
 *  within this, a page that holds never does. */
const SETTLE_MS = 500;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const protectSwitch = (doc: Doc) => doc.getElementById("switch-protection");
/** The Protection row as drawn, and whether the switch holds. */
const protectRow = (doc: Doc) => ({
  checked: protectSwitch(doc)?.getAttribute("aria-checked"),
  held: protectSwitch(doc)?.getAttribute("aria-disabled") === "true",
  name: doc.querySelector("#settings-protect-row .name")?.textContent,
  text: doc.getElementById("settings-protect-text")?.textContent,
});
/** Open a page of the product as its nav does. */
const visit = (doc: Doc, page: string) => doc.querySelector(`[data-page-link="${page}"]`)
  .dispatchEvent(new doc.defaultView.MouseEvent("click", { bubbles: true, cancelable: true, button: 0 }));
/** Press the switch the way a keyboard does: the focus on it first. */
function press(doc: Doc): void {
  const sw = protectSwitch(doc);
  assert.ok(sw && !sw.disabled, "the switch is drawn and not disabled");
  sw.focus();
  sw.click();
}

test("Settings › Protection over the real dashboard: the switch holds while its change is on its way; one POST per change; no secret anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-protection-switch-holds-"));
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
  /** The flips that reached the dashboard. */
  const posts = () => relay.seen.filter((r) => r === `POST ${AXES}`).length;
  const bodies: string[] = [];
  /** What the dashboard says is saved, read past the relay. */
  const saved = async (): Promise<string> => {
    const r = await pageFetch(`http://127.0.0.1:${port}${AXES}`, { headers: { Cookie: ADMIN_COOKIE } });
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
      assert.deepEqual(protectRow(doc), { checked: "true", held: false, name: "On", text: ON_WORDS });
      keep();
      let asked = 0;
      doc.defaultView.prompt = () => { asked++; return "OFF"; };

      // ── S2: turned off, the answer held ───────────────────────────────────
      const off = relay.holdNext(AXES, "POST");
      press(doc);
      assert.equal(await off.asked, 200, "the dashboard answered the flip, and the relay holds it");
      assert.equal(await saved(), "off", "the dashboard saved off");
      assert.deepEqual(protectRow(doc), { checked: "true", held: true, name: "On", text: ON_WORDS },
        "held while the answer is on its way, still showing what it showed");
      assert.equal(doc.activeElement, protectSwitch(doc), "the focus stays on the switch");
      press(doc);
      press(doc);
      await waitWhile(() => posts() === 1, SETTLE_MS);
      assert.equal(asked, 1, "the typed OFF is not asked again");
      assert.equal(posts(), 1, "nothing posted again");
      keep();
      // Settings opened again reads the setting the dashboard saved and draws
      // it; the switch still holds, and a press there posts nothing.
      visit(doc, "home");
      visit(doc, "settings");
      await waitWhile(() => protectRow(doc).checked !== "false");
      assert.deepEqual(protectRow(doc), { checked: "false", held: true, name: "Off", text: STILL_ON }, "drawn again, still held");
      press(doc);
      await waitWhile(() => posts() === 1, SETTLE_MS);
      assert.equal(posts(), 1, "a press on the redrawn switch posts nothing");
      keep();

      // ── S3: the answer comes ──────────────────────────────────────────────
      await off.release();
      await waitWhile(() => protectRow(doc).held);
      assert.deepEqual(protectRow(doc), { checked: "false", held: false, name: "Off", text: STILL_ON });
      assert.equal(doc.activeElement, protectSwitch(doc), "the focus is still on the switch");
      assert.deepEqual({ asked, posts: posts() }, { asked: 1, posts: 1 }, "one question, one POST");
      assert.equal(await saved(), "off");

      // ── S4: turned on, pressed twice ──────────────────────────────────────
      const on = relay.holdNext(AXES, "POST");
      press(doc);
      press(doc);
      assert.equal(await on.asked, 200);
      await waitWhile(() => posts() === 2, SETTLE_MS);
      assert.equal(posts(), 2, "one POST for the double press");
      assert.equal(asked, 1, "turning it on asks nothing");
      assert.equal(protectRow(doc).held, true);
      assert.equal(await saved(), "secrets", "the dashboard saved on");
      await on.release();
      await waitWhile(() => protectRow(doc).held);
      assert.deepEqual(protectRow(doc), { checked: "true", held: false, name: "On", text: ON_WORDS });
      assert.equal(posts(), 2);
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
