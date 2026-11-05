/**
 * protection-last-changed.test — Settings › Protection says when protection
 * was last turned off or on in the dashboard, from the `config_change`
 * record the dashboard keeps in the arbiter's audit stream, across the REAL
 * components (dashboard.md §4.25 *The Protection row says when it was last
 * turned off or on in the dashboard*, queue item #306). Mandu-new.
 *
 * Until 2026-11-04 the row said only "Off", so a person who turned
 * protection off for a quick test and forgot could not tell ten minutes from
 * ten days, though GET /api/config/axes already answered the record.
 *
 * A real ArbiterServer runs at the `secrets` axes with its admin and human
 * sockets and a labelled secret file; a real DashboardServer reaches it over
 * the production adapter (`makeApprovalsArbiter`), with its audit surface
 * (`auditArbiter`), and keeps its config.toml in a scratch MANDU_HOME. Served
 * Settings pages (jsdom over the served page and script, served-page.ts):
 *
 *   L1  a page turns protection off with the typed OFF; a Settings page
 *       opened after it reads "Turned off in the dashboard <time>." with a
 *       moment within the last minute, from the record on the arbiter;
 *   L2  `mandu mode secrets` writes config.toml (the launcher's own
 *       writeModeToConfig) and leaves no record: a page opened after it
 *       reads On, with no lead (the record's `to` no longer matches);
 *   L3  the oracle: no page text carries the labelled value or a token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { writeModeToConfig } from "../../launcher/src/config-edit.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { offBox, typeInOffBox, enterInOffBox } from "../../dashboard/test/unit/ui/protect-off.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const KEY_VALUE = `sk_live_lastChangedCanary_${process.pid}_00000000`;
const APPLIES = "A change applies when the protection service next starts.";

test("Settings › Protection says when protection was turned off in the dashboard, and says nothing once mandu mode changed it (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-protection-last-changed-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const mhome = join(tmp, "mhome");
  mkdirSync(mhome);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const env = join(home, "proj", ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  await admin.setPathLabel({ path: env, confidentiality: "no-model", bindings: [], recursive: false });
  admin.close();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production wiring connects");
  assert.ok(wired.audit, "the production wiring has the audit surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, auditArbiter: wired.audit, fileBrowserHome: home,
    configEnv: { MANDU_HOME: mhome, MANDU_POLICY_FILE: policyPath }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const configPath = join(mhome, "config.toml");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  type Doc = any;
  const drawn = (doc: Doc) => !doc.getElementById("switch-protection").disabled
    && doc.getElementById("settings-protect-note").textContent !== "";
  const opened = { headers: { Cookie: ADMIN_COOKIE } };
  const name = (doc: Doc) => doc.querySelector("#settings-protect-row .name").textContent as string;
  const note = (doc: Doc) => doc.getElementById("settings-protect-note");
  const oracle = (doc: Doc) => {
    const dom = doc.documentElement.outerHTML as string;
    assert.ok(!dom.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: the labelled value is in the page");
    assert.doesNotMatch(doc.body.textContent, /\$MDU/, "no token in the page's text");
  };
  try {
    // Before any change: On, no record, no lead.
    await servedProductPage(base, "/settings", drawn, async (doc) => {
      assert.equal(name(doc), "On");
      assert.equal(note(doc).querySelector("time"), null, "no record yet, no lead");
      assert.doesNotMatch(note(doc).textContent, /^Turned/);
    }, opened);

    // L1: turned off on a page with the typed OFF.
    const before = Date.now();
    await servedProductPage(base, "/settings", drawn, async (doc) => {
      doc.getElementById("switch-protection").click();
      assert.ok(offBox(doc), "the page asks for OFF");
      typeInOffBox(doc, "OFF");
      enterInOffBox(doc);
      await waitWhile(() => name(doc) !== "Off");
    }, opened);
    assert.match(readFileSync(configPath, "utf8"), /^mode = "off"$/m, "config.toml says off");
    await servedProductPage(base, "/settings", (doc: Doc) => drawn(doc) && name(doc) === "Off", async (doc) => {
      const t = note(doc).querySelector("time");
      assert.ok(t, "the note names the moment");
      const at = Date.parse(t.getAttribute("datetime"));
      assert.ok(at >= before - 1000 && at <= Date.now() + 1000, `the moment is the flip's: ${t.getAttribute("datetime")}`);
      assert.match(t.textContent, / · just now$/);
      assert.match(note(doc).textContent, /^Turned off in the dashboard .+\. /);
      assert.ok(note(doc).textContent.startsWith(`Turned off in the dashboard ${t.textContent}. `));
      assert.doesNotMatch(doc.body.textContent, /requested|by you/i, "never who pressed");
      oracle(doc);
    }, opened);

    // L2: `mandu mode secrets` in a terminal: no record.
    writeModeToConfig(configPath, "secrets");
    await servedProductPage(base, "/settings", (doc: Doc) => drawn(doc) && name(doc) === "On", async (doc) => {
      assert.equal(doc.getElementById("switch-protection").getAttribute("aria-checked"), "true");
      assert.equal(note(doc).querySelector("time"), null, "the record says off, the setting on: no lead");
      assert.equal(note(doc).textContent, APPLIES);
      // L3
      oracle(doc);
    }, opened);
  } finally {
    await dashboard.close();
    wired.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
