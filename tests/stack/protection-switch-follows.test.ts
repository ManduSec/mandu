/**
 * protection-switch-follows.test — an open Settings › Protection follows an
 * on/off saved elsewhere within one Home poll, as the top bar beside it
 * does, across the REAL components (dashboard.md §4.25 *The protection
 * switch keeps what you saved*). Mandu-new.
 *
 * Until 2026-10-30 the card read config.toml only when Settings opened. A
 * change saved in another tab, or by `mandu mode` in a terminal, left the
 * switch On under a top bar that said "off from the next start", and after
 * the restart the card said "Still off until the protection service
 * restarts" for a setting that was off.
 *
 * Here a real ArbiterServer runs at the `secrets` axes with a labelled
 * secret file, a real DashboardServer reaches it over the production adapter
 * (`makeApprovalsArbiter`) and keeps its config.toml in a scratch
 * MANDU_HOME, and two signed-in Settings pages are served (jsdom over the
 * served page and script, served-page.ts):
 *
 *   F1  the second page turns protection off with the typed OFF; the first
 *       page's next poll reads the setting again: its switch reads Off, the
 *       top bar says "off from the next start", and a status line says the
 *       switch changed outside the page, with no navigation;
 *   F2  `mandu mode secrets` writes config.toml (the launcher's own
 *       writeModeToConfig): the next poll draws the switch On again;
 *   F3  the oracle: no page text carries the labelled value or a token.
 *
 * And what RUNS (dashboard.md §4.25 *The on/off says what runs*, queue
 * item #294): a real protection service started with protection off, then
 * started again on the same sockets with it on, as a restart after the
 * switch does, under one open Settings page:
 *
 *   R1  off: the Prompt filters card says "Protection is off, so Mandu only
 *       notes what it finds" and a Try a message answer says Mandu would
 *       only note what it found;
 *   R2  after the restart on, the polls that see it read the card and the
 *       answer again: both off lines go, with no reload;
 *   R3  the oracle, as F3.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON; R1 runs
 * the `off` axes on purpose and states them).
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
import { pollWhile, waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { offBox, typeInOffBox, enterInOffBox } from "../../dashboard/test/unit/ui/protect-off.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const KEY_VALUE = `sk_live_switchFollowsCanary_${process.pid}_0000000`;

test("an open Settings page follows protection turned off in another tab and on by mandu mode within one poll (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-protection-follows-"));
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
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, fileBrowserHome: home,
    configEnv: { MANDU_HOME: mhome, MANDU_POLICY_FILE: policyPath }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const configPath = join(mhome, "config.toml");
  const onReady = (doc: any) => doc.getElementById("switch-protection").getAttribute("aria-checked") === "true"
    && !doc.getElementById("switch-protection").disabled
    && /Keys and secret files leave/.test(doc.getElementById("settings-protect-text").textContent);
  try {
    await servedProductPage(base, "/settings", onReady, async (doc) => {
      const w = doc.defaultView;
      Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
      const homes = () => w.__homes as number;
      const poll = async () => {
        const n = homes();
        doc.dispatchEvent(new w.Event("visibilitychange"));
        await waitWhile(() => homes() <= n);
      };
      const name = () => doc.querySelector("#settings-protect-row .name").textContent as string;
      const sw = () => doc.getElementById("switch-protection");
      const top = () => doc.getElementById("top-status").textContent as string;
      const line = () => doc.getElementById("settings-protect-changed");
      w.__stayed = true;
      await poll();
      assert.equal(name(), "On");
      assert.equal(top(), "Protection on");
      assert.equal(line().hidden, true, "nothing changed yet");

      // F1: the second page turns it off with the typed OFF.
      await servedProductPage(base, "/settings", onReady, async (other) => {
        other.getElementById("switch-protection").click();
        assert.ok(offBox(other), "the second page asks for OFF");
        typeInOffBox(other, "OFF");
        enterInOffBox(other);
        await waitWhile(() => other.querySelector("#settings-protect-row .name").textContent !== "Off");
      }, { headers: { Cookie: ADMIN_COOKIE } });
      assert.match(readFileSync(configPath, "utf8"), /^mode = "off"$/m, "config.toml says off");
      assert.equal(name(), "On", "the first page has not polled yet");
      await poll();
      await waitWhile(() => name() !== "Off");
      assert.equal(sw().getAttribute("aria-checked"), "false");
      assert.equal(top(), "Protection on · off from the next start", "the top bar says the same");
      assert.equal(doc.getElementById("settings-protect-text").textContent,
        "Still on until the protection service restarts: keys and secret files leave this computer only where a rule or your OK allows.");
      assert.equal(line().hidden, false);
      assert.equal(line().getAttribute("role"), "status");
      assert.equal(line().textContent, "Changed outside this page: saved as off.");
      assert.equal(w.__stayed, true, "no navigation: the same page");

      // F2: `mandu mode secrets` in a terminal.
      writeModeToConfig(configPath, "secrets");
      await poll();
      await waitWhile(() => name() !== "On");
      assert.equal(sw().getAttribute("aria-checked"), "true");
      assert.equal(top(), "Protection on");
      assert.equal(line().textContent, "Changed outside this page: saved as on.");
      assert.equal(w.__stayed, true);

      // F3: the oracle.
      const dom = doc.documentElement.outerHTML as string;
      assert.ok(!dom.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: the labelled value is in the page");
      assert.doesNotMatch(doc.body.textContent, /\$MDU/, "no token in the page's text");
    }, {
      headers: { Cookie: ADMIN_COOKIE },
      beforeScripts: (w) => {
        // Count the Home answers, to wait for one poll.
        w.__homes = 0;
        const fetchIt = w.fetch;
        w.fetch = (url: string, init: unknown) => fetchIt(url, init).then((res: { json: () => Promise<unknown> }) => {
          const json = res.json;
          return { ...res, json: () => json().then((b) => { if (String(url).endsWith("/api/home")) w.__homes++; return b; }) };
        });
      },
    });
  } finally {
    await dashboard.close();
    wired.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("an open Settings page's Prompt filters and Try a message follow a restart of the protection service from off to on (off, then secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-prompt-follows-running-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const mhome = join(tmp, "mhome");
  mkdirSync(mhome);
  const policyPath = join(tmp, "policy.yaml");
  // A filter that finds an address, so Try a message has a finding to say
  // Mandu would only note (as dashboard-prompt-settings.test.ts does).
  const packs = join(tmp, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "mine.yaml"), "pack: mine\nversion: 1\npatterns:\n  - id: email\n    category: pii.email\n    regex: '[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\\.[a-z]{2,}'\n");
  writeFileSync(policyPath, "version: 1\nprompt_filters:\n  filters:\n    mine: on\n  actions:\n    pii.email: mask\n");
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  // One protection service, then another on the same sockets, as the
  // restart after a flip of the switch brings it back.
  const serve = (confidentiality: boolean) => new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: packs, adminPromptPackDir: null, packDir: null, packKeysDir: join(tmp, "keys"),
    confidentiality, integrity: false, log: () => {}, // `off`, then the `secrets` axes, stated
  });
  let arbiter = serve(false);
  await arbiter.listen();
  let arbiterOpen = true;
  const env = join(home, "proj", ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  await admin.setPathLabel({ path: env, confidentiality: "no-model", bindings: [], recursive: false });
  admin.close();
  writeModeToConfig(join(mhome, "config.toml"), "secrets");
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, fileBrowserHome: home,
    configEnv: { MANDU_HOME: mhome, MANDU_POLICY_FILE: policyPath }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const offNote = (doc: any) => doc.querySelector("#settings-prompt-kinds .prompt-off");
  const tryOff = (doc: any) => doc.querySelector("#prompt-try-answer .prompt-try-off");
  const ready = (doc: any) => !!doc.querySelector("#settings-prompt-kinds .prompt-kind") && !!offNote(doc);
  try {
    await servedProductPage(base, "/settings", ready, async (doc) => {
      const w = doc.defaultView;
      Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
      const poll = () => doc.dispatchEvent(new w.Event("visibilitychange"));
      const name = () => doc.querySelector("#settings-protect-row .name").textContent as string;
      const top = () => doc.getElementById("top-status").textContent as string;
      w.__stayed = true;

      // R1: off (a Home poll has said so), and both lines say so.
      await pollWhile(() => !/^Protection off/.test(top()), poll);
      assert.match(top(), /^Protection off/);
      assert.equal(offNote(doc).textContent, "Protection is off, so Mandu only notes what it finds. These choices apply when it is on.");
      (doc.getElementById("prompt-try-text") as { value: string }).value = "mail ann@example.com today";
      doc.getElementById("prompt-try-form").dispatchEvent(new w.Event("submit", { cancelable: true }));
      await waitWhile(() => doc.getElementById("prompt-try-answer").hidden);
      assert.equal(doc.getElementById("prompt-try-answer").hidden, false, "the answer is drawn");
      assert.ok(tryOff(doc), "the answer says Mandu would only note what it found");
      assert.equal(tryOff(doc).textContent, "Protection is off, so Mandu would only note these.");

      // R2: the service restarts with protection on; the polls that see it
      // read the card and the answer again.
      await arbiter.close(); arbiterOpen = false;
      arbiter = serve(true);
      await arbiter.listen(); arbiterOpen = true;
      await pollWhile(() => name() !== "On" || !!offNote(doc) || !!tryOff(doc), poll);
      assert.equal(name(), "On", "Settings › Protection follows what runs");
      assert.equal(offNote(doc), null, "the Prompt filters note goes, with no reload");
      assert.equal(tryOff(doc), null, "and the answer's off line");
      assert.equal(doc.getElementById("prompt-try-answer").hidden, false, "the answer stays drawn");
      assert.equal(w.__stayed, true, "no navigation: the same page");

      // R3: the oracle.
      const dom = doc.documentElement.outerHTML as string;
      assert.ok(!dom.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: the labelled value is in the page");
      assert.doesNotMatch(doc.body.textContent, /\$MDU/, "no token in the page's text");
    }, { headers: { Cookie: ADMIN_COOKIE } });
  } finally {
    await dashboard.close();
    wired.close();
    if (arbiterOpen) await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
