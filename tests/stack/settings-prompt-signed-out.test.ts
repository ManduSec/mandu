/**
 * settings-prompt-signed-out.test — Settings › Prompt filters signed out is
 * its sign-in note alone, across the REAL components (dashboard.md §4.25
 * "Empty states", *Settings › Prompt filters*). Mandu-new.
 *
 * Until 2026-10-09 a signed-out reader saw the sign-in note and, under it,
 * "What the choices mean": `home.js loadPromptSettings` hid the meanings'
 * list but not the fold around it, so the fold opened on nothing.
 *
 * Here a real ArbiterServer (secrets) with a registered key, and a real
 * DashboardServer over the production adapter (`makeApprovalsArbiter`); the
 * served Settings page (its own index.html and home.js in jsdom):
 *
 *   S1  signed out, `/api/policy/prompt-filters` is refused (403), and the
 *       block shows the sign-in note alone: its own More is the one fold
 *       drawn, with no "What the choices mean", Exceptions heading, note,
 *       list or form;
 *   S2  signed in, the same page lists the kinds and draws the fold with
 *       every meaning the route sends, and the Exceptions heading;
 *   S3  the oracle: no answer or rendered page carries the registered key or
 *       a token.
 *
 * Axes: secrets (stated).
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
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const KEY = "sk_" + "live_settingsPromptSignedOutCanary000001";
const SIGN_IN = "Sign in first: reload this page and sign in with your dashboard account (if there isn't one yet, run mandu dashboard --set-password in your own terminal).";
const PARTS = ["settings-prompt-meanings-fold", "settings-prompt-meanings", "settings-prompt-exceptions-head", "settings-prompt-exceptions-about", "settings-prompt-exceptions", "prompt-exception-form"];

/** The block's folds a reader can see: each `<summary>` outside a hidden part. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const drawnFolds = (doc: any): string[] =>
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [...doc.getElementById("settings-prompt-block").querySelectorAll("summary")].filter((s: any) => !s.closest("[hidden]")).map((s: any) => s.textContent);

test("Settings › Prompt filters over the real arbiter: signed out, the sign-in note alone, no \"What the choices mean\"; signed in, the fold and its meanings; no value on the page", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-settings-prompt-signed-out-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
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
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home") }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const bodies: string[] = [];
  const pages: string[] = [];
  const get = async (path: string, headers: Record<string, string>) => {
    const r = await pageFetch(base + path, { headers });
    const text = await r.text();
    bodies.push(text);
    return { status: r.status, body: JSON.parse(text) };
  };
  try {
    // A registered key, for the oracle: nothing below may carry it.
    await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });

    // S1: signed out (the page's own request: the control header, no cookie).
    const refused = await get("/api/policy/prompt-filters", { "X-Mandu-Control": "1" });
    assert.equal(refused.status, 403, "signed out, the prompt filters are not read");
    await servedProductPage(base, "/settings", (doc) => doc.querySelector("#settings-prompt-kinds .empty") != null, (doc) => {
      assert.equal(doc.getElementById("settings-prompt-kinds").textContent, SIGN_IN);
      assert.deepEqual(drawnFolds(doc), ["More"], "the block's own More is the one fold drawn");
      for (const id of PARTS) assert.equal(doc.getElementById(id).hidden, true, `${id} hidden`);
      pages.push(doc.body.textContent ?? "");
    });

    // S2: signed in, the same page.
    const read = await get("/api/policy/prompt-filters", CSRF_ADMIN);
    assert.equal(read.status, 200, JSON.stringify(read.body));
    const vm = read.body.settings;
    assert.equal(vm.available, true, "the real arbiter gives the filters");
    assert.ok(vm.kinds.length > 0 && vm.meanings.length > 0, "with kinds and meanings");
    await servedProductPage(base, "/settings", (doc) => doc.querySelector("#settings-prompt-kinds .prompt-kind") != null, (doc) => {
      assert.equal(doc.querySelectorAll("#settings-prompt-kinds .prompt-kind").length, vm.kinds.length, "every kind is listed");
      assert.deepEqual(drawnFolds(doc), ["More", "What the choices mean"]);
      assert.equal(doc.getElementById("settings-prompt-meanings-fold").hidden, false);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      assert.deepEqual([...doc.querySelectorAll("#settings-prompt-meanings dt")].map((d: any) => d.textContent), vm.meanings.map((m: { words: string }) => m.words));
      assert.equal(doc.getElementById("settings-prompt-exceptions-head").hidden, false);
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // S3: the oracle.
    assert.equal(pages.length, 2, "both pages were read");
    for (const b of [...bodies, ...pages]) assert.ok(!b.includes(KEY), "no answer or page carries the registered key");
    for (const p of pages) assert.doesNotMatch(p, /\$MDU/, "no page carries a token");
  } finally {
    await dashboard.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
