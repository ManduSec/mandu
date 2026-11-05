/**
 * rule-changes-find e2e — Approvals › Rule changes finds a past change by
 * its file, host or agent (dashboard.md §4.25 *Finding a rule change*),
 * across the REAL components: a real ArbiterServer at the `secrets` axes
 * with a policy.yaml, the real dashboard over the production adapter
 * (`makeApprovalsArbiter`), signed in, in a real headless Chromium.
 * Mandu-new.
 *
 * Until 2026-10-26 the list could only be paged: the change to undo was
 * found by pressing Show more and reading every row. The seed, three rule
 * changes over the real routes: an agent asks to let `.env` (a registered
 * secret) be sent to `api.stripe.com` and to let `deploy.env` be sent to
 * `upload.example`, each approved over the dashboard's route, and the agent
 * locks `id_rsa` (a tightening, made at once). Then:
 *
 *   F1  "Find a change" is shown; typing `stripe` leaves the one row naming
 *       `api.stripe.com`; the count says "1 of 3 changes matches"; the address
 *       carries `?changes=stripe`;
 *   F2  Undo on that found row undoes it over the real route: the listing
 *       says the change is undone, and the found row says "Undone";
 *   F3  the oracle: no `$MDU:` code and no registered secret value in the
 *       count line or the found rows (nor in the whole page drawn).
 *
 * Self-SKIPs without a Chromium (probeBrowser: MANDU_TOUR_BROWSER,
 * CHROME_PATH, a Playwright headless shell).
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

after(() => resetCurrentPolicyForTests("claude-code"));

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  Cdp: { connect(url: string): Promise<Cdp> };
};
const chromium = tour.probeBrowser({});

const KEY_VALUE = `sk_live_ruleChangesFindCanary_${process.pid}_0000`;
const SESSION = `rule-changes-find-${process.pid}`;

test("in a real Chromium: Find a change leaves the one change naming a host, and Undo on that found row undoes it over the real route; no value or token shown (secrets axes, explicit)", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rule-changes-find-"));
  const repo = join(tmp, "home", "proj");
  mkdirSync(repo, { recursive: true });
  const env = join(repo, ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const adminPath = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminPath, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminPath }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const call = async (path: string, init: { method?: string; body?: string; headers?: Record<string, string> } = {}) => {
    const r = await pageFetch(`${base}${path}`, { headers: CSRF_ADMIN, ...init });
    const text = await r.text();
    assert.equal(r.status, 200, `${path}: ${text}`);
    return JSON.parse(text);
  };
  const { proc, wsUrl } = await tour.startBrowser(chromium as string, join(tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  try {
    // ── The seed: a registered secret, and three rule changes ───────────────
    const reg = await data.registerSecret({ path: env, sessionKey: SESSION });
    assert.ok(/\$MDU:/.test(reg.twin ?? ""), `the key has its symbol: ${JSON.stringify(reg)}`);
    const approve = async (path: string, host: string) => {
      const asked = await data.policyPropose({ edits: [{ op: "lock-path", path, level: "no-model", bindings: [host] }], sessionKey: SESSION, reason: "deploy needs it" });
      assert.ok("proposalId" in asked && asked.proposalId, `the binding waits for you: ${JSON.stringify(asked)}`);
      const approved = await call(`/api/policy/proposals/${asked.proposalId}`, { method: "POST", body: JSON.stringify({ verdict: "approved" }), headers: { ...CSRF_ADMIN, "content-type": "application/json" } });
      assert.match(String(approved.changeId), /^pc-\d{6}$/, `approved: ${JSON.stringify(approved)}`);
      return String(approved.changeId);
    };
    const stripeId = await approve(env, "api.stripe.com");
    const uploadId = await approve(join(repo, "deploy.env"), "upload.example");
    const tight = await data.policyPropose({ edits: [{ op: "lock-path", path: join(repo, "id_rsa"), level: "no-model" }], sessionKey: SESSION });
    assert.ok("applied" in tight && tight.applied && tight.changeId, `the tightening is made: ${JSON.stringify(tight)}`);
    const listing = await call("/api/policy/changes?limit=20");
    assert.deepEqual(listing.changes.map((c: { id: string }) => c.id), [String(tight.changeId), uploadId, stripeId], "three changes, newest first");

    // ── Chromium, signed in ─────────────────────────────────────────────────
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const send = (method: string, params: object = {}) => cdp.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    };
    const until = async (what: string, expression: string) => {
      let ok = false;
      for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((r) => setTimeout(r, 100))) {
        try { ok = await evaluate(expression); } catch { /* navigating */ }
      }
      assert.ok(ok, what);
    };
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Network.enable");
    const eq = ADMIN_COOKIE.indexOf("=");
    await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });
    await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
    await send("Page.navigate", { url: `${base}/approvals` });
    const rows = `[...document.querySelectorAll("#approvals-rule-history .row.answered")]`;
    await until("Rule changes lists the three", `!document.getElementById("page-approvals").hidden && ${rows}.length === 3`);

    // ── F1: the box, one host typed, one row left ───────────────────────────
    assert.equal(await evaluate(`document.getElementById("changes-search").hidden`), false, "the box is shown");
    assert.equal(await evaluate(`document.querySelector('label[for="changes-q"]').textContent`), "Find a change");
    await evaluate(`(() => { const b = document.getElementById("changes-q"); b.focus(); b.value = "stripe"; b.dispatchEvent(new Event("input", { bubbles: true })); return true; })()`);
    await until("one row left", `${rows}.length === 1 && !document.getElementById("changes-count").hidden`);
    const found = await evaluate(`({ ids: ${rows}.map((r) => r.dataset.id), text: ${rows}.map((r) => r.innerText).join("\\n"), count: document.getElementById("changes-count").textContent, address: location.pathname + location.search, focus: document.activeElement === document.getElementById("changes-q") })`);
    assert.deepEqual(found.ids, [stripeId], "the change naming api.stripe.com");
    assert.match(found.text, /api\.stripe\.com/);
    assert.equal(found.count, "1 of 3 changes matches");
    assert.equal(found.address, "/approvals?changes=stripe");
    assert.equal(found.focus, true, "the focus stays in the box");

    // ── F2: Undo on the found row ───────────────────────────────────────────
    const undo = `${rows}[0].querySelector("button.right")`;
    assert.equal(await evaluate(`${undo}.textContent`), "Undo");
    await evaluate(`${undo}.click(), true`);
    await until("the found row says Undone", `${rows}.length === 1 && /Undone/.test(${rows}[0].innerText)`);
    const after = await call("/api/policy/changes?limit=20");
    const was = after.changes.find((c: { id: string }) => c.id === stripeId);
    assert.equal(was?.undone, true, "the change is undone over the real route");
    assert.equal(after.changes.length, 4, "the Undo is a change of its own");
    assert.equal(await evaluate(`${rows}[0].dataset.id`), stripeId, "the search still holds: the Undo row does not name the host");

    // ── F3: the oracle ──────────────────────────────────────────────────────
    const shown = await evaluate(`({ count: document.getElementById("changes-count").textContent, rows: ${rows}.map((r) => r.innerText).join("\\n"), body: document.body.innerText })`);
    for (const [where, text] of [["the count line", shown.count], ["the found rows", shown.rows], ["the page", shown.body]] as const) {
      assert.ok(!text.includes(KEY_VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the key's value`);
      assert.doesNotMatch(text, /\$MDU:/, `${where} carries a token`);
    }
  } finally {
    cdp.close();
    await tour.stopProc(proc);
    await dashboard.close();
    data.close();
    wired.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
