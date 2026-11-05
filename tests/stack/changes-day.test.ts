/**
 * changes-day e2e — Approvals › Rule changes lists the changes from a day
 * back (dashboard.md §4.25 *Go to a day on Rule changes*), across the REAL
 * components: a real ArbiterServer at the `secrets` axes with a policy.yaml,
 * the real dashboard over the production adapter (`makeApprovalsArbiter`),
 * signed in, in a real headless Chromium. Mandu-new.
 *
 * Until 2026-11-04 Rule changes reached past its newest 20 only by Show
 * more. The seed, made over the real routes as in rule-changes-find: an
 * agent asks to let `.env` (a registered secret) be sent to
 * `api.stripe.com`, approved over the dashboard's route, and the agent
 * locks `id_rsa` (a tightening, made at once). Then:
 *
 *   C1  "Go to a day" sits in Find a change's form; set to yesterday, the
 *       list says no rule changed on or before it, with Show the newest,
 *       and the address carries `?cday=<yesterday>`;
 *   C2  set to today, both changes are listed under Today, the status line
 *       says "From today back", and a reload keeps the day and the list;
 *   C3  Show the newest clears the day from the box and the address;
 *   C4  the oracle: no `$MDU:` code and no registered secret value in the
 *       status line or the rows (nor in the whole page drawn).
 *
 * The change ledger stamps each change with the arbiter's own clock, so
 * a change on an older day is not seeded here: the middle of three days is
 * the jsdom suite's case (home-js-changes-day). Self-SKIPs without a
 * Chromium (probeBrowser: MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright
 * headless shell).
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

const KEY_VALUE = `sk_live_changesDayCanary_${process.pid}_0000`;
const SESSION = `changes-day-${process.pid}`;

test("in a real Chromium: Go to a day on Rule changes lists the changes from that day back, says when none is on or before it, and keeps the day in the address over a reload; no value or token shown (secrets axes, explicit)", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-changes-day-"));
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
    const asked = await data.policyPropose({ edits: [{ op: "lock-path", path: env, level: "no-model", bindings: ["api.stripe.com"] }], sessionKey: SESSION, reason: "deploy needs it" });
    assert.ok("proposalId" in asked && asked.proposalId, `the binding waits for you: ${JSON.stringify(asked)}`);
    const approved = await call(`/api/policy/proposals/${asked.proposalId}`, { method: "POST", body: JSON.stringify({ verdict: "approved" }), headers: { ...CSRF_ADMIN, "content-type": "application/json" } });
    assert.match(String(approved.changeId), /^pc-\d{6}$/, `approved: ${JSON.stringify(approved)}`);
    const tight = await data.policyPropose({ edits: [{ op: "lock-path", path: join(repo, "id_rsa"), level: "no-model" }], sessionKey: SESSION });
    assert.ok("applied" in tight && tight.applied && tight.changeId, `the tightening is made: ${JSON.stringify(tight)}`);
    const listing = await call("/api/policy/changes?limit=20");
    const both = [String(tight.changeId), String(approved.changeId)];
    assert.deepEqual(listing.changes.map((c: { id: string }) => c.id), both, "two changes, newest first");

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
    await until("Rule changes lists the two", `!document.getElementById("page-approvals").hidden && ${rows}.length === 2`);

    // ── C1: the box, set to yesterday ──────────────────────────────────────
    const box = `document.getElementById("changes-day")`;
    assert.equal(await evaluate(`document.querySelector('label[for="changes-day"]').textContent`), "Go to a day");
    assert.equal(await evaluate(`${box}.closest("form").id`), "changes-search", "beside Find a change");
    // The days as the page reckons them (the browser's own clock and zone).
    const today = await evaluate(`${box}.max`);
    const yesterday = await evaluate(`(() => { const d = new Date(); d.setDate(d.getDate() - 1); return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0"); })()`);
    const choose = (day: string) => evaluate(`(() => { const b = ${box}; b.focus(); b.value = ${JSON.stringify(day)}; b.dispatchEvent(new Event("change", { bubbles: true })); return true; })()`);
    const empty = `document.querySelector("#approvals-rule-history .empty")`;
    await choose(yesterday);
    await until("nothing on or before yesterday", `${rows}.length === 0 && !!${empty} && /No rule changed on or before yesterday\\./.test(${empty}.textContent)`);
    const none = await evaluate(`({ button: ${empty}.querySelector("button")?.textContent, address: location.pathname + location.search, newest: !document.getElementById("changes-newest").hidden })`);
    assert.equal(none.button, "Show the newest");
    assert.equal(none.address, `/approvals?cday=${yesterday}`);
    assert.equal(none.newest, true, "Show the newest beside the box");

    // ── C2: today lists both under Today; a reload keeps it ────────────────
    await choose(today);
    await until("both from today back", `${rows}.length === 2 && document.getElementById("changes-count").textContent === "From today back"`);
    const listed = async () => evaluate(`({ ids: ${rows}.map((r) => r.dataset.id), days: [...document.querySelectorAll("#approvals-rule-history .history-day")].map((h) => h.textContent), address: location.pathname + location.search, box: ${box}.value })`);
    const on = await listed();
    assert.deepEqual(on.ids, both);
    assert.deepEqual(on.days, ["Today"]);
    assert.equal(on.address, `/approvals?cday=${today}`);
    await send("Page.reload");
    await until("the reload lists them again", `!document.getElementById("page-approvals").hidden && ${rows}.length === 2 && document.getElementById("changes-count").textContent === "From today back"`);
    const again = await listed();
    assert.deepEqual(again, on, "a reload keeps the day and its list");

    // ── C3: Show the newest ─────────────────────────────────────────────────
    await evaluate(`document.getElementById("changes-newest").click(), true`);
    await until("the day cleared", `${box}.value === "" && location.search === "" && document.getElementById("changes-count").hidden`);
    assert.deepEqual((await listed()).ids, both);

    // ── C4: the oracle ──────────────────────────────────────────────────────
    await choose(today);
    await until("from today back again", `document.getElementById("changes-count").textContent === "From today back"`);
    const shown = await evaluate(`({ count: document.getElementById("changes-count").textContent, rows: ${rows}.map((r) => r.innerText).join("\\n"), body: document.body.innerText })`);
    for (const [where, text] of [["the status line", shown.count], ["the rows", shown.rows], ["the page", shown.body]] as const) {
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
