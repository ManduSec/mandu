/**
 * home-urgent-first e2e — a question your agent waits on comes before the
 * cards that are advice, in a real browser (dashboard.md §4.25ai *Home's
 * card*, §4.25 *Section links*, 2026-10-26). Mandu-new.
 *
 * Until 2026-10-26 Home drew the scan card ("Did your agents already send a
 * secret to the AI?") above *Approvals waiting*, so on a 390 px phone the
 * question started under the fold, and Approvals drew *Keys Mandu found*
 * above *Waiting for your answer*. A REAL ArbiterServer (secrets) asks the
 * human about a masked variable at a host no rule binds it to (the real
 * egress gate); the real workspace scan files a key in a work tree (Keys
 * Mandu found); no `mandu scan` is kept, so Home shows the card saying how
 * to run one. A REAL DashboardServer over the production adapter serves
 * the pages to a REAL headless Chromium (Playwright's headless shell; none
 * found: the test skips) at 390×844, signed in with the one-time admin link:
 *
 *   U1  Home: the scan card shows, the waiting question's card comes before
 *       it and its top is inside the first 844 px;
 *   U2  Approvals: the waiting question's card comes before the possible-keys
 *       card, in the document and on the screen, and the links under the
 *       title follow (Rule changes asked for is hidden: nothing asked);
 *   U3  the oracle: no page read here carries the key or the variable's value.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { emitLauncherEvent, launchPostureEvent } from "../../launcher/src/services/observe.js";
import { chromiumBinary, READY, startChromium, stopChromium } from "../lib/chromium.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const BIN = chromiumBinary();
// Assembled at run time: this file holds no credential-shaped literal.
const KEY = "sk_" + "live_homeUrgentFirstStackCanary000000001";
const VAR_VALUE = "ghp_" + "homeUrgentFirstStackVariable00000002";
const SESSION = "home-urgent-first-session";
const WIDTH = 390;
const HEIGHT = 844;

/** A DevTools client over Node's built-in WebSocket. */
async function devtools(wsUrl: string) {
  const ws = new WebSocket(wsUrl);
  await new Promise<void>((resolve, reject) => {
    ws.addEventListener("open", () => resolve(), { once: true });
    ws.addEventListener("error", () => reject(new Error(`no DevTools at ${wsUrl}`)), { once: true });
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const waiting = new Map<number, (m: any) => void>();
  ws.addEventListener("message", (ev) => {
    const m = JSON.parse(String(ev.data));
    if (typeof m.id === "number") waiting.get(m.id)?.(m);
  });
  let id = 1;
  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    send(method: string, params: Record<string, unknown> = {}): Promise<any> {
      const my = id++;
      return new Promise((resolve) => { waiting.set(my, resolve); ws.send(JSON.stringify({ id: my, method, params })); });
    },
    close: () => ws.close(),
  };
}

let tmp = "";
after(() => {
  resetCurrentPolicyForTests("claude-code");
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

test("a 390 px phone: Home's waiting question comes before the scan card, inside the first screen; Approvals' comes before Keys Mandu found; no secret anywhere", { skip: BIN === null ? "no headless Chromium (Playwright's headless shell) on this host" : false, timeout: 120_000 }, async () => {
  tmp = mkdtempSync(join(tmpdir(), "mdu-urgent-first-"));
  const home = join(tmp, "home");
  const repo = join(home, "proj");
  mkdirSync(join(repo, "deploy"), { recursive: true });
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: repo, env: gitEnv });
  writeFileSync(join(repo, "README.md"), "a project\n");
  writeFileSync(join(repo, "deploy", "app.conf"), `[api]\nAPI_TOKEN=${KEY}\n`);
  const mh = join(tmp, "mh"); // no state/last-scan.json: no scan kept
  mkdirSync(mh, { recursive: true });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\npaths: []\n");
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
  assert.ok(wired?.secrets && wired.policyDoc, "the production adapter has the secrets and policy surfaces");
  const dash = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { HOME: home, MANDU_HOME: mh, MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dash.listen(0)}`;
  const profile = join(tmp, "chrome");
  let chrome: ChildProcess | null = null;
  let page: Awaited<ReturnType<typeof devtools>> | null = null;
  try {
    // A session on record (the launcher's own event), so Home is past its
    // first-run card, as on a machine where an agent asks.
    assert.ok(await emitLauncherEvent(socketPath, launchPostureEvent({ scopeId: SESSION, target: "claude", argv0: "/usr/local/bin/claude", notes: [] })));
    // Keys Mandu found: the real scan files the key.
    const scanned = await pageFetch(`${base}/api/suggestions/scan`, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, body: JSON.stringify({ root: "~/proj" }) });
    assert.equal(scanned.status, 200, await scanned.text());
    // A waiting question: the egress gate asks about a masked variable.
    const vars = await data.registerEnvSecrets({ vars: [{ name: "GITHUB_TOKEN", value: VAR_VALUE }], sessionKey: SESSION });
    const sym = String(vars.vars[0]?.symbol);
    const d = await data.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "gist.github.com", sessionKey: SESSION, scheme: "https" });
    assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "the gate asks the human");

    const started = await startChromium(BIN!, profile, `${base}${dash.adminLoginPath()}`);
    chrome = started.proc;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let target: any = null;
    for (let i = 0; i < 50 && target === null; i++) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const list = (await (await fetch(`http://127.0.0.1:${started.port}/json/list`)).json()) as any[];
      target = list.find((x) => x.type === "page") ?? null;
      if (target === null) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(target, "the page is listed");
    page = await devtools(target.webSocketDebuggerUrl);
    const p = page;
    const evaluate = async (expression: string): Promise<unknown> => (await p.send("Runtime.evaluate", { expression, returnByValue: true })).result?.result?.value;
    const until = async (expression: string, what: string): Promise<void> => {
      for (let i = 0; i < 150; i++) {
        if (await evaluate(expression) === true) return;
        await new Promise((r) => setTimeout(r, 100));
      }
      assert.fail(`the page never showed ${what}`);
    };
    await until(`${READY} && location.pathname === "/"`, "Home after the sign-in link");
    await p.send("Emulation.setDeviceMetricsOverride", { width: WIDTH, height: HEIGHT, deviceScaleFactor: 1, mobile: true });
    const texts: string[] = [];

    // ── U1: Home ──
    await p.send("Page.navigate", { url: `${base}/` });
    await until(`${READY} && location.pathname === "/" && !!document.querySelector("#home-waiting .ask") && !document.getElementById("home-scan").hidden`, "Home with its question and the scan card");
    const homeFacts = JSON.parse(String(await evaluate(`JSON.stringify((() => {
      const ask = document.querySelector("#home-waiting .ask");
      const scan = document.getElementById("home-scan");
      return {
        scrollY: window.scrollY, inner: window.innerHeight,
        askTop: ask.getBoundingClientRect().top, scanTop: scan.getBoundingClientRect().top,
        before: !!(ask.compareDocumentPosition(scan) & Node.DOCUMENT_POSITION_FOLLOWING),
        scanHead: document.getElementById("home-scan-headline").textContent,
        ask: ask.querySelector(".ask-sentence").textContent,
        firstRun: !document.getElementById("home-first-run").hidden,
        text: document.body.innerText,
      };
    })())`)));
    assert.equal(homeFacts.scrollY, 0, "Home opens at its top");
    assert.equal(homeFacts.firstRun, false, "a session is on record: no first-run card");
    assert.equal(homeFacts.scanHead, "Did your agents already send a secret to the AI?", "no scan kept: the card says how to run one");
    assert.match(homeFacts.ask, /GITHUB_TOKEN/);
    assert.ok(homeFacts.before, "the question comes before the scan card");
    assert.ok(homeFacts.askTop < homeFacts.scanTop, `the question is drawn above the scan card (${homeFacts.askTop} < ${homeFacts.scanTop})`);
    assert.ok(homeFacts.askTop >= 0 && homeFacts.askTop < HEIGHT, `the question's card starts inside the first ${HEIGHT} px (at ${homeFacts.askTop})`);
    texts.push(homeFacts.text);

    // ── U2: Approvals ──
    await p.send("Page.navigate", { url: `${base}/approvals` });
    await until(`${READY} && location.pathname === "/approvals" && !!document.querySelector("#approvals-waiting .ask") && !!document.querySelector("#approvals-suggestions .ask.suggestion-card")`, "Approvals with its question and Keys Mandu found");
    const apprFacts = JSON.parse(String(await evaluate(`JSON.stringify((() => {
      const ask = document.querySelector("#approvals-waiting .ask");
      const keys = document.querySelector("#approvals-suggestions .ask.suggestion-card");
      return {
        askTop: ask.getBoundingClientRect().top, keysTop: keys.getBoundingClientRect().top,
        before: !!(ask.compareDocumentPosition(keys) & Node.DOCUMENT_POSITION_FOLLOWING),
        keys: keys.querySelector(".ask-sentence").textContent,
        links: [...document.querySelectorAll('#page-approvals nav.section-links li:not([hidden]) a')].map((a) => a.textContent),
        text: document.body.innerText,
      };
    })())`)));
    assert.match(apprFacts.keys, /^Mandu found 1 possible key in /);
    assert.ok(apprFacts.before, "Waiting for your answer comes before Keys Mandu found");
    assert.ok(apprFacts.askTop < apprFacts.keysTop, `and is drawn above it (${apprFacts.askTop} < ${apprFacts.keysTop})`);
    assert.deepEqual(apprFacts.links, ["Waiting", "Keys Mandu found", "Answered earlier"], "the links follow the lists shown, in their order");
    texts.push(apprFacts.text);

    // ── U3: the oracle ──
    for (const text of texts) {
      for (const value of [KEY, VAR_VALUE]) assert.ok(!text.includes(value), "no secret value on a page");
    }
  } finally {
    page?.close();
    await stopChromium(chrome, profile);
    await dash.close();
    data.close();
    await arbiter.close();
  }
});
