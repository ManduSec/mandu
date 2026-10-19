/**
 * proposal-notifies.test — a rule change your agent asks for raises one
 * browser notification, as a waiting question does, across the REAL
 * components (dashboard.md §4.25 *Notifications*). Mandu-new.
 *
 * Until 2026-10-19 the product page notified only for questions: a rule
 * change the agent asked for was counted in the tab title and waited there
 * in silence, though the agent is told it is not applied until the person
 * answers it.
 *
 * Here a real ArbiterServer runs at the `secrets` axes with a policy file;
 * a real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`, as dashboard-policy-proposals-parity wires it)
 * serves the page, signed in. The page's `Notification` is a recording stub
 * with the permission granted:
 *
 *   T1  the first poll primes this browser (`mandu.home.seenProposals`),
 *       showing nothing;
 *   T2  the agent asks, over the data socket, for a loosening change (let
 *       its programs connect to a named host), with a reason that holds a
 *       fake key and the host; the next poll shows exactly one
 *       notification, "Mandu: your agent asks to change a rule";
 *   T3  the oracle: neither the reason, the host nor the key is in its
 *       title or body (a desktop notification can be mirrored off the
 *       machine), and no notification carries a token (`$MDU`).
 *
 * Once in jsdom over the served page and script (served-page.ts), and once
 * in a real headless Chromium over the DevTools protocol
 * (scripts/tour-screenshots.mjs, as settings-notify-off.test does). The
 * Chromium test self-SKIPs without a Chromium (probeBrowser). Axes: secrets
 * (stated; the arbiter's confidentiality pinned ON).
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
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests());

const SECRET = `sk_live_proposalNotifyCanary_${process.pid}_00000`;
const HOST = "exfil-notify.example.net";
const REASON = `the deploy step posts ${SECRET} to ${HOST}`;
const SESSION = `1791300000-${process.pid}`;
const SEEN_KEY = "mandu.home.seenProposals";
const TITLE = "Mandu: your agent asks to change a rule";
const BODY = "Open Approvals to answer it.";
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  Cdp: { connect(url: string): Promise<Cdp> };
};
const browser = tour.probeBrowser({});

/** The recording stub, as page script: `window.__notes` holds what was shown. */
const STUB = `(() => {
  const notes = [];
  function N(title, o) { notes.push({ title, body: (o && o.body) || "" }); this.close = () => {}; }
  N.permission = "granted";
  N.requestPermission = () => Promise.resolve("granted");
  Object.defineProperty(window, "Notification", { value: N, configurable: true, writable: true });
  window.__notes = notes;
})();`;

/** A fresh stack: arbiter (secrets axes) with a policy file, the dashboard
 *  over the production wiring, signed in; `propose()` has the agent ask for
 *  a loosening rule change over the data socket. */
async function stack() {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-proposal-notifies-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath, policyPollMs: 0, adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const agent = new ArbiterClient(sock);
  await agent.connect();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  return {
    tmp, base,
    propose: async (): Promise<string> => {
      const r = await agent.policyPropose({ edits: [{ op: "allow-connect", host: HOST }], reason: REASON, sessionKey: SESSION });
      assert.ok("proposalId" in r && r.proposalId, `it waits for the person: ${JSON.stringify(r)}`);
      return String(r.proposalId);
    },
    close: async () => {
      await dashboard.close();
      wired.close();
      agent.close();
      await arbiter.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

function oracle(notes: { title: string; body: string }[]) {
  for (const n of notes) {
    const words = n.title + "\n" + n.body;
    assert.ok(!words.includes(SECRET), `CONFIDENTIALITY VIOLATION: a notification carries the key: ${words}`);
    assert.ok(!words.includes(HOST), `a notification names the host: ${words}`);
    assert.ok(!words.includes("deploy step"), `a notification carries the agent's reason: ${words}`);
    assert.doesNotMatch(words, /\$MDU/, "a notification carries no token");
  }
}

test("served page: a loosening rule change the agent asks for notifies once, naming no reason, host or key (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const s = await stack();
  try {
    const seen = (doc: any): string[] | null => JSON.parse(doc.defaultView.localStorage.getItem(SEEN_KEY) ?? "null");
    await servedProductPage(s.base, "/", (doc) => seen(doc) !== null, async (doc) => {
      const w = doc.defaultView;
      const notes = w.__notes as { title: string; body: string }[];
      // T1
      assert.deepEqual(seen(doc), [], "primed with nothing waiting");
      assert.equal(notes.length, 0);
      // T2
      const id = await s.propose();
      Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
      doc.dispatchEvent(new w.Event("visibilitychange"));
      await waitWhile(() => !(seen(doc) ?? []).includes(id));
      assert.match(doc.title, /^\(1\) Mandu\b/, "the tab title counts it");
      // Plain copies: the page's objects belong to its own realm.
      const shown = Array.from(notes, (n) => ({ title: n.title, body: n.body }));
      assert.deepEqual(shown, [{ title: TITLE, body: BODY }], "exactly one notification");
      // T3
      oracle(shown);
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: (w) => w.eval(STUB) });
  } finally {
    await s.close();
  }
});

test("in a real Chromium: a loosening rule change the agent asks for notifies once, naming no reason, host or key (secrets axes, explicit)", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const s = await stack();
  const { proc, wsUrl } = await tour.startBrowser(browser as string, join(s.tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  try {
    await cdp.send("Browser.grantPermissions", { origin: s.base, permissions: ["notifications"] });
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
    await send("Page.addScriptToEvaluateOnNewDocument", { source: STUB });
    const eq = ADMIN_COOKIE.indexOf("=");
    await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: s.base, httpOnly: true, sameSite: "Strict" });
    await send("Page.navigate", { url: s.base + "/" });
    // T1
    await until("the first poll primes this browser", `localStorage.getItem(${JSON.stringify(SEEN_KEY)}) === "[]"`);
    assert.deepEqual(await evaluate("window.__notes"), []);
    // T2
    const id = await s.propose();
    await evaluate(`document.dispatchEvent(new Event("visibilitychange")), true`);
    await until("the rule change is seen", `JSON.parse(localStorage.getItem(${JSON.stringify(SEEN_KEY)}) || "[]").includes(${JSON.stringify(id)})`);
    const after = await evaluate(`({ title: document.title, notes: window.__notes })`);
    assert.match(after.title, /^\(1\) Mandu\b/, "the tab title counts it");
    assert.deepEqual(after.notes, [{ title: TITLE, body: BODY }], "exactly one notification");
    // T3
    oracle(after.notes);
  } finally {
    cdp.close();
    await tour.stopProc(proc);
    await s.close();
  }
});
