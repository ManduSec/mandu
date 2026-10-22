/**
 * product-link-width.test — a text link in one of the product page's columns
 * is only as wide as its words, in a real headless Chromium over the REAL
 * components (dashboard.md §4.25 *Page frame*). Mandu-new.
 *
 * Until 2026-10-20 "Back to home" (`a.back`, in `.page-head`) and "… in
 * Approvals" (`a.more`, in `.cards`) stretched across their column, a column
 * flexbox: 944 px wide at 1280 px around words of 85 and about 305 px. A
 * click in the blank space right of "Back to home" went Home, and one under
 * the last waiting card went to Approvals.
 *
 * Here a real ArbiterServer (`secrets`) with a workspace `.env` at
 * `no-model` in policy.yaml; the REAL anthropic-proxy on its production
 * client carries one session that reads the `.env` (masked); the session's
 * agent asks, over the data socket, to let the `.env` be sent to a host,
 * which waits for you; a real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`); and a headless Chromium driven over the DevTools
 * protocol (scripts/tour-screenshots.mjs), signed in. At 1280, 390 and
 * 320 px:
 *
 *   W1  on the session page and on History, `a.back`, and on Home and the
 *       session page, the `a.more` to the rule change, start at their
 *       column's left edge and are no wider than their words plus their
 *       padding (where the words fit the column on one line: 1280 and
 *       390 px); at 320 px the longer link wraps inside its column;
 *   W2  a click 200 px right of "Back to home" (on its row, inside the
 *       column) leaves the page where it was; at 1280 px a click 200 px
 *       right of Home's link to Approvals does too; a click on the words
 *       of "Back to home" still goes Home;
 *   W3  the oracle: the model never got the `.env`'s value, and no page
 *       drawn here carries it or a token.
 *
 * Self-SKIPs without a Chromium (scripts/tour-screenshots.mjs probeBrowser:
 * MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell, or one on
 * PATH). Axes: secrets (stated).
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
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

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
const browser = tour.probeBrowser({});

const ENV_VALUE = `linkWidthStackEnvValue_${process.pid}_0001`;
const SESSION = `link-width-${process.pid}`;
const WIDTHS = [1280, 390, 320];
const BACK = "Back to home";
const HOME_MORE = "1 rule change your agent asked for is in Approvals";
const AGENT_MORE = "1 rule change this agent asked for is in Approvals";

/** A link's box, its words' box (a Range over its contents), its padding,
 *  its column's box, and where the page is. Window px. */
interface Box { left: number; right: number; top: number; bottom: number }
interface Shot { words: string; link: Box; text: Box; pad: number; column: Box; lines: number }
const measure = (selector: string) => `(() => {
  const a = document.querySelector(${JSON.stringify(selector)});
  if (!a) return null;
  const box = (r) => ({ left: r.left, right: r.right, top: r.top, bottom: r.bottom });
  const range = document.createRange();
  range.selectNodeContents(a);
  const cs = getComputedStyle(a);
  const col = a.parentElement, ccs = getComputedStyle(col), cr = col.getBoundingClientRect();
  return {
    words: a.textContent, link: box(a.getBoundingClientRect()), text: box(range.getBoundingClientRect()),
    pad: parseFloat(cs.paddingLeft) + parseFloat(cs.paddingRight),
    column: { left: cr.left + parseFloat(ccs.paddingLeft), right: cr.right - parseFloat(ccs.paddingRight), top: cr.top, bottom: cr.bottom },
    lines: range.getClientRects().length,
  };
})()`;

test("Back to home and the links to Approvals are only as wide as their words, and a click beside them stays on the page, in a real Chromium over the real arbiter, proxy and dashboard; no value on the page (secrets axes)", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 240_000,
}, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-link-width-"));
  const repo = join(tmp, "home", "proj");
  mkdirSync(repo, { recursive: true });
  const env = join(repo, ".env");
  writeFileSync(env, `DB_PASSWORD=${ENV_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n`);
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
  // The proxy's production wiring (anthropic-proxy/src/server-main.ts).
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const human = new ArbiterClient(humanPath);
  await human.connect();
  let upstream = new MockUpstream({ sse: buildTextSse("ok") });
  const toModel: string[] = [];
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream: (x) => upstream.fetcher(x), log: () => {} });
  const proxyPort = await proxy.listen(0);
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    fileBrowserHome: join(tmp, "home"),
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const tools = [{ name: "Read", description: "read", input_schema: { type: "object" } }];
  const turn = async (messages: unknown[], sse: string) => {
    upstream = new MockUpstream({ sse });
    const r = await pageFetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "user-agent": "claude-cli/2.1.289 (external, cli)" },
      body: JSON.stringify({
        model: "claude-opus-4", stream: true, tools, messages,
        system: [{ type: "text", text: `You are Claude Code.\n\n# Environment\n - Primary working directory: ${repo}\n - Platform: linux` }],
      }),
    });
    assert.equal(r.status, 200, await r.text());
    toModel.push(upstream.requests[0]!.bodyText);
  };
  let proc: unknown = null;
  let cdp: Cdp | null = null;
  const pages: string[] = [];
  try {
    // The session reads .env (masked on its way to the model).
    const ask = { role: "user", content: "Read the env and tell me what it holds." };
    const use = { type: "tool_use", id: "toolu_lw_1", name: "Read", input: { file_path: env } };
    await turn([ask], buildToolUseSse({ id: "toolu_lw_1", name: "Read", input: { file_path: env } }));
    await turn([ask, { role: "assistant", content: [use] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_lw_1", content: `DB_PASSWORD=${ENV_VALUE}\n` }] }], buildTextSse("It holds a password."));
    // Its agent asks to let .env be sent to a host: it waits for you.
    const asked = await data.policyPropose({ edits: [{ op: "lock-path", path: env, level: "no-model", bindings: ["api.stripe.com"] }], sessionKey: SESSION, reason: "deploy needs it" });
    assert.ok("proposalId" in asked && asked.proposalId, `the binding waits for the human: ${JSON.stringify(asked)}`);
    // The session is listed (emission is best-effort and asynchronous).
    let found = false;
    for (let i = 0; i < 200 && !found; i++) {
      found = ((await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`, { headers: { Cookie: ADMIN_COOKIE } })).json()) as { found: boolean }).found;
      if (!found) await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(found, "the session is on record");

    const started = await tour.startBrowser(browser as string, join(tmp, "chrome"), process.env);
    proc = started.proc;
    cdp = await tour.Cdp.connect(started.wsUrl);
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const s = (method: string, params: object = {}) => cdp!.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const r = await s("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    };
    await s("Page.enable");
    await s("Runtime.enable");
    await s("Network.enable");
    const eq = ADMIN_COOKIE.indexOf("=");
    await s("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });
    const settle = () => evaluate("new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(() => r(true), 200))))");
    /** Opens `path` and waits until `selector` is drawn with its words. */
    const open = async (path: string, selector: string, words: string) => {
      await s("Page.navigate", { url: base + path });
      let ok = false;
      for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((r) => setTimeout(r, 100))) {
        try {
          ok = await evaluate(`document.readyState === "complete" && document.fonts.status === "loaded"
            && document.querySelector(${JSON.stringify(selector)})?.textContent === ${JSON.stringify(words)}`);
        } catch { /* navigating */ }
      }
      assert.ok(ok, `${path}: ${selector} reads "${words}"`);
      await settle();
      pages.push(await evaluate("document.documentElement.outerHTML + document.body.innerText"));
    };
    const where = () => evaluate("location.pathname") as Promise<string>;
    const click = async (x: number, y: number) => {
      for (const type of ["mouseMoved", "mousePressed", "mouseReleased"]) {
        await s("Input.dispatchMouseEvent", { type, x, y, button: type === "mouseMoved" ? "none" : "left", clickCount: type === "mouseMoved" ? 0 : 1 });
      }
      await settle();
    };

    const CASES = [
      { what: "the session page's Back to home", path: `/agents/${SESSION}`, selector: "#page-agent .page-head > a.back", words: BACK },
      { what: "History's Back to home", path: "/history", selector: "#page-history .page-head > a.back", words: BACK },
      { what: "Home's link to the rule change", path: "/", selector: "#home-waiting > a.more", words: HOME_MORE },
      { what: "the session page's link to its rule change", path: `/agents/${SESSION}`, selector: "#agent-waiting > a.more", words: AGENT_MORE },
    ];
    for (const width of WIDTHS) {
      await s("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 640 });
      for (const c of CASES) {
        const at = `${c.what} at ${width}px`;
        await open(c.path, c.selector, c.words);
        const m = await evaluate(measure(c.selector)) as Shot;
        // W1: it starts at its column's edge and stays inside the column.
        assert.ok(Math.abs(m.link.left - m.column.left) <= 1, `${at}: starts at the column's left edge (${JSON.stringify(m)})`);
        assert.ok(m.link.right <= m.column.right + 1, `${at}: inside its column (${JSON.stringify(m)})`);
        if (m.lines === 1) {
          assert.ok(m.link.right - m.link.left <= m.text.right - m.text.left + m.pad + 1,
            `${at}: ${Math.round(m.link.right - m.link.left)}px wide around words of ${Math.round(m.text.right - m.text.left)}px (padding ${m.pad}px)`);
        } else {
          // Words longer than the column wrap inside it (only the longer
          // link, only at 320 px).
          assert.equal(width, 320, `${at}: one line where the words fit (${m.lines} lines)`);
          assert.notEqual(c.words, BACK, `${at}: Back to home keeps one line`);
        }
        // W2: a click 200 px right of the words, on their row, stays on the page.
        const x = m.text.right + 200;
        if (x < m.column.right) {
          const before = await where();
          await click(x, (m.link.top + m.link.bottom) / 2);
          assert.equal(await where(), before, `${at}: a click 200px right of the words leaves the page where it was`);
        } else {
          assert.notEqual(c.words, BACK, `${at}: Back to home has 200px of blank space beside it`);
        }
      }
      // W2: the words themselves are still the link.
      await open(`/agents/${SESSION}`, "#page-agent .page-head > a.back", BACK);
      const m = await evaluate(measure("#page-agent .page-head > a.back")) as Shot;
      await click((m.text.left + m.text.right) / 2, (m.text.top + m.text.bottom) / 2);
      assert.equal(await where(), "/", `${width}px: a click on "Back to home" goes Home`);
    }

    // W3: the oracle.
    assert.equal(pages.length, WIDTHS.length * (CASES.length + 1), "every page was read");
    for (const p of pages) {
      assert.ok(!p.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: .env's value on a page");
      assert.doesNotMatch(p, /\$MDU/, "nor a token");
    }
    assert.equal(toModel.length, 2, "the session made its two requests");
    for (const body of toModel) assert.ok(!body.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: the model got .env's value");
    assert.ok(toModel.some((b) => b.includes("$MDU:")), "the .env's Read reached the model as a placeholder");
  } finally {
    cdp?.close();
    if (proc) await tour.stopProc(proc);
    await proxy.close();
    await dashboard.close();
    data.close();
    human.close();
    wired?.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
