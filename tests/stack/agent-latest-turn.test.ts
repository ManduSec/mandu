/**
 * agent-latest-turn e2e — the session page's **Latest turn ↓** takes you to
 * the newest turn at the page's end (dashboard.md §4.25ad *Latest turn takes
 * you to the newest turn*), across the REAL components: a real
 * ArbiterServer in `secrets`, the real anthropic-proxy on its production
 * client (`new ArbiterClientAdapter(data, human)`) with a scripted model
 * behind it, and a real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`).
 *
 * Until 2026-10-22 the page drew its turns oldest first and nothing on it
 * went to the newest one, the answer to "what is my agent doing now?".
 *
 *   T1  the session: twelve turns, the third reading a `.env` whose key the
 *       proxy masks; the served record has the twelve, in order;
 *   T2  a real headless Chromium at 1280 and 390 px with the served
 *       stylesheet: the page opens at its top with the newest turn below
 *       the screen; the button shows in the story head, beside the switch
 *       at 1280 and on its own line under it at 390, its words the newest
 *       card's time; pressed, the newest turn's top is in the viewport and
 *       `document.activeElement` is that turn; the page never scrolls
 *       sideways;
 *   T3  the oracle: the model never got the `.env` value, and no read or
 *       drawn page carries it.
 *
 * The Chromium half self-SKIPs without a Chromium (probeBrowser:
 * MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell).
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm test  (tests/)
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

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

const SESSION = `1791850000-${process.pid}`;
const VALUE = `sk_live_latestTurnCanary_${process.pid}_4Kx8`;
const TURNS = 12;
const render = (s: string) => s.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";
/** A reply of a few lines, so twelve turns run well past one screen. */
const reply = (i: number) => [`Turn ${i + 1}: done.`, "", "- checked the parser", "- ran the tests", "- left the rest as it was"].join("\n");

const dirs: string[] = [];
const closers: Array<() => Promise<void>> = [];
after(async () => {
  for (const c of closers.reverse()) await c();
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

let stack: { base: string; page: AgentPageVM; text: string; seen: string[] } | null = null;
/** The recorded session, once for both tests. */
async function start() {
  if (stack) return stack;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-latest-turn-"));
  dirs.push(tmp);
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${join(tmp, "other.key")}\n    level: no-model\n`);
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"),
    policyPath, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await arbiter.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production wiring");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    configEnv: { MANDU_HOME: join(tmp, "home") }, log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const replies: string[] = [];
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = replies.shift() ?? buildTextSse("Done.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: SESSION, log: () => {} });
  const port = await proxy.listen(0);
  closers.push(async () => {
    await proxy.close(); await dashboard.close(); wired.close();
    data.close(); human.close();
    await arbiter.close();
  });

  type Msg = { role: string; content: unknown };
  const ask = async (messages: Msg[], sse: string): Promise<string> => {
    replies.push(sse);
    const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
    return seen.at(-1)!;
  };
  // ── T1: twelve turns, the third reads the .env ──
  let history: Msg[] = [];
  for (let i = 0; i < TURNS; i++) {
    const q: Msg[] = [...history, { role: "user", content: `Question ${i + 1}` }];
    if (i === 2) {
      const id = "toolu_latest_env";
      await ask(q, buildToolUseSse({ id, name: "Read", input: { file_path: env } }));
      const withResult: Msg[] = [
        ...q,
        { role: "assistant", content: [{ type: "tool_use", id, name: "Read", input: { file_path: env } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: render(`STRIPE_KEY=${VALUE}\n`) }] },
      ];
      const got = await ask(withResult, buildTextSse(reply(i), { deltas: 1 }));
      assert.ok(!got.includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
      assert.match(got, /\$MDU:/, "the model got the key's placeholder");
      history = [...withResult, { role: "assistant", content: reply(i) }];
    } else {
      await ask(q, buildTextSse(reply(i), { deltas: 1 }));
      history = [...q, { role: "assistant", content: reply(i) }];
    }
    await new Promise((r) => setTimeout(r, 15));
  }
  let page: AgentPageVM | undefined;
  let text = "";
  for (let i = 0; i < 200; i++) {
    // emission is best-effort and asynchronous
    const r = await pageFetch(`${base}/api/home/agent?session=${SESSION}`);
    assert.equal(r.status, 200);
    text = await r.text();
    page = JSON.parse(text) as AgentPageVM;
    if (page.story?.length === TURNS && page.story.at(-1)?.reply) break;
    await new Promise((res) => setTimeout(res, 25));
  }
  stack = { base, page: page!, text, seen };
  return stack;
}

test("a twelve-turn session is recorded in order, and no read carries the .env value (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const { base, page, text, seen } = await start();
  assert.deepEqual(page.story.map((t) => t.prompt), Array.from({ length: TURNS }, (_, i) => `Question ${i + 1}`), "the twelve turns, oldest first");
  assert.equal(page.earlier, 0, "all drawn");
  // ── T3: the oracle ──
  assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
  assert.ok(!text.includes(VALUE), "CONFIDENTIALITY VIOLATION: the session page's read carries the .env value");
  for (const route of ["/api/home", "/api/home/history", `/agents/${SESSION}`]) {
    assert.ok(!(await (await pageFetch(base + route)).text()).includes(VALUE), `CONFIDENTIALITY VIOLATION: ${route} carries the .env value`);
  }
});

test("in a real Chromium at 1280 and 390 px: Latest turn shows in the story head and takes the focus to the newest turn, in view", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const { base, page } = await start();
  const newest = page.story.at(-1)!.id;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-latest-turn-cdp-"));
  dirs.push(tmp);
  const { proc, wsUrl } = await tour.startBrowser(chromium as string, join(tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  try {
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
    const last = `[...document.querySelectorAll("#agent-story article.turn[data-turn-id]")].at(-1)`;
    const measure = () => evaluate(`(() => {
      const b = document.getElementById("agent-latest");
      const row = document.getElementById("agent-only-row");
      const t = ${last};
      const r = b.getBoundingClientRect(), s = row.getBoundingClientRect(), l = t.getBoundingClientRect();
      return {
        hidden: b.hidden, inHead: !!b.closest(".story-head"), text: b.textContent,
        time: t.querySelector(".turn-head > time.time").textContent, turnId: t.dataset.turnId,
        b: { top: r.top, bottom: r.bottom, left: r.left, right: r.right, h: r.height }, row: { top: s.top, bottom: s.bottom },
        last: { top: l.top }, view: { w: innerWidth, h: innerHeight }, y: scrollY,
        active: document.activeElement === t, page: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth,
        body: document.body.innerText,
      };
    })()`);
    for (const width of [1280, 390]) {
      await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 600 });
      await send("Page.navigate", { url: `${base}/agents/${SESSION}` });
      await until(`the story drawn at ${width} px`, `document.querySelectorAll("#agent-story article.turn[data-turn-id]").length === ${TURNS} && document.fonts.status === "loaded"`);
      const m = await measure();
      assert.equal(m.turnId, newest);
      assert.equal(m.y, 0, `the page opens at its top at ${width} px`);
      assert.ok(m.last.top > m.view.h, `the newest turn starts below the screen at ${width} px (${m.last.top} of ${m.view.h})`);
      assert.equal(m.hidden, false, "shown with twelve turns");
      assert.ok(m.inHead, "in the story head");
      assert.ok(m.b.h > 0 && m.b.left >= 0 && m.b.right <= m.view.w, `visible across at ${width} px (${JSON.stringify(m.b)})`);
      assert.ok(m.time.length > 0);
      assert.equal(m.text, `Latest turn, ${m.time} ↓`, "the newest card's time words");
      if (width === 1280) assert.ok(m.b.top < m.row.bottom && m.b.bottom > m.row.top, `beside the switch at 1280 px (${JSON.stringify([m.b, m.row])})`);
      else assert.ok(m.b.top >= m.row.bottom - 1, `on its own line under the switch at 390 px (${JSON.stringify([m.b, m.row])})`);
      assert.ok(m.page <= m.cw, `no sideways scroll at ${width} px`);
      assert.ok(!m.body.includes(VALUE), "CONFIDENTIALITY VIOLATION: the page shows the .env value");

      await evaluate(`document.getElementById("agent-latest").click(), true`);
      await until(`scrolled at ${width} px`, `scrollY > 0`);
      const c = await measure();
      assert.ok(c.last.top >= 0 && c.last.top < c.view.h, `the newest turn's top is in the viewport at ${width} px (${c.last.top} of ${c.view.h})`);
      assert.ok(c.active, `the newest turn has the focus at ${width} px`);
      assert.ok(c.page <= c.cw, `no sideways scroll after the press at ${width} px`);
    }
  } finally {
    cdp.close();
    await tour.stopProc(proc);
  }
});
