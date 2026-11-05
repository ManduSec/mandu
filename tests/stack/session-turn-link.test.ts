/**
 * session-turn-link e2e — a turn's time on the session page links to that
 * turn (dashboard.md §4.25 *A turn's time links to that turn*), across the
 * REAL components: a real ArbiterServer in `secrets`, the real
 * anthropic-proxy on its production client (`new ArbiterClientAdapter(data,
 * human)`) with a scripted model behind it, and a real DashboardServer over
 * the production adapter (`makeApprovalsArbiter`), whose served page runs
 * its own home.js in jsdom.
 *
 * Until 2026-10-28 nothing on the page gave an address for one moment of a
 * session: a report or a note could only name the session.
 *
 *   U1  the session: 62 turns, the third reading a `.env` whose key the
 *       proxy masks; the first read draws the newest 60 (`earlier` 2);
 *   U2  the served page opened at `/agents/<id>?turn=<the first turn>`, a
 *       turn the first read does not draw, asks for every turn (the Show
 *       them read) and lands on it: focused, marked, its address kept;
 *   U3  every turn's time is a link to `?turn=<its id>`, ids only; a click
 *       on another replaces the address and moves the mark;
 *   U4  the oracle: the model never got the `.env` value, and neither the
 *       address, a turn link, the drawn page nor a read carries it or a
 *       `$MDU` token;
 *   U5  a real headless Chromium at 1280 and 390 px with the served
 *       stylesheet: opened at that address, the page lands with the turn's
 *       top in the viewport (about 8 px down at 390 px, so its marked ring
 *       is whole), the turn focused and marked, the page never
 *       scrolling sideways; its time link is a real link, the time's own
 *       words.
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
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
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
const VALUE = `sk_live_turnLinkCanary_${process.pid}_7Qz2`;
/** Two more than the page's first read draws (TURN_CAP, 60). */
const TURNS = 62;
const render = (s: string) => s.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";

const dirs: string[] = [];
const closers: Array<() => Promise<void>> = [];
const noValue = (text: string, where: string) => {
  assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the .env value`);
  assert.doesNotMatch(text, /\$MDU/, `${where} carries no token`);
};
after(async () => {
  for (const c of closers.reverse()) await c();
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

const at = (id: string) => `/agents/${encodeURIComponent(SESSION)}?turn=${encodeURIComponent(id)}`;
let stack: { base: string; story: AgentPageVM["story"]; seen: string[] } | null = null;
/** The recorded session, once for both tests (U1). */
async function start() {
  if (stack) return stack;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-turn-link-"));
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
  // ── U1: 62 turns, the third reads the .env ──
  let history: Msg[] = [];
  for (let i = 0; i < TURNS; i++) {
    const q: Msg[] = [...history, { role: "user", content: `Question ${i + 1}` }];
    const said = `Turn ${i + 1}: done.`;
    if (i === 2) {
      const id = "toolu_turn_link_env";
      await ask(q, buildToolUseSse({ id, name: "Read", input: { file_path: env } }));
      const withResult: Msg[] = [
        ...q,
        { role: "assistant", content: [{ type: "tool_use", id, name: "Read", input: { file_path: env } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: render(`STRIPE_KEY=${VALUE}\n`) }] },
      ];
      const got = await ask(withResult, buildTextSse(said, { deltas: 1 }));
      assert.ok(!got.includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
      assert.match(got, /\$MDU:/, "the model got the key's placeholder");
      history = [...withResult, { role: "assistant", content: said }];
    } else {
      await ask(q, buildTextSse(said, { deltas: 1 }));
      history = [...q, { role: "assistant", content: said }];
    }
    await new Promise((r) => setTimeout(r, 5));
  }
  let page: AgentPageVM | undefined;
  for (let i = 0; i < 400; i++) {
    // emission is best-effort and asynchronous
    const r = await pageFetch(`${base}/api/home/agent?session=${SESSION}&turns=all`);
    assert.equal(r.status, 200);
    const text = await r.text();
    noValue(text, "the session page's read of every turn");
    page = JSON.parse(text) as AgentPageVM;
    if (page.story?.length === TURNS && page.story.at(-1)?.reply) break;
    await new Promise((res) => setTimeout(res, 25));
  }
  assert.equal(page!.story.length, TURNS, "every turn recorded");
  const first = page!.story[0]!;
  assert.equal(first.prompt, "Question 1");
  assert.match(first.id, /^turn:input:[\w-]+:\d+$/, "a turn id is the server's own: no prompt, path or value in it");
  const capped = JSON.parse(await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`)).text()) as AgentPageVM;
  assert.equal(capped.earlier, 2, "the first read leaves the two oldest turns out");
  assert.ok(!capped.story.some((t) => t.id === first.id), "the first turn is not in the first read");
  stack = { base, story: page!.story, seen };
  return stack;
}

test("a turn's address opens the session page at that turn, beyond the turns first drawn, and carries no secret (secrets axes, explicit)", { timeout: 180_000 }, async () => {
  const { base, story, seen } = await start();
  const [first, second] = [story[0]!, story[1]!];

  // ── U2: the turn's address lands on it ──
  const turnOf = (doc: El, id: string) => [...doc.querySelectorAll("#agent-story article.turn[data-turn-id]")].find((t: El) => t.dataset.turnId === id);
  await servedProductPage(base, at(first.id), (doc) => !!turnOf(doc, first.id) && doc.activeElement === turnOf(doc, first.id), async (doc) => {
    const w = doc.defaultView;
    const card = turnOf(doc, first.id);
    assert.equal(doc.querySelectorAll("#agent-story article.turn[data-turn-id]").length, TURNS, "every turn drawn: the Show them read");
    assert.equal(doc.activeElement, card, "the turn has the focus");
    assert.ok(card.classList.contains("shown"), "marked");
    assert.match(card.textContent, /Question 1/);
    assert.equal(w.location.pathname + w.location.search, at(first.id), "the address is kept");

    // ── U3: every time is a link to its turn, ids only ──
    const links = [...doc.querySelectorAll("#agent-story .turn-head > time.time > a.turn-link")] as El[];
    assert.equal(links.length, TURNS, "each turn's time is a link");
    for (const a of links) {
      const id = a.closest("article.turn").dataset.turnId;
      assert.equal(a.getAttribute("href"), at(id));
      assert.equal(a.getAttribute("aria-label"), `Link to this turn, ${a.textContent}`);
      assert.doesNotMatch(a.getAttribute("href"), /Question|STRIPE|env/, "no prompt, path or key name in the address");
      noValue(a.getAttribute("href"), "a turn's link");
    }
    const next = links.find((a) => a.closest("article.turn").dataset.turnId === second.id);
    next.dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true, button: 0 }));
    await waitWhile(() => w.location.search !== `?turn=${encodeURIComponent(second.id)}`);
    assert.equal(w.location.pathname + w.location.search, at(second.id), "the click replaced the address");
    assert.deepEqual([...doc.querySelectorAll("#agent-story article.turn.shown")].map((t: El) => t.dataset.turnId), [second.id], "and moved the mark");

    // ── U4: the drawn page ──
    noValue(w.location.href, "the address");
    noValue(doc.body.textContent, "the drawn session page");
  });

  // ── U4: the oracle ──
  for (const body of seen) assert.ok(!body.includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
  for (const route of [`/api/home/agent?session=${SESSION}`, at(first.id)]) noValue(await (await pageFetch(base + route)).text(), route);
});

test("in a real Chromium at 1280 and 390 px: a turn's address lands with that turn's top in view, focused and marked", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const { base, story } = await start();
  const first = story[0]!;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-turn-link-cdp-"));
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
    const card = `[...document.querySelectorAll("#agent-story article.turn[data-turn-id]")].find((t) => t.dataset.turnId === ${JSON.stringify(first.id)})`;
    for (const width of [1280, 390]) {
      await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 600 });
      await send("Page.navigate", { url: base + at(first.id) });
      await until(`landed at ${width} px`, `(() => { const t = ${card}; return !!t && document.activeElement === t && document.fonts.status === "loaded"; })()`);
      // The scroll is the browser's own (scrollIntoView): let it settle.
      await new Promise((r) => setTimeout(r, 300));
      const m = await evaluate(`(() => {
        const t = ${card};
        const a = t.querySelector(".turn-head > time.time > a.turn-link");
        const r = t.getBoundingClientRect();
        return {
          top: r.top, h: innerHeight, shown: t.classList.contains("shown"), edge: getComputedStyle(t).borderTopColor,
          turns: document.querySelectorAll("#agent-story article.turn[data-turn-id]").length,
          link: a && a.href, words: a && a.textContent, time: a && a.closest("time").textContent,
          where: location.pathname + location.search, page: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth,
          body: document.body.innerText,
        };
      })()`);
      assert.equal(m.turns, TURNS, `every turn drawn at ${width} px`);
      assert.ok(m.top >= 0 && m.top < m.h, `the turn's top is in the viewport at ${width} px (${m.top} of ${m.h})`);
      // A phone keeps 8 px above it, so its marked ring is whole, not cut
      // off at the screen's edge (dashboard.md §4.25 *The bar stays in sight
      // on a wide window*); a wide window keeps the bar's 73 px.
      if (width < 830) assert.ok(m.top >= 6 && m.top <= 10, `the turn lands about 8 px down at ${width} px (${m.top})`);
      assert.ok(m.shown, "marked");
      assert.notEqual(m.edge, "rgba(0, 0, 0, 0)", "the mark draws an edge");
      assert.equal(m.where, at(first.id), "the address kept");
      assert.equal(m.link, base + at(first.id), "its time is a link to it");
      assert.equal(m.words, m.time, "the link's words are the time's");
      assert.ok(m.page <= m.cw, `no sideways scroll at ${width} px`);
      noValue(m.body, `the page at ${width} px`);
    }
  } finally {
    cdp.close();
    await tour.stopProc(proc);
  }
});
