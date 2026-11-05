/**
 * top-bar-sticks e2e — on a wide window the product page's top bar (the
 * Approvals count, the protection status) stays at the top of the window
 * while a long page scrolls under it, and every jump lands below it
 * (dashboard.md §4.25 *The bar stays in sight on a wide window*), across the
 * REAL components: a real ArbiterServer in `secrets`, the real
 * anthropic-proxy in its production wiring (`new ArbiterClientAdapter(data,
 * human)`) with a scripted model behind it, and the real dashboard over the
 * arbiter's store with the production approvals adapter
 * (`makeApprovalsArbiter`), signed in. Mandu-new.
 *
 * Until 2026-10-26 the bar scrolled away with the page: on a long session
 * page a new question from another agent showed only in a count no longer
 * on the screen.
 *
 * The session: the agent Reads a registered `~/mandu-try/.env` (the AI gets
 * its twin) and answers six questions at length (~4,000 characters each),
 * then its program sends the key's placeholder to a host no rule binds it
 * to, which the real egress gate refuses and asks about. Then a real
 * headless Chromium with the served page:
 *
 *   B1  at 1280×900 the session page scrolled to its end: `#top` is at the
 *       window's top, the Approvals link with its count "1" is drawn on top
 *       there (nothing covers it), and so is the protection status;
 *   B2  Latest turn, the "waiting for you" tile and a reply folded again
 *       each leave what they go to at or below the bar's bottom, Latest turn
 *       exactly the bar and 8 px below it;
 *   B3  on Rules, a section link under the title lands its card at the
 *       bar's bottom and 8 px, or the page at its end;
 *   B4  at 390×844 after the same scroll the bar is out of view: on a phone
 *       it scrolls away;
 *   B5  the oracle: the model never got the key's value, and no page the
 *       browser drew nor any read here carries it or a token.
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
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

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

const VALUE = `sk_live_topBarCanary_${process.pid}_00000000`;
const SESSION = `top-bar-sticks-${process.pid}`;
const QUESTIONS = ["Read .env and fix the parser retries.", "Now the cache.", "And the logger.", "Then the CLI flags.", "Update the docs.", "Run the release notes."];
/** A coding agent's summary of ~4,000 characters. */
function summary(n: number): string {
  const lines = [`Done with part ${n}. Here is what I changed and why:`, ""];
  for (let i = 1; i <= 34; i++) lines.push(`- **Step ${i}**: updated \`src/part${n}/module-${i}.ts\` so it keeps its place across a retry, and its tests.`);
  return lines.join("\n");
}

const dirs: string[] = [];
const closers: Array<() => Promise<void>> = [];
after(async () => {
  for (const c of closers.reverse()) await c();
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const noValue = (text: string, where: string) => {
  assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the key's value`);
  assert.doesNotMatch(text, /\$MDU:/, `${where} carries a token`);
};

/** The recorded session, with one send waiting for an answer. */
async function start(): Promise<{ base: string }> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-top-bar-"));
  dirs.push(tmp);
  const home = join(tmp, "home");
  mkdirSync(join(home, "mandu-try"), { recursive: true });
  const env = join(home, "mandu-try", ".env");
  writeFileSync(env, `STRIPE_KEY='${VALUE}'\nDEBUG=1\n`);
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, "version: 1\npaths: []\n");
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    policyPath: policy, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const gate = await open(sock);
  const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
  assert.ok(reg.twin, `the .env is registered: ${JSON.stringify(reg)}`);

  // The scripted model: a Read of the .env, then a long summary per question.
  const sent: { bodyText: string }[] = [];
  const answers = [buildToolUseSse({ id: "toolu_env", name: "Read", input: { file_path: env } }), ...QUESTIONS.map((_, i) => buildTextSse(summary(i + 1)))]
    .map((sse) => new MockUpstream({ sse }));
  const upstream: UpstreamFetcher = async (a) => {
    const m = answers[sent.length]!;
    const res = await m.fetcher(a);
    sent.push(m.requests.at(-1)!);
    return res;
  };
  const human = await open(humanSock);
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), human), upstream, sessionKey: SESSION, log: () => {} });
  const port = await proxy.listen(0);
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets, "the production adapter has the secrets surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policy },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  closers.push(async () => {
    await dashboard.close(); await proxy.close(); wired.close();
    for (const c of clients) c.close();
    await arbiter.close();
  });

  type Msg = { role: string; content: unknown };
  const send = async (messages: Msg[]): Promise<void> => {
    const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 2048, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
  };
  // The first turn reads the .env; each turn after asks again.
  const first: Msg[] = [{ role: "user", content: QUESTIONS[0] }];
  await send(first);
  const readRender = (reg.twin ?? "").split("\n").map((l, i) => `${i + 1}\t${l}`).join("\n");
  let history: Msg[] = [
    ...first,
    { role: "assistant", content: [{ type: "tool_use", id: "toolu_env", name: "Read", input: { file_path: env } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_env", content: readRender }] },
  ];
  await send(history);
  history = [...history, { role: "assistant", content: summary(1) }];
  for (const [i, q] of QUESTIONS.slice(1).entries()) {
    await new Promise((r) => setTimeout(r, 5)); // each question strictly after the last answer
    const asked: Msg[] = [...history, { role: "user", content: q }];
    await send(asked);
    history = [...asked, { role: "assistant", content: summary(i + 2) }];
  }
  assert.equal(sent.length, QUESTIONS.length + 1);
  for (const s of sent) assert.ok(!s.bodyText.includes(VALUE), "CONFIDENTIALITY VIOLATION: the key's value reached the model");
  // The agent's program sends the key's placeholder to a host no rule binds
  // it to: the real gate refuses and asks (as the real proxies ask, from the
  // human socket).
  const symbol = /\$MDU:[A-Za-z_]+\[[0-9a-f]+\](?:\.[A-Za-z_]+)?/.exec(sent[1]!.bodyText)?.[0];
  assert.ok(symbol, "the AI got the key as a placeholder");
  const d = await human.desymbolizationDecision({ symbol: symbol!, boundary: "network", destination: "paste.top-bar.example", sessionKey: SESSION, scheme: "https" });
  assert.equal(d.allow, false, "the real gate refuses an unbound send");
  assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "and asks for an OK");

  let page: AgentPageVM | undefined;
  let body = "";
  for (let i = 0; i < 200; i++) {
    // emission is best-effort and asynchronous
    const r = await pageFetch(`${base}/api/home/agent?session=${SESSION}`, { headers: { Cookie: ADMIN_COOKIE } });
    if (r.status === 200) {
      body = await r.text();
      page = JSON.parse(body) as AgentPageVM;
      if (page.story.length === QUESTIONS.length && page.story.every((t) => t.reply) && page.waiting.length === 1) break;
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.deepEqual(page?.story.map((t) => t.prompt), QUESTIONS, `the six turns, in order: ${body.slice(0, 400)}`);
  assert.equal(page!.waiting.length, 1, "one send waits for an answer");
  noValue(body, "the session page's read");
  return { base };
}

test("in a real Chromium the top bar stays in sight on a 1280 px window and every jump lands below it; on a 390 px phone it scrolls away; no value anywhere (secrets axes, explicit)", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const { base } = await start();
  const tmp = mkdtempSync(join(tmpdir(), "mandu-top-bar-cdp-"));
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
    /** Smooth scrolling would move the page after the measure. */
    const settle = () => new Promise((r) => setTimeout(r, 400));
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Network.enable");
    const eq = ADMIN_COOKIE.indexOf("=");
    await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });
    const turns = `[...document.querySelectorAll("#agent-story article.turn[data-turn-id]")]`;
    const bar = `document.getElementById("top").getBoundingClientRect()`;
    /** Is `el` drawn on top at its own centre: nothing (a card scrolled
     *  under the bar) covers it. */
    const onTop = (el: string) => `(() => { const e = ${el}; const r = e.getBoundingClientRect(); const at = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2); return r.height > 0 && r.top >= 0 && !!at && (at === e || e.contains(at)); })()`;
    const openSession = async (width: number, height: number) => {
      await send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });
      await send("Page.navigate", { url: `${base}/agents/${encodeURIComponent(SESSION)}` });
      await until(`the six turns drawn at ${width}px, the send waiting`, `${turns}.length === ${QUESTIONS.length} && !!document.querySelector("#agent-facts button.tile[data-goes='waiting']") && document.getElementById("nav-approvals-count").textContent === "1" && !document.getElementById("nav-approvals-count").hidden && document.fonts.status === "loaded"`);
      await evaluate(`window.scrollTo(0, document.documentElement.scrollHeight), true`);
      await settle();
    };

    // ── B1: 1280×900, scrolled to the end ──
    await openSession(1280, 900);
    const end = await evaluate(`({ y: window.scrollY, height: document.documentElement.scrollHeight, top: ${bar}.top, bottom: ${bar}.bottom, body: document.body.innerText })`);
    assert.ok(end.y > 3000, `deep in a long page (${end.y} of ${end.height} px)`);
    assert.equal(end.top, 0, "the bar is at the window's top");
    assert.equal(end.bottom, 65, "the bar is its 64 px row and its border");
    assert.ok(await evaluate(onTop(`document.querySelector('#nav a[data-page-link="approvals"]')`)), "the Approvals link is drawn on top, its count beside it");
    assert.ok(await evaluate(onTop(`document.getElementById("nav-approvals-count")`)), "the count is drawn on top");
    assert.ok(await evaluate(onTop(`document.getElementById("top-status")`)), "the protection status is drawn on top");
    noValue(end.body, "the session page Chromium drew");

    // ── B2: the page's own jumps land below the bar ──
    // The newest reply unfolded, so the page can scroll its turn to the top.
    await evaluate(`${turns}.at(-1).querySelector("button.reply-fold").click(), true`);
    await until("the newest reply unfolded", `!${turns}.at(-1).querySelector(".reply-text").classList.contains("folded")`);
    await evaluate(`window.scrollTo(0, 0), true`);
    await settle();
    await evaluate(`document.getElementById("agent-latest").click(), true`);
    await settle();
    const latest = await evaluate(`({ top: ${turns}.at(-1).getBoundingClientRect().top, y: window.scrollY })`);
    assert.ok(latest.y > 0, "Latest turn scrolled the page");
    assert.ok(Math.abs(latest.top - 73) <= 1, `Latest turn lands the turn the bar and 8 px down, not under the bar (${latest.top})`);

    await evaluate(`window.scrollTo(0, document.documentElement.scrollHeight), true`);
    await settle();
    await evaluate(`document.querySelector("#agent-facts button.tile[data-goes='waiting']").click(), true`);
    await settle();
    const ask = await evaluate(`(() => { const r = [...document.getElementById("agent-waiting").children].find((c) => c.classList.contains("ask")).getBoundingClientRect(); return { top: r.top, bottom: r.bottom }; })()`);
    assert.ok(ask.top >= 65, `the waiting tile lands its question below the bar (${ask.top})`);
    assert.ok(ask.bottom <= 900, `and in the window (${ask.bottom})`);

    // A reply unfolded, read to its end, then folded again from its button,
    // the page where the folded button comes to rest 30 px down the window,
    // under the bar: it is brought out below the bar, in view.
    const foldedAt = await evaluate(`${turns}[2].querySelector("button.reply-fold").getBoundingClientRect().top + window.scrollY`);
    await evaluate(`${turns}[2].querySelector("button.reply-fold").click(), true`);
    await until("the third reply unfolded", `!${turns}[2].querySelector(".reply-text").classList.contains("folded")`);
    await evaluate(`window.scrollTo(0, ${foldedAt} - 30), true`);
    await settle();
    await evaluate(`${turns}[2].querySelector("button.reply-fold").click(), true`);
    await settle();
    const folded = await evaluate(`(() => { const b = ${turns}[2].querySelector("button.reply-fold"); const r = b.getBoundingClientRect(); return { top: r.top, bottom: r.bottom, words: b.textContent, folded: ${turns}[2].querySelector(".reply-text").classList.contains("folded") }; })()`);
    assert.equal(folded.folded, true, "the reply folded again");
    assert.equal(folded.words, "Show the whole reply");
    assert.ok(folded.top >= 65 && folded.bottom <= 900, `its button is in view below the bar (${folded.top} to ${folded.bottom})`);

    // ── B3: Rules, a section link under its title ──
    await send("Page.navigate", { url: `${base}/rules` });
    await until("Rules drawn with its section links", `!document.getElementById("page-rules").hidden && !!document.querySelector('nav.section-links a[data-section="built-in"]') && !document.getElementById("builtin-block").hidden && document.fonts.status === "loaded"`);
    await settle();
    await evaluate(`document.querySelector('nav.section-links a[data-section="built-in"]').click(), true`);
    await settle();
    const card = await evaluate(`({ top: document.getElementById("builtin-block").getBoundingClientRect().top, y: window.scrollY, max: document.documentElement.scrollHeight - window.innerHeight, bar: ${bar}.top, body: document.body.innerText })`);
    assert.equal(card.bar, 0, "the bar stays at the window's top on Rules");
    assert.ok(card.y > 0, "the link scrolled the page");
    assert.ok(card.top >= 65, `the card's top is below the bar (${card.top})`);
    assert.ok(Math.abs(card.top - 73) <= 1 || Math.abs(card.y - card.max) <= 1, `the card lands the bar and 8 px down, or the page at its end (top ${card.top}, y ${card.y} of ${card.max})`);
    noValue(card.body, "Rules as Chromium drew it");

    // ── B4: a 390 px phone, scrolled to the end ──
    await openSession(390, 844);
    const phone = await evaluate(`({ y: window.scrollY, bottom: ${bar}.bottom, body: document.body.innerText })`);
    assert.ok(phone.y > 3000, `deep in the page on a phone (${phone.y})`);
    assert.ok(phone.bottom <= 0, `the bar scrolled away on a phone (its bottom at ${phone.bottom})`);
    noValue(phone.body, "the session page on a phone");
  } finally {
    cdp.close();
    await tour.stopProc(proc);
  }
});
