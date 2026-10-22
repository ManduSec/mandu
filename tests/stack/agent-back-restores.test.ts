/**
 * agent-back-restores e2e — Back to a session's page returns to where you
 * were, with the reply you had unfolded still unfolded (dashboard.md §4.25
 * *Back and Forward keep your place*), across the REAL components: a real
 * ArbiterServer in `secrets`, the real anthropic-proxy in its production
 * wiring (`new ArbiterClientAdapter(data, human)`) with a scripted model
 * behind it, and the real dashboard over the arbiter's store with the
 * production approvals adapter (`makeApprovalsArbiter`), signed in, its
 * file browser on the test's home folder. Mandu-new.
 *
 * Until 2026-10-21 the session page started again at its top on every Back,
 * every fold closed: a secret's "Change it in Rules" (§4.25b *A card opens
 * its file in Rules*) sent a person reading turn 20 some 9,000 px up on
 * their way back.
 *
 * The session: the agent Reads a registered `~/mandu-try/.env` (the AI gets
 * its twin) and answers at length, then five more questions, each answered
 * with a ~4,000-character summary. Then:
 *
 *   R1  the served page in jsdom: the fourth turn's reply unfolded, the
 *       secret's card followed to Rules, the browser's Back: the reply is
 *       still unfolded, the others folded;
 *   R2  a real headless Chromium at 1280 px with the served stylesheet: the
 *       same, scrolled to the fifth turn first; after Back the page is within
 *       3 px of where it was and the fifth turn at the height it had on the
 *       screen;
 *   R3  the oracle: the model never got the value, and no read or drawn page
 *       carries it or a token.
 *
 * The Chromium half self-SKIPs without a Chromium (probeBrowser:
 * MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell). Every
 * request of the jsdom half goes through `pageFetch` (served-page-fetch).
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
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
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

const VALUE = `sk_live_agentBackCanary_${process.pid}_0000000`;
const SESSION = `agent-back-restores-${process.pid}`;
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

const words = (parts: { kind: string; text: string }[]) => parts.map((p) => p.text).join("");
const noValue = (text: string, where: string) => {
  assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the key's value`);
  assert.doesNotMatch(text, /\$MDU:/, `${where} carries a token`);
};

let stack: { base: string } | null = null;
/** The recorded session, once for both tests. */
async function start() {
  if (stack) return stack;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-agent-back-"));
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
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), await open(humanSock)), upstream, sessionKey: SESSION, log: () => {} });
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

  let page: AgentPageVM | undefined;
  let body = "";
  for (let i = 0; i < 200; i++) {
    // emission is best-effort and asynchronous
    const r = await pageFetch(`${base}/api/home/agent?session=${SESSION}`, { headers: { Cookie: ADMIN_COOKIE } });
    if (r.status === 200) {
      body = await r.text();
      page = JSON.parse(body) as AgentPageVM;
      const card = page.secrets?.secrets.find((s) => /STRIPE_KEY/.test(words(s.what)));
      if (card?.file && page.story.length === QUESTIONS.length && page.story.every((t) => t.reply)) break;
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.deepEqual(page?.story.map((t) => t.prompt), QUESTIONS, `the six turns, in order: ${body.slice(0, 400)}`);
  assert.ok(page!.story.every((t) => t.reply), "each turn has its reply");
  assert.ok(page!.secrets?.secrets.some((s) => s.file === "~/mandu-try/.env"), "the key's card names its file");
  noValue(body, "the session page's read");
  stack = { base };
  return stack;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const storyTurns = (doc: Doc) => [...doc.querySelectorAll("#agent-story article.turn[data-turn-id]")] as Doc[];
const replyButton = (doc: Doc, i: number) => storyTurns(doc)[i]?.querySelector("button.reply-fold");

test("Back from Rules (a secret's card) to a session's page keeps the reply you unfolded unfolded, on the real stack; no value anywhere (secrets axes, explicit)", { timeout: 180_000 }, async () => {
  const { base } = await start();
  await servedProductPage(base, `/agents/${encodeURIComponent(SESSION)}`, (doc: Doc) => storyTurns(doc).length === QUESTIONS.length && !!doc.querySelector("#agent-secrets a.secret-rule-link"), async (doc: Doc) => {
    const w = doc.defaultView;
    assert.equal(storyTurns(doc).length, QUESTIONS.length);
    noValue(doc.body.textContent, "the session page");
    // R1: the fourth reply unfolded, then the secret's card to Rules.
    replyButton(doc, 3).click();
    assert.equal(replyButton(doc, 3).getAttribute("aria-expanded"), "true");
    // The story drawn before: Back draws it afresh from its first read, so
    // the wait is for that draw, not for what stayed in the hidden page.
    const drawn = storyTurns(doc)[3];
    const link = doc.querySelector("#agent-secrets a.secret-rule-link");
    link.focus();
    link.click();
    await waitWhile(() => doc.getElementById("page-rules").hidden);
    assert.equal(w.location.pathname, "/rules");
    w.history.back();
    await waitWhile(() => doc.getElementById("page-agent").hidden || storyTurns(doc)[3] === drawn || replyButton(doc, 3)?.getAttribute("aria-expanded") !== "true");
    assert.notEqual(storyTurns(doc)[3], drawn, "drawn again by the read Back made");
    assert.equal(w.location.pathname, `/agents/${encodeURIComponent(SESSION)}`);
    assert.equal(replyButton(doc, 3).getAttribute("aria-expanded"), "true", "the reply you unfolded is still unfolded");
    assert.equal(replyButton(doc, 3).textContent, "Show less");
    for (const i of [0, 1, 2, 4, 5]) assert.equal(replyButton(doc, i).getAttribute("aria-expanded"), "false", `reply ${i + 1} still folded`);
    // R3: the oracle.
    noValue(doc.body.textContent, "the session page returned to");
  }, { headers: { Cookie: ADMIN_COOKIE } });
});

test("in a real Chromium at 1280 px: Back from Rules lands the session's page within 3 px of where you were, the turn at its height, the reply still unfolded", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const { base } = await start();
  const tmp = mkdtempSync(join(tmpdir(), "mandu-agent-back-cdp-"));
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
    await send("Network.enable");
    const eq = ADMIN_COOKIE.indexOf("=");
    await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });
    await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
    await send("Page.navigate", { url: `${base}/agents/${encodeURIComponent(SESSION)}` });
    const turns = `[...document.querySelectorAll("#agent-story article.turn[data-turn-id]")]`;
    await until("the six turns drawn, their replies folded", `${turns}.length === ${QUESTIONS.length} && ${turns}.every((t) => t.querySelector(".reply-text.folded")) && document.fonts.status === "loaded" && !!document.querySelector("#agent-secrets a.secret-rule-link")`);
    // The fourth reply unfolded, the fifth turn scrolled to 200 px down the
    // screen, then a pause past the page's own save of the scroll.
    await evaluate(`${turns}[3].querySelector("button.reply-fold").click(), true`);
    await until("the fourth reply unfolded", `!${turns}[3].querySelector(".reply-text").classList.contains("folded")`);
    await evaluate(`window.scrollTo(0, ${turns}[4].getBoundingClientRect().top + window.scrollY - 200), true`);
    await new Promise((r) => setTimeout(r, 500));
    const before = await evaluate(`({ y: window.scrollY, top: ${turns}[4].getBoundingClientRect().top, height: document.documentElement.scrollHeight })`);
    assert.ok(before.y > 2000, `deep in the page (${before.y} of ${before.height} px)`);
    assert.ok(Math.abs(before.top - 200) <= 1, `the fifth turn 200 px down the screen (${before.top})`);

    await evaluate(`window.drawnBefore = ${turns}[3], document.querySelector("#agent-secrets a.secret-rule-link").click(), true`);
    await until("Rules shown", `!document.getElementById("page-rules").hidden && location.pathname === "/rules"`);
    await evaluate(`history.back(), true`);
    await until("the session page back, the reply unfolded", `!document.getElementById("page-agent").hidden && ${turns}.length === ${QUESTIONS.length} && ${turns}[3] !== window.drawnBefore && ${turns}[3].querySelector("button.reply-fold").getAttribute("aria-expanded") === "true"`);
    await new Promise((r) => setTimeout(r, 500));
    const back = await evaluate(`({ y: window.scrollY, top: ${turns}[4].getBoundingClientRect().top, folded: ${turns}[3].querySelector(".reply-text").classList.contains("folded"), others: ${turns}.filter((t, i) => i !== 3).every((t) => t.querySelector(".reply-text.folded")), body: document.body.innerText })`);
    assert.ok(Math.abs(back.y - before.y) <= 3, `the page within 3 px of where it was: ${back.y}, was ${before.y}`);
    assert.ok(Math.abs(back.top - before.top) <= 3, `the fifth turn at its height: ${back.top}, was ${before.top}`);
    assert.equal(back.folded, false, "the reply you unfolded is unfolded");
    assert.equal(back.others, true, "the others folded");
    noValue(back.body, "the page Chromium drew");
  } finally {
    cdp.close();
    await tour.stopProc(proc);
  }
});
