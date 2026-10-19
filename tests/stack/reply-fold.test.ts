/**
 * reply-fold e2e — a long agent reply on the product's session page folds
 * to its first lines, with "Show the whole reply" (dashboard.md §4.25b *A
 * long reply folds*), across the REAL components: a real ArbiterServer in
 * `secrets`, the real anthropic-proxy in its production wiring (`new
 * ArbiterClientAdapter(data, human)`) with a scripted model behind it, and
 * the real dashboard over the arbiter's store with the PRODUCTION surfaces
 * (`makeApprovalsArbiter`), signed in.
 *
 * Until 2026-10-19 every reply was drawn whole: a 1,392-character reply of
 * a recorded session took 883 px of a 2,028 px page at 1280 px, and a
 * coding agent's summary is often 3,000 to 6,000 characters.
 *
 *   R1  the session reads a registered .env (the AI gets the key as a
 *       placeholder) and answers with a ~4,000-character summary that names
 *       the key's placeholder; the session page records the reply and its
 *       "kept" line;
 *   R2  the oracle: no read here carries the key, signed out or in (the
 *       secret is never filled in), and no page or answer carries the
 *       admin token;
 *   R3  a real headless Chromium at 1280 and 390 px with the served
 *       stylesheet: the reply's box is no taller than its fold (10 of its
 *       lines) and fades, the kept line shows under it, one button reads
 *       "Show the whole reply"; pressed, the whole text shows, the button
 *       reads "Show less" with `aria-expanded="true"` and keeps the focus;
 *       pressed again it folds; a short reply has no button; the page never
 *       scrolls sideways and shows no key. Then the browser scrolls words
 *       of the folded rest into view, as its find in page or a Tab does
 *       (`scrollIntoView`: Chromium's `window.find` selects but does not
 *       scroll): the fold opens and the words stay in view.
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
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { ADMIN_COOKIE, ADMIN_OPTS, ADMIN_TOKEN } from "../../dashboard/test/unit/admin-session.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
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

const KEY = `sk_live_replyFoldCanary_${process.pid}_7Qm2Xw9Kd4`;
const SESSION = `reply-fold-${process.pid}`;
/** Words only in the last line of the long reply, far below its fold. */
const TAIL = "zanzibar-quokka-tail-marker";
/** A coding agent's summary of ~4,000 characters, naming the key's
 *  placeholder `token` near its end. */
function summary(token: string): string {
  const lines = ["Done. Here is what I changed and why:", ""];
  for (let i = 1; i <= 34; i++) lines.push(`- **Step ${i}**: updated \`src/module-${i}.ts\` so the parser keeps its place across a retry, and its tests.`);
  lines.push("", `The service reads its key from .env (${token}); I left it as it was.`, "", `- Last: ${TAIL}.`);
  return lines.join("\n");
}

const dirs: string[] = [];
const closers: Array<() => Promise<void>> = [];
after(async () => {
  for (const c of closers.reverse()) await c();
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

let stack: { base: string; page: AgentPageVM; reply: string } | null = null;
/** The recorded session, once for both tests. */
async function start() {
  if (stack) return stack;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-reply-fold-"));
  dirs.push(tmp);
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${join(tmp, "other.key")}\n    level: no-model\n`);
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    policyPath, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const gate = await open(sock);
  const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
  assert.ok(reg.symbol || reg.twin, `the .env is registered: ${JSON.stringify(reg)}`);

  // The scripted model: a Read of the .env, then the long summary, which
  // names the placeholder the AI got for the key.
  const sent: { bodyText: string }[] = [];
  let reply = "";
  const upstream: UpstreamFetcher = async (a) => {
    let m: MockUpstream;
    if (!sent.length) m = new MockUpstream({ sse: buildToolUseSse({ id: "toolu_env", name: "Read", input: { file_path: env } }) });
    else {
      const token = /\$MDU:[A-Za-z_]+\[[0-9a-f]+\](?:\.[A-Za-z_]+)?/.exec(a.body.toString("utf8"))?.[0];
      assert.ok(token, "the AI got the key as a placeholder");
      reply = summary(token!);
      m = new MockUpstream({ sse: buildTextSse(reply) });
    }
    const res = await m.fetcher(a);
    sent.push(m.requests.at(-1)!);
    return res;
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), await open(humanSock)), upstream, sessionKey: SESSION, log: () => {} });
  const port = await proxy.listen(0);
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock }), log: () => {}, ...ADMIN_OPTS,
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  closers.push(async () => {
    await dashboard.close(); await proxy.close(); wired.close();
    for (const c of clients) c.close();
    await arbiter.close();
  });

  type Msg = { role: string; content: unknown };
  const send = async (messages: Msg[]): Promise<string> => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 2048, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
    return sent.at(-1)!.bodyText;
  };
  // ── R1: the session reads the .env and answers at length ───────────────
  const ask: Msg[] = [{ role: "user", content: "Fix the parser retries and tell me what you changed." }];
  await send(ask);
  const toModel = await send([
    ...ask,
    { role: "assistant", content: [{ type: "tool_use", id: "toolu_env", name: "Read", input: { file_path: env } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_env", content: `     1\tSTRIPE_KEY=${KEY}\n` }] },
  ]);
  assert.ok(!toModel.includes(KEY), "CONFIDENTIALITY VIOLATION: the key reached the model");
  assert.ok(reply.length > 3500 && reply.length < 4500, `a ~4,000-character reply (${reply.length})`);

  let page: AgentPageVM | undefined;
  for (let i = 0; i < 100; i++) {
    // emission is best-effort and asynchronous
    const r = await fetch(`${base}/api/home/agent?session=${SESSION}`, { headers: { Cookie: ADMIN_COOKIE } });
    assert.equal(r.status, 200);
    page = (await r.json()) as AgentPageVM;
    if (page.story?.some((t) => t.reply)) break;
    await new Promise((res) => setTimeout(res, 20));
  }
  assert.ok(page?.story.some((t) => t.reply), "the reply is on the page");
  stack = { base, page: page!, reply };
  return stack;
}

const words = (parts: { kind: string; text: string }[]) => parts.map((p) => (p.kind === "masked" ? "[masked]" : p.text)).join("");

test("a ~4,000-character reply is recorded whole with its kept line, and no read carries the key or the admin token (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const { base, page } = await start();
  const reply = page.story.find((t) => t.reply)!.reply!;
  assert.equal(reply.ai, null, "a secret is never filled in: one card");
  assert.match(words(reply.parts), new RegExp(`Last: ${TAIL}\\.$`), "the whole reply, to its last line");
  assert.ok(words(reply.parts).includes("[masked]"), "the key stays a chip");
  assert.match(words(reply.kept ?? []), /^The reply held your secret \.env\. /, "the kept line names it");

  // ── R2: the oracle ──────────────────────────────────────────────────────
  for (const [what, url, cookie] of [
    ["the session page, signed out", `/api/home/agent?session=${SESSION}`, null],
    ["Home, signed out", "/api/home", null],
    ["the session page, signed in", `/api/home/agent?session=${SESSION}`, ADMIN_COOKIE],
    ["Home, signed in", "/api/home", ADMIN_COOKIE],
    ["the served page", `/agents/${SESSION}`, ADMIN_COOKIE],
  ] as const) {
    const r = await fetch(base + url, cookie ? { headers: { Cookie: cookie } } : {});
    assert.equal(r.status, 200, what);
    const body = await r.text();
    assert.ok(!body.includes(KEY), `CONFIDENTIALITY VIOLATION: ${what} carries the key`);
    assert.ok(!body.includes(ADMIN_TOKEN), `${what} carries the admin token`);
  }
});

test("in a real Chromium at 1280 and 390 px: the long reply folds to 10 lines with its kept line in sight, opens whole on Show the whole reply, and a browser revealing folded words opens it", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const { base } = await start();
  const tmp = mkdtempSync(join(tmpdir(), "mandu-reply-fold-cdp-"));
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
    const card = `document.querySelector("#agent-story .step.reply")`;
    /** The reply as drawn: its box, its fold, its button and its kept line. */
    const measure = () => evaluate(`(() => {
      const card = ${card};
      const t = card.querySelector(".reply-text");
      const cs = getComputedStyle(t);
      const btn = card.querySelector("button.reply-fold");
      const kept = card.querySelector(".hidden-note.reply-kept");
      const visible = (x) => !!x && !x.closest("[hidden]") && x.getBoundingClientRect().height > 0;
      return {
        height: t.getBoundingClientRect().height, whole: t.scrollHeight, line: parseFloat(cs.lineHeight),
        folded: t.classList.contains("folded"), mask: cs.maskImage || cs.webkitMaskImage || "",
        buttons: card.querySelectorAll("button.reply-fold").length, button: visible(btn) ? btn.textContent : null,
        expanded: btn && btn.getAttribute("aria-expanded"), controls: btn && btn.getAttribute("aria-controls") === t.id,
        focused: document.activeElement === btn,
        kept: visible(kept) && !t.contains(kept) && kept.getBoundingClientRect().top >= t.getBoundingClientRect().bottom - 1,
        page: document.documentElement.scrollWidth, view: document.documentElement.clientWidth,
        body: document.body.innerText,
      };
    })()`);
    for (const width of [1280, 390]) {
      await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 600 });
      await send("Page.navigate", { url: `${base}/agents/${SESSION}` });
      await until(`the reply drawn at ${width} px`, `!!${card} && document.fonts.status === "loaded"`);
      await until(`the reply folded at ${width} px`, `${card}.querySelector(".reply-text").classList.contains("folded")`);
      const m = await measure();
      assert.ok(m.line > 0, `the reply has a line height (${m.line})`);
      assert.ok(m.whole > 12 * m.line, `the reply is long at ${width} px: ${m.whole}px, ${(m.whole / m.line).toFixed(1)} lines`);
      assert.ok(m.height <= 10 * m.line + 1, `folded to 10 lines at ${width} px: ${m.height}px, a line ${m.line}px`);
      assert.ok(m.height >= 9 * m.line, `and shows about 10 lines (${m.height}px)`);
      assert.match(m.mask, /linear-gradient/, "it fades out at its foot");
      assert.equal(m.buttons, 1);
      assert.equal(m.button, "Show the whole reply");
      assert.equal(m.expanded, "false");
      assert.ok(m.controls, "the button controls the text");
      assert.ok(m.kept, "the kept line shows under the folded reply");
      assert.ok(m.page <= m.view, `no sideways scroll at ${width} px (${m.page} > ${m.view})`);
      assert.ok(!m.body.includes(KEY), "CONFIDENTIALITY VIOLATION: the page shows the key");

      await evaluate(`(() => { const b = ${card}.querySelector("button.reply-fold"); b.focus(); b.click(); return true; })()`);
      const o = await measure();
      assert.equal(o.folded, false);
      assert.ok(Math.abs(o.height - o.whole) <= 1, `the whole reply shows at ${width} px: ${o.height}px of ${o.whole}px`);
      assert.equal(o.button, "Show less");
      assert.equal(o.expanded, "true");
      assert.ok(o.focused, "the focus stays on the button");
      assert.ok(o.kept, "the kept line still under it");
      assert.ok(o.page <= o.view, `no sideways scroll opened at ${width} px`);
      assert.ok(o.body.includes(TAIL), "its last line shows");

      await evaluate(`${card}.querySelector("button.reply-fold").click(), true`);
      const c = await measure();
      assert.ok(c.folded && c.height <= 10 * c.line + 1, "Show less folds it again");
      assert.equal(c.button, "Show the whole reply");
      assert.ok(c.focused, "the focus still on the button");
    }

    // The browser shows words of the folded rest (its find in page, a Tab
    // to a link there): it scrolls the clipped box, and the fold opens.
    await evaluate(`window.scrollTo(0, 0), true`);
    await evaluate(`[...${card}.querySelectorAll(".md-li")].at(-1).scrollIntoView({ block: "center" }), true`);
    await until("the fold opens when the browser reveals folded words", `!${card}.querySelector(".reply-text").classList.contains("folded")`);
    const f = await evaluate(`(() => {
      const r = [...${card}.querySelectorAll(".md-li")].at(-1).getBoundingClientRect();
      return { button: ${card}.querySelector("button.reply-fold").getAttribute("aria-expanded"), text: ${card}.querySelector("button.reply-fold").textContent, top: r.top, bottom: r.bottom, view: innerHeight };
    })()`);
    assert.equal(f.button, "true", "the button says the reply is open");
    assert.equal(f.text, "Show less");
    assert.ok(f.top >= 0 && f.bottom <= f.view, `the revealed words stay in view (${f.top}..${f.bottom} of ${f.view})`);
  } finally {
    cdp.close();
    await tour.stopProc(proc);
  }
});
