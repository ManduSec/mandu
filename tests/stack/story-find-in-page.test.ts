/**
 * story-find-in-page e2e — the browser's Find (Ctrl+F) on a session page
 * reaches folded steps and folded quiet turns, and the browser opening one
 * opens it through its button (dashboard.md §4.25b *Find in page opens a
 * fold*, §4.25ae), across the REAL components: a real ArbiterServer in
 * `secrets`, the real anthropic-proxy in its production wiring (`new
 * ArbiterClientAdapter(data, human)`) with a scripted model behind it, and
 * the real dashboard over the arbiter's store with the PRODUCTION surfaces
 * (`makeApprovalsArbiter`), signed in.
 *
 * Until 2026-10-22 both folds were `hidden` (display: none), which takes
 * them out of find in page: past a turn's first 6 steps, a busy turn's
 * commands and file names could not be found, nor, under *Only where Mandu
 * stepped in*, anything in a folded quiet turn.
 *
 *   F1  the session: a turn of 14 Reads whose 10th reads a file of a
 *       distinct name, a turn that reads a registered .env (the AI gets the
 *       key as a placeholder), and two quiet turns, the last reading
 *       another distinct name; the page records them;
 *   F2  the oracle: the model never got the key, and no read carries it, a
 *       `$MDU` token or the admin token, signed out or in;
 *   F3  a real headless Chromium with the served stylesheet: the folded
 *       steps are kept for the browser's find (computed `display` not
 *       `none`, `content-visibility: hidden`) and take no room; the find
 *       reaches the 10th step's file name (`window.find`, which a
 *       `display: none` fold makes fail); the browser itself reveals the
 *       step (a fragment navigation to it: Chromium fires `beforematch` and
 *       shows the fold), and the fold's button reads "Show fewer steps",
 *       `aria-expanded="true"`;
 *   F4  opened with `?only=stepped-in`: each quiet run is kept for the
 *       find and takes no room (the story's 16 px gap between what shows,
 *       as before); the find reaches the last quiet turn's file name; the
 *       browser revealing it opens the whole run and its button reads
 *       "Hide them"; the drawn page carries no key and no `$MDU` token.
 *
 * A text fragment (`#:~:text=`), the spec's first choice for F3, does
 * nothing in the headless shell (not even for words in plain sight), and
 * `scrollIntoView` reveals no `until-found` content; Chromium's `window.find`
 * searches it but selects without opening it. So the test gives the step an
 * id and navigates to it: the same reveal Chromium runs for its find.
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

const KEY = `sk_live_findInPageCanary_${process.pid}_4Rt8Zp2Lq6`;
const SESSION = `story-find-${process.pid}`;
/** The file the long turn's 10th step reads: past its first 6, folded. */
const DEEP = "zanzibar-quokka-ledger.md";
/** The file the last quiet turn reads. */
const QUIET = "marmot-veranda-notes.md";
/** What the find looks for: a name's stem, as a long name draws in two
 *  parts (its extension apart), and `window.find` does not match across
 *  them. */
const stem = (name: string) => name.replace(/\.md$/, "");
const FILES = Array.from({ length: 14 }, (_, i) => (i === 9 ? DEEP : `part-${i + 1}.md`));
const render = (s: string) => s.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";

const dirs: string[] = [];
const closers: Array<() => Promise<void>> = [];
after(async () => {
  for (const c of closers.reverse()) await c();
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

let stack: { base: string; page: AgentPageVM; seen: string[] } | null = null;
/** The recorded session, once for both tests. */
async function start() {
  if (stack) return stack;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-story-find-"));
  dirs.push(tmp);
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  for (const f of [...FILES, QUIET, "notes.txt"]) writeFileSync(join(ws, f), `Notes in ${f}.\n`);
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

  // The scripted model answers each request with the next of `replies`.
  const replies: string[] = [];
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async (a) => {
    const m = new MockUpstream({ sse: replies.shift() ?? buildTextSse("Done.", { deltas: 1 }) });
    const res = await m.fetcher(a);
    seen.push(m.requests.at(-1)!.bodyText);
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
  const ask = async (messages: Msg[], reply: string): Promise<string> => {
    replies.push(reply);
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
    return seen.at(-1)!;
  };
  /** One turn: the question, then a Read of each file, one request a step. */
  let history: Msg[] = [];
  let n = 0;
  const turn = async (q: string, files: string[]) => {
    let msgs: Msg[] = [...history, { role: "user", content: q }];
    for (const f of files) {
      const id = `toolu_find_${++n}`;
      const path = f === ".env" ? env : join(ws, f);
      await ask(msgs, buildToolUseSse({ id, name: "Read", input: { file_path: path } }));
      msgs = [
        ...msgs,
        { role: "assistant", content: [{ type: "tool_use", id, name: "Read", input: { file_path: path } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: render(f === ".env" ? `STRIPE_KEY=${KEY}\n` : `Notes in ${f}.\n`) }] },
      ];
    }
    const got = await ask(msgs, buildTextSse("Done.", { deltas: 1 }));
    history = [...msgs, { role: "assistant", content: "Done." }];
    await new Promise((r) => setTimeout(r, 5));
    return got;
  };

  // ── F1: the session ─────────────────────────────────────────────────────
  await turn("Read every part of the plan", FILES);
  const got = await turn("What is in .env?", [".env"]);
  assert.ok(!got.includes(KEY), "CONFIDENTIALITY VIOLATION: the key reached the model");
  assert.match(got, /\$MDU:/, "the AI got the key as a placeholder");
  await turn("Read notes.txt", ["notes.txt"]);
  await turn("Read the veranda notes", [QUIET]);

  let page: AgentPageVM | undefined;
  const settled = (vm?: AgentPageVM) => !!vm && vm.story?.length === 4 && vm.story[0].steps.length === 14 && vm.story.filter((t) => t.tone !== "plain").length === 1;
  for (let i = 0; i < 200 && !settled(page); i++) {
    // emission is best-effort and asynchronous
    const r = await fetch(`${base}/api/home/agent?session=${SESSION}`, { headers: { Cookie: ADMIN_COOKIE } });
    assert.equal(r.status, 200);
    page = (await r.json()) as AgentPageVM;
    if (!settled(page)) await new Promise((res) => setTimeout(res, 25));
  }
  assert.ok(settled(page), `four turns, 14 steps in the first, Mandu stepping in only at the .env: ${JSON.stringify(page?.story.map((t) => [t.prompt, t.tone, t.steps.length]))}`);
  stack = { base, page: page!, seen };
  return stack;
}

test("a turn of 14 reads, a masked .env and quiet turns are recorded, and no read carries the key, a token or the admin token (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const { base, page, seen } = await start();
  assert.deepEqual(page.story.map((t) => t.prompt), ["Read every part of the plan", "What is in .env?", "Read notes.txt", "Read the veranda notes"]);
  assert.deepEqual(page.story.map((t) => t.tone === "plain"), [true, false, true, true], "Mandu stepped in only where the .env was read");

  // ── F2: the oracle ──────────────────────────────────────────────────────
  assert.ok(!seen.join("\n").includes(KEY), "CONFIDENTIALITY VIOLATION: the model got the key");
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
    assert.doesNotMatch(body, /\$MDU/, `${what} carries a token`);
    assert.ok(!body.includes(ADMIN_TOKEN), `${what} carries the admin token`);
  }
});

test("in a real Chromium: the find reaches a folded step and a folded quiet turn, and the browser revealing one opens it with its button (secrets axes, explicit)", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const { base, page } = await start();
  const ids = page.story.map((t) => t.id);
  const tmp = mkdtempSync(join(tmpdir(), "mandu-story-find-cdp-"));
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
    await send("Page.addScriptToEvaluateOnNewDocument", {
      source: `addEventListener("popstate", (e) => { if (window.__findReveal) { window.__findReveal = false; e.stopImmediatePropagation(); } });`,
    });
    // Compared as values in the page, never spliced into a selector.
    const turnJs = (id: string) => `[...document.querySelectorAll("#agent-story article.turn[data-turn-id]")].find((t) => t.dataset.turnId === ${JSON.stringify(id)})`;
    const stepJs = (name: string) => `[...document.querySelectorAll("#agent-story [data-step-id]")].find((s) => s.textContent.includes(${JSON.stringify(name)}))`;
    /** A fold as the browser draws it: kept for the find, taking no room. */
    const kept = (fold: string) => evaluate(`(() => {
      const f = ${fold}; const cs = getComputedStyle(f); const r = f.getBoundingClientRect();
      return { hidden: f.getAttribute("hidden"), display: cs.display, cv: cs.contentVisibility, w: r.width, h: r.height };
    })()`);
    /** Chromium's find over the page: true when it found the words. */
    const finds = (words: string) => evaluate(`(() => { getSelection().removeAllRanges(); const found = window.find(${JSON.stringify(words)}); getSelection().removeAllRanges(); return found; })()`);
    /** The browser itself reveals the step: a fragment navigation to it.
     *  A find changes no address, but a fragment navigation fires
     *  `popstate`, which the page's router reads as a new visit and draws
     *  again. That one `popstate` is kept from the router by a listener
     *  added before the page's own (window's listeners run in the order
     *  they were added). */
    const reveal = async (name: string, id: string) => {
      await evaluate(`(${stepJs(name)}).id = ${JSON.stringify(id)}, true`);
      await evaluate(`window.__findReveal = true`);
      await evaluate(`location.hash = ${JSON.stringify("#" + id)}, true`);
      assert.equal(await evaluate(`window.__findReveal`), false, "the fragment navigation's popstate came and was kept from the router");
    };
    const clean = async (where: string) => {
      const body = await evaluate(`document.body.innerText + document.documentElement.outerHTML`);
      assert.ok(!body.includes(KEY), `CONFIDENTIALITY VIOLATION: ${where} shows the key`);
      assert.doesNotMatch(body, /\$MDU/, `${where} carries a token`);
    };

    // ── F3: a folded run of steps ─────────────────────────────────────────
    await send("Page.navigate", { url: `${base}/agents/${SESSION}` });
    await until("the long turn drawn with its fold", `!!${stepJs(DEEP)} && !!${stepJs(DEEP)}.closest(".steps-more") && document.fonts.status === "loaded"`);
    const fold = `${stepJs(DEEP)}.closest(".steps-more")`;
    const toggle = `${fold}.nextElementSibling.querySelector(".steps-toggle")`;
    const k = await kept(fold);
    assert.equal(k.hidden, "until-found", "folded where the find still searches");
    assert.notEqual(k.display, "none", "not display: none, which takes it out of the find");
    assert.equal(k.cv, "hidden", "the browser skips its content until found");
    assert.ok(k.w === 0 && k.h === 0, `folded, it takes no room (${k.w}x${k.h})`);
    assert.equal(await evaluate(`${toggle}.textContent`), "Show 8 more steps");
    assert.equal(await finds(stem(DEEP)), true, "the find reaches the 10th step's file name");
    await clean("the session page");

    await reveal(DEEP, "find-deep");
    await until("the fold opens when the browser reveals the step", `!${fold}.hasAttribute("hidden")`);
    assert.equal(await evaluate(`${toggle}.textContent`), "Show fewer steps");
    assert.equal(await evaluate(`${toggle}.getAttribute("aria-expanded")`), "true");
    const r = await evaluate(`(() => { const r = ${stepJs(DEEP)}.getBoundingClientRect(); return { top: r.top, bottom: r.bottom, h: r.height, view: innerHeight }; })()`);
    assert.ok(r.h > 0 && r.top >= 0 && r.bottom <= r.view, `the step shows, in view (${r.top}..${r.bottom} of ${r.view})`);
    // Folded again by its button: still for the find.
    await evaluate(`${toggle}.click(), true`);
    assert.equal((await kept(fold)).hidden, "until-found");

    // ── F4: a folded run of quiet turns ───────────────────────────────────
    await send("Page.navigate", { url: `${base}/agents/${SESSION}?only=stepped-in` });
    await until("the quiet runs folded", `document.querySelectorAll("#agent-story .story-quiet").length === 2 && document.fonts.status === "loaded"`);
    for (const id of [ids[0], ids[2], ids[3]]) {
      const q = await kept(turnJs(id));
      assert.equal(q.hidden, "until-found", `quiet turn ${id} folded where the find still searches`);
      assert.notEqual(q.display, "none");
      assert.equal(q.cv, "hidden");
      assert.ok(q.w === 0 && q.h === 0, `it takes no room (${q.w}x${q.h})`);
    }
    // What shows keeps the story's gap, as before: no folded turn adds one.
    const gaps = await evaluate(`(() => {
      const shown = [...document.getElementById("agent-story").children].filter((x) => !x.hasAttribute("hidden"));
      return shown.slice(1).map((x, i) => Math.round(x.getBoundingClientRect().top - shown[i].getBoundingClientRect().bottom));
    })()`);
    assert.ok(gaps.length >= 2 && gaps.every((g: number) => g === 16), `the story's 16 px gap between what shows (${gaps})`);
    const line = `document.querySelectorAll("#agent-story .story-quiet")[1]`;
    assert.equal(await evaluate(`${line}.querySelector("span").textContent`), "2 turns where Mandu did nothing");
    assert.equal(await finds(stem(QUIET)), true, "the find reaches a folded quiet turn");
    await clean("the filtered session page");

    await reveal(QUIET, "find-quiet");
    await until("the quiet run opens when the browser reveals the step", `!${turnJs(ids[3])}.hasAttribute("hidden")`);
    assert.equal(await evaluate(`${turnJs(ids[2])}.hasAttribute("hidden")`), false, "the whole run opens, not just the one turn");
    assert.equal(await evaluate(`${line}.querySelector(".quiet-toggle").textContent`), "Hide them");
    assert.equal(await evaluate(`${line}.querySelector(".quiet-toggle").getAttribute("aria-expanded")`), "true");
    assert.equal((await kept(turnJs(ids[0]))).hidden, "until-found", "another run stays folded");
    await clean("the opened session page");
  } finally {
    cdp.close();
    await tour.stopProc(proc);
  }
});
