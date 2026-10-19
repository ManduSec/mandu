/**
 * reveal-redraw.test — "Show the real value" answered after the agent page
 * was drawn again, across the REAL components (dashboard.md §4.25b *Show
 * the real value keeps the focus*). Mandu-new.
 *
 * The agent page is drawn again from nothing when a read brings a changed
 * answer: the agent did more, or the protection service stopped. Until
 * 2026-10-15 a reveal answered after such a redraw went to the box the
 * redraw replaced, so the value or the refusal showed nowhere and the focus
 * stayed on <body> (CI job 16259 hit this in reveal-focus.test.ts F3). Here
 * a real ArbiterServer runs at the `secrets` axes with `.env` at `no-model`;
 * the REAL anthropic-proxy on its production client carries one session
 * whose scripted model reads it; a real DashboardServer serves its page
 * (index.html and home.js in jsdom, signed in). The page's reveal request
 * goes to the real server at once; only its answer is held in the page:
 *
 *   R1  the agent does one more turn, and the page's read draws the card
 *       again; then the real value comes: it shows in the card drawn now,
 *       whose button has the focus, reading "Hide it again";
 *   R2  the protection service stops, and the page's read says "Not
 *       connected"; then the real value comes: the page draws it nowhere,
 *       and the focus goes to the page's heading;
 *   R3  the oracle: the value never reached the model; the pages drawn
 *       carry no value once hidden, nor any token.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const ENV_VALUE = "revealRedrawStackEnvValue0001";
const SESSION = `reveal-redraw-${process.pid}`;
const HIDE = "Hide it again";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** Enter on a button that goes off while it acts: Chromium drops its focus. */
function press(btn: Doc): void {
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "the button goes off while it asks");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
  assert.equal(btn.ownerDocument.activeElement, btn.ownerDocument.body);
}
/** The page's poll, as on a return to its tab: Home, then the agent page. */
function poll(doc: Doc): void {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
}

test("the agent page: Show the real value answered after a redraw goes to the card drawn now, or nowhere once the page says Not connected (real arbiter, anthropic-proxy, dashboard)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-reveal-redraw-"));
  const ws = join(tmp, "home", "ws");
  mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, `API_TOKEN=${ENV_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  let arbiterUp = true;
  const stopArbiter = async () => { if (arbiterUp) { arbiterUp = false; await arbiter.close(); } };
  // The proxy's production wiring (anthropic-proxy/src/server-main.ts).
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const human = new ArbiterClient(humanPath);
  await human.connect();
  let upstream = new MockUpstream({ sse: buildTextSse("ok") });
  const toModel: string[] = [];
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream: (x) => upstream.fetcher(x), log: () => {} });
  const proxyPort = await proxy.listen(0);
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }), log: () => {}, ...ADMIN_OPTS });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const tools = [{ name: "Read", description: "read", input_schema: { type: "object" } }];
  const turn = async (messages: unknown[], sse: string) => {
    upstream = new MockUpstream({ sse });
    const r = await pageFetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "user-agent": "claude-cli/2.1.289 (external, cli)" },
      body: JSON.stringify({ model: "claude-opus-4", stream: true, system: "You are Claude Code.", tools, messages }),
    });
    assert.equal(r.status, 200, await r.text());
    toModel.push(upstream.requests[0]!.bodyText);
  };
  /** The agent page as the dashboard answers it now, signed in. */
  const agentText = async () => (await pageFetch(`${base}/api/home/agent?session=${SESSION}`, { headers: { Cookie: ADMIN_COOKIE } })).text();
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const rendered: string[] = [];
  // The page's reads still out (the boot's, a poll's), and its reveal
  // answers held until the test lets each go: the request reaches the
  // real server at once, as from a browser on a slow line.
  let reads = 0;
  const heldAnswers: Array<() => void> = [];
  const letGo = () => { const go = heldAnswers.shift(); assert.ok(go, "a reveal answer is held"); go(); };
  const holdReveals = (w: Doc) => {
    const f0 = w.fetch;
    w.fetch = (url: string, init: Doc = {}) => {
      if (/\/api\/home\/reveal$/.test(url)) return f0(url, init).then((r: unknown) => new Promise((go) => heldAnswers.push(() => go(r))));
      reads++;
      return f0(url, init).finally(() => { reads--; });
    };
  };
  try {
    // One session reads the file, masked on its way to the model.
    const ask = { role: "user", content: "Read the env file." };
    const use = { role: "assistant", content: [{ type: "tool_use", id: "toolu_rr_1", name: "Read", input: { file_path: env } }] };
    const res = { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_rr_1", content: `API_TOKEN=${ENV_VALUE}\n` }] };
    await turn([ask], buildToolUseSse({ id: "toolu_rr_1", name: "Read", input: { file_path: env } }));
    await turn([ask, use, res], buildTextSse("It holds one token."));

    // Emission is best-effort and asynchronous: wait for the secret.
    let text = "";
    for (let i = 0; i < 200; i++) {
      text = await agentText();
      const page = JSON.parse(text) as AgentPageVM;
      if (page.found && page.secrets && page.secrets.secrets.some((s) => s.ref) && /one token/.test(text)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    const page = JSON.parse(text) as AgentPageVM;
    assert.ok(page.secrets?.secrets.some((s) => s.ref), `a secret with a ref: ${text.slice(0, 400)}`);

    const cardButton = (doc: Doc) => doc.querySelector("#agent-secrets .secret-card button.secret-reveal");
    await servedProductPage(base, `/agents/${SESSION}`, (doc: Doc) => !!cardButton(doc), async (doc: Doc) => {
      // The boot's reads end first, so only the reads below draw the page.
      await waitWhile(() => reads > 0);

      // R1: the agent does one more turn while the value is on its way.
      const pressed = cardButton(doc);
      const named = pressed.getAttribute("aria-label");
      press(pressed);
      await waitWhile(() => heldAnswers.length === 0);
      const more = { role: "assistant", content: "It holds one token." };
      await turn([ask, use, res, more, { role: "user", content: "Thanks, that is all." }], buildTextSse("Glad to help with the file."));
      for (let i = 0; i < 200 && !/Glad to help/.test(await agentText()); i++) await new Promise((r) => setTimeout(r, 25));
      poll(doc);
      await waitWhile(() => cardButton(doc) === pressed || reads > 0);
      const now = cardButton(doc);
      assert.ok(now && now !== pressed && !pressed.isConnected, "the card was drawn again while the value was on its way");
      assert.equal(now.getAttribute("aria-label"), named, "the same secret's card");
      const box = now.closest(".secret-card").querySelector("pre.secret-value");
      letGo();
      await waitWhile(() => box.hidden);
      assert.equal(box.textContent, `API_TOKEN=${ENV_VALUE}\n`, "the card drawn now shows the file's own value");
      assert.equal(doc.activeElement, now, "the focus is on the button drawn now");
      assert.equal(now.textContent, HIDE);
      assert.equal(now.getAttribute("aria-expanded"), "true");
      assert.ok(!pressed.closest(".secret-card").textContent.includes(ENV_VALUE), "nothing went to the card the redraw replaced");
      now.click();
      assert.ok(!doc.documentElement.outerHTML.includes(ENV_VALUE), "hidden again: no value left on the page");
      rendered.push(doc.documentElement.outerHTML);

      // R2: the protection service stops while the next value is on its way.
      const again = cardButton(doc);
      press(again);
      await waitWhile(() => heldAnswers.length === 0);
      await stopArbiter();
      poll(doc);
      await waitWhile(() => doc.getElementById("agent-name").textContent !== "Not connected");
      assert.equal(doc.getElementById("agent-name").textContent, "Not connected");
      assert.equal(doc.getElementById("agent-secrets-block").hidden, true);
      letGo();
      await waitWhile(() => again.disabled);
      await new Promise((r) => setTimeout(r, 50));
      assert.ok(!doc.documentElement.outerHTML.includes(ENV_VALUE), "the value that came is drawn nowhere");
      assert.ok(!again.closest(".secret-card").textContent.includes(ENV_VALUE), "nor in the card the redraw replaced");
      assert.equal(doc.activeElement, doc.getElementById("agent-name"), "the focus is on the page's heading");
      rendered.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: holdReveals });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // R3: the oracle.
    for (const html of rendered) {
      assert.ok(!html.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: a value left in a drawn page");
      assert.doesNotMatch(html, /\$MDU/, "nor a token");
    }
    for (const body of toModel) {
      assert.ok(!body.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: the model got the file's value");
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await proxy.close();
    await dashboard.close();
    data.close();
    human.close();
    await stopArbiter();
    rmSync(tmp, { recursive: true, force: true });
  }
});
