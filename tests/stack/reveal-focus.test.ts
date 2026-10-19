/**
 * reveal-focus.test — "Show the real value" keeps the keyboard focus
 * through its request, across the REAL components (dashboard.md §4.25b
 * *Show the real value keeps the focus*). Mandu-new.
 *
 * The button goes off while it asks the dashboard for the value, and a
 * browser drops the focus of a button turned off to the page (<body>).
 * Until 2026-10-14 the focus stayed there once the value showed, and after
 * a refusal too. Here a real ArbiterServer runs at the `secrets` axes with
 * `.env` at `no-model` in policy.yaml; the REAL anthropic-proxy on its
 * production client carries one session whose scripted model reads it; a
 * real DashboardServer serves the session's page (its own index.html and
 * home.js in jsdom, signed in). jsdom keeps the focus of a button turned
 * off, so `press` drops it, as Chromium does:
 *
 *   F1  Enter on the Your secrets card's Show the real value: the file's
 *       value shows, and the button has the focus back, reading "Hide it
 *       again: The file …/.env", described by nothing;
 *   F2  Hide it again keeps the focus and takes the value off the page;
 *   F3  the protection service stops, and Enter again: refused, the button
 *       has the focus back, described by the refusal's words, nothing shown;
 *   F4  the oracle: the value never reached the model; signed out, the
 *       page's answer and the served page carry no value and no button.
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

const ENV_VALUE = "revealFocusStackEnvValue000001";
const SESSION = `reveal-focus-${process.pid}`;
const SHOW = "Show the real value";
const HIDE = "Hide it again";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const nameOf = (b: Doc): string => b.getAttribute("aria-label") ?? b.textContent;

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

test("the agent page: Show the real value has the focus back once the value shows, and after a refusal, described by it (real arbiter, anthropic-proxy, dashboard)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-reveal-focus-"));
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
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const rendered: string[] = [];
  // The page's reads still out: the boot's last one can come seconds after
  // the page is drawn on a loaded host.
  let reads = 0;
  const countReads = (w: Doc) => {
    const f0 = w.fetch;
    w.fetch = (url: string, init: Doc = {}) => {
      if (/\/api\/home\/reveal$/.test(url)) return f0(url, init);
      reads++;
      return f0(url, init).finally(() => { reads--; });
    };
  };
  try {
    // One session reads the file, masked on its way to the model.
    const ask = { role: "user", content: "Read the env file." };
    const use = { role: "assistant", content: [{ type: "tool_use", id: "toolu_rf_1", name: "Read", input: { file_path: env } }] };
    const res = { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_rf_1", content: `API_TOKEN=${ENV_VALUE}\n` }] };
    await turn([ask], buildToolUseSse({ id: "toolu_rf_1", name: "Read", input: { file_path: env } }));
    await turn([ask, use, res], buildTextSse("It holds one token."));

    // Emission is best-effort and asynchronous: wait for the secret.
    let text = "";
    for (let i = 0; i < 200; i++) {
      text = await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`, { headers: { Cookie: ADMIN_COOKIE } })).text();
      const page = JSON.parse(text) as AgentPageVM;
      if (page.found && page.secrets && page.secrets.secrets.some((s) => s.ref) && /one token/.test(text)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    const page = JSON.parse(text) as AgentPageVM;
    assert.ok(page.secrets?.secrets.some((s) => s.ref), `a secret with a ref: ${text.slice(0, 400)}`);

    // F4 (signed out), while the protection service still runs.
    const out = await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`)).text();
    assert.ok(!out.includes(ENV_VALUE), "signed out, no value in the answer");
    await servedProductPage(base, `/agents/${SESSION}`, (doc: Doc) => !!doc.querySelector("#agent-secrets .secret-card"), (doc: Doc) => {
      assert.equal(doc.querySelector("button.secret-reveal"), null, "signed out, no Show the real value");
      rendered.push(doc.documentElement.outerHTML);
    });

    const cardButton = (doc: Doc) => doc.querySelector("#agent-secrets .secret-card button.secret-reveal");
    await servedProductPage(base, `/agents/${SESSION}`, (doc: Doc) => !!cardButton(doc), async (doc: Doc) => {
      const btn = cardButton(doc);
      const card = btn.closest(".secret-card");
      const box = card.querySelector("pre.secret-value");
      const named = nameOf(btn);
      assert.ok(named.startsWith(`${SHOW}: The file `) && named.endsWith("/ws/.env"), `named by its card: ${named}`);

      // F1: the value shows, and the button has the focus back.
      press(btn);
      await waitWhile(() => box.hidden);
      assert.equal(box.textContent, `API_TOKEN=${ENV_VALUE}\n`, "the file's own value, as text");
      assert.equal(doc.activeElement, btn, "the focus is back on the button pressed");
      assert.equal(btn.disabled, false);
      assert.equal(nameOf(btn), `${HIDE}: ${named.slice(SHOW.length + 2)}`);
      assert.equal(btn.getAttribute("aria-expanded"), "true");
      assert.equal(btn.getAttribute("aria-describedby"), null, "nothing was refused");

      // F2: Hide it again asks nothing and keeps the focus; the value goes.
      btn.click();
      assert.equal(doc.activeElement, btn);
      assert.equal(box.hidden, true);
      assert.equal(box.textContent, "");
      assert.ok(!doc.body.textContent.includes(ENV_VALUE), "no value left on the page");

      // F3: the protection service stops; the next press is refused. The
      // boot's reads end first: one answered after the stop draws the page
      // as Not connected, with no button to give the focus back to (CI job
      // 16259; that case is reveal-redraw.test.ts R2).
      await waitWhile(() => reads > 0);
      await stopArbiter();
      press(btn);
      await waitWhile(() => btn.disabled || !card.querySelector(".ask-error"));
      assert.equal(doc.activeElement, btn, "refused: the focus is back on the button pressed");
      assert.equal(btn.getAttribute("aria-expanded"), "false", "nothing shown");
      assert.equal(box.hidden, true);
      const said = doc.getElementById(btn.getAttribute("aria-describedby") ?? "");
      assert.ok(said && said === card.querySelector(".ask-error") && said.textContent.trim(), "described by the refusal's words");
      assert.equal(nameOf(btn), named, "it still offers the value");
      rendered.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: countReads });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // F4: the oracle.
    for (const html of rendered) {
      assert.ok(!html.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: a value in a drawn page");
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
