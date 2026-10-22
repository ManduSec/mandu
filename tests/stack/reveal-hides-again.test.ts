/**
 * reveal-hides-again.test — a real value shown on a session's page hides
 * itself again, across the REAL components (dashboard.md §4.25b *Showing a
 * real value*, *The page*). Mandu-new.
 *
 * "Never inline by default" holds after a click too: a page left open,
 * shown or screenshotted keeps a secret's real value only while it is
 * asked for. A real ArbiterServer runs at the `secrets` axes with `.env` at
 * `no-model` in policy.yaml; the REAL anthropic-proxy on its production
 * client carries one session whose scripted model reads it; a real
 * DashboardServer serves the session's page (its own index.html and
 * home.js in jsdom, signed in), with a clock of its own for the hide's
 * timers (50 s, then 10 s):
 *
 *   H1  Show the real value on the Your secrets card puts the arbiter's
 *       value in the box; a minute later the page's DOM no longer holds it,
 *       and the button offers it again;
 *   H2  shown again, the tab goes to the background: at once the page's
 *       DOM no longer holds it;
 *   H3  the oracle: the value never reached the model, nor a drawn page
 *       after it hid.
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

const ENV_VALUE = "revealHidesAgainStackEnvValue01";
const SESSION = `reveal-hides-${process.pid}`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

test("the agent page: a shown real value leaves the page a minute later, and at once when the tab goes to the background (real arbiter, anthropic-proxy, dashboard)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-reveal-hides-"));
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
  // The page's clock for the hide's two timers; every other timer is real.
  let now = 0;
  let seq = 1_000_000;
  const timers = new Map<number, { at: number; fn: () => void }>();
  let visibility = "visible";
  const clock = (w: Doc) => {
    const real = w.setTimeout.bind(w);
    const realClear = w.clearTimeout.bind(w);
    w.setTimeout = (fn: () => void, ms: number) => {
      if (ms !== 50_000 && ms !== 10_000) return real(fn, ms);
      timers.set(++seq, { at: now + ms, fn });
      return seq;
    };
    w.clearTimeout = (id: number) => (timers.has(id) ? timers.delete(id) : realClear(id));
    Object.defineProperty(w.document, "visibilityState", { configurable: true, get: () => visibility });
  };
  const advance = (ms: number) => {
    const end = now + ms;
    for (;;) {
      const due = [...timers].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
      if (!due) break;
      timers.delete(due[0]);
      now = due[1].at;
      due[1].fn();
    }
    now = end;
  };
  const rendered: string[] = [];
  try {
    // One session reads the file, masked on its way to the model.
    const ask = { role: "user", content: "Read the env file." };
    const use = { role: "assistant", content: [{ type: "tool_use", id: "toolu_rh_1", name: "Read", input: { file_path: env } }] };
    const res = { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_rh_1", content: `API_TOKEN=${ENV_VALUE}\n` }] };
    await turn([ask], buildToolUseSse({ id: "toolu_rh_1", name: "Read", input: { file_path: env } }));
    await turn([ask, use, res], buildTextSse("It holds one token."));

    // Emission is best-effort and asynchronous: wait for the secret.
    let text = "";
    for (let i = 0; i < 200; i++) {
      text = await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`, { headers: { Cookie: ADMIN_COOKIE } })).text();
      const page = JSON.parse(text) as AgentPageVM;
      if (page.found && page.secrets && page.secrets.secrets.some((s) => s.ref) && /one token/.test(text)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok((JSON.parse(text) as AgentPageVM).secrets?.secrets.some((s) => s.ref), `a secret with a ref: ${text.slice(0, 400)}`);

    const cardButton = (doc: Doc) => doc.querySelector("#agent-secrets .secret-card button.secret-reveal");
    await servedProductPage(base, `/agents/${SESSION}`, (doc: Doc) => !!cardButton(doc), async (doc: Doc) => {
      const btn = cardButton(doc);
      const box = btn.closest(".secret-card").querySelector("pre.secret-value");
      const offer = btn.getAttribute("aria-label") ?? btn.textContent;
      assert.ok(!doc.body.textContent.includes(ENV_VALUE), "no value before the click");

      // H1: shown, then gone a minute later.
      btn.click();
      await waitWhile(() => box.hidden);
      assert.equal(box.textContent, `API_TOKEN=${ENV_VALUE}\n`, "the arbiter's value, as text");
      assert.ok(doc.body.textContent.includes(ENV_VALUE));
      advance(59_000);
      assert.ok(doc.body.textContent.includes(ENV_VALUE), "at 59 s it still shows");
      advance(1_000);
      assert.ok(!doc.body.textContent.includes(ENV_VALUE), "a minute later the value has left the page");
      assert.equal(box.hidden, true);
      assert.equal(btn.getAttribute("aria-expanded"), "false");
      assert.equal(btn.getAttribute("aria-label") ?? btn.textContent, offer, "the button offers it again");
      rendered.push(doc.documentElement.outerHTML);

      // H2: shown again (the server asked again), then the tab goes away.
      btn.click();
      await waitWhile(() => box.hidden);
      assert.ok(doc.body.textContent.includes(ENV_VALUE), "another click asks the server again");
      visibility = "hidden";
      doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
      assert.ok(!doc.body.textContent.includes(ENV_VALUE), "the tab went to the background: the value has left the page");
      assert.equal(box.hidden, true);
      assert.equal(timers.size, 0, "no timer left");
      rendered.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: clock });

    // H3: the oracle.
    for (const html of rendered) {
      assert.ok(!html.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: a value left in a page after it hid");
      assert.doesNotMatch(html, /\$MDU/, "nor a token");
    }
    assert.ok(toModel.length > 0);
    for (const body of toModel) {
      assert.ok(!body.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: the model got the file's value");
    }
  } finally {
    await proxy.close();
    await dashboard.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
