/**
 * agent-page-missing.test — a session link Mandu has no record of says so in
 * the page's words and leads to History, across the REAL components
 * (dashboard.md §4.25 *Empty states*). Mandu-new.
 *
 * Until 2026-10-23 the page said "It may have been deleted, or it belongs to
 * the other tenant.": a tenant is the developer view's test store, which the
 * product page is never served from, and nothing on the product page deletes
 * a session. Here a real ArbiterServer runs at the `secrets` axes with `.env`
 * at `no-model` in policy.yaml; the REAL anthropic-proxy on its production
 * client carries one session that reads `.env`. A real DashboardServer
 * reaches the arbiter over the production adapter (`makeApprovalsArbiter`),
 * and the served product page (its own index.html and home.js in jsdom,
 * signed in) opens `/agents/<an id Mandu never saw>`:
 *
 *   M1  the route answers `found: false` for it, and `found: true` for the
 *       real session (the control);
 *   M2  the page is "Session not found" with the new words, names no tenant
 *       and says nothing was deleted; its one link is History, and a click
 *       opens History in place;
 *   M3  the oracle: `.env`'s value never reached the model, and no page or
 *       answer read here carries it or a token.
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
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const ENV_VALUE = "agentPageMissingStackEnvValue000001";
const SESSION = `agent-page-missing-${process.pid}`;
const UNKNOWN = `never-seen-${process.pid}`;
const WORDS = "Mandu has no record of this session. Records are kept for 90 days, so it may be older than that, or the link may be wrong. Look for it in History.";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

test("a session link Mandu has no record of says why and links History (real arbiter, anthropic-proxy, dashboard); no tenant, no secret", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-agent-page-missing-"));
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
  assert.ok(wired, "the production adapter");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
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
  const bodies: string[] = [];
  const agentRoute = async (session: string) => {
    const r = await pageFetch(`${base}/api/home/agent?session=${session}`, { headers: { Cookie: ADMIN_COOKIE } });
    const text = await r.text();
    bodies.push(text);
    assert.equal(r.status, 200, `${session}: ${text}`);
    return JSON.parse(text) as { found: boolean };
  };
  const rendered: string[] = [];
  try {
    // The session reads .env (masked on its way to the model).
    const ask = { role: "user", content: "Read the env and tell me what it holds." };
    const read1 = { type: "tool_use", id: "toolu_apm_1", name: "Read", input: { file_path: env } };
    await turn([ask], buildToolUseSse({ id: "toolu_apm_1", name: "Read", input: { file_path: env } }));
    await turn([ask, { role: "assistant", content: [read1] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_apm_1", content: `DB_PASSWORD=${ENV_VALUE}\n` }] }], buildTextSse("It holds a password."));
    for (const body of toModel) assert.ok(!body.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: the model got .env's value");

    // M1: the real session is found (emission is best-effort and
    // asynchronous), the unknown one is not.
    let found = false;
    for (let i = 0; i < 200 && !found; i++) {
      found = (await agentRoute(SESSION)).found;
      if (!found) await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(found, true, "the control: the real session is found");
    assert.equal((await agentRoute(UNKNOWN)).found, false, "an id Mandu never saw is not found");

    // M2: the served page for the unknown id.
    await servedProductPage(base, `/agents/${UNKNOWN}`, (doc: Doc) => (doc.getElementById("agent-sub").textContent ?? "") !== "", async (doc: Doc) => {
      assert.equal(doc.getElementById("page-agent").hidden, false);
      assert.equal(doc.getElementById("agent-name").textContent, "Session not found");
      const sub = doc.getElementById("agent-sub");
      assert.equal(sub.textContent, WORDS);
      assert.deepEqual([...sub.querySelectorAll("a")].map((a: Doc) => [a.textContent, a.getAttribute("href")]), [["History", "/history"]]);
      assert.doesNotMatch(doc.getElementById("page-agent").textContent, /tenant|deleted/i);
      assert.equal(doc.getElementById("agent-story-block").hidden, true, "no empty What happened");
      rendered.push(doc.documentElement.outerHTML);
      sub.querySelector("a").click();
      await waitWhile(() => doc.getElementById("page-history").hidden);
      assert.equal(doc.getElementById("page-history").hidden, false, "the link opens History");
      assert.equal(doc.getElementById("page-agent").hidden, true);
      rendered.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // M3: the oracle on every page drawn and every answer read above.
    assert.equal(rendered.length, 2);
    for (const text of [...rendered, ...bodies]) {
      assert.ok(!text.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: .env's value in a page or an answer");
      assert.doesNotMatch(text, /\$MDU/, "nor a token");
    }
    for (const body of toModel) assert.ok(!body.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: the model got .env's value");
  } finally {
    await proxy.close();
    await dashboard.close();
    data.close();
    human.close();
    wired?.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
