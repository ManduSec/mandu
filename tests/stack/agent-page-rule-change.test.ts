/**
 * agent-page-rule-change.test — a rule change your agent asked for and the
 * agent that asked find each other, across the REAL components
 * (dashboard.md §4.25 *A rule change and the agent that asked*). Mandu-new.
 *
 * Until 2026-10-12 the request's card projection dropped the session, so
 * the agent page of the agent that asked said nothing of its request (its
 * *Needs your OK* hidden with no question) while the nav badge said
 * Approvals 1, and the card on Approvals had no way to the agent that
 * asked. Here a real ArbiterServer runs at the `secrets` axes with `.env`
 * at `no-model` in policy.yaml; the REAL anthropic-proxy on its production
 * client carries two sessions (A reads `.env`, B writes notes); A's agent
 * asks (over the data socket) to let `.env` be sent to a host, which waits
 * for the human. A real DashboardServer reaches it over the production
 * adapter (`makeApprovalsArbiter`), and the served product page (its own
 * index.html and home.js in jsdom, signed in) draws:
 *
 *   R1  the listing: the card carries A's session, signed in and signed out;
 *   R2  Approvals: the card names the agent and folder that asked, "Claude
 *       Code wants to change a rule" and "· from Claude Code in ~/proj"
 *       (each session's turn names its folder, as Claude Code's system
 *       prompt does; B works in ~/blog); its "See what the agent was
 *       doing" is addressed to `/agents/<A>`; a click opens A's page, whose *Needs your OK*
 *       says "No question is waiting for you." and links "1 rule change
 *       this agent asked for is in Approvals", with no Allow of its own;
 *   R3  the link opens Approvals; Not now: the server records it, and A's
 *       page, opened again, has no *Needs your OK*;
 *   R4  B's page never shows A's request;
 *   R5  no unhandled rejection; the oracle: `.env`'s value never reached the
 *       model, and no page or answer read here carries it or a token.
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
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const ENV_VALUE = "agentRuleChangeStackEnvValue00000001";
const A = `agent-rule-change-a-${process.pid}`;
const B = `agent-rule-change-b-${process.pid}`;
const PENDING = "/api/policy/proposals?status=pending";
const NO_QUESTION = "No question is waiting for you.";
const LINK = "1 rule change this agent asked for is in Approvals";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const cardOf = (doc: Doc, id: string) => [...doc.querySelectorAll("#approvals-proposals .proposal")].find((c: Doc) => c.dataset.id === id);
const button = (root: Doc, label: string) => root && [...root.querySelectorAll("button")].find((b: Doc) => b.textContent === label);
const agentLink = (doc: Doc) => doc.querySelector("#agent-waiting a.more");

test("the agent page of the agent that asked links its rule change, and the change's card links that agent (real arbiter, anthropic-proxy, dashboard); no secret anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-agent-rule-change-"));
  const repo = join(tmp, "home", "proj");
  const blog = join(tmp, "home", "blog");
  mkdirSync(repo, { recursive: true });
  mkdirSync(blog, { recursive: true });
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
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    fileBrowserHome: join(tmp, "home"),
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const bodies: string[] = [];
  const read = async (path: string, headers: Record<string, string> = CSRF_ADMIN) => {
    const r = await pageFetch(`${base}${path}`, { headers });
    const text = await r.text();
    bodies.push(text);
    assert.equal(r.status, 200, `${path}: ${text}`);
    return JSON.parse(text);
  };
  const tools = [{ name: "Read", description: "read", input_schema: { type: "object" } }];
  const turn = async (session: string, messages: unknown[], sse: string) => {
    upstream = new MockUpstream({ sse });
    const r = await pageFetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "user-agent": "claude-cli/2.1.289 (external, cli)" },
      body: JSON.stringify({
        model: "claude-opus-4", stream: true, tools, messages,
        // Claude Code names its folder in its system prompt: A works in ~/proj, B in ~/blog.
        system: [{ type: "text", text: `You are Claude Code.\n\n# Environment\n - Primary working directory: ${session === A ? repo : blog}\n - Platform: linux` }],
      }),
    });
    assert.equal(r.status, 200, await r.text());
    toModel.push(upstream.requests[0]!.bodyText);
  };
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const rendered: string[] = [];
  try {
    // A reads .env (masked on its way to the model); B writes notes.
    const ask = { role: "user", content: "Read the env and tell me what it holds." };
    const read1 = { type: "tool_use", id: "toolu_arc_1", name: "Read", input: { file_path: env } };
    await turn(A, [ask], buildToolUseSse({ id: "toolu_arc_1", name: "Read", input: { file_path: env } }));
    await turn(A, [ask, { role: "assistant", content: [read1] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_arc_1", content: `DB_PASSWORD=${ENV_VALUE}\n` }] }], buildTextSse("It holds a password."));
    await turn(B, [{ role: "user", content: "Write the release notes" }], buildTextSse("Done: release notes"));
    for (const body of toModel) assert.ok(!body.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: the model got .env's value");

    // A's agent asks to let .env be sent to a host: it waits for you.
    const asked = await data.policyPropose({ edits: [{ op: "lock-path", path: env, level: "no-model", bindings: ["api.stripe.com"] }], sessionKey: A, reason: "deploy needs it" });
    assert.ok("proposalId" in asked && asked.proposalId, `the binding waits for the human: ${JSON.stringify(asked)}`);
    const id = String(asked.proposalId);

    // R1: the listing carries the session, signed in and signed out.
    assert.deepEqual((await read(PENDING)).proposals.map((p: { id: string; session: string }) => [p.id, p.session]), [[id, A]]);
    assert.deepEqual((await read(PENDING, {})).proposals.map((p: { id: string; session: string }) => [p.id, p.session]), [[id, A]], "signed out too, as the origins listing");

    // Both sessions are listed (emission is best-effort and asynchronous).
    for (let i = 0; i < 200; i++) {
      const [a, b] = await Promise.all([A, B].map(async (s) => (await (await pageFetch(`${base}/api/home/agent?session=${s}`, { headers: { Cookie: ADMIN_COOKIE } })).json()) as { found: boolean }));
      if (a!.found && b!.found) break;
      await new Promise((r) => setTimeout(r, 25));
    }

    await servedProductPage(base, "/approvals", (doc: Doc) => !!cardOf(doc, id)?.querySelector(".ask-from"), async (doc: Doc) => {
      const keep = () => rendered.push(doc.documentElement.outerHTML);
      // R2: the card names the agent and the folder of the session that asked.
      assert.equal(cardOf(doc, id).querySelector(".ask-sentence").textContent, "Claude Code wants to change a rule");
      const sub = cardOf(doc, id).querySelector(".ask-sub");
      assert.match(sub.textContent, / · from Claude Code in ~\/proj$/, "A's folder, not B's, with no period");
      assert.equal(sub.querySelector(".ask-from code").textContent, "~/proj", "the folder is code");
      assert.equal(doc.getElementById("approvals-proposals-head").textContent, "Rule changes your agent asked for", "the heading is unchanged");
      // R2: the card links the agent that asked.
      const to = cardOf(doc, id).querySelector("a.ask-link");
      assert.ok(to, "the card links the agent that asked");
      assert.equal(to.textContent, "See what the agent was doing");
      assert.equal(to.getAttribute("href"), `/agents/${A}`);
      keep();
      to.click();
      await waitWhile(() => doc.getElementById("page-agent").hidden || !agentLink(doc));
      assert.equal(doc.getElementById("page-agent").hidden, false, "A's page is open");
      assert.equal(doc.getElementById("agent-sub").textContent.startsWith("Read the env and tell me what it holds."), true, "the session that asked");
      assert.equal(doc.getElementById("agent-waiting-block").hidden, false, "Needs your OK shows");
      assert.equal(doc.querySelector("#agent-waiting .empty").textContent, NO_QUESTION);
      assert.equal(agentLink(doc).textContent, LINK);
      assert.equal(doc.querySelector("#agent-waiting button"), null, "no Allow on the agent page");
      keep();

      // R3: the link opens Approvals; Not now.
      agentLink(doc).click();
      await waitWhile(() => doc.getElementById("page-approvals").hidden || !cardOf(doc, id));
      button(cardOf(doc, id), "Not now").click();
      await waitWhile(() => !!cardOf(doc, id));
      assert.equal(cardOf(doc, id), undefined, "answered: its card is gone");
      keep();
    }, { headers: { Cookie: ADMIN_COOKIE } });
    assert.deepEqual((await read(PENDING)).proposals, [], "the server recorded the answer");

    // R3 (cont.) and R4: neither page shows a request now, and B's never did.
    for (const s of [A, B]) {
      await servedProductPage(base, `/agents/${s}`, (doc: Doc) => doc.getElementById("agent-name").textContent === "Claude Code", async (doc: Doc) => {
        await new Promise((r) => setTimeout(r, 100));
        assert.equal(doc.getElementById("agent-waiting-block").hidden, true, `${s}: no Needs your OK`);
        assert.equal(agentLink(doc), null, `${s}: no link`);
        rendered.push(doc.documentElement.outerHTML);
      }, { headers: { Cookie: ADMIN_COOKIE } });
    }
    // R4 while it waited: B's page, with A's request waiting again.
    const again = await data.policyPropose({ edits: [{ op: "lock-path", path: env, level: "no-model", bindings: ["api.github.com"] }], sessionKey: A, reason: "ci needs it" });
    assert.ok("proposalId" in again && again.proposalId, `the second binding waits too: ${JSON.stringify(again)}`);
    await servedProductPage(base, `/agents/${B}`, (doc: Doc) => doc.getElementById("agent-name").textContent === "Claude Code" && doc.getElementById("nav-approvals-count").textContent === "1", async (doc: Doc) => {
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(doc.getElementById("nav-approvals-count").hidden, false, "the badge counts A's request");
      assert.equal(doc.getElementById("agent-waiting-block").hidden, true, "B's page never shows A's request");
      assert.equal(agentLink(doc), null);
      rendered.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE } });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // R5: the oracle on every page drawn and every answer read above.
    assert.equal(rendered.length, 6);
    for (const text of [...rendered, ...bodies]) {
      assert.ok(!text.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: .env's value in a page or an answer");
      assert.doesNotMatch(text, /\$MDU/, "nor a token");
    }
    for (const body of toModel) assert.ok(!body.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: the model got .env's value");
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await proxy.close();
    await dashboard.close();
    data.close();
    human.close();
    wired?.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
