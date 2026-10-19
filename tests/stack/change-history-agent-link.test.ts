/**
 * change-history-agent-link.test — a row of Approvals › *Rule changes* that
 * your agent made, or asked for and you approved, links the agent that did
 * it, across the REAL components (dashboard.md §4.25 *A rule change and the
 * agent that asked*). Mandu-new.
 *
 * Until 2026-10-12 the history's projection dropped the change's session,
 * so "Your agent tightened your rules" and "You approved a change your
 * agent asked for" led nowhere, while the Rules origin line, an *Answered
 * earlier* row and the waiting request's card each link the agent. Here a
 * real ArbiterServer runs at the `secrets` axes with `.env` at `no-model`
 * in policy.yaml; the REAL anthropic-proxy on its production client carries
 * two sessions (A reads `.env`, B writes notes). Over the data socket, A's
 * agent locks a key file (a tightening, made at once), B's agent locks
 * another, and A's agent asks to let `.env` be sent to a host, which you
 * approve over the dashboard's route; then you undo B's tightening. A real
 * DashboardServer reaches the arbiter over the production adapter
 * (`makeApprovalsArbiter`), and the served product page (its own index.html
 * and home.js in jsdom, signed in) draws:
 *
 *   R1  the listing: each agent's change carries its own session, yours
 *       and the Undo none, signed in and signed out;
 *   R2  Approvals: each agent's row ends its moment's line with "See what
 *       the agent was doing", addressed to that agent's page; the Undo row
 *       has no link; each row is still named by its sentence;
 *   R3  a click on A's tightening opens A's page (the session that read
 *       `.env`), and the one on B's row opens B's;
 *   R4  no unhandled rejection; the oracle: `.env`'s value never reached the
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

const ENV_VALUE = "changeHistoryAgentStackEnvValue00001";
const A = `change-history-a-${process.pid}`;
const B = `change-history-b-${process.pid}`;
const CHANGES = "/api/policy/changes?limit=20";
const LINK = "See what the agent was doing";
const TIGHTENED = "Your agent tightened your rules";
const APPROVED = "You approved a change your agent asked for";
const UNDID = "You undid an earlier change";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const rowOf = (doc: Doc, id: string) => [...doc.querySelectorAll("#approvals-rule-history .row")].find((r: Doc) => r.dataset.id === id);
const linkOf = (doc: Doc, id: string) => rowOf(doc, id)?.querySelector("a.ask-link") ?? null;
const nameOf = (doc: Doc, row: Doc) => doc.getElementById(row.getAttribute("aria-labelledby"))?.textContent;

test("a rule change your agent made or asked for links that agent in Approvals' history (real arbiter, anthropic-proxy, dashboard); no secret anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-change-history-agent-"));
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
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const bodies: string[] = [];
  const call = async (path: string, init: { method?: string; body?: string; headers?: Record<string, string> } = {}) => {
    const r = await pageFetch(`${base}${path}`, { headers: CSRF_ADMIN, ...init });
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
      body: JSON.stringify({ model: "claude-opus-4", stream: true, system: "You are Claude Code.", tools, messages }),
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
    const read1 = { type: "tool_use", id: "toolu_cha_1", name: "Read", input: { file_path: env } };
    await turn(A, [ask], buildToolUseSse({ id: "toolu_cha_1", name: "Read", input: { file_path: env } }));
    await turn(A, [ask, { role: "assistant", content: [read1] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_cha_1", content: `DB_PASSWORD=${ENV_VALUE}\n` }] }], buildTextSse("It holds a password."));
    await turn(B, [{ role: "user", content: "Write the release notes" }], buildTextSse("Done: release notes"));
    for (const body of toModel) assert.ok(!body.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: the model got .env's value");

    // A's and B's agents each lock a key file: tightenings, made at once.
    const tightA = await data.policyPropose({ edits: [{ op: "lock-path", path: join(repo, "id_rsa"), level: "no-model" }], sessionKey: A });
    assert.ok("applied" in tightA && tightA.applied && tightA.changeId, `A's tightening is made: ${JSON.stringify(tightA)}`);
    const tightB = await data.policyPropose({ edits: [{ op: "lock-path", path: join(repo, "deploy.pem"), level: "no-model" }], sessionKey: B });
    assert.ok("applied" in tightB && tightB.applied && tightB.changeId, `B's tightening is made: ${JSON.stringify(tightB)}`);
    // A's agent asks to let .env be sent to a host: you approve it.
    const asked = await data.policyPropose({ edits: [{ op: "lock-path", path: env, level: "no-model", bindings: ["api.stripe.com"] }], sessionKey: A, reason: "deploy needs it" });
    assert.ok("proposalId" in asked && asked.proposalId, `the binding waits for the human: ${JSON.stringify(asked)}`);
    const approved = await call(`/api/policy/proposals/${asked.proposalId}`, { method: "POST", body: JSON.stringify({ verdict: "approved" }), headers: { ...CSRF_ADMIN, "content-type": "application/json" } });
    const approvedId = String(approved.changeId);
    assert.match(approvedId, /^pc-\d{6}$/, `approved: ${JSON.stringify(approved)}`);
    // You undo B's tightening.
    const undone = await call(`/api/policy/changes/${tightB.changeId}/undo`, { method: "POST" });
    const undoId = String(undone.changeId);
    const ids = { tightA: String(tightA.changeId), tightB: String(tightB.changeId), approved: approvedId, undo: undoId };

    // R1: each change carries its own agent's session, signed in and out.
    const want = [[undoId, UNDID, null], [approvedId, APPROVED, A], [ids.tightB, TIGHTENED, B], [ids.tightA, TIGHTENED, A]];
    const listed = (r: { changes: Array<{ id: string; sentence: string; session: string | null }> }) => r.changes.map((c) => [c.id, c.sentence, c.session]);
    assert.deepEqual(listed(await call(CHANGES)), want);
    assert.deepEqual(listed(await call(CHANGES, { headers: {} })), want, "signed out too, as the origins listing");

    // Both sessions are listed (emission is best-effort and asynchronous).
    for (let i = 0; i < 200; i++) {
      const [a, b] = await Promise.all([A, B].map(async (s) => (await (await pageFetch(`${base}/api/home/agent?session=${s}`, { headers: { Cookie: ADMIN_COOKIE } })).json()) as { found: boolean }));
      if (a!.found && b!.found) break;
      await new Promise((r) => setTimeout(r, 25));
    }

    // R2 and R3, for each agent's row: the link, and its click.
    for (const [id, session, prompt] of [[ids.tightA, A, "Read the env and tell me what it holds."], [ids.tightB, B, "Write the release notes"], [approvedId, A, "Read the env"]] as const) {
      await servedProductPage(base, "/approvals", (doc: Doc) => !!rowOf(doc, undoId), async (doc: Doc) => {
        // R2: every row as the listing says.
        for (const [rid, sentence, s] of want as Array<[string, string, string | null]>) {
          const row = rowOf(doc, rid);
          assert.equal(nameOf(doc, row), sentence, `${rid}: named by its sentence`);
          const a = linkOf(doc, rid);
          if (s === null) { assert.equal(a, null, `${rid}: no link`); continue; }
          assert.equal(a.textContent, LINK);
          assert.equal(a.getAttribute("href"), `/agents/${s}`, `${rid}: the page of the agent that did it`);
          assert.ok(row.querySelector(".answered-when").contains(a), `${rid}: on the moment's line`);
        }
        rendered.push(doc.documentElement.outerHTML);
        // R3: the click opens that agent's page.
        linkOf(doc, id).click();
        await waitWhile(() => doc.getElementById("page-agent").hidden || !doc.getElementById("agent-sub").textContent);
        assert.equal(doc.getElementById("page-agent").hidden, false, `${id}: the agent's page is open`);
        assert.equal(doc.getElementById("agent-sub").textContent.startsWith(prompt), true, `${id}: the session of ${session}`);
        rendered.push(doc.documentElement.outerHTML);
      }, { headers: { Cookie: ADMIN_COOKIE } });
    }
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // R4: the oracle on every page drawn and every answer read above.
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
