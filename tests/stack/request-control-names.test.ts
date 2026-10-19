/**
 * request-control-names.test — the controls on a card of a rule change
 * your agent asked for say which request they answer, across the REAL
 * components (dashboard.md §4.25 *Details, Undo and the agent link name
 * their row*). Mandu-new.
 *
 * Every request of your agent has one headline, "Your agent wants to
 * change a rule". Until 2026-10-12 two waiting requests drew two buttons
 * named "Allow", two named "Not now" and two links named "See what the
 * agent was doing", in two groups of one name. Here a real ArbiterServer
 * runs at the `secrets` axes with `.env` at `no-model` in policy.yaml; the
 * REAL anthropic-proxy on its production client carries two sessions (A
 * reads `.env`, B writes notes). Over the data socket A's agent asks to let
 * `.env` be sent to api.stripe.com, giving a reason, and B's agent asks to
 * let it be sent to api.github.com: two requests that wait for you. A real
 * DashboardServer reaches the arbiter over the production adapter
 * (`makeApprovalsArbiter`), and the served product page (its own
 * index.html and home.js in jsdom, signed in) draws Approvals:
 *
 *   Q1  both cards are still groups named "Your agent wants to change a
 *       rule"; each card's Allow, Not now and link still read their words,
 *       are named by its own request (`.env` and its host), each link to
 *       its own agent; no two answers and no two links share a name;
 *   Q2  no name carries the reason A's agent gave (drawn on its card);
 *   Q3  the Allow named for api.github.com approves B's request and
 *       nothing else: A's request still waits, and the one change recorded
 *       is B's (read back from the listings);
 *   Q4  no unhandled rejection; the oracle: `.env`'s value never reached
 *       the model, and no page or answer read here carries it or a token.
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

const ENV_VALUE = "requestControlNamesStackEnvValue01";
const REASON = "TRUSTME the deploy needs it";
const A = `request-names-a-${process.pid}`;
const B = `request-names-b-${process.pid}`;
const PENDING = "/api/policy/proposals?status=pending";
const CHANGES = "/api/policy/changes?limit=20";
const LINK = "See what the agent was doing";
const HEADLINE = "Your agent wants to change a rule";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const cardOf = (doc: Doc, id: string) => [...doc.querySelectorAll("#approvals-proposals .proposal")].find((c: Doc) => c.dataset.id === id);
const buttonOf = (doc: Doc, id: string, words: string) => [...(cardOf(doc, id)?.querySelectorAll("button") ?? [])].find((b: Doc) => b.textContent === words) ?? null;
const linkOf = (doc: Doc, id: string) => cardOf(doc, id)?.querySelector("a.ask-link") ?? null;
const groupName = (doc: Doc, card: Doc) => doc.getElementById(card.getAttribute("aria-labelledby"))?.textContent;
const unique = (names: string[], what: string) => assert.equal(new Set(names).size, names.length, `${what}: no two share a name (${JSON.stringify(names)})`);

test("Approvals: each waiting request's Allow, Not now and agent link are named by that request (real arbiter, anthropic-proxy, dashboard); no secret anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-request-control-names-"));
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
  const call = async (path: string) => {
    const r = await pageFetch(`${base}${path}`, { headers: CSRF_ADMIN });
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
    // A reads .env (masked on its way to the model); B only talks.
    const ask = { role: "user", content: "Read the env and tell me what it holds." };
    const read1 = { type: "tool_use", id: "toolu_qcn_1", name: "Read", input: { file_path: env } };
    await turn(A, [ask], buildToolUseSse({ id: "toolu_qcn_1", name: "Read", input: { file_path: env } }));
    await turn(A, [ask, { role: "assistant", content: [read1] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_qcn_1", content: `DB_PASSWORD=${ENV_VALUE}\n` }] }], buildTextSse("It holds a password."));
    await turn(B, [{ role: "user", content: "Write the release notes" }], buildTextSse("Done: release notes"));
    for (const body of toModel) assert.ok(!body.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: the model got .env's value");

    // Two agents each ask to let .env go to a host: two requests that wait.
    const askA = await data.policyPropose({ edits: [{ op: "lock-path", path: env, level: "no-model", bindings: ["api.stripe.com"] }], sessionKey: A, reason: REASON });
    assert.ok("proposalId" in askA && askA.proposalId, `A's request waits for the human: ${JSON.stringify(askA)}`);
    const askB = await data.policyPropose({ edits: [{ op: "lock-path", path: env, level: "no-model", bindings: ["api.github.com"] }], sessionKey: B });
    assert.ok("proposalId" in askB && askB.proposalId, `B's request waits for the human: ${JSON.stringify(askB)}`);
    const ids = { a: String(askA.proposalId), b: String(askB.proposalId) };
    const waiting = (await call(PENDING)) as { proposals: Array<{ id: string; headline: string }> };
    assert.deepEqual(waiting.proposals.map((p) => p.id).sort(), [ids.a, ids.b].sort(), "both wait");
    for (const p of waiting.proposals) assert.equal(p.headline, HEADLINE, "one headline for both");

    await servedProductPage(base, "/approvals", (doc: Doc) => !!cardOf(doc, ids.a) && !!cardOf(doc, ids.b), async (doc: Doc) => {
      // Q1: alike groups; each control named by its own request.
      for (const [id, host, session] of [[ids.a, "api.stripe.com", A], [ids.b, "api.github.com", B]] as const) {
        const card = cardOf(doc, id);
        assert.equal(groupName(doc, card), HEADLINE, `${id}: the group is still named by the headline`);
        const name = String(buttonOf(doc, id, "Allow").getAttribute("aria-label"));
        assert.match(name, /^Allow: /, `${id}: Allow is named by its request`);
        const about = name.slice("Allow: ".length);
        assert.ok(about.includes("/proj/.env") && about.includes(host), `${id}: named by .env and ${host}: ${about}`);
        assert.equal(about, card.querySelector(".proposal-rows li").textContent.replace(/\s+/g, " ").trim(), `${id}: the card's own first line`);
        assert.equal(buttonOf(doc, id, "Not now").getAttribute("aria-label"), `Not now: ${about}`);
        const a = linkOf(doc, id);
        assert.equal(a.textContent, LINK);
        assert.equal(a.getAttribute("aria-label"), `${LINK}: ${about}`);
        assert.equal(a.dataset.session, session, `${id}: links its own agent`);
      }
      const host = doc.getElementById("approvals-proposals");
      unique([...host.querySelectorAll("button")].map((b: Doc) => b.getAttribute("aria-label")), "the answers");
      unique([...host.querySelectorAll("a.ask-link")].map((a: Doc) => a.getAttribute("aria-label")), "the agent links");
      // Q2: the reason is drawn, never a name.
      assert.match(cardOf(doc, ids.a).textContent, /TRUSTME/, "A's reason is on its card");
      for (const x of host.querySelectorAll("[aria-label]")) assert.doesNotMatch(x.getAttribute("aria-label"), /TRUSTME/, "the reason is never a name");
      rendered.push(doc.documentElement.outerHTML);
      // Q3: the Allow named for api.github.com answers B's request.
      const allow = [...host.querySelectorAll("button")].find((b: Doc) => /^Allow: .*api\.github\.com/.test(b.getAttribute("aria-label")));
      assert.equal(allow, buttonOf(doc, ids.b, "Allow"));
      allow.click();
      await waitWhile(() => !!cardOf(doc, ids.b));
      assert.ok(cardOf(doc, ids.a), "A's request is still drawn");
      rendered.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE } });
    const still = (await call(PENDING)) as { proposals: Array<{ id: string }> };
    assert.deepEqual(still.proposals.map((p) => p.id), [ids.a], "A's request alone still waits");
    const changes = (await call(CHANGES)) as { changes: Array<{ id: string; sentence: string; rows: Array<Array<{ text: string }>> }> };
    assert.equal(changes.changes.length, 1, `one change recorded: ${JSON.stringify(changes.changes.map((c) => c.sentence))}`);
    const words = JSON.stringify(changes.changes[0]!.rows);
    assert.ok(words.includes("api.github.com") && !words.includes("api.stripe.com"), `the change is B's: ${words}`);
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // Q4: the oracle on every page drawn and every answer read above.
    assert.equal(rendered.length, 2);
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
