/**
 * rule-change-link.test — a link to a rule change opens Approvals at that
 * change, marked, across the REAL components (dashboard.md §4.25 *Details*,
 * §4.25b *Mandu's own tools*). Mandu-new.
 *
 * Until 2026-10-20 the session page's note under the agent's call to
 * Mandu's propose tool named the place ("You can undo it under Rule changes
 * in Approvals.") without linking it, and `/approvals/<pc-…>` read as "That
 * question is no longer waiting for you.". Here a real ArbiterServer runs at
 * the `secrets` axes with `.env` at `no-model` in policy.yaml. The agent of
 * session A calls the REAL mandu-policy server (its `tools/call` over the
 * production wiring, `new PolicyArbiterAdapter(new ArbiterClient(sock))`)
 * twice: a tightening (made at once) and a loosening (held for you). The
 * REAL anthropic-proxy on its production client carries the turns, so the
 * calls and their answers are recorded as in a live session. A real
 * DashboardServer reaches the arbiter over the production adapter
 * (`makeApprovalsArbiter`), and the served product page (its own index.html
 * and home.js in jsdom, signed in) draws:
 *
 *   L1  the session page: the tightening's note "… You can undo it in
 *       Approvals." links `/approvals/<changeId>`, the loosening's "…
 *       Mandu asked for your OK in Approvals." links `/approvals/<proposalId>`,
 *       each id the one the arbiter returned;
 *   L2  following the first marks that change's row under Rule changes, no
 *       note; following the second marks the waiting request's card;
 *   L3  approved over the dashboard's route, the request's address marks
 *       the change it made, and the note says it was already answered;
 *   L4  no unhandled rejection; the oracle: `.env`'s value never reached the
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
import { PolicyArbiterAdapter } from "../../interceptors/policy-mcp/src/arbiter-client.js";
import { handleRpc, type ServerDeps } from "../../interceptors/policy-mcp/src/mcp-server.js";
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

const ENV_VALUE = "ruleChangeLinkStackEnvValue000000001";
const A = `rule-change-link-${process.pid}`;
const PROPOSE = "mcp__mandu-policy__mandu_policy_propose";
const UNDO_NOTE = "Mandu applied it at once, because it only adds protection. You can undo it in Approvals.";
const HELD_NOTE = "Not applied: it would loosen protection, so Mandu asked for your OK in Approvals.";
const ANSWERED = "That rule change was already answered. The change it made is marked below, under Rule changes.";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
type Part = { kind: string; text: string; ask?: string };
type Step = { kind: string; note?: string | null; noteParts?: Part[] };
const marked = (doc: Doc) => [...doc.querySelectorAll("#page-approvals .focus")].map((x: Doc) => x.dataset.id);
const noteLink = (doc: Doc, words: string) => {
  const note = [...doc.querySelectorAll("#agent-story .note")].find((n: Doc) => n.textContent === words);
  return note ? note.querySelector("a") : null;
};

test("the session page links the change its agent made and the request it filed; each opens Approvals at it, marked (real arbiter, policy server, anthropic-proxy, dashboard); no secret anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rule-change-link-"));
  const repo = join(tmp, "home", "proj");
  mkdirSync(repo, { recursive: true });
  const env = join(repo, ".env");
  writeFileSync(env, `DB_PASSWORD=${ENV_VALUE}\n`);
  writeFileSync(join(repo, "id_rsa"), "FAKE KEY FOR THE TEST\n");
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
  // The policy server's production wiring (policy-mcp/src/server-main.ts).
  const policyClient = new ArbiterClient(socketPath);
  await policyClient.connect();
  const deps: ServerDeps = { arbiter: new PolicyArbiterAdapter(policyClient), sessionKey: A, projectDir: repo };
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
  const tools = [{ name: PROPOSE, description: "propose a rule change", input_schema: { type: "object" } }];
  const turn = async (messages: unknown[], sse: string) => {
    upstream = new MockUpstream({ sse });
    const r = await pageFetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": A, "user-agent": "claude-cli/2.1.289 (external, cli)" },
      body: JSON.stringify({ model: "claude-opus-4", stream: true, system: "You are Claude Code.", tools, messages }),
    });
    assert.equal(r.status, 200, await r.text());
    toModel.push(upstream.requests[0]!.bodyText);
  };
  const propose = async (args: Record<string, unknown>) => {
    const r = await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "mandu_policy_propose", arguments: args } }, deps);
    const res = r!.result as { content: Array<{ text: string }>; isError: boolean };
    assert.equal(res.isError, false, res.content[0]!.text);
    return res.content[0]!.text;
  };
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const rendered: string[] = [];
  try {
    // The agent locks a key file (a tightening), then asks to reach a host
    // (a loosening), each through the real policy server.
    const ask = { role: "user", content: "Lock the deploy key, then let pip reach pypi.org." };
    const lockArgs = { edits: [{ op: "lock-path", path: join(repo, "id_rsa"), level: "no-model" }], reason: "keep the key away" };
    const relaxArgs = { edits: [{ op: "allow-connect", host: "pypi.org", port: 443 }], reason: "pip" };
    const use1 = { type: "tool_use", id: "toolu_rcl_1", name: PROPOSE, input: lockArgs };
    const use2 = { type: "tool_use", id: "toolu_rcl_2", name: PROPOSE, input: relaxArgs };
    await turn([ask], buildToolUseSse({ id: "toolu_rcl_1", name: PROPOSE, input: lockArgs }));
    const locked = await propose(lockArgs);
    const changeId = String((JSON.parse(locked) as { changeId?: unknown }).changeId);
    assert.match(changeId, /^pc-\d{6}$/, `the tightening is made: ${locked}`);
    const history = [ask, { role: "assistant", content: [use1] }, { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_rcl_1", content: locked }] }];
    await turn(history, buildToolUseSse({ id: "toolu_rcl_2", name: PROPOSE, input: relaxArgs }));
    const held = await propose(relaxArgs);
    const proposalId = String((JSON.parse(held) as { proposalId?: unknown }).proposalId);
    assert.match(proposalId, /^pp-\d{6}$/, `the loosening waits for you: ${held}`);
    await turn([...history, { role: "assistant", content: [use2] }, { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_rcl_2", content: held }] }], buildTextSse("Locked the key; pypi.org waits for your OK."));
    for (const body of toModel) assert.ok(!body.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: the model got .env's value");

    // L1: the story's two notes, from the recorded answers (emission is
    // best-effort and asynchronous: wait for both).
    let steps: Step[] = [];
    for (let i = 0; i < 200; i++) {
      const page = (await (await pageFetch(`${base}/api/home/agent?session=${A}`, { headers: { Cookie: ADMIN_COOKIE } })).json()) as { found: boolean; story?: Array<{ steps: Step[] }> };
      steps = page.found ? (page.story ?? []).flatMap((t) => t.steps).filter((s) => s.kind === "action" && !!s.noteParts) : [];
      if (steps.length >= 2) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    const links = steps.map((s) => [s.note, (s.noteParts ?? []).filter((p) => p.ask).map((p) => [p.text, p.ask])]);
    assert.deepEqual(links, [[UNDO_NOTE, [["Approvals", changeId]]], [HELD_NOTE, [["Approvals", proposalId]]]]);

    // L1 drawn, and L2: each link opens Approvals at what it names.
    for (const [words, id, sel] of [[UNDO_NOTE, changeId, "#approvals-rule-history .row"], [HELD_NOTE, proposalId, "#approvals-proposals .proposal"]] as const) {
      await servedProductPage(base, `/agents/${A}`, (doc: Doc) => !!noteLink(doc, words), async (doc: Doc) => {
        const a = noteLink(doc, words);
        assert.equal(a.textContent, "Approvals");
        assert.equal(a.getAttribute("href"), `/approvals/${id}`);
        rendered.push(doc.documentElement.outerHTML);
        a.click();
        await waitWhile(() => !marked(doc).includes(id));
        assert.equal(doc.getElementById("page-approvals").hidden, false, `${id}: Approvals is open`);
        assert.equal(doc.defaultView.location.pathname, `/approvals/${id}`);
        assert.deepEqual(marked(doc), [id], `${id}: exactly what the link names`);
        assert.ok(doc.querySelector(`${sel}.focus`), `${id}: in its list`);
        assert.equal(doc.getElementById("approvals-focus-note").hidden, true, `${id}: no note`);
        rendered.push(doc.documentElement.outerHTML);
      }, { headers: { Cookie: ADMIN_COOKIE } });
    }

    // L3: you allow the request; its address now marks the change it made.
    const approved = await call(`/api/policy/proposals/${proposalId}`, { method: "POST", body: JSON.stringify({ verdict: "approved" }), headers: { ...CSRF_ADMIN, "content-type": "application/json" } });
    const madeId = String(approved.changeId);
    assert.match(madeId, /^pc-\d{6}$/, `approved: ${JSON.stringify(approved)}`);
    const listed = await call("/api/policy/changes?limit=21");
    assert.equal(listed.changes.find((c: { id: string }) => c.id === madeId)?.proposalId, proposalId, "the listing names the request a change answered");
    await servedProductPage(base, `/approvals/${proposalId}`, (doc: Doc) => marked(doc).length > 0, (doc: Doc) => {
      assert.deepEqual(marked(doc), [madeId], "the change the request made");
      assert.ok(doc.querySelector("#approvals-rule-history .row.focus"));
      const note = doc.getElementById("approvals-focus-note");
      assert.equal(note.hidden, false);
      assert.equal(note.textContent, ANSWERED);
      rendered.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE } });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // L4: the oracle on every page drawn and every answer read above.
    assert.equal(rendered.length, 5);
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
    policyClient.close();
    wired?.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
