/**
 * proposal-answer-line.test — an answer to a rule change says what it did,
 * with its Undo, across the REAL components (dashboard.md §4.25 *An answer
 * says what it did*). Mandu-new.
 *
 * Until 2026-10-25 Allow on the card "Claude Code wants to change a rule"
 * just took the card away: when it was the last one, *Rule changes your
 * agent asked for* hid, nothing said to tell the agent it may go on, and
 * the Undo of the change made sat at the bottom of Approvals. Here a real
 * ArbiterServer runs at the `secrets` axes with `.env` at `no-model` in
 * policy.yaml. A Claude Code session is on record (the REAL anthropic-proxy
 * on its production client carries its turn), and its agent calls the REAL
 * mandu-policy server (its `tools/call` over the production wiring,
 * `new PolicyArbiterAdapter(new ArbiterClient(sock))`) to let `.env` be sent
 * to api.stripe.com, which waits for you. A real DashboardServer reaches
 * the arbiter over the production adapter (`makeApprovalsArbiter`), and the
 * served product page (its own index.html and home.js in jsdom, signed in)
 * draws:
 *
 *   P1  Allow on the card: where it was, "Allowed: Claude Code's rule
 *       change: Make ~/proj/.env a secret no AI may read, may be sent to
 *       api.stripe.com. It is in force now. Tell Claude Code it may go on.
 *       Undo it" (the card's own words), a status with the focus, the
 *       block still shown; the arbiter's law binds the host;
 *   P2  Undo it opens `/approvals/<pc-…>` with that change's row marked,
 *       and its Undo restores the rule;
 *   P3  a second request, answered Not now: "Not now: … Your rules stay as
 *       they are.", no link; the law is unchanged;
 *   P4  the session ends (its launcher's REAL `session_exit`), and a
 *       third request it made says on its card "The agent that asked has
 *       ended, so nothing is waiting on this now." (a question's words,
 *       §4.34 *After you answer*); Allow leaves "… It is in force now.
 *       Undo it", with no "Tell Claude Code it may go on." (2026-11-02:
 *       no agent waits to go on);
 *   P5  no unhandled rejection; the oracle: `.env`'s value never reached
 *       the model, and no line, page or `/api/policy/proposals` read carries
 *       it or a token.
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
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { PolicyArbiterAdapter } from "../../interceptors/policy-mcp/src/arbiter-client.js";
import { handleRpc, type ServerDeps } from "../../interceptors/policy-mcp/src/mcp-server.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { emitLauncherEvent, sessionExitEvent } from "../../launcher/src/services/observe.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const ENV_VALUE = "proposalAnswerLineStackEnvValue00001";
const A = `proposal-answer-line-${process.pid}`;
const PENDING = "/api/policy/proposals?status=pending";
const ALLOWED = "Allowed: Claude Code's rule change: Make ~/proj/.env a secret no AI may read, may be sent to api.stripe.com. It is in force now. Tell Claude Code it may go on. Undo it";
const ENDED_ALLOWED = "Allowed: Claude Code's rule change: Make ~/proj/.env a secret no AI may read, may be sent to api.example.com. It is in force now. Undo it";
const ENDED = "The agent that asked has ended, so nothing is waiting on this now.";
const NOT_NOW = "Not now: Claude Code's rule change: Make ~/proj/.env a secret no AI may read, may be sent to api.github.com. Your rules stay as they are.";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const cardOf = (doc: Doc, id: string) => [...doc.querySelectorAll("#approvals-proposals .proposal")].find((c: Doc) => c.dataset.id === id);
const button = (root: Doc, label: string) => root && [...root.querySelectorAll("button")].find((b: Doc) => b.textContent === label);
const lineOf = (doc: Doc) => doc.querySelector("#approvals-proposals > .answer-line");
const marked = (doc: Doc) => [...doc.querySelectorAll("#page-approvals .focus")].map((x: Doc) => x.dataset.id);
const words = (x: Doc) => String(x.textContent).replace(/\s+/g, " ").trim();
/** Enter on a button: it has the focus, the click answers, and the browser
 *  drops the focus of the button the answer turned off to <body>. */
function press(btn: Doc): void {
  assert.ok(btn, "the button is there");
  btn.focus();
  btn.click();
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
}

test("Allow and Not now on a rule change leave a line that says what you chose; Allow's Undo it opens the change made, whose Undo restores the rule; a change from a session that has ended says so and tells no one to go on (real arbiter, policy server, anthropic-proxy, dashboard); no secret anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-proposal-answer-line-"));
  const home = join(tmp, "home");
  const repo = join(home, "proj");
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
    fileBrowserHome: home,
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const bodies: string[] = [];
  const read = async (path: string) => {
    const r = await pageFetch(`${base}${path}`, { headers: CSRF_ADMIN });
    const text = await r.text();
    bodies.push(text);
    assert.equal(r.status, 200, `${path}: ${text}`);
    return JSON.parse(text);
  };
  const propose = async (bindings: string[], reason: string) => {
    const r = await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "mandu_policy_propose", arguments: { edits: [{ op: "lock-path", path: env, level: "no-model", bindings }], reason } } }, deps);
    const res = r!.result as { content: Array<{ text: string }>; isError: boolean };
    assert.equal(res.isError, false, res.content[0]!.text);
    const id = String((JSON.parse(res.content[0]!.text) as { proposalId?: unknown }).proposalId);
    assert.match(id, /^pp-\d{6}$/, `the binding waits for you: ${res.content[0]!.text}`);
    return id;
  };
  const bound = async () => (await human.pathLevel(env)).bindings;
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const rendered: string[] = [];
  try {
    // The session is on record as Claude Code's, in ~/proj.
    upstream = new MockUpstream({ sse: buildTextSse("I need to send the key to Stripe.") });
    const r = await pageFetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": A, "user-agent": "claude-cli/2.1.289 (external, cli)" },
      body: JSON.stringify({
        model: "claude-opus-4", stream: true, messages: [{ role: "user", content: "Set up the Stripe deploy." }],
        system: [{ type: "text", text: `You are Claude Code.\n\n# Environment\n - Primary working directory: ${repo}\n - Platform: linux` }],
      }),
    });
    assert.equal(r.status, 200, await r.text());
    toModel.push(upstream.requests[0]!.bodyText);
    for (let i = 0; i < 200; i++) {
      const page = (await (await pageFetch(`${base}/api/home/agent?session=${A}`, { headers: { Cookie: ADMIN_COOKIE } })).json()) as { found: boolean };
      if (page.found) break;
      await new Promise((res) => setTimeout(res, 25));
    }
    const first = await propose(["api.stripe.com"], "the deploy sends it to Stripe");
    assert.deepEqual(await bound(), [], "nothing is bound before you answer");

    await servedProductPage(base, "/approvals", (doc: Doc) => cardOf(doc, first)?.querySelector(".ask-sentence")?.textContent === "Claude Code wants to change a rule", async (doc: Doc) => {
      // P1: Allow; the line where the card was.
      press(button(cardOf(doc, first), "Allow"));
      await waitWhile(() => lineOf(doc) === null, 20_000);
      assert.equal(cardOf(doc, first), undefined, "the card went");
      assert.equal(words(lineOf(doc)), ALLOWED);
      assert.equal(lineOf(doc).getAttribute("role"), "status");
      assert.equal(doc.activeElement, lineOf(doc), "the line has the focus");
      assert.equal(doc.getElementById("approvals-proposals-block").hidden, false, "the block stays shown under its line");
      assert.ok(!words(lineOf(doc)).includes("the deploy sends it"), "never the agent's reason");
      rendered.push(doc.documentElement.outerHTML);
      assert.deepEqual(await bound(), ["api.stripe.com"], "the arbiter's law binds the host");

      // P2: Undo it opens the change made, marked, and its Undo restores the rule.
      const undo = lineOf(doc).querySelector("a");
      assert.equal(undo.textContent, "Undo it");
      const changeId = String(undo.dataset.ask);
      assert.match(changeId, /^pc-\d{6}$/);
      assert.equal(undo.getAttribute("href"), `/approvals/${changeId}`);
      undo.click();
      await waitWhile(() => !marked(doc).includes(changeId), 20_000);
      assert.equal(doc.defaultView.location.pathname, `/approvals/${changeId}`);
      assert.deepEqual(marked(doc), [changeId], "the change's row, marked");
      const row = doc.querySelector("#approvals-rule-history .row.focus");
      assert.equal(row.dataset.id, changeId);
      assert.equal(lineOf(doc), null, "the line went with the visit");
      rendered.push(doc.documentElement.outerHTML);
      button(row, "Undo").click();
      await waitWhile(() => !!button(doc.querySelector(`#approvals-rule-history .row[data-id="${changeId}"]`), "Undo"), 20_000);
      assert.deepEqual(await bound(), [], "Undo restored the rule");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // P3: a second request, answered Not now.
    const second = await propose(["api.github.com"], "ci needs it");
    await servedProductPage(base, "/approvals", (doc: Doc) => cardOf(doc, second)?.querySelector(".ask-sentence")?.textContent === "Claude Code wants to change a rule", async (doc: Doc) => {
      press(button(cardOf(doc, second), "Not now"));
      await waitWhile(() => lineOf(doc) === null, 20_000);
      assert.equal(words(lineOf(doc)), NOT_NOW);
      assert.equal(lineOf(doc).querySelector("a"), null, "no link");
      assert.equal(doc.getElementById("approvals-proposals-block").hidden, false);
      rendered.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE } });
    assert.deepEqual((await read(PENDING)).proposals, [], "the server recorded both answers");
    assert.deepEqual(await bound(), [], "Not now left the law as it was");

    // P4: the session ends; a change it asked for says so, and Allow tells no one to go on.
    const third = await propose(["api.example.com"], "the example deploy");
    assert.ok(await emitLauncherEvent(socketPath, sessionExitEvent({ scopeId: A, code: 0, durationMs: 4_000 }), humanPath), "the launcher's emit lands");
    await servedProductPage(base, "/approvals", (doc: Doc) => !!cardOf(doc, third)?.querySelector(".ask-ended"), async (doc: Doc) => {
      const card = cardOf(doc, third);
      assert.equal(card.querySelector(".ask-sentence").textContent, "Claude Code wants to change a rule");
      assert.equal(card.querySelector(".ask-ended").textContent.trim(), ENDED);
      const sub = words(card.querySelector(".ask-sub"));
      assert.ok(sub.endsWith(`· from Claude Code in ~/proj. ${ENDED}`), sub);
      press(button(card, "Allow"));
      await waitWhile(() => lineOf(doc) === null, 20_000);
      assert.equal(words(lineOf(doc)), ENDED_ALLOWED);
      assert.ok(!words(lineOf(doc)).includes("Tell"), "no agent waits to go on");
      rendered.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE } });
    assert.deepEqual(await bound(), ["api.example.com"], "the arbiter's law binds the host");
    await new Promise((res) => setTimeout(res, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // P5: the oracle on every page drawn and every answer read.
    bodies.push(await (await pageFetch(`${base}${PENDING}`)).text());
    bodies.push(await (await pageFetch(`${base}/api/policy/proposals?status=approved`, { headers: CSRF_ADMIN })).text());
    assert.equal(rendered.length, 4);
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
