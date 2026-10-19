/**
 * rule-change-home-paths — a rule change names a file under the dashboard's
 * home folder as `~/…`, as the Rules page names it (dashboard.md §4.34
 * "`~` is the dashboard's home"), across the REAL components. Mandu-new.
 *
 * Until 2026-10-15 the rule-change grammar (policy-proposals.ts `editRow`,
 * `relaxLine`) wrote every file as recorded: Approvals said "Make
 * `/home/alice/proj/.env` a secret no AI may read" beside a Rules row that
 * says `~/proj/.env`, and a session page's step "Asked Mandu to make
 * `/home/alice/…`". Here a real ArbiterServer runs at the `secrets` axes with
 * `.env` (under the home) and `other.env` (outside it) at `no-model`; the
 * REAL anthropic-proxy on its production client carries a session whose
 * agent calls Mandu's own rule tool (the REAL mandu-policy server over its
 * production adapter) to lock `deploy/staging.conf` (applied at once), then
 * asks to mark `.env` not secret and to remove `other.env`'s rule (waits). A
 * real DashboardServer, its home folder the temp home, reaches it over the
 * production adapter (`makeApprovalsArbiter`). (The agent's loosening also
 * asks to remove `notes.md`'s rule, under the home.)
 *
 *   H1  the listings: the waiting card's rows and what it would let, and the
 *       Rule changes row, say `~/proj/…` for the files under the home and
 *       the other file in full, signed in and signed out;
 *   H2  the served Approvals page (index.html and home.js in jsdom, signed
 *       in) draws those words, and names its Allow by them; Undo on the
 *       lock's row: the undo's row says "Loosened: ~/proj/…", on the page
 *       and in the listing; no rule-change row there spells the home folder
 *       out;
 *   H3  the served session page draws "Asked Mandu to make
 *       ~/proj/deploy/staging.conf a secret no AI may read";
 *   H4  no unhandled rejection; the oracle: no file's value reached the
 *       model, and no page or answer read here carries one or a token.
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

const ENV_VALUE = "ruleChangeHomeEnvValue000000000001";
const STAGING_VALUE = "ruleChangeHomeStagingValue00000002";
const OTHER_VALUE = "ruleChangeHomeOtherValue0000000003";
const NOTES_VALUE = "ruleChangeHomeNotesValue0000000004";
const VALUES = [ENV_VALUE, STAGING_VALUE, OTHER_VALUE, NOTES_VALUE];
const S = `rule-change-home-${process.pid}`;
const PROPOSE = "mcp__mandu-policy__mandu_policy_propose";
const PENDING = "/api/policy/proposals?status=pending";
const CHANGES = "/api/policy/changes";
const LOCKED = "Make ~/proj/deploy/staging.conf a secret no AI may read";
const UNDONE = "Loosened: ~/proj/deploy/staging.conf";
const ASKED = "Asked Mandu to make ~/proj/deploy/staging.conf a secret no AI may read";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
type Rows = Array<Array<{ kind: string; text: string }>>;
const said = (rows: Rows): string[] => rows.map((r) => r.map((p) => p.text).join(""));
const words = (el: Doc): string => String(el?.textContent ?? "").replace(/\s+/g, " ").trim();

async function callTool(deps: ServerDeps, name: string, args: Record<string, unknown>): Promise<string> {
  const r = await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }, deps);
  const res = r!.result as { content: Array<{ text: string }>; isError: boolean };
  assert.equal(res.isError, false, res.content[0]!.text);
  return res.content[0]!.text;
}

test("a rule change names a file under the dashboard's home as ~/…, as the Rules page does, on Approvals and the session page (real arbiter, anthropic-proxy, mandu-policy, dashboard); no secret anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rule-change-home-"));
  const home = join(tmp, "home");
  const repo = join(home, "proj");
  mkdirSync(join(repo, "deploy"), { recursive: true });
  const env = join(repo, ".env");
  writeFileSync(env, `DB_PASSWORD=${ENV_VALUE}\n`);
  const staging = join(repo, "deploy", "staging.conf");
  writeFileSync(staging, `token = ${STAGING_VALUE}\n`);
  const notes = join(repo, "notes.md");
  writeFileSync(notes, `${NOTES_VALUE}\n`);
  // Outside the home: always named in full.
  mkdirSync(join(tmp, "elsewhere"));
  const other = join(tmp, "elsewhere", "other.env");
  writeFileSync(other, `K=${OTHER_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n  - path: ${notes}\n    level: no-model\n  - path: ${other}\n    level: no-model\n`);
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
  // The mandu-policy server's production wiring (policy-mcp/src/server-main.ts).
  const policyClient = new ArbiterClient(socketPath);
  await policyClient.connect();
  const deps: ServerDeps = { arbiter: new PolicyArbiterAdapter(policyClient), sessionKey: S, projectDir: repo };
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
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
  const tools = [{ name: PROPOSE, description: "propose a rule change", input_schema: { type: "object" } }];
  const turn = async (messages: unknown[], sse: string) => {
    upstream = new MockUpstream({ sse });
    const r = await pageFetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": S, "user-agent": "claude-cli/2.1.289 (external, cli)" },
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
    // The agent locks staging.conf with Mandu's own rule tool: applied at once.
    const ask = { role: "user", content: "Use Mandu's policy tools to mark deploy/staging.conf as a secret hidden from you." };
    const lockArgs = { edits: [{ op: "lock-path", path: staging, level: "no-model" }], reason: "keep it from me" };
    const use = { type: "tool_use", id: "toolu_rch_1", name: PROPOSE, input: lockArgs };
    await turn([ask], buildToolUseSse({ id: "toolu_rch_1", name: PROPOSE, input: lockArgs }));
    const lock = await callTool(deps, "mandu_policy_propose", lockArgs);
    assert.equal((JSON.parse(lock) as { applied: boolean }).applied, true, `the lock only tightens: ${lock}`);
    await turn([ask, { role: "assistant", content: [use] }, { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_rch_1", content: lock }] }],
      buildTextSse("Locked deploy/staging.conf."));

    // Then it asks to loosen three rules: that waits for you.
    const relax = await callTool(deps, "mandu_policy_propose", { edits: [{ op: "lock-path", path: env, level: "public" }, { op: "unlock-path", path: notes }, { op: "unlock-path", path: other }], reason: "tests need them" });
    const proposalId = (JSON.parse(relax) as { proposalId?: string }).proposalId;
    assert.ok(proposalId, `the loosening waits for the human: ${relax}`);

    const ROWS = ["Mark ~/proj/.env not secret", "Remove the rule for ~/proj/notes.md", `Remove the rule for ${other}`];
    const LETS = ["~/proj/.env would be protected less", "~/proj/notes.md would be protected less", `${other} would be protected less`].sort();

    // H1: the listings, signed in and signed out.
    for (const headers of [CSRF_ADMIN, {}]) {
      const { proposals } = await read(PENDING, headers);
      assert.equal(proposals.length, 1);
      assert.deepEqual(said(proposals[0].rows), ROWS, JSON.stringify(headers));
      assert.deepEqual(said(proposals[0].wouldLet).sort(), LETS);
      const { changes } = await read(CHANGES, headers);
      const mine = changes.find((c: { sentence: string }) => c.sentence === "Your agent tightened your rules");
      assert.ok(mine, `the lock is listed: ${JSON.stringify(changes)}`);
      assert.deepEqual(said(mine.rows), [LOCKED]);
      assert.equal(mine.session, S, "the row links the agent that asked");
    }

    // The session is listed with its two turns (emission is best-effort and asynchronous).
    let asked = "";
    for (let i = 0; i < 200 && asked !== ASKED; i++) {
      const page = (await (await pageFetch(`${base}/api/home/agent?session=${S}`, { headers: { Cookie: ADMIN_COOKIE } })).json()) as {
        found: boolean; story?: Array<{ steps: Array<{ kind: string; sentence?: Array<{ text: string }> }> }>;
      };
      const step = (page.story ?? []).flatMap((t) => t.steps).find((s) => s.kind === "action" && s.sentence?.[0]?.text === "Asked Mandu to ");
      asked = step ? step.sentence!.map((p) => p.text).join("") : "";
      if (asked !== ASKED) await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(asked, ASKED, "the session page's step, from the recorded call");

    // H2: the served Approvals page.
    await servedProductPage(base, "/approvals", (doc: Doc) => !!doc.querySelector(`#approvals-proposals .proposal[data-id="${proposalId}"]`) && doc.querySelectorAll("#approvals-rule-history .row").length > 0, async (doc: Doc) => {
      const card = doc.querySelector(`#approvals-proposals .proposal[data-id="${proposalId}"]`);
      assert.deepEqual([...card.querySelectorAll(".proposal-rows li")].map(words), ROWS);
      assert.deepEqual([...card.querySelectorAll(".proposal-let li")].map(words).sort(), LETS);
      const allow = [...card.querySelectorAll("button")].find((b: Doc) => b.textContent === "Allow");
      assert.match(String(allow?.getAttribute("aria-label")), /^Allow: Mark ~\/proj\/\.env not secret, and 2 more/, "Allow is named by the words drawn");
      const rowOf = (sentence: string) => [...doc.querySelectorAll("#approvals-rule-history .row")].find((r: Doc) => words(r).includes(sentence));
      const history = rowOf("Your agent tightened your rules");
      assert.ok(history, "the lock's Rule changes row");
      assert.deepEqual([...history.querySelectorAll(".proposal-let li")].map(words), [LOCKED]);
      // Undo the lock: the undo's row names what it loosened.
      const undo = [...history.querySelectorAll("button")].find((b: Doc) => b.textContent === "Undo");
      assert.ok(undo, "the lock can be undone");
      undo.click();
      await waitWhile(() => !rowOf("You undid an earlier change"));
      assert.deepEqual([...rowOf("You undid an earlier change").querySelectorAll(".proposal-let li")].map(words), [UNDONE]);
      for (const part of [doc.getElementById("approvals-proposals"), doc.getElementById("approvals-rule-history")]) {
        assert.ok(!part.textContent.includes(`${home}/`), `no rule-change row spells the home folder out: ${words(part)}`);
      }
      rendered.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE } });
    for (const headers of [CSRF_ADMIN, {}]) {
      const { changes } = await read(CHANGES, headers);
      const undone = changes.find((c: { sentence: string }) => c.sentence === "You undid an earlier change");
      assert.ok(undone, `the undo is listed: ${JSON.stringify(changes)}`);
      assert.deepEqual(said(undone.rows), [UNDONE], JSON.stringify(headers));
    }

    // H3: the served session page.
    await servedProductPage(base, `/agents/${S}`, (doc: Doc) => [...doc.querySelectorAll("#agent-story [data-step-id] .what")].some((w: Doc) => words(w).startsWith("Asked Mandu to ")), async (doc: Doc) => {
      const step = [...doc.querySelectorAll("#agent-story [data-step-id] .what")].find((w: Doc) => words(w).startsWith("Asked Mandu to "));
      assert.ok(words(step).startsWith(ASKED), words(step));
      assert.deepEqual([...step.querySelectorAll("code")].map(words), ["~/proj/deploy/staging.conf"]);
      assert.ok(!words(step).includes(home), "the step does not spell the home folder out");
      rendered.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE } });

    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // H4: the oracle on every page drawn and every answer read above.
    assert.equal(rendered.length, 2);
    assert.ok(bodies.length >= 6);
    for (const text of [...rendered, ...bodies]) {
      for (const v of VALUES) assert.ok(!text.includes(v), "CONFIDENTIALITY VIOLATION: a file's value in a page or an answer");
      assert.doesNotMatch(text, /\$MDU/, "nor a token");
    }
    assert.equal(toModel.length, 2);
    for (const body of toModel) for (const v of VALUES) assert.ok(!body.includes(v), "CONFIDENTIALITY VIOLATION: the model got a file's value");
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
