/**
 * row-control-names.test — a control that every row of a list repeats says
 * which row it belongs to, across the REAL components (dashboard.md §4.25
 * *Details, Undo and the agent link name their row*). Mandu-new.
 *
 * Until 2026-10-12 Home drew one link named "Details" per agent row, and
 * Approvals › *Rule changes* one "Undo" and one "See what the agent was
 * doing" per row, in rows two of which shared a sentence ("Your agent
 * tightened your rules"). Here a real ArbiterServer runs at the `secrets`
 * axes with `.env` at `no-model` in policy.yaml; the REAL anthropic-proxy
 * on its production client carries three sessions (A reads `.env`, B writes
 * notes, C renames a key). Over the data socket A's agent locks `id_rsa`
 * and B's agent locks `deploy.pem` (two tightenings, made at once, one
 * sentence), and A's agent asks to let `.env` be sent to a host, which you
 * approve over the dashboard's route. A real DashboardServer reaches the
 * arbiter over the production adapter (`makeApprovalsArbiter`), and the
 * served product page (its own index.html and home.js in jsdom, signed in)
 * draws:
 *
 *   N1  Home: each agent's Details still reads "Details", is named by the
 *       agent and its own prompt, and no two share a name;
 *   N2  Approvals › Rule changes: the two tightenings are still both named
 *       "Your agent tightened your rules", while each one's Undo and link
 *       name its own file, the approved change's name `.env` and the host;
 *       no two Undo, and no two links, share a name;
 *   N3  the Undo named for `deploy.pem` undoes B's change and nothing else
 *       (read back from the listing);
 *   N4  no unhandled rejection; the oracle: `.env`'s value never reached the
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

const ENV_VALUE = "rowControlNamesStackEnvValue000001";
const A = `row-names-a-${process.pid}`;
const B = `row-names-b-${process.pid}`;
const C = `row-names-c-${process.pid}`;
const PROMPTS: Record<string, string> = { [A]: "Read the env and tell me what it holds.", [B]: "Write the release notes", [C]: "Rename the config key" };
const CHANGES = "/api/policy/changes?limit=20";
const LINK = "See what the agent was doing";
const TIGHTENED = "Your agent tightened your rules";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const rowOf = (doc: Doc, id: string) => [...doc.querySelectorAll("#approvals-rule-history .row")].find((r: Doc) => r.dataset.id === id);
const undoOf = (doc: Doc, id: string) => rowOf(doc, id)?.querySelector("button") ?? null;
const linkOf = (doc: Doc, id: string) => rowOf(doc, id)?.querySelector("a.ask-link") ?? null;
const groupName = (doc: Doc, row: Doc) => doc.getElementById(row.getAttribute("aria-labelledby"))?.textContent;
const details = (doc: Doc) => [...doc.querySelectorAll("#home-agents a, #home-earlier a")].filter((a: Doc) => a.textContent === "Details");
const unique = (names: string[], what: string) => assert.equal(new Set(names).size, names.length, `${what}: no two share a name (${JSON.stringify(names)})`);

test("Home's Details and Approvals' Undo and agent link are named by their row (real arbiter, anthropic-proxy, dashboard); no secret anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-row-control-names-"));
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
    // A reads .env (masked on its way to the model); B and C only talk.
    const ask = { role: "user", content: PROMPTS[A] };
    const read1 = { type: "tool_use", id: "toolu_rcn_1", name: "Read", input: { file_path: env } };
    await turn(A, [ask], buildToolUseSse({ id: "toolu_rcn_1", name: "Read", input: { file_path: env } }));
    await turn(A, [ask, { role: "assistant", content: [read1] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_rcn_1", content: `DB_PASSWORD=${ENV_VALUE}\n` }] }], buildTextSse("It holds a password."));
    await turn(B, [{ role: "user", content: PROMPTS[B] }], buildTextSse("Done: release notes"));
    await turn(C, [{ role: "user", content: PROMPTS[C] }], buildTextSse("Done: config key"));
    for (const body of toModel) assert.ok(!body.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: the model got .env's value");

    // A's and B's agents each lock a key file: two tightenings, one sentence.
    const tightA = await data.policyPropose({ edits: [{ op: "lock-path", path: join(repo, "id_rsa"), level: "no-model" }], sessionKey: A });
    assert.ok("applied" in tightA && tightA.applied && tightA.changeId, `A's tightening is made: ${JSON.stringify(tightA)}`);
    const tightB = await data.policyPropose({ edits: [{ op: "lock-path", path: join(repo, "deploy.pem"), level: "no-model" }], sessionKey: B });
    assert.ok("applied" in tightB && tightB.applied && tightB.changeId, `B's tightening is made: ${JSON.stringify(tightB)}`);
    // A's agent asks to let .env be sent to a host: you approve it.
    const asked = await data.policyPropose({ edits: [{ op: "lock-path", path: env, level: "no-model", bindings: ["api.stripe.com"] }], sessionKey: A, reason: "deploy needs it" });
    assert.ok("proposalId" in asked && asked.proposalId, `the binding waits for the human: ${JSON.stringify(asked)}`);
    const approved = await call(`/api/policy/proposals/${asked.proposalId}`, { method: "POST", body: JSON.stringify({ verdict: "approved" }), headers: { ...CSRF_ADMIN, "content-type": "application/json" } });
    const ids = { a: String(tightA.changeId), b: String(tightB.changeId), approved: String(approved.changeId) };
    assert.match(ids.approved, /^pc-\d{6}$/, `approved: ${JSON.stringify(approved)}`);

    // The three sessions are listed (emission is best-effort and asynchronous).
    for (let i = 0; i < 200; i++) {
      const home = (await (await pageFetch(`${base}/api/home`, { headers: { Cookie: ADMIN_COOKIE } })).json()) as { agents: Array<{ id: string }> };
      if ([A, B, C].every((s) => home.agents.some((a) => a.id === s))) break;
      await new Promise((r) => setTimeout(r, 25));
    }

    // N1: Home's Details, one per agent, each named by its agent and prompt.
    await servedProductPage(base, "/", (doc: Doc) => details(doc).length >= 3, (doc: Doc) => {
      const names = new Map(details(doc).map((a: Doc) => [a.dataset.session, a.getAttribute("aria-label")]));
      for (const s of [A, B, C]) {
        assert.equal(names.get(s), `Details: Claude Code, ${PROMPTS[s]}`, `${s}: named by its agent and its prompt`);
      }
      for (const a of details(doc)) assert.equal(a.textContent, "Details", "the eye still reads Details");
      unique(details(doc).map((a: Doc) => a.getAttribute("aria-label")), "Home's Details");
      rendered.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // N2 and N3: Approvals' Rule changes, then the Undo named for deploy.pem.
    await servedProductPage(base, "/approvals", (doc: Doc) => !!rowOf(doc, ids.approved), async (doc: Doc) => {
      assert.equal(groupName(doc, rowOf(doc, ids.a)), TIGHTENED);
      assert.equal(groupName(doc, rowOf(doc, ids.b)), TIGHTENED, "two rows, one sentence: the rows' names stay alike");
      for (const [id, file] of [[ids.a, "id_rsa"], [ids.b, "deploy.pem"]] as const) {
        const undo = undoOf(doc, id);
        assert.equal(undo.textContent, "Undo");
        assert.match(undo.getAttribute("aria-label"), new RegExp(`^Undo: Make \\S*/proj/${file.replace(".", "\\.")} a secret no AI may read$`), `${id}: Undo names ${file}`);
        assert.equal(linkOf(doc, id).getAttribute("aria-label"), LINK + undo.getAttribute("aria-label").slice("Undo".length), `${id}: the link names it too`);
      }
      const bound = linkOf(doc, ids.approved).getAttribute("aria-label");
      assert.ok(bound.startsWith(LINK + ": Make ") && bound.includes("/proj/.env") && bound.includes("api.stripe.com"), `the approved change names .env and its host: ${bound}`);
      const host = doc.getElementById("approvals-rule-history");
      unique([...host.querySelectorAll("button")].map((b: Doc) => b.getAttribute("aria-label")), "Undo");
      unique([...host.querySelectorAll("a.ask-link")].map((a: Doc) => a.getAttribute("aria-label")), "the agent links");
      rendered.push(doc.documentElement.outerHTML);
      // N3: the Undo named for deploy.pem undoes B's change, and only it.
      const undo = [...host.querySelectorAll("button")].find((b: Doc) => /deploy\.pem/.test(b.getAttribute("aria-label")));
      assert.equal(undo, undoOf(doc, ids.b));
      undo.click();
      await waitWhile(() => !/Undone/.test(rowOf(doc, ids.b)?.textContent ?? ""));
      rendered.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE } });
    const after = (await call(CHANGES)) as { changes: Array<{ id: string; undone: boolean }> };
    const undoneIds = after.changes.filter((c) => c.undone).map((c) => c.id);
    assert.deepEqual(undoneIds, [ids.b], "B's tightening alone is undone");
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // N4: the oracle on every page drawn and every answer read above.
    assert.equal(rendered.length, 3);
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
