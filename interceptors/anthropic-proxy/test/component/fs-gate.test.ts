/**
 * fs-gate.test.ts (e2e) — the P3 sensitive-path gate through the REAL proxy
 * data path (fs-sync.md §1.4.1): a model-emitted Read of ~/.ssh/id_rsa
 * is denied on the wire (rewritten into /mandu/denied/…) while a workspace
 * read in the SAME response flows through the P2 forward map untouched; an
 * unreachable arbiter fails closed to the same sentinel; the JSON
 * (non-streaming) path enforces identically.
 *
 * Run: npm run test:component
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { AnthropicProxy } from "../../src/proxy.js";
import { ViewMap } from "../../src/view-map.js";
import { DENIED_NAMESPACE } from "../../src/fs-gate.js";
import { SseToolUseParser, type ReconstructedToolUse } from "../../src/sse-parser.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildToolUseSse } from "../helpers/mock-upstream.js";

const HUMAN = "/home/u/project/webapp";
const AGENT = "/home/u/.mandu/workspaces/wid/agentview";
const SSH_KEY = "/home/u/.ssh/id_rsa";

function makeMap(): ViewMap {
  return new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix", home: "/home/u" });
}

function call(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function toolUsesOf(sseBody: string): ReconstructedToolUse[] {
  const seen: ReconstructedToolUse[] = [];
  const p = new SseToolUseParser((tu) => seen.push(tu));
  p.feed(sseBody);
  p.end();
  return seen;
}

const TURN = JSON.stringify({
  model: "claude-opus-4",
  stream: true,
  messages: [{ role: "user", content: "read the key and the notes" }],
});

test("P3 e2e: sensitive Read is denied on the wire; the workspace Read in the same response flows", async () => {
  // Deny like the default mock, plus the queue row a real arbiter stamps on a
  // queued deny (policy-surface.md §9.5) — asserted on the event below.
  const arbiter = new MockArbiter({
    fsPathDecisionFn: (req) =>
      req.workspaceRoots.some((r) => req.path.startsWith(r + "/"))
        ? { allow: true, reason: "inside workspace root" }
        : {
            allow: false, requiresApproval: true, reason: "out-of-workspace (fail closed)",
            ruleRef: { source: "fail-closed", id: "fs:default-deny" },
            approvalId: "egr-7",
          },
  });
  const upstream = new MockUpstream({
    sse:
      buildToolUseSse({ id: "tu_ws", name: "Read", input: { file_path: `${HUMAN}/notes.md` }, index: 0 }) +
      buildToolUseSse({ id: "tu_ssh", name: "Read", input: { file_path: SSH_KEY }, index: 1 }),
    chunkInto: 6,
  });
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, viewMap: makeMap() });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN);
    assert.equal(res.status, 200);
    const tus = toolUsesOf(res.body);
    assert.equal(tus.length, 2);

    // The workspace read: forward-mapped (P2), NOT gated.
    assert.deepEqual(tus[0].input, { file_path: `${AGENT}/notes.md` });
    // The sensitive read: DENIED — the agent receives only the sentinel, which
    // fails at execution (nothing exists under /mandu).
    const sentinel = `${DENIED_NAMESPACE}/policy${SSH_KEY}`;
    assert.deepEqual(tus[1].input, { file_path: sentinel });

    // recordToolCall carries the AS-DELIVERED form for both.
    const recorded = arbiter.recordedToolCalls.map((r) => (r.input as { file_path: string }).file_path);
    assert.deepEqual(recorded.sort(), [`${AGENT}/notes.md`, sentinel].sort());

    // The gate submits EVERY absolute path to the arbiter — the workspace path
    // included, so rule-1 deny-precedence stays reachable — and does so on the
    // REQUESTED (HumanView) spelling, so the arbiter's HumanView sensitive list
    // can match. The workspace read is allowed (then forward-mapped for
    // delivery); the sensitive read is denied. One fs_action narrates it.
    assert.equal(arbiter.fsPathDecisionCalls.length, 2);
    const gatedPaths = arbiter.fsPathDecisionCalls.map((c) => c.path).sort();
    assert.deepEqual(gatedPaths, [`${HUMAN}/notes.md`, SSH_KEY].sort());
    const fsEvents = arbiter.eventsOfKind("fs_action");
    assert.equal(fsEvents.length, 1);
    assert.equal(fsEvents[0].callId, "tu_ssh");
    assert.equal(fsEvents[0].policy?.usage, "needs_approval");
    assert.match(String(fsEvents[0].output?.symbolized ?? ""), /DENIED/);
    // Decision provenance + the Pending-tab join key ride the event.
    assert.deepEqual(fsEvents[0].policy?.ruleRef, { source: "fail-closed", id: "fs:default-deny" });
    assert.equal(fsEvents[0].policy?.approvalId, "egr-7");
  } finally {
    await proxy.close();
  }
});

test("P3 e2e: a sensitive path INSIDE the workspace root is still gated (deny-precedence)", async () => {
  // Regression: a workspace rooted at $HOME (a dotfiles repo) must NOT let the
  // agent read ~/.ssh just because it is nested under the workspace root. The
  // proxy submits the REQUESTED HumanView path to the arbiter, whose rule 1
  // denies it. AgentView state lives OUTSIDE home here (a non-nested pair, so
  // the map is active), matching the finding's stated exploit precondition.
  const HOME_HUMAN = "/home/u";
  const HOME_AGENT = "/srv/view-state/wid/agentview";
  const homeMap = new ViewMap([{ human: HOME_HUMAN, agent: HOME_AGENT }], { dialect: "posix", home: "/home/u" });
  const arbiter = new MockArbiter({
    fsPathDecisionFn: (req) =>
      req.path.startsWith("/home/u/.ssh")
        ? { allow: false, requiresApproval: true, reason: "sensitive (~/.ssh) requires approval" }
        : { allow: true, reason: "inside workspace root" },
  });
  const upstream = new MockUpstream({
    sse: buildToolUseSse({ id: "tu_ssh", name: "Read", input: { file_path: SSH_KEY } }),
  });
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, viewMap: homeMap });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN);
    assert.equal(res.status, 200);
    const tus = toolUsesOf(res.body);
    // Denied even though /home/u/.ssh/id_rsa is inside the /home/u workspace root.
    assert.deepEqual(tus[0].input, { file_path: `${DENIED_NAMESPACE}/policy${SSH_KEY}` });
    assert.ok(arbiter.fsPathDecisionCalls.some((c) => c.path === SSH_KEY), "the in-workspace sensitive path reached the arbiter");
  } finally {
    await proxy.close();
  }
});

test("P3 e2e: arbiter unreachable fails CLOSED — the unreachable sentinel, never the raw path", async () => {
  const arbiter = new MockArbiter({ failFsPathDecision: true });
  const upstream = new MockUpstream({
    sse: buildToolUseSse({ id: "tu_ssh", name: "Read", input: { file_path: SSH_KEY } }),
  });
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, viewMap: makeMap() });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN);
    assert.equal(res.status, 200);
    const tus = toolUsesOf(res.body);
    assert.deepEqual(tus[0].input, { file_path: `${DENIED_NAMESPACE}/unreachable${SSH_KEY}` });
  } finally {
    await proxy.close();
  }
});

test("P3 e2e: the buffered-JSON response path enforces identically", async () => {
  const arbiter = new MockArbiter();
  const upstream = new MockUpstream({
    json: {
      id: "msg_1",
      type: "message",
      role: "assistant",
      content: [
        { type: "tool_use", id: "tu_ssh", name: "Read", input: { file_path: SSH_KEY } },
      ],
    },
  });
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, viewMap: makeMap() });
  const port = await proxy.listen(0);
  try {
    const res = await call(
      port,
      JSON.stringify({ model: "m", stream: false, messages: [{ role: "user", content: "go" }] }),
    );
    assert.equal(res.status, 200);
    const body = JSON.parse(res.body) as { content: Array<{ input: Record<string, unknown> }> };
    assert.deepEqual(body.content[0].input, { file_path: `${DENIED_NAMESPACE}/policy${SSH_KEY}` });
  } finally {
    await proxy.close();
  }
});
