/**
 * proxy-view-map.test.ts — unit tests for the ViewMap wiring in the OpenAI
 * proxy (fs-sync.md §1.3, P4): response-side forward mapping over the
 * streamed function_call args, request-side reverse mapping, and the no-map
 * default relaying byte-verbatim.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { OpenAiProxy } from "../../src/proxy.js";
import { ViewMap } from "../../src/view-map.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildExecCommandSse } from "../helpers/mock-upstream.js";

const HUMAN = "/home/u/project/webapp";
const AGENT = "/home/u/.mandu/workspaces/wid/agentview";

function makeMap(): ViewMap {
  return new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix", home: "/home/u" });
}

function call(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/responses", headers: { "content-type": "application/json" } },
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

const TURN1 = JSON.stringify({
  model: "gpt-x", stream: true,
  input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "go" }] }],
});

test("response side: exec_command HumanView path is forward-mapped in the streamed args", async () => {
  const arbiter = new MockArbiter();
  const upstream = new MockUpstream({ sse: buildExecCommandSse({ cmd: `cat ${HUMAN}/notes.md`, argDeltas: 3 }), chunkInto: 4 });
  const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, viewMap: makeMap() });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN1);
    assert.equal(res.status, 200);
    assert.ok(res.body.includes(`${AGENT}/notes.md`), "client stream carries the AgentView path");
    assert.ok(!res.body.includes(HUMAN), "HumanView path must not reach the agent");
  } finally {
    await proxy.close();
  }
});

test("request side: echoed function_call args + trusted output reverse-map to HumanView", async () => {
  const arbiter = new MockArbiter({ trustedTools: ["exec_command"] });
  const upstream = new MockUpstream({ sse: "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"output\":[]}}\n\n" });
  const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, viewMap: makeMap() });
  const port = await proxy.listen(0);
  try {
    const body = JSON.stringify({
      model: "gpt-x", stream: true,
      input: [
        { type: "function_call", call_id: "c1", name: "exec_command", arguments: JSON.stringify({ cmd: `cat ${AGENT}/a` }) },
        { type: "function_call_output", call_id: "c1", output: `read ${AGENT}/a ok` },
      ],
    });
    const res = await call(port, body);
    assert.equal(res.status, 200);
    const forwarded = upstream.requests[0]!.bodyText;
    assert.ok(forwarded.includes(`cat ${HUMAN}/a`), "echoed command reverse-mapped");
    assert.ok(forwarded.includes(`read ${HUMAN}/a ok`), "trusted output reverse-mapped");
    assert.ok(!forwarded.includes(AGENT), "worktree path must never reach T-LLM");
  } finally {
    await proxy.close();
  }
});

test("response side (stream:false): non-streaming JSON function_call args are forward-mapped", async () => {
  const arbiter = new MockArbiter();
  const upstream = new MockUpstream({
    json: {
      id: "resp_1", object: "response",
      output: [
        { type: "function_call", call_id: "c1", name: "exec_command", arguments: JSON.stringify({ cmd: `cat ${HUMAN}/notes.md` }) },
        { type: "message", role: "assistant", content: [{ type: "output_text", text: "done" }] },
      ],
    },
  });
  const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, viewMap: makeMap() });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, JSON.stringify({ model: "gpt-x", stream: false, input: [] }));
    assert.equal(res.status, 200);
    const obj = JSON.parse(res.body) as { output: Array<{ type: string; arguments?: string }> };
    const fc = obj.output.find((o) => o.type === "function_call")!;
    assert.equal(fc.arguments, JSON.stringify({ cmd: `cat ${AGENT}/notes.md` }));
    assert.ok(!res.body.includes(HUMAN), "HumanView path must not reach the agent on the JSON path");
  } finally {
    await proxy.close();
  }
});

test("request side: a TRUSTED STRUCTURED function_call_output reverse-maps its text parts", async () => {
  const arbiter = new MockArbiter({ trustedTools: ["exec_command"] });
  const upstream = new MockUpstream({ sse: "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"output\":[]}}\n\n" });
  const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, viewMap: makeMap() });
  const port = await proxy.listen(0);
  try {
    const body = JSON.stringify({
      model: "gpt-x", stream: true,
      input: [
        // The structured-output variant (array of content parts), TRUSTED pass-through.
        { type: "function_call_output", call_id: "c1", output: [{ type: "output_text", text: `wrote ${AGENT}/a.txt` }] },
      ],
    });
    const res = await call(port, body);
    assert.equal(res.status, 200);
    const forwarded = upstream.requests[0]!.bodyText;
    assert.ok(forwarded.includes(`wrote ${HUMAN}/a.txt`), "structured output text reverse-mapped");
    assert.ok(!forwarded.includes(AGENT), "worktree path must never reach T-LLM");
  } finally {
    await proxy.close();
  }
});

test("no interceptor (no view map, exec gate off): the SSE response relays byte-verbatim", async () => {
  // Byte-verbatim requires BOTH interceptors off: the exec gate (default-on,
  // exec-routing.md §3) buffers+collapses function_call deltas to inspect the
  // assembled command even without a view map. With it off and no map, the
  // proxy touches nothing.
  const arbiter = new MockArbiter();
  const sse = buildExecCommandSse({ cmd: `cat ${HUMAN}/x` });
  const upstream = new MockUpstream({ sse });
  const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, execGate: false });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN1);
    assert.equal(res.body, sse); // untouched
  } finally {
    await proxy.close();
  }
});

test("exec gate on, no view map: a benign command is ALLOWED (reconstructed command unchanged)", async () => {
  // The exec gate is default-on and independent of the view map: a symbol-free
  // command is allowed, though the stream is no longer byte-verbatim (deltas are
  // buffered + re-emitted as one). The reconstructed command is unchanged.
  const arbiter = new MockArbiter();
  const sse = buildExecCommandSse({ cmd: `cat ${HUMAN}/x` });
  const upstream = new MockUpstream({ sse });
  const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN1);
    assert.match(res.body, new RegExp(`"cmd\\\\":\\\\"cat ${HUMAN.replace(/[/]/g, "\\/")}\\/x`));
    assert.equal(arbiter.execGateCalls.length, 1);
    assert.equal(arbiter.eventsOfKind("exec_action").length, 1);
  } finally {
    await proxy.close();
  }
});

// ── identity endpoint (start-or-reuse safety check) ───────────────────────────

function getIdentity(port: number): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method: "GET", path: "/_mandu/identity" }, (res) => {
      let buf = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (buf += c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
    });
    req.on("error", reject);
    req.end();
  });
}

test("GET /_mandu/identity reports the configured identity (reuse key)", async () => {
  const upstream = new MockUpstream({ json: {} });
  const proxy = new OpenAiProxy({
    arbiter: new MockArbiter(), upstream: upstream.fetcher, log: () => {},
    identity: { service: "openai-proxy", sessionKey: "sid-3", arbiterSock: "/run/b.sock", viewMap: [{ human: HUMAN, agent: AGENT }] },
  });
  const port = await proxy.listen(0);
  try {
    const res = await getIdentity(port);
    assert.equal(res.status, 200);
    const id = JSON.parse(res.body);
    assert.equal(id.mandu, true);
    assert.equal(id.service, "openai-proxy");
    assert.equal(id.arbiterSock, "/run/b.sock");
    assert.deepEqual(id.viewMap, [{ human: HUMAN, agent: AGENT }]);
    assert.equal(upstream.requests.length, 0); // never forwarded upstream
  } finally {
    await proxy.close();
  }
});

test("GET /_mandu/identity with no identity reports {mandu:false}", async () => {
  const proxy = new OpenAiProxy({ arbiter: new MockArbiter(), upstream: new MockUpstream({ json: {} }).fetcher, log: () => {} });
  const port = await proxy.listen(0);
  try {
    assert.equal(JSON.parse((await getIdentity(port)).body).mandu, false);
  } finally {
    await proxy.close();
  }
});
