/**
 * proxy-view-map.test.ts — unit tests for the ViewMap wiring in the proxy
 * (fs-sync.md §1.3, P2): response-side forward mapping (SSE + buffered
 * JSON), request-side reverse mapping (tool_result content + echoed tool_use
 * args), and the sniffer/recordToolCall seeing the rewritten form.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { AnthropicProxy } from "../../src/proxy.js";
import { ViewMap } from "../../src/view-map.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildToolUseSse } from "../helpers/mock-upstream.js";

const HUMAN = "/home/u/project/webapp";
const AGENT = "/home/u/.mandu/workspaces/wid/agentview";

function makeMap(): ViewMap {
  return new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix", home: "/home/u" });
}

interface ClientResult {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function call(port: number, method: string, path: string, body?: string): Promise<ClientResult> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method, path, headers: { "content-type": "application/json" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: buf }));
      },
    );
    req.on("error", reject);
    if (body != null) req.write(body);
    req.end();
  });
}

async function withProxy<T>(
  arbiter: MockArbiter,
  upstream: MockUpstream,
  fn: (port: number) => Promise<T>,
): Promise<T> {
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, viewMap: makeMap() });
  const port = await proxy.listen(0);
  try {
    return await fn(port);
  } finally {
    await proxy.close();
  }
}

test("SSE response: model-emitted HumanView Read is forward-mapped; sniffer records the AgentView form", async () => {
  const arbiter = new MockArbiter();
  const upstream = new MockUpstream({
    sse: buildToolUseSse({
      id: "tu_r",
      name: "Read",
      input: { file_path: `${HUMAN}/vendor/notes.txt` },
      inputDeltas: 3,
    }),
    chunkInto: 5,
  });
  await withProxy(arbiter, upstream, async (port) => {
    const res = await call(
      port,
      "POST",
      "/v1/messages",
      JSON.stringify({ model: "m", stream: true, messages: [{ role: "user", content: "go" }] }),
    );
    assert.equal(res.status, 200);
    // The client sees the AgentView path, never the HumanView one, in ONE delta.
    assert.ok(res.body.includes(AGENT), "client stream must carry the AgentView path");
    assert.ok(!res.body.includes(HUMAN), "HumanView path must not reach the agent");
    // recordToolCall (OS-interceptor correlation) got the AS-DELIVERED input.
    assert.equal(arbiter.recordedToolCalls.length, 1);
    assert.deepEqual(arbiter.recordedToolCalls[0].input, {
      file_path: `${AGENT}/vendor/notes.txt`,
    });
  });
});

test("buffered JSON response: tool_use input forward-mapped, body re-serialized consistently", async () => {
  const arbiter = new MockArbiter();
  const upstream = new MockUpstream({
    json: {
      id: "msg_1",
      type: "message",
      role: "assistant",
      content: [
        { type: "text", text: `reading ${HUMAN}/a.md now` }, // prose is NOT rewritten
        { type: "tool_use", id: "tu_j", name: "Read", input: { file_path: `${HUMAN}/a.md` } },
      ],
    },
  });
  await withProxy(arbiter, upstream, async (port) => {
    const res = await call(
      port,
      "POST",
      "/v1/messages",
      JSON.stringify({ model: "m", stream: false, messages: [{ role: "user", content: "go" }] }),
    );
    assert.equal(res.status, 200);
    const body = JSON.parse(res.body) as {
      content: Array<{ type: string; text?: string; input?: Record<string, unknown> }>;
    };
    assert.equal(body.content[0].text, `reading ${HUMAN}/a.md now`); // mention untouched
    assert.deepEqual(body.content[1].input, { file_path: `${AGENT}/a.md` });
    assert.deepEqual(arbiter.recordedToolCalls[0].input, { file_path: `${AGENT}/a.md` });
  });
});

test("request side: TRUSTED tool_result error text naming the worktree reverse-maps to HumanView", async () => {
  const arbiter = new MockArbiter({ trustedTools: ["Read"] });
  const upstream = new MockUpstream({
    sse: buildToolUseSse({ id: "tu_2", name: "Bash", input: { command: "true" } }),
  });
  await withProxy(arbiter, upstream, async (port) => {
    const res = await call(
      port,
      "POST",
      "/v1/messages",
      JSON.stringify({
        model: "m",
        stream: true,
        messages: [
          { role: "user", content: "read it" },
          {
            role: "assistant",
            // The client echoes the FORWARD-mapped form it received (AgentView).
            content: [
              { type: "tool_use", id: "tu_1", name: "Read", input: { file_path: `${AGENT}/gone.txt` } },
            ],
          },
          {
            role: "user",
            content: [
              {
                type: "tool_result",
                tool_use_id: "tu_1",
                is_error: true,
                content: `ENOENT: no such file or directory, open '${AGENT}/gone.txt'`,
              },
            ],
          },
        ],
      }),
    );
    assert.equal(res.status, 200);
    const forwarded = upstream.requests[0].bodyText;
    // T-LLM sees HumanView paths only: the error text AND the echoed tool_use.
    assert.ok(forwarded.includes(`${HUMAN}/gone.txt`), "reverse-mapped path expected");
    assert.ok(!forwarded.includes(AGENT), "the worktree path must never reach T-LLM");
  });
});

test("request side: UNTRUSTED tool_result still symbolizes; the symbol table keeps the raw original", async () => {
  const arbiter = new MockArbiter(); // fail-closed: everything UNTRUSTED
  const upstream = new MockUpstream({
    sse: buildToolUseSse({ id: "tu_3", name: "Bash", input: { command: "true" } }),
  });
  const rawContent = `injected! see ${AGENT}/evil.txt`;
  await withProxy(arbiter, upstream, async (port) => {
    const res = await call(
      port,
      "POST",
      "/v1/messages",
      JSON.stringify({
        model: "m",
        stream: true,
        messages: [
          { role: "user", content: "go" },
          {
            role: "assistant",
            content: [{ type: "tool_use", id: "tu_1", name: "Read", input: { file_path: `${AGENT}/evil.txt` } }],
          },
          {
            role: "user",
            content: [{ type: "tool_result", tool_use_id: "tu_1", content: rawContent }],
          },
        ],
      }),
    );
    assert.equal(res.status, 200);
    const forwarded = upstream.requests[0].bodyText;
    // Symbolization wins: content replaced by the opaque token (raw text gone),
    // and the arbiter's table holds the ORIGINAL (pre-reverse-map) bytes.
    assert.ok(!forwarded.includes("injected!"));
    const symbol = arbiter.symbolFor("Read", rawContent);
    assert.ok(symbol, "symbol minted for the RAW original value");
    assert.ok(forwarded.includes(symbol!));
    // The echoed tool_use arg still reverse-maps (it is not tool_result content).
    assert.ok(forwarded.includes(`${HUMAN}/evil.txt`));
    assert.ok(!forwarded.includes(AGENT), "worktree path must not survive anywhere");
  });
});

test("no view map: response bytes relay verbatim (content-length preserved)", async () => {
  const arbiter = new MockArbiter();
  const upstream = new MockUpstream({
    json: {
      content: [{ type: "tool_use", id: "t", name: "Read", input: { file_path: `${HUMAN}/x` } }],
    },
  });
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const res = await call(
      port,
      "POST",
      "/v1/messages",
      JSON.stringify({ model: "m", stream: false, messages: [{ role: "user", content: "go" }] }),
    );
    const body = JSON.parse(res.body) as { content: Array<{ input: Record<string, unknown> }> };
    assert.deepEqual(body.content[0].input, { file_path: `${HUMAN}/x` }); // untouched
  } finally {
    await proxy.close();
  }
});

// ── identity endpoint (start-or-reuse safety check) ───────────────────────────

test("GET /_mandu/identity reports the configured identity (reuse key)", async () => {
  const arbiter = new MockArbiter();
  const upstream = new MockUpstream({ json: {} });
  const proxy = new AnthropicProxy({
    arbiter, upstream: upstream.fetcher, log: () => {},
    identity: {
      service: "anthropic-proxy", sessionKey: "sid-9", arbiterSock: "/run/a.sock",
      viewMap: [{ human: HUMAN, agent: AGENT }],
    },
  });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, "GET", "/_mandu/identity");
    assert.equal(res.status, 200);
    const id = JSON.parse(res.body);
    assert.equal(id.mandu, true);
    assert.equal(id.service, "anthropic-proxy");
    assert.equal(id.arbiterSock, "/run/a.sock");
    assert.deepEqual(id.viewMap, [{ human: HUMAN, agent: AGENT }]);
    // The identity path is NEVER forwarded upstream.
    assert.equal(upstream.requests.length, 0);
  } finally {
    await proxy.close();
  }
});

test("GET /_mandu/identity on a proxy with no identity reports {mandu:false}", async () => {
  const proxy = new AnthropicProxy({ arbiter: new MockArbiter(), upstream: new MockUpstream({ json: {} }).fetcher, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, "GET", "/_mandu/identity");
    assert.equal(JSON.parse(res.body).mandu, false);
  } finally {
    await proxy.close();
  }
});

test("forward map emits a path_rewrite event: human→agent spelling, per changed field", async () => {
  const arbiter = new MockArbiter();
  const upstream = new MockUpstream({
    sse: buildToolUseSse({
      id: "tu_pr",
      name: "Read",
      input: { file_path: `${HUMAN}/vendor/notes.txt` },
      inputDeltas: 2,
    }),
  });
  await withProxy(arbiter, upstream, async (port) => {
    const res = await call(
      port,
      "POST",
      "/v1/messages",
      JSON.stringify({ model: "m", stream: true, messages: [{ role: "user", content: "go" }] }),
    );
    assert.equal(res.status, 200);
    const rewrites = arbiter.emittedEvents.filter((e) => e.kind === "path_rewrite");
    assert.equal(rewrites.length, 1);
    const ev = rewrites[0] as typeof rewrites[0] & {
      rewrite: { direction: string; tool: string | null; field: string | null; human: string; agent: string };
    };
    assert.equal(ev.callId, "tu_pr");
    assert.deepEqual(ev.rewrite, {
      direction: "forward",
      tool: "Read",
      field: "file_path",
      human: `${HUMAN}/vendor/notes.txt`,
      agent: `${AGENT}/vendor/notes.txt`,
    });
    // Generic DualRepr rendering carries both spellings (in → out).
    assert.ok(ev.input?.symbolized.includes(HUMAN));
    assert.ok(ev.output?.symbolized.includes(AGENT));
  });
});

test("reverse map emits path_rewrite events: echoed tool_use field + tool_result content roots", async () => {
  const arbiter = new MockArbiter({ trustedTools: ["Read"] });
  const upstream = new MockUpstream({
    sse: buildToolUseSse({ id: "tu_x", name: "Bash", input: { command: "true" } }),
  });
  await withProxy(arbiter, upstream, async (port) => {
    const res = await call(
      port,
      "POST",
      "/v1/messages",
      JSON.stringify({
        model: "m",
        stream: true,
        messages: [
          { role: "user", content: "read it" },
          {
            role: "assistant",
            content: [
              { type: "tool_use", id: "tu_1", name: "Read", input: { file_path: `${AGENT}/gone.txt` } },
            ],
          },
          {
            role: "user",
            content: [
              {
                type: "tool_result",
                tool_use_id: "tu_1",
                is_error: true,
                content: `ENOENT: no such file or directory, open '${AGENT}/gone.txt'`,
              },
            ],
          },
        ],
      }),
    );
    assert.equal(res.status, 200);
    const rewrites = arbiter.emittedEvents
      .filter((e) => e.kind === "path_rewrite")
      .map((e) => (e as unknown as { rewrite: Record<string, unknown>; callId: string | null }));
    // One for the echoed tool_use field (full spellings), one for the
    // tool_result free text (root-pair granularity).
    const fieldEv = rewrites.find((e) => e.rewrite.field === "file_path");
    const textEv = rewrites.find((e) => e.rewrite.field === "content");
    assert.ok(fieldEv, "echoed tool_use field rewrite must be reported");
    assert.deepEqual(fieldEv.rewrite, {
      direction: "reverse",
      tool: "Read",
      field: "file_path",
      human: `${HUMAN}/gone.txt`,
      agent: `${AGENT}/gone.txt`,
    });
    assert.equal(fieldEv.callId, "tu_1");
    assert.ok(textEv, "tool_result content rewrite must be reported");
    assert.deepEqual(textEv.rewrite, {
      direction: "reverse",
      tool: null,
      field: "content",
      human: HUMAN,
      agent: AGENT,
    });
    assert.equal(textEv.callId, "tu_1");
  });
});
