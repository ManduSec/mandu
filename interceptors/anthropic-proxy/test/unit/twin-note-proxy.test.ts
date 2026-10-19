/**
 * twin-note-proxy.test.ts — the symbol-twin shell note through the REAL proxy
 * (symbol-twin-shell-blindness.md §4.4/§4.6): a view map with real temp roots,
 * the forwarded upstream body carrying `<symbol>\n\n[mandu:twin] …` with the
 * path reverse-mapped to HumanView, the tool_result event's `twinNote`
 * summary, and the §9 oracle NOT tripping on the proxy's own suffix.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AnthropicProxy } from "../../src/proxy.js";
import { ViewMap } from "../../src/view-map.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream } from "../helpers/mock-upstream.js";

function call(port: number, body: string, headers: Record<string, string>): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", ...headers } },
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

test("proxy: twin note rides the wire after the symbol, path in HumanView spelling; event carries twinNote; oracle stays clean", async () => {
  const base = mkdtempSync(join(tmpdir(), "twin-proxy-"));
  const human = join(base, "ws");
  const agent = join(base, "view-state", "agentview");
  mkdirSync(human, { recursive: true });
  mkdirSync(agent, { recursive: true });
  writeFileSync(join(human, "notes.md"), "# Project notes\n\nTODO: ship the proxy.\nMDUINJECT line\n");
  writeFileSync(join(agent, "notes.md"), "$MDU:Read[2d3e].notes.md\n");
  const arbiter = new MockArbiter();
  const upstream = new MockUpstream({ json: { type: "message", role: "assistant", content: [] } });
  const proxy = new AnthropicProxy({
    arbiter, upstream: upstream.fetcher, log: () => {},
    viewMap: new ViewMap([{ human, agent }], { dialect: "posix", home: base }),
  });
  const port = await proxy.listen(0);
  try {
    const body = JSON.stringify({
      model: "claude-haiku-4-5", stream: false, max_tokens: 64,
      tools: [{ name: "Bash", input_schema: { type: "object", properties: { command: { type: "string" } } } }],
      messages: [
        { role: "user", content: "quote line 3" },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_twin", name: "Bash", input: { command: `sed -n '3p' ${join(agent, "notes.md")}` } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_twin", content: "(Bash completed with no output)" }] },
      ],
    });
    const r = await call(port, body, { "x-mandu-session-id": "sess-twin" });
    assert.equal(r.status, 200);
    const forwarded = upstream.requests[0]!.bodyText;
    const m = /"content":"(\$MDU:Bash\[[0-9a-f]+\][^"\\]*)\\n\\n\[mandu:twin\] ([^"\\]*) is an untrusted file: in this workspace its content is the opaque symbol \$MDU:Read\[2d3e\]\.notes\.md \(1 token\)\./.exec(forwarded);
    assert.ok(m, `forwarded body carries symbol + note: ${forwarded.slice(0, 400)}`);
    assert.equal(m![2], join(human, "notes.md"), "the note's path is spelled in HumanView after the reverse map");
    assert.ok(!forwarded.includes("no output"), "the raw body never reaches upstream");
    assert.ok(!forwarded.includes(agent), "no AgentView spelling survives on the wire");
    await new Promise((res) => setTimeout(res, 50));
    const ev = arbiter.emittedEvents.find((e) => e.kind === "tool_result" && e.callId === "toolu_twin") as
      | (Record<string, unknown> & { invariant?: { violatedInvariant?: boolean }; output?: { symbolized?: string } })
      | undefined;
    assert.ok(ev, "a tool_result event was emitted");
    assert.deepEqual(ev!["twinNote"], { paths: [join(human, "notes.md")], tokens: 1 });
    assert.equal(ev!.invariant?.violatedInvariant, false, "the proxy's own suffix does not trip the §9 oracle");
    assert.match(ev!.output?.symbolized ?? "", /^\$MDU:Bash\[[0-9a-f]+\][^\n]*\n\n\[mandu:twin\]/);
    // a second call over a non-twin path: no note, no field
    const body2 = body.replaceAll("toolu_twin", "toolu_plain").replace(`sed -n '3p' ${join(agent, "notes.md")}`, "echo hi").replace("(Bash completed with no output)", "hi");
    assert.equal((await call(port, body2, { "x-mandu-session-id": "sess-twin" })).status, 200);
    assert.ok(!upstream.requests[1]!.bodyText.includes("[mandu:twin]"));
    await new Promise((res) => setTimeout(res, 50));
    const ev2 = arbiter.emittedEvents.find((e) => e.kind === "tool_result" && e.callId === "toolu_plain") as Record<string, unknown> | undefined;
    assert.ok(ev2 && !("twinNote" in ev2));
    // the handling prompt reported the file view
    assert.equal(arbiter.handlingPromptArgs[0]?.capabilities?.fsView, true);
  } finally {
    await proxy.close();
    rmSync(base, { recursive: true, force: true });
  }
});

test("proxy: a post-cd leaf the command parse cannot resolve is noted via the exec box's hint (v2); the note is cached per callId across re-sends; a failing hint op is silent", async () => {
  const base = mkdtempSync(join(tmpdir(), "twin-proxy-v2-"));
  const human = join(base, "ws");
  const agent = join(base, "view-state", "agentview");
  mkdirSync(join(human, "docs"), { recursive: true });
  mkdirSync(join(agent, "docs"), { recursive: true });
  writeFileSync(join(human, "docs", "release-notes-alpha.md"), "# release-notes-alpha\n\nnothing to see here.\n");
  writeFileSync(join(agent, "docs", "release-notes-alpha.md"), "$MDU:Read[d3bd].__mdu_field_0\n");
  const command = "cd docs && sed -n '3p' release-notes-alpha.md";
  // The mock arbiter answers the hint ONCE (as the real store would while the
  // leaf's report is inside its recency window), then stops.
  let hintAnswers = 0;
  const arbiter = new MockArbiter({
    execTwinsFn: (cmd) => {
      if (cmd !== command || hintAnswers++ > 0) return [];
      return [{ asTyped: "release-notes-alpha.md", abs: join(agent, "docs", "release-notes-alpha.md") }];
    },
  });
  const upstream = new MockUpstream({ json: { type: "message", role: "assistant", content: [] } });
  const proxy = new AnthropicProxy({
    arbiter, upstream: upstream.fetcher, log: () => {},
    viewMap: new ViewMap([{ human, agent }], { dialect: "posix", home: base }),
  });
  const port = await proxy.listen(0);
  try {
    const body = (extra: unknown[] = []) => JSON.stringify({
      model: "claude-haiku-4-5", stream: false, max_tokens: 64,
      tools: [{ name: "Bash", input_schema: { type: "object", properties: { command: { type: "string" } } } }],
      messages: [
        { role: "user", content: "quote line 3 of docs/release-notes-alpha.md" },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_cd", name: "Bash", input: { command } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_cd", content: "(Bash completed with no output)" }] },
        ...extra,
      ],
    });
    const noteRe = /\\n\\n\[mandu:twin\] release-notes-alpha\.md is an untrusted file: in this workspace its content is the opaque symbol \$MDU:Read\[d3bd\]\.__mdu_field_0 \(1 token\)\./;
    // request 1: the parse misses (no `release-notes-alpha.md` at the root), the hint lands
    assert.equal((await call(port, body(), { "x-mandu-session-id": "sess-v2" })).status, 200);
    assert.match(upstream.requests[0]!.bodyText, noteRe);
    assert.ok(!upstream.requests[0]!.bodyText.includes("no output"));
    assert.deepEqual(arbiter.execTwinsCalls, [command]);
    await new Promise((res) => setTimeout(res, 50));
    const ev = arbiter.emittedEvents.find((e) => e.kind === "tool_result" && e.callId === "toolu_cd") as Record<string, unknown> | undefined;
    assert.deepEqual(ev?.["twinNote"], { paths: ["release-notes-alpha.md"], tokens: 1, hinted: 1 });
    // request 2 (next turn re-sends the history): the arbiter no longer answers,
    // the per-callId cache keeps the note byte-stable — and no second ask.
    const turn2 = body([
      { role: "assistant", content: "I need to Read it." },
      { role: "user", content: "go on" },
    ]);
    assert.equal((await call(port, turn2, { "x-mandu-session-id": "sess-v2" })).status, 200);
    assert.match(upstream.requests[1]!.bodyText, noteRe);
    assert.deepEqual(arbiter.execTwinsCalls, [command], "cached: the hint op is asked once per callId");
    // the oracle never trips on the proxy's own suffix
    assert.ok(arbiter.emittedEvents.filter((e) => e.kind === "tool_result").every((e) => (e as { invariant?: { violatedInvariant?: boolean } }).invariant?.violatedInvariant === false));
  } finally {
    await proxy.close();
    rmSync(base, { recursive: true, force: true });
  }

  // A throwing hint op (or an arbiter without it) leaves the request intact and un-noted.
  const base2 = mkdtempSync(join(tmpdir(), "twin-proxy-v2b-"));
  const human2 = join(base2, "ws"); const agent2 = join(base2, "agentview");
  mkdirSync(human2, { recursive: true }); mkdirSync(agent2, { recursive: true });
  const failing = new MockArbiter({ failExecTwins: true });
  const up2 = new MockUpstream({ json: { type: "message", role: "assistant", content: [] } });
  const proxy2 = new AnthropicProxy({ arbiter: failing, upstream: up2.fetcher, log: () => {}, viewMap: new ViewMap([{ human: human2, agent: agent2 }], { dialect: "posix", home: base2 }) });
  const port2 = await proxy2.listen(0);
  try {
    const b = JSON.stringify({
      model: "claude-haiku-4-5", stream: false, max_tokens: 64,
      tools: [{ name: "Bash", input_schema: { type: "object", properties: { command: { type: "string" } } } }],
      messages: [
        { role: "user", content: "x" },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_f", name: "Bash", input: { command: "cd docs && cat a.md" } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_f", content: "(Bash completed with no output)" }] },
      ],
    });
    assert.equal((await call(port2, b, { "x-mandu-session-id": "sess-v2b" })).status, 200);
    assert.ok(!up2.requests[0]!.bodyText.includes("[mandu:twin]"));
    assert.equal(failing.execTwinsCalls.length, 1);
    // …and a FAILED ask is not remembered: the next re-send asks again
    assert.equal((await call(port2, b, { "x-mandu-session-id": "sess-v2b" })).status, 200);
    assert.equal(failing.execTwinsCalls.length, 2, "a failed hint ask is never cached");
  } finally {
    await proxy2.close();
    rmSync(base2, { recursive: true, force: true });
  }
});

test("proxy: a hint answer delayed by arbiter contention still lands (no 250 ms cliff); a failed ask does not poison the per-callId cache", async () => {
  const base = mkdtempSync(join(tmpdir(), "twin-proxy-v2c-"));
  const human = join(base, "ws"); const agent = join(base, "agentview");
  mkdirSync(join(human, "docs"), { recursive: true }); mkdirSync(join(agent, "docs"), { recursive: true });
  writeFileSync(join(agent, "docs", "a.md"), "$MDU:Read[a1b2].a\n");
  const command = "cd docs && sed -n '3p' a.md";
  let fail = true;
  const arbiter = new MockArbiter({
    execTwinsDelayMs: 400, // slower than the OLD 250 ms cliff, well inside the bound
    execTwinsFn: (cmd) => {
      if (fail) throw new Error("mock arbiter: busy (injected)");
      return cmd === command ? [{ asTyped: "a.md", abs: join(agent, "docs", "a.md") }] : [];
    },
  });
  const upstream = new MockUpstream({ json: { type: "message", role: "assistant", content: [] } });
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, viewMap: new ViewMap([{ human, agent }], { dialect: "posix", home: base }) });
  const port = await proxy.listen(0);
  try {
    const body = JSON.stringify({
      model: "claude-haiku-4-5", stream: false, max_tokens: 64,
      tools: [{ name: "Bash", input_schema: { type: "object", properties: { command: { type: "string" } } } }],
      messages: [
        { role: "user", content: "x" },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_slow", name: "Bash", input: { command } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_slow", content: "(Bash completed with no output)" }] },
      ],
    });
    // request 1: the arbiter throws → no note, nothing cached
    assert.equal((await call(port, body, { "x-mandu-session-id": "sess-slow" })).status, 200);
    assert.ok(!upstream.requests[0]!.bodyText.includes("[mandu:twin]"));
    // request 2: the arbiter answers, slowly → the note lands and is now cached
    fail = false;
    assert.equal((await call(port, body, { "x-mandu-session-id": "sess-slow" })).status, 200);
    assert.ok(upstream.requests[1]!.bodyText.includes("[mandu:twin] a.md is an untrusted file"), upstream.requests[1]!.bodyText.slice(0, 300));
    assert.equal(arbiter.execTwinsCalls.length, 2);
    // request 3: served from the cache — no third ask
    assert.equal((await call(port, body, { "x-mandu-session-id": "sess-slow" })).status, 200);
    assert.ok(upstream.requests[2]!.bodyText.includes("[mandu:twin] a.md"));
    assert.equal(arbiter.execTwinsCalls.length, 2, "cached after the first real answer");
  } finally {
    await proxy.close();
    rmSync(base, { recursive: true, force: true });
  }
});
