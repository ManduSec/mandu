/**
 * local-endpoint-routing e2e (Plan 11 D5): the MCP server over stdio, two mock
 * HTTP model endpoints on the wire.
 *
 * The invariant, end to end inside this package: a local-model datum's bytes
 * appear ONLY on the declared local endpoint's wire (an OpenAI chat server),
 * never on the external default U-LLM's (an Anthropic Messages server), and
 * what returns over MCP is an opaque symbol. An any-model datum still goes to
 * the default. With no local endpoint declared the call is refused and NEITHER
 * wire sees a byte. With one declared but failing (closed port, 5xx, no answer,
 * garbage) the call is refused too, and the default wire still sees nothing
 * (plan 11 §8 item 4).
 *
 * Axes: the mock arbiter plays confidentiality ON (`secrets` / `full`); this
 * package reads no axis itself.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { reservePort } from "../helpers/reserve-port.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(HERE, "fixtures", "stdio-server.ts");
const TSX = join(HERE, "..", "..", "node_modules", ".bin", "tsx");

const LOCAL = "$MDU:localmodel_Read[c0de]";
const ANY = "$MDU:anymodel_Read[a11a]";
const CONTRACT = "CONTRACT-BYTES: Acme pays Initech 4,200,000 on 2026-09-30.";
const PUBLIC_DOC = "ANYMODEL-BYTES: the release notes for 0.1.0.";

interface Wire { server: Server; url: string; bodies: string[] }

async function mockServer(kind: "anthropic" | "openai"): Promise<Wire> {
  const bodies: string[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      bodies.push(`${req.method} ${req.url}\n${body}`);
      const isTriage = body.includes("quarantined content classifier");
      const text = isTriage ? "substantive" : `${kind}-summary`;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(kind === "anthropic"
        ? { model: "claude-mock", content: [{ type: "text", text }] }
        : { model: "llama-mock", choices: [{ message: { role: "assistant", content: text } }] }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, bodies };
}

class McpChild {
  private next = 1;
  private waiting = new Map<number, (v: Record<string, unknown>) => void>();
  readonly stdout: string[] = [];
  constructor(readonly child: ChildProcess) {
    createInterface({ input: child.stdout! }).on("line", (line) => {
      this.stdout.push(line);
      const msg = JSON.parse(line) as { id: number };
      this.waiting.get(msg.id)?.(msg as unknown as Record<string, unknown>);
    });
  }
  call(method: string, params: unknown): Promise<Record<string, unknown>> {
    const id = this.next++;
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`timeout waiting for ${method}`)), 20_000);
      this.waiting.set(id, (v) => { clearTimeout(t); resolve(v); });
      this.child.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }
  close(): void { this.child.stdin!.end(); this.child.kill("SIGTERM"); }
}

async function rig(endpoints: unknown[]) {
  const external = await mockServer("anthropic");
  const local = await mockServer("openai");
  const dir = mkdtempSync(join(tmpdir(), "inspect-e2e-"));
  const events = join(dir, "events.ndjson");
  const eps = (endpoints as Array<Record<string, unknown>>).map((e) => ({ ...e, url: String(e.url).replace(/^LOCAL/, local.url) }));
  const child = spawn(TSX, [FIXTURE], {
    env: {
      ...process.env,
      E2E_DEFAULT_URL: external.url,
      E2E_ENDPOINTS: JSON.stringify(eps),
      E2E_SEED: JSON.stringify({ [LOCAL]: CONTRACT, [ANY]: PUBLIC_DOC }),
      E2E_EVENTS: events,
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const mcp = new McpChild(child);
  await mcp.call("initialize", {});
  const readEvents = () => existsSync(events)
    ? readFileSync(events, "utf-8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>)
    : [];
  const done = async () => {
    mcp.close();
    await Promise.all([external, local].map((w) => new Promise<void>((r) => { w.server.closeAllConnections(); w.server.close(() => r()); })));
    rmSync(dir, { recursive: true, force: true });
  };
  return { external, local, mcp, readEvents, done };
}

const inspect = (mcp: McpChild, args: Record<string, unknown>) =>
  mcp.call("tools/call", { name: "inspect_symbol", arguments: args }) as Promise<{ result: { isError: boolean; content: Array<{ text: string }>; structuredContent?: Record<string, string> } }>;

test("a local-model datum's bytes reach ONLY the declared local endpoint; the result is opaque", async () => {
  const r = await rig([{ name: "ollama", url: "LOCAL", wire: "openai-chat", model: "llama3.2", local: true }]);
  try {
    const resp = await inspect(r.mcp, { symbol: LOCAL, instruction: "summarize the contract" });
    assert.equal(resp.result.isError, false, JSON.stringify(resp));
    assert.match(resp.result.content[0].text, /^\$MDU:/);

    assert.equal(r.local.bodies.length, 1, "the main call only (no triage at a declared local endpoint)");
    assert.ok(r.local.bodies.every((b) => b.startsWith("POST /v1/chat/completions")));
    assert.ok(r.local.bodies.every((b) => b.includes("CONTRACT-BYTES")), "the local model read the contract");
    assert.equal(r.external.bodies.length, 0, "the external default U-LLM saw NOTHING");
    assert.ok(!r.mcp.stdout.join("\n").includes("CONTRACT-BYTES"), "nor did the MCP reply to T-LLM");
    assert.ok(!r.mcp.stdout.join("\n").includes("openai-summary"), "the summary comes back sealed");

    const evs = r.readEvents();
    assert.equal(evs.length, 1);
    for (const e of evs) assert.deepEqual(e.endpoint, { name: "ollama", location: "local", placement: "host" });
  } finally {
    await r.done();
  }
});

test("an any-model datum still goes to the default (external) U-LLM, and the local wire stays silent", async () => {
  const r = await rig([{ name: "ollama", url: "LOCAL", wire: "openai-chat", model: "llama3.2", local: true }]);
  try {
    const resp = await inspect(r.mcp, { symbol: ANY, instruction: "summarize" });
    assert.equal(resp.result.isError, false, JSON.stringify(resp));
    assert.equal(r.external.bodies.length, 2);
    assert.ok(r.external.bodies.every((b) => b.startsWith("POST /v1/messages") && b.includes("ANYMODEL-BYTES")));
    assert.equal(r.local.bodies.length, 0);
    for (const e of r.readEvents()) assert.deepEqual(e.endpoint, { name: "default", location: "external" });
  } finally {
    await r.done();
  }
});

test("multi-input local-model + any-model: every byte goes to the local wire", async () => {
  const r = await rig([{ name: "ollama", url: "LOCAL", wire: "openai-chat", model: "llama3.2", local: true }]);
  try {
    const resp = await inspect(r.mcp, { symbols: [ANY, LOCAL], instruction: "merge" });
    assert.equal(resp.result.isError, false, JSON.stringify(resp));
    assert.equal(r.external.bodies.length, 0);
    const main = r.local.bodies.find((b) => !b.includes("quarantined content classifier"))!;
    assert.ok(main.includes("CONTRACT-BYTES") && main.includes("ANYMODEL-BYTES"));
  } finally {
    await r.done();
  }
});

test("one Ollama for Codex and the helper: an entry whose url ends in /v1 is posted at /v1/chat/completions, not /v1/v1", async () => {
  const r = await rig([{ name: "codex-main", url: "LOCAL/v1", wire: "openai-chat", model: "llama3.2", local: true }]);
  try {
    const resp = await inspect(r.mcp, { symbol: LOCAL, instruction: "summarize the contract" });
    assert.equal(resp.result.isError, false, JSON.stringify(resp));
    assert.equal(r.local.bodies.length, 1);
    assert.ok(r.local.bodies[0].startsWith("POST /v1/chat/completions\n"), r.local.bodies[0].split("\n")[0]);
    assert.ok(r.local.bodies[0].includes("CONTRACT-BYTES"));
    assert.equal(r.external.bodies.length, 0);
  } finally {
    await r.done();
  }
});

test("helper: true picks the helper's model: a first local entry that is not the helper sees no byte", async () => {
  // The first local entry points at a closed port: routing to it would refuse
  // the call, so a green result proves the helper entry was chosen.
  const r = await rig([
    { name: "big-box", url: "http://127.0.0.1:9", wire: "openai-chat", model: "qwen", local: true },
    { name: "ollama", url: "LOCAL", wire: "openai-chat", model: "llama3.2", local: true, helper: true },
  ]);
  try {
    const resp = await inspect(r.mcp, { symbol: LOCAL, instruction: "summarize the contract" });
    assert.equal(resp.result.isError, false, JSON.stringify(resp));
    assert.equal(r.local.bodies.length, 1);
    assert.ok(r.local.bodies[0].includes("CONTRACT-BYTES"));
    assert.equal(r.external.bodies.length, 0);
    for (const e of r.readEvents()) assert.deepEqual(e.endpoint, { name: "ollama", location: "local", placement: "host" });
  } finally {
    await r.done();
  }
});

test("no local endpoint declared: refused by design, and NEITHER wire sees a byte", async () => {
  const r = await rig([{ name: "cloud", url: "https://llm.example.com", wire: "anthropic", local: false }]);
  try {
    const resp = await inspect(r.mcp, { symbol: LOCAL, instruction: "summarize" });
    assert.equal(resp.result.isError, true);
    assert.match(resp.result.content[0].text, /readable only by your own model and none is declared in policy\.yaml `models:`/);
    assert.equal(r.external.bodies.length, 0);
    assert.equal(r.local.bodies.length, 0);
    assert.ok(!r.mcp.stdout.join("\n").includes("CONTRACT-BYTES"));
    assert.equal(r.readEvents().length, 0);
  } finally {
    await r.done();
  }
});

test("a declared 'local' endpoint at the forwarder's address is refused before any byte moves", async () => {
  // The fixture pins the external mock as the forwarder; declaring THAT
  // address local would relay local-model bytes to an external vendor.
  const external = await mockServer("anthropic");
  const dir = mkdtempSync(join(tmpdir(), "inspect-e2e-"));
  const child = spawn(TSX, [FIXTURE], {
    env: {
      ...process.env,
      E2E_DEFAULT_URL: external.url,
      E2E_ENDPOINTS: JSON.stringify([{ name: "sneaky", url: external.url, wire: "anthropic", local: true }]),
      E2E_SEED: JSON.stringify({ [LOCAL]: CONTRACT }),
      E2E_EVENTS: join(dir, "events.ndjson"),
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const mcp = new McpChild(child);
  try {
    await mcp.call("initialize", {});
    const resp = await inspect(mcp, { symbol: LOCAL, instruction: "summarize" });
    assert.equal(resp.result.isError, true);
    assert.match(resp.result.content[0].text, /unusable: .*forwarder's address/);
    assert.equal(external.bodies.length, 0, "not one byte to the forwarder");
  } finally {
    mcp.close();
    external.server.closeAllConnections();
    await new Promise<void>((res) => external.server.close(() => res()));
    rmSync(dir, { recursive: true, force: true });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Plan 11 §8 item 4: the declared endpoint is unreachable ⇒ REFUSE, never the
// default. Real sockets: a closed port, a server answering 500 with the
// request echoed back, one that never answers (the production factory's
// MANDU_ULLM_ENDPOINT_TIMEOUT_MS bounds it), and one answering 200 garbage.
// ─────────────────────────────────────────────────────────────────────────────

type Failing = "closed" | "500-echo" | "hang" | "garbage";

async function failingEndpoint(kind: Failing): Promise<{ url: string; hits: string[]; close: () => Promise<void> }> {
  const hits: string[] = [];
  if (kind === "closed") {
    // A port nothing listens on, reserved so no suite running alongside can
    // be handed it (test-organization.md §8.4).
    const port = await reservePort();
    return { url: `http://127.0.0.1:${port}`, hits, close: async () => {} };
  }
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      hits.push(body);
      if (kind === "hang") return; // never answer
      if (kind === "500-echo") {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "boom", echo: body }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(`<<garbage ${body.slice(0, 200)}`);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    hits,
    close: async () => { server.closeAllConnections(); await new Promise<void>((r) => server.close(() => r())); },
  };
}

for (const wire of ["openai-chat", "anthropic"] as const) {
  for (const kind of ["closed", "500-echo", "hang", "garbage"] as const) {
    test(`declared ${wire} endpoint ${kind}: refused, the default wire sees NOTHING, no byte echoes back`, async () => {
      const external = await mockServer("anthropic");
      const bad = await failingEndpoint(kind);
      const dir = mkdtempSync(join(tmpdir(), "inspect-e2e-"));
      const events = join(dir, "events.ndjson");
      const child = spawn(TSX, [FIXTURE], {
        env: {
          ...process.env,
          E2E_DEFAULT_URL: external.url,
          E2E_ENDPOINTS: JSON.stringify([{ name: "ollama", url: bad.url, wire, model: "llama3.2", local: true }]),
          E2E_SEED: JSON.stringify({ [LOCAL]: CONTRACT }),
          E2E_EVENTS: events,
          MANDU_ULLM_ENDPOINT_TIMEOUT_MS: "400",
        },
        stdio: ["pipe", "pipe", "pipe"],
      });
      const mcp = new McpChild(child);
      try {
        await mcp.call("initialize", {});
        const t0 = Date.now();
        const resp = await inspect(mcp, { symbol: LOCAL, instruction: "summarize the contract" });
        assert.equal(resp.result.isError, true, JSON.stringify(resp));
        const text = resp.result.content[0].text;
        assert.match(text, /your declared model 'ollama' did not answer/);
        assert.match(text, {
          closed: /could not reach the endpoint \(ECONNREFUSED\)/,
          "500-echo": /500 Internal Server Error/,
          hang: /timed out after 400ms/,
          garbage: /not valid JSON/,
        }[kind]);
        assert.match(text, /not sent to any other model/);
        if (kind === "hang") assert.ok(Date.now() - t0 < 10_000, "the knob bounds the wait");

        assert.equal(external.bodies.length, 0, "the external default U-LLM saw NOTHING");
        if (kind !== "closed") assert.ok(bad.hits.length >= 1 && bad.hits.every((b) => b.includes("CONTRACT-BYTES")), "the bytes went only to the declared endpoint");
        const wireOut = mcp.stdout.join("\n");
        assert.ok(!wireOut.includes("CONTRACT-BYTES"), "no echoed byte reached T-LLM through the error");
        assert.ok(!wireOut.includes("boom") && !wireOut.includes("garbage"), "no response body fragment either");
        const evs = existsSync(events) ? readFileSync(events, "utf-8").trim().split("\n").filter(Boolean) : [];
        assert.equal(evs.length, 0, "no ullm_call event for a call that produced nothing");
      } finally {
        mcp.close();
        external.server.closeAllConnections();
        await new Promise<void>((res) => external.server.close(() => res()));
        await bad.close();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
}
