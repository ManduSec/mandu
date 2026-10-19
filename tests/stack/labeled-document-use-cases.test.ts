/**
 * labeled-document-use-cases.test.ts — the four confidentiality use cases,
 * pinned on a PLAIN DOCUMENT labeled through policy.yaml, across the real
 * components (docs/design/confidentiality/model-endpoints.md §1
 * names the four use cases; this suite is their oracle).
 *
 *   Use case 1: "a file I name never reaches the model vendor". Not a
 *   credential the catalog knows, a document: `~/notes/contract.md` labeled
 *   `no-model` in `paths:`. The model sees `$MDU:nomodel_Read[…]`, the
 *   quarantined helper is refused, and `any-model` on the same file is
 *   the dual (readable in the quarantine, never in the T-LLM wire).
 *
 *   Use case 2: "only the programs I name read the file". The same document
 *   with `readers:`: the named program gets the bytes, any other program is
 *   denied (or gets the placeholder twin under `others: twin`), a reader
 *   conditioned on its parent (`{app, from}`) is raw only under that parent,
 *   and the agent itself always gets the twin.
 *
 *   Use case 3: "my own model may read it, an outside model may not". The
 *   document labeled `local-model` with a model declared `local: true` in
 *   `models:`: the T-LLM sees `$MDU:localmodel_Read[…]`, the helper routes the
 *   read to the declared local model (a mock OpenAI-chat server on loopback,
 *   through the production endpoint client), the default helper is never
 *   called, and the answer comes back `localmodel_`. With no model declared
 *   the same read is refused and no model sees a byte.
 *
 *   Use case 4: use case 3 plus `readers:`; the reader verdicts are use case
 *   2's, at the new level.
 *
 * Every earlier test of these properties used a credential-shaped fixture
 * (`.env`, `.pgpass`, a private key) or the admin `setPathLabel` act. What is
 * new here is the path a user actually takes for a document: write the label
 * in policy.yaml, and nothing else. The arbiter is real, the proxy is real
 * with its production adapter over the real client, inspect-mcp's core is
 * real; only the model upstream and the U-LLM are mocks.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as AnthropicProxyArbiterAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { inspectSymbol } from "../../interceptors/inspect-mcp/src/inspect-symbol.js";
import { ArbiterClientAdapter as InspectArbiterAdapter } from "../../interceptors/inspect-mcp/src/arbiter-client.js";
import { MockUllm } from "../../interceptors/inspect-mcp/test/helpers/mock-ullm.js";
import { createEndpointUllmFactory } from "../../interceptors/inspect-mcp/src/ullm-config.js";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the built-in default: confidentiality ON, integrity OFF

/** The document. Nothing about its name or content matches the secret catalog. */
const CONTRACT_BODY = "Acme agrees to pay $4,200,000 on 2026-09-30. DOC_CANARY_2026";
const CANARY = "DOC_CANARY_2026";
const SUMMARY = "A $4.2M payment due at the end of Q3. SUMMARY_CANARY_31";
const SUMMARY_CANARY = "SUMMARY_CANARY_31";

// ── helpers ─────────────────────────────────────────────────────────────────

function modelProxyRealClient(
  client: ArbiterClient,
): ConstructorParameters<typeof AnthropicProxyArbiterAdapter>[0] {
  return {
    connect: () => client.connect(),
    classify: (req) => client.classify(req as never) as never,
    symbolize: (args) => client.symbolize(args),
    handlingPrompt: (mode?: string, capabilities?: { inspect?: boolean; policyTools?: boolean; exec?: boolean }) =>
      client.handlingPrompt(mode as never, capabilities),
    recordToolCall: (args) => client.recordToolCall(args),
    callTaint: (callId: string, opts?: { command?: string; session?: string }) => client.callTaint(callId, opts ?? {}),
    scanSecretValues: (text: string) => client.scanSecretValues(text),
    // the prompt filter (confidentiality-plan-15 §3.2), as the real client has it
    filterPrompt: (args: Parameters<ArbiterClient["filterPrompt"]>[0]) => client.filterPrompt(args),
    fsPathDecision: (req) => client.fsPathDecision(req as never) as never,
    execGate: (req) => client.execGate(req as never) as never,
    sessionEgressDecision: (req) => client.sessionEgressDecision(req as never) as never,
    labelWrittenPath: (req) => client.labelWrittenPath(req as never) as never,
    emit: async (event) => ({ seq: await client.emit(event as never) }),
    close: () => client.close(),
  };
}

/** inspect-mcp's narrow adapter over the real client. `opts` is passed through:
 *  `{deep: true}` IS the quarantine's resolution path and where the per-level
 *  split lives; a bridge that dropped it would resolve shallow and prove nothing. */
function inspectBridge(c: ArbiterClient): InspectArbiterAdapter {
  return new InspectArbiterAdapter({
    connect: () => c.connect(),
    resolve: (sym, opts) => c.resolve(sym, opts),
    symbolize: (args) => c.symbolize(args),
    symbolizeDerived: (args) => c.symbolizeDerived(args),
    emit: (event) => c.emit(event as never),
    symbolProvenance: (sym) => c.symbolProvenance(sym),
    modelEndpoints: () => c.modelEndpoints(),
    close: () => c.close(),
  });
}

function postMessages(port: number, headers: Record<string, string>, body: string): Promise<{ status: number; body: string }> {
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

/** The tool_result span for one tool_use, not a body-wide regex: the handling
 *  prompt prints example `nomodel_`/`anymodel_` tokens to teach the model the shape. */
function toolResultContent(bodyText: string, toolUseId: string): string {
  const req = JSON.parse(bodyText) as { messages: Array<{ content?: unknown }> };
  for (const msg of req.messages) {
    if (!Array.isArray(msg.content)) continue;
    for (const block of msg.content as Array<Record<string, unknown>>) {
      if (block.type !== "tool_result" || block.tool_use_id !== toolUseId) continue;
      const c = block.content;
      if (typeof c === "string") return c;
      if (Array.isArray(c)) return (c as Array<{ text?: string }>).map((b) => b.text ?? "").join("");
    }
  }
  throw new Error(`no tool_result for ${toolUseId} in the forwarded body`);
}

/** The agent Reads the document: the exact shape the proxy must symbolize. */
function readRequest(sessionId: string, path: string): { headers: Record<string, string>; body: string } {
  const body = JSON.stringify({
    model: "claude-opus-4",
    stream: true,
    system: "You are Claude Code.",
    messages: [
      { role: "user", content: "Summarize the contract." },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_doc1", name: "Read", input: { file_path: path } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_doc1", content: CONTRACT_BODY }] },
    ],
  });
  return { headers: { "x-mandu-session-id": sessionId }, body };
}

/** A home with a plain document and its label in policy.yaml; the real stack over it. */
async function bootStack(pathsEntry: (contract: string) => Record<string, unknown>, extra: { models?: unknown[] } = {}): Promise<{
  home: string;
  contract: string;
  port: number;
  upstream: MockUpstream;
  data: ArbiterClient;
  admin: ArbiterClient;
  stop: () => Promise<void>;
}> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-doc-uc-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "notes"), { recursive: true });
  const contract = join(home, "notes", "contract.md");
  writeFileSync(contract, CONTRACT_BODY + "\n");
  writeFileSync(join(home, "notes", "todo.md"), "- ship the proxy\n");

  const socketPath = join(tmp, "arbiter.sock");
  const adminSocketPath = join(tmp, "admin.sock");
  const arbiter = new ArbiterServer({
    socketPath,
    dbPath: join(tmp, "symbols.sqlite"),
    adminSocketPath,
    humanSocketPath: join(tmp, "human", "h.sock"),
    eventDir: join(tmp, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
    // The user's one act: a `paths:` entry in policy.yaml. No admin labeling.
    policyDocument: { version: 1, paths: [pathsEntry(contract)], ...(extra.models ? { models: extra.models } : {}) } as never,
  });
  await arbiter.listen();

  const proxyClient = new ArbiterClient(socketPath);
  await proxyClient.connect();
  // The guard's reports go to the human socket (plan 13 D9).
  const data = new ArbiterClient(join(tmp, "human", "h.sock"));
  await data.connect();
  const admin = new ArbiterClient(adminSocketPath);
  await admin.connect();

  const upstream = new MockUpstream({ sse: buildToolUseSse({ id: "tu_done", name: "TodoWrite", input: { todos: [] } }) });
  const proxy = new AnthropicProxy({
    arbiter: new AnthropicProxyArbiterAdapter(modelProxyRealClient(proxyClient)),
    upstream: upstream.fetcher,
    log: () => {},
  });
  const port = await proxy.listen(0);

  return {
    home, contract, port, upstream, data, admin,
    stop: async () => {
      await proxy.close();
      proxyClient.close();
      data.close();
      admin.close();
      await arbiter.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

// ── use case 1: a document the model vendor never sees ──────────────────────

test("UC1: a plain document labeled no-model in policy.yaml reaches the model only as $MDU:nomodel_, and the quarantined helper is refused", async () => {
  const s = await bootStack((contract) => ({ path: contract, level: "no-model" }));
  const sessionId = "doc-uc1-strict";
  try {
    // The launcher's registration path for a labeled file: the arbiter reads
    // the file, mints the symbol, and returns the twin the agent's world gets.
    // A document of no known shape gets the whole-file twin (its symbol).
    const reg = await s.data.registerSecret({ path: s.contract, sessionKey: sessionId, home: s.home });
    assert.ok(reg.symbol, `a policy.yaml strict label registers a plain document (${reg.reason})`);
    assert.match(reg.symbol!, /^\$MDU:nomodel_/, "the document's symbol carries the strict marker");
    assert.ok(!(reg.twin ?? "").includes(CANARY), "the twin the agent's world receives holds no document bytes");
    const sibling = await s.data.registerSecret({ path: join(s.home, "notes", "todo.md"), sessionKey: sessionId, home: s.home });
    assert.equal(sibling.symbol, null, "an unlabeled sibling document is not a secret: the label is the only reason");

    // Ingress: the agent's Read of the document, through the production proxy.
    const { headers, body } = readRequest(sessionId, s.contract);
    const res = await postMessages(s.port, headers, body);
    assert.equal(res.status, 200);

    const forwarded = s.upstream.requests[0]!.bodyText;
    assert.ok(!forwarded.includes(CANARY), "USE CASE 1 VIOLATION: the document's bytes reached the model request");
    const span = toolResultContent(forwarded, "toolu_doc1");
    const minted = span.match(/\$MDU:nomodel_[A-Za-z0-9_]*\[[0-9a-f]+\]/)?.[0];
    assert.ok(minted, `the model must see a nomodel_ symbol for the document; got: ${span}`);

    // The quarantined helper is a vendor endpoint too: refused, zero calls.
    const ullm = new MockUllm({ reply: "should never run", model: "claude-haiku-mock" });
    const out = await inspectSymbol({ arbiter: inspectBridge(s.data), ullm, sessionId }, { symbol: minted!, instruction: "Summarize this contract." });
    assert.equal(out.ok, false, "strict is refused into the quarantine");
    assert.equal(ullm.calls.length, 0, "no model, not even the quarantined one, read the document");
    assert.match((out as { error: string }).error, /by design/i, "the refusal is reported as a decision, not as an unknown symbol");

    // The direct quarantine path, without inspect-mcp's wording in between.
    assert.equal(await s.data.resolve(minted!, { deep: true }), null, "resolve(deep) refuses a strict document");

    // The human is unrestricted: the shallow resolve (the reply filter's path) is the original.
    assert.equal(await s.admin.resolve(minted!), CONTRACT_BODY);
  } finally {
    await s.stop();
  }
});

test("UC1 dual: the same document labeled any-model is readable in the quarantine, and neither it nor its summary reaches the T-LLM wire", async () => {
  const s = await bootStack((contract) => ({ path: contract, level: "any-model" }));
  const sessionId = "doc-uc1-model-ok";
  try {
    const { headers, body } = readRequest(sessionId, s.contract);
    const res = await postMessages(s.port, headers, body);
    assert.equal(res.status, 200);

    const forwarded = s.upstream.requests[0]!.bodyText;
    assert.ok(!forwarded.includes(CANARY), "model-ok is still symbolized at ingress (least exposure)");
    const span = toolResultContent(forwarded, "toolu_doc1");
    const minted = span.match(/\$MDU:anymodel_[A-Za-z0-9_]*\[[0-9a-f]+\]/)?.[0];
    assert.ok(minted, `the model must see a anymodel_ symbol; got: ${span}`);

    const ullm = new MockUllm({ reply: SUMMARY, model: "claude-haiku-mock" });
    const out = await inspectSymbol({ arbiter: inspectBridge(s.data), ullm, sessionId }, { symbol: minted!, instruction: "Summarize this contract." });
    assert.equal(out.ok, true, "model-ok IS readable in the quarantine: that is what the label grants");
    if (!out.ok) return;
    assert.ok(ullm.calls.some((c) => c.user.includes(CANARY)), "the quarantined model read the document");
    assert.match(out.resultSymbol, /^\$MDU:anymodel_/, "the summary comes back at the document's level, never public");

    const wire = JSON.stringify(s.upstream.requests);
    assert.ok(!wire.includes(CANARY), "the document never reached the privileged model");
    assert.ok(!wire.includes(SUMMARY_CANARY), "nor did its summary");
  } finally {
    await s.stop();
  }
});

// ── use case 2: only the programs I name read the file ──────────────────────

test("UC2: with readers: on the document, the named program gets the bytes, every other program is denied, and the agent gets the twin", async () => {
  const s = await bootStack((contract) => ({
    path: contract,
    level: "no-model",
    readers: [{ app: "report-tool", path: "/opt/bin/report-tool", sha256: "a".repeat(64), prints: "nothing" }],
  }));
  try {
    const open = (exe: string, procKey: string, extra: Record<string, unknown> = {}) =>
      s.data.decideSecretOpen({ path: s.contract, exe, isAgent: false, exeSystem: true, openerEnv: [], procKey, ...extra } as never);

    const listed = await open("/opt/bin/report-tool", "rt-1", { sha256: "a".repeat(64) });
    assert.equal(listed.verdict, "raw", "the named program reads the real document");
    assert.equal(listed.app, "report-tool");
    assert.equal(listed.level, "no-model");
    const taint = await s.data.processSecretTaint("rt-1");
    assert.equal(taint.level, "no-model", "holding the bytes taints the process: its exits are confined (Plan 10)");

    const rebuilt = await open("/opt/bin/report-tool", "rt-2", { sha256: "b".repeat(64) });
    assert.equal(rebuilt.verdict, "deny", "a pin is path AND hash: a rebuilt binary is not the reader");

    for (const [exe, key] of [["/usr/bin/cat", "cat-3"], ["/usr/bin/grep", "grep-4"], ["/usr/bin/ssh-add", "psql-5"], ["/usr/bin/python3", "py-6"]] as const) {
      const other = await open(exe, key);
      assert.equal(other.verdict, "deny", `${exe} is not on the list: denied`);
      // plan 13 §8 decision (b): an interpreter is refused before the list
      // is read, as no reader unless it runs a script R5 pins; plan 13 D8
      // (2026-10-03): so is a printer (cat, grep), listed or not
      assert.match(other.reason, exe.endsWith("python3") ? /reads a secret only as a pinned script/ : /\/(cat|grep)$/.test(exe) ? /prints or copies/ : /exhaustive/, "the list is the user's exhaustive statement of who reads this file");
      assert.equal((await s.data.processSecretTaint(key)).level, null, "a denied open records no taint");
    }

    const agent = await open("/opt/bin/report-tool", "agent-7", { sha256: "a".repeat(64), isAgent: true });
    assert.equal(agent.verdict, "twin", "the agent's own process never gets the bytes, whatever the list says");
  } finally {
    await s.stop();
  }
});

test("UC2: a reader conditioned on its parent ({app, from}) is raw only under that parent", async () => {
  const s = await bootStack((contract) => ({
    path: contract,
    level: "no-model",
    readers: [{ app: "pandoc", from: "make", prints: "nothing" }],
    others: "deny",
  }));
  try {
    const direct = await s.data.decideSecretOpen({ path: s.contract, exe: "/usr/bin/pandoc", isAgent: false, exeSystem: true, openerEnv: [], procKey: "pd-1", ancestorExes: ["/usr/bin/bash", "/usr/bin/node"], ancestorTrusted: [true, true] });
    assert.equal(direct.verdict, "deny", "pandoc run by the agent's shell directly is refused");
    const viaMake = await s.data.decideSecretOpen({ path: s.contract, exe: "/usr/bin/pandoc", isAgent: false, exeSystem: true, openerEnv: [], procKey: "pd-2", ancestorExes: ["/usr/bin/make", "/usr/bin/bash"], ancestorTrusted: [true, true] });
    assert.equal(viaMake.verdict, "raw", "pandoc under make reads the document");
    const otherUnderMake = await s.data.decideSecretOpen({ path: s.contract, exe: "/usr/bin/cat", isAgent: false, exeSystem: true, openerEnv: [], procKey: "cat-3", ancestorExes: ["/usr/bin/make", "/usr/bin/bash"], ancestorTrusted: [true, true] });
    assert.equal(otherUnderMake.verdict, "deny", "the parent condition does not admit other programs under make");
  } finally {
    await s.stop();
  }
});

test("UC2: `others: twin` gives an unlisted program the placeholder document instead of a denial", async () => {
  const s = await bootStack((contract) => ({
    path: contract,
    level: "no-model",
    readers: [{ app: "report-tool", path: "/opt/bin/report-tool", sha256: "a".repeat(64), prints: "nothing" }],
    others: "twin",
  }));
  try {
    const listed = await s.data.decideSecretOpen({ path: s.contract, exe: "/opt/bin/report-tool", sha256: "a".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "rt-1" });
    assert.equal(listed.verdict, "raw");
    const other = await s.data.decideSecretOpen({ path: s.contract, exe: "/usr/bin/cat", isAgent: false, exeSystem: true, openerEnv: [], procKey: "cat-2" });
    assert.equal(other.verdict, "twin", "others: twin restores the no-list baseline for the rest");
    assert.equal((await s.data.processSecretTaint("cat-2")).level, null, "a twin read holds no bytes: no taint");
  } finally {
    await s.stop();
  }
});

test("UC2: with no readers: on the document, every program gets the twin (the baseline the list replaces)", async () => {
  const s = await bootStack((contract) => ({ path: contract, level: "no-model" }));
  try {
    for (const [exe, key] of [["/usr/bin/cat", "cat-1"], ["/usr/bin/pandoc", "pd-2"]] as const) {
      const v = await s.data.decideSecretOpen({ path: s.contract, exe, isAgent: false, exeSystem: true, openerEnv: [], procKey: key });
      assert.equal(v.verdict, "twin", `${exe}: no list, so the placeholder`);
    }
  } finally {
    await s.stop();
  }
});

// ── use cases 3 and 4: your own model may read it, an outside model may not ─

/** A mock OpenAI-chat model server on loopback (what Ollama speaks): records
 *  every request body and answers with SUMMARY (or the triage verdict). */
async function localModel(): Promise<{ url: string; bodies: string[]; close: () => Promise<void> }> {
  const bodies: string[] = [];
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      bodies.push(body);
      const text = body.includes("quarantined content classifier") ? "substantive" : SUMMARY;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ model: "llama3.2", choices: [{ message: { role: "assistant", content: text } }] }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    bodies,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

test("UC3: a document labeled local-model is read only by the declared local model; the T-LLM and the default helper never see it or its summary", async () => {
  const own = await localModel();
  const s = await bootStack((contract) => ({ path: contract, level: "local-model" }),
    { models: [{ name: "ollama", url: own.url, wire: "openai-chat", model: "llama3.2", local: true }] });
  const sessionId = "doc-uc3";
  try {
    const { headers, body } = readRequest(sessionId, s.contract);
    assert.equal((await postMessages(s.port, headers, body)).status, 200);
    const forwarded = s.upstream.requests[0]!.bodyText;
    assert.ok(!forwarded.includes(CANARY), "USE CASE 3 VIOLATION: the document reached the outside model's request");
    const minted = toolResultContent(forwarded, "toolu_doc1").match(/\$MDU:localmodel_[A-Za-z0-9_]*\[[0-9a-f]+\]/)?.[0];
    assert.ok(minted, "the T-LLM sees a localmodel_ symbol for the document");

    const outside = new MockUllm({ reply: "the outside helper must not run", model: "claude-haiku-mock" });
    const out = await inspectSymbol(
      { arbiter: inspectBridge(s.data), ullm: outside, sessionId, endpointUllm: createEndpointUllmFactory({}) },
      { symbol: minted!, instruction: "Summarize this contract." },
    );
    assert.equal(out.ok, true, `the helper reaches the declared local model (${(out as { error?: string }).error ?? ""})`);
    if (!out.ok) return;
    assert.equal(outside.calls.length, 0, "the default (outside) helper was never called");
    assert.ok(own.bodies.some((b) => b.includes(CANARY)), "the local model read the document");
    assert.match(out.resultSymbol, /^\$MDU:localmodel_/, "the summary comes back at the document's level");
    assert.equal(await s.data.resolve(out.resultSymbol, { deep: true }), null, "and an outside helper may not read the summary either");

    const wire = JSON.stringify(s.upstream.requests);
    assert.ok(!wire.includes(CANARY) && !wire.includes(SUMMARY_CANARY), "neither the document nor its summary reached the T-LLM");
  } finally {
    await s.stop();
    await own.close();
  }
});

test("UC3 fail-closed: with no model declared, a local-model document is read by no model at all", async () => {
  const s = await bootStack((contract) => ({ path: contract, level: "local-model" }));
  try {
    const reg = await s.data.registerSecret({ path: s.contract, sessionKey: "doc-uc3-none", home: s.home });
    assert.match(reg.symbol ?? "", /^\$MDU:localmodel_/);
    const outside = new MockUllm({ reply: "must not run", model: "claude-haiku-mock" });
    let built = 0;
    const out = await inspectSymbol(
      { arbiter: inspectBridge(s.data), ullm: outside, sessionId: "doc-uc3-none", endpointUllm: () => { built++; throw new Error("no endpoint may be built"); } },
      { symbol: reg.symbol!, instruction: "Summarize this contract." },
    );
    assert.equal(out.ok, false);
    assert.match((out as { error: string }).error, /none is declared/);
    assert.deepEqual([outside.calls.length, built], [0, 0], "no model was called and no endpoint client was built");
    assert.equal(await s.data.resolve(reg.symbol!, { deep: true }), null, "the arbiter refuses the quarantine read by itself too");
  } finally {
    await s.stop();
  }
});

test("UC4: local-model plus readers: the named program reads the document, every other program is denied, the agent gets the twin", async () => {
  const s = await bootStack((contract) => ({
    path: contract,
    level: "local-model",
    readers: [{ app: "report-tool", path: "/opt/bin/report-tool", sha256: "a".repeat(64), prints: "nothing" }],
  }), { models: [{ name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true }] });
  try {
    const open = (exe: string, procKey: string, extra: Record<string, unknown> = {}) =>
      s.data.decideSecretOpen({ path: s.contract, exe, isAgent: false, exeSystem: true, openerEnv: [], procKey, ...extra } as never);
    const listed = await open("/opt/bin/report-tool", "rt-1", { sha256: "a".repeat(64) });
    assert.deepEqual([listed.verdict, listed.level], ["raw", "local-model"]);
    assert.equal((await s.data.processSecretTaint("rt-1")).level, "local-model", "the reader's taint carries the level");
    assert.equal((await open("/usr/bin/curl", "curl-2")).verdict, "deny", "an unlisted program is denied");
    assert.equal((await open("/opt/bin/report-tool", "agent-3", { sha256: "a".repeat(64), isAgent: true })).verdict, "twin");
  } finally {
    await s.stop();
  }
});
