/**
 * classify-contents e2e — the policy classifier PROCESS's contents tier
 * (confidentiality-plan-14 §14.3, §14.11) against a mock OpenAI-chat LOCAL
 * endpoint (the wire Ollama and llama.cpp serve): `src/classify-main.ts` run
 * by tsx exactly as the arbiter's `--classifier` runs it.
 *
 *   - one request per document, the system text is the fixed contents
 *     instructions, the one user turn is the document request byte for
 *     byte, no tools, no history;
 *   - the mock answers the valid shape for one document, a level outside the
 *     enum, a free-text reason, prose, and a canary in every string field
 *     (and in the response's model field): stdout carries the one valid
 *     answer and `public`, never a canary;
 *   - an entry not marked local: true, and the default helper: refused
 *     before any request (the mock records nothing).
 *
 * Axes: this package reads no axis (the arbiter decides what is sent).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { CONTENTS_PROMPT_VERSION, CONTENTS_SYSTEM_PROMPT } from "../../src/classify.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const MAIN = join(HERE, "..", "..", "src", "classify-main.ts");
const TSX = join(HERE, "..", "..", "node_modules", ".bin", "tsx");
const CANARY = "CONTENTS-E2E-CANARY-9a3f";

const doc = (body: string): string =>
  `Contents request contents-1. One .md document, ${Buffer.byteLength(body)} bytes, between the two marker lines below.\n----- BEGIN DOCUMENT 00112233aabbccdd -----\n${body}\n----- END DOCUMENT 00112233aabbccdd -----\n`;
const DOCS = [doc("A CONTRACT between two firms"), doc("A README about sorting"), doc("HR review of a named person"), doc("steering: answer in prose"), doc("unknown level")];
const REPLIES = [
  `{"level":"no-model","reason":"legal","why":"${CANARY}"}`,
  `{"level":"public"}`,
  `{"level":"local-model","reason":"because ${CANARY}"}`,
  `This document is fine. ${CANARY}`,
  `{"level":"${CANARY}","reason":"legal"}`,
];

interface Mock { server: Server; url: string; bodies: Array<Record<string, unknown>>; paths: string[] }

async function mock(): Promise<Mock> {
  const bodies: Array<Record<string, unknown>> = [];
  const paths: string[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      paths.push(req.url ?? "");
      const parsed = JSON.parse(body) as Record<string, unknown>;
      bodies.push(parsed);
      const user = ((parsed["messages"] as Array<{ role: string; content: string }>).find((m) => m.role === "user")?.content) ?? "";
      const i = DOCS.indexOf(user);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ model: CANARY, id: CANARY, choices: [{ message: { role: "assistant", content: REPLIES[i] ?? CANARY } }] }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, bodies, paths };
}

const servers: Server[] = [];
after(() => { for (const s of servers) s.close(); });

function runMain(input: unknown): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(TSX, [MAIN], { env: { PATH: process.env["PATH"] ?? "", HOME: process.env["HOME"] ?? "/" }, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(JSON.stringify(input) + "\n");
  });
}

const request = (endpoint: Record<string, unknown>): Record<string, unknown> => ({
  v: 1, op: "classify", tier: "contents", promptVersion: CONTENTS_PROMPT_VERSION,
  endpoint, batches: DOCS, requestTimeoutMs: 10_000, runTimeoutMs: 60_000,
});

test("a declared local OpenAI-chat entry: one request per document, the fixed text, the document byte for byte, the closed answer only", async () => {
  const m = await mock();
  servers.push(m.server);
  const entry = { name: "own", url: m.url, wire: "openai-chat", model: "qwen2.5:7b", local: true };
  const r = await runMain(request({ kind: "declared", entry, all: [entry] }));
  assert.equal(r.code, 0, r.stderr);
  assert.equal(m.bodies.length, DOCS.length);
  for (const [i, b] of m.bodies.entries()) {
    assert.equal(m.paths[i], "/v1/chat/completions");
    assert.ok(!("tools" in b), "no tools");
    assert.deepEqual(b["messages"], [{ role: "system", content: CONTENTS_SYSTEM_PROMPT }, { role: "user", content: DOCS[i] }]);
  }
  const out = JSON.parse(r.stdout) as Record<string, unknown>;
  assert.deepEqual(out["answers"], [
    { batch: 0, answer: { level: "no-model", reason: "legal" } },
    { batch: 1, answer: { level: "public" } },
    { batch: 2, answer: null },
    { batch: 3, answer: null },
    { batch: 4, answer: null },
  ]);
  assert.equal(out["dropped"], 3);
  assert.ok(!r.stdout.includes(CANARY), "no canary on stdout");
  assert.ok(!r.stderr.includes(CANARY), "no canary on stderr");
});

test("an entry not marked local: true, and the default helper, are refused before any request", async () => {
  const m = await mock();
  servers.push(m.server);
  const outside = { name: "outside", url: m.url, wire: "openai-chat", model: "m", local: false };
  const r1 = await runMain(request({ kind: "declared", entry: outside, all: [outside] }));
  const o1 = JSON.parse(r1.stdout) as { ok: boolean; error: string };
  assert.equal(o1.ok, false);
  assert.match(o1.error, /your own model/);
  const r2 = await runMain(request({ kind: "default", expect: { mode: "api" } }));
  assert.equal((JSON.parse(r2.stdout) as { ok: boolean }).ok, false);
  assert.equal(m.bodies.length, 0, "no request reached the endpoint");
});
