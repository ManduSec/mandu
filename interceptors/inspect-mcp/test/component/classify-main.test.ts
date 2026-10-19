/**
 * classify-main e2e — the policy classifier PROCESS (confidentiality-plan-14
 * §14.3) against mock model endpoints on the wire: `src/classify-main.ts`
 * run by tsx exactly as the arbiter's `--classifier` runs it, one JSON
 * request on stdin, one JSON answer on stdout.
 *
 *   - a declared Anthropic-wire entry and a declared OpenAI-chat entry: one
 *     request per batch, the system text is the fixed instructions, the one
 *     user turn is the batch byte for byte, no tools, no history;
 *   - the mock answers a valid rule, an unknown id, a free-text reason and a
 *     canary in every string field (and in the response's model field):
 *     stdout carries the valid rule only, no canary;
 *   - a 500 and a closed port: fixed categories, no response text;
 *   - an entry at the model proxy's address: refused before any request
 *     (the mock records nothing).
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

import { NAMES_SYSTEM_PROMPT } from "../../src/classify.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const MAIN = join(HERE, "..", "..", "src", "classify-main.ts");
const TSX = join(HERE, "..", "..", "node_modules", ".bin", "tsx");
const CANARY = "CLASSIFY-E2E-CANARY-4d1e";

const BATCHES = [
  ['Names-only request names-1, part 1 of 2.', 'd1 root 1 "clients/"', 'f1 root 1 "clients/contract.docx" size=under1KB ext=docx', ""].join("\n"),
  ['Names-only request names-1, part 2 of 2.', 'd2 root 1 "src/"', 'f2 root 1 "src/main.ts" size=under1KB ext=ts', ""].join("\n"),
];

const ANSWER = JSON.stringify({
  rules: [
    { candidate: "d1", level: "no-model", reason: "customer-data", note: CANARY },
    { candidate: "f99", level: "no-model", reason: "legal" },
    { candidate: "d1", level: "no-model", reason: `free ${CANARY}` },
    { candidate: CANARY, level: CANARY, reason: CANARY },
  ],
  comment: CANARY,
});

interface Mock { server: Server; url: string; bodies: Array<Record<string, unknown>>; paths: string[] }

async function mock(kind: "anthropic" | "openai" | "error"): Promise<Mock> {
  const bodies: Array<Record<string, unknown>> = [];
  const paths: string[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      paths.push(req.url ?? "");
      bodies.push(JSON.parse(body) as Record<string, unknown>);
      if (kind === "error") { res.writeHead(500); res.end(`upstream broke ${CANARY}`); return; }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(kind === "anthropic"
        ? JSON.stringify({ model: CANARY, content: [{ type: "text", text: `Here: ${CANARY}\n${ANSWER}` }], stop_reason: CANARY })
        : JSON.stringify({ model: CANARY, choices: [{ message: { role: "assistant", content: ANSWER } }] }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, bodies, paths };
}

const servers: Server[] = [];
after(() => { for (const s of servers) s.close(); });

function runMain(input: unknown, env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(TSX, [MAIN], { env: { PATH: process.env["PATH"] ?? "", HOME: process.env["HOME"] ?? "/", ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(JSON.stringify(input) + "\n");
  });
}

const request = (entry: Record<string, unknown>): Record<string, unknown> => ({
  v: 1, op: "classify", tier: "names", promptVersion: "names-1",
  endpoint: { kind: "declared", entry, all: [entry] }, batches: BATCHES, requestTimeoutMs: 10_000, runTimeoutMs: 60_000,
});

for (const wire of ["anthropic", "openai"] as const) {
  test(`a declared ${wire} entry: one request per batch, the fixed system text, the batch byte for byte, the closed answer only`, async () => {
    const m = await mock(wire);
    servers.push(m.server);
    const entry = { name: `mock-${wire}`, url: m.url, wire: wire === "openai" ? "openai-chat" : "anthropic", model: "m-1", local: false };
    const r = await runMain(request(entry));
    assert.equal(r.code, 0, r.stderr);
    assert.equal(m.bodies.length, 2);
    for (let i = 0; i < 2; i++) {
      const b = m.bodies[i]!;
      assert.ok(!("tools" in b), "no tools");
      if (wire === "anthropic") {
        assert.equal(m.paths[i], "/v1/messages");
        assert.equal(b["system"], NAMES_SYSTEM_PROMPT);
        assert.deepEqual(b["messages"], [{ role: "user", content: BATCHES[i] }]);
      } else {
        assert.equal(m.paths[i], "/v1/chat/completions");
        assert.deepEqual(b["messages"], [{ role: "system", content: NAMES_SYSTEM_PROMPT }, { role: "user", content: BATCHES[i] }]);
      }
    }
    const out = JSON.parse(r.stdout) as Record<string, unknown>;
    assert.deepEqual(out["answers"], [
      { batch: 0, rules: [{ candidate: "d1", level: "no-model", reason: "customer-data" }] },
      { batch: 1, rules: [] },
    ]);
    assert.ok(!r.stdout.includes(CANARY), "no canary on stdout");
    assert.ok(!r.stderr.includes(CANARY), "no canary on stderr");
  });
}

test("a 500 and a closed port are fixed categories; the proxy's address is refused before any request", async () => {
  const bad = await mock("error");
  servers.push(bad.server);
  const e1 = await runMain(request({ name: "broken", url: bad.url, wire: "anthropic", local: false }));
  const o1 = JSON.parse(e1.stdout) as { answers: unknown[] };
  assert.deepEqual(o1.answers, [{ batch: 0, failed: "refused (http 500)" }, { batch: 1, failed: "refused (http 500)" }]);
  assert.ok(!e1.stdout.includes(CANARY) && !e1.stderr.includes(CANARY));

  const closed = await mock("anthropic");
  const port = (closed.server.address() as AddressInfo).port;
  await new Promise<void>((r) => closed.server.close(() => r()));
  const e2 = await runMain(request({ name: "gone", url: `http://127.0.0.1:${port}`, wire: "anthropic", local: false }));
  assert.deepEqual((JSON.parse(e2.stdout) as { answers: unknown[] }).answers, [{ batch: 0, failed: "unreachable" }, { batch: 1, failed: "unreachable" }]);

  const proxy = await mock("anthropic");
  servers.push(proxy.server);
  const e3 = await runMain(request({ name: "proxy", url: proxy.url, wire: "anthropic", local: false }), { MANDU_MODEL_PROXY_URL: proxy.url });
  const o3 = JSON.parse(e3.stdout) as { ok: boolean; error: string };
  assert.equal(o3.ok, false);
  assert.match(o3.error, /model proxy/);
  assert.equal(proxy.bodies.length, 0, "no request reached the proxy's address");
});
