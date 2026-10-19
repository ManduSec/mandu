/**
 * policy-classifier-confine — the policy classifier's kernel network confine
 * (confidentiality-plan-14 §14.3): the arbiter runs the classifier (inspect-mcp
 * classify-main.ts) under `mandu-landlock-apply --net-only` with ONLY the
 * endpoint's port.
 *
 *   - through a real ArbiterServer given the applier (`--landlock-apply`):
 *     the preview says the confine is live, and a names-only run reaches the
 *     declared mock model on its port;
 *   - the same wrap argv the arbiter builds (`landlockWrap`), around the real
 *     classifier, with another endpoint's port: the connect is refused
 *     ("unreachable") and that endpoint records nothing;
 *   - the contents tier (plan 14 §14.11) the same way: a run to a declared
 *     local OpenAI-chat model reaches its port through the wrap, and the
 *     wrap refuses a contents request dialing another port.
 *
 * Kernel-gated: self-SKIPs without the mandu-landlock-apply bin or Landlock
 * TCP rules (kernel 6.7). Axes stated: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { landlockWrap, probeLandlockNet, spawnClassifier } from "../../arbiter/ipc/policy-model-ops.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { resolveNativeBin } from "../../launcher/src/services/native-bins.js";
import { Layout } from "../../launcher/src/services/layout.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

async function mock(wire: "anthropic" | "openai" = "anthropic"): Promise<{ server: Server; url: string; port: number; hits: number }> {
  const m = { server: undefined as unknown as Server, url: "", port: 0, hits: 0 };
  m.server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      m.hits++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(wire === "openai"
        ? JSON.stringify({ choices: [{ message: { role: "assistant", content: '{"level":"public"}' } }] })
        : JSON.stringify({ content: [{ type: "text", text: '{"rules":[]}' }] }));
    });
  });
  await new Promise<void>((r) => m.server.listen(0, "127.0.0.1", r));
  m.port = (m.server.address() as AddressInfo).port;
  m.url = `http://127.0.0.1:${m.port}`;
  return m;
}

test("the classifier reaches only its endpoint's port under the arbiter's Landlock wrap", async (t) => {
  const applier = resolveNativeBin("mandu-landlock-apply");
  if (!applier) { t.skip("the mandu-landlock-apply bin is not built (scripts/build-native.sh)"); return; }
  if (!probeLandlockNet(applier)) { t.skip("this kernel has no Landlock TCP rules (needs 6.7)"); return; }
  const classifier = Layout.dev(REPO_ROOT).policyClassifier();
  if (classifier === null) { t.skip("inspect-mcp has no node_modules"); return; }
  const a = await mock();
  const b = await mock();
  const dir = mkdtempSync(join(tmpdir(), "mdu-classifier-confine-"));
  const repo = join(dir, "home", "proj");
  mkdirSync(join(repo, "clients"), { recursive: true });
  writeFileSync(join(repo, "clients", "contract.txt"), "x\n");
  writeFileSync(join(repo, "README.md"), "x\n");
  writeFileSync(join(repo, "notes.md"), "x\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\nmodels:\n  - name: mock-cloud\n    url: ${a.url}\n    wire: anthropic\n    model: m-1\n    local: false\n`);
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: policy, policyPollMs: 0, confidentiality: true, integrity: false, log: () => {},
    policyClassifier: { argv: classifier, landlockApply: applier },
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  try {
    const p = await client.modelSuggestPreview([repo], { endpoint: "mock-cloud", home: join(dir, "home") });
    assert.deepEqual(p.confine, { live: true });
    const r = await client.modelSuggest(p.digest);
    assert.equal(r.error, null, r.error ?? "");
    assert.equal(r.counts.failedRequests, 0);
    assert.ok(a.hits >= 1, "the declared endpoint's port is reachable through the wrap");

    // The same wrap (A's port only) around the real classifier, dialing B.
    const entry = { name: "other", url: b.url, wire: "anthropic", local: false };
    const req = { v: 1, op: "classify", tier: "names", promptVersion: "names-1", endpoint: { kind: "declared", entry, all: [entry] }, batches: ['x\nd1 root 1 "a/"\n'], requestTimeoutMs: 5000, runTimeoutMs: 20_000 };
    const out = await spawnClassifier([...landlockWrap(applier, [a.port]), ...classifier], JSON.stringify(req) + "\n", { env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: dir }, timeoutMs: 60_000 });
    assert.deepEqual((JSON.parse(out.stdout) as { answers: unknown[] }).answers, [{ batch: 0, failed: "unreachable" }]);
    assert.equal(b.hits, 0, "another port is refused by the kernel");
  } finally {
    client.close();
    await server.close();
    a.server.close();
    b.server.close();
    resetCurrentPolicyForTests("claude-code");
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the contents tier: the classifier reaches only its local model's port under the wrap", async (t) => {
  const applier = resolveNativeBin("mandu-landlock-apply");
  if (!applier) { t.skip("the mandu-landlock-apply bin is not built (scripts/build-native.sh)"); return; }
  if (!probeLandlockNet(applier)) { t.skip("this kernel has no Landlock TCP rules (needs 6.7)"); return; }
  const classifier = Layout.dev(REPO_ROOT).policyClassifier();
  if (classifier === null) { t.skip("inspect-mcp has no node_modules"); return; }
  const a = await mock("openai");
  const b = await mock("openai");
  const dir = mkdtempSync(join(tmpdir(), "mdu-classifier-confine-t2-"));
  const repo = join(dir, "home", "proj");
  mkdirSync(join(repo, "docs"), { recursive: true });
  writeFileSync(join(repo, "docs", "notes.md"), "ordinary notes\n");
  writeFileSync(join(repo, "README.md"), "a readme\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\nmodels:\n  - name: own\n    url: ${a.url}\n    wire: openai-chat\n    model: llama3.2\n    local: true\n`);
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: policy, policyPollMs: 0, confidentiality: true, integrity: false, log: () => {},
    policyClassifier: { argv: classifier, landlockApply: applier },
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  try {
    const p = await client.modelSuggestPreview([repo], { tier: "contents", home: join(dir, "home") });
    assert.deepEqual(p.confine, { live: true });
    assert.equal(p.items, 2);
    const r = await client.modelSuggest(p.digest);
    assert.equal(r.error, null, r.error ?? "");
    assert.equal(r.counts.failedRequests, 0);
    assert.equal(a.hits, 2, "the local model's port is reachable through the wrap");

    // The same wrap (A's port only) around the real classifier, dialing B.
    const entry = { name: "other", url: b.url, wire: "openai-chat", model: "m", local: true };
    const req = { v: 1, op: "classify", tier: "contents", promptVersion: "contents-1", endpoint: { kind: "declared", entry, all: [entry] }, batches: ["Contents request contents-1.\nx\n"], requestTimeoutMs: 5000, runTimeoutMs: 20_000 };
    const out = await spawnClassifier([...landlockWrap(applier, [a.port]), ...classifier], JSON.stringify(req) + "\n", { env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: dir }, timeoutMs: 60_000 });
    assert.deepEqual((JSON.parse(out.stdout) as { answers: unknown[] }).answers, [{ batch: 0, failed: "unreachable" }]);
    assert.equal(b.hits, 0, "another port is refused by the kernel");
  } finally {
    client.close();
    await server.close();
    a.server.close();
    b.server.close();
    resetCurrentPolicyForTests("claude-code");
    rmSync(dir, { recursive: true, force: true });
  }
});
