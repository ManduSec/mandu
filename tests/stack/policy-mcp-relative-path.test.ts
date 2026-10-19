/**
 * policy-mcp-relative-path — the mandu-policy tool reads a relative path in
 * the project directory and refuses a path that does not exist (2026-10-04,
 * policy-surface.md §8.5.1), over the PRODUCTION wiring: the server's own
 * tools/call with `new PolicyArbiterAdapter(new ArbiterClient(sock))` and the
 * deps server-main builds from the launcher's environment (`envDeps`:
 * MANDU_PROJECT_DIR), against a real ArbiterServer in `secrets`.
 *
 *   - `lock-path .env` (relative) is applied as `<project>/.env`: the law on
 *     disk names the absolute path, the result states it under `resolved`,
 *     and the arbiter's classify trusts the envelope under the Mandu name;
 *   - `lock-path test/fixtures/.env` at `public` (a loosening) waits for the
 *     user, filed with the absolute path the user reviews; the law is
 *     unchanged;
 *   - `/.env` (the live slip: an absolute path at the root of the machine)
 *     and `../elsewhere/.env` are refused before the arbiter: nothing filed,
 *     nothing written; the problem names `<project>/.env`.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { classifyManduPolicyResult } from "../../arbiter/policy/policy-tool.js";
import { PolicyArbiterAdapter } from "../../interceptors/policy-mcp/src/arbiter-client.js";
import { handleRpc, type ServerDeps } from "../../interceptors/policy-mcp/src/mcp-server.js";
import { envDeps } from "../../interceptors/policy-mcp/src/server-main.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

test("the policy tool reads a relative path in the project directory and states the absolute path; `/.env` and a path out of the project are refused, nothing filed (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-policy-relpath-"));
  dirs.push(dir);
  const ws = join(dir, "proj");
  mkdirSync(join(ws, "test", "fixtures"), { recursive: true });
  writeFileSync(join(ws, ".env"), "API_KEY=x\n");
  writeFileSync(join(ws, "test", "fixtures", ".env"), "API_KEY=fixture\n");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${join(dir, "other.key")}\n    level: no-model\n`);
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"), policyPath, policyPollMs: 0,
    integrity: false, confidentiality: true, log: () => {},
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  try {
    await client.connect();
    // THE production wiring, with the deps server-main takes from the launcher's env.
    const deps: ServerDeps = { arbiter: new PolicyArbiterAdapter(client), ...envDeps({ MANDU_SCOPE_ID: "sess-relpath", MANDU_PROJECT_DIR: ws }) };
    assert.equal(deps.projectDir, ws);
    const propose = async (edits: unknown[]): Promise<{ text: string; env: Record<string, unknown> }> => {
      const r = await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "mandu_policy_propose", arguments: { edits, reason: "test" } } }, deps);
      const text = (r!.result as { content: Array<{ text: string }> }).content[0]!.text;
      // the envelope the model gets is trusted under the Mandu name (the gate and the envelope agree)
      assert.equal(classifyManduPolicyResult("mcp__mandu-policy__mandu_policy_propose", text).trust, "TRUSTED", text);
      return { text, env: JSON.parse(text) as Record<string, unknown> };
    };

    // a relative lock (a tightening): applied at the absolute path, stated back
    const lock = await propose([{ op: "lock-path", path: ".env", level: "no-model" }]);
    assert.equal(lock.env.applied, true, lock.text);
    assert.deepEqual(lock.env.resolved, [{ from: ".env", path: join(ws, ".env") }]);
    assert.ok(readFileSync(policyPath, "utf8").includes(`path: ${join(ws, ".env")}`), "the law on disk names the absolute path");

    // a relative loosening: waits for the user, filed at the absolute path
    const before = readFileSync(policyPath);
    const loose = await propose([{ op: "lock-path", path: "test/fixtures/.env", level: "public" }]);
    assert.equal(loose.env.applied, false, loose.text);
    assert.deepEqual(loose.env.resolved, [{ from: "test/fixtures/.env", path: join(ws, "test", "fixtures", ".env") }]);
    assert.ok(readFileSync(policyPath).equals(before), "a loosening does not touch the law");
    const pending = (await client.policyProposals("pending")).proposals;
    assert.equal(pending.length, 1);
    assert.ok(JSON.stringify(pending[0]).includes(join(ws, "test", "fixtures", ".env")), `the user reviews the absolute path: ${JSON.stringify(pending[0])}`);

    // the live slip and a path out of the project: refused before the arbiter
    for (const [path, problem] of [
      ["/.env", new RegExp(`/\\.env does not exist; did you mean ${join(ws, ".env").replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}\\?`)],
      ["../elsewhere/.env", /leaves the project directory/],
    ] as const) {
      const before2 = readFileSync(policyPath);
      const r = await propose([{ op: "lock-path", path, level: "no-model" }]);
      assert.equal(r.env.applied, false, r.text);
      assert.match(String((r.env.problems as string[])[0]), problem, r.text);
      assert.ok(readFileSync(policyPath).equals(before2), `${path}: nothing written`);
    }
    assert.equal((await client.policyProposals("pending")).proposals.length, 1, "nothing filed for a refused call");
  } finally {
    client.close();
    await server.close();
  }
});
