/**
 * path-denial-notice — a write the derived-label hook refused explains itself
 * to the model, over the REAL arbiter and the anthropic-proxy's PRODUCTION
 * adapter, `secrets` axes (confidentiality plan 10 §11.8, "Path denials").
 *
 * A HIGH session writes a RELATIVE path: the arbiter cannot key a label on it
 * and refuses, so fs-label rewrites the field to its sentinel
 * (`/dev/null/mandu-unlabeled/<path>`) and nothing is written. Claude Code's
 * error comes back next turn. Before this change that error reached the
 * model as one `$MDU:nomodel_Write[…]` whenever the path looked secret (the
 * classify path scan reads the sentinel, and `.env` is a catalog shape), and
 * as the harness's bare error otherwise: either way, no word of why. Now the
 * result is replaced by Mandu's own notice, built from the proxy's record;
 * no byte of the tool's output is forwarded, so a registered secret placed
 * in the harness error never reaches the upstream.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { SseToolUseParser, type ReconstructedToolUse } from "../../interceptors/anthropic-proxy/src/sse-parser.js";
import { MockUpstream, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

test("a refused write in a HIGH session explains itself: Mandu's notice replaces the tool's error, secret-shaped path or not (secrets axes, production adapter)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-path-denial-"));
  const home = join(tmp, "home");
  const contracts = join(home, "contracts");
  const vault = join(home, "vault");
  mkdirSync(contracts, { recursive: true });
  mkdirSync(vault, { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` mode axes, stated
  });
  await server.listen();
  const real = new ArbiterClient(socketPath); await real.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const session = `path-denial-${process.pid}`;
  // A per-run value, registered as a no-model secret below: never a literal.
  const canary = `path-denial-${randomBytes(16).toString("hex")}`;
  let proxy: AnthropicProxy | null = null;
  try {
    await admin.setPathLabel({ path: vault, confidentiality: "no-model" });
    await admin.symbolizeFull({ tool: "Read", value: canary, field: "content", origin: join(vault, "key.txt"), integrity: "trusted", sessionKey: session });
    await admin.setPathLabel({ path: contracts, confidentiality: "any-model", bindings: ["docs.corp"] });
    const sym = await admin.symbolizeFull({ tool: "read", value: "Acme pays $4,200,000 on 2026-09-30.", field: "content", origin: join(contracts, "c.md"), integrity: "trusted", sessionKey: session });
    assert.equal((await admin.declassifySymbol({ symbol: sym.symbol, sessionKey: session })).allowed, true);
    assert.equal((await admin.sessionState(session)).high, true, "the session is HIGH");

    const up = new MockUpstream({
      sse:
        buildToolUseSse({ id: "tu_env", name: "Write", input: { file_path: "config/.env", content: "MODE=1\n" }, index: 0 }) +
        buildToolUseSse({ id: "tu_yaml", name: "Write", input: { file_path: "config/app.yaml", content: "mode: 1\n" }, index: 1 }),
    });
    proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey: session, log: () => {} });
    const port = await proxy.listen(0);
    const post = async (messages: unknown[]): Promise<string> => {
      const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "claude-sonnet-5", stream: true, messages }),
      });
      assert.equal(res.status, 200);
      return res.text();
    };

    // Turn 1: both writes reach the agent as the unlabeled sentinel.
    const seen: ReconstructedToolUse[] = [];
    const p = new SseToolUseParser((tu) => seen.push(tu));
    p.feed(await post([{ role: "user", content: "write the config" }]));
    p.end();
    const delivered = new Map(seen.map((t) => [t.id, t.input as { file_path: string; content: string }]));
    assert.equal(delivered.get("tu_env")!.file_path, "/dev/null/mandu-unlabeled/config/.env");
    assert.equal(delivered.get("tu_yaml")!.file_path, "/dev/null/mandu-unlabeled/config/app.yaml");

    // Turn 2: Claude Code's errors come back; the .env one carries a
    // registered secret, standing for any byte the tool might have added.
    const err = (path: string, extra = ""): string => `<tool_use_error>ENOTDIR: not a directory, mkdir '${path.slice(0, path.lastIndexOf("/"))}'${extra}</tool_use_error>`;
    await post([
      { role: "user", content: "write the config" },
      { role: "assistant", content: [
        { type: "tool_use", id: "tu_env", name: "Write", input: delivered.get("tu_env") },
        { type: "tool_use", id: "tu_yaml", name: "Write", input: delivered.get("tu_yaml") },
      ] },
      { role: "user", content: [
        { type: "tool_result", tool_use_id: "tu_env", content: err(delivered.get("tu_env")!.file_path, ` ${canary}`), is_error: true },
        { type: "tool_result", tool_use_id: "tu_yaml", content: err(delivered.get("tu_yaml")!.file_path), is_error: true },
      ] },
    ]);
    const body = up.requests[1]!.json() as { messages: Array<{ content: unknown }> };
    const results = new Map((body.messages[2]!.content as Array<{ tool_use_id: string; content: unknown }>).map((b) => [b.tool_use_id, String(b.content)]));
    for (const [id, path] of [["tu_env", "config/.env"], ["tu_yaml", "config/app.yaml"]] as const) {
      const text = results.get(id)!;
      assert.match(text, /^mandu-fs-gate: denied, nothing was read or written: /, `${id}: the model reads Mandu's notice: ${text.slice(0, 80)}`);
      assert.ok(text.includes(path), `${id}: the notice names the path`);
      assert.match(text, /the session is HIGH/, `${id}: and why`);
      assert.ok(!text.includes("$MDU:"), `${id}: no symbol stands in for Mandu's notice`);
      assert.ok(!text.includes("ENOTDIR"), `${id}: no byte of the tool's output is forwarded`);
    }
    for (const r of up.requests) assert.ok(!r.bodyText.includes(canary), "the registered secret never reaches the upstream");
  } finally {
    await proxy?.close().catch(() => {});
    real.close(); admin.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
