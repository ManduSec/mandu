/**
 * session-spec.test.ts — ONE arbiter serving MIXED agents over the real IPC
 * socket (agent-e2e-harness.md §7.1, session-keyed inbound specs).
 *
 * Mandu-new test. The unit half (arbiter/test/integrity/multi-agent-policy.test.ts,
 * session-keyed section) proves the pure resolution logic; this file proves the
 * WIRE: the `setSessionSpec` op binds, `classify` carries `sessionKey`, and two
 * concurrent sessions on the SAME arbiter process resolve the SAME tool name
 * against different agents' specs — with fail-closed fallbacks at every miss
 * (unbound session → global spec; unknown spec id → the empty "fail-closed"
 * spec, never another agent's TRUSTED grants).
 *
 * Run: npm run test:integrity   (or: npx tsx --test test/integrity/session-spec.test.ts)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

test("one arbiter, mixed agents: per-session specs over the real IPC", async () => {
  const workdir = mkdtempSync(join(tmpdir(), "mandu-e2e-sspec-"));
  const server = new ArbiterServer({
    socketPath: join(workdir, "arbiter.sock"),
    dbPath: join(workdir, "symbols.db"),
    eventDir: join(workdir, "events"),
    log: () => {},
  });
  await server.listen();
  const client = new ArbiterClient(join(workdir, "arbiter.sock"));
  try {
    await client.connect();

    // ── Bind two real agents + one bogus declaration. ──
    const a = await client.setSessionSpec({
      sessionKey: "s-opencode",
      spec: "opencode",
      requestedBy: "session-spec e2e",
    });
    assert.deepEqual({ bound: a.bound, applied: a.applied }, { bound: "opencode", applied: true });

    const b = await client.setSessionSpec({ sessionKey: "s-openclaw", spec: "openclaw-agent" });
    assert.equal(b.applied, true);

    // FAIL-CLOSED: an unknown spec id binds the empty spec, not claude-code.
    const c = await client.setSessionSpec({ sessionKey: "s-bogus", spec: "no-such-agent" });
    assert.deepEqual({ bound: c.bound, applied: c.applied }, { bound: "fail-closed", applied: false });

    // ── The SAME tool name, four sessions, four independent verdicts. ──
    const glob = { tool: "glob", value: "a.ts\nb.ts", boundary: "model_context" as const, params: {} };
    assert.equal(
      (await client.classify({ ...glob, sessionKey: "s-opencode" })).trust,
      "TRUSTED",
      "opencode maps `glob` TRUSTED — the utility half the binding exists for",
    );
    assert.equal(
      (await client.classify({ ...glob, sessionKey: "s-openclaw" })).trust,
      "UNTRUSTED",
      "openclaw-agent has no `glob` → fail-closed, no leak from the sibling session",
    );
    assert.equal(
      (await client.classify(glob)).trust,
      "UNTRUSTED",
      "no sessionKey → the global claude-code boot spec (lowercase `glob` unmapped)",
    );
    assert.equal(
      (await client.classify({ ...glob, sessionKey: "s-unbound" })).trust,
      "UNTRUSTED",
      "an unbound sessionKey falls back to the global spec",
    );

    // A tool BOTH bound agents map (write → TRUSTED) still resolves TRUSTED
    // per-session, while the fail-closed-bound session gets nothing at all.
    const write = { tool: "write", value: "wrote 3 lines", boundary: "model_context" as const, params: {} };
    assert.equal((await client.classify({ ...write, sessionKey: "s-openclaw" })).trust, "TRUSTED");
    assert.equal(
      (await client.classify({ ...write, sessionKey: "s-bogus" })).trust,
      "UNTRUSTED",
      "the fail-closed binding symbolizes EVERYTHING — the declared-but-unknown agent",
    );

    // ── Wire validation errors, not silent acceptance. ──
    await assert.rejects(
      () => client.setSessionSpec({ sessionKey: "", spec: "opencode" }),
      /sessionKey required/,
    );
  } finally {
    client.close();
    await server.close();
    rmSync(workdir, { recursive: true, force: true });
  }
});
