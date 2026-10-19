/**
 * session-spec-scope.test.ts — the `setSessionSpec` bindings belong to ONE
 * arbiter (agent-e2e-harness.md §4, 2026-10-09), over the real IPC.
 *
 * The bug: the bindings were a map in the policy module, so they outlived the
 * ArbiterServer that made them. On 2026-10-09 the differential drill lane ran
 * OpenClaw and then OpenCode on the same scenario in one test process, each
 * with its own fresh in-process arbiter: OpenClaw's arbiter bound
 * `diff-fidelity-two-turn-prose-wrapped` to `openclaw-agent`, and OpenCode's
 * arbiter then refused `opencode` for the same key ("already bound … specs
 * are bind-once"), so its anthropic-proxy exited at startup. Worse than the
 * refusal, a second arbiter resolved that session by the FIRST one's binding.
 *
 * Pinned here, two real ArbiterServers in one process:
 *   - each binds the same session key to a different spec, and each resolves
 *     it by its own binding: the gate surface (server-side lookups) and
 *     classify's confidentiality derivation (the engine's lookups);
 *   - within one arbiter bind-once still holds: another spec is refused, the
 *     same spec is a no-op, a session with classified traffic cannot bind,
 *     and a policy rebuild keeps the bindings (the registry, not the engine,
 *     owns them);
 *   - close releases the server's bindings, and the module's process
 *     registry is never touched by a server.
 *
 * Mandu-new test. Real ArbiterServers on temp sockets, the real client.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { SessionSpecs, sessionSpecBindings } from "../../policy/tool-inbound.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const CREDS = join(homedir(), ".aws", "credentials"); // the catalog's no-model prefix
const SESSION = "diff-fidelity-two-turn-prose-wrapped"; // the key of the 2026-10-09 collision

interface Arb { server: ArbiterServer; client: ArbiterClient; dir: string; close(): Promise<void> }

async function arbiter(sessionSpecs?: SessionSpecs): Promise<Arb> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sspec-scope-"));
  const sock = join(dir, "a.sock");
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false, adminPolicyDir: null,
    ...(sessionSpecs ? { sessionSpecs } : {}),
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  let closed = false;
  return {
    server, client, dir,
    async close() {
      if (closed) return;
      closed = true;
      client.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** OpenClaw's `read` with an unrelated key naming a no-model path: a session
 *  whose spec maps `read` (openclaw-agent) reads only its named params →
 *  public; one whose spec does not (claude-code: `Read`, not `read`) scans
 *  every input string → no-model (plan 10 §11.11). The verdict therefore
 *  says which spec the ENGINE resolved the session to. */
async function readLevel(c: ArbiterClient, sessionKey: string): Promise<string | undefined> {
  const r = await c.classify({
    tool: "read", value: "hello", boundary: "model_context",
    sessionKey, params: { path: "/tmp/notes.md", note: CREDS },
  });
  return r.confidentiality;
}

test("two arbiters in one process bind the same session independently, and each resolves it by its own binding", async () => {
  const a = await arbiter();
  const b = await arbiter();
  try {
    const ra = await a.client.setSessionSpec({ sessionKey: SESSION, spec: "openclaw-agent", requestedBy: "scope e2e" });
    assert.deepEqual({ bound: ra.bound, applied: ra.applied }, { bound: "openclaw-agent", applied: true });
    // The 2026-10-09 refusal: a fresh arbiter asked for another spec on the key.
    const rb = await b.client.setSessionSpec({ sessionKey: SESSION, spec: "claude-code", requestedBy: "scope e2e" });
    assert.deepEqual({ bound: rb.bound, applied: rb.applied }, { bound: "claude-code", applied: true });

    // Server-side lookups (the gate surface the exec/net/path gates read).
    assert.equal((await a.client.gateSurface(SESSION)).spec, "openclaw-agent");
    assert.equal((await b.client.gateSurface(SESSION)).spec, "claude-code");
    // The engine's lookups (classify): each arbiter's own binding, not the other's.
    assert.equal(await readLevel(a.client, SESSION), "public", "openclaw-agent maps `read`: only its named params are read");
    assert.equal(await readLevel(b.client, SESSION), "no-model", "claude-code does not map `read`: every input string is read");

    // No server touches the module's process registry.
    assert.equal(sessionSpecBindings().size, 0);
  } finally {
    await a.close();
    await b.close();
  }
});

test("an arbiter's binding never reaches another arbiter's classify: the other falls back to its boot spec", async () => {
  const a = await arbiter();
  const b = await arbiter();
  try {
    await a.client.setSessionSpec({ sessionKey: SESSION, spec: "openclaw-agent" });
    assert.equal((await b.client.gateSurface(SESSION)).spec, "claude-code", "unbound on b: the boot spec");
    assert.equal(await readLevel(b.client, SESSION), "no-model", "b over-symbolizes its unbound session (fail-closed), not a's grant");
  } finally {
    await a.close();
    await b.close();
  }
});

test("within one arbiter bind-once holds: another spec is refused, the same is a no-op, traffic closes binding, a policy rebuild keeps it", async () => {
  const a = await arbiter();
  try {
    await a.client.setSessionSpec({ sessionKey: SESSION, spec: "openclaw-agent" });
    await assert.rejects(
      () => a.client.setSessionSpec({ sessionKey: SESSION, spec: "claude-code" }),
      /already bound to 'openclaw-agent' — specs are bind-once/,
    );
    // An unknown spec id is the fail-closed spec, a different id: refused too.
    await assert.rejects(() => a.client.setSessionSpec({ sessionKey: SESSION, spec: "no-such-agent" }), /bind-once/);
    const again = await a.client.setSessionSpec({ sessionKey: SESSION, spec: "openclaw-agent" });
    assert.equal(again.bound, "openclaw-agent", "the same spec again: idempotent");

    // A session that classified before binding cannot bind at all.
    await readLevel(a.client, "s-live");
    await assert.rejects(
      () => a.client.setSessionSpec({ sessionKey: "s-live", spec: "openclaw-agent" }),
      /already classified traffic/,
    );

    // A rebuilt engine (the admin layer re-read) keeps the server's bindings.
    assert.deepEqual(a.server.reloadAdminLayer(), { ok: true });
    assert.equal(await readLevel(a.client, SESSION), "public", "still resolved as openclaw-agent after the rebuild");
    await assert.rejects(() => a.client.setSessionSpec({ sessionKey: SESSION, spec: "claude-code" }), /bind-once/);
  } finally {
    await a.close();
  }
});

test("close releases the server's bindings, and a fresh arbiter binds the key from scratch", async () => {
  const specs = new SessionSpecs();
  const a = await arbiter(specs);
  try {
    await a.client.setSessionSpec({ sessionKey: SESSION, spec: "openclaw-agent" });
    assert.equal(specs.specOf(SESSION), "openclaw-agent", "the server binds in the registry it was given");
  } finally {
    await a.close();
  }
  assert.equal(specs.bindings().size, 0, "close released the bindings");

  const c = await arbiter();
  try {
    const r = await c.client.setSessionSpec({ sessionKey: SESSION, spec: "opencode" });
    assert.equal(r.bound, "opencode");
    assert.equal((await c.client.gateSurface(SESSION)).spec, "opencode");
  } finally {
    await c.close();
  }
  assert.equal(sessionSpecBindings().size, 0);
});
