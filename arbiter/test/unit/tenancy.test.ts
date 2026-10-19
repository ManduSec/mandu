/**
 * tenancy.test — the arbiter half of live/test tenancy
 * (docs/design/ui/policy-surface.md §2.7).
 *
 * Pins, over the real IPC:
 *   - an UNTENANTED arbiter (no MANDU_TENANT / option) accepts events of
 *     either tenant and unstamped ones, stamps nothing, and reports
 *     `hello.tenant === null`; its `sessions` summary still surfaces the
 *     tenant a session's own events carry;
 *   - a `live` arbiter REFUSES a `test`-stamped emit with the catalog error
 *     (nothing persisted), accepts live-stamped events, and STAMPS unstamped
 *     events as live — so every session it holds is attributable;
 *   - a `test` arbiter is the mirror image;
 *   - `tenantFromEnv` parses live/test, treats unset/empty as untenanted, and
 *     throws on anything else (never a silent fallback).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer, tenantMismatchError } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { tenantFromEnv, type Tenant } from "../../events/event-store.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

async function up(tenant?: Tenant) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-tenancy-"));
  const socketPath = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath,
    humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "symbols.db"),
    eventDir: join(dir, "events"),
    log: () => {},
    // Explicit `undefined` would still fall back to the env; pin the untenanted
    // case by scrubbing the env for the construction.
    ...(tenant ? { tenant } : {}),
  });
  await server.listen();
  const client = new ArbiterClient(socketPath);
  await client.connect();
  // events / sessions are read over the human plane (arbiter-human-plane.md);
  // the interceptors emit on the data socket.
  const human = new ArbiterClient(join(dir, "human", "h.sock"));
  return {
    server,
    client,
    human,
    close: async () => {
      client.close();
      human.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

function ev(sessionId: string, extra: Record<string, unknown> = {}) {
  return { id: `${sessionId}-${Math.random().toString(36).slice(2)}`, sessionId, ts: new Date().toISOString(), ...extra };
}

test("untenanted arbiter: accepts any tenant, stamps nothing, hello.tenant is null, summaries surface the stamps", async () => {
  const saved = process.env.MANDU_TENANT;
  delete process.env.MANDU_TENANT;
  const h = await up();
  try {
    assert.equal((await h.client.hello()).tenant, null);
    await h.client.emit(ev("s-live", { tenant: "live" }));
    await h.client.emit(ev("s-test", { tenant: "test" }));
    await h.client.emit(ev("s-none"));
    const none = await h.human.events("s-none");
    assert.equal(none.length, 1);
    assert.equal((none[0] as { tenant?: unknown }).tenant, undefined, "untenanted → no stamp added");
    const byId = new Map((await h.human.sessions()).map((s) => [s.sessionId, s]));
    assert.equal(byId.get("s-live")?.tenant, "live");
    assert.equal(byId.get("s-test")?.tenant, "test");
    assert.equal(byId.get("s-none")?.tenant, undefined, "an unstamped session has no tenant in its summary");
  } finally {
    await h.close();
    if (saved !== undefined) process.env.MANDU_TENANT = saved;
  }
});

test("live arbiter: refuses test-stamped emits (nothing persisted), accepts live, stamps unstamped as live", async () => {
  const h = await up("live");
  try {
    assert.equal((await h.client.hello()).tenant, "live");
    await assert.rejects(
      () => h.client.emit(ev("s-harness", { tenant: "test" })),
      (err: Error) => {
        assert.equal(err.message, tenantMismatchError("live", "test"));
        return true;
      },
    );
    assert.equal((await h.human.events("s-harness")).length, 0, "the refused event was never persisted");
    await h.client.emit(ev("s-human", { tenant: "live" }));
    await h.client.emit(ev("s-legacy"));
    const legacy = await h.human.events("s-legacy");
    assert.equal((legacy[0] as { tenant?: unknown }).tenant, "live", "a tenanted arbiter labels unstamped events as its own");
    const byId = new Map((await h.human.sessions()).map((s) => [s.sessionId, s]));
    assert.equal(byId.get("s-human")?.tenant, "live");
    assert.equal(byId.get("s-legacy")?.tenant, "live");
    assert.equal(byId.has("s-harness"), false, "no session file exists for the refused emit");
  } finally {
    await h.close();
  }
});

test("test arbiter: the mirror image — live-stamped emits are refused, test and unstamped land as test", async () => {
  const h = await up("test");
  try {
    assert.equal((await h.client.hello()).tenant, "test");
    await assert.rejects(() => h.client.emit(ev("s-real", { tenant: "live" })), /tenant mismatch/);
    await h.client.emit(ev("s-e2e", { tenant: "test" }));
    await h.client.emit(ev("s-plain"));
    const byId = new Map((await h.human.sessions()).map((s) => [s.sessionId, s]));
    assert.equal(byId.get("s-e2e")?.tenant, "test");
    assert.equal(byId.get("s-plain")?.tenant, "test");
  } finally {
    await h.close();
  }
});

test("tenantFromEnv: live/test parse, unset/empty = untenanted, anything else throws", () => {
  assert.equal(tenantFromEnv({ MANDU_TENANT: "live" }), "live");
  assert.equal(tenantFromEnv({ MANDU_TENANT: "test" }), "test");
  assert.equal(tenantFromEnv({}), undefined);
  assert.equal(tenantFromEnv({ MANDU_TENANT: "" }), undefined);
  assert.throws(() => tenantFromEnv({ MANDU_TENANT: "staging" }), /must be "live" or "test"/);
  assert.throws(() => tenantFromEnv({ MANDU_TENANT: "TEST" }), /must be "live" or "test"/, "case-sensitive: no silent coercion");
});
