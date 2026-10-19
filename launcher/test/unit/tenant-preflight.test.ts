/**
 * tenant-preflight.test — the launcher half of live/test tenancy
 * (docs/design/ui/policy-surface.md §2.7): a launch refuses to start
 * against an arbiter that declares the OTHER tenant, passes an untenanted
 * (legacy) arbiter, and proceeds with a warning when hello is unreadable.
 *
 * A fake arbiter (raw NDJSON `hello` over a temp Unix socket) stands in for
 * the daemon; nothing else is spawned.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { assertArbiterTenant, readArbiterTenant, TenantMismatchError } from "../../src/tenant-preflight.js";

function fakeArbiter(answer: (op: string) => unknown | null): Promise<{ sock: string; close: () => Promise<void> }> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-tenant-preflight-"));
  const sock = join(dir, "arbiter.sock");
  const server: Server = createServer((c) => {
    let buf = "";
    c.setEncoding("utf8");
    c.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      const req = JSON.parse(buf.slice(0, nl)) as { id: unknown; op: string };
      buf = buf.slice(nl + 1);
      const result = answer(req.op);
      if (result === null) return; // never answers → the caller's deadline decides
      c.write(JSON.stringify({ id: req.id, ok: true, result }) + "\n");
    });
  });
  return new Promise((resolve) => {
    server.listen(sock, () =>
      resolve({
        sock,
        close: () =>
          new Promise<void>((r) => {
            server.close(() => {
              rmSync(dir, { recursive: true, force: true });
              r();
            });
          }),
      }),
    );
  });
}

test("readArbiterTenant: live / test / null (untenanted) / garbage→null / unreadable→undefined", async () => {
  for (const [declared, expected] of [
    ["live", "live"],
    ["test", "test"],
    [null, null],
    ["staging", null],
    [undefined, null],
  ] as const) {
    const a = await fakeArbiter(() => ({ pid: 1, ...(declared === undefined ? {} : { tenant: declared }) }));
    try {
      assert.equal(await readArbiterTenant(a.sock), expected, `declared ${String(declared)}`);
    } finally {
      await a.close();
    }
  }
  const silent = await fakeArbiter(() => null);
  try {
    assert.equal(await readArbiterTenant(silent.sock, 150), undefined, "no answer within the deadline → undefined");
  } finally {
    await silent.close();
  }
  assert.equal(await readArbiterTenant("/nonexistent/mandu-preflight.sock", 150), undefined, "connect failure → undefined");
});

test("assertArbiterTenant: mismatch throws with the remedy, same tenant passes, untenanted passes", async () => {
  const live = await fakeArbiter(() => ({ tenant: "live" }));
  try {
    await assert.rejects(
      () => assertArbiterTenant(live.sock, "test"),
      (err: Error) => {
        assert.ok(err instanceof TenantMismatchError);
        assert.match(err.message, /test-tenant arbiter/);
        assert.match(err.message, /never the live one/);
        return true;
      },
    );
    assert.deepEqual(await assertArbiterTenant(live.sock, "live"), { arbiterTenant: "live" });
  } finally {
    await live.close();
  }
  const testArb = await fakeArbiter(() => ({ tenant: "test" }));
  try {
    await assert.rejects(() => assertArbiterTenant(testArb.sock, "live"), /must not land in the test store/);
  } finally {
    await testArb.close();
  }
  const legacy = await fakeArbiter(() => ({ pid: 7 }));
  try {
    assert.deepEqual(await assertArbiterTenant(legacy.sock, "test"), { arbiterTenant: null });
    assert.deepEqual(await assertArbiterTenant(legacy.sock, "live"), { arbiterTenant: null });
  } finally {
    await legacy.close();
  }
});

test("assertArbiterTenant: an unreadable hello warns and proceeds (tenancy is hygiene, not the invariant)", async () => {
  const silent = await fakeArbiter(() => null);
  const warnings: string[] = [];
  try {
    const r = await assertArbiterTenant(silent.sock, "live", { timeoutMs: 150, warn: (m) => warnings.push(m) });
    assert.deepEqual(r, { arbiterTenant: undefined });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!, /could not read the arbiter's tenant/);
  } finally {
    await silent.close();
  }
});
