/**
 * axis-preflight.test — an EXPLICIT axis flag must match the attached arbiter
 * (axis-preflight.ts): mismatch refuses, an unset axis is never checked, an
 * arbiter that cannot report its axes passes with a warning, and the
 * `policySnapshot.posture` fallback is honored.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assertArbiterAxes, readArbiterAxes, AxisMismatchError } from "../../src/axis-preflight.js";

function fakeArbiter(answer: (op: string) => unknown | null): Promise<{ sock: string; close: () => Promise<void> }> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-axis-preflight-"));
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
      if (result === null) return;
      c.write(JSON.stringify({ id: req.id, ok: true, result }) + "\n");
    });
  });
  return new Promise((resolve) => {
    server.listen(sock, () => resolve({
      sock,
      close: () => new Promise<void>((r) => { server.close(() => { rmSync(dir, { recursive: true, force: true }); r(); }); }),
    }));
  });
}

test("a resident int-ON arbiter refuses --no-integrity (the C7 half-posture) and accepts a matching or unset axis", async () => {
  // the REAL hello shape: axes at the top level, beside tenant / gitRev
  const a = await fakeArbiter((op) => (op === "hello" ? { tenant: "live", gitRev: "abc1234", integrity: true, confidentiality: true } : null));
  try {
    await assert.rejects(assertArbiterAxes(a.sock, { integrity: false }), (e: unknown) => {
      assert.ok(e instanceof AxisMismatchError);
      // protection-modes.md §3.4: the refusal names the RUNNING mode, the mode
      // the flags asked for, and the command that changes it for every session.
      assert.match((e as Error).message, /mode secrets cannot take effect/);
      assert.match((e as Error).message, /already running in mode full/);
      assert.match((e as Error).message, /integrity would have to be OFF/);
      assert.match((e as Error).message, /`mandu mode secrets`, then `mandu stop`/);
      assert.match((e as Error).message, /MANDU_INTEGRITY=0 scripts\/dev-arbiter\.sh/);
      return true;
    });
    await assert.rejects(assertArbiterAxes(a.sock, { confidentiality: false }), AxisMismatchError);
    assert.deepEqual(await assertArbiterAxes(a.sock, { integrity: true, confidentiality: true }), { integrity: true, confidentiality: true });
    assert.deepEqual(await assertArbiterAxes(a.sock, {}), {}, "nothing explicit → nothing asked, nothing checked");
    assert.deepEqual(await assertArbiterAxes(a.sock, { integrity: undefined, confidentiality: undefined }), {});
    assert.deepEqual(
      await assertArbiterAxes(a.sock, {}, { readAlways: true }),
      { integrity: true, confidentiality: true },
      "readAlways: nothing asked, nothing refused, but the launcher learns the running pair (the effective mode)",
    );
  } finally {
    await a.close();
  }
});

test("the dangerous direction: --integrity against an int-OFF arbiter refuses too", async () => {
  const a = await fakeArbiter((op) => (op === "hello" ? { identity: { integrity: false, confidentiality: true } } : null));
  try {
    await assert.rejects(assertArbiterAxes(a.sock, { integrity: true }), (e: unknown) => {
      assert.match((e as Error).message, /mode full cannot take effect/);
      assert.match((e as Error).message, /already running in mode secrets/);
      return true;
    });
  } finally {
    await a.close();
  }
});

test("policySnapshot.posture is the fallback; an arbiter reporting neither passes with a warning", async () => {
  const snap = await fakeArbiter((op) => (op === "hello" ? { tenant: "live" } : op === "policySnapshot" ? { posture: { integrity: false, confidentiality: true } } : null));
  try {
    assert.deepEqual(await readArbiterAxes(snap.sock), { integrity: false, confidentiality: true });
    assert.deepEqual(await assertArbiterAxes(snap.sock, { integrity: false }), { integrity: false, confidentiality: true });
    await assert.rejects(assertArbiterAxes(snap.sock, { integrity: true }), AxisMismatchError);
  } finally {
    await snap.close();
  }
  const old = await fakeArbiter((op) => (op === "hello" ? { tenant: "live" } : op === "policySnapshot" ? {} : null));
  try {
    const warns: string[] = [];
    assert.deepEqual(await assertArbiterAxes(old.sock, { integrity: false }, { warn: (m) => warns.push(m) }), {});
    assert.equal(warns.length, 1);
    assert.match(warns[0]!, /could not read the arbiter's integrity axis/);
  } finally {
    await old.close();
  }
});
