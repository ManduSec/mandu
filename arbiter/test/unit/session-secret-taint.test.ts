/**
 * session-secret-taint.test.ts — the `sessionSecretTaint` op (plan 13 D6):
 * the net-proxy's question for a connection it cannot attribute to a
 * process. "Does any process of this session hold a secret?" is yes exactly
 * when a raw read of a secret is on record for the session, and the answer
 * names the files, never their contents.
 *
 * A real ArbiterServer on a temp socket, a real ArbiterClient. Mandu-new (no
 * reference origin).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis: raw reads are recorded

test("sessionSecretTaint: yes for the session a reader read raw in, no for another session; names files, never bytes", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sst-"));
  const p = join(dir, ".env");
  writeFileSync(p, "STRIPE_KEY=sk_live_sessiontaint123456\n");
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: p, level: "no-model", bindings: ["api.stripe.com"], readers: ["ssh-add"] }] },
  });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's and the proxy's channel (plan 13 D9)
  await c.connect();
  try {
    assert.deepEqual(await c.sessionSecretTaint({ session: "sess-a" }), { tainted: false, level: null, files: [] }, "nothing read yet");
    assert.ok((await c.registerSecret({ path: p })).symbol);
    const raw = await c.decideSecretOpen({ path: p, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "sst-sh-1", session: "sess-a" });
    assert.equal(raw.verdict, "raw");
    const a = await c.sessionSecretTaint({ session: "sess-a" });
    assert.equal(a.tainted, true);
    assert.equal(a.level, "no-model");
    assert.deepEqual(a.files, [p]);
    assert.ok(!JSON.stringify(a).includes("sk_live_sessiontaint123456"), "the answer carries no secret byte");
    assert.deepEqual(await c.sessionSecretTaint({ session: "sess-b" }), { tainted: false, level: null, files: [] }, "another session holds nothing");
    assert.equal((await c.sessionSecretTaint()).tainted, true, "no session named ⇒ every session");
  } finally {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sessionSecretTaint: the confidentiality axis OFF ⇒ nothing is held", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sst-off-"));
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: false, integrity: false,
  });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's and the proxy's channel (plan 13 D9)
  await c.connect();
  try {
    await c.taintProcessSecret({ procKey: "off-1", path: join(dir, "x"), level: "no-model", app: "ssh-add", session: "s" });
    assert.deepEqual(await c.sessionSecretTaint({ session: "s" }), { tainted: false, level: null, files: [] });
  } finally {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
