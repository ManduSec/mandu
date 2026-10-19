/**
 * holder-bindings-intersection.test.ts — confidentiality plan 13 D1 (and its
 * session twin, §9 R3): a holder of several secrets may send only where EVERY
 * one of them may go. The bindings of a process that read `.env` (bound to
 * api.stripe.com) and `~/.aws/credentials` (bound to *.amazonaws.com) are
 * their INTERSECTION — here nothing — never the union that let the AWS key go
 * to Stripe. The same for the session watermark after two in-context reads.
 *
 * Three layers: the pure join (`intersectBindings` / `bindingCovers`), the
 * network exit over IPC (`taintedProcessBindings` on a real ArbiterServer,
 * the answer the guard and the net-proxy enforce), and the session store.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { bindingCovers, intersectBindings } from "../../policy/flow-taint.js";
import { SessionLabelStore } from "../../policy/session-labels.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis: where a holder's bytes may go

// ── the pure join ───────────────────────────────────────────────────────────

test("intersectBindings: disjoint sets give nothing; one set is itself; a shared host survives", () => {
  assert.deepEqual(intersectBindings([["api.stripe.com"], ["*.amazonaws.com"]]), []);
  assert.deepEqual(intersectBindings([["b.example", "a.example"]]), ["a.example", "b.example"]);
  assert.deepEqual(intersectBindings([["a.example", "b.example"], ["b.example", "c.example"]]), ["b.example"]);
  assert.deepEqual(intersectBindings([]), [], "no datum: nothing is bound (the caller never asks this for an untainted holder)");
  assert.deepEqual(intersectBindings([["a.example"], []]), [], "a datum bound nowhere empties the holder's set");
});

test("intersectBindings: a narrower destination inside a wildcard is kept, the wildcard is not", () => {
  assert.deepEqual(intersectBindings([["*.amazonaws.com"], ["s3.amazonaws.com"]]), ["s3.amazonaws.com"]);
  assert.deepEqual(intersectBindings([["*.amazonaws.com"], ["*.s3.amazonaws.com"]]), ["*.s3.amazonaws.com"]);
  // a port narrows; a port-less host admits every port of that host
  assert.deepEqual(intersectBindings([["db.internal"], ["db.internal:5432"]]), ["db.internal:5432"]);
  assert.deepEqual(intersectBindings([["db.internal:5432"], ["db.internal:6543"]]), []);
  // case does not split a host
  assert.deepEqual(intersectBindings([["API.Stripe.com"], ["api.stripe.com"]]).map((b) => b.toLowerCase()), ["api.stripe.com"]);
});

test("bindingCovers is conservative: CIDR, IPv6 and unix: only by equality; a wildcard never covers its apex", () => {
  assert.equal(bindingCovers("10.0.0.0/8", "10.1.2.3"), false);
  assert.equal(bindingCovers("10.0.0.0/8", "10.0.0.0/8"), true);
  assert.equal(bindingCovers("[::1]:443", "[::1]:443"), true);
  assert.equal(bindingCovers("unix:/run/postgresql", "unix:/run/postgresql"), true);
  assert.equal(bindingCovers("unix:/run", "unix:/run/postgresql"), false);
  assert.equal(bindingCovers("*.amazonaws.com", "amazonaws.com"), false);
  assert.equal(bindingCovers("s3.amazonaws.com", "*.amazonaws.com"), false);
  assert.equal(bindingCovers("*", "evil.example"), false, "a bare * is not a pattern this join widens to");
});

test("plan 13 §9 R4 (b): a mount: binding is compared by equality, case kept, and survives the join only when every datum has it", () => {
  const nas = "mount:nfs4:NAS.lan:/export/home";
  assert.equal(bindingCovers(nas, nas), true);
  assert.equal(bindingCovers(nas, nas.toLowerCase()), false, "a mount source is a path: case is kept");
  assert.equal(bindingCovers("mount:nfs4:nas.lan:/export", "mount:nfs4:nas.lan:/export/home"), false, "no prefix match");
  assert.equal(bindingCovers("mount:fuse.sshfs:u@host:/srv", "host"), false);
  assert.equal(bindingCovers("host", "mount:fuse.sshfs:u@host:/srv"), false);
  assert.deepEqual(intersectBindings([[nas, "api.example.com"], [nas]]), [nas]);
  assert.deepEqual(intersectBindings([[nas], ["api.example.com"]]), []);
});

// ── the network exit: taintedProcessBindings over IPC ────────────────────────

async function withArbiter(
  paths: Array<{ name: string; content: string; bindings?: string[] }>,
  fn: (c: ArbiterClient, files: string[]) => Promise<void>,
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-d1-"));
  const files = paths.map((p) => {
    const f = join(dir, p.name);
    writeFileSync(f, p.content);
    return f;
  });
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: {
      version: 1,
      paths: paths.map((p, i) => ({ path: files[i]!, level: "no-model", readers: ["ssh-add"], ...(p.bindings ? { bindings: p.bindings } : {}) })),
    },
  });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's and the proxy's channel (plan 13 D9)
  await c.connect();
  try {
    for (const f of files) assert.ok((await c.registerSecret({ path: f })).symbol, `registered ${f}`);
    await fn(c, files);
  } finally {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test("D1: a process that read two secrets with disjoint bindings may send to NEITHER host (today: either)", async () => {
  await withArbiter([
    { name: ".env", content: "STRIPE_KEY=sk_live_d1canary000001\n", bindings: ["api.stripe.com"] },
    { name: "credentials", content: "[default]\naws_secret_access_key=d1canaryAWS0000000000000000000000000000\n", bindings: ["*.amazonaws.com"] },
  ], async (c, [env, aws]) => {
    for (const path of [env!, aws!]) {
      assert.equal((await c.decideSecretOpen({ path, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "d1-sh-1", parentKey: "d1-agent-0" })).verdict, "raw");
    }
    const b = await c.taintedProcessBindings({ procKey: "d1-sh-1" });
    assert.equal(b.tainted, true);
    assert.deepEqual([...b.files].sort(), [aws!, env!].sort());
    assert.deepEqual(b.bindings, [], "holding both keys: the intersection of {api.stripe.com} and {*.amazonaws.com} is empty");
    // the child inherits the same (it holds both through its parent)
    const child = await c.taintedProcessBindings({ procKey: "d1-curl-2", ancestors: ["d1-sh-1"] });
    assert.deepEqual(child.bindings, []);
  });
});

test("D1: one secret alone keeps its own bindings (the single-file case is unchanged)", async () => {
  await withArbiter([
    { name: ".env", content: "STRIPE_KEY=sk_live_d1canary000002\n", bindings: ["api.stripe.com", "db.internal:5432"] },
    { name: "credentials", content: "aws_secret_access_key=d1canaryAWS0000000000000000000000000001\n", bindings: ["*.amazonaws.com"] },
  ], async (c, [env]) => {
    assert.equal((await c.decideSecretOpen({ path: env!, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "d1-sh-9" })).verdict, "raw");
    const b = await c.taintedProcessBindings({ procKey: "d1-sh-9" });
    assert.deepEqual([...b.bindings].sort(), ["api.stripe.com", "db.internal:5432"]);
  });
});

test("D1: overlapping bindings leave exactly the shared destinations; a file bound nowhere empties them", async () => {
  await withArbiter([
    { name: "a.env", content: "A_KEY=d1canaryA00000000003\n", bindings: ["shared.example", "only-a.example"] },
    { name: "b.env", content: "B_KEY=d1canaryB00000000003\n", bindings: ["shared.example", "only-b.example"] },
    { name: "c.env", content: "C_KEY=d1canaryC00000000003\n" },
  ], async (c, [a, b, cc]) => {
    for (const path of [a!, b!]) assert.equal((await c.decideSecretOpen({ path, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "d1-sh-3" })).verdict, "raw");
    assert.deepEqual((await c.taintedProcessBindings({ procKey: "d1-sh-3" })).bindings, ["shared.example"]);
    assert.equal((await c.decideSecretOpen({ path: cc!, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "d1-sh-3" })).verdict, "raw");
    assert.deepEqual((await c.taintedProcessBindings({ procKey: "d1-sh-3" })).bindings, [], "a third file with no bindings: nothing is bound");
  });
});

// ── the session twin (§9 R3): SessionLabels.raise ────────────────────────────

test("R3: the session's destinations intersect across in-context reads; the first secret read sets them", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-d1-sess-"));
  const s = new SessionLabelStore({ dbPath: join(dir, "a.db") });
  try {
    s.raise("sess", "any-model", ["a.example", "shared.example"]);
    assert.deepEqual([...s.get("sess").bindings].sort(), ["a.example", "shared.example"]);
    s.raise("sess", "any-model", ["b.example", "shared.example"]);
    assert.deepEqual(s.get("sess").bindings, ["shared.example"]);
    s.raise("sess", "no-model", ["c.example"]);
    assert.deepEqual(s.get("sess").bindings, [], "disjoint: the session can deliver nowhere without an ask");
    assert.equal(s.get("sess").confidentiality, "no-model");
    // a public read changes nothing about the destinations
    s.raise("other", "any-model", ["x.example"]);
    s.raise("other", "public", []);
    assert.deepEqual(s.get("other").bindings, ["x.example"]);
  } finally {
    s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
