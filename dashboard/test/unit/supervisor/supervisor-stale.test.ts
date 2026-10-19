/**
 * supervisor-stale.test — the scope-honest arbiter staleness verdict
 * (supervisor-defs arbiterStaleness) and its wiring through Supervisor.status().
 *
 * The incident this pins down (2026-07-16): the shared-stack arbiter was
 * deployed on the then-HEAD, a dashboard-only commit landed after, and the old
 * whole-repo rev comparison bannered "STALE arbiter — restart it" for a restart
 * that would have loaded byte-identical arbiter code. Over-eager staleness
 * trains the operator to ignore the badge — the exact alert-fatigue failure the
 * dashboard's own self-status already guards against with a package-scoped diff.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { join } from "node:path";

import { arbiterStaleness, type ArbiterIdentity } from "../../../src/supervisor/supervisor-defs.js";
import { NEVER_READY_SCRIPT, tmpdir, nodeArgs, mkSup, registerTmpHooks } from "./supervisor-harness.js";

registerTmpHooks();

const IDENT = (gitRev: string): ArbiterIdentity => ({
  pid: 4242, startedAt: "2026-07-16T08:58:50.809Z", instanceId: null,
  gitRev, gitDirty: false, sockPath: "/s", eventDir: "/e", symbolDb: "/db",
});

// ── the pure verdict ──────────────────────────────────────────────────────────

test("no identity / unknown revs on either side → fresh (nothing to compare)", () => {
  const diff = (): string[] => {
    throw new Error("must not diff without two known revs");
  };
  assert.deepEqual(arbiterStaleness(null, "/repo", () => "bbbb222", diff), { stale: false, staleReason: null });
  assert.equal(arbiterStaleness(IDENT("nogit"), "/repo", () => "bbbb222", diff).stale, false);
  assert.equal(arbiterStaleness(IDENT("aaaa111"), "/repo", () => "nogit", diff).stale, false);
});

test("same rev → fresh, without spawning a diff", () => {
  const v = arbiterStaleness(IDENT("aaaa111"), "/repo", () => "aaaa111", () => {
    throw new Error("must not diff equal revs");
  });
  assert.deepEqual(v, { stale: false, staleReason: null });
});

test("HEAD moved but the range does NOT touch arbiter/ → fresh (the 2026-07-16 incident)", () => {
  // e.g. a dashboard-only commit after the arbiter deploy: restarting the
  // arbiter would load identical code, so the banner must stay down.
  const v = arbiterStaleness(IDENT("0c7d683"), "/repo", () => "4c3f8b1", () => []);
  assert.deepEqual(v, { stale: false, staleReason: null });
});

test("HEAD moved and the range touches arbiter/ → stale, reason names revs + file count", () => {
  const v = arbiterStaleness(IDENT("aaaa111"), "/repo", () => "bbbb222", (root, from, to, dir) => {
    assert.equal(root, "/repo");
    assert.equal(from, "aaaa111");
    assert.equal(to, "bbbb222");
    assert.equal(dir, join("/repo", "arbiter"), "the diff is scoped to the arbiter package");
    return ["arbiter/ipc/server.ts", "arbiter/policy/claude-code-inbound.ts"];
  });
  assert.equal(v.stale, true);
  assert.match(v.staleReason!, /aaaa111 → bbbb222/);
  assert.match(v.staleReason!, /2 files/);
});

test("an UNRESOLVABLE foreign rev → stale, fail-loud (unlike the self-check's quiet bootRev)", () => {
  // identity.gitRev is a foreign daemon's claim: if this repo cannot resolve it
  // (rebased away, another checkout), that IS the masquerading-daemon trap.
  const v = arbiterStaleness(IDENT("deadbee"), "/repo", () => "bbbb222", () => null);
  assert.equal(v.stale, true);
  assert.match(v.staleReason!, /deadbee is not in this repo's history/);
  assert.match(v.staleReason!, /assuming stale/);
});

// ── wiring through Supervisor.status() (seams injected, fake hello daemon) ────

test("status() carries the scoped verdict + reason, re-reading HEAD per call", async () => {
  const dir = tmpdir();
  const sock = join(dir, "arbiter.sock");
  const identity = IDENT("0c7d683");
  const fake = net.createServer((c) => {
    c.on("data", (b) => {
      if (b.toString().includes('"hello"')) {
        c.write(JSON.stringify({ id: 1, ok: true, result: { ...identity, sockPath: sock } }) + "\n");
      }
    });
  });
  await new Promise<void>((r) => fake.listen(sock, r));

  // Seams: HEAD and the scoped diff are swappable mid-test — status() must
  // track them live (not a boot-captured snapshot).
  let head = "0c7d683";
  let touched: string[] | null = [];
  const sup = mkSup(
    { arbiter: { label: "Arbiter", command: process.execPath, args: nodeArgs(NEVER_READY_SCRIPT),
      cwd: dir, env: {}, ready: { kind: "socket", path: sock }, endpoint: sock } },
    { arbiterSock: sock, gitRev: () => head, gitChangedInRange: () => touched },
  );
  try {
    await sup.start("arbiter"); // endpoint already live → ADOPT, identity fetched
    const at = (): { stale?: boolean; staleReason?: string | null } =>
      sup.status().find((s) => s.id === "arbiter")!;

    assert.equal(at().stale, false, "same rev → fresh");

    head = "4c3f8b1"; // a dashboard-only commit lands: HEAD moves, arbiter/ untouched
    assert.equal(at().stale, false, "rev mismatch alone must NOT banner the arbiter");
    assert.equal(at().staleReason, null);

    touched = ["arbiter/ipc/server.ts"]; // now an arbiter commit lands too
    const stale = at();
    assert.equal(stale.stale, true, "an arbiter-touching range flags without any restart");
    assert.match(stale.staleReason!, /0c7d683 → 4c3f8b1/);
    assert.match(stale.staleReason!, /1 file\b/);
  } finally {
    await sup.shutdownAll();
    await new Promise<void>((r) => fake.close(() => r()));
  }
});
