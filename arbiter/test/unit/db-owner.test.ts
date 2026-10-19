/**
 * db-owner.test — LOUD single-writer ownership of the symbol DB.
 *
 * The invariant under test (runtime-instances.md §9): a second arbiter on the
 * SAME symbol DB refuses at listen() instead of silently interleaving writes
 * (the launcher/dashboard split-brain class). Staleness rules: dead pid or a
 * recycled pid (cmdline mismatch) is stealable; a live matching owner — or one
 * we cannot probe — refuses (fail closed).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
import { spawn, type ChildProcess } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  acquireSymbolDbOwner,
  processCmdline,
  realOwnerProbe,
  SymbolDbOwnedError,
  type CmdlineSource,
  type OwnerProbe,
} from "../../symbol-table/db-owner.js";
import { ArbiterServer } from "../../ipc/server.js";
import { createDefaultPolicyEngine } from "../../policy/policy-interface.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

function withDir(fn: (dir: string) => void | Promise<void>): Promise<void> | void {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dbowner-"));
  const out = fn(dir);
  if (out instanceof Promise) return out.finally(() => rmSync(dir, { recursive: true, force: true }));
  rmSync(dir, { recursive: true, force: true });
}

/** A probe whose world is a fixed pid→cmdline table. */
function probeOf(world: Record<number, string | null>): OwnerProbe {
  return {
    pidAlive: (pid) => pid in world,
    cmdlineOf: (pid) => world[pid] ?? null,
  };
}

test("fresh acquire writes the lock; release removes it", () => {
  withDir((dir) => {
    const db = join(dir, "symbols.db");
    const probe = probeOf({ 100: "node arbiter" });
    const owner = acquireSymbolDbOwner(db, probe, { pid: 100 });
    assert.ok(existsSync(`${db}.owner`));
    assert.equal(JSON.parse(readFileSync(`${db}.owner`, "utf8")).pid, 100);
    owner.release();
    assert.ok(!existsSync(`${db}.owner`), "release unlinks our own lock");
  });
});

test("the lock and a fresh parent dir are owner-only, whatever the umask", () => {
  withDir((dir) => {
    const db = join(dir, "state", "symbols.db");
    const old = process.umask(0o002);
    try {
      const owner = acquireSymbolDbOwner(db, probeOf({ 100: "node arbiter" }), { pid: 100 });
      assert.equal(statSync(`${db}.owner`).mode & 0o777, 0o600);
      assert.equal(statSync(join(dir, "state")).mode & 0o777, 0o700);
      owner.release();
    } finally {
      process.umask(old);
    }
  });
});

test("live owner with matching cmdline → SymbolDbOwnedError names the owner", () => {
  withDir((dir) => {
    const db = join(dir, "symbols.db");
    const probe = probeOf({ 100: "node arbiter-a", 200: "node arbiter-b" });
    acquireSymbolDbOwner(db, probe, { pid: 100 });
    assert.throws(
      () => acquireSymbolDbOwner(db, probe, { pid: 200 }),
      (e: unknown) => e instanceof SymbolDbOwnedError && e.owner.pid === 100 && /single-writer/.test(e.message),
    );
  });
});

test("dead owner pid → stale, steal", () => {
  withDir((dir) => {
    const db = join(dir, "symbols.db");
    acquireSymbolDbOwner(db, probeOf({ 100: "node arbiter-a" }), { pid: 100 });
    // Owner 100 has died; 200 must claim.
    const owner = acquireSymbolDbOwner(db, probeOf({ 200: "node arbiter-b" }), { pid: 200 });
    assert.equal(JSON.parse(readFileSync(owner.lockPath, "utf8")).pid, 200);
  });
});

test("recycled pid (cmdline mismatch) → stale, steal", () => {
  withDir((dir) => {
    const db = join(dir, "symbols.db");
    acquireSymbolDbOwner(db, probeOf({ 100: "node arbiter-a" }), { pid: 100 });
    // pid 100 now belongs to an unrelated process.
    const probe = probeOf({ 100: "vim notes.txt", 200: "node arbiter-b" });
    const owner = acquireSymbolDbOwner(db, probe, { pid: 200 });
    assert.equal(JSON.parse(readFileSync(owner.lockPath, "utf8")).pid, 200);
  });
});

test("live pid but current cmdline UNREADABLE → fail closed (refuse)", () => {
  withDir((dir) => {
    const db = join(dir, "symbols.db");
    acquireSymbolDbOwner(db, probeOf({ 100: "node arbiter-a" }), { pid: 100 });
    // pid 100 alive but /proc read fails now (cmdlineOf → null).
    const probe: OwnerProbe = { pidAlive: (pid) => pid === 100 || pid === 200, cmdlineOf: () => null };
    assert.throws(() => acquireSymbolDbOwner(db, probe, { pid: 200 }), SymbolDbOwnedError);
  });
});

test("corrupt lockfile → stale, steal", () => {
  withDir((dir) => {
    const db = join(dir, "symbols.db");
    writeFileSync(`${db}.owner`, "not json at all");
    const owner = acquireSymbolDbOwner(db, probeOf({ 200: "node arbiter-b" }), { pid: 200 });
    assert.equal(JSON.parse(readFileSync(owner.lockPath, "utf8")).pid, 200);
  });
});

test("release never deletes a successor's lock", () => {
  withDir((dir) => {
    const db = join(dir, "symbols.db");
    const first = acquireSymbolDbOwner(db, probeOf({ 100: "node arbiter-a" }), { pid: 100 });
    // First crashes (releases late); successor steals meanwhile.
    acquireSymbolDbOwner(db, probeOf({ 200: "node arbiter-b" }), { pid: 200 });
    first.release(); // must be a no-op: the file records 200, not 100
    assert.equal(JSON.parse(readFileSync(`${db}.owner`, "utf8")).pid, 200);
  });
});

// ── the invariant end-to-end: two real ArbiterServers, ONE symbol DB ──

function mkServer(socketPath: string, dbPath: string): ArbiterServer {
  return new ArbiterServer({
    socketPath,
    dbPath,
    eventDir: join(dbPath, "..", "events"),
    policy: createDefaultPolicyEngine({}),
    log: () => {},
  });
}

test("two ArbiterServers on one symbol DB: second listen() refuses; close() frees it", async () => {
  await withDir(async (dir) => {
    const db = join(dir, "symbols.db");
    const a = mkServer(join(dir, "a.sock"), db);
    const b = mkServer(join(dir, "b.sock"), db);
    await a.listen();
    await assert.rejects(() => b.listen(), SymbolDbOwnedError);
    // The refused server must not have planted a socket either.
    assert.ok(!existsSync(join(dir, "b.sock")), "refused arbiter binds nothing");
    await a.close();
    // Ownership released → the next writer may start.
    await b.listen();
    await b.close();
  });
});

// ── the cmdline probe: /proc on Linux, ps where there is no /proc (darwin) ──

/** A CmdlineSource that records which rung was asked. */
function sourceOf(platform: NodeJS.Platform, proc: () => string, ps: () => string): CmdlineSource & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    platform,
    readProcCmdline: () => { asked.push("proc"); return proc(); },
    psArgs: () => { asked.push("ps"); return ps(); },
  };
}

test("processCmdline: Linux reads /proc (NULs as spaces) and never runs ps", () => {
  const src = sourceOf("linux", () => "node\0server-main.ts\0", () => "WRONG");
  assert.equal(processCmdline(100, src), "node server-main.ts");
  assert.deepEqual(src.asked, ["proc"]);
  const gone = sourceOf("linux", () => { throw new Error("ENOENT"); }, () => "WRONG");
  assert.equal(processCmdline(100, gone), null, "an unreadable /proc entry is null, never a ps fallback on Linux");
  assert.deepEqual(gone.asked, ["proc"]);
});

test("processCmdline: darwin asks ps (the title padding trimmed); a failed, empty or hung ps is null", () => {
  const src = sourceOf("darwin", () => "WRONG", () => "mandu-arbiter   \n");
  assert.equal(processCmdline(100, src), "mandu-arbiter");
  assert.deepEqual(src.asked, ["ps"], "no /proc read on darwin");
  assert.equal(processCmdline(100, sourceOf("darwin", () => "", () => { throw new Error("ps exited 1"); })), null);
  assert.equal(processCmdline(100, sourceOf("darwin", () => "", () => "  \n")), null);
  const none = sourceOf("darwin", () => "", () => "x");
  for (const bad of [0, -1, 1.5, Number.NaN]) assert.equal(processCmdline(bad, none), null);
  assert.deepEqual(none.asked, [], "a non-pid never reaches ps");
});

/** A live child with a known canonical title, the shape of a real daemon. */
async function titledChild(title: string): Promise<ChildProcess> {
  const child = spawn(process.execPath, ["-e", `process.title = ${JSON.stringify(title)}; console.log("up"); setInterval(() => {}, 1e9);`], {
    stdio: ["ignore", "pipe", "ignore"],
  });
  await new Promise<void>((resolve, reject) => {
    child.stdout!.once("data", () => resolve());
    child.once("exit", () => reject(new Error("child exited early")));
  });
  return child;
}

test("processCmdline on this host reads a live process's canonical title (/proc on Linux, ps on darwin)", async () => {
  const child = await titledChild("mandu-dbowner-probe");
  try {
    assert.match(processCmdline(child.pid!) ?? "", /mandu-dbowner-probe/);
    assert.ok(processCmdline(process.pid), "this process's own command line is readable");
  } finally {
    child.kill("SIGKILL");
  }
});

test("REAL probe: a stale lock whose pid now belongs to another process is stolen; a lock matching the live process refuses", async () => {
  const child = await titledChild("mandu-not-an-arbiter");
  try {
    await withDir(async (dir) => {
      const db = join(dir, "symbols.db");
      // The recorded owner died and the kernel handed its pid to `child`: the
      // pid is alive, the command line differs → stale. Before the ps rung
      // darwin read no command line at all and refused every later start.
      writeFileSync(`${db}.owner`, JSON.stringify({ pid: child.pid, cmdline: "mandu-arbiter", startedAt: "earlier" }));
      const owner = acquireSymbolDbOwner(db, realOwnerProbe);
      const rec = JSON.parse(readFileSync(owner.lockPath, "utf8"));
      assert.equal(rec.pid, process.pid);
      assert.ok(rec.cmdline, "the new owner records a readable command line on this host");
      owner.release();
      // The same live pid, recorded with ITS OWN command line: a live owner → refuse.
      writeFileSync(`${db}.owner`, JSON.stringify({ pid: child.pid, cmdline: processCmdline(child.pid!), startedAt: "now" }));
      assert.throws(() => acquireSymbolDbOwner(db, realOwnerProbe), SymbolDbOwnedError);
      // …and a real ArbiterServer starts over a recycled-pid lock (the darwin incident end to end).
      writeFileSync(`${db}.owner`, JSON.stringify({ pid: child.pid, cmdline: "mandu-arbiter", startedAt: "earlier" }));
      const a = mkServer(join(dir, "a.sock"), db);
      await a.listen();
      await a.close();
    });
  } finally {
    child.kill("SIGKILL");
  }
});
