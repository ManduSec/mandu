/**
 * reap-guests.test — `mandu reap` and the qemu guests of the VM test
 * harnesses (os-test-matrix.md §10.5, runtime-instances.md §10).
 *
 * Entries are what scripts/lib/guest-registry.sh writes
 * (`vm-guests/<harness>-<pid>.json`). The contract under test: nothing is
 * touched while the owner harness lives (same pid AND start time); a guest is
 * signalled only when its pid, start time and qemu cmdline ALL still match;
 * a reused pid loses its entry, never a signal; --keep keeps the work dir but
 * never an `alsoRemove` path; a scratch path that is not one is refused.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { planReap, runReap, safeScratchPath, type ReapDeps } from "../../src/reap.js";
import { leftoverSummary } from "../../src/subcommands.js";

async function withBase(fn: (base: string) => Promise<void>): Promise<void> {
  const root = mkdtempSync(join(tmpdir(), "mandu-reap-guests-"));
  const base = join(root, "mandu");
  mkdirSync(base, { recursive: true });
  try {
    await fn(base);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

interface Proc { cmd: string; start: number; zombie?: boolean }

/** A pid table with start times; a signalled qemu exits unless `stubborn`. */
function guestDeps(
  world: Record<number, Proc>,
  killed: Array<[number, string]> = [],
  opts: { boot?: string; stubborn?: boolean } = {},
): ReapDeps {
  return {
    pidAlive: (pid) => pid in world,
    cmdlineOf: (pid) => world[pid]?.cmd ?? null,
    kill: (pid, sig) => {
      killed.push([pid, sig]);
      if (!opts.stubborn) delete world[pid];
    },
    socketLive: async () => false,
    now: () => Date.now(),
    procStart: (pid) => (world[pid] && !world[pid]!.zombie ? world[pid]!.start : null),
    bootId: () => opts.boot ?? "boot-1",
    sleep: async () => {},
  };
}

function seedGuest(base: string, id: string, entry: object | string): string {
  const dir = join(base, "vm-guests");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${id}.json`);
  writeFileSync(path, typeof entry === "string" ? entry : JSON.stringify(entry));
  return path;
}

/** A work dir with an overlay and an ephemeral credential copy, as the matrix leaves one. */
function seedWork(base: string, name: string): string {
  const w = join(base, "..", "work", name);
  mkdirSync(join(w, "artifacts", "ephemeral"), { recursive: true });
  writeFileSync(join(w, "overlay.qcow2"), "disk");
  writeFileSync(join(w, "artifacts", "ephemeral", "cred.json"), "{}");
  return w;
}

const QEMU = "/usr/bin/qemu-system-x86_64 -enable-kvm -m 4096";
const ENV = (base: string) => ({ MANDU_RUNTIME_DIR: base });

test("a LIVE owner protects its guest, running or not", async () => {
  await withBase(async (base) => {
    const w = seedWork(base, "a");
    seedGuest(base, "vm-run-300", { pid: 300, pidStart: 30, bootId: "boot-1", ownerPid: 900, ownerStart: 90, workDir: w, harness: "vm-run" });
    seedGuest(base, "vm-run-301", { pid: 301, pidStart: 31, bootId: "boot-1", ownerPid: 900, ownerStart: 90, workDir: w, harness: "vm-run" });
    const world = { 300: { cmd: QEMU, start: 30 }, 900: { cmd: "bash scripts/ci/vm-run.sh", start: 90 } };
    assert.deepEqual(await planReap(base, guestDeps(world)), []);
  });
});

test("owner gone + guest confirmed → stop it and remove its work dir; a stopped guest → entry + dir, no signal", async () => {
  await withBase(async (base) => {
    const w1 = seedWork(base, "live");
    const w2 = seedWork(base, "dead");
    const e1 = seedGuest(base, "matrix-300", {
      pid: 300, pidStart: 30, bootId: "boot-1", ownerPid: 900, ownerStart: 90, workDir: w1, keep: false,
      alsoRemove: [join(w1, "artifacts", "ephemeral")], harness: "matrix",
    });
    const e2 = seedGuest(base, "matrix-301", { pid: 301, pidStart: 31, bootId: "boot-1", ownerPid: 900, ownerStart: 90, workDir: w2, harness: "matrix" });
    const world = (): Record<number, Proc> => ({ 300: { cmd: QEMU, start: 30 } });

    const plan = await planReap(base, guestDeps(world()));
    const kinds = Object.fromEntries(plan.map((a) => [a.path, a.kind]));
    assert.equal(kinds[e1], "kill-orphan-guest");
    assert.equal(kinds[e2], "rm-dead-guest");
    assert.match(plan.find((a) => a.path === e1)!.detail, /^matrix matrix-300: owner 900 is gone; stop qemu pid 300; remove /);
    assert.equal(leftoverSummary(plan), "1 test VM from ended runs, 1 stale record");

    const killed: Array<[number, string]> = [];
    assert.equal(await runReap(["--dry-run"], ENV(base), guestDeps(world(), killed)), 0);
    assert.deepEqual(killed, [], "--dry-run signals nothing");
    assert.ok(existsSync(w1) && existsSync(e1) && existsSync(w2), "--dry-run removes nothing");

    assert.equal(await runReap([], ENV(base), guestDeps(world(), killed)), 0);
    assert.deepEqual(killed, [[300, "SIGTERM"]], "only the confirmed guest is signalled");
    for (const p of [w1, w2, e1, e2]) assert.ok(!existsSync(p), `${p} removed`);
  });
});

test("a REUSED guest pid (start time differs) loses its entry, never a signal; same start but not qemu is skipped", async () => {
  await withBase(async (base) => {
    const w = seedWork(base, "r");
    const e1 = seedGuest(base, "g-300", { pid: 300, pidStart: 30, bootId: "boot-1", ownerPid: 900, ownerStart: 90, workDir: w });
    const e2 = seedGuest(base, "g-301", { pid: 301, pidStart: 31, bootId: "boot-1", ownerPid: 900, ownerStart: 90, workDir: w });
    const world = (): Record<number, Proc> => ({ 300: { cmd: QEMU, start: 77 }, 301: { cmd: "vim notes-qemu-system-x86_64", start: 31 } });
    assert.deepEqual((await planReap(base, guestDeps(world()))).map((a) => [a.path, a.kind]), [[e1, "rm-dead-guest"]]);
    const killed: Array<[number, string]> = [];
    assert.equal(await runReap([], ENV(base), guestDeps(world(), killed)), 0);
    assert.deepEqual(killed, []);
    assert.ok(!existsSync(e1) && existsSync(e2));
  });
});

test("a reused OWNER pid does not keep a leaked guest alive; an unprovable owner or guest does nothing", async () => {
  await withBase(async (base) => {
    const w = seedWork(base, "o");
    const e = seedGuest(base, "g-300", { pid: 300, pidStart: 30, bootId: "boot-1", ownerPid: 900, ownerStart: 90, workDir: w });
    const reused = await planReap(base, guestDeps({ 300: { cmd: QEMU, start: 30 }, 900: { cmd: "bash", start: 555 } }));
    assert.deepEqual(reused.map((a) => [a.path, a.kind]), [[e, "kill-orphan-guest"]]);
    // Owner 900 alive, start time unreadable (a zombie not yet collected): unknown.
    assert.deepEqual(await planReap(base, guestDeps({ 300: { cmd: QEMU, start: 30 }, 900: { cmd: "", start: 90, zombie: true } })), []);
    // No procStart at all: identity unprovable, nothing is done.
    const plain = guestDeps({ 300: { cmd: QEMU, start: 30 } });
    delete plain.procStart;
    assert.deepEqual(await planReap(base, plain), []);
    // Guest entry without a start time: unprovable, nothing is done.
    seedGuest(base, "g-300", { pid: 300, ownerPid: 900, ownerStart: 90, workDir: w });
    assert.deepEqual(await planReap(base, guestDeps({ 300: { cmd: QEMU, start: 30 } })), []);
  });
});

test("an entry from an earlier boot names no live process: entry + dir go, nothing is signalled", async () => {
  await withBase(async (base) => {
    const w = seedWork(base, "b");
    const e = seedGuest(base, "g-300", { pid: 300, pidStart: 30, bootId: "boot-0", ownerPid: 900, ownerStart: 90, workDir: w });
    const world = (): Record<number, Proc> => ({ 300: { cmd: QEMU, start: 30 }, 900: { cmd: "bash", start: 90 } });
    assert.deepEqual((await planReap(base, guestDeps(world()))).map((a) => a.kind), ["rm-dead-guest"]);
    const killed: Array<[number, string]> = [];
    await runReap([], ENV(base), guestDeps(world(), killed));
    assert.deepEqual(killed, []);
    assert.ok(!existsSync(e) && !existsSync(w));
  });
});

test("--keep keeps the work dir, never the alsoRemove paths (a host credential copy)", async () => {
  await withBase(async (base) => {
    const w = seedWork(base, "k");
    const eph = join(w, "artifacts", "ephemeral");
    const e = seedGuest(base, "g-300", { pid: 300, pidStart: 30, ownerPid: 900, ownerStart: 90, workDir: w, keep: true, alsoRemove: [eph] });
    const killed: Array<[number, string]> = [];
    const plan = await planReap(base, guestDeps({ 300: { cmd: QEMU, start: 30 } }));
    assert.match(plan[0]!.detail, /keep .* \(--keep\)/);
    await runReap([], ENV(base), guestDeps({ 300: { cmd: QEMU, start: 30 } }, killed));
    assert.deepEqual(killed, [[300, "SIGTERM"]]);
    assert.ok(existsSync(join(w, "overlay.qcow2")), "the kept overlay stays");
    assert.ok(!existsSync(eph) && !existsSync(e), "the credential copy and the entry go");
  });
});

test("a guest that ignores SIGTERM gets SIGKILL; one that survives it keeps entry and dir, and reap fails", async () => {
  await withBase(async (base) => {
    const w = seedWork(base, "s");
    const e = seedGuest(base, "g-300", { pid: 300, pidStart: 30, ownerPid: 900, ownerStart: 90, workDir: w });
    const killed: Array<[number, string]> = [];
    const code = await runReap([], ENV(base), guestDeps({ 300: { cmd: QEMU, start: 30 } }, killed, { stubborn: true }));
    assert.equal(code, 1);
    assert.deepEqual(killed, [[300, "SIGTERM"], [300, "SIGKILL"]]);
    assert.ok(existsSync(e) && existsSync(w));
  });
});

test("a pid reused between plan and execute is not signalled", async () => {
  await withBase(async (base) => {
    const w = seedWork(base, "t");
    seedGuest(base, "g-300", { pid: 300, pidStart: 30, ownerPid: 900, ownerStart: 90, workDir: w });
    const world: Record<number, Proc> = { 300: { cmd: QEMU, start: 30 } };
    const killed: Array<[number, string]> = [];
    const deps = guestDeps(world, killed);
    const plan = deps.procStart!;
    let calls = 0;
    // The plan sees the guest; by the time reap acts, 300 is someone else.
    deps.procStart = (pid) => (++calls > 1 ? 99 : plan(pid));
    assert.equal(await runReap([], ENV(base), deps), 0);
    assert.deepEqual(killed, []);
  });
});

test("unsafe scratch paths are refused; unreadable entries go; ownerless live guests stay", async () => {
  await withBase(async (base) => {
    const home = join(base, "..", "home");
    const g300 = seedGuest(base, "g-300", {
      pid: 300, pidStart: 30, ownerPid: 900, ownerStart: 90, workDir: "/",
      alsoRemove: [base, "rel/dir", "/a/../b", join(base, ".."), "/tmp/"],
    });
    const bad = seedGuest(base, "g-bad", "{half");
    seedGuest(base, "g-301", { pid: 301, pidStart: 31, ownerPid: null, workDir: seedWork(base, "n") });
    writeFileSync(join(base, "vm-guests", "g-302.json.tmp"), "{");
    const plan = await planReap(base, guestDeps({ 301: { cmd: QEMU, start: 31 } }));
    const a300 = plan.find((a) => a.path === g300)!;
    assert.equal(a300.kind, "rm-dead-guest");
    assert.deepEqual(a300.remove, []);
    assert.match(a300.detail, /refuse to remove/);
    assert.ok(plan.some((a) => a.path === bad && a.kind === "rm-dead-guest" && a.remove!.length === 0));
    assert.ok(!plan.some((a) => a.path.endsWith("g-301.json")), "a live guest nobody owns is not garbage");
    assert.ok(!plan.some((a) => a.path.endsWith(".tmp")), "a half-written entry is not one");
    assert.ok(!safeScratchPath(home, base, home));
    assert.ok(!safeScratchPath(join(home, ".."), base, home));
    assert.ok(safeScratchPath("/tmp/mandu-matrix.abc123", base, home));
    assert.ok(safeScratchPath(join(home, ".cache", "mandu", "ci", "runs", "x.1"), base, home));
  });
});
