/**
 * reap-planted — `mandu reap` never walks or deletes through a link planted
 * in the runtime base (runtime-instances.md §2 "planted paths", §10).
 *
 * Each case plants a link where reap walks (`instances/`, `dashboards/`,
 * `vm-guests/`, an instance dir, a scope dir, a guest's scratch dir or a
 * folder on its way) pointing at a CANARY folder that holds what reap would
 * take for garbage (old manifest-less subdirectories, a `package.json` that
 * names no live pid, a forged guest entry). The canary must survive whole;
 * a link itself may be removed or left. The safe-remove helper's own rules
 * (ownership, the swapped-directory check, a link on the way) are pinned at
 * the end. The real CLI form is test/component/reap-planted-link.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { executeReapAction, planReap, runReap, safeScratchPath, type ReapDeps } from "../../src/reap.js";
import { closeDir, openDir, openDirIn, readJsonIn, removeIn, removePath } from "../../src/safe-remove.js";

async function withRoot(fn: (root: string, base: string, canary: string) => Promise<void>): Promise<void> {
  const root = mkdtempSync(join(tmpdir(), "mandu-reap-planted-"));
  const base = join(root, "mandu");
  mkdirSync(base);
  const canary = join(root, "project");
  mkdirSync(canary);
  try {
    await fn(root, base, canary);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

/** Every pid is dead, except the ones listed; sockets dead; kills recorded. */
function deps(live: number[] = []): ReapDeps {
  return {
    pidAlive: (pid) => live.includes(pid),
    cmdlineOf: () => null,
    kill: () => { throw new Error("nothing may be signalled here"); },
    socketLive: async () => false,
    now: () => Date.now(),
    procStart: () => null,
    bootId: () => "boot-1",
    sleep: async () => {},
  };
}

/** Old, manifest-less subdirectories: what reap takes for abandoned instances. */
function oldSubdirs(dir: string, names: string[]): void {
  const old = new Date(Date.now() - 3_600_000);
  for (const n of names) {
    mkdirSync(join(dir, n, "src"), { recursive: true });
    writeFileSync(join(dir, n, "src", "main.ts"), "work\n");
    utimesSync(join(dir, n), old, old);
  }
}

function quietly<T>(fn: () => Promise<T>): Promise<T> {
  const w = process.stdout.write.bind(process.stdout);
  process.stdout.write = (() => true) as typeof process.stdout.write;
  return fn().finally(() => { process.stdout.write = w; });
}

test("a linked instances/ is never walked: the linked-to folder's old subdirectories survive", async () => {
  await withRoot(async (_root, base, canary) => {
    oldSubdirs(canary, ["src", "docs", "node_modules"]);
    symlinkSync(canary, join(base, "instances"));
    const plan = await planReap(base, deps());
    assert.deepEqual(plan.filter((a) => a.kind === "rm-dead-instance"), [], "nothing under a linked instances/ is an instance");
    assert.equal(await quietly(() => runReap([], { MANDU_RUNTIME_DIR: base }, deps())), 0);
    assert.deepEqual(readdirSync(canary).sort(), ["docs", "node_modules", "src"]);
  });
});

test("a linked dashboards/ is never walked: a package.json there is not a dead entry", async () => {
  await withRoot(async (_root, base, canary) => {
    writeFileSync(join(canary, "package.json"), `{"name":"mine"}`);
    writeFileSync(join(canary, "tsconfig.json"), `{"pid": 4}`);
    symlinkSync(canary, join(base, "dashboards"));
    const plan = await planReap(base, deps());
    assert.deepEqual(plan.filter((a) => a.kind === "rm-dead-dashboard-entry"), []);
    await quietly(() => runReap([], { MANDU_RUNTIME_DIR: base }, deps()));
    assert.deepEqual(readdirSync(canary).sort(), ["package.json", "tsconfig.json"]);
  });
});

test("a linked vm-guests/ is never walked: a forged entry there names nothing reap removes", async () => {
  await withRoot(async (root, base, canary) => {
    const victim = join(root, "victim");
    mkdirSync(victim);
    writeFileSync(join(victim, "keep.txt"), "mine\n");
    const forged = join(root, "forged-guests");
    mkdirSync(forged);
    writeFileSync(join(forged, "g-1.json"), JSON.stringify({ pid: 300, pidStart: 30, ownerPid: 900, ownerStart: 90, workDir: victim }));
    symlinkSync(forged, join(base, "vm-guests"));
    await quietly(() => runReap([], { MANDU_RUNTIME_DIR: base }, deps()));
    assert.ok(existsSync(join(victim, "keep.txt")), "the forged entry's workDir survives");
    assert.ok(existsSync(join(forged, "g-1.json")), "the entry in the linked-to folder is not removed either");
    void canary;
  });
});

test("an instance dir, a scope dir or the current link that is a link: only the link goes, never what it names", async () => {
  await withRoot(async (_root, base, canary) => {
    writeFileSync(join(canary, "notes.md"), "mine\n");
    mkdirSync(join(base, "instances"));
    symlinkSync(canary, join(base, "instances", "20260101-0000-abc-p1"));
    const old = new Date(Date.now() - 3_600_000);
    // A dead launcher pid in the scope-dir name.
    symlinkSync(canary, join(base, "1700000000-2147480000"));
    // A real (dead) instance whose dir holds a link to the canary.
    const real = join(base, "instances", "20260101-0001-abc-p2");
    mkdirSync(real);
    writeFileSync(join(real, "manifest.json"), JSON.stringify({ pid: 2147480001 }));
    symlinkSync(canary, join(real, "logs"));
    utimesSync(real, old, old);
    await quietly(() => runReap([], { MANDU_RUNTIME_DIR: base }, deps()));
    assert.deepEqual(readdirSync(canary), ["notes.md"]);
    assert.ok(!existsSync(real), "the real dead instance is removed, its inner link with it (not followed)");
  });
});

test("a guest's scratch dir that is a link, or reached through one, is never deleted through it", async () => {
  await withRoot(async (root, base, canary) => {
    writeFileSync(join(canary, "notes.md"), "mine\n");
    mkdirSync(join(base, "vm-guests"));
    const scratch = join(root, "scratch");
    mkdirSync(scratch);
    // 1. workDir itself a link to the canary.
    symlinkSync(canary, join(scratch, "work-link"));
    writeFileSync(join(base, "vm-guests", "g-1.json"), JSON.stringify({ pid: 2147480010, pidStart: 1, ownerPid: 2147480011, ownerStart: 1, workDir: join(scratch, "work-link") }));
    // 2. workDir under a linked folder: <scratch>/via/<name>, via → root.
    symlinkSync(root, join(scratch, "via"));
    writeFileSync(join(base, "vm-guests", "g-2.json"), JSON.stringify({ pid: 2147480012, pidStart: 1, ownerPid: 2147480013, ownerStart: 1, workDir: join(scratch, "via", "project") }));
    await quietly(() => runReap([], { MANDU_RUNTIME_DIR: base }, deps()));
    assert.deepEqual(readdirSync(canary), ["notes.md"]);
  });
});

test("the plan is re-checked at execution: an instances/ swapped for a link after the plan deletes nothing through it", async () => {
  await withRoot(async (root, base, canary) => {
    oldSubdirs(canary, ["20260101-0000-abc-p1"]);
    mkdirSync(join(base, "instances"));
    oldSubdirs(join(base, "instances"), ["20260101-0000-abc-p1"]);
    const d = deps();
    const plan = await planReap(base, d);
    assert.equal(plan.filter((a) => a.kind === "rm-dead-instance").length, 1);
    // Between the plan and its execution, instances/ becomes a link.
    renameSync(join(base, "instances"), join(root, "instances.real"));
    symlinkSync(canary, join(base, "instances"));
    for (const a of plan) {
      await assert.rejects(executeReapAction(a, base, d), /symbolic link/, "refused, not followed");
    }
    assert.deepEqual(readdirSync(canary), ["20260101-0000-abc-p1"]);
    assert.ok(existsSync(join(canary, "20260101-0000-abc-p1", "src", "main.ts")));
  });
});

test("scratch paths: only below a temp or cache root, never the home's other folders", () => {
  const home = "/home/u";
  const roots = ["/tmp", "/home/u/.cache", "/home/u/.mandu/cache"];
  assert.ok(!safeScratchPath("/home/u/Documents", "/run/user/1/mandu", home, roots), "~/Documents is not a scratch dir");
  assert.ok(!safeScratchPath("/home/u/project/build", "/run/user/1/mandu", home, roots));
  assert.ok(!safeScratchPath("/tmp", "/run/user/1/mandu", home, roots), "a root itself is not one");
  assert.ok(safeScratchPath("/tmp/mandu-kernel-vm.abc123", "/run/user/1/mandu", home, roots));
  assert.ok(safeScratchPath("/home/u/.mandu/cache/ci/runs/x.1", "/run/user/1/mandu", home, roots));
  assert.ok(safeScratchPath("/home/u/.cache/mandu-vm/x", "/run/user/1/mandu", home, roots));
});

test("safe-remove: ownership, a link on the way, a swapped directory, a planted FIFO", async () => {
  await withRoot(async (root, base, canary) => {
    writeFileSync(join(canary, "notes.md"), "mine\n");
    const uid = process.getuid?.() ?? 0;
    // Another owner's entry is refused (simulated: the expected uid differs).
    mkdirSync(join(base, "x"));
    const h = openDir(base);
    try {
      assert.throws(() => removeIn(h, "x", { kind: "dir", uid: uid + 1 }), /not yours/);
      assert.ok(existsSync(join(base, "x")));
      assert.throws(() => openDirIn(h, "x", { uid: uid + 1 }), /not yours/);
      // A kind mismatch is refused.
      symlinkSync(canary, join(base, "l"));
      assert.throws(() => removeIn(h, "l", { kind: "dir" }), /symbolic link, not a directory/);
      assert.throws(() => openDirIn(h, "l"), /symbolic link/);
      removeIn(h, "l", { kind: "link" });
      assert.ok(!existsSync(join(base, "l")) && existsSync(join(canary, "notes.md")));
      // A FIFO at a JSON name is never opened for a blocking read.
      const { execFileSync } = await import("node:child_process");
      execFileSync("mkfifo", [join(base, "f.json")]);
      assert.equal(readJsonIn(h, "f.json"), null);
      symlinkSync(join(canary, "notes.md"), join(base, "n.json"));
      assert.equal(readJsonIn(h, "n.json"), null, "a link is not followed");
    } finally {
      closeDir(h);
    }
    // A link this user made on the way to a path refuses it.
    symlinkSync(canary, join(root, "via"));
    assert.throws(() => openDir(join(root, "via")), /symbolic link/);
    assert.throws(() => removePath(join(root, "via", "notes.md"), { kind: "file" }), /symbolic link/);
    assert.throws(() => removePath(join(root, "via", "x", "y"), { kind: "file" }), /symbolic link on the way/);
    assert.ok(existsSync(join(canary, "notes.md")));
    // A plain tree goes, an inner link unlinked, not followed.
    mkdirSync(join(root, "tree", "a"), { recursive: true });
    symlinkSync(canary, join(root, "tree", "a", "out"));
    removePath(join(root, "tree"), { kind: "dir" });
    assert.ok(!existsSync(join(root, "tree")));
    assert.ok(existsSync(join(canary, "notes.md")));
    assert.ok(lstatSync(canary).isDirectory());
    assert.equal(readFileSync(join(canary, "notes.md"), "utf8"), "mine\n");
  });
});
