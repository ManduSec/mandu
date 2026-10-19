/**
 * instance.test.ts — unit tests for the per-deployment runtime identity scheme
 * (ipc/instance.ts; docs/design/architecture/runtime-instances.md): instance ids, the atomic
 * `current` promotion, client socket resolution order, and dead-instance GC.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync,
} from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  ARBITER_SOCK,
  CURRENT_LINK,
  CURRENT_TMP_PREFIX,
  INSTANCES_DIR,
  accountIdentity,
  createInstanceDir,
  currentInstanceId,
  gitRevOf,
  instanceId,
  instancePaths,
  pidAlive,
  promoteInstance,
  foreignHomePromotion,
  readManifest,
  resolveArbiterSock,
  runtimeBase,
  sweepDeadInstances,
  writeManifest,
  type InstanceManifest,
} from "../../ipc/instance.js";

function tmpBase(): { base: string; cleanup: () => void } {
  const base = mkdtempSync(join(tmpdir(), "mandu-instance-"));
  return { base, cleanup: () => rmSync(base, { recursive: true, force: true }) };
}

function manifestFor(id: string, paths: { sockPath: string }, pid: number): InstanceManifest {
  return {
    instanceId: id, role: "arbiter", pid,
    startedAt: new Date().toISOString(),
    gitRev: "abc1234", gitDirty: false,
    sockPath: paths.sockPath, eventDir: "/tmp/events", symbolDb: "/tmp/symbols.db",
  };
}

// ── naming ────────────────────────────────────────────────────────────────────

test("instanceId is <utc-time>-<rev>-p<pid>: sortable, readable, unique-by-pid", () => {
  const id = instanceId(new Date("2026-07-07T11:39:42Z"), "91dca36", 402360);
  assert.equal(id, "20260707-1139-91dca36-p402360");
  // A hostile/odd rev is sanitized, never able to escape the instances dir.
  const weird = instanceId(new Date("2026-07-07T11:39:42Z"), "../../etc", 1);
  assert.ok(!weird.includes("/"), weird);
});

test("runtimeBase honors MANDU_RUNTIME_DIR, then XDG_RUNTIME_DIR/mandu, then a short TMPDIR, then the /tmp fallback", () => {
  assert.equal(runtimeBase({ MANDU_RUNTIME_DIR: "/x/y" } as never), "/x/y");
  assert.equal(runtimeBase({ MANDU_RUNTIME_DIR: "/x/y/" } as never), "/x/y", "one trailing slash stripped, as the launcher always did");
  assert.equal(runtimeBase({ XDG_RUNTIME_DIR: "/run/user/7" } as never), "/run/user/7/mandu");
  const me = process.getuid?.();
  assert.equal(runtimeBase({ TMPDIR: "/t" } as never), me === undefined ? "/t/mandu" : `/t/mandu-${me}`, "per-user (2026-10-09)");
  // Too long for an instance socket on ANY platform (130-byte TMPDIR):
  // the private /tmp/mandu-<uid> (runtime-base.test.ts pins every branch).
  const uid = process.getuid?.();
  if (uid !== undefined) {
    assert.equal(runtimeBase({ TMPDIR: "/" + "t".repeat(129), MANDU_RUNTIME_FALLBACK_ROOT: "/fb" } as never), `/fb/mandu-${uid}`);
  }
});

test("runtimeBase is the table's runtime-dir: TMPDIR, then /tmp (per-user), and only the env it is given counts", () => {
  const u = process.getuid?.();
  const pu = (p: string): string => (u === undefined ? p : `${p}-${u}`);
  assert.equal(runtimeBase({ TMPDIR: "/var/tmp/" } as never), pu("/var/tmp/mandu"));
  assert.equal(runtimeBase({ XDG_RUNTIME_DIR: "", TMPDIR: "/var/tmp" } as never), pu("/var/tmp/mandu"), "empty counts as unset");
  assert.equal(runtimeBase({ MANDU_RUNTIME_DIR: "", XDG_RUNTIME_DIR: "/run/user/7" } as never), "/run/user/7/mandu");
  // Phase 3b (on-disk-layout.md §7): os.tmpdir() no longer fills in, so
  // TMP/TEMP and the process's own TMPDIR do not move a passed-in env's base.
  const saved = process.env["TMPDIR"];
  process.env["TMPDIR"] = "/process/tmp";
  try {
    assert.equal(runtimeBase({} as never), pu("/tmp/mandu"));
    assert.equal(runtimeBase({ TMP: "/t", TEMP: "/u" } as never), pu("/tmp/mandu"));
  } finally {
    if (saved === undefined) delete process.env["TMPDIR"]; else process.env["TMPDIR"] = saved;
  }
});

test("accountIdentity: the rendezvous is the table's runtime-dir under /run/user/<uid> (macOS: /tmp/mandu-<uid>)", () => {
  const id = accountIdentity();
  if (id === null || typeof process.getuid !== "function") return;
  // macOS: DARWIN_USER_TEMP_DIR (/var/folders/…/T/) has no room for an
  // instance socket, so the account's default base is the private fallback
  // (runtime-base.ts accountRendezvous; pinned for both platforms below).
  const want = process.platform === "darwin" ? `/tmp/mandu-${process.getuid()}` : `/run/user/${process.getuid()}/mandu`;
  assert.equal(id.rendezvous, want);
});

test("gitRevOf: a non-repo dir yields nogit (never throws)", () => {
  const { base, cleanup } = tmpBase();
  try {
    assert.deepEqual(gitRevOf(base), { rev: "nogit", dirty: false });
  } finally {
    cleanup();
  }
});

// ── promotion (the atomic current symlink) ────────────────────────────────────

test("promoteInstance swaps `current` atomically between instances", () => {
  const { base, cleanup } = tmpBase();
  try {
    const a = createInstanceDir(base, "20260707-1100-aaaaaaa-p1");
    writeFileSync(a.sockPath, ""); // stand-in for the bound socket
    writeManifest(a, manifestFor("20260707-1100-aaaaaaa-p1", a, process.pid));
    promoteInstance(base, "20260707-1100-aaaaaaa-p1");
    assert.equal(currentInstanceId(base), "20260707-1100-aaaaaaa-p1");
    // The link target is RELATIVE (survives a moved/bind-mounted base).
    assert.equal(readlinkSync(join(base, CURRENT_LINK)), join(INSTANCES_DIR, "20260707-1100-aaaaaaa-p1"));

    const b = createInstanceDir(base, "20260707-1200-bbbbbbb-p2");
    writeFileSync(b.sockPath, "");
    promoteInstance(base, "20260707-1200-bbbbbbb-p2");
    assert.equal(currentInstanceId(base), "20260707-1200-bbbbbbb-p2");
    // The old instance dir is untouched by promotion (GC handles it later).
    assert.ok(existsSync(a.dir));
  } finally {
    cleanup();
  }
});

test("promoteInstance repairs a plain directory squatting the `current` name", () => {
  const { base, cleanup } = tmpBase();
  try {
    // The stray-`mkdir -p .../current/...` foot-gun (a real hazard for shell
    // wrappers): promotion must replace the real dir with the symlink.
    mkdirSync(join(base, CURRENT_LINK, "junk"), { recursive: true });
    const p = createInstanceDir(base, "20260707-1300-ccccccc-p3");
    writeFileSync(p.sockPath, "");
    promoteInstance(base, "20260707-1300-ccccccc-p3");
    assert.ok(lstatSync(join(base, CURRENT_LINK)).isSymbolicLink());
    assert.equal(currentInstanceId(base), "20260707-1300-ccccccc-p3");
  } finally {
    cleanup();
  }
});

test("currentInstanceId is null when nothing was promoted or the target socket is gone", () => {
  const { base, cleanup } = tmpBase();
  try {
    assert.equal(currentInstanceId(base), null);
    const p = createInstanceDir(base, "20260707-1400-ddddddd-p4");
    promoteInstance(base, "20260707-1400-ddddddd-p4");
    // Promoted but no socket file → a dead/dangling promotion, not current.
    assert.equal(currentInstanceId(base), null);
    writeFileSync(p.sockPath, "");
    assert.equal(currentInstanceId(base), "20260707-1400-ddddddd-p4");
  } finally {
    cleanup();
  }
});

// ── client resolution order ───────────────────────────────────────────────────

test("resolveArbiterSock: explicit env → current → legacy fixed path", () => {
  const { base, cleanup } = tmpBase();
  try {
    // 1. Explicit env wins verbatim (tests + pinned deployments).
    assert.equal(
      resolveArbiterSock({ MANDU_ARBITER_SOCK: "/tmp/x.sock", MANDU_RUNTIME_DIR: base } as never),
      "/tmp/x.sock",
    );
    // 3. No promotion yet → the legacy fixed path (compat with old stacks).
    const env = { MANDU_RUNTIME_DIR: base } as never;
    assert.equal(resolveArbiterSock(env), join(base, ARBITER_SOCK));
    // 2. A promoted instance with a live socket file → current/arbiter.sock.
    const p = createInstanceDir(base, "20260707-1500-eeeeeee-p5");
    writeFileSync(p.sockPath, "");
    promoteInstance(base, "20260707-1500-eeeeeee-p5");
    assert.equal(resolveArbiterSock(env), join(base, CURRENT_LINK, ARBITER_SOCK));
  } finally {
    cleanup();
  }
});

// ── manifest + GC ─────────────────────────────────────────────────────────────

test("manifest round-trips; corrupt manifests read as null", () => {
  const { base, cleanup } = tmpBase();
  try {
    const p = createInstanceDir(base, "20260707-1600-fffffff-p6");
    const m = manifestFor("20260707-1600-fffffff-p6", p, 1234);
    writeManifest(p, m);
    assert.deepEqual(readManifest(p.dir), m);
    writeFileSync(p.manifestPath, "not json");
    assert.equal(readManifest(p.dir), null);
  } finally {
    cleanup();
  }
});

test("writeManifest renames a complete file into place, never writes the final path in place", () => {
  const { base, cleanup } = tmpBase();
  try {
    const p = createInstanceDir(base, "20260707-1610-fffffff-p7");
    // What a reader of a plain in-place write could see: the file created,
    // its bytes not yet landed. A write in place keeps this inode; the rename
    // replaces it with a new one that was complete before it got the name.
    writeFileSync(p.manifestPath, "");
    const before = statSync(p.manifestPath).ino;
    assert.equal(readManifest(p.dir), null, "an empty manifest reads as unknown, not a throw");
    const m = manifestFor("20260707-1610-fffffff-p7", p, 1234);
    writeManifest(p, m);
    assert.notEqual(statSync(p.manifestPath).ino, before, "the manifest arrived by rename(2)");
    assert.deepEqual(readManifest(p.dir), m);
    // No temp file is left behind in the instance dir.
    assert.deepEqual(readdirSync(p.dir).sort(), ["logs", "manifest.json"]);
  } finally {
    cleanup();
  }
});

test("writeManifest failing leaves neither a partial manifest nor its temp file", () => {
  const { base, cleanup } = tmpBase();
  try {
    const p = createInstanceDir(base, "20260707-1620-fffffff-p8");
    // A directory squatting the manifest name makes the rename fail.
    mkdirSync(p.manifestPath);
    assert.throws(() => writeManifest(p, manifestFor("20260707-1620-fffffff-p8", p, 1234)));
    assert.deepEqual(readdirSync(p.dir).sort(), ["logs", "manifest.json"]);
    assert.ok(statSync(p.manifestPath).isDirectory(), "the squatter is untouched");
  } finally {
    cleanup();
  }
});

test("a truncated manifest reads as null and sweepDeadInstances grace-protects its dir", () => {
  const { base, cleanup } = tmpBase();
  try {
    const p = createInstanceDir(base, "20260707-1630-fffffff-p9");
    const full = JSON.stringify(manifestFor("20260707-1630-fffffff-p9", p, 2 ** 30), null, 2);
    for (const torn of ["", full.slice(0, 1), full.slice(0, full.length >> 1)]) {
      writeFileSync(p.manifestPath, torn);
      assert.equal(readManifest(p.dir), null, `torn at ${torn.length} bytes`);
      assert.deepEqual(sweepDeadInstances(base), [], "a fresh dir with a torn manifest is kept");
      assert.ok(existsSync(p.dir));
    }
  } finally {
    cleanup();
  }
});

// ── planted paths (runtime-instances.md §2, 2026-09-30) ──────────────────────
// Whoever can write the runtime base (the agent on macOS, whose Seatbelt
// profile keeps the base writable; any same-uid process on Linux) knows every
// name the arbiter is about to use. The arbiter runs outside the agent's
// confinement, so a link planted at one of them must never be followed.

test("writeManifest: a link planted at the temp name is removed, never written through", () => {
  const { base, cleanup } = tmpBase();
  try {
    const p = createInstanceDir(base, "20260930-1000-abc1234-p1");
    const victim = join(base, "victim.txt");
    writeFileSync(victim, "untouched\n");
    const tmp = join(p.dir, `.manifest.json.${process.pid}.tmp`);
    symlinkSync(victim, tmp);
    const m = manifestFor("20260930-1000-abc1234-p1", p, 1234);
    writeManifest(p, m);
    assert.equal(readFileSync(victim, "utf8"), "untouched\n", "the link's target is untouched");
    assert.deepEqual(readManifest(p.dir), m);
    assert.ok(!lstatSync(p.manifestPath).isSymbolicLink(), "the manifest is a file of its own");
    assert.deepEqual(readdirSync(p.dir).sort(), ["logs", "manifest.json"]);
  } finally {
    cleanup();
  }
});

test("writeManifest: a link re-planted between the unlink and the write is REFUSED (O_EXCL), never followed", () => {
  const { base, cleanup } = tmpBase();
  // The race a planter can try: put the link back right after the arbiter
  // removed it. The exclusive create must then fail, whatever the link names:
  // an existing file (would be overwritten) or a free name (would be created).
  const fs = createRequire(import.meta.url)("node:fs") as typeof import("node:fs");
  const realUnlink = fs.unlinkSync;
  try {
    for (const target of ["existing", "absent"]) {
      const id = `20260930-1001-abc1234-p${target.length}`;
      const p = createInstanceDir(base, id);
      const victim = join(base, `victim-${target}.txt`);
      if (target === "existing") writeFileSync(victim, "untouched\n");
      const tmp = join(p.dir, `.manifest.json.${process.pid}.tmp`);
      let replanted = false;
      fs.unlinkSync = ((q: Parameters<typeof realUnlink>[0]) => {
        try {
          realUnlink(q); // ENOENT when nothing was there: still thrown, as before
        } finally {
          if (q === tmp && !replanted) { replanted = true; fs.symlinkSync(victim, tmp); }
        }
      }) as typeof realUnlink;
      syncBuiltinESMExports();
      try {
        assert.throws(() => writeManifest(p, manifestFor(id, p, 1234)), (e: NodeJS.ErrnoException) => e.code === "EEXIST");
      } finally {
        fs.unlinkSync = realUnlink;
        syncBuiltinESMExports();
      }
      assert.ok(replanted, "the race was staged");
      if (target === "existing") assert.equal(readFileSync(victim, "utf8"), "untouched\n", "an existing target is not overwritten");
      else assert.equal(existsSync(victim), false, "a free target name is not created");
      assert.equal(existsSync(p.manifestPath), false, "no manifest from a refused write");
    }
  } finally {
    fs.unlinkSync = realUnlink;
    syncBuiltinESMExports();
    cleanup();
  }
});

test("createInstanceDir: 0700, made exclusively; an instance dir that already exists is refused and left alone", () => {
  const { base, cleanup } = tmpBase();
  try {
    const p = createInstanceDir(base, "20260930-1002-abc1234-p7");
    assert.equal(statSync(p.dir).mode & 0o777, 0o700);
    assert.ok(statSync(p.logsDir).isDirectory());
    // Pre-made under a predictable id, a link planted inside: never adopted.
    const planted = join(base, INSTANCES_DIR, "20260930-1003-abc1234-p8");
    mkdirSync(planted, { recursive: true });
    symlinkSync(join(base, "victim"), join(planted, "logs"));
    assert.throws(() => createInstanceDir(base, "20260930-1003-abc1234-p8"), /already exists .* refusing to start/);
    assert.deepEqual(readdirSync(planted), ["logs"], "the refused dir is left as it was");
    assert.ok(lstatSync(join(planted, "logs")).isSymbolicLink());
    assert.equal(existsSync(join(base, "victim")), false, "nothing was created through the link");
    // The same holds for our own id a second time (a pid reused in the minute).
    assert.throws(() => createInstanceDir(base, "20260930-1002-abc1234-p7"), /already exists/);
  } finally {
    cleanup();
  }
});

test("a symlinked instances/ is never swept through, and no instance dir is made in it", () => {
  const { base, cleanup } = tmpBase();
  try {
    // What the link names: someone's files, old enough that a sweep that
    // followed it would take each for an abandoned manifest-less instance.
    const victim = join(base, "victim");
    mkdirSync(join(victim, "project"), { recursive: true });
    writeFileSync(join(victim, "notes.txt"), "keep me\n");
    const past = new Date(Date.now() - 3_600_000);
    for (const q of [join(victim, "project"), join(victim, "notes.txt")]) utimesSync(q, past, past);
    symlinkSync(victim, join(base, INSTANCES_DIR));
    assert.deepEqual(sweepDeadInstances(base, 0), [], "nothing is swept through the link");
    assert.deepEqual(readdirSync(victim).sort(), ["notes.txt", "project"], "the link's target is untouched");
    assert.throws(() => createInstanceDir(base, "20260930-1004-abc1234-p9"), /not a real directory .* refusing to start/);
    assert.deepEqual(readdirSync(victim).sort(), ["notes.txt", "project"]);
    // A file squatting the name is refused the same way.
    rmSync(join(base, INSTANCES_DIR));
    writeFileSync(join(base, INSTANCES_DIR), "");
    assert.deepEqual(sweepDeadInstances(base, 0), []);
    assert.throws(() => createInstanceDir(base, "20260930-1004-abc1234-p9"));
  } finally {
    cleanup();
  }
});

test("the promotion's temporary link is named with CURRENT_TMP_PREFIX (the macOS profile write-denies the prefix)", () => {
  const { base, cleanup } = tmpBase();
  try {
    assert.equal(CURRENT_TMP_PREFIX, ".current.tmp-");
    const p = createInstanceDir(base, "20260930-1005-abc1234-p10");
    writeFileSync(p.sockPath, "");
    // A stale temp link of this pid (a crash mid-promotion) is replaced, and
    // the promotion lands as before.
    symlinkSync(join(INSTANCES_DIR, "stale"), join(base, `${CURRENT_TMP_PREFIX}${process.pid}`));
    promoteInstance(base, "20260930-1005-abc1234-p10");
    assert.equal(currentInstanceId(base), "20260930-1005-abc1234-p10");
    assert.ok(!existsSync(join(base, `${CURRENT_TMP_PREFIX}${process.pid}`)) && !readdirSync(base).some((n) => n.startsWith(CURRENT_TMP_PREFIX)));
  } finally {
    cleanup();
  }
});

test("sweepDeadInstances reaps dead-pid dirs, keeps live ones and fresh manifest-less dirs", () => {
  const { base, cleanup } = tmpBase();
  try {
    // Live: manifest pid = this process.
    const live = createInstanceDir(base, "live");
    writeManifest(live, manifestFor("live", live, process.pid));
    // Dead: a pid that cannot exist (beyond pid_max).
    const dead = createInstanceDir(base, "dead");
    writeManifest(dead, manifestFor("dead", dead, 2 ** 30));
    // Mid-creation: no manifest yet, just created → grace-protected.
    const fresh = createInstanceDir(base, "fresh");

    const removed = sweepDeadInstances(base);
    assert.deepEqual(removed, ["dead"]);
    assert.ok(existsSync(live.dir), "live instance survives");
    assert.ok(!existsSync(dead.dir), "dead instance reaped");
    assert.ok(existsSync(fresh.dir), "fresh manifest-less dir survives the grace window");

    // Past the grace window, a manifest-less dir is abandoned → reaped. Backdate
    // it first: on APFS a new dir's mtime can sit a fraction of a ms AFTER
    // Date.now(), so a grace of 0 would still see it as not yet old.
    const past = new Date(Date.now() - 5_000);
    utimesSync(fresh.dir, past, past);
    assert.deepEqual(sweepDeadInstances(base, 0), ["fresh"]);
  } finally {
    cleanup();
  }
});

test("pidAlive: this process is alive; an impossible pid is not", () => {
  assert.equal(pidAlive(process.pid), true);
  assert.equal(pidAlive(2 ** 30), false);
});

test("instancePaths shapes the dir layout without touching the filesystem", () => {
  const p = instancePaths("/base", "id1");
  assert.equal(p.dir, "/base/instances/id1");
  assert.equal(p.sockPath, "/base/instances/id1/arbiter.sock");
  assert.equal(p.manifestPath, "/base/instances/id1/manifest.json");
  assert.equal(p.logsDir, "/base/instances/id1/logs");
});

// ── runtime-instances.md §13: no promotion from a foreign HOME (2026-09-28) ──

test("foreignHomePromotion: refuses only a foreign HOME at the account's own rendezvous", () => {
  const account = { home: "/home/u", rendezvous: "/run/user/1001/mandu" };
  const why = foreignHomePromotion("/run/user/1001/mandu", { HOME: "/tmp/scratch/home" }, account);
  assert.ok(why !== null && why.includes("/tmp/scratch/home") && why.includes("/home/u"), String(why));
  assert.equal(foreignHomePromotion("/run/user/1001/mandu/", { HOME: "/home/u/" }, account), null, "the real home");
  assert.equal(foreignHomePromotion("/tmp/iso/mandu", { HOME: "/tmp/scratch/home" }, account), null, "an isolated base");
  assert.equal(foreignHomePromotion("/run/user/1001/mandu", {}, account), null, "no HOME: no guess");
  assert.equal(foreignHomePromotion("/run/user/1001/mandu", { HOME: "/tmp/x" }, null), null, "unknown account: no guess");
});

test("foreignHomePromotion: MANDU_HOME never lifts the refusal, and the reason says where the stores are", () => {
  const account = { home: "/home/u", rendezvous: "/run/user/1001/mandu" };
  const at = (env: NodeJS.ProcessEnv): string | null => foreignHomePromotion("/run/user/1001/mandu", env, account);
  // MANDU_HOME inside the foreign HOME (what the launcher drops): refused, the stores named there.
  const inside = at({ HOME: "/tmp/scratch/home", MANDU_HOME: "/tmp/scratch/home/state/.mandu" });
  assert.ok(inside !== null && inside.includes("symbol DB, policy and events under that HOME (/tmp/scratch/home/state/.mandu)"), String(inside));
  // No MANDU_HOME: $HOME/.mandu, inside the foreign HOME.
  assert.match(String(at({ HOME: "/tmp/scratch/home" })), /under that HOME \(\/tmp\/scratch\/home\/\.mandu\)/);
  // MANDU_HOME set elsewhere (what the launcher keeps), even the account's own
  // ~/.mandu: still refused, since HOME is the policy's ~ (secret catalog, path labels).
  for (const mh of ["/data/mandu", "/home/u/.mandu"]) {
    const why = at({ HOME: "/tmp/scratch/home", MANDU_HOME: mh });
    assert.ok(why !== null && why.includes(`its stores in MANDU_HOME ${mh}`) && why.includes("secret catalog"), String(why));
  }
  // The account's HOME with a relocated MANDU_HOME: a deliberate move, promoted
  // (the launcher keeps such a MANDU_HOME too).
  assert.equal(at({ HOME: "/home/u", MANDU_HOME: "/data/mandu" }), null);
  assert.equal(at({ HOME: "/home/u", MANDU_HOME: "" }), null, "an empty MANDU_HOME counts as unset");
});

test("accountIdentity: the rendezvous is /run/user/<uid>/mandu on Linux and /tmp/mandu-<uid> on macOS (not the inert Linux path)", () => {
  const darwin = accountIdentity({
    platform: "darwin", getuid: () => 501, homedir: () => "/Users/u",
    darwinTempDir: () => "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/",
  });
  assert.deepEqual(darwin, { home: "/Users/u", rendezvous: "/tmp/mandu-501" });
  assert.deepEqual(accountIdentity({ platform: "linux", getuid: () => 1001, homedir: () => "/home/u" }), {
    home: "/home/u", rendezvous: "/run/user/1001/mandu",
  });
  assert.equal(accountIdentity({ getuid: null }), null, "no getuid: no guess");
  assert.equal(accountIdentity({ getuid: () => 1, homedir: () => { throw new Error("no passwd entry"); } }), null);
});

test("foreignHomePromotion on macOS: a scratch-HOME instance at /tmp/mandu-<uid> is refused; an isolated base is not", () => {
  const account = accountIdentity({
    platform: "darwin", getuid: () => 501, homedir: () => "/Users/u",
    darwinTempDir: () => "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/",
  });
  assert.ok(foreignHomePromotion("/tmp/mandu-501", { HOME: "/tmp/scratch/home" }, account) !== null);
  assert.equal(foreignHomePromotion("/tmp/mandu-501", { HOME: "/Users/u" }, account), null);
  assert.equal(foreignHomePromotion("/tmp/mdu-iso/rt", { HOME: "/tmp/scratch/home" }, account), null);
});
