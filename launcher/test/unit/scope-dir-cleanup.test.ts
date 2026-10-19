/**
 * scope-dir-cleanup.test — a clean launch removes its own scope run dir and
 * nothing else (src/scope-dir-cleanup.ts; runtime-instances.md §10.1).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  removeOwnScopeDir,
  scopeDirCleanupDecision,
  type ScopeDirCleanupInput,
} from "../../src/scope-dir-cleanup.js";

const BASE = "/run/user/1000/mandu";
function input(over: Partial<ScopeDirCleanupInput> = {}): ScopeDirCleanupInput {
  return {
    scopeRunDir: `${BASE}/1790000000-4242`,
    runtimeBase: BASE,
    scopeId: "1790000000-4242",
    scopeIdGenerated: true,
    pid: 4242,
    code: 0,
    startedPinnedArbiter: false,
    arbiterSock: `${BASE}/current/arbiter.sock`,
    keep: false,
    ...over,
  };
}

test("decision: a clean end of a launch with its own minted scope id removes the dir", () => {
  assert.deepEqual(scopeDirCleanupDecision(input()), { remove: true });
});

test("decision: every condition that keeps the dir, each with its reason", () => {
  const cases: Array<[Partial<ScopeDirCleanupInput>, RegExp]> = [
    [{ keep: true }, /MANDU_KEEP_SCOPE_DIR/],
    [{ code: 3 }, /exited 3.*diagnosis/],
    [{ code: 130 }, /exited 130/],
    [{ scopeIdGenerated: false }, /named/],
    // A minted-looking id that is not this pid's (another launcher's).
    [{ scopeId: "1790000000-4243", scopeRunDir: `${BASE}/1790000000-4243` }, /not this launcher's/],
    [{ scopeId: "instances", scopeRunDir: `${BASE}/instances` }, /not this launcher's/],
    // The dir is not <base>/<id> (a traversal, another base).
    [{ scopeRunDir: `${BASE}/../1790000000-4242` }, /not <runtime base>/],
    [{ scopeRunDir: "/tmp/1790000000-4242" }, /not <runtime base>/],
    [{ runtimeBase: "relative/mandu", scopeRunDir: "relative/mandu/1790000000-4242" }, /not <runtime base>/],
    [{ startedPinnedArbiter: true }, /arbiter this launch started/],
    [{ arbiterSock: `${BASE}/1790000000-4242/arbiter.sock` }, /socket lives there/],
  ];
  for (const [over, why] of cases) {
    const v = scopeDirCleanupDecision(input(over));
    assert.equal(v.remove, false, JSON.stringify(over));
    assert.match((v as { reason: string }).reason, why, JSON.stringify(over));
  }
  // A socket beside the scope dir (same prefix, another name) does not keep it.
  assert.deepEqual(scopeDirCleanupDecision(input({ arbiterSock: `${BASE}/1790000000-4242x/arbiter.sock` })), { remove: true });
});

test("remove: the whole tree goes (unreadable files, nested dirs); its siblings stay", () => {
  const base = mkdtempSync(join(tmpdir(), "mandu-scope-rm-"));
  try {
    const dir = join(base, "1790000000-4242");
    mkdirSync(join(dir, "events"), { recursive: true });
    mkdirSync(join(dir, "secret-twins", "a"), { recursive: true });
    writeFileSync(join(dir, "launch.log"), "x\n");
    writeFileSync(join(dir, "secret-twins", "a", "t"), "", { mode: 0o000 });
    const sibling = join(base, "1790000000-9999");
    mkdirSync(sibling);
    // A link inside the tree is unlinked, never followed.
    const outside = join(base, "outside");
    mkdirSync(outside);
    writeFileSync(join(outside, "keep"), "k");
    symlinkSync(outside, join(dir, "link"));
    assert.deepEqual(removeOwnScopeDir(dir), { removed: true });
    assert.equal(existsSync(dir), false);
    assert.equal(existsSync(sibling), true);
    assert.equal(existsSync(join(outside, "keep")), true, "the link's target is untouched");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("remove: a symlinked scope dir is refused (its target untouched); a missing one is no error", () => {
  const base = mkdtempSync(join(tmpdir(), "mandu-scope-rm-"));
  try {
    const target = join(base, "elsewhere");
    mkdirSync(target);
    writeFileSync(join(target, "keep"), "k");
    const link = join(base, "1790000000-4242");
    symlinkSync(target, link);
    const r = removeOwnScopeDir(link);
    assert.equal(r.removed, false);
    assert.match(r.error ?? "", /not a directory/);
    assert.equal(existsSync(join(target, "keep")), true);
    assert.deepEqual(removeOwnScopeDir(join(base, "absent")), { removed: false });
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("remove: a dir owned by another uid is refused; an rm failure is reported, never thrown", () => {
  const dirStat = { isDirectory: () => true, isSymbolicLink: () => false, uid: 0 };
  let rmCalls = 0;
  const other = removeOwnScopeDir("/x", { lstat: () => dirStat, rm: () => { rmCalls++; }, uid: 1000 });
  assert.equal(other.removed, false);
  assert.match(other.error ?? "", /not owned by uid 1000/);
  assert.equal(rmCalls, 0);
  const failing = removeOwnScopeDir("/x", {
    lstat: () => ({ ...dirStat, uid: 1000 }),
    rm: () => { throw Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" }); },
    uid: 1000,
  });
  assert.equal(failing.removed, false);
  assert.match(failing.error ?? "", /EACCES/);
});

test("remove: a read-only subdir the agent left makes it a reported failure, the dir left for reap", { skip: process.getuid?.() === 0 ? "root ignores dir modes" : false }, () => {
  const base = mkdtempSync(join(tmpdir(), "mandu-scope-rm-"));
  const dir = join(base, "1790000000-4242");
  const ro = join(dir, "ro");
  try {
    mkdirSync(ro, { recursive: true });
    writeFileSync(join(ro, "f"), "x");
    chmodSync(ro, 0o500);
    const r = removeOwnScopeDir(dir);
    assert.equal(r.removed, false);
    assert.ok(r.error, "the failure is reported");
    assert.equal(existsSync(dir), true, "left for mandu reap");
  } finally {
    try { chmodSync(ro, 0o700); } catch { /* gone */ }
    rmSync(base, { recursive: true, force: true });
  }
});
