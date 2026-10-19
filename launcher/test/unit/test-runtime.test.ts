/**
 * test-runtime.test — the launcher tests' own runtime dir
 * (test/lib/test-runtime.ts, test-organization.md §8.7): an env that names no
 * runtime dir gets the file's private one, so a test never resolves the
 * host's shared /tmp/mandu; an env that names one is left alone.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { statSync } from "node:fs";
import { tmpdir } from "node:os";
import { parse } from "../../src/parse.js";
import { resolveRuntimeBase } from "../../src/runtime-base.js";
import { hermetic, testRuntimeDir, withTestRuntime } from "../lib/test-runtime.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // no arbiter here; stated per the suite rule

test("why: an env naming no runtime dir resolves the host's real /tmp/mandu-<uid> (the shared /tmp/mandu before 2026-10-09)", () => {
  assert.equal(resolveRuntimeBase({}, { platform: "linux" }).base, `/tmp/mandu-${process.getuid!()}`);
});

test("withTestRuntime: a private dir of the file's own when the env names none; else the env unchanged", () => {
  const dir = testRuntimeDir();
  assert.equal(testRuntimeDir(), dir, "one per file");
  assert.ok(dir.startsWith(tmpdir()), dir);
  const st = statSync(dir);
  assert.equal(st.mode & 0o777, 0o700);
  assert.equal(st.uid, process.getuid?.() ?? st.uid);
  const env = withTestRuntime({ HOME: "/h" });
  assert.deepEqual(env, { HOME: "/h", XDG_RUNTIME_DIR: dir });
  assert.equal(resolveRuntimeBase(env).base, `${dir}/mandu`);
  for (const own of [{ MANDU_RUNTIME_DIR: "/r" }, { XDG_RUNTIME_DIR: "/run/u" }, { TMPDIR: "/t" }]) {
    assert.equal(withTestRuntime(own), own, JSON.stringify(own));
  }
});

test("hermetic: only the env argument is changed, and an omitted one keeps the function's default", () => {
  const seen: unknown[][] = [];
  const f = hermetic((...a: unknown[]) => { seen.push(a); return a.length; }, 1);
  f("x", {}, "y");
  assert.deepEqual(seen[0], ["x", { XDG_RUNTIME_DIR: testRuntimeDir() }, "y"]);
  f("x");
  assert.deepEqual(seen[1], ["x"], "no env given: the function's own default stands");
  // A launch parsed through it never names /tmp/mandu.
  const p = hermetic(parse, 1)(["claude"], {});
  assert.ok(!p.arbiterSock.startsWith("/tmp/mandu/"), p.arbiterSock);
  assert.ok(p.arbiterSock.startsWith(testRuntimeDir()), p.arbiterSock);
});
