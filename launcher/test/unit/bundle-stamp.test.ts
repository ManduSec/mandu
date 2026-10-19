/**
 * bundle-stamp — the build record that decides whether a checkout's
 * launcher/dist may run instead of the source (packaging.md §5.1;
 * launcher/scripts/bundle-stamp.mjs). Fresh only when every recorded input and
 * output is unchanged; everything else is stale, so a stale bundle never runs.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, rmSync, utimesSync, writeFileSync, existsSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import {
  BUILD_SCRIPT_INPUTS, STAMP_NAME, checkStamp, clearStamp, fsClockMs, stampInputs, writeStamp,
} from "../../scripts/bundle-stamp.mjs";
import { tmpDir } from "../lib/tmp-dir.js";

/** A fake repo: two source files in a package with a tsconfig, one
 *  node_modules file, and a dist holding one built output. */
function fixture() {
  const root = tmpDir("mandu-stamp-");
  const repo = join(root, "repo");
  const dist = join(repo, "launcher", "dist");
  for (const d of ["arbiter/ipc", "arbiter/node_modules/js-yaml", "launcher/src"]) mkdirSync(join(repo, d), { recursive: true });
  mkdirSync(dist, { recursive: true });
  writeFileSync(join(repo, "arbiter", "package.json"), "{}");
  writeFileSync(join(repo, "arbiter", "tsconfig.json"), "{}");
  writeFileSync(join(repo, "arbiter", "ipc", "server-main.ts"), "export {};\n");
  writeFileSync(join(repo, "arbiter", "node_modules", "js-yaml", "index.mjs"), "export {};\n");
  writeFileSync(join(repo, "arbiter", "node_modules", ".package-lock.json"), "{}");
  writeFileSync(join(repo, "launcher", "package.json"), "{}");
  writeFileSync(join(repo, "launcher", "src", "run.ts"), "export {};\n");
  writeFileSync(join(dist, "mandu.mjs"), "// built\n");
  // Every input predates the build start.
  const past = new Date(Date.now() - 60_000);
  for (const f of ["arbiter/package.json", "arbiter/tsconfig.json", "arbiter/ipc/server-main.ts", "arbiter/node_modules/js-yaml/index.mjs",
    "arbiter/node_modules/.package-lock.json", "launcher/package.json", "launcher/src/run.ts"]) utimesSync(join(repo, f), past, past);
  const inputs = stampInputs(repo, ["arbiter/ipc/server-main.ts", "arbiter/node_modules/js-yaml/index.mjs", "launcher/src/run.ts", "<runtime>"]);
  return { root, repo, dist, inputs };
}

test("stampInputs: the metafile inputs plus each source package's package.json + tsconfig.json, each node_modules tree's .package-lock.json, and the build's own files that exist", () => {
  const f = fixture();
  try {
    assert.deepEqual(f.inputs, [
      "arbiter/ipc/server-main.ts",
      "arbiter/node_modules/.package-lock.json",
      "arbiter/node_modules/js-yaml/index.mjs",
      "arbiter/package.json",
      "arbiter/tsconfig.json",
      "launcher/package.json",
      "launcher/src/run.ts",
    ], "virtual inputs (<runtime>) are skipped; a missing tsconfig or build script is not an input");
    // In the real repo every build script is an input.
    const all = stampInputs("/r", ["a/x.ts"], () => true);
    for (const b of BUILD_SCRIPT_INPUTS) assert.ok(all.includes(b), b);
    assert.ok(all.includes("a/package.json") && all.includes("a/tsconfig.json"));
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("writeStamp + checkStamp: a clean build is fresh; the record names the repo and each input's mtime and size", () => {
  const f = fixture();
  try {
    assert.equal(writeStamp(f.dist, { repoRoot: f.repo, inputs: f.inputs, outputs: ["mandu.mjs"], startMs: fsClockMs(f.dist) }), null);
    const r = checkStamp(f.dist, { repoRoot: f.repo });
    assert.deepEqual(r, { fresh: true, inputs: f.inputs.length });
    const rec = JSON.parse(readFileSync(join(f.dist, STAMP_NAME), "utf8")) as { root: string; inputs: Record<string, [number, number]> };
    assert.equal(rec.root, f.repo);
    assert.equal(rec.inputs["launcher/src/run.ts"]![1], "export {};\n".length);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("checkStamp: STALE on an edited, resized or deleted input, a replaced or missing output, no record, another record version, or another repo", () => {
  const f = fixture();
  // A clean build of the tree as it is now: every input dated well before it.
  const T = new Date(Date.now() - 60_000);
  const stamp = () => {
    for (const i of f.inputs) if (existsSync(join(f.repo, i))) utimesSync(join(f.repo, i), T, T);
    assert.equal(writeStamp(f.dist, { repoRoot: f.repo, inputs: f.inputs, outputs: ["mandu.mjs"], startMs: fsClockMs(f.dist) }), null);
  };
  const stale = (re: RegExp, msg: string) => {
    const r = checkStamp(f.dist, { repoRoot: f.repo });
    assert.equal(r.fresh, false, msg);
    assert.match((r as { reason: string }).reason, re, msg);
  };
  try {
    stamp();
    // An edit (git checkout, an editor save) moves the mtime.
    const src = join(f.repo, "arbiter", "ipc", "server-main.ts");
    utimesSync(src, new Date(), new Date());
    stale(/arbiter\/ipc\/server-main\.ts changed since the build/, "edited input");

    stamp();
    // npm backdates extracted files; its lock file is what moves.
    writeFileSync(join(f.repo, "arbiter", "node_modules", ".package-lock.json"), '{"v":2}');
    stale(/\.package-lock\.json changed/, "npm install");

    stamp();
    // Same mtime, different size: still a change (a copy that kept mtimes).
    writeFileSync(src, "export const x = 22;\n");
    utimesSync(src, T, T);
    stale(/server-main\.ts changed/, "resized input, same mtime");

    stamp();
    rmSync(join(f.repo, "launcher", "src", "run.ts"));
    stale(/launcher\/src\/run\.ts changed/, "deleted input");
    writeFileSync(join(f.repo, "launcher", "src", "run.ts"), "export {};\n");

    stamp();
    writeFileSync(join(f.dist, "mandu.mjs"), "// half a build\n");
    stale(/the built mandu\.mjs is missing or was replaced/, "replaced output");
    stamp();
    rmSync(join(f.dist, "mandu.mjs"));
    stale(/mandu\.mjs is missing/, "missing output");
    writeFileSync(join(f.dist, "mandu.mjs"), "// built\n");

    clearStamp(f.dist);
    stale(/no build record/, "no record (never built, or a build that did not finish)");

    stamp();
    const rec = JSON.parse(readFileSync(join(f.dist, STAMP_NAME), "utf8"));
    writeFileSync(join(f.dist, STAMP_NAME), JSON.stringify({ ...rec, version: 0 }));
    stale(/another version of the build/, "old record format");
    writeFileSync(join(f.dist, STAMP_NAME), "{not json");
    stale(/no build record/, "unreadable record");

    stamp();
    const other = checkStamp(f.dist, { repoRoot: join(f.root, "elsewhere") });
    assert.equal(other.fresh, false);
    assert.match((other as { reason: string }).reason, /it was built from/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("checkStamp: the repo root is compared through symlinks (a shell's `pwd` vs node's realpath)", () => {
  const f = fixture();
  try {
    assert.equal(writeStamp(f.dist, { repoRoot: f.repo, inputs: f.inputs, outputs: ["mandu.mjs"], startMs: fsClockMs(f.dist) }), null);
    const link = join(f.root, "link");
    symlinkSync(f.repo, link);
    assert.equal(checkStamp(f.dist, { repoRoot: link }).fresh, true);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("writeStamp DECLINES when an input changed while the build ran (its mtime is not older than the build start): no record, so the next launch rebuilds", () => {
  const f = fixture();
  try {
    const startMs = fsClockMs(f.dist);
    const src = join(f.repo, "arbiter", "ipc", "server-main.ts");
    utimesSync(src, new Date(startMs + 5), new Date(startMs + 5));
    const why = writeStamp(f.dist, { repoRoot: f.repo, inputs: f.inputs, outputs: ["mandu.mjs"], startMs });
    assert.match(String(why), /arbiter\/ipc\/server-main\.ts changed during the build/);
    assert.equal(existsSync(join(f.dist, STAMP_NAME)), false);
    assert.equal(checkStamp(f.dist, { repoRoot: f.repo }).fresh, false);
    // An output that is missing at the end is no clean build either.
    utimesSync(src, new Date(startMs - 60_000), new Date(startMs - 60_000));
    assert.match(String(writeStamp(f.dist, { repoRoot: f.repo, inputs: f.inputs, outputs: ["nope.mjs"], startMs })), /the output nope\.mjs is missing/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});
