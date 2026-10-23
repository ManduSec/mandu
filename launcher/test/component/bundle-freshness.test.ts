/**
 * bundle-freshness — a source checkout runs its prebuilt launcher/dist only
 * while that bundle matches the source (packaging.md §5.1).
 *
 *   1. launcher/mandu-run.sh and bin/mandu.mjs with its checkout prelude
 *      (scripts/checkout-launch.mjs), the real scripts, in a stand-in checkout
 *      whose tsx, built launcher and build-bundle.mjs are stubs that say which
 *      ran: fresh → the bundle, no build, ONE node process in all; stale → one
 *      rebuild, then the bundle; stale and the rebuild fails or leaves no
 *      record → the source (tsx) in place of the launcher's node, loudly
 *      (and as a mirrored child on a node without process.execve);
 *      MANDU_FROM_SOURCE=1 → the source even when fresh; an installed package
 *      (no src/, no tsx) → the bundle; the hand-off variable never reaches
 *      the launcher. The secrets half of the prelude is
 *      tests/stack/shim-secrets-env.test.ts.
 *   2. the real build-bundle.mjs into a private dir: it ends with a build record
 *      the real check calls fresh; a changed input makes it stale; --if-stale
 *      rebuilds a stale bundle and leaves a fresh one alone; two concurrent
 *      --if-stale runs (two launches after an edit) serialize on the build
 *      lock and end fresh; the record never ships in the npm tarball
 *      (npm-pack.test.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { STAMP_NAME } from "../../scripts/bundle-stamp.mjs";
import { tmpDir } from "../lib/tmp-dir.js";
import { stateAxes } from "../axes.js";

stateAxes("off"); // which program runs; no arbiter decides anything here

const PKG_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const REPO_ROOT = resolve(PKG_ROOT, "..");

// ── 1. the shim's decision ──────────────────────────────────────────────────

/** A stand-in checkout: <root>/launcher with the real mandu-run.sh,
 *  bin/mandu.mjs and its checkout prelude (scripts/checkout-launch.mjs,
 *  bundle-stamp.mjs), and stubs that report what ran into <root>/ran.log: the
 *  built launcher (dist/mandu.mjs, whose main() logs `bundle <argv>`), tsx
 *  and the build. A `node` first on PATH counts the node processes the
 *  launch starts by name (<root>/node.log). */
function standInCheckout(opts: { installed?: boolean } = {}) {
  const root = tmpDir("mandu-shim-");
  const pkg = join(root, "launcher");
  const ranLog = join(root, "ran.log");
  const nodeLog = join(root, "node.log");
  const home = join(root, "home"); // no secrets file to find
  const pathDir = join(root, "path");
  for (const d of ["bin", "scripts", "dist", "src", "node_modules/.bin"]) mkdirSync(join(pkg, d), { recursive: true });
  mkdirSync(home);
  mkdirSync(pathDir);
  copyFileSync(join(PKG_ROOT, "mandu-run.sh"), join(pkg, "mandu-run.sh"));
  copyFileSync(join(PKG_ROOT, "bin", "mandu.mjs"), join(pkg, "bin", "mandu.mjs"));
  copyFileSync(join(PKG_ROOT, "scripts", "bundle-stamp.mjs"), join(pkg, "scripts", "bundle-stamp.mjs"));
  copyFileSync(join(PKG_ROOT, "scripts", "checkout-launch.mjs"), join(pkg, "scripts", "checkout-launch.mjs"));
  writeFileSync(join(pkg, "dist", "mandu.mjs"), `// the built launcher
import { appendFileSync, writeFileSync } from "node:fs";
export async function main(argv) {
  appendFileSync(${JSON.stringify(ranLog)}, "bundle " + argv.join(" ") + "\\n");
  if (process.env.DUMP_ENV) writeFileSync(process.env.DUMP_ENV, JSON.stringify(process.env));
  return Number(process.env.FAKE_MAIN_EXIT ?? 0);
}
`);
  writeFileSync(join(pathDir, "node"), `#!/bin/sh\necho node >> ${JSON.stringify(nodeLog)}\nexec ${JSON.stringify(process.execPath)} "$@"\n`);
  chmodSync(join(pathDir, "node"), 0o755);
  if (!opts.installed) {
    writeFileSync(join(pkg, "src", "run.ts"), "export {};\n");
    writeFileSync(join(pkg, "node_modules", ".bin", "tsx"), `#!/usr/bin/env bash\necho "tsx $*" >> ${JSON.stringify(ranLog)}\nexit "\${FAKE_TSX_EXIT:-0}"\n`);
    chmodSync(join(pkg, "node_modules", ".bin", "tsx"), 0o755);
  }
  // The build stub: FAKE_BUILD=ok writes a clean record over the one input
  // (src/run.ts, dated before the build); =fail exits 1; =nostamp exits 0 and
  // leaves no record (an input changed during the build).
  writeFileSync(join(pkg, "scripts", "build-bundle.mjs"), `
import { appendFileSync, utimesSync } from "node:fs";
import { join } from "node:path";
import { writeStamp, fsClockMs, clearStamp } from "./bundle-stamp.mjs";
appendFileSync(${JSON.stringify(ranLog)}, "build " + process.argv.slice(2).join(" ") + "\\n");
const mode = process.env.FAKE_BUILD ?? "ok";
if (mode === "fail") process.exit(1);
const repo = ${JSON.stringify(root)}, dist = join(repo, "launcher", "dist");
clearStamp(dist);
if (mode === "nostamp") process.exit(0);
const past = new Date(Date.now() - 60_000);
utimesSync(join(repo, "launcher", "src", "run.ts"), past, past);
const why = writeStamp(dist, { repoRoot: repo, inputs: ["launcher/src/run.ts"], outputs: ["mandu.mjs"], startMs: fsClockMs(dist) });
process.exit(why === null ? 0 : 1);
`);
  const run = (env: Record<string, string> = {}) => {
    writeFileSync(ranLog, "");
    writeFileSync(nodeLog, "");
    const r = spawnSync("bash", [join(pkg, "mandu-run.sh"), "claude", "--version"], {
      cwd: root, encoding: "utf8", timeout: 60_000,
      env: { PATH: `${pathDir}:${process.env["PATH"]}`, HOME: home, ...env },
    });
    return {
      status: r.status, stderr: r.stderr,
      ran: readFileSync(ranLog, "utf8").trim().split("\n").filter(Boolean),
      nodeStarts: readFileSync(nodeLog, "utf8").trim().split("\n").filter(Boolean).length,
    };
  };
  /** Build once (through the stub) so the bundle is fresh. */
  const makeFresh = () => {
    const r = spawnSync("node", [join(pkg, "scripts", "build-bundle.mjs")], { encoding: "utf8", env: { ...process.env, FAKE_BUILD: "ok" } });
    assert.equal(r.status, 0, r.stderr);
  };
  const editSource = () => { const now = new Date(); utimesSync(join(pkg, "src", "run.ts"), now, now); };
  return { root, pkg, run, makeFresh, editSource };
}

test("mandu-run.sh: a FRESH bundle runs through bin/mandu.mjs with no build, in ONE node process (the check runs in it)", () => {
  const c = standInCheckout();
  c.makeFresh();
  const r = c.run();
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.ran, ["bundle claude --version"]);
  assert.equal(r.nodeStarts, 1, "no node of the shim's own before the launcher (it was three: secrets, stamp check, launcher)");
  assert.equal(r.stderr, "", "a quiet launch with no secrets file prints nothing of its own");
  assert.equal(c.run({ FAKE_MAIN_EXIT: "3" }).status, 3, "the launcher's exit code is the launch's");
});

test("mandu-run.sh: the checkout hand-off (MANDU_SHIM_CHECKOUT) never reaches the launcher's environment, and an inherited one is not trusted", () => {
  const c = standInCheckout();
  c.makeFresh();
  const dump = join(c.root, "env.json");
  const r = c.run({ DUMP_ENV: dump, MANDU_SHIM_CHECKOUT: "/elsewhere" });
  assert.equal(r.status, 0, r.stderr);
  const env = JSON.parse(readFileSync(dump, "utf8")) as Record<string, string>;
  assert.equal(env["MANDU_SHIM_CHECKOUT"], undefined);
  // An installed package handed an inherited one runs as installed: the shim
  // drops it, so bin/mandu.mjs looks for no checkout prelude.
  const inst = standInCheckout({ installed: true });
  const ri = inst.run({ MANDU_SHIM_CHECKOUT: c.root });
  assert.equal(ri.status, 0, ri.stderr);
  assert.deepEqual(ri.ran, ["bundle claude --version"]);
});

test("mandu-run.sh: a STALE bundle is rebuilt once (--if-stale, no native bins), then the bundle runs", () => {
  const c = standInCheckout();
  c.makeFresh();
  c.editSource();
  const r = c.run();
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.ran, ["build --if-stale --no-native --quiet", "bundle claude --version"]);
  // Fresh again: the next launch builds nothing.
  assert.deepEqual(c.run().ran, ["bundle claude --version"]);
});

test("mandu-run.sh: a never-built checkout builds first", () => {
  const c = standInCheckout();
  const r = c.run();
  assert.deepEqual(r.ran, ["build --if-stale --no-native --quiet", "bundle claude --version"]);
});

test("mandu-run.sh: a stale bundle that cannot be rebuilt NEVER runs: the source runs through tsx, and the shim says why", () => {
  const c = standInCheckout();
  c.makeFresh();
  c.editSource();
  const failed = c.run({ FAKE_BUILD: "fail" });
  assert.deepEqual(failed.ran, ["build --if-stale --no-native --quiet", "tsx " + join(c.pkg, "src", "run.ts") + " claude --version"]);
  assert.match(failed.stderr, /out of date and could not be rebuilt; running from source/);
  // A build that exits 0 but leaves no record (an input changed while it ran)
  // is not trusted either: the re-check after the build decides.
  const unrecorded = c.run({ FAKE_BUILD: "nostamp" });
  assert.deepEqual(unrecorded.ran, ["build --if-stale --no-native --quiet", "tsx " + join(c.pkg, "src", "run.ts") + " claude --version"]);
  // The source REPLACES the launcher's node (execve, as the shim's exec did):
  // its exit status is the launch's.
  assert.equal(c.run({ FAKE_BUILD: "fail", FAKE_TSX_EXIT: "7" }).status, 7);
});

test("mandu-run.sh: on a node without process.execve the stale fallback runs the source as a child and mirrors its exit", () => {
  const c = standInCheckout();
  c.makeFresh();
  c.editSource();
  const noExecve = join(c.root, "no-execve.mjs");
  writeFileSync(noExecve, "delete process.execve;\nif (typeof process.execve === 'function') process.execve = undefined;\n");
  const r = c.run({ FAKE_BUILD: "fail", FAKE_TSX_EXIT: "5", NODE_OPTIONS: `--import=${pathToFileURL(noExecve).href}` });
  assert.deepEqual(r.ran, ["build --if-stale --no-native --quiet", "tsx " + join(c.pkg, "src", "run.ts") + " claude --version"]);
  assert.match(r.stderr, /out of date and could not be rebuilt; running from source/);
  assert.equal(r.status, 5);
});

test("mandu-run.sh: MANDU_FROM_SOURCE=1 runs the source through tsx even when the bundle is fresh, and builds nothing", () => {
  const c = standInCheckout();
  c.makeFresh();
  for (const v of ["1", "true", "yes"]) {
    assert.deepEqual(c.run({ MANDU_FROM_SOURCE: v }).ran, ["tsx " + join(c.pkg, "src", "run.ts") + " claude --version"], v);
  }
  assert.deepEqual(c.run({ MANDU_FROM_SOURCE: "0" }).ran, ["bundle claude --version"], "0 is not a request");
});

test("mandu-run.sh: an installed package (no src/, no tsx) runs its bundle with no freshness check or build", () => {
  const c = standInCheckout({ installed: true });
  assert.deepEqual(c.run().ran, ["bundle claude --version"]);
});

// ── 2. the real build and its record ────────────────────────────────────────

const STAMP_CLI = join(PKG_ROOT, "scripts", "bundle-stamp.mjs");
const BUILD = join(PKG_ROOT, "scripts", "build-bundle.mjs");
const fresh = (dist: string) => spawnSync("node", [STAMP_CLI, "--why", `--root=${REPO_ROOT}`, dist], { encoding: "utf8" });
const build = (dist: string, ...flags: string[]) =>
  spawnSync("node", [BUILD, `--outdir=${dist}`, "--no-native", ...flags], { cwd: PKG_ROOT, encoding: "utf8", timeout: 180_000 });

/** Mark one recorded input as changed since the build, without touching the
 *  real source (other suites read it): the record's mtime for it moves. */
function simulateEdit(dist: string, rel: string): void {
  const p = join(dist, STAMP_NAME);
  const rec = JSON.parse(readFileSync(p, "utf8")) as { inputs: Record<string, [number, number]> };
  assert.ok(rec.inputs[rel], `${rel} is a recorded input`);
  rec.inputs[rel] = [rec.inputs[rel]![0] - 1000, rec.inputs[rel]![1]];
  writeFileSync(p, JSON.stringify(rec));
}

test("build-bundle.mjs: a clean build is recorded fresh over the inputs esbuild read; a changed input is stale; --if-stale rebuilds it and leaves a fresh one alone", { timeout: 300_000 }, () => {
  const dist = join(tmpDir("mandu-bundle-fresh-"), "dist");
  const b = build(dist);
  assert.equal(b.status, 0, `${b.stdout}\n${b.stderr}`);
  assert.equal(fresh(dist).status, 0, fresh(dist).stderr);
  const rec = JSON.parse(readFileSync(join(dist, STAMP_NAME), "utf8")) as { root: string; inputs: Record<string, unknown>; outputs: Record<string, unknown> };
  assert.equal(rec.root, REPO_ROOT);
  for (const must of ["launcher/src/run.ts", "arbiter/ipc/server-main.ts", "interceptors/exec-wrap/src/wrap.ts", "launcher/bundle-manifest.json",
    "launcher/scripts/build-bundle.mjs", "arbiter/package.json"]) {
    assert.ok(must in rec.inputs, `${must} is recorded`);
  }
  assert.ok("mandu.mjs" in rec.outputs && "exec-shim.mjs" in rec.outputs, "the outputs are recorded");
  assert.ok(!existsSync(join(dist, ".build.lock")), "the lock is released");
  // Every package whose files (or node_modules) the build read is one
  // `suites.mjs packages --bundle` lists: what the OS test matrix's host prep
  // installs in a clean checkout before `npm pack` (os-test-matrix.md §10.3.2).
  const listed = spawnSync("node", [join(REPO_ROOT, "scripts", "suites.mjs"), "packages", "--bundle"], { cwd: REPO_ROOT, encoding: "utf8" });
  assert.equal(listed.status, 0, listed.stderr);
  const bundlePkgs = new Set(listed.stdout.split("\n").filter(Boolean));
  for (const rel of Object.keys(rec.inputs)) {
    let pkg: string | null = null;
    if (rel.includes("/node_modules/")) pkg = rel.slice(0, rel.indexOf("/node_modules/"));
    else for (let d = dirname(rel); d !== "." && d !== ""; d = dirname(d)) if (existsSync(join(REPO_ROOT, d, "package.json"))) { pkg = d; break; }
    if (pkg !== null) assert.ok(bundlePkgs.has(pkg), `${rel}: its package ${pkg} is not in \`suites.mjs packages --bundle\` (${[...bundlePkgs].join(", ")})`);
  }

  simulateEdit(dist, "interceptors/exec-wrap/src/wrap.ts");
  const stale = fresh(dist);
  assert.equal(stale.status, 1);
  assert.match(stale.stderr, /interceptors\/exec-wrap\/src\/wrap\.ts changed since the build/);

  const re = build(dist, "--if-stale");
  assert.equal(re.status, 0, `${re.stdout}\n${re.stderr}`);
  assert.match(re.stdout, /rebuilding: interceptors\/exec-wrap\/src\/wrap\.ts changed/);
  assert.equal(fresh(dist).status, 0);

  const before = statSync(join(dist, "mandu.mjs")).mtimeMs;
  const noop = build(dist, "--if-stale");
  assert.equal(noop.status, 0);
  assert.match(noop.stdout, /up to date/);
  assert.equal(statSync(join(dist, "mandu.mjs")).mtimeMs, before, "a fresh bundle is not rewritten");
});

test("build-bundle.mjs --if-stale: two launches that both find the bundle stale serialize on the build lock and end fresh", { timeout: 300_000 }, async () => {
  const dist = join(tmpDir("mandu-bundle-lock-"), "dist");
  assert.equal(build(dist).status, 0);
  simulateEdit(dist, "launcher/src/run.ts");
  const runOne = () => new Promise<{ code: number | null; out: string }>((res) => {
    const c = spawn("node", [BUILD, `--outdir=${dist}`, "--no-native", "--if-stale"], { cwd: PKG_ROOT });
    let out = "";
    c.stdout.on("data", (d) => { out += d; });
    c.stderr.on("data", (d) => { out += d; });
    c.on("exit", (code) => res({ code, out }));
  });
  const [a, b] = await Promise.all([runOne(), runOne()]);
  assert.equal(a.code, 0, a.out);
  assert.equal(b.code, 0, b.out);
  const rebuilt = [a, b].filter((r) => /building \d+ bundles/.test(r.out)).length;
  assert.equal(rebuilt, 1, `exactly one of them builds; the other finds it fresh under the lock:\n${a.out}\n---\n${b.out}`);
  assert.equal(fresh(dist).status, 0);
});
