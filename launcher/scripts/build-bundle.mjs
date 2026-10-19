#!/usr/bin/env node
/**
 * build-bundle.mjs — esbuild each shipped service entry into a single-file
 * dist/<name>.mjs (packaging.md §5). After the node:sqlite migration (§4) every
 * entry is pure-JS, so each bundle inlines its deps (js-yaml is the only runtime
 * dep; node:* builtins — including node:sqlite — stay external on platform node)
 * and needs no per-package node_modules, no tsx, and no `npm run serve` at
 * runtime. The launcher's layout resolver spawns `node dist/<name>.mjs`.
 *
 * The service list is bundle-manifest.json — the SAME map the resolver reads, so
 * the built set and the spawned set cannot drift.
 *
 * Usage: node scripts/build-bundle.mjs [--minify] [--sourcemap] [--outdir=DIR]
 *                                      [--no-native] [--if-stale] [--quiet]
 *
 * --outdir lets a test build into a private dir so parallel test files don't race
 * on the shared launcher/dist (the packed dir); defaults to launcher/dist.
 *
 * A source checkout runs its launcher and services from this build while it is
 * fresh (packaging.md §5.1), so the build is safe to run under live sessions:
 *   - every bundle is written to a temp name and renamed over the old one, so a
 *     running session's next exec-wrap shim call never finds a half-written or
 *     missing file (no whole-dir wipe: entries the manifest no longer names are
 *     pruned at the end instead);
 *   - builds are serialized by `<outdir>/.build.lock`;
 *   - a build starts by removing the build record (bundle-stamp.mjs) and writes
 *     it only when it ends clean, so an interrupted or failed build is never
 *     taken as fresh.
 * --if-stale builds only when that record says the bundle no longer matches its
 * source (checked after taking the lock, so two launches that both found it
 * stale build it once). --no-native skips copying the native bins (a checkout's
 * launcher resolves them from interceptors/target, never from its own dist/:
 * services/native-bins.ts). --quiet prints only failures.
 */
import { build } from "esbuild";
import {
  chmodSync, closeSync, copyFileSync, cpSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync,
  renameSync, rmSync, statSync, unlinkSync, writeFileSync,
} from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { nativeBinMismatch, nativeSources, stripCandidates } from "./native-targets.mjs";
import { STAMP_NAME, checkStamp, clearStamp, fsClockMs, stampInputs, writeStamp } from "./bundle-stamp.mjs";
import { BUILD_INFO_NAME, resolveBuildInfo, writeBuildInfo } from "./build-info.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(here, ".."); // launcher/
const repoRoot = resolve(pkgRoot, ".."); // repo root
const outdirArg = process.argv.find((a) => a.startsWith("--outdir="));
const distDir = outdirArg ? resolve(outdirArg.slice("--outdir=".length)) : join(pkgRoot, "dist");

const manifest = JSON.parse(readFileSync(join(pkgRoot, "bundle-manifest.json"), "utf8"));
// Bundle spawnable services AND imported modules (the arbiter IPC client) — both
// land in dist/<name>.mjs; only `services` are later spawned by the resolver.
// An optional module is built only when its source exists (the dashboard's
// developer view, which the public tree does not carry; dashboard.md §4.25ac).
const optional = Object.entries(manifest.optionalModules ?? {});
const entries = {
  ...manifest.services, ...manifest.modules,
  ...Object.fromEntries(optional.filter(([, src]) => existsSync(join(repoRoot, src)))),
};
const skippedOptional = optional.filter(([, src]) => !existsSync(join(repoRoot, src))).map(([name]) => name);

const minify = process.argv.includes("--minify");
const sourcemap = process.argv.includes("--sourcemap");
const withNative = !process.argv.includes("--no-native");
const ifStale = process.argv.includes("--if-stale");
const quiet = process.argv.includes("--quiet");
const log = (line) => { if (!quiet) console.log(line); };

const LOCK_NAME = ".build.lock";

/** Take `<dist>/.build.lock` (created exclusively, holding our pid), waiting
 *  while a live build holds it and breaking a dead one's. Released on exit. */
function acquireLock(path, timeoutMs = 180_000) {
  const deadline = Date.now() + timeoutMs;
  const nap = new Int32Array(new SharedArrayBuffer(4));
  for (;;) {
    try {
      const fd = openSync(path, "wx");
      writeFileSync(fd, String(process.pid));
      closeSync(fd);
      process.on("exit", () => { try { unlinkSync(path); } catch { /* gone */ } });
      return;
    } catch (err) {
      if (err?.code !== "EEXIST") throw err;
    }
    let pid = NaN;
    let ageMs = 0;
    try {
      pid = Number(readFileSync(path, "utf8").trim());
      ageMs = Date.now() - statSync(path).mtimeMs;
    } catch {
      continue; // released between our open and this read
    }
    const alive = Number.isInteger(pid) && pid > 0
      ? (() => { try { process.kill(pid, 0); return true; } catch (e) { return e?.code === "EPERM"; } })()
      : ageMs < 5_000; // just created, its pid not written yet
    if (!alive) {
      try { unlinkSync(path); } catch { /* another waiter broke it first */ }
      continue;
    }
    if (Date.now() > deadline) {
      console.error(`build-bundle: ${path} is still held by pid ${pid} after ${timeoutMs / 1000} s`);
      process.exit(1);
    }
    Atomics.wait(nap, 0, 0, 100);
  }
}

/** Write `contents` to `path` through a rename: a reader sees the old file or
 *  the new one, never a partial one. */
function writeAtomic(path, contents) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, contents);
  renameSync(tmp, path);
}

mkdirSync(distDir, { recursive: true });
acquireLock(join(distDir, LOCK_NAME));

if (ifStale) {
  const r = checkStamp(distDir, { repoRoot });
  if (r.fresh) {
    log(`bundles in ${distDir} are up to date (${r.inputs} inputs unchanged)`);
    process.exit(0);
  }
  log(`rebuilding: ${r.reason}`);
}

// No record while the build runs: an interrupted build is never taken as fresh.
clearStamp(distDir);
const startMs = fsClockMs(distDir);

const names = Object.keys(entries);
log(`building ${names.length} bundles → ${distDir}${minify ? " (minified)" : ""}`);
for (const name of skippedOptional) log(`  · ${name.padEnd(16)} (optional) no source here — skipped`);

const metaInputs = new Set();
const outputs = [];
let failed = 0;
for (const name of names) {
  const entry = join(repoRoot, entries[name]);
  const outfile = join(distDir, `${name}.mjs`);
  try {
    const result = await build({
      entryPoints: [entry],
      outfile,
      bundle: true,
      platform: "node",
      format: "esm",
      target: "node22",
      minify,
      sourcemap,
      // No shebang banner: bundles are always spawned as `node dist/<name>.mjs`
      // by the layout resolver, and a shebang after esbuild's ESM preamble lands
      // on line 2 → SyntaxError.
      // node:* builtins (incl. node:sqlite) auto-externalize on platform:node;
      // everything else (js-yaml, cross-package source) is inlined.
      logLevel: "warning",
      metafile: true,
      // Metafile input paths relative to the repo root (the build record's keys).
      absWorkingDir: repoRoot,
      // Written below through a rename, never in place: a live session may be
      // reading the old file.
      write: false,
    });
    for (const f of result.outputFiles) {
      writeAtomic(f.path, f.contents);
      outputs.push(relative(distDir, f.path));
    }
    for (const input of Object.keys(result.metafile.inputs)) metaInputs.add(input);
    const bytes = Object.values(result.metafile.outputs).find((o) => o.entryPoint)?.bytes
      ?? result.metafile.outputs[Object.keys(result.metafile.outputs).find((k) => k.endsWith(`${name}.mjs`))]?.bytes
      ?? 0;
    log(`  ✓ ${name.padEnd(16)} ${(bytes / 1024).toFixed(0)}kb`);
  } catch (err) {
    failed++;
    console.error(`  ✗ ${name.padEnd(16)} ${err instanceof Error ? err.message : String(err)}`);
  }
}

// Static directories, copied whole: the dashboard's front-ends (dashboard.md
// §4.25). The bundled server (dist/dashboard.mjs) looks for `dashboard/public`
// beside itself, and the developer view's module (dist/dashboard-dev.mjs) for
// `dashboard/dev`, which is optional (§4.25ac): copied when its source exists,
// else removed, so a product-only build keeps no old copy. Replaced whole, so
// a file removed from the source does not linger.
const optionalDirs = Object.entries(manifest.optionalAssetDirs ?? {});
for (const [rel, src] of optionalDirs) {
  if (existsSync(join(repoRoot, src))) continue;
  rmSync(join(distDir, rel), { recursive: true, force: true });
  log(`  · ${rel.padEnd(16)} (optional asset dir) no source here — skipped`);
}
const assetDirs = [...Object.entries(manifest.assetDirs ?? {}), ...optionalDirs.filter(([, src]) => existsSync(join(repoRoot, src)))];
for (const [rel, src] of assetDirs) {
  try {
    const dst = join(distDir, rel);
    rmSync(dst, { recursive: true, force: true });
    cpSync(join(repoRoot, src), dst, { recursive: true });
    if (!existsSync(join(dst, "index.html"))) throw new Error(`no index.html in ${src}`);
    log(`  ✓ ${rel.padEnd(16)} (asset dir)`);
  } catch (err) {
    failed++;
    console.error(`  ✗ ${rel.padEnd(16)} ${err instanceof Error ? err.message : String(err)}`);
  }
}

// Static assets, copied byte for byte (the AppArmor profiles `mandu setup`
// installs: an npm-installed user has no scripts/ directory to run).
for (const [rel, src] of Object.entries(manifest.assets ?? {})) {
  try {
    writeAtomic(join(distDir, rel), readFileSync(join(repoRoot, src)));
    log(`  ✓ ${rel.padEnd(16)} (asset)`);
  } catch (err) {
    failed++;
    console.error(`  ✗ ${rel.padEnd(16)} ${err instanceof Error ? err.message : String(err)}`);
  }
}

// Prebuilt native supervisor bins (manifest `native`): copied to
// dist/native/<platform>-<arch>/<name> when built, so an npm user gets the
// whole-agent guard (and with it a `confined` posture on a no-userns host,
// plan 10 §11.7) without a Rust toolchain. One tarball carries every tag the
// release builds (native-targets.mjs: linux-x64 and linux-arm64); the launcher
// picks its own at run time. Sources: $MANDU_NATIVE_BIN_DIRS
// (`linux-x64=<dir>,linux-arm64=<dir>`, the release job), else the host's tag
// from $MANDU_NATIVE_BIN_DIR (the fresh-install packer points it at the
// checkout's release tree when it packs a clean `git archive`), else
// interceptors/target/release. A bin that is not built is a NOTE, never a
// failure: the package still works, gated. A bin built for the WRONG CPU is a
// failure: it would sit under the right tag and fail every exec.
if (withNative) {
  rmSync(join(distDir, "native"), { recursive: true, force: true });
  const hostTag = `${process.platform}-${process.arch}`;
  let nativeSourceList = [];
  try {
    nativeSourceList = nativeSources({ env: process.env, repoRoot, hostTag });
  } catch (err) {
    failed++;
    console.error(`  ✗ native           ${err instanceof Error ? err.message : String(err)}`);
  }
  for (const { tag, dir } of nativeSourceList) {
    for (const name of manifest.native ?? []) {
      const src = join(dir, name);
      if (!existsSync(src)) {
        log(`  · ${name.padEnd(16)} (native, ${tag}) not built at ${src} — skipped; the package runs without it`);
        continue;
      }
      const why = nativeBinMismatch(tag, readFileSync(src).subarray(0, 64));
      if (why) {
        failed++;
        console.error(`  ✗ ${name.padEnd(16)} (native, ${tag}) ${src}: ${why}`);
        continue;
      }
      const dst = join(distDir, "native", tag, name);
      mkdirSync(dirname(dst), { recursive: true });
      copyFileSync(src, dst);
      chmodSync(dst, 0o755);
      // Strip the copy (never the checkout's artifact, whose `.d` dep-info and
      // symbols the stale-bin check and gdb still want): a release Rust bin is
      // ~14 MB with symbols and ~2 MB without. Best-effort: the first strip
      // tool that knows the bin's architecture wins; none ships it unstripped.
      for (const tool of stripCandidates(tag, hostTag)) {
        try { execFileSync(tool, [dst], { stdio: "ignore" }); break; } catch { /* next tool */ }
      }
      log(`  ✓ ${name.padEnd(16)} (native, ${tag}, ${(statSync(dst).size / 1024 / 1024).toFixed(1)} MB)`);
    }
  }
}

// Which commit this build is (build-info.mjs, packaging.md §11.7): an
// installed package has no git to ask, so `mandu version` reads it here.
try {
  const info = resolveBuildInfo({ repoRoot });
  writeBuildInfo(distDir, info);
  const short = (c) => (c ? c.slice(0, 12) : "not recorded");
  log(`  ✓ ${BUILD_INFO_NAME.padEnd(16)} source ${short(info.sourceCommit)}, public ${short(info.publicCommit)}${info.dirty ? " (uncommitted changes)" : ""}`);
} catch (err) {
  failed++;
  console.error(`  ✗ ${BUILD_INFO_NAME.padEnd(16)} ${err instanceof Error ? err.message : String(err)}`);
}

// Prune what this build did not produce (an entry the manifest dropped, an
// old temp file). The lock, and the native bins a --no-native build left
// alone, stay.
const keep = new Set([
  ...outputs.map((o) => o.split("/")[0]),
  ...assetDirs.map(([r]) => r.split("/")[0]),
  ...Object.keys(manifest.assets ?? {}).map((r) => r.split("/")[0]),
  "native", LOCK_NAME, BUILD_INFO_NAME,
]);
for (const ent of readdirSync(distDir)) {
  if (keep.has(ent)) continue;
  if (failed > 0 && ent.endsWith(".mjs")) continue; // a failed entry keeps its last build
  rmSync(join(distDir, ent), { recursive: true, force: true });
}

if (failed > 0) {
  console.error(`\n${failed} bundle(s) failed`);
  process.exit(1);
}

// The build record (packaging.md §5.1): written last, and only when no input
// changed while the build ran.
const notStamped = writeStamp(distDir, {
  repoRoot,
  inputs: stampInputs(repoRoot, [...metaInputs]),
  outputs: outputs.filter((o) => o.endsWith(".mjs")),
  startMs,
});
if (notStamped) {
  console.error(`build-bundle: built, but not recorded as fresh: ${notStamped}; the next launch rebuilds`);
  process.exit(ifStale ? 1 : 0);
}
log(`done (${STAMP_NAME} records ${metaInputs.size} inputs)`);
