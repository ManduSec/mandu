/**
 * native-provenance.test — may a git worktree use its main checkout's native
 * bin? (packaging.md §5.2; src/services/native-provenance.ts, the writer
 * scripts/native-provenance.mjs run as scripts/build-native.sh runs it.)
 *
 * Over a REAL main checkout and `git worktree add`, with stand-in bins and
 * cargo dep-info: the record the writer leaves is honoured only while the
 * bin and every source it names hash the same in the worktree; one changed
 * source, a changed bin, a file present on one side only, no record, or a
 * record that names a path outside the interceptors dir refuses it, with the
 * reason in the build hint. The writer itself refuses to record a bin whose
 * source changed after it was built, or a source outside the dir.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildHintFor, nativeBinBuildHint, NATIVE_BIN_BUILD_HINT, resolveNativeBin, staleNativeBinNote } from "../../src/services/native-bins.js";
import {
  mainCheckoutOf, PROVENANCE_SUFFIX, resetSharedBins, sharedBinRefusal, sharedCheckoutBin, verifiedSharedBin, verifyNativeProvenance,
} from "../../src/services/native-provenance.js";

const WRITER = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "scripts", "native-provenance.mjs");
const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...a: string[]): string => execFileSync("git", a, { cwd, encoding: "utf8", env: GIT_ENV });
const BIN = "mandu-net-guard";
const SOURCES = ["net-supervisor/src/lib.rs", "net-supervisor/src/bin/mandu-net-guard.rs", "mandu-paths/src/lib.rs"];

interface Rig { dir: string; main: string; wt: string; bin: string; record: () => string; done: () => void }

/** A main checkout whose interceptors/ holds the sources, a stand-in bin
 *  built "after" them with cargo's dep-info, and a worktree of it. */
function rig(): Rig {
  const dir = mkdtempSync(join(tmpdir(), "mandu-native-prov-"));
  const main = join(dir, "main");
  mkdirSync(main);
  git(main, "init", "-q");
  const ic = join(main, "interceptors");
  for (const rel of SOURCES) {
    mkdirSync(dirname(join(ic, rel)), { recursive: true });
    writeFileSync(join(ic, rel), `// ${rel}\nfn main() {}\n`);
  }
  writeFileSync(join(ic, "Cargo.toml"), "[workspace]\nmembers = [\"net-supervisor\", \"mandu-paths\"]\n");
  writeFileSync(join(ic, "Cargo.lock"), "version = 3\n");
  writeFileSync(join(ic, "net-supervisor", "Cargo.toml"), "[package]\nname = \"net-supervisor\"\n");
  writeFileSync(join(ic, "mandu-paths", "Cargo.toml"), "[package]\nname = \"mandu-paths\"\n");
  writeFileSync(join(main, ".gitignore"), "target/\n");
  git(main, "add", ".");
  git(main, "commit", "-qm", "sources");
  const out = join(ic, "target", "release");
  mkdirSync(out, { recursive: true });
  const bin = join(out, BIN);
  writeFileSync(bin, Buffer.concat([Buffer.from("\x7fELF stand-in "), Buffer.alloc(4096, 7)]), { mode: 0o755 });
  writeFileSync(`${bin}.d`, `${bin}: ${SOURCES.map((s) => join(ic, s)).join(" ")}\n`);
  // Built after its sources (cargo's own rule).
  const later = new Date(Date.now() + 5000);
  utimesSync(bin, later, later);
  const wt = join(dir, "wt");
  git(main, "worktree", "add", "-q", "--detach", wt);
  return {
    dir, main, wt, bin,
    record: () => execFileSync(process.execPath, [WRITER, "record", ic, out, BIN], { encoding: "utf8" }),
    done: () => { resetSharedBins(); rmSync(dir, { recursive: true, force: true }); },
  };
}

test("mainCheckoutOf: a linked worktree names its main checkout; the main checkout itself, and a directory outside git, name none", () => {
  const r = rig();
  try {
    assert.equal(mainCheckoutOf(r.wt), r.main);
    assert.equal(mainCheckoutOf(r.main), null, "a main checkout is not a worktree");
    assert.equal(mainCheckoutOf(r.dir), null, "no .git at all");
    writeFileSync(join(r.dir, ".git"), "not a gitdir line\n");
    assert.equal(mainCheckoutOf(r.dir), null, "a .git file not of git's shape");
  } finally { r.done(); }
});

test("the writer records the bin's hash and every source it was built from, plus the manifests and the lock (absent files as null)", () => {
  const r = rig();
  try {
    assert.match(r.record(), /mandu-net-guard: provenance recorded \(\d+ sources\)/);
    const rec = JSON.parse(readFileSync(`${r.bin}${PROVENANCE_SUFFIX}`, "utf8"));
    assert.equal(rec.format, "mandu-native-provenance/1");
    assert.equal(rec.bin, BIN);
    assert.equal(rec.profile, "release");
    assert.deepEqual(rec.features, ["kernel"]);
    assert.equal(rec.size, readFileSync(r.bin).length);
    for (const s of [...SOURCES, "Cargo.toml", "Cargo.lock", "net-supervisor/Cargo.toml", "mandu-paths/Cargo.toml"]) {
      assert.match(rec.sources[s], /^[0-9a-f]{64}$/, s);
    }
    assert.equal(rec.sources["net-supervisor/build.rs"], null, "an absent build input is recorded as absent");
    assert.equal(rec.sources["rust-toolchain.toml"], null);
  } finally { r.done(); }
});

test("the writer records nothing (and removes an older record) when a source changed after the bin was built, or lies outside the interceptors dir", () => {
  const r = rig();
  try {
    r.record();
    assert.ok(existsSync(`${r.bin}${PROVENANCE_SUFFIX}`));
    const src = join(r.main, "interceptors", SOURCES[0]!);
    const later = new Date(Date.now() + 60_000);
    utimesSync(src, later, later);
    assert.match(r.record(), /no provenance record \(.*changed after the bin was built\)/);
    assert.ok(!existsSync(`${r.bin}${PROVENANCE_SUFFIX}`), "the older record is gone");
    utimesSync(src, new Date(), new Date(Date.now() - 60_000));
    writeFileSync(`${r.bin}.d`, `${r.bin}: ${join(r.dir, "elsewhere.rs")}\n`);
    assert.match(r.record(), /lies outside/);
    assert.ok(!existsSync(`${r.bin}${PROVENANCE_SUFFIX}`));
  } finally { r.done(); }
});

test("a worktree with no bins of its own resolves the main checkout's bin when its sources are byte-identical; its own bin, an installed package or an override still win", () => {
  const r = rig();
  try {
    r.record();
    const env = { PATH: "" };
    assert.deepEqual(verifyNativeProvenance(r.bin, BIN, join(r.wt, "interceptors")), { ok: true });
    assert.equal(resolveNativeBin(BIN, { repoRoot: r.wt, env, installedDir: null }), r.bin);
    assert.equal(verifiedSharedBin(r.bin), true);
    assert.equal(sharedBinRefusal(BIN), null);
    // The main checkout's own sources moved on after the build: the bin is
    // still exactly what the worktree's sources build, so it is not stale here.
    const later = new Date(Date.now() + 60_000);
    utimesSync(join(r.main, "interceptors", SOURCES[0]!), later, later);
    assert.equal(staleNativeBinNote(BIN, r.bin), null);
    // Precedence.
    const own = join(r.wt, "interceptors", "target", "debug");
    mkdirSync(own, { recursive: true });
    writeFileSync(join(own, BIN), "own");
    assert.equal(resolveNativeBin(BIN, { repoRoot: r.wt, env, installedDir: null }), join(own, BIN), "the worktree's own bin first");
    rmSync(join(own, BIN));
    const inst = join(r.dir, "dist-native");
    mkdirSync(inst);
    assert.equal(resolveNativeBin(BIN, { repoRoot: r.wt, env, installedDir: inst }), null, "an installed package never reaches another checkout");
    assert.equal(resolveNativeBin(BIN, { repoRoot: r.wt, env: { PATH: "", MANDU_NET_GUARD_BIN: "/opt/g" }, installedDir: null, exists: (p) => p === "/opt/g" }), "/opt/g");
    assert.equal(resolveNativeBin(BIN, { repoRoot: r.main, env, installedDir: null }), r.bin, "the main checkout resolves its own, as before");
  } finally { r.done(); }
});

test("refused, with the reason in the build hint: one source byte different, a changed bin, a file on one side only, no record, a record naming a path outside", () => {
  const cases: Array<[string, (r: Rig) => void, RegExp]> = [
    ["a source differs", (r) => appendFileSync(join(r.wt, "interceptors", SOURCES[1]!), " "), /interceptors\/net-supervisor\/src\/bin\/mandu-net-guard\.rs differs from the source it was built from/],
    ["the lock differs", (r) => writeFileSync(join(r.wt, "interceptors", "Cargo.lock"), "version = 4\n"), /interceptors\/Cargo\.lock differs/],
    ["a source is missing here", (r) => rmSync(join(r.wt, "interceptors", SOURCES[2]!)), /interceptors\/mandu-paths\/src\/lib\.rs is missing here/],
    ["a build input exists only here", (r) => writeFileSync(join(r.wt, "interceptors", "net-supervisor", "build.rs"), "fn main() {}\n"), /net-supervisor\/build\.rs exists here but not where it was built/],
    ["the bin changed after its record", (r) => appendFileSync(r.bin, "x"), /changed after its provenance was recorded/],
    ["no record", (r) => rmSync(`${r.bin}${PROVENANCE_SUFFIX}`), /has no provenance record/],
    ["a record naming ../", (r) => {
      const p = `${r.bin}${PROVENANCE_SUFFIX}`;
      const rec = JSON.parse(readFileSync(p, "utf8"));
      rec.sources["../../etc/passwd"] = "0".repeat(64);
      writeFileSync(p, JSON.stringify(rec));
    }, /names a source it may not/],
    ["another bin's record", (r) => {
      const p = `${r.bin}${PROVENANCE_SUFFIX}`;
      writeFileSync(p, readFileSync(p, "utf8").replace(`"bin": "${BIN}"`, '"bin": "mandu-exec-box"'));
    }, /not of the expected shape/],
  ];
  for (const [what, spoil, why] of cases) {
    const r = rig();
    try {
      r.record();
      spoil(r);
      assert.equal(resolveNativeBin(BIN, { repoRoot: r.wt, env: { PATH: "" }, installedDir: null }), null, what);
      assert.equal(sharedCheckoutBin(BIN, r.wt), null, what);
      assert.match(sharedBinRefusal(BIN) ?? "", why, what);
      // The hints' Linux form: off Linux (macOS) there are no native bins and
      // the hint says so instead, whatever the provenance record says.
      const hint = buildHintFor(BIN, false, undefined, "linux");
      assert.match(hint, /^build with: cd interceptors && cargo build -p net-supervisor --features kernel --bins\. The main checkout's bins were not used \(/, what);
      assert.match(hint, /run scripts\/build-native\.sh in this worktree to launch confined$/, what);
      assert.match(nativeBinBuildHint(false, undefined, "linux"), why, `${what}: the crate-less hint names it too`);
      assert.equal(verifiedSharedBin(r.bin), false, what);
    } finally { r.done(); }
  }
  // With nothing refused, the hints are as before.
  assert.equal(nativeBinBuildHint(false, undefined, "linux"), NATIVE_BIN_BUILD_HINT);
  assert.equal(buildHintFor(BIN, false, undefined, "linux"), "build with: cd interceptors && cargo build -p net-supervisor --features kernel --bins");
});
