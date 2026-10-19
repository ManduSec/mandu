/**
 * native-multiarch-bundle — the real build-bundle.mjs packs every shipped
 * tag's native bins side by side (packaging.md §11.3): with MANDU_NATIVE_BIN_DIRS
 * naming a linux-x64 and a linux-arm64 tree, dist/native/<tag>/ holds each
 * tag's own bins, and a tree holding the WRONG CPU's bins fails the pack
 * rather than shipping a bin that would fail every exec. The fixtures are ELF
 * headers only (the strip step fails on them and ships them as they are); the
 * real cross-built bins are packed by scripts/ci/release-pack.sh.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PKG = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const BINS = JSON.parse(readFileSync(join(PKG, "bundle-manifest.json"), "utf8")).native as string[];

function fakeBins(dir: string, machine: number): void {
  mkdirSync(dir, { recursive: true });
  for (const name of BINS) {
    const b = Buffer.alloc(64);
    b.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
    b.writeUInt16LE(machine, 18);
    writeFileSync(join(dir, name), b, { mode: 0o755 });
  }
}

function pack(env: Record<string, string>, outdir: string) {
  const baseEnv = { ...process.env };
  delete baseEnv.MANDU_NATIVE_BIN_DIR;
  delete baseEnv.MANDU_NATIVE_BIN_DIRS;
  return spawnSync("node", [join(PKG, "scripts", "build-bundle.mjs"), `--outdir=${outdir}`], {
    cwd: PKG, encoding: "utf8", timeout: 120_000, env: { ...baseEnv, ...env },
  });
}

test("one bundle carries linux-x64 and linux-arm64 bins, each under its own tag", () => {
  const root = mkdtempSync(join(tmpdir(), "mandu-multiarch-"));
  try {
    fakeBins(join(root, "x64"), 62);
    fakeBins(join(root, "arm64"), 183);
    const dist = join(root, "dist");
    const r = pack({ MANDU_NATIVE_BIN_DIRS: `linux-x64=${join(root, "x64")},linux-arm64=${join(root, "arm64")}` }, dist);
    assert.equal(r.status, 0, `build-bundle failed:\n${r.stdout}\n${r.stderr}`);
    for (const [tag, machine] of [["linux-x64", 62], ["linux-arm64", 183]] as const) {
      for (const name of BINS) {
        const p = join(dist, "native", tag, name);
        assert.ok(existsSync(p), `${tag}/${name} packed`);
        assert.equal(readFileSync(p).readUInt16LE(18), machine, `${tag}/${name} is the ${tag} build`);
      }
      assert.match(r.stdout, new RegExp(`\\(native, ${tag},`));
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a tree of x64 bins named as linux-arm64 fails the pack; nothing ships under that tag", () => {
  const root = mkdtempSync(join(tmpdir(), "mandu-multiarch-"));
  try {
    fakeBins(join(root, "x64"), 62);
    const dist = join(root, "dist");
    const r = pack({ MANDU_NATIVE_BIN_DIRS: `linux-arm64=${join(root, "x64")}` }, dist);
    assert.notEqual(r.status, 0, "a wrong-CPU bin must fail the pack");
    assert.match(r.stderr, /ELF machine 62, but linux-arm64 needs 183/);
    for (const name of BINS) assert.ok(!existsSync(join(dist, "native", "linux-arm64", name)), `${name} not shipped`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("an unknown tag in MANDU_NATIVE_BIN_DIRS fails the pack instead of shipping one architecture", () => {
  const root = mkdtempSync(join(tmpdir(), "mandu-multiarch-"));
  try {
    const r = pack({ MANDU_NATIVE_BIN_DIRS: `linux-riscv64=${root}` }, join(root, "dist"));
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /unknown tag "linux-riscv64"/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
