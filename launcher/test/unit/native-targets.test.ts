/**
 * native-targets — the shipped native tags and the pure rules build-bundle.mjs
 * follows to copy each tag's bins (launcher/scripts/native-targets.mjs,
 * packaging.md §11.3). The multi-tag pack itself is test/component/native-multiarch-bundle.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  elfMachine,
  NATIVE_TARGETS,
  nativeBinMismatch,
  nativeSources,
  parseNativeBinDirs,
  stripCandidates,
} from "../../scripts/native-targets.mjs";
import { nativePlatformTag } from "../../src/services/native-bins.js";

/** The first 64 bytes of an ELF64 file for `machine`, little- or big-endian. */
function elfHeader(machine: number, bigEndian = false): Uint8Array {
  const b = new Uint8Array(64);
  b.set([0x7f, 0x45, 0x4c, 0x46, 2, bigEndian ? 2 : 1, 1]);
  if (bigEndian) { b[18] = machine >> 8; b[19] = machine & 0xff; } else { b[18] = machine & 0xff; b[19] = machine >> 8; }
  return b;
}

test("the release ships linux-x64 and linux-arm64; each tag is the launcher's own nativePlatformTag for that CPU", () => {
  assert.deepEqual(Object.keys(NATIVE_TARGETS).sort(), ["linux-arm64", "linux-x64"]);
  // the keys must be what the running launcher looks up (process.platform-process.arch)
  assert.equal(nativePlatformTag("linux", "x64"), "linux-x64");
  assert.equal(nativePlatformTag("linux", "arm64"), "linux-arm64");
  assert.equal(NATIVE_TARGETS["linux-x64"].triple, "x86_64-unknown-linux-gnu");
  assert.equal(NATIVE_TARGETS["linux-arm64"].triple, "aarch64-unknown-linux-gnu");
  // EM_X86_64 = 62, EM_AARCH64 = 183 (elf.h)
  assert.equal(NATIVE_TARGETS["linux-x64"].elfMachine, 62);
  assert.equal(NATIVE_TARGETS["linux-arm64"].elfMachine, 183);
});

test("parseNativeBinDirs: <tag>=<dir> pairs; an unknown tag, a repeat or a malformed entry throws", () => {
  assert.deepEqual(parseNativeBinDirs("linux-x64=/a/release, linux-arm64=/b/aarch64/release,"), {
    "linux-x64": "/a/release",
    "linux-arm64": "/b/aarch64/release",
  });
  assert.throws(() => parseNativeBinDirs("linux-riscv64=/c"), /unknown tag "linux-riscv64"/);
  assert.throws(() => parseNativeBinDirs("linux-x64=/a,linux-x64=/b"), /given twice/);
  assert.throws(() => parseNativeBinDirs("/just/a/dir"), /not <tag>=<dir>/);
  assert.throws(() => parseNativeBinDirs("linux-x64="), /not <tag>=<dir>/);
});

test("nativeSources: MANDU_NATIVE_BIN_DIRS wins; else the host tag from MANDU_NATIVE_BIN_DIR; else target/release", () => {
  const repoRoot = "/repo";
  assert.deepEqual(
    nativeSources({ env: { MANDU_NATIVE_BIN_DIRS: "linux-x64=/x,linux-arm64=/y", MANDU_NATIVE_BIN_DIR: "/ignored" }, repoRoot, hostTag: "linux-x64" }),
    [{ tag: "linux-x64", dir: "/x" }, { tag: "linux-arm64", dir: "/y" }],
  );
  assert.deepEqual(nativeSources({ env: { MANDU_NATIVE_BIN_DIR: "/one" }, repoRoot, hostTag: "linux-arm64" }), [{ tag: "linux-arm64", dir: "/one" }]);
  assert.deepEqual(nativeSources({ env: {}, repoRoot, hostTag: "linux-x64" }), [{ tag: "linux-x64", dir: "/repo/interceptors/target/release" }]);
  // a blank multi-dir value is "unset", not "ship nothing"
  assert.deepEqual(nativeSources({ env: { MANDU_NATIVE_BIN_DIRS: "  " }, repoRoot, hostTag: "linux-x64" }), [{ tag: "linux-x64", dir: "/repo/interceptors/target/release" }]);
});

test("elfMachine / nativeBinMismatch: a bin built for another CPU cannot ship under a tag", () => {
  assert.equal(elfMachine(elfHeader(62)), 62);
  assert.equal(elfMachine(elfHeader(183)), 183);
  assert.equal(elfMachine(elfHeader(183, true)), 183);
  assert.equal(elfMachine(new TextEncoder().encode("#!/bin/sh\necho not elf, padded to twenty\n")), null);
  assert.equal(elfMachine(new Uint8Array(4)), null);
  assert.equal(nativeBinMismatch("linux-x64", elfHeader(62)), null);
  assert.equal(nativeBinMismatch("linux-arm64", elfHeader(183)), null);
  assert.match(nativeBinMismatch("linux-arm64", elfHeader(62)) ?? "", /ELF machine 62, but linux-arm64 needs 183/);
  assert.match(nativeBinMismatch("linux-x64", elfHeader(183)) ?? "", /ELF machine 183, but linux-x64 needs 62/);
  assert.match(nativeBinMismatch("linux-x64", new TextEncoder().encode("#!/bin/sh\n" + " ".repeat(40))) ?? "", /not an ELF/);
  // a tag outside the table (a developer packing on another host) is not judged
  assert.equal(nativeBinMismatch("darwin-arm64", new Uint8Array(0)), null);
});

test("stripCandidates: the host's plain strip only for the host tag; a cross tag gets its own tool, then llvm-strip", () => {
  assert.deepEqual(stripCandidates("linux-x64", "linux-x64"), ["x86_64-linux-gnu-strip", "llvm-strip", "strip"]);
  assert.deepEqual(stripCandidates("linux-arm64", "linux-x64"), ["aarch64-linux-gnu-strip", "llvm-strip"]);
  assert.deepEqual(stripCandidates("linux-arm64", "linux-arm64"), ["aarch64-linux-gnu-strip", "llvm-strip", "strip"]);
});
