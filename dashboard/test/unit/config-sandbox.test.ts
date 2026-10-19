/**
 * config-sandbox.test — the Settings → Sandbox switches over the launcher's
 * config.toml (src/config-axes.ts SANDBOX_*; policy-surface.md §4,
 * stage 6): the catalog mirrors launcher/src/parse.ts defaults, the reader
 * resolves configured ?? default (fs-sync's unset = auto), and the surgical
 * editor touches only the managed lines.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, rmSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";

import {
  SANDBOX_KEYS,
  SANDBOX_META,
  SANDBOX_PROVENANCE_COMMENT,
  PROVENANCE_COMMENT,
  applySandboxEdit,
  readSandboxState,
  writeSandbox,
} from "../../src/config-axes.js";
import { tmpDir } from "./tmp-dir.js";

test("catalog: every launcher bool wrap key has env + default mirroring parse.ts (tri-state rungs ON; strict + no-kernel opt-in; fs-sync auto)", () => {
  assert.equal(SANDBOX_KEYS.length, 12);
  for (const k of SANDBOX_KEYS) assert.match(SANDBOX_META[k].env, /^MANDU_[A-Z_]+$/);
  assert.equal(SANDBOX_META["exec-box"].default, true);
  assert.equal(SANDBOX_META["exec-clean-box"].default, true);
  assert.equal(SANDBOX_META["landlock-net"].default, true);
  assert.equal(SANDBOX_META["landlock-net-strict"].default, false);
  assert.equal(SANDBOX_META["net-guard"].default, true);
  assert.equal(SANDBOX_META["reply-filter"].default, true);
  assert.equal(SANDBOX_META["fs-sync"].default, "auto");
  assert.equal(SANDBOX_META["no-kernel"].default, false);
  assert.ok(SANDBOX_META["exec-box"].kernel && SANDBOX_META["net-guard"].kernel && !SANDBOX_META["reply-filter"].kernel);
});

test("readSandboxState: missing file → exists:false, nothing configured, effective = the defaults", () => {
  const s = readSandboxState({ MANDU_HOME: "/nonexistent/mandu" }, () => null);
  assert.equal(s.exists, false);
  assert.equal(s.keys.length, 12);
  for (const k of s.keys) {
    assert.equal(k.configured, null);
    assert.equal(k.effective, k.default);
  }
  assert.equal(s.keys.find((k) => k.key === "fs-sync")!.effective, "auto");
});

test("readSandboxState: configured values win; a string \"true\" coerces; longer keys never match", () => {
  const text = [
    "exec-box = false",
    'net-guard = "true"',
    "fs-sync = true",
    "exec-box-cmds = \"cat,ls\"",
    "# reply-filter = false",
  ].join("\n");
  const s = readSandboxState({ MANDU_HOME: "/x" }, () => text);
  const by = Object.fromEntries(s.keys.map((k) => [k.key, k]));
  assert.equal(by["exec-box"].configured, false);
  assert.equal(by["exec-box"].effective, false);
  assert.equal(by["net-guard"].configured, true);
  assert.equal(by["fs-sync"].effective, true, "an explicit fs-sync replaces auto");
  assert.equal(by["reply-filter"].configured, null, "a commented line does not configure");
});

test("applySandboxEdit: replaces in place (indent + inline comment kept), appends absent keys under ITS OWN provenance comment once, leaves the axes alone", () => {
  const before = [
    "integrity = true",
    "  exec-box = true  # boxed",
    "exec-box-cmds = \"cat\"",
    "# net-guard = false",
  ].join("\n") + "\n";
  const once = applySandboxEdit(before, { "exec-box": false, "net-guard": false });
  assert.ok(once.includes("  exec-box = false  # boxed"), "in place, indent + comment kept");
  assert.ok(once.includes('exec-box-cmds = "cat"'), "the longer key untouched");
  assert.ok(once.includes("# net-guard = false"), "the commented line untouched");
  assert.ok(once.includes("integrity = true"), "an axis line untouched");
  assert.ok(once.includes(SANDBOX_PROVENANCE_COMMENT + "\nnet-guard = false\n"));
  assert.ok(!once.includes(PROVENANCE_COMMENT), "the axes' comment is not the sandbox's");
  const twice = applySandboxEdit(once, { "reply-filter": false });
  assert.equal(twice.split(SANDBOX_PROVENANCE_COMMENT).length - 1, 1, "provenance comment added once");
  assert.ok(twice.endsWith("net-guard = false\nreply-filter = false\n"));
});

test("writeSandbox: creates dir + file, round-trips unrelated bytes verbatim, returns the post-write state", () => {
  const dir = tmpDir("mandu-sandbox-");
  try {
    const path = join(dir, "mandu", "config.toml");
    const env = { MANDU_HOME: join(dir, "mandu") };
    const s1 = writeSandbox(env, { "landlock-net": false });
    assert.ok(existsSync(path));
    assert.equal(s1.keys.find((k) => k.key === "landlock-net")!.effective, false);
    const hand = "# my config\nproxy-port = 0\n" + readFileSync(path, "utf8") + "\n[extra]\nfoo = 1\n";
    writeFileSync(path, hand);
    writeSandbox(env, { "landlock-net": true });
    const after = readFileSync(path, "utf8");
    assert.equal(after, hand.replace("landlock-net = false", "landlock-net = true"), "only the managed line changed");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeSandbox: no resolvable path → throws, writes nothing", () => {
  assert.throws(() => writeSandbox({}, { "exec-box": false }), /cannot resolve the config path/);
});
