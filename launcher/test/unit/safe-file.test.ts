/**
 * safe-file — the launcher's files written by name in a session's scope dir
 * (and beside a config file) never follow a planted link
 * (runtime-instances.md §2, "planted paths"). Each writer is driven with a
 * link planted at the name it writes (or at the directory it writes into),
 * pointing at a canary file or folder: the canary must keep its bytes.
 *
 * The real-process form (the proxies' port files) is
 * tests/stack/safe-file-parity.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dirProblem, publishFile } from "../../src/safe-file.js";
import { mergeGuardPolicy } from "../../src/guard-policy-file.js";
import { writeExecShims } from "../../src/services/exec-shims.js";
import { writeExecBoxShims } from "../../src/services/exec-box-shims.js";
import { writeCaBundle } from "../../src/services/net-proxy.js";
import { inheritCodexTrust } from "../../src/services/codex-trust.js";
import { inheritWorkspaceTrust } from "../../src/services/claude-trust.js";
import { Layout } from "../../src/services/layout.js";

const CANARY = "# my shell startup file\n";

function fixture(): { dir: string; scope: string; canary: string; done: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-safe-file-"));
  const scope = join(dir, "scope");
  mkdirSync(scope, { mode: 0o700 });
  const canary = join(dir, "bashrc");
  writeFileSync(canary, CANARY);
  return { dir, scope, canary, done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("publishFile: replaces a link at the name, writes nothing through it, mode exact, no temp left", () => {
  const f = fixture();
  try {
    const target = join(f.scope, "out.json");
    symlinkSync(f.canary, target);
    publishFile(target, "{}\n", { mode: 0o640 });
    assert.equal(readFileSync(f.canary, "utf8"), CANARY);
    assert.ok(lstatSync(target).isFile());
    assert.equal(readFileSync(target, "utf8"), "{}\n");
    assert.equal(lstatSync(target).mode & 0o777, 0o640, "fchmod: the exact mode, not narrowed by the umask");
    assert.deepEqual(readdirSync(f.scope), ["out.json"]);
  } finally {
    f.done();
  }
});

test("publishFile: a link at the old fixed temp name is left alone, never written through", () => {
  const f = fixture();
  try {
    const target = join(f.scope, "port");
    symlinkSync(f.canary, `${target}.tmp`);
    publishFile(target, "4242");
    assert.equal(readFileSync(f.canary, "utf8"), CANARY);
    assert.equal(readFileSync(target, "utf8"), "4242");
  } finally {
    f.done();
  }
});

test("publishFile: a directory that is a link is refused (unless the caller allows a user's link)", () => {
  const f = fixture();
  try {
    const elsewhere = join(f.dir, "project");
    mkdirSync(elsewhere);
    const linked = join(f.dir, "linked");
    symlinkSync(elsewhere, linked);
    assert.throws(() => publishFile(join(linked, "x"), "y"), /refusing to write .*symbolic link/);
    assert.deepEqual(readdirSync(elsewhere), [], "nothing written into the linked-to folder");
    publishFile(join(linked, "x"), "y", { dirMayBeLink: true });
    assert.equal(readFileSync(join(elsewhere, "x"), "utf8"), "y");
    assert.match(dirProblem(f.scope, { uid: (process.getuid?.() ?? 0) + 1 }) ?? "", /not yours/, "another user's directory is refused");
    assert.match(dirProblem(f.canary) ?? "", /not a directory/);
    assert.equal(dirProblem(f.scope), null);
  } finally {
    f.done();
  }
});

test("the guard policy file in the scope dir: a planted link is replaced, not written through", () => {
  const f = fixture();
  try {
    symlinkSync(f.canary, join(f.scope, "guard-policy.json"));
    const env: Record<string, string> = {};
    const path = mergeGuardPolicy(env, { scopeRunDir: f.scope, agentExe: "/bin/true", session: "s1", askTimeoutMs: 1000 }, { writeProtect: [] });
    assert.equal(readFileSync(f.canary, "utf8"), CANARY);
    assert.ok(lstatSync(path).isFile());
    assert.equal(JSON.parse(readFileSync(path, "utf8")).session, "s1");
    assert.equal(lstatSync(path).mode & 0o777, 0o600);
  } finally {
    f.done();
  }
});

test("exec shims: a planted shim link is replaced; a linked exec-shims dir refuses the write", () => {
  const f = fixture();
  try {
    mkdirSync(join(f.scope, "exec-shims"));
    symlinkSync(f.canary, join(f.scope, "exec-shims", "curl"));
    const dir = writeExecShims(["curl"], Layout.dev("/repo"), "/run/a.sock", f.scope);
    assert.equal(readFileSync(f.canary, "utf8"), CANARY);
    assert.ok(lstatSync(join(dir, "curl")).isFile());
    assert.equal(lstatSync(join(dir, "curl")).mode & 0o777, 0o755);

    const scope2 = join(f.dir, "scope2");
    mkdirSync(scope2);
    const bin = join(f.dir, "bin");
    mkdirSync(bin);
    symlinkSync(bin, join(scope2, "exec-shims"));
    assert.throws(() => writeExecShims(["curl"], Layout.dev("/repo"), "/run/a.sock", scope2), /symbolic link/);
    assert.deepEqual(readdirSync(bin), [], "no shim landed in the linked-to folder");
    // The exec box's shims, the same way.
    mkdirSync(join(f.scope, "exec-box-shims"), { recursive: true });
    const boxDir = writeExecBoxShims(["git"], "/opt/box", "/run/a.sock", f.scope);
    symlinkSync(f.canary, join(boxDir, "make"));
    writeExecBoxShims(["git", "make"], "/opt/box", "/run/a.sock", f.scope);
    assert.equal(readFileSync(f.canary, "utf8"), CANARY);
    assert.ok(lstatSync(join(boxDir, "make")).isFile());
  } finally {
    f.done();
  }
});

test("the CA bundle in the scope dir: a planted link is replaced", (t) => {
  const f = fixture();
  try {
    const session = join(f.dir, "session-ca.pem");
    writeFileSync(session, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
    symlinkSync(f.canary, join(f.scope, "mandu-ca-bundle.pem"));
    const out = writeCaBundle(f.scope, session);
    if (out === undefined) { t.skip("this host has no system CA bundle"); return; }
    assert.equal(readFileSync(f.canary, "utf8"), CANARY);
    assert.ok(lstatSync(out).isFile());
    assert.equal(lstatSync(out).mode & 0o777, 0o644);
  } finally {
    f.done();
  }
});

test("trust inheritance: a link at the old fixed temp name beside the config is never written through", () => {
  const f = fixture();
  try {
    // Codex: <CODEX_HOME>/config.toml.
    const codexHome = join(f.dir, "codex");
    mkdirSync(codexHome);
    writeFileSync(join(codexHome, "config.toml"), `[projects."/h"]\ntrust_level = "trusted"\n`);
    symlinkSync(f.canary, join(codexHome, `config.toml.mandu-${process.pid}.tmp`));
    const r = inheritCodexTrust({ codexHome, humanRoot: "/h", agentPaths: ["/a"] });
    assert.equal(r.action, "inherited");
    assert.equal(readFileSync(f.canary, "utf8"), CANARY);
    assert.match(readFileSync(join(codexHome, "config.toml"), "utf8"), /\[projects\."\/a"\]/);
    // Claude Code: <config dir>/.claude.json.
    const cfg = join(f.dir, "claude");
    mkdirSync(cfg);
    writeFileSync(join(cfg, ".claude.json"), JSON.stringify({ projects: { "/h": { hasTrustDialogAccepted: true } } }));
    symlinkSync(f.canary, join(cfg, `.claude.json.mandu-${process.pid}.tmp`));
    const c = inheritWorkspaceTrust({ configDir: cfg, humanCwd: "/h", agentCwd: "/a" });
    assert.equal(c.action, "inherited");
    assert.equal(readFileSync(f.canary, "utf8"), CANARY);
    assert.equal(JSON.parse(readFileSync(join(cfg, ".claude.json"), "utf8")).projects["/a"].hasTrustDialogAccepted, true);
  } finally {
    f.done();
  }
});
