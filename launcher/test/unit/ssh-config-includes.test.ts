/**
 * ssh-config-includes.test — the files ssh reads as configuration through an
 * `Include` go on the write-protect list (P0 (D), 2026-10-07;
 * write-protection.md §2). Red before: only `~/.ssh/config` itself was held,
 * so the agent could write `~/.ssh/config.d/x.conf` (or OrbStack's included
 * file) with `Include ~/.ssh/id_ed25519`, and ssh, which reads the key raw,
 * printed every line of it as a bad keyword.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { stateAxes } from "../axes.js";
import { includeLines, includeWords, sshIncludeTargets, type IncludeFs } from "../../src/ssh-config-includes.js";
import { sshIncludeFiles, writeProtectList, type WriteProtectFs } from "../../src/write-protect.js";

stateAxes("secrets"); // the write-protect list is built in every mode the guard runs; secrets is the default

/** A virtual file tree: path → text (a file) or string[] (a directory's names). */
function vfs(tree: Record<string, string | string[]>): IncludeFs & WriteProtectFs {
  return {
    read: (p) => (typeof tree[p] === "string" ? (tree[p] as string) : null),
    list: (d) => (Array.isArray(tree[d]) ? (tree[d] as string[]) : null),
    exists: (p) => p in tree,
    isDir: (p) => Array.isArray(tree[p]),
  };
}

test("includeWords: ssh's word split (quotes, a backslash, a comment ends the line)", () => {
  assert.deepEqual(includeWords("config.d/*  ~/.orbstack/ssh/config"), ["config.d/*", "~/.orbstack/ssh/config"]);
  assert.deepEqual(includeWords(`"~/My Configs/ssh.conf" 'b c' d\\ e`), ["~/My Configs/ssh.conf", "b c", "d e"]);
  assert.deepEqual(includeWords("a # b c"), ["a"]);
  assert.deepEqual(includeWords("   "), []);
});

test("includeLines: the keyword in any case, with `=` or spaces, inside a Host or Match block too", () => {
  const text = [
    "Include a.conf",
    "Host work",
    "  include = b.conf c.conf",
    "Match host x exec true",
    "\tINCLUDE\td.conf",
    "# Include e.conf",
    "IdentityFile ~/.ssh/include.key",
  ].join("\n");
  assert.deepEqual(includeLines(text), [["a.conf"], ["b.conf", "c.conf"], ["d.conf"]]);
});

test("sshIncludeTargets: each Include of ~/.ssh/config and of /etc/ssh/ssh_config, followed, with ssh's rules for ~ and relative words", () => {
  const fs = vfs({
    "/h/.ssh/config": [
      "Include config.d/*",
      "Host *.orb",
      "  Include ~/.orbstack/ssh/config",
      `Include "~/My Configs/ssh.conf"`,
      "Include ~u/.colima/ssh_config",
    ].join("\n"),
    "/h/.ssh/config.d": ["work.conf", "loop.conf"],
    "/h/.ssh/config.d/work.conf": "Host work\n  Include nested/*.conf\n",
    "/h/.ssh/config.d/loop.conf": "Include ~/.ssh/config\n",
    "/h/.ssh/nested": ["n.conf"],
    "/h/.ssh/nested/n.conf": "Include ~/.lima/ssh.config\n",
    "/etc/ssh/ssh_config": "Include /etc/ssh/ssh_config.d/*.conf\nInclude extra.conf\nInclude ~/never\n",
  });
  const t = sshIncludeTargets(["/h"], fs, "/etc/ssh/ssh_config", "u");
  assert.deepEqual(new Set(t.paths), new Set([
    // a pattern: the directory before its first glob character
    "/h/.ssh/config.d",
    "/h/.ssh/nested",
    "/etc/ssh/ssh_config.d",
    // a plain word: the file, existing or not
    "/h/.orbstack/ssh/config",
    "/h/My Configs/ssh.conf",
    "/h/.colima/ssh_config",
    "/h/.lima/ssh.config",
    "/h/.ssh/config",
    "/etc/ssh/extra.conf",
  ]));
  assert.deepEqual(t.unprotectable, [], "nothing too broad here");
  assert.ok(!t.paths.includes("/h/never"), "ssh refuses ~ in the system file");
});

test("sshIncludeTargets: an Include that would need the home, a directory above it or a top-level directory held is reported, never protected", () => {
  const fs = vfs({
    "/h/.ssh/config": "Include ~\nInclude ~/*.conf\nInclude /tmp/*.conf\nInclude /*\nInclude ~bob/.ssh/config\nInclude ~/.ssh/ok.conf\n",
  });
  const t = sshIncludeTargets(["/h"], fs, "/nonexistent/ssh_config");
  assert.deepEqual(t.paths, ["/h/.ssh/ok.conf"]);
  assert.deepEqual(t.unprotectable.map((u) => u.word), ["~", "~/*.conf", "/tmp/*.conf", "/*", "~bob/.ssh/config"]);
  assert.ok(t.unprotectable.every((u) => u.file === "~/.ssh/config"), "the file is named from the home, never by its text");
});

test("sshIncludeTargets: each home's config (the launch's HOME and the account's); a missing config is nothing", () => {
  const fs = vfs({ "/acct/.ssh/config": "Include config.d/*\n" });
  assert.deepEqual(sshIncludeTargets(["/scratch", "/acct"], fs, "/none").paths, ["/acct/.ssh/config.d"]);
  assert.deepEqual(sshIncludeTargets(["/scratch"], fs, "/none").paths, []);
  // No list: the directory is still held, nested includes are not followed.
  const noList: IncludeFs = { read: (p) => (p === "/acct/.ssh/config" ? "Include config.d/*\n" : null) };
  assert.deepEqual(sshIncludeTargets(["/acct"], noList, "/none").paths, ["/acct/.ssh/config.d"]);
});

test("the write-protect list holds every ssh include under the ssh label, the account's ~/.ssh/config too; a broad one is a warning; unprotect drops one", () => {
  const fs = vfs({
    "/h/.ssh/config": "Include config.d/*\nInclude /tmp/*.conf\n",
    "/h/.ssh/config.d": [],
    "/acct/.ssh/config": "Include ~/.orbstack/ssh/config\n",
  });
  const logs: string[] = [];
  const list = writeProtectList({ HOME: "/h" }, "/w", fs, undefined, undefined, (m) => logs.push(m), [], "linux", "/acct");
  const ssh = list.filter((e) => e.label === "an ssh setting").map((e) => e.path);
  for (const p of ["/h/.ssh/config", "/h/.ssh/config.d", "/acct/.ssh/config", "/acct/.orbstack/ssh/config"]) assert.ok(ssh.includes(p), `${p} held: ${ssh.join(", ")}`);
  assert.ok(list.filter((e) => e.label === "an ssh setting").every((e) => e.answer === "ask"));
  assert.equal(ssh.filter((p) => p === "/h/.ssh/config").length, 1, "each path once");
  assert.ok(logs.some((l) => /WARNING: mandu: ~\/\.ssh\/config includes \/tmp\/\*\.conf/.test(l)), logs.join("\n"));
  const dropped = writeProtectList({ HOME: "/h" }, "/w", fs, undefined, { deny: [], ask: [], unprotect: ["~/.ssh/config.d"] }, () => {}, [], "linux", "/acct");
  assert.ok(!dropped.some((e) => e.path === "/h/.ssh/config.d"), "policy.yaml write_protect.unprotect drops an include like any built-in ask");
  // A stub fs with no `list` (the other tests'): no include walk at all.
  const stub = writeProtectList({ HOME: "/h" }, "/w", { exists: () => false, isDir: () => false, read: () => null }, undefined, undefined, () => {}, [], "linux", "/acct");
  assert.ok(!stub.some((e) => e.path === "/acct/.ssh/config"));
  assert.deepEqual(sshIncludeFiles({}, fs, null), [], "no home, nothing");
});
