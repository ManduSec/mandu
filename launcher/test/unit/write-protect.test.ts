/**
 * write-protect.test — the launcher's write-protect list
 * (sandbox-security-review-2026-09-28 findings 2 and 6): which paths, which
 * answer, and how the list reaches the guard's policy file.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { manduPath } from "../../src/generated/mandu-paths.js";
import { applyWriteProtect, arbiterSocketFiles, laterRunFiles, ownFiles, repoHooksDirs, WRITE_PROTECT_LABELS, writeProtectList } from "../../src/write-protect.js";

const ENV = { HOME: "/h" };

test("Mandu's own files are refused: the whole home as one entry, the install dir, nothing part by part (on-disk-layout.md §4)", () => {
  const own = ownFiles(ENV, [], null);
  assert.ok(own.every((e) => e.answer === "deny" && e.label === "Mandu's own files"));
  assert.deepEqual(own.map((e) => e.path), ["/h/.mandu", "/h/.local/share/mandu"]);
  assert.equal(own[0]!.except, undefined, "no carve-out unless the launch names one");
  // A new file at the top of the home (a stray pre-one-home mandu.db) or
  // under state/ falls under the one entry: the guard refuses its creation.
  for (const p of ["/h/.mandu/mandu.db", "/h/.mandu/new-file", "/h/.mandu/state/x", "/h/.mandu/state/workspaces/w/repo.git/HEAD", "/h/.mandu/cache/object-twins/k/p.pack"]) {
    assert.ok(own.some((e) => p === e.path || p.startsWith(`${e.path}/`)), p);
  }
  assert.deepEqual(ownFiles({}, [], null), [], "no HOME, no list");
});

test("the integrity modes' carve-outs ride on the home entry as `except`; nothing else in the home is spared", () => {
  const av = "/h/.mandu/state/workspaces/w/agentview";
  const repo = "/h/.mandu/state/workspaces/w/repo.git";
  const own = ownFiles(ENV, [av, repo, av, "relative/x"], null);
  assert.deepEqual(own[0], { path: "/h/.mandu", answer: "deny", label: "Mandu's own files", except: [av, repo] });
  const list = writeProtectList(ENV, "/w", { exists: () => false, isDir: () => false, read: () => null }, undefined, undefined, undefined, [av]);
  assert.deepEqual(list[0]!.except, [av], "writeProtectList hands the carve-outs to the home entry");
  assert.equal(writeProtectList(ENV, "/w", { exists: () => false, isDir: () => false, read: () => null })[0]!.except, undefined, "none by default: the whole home refused");
});

test("MANDU_HOME moves the home; the default ~/.mandu stays refused; an explicit MANDU_POLICY_FILE and MANDU_PREFIX are refused", () => {
  const own = ownFiles({ HOME: "/h", MANDU_HOME: "/m", MANDU_POLICY_FILE: "/p/law.yaml", MANDU_PREFIX: "/opt/mandu" }, ["/m/state/workspaces/w/agentview"], null);
  assert.deepEqual(own.map((e) => e.path), ["/m", "/h/.mandu", "/h/.local/share/mandu", "/opt/mandu", "/p/law.yaml"]);
  assert.deepEqual(own[0]!.except, ["/m/state/workspaces/w/agentview"], "the carve-outs belong to the effective home");
  assert.equal(own[1]!.except, undefined, "the default home is refused whole");
});

test("every location is the path table's (on-disk-layout.md §5); the retired per-path overrides move nothing", () => {
  const env = { HOME: "/h", XDG_CONFIG_HOME: "/c", XDG_STATE_HOME: "/s", XDG_DATA_HOME: "/d", MANDU_PREFIX: "/opt/mandu" };
  const paths = ownFiles(env, [], null).map((e) => e.path);
  assert.ok(paths.includes(manduPath("mandu-home", env, "/h")));
  // The install dir is where scripts/install.sh puts it: MANDU_PREFIX, else
  // ~/.local/share/mandu, never $XDG_DATA_HOME/mandu.
  assert.ok(paths.includes("/opt/mandu") && paths.includes("/h/.local/share/mandu"));
  assert.ok(!paths.includes("/d/mandu"));
  const retired = { HOME: "/h", MANDU_CONFIG: "/dev/null", MANDU_SECRETS: "/dev/null", MANDU_EVENT_DIR: "/tmp/x", MANDU_SYMBOL_DB: "/x/sym.db", MANDU_VIEW_STATE: "/v" };
  assert.deepEqual(ownFiles(retired, [], null), ownFiles({ HOME: "/h" }, [], null), "no retired variable adds, moves or drops an entry");
});

test("files that run later are held for the human, each with a label the arbiter shows", () => {
  const later = laterRunFiles(ENV);
  assert.ok(later.every((e) => e.answer === "ask"));
  assert.ok(later.every((e) => (WRITE_PROTECT_LABELS as readonly string[]).includes(e.label)), "every label is one the Inbox shows");
  const byPath = new Map(later.map((e) => [e.path, e.label]));
  assert.equal(byPath.get("/h/.bashrc"), "a shell startup file");
  assert.equal(byPath.get("/h/.profile"), "a shell startup file");
  assert.equal(byPath.get("/h/.config/systemd/user"), "a systemd user unit");
  assert.equal(byPath.get("/h/.config/autostart"), "a desktop autostart entry");
  assert.equal(byPath.get("/h/.ssh/authorized_keys"), "an ssh setting");
  assert.equal(byPath.get("/h/.gitconfig"), "a git setting");
  // The user's decision (2026-09-28): written legitimately too often.
  assert.ok(!byPath.has("/h/.claude/settings.json"));
  assert.ok(![...byPath.keys()].some((p) => p.endsWith(".git/config")));
});

test("repoHooksDirs: a plain repository's .git/hooks, a linked worktree's common dir, none outside a repo", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-wp-repo-"));
  try {
    mkdirSync(join(dir, "main", ".git", "hooks"), { recursive: true });
    mkdirSync(join(dir, "main", "src", "deep"), { recursive: true });
    assert.deepEqual(repoHooksDirs(join(dir, "main", "src", "deep")), [join(dir, "main", ".git", "hooks")]);
    // A linked worktree: `.git` is a file naming its gitdir, whose commondir
    // leads back to the main repository's .git.
    mkdirSync(join(dir, "main", ".git", "worktrees", "wt"), { recursive: true });
    writeFileSync(join(dir, "main", ".git", "worktrees", "wt", "commondir"), "../..\n");
    mkdirSync(join(dir, "wt"), { recursive: true });
    writeFileSync(join(dir, "wt", ".git"), `gitdir: ${join(dir, "main", ".git", "worktrees", "wt")}\n`);
    assert.deepEqual(repoHooksDirs(join(dir, "wt")), [join(dir, "main", ".git", "hooks")]);
    mkdirSync(join(dir, "plain"), { recursive: true });
    const outside = repoHooksDirs(join(dir, "plain"));
    assert.ok(outside.every((p) => !p.startsWith(dir)), "no repository inside the fixture");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the arbiter's socket, its real path and each symlink on the way are refused, not its directory", () => {
  const fsx = {
    real: (p: string) => (p === "/run/user/7/mandu/current/arbiter.sock" ? "/run/user/7/mandu/instances/abc/arbiter.sock" : null),
    isLink: (p: string) => p === "/run/user/7/mandu/current",
  };
  const e = arbiterSocketFiles("/run/user/7/mandu/current/arbiter.sock", fsx);
  assert.ok(e.every((x) => x.answer === "deny"));
  assert.deepEqual(e.map((x) => x.path).sort(), [
    "/run/user/7/mandu/current",
    "/run/user/7/mandu/current/arbiter.sock",
    "/run/user/7/mandu/instances/abc/arbiter.sock",
  ]);
  assert.deepEqual(arbiterSocketFiles(undefined, fsx), []);
  assert.deepEqual(arbiterSocketFiles("relative.sock", fsx), []);
});

test("writeProtectList: own files, later-run files and the workspace's hooks together", () => {
  const fs = { exists: (p: string) => p === "/w/.git", isDir: (p: string) => p === "/w/.git", read: () => null };
  const list = writeProtectList(ENV, "/w/sub", fs);
  assert.ok(list.some((e) => e.path === "/w/.git/hooks" && e.answer === "ask" && e.label === "a git hook"));
  assert.ok(list.some((e) => e.path === "/h/.mandu" && e.answer === "deny"));
});

test("applyWriteProtect: joins the secret setup's policy file, or writes its own, and turns the traps on", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-wp-apply-"));
  try {
    const list = [{ path: "/h/.bashrc", answer: "ask" as const, label: "a shell startup file" }];
    const logs: string[] = [];
    // No policy file yet (confidentiality axis off): one of its own.
    const env1: Record<string, string> = {};
    applyWriteProtect(list, env1, { log: (m) => logs.push(m), scopeRunDir: dir, agentExe: "/bin/claude", session: "s1" });
    assert.equal(env1["MANDU_NET_GUARD_SECRETS"], join(dir, "guard-policy.json"));
    assert.equal(env1["MANDU_NET_GUARD_PROTECT"], "1");
    const own = JSON.parse(readFileSync(join(dir, "guard-policy.json"), "utf8"));
    assert.deepEqual(own.writeProtect, list);
    assert.deepEqual(own.secrets, []);
    assert.equal(own.agentExe, "/bin/claude");
    // A secret setup's file: kept, the list added.
    const secretPolicy = join(dir, "secret-policy.json");
    writeFileSync(secretPolicy, JSON.stringify({ agentExe: "/bin/claude", secrets: [{ path: "/h/.aws/credentials", twin: "/t", level: "no-model" }], protect: ["/h/keep"] }));
    const env2: Record<string, string> = { MANDU_NET_GUARD_SECRETS: secretPolicy };
    applyWriteProtect(list, env2, { log: () => {}, scopeRunDir: dir, agentExe: "", session: "s2" });
    const merged = JSON.parse(readFileSync(secretPolicy, "utf8"));
    assert.equal(merged.secrets.length, 1, "the secrets stay");
    assert.deepEqual(merged.protect, ["/h/keep"]);
    assert.deepEqual(merged.writeProtect, list);
    assert.equal(env2["MANDU_NET_GUARD_PROTECT"], "1");
    assert.match(logs.join("\n"), /write-protect/);
    // An empty list changes nothing.
    const env3: Record<string, string> = {};
    applyWriteProtect([], env3, { log: () => {}, scopeRunDir: dir, agentExe: "", session: "s3" });
    assert.deepEqual(env3, {});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a scratch HOME still refuses the account's own ~/.mandu (an eval leg, a test launch)", () => {
  const paths = ownFiles({ HOME: "/tmp/leg/home" }, [], "/home/real").map((e) => e.path);
  assert.ok(paths.includes("/tmp/leg/home/.mandu"), "the launch's home");
  assert.ok(paths.includes("/home/real/.mandu"), "the account's own home");
  assert.equal(ownFiles({ HOME: "/home/real" }, [], "/home/real").filter((e) => e.path === "/home/real/.mandu").length, 1, "listed once when they are the same");
});

test("macOS (platform darwin): launchd agents join the files that run later, under the existing autostart label; Linux is unchanged", () => {
  const mac = laterRunFiles(ENV, "darwin");
  const la = mac.find((e) => e.path === "/h/Library/LaunchAgents");
  assert.deepEqual(la, { path: "/h/Library/LaunchAgents", answer: "ask", label: "a desktop autostart entry" });
  assert.ok(mac.every((e) => (WRITE_PROTECT_LABELS as readonly string[]).includes(e.label)), "no new label (pinned by the arbiter parity test)");
  assert.ok(!laterRunFiles(ENV).some((e) => e.path.includes("Library")), "the Linux guard's list has no ~/Library entry");
  const nofs = { exists: () => false, isDir: () => false, read: () => null };
  assert.ok(writeProtectList(ENV, "/h/w", nofs, undefined, undefined, () => {}, [], "darwin").some((e) => e.path === "/h/Library/LaunchAgents"));
  assert.ok(!writeProtectList(ENV, "/h/w", nofs).some((e) => e.path === "/h/Library/LaunchAgents"));
  // An opt-out drops it on macOS like any built-in later-run entry.
  const out = writeProtectList(ENV, "/h/w", nofs, undefined, { deny: [], ask: [], unprotect: ["~/Library/LaunchAgents"] }, () => {}, [], "darwin");
  assert.ok(!out.some((e) => e.path === "/h/Library/LaunchAgents"));
});

test("macOS: the xcrun shim's cache (which picks the git /usr/bin/git runs) is a file that runs later, a git setting; none off macOS or without an absolute temp dir", () => {
  const T = "/var/folders/gc/abc/T/";
  const mac = laterRunFiles(ENV, "darwin", () => T);
  assert.deepEqual(mac.find((e) => e.path.endsWith("xcrun_db")), { path: "/var/folders/gc/abc/T/xcrun_db", answer: "ask", label: "a git setting" });
  assert.ok(!laterRunFiles(ENV, "linux", () => T).some((e) => e.path.endsWith("xcrun_db")), "Linux has no xcrun");
  assert.ok(!laterRunFiles(ENV, "darwin", () => "").some((e) => e.path.endsWith("xcrun_db")), "no temp dir: no entry");
});
