/**
 * claude-permission-mode.test — Claude Code starts in its default
 * permission mode under Mandu unless the user chose one
 * (claude-permission-mode.ts; supported-agents.md §2, "Claude Code's
 * permission mode under Mandu"). Every source that counts as a choice, the
 * ones that do not, the subcommands that get nothing, the one rule
 * (claude-permission-rule.cjs) the launch, the SDK route preload and the
 * PATH shim all apply. Pure: no process; settings files only through
 * injected readers (the preload's `--settings` file read and the PATH
 * lookup: temp files).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CLAUDE_DEFAULT_PERMISSION_ARGS, claudeArgvFileScopes, claudeArgvModeChoice, claudeArgvModeFlag, claudeModeScopes,
  claudePermissionModeDecision, settingsDefaultMode, type ClaudeModeLayer,
} from "../../src/claude-permission-mode.js";
import { CLAUDE_NON_SESSION } from "../../src/claude-sandbox.js";
import { claudeRouteEnv } from "../../src/claude-route.js";
import * as rule from "../../src/claude-permission-rule.cjs";
import * as fs from "node:fs";
import * as path from "node:path";

// Axes: none. The permission mode is axis-independent and nothing here starts a service.

interface Mode { cwd: string; configDir: string; scopes: string[] }
interface Preload {
  claudeModeArgs(args: string[], mode: Mode | undefined, cwd: string, env: Record<string, string | undefined>): string[];
  routeSpawn(route: unknown, file: string, args: string[], env: Record<string, string | undefined>, cwd?: string): { args: string[] };
}
const preload = createRequire(import.meta.url)("../../src/sdk-route-preload.cjs") as Preload;

const noFile = (): string | null => null;
const layer = (scope: ClaudeModeLayer["scope"], doc: unknown, path = `/s/${scope}.json`): ClaudeModeLayer =>
  ({ path, scope, text: doc === null ? null : typeof doc === "string" ? doc : JSON.stringify(doc) });
const MODE = (m: string) => ({ permissions: { defaultMode: m } });
const NO_LAYERS: ClaudeModeLayer[] = [
  layer("global", { permissions: { defaultMode: "plan" } }), // ~/.claude.json: not a settings source for this
  layer("user", { permissions: { allow: ["Bash(ls)"] } }),
  layer("project", null),
  layer("local", ""),
  layer("managed", null),
];
const decide = (argv: string[], layers: ClaudeModeLayer[] = NO_LAYERS, readFile: (p: string) => string | null = noFile) =>
  claudePermissionModeDecision(["claude", ...argv], layers, readFile);

test("nothing chosen: a session (TUI, -p, --resume, --continue) gets --permission-mode default", () => {
  assert.deepEqual(CLAUDE_DEFAULT_PERMISSION_ARGS, ["--permission-mode", "default"]);
  for (const argv of [[], ["-p", "hi"], ["--resume"], ["-r", "abc"], ["--continue"], ["-c", "-p", "go on"], ["--model", "opus", "fix it"]]) {
    assert.deepEqual(decide(argv), { inject: true }, JSON.stringify(argv));
  }
});

test("a mode chosen on the command line is kept: --permission-mode (any value, either spelling), --dangerously-skip-permissions", () => {
  for (const m of ["default", "manual", "auto", "acceptEdits", "plan", "bypassPermissions", "dontAsk", "someFutureMode"]) {
    assert.deepEqual(decide(["--permission-mode", m, "-p", "x"]), { inject: false, reason: `--permission-mode ${m}` });
    assert.deepEqual(decide([`--permission-mode=${m}`]), { inject: false, reason: `--permission-mode=${m}` });
  }
  assert.deepEqual(decide(["-p", "x", "--dangerously-skip-permissions"]), { inject: false, reason: "--dangerously-skip-permissions" });
  // Past a `--` too: a false match only leaves Claude Code's own pick.
  assert.equal(decide(["--", "--permission-mode", "plan"]).inject, false);
});

test("--allow-dangerously-skip-permissions is NOT a choice (it only makes bypass selectable; alone Claude Code starts in auto)", () => {
  assert.deepEqual(decide(["--allow-dangerously-skip-permissions", "-p", "x"]), { inject: true });
});

test("permissions.defaultMode in a user, project, local or managed settings file is a choice (a flag would override it)", () => {
  for (const scope of ["user", "project", "local", "managed"] as const) {
    const layers = [...NO_LAYERS, layer(scope, MODE("acceptEdits"), `/s/${scope}-mode.json`)];
    assert.deepEqual(decide(["-p", "x"], layers), { inject: false, reason: `/s/${scope}-mode.json (permissions.defaultMode)` }, scope);
  }
  // Claude Code's own parse: a byte-order mark is dropped.
  assert.equal(decide([], [layer("user", "﻿" + JSON.stringify(MODE("plan")))]).inject, false);
});

test("settings that set no usable mode are not a choice: other keys, a non-string or empty defaultMode, a file that does not parse, the global config", () => {
  for (const doc of [{}, { permissions: {} }, { permissions: { defaultMode: 3 } }, { permissions: { defaultMode: " " } }, { defaultMode: "plan" }, "{not json", null]) {
    assert.equal(decide([], [layer("user", doc)]).inject, true, JSON.stringify(doc));
  }
  assert.equal(decide([], [layer("global", MODE("plan"))]).inject, true);
});

test("--setting-sources and --restricted decide which user/project/local files count; managed ones always do", () => {
  const user = [layer("user", MODE("acceptEdits"))];
  assert.equal(decide(["--setting-sources", "project,local"], user).inject, true, "user file not read");
  assert.equal(decide(["--setting-sources=project,user"], user).inject, false);
  assert.equal(decide(["--setting-sources="], user).inject, true, "SDK settingSources: [] reads none");
  assert.equal(decide(["--setting-sources", "user", "--setting-sources", "local"], user).inject, true, "the last one counts");
  assert.equal(decide(["--restricted"], user).inject, true, "--restricted ignores user, project and local files");
  const managed = [layer("managed", MODE("plan"))];
  assert.equal(decide(["--setting-sources="], managed).inject, false);
  assert.equal(decide(["--restricted"], managed).inject, false);
  assert.deepEqual([...claudeArgvFileScopes(["claude"])], ["user", "project", "local"]);
  assert.deepEqual([...claudeArgvFileScopes(["claude", "--setting-sources", " local , nope"])], ["local"]);
});

test("a managed source Mandu cannot read counts as a choice (it may set one); an unreadable lower one does not exist for Claude Code either", () => {
  const plist: ClaudeModeLayer = { path: "/Library/Managed Preferences/com.anthropic.claudecode.plist", scope: "managed", text: null, unreadable: true };
  assert.deepEqual(decide([], [plist]), { inject: false, reason: `${plist.path} (unreadable)` });
  assert.equal(decide([], [{ path: "/u", scope: "user", text: null, unreadable: true }]).inject, true);
});

test("the run's own --settings (the last one; inline or a file) and --managed-settings count", () => {
  const files: Record<string, string> = { "/tmp/s.json": JSON.stringify(MODE("plan")), "/tmp/plain.json": "{}" };
  const read = (p: string): string | null => files[p] ?? null;
  assert.equal(decide(["--settings", JSON.stringify(MODE("plan"))]).inject, false);
  assert.equal(decide([`--settings=${JSON.stringify(MODE("plan"))}`]).inject, false);
  assert.equal(decide(["--settings", "/tmp/s.json"], NO_LAYERS, read).inject, false);
  assert.equal(decide(["--settings", JSON.stringify(MODE("plan")), "--settings", "{}"]).inject, true, "Claude Code reads only the last --settings");
  assert.equal(decide(["--settings", "/tmp/plain.json"], NO_LAYERS, read).inject, true);
  assert.equal(decide(["--managed-settings", JSON.stringify(MODE("dontAsk"))]).inject, false);
  assert.equal(claudeArgvModeChoice(["claude", "--managed-settings=/tmp/s.json"], read), "--managed-settings (permissions.defaultMode)");
});

test("no session, no flag: claude mcp / config / doctor / update / --version / --help get nothing", () => {
  for (const argv of [["mcp", "list"], ["config", "list"], ["doctor"], ["update"], ["auth", "status"], ["plugin", "list"], ["--version"], ["-v"], ["--help"], ["-p", "x", "-h"]]) {
    assert.deepEqual(decide(argv), { inject: false, reason: "no session" }, JSON.stringify(argv));
  }
});

test("claudeModeScopes: the scopes whose files set a mode, a managed unreadable one included", () => {
  assert.deepEqual(claudeModeScopes(NO_LAYERS), []);
  assert.deepEqual(new Set(claudeModeScopes([
    layer("user", MODE("plan")), layer("local", MODE("auto"), "/a"), layer("local", {}, "/b"), layer("global", MODE("plan")),
    { path: "/m.plist", scope: "managed", text: null, unreadable: true },
  ])), new Set(["user", "local", "managed"]));
});

test("settingsDefaultMode reads permissions.defaultMode only", () => {
  assert.equal(settingsDefaultMode(MODE("plan")), "plan");
  assert.equal(settingsDefaultMode({ defaultMode: "plan" }), null);
  assert.equal(settingsDefaultMode([MODE("plan")]), null);
});

// ── the one rule (claude-permission-rule.cjs) ──────────────────────────────

test("--inherit-permission-mode (a parent session's mode for its child, either spelling) is a choice: our flag would override it", () => {
  assert.deepEqual(decide(["--inherit-permission-mode", "bypassPermissions", "-p", "x"]), { inject: false, reason: "--inherit-permission-mode bypassPermissions" });
  assert.deepEqual(decide(["--inherit-permission-mode=acceptEdits"]), { inject: false, reason: "--inherit-permission-mode=acceptEdits" });
});

test("only where the flag is valid: agents, remote-control / rc and daemon (also behind the skip-permissions flags) get nothing", () => {
  for (const argv of [["agents"], ["remote-control"], ["rc"], ["daemon"], ["daemon", "status"], ["--allow-dangerously-skip-permissions", "daemon"]]) {
    assert.deepEqual(decide(argv), { inject: false, reason: "no session" }, JSON.stringify(argv));
  }
  // A prompt that only mentions one is still a session.
  assert.deepEqual(decide(["-p", "daemon"]), { inject: true });
  assert.deepEqual(decide(["fix", "the", "agents"]), { inject: true });
});

test("the rule's no-session set is a superset of claude-sandbox.ts CLAUDE_NON_SESSION (the routing's set), so it never adds the flag where the routing sees no session", () => {
  for (const sub of CLAUDE_NON_SESSION) {
    assert.ok(rule.NO_MODE_SUBCOMMANDS.has(sub), sub);
    assert.equal(rule.takesPermissionMode([sub]), false, sub);
  }
});

const ARGV_CORPUS: string[][] = [
  [], ["-p", "x"], ["--output-format", "stream-json", "--verbose", "--input-format", "stream-json"],
  ["--permission-mode", "plan"], ["--permission-mode=auto"], ["--dangerously-skip-permissions"], ["--allow-dangerously-skip-permissions"],
  ["--inherit-permission-mode", "plan"], ["--setting-sources=", "-p", "x"], ["--setting-sources", "user,project"], ["--restricted"],
  ["--", "--permission-mode", "plan"], ["mcp", "list"], ["--version"], ["-h"], ["doctor"], ["--resume", "abc"], ["daemon"], ["agents"],
];

test("one rule: the launch's wrappers are the rule over argv without argv[0]", () => {
  for (const args of ARGV_CORPUS) {
    const argv = ["claude", ...args];
    assert.equal(claudeArgvModeFlag(argv), rule.argvModeFlag(args), JSON.stringify(args));
    assert.deepEqual([...claudeArgvFileScopes(argv)], rule.argvFileScopes(args), JSON.stringify(args));
    assert.deepEqual(decide(args, []), rule.permissionModeDecision(args, () => null, () => null), JSON.stringify(args));
  }
  assert.deepEqual(rule.withPermissionMode(["-p", "x"], { inject: true }), ["--permission-mode", "default", "-p", "x"]);
  const kept = ["-p", "x"];
  assert.equal(rule.withPermissionMode(kept, { inject: false, reason: "r" }), kept, "the same array when nothing is added");
});

test("realExecutable: the next `claude` on PATH past the shim folder (and not a link into it); null when none", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-permrule-"));
  try {
    const shims = join(dir, "shims");
    const bin = join(dir, "bin");
    const other = join(dir, "other");
    for (const d of [shims, bin, other]) mkdirSync(d);
    writeFileSync(join(shims, "claude"), "#!/bin/sh\n", { mode: 0o755 });
    writeFileSync(join(bin, "claude"), "not executable", { mode: 0o644 });
    writeFileSync(join(other, "claude"), "#!/bin/sh\n", { mode: 0o755 });
    symlinkSync(join(shims, "claude"), join(bin, "claude-link"));
    assert.equal(rule.realExecutable("claude", [shims, bin, other].join(":"), shims, fs, path), join(other, "claude"));
    assert.equal(rule.realExecutable("claude-link", [shims, bin].join(":"), shims, fs, path), null, "a link into the shim folder is the shim");
    assert.equal(rule.realExecutable("claude", [shims, bin].join(":"), shims, fs, path), null);
    assert.equal(rule.realExecutable("claude", undefined, shims, fs, path), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── the SDK route preload and the PATH shim apply the same rule ─────────────

test("parity: with no scope setting a mode, the preload injects exactly when the launch would", () => {
  const mode: Mode = { cwd: "/work", configDir: "/home/u/.claude", scopes: [] };
  const env = { HOME: "/home/u" };
  for (const args of ARGV_CORPUS) {
    const injected = preload.claudeModeArgs(args, mode, "/work", env) !== args;
    assert.equal(injected, decide(args, []).inject, JSON.stringify(args));
  }
});

test("preload: a scope that sets a mode, read for this child, keeps the child's mode; one it does not read does not", () => {
  const env = { HOME: "/home/u" };
  const user: Mode = { cwd: "/work", configDir: "/home/u/.claude", scopes: ["user"] };
  assert.deepEqual(preload.claudeModeArgs(["-p", "x"], user, "/work", env), ["-p", "x"]);
  assert.deepEqual(preload.claudeModeArgs(["--setting-sources=", "-p", "x"], user, "/work", env), ["--permission-mode", "default", "--setting-sources=", "-p", "x"]);
  const managed: Mode = { ...user, scopes: ["managed"] };
  assert.deepEqual(preload.claudeModeArgs(["--setting-sources="], managed, "/work", env), ["--setting-sources="]);
  const project: Mode = { ...user, scopes: ["project"] };
  assert.deepEqual(preload.claudeModeArgs(["--setting-sources", "user"], project, "/work", env), ["--permission-mode", "default", "--setting-sources", "user"]);
  assert.deepEqual(preload.claudeModeArgs([], undefined, "/work", env), [], "a route without claudeMode leaves the mode alone");
});

test("preload: a child whose project/local or user files the launch did not read is left alone", () => {
  const mode: Mode = { cwd: "/work", configDir: "/home/u/.claude", scopes: [] };
  assert.deepEqual(preload.claudeModeArgs([], mode, "/elsewhere", { HOME: "/home/u" }), [], "another cwd");
  assert.deepEqual(preload.claudeModeArgs(["--setting-sources=user"], mode, "/elsewhere", { HOME: "/home/u" }), ["--permission-mode", "default", "--setting-sources=user"], "only user files read");
  assert.deepEqual(preload.claudeModeArgs([], mode, "/work", { HOME: "/home/u", CLAUDE_CONFIG_DIR: "/cfg" }), [], "another config dir");
  assert.deepEqual(preload.claudeModeArgs(["--setting-sources=project,local"], mode, "/work", { HOME: "/home/v" }), ["--permission-mode", "default", "--setting-sources=project,local"]);
});

test("preload: the child's own --settings (inline or a file) and --managed-settings count", () => {
  const mode: Mode = { cwd: "/work", configDir: "/home/u/.claude", scopes: [] };
  const env = { HOME: "/home/u" };
  const dir = mkdtempSync(join(tmpdir(), "mandu-permmode-"));
  try {
    const f = join(dir, "s.json");
    writeFileSync(f, JSON.stringify(MODE("plan")));
    for (const args of [["--settings", JSON.stringify(MODE("plan"))], ["--managed-settings", f], [`--managed-settings=${JSON.stringify(MODE("auto"))}`]]) {
      assert.deepEqual(preload.claudeModeArgs(args, mode, "/work", env), args, JSON.stringify(args));
    }
    assert.notDeepEqual(preload.claudeModeArgs(["--settings", "{}"], mode, "/work", env), ["--settings", "{}"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("preload routeSpawn: a claude child gets the mode before its routed --settings; a chosen one and a non-session child are untouched", () => {
  const route = {
    v: 1, target: "claude", env: { ANTHROPIC_BASE_URL: "http://127.0.0.1:8788" }, path: "/usr/bin", pathPrefix: [], require: "", anthropic: true, codex: null,
    launchRouting: claudeRouteEnv({ ANTHROPIC_BASE_URL: "http://127.0.0.1:8788" }),
    claudeMode: { cwd: "/work", configDir: "/home/u/.claude", scopes: [] },
  };
  const env = { HOME: "/home/u", ANTHROPIC_BASE_URL: "http://127.0.0.1:8788" };
  const out = preload.routeSpawn(route, "/sdk/claude", ["--output-format", "stream-json", "--setting-sources="], env, "/work").args;
  assert.deepEqual(out.slice(0, 3), ["--permission-mode", "default", "--settings"]);
  assert.ok(out.includes("--setting-sources="));
  const chosen = preload.routeSpawn(route, "/sdk/claude", ["--permission-mode", "bypassPermissions", "--allow-dangerously-skip-permissions"], env, "/work").args;
  assert.equal(chosen.filter((a) => a === "--permission-mode").length, 1);
  assert.equal(chosen[chosen.indexOf("--permission-mode") + 1], "bypassPermissions");
  assert.ok(!preload.routeSpawn(route, "/sdk/claude", ["--version"], env, "/work").args.includes("--permission-mode"));
  const { claudeMode: _omit, ...noMode } = route;
  assert.ok(!preload.routeSpawn(noMode, "/sdk/claude", [], env, "/work").args.includes("--permission-mode"), "a route without claudeMode: unchanged");
});
