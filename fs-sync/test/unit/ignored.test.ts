/**
 * Unit: the ignored-file enumeration, caps, env knobs and manifest
 * (src/ignored.ts; fs-sync.md §3.4.1). Real git in a temp dir, no
 * arbiter: nothing here mints.
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  DEFAULT_IGNORED_DENY_DIRS,
  DEFAULT_IGNORED_LIMITS,
  applyIgnoredCaps,
  emptyManifest,
  humanIgnoredSet,
  ignoredInclusionEnabled,
  listAgentViewIgnored,
  ignoredLimitsFromEnv,
  listIgnoredFiles,
  loadIgnoredManifest,
  pathCrossesSymlink,
  saveIgnoredManifest,
  skipCounts,
} from "../../src/ignored.js";
import { initShadowRepo, shadowCtx } from "../../src/git.js";
import { ViewLayout } from "../../src/layout.js";
import { makeTempRepo } from "../helpers/temp-repo.js";

test("caps: too-large, file-cap and total-cap skip in path order, the rest is kept", () => {
  const limits = { ...DEFAULT_IGNORED_LIMITS, maxFileBytes: 100, maxFiles: 3, maxTotalBytes: 150 };
  const out = applyIgnoredCaps(
    [
      { rel: "d", size: 10 },
      { rel: "a", size: 60 },
      { rel: "big", size: 101 },
      { rel: "b", size: 60 },
      { rel: "c", size: 60 }, // 60+60+60 > 150
      { rel: "e", size: 1 }, // file-cap: a, b, d already kept
    ],
    limits,
  );
  assert.deepEqual(out.files.map((f) => f.rel), ["a", "b", "d"]);
  assert.deepEqual(
    out.skipped.map((s) => `${s.rel}:${s.reason}`),
    ["big:too-large", "c:total-cap", "e:file-cap"],
  );
});

test("env: MANDU_FS_IGNORED=0 turns inclusion off; MANDU_FS_IGNORED_DENY adds plain names only", () => {
  assert.equal(ignoredInclusionEnabled({}), true);
  assert.equal(ignoredInclusionEnabled({ MANDU_FS_IGNORED: "0" }), false);
  assert.equal(ignoredLimitsFromEnv({}), DEFAULT_IGNORED_LIMITS);
  const l = ignoredLimitsFromEnv({ MANDU_FS_IGNORED_DENY: " vendor , a/b, .., , tmp" });
  assert.ok(l.denyDirs.includes("vendor") && l.denyDirs.includes("tmp"));
  assert.ok(!l.denyDirs.includes("a/b") && !l.denyDirs.includes(".."));
  for (const d of DEFAULT_IGNORED_DENY_DIRS) assert.ok(l.denyDirs.includes(d), `default ${d} kept`);
});

test("enumeration over the shadow context: ignored files listed, heavy dirs denied as one entry, symlinks skipped, tracked files absent", () => {
  const repo = makeTempRepo({
    ".gitignore": ".env\nnotes/\nnode_modules/\n*.log\nlinks/\n",
    "app.ts": "export const x = 1;\n",
  });
  try {
    const ws = repo.workspacePath;
    writeFileSync(join(ws, ".env"), "API_KEY=abc\n");
    mkdirSync(join(ws, "notes/deep"), { recursive: true });
    writeFileSync(join(ws, "notes/a.md"), "a\n");
    writeFileSync(join(ws, "notes/deep/b.md"), "b\n");
    mkdirSync(join(ws, "notes/node_modules"), { recursive: true });
    writeFileSync(join(ws, "notes/node_modules/x.js"), "x\n");
    mkdirSync(join(ws, "node_modules/pkg"), { recursive: true });
    writeFileSync(join(ws, "node_modules/pkg/index.js"), "module.exports = 1;\n");
    writeFileSync(join(ws, "run.log"), "log\n");
    mkdirSync(join(ws, "links"));
    symlinkSync("/etc/hostname", join(ws, "links/host"));
    writeFileSync(join(ws, "untracked.txt"), "not ignored\n"); // untracked but NOT ignored

    const layout = new ViewLayout(ws, repo.stateBase);
    initShadowRepo(layout);
    const out = listIgnoredFiles(shadowCtx(layout), ws, DEFAULT_IGNORED_LIMITS);
    assert.deepEqual(out.files.map((f) => f.rel), [".env", "notes/a.md", "notes/deep/b.md", "run.log"]);
    const skipped = out.skipped.map((s) => `${s.rel}:${s.reason}`).sort();
    assert.deepEqual(skipped, ["links/host:symlink", "node_modules/:deny-dir", "notes/node_modules/:deny-dir"]);
    assert.deepEqual(skipCounts(out.skipped), { "deny-dir": 2, symlink: 1 });
  } finally {
    repo.cleanup();
  }
});

test("HumanView rules decide for AgentView paths: absent paths match by pattern, tracked files never count as ignored", () => {
  const repo = makeTempRepo({
    ".gitignore": "notes/\n*.log\nnode_modules/\nforced.txt\n",
    "src.ts": "x\n",
  });
  try {
    const ws = repo.workspacePath;
    const layout = new ViewLayout(ws, repo.stateBase);
    writeFileSync(join(ws, "forced.txt"), "tracked although ignored\n");
    initShadowRepo(layout);
    // Force-track an ignored file in the SHADOW repo: git never reports a
    // tracked path as ignored, so it stays on the tracked sync.
    execFileSync("git", ["add", "-f", "forced.txt"], { cwd: ws, env: { ...process.env, ...shadowCtx(layout).env } });
    const set = humanIgnoredSet(shadowCtx(layout), [
      "notes/new.md", // none of these exist in the HumanView
      "a/b.log",
      "node_modules/",
      "deep/node_modules/y.js",
      "src/x.ts",
      ".gitignore",
      "forced.txt",
    ]);
    assert.deepEqual([...set].sort(), ["a/b.log", "deep/node_modules/y.js", "node_modules/", "notes/new.md"]);
    assert.deepEqual([...humanIgnoredSet(shadowCtx(layout), [])], []);
  } finally {
    repo.cleanup();
  }
});

test("AgentView listing: untracked files the HumanView ignores, whatever the worktree's own rules say", () => {
  const repo = makeTempRepo({ ".gitignore": "*.log\n", "a.ts": "x\n" });
  const av = mkdtempSync(join(tmpdir(), "ignored-av-"));
  try {
    const layout = new ViewLayout(repo.workspacePath, repo.stateBase);
    initShadowRepo(layout);
    execFileSync("git", ["init", "-q"], { cwd: av });
    writeFileSync(join(av, ".gitignore"), "$MDU:Read[abcd]\n"); // the seeded twin: ignores nothing
    writeFileSync(join(av, "out.log"), "o\n");
    writeFileSync(join(av, "keep.ts"), "k\n");
    const out = listAgentViewIgnored(av, shadowCtx(layout), DEFAULT_IGNORED_LIMITS);
    assert.deepEqual(out.files.map((f) => f.rel), ["out.log"]);
  } finally {
    rmSync(av, { recursive: true, force: true });
    repo.cleanup();
  }
});

test("manifest: round-trips, and a malformed file is an empty manifest (re-mint, never a leak)", () => {
  const dir = mkdtempSync(join(tmpdir(), "ignored-manifest-"));
  try {
    const p = join(dir, "ignored.json");
    assert.deepEqual(loadIgnoredManifest(p), emptyManifest());
    const m = emptyManifest();
    m.entries["a/b"] = { humanSha: "h", agentSha: "g" };
    m.notSynced = ["node_modules/"];
    saveIgnoredManifest(p, m);
    assert.deepEqual(loadIgnoredManifest(p), m);
    writeFileSync(p, "{not json");
    assert.deepEqual(loadIgnoredManifest(p), emptyManifest());
    writeFileSync(p, JSON.stringify({ version: 1, entries: { x: { humanSha: 1 } } }));
    assert.deepEqual(loadIgnoredManifest(p).entries, {});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("pathCrossesSymlink: a link anywhere on the path is caught; a missing tail is not a link", () => {
  const dir = mkdtempSync(join(tmpdir(), "ignored-link-"));
  try {
    mkdirSync(join(dir, "real"));
    symlinkSync(join(dir, "real"), join(dir, "alias"));
    assert.equal(pathCrossesSymlink(dir, "real/file"), false);
    assert.equal(pathCrossesSymlink(dir, "alias/file"), true);
    assert.equal(pathCrossesSymlink(dir, "missing/deeper/file"), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
