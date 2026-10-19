/**
 * build-info.test — which commit a build records (scripts/build-info.mjs,
 * packaging.md §11.7): the source repository's HEAD, a public clone's
 * snapshot (its trailer names the source commit), the release pack's
 * MANDU_BUILD_* override, and "not recorded" rather than a guess. A real
 * throwaway git repository proves the trailer walk against git itself; the
 * reader re-checks what it reads.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BUILD_INFO_NAME, SNAPSHOT_TRAILER, commitOrNull, gitFacts, readBuildInfo, resolveBuildInfo, writeBuildInfo, type GitRun,
} from "../../scripts/build-info.mjs";
import { stateAxes } from "../axes.js";

stateAxes("off"); // build metadata only: no arbiter, no axis in play

const A = "a".repeat(40), B = "b".repeat(40), S = "5".repeat(40);

/** A fake git: `log` returns the records given, newest first. */
function fakeGit(head: string | null, records: Array<[string, string]>, status = ""): GitRun {
  return (dir, args) => {
    if (args[0] === "rev-parse") return head === null ? null : `${dir}\n${head}\n`;
    if (args[0] === "status") return status;
    if (args[0] === "log") return records.map(([sha, trailer]) => `${sha}\x1f${trailer}\x1e`).join("\n");
    return null;
  };
}

test("commitOrNull keeps 7-40 hex digits, lower-cased, and nothing else", () => {
  assert.equal(commitOrNull("ABCDEF1"), "abcdef1");
  assert.equal(commitOrNull(` ${A}\n`), A);
  for (const bad of ["", "abc", "g".repeat(40), "a".repeat(41), "--upload-pack=x", null, 42]) {
    assert.equal(commitOrNull(bad), null, String(bad));
  }
});

test("gitFacts: a HEAD with no snapshot in its first-parent history is the source repository's", () => {
  assert.deepEqual(gitFacts("/r", fakeGit(A, [[A, ""], [B, ""]])),
    { repo: "source", sourceCommit: A, publicCommit: null, publicAhead: 0, dirty: false });
  assert.equal(gitFacts("/r", fakeGit(A, [[A, ""]], " M launcher/src/run.ts\n"))?.dirty, true);
});

test("gitFacts: a public snapshot names its source commit; commits on top are counted", () => {
  assert.deepEqual(gitFacts("/r", fakeGit(A, [[A, S]])),
    { repo: "public", sourceCommit: S, publicCommit: A, publicAhead: 0, dirty: false });
  const ahead = gitFacts("/r", fakeGit(A, [[A, ""], [B, ""], ["c".repeat(40), S]]));
  assert.equal(ahead?.repo, "public");
  assert.equal(ahead?.publicCommit, A, "the public commit is HEAD");
  assert.equal(ahead?.sourceCommit, S);
  assert.equal(ahead?.publicAhead, 2);
});

test("gitFacts: no git, or no work tree, is null; a trailer that is not a commit is ignored", () => {
  assert.equal(gitFacts("/r", fakeGit(null, [])), null);
  assert.equal(gitFacts("/r", () => null), null);
  assert.equal(gitFacts("/r", fakeGit(A, [[A, "not-a-sha"]]))?.repo, "source");
});

test("resolveBuildInfo: MANDU_BUILD_* names the commits over git; with neither, nothing is guessed", () => {
  const readFile = () => JSON.stringify({ version: "0.2.0-beta.7" });
  const env = { MANDU_BUILD_SOURCE_COMMIT: S, MANDU_BUILD_PUBLIC_COMMIT: B };
  assert.deepEqual(resolveBuildInfo({ repoRoot: "/r", env, git: () => null, readFile }),
    { version: "0.2.0-beta.7", sourceCommit: S, publicCommit: B, publicAhead: 0, dirty: null });
  assert.deepEqual(resolveBuildInfo({ repoRoot: "/r", env: {}, git: () => null, readFile }),
    { version: "0.2.0-beta.7", sourceCommit: null, publicCommit: null, publicAhead: 0, dirty: null });
  // Env fills only what it names; git the rest.
  const mixed = resolveBuildInfo({ repoRoot: "/r", env: { MANDU_BUILD_PUBLIC_COMMIT: B }, git: fakeGit(A, [[A, ""]]), readFile });
  assert.equal(mixed.sourceCommit, A);
  assert.equal(mixed.publicCommit, B);
  // A malformed override is not a commit.
  assert.equal(resolveBuildInfo({ repoRoot: "/r", env: { MANDU_BUILD_SOURCE_COMMIT: "HEAD" }, git: () => null, readFile }).sourceCommit, null);
});

test("write/readBuildInfo round-trip; the reader drops what is not a commit", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-build-info-"));
  try {
    const info = { version: "0.2.0-beta.7", sourceCommit: S, publicCommit: null, publicAhead: 0, dirty: false };
    writeBuildInfo(dir, info);
    assert.deepEqual(readBuildInfo(dir), info);
    writeFileSync(join(dir, BUILD_INFO_NAME), JSON.stringify({ version: 7, sourceCommit: "$(rm -rf ~)", publicCommit: B, publicAhead: -1, dirty: "yes" }));
    assert.deepEqual(readBuildInfo(dir), { version: null, sourceCommit: null, publicCommit: B, publicAhead: 0, dirty: null });
    writeFileSync(join(dir, BUILD_INFO_NAME), "not json");
    assert.equal(readBuildInfo(dir), null);
    rmSync(join(dir, BUILD_INFO_NAME));
    assert.equal(readBuildInfo(dir), null, "a package built before the record has none");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("gitFacts against real git: a snapshot commit's trailer, then a commit on top", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-build-info-git-"));
  const git = (...args: string[]): string => {
    const r = spawnSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    return r.stdout.trim();
  };
  try {
    git("init", "-q");
    mkdirSync(join(dir, "launcher"));
    writeFileSync(join(dir, "launcher", "package.json"), JSON.stringify({ version: "0.2.0-beta.7" }));
    git("add", "-A");
    git("commit", "-q", "-m", `Mandu snapshot of ${S.slice(0, 12)}\n\n${SNAPSHOT_TRAILER}: ${S}`);
    const snap = git("rev-parse", "HEAD");
    assert.deepEqual(gitFacts(dir), { repo: "public", sourceCommit: S, publicCommit: snap, publicAhead: 0, dirty: false });

    writeFileSync(join(dir, "README.md"), "local work\n");
    git("add", "-A");
    git("commit", "-q", "-m", "docs: local work");
    const head = git("rev-parse", "HEAD");
    writeFileSync(join(dir, "README.md"), "uncommitted\n");
    const f = gitFacts(dir);
    assert.deepEqual(f, { repo: "public", sourceCommit: S, publicCommit: head, publicAhead: 1, dirty: true });

    // A tree that merely sits inside this repository (an exported tree under
    // a home kept in git) takes nothing from it.
    mkdirSync(join(dir, "export", "launcher"), { recursive: true });
    assert.equal(gitFacts(join(dir, "export")), null);

    const info = resolveBuildInfo({ repoRoot: dir, env: {} });
    assert.equal(info.version, "0.2.0-beta.7");
    assert.equal(info.publicCommit, head);
    // Two builds of one commit record the same bytes (no time, no path).
    const out = mkdtempSync(join(tmpdir(), "mdu-build-info-out-"));
    try {
      writeBuildInfo(out, info);
      const first = readFileSync(join(out, BUILD_INFO_NAME), "utf8");
      writeBuildInfo(out, resolveBuildInfo({ repoRoot: dir, env: {} }));
      assert.equal(readFileSync(join(out, BUILD_INFO_NAME), "utf8"), first);
      assert.ok(!first.includes(dir), "the record names no path");
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
