#!/usr/bin/env node
/**
 * build-info.mjs — which commit a Mandu build came from (packaging.md §11.7).
 *
 * Mandu has two histories: the source repository, where it is developed, and
 * the public repository, which receives one snapshot commit per export (its
 * message carries a `Mandu-Snapshot: <source commit>` trailer). The npm
 * tarball is packed from an exported tree that has no `.git`, so an installed
 * package cannot ask git which commit it is: build-bundle.mjs records it in
 * `<dist>/build-info.json` when it builds, and `mandu version` reads it back.
 *
 *   { "version": "0.2.0-beta.6",
 *     "sourceCommit": "<40 hex>" | null,   // the source repository's commit
 *     "publicCommit": "<40 hex>" | null,   // the public repository's commit
 *     "publicAhead": 0,                    // commits on top of that snapshot
 *     "dirty": false | null }              // uncommitted changes (null: no git)
 *
 * Each commit comes from, first to last:
 *   1. MANDU_BUILD_SOURCE_COMMIT / MANDU_BUILD_PUBLIC_COMMIT (the release
 *      pack, which builds the exported tree and knows both);
 *   2. git, when the tree is a git work tree: a HEAD whose first-parent
 *      history reaches a snapshot commit is the public repository (the public
 *      commit is HEAD, the source commit is the snapshot's trailer, and
 *      publicAhead counts the commits after the snapshot); any other HEAD is
 *      the source repository's;
 *   3. otherwise null: "not recorded", never a guess.
 * No timestamp and no path: two builds of one commit write the same bytes.
 *
 * Plain JS with no dependencies: build-bundle runs it, and the launcher reads
 * a checkout's live commit with the same code (src/version-report.ts).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
import { spawnSync } from "node:child_process";
import { readFileSync, realpathSync, renameSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The file's name inside the dist directory. */
export const BUILD_INFO_NAME = "build-info.json";
/** The trailer a public snapshot commit carries (the export writes it). */
export const SNAPSHOT_TRAILER = "Mandu-Snapshot";
/** How far back the first-parent walk looks for a snapshot commit. */
const SNAPSHOT_WALK = 200;

const COMMIT = /^[0-9a-f]{7,40}$/;

/** A commit id as given, lower-cased, or null when it is not one. */
export function commitOrNull(v) {
  if (typeof v !== "string") return null;
  const s = v.trim().toLowerCase();
  return COMMIT.test(s) ? s : null;
}

/** `git -C dir args…`'s stdout, or null when git fails or is absent. */
function realGit(dir, args) {
  const r = spawnSync("git", ["-C", dir, ...args], {
    encoding: "utf8", timeout: 10_000, stdio: ["ignore", "pipe", "ignore"],
    // A build's environment must not point git elsewhere.
    env: { ...process.env, GIT_DIR: undefined, GIT_WORK_TREE: undefined, GIT_OPTIONAL_LOCKS: "0" },
  });
  return r.status === 0 && typeof r.stdout === "string" ? r.stdout : null;
}

/** Two paths name one directory (symlinks resolved). */
function sameDir(a, b) {
  const real = (p) => { try { return realpathSync(p); } catch { return resolve(p); } };
  return real(a) === real(b);
}

/**
 * What git says about the work tree at `dir`, or null when it is not one,
 * or when `dir` merely sits inside another repository (an exported tree
 * under a home kept in git must not take that repository's HEAD).
 * `git` is injectable (tests): (dir, args) => stdout | null.
 */
export function gitFacts(dir, git = realGit, same = sameDir) {
  const [top = "", sha = ""] = (git(dir, ["rev-parse", "--show-toplevel", "HEAD"]) ?? "").split("\n");
  const head = commitOrNull(sha);
  if (head === null || top === "" || !same(top, dir)) return null;
  const status = git(dir, ["status", "--porcelain", "--untracked-files=no"]);
  const dirty = status === null ? null : status.trim() !== "";
  const log = git(dir, ["log", "--first-parent", "-n", String(SNAPSHOT_WALK),
    `--format=%H%x1f%(trailers:key=${SNAPSHOT_TRAILER},valueonly,separator=%x2c)%x1e`, "HEAD"]) ?? "";
  const recs = log.split("\x1e").map((r) => r.replace(/^\n/, "")).filter((r) => r.includes("\x1f"));
  for (let i = 0; i < recs.length; i++) {
    const [, trailer = ""] = recs[i].split("\x1f");
    const source = commitOrNull(trailer.split(",")[0] ?? "");
    if (source !== null) return { repo: "public", sourceCommit: source, publicCommit: head, publicAhead: i, dirty };
  }
  return { repo: "source", sourceCommit: head, publicCommit: null, publicAhead: 0, dirty };
}

/**
 * The build info for a build of the tree at `repoRoot` (version from
 * launcher/package.json there). Pure but for the injected reads.
 */
export function resolveBuildInfo({ repoRoot, env = process.env, git = realGit, readFile = (p) => readFileSync(p, "utf8") }) {
  let version = null;
  try {
    const v = JSON.parse(readFile(join(repoRoot, "launcher", "package.json"))).version;
    version = typeof v === "string" ? v : null;
  } catch { /* no version: null */ }
  const facts = gitFacts(repoRoot, git);
  const envSource = commitOrNull(env.MANDU_BUILD_SOURCE_COMMIT);
  const envPublic = commitOrNull(env.MANDU_BUILD_PUBLIC_COMMIT);
  return {
    version,
    sourceCommit: envSource ?? facts?.sourceCommit ?? null,
    publicCommit: envPublic ?? facts?.publicCommit ?? null,
    // Commits after the snapshot mean nothing beside a commit the release named.
    publicAhead: envPublic !== null ? 0 : (facts?.publicAhead ?? 0),
    dirty: facts?.dirty ?? null,
  };
}

/** Write `<distDir>/build-info.json` (through a rename). */
export function writeBuildInfo(distDir, info) {
  const path = join(distDir, BUILD_INFO_NAME);
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(info, null, 2) + "\n");
  renameSync(tmp, path);
}

/** Read `<distDir>/build-info.json`, or null when it is absent or not one
 *  (a package built before the record existed). Fields are re-checked: the
 *  file is data, and a commit reaches a git argv later. */
export function readBuildInfo(distDir, readFile = (p) => readFileSync(p, "utf8")) {
  let raw;
  try {
    raw = JSON.parse(readFile(join(distDir, BUILD_INFO_NAME)));
  } catch {
    return null;
  }
  if (raw === null || typeof raw !== "object") return null;
  const ahead = Number.isInteger(raw.publicAhead) && raw.publicAhead >= 0 ? raw.publicAhead : 0;
  return {
    version: typeof raw.version === "string" ? raw.version : null,
    sourceCommit: commitOrNull(raw.sourceCommit),
    publicCommit: commitOrNull(raw.publicCommit),
    publicAhead: ahead,
    dirty: typeof raw.dirty === "boolean" ? raw.dirty : null,
  };
}

// CLI: node build-info.mjs [<repoRoot>] — print what a build here would record.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = resolve(process.argv[2] ?? join(fileURLToPath(import.meta.url), "..", "..", ".."));
  process.stdout.write(JSON.stringify(resolveBuildInfo({ repoRoot: root }), null, 2) + "\n");
}
