/**
 * The launch's history step and placeholder watch over one shared runner
 * (git-shared-answers.ts, secret-setup.ts; confidentiality.md §7.2a "The
 * same question once"), with REAL repositories and the production git
 * runner underneath a counting one:
 *
 *   - run as the launch runs them (at once), the two asked each work tree's
 *     `rev-list --all --no-walk` and the protected files' `ls-files -s -z`
 *     twice; shared, once; and every answer is the same: the same twins,
 *     the same locked ids (each protected version hidden), the same watch;
 *   - a failure reaches each caller as before: a failing `rev-list` or
 *     `ls-files` still refuses the step (GitObjectTwinError) and still costs
 *     the watch the tips or the repository, shared or not;
 *   - after the step the runner is closed: the check after the agent exits
 *     reads git afresh and finds a placeholder committed in the session.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  defaultGitRunner, GitObjectTwinError, prepareGitObjectTwins, type GitObjectTwinResult, type GitRunner,
} from "../../src/git-object-twins.js";
import { shareGitAnswers } from "../../src/git-shared-answers.js";
import { checkPlaceholderRepo, preparePlaceholderWatch, type TwinSource, type WatchedRepo } from "../../src/placeholder-commits.js";
import { stateAxes } from "../axes.js";
import { memorySeals } from "../lib/memory-seals.js";

stateAxes("secrets"); // the confidentiality axis is what the object twins and the watch serve

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...args: string[]): string => execFileSync("git", args, { cwd, encoding: "utf8", env: ENV });
/** A key-shaped canary assembled at run time (no key literal in the file). */
const key = (v: number): string => ["SHARED", "CANARY", String(v), "Qz".repeat(14)].join("_");
const blobOf = (cwd: string, text: string): string =>
  execFileSync("git", ["hash-object", "--stdin"], { cwd, input: text, encoding: "utf8", env: ENV }).trim();
const PLACEHOLDER = "TOKEN=$MDU:nomodel_File[0].TOKEN\n";

interface Fx { tmp: string; repos: string[]; secrets: string[]; opts: { cacheDir: string; denyFile: string; walkCacheDir: string }; done: () => void }

function fixture(): Fx {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-shared-git-"));
  const repos: string[] = [];
  const secrets: string[] = [];
  for (const name of ["a", "b"]) {
    const ws = join(tmp, name);
    git(tmp, "init", "-q", "-b", "main", ws);
    writeFileSync(join(ws, "README"), "readme\n");
    const secret = join(ws, ".env");
    writeFileSync(secret, `TOKEN=${key(1)}\n`);
    git(ws, "add", ".");
    git(ws, "commit", "-qm", "one");
    writeFileSync(secret, `TOKEN=${key(2)}\n`);
    git(ws, "commit", "-qam", "two");
    git(ws, "repack", "-adq");
    repos.push(ws);
    secrets.push(secret);
  }
  const denyFile = join(tmp, "denied");
  writeFileSync(denyFile, "");
  chmodSync(denyFile, 0o000);
  return {
    tmp, repos, secrets,
    opts: { cacheDir: join(tmp, "cache"), denyFile, walkCacheDir: join(tmp, "walks") },
    done: () => rmSync(tmp, { recursive: true, force: true }),
  };
}

/** A runner that counts each (work tree, arguments) and may fail some. */
function counting(base: GitRunner, failIf?: (args: readonly string[], cwd: string) => boolean): { run: GitRunner; count: (cwd: string, args: string) => number } {
  const n = new Map<string, number>();
  const run: GitRunner = (args, opts) => {
    const k = `${opts.cwd}\0${args.join(" ")}`;
    n.set(k, (n.get(k) ?? 0) + 1);
    if (failIf?.(args, opts.cwd)) return Promise.resolve({ code: 128, stdout: "", stderr: "fatal: a scripted failure" });
    return base(args, opts);
  };
  return { run, count: (cwd, args) => n.get(`${cwd}\0${args}`) ?? 0 };
}

const sources = (f: Fx): TwinSource[] => f.secrets.map((s) => ({ targetPath: s, content: PLACEHOLDER }));
const shape = (g: GitObjectTwinResult): string => JSON.stringify({
  twins: g.twins.map((x) => [x.kind, x.targetPath]).sort(), lockedIds: g.lockedIds, repos: g.repos, blobs: g.blobs,
});

/** The step and the watch at once, as secret-setup runs them. */
async function launchReads(f: Fx, git: GitRunner): Promise<{ step: GitObjectTwinResult; watch: WatchedRepo[] }> {
  const watch = preparePlaceholderWatch(sources(f), { git });
  const step = await prepareGitObjectTwins(f.secrets, { ...f.opts, seals: memorySeals(), git });
  return { step, watch: await watch };
}

test("shared, the step and the watch ask each work tree's tips and index once, and every answer is the same", async () => {
  const f = fixture();
  try {
    const apart = counting(defaultGitRunner);
    const before = await launchReads(f, apart.run);
    const one = counting(defaultGitRunner);
    const shared = shareGitAnswers(one.run);
    const after = await launchReads(f, shared.runner);
    shared.close();
    for (const r of f.repos) {
      assert.equal(apart.count(r, "rev-list --all --no-walk"), 2, `apart: the step and the watch each asked ${r}`);
      assert.equal(apart.count(r, "ls-files -s -z -- .env"), 2);
      assert.equal(one.count(r, "rev-list --all --no-walk"), 1, `shared: asked once in ${r}`);
      assert.equal(one.count(r, "ls-files -s -z -- .env"), 1);
    }
    assert.equal(shared.stats.shared, 4);
    assert.equal(shape(after.step), shape(before.step), "the same twins and locked ids");
    assert.deepEqual(after.watch, before.watch, "the same watch: ids, index entries, tips");
    // Every committed version is still hidden (locked) in each repository.
    for (const r of f.repos) {
      for (const v of [1, 2]) assert.ok(after.step.lockedIds!.includes(`sha1:${blobOf(r, `TOKEN=${key(v)}\n`)}`), `${r} version ${v} locked`);
    }
    assert.ok(after.step.twins.some((t) => t.kind === "object" && t.targetPath.startsWith(f.repos[0]!)), "a sanitized pack served");
  } finally {
    f.done();
  }
});

test("a failing tips or index call still refuses the step and still costs the watch what it did, shared or not", async () => {
  const f = fixture();
  try {
    const [a, b] = f.repos as [string, string];
    for (const [what, failIf] of [
      ["rev-list", (args: readonly string[], cwd: string) => cwd === a && args.join(" ") === "rev-list --all --no-walk"],
      ["ls-files", (args: readonly string[], cwd: string) => cwd === a && args[0] === "ls-files"],
    ] as const) {
      const outcomes: string[] = [];
      for (const mode of ["apart", "shared"] as const) {
        const c = counting(defaultGitRunner, failIf);
        const s = mode === "shared" ? shareGitAnswers(c.run) : null;
        const run = s?.runner ?? c.run;
        const watchP = preparePlaceholderWatch(sources(f), { git: run });
        const step = await prepareGitObjectTwins(f.secrets, { ...f.opts, seals: memorySeals(), git: run }).then(() => null, (e: unknown) => e);
        const watch = await watchP;
        s?.close();
        assert.ok(step instanceof GitObjectTwinError, `${what} ${mode}: the step refuses (${String(step)})`);
        const wa = watch.find((w) => w.root === a);
        // The watch's own rules: a failed tips call keeps the repository
        // without tips; a failed index call leaves it out.
        if (what === "rev-list") assert.equal(wa?.tips, null, `${what} ${mode}: no tips for ${a}`);
        else assert.equal(wa, undefined, `${what} ${mode}: ${a} is not watched`);
        assert.ok(watch.find((w) => w.root === b)?.tips !== null, `${what} ${mode}: ${b} is watched in full`);
        outcomes.push(JSON.stringify([(step as Error).message.replace(/ in \/.*$/, ""), watch]));
      }
      assert.equal(outcomes[0], outcomes[1], `${what}: the same failure, shared or not`);
    }
  } finally {
    f.done();
  }
});

test("a step refused on a failed index call has no read of that work tree still running (its history walk ended first)", async () => {
  const f = fixture();
  try {
    let pending = 0;
    const tracked: GitRunner = (args, opts) => {
      if (args[0] === "ls-files" && opts.cwd === f.repos[0]) return Promise.resolve({ code: 128, stdout: "", stderr: "fatal: a scripted failure" });
      pending++;
      return defaultGitRunner(args, opts).finally(() => { pending--; });
    };
    const step = await prepareGitObjectTwins([f.secrets[0]!], { ...f.opts, seals: memorySeals(), git: tracked }).then(() => null, (e: unknown) => e);
    assert.ok(step instanceof GitObjectTwinError, String(step));
    assert.equal(pending, 0, "no git call of the step outlives it");
    // Before, the walk went on after the refusal and wrote its cache entry
    // into a folder its caller had already removed (CI: a leftover under
    // TMPDIR, 2026-10-21).
    assert.ok(existsSync(f.opts.walkCacheDir), "the walk had ended (its entry written) when the step gave up");
  } finally {
    f.done();
  }
  await new Promise((r) => setTimeout(r, 300));
  assert.ok(!existsSync(f.tmp), "nothing recreates the fixture after it is removed");
});

test("after the step the shared runner is closed: the check after the agent exits reads git afresh", async () => {
  const f = fixture();
  try {
    const one = counting(defaultGitRunner);
    const shared = shareGitAnswers(one.run);
    const { watch } = await launchReads(f, shared.runner);
    shared.close();
    const repo = watch.find((w) => w.root === f.repos[0])!;
    // In the session, git commits the twin's bytes.
    writeFileSync(f.secrets[0]!, PLACEHOLDER);
    git(f.repos[0]!, "commit", "-qam", "the agent's commit");
    const c = await checkPlaceholderRepo(repo, { git: shared.runner });
    assert.equal(one.count(f.repos[0]!, "rev-list --all --no-walk"), 2, "the check asked again");
    assert.ok(c.finding !== null && c.finding.commits.length === 1, `the session's placeholder commit is found: ${JSON.stringify(c)}`);
  } finally {
    f.done();
  }
});
