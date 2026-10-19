/**
 * reflog-tips parity + e2e — the arbiter's history readers read the reflogs
 * from their files, as the launcher does (confidentiality.md §7.2a "Cost on
 * a relaunch", the arbiter's readers), and still see every commit a reflog
 * names:
 *
 *   - the two copies of reflog-tips.ts (launcher/src, arbiter/src) are
 *     byte-identical (the packages ship standalone);
 *   - over a fixture whose secrets only a reflog names (a commit reset away;
 *     a linked worktree's detached commit left behind), a REAL ArbiterServer
 *     answers the production ops: `scanSecretHistory` (ArbiterClient) finds
 *     both reflog-only secrets, masked, and `gitHistoryLocks` (the
 *     launcher's socket adapter) locks both reflog-only versions of the
 *     labelled path under the key the launcher computes itself, so the
 *     launcher's object twins take the arbiter's answer in place of their
 *     walk and twin the same versions;
 *   - the same with a doubt planted in the reflogs (a line that is not an
 *     entry): the arbiter falls back to git's own `--reflog`, as the
 *     launcher does, and the answers stay the same.
 *
 * The oracle (implementation-plan.md §9): no byte of a secret's value in
 * any reply. Axes stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { appendFileSync, chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { socketSecretArbiter, asGitHistoryLocks } from "../../launcher/src/secret-setup.js";
import { defaultGitRunner, historyStateOf, prepareGitObjectTwins, RepoReads } from "../../launcher/src/git-object-twins.js";
import { randomSecretBody } from "../../arbiter/test/helpers/random-secret.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the scan and the locks serve the confidentiality axis

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...a: string[]): string => execFileSync("git", a, { cwd, encoding: "utf8", env: ENV });
const blobOf = (cwd: string, body: string): string =>
  execFileSync("git", ["hash-object", "--stdin"], { cwd, input: body, encoding: "utf8", env: ENV }).trim();
const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

test("the two copies of reflog-tips.ts are byte-identical", () => {
  assert.equal(readFileSync(join(ROOT, "arbiter/src/reflog-tips.ts"), "utf8"), readFileSync(join(ROOT, "launcher/src/reflog-tips.ts"), "utf8"),
    "arbiter/src/reflog-tips.ts drifted from launcher/src/reflog-tips.ts; copy the launcher's file out again");
});

interface Fixture { d: string; home: string; ws: string; bodies: string[]; blobs: string[] }

/** A workspace whose two secrets only a reflog names. */
function fixture(): Fixture {
  const d = realpathSync(mkdtempSync(join(tmpdir(), "mdu-reflog-e2e-")));
  dirs.push(d);
  const home = join(d, "home");
  const ws = join(home, "ws");
  mkdirSync(join(ws, "deploy"), { recursive: true });
  git(home, "init", "-q", "-b", "main", ws);
  // Random, assembled at run time: no credential-shaped literal here.
  const bodies = [`${randomSecretBody(34)}a7`, `${randomSecretBody(34)}a7`];
  const values = bodies.map((b) => `TOKEN=${"gh" + "p_"}${b}\n`);
  writeFileSync(join(ws, "README"), "one\n");
  writeFileSync(join(ws, "deploy", "key"), "placeholder\n");
  git(ws, "add", "."); git(ws, "commit", "-qm", "c1");
  // Reset away: only HEAD's and main's reflogs name it.
  writeFileSync(join(ws, "deploy", "key"), values[0]!);
  git(ws, "commit", "-qam", "r1");
  git(ws, "reset", "-q", "--hard", "HEAD~1");
  // A linked worktree's detached commit left behind: only its own HEAD log.
  const wt = join(d, "wt");
  git(ws, "worktree", "add", "-q", "-b", "side", wt);
  git(wt, "checkout", "-q", "--detach");
  writeFileSync(join(wt, "deploy", "key"), values[1]!);
  git(wt, "commit", "-qam", "d1");
  git(wt, "checkout", "-q", "side");
  return { d, home, ws, bodies, blobs: values.map((v) => blobOf(ws, v)) };
}

for (const doubt of [false, true]) {
  test(`production ops over a real arbiter: the scan finds, the locks hold, both reflog-only secrets; the launcher takes the arbiter's key${doubt ? " (a doubt: git's own --reflog)" : ""}`, async () => {
    const f = fixture();
    if (doubt) appendFileSync(join(f.ws, ".git", "logs", "HEAD"), "not a reflog line\n");
    // git's own answer is what the readers must never fall below.
    const gitsTips = git(f.ws, "rev-list", "--all", "--reflog", "--no-walk").split("\n").filter(Boolean).sort();
    for (const b of f.blobs) assert.ok(git(f.ws, "rev-list", "--all", "--reflog", "--objects").includes(b), "the fixture: git's --reflog reaches it");
    for (const b of f.blobs) assert.ok(!git(f.ws, "rev-list", "--all", "--objects").includes(b), "the fixture: only a reflog reaches it");

    const sock = join(f.d, "a.sock");
    const doc = { version: 1, paths: [{ path: join(f.ws, "deploy", "key"), level: "no-model" }] };
    const s = new ArbiterServer({
      socketPath: sock, dbPath: join(f.d, "db.sqlite"), eventDir: join(f.d, "events"), log: () => {}, confidentiality: true, integrity: false,
      policyPollMs: 0, policyDocument: doc as never, lockResolution: { home: f.home, selfDir: null },
    });
    await s.listen();
    try {
      // ── the git-history secret scan (ArbiterClient, the production client) ──
      const client = new ArbiterClient(sock);
      const reply = await client.scanSecretHistory([f.ws], f.home);
      client.close();
      assert.equal(reply.axis, true);
      assert.equal(reply.capped.unlisted, false, reply.capped.lines.join("; "));
      const found = new Set(reply.findings.map((x) => x.blob));
      for (const b of f.blobs) assert.ok(found.has(b), `the scan found the reflog-only secret ${b}`);
      const wire = JSON.stringify(reply);
      for (const body of f.bodies) assert.ok(!wire.includes(body.slice(0, 12)), "no value in the scan's reply");

      // ── the lock resolution (the launcher's socket adapter) ──
      const adapter = socketSecretArbiter(sock);
      await adapter.gitHistoryLocks!([f.ws]);
      await s.resolveLocksNow();
      const locks = asGitHistoryLocks(await adapter.gitHistoryLocks!([f.ws]));
      const mine = locks.repos!.find((x) => x.root === f.ws)!;
      for (const b of f.blobs) assert.ok(mine.blobs.includes(b), `the reflog-only version ${b} is locked`);
      assert.ok(JSON.stringify(locks).length > 0 && !f.bodies.some((b) => JSON.stringify(locks).includes(b.slice(0, 12))));

      // The key is the launcher's: its tips (read the same way) are git's,
      // and its object twins take the arbiter's answer for the walk.
      const reads = new RepoReads(defaultGitRunner);
      const state = await historyStateOf(defaultGitRunner, f.ws, reads);
      assert.equal(reads.reflogFallbacks.size, doubt ? 1 : 0, "the launcher's own fallback agrees");
      assert.deepEqual(gitsTips.filter((t) => !state.tips.includes(t)), [], "never fewer tips than git's");
      const deny = join(f.d, "denied");
      writeFileSync(deny, "");
      chmodSync(deny, 0o000);
      const opts = { cacheDir: join(f.d, "cache"), denyFile: deny, labels: locks.labels, repoHints: [f.ws] };
      const walked = await prepareGitObjectTwins([], opts);
      const stood = await prepareGitObjectTwins([], { ...opts, resolved: new Map(locks.repos!.map((x) => [x.root, { key: x.key, blobs: x.blobs }])) });
      assert.equal(stood.fromArbiter, 1, "the arbiter's key is the launcher's: its answer stood in for the walk");
      assert.deepEqual(stood.twins, walked.twins);
      assert.equal(stood.blobs, walked.blobs);
    } finally {
      await s.close();
    }
  });
}
