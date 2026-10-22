/**
 * Parity — plan 14 §11.1 R2: the arbiter's background lock resolution
 * (arbiter/policy/lock-resolution.ts) and the launcher's label walk
 * (launcher/src/git-object-twins.ts `labelledBlobsOf`) resolve the same
 * labels into the same blob ids and the same key, so the launcher may use
 * the arbiter's answer in place of its walk:
 *
 *   - the two copies of history-labels.ts (the precedence rule, the
 *     pathspecs, the walk's keys) are identical below their headers;
 *   - over a corpus of real repositories (SHA-1 and SHA-256; a key added,
 *     changed and deleted; a merge; a branch; a staged-only file; odd file
 *     names) and label sets (a gone literal, a folder with a public
 *     carve-out, patterns rooted and unrooted, a non-recursive folder, a
 *     label written through a symlink, a label above the repository, a
 *     label elsewhere), every repository's labelled versions AND its
 *     resolution key are equal on both sides;
 *   - the PRODUCTION wiring: the launcher's socket adapter
 *     (`socketSecretArbiter`) names its workspace to a real ArbiterServer,
 *     reads the resolved repository back, and the real object twins then
 *     skip the walk (an equal key) and produce the twins the walk does.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { LockResolver } from "../../arbiter/policy/lock-resolution.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { socketSecretArbiter, asGitHistoryLocks } from "../../launcher/src/secret-setup.js";
import {
  compileHistoryLabels, historyPathspecs, labelFilterKey, labelWalkKey, realSpellingOf, resolutionKey, withRealSpellings, type HistoryLabel,
} from "../../launcher/src/history-labels.js";
import { defaultGitRunner, historyStateOf, labelledBlobsOf, prepareGitObjectTwins } from "../../launcher/src/git-object-twins.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the confidentiality axis is what the locks serve

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...a: string[]): string => execFileSync("git", a, { cwd, encoding: "utf8", env: ENV });
const KEY = ["PARITY", "LOCK", "KEY", "z".repeat(28)].join("_");
const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});
const tmp = (): string => { const d = realpathSync(mkdtempSync(join(tmpdir(), "mdu-lockres-parity-"))); dirs.push(d); return d; };

test("the arbiter's history-labels.ts is the launcher's, below the header", () => {
  const body = (p: string): string => {
    const s = readFileSync(join(ROOT, p), "utf8");
    return s.slice(s.indexOf("\n */\n") + 5);
  };
  assert.equal(body("arbiter/policy/history-labels.ts"), body("launcher/src/history-labels.ts"),
    "arbiter/policy/history-labels.ts drifted from launcher/src/history-labels.ts; copy the launcher's body out again");
});

const put = (root: string, rel: string, body: string): void => {
  mkdirSync(join(root, rel, ".."), { recursive: true });
  writeFileSync(join(root, rel), body);
};

/** A repository with history worth resolving. */
function corpusRepo(parent: string, name: string, format: "sha1" | "sha256"): string {
  const root = join(parent, name);
  mkdirSync(root, { recursive: true });
  git(root, "init", "-q", "-b", "main", `--object-format=${format}`);
  put(root, "deploy/id_rsa", `${KEY}-1\n`);
  put(root, "cfg/a.env", "A=1\n");
  put(root, "cfg/sub/b.env", "B=1\n");
  put(root, "keys/x.pem", "pem-1\n");
  put(root, "keys/we ird name.pem", "odd\n");
  put(root, "docs/README", "readme\n");
  put(root, "docs/keys.txt", `${KEY}-docs\n`);
  put(root, "app.txt", "app\n");
  git(root, "add", "."); git(root, "commit", "-qm", "1");
  put(root, "deploy/id_rsa", `${KEY}-2\n`);
  git(root, "commit", "-qam", "2");
  git(root, "checkout", "-q", "-b", "side");
  put(root, "keys/side.pem", "side\n");
  put(root, "cfg/a.env", "A=side\n");
  git(root, "add", "."); git(root, "commit", "-qm", "side");
  git(root, "checkout", "-q", "main");
  put(root, "cfg/a.env", "A=main\n");
  git(root, "commit", "-qam", "main");
  git(root, "merge", "-q", "--no-edit", "-X", "ours", "side");
  git(root, "rm", "-q", "deploy/id_rsa"); git(root, "commit", "-qm", "gone");
  put(root, "deploy/staged.key", "staged-only\n");
  git(root, "add", "deploy/staged.key");
  return root;
}

test("resolution parity: the arbiter's resolver and the launcher's walk find the same versions and the same key, over a corpus of repositories and label sets", async () => {
  const d = tmp();
  const home = join(d, "home");
  const repos = [corpusRepo(home, "one", "sha1"), corpusRepo(join(home, "nest"), "two", "sha256")];
  symlinkSync(home, join(d, "via-link")); // a label written through a symlink
  const setsFor = (r: string): Array<[string, HistoryLabel[]]> => {
    const L = (path: string, level = "no-model", recursive = true, glob = false): HistoryLabel =>
      ({ path, level, recursive, ...(glob ? { glob: true as const } : {}) });
    const link = r.replace(home, join(d, "via-link"));
    return [
      ["a gone literal", [L(join(r, "deploy", "id_rsa"))]],
      ["a folder with a public carve-out", [L(join(r, "docs")), L(join(r, "docs", "README"), "public"), L(join(r, "deploy"), "local-model")]],
      ["an unrooted pattern", [L("**/*.pem", "no-model", true, true)]],
      ["a rooted pattern", [L(`${r}/cfg/**/*.env`, "any-model", true, true), L(`${r}/cfg/a.env`, "public")]],
      ["a non-recursive folder", [L(join(r, "keys"), "no-model", false), L(join(r, "keys", "x.pem"), "no-model", false)]],
      ["through a symlink", [L(join(link, "deploy")), L(`${link}/keys/*.pem`, "no-model", true, true)]],
      ["above the repository", [L(home), L(join(r, "app.txt"), "public")]],
      ["elsewhere", [L("/elsewhere/deploy/id_rsa")]],
      ["public only", [L(join(r, "deploy"), "public")]],
    ];
  };
  const realpath = (p: string): string | null => { try { return realpathSync(p); } catch { return null; } };
  let compared = 0;
  for (const r of repos) {
    for (const [what, wire] of setsFor(r)) {
      // The launcher, as prepareGitObjectTwins drives it.
      const labels = withRealSpellings(wire, (p) => realSpellingOf(p, realpath));
      const compiled = compileHistoryLabels(labels);
      const labelKey = labelWalkKey(labels, null);
      const launcher = await labelledBlobsOf(defaultGitRunner, r, compiled, labelKey);
      const specs = historyPathspecs(r, compiled);
      // The arbiter.
      const res = new LockResolver({ labels: () => wire, blobLocks: () => [], home: d });
      try {
        res.note([r], "launch");
        await res.runCycle(); await res.idle();
        const snap = res.snapshot([r]);
        assert.equal(snap.complete, true, `${what}: resolved`);
        const entry = snap.repos.find((x) => x.root === r);
        if (specs !== null && specs.length === 0) {
          assert.equal(entry, undefined, `${what}: no label reaches ${r}`);
          assert.deepEqual(launcher, [], `${what}: the launcher walks nothing either`);
          continue;
        }
        assert.ok(entry !== undefined, `${what}: ${r} listed`);
        assert.deepEqual(entry.blobs, launcher, `${what} in ${r}: the same versions`);
        const state = await historyStateOf(defaultGitRunner, r);
        assert.equal(entry.key, resolutionKey(r, labelFilterKey(labelKey, specs), state.base, state.tips), `${what} in ${r}: the same key`);
        compared++;
      } finally { await res.stop(); }
    }
  }
  assert.ok(compared >= 12, `enough non-trivial cases compared (${compared})`);
});

test("production wiring: the launcher names its workspace, reads the resolution back, and its object twins skip the walk with the same result", async () => {
  const d = tmp();
  const ws = corpusRepo(join(d, "home"), "ws", "sha1");
  const sock = join(d, "a.sock");
  const doc = { version: 1, paths: [{ path: join(ws, "deploy", "id_rsa"), level: "no-model" }] };
  const s = new ArbiterServer({
    socketPath: sock, dbPath: join(d, "db.sqlite"), eventDir: join(d, "events"), log: () => {}, confidentiality: true, integrity: false,
    policyPollMs: 0, policyDocument: doc as never, lockResolution: { home: join(d, "home"), selfDir: null },
  });
  await s.listen();
  try {
    const adapter = socketSecretArbiter(sock);
    const first = asGitHistoryLocks(await adapter.gitHistoryLocks!([ws]));
    assert.equal(first.repos?.some((x) => x.root === ws), false, "just registered: not resolved yet");
    await s.resolveLocksNow();
    const locks = asGitHistoryLocks(await adapter.gitHistoryLocks!([ws]));
    const mine = locks.repos!.find((x) => x.root === ws)!;
    assert.equal(mine.blobs.length, 2, "both versions of the gone key");
    const deny = join(d, "denied");
    writeFileSync(deny, "");
    chmodSync(deny, 0o000);
    const opts = { cacheDir: join(d, "cache"), denyFile: deny, labels: locks.labels, repoHints: [ws] };
    const walked = await prepareGitObjectTwins([], opts);
    const stood = await prepareGitObjectTwins([], { ...opts, resolved: new Map(locks.repos!.map((x) => [x.root, { key: x.key, blobs: x.blobs }])) });
    assert.equal(stood.fromArbiter, 1, "the arbiter's resolution stood in for the walk");
    assert.deepEqual(stood.twins, walked.twins);
    assert.equal(stood.blobs, walked.blobs);
  } finally {
    await s.close();
  }
});

test("rewrites (security fix 2026-10-21): with a graft, a replace ref or a forged shallow file in the repository, and in a real shallow clone, the resolver and the launcher find the same versions and key, every committed version included", async () => {
  const d = tmp();
  const make = (name: string): { root: string; versions: string[]; head: string } => {
    const root = join(d, name);
    mkdirSync(root, { recursive: true });
    git(root, "init", "-q", "-b", "main");
    put(root, "README", "readme\n");
    for (const v of [1, 2, 3]) { put(root, "deploy/id_rsa", `${KEY}-${v}\n`); git(root, "add", "."); git(root, "commit", "-qm", `v${v}`); }
    git(root, "reflog", "expire", "--expire=now", "--all");
    git(root, "repack", "-adq");
    const versions = [1, 2, 3].map((v) => execFileSync("git", ["hash-object", "--stdin"], { cwd: root, input: `${KEY}-${v}\n`, encoding: "utf8" }).trim());
    return { root, versions, head: git(root, "rev-parse", "HEAD").trim() };
  };
  const graft = make("graft");
  mkdirSync(join(graft.root, ".git", "info"), { recursive: true });
  writeFileSync(join(graft.root, ".git", "info", "grafts"), `${graft.head}\n`);
  const replace = make("replace");
  const lone = execFileSync("git", ["commit-tree", `${replace.head}^{tree}`, "-m", "lone"], { cwd: replace.root, encoding: "utf8", env: ENV }).trim();
  git(replace.root, "replace", replace.head, lone);
  const shallow = make("shallow");
  writeFileSync(join(shallow.root, ".git", "shallow"), `${shallow.head}\n`);
  const source = make("source");
  const clone = join(d, "clone");
  git(d, "clone", "-q", "--depth", "2", `file://${source.root}`, clone);
  const cases: Array<[string, string, string[]]> = [
    ["a graft", graft.root, graft.versions],
    ["a replace ref", replace.root, replace.versions],
    ["a forged shallow file", shallow.root, shallow.versions],
    ["a real shallow clone (depth 2: its two versions)", clone, source.versions.slice(1)],
  ];
  for (const [what, root, want] of cases) {
    const wire: HistoryLabel[] = [{ path: join(root, "deploy", "id_rsa"), level: "no-model", recursive: true }];
    const compiled = compileHistoryLabels(wire);
    const labelKey = labelWalkKey(wire, null);
    const launcher = await labelledBlobsOf(defaultGitRunner, root, compiled, labelKey);
    for (const v of want) assert.ok(launcher.includes(v), `${what}: the launcher finds ${v.slice(0, 7)}`);
    const res = new LockResolver({ labels: () => wire, blobLocks: () => [], home: d });
    try {
      res.note([root], "launch");
      await res.runCycle(); await res.idle();
      const entry = res.snapshot([root]).repos.find((x) => x.root === root);
      assert.ok(entry !== undefined, `${what}: resolved`);
      assert.deepEqual(entry.blobs, launcher, `${what}: the same versions`);
      const state = await historyStateOf(defaultGitRunner, root);
      assert.equal(entry.key, resolutionKey(root, labelFilterKey(labelKey, historyPathspecs(root, compiled)), state.base, state.tips), `${what}: the same key`);
    } finally { await res.stop(); }
  }
});
