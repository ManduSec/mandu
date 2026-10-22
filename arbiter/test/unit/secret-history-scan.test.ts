/**
 * secret-history-scan.test — the git-history secret scan
 * (docs/design/confidentiality/secret-discovery.md §3): the limits, the git output parsers,
 * the walk over REAL temporary repositories (a key
 * committed then deleted, a staged-only key, a stashed key, a deleted `.env`
 * found by name), the caps, the hardening against a repository-configured
 * program, and the server op (axis OFF answers empty, one scan at a time).
 * The detector per format, the placeholder filter and the masks (never a
 * character of a value's body) moved with the code to
 * secret-detectors.test.ts (plan 14 §13.2).
 *
 * Fixture keys are assembled at run time, so this file itself holds no
 * credential-shaped literal for a scanner (this one included) to report.
 *
 * docs-lane-exempt: the git calls (ls-files among them) run in temporary
 * fixture repositories, never over this repository's tracked docs.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  defaultBlobReader,
  historyLimitsFromEnv,
  isBinaryBlob,
  parseBatchCheck,
  parseBatchOutput,
  parseFindObjectLog,
  parseIndexOrTree,
  parseRevListObjects,
  scanSecretHistory,
  unquoteGitPath,
  DEFAULT_HISTORY_LIMITS,
  type HistoryGitRunner,
  type PathClassifier,
} from "../../policy/secret-history-scan.js";
import { ArbiterServer } from "../../ipc/server.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

// ── fixture values (assembled, never literal) ────────────────────────────────
const rep = (s: string, n: number): string => s.repeat(n);
const BODY = "Q7wX2mZ9pL4kV8rT";
const K = {
  anthropic: "sk-" + "ant-" + "api03-" + BODY + BODY,
  openai: "sk-" + "proj-" + BODY + BODY,
  github: "gh" + "p_" + rep("A1b2C3d4", 5),
  githubPat: "github" + "_pat_" + rep("11ABCDEFG0", 7),
  gitlab: "gl" + "pat-" + BODY + "x9" + BODY,
  slack: "xo" + "xb-" + "1234567890-" + BODY,
  stripe: "sk" + "_live_" + BODY + BODY,
  google: "AI" + "za" + BODY + BODY + "abc",
  npm: "np" + "m_" + rep("aB3dE5fG7h", 4).slice(0, 36),
  pypi: "py" + "pi-AgE" + rep(BODY, 4),
  hf: "h" + "f_" + BODY + BODY + "zz",
  awsId: "AK" + "IA" + "Q7WX2MZ9PL4KV8RT",
  awsSecret: rep("Q7wX2mZ9/pL4kV8rT+", 3).slice(0, 40),
  dbPass: "Zr8" + "!kq2Vw9pLx4",
  urlPass: "s3cr" + "etPw9Xq",
  pemBody: rep("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ", 2),
};
const PEM = `-----BEGIN OPENSSH PRIVATE KEY-----\n${K.pemBody}\n${K.pemBody.slice(0, 40)}\n-----END OPENSSH PRIVATE KEY-----\n`;

/** Every fixture value's body (past its public prefix), for the no-leak checks. */
const BODIES = [BODY, K.awsId.slice(4), K.awsSecret.slice(4), K.dbPass, K.urlPass, K.pemBody.slice(0, 20), K.githubPat.slice(11, 30), K.npm.slice(4)];

function assertNoValue(text: string, what: string): void {
  for (const b of BODIES) assert.ok(!text.includes(b), `${what} carries a value body (${b.slice(0, 3)}…)`);
}

// The detector tests live in secret-detectors.test.ts (plan 14 §13.2).

test("limits from the environment", () => {
  assert.deepEqual(historyLimitsFromEnv({}), DEFAULT_HISTORY_LIMITS);
  const l = historyLimitsFromEnv({ MANDU_HISTORY_SCAN_BLOB_MAX_KB: "64", MANDU_HISTORY_SCAN_MAX_MB: "2", MANDU_HISTORY_SCAN_TIMEOUT_S: "5", });
  assert.equal(l.blobMaxBytes, 64 * 1024);
  assert.equal(l.totalMaxBytes, 2 * 1024 * 1024);
  assert.equal(l.timeoutMs, 5000);
  assert.equal(historyLimitsFromEnv({ MANDU_HISTORY_SCAN_MAX_MB: "nope" }).totalMaxBytes, DEFAULT_HISTORY_LIMITS.totalMaxBytes);
});

// ── the parsers ──────────────────────────────────────────────────────────────

const A = "a".repeat(40);
const B = "b".repeat(40);
const C = "c".repeat(40);

test("parsers: rev-list objects, batch-check, ls-files / ls-tree, batch output, find-object log, quoting", () => {
  const rl = parseRevListObjects(`${A}\n${B} dir/file name.txt\n${C} \nnot-an-oid x\n${B} other\n`);
  assert.equal(rl.get(A), null);
  assert.equal(rl.get(B), "dir/file name.txt", "the first path wins; spaces kept");
  assert.equal(rl.get(C), null);
  assert.equal(rl.size, 3);

  const bc = parseBatchCheck(`${A} blob 12\n${B} tree 40\n${C} missing\n`);
  assert.deepEqual(bc.get(A), { type: "blob", size: 12 });
  assert.equal(bc.get(B)?.type, "tree");
  assert.equal(bc.has(C), false);

  const lf = parseIndexOrTree(`100644 ${A} 0\t.env\u0000100644 ${A} 0\tcopy.env\u0000160000 ${B} 0\tsub\u0000`);
  assert.deepEqual(lf.get(A), [".env", "copy.env"]);
  assert.equal(lf.has(B), false, "a gitlink is not a blob");
  const lt = parseIndexOrTree(`100644 blob ${C}\tsrc/a b.ts\u0000160000 commit ${B}\tsub\u0000`);
  assert.deepEqual(lt.get(C), ["src/a b.ts"]);
  assert.equal(lt.has(B), false);

  const buf = Buffer.concat([
    Buffer.from(`${A} blob 5\nhello\n${B} missing\n${C} blob 3\n`), Buffer.from([0x00, 0x01, 0x02]), Buffer.from("\n"),
    Buffer.from(`${A} blob 99\ntorn`),
  ]);
  const objs = parseBatchOutput(buf);
  assert.deepEqual(objs.map((o) => [o.oid, o.content.length]), [[A, 5], [C, 3]], "a missing object skipped, a torn tail dropped");
  assert.ok(isBinaryBlob(objs[1]!.content));
  assert.ok(!isBinaryBlob(objs[0]!.content));

  const log = `commit ${C}\n\n:100644 000000 ${A} ${"0".repeat(40)} D\tkeys/deploy\ncommit ${B}\n\n:000000 100644 ${"0".repeat(40)} ${A} A\tkeys/deploy\n:000000 100644 ${"0".repeat(40)} ${B} A\tother\ncommit ${B}\n`;
  const f = parseFindObjectLog(log, A);
  assert.deepEqual(f.commits, [C, B], "newest first, unique (a merge seen per parent once)");
  assert.deepEqual(f.paths, ["keys/deploy"]);
  assert.equal(unquoteGitPath('"a\\tb\\303\\251"'), "a\tbé");
  assert.equal(unquoteGitPath("plain"), "plain");
});

// ── real repositories ────────────────────────────────────────────────────────

const GIT_ENV = { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };

function repo(): { root: string; git: (...a: string[]) => string; put: (rel: string, body: string | Buffer) => void; done: () => void } {
  // realpath: git answers canonical paths, and macOS /tmp is a link.
  const base = realpathSync(mkdtempSync(join(tmpdir(), "mdu-hist-")));
  const root = join(base, "repo");
  mkdirSync(root);
  const env = { ...GIT_ENV, HOME: base };
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: root, env, encoding: "utf8" });
  git("init", "-q", "-b", "main");
  const put = (rel: string, body: string | Buffer): void => {
    mkdirSync(join(root, rel, ".."), { recursive: true });
    writeFileSync(join(root, rel), body);
  };
  return { root, git, put, done: () => rmSync(base, { recursive: true, force: true }) };
}

/** The catalog, as the arbiter would answer for these fixtures. */
const classify: PathClassifier = (paths) => paths.map((p) =>
  /\/\.env$/.test(p) ? { level: "no-model", rule: "catalog:dotenv" }
  : /\/protected\.txt$/.test(p) ? { level: "no-model", rule: `label:${p}` }
  : { level: "public", rule: null });

test("walk: a key committed and then deleted is found in history, traced to its commits, masked", async () => {
  const r = repo();
  try {
    r.put("README.md", "hello\n");
    r.git("add", "."); r.git("commit", "-qm", "init");
    r.put("deploy/id_ed25519", PEM);
    r.git("add", "."); r.git("commit", "-qm", "add deploy key");
    const added = r.git("rev-parse", "HEAD").trim();
    r.git("rm", "-q", "deploy/id_ed25519"); r.git("commit", "-qm", "oops, remove it");
    const removed = r.git("rev-parse", "HEAD").trim();
    const blob = r.git("rev-parse", `${added}:deploy/id_ed25519`).trim();

    const scan = await scanSecretHistory([r.root], { classifyPaths: classify });
    assert.deepEqual(scan.repos, [{ root: r.root, repoRoot: r.root }]);
    assert.equal(scan.findings.length, 1);
    const f = scan.findings[0]!;
    assert.equal(f.repoRoot, r.root);
    assert.equal(f.blob, blob);
    assert.deepEqual(f.paths, ["deploy/id_ed25519"]);
    assert.equal(f.firstCommit, added);
    assert.equal(f.lastCommit, removed);
    assert.equal(f.inHead, false);
    assert.equal(f.inIndex, false);
    assert.equal(f.stillPresent, false);
    assert.equal(f.pathStillSecretByCatalog, false, "only in history: nothing covers it");
    assert.deepEqual(f.detector, { kind: "content-shape", rule: "private-key", line: 1, preview: "-----BEGIN OPENSSH PRIVATE KEY-----…" });
    assert.equal(scan.counts.blobs, 2);
    assert.equal(scan.counts.scanned, 2);
    assert.equal(scan.capped.lines.length, 0, scan.capped.lines.join("; "));
    assertNoValue(JSON.stringify(scan), "the scan");
  } finally { r.done(); }
});

test("walk (2026-10-21): a shallow file written over a full history hides no key from the scan; a real shallow clone's boundary is honoured", async () => {
  const r = repo();
  try {
    r.put("README.md", "hello\n");
    r.git("add", "."); r.git("commit", "-qm", "init");
    r.put("deploy/id_ed25519", PEM);
    r.git("add", "."); r.git("commit", "-qm", "add deploy key");
    r.git("rm", "-q", "deploy/id_ed25519"); r.git("commit", "-qm", "oops, remove it");
    r.git("reflog", "expire", "--expire=now", "--all");
    // The forged boundary: the last commit, whose parent is in the store.
    writeFileSync(join(r.root, ".git", "shallow"), `${r.git("rev-parse", "HEAD").trim()}\n`);
    assert.equal(r.git("log", "--format=%s").trim(), "oops, remove it", "git log stops at it");
    const scan = await scanSecretHistory([r.root], { classifyPaths: classify });
    assert.equal(scan.findings.length, 1, "the key in the history behind it is found");
    assert.equal(scan.capped.lines.length, 0, scan.capped.lines.join("; "));
    // A real shallow clone: its boundary is true, the scan runs within it.
    rmSync(join(r.root, ".git", "shallow"));
    const clone = join(r.root, "..", "clone");
    execFileSync("git", ["clone", "-q", "--depth", "1", `file://${r.root}`, clone], { encoding: "utf8" });
    const shallow = await scanSecretHistory([clone], { classifyPaths: classify });
    assert.equal(shallow.capped.unlisted, false, shallow.capped.lines.join("; "));
    assert.equal(shallow.findings.length, 0, "the key is past its boundary: not in this store");
  } finally { r.done(); }
});

test("walk: a history-only key is covered once a human label holds its gone path, or its blob is locked (plan 14 §8.1, §8.2)", async () => {
  const r = repo();
  try {
    r.put("README.md", "hello\n");
    r.git("add", "."); r.git("commit", "-qm", "init");
    r.put("deploy/id_ed25519", PEM);
    r.git("add", "."); r.git("commit", "-qm", "add deploy key");
    const blob = r.git("rev-parse", "HEAD:deploy/id_ed25519").trim();
    r.git("rm", "-q", "deploy/id_ed25519"); r.git("commit", "-qm", "remove it");
    const asked: string[][] = [];
    const scan = async (o: { label?: boolean; locked?: string[] }) => (await scanSecretHistory([r.root], {
      classifyPaths: classify,
      labelledAbovePublic: (ps) => { asked.push(ps); return ps.map(() => o.label === true); },
      ...(o.locked ? { lockedBlobs: new Set(o.locked) } : {}),
    })).findings[0]!;
    assert.equal((await scan({})).pathStillSecretByCatalog, false, "nothing covers it");
    assert.deepEqual(asked.at(-1), [join(r.root, "deploy/id_ed25519")], "the gone path is asked, absolute");
    assert.equal((await scan({ label: true })).pathStillSecretByCatalog, true, "a label on the gone path covers it");
    assert.equal((await scan({ locked: [`sha1:${blob}`] })).pathStillSecretByCatalog, true, "a blob lock covers it");
    assert.equal((await scan({ locked: [`sha256:${blob}`] })).pathStillSecretByCatalog, false, "only the repository's own object format applies");
  } finally { r.done(); }
});

test("walk: the index, the stash, a deleted .env by name, a covered file, a live file, binary and oversized blobs", async () => {
  const r = repo();
  try {
    r.put("app.py", "print('hi')\n");
    r.put(".env", "MODE=dev\n");                         // catalog by name; content harmless
    r.put("protected.txt", `token=${K.github}\n`);       // labelled now: covered
    r.put("config.py", `STRIPE = "${K.stripe}"\n`);      // exists now, unprotected
    r.put("blob.bin", Buffer.concat([Buffer.from(`${K.anthropic}\n`), Buffer.from([0, 1, 2])]));
    r.put("big.txt", `${K.gitlab}\n` + "x".repeat(4096));
    r.git("add", "."); r.git("commit", "-qm", "init");
    r.git("rm", "-q", ".env"); r.git("commit", "-qm", "drop env");
    // A stashed key (in refs/stash only).
    r.put("app.py", `print('hi')\nKEY = "${K.openai}"\n`);
    r.git("stash", "-q");
    // A staged-only key (in the index only).
    r.put("staged.txt", `slack ${K.slack}\n`);
    r.git("add", "staged.txt");

    const scan = await scanSecretHistory([r.root, join(r.root, "..")], { classifyPaths: classify, limits: { blobMaxBytes: 1024 } });
    assert.equal(scan.repos[1]!.repoRoot, null, "a root in no work tree is named, not an error");
    assert.equal(scan.repos[1]!.reason, "not in a git work tree");
    const byPath = (p: string) => scan.findings.find((f) => f.paths.includes(p));

    const env = byPath(".env")!;
    assert.deepEqual(env.detector, { kind: "catalog-path", rule: "catalog:dotenv", path: ".env", level: "no-model" });
    assert.equal(env.stillPresent, false);

    const prot = byPath("protected.txt")!;
    assert.equal(prot.pathStillSecretByCatalog, true, "a file protected now covers its own history");
    assert.equal(prot.inHead, true);

    const cfg = byPath("config.py")!;
    assert.equal(cfg.stillPresent, true);
    assert.equal(cfg.pathStillSecretByCatalog, false);
    assert.equal(cfg.detector.kind === "content-shape" && cfg.detector.rule, "stripe-key");

    const stash = scan.findings.find((f) => f.detectors.some((d) => d.kind === "content-shape" && d.rule === "openai-key"))!;
    assert.ok(stash, "the stashed key is reachable through refs/stash");
    assert.deepEqual(stash.paths, ["app.py"]);
    assert.equal(stash.inHead, false);

    const staged = byPath("staged.txt")!;
    assert.equal(staged.inIndex, true);
    assert.equal(staged.firstCommit, null, "in no commit");

    assert.equal(byPath("blob.bin"), undefined, "a binary blob is skipped");
    assert.equal(byPath("big.txt"), undefined, "an oversized blob is not read");
    assert.equal(scan.capped.binary, 1);
    assert.equal(scan.capped.tooBig, 1);
    assert.ok(scan.capped.lines.some((l) => /^1 blob\(s\) over .* not read \(MANDU_HISTORY_SCAN_BLOB_MAX_KB\)$/.test(l)));
    assert.equal(scan.capped.untraced, 0);
    assert.equal(scan.findings[0]!.stillPresent, false, "history-only findings come first");
    assertNoValue(JSON.stringify(scan), "the scan");
  } finally { r.done(); }
});

test("walk: the total cap reads history-only blobs first and says what it left", async () => {
  const r = repo();
  try {
    r.put("live.txt", `a ${K.github}\n` + "y".repeat(200));
    r.put("gone.txt", `b ${K.gitlab}\n` + "z".repeat(200));
    r.git("add", "."); r.git("commit", "-qm", "init");
    r.git("rm", "-q", "gone.txt"); r.git("commit", "-qm", "rm");
    const scan = await scanSecretHistory([r.root], { limits: { totalMaxBytes: 300 } });
    assert.deepEqual(scan.findings.map((f) => f.paths[0]), ["gone.txt"], "the history-only blob was read first");
    assert.equal(scan.capped.overTotal, 1);
    assert.ok(scan.capped.lines.some((l) => /1 blob\(s\) not read: over the/.test(l)));
  } finally { r.done(); }
});

test("walk: a history that cannot be listed scans nothing and says why; tracing stops at its cap", async () => {
  const failing: HistoryGitRunner = async (args) =>
    args[0] === "rev-parse" ? { code: 0, stdout: "/r\n", stderr: "" } : { code: 128, stdout: "", stderr: "fatal: bad object" };
  const s1 = await scanSecretHistory(["/r"], { git: failing });
  assert.equal(s1.capped.unlisted, true);
  assert.match(s1.capped.lines[0]!, /\/r: the history could not be listed \(fatal: bad object\); nothing was scanned/);
  assert.equal(s1.findings.length, 0);

  const r = repo();
  try {
    r.put("a.txt", `x ${K.github}\n`);
    r.put("b.txt", `y ${K.gitlab}\n`);
    r.git("add", "."); r.git("commit", "-qm", "init");
    r.git("rm", "-q", "a.txt", "b.txt"); r.git("commit", "-qm", "rm");
    const s2 = await scanSecretHistory([r.root], { limits: { traceMax: 1 } });
    assert.equal(s2.findings.length, 2);
    assert.equal(s2.findings.filter((f) => f.firstCommit !== null).length, 1);
    assert.equal(s2.capped.untraced, 1);
    assert.ok(s2.capped.lines.some((l) => /1 finding\(s\) not traced/.test(l)));
  } finally { r.done(); }
});

test("walk: the deadline stops reading and says so", async () => {
  const r = repo();
  try {
    r.put("a.txt", `x ${K.github}\n`);
    r.git("add", "."); r.git("commit", "-qm", "init");
    let t = 0;
    // Each clock read advances 10 s: the 20 s budget is gone before the blobs are read.
    const scan = await scanSecretHistory([r.root], { now: () => (t += 10_000), limits: { timeoutMs: 20_000 } });
    assert.equal(scan.counts.scanned, 0);
    assert.ok(scan.capped.overTime > 0 || scan.capped.unlisted, JSON.stringify(scan.capped));
    assert.equal(scan.capped.readFailed, 0, "the deadline is not a failed read");
    assert.ok(scan.capped.lines.some((l) => /time budget/.test(l)), scan.capped.lines.join("; "));
  } finally { r.done(); }
});

test("walk: a blob read git fails before the deadline is readFailed, named, never the time budget", async () => {
  const r = repo();
  try {
    r.put("a.txt", `x ${K.github}\n`);
    r.put("b.txt", `y ${K.gitlab}\n`);
    r.git("add", "."); r.git("commit", "-qm", "init");
    r.git("rm", "-q", "a.txt", "b.txt"); r.git("commit", "-qm", "rm");
    const ok = await scanSecretHistory([r.root]);
    assert.equal(ok.findings.length, 2, "the fixture is found when git reads it");

    // git hands back nothing at all (a git sandbox that did not come up,
    // before the reader threw on a failed exit): both blobs are readFailed.
    const empty = await scanSecretHistory([r.root], { readBlobs: async () => Buffer.alloc(0) });
    assert.equal(empty.findings.length, 0);
    assert.equal(empty.capped.readFailed, 2, JSON.stringify(empty.capped));
    assert.equal(empty.capped.overTime, 0, "not the time budget");
    assert.ok(empty.capped.lines.some((l) => /2 of 2 blob\(s\) asked of git did not come back/.test(l)), empty.capped.lines.join("; "));
    assert.ok(empty.capped.lines.some((l) => /^2 blob\(s\) not read: git failed to hand them over$/.test(l)), empty.capped.lines.join("; "));
    assert.ok(!empty.capped.lines.some((l) => /time budget/.test(l)), empty.capped.lines.join("; "));

    // One of two comes back: the other is readFailed, the one read is matched.
    const half = await scanSecretHistory([r.root], {
      readBlobs: async (root, oids, o) => {
        const full = await defaultBlobReader(root, oids, o);
        const objs = parseBatchOutput(full);
        const first = objs[0]!;
        return Buffer.concat([Buffer.from(`${first.oid} blob ${first.content.length}\n`), first.content, Buffer.from("\n")]);
      },
    });
    assert.equal(half.findings.length, 1);
    assert.equal(half.capped.readFailed, 1);
    assert.equal(half.capped.overTime, 0);

    // The reader throws (git exited non-zero): its message is kept.
    const threw = await scanSecretHistory([r.root], { readBlobs: async () => { throw new Error("git cat-file failed: bwrap: no permission"); } });
    assert.equal(threw.capped.readFailed, 2);
    assert.equal(threw.capped.overTime, 0);
    assert.ok(threw.capped.lines.some((l) => /blob contents could not be read \(git cat-file failed: bwrap: no permission\)/.test(l)), threw.capped.lines.join("; "));

    // A reader stopped at the deadline (the clock past it when it returns)
    // stays the time budget.
    let t = 0;
    let past = false;
    const stopped = await scanSecretHistory([r.root], {
      now: () => (past ? 100_000 : ++t),
      limits: { timeoutMs: 60_000 },
      readBlobs: async () => { past = true; return Buffer.alloc(0); },
    });
    assert.equal(stopped.capped.overTime, 2, JSON.stringify(stopped.capped));
    assert.equal(stopped.capped.readFailed, 0);
  } finally { r.done(); }
});

test("defaultBlobReader: a git that fails on its own throws with git's last line; a good call returns the batch", async () => {
  const notRepo = mkdtempSync(join(tmpdir(), "mdu-hist-norepo-"));
  try {
    // git's own words vary (in the sandbox: "Stopping at filesystem boundary").
    await assert.rejects(defaultBlobReader(notRepo, ["0".repeat(40)], { timeoutMs: 30_000 }), /^Error: git cat-file failed: \S/);
  } finally { rmSync(notRepo, { recursive: true, force: true }); }
  const r = repo();
  try {
    r.put("a.txt", "hello\n");
    r.git("add", "."); r.git("commit", "-qm", "init");
    const oid = r.git("rev-parse", "HEAD:a.txt").trim();
    const objs = parseBatchOutput(await defaultBlobReader(r.root, [oid], { timeoutMs: 30_000 }));
    assert.deepEqual(objs.map((o) => [o.oid, o.type, o.content.toString()]), [[oid, "blob", "hello\n"]]);
  } finally { r.done(); }
});

test("hardening: a repository-configured fsmonitor program is never started", async () => {
  const r = repo();
  try {
    r.put("a.txt", "hello\n");
    r.git("add", "."); r.git("commit", "-qm", "init");
    const marker = join(r.root, "..", "fsmonitor-ran");
    const hook = join(r.root, "..", "hook.sh");
    writeFileSync(hook, `#!/bin/sh\ntouch '${marker}'\n`);
    chmodSync(hook, 0o755);
    r.git("config", "core.fsmonitor", hook);
    await scanSecretHistory([r.root]);
    assert.equal(existsSync(marker), false, "the arbiter must not run a program the repository names");
  } finally { r.done(); }
});

test("hardening: a repository's signature verifier (log.showSignature + gpg.program) is never started by the trace walk", async () => {
  const r = repo();
  try {
    r.put("a.txt", `x ${K.github}\n`);
    r.git("add", "."); r.git("commit", "-qm", "init");
    r.put("b.txt", `y ${K.github}\n`);
    r.git("add", "."); r.git("commit", "-qm", "two");
    // A signed commit on top (a gpgsig header), so `git log` would ask the
    // verifier; the findings make the scan trace them with `git log`.
    const tree = r.git("write-tree").trim();
    const head = r.git("rev-parse", "HEAD").trim();
    const signed = execFileSync("git", ["hash-object", "-t", "commit", "-w", "--stdin"], {
      cwd: r.root, encoding: "utf8",
      input: `tree ${tree}\nparent ${head}\nauthor t <t@x> 1 +0000\ncommitter t <t@x> 1 +0000\ngpgsig -----BEGIN PGP ` + `SIGNATURE-----\n \n abc\n -----END PGP SIGNATURE-----\n\nsigned\n`,
    }).trim();
    r.git("update-ref", "HEAD", signed);
    const marker = join(r.root, "..", "verifier-ran");
    const hook = join(r.root, "..", "verifier.sh");
    writeFileSync(hook, `#!/bin/sh\ntouch '${marker}'\nexit 1\n`);
    chmodSync(hook, 0o755);
    r.git("config", "log.showSignature", "true");
    r.git("config", "gpg.program", hook);
    const scan = await scanSecretHistory([r.root]);
    assert.ok(scan.findings.length >= 2, "the findings are traced (the walk runs)");
    assert.equal(existsSync(marker), false, "the arbiter must not run a program the repository names");
  } finally { r.done(); }
});

// ── the server op ────────────────────────────────────────────────────────────

test("server: scanSecretHistoryOp answers empty with the axis OFF, refuses a second concurrent scan, rejects bad roots", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-hist-srv-"));
  const mk = (confidentiality: boolean, git?: HistoryGitRunner) => new ArbiterServer({
    socketPath: join(dir, `${confidentiality}.sock`), dbPath: join(dir, `${confidentiality}.sqlite`), eventDir: join(dir, `ev-${confidentiality}`),
    log: () => {}, confidentiality, integrity: false, policyPollMs: 0, policyDocument: null,
    ...(git ? { historyScan: { git } } : {}),
  });
  try {
    const off = mk(false);
    const r0 = await off.scanSecretHistoryOp({ id: 1, op: "scanSecretHistory", roots: [dir] });
    assert.equal(r0.ok, true);
    assert.deepEqual((r0 as { result: { axis: boolean; findings: unknown[] } }).result.axis, false);
    await off.close();

    let release: () => void = () => {};
    const gate = new Promise<void>((res) => { release = res; });
    const slow: HistoryGitRunner = async () => { await gate; return { code: 128, stdout: "", stderr: "no" }; };
    const on = mk(true, slow);
    const first = on.scanSecretHistoryOp({ id: 2, op: "scanSecretHistory", roots: [dir] });
    const second = await on.scanSecretHistoryOp({ id: 3, op: "scanSecretHistory", roots: [dir] });
    assert.equal(second.ok, false);
    assert.match((second as { error: string }).error, /already running/);
    release();
    assert.equal((await first).ok, true);
    const bad = await on.scanSecretHistoryOp({ id: 4, op: "scanSecretHistory", roots: "nope" as unknown as string[] });
    assert.equal(bad.ok, false);
    const sync = on.dispatch({ id: 5, op: "scanSecretHistory", roots: [dir] });
    assert.equal(sync.ok, false, "the synchronous dispatch names the async path");
    await on.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
