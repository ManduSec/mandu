/**
 * lock-resolution e2e — confidentiality plan 14 §11.1 R1/R2 through the
 * REAL arbiter: an in-process ArbiterServer with its background schedule
 * (a HOME walk at start), the production `ArbiterClient` on the DATA socket
 * (what a launcher and the guard reach), and real repositories:
 *
 *   - repository A: a deploy key committed and then deleted (a gone path a
 *     human label holds) and a token once inline in `config.py` (a `blobs:`
 *     lock); repository B, unrelated; F, a clone ("fork") of A in another
 *     folder, which no label names;
 *   - the HOME walk finds all three; once resolved, the GLOBAL LOCKED SET
 *     holds A's deploy-key version and the locked blob, A is listed with its
 *     key, B holds nothing and F is covered by id (it holds the same blobs);
 *   - `gitHistoryLocks` `roots` registers a launch's workspace, listed once
 *     resolved even with nothing labelled in it;
 *   - `registerRepository` refuses a folder that is no repository, a relative
 *     path, a repository inside Mandu's own home, and past its cap;
 *   - axis OFF: every answer empty, nothing registered.
 *
 * The oracle (implementation-plan.md §9): the key's bytes, and every
 * 8-character run of either secret's body, appear in no reply and no line of
 * the arbiter's log (the resolver reads names and paths, never content).
 * Axes stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import type { GitHistoryLocksResult } from "../../ipc/protocol.js";
import { stateAxes } from "../axes.js";
import { randomSecretBody } from "../helpers/random-secret.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

// A letter and a digit, no placeholder run: a value the detectors take
// (a plain random draw has no digit 0.19% of the time; random-secret.ts).
const alnum = randomSecretBody;
const KEY_BODY = alnum(96);
const PEM = `-----BEGIN OPENSSH ` + `PRIVATE KEY-----\n${KEY_BODY}\n-----END OPENSSH PRIVATE KEY-----\n`;
const TOKEN_BODY = alnum(36);
const TOKEN = "gh" + "p_" + TOKEN_BODY;
const RUNS = [KEY_BODY, TOKEN_BODY].flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));

function noValue(what: string, s: string): void {
  assert.ok(!s.includes(PEM) && !s.includes(TOKEN), `${what} carries a secret`);
  const hit = RUNS.find((r) => s.includes(r));
  assert.equal(hit, undefined, `${what} carries an 8-character run of a secret's body`);
}

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

interface Fixture { dir: string; home: string; a: string; b: string; fork: string; plain: string; own: string; keyBlob: string; tokenBlob: string }

function fixture(): Fixture {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-lockres-e2e-")));
  dirs.push(dir);
  const home = join(dir, "home");
  const a = join(home, "work", "a");
  const b = join(home, "work", "b");
  mkdirSync(join(a, "deploy"), { recursive: true });
  mkdirSync(b, { recursive: true });
  git(a, "init", "-q", "-b", "main");
  writeFileSync(join(a, "README.md"), "# a\n");
  writeFileSync(join(a, "deploy", "id_rsa"), PEM);
  writeFileSync(join(a, "config.py"), `TOKEN = "${TOKEN}"\n`);
  git(a, "add", "."); git(a, "commit", "-qm", "init");
  git(a, "rm", "-q", "deploy/id_rsa");
  writeFileSync(join(a, "config.py"), "TOKEN = os.environ['TOKEN']\n");
  git(a, "add", "."); git(a, "commit", "-qm", "rotate");
  git(b, "init", "-q", "-b", "main");
  writeFileSync(join(b, "notes.txt"), "nothing here\n");
  git(b, "add", "."); git(b, "commit", "-qm", "b");
  const fork = join(home, "forks", "a-fork");
  mkdirSync(join(home, "forks"), { recursive: true });
  git(join(home, "forks"), "clone", "-q", "--no-local", a, fork);
  const plain = join(home, "plain");
  mkdirSync(plain, { recursive: true });
  // A repository inside Mandu's own home (the default `<home>/.mandu`): never
  // walked, never registered.
  const own = join(home, ".mandu", "state", "workspaces", "w1", "shadow");
  mkdirSync(own, { recursive: true });
  git(own, "init", "-q");
  return { dir, home, a, b, fork, plain, own, keyBlob: blobOf(a, PEM), tokenBlob: blobOf(a, `TOKEN = "${TOKEN}"\n`) };
}

async function server(f: Fixture, confidentiality: boolean, doc: unknown, logs: string[], dataPlaneCap?: number, walk = true) {
  const tag = `${confidentiality}-${dataPlaneCap ?? "d"}`;
  const sock = join(f.dir, `a-${tag}.sock`);
  const s = new ArbiterServer({
    socketPath: sock, dbPath: join(f.dir, `db-${tag}.sqlite`), eventDir: join(f.dir, `ev-${tag}`),
    log: (m) => logs.push(m), confidentiality, integrity: false, policyPollMs: 0, policyDocument: doc as never,
    lockResolution: {
      home: f.home, selfDir: null,
      ...(walk ? { schedule: { walkHome: true, startDelayMs: 0, cycleMs: 0, homeWalkMs: 0, labelPollMs: 0 } } : {}),
      ...(dataPlaneCap !== undefined ? { registryLimits: { dataPlane: dataPlaneCap } } : {}),
    },
  });
  await s.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  return { s, data };
}

async function until(data: ArbiterClient, ok: (r: GitHistoryLocksResult) => boolean, roots?: string[]): Promise<GitHistoryLocksResult> {
  const t0 = Date.now();
  for (;;) {
    const r = await data.gitHistoryLocks(roots);
    if (ok(r)) return r;
    if (Date.now() - t0 > 30_000) assert.fail(`not resolved in 30 s: ${JSON.stringify({ complete: r.complete, pending: r.pending, repos: r.repos.map((x) => x.root) })}`);
    await new Promise((res) => setTimeout(res, 50));
  }
}

test("R1/R2: the HOME walk finds A, B and A's fork; the locked set holds A's gone deploy key and the locked blob, which covers the fork; nothing leaks", async () => {
  const f = fixture();
  const logs: string[] = [];
  const doc = {
    version: 1,
    paths: [{ path: join(f.a, "deploy", "id_rsa"), level: "no-model" }],
    blobs: [{ id: `sha1:${f.tokenBlob}`, level: "no-model", note: "found in history: config.py" }],
  };
  const { s, data } = await server(f, true, doc, logs);
  const replies: string[] = [];
  try {
    const r = await until(data, (x) => x.complete && x.repos.some((p) => p.root === f.a));
    replies.push(JSON.stringify(r));
    assert.equal(r.axis, true);
    assert.ok(r.lockedSet.sha1.includes(f.keyBlob), "A's deploy key version, a gone path, is in the global locked set");
    assert.ok(r.lockedSet.sha1.includes(f.tokenBlob), "the blobs: lock is in the global locked set");
    assert.deepEqual(r.lockedSet.sha256, []);
    const repoA = r.repos.find((p) => p.root === f.a)!;
    assert.equal(repoA.format, "sha1");
    assert.deepEqual(repoA.blobs, [f.keyBlob], "A: exactly the labelled path's version (the token is a blob lock, not a path)");
    assert.match(repoA.key, /^[0-9a-f]{64}$/);
    assert.equal(r.repos.some((p) => p.root === f.b || p.root === f.fork), false, "no label reaches B or the fork by path");
    assert.deepEqual(r.pending, []);
    // The fork holds the very same objects: covered by id with no work of its own.
    const forkHas = git(f.fork, "cat-file", "--batch-check", "--batch-all-objects").split("\n").map((l) => l.split(" ")[0]);
    assert.ok(forkHas.includes(f.keyBlob) && forkHas.includes(f.tokenBlob), "the fork holds both locked blobs");
    // The registry knows every repository the walk found, and not Mandu's own.
    const walked = logs.find((l) => /the HOME walk found/.test(l));
    assert.ok(walked !== undefined && /found 3 /.test(walked), `the walk found A, B and the fork: ${walked}`);

    // A launch in B: registered (source launch), listed once resolved when a
    // label reaches it (a pattern does), with no labelled version.
  } finally {
    data.close();
    await s.close();
  }
  // A new law with a pattern that reaches every repository: B is resolved
  // with nothing in it and listed because the launch named it.
  const logs2: string[] = [];
  const doc2 = { ...doc, paths: [...doc.paths, { path: "**/*.pem", level: "no-model" }] };
  mkdirSync(join(f.dir, "second"), { recursive: true });
  const second = await server({ ...f, dir: join(f.dir, "second") }, true, doc2, logs2);
  try {
    const r2 = await until(second.data, (x) => x.complete && x.repos.some((p) => p.root === f.b), [join(f.b, "sub", "dir")]);
    replies.push(JSON.stringify(r2));
    const repoB = r2.repos.find((p) => p.root === f.b)!;
    assert.deepEqual(repoB.blobs, [], "B: resolved, nothing labelled, listed because the launch named it");
    assert.ok(r2.lockedSet.sha1.includes(f.keyBlob));
  } finally {
    second.data.close();
    await second.s.close();
  }
  for (const x of replies) noValue("a gitHistoryLocks reply", x);
  noValue("the arbiter's log", [...logs, ...logs2].join("\n"));
});

test("registerRepository: a repository is added (add-only); a plain folder, a relative path, Mandu's own home and a full registry are refused", async () => {
  const f = fixture();
  const logs: string[] = [];
  mkdirSync(join(f.dir, "reg"), { recursive: true });
  const { s, data } = await server({ ...f, dir: join(f.dir, "reg") }, true, { version: 1 }, logs, 2, false);
  try {
    const got = await data.registerRepository(join(f.a, "deploy"));
    assert.deepEqual({ ...got, known: undefined }, { axis: true, root: f.a, added: true, known: undefined }, "the work tree's top, by real path");
    assert.equal((await data.registerRepository(f.a)).added, false, "already known: renewed, not added twice");
    await assert.rejects(data.registerRepository(f.plain), /not a git work tree/);
    await assert.rejects(data.registerRepository("work/a"), /absolute/);
    await assert.rejects(data.registerRepository(f.own), /not a git work tree|Mandu/);
    assert.equal((await data.registerRepository(f.b)).added, true);
    await assert.rejects(data.registerRepository(f.fork), /registry is full/, "the data-plane cap refuses, never evicts");
    const r = await data.gitHistoryLocks();
    noValue("a reply", JSON.stringify(r));
  } finally {
    data.close();
    await s.close();
  }
});

test("axis OFF: gitHistoryLocks answers empty and registerRepository registers nothing", async () => {
  const f = fixture();
  const logs: string[] = [];
  const doc = { version: 1, paths: [{ path: join(f.a, "deploy", "id_rsa"), level: "no-model" }], blobs: [{ id: `sha1:${f.tokenBlob}`, level: "no-model" }] };
  const { s, data } = await server(f, false, doc, logs);
  try {
    assert.deepEqual(await data.gitHistoryLocks([f.a]), {
      axis: false, blobs: [], labels: [], lockedSet: { sha1: [], sha256: [] }, repos: [], complete: true, pending: [],
    });
    assert.deepEqual(await data.registerRepository(f.a), { axis: false, root: null, added: false, known: 0 });
    await s.resolveLocksNow();
    assert.equal(logs.some((l) => /HOME walk|lock resolution/.test(l)), false, "the axis OFF walks and resolves nothing");
  } finally {
    data.close();
    await s.close();
  }
});
