/**
 * prepared-copies e2e — confidentiality plan 14 §11.1 R3 through the REAL
 * arbiter: an in-process ArbiterServer with its lock resolution (on demand)
 * and its preparation of sanitized copies, its human socket (the seals), the
 * production `ArbiterClient` on the DATA socket (what a launcher and the
 * guard reach), and real repositories:
 *
 *   - repository A: a deploy key committed and then deleted, under a human
 *     label (`paths:`), and a token once inline in `config.py` (a `blobs:`
 *     lock); F, a clone of A no label names; B, nothing locked;
 *   - A and F registered (`registerRepository`, as the guard does on a
 *     refusal); once the background resolution and preparation ran, the
 *     answer lists A and F `prepared`, B not; each copy's `.pack`, `.idx`
 *     and `.rev` are sealed in the current epoch (read back on the human
 *     socket) with the bytes on disk; no copy's index lists a locked id;
 *   - an unconfined launch recorded on the human socket pauses the
 *     preparation (the answer says so, nothing is built); its end resumes
 *     it;
 *   - axis OFF: no preparation, no `prepared`.
 *
 * The oracle (implementation-plan.md §9): the secrets' bytes, and every
 * 8-character run of their bodies, appear in no reply and no line of the
 * arbiter's log, and in no copy (inflated). Axes stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inflateSync } from "node:zlib";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import { idxLookupFile } from "../../policy/prepared-copies.js";
import type { GitHistoryLocksResult } from "../../ipc/protocol.js";
import { stateAxes } from "../axes.js";
import { randomSecretBody } from "../helpers/random-secret.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

// A letter and a digit, no placeholder run: a value the detectors take
// (a plain random draw has no digit 0.19% of the time; random-secret.ts).
const alnum = randomSecretBody;
const KEY_BODY = alnum(96);
const KEY = `DEPLOY_KEY_${KEY_BODY}`;
const TOKEN_BODY = alnum(36);
const TOKEN = "gh" + "p_" + TOKEN_BODY;
const RUNS = [KEY_BODY, TOKEN_BODY].flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));

function noValue(what: string, s: string): void {
  assert.ok(!s.includes(KEY) && !s.includes(TOKEN), `${what} carries a secret`);
  const hit = RUNS.find((r) => s.includes(r));
  assert.equal(hit, undefined, `${what} carries an 8-character run of a secret's body`);
}

function inflated(buf: Buffer): string {
  let out = "";
  for (let i = 12; i < buf.length - 2; i++) {
    if (buf[i] !== 0x78) continue;
    try { out += `${inflateSync(buf.subarray(i)).toString("latin1")}\n`; } catch { /* not a stream start */ }
  }
  return out;
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

interface Fixture { dir: string; a: string; fork: string; b: string; keyBlob: string; tokenBlob: string }

function fixture(): Fixture {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-prep-e2e-")));
  dirs.push(dir);
  const a = join(dir, "work", "a");
  const b = join(dir, "work", "b");
  mkdirSync(join(a, "deploy"), { recursive: true });
  mkdirSync(b, { recursive: true });
  git(a, "init", "-q", "-b", "main");
  writeFileSync(join(a, "README.md"), "# a\n");
  writeFileSync(join(a, "deploy", "id_rsa"), `${KEY}\n`);
  writeFileSync(join(a, "config.py"), `TOKEN = "${TOKEN}"\n`);
  git(a, "add", "."); git(a, "commit", "-qm", "init");
  git(a, "rm", "-q", "deploy/id_rsa");
  writeFileSync(join(a, "config.py"), "TOKEN = os.environ['TOKEN']\n");
  git(a, "add", "."); git(a, "commit", "-qm", "rotate");
  git(a, "repack", "-adq");
  const fork = join(dir, "forks", "a-fork");
  mkdirSync(join(dir, "forks"), { recursive: true });
  git(join(dir, "forks"), "clone", "-q", "--no-local", a, fork);
  git(b, "init", "-q", "-b", "main");
  writeFileSync(join(b, "notes.txt"), "nothing here\n");
  git(b, "add", "."); git(b, "commit", "-qm", "b"); git(b, "repack", "-adq");
  return { dir, a, fork, b, keyBlob: blobOf(a, `${KEY}\n`), tokenBlob: blobOf(a, `TOKEN = "${TOKEN}"\n`) };
}

async function server(f: Fixture, tag: string, confidentiality: boolean, doc: unknown, logs: string[]) {
  const sock = join(f.dir, `a-${tag}.sock`);
  const humanSock = join(f.dir, `h-${tag}`, "h.sock");
  const cacheDir = join(f.dir, `cache-${tag}`, "object-twins");
  const s = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(f.dir, `db-${tag}.sqlite`), eventDir: join(f.dir, `ev-${tag}`),
    log: (m) => logs.push(m), confidentiality, integrity: false, policyPollMs: 0, policyDocument: doc as never, packDir: null,
    lockResolution: { home: join(f.dir, "no-home"), selfDir: null },
    preparedCopies: { cacheDir },
  });
  await s.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  const human = confidentiality ? new ArbiterClient(humanSock) : null;
  await human?.connect();
  return { s, data, human, cacheDir };
}

const DOC = (f: Fixture) => ({
  version: 1,
  paths: [{ path: join(f.a, "deploy", "id_rsa"), level: "no-model" }],
  blobs: [{ id: `sha1:${f.tokenBlob}`, level: "no-model", note: "found in history: config.py" }],
});

test("R3: A and its fork, registered, get sealed sanitized copies in the background; B holds nothing; no copy, reply or log line holds a secret", async () => {
  const f = fixture();
  const logs: string[] = [];
  const { s, data, human, cacheDir } = await server(f, "on", true, DOC(f), logs);
  const replies: string[] = [];
  try {
    for (const root of [f.a, f.fork, f.b]) assert.equal((await data.registerRepository(root)).added, true);
    await s.prepareCopiesNow();
    const r: GitHistoryLocksResult = await data.gitHistoryLocks();
    replies.push(JSON.stringify(r));
    assert.ok(r.lockedSet.sha1.includes(f.keyBlob) && r.lockedSet.sha1.includes(f.tokenBlob));
    assert.deepEqual((r.prepared ?? []).map((p) => p.root).sort(), [f.a, f.fork].sort(), "A and its fork are prepared; B holds nothing locked");
    assert.ok((r.prepared ?? []).every((p) => p.format === "sha1"));
    assert.equal(r.preparation?.ready, 2);
    assert.deepEqual(r.preparation?.pending, []);
    assert.deepEqual(r.preparation?.capped, []);
    assert.equal(r.preparation?.paused, undefined);
    // Each copy: sealed in the current epoch, part by part, with the bytes
    // on disk; its index lists no locked id; inflated, it holds no secret.
    const keys = readdirSync(cacheDir).filter((n) => /^[0-9a-f]{32}$/.test(n));
    assert.equal(keys.length, 2, "one copy per repository's pack");
    for (const k of keys) {
      const files = readdirSync(join(cacheDir, k));
      const sealed = await human!.cacheSeals("object-twin", files.map((n) => `${k}/${n}`));
      assert.equal(sealed.honoured, true);
      assert.equal(sealed.seals.length, 3, `${k}: the .pack, .idx and .rev each sealed`);
      for (const n of files) {
        const bytes = readFileSync(join(cacheDir, k, n));
        const seal = sealed.seals.find((x) => x.key === `${k}/${n}`)!;
        assert.equal(seal.sha256, createHash("sha256").update(bytes).digest("hex"), `${k}/${n}: sealed with its bytes`);
        if (n.endsWith(".pack")) noValue(`the copy ${k}/${n}, inflated`, inflated(bytes));
        if (n.endsWith(".idx")) assert.deepEqual(idxLookupFile(join(cacheDir, k, n), [f.keyBlob, f.tokenBlob]), []);
      }
    }
    // The seal ops stay off the data socket (plan 14 §11.2).
    await assert.rejects(data.cacheSeals("object-twin", [`${keys[0]}/x.pack`]), /human/i);
  } finally {
    data.close();
    human?.close();
    await s.close();
  }
  for (const x of replies) noValue("a gitHistoryLocks reply", x);
  noValue("the arbiter's log", logs.join("\n"));
});

test("R3: an unconfined launch pauses the preparation (said in the answer, nothing built); its end resumes it", async () => {
  const f = fixture();
  const logs: string[] = [];
  const { s, data, human, cacheDir } = await server(f, "paused", true, DOC(f), logs);
  try {
    const live = await human!.beginLaunch({ pid: process.pid, mode: "off", posture: "confined", writeProtect: false });
    assert.equal(live.confined, false);
    assert.equal((await data.registerRepository(f.a)).added, true);
    await s.prepareCopiesNow();
    const during = await data.gitHistoryLocks();
    assert.match(during.preparation?.paused ?? "", /unconfined launch/);
    assert.deepEqual(during.prepared, []);
    let built: string[] = [];
    try { built = readdirSync(cacheDir).filter((n) => /^[0-9a-f]{32}$/.test(n)); } catch { /* none */ }
    assert.deepEqual(built, [], "nothing is built during an unconfined period");
    const end = await human!.endLaunch(live.token);
    assert.equal(end.rotated, true);
    await s.prepareCopiesNow();
    const afterEnd = await data.gitHistoryLocks();
    assert.equal(afterEnd.preparation?.paused, undefined);
    assert.deepEqual((afterEnd.prepared ?? []).map((p) => p.root), [f.a]);
  } finally {
    data.close();
    human?.close();
    await s.close();
  }
  noValue("the arbiter's log", logs.join("\n"));
});

// write-protection.md §8.5.1, the hang of CI pipelines 7777 and 7778: close()
// while the background resolution and preparation (kicked by a
// registration) are starting their sandboxed git. The close stops both,
// killing each call's whole process group; it must return every time.
test("R3: closing the arbiter while the background cycles start their git always returns (never hangs)", async () => {
  const f = fixture();
  const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
  for (let i = 0; i < 12; i++) {
    const logs: string[] = [];
    const { s, data, human } = await server(f, `close-${i}`, true, DOC(f), logs);
    try {
      for (const root of [f.a, f.fork]) await data.registerRepository(root);
      await sleep(Math.random() * 150);
    } finally {
      data.close();
      human?.close();
      let t: NodeJS.Timeout | undefined;
      await Promise.race([s.close(), new Promise<never>((_, rej) => { t = setTimeout(() => rej(new Error(`close ${i} did not return within 15 s`)), 15_000); })]);
      clearTimeout(t);
    }
    noValue("the arbiter's log", logs.join("\n"));
  }
});

test("R3, axis OFF: no preparation and no `prepared` in the answer", async () => {
  const f = fixture();
  const { s, data } = await server(f, "off", false, DOC(f), []);
  try {
    await s.prepareCopiesNow();
    const r = await data.gitHistoryLocks();
    assert.equal(r.axis, false);
    assert.equal(r.prepared, undefined);
    assert.equal(r.preparation, undefined);
  } finally {
    data.close();
    await s.close();
  }
});
