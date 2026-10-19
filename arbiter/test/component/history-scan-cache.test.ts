/**
 * history-scan-cache e2e — the git-history scan's cache through the REAL
 * arbiter (secret-discovery.md §3.2 item 8; confidentiality-plan-14 §3, §5.5):
 * an in-process ArbiterServer on a socket, the production `ArbiterClient`,
 * the production cache wiring (no `historyScan` seam: real git, real blob
 * reader, the cache directory resolved from MANDU_HOME exactly as the daemon
 * resolves it), and a REAL fixture repository holding a committed-then-
 * deleted deploy key and a token still in a file.
 *
 *   - two `suggestPolicy` calls: the second is served from the cache (plan
 *     `hit`, no blob read), answers the same suggestions and files nothing
 *     new; the timing assertion is loose (the second is not slower than the
 *     first plus a margin);
 *   - `scanSecretHistory` after them answers the same findings;
 *   - a new commit is scanned incrementally and its key found.
 *
 * The oracle (implementation-plan.md §9): the cache file is owner-only and
 * carries no key and no 8-character run of either secret's body, and
 * neither does any reply or the arbiter's log. Axes stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import { stateAxes } from "../axes.js";
import { randomSecretBody } from "../helpers/random-secret.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

// A letter and a digit, no placeholder run: a value the detectors take
// (a plain random draw has no digit 0.19% of the time; random-secret.ts).
const alnum = randomSecretBody;
const KEY_BODY = `${alnum(94)}a7`;
const PEM = `-----BEGIN OPENSSH ` + `PRIVATE KEY-----\n${KEY_BODY}\n-----END OPENSSH PRIVATE KEY-----\n`;
const TOKEN_BODY = `${alnum(34)}b8`;
const TOKEN = "gh" + "p_" + TOKEN_BODY;
const LATER_BODY = `${alnum(34)}c9`;
const LATER = "gh" + "p_" + LATER_BODY;
const RUNS = [KEY_BODY, TOKEN_BODY, LATER_BODY].flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));

function noValue(what: string, s: string): void {
  assert.ok(!s.includes(PEM) && !s.includes(TOKEN) && !s.includes(LATER), `${what} carries a secret`);
  const hit = RUNS.find((r) => s.includes(r));
  assert.equal(hit, undefined, `${what} carries an 8-character run of a secret's body`);
}

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

test("e2e: a second suggestPolicy is served from the cache, equal and fast; a new commit is scanned incrementally", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-hcache-e2e-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const manduHome = join(dir, "mandu-home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: repo, env: gitEnv, encoding: "utf8" });
  const put = (rel: string, body: string): void => { mkdirSync(join(repo, rel, ".."), { recursive: true }); writeFileSync(join(repo, rel), body); };
  git("init", "-q", "-b", "main");
  put("README.md", "a project\n");
  put("config.py", `API_TOKEN = "${TOKEN}"\n`);
  for (let i = 0; i < 40; i++) put(`src/m${i}.py`, `def f${i}():\n    return ${i}\n`);
  git("add", "."); git("commit", "-qm", "init");
  put("deploy/id_ed25519", PEM);
  git("add", "."); git("commit", "-qm", "add deploy key");
  git("rm", "-q", "deploy/id_ed25519"); git("commit", "-qm", "remove it");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\n");

  // The production default: the cache dir comes from MANDU_HOME, as in the
  // daemon (server.ts `historyScanCacheDir` unset).
  const savedHome = process.env["MANDU_HOME"];
  process.env["MANDU_HOME"] = manduHome;
  const logs: string[] = [];
  let server: ArbiterServer;
  try {
    server = new ArbiterServer({
      socketPath: join(dir, "arbiter.sock"),
      dbPath: join(dir, "mandu.db"),
      eventDir: join(dir, "events"),
      policyPath: policy,
      policyPollMs: 0,
      confidentiality: true,
      integrity: false,
      packDir: null,
      log: (m) => logs.push(m),
    });
  } finally {
    if (savedHome === undefined) delete process.env["MANDU_HOME"];
    else process.env["MANDU_HOME"] = savedHome;
  }
  await server.listen();
  const client = new ArbiterClient(join(dir, "arbiter.sock"));
  try {
    const t1 = Date.now();
    const first = await client.suggestPolicy([repo], { home });
    const ms1 = Date.now() - t1;
    assert.equal(first.axis, true);
    assert.equal(first.running, false);
    assert.equal(first.scan!.repos[0]!.cache!.plan, "fresh");
    assert.ok(first.scan!.repos[0]!.cache!.read >= 43, JSON.stringify(first.scan!.repos[0]));
    assert.ok(first.filed.length >= 1, "the deploy key is filed");

    const t2 = Date.now();
    const second = await client.suggestPolicy([repo], { home });
    const ms2 = Date.now() - t2;
    assert.deepEqual(second.scan!.repos[0]!.cache, { plan: "hit", read: 0, stored: false });
    assert.deepEqual(second.filed, [], "nothing new to file");
    assert.deepEqual(second.suggestions.map((s) => s.id).sort(), first.suggestions.map((s) => s.id).sort(), "the same suggestions");
    assert.deepEqual(second.scan!.counts, first.scan!.counts);
    assert.deepEqual(second.counts.findings, first.counts.findings);
    assert.ok(ms2 <= ms1 + 2000, `the cached call (${ms2} ms) is not slower than the first (${ms1} ms)`);

    const scan = await client.scanSecretHistory([repo], home);
    assert.equal(scan.repos[0]!.cache!.plan, "hit");
    const key = scan.findings.find((f) => f.paths.includes("deploy/id_ed25519"))!;
    assert.ok(key.firstCommit !== null && key.lastCommit !== null, "traced, from the cache");

    // A new commit: only its blob is read.
    put("later.py", `T = "${LATER}"\n`);
    git("add", "."); git("commit", "-qm", "later");
    const third = await client.suggestPolicy([repo], { home });
    assert.deepEqual(third.scan!.repos[0]!.cache, { plan: "incremental", read: 1, stored: true });
    // `counts.findings` counts both sources (plan 14 §13.5): the new key is
    // a history finding (a blob of HEAD) and a workspace one (the file).
    assert.equal(third.counts.findings, first.counts.findings + 2);

    // Where it lives, and what it holds.
    const cacheDir = join(manduHome, "state", "object-walks", "history-scan");
    const files = readdirSync(cacheDir);
    assert.equal(files.length, 1);
    assert.equal(statSync(cacheDir).mode & 0o777, 0o700);
    assert.equal(statSync(join(cacheDir, files[0]!)).mode & 0o777, 0o600);
    noValue("the cache file", readFileSync(join(cacheDir, files[0]!), "utf8"));
    noValue("the replies", JSON.stringify([first, second, third, scan]));
    noValue("the arbiter log", logs.join("\n"));
    assert.ok(logs.some((l) => /cache: hit, 0 read/.test(l)), logs.join("\n"));
  } finally {
    client.close();
    await server.close();
  }
});
