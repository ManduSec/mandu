/**
 * doctor-history-scan e2e — `mandu doctor --secrets`'s git-history scan
 * (docs/design/confidentiality/secret-discovery.md §3, phase 1) over its PRODUCTION path: the
 * launcher's `realDoctorSecretsDeps().historyScan` (ndjsonCall, the op name
 * it sends) and the arbiter's `ArbiterClient.scanSecretHistory`, both
 * against a REAL ArbiterServer on a socket that holds a law (a label on a
 * protected file), over a REAL fixture repository:
 *
 *   - a deploy key committed and then deleted (the C17 case): reported as
 *     only in history, traced to its commits, MASKED;
 *   - a deleted `.env` (harmless content): found by the catalog's name;
 *   - a key in a labelled file that still exists: covered;
 *   - (second test) a GitHub token whose random part a placeholder pattern
 *     takes (`xxxx`), committed then deleted: found by GitHub's checksum
 *     (secret-discovery.md §3.2 item 5); the same with a broken checksum is
 *     not a finding.
 *
 * The oracle (implementation-plan.md §9): no byte of a key's value reaches
 * the doctor's stdout, its --json, the socket reply or the arbiter's log.
 * Only the arbiter reads the blobs. Axes stated: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomInt } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { crc32 } from "node:zlib";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { loadPolicyFileStrict } from "../../arbiter/policy/policy-file-validate.js";
import { realDoctorSecretsDeps, runDoctorSecrets, type DoctorSecretsReport } from "../../launcher/src/doctor-secrets.js";
import type { Layout } from "../../launcher/src/services/layout.js";
import { stateAxes } from "../../arbiter/test/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

// Assembled at run time: this file holds no credential-shaped literal.
const KEY_BODY = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ".repeat(2);
const PEM = `-----BEGIN OPENSSH ` + `PRIVATE KEY-----\n${KEY_BODY}\n-----END OPENSSH PRIVATE KEY-----\n`;
const TOKEN_BODY = "A1b2C3d4".repeat(5);
const TOKEN = "gh" + "p_" + TOKEN_BODY;
const BODIES = [KEY_BODY.slice(0, 24), TOKEN_BODY.slice(0, 24)];

test("doctor --secrets reports a committed-then-deleted key, a deleted .env and a covered file from the real arbiter, masked end to end", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-doctor-hist-"));
  const home = join(dir, "home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: repo, env: gitEnv, encoding: "utf8" });
  const put = (rel: string, body: string): void => { mkdirSync(join(repo, rel, ".."), { recursive: true }); writeFileSync(join(repo, rel), body); };

  git("init", "-q", "-b", "main");
  put("README.md", "a project\n");
  put(".env", "MODE=dev\n");
  put("protected.txt", `token ${TOKEN}\n`);
  git("add", "."); git("commit", "-qm", "init");
  put("deploy/id_ed25519", PEM);
  git("add", "."); git("commit", "-qm", "add deploy key");
  const added = git("rev-parse", "HEAD").trim();
  git("rm", "-q", "deploy/id_ed25519", ".env"); git("commit", "-qm", "remove the key and the env");
  const removed = git("rev-parse", "HEAD").trim();

  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(repo, "protected.txt")}\n    level: no-model\n`);
  const sock = join(dir, "a.sock");
  const logs: string[] = [];
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: (m) => logs.push(m), confidentiality: true, integrity: false, policyPollMs: 0,
    policyDocument: loadPolicyFileStrict(policy).config,
  });
  await server.listen();
  // Only the arbiter lookup and the host posture are injected (the
  // resident-or-throwaway choice and the posture probe are covered
  // elsewhere); every arbiter call is the production seam.
  const deps = {
    ...realDoctorSecretsDeps(),
    arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }),
    confinement: () => ({ posture: "confined" as const }),
  };
  const env = { HOME: home, PATH: process.env["PATH"] ?? "/usr/bin:/bin" };
  try {
    // ── text ──
    const outs: string[] = [];
    const code = await runDoctorSecrets(["--secrets"], env, {} as Layout, deps, { out: (s) => outs.push(s), cwd: repo });
    const text = outs.join("");
    assert.equal(code, 0, text);
    assert.match(text, /Git history of ~\/proj \(/);
    assert.match(text, /✗ 2 files only in git history, not protected:/);
    assert.match(text, /deploy\/id_ed25519 {3}private key -----BEGIN OPENSSH PRIVATE KEY-----… \(line 1\)/);
    assert.match(text, new RegExp(`added ${added.slice(0, 8)}, last ${removed.slice(0, 8)}`));
    assert.match(text, /\.env {3}a deleted file named like a credential file \(\.env, /);
    assert.match(text, /✓ 1 file covered \(protected now\):\n {4}protected\.txt {3}GitHub token ghp_… \(line 1\)/);
    assert.match(text, /Rotate the key: it is in every clone/);

    // ── json ──
    const jouts: string[] = [];
    await runDoctorSecrets(["--secrets", "--json"], env, {} as Layout, deps, { out: (s) => jouts.push(s), cwd: repo });
    const json = jouts.join("");
    const report = JSON.parse(json) as DoctorSecretsReport;
    const findings = report.history?.scan?.findings ?? [];
    const key = findings.find((f) => f.paths.includes("deploy/id_ed25519"))!;
    assert.equal(key.repoRoot, repo);
    assert.equal(key.blob, git("rev-parse", `${added}:deploy/id_ed25519`).trim());
    assert.equal(key.firstCommit, added);
    assert.equal(key.lastCommit, removed);
    assert.equal(key.stillPresent, false);
    assert.equal(key.pathStillSecretByCatalog, false);
    assert.deepEqual(key.detector, { kind: "content-shape", rule: "private-key", line: 1, preview: "-----BEGIN OPENSSH PRIVATE KEY-----…" });
    const env0 = findings.find((f) => f.paths.includes(".env"))!;
    assert.equal(env0.detector.kind, "catalog-path");
    const prot = findings.find((f) => f.paths.includes("protected.txt"))!;
    assert.equal(prot.pathStillSecretByCatalog, true);
    assert.deepEqual(report.history?.classes?.slice().sort(), ["covered", "history-only", "history-only"]);

    // ── the arbiter's own client (the production wiring for other callers) ──
    const client = new ArbiterClient(sock);
    const direct = await client.scanSecretHistory([repo], home);
    client.close();
    assert.equal(direct.axis, true);
    assert.equal(direct.findings.length, 3);

    // ── the oracle: no value anywhere ──
    // The scan emits no event; whatever the store holds must carry no value.
    const events = existsSync(join(dir, "events"))
      ? readdirSync(join(dir, "events"), { recursive: true, withFileTypes: true })
        .filter((e) => e.isFile()).map((e) => readFileSync(join(e.parentPath, e.name), "utf8")).join("")
      : "";
    for (const [what, s] of [["stdout", text], ["--json", json], ["the socket reply", JSON.stringify(direct)], ["the arbiter log", logs.join("\n")], ["the event store", events]] as const) {
      for (const b of BODIES) assert.ok(!s.includes(b), `${what} carries a key's value`);
    }
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});


/** GitHub's layout: 30 random, then CRC-32 of those 30 in base62, padded to 6. */
function githubToken(random30: string): string {
  const b62 = "0123456789" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz";
  let n = crc32(random30);
  let sum = "";
  for (let i = 0; i < 6; i++) { sum = b62[n % 62]! + sum; n = Math.floor(n / 62); }
  return "gh" + "p_" + random30 + sum;
}

test("history scan: a checksum-valid GitHub token whose body a placeholder pattern takes is found, masked, over the real arbiter; a broken checksum is not", async () => {
  const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz";
  const random = "xxxx" + Array.from({ length: 26 }, () => letters[randomInt(letters.length)]).join("");
  const real = githubToken(random);
  const fake = real.slice(0, -1) + (real.endsWith("Q") ? "R" : "Q");
  const dir = mkdtempSync(join(tmpdir(), "mdu-hist-ghsum-"));
  const home = join(dir, "home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: repo, env: gitEnv, encoding: "utf8" });
  git("init", "-q", "-b", "main");
  writeFileSync(join(repo, "README.md"), "a project\n");
  writeFileSync(join(repo, "ci-notes.txt"), `push with ${real}\n`);
  writeFileSync(join(repo, "old-notes.txt"), `push with ${fake}\n`);
  git("add", "."); git("commit", "-qm", "notes");
  git("rm", "-q", "ci-notes.txt", "old-notes.txt"); git("commit", "-qm", "drop the notes");

  const sock = join(dir, "a.sock");
  const logs: string[] = [];
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: (m) => logs.push(m), confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  try {
    const client = new ArbiterClient(sock);
    const reply = await client.scanSecretHistory([repo], home);
    client.close();
    assert.equal(reply.axis, true);
    const found = reply.findings.filter((f) => f.paths.includes("ci-notes.txt"));
    assert.equal(found.length, 1, JSON.stringify(reply.findings.map((f) => f.paths)));
    assert.deepEqual(found[0]!.detector, { kind: "content-shape", rule: "github-token", line: 1, preview: "ghp_…" });
    assert.equal(found[0]!.stillPresent, false);
    assert.equal(reply.findings.filter((f) => f.paths.includes("old-notes.txt")).length, 0, "a broken checksum stays under the placeholder filter");
    for (const [what, s] of [["the socket reply", JSON.stringify(reply)], ["the arbiter log", logs.join("\n")]] as const) {
      assert.ok(!s.includes(random.slice(4, 20)), `${what} carries the token's body`);
    }
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
