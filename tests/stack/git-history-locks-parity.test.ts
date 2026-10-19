/**
 * Parity — `gitHistoryLocks` (confidentiality-plan-14 §8.1, §8.2) over the
 * PRODUCTION wiring: the launcher's socket adapter (`socketSecretArbiter`,
 * what applySecretTwins calls) and the arbiter's own client against a REAL
 * ArbiterServer holding a law with blob locks, path labels (a literal, a
 * folder, a public carve-out, a pattern) and a dashboard label, then:
 *
 *   - both answer the same: the blob locks above public only, every human
 *     label with its level (carve-outs included); the axis OFF answers empty;
 *   - the launcher's MIRROR of the label precedence (history-labels.ts)
 *     decides every path of a corpus, fixed and generated, exactly as the
 *     arbiter's `resolvePathLabel` does;
 *   - the answer, handed to the real object twins over a real repository,
 *     hides a labelled deploy key that no longer exists and a locked inline
 *     key's version, and nothing else (the wrapped `git show` and the model
 *     side are tests/sandbox/git-history-locks.test.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { compilePolicy } from "../../arbiter/policy/compiled-policy.js";
import { resolvePathLabel, type PathLabel } from "../../arbiter/policy/path-labels.js";
import { socketSecretArbiter, asGitHistoryLocks } from "../../launcher/src/secret-setup.js";
import { lockedIdsOf } from "../../launcher/src/git-lock-backstop.js";
import { compileHistoryLabels, resolveHistoryLevel, type HistoryLabel } from "../../launcher/src/history-labels.js";
import { idxObjectNames, prepareGitObjectTwins } from "../../launcher/src/git-object-twins.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the confidentiality axis is what the locks serve

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...a: string[]): string => execFileSync("git", a, { cwd, encoding: "utf8", env: ENV });
const blobOf = (cwd: string, body: string): string =>
  execFileSync("git", ["hash-object", "--stdin"], { cwd, input: body, encoding: "utf8", env: ENV }).trim();
const KEY = ["PARITY", "DEPLOY", "KEY", "q".repeat(28)].join("_");

async function server(dir: string, doc: unknown, confidentiality = true): Promise<{ s: ArbiterServer; data: ArbiterClient; admin: ArbiterClient; sock: string }> {
  const sock = join(dir, `a-${confidentiality}.sock`);
  const s = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, `admin-${confidentiality}.sock`), dbPath: join(dir, `db-${confidentiality}.sqlite`),
    eventDir: join(dir, `events-${confidentiality}`), log: () => {}, confidentiality, integrity: false, policyPollMs: 0,
    policyDocument: doc as never,
  });
  await s.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  const admin = new ArbiterClient(join(dir, `admin-${confidentiality}.sock`));
  await admin.connect();
  return { s, data, admin, sock };
}

test("gitHistoryLocks: the launcher's adapter and the arbiter's client answer the same law; the axis OFF answers empty", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-histlock-parity-"));
  const S1 = `sha1:${"1f".repeat(20)}`, S2 = `sha256:${"2e".repeat(32)}`, PUB = `sha1:${"3d".repeat(20)}`;
  const doc = {
    version: 1,
    paths: [
      { path: "/w/repo/deploy/id_rsa", level: "no-model" },
      { path: "/w/secret", level: "local-model" },
      { path: "/w/secret/README.md", level: "public" },
      { path: "**/*.pem", level: "no-model" },
    ],
    blobs: [{ id: S1, level: "no-model", note: "found in history: config.py" }, { id: S2, level: "any-model" }, { id: PUB, level: "public" }],
  };
  const on = await server(dir, doc);
  const off = await server(dir, doc, false);
  try {
    await on.admin.setPathLabel({ path: "/w/page/notes", confidentiality: "no-model", recursive: false });
    const viaLauncher = await socketSecretArbiter(on.sock).gitHistoryLocks!();
    const viaClient = await on.data.gitHistoryLocks();
    assert.deepEqual(viaLauncher, viaClient, "one answer through both adapters");
    const { axis, blobs, labels, repos, lockedSet } = viaLauncher;
    assert.deepEqual(asGitHistoryLocks(viaLauncher), { axis, blobs, labels, repos, lockedSet }, "the launcher's shape check accepts the real answer (the fields it reads) unchanged");
    // Plan 14 §11.1 R4: the global set reaches the guard's backstop as
    // prefixed ids, the public lock never.
    assert.deepEqual(lockedIdsOf({ blobs, ...(lockedSet !== undefined ? { lockedSet } : {}) }), [S1, S2].sort(), "the guard's locked set from the real answer");
    assert.equal(viaClient.axis, true);
    assert.deepEqual(viaClient.blobs, [{ id: S1, level: "no-model" }, { id: S2, level: "any-model" }], "above public only; no note crosses");
    const byPath = Object.fromEntries(viaClient.labels.map((l) => [l.path, [l.level, l.recursive, l.glob === true]]));
    assert.deepEqual(byPath, {
      "/w/repo/deploy/id_rsa": ["no-model", true, false],
      "/w/secret": ["local-model", true, false],
      "/w/secret/README.md": ["public", true, false],
      "**/*.pem": ["no-model", true, true],
      "/w/page/notes": ["no-model", false, false],
    }, "every human label, carve-outs and the dashboard's included");
    const empty = { axis: false, blobs: [], labels: [], lockedSet: { sha1: [], sha256: [] }, repos: [], complete: true, pending: [] };
    assert.deepEqual(await off.data.gitHistoryLocks(), empty);
    assert.deepEqual(await socketSecretArbiter(off.sock).gitHistoryLocks!(), empty);
  } finally {
    for (const x of [on, off]) { x.data.close(); x.admin.close(); await x.s.close(); }
    rmSync(dir, { recursive: true, force: true });
  }
});

/** A deterministic generator (no Math.random: a failure must reproduce). */
function lcg(seed: number): () => number {
  let s = seed >>> 0;
  return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; };
}

test("the launcher's label precedence is the arbiter's: a fixed corpus and 400 generated label sets, every path decided the same", () => {
  const levels = ["public", "any-model", "local-model", "no-model"];
  const check = (labels: HistoryLabel[], paths: string[], what: string): void => {
    const doc = { version: 1, paths: labels.map((l) => ({ path: l.path, level: l.level, recursive: l.recursive })) };
    const arbiterMap = compilePolicy({ specId: "claude-code", document: doc as never }).pathLabels as ReadonlyMap<string, PathLabel>;
    // The launcher gets the compiled map's entries (gitHistoryLocks); decide both ways.
    const mirror = compileHistoryLabels([...arbiterMap.values()].map((l) => ({ path: l.path, level: l.confidentiality, recursive: l.recursive, ...(l.glob ? { glob: true as const } : {}) })));
    for (const p of paths) {
      const want = resolvePathLabel(p, arbiterMap, "/home/u")?.level ?? null;
      assert.equal(resolveHistoryLevel(p, mirror), want, `${what}: ${p} under ${JSON.stringify(labels)}`);
    }
  };
  const L = (path: string, level: string, recursive = true): HistoryLabel => ({ path, level, recursive });
  check([
    L("/w/repo", "no-model"), L("/w/repo/README.md", "public"), L("/w/repo/docs", "public"), L("/w/repo/docs/keys.txt", "no-model"),
    L("**/.env", "no-model"), L("/w/fixtures", "public"), L("/w/fixtures/*", "any-model"), L("/w/t/*", "public"), L("/w/t/*", "no-model", false),
    L("/w/[ab]/x?", "local-model"), L("/w/n", "any-model", false), L("/w/esc\\*", "no-model"),
  ], [
    "/w/repo/deploy/id_rsa", "/w/repo/README.md", "/w/repo/docs/a.md", "/w/repo/docs/keys.txt", "/w/repo-2/x", "/w/app/.env",
    "/w/fixtures/.env", "/w/fixtures/a/b", "/w/t/x", "/w/t/x/y", "/w/a/x1", "/w/c/x1", "/w/n", "/w/n/x", "/w/esc*", "/w/escX", "/elsewhere",
  ], "fixed");
  const rnd = lcg(7731);
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)]!;
  const segs = ["w", "repo", "a", "b", ".env", "k.pem", "docs", "x"];
  const segPats = ["*", "?", "*.pem", "[ab]", "**", ".e*"];
  for (let n = 0; n < 400; n++) {
    const labels: HistoryLabel[] = [];
    const k = 1 + Math.floor(rnd() * 5);
    for (let i = 0; i < k; i++) {
      const depth = 1 + Math.floor(rnd() * 4);
      const parts: string[] = [];
      for (let d = 0; d < depth; d++) parts.push(rnd() < 0.3 ? pick(segPats) : pick(segs));
      let path = (rnd() < 0.15 ? "**/" : "/") + parts.join("/");
      if (path === "/**" || path.split("/").every((s) => s === "" || s === "**")) path = "/w";
      labels.push(L(path, pick(levels), rnd() < 0.8));
    }
    const paths: string[] = [];
    for (let i = 0; i < 12; i++) {
      const depth = 1 + Math.floor(rnd() * 5);
      paths.push("/" + Array.from({ length: depth }, () => pick(segs)).join("/"));
    }
    check(labels, paths, `generated #${n}`);
  }
});

test("the answer, handed to the real object twins: a labelled deploy key that no longer exists and a locked inline key's version are excluded; the rest reads", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-histlock-e2e-"));
  const ws = join(dir, "ws");
  git(dir, "init", "-q", ws);
  const put = (rel: string, body: string): void => { mkdirSync(join(ws, rel, ".."), { recursive: true }); writeFileSync(join(ws, rel), body); };
  put("config.py", `API_KEY = "${KEY}"\n`);
  put("deploy/id_rsa", `${KEY} deploy\n`);
  git(ws, "add", ".");
  git(ws, "commit", "-qm", "one");
  put("config.py", "API_KEY = None\n");
  git(ws, "rm", "-rq", "deploy");
  git(ws, "commit", "-qam", "two");
  git(ws, "repack", "-adq");
  const inline = blobOf(ws, `API_KEY = "${KEY}"\n`), deploy = blobOf(ws, `${KEY} deploy\n`), now = blobOf(ws, "API_KEY = None\n");
  const a = await server(dir, { version: 1, paths: [{ path: join(ws, "deploy", "id_rsa"), level: "no-model" }], blobs: [{ id: `sha1:${inline}`, level: "no-model" }] });
  try {
    const locks = asGitHistoryLocks(await socketSecretArbiter(a.sock).gitHistoryLocks!());
    const denyFile = join(dir, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    const got = await prepareGitObjectTwins([], {
      cacheDir: join(dir, "cache"), denyFile, labels: locks.labels, blobLocks: locks.blobs.map((b) => b.id), repoHints: [ws],
    });
    assert.equal(got.repos, 1);
    const idx = got.twins.find((x) => x.targetPath.endsWith(".idx"))!;
    const names = new Set(idxObjectNames(readFileSync(idx.twinPath)));
    assert.ok(!names.has(deploy), "the gone deploy key's version is excluded");
    assert.ok(!names.has(inline), "the locked inline version is excluded");
    assert.ok(names.has(now), "the current config.py reads normally");
  } finally {
    a.data.close(); a.admin.close(); await a.s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
