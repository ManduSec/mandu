/**
 * darwin-walk-prunes e2e — plan 14's HOME walks on macOS
 * (confidentiality-plan-14-policy-suggestions.md §11.1 R1 and §13.1, "On
 * macOS") through the REAL arbiter: an in-process ArbiterServer, the
 * production `ArbiterClient` on the DATA socket (what the launcher and
 * `mandu policy suggest` reach), real files and real repositories in a
 * fixture HOME. The platform is injected (`workspaceScan.platform`,
 * `lockResolution.platform`), so both platforms run on every host:
 *
 *   - the workspace scan (`suggestPolicy`, the home tier): on macOS a
 *     name-hinted file holding a token in `~/Library/Application Support`
 *     and one in `~/Pictures` are never opened and never suggested, while
 *     `~/tools.toml` is; on Linux all three are suggested, as before;
 *   - the known-repository HOME walk: on macOS a repository in `~/Music`
 *     and one in `~/Library/Mobile Documents` (iCloud Drive) are not found
 *     by the walk, while `~/work/a` is; on Linux the walk finds all three.
 *     The iCloud one holds a deploy key committed and then deleted under a
 *     human label on that FILE: on BOTH platforms its version is in the
 *     global locked set, because the `label` source walks UP from the
 *     labelled path to its work tree, pruned folder or not. A file label
 *     therefore lifts no prune;
 *   - a label ABOVE the repository, which the `label` source cannot follow
 *     down (it names no work tree): a folder label on the iCloud Drive
 *     folder, or a pattern rooted at `~/Library`. On macOS the walk
 *     re-enters for it by discovery's rule (`darwinPrune`), finds the
 *     iCloud project (still not `~/Music`'s) and its deleted key is locked;
 *     on Linux the walk finds all three, as before.
 *
 * The oracle (implementation-plan.md §9): no key byte, and no 8-character
 * run of any key body, in any reply or line of the arbiter's log. Axes
 * stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import { defaultWorkspaceFs, type WorkspaceScanFs } from "../../policy/secret-workspace-scan.js";
import type { GitHistoryLocksResult } from "../../ipc/protocol.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const alnum = (n: number): string => {
  let s = "";
  while (s.length < n) s += randomBytes(64).toString("base64").replace(/[^A-Za-z0-9]/g, "");
  return s.slice(0, n);
};
const TOKEN_BODIES = [alnum(36), alnum(36), alnum(36)];
const TOKENS = TOKEN_BODIES.map((b) => "gh" + "p_" + b);
const KEY_BODY = alnum(96);
const PEM = `-----BEGIN OPENSSH ` + `PRIVATE KEY-----\n${KEY_BODY}\n-----END OPENSSH PRIVATE KEY-----\n`;
const RUNS = [...TOKEN_BODIES, KEY_BODY].flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));

function noValue(what: string, s: string): void {
  for (const v of [...TOKENS, PEM]) assert.ok(!s.includes(v), `${what} carries a secret`);
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

interface Fixture { dir: string; home: string; tools: string; library: string; pictures: string; work: string; icloud: string; music: string; keyBlob: string }

function fixture(): Fixture {
  // Canonical, like a real HOME: the walk registers repositories by real path.
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-walk-prune-")));
  dirs.push(dir);
  const home = join(dir, "home");
  const put = (p: string, body: string): void => { mkdirSync(join(p, ".."), { recursive: true }); writeFileSync(p, body); };
  const tools = join(home, "tools.toml");
  const library = join(home, "Library", "Application Support", "acme", "tools.toml");
  const pictures = join(home, "Pictures", "export", "settings.json");
  put(tools, `[registry]\ntoken = "${TOKENS[0]}"\n`);
  put(library, `[registry]\ntoken = "${TOKENS[1]}"\n`);
  put(pictures, `{"token": "${TOKENS[2]}"}\n`);
  const repo = (root: string, files: Record<string, string>): void => {
    mkdirSync(root, { recursive: true });
    git(root, "init", "-q", "-b", "main");
    for (const [rel, body] of Object.entries(files)) put(join(root, rel), body);
    git(root, "add", "."); git(root, "commit", "-qm", "init");
  };
  const work = join(home, "work", "a");
  repo(work, { "README.md": "# a\n" });
  const music = join(home, "Music", "lib", "repo");
  repo(music, { "README.md": "# music\n" });
  // iCloud Drive: a deploy key committed and then deleted, under a label.
  const icloud = join(home, "Library", "Mobile Documents", "com~apple~CloudDocs", "proj");
  repo(icloud, { "README.md": "# proj\n", "deploy/id_rsa": PEM });
  git(icloud, "rm", "-q", "deploy/id_rsa"); git(icloud, "commit", "-qm", "rotate");
  return { dir, home, tools, library, pictures, work, icloud, music, keyBlob: blobOf(icloud, PEM) };
}

/** The human label of the first test: the deleted key FILE itself. */
const fileLabel = (f: Fixture): Array<{ path: string; level: string }> => [{ path: join(f.icloud, "deploy", "id_rsa"), level: "no-model" }];

async function rig(
  f: Fixture, platform: NodeJS.Platform, logs: string[],
  fn: (c: { data: ArbiterClient; opened: string[] }) => Promise<void>,
  paths: Array<{ path: string; level: string }> = fileLabel(f),
): Promise<void> {
  const tag = platform;
  const opened: string[] = [];
  // The real filesystem and the real safe open, with every open recorded.
  const fs: WorkspaceScanFs = { ...defaultWorkspaceFs, readRegular: async (p, caps) => { opened.push(p); return defaultWorkspaceFs.readRegular(p, caps); } };
  const sock = join(f.dir, `a-${tag}.sock`);
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(f.dir, `db-${tag}.sqlite`), eventDir: join(f.dir, `ev-${tag}`),
    log: (m) => logs.push(m), confidentiality: true, integrity: false, policyPollMs: 0, historyScanCacheDir: null,
    policyDocument: { version: 1, paths } as never,
    workspaceScan: { fs, env: {}, discovery: { installEnv: {}, selfDir: null }, platform },
    lockResolution: {
      home: f.home, selfDir: null, platform,
      schedule: { walkHome: true, startDelayMs: 0, cycleMs: 0, homeWalkMs: 0, labelPollMs: 0 },
    },
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  try {
    await fn({ data, opened });
  } finally {
    data.close();
    await server.close();
  }
}

async function until(data: ArbiterClient, ok: (r: GitHistoryLocksResult) => boolean): Promise<GitHistoryLocksResult> {
  const t0 = Date.now();
  for (;;) {
    const r = await data.gitHistoryLocks();
    if (ok(r)) return r;
    if (Date.now() - t0 > 30_000) assert.fail(`not resolved in 30 s: ${JSON.stringify({ complete: r.complete, pending: r.pending, repos: r.repos.map((x) => x.root) })}`);
    await new Promise((res) => setTimeout(res, 50));
  }
}

for (const platform of ["darwin", "linux"] as const) {
  test(`${platform}: the workspace scan's home tier ${platform === "darwin" ? "never opens ~/Library or ~/Pictures" : "walks ~/Library and ~/Pictures as before"}; the HOME walk ${platform === "darwin" ? "skips" : "finds"} their repositories; a labelled one is locked either way`, async () => {
    const f = fixture();
    const logs: string[] = [];
    const replies: string[] = [];
    await rig(f, platform, logs, async ({ data, opened }) => {
      // The workspace scan, home tier (a launch from ~, `mandu policy suggest --home`).
      const r = await data.suggestPolicy([f.home], { home: f.home, sources: ["workspace"] });
      replies.push(JSON.stringify(r));
      assert.deepEqual(r.workspaceScan!.roots, [{ root: f.home, tier: "home" }]);
      const suggested = r.suggestions.flatMap((s) => s.evidence.paths);
      assert.ok(suggested.includes("tools.toml"), JSON.stringify(suggested));
      const inPruned = [f.library, f.pictures];
      if (platform === "darwin") {
        for (const p of inPruned) assert.ok(!opened.includes(p), `opened on macOS: ${p}`);
        assert.ok(!opened.some((p) => p.startsWith(join(f.home, "Library") + "/") || p.startsWith(join(f.home, "Pictures") + "/")));
        assert.deepEqual(suggested, ["tools.toml"], "nothing under a pruned folder is suggested");
      } else {
        for (const p of inPruned) assert.ok(opened.includes(p), `Linux reads ${p}`);
        assert.ok(suggested.includes("Library/Application Support/acme/tools.toml") && suggested.includes("Pictures/export/settings.json"), JSON.stringify(suggested));
      }

      // The known-repository HOME walk, then the resolution.
      const locks = await until(data, (x) => x.complete && x.repos.some((p) => p.root === f.icloud) && logs.some((l) => /the HOME walk found/.test(l)));
      replies.push(JSON.stringify(locks));
      const walked = logs.find((l) => /the HOME walk found/.test(l))!;
      if (platform === "darwin") assert.match(walked, /found 1 /, `only ~/work/a: ${walked}`);
      else assert.match(walked, /found 3 /, `~/work/a, ~/Music/… and the iCloud project: ${walked}`);
      // The label source, not the walk, registered the iCloud project: its
      // deleted key's version is locked on both platforms.
      assert.ok(locks.lockedSet.sha1.includes(f.keyBlob), "the labelled version is in the global locked set");
      assert.deepEqual(locks.repos.find((p) => p.root === f.icloud)!.blobs, [f.keyBlob]);
    });
    noValue("the replies", replies.join("\n"));
    noValue("the arbiter's log", logs.join("\n"));
  });
}

for (const platform of ["darwin", "linux"] as const) {
  for (const kind of ["a folder label on iCloud Drive", "a pattern rooted at ~/Library"] as const) {
    test(`${platform}: ${kind}, above the repository, ${platform === "darwin" ? "has the HOME walk re-enter ~/Library for it (not ~/Music)" : "changes nothing: the walk finds all three"}; its deleted key is locked`, async () => {
      const f = fixture();
      const logs: string[] = [];
      const replies: string[] = [];
      const cloud = join(f.home, "Library", "Mobile Documents", "com~apple~CloudDocs");
      const label = kind.startsWith("a folder")
        ? { path: cloud, level: "no-model" }
        : { path: `${f.home}/Library/**/id_rsa`, level: "no-model" };
      await rig(f, platform, logs, async ({ data }) => {
        const locks = await until(data, (x) => x.complete && x.repos.some((p) => p.root === f.icloud) && logs.some((l) => /the HOME walk found/.test(l)));
        replies.push(JSON.stringify(locks));
        const walked = logs.find((l) => /the HOME walk found/.test(l))!;
        // Only the walk can name the iCloud project here: a label above a
        // work tree names none (the `label` source walks up, not down).
        if (platform === "darwin") assert.match(walked, /found 2 /, `~/work/a and the iCloud project, not ~/Music's: ${walked}`);
        else assert.match(walked, /found 3 /, walked);
        assert.ok(locks.lockedSet.sha1.includes(f.keyBlob), "the labelled version is in the global locked set");
        assert.ok(locks.repos.find((p) => p.root === f.icloud)!.blobs.includes(f.keyBlob));
        assert.ok(!locks.repos.some((p) => p.root === f.music), "no label concerns ~/Music's repository");
      }, [label]);
      noValue("the replies", replies.join("\n"));
      noValue("the arbiter's log", logs.join("\n"));
    });
  }
}
