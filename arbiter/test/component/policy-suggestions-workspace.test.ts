/**
 * policy-suggestions-workspace e2e — confidentiality plan 14 §13 (S2, the
 * workspace scan) through the REAL arbiter: an in-process ArbiterServer with
 * a file-backed law, a DATA socket and an ADMIN socket, the production
 * `ArbiterClient` on both (no test bridge: the client's parity test for
 * `sources` / `includeHome` / `workspaceScan`), the real walk and the real
 * safe open over a fixture workspace that is a git work tree:
 *
 *   - `deploy/staging.conf` with a token, `config.toml` with a password
 *     assignment, `notes/deploy.md` with an AWS key: three workspace
 *     suggestions (`source: "workspace"`, `rotate: false`);
 *   - `README.md` with a placeholder key: no finding;
 *   - `.env.staging` with a token: the CATALOG covers it (`shape:.env*`), and
 *     `private/ledger.txt` with a token: a LABEL covers it; both counted
 *     `covered` and NEVER OPENED (the fs seam wraps the real one and records
 *     every open);
 *   - `settings.py`, tracked, whose current content holds a key: both scans
 *     find it, ONE suggestion (the history one) is filed;
 *   - apply on the DATA socket writes the `paths:` lock; a rescan files
 *     nothing (the applied file is now covered and not opened, the rest are
 *     pending); "Not a secret" on the ADMIN socket, and a rescan counts it
 *     dismissed;
 *   - `includeHome` adds the home tier (a name-hinted file in HOME), and
 *     `sources: ["workspace"]` runs the walk alone;
 *   - the §5.5 budget covers both scans: with `waitMs: 0` the reply says
 *     `running`, and the background job files the workspace suggestions;
 *   - axis OFF: empty, `workspaceScan: null`.
 *
 * The oracle (implementation-plan.md §9): no key byte, and no 8-character
 * run of any key body, in any op reply, the event store, the proposals and
 * changes tables, the arbiter's log, or policy.yaml. Axes stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import Database from "../../db/sqlite.js";
import { ArbiterServer, adminOnlyError } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import { defaultWorkspaceFs, type WorkspaceScanFs } from "../../policy/secret-workspace-scan.js";
import type { SuggestPolicyResult } from "../../ipc/protocol.js";
import { stateAxes } from "../axes.js";
import { randomSecretBody } from "../helpers/random-secret.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

// Assembled at run time from random bytes: this file holds no key-shaped
// literal, and a run of a body cannot match an id or a path by accident.
// A letter and a digit, no placeholder run: a value the detectors take
// (a plain random draw has no digit 0.19% of the time; random-secret.ts).
const alnum = randomSecretBody;
const upper = (n: number): string => {
  let s = "";
  while (s.length < n) s += randomBytes(64).toString("hex").toUpperCase();
  return s.slice(0, n);
};
const TOKEN_BODY = alnum(36);
const TOKEN = "gh" + "p_" + TOKEN_BODY;
const AWS_BODY = upper(16);
const AWS = "AK" + "IA" + AWS_BODY;
const PASS = "Zr8" + alnum(20) + "9q";
const SETTINGS_BODY = alnum(40);
const COVERED_BODY = alnum(36);
const COVERED = "gh" + "p_" + COVERED_BODY;
const HOME_BODY = alnum(36);
const HOME_TOKEN = "gl" + "pat-" + HOME_BODY;
const BODIES = [TOKEN_BODY, AWS_BODY, PASS, SETTINGS_BODY, COVERED_BODY, HOME_BODY];
const RUNS = BODIES.flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));

function noValue(what: string, s: string): void {
  for (const v of [TOKEN, AWS, PASS, COVERED, HOME_TOKEN, SETTINGS_BODY]) assert.ok(!s.includes(v), `${what} carries a secret`);
  const hit = RUNS.find((r) => s.includes(r));
  assert.equal(hit, undefined, `${what} carries an 8-character run of a secret's body`);
}

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

interface Fixture { dir: string; home: string; proj: string; policy: string }

function fixture(): Fixture {
  // realpath: the history scan names a repository by git's real top level,
  // and macOS reaches the temp dir through a link (/tmp, /var → /private/…).
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-suggest-ws-e2e-")));
  dirs.push(dir);
  const home = join(dir, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: proj, env: gitEnv, encoding: "utf8" });
  const put = (rel: string, body: string): void => { mkdirSync(join(proj, rel, ".."), { recursive: true }); writeFileSync(join(proj, rel), body); };
  git("init", "-q", "-b", "main");
  put("README.md", "# app\n\nSet API_KEY=your-api-key-here in your shell.\n");
  put("settings.py", `DEBUG = False\nSECRET_KEY = "${SETTINGS_BODY}"\n`);
  git("add", "."); git("commit", "-qm", "init");
  // Untracked: only the workspace scan sees these.
  put("deploy/staging.conf", `[api]\nAPI_TOKEN=${TOKEN}\n`);
  put("config.toml", `[db]\ndb_password = "${PASS}"\n`);
  put("notes/deploy.md", `# deploy\n\nthe old key was ${AWS}, rotate it\n`);
  put(".env.staging", `TOKEN=${COVERED}\n`);
  put("private/ledger.txt", `token ${COVERED}\n`);
  writeFileSync(join(home, "tools.toml"), `[registry]\ntoken = "${HOME_TOKEN}"\n`);
  writeFileSync(join(home, "notes.txt"), `${HOME_TOKEN}\n`); // no name hint: the home tier does not read it
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(proj, "private", "ledger.txt")}\n    level: no-model\n`);
  return { dir, home, proj, policy };
}

async function rig(
  f: Fixture,
  opts: { confidentiality?: boolean; slowMs?: number },
  fn: (c: { data: ArbiterClient; admin: ArbiterClient; logs: string[]; opened: string[] }) => Promise<void>,
): Promise<void> {
  const logs: string[] = [];
  const opened: string[] = [];
  // The real filesystem and the real safe open, with every open recorded.
  const fs: WorkspaceScanFs = {
    ...defaultWorkspaceFs,
    lstat: async (p) => {
      if (opts.slowMs) await new Promise((r) => setTimeout(r, opts.slowMs));
      return defaultWorkspaceFs.lstat(p);
    },
    readRegular: async (p, caps) => { opened.push(p); return defaultWorkspaceFs.readRegular(p, caps); },
  };
  const server = new ArbiterServer({
    socketPath: join(f.dir, "arbiter.sock"),
    adminSocketPath: join(f.dir, "admin.sock"),
    dbPath: join(f.dir, "mandu.db"),
    eventDir: join(f.dir, "events"),
    policyPath: f.policy,
    policyPollMs: 0,
    historyScanCacheDir: null,
    confidentiality: opts.confidentiality ?? true,
    integrity: false,
    log: (m) => logs.push(m),
    workspaceScan: { fs, env: {}, discovery: { installEnv: {}, selfDir: null } },
  });
  await server.listen();
  const data = new ArbiterClient(join(f.dir, "arbiter.sock"));
  const admin = new ArbiterClient(join(f.dir, "admin.sock"));
  try {
    await fn({ data, admin, logs, opened });
  } finally {
    data.close();
    admin.close();
    await server.close();
  }
}

function storeText(f: Fixture): { events: string; proposals: string } {
  const eventsDir = join(f.dir, "events");
  const events = existsSync(eventsDir)
    ? readdirSync(eventsDir, { recursive: true, withFileTypes: true })
      .filter((e) => e.isFile()).map((e) => readFileSync(join(e.parentPath, e.name), "utf8")).join("")
    : "";
  const db = new Database(join(f.dir, "mandu.db"));
  const proposals = JSON.stringify(db.prepare("SELECT * FROM policy_proposals").all()) + JSON.stringify(db.prepare("SELECT * FROM policy_changes").all());
  db.close();
  return { events, proposals };
}

test("S2 through the real arbiter: three workspace suggestions, covered files never opened, one suggestion for a file both scans find, apply, dismiss, rescan, no value anywhere", async () => {
  const f = fixture();
  const replies: string[] = [];
  await rig(f, {}, async ({ data, admin, logs, opened }) => {
    const r = await data.suggestPolicy([f.proj], { home: f.home });
    replies.push(JSON.stringify(r));
    assert.equal(r.axis, true);
    assert.equal(r.running, false);
    const ws = r.workspaceScan!;
    assert.ok(ws, "the workspace scan ran (sources absent: both)");
    assert.deepEqual(ws.roots, [{ root: f.proj, tier: "workspace" }]);
    assert.equal(ws.counts.covered, 2, ".env.staging (the catalog) and private/ledger.txt (a label)");
    assert.ok(!opened.includes(join(f.proj, ".env.staging")), "a catalog-covered file is never opened");
    assert.ok(!opened.includes(join(f.proj, "private", "ledger.txt")), "a labelled file is never opened");
    assert.ok(!opened.some((p) => p.includes("/.git/")), "history is S1's job");
    assert.ok(opened.includes(join(f.proj, "README.md")), "the placeholder file is read, and gives no finding");
    assert.equal(r.counts.findings, 1 + 4, "history: settings.py; workspace: staging.conf, config.toml, deploy.md, settings.py");
    assert.equal(r.counts.filed, 4, JSON.stringify(r.counts));
    assert.equal(r.counts.alreadyPending, 1, "settings.py: the history suggestion is the one");

    const byPath = new Map(r.suggestions.map((s) => [s.evidence.paths.join(","), s]));
    const settings = byPath.get("settings.py")!;
    assert.equal(settings.source, "git-history");
    assert.equal(r.suggestions.filter((s) => s.evidence.paths.includes("settings.py")).length, 1, "one suggestion, not two");
    for (const [rel, rule] of [["deploy/staging.conf", "github-token"], ["config.toml", "credential-assignment"], ["notes/deploy.md", "aws-access-key-id"]] as const) {
      const s = byPath.get(rel);
      assert.ok(s, `${rel} suggested`);
      assert.equal(s!.source, "workspace");
      assert.equal(s!.rotate, false);
      assert.equal(s!.historyOnly, false);
      assert.equal(s!.repoRoot, f.proj);
      assert.equal(s!.requestedBy, "mandu:scan");
      assert.equal(s!.findingKey, `workspace:path:${join(f.proj, rel)}`);
      assert.deepEqual(s!.edits, [{ op: "lock-path", path: join(f.proj, rel), level: "no-model" }]);
      assert.deepEqual(s!.impact, { historicalVersions: 0, workingTreeChanges: true, files: [rel] });
      assert.equal(s!.evidence.findings[0]!.blob, "");
      assert.equal(s!.evidence.findings[0]!.firstCommit, null);
      assert.equal(s!.evidence.findings[0]!.detectors[0]!.rule, rule);
    }
    assert.equal(byPath.get("deploy/staging.conf")!.sentence, "Make ~/proj/deploy/staging.conf a secret no AI may read");
    assert.equal(byPath.get("deploy/staging.conf")!.evidence.findings[0]!.detectors[0]!.mask, "ghp_…");
    assert.equal(byPath.get("config.toml")!.evidence.findings[0]!.detectors[0]!.mask, "db_password=…");
    assert.equal(byPath.get("notes/deploy.md")!.evidence.findings[0]!.detectors[0]!.mask, "AKIA…");
    assert.ok(![...byPath.keys()].some((p) => p.includes("README")), "a placeholder is not a finding");

    // Apply a workspace suggestion on the DATA socket: the paths: lock.
    const conf = byPath.get("deploy/staging.conf")!;
    const applied = await data.applySuggestion(conf.id);
    replies.push(JSON.stringify(applied));
    assert.equal(applied.applied, true, JSON.stringify(applied));
    const law = await data.policyDocument();
    const lock = (law.inForce as { paths?: Array<{ path: string; level: string }> }).paths?.find((p) => p.path === join(f.proj, "deploy", "staging.conf"));
    assert.deepEqual(lock, { path: join(f.proj, "deploy", "staging.conf"), level: "no-model" });
    const change = (await data.policyChanges(1)).changes[0]!;
    assert.equal(change.via, "agent-tighten");
    assert.equal(change.proposedBy, "mandu:scan");

    // "Not a secret" is refused on the data socket, done on the admin one.
    const notes = byPath.get("notes/deploy.md")!;
    await assert.rejects(() => data.dismissSuggestion(notes.id), new RegExp(adminOnlyError("dismissSuggestion").replace(/[()']/g, ".")));
    replies.push(JSON.stringify(await admin.dismissSuggestion(notes.id, "human:e2e")));

    // A rescan files nothing: the applied file is covered now (not opened),
    // the dismissed one stays dismissed, the rest are pending.
    opened.length = 0;
    const again = await data.suggestPolicy([f.proj], { home: f.home });
    replies.push(JSON.stringify(again));
    assert.equal(again.counts.filed, 0, JSON.stringify(again.counts));
    assert.equal(again.counts.dismissed, 1);
    assert.equal(again.counts.alreadyPending, 3, "config.toml, settings.py twice");
    assert.equal(again.workspaceScan!.counts.covered, 3);
    assert.ok(!opened.includes(join(f.proj, "deploy", "staging.conf")), "the file the person locked is not opened again");
    assert.ok(again.workspaceScan!.counts.cached > 0, "unchanged files come from the in-memory cache");

    // The home tier, and the walk alone.
    const home = await data.suggestPolicy([f.proj], { home: f.home, sources: ["workspace"], includeHome: true });
    replies.push(JSON.stringify(home));
    assert.equal(home.scan, null, "no history scan was asked for");
    assert.deepEqual(home.workspaceScan!.roots.map((x) => [x.root, x.tier]), [[f.proj, "workspace"], [f.home, "home"]]);
    assert.equal(home.counts.filed, 1, JSON.stringify(home.counts));
    const tools = home.suggestions.find((s) => s.evidence.paths.includes("tools.toml"))!;
    assert.equal(tools.repoRoot, f.home);
    assert.equal(tools.sentence, "Make ~/tools.toml a secret no AI may read");
    assert.ok(!opened.includes(join(f.home, "notes.txt")), "the home tier reads name-hinted files only");

    // The oracle.
    replies.push(JSON.stringify(await admin.policySuggestions()), JSON.stringify(await admin.policyProposals(undefined)));
    const { events, proposals } = storeText(f);
    assert.match(events, /"policySuggestion":\{"action":"filed"/);
    for (const [what, s] of [["the op replies", replies.join("\n")], ["the event store", events], ["the proposals and changes tables", proposals], ["the arbiter log", logs.join("\n")], ["policy.yaml", readFileSync(f.policy, "utf8")]] as const) {
      noValue(what, s);
    }
  });
});

test("§5.5 over both scans: with a budget the reply comes first; the background job files the workspace suggestions", async () => {
  const f = fixture();
  await rig(f, { slowMs: 20 }, async ({ data }) => {
    const r: SuggestPolicyResult = await data.suggestPolicy([f.proj], { home: f.home, waitMs: 0 });
    assert.equal(r.running, true);
    assert.equal(r.workspaceScan, null);
    const deadline = Date.now() + 60_000;
    let ws = 0;
    while (Date.now() < deadline) {
      ws = (await data.policySuggestions("pending")).suggestions.filter((s) => s.source === "workspace").length;
      // One filing lands every suggestion at once: stop at the first count, so a
      // wrong one fails the assert below at once, not at the deadline.
      if (ws >= 3) break;
      await new Promise((res) => setTimeout(res, 100));
    }
    assert.equal(ws, 3, "the background job filed the workspace suggestions");
  });
});

test("axis OFF: suggestPolicy answers empty with workspaceScan null, and opens nothing", async () => {
  const f = fixture();
  await rig(f, { confidentiality: false }, async ({ data, opened }) => {
    const r = await data.suggestPolicy([f.proj], { home: f.home, includeHome: true });
    assert.equal(r.axis, false);
    assert.equal(r.workspaceScan, null);
    assert.deepEqual(r.suggestions, []);
    assert.deepEqual(opened, []);
  });
});
