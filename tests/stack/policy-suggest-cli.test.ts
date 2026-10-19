/**
 * policy-suggest-cli e2e — `mandu policy suggest` and the launch-time notice
 * (confidentiality-plan-14-policy-suggestions.md §5.3, §5.5) over their
 * PRODUCTION path: the launcher's `realPolicySuggestDeps()` (ndjsonCall, the
 * op names it sends: suggestPolicy, applySuggestion) and `startLaunchSuggest`,
 * against a REAL ArbiterServer holding a file-backed law, over a REAL fixture
 * repository:
 *
 *   - a deploy key committed and then deleted (C17): `--json` lists its
 *     lock-path suggestion; a scripted terminal session ([p], then [a])
 *     applies it on the DATA socket and the law shows the lock;
 *   - a token once inline in `config.py`, since removed: a lock-blob
 *     suggestion, skipped (and not appliable until the grammar has the op);
 *   - a labelled file holding a key: covered;
 *   - a token in `deploy/staging.conf`, on disk and never committed (plan 14
 *     §13, the workspace scan; a name the catalog misses): `--json` lists
 *     it as `source: "workspace"` with the scan's `workspaceScan`, the
 *     launch notice counts it "in this project", and the scripted session
 *     applies it (the law shows its `lock-path`);
 *   - `--apply-all` with no terminal is refused and changes nothing;
 *   - the launch notice counts what still waits in this repository; after
 *     a finished scan of it (§5.5) it answers at once from that scan's
 *     result, says so, and the arbiter scans again in the background.
 *
 * Only the arbiter lookup and the terminal (keys, TTY) are injected.
 *
 * The oracle (implementation-plan.md §9): no byte of either secret, and no
 * 8-character run of either body, in the command's stdout or stderr (text and
 * --json), the launch notice, or policy.yaml. Axes stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { POLICY_EDIT_OPS } from "../../arbiter/policy/policy-edit.js";
import type { ApplySuggestionResult, SuggestionView, SuggestPolicyResult } from "../../arbiter/ipc/protocol.js";
import {
  realPolicySuggestDeps, runPolicySuggest, startLaunchSuggest, EARLIER_SCAN_NOTE,
  type ApplySuggestionWire, type PolicySuggestDeps, type SuggestionViewWire, type SuggestPolicyWire, type WorkspaceScanWire,
} from "../../launcher/src/policy-suggest.js";
import type { Layout } from "../../launcher/src/services/layout.js";
import { stateAxes } from "../../arbiter/test/axes.js";
import { randomSecretBody } from "../../arbiter/test/helpers/random-secret.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

// The launcher's wire mirror takes the arbiter's types as they are (a
// compile-time parity check: `npm run typecheck` fails when they drift).
const wireParity = (v: SuggestionView, r: SuggestPolicyResult, a: ApplySuggestionResult): [SuggestionViewWire, SuggestPolicyWire, ApplySuggestionWire] => [v, r, a];
void wireParity;
// And the other way for what the launcher reads of the workspace scan (plan
// 14 §13.5): the arbiter must still send `workspaceScan` (the launcher's
// field is optional, for an older arbiter) and every `source` it names must
// be one the launcher renders.
const workspaceParity = (r: SuggestPolicyResult): WorkspaceScanWire | null => r.workspaceScan;
const sourceParity = (s: SuggestionViewWire["source"]): SuggestionView["source"] => s;
void workspaceParity; void sourceParity;

const LOCK_BLOB_KNOWN = (POLICY_EDIT_OPS as readonly string[]).includes("lock-blob");

// Assembled at run time from random bytes: no key-shaped literal here.
// A letter and a digit, no placeholder run: a value the detectors take
// (a plain random draw has no digit 0.19% of the time; random-secret.ts).
const alnum = randomSecretBody;
const KEY_BODY = alnum(96);
const PEM = `-----BEGIN OPENSSH ` + `PRIVATE KEY-----\n${KEY_BODY}\n-----END OPENSSH PRIVATE KEY-----\n`;
const TOKEN_BODY = alnum(36);
const TOKEN = "gh" + "p_" + TOKEN_BODY;
// The workspace file's token (plan 14 §13): on disk, never committed.
const WS_BODY = alnum(36);
const WS_TOKEN = "gh" + "p_" + WS_BODY;
const RUNS = [KEY_BODY, TOKEN_BODY, WS_BODY].flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));

function noValue(what: string, s: string): void {
  assert.ok(!s.includes(PEM) && !s.includes(TOKEN) && !s.includes(KEY_BODY) && !s.includes(TOKEN_BODY) && !s.includes(WS_BODY), `${what} carries a secret`);
  const hit = RUNS.find((r) => s.includes(r));
  assert.equal(hit, undefined, `${what} carries an 8-character run of a secret's body`);
}

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

test("mandu policy suggest over the real arbiter: --json lists the deleted key and the workspace file, a scripted terminal applies both (the law shows the locks), --apply-all without a terminal refuses, the launch notice counts what waits in this project; no value in any output", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-suggest-cli-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: repo, env: gitEnv, encoding: "utf8" });
  const put = (rel: string, body: string): void => { mkdirSync(join(repo, rel, ".."), { recursive: true }); writeFileSync(join(repo, rel), body); };
  git("init", "-q", "-b", "main");
  put("README.md", "a project\n");
  put("config.py", `API_TOKEN = "${TOKEN}"\n`);
  put("protected.txt", `token ${TOKEN}\n`);
  git("add", "."); git("commit", "-qm", "init");
  put("deploy/id_ed25519", PEM);
  git("add", "."); git("commit", "-qm", "add deploy key");
  const added = git("rev-parse", "HEAD").trim();
  git("rm", "-q", "deploy/id_ed25519");
  put("config.py", "import os\nAPI_TOKEN = os.environ['API_TOKEN']\n");
  git("add", "."); git("commit", "-qm", "remove the key; read the token from the environment");
  // Untracked, so only the workspace scan sees it; `.env.staging` would be
  // the catalog's (`shape:.env*`) and never opened.
  put("deploy/staging.conf", `[api]\nAPI_TOKEN=${WS_TOKEN}\n`);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(repo, "protected.txt")}\n    level: no-model\n`);

  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: policy, policyPollMs: 0, confidentiality: true, integrity: false, log: () => {},
  });
  await server.listen();
  const env = { HOME: home, NO_COLOR: "1", PATH: process.env["PATH"] ?? "/usr/bin:/bin" };
  const outputs: string[] = [];
  // The production deps; only the arbiter lookup (the resident one here) and
  // the terminal are injected.
  const deps = (o: { tty: boolean; keys?: string[]; lines?: string[] }): { d: PolicySuggestDeps; out: string[]; err: string[] } => {
    const out: string[] = [], err: string[] = [];
    const keys = [...(o.keys ?? [])], lines = [...(o.lines ?? [])];
    return {
      out, err,
      d: {
        ...realPolicySuggestDeps(),
        arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }),
        cwd: () => repo,
        isTTY: () => o.tty,
        readKey: async () => keys.shift() ?? "",
        readLine: async () => lines.shift() ?? "",
        out: (s) => { out.push(s); outputs.push(s); },
        err: (s) => { err.push(s); outputs.push(s); },
      },
    };
  };
  const client = new ArbiterClient(sock);
  try {
    // ── --json (no terminal): the scan files, the command lists
    const j = deps({ tty: false });
    assert.equal(await runPolicySuggest(["--json"], env, {} as Layout, j.d), 0, j.err.join(""));
    const listed = JSON.parse(j.out.join("")) as { suggestions: SuggestionViewWire[]; covered: Array<{ paths: string[] }>; canApply: boolean; workspaceScan: WorkspaceScanWire | null };
    const key = listed.suggestions.find((s) => s.source === "git-history" && s.edits[0]?.op === "lock-path")!;
    const ws = listed.suggestions.find((s) => s.source === "workspace")!;
    const blob = listed.suggestions.find((s) => s.edits[0]?.op === "lock-blob")!;
    assert.ok(key, "the deleted deploy key is listed");
    assert.deepEqual(key.edits, [{ op: "lock-path", path: join(repo, "deploy/id_ed25519"), level: "no-model" }]);
    assert.equal(key.evidence.findings[0]!.firstCommit, added);
    assert.equal(key.evidence.findings[0]!.detectors[0]!.mask, "-----BEGIN OPENSSH " + "PRIVATE KEY-----…");
    assert.equal(blob.sentence, "Hide an old version of ~/proj/config.py from the AI");
    assert.deepEqual(listed.covered.map((c) => c.paths), [["protected.txt"]]);
    assert.equal(listed.canApply, true);
    // The workspace file (plan 14 §13.4): one path lock, no commits, no
    // exposure claim; the scan's summary rides along.
    assert.ok(ws, `the workspace file is listed: ${JSON.stringify(listed.suggestions.map((s) => s.findingKey))}`);
    assert.deepEqual(ws.edits, [{ op: "lock-path", path: join(repo, "deploy/staging.conf"), level: "no-model" }]);
    assert.equal(ws.repoRoot, repo);
    assert.equal(ws.rotate, false);
    assert.equal(ws.historyOnly, false);
    assert.deepEqual(ws.impact, { historicalVersions: 0, workingTreeChanges: true, files: ["deploy/staging.conf"] });
    const wf = ws.evidence.findings[0]!;
    assert.deepEqual([wf.blob, wf.firstCommit, wf.lastCommit, wf.inHead, wf.stillPresent], ["", null, null, false, true]);
    assert.equal(wf.detectors[0]!.rule, "github-token");
    assert.equal(wf.detectors[0]!.line, 2);
    assert.equal(listed.suggestions.length, 3);
    assert.ok(listed.workspaceScan !== null && listed.workspaceScan.roots.some((r) => r.root === repo && r.tier === "workspace"), JSON.stringify(listed.workspaceScan));
    assert.ok(listed.workspaceScan!.counts.read >= 1);
    assert.ok(listed.workspaceScan!.counts.covered >= 1, "the labelled protected.txt is covered, not opened");

    // ── the launch notice counts it, with the history ones, "in this project";
    // the --json run above finished a scan of this repository, so the launch
    // answers at once from it (§5.5) and says so, while a new scan runs.
    const t0 = Date.now();
    const all = await startLaunchSuggest({ sock, cwd: repo, home, env: { MANDU_SUGGEST_WAIT_MS: "20000" } });
    assert.ok(Date.now() - t0 < 5_000, `answered from the earlier scan without waiting out the budget (${Date.now() - t0} ms)`);
    assert.equal(all, "mandu: 3 possible keys in this project are not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard" + EARLIER_SCAN_NOTE);
    outputs.push(all!);

    // ── --apply-all without a terminal: refused, nothing changed
    const beforeRefusal = readFileSync(policy, "utf8");
    const r = deps({ tty: false, lines: ["apply"] });
    assert.equal(await runPolicySuggest(["--apply-all"], env, {} as Layout, r.d), 2);
    assert.match(r.err.join(""), /--apply-all needs a terminal to confirm on/);
    assert.equal(readFileSync(policy, "utf8"), beforeRefusal);
    assert.equal((await client.policySuggestions("pending")).suggestions.length, 3);

    // ── a scripted terminal: [p] shows the lines, [a] applies the key; the blob one is skipped;
    // [a] applies the workspace file (history-only suggestions come first, so the deleted
    // key is [1/3]; then oldest first, and the history ones are filed first).
    const t = deps({ tty: true, keys: ["p", "a", "s", "a"] });
    assert.equal(await runPolicySuggest([], env, {} as Layout, t.d), 0, t.err.join("") + t.out.join(""));
    const screen = t.out.join("");
    assert.match(screen, /\[1\/3\] Make ~\/proj\/deploy\/id_ed25519 a secret no AI may read \(only in git history\)/);
    assert.match(screen, /^Scanned the git history of ~\/proj \(\d+ file versions? read in [\d.]+ s\) and \d+ files? in ~\/proj \(/m, screen);
    assert.ok(screen.includes("looks like a private key · -----BEGIN OPENSSH " + "PRIVATE KEY-----… (line 1)"), "the mask, as the scan made it");
    assert.match(screen, new RegExp(`deploy/id_ed25519: added ${added.slice(0, 8)}, removed or replaced `));
    assert.match(screen, /This key was exposed\. Rotate it/);
    assert.match(screen, new RegExp(`paths:\\n {10}- path: ${join(repo, "deploy/id_ed25519").replace(/[.]/g, "\\.")}\\n {10}  level: no-model`));
    assert.match(screen, /Applied \(change pc-\d+; undo it in the dashboard, under Rule changes in Approvals\)\./);
    assert.match(screen, /\[2\/3\] Hide an old version of ~\/proj\/config\.py from the AI/);
    // The workspace screen (§13.6): its hit, no commit line, the softer advice.
    const wsScreen = screen.slice(screen.indexOf("[3/3]"));
    assert.match(wsScreen, /^\[3\/3\] Make ~\/proj\/deploy\/staging\.conf a secret no AI may read\n/);
    assert.match(wsScreen, /looks like a GitHub token · ghp_… \(line 2\)\n {6}hides: this file, from the next launch\n {6}If an AI session read this file before, rotate the key\.\n/);
    assert.doesNotMatch(wsScreen.split("\n\n")[0]!, /added|removed or replaced|This key was exposed/);
    assert.match(screen, /Not a secret\? Say so in the dashboard/);
    if (!LOCK_BLOB_KNOWN) assert.match(screen, /this Mandu cannot apply lock-blob yet/);
    assert.match(screen, /Applied 2, skipped 1\./);

    // The law shows the lock, applied on the DATA socket as a tightening.
    const law = await client.policyDocument();
    const lock = (law.inForce as { paths?: Array<{ path: string; level: string }> }).paths?.find((p) => p.path === join(repo, "deploy/id_ed25519"));
    assert.deepEqual(lock, { path: join(repo, "deploy/id_ed25519"), level: "no-model" });
    const change = (await client.policyChanges(5)).changes.find((c) => c.proposalId === key.id)!;
    assert.equal(change.via, "agent-tighten");
    assert.equal(change.proposalId, key.id);
    assert.equal(change.proposedBy, "mandu:scan");
    const wsLock = (law.inForce as { paths?: Array<{ path: string; level: string }> }).paths?.find((p) => p.path === join(repo, "deploy/staging.conf"));
    assert.deepEqual(wsLock, { path: join(repo, "deploy/staging.conf"), level: "no-model" }, "the workspace file's lock-path");
    const wsChange = (await client.policyChanges(5)).changes.find((c) => c.proposalId === ws.id)!;
    assert.equal(wsChange.via, "agent-tighten");
    assert.equal(wsChange.proposedBy, "mandu:scan");

    // ── --dry-run now: one left, nothing applied
    const d = deps({ tty: true, keys: ["a"] });
    assert.equal(await runPolicySuggest(["--dry-run"], env, {} as Layout, d.d), 0);
    assert.match(d.out.join(""), /1 suggestion waits for you/);
    assert.equal((await client.policySuggestions("pending")).suggestions.length, 1);

    // ── the launch notice (§5.5): what still waits in this repository
    const notice = await startLaunchSuggest({ sock, cwd: join(repo), home, env: { MANDU_SUGGEST_WAIT_MS: "20000" } });
    assert.equal(notice, "mandu: 1 possible key in this project is not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard" + EARLIER_SCAN_NOTE);
    outputs.push(notice!);
    const elsewhere = mkdtempSync(join(tmpdir(), "mdu-suggest-cli-other-"));
    dirs.push(elsewhere);
    assert.equal(await startLaunchSuggest({ sock, cwd: elsewhere, home, env: { MANDU_SUGGEST_WAIT_MS: "20000" } }), null, "not this repository: no line");

    // ── the lock-blob one, from the terminal: the old version locked by id,
    // the current config.py not locked (plan 14 §8.2)
    if (LOCK_BLOB_KNOWN) {
      const b = deps({ tty: true, keys: ["a"] });
      assert.equal(await runPolicySuggest([], env, {} as Layout, b.d), 0, b.err.join("") + b.out.join(""));
      const bs = b.out.join("");
      assert.match(bs, /\[1\/1\] Hide an old version of ~\/proj\/config\.py from the AI/);
      assert.match(bs, /hides: 1 old version of config\.py · the current config\.py stays readable to the AI/);
      assert.match(bs, /Applied \(change pc-\d+;/);
      const yaml = readFileSync(policy, "utf8");
      assert.match(yaml, new RegExp(`blobs:\\n\\s+- id: sha1:${blob.evidence.blobs[0]}`));
      assert.doesNotMatch(yaml, /config\.py\n\s+level/, "no path lock on the current config.py");
      assert.equal((await client.policySuggestions("pending")).suggestions.length, 0);
      assert.equal(await startLaunchSuggest({ sock, cwd: repo, home, env: { MANDU_SUGGEST_WAIT_MS: "20000" } }), null, "nothing waits: no line");
    }

    // ── the oracle
    for (const [what, s] of [["the command's output", outputs.join("\n")], ["policy.yaml", readFileSync(policy, "utf8")]] as const) noValue(what, s);
    // The launch's background scan ends before the arbiter closes (a call
    // with no budget is refused while one runs).
    for (let i = 0; i < 600; i++) {
      try { await client.suggestPolicy([repo], { home }); break; } catch { await new Promise((r) => setTimeout(r, 100)); }
    }
  } finally {
    client.close();
    await server.close();
  }
});
