/**
 * dashboard-suggestions e2e — the Files and folders explorer's Suggested view
 * (dashboard.md §4.25r, confidentiality-plan-14-policy-suggestions.md §5.4)
 * through the PRODUCTION wiring: `makeApprovalsArbiter(dataSock, () =>
 * ({ socketPath: adminSock }))` over a REAL ArbiterServer with a file-backed
 * law, a real DashboardServer, the real git-history scan and a REAL fixture
 * repository holding
 *
 *   - a deploy key committed and then deleted (C17),
 *   - a token committed in `secrets/prod.env` and then deleted,
 *   - a token once inline in `config.py`, since removed (a lock-blob).
 *
 *   0. parity: the adapter forwards suggestPolicy, policySuggestions and
 *      dismissSuggestion (and resolvePolicyProposal), so what the routes see
 *      is the arbiter's own, not a test bridge's;
 *   1. the GET and every POST need the CSRF header and the admin session;
 *   2. Scan over the folder the recorded session worked in files the three;
 *      the GET lists them: two paths only git history holds, and the old
 *      version of config.py under its file;
 *   3. one Save of the deploy key and the old config.py: the law shows the
 *      lock-path and the lock-blob at once, each a change proposed by
 *      mandu:scan (on an arbiter without lock-blob, that one is refused and
 *      stays waiting);
 *   4. Not a secret needs the admin channel (an adopted arbiter → 503, still
 *      waiting); with it, prod.env is dismissed, and a rescan files nothing
 *      again: the key is covered by the law, prod.env stays dismissed;
 *   5. the oracle: no response body holds either secret, or any 8-character
 *      run of either body.
 *
 * A history git could not fully read (every blob read comes back empty, as
 * when the git sandbox fails to start): the page says part of the history
 * could not be read, never that the time budget ran out; the arbiter counts
 * the blobs `readFailed` and files only what the names show (the deleted
 * key and .env; the old config.py needs its content) (secret-discovery.md §3
 * §2). Fixture tokens are drawn by arbiter/test/helpers/random-secret.ts,
 * never digit-less: a digit-less body is no token to the detector, and a
 * plain draw filed 2, not 3, in CI job gl-7778-12993.
 *
 * The workspace-scan test (plan 14 §13.6) runs through the same
 * wiring: a work tree with a clean history, an untracked
 * `deploy/staging.conf` holding a token (a name the catalog misses), an
 * `.env.staging` the catalog covers, and a name-hinted `tools.toml` in HOME.
 * The scan lists the conf file as `source: "workspace"` (an ordinary row,
 * no commits, the detector's line, the softer advice), Save applies it
 * through the dashboard's apply route and the law shows its `lock-path`;
 * "Also look in your home folder" (`includeHome`) files `tools.toml`, which
 * Not a secret dismisses; and no response of the view, nor policy.yaml,
 * holds any of the three values or an 8-character run of one.
 *
 * Axes stated: secrets (confidentiality ON, integrity OFF).
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
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import type { EventSource, SessionRef } from "../../dashboard/src/event-source.js";
import type { ManduEvent } from "../../dashboard/src/event-model.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { randomSecretBody } from "../../arbiter/test/helpers/random-secret.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

// Assembled at run time from random bytes: this file holds no key-shaped
// literal, and a run of a body cannot match an id or a path by accident.
// A letter and a digit, no placeholder run: a value the detectors take
// (a plain random draw has no digit 0.19% of the time; random-secret.ts).
const alnum = randomSecretBody;
const KEY_BODY = alnum(96);
const PEM = `-----BEGIN OPENSSH ` + `PRIVATE KEY-----\n${KEY_BODY}\n-----END OPENSSH ` + `PRIVATE KEY-----\n`;
const TOKEN_BODY = alnum(36);
const TOKEN = "gh" + "p_" + TOKEN_BODY;
const TOKEN2_BODY = alnum(36);
const TOKEN2 = "gh" + "p_" + TOKEN2_BODY;
const RUNS = [KEY_BODY, TOKEN_BODY, TOKEN2_BODY].flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));

function noValue(what: string, s: string): void {
  assert.ok(!s.includes(PEM) && !s.includes(TOKEN) && !s.includes(TOKEN2), `${what} carries a secret`);
  const hit = RUNS.find((r) => s.includes(r));
  assert.equal(hit, undefined, `${what} carries an 8-character run of a secret's body`);
}

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function fixture(): { dir: string; home: string; repo: string; policy: string } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dash-suggest-"));
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
  git("add", "."); git("commit", "-qm", "init");
  put("deploy/id_ed25519", PEM);
  put("secrets/prod.env", `GITHUB_TOKEN=${TOKEN2}\n`);
  git("add", "."); git("commit", "-qm", "add deploy key and prod env");
  git("rm", "-q", "deploy/id_ed25519", "secrets/prod.env");
  put("config.py", "import os\nAPI_TOKEN = os.environ['API_TOKEN']\n");
  git("add", "."); git("commit", "-qm", "remove the keys");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  return { dir, home, repo, policy };
}

/** One recorded live session that worked in `cwd` (what the home shows per
 *  agent): the scan's default folder. */
function sessionIn(cwd: string): EventSource {
  const now = new Date().toISOString();
  const ref: SessionRef = { id: "s-live-1", label: null, eventCount: 1, firstTs: now, lastTs: now, violated: false };
  return {
    async listSessions() { return [ref]; },
    async readEvents(): Promise<ManduEvent[]> {
      return [{
        id: "e1", seq: 0, ts: now, sessionId: ref.id, turn: 0, kind: "tllm_call", view: "AgentView", boundary: "model_context",
        emitter: "anthropic-proxy", callId: null, parentId: null, input: null, output: null, invariant: { violatedInvariant: false },
        fullInput: { blocks: [{ role: "system", source: "agent", text: `<env>\nWorking directory: ${cwd}\n</env>` }] },
      } as unknown as ManduEvent];
    },
    subscribe() { return () => {}; },
    close() {},
  };
}

test("Suggested view over the real arbiter: scan, list, Save applies the lock, Not a secret only on the admin channel, a rescan refiles nothing, no value in any body", async () => {
  const f = fixture();
  const dataSock = join(f.dir, "arbiter.sock");
  const adminSock = join(f.dir, "admin.sock");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(f.dir, "mandu.db"), eventDir: join(f.dir, "events"),
    policyPath: f.policy, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
  });
  await arbiter.listen();
  const gate = new ArbiterClient(dataSock);
  await gate.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  // An adopted arbiter: the same data socket, no admin channel.
  const adopted = await makeApprovalsArbiter(dataSock, () => undefined);
  assert.ok(wired?.policyDoc && adopted?.policyDoc);
  // 0. Parity: the production adapter forwards every op the view uses.
  for (const op of ["suggestPolicy", "policySuggestions", "dismissSuggestion", "resolvePolicyProposal"] as const) {
    assert.equal(typeof wired.policyDoc[op], "function", `the adapter forwards ${op}`);
  }
  const mk = (policyDoc: NonNullable<typeof wired>["policyDoc"]) => new DashboardServer({
    source: sessionIn(f.repo), policyDocArbiter: policyDoc, fileBrowserHome: f.home, log: () => {}, ...ADMIN_OPTS,
  });
  const server = mk(wired.policyDoc);
  const adoptedServer = mk(adopted.policyDoc);
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  const adoptedBase = `http://127.0.0.1:${await adoptedServer.listen(0)}`;
  const bodies: string[] = [];
  const call = async (method: "GET" | "POST", path: string, body?: unknown, headers: Record<string, string> = CSRF_ADMIN, at = base) => {
    const r = await fetch(at + path, { method, headers: { ...headers, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const text = await r.text();
    bodies.push(text);
    return { status: r.status, body: JSON.parse(text) as any };
  };

  try {
    // 1. The gates: the CSRF header and the admin session, for the GET too.
    assert.equal((await call("GET", "/api/suggestions", undefined, {})).status, 403);
    assert.equal((await call("GET", "/api/suggestions", undefined, { "X-Mandu-Control": "1" })).status, 403);
    assert.equal((await call("POST", "/api/suggestions/scan", {}, { "X-Mandu-Control": "1" })).status, 403);
    assert.equal((await call("POST", "/api/suggestions/dismiss", { id: "pp-000001" }, { "X-Mandu-Control": "1" })).status, 403);
    assert.equal((await gate.policySuggestions()).suggestions.length, 0, "nothing was scanned or filed");

    // 2. Scan over the folder the recorded session worked in.
    const scan = await call("POST", "/api/suggestions/scan", {});
    assert.equal(scan.status, 200, JSON.stringify(scan.body));
    assert.equal(scan.body.scan.running, false);
    assert.deepEqual(scan.body.scan.roots, ["~/proj"]);
    // The whole history was read (no cap, no failed read): a short count
    // below would otherwise be a partial scan, not a missed finding.
    assert.doesNotMatch(scan.body.scan.summary, /there may be more/, scan.body.scan.summary);
    assert.equal(scan.body.scan.filed, 3, scan.body.scan.summary);
    assert.match(scan.body.scan.summary, /^Scanned the git history of ~\/proj and \d+ files?\. 3 possible keys to review\./, "it names both scans");
    const listed = await call("GET", "/api/suggestions");
    assert.equal(listed.status, 200);
    assert.equal(listed.body.count, 3);
    const byName = (name: RegExp) => listed.body.suggestions.find((s: any) => name.test(s.name));
    const key = byName(/^id_ed25519$/);
    const env = byName(/^prod\.env$/);
    const blob = byName(/old version of config\.py$/);
    assert.ok(key && env && blob, JSON.stringify(listed.body.suggestions.map((s: any) => s.name)));
    assert.equal(key.tag, "only in git history");
    assert.equal(key.path, join(f.repo, "deploy/id_ed25519"));
    assert.ok(key.found.some((x: any) => x.words === "Looks like a private key"));
    assert.equal(env.tag, "only in git history");
    assert.equal(blob.kind, "versions");
    assert.equal(blob.parent.display, "~/proj/config.py");
    assert.equal(blob.tag, null);

    // 3. Save (one click, both ticked): the key's lock-path and the old
    //    config.py's lock-blob apply at once, each its own change; on an
    //    arbiter whose grammar lacks lock-blob that one is refused and waits.
    const save = await call("POST", "/api/suggestions/apply", { ids: [key.id, blob.id] });
    assert.equal(save.status, 200, JSON.stringify(save.body));
    assert.equal(save.body.applied[0].id, key.id);
    const law = await gate.policyDocument();
    const inForce = law.inForce as { paths?: Array<{ path: string; level: string }>; blobs?: Array<{ id: string; level: string }> };
    const lock = inForce.paths?.find((p) => p.path === join(f.repo, "deploy/id_ed25519"));
    assert.deepEqual(lock, { path: join(f.repo, "deploy/id_ed25519"), level: "no-model" }, "the law shows the lock-path");
    assert.match(readFileSync(f.policy, "utf8"), /deploy\/id_ed25519/);
    const changes = (await gate.policyChanges(5)).changes;
    const change = changes.find((c) => c.id === save.body.applied[0].changeId)!;
    assert.ok(change, "the Save is in History");
    assert.equal(change.via, "proposal", "approved by a human on the admin channel");
    assert.equal(change.proposedBy, "mandu:scan");
    assert.equal(change.requestedBy, "dashboard");
    if (blob.applicable) {
      assert.deepEqual(save.body.applied.map((a: any) => a.id), [key.id, blob.id]);
      assert.notEqual(save.body.applied[0].changeId, save.body.applied[1].changeId, "one change per suggestion");
      const id = /^\s+- id: (\S+)$/m.exec(blob.yaml)![1];
      assert.deepEqual(inForce.blobs?.find((b) => b.id === id)?.level, "no-model", "the law shows the lock-blob");
      assert.doesNotMatch(readFileSync(f.policy, "utf8"), /config\.py\n\s+level/, "no path lock on the current config.py");
    } else {
      assert.equal(save.body.applied.length, 1);
      assert.match(save.body.refused[0].error, /cannot hide old versions of a file yet/);
      assert.ok(save.body.suggestions.some((s: any) => s.id === blob.id), "it stays waiting");
    }
    assert.ok(!save.body.suggestions.some((s: any) => s.id === key.id), "the saved one no longer waits");

    // 4. Not a secret: refused without the admin channel, done with it.
    const refused = await call("POST", "/api/suggestions/dismiss", { id: env.id }, CSRF_ADMIN, adoptedBase);
    assert.equal(refused.status, 503, JSON.stringify(refused.body));
    assert.ok((await gate.policySuggestions("pending")).suggestions.some((s) => s.id === env.id), "still waiting");
    const dismissed = await call("POST", "/api/suggestions/dismiss", { id: env.id });
    assert.equal(dismissed.status, 200, JSON.stringify(dismissed.body));
    assert.equal(dismissed.body.status, "denied");
    const rescan = await call("POST", "/api/suggestions/scan", { root: "~/proj" });
    assert.equal(rescan.status, 200);
    assert.equal(rescan.body.scan.filed, 0, rescan.body.scan.summary);
    assert.match(rescan.body.scan.summary, new RegExp(`${blob.applicable ? "2 keys are" : "1 key is"} already protected\\. 1 finding you marked as not a secret was left out\\.`));
    assert.ok(!rescan.body.suggestions.some((s: any) => s.id === env.id || s.id === key.id));

    // 5. The oracle: no body holds a secret or any 8-character run of one.
    noValue("the Suggested view's responses", bodies.join("\n"));
    noValue("policy.yaml", readFileSync(f.policy, "utf8"));
  } finally {
    await server.close();
    await adoptedServer.close();
    wired.close();
    adopted.close();
    gate.close();
    await arbiter.close();
  }
});

test("Suggested view, a history git could not fully read: the page says part could not be read (never the time budget), files what the names alone show, no value in any body", async () => {
  const f = fixture();
  const dataSock = join(f.dir, "arbiter.sock");
  const adminSock = join(f.dir, "admin.sock");
  // git hands no blob back (a git sandbox that failed to start): the content
  // detector sees nothing; the catalog still knows the deleted key's and
  // .env's names.
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(f.dir, "mandu.db"), eventDir: join(f.dir, "events"),
    policyPath: f.policy, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
    historyScanCacheDir: null, historyScan: { readBlobs: async () => Buffer.alloc(0) },
  });
  await arbiter.listen();
  const gate = new ArbiterClient(dataSock);
  await gate.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc);
  const server = new DashboardServer({
    source: sessionIn(f.repo), policyDocArbiter: wired.policyDoc, fileBrowserHome: f.home, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  const bodies: string[] = [];
  try {
    const r = await fetch(`${base}/api/suggestions/scan`, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, body: "{}" });
    const text = await r.text();
    bodies.push(text);
    assert.equal(r.status, 200, text);
    const summary: string = JSON.parse(text).scan.summary;
    assert.match(summary, /Part of the history could not be read, so there may be more\./, summary);
    assert.doesNotMatch(summary, /in time/, "not the time budget");
    // The arbiter's own answer: the blobs are readFailed, named, not overTime.
    const own = await gate.scanSecretHistory([f.repo]);
    bodies.push(JSON.stringify(own));
    // Every blob of the history (README, config.py twice, the key, prod.env).
    assert.equal(own.counts.blobs, 5);
    assert.equal(own.counts.scanned, 0);
    assert.equal(own.capped.readFailed, 5, JSON.stringify(own.capped));
    assert.equal(own.capped.overTime, 0);
    assert.ok(own.capped.lines.some((l) => /^5 blob\(s\) not read: git failed to hand them over$/.test(l)), own.capped.lines.join("; "));
    const names = own.findings.map((x) => x.paths.join(",")).sort();
    assert.deepEqual(names, ["deploy/id_ed25519", "secrets/prod.env"], "the names alone find the key and the .env; the old config.py needs its content");
    noValue("the responses of a partly read scan", bodies.join("\n"));
  } finally {
    await server.close();
    wired.close();
    gate.close();
    await arbiter.close();
  }
});

// ── The workspace scan (plan 14 §13.6): a file the catalog misses ───────────

const WS_TOKEN_BODY = alnum(36);
const WS_TOKEN = "gh" + "p_" + WS_TOKEN_BODY;
const COVERED_BODY = alnum(36);
const COVERED = "gh" + "p_" + COVERED_BODY;
const HOME_BODY = alnum(36);
const HOME_TOKEN = "gl" + "pat-" + HOME_BODY;
const WS_RUNS = [WS_TOKEN_BODY, COVERED_BODY, HOME_BODY].flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));

function noWorkspaceValue(what: string, s: string): void {
  for (const v of [WS_TOKEN, COVERED, HOME_TOKEN]) assert.ok(!s.includes(v), `${what} carries a secret`);
  const hit = WS_RUNS.find((r) => s.includes(r));
  assert.equal(hit, undefined, `${what} carries an 8-character run of a secret's body`);
}

/** A work tree whose history is clean, with an untracked
 *  `deploy/staging.conf` holding a token (a name the catalog misses), an
 *  `.env.staging` the catalog covers, and a name-hinted file in HOME. */
function workspaceFixture(): { dir: string; home: string; repo: string; policy: string } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dash-suggest-ws-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: repo, env: gitEnv, encoding: "utf8" });
  const put = (rel: string, body: string): void => { mkdirSync(join(repo, rel, ".."), { recursive: true }); writeFileSync(join(repo, rel), body); };
  git("init", "-q", "-b", "main");
  put("README.md", "# app\n\nSet API_KEY=your-api-key-here in your shell.\n");
  git("add", "."); git("commit", "-qm", "init");
  put("deploy/staging.conf", `[api]\nAPI_TOKEN=${WS_TOKEN}\n`);
  put(".env.staging", `TOKEN=${COVERED}\n`);
  writeFileSync(join(home, "tools.toml"), `[registry]\ntoken = "${HOME_TOKEN}"\n`);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  return { dir, home, repo, policy };
}

test("Suggested view, workspace scan: a file found as it is now is listed, applied through Save, shown in the law; the home folder on request; no value in any body", async () => {
  const f = workspaceFixture();
  const dataSock = join(f.dir, "arbiter.sock");
  const adminSock = join(f.dir, "admin.sock");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(f.dir, "mandu.db"), eventDir: join(f.dir, "events"),
    policyPath: f.policy, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
  });
  await arbiter.listen();
  const gate = new ArbiterClient(dataSock);
  await gate.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc);
  const server = new DashboardServer({
    source: sessionIn(f.repo), policyDocArbiter: wired.policyDoc, fileBrowserHome: f.home, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  const bodies: string[] = [];
  const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
    const r = await fetch(base + path, { method, headers: { ...CSRF_ADMIN, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const text = await r.text();
    bodies.push(text);
    return { status: r.status, body: JSON.parse(text) as any };
  };

  try {
    // includeHome is validated before the arbiter is asked.
    assert.equal((await call("POST", "/api/suggestions/scan", { includeHome: "yes" })).status, 400);
    assert.equal((await gate.policySuggestions()).suggestions.length, 0, "nothing was scanned or filed");

    // 1. Scan (both sources) over the folder the recorded session worked in.
    const scan = await call("POST", "/api/suggestions/scan", {});
    assert.equal(scan.status, 200, JSON.stringify(scan.body));
    assert.equal(scan.body.scan.running, false);
    assert.doesNotMatch(scan.body.scan.summary, /there may be more/, scan.body.scan.summary);
    assert.equal(scan.body.scan.filed, 1, scan.body.scan.summary);
    assert.match(scan.body.scan.summary, /^Scanned the git history of ~\/proj and \d+ files?\. 1 possible key to review\./);
    assert.match(scan.body.scan.summary, /1 file your rules already protect was not opened\./, ".env.staging is the catalog's");
    const listed = await call("GET", "/api/suggestions");
    assert.equal(listed.status, 200);
    assert.equal(listed.body.count, 1, JSON.stringify(listed.body.suggestions.map((s: any) => s.display)));
    const ws = listed.body.suggestions[0];
    assert.equal(ws.source, "workspace");
    assert.equal(ws.path, join(f.repo, "deploy/staging.conf"));
    assert.equal(ws.kind, "path");
    assert.equal(ws.tag, null, "an ordinary row: no 'only in git history' tag");
    assert.equal(ws.historyOnly, false);
    assert.deepEqual(ws.when, [], "no commit lines");
    assert.deepEqual(ws.found, [{ words: "Looks like a GitHub token", mask: "ghp_…", line: 2 }]);
    assert.equal(ws.rotateSoft, true);
    assert.match(ws.rotate, /^If an AI session read this file before, rotate the key/);
    assert.match(ws.impact, /from the next time an agent starts/);
    assert.equal(ws.by, "Suggested by Mandu's scan");
    assert.equal(ws.repo, "~/proj");
    assert.equal(ws.yaml, `paths:\n  - path: ${join(f.repo, "deploy/staging.conf")}\n    level: no-model`, "Show in policy.yaml");
    const raw = (await gate.policySuggestions("pending")).suggestions.find((s) => s.id === ws.id)!;
    assert.equal(raw.source, "workspace", "the arbiter's own view");

    // 2. Save applies it through the dashboard's apply route; the law shows the lock-path.
    const save = await call("POST", "/api/suggestions/apply", { ids: [ws.id] });
    assert.equal(save.status, 200, JSON.stringify(save.body));
    assert.deepEqual(save.body.applied.map((a: any) => a.id), [ws.id]);
    assert.deepEqual(save.body.refused, []);
    const law = await gate.policyDocument();
    const inForce = law.inForce as { paths?: Array<{ path: string; level: string }> };
    assert.deepEqual(inForce.paths?.find((p) => p.path === join(f.repo, "deploy/staging.conf")), { path: join(f.repo, "deploy/staging.conf"), level: "no-model" }, "the law shows the lock-path");
    const change = (await gate.policyChanges(5)).changes.find((c) => c.id === save.body.applied[0].changeId)!;
    assert.ok(change, "the Save is in History");
    assert.equal(change.proposedBy, "mandu:scan");
    assert.equal(change.requestedBy, "dashboard");
    assert.equal(save.body.count, 0);

    // 3. "Also look in your home folder": the home tier's name-hinted file.
    const homeScan = await call("POST", "/api/suggestions/scan", { includeHome: true });
    assert.equal(homeScan.status, 200, JSON.stringify(homeScan.body));
    assert.equal(homeScan.body.scan.includeHome, true);
    assert.equal(homeScan.body.scan.filed, 1, homeScan.body.scan.summary);
    assert.match(homeScan.body.scan.summary, /files? in ~\/proj and your home folder\. 1 possible key to review\./);
    const inHome = homeScan.body.suggestions.find((s: any) => s.path === join(f.home, "tools.toml"));
    assert.ok(inHome, JSON.stringify(homeScan.body.suggestions.map((s: any) => s.display)));
    assert.equal(inHome.source, "workspace");
    assert.equal(inHome.repo, "~");
    // Not a secret on it, per id, over the admin channel.
    const dismissed = await call("POST", "/api/suggestions/dismiss", { id: inHome.id });
    assert.equal(dismissed.status, 200, JSON.stringify(dismissed.body));
    assert.equal(dismissed.body.status, "denied");
    const rescan = await call("POST", "/api/suggestions/scan", { includeHome: true });
    assert.equal(rescan.body.scan.filed, 0, rescan.body.scan.summary);
    assert.match(rescan.body.scan.summary, /1 finding you marked as not a secret was left out\./);

    // 4. The oracle: no response of the Suggested view holds a secret or any
    //    8-character run of one; nor does policy.yaml.
    noWorkspaceValue("the Suggested view's responses", bodies.join("\n"));
    noWorkspaceValue("policy.yaml", readFileSync(f.policy, "utf8"));
  } finally {
    await server.close();
    wired.close();
    gate.close();
    await arbiter.close();
  }
});
