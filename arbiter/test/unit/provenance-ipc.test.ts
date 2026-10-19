/**
 * provenance-ipc.test.ts — IPC round-trip tests for the provenance (taint)
 * registry ops: taintProcess, processLineage, isProcessTainted, taintFile,
 * fileTrust.
 *
 * Mandu-new test (no reference origin). Stands up a real ArbiterServer on a
 * temp socket, connects a real ArbiterClient, and exercises all five provenance
 * ops over the wire.
 *
 * Run: npx tsx --test test/unit/provenance-ipc.test.ts
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

let workdir: string;
let server: ArbiterServer;
let client: ArbiterClient;

before(async () => {
  workdir = mkdtempSync(join(tmpdir(), "mandu-prov-ipc-"));
  const socketPath = join(workdir, "arbiter.sock");
  server = new ArbiterServer({
    socketPath,
    humanSocketPath: join(workdir, "human", "h.sock"),
    dbPath: join(workdir, "symbols.db"),
    eventDir: join(workdir, "events"),
    log: () => {},
  });
  await server.listen();
  client = new ArbiterClient(join(workdir, "human", "h.sock")); // the guard's channel (plan 13 D9)
  await client.connect();
});

after(async () => {
  client.close();
  await server.close();
  rmSync(workdir, { recursive: true, force: true });
});

test("taintProcess + isProcessTainted round-trip over IPC", async () => {
  await client.taintProcess({ procKey: "1234-9", originHost: "evil.example", session: "s1" });
  const r = await client.isProcessTainted("1234-9");
  assert.equal(r.tainted, true);
  assert.equal(r.originHost, "evil.example");
});

test("lineage propagation over IPC", async () => {
  await client.taintProcess({ procKey: "bash-9", originHost: "evil.example" });
  await client.processLineage({ childKey: "curl-9", parentKey: "bash-9" });
  assert.equal((await client.isProcessTainted("curl-9")).tainted, true);
});

test("taintFile + fileTrust round-trip over IPC", async () => {
  await client.taintFile({ contentHash: "h1", path: "/tmp/x", originHost: "example.test" });
  assert.equal((await client.fileTrust({ path: "/tmp/x" })).untrusted, true);
  assert.equal((await client.fileTrust({ contentHash: "unknown" })).untrusted, false);
});

// ── plan 10 ops ──────────────────────────────────────────────────────────────
test("taintProcessSecret / processSecretTaint / recordCallRoot / callTaint over IPC: the fold defaults to `secret`", async () => {
  await client.processLineage({ childKey: "p-psql-1", parentKey: "p-bash-1" });
  await client.recordCallRoot({ callId: "toolu_p10", procKey: "p-bash-1" });
  assert.equal((await client.callTaint("toolu_p10")).level, null);
  await client.taintProcessSecret({ procKey: "p-psql-1", path: "/h/.pgpass", level: "no-model", app: "ssh-add" });
  const p = await client.processSecretTaint("p-psql-1");
  assert.equal(p.level, "no-model");
  const t = await client.callTaint("toolu_p10");
  assert.equal(t.level, "no-model");
  assert.deepEqual(t.files, ["/h/.pgpass"]);
  assert.deepEqual(t.apps, ["ssh-add"]);
  assert.equal(t.rule, "secret", "no apps table in force: the default rule");
  assert.equal(t.root, "p-bash-1");
});

// ── plan 10 §4.1: decideSecretOpen ───────────────────────────────────────────
import { mkdirSync, writeFileSync } from "node:fs";

test("decideSecretOpen: no reader list ⇒ twin; a listed reader ⇒ raw and the taint is recorded; others ⇒ deny; the agent ⇒ twin; axis OFF ⇒ twin", async () => {
  // a private arbiter with a policy document naming a reader, confidentiality ON
  const dir = mkdtempSync(join(tmpdir(), "mandu-dso-"));
  const home = join(dir, "home");
  mkdirSync(home, { recursive: true });
  const pgpass = join(home, ".pgpass");
  writeFileSync(pgpass, "db:5432:prod:app:pw_123456\n");
  const env = join(home, ".env");
  writeFileSync(env, "API_KEY=abc123456\n");
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: pgpass, level: "no-model", readers: [{ app: "ssh-add", path: "/usr/bin/ssh-add", sha256: "a".repeat(64) }] }] },
  });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's channel (plan 13 D9)
  await c.connect();
  try {
    const twin = await c.decideSecretOpen({ path: env, exe: "/usr/bin/cat", isAgent: false, exeSystem: true, openerEnv: [], procKey: "cat-1" });
    assert.equal(twin.verdict, "twin");
    const raw = await c.decideSecretOpen({ path: pgpass, exe: "/usr/bin/ssh-add", sha256: "a".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "psql-2" });
    assert.equal(raw.verdict, "raw");
    assert.equal(raw.app, "ssh-add");
    assert.equal(raw.level, "no-model");
    const taint = await c.processSecretTaint("psql-2");
    assert.equal(taint.level, "no-model");
    assert.deepEqual(taint.rows.map((r) => [r.path, r.app]), [[pgpass, "ssh-add"]]);
    const rebuilt = await c.decideSecretOpen({ path: pgpass, exe: "/usr/bin/ssh-add", sha256: "b".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "psql-3" });
    assert.equal(rebuilt.verdict, "deny", "a pin is path AND hash");
    const other = await c.decideSecretOpen({ path: pgpass, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "cat-4" });
    assert.equal(other.verdict, "deny");
    assert.match(other.reason, /exhaustive/);
    const agent = await c.decideSecretOpen({ path: pgpass, exe: "/usr/bin/ssh-add", sha256: "a".repeat(64), isAgent: true, exeSystem: true, openerEnv: [], procKey: "agent-5" });
    assert.equal(agent.verdict, "twin");
    // a known consumer with no list and ask=known: answered deny (held opens not built) with the way out
    const held = await c.decideSecretOpen({ path: env, exe: "/usr/bin/node", isAgent: false, exeSystem: true, openerEnv: [], procKey: "node-6", ask: "known" });
    assert.equal(held.verdict, "twin", "node is not a known consumer of .env: the twin, no hold");
    const heldPg = await c.decideSecretOpen({ path: join(home, ".pgpass"), exe: "/usr/bin/pg_dump", isAgent: false, exeSystem: true, openerEnv: [], procKey: "pgd-7", ask: "known" });
    assert.equal(heldPg.verdict, "ask", "a list exists (ssh-add) and pg_dump is not on it: with ask=known it is HELD for the human");
    assert.ok(heldPg.approvalId);
    // a listless file's vetted known consumer is a default reader (§11.3,
    // plan 13 D8 (12)); an unvetted one (aws) reads the twin
    const ssh = join(home, ".ssh"); mkdirSync(ssh, { recursive: true }); const key = join(ssh, "id_ed25519");
    writeFileSync(key, "-----BEGIN OPENSSH PRIVATE KEY-----\nabcdefghij123456\n");
    const dflt = await c.decideSecretOpen({ path: key, exe: "/usr/bin/ssh", isAgent: false, exeSystem: true, openerEnv: [], procKey: "ssh-8" });
    assert.equal(dflt.verdict, "raw");
    assert.equal(dflt.pinNeeded, true);
    assert.equal((await c.processSecretTaint("ssh-8")).level, "no-model");
    const aws = join(home, ".aws"); mkdirSync(aws, { recursive: true }); const cred = join(aws, "credentials");
    writeFileSync(cred, "[default]\naws_secret_access_key = abcdefghij123456\n");
    assert.equal((await c.decideSecretOpen({ path: cred, exe: "/usr/bin/aws", isAgent: false, exeSystem: true, openerEnv: [], procKey: "aws-9" })).verdict, "twin", "aws is not vetted");
    assert.equal((await c.processSecretTaint("cat-4")).level, null, "a denied open records no taint");
  } finally {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Plan 13 D7 over IPC: the guard's chains (recordExecRoot `ancestors`, decideSecretOpen `ancestorKeys`) link a reader under a subshell that never exec'd to its call's root (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-d7-chain-"));
  const pgpass = join(dir, ".pgpass");
  writeFileSync(pgpass, "db:5432:prod:app:pw_d7_123456\n");
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: pgpass, level: "no-model", readers: [{ app: "ssh-add", path: "/usr/bin/ssh-add", sha256: "a".repeat(64) }] }] },
  });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's channel (plan 13 D9)
  await c.connect();
  try {
    // `( psql -c 1; true ) | cat` — the root execs, the subshell never does,
    // ssh-add opens .pgpass raw with no exec record of its own reaching the root
    await c.recordExecRoot({ procKey: "d7-bash-1", parentKey: "d7-agent-0", ancestors: ["d7-agent-0"], argv: ["/bin/bash", "-c", "( psql -c 1; true ) | cat"], session: "d7" });
    const raw = await c.decideSecretOpen({ path: pgpass, exe: "/usr/bin/ssh-add", sha256: "a".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "d7-psql-3", parentKey: "d7-sub-2", ancestorKeys: ["d7-sub-2", "d7-bash-1", "d7-agent-0"], session: "d7" });
    assert.equal(raw.verdict, "raw");
    await c.recordCallRoot({ callId: "toolu_d7", procKey: "d7-bash-1", session: "d7" });
    const t = await c.callTaint("toolu_d7", { session: "d7" });
    assert.equal(t.level, "no-model", `the reader under the subshell is in the call's tree: ${JSON.stringify(t)}`);
    assert.deepEqual(t.apps, ["ssh-add"]);
    // an exec below a second subshell, reported with its chain, is linked too
    await c.recordExecRoot({ procKey: "d7-bash-4", parentKey: "d7-agent-0", ancestors: ["d7-agent-0"], argv: ["/bin/bash", "-c", "echo \"$(psql -c 1; true)\""], session: "d7" });
    await c.recordExecRoot({ procKey: "d7-psql-6", parentKey: "d7-subst-5", ancestors: ["d7-subst-5", "d7-bash-4", "d7-agent-0"], argv: ["/usr/bin/ssh-add", "-c", "1"], session: "d7" });
    await c.taintProcessSecret({ procKey: "d7-psql-6", path: pgpass, level: "no-model", app: "ssh-add", session: "d7" });
    await c.recordCallRoot({ callId: "toolu_d7b", procKey: "d7-bash-4", session: "d7" });
    assert.equal((await c.callTaint("toolu_d7b", { session: "d7" })).level, "no-model");
  } finally {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── Plan 13 D7: the call-root recorder, and the fail-closed unknown tree ─────
// The guard reports each exec by a direct child of the agent as `callRoot`;
// the arbiter binds a tool call to the one whose command is the call's, no
// older than the proxy's gate of the call (execGate with its callId). Before,
// callTaint took "the most recent exec of this command signature": Claude
// Code's eval-wrapped shell matched nothing, two runs of one command bound
// both calls to the last tree, and a miss answered no level at all.
async function d7Stack(): Promise<{ c: ArbiterClient; done: () => Promise<void> }> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-d7-rec-"));
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({ socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's channel (plan 13 D9)
  await c.connect();
  return { c, done: async () => { c.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); } };
}
const tick = (): Promise<void> => new Promise((ok) => setTimeout(ok, 5));
/** Claude Code's shell for one Bash call, as the guard reads its argv. */
const ccShell = (command: string): string[] => ["/usr/bin/zsh", "-c", `source /h/.claude/shell-snapshots/snapshot-zsh-1.sh 2>/dev/null || true && eval '${command.replace(/'/g, `'"'"'`)}' && pwd -P >| /tmp/claude-9f3a-cwd`];

test("Plan 13 D7 recorder over IPC: Claude Code's eval-wrapped shell binds its call by command text; the reader under it masks the result (secrets axes, explicit)", async () => {
  const { c, done } = await d7Stack();
  try {
    const cmd = "( cat ./x.tx?; true ) | od -An -tx1";
    await c.execGate({ command: cmd, sessionKey: "rc", callId: "toolu_rc1" });
    await c.recordExecRoot({ procKey: "rc-zsh-1", ancestors: ["rc-agent-0"], argv: ccShell(cmd), session: "rc", callRoot: true });
    await c.recordExecRoot({ procKey: "rc-cat-3", ancestors: ["rc-sub-2", "rc-zsh-1", "rc-agent-0"], argv: ["cat", "./x.txt"], session: "rc" });
    await c.taintProcessSecret({ procKey: "rc-cat-3", path: "/w/x.txt", level: "no-model", app: "cat", session: "rc" });
    const t = await c.callTaint("toolu_rc1", { command: cmd, session: "rc" });
    assert.equal(t.root, "rc-zsh-1", `bound to the agent's shell for the call: ${JSON.stringify(t)}`);
    assert.equal(t.level, "no-model");
    assert.equal(t.evidence, "tree");
    assert.deepEqual(t.apps, ["cat"]);
  } finally { await done(); }
});

test("Plan 13 D7 recorder over IPC: two calls with the same command text running together are each folded over both trees; a later call of the text binds its own tree alone (secrets axes, explicit)", async () => {
  const { c, done } = await d7Stack();
  try {
    const cmd = "if mkdir /tmp/lk 2>/dev/null; then cat ./x.tx?; else echo none; fi";
    // the model emits two calls with the same text in one turn; the agent
    // runs them together: one wins the lock and reads, the other does not
    await c.execGate({ command: cmd, sessionKey: "rt", callId: "toolu_ra" });
    await c.execGate({ command: cmd, sessionKey: "rt", callId: "toolu_rb" });
    await c.recordExecRoot({ procKey: "rt-bash-1", ancestors: ["rt-agent-0"], argv: ["bash", "-lc", cmd], session: "rt", callRoot: true });
    await c.recordExecRoot({ procKey: "rt-bash-2", ancestors: ["rt-agent-0"], argv: ["bash", "-lc", cmd], session: "rt", callRoot: true });
    await c.recordExecRoot({ procKey: "rt-cat-3", ancestors: ["rt-bash-1", "rt-agent-0"], argv: ["cat", "./x.txt"], session: "rt" });
    await c.taintProcessSecret({ procKey: "rt-cat-3", path: "/w/x.txt", level: "no-model", app: "cat", session: "rt" });
    // which call's output came from the reading tree is unknowable from
    // the text: both are masked (before: both bound to the LAST tree, the
    // clean one, and the reader's output reached the model raw)
    const a = await c.callTaint("toolu_ra", { command: cmd, session: "rt" });
    const b = await c.callTaint("toolu_rb", { command: cmd, session: "rt" });
    assert.equal(a.level, "no-model", JSON.stringify(a));
    assert.equal(b.level, "no-model", JSON.stringify(b));
    assert.equal(a.evidence, "tree");
    // a later call of the same text, gated after both ran: its own tree only
    await tick();
    await c.execGate({ command: cmd, sessionKey: "rt", callId: "toolu_rc" });
    await c.recordExecRoot({ procKey: "rt-bash-4", ancestors: ["rt-agent-0"], argv: ["bash", "-lc", cmd], session: "rt", callRoot: true });
    const later = await c.callTaint("toolu_rc", { command: cmd, session: "rt" });
    assert.equal(later.root, "rt-bash-4");
    assert.equal(later.level, null, `a clean later run is not folded with the earlier reader: ${JSON.stringify(later)}`);
    // two calls with DIFFERENT texts running together bind exactly
    await tick();
    await c.execGate({ command: "cat ./x.tx?", sessionKey: "rt", callId: "toolu_rd" });
    await c.execGate({ command: "echo hi", sessionKey: "rt", callId: "toolu_re" });
    await c.recordExecRoot({ procKey: "rt-bash-6", ancestors: ["rt-agent-0"], argv: ["bash", "-lc", "echo hi"], session: "rt", callRoot: true });
    await c.recordExecRoot({ procKey: "rt-bash-5", ancestors: ["rt-agent-0"], argv: ["bash", "-lc", "cat ./x.tx?"], session: "rt", callRoot: true });
    await c.taintProcessSecret({ procKey: "rt-bash-5", path: "/w/x.txt", level: "no-model", app: "cat", session: "rt" });
    assert.equal((await c.callTaint("toolu_rd", { command: "cat ./x.tx?", session: "rt" })).level, "no-model");
    assert.equal((await c.callTaint("toolu_re", { command: "echo hi", session: "rt" })).level, null);
  } finally { await done(); }
});

test("Plan 13 D7 fail-closed over IPC: a call whose tree the recorder cannot bind is masked at the session's level while the session holds a raw read; a claim or a stale exec never lowers that (secrets axes, explicit)", async () => {
  const { c, done } = await d7Stack();
  try {
    // a session holding nothing: an unknown tree has nothing to mask
    const quiet = await c.callTaint("toolu_q", { command: "ls", session: "rf" });
    assert.equal(quiet.level, null);
    // a reader read x.txt raw in an earlier call of the session
    await c.taintProcessSecret({ procKey: "rf-cat-1", path: "/w/x.txt", level: "local-model", app: "cat", session: "rf" });
    // no exec of the agent matched this call (its shell record lost, or a
    // tool with no command such as BashOutput): masked at the session level
    const lost = await c.callTaint("toolu_lost", { command: "cat ./x.tx?", session: "rf" });
    assert.equal(lost.level, "local-model", JSON.stringify(lost));
    assert.equal(lost.rule, "secret");
    assert.equal(lost.evidence, "session");
    const noCommand = await c.callTaint("toolu_bashoutput", { session: "rf" });
    assert.equal(noCommand.level, "local-model");
    // an exec of the call's text reported AFTER the call was first asked for
    // (a late or stray report; one forged over the data socket is not even
    // recorded, plan 13 D9, test/component/guard-report-attestation) never
    // binds it
    await tick();
    await c.recordExecRoot({ procKey: "rf-forged-1", ancestors: ["rf-agent-0"], argv: ["bash", "-lc", "cat ./x.tx?"], session: "rf", callRoot: true });
    const again = await c.callTaint("toolu_lost", { command: "cat ./x.tx?", session: "rf" });
    assert.equal(again.level, "local-model", JSON.stringify(again));
    assert.equal(again.evidence, "session");
    // a claimed root (recordCallRoot is reachable from the agent's tree) is
    // no evidence: a clean claimed tree does not lower the mask
    await c.recordExecRoot({ procKey: "rf-sh-9", ancestors: ["rf-agent-0"], argv: ["bash", "-c", "true"], session: "rf" });
    await c.recordCallRoot({ callId: "toolu_claim", procKey: "rf-sh-9", session: "rf" });
    assert.equal((await c.callTaint("toolu_claim", { command: "wc -c ./x.tx?", session: "rf" })).level, "local-model");
    // a shell of the same text that ran BEFORE the proxy gated this call is
    // not its root: with the real root's record lost, the call masks rather
    // than borrowing that older clean tree
    await c.recordExecRoot({ procKey: "rf-sh-10", ancestors: ["rf-agent-0"], argv: ["bash", "-lc", "head -c 3 ./x.tx?"], session: "rf", callRoot: true });
    await tick();
    await c.execGate({ command: "head -c 3 ./x.tx?", sessionKey: "rf", callId: "toolu_stale" });
    const stale = await c.callTaint("toolu_stale", { command: "head -c 3 ./x.tx?", session: "rf" });
    assert.equal(stale.level, "local-model", JSON.stringify(stale));
    assert.equal(stale.evidence, "session");
    // and a call the recorder binds to a clean tree is not masked (utility)
    await c.execGate({ command: "echo ok", sessionKey: "rf", callId: "toolu_ok" });
    await c.recordExecRoot({ procKey: "rf-sh-11", ancestors: ["rf-agent-0"], argv: ccShell("echo ok"), session: "rf", callRoot: true });
    const ok = await c.callTaint("toolu_ok", { command: "echo ok", session: "rf" });
    assert.equal(ok.level, null, JSON.stringify(ok));
    assert.equal(ok.evidence, "tree");
  } finally { await done(); }
});

test("decideSecretOpen with the confidentiality axis OFF: always the twin, never raw", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dso-off-"));
  const p = join(dir, ".pgpass");
  writeFileSync(p, "x:1:2:3:pw\n");
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({ socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: false,
    policyDocument: { version: 1, paths: [{ path: p, level: "no-model", readers: ["ssh-add"] }] } });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's channel (plan 13 D9)
  await c.connect();
  try {
    assert.equal((await c.decideSecretOpen({ path: p, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "k" })).verdict, "twin");
  } finally {
    c.close(); await s.close(); rmSync(dir, { recursive: true, force: true });
  }
});

test("recordExecRoot + callTaint by command signature; denials ride the fold; scanSecretValues is the value backstop", async () => {
  // the guard saw `bash -lc "psql -c 'select 1'"` exec, then ssh-add under it opened .pgpass raw
  await client.recordExecRoot({ procKey: "x-bash-1", parentKey: "x-agent-0", argv: ["/bin/bash", "-lc", "psql -c 'select 1'"], session: "sx" });
  await client.recordExecRoot({ procKey: "x-psql-2", parentKey: "x-bash-1", argv: ["/usr/bin/ssh-add", "-c", "select 1"], session: "sx" });
  await client.taintProcessSecret({ procKey: "x-psql-2", path: "/h/.pgpass", level: "no-model", app: "ssh-add", session: "sx" });
  // the proxy knows only the tool call's command text
  const t = await client.callTaint("toolu_sig_1", { command: "psql -c 'select 1'", session: "sx" });
  assert.equal(t.root, "x-bash-1", "matched by exec signature to the shell wrapper");
  assert.equal(t.level, "no-model");
  assert.deepEqual(t.apps, ["ssh-add"]);
  // remembered by callId: a second ask needs no command
  assert.equal((await client.callTaint("toolu_sig_1")).root, "x-bash-1");
  // a different command matches nothing
  assert.equal((await client.callTaint("toolu_sig_2", { command: "ls -la", session: "sx" })).root, null);
  // a denial in the tree surfaces
  await client.recordExecRoot({ procKey: "y-bash-1", argv: ["/bin/sh", "-c", "head -c 9 /h/.pgpass"], session: "sy" });
  await client.processLineage({ childKey: "y-head-2", parentKey: "y-bash-1" });
  // (the arbiter records denials in decideSecretOpen; here the store is exercised directly through the op path below)
  const d0 = await client.callTaint("toolu_sig_3", { command: "head -c 9 /h/.pgpass", session: "sy" });
  assert.equal(d0.root, "y-bash-1");
  assert.deepEqual(d0.denied, []);
});

test("scanSecretValues: a registered value in text is a hit; short values and unregistered text are not", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-scan-"));
  const p = join(dir, ".env");
  writeFileSync(p, "TOKEN=tok_abcdef123456\nSHORT=ab\n");
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({ socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's channel (plan 13 D9)
  await c.connect();
  try {
    const reg = await c.registerSecret({ path: p });
    assert.ok(reg.symbol);
    const hit = await c.scanSecretValues("the output was tok_abcdef123456 and more");
    assert.ok(hit.hits.some((h) => h.symbol.endsWith(".TOKEN")), JSON.stringify(hit));
    assert.equal((await c.scanSecretValues("nothing here ab")).hits.length, 0, "a 2-char value never fingerprints");
    // a command output masked for its PROVENANCE is not a secret value: the
    // harmless failure text of one refused `cat` must not match the next
    // (S7 rerun 2026-09-24: the §11.8 release never fired on a seen database)
    const failure = "Exit code 1\ncat: .env: Permission denied";
    const masked = await c.symbolize({ tool: "Bash", value: failure, origin: "cat .env", confidentiality: "no-model", sessionKey: "scan-s" });
    assert.match(masked, /^\$MDU:nomodel_Bash\[/);
    assert.equal((await c.scanSecretValues(failure)).hits.length, 0, "a precautionary exec-output row (no taint on record) never fingerprints");
    // …but an exec output masked on EVIDENCE (its call's tree held a secret,
    // rule (i)) is the secret's bytes as a reader printed them: it fingerprints,
    // so the same bytes released later under (ii)/(iii) or a denied-only tree
    // stay masked even for a labeled file that is not in the registry
    await c.recordExecRoot({ procKey: "scan-sh-1", argv: ["/bin/sh", "-c", "cat notes.txt"], session: "scan-s" });
    await c.taintProcessSecret({ procKey: "scan-sh-1", path: join(dir, "notes.txt"), level: "no-model", app: "sh", session: "scan-s" });
    await c.recordCallRoot({ callId: "toolu_scan_evidence", procKey: "scan-sh-1", session: "scan-s" });
    const printed = "NOTES_SECRET=plain_file_value_9876\n";
    const evidential = await c.symbolize({ tool: "Bash", value: printed, origin: "cat notes.txt", confidentiality: "no-model", sessionKey: "scan-s", callId: "toolu_scan_evidence" });
    assert.match(evidential, /^\$MDU:nomodel_Bash\[/);
    assert.ok((await c.scanSecretValues(`later: ${printed}`)).hits.some((h) => h.symbol === evidential), "an evidential exec-output row fingerprints");
    // the same text from a call with NO taint on record is a precaution, not evidence
    const precaution = await c.symbolize({ tool: "Bash", value: "sh: notes.txt: Permission denied\n", origin: "cat notes.txt", confidentiality: "no-model", sessionKey: "scan-s", callId: "toolu_scan_norecord" });
    assert.equal((await c.scanSecretValues("sh: notes.txt: Permission denied\n")).hits.filter((h) => h.symbol === precaution).length, 0);
    // …while a labeled file's content the model tried to READ still does
    const content = await c.symbolize({ tool: "Read", value: "PGPASS=pg_secret_value_0123\n", origin: join(dir, "notes.txt"), confidentiality: "no-model", sessionKey: "scan-s" });
    assert.ok((await c.scanSecretValues("saw PGPASS=pg_secret_value_0123\n today")).hits.some((h) => h.symbol === content));
    // …but a read whose content was the file's STRUCTURED TWIN (keys and field
    // symbols, no secret byte) never fingerprints, or every later rendering of
    // the twin would be masked whole (plan 10 §11.8; VM run 2026-09-28)
    const twinRead = await c.symbolize({ tool: "read", value: reg.twin as string, origin: p, confidentiality: "no-model", sessionKey: "scan-s" });
    assert.match(twinRead, /^\$MDU:nomodel_read\[/);
    assert.equal((await c.scanSecretValues(`${reg.twin as string}`)).hits.filter((h) => h.symbol === twinRead).length, 0, "a twin-piece row is no fingerprint");
    // a denial recorded by decideSecretOpen reaches callTaint through the exec root
    await c.recordExecRoot({ procKey: "z-sh-1", argv: ["/bin/sh", "-c", `head ${p}`], session: "sz" });
    const v = await c.decideSecretOpen({ path: p, exe: "/usr/bin/head", isAgent: false, exeSystem: true, openerEnv: [], procKey: "z-head-2", parentKey: "z-sh-1", session: "sz" });
    assert.equal(v.verdict, "twin", "no reader list on this file: the twin, not a denial");
    // give the file a reader list through the document store is admin-only; exercise the denial store directly
    (s as unknown as { provenance: { recordSecretOpenDenial: (a: object) => void } }).provenance.recordSecretOpenDenial({ procKey: "z-head-2", path: p, app: "head", reason: "not a listed reader", session: "sz" });
    const t = await c.callTaint("toolu_z", { command: `head ${p}`, session: "sz" });
    assert.equal(t.root, "z-sh-1");
    assert.deepEqual(t.denied.map((d) => d.app), ["head"]);
  } finally {
    c.close(); await s.close(); rmSync(dir, { recursive: true, force: true });
  }
});

test("taintedProcessBindings: a reader's bindings (label + registry) are the hosts it may reach; ancestors get their edges; untainted ⇒ unrestricted", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-tpb-"));
  const p = join(dir, ".env");
  writeFileSync(p, "STRIPE_KEY=sk_live_abcdef123456\n");
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: p, level: "no-model", bindings: ["api.stripe.com", "db.internal:5432"], readers: ["ssh-add"] }] },
  });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's channel (plan 13 D9)
  await c.connect();
  try {
    assert.ok((await c.registerSecret({ path: p })).symbol);
    // a leaf reader (plan 13 §8 decision (b): a shell is none by name)
    const raw = await c.decideSecretOpen({ path: p, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "b-sh-1", parentKey: "b-agent-0" });
    assert.equal(raw.verdict, "raw");
    // the reader's child curl: the guard passes the ancestor chain
    const child = await c.taintedProcessBindings({ procKey: "b-curl-2", ancestors: ["b-sh-1", "b-agent-0"] });
    assert.equal(child.tainted, true);
    assert.equal(child.level, "no-model");
    assert.deepEqual(child.files, [p]);
    assert.deepEqual([...child.bindings].sort(), ["api.stripe.com", "db.internal:5432"]);
    assert.deepEqual(await c.taintedProcessBindings({ procKey: "stranger-9" }), { tainted: false, level: null, files: [], bindings: [] });
    // the filesystem exit: a file the tainted child writes is labeled at the taint's level; the secret itself is not
    const out = join(dir, "notes.txt");
    const l = await c.labelWrittenPathTainted({ path: out, procKey: "b-curl-2" });
    assert.equal(l.labeled, true);
    assert.equal(l.level, "no-model");
    assert.equal((await c.labelWrittenPathTainted({ path: p, procKey: "b-sh-1" })).labeled, false);
    assert.equal((await c.labelWrittenPathTainted({ path: join(dir, "x"), procKey: "stranger-9" })).labeled, false);
    // the derived label is what a later classify sees
    const cls = await c.classify({ tool: "Read", value: "hello", boundary: "model_context", origin: out, params: { file_path: out } });
    assert.equal(cls.confidentiality, "no-model");
  } finally {
    c.close(); await s.close(); rmSync(dir, { recursive: true, force: true });
  }
});

// ── plan 10 §11.1 / §11.2: the hold, the human's verdict, the pin write-back ──
import { readFileSync } from "node:fs";

test("a held open: pending Inbox row → the human's allow (always) makes it raw and pins the reader into policy.yaml; a deny denies; a bare-name match is pinned on first use", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-hold-"));
  const home = join(dir, "home"); mkdirSync(home, { recursive: true });
  const pgpass = join(home, ".pgpass"); writeFileSync(pgpass, "db:5432:prod:app:pw_123456789\n");
  const env = join(home, ".env"); writeFileSync(env, "API_KEY=abcdef123456\n");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${pgpass}\n    level: no-model\n    readers: [ssh-add]\n  - path: ${env}\n    level: no-model\n    readers: [sh, { app: mytool, prints: nothing }]\n`);
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({ socketPath: sock, adminSocketPath: join(dir, "admin.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0 });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's channel (plan 13 D9) await c.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  try {
    // pg_dump is a known consumer but the list names only ssh-add: with ask=known it is HELD
    const held = await c.decideSecretOpen({ path: pgpass, exe: "/usr/bin/pg_dump", sha256: "a".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "psql-1", ask: "known" });
    assert.equal(held.verdict, "ask");
    assert.ok(held.approvalId);
    const pending = (await admin.egressApprovals("pending")).find((a) => a.id === held.approvalId);
    assert.ok(pending, "an Inbox row exists");
    assert.equal(pending!.symbol, `trust:/usr/bin/pg_dump#${"a".repeat(64)}`, "the row names the binary by path and hash (Plan 13 D8)");
    assert.equal(pending!.destination, pgpass);
    // re-asking while pending stays held (the guard polls)
    assert.equal((await c.decideSecretOpen({ path: pgpass, exe: "/usr/bin/pg_dump", sha256: "a".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "psql-1", ask: "known" })).verdict, "ask");
    // the human allows, standing
    await admin.resolveEgressApproval(held.approvalId!, true, "always");
    const raw = await c.decideSecretOpen({ path: pgpass, exe: "/usr/bin/pg_dump", sha256: "a".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "psql-1", ask: "known" });
    assert.equal(raw.verdict, "raw");
    assert.match(raw.reason, /human-approved/);
    assert.equal((await c.processSecretTaint("psql-1")).level, "no-model");
    const law = readFileSync(policyPath, "utf8");
    assert.match(law, /app: pg_dump/);
    assert.match(law, new RegExp(`path: /usr/bin/pg_dump`));
    assert.match(law, new RegExp(`sha256: ${"a".repeat(64)}`));
    // a bare-name reader (mytool) is pinned on its first raw use
    const bare = await c.decideSecretOpen({ path: env, exe: "/usr/bin/mytool", sha256: "b".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "sh-2" });
    assert.equal(bare.verdict, "raw");
    assert.equal(bare.pinNeeded, true);
    assert.match(readFileSync(policyPath, "utf8"), /path: \/usr\/bin\/mytool/);
    assert.match(readFileSync(policyPath, "utf8"), /path: \/usr\/bin\/mytool[\s\S]{0,120}prints: nothing|prints: nothing[\s\S]{0,120}path: \/usr\/bin\/mytool/, "the pin keeps the human's word (D8 (12))");
    // plan 13 §8 decision (b): the bare shell beside it admits no shell
    // running inline code, and nothing pins it
    const shell = await c.decideSecretOpen({ path: env, exe: "/bin/sh", sha256: "e".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], scriptProblem: "inline code (sh -c)", procKey: "sh-3", ask: "known" });
    assert.equal(shell.verdict, "deny", shell.reason);
    assert.equal(shell.approvalId, undefined, "never asked about");
    assert.equal((await c.processSecretTaint("sh-3")).level, null);
    assert.doesNotMatch(readFileSync(policyPath, "utf8"), /path: \/bin\/sh/);
    // a denial holds
    const held2 = await c.decideSecretOpen({ path: pgpass, exe: "/usr/local/bin/pg_dump", isAgent: false, exeSystem: true, openerEnv: [], procKey: "pgr-3", ask: "known" });
    assert.equal(held2.verdict, "ask");
    await admin.resolveEgressApproval(held2.approvalId!, false);
    const denied = await c.decideSecretOpen({ path: pgpass, exe: "/usr/local/bin/pg_dump", isAgent: false, exeSystem: true, openerEnv: [], procKey: "pgr-3", ask: "known" });
    assert.equal(denied.verdict, "deny");
    assert.equal(denied.reason, "human-denied");
  } finally {
    c.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true });
  }
});

test("§12.2 ceiling: the guard's last ask carries heldMs → deny with the recorded 'held for N s' denial (callTaint's `denied`), the Inbox row stays pending, a later allow makes the next attempt raw with no new prompt", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-heldms-"));
  const home = join(dir, "home"); mkdirSync(home, { recursive: true });
  const pgpass = join(home, ".pgpass"); writeFileSync(pgpass, "db:5432:prod:app:pw_123456789\n");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${pgpass}\n    level: no-model\n    readers: [ssh-add]\n`);
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({ socketPath: sock, adminSocketPath: join(dir, "admin.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0 });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's channel (plan 13 D9) await c.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  try {
    const open = { path: pgpass, exe: "/usr/bin/pg_dump", sha256: "a".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "psql-held-1", session: "s-held", ask: "known" as const };
    const held = await c.decideSecretOpen(open);
    assert.equal(held.verdict, "ask");
    // the ceiling passes: ONE more ask, saying how long the guard waited
    const expired = await c.decideSecretOpen({ ...open, heldMs: 60_000 });
    assert.equal(expired.verdict, "deny");
    assert.equal(expired.reason, "held for 60 s, nobody answered; the approval is still waiting in the dashboard");
    // the denial is on record for the tool result's note (§11.8 "held:")
    await c.recordCallRoot({ callId: "toolu_held", procKey: "psql-held-1", session: "s-held" });
    const t = await c.callTaint("toolu_held", { session: "s-held" });
    assert.equal(t.level, null, "a refused open records no taint");
    assert.deepEqual(t.denied, [{ path: pgpass, app: "pg_dump", reason: "held for 60 s, nobody answered; the approval is still waiting in the dashboard" }]);
    // the row is untouched: still pending
    const row = (await admin.egressApprovals("pending")).find((a) => a.id === held.approvalId);
    assert.ok(row, "the Inbox row outlives the hold");
    assert.equal(row!.status, "pending");
    // the human answers later: the next attempt is raw, with no new prompt
    await admin.resolveEgressApproval(held.approvalId!, true, "once");
    const next = await c.decideSecretOpen({ ...open, procKey: "psql-held-2" });
    assert.equal(next.verdict, "raw");
    assert.match(next.reason, /human-approved \(once\)/);
    // heldMs on an open the law decides outright changes nothing (it is not a hold)
    const other = await c.decideSecretOpen({ path: pgpass, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "pgd-9", heldMs: 60_000 });
    assert.equal(other.verdict, "raw");
  } finally {
    c.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true });
  }
});

test("Plan 13 D8: a human verdict is keyed by the executable's path and hash: approving /usr/bin/pg_dump admits no other binary named pg_dump", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-verdict-key-"));
  const home = join(dir, "home"); mkdirSync(home, { recursive: true });
  const pgpass = join(home, ".pgpass"); writeFileSync(pgpass, "db:5432:prod:app:pw_123456789\n");
  const policyPath = join(dir, "policy.yaml");
  // the list names ssh-add only, so pg_dump (a known consumer) is held under ask=known
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${pgpass}\n    level: no-model\n    readers: [ssh-add]\n`);
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({ socketPath: sock, adminSocketPath: join(dir, "admin.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0 });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's channel (plan 13 D9) await c.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  const real = { exe: "/usr/bin/pg_dump", sha256: "a".repeat(64) };
  const copyOf = (exe: string, sha256?: string) => ({ exe, ...(sha256 ? { sha256 } : {}) });
  const open = (who: { exe: string; sha256?: string }, procKey: string) =>
    c.decideSecretOpen({ path: pgpass, ...who, isAgent: false, exeSystem: who.exe.startsWith("/usr/"), openerEnv: [], procKey, ask: "known" });
  try {
    // once: the human allows the real pg_dump for one open
    const held = await open(real, "psql-1");
    assert.equal(held.verdict, "ask");
    await admin.resolveEgressApproval(held.approvalId!, true, "once");
    // the agent's copy named pg_dump opens first: the once-verdict is not its to spend
    const copy = await open(copyOf(join(dir, "x", "pg_dump"), "c".repeat(64)), "evil-1");
    assert.notEqual(copy.verdict, "raw", "a copy named pg_dump in a scratch dir is not the approved binary");
    assert.equal((await c.processSecretTaint("evil-1")).level, null, "and it holds no raw byte");
    assert.equal((await open(real, "psql-2")).verdict, "raw", "the approved binary still has its once");
    // always: a standing allow for the real pg_dump
    const again = await open(real, "psql-3");
    assert.notEqual(again.verdict, "raw", "the once is spent");
    await admin.resolveEgressApproval(again.approvalId!, true, "always");
    assert.equal((await open(real, "psql-4")).verdict, "raw");
    assert.notEqual((await open(copyOf("/tmp/x/pg_dump", "c".repeat(64)), "evil-2")).verdict, "raw", "another path named pg_dump is not admitted");
    assert.notEqual((await open(copyOf("/usr/bin/pg_dump", "d".repeat(64)), "evil-3")).verdict, "raw", "the same path rebuilt (another hash) is not admitted");
    assert.notEqual((await open(copyOf("/tmp/x/pg_dump"), "evil-4")).verdict, "raw", "nor a path whose hash the guard could not take");
    for (const k of ["evil-2", "evil-3", "evil-4"]) assert.equal((await c.processSecretTaint(k)).level, null, k);
    // a denial is the binary's too: denying the copy does not deny the real pg_dump
    const heldCopy = await open(copyOf("/tmp/x/pg_dump", "c".repeat(64)), "evil-5");
    assert.equal(heldCopy.verdict, "ask");
    await admin.resolveEgressApproval(heldCopy.approvalId!, false);
    assert.equal((await open(copyOf("/tmp/x/pg_dump", "c".repeat(64)), "evil-6")).verdict, "deny");
    assert.equal((await open(real, "psql-5")).verdict, "raw");
    // `mandu why` names the binary each answer is about
    const why = await admin.whyPath(pgpass);
    assert.ok(why.verdicts.some((v) => v.app === "pg_dump" && v.exe === "/usr/bin/pg_dump" && v.status === "approved"), JSON.stringify(why.verdicts));
    assert.ok(why.verdicts.some((v) => v.app === "pg_dump" && v.exe === "/tmp/x/pg_dump" && v.status === "denied"), JSON.stringify(why.verdicts));
  } finally {
    c.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true });
  }
});

test("Plan 13 D8 over IPC: a pinned reader run with LD_PRELOAD is refused raw and spends no once; a bare name is not pinned to the agent's copy; an unreported fact counts against the opener; from: needs a trusted parent", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-d8-ipc-"));
  const home = join(dir, "home"); mkdirSync(home, { recursive: true });
  const pgpass = join(home, ".pgpass"); writeFileSync(pgpass, "db:5432:prod:app:pw_123456789\n");
  const env = join(home, "app.env"); writeFileSync(env, "API_KEY=abcdef123456\n");
  const key = join(home, "deploy_key"); writeFileSync(key, "-----BEGIN KEY-----\nk\n");
  const policyPath = join(dir, "policy.yaml");
  const PSQL_PIN = { app: "ssh-add", path: "/usr/bin/ssh-add", sha256: "a".repeat(64) };
  writeFileSync(policyPath, [
    "version: 1", "paths:",
    `  - path: ${pgpass}`, "    level: no-model", "    readers:", `      - { app: ssh-add, path: ${PSQL_PIN.path}, sha256: ${PSQL_PIN.sha256} }`,
    `  - path: ${env}`, "    level: no-model", "    readers: [{ app: report-tool, prints: nothing }]",
    `  - path: ${key}`, "    level: no-model", "    readers:", "      - { app: ssh, from: deployer }", "    others: deny", "",
  ].join("\n"));
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({ socketPath: sock, adminSocketPath: join(dir, "admin.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0 });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's channel (plan 13 D9) await c.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  const sshAdd = { path: pgpass, exe: "/usr/bin/ssh-add", sha256: "a".repeat(64), isAgent: false, exeSystem: true };
  try {
    // the pinned reader, clean: raw
    assert.equal((await c.decideSecretOpen({ ...sshAdd, openerEnv: [], procKey: "p-1" })).verdict, "raw");
    // the same binary with LD_PRELOAD the launch did not give: not the pinned program
    const pre = await c.decideSecretOpen({ ...sshAdd, openerEnv: ["LD_PRELOAD"], procKey: "p-2", ask: "always" });
    assert.equal(pre.verdict, "deny", `a pinned reader with LD_PRELOAD set is refused raw (got ${pre.verdict}: ${pre.reason})`);
    assert.match(pre.reason, /LD_PRELOAD/);
    assert.equal((await c.processSecretTaint("p-2")).level, null);
    // no environment reported (an older guard): not clean
    assert.notEqual((await c.decideSecretOpen({ ...sshAdd, procKey: "p-3" })).verdict, "raw", "an unchecked environment is not clean");
    // a once given to the clean binary is not spent by the preloaded one
    const held = await c.decideSecretOpen({ path: pgpass, exe: "/usr/bin/pg_dump", sha256: "b".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "d-1", ask: "known" });
    assert.equal(held.verdict, "ask");
    await admin.resolveEgressApproval(held.approvalId!, true, "once");
    const preDump = await c.decideSecretOpen({ path: pgpass, exe: "/usr/bin/pg_dump", sha256: "b".repeat(64), isAgent: false, exeSystem: true, openerEnv: ["LD_PRELOAD"], procKey: "d-2", ask: "known" });
    assert.notEqual(preDump.verdict, "raw");
    assert.equal((await c.decideSecretOpen({ path: pgpass, exe: "/usr/bin/pg_dump", sha256: "b".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "d-3", ask: "known" })).verdict, "raw", "the once is still the clean binary's");

    // a bare name: the agent's copy in the workspace is not pinned (it asks), the policy keeps the bare name
    const copy = await c.decideSecretOpen({ path: env, exe: join(home, "ws", "report-tool"), sha256: "c".repeat(64), isAgent: false, exeSystem: false, openerEnv: [], procKey: "r-1", ask: "known" });
    assert.equal(copy.verdict, "ask", `the agent's copy is not pinned on first use (got ${copy.verdict}: ${copy.reason})`);
    assert.equal((await c.processSecretTaint("r-1")).level, null);
    assert.doesNotMatch(readFileSync(policyPath, "utf8"), /ws\/report-tool/, "no pin written for the copy");
    assert.notEqual((await c.decideSecretOpen({ path: env, exe: join(home, "ws", "report-tool"), sha256: "c".repeat(64), isAgent: false, openerEnv: [], procKey: "r-2", ask: "never" })).verdict, "raw", "no exeSystem reported: not pinned");
    const sys = await c.decideSecretOpen({ path: env, exe: "/usr/bin/report-tool", sha256: "d".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "r-3", ask: "known" });
    assert.equal(sys.verdict, "raw");
    assert.match(readFileSync(policyPath, "utf8"), /path: \/usr\/bin\/report-tool/, "the system binary is pinned");

    // from: the parent's name is not enough; the guard must call it trusted
    const ssh = { path: key, exe: "/usr/bin/ssh", isAgent: false, exeSystem: true, openerEnv: [] };
    assert.equal((await c.decideSecretOpen({ ...ssh, procKey: "s-1", ancestorExes: [join(home, "ws", "deployer"), "/usr/bin/bash"], ancestorTrusted: [false, true] })).verdict, "deny", "a renamed shell called deployer");
    assert.equal((await c.decideSecretOpen({ ...ssh, procKey: "s-2", ancestorExes: ["/usr/bin/deployer"] })).verdict, "deny", "no trust reported");
    assert.equal((await c.decideSecretOpen({ ...ssh, procKey: "s-3", ancestorExes: ["/usr/bin/deployer", "/usr/bin/bash"], ancestorTrusted: [true, true] })).verdict, "raw");
  } finally {
    c.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true });
  }
});

test("decideSecretOpen: a from: reader is raw only under its parent app, and its first-use pin keeps the condition on disk", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dso-from-"));
  const key = join(dir, "id_ed25519");
  writeFileSync(key, "-----BEGIN OPENSSH PRIVATE KEY-----\nk\n");
  const file = join(dir, "policy.yaml");
  writeFileSync(file, `version: 1\npaths:\n  - path: ${key}\n    level: no-model\n    readers:\n      - app: ssh\n        from: git\n    others: deny\n`);
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({ socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPath: file, policyPollMs: 0 });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's channel (plan 13 D9)
  await c.connect();
  try {
    const direct = await c.decideSecretOpen({ path: key, exe: "/usr/bin/ssh", isAgent: false, exeSystem: true, openerEnv: [], procKey: "ssh-1", ancestorExes: ["/usr/bin/bash", "/usr/bin/node"], ancestorTrusted: [true, true] });
    assert.equal(direct.verdict, "deny", "an ssh the agent runs directly is refused (others: deny)");
    const viaGit = await c.decideSecretOpen({ path: key, exe: "/usr/bin/ssh", isAgent: false, exeSystem: true, openerEnv: [], procKey: "ssh-2", ancestorExes: ["/usr/lib/git-core/git", "/usr/bin/bash"], ancestorTrusted: [true, true] });
    assert.equal(viaGit.verdict, "raw", "git's ssh reads the key");
    const onDisk = readFileSync(file, "utf8");
    assert.match(onDisk, /app: ssh/);
    assert.match(onDisk, /path: \/usr\/bin\/ssh/, "pinned on first use");
    assert.match(onDisk, /from: git/, "the pin kept the lineage condition");
    const again = await c.decideSecretOpen({ path: key, exe: "/usr/bin/ssh", isAgent: false, exeSystem: true, openerEnv: [], procKey: "ssh-3", ancestorExes: ["/usr/bin/zsh"], ancestorTrusted: [true] });
    assert.equal(again.verdict, "deny", "the pinned reader is still conditional");
  } finally {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sshAgentPolicy: the law's ssh_agent readers, or null when the agent socket is ungated", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sshagent-"));
  const mk = async (doc: object) => {
    const sock = join(dir, `a${Math.random().toString(36).slice(2, 7)}.sock`);
    const s = new ArbiterServer({ socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, `${Math.random()}.sqlite`), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyDocument: doc as never });
    await s.listen();
    const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's channel (plan 13 D9)
    await c.connect();
    return { s, c };
  };
  // One server at a time: the law in force is process-wide (getCurrentPolicy).
  try {
    const a = await mk({ version: 1, ssh_agent: { readers: [{ app: "ssh", from: "git" }] } });
    try { assert.deepEqual((await a.c.sshAgentPolicy()).readers, [{ app: "ssh", from: "git" }]); } finally { a.c.close(); await a.s.close(); }
    const b = await mk({ version: 1 });
    try { assert.equal((await b.c.sshAgentPolicy()).readers, null); } finally { b.c.close(); await b.s.close(); }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("verifyEvents: the op reports an intact chain over the wire, and the break after an edit", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-verify-events-"));
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "human", "h.sock");
  const s = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false });
  await s.listen();
  const c = new ArbiterClient(sock);
  await c.connect();
  // verifyEvents reads the observability store: human plane only
  // (arbiter-human-plane.md) — refused on the data socket.
  const h = new ArbiterClient(humanSock);
  try {
    for (let i = 0; i < 3; i++) await c.emit({ sessionId: "vs", id: `e${i}`, kind: "emit" } as never);
    await assert.rejects(() => c.verifyEvents("vs"), /human-plane/);
    const ok = await h.verifyEvents("vs");
    assert.equal(ok.ok, true);
    assert.equal(ok.chained, 3);
    const f = join(dir, "events", "vs.ndjson");
    writeFileSync(f, readFileSync(f, "utf8").replace('"id":"e1"', '"id":"eX"'));
    const bad = await h.verifyEvents("vs");
    assert.equal(bad.ok, false);
    assert.equal(bad.brokenAt, 2);
  } finally {
    c.close();
    h.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a signed consumer pack makes its program a known consumer (since plan 13 D8 (12) it reads the twin: a pack is not a probe), and the snapshot lists the relaxation with its provenance", async () => {
  const { execFileSync } = await import("node:child_process");
  const { setPackConsumers } = await import("../../policy/flow-taint.js");
  const dir = mkdtempSync(join(tmpdir(), "mandu-pack-ipc-"));
  const packs = join(dir, "packs"), keys = join(dir, "keys");
  mkdirSync(packs); mkdirSync(keys);
  const SIGN = join(import.meta.dirname, "..", "..", "..", "scripts", "sign-pack.mjs");
  execFileSync("node", [SIGN, "--keygen", dir, "acme"]);
  execFileSync("cp", [join(dir, "acme.pem"), keys]);
  const pack = join(packs, "acme.json");
  writeFileSync(pack, JSON.stringify({ format: "mandu-consumer-pack/1", name: "acme/cli", version: "1", consumers: [{ basename: ".vault-token", apps: ["vault"] }] }));
  execFileSync("node", [SIGN, pack, join(dir, "acme.key")]);
  const home = join(dir, "home"); mkdirSync(home);
  const token = join(home, ".vault-token"); writeFileSync(token, "hvs.secret\n");
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({ socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false, packDir: packs, packKeysDir: keys,
    policyDocument: { version: 1, paths: [{ path: token, level: "no-model" }] } });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's channel (plan 13 D9)
  await c.connect();
  try {
    const listed = await c.consumerPacks();
    assert.deepEqual(listed.packs, [{ name: "acme/cli", version: "1", keyId: "acme", consumers: 1 }]);
    const v = await c.decideSecretOpen({ path: token, exe: "/usr/bin/vault", isAgent: false, exeSystem: true, openerEnv: [], procKey: "vault-1" });
    // plan 13 D8 (12): a pack is not a probe, so its program is no vetted
    // reader; it reads the twin (the wire release's, where it serves)
    assert.equal(v.verdict, "twin", "the pack's consumer reads the twin");
    const other = await c.decideSecretOpen({ path: token, exe: "/usr/bin/cat", isAgent: false, exeSystem: true, openerEnv: [], procKey: "cat-1" });
    assert.notEqual(other.verdict, "raw");
    const snap = await c.policySnapshot() as unknown as { relaxations: Array<{ kind: string; detail: string }> };
    assert.ok(snap.relaxations.some((r) => r.kind === "pack-consumer" && /consumer pack acme\/cli 1, key acme/.test(r.detail)), JSON.stringify(snap.relaxations));
  } finally {
    setPackConsumers([]);
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
