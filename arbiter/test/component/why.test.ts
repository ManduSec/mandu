/**
 * why e2e — the `whyPath` / `whyHost` ops over the REAL ArbiterServer and
 * ArbiterClient (comparisons.md §3.2, `mandu why`): a law with a
 * reader-listed, bound `.env`, a catalog-only `.pgpass`, and a connect
 * allowance. Read-only: asking leaves the approval queue and the rule-hit
 * counts untouched. 2026-10-10: `whyPath` reads only a regular file of at
 * most MAX_STRUCTURED_BYTES (the agent reaches it on the data socket; a
 * FIFO named `.env` used to block the arbiter for good); since the second
 * review it checks the file before opening it (a FIFO is never opened) and
 * reads at most WHY_MAX_BYTES (unit: why-preview.test.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { whyFileText } from "../../ipc/why-preview.js";
import { MAX_STRUCTURED_BYTES } from "../../policy/secret-extract.js";
import { ArbiterClient } from "../../ipc/client.js";
import { loadPolicyFileStrict } from "../../policy/policy-file-validate.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON: levels, readers and bindings exist on this axis

test("whyPath and whyHost answer from the law in force and record nothing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-why-e2e-"));
  const home = join(dir, "home");
  const env = join(home, "proj", ".env");
  const file = join(dir, "policy.yaml");
  writeFileSync(file, `version: 1
paths:
  - path: ${env}
    level: no-model
    bindings: [api.stripe.com]
    readers: [deploy-tool]
    others: deny
destinations:
  - host: db.internal
    port: 5432
    connect: allow
    reason: the team database
`);
  const loaded = loadPolicyFileStrict(file);
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0, policyDocument: loaded.config,
  });
  await server.listen();
  const client = new ArbiterClient(join(dir, "a.sock"));
  try {
    await client.connect();
    const p = await client.whyPath(env, home);
    assert.equal(p.axis, true);
    assert.equal(p.level, "no-model");
    assert.match(p.rule ?? "", /^label:/);
    assert.deepEqual(p.bindings, ["api.stripe.com"]);
    assert.equal(p.others, "deny");
    assert.equal(JSON.stringify(p.readers).includes("deploy-tool"), true);
    assert.equal(p.twinShape, "dotenv");

    const pg = await client.whyPath(join(home, ".pgpass"), home);
    assert.equal(pg.level, "no-model");
    assert.equal(pg.rule, "prefix:~/.pgpass", "the catalog decided, against the launching user's HOME");
    assert.deepEqual(pg.consumers, ["psql", "pg_dump", "pg_restore"]);
    assert.equal(pg.wire?.served, false);
    assert.equal(pg.twinShape, "pgpass");

    // Plan 10 §11.13.3: an ssh config's withheld commands, by line and
    // keyword, read from the real file; never their text.
    const sshDir = join(home, ".ssh");
    mkdirSync(sshDir, { recursive: true });
    writeFileSync(join(sshDir, "config"), "Host db\n  ProxyCommand mysql -pWHYpw77 -h %h\nHost jump\n  ProxyCommand ssh -W %h:%p bastion\n  RemoteCommand tmux attach\n");
    const ssh = await client.whyPath(join(sshDir, "config"), home);
    assert.equal(ssh.twinShape, "ssh-config");
    assert.deepEqual(ssh.withheld, [{ line: 2, keyword: "ProxyCommand" }, { line: 5, keyword: "RemoteCommand" }]);
    assert.ok(!JSON.stringify(ssh).includes("WHYpw77") && !JSON.stringify(ssh).includes("mysql"), "no command text in the answer");
    assert.equal(p.withheld, undefined, "only an ssh config carries the list");

    // 2026-10-09: the twin a registration makes of the file AS IT IS, read
    // from the real file (not the shape its path suggests): the ssh config's
    // withheld commands are its masked values; a file that is not there has
    // no twin to describe; a catalog config with no secret is its own text.
    assert.deepEqual(ssh.twin, { form: "structured", shape: "ssh-config", fields: 2 });
    assert.equal(p.twin, undefined, "no .env on disk: nothing is registered, nothing to describe");
    writeFileSync(join(sshDir, "config"), "Host db\n  HostName 10.0.0.7\n  User deploy\n");
    assert.deepEqual((await client.whyPath(join(sshDir, "config"), home)).twin, { form: "own-text", shape: "ssh-config", fields: 0 });
    mkdirSync(join(home, "proj"), { recursive: true });
    writeFileSync(env, "STRIPE_KEY=sk_live_WHYtwin\nPORT=3000\n");
    assert.deepEqual((await client.whyPath(env, home)).twin, { form: "structured", shape: "dotenv", fields: 1 });

    const pub = await client.whyPath(join(home, "proj", "README.md"), home);
    assert.equal(pub.level, "public");
    assert.equal(pub.rule, null);
    assert.equal(pub.agentFile, undefined, "an ordinary file is no agent's");
    assert.equal(pg.agentFile, undefined);

    // secret-discovery.md §1.10: an agent's login (raw only in a launch of
    // that agent) and an agent's own data (raw in every launch) say so, so
    // `mandu why` never promises a placeholder copy where a launch leaves the
    // file raw. A moved Codex home is named from the user's variables.
    const codexAuth = await client.whyPath(join(home, ".codex", "auth.json"), home);
    assert.equal(codexAuth.level, "no-model");
    assert.deepEqual(codexAuth.agentFile, { kind: "login", agent: "codex" });
    assert.deepEqual((await client.whyPath(join(home, ".claude.json"), home)).agentFile, { kind: "login", agent: "claude" });
    assert.deepEqual((await client.whyPath(join(home, ".claude", "projects", "s.jsonl"), home)).agentFile, { kind: "store", agent: "claude" });
    const moved = join(dir, "cx", "auth.json");
    const bare = await client.whyPath(moved, home);
    assert.equal(bare.agentFile, undefined);
    assert.equal(bare.level, "public", "no catalog rule names a moved Codex home");
    const named = await client.whyPath(moved, home, { CODEX_HOME: join(dir, "cx"), OPENAI_API_KEY: "sk-not-a-path" });
    assert.deepEqual(named.agentFile, { kind: "login", agent: "codex" });
    // …and a login is a secret all the same, as the walk judges it
    // (`agentLoginConfidentiality`): twinned under every other agent.
    assert.equal(named.level, "no-model");
    assert.equal(named.rule, "agent-login:codex");

    const h = await client.whyHost("api.stripe.com");
    assert.deepEqual(h.bound.map((b) => b.path), [env]);
    assert.ok(h.release.bound && h.release.unbound, "both probes answered");
    assert.equal(h.release.bound!.decision.allow, true, `a bound secret is released at its host: ${JSON.stringify(h.release.bound)}`);
    assert.equal(h.release.unbound!.decision.allow, false, "an unbound secret is not");

    const db = await client.whyHost("db.internal");
    assert.deepEqual(db.bound, []);
    assert.deepEqual(db.destinations.map((d) => [d.host, d.port, d.connect]), [["db.internal", 5432, "allow"]]);

    const snap = await client.policySnapshot();
    assert.equal(snap.verdicts.length, 0, "asking queued nothing");
  } finally {
    client.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("whyPath reads only a regular file of bounded size: a FIFO, a link to /dev/zero or an oversize file has no twin, the answer comes at once, and the arbiter keeps answering (2026-10-10)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-why-fifo-"));
  const home = join(dir, "home");
  const proj = join(home, "proj");
  const sshDir = join(home, ".ssh");
  for (const d of [join(proj, "fifo"), join(proj, "zero"), join(proj, "big"), sshDir]) mkdirSync(d, { recursive: true });
  // Catalog shapes the agent can make in its workspace: `.env*`, and its own ~/.ssh/config.
  const fifoEnv = join(proj, "fifo", ".env");
  const sshConfig = join(sshDir, "config");
  execFileSync("mkfifo", [fifoEnv]);
  execFileSync("mkfifo", [sshConfig]);
  const zeroEnv = join(proj, "zero", ".env");
  symlinkSync("/dev/zero", zeroEnv);
  const bigEnv = join(proj, "big", ".env");
  writeFileSync(bigEnv, "STRIPE_KEY=sk_live_WHYbig\n");
  truncateSync(bigEnv, MAX_STRUCTURED_BYTES + 1); // sparse: no 8 MB written
  const okEnv = join(proj, ".env");
  writeFileSync(okEnv, "STRIPE_KEY=sk_live_WHYok\nPORT=3000\n");
  let watchdog: ChildProcess | undefined;
  let writer: ChildProcess | undefined;
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  const client = new ArbiterClient(join(dir, "a.sock"));
  try {
    await client.connect();
    // A writer that opens each FIFO after 3 s: if the arbiter blocked on one
    // (it runs in this process, so no timer here could fire), this frees it
    // and the elapsed time below fails the test instead of hanging the run.
    // Its own process group, killed whole at the end: no writer outlives the test.
    watchdog = spawn("sh", ["-c", 'sleep 3; for f; do (echo x > "$f") & done; wait', "_", fifoEnv, sshConfig], { stdio: "ignore", detached: true });
    const t0 = Date.now();
    const fifo = await client.whyPath(fifoEnv, home);
    const ssh = await client.whyPath(sshConfig, home);
    const ms = Date.now() - t0;
    assert.ok(ms < 2000, `the two FIFO answers took ${ms} ms: the arbiter blocked on a FIFO`);
    const big = await client.whyPath(bigEnv, home);
    const zero = await client.whyPath(zeroEnv, home);
    assert.ok(Date.now() - t0 < 2000, `the answers took ${Date.now() - t0} ms: the arbiter read a file without a limit`);
    for (const [what, a] of [["a FIFO", fifo], ["a link to /dev/zero", zero], ["a file over MAX_STRUCTURED_BYTES", big], ["an ssh config that is a FIFO", ssh]] as const) {
      assert.notEqual(a.level, "public", `${what} is a secret path by its name`);
      assert.equal(a.twin, undefined, `${what}: no twin is described`);
    }
    assert.deepEqual(ssh.withheld ?? [], [], "an ssh config it cannot read withholds nothing it can name");
    // Still answering, and a regular file is read as before.
    assert.deepEqual((await client.whyPath(okEnv, home)).twin, { form: "structured", shape: "dotenv", fields: 1 });
    // The reader itself: only a regular file within the limit.
    assert.equal(whyFileText(fifoEnv), null);
    assert.equal(whyFileText(zeroEnv), null);
    assert.equal(whyFileText(bigEnv), null);
    assert.equal(whyFileText(join(proj, "missing")), null);
    assert.equal(whyFileText(okEnv), "STRIPE_KEY=sk_live_WHYok\nPORT=3000\n");
    // Checked before it is opened (2026-10-10, second review): a writer
    // blocked on a FIFO stays blocked, since no reader ever opened it.
    const fifo2 = join(proj, "fifo", "servers.json");
    execFileSync("mkfifo", [fifo2]);
    const opened = join(dir, "opened");
    writer = spawn("sh", ["-c", 'echo x > "$1" && : > "$2"', "_", fifo2, opened], { stdio: "ignore", detached: true });
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(whyFileText(fifo2), null);
    await client.whyPath(fifo2, home);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(existsSync(opened), false, "the FIFO was opened (its writer got through)");
  } finally {
    for (const w of [watchdog, writer]) if (w?.pid !== undefined) try { process.kill(-w.pid, "SIGKILL"); } catch { /* already gone */ }
    client.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
