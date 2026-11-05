/**
 * pgpass-wire-twin.test.ts — db-login-release.md §3.3 over the real IPC:
 * pg_dump (a known consumer of `~/.pgpass` that is not a printer) reads the
 * launch HOME's `.pgpass` as its twin, with no ask, in a session whose proxy
 * inspects TLS (`registerWireRelease`), when every line's password is bound
 * to its own database (the registration's wire grant): the session's
 * database relay puts it back in that database's login.
 *
 * Found by the live client run (docs/design/testing/live-clients.md §2.3,
 * 2026-10-25): pg_dump was ASKED for the raw file; with nobody to answer its
 * open was refused after the ask's timeout, libpq found no password and
 * pg_dump prompted for one.
 *
 *   - before the session's word, and for a file with a `*` host line (no
 *     relay, no binding): pg_dump is asked, as before;
 *   - after it: the twin, no taint;
 *   - psql (a printer) reads the twin throughout.
 *
 * Mandu-new test. Axes stated: `secrets` (confidentiality on, integrity off).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const S = "sess-pgpass-wire";

async function stack(pgpass: string) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-pgpass-wire-"));
  const home = join(dir, "home");
  mkdirSync(home);
  const file = join(home, ".pgpass");
  writeFileSync(file, pgpass, { mode: 0o600 });
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${JSON.stringify(file)}\n    level: no-model\n`);
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "human", "h.sock");
  const s = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath: policy });
  await s.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const h = new ArbiterClient(humanSock); await h.connect();
  const open = (procKey: string, exe: string, session = S) =>
    h.decideSecretOpen({ path: file, exe, isAgent: false, exeSystem: true, openerEnv: [], procKey, session, ask: "known" });
  return { data, h, file, home, open, done: async () => { data.close(); h.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("pg_dump reads the HOME .pgpass's twin, unasked and untainted, in a session whose relay puts each password back; before it, it is asked", async () => {
  const k = await stack("db.internal:5432:app:alice:pgPW_alice_WIRE1\nold.internal:5433:*:bob:pgPW_bob_WIRE2\n");
  try {
    const reg = await k.h.registerSecret({ path: k.file, home: k.home, sessionKey: S });
    assert.ok(reg.twin, reg.reason);
    assert.equal((await k.open("pg_dump-0", "/usr/lib/postgresql/16/bin/pg_dump")).verdict, "ask", "no session word: asked, as before");
    assert.equal((await k.open("psql-0", "/usr/lib/postgresql/16/bin/psql")).verdict, "twin", "a printer reads the twin");
    await k.h.registerWireRelease(S, true);
    const d = await k.open("pg_dump-1", "/usr/lib/postgresql/16/bin/pg_dump");
    assert.equal(d.verdict, "twin", d.reason);
    assert.match(d.reason, /served its twin: the session's database relay puts each password back in its own database's login \(db\.internal:5432, old\.internal:5433\)/);
    assert.equal((await k.data.processSecretTaint("pg_dump-1")).level, null, "no raw byte, no taint");
    assert.equal((await k.open("pg_dump-2", "/usr/lib/postgresql/16/bin/pg_dump", "sess-other")).verdict, "ask", "another session: asked");
  } finally { await k.done(); }
});

test("a .pgpass with a * host line (no relay puts that password back) keeps pg_dump's ask", async () => {
  const k = await stack("db.internal:5432:app:alice:pgPW_alice_WIRE3\n*:*:*:carol:pgPW_carol_WIRE4\n");
  try {
    await k.h.registerSecret({ path: k.file, home: k.home, sessionKey: S });
    await k.h.registerWireRelease(S, true);
    assert.equal((await k.open("pg_dump-3", "/usr/lib/postgresql/16/bin/pg_dump")).verdict, "ask");
  } finally { await k.done(); }
});
