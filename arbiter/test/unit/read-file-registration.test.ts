/**
 * read-file-registration.test — plan 10 §11.15, case 2 (the maintainer,
 * 2026-10-03): when the guard reports, on the human plane, a raw read of a
 * labelled file the launch never registered, the arbiter registers that
 * file itself (`registerSecret`), so its values are known secrets the value
 * backstop matches. Only on an attested report (never a data-socket claim:
 * an agent must not make the arbiter read or register files), idempotent,
 * at the label's level and bindings; no output is registered.
 *
 * Confidentiality axis: registration is a confidentiality act.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { loadSymbolMap } from "../../symbol-table/symbol-table.js";
import { fileRegisteredAsIs, registerSecret } from "../../secret-registry/registry.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const SHORT = "Tq7vZ2pX9kLm";

interface RegistryRow { path: string; symbol: string; level: string; bindings: string[]; fields: number }

test("a guard-reported raw read registers the labelled file once, at its label's level and bindings; a data-socket claim registers nothing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-read-reg-"));
  const notes = join(dir, "notes.txt");
  writeFileSync(notes, `vault notes for the team\npassword ${SHORT}\nrotate monthly\n`);
  const env = join(dir, ".env");
  writeFileSync(env, "API_KEY=Hw4rN8sQ2yBdKx\n");
  const big = join(dir, "dump.txt");
  writeFileSync(big, `${"filler line of a large labelled file\n".repeat(40_000)}`); // ~1.4 MiB
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, [
    "version: 1",
    "paths:",
    `  - path: ${notes}`,
    "    level: local-model",
    "    bindings: [vault.corp]",
    "    readers: [ssh-add]",
    `  - path: ${env}`,
    "    level: no-model",
    "    readers: [ssh-add]",
    `  - path: ${big}`,
    "    level: no-model",
    "    readers: [ssh-add]",
    "",
  ].join("\n"));
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({ socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's channel (plan 13 D9)
  const agent = new ArbiterClient(join(dir, "a.sock")); // the data socket the agent's programs reach
  await guard.connect();
  await agent.connect();
  const registry = (): RegistryRow[] => {
    const r = s.dispatch({ id: 1, op: "secretRegistry" } as never) as { ok: boolean; result: { entries: RegistryRow[] } };
    return r.result.entries;
  };
  const rowsFor = (p: string) => registry().filter((e) => e.path === p);
  const open = (c: ArbiterClient, path: string, n: number) =>
    c.decideSecretOpen({ path, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: `rr-psql-${n}`, parentKey: "rr-sh-0", ancestorKeys: ["rr-sh-0"], session: "rr" });
  try {
    // 1. a data-socket claim: the twin, and nothing read or registered
    const claimed = await open(agent, notes, 1);
    assert.equal(claimed.verdict, "twin");
    assert.deepEqual(rowsFor(notes), [], "a data-socket claim never makes the arbiter register a file");
    assert.deepEqual((await guard.scanSecretValues(`x ${SHORT} y`)).hits, []);

    // 2. the guard's attested report: raw, and the file is registered at its label
    const raw = await open(guard, notes, 2);
    assert.equal(raw.verdict, "raw", raw.reason);
    const reg = rowsFor(notes);
    assert.equal(reg.length, 1);
    assert.equal(reg[0]!.level, "local-model", "the label's level");
    assert.deepEqual(reg[0]!.bindings, ["vault.corp"], "the label's bindings");
    assert.deepEqual((await guard.scanSecretValues(`the key is ${SHORT}, ok`)).hits.map((h) => h.symbol), [reg[0]!.symbol],
      "the file's bare credential token is a known secret now (case 1)");
    assert.deepEqual((await guard.scanSecretValues("please rotate monthly")).hits, [], "its prose is not");

    // 3. idempotent: a second read, or a third by another process, adds no row
    await open(guard, notes, 3);
    await open(guard, notes, 4);
    assert.equal(rowsFor(notes).length, 1);
    // ...and the launch's own registration of the same file is the same row
    const launch = await guard.registerSecret({ path: notes });
    assert.equal(launch.symbol, reg[0]!.symbol);
    // a changed file is registered again (its new value is the secret now)
    writeFileSync(notes, `password Zx81qWv0pLr4Nb\n`);
    await open(guard, notes, 5);
    assert.ok((await guard.scanSecretValues("Zx81qWv0pLr4Nb")).hits.length > 0);

    // 4. a shaped file: its fields, as the launch would mint them
    assert.equal((await open(guard, env, 6)).verdict, "raw");
    assert.equal(rowsFor(env)[0]?.fields, 1);
    assert.ok((await guard.scanSecretValues("export T=Hw4rN8sQ2yBdKx")).hits.length > 0);

    // 5. a file over 1 MiB is registered too (plan 10 §11.18: it was skipped)
    assert.equal((await open(guard, big, 7)).verdict, "raw");
    assert.equal(rowsFor(big).length, 1);
  } finally {
    guard.close();
    agent.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// The self-registration skips a file whose current text the launch already
// registered (2026-10-03, the npmrc-wire-twin flake): its rows are the known
// secret, and a second base row under the self-registration's key (no
// session) competed with them for "the newest registration".
test("fileRegisteredAsIs: the launch's row of this exact text, under any session key, at a level at least the label's; never another text, path or a lower row", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-read-reg-asis-"));
  try {
    const dbPath = join(dir, "db.sqlite");
    const file = join(dir, "notes.txt");
    const text = `password ${SHORT}\n`;
    writeFileSync(file, text);
    const label = (p: string) => (p === file ? { level: "local-model" as const, bindings: [], via: file } : null);
    const map = loadSymbolMap(dbPath);
    assert.equal(fileRegisteredAsIs(map, file, text, "local-model"), false, "nothing registered yet");
    const reg = registerSecret(map, { path: file, sessionKey: "sess-a", resolveLabel: label }, dbPath);
    assert.ok(reg.symbol, reg.reason);
    assert.equal(fileRegisteredAsIs(map, file, text, "local-model"), true, "a session-keyed launch row counts");
    assert.equal(fileRegisteredAsIs(map, file, text, "any-model"), true, "a label lowered since is covered");
    assert.equal(fileRegisteredAsIs(map, file, text, "no-model"), false, "a stricter label is not: the file registers at the label's level");
    assert.equal(fileRegisteredAsIs(map, file, "password Zx81qWv0pLr4Nb\n", "local-model"), false, "a changed file registers its new value");
    assert.equal(fileRegisteredAsIs(map, join(dir, "other.txt"), text, "local-model"), false, "another path");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── plan 10 §11.18: large and binary files, a holder's copy (D4), the bound ──

const BIG_SECRET = "Rk4mW9xQ2pLs"; // 12 characters, a bare token deep in a 2 MiB file
const BIN_SECRET = "Gv7bN3kT8rYd"; // 12 characters, a printable string inside a binary file
const COPY_SECRET = "Jc2hP6wZ9sMf"; // 12 characters, a value only the copy holds

interface Harness {
  dir: string;
  guard: ArbiterClient;
  rowsFor: (p: string) => RegistryRow[];
  open: (path: string, procKey: string, opts?: { exe?: string; parentKey?: string }) => Promise<{ verdict: string; reason: string }>;
}

async function withServer(
  paths: (dir: string) => Array<Record<string, unknown>>,
  fn: (h: Harness) => Promise<void>,
  pieceLimits?: { scanChars?: number; pieces?: number },
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-read-reg-big-"));
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    policyDocument: { version: 1, paths: paths(dir) } as never, log: () => {}, confidentiality: true, integrity: false,
    ...(pieceLimits ? { pieceLimits } : {}),
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock"));
  await guard.connect();
  const rowsFor = (p: string): RegistryRow[] => {
    const r = s.dispatch({ id: 1, op: "secretRegistry" } as never) as { ok: boolean; result: { entries: RegistryRow[] } };
    return r.result.entries.filter((e) => e.path === p);
  };
  const open: Harness["open"] = (path, procKey, opts = {}) =>
    guard.decideSecretOpen({ path, exe: opts.exe ?? "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey, ...(opts.parentKey ? { parentKey: opts.parentKey, ancestorKeys: [opts.parentKey] } : {}), session: "rr" });
  try {
    await fn({ dir, guard, rowsFor, open });
  } finally {
    guard.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test("a raw read of a labelled file over 1 MiB, or binary, registers it: a short token inside is a known secret (plan 10 §11.18)", async () => {
  const big = (d: string) => join(d, "export.log");
  const bin = (d: string) => join(d, "vault.db");
  await withServer((d) => [
    { path: big(d), level: "no-model", readers: ["ssh-add"] },
    { path: bin(d), level: "no-model", readers: ["ssh-add"] },
  ], async ({ dir, guard, rowsFor, open }) => {
    writeFileSync(big(dir), `${"2026-10-07 12:00:00 INFO request served in 12 ms\n".repeat(30_000)}login password ${BIG_SECRET}\n${"2026-10-07 12:00:01 INFO request served in 9 ms\n".repeat(20_000)}`);
    writeFileSync(bin(dir), Buffer.concat([Buffer.from([0, 1, 2, 3]), Buffer.from("SQLite format 3"), Buffer.alloc(64), Buffer.from(`api_token ${BIN_SECRET}`), Buffer.from([0, 0xff, 0xfe, 0])]));
    assert.deepEqual((await guard.scanSecretValues(`x ${BIG_SECRET} ${BIN_SECRET}`)).hits, [], "nothing registered before the reads");
    assert.equal((await open(big(dir), "rr-big-1")).verdict, "raw");
    assert.equal(rowsFor(big(dir)).length, 1, "the 2 MiB file is registered");
    assert.equal((await guard.scanSecretValues(`the password is ${BIG_SECRET}`)).hits.length, 1, "its short token is a known secret");
    assert.deepEqual((await guard.scanSecretValues("INFO request served")).hits, [], "its short prose is not");
    assert.equal((await open(bin(dir), "rr-bin-2")).verdict, "raw");
    assert.equal(rowsFor(bin(dir)).length, 1, "the binary file is registered");
    assert.equal((await guard.scanSecretValues(`strings: api_token ${BIN_SECRET}\n`)).hits.length, 1, "its printable token is a known secret");
  });
});

test("D4: a holder's raw read of a copy it wrote registers the copy, at its sources' bindings: a value only the copy holds is a known secret (plan 10 §11.18)", async () => {
  const env = (d: string) => join(d, ".env");
  await withServer((d) => [{ path: env(d), level: "no-model", readers: ["ssh-add"], bindings: ["api.stripe.com"] }], async ({ dir, guard, rowsFor, open }) => {
    writeFileSync(env(dir), "STRIPE_KEY=sk_live_D4CANARY0000000001\n");
    assert.equal((await open(env(dir), "rr-holder-1")).verdict, "raw");
    // the holder derives a session token from it and writes it out
    const copy = join(dir, "session.json");
    writeFileSync(copy, `{"session_token": "${COPY_SECRET}", "expires": 3600}\n`);
    assert.equal((await guard.labelWrittenPathTainted({ path: copy, procKey: "rr-holder-1" })).labeled, true);
    assert.deepEqual((await guard.scanSecretValues(`token ${COPY_SECRET}`)).hits, [], "not a known secret before the copy is read");
    // the holder's child reads the copy raw (it holds every source)
    const d = await open(copy, "rr-child-2", { exe: "/usr/bin/node", parentKey: "rr-holder-1" });
    assert.equal(d.verdict, "raw", d.reason);
    const rows = rowsFor(copy);
    assert.equal(rows.length, 1, "the copy is registered");
    assert.deepEqual(rows[0]!.bindings, ["api.stripe.com"], "at its sources' bindings (label by reference, plan 13 §4.6)");
    const hits = (await guard.scanSecretValues(`export TOKEN=${COPY_SECRET}`)).hits;
    assert.ok(hits.length > 0 && hits.every((h) => h.symbol.startsWith(rows[0]!.symbol)), `the copy's own value is a known secret, of the copy's rows: ${JSON.stringify(hits)}`);
  });
});

test("fail-closed: a file whose pieces cannot be computed (over the bound) is never released by an output rule; one under it is (plan 10 §11.18)", async () => {
  const small = (d: string) => join(d, "small.txt");
  const big = (d: string) => join(d, "big.txt");
  const dense = (d: string) => join(d, "dense.txt");
  const env = (d: string) => join(d, ".env");
  const clear = [{ app: "ssh-add", output: "clear" }];
  await withServer((d) => [
    { path: small(d), level: "no-model", readers: clear },
    { path: big(d), level: "no-model", readers: clear },
    { path: dense(d), level: "no-model", readers: clear },
    { path: env(d), level: "no-model", readers: ["ssh-add"] },
  ], async ({ dir, guard, open }) => {
    writeFileSync(small(dir), `password ${BIG_SECRET}\n`);
    writeFileSync(big(dir), `${"lorem ipsum dolor sit amet consectetur\n".repeat(2_000)}password ${BIG_SECRET}\n`); // ~78 KiB, over the 64 KiB bound
    // under the scan bound, over the piece bound (the launch registers it)
    writeFileSync(dense(dir), Array.from({ length: 12 }, (_, i) => `token k${i}Q7vZ2pX9kLm${i}`).join("\n") + "\n");
    assert.ok((await guard.registerSecret({ path: dense(dir) })).symbol);
    let n = 0;
    const ruleOf = async (path: string): Promise<string> => {
      n++;
      const callId = `toolu_bound_${n}`;
      const command = `ssh-add -L ${path}`;
      await guard.recordCallCommand({ callId, command, sessionKey: "rr" });
      await guard.recordExecRoot({ procKey: `bound-sh-${n}`, parentKey: "agent-0", argv: ["/bin/bash", "-lc", command], session: "rr", callRoot: true });
      await guard.recordExecRoot({ procKey: `bound-r-${n}`, parentKey: `bound-sh-${n}`, argv: ["/usr/bin/ssh-add", "-L", path], session: "rr" });
      const d = await open(path, `bound-r-${n}`, { parentKey: `bound-sh-${n}` });
      assert.equal(d.verdict, "raw", d.reason);
      const t = await guard.callTaint(callId, { command, session: "rr" });
      assert.equal(t.evidence, "tree");
      return t.rule;
    };
    assert.equal(await ruleOf(small(dir)), "clear", "control: a file under the bound keeps its output rule");
    assert.equal(await ruleOf(big(dir)), "secret", "a file over the scan bound (not registered): masked whole");
    assert.equal(await ruleOf(dense(dir)), "secret", "a registered file cut at the piece bound: masked whole");

    // D4: a holder's copy over the bound is not read raw (its pieces would be unknown)
    writeFileSync(env(dir), "STRIPE_KEY=sk_live_D4CANARY0000000001\n");
    assert.equal((await open(env(dir), "bound-holder")).verdict, "raw");
    const copy = join(dir, "copy.txt");
    writeFileSync(copy, `${"lorem ipsum dolor sit amet consectetur\n".repeat(2_000)}STRIPE_KEY=sk_live_D4CANARY0000000001\n`);
    assert.equal((await guard.labelWrittenPathTainted({ path: copy, procKey: "bound-holder" })).labeled, true);
    assert.equal((await open(copy, "bound-child", { exe: "/usr/bin/node", parentKey: "bound-holder" })).verdict, "twin", "fail-closed: the twin");
    const okCopy = join(dir, "copy-small.txt");
    writeFileSync(okCopy, "STRIPE_KEY=sk_live_D4CANARY0000000001\n");
    assert.equal((await guard.labelWrittenPathTainted({ path: okCopy, procKey: "bound-holder" })).labeled, true);
    assert.equal((await open(okCopy, "bound-child2", { exe: "/usr/bin/node", parentKey: "bound-holder" })).verdict, "raw", "control: a copy under the bound");
  }, { scanChars: 64 * 1024, pieces: 8 });
});
