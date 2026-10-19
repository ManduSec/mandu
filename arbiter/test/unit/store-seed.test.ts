/**
 * store-seed.test.ts — a temporary arbiter's store seeded READ-ONLY from the
 * resident one's (db/store-seed.ts; `mandu why` with no Mandu running,
 * comparisons.md §3.2, runtime-instances.md §9b).
 *
 * Pins:
 *   - the copy holds the tables `mandu why` reads beyond the law in the
 *     file (remembered answers, waiting changes, the content in force,
 *     labels), the registered files' placeholder rows only, and NO original:
 *     every copied `value` is the placeholder's own name;
 *   - the content in force is carried for the policy file asked about only,
 *     re-keyed to the copy the temporary arbiter reads;
 *   - the resident store is never written: its bytes are unchanged and no
 *     `-wal` / `-shm` appears beside a closed one where SQLite takes a URI
 *     (on Node 22.13, which takes none, only the empty WAL and the index any
 *     reader of a WAL database creates); beside an open writer the
 *     read goes through the WAL (the newest commit is seen);
 *   - refusals leave nothing behind: no store, another Mandu version, a copy
 *     path already taken, the store as its own copy.
 *
 * Pure but for temp files: no axis is read (axes: none).
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { readOnlyUri, seedStoreFrom, SEED_TABLES } from "../../db/store-seed.js";
import { MANDU_DB_SCHEMA_VERSION, loadSymbolMap, openSymbolDb } from "../../symbol-table/symbol-table.js";
import { EgressApprovalStore } from "../../policy/egress-approvals.js";
import { PolicyProposalStore } from "../../policy/policy-proposals.js";
import { listSecretRegistry, registeredFileSymbols } from "../../secret-registry/registry.js";

const SECRET = "sk_live_SEEDVALUE_0123456789";
const POLICY = "/h/.mandu/policy.yaml";
const COPY_POLICY = "/t/policy.yaml";

/** A store as the arbiter's own modules write it, then closed. */
function residentStore(dir: string): string {
  const db = join(dir, "state", "mandu.db");
  mkdirSync(join(dir, "state"), { recursive: true });
  const s = openSymbolDb(db, { HOME: dir });
  const ins = s.prepare(
    "INSERT INTO symbols (sym_name, value, tool, field, origin, session_key, call_id, created_at, obsoleted_at, confidentiality, bindings, integrity) VALUES (?, ?, ?, ?, ?, NULL, ?, 1, ?, ?, ?, ?)",
  );
  // A registered .env (base row + its field row), an obsolete registration,
  // and a tool result's span (not a registration).
  ins.run("$MDU:nomodel_Read[aa11]", `STRIPE_KEY=${SECRET}\n`, "Read", null, "/h/proj/.env", null, null, "no-model", null, "trusted");
  ins.run("$MDU:nomodel_Read[aa11].STRIPE_KEY", SECRET, "Read", "STRIPE_KEY", "/h/proj/.env", null, null, "no-model", "[\"api.stripe.com\"]", "trusted");
  ins.run("$MDU:nomodel_Read[bb22]", "OLD=old-secret-value\n", "Read", null, "/h/proj/.env", null, 5, "no-model", null, "trusted");
  ins.run("$MDU:untrusted_WebFetch[cc33]", "a page's text", "WebFetch", "content", "https://example.com", "toolu_1", null, "public", null, "untrusted");
  s.close();
  const eg = new EgressApprovalStore({ dbPath: db });
  const row = eg.recordPending("$MDU:nomodel_Read[aa11].STRIPE_KEY", "collector.example", "unbound destination");
  eg.resolve(row.id, true, "always");
  eg.close();
  const pp = new PolicyProposalStore({ dbPath: db });
  pp.recordEnforced(POLICY, { hash: "h-in-force", text: "version: 1\n" });
  pp.recordEnforced("/elsewhere/policy.yaml", { hash: "h-other", text: "version: 1\n# other\n" });
  pp.close();
  return db;
}

const sha = (p: string): string => createHash("sha256").update(readFileSync(p)).digest("hex");

/** Beside a closed store: nothing new where this SQLite takes a URI (the
 *  immutable read); else only what any SQLite reader of a WAL database
 *  creates (Node 22.13): an EMPTY `-wal` and the `-shm` index, owner-only. */
function assertBeside(dir: string, before: string[], via: "uri" | "path"): void {
  const now = readdirSync(dir).sort();
  if (via === "uri") {
    assert.deepEqual(now, before, "nothing created beside the store");
    return;
  }
  for (const f of now.filter((n) => !before.includes(n))) {
    assert.ok(/\.db-(wal|shm)$/.test(f), `only a reader's WAL companions: ${f}`);
    assert.equal(statSync(join(dir, f)).mode & 0o077, 0, `${f} is owner-only`);
    if (f.endsWith("-wal")) assert.equal(statSync(join(dir, f)).size, 0, "an empty WAL: nothing written");
  }
}

test("the copy holds the remembered answers, the content in force and the registered placeholders, never an original; the store is untouched", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-seed-"));
  try {
    const from = residentStore(dir);
    // What the arbiter's own readers find in the store (they open and close it).
    const expect = { names: registeredFileSymbols(loadSymbolMap(from), "/h/proj/.env").map((r) => r.symbol), registry: listSecretRegistry(loadSymbolMap(from)) };
    const beside = readdirSync(join(dir, "state")).sort();
    assert.deepEqual(beside, ["mandu.db"], "a closed store: no -wal beside it");
    const settled = sha(from);
    const to = join(dir, "copy", "state", "mandu.db");
    const r = seedStoreFrom({ from, to, policy: { from: POLICY, to: COPY_POLICY } });
    assert.ok(r.ok, JSON.stringify(r));
    assert.equal(r.rows["symbols"], 2, "the active registration's rows only");
    assert.equal(r.rows["egress_approvals"], 1);
    assert.equal(r.rows["policy_enforced"], 1, "only the policy file asked about");
    assert.equal(sha(from), settled, "the store's bytes are unchanged");
    assertBeside(join(dir, "state"), beside, r.via);
    assert.equal(statSync(to).mode & 0o777, 0o600);

    assert.ok(!readFileSync(to).includes(SECRET), "no original in the copy's bytes");
    assert.ok(!readFileSync(to).includes("old-secret-value"));
    assert.ok(!readFileSync(to).includes("a page's text"), "no tool result either");
    const c = new DatabaseSync(to, { readOnly: true });
    try {
      for (const row of c.prepare("SELECT sym_name, value FROM symbols").all() as Array<{ sym_name: string; value: string }>) {
        assert.equal(row.value, row.sym_name, "the value is the placeholder's own name");
      }
      const eg = c.prepare("SELECT symbol, destination, status, scope FROM egress_approvals").all() as Array<Record<string, unknown>>;
      assert.deepEqual(eg.map((e) => ({ ...e })), [{ symbol: "$MDU:nomodel_Read[aa11].STRIPE_KEY", destination: "collector.example", status: "approved", scope: "always" }]);
      const enforced = c.prepare("SELECT path, hash FROM policy_enforced").all() as Array<Record<string, unknown>>;
      assert.deepEqual(enforced.map((e) => ({ ...e })), [{ path: COPY_POLICY, hash: "h-in-force" }], "re-keyed to the copy the temporary arbiter reads");
      assert.equal(Number((c.prepare("PRAGMA user_version").get() as { user_version: number }).user_version), MANDU_DB_SCHEMA_VERSION);
      const tables = (c.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>).map((t) => t.name);
      for (const t of tables) assert.ok((SEED_TABLES as readonly string[]).includes(t), `only the seed tables: ${t}`);
    } finally {
      c.close();
    }
    // The arbiter's own readers find the same registration in the copy.
    const copy = loadSymbolMap(to);
    assert.deepEqual(registeredFileSymbols(copy, "/h/proj/.env").map((r) => r.symbol), expect.names);
    assert.deepEqual(listSecretRegistry(copy).map((e) => ({ ...e })), expect.registry.map((e) => ({ ...e })));
    assert.ok(new EgressApprovalStore({ dbPath: to }).lookup("$MDU:nomodel_Read[aa11].STRIPE_KEY", "collector.example") === "approved");
    assert.deepEqual(new PolicyProposalStore({ dbPath: to }).enforcedPolicy(COPY_POLICY), { hash: "h-in-force", text: "version: 1\n" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("without a policy mapping no content in force is carried (the file is the law)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-seed-"));
  try {
    const from = residentStore(dir);
    const to = join(dir, "copy.db");
    const r = seedStoreFrom({ from, to });
    assert.ok(r.ok, JSON.stringify(r));
    assert.equal(r.rows["policy_enforced"], undefined);
    assert.equal(new PolicyProposalStore({ dbPath: to }).enforcedPolicy(POLICY), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("beside an open writer the read goes through the WAL: the newest commit is in the copy", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-seed-"));
  try {
    const from = residentStore(dir);
    const writer = new EgressApprovalStore({ dbPath: from });
    try {
      writer.recordPending("$MDU:nomodel_Read[aa11].STRIPE_KEY", "late.example", "unbound destination");
      assert.ok(existsSync(`${from}-wal`), "a live writer keeps a WAL");
      const to = join(dir, "copy.db");
      const r = seedStoreFrom({ from, to });
      assert.ok(r.ok, JSON.stringify(r));
      assert.equal(r.rows["egress_approvals"], 2);
      assert.equal(new EgressApprovalStore({ dbPath: to }).lookup("$MDU:nomodel_Read[aa11].STRIPE_KEY", "late.example"), "pending");
    } finally {
      writer.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("refusals leave nothing behind: no store, another Mandu version, a copy path taken, the store as its own copy", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-seed-"));
  try {
    const none = seedStoreFrom({ from: join(dir, "absent.db"), to: join(dir, "c1.db") });
    assert.equal(none.ok, false);
    assert.ok(!existsSync(join(dir, "c1.db")), "no copy for no store");
    assert.ok(!existsSync(join(dir, "absent.db")), "and no store created");

    const old = join(dir, "old.db");
    const o = new DatabaseSync(old);
    o.exec("PRAGMA user_version = 3; CREATE TABLE symbols (sym_name TEXT PRIMARY KEY, value TEXT NOT NULL)");
    o.close();
    const v = seedStoreFrom({ from: old, to: join(dir, "c2.db") });
    assert.equal(v.ok, false);
    assert.match((v as { why: string }).why, /another Mandu version \(schema v3\)/);
    assert.ok(!existsSync(join(dir, "c2.db")), "a refused copy is removed");

    const from = residentStore(join(dir, "r"));
    const taken = join(dir, "taken.db");
    writeFileSync(taken, "mine");
    const t = seedStoreFrom({ from, to: taken });
    assert.equal(t.ok, false);
    assert.equal(readFileSync(taken, "utf8"), "mine", "an existing file is never overwritten");

    const self = seedStoreFrom({ from, to: from });
    assert.equal(self.ok, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("readOnlyUri: read-only always; immutable only with no WAL beside the store; the path percent-encoded", () => {
  assert.equal(readOnlyUri("/h/.mandu/state/mandu.db", () => false), "file:///h/.mandu/state/mandu.db?mode=ro&immutable=1");
  assert.equal(readOnlyUri("/h/.mandu/state/mandu.db", (p) => p === "/h/.mandu/state/mandu.db-wal"), "file:///h/.mandu/state/mandu.db?mode=ro");
  assert.equal(readOnlyUri("/h/a b?c#d%e/mandu.db", () => false), "file:///h/a%20b%3Fc%23d%25e/mandu.db?mode=ro&immutable=1");
});
