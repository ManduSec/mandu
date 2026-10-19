/**
 * secret-registry — the arbiter pre-symbolizes the user's secrets so the agent
 * learns NAMES, never BYTES (confidentiality.md §7.2, plan 4′).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadSymbolMap, getSymbolEntry } from "../../symbol-table/symbol-table.js";
import { registerSecret, listSecretRegistry, noProxyMatches, wireServableTwin, wireReleaseScheme } from "../../secret-registry/registry.js";
import { type DesymbolizationRequest, wirePositionRefusal, wireSchemeRefusal } from "../../policy/policy-interface.js";
import { ArbiterServer } from "../../ipc/server.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const RAW = "[default]\naws_access_key_id=AKIA-REAL-SECRET\n";

function fixture(): { dir: string; dbPath: string; secret: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-reg-"));
  mkdirSync(join(dir, ".aws"), { recursive: true });
  const secret = join(dir, ".aws", "credentials");
  writeFileSync(secret, RAW);
  return {
    dir,
    dbPath: join(dir, "symbols.db"),
    secret,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

test("registerSecret reads the file and mints a strict × trusted symbol", () => {
  const { dbPath, secret, cleanup } = fixture();
  try {
    const map = loadSymbolMap(dbPath);
    const r = registerSecret(map, { path: secret }, dbPath);
    assert.ok(r.symbol, r.reason);
    assert.ok(r.symbol!.startsWith("$MDU:nomodel_Read["), r.symbol!);

    const e = getSymbolEntry(map, r.symbol!);
    assert.equal(e?.confidentiality, "no-model");
    // TRUSTED integrity is what lets the gate release it at a BOUND destination
    // with no approval (§3.2) — it is the user's own file, not attacker input.
    assert.equal(e?.integrity, "trusted");
    assert.equal(e?.origin, secret);
    assert.equal(e?.value, RAW, "the arbiter holds the original bytes");
  } finally {
    cleanup();
  }
});

test("registration is idempotent — the twin stays stable across launches", () => {
  const { dbPath, secret, cleanup } = fixture();
  try {
    const map = loadSymbolMap(dbPath);
    const a = registerSecret(map, { path: secret }, dbPath);
    const b = registerSecret(map, { path: secret }, dbPath);
    assert.equal(b.symbol, a.symbol);
    assert.match(b.reason, /already registered/);
    // ...and it survives a reload (the launcher re-registers every launch).
    const c = registerSecret(loadSymbolMap(dbPath), { path: secret }, dbPath);
    assert.equal(c.symbol, a.symbol);
  } finally {
    cleanup();
  }
});

test("fail-soft: a non-catalog path, a missing file, and an empty file all return null", () => {
  const { dir, dbPath, cleanup } = fixture();
  try {
    const map = loadSymbolMap(dbPath);
    const notes = join(dir, "notes.md");
    writeFileSync(notes, "hello");
    assert.equal(registerSecret(map, { path: notes }, dbPath).symbol, null);
    assert.equal(registerSecret(map, { path: join(dir, ".aws", "nope") }, dbPath).symbol, null);
    const empty = join(dir, ".aws", "credentials.empty");
    writeFileSync(empty, "");
    assert.equal(registerSecret(map, { path: empty }, dbPath).symbol, null);
  } finally {
    cleanup();
  }
});

test("listSecretRegistry returns {path, symbol, level, bindings}, sorted", () => {
  const { dir, dbPath, secret, cleanup } = fixture();
  try {
    const map = loadSymbolMap(dbPath);
    const env = join(dir, ".env");
    writeFileSync(env, "API_KEY=x");
    registerSecret(map, { path: secret }, dbPath);
    registerSecret(map, { path: env }, dbPath);
    const list = listSecretRegistry(map);
    assert.equal(list.length, 2);
    assert.deepEqual(list.map((e) => e.path), [env, secret].sort());
    for (const e of list) assert.ok(e.symbol.startsWith("$MDU:nomodel_"));
  } finally {
    cleanup();
  }
});

// ── the IPC ops, ON and OFF ─────────────────────────────────────────────────

function server(dir: string, dbPath: string, confidentiality: boolean): ArbiterServer {
  return new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"),
    dbPath,
    eventDir: join(dir, "events"),
    log: () => {},
    confidentiality,
  });
}

test("registerSecret op ON: mints the symbol; the deep resolve REFUSES it (Plan 2)", () => {
  const { dir, dbPath, secret, cleanup } = fixture();
  const s = server(dir, dbPath, true);
  try {
    const reg = s.dispatch({ id: 1, op: "registerSecret", path: secret }) as {
      ok: boolean; result: { symbol: string | null };
    };
    assert.equal(reg.ok, true);
    const sym = reg.result.symbol;
    assert.ok(sym);

    // The U-LLM path must not see it (the quarantine is an egress to the provider).
    const deep = s.dispatch({ id: 2, op: "resolve", symbol: sym!, deep: true }) as {
      result: { value: string | null };
    };
    assert.equal(deep.result.value, null, "deep resolve refuses a secret");

    // But the HumanView desymbolize DOES reveal it — the human owns their secrets.
    const human = s.dispatch({ id: 3, op: "desymbolize", text: `key: ${sym}` }) as {
      result: { text: string };
    };
    assert.ok(human.result.text.includes("AKIA-REAL-SECRET"));

    const list = s.dispatch({ id: 4, op: "secretRegistry" }) as {
      result: { entries: Array<{ path: string; symbol: string; level: string; bindings: string[] }> };
    };
    assert.deepEqual(list.result.entries, [
      { path: secret, symbol: sym!, fields: 1, level: "no-model", bindings: [] },
    ]);
  } finally {
    void s.close();
    cleanup();
  }
});

test("registerSecret op OFF: refuses — no silent secret-symbol minting when the switch is off", () => {
  const { dir, dbPath, secret, cleanup } = fixture();
  const s = server(dir, dbPath, false);
  try {
    const reg = s.dispatch({ id: 1, op: "registerSecret", path: secret }) as {
      ok: boolean; result: { symbol: string | null; reason: string };
    };
    assert.equal(reg.result.symbol, null);
    assert.match(reg.result.reason, /OFF/);

    const list = s.dispatch({ id: 2, op: "secretRegistry" }) as {
      result: { entries: unknown[] };
    };
    assert.deepEqual(list.result.entries, []);

    const disc = s.dispatch({ id: 3, op: "discoverSecrets", roots: [dir] }) as {
      result: { files: unknown[] };
    };
    assert.deepEqual(disc.result.files, [], "OFF discovers nothing");
  } finally {
    void s.close();
    cleanup();
  }
});

test("discoverSecrets op ON: finds the catalog files under the given roots, and carries the not-covered ledger", () => {
  const { dir, dbPath, secret, cleanup } = fixture();
  const s = server(dir, dbPath, true);
  try {
    const disc = s.dispatch({ id: 1, op: "discoverSecrets", roots: [dir] }) as {
      result: { files: Array<{ path: string }>; skipped: unknown[]; counts: Record<string, number>; limits: { maxDepth: number; maxFiles: number }; truncated: boolean };
    };
    assert.ok(disc.result.files.some((f) => f.path === secret));
    assert.ok(Array.isArray(disc.result.skipped));
    assert.equal(typeof disc.result.counts["depth"], "number");
    assert.equal(disc.result.limits.maxDepth, 4);
    assert.equal(disc.result.truncated, false);
  } finally {
    void s.close();
    cleanup();
  }
});

test("envSecretNames op: names only, values unseen, nothing minted; answers with the axis OFF too", () => {
  const { dir, dbPath, cleanup } = fixture();
  for (const on of [true, false]) {
    const s = server(dir, dbPath, on);
    try {
      const r = s.dispatch({ id: 1, op: "envSecretNames", names: ["STRIPE_KEY", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "HOME", "ANTHROPIC_API_KEY", "PATH", "DB_PASSWORD"] }) as {
        ok: boolean; result: { matched: string[] };
      };
      assert.equal(r.ok, true);
      assert.deepEqual(r.result.matched, ["GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD"], `axis ${on}`);
      const list = s.dispatch({ id: 2, op: "secretRegistry" }) as { result: { entries: unknown[] } };
      assert.deepEqual(list.result.entries, [], "the dry run registers nothing");
    } finally {
      void s.close();
    }
  }
  cleanup();
});

// ── confidentialityState: the dashboard's one call (plan 5) ─────────────────

test("confidentialityState ON: the switch + the standing release surface, never values", () => {
  const { dir, dbPath, secret, cleanup } = fixture();
  const s = server(dir, dbPath, true);
  try {
    s.dispatch({ id: 1, op: "registerSecret", path: secret });
    const st = s.dispatch({ id: 2, op: "confidentialityState" }) as {
      result: {
        enabled: boolean;
        secrets: Array<{ path: string; symbol: string; level: string; bindings: string[] }>;
      };
    };
    assert.equal(st.result.enabled, true);
    assert.equal(st.result.secrets.length, 1);
    const e = st.result.secrets[0]!;
    assert.equal(e.path, secret);
    assert.ok(e.symbol.startsWith("$MDU:nomodel_"));
    assert.equal(e.level, "no-model");
    assert.deepEqual(e.bindings, []);
    // §6: the panel shows WHAT is confined and WHERE it may go — never what is
    // inside. No field of the response may carry the secret's contents.
    assert.ok(!JSON.stringify(st.result).includes("AKIA-REAL-SECRET"));
  } finally {
    void s.close();
    cleanup();
  }
});

test("confidentialityState OFF: disabled, empty surface", () => {
  const { dir, dbPath, cleanup } = fixture();
  const s = server(dir, dbPath, false);
  try {
    const st = s.dispatch({ id: 1, op: "confidentialityState" }) as {
      result: { enabled: boolean; secrets: unknown[] };
    };
    assert.equal(st.result.enabled, false);
    assert.deepEqual(st.result.secrets, []);
  } finally {
    void s.close();
    cleanup();
  }
});

// ── plan 10 §2.4: the structured twin ───────────────────────────────────────
import { findSymbolByName, resolveSymbol } from "../../symbol-table/symbol-table.js";
import { registerEnvSecret, structuredTwinFor } from "../../secret-registry/registry.js";

const DOTENV = "# app\nPORT=3000\nSTRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\nDATABASE_URL=postgres://app:pw-9f8e7d@db:5432/prod\n";

function dotenvFixture(): { dir: string; dbPath: string; env: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-reg-"));
  const env = join(dir, ".env");
  writeFileSync(env, DOTENV);
  return { dir, dbPath: join(dir, "symbols.db"), env, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("structured twin: one field symbol per secret value, sharing the base hash; the twin has no secret byte", () => {
  const { dbPath, env, cleanup } = dotenvFixture();
  try {
    const map = loadSymbolMap(dbPath);
    const r = registerSecret(map, { path: env }, dbPath);
    assert.ok(r.symbol);
    assert.equal(r.shape, "dotenv");
    assert.equal(r.fields, 2);
    const hash = r.symbol!.match(/\[([0-9a-f]+)\]/)![1];
    assert.equal(
      r.twin,
      `# app\nPORT=3000\nSTRIPE_KEY='$MDU:nomodel_Read[${hash}].STRIPE_KEY'\nDATABASE_URL='postgres://app:$MDU:nomodel_Read[${hash}].DATABASE_URL.password@db:5432/prod'\n`,
    );
    assert.ok(!r.twin!.includes("sk_live") && !r.twin!.includes("pw-9f8e7d"));
    // each field row stands for exactly its value, at the file's label
    const f = getSymbolEntry(map, `$MDU:nomodel_Read[${hash}].STRIPE_KEY`);
    assert.equal(f?.value, "sk_live_4eC39HqLyjWDarjtT1zdp7dc");
    assert.equal(f?.confidentiality, "no-model");
    assert.equal(f?.integrity, "trusted");
    assert.equal(f?.origin, env);
    assert.equal(resolveSymbol(map, `$MDU:nomodel_Read[${hash}].DATABASE_URL.password`), "pw-9f8e7d");
    // the base row still holds the whole file (fingerprints, listing)
    assert.equal(getSymbolEntry(map, r.symbol!)?.value, DOTENV);
    assert.deepEqual(listSecretRegistry(map).map((e) => [e.path, e.fields]), [[env, 2]]);
    // re-rendered from the table, byte for byte
    assert.equal(structuredTwinFor(map, env), r.twin);
    assert.equal(structuredTwinFor(map, "/nowhere/.env"), null);
  } finally {
    cleanup();
  }
});

test("structured twin: idempotent across launches (same field names), and a hallucinated field never resolves to the whole file", () => {
  const { dbPath, env, cleanup } = dotenvFixture();
  try {
    const a = registerSecret(loadSymbolMap(dbPath), { path: env }, dbPath);
    const map = loadSymbolMap(dbPath);
    const b = registerSecret(map, { path: env }, dbPath);
    assert.equal(b.symbol, a.symbol);
    assert.equal(b.twin, a.twin);
    assert.match(b.reason, /already registered/);
    const base = a.symbol!;
    // exact field: hits; invented field: nothing (not the base row's file bytes)
    assert.ok(findSymbolByName(map, `${base}.STRIPE_KEY`));
    assert.equal(findSymbolByName(map, `${base}.bogus`), null);
    assert.equal(resolveSymbol(map, `${base}.PORT`), null);
    // trailing punctuation still trims to the base, as before
    assert.equal(findSymbolByName(map, `${base}.`)?.name, base);
  } finally {
    cleanup();
  }
});

test("a file of no known shape stays a whole-file twin (no fields, no twin text)", () => {
  const { dbPath, secret, cleanup } = fixture(); // ~/.aws/credentials has a shape; use an ssh key
  try {
    const dir = join(secret, "..", "..");
    mkdirSync(join(dir, ".ssh"), { recursive: true });
    const key = join(dir, ".ssh", "id_ed25519");
    writeFileSync(key, "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n");
    const map = loadSymbolMap(dbPath);
    const r = registerSecret(map, { path: key, home: dir }, dbPath);
    assert.ok(r.symbol);
    assert.equal(r.twin, undefined);
    assert.equal(r.fields, undefined);
    assert.equal(structuredTwinFor(map, key), null);
  } finally {
    cleanup();
  }
});

test("registerEnvSecret: shape-matched names mask the whole value, URL passwords mask the password, the agent's own key is exempt", () => {
  const { dbPath, cleanup } = dotenvFixture();
  try {
    const map = loadSymbolMap(dbPath);
    const t = registerEnvSecret(map, { name: "GH_TOKEN", value: "ghp_abcdef123456" }, dbPath);
    assert.ok(t.symbol!.startsWith("$MDU:nomodel_Env["), t.symbol!);
    assert.ok(t.symbol!.endsWith(".GH_TOKEN"));
    assert.equal(t.twin, t.symbol);
    assert.equal(getSymbolEntry(map, t.symbol!)?.value, "ghp_abcdef123456");
    assert.equal(getSymbolEntry(map, t.symbol!)?.origin, "env:GH_TOKEN");
    const u = registerEnvSecret(map, { name: "DATABASE_URL", value: "postgres://app:pw-1234567@db/prod" }, dbPath);
    assert.ok(u.symbol!.endsWith(".DATABASE_URL.password"));
    assert.equal(u.twin, `postgres://app:${u.symbol}@db/prod`);
    for (const [name, value] of [["ANTHROPIC_API_KEY", "sk-ant-xyz"], ["PATH", "/usr/bin"], ["MANDU_MODE", "secrets"], ["HOME", "/home/u"]]) {
      assert.equal(registerEnvSecret(map, { name: name!, value: value! }, dbPath).symbol, null, name);
    }
    // idempotent
    assert.equal(registerEnvSecret(map, { name: "GH_TOKEN", value: "ghp_abcdef123456" }, dbPath).symbol, t.symbol);
  } finally {
    cleanup();
  }
});

test("registerEnvSecrets op: masks over the wire, refused with the axis OFF", () => {
  const { dir, dbPath, cleanup } = dotenvFixture();
  const on = server(dir, dbPath, true);
  const off = server(dir, join(dir, "off.db"), false);
  try {
    const r = on.dispatch({ id: 1, op: "registerEnvSecrets", vars: [{ name: "NPM_TOKEN", value: "npm_123456789" }, { name: "SHELL", value: "/bin/bash" }] }) as {
      ok: boolean; result: { vars: Array<{ name: string; symbol: string | null; twin?: string }> };
    };
    assert.equal(r.ok, true);
    assert.ok(r.result.vars[0]!.symbol?.endsWith(".NPM_TOKEN"));
    assert.equal(r.result.vars[1]!.symbol, null);
    const o = off.dispatch({ id: 2, op: "registerEnvSecrets", vars: [{ name: "NPM_TOKEN", value: "npm_123456789" }] }) as {
      result: { vars: Array<{ symbol: string | null; reason: string }> };
    };
    assert.equal(o.result.vars[0]!.symbol, null);
    assert.match(o.result.vars[0]!.reason, /OFF/);
  } finally {
    void on.close(); void off.close();
    cleanup();
  }
});

test("a label's extract regex overrides the shape: group 1 becomes the field, the rest of the file stays raw", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-reg-"));
  try {
    const conf = join(dir, "custom.conf");
    writeFileSync(conf, "name: svc\noauth: tok_ABCDEF123\nregion: eu\n");
    const dbPath = join(dir, "symbols.db");
    const map = loadSymbolMap(dbPath);
    const resolveLabel = (p: string) => (p === conf ? { level: "no-model" as const, bindings: [], via: conf, extract: "oauth: (\\S+)" } : null);
    const r = registerSecret(map, { path: conf, resolveLabel }, dbPath);
    assert.ok(r.symbol, r.reason);
    assert.equal(r.shape, "extract");
    assert.equal(r.fields, 1);
    assert.match(r.twin!, /^name: svc\noauth: \$MDU:nomodel_Read\[[0-9a-f]+\]\.extract_1\nregion: eu\n$/);
    assert.equal(structuredTwinFor(map, conf, { resolveLabel }), r.twin);
    assert.equal(structuredTwinFor(map, conf), null, "without the label the file has no shape: whole-file");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});


test("plan 10 §12.5: registration reports the label's reader list shape (named, pinned); none without a list", () => {
  const { dbPath, env, cleanup } = dotenvFixture();
  try {
    const map = loadSymbolMap(dbPath);
    const withList = (p: string) => (p === env
      ? { level: "no-model" as const, bindings: [], via: env, readers: ["psql", { app: "cat", path: "/usr/bin/cat", sha256: "a".repeat(64) }, { app: "pg_dump" }] }
      : null);
    const r = registerSecret(map, { path: env, resolveLabel: withList }, dbPath);
    assert.ok(r.symbol);
    assert.deepEqual(r.readers, { named: 3, pinned: 1 });
    const bare = registerSecret(map, { path: env }, dbPath);
    assert.equal(bare.readers, undefined);
  } finally {
    cleanup();
  }
});

test("registerEnvSecret honors the law's env rules: an added name is minted, an exempted shape hit is not (plan 10 §11.4)", () => {
  const { dbPath, cleanup } = dotenvFixture();
  try {
    const map = loadSymbolMap(dbPath);
    const rules = { secrets: ["MYCO_*"], exempt: ["GH_TOKEN"] };
    const added = registerEnvSecret(map, { name: "MYCO_THING", value: "plain-looking-value", rules }, dbPath);
    assert.ok(added.symbol?.endsWith(".MYCO_THING"), added.reason);
    assert.equal(getSymbolEntry(map, added.symbol!)?.value, "plain-looking-value");
    assert.equal(registerEnvSecret(map, { name: "GH_TOKEN", value: "ghp_abcdef123456", rules }, dbPath).symbol, null);
    assert.ok(registerEnvSecret(map, { name: "GH_TOKEN", value: "ghp_abcdef123456" }, dbPath).symbol, "no rules: the built-in shape holds");
  } finally {
    cleanup();
  }
});

test("discoverSecrets / registerSecret honor the LAUNCH's `home`: a `~/.ssh/` prefix match under a session home the arbiter does not live in", () => {
  const { dir, dbPath, cleanup } = fixture();
  const home = mkdtempSync(join(tmpdir(), "mandu-session-home-"));
  const s = server(dir, dbPath, true);
  try {
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_custom"), "-----BEGIN OPENSSH PRIVATE KEY-----\nSESSIONHOMEKEY\n"); // no basename shape: the ~/.ssh/ prefix alone
    const without = s.dispatch({ id: 1, op: "discoverSecrets", roots: [home] }) as { result: { files: Array<{ path: string }> } };
    assert.ok(!without.result.files.some((f) => f.path.endsWith("id_custom")), "against the arbiter's own HOME the prefix rule cannot match");
    const withHome = s.dispatch({ id: 2, op: "discoverSecrets", roots: [home], home }) as { result: { files: Array<{ path: string }> } };
    assert.ok(withHome.result.files.some((f) => f.path.endsWith("id_custom")), "with the session's home it is found");
    const reg = s.dispatch({ id: 3, op: "registerSecret", path: join(home, ".ssh", "id_custom"), home }) as { result: { symbol: string | null; reason: string } };
    assert.ok(reg.result.symbol, reg.result.reason);
  } finally {
    void s.close();
    rmSync(home, { recursive: true, force: true });
    cleanup();
  }
});

test("registerEnvSecret: a sourced variable's bindings ride on its symbol (the egress gate releases it there)", () => {
  const { dbPath, cleanup } = dotenvFixture();
  try {
    const map = loadSymbolMap(dbPath);
    const r = registerEnvSecret(map, { name: "PLAIN_NAME", value: "tok-src-1", rules: { secrets: ["PLAIN_NAME"] }, bindings: ["api.github.com"] }, dbPath);
    assert.ok(r.symbol);
    assert.deepEqual(getSymbolEntry(map, r.symbol!)?.bindings, ["api.github.com"]);
    const plain = registerEnvSecret(map, { name: "GH_TOKEN", value: "ghp_nobind_1" }, dbPath);
    assert.ok(!(getSymbolEntry(map, plain.symbol!)?.bindings ?? []).length, "no bindings unless the law gives them");
  } finally {
    cleanup();
  }
});

test("registerEnvSecrets op: a declared model's token_env is a secret whatever its name, bound to that model's host (plan 11 D2)", () => {
  const { dir, dbPath, cleanup } = dotenvFixture();
  const s = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"), dbPath, eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPollMs: 0,
    policyDocument: {
      version: 1,
      models: [
        { name: "own", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true, token_env: "OLLAMA_BEARER" },
        { name: "lan", url: "https://gpu.lan:8443", wire: "openai-chat", model: "qwen", local: true, token_env: "OLLAMA_BEARER" },
        { name: "v6", url: "http://[::1]:11434", wire: "openai-chat", model: "m", local: true, token_env: "V6_BEARER" },
      ],
    },
  });
  try {
    const r = s.dispatch({ id: 1, op: "registerEnvSecrets", vars: [
      { name: "OLLAMA_BEARER", value: "tok-real-123456" },
      { name: "V6_BEARER", value: "tok-v6-123456" },
      { name: "OTHER_BEARER", value: "not-declared-123" },
    ] }) as { ok: boolean; result: { vars: Array<{ name: string; symbol: string | null; twin?: string }> } };
    assert.equal(r.ok, true);
    const [own, v6, other] = r.result.vars;
    assert.ok(own!.symbol?.startsWith("$MDU:nomodel_Env["), "the name matches no built-in shape, and is masked anyway");
    assert.equal(own!.twin, own!.symbol, "the agent's environment carries the symbol");
    assert.equal(other!.symbol, null, "an undeclared name of the same shape is not a secret");
    const map = loadSymbolMap(dbPath);
    assert.deepEqual([...(getSymbolEntry(map, own!.symbol!)?.bindings ?? [])].sort(), ["127.0.0.1", "gpu.lan"], "bound to every host that names it");
    assert.ok(v6!.symbol, "an IPv6 endpoint's token is masked too");
    assert.equal((getSymbolEntry(map, v6!.symbol!)?.bindings ?? []).length, 0, "with no binding (a binding is a host name), so any send of it asks");
  } finally {
    void s.close();
    cleanup();
  }
});

// ── plan 10 §11.13: twins the programs that read them still parse ──────────

function homeFixture(files: Record<string, string>): { home: string; dbPath: string; cleanup: () => void } {
  const home = mkdtempSync(join(tmpdir(), "mandu-reg-home-"));
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(join(home, rel, ".."), { recursive: true });
    writeFileSync(join(home, rel), content);
  }
  return { home, dbPath: join(home, "symbols.db"), cleanup: () => rmSync(home, { recursive: true, force: true }) };
}

test("per-file twin decisions: ssh config and a plain pip.conf are their own text; a credentialed pip.conf and .git-credentials mask only the secret; a key stays whole-file; no twin holds a secret", () => {
  const SSH_CONFIG = "Host bastion\n  HostName 10.9.8.7\n  User deploy\n  IdentityFile ~/.ssh/id_ed25519\n";
  const PIP_PLAIN = "[global]\nindex-url = https://pypi.org/simple\n";
  const PIP_CRED = "[global]\nindex-url = https://__token__:REGPIPPW_1@pypi.corp.example/simple\n";
  const GITCRED = "https://alice:REGGITPW_2@github.com\n";
  const KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nREGKEY_3\n-----END OPENSSH PRIVATE KEY-----";
  const { home, dbPath, cleanup } = homeFixture({
    ".ssh/config": SSH_CONFIG, ".config/pip/pip.conf": PIP_PLAIN, ".pip/pip.conf": PIP_CRED,
    ".git-credentials": GITCRED, ".ssh/id_ed25519": KEY, ".ssh/known_hosts": "github.com ssh-ed25519 AAAAC3Nza\n",
  });
  try {
    const map = loadSymbolMap(dbPath);
    const reg = (rel: string) => registerSecret(map, { path: join(home, rel), home }, dbPath);

    const ssh = reg(".ssh/config");
    assert.ok(ssh.symbol, ssh.reason);
    assert.equal(ssh.shape, "ssh-config");
    assert.equal(ssh.fields, 0);
    assert.equal(ssh.twin, SSH_CONFIG, "ssh reads its own config");
    assert.match(ssh.reason, /holds no secret value/);

    const plain = reg(".config/pip/pip.conf");
    assert.equal(plain.twin, PIP_PLAIN);

    const cred = reg(".pip/pip.conf");
    assert.equal(cred.shape, "pip-conf");
    assert.equal(cred.fields, 1);
    // The URL password's token is percent-encoded (pip decodes it; a raw
    // token's brackets break Python's URL parser, plan 10 §11.13.1).
    assert.match(cred.twin!, /^\[global\]\nindex-url = https:\/\/__token__:%24MDU%3Anomodel_Read%5B[0-9a-f]+%5D\.global\.pypi\.corp\.example\.password@pypi\.corp\.example\/simple\n$/);

    const git = reg(".git-credentials");
    assert.equal(git.shape, "git-credentials");
    assert.match(git.twin!, /^https:\/\/alice:\$MDU:nomodel_Read\[[0-9a-f]+\]\.git\.github\.com\.password@github\.com\n$/);

    const key = reg(".ssh/id_ed25519");
    assert.equal(key.twin, undefined, "a private key is a whole-file twin");
    assert.equal(key.terminator, "", "it ends without a newline, and so will its twin");

    const known = reg(".ssh/known_hosts");
    assert.equal(known.symbol, null, "known_hosts is public material: not registered, never twinned");

    // The leak oracle at the registry: no twin, structured or whole, holds a secret byte.
    for (const r of [ssh, plain, cred, git, key]) {
      const text = r.twin ?? r.symbol!;
      for (const secret of ["REGPIPPW_1", "REGGITPW_2", "REGKEY_3"]) assert.ok(!text.includes(secret), `${secret} in ${text}`);
    }
  } finally {
    cleanup();
  }
});

test("an exhaustive shape is its own text only on the catalog's word: a human label on the same file keeps the whole-file twin", () => {
  const SSH_CONFIG = "Host internal\n  HostName 10.1.1.1\n";
  const { home, dbPath, cleanup } = homeFixture({ ".ssh/config": SSH_CONFIG });
  try {
    const map = loadSymbolMap(dbPath);
    const path = join(home, ".ssh", "config");
    const resolveLabel = (p: string) => (p === path ? { level: "no-model" as const, bindings: [], via: path } : null);
    const r = registerSecret(map, { path, home, resolveLabel }, dbPath);
    assert.ok(r.symbol, r.reason);
    assert.equal(r.twin, undefined, "the human said the file is the secret");
    assert.equal(r.terminator, "\n");
  } finally {
    cleanup();
  }
});

test("the whole-file twin's terminator mirrors the original's last line ending: none, \\n or \\r\\n", () => {
  const { home, dbPath, cleanup } = homeFixture({ "a/id_rsa": "KEY-A", "b/id_rsa": "KEY-B\n", "c/id_rsa": "KEY-C\r\n" });
  try {
    const map = loadSymbolMap(dbPath);
    const t = (rel: string) => registerSecret(map, { path: join(home, rel), home }, dbPath).terminator;
    assert.equal(t("a/id_rsa"), "");
    assert.equal(t("b/id_rsa"), "\n");
    assert.equal(t("c/id_rsa"), "\r\n");
  } finally {
    cleanup();
  }
});

// ── plan 10 §11.13.1: npm reads the .npmrc twin; the wire carries its token ──

const NPMRC = "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_REGWIRE_1\n//npm.pkg.github.com/acme/:_authToken=ghp_REGWIRE_2\n";

test("the HOME .npmrc: each token's field symbol is bound to the registry its own key names, read from the real file", () => {
  const { home, dbPath, cleanup } = homeFixture({ ".npmrc": NPMRC });
  try {
    const map = loadSymbolMap(dbPath);
    const r = registerSecret(map, { path: join(home, ".npmrc"), home }, dbPath);
    assert.equal(r.fields, 2, r.reason);
    const fields = [...map.symbols.values()].filter((e) => e.origin === join(home, ".npmrc") && e.field !== null);
    assert.deepEqual(fields.map((e) => [e.value, e.bindings]).sort(), [
      ["ghp_REGWIRE_2", ["npm.pkg.github.com"]],
      ["npm_REGWIRE_1", ["registry.npmjs.org"]],
    ]);
    const base = [...map.symbols.values()].find((e) => e.origin === join(home, ".npmrc") && e.field === null)!;
    assert.ok(!(base.bindings ?? []).length, "the whole file is bound nowhere");
    const w = wireServableTwin(map, join(home, ".npmrc"));
    assert.equal(w.servable, true, w.why);
    assert.deepEqual(w.hosts, ["registry.npmjs.org", "npm.pkg.github.com"]);
    // The standing releases are visible on the file's registry entry (§6).
    const entry = listSecretRegistry(map).find((x) => x.path === join(home, ".npmrc"))!;
    assert.deepEqual([...entry.bindings].sort(), ["npm.pkg.github.com", "registry.npmjs.org"]);
  } finally {
    cleanup();
  }
});

test("a .npmrc that is not the launch HOME's own (a workspace one, a labelled copy) derives no binding and is not servable", () => {
  const { home, dbPath, cleanup } = homeFixture({ "ws/.npmrc": NPMRC, ".npmrc": NPMRC });
  try {
    const map = loadSymbolMap(dbPath);
    const ws = join(home, "ws", ".npmrc");
    const resolveLabel = (p: string) => (p === ws ? { level: "no-model" as const, bindings: [], via: ws } : null);
    const r = registerSecret(map, { path: ws, home, resolveLabel }, dbPath);
    assert.ok(r.symbol, r.reason);
    for (const e of map.symbols.values()) if (e.origin === ws) assert.ok(!(e.bindings ?? []).length, `${e.field}: no binding`);
    assert.equal(wireServableTwin(map, ws).servable, false);
    // No home given: no derivation either (the arbiter never guesses the launch's HOME).
    const map2 = loadSymbolMap(join(home, "other.db"));
    registerSecret(map2, { path: join(home, ".npmrc"), resolveLabel: () => ({ level: "no-model" as const, bindings: [], via: "x" }) }, join(home, "other.db"));
    assert.equal(wireServableTwin(map2, join(home, ".npmrc")).servable, false);
  } finally {
    cleanup();
  }
});

test("not servable: a _password npm cannot decode, an unscoped token, a key that routes npm around the proxy; servable files lose nothing", () => {
  const { home, dbPath, cleanup } = homeFixture({ ".npmrc": "x" });
  try {
    const p = join(home, ".npmrc");
    const cases: Array<[string, RegExp]> = [
      // A scoped base64 `_password` is servable since 2026-10-03 (§11.13.1);
      // one that is not clean base64 of text is not.
      ["//corp.example/npm/:username=me\n//corp.example/npm/:_password=not-base64!\n", /_password is not a value npm sends/],
      ["_password=cGFzcw==\n", /_password is not a value npm sends/],
      ["_authToken=npm_UNSCOPED_3\n", /_authToken is not a value npm sends/],
      ["//registry.npmjs.org/:_authToken=npm_BYPASS_4\ncafile=/etc/corp.pem\n", /cafile would send npm around the session proxy/],
      ["//registry.npmjs.org/:_authToken=npm_BYPASS_5\nhttps-proxy=http://corp:3128\n", /https-proxy/],
      ["registry=https://registry.npmjs.org/\n", /no token in the file/],
    ];
    for (const [i, [content, why]] of cases.entries()) {
      writeFileSync(p, content);
      const db = join(home, `case-${i}.db`);
      const map = loadSymbolMap(db);
      registerSecret(map, { path: p, home }, db);
      const w = wireServableTwin(map, p);
      assert.equal(w.servable, false, content);
      assert.match(w.why, why);
    }
    assert.equal(wireServableTwin(loadSymbolMap(join(home, "none.db")), p).why, "not registered");
    assert.equal(wireServableTwin(loadSymbolMap(join(home, "none.db")), join(home, ".pgpass")).servable, false);
  } finally {
    cleanup();
  }
});

test("noProxyMatches: NO_PROXY's exact and suffix forms, ports ignored; a registry reached directly is not servable", () => {
  assert.equal(noProxyMatches("registry.npmjs.org", ["127.0.0.1", "localhost"]), false);
  assert.equal(noProxyMatches("localhost:4873", ["127.0.0.1", "localhost"]), true);
  assert.equal(noProxyMatches("npm.corp.example", [".corp.example"]), true);
  assert.equal(noProxyMatches("npm.corp.example", ["corp.example"]), true);
  assert.equal(noProxyMatches("notcorp.example", ["corp.example"]), false);
  assert.equal(noProxyMatches("anything", ["*"]), true);
  const { home, dbPath, cleanup } = homeFixture({ ".npmrc": NPMRC });
  try {
    const map = loadSymbolMap(dbPath);
    registerSecret(map, { path: join(home, ".npmrc"), home }, dbPath);
    assert.equal(wireServableTwin(map, join(home, ".npmrc"), { direct: ["localhost"] }).servable, true);
    const w = wireServableTwin(map, join(home, ".npmrc"), { direct: ["github.com"] });
    assert.equal(w.servable, false);
    assert.match(w.why, /npm reaches npm\.pkg\.github\.com directly \(NO_PROXY\)/);
  } finally {
    cleanup();
  }
});

test("a field row minted before this change (no binding) is given its registry on the next registration, and stays the same symbol", () => {
  const { home, dbPath, cleanup } = homeFixture({ ".npmrc": NPMRC });
  try {
    const p = join(home, ".npmrc");
    const map = loadSymbolMap(dbPath);
    const resolveLabel = (q: string) => (q === p ? { level: "no-model" as const, bindings: [], via: p } : null);
    registerSecret(map, { path: p, resolveLabel }, dbPath); // no home: the older registration, unbound
    const before = [...map.symbols.entries()].filter(([, e]) => e.origin === p && e.field !== null);
    assert.equal(before.length, 2);
    assert.ok(before.every(([, e]) => !(e.bindings ?? []).length));
    assert.equal(wireServableTwin(map, p).servable, false);
    registerSecret(map, { path: p, home, resolveLabel }, dbPath);
    const after = [...map.symbols.entries()].filter(([, e]) => e.origin === p && e.field !== null);
    assert.deepEqual(after.map(([n]) => n).sort(), before.map(([n]) => n).sort(), "the same names");
    assert.equal(wireServableTwin(map, p).servable, true);
    // ...and persisted: a reload sees the binding.
    assert.equal(wireServableTwin(loadSymbolMap(dbPath), p).servable, true);
  } finally {
    cleanup();
  }
});

// ── plan 10 §11.13.1 (2026-10-03): the wire twin for passwords ─────────────

const PW = "npmPasswordWIRE_7q";
const NPMRC_PW = `//npm.corp.example/repo/:username=builder\n//npm.corp.example/repo/:_password=${Buffer.from(PW).toString("base64")}\n`;

test("the HOME .npmrc's _password: its field stands for the DECODED password, bound to its registry; the twin holds the base64 of the token; the file's base64 text keeps an unbound row; servable", () => {
  const { home, dbPath, cleanup } = homeFixture({ ".npmrc": NPMRC_PW });
  try {
    const p = join(home, ".npmrc");
    const map = loadSymbolMap(dbPath);
    const r = registerSecret(map, { path: p, home }, dbPath);
    assert.equal(r.fields, 1, r.reason);
    const rows = [...map.symbols.entries()].filter(([, e]) => e.origin === p && e.field !== null);
    assert.deepEqual(rows.map(([, e]) => [e.field, e.value, e.bindings ?? []]).sort(), [
      ["npm.corp.example/repo._password", PW, ["npm.corp.example"]],
      ["npm.corp.example/repo._password.encoded", Buffer.from(PW).toString("base64"), []],
    ]);
    const field = rows.find(([, e]) => e.value === PW)![0];
    assert.equal(r.twin, `//npm.corp.example/repo/:username=builder\n//npm.corp.example/repo/:_password=${Buffer.from(field).toString("base64")}\n`);
    for (const secret of [PW, Buffer.from(PW).toString("base64")]) assert.ok(!r.twin!.includes(secret));
    const w = wireServableTwin(map, p);
    assert.equal(w.servable, true, w.why);
    assert.deepEqual(w.hosts, ["npm.corp.example"]);
    // Re-registering the unchanged file reuses every row.
    const again = registerSecret(map, { path: p, home }, dbPath);
    assert.equal(again.twin, r.twin);
  } finally {
    cleanup();
  }
});

const PIP_PW = "pipPasswordWIRE_3x";
const PIP_CONF = `[global]\nindex-url = https://builder:${PIP_PW}@pypi.corp.example/simple\nextra-index-url = https://ci:p%40ss@pkgs.example:8443/simple\n[install]\nproxy = http://proxyuser:PROXYPW_1@proxy.example:3128\n`;

test("the HOME pip.conf (either path): an index URL's password is bound to its index host; the twin holds the percent-encoded token; a proxy password is not bound", () => {
  for (const rel of [".config/pip/pip.conf", ".pip/pip.conf"]) {
    const { home, dbPath, cleanup } = homeFixture({ [rel]: PIP_CONF });
    try {
      const p = join(home, rel);
      const map = loadSymbolMap(dbPath);
      const r = registerSecret(map, { path: p, home }, dbPath);
      assert.equal(r.shape, "pip-conf", r.reason);
      const rows = [...map.symbols.entries()].filter(([, e]) => e.origin === p && e.field !== null);
      assert.deepEqual(rows.map(([, e]) => [e.field, e.value, e.bindings ?? []]).sort(), [
        ["global.pkgs.example.password", "p@ss", ["pkgs.example:8443"]],
        ["global.pkgs.example.password.encoded", "p%40ss", []],
        ["global.pypi.corp.example.password", PIP_PW, ["pypi.corp.example"]],
        ["install.proxy.example.password", "PROXYPW_1", []],
      ], rel);
      const name = rows.find(([, e]) => e.value === PIP_PW)![0];
      assert.ok(r.twin!.includes(`index-url = https://builder:${encodeURIComponent(name)}@pypi.corp.example/simple\n`), r.twin);
      for (const secret of [PIP_PW, "p%40ss", "PROXYPW_1"]) assert.ok(!r.twin!.includes(secret), `${secret} in ${r.twin}`);
      // The twin decodes, as pip decodes it, back into the token.
      assert.ok(decodeURIComponent(r.twin!).includes(`https://builder:${name}@`));
    } finally {
      cleanup();
    }
  }
});

test("a pip.conf that is not the launch HOME's own (a workspace one, no home given) derives no binding", () => {
  const { home, dbPath, cleanup } = homeFixture({ "ws/.config/pip/pip.conf": PIP_CONF, ".config/pip/pip.conf": PIP_CONF });
  try {
    const map = loadSymbolMap(dbPath);
    const ws = join(home, "ws", ".config", "pip", "pip.conf");
    const resolveLabel = (q: string) => (q.endsWith("pip.conf") ? { level: "no-model" as const, bindings: [], via: q } : null);
    registerSecret(map, { path: ws, home, resolveLabel }, dbPath);
    registerSecret(map, { path: join(home, ".config", "pip", "pip.conf"), resolveLabel }, dbPath); // no home
    for (const e of map.symbols.values()) assert.ok(!(e.bindings ?? []).length, `${e.origin} ${e.field}: no binding`);
  } finally {
    cleanup();
  }
});

test("registerEnvSecret: PIP_INDEX_URL's password is bound to its index host and twinned percent-encoded; a row minted unbound gains the host; DATABASE_URL is not bound", () => {
  const { dbPath, cleanup } = dotenvFixture();
  try {
    const map = loadSymbolMap(dbPath);
    const value = `https://builder:${PIP_PW}@pypi.corp.example/simple`;
    const r = registerEnvSecret(map, { name: "PIP_INDEX_URL", value }, dbPath);
    assert.ok(r.symbol, r.reason);
    assert.deepEqual(getSymbolEntry(map, r.symbol!)?.bindings, ["pypi.corp.example"]);
    assert.equal(getSymbolEntry(map, r.symbol!)?.value, PIP_PW);
    assert.equal(r.twin, `https://builder:${encodeURIComponent(r.symbol!)}@pypi.corp.example/simple`);
    // With the law's own bindings too, both ride.
    const both = registerEnvSecret(map, { name: "PIP_EXTRA_INDEX_URL", value: "https://u:EXTRAPW_2@x.example/simple", bindings: ["mirror.example"] }, dbPath);
    assert.deepEqual(getSymbolEntry(map, both.symbol!)?.bindings, ["mirror.example", "x.example"]);
    // A row of the same value minted unbound (an older arbiter) gains the host.
    getSymbolEntry(map, r.symbol!)!.bindings = null;
    const again = registerEnvSecret(map, { name: "PIP_INDEX_URL", value }, dbPath);
    assert.equal(again.symbol, r.symbol);
    assert.deepEqual(getSymbolEntry(map, r.symbol!)?.bindings, ["pypi.corp.example"]);
    const db = registerEnvSecret(map, { name: "DATABASE_URL", value: "postgres://u:DBPW_3@db.example/app" }, dbPath);
    assert.ok(!(getSymbolEntry(map, db.symbol!)?.bindings ?? []).length);
    assert.equal(db.twin, `postgres://u:${db.symbol}@db.example/app`, "other URL variables keep the raw token");
  } finally {
    cleanup();
  }
});

// ── plan 10 §11.13.1 (2026-10-03, maintainer decision): https only ──────────

test("wireReleaseScheme: a wire credential declared for https answers `https`, one declared http `any`; a non-wire field and other rows answer null; a field the file no longer has fails closed to `https`", () => {
  const { home, dbPath, cleanup } = homeFixture({
    ".npmrc": "//r.example/:_authToken=npm_SCHEME_1\n//h.example/:_authToken=npm_SCHEME_2\nregistry=http://h.example/\n",
    ".config/pip/pip.conf": "[global]\nindex-url = https://u:PIPS_1@pypi.example/simple\nextra-index-url = http://u:PIPS_2@plain.example/simple\n[install]\nproxy = http://p:PROXYS_3@proxy.example:3128\n",
  });
  try {
    const map = loadSymbolMap(dbPath);
    registerSecret(map, { path: join(home, ".npmrc"), home }, dbPath);
    registerSecret(map, { path: join(home, ".config/pip/pip.conf"), home }, dbPath);
    const byValue = (v: string) => [...map.symbols.entries()].find(([, e]) => e.value === v)![0];
    assert.equal(wireReleaseScheme(map, byValue("npm_SCHEME_1")), "https");
    assert.equal(wireReleaseScheme(map, byValue("npm_SCHEME_2")), "any", "the file declares h.example's registry as http");
    assert.equal(wireReleaseScheme(map, byValue("PIPS_1")), "https");
    assert.equal(wireReleaseScheme(map, byValue("PIPS_2")), "any");
    assert.equal(wireReleaseScheme(map, byValue("PROXYS_3")), null, "a proxy password is no wire credential");
    // A field row the current file text no longer has: fail closed.
    const row = map.symbols.get(byValue("npm_SCHEME_1"))!;
    map.symbols.set("$MDU:nomodel_Read[ffff].gone._authToken", { ...row, field: "gone._authToken" });
    assert.equal(wireReleaseScheme(map, "$MDU:nomodel_Read[ffff].gone._authToken"), "https");
    assert.equal(wireReleaseScheme(map, "$MDU:nomodel_Read[0000].nope"), null, "unknown symbol");
  } finally {
    cleanup();
  }
  const { dbPath: db2, cleanup: c2 } = dotenvFixture();
  try {
    const map = loadSymbolMap(db2);
    const s = registerEnvSecret(map, { name: "PIP_INDEX_URL", value: "https://u:ENVS_1@pypi.example/simple" }, db2).symbol!;
    const h = registerEnvSecret(map, { name: "PIP_EXTRA_INDEX_URL", value: "http://u:ENVS_2@plain.example/simple" }, db2).symbol!;
    const d = registerEnvSecret(map, { name: "DATABASE_URL", value: "postgres://u:ENVS_3@db.example/app" }, db2).symbol!;
    assert.equal(wireReleaseScheme(map, s), "https");
    assert.equal(wireReleaseScheme(map, h), "any");
    assert.equal(wireReleaseScheme(map, d), null);
  } finally {
    c2();
  }
});

test("wireSchemeRefusal: an https-declared credential is refused (no approval) unless the request is stated HTTPS; nothing else is touched", () => {
  const net = (scheme?: "http" | "https") => ({ boundary: "network" as const, destination: "pypi.example", ...(scheme ? { scheme } : {}) });
  for (const req of [net("http"), net()]) {
    const r = wireSchemeRefusal(req, "https")!;
    assert.equal(r.allow, false);
    assert.equal(r.allow === false && r.requiresApproval, false, "a hard refusal: nothing to approve");
    assert.equal(r.ruleRef?.id, "egress:secret-https-only");
    assert.match(r.reason, /declared for https/);
  }
  assert.match(wireSchemeRefusal(net("http"), "https")!.reason, /plain-HTTP request to 'pypi\.example'/);
  assert.equal(wireSchemeRefusal(net("https"), "https"), null);
  assert.equal(wireSchemeRefusal(net("http"), "any"), null, "declared http: plain HTTP is its own scheme");
  assert.equal(wireSchemeRefusal(net("http"), null), null, "not a wire credential");
  assert.equal(wireSchemeRefusal({ boundary: "filesystem" }, "https"), null);
  // A network ask that says the value would run as a command is judged all
  // the same (2026-10-10: it was exempt, and went on to a standing verdict).
  const asCommand: DesymbolizationRequest = { symbol: "$MDU:nomodel_Read[ab12].t", boundary: "network", destination: "pypi.example", asCommand: true };
  for (const scheme of [undefined, "http"] as const) {
    const r = wireSchemeRefusal({ ...asCommand, ...(scheme ? { scheme } : {}) }, "https");
    assert.equal(r?.ruleRef?.id, "egress:secret-https-only", `asCommand, scheme ${scheme}`);
    assert.equal(r?.allow === false && r.requiresApproval, false, "a hard refusal");
  }
  assert.equal(wireSchemeRefusal({ ...asCommand, scheme: "https" }, "https"), null, "asCommand over https: other rules decide");
  assert.equal(wireSchemeRefusal({ ...asCommand, scheme: "http" }, "any"), null, "asCommand, declared http: other rules decide");
});

test("the server's https-only rule judges the row a mutated placeholder resolves to (2026-10-09): `<field>.x` of an https-declared token is refused in plain HTTP and released over https, as the field itself is", () => {
  const { home, dbPath, cleanup } = homeFixture({ ".npmrc": "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_SCHEME_MUTATED_1\n" });
  // Axes stated by explicit options: secrets (confidentiality ON, integrity OFF).
  const s = new ArbiterServer({ socketPath: join(home, "arbiter.sock"), dbPath, eventDir: join(home, "events"), log: () => {}, confidentiality: true, integrity: false });
  try {
    const reg = s.dispatch({ id: 1, op: "registerSecret", path: join(home, ".npmrc"), home }) as { ok: boolean; result: { twin?: string; reason: string } };
    assert.ok(reg.ok && reg.result.twin, reg.result.reason);
    const field = /\$MDU:[A-Za-z_]+\[[0-9a-f]+\][A-Za-z0-9_.]*/.exec(reg.result.twin!)![0];
    const ask = (symbol: string, scheme: "http" | "https") => (s.dispatch({
      id: 2, op: "desymbolizationDecision",
      request: { symbol, boundary: "network", destination: "registry.npmjs.org", scheme, positions: ["authorization"] },
    }) as { result: { allow: boolean; requiresApproval?: boolean; reason: string; ruleRef?: { id: string } } }).result;
    for (const symbol of [field, `${field}.x`]) {
      const plain = ask(symbol, "http");
      assert.equal(plain.allow, false, `${symbol}: ${plain.reason}`);
      assert.equal(plain.requiresApproval, false, `${symbol}: a hard refusal, nothing to approve`);
      assert.equal(plain.ruleRef?.id, "egress:secret-https-only", symbol);
      const tls = ask(symbol, "https");
      assert.equal(tls.allow, true, `${symbol}: ${tls.reason}`);
    }
  } finally {
    void s.close();
    cleanup();
  }
});

test("wirePositionRefusal (2026-10-09): a credential bound only automatically is refused (no approval) unless every position is the Authorization header; a user's binding and other boundaries are untouched", () => {
  const net = (positions?: unknown) => ({ boundary: "network" as const, destination: "registry.npmjs.org", ...(positions === undefined ? {} : { positions: positions as never }) });
  assert.equal(wirePositionRefusal(net(["authorization"]), true), null, "the header: put back");
  assert.equal(wirePositionRefusal(net(["authorization", "authorization"]), true), null);
  for (const [positions, words] of [
    [["body"], /never in its body/],
    [["url"], /never in its URL/],
    [["header"], /never in its other headers/],
    [["authorization", "body"], /never in its body/],
    [["url", "header", "body"], /never in its URL or other headers or body/],
    [["body", "url"], /never in its URL or body/],
    [[], /does not say where/],
    [undefined, /does not say where/],
    [["somewhere"], /outside that header/],
    [["authorization", 7], /outside that header/],
    ["authorization", /does not say where/],
  ] as const) {
    const r = wirePositionRefusal(net(positions), true);
    assert.ok(r, JSON.stringify(positions));
    assert.equal(r!.allow, false);
    assert.equal(r!.allow === false && r!.requiresApproval, false, `${JSON.stringify(positions)}: a hard refusal, nothing to approve`);
    assert.equal(r!.ruleRef?.id, "egress:secret-wire-position");
    assert.match(r!.reason, words, JSON.stringify(positions));
    assert.match(r!.reason, /bound to 'registry\.npmjs\.org' only by its own config file or sign-in/);
  }
  // Not this rule's: a binding the user declared (or none: the bindings
  // branches decide), another boundary.
  assert.equal(wirePositionRefusal(net(["body"]), false), null, "a user's binding keeps the whole-request release");
  assert.equal(wirePositionRefusal({ boundary: "filesystem", positions: ["body"] }, true), null);
  // A network ask that says the value would run as a command is judged all
  // the same (2026-10-10: it was exempt, and went on to a standing verdict).
  const asCommand: DesymbolizationRequest = { symbol: "$MDU:nomodel_Read[ab12].t", boundary: "network", destination: "h", asCommand: true };
  for (const positions of [undefined, ["body"], ["authorization", "url"]] as const) {
    const r = wirePositionRefusal({ ...asCommand, ...(positions ? { positions: [...positions] } : {}) }, true);
    assert.equal(r?.ruleRef?.id, "egress:secret-wire-position", `asCommand, ${JSON.stringify(positions)}`);
    assert.equal(r?.allow === false && r.requiresApproval, false, "a hard refusal");
  }
  assert.equal(wirePositionRefusal({ ...asCommand, positions: ["authorization"] }, true), null, "asCommand in the header alone: other rules decide");
});
