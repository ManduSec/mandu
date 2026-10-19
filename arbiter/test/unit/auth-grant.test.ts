/**
 * auth-grant — an agent's own key file, twinned, with its key field bound
 * to the provider the launch routes (agent-sign-in.md §3): the grant parser,
 * the in-memory store, the bindings law keeping a granted field (and only
 * it) bound to the granted hosts in both directions, the restart dropping
 * the binding, the egress gate releasing the key at the granted host only,
 * and the wire scheme rule.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getSymbolEntry, loadSymbolMap } from "../../symbol-table/symbol-table.js";
import { registerEnvSecret, registerSecret, wireReleaseScheme } from "../../secret-registry/registry.js";
import { envSecretSpan } from "../../policy/secret-extract.js";
import { releaseRestsOnWireGrant, syncEnvBindings, syncRegisteredBindings } from "../../secret-registry/current-bindings.js";
import { AuthGrantStore, destinationHost, isGrantOrigin, isLoopbackGrantHost, parseAuthGrants } from "../../secret-registry/auth-grants.js";
import { decideDesymbolization, wirePositionRefusal, wireSchemeRefusal } from "../../policy/policy-interface.js";
import type { LabelLookup } from "../../policy/secret-catalog.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the file is a catalog secret only with confidentiality on

const KEY = "sk-ant-api03-MANDUFAKEauthGRANTkey0123456789abcdef";
const OKEY = "sk-proj-MANDUFAKEopenaiGRANT0123456789abcdef";
const TOKEN = "ghp_MANDUFAKEextensionTOKEN0123456789abcd";

function fixture(): { dir: string; dbPath: string; secrets: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-auth-grant-"));
  const goose = join(dir, ".config", "goose");
  mkdirSync(goose, { recursive: true });
  const secrets = join(goose, "secrets.yaml");
  writeFileSync(secrets, `ANTHROPIC_API_KEY: ${KEY}\nOPENAI_API_KEY: ${OKEY}\nGITHUB_PERSONAL_ACCESS_TOKEN: ${TOKEN}\n`, { mode: 0o600 });
  return { dir, dbPath: join(dir, "symbols.db"), secrets, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/** The field symbol of `field` in a structured twin. */
function fieldSymbol(twin: string, field: string): string {
  const m = new RegExp(`^${field}: (\\$MDU:\\S+)$`, "m").exec(twin);
  assert.ok(m, `${field} in the twin:\n${twin}`);
  return m![1]!;
}

test("parseAuthGrants: a field name, a plain host or loopback address, https; plain HTTP only on loopback", () => {
  assert.deepEqual(parseAuthGrants([{ field: "ANTHROPIC_API_KEY", host: "API.Anthropic.com", https: true }]), [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }]);
  assert.deepEqual(parseAuthGrants([{ field: "K", host: "127.0.0.1", https: false }]), [{ field: "K", host: "127.0.0.1", https: false }]);
  assert.deepEqual(parseAuthGrants([{ field: "K", host: "::1", https: false }]), [{ field: "K", host: "::1", https: false }]);
  for (const bad of [
    [], "x", [null], [{ field: "a.b", host: "h", https: true }], [{ field: "K", host: "h:443", https: true }],
    [{ field: "K", host: "*.anthropic.com", https: true }], [{ field: "K", host: "https://h", https: true }],
    [{ field: "K", host: "h", https: "yes" }], [{ field: "K", host: "api.openai.com", https: false }],
    [{ field: "K", host: "999.1.1.1", https: true }], [{ field: "K", host: "evil.example/x", https: true }],
    Array.from({ length: 17 }, () => ({ field: "K", host: "h", https: true })),
  ]) {
    assert.throws(() => parseAuthGrants(bad), JSON.stringify(bad));
  }
  assert.ok(isLoopbackGrantHost("127.0.0.1") && isLoopbackGrantHost("localhost") && isLoopbackGrantHost("::1"));
  assert.ok(!isLoopbackGrantHost("api.anthropic.com") && !isLoopbackGrantHost("128.0.0.1"));
  assert.equal(destinationHost("API.anthropic.com:443"), "api.anthropic.com");
  assert.equal(destinationHost("[::1]:8080"), "::1");
});

test("AuthGrantStore: hosts accumulate per file and field; the scheme is read at the destination", () => {
  const s = new AuthGrantStore();
  s.grant("/h/.config/goose/secrets.yaml", [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }]);
  s.grant("/h/.config/goose/secrets.yaml", [{ field: "ANTHROPIC_API_KEY", host: "127.0.0.1", https: false }]);
  assert.deepEqual(s.hosts("/h/.config/goose/secrets.yaml", "ANTHROPIC_API_KEY").sort(), ["127.0.0.1", "api.anthropic.com"]);
  assert.deepEqual(s.hosts("/h/.config/goose/secrets.yaml", "OPENAI_API_KEY"), []);
  assert.deepEqual(s.hosts("/elsewhere/secrets.yaml", "ANTHROPIC_API_KEY"), []);
  assert.equal(s.scheme("/h/.config/goose/secrets.yaml", "ANTHROPIC_API_KEY", "api.anthropic.com"), "https");
  assert.equal(s.scheme("/h/.config/goose/secrets.yaml", "ANTHROPIC_API_KEY", "127.0.0.1:9000"), "any");
  assert.equal(s.scheme("/h/.config/goose/secrets.yaml", "ANTHROPIC_API_KEY", "evil.example"), "https", "an ungranted host: fail closed");
  assert.equal(s.scheme("/h/.config/goose/secrets.yaml", "OPENAI_API_KEY", "api.openai.com"), undefined);
});

test("the granted field alone is bound to the granted host; the base row and the other fields are not", () => {
  const { dbPath, secrets, cleanup } = fixture();
  try {
    const store = new AuthGrantStore();
    store.grant(secrets, [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }]);
    const fieldGrants = (o: string, f: string) => store.hosts(o, f);
    const map = loadSymbolMap(dbPath);
    const r = registerSecret(map, { path: secrets, fieldGrants }, dbPath);
    assert.ok(r.symbol && r.twin, r.reason);
    assert.ok(!r.twin!.includes(KEY) && !r.twin!.includes(TOKEN), "the twin holds no value");
    const anth = fieldSymbol(r.twin!, "ANTHROPIC_API_KEY");
    const oai = fieldSymbol(r.twin!, "OPENAI_API_KEY");
    const gh = fieldSymbol(r.twin!, "GITHUB_PERSONAL_ACCESS_TOKEN");
    assert.deepEqual(getSymbolEntry(map, anth)?.bindings, ["api.anthropic.com"], "bound from its first registration");
    assert.equal(getSymbolEntry(map, anth)?.value, KEY);
    assert.equal(getSymbolEntry(map, oai)?.bindings ?? null, null, "a field the launch did not grant");
    assert.equal(getSymbolEntry(map, gh)?.bindings ?? null, null, "the extension's token");
    assert.equal(getSymbolEntry(map, r.symbol!)?.bindings ?? null, null, "the base row");

    // A grant added later reaches the rows at the next sync (the op runs it).
    store.grant(secrets, [{ field: "OPENAI_API_KEY", host: "api.openai.com", https: true }]);
    syncRegisteredBindings(map, { paths: [secrets], fieldGrants }, dbPath);
    assert.deepEqual(getSymbolEntry(map, oai)?.bindings, ["api.openai.com"]);

    // A re-registration (another launch) keeps the grants it is told of…
    registerSecret(map, { path: secrets, fieldGrants }, dbPath);
    assert.deepEqual(getSymbolEntry(map, anth)?.bindings, ["api.anthropic.com"]);
    // …and an arbiter that holds none (a restart) drops them: fail closed.
    syncRegisteredBindings(map, { paths: [secrets], fieldGrants: () => [] }, dbPath);
    assert.equal(getSymbolEntry(map, anth)?.bindings ?? null, null, "a restart drops the binding");
    assert.equal(getSymbolEntry(map, oai)?.bindings ?? null, null);
    // The persisted rows agree.
    assert.equal(getSymbolEntry(loadSymbolMap(dbPath), anth)?.bindings ?? null, null);
  } finally {
    cleanup();
  }
});

test("the egress gate releases the granted key at the granted host only, and the scheme rule holds", () => {
  const { dbPath, secrets, cleanup } = fixture();
  try {
    const store = new AuthGrantStore();
    store.grant(secrets, [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }]);
    const map = loadSymbolMap(dbPath);
    const r = registerSecret(map, { path: secrets, fieldGrants: (o, f) => store.hosts(o, f) }, dbPath);
    const anth = fieldSymbol(r.twin!, "ANTHROPIC_API_KEY");
    const gh = fieldSymbol(r.twin!, "GITHUB_PERSONAL_ACCESS_TOKEN");
    const lookup = (s: string) => getSymbolEntry(map, s) ?? undefined;
    const decide = (symbol: string, destination: string) =>
      decideDesymbolization({ symbol, boundary: "network", destination }, lookup, () => false, { confidentiality: true });
    const ok = decide(anth, "api.anthropic.com");
    assert.equal(ok.allow, true, ok.reason);
    assert.equal(ok.ruleRef?.id, "egress:secret-bound-trusted");
    for (const [sym, dest] of [[anth, "evil.example"], [anth, "api.openai.com"], [gh, "api.anthropic.com"], [r.symbol!, "api.anthropic.com"]] as const) {
      const d = decide(sym, dest);
      assert.equal(d.allow, false, `${sym} at ${dest}`);
    }
    // In model context it is a hard deny, granted or not.
    const mc = decideDesymbolization({ symbol: anth, boundary: "model_context" }, lookup, () => false, { confidentiality: true });
    assert.equal(mc.allow, false);
    // The scheme: an https grant never goes over plain HTTP.
    const at = (dest: string) => wireReleaseScheme(map, anth, { grantScheme: (o, f) => store.scheme(o, f, dest) });
    assert.equal(at("api.anthropic.com"), "https");
    assert.ok(wireSchemeRefusal({ boundary: "network", destination: "api.anthropic.com", scheme: "http" }, at("api.anthropic.com")), "plain HTTP refused");
    assert.equal(wireSchemeRefusal({ boundary: "network", destination: "api.anthropic.com", scheme: "https" }, at("api.anthropic.com")), null);
    store.grant(secrets, [{ field: "ANTHROPIC_API_KEY", host: "127.0.0.1", https: false }]);
    assert.equal(at("127.0.0.1:8080"), "any", "a loopback plain-HTTP grant");
    assert.equal(at("api.anthropic.com"), "https", "still https at the vendor");
    assert.equal(wireReleaseScheme(map, gh, { grantScheme: (o, f) => store.scheme(o, f, "api.anthropic.com") }), null, "an ungranted field is no wire credential");
  } finally {
    cleanup();
  }
});

test("an auth grant is an automatic binding (2026-10-09): the granted key at the granted host rests on the grant alone, so the gate puts it back only in the auth header; a label naming the host makes it the user's", () => {
  const { dbPath, secrets, cleanup } = fixture();
  try {
    const store = new AuthGrantStore();
    store.grant(secrets, [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }]);
    const fieldGrants = (o: string, f: string) => store.hosts(o, f);
    const map = loadSymbolMap(dbPath);
    let declared: string[] = [];
    const resolveLabel: LabelLookup = (p) => (p === secrets ? { level: "no-model", bindings: [...declared], via: p } : null);
    const r = registerSecret(map, { path: secrets, fieldGrants, resolveLabel }, dbPath);
    const anth = fieldSymbol(r.twin!, "ANTHROPIC_API_KEY");
    assert.equal(releaseRestsOnWireGrant(map, anth, "api.anthropic.com", { resolveLabel }), true);
    assert.equal(wirePositionRefusal({ boundary: "network", destination: "api.anthropic.com", positions: ["authorization"] }, true), null, "the model proxy's header put-back");
    assert.equal(wirePositionRefusal({ boundary: "network", destination: "api.anthropic.com", positions: ["body"] }, true)?.ruleRef?.id, "egress:secret-wire-position");
    assert.equal(releaseRestsOnWireGrant(map, anth, "evil.example", { resolveLabel }), false, "not bound there");
    declared = ["api.anthropic.com"];
    syncRegisteredBindings(map, { paths: [secrets], fieldGrants, resolveLabel }, dbPath);
    assert.equal(releaseRestsOnWireGrant(map, anth, "api.anthropic.com", { resolveLabel }), false, "the label declares the host: the user's binding");
  } finally {
    cleanup();
  }
});

test("across a restart (2026-10-11): a grant with its launcher's pid is kept in the DB and taken back while that launcher lives, never after", () => {
  const { dbPath, secrets, cleanup } = fixture();
  try {
    const live = new Set<number>([111, 222]);
    const starts = new Map<number, string>([[111, "s111"], [222, "s222"]]);
    const seams = { pidExists: (p: number) => live.has(p), procStartTime: (p: number) => starts.get(p) ?? null };
    const a = new AuthGrantStore({ dbPath, ...seams });
    a.grant(secrets, [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }], { pid: 111 });
    a.grant(secrets, [{ field: "OPENAI_API_KEY", host: "api.openai.com", https: true }], { pid: 222 });
    a.grant(secrets, [{ field: "GITHUB_PERSONAL_ACCESS_TOKEN", host: "api.github.com", https: true }]); // no pid: memory only
    a.grant(secrets, [{ field: "OPENAI_API_KEY", host: "127.0.0.1", https: false }], { pid: 999 }); // a pid this process cannot see
    // A row names a path, a field, a host, the scheme and a pid: never a value.
    const rows = a.persisted();
    assert.deepEqual(rows.map((r) => `${r.field}@${r.host}#${r.pid}`), ["ANTHROPIC_API_KEY@api.anthropic.com#111", "OPENAI_API_KEY@api.openai.com#222"]);
    for (const r of rows) for (const v of Object.values(r)) for (const k of [KEY, OKEY, TOKEN]) assert.ok(!String(v).includes(k));
    a.close();

    // Restart with both launchers alive: both taken back, the unpersisted not.
    const b = new AuthGrantStore({ dbPath, ...seams });
    assert.equal(b.restored, 2);
    assert.deepEqual(b.hosts(secrets, "ANTHROPIC_API_KEY"), ["api.anthropic.com"]);
    assert.deepEqual(b.hosts(secrets, "OPENAI_API_KEY"), ["api.openai.com"]);
    assert.deepEqual(b.hosts(secrets, "GITHUB_PERSONAL_ACCESS_TOKEN"), [], "a grant without a pid dies with the arbiter");
    assert.equal(b.scheme(secrets, "ANTHROPIC_API_KEY", "api.anthropic.com"), "https");
    b.close();

    // Launcher 222 ended; 111's pid now belongs to another process (another
    // start time): neither is taken back.
    live.delete(222);
    starts.set(111, "s111-reused");
    const c = new AuthGrantStore({ dbPath, ...seams });
    assert.equal(c.restored, 0);
    assert.deepEqual(c.hosts(secrets, "ANTHROPIC_API_KEY"), []);
    assert.deepEqual(c.hosts(secrets, "OPENAI_API_KEY"), []);
    // The next write prunes the gone launchers' rows.
    live.add(333); starts.set(333, "s333");
    c.grant(secrets, [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }], { pid: 333 });
    assert.deepEqual(c.persisted().map((r) => r.pid), [333]);
    c.close();
  } finally {
    cleanup();
  }
});

test("a restarted arbiter's sync keeps a live launch's binding (the grant taken back) and drops an ended one's", () => {
  const { dbPath, secrets, cleanup } = fixture();
  try {
    let alive = true;
    const seams = { pidExists: () => alive, procStartTime: () => "t0" };
    const before = new AuthGrantStore({ dbPath, ...seams });
    before.grant(secrets, [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }], { pid: 4321 });
    const map = loadSymbolMap(dbPath);
    const r = registerSecret(map, { path: secrets, fieldGrants: (o, f) => before.hosts(o, f) }, dbPath);
    const anth = fieldSymbol(r.twin!, "ANTHROPIC_API_KEY");
    before.close();

    // The restart: a fresh symbol map from disk, a fresh store from the DB.
    const after = new AuthGrantStore({ dbPath, ...seams });
    const map2 = loadSymbolMap(dbPath);
    syncRegisteredBindings(map2, { fieldGrants: (o, f) => after.hosts(o, f) }, dbPath);
    assert.deepEqual(getSymbolEntry(map2, anth)?.bindings, ["api.anthropic.com"], "the live launch keeps its key working");
    after.close();

    alive = false;
    const ended = new AuthGrantStore({ dbPath, ...seams });
    const map3 = loadSymbolMap(dbPath);
    syncRegisteredBindings(map3, { fieldGrants: (o, f) => ended.hosts(o, f) }, dbPath);
    assert.equal(getSymbolEntry(map3, anth)?.bindings ?? null, null, "an ended launch's grant is not taken back: fail closed");
    ended.close();
  } finally {
    cleanup();
  }
});

// ── the environment form (§3.8): Claude Code's ANTHROPIC_API_KEY ─────────────

test("envSecretSpan: the agent's own key variable stays exempt unless the launch's grant names it (agentKeys); never a pattern, never another name", () => {
  assert.equal(envSecretSpan("ANTHROPIC_API_KEY", KEY), null, "exempt by default: the agent keeps a key it can use");
  assert.deepEqual(envSecretSpan("ANTHROPIC_API_KEY", KEY, { agentKeys: ["ANTHROPIC_API_KEY"] }), { key: "ANTHROPIC_API_KEY", start: 0, end: KEY.length, value: KEY });
  assert.equal(envSecretSpan("ANTHROPIC_API_KEY", KEY, { agentKeys: ["ANTHROPIC_*"] }), null, "exact names only");
  assert.equal(envSecretSpan("MANDU_ULLM_API_KEY", KEY, { agentKeys: ["MANDU_ULLM_API_KEY"] }), null, "only an agent credential name");
  assert.equal(envSecretSpan("ANTHROPIC_API_KEY", "", { agentKeys: ["ANTHROPIC_API_KEY"] }), null, "an empty value is nothing");
  // Codex's key variables (§3.11): exempt by name, masked with the grant.
  for (const name of ["OPENAI_API_KEY", "CODEX_API_KEY"]) {
    assert.equal(envSecretSpan(name, OKEY), null);
    assert.equal(envSecretSpan(name, OKEY, { agentKeys: [name] })?.value, OKEY);
  }
  // Mandu's own routing is never an agent key, whatever the request says.
  assert.equal(envSecretSpan("MANDU_ULLM_API_KEY", KEY, { agentKeys: ["MANDU_ULLM_API_KEY"] }), null);
});

test("an env auth grant binds the variable's row to the granted host (rule 3, both directions); the gate releases it there only, over https, in the auth header only", () => {
  const { dbPath, cleanup } = fixture();
  try {
    const store = new AuthGrantStore();
    store.grant("env:ANTHROPIC_API_KEY", [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }]);
    const fieldGrants = (o: string, f: string) => store.hosts(o, f);
    const map = loadSymbolMap(dbPath);
    const r = registerEnvSecret(map, { name: "ANTHROPIC_API_KEY", value: KEY, rules: { agentKeys: ["ANTHROPIC_API_KEY"] }, bindings: store.hosts("env:ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY") }, dbPath);
    assert.ok(r.symbol && r.twin, r.reason);
    assert.match(r.twin!, /^\$MDU:nomodel_Env\[[0-9a-f]+\]\.ANTHROPIC_API_KEY$/, "the agent's environment carries the placeholder only");
    assert.ok(!r.twin!.includes(KEY));
    const sym = r.symbol!;
    assert.deepEqual(getSymbolEntry(map, sym)?.bindings, ["api.anthropic.com"]);
    // A sync with no grant (an ended launch after a restart) drops it; the grant back restores it.
    const law = () => [] as string[];
    syncEnvBindings(map, { envBindings: law, fieldGrants: () => [] }, dbPath);
    assert.equal(getSymbolEntry(map, sym)?.bindings ?? null, null, "no grant: unbound (fail closed)");
    syncEnvBindings(map, { envBindings: law, fieldGrants }, dbPath);
    assert.deepEqual(getSymbolEntry(map, sym)?.bindings, ["api.anthropic.com"]);

    const lookup = (s: string) => getSymbolEntry(map, s) ?? undefined;
    const decide = (destination: string) => decideDesymbolization({ symbol: sym, boundary: "network", destination }, lookup, () => false, { confidentiality: true });
    assert.equal(decide("api.anthropic.com").allow, true, decide("api.anthropic.com").reason);
    assert.equal(decide("evil.example").allow, false);
    assert.equal(decideDesymbolization({ symbol: sym, boundary: "model_context" }, lookup, () => false, { confidentiality: true }).allow, false, "never into a model's context");
    // The scheme rule reads the env grant.
    const scheme = wireReleaseScheme(map, sym, { grantScheme: (o, f) => store.scheme(o, f, "api.anthropic.com") });
    assert.equal(scheme, "https");
    assert.ok(wireSchemeRefusal({ boundary: "network", destination: "api.anthropic.com", scheme: "http" }, scheme), "never over plain HTTP");
    // The binding is Mandu's, not the user's: the auth header only.
    assert.equal(releaseRestsOnWireGrant(map, sym, "api.anthropic.com", { envBindings: law }), true);
    assert.equal(wirePositionRefusal({ boundary: "network", destination: "api.anthropic.com", positions: ["body"] }, true)?.ruleRef?.id, "egress:secret-wire-position");
    // A user's env.sources binding on the same host makes it the user's.
    assert.equal(releaseRestsOnWireGrant(map, sym, "api.anthropic.com", { envBindings: () => ["api.anthropic.com"] }), false);
  } finally {
    cleanup();
  }
});

test("an env grant persists like a file's: taken back across a restart while its launcher lives", () => {
  const { dbPath, cleanup } = fixture();
  try {
    const seams = { pidExists: (p: number) => p === 77, procStartTime: () => "t" };
    const a = new AuthGrantStore({ dbPath, ...seams });
    a.grant("env:ANTHROPIC_API_KEY", [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }], { pid: 77 });
    a.close();
    const b = new AuthGrantStore({ dbPath, ...seams });
    assert.deepEqual(b.hosts("env:ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"), ["api.anthropic.com"]);
    b.close();
    assert.ok(isGrantOrigin("env:ANTHROPIC_API_KEY") && isGrantOrigin("/abs/path"));
    assert.ok(!isGrantOrigin("env:") && !isGrantOrigin("env:A-B") && !isGrantOrigin("relative/path"));
  } finally {
    cleanup();
  }
});

test("§3.10: a provider key variable masked by its name's shape (OPENROUTER_API_KEY) takes its env grant's host the same way, and only that host", () => {
  const { dbPath, cleanup } = fixture();
  try {
    const OR = "sk-or-v1-MANDUFAKEopenrouterGRANT0123456789";
    const store = new AuthGrantStore();
    store.grant("env:OPENROUTER_API_KEY", [{ field: "OPENROUTER_API_KEY", host: "openrouter.ai", https: true }]);
    const map = loadSymbolMap(dbPath);
    const r = registerEnvSecret(map, { name: "OPENROUTER_API_KEY", value: OR, bindings: store.hosts("env:OPENROUTER_API_KEY", "OPENROUTER_API_KEY") }, dbPath);
    assert.ok(r.symbol, r.reason);
    assert.deepEqual(getSymbolEntry(map, r.symbol!)?.bindings, ["openrouter.ai"]);
    syncEnvBindings(map, { envBindings: () => [], fieldGrants: (o, f) => store.hosts(o, f) }, dbPath);
    assert.deepEqual(getSymbolEntry(map, r.symbol!)?.bindings, ["openrouter.ai"], "rule 3 keeps it");
    const lookup = (s: string) => getSymbolEntry(map, s) ?? undefined;
    const at = (destination: string) => decideDesymbolization({ symbol: r.symbol!, boundary: "network", destination }, lookup, () => false, { confidentiality: true }).allow;
    assert.equal(at("openrouter.ai"), true);
    assert.equal(at("api.anthropic.com"), false);
    assert.equal(releaseRestsOnWireGrant(map, r.symbol!, "openrouter.ai", { envBindings: () => [] }), true, "the auth header only");
  } finally {
    cleanup();
  }
});
