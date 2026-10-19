/**
 * npmrc-wire-twin.test.ts — plan 10 §11.13.1 over the real IPC: npm reads
 * the `.npmrc` twin, not the raw file, when the session proxy can put its
 * token back at its registry.
 *
 *   - registerSecret (HUMAN socket, at launch: only there does the HOME's
 *     file earn its wire grant, 2026-10-17) reads the launch HOME's real
 *     `.npmrc` and binds each `_authToken` / `_auth` field symbol to the
 *     registry its own key names;
 *   - registerWireRelease (HUMAN socket only) says the session's proxy
 *     inspects TLS;
 *   - decideSecretOpen then serves node (a known consumer, no reader list)
 *     the twin and records NO taint; without the registration, or for a file
 *     with a `cafile` or a `_password` npm cannot decode, node running a
 *     script R5's checks pin reads raw and is tainted, as before, and node
 *     running inline code gets the twin (plan 13 §8 decision (b), 2026-10-02);
 *   - the egress decision releases the field symbol at its registry only;
 *   - since 2026-10-03 a `username` + `_password` file is servable too (the
 *     decoded password's symbol, released at its registry only), and a HOME
 *     pip.conf's index password symbol is released at its index host only.
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
import { allocateSymbol, loadSymbolMap, obsoleteSymbol } from "../../symbol-table/symbol-table.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const TOKEN = "npm_WIRETWIN_CANARY_7Q";
const S = "sess-npmrc";

async function stack(npmrc: string, labelExtra = "") {
  const dir = mkdtempSync(join(tmpdir(), "mandu-npmrc-wire-"));
  const home = join(dir, "home");
  mkdirSync(home);
  const file = join(home, ".npmrc");
  writeFileSync(file, npmrc);
  // The arbiter's own HOME is not the launch's: a human label names the file
  // (decideSecretOpen judges the path by the law, registerSecret by the launch's home).
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${JSON.stringify(file)}\n    level: no-model\n${labelExtra}`);
  const sock = join(dir, "a.sock");
  const human = join(dir, "human", "h.sock");
  const s = new ArbiterServer({ socketPath: sock, humanSocketPath: human, adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath: policy });
  await s.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const h = new ArbiterClient(human); await h.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  return { data, h, admin, file, home, done: async () => { data.close(); h.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); } };
}

// The guard asks on the human socket (plan 13 D9). Plan 13 §8 decision (b):
// node runs code it is given, so it is a default reader only as a script R5's
// checks pin (`NPM_CLI`, out of the agent's reach, isolated, untraced); the
// same node running inline code (`INLINE`) is no reader at all.
const NPM_CLI = { path: "/usr/lib/node_modules/npm/bin/npm-cli.js", sha256: "c".repeat(64), system: true, isolated: true, traced: false };
const INLINE = { scriptProblem: "inline code (node -e)" };
/** Plan 13 D8 (12): node is no vetted reader, so it reads `.npmrc` raw only
 *  where the human vouches for npm's script (`prints: nothing`); with no
 *  entry it is asked about with the warning (`ask: known`). */
const VOUCHED = `    readers: [{ app: node, script: ${NPM_CLI.path}, prints: nothing }]\n`;
const open = (k: { h: ArbiterClient; file: string }, procKey: string, exe = "/usr/bin/node", how: { script: typeof NPM_CLI } | typeof INLINE = { script: NPM_CLI }) =>
  k.h.decideSecretOpen({ path: k.file, exe, isAgent: false, exeSystem: true, openerEnv: [], procKey, session: S, ask: "known", ...how });

test("registerWireRelease is human-plane only", async () => {
  const k = await stack(`//registry.npmjs.org/:_authToken=${TOKEN}\n`);
  try {
    await assert.rejects(k.data.registerWireRelease(S, true), /human-plane/);
    assert.deepEqual(await k.h.registerWireRelease(S, true), { inspecting: true });
  } finally { await k.done(); }
});

test("a servable HOME .npmrc: node, vouched for, reads raw (tainted) until the session's proxy is known to inspect TLS, then the twin (no taint); not vouched for, it is asked with the warning", async () => {
  const bare = await stack(`registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${TOKEN}\n`);
  try {
    const d = await open(bare, "node-0");
    assert.equal(d.verdict, "ask", d.reason);
    assert.match(d.reason, /node is not a program Mandu knows keeps a file's contents out of what it prints/);
    assert.equal((await bare.data.processSecretTaint("node-0")).level, null);
    const row = (await bare.admin.egressApprovals("pending")).find((e) => e.id === d.approvalId);
    assert.match(String(row?.symbol), /^trust:\/usr\/bin\/node#/, "the warning question");
  } finally { await bare.done(); }
  const k = await stack(`registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${TOKEN}\n`, VOUCHED);
  try {
    const reg = await k.h.registerSecret({ path: k.file, home: k.home, sessionKey: S });
    assert.ok(reg.symbol && reg.twin, reg.reason);
    assert.ok(!reg.twin!.includes(TOKEN), "the twin holds no secret byte");

    const before = await open(k, "node-1");
    assert.equal(before.verdict, "raw", before.reason);
    assert.equal((await k.data.processSecretTaint("node-1")).level, "no-model", "today's default reader is tainted");
    // Plan 13 §8 decision (b): node running inline code is no default reader
    // (refused: node-1's read pinned the script into a reader list, §11.2).
    const inline = await open(k, "node-inline", "/usr/bin/node", INLINE);
    assert.equal(inline.verdict, "deny", inline.reason);
    assert.match(inline.reason, /pinned script/);
    assert.equal((await k.data.processSecretTaint("node-inline")).level, null, "inline code holds no raw byte");

    await k.h.registerWireRelease(S, true);
    const after = await open(k, "node-2");
    assert.equal(after.verdict, "twin", after.reason);
    assert.match(after.reason, /served its twin: the session proxy puts every token back at its own registry \(registry\.npmjs\.org\)/);
    assert.equal((await k.data.processSecretTaint("node-2")).level, null, "the twin holds no byte: no taint");
    assert.equal((await open(k, "npm-3", "/usr/bin/npm")).verdict, "twin");
    // Another session, whose proxy nobody vouched for, keeps the raw read.
    const other = await k.h.decideSecretOpen({ path: k.file, exe: "/usr/bin/node", isAgent: false, exeSystem: true, openerEnv: [], procKey: "node-4", session: "sess-other", ask: "known", script: NPM_CLI });
    assert.equal(other.verdict, "raw");
    // node-1's raw read pinned node into the file's reader list (§11.2): the
    // wire twin still applies to it, as asserted above for node-2.
    // A registry npm reaches around the proxy (the session's NO_PROXY): raw.
    await k.h.registerWireRelease(S, true, ["127.0.0.1", "localhost", ".npmjs.org"]);
    const direct = await open(k, "node-6");
    assert.equal(direct.verdict, "raw", direct.reason);
    // Cleared: back to raw.
    await k.h.registerWireRelease(S, false);
    assert.equal((await open(k, "node-5")).verdict, "raw");
  } finally { await k.done(); }
});

// The CI flake of 2026-10-03 (red on master 43976849), made deterministic:
// node-1's raw read self-registers the file (§11.15 case 2). It used to mint
// a second base row (no session key, no launch HOME: no wire binding), and
// the newest base row by `created_at` (whole seconds) decides the wire twin,
// so a registration and a raw read one second apart lost the twin. The clock
// is moved on 2 s between the two so the race is always lost.
test("a raw read of a file the launch registered (under a session key) registers nothing new: the wire twin holds a second later", async (t) => {
  const k = await stack(`registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${TOKEN}\n`, VOUCHED);
  try {
    const reg = await k.h.registerSecret({ path: k.file, home: k.home, sessionKey: S });
    assert.ok(reg.symbol && reg.twin, reg.reason);
    const realNow = Date.now.bind(Date);
    t.mock.method(Date, "now", () => realNow() + 2000);
    assert.equal((await open(k, "node-1")).verdict, "raw");
    const rows = (await k.h.secretRegistry()).filter((e) => e.path === k.file);
    assert.deepEqual(rows.map((e) => e.symbol), [reg.symbol], "the launch's row is the file's only registration");
    await k.h.registerWireRelease(S, true);
    const after = await open(k, "node-2");
    assert.equal(after.verdict, "twin", after.reason);
    assert.equal((await k.data.processSecretTaint("node-2")).level, null, "the twin holds no byte: no taint");
    // The fingerprint scan still holds the token (the launch's rows are the known secret).
    assert.ok((await k.h.scanSecretValues(`x ${TOKEN} y`)).hits.length > 0, "the token stays a known secret");
  } finally { await k.done(); }
});

test("the field symbol is released at its registry only; anywhere else needs the human", async () => {
  const k = await stack(`//registry.npmjs.org/:_authToken=${TOKEN}\n`);
  try {
    const reg = await k.h.registerSecret({ path: k.file, home: k.home, sessionKey: S });
    const field = /\$MDU:[A-Za-z_]+\[[0-9a-f]+\][A-Za-z0-9_.]*/.exec(reg.twin!)![0];
    // In the Authorization header, where npm sends it (2026-10-09: the only
    // position a wire-bound token is put back in; see the test below).
    const at = (destination: string) => k.data.desymbolizationDecision({ symbol: field, destination, boundary: "network", scheme: "https", positions: ["authorization"] });
    const bound = await at("registry.npmjs.org");
    assert.equal(bound.allow, true, bound.reason);
    for (const d of ["evil.example", "registry.npmjs.org.evil.example", "npmjs.org"]) {
      const r = await at(d);
      assert.equal(r.allow, false, `${d}: ${r.reason}`);
    }
  } finally { await k.done(); }
});

test("https only (2026-10-03): an https-declared token is refused in plain HTTP or with no stated scheme, a hard refusal no human approval overrides; an http-declared registry's token is released over http", async () => {
  const k = await stack(`//registry.npmjs.org/:_authToken=${TOKEN}\n//npm.lan.example/:_authToken=${TOKEN}_LAN\n@lan:registry=http://npm.lan.example/\n`);
  try {
    const reg = await k.h.registerSecret({ path: k.file, home: k.home, sessionKey: S });
    const [pub, lan] = [...reg.twin!.matchAll(/\$MDU:[A-Za-z_]+\[[0-9a-f]+\][A-Za-z0-9_.]*/g)].map((m) => m[0]);
    const at = (symbol: string, destination: string, scheme?: "http" | "https") =>
      k.data.desymbolizationDecision({ symbol: symbol!, destination, boundary: "network", positions: ["authorization"], ...(scheme ? { scheme } : {}) });
    assert.equal((await at(pub!, "registry.npmjs.org", "https")).allow, true);
    for (const scheme of ["http", undefined] as const) {
      const r = await at(pub!, "registry.npmjs.org", scheme);
      assert.equal(r.allow, false, `${scheme}: ${r.reason}`);
      assert.equal(r.allow === false && r.requiresApproval, false, "nothing to approve");
      assert.equal(r.ruleRef?.id, "egress:secret-https-only");
    }
    // A mutated token (a field tail the gate's lookup walks back to the
    // token's row, and `resolve` returns the token for) is that row: refused
    // in plain HTTP too (2026-10-09: the rule read the exact name and skipped it).
    const mutated = await at(`${pub!}.x`, "registry.npmjs.org", "http");
    assert.equal(mutated.allow, false, mutated.reason);
    assert.equal(mutated.ruleRef?.id, "egress:secret-https-only");
    assert.equal((await at(`${pub!}.x`, "registry.npmjs.org", "https")).allow, true, "the same token over https is the token's own release");
    // The http-declared registry's token: plain HTTP is its own scheme.
    assert.equal((await at(lan!, "npm.lan.example", "http")).allow, true);
    assert.equal((await at(lan!, "npm.lan.example", "https")).allow, true);
    // A standing human approval for a host releases over https only.
    const asked = await at(pub!, "decoy.example", "https");
    assert.equal(asked.allow, false);
    const id = asked.allow === false ? asked.approvalId : undefined;
    assert.ok(id, "the unbound host queued an ask");
    await k.admin.resolveEgressApproval(id!, true);
    assert.equal((await at(pub!, "decoy.example", "https")).allow, true, "the human's answer, over https");
    const http = await at(pub!, "decoy.example", "http");
    assert.equal(http.allow, false, "never over plain HTTP, whatever the human answered");
    assert.equal(http.ruleRef?.id, "egress:secret-https-only");
    // Nor does an ask that says the value would run as a command, in plain
    // HTTP or with no stated scheme (2026-10-10: `asCommand` exempted it from
    // the rule, and the standing answer released it).
    for (const scheme of ["http", undefined] as const) {
      for (const destination of ["decoy.example", "registry.npmjs.org"]) {
        const r = await k.data.desymbolizationDecision({ symbol: pub!, destination, boundary: "network", positions: ["authorization"], asCommand: true, ...(scheme ? { scheme } : {}) });
        assert.equal(r.allow, false, `asCommand ${destination} ${scheme}: ${r.reason}`);
        assert.equal(r.allow === false && r.requiresApproval, false, "nothing to approve");
        assert.equal(r.ruleRef?.id, "egress:secret-https-only", `asCommand ${destination} ${scheme}`);
      }
    }
  } finally { await k.done(); }
});

// Plan 10 §11.13.1, 2026-10-09: a credential bound to its host only by its
// own config (the wire twin) is put back only in the request's Authorization
// header. Before, the same placeholder in a publish document's body, the
// query or any header was released with no prompt (an injected agent could
// have npm publish the token in a package's readme).
test("the Authorization header only (2026-10-09): a wire-bound token anywhere else in the request, or where the caller does not say, is a hard refusal that runs before a standing Always allow; a binding the user declared keeps the whole-request release", async () => {
  const k = await stack(`registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${TOKEN}\n`);
  try {
    const reg = await k.h.registerSecret({ path: k.file, home: k.home, sessionKey: S });
    const field = /\$MDU:[A-Za-z_]+\[[0-9a-f]+\][A-Za-z0-9_.]*/.exec(reg.twin!)![0];
    const at = (positions: unknown, symbol = field, destination = "registry.npmjs.org") =>
      k.data.desymbolizationDecision({ symbol, destination, boundary: "network", scheme: "https", ...(positions === undefined ? {} : { positions: positions as never }) });
    const ok = await at(["authorization"]);
    assert.equal(ok.allow, true, ok.reason);
    assert.equal(ok.ruleRef?.id, "egress:secret-bound-trusted");
    for (const positions of [["body"], ["url"], ["header"], ["authorization", "body"], ["authorization", "header"], [], undefined, ["somewhere"], "authorization"]) {
      const r = await at(positions);
      assert.equal(r.allow, false, `${JSON.stringify(positions)}: ${r.reason}`);
      assert.equal(r.allow === false && r.requiresApproval, false, `${JSON.stringify(positions)}: nothing to approve`);
      assert.equal(r.ruleRef?.id, "egress:secret-wire-position", JSON.stringify(positions));
      assert.equal(r.allow === false ? r.approvalId : undefined, undefined, "nothing queued");
    }
    assert.match((await at(["authorization", "body"])).reason, /only in the request's Authorization header, never in its body/);
    // A mutated token (a field tail the gate's lookup walks back to the
    // token's row) is that row: refused too.
    assert.equal((await at(["body"], `${field}.x`)).ruleRef?.id, "egress:secret-wire-position");
    // Another host: not this rule's (unbound, the human decides).
    assert.equal((await at(["body"], field, "evil.example")).ruleRef?.id, "egress:secret-unbound");
    assert.deepEqual((await k.admin.egressApprovals("pending")).filter((e) => e.destination === "registry.npmjs.org"), [], "no ask was filed for the registry");

    // A standing "Always allow" at the registry does not carry the token out
    // of the header: under a lockdown the header ask is queued, the human
    // allows it always, the lockdown ends.
    await k.admin.setSessionPosture({ posture: "lockdown", requestedBy: "wire-position test" });
    const held = await at(["authorization"]);
    assert.equal(held.allow, false);
    const id = held.allow === false ? held.approvalId : undefined;
    assert.ok(id, held.reason);
    await k.admin.resolveEgressApproval(id!, true, "always");
    await k.admin.setSessionPosture({ posture: "normal", allowRelax: true, requestedBy: "wire-position test" });
    const verdict = await at(["authorization"]);
    assert.equal(verdict.allow, true);
    assert.equal(verdict.ruleRef?.source, "verdict", "the human's standing answer decided the header");
    const body = await at(["body"]);
    assert.equal(body.allow, false, "the Always allow does not reach the body");
    assert.equal(body.ruleRef?.id, "egress:secret-wire-position");
    // Nor does an ask that says the value would run as a command (2026-10-10:
    // `asCommand` exempted it from the rule, and the Always allow released it).
    for (const positions of [["body"], undefined] as const) {
      const asCommand = await k.data.desymbolizationDecision({ symbol: field, destination: "registry.npmjs.org", boundary: "network", scheme: "https", asCommand: true, ...(positions ? { positions: [...positions] } : {}) });
      assert.equal(asCommand.allow, false, `asCommand ${JSON.stringify(positions)}: ${asCommand.reason}`);
      assert.equal(asCommand.ruleRef?.id, "egress:secret-wire-position");
    }

    // pip's index variable: bound to its index host by its own URL.
    const env = await k.data.registerEnvSecrets({ vars: [{ name: "PIP_INDEX_URL", value: `https://builder:${TOKEN}_PIP@pypi.corp.example/simple` }], sessionKey: S });
    const pip = env.vars[0]!.symbol!;
    assert.ok(pip, env.vars[0]!.reason);
    assert.equal((await at(["authorization"], pip, "pypi.corp.example")).allow, true);
    assert.equal((await at(["url"], pip, "pypi.corp.example")).ruleRef?.id, "egress:secret-wire-position");
  } finally { await k.done(); }

  // The same file with the registry in the label's `bindings:`: the user's
  // own binding, which keeps today's whole-request release.
  const mine = await stack(`registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${TOKEN}\n`, "    bindings: [registry.npmjs.org]\n");
  try {
    const reg = await mine.h.registerSecret({ path: mine.file, home: mine.home, sessionKey: S });
    const field = /\$MDU:[A-Za-z_]+\[[0-9a-f]+\][A-Za-z0-9_.]*/.exec(reg.twin!)![0];
    for (const positions of [["body"], ["url", "header"], ["authorization"]]) {
      const r = await mine.data.desymbolizationDecision({ symbol: field, destination: "registry.npmjs.org", boundary: "network", scheme: "https", positions: positions as never });
      assert.equal(r.allow, true, `${JSON.stringify(positions)}: ${r.reason}`);
      assert.equal(r.ruleRef?.id, "egress:secret-bound-trusted");
    }
  } finally { await mine.done(); }
});

// 2026-10-10: an OBSOLETED wire row, and a copy whose only parent is one,
// were judged as a binding of the user's, so the rule above let them go
// anywhere in the request. No IPC op obsoletes or copies a row today: the
// table is edited between two runs of the arbiter on one database, the state
// such an op would leave.
test("an obsoleted wire-bound token, and a copy whose only parent it is, are still put back only in the Authorization header (2026-10-10)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-npmrc-obsolete-"));
  const home = join(dir, "home");
  mkdirSync(home);
  const file = join(home, ".npmrc");
  writeFileSync(file, `registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${TOKEN}\n`);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${JSON.stringify(file)}\n    level: no-model\n`);
  const db = join(dir, "db.sqlite");
  const run = async () => {
    const sock = join(dir, "a.sock");
    const s = new ArbiterServer({ socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), adminSocketPath: join(dir, "admin.sock"), dbPath: db, eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath: policy });
    await s.listen();
    const data = new ArbiterClient(sock); await data.connect();
    const human = new ArbiterClient(join(dir, "human", "h.sock")); await human.connect();
    return { data, human, done: async () => { data.close(); human.close(); await s.close(); } };
  };
  try {
    const first = await run();
    let field: string;
    try {
      const reg = await first.human.registerSecret({ path: file, home, sessionKey: S });
      field = /\$MDU:[A-Za-z_]+\[[0-9a-f]+\][A-Za-z0-9_.]*/.exec(reg.twin!)![0];
    } finally { await first.done(); }
    const map = loadSymbolMap(db);
    const copy = allocateSymbol(map, { tool: "inspect_symbol", value: TOKEN, origin: field, confidentiality: "no-model", bindings: ["registry.npmjs.org"], integrity: "trusted" }, db);
    obsoleteSymbol(map, field, "human", db);

    const second = await run();
    try {
      const at = (symbol: string, positions: string[]) =>
        second.data.desymbolizationDecision({ symbol, destination: "registry.npmjs.org", boundary: "network", scheme: "https", positions: positions as never });
      for (const symbol of [field, copy]) {
        const r = await at(symbol, ["body"]);
        assert.equal(r.allow, false, `${symbol}: ${r.reason}`);
        assert.equal(r.allow === false && r.requiresApproval, false, `${symbol}: a hard refusal, nothing to approve`);
        assert.equal(r.ruleRef?.id, "egress:secret-wire-position", symbol);
      }
      const header = await at(copy, ["authorization"]);
      assert.equal(header.allow, true, header.reason);
      assert.equal(header.ruleRef?.id, "egress:secret-bound-trusted");
    } finally { await second.done(); }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a HOME .npmrc with a _password (2026-10-03): node reads the twin, no taint; the decoded password's symbol is released at its registry only", async () => {
  const k = await stack(`//corp.example/npm/:username=me\n//corp.example/npm/:_password=${Buffer.from(TOKEN).toString("base64")}\n`);
  try {
    const reg = await k.h.registerSecret({ path: k.file, home: k.home, sessionKey: S });
    assert.ok(reg.twin, reg.reason);
    assert.ok(!reg.twin!.includes(TOKEN) && !reg.twin!.includes(Buffer.from(TOKEN).toString("base64")));
    await k.h.registerWireRelease(S, true);
    const d = await open(k, "node-pw");
    assert.equal(d.verdict, "twin", d.reason);
    assert.equal((await k.data.processSecretTaint("node-pw")).level, null);
    // npm decodes the twin's _password into the token and sends it in Basic.
    const b64 = /:_password=([A-Za-z0-9+/=]+)\n/.exec(reg.twin!)![1]!;
    const field = Buffer.from(b64, "base64").toString("utf8");
    assert.match(field, /^\$MDU:[A-Za-z_]+\[[0-9a-f]+\]\.[A-Za-z0-9_.]+$/, "a field symbol");
    const at = (destination: string) => k.data.desymbolizationDecision({ symbol: field, destination, boundary: "network", scheme: "https", positions: ["authorization"] });
    assert.equal((await at("corp.example")).allow, true);
    for (const dst of ["evil.example", "corp.example.evil.example"]) assert.equal((await at(dst)).allow, false, dst);
  } finally { await k.done(); }
});

test("a HOME pip.conf: the index URL password's symbol (percent-encoded in the twin) is released at its index host only; a workspace pip.conf's nowhere", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-pip-wire-"));
  const home = join(dir, "home");
  const conf = join(home, ".config", "pip", "pip.conf");
  const wsConf = join(dir, "ws", "pip.conf");
  mkdirSync(join(home, ".config", "pip"), { recursive: true });
  mkdirSync(join(dir, "ws"));
  const content = `[global]\nindex-url = https://builder:${TOKEN}@pypi.corp.example/simple\n`;
  writeFileSync(conf, content);
  writeFileSync(wsConf, content.replace("builder", "other"));
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${JSON.stringify(conf)}\n    level: no-model\n  - path: ${JSON.stringify(wsConf)}\n    level: no-model\n`);
  const s = new ArbiterServer({ socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, policyPath: policy });
  await s.listen();
  const data = new ArbiterClient(join(dir, "a.sock")); await data.connect();
  const human = new ArbiterClient(join(dir, "human", "h.sock")); await human.connect();
  try {
    const tokenOf = async (path: string): Promise<string> => {
      const reg = await human.registerSecret({ path, home, sessionKey: S });
      assert.ok(reg.twin && !reg.twin.includes(TOKEN), reg.reason);
      const enc = /:\/\/[a-z]+:([^@]+)@/.exec(reg.twin!)![1]!;
      assert.ok(!enc.includes("[") && !enc.includes("$"), `percent-encoded: ${enc}`);
      return decodeURIComponent(enc);
    };
    const home1 = await tokenOf(conf);
    const at = (symbol: string, destination: string) => data.desymbolizationDecision({ symbol, destination, boundary: "network", scheme: "https", positions: ["authorization"] });
    assert.equal((await at(home1, "pypi.corp.example")).allow, true);
    for (const dst of ["evil.example", "pypi.corp.example.evil.example"]) assert.equal((await at(home1, dst)).allow, false, dst);
    const ws = await tokenOf(wsConf);
    assert.notEqual(ws, home1);
    assert.equal((await at(ws, "pypi.corp.example")).allow, false, "a workspace pip.conf derives no binding");
  } finally {
    data.close(); human.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("not servable: a _password npm cannot decode, or a cafile, keeps node (vouched for) a raw reader even when the proxy inspects TLS", async () => {
  for (const npmrc of [
    `//corp.example/npm/:username=me\n//corp.example/npm/:_password=${TOKEN}!\n`,
    `//registry.npmjs.org/:_authToken=${TOKEN}\ncafile=/etc/corp-ca.pem\n`,
  ]) {
    const k = await stack(npmrc, VOUCHED);
    try {
      await k.h.registerSecret({ path: k.file, home: k.home, sessionKey: S });
      await k.h.registerWireRelease(S, true);
      const d = await open(k, "node-9");
      assert.equal(d.verdict, "raw", `${npmrc}: ${d.reason}`);
      assert.equal((await k.data.processSecretTaint("node-9")).level, "no-model");
      // Plan 13 §8 decision (b): not node running inline code (refused:
      // the file has a reader list, the vouched script's).
      const inline = await open(k, "node-9i", "/usr/bin/node", INLINE);
      assert.equal(inline.verdict, "deny", `${npmrc}: ${inline.reason}`);
      assert.equal((await k.data.processSecretTaint("node-9i")).level, null);
    } finally { await k.done(); }
  }
});

test("an explicit `others: twin` label is served without the known-consumer prompt; without it node is held", async () => {
  const k = await stack(`//corp.example/npm/:_password=cGFzcw==\n`, "    readers: [yarn]\n    others: twin\n");
  try {
    const d = await open(k, "node-10");
    assert.equal(d.verdict, "twin", d.reason);
    assert.equal((await k.data.processSecretTaint("node-10")).level, null);
  } finally { await k.done(); }
  const held = await stack(`//corp.example/npm/:_password=cGFzcw==\n`, "    readers: [yarn]\n");
  try {
    const d = await open(held, "node-11");
    assert.equal(d.verdict, "ask", d.reason);
    // Plan 13 §8 decision (b): node running inline code is refused unasked
    // (the human would be approving code nobody showed them).
    const inline = await open(held, "node-11i", "/usr/bin/node", INLINE);
    assert.equal(inline.verdict, "deny", inline.reason);
    assert.equal(inline.approvalId, undefined, "no Inbox row for inline code");
  } finally { await held.done(); }
});
