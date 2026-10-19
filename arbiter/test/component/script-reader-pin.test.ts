/**
 * script-reader-pin (component) — confidentiality plan 13 §9 R5 over a real
 * ArbiterServer with both sockets: the `(interpreter, script)` reader pin
 * from the guard's report to the policy file on disk and the model exit.
 *
 *   policy.yaml: ~/.pgpass  readers: [{ app: python3, script: <report.py>, output: clear, prints: nothing }]
 *
 * The guard (a production client on the HUMAN socket, plan 13 D9) reports a
 * python3 open of ~/.pgpass with its script facts. Asserted:
 *   - the pinned pair reads raw; the arbiter writes the interpreter's pin and
 *     the script's hash into policy.yaml, keeping `output: clear`;
 *   - its call folds `clear` (the script's output reaches the model) while
 *     the script started no other program, and `secret` once it did;
 *   - inline code, a workspace copy, no isolation, a traced opener, a
 *     PYTHONPATH the launch did not give, a changed script: no raw byte, no
 *     pin;
 *   - the same report on the DATA socket (a program of the agent's) is the
 *     twin.
 * Each `raw`/`clear` here was `deny`/`secret` on the code before R5 (the
 * entry's `script:` key did not load, and a code-running reader could not
 * be cleared).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const PY = "/usr/bin/python3.12";
const PY_SHA = "a".repeat(64);
const SCRIPT = "/opt/tools/report.py";
const S_SHA = "b".repeat(64);
type Facts = { path: string; sha256?: string; system: boolean; isolated: boolean; traced: boolean };
const facts = (over: Partial<Facts> = {}): Facts => ({ path: SCRIPT, sha256: S_SHA, system: true, isolated: true, traced: false, ...over });

async function rig(fn: (r: { guard: ArbiterClient; agent: ArbiterClient; secret: string; policy: string }) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-r5-"));
  const secret = join(dir, ".pgpass");
  writeFileSync(secret, "db.internal:5432:prod:app:r5canary000000000001\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers:\n      - { app: python3, script: ${SCRIPT}, output: clear, prints: nothing }\n`);
  const human = join(dir, "human", "h.sock");
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: human, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    policyPath: policy, log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const agent = new ArbiterClient(join(dir, "a.sock")); await agent.connect();
  try { await fn({ guard, agent, secret, policy }); } finally { guard.close(); agent.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); }
}

const cmd = (id: string): string => `python3 -I ${SCRIPT} --rows ${id}`;

/** One tool call: its shell (the agent's own child), then python's open. */
async function call(c: ArbiterClient, id: string, open: Record<string, unknown>, secret: string): Promise<string> {
  const session = "r5";
  await c.execGate({ command: cmd(id), sessionKey: session, callId: `toolu_${id}` });
  await c.recordExecRoot({ procKey: `${id}-sh`, ancestors: ["r5-agent"], argv: ["/bin/bash", "-c", cmd(id)], session, callRoot: true });
  const chain = [`${id}-sh`, "r5-agent"];
  await c.recordExecRoot({ procKey: `${id}-py`, ancestors: chain, argv: ["python3", "-I", SCRIPT], session });
  const d = await c.decideSecretOpen({ path: secret, exe: PY, sha256: PY_SHA, isAgent: false, exeSystem: true, openerEnv: [], procKey: `${id}-py`, parentKey: chain[0], ancestorKeys: chain, session, ...open } as Parameters<ArbiterClient["decideSecretOpen"]>[0]);
  return d.verdict;
}

test("R5: the pinned (python3, script) pair reads raw, is pinned with the script's hash, and its call's output is cleared until it starts another program (secrets axes)", async () => {
  await rig(async ({ guard, secret, policy }) => {
    assert.equal(await call(guard, "c1", { script: facts() }, secret), "raw");
    const law = readFileSync(policy, "utf8");
    assert.match(law, /scriptSha256: b{64}/, `the script's hash is pinned:\n${law}`);
    assert.match(law, new RegExp(`path: ${PY}`), "and the interpreter's path");
    assert.match(law, /output: clear/, "the entry keeps its output (a system interpreter)");
    assert.doesNotMatch(law, /app: python3\.12/, "the pin replaces the entry; it is not appended under the binary's own name");
    const t = await guard.callTaint("toolu_c1", { command: cmd("c1"), session: "r5" });
    assert.equal(t.evidence, "tree");
    assert.equal(t.rule, "clear", `the pinned script's output reaches the model: ${JSON.stringify(t)}`);

    // the second run of the now fully pinned pair: raw, still cleared
    assert.equal(await call(guard, "c2", { script: facts() }, secret), "raw");
    assert.equal((await guard.callTaint("toolu_c2", { command: cmd("c2"), session: "r5" })).rule, "clear");
    // a run that started another program (a child under python): secret
    assert.equal(await call(guard, "c3", { script: facts() }, secret), "raw");
    await guard.recordExecRoot({ procKey: "c3-child", ancestors: ["c3-py", "c3-sh", "r5-agent"], argv: ["grep", "x"], session: "r5" });
    assert.equal((await guard.callTaint("toolu_c3", { command: cmd("c3"), session: "r5" })).rule, "secret", "a cleared script that ran another program is masked");
  });
});

test("R5 fail-closed: no raw byte and no pin for inline code, a workspace copy, no isolation, a traced opener, a loader variable, a changed script; the data socket gets the twin (secrets axes)", async () => {
  await rig(async ({ guard, agent, secret, policy }) => {
    const cases: Array<[string, Record<string, unknown>]> = [
      ["inline code", { scriptProblem: "inline code (python -c)" }],
      ["a workspace copy", { script: facts({ path: "/home/u/ws/report.py", system: false }) }],
      ["the pinned path, agent-writable", { script: facts({ system: false }) }],
      ["no isolation", { script: facts({ isolated: false }) }],
      ["traced", { script: facts({ traced: true }) }],
      ["PYTHONPATH", { script: facts(), openerEnv: ["PYTHONPATH"] }],
      ["no facts (an older guard)", {}],
    ];
    const before = readFileSync(policy, "utf8");
    for (const [why, open] of cases) {
      const v = await call(guard, `f-${why.replace(/\W/g, "")}`, open, secret);
      assert.equal(v, "deny", `${why}: a non-reader of a listed file is refused`);
    }
    assert.equal(readFileSync(policy, "utf8"), before, "nothing was pinned");
    // pin it, then change the script: the old hash no longer matches
    assert.equal(await call(guard, "p1", { script: facts() }, secret), "raw");
    assert.equal(await call(guard, "p2", { script: facts({ sha256: "c".repeat(64) }) }, secret), "deny", "a changed script must be re-pinned");
    // a program of the agent reporting the same facts on the data socket
    const d = await agent.decideSecretOpen({ path: secret, exe: PY, sha256: PY_SHA, isAgent: false, exeSystem: true, openerEnv: [], procKey: "forged-py", session: "r5", script: facts() });
    assert.equal(d.verdict, "twin", "unauthenticated: the twin (plan 13 D9)");
  });
});

test("a pin on a file a PATTERN labels writes the file's own entry with the pattern's bindings, others and other readers (the registered key stays bound; secrets axes)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-r5-glob-"));
  mkdirSync(join(dir, "proj"));
  const secret = join(dir, "proj", ".pgpass");
  writeFileSync(secret, "db.internal:5432:prod:app:r5canary000000000002\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, [
    "version: 1", "paths:",
    "  - path: \"**/proj/.pgpass\"", "    level: no-model",
    `    readers: [{ app: python3, script: ${SCRIPT}, output: clear, prints: nothing }, { app: psql }]`,
    "    others: twin", "    bindings: [db.internal]", "",
  ].join("\n"));
  const human = join(dir, "human", "h.sock");
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: human, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    policyPath: policy, log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  try {
    const reg = await guard.registerSecret({ path: secret, sessionKey: "r5" });
    assert.ok(reg.symbol, reg.reason);
    assert.equal(await call(guard, "g1", { script: facts() }, secret), "raw");
    const law = readFileSync(policy, "utf8");
    const own = law.indexOf(`path: ${secret}`);
    assert.ok(own > 0, `the file has its own entry now:\n${law}`);
    assert.match(law, /scriptSha256: b{64}/, `the pin landed:\n${law}`);
    const level = await guard.pathLevel(secret);
    assert.equal(level.rule, `label:${secret}`, "the file's own entry decides");
    assert.deepEqual(level.bindings, ["db.internal"], "with the pattern's binding");
    assert.match(law.slice(own), /app: psql/, "the pattern's other reader is kept");
    assert.match(law.slice(own), /others: twin/, "and its others");
    // The key's symbol, bound by the law in force, still releases at its host.
    const d = await guard.desymbolizationDecision({ symbol: reg.symbol!, boundary: "network", destination: "db.internal" });
    assert.equal(d.ruleRef?.id, "egress:secret-bound-trusted", JSON.stringify(d));
  } finally {
    guard.close(); await s.close(); rmSync(dir, { recursive: true, force: true });
  }
});

// ── plan 13 §8 decision (c): an Inbox answer about an interpreter names its script ──

test("DECISION (c): an Always for python3 running a.py names the script: it admits neither b.py nor python3 -c; an answer naming the interpreter alone (before the decision) admits nothing (secrets axes)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-r5c-"));
  const secret = join(dir, ".netrc");
  writeFileSync(secret, "machine api.example.com login me password c-canary-0001\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [psql]\n`);
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"), humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), policyPath: policy, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock")); await guard.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  const A = "/opt/tools/a.py", B = "/opt/tools/b.py";
  const open = (procKey: string, how: Record<string, unknown>) =>
    guard.decideSecretOpen({ path: secret, exe: PY, sha256: PY_SHA, isAgent: false, exeSystem: true, openerEnv: [], procKey, session: "r5c", ask: "always", ...how } as Parameters<ArbiterClient["decideSecretOpen"]>[0]);
  const pending = async () => (await admin.egressApprovals("pending")).filter((e) => e.destination === secret);
  try {
    // The row names the interpreter AND the script.
    const held = await open("a-1", { script: facts({ path: A }) });
    assert.equal(held.verdict, "ask", held.reason);
    const [row] = await pending();
    // plan 13 D8 (12): an interpreter's script is no vetted reader, so the
    // question is the warning one (`trust:`)
    assert.equal(row?.symbol, `trust:${PY}#${PY_SHA}#script:${encodeURIComponent(A)}#${S_SHA}`);
    assert.match(row!.reason, /running \/opt\/tools\/a\.py wants to read/);
    assert.match(row!.reason, /Mandu does not know whether python3\.12 keeps what it reads out of what it prints/);
    await admin.resolveEgressApproval(held.approvalId!, true, "always");
    assert.equal((await open("a-2", { script: facts({ path: A }) })).verdict, "raw", "the answered pair reads");
    assert.match(readFileSync(policy, "utf8"), /script: \/opt\/tools\/a\.py[\s\S]{0,200}prints: nothing|prints: nothing[\s\S]{0,200}script: \/opt\/tools\/a\.py/, "the Always wrote the human's word");
    // Another script of the same interpreter: its own question.
    const b = await open("b-1", { script: facts({ path: B, sha256: "c".repeat(64) }) });
    assert.equal(b.verdict, "ask", `python3 running b.py is not what the human allowed (${b.verdict}: ${b.reason})`);
    assert.equal((await guard.processSecretTaint("b-1")).level, null);
    // The same script changed: another question too.
    assert.equal((await open("a-3", { script: facts({ path: A, sha256: "d".repeat(64) }) })).verdict, "ask", "a changed a.py is asked again");
    // Inline code: refused, never asked (decision (b)), whatever was allowed.
    const inline = await open("c-1", { scriptProblem: "inline code (python -c)" });
    assert.equal(inline.verdict, "deny", inline.reason);
    assert.equal(inline.approvalId, undefined);
    // An answer written before decision (c), naming the interpreter alone.
    const store = (s as unknown as { egressApprovals: { recordPending(sym: string, d: string, r: string): { id: string }; resolve(id: string, approve: boolean, scope: "once" | "always"): unknown } }).egressApprovals;
    const old = store.recordPending(`open:${PY}#${PY_SHA}`, secret, "python3 wants to read it");
    store.resolve(old.id, true, "always"); // answered then (an answer now is refused: it would change nothing)
    const third = await open("t-1", { script: facts({ path: "/opt/tools/third.py", sha256: "e".repeat(64) }) });
    assert.equal(third.verdict, "ask", `the old interpreter-only Always admitted another script (${third.reason})`);
    assert.equal((await open("c-2", { scriptProblem: "inline code (python -c)" })).verdict, "deny", "nor inline code");
    // `mandu why` names the script, and marks the old answer as applying to nothing.
    const why = await admin.whyPath(secret);
    const opens = why.verdicts.filter((v) => v.kind !== "write");
    assert.ok(opens.some((v) => v.script === A && v.status === "approved" && v.scope === "always" && !v.stale), JSON.stringify(opens));
    assert.ok(opens.some((v) => v.stale === true && v.script === undefined && v.exe === PY), JSON.stringify(opens));
    assert.ok(!JSON.stringify(why.verdicts).includes(PY_SHA), "the hashes stay in the key");
  } finally {
    guard.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true });
  }
});
