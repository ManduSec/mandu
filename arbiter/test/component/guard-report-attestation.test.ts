/**
 * guard-report-attestation — the guard's process records are believed only
 * from a channel the agent's process tree cannot reach (plan 13 §3 D9,
 * exec-routing.md §7.5 "Authenticated reports", arbiter-human-plane.md §3).
 *
 * The guard (`mandu-net-guard`) reports which process started which (lineage
 * chains), which exec is the agent's own shell for a tool call (`callRoot`),
 * which raw opens it let through with the opener's identity facts
 * (`exeSystem`, `openerEnv`, ancestor trust), and the model proxies record
 * when they gated a call and ask for its tree. Before this change every one
 * of those ops was believed on the DATA socket, which every process the agent
 * runs can reach, so a program the agent ran could:
 *   - record a false parent for a reader before the guard did (first edge
 *     wins) and take it out of its tool call's tree: its result reached the
 *     model raw (four roads: processLineage, recordExecRoot, the chains of
 *     taintedProcessBindings and of decideSecretOpen);
 *   - report a shell for a call whose real shell record was lost: the call
 *     bound to that clean shell and its result reached the model raw;
 *   - ask callTaint for another call first, with a clean call's text: the
 *     call bound to the clean call's shell;
 *   - report a raw open of its own copy of `mytool` as a system binary: the
 *     arbiter pinned the bare-name reader to that copy, which then read the
 *     file raw under the real guard;
 *   - record a taint row naming the source of a derived copy: the process
 *     then read the copy raw as "a copy of secrets it already holds";
 *   - file an Inbox row for a protected write in the guard's words.
 * Now the guard and the proxies send these on the HUMAN socket; the same
 * records from the data socket are claims: they may add taint (a claimed
 * edge or row only widens a fold) and never lower one.
 *
 * Every test here was red on master `6f27c2cc` (the assertion marked
 * MASTER names what master answered). A real ArbiterServer with both
 * sockets; `guard` and `proxy` are production clients on the human socket,
 * `agent` one on the data socket, as a program the agent runs has.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer, ATTESTED_REPORT_OPS, attestedChannel } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

interface Rig {
  dir: string;
  secret: string;
  policy: string;
  guard: ArbiterClient;
  proxy: ArbiterClient;
  agent: ArbiterClient;
  done: () => Promise<void>;
}

async function rig(policyYaml?: (secret: string) => string): Promise<Rig> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-attest-"));
  const secret = join(dir, "x.txt");
  writeFileSync(secret, "token=ATTEST_CANARY_0\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, policyYaml ? policyYaml(secret) : `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mytool, prints: nothing }]\n`);
  const sock = join(dir, "a.sock");
  const human = join(dir, "human", "h.sock");
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({
    socketPath: sock, humanSocketPath: human, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    policyPath: policy, log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const proxy = new ArbiterClient(human); await proxy.connect();
  const agent = new ArbiterClient(sock); await agent.connect();
  return {
    dir, secret, policy, guard, proxy, agent,
    done: async () => { guard.close(); proxy.close(); agent.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

const READ = "( mytool ./x.tx?; true ) | od -An -tx1";
const CLEAN = "echo clean-42";
const shell = (command: string): string[] => ["/bin/bash", "-c", command];
const tick = (): Promise<void> => new Promise((ok) => setTimeout(ok, 5));

/** One call whose shell's subshell runs `mytool` on the secret, the guard's
 *  records in the guard's order, with `forge` run by the agent's program
 *  before the guard reports the reader. */
async function readerCall(r: Rig, session: string, forge: () => Promise<unknown>): Promise<Awaited<ReturnType<ArbiterClient["callTaint"]>>> {
  await r.proxy.execGate({ command: READ, sessionKey: session, callId: `toolu_${session}` });
  await r.guard.recordExecRoot({ procKey: `${session}-sh-1`, ancestors: [`${session}-agent-0`], argv: shell(READ), session, callRoot: true });
  await forge();
  const chain = [`${session}-sub-2`, `${session}-sh-1`, `${session}-agent-0`];
  await r.guard.recordExecRoot({ procKey: `${session}-mytool-3`, ancestors: chain, argv: ["mytool", "./x.txt"], session });
  const d = await r.guard.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: `${session}-mytool-3`, parentKey: chain[0], ancestorKeys: chain, session });
  assert.equal(d.verdict, "raw", `the guard's report of the pinned reader is raw: ${d.reason}`);
  return r.proxy.callTaint(`toolu_${session}`, { command: READ, session });
}

test("a forged lineage edge sent over the data socket before the guard's does not take a reader out of its call's tree, by any of the five roads (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    const roads: Array<[string, (session: string) => Promise<unknown>]> = [
      ["processLineage", (s) => r.agent.processLineage({ childKey: `${s}-mytool-3`, parentKey: `${s}-elsewhere-9`, session: s })],
      ["recordExecRoot", (s) => r.agent.recordExecRoot({ procKey: `${s}-mytool-3`, ancestors: [`${s}-elsewhere-9`], argv: ["true"], session: s })],
      ["taintedProcessBindings", (s) => r.agent.taintedProcessBindings({ procKey: `${s}-mytool-3`, ancestors: [`${s}-elsewhere-9`], session: s })],
      ["labelWrittenPathTainted", (s) => r.agent.labelWrittenPathTainted({ path: join(r.dir, "out.txt"), procKey: `${s}-mytool-3`, ancestors: [`${s}-elsewhere-9`], session: s })],
      ["decideSecretOpen", (s) => r.agent.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: `${s}-mytool-3`, ancestorKeys: [`${s}-elsewhere-9`], session: s })],
    ];
    const lost: string[] = [];
    for (const [road, forge] of roads) {
      const session = `lin-${road}`;
      const t = await readerCall(r, session, () => forge(session));
      // MASTER: level null on every road (the reader hung under `elsewhere-9`), the hex dump raw
      if (t.level !== "no-model" || t.evidence !== "tree" || t.apps.join() !== "mytool") lost.push(`${road}: ${JSON.stringify(t)}`);
    }
    assert.deepEqual(lost, [], "the reader stays in its call's tree whatever the forged road");
  } finally { await r.done(); }
});

test("a forged exec report (`callRoot`) over the data socket for a call whose shell record was lost does not bind it: the call masks at the session's level (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    const session = "lost";
    const LOST = "head -c 64 ./x.tx? | od -An -tx1";
    await r.proxy.execGate({ command: LOST, sessionKey: session, callId: "toolu_lost" });
    // the reader ran under a wrapper; no exec of the agent carried the command
    const chain = ["lost-wrap-7", "lost-agent-0"];
    await r.guard.recordExecRoot({ procKey: "lost-head-8", ancestors: chain, argv: ["head", "-c", "64", "./x.txt"], session });
    const d = await r.guard.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "lost-head-8", ancestorKeys: chain, session });
    assert.equal(d.verdict, "raw");
    // a program of the agent reports a clean shell of the call's text BEFORE the proxy asks
    await r.agent.recordExecRoot({ procKey: "lost-forged-9", ancestors: ["lost-agent-0"], argv: shell(LOST), session, callRoot: true });
    const t = await r.proxy.callTaint("toolu_lost", { command: LOST, session });
    // MASTER: bound exact to the forged shell, level null, evidence tree (raw)
    assert.equal(t.level, "no-model", JSON.stringify(t));
    assert.equal(t.evidence, "session");
    assert.notEqual(t.root, "lost-forged-9");
  } finally { await r.done(); }
});

test("a forged callTaint over the data socket cannot bind a call to another call's clean shell; the clean call keeps its own (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    const session = "steal";
    await r.proxy.execGate({ command: READ, sessionKey: session, callId: "toolu_read" });
    await r.proxy.execGate({ command: CLEAN, sessionKey: session, callId: "toolu_clean" });
    await r.guard.recordExecRoot({ procKey: "st-sh-1", ancestors: ["st-agent-0"], argv: shell(READ), session, callRoot: true });
    await r.guard.recordExecRoot({ procKey: "st-sh-2", ancestors: ["st-agent-0"], argv: shell(CLEAN), session, callRoot: true });
    const chain = ["st-sub-3", "st-sh-1", "st-agent-0"];
    await r.guard.recordExecRoot({ procKey: "st-mytool-4", ancestors: chain, argv: ["mytool", "./x.txt"], session });
    assert.equal((await r.guard.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "st-mytool-4", ancestorKeys: chain, session })).verdict, "raw");
    // the reader's program asks for its own call first, naming the clean call's text
    await r.agent.callTaint("toolu_read", { command: CLEAN, session });
    const read = await r.proxy.callTaint("toolu_read", { command: READ, session });
    // MASTER: bound exact to st-sh-2 (the clean shell), level null
    assert.equal(read.level, "no-model", JSON.stringify(read));
    assert.equal(read.root, "st-sh-1");
    const clean = await r.proxy.callTaint("toolu_clean", { command: CLEAN, session });
    // MASTER: the clean shell was taken by the reader's call, so this one masked at the session level
    assert.equal(clean.level, null, `utility: the clean call is bound to its own shell: ${JSON.stringify(clean)}`);
    assert.equal(clean.evidence, "tree");
  } finally { await r.done(); }
});

// Plan 13 D9 follow-up: the proxy itself asked with the ECHOED text, which
// the agent controls (it builds the conversation the proxy reads back). On
// master `c82f1656` the call bound by that text: an agent that echoed the
// clean call's command for the reader's call bound it to the clean shell
// (raw), and the clean call lost its own (masked). Now a call binds by the
// command the proxy recorded on the human plane (execGate, recordCallCommand).
test("the D9 follow-up: an echoed command differing from the one the proxy gated binds nothing new; the reader's call stays bound to its own shell, masked, and the clean call keeps its own (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    const session = "echo";
    await r.proxy.execGate({ command: READ, sessionKey: session, callId: "toolu_e_read" });
    await r.proxy.execGate({ command: CLEAN, sessionKey: session, callId: "toolu_e_clean" });
    await r.guard.recordExecRoot({ procKey: "ec-sh-1", ancestors: ["ec-agent-0"], argv: shell(READ), session, callRoot: true });
    await r.guard.recordExecRoot({ procKey: "ec-sh-2", ancestors: ["ec-agent-0"], argv: shell(CLEAN), session, callRoot: true });
    const chain = ["ec-sub-3", "ec-sh-1", "ec-agent-0"];
    await r.guard.recordExecRoot({ procKey: "ec-mytool-4", ancestors: chain, argv: ["mytool", "./x.txt"], session });
    assert.equal((await r.guard.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "ec-mytool-4", ancestorKeys: chain, session })).verdict, "raw");
    // the agent echoes the clean call's command for the reader's call; the
    // proxy asks with it, on the human socket, before the clean call is asked
    const read = await r.proxy.callTaint("toolu_e_read", { command: CLEAN, session });
    // MASTER: bound exact to ec-sh-2 (the clean shell), level null: raw
    assert.equal(read.level, "no-model", `CONFIDENTIALITY: the reader's call is masked: ${JSON.stringify(read)}`);
    assert.equal(read.root, "ec-sh-1", "bound to the shell of the command the proxy gated");
    assert.equal(read.evidence, "tree");
    const clean = await r.proxy.callTaint("toolu_e_clean", { command: CLEAN, session });
    // MASTER: its shell was taken, so it masked at the session's level
    assert.equal(clean.level, null, `utility: the clean call keeps its own shell: ${JSON.stringify(clean)}`);
    assert.equal(clean.root, "ec-sh-2");
  } finally { await r.done(); }
});

test("the D9 follow-up: recordCallCommand from the data socket records nothing, so a program the agent runs cannot re-point a call at a clean shell; from the human socket the delivered form binds (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    const session = "deliv";
    // the proxy gated the reader's call as the model wrote it (HumanView) and
    // delivered it rewritten (the view map's AgentView path)
    const human = "( mytool /home/u/proj/x.tx?; true ) | od -An -tx1";
    const delivered = "( mytool /h/.mandu/views/proj/x.tx?; true ) | od -An -tx1";
    await r.proxy.execGate({ command: human, sessionKey: session, callId: "toolu_d_read" });
    assert.deepEqual(await r.proxy.recordCallCommand({ callId: "toolu_d_read", command: delivered, sessionKey: session }), { recorded: true });
    await r.proxy.execGate({ command: CLEAN, sessionKey: session, callId: "toolu_d_clean" });
    // a program the agent runs forges the reader's delivered command as the clean text
    const forged = await r.agent.recordCallCommand({ callId: "toolu_d_read", command: CLEAN, sessionKey: session });
    assert.equal(forged.recorded, false);
    assert.match(forged.reason ?? "", /unauthenticated/);
    await r.guard.recordExecRoot({ procKey: "dv-sh-1", ancestors: ["dv-agent-0"], argv: shell(delivered), session, callRoot: true });
    await r.guard.recordExecRoot({ procKey: "dv-sh-2", ancestors: ["dv-agent-0"], argv: shell(CLEAN), session, callRoot: true });
    const chain = ["dv-sub-3", "dv-sh-1", "dv-agent-0"];
    await r.guard.recordExecRoot({ procKey: "dv-mytool-4", ancestors: chain, argv: ["mytool", "./x.txt"], session });
    assert.equal((await r.guard.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "dv-mytool-4", ancestorKeys: chain, session })).verdict, "raw");
    const read = await r.proxy.callTaint("toolu_d_read", { command: CLEAN, session });
    assert.equal(read.level, "no-model", `CONFIDENTIALITY: ${JSON.stringify(read)}`);
    assert.equal(read.root, "dv-sh-1", "bound by the delivered (AgentView) form the proxy recorded");
    assert.equal((await r.proxy.callTaint("toolu_d_clean", { command: CLEAN, session })).root, "dv-sh-2");
  } finally { await r.done(); }
});

// Plan 13 D7's last residual (closed 2026-10-02): a call whose shell record
// was lost, while a same-text shell of ANOTHER live call sat in its window,
// bound `exact` to that other shell. No forgery needed: a report the guard
// failed to deliver is enough.
test("D7 lost record: a call whose shell record was lost does not bind to a live same-text call's clean shell; both calls mask at the session's level (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    const session = "twin-text";
    const CMD = "./build.sh";
    await r.proxy.execGate({ command: CMD, sessionKey: session, callId: "toolu_t_x" });
    await r.proxy.execGate({ command: CMD, sessionKey: session, callId: "toolu_t_y" });
    await tick();
    // X's shell ran a reader; its own exec report was lost, its reader's was not
    const chain = ["tt-sh-x", "tt-agent-0"];
    await r.guard.recordExecRoot({ procKey: "tt-mytool-3", ancestors: chain, argv: ["mytool", "./x.txt"], session });
    assert.equal((await r.guard.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "tt-mytool-3", ancestorKeys: chain, session })).verdict, "raw");
    // Y's shell, clean, is recorded
    await r.guard.recordExecRoot({ procKey: "tt-sh-y", ancestors: ["tt-agent-0"], argv: shell(CMD), session, callRoot: true });
    await tick();
    const x = await r.proxy.callTaint("toolu_t_x", { command: CMD, session });
    // MASTER: bound exact to tt-sh-y (Y's clean shell), level null, evidence tree: raw
    assert.equal(x.level, "no-model", `CONFIDENTIALITY: X is masked: ${JSON.stringify(x)}`);
    assert.equal(x.evidence, "session", "not bound by the recorder (Y's shell is at most a folded guess)");
    const y = await r.proxy.callTaint("toolu_t_y", { command: CMD, session });
    assert.equal(y.level, "no-model", `nothing tells Y's shell from X's: Y masks too: ${JSON.stringify(y)}`);
    assert.equal(y.evidence, "session");
  } finally { await r.done(); }
});

test("a forged identity fact over the data socket does not make a reader: no first-use pin, and the agent's copy of mytool gets no raw byte under the real guard's report (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    const session = "pin";
    const copy = join(r.dir, "ws", "mytool");
    const hash = "c".repeat(64);
    const forged = await r.agent.decideSecretOpen({ path: r.secret, exe: copy, sha256: hash, isAgent: false, exeSystem: true, openerEnv: [], procKey: "pin-1", session });
    // MASTER: raw, pinNeeded, and policy.yaml gained `{app: mytool, path: <copy>, sha256}`
    assert.notEqual(forged.verdict, "raw", JSON.stringify(forged));
    assert.equal(forged.pinNeeded, false);
    assert.ok(!readFileSync(r.policy, "utf8").includes(copy), `no pin of the agent's copy was written:\n${readFileSync(r.policy, "utf8")}`);
    // the guard reports the copy as it is: agent-writable
    const real = await r.guard.decideSecretOpen({ path: r.secret, exe: copy, sha256: hash, isAgent: false, exeSystem: false, openerEnv: [], procKey: "pin-2", session });
    // MASTER: raw (the forged pin matched path and hash)
    assert.notEqual(real.verdict, "raw", JSON.stringify(real));
    assert.equal((await r.proxy.processSecretTaint("pin-2")).level, null, "the copy holds nothing raw");
    // the control: the guard's report of the system mytool is a reader
    assert.equal((await r.guard.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", sha256: "d".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "pin-3", session })).verdict, "raw");
  } finally { await r.done(); }
});

test("a forged taint row over the data socket does not let a process read a derived copy raw, and folds as `secret` (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    const session = "derived";
    const copy = join(r.dir, "copy.txt");
    writeFileSync(copy, "token=ATTEST_CANARY_0\n");
    // a real holder (the guard's report) writes a copy: the copy is derived from x.txt
    assert.equal((await r.guard.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "dv-mytool-1", ancestorKeys: ["dv-agent-0"], session })).verdict, "raw");
    const labeled = await r.guard.labelWrittenPathTainted({ path: copy, procKey: "dv-mytool-1", session });
    assert.equal(labeled.labeled, true, labeled.reason);
    // a program of the agent claims to hold x.txt already, at `public`
    await r.agent.taintProcessSecret({ procKey: "dv-py-2", path: r.secret, level: "public", app: "mytool", session });
    const open = await r.guard.decideSecretOpen({ path: copy, exe: "/usr/bin/python3", isAgent: false, exeSystem: true, openerEnv: [], procKey: "dv-py-2", ancestorKeys: ["dv-agent-0"], session });
    // MASTER: raw ("a copy of secrets this process already holds")
    assert.notEqual(open.verdict, "raw", JSON.stringify(open));
    // the claimed row still taints (tightening is anyone's), and folds as `secret`
    await r.proxy.execGate({ command: "python3 p.py", sessionKey: session, callId: "toolu_dv" });
    await r.guard.recordExecRoot({ procKey: "dv-py-2", ancestors: ["dv-agent-0"], argv: shell("python3 p.py"), session, callRoot: true });
    const t = await r.proxy.callTaint("toolu_dv", { command: "python3 p.py", session });
    assert.equal(t.rule, "secret", JSON.stringify(t));
    assert.ok(t.files.includes(r.secret), JSON.stringify(t));
  } finally { await r.done(); }
});

test("decideProtectedWrite over the data socket files no Inbox row and is refused (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    const target = join(r.dir, ".bashrc");
    const forged = await r.agent.decideProtectedWrite({ path: target, exe: "/usr/bin/vim", sha256: "e".repeat(64), exeSystem: true, openerEnv: [], procKey: "pw-1", label: "a shell startup file", session: "pw" });
    // MASTER: ask, with a pending row whose text omits "The agent could have written this program"
    assert.equal(forged.verdict, "deny", JSON.stringify(forged));
    assert.equal((await r.proxy.egressApprovals("pending")).length, 0, "no row in front of the human");
    // the guard's report is held for the human, as before
    const real = await r.guard.decideProtectedWrite({ path: target, exe: "/usr/bin/vim", sha256: "e".repeat(64), exeSystem: true, openerEnv: [], procKey: "pw-2", label: "a shell startup file", session: "pw" });
    assert.equal(real.verdict, "ask");
    assert.equal((await r.proxy.egressApprovals("pending")).length, 1);
  } finally { await r.done(); }
});

test("a guard that cannot authenticate (an older binary on the data socket) fails closed: its raw opens are twins and the proxy's calls are masked while the session holds a read (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    const session = "old";
    // the old guard reports on the data socket: every record is a claim
    await r.agent.recordExecRoot({ procKey: "old-sh-1", ancestors: ["old-agent-0"], argv: shell(READ), session, callRoot: true });
    const d = await r.agent.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "old-mytool-2", ancestorKeys: ["old-sub-1", "old-sh-1", "old-agent-0"], session });
    assert.equal(d.verdict, "twin", JSON.stringify(d));
    assert.match(d.reason, /unauthenticated/);
    // a reader the human-socket guard let read raw earlier in the session
    assert.equal((await r.guard.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "old-mytool-3", ancestorKeys: ["old-agent-0"], session })).verdict, "raw");
    // an old proxy asks on the data socket: no binding, the session's level
    await r.agent.execGate({ command: CLEAN, sessionKey: session, callId: "toolu_old" });
    await tick();
    await r.guard.recordExecRoot({ procKey: "old-sh-4", ancestors: ["old-agent-0"], argv: shell(CLEAN), session, callRoot: true });
    const t = await r.agent.callTaint("toolu_old", { command: CLEAN, session });
    assert.equal(t.level, "no-model", JSON.stringify(t));
    assert.equal(t.evidence, "session");
    // the same ask from the human socket still binds nothing: the call's
    // command was never recorded on the human plane (the D9 follow-up: a
    // call is bound by the command the proxy recorded, never by the echoed
    // text), so it stays masked at the session's level
    const unbound = await r.proxy.callTaint("toolu_old", { command: CLEAN, session });
    assert.equal(unbound.evidence, "session", JSON.stringify(unbound));
    assert.equal(unbound.level, "no-model");
  } finally { await r.done(); }
});

test("the attested ops are the ones plan 13 §3 D9's table lists; only the data socket is unattested", () => {
  assert.deepEqual([...ATTESTED_REPORT_OPS].sort(), [
    "agentReceiptTaint", "callTaint", "decideProtectedWrite", "decideSecretOpen", "execGate", "labelWrittenPathTainted",
    "processLineage", "recordAgentFlow", "recordCallCommand", "recordEgressRefusal", "recordExecRoot", "recordProcessFlow", "taintProcessSecret", "taintedProcessBindings",
  ]);
  assert.equal(attestedChannel("data"), false);
  assert.equal(attestedChannel("human"), true);
  assert.equal(attestedChannel("admin"), true, "an in-process dispatch (admin by default) is the arbiter's own caller");
});

test("hello names the channel it answers on (the guard checks it reports where it is believed)", async () => {
  const r = await rig();
  try {
    assert.equal((await r.agent.hello()).channel, "data");
    assert.equal((await r.guard.hello()).channel, "human");
  } finally { await r.done(); }
});

// Plan 13 D7's lineage residual (closed 2026-10-02): `( read -t 2; mytool x ) &`
// once the call's shell returned. The subshell, re-parented to the guard,
// acts only after its parent exited: mytool's chain stops at it, and no edge
// links it to the call. The guard names the orphan root; the arbiter folds
// its tree into every call relayed no later than it was first seen.
test("D7 orphan root over the wire: a reader under an orphaned subshell folds into the call relayed before it, masked; a later call stays raw; a data-socket report only widens (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    const session = "orphan";
    const BG = "( read -t 2 <&-; mytool ./x.tx? | od -An -tx1 ) &";
    await r.proxy.execGate({ command: BG, sessionKey: session, callId: "toolu_o_bg" });
    await r.guard.recordExecRoot({ procKey: "or-sh-1", ancestors: ["or-agent-0"], argv: shell(BG), session, callRoot: true });
    await tick();
    // the shell returned; its subshell or-sub-2 now has the guard as parent
    // (the chain stops below the guard), and only then runs mytool
    await r.guard.recordExecRoot({ procKey: "or-mytool-3", ancestors: ["or-sub-2"], argv: ["mytool", "./x.txt"], session, orphanRoot: "or-sub-2" });
    const d = await r.guard.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "or-mytool-3", parentKey: "or-sub-2", ancestorKeys: ["or-sub-2"], orphanRoot: "or-sub-2", session });
    assert.equal(d.verdict, "raw", d.reason);
    await tick();
    await r.proxy.execGate({ command: CLEAN, sessionKey: session, callId: "toolu_o_later" });
    await r.guard.recordExecRoot({ procKey: "or-sh-4", ancestors: ["or-agent-0"], argv: shell(CLEAN), session, callRoot: true });
    await tick();
    const bg = await r.proxy.callTaint("toolu_o_bg", { command: BG, session });
    // MASTER: bound exact to or-sh-1, whose recorded tree read nothing: level null (raw)
    assert.equal(bg.level, "no-model", `CONFIDENTIALITY: the orphan's reader folds into its call: ${JSON.stringify(bg)}`);
    assert.equal(bg.evidence, "tree");
    assert.equal(bg.root, "or-sh-1");
    const later = await r.proxy.callTaint("toolu_o_later", { command: CLEAN, session });
    assert.equal(later.level, null, `utility: a call relayed after the orphan was seen is raw: ${JSON.stringify(later)}`);
    // a data-socket report of an orphan root is a claim: it only widens
    const s2 = "orphan-claim";
    await r.proxy.execGate({ command: CLEAN, sessionKey: s2, callId: "toolu_o_c" });
    await r.guard.recordExecRoot({ procKey: "oc-sh-1", ancestors: ["oc-agent-0"], argv: shell(CLEAN), session: s2, callRoot: true });
    await tick();
    await r.agent.recordExecRoot({ procKey: "oc-x-2", ancestors: ["oc-y-3"], argv: ["true"], session: s2, orphanRoot: "oc-y-3" });
    await r.guard.taintProcessSecret({ procKey: "oc-y-3", path: r.secret, level: "no-model", app: "mytool", session: s2 });
    assert.equal((await r.proxy.callTaint("toolu_o_c", { command: CLEAN, session: s2 })).level, "no-model", "a claimed orphan root widens the fold");
  } finally { await r.done(); }
});
