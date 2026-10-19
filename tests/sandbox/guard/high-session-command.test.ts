/**
 * high-session-command — under the REAL guard, a HIGH session's command runs
 * as a holder of what the session read (confidentiality.md §4, "What Allow
 * once means for a command", 2026-10-11).
 *
 *   the real mandu-net-guard (seccomp user notification, no root) around an
 *   "agent" process (a copy of node, the launch's `agentExe`) that runs each
 *   command as an agent does (`bash -c <command>`, the agent's own child:
 *   the call root), in `secrets`, against a real ArbiterServer. The session
 *   read a memo into the model's context (`declassify_symbol`), the memo
 *   bound to one local listener (A) and not another (B).
 *
 * The oracle: in the HIGH session the command reaches A and is refused at B,
 * and the file it writes carries a derived label at the memo's level (the
 * next session reads it as secret). The control: the same command in a
 * session that read nothing reaches both and writes an unlabeled file. The
 * guard announces itself (`guardAttach`), so the command card says an
 * allowed run is held. SKIPs where the guard is not built or the kernel lacks
 * seccomp user notification.
 *
 * A held command's refused connection (2026-10-12): the refusal at B files
 * the session's own question (`session-net:<session>` × B's address); after
 * Allow once the retry, a new command, connects to B and sends on that
 * connection (sendmsg, judged by the socket's peer); the third try is
 * refused again.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import net from "node:net";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { agentNodeCopy, pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const skip = process.platform !== "linux" ? "Linux only" : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)" : false;

/** The agent: each command as an agent runs it, its own child. */
const AGENT = `import { spawnSync } from "node:child_process";
const cfg = JSON.parse(process.argv[2]);
const r = spawnSync("bash", ["-c", cfg.command], { encoding: "utf8", cwd: cfg.cwd });
process.stdout.write("AGENT_OUT " + JSON.stringify((r.stdout ?? "") + (r.stderr ?? "")) + "\\n");
`;

function runGuarded(argv: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; status: number | null }> {
  return new Promise((ok) => {
    const child = spawn(GUARD.path!, ["--allow", "127.0.0.0/8:*", "--", ...argv], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => (stdout += String(c)));
    child.stderr.on("data", (c) => (stderr += String(c)));
    const timer = setTimeout(() => child.kill("SIGKILL"), 120_000);
    child.on("close", (status) => { clearTimeout(timer); ok({ stdout, stderr, status }); });
  });
}

function listener(): Promise<{ port: number; close: () => void }> {
  return new Promise((ok) => {
    const s = net.createServer((c) => { c.on("error", () => {}); c.end("hello\n"); });
    s.listen(0, "127.0.0.1", () => ok({ port: (s.address() as net.AddressInfo).port, close: () => s.close() }));
  });
}

const cannotAttach = (stderr: string): boolean => /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(stderr);

function hasPython3(): boolean {
  return spawnSync("python3", ["-c", "pass"], { stdio: "ignore" }).status === 0;
}

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("a HIGH session's command is a holder of what the session read: the bound listener answers, the unbound one is refused, its file is labeled; a low session's is free (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-high-cmd-")));
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const work = join(tmp, "work");
  mkdirSync(work, { recursive: true });
  const A = await listener();
  const B = await listener();
  const sock = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), adminSocketPath: join(tmp, "admin.sock"),
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const client = new ArbiterClient(sock); await client.connect();
  try {
    // The guard needs a registered secret to hold anything (its secrets half).
    const secret = join(work, "x.txt");
    writeFileSync(secret, "token=HIGH_CMD_UNUSED\n");
    const reg = await client.registerSecret({ path: secret, home: tmp });
    const twin = join(tmp, "x.twin");
    writeFileSync(twin, `${reg.symbol}\n`);
    const agentNode = agentNodeCopy(tmp);
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT);

    // The memo, bound to A only, read into the HIGH session's context.
    const memos = join(tmp, "memos");
    await admin.setPathLabel({ path: memos, confidentiality: "any-model", bindings: [`127.0.0.1:${A.port}`] });
    const high = `high-cmd-${process.pid}`;
    const sym = await admin.symbolizeFull({ tool: "Read", value: "Acme pays $4,200,000.", field: "content", origin: join(memos, "q3.md"), integrity: "trusted", sessionKey: high });
    assert.equal((await admin.declassifySymbol({ symbol: sym.symbol, sessionKey: high })).allowed, true);

    const probe = (out: string) =>
      `(exec 3<>/dev/tcp/127.0.0.1/${A.port} && echo A-ok) 2>/dev/null || echo A-refused; ` +
      `(exec 3<>/dev/tcp/127.0.0.1/${B.port} && echo B-ok) 2>/dev/null || echo B-refused; ` +
      `echo derived > ${out}; echo wrote`;
    const run = async (session: string, out: string): Promise<string | null> => {
      const policy = join(tmp, `secret-policy-${session}.json`);
      writeFileSync(policy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: secret, twin, level: "no-model" }] }));
      const r = await runGuarded([agentNode, agentJs, JSON.stringify({ command: probe(out), cwd: work })], {
        ...process.env, HOME: tmp, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: policy, MANDU_SESSION_ID: session,
      });
      const line = r.stdout.split("\n").find((l) => l.startsWith("AGENT_OUT "));
      if (!line && cannotAttach(r.stderr)) return null;
      assert.ok(line, `the agent ran under the guard (status ${r.status}): ${r.stdout}\n${r.stderr}`);
      return JSON.parse(line!.slice("AGENT_OUT ".length)) as string;
    };

    // control: a session that read nothing
    const lowOut = join(work, "low.txt");
    const low = await run(`low-cmd-${process.pid}`, lowOut);
    if (low === null) { t.skip("the guard cannot attach here"); return; }
    assert.match(low, /A-ok/);
    assert.match(low, /B-ok/, "a session that read nothing is free");
    const lowLabel = await admin.symbolizeFull({ tool: "Read", value: "derived\n", field: "content", origin: lowOut, integrity: "trusted", sessionKey: "next-low" });
    assert.equal(lowLabel.confidentiality, "public", "a low session's file is not labeled");

    // the HIGH session
    const highOut = join(work, "high.txt");
    const got = await run(high, highOut);
    assert.ok(got !== null);
    assert.match(got!, /A-ok/, `the bound listener answers: ${got}`);
    assert.match(got!, /B-refused/, `CONFIDENTIALITY: a HIGH session's command reached an unbound listener: ${got}`);
    assert.match(got!, /wrote/);
    const next = await admin.symbolizeFull({ tool: "Read", value: "derived\n", field: "content", origin: highOut, integrity: "trusted", sessionKey: "next-high" });
    assert.equal(next.confidentiality, "any-model", "the HIGH session's file is labeled at the memo's level: the next session reads it as secret");

    // the guard announced itself: a HIGH session's command card says an allowed run is held
    const human = new ArbiterClient(join(tmp, "human", "h.sock")); await human.connect();
    const ask = await human.execGate({ command: "echo hi", sessionKey: high });
    human.close();
    const row = (await admin.egressApprovals()).find((a) => a.id === ask.approvalId) as { sessionConfined?: boolean } | undefined;
    assert.equal(row?.sessionConfined, true, JSON.stringify(row));
  } finally {
    A.close(); B.close();
    admin.close(); client.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

// confidentiality.md §4, "A held command's refused connection" (2026-10-12).
test("a held command refused at an unbound listener asks the session's question; Allow once lets the retry's connection (and its own sends) through; the third try is refused (secrets axes)", { skip: skip || (!hasPython3() ? "python3 not installed" : false), timeout: 300_000 }, async (t) => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-held-ask-")));
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const work = join(tmp, "work");
  mkdirSync(work, { recursive: true });
  const A = await listener();
  const B = await listener();
  const sock = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), adminSocketPath: join(tmp, "admin.sock"),
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const client = new ArbiterClient(sock); await client.connect();
  try {
    const secret = join(work, "x.txt");
    writeFileSync(secret, "token=HELD_ASK_UNUSED\n");
    const reg = await client.registerSecret({ path: secret, home: tmp });
    const twin = join(tmp, "x.twin");
    writeFileSync(twin, `${reg.symbol}\n`);
    const agentNode = agentNodeCopy(tmp);
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT);
    const memos = join(tmp, "memos");
    await admin.setPathLabel({ path: memos, confidentiality: "any-model", bindings: [`127.0.0.1:${A.port}`] });
    const session = `held-ask-${process.pid}`;
    const sym = await admin.symbolizeFull({ tool: "Read", value: "Acme pays $4,200,000.", field: "content", origin: join(memos, "q3.md"), integrity: "trusted", sessionKey: session });
    assert.equal((await admin.declassifySymbol({ symbol: sym.symbol, sessionKey: session })).allowed, true);

    // The command connects to B (unbound) and SENDS on the connection with
    // sendmsg, which the guard judges by the socket's peer.
    const probe = `python3 -c "import socket; s = socket.create_connection(('127.0.0.1', ${B.port}), timeout=5); s.sendmsg([b'hi']); print('B-ok ' + s.recv(16).decode().strip())" 2>/dev/null || echo B-refused`;
    const policy = join(tmp, "secret-policy.json");
    writeFileSync(policy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: secret, twin, level: "no-model" }] }));
    const run = async (): Promise<string | null> => {
      const r = await runGuarded([agentNode, agentJs, JSON.stringify({ command: probe, cwd: work })], {
        ...process.env, HOME: tmp, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: policy, MANDU_SESSION_ID: session,
      });
      const line = r.stdout.split("\n").find((l) => l.startsWith("AGENT_OUT "));
      if (!line && cannotAttach(r.stderr)) return null;
      assert.ok(line, `the agent ran under the guard (status ${r.status}): ${r.stdout}\n${r.stderr}`);
      return JSON.parse(line!.slice("AGENT_OUT ".length)) as string;
    };
    const rows = async () => (await admin.egressApprovals()).filter((a) => a.symbol === `session-net:${session}`);

    // the first try: refused, and the user asked (the session's question, keyed by the address)
    const first = await run();
    if (first === null) { t.skip("the guard cannot attach here"); return; }
    assert.match(first, /B-refused/, `CONFIDENTIALITY: a held command reached an unbound listener unasked: ${first}`);
    const [row] = await rows();
    assert.ok(row, `the refusal filed the session's question: ${JSON.stringify(await admin.egressApprovals())}`);
    assert.equal(row!.destination, `127.0.0.1:${B.port}`);
    assert.equal(row!.status, "pending");
    assert.equal((row as { sessionHeld?: boolean }).sessionHeld, true);
    assert.ok(!(await admin.egressApprovals()).some((a) => a.symbol.startsWith("holder-send:")), "no holder's send question for an address");

    // Allow once: the retry, a new command, connects and sends on its connection
    await admin.resolveEgressApproval(row!.id, true, "once");
    const second = await run();
    assert.match(second!, /B-ok hello/, `the retry the user allowed connects and its own sends go: ${second}`);

    // the third try: the answer was one connection
    const third = await run();
    assert.match(third!, /B-refused/, `CONFIDENTIALITY: an Allow once admitted a second connection: ${third}`);
    const after = await rows();
    assert.equal(after.length, 1, "the same row");
    assert.equal(after[0]!.status, "pending", "a fresh question");
  } finally {
    A.close(); B.close();
    admin.close(); client.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
