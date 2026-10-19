/**
 * report-channel-late (sandbox) — a guard that started with no human plane
 * moves its reports there when it comes up (docs/design/architecture/
 * arbiter-human-plane.md §5.2; confidentiality plan 13 §3 D9).
 *
 * The guard reports on the arbiter's human-plane socket, the one channel the
 * arbiter believes its reports on; on the data socket each report is a claim
 * (every open of a registered secret gets its twin, every protected write is
 * refused). Before this change a guard that found no human plane at its start
 * (the arbiter down, restarting, or naming none) stayed on the data socket
 * for the whole session.
 *
 * 1. The move. Arbiter A serves the data socket only (no human plane); the
 *    agent starts under the REAL guard, which says it reports on the data
 *    socket, and runs `mdu-holder` (tests/lib/holder-reader.c, the reader the
 *    file's policy vouches for with `prints: nothing`) on the file: a twin
 *    (A took the open as a claim). A stops; B starts on the same data
 *    socket, DB and policy, with its human socket in the directory the
 *    guard walls off (`unixDeny`). The guard finds it (the data socket's
 *    `hello`, the directory, the same listening process, outside its tree),
 *    moves, and announces itself there (`guardAttach`). The agent's second
 *    run reads the file raw: B believed the report. The first run's answer
 *    stays the twin it was. Red before: the second run is a twin too, and
 *    the guard never says it moved.
 * 2. A guard that never gets a human plane (the claims-only guard): a HIGH
 *    session's command is still a holder of what the session read, so its
 *    connection to a listener the session's data is not bound to is refused
 *    and its file is labeled. Red before: `sessionExecRoot` answered `holder:
 *    false` on the data socket, and the command reached the unbound listener.
 *
 * Self-skips without a C compiler, a built guard, or seccomp user
 * notification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import net from "node:net";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { agentNodeCopy, pickGuard } from "../../lib/native-guard.js";
import { holderReader, holderSkip } from "../../lib/holder-reader.js";
import { stateAxes } from "../../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const guardSkip = process.platform !== "linux" ? "Linux only" : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)" : false;
const skip = guardSkip || (holderSkip() !== false ? holderSkip() : false);

const CANARY = `REPORT_LATE_${process.pid}_x7Qe`;
const cannotAttach = (stderr: string): boolean => /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(stderr);

/** The "agent": runs its command once per go file (GO_F.1, GO_F.2, …), each
 *  run's output on its own line. */
const PHASED_AGENT = `import { spawnSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
writeFileSync(process.env.READY_F, "up");
for (let n = 1; n <= Number(process.env.RUNS); n++) {
  const deadline = Date.now() + 180000;
  while (!existsSync(process.env.GO_F + "." + n)) {
    if (Date.now() > deadline) { process.stdout.write("AGENT_OUT_" + n + " {\\"err\\":\\"no go\\"}\\n"); process.exit(3); }
    spawnSync("sleep", ["0.05"]);
  }
  const r = spawnSync("bash", ["-c", process.argv[2]], { encoding: "utf8", timeout: 30000 });
  process.stdout.write("AGENT_OUT_" + n + " " + JSON.stringify({ out: (r.stdout ?? "") + (r.stderr ?? "") }) + "\\n");
}
`;

async function until(cond: () => boolean, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > deadline) return false;
    await new Promise((r) => setTimeout(r, 50));
  }
  return true;
}

test("the guard under test is built from the current sources", { skip: guardSkip }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("a guard that started with no human plane moves to it when it comes up: its next report is believed, its earlier one stays a claim (secrets axes)", { skip, timeout: 400_000 }, async (t) => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-report-late-")));
  const humanDir = join(tmp, "human");
  mkdirSync(humanDir, { mode: 0o700 });
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const vouched = join(home, "vouched.env");
  writeFileSync(vouched, `API_TOKEN=${CANARY}\n`);
  const holder = holderReader(tmp)!;
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, ["version: 1", "paths:", `  - path: ${vouched}`, "    level: no-model", `    readers: [${holder.yaml}]`, ""].join("\n"));
  const sock = join(tmp, "arbiter.sock");
  const logsA: string[] = [];
  const logsB: string[] = [];
  const arbiter = (human: string | null, logs: string[]) => new ArbiterServer({
    socketPath: sock,
    ...(human ? { humanSocketPath: join(humanDir, human) } : {}),
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy,
    log: (m) => logs.push(m), confidentiality: true, integrity: false,
  });
  let a: ArbiterServer | null = arbiter(null, logsA); // an arbiter with no human plane
  let b: ArbiterServer | null = null;
  let child: ReturnType<typeof spawn> | null = null;
  try {
    await a.listen();
    const session = `report-late-${process.pid}`;
    const register = async (): Promise<string> => {
      const c = new ArbiterClient(sock);
      try {
        const reg = await c.registerSecret({ path: vouched, home });
        assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
        return typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`;
      } finally {
        c.close();
      }
    };
    const twin = join(tmp, "twin-0");
    writeFileSync(twin, await register());
    const agentNode = agentNodeCopy(tmp);
    const secretPolicy = join(tmp, "secret-policy.json");
    // unixDeny: the human-plane directory, walled off from the agent's world
    // as a launch's guard policy does (launcher human-plane.ts).
    writeFileSync(secretPolicy, JSON.stringify({ agentExe: agentNode, ask: "never", session, unixDeny: [humanDir], secrets: [{ path: vouched, twin, level: "no-model" }] }));
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, PHASED_AGENT);
    const ready = join(tmp, "ready");
    const go = join(tmp, "go");
    const env: NodeJS.ProcessEnv = {
      ...process.env, HOME: home, VOUCHED_F: vouched, READY_F: ready, GO_F: go, RUNS: "2",
      PATH: `${join(tmp, "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`,
      MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy,
    };
    delete env["MANDU_ARBITER_HUMAN_SOCK"]; // the guard discovers it, as in a launch
    const proc = spawn(GUARD.path!, ["--allow", "127.0.0.0/8:*", "--", agentNode, agentJs, `mdu-holder "$VOUCHED_F"`], { env, stdio: ["ignore", "pipe", "pipe"] });
    child = proc;
    let stdout = "", stderr = "";
    proc.stdout!.on("data", (c) => (stdout += String(c)));
    proc.stderr!.on("data", (c) => (stderr += String(c)));
    const closed = new Promise<number | null>((ok) => proc.on("close", (s) => ok(s)));
    const out = (n: number): string | null => {
      const line = stdout.split("\n").find((l) => l.startsWith(`AGENT_OUT_${n} `));
      return line ? ((JSON.parse(line.slice(`AGENT_OUT_${n} `.length)) as { out?: string }).out ?? "") : null;
    };

    await until(() => existsSync(ready) || proc.exitCode !== null, 120_000);
    if (!existsSync(ready) && cannotAttach(stderr)) {
      t.skip(`the guard cannot attach here: ${stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(existsSync(ready), `the agent started under the guard: ${stdout}\n${stderr}`);
    assert.match(stderr, /reporting on the data socket/, "no human plane at start: the guard reports on the data socket");

    // run 1, on the data socket: the open is a claim, the reader gets the twin
    writeFileSync(`${go}.1`, "");
    assert.ok(await until(() => out(1) !== null, 60_000), `run 1 ran: ${stdout}\n${stderr}`);
    assert.ok(!out(1)!.includes(CANARY), `CONFIDENTIALITY: a claimed open was answered raw: ${out(1)}`);
    assert.ok(logsA.some((l) => l.includes("decideSecretOpen") && /unauthenticated: data socket/.test(l)), `A took the open as a claim:\n${logsA.filter((l) => l.includes("decideSecretOpen")).join("\n")}`);

    // The human plane comes up: A goes, B binds the data socket again and a
    // human socket in the walled directory.
    await a.close();
    a = null;
    b = arbiter("b.sock", logsB);
    await b.listen();
    await register(); // the registration a restarted daemon re-reads (idempotent)
    assert.ok(await until(() => /the human plane is up: reporting on .*b\.sock/.test(stderr), 90_000), `the guard moved to B's human plane:\n${stderr}`);
    assert.ok(logsB.some((l) => l.includes(`guardAttach: ${session}`)), `the guard announced itself on the human plane:\n${logsB.join("\n")}`);

    // run 2, on the human plane: B believes the report, the vouched reader reads raw
    writeFileSync(`${go}.2`, "");
    const timer = setTimeout(() => proc.kill("SIGKILL"), 120_000);
    await closed;
    clearTimeout(timer);
    const opens = logsB.filter((l) => l.includes("decideSecretOpen")).join("\n");
    assert.ok(out(2)?.includes(CANARY), `the vouched reader read the raw file once the guard reported on the human plane\n${out(2)}\n${opens}\n${stderr}`);
    assert.ok(logsB.some((l) => l.includes(`${vouched} by ${holder.path}`) && / → raw /.test(l)), `B decided the open raw:\n${opens}`);
    assert.ok(!logsB.some((l) => /decideSecretOpen.*unauthenticated/.test(l)), `no report reached B's data socket:\n${opens}`);
    assert.ok(!out(1)!.includes(CANARY), "the earlier answer stays what it was");
  } finally {
    child?.kill("SIGKILL");
    await a?.close().catch(() => {});
    await b?.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
});

/** The agent of the HIGH-session case: one command, as an agent runs it. */
const ONE_SHOT_AGENT = `import { spawnSync } from "node:child_process";
const cfg = JSON.parse(process.argv[2]);
const r = spawnSync("bash", ["-c", cfg.command], { encoding: "utf8", cwd: cfg.cwd });
process.stdout.write("AGENT_OUT " + JSON.stringify((r.stdout ?? "") + (r.stderr ?? "")) + "\\n");
`;

function listener(): Promise<{ port: number; close: () => void }> {
  return new Promise((ok) => {
    const s = net.createServer((c) => { c.on("error", () => {}); c.end("hello\n"); });
    s.listen(0, "127.0.0.1", () => ok({ port: (s.address() as net.AddressInfo).port, close: () => s.close() }));
  });
}

test("a guard with no human plane all session: a HIGH session's command is still a holder (the unbound listener refused, its file labeled) (secrets axes)", { skip: guardSkip, timeout: 300_000 }, async (t) => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-claims-guard-")));
  const work = join(tmp, "work");
  mkdirSync(work, { recursive: true });
  const A = await listener();
  const B = await listener();
  const sock = join(tmp, "arbiter.sock");
  // no human socket at all: every report of this guard is a claim
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(tmp, "admin.sock"),
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const client = new ArbiterClient(sock); await client.connect();
  try {
    const secret = join(work, "x.txt");
    writeFileSync(secret, "token=CLAIMS_GUARD_UNUSED\n");
    const reg = await client.registerSecret({ path: secret, home: tmp });
    const twin = join(tmp, "x.twin");
    writeFileSync(twin, `${reg.symbol}\n`);
    const agentNode = agentNodeCopy(tmp);
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, ONE_SHOT_AGENT);
    // the memo, bound to A only, read into the HIGH session's context
    const memos = join(tmp, "memos");
    await admin.setPathLabel({ path: memos, confidentiality: "any-model", bindings: [`127.0.0.1:${A.port}`] });
    const session = `claims-guard-${process.pid}`;
    const sym = await admin.symbolizeFull({ tool: "Read", value: "Acme pays $4,200,000.", field: "content", origin: join(memos, "q3.md"), integrity: "trusted", sessionKey: session });
    assert.equal((await admin.declassifySymbol({ symbol: sym.symbol, sessionKey: session })).allowed, true);

    const outFile = join(work, "high.txt");
    const command =
      `(exec 3<>/dev/tcp/127.0.0.1/${A.port} && echo A-ok) 2>/dev/null || echo A-refused; ` +
      `(exec 3<>/dev/tcp/127.0.0.1/${B.port} && echo B-ok) 2>/dev/null || echo B-refused; ` +
      `echo derived > ${outFile}; echo wrote`;
    const policy = join(tmp, "secret-policy.json");
    writeFileSync(policy, JSON.stringify({ agentExe: agentNode, ask: "never", session, secrets: [{ path: secret, twin, level: "no-model" }] }));
    const r = await new Promise<{ stdout: string; stderr: string }>((ok) => {
      const env: NodeJS.ProcessEnv = { ...process.env, HOME: tmp, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: policy, MANDU_SESSION_ID: session };
      delete env["MANDU_ARBITER_HUMAN_SOCK"];
      const p = spawn(GUARD.path!, ["--allow", "127.0.0.0/8:*", "--", agentNode, agentJs, JSON.stringify({ command, cwd: work })], { env, stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "", stderr = "";
      p.stdout.on("data", (c) => (stdout += String(c)));
      p.stderr.on("data", (c) => (stderr += String(c)));
      const timer = setTimeout(() => p.kill("SIGKILL"), 120_000);
      p.on("close", () => { clearTimeout(timer); ok({ stdout, stderr }); });
    });
    const line = r.stdout.split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && cannotAttach(r.stderr)) { t.skip("the guard cannot attach here"); return; }
    assert.ok(line, `the agent ran under the guard: ${r.stdout}\n${r.stderr}`);
    assert.match(r.stderr, /reporting on the data socket/, "the guard had no human plane");
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as string;
    assert.match(got, /A-ok/, `the bound listener answers: ${got}`);
    assert.match(got, /B-refused/, `CONFIDENTIALITY: a claims-only guard let a HIGH session's command reach an unbound listener: ${got}`);
    assert.match(got, /wrote/);
    const next = await admin.symbolizeFull({ tool: "Read", value: "derived\n", field: "content", origin: outFile, integrity: "trusted", sessionKey: "next-session" });
    assert.equal(next.confidentiality, "any-model", "its file is labeled at the memo's level");
  } finally {
    A.close(); B.close();
    admin.close(); client.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
