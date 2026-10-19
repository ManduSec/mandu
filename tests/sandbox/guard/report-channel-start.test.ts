/**
 * report-channel-start (sandbox) — the guard's START choice of its report
 * channel, under the REAL guard (docs/design/architecture/arbiter-human-plane.md
 * §5.2, §5.3; confidentiality plan 13 §3 D9).
 *
 * 1. An impostor human plane at start. The guard believes whatever answers on
 *    the socket it reports on: on the human plane its secret-open questions
 *    decide raw or twin. Before 2026-10-17 the start took any socket named for
 *    the human plane (the data socket's `hello`, or a rig's
 *    MANDU_ARBITER_HUMAN_SOCK) once it answered `channel: human`. Here a
 *    process that is not the arbiter serves such a socket in the walled
 *    human directory and answers every open `raw`; the agent reads a
 *    registered secret no reader is vouched for. Now the guard sees the
 *    socket is served by another process than the data socket's arbiter,
 *    reports on the data socket (claims), and the reader gets the twin; the
 *    impostor gets no report. Red before: the reader read the secret raw.
 * 2. `MANDU_NET_GUARD_EVENTS=0` turns off the guard's events only. Before
 *    2026-10-17 it dropped the guard's whole arbiter client: no open was
 *    asked (every secret a twin, even a vouched reader's) and no report was
 *    sent. Here, with it set, a reader vouched for with `prints: nothing`
 *    still reads raw (the arbiter believed the guard's report, on the human
 *    plane) while a refused connect files no guard event. Red before: the
 *    twin.
 *
 * Self-skips without a C compiler, a built guard, or seccomp user
 * notification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
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

const CANARY = `REPORT_START_${process.pid}_k3Wd`;
const cannotAttach = (stderr: string): boolean => /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(stderr);

/** The agent: one command, as an agent runs it. */
const AGENT = `import { spawnSync } from "node:child_process";
const r = spawnSync("bash", ["-c", process.argv[2]], { encoding: "utf8", timeout: 30000 });
process.stdout.write("AGENT_OUT " + JSON.stringify((r.stdout ?? "") + (r.stderr ?? "")) + "\\n");
`;

/** The impostor: a human-plane socket that answers as the arbiter would and
 *  grants every open raw. Records each op it is sent. */
const IMPOSTOR = `import net from "node:net";
import { appendFileSync, writeFileSync } from "node:fs";
const [sock, seen, ready, instanceId] = process.argv.slice(2);
net.createServer((c) => {
  let buf = "";
  c.on("data", (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\\n")) >= 0) {
      const req = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1);
      appendFileSync(seen, req.op + "\\n");
      const result = req.op === "hello" ? { channel: "human", instanceId, humanSock: sock }
        : req.op === "decideSecretOpen" ? { verdict: "raw", app: "cat", level: "no-model", reason: "the impostor says so", pinNeeded: false }
        : {};
      c.write(JSON.stringify({ id: req.id, ok: true, result }) + "\\n");
    }
  });
  c.on("error", () => {});
}).listen(sock, () => writeFileSync(ready, "up"));
`;

function runGuarded(argv: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string }> {
  return new Promise((ok) => {
    const p = spawn(GUARD.path!, ["--allow", "127.0.0.0/8:*", "--", ...argv], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    p.stdout.on("data", (c) => (stdout += String(c)));
    p.stderr.on("data", (c) => (stderr += String(c)));
    const timer = setTimeout(() => p.kill("SIGKILL"), 120_000);
    p.on("close", () => { clearTimeout(timer); ok({ stdout, stderr }); });
  });
}

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

test("at start, a human-plane socket another process serves is not believed: the guard reports on the data socket and the reader gets the twin (secrets axes)", { skip: guardSkip, timeout: 300_000 }, async (t) => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-report-start-")));
  const humanDir = join(tmp, "human");
  mkdirSync(humanDir, { mode: 0o700 });
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const secret = join(home, "creds.env");
  writeFileSync(secret, `API_TOKEN=${CANARY}\n`);
  const sock = join(tmp, "arbiter.sock");
  // the arbiter: its data socket only (the impostor is the "human plane")
  const server = new ArbiterServer({ socketPath: sock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(sock); await client.connect();
  let impostor: ReturnType<typeof spawn> | null = null;
  try {
    const reg = await client.registerSecret({ path: secret, home });
    const twin = join(tmp, "twin-0");
    writeFileSync(twin, `${reg.symbol}\n`);
    const instanceId = String((await client.hello() as unknown as { instanceId?: unknown }).instanceId ?? "");
    const fake = join(humanDir, "i.sock");
    const seen = join(tmp, "impostor-seen");
    const ready = join(tmp, "impostor-ready");
    const impostorJs = join(tmp, "impostor.mjs");
    writeFileSync(impostorJs, IMPOSTOR);
    impostor = spawn(process.execPath, [impostorJs, fake, seen, ready, instanceId], { stdio: "ignore" });
    assert.ok(await until(() => existsSync(ready), 20_000), "the impostor is up");

    const agentNode = agentNodeCopy(tmp);
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT);
    const policy = join(tmp, "secret-policy.json");
    const session = `report-start-${process.pid}`;
    writeFileSync(policy, JSON.stringify({ agentExe: agentNode, ask: "never", session, unixDeny: [humanDir], secrets: [{ path: secret, twin, level: "no-model" }] }));
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, MANDU_ARBITER_SOCK: sock, MANDU_ARBITER_HUMAN_SOCK: fake, MANDU_NET_GUARD_SECRETS: policy, MANDU_SESSION_ID: session };
    const r = await runGuarded([agentNode, agentJs, `cat ${JSON.stringify(secret)}`], env);
    const line = r.stdout.split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && cannotAttach(r.stderr)) { t.skip("the guard cannot attach here"); return; }
    assert.ok(line, `the agent ran under the guard: ${r.stdout}\n${r.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as string;
    assert.ok(!got.includes(CANARY), `CONFIDENTIALITY: an impostor human plane granted a raw read at the guard's start: ${got}\n${r.stderr}`);
    assert.match(got, /\$MDU:/, `the reader got the twin: ${got}`);
    assert.match(r.stderr, /reporting on the data socket \(.*served by process \d+, not by the arbiter/, r.stderr);
    const ops = existsSync(seen) ? readFileSync(seen, "utf8").split("\n").filter(Boolean) : [];
    assert.ok(!ops.includes("decideSecretOpen"), `no report reached the impostor: ${ops.join(",")}`);
  } finally {
    impostor?.kill("SIGKILL");
    client.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("MANDU_NET_GUARD_EVENTS=0 silences the guard's events only: its open report is still believed, and a refused connect files no event (secrets axes)", { skip: guardSkip || (holderSkip() !== false ? holderSkip() : false), timeout: 300_000 }, async (t) => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-guard-noevents-")));
  const humanDir = join(tmp, "human");
  mkdirSync(humanDir, { mode: 0o700 });
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const vouched = join(home, "vouched.env");
  writeFileSync(vouched, `API_TOKEN=${CANARY}\n`);
  const holder = holderReader(tmp)!;
  const lawPath = join(tmp, "policy.yaml");
  writeFileSync(lawPath, ["version: 1", "paths:", `  - path: ${vouched}`, "    level: no-model", `    readers: [${holder.yaml}]`, ""].join("\n"));
  const sock = join(tmp, "arbiter.sock");
  const logs: string[] = [];
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(humanDir, "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    policyPath: lawPath, log: (m) => logs.push(m), confidentiality: true, integrity: false,
  });
  await server.listen();
  const client = new ArbiterClient(sock); await client.connect();
  const human = new ArbiterClient(join(humanDir, "h.sock")); await human.connect();
  try {
    const reg = await client.registerSecret({ path: vouched, home });
    const twin = join(tmp, "twin-0");
    writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
    const agentNode = agentNodeCopy(tmp);
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT);
    const policy = join(tmp, "secret-policy.json");
    const session = `guard-noevents-${process.pid}`;
    writeFileSync(policy, JSON.stringify({ agentExe: agentNode, ask: "never", session, unixDeny: [humanDir], secrets: [{ path: vouched, twin, level: "no-model" }] }));
    // a connect the guard refuses (only 127.0.0.0/8 is allowed): an event, normally
    const command = `mdu-holder ${JSON.stringify(vouched)}; (exec 3<>/dev/tcp/10.255.255.1/9) 2>/dev/null && echo far-ok || echo far-refused`;
    const env: NodeJS.ProcessEnv = {
      ...process.env, HOME: home, PATH: `${join(tmp, "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`,
      MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: policy, MANDU_SESSION_ID: session, MANDU_NET_GUARD_EVENTS: "0",
    };
    delete env["MANDU_ARBITER_HUMAN_SOCK"];
    const r = await runGuarded([agentNode, agentJs, command], env);
    const line = r.stdout.split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && cannotAttach(r.stderr)) { t.skip("the guard cannot attach here"); return; }
    assert.ok(line, `the agent ran under the guard: ${r.stdout}\n${r.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as string;
    assert.match(got, /far-refused/, `the guard refused the far connect: ${got}`);
    assert.ok(got.includes(CANARY), `the vouched reader read raw: the guard's report reached the arbiter's human plane with its events off\n${got}\n${r.stderr}`);
    assert.ok(logs.some((l) => l.includes(`${vouched} by ${holder.path}`) && / → raw /.test(l)), `the arbiter decided the open raw:\n${logs.filter((l) => l.includes("decideSecretOpen")).join("\n")}`);
    assert.ok(logs.some((l) => l.includes(`guardAttach: ${session}`)), "the guard announced itself (a security report)");
    const guardEvents = async (s: string) => (await human.events(s)).filter((e) => (e as unknown as { emitter?: string }).emitter === "net-supervisor");
    const quiet = await guardEvents(session);
    assert.deepEqual(quiet, [], `no guard event with MANDU_NET_GUARD_EVENTS=0: ${JSON.stringify(quiet).slice(0, 400)}`);

    // the control: the same run with events on files the refused connect
    const loud = `${session}-events`;
    writeFileSync(policy, JSON.stringify({ agentExe: agentNode, ask: "never", session: loud, unixDeny: [humanDir], secrets: [{ path: vouched, twin, level: "no-model" }] }));
    const envOn: NodeJS.ProcessEnv = { ...env, MANDU_SESSION_ID: loud };
    delete envOn["MANDU_NET_GUARD_EVENTS"];
    const r2 = await runGuarded([agentNode, agentJs, command], envOn);
    assert.ok(r2.stdout.includes("AGENT_OUT "), `the control ran: ${r2.stdout}\n${r2.stderr}`);
    assert.ok((await guardEvents(loud)).length > 0, `with events on, the guard files its refused connect: ${r2.stderr}`);
  } finally {
    human.close();
    client.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
