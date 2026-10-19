/**
 * report-channel-restart (sandbox) — the REAL guard follows an arbiter
 * restart to its new human socket (docs/design/architecture/arbiter-human-plane.md
 * §5.1; confidentiality plan 13 §3 D9).
 *
 * The guard reports on the arbiter's human-plane socket, the one channel the
 * arbiter believes its reports on; on the data socket every report is a
 * claim and every open of a registered secret gets its twin. The human
 * socket's name carries the instance id, so a restarted arbiter listens
 * elsewhere. Before this change the guard's report client kept the launch's
 * path: after a restart every report failed and every open was a twin until
 * the session ended.
 *
 * Here: arbiter A (data `arbiter.sock`, human `human/a.sock`) and a file
 * whose readers name `mdu-holder` with `prints: nothing` (tests/lib/
 * holder-reader.c: a program it vouches for reads it raw). The agent starts
 * under the guard (which chose A's human socket and reported its start-up
 * opens there), then waits. A stops; B starts on the same data socket,
 * symbol DB and policy with its human socket at `human/b.sock`; the agent
 * runs `mdu-holder` on the file. The oracle: the holder read the raw file
 * (B believed the guard's report: it came on B's human plane, re-learned from
 * the data socket's `hello`), B logged the open raw, and no data channel
 * refused a report. Red before: the twin. Self-skips without a C compiler or
 * a built guard.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : holderSkip() !== false ? holderSkip()
  : false;

const CANARY = `REPORT_RESTART_${process.pid}_q4Vz`;

/** The "agent": says it is up, waits for the go file, then runs its command. */
const AGENT_SOURCE = `import { spawnSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
writeFileSync(process.env.READY_F, "up");
const deadline = Date.now() + 120000;
while (!existsSync(process.env.GO_F)) {
  if (Date.now() > deadline) { process.stdout.write("AGENT_OUT {\\"err\\":\\"no go\\"}\\n"); process.exit(3); }
  spawnSync("sleep", ["0.05"]);
}
const r = spawnSync("bash", ["-c", process.argv[2]], { encoding: "utf8", timeout: 30000 });
process.stdout.write("AGENT_OUT " + JSON.stringify({ out: (r.stdout ?? "") + (r.stderr ?? "") }) + "\\n");
`;

function arbiter(tmp: string, human: string, policy: string, logs: string[]): ArbiterServer {
  return new ArbiterServer({
    socketPath: join(tmp, "arbiter.sock"),
    humanSocketPath: join(tmp, "human", human),
    dbPath: join(tmp, "symbols.sqlite"),
    eventDir: join(tmp, "events"),
    policyPath: policy,
    log: (m) => logs.push(m),
    confidentiality: true,
    integrity: false,
  });
}

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("an arbiter restarted on a new human socket: the guard's reports reach it, and the vouched reader reads raw (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-report-restart-"));
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
  let a: ArbiterServer | null = arbiter(tmp, "a.sock", policy, logsA);
  let b: ArbiterServer | null = null;
  let child: ReturnType<typeof spawn> | null = null;
  try {
    await a.listen();
    const session = `report-restart-${process.pid}`;
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
    const secretPolicy = join(tmp, "secret-policy.json");
    const agentNode = agentNodeCopy(tmp);
    writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: vouched, twin, level: "no-model" }] }));
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT_SOURCE);
    const ready = join(tmp, "ready");
    const go = join(tmp, "go");
    const env: NodeJS.ProcessEnv = {
      ...process.env, HOME: home, VOUCHED_F: vouched, READY_F: ready, GO_F: go,
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

    const deadline = Date.now() + 120_000;
    while (!existsSync(ready)) {
      if (Date.now() > deadline || proc.exitCode !== null) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    if (!existsSync(ready) && /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(stderr)) {
      t.skip(`the guard cannot attach here: ${stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(existsSync(ready), `the agent started under the guard: ${stdout}\n${stderr}`);
    assert.doesNotMatch(stderr, /reporting on the data socket/, "the guard chose A's human plane");

    // The restart: A goes, B comes up on the same data socket, DB and policy,
    // its human socket elsewhere.
    await a.close();
    a = null;
    await new Promise((r) => setTimeout(r, 300));
    assert.ok(!existsSync(join(tmp, "human", "a.sock")), "A's human socket is gone");
    b = arbiter(tmp, "b.sock", policy, logsB);
    await b.listen();
    await register(); // the registration a restarted daemon re-reads (idempotent)
    writeFileSync(go, "");

    const timer = setTimeout(() => proc.kill("SIGKILL"), 120_000);
    await closed;
    clearTimeout(timer);
    const line = stdout.split("\n").find((l) => l.startsWith("AGENT_OUT "));
    assert.ok(line, `the agent ran (stdout ${stdout})\n${stderr}`);
    const got = (JSON.parse(line!.slice("AGENT_OUT ".length)) as { out?: string }).out ?? "";
    const opens = logsB.filter((l) => l.includes("decideSecretOpen")).join("\n");
    assert.ok(got.includes(CANARY), `the vouched reader read the raw file after the restart: the report reached B's human plane\n${got}\n${opens}\n${stderr}`);
    assert.ok(logsB.some((l) => l.includes(`${vouched} by ${holder.path}`) && / → raw /.test(l)), `B decided the open raw:\n${opens}`);
    assert.ok(![...logsA, ...logsB].some((l) => /refused on data channel: (decideSecretOpen|desymbolize|resolve)/.test(l)), "no report or original-returning op went to a data socket");
  } finally {
    child?.kill("SIGKILL");
    await a?.close().catch(() => {});
    await b?.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
});
