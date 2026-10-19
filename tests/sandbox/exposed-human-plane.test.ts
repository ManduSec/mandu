/**
 * The human plane's exposure e2e (confidentiality plan 13 D9 leftovers,
 * arbiter-human-plane.md §8, §10), across the REAL components: the
 * launcher's main() in `secrets` mode, a REAL ArbiterServer serving both
 * sockets, and, for the walled leg, the REAL mandu-net-guard. The "agent" is
 * bash + python3.
 *
 *   - Without the guard (`--no-net-guard`: the `gated` posture), with no
 *     store to hide (so no wrap goes up), nothing walls the human socket off:
 *     a program the agent runs connects to it and reports a raw open of its
 *     own copy of `ssh-add` as a system binary. The launch told the arbiter it is
 *     unwalled, so that report is a claim (`twin`) and policy.yaml gains no
 *     pin. (On master `a79ccf98` it was answered raw, and the pin outlived
 *     the launch.) Where the host's wrap does go up, the agent cannot connect
 *     at all; either way no pin.
 *   - With the guard and an unwalled launch begun beside it (§10.1.1), the
 *     launcher (run.ts's human-plane watch) warns by pid and session while
 *     the report is a claim, says when it is believed again, and recaps
 *     after the agent. With the unwalled launch already running, the block
 *     (and the concurrent-launch WARNING) is held below the banner, the
 *     last thing before the agent takes the terminal (packaging.md §5 "Last
 *     before the agent"): by default as one posture line each, whole in the
 *     launch's log.
 *   - With the guard (MANDU_WRITE_PROTECT=0, so the launch is recorded as
 *     unconfined for the caches), the launch tells the arbiter it is walled:
 *     while it runs, a report on the human socket from outside the agent's
 *     world (this test process, standing in for the guard) is still believed.
 *
 * Self-SKIPs without python3, and the walled leg without the guard bin
 * (scripts/build-native.sh).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { launchLogs } from "../../launcher/test/lib/launch-log-read.js";
import { stateAxes } from "../lib/axes.js";
import { pickGuard } from "../lib/native-guard.js";

stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGET = resolve(HERE, "..", "..", "interceptors", "target");
const PICK = pickGuard(TARGET);
const GUARD = PICK.path;
const PY = spawnSync("python3", ["-c", "print(1)"]).status === 0;
const skipAll = process.platform !== "linux" ? "linux only" : !PY ? "python3 is not installed" : false;
const skipGuard = skipAll || (!GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)" : false);

/** A program of the agent: connect to the human socket by path and report a
 *  raw open of its own copy of `ssh-add` (exeSystem claimed). Prints the verdict,
 *  or `errno:<n>` when it cannot connect. */
const FORGER = `import json, socket, sys
s = socket.socket(socket.AF_UNIX)
try:
    s.connect(sys.argv[1])
except OSError as e:
    print("errno:%d" % e.errno); sys.exit(0)
req = {"id": "f1", "op": "decideSecretOpen", "path": sys.argv[2], "exe": sys.argv[3], "sha256": "c" * 64,
       "isAgent": False, "exeSystem": True, "openerEnv": [], "procKey": "forge-1", "session": "exposed"}
s.sendall((json.dumps(req) + "\\n").encode())
buf = b""
while not buf.endswith(b"\\n"):
    chunk = s.recv(65536)
    if not chunk: break
    buf += chunk
r = json.loads(buf.decode())
print(r.get("result", {}).get("verdict", "error:" + str(r.get("error"))))
`;

interface World { dir: string; home: string; sock: string; humanSock: string; secret: string; policy: string; server: ArbiterServer; close: () => Promise<void> }

async function world(): Promise<World> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-exposed-"));
  const home = join(dir, "home");
  mkdirSync(home, { recursive: true });
  const secret = join(dir, "x.txt");
  writeFileSync(secret, "token=EXPOSED_SANDBOX_CANARY\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [ssh-add]\n`);
  const sock = join(dir, "arbiter.sock");
  const humanSock = join(dir, "mandu", "human", "test-instance.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, policyPath: policy,
    dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  return { dir, home, sock, humanSock, secret, policy, server, close: async () => { await server.close(); rmSync(dir, { recursive: true, force: true }); } };
}

/** `lines`: where the launcher's stderr lines land as they are printed (a
 *  test reads what was on screen when the agent started). */
async function launch(w: World, flags: string[], extraEnv: Record<string, string>, script: string, lines: string[] = []): Promise<{ code: number; log: string }> {
  const orig = console.error;
  const saved = { bin: process.env["MANDU_NET_GUARD_BIN"], home: process.env["HOME"], mh: process.env["MANDU_HOME"] };
  try {
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    if (GUARD) process.env["MANDU_NET_GUARD_BIN"] = GUARD;
    process.env["HOME"] = w.home;
    process.env["MANDU_HOME"] = join(w.home, ".mandu");
    const code = await main(
      ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", ...flags, "--", "bash", "-c", script],
      {
        HOME: w.home, PWD: w.dir, MANDU_ARBITER_SOCK: w.sock, PATH: process.env["PATH"],
        MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(w.home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: w.dir,
        MANDU_VERBOSE: "1", ...extraEnv,
      },
    );
    return { code, log: lines.join("\n") };
  } finally {
    console.error = orig;
    for (const [k, v] of [["MANDU_NET_GUARD_BIN", saved.bin], ["HOME", saved.home], ["MANDU_HOME", saved.mh]] as const) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
}

test("gated, no wall: a program the agent runs reaches the human socket, but its forged open is a claim while the launch runs: no raw, no pin", { skip: skipAll, timeout: 120_000 }, async () => {
  const w = await world();
  try {
    writeFileSync(join(w.dir, "forge.py"), FORGER);
    const out = join(w.dir, "out");
    const copy = join(w.dir, "ws", "ssh-add");
    const { code, log } = await launch(w, ["--no-net-guard"], {}, `python3 ${w.dir}/forge.py ${w.humanSock} ${w.secret} ${copy} > ${out}`);
    assert.equal(code, 0, log);
    const got = readFileSync(out, "utf8").trim();
    // MASTER: "raw" (and the pin below)
    assert.ok(got === "twin" || /^errno:\d+$/.test(got), `the forged report must not be believed; got ${got}\n${log}`);
    assert.ok(!readFileSync(w.policy, "utf8").includes(copy), `no pin of the agent's copy:\n${readFileSync(w.policy, "utf8")}`);
  } finally { await w.close(); }
});

test("guard, walled (write protection off, so the launch is recorded): the human socket stays believed while it runs", { skip: skipGuard, timeout: 120_000 }, async () => {
  const w = await world();
  const human = new ArbiterClient(w.humanSock);
  try {
    const ready = join(w.dir, "ready");
    const go = join(w.dir, "go");
    const script = `touch ${ready}; for i in $(seq 1 100); do [ -e ${go} ] && break; sleep 0.1; done`;
    const running = launch(w, [], { MANDU_WRITE_PROTECT: "0" }, script);
    for (let i = 0; i < 300 && !existsSync(ready); i++) await new Promise((ok) => setTimeout(ok, 100));
    assert.ok(existsSync(ready), "the agent started");
    const d = await human.decideSecretOpen({ path: w.secret, exe: "/usr/bin/ssh-add", sha256: "d".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "guard-1", session: "walled" });
    writeFileSync(go, "");
    const { code, log } = await running;
    assert.equal(code, 0, log);
    assert.equal(d.verdict, "raw", `a walled launch leaves the human socket believed: ${JSON.stringify(d)}\n${log}`);
  } finally { human.close(); await w.close(); }
});

test("guard, walled, an unwalled launch already runs (§10.1.1): in the default display the WARNING block is the LAST thing the launcher prints before the agent takes the terminal (below the mode line, the dashboard line and the notices), whole; the recap after the agent still names the period", { skip: skipGuard, timeout: 120_000 }, async () => {
  const w = await world();
  const human = new ArbiterClient(w.humanSock);
  const { spawn } = await import("node:child_process");
  const other = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  const lines: string[] = [];
  try {
    // Another launch with no wall (what `mandu --mode off` records), begun BEFORE this one.
    const rec = await human.beginLaunch({ pid: other.pid!, mode: "off", posture: "off", writeProtect: false, humanPlaneWalled: false, sessionId: "sandbox-off-0" });
    const ready = join(w.dir, "ready");
    const go = join(w.dir, "go");
    const script = `touch ${ready}; for i in $(seq 1 300); do [ -e ${go} ] && break; sleep 0.1; done`;
    const logs = launchLogs({ HOME: w.home, MANDU_HOME: join(w.home, ".mandu") });
    const running = launch(w, [], { MANDU_WRITE_PROTECT: "0", MANDU_VERBOSE: "0" }, script, lines);
    for (let i = 0; i < 300 && !existsSync(ready); i++) await new Promise((ok) => setTimeout(ok, 100));
    assert.ok(existsSync(ready), "the agent started");
    // What the terminal held when the agent took it.
    const before = [...lines];
    writeFileSync(go, "");
    const { code, log } = await running;
    assert.equal(code, 0, log);
    // The default display (packaging.md §5, 2026-10-18): the block's marked
    // first line, as one posture line naming the launch by pid and session,
    // is the last thing before the agent; the block is whole in the launch's log.
    const first = before.findIndex((l) => l.startsWith("mandu: WARNING: this session's file guard is not believed: another Mandu launch can reach Mandu's own controls: " +
      `pid ${other.pid} (session sandbox-off-0, mode off)`));
    assert.ok(first >= 0, `the WARNING was printed before the agent started:\n${before.join("\n")}`);
    assert.equal(first, before.length - 1, `it is the last thing before the agent:\n${before.join("\n")}`);
    assert.match(before[first]!, /\(more: `mandu log`\)$/);
    const full = logs.newLines();
    const whole = full.findIndex((l) => l.startsWith("WARNING: mandu: this session's file guard is not believed: another Mandu launch can reach Mandu's own controls: " +
      `pid ${other.pid} (session sandbox-off-0, mode off)`));
    assert.ok(whole >= 0, `the block is in the launch's log:\n${full.join("\n")}`);
    assert.match(full[whole + 3]!, /To fix it: stop that launch, or start it again with its file guard on/, "whole");
    const banner = before.findIndex((l) => /^mandu: secrets mode · .* · (dashboard |no dashboard)/.test(l));
    assert.ok(banner >= 0 && banner < first, `the banner comes before it:\n${before.join("\n")}`);
    // The other WARNING about that launch (it can rewrite this launch's
    // placeholder files) is held the same way: below the banner too.
    const beside = before.findIndex((l) => l.startsWith("mandu: WARNING: 1 other Mandu launch runs without confinement beside this one"));
    assert.ok(beside > banner && beside < first, `the concurrent-launch WARNING is below the banner too:\n${before.join("\n")}`);
    assert.match(log, /during this session its file guard was not believed/, "the recap after the agent stays");
    await human.endLaunch(rec.token);
  } finally { other.kill("SIGKILL"); human.close(); await w.close(); }
});

test("guard, walled, an unwalled launch begins beside it (§10.1.1): the walled launcher warns by pid and session, the guard's report is a claim meanwhile, and it says when it is believed again and recaps after the agent", { skip: skipGuard, timeout: 120_000 }, async () => {
  const w = await world();
  const human = new ArbiterClient(w.humanSock);
  const { spawn } = await import("node:child_process");
  const other = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  try {
    const ready = join(w.dir, "ready");
    const go = join(w.dir, "go");
    const script = `touch ${ready}; for i in $(seq 1 300); do [ -e ${go} ] && break; sleep 0.1; done`;
    const running = launch(w, [], { MANDU_WRITE_PROTECT: "0" }, script);
    for (let i = 0; i < 300 && !existsSync(ready); i++) await new Promise((ok) => setTimeout(ok, 100));
    assert.ok(existsSync(ready), "the agent started");
    // Another launch with no wall (what `mandu --mode off` records), begun after this one.
    const rec = await human.beginLaunch({ pid: other.pid!, mode: "off", posture: "off", writeProtect: false, humanPlaneWalled: false, sessionId: "sandbox-off-1" });
    await new Promise((ok) => setTimeout(ok, 2600)); // one watch interval and some
    const d = await human.decideSecretOpen({ path: w.secret, exe: "/usr/bin/ssh-add", sha256: "d".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "guard-2", session: "walled" });
    await human.endLaunch(rec.token);
    await new Promise((ok) => setTimeout(ok, 2600));
    writeFileSync(go, "");
    const { code, log } = await running;
    assert.equal(code, 0, log);
    assert.equal(d.verdict, "twin", `the masking stays while exposed: ${JSON.stringify(d)}`);
    assert.match(log, new RegExp(`WARNING: mandu: this session's file guard is not believed: another Mandu launch can reach Mandu's own controls: pid ${other.pid} \\(session sandbox-off-1, mode off\\)`), log);
    assert.match(log, /To fix it: stop that launch, or start it again with its file guard on/);
    assert.match(log, /this session's file guard is believed again/);
    assert.match(log, /during this session its file guard was not believed/);
  } finally { other.kill("SIGKILL"); human.close(); await w.close(); }
});
