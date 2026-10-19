/**
 * holder-accept-scenario.fixture — this side of holder-accept.test.ts
 * (exec-routing.md §7.5 gap (a), "An inbound connection to a holder"), run
 * inside tests/lib/netns.ts's namespaces. "The other machine" runs the
 * test's connect agent (ACCEPT_AGENT_PY's `control` mode, on
 * PEER_ADDR:PEER_CTRL): asked over a control connection, it connects to an
 * address of this side FROM one of its two addresses (10.77.0.2, which the
 * bound secret names, or 203.0.113.9, which nothing names) and answers what
 * it read.
 *
 * It runs the REAL launcher (its default-on hardening: the guard, the
 * secret twins, the Landlock port wrap, the net-proxy) in `secrets` mode
 * against a private arbiter whose policy.yaml labels two project files
 * `no-model`, each read by python3 running the stdlib's base64.py (an R5
 * script pin, tests/lib/holder-reader.ts `stdlibBase64`); one of them is
 * bound to 10.77.0.2. The agent is `/bin/sh` starting three python3
 * servers (not node: a node dev server here was flaky under the peer's
 * load, the reason the gap had only a kernel oracle until 2026-10-18):
 *
 *   plain    reads nothing: a NON-holder;
 *   unbound  holds the unbound file, through the reader's pipe (plan 13
 *            D2: the reader's bytes taint the process reading its pipe);
 *   bound    holds the bound file the same way.
 *
 * Each listens on 0.0.0.0 and on a Unix socket, marks itself ready, and
 * then accepts exactly four TCP connections and one Unix connection,
 * writing what each accept returned ("ok", or "e<errno>": a refused one
 * answers ECONNABORTED, e103) and answering every connection it gets with
 * what it holds (the file's bytes) or its name. The fixture, outside the
 * agent's tree, waits for every mark (no sleeps), then drives the
 * connections ONE AT A TIME, each waiting for its own end, so a server's
 * accepts come in the order the legs ran:
 *
 *   outside   from 203.0.113.9 (the other machine, unbound)
 *   inside    from 10.77.0.2   (the other machine, the bound host)
 *   loopback  127.0.0.1 -> 127.0.0.1
 *   own       10.77.0.1 -> 10.77.0.1 (the connection's own local address)
 *   unix      the server's Unix socket
 *
 * Prints one JSON line: the launch's exit code and output tail, every
 * leg's client answer, every server's accept record, and the canaries.
 * env: PEER_ADDR, PEER_CTRL, SELF_ADDR, OUTSIDE_ADDR, ACCEPT_AGENT_PY.
 * PROVENANCE: NEW Mandu test code.
 */
import { execFile } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { promisify } from "node:util";

import { runLauncher, withStack } from "../lib/launcher-live.js";
import { stdlibBase64 } from "../lib/holder-reader.js";

const run = promisify(execFile);
const env = (k: string): string => {
  const v = process.env[k];
  if (!v) throw new Error(`${k} is required`);
  return v;
};
const PEER = env("PEER_ADDR");
const PEER_CTRL = env("PEER_CTRL");
const SELF = env("SELF_ADDR");
const OUTSIDE = env("OUTSIDE_ADDR");
const AGENT_PY = env("ACCEPT_AGENT_PY");
/** The reader: python3 running the stdlib's base64.py. */
const B64 = stdlibBase64();
if (B64 === null) throw new Error("python3 with a stdlib base64.py is required (the secrets' reader)");

const alnum = (n: number): string => {
  const abc = "abcdefghijklmnopqrstuvwxyz0123456789";
  return [...randomBytes(n)].map((b) => abc[b % abc.length]).join("");
};
const UNBOUND_CANARY = `acceptunbound${alnum(20)}`;
const BOUND_CANARY = `acceptbound${alnum(20)}`;

/** A server of the agent's tree. argv: mode (holder|plain), the file it
 *  holds through its reader ("-" for none), base64.py, the work dir, its
 *  name, its TCP port (one the launch's `--landlock-net-bind` lists, as a
 *  dev server's port is: the Landlock TCP wrap refuses a bind to any other,
 *  port 0 included). Reads first (no socket open yet), then listens, marks ready
 *  (atomically: the mark is whole when it exists), accepts four TCP
 *  connections and one Unix connection, records each, exits. */
const SERVER = String.raw`
import base64, json, os, socket, subprocess, sys
mode, secret, b64, d, name, port = sys.argv[1:7]
answer = ("LIVE-" + name).encode()
if mode == "holder":
    r = subprocess.run(["/usr/bin/python3", "-I", b64, secret], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode != 0:
        open(os.path.join(d, name + ".fail"), "w").write("reader exit %d: %s" % (r.returncode, r.stderr[:300]))
        sys.exit(4)
    answer = base64.b64decode(r.stdout)
t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
t.bind(("0.0.0.0", int(port))); t.listen(16)
upath = os.path.join(d, name + ".sock")
u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); u.bind(upath); u.listen(4)
t.settimeout(120); u.settimeout(120)
tmp = os.path.join(d, name + ".ready.tmp")
open(tmp, "w").write(json.dumps({"port": t.getsockname()[1], "unix": upath}))
os.rename(tmp, os.path.join(d, name + ".ready"))
seen = []
def take(l, tag):
    try:
        c, _ = l.accept()
    except socket.timeout:
        seen.append(tag + "timeout"); return False
    except OSError as e:
        seen.append(tag + "e%d" % e.errno); return True
    try:
        c.sendall(answer)
    finally:
        c.close()
    seen.append(tag + "ok"); return True
while len(seen) < 4 and take(t, ""):
    pass
take(u, "unix-")
open(os.path.join(d, name + ".seen"), "w").write(json.dumps(seen))
`;

/** One leg, the fixture's half: through the peer's control connection
 *  ("the other machine" connects), or from here. */
async function leg(how: string[]): Promise<string> {
  try {
    const r = await run("/usr/bin/python3", ["-I", AGENT_PY, ...how], { timeout: 60_000 });
    return r.stdout.trim();
  } catch (e) {
    const x = e as { stdout?: string; stderr?: string; message: string };
    return `client-failed: ${(x.stdout ?? "").trim()} ${(x.stderr ?? x.message).trim().slice(0, 300)}`;
  }
}

async function waitFor(path: string, fail: string, deadline: number, done: () => boolean): Promise<boolean> {
  while (Date.now() < deadline && !done()) {
    if (existsSync(path)) return true;
    if (existsSync(fail)) return false;
    await new Promise((r) => setTimeout(r, 25));
  }
  return existsSync(path);
}

async function main(): Promise<void> {
  let result: Record<string, unknown> = {};
  const scratch = join(process.env["TMPDIR"] ?? "/tmp", `mandu-holder-accept-${process.pid}`);
  mkdirSync(scratch, { recursive: true });
  const policy = join(scratch, "policy.yaml");
  writeFileSync(policy, [
    "version: 1",
    "paths:",
    "  - path: \"**/workspace/accept-unbound.env\"",
    "    level: no-model",
    `    readers: [{ app: python3, script: ${B64}, prints: nothing }]`,
    "  - path: \"**/workspace/accept-bound.env\"",
    "    level: no-model",
    `    readers: [{ app: python3, script: ${B64}, prints: nothing }]`,
    `    bindings: ["${PEER}"]`,
    "",
  ].join("\n"));
  await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
    const unbound = join(workspace, "accept-unbound.env");
    const bound = join(workspace, "accept-bound.env");
    writeFileSync(unbound, `UNBOUND_KEY=${UNBOUND_CANARY}\n`);
    writeFileSync(bound, `BOUND_KEY=${BOUND_CANARY}\n`);
    const work = join(tmp, "accept");
    mkdirSync(work, { recursive: true });
    const server = join(work, "server.py");
    writeFileSync(server, SERVER);
    const servers: Array<[string, string, string, number]> = [
      ["plain", "plain", "-", 18431], ["unbound", "holder", unbound, 18432], ["bound", "holder", bound, 18433],
    ];
    const script = join(tmp, "agent.sh");
    writeFileSync(script, [
      ...servers.map(([name, mode, file, port]) => `/usr/bin/python3 ${server} ${mode} ${file} ${B64} ${work} ${name} ${port} &`),
      "wait",
      "echo AGENT done",
    ].join("\n") + "\n");
    const launchEnv = { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home };
    let launched = false;
    // The servers' ports are the launch's listen ports, as a user names a
    // dev server's (the Landlock TCP wrap stays on).
    const bindPorts = `--landlock-net-bind=${servers.map(([, , , port]) => port).join(",")}`;
    const launch = runLauncher(["--no-scope", "--no-mcp", "--no-reply-filter", bindPorts, "--target", "claude", "--", "/bin/sh", script], launchEnv, workspace, 240_000)
      .catch((e: unknown) => ({ code: -1, out: String((e as Error).message ?? e) }))
      .finally(() => { launched = true; });

    const legs: Record<string, Record<string, string>> = {};
    const ready: Record<string, boolean> = {};
    const deadline = Date.now() + 150_000;
    for (const [name] of servers) {
      ready[name] = await waitFor(join(work, `${name}.ready`), join(work, `${name}.fail`), deadline, () => launched);
    }
    for (const [name] of servers) {
      if (!ready[name]) continue;
      const mark = JSON.parse(readFileSync(join(work, `${name}.ready`), "utf8")) as { port: number; unix: string };
      const port = String(mark.port);
      const l: Record<string, string> = {};
      l["outside"] = await leg(["ask", PEER, PEER_CTRL, OUTSIDE, SELF, port]);
      l["inside"] = await leg(["ask", PEER, PEER_CTRL, PEER, SELF, port]);
      l["loopback"] = await leg(["tcp", "127.0.0.1", "127.0.0.1", port]);
      l["own"] = await leg(["tcp", SELF, SELF, port]);
      l["unix"] = await leg(["unix", mark.unix]);
      legs[name] = l;
    }
    const r = await launch;
    const seen: Record<string, unknown> = {};
    const fails: Record<string, string> = {};
    for (const [name] of servers) {
      const p = join(work, `${name}.seen`);
      seen[name] = existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : null;
      const f = join(work, `${name}.fail`);
      if (existsSync(f)) fails[name] = readFileSync(f, "utf8");
    }
    result = {
      code: r.code,
      outTail: r.out.slice(-6000),
      guardLive: /net-guard LIVE/.test(r.out),
      agentDone: /AGENT done/.test(r.out),
      ready,
      legs,
      seen,
      fails,
      unboundCanary: UNBOUND_CANARY,
      boundCanary: BOUND_CANARY,
    };
  }, { mode: "secrets", policyPath: policy });
  rmSync(scratch, { recursive: true, force: true });
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(0);
}

main().catch((e) => {
  process.stdout.write(JSON.stringify({ error: String((e as Error).stack ?? e) }) + "\n");
  process.exit(1);
});
