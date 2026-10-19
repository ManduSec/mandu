/**
 * Unix socket allow-list e2e (sandbox-security-review-2026-09-28 finding 1),
 * across the REAL components: the launcher's main() in `secrets` mode writes
 * the allow-list, the REAL mandu-net-guard enforces it for the whole agent
 * tree, a REAL ArbiterServer backs the session. The "agent" is bash + python3.
 *
 *   - A socket a host process listens on (this test, standing in for the
 *     D-Bus session bus or docker) is refused.
 *   - A server the agent itself starts and daemonizes (double fork, setsid)
 *     is reachable: the guard is the tree's subreaper, so the listener is
 *     still in the tree.
 *   - A server of the agent's that accepts exactly ONE connection (bind,
 *     listen, fork, the parent exits: ssh-agent's shape), on a socket file
 *     and on an abstract name, serves its real client (exec-routing.md
 *     §4.3, the bind record, 2026-10-18): the guard judges the listener by
 *     the record, without a probe connection of its own, which used to be
 *     the server's one accept (its client then waited on nothing).
 *   - Where this host runs a systemd user manager that `systemd-run --user`
 *     reaches from outside, the same command from inside the agent fails:
 *     the review's confirmed escape (a unit started that way runs outside
 *     every Mandu confinement and reads the real secret files).
 *
 * Self-SKIPs without the guard bin (scripts/build-native.sh) or python3.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createServer, type Server } from "node:net";
import { once } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../lib/axes.js";
import { pickGuard } from "../lib/native-guard.js";

stateAxes("secrets"); // the allow-list is the confidentiality axis's

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGET = resolve(HERE, "..", "..", "interceptors", "target");
// The newest FRESH build (lib/native-guard.ts): a stale bin tests an older guard.
const PICK = pickGuard(TARGET);
const GUARD = PICK.path;
const PY = spawnSync("python3", ["-c", "print(1)"]).status === 0;
const skip = process.platform !== "linux" || !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)" : !PY ? "python3 is not installed" : false;

const CLIENT = `import socket, sys
s = socket.socket(socket.AF_UNIX)
try:
    s.connect(sys.argv[1]); print(0)
except OSError as e:
    print(e.errno)
`;
// Daemonize (double fork + setsid), listen, say so, answer connections until
// told to stop (a ".stop" file) or 30 s pass. The readiness mark comes AFTER
// listen(): the socket file exists from bind() on, and a connect between
// bind() and listen() gets the kernel's own ECONNREFUSED (the guard answers
// exactly that too, for "nobody listens"), so "the file exists" is not "the
// server is up" (the CI's local-full-3 run: "got 111"). It serves more than
// one connection: before the bind record (2026-10-18) the guard opened its
// own probe connection to the listener first (unix_owner.rs), and a server
// that answered one connection could spend it on the probe (CI 2026-09-29);
// the one-accept case is ONCE's, below.
const SERVER = `import os, socket, sys, time
if os.fork(): sys.exit(0)
os.setsid()
if os.fork(): sys.exit(0)
s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(4)
open(sys.argv[1] + ".ready", "w").close()
s.settimeout(0.2)
end = time.time() + 30
while time.time() < end and not os.path.exists(sys.argv[1] + ".stop"):
    try:
        c, _ = s.accept(); c.close()
    except OSError:
        pass
`;


// ssh-agent's shape with a server that takes exactly one connection: bind,
// listen, fork, the parent marks readiness and exits; the server accepts
// once, reads a byte, answers "k". argv: the address ("@name": abstract),
// the readiness mark.
const ONCE = `import os, socket, sys
a = sys.argv[1]
a = "\\0" + a[1:] if a.startswith("@") else a
s = socket.socket(socket.AF_UNIX); s.bind(a); s.listen(4)
if os.fork():
    open(sys.argv[2], "w").close(); sys.exit(0)
os.setsid()
s.settimeout(30)
c, _ = s.accept()
c.settimeout(10)
if c.recv(1): c.send(b"k")
`;
// Connect, send a byte, print the answer ("eof": the connection was the
// server's and it closed; "timeout": nobody answered), or the errno.
const ONCE_CLIENT = `import socket, sys
a = sys.argv[1]
a = "\\0" + a[1:] if a.startswith("@") else a
s = socket.socket(socket.AF_UNIX); s.settimeout(5)
try:
    s.connect(a); s.send(b"x"); b = s.recv(1); print(b.decode() or "eof")
except socket.timeout:
    print("timeout")
except OSError as e:
    print(e.errno)
`;

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD }, () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
});
test("the agent's tree reaches its own sockets, not a host service's", { skip, timeout: 120_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-unix-e2e-"));
  const home = join(dir, "home");
  mkdirSync(home, { recursive: true });
  writeFileSync(join(dir, "client.py"), CLIENT);
  writeFileSync(join(dir, "server.py"), SERVER);
  writeFileSync(join(dir, "once.py"), ONCE);
  writeFileSync(join(dir, "once_client.py"), ONCE_CLIENT);
  const onceSock = join(dir, "once.sock");
  const onceAbs = `@mandu-once-e2e-${process.pid}-${Date.now()}`;
  const hostSock = join(dir, "host.sock");
  const ownSock = join(dir, "own.sock");
  const out = join(dir, "out");
  const host: Server = createServer((c) => c.end());
  host.listen(hostSock);
  await once(host, "listening");
  // The real systemd user manager, when this host has one reachable from here.
  const realRuntime = process.env["XDG_RUNTIME_DIR"] ?? "";
  const sdOutside = realRuntime !== "" && existsSync(join(realRuntime, "systemd", "private"))
    && spawnSync("systemd-run", ["--user", "--wait", "--quiet", "true"], { timeout: 20_000 }).status === 0;
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({ socketPath: sock, dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {} });
  await server.listen();
  const lines: string[] = [];
  const orig = console.error;
  const savedBin = process.env["MANDU_NET_GUARD_BIN"];
  const savedHome = process.env["HOME"];
  const savedManduHome = process.env["MANDU_HOME"];
  try {
    const script =
      `echo "host=$(python3 ${dir}/client.py ${hostSock})" > ${out}; ` +
      `python3 ${dir}/server.py ${ownSock}; ` +
      // Wait for the listener, not the socket file (see SERVER): up to
      // 60 s on a loaded machine, polled.
      `for i in $(seq 1200); do [ -e ${ownSock}.ready ] && break; sleep 0.05; done; ` +
      `echo "own=$(python3 ${dir}/client.py ${ownSock})" >> ${out}; ` +
      `touch ${ownSock}.stop; ` +
      `python3 ${dir}/once.py ${onceSock} ${dir}/once.ready; ` +
      `for i in $(seq 1200); do [ -e ${dir}/once.ready ] && break; sleep 0.05; done; ` +
      `echo "once=$(python3 ${dir}/once_client.py ${onceSock})" >> ${out}; ` +
      `python3 ${dir}/once.py ${onceAbs} ${dir}/once-abs.ready; ` +
      `for i in $(seq 1200); do [ -e ${dir}/once-abs.ready ] && break; sleep 0.05; done; ` +
      `echo "onceabs=$(python3 ${dir}/once_client.py ${onceAbs})" >> ${out}; ` +
      (sdOutside ? `XDG_RUNTIME_DIR=${realRuntime} timeout 20 systemd-run --user --wait --quiet true 2>/dev/null; echo "sd=$?" >> ${out}; ` : "") +
      "true";
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    // The launcher's secret discovery walks os.homedir(): the throwaway HOME,
    // not this host's.
    process.env["HOME"] = home;
    process.env["MANDU_HOME"] = join(home, ".mandu");
    const code = await main(
      ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--", "bash", "-c", script],
      {
        HOME: home, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
        MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: dir,
      },
    );
    console.error = orig;
    const got = Object.fromEntries(readFileSync(out, "utf8").trim().split("\n").map((l) => l.split("=") as [string, string]));
    assert.equal(code, 0, lines.join("\n"));
    assert.equal(got["host"], "13", `a host service's socket must be refused (EACCES); got ${got["host"]}\n${lines.join("\n")}`);
    assert.equal(got["own"], "0", `the agent's own daemonized server must be reachable; got ${got["own"]}`);
    assert.equal(got["once"], "k", `the agent's one-accept server (socket file) must serve its real client, not a guard probe; got ${got["once"]}`);
    assert.equal(got["onceabs"], "k", `the agent's one-accept server (abstract name) must serve its real client, not a guard probe; got ${got["onceabs"]}`);
    if (sdOutside) assert.notEqual(got["sd"], "0", "systemd-run --user reached the host's user manager from inside the agent");
    else console.error("note: no reachable systemd user manager here; the systemd-run leg did not run");
  } finally {
    console.error = orig;
    if (savedBin === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = savedBin;
    if (savedHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = savedHome;
    if (savedManduHome === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = savedManduHome;
    host.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
