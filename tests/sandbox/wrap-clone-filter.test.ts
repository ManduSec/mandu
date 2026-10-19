/**
 * No siblings in the agent's tree (exec-routing.md §7.5 gap (d), closed
 * 2026-10-03), across the REAL components: the launcher's main() in
 * `secrets` mode with a catalog credential file (so the twin wrap goes up
 * where the host allows it), the REAL mandu-net-guard around it, a REAL
 * ArbiterServer in this process. The "agent" is bash, python3 and node.
 *
 *   - `clone(CLONE_PARENT)` answers EPERM and `clone3` ENOSYS inside the
 *     tree: a process cannot make a sibling of itself, so whatever a holder
 *     starts is its child, in reach of the lineage walk and the orphan
 *     backstop.
 *   - What falls back from `clone3` keeps working under the wrap: the
 *     shell's subshells, pipelines and background jobs, Python's subprocess,
 *     posix_spawn and threads, Node's child_process, a worker thread and the
 *     libuv pool, and a nested bwrap (the command box's shape: a namespace
 *     clone, which the filter does not touch).
 *   - Go (the crate's `tests/fixtures/clone-probe.go`, built static before
 *     the launch): its runtime's raw thread clones, os/exec in each shape
 *     (the clone(CLONE_VFORK|CLONE_VM|CLONE_PIDFD) path), loopback TCP,
 *     HTTP and a unix socket work in the tree, a raw clone(CLONE_PARENT),
 *     clone3(CLONE_PARENT) and Go's `Cloneflags: CLONE_PARENT` spawn are
 *     refused, and Go's one clone3 path (`UseCgroupFD`) answers ENOSYS (Go
 *     has no fallback there: the documented cost). Left out where `go` is
 *     not installed.
 *
 * The earlier attempt at this gap trapped the fork family with seccomp
 * user-notification and broke the bubblewrap-wrapped agent; this refusal
 * traps nothing, and this test is its proof under the real wrap.
 *
 * Self-SKIPs without the guard bin (scripts/build-native.sh), python3 or
 * node; where bwrap cannot run or the wrap would forbid a sandbox inside it
 * the launch runs guard-only (the filter is the same) and the nested-bwrap
 * check is left out.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { resolveWrapBwrap } from "../../launcher/src/bwrap-grant.js";
import { nestedSandboxProbeArgv } from "../../launcher/src/secret-twins.js";
import { stateAxes } from "../lib/axes.js";
import { pickGuard } from "../lib/native-guard.js";

stateAxes("secrets"); // the refusal is the confidentiality axis's (a holder's lineage)

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGET = resolve(HERE, "..", "..", "interceptors", "target");
const PICK = pickGuard(TARGET);
const GUARD = PICK.path;
const BWRAP = (process.platform === "linux" ? resolveWrapBwrap() : null) ?? "bwrap";
const BWRAP_RUNS = process.platform === "linux" && spawnSync(BWRAP, ["--ro-bind", "/", "/", "--", "true"], { stdio: "ignore", timeout: 10_000 }).status === 0;
const NESTS = BWRAP_RUNS && (() => {
  const [cmd, ...args] = nestedSandboxProbeArgv(BWRAP);
  return spawnSync(cmd!, args, { stdio: "ignore", timeout: 10_000 }).status === 0;
})();
const PY = spawnSync("python3", ["-c", "print(1)"]).status === 0;
const GO = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;
const GO_PROBE_SRC = resolve(HERE, "..", "..", "interceptors", "net-supervisor", "tests", "fixtures", "clone-probe.go");

/** Build the Go probe (static, no module, nothing downloaded) into `out`. */
function buildGoProbe(out: string): void {
  const r = spawnSync("go", ["build", "-o", out, GO_PROBE_SRC], {
    env: { ...process.env, GOTOOLCHAIN: "local", CGO_ENABLED: "0", GOFLAGS: "" },
    encoding: "utf8", timeout: 300_000,
  });
  assert.equal(r.status, 0, `go build of the probe failed:\n${r.stdout}${r.stderr}`);
}
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : !PY ? "python3 is not installed" : false;

// Each check prints `name=value`; the test compares them.
const PROBE_PY = `import ctypes, errno, os, platform, subprocess, threading
libc = ctypes.CDLL(None, use_errno=True)
L = ctypes.c_long
SYS_clone = {"x86_64": 56, "aarch64": 220}[platform.machine()]
r = libc.syscall(L(SYS_clone), L(0x8000 | 17), L(0), L(0), L(0), L(0))
if r == 0:
    os._exit(0)
print("clone_parent=%d" % (0 if r >= 0 else ctypes.get_errno()))
r = libc.syscall(L(435), L(0), L(0))
print("clone3=%d" % (0 if r >= 0 else ctypes.get_errno()))
r = libc.syscall(L(SYS_clone), L(17), L(0), L(0), L(0), L(0))
if r == 0:
    os._exit(9)
print("plain_clone=%d" % (os.waitpid(r, 0)[1] >> 8 if r > 0 else -1))
print("subprocess=%d" % subprocess.run(["sh", "-c", "exit 3"]).returncode)
pid = os.posix_spawn("/bin/sh", ["sh", "-c", "exit 4"], os.environ)
print("posix_spawn=%d" % (os.waitpid(pid, 0)[1] >> 8))
seen = []
ts = [threading.Thread(target=lambda i=i: seen.append(i)) for i in range(4)]
[t.start() for t in ts]
[t.join() for t in ts]
print("threads=%d" % len(seen))
`;

const PROBE_NODE = `const cp = require("child_process");
const { Worker } = require("worker_threads");
console.log("node_sync=" + cp.execFileSync("sh", ["-c", "echo 5"]).toString().trim());
const w = new Worker("require('worker_threads').parentPort.postMessage(6)", { eval: true });
w.on("message", (m) => {
  console.log("node_worker=" + m);
  cp.exec("echo 7", (e, out) => {
    console.log("node_async=" + (e ? "err" : out.trim()));
    require("fs").readFile("/proc/self/status", (e2) => {
      console.log("node_pool=" + (e2 ? "err" : "8"));
      w.terminate();
    });
  });
});
`;

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD }, () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
});

test("no process in the agent's tree can make a sibling, and every ordinary spawn still works", { skip, timeout: 180_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-clone-e2e-"));
  const home = join(dir, "home");
  mkdirSync(join(home, ".aws"), { recursive: true });
  writeFileSync(join(home, ".aws", "credentials"), "[default]\naws_secret_access_key=AKIA_CLONE_E2E_RAW\n");
  writeFileSync(join(dir, "probe.py"), PROBE_PY);
  writeFileSync(join(dir, "probe.js"), PROBE_NODE);
  if (GO) buildGoProbe(join(dir, "go-probe"));
  else console.log("# SKIP: go is not installed (the Go leg)");
  const out = join(dir, "out");
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({ socketPath: sock, dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {} });
  await server.listen();
  const lines: string[] = [];
  const orig = console.error;
  const savedBin = process.env["MANDU_NET_GUARD_BIN"];
  const savedHome = process.env["HOME"];
  const savedManduHome = process.env["MANDU_HOME"];
  try {
    const script = [
      `: > ${out}`,
      `( exit 0 ); echo "subshell=$?" >> ${out}`,
      `echo hi | cat > /dev/null; echo "pipeline=$?" >> ${out}`,
      `sleep 0 & wait $!; echo "background=$?" >> ${out}`,
      `python3 ${dir}/probe.py >> ${out} 2>&1`,
      `node ${dir}/probe.js >> ${out} 2>&1`,
      // Go's report is its own file (its clone_parent= is not Python's); a
      // hang dumps its goroutines there (SIGQUIT) instead of timing out blind.
      GO ? `timeout -s QUIT 60 ${dir}/go-probe refused > ${dir}/go.out 2>&1; echo "go_exit=$?" >> ${out}` : "true",
      NESTS ? `${BWRAP} --dev-bind / / --unshare-pid --proc /proc -- true 2>/dev/null; echo "nested=$?" >> ${out}` : "true",
    ].join("; ");
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    process.env["HOME"] = home;
    process.env["MANDU_HOME"] = join(home, ".mandu");
    const code = await main(
      ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--", "bash", "-c", script],
      {
        HOME: home, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
        MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: dir,
        // The Go probe's TCP and HTTP legs: loopback to its own listeners.
        MANDU_NET_ALLOW: "127.0.0.0/8:*",
      },
    );
    console.error = orig;
    const log = lines.join("\n");
    assert.equal(code, 0, log);
    const text = readFileSync(out, "utf8");
    const got = Object.fromEntries(text.trim().split("\n").filter((l) => /^\w+=/.test(l)).map((l) => l.split("=") as [string, string]));
    const why = `${text}\n${log}`;
    // The refusal, under the real wrap and guard.
    assert.equal(got["clone_parent"], "1", `clone(CLONE_PARENT) must answer EPERM (1)\n${why}`);
    assert.equal(got["clone3"], "38", `clone3 must answer ENOSYS (38)\n${why}`);
    // What falls back from it, and what never used it.
    assert.equal(got["plain_clone"], "9", why);
    assert.equal(got["subshell"], "0", why);
    assert.equal(got["pipeline"], "0", why);
    assert.equal(got["background"], "0", why);
    assert.equal(got["subprocess"], "3", why);
    assert.equal(got["posix_spawn"], "4", why);
    assert.equal(got["threads"], "4", why);
    assert.equal(got["node_sync"], "5", why);
    assert.equal(got["node_worker"], "6", why);
    assert.equal(got["node_async"], "7", why);
    assert.equal(got["node_pool"], "8", why);
    if (NESTS) assert.equal(got["nested"], "0", `a nested bwrap (the command box's shape) starts under the refusal\n${why}`);
    if (GO) {
      // Go: threads, spawns and sockets work; the refusal holds against it.
      let goText = "";
      try { goText = readFileSync(join(dir, "go.out"), "utf8"); } catch { /* reported below */ }
      const go = Object.fromEntries(goText.split("\n").filter((l) => /^\w+=/.test(l)).map((l) => l.split("=") as [string, string]));
      const goWhy = `--- the Go probe (exit ${got["go_exit"]}; 124: hung, its goroutines dumped):\n${goText}\n${log}`;
      assert.equal(got["go_exit"], "0", `the Go probe failed in the tree\n${goWhy}`);
      assert.match(goText, /^go-ok$/m, goWhy);
      assert.equal(go["clone_parent"], "EPERM", goWhy);
      assert.equal(go["clone3_parent"], "ENOSYS", goWhy);
      assert.equal(go["exec_clone_parent"], "EPERM", `Go's Cloneflags=CLONE_PARENT spawn is refused\n${goWhy}`);
      assert.equal(go["exec_concurrent"], "40", goWhy);
      assert.equal(go["http"], "ok", goWhy);
      assert.equal(go["unix"], "ok", goWhy);
      // 2 under the Unix allow-list: the guard's probe of the unlisted
      // listener was accepted first (exec-routing.md §4.1).
      console.log(`go ${go["go"]}: unix_accepts=${go["unix_accepts"]}, pidfd=${go["pidfd"]}`);
      assert.equal(go["exec_cgroupfd"], "ENOSYS", `Go's UseCgroupFD (clone3, no fallback) is the refusal's documented cost\n${goWhy}`);
    }
  } finally {
    console.error = orig;
    if (savedBin === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = savedBin;
    if (savedHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = savedHome;
    if (savedManduHome === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = savedManduHome;
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
