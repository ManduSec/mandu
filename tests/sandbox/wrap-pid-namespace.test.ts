/**
 * The whole-agent wrap's own pid namespace (sandbox-security-review-2026-09-28
 * finding 3), across the REAL components: the launcher's main() in `secrets`
 * mode with a catalog credential file (so the twin wrap goes up), the REAL
 * mandu-net-guard around it, a REAL ArbiterServer (in THIS process, standing
 * in for the resident arbiter). The "agent" is bash + python3.
 *
 *   - The agent's tree lives in a pid namespace of its own: this test's
 *     process (the arbiter here) and a host process it started cannot be
 *     signalled from inside ("No such process").
 *   - The tree still reads its own procfs under the guard, which runs OUTSIDE
 *     that namespace: `/proc/self/…`, `/etc/mtab` (a link into `self`) and a
 *     nested bwrap (the command box's shape) all work.
 *   - A connect from a worker THREAD (glibc's and Bun's DNS) is served: the
 *     guard reaches the socket through the thread-group leader (a regression
 *     of finding 8's mandatory copy stopped Claude Code's DNS).
 *   - A socket file nobody listens on answers ECONNREFUSED, the kernel's own
 *     answer (Claude Code's stale `cc-socks/2.sock`, the same name in every
 *     session now that the agent is always pid 2).
 *
 * Self-SKIPs where bwrap cannot create a user namespace, where the wrap
 * would forbid a sandbox inside it (the launcher's own nesting probe,
 * `nestedSandboxProbeArgv`, fails: Ubuntu's `bwrap-userns-restrict` profile
 * on the distro's /usr/bin/bwrap, with Mandu's own bubblewrap not installed by
 * `mandu setup`), without the guard bin (scripts/build-native.sh), or without
 * python3. Where nesting is forbidden the launch serves the twins with the
 * guard alone and puts up no wrap, so there is no pid namespace to test
 * (exec-routing.md, "The wrap exists only with the bind layer").
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { resolveWrapBwrap } from "../../launcher/src/bwrap-grant.js";
import { nestedSandboxProbeArgv } from "../../launcher/src/secret-twins.js";
import { stateAxes } from "../lib/axes.js";
import { pickGuard } from "../lib/native-guard.js";

stateAxes("secrets"); // the twin wrap is the confidentiality axis's

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGET = resolve(HERE, "..", "..", "interceptors", "target");
// The newest FRESH build (lib/native-guard.ts): a stale bin tests an older guard.
const PICK = pickGuard(TARGET);
const GUARD = PICK.path;
const BWRAP = (process.platform === "linux" ? resolveWrapBwrap() : null) ?? "bwrap";
const BWRAP_RUNS = process.platform === "linux" && spawnSync(BWRAP, ["--ro-bind", "/", "/", "--", "true"], { stdio: "ignore", timeout: 10_000 }).status === 0;
// The probe the launch itself runs before the bind (secret-setup.ts): where
// it fails, the launch runs guard-only, with no wrap and so no pid namespace.
const NESTS = BWRAP_RUNS && (() => {
  const [cmd, ...args] = nestedSandboxProbeArgv(BWRAP);
  return spawnSync(cmd!, args, { stdio: "ignore", timeout: 10_000 }).status === 0;
})();
const PY = spawnSync("python3", ["-c", "print(1)"]).status === 0;
const skip = !BWRAP_RUNS ? "bwrap cannot create a user namespace on this host (no wrap)"
  : !NESTS ? `the wrap's bubblewrap (${BWRAP}) forbids a sandbox inside it on this host, so the launch runs guard-only with no wrap ` +
    "and no pid namespace (Ubuntu's bwrap-userns-restrict; `mandu setup` installs Mandu's own bubblewrap)"
  : !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : !PY ? "python3 is not installed" : false;

// A worker thread connects to the arbiter's socket (listed: always allowed);
// then a stale socket file is connected. Prints the two errnos (0 = connected).
const PROBE = `import os, socket, sys, threading
res = {}
def worker():
    s = socket.socket(socket.AF_UNIX)
    try:
        s.connect(sys.argv[1]); res["thread"] = 0
    except OSError as e:
        res["thread"] = e.errno
t = threading.Thread(target=worker); t.start(); t.join()
stale = sys.argv[2]
l = socket.socket(socket.AF_UNIX); l.bind(stale); l.close()
c = socket.socket(socket.AF_UNIX)
try:
    c.connect(stale); res["stale"] = 0
except OSError as e:
    res["stale"] = e.errno
print("thread=%d" % res["thread"]); print("stale=%d" % res["stale"])
`;


test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD }, () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
});
test("the agent's tree has its own pid namespace, and still works under the guard", { skip, timeout: 180_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-pidns-e2e-"));
  const home = join(dir, "home");
  mkdirSync(join(home, ".aws"), { recursive: true });
  writeFileSync(join(home, ".aws", "credentials"), "[default]\naws_secret_access_key=AKIA_PIDNS_E2E_RAW\n");
  writeFileSync(join(dir, "probe.py"), PROBE);
  const out = join(dir, "out");
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({ socketPath: sock, dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {} });
  await server.listen();
  // A host process outside the agent's tree.
  const victim = spawn("sleep", ["120"], { stdio: "ignore" });
  const ourNs = readlinkSync("/proc/self/ns/pid");
  const lines: string[] = [];
  const orig = console.error;
  const savedBin = process.env["MANDU_NET_GUARD_BIN"];
  const savedHome = process.env["HOME"];
  const savedManduHome = process.env["MANDU_HOME"];
  try {
    const script = [
      `echo "ns=$(readlink /proc/self/ns/pid)" > ${out}`,
      `kill -0 ${process.pid} 2>/dev/null; echo "arbiter=$?" >> ${out}`,
      `kill -0 ${victim.pid} 2>/dev/null; echo "victim=$?" >> ${out}`,
      `read -r a rest < /proc/self/stat; [ "$a" = "$$" ]; echo "selfstat=$?" >> ${out}`,
      `head -c1 /proc/self/mountinfo >/dev/null 2>&1; echo "mountinfo=$?" >> ${out}`,
      `case "$(readlink /etc/mtab 2>/dev/null)" in *self*) head -c1 /etc/mtab >/dev/null 2>&1; echo "mtab=$?" >> ${out} ;; esac`,
      `${BWRAP} --dev-bind / / --unshare-pid --proc /proc -- true 2>/dev/null; echo "nested=$?" >> ${out}`,
      `python3 ${dir}/probe.py ${sock} ${dir}/stale.sock >> ${out}`,
    ].join("; ");
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    // The launcher's secret discovery walks os.homedir(): the throwaway HOME.
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
    const log = lines.join("\n");
    assert.equal(code, 0, log);
    const got = Object.fromEntries(readFileSync(out, "utf8").trim().split("\n").map((l) => l.split("=") as [string, string]));
    assert.ok(got["ns"] && got["ns"] !== ourNs, `the tree must have a pid namespace of its own (${got["ns"]} vs ${ourNs})\n${log}`);
    assert.notEqual(got["arbiter"], "0", "the arbiter (this process) must not be signallable from inside");
    assert.notEqual(got["victim"], "0", "a host process must not be signallable from inside");
    assert.equal(got["selfstat"], "0", "/proc/self/stat names the reader itself under the guard");
    assert.equal(got["mountinfo"], "0", "/proc/self/mountinfo opens under the guard");
    if (got["mtab"] !== undefined) assert.equal(got["mtab"], "0", "/etc/mtab (a link into procfs self) opens under the guard");
    assert.equal(got["nested"], "0", "a nested bwrap (the command box's shape) starts inside the wrap");
    assert.equal(got["thread"], "0", "a worker thread's connect to an allowed socket is served");
    assert.equal(got["stale"], "111", "a socket nobody listens on answers ECONNREFUSED, not EACCES");
  } finally {
    console.error = orig;
    if (savedBin === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = savedBin;
    if (savedHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = savedHome;
    if (savedManduHome === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = savedManduHome;
    victim.kill("SIGKILL");
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
