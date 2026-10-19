/**
 * The guard's opens under the launch's net-only wrap (plan 10 §4.1a, "The
 * cost of the mirror", 2026-10-05), across the REAL components: the
 * launcher's main() in `secrets` mode with the whole-agent Landlock wrap
 * (`mandu-landlock-apply --net-only`) ON, the REAL mandu-net-guard around
 * it, a REAL ArbiterServer in this process, a catalog credential file. The
 * "agent" is bash and python3.
 *
 * The guard performs every open that can read. A task in a Landlock domain
 * had that access run on a mirror thread restricted like it, and the whole
 * agent tree is in the wrap's domain, so every open paid two cross-thread
 * handoffs (about 0.2 ms of every open; the ~3x slower boxed commands of
 * 2026-10-03 were mostly that). The wrap handles no file access, so the
 * guard now reopens on its own thread for a task whose domain is the wrap
 * alone. Every decision must be what it was:
 *
 *   - a plain file reads; the credential file reads as its twin, never raw;
 *   - another process's `/proc/<pid>/environ` stays refused (Landlock's
 *     ptrace scoping, which every domain carries: the context helper
 *     reopens a pseudo file under the whole domain);
 *   - the process's own `/proc/self/environ` still reads;
 *   - a sandbox the agent's program sets up under the wrap (a Landlock
 *     ruleset that handles file reads) still confines what the guard opens
 *     for it (the mirror runs for a domain that governs files).
 *
 * And that the fast path is the one taken, in a real launch: the guard's
 * own count (`MANDU_NET_GUARD_OPEN_STATS`, written at its exit) shows opens
 * reopened on its thread under the wrap and the nested sandbox's opens on a
 * mirror. Not a timing assertion: the mirror's cost is wakeup latency, about
 * 0.3 ms an open on a busy host and 0.06 ms on an idle VM, so the medians
 * are reported as a diagnostic only.
 *
 * Self-SKIPs without the guard and applier bins (scripts/build-native.sh),
 * python3, or Landlock TCP rules (kernel >= 6.7: without them the wrap
 * installs nothing and there is nothing to prove).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../lib/axes.js";
import { pickGuard } from "../lib/native-guard.js";

stateAxes("secrets"); // the twin and the guard's open are the confidentiality axis's

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGET = resolve(HERE, "..", "..", "interceptors", "target");
const PICK = pickGuard(TARGET);
const GUARD = PICK.path;
const PY = spawnSync("python3", ["-c", "print(1)"]).status === 0;
// Landlock TCP rules (ABI >= 4): the wrap's ruleset exists only then.
const LANDLOCK_NET = PY && spawnSync("python3", ["-c",
  "import ctypes,sys; l=ctypes.CDLL(None); sys.exit(0 if l.syscall(444, None, 0, 1) >= 4 else 1)"]).status === 0;
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : !PY ? "python3 is not installed"
  : !LANDLOCK_NET ? "no Landlock TCP rules on this kernel (needs >= 6.7): the net-only wrap installs nothing" : false;

const RAW = "AKIA_FASTPATH_E2E_RAW";

// Each check prints `name=value`; the test compares them.
const PROBE_PY = `import ctypes, os, struct, sys, time
libc = ctypes.CDLL(None, use_errno=True)
d, outside = sys.argv[1], int(sys.argv[2])
print("plain=" + open(d + "/plain.txt").read().strip())
s = open(os.path.expanduser("~/.aws/credentials")).read()
print("secret_raw=%d" % ("${RAW}" in s))
try:
    open("/proc/%d/environ" % outside, "rb").read()
    print("outside_environ=ok")
except OSError as e:
    print("outside_environ=%d" % e.errno)
open("/proc/self/environ", "rb").read()
print("own_environ=ok")

def batch(path, n=400):
    t = time.perf_counter()
    for _ in range(n):
        os.close(os.open(path, os.O_RDONLY))
    return (time.perf_counter() - t) / n

# A nested sandbox: reads only under d/allowed (READ_FILE | READ_DIR handled).
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r)
    attr = struct.pack("Q", (1 << 2) | (1 << 3))
    rs = libc.syscall(444, ctypes.c_char_p(attr), ctypes.c_size_t(len(attr)), ctypes.c_uint32(0))
    pfd = os.open(d + "/allowed", os.O_PATH | os.O_DIRECTORY)
    rule = struct.pack("=Qi", (1 << 2) | (1 << 3), pfd)
    ok = rs >= 0 and libc.syscall(445, rs, 1, ctypes.c_char_p(rule), 0) == 0
    ok = ok and libc.prctl(38, 1, 0, 0, 0) == 0 and libc.syscall(446, rs, 0) == 0
    out = ["nested_restricted=%d" % ok]
    try:
        open(d + "/allowed/a.txt").read()
        out.append("nested_allowed=ok")
    except OSError as e:
        out.append("nested_allowed=%d" % e.errno)
    try:
        open(d + "/plain.txt").read()
        out.append("nested_denied=ok")
    except OSError as e:
        out.append("nested_denied=%d" % e.errno)
    # One line per batch: the mirrored open's cost.
    for _ in range(5):
        out.append("nested_open_us=%.1f" % (batch(d + "/allowed/a.txt") * 1e6))
    os.write(w, ("\\n".join(out) + "\\n").encode())
    os._exit(0)
os.close(w)
os.waitpid(pid, 0)
print(os.read(r, 65536).decode().strip())
# After the child's batches, not beside them: neither slows the other.
wrap = [batch(d + "/plain.txt") * 1e6 for _ in range(5)]
for v in wrap:
    print("wrap_open_us=%.1f" % v)
`;

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD }, () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
});

test("under the net-only wrap alone the guard's opens skip the mirror, and every decision is unchanged", { skip, timeout: 180_000 }, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-open-fast-"));
  const home = join(dir, "home");
  mkdirSync(join(home, ".aws"), { recursive: true });
  writeFileSync(join(home, ".aws", "credentials"), `[default]\naws_secret_access_key=${RAW}\n`);
  mkdirSync(join(dir, "allowed"));
  writeFileSync(join(dir, "allowed", "a.txt"), "A\n");
  writeFileSync(join(dir, "plain.txt"), "PLAIN\n");
  writeFileSync(join(dir, "probe.py"), PROBE_PY);
  const out = join(dir, "out");
  const stats = join(dir, "open-stats");
  const sock = join(dir, "arbiter.sock");
  // A process outside the agent's tree (and its Landlock domain), same uid.
  const outside = spawn("sleep", ["120"], { stdio: "ignore", detached: true });
  const server = new ArbiterServer({ socketPath: sock, dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {} });
  await server.listen();
  const lines: string[] = [];
  const orig = console.error;
  const savedBin = process.env["MANDU_NET_GUARD_BIN"];
  const savedHome = process.env["HOME"];
  const savedManduHome = process.env["MANDU_HOME"];
  try {
    const script = `python3 ${dir}/probe.py ${dir} ${outside.pid} > ${out} 2>&1`;
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    process.env["HOME"] = home;
    process.env["MANDU_HOME"] = join(home, ".mandu");
    const code = await main(
      // landlock-net stays ON (the default): the wrap is the point.
      ["--target", "claude", "--verbose", "--no-scope", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--", "bash", "-c", script],
      {
        HOME: home, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
        MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: dir,
        MANDU_NET_GUARD_OPEN_STATS: stats,
      },
    );
    console.error = orig;
    const log = lines.join("\n");
    assert.equal(code, 0, log);
    assert.match(log, /landlock-net LIVE/, `the whole-agent wrap must be up for this test to mean anything\n${log}`);
    const text = readFileSync(out, "utf8");
    const rows = text.trim().split("\n").filter((l) => /^\w+=/.test(l)).map((l) => l.split("=") as [string, string]);
    const got = Object.fromEntries(rows);
    const all = (k: string) => rows.filter(([n]) => n === k).map(([, v]) => Number(v));
    const why = `${text}\n${log}`;
    // The decisions, unchanged.
    assert.equal(got["plain"], "PLAIN", why);
    assert.equal(got["secret_raw"], "0", `the credential file must read as its twin\n${why}`);
    // 13 = EACCES. ENOENT (2): a pid namespace hides the outside process (nothing to judge).
    assert.ok(got["outside_environ"] === "13" || got["outside_environ"] === "2", `another process's environ must stay refused\n${why}`);
    assert.equal(got["own_environ"], "ok", why);
    assert.equal(got["nested_restricted"], "1", `the probe's nested sandbox did not go up\n${why}`);
    assert.equal(got["nested_allowed"], "ok", why);
    assert.equal(got["nested_denied"], "13", `a sandbox under the wrap must still confine what the guard opens for it\n${why}`);
    // The path each open took, by the guard's own count.
    const counted = Object.fromEntries(readFileSync(stats, "utf8").trim().split("\n").map((l) => l.split(" ") as [string, string]));
    t.diagnostic(`guard: ${counted["wrap_opens"]} opens on its own thread under the wrap, ${counted["mirrored_opens"]} through a mirror`);
    assert.ok(Number(counted["wrap_opens"]) >= 400 * 5, `the tree's opens under the wrap alone must skip the mirror\n${JSON.stringify(counted)}\n${why}`);
    assert.ok(Number(counted["mirrored_opens"]) >= 400 * 5, `the nested sandbox's opens must still go through its mirror\n${JSON.stringify(counted)}\n${why}`);
    // The cost, reported: the median of five batches each, the mirrored
    // ones first and the wrap's after them (never side by side).
    const median = (xs: number[]) => [...xs].sort((x, y) => x - y)[xs.length >> 1]!;
    t.diagnostic(`median open: ${median(all("wrap_open_us"))} us under the wrap alone, ${median(all("nested_open_us"))} us through the mirror`);
  } finally {
    console.error = orig;
    try { process.kill(outside.pid!, "SIGKILL"); } catch { /* gone */ }
    if (savedBin === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = savedBin;
    if (savedHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = savedHome;
    if (savedManduHome === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = savedManduHome;
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
