/**
 * The guard lets go of the Landlock mirror of a sandbox whose processes are
 * gone (plan 10 §4.1a, "The mirror's records over a session", 2026-10-11),
 * across the REAL components: the launcher's main() in `secrets` mode, the
 * REAL mandu-net-guard around it, a REAL ArbiterServer in this process. The
 * "agent" is python3.
 *
 * Every program in the agent's tree that sandboxes itself with Landlock (the
 * command box's applier does, once per boxed command) gets a mirror in the
 * guard: a thread restricted like it, which performs its opens. The guard
 * kept the record of each such process until 4096 had piled up, so a session
 * grew a thread per boxed command (about 500 at the peak) and every boxed
 * command slowed as they did (the wrapped Stop hook, ~270 -> 600 ms over a
 * session). The records of gone processes are now swept once the map holds
 * twice what the last sweep left. Proved here:
 *
 *   - the churn: 400 short-lived processes each sandbox themselves and read
 *     through their mirror, and every one is still confined (its allowed
 *     file reads, the file outside its rule is refused);
 *   - the guard's own count (`MANDU_NET_GUARD_OPEN_STATS`, written at its
 *     exit): at least 400 mirrors were built, and far fewer mirror threads
 *     were ever alive at once (the old guard's peak was one per process);
 *   - nothing live is forgotten: a sandboxed process started BEFORE the
 *     churn, and a child it forks AFTER it, are still confined by their
 *     sandbox after every sweep the churn caused.
 *
 * Not a timing assertion (host-dependent): the boxed commands' cost is
 * plan 10 §4.1a's measurement. Self-SKIPs without the guard bin
 * (scripts/build-native.sh), python3, or Landlock.
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
import { stateAxes } from "../lib/axes.js";
import { pickGuard } from "../lib/native-guard.js";

stateAxes("secrets"); // the guard performs the tree's reads under the confidentiality axis

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGET = resolve(HERE, "..", "..", "interceptors", "target");
const PICK = pickGuard(TARGET);
const GUARD = PICK.path;
const PY = spawnSync("python3", ["-c", "print(1)"]).status === 0;
// Landlock at all (ABI >= 1): the processes below sandbox themselves.
const LANDLOCK = PY && spawnSync("python3", ["-c",
  "import ctypes,sys; l=ctypes.CDLL(None); sys.exit(0 if l.syscall(444, None, 0, 1) >= 1 else 1)"]).status === 0;
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : !PY ? "python3 is not installed"
  : !LANDLOCK ? "no Landlock on this kernel" : false;

const CHURN = 400;

// Prints `name=value` lines; the test reads them.
const PROBE_PY = `import ctypes, os, struct, sys
libc = ctypes.CDLL(None, use_errno=True)
d, n = sys.argv[1], int(sys.argv[2])

def sandbox():
    """Reads only under d/allowed (READ_FILE | READ_DIR handled)."""
    attr = struct.pack("Q", (1 << 2) | (1 << 3))
    rs = libc.syscall(444, ctypes.c_char_p(attr), ctypes.c_size_t(len(attr)), ctypes.c_uint32(0))
    pfd = os.open(d + "/allowed", os.O_PATH | os.O_DIRECTORY)
    rule = struct.pack("=Qi", (1 << 2) | (1 << 3), pfd)
    return rs >= 0 and libc.syscall(445, rs, 1, ctypes.c_char_p(rule), 0) == 0 \\
        and libc.prctl(38, 1, 0, 0, 0) == 0 and libc.syscall(446, rs, 0) == 0

def confined():
    """1 when the allowed file reads and the outside one is refused."""
    try:
        if open(d + "/allowed/a.txt").read() != "A\\n":
            return 0
    except OSError:
        return 0
    try:
        open(d + "/plain.txt").read()
        return 0
    except OSError as e:
        return 1 if e.errno == 13 else 0

def child(fn):
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        os.write(w, fn().encode())
        os._exit(0)
    os.close(w)
    return pid, r

def collect(pid, r):
    out = b""
    while True:
        b = os.read(r, 4096)
        if not b:
            break
        out += b
    os.close(r)
    os.waitpid(pid, 0)
    return out.decode()

# A sandboxed process that lives through the churn: it waits on a pipe,
# then checks itself and a child it forks then.
go_r, go_w = os.pipe()
def long_lived():
    ok = sandbox()
    os.read(go_r, 1)
    me = confined()
    pid, r = child(lambda: str(confined()))
    kid = collect(pid, r)
    return "long_restricted=%d\\nlong_confined=%d\\nlong_child_confined=%s\\n" % (ok, me, kid)
lpid, lr = child(long_lived)

bad = 0
for _ in range(n):
    pid, r = child(lambda: "1" if sandbox() and confined() == 1 else "0")
    if collect(pid, r) != "1":
        bad += 1
print("churn=%d" % n)
print("churn_unconfined=%d" % bad)
os.write(go_w, b"x")
print(collect(lpid, lr).strip())
`;

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD }, () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
});

test("the guard lets go of the mirrors of gone sandboxes, and every live one stays confined", { skip, timeout: 240_000 }, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-mirror-records-"));
  const home = join(dir, "home");
  mkdirSync(home, { recursive: true });
  mkdirSync(join(dir, "allowed"));
  writeFileSync(join(dir, "allowed", "a.txt"), "A\n");
  writeFileSync(join(dir, "plain.txt"), "PLAIN\n");
  writeFileSync(join(dir, "probe.py"), PROBE_PY);
  const out = join(dir, "out");
  const stats = join(dir, "open-stats");
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({ socketPath: sock, dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {} });
  await server.listen();
  const lines: string[] = [];
  const orig = console.error;
  const savedBin = process.env["MANDU_NET_GUARD_BIN"];
  const savedHome = process.env["HOME"];
  const savedManduHome = process.env["MANDU_HOME"];
  try {
    const script = `python3 ${dir}/probe.py ${dir} ${CHURN} > ${out} 2>&1`;
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    process.env["HOME"] = home;
    process.env["MANDU_HOME"] = join(home, ".mandu");
    const code = await main(
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
    assert.match(log, /net-guard LIVE/, `the guard must be up for this test to mean anything\n${log}`);
    const text = readFileSync(out, "utf8");
    const got = Object.fromEntries(text.trim().split("\n").filter((l) => /^\w+=/.test(l)).map((l) => l.split("=") as [string, string]));
    const why = `${text}\n${log}`;
    // Every sandbox confined, through the churn and after it.
    assert.equal(got["churn"], String(CHURN), why);
    assert.equal(got["churn_unconfined"], "0", `a sandboxed process read outside its rule (or not inside it)\n${why}`);
    assert.equal(got["long_restricted"], "1", `the long-lived sandbox did not go up\n${why}`);
    assert.equal(got["long_confined"], "1", `a live sandbox lost its confinement after the sweeps\n${why}`);
    assert.equal(got["long_child_confined"], "1", `a child forked from a live sandbox after the sweeps was not confined\n${why}`);
    // The guard's own count: a mirror per sandbox, but not a thread kept per one.
    const counted = Object.fromEntries(readFileSync(stats, "utf8").trim().split("\n").map((l) => l.split(" ") as [string, string]));
    const domains = Number(counted["mirror_domains"]);
    const peak = Number(counted["mirror_threads_peak"]);
    t.diagnostic(`guard: ${domains} mirrors built, at most ${peak} mirror threads alive at once`);
    assert.ok(domains >= CHURN + 1, `every sandbox gets a mirror\n${JSON.stringify(counted)}\n${why}`);
    assert.ok(peak < CHURN / 2, `the mirrors of gone sandboxes must be let go (peak ${peak} threads for ${domains} mirrors)\n${JSON.stringify(counted)}`);
  } finally {
    console.error = orig;
    if (savedBin === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = savedBin;
    if (savedHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = savedHome;
    if (savedManduHome === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = savedManduHome;
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
