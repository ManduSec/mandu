/**
 * An agent's open of its own tmp directory under the guard, with the
 * launch's Landlock TCP rung OFF (`--no-landlock-net`) and ON, across the
 * REAL components: the launcher's main() in `secrets` mode with a catalog
 * credential file (so the guard performs every open that can read), the
 * REAL mandu-net-guard, a REAL ArbiterServer in this process. The "agent"
 * is bash and python3, issuing the opens the way Bun (Claude Code) does.
 *
 * 2026-10-16: `mandu --no-landlock-net claude` stopped at start with "Error
 * processing settings: EINVAL: invalid argument, open '/tmp/claude-<uid>'".
 * Bun passes 0666 as the mode of every open, a directory's `O_DIRECTORY`
 * open too. The kernel ignores the mode of an open that creates nothing,
 * but the guard took every `O_DIRECTORY` open for a create (libc's
 * `O_TMPFILE` carries the `O_DIRECTORY` bit) and its performed `openat2`
 * carried the mode, which openat2 refuses (EINVAL). Under the net-only wrap
 * (the default) the guard's split open (`O_PATH`, then a reopen) never
 * passed the mode, so only a launch whose agent is in no Landlock domain
 * met it (plan 10 §4.1a; guard-file-identity.md).
 *
 * Proved, in both postures:
 *   - the agent makes its tmp directory and opens it `O_DIRECTORY` with a
 *     stray 0666 (absolute, and relative to a descriptor);
 *   - a file it creates there gets the mode it asked for under its umask
 *     (a create still carries its mode);
 *   - the credential file still reads as its twin, never raw.
 *
 * Self-SKIPs without the guard bin (scripts/build-native.sh) or python3;
 * the landlock-net-on case also without Landlock TCP rules (kernel >= 6.7)
 * or the applier bin.
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

stateAxes("secrets"); // the guard's performed open is the confidentiality axis's

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGET = resolve(HERE, "..", "..", "interceptors", "target");
const PICK = pickGuard(TARGET);
const GUARD = PICK.path;
const PY = spawnSync("python3", ["-c", "print(1)"]).status === 0;
const LANDLOCK_NET = PY && spawnSync("python3", ["-c",
  "import ctypes,sys; l=ctypes.CDLL(None); sys.exit(0 if l.syscall(444, None, 0, 1) >= 4 else 1)"]).status === 0;
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : !PY ? "python3 is not installed" : false;

const RAW = "AKIA_DIRMODE_E2E_RAW";

// Each check prints `name=value`. Raw syscalls, so the mode register holds
// 0666 on the directory opens exactly as Bun's do.
const PROBE_PY = `import ctypes, os, stat, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
SYS_openat = {"x86_64": 257, "aarch64": 56}[os.uname().machine]
AT_FDCWD = -100
base = sys.argv[1]
tmp = os.path.join(base, "claude-%d" % os.getuid())
try:
    os.mkdir(tmp, 0o700)
except FileExistsError:
    pass
O_LARGEFILE = 0o100000 if os.uname().machine == "x86_64" else 0o400000
bun_dir = os.O_RDONLY | O_LARGEFILE | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_DIRECTORY
def raw_open(dirfd, path, flags, mode):
    fd = libc.syscall(ctypes.c_long(SYS_openat), ctypes.c_long(dirfd), ctypes.c_char_p(path.encode()), ctypes.c_long(flags), ctypes.c_long(mode))
    return fd if fd >= 0 else -ctypes.get_errno()
fd = raw_open(AT_FDCWD, tmp, bun_dir, 0o666)
print("tmp_dir_open=%s" % ("ok" if fd >= 0 else fd))
if fd >= 0:
    print("tmp_dir_is_dir=%d" % stat.S_ISDIR(os.fstat(fd).st_mode))
    os.close(fd)
bfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
rel = raw_open(bfd, os.path.basename(tmp), bun_dir, 0o666)
print("tmp_dir_open_rel=%s" % ("ok" if rel >= 0 else rel))
if rel >= 0:
    os.close(rel)
os.umask(0o022)
f = raw_open(AT_FDCWD, os.path.join(tmp, "settings.json"), os.O_CREAT | os.O_WRONLY | os.O_EXCL | os.O_CLOEXEC, 0o666)
print("create=%s" % ("ok" if f >= 0 else f))
if f >= 0:
    os.close(f)
    print("create_mode=%o" % (os.stat(os.path.join(tmp, "settings.json")).st_mode & 0o7777))
s = open(os.path.expanduser("~/.aws/credentials")).read()
print("secret_raw=%d" % ("${RAW}" in s))
`;

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD }, () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
});

for (const landlockNet of [false, true]) {
  const name = landlockNet ? "with the Landlock TCP rung on (the guard's split open)" : "with --no-landlock-net (the guard's one-step open)";
  const caseSkip = skip || (landlockNet && !LANDLOCK_NET ? "no Landlock TCP rules on this kernel (needs >= 6.7)" : false);
  test(`the agent opens its own tmp dir ${name}`, { skip: caseSkip, timeout: 180_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-dirmode-e2e-"));
    const home = join(dir, "home");
    mkdirSync(join(home, ".aws"), { recursive: true });
    writeFileSync(join(home, ".aws", "credentials"), `[default]\naws_secret_access_key=${RAW}\n`);
    mkdirSync(join(dir, "agent-tmp"));
    writeFileSync(join(dir, "probe.py"), PROBE_PY);
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
      const script = `python3 ${dir}/probe.py ${dir}/agent-tmp > ${out} 2>&1`;
      console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
      process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
      process.env["HOME"] = home;
      process.env["MANDU_HOME"] = join(home, ".mandu");
      const code = await main(
        ["--target", "claude", "--verbose", "--no-scope", ...(landlockNet ? [] : ["--no-landlock-net"]),
          "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--", "bash", "-c", script],
        {
          HOME: home, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
          MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: dir,
        },
      );
      console.error = orig;
      const log = lines.join("\n");
      assert.equal(code, 0, log);
      assert.match(log, /net-guard LIVE/, `the guard must be up for this test to mean anything\n${log}`);
      if (landlockNet) assert.match(log, /landlock-net LIVE/, `the wrap must be up for this case\n${log}`);
      else assert.doesNotMatch(log, /landlock-net LIVE/, `the wrap must be off for this case\n${log}`);
      const text = readFileSync(out, "utf8");
      const got = Object.fromEntries(text.trim().split("\n").filter((l) => /^\w+=/.test(l)).map((l) => l.split("=") as [string, string]));
      const why = `${text}\n${log}`;
      // -22 = EINVAL: the 2026-10-16 failure.
      assert.equal(got["tmp_dir_open"], "ok", `the agent's O_DIRECTORY open of its tmp dir (mode 0666, as Bun) must open\n${why}`);
      assert.equal(got["tmp_dir_is_dir"], "1", why);
      assert.equal(got["tmp_dir_open_rel"], "ok", `…relative to a descriptor too\n${why}`);
      assert.equal(got["create"], "ok", why);
      assert.equal(got["create_mode"], "644", `a create keeps its mode under the umask\n${why}`);
      assert.equal(got["secret_raw"], "0", `the credential file must read as its twin\n${why}`);
    } finally {
      console.error = orig;
      if (savedBin === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = savedBin;
      if (savedHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = savedHome;
      if (savedManduHome === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = savedManduHome;
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
}
