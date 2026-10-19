/**
 * The human-plane wall e2e (docs/design/architecture/arbiter-human-plane.md §5), across
 * the REAL components: the launcher's main() in `secrets` mode reads the
 * arbiter's human socket from `hello`, writes the guard's always-deny
 * `unixDeny` entry (and the twin wrap's tmpfs where the host can bind), the
 * REAL mandu-net-guard enforces it for the whole agent tree, a REAL
 * ArbiterServer serves both sockets. The "agent" is bash + python3.
 *
 *   - The data socket stays reachable from the agent's tree (its shims need it).
 *   - The human socket is not: by its path, through a symlink to it, through
 *     a symlink to its directory, and through a hard link the agent tries to
 *     make (refused EACCES by the guard, or ENOENT where the wrap's tmpfs
 *     hides the directory).
 *   - The same holds with the Unix allow-list opted out (MANDU_UNIX_POLICY=0):
 *     the deny list is not part of it.
 *   - Control: this test process (outside the agent's world) does reach the
 *     human socket, so a refusal inside is the wall, not a dead socket.
 *
 * Self-SKIPs without the guard bin (scripts/build-native.sh) or python3.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { connect } from "node:net";
import { once } from "node:events";
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../lib/axes.js";
import { pickGuard } from "../lib/native-guard.js";

stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGET = resolve(HERE, "..", "..", "interceptors", "target");
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

/** 0 = connected; an errno otherwise. */
async function connectFromHere(path: string): Promise<number> {
  const c = connect(path);
  try {
    await once(c, "connect");
    return 0;
  } catch (e) {
    return (e as NodeJS.ErrnoException).errno ? Math.abs((e as NodeJS.ErrnoException).errno!) : -1;
  } finally {
    c.destroy();
  }
}

async function runWall(opts: { unixPolicyOff?: boolean; guardOnly?: boolean } = {}): Promise<void> {
  const { unixPolicyOff = false, guardOnly = false } = opts;
  const dir = mkdtempSync(join(tmpdir(), "mandu-hp-wall-"));
  const home = join(dir, "home");
  mkdirSync(home, { recursive: true });
  writeFileSync(join(dir, "client.py"), CLIENT);
  const out = join(dir, "out");
  const sock = join(dir, "arbiter.sock");
  // The launcher's runtime base is `${XDG_RUNTIME_DIR}/mandu`; the human
  // socket lives in its `human/` dir, as server-main binds it.
  const humanDir = join(dir, "mandu", "human");
  const humanSock = join(humanDir, "test-instance.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock,
    dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {},
  });
  await server.listen();
  const lines: string[] = [];
  const orig = console.error;
  const savedBin = process.env["MANDU_NET_GUARD_BIN"];
  const savedHome = process.env["HOME"];
  const savedManduHome = process.env["MANDU_HOME"];
  try {
    assert.equal(await connectFromHere(humanSock), 0, "control: the human socket is live outside the agent's world");
    linkSync(humanSock, join(dir, "hard-pre.sock"));
    const c = `python3 ${dir}/client.py`;
    const script =
      `echo "data=$(${c} ${sock})" > ${out}; ` +
      `echo "direct=$(${c} ${humanSock})" >> ${out}; ` +
      `ln -s ${humanSock} ${dir}/link.sock 2>/dev/null; echo "symlink=$(${c} ${dir}/link.sock)" >> ${out}; ` +
      `ln -s ${humanDir} ${dir}/hdir 2>/dev/null; echo "dirlink=$(${c} ${dir}/hdir/test-instance.sock)" >> ${out}; ` +
      // A hard link the agent makes is refused outright (the human plane's
      // directory is on the write-protect list, runtime-instances.md §2);
      // one made outside the agent's world beforehand is refused by identity.
      `ln ${humanSock} ${dir}/hard.sock 2>/dev/null; echo "mklink=$?" >> ${out}; ` +
      `echo "hardlink=$(${c} ${dir}/hard-pre.sock)" >> ${out}; ` +
      `echo "env=\${MANDU_ARBITER_HUMAN_SOCK:-unset}" >> ${out}; ` +
      "true";
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    process.env["HOME"] = home;
    process.env["MANDU_HOME"] = join(home, ".mandu");
    const code = await main(
      ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", ...(guardOnly ? ["--no-secret-bind"] : []), "--", "bash", "-c", script],
      {
        HOME: home, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
        MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: dir,
        MANDU_VERBOSE: "1",
        // An ambient value must not reach the agent either.
        MANDU_ARBITER_HUMAN_SOCK: humanSock,
        ...(unixPolicyOff ? { MANDU_UNIX_POLICY: "0" } : {}),
      },
    );
    console.error = orig;
    const got = Object.fromEntries(readFileSync(out, "utf8").trim().split("\n").map((l) => l.split("=") as [string, string]));
    const log = lines.join("\n");
    assert.equal(code, 0, log);
    assert.ok(lines.some((l) => l.includes("human plane")), `the launch walls the human plane: ${log}`);
    assert.equal(got["data"], "0", `the data socket stays reachable; got ${got["data"]}\n${log}`);
    // EACCES (13) from the guard, or ENOENT (2) where the wrap's tmpfs hides
    // the directory; never a connection.
    for (const leg of ["direct", "symlink", "dirlink", "hardlink"]) {
      // Guard only (no mount layer): the directory is visible, so every leg
      // reaches the guard, which must refuse it (the hard link by identity).
      const ok = guardOnly ? got[leg] === "13" : got[leg] === "13" || got[leg] === "2";
      assert.ok(ok, `${leg}: the human socket must be refused inside the agent's world; got ${got[leg]}\n${log}`);
    }
    assert.notEqual(got["mklink"], "0", `the agent made a hard link to the human socket\n${log}`);
    assert.ok(!existsSync(join(dir, "hard.sock")), "no hard link of the agent's");
    assert.equal(got["env"], "unset", "the agent never inherits MANDU_ARBITER_HUMAN_SOCK");
  } finally {
    console.error = orig;
    if (savedBin === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = savedBin;
    if (savedHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = savedHome;
    if (savedManduHome === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = savedManduHome;
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD }, () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
});

test("the agent's tree cannot connect to the human socket (path, symlink, dir symlink, hard link); the data socket stays reachable", { skip, timeout: 120_000 }, async () => {
  await runWall();
});

test("the wall holds with the Unix allow-list opted out (MANDU_UNIX_POLICY=0)", { skip, timeout: 120_000 }, async () => {
  await runWall({ unixPolicyOff: true });
});

test("the guard alone refuses every leg (no mount layer: --no-secret-bind), allow-list off too", { skip, timeout: 120_000 }, async () => {
  await runWall({ guardOnly: true, unixPolicyOff: true });
});
