/**
 * A program the agent's tree has just written runs at once under the guard
 * (CI pipelines 11765 and 11856, `integration.kernel` case "the agent tree
 * cannot change Mandu's policy, and a .bashrc change waits for the human"):
 * across the REAL components, the launcher's main() in `secrets` mode with
 * a catalog credential file (so the guard performs every open that can
 * change a file), the REAL mandu-net-guard, a REAL ArbiterServer in this
 * process. The "agent" is bash.
 *
 * The guard performs a write-capable open in its own process and hands the
 * descriptor over with SECCOMP_IOCTL_NOTIF_ADDFD. The tracee's descriptor is
 * the guard's open file description, and the kernel refuses to exec a file
 * any description holds open for writing (ETXTBSY). Before 2026-10-18 the
 * guard closed its own descriptor only after the answer that woke the
 * tracee: a guard thread descheduled in between (CI under load) made
 * `cp prog ws/prog && ws/prog` fail with "Text file busy", exit 126. That
 * is how the workspace copy of tee in write-protect.test.ts never ran, so
 * the human was never asked about it. Now the guard installs the
 * descriptor, closes its own, and only then answers (confidentiality plan 10
 * §4.1a, "The descriptor handed over"; the kernel test
 * `a_program_written_through_the_guard_runs_at_once` proves the order).
 *
 * Proved: several loops side by side, each copying an executable script
 * into the workspace and running it at once: every run exits 0 and prints
 * what the script says (126 "Text file busy" before the fix: 96 to 182
 * of 2000 such runs on a 4-vCPU guest).
 *
 * Self-SKIPs without the guard bin (scripts/build-native.sh).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
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
const skip = process.platform !== "linux" ? "Linux only" : !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)" : false;

/** Loops side by side, and copies each one writes and runs. */
const LOOPS = 6;
const ROUNDS = 60;

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD }, () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
});

test("a program the agent's tree has just copied runs at once: the guard keeps no write descriptor of it", { skip, timeout: 300_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-written-exec-e2e-"));
  const home = join(dir, "home");
  mkdirSync(join(home, ".aws"), { recursive: true });
  writeFileSync(join(home, ".aws", "credentials"), "[default]\naws_secret_access_key=AKIA_WRITTEN_EXEC_E2E_RAW\n");
  const ws = join(realpathSync(dir), "ws");
  mkdirSync(ws);
  // A script, not a binary: the kernel refuses to exec either while a
  // description holds it open for writing, and a script needs no GNU program.
  const prog = join(dir, "prog.sh");
  writeFileSync(prog, "#!/bin/sh\necho ran\n");
  chmodSync(prog, 0o755);
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
    // Each loop: copy, run at once, record the run's status and output.
    const loop = (w: number) =>
      `( i=0; while [ $i -lt ${ROUNDS} ]; do i=$((i+1)); c=${ws}/p${w}-$i; cp ${prog} $c; o=$($c 2>&1); echo "${w}-$i=$?:$o" >> ${out}.${w}; done ) &`;
    const script = `${Array.from({ length: LOOPS }, (_, w) => loop(w)).join(" ")} wait; cat ${out}.* > ${out}`;
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    process.env["HOME"] = home;
    process.env["MANDU_HOME"] = join(home, ".mandu");
    const code = await main(
      ["--target", "claude", "--verbose", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--", "bash", "-c", script],
      {
        HOME: home, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
        MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: dir,
      },
    );
    console.error = orig;
    const log = lines.join("\n");
    assert.equal(code, 0, log);
    assert.match(log, /net-guard LIVE/, `the guard must be up for this test to mean anything\n${log}`);
    const runs = readFileSync(out, "utf8").trim().split("\n");
    assert.equal(runs.length, LOOPS * ROUNDS, `every run recorded\n${runs.join("\n")}`);
    const bad = runs.filter((r) => !r.endsWith("=0:ran"));
    // 126 + "Text file busy": the guard still held the copy open for writing.
    assert.deepEqual(bad, [], `a copy the agent had just written did not run (${bad.length} of ${runs.length})`);
  } finally {
    console.error = orig;
    if (savedBin === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = savedBin;
    if (savedHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = savedHome;
    if (savedManduHome === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = savedManduHome;
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
