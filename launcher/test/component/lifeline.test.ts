/**
 * lifeline.test — E2E for the kernel-bound service lifetime
 * (runtime-instances.md §8; services/primitives.ts startDetachedCmd).
 *
 * THE contract under test: a detached service spawned by startDetachedCmd dies
 * when its spawner dies, HOWEVER the spawner dies — including SIGKILL, where no
 * userspace teardown (stop() closures, trap EXIT) ever runs. That is the
 * orphaned-daemon class this retires: launcher/test-runner processes killed
 * hard used to leave `npm run serve` groups squatting ports for hours.
 *
 * The spawner side is proven with a REAL wrapper process that is SIGKILLed;
 * the service side uses `node -e` stand-ins honoring the same contract the
 * real entries arm via lifeline.ts (armLifeline unit tests live per package).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { startDetachedCmd } from "../../src/services/primitives.js";

const LAUNCHER_ROOT = resolve(fileURLToPath(import.meta.url), "..", "..", "..");

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

async function pollUntil(check: () => boolean, tries = 100, delayMs = 100): Promise<boolean> {
  for (let i = 0; i < tries; i++) {
    if (check()) return true;
    await new Promise((r) => setTimeout(r, delayMs));
  }
  return check();
}

/** A stand-in service honoring the lifeline contract (what armLifeline does). */
const SVC_HONORING = `
  if (process.env.MANDU_LIFELINE === "stdin") {
    process.stdin.resume();
    process.stdin.on("end", () => process.exit(0));
    process.stdin.on("error", () => process.exit(0));
  }
  setInterval(() => {}, 1000);
`;

test("SIGKILLed spawner: the detached service exits on the kernel-closed lifeline", { timeout: 30_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-lifeline-"));
  try {
    const pidFile = join(dir, "svc.pid");
    // A REAL intermediate spawner: calls startDetachedCmd exactly like the
    // service manager, records the service pid, then hangs holding the
    // lifeline's write end — until we SIGKILL it (no teardown code runs).
    const wrapper = join(dir, "wrapper.ts");
    writeFileSync(wrapper, `
      import { startDetachedCmd } from "${LAUNCHER_ROOT}/src/services/primitives.js";
      import { writeFileSync } from "node:fs";
      const h = startDetachedCmd(
        process.execPath,
        ["-e", ${JSON.stringify(SVC_HONORING)}],
        { cwd: "${dir}", env: { PATH: process.env["PATH"] } },
        "${join(dir, "svc.log")}",
      );
      writeFileSync("${pidFile}", String(h.pid));
      setInterval(() => {}, 1000); // hold the lifeline until SIGKILLed
    `);
    const w = spawn(process.execPath, ["--import", "tsx", wrapper], {
      cwd: LAUNCHER_ROOT, stdio: "ignore",
    });
    assert.ok(await pollUntil(() => existsSync(pidFile) && readFileSync(pidFile, "utf8") !== ""), "wrapper spawned the service");
    const svcPid = Number(readFileSync(pidFile, "utf8"));
    assert.ok(Number.isInteger(svcPid) && svcPid > 0, `service pid recorded (${svcPid})`);
    assert.ok(alive(svcPid), "service is up while the spawner lives");

    w.kill("SIGKILL"); // the ungraceful death: no stop(), no trap, nothing
    assert.ok(
      await pollUntil(() => !alive(svcPid)),
      `detached service ${svcPid} still alive after its spawner was SIGKILLed — the lifeline did not deliver`,
    );
  } finally {
    // Belt: if the assertion failed, don't leave the stand-ins running.
    try { const p = Number(readFileSync(join(dir, "svc.pid"), "utf8")); process.kill(p, "SIGKILL"); } catch { /* gone */ }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("stop() severs the lifeline: even a SIGTERM-ignoring service exits; env contract set", { timeout: 30_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-lifeline-"));
  try {
    const envFile = join(dir, "env.txt");
    // This service IGNORES SIGTERM (the tsx-wrapper 143 quirk, a wedged drain…)
    // but honors the lifeline — stop() must still take it down via stdin EOF.
    const svc = `
      require("node:fs").writeFileSync(${JSON.stringify(envFile)}, String(process.env.MANDU_LIFELINE));
      process.on("SIGTERM", () => {});
      process.stdin.resume();
      process.stdin.on("end", () => process.exit(0));
      process.stdin.on("error", () => process.exit(0));
      setInterval(() => {}, 1000);
    `;
    const h = startDetachedCmd(process.execPath, ["-e", svc], { cwd: dir, env: { PATH: process.env["PATH"] } }, join(dir, "svc.log"));
    assert.ok(h.pid !== undefined);
    // Poll for the CONTENT: writeFileSync creates the file before it writes
    // it, and under CI load a read landed in between ('' !== 'stdin').
    assert.ok(await pollUntil(() => existsSync(envFile) && readFileSync(envFile, "utf8") !== ""), "service came up");
    assert.equal(readFileSync(envFile, "utf8"), "stdin", "spawner set MANDU_LIFELINE=stdin");
    assert.ok(alive(h.pid!));

    h.stop();
    assert.ok(
      await pollUntil(() => !alive(h.pid!)),
      "SIGTERM-ignoring service survived stop() — the severed lifeline should have ended it",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── the shell suites' side: mdu_stop_group (lib/lifeline.sh) ──────────────────

/**
 * Run `script` in bash with lib/lifeline.sh sourced; resolves with its stdout.
 * Bounded: past `deadlineMs` the shell is SIGKILLed and the output says so, so
 * a primitive the host lacks fails the test instead of leaving a child that
 * keeps the test file alive (macOS, 2026-10-09: with no setsid(1) the wait
 * below spun until the suite's 1800 s timeout).
 */
function bashWithLifeline(script: string, deadlineMs = 20_000): Promise<{ code: number | null; out: string }> {
  return new Promise((done) => {
    const c = spawn("bash", ["-c", `source "${join(LAUNCHER_ROOT, "test", "lib", "lifeline.sh")}"\n${script}`], { stdio: ["ignore", "pipe", "inherit"] });
    let out = "";
    const timer = setTimeout(() => { out += `\n(killed: still running after ${deadlineMs} ms)`; c.kill("SIGKILL"); }, deadlineMs);
    c.stdout.on("data", (d: Buffer) => { out += d.toString(); });
    c.on("exit", (code) => { clearTimeout(timer); done({ code, out }); });
  });
}

/**
 * The shell suites that use mdu_stop_group run on Linux, and this test drives
 * it the way they do: setsid(1) (util-linux; macOS has none), `ps -o sid=`
 * (procps; macOS ps has no session-id keyword) and GNU `date +%s%N`. A host
 * without them SKIPs, naming what is missing.
 */
function shellSuiteToolsMissing(): string | false {
  const probe = spawnSync("bash", ["-c", 'command -v setsid >/dev/null && ps -o sid= -p $$ >/dev/null 2>&1 && case "$(date +%N)" in *N*|"") exit 1;; esac'], { stdio: "ignore" });
  return probe.status === 0 ? false : `setsid(1), ps -o sid= or GNU date +%N is missing on ${process.platform} (the Linux shell suites' tools)`;
}

test("mdu_stop_group: returns only once the setsid daemon's whole group is gone, graceful or SIGKILLed", { timeout: 60_000, skip: shellSuiteToolsMissing() }, async () => {
  // A daemon group (leader + child) that takes 0.5 s to shut down on SIGTERM,
  // and one that ignores SIGTERM: both are gone when the function returns.
  for (const [name, trapCmd] of [["graceful", "sleep 0.5; exit 0"], ["stubborn", ""]] as const) {
    const r = await bashWithLifeline([
      `setsid bash -c 'trap "${trapCmd}" TERM; sleep 300 & while :; do sleep 0.1; done' </dev/null >/dev/null 2>&1 &`,
      "pg=$!",
      `n=0; until [ "$(ps -o sid= -p $pg | tr -d ' ')" = "$pg" ]; do n=$((n + 1)); [ $n -lt 1000 ] || { echo "no session led by $pg"; exit 3; }; sleep 0.01; done`,
      "sleep 0.2",
      "echo \"members=$(pgrep -g $pg | wc -l)\"",
      "start=$(date +%s%N)",
      "mdu_stop_group \"$pg\"",
      "echo \"took=$(( ($(date +%s%N) - start) / 1000000 ))\"",
      "if kill -0 -- \"-$pg\" 2>/dev/null; then echo left=yes; else echo left=no; fi",
      "mdu_stop_group \"$pg\"; mdu_stop_group ''; echo again=$?",
    ].join("\n"));
    assert.equal(r.code, 0, `${name}: ${r.out}`);
    assert.match(r.out, /^members=[2-9]/m, `${name}: the daemon's group has its leader and a child: ${r.out}`);
    assert.match(r.out, /^left=no$/m, `${name}: no member of the group is left: ${r.out}`);
    assert.match(r.out, /^again=0$/m, `${name}: a gone or empty group is a no-op`);
    const took = Number(/^took=(\d+)$/m.exec(r.out)?.[1]);
    if (name === "graceful") assert.ok(took >= 400 && took < 4500, `${name}: waited for the shutdown, no SIGKILL (${took} ms)`);
    else assert.ok(took >= 4500, `${name}: SIGKILL only after the grace (${took} ms)`);
  }
});
