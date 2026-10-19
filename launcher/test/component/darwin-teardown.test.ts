/**
 * darwin-teardown.test — E2E (macOS only): what the agent leaves running ends
 * with the session (portable-wrapper-cross-platform.md §3.5).
 *
 * On darwin the launch is scoped by a process group only, and everything the
 * chain leaves behind is reparented to launchd the moment it exits. Before
 * Platform.killTree those processes lived on (inside the Seatbelt wrap, with
 * HTTP(S)_PROXY naming ports nobody served any more). Two layers:
 *   1. runAgent + darwinPlatform on the real host: a plain `&` job, a nohup
 *      job, a setsid'd process (a session of its own, seen by a sample while
 *      its parent lived) and a job that ignores SIGTERM all end; a bystander
 *      process of the same user does not.
 *   2. The real launch path: `mandu --target shell -- sh -c '… & echo
 *      started'` under a scratch HOME in mode secrets, the chain wrapped by
 *      Seatbelt (a fake credential is confined), with the stack autostarted:
 *      the agent's jobs end, the launcher says so in one line, and Mandu's
 *      own arbiter and dashboard keep running.
 * Every process a case starts is killed in its finally, and the scratch dirs
 * are removed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { runAgent } from "../../src/spawn.js";
import { darwinPlatform } from "../../src/platform/darwin.js";
import { runCli } from "../lib/run-cli.js";
import { axesEnv, stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const SKIP = process.platform !== "darwin" ? "macOS only: Linux holds the tree in its kernel scope" : false;

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === "EPERM"; }
}

function readPids(file: string): number[] {
  if (!existsSync(file)) return [];
  return readFileSync(file, "utf8").split(/\s+/).filter(Boolean).map(Number);
}

/** A process of the same user started OUTSIDE the launch: it must survive. */
function bystander(): number {
  const b = spawn("sleep", ["300"], { detached: true, stdio: "ignore" });
  b.unref();
  return b.pid!;
}

/** The agent's jobs, each appending its pid to `pids`. The setsid'd one moves
 *  to a session of its own; its parent stays for `hold` seconds (longer than
 *  a sampling interval) before the chain exits. */
function jobsScript(pids: string, hold: number): string {
  return [
    `sleep 300 >/dev/null 2>&1 & echo $! >> ${pids}`,
    `nohup sleep 301 >/dev/null 2>&1 & echo $! >> ${pids}`,
    `sh -c 'trap "" TERM; sleep 302' >/dev/null 2>&1 & echo $! >> ${pids}`,
    `perl -MPOSIX -e 'POSIX::setsid(); open(my $f, ">>", $ARGV[0]); print $f "$$\\n"; close $f; sleep 303' ${pids} >/dev/null 2>&1 &`,
    `sleep ${hold}`,
    `echo started`,
  ].join("\n");
}

function killAll(pids: number[]): void {
  for (const p of pids) { try { process.kill(p, "SIGKILL"); } catch { /* gone */ } }
}

function groupOf(pid: number): number | null {
  const r = spawnSync("ps", ["-o", "pgid=", "-p", String(pid)], { encoding: "utf8" });
  const g = Number((r.stdout ?? "").trim());
  return Number.isInteger(g) && g > 1 ? g : null;
}

/** Stop the scratch stack this test autostarted: each service's whole process
 *  group (its tsx wrapper and esbuild service), never this runner's group. */
async function stopStack(pids: number[]): Promise<void> {
  const own = groupOf(process.pid);
  const groups = [...new Set(pids.map(groupOf).filter((g): g is number => g !== null && g !== own))];
  for (const g of groups) { try { process.kill(-g, "SIGTERM"); } catch { /* gone */ } }
  await new Promise((res) => setTimeout(res, 800));
  for (const g of groups) { try { process.kill(-g, "SIGKILL"); } catch { /* gone */ } }
}

test("runAgent + darwinPlatform: the agent's surviving jobs end after the chain exits (plain &, nohup, setsid, SIGTERM-ignoring); a bystander does not", { skip: SKIP, timeout: 60_000 }, async () => {
  const S = mkdtempSync("/tmp/mdu-w.");
  const pids = join(S, "pids");
  const by = bystander();
  let started: number[] = [];
  try {
    let result: Awaited<ReturnType<typeof darwinPlatform.killTree>> | undefined;
    const lines: string[] = [];
    const orig = console.error;
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    const t0 = Date.now();
    let code: number;
    try {
      code = await runAgent({
        // The agent's output goes to a file, not into this runner's TAP stream.
        argv: ["sh", "-c", `exec >${join(S, "out")} 2>&1\n` + jobsScript(pids, 1)],
        env: { ...process.env }, cwd: S, detached: true,
        tree: {
          track: (pid) => darwinPlatform.trackTree(pid, { intervalMs: 200 }),
          end: async (t) => (result = await darwinPlatform.killTree(t, { graceMs: 1000 })),
        },
      });
    } finally {
      console.error = orig;
    }
    const elapsed = Date.now() - t0;
    started = readPids(pids);
    assert.equal(code, 0);
    assert.equal(started.length, 4, `four jobs recorded their pids: ${started}`);
    for (const p of started) assert.equal(alive(p), false, `job ${p} ended with the session`);
    assert.ok(result, "killTree ran");
    for (const p of started) assert.ok(result!.terminated.includes(p), `job ${p} was sent SIGTERM: ${JSON.stringify(result)}`);
    // The TERM-ignoring `sh` (and its sleep, which inherits the ignored TERM) needed SIGKILL.
    assert.ok(result!.killed.includes(started[2]!), `the SIGTERM-ignoring job got SIGKILL: ${JSON.stringify(result)}`);
    assert.deepEqual(result!.survivors, []);
    assert.equal(lines.length, 1, JSON.stringify(lines));
    assert.match(lines[0]!, /^mandu: the session ended, so \d+ processes the agent left running were stopped \(pid /);
    assert.ok(alive(by), "the bystander (same user, not the agent's) is untouched");
    assert.ok(alive(process.pid));
    assert.ok(elapsed < 20_000, `teardown is bounded: ${elapsed} ms`);
  } finally {
    killAll([...started, by]);
    rmSync(S, { recursive: true, force: true });
  }
});

/** Pids from the runtime registry the autostart wrote: the instance arbiter and the dashboard. */
function stackPids(rt: string): { arbiter: number[]; dashboard: number[] } {
  const pidsIn = (dir: string, file: (n: string) => string | null): number[] => {
    if (!existsSync(dir)) return [];
    const out: number[] = [];
    for (const n of readdirSync(dir)) {
      const f = file(n);
      if (!f || !existsSync(f)) continue;
      try {
        const pid = (JSON.parse(readFileSync(f, "utf8")) as { pid?: unknown }).pid;
        if (typeof pid === "number") out.push(pid);
      } catch { /* torn entry */ }
    }
    return out;
  };
  return {
    arbiter: pidsIn(join(rt, "instances"), (n) => join(rt, "instances", n, "manifest.json")),
    dashboard: pidsIn(join(rt, "dashboards"), (n) => (n.endsWith(".json") ? join(rt, "dashboards", n) : null)),
  };
}

test("the real launch path: `mandu --target shell -- sh -c '… & echo started'` in mode secrets ends the agent's jobs inside the Seatbelt wrap and leaves Mandu's own services running", { skip: SKIP, timeout: 180_000 }, async () => {
  // Scratch everything: HOME, TMPDIR, a SHORT runtime dir (the socket-path limit).
  const S = mkdtempSync("/tmp/mdu-w.");
  const home = join(S, "home");
  const ws = join(S, "ws");
  const rt = join(S, "rt");
  for (const d of [home, ws, rt, join(S, "tmp"), join(home, ".aws")]) mkdirSync(d, { recursive: true });
  writeFileSync(join(home, ".gitconfig"), "[user]\n\tname = Mandu Test\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = master\n");
  // A fake credential in the catalog: the launch confines it, so the chain runs under sandbox-exec.
  writeFileSync(join(home, ".aws", "credentials"),
    "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n");
  const pids = join(S, "pids");
  const by = bystander();
  let started: number[] = [];
  let stack: { arbiter: number[]; dashboard: number[] } = { arbiter: [], dashboard: [] };
  try {
    const agent =
      `cat ${join(home, ".aws", "credentials")} >/dev/null 2>&1 && echo CREDENTIAL-READABLE || echo CREDENTIAL-DENIED; ` +
      jobsScript(pids, 3);
    const r = await runCli(["--target", "shell", "--", "sh", "-c", agent], {
      HOME: home, TMPDIR: join(S, "tmp"), PWD: ws, USER: process.env["USER"], LOGNAME: process.env["LOGNAME"],
      MANDU_RUNTIME_DIR: rt, MANDU_CONFIG: "/dev/null", MANDU_MODE: "secrets", ...axesEnv("secrets"),
      MANDU_HOME: join(S, "mandu-home"),
    });
    started = readPids(pids);
    stack = stackPids(rt);
    const why = `\nstdout: ${r.stdout}\nstderr: ${r.stderr}`;
    assert.equal(r.code, 0, why);
    assert.match(r.stdout, /^started$/m, why);
    assert.match(r.stdout, /CREDENTIAL-DENIED/, "the jobs ran inside the Seatbelt wrap" + why);
    assert.equal(started.length, 4, `four jobs recorded their pids: ${started}` + why);
    for (const p of started) assert.equal(alive(p), false, `job ${p} ended with the session` + why);
    assert.match(r.stderr, /^mandu: the session ended, so \d+ processes the agent left running were stopped \(pid /m, why);
    assert.ok(alive(by), "the bystander is untouched");
    // Mandu's own services are not the agent's: the autostarted stack keeps running.
    assert.ok(stack.arbiter.length >= 1 && stack.dashboard.length >= 1, `the stack registered: ${JSON.stringify(stack)}` + why);
    for (const p of [...stack.arbiter, ...stack.dashboard]) assert.ok(alive(p), `Mandu service ${p} still runs`);
  } finally {
    killAll([...started, by]);
    // We own this scratch stack (the dashboard supervises the arbiter): stop both.
    const now = stackPids(rt);
    await stopStack([...new Set([...stack.dashboard, ...stack.arbiter, ...now.dashboard, ...now.arbiter])]);
    rmSync(S, { recursive: true, force: true });
  }
});
