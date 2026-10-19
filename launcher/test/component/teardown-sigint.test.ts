/**
 * teardown-sigint.test — E2E: a ^C while the launcher tears down does not
 * stop the teardown (src/teardown-signals.ts; portable-wrapper.md §2.1
 * "Teardown signals"; differential-interactive.md §21).
 *
 * The real launcher runs as its own process (`node --import tsx src/run.ts`)
 * in a process group of its own, the way a terminal's foreground job is, and
 * the test sends SIGINT to that GROUP, which is what the kernel does with a ^C
 * once the reply filter's script(1) has put the terminal back in cooked mode.
 * A real context proxy is started (port 0) so there is a service to stop; the
 * mock arbiter holds its answer to the session-exit event, the teardown's last
 * step, so the ^Cs provably land inside the teardown.
 *
 * The fs-view sweep is not in this launch: it runs only with the frozen
 * integrity axis on (docs/design/architecture/protection-modes.md §10), and this suite runs
 * `off`. What protects the sweep from the same ^C is that it runs in a session
 * of its own; the last two tests prove that mechanism (runOnce ownSession)
 * under a group SIGINT, and test/unit/fs-view.test.ts pins that the sweep asks
 * for it.
 *
 * The `--no-reply-filter` burst test runs the launcher under a real terminal
 * (util-linux script(1)), where a ^C byte becomes SIGINT for the foreground
 * group only once the agent has put the terminal back in cooked mode. It
 * caught the last unguarded stretch: the guard came off before the process
 * exited, and process.exit()'s own shutdown on a terminal ran long enough for
 * a ^C to kill the launcher 130 in about half the runs
 * (differential-interactive.md §21.1).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createServer, connect, type Server, type Socket } from "node:net";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { once } from "node:events";
import { answerUnavailable, unavailableReply } from "../lib/unanswered-arbiter.js";

const LAUNCHER_ROOT = resolve(fileURLToPath(import.meta.url), "..", "..", "..");
// The launch runs in its folder (cwd = PWD = dir), as a shell starts it: the
// launcher launches for its real cwd (launch-cwd.ts), so tsx is imported by path.
const TSX_LOADER = pathToFileURL(join(LAUNCHER_ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;

/** A mock arbiter that answers every request with the bare "unavailable"
 *  reply, except the `session_exit` emit, whose answer it holds until
 *  `release()` (the launcher gives up on it after 2 s by itself). */
async function holdingArbiter(dir: string): Promise<{
  sock: string;
  sessionExit: Promise<Record<string, unknown>>;
  release: () => void;
  close: () => void;
}> {
  const sock = join(dir, "arbiter.sock");
  const conns = new Set<Socket>();
  let gotExit!: (e: Record<string, unknown>) => void;
  const sessionExit = new Promise<Record<string, unknown>>((r) => { gotExit = r; });
  const held: Array<() => void> = [];
  let released = false;
  const srv: Server = createServer((s) => {
    conns.add(s);
    s.on("close", () => conns.delete(s));
    s.on("error", () => {});
    let buf = "";
    s.on("data", (d) => {
      buf += String(d);
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        const reply = () => { if (!s.destroyed) s.write(unavailableReply(line) + "\n"); };
        let ev: Record<string, unknown> | undefined;
        try {
          const req = JSON.parse(line) as { op?: string; params?: { event?: Record<string, unknown> }; event?: Record<string, unknown> };
          const e = req.params?.event ?? req.event;
          if (req.op === "emit" && e && e["kind"] === "session_exit") ev = e;
        } catch { /* not JSON */ }
        if (ev) {
          gotExit(ev);
          if (released) reply(); else held.push(reply);
        } else {
          reply();
        }
      }
    });
  });
  srv.listen(sock);
  await once(srv, "listening");
  return {
    sock,
    sessionExit,
    release: () => { released = true; for (const r of held.splice(0)) r(); },
    close: () => { srv.close(); for (const s of conns) s.destroy(); },
  };
}

function portUp(port: number): Promise<boolean> {
  return new Promise((res) => {
    const s = connect({ host: "127.0.0.1", port });
    s.once("connect", () => { s.destroy(); res(true); });
    s.once("error", () => res(false));
  });
}

async function until(check: () => boolean | Promise<boolean>, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await check()) return true;
    await new Promise((r) => setTimeout(r, 25));
  }
  return check();
}

/** Launch the real launcher, detached (its own process group), over a fake
 *  agent that ignores SIGINT, touches `marker`, lingers briefly, exits 7. */
function launch(dir: string, sock: string): { child: ChildProcess; marker: string; baseUrlFile: string; stderr: () => string; exited: Promise<[number | null, NodeJS.Signals | null]> } {
  const marker = join(dir, "agent-exiting");
  const baseUrlFile = join(dir, "base-url.txt");
  const fake = join(dir, "fake-agent.sh");
  writeFileSync(fake, [
    "#!/usr/bin/env bash",
    // Ignore the ^Cs the launcher forwards while the agent still runs, so the
    // agent's own exit code is the one under test.
    "trap '' INT",
    `printf '%s' "\${ANTHROPIC_BASE_URL:-}" > ${baseUrlFile}`,
    `touch ${marker}`,
    "sleep 0.3",
    "exit 7",
    "",
  ].join("\n"));
  chmodSync(fake, 0o755);
  const child = spawn(process.execPath, [
    "--import", TSX_LOADER, join(LAUNCHER_ROOT, "src", "run.ts"),
    "--target", "claude", "--no-net-proxy", "--no-scope", "--no-reply-filter", "--", "bash", fake,
  ], {
    cwd: dir,
    detached: true, // a process group of its own: the terminal's foreground job
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      HOME: process.env["HOME"], PATH: process.env["PATH"], PWD: dir, XDG_RUNTIME_DIR: dir,
      MANDU_ARBITER_SOCK: sock, MANDU_MCP_CONFIG: join(dir, ".mcp.json"), MANDU_PROXY_PORT: "0",
      MANDU_HOME: join(dir, "mandu-home"), MANDU_MODE: "off", MANDU_NO_ARBITER_AUTOSTART: "1",
    },
  });
  let err = "";
  child.stderr!.on("data", (d) => { err += String(d); });
  child.stdout!.resume();
  const exited = new Promise<[number | null, NodeJS.Signals | null]>((r) => child.on("exit", (c, s) => r([c, s])));
  return { child, marker, baseUrlFile, stderr: () => err, exited };
}

test("^C (a group SIGINT) through the whole teardown: the launcher finishes it and exits with the AGENT's code", { timeout: 90_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-teardown-int-"));
  const arb = await holdingArbiter(dir);
  let run: ReturnType<typeof launch> | undefined;
  try {
    run = launch(dir, arb.sock);
    const r = run;
    assert.ok(await until(() => existsSync(r.marker), 60_000), `the agent never ran: ${r.stderr()}`);
    // From here the human mashes ^C: every 50 ms, to the launcher's group,
    // across the agent's exit, the service stop and the session-exit event.
    let exitedYet = false;
    void r.exited.then(() => { exitedYet = true; });
    let afterSessionExit = 0;
    let sessionExitSeen = false;
    void arb.sessionExit.then(() => { sessionExitSeen = true; });
    const presser = (async () => {
      while (!exitedYet) {
        try { process.kill(-r.child.pid!, "SIGINT"); } catch { break; }
        if (sessionExitSeen) afterSessionExit++;
        await new Promise((res) => setTimeout(res, 50));
      }
    })();
    const ev = await Promise.race([
      arb.sessionExit,
      r.exited.then(([c, s]) => { throw new Error(`the launcher exited (${c ?? s}) before its session-exit event: ${r.stderr()}`); }),
    ]);
    // Keep the teardown's last step open while at least 5 more ^Cs land.
    assert.ok(await until(() => afterSessionExit >= 5 || exitedYet, 5_000));
    arb.release();
    const [code, sig] = await r.exited;
    await presser;
    assert.equal(sig, null, `the launcher was killed by ${sig}: ${r.stderr()}`);
    assert.equal(code, 7, `exit code is the agent's 7, not 130: ${r.stderr()}`);
    assert.ok(afterSessionExit >= 5, `the ^Cs landed inside the teardown (${afterSessionExit} after the session-exit event)`);
    assert.equal(ev["code"], 7, "the session-exit event, the teardown's last step, was sent with the agent's code");
    assert.equal(r.stderr().match(/\^C is ignored until that is done/g)?.length, 1, `one note: ${r.stderr()}`);
    // The services were stopped: the context proxy the agent was pointed at is gone.
    const m = readFileSync(r.baseUrlFile, "utf8").match(/^http:\/\/127\.0\.0\.1:(\d+)$/);
    assert.ok(m, "the agent saw the context proxy's base URL");
    assert.ok(await until(async () => !(await portUp(Number(m![1]))), 5_000), "the context proxy was stopped");
  } finally {
    arb.release();
    if (run && run.child.exitCode === null && run.child.signalCode === null) { try { process.kill(-run.child.pid!, "SIGKILL"); } catch { /* gone */ } }
    arb.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("SIGTERM during the teardown still ends the launcher at once (a supervisor's stop is not deferred)", { timeout: 90_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-teardown-term-"));
  const arb = await holdingArbiter(dir);
  let run: ReturnType<typeof launch> | undefined;
  try {
    run = launch(dir, arb.sock);
    const r = run;
    // Inside the teardown, its last step held open.
    await Promise.race([
      arb.sessionExit,
      r.exited.then(([c, s]) => { throw new Error(`the launcher exited (${c ?? s}) before its session-exit event: ${r.stderr()}`); }),
    ]);
    const t0 = Date.now();
    process.kill(run.child.pid!, "SIGTERM");
    const [code, sig] = await run.exited;
    assert.equal(sig, "SIGTERM", `ended by the signal, not by finishing the teardown (code ${code})`);
    assert.ok(Date.now() - t0 < 1_500, "promptly: well before the held event's own 2 s deadline");
  } finally {
    arb.release();
    if (run && run.child.exitCode === null && run.child.signalCode === null) { try { process.kill(-run.child.pid!, "SIGKILL"); } catch { /* gone */ } }
    arb.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

/** A stand-in launcher: arms the teardown guard, then runs a 0.8 s one-shot
 *  (the sweep's shape) through runOnce, with or without ownSession, and
 *  exits 0 only if the one-shot completed. */
function sweepHost(dir: string, ownSession: boolean): { child: ChildProcess; done: string } {
  const done = join(dir, `sweep-done-${ownSession}`);
  const src = `
    import { createTeardownGuard } from ${JSON.stringify(join(LAUNCHER_ROOT, "src", "teardown-signals.ts"))};
    import { runOnce } from ${JSON.stringify(join(LAUNCHER_ROOT, "src", "services", "primitives.ts"))};
    createTeardownGuard({ note: () => {} }).arm();
    process.stdout.write("sweeping\\n");
    const r = runOnce("bash", ["-c", "sleep 0.8; echo ok > ${done}"], { cwd: "/tmp", env: process.env, ownSession: ${ownSession} });
    process.exit(r.status === 0 ? 0 : 1);
  `;
  const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", src], {
    cwd: LAUNCHER_ROOT, detached: true, stdio: ["ignore", "pipe", "ignore"],
  });
  return { child, done };
}

async function groupSigintDuringSweep(ownSession: boolean): Promise<{ code: number | null; completed: boolean }> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-teardown-sweep-"));
  try {
    const { child, done } = sweepHost(dir, ownSession);
    const exited = new Promise<number | null>((r) => child.on("exit", (c) => r(c)));
    await new Promise<void>((res) => { let o = ""; child.stdout!.on("data", (d) => { o += String(d); if (o.includes("sweeping")) res(); }); });
    await new Promise((r) => setTimeout(r, 300)); // the one-shot is running
    for (let i = 0; i < 3; i++) {
      try { process.kill(-child.pid!, "SIGINT"); } catch { /* gone */ }
      await new Promise((r) => setTimeout(r, 30));
    }
    const code = await exited;
    return { code, completed: existsSync(done) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("the sweep's shape: a one-shot in its own session survives a group ^C and completes", { timeout: 30_000 }, async () => {
  const r = await groupSigintDuringSweep(true);
  assert.equal(r.code, 0);
  assert.equal(r.completed, true);
});

test("control: the same one-shot in the launcher's group dies of the ^C part-way (why the sweep gets its own session)", { timeout: 30_000 }, async () => {
  const r = await groupSigintDuringSweep(false);
  assert.equal(r.code, 1, "the guarded host survived, its one-shot did not");
  assert.equal(r.completed, false);
});

// ── the ^C burst under a real terminal, --no-reply-filter ───────────────────

const SCRIPT_OK = (() => {
  if (process.platform !== "linux") return false;
  const r = spawnSync("script", ["--version"], { stdio: ["ignore", "pipe", "ignore"], timeout: 5000 });
  return r.status === 0 && String(r.stdout).includes("util-linux");
})();

/** A stand-in agent: ignores SIGINT, takes the terminal raw, quits on a ^C
 *  byte by putting it back in cooked mode, then exits 0 after 1.5 s. From
 *  its cooked-mode exit on, every ^C is a SIGINT for the launcher's group. */
const QUITTER = [
  "#!/usr/bin/env bash",
  "trap '' INT",
  "stty raw -echo",
  "printf 'READY\\r\\n'",
  "dd bs=1 count=1 of=/dev/null 2>/dev/null",
  "stty sane",
  "sleep 1.5",
  "exit 0",
  "",
].join("\n");

const shq = (a: string): string => `'${a.replace(/'/g, "'\\''")}'`;

/** One launch under script(1) with a ^C every 30 ms from the agent's READY
 *  to the launcher's exit; resolves with the exit code script(1) reports (the
 *  launcher's; 130 for a SIGINT death) and the ms from the first ^C. */
async function burstLaunch(dir: string, sock: string, i: number): Promise<{ code: number | null; ms: number; out: string }> {
  const fake = join(dir, `quitter-${i}.sh`);
  writeFileSync(fake, QUITTER);
  chmodSync(fake, 0o755);
  const cmd = "exec " + [process.execPath, "--import", TSX_LOADER, join(LAUNCHER_ROOT, "src", "run.ts"),
    "--target", "claude", "--no-net-proxy", "--no-scope", "--no-reply-filter", "--", "bash", fake].map(shq).join(" ");
  const child = spawn("script", ["-qefc", cmd, "/dev/null"], {
    cwd: dir,
    detached: true,
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      HOME: process.env["HOME"], PATH: process.env["PATH"], PWD: dir, XDG_RUNTIME_DIR: dir, SHELL: "/bin/bash", TERM: "xterm",
      MANDU_ARBITER_SOCK: sock, MANDU_MCP_CONFIG: join(dir, ".mcp.json"), MANDU_PROXY_PORT: "0",
      MANDU_HOME: join(dir, "mandu-home"), MANDU_MODE: "off", MANDU_NO_ARBITER_AUTOSTART: "1",
    },
  });
  let out = "";
  child.stdout!.on("data", (d) => { out += String(d); });
  child.stderr!.resume();
  child.stdin!.on("error", () => {});
  let exited = false;
  const done = new Promise<number | null>((r) => child.on("exit", (c) => { exited = true; r(c); }));
  try {
    assert.ok(await until(() => out.includes("READY") || exited, 60_000), `launch ${i}: the agent never took the terminal: ${out}`);
    const t0 = Date.now();
    const presser = (async () => {
      while (!exited) {
        child.stdin!.write("\x03");
        await new Promise((r) => setTimeout(r, 30));
      }
    })();
    const code = await Promise.race([done, new Promise<null>((r) => setTimeout(() => r(null), 30_000))]);
    const ms = Date.now() - t0;
    exited = true;
    await presser;
    return { code, ms, out };
  } finally {
    if (child.exitCode === null && child.signalCode === null) { try { process.kill(-child.pid!, "SIGKILL"); } catch { /* gone */ } }
  }
}

test("--no-reply-filter under a terminal: a ^C burst across the agent's exit and the teardown never kills the launcher; it exits 0, promptly", { skip: SCRIPT_OK ? false : "util-linux script(1) not available", timeout: 240_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-teardown-pty-"));
  const sock = join(dir, "arbiter.sock");
  const srv = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  try {
    // Before the fix about half of these died 130; six in a row is the bar.
    for (let i = 0; i < 6; i++) {
      const r = await burstLaunch(dir, sock, i);
      const tail = r.out.replace(/\^C/g, "").slice(-600);
      assert.notEqual(r.code, null, `launch ${i}: still running 30 s after the first ^C: ${tail}`);
      assert.equal(r.code, 0, `launch ${i}: exit ${r.code}, not the agent's 0 (130 = killed by a ^C): ${tail}`);
      assert.ok(r.ms < 20_000, `launch ${i}: exited ${r.ms} ms after the first ^C`);
    }
  } finally {
    srv.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
