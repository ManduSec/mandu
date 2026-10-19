/**
 * arbiter-version-skew.test.ts — a launch never uses an arbiter of another
 * Mandu release (runtime-instances.md §4.1; reply-row-reservation.md §18.6).
 *
 * The real launcher (`main()`, in process) against REAL arbiters that say
 * they are another release (ArbiterServer with an identity override; the
 * resident ones run as their own titled processes, tests/fixtures/
 * older-arbiter.fixture.ts):
 *
 *   1. a pinned arbiter of an older release, or of one from before the
 *      check: refused, and the arbiter saw nothing but `hello` (no session,
 *      no event, no launch record);
 *   2. the account's resident stack of an older release, another `mandu`
 *      session on it: refused, naming `mandu stop --stack <dir>`; the old
 *      arbiter still runs;
 *   3. the same with no session: the old stack is stopped, this release's
 *      starts in its place (instance mode, promoted), the agent runs against
 *      it, and the new arbiter reports this release.
 *
 * The check is axis-independent; the launches run in `off` so the restart
 * leg needs no confinement (the refusals come before any).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, chmodSync } from "node:fs";
import { connect, createServer, type Server, type Socket } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { sweepRuntimeProcesses } from "../../launcher/test/lib/runtime-sweep.js";
import { ndjsonCall } from "../../launcher/src/secret-setup.js";
import { launcherVersion } from "../../launcher/src/update-check.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("off"); // the release check is axis-independent; `off` keeps the restart leg free of confinement

const HERE = dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = join(HERE, "..");
const FIXTURE = join(TESTS_DIR, "fixtures", "older-arbiter.fixture.ts");
const FAKE_AGENT = join(TESTS_DIR, "..", "launcher", "test", "fixtures", "fake-agent.sh");
const OURS = launcherVersion();

/** A short private dir (a Unix socket path must fit sun_path). */
function shortTmp(tag: string): string {
  return realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : TESTS_DIR, `mdu-${tag}-`)));
}

/** console.error lines while `fn` runs (the launcher's notes and refusals). */
async function capturingStderr<T>(fn: () => Promise<T>): Promise<{ value?: T; error?: Error; lines: string[] }> {
  const lines: string[] = [];
  const orig = console.error;
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  try {
    return { value: await fn(), lines };
  } catch (e) {
    return { error: e as Error, lines };
  } finally {
    console.error = orig;
  }
}

/** A relay in front of `upstream` that records every op the launcher sends. */
function opTap(path: string, upstream: string): Promise<{ ops: Array<{ op: string; sessionKey?: unknown }>; close: () => Promise<void> }> {
  const ops: Array<{ op: string; sessionKey?: unknown }> = [];
  const conns = new Set<Socket>();
  const server: Server = createServer((c) => {
    const up = connect(upstream);
    conns.add(c); conns.add(up);
    let buf = "";
    c.on("data", (chunk: Buffer) => {
      buf += chunk.toString("utf8");
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        try { const r = JSON.parse(buf.slice(0, nl)) as { op: string; sessionKey?: unknown }; ops.push({ op: r.op, sessionKey: r.sessionKey }); } catch { /* not a request */ }
        buf = buf.slice(nl + 1);
      }
      up.write(chunk);
    });
    up.pipe(c);
    c.on("error", () => up.destroy());
    up.on("error", () => c.destroy());
    c.on("close", () => up.destroy());
  });
  return new Promise((resolve) => server.listen(path, () => resolve({
    ops,
    close: () => new Promise<void>((r) => { for (const s of conns) s.destroy(); server.close(() => r()); }),
  })));
}

/** The launch's env: hermetic home, runtime dir and scope dir root. */
function launchEnv(tmp: string, extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    HOME: process.env["HOME"], PATH: process.env["PATH"], PWD: tmp,
    MANDU_HOME: join(tmp, "home"), MANDU_NO_CONTEXT_PROXY: "1", TMPDIR: tmp,
    ...extra,
  };
}

for (const older of ["0.1.0", "none"] as const) {
  test(`pinned: an arbiter of ${older === "none" ? "a release from before the check" : `Mandu ${older}`} is refused before any session op`, async () => {
    const tmp = shortTmp("vsp");
    const real = join(tmp, "real.sock");
    const tapped = join(tmp, "a.sock");
    const server = new ArbiterServer({
      socketPath: real, dbPath: join(tmp, "symbols.db"), eventDir: join(tmp, "events"), log: () => {},
      identity: { instanceId: null, gitRev: "old0000", gitDirty: false, version: older === "none" ? null : older },
    });
    await server.listen();
    const tap = await opTap(tapped, real);
    try {
      const out = join(tmp, "out.json");
      const r = await capturingStderr(() => main(
        ["--target", "claude", "--no-scope", "--", "bash", "-c", `${FAKE_AGENT} > ${out}`],
        launchEnv(tmp, { MANDU_ARBITER_SOCK: tapped, MANDU_RUNTIME_DIR: join(tmp, "rt") }),
      ));
      assert.ok(r.error, `the launch is refused (exit ${r.value})`);
      assert.match(r.error!.message, new RegExp(`the arbiter at ${tapped} \\(MANDU_ARBITER_SOCK, pid ${process.pid}\\) runs ` +
        (older === "none" ? "an older Mandu release" : "Mandu 0\\.1\\.0") + `.*this mandu is ${OURS.replace(/\./g, "\\.")}`));
      assert.match(r.error!.message, /refusing to launch against another release/);
      assert.ok(!existsSync(out), "the agent never ran");
      assert.deepEqual([...new Set(tap.ops.map((o) => o.op))], ["hello"], `only hello reached the arbiter: ${JSON.stringify(tap.ops)}`);
      assert.ok(tap.ops.every((o) => o.sessionKey === undefined), "no session-keyed op");
    } finally {
      await tap.close();
      await server.close();
      rmSync(tmp, { recursive: true, force: true });
    }
  });
}

/** Start the older resident arbiter under `base`; resolves once promoted. */
async function startOlder(base: string, version: string, stateDir: string): Promise<ChildProcess> {
  const child = spawn(process.execPath, ["--import", "tsx", FIXTURE, base, version, stateDir], {
    cwd: TESTS_DIR, detached: true, stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, MANDU_RUNTIME_DIR: base, MANDU_HOME: join(stateDir, "home") },
  });
  let out = "";
  let err = "";
  child.stdout!.on("data", (c) => { out += c; });
  child.stderr!.on("data", (c) => { err += c; });
  const deadline = Date.now() + 60_000;
  while (!out.includes("ready ")) {
    if (child.exitCode !== null || Date.now() > deadline) throw new Error(`older arbiter did not start: ${err}`);
    await new Promise((r) => setTimeout(r, 50));
  }
  return child;
}

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

async function helloAt(sock: string): Promise<Record<string, unknown>> {
  return ndjsonCall<Record<string, unknown>>(sock, "hello", {}, 5_000);
}

test("resident: an older stack another session uses is refused, naming mandu stop --stack, and left running", async () => {
  const tmp = shortTmp("vsr");
  const base = join(tmp, "mandu");
  mkdirSync(base, { recursive: true });
  const old = await startOlder(base, "0.1.0", tmp);
  // Another `mandu` session on this stack: a process titled `mandu` whose
  // environment selects this runtime dir (how `mandu stop` places it).
  const peer = spawn(process.execPath, ["-e", "process.title = 'mandu'; setInterval(() => {}, 1 << 30);"], {
    detached: true, stdio: "ignore", env: { ...process.env, MANDU_RUNTIME_DIR: base },
  });
  try {
    await new Promise((r) => setTimeout(r, 300)); // the title is set
    const r = await capturingStderr(() => main(
      ["--target", "claude", "--no-scope", "--", "true"],
      launchEnv(tmp, { MANDU_RUNTIME_DIR: base }),
    ));
    assert.ok(r.error, `the launch is refused (exit ${r.value})`);
    const m = r.error!.message;
    assert.match(m, /the Mandu services running for you .* are Mandu 0\.1\.0, but this mandu is/);
    assert.match(m, new RegExp(`another mandu session uses them \\(pid ${peer.pid}\\)`));
    assert.ok(m.endsWith(`mandu stop --stack ${base}`), m);
    assert.ok(alive(old.pid!), "the older arbiter was not stopped");
    assert.equal((await helloAt(join(base, "current", "arbiter.sock")))["version"], "0.1.0", "and still answers");
  } finally {
    try { process.kill(-peer.pid!, "SIGKILL"); } catch { /* gone */ }
    try { process.kill(-old.pid!, "SIGTERM"); } catch { /* gone */ }
    await sweepRuntimeProcesses(base);
    rmSync(tmp, { recursive: true, force: true });
  }
});

// The timeout covers the autostart's load-aware deadlines (runtime-instances.md §14.6).
test("resident: an older stack no session uses is stopped and this release's starts in its place", { timeout: 300_000 }, async () => {
  chmodSync(FAKE_AGENT, 0o755);
  const tmp = shortTmp("vsx");
  const base = join(tmp, "mandu");
  mkdirSync(base, { recursive: true });
  const old = await startOlder(base, "none", tmp);
  // The autostart spawns from process.env (main()'s env feeds the plan): keep
  // the new stack's home in temp, and skip the dashboard supervisor (the bare
  // arbiter is what this proves; instance-autostart.test.ts covers the rest).
  const saved = { MANDU_HOME: process.env["MANDU_HOME"], MANDU_AUTOSTART_SUPERVISOR: process.env["MANDU_AUTOSTART_SUPERVISOR"], MANDU_ARBITER_SOCK: process.env["MANDU_ARBITER_SOCK"] };
  process.env["MANDU_HOME"] = join(tmp, "home");
  process.env["MANDU_AUTOSTART_SUPERVISOR"] = "0";
  delete process.env["MANDU_ARBITER_SOCK"];
  try {
    const oldSock = (await helloAt(join(base, "current", "arbiter.sock")))["sockPath"];
    const out = join(tmp, "out.json");
    // --no-net-proxy: the egress gate is not what this proves, and the
    // launch must not depend on it here.
    const r = await capturingStderr(() => main(
      ["--target", "claude", "--no-scope", "--no-net-proxy", "--", "bash", "-c", `${FAKE_AGENT} > ${out} 2>&1`],
      launchEnv(tmp, { MANDU_RUNTIME_DIR: base }),
    ));
    assert.equal(r.error, undefined, `the launch ran: ${r.error?.message}\n${r.lines.join("\n")}`);
    assert.equal(r.value, 0);
    assert.ok(r.lines.some((l) => l.includes("were an older Mandu release (one that does not report its version); restarting them as Mandu " + OURS)),
      `the restart is said: ${r.lines.join("\n")}`);

    // The older arbiter is gone; this release's answers on the rendezvous.
    const deadline = Date.now() + 10_000;
    while (alive(old.pid!) && Date.now() < deadline) await new Promise((res) => setTimeout(res, 50));
    assert.ok(!alive(old.pid!), "the older arbiter was stopped");
    const current = join(base, "current", "arbiter.sock");
    const hello = await helloAt(current);
    assert.equal(hello["version"], OURS, "the arbiter on the rendezvous is this release");
    assert.notEqual(hello["sockPath"], oldSock, "a new instance");
    assert.equal(JSON.parse(readFileSync(out, "utf8")).arbiter, current, "the agent got the current spelling");
  } finally {
    try { process.kill(-old.pid!, "SIGTERM"); } catch { /* gone */ }
    await sweepRuntimeProcesses(base);
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    rmSync(tmp, { recursive: true, force: true });
  }
});
