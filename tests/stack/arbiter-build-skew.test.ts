/**
 * arbiter-build-skew.test.ts — a launch never uses another BUILD of its own
 * Mandu release either (runtime-instances.md §4.1; reply-row-reservation.md
 * §18.2, S8: two commits of one version looked alike).
 *
 * The real launcher (`main()`, in process, from this checkout's source: its
 * own build is this checkout's rev) against REAL arbiters that report this
 * release but another build (ArbiterServer with an identity override, a fake
 * bundle hash and a rev this repository does not have; the resident ones run
 * as their own titled processes, tests/fixtures/older-arbiter.fixture.ts):
 *
 *   1. pinned: refused, both builds named, and the arbiter saw nothing but
 *      `hello`;
 *   2. the resident stack with another session on it: refused, both builds
 *      named, `mandu stop --stack <dir>`; the arbiter still runs; and the
 *      dashboard supervisor adopting it flags it STALE by its build (its own
 *      arbiter bundle hashes otherwise), not by git rev;
 *   3. the resident stack with no session: stopped and replaced by this
 *      build, which then reports this checkout's rev.
 *
 * The check is axis-independent; the launches run in `off`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { connect, createServer, type Server, type Socket } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { Supervisor } from "../../dashboard/src/supervisor/supervisor.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { sweepRuntimeProcesses } from "../../launcher/test/lib/runtime-sweep.js";
import { ndjsonCall } from "../../launcher/src/secret-setup.js";
import { launcherVersion } from "../../launcher/src/update-check.js";
import { arbiterRevOf } from "../../launcher/src/arbiter.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("off"); // the release check is axis-independent; `off` keeps the restart leg free of confinement

const HERE = dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = join(HERE, "..");
const REPO = join(TESTS_DIR, "..");
const FIXTURE = join(TESTS_DIR, "fixtures", "older-arbiter.fixture.ts");
const FAKE_AGENT = join(TESTS_DIR, "..", "launcher", "test", "fixtures", "fake-agent.sh");
const OURS = launcherVersion();
/** This checkout's rev: the launcher's own build from source. */
const REV = arbiterRevOf(REPO);
/** The other build: a bundle hash and a rev this repository does not have. */
const FAKE_BUNDLE = "f00df00df00df00d";
const FAKE_REV = "0000000";
const NO_GIT = REV === "nogit" ? "no git checkout here: the launcher's own build from source is its rev" : false;
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const BOTH = new RegExp(esc(`another build of Mandu ${OURS} (bundle ${FAKE_BUNDLE}, rev ${FAKE_REV}) than this mandu (rev ${REV})`));

function shortTmp(tag: string): string {
  return realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : TESTS_DIR, `mdu-${tag}-`)));
}

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
function opTap(path: string, upstream: string): Promise<{ ops: string[]; close: () => Promise<void> }> {
  const ops: string[] = [];
  const conns = new Set<Socket>();
  const server: Server = createServer((c) => {
    const up = connect(upstream);
    conns.add(c); conns.add(up);
    let buf = "";
    c.on("data", (chunk: Buffer) => {
      buf += chunk.toString("utf8");
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        try { ops.push((JSON.parse(buf.slice(0, nl)) as { op: string }).op); } catch { /* not a request */ }
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

function launchEnv(tmp: string, extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    HOME: process.env["HOME"], PATH: process.env["PATH"], PWD: tmp,
    MANDU_HOME: join(tmp, "home"), MANDU_NO_CONTEXT_PROXY: "1", TMPDIR: tmp,
    ...extra,
  };
}

/** The other build as the resident arbiter under `base`; resolves once promoted. */
async function startOtherBuild(base: string, stateDir: string): Promise<ChildProcess> {
  const child = spawn(process.execPath, ["--import", "tsx", FIXTURE, base, OURS, stateDir, FAKE_BUNDLE, FAKE_REV], {
    cwd: TESTS_DIR, detached: true, stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, MANDU_RUNTIME_DIR: base, MANDU_HOME: join(stateDir, "home") },
  });
  let out = "";
  let err = "";
  child.stdout!.on("data", (c) => { out += c; });
  child.stderr!.on("data", (c) => { err += c; });
  const deadline = Date.now() + 60_000;
  while (!out.includes("ready ")) {
    if (child.exitCode !== null || Date.now() > deadline) throw new Error(`the other build's arbiter did not start: ${err}`);
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

test("pinned: another build of this release is refused before any session op, naming both builds", { skip: NO_GIT }, async () => {
  const tmp = shortTmp("vbp");
  const real = join(tmp, "real.sock");
  const tapped = join(tmp, "a.sock");
  const server = new ArbiterServer({
    socketPath: real, dbPath: join(tmp, "symbols.db"), eventDir: join(tmp, "events"), log: () => {},
    identity: { instanceId: null, gitRev: FAKE_REV, gitDirty: false, build: { bundle: FAKE_BUNDLE, rev: FAKE_REV } },
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
    assert.match(r.error!.message, BOTH);
    assert.match(r.error!.message, /\(MANDU_ARBITER_SOCK, pid \d+\) runs .*refusing to launch against another build/);
    assert.ok(!existsSync(out), "the agent never ran");
    assert.deepEqual([...new Set(tap.ops)], ["hello"], `only hello reached the arbiter: ${JSON.stringify(tap.ops)}`);
    assert.ok(!existsSync(join(tmp, "rt", "release-check")), "a pinned launch writes nothing in the runtime dir");
  } finally {
    await tap.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("resident: another build a session uses is refused and left running; the dashboard flags it STALE by build", { skip: NO_GIT }, async () => {
  const tmp = shortTmp("vbr");
  const base = join(tmp, "mandu");
  mkdirSync(base, { recursive: true });
  const other = await startOtherBuild(base, tmp);
  const peer = spawn(process.execPath, ["-e", "process.title = 'mandu'; setInterval(() => {}, 1 << 30);"], {
    detached: true, stdio: "ignore", env: { ...process.env, MANDU_RUNTIME_DIR: base },
  });
  const current = join(base, "current", "arbiter.sock");
  let sup: Supervisor | null = null;
  try {
    await new Promise((r) => setTimeout(r, 300)); // the title is set
    const r = await capturingStderr(() => main(
      ["--target", "claude", "--no-scope", "--", "true"],
      launchEnv(tmp, { MANDU_RUNTIME_DIR: base }),
    ));
    assert.ok(r.error, `the launch is refused (exit ${r.value})`);
    const m = r.error!.message;
    assert.match(m, BOTH);
    assert.match(m, new RegExp(`another mandu session uses them \\(pid ${peer.pid}\\)`));
    assert.ok(m.endsWith(`mandu stop --stack ${base}`), m);
    assert.ok(alive(other.pid!), "the other build's arbiter was not stopped");
    assert.deepEqual((await helloAt(current))["build"], { bundle: FAKE_BUNDLE, rev: FAKE_REV }, "and still answers");

    // The dashboard supervisor adopting it: its own arbiter bundle (a
    // checkout's build here) hashes to something else, so it is STALE by
    // build, ahead of the rev rule.
    const dist = join(tmp, "launcher", "dist");
    mkdirSync(dist, { recursive: true });
    writeFileSync(join(dist, "arbiter.mjs"), "// this dashboard's arbiter bundle\n");
    sup = new Supervisor({
      repoRoot: REPO, arbiterSock: current, checkoutDist: dist, logDir: join(tmp, "dash-logs"), log: () => {},
      startTimeoutMs: 4000, stopGraceMs: 800,
      definitions: {
        arbiter: {
          label: "Arbiter", command: process.execPath, args: ["-e", "setInterval(() => {}, 1 << 30)"], cwd: tmp, env: {},
          ready: { kind: "socket", path: current }, endpoint: current,
        },
      },
    });
    await sup.start("arbiter"); // live endpoint → adopt, hello fetched
    const row = sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(row.adopted, true);
    assert.equal(row.identity?.version, OURS);
    assert.equal(row.stale, true);
    assert.match(row.staleReason!, new RegExp(esc(`another build of Mandu ${OURS} (bundle ${FAKE_BUNDLE}, rev ${FAKE_REV}) than this dashboard starts (bundle `)));
  } finally {
    if (sup) await sup.shutdownAll();
    try { process.kill(-peer.pid!, "SIGKILL"); } catch { /* gone */ }
    try { process.kill(-other.pid!, "SIGTERM"); } catch { /* gone */ }
    await sweepRuntimeProcesses(base);
    rmSync(tmp, { recursive: true, force: true });
  }
});

// The timeout covers the autostart's load-aware deadlines (runtime-instances.md §14.6).
test("resident: another build no session uses is stopped and this build starts in its place", { skip: NO_GIT, timeout: 300_000 }, async () => {
  chmodSync(FAKE_AGENT, 0o755);
  const tmp = shortTmp("vbx");
  const base = join(tmp, "mandu");
  mkdirSync(base, { recursive: true });
  const other = await startOtherBuild(base, tmp);
  const saved = { MANDU_HOME: process.env["MANDU_HOME"], MANDU_AUTOSTART_SUPERVISOR: process.env["MANDU_AUTOSTART_SUPERVISOR"], MANDU_ARBITER_SOCK: process.env["MANDU_ARBITER_SOCK"] };
  process.env["MANDU_HOME"] = join(tmp, "home");
  process.env["MANDU_AUTOSTART_SUPERVISOR"] = "0";
  delete process.env["MANDU_ARBITER_SOCK"];
  try {
    const current = join(base, "current", "arbiter.sock");
    const oldSock = (await helloAt(current))["sockPath"];
    const out = join(tmp, "out.json");
    const r = await capturingStderr(() => main(
      ["--target", "claude", "--no-scope", "--no-net-proxy", "--", "bash", "-c", `${FAKE_AGENT} > ${out} 2>&1`],
      launchEnv(tmp, { MANDU_RUNTIME_DIR: base }),
    ));
    assert.equal(r.error, undefined, `the launch ran: ${r.error?.message}\n${r.lines.join("\n")}`);
    assert.equal(r.value, 0);
    assert.ok(r.lines.some((l) => BOTH.test(l) && l.endsWith("restarting them as this build")), `the restart is said: ${r.lines.join("\n")}`);

    const deadline = Date.now() + 10_000;
    while (alive(other.pid!) && Date.now() < deadline) await new Promise((res) => setTimeout(res, 50));
    assert.ok(!alive(other.pid!), "the other build's arbiter was stopped");
    const hello = await helloAt(current);
    assert.equal(hello["version"], OURS);
    assert.deepEqual(hello["build"], { bundle: null, rev: REV }, "the arbiter on the rendezvous is this build");
    assert.notEqual(hello["sockPath"], oldSock, "a new instance");
    assert.equal(JSON.parse(readFileSync(out, "utf8")).arbiter, current, "the agent got the current spelling");
    assert.deepEqual(existsSync(join(base, "release-check")) ? readdirSync(join(base, "release-check")) : [], [],
      "no pending marker or lock is left behind");
  } finally {
    try { process.kill(-other.pid!, "SIGTERM"); } catch { /* gone */ }
    await sweepRuntimeProcesses(base);
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    rmSync(tmp, { recursive: true, force: true });
  }
});
