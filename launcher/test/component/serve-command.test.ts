/**
 * serve-command.test (component) — `mandu serve` against a REAL dashboard and
 * arbiter that a fake systemd (test/lib/fake-systemd.ts) starts from the unit
 * file `mandu serve install` rendered, on the test's own runtime dir
 * (runtime-instances.md §4.1d). The host's real user manager is never
 * called: the fake runs the unit's ExecStart with only a user manager's
 * environment plus the unit's own Environment= lines, so the unit has to
 * carry everything the stack needs.
 *
 * The story, in order:
 *   1. a launch autostarts the stack (no service yet): an ownerless dashboard
 *      and its arbiter, outside any unit;
 *   2. `mandu serve install` writes the unit, replaces that outside stack (no
 *      session uses it) and starts the unit: one arbiter, the unit's own;
 *   3. `mandu serve status` reports the unit, the arbiter (the service's own,
 *      this mandu's release) and the dashboard;
 *   4. a launch afterwards ATTACHES to the unit's arbiter: no second arbiter,
 *      no second dashboard, the agent handed the `current` spelling;
 *   5. `stop`, then `start`, then `uninstall`, each over the real processes.
 */
import { test } from "node:test";
import "../lib/private-home.js"; // daemons' npm cache, the Mandu home and agent trust files go to temp (test-organization.md §8.4)
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { main } from "../lib/launch-in-dir.js";
import { stateAxes } from "../axes.js";
import { sweepRuntimeProcesses } from "../lib/runtime-sweep.js";
import { FakeSystemd } from "../lib/fake-systemd.js";
import { realServeDeps, runServe, SERVE_EXIT, type ServeDeps } from "../../src/serve-command.js";
import { parseUnitFile, SERVE_UNIT } from "../../src/serve-unit.js";
import { Layout } from "../../src/services/layout.js";

stateAxes("off"); // the service's wiring is axis-independent; the launches state theirs through the default mode

const HERE = dirname(fileURLToPath(import.meta.url));
const FAKE_AGENT = join(HERE, "..", "fixtures", "fake-agent.sh");

function manifestsOf(base: string): { pid: number; sockPath: string }[] {
  const dir = join(base, "instances");
  if (!existsSync(dir)) return [];
  const out: { pid: number; sockPath: string }[] = [];
  for (const id of readdirSync(dir)) {
    const m = join(dir, id, "manifest.json");
    try { if (existsSync(m)) out.push(JSON.parse(readFileSync(m, "utf8"))); } catch { /* torn */ }
  }
  return out;
}

function dashboardPidsOf(base: string): number[] {
  const dir = join(base, "dashboards");
  if (!existsSync(dir)) return [];
  const pids: number[] = [];
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".json"))) {
    try {
      const m = JSON.parse(readFileSync(join(dir, f), "utf8")) as { pid?: unknown };
      if (typeof m.pid === "number") pids.push(m.pid);
    } catch { /* torn */ }
  }
  return pids;
}

function alive(pid: number): boolean {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    return !/^[ZX]/.test(stat.slice(stat.lastIndexOf(")") + 2));
  } catch {
    return false;
  }
}

async function until(pred: () => boolean, ms = 30_000): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (pred()) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return pred();
}

test("mandu serve: install replaces a launch's stack, a later launch attaches to the service's arbiter", {
  timeout: 600_000, skip: process.platform !== "linux" ? "Linux only (/proc, systemd)" : false,
}, async () => {
  chmodSync(FAKE_AGENT, 0o755);
  // Short, under /tmp: the arbiter's instance socket must fit sun_path.
  const tmp = realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "mdu-sv-")));
  const base = join(tmp, "mandu");
  const manduHome = join(tmp, "mandu-home");
  const xdg = join(tmp, "xdg");
  mkdirSync(xdg, { mode: 0o700 });
  const unitPath = join(tmp, "config", "systemd", "user", SERVE_UNIT);
  const saved = { MANDU_HOME: process.env["MANDU_HOME"], MANDU_ARBITER_SOCK: process.env["MANDU_ARBITER_SOCK"] };
  // The launch's autostart spawns from process.env: never the host's Mandu home.
  process.env["MANDU_HOME"] = manduHome;
  delete process.env["MANDU_ARBITER_SOCK"];
  const fake = new FakeSystemd(unitPath, { HOME: process.env["HOME"] ?? tmp, XDG_RUNTIME_DIR: xdg, USER: process.env["USER"] ?? "u" }, join(tmp, "unit.log"));
  const serveEnv = {
    HOME: process.env["HOME"], PATH: process.env["PATH"], TMPDIR: tmp,
    XDG_CONFIG_HOME: join(tmp, "config"),
    MANDU_RUNTIME_DIR: base, MANDU_HOME: manduHome,
    // A free port: the host's own dashboard may hold 4500.
    DASHBOARD_PORT: "0",
  };
  const layout = Layout.detect(new URL("../../src/run.ts", import.meta.url).href, {});
  let out = "";
  let err = "";
  const deps: ServeDeps = {
    ...realServeDeps(layout, serveEnv),
    systemctl: fake.run,
    unitOfPid: (pid) => (fake.inUnit(pid) ? SERVE_UNIT : null),
    // Only this test's stack is judged: the host's own services never count.
    otherService: () => null,
    linger: () => true,
    out: (s) => { out += s; },
    err: (s) => { err += s; },
  };
  const serve = async (...args: string[]): Promise<number> => {
    out = ""; err = "";
    return runServe(args, serveEnv, deps);
  };
  const launch = async (outFile: string): Promise<number> => main(
    ["--target", "claude", "--no-scope", "--", "bash", "-c", `${FAKE_AGENT} > ${outFile} 2>&1`],
    {
      HOME: process.env["HOME"], PWD: tmp, PATH: process.env["PATH"],
      MANDU_HOME: manduHome, MANDU_NO_CONTEXT_PROXY: "1", MANDU_RUNTIME_DIR: base, TMPDIR: tmp,
    },
  );
  try {
    // 1. A launch's autostart: the stack outside any unit.
    assert.equal(await launch(join(tmp, "a.json")), 0);
    const first = manifestsOf(base);
    assert.equal(first.length, 1, "the launch autostarted one arbiter");
    const outsideArbiter = first[0]!.pid;
    assert.ok(await until(() => dashboardPidsOf(base).length === 1), "its supervisor dashboard registered");
    const outsideDash = dashboardPidsOf(base)[0]!;
    assert.equal(fake.inUnit(outsideArbiter), false);

    // 2. install: the unit written for this mandu, the outside stack replaced, the unit started.
    const rc = await serve("install");
    assert.equal(rc, SERVE_EXIT.ok, `install: ${out}${err}\nunit log:\n${existsSync(join(tmp, "unit.log")) ? readFileSync(join(tmp, "unit.log"), "utf8").slice(-3000) : ""}`);
    const unit = parseUnitFile(readFileSync(unitPath, "utf8"));
    assert.equal(unit.ours, true);
    assert.equal(unit.environment["MANDU_RUNTIME_DIR"], base, "a stack of its own: the literal runtime dir");
    assert.equal(unit.environment["MANDU_HOME"], manduHome, "the Mandu home carried");
    assert.equal(unit.environment["DASHBOARD_PORT"], "0");
    assert.ok(fake.calls.includes("daemon-reload") && fake.calls.includes(`enable ${SERVE_UNIT}`) && fake.calls.includes(`start ${SERVE_UNIT}`));
    assert.match(out, /stopping the Mandu services that run for .* outside the service/);
    assert.ok(await until(() => !alive(outsideArbiter) && !alive(outsideDash)), "the outside arbiter and dashboard were stopped");
    assert.ok(await until(() => manifestsOf(base).length === 1), "one arbiter on the stack");
    const served = manifestsOf(base)[0]!;
    assert.notEqual(served.pid, outsideArbiter);
    assert.equal(fake.inUnit(served.pid), true, "the stack's arbiter is the unit's own process");
    assert.ok(await until(() => dashboardPidsOf(base).length === 1 && fake.inUnit(dashboardPidsOf(base)[0]!)), "one dashboard, the unit's");
    assert.match(out, /running: the arbiter at .*current\/arbiter\.sock \(pid \d+\), the dashboard at http:\/\/127\.0\.0\.1:\d+\//);

    // 3. status: the unit, its own arbiter of this release, the dashboard answering.
    assert.equal(await serve("status"), SERVE_EXIT.ok, out);
    assert.match(out, /^Mandu service \(mandu serve\): running\n/);
    assert.match(out, new RegExp(`arbiter: +answering at ${base}/current/arbiter\\.sock \\(Mandu [^,]+, pid ${served.pid}, the service's own\\)`));
    assert.match(out, /the arbiter matches it/);
    assert.match(out, /dashboard: +http:\/\/127\.0\.0\.1:\d+\/\n/);
    assert.match(out, /unit file: .*\(current\)/);

    // 4. A launch afterwards attaches: no second arbiter, no second dashboard.
    assert.equal(await launch(join(tmp, "b.json")), 0);
    const got = JSON.parse(readFileSync(join(tmp, "b.json"), "utf8")) as { arbiter: string };
    assert.equal(got.arbiter, join(base, "current", "arbiter.sock"), "the agent got the current spelling");
    const after = manifestsOf(base);
    assert.deepEqual(after.map((m) => m.pid), [served.pid], "the same arbiter: the launch attached, it started none");
    assert.equal(dashboardPidsOf(base).length, 1, "and no dashboard of its own");

    // 5. stop, start, uninstall over the real processes.
    assert.equal(await serve("stop"), SERVE_EXIT.ok, err);
    assert.ok(await until(() => !alive(served.pid)), "the dashboard stopped its arbiter with it");
    assert.equal(await serve("status"), SERVE_EXIT.deferred);
    assert.match(out, /Mandu service \(mandu serve\): inactive/);
    assert.equal(await serve("start"), SERVE_EXIT.ok, `${out}${err}`);
    const again = manifestsOf(base);
    assert.equal(again.length, 1);
    assert.equal(fake.inUnit(again[0]!.pid), true);
    assert.equal(await serve("uninstall"), SERVE_EXIT.ok, err);
    assert.equal(existsSync(unitPath), false, "the unit file removed");
    assert.ok(await until(() => !alive(again[0]!.pid)), "and the service stopped");
  } finally {
    fake.stopAll();
    for (const pid of dashboardPidsOf(base)) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
    for (const m of manifestsOf(base)) { try { process.kill(m.pid, "SIGTERM"); } catch { /* gone */ } }
    await sweepRuntimeProcesses(base);
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    rmSync(tmp, { recursive: true, force: true });
  }
});
