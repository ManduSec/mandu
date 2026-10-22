/**
 * subcommands.test — the `mandu status/stop/dashboard` management verbs
 * (packaging.md §5). Pure helpers are tested directly; runStop is driven with a
 * MOCK ProcOps so no real process is signalled (never touch the shared stack).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  RESERVED_SUBCOMMANDS,
  parsePsLines,
  stopTargets,
  containerSkips,
  isContainerCgroup,
  runStop,
  parseStopArgs,
  planStop,
  defaultStack,
  operatorStack,
  normStack,
  parseEnviron,
  registeredPids,
  registryTrusted,
  runDashboard as runDashboardIn,
  dashboardForScan as dashboardForScanIn,
  registeredDashboards,
  dashboardUrl,
  leftoverSummary,
  runStatus,
  runSubcommand,
  type DashboardDeps,
  type Proc,
  type ProcOps,
  runSetupThenAccount,
} from "../../src/subcommands.js";
import type { ReapAction } from "../../src/reap.js";
import { Layout } from "../../src/services/layout.js";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hermetic } from "../lib/test-runtime.js";

/** runDashboard with this file's own runtime dir when the env names none (test-runtime.ts). */
const runDashboard = hermetic(runDashboardIn, 1);
/** dashboardForScan likewise (its env is the first argument). */
const dashboardForScan = hermetic(dashboardForScanIn, 0);

/** Collect what fn() writes through the `out` sink it is handed. (Never patch
 *  process.stdout.write: the test runner reports through the same stream, and
 *  a patch held across an await swallows the previous test's result.) */
async function captureOut(fn: (out: (s: string) => void) => Promise<unknown> | unknown): Promise<string> {
  let buf = "";
  await fn((s) => { buf += s; });
  return buf;
}

test("reserved verbs are exactly status/stop/dashboard/doctor/init/reap/setup/mode/why/revert/demo", () => {
  assert.deepEqual([...RESERVED_SUBCOMMANDS].sort(), ["dashboard", "demo", "doctor", "init", "log", "mode", "paths", "policy", "reap", "revert", "scan", "setup", "status", "stop", "version", "why"]);
});

test("parsePsLines: keeps mandu-titled procs, drops self + non-mandu, trims padding", () => {
  const ps = [
    "  100 mandu-arbiter          ", // trailing padding
    "  101 mandu",
    "  102 mandu-anthropic-proxy",
    "  103 node /some/other/thing",
    "  104 sshd: user",
    "  999 mandu-dashboard",
  ].join("\n");
  const procs = parsePsLines(ps, /* selfPid */ 999);
  assert.deepEqual(
    procs.map((p) => `${p.pid}:${p.title}`),
    ["100:mandu-arbiter", "101:mandu", "102:mandu-anthropic-proxy"],
  );
});

test("stopTargets: residents by default; everything under --all", () => {
  const procs: Proc[] = [
    { pid: 1, title: "mandu-arbiter" },
    { pid: 2, title: "mandu-dashboard" },
    { pid: 3, title: "mandu" },              // launcher — not a resident
    { pid: 4, title: "mandu-reply-filter" }, // per-session — not a resident
  ];
  assert.deepEqual(stopTargets(procs, false).map((p) => p.pid), [1, 2]);
  assert.deepEqual(stopTargets(procs, true).map((p) => p.pid), [1, 2, 3, 4]);
});

test("stopTargets: inspect-mcp is session-owned — never a default target", () => {
  const procs: Proc[] = [
    { pid: 1, title: "mandu-arbiter" },
    { pid: 2, title: "mandu-inspect-mcp" }, // owned by a live claude session
  ];
  assert.deepEqual(stopTargets(procs, false).map((p) => p.pid), [1]);
  // --all (the explicit sweep) still includes it.
  assert.deepEqual(stopTargets(procs, true).map((p) => p.pid), [1, 2]);
});

test("stopTargets/containerSkips: container-scoped procs are never signalled, even under --all", () => {
  const procs: Proc[] = [
    { pid: 1, title: "mandu-arbiter" },
    { pid: 2, title: "mandu-arbiter", container: true },   // CI container's arbiter
    { pid: 3, title: "mandu-dashboard", container: true }, // CI container's dashboard
    { pid: 4, title: "mandu", container: true },           // CI container's launcher
  ];
  assert.deepEqual(stopTargets(procs, false).map((p) => p.pid), [1]);
  assert.deepEqual(stopTargets(procs, true).map((p) => p.pid), [1]);
  assert.deepEqual(containerSkips(procs, false).map((p) => p.pid), [2, 3]);
  assert.deepEqual(containerSkips(procs, true).map((p) => p.pid), [2, 3, 4]);
});

test("isContainerCgroup: recognizes docker/containerd/podman/k8s scopes, not host slices", () => {
  // docker, systemd cgroup driver (what `docker run` produces on this host)
  assert.equal(isContainerCgroup("0::/system.slice/docker-abc123def.scope\n"), true);
  // docker, cgroupfs driver
  assert.equal(isContainerCgroup("0::/docker/abc123def\n"), true);
  // rootless podman
  assert.equal(
    isContainerCgroup("0::/user.slice/user-1001.slice/user@1001.service/user.slice/libpod-abc.scope\n"),
    true,
  );
  // kubernetes
  assert.equal(isContainerCgroup("0::/kubepods/besteffort/pod123/abc\n"), true);
  // host processes — a user session and a plain service — must NOT match
  assert.equal(isContainerCgroup("0::/user.slice/user-1001.slice/session-42.scope\n"), false);
  assert.equal(isContainerCgroup("0::/system.slice/ssh.service\n"), false);
});

test("runStop (default): SIGTERMs only resident daemons, leaves launchers alone", async () => {
  const killed: Array<[number, string]> = [];
  const ops: ProcOps = {
    list: () => [
      { pid: 10, title: "mandu-arbiter" },
      { pid: 11, title: "mandu" },              // launcher — must survive
      { pid: 12, title: "mandu-net-proxy" },
    ],
    kill: (pid, sig) => { killed.push([pid, sig]); },
  };
  const out = await captureOut((out) => runStop([], {}, ops, out));
  assert.deepEqual(killed, [[10, "SIGTERM"], [12, "SIGTERM"]]);
  assert.match(out, /stopped 2 process/);
});

test("runStop --all: SIGTERMs launchers too", async () => {
  const killed: number[] = [];
  const ops: ProcOps = {
    list: () => [
      { pid: 10, title: "mandu-arbiter" },
      { pid: 11, title: "mandu" },
    ],
    kill: (pid) => { killed.push(pid); },
  };
  await captureOut((out) => runStop(["--all"], {}, ops, out));
  assert.deepEqual(killed, [10, 11]);
});

test("runStop: container procs are reported as skipped, never killed", async () => {
  const killed: number[] = [];
  const ops: ProcOps = {
    list: () => [
      { pid: 10, title: "mandu-arbiter" },
      { pid: 20, title: "mandu-arbiter", container: true }, // CI run in flight
    ],
    kill: (pid) => { killed.push(pid); },
  };
  const out = await captureOut((out) => runStop([], {}, ops, out));
  assert.deepEqual(killed, [10]);
  assert.match(out, /\(skip\)\s+20\s+mandu-arbiter — container-scoped/);
});

// ── Stop scope (runtime-instances.md §10.3): the bare form is every stack of
// this user for the operator; an isolated caller is refused when the sweep
// would reach another stack; --stack touches only the named one.

const SHARED = "/run/user/1000/mandu";
const ISO = "/tmp/bench/run";
const OPERATOR_ENV = { XDG_RUNTIME_DIR: "/run/user/1000" };
const ISOLATED_ENV = { XDG_RUNTIME_DIR: "/run/user/1000", MANDU_RUNTIME_DIR: ISO };

/** The shared stack's dashboard + arbiter, a benchmark stack's arbiter +
 *  launcher, and a process whose stack cannot be told. */
function twoStacks(): { ops: ProcOps; killed: number[] } {
  const killed: number[] = [];
  const stacks: Record<number, string | null> = { 10: SHARED, 11: SHARED, 20: ISO, 21: ISO, 30: null };
  const ops: ProcOps = {
    list: () => [
      { pid: 10, title: "mandu-dashboard" },
      { pid: 11, title: "mandu-arbiter" },
      { pid: 20, title: "mandu-arbiter" },
      { pid: 21, title: "mandu" },
      { pid: 30, title: "mandu-net-proxy" },
    ],
    kill: (pid) => { killed.push(pid); },
    stackOf: (pid) => stacks[pid] ?? null,
  };
  return { ops, killed };
}

async function captureBoth(fn: (out: (s: string) => void, err: (s: string) => void) => Promise<number>): Promise<{ code: number; out: string; err: string }> {
  let out = "", err = "";
  const code = await fn((s) => { out += s; }, (s) => { err += s; });
  return { code, out, err };
}

test("parseStopArgs: --stack (both spellings, resolved), --every-stack, --all; contradictions and a missing dir are errors", () => {
  assert.deepEqual(parseStopArgs([]), { all: false, scope: { kind: "user" } });
  assert.deepEqual(parseStopArgs(["--all", "--every-stack"]), { all: true, scope: { kind: "every" } });
  assert.deepEqual(parseStopArgs(["--stack", "/tmp/x/"]), { all: false, scope: { kind: "stack", base: "/tmp/x" } });
  assert.deepEqual(parseStopArgs(["--stack=run", "--all"], "/tmp/bench"), { all: true, scope: { kind: "stack", base: "/tmp/bench/run" } });
  assert.ok("error" in parseStopArgs(["--stack"]));
  assert.ok("error" in parseStopArgs(["--stack", "--all"]));
  assert.ok("error" in parseStopArgs(["--stack", "/tmp/x", "--every-stack"]));
});

test("planStop: the operator's bare stop keeps its meaning — every stack, unknown included", () => {
  const { ops } = twoStacks();
  const plan = planStop({ procs: ops.list(), all: true, scope: { kind: "user" }, callerStack: SHARED, defaultStack: SHARED, stackOf: (p) => ops.stackOf!(p, []) });
  assert.deepEqual(plan.targets.map((p) => p.pid), [10, 11, 20, 21, 30]);
  assert.equal(plan.refused, undefined);
});

test("planStop: an isolated caller's bare stop is REFUSED when it would reach the shared stack (2026-10-04)", () => {
  const { ops } = twoStacks();
  const plan = planStop({ procs: ops.list(), all: false, scope: { kind: "user" }, callerStack: ISO, defaultStack: SHARED, stackOf: (p) => ops.stackOf!(p, []) });
  assert.deepEqual(plan.targets, []);
  assert.deepEqual(plan.refused!.map((p) => [p.pid, p.stack]), [[10, SHARED], [11, SHARED], [30, null]]);
});

test("planStop: an isolated caller alone on the host stops its own stack without a flag", () => {
  const procs: Proc[] = [{ pid: 20, title: "mandu-arbiter" }, { pid: 21, title: "mandu" }];
  const plan = planStop({ procs, all: true, scope: { kind: "user" }, callerStack: ISO, defaultStack: SHARED, stackOf: () => ISO });
  assert.deepEqual(plan.targets.map((p) => p.pid), [20, 21]);
  assert.equal(plan.refused, undefined);
});

test("planStop --stack: only that stack's processes; another stack's and an unknown one are left alone", () => {
  const { ops } = twoStacks();
  const plan = planStop({ procs: ops.list(), all: true, scope: { kind: "stack", base: ISO }, callerStack: SHARED, defaultStack: SHARED, stackOf: (p) => ops.stackOf!(p, []) });
  assert.deepEqual(plan.targets.map((p) => p.pid), [20, 21]);
  assert.deepEqual(plan.otherStacks.map((p) => p.pid), [10, 11, 30]);
});

test("planStop --every-stack: the sweep, said explicitly, from an isolated caller; containers still skipped", () => {
  const { ops } = twoStacks();
  const procs = [...ops.list(), { pid: 40, title: "mandu-arbiter", container: true }];
  const plan = planStop({ procs, all: false, scope: { kind: "every" }, callerStack: ISO, defaultStack: SHARED, stackOf: (p) => ops.stackOf!(p, []) });
  assert.deepEqual(plan.targets.map((p) => p.pid), [10, 11, 20, 30]);
  assert.deepEqual(plan.containerSkips.map((p) => p.pid), [40]);
});

test("runStop from an isolated environment: refused, exit 2, nothing signalled, both ways out named", async () => {
  const { ops, killed } = twoStacks();
  const r = await captureBoth((out, err) => runStop(["--all"], ISOLATED_ENV, ops, out, err));
  assert.equal(r.code, 2);
  assert.deepEqual(killed, []);
  assert.match(r.err, /refused/);
  assert.match(r.err, /mandu-dashboard\s+\(\/run\/user\/1000\/mandu\)/);
  assert.match(r.err, /stack unknown/);
  assert.match(r.err, /mandu stop --all --stack \/tmp\/bench\/run/);
  assert.match(r.err, /mandu stop --all --every-stack/);
});

test("runStop --stack from an isolated environment: its own stack only, the rest reported as left running", async () => {
  const { ops, killed } = twoStacks();
  const r = await captureBoth((out, err) => runStop(["--all", "--stack", ISO], ISOLATED_ENV, ops, out, err));
  assert.equal(r.code, 0);
  assert.deepEqual(killed, [20, 21]);
  assert.match(r.out, /stopped 2 process\(es\) of the stack at \/tmp\/bench\/run \(3 of other stacks left running\)/);
});

test("runStop: the operator's bare stop still sweeps every stack", async () => {
  const { ops, killed } = twoStacks();
  const r = await captureBoth((out, err) => runStop([], OPERATOR_ENV, ops, out, err));
  assert.equal(r.code, 0);
  assert.deepEqual(killed, [10, 11, 20, 30]);
});

test("runStop: a malformed --stack is a usage error, nothing signalled", async () => {
  const { ops, killed } = twoStacks();
  const r = await captureBoth((out, err) => runStop(["--stack"], OPERATOR_ENV, ops, out, err));
  assert.equal(r.code, 2);
  assert.deepEqual(killed, []);
  assert.match(r.err, /--stack needs/);
});

test("defaultStack ignores MANDU_RUNTIME_DIR; normStack strips trailing slashes", () => {
  assert.equal(defaultStack(ISOLATED_ENV), SHARED);
  assert.equal(normStack("/tmp/x//"), "/tmp/x");
});

// The operator is who the OS says (2026-10-09): a harness's
// `XDG_RUNTIME_DIR=<own dir> mandu stop` (MANDU_RUNTIME_DIR unset) counted as
// the operator and SIGTERMed the systemd dashboard and two live drill runs'
// arbiters on the same host.

test("operatorStack (Linux): logind's /run/user/<uid>/mandu whatever the caller's XDG_RUNTIME_DIR or MANDU_RUNTIME_DIR", () => {
  const linux = { platform: "linux", uid: 1000, isDir: (p: string) => p === "/run/user/1000" };
  assert.equal(operatorStack({ XDG_RUNTIME_DIR: "/tmp/harness-xdg" }, linux), SHARED);
  assert.equal(operatorStack({ ...ISOLATED_ENV }, linux), SHARED);
  assert.equal(operatorStack({}, linux), SHARED, "an env with no XDG_RUNTIME_DIR (cron, env -i) is not the operator's either");
});

test("operatorStack (Linux, no logind dir): the env's default, as before; an unknown uid likewise", () => {
  const noLogin = { platform: "linux", uid: 1000, isDir: () => false };
  assert.equal(operatorStack({ XDG_RUNTIME_DIR: "/tmp/rt" }, noLogin), "/tmp/rt/mandu");
  assert.equal(operatorStack({ XDG_RUNTIME_DIR: "/tmp/rt", MANDU_RUNTIME_DIR: ISO }, noLogin), "/tmp/rt/mandu");
  assert.equal(operatorStack({ XDG_RUNTIME_DIR: "/tmp/rt" }, { platform: "linux", uid: null, isDir: () => true }), "/tmp/rt/mandu");
});

test("operatorStack (macOS): the account's rendezvous from DARWIN_USER_TEMP_DIR, never the caller's TMPDIR", () => {
  const darwin = { platform: "darwin", uid: 501, darwinTempDir: () => "/var/folders/xy/abcdefghijklmnopqrstuvw0000gn/T/" };
  assert.equal(operatorStack({ TMPDIR: "/tmp/harness" }, darwin), "/tmp/mandu-501");
  assert.equal(operatorStack({ XDG_RUNTIME_DIR: "/tmp/x" }, darwin), "/tmp/mandu-501");
});

test("runStop from an isolated XDG_RUNTIME_DIR (no MANDU_RUNTIME_DIR): refused, nothing signalled (2026-10-09)", async () => {
  const { ops, killed } = twoStacks();
  const ISO_XDG = "/tmp/harness-xdg";
  const stacks: Record<number, string | null> = { 10: SHARED, 11: SHARED, 20: `${ISO_XDG}/mandu`, 21: `${ISO_XDG}/mandu`, 30: null };
  const withOperator: ProcOps = { ...ops, stackOf: (pid) => stacks[pid] ?? null, operatorStack: () => SHARED };
  const r = await captureBoth((out, err) => runStop([], { XDG_RUNTIME_DIR: ISO_XDG }, withOperator, out, err));
  assert.equal(r.code, 2);
  assert.deepEqual(killed, []);
  assert.match(r.err, /refused/);
  assert.match(r.err, /not this account's own at \/run\/user\/1000\/mandu/);
  assert.match(r.err, /mandu stop --stack \/tmp\/harness-xdg\/mandu/);
  // The same caller naming its own stack stops only that.
  const own = await captureBoth((out, err) => runStop(["--stack", `${ISO_XDG}/mandu`], { XDG_RUNTIME_DIR: ISO_XDG }, withOperator, out, err));
  assert.equal(own.code, 0);
  assert.deepEqual(killed, [20]);
  // The operator (its env selects the stack the OS names) still sweeps.
  killed.length = 0;
  const swept = await captureBoth((out, err) => runStop([], OPERATOR_ENV, withOperator, out, err));
  assert.equal(swept.code, 0);
  assert.deepEqual(killed, [10, 11, 20, 30]);
});

test("parseEnviron: NUL-separated KEY=VALUE, values may hold '='", () => {
  assert.deepEqual(parseEnviron("A=1\0MANDU_RUNTIME_DIR=/tmp/x\0B=a=b\0\0"), { A: "1", MANDU_RUNTIME_DIR: "/tmp/x", B: "a=b" });
});

test("registeredPids: a stack's arbiter instances, dashboards and session launchers", () => {
  const base = mkdtempSync(join(tmpdir(), "mdu-stop-reg-"));
  try {
    mkdirSync(join(base, "instances", "i1"), { recursive: true });
    writeFileSync(join(base, "instances", "i1", "manifest.json"), JSON.stringify({ pid: 101 }));
    mkdirSync(join(base, "instances", "broken"));
    mkdirSync(join(base, "dashboards"));
    writeFileSync(join(base, "dashboards", "d1.json"), JSON.stringify({ pid: 102, port: 4500 }));
    writeFileSync(join(base, "dashboards", "d1.json.tmp"), JSON.stringify({ pid: 999 }));
    mkdirSync(join(base, "1791092872-103"));
    mkdirSync(join(base, "logs"));
    assert.deepEqual(registeredPids(base).sort(), [101, 102, 103]);
    assert.deepEqual(registeredPids(join(base, "nope")), []);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("registryTrusted (runtime-instances.md §3b): `mandu stop` reads a stack's registry only from a dir of this uid, writable by no one else when it sits in /tmp", () => {
  const root = mkdtempSync(join(tmpdir(), "mdu-stop-trust-"));
  const base = join(root, "mandu");
  mkdirSync(base);
  const sticky = () => 0o41777; // the base's parent stands in for /tmp
  try {
    chmodSync(base, 0o700);
    assert.equal(registryTrusted(base), true, "this uid's private dir");
    assert.equal(registryTrusted(base, undefined, sticky), true, "…also in /tmp");
    chmodSync(base, 0o755);
    assert.equal(registryTrusted(base, undefined, sticky), true, "group/other may read and search");
    chmodSync(base, 0o777);
    assert.equal(registryTrusted(base, undefined, sticky), false, "in /tmp, others can plant entries");
    chmodSync(base, 0o775);
    assert.equal(registryTrusted(base), true, "outside a shared sticky dir a group-writable base is the user's own (a umask-002 /run/user/<uid>/mandu)");
    chmodSync(base, 0o700);
    // Another account's /tmp/mandu (made first, on a host with no
    // XDG_RUNTIME_DIR): simulated through the injected lstat.
    const uid = process.getuid?.() ?? 0;
    const foreign = () => ({ isDirectory: () => true, isSymbolicLink: () => false, uid: uid + 1, mode: 0o40700 });
    assert.equal(registryTrusted(base, foreign), false, "another user's dir");
    const link = join(base, "link");
    symlinkSync(base, link);
    assert.equal(registryTrusted(link), false, "a symlink");
    assert.equal(registryTrusted(join(base, "absent")), false, "nothing to read");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ── `mandu dashboard` (release checklist a1): reuse this user's registered
// dashboard, else a FREE port; a pinned port is adopted only when it is ours.

function dashHarness(over: Partial<DashboardDeps> & { listening?: number[] } = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const started: Record<string, string | undefined>[] = [];
  let stopped = 0;
  const listening = new Set(over.listening ?? []);
  const deps: DashboardDeps = {
    registered: () => [],
    pidAlive: () => true,
    probePort: async (_h, p) => listening.has(p),
    start: (env) => {
      started.push(env);
      return { stop: () => { stopped++; } };
    },
    waitFor: async (pred) => Boolean(await pred()),
    readPortFile: () => { listening.add(40123); return 40123; },
    sockExists: () => true,
    out: (s) => out.push(s),
    err: (s) => err.push(s),
    ...over,
  };
  return { deps, out, err, started, stopped: () => stopped };
}
const LAYOUT = Layout.dev("/repo");

test("dashboard: unpinned + a live registered dashboard of this user → REUSE it (no start); a wildcard bind is shown on loopback", async () => {
  const h = dashHarness({
    listening: [4500],
    registered: () => [{ id: "20260926-0813-abc-p9", pid: 9, host: "0.0.0.0", port: 4500 }],
  });
  assert.equal(await runDashboard([], {}, LAYOUT, h.deps), 0);
  assert.deepEqual(h.out, ["dashboard already up — http://127.0.0.1:4500/mandu/\n"], "an entry from before basePath was recorded");
  assert.equal(h.started.length, 0);
  // An explicit DASHBOARD_PORT=0 (config `dashboard-port = 0`) means "any free
  // port": it reuses too, rather than starting a second dashboard every call.
  const zero = dashHarness({ listening: [4500], registered: () => [{ id: "x", pid: 9, host: "127.0.0.1", port: 4500 }] });
  assert.equal(await runDashboard([], { DASHBOARD_PORT: "0" }, LAYOUT, zero.deps), 0);
  assert.equal(zero.started.length, 0);
});

test("dashboard: unpinned + nothing live (dead pid / silent port) → START on a kernel-assigned port and print the published one", async () => {
  const h = dashHarness({
    registered: () => [
      { id: "b", pid: 8, host: "127.0.0.1", port: 4600 }, // pid dead
      { id: "a", pid: 7, host: "127.0.0.1", port: 4700 }, // pid alive, port silent
    ],
    pidAlive: (pid) => pid === 7,
    ensureRuntimeDir: () => {}, // /run/u is a name, not a dir this test may create
  });
  assert.equal(await runDashboard([], { XDG_RUNTIME_DIR: "/run/u" }, LAYOUT, h.deps), 0);
  assert.equal(h.started.length, 1);
  assert.equal(h.started[0]!["DASHBOARD_PORT"], "0", "never the fixed 4500 another user may hold");
  assert.match(String(h.started[0]!["MANDU_PORT_FILE"]), /^\/run\/u\/mandu\/dashboard-\d+\.port$/);
  assert.deepEqual(h.out, ["dashboard up — http://127.0.0.1:40123/\n"], "a fresh dashboard serves at the root by default");
  assert.equal(h.started[0]!["DASHBOARD_BASE_PATH"], "");
  assert.equal(h.started[0]!["MANDU_OWNER_PID"], "none", "resident: this CLI exits at once, so it must not own the dashboard (d4)");
});

test("dashboard: a PINNED port is adopted only when it is one of this user's registered dashboards", async () => {
  const mine = dashHarness({ listening: [4500], registered: () => [{ id: "x", pid: 9, host: "127.0.0.1", port: 4500 }] });
  assert.equal(await runDashboard([], { DASHBOARD_PORT: "4500" }, LAYOUT, mine.deps), 0);
  assert.deepEqual(mine.out, ["dashboard already up — http://127.0.0.1:4500/mandu/\n"]);

  // Someone else's server (another user's dashboard, anything) on the pinned
  // port: refuse, never hand out a stranger's URL.
  const foreign = dashHarness({ listening: [4500] });
  assert.equal(await runDashboard([], { DASHBOARD_PORT: "4500" }, LAYOUT, foreign.deps), 1);
  assert.equal(foreign.started.length, 0);
  assert.equal(foreign.out.length, 0);
  assert.match(foreign.err.join(""), /127\.0\.0\.1:4500 is in use by something that is not one of your Mandu dashboards/);

  // Pinned + free: start exactly there (no port file).
  const free = dashHarness({ start: (env) => { free.started.push(env); return { stop: () => {} }; } });
  const probeAfterStart = new Set<number>();
  free.deps.probePort = async (_h, p) => probeAfterStart.has(p) || (free.started.length > 0 && p === 4600);
  assert.equal(await runDashboard([], { DASHBOARD_PORT: "4600" }, LAYOUT, free.deps), 0);
  assert.equal(free.started[0]!["DASHBOARD_PORT"], "4600");
  assert.equal(free.started[0]!["MANDU_PORT_FILE"], undefined);
  assert.deepEqual(free.out, ["dashboard up — http://127.0.0.1:4600/\n"]);
});

test("dashboard, Mandu not running (plan 17 §3 item 12): the dashboard starts anyway, starts nothing of Mandu's, pins no socket, and says protection is off", async () => {
  // The person who only ran `mandu scan`: no arbiter at the rendezvous.
  const h = dashHarness({ sockExists: () => false, ensureRuntimeDir: () => {} });
  assert.equal(await runDashboard([], { XDG_RUNTIME_DIR: "/run/u" }, LAYOUT, h.deps), 0);
  assert.equal(h.started.length, 1);
  assert.equal(h.started[0]!["DASHBOARD_AUTOSTART"], "0", "opening the page is not starting protection");
  assert.equal(h.started[0]!["MANDU_ARBITER_SOCK"], undefined, "the dashboard dials the rendezvous itself, where a later launch promotes");
  assert.equal(h.started[0]!["MANDU_OWNER_PID"], "none");
  assert.deepEqual(h.out, [
    "dashboard up — http://127.0.0.1:40123/\n",
    "Mandu is not running, so it protects no agent now: start yours with mandu claude (or mandu codex). The dashboard shows your last scan under Scan.\n",
  ]);
  // Run through npx: the commands as the person types them.
  const npx = dashHarness({ sockExists: () => false, ensureRuntimeDir: () => {} });
  assert.equal(await runDashboard([], { XDG_RUNTIME_DIR: "/run/u", npm_command: "exec", npm_lifecycle_event: "npx", npm_lifecycle_script: "mandu" }, LAYOUT, npx.deps), 0);
  assert.match(npx.out[1]!, /start yours with npx @mandusec\/mandu claude \(or npx @mandusec\/mandu codex\)\./);
  // An arbiter there: the dashboard joins it as before, and says nothing more.
  const up = dashHarness({ ensureRuntimeDir: () => {} });
  assert.equal(await runDashboard([], { XDG_RUNTIME_DIR: "/run/u" }, LAYOUT, up.deps), 0);
  assert.equal(up.started[0]!["DASHBOARD_AUTOSTART"], process.env["DASHBOARD_AUTOSTART"]);
  assert.equal(up.started[0]!["MANDU_ARBITER_SOCK"], "/run/u/mandu/current/arbiter.sock");
  assert.equal(up.out.length, 1);
});

test("dashboard: a PINNED arbiter socket that is absent → exit 2 before starting; no published port → the start is torn down, exit 1; a bad DASHBOARD_PORT → exit 2", async () => {
  const noSock = dashHarness({ sockExists: () => false });
  assert.equal(await runDashboard([], { MANDU_ARBITER_SOCK: "/run/u/elsewhere.sock" }, LAYOUT, noSock.deps), 2);
  assert.equal(noSock.started.length, 0);
  assert.match(noSock.err.join(""), /arbiter socket \/run\/u\/elsewhere\.sock is absent/);

  const noPort = dashHarness({ readPortFile: () => null });
  assert.equal(await runDashboard([], {}, LAYOUT, noPort.deps), 1);
  assert.equal(noPort.stopped(), 1);
  assert.match(noPort.err.join(""), /the dashboard did not start \(log: /);

  // d6: the reason from what THIS start appended to the log, not a guess.
  const why = dashHarness({
    readPortFile: () => null,
    logSize: () => 10,
    logSince: (_p, off) => (off === 10 ? "Error: listen EADDRINUSE: address already in use 127.0.0.1:4555\n" : null),
  });
  assert.equal(await runDashboard([], {}, LAYOUT, why.deps), 1);
  assert.match(why.err.join(""), /the dashboard did not start: port 4555 is already in use/);

  const bad = dashHarness();
  assert.equal(await runDashboard([], { DASHBOARD_PORT: "http" }, LAYOUT, bad.deps), 2);
});

test("dashboardForScan (mandu scan --open): a live dashboard is reused as found; none, one started as mandu dashboard starts it, with its registry entry; a failed start is null, its reason printed", async () => {
  // Reused: no start, the entry as registered (its sign-in mode with it).
  const entry = { id: "x", pid: 9, host: "127.0.0.1", port: 4500, basePath: "", passwordFirst: true };
  const live = dashHarness({ listening: [4500], registered: () => [entry] });
  assert.deepEqual(await dashboardForScan({}, live.deps), { d: entry, started: false });
  assert.equal(live.started.length, 0);
  assert.deepEqual(live.out, [], "it prints nothing: the scan says what happened");

  // None live: started exactly as `mandu dashboard` starts it (a free port,
  // resident, no arbiter pinned when none runs), then its entry once it
  // registers.
  let registered: (typeof entry)[] = [];
  const fresh = dashHarness({
    sockExists: () => false, ensureRuntimeDir: () => {},
    registered: () => registered,
    readPortFile: () => { registered = [{ ...entry, id: "y", pid: 10, port: 40123, passwordFirst: false }]; fresh.deps.probePort = async () => true; return 40123; },
  });
  const got = await dashboardForScan({ XDG_RUNTIME_DIR: "/run/u" }, fresh.deps);
  assert.deepEqual(got, { d: { ...entry, id: "y", pid: 10, port: 40123, passwordFirst: false }, started: true });
  assert.equal(fresh.started.length, 1);
  assert.equal(fresh.started[0]!["DASHBOARD_PORT"], "0");
  assert.equal(fresh.started[0]!["MANDU_OWNER_PID"], "none", "it runs on after the scan exits, as mandu dashboard leaves it");
  assert.equal(fresh.started[0]!["DASHBOARD_AUTOSTART"], "0");
  assert.deepEqual(fresh.out, []);
  // It never registered: where it answers, all the same.
  const unregistered = dashHarness({ ensureRuntimeDir: () => {} });
  assert.deepEqual(await dashboardForScan({ XDG_RUNTIME_DIR: "/run/u" }, unregistered.deps), { d: { host: "127.0.0.1", port: 40123, basePath: "" }, started: true });

  // It did not start: null, the reason on stderr, the start torn down.
  const failed = dashHarness({ readPortFile: () => null });
  assert.equal(await dashboardForScan({}, failed.deps), null);
  assert.equal(failed.stopped(), 1);
  assert.match(failed.err.join(""), /the dashboard did not start/);
  // Another user's server on a pinned port: refused, never opened.
  const foreign = dashHarness({ listening: [4500] });
  assert.equal(await dashboardForScan({ DASHBOARD_PORT: "4500" }, foreign.deps), null);
  assert.match(foreign.err.join(""), /is in use by something that is not one of your Mandu dashboards/);
});

test("dashboard (runtime-instances.md §3b): the log and port file live in the DEFAULT runtime base, made safe first; a refused base starts nothing", async () => {
  const uid = process.getuid?.() ?? 0;
  // A TMPDIR too long for an instance socket: the /tmp/mandu-<uid> fallback
  // (its root is the test hook), the same base the scope dirs use.
  const env = { TMPDIR: "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/" + "x".repeat(10), MANDU_RUNTIME_FALLBACK_ROOT: "/fbroot" };
  const prepared: string[] = [];
  const h = dashHarness({ ensureRuntimeDir: (d) => { prepared.push(d); } });
  assert.equal(await runDashboard([], env, LAYOUT, h.deps), 0);
  assert.deepEqual(prepared, [`/fbroot/mandu-${uid}`], "the base is made private BEFORE the start");
  assert.match(String(h.started[0]!["MANDU_PORT_FILE"]), new RegExp(`^/fbroot/mandu-${uid}/dashboard-\\d+\\.port$`));
  // The shared-/tmp fallback cannot be made private: refuse, start nothing.
  const refused = dashHarness({ ensureRuntimeDir: () => { throw new Error("the Mandu runtime dir /tmp/mandu-1 is shared (mode 0755: …)"); } });
  assert.equal(await runDashboard([], env, LAYOUT, refused.deps), 1);
  assert.equal(refused.started.length, 0);
  assert.match(refused.err.join(""), /^mandu: the Mandu runtime dir \/tmp\/mandu-1 is shared/);
});

test("dashboard (§3b): a registry entry under a SHARED fallback is never trusted — no stranger's URL, nothing started", async () => {
  const uid = process.getuid?.() ?? 0;
  const root = mkdtempSync(join(tmpdir(), "mandu-dash-fb-"));
  try {
    const base = join(root, `mandu-${uid}`);
    mkdirSync(join(base, "dashboards"), { recursive: true });
    chmodSync(base, 0o775);
    const env = { TMPDIR: "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/" + "x".repeat(10), MANDU_RUNTIME_FALLBACK_ROOT: root };
    const h = dashHarness({ listening: [4500], registered: () => [{ id: "x", pid: 9, host: "127.0.0.1", port: 4500 }] });
    assert.equal(await runDashboard([], env, LAYOUT, h.deps), 1);
    assert.deepEqual(h.out, [], "no 'already up' URL out of a dir someone else may control");
    assert.equal(h.started.length, 0);
    assert.match(h.err.join(""), /^mandu: the Mandu runtime dir .* is shared \(mode 0775/);
    // `mandu reap` signals the pids manifests there name: refused before it reads one.
    mkdirSync(join(base, "instances", "20260101-0000-x-p1"), { recursive: true });
    writeFileSync(join(base, "instances", "20260101-0000-x-p1", "manifest.json"), JSON.stringify({ pid: process.pid }));
    await assert.rejects(runSubcommand("reap", ["--dry-run"], env, LAYOUT), /^Error: mandu: the Mandu runtime dir .* is shared/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("registeredDashboards: reads <runtime>/dashboards/*.json newest first, skipping unreadable / portless entries", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dashreg-"));
  try {
    const reg = join(dir, "mandu", "dashboards");
    mkdirSync(reg, { recursive: true });
    writeFileSync(join(reg, "20260901-0000-aaa-p1.json"), JSON.stringify({ pid: 1, port: 4500, host: "0.0.0.0" }));
    writeFileSync(join(reg, "20260926-0000-bbb-p2.json"), JSON.stringify({ pid: 2, port: 40555, host: "127.0.0.1" }));
    writeFileSync(join(reg, "20260927-0000-ccc-p3.json"), "{not json");
    writeFileSync(join(reg, "20260928-0000-ddd-p4.json"), JSON.stringify({ pid: 4 }));
    assert.deepEqual(registeredDashboards({ XDG_RUNTIME_DIR: dir }), [
      { id: "20260926-0000-bbb-p2", pid: 2, host: "127.0.0.1", port: 40555 },
      { id: "20260901-0000-aaa-p1", pid: 1, host: "0.0.0.0", port: 4500 },
    ]);
    assert.deepEqual(registeredDashboards({ XDG_RUNTIME_DIR: join(dir, "nope") }), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("registeredDashboards: a password or Basic-auth sign-in is password-first; one-time links and old entries are not (2026-10-22)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dashreg-"));
  try {
    const reg = join(dir, "mandu", "dashboards");
    mkdirSync(reg, { recursive: true });
    writeFileSync(join(reg, "20261022-0000-aaa-p1.json"), JSON.stringify({ pid: 1, port: 4501, signInMode: "basic-auth" }));
    writeFileSync(join(reg, "20261022-0001-bbb-p2.json"), JSON.stringify({ pid: 2, port: 4502, signInMode: "password" }));
    writeFileSync(join(reg, "20261022-0002-ccc-p3.json"), JSON.stringify({ pid: 3, port: 4503, signInMode: "tickets" }));
    writeFileSync(join(reg, "20261022-0003-ddd-p4.json"), JSON.stringify({ pid: 4, port: 4504 }));
    writeFileSync(join(reg, "20261022-0004-eee-p5.json"), JSON.stringify({ pid: 5, port: 4505, signInMode: "account" }));
    const all = registeredDashboards({ XDG_RUNTIME_DIR: dir });
    const first = new Map(all.map((d) => [d.port, d.passwordFirst === true]));
    assert.deepEqual([...first].sort(), [[4501, true], [4502, true], [4503, false], [4504, false], [4505, true]]);
    // With what: the dashboard account, a username and password, or the password.
    const how = new Map(all.map((d) => [d.port, d.signInWith ?? null]));
    assert.deepEqual([...how].sort(), [[4501, "basic"], [4502, null], [4503, null], [4504, null], [4505, "account"]]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("mandu setup then offers the dashboard account; not after --print or --uninstall (dashboard.md §6.z)", async () => {
  for (const [rest, offered] of [[[], true], [["--yes"], true], [["--print"], false], [["--uninstall"], false]] as const) {
    let asked = 0;
    const rc = await runSetupThenAccount([...rest], async () => 3, async () => { asked++; });
    assert.equal(rc, 3, "setup's own exit code");
    assert.equal(asked, offered ? 1 : 0, JSON.stringify(rest));
  }
});

test("runStop: nothing to stop → no kills, clear message", async () => {
  const killed: number[] = [];
  const ops: ProcOps = { list: () => [], kill: (pid) => killed.push(pid) };
  const out = await captureOut((out) => runStop([], {}, ops, out));
  assert.equal(killed.length, 0);
  assert.match(out, /no resident mandu daemons/);
});

test("dashboardUrl: the entry's own base path (none → root), loopback for a wildcard bind, trailing slash", () => {
  assert.equal(dashboardUrl({ host: "0.0.0.0", port: 4500, basePath: "" }), "http://127.0.0.1:4500/");
  assert.equal(dashboardUrl({ host: "127.0.0.1", port: 4500, basePath: "/mandu/" }), "http://127.0.0.1:4500/mandu/");
  assert.equal(dashboardUrl({ host: "127.0.0.1", port: 4500 }), "http://127.0.0.1:4500/mandu/", "entries from before 2026-09-26 were served under /mandu");
});

test("dashboard: a registered entry's recorded base path wins over the env", async () => {
  const h = dashHarness({
    listening: [4500],
    registered: () => [{ id: "x", pid: 9, host: "127.0.0.1", port: 4500, basePath: "" }],
  });
  assert.equal(await runDashboard([], { DASHBOARD_BASE_PATH: "/elsewhere" }, LAYOUT, h.deps), 0);
  assert.deepEqual(h.out, ["dashboard already up — http://127.0.0.1:4500/\n"]);
});

test("leftoverSummary: services from ended sessions vs stale records; nothing → null", () => {
  const a = (kind: ReapAction["kind"]): ReapAction => ({ kind, path: "/x", detail: "" });
  assert.equal(leftoverSummary([]), null);
  assert.equal(leftoverSummary([a("kill-orphan-arbiter")]), "1 service from ended sessions");
  assert.equal(
    leftoverSummary([a("kill-orphan-arbiter"), a("kill-orphan-dashboard"), a("rm-stale-scope-dir"), a("rm-dead-instance")]),
    "2 services from ended sessions, 2 stale records",
  );
});

test("runStatus: a plain summary by default (running, dashboard URL, leftovers); lists only under --verbose", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-status-"));
  try {
    const base = join(dir, "mandu");
    mkdirSync(join(base, "dashboards"), { recursive: true });
    writeFileSync(join(base, "dashboards", "20260926-0000-aaa-p7.json"), JSON.stringify({ pid: 7, port: 40555, host: "127.0.0.1", basePath: "" }));
    mkdirSync(join(base, "1700000000-99"), { recursive: true }); // a finished launch's scope dir
    const env = { XDG_RUNTIME_DIR: dir, MANDU_ARBITER_SOCK: join(dir, "none.sock") };
    const reapDeps = { pidAlive: (p: number) => p === 7, cmdlineOf: () => "mandu-dashboard", kill: () => {}, socketLive: async () => false, now: () => Date.now() };
    const ops: ProcOps = { list: () => [{ pid: 5, title: "mandu-net-proxy" }], kill: () => {} };
    const lines: string[] = [];
    assert.equal(await runStatus(env, { ops, reapDeps, out: (s) => lines.push(s) }), 0);
    const text = lines.join("");
    assert.match(text, /^Mandu is not running \(the next launch starts it\)\.\n/);
    assert.match(text, /  dashboard: http:\/\/127\.0\.0\.1:40555\/\n/);
    assert.match(text, /  leftovers: 1 stale record \(`mandu reap` cleans them up/);
    assert.doesNotMatch(text, /mandu-net-proxy|registered (arbiters|dashboards) \(/, "no process or registry dump by default");
    const verbose: string[] = [];
    await runStatus(env, { ops, reapDeps, verbose: true, out: (s) => verbose.push(s) });
    assert.match(verbose.join(""), /registered dashboards \(1\):[\s\S]*Mandu processes of this user, any stack \(1\):\n\s+5  mandu-net-proxy/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
