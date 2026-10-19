/**
 * stack-supervisor.test — a Mandu stack that a systemd service restarts is
 * named, never fought (stack-supervisor.ts; runtime-instances.md §4.1a).
 *
 * The cgroup and `systemctl show` parsing; the rule that a daemon is
 * supervised only as the unit's main process or its direct child (a tsx or
 * script wrapper), never merely inside a service's cgroup (a CI runner's
 * job); and the release check: a supervised stack of another release or
 * build is refused with the unit and its disable command instead of being
 * restarted, and a refusal's "stop it" names that command. Nothing is
 * spawned: /proc and systemctl are injected.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  describeSupervisor, disableCommand, ownStackCommand, parseSystemctlShow, ppidOfStat, serviceUnitOfCgroup, stackSupervisor,
  type StackSupervisor, type SupervisorDeps,
} from "../../src/stack-supervisor.js";
import { checkArbiterRelease, skewAction, type SkewInput, type VersionVerdict } from "../../src/arbiter-version.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the release check is axis-blind; stated per the suite rule

const SVC = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/mandu-dashboard.service\n";
const TMUX = "0::/user.slice/user-1000.slice/user@1000.service/tmux-spawn-f201c02d.scope\n";
const RUNNER = "0::/system.slice/gitlab-runner.service\n";

test("serviceUnitOfCgroup: a user or system service; a scope, a slice or the user manager is none", () => {
  assert.deepEqual(serviceUnitOfCgroup(SVC), { unit: "mandu-dashboard.service", user: true });
  assert.deepEqual(serviceUnitOfCgroup(RUNNER), { unit: "gitlab-runner.service", user: false });
  assert.equal(serviceUnitOfCgroup(TMUX), null);
  assert.equal(serviceUnitOfCgroup("0::/user.slice/user-1000.slice/user@1000.service\n"), null);
  assert.equal(serviceUnitOfCgroup("0::/user.slice/user-1000.slice/session-3.scope\n"), null);
  assert.equal(serviceUnitOfCgroup(""), null);
  // cgroup v1: the name=systemd hierarchy.
  assert.deepEqual(serviceUnitOfCgroup("12:cpu:/\n1:name=systemd:/user.slice/user-1000.slice/user@1000.service/mandu.service\n"),
    { unit: "mandu.service", user: true });
});

test("parseSystemctlShow and ppidOfStat", () => {
  assert.deepEqual(parseSystemctlShow("MainPID=42\nRestart=always\nWorkingDirectory=/a=b\n"),
    { MainPID: "42", Restart: "always", WorkingDirectory: "/a=b" });
  assert.equal(ppidOfStat("4242 (node) S 4100 4242 4242 0 -1"), 4100);
  assert.equal(ppidOfStat("4242 (my (odd) name) S 7 1 1"), 7, "a command name with spaces and parentheses");
  assert.equal(ppidOfStat("garbage"), null);
});

/** /proc and systemctl for one host: pid → [cgroup, ppid]; unit → show text. */
function host(procs: Record<number, [string, number]>, units: Record<string, string>): SupervisorDeps {
  return {
    cgroupOf: (pid) => procs[pid]?.[0] ?? null,
    ppidOf: (pid) => procs[pid]?.[1] ?? null,
    show: (unit) => units[unit] ?? null,
  };
}
const SHOW = (main: number, restart = "always") =>
  `MainPID=${main}\nRestart=${restart}\nWorkingDirectory=/home/u/project/mandu/dashboard\nFragmentPath=/home/u/.config/systemd/user/mandu-dashboard.service\n`;

test("stackSupervisor: the unit's main process, or its direct child (ExecStart through tsx), is supervised", () => {
  const direct = stackSupervisor([200], host({ 200: [SVC, 1] }, { "mandu-dashboard.service": SHOW(200) }));
  assert.equal(direct?.unit, "mandu-dashboard.service");
  // The incident's shape: the unit runs tsx (main pid 100), whose child is
  // the dashboard; the arbiter sits in a tmux scope and is not the unit's.
  const viaTsx = stackSupervisor([300, 200], host({ 300: [TMUX, 1], 200: [SVC, 100] }, { "mandu-dashboard.service": SHOW(100) }));
  assert.deepEqual(viaTsx, {
    unit: "mandu-dashboard.service", user: true, mainPid: 100, restart: "always",
    workingDirectory: "/home/u/project/mandu/dashboard", fragmentPath: "/home/u/.config/systemd/user/mandu-dashboard.service",
  });
});

test("stackSupervisor: deeper in a service's cgroup (a CI runner's job), Restart=no, or no systemd is none", () => {
  // The arbiter's parent is a job shell, not the runner's main process.
  assert.equal(stackSupervisor([200], host({ 200: [RUNNER, 150] }, { "gitlab-runner.service": SHOW(10) })), null);
  assert.equal(stackSupervisor([200], host({ 200: [SVC, 1] }, { "mandu-dashboard.service": SHOW(200, "no") })), null);
  assert.equal(stackSupervisor([200], host({ 200: [SVC, 1] }, {})), null, "systemctl did not answer");
  assert.equal(stackSupervisor([200], host({}, {})), null, "no /proc (macOS)");
  assert.equal(stackSupervisor([], host({}, {})), null);
});

const SUP: StackSupervisor = {
  unit: "mandu-dashboard.service", user: true, mainPid: 100, restart: "always",
  workingDirectory: "/home/u/project/mandu/dashboard", fragmentPath: "/home/u/.config/systemd/user/mandu-dashboard.service",
};

test("disableCommand / describeSupervisor", () => {
  assert.equal(disableCommand(SUP), "systemctl --user disable --now mandu-dashboard.service");
  assert.equal(disableCommand({ ...SUP, user: false }), "systemctl disable --now mandu-dashboard.service");
  assert.equal(describeSupervisor(SUP), "the systemd user service mandu-dashboard.service (Restart=always, in /home/u/project/mandu/dashboard)");
});

const OURS = "0.2.0-beta.6";
function input(verdict: VersionVerdict, over: Partial<SkewInput> = {}): SkewInput {
  return {
    verdict, ours: OURS, sock: "/run/user/1/mandu/current/arbiter.sock", mode: "current", started: false,
    base: "/run/user/1/mandu", arbiterPid: 4242, peers: [], supervisor: SUP, ...over,
  };
}
const BUILD: VersionVerdict = { kind: "build", theirs: OURS, theirsBuild: { bundle: null, rev: "abc1234" }, oursBuild: { bundle: "0123456789abcdef", rev: null } };

test("skewAction: a supervised stack of another release or build is refused, never restarted, naming the unit", () => {
  for (const v of [{ kind: "older", theirs: "0.2.0-beta.5" }, { kind: "other", theirs: "unknown" }, BUILD] as VersionVerdict[]) {
    const a = skewAction(input(v));
    assert.equal(a.kind, "refuse", v.kind);
    const m = (a as { message: string }).message;
    assert.match(m, /systemd user service mandu-dashboard\.service \(Restart=always/);
    assert.match(m, /systemctl --user disable --now mandu-dashboard\.service/);
    assert.match(m, /cannot replace them/);
    assert.doesNotMatch(m, /reinstall/, "not the misleading 'installation is mixed'");
    // A service kept on purpose (the lab's dashboard service): the second way out.
    // Its own Mandu folder too: the symbol database has one writer.
    assert.match(m, /If you keep that service on purpose, run this mandu on its own stack instead: MANDU_HOME=~\/\.mandu-own MANDU_RUNTIME_DIR=\/run\/user\/1\/mandu-own mandu … \(a Mandu folder of its own, so its own rules and history: copy your policy\.yaml and config\.toml from ~\/\.mandu into it to keep your rules\)$/);
  }
  // Unsupervised: still the restart.
  assert.equal(skewAction(input({ kind: "older", theirs: "0.2.0-beta.5" }, { supervisor: null })).kind, "restart");
  assert.equal(skewAction(input(BUILD, { supervisor: undefined })).kind, "restart");
});

test("skewAction: a refusal's stop names the unit's command, not mandu stop, when supervised", () => {
  const both = /systemctl --user disable --now mandu-dashboard\.service; or, to keep that service, run this mandu on its own stack: MANDU_HOME=~\/\.mandu-own MANDU_RUNTIME_DIR=\/run\/user\/1\/mandu-own mandu … \(a Mandu folder of its own, [^)]*\)$/;
  const peers = skewAction(input({ kind: "older", theirs: "0.2.0-beta.5" }, { peers: [7] }));
  assert.match((peers as { message: string }).message, both);
  const newer = skewAction(input({ kind: "newer", theirs: "0.3.0" }));
  assert.match((newer as { message: string }).message, both);
  assert.equal(ownStackCommand("/run/user/1/mandu/"), "MANDU_HOME=~/.mandu-own MANDU_RUNTIME_DIR=/run/user/1/mandu-own mandu …");
  assert.match((skewAction(input({ kind: "newer", theirs: "0.3.0" }, { supervisor: null })) as { message: string }).message,
    /mandu stop --stack \/run\/user\/1\/mandu$/);
});

test("checkArbiterRelease: looks for a supervisor only for a resident stack of another release or build", async () => {
  const base = { ours: OURS, sock: "/s", mode: "current" as const, started: false, base: "/run/user/1/mandu" };
  const asked: Array<[string, number | null]> = [];
  const deps = (hello: unknown) => ({
    hello: async () => hello,
    peers: () => [],
    supervisor: (b: string, pid: number | null) => { asked.push([b, pid]); return SUP; },
  });
  const REAL = { pid: 4242, protocolVersion: 1 };
  assert.equal((await checkArbiterRelease(base, deps({ ...REAL, version: OURS }))).action.kind, "proceed");
  assert.equal(asked.length, 0, "a match asks nothing");
  assert.equal((await checkArbiterRelease({ ...base, mode: "pinned" }, deps({ ...REAL, version: "0.1.0" }))).action.kind, "refuse");
  assert.equal((await checkArbiterRelease({ ...base, started: true }, deps({ ...REAL, version: "0.1.0" }))).action.kind, "refuse");
  assert.equal(asked.length, 0, "pinned or self-started: not a resident stack to stop");
  const r = await checkArbiterRelease(base, deps({ ...REAL, version: "0.1.0" }));
  assert.equal(r.action.kind, "refuse");
  assert.deepEqual(asked, [["/run/user/1/mandu", 4242]]);
  // A supervisor probe that throws is no supervisor: the restart stands.
  const thrown = await checkArbiterRelease(base, { hello: async () => ({ ...REAL, version: "0.1.0" }), peers: () => [], supervisor: () => { throw new Error("EPERM"); } });
  assert.equal(thrown.action.kind, "restart");
});
