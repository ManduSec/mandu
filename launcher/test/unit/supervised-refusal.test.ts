/**
 * supervised-refusal.test — what a launch refused by an older stack under a
 * systemd service tells the user, by which process is old and who runs it
 * (arbiter-version.ts supervisedRefusal; stack-supervisor.ts withStackFacts;
 * runtime-instances.md §4.1a, §4.1b). The 2026-10-21 refusal told the user to
 * `systemctl --user disable --now mandu-dashboard.service` when the service
 * ran current code and only an arbiter it had adopted was old; the fix was
 * `mandu stop`.
 *
 *   - the service's own arbiter is old: the service runs old code (disable
 *     it, or run on a stack of one's own);
 *   - only an adopted arbiter is old and the service runs this mandu's code:
 *     replace the arbiter (`mandu stop --stack`, or Replace), never disable;
 *   - an adopted arbiter and the service runs other code: replace first,
 *     disable if it comes back old;
 *   - an unrelated stack (no service): restarted, as before.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { skewAction, type SkewInput, type VersionVerdict } from "../../src/arbiter-version.js";
import { problemsOf } from "../../src/version-report.js";
import { withStackFacts, type StackFactDeps, type StackSupervisor } from "../../src/stack-supervisor.js";

const BASE = "/run/user/1007/mandu";
const ROOT = "/home/u/project/mandu";
const UNIT_CG = "0::/user.slice/user-1007.slice/user@1007.service/app.slice/mandu-dashboard.service";
const SCOPE_CG = "0::/user.slice/user-1007.slice/user@1007.service/tmux-spawn-1.scope";

const SUP: StackSupervisor = {
  unit: "mandu-dashboard.service", user: true, mainPid: 100, restart: "always",
  workingDirectory: `${ROOT}/dashboard`, fragmentPath: "/home/u/.config/systemd/user/mandu-dashboard.service",
};

function facts(cgs: Record<number, string>, cwds: Record<number, string> = {}): StackFactDeps {
  return { cgroupOf: (p) => cgs[p] ?? null, cwdOf: (p) => cwds[p] ?? null, realpath: (p) => p };
}

test("withStackFacts: where the arbiter runs, and whether the service runs this mandu's code", () => {
  assert.equal(withStackFacts(SUP, 4242, ROOT, facts({ 4242: SCOPE_CG })).arbiterOutside, true, "a tmux scope: adopted");
  assert.equal(withStackFacts(SUP, 4242, ROOT, facts({ 4242: UNIT_CG })).arbiterOutside, false, "the unit's own");
  assert.equal(withStackFacts(SUP, null, ROOT, facts({})).arbiterOutside, null, "no pid");
  assert.equal(withStackFacts(SUP, 4242, ROOT, facts({})).arbiterOutside, null, "no /proc");
  assert.equal(withStackFacts(SUP, 4242, ROOT, facts({})).runsOurCode, true, "its folder is in this checkout");
  assert.equal(withStackFacts(SUP, 4242, `${ROOT}-wt`, facts({})).runsOurCode, false, "a sibling path is not inside");
  assert.equal(withStackFacts({ ...SUP, workingDirectory: null }, 4242, ROOT, facts({}, { 100: "/opt/other/dashboard" })).runsOurCode, false,
    "no WorkingDirectory: the main process's folder");
  assert.equal(withStackFacts({ ...SUP, workingDirectory: null }, 4242, ROOT, facts({})).runsOurCode, null);
});

const OLDER: VersionVerdict = { kind: "older", theirs: "0.2.0-beta.5" };
const BUILD: VersionVerdict = {
  kind: "build", theirs: "0.2.0-beta.7",
  theirsBuild: { bundle: "aaaaaaaaaaaaaaaa", rev: "88da43ace" }, oursBuild: { bundle: "bbbbbbbbbbbbbbbb", rev: "f89d0feed" },
};

function input(verdict: VersionVerdict, supervisor: StackSupervisor | null, over: Partial<SkewInput> = {}): SkewInput {
  return {
    verdict, ours: "0.2.0-beta.7", sock: `${BASE}/current/arbiter.sock`, mode: "resident" as SkewInput["mode"],
    started: false, base: BASE, arbiterPid: 4242, peers: [], supervisor, ...over,
  };
}

function refusal(i: SkewInput): string {
  const a = skewAction(i);
  assert.equal(a.kind, "refuse");
  return (a as { message: string }).message;
}

test("the service's own arbiter is old: the service runs old code — disable it, or a stack of one's own", () => {
  const m = refusal(input(OLDER, { ...SUP, arbiterOutside: false, runsOurCode: false }));
  assert.match(m, /That arbiter is the systemd user service mandu-dashboard\.service \(Restart=always, in \/home\/u\/project\/mandu\/dashboard\)'s own process/);
  assert.match(m, /systemctl --user disable --now mandu-dashboard\.service/);
  assert.match(m, /run this mandu on its own stack instead/);
});

test("only an adopted arbiter is old and the service runs this mandu's code: replace the arbiter, never disable the service", () => {
  for (const v of [OLDER, BUILD]) {
    const m = refusal(input(v, { ...SUP, arbiterOutside: true, runsOurCode: true }));
    assert.match(m, /Only that arbiter process is old: it is not the systemd user service mandu-dashboard\.service .*'s own process\. An earlier launch or another dashboard started it, and the service's dashboard adopted it/);
    assert.match(m, /The service runs this mandu's own code, so replace the old arbiter and the service starts a current one: mandu stop --stack \/run\/user\/1007\/mandu \(or press Replace on the arbiter in the dashboard's Services panel\)/);
    assert.doesNotMatch(m, /disable/);
    assert.doesNotMatch(m, /mandu-own/);
  }
  // With a session on it, the stop it names is the same replacement.
  const peers = refusal(input(OLDER, { ...SUP, arbiterOutside: true, runsOurCode: true }, { peers: [777] }));
  assert.match(peers, /another mandu session uses them \(pid 777\).*: mandu stop --stack \/run\/user\/1007\/mandu$/);
});

test("an adopted arbiter and the service runs other code: replace it first, disable the service if an old one comes back", () => {
  const m = refusal(input(OLDER, { ...SUP, workingDirectory: "/opt/old-mandu/dashboard", arbiterOutside: true, runsOurCode: false }));
  assert.match(m, /Only that arbiter process is old/);
  assert.match(m, /The service runs code from \/opt\/old-mandu\/dashboard, not this mandu's\. First replace the old arbiter: mandu stop --stack \/run\/user\/1007\/mandu, then run mandu again\./);
  assert.match(m, /If the service then starts an old arbiter again, the service itself runs an older Mandu: stop it for good with systemctl --user disable --now mandu-dashboard\.service/);
});

test("an unrelated stack (no service keeps it) is restarted as before", () => {
  const a = skewAction(input(OLDER, null));
  assert.equal(a.kind, "restart");
});

test("mandu version says the same: an adopted old arbiter under a service running this mandu's code", () => {
  const base = {
    self: { invoked: null, realPath: null, kind: "checkout-shim" as const, root: ROOT, version: "0.2.0-beta.7", commitsFrom: "git" as const, sourceCommit: null, publicCommit: null, publicAhead: 0, dirty: false },
    node: { version: "22.0.0", path: "/usr/bin/node", meetsFloor: true, floor: "22.0.0" },
    path: [], env: {}, npmGlobal: null, forcedLayout: null,
  };
  const services = (supervisor: StackSupervisor) => ({
    sock: `${BASE}/current/arbiter.sock`, sockMode: "resident", base: BASE, running: true, version: "0.2.0-beta.5", build: null,
    pid: 4242, startedAt: null, codeDir: `${ROOT}/launcher`, verdict: "older" as const, ourBuild: null, supervisor,
  });
  const adopted = problemsOf({ ...base, services: services({ ...SUP, arbiterOutside: true, runsOurCode: true }) });
  assert.deepEqual(adopted.map((p) => p.id), ["services-adopted-other-build"]);
  assert.match(adopted[0]!.problem, /not the systemd user service mandu-dashboard\.service .*'s own process/);
  assert.match(adopted[0]!.fix, /^replace the old arbiter: mandu stop --stack \/run\/user\/1007\/mandu/);
  assert.doesNotMatch(adopted[0]!.fix, /disable/);
  const own = problemsOf({ ...base, services: services({ ...SUP, arbiterOutside: false, runsOurCode: false }) });
  assert.deepEqual(own.map((p) => p.id), ["services-supervised-other-build"]);
  assert.match(own[0]!.fix, /^systemctl --user disable --now/);
});
