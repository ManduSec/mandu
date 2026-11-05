/**
 * serve-unit.test — the shipped systemd user unit of `mandu serve` and the
 * decisions of its verbs (launcher/src/serve-unit.ts, runtime-instances.md
 * §4.1d). Pure: no systemd, no file, no process. No protection axis is
 * involved (the unit runs the stack in whatever mode it is configured for).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  envAssignment, execWord, expandSpecifiers, hostRefusal, parseUnitFile, planStart, planUpgrade, renderServeUnit,
  SERVE_UNIT, SERVE_UNIT_MARKER, serveHost, serveUnitInput, stopBlockedBy, unitFilePath, unitPath, unitRuntimeDir,
  type ServeUnitInput, type UpgradeFacts,
} from "../../src/serve-unit.js";
import { Layout } from "../../src/services/layout.js";

function input(over: Partial<ServeUnitInput> = {}): ServeUnitInput {
  return {
    version: "0.2.0-beta.8",
    install: "npm",
    root: "/usr/lib/node_modules/@mandusec/mandu",
    node: "/home/u/.nvm/versions/node/v22.13.0/bin/node",
    daemon: {
      cmd: "node",
      args: ["--no-warnings=ExperimentalWarning", "/usr/lib/node_modules/@mandusec/mandu/dist/dashboard.mjs"],
      cwd: "/usr/lib/node_modules/@mandusec/mandu",
      env: { MANDU_ARBITER_CLIENT_MODULE: "/usr/lib/node_modules/@mandusec/mandu/dist/arbiter-client.mjs" },
    },
    runtimeDir: "%t/mandu",
    carried: {},
    docs: "https://example.invalid/docs/usage.md#the-mandu-service",
    ...over,
  };
}

test("the unit runs the dashboard as the arbiter's supervisor, promoted, ownerless, restarted by systemd", () => {
  const text = renderServeUnit(input());
  const u = parseUnitFile(text);
  assert.equal(u.ours, true, "marked as mandu serve's");
  assert.ok(text.split("\n").includes(SERVE_UNIT_MARKER));
  assert.deepEqual(u.execStart, [
    "/home/u/.nvm/versions/node/v22.13.0/bin/node", "--no-warnings=ExperimentalWarning",
    "/usr/lib/node_modules/@mandusec/mandu/dist/dashboard.mjs",
  ], "`node` becomes the absolute node: a user manager's PATH has no nvm node");
  assert.equal(u.workingDirectory, "/usr/lib/node_modules/@mandusec/mandu");
  assert.equal(u.restart, "always");
  assert.equal(u.environment["DASHBOARD_AUTOSTART"], "arbiter");
  assert.equal(u.environment["MANDU_PROMOTE"], "1");
  assert.equal(u.environment["MANDU_OWNER_PID"], "none");
  assert.equal(u.environment["MANDU_RUNTIME_DIR"], "%t/mandu", "the specifier is kept for systemd to expand");
  assert.equal(u.environment["MANDU_SERVE"], "1");
  assert.equal(u.environment["MANDU_ARBITER_CLIENT_MODULE"], "/usr/lib/node_modules/@mandusec/mandu/dist/arbiter-client.mjs");
  assert.equal(u.environment["PATH"], "/home/u/.nvm/versions/node/v22.13.0/bin:/usr/local/bin:/usr/bin:/bin");
  assert.match(text, /^KillMode=mixed$/m, "the dashboard stops its arbiter itself");
  assert.match(text, /^WantedBy=default\.target$/m);
  assert.match(text, /From mandu 0\.2\.0-beta\.8, the npm package at \/usr\/lib\/node_modules\/@mandusec\/mandu\./);
  assert.equal(SERVE_UNIT, "mandu.service");
});

test("the render is deterministic, and changes with the node, the paths, the release or a carried variable", () => {
  const a = renderServeUnit(input());
  assert.equal(renderServeUnit(input()), a);
  assert.notEqual(renderServeUnit(input({ node: "/usr/bin/node" })), a);
  assert.notEqual(renderServeUnit(input({ version: "0.2.0-beta.9" })), a);
  assert.notEqual(renderServeUnit(input({ carried: { DASHBOARD_PORT: "4600" } })), a);
  assert.notEqual(renderServeUnit(input({ runtimeDir: "/tmp/mdu-own" })), a);
});

test("quoting: spaces, quotes, backslashes, % and $ survive the round trip; a line break is refused", () => {
  const odd = "/home/u/My Code/100% \"mandu\" $HOME\\x";
  const text = renderServeUnit(input({
    daemon: { cmd: "node", args: [`${odd}/dist/dashboard.mjs`], cwd: odd, env: { MANDU_X: odd } },
    carried: { MANDU_HOME: `${odd}/home` },
  }));
  const u = parseUnitFile(text);
  assert.deepEqual(u.execStart.slice(1), [`${odd}/dist/dashboard.mjs`]);
  assert.equal(u.workingDirectory, odd);
  assert.equal(u.environment["MANDU_X"], odd);
  assert.equal(u.environment["MANDU_HOME"], `${odd}/home`);
  assert.equal(execWord("a%b$c"), '"a%%b$$c"', "ExecStart expands both");
  assert.equal(envAssignment("K", "a%b$c"), 'Environment="K=a%%b$c"', "Environment expands specifiers only");
  assert.equal(envAssignment("K", "%t/mandu", true), 'Environment="K=%t/mandu"');
  assert.throws(() => execWord("a\nExecStartPre=/bin/evil"), /line break/);
  assert.throws(() => envAssignment("K", "a\nb"), /line break/);
  assert.throws(() => envAssignment("K=1", "x"), /not a variable name/);
});

test("the runtime dir: %t/mandu for the account's default, else the literal path", () => {
  assert.equal(unitRuntimeDir("/run/user/1000/mandu", "xdg"), "%t/mandu");
  assert.equal(unitRuntimeDir("/tmp/mdu-own", "explicit"), "/tmp/mdu-own");
  assert.equal(unitRuntimeDir("/tmp/mandu-1000", "fallback"), "/tmp/mandu-1000");
  assert.equal(expandSpecifiers("%t/mandu", { XDG_RUNTIME_DIR: "/run/user/1000" }), "/run/user/1000/mandu");
  assert.equal(expandSpecifiers("%h/x %% %n", { HOME: "/home/u" }), "/home/u/x % %n");
});

test("the carried variables are only the ones set", () => {
  const i = serveUnitInput({
    version: "v", install: "checkout", root: "/r", node: "/n/node", daemon: input().daemon, runtimeDir: "%t/mandu", docs: "d",
    env: { MANDU_HOME: "/m", DASHBOARD_PORT: "0", DASHBOARD_HOST: "", OPENAI_API_KEY: "sk-secret", HOME: "/home/u" },
  });
  assert.deepEqual(i.carried, { MANDU_HOME: "/m", DASHBOARD_PORT: "0" }, "never the caller's other variables (a key)");
  assert.doesNotMatch(renderServeUnit(i), /sk-secret|OPENAI/);
});

test("the pool's model upstream is carried (openclaw-plugin.md §3.2), never one with credentials in it", () => {
  const base = { version: "v", install: "checkout" as const, root: "/r", node: "/n/node", daemon: input().daemon, runtimeDir: "%t/mandu", docs: "d" };
  const i = serveUnitInput({ ...base, env: { MANDU_UPSTREAM: "http://127.0.0.1:9999", MANDU_UPSTREAM_LOCAL: "1" } });
  assert.deepEqual(i.carried, { MANDU_UPSTREAM: "http://127.0.0.1:9999", MANDU_UPSTREAM_LOCAL: "1" });
  assert.match(renderServeUnit(i), /^Environment="MANDU_UPSTREAM=http:\/\/127\.0\.0\.1:9999"$/m);
  const cred = serveUnitInput({ ...base, env: { MANDU_UPSTREAM: "https://bob:hunter2@gw.example/v1" } });
  assert.deepEqual(cred.carried, {});
  assert.doesNotMatch(renderServeUnit(cred), /hunter2/);
});

test("the unit file goes under XDG_CONFIG_HOME, else ~/.config", () => {
  assert.equal(unitFilePath({ XDG_CONFIG_HOME: "/c", HOME: "/home/u" }), "/c/systemd/user/mandu.service");
  assert.equal(unitFilePath({ HOME: "/home/u" }), "/home/u/.config/systemd/user/mandu.service");
  assert.equal(unitFilePath({}), null);
  assert.equal(unitPath("/usr/bin/node"), "/usr/bin:/usr/local/bin:/bin", "no folder twice");
});

test("a foreign unit file of the same name is not ours", () => {
  const u = parseUnitFile("[Unit]\nDescription=mine\n[Service]\nExecStart=/usr/bin/sleep 1\nEnvironment=A=1 \"B=two words\"\n");
  assert.equal(u.ours, false);
  assert.deepEqual(u.execStart, ["/usr/bin/sleep", "1"]);
  assert.deepEqual(u.environment, { A: "1", B: "two words" });
});

test("the real layouts: the npm package runs its dashboard bundle, a source checkout its TypeScript through tsx", () => {
  const npm = Layout.installed("/usr/lib/node_modules/@mandusec/mandu");
  const d1 = parseUnitFile(renderServeUnit(input({ daemon: npm.daemon("dashboard", "dashboard") })));
  assert.equal(d1.execStart[d1.execStart.length - 1], "/usr/lib/node_modules/@mandusec/mandu/dist/dashboard.mjs");
  assert.equal(d1.environment["MANDU_ULLM_MODULE"], "/usr/lib/node_modules/@mandusec/mandu/dist/ullm-client.mjs");
  const dev = Layout.dev("/home/u/mandu");
  const d2 = parseUnitFile(renderServeUnit(input({ install: "checkout", root: "/home/u/mandu", daemon: dev.daemon("dashboard", "dashboard") })));
  assert.equal(d2.execStart[0], "/home/u/.nvm/versions/node/v22.13.0/bin/node");
  assert.equal(d2.execStart[1], "--import");
  assert.match(d2.execStart[2]!, /^file:\/\/\/home\/u\/mandu\/dashboard\/node_modules\/tsx\//);
  assert.equal(d2.execStart[3], "/home/u/mandu/dashboard/src/server-main.ts");
  assert.equal(d2.workingDirectory, "/home/u/mandu/dashboard");
});

test("the host: Linux with a user manager; macOS not yet; no systemd refused with what to do instead", () => {
  assert.deepEqual(serveHost("linux", { code: 0, stderr: "" }), { kind: "ok" });
  assert.deepEqual(serveHost("darwin", null), { kind: "darwin" });
  assert.deepEqual(serveHost("win32", null), { kind: "other-os", platform: "win32" });
  assert.deepEqual(serveHost("linux", { code: 127, stderr: "" }), { kind: "no-systemd", why: "systemctl is not installed" });
  const bus = serveHost("linux", { code: 1, stderr: "Failed to connect to bus: No medium found\n" });
  assert.deepEqual(bus, { kind: "no-systemd", why: "Failed to connect to bus: No medium found" });
  assert.match(hostRefusal({ kind: "darwin" }), /not yet on macOS \(a launchd agent is planned\)/);
  const none = hostRefusal(bus as Exclude<typeof bus, { kind: "ok" }>);
  assert.match(none, /no systemd user manager here \(Failed to connect to bus/);
  assert.match(none, /\[boot\] systemd=true/);
  assert.match(none, /mandu dashboard/);
});

test("planStart: another service refused; an outside stack replaced, deferred under sessions unless --force", () => {
  assert.deepEqual(planStart({ otherService: "mandu-dashboard.service", outside: [], sessions: [], force: true }),
    { kind: "refuse-other-service", unit: "mandu-dashboard.service" });
  assert.deepEqual(planStart({ otherService: null, outside: [], sessions: [9], force: false }), { kind: "start", stopOutside: [] },
    "nothing outside: a session is not cut off by starting");
  assert.deepEqual(planStart({ otherService: null, outside: [5, 6], sessions: [], force: false }), { kind: "start", stopOutside: [5, 6] });
  assert.deepEqual(planStart({ otherService: null, outside: [5], sessions: [9], force: false }), { kind: "defer", outside: [5], sessions: [9] });
  assert.deepEqual(planStart({ otherService: null, outside: [5], sessions: [9], force: true }), { kind: "start", stopOutside: [5] });
});

function up(over: Partial<UpgradeFacts> = {}): UpgradeFacts {
  return { onDisk: "ours", unitChanged: false, active: true, verdict: "match", arbiterOutside: false, sessions: [], force: false, wait: false, ...over };
}

test("planUpgrade: restart only when the service does not run this mandu, never under a session without --force/--wait", () => {
  assert.deepEqual(planUpgrade(up({ onDisk: "absent" })), { kind: "not-installed" });
  assert.deepEqual(planUpgrade(up({ onDisk: "foreign" })), { kind: "foreign" });
  assert.deepEqual(planUpgrade(up()), { kind: "current", write: false });
  assert.deepEqual(planUpgrade(up({ verdict: "unknown" })), { kind: "current", write: false }, "an arbiter that cannot be compared is not restarted");
  for (const [over, why] of [
    [{ verdict: "older" }, "the service runs other code than this mandu"],
    [{ verdict: "build" }, "the service runs other code than this mandu"],
    [{ verdict: "not-running" }, "the service's arbiter does not answer"],
    [{ arbiterOutside: true }, "the stack's arbiter is not the service's own process"],
    [{ unitChanged: true }, "the unit file changed"],
    [{ force: true }, "--force"],
  ] as const) {
    const p = planUpgrade(up(over));
    assert.equal(p.kind, "restart", JSON.stringify(over));
    assert.equal((p as { why: string }).why, why);
  }
  assert.deepEqual(planUpgrade(up({ verdict: "older", unitChanged: true, sessions: [7] })),
    { kind: "defer", write: true, sessions: [7], why: "the service runs other code than this mandu" },
    "deferred, the file still rewritten (it takes effect at the next start)");
  assert.equal(planUpgrade(up({ verdict: "older", sessions: [7], wait: true })).kind, "wait");
  assert.equal(planUpgrade(up({ verdict: "older", sessions: [7], force: true })).kind, "restart");
  assert.deepEqual(planUpgrade(up({ sessions: [7] })), { kind: "current", write: false }, "a current service under sessions: nothing to do");
  assert.deepEqual(planUpgrade(up({ active: false, sessions: [7] })), { kind: "restart", write: false, why: "the service is not running" },
    "a stopped service cuts nobody off (the start's own rule still applies)");
});

test("stop and uninstall are refused under live sessions unless --force", () => {
  assert.deepEqual(stopBlockedBy(true, [3, 4], false), [3, 4]);
  assert.deepEqual(stopBlockedBy(true, [3, 4], true), []);
  assert.deepEqual(stopBlockedBy(false, [3, 4], false), [], "nothing running: nothing to cut off");
});
