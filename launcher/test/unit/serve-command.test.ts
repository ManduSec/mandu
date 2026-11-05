/**
 * serve-command.test — `mandu serve install|uninstall|start|stop|status|upgrade`
 * over a fake `systemctl --user` and fake stack facts (launcher/src/serve-command.ts,
 * runtime-instances.md §4.1d). No systemd, no process, no file is touched:
 * the unit file lives in a map, the arbiter's `hello` is a function of the
 * fake unit's state. The real dashboard and arbiter started from the
 * rendered unit are the component test's (test/component/serve-command.test.ts).
 * No protection axis is involved.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseServeArgs, runServe, SERVE_EXIT, type ServeDeps, type SystemctlResult } from "../../src/serve-command.js";
import { parseUnitFile, renderServeUnit, SERVE_UNIT, serveUnitInput } from "../../src/serve-unit.js";
import type { VersionVerdict } from "../../src/arbiter-version.js";

const BASE = "/run/user/1000/mandu";
const UNIT_PATH = "/home/u/.config/systemd/user/mandu.service";
const ENV = { HOME: "/home/u", XDG_RUNTIME_DIR: "/run/user/1000" };
const DAEMON = { cmd: "node", args: ["/pkg/dist/dashboard.mjs"], cwd: "/pkg", env: {} };

interface World {
  files: Map<string, string>;
  calls: string[];
  active: boolean;
  enabled: boolean;
  /** The arbiter's release as hello reports it while the unit runs. */
  arbiterVersion: string;
  sessions: number[];
  outside: number[];
  otherService: string | null;
  stopped: number[][];
  linger: boolean | null;
  platform: string;
  /** systemctl --user show -p Version's result (null: answers). */
  probe: SystemctlResult | null;
  /** hello answers only after this many polls following a start. */
  out: string;
  err: string;
}

function world(over: Partial<World> = {}): World {
  return {
    files: new Map(), calls: [], active: false, enabled: false, arbiterVersion: "0.2.0-beta.8", sessions: [], outside: [],
    otherService: null, stopped: [], linger: true, platform: "linux", probe: null, out: "", err: "", ...over,
  };
}

function deps(w: World): ServeDeps {
  const systemctl = (args: string[]): SystemctlResult => {
    if (args[0] === "show" && args.includes("Version")) return w.probe ?? { code: 0, stdout: "255\n", stderr: "" };
    w.calls.push(args.join(" "));
    switch (args[0]) {
      case "show":
        return {
          code: 0, stderr: "",
          stdout: w.files.has(UNIT_PATH)
            ? `LoadState=loaded\nActiveState=${w.active ? "active" : "inactive"}\nSubState=${w.active ? "running" : "dead"}\n` +
              `UnitFileState=${w.enabled ? "enabled" : "disabled"}\nMainPID=${w.active ? 100 : 0}\nActiveEnterTimestamp=Sun 2026-10-25 10:00:00 KST\nNRestarts=0\n`
            : "LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\nMainPID=0\n",
        };
      case "start": w.active = true; w.outside = []; return { code: 0, stdout: "", stderr: "" };
      case "stop": w.active = false; return { code: 0, stdout: "", stderr: "" };
      case "enable": w.enabled = true; return { code: 0, stdout: "", stderr: "" };
      case "disable": w.enabled = false; if (args.includes("--now")) w.active = false; return { code: 0, stdout: "", stderr: "" };
      default: return { code: 0, stdout: "", stderr: "" };
    }
  };
  return {
    platform: w.platform,
    self: {
      version: "0.2.0-beta.8", install: "npm", root: "/pkg", node: "/usr/bin/node",
      layout: { daemon: () => DAEMON }, base: BASE, baseSource: "xdg",
      verdict: (hello): VersionVerdict => {
        const v = (hello as { version: string }).version;
        return v === "0.2.0-beta.8" ? { kind: "match", theirs: v } : { kind: "older", theirs: v };
      },
    },
    systemctl,
    linger: () => w.linger,
    readFile: (p) => w.files.get(p) ?? null,
    writeFile: (p, t) => { w.files.set(p, t); w.calls.push(`write ${p}`); },
    removeFile: (p) => { w.files.delete(p); w.calls.push(`rm ${p}`); },
    hello: async () => (w.active ? { protocolVersion: 1, version: w.arbiterVersion, pid: 101 } : undefined),
    sessions: () => w.sessions,
    residentPids: () => [...(w.active ? [100, 101] : []), ...w.outside],
    unitOfPid: (pid) => (w.active && (pid === 100 || pid === 101) ? SERVE_UNIT : null),
    otherService: () => w.otherService,
    stopPids: async (ps) => { w.stopped.push([...ps]); w.outside = w.outside.filter((p) => !ps.includes(p)); return []; },
    dashboards: () => (w.active ? [{ id: "d", pid: 100, host: "127.0.0.1", port: 4500, basePath: "" }] : []),
    probePort: async () => w.active,
    sleep: async () => { /* the clock is the calls */ },
    readyMs: 1_000,
    waitPollMs: 1,
    out: (s) => { w.out += s; },
    err: (s) => { w.err += s; },
  };
}

function current(): string {
  return renderServeUnit(serveUnitInput({
    version: "0.2.0-beta.8", install: "npm", root: "/pkg", node: "/usr/bin/node", daemon: DAEMON, runtimeDir: "%t/mandu", env: ENV,
    docs: "https://github.com/mandusec/mandu/blob/main/docs/usage.md#the-mandu-service",
  }));
}

test("parseServeArgs: a verb, its own options only", () => {
  assert.deepEqual(parseServeArgs(["upgrade", "--wait"]), { verb: "upgrade", force: false, wait: true, json: false, rest: [] });
  assert.match((parseServeArgs([]) as { error: string }).error, /mandu serve install\|uninstall\|start\|stop\|status\|upgrade\|attach\|detach$/);
  // attach / detach / the pool's register-secrets keep their own arguments
  assert.deepEqual(parseServeArgs(["attach", "openclaw", "--agent", "ops"]), { verb: "attach", force: false, wait: false, json: false, rest: ["openclaw", "--agent", "ops"] });
  assert.deepEqual(parseServeArgs(["register-secrets", "--agent", "main", "--json"]), { verb: "register-secrets", force: false, wait: false, json: false, rest: ["--agent", "main", "--json"] });
  assert.match((parseServeArgs(["restart"]) as { error: string }).error, /unknown verb 'restart'/);
  assert.match((parseServeArgs(["status", "--force"]) as { error: string }).error, /unknown option '--force'/);
});

test("install: writes the unit, reloads, enables and starts it, and waits for its arbiter", async () => {
  const w = world({ linger: false });
  const rc = await runServe(["install"], ENV, deps(w));
  assert.equal(rc, SERVE_EXIT.ok, w.err);
  assert.equal(w.files.get(UNIT_PATH), current());
  assert.ok(parseUnitFile(w.files.get(UNIT_PATH)!).ours);
  const order = w.calls.filter((c) => !c.startsWith("show"));
  assert.deepEqual(order, [`write ${UNIT_PATH}`, "daemon-reload", `enable ${SERVE_UNIT}`, `start ${SERVE_UNIT}`]);
  assert.match(w.out, /running: the arbiter at \/run\/user\/1000\/mandu\/current\/arbiter\.sock \(pid 101\), the dashboard at http:\/\/127\.0\.0\.1:4500\//);
  assert.match(w.out, /loginctl enable-linger/, "linger off: said once");
  // Again: nothing to rewrite.
  w.calls = [];
  assert.equal(await runServe(["install"], ENV, deps(w)), SERVE_EXIT.ok);
  assert.ok(!w.calls.includes(`write ${UNIT_PATH}`));
});

test("install refuses: macOS (not yet), no systemd user manager, a foreign unit file, another service on the stack", async () => {
  const mac = world({ platform: "darwin" });
  assert.equal(await runServe(["install"], ENV, deps(mac)), SERVE_EXIT.usage);
  assert.match(mac.err, /not yet on macOS/);
  assert.equal(mac.files.size, 0);

  const nobus = world({ probe: { code: 1, stdout: "", stderr: "Failed to connect to bus: No medium found" } });
  assert.equal(await runServe(["install"], ENV, deps(nobus)), SERVE_EXIT.usage);
  assert.match(nobus.err, /no systemd user manager here \(Failed to connect to bus/);
  assert.equal(nobus.files.size, 0);

  const foreign = world();
  foreign.files.set(UNIT_PATH, "[Service]\nExecStart=/bin/true\n");
  assert.equal(await runServe(["install"], ENV, deps(foreign)), SERVE_EXIT.failed);
  assert.match(foreign.err, /was not written by mandu serve; refusing to replace it/);
  assert.equal(foreign.files.get(UNIT_PATH), "[Service]\nExecStart=/bin/true\n");

  const other = world({ otherService: "mandu-dashboard.service" });
  assert.equal(await runServe(["install"], ENV, deps(other)), SERVE_EXIT.failed);
  assert.match(other.err, /already run by the systemd user service mandu-dashboard\.service.*systemctl --user disable --now mandu-dashboard\.service/s);
  assert.equal(other.files.size, 0, "nothing written beside the other service");
});

test("install with the stack already running outside the unit: replaced when no session uses it, deferred when one does", async () => {
  const idle = world({ outside: [500, 501] });
  assert.equal(await runServe(["install"], ENV, deps(idle)), SERVE_EXIT.ok, idle.err);
  assert.deepEqual(idle.stopped, [[500, 501]]);
  assert.match(idle.out, /stopping the Mandu services that run for \/run\/user\/1000\/mandu outside the service \(pid 500, 501\)/);

  const busy = world({ outside: [500], sessions: [900] });
  assert.equal(await runServe(["install"], ENV, deps(busy)), SERVE_EXIT.deferred);
  assert.deepEqual(busy.stopped, [], "a session's arbiter is never stopped under it");
  assert.equal(busy.active, false);
  assert.ok(busy.enabled && busy.files.has(UNIT_PATH), "installed and enabled all the same");
  assert.match(busy.out, /not started now:.*a mandu session uses them \(pid 900\).*mandu serve start --force/s);

  const forced = world({ outside: [500], sessions: [900] });
  assert.equal(await runServe(["install", "--force"], ENV, deps(forced)), SERVE_EXIT.ok);
  assert.deepEqual(forced.stopped, [[500]]);
});

test("start: not installed is said; stop and uninstall do not cut a session off without --force", async () => {
  const none = world();
  assert.equal(await runServe(["start"], ENV, deps(none)), SERVE_EXIT.deferred);
  assert.match(none.err, /not installed: mandu serve install/);

  const w = world({ sessions: [900] });
  w.files.set(UNIT_PATH, current());
  w.active = true;
  assert.equal(await runServe(["stop"], ENV, deps(w)), SERVE_EXIT.deferred);
  assert.match(w.err, /ends the protection of a running mandu session \(pid 900\): it fails closed until the service is back/);
  assert.equal(w.active, true);
  assert.equal(await runServe(["uninstall"], ENV, deps(w)), SERVE_EXIT.deferred);
  assert.ok(w.files.has(UNIT_PATH));
  assert.equal(await runServe(["stop", "--force"], ENV, deps(w)), SERVE_EXIT.ok);
  assert.equal(w.active, false);
  assert.match(w.out, /stopped\. It is still enabled/);
});

test("uninstall: disables and stops it, removes the file; a foreign file is left; none is fine", async () => {
  const w = world();
  w.files.set(UNIT_PATH, current());
  w.active = true; w.enabled = true;
  assert.equal(await runServe(["uninstall"], ENV, deps(w)), SERVE_EXIT.ok);
  assert.equal(w.files.has(UNIT_PATH), false);
  assert.deepEqual(w.calls.filter((c) => !c.startsWith("show")), [`disable --now ${SERVE_UNIT}`, `rm ${UNIT_PATH}`, "daemon-reload"]);
  assert.equal(w.active, false);

  const foreign = world();
  foreign.files.set(UNIT_PATH, "[Service]\nExecStart=/bin/true\n");
  assert.equal(await runServe(["uninstall"], ENV, deps(foreign)), SERVE_EXIT.failed);
  assert.ok(foreign.files.has(UNIT_PATH));

  assert.equal(await runServe(["uninstall"], ENV, deps(world())), SERVE_EXIT.ok);
});

test("upgrade: nothing to do when current; a stale service restarted, deferred under a session, waited for with --wait", async () => {
  const cur = world({ active: true });
  cur.files.set(UNIT_PATH, current());
  assert.equal(await runServe(["upgrade"], ENV, deps(cur)), SERVE_EXIT.ok);
  assert.match(cur.out, /already runs this mandu \(0\.2\.0-beta\.8\); nothing to restart/);
  assert.ok(!cur.calls.some((c) => c.startsWith("stop") || c.startsWith("start")));

  // An npm update in place: the file names the old release, the arbiter runs it.
  const stale = world({ active: true, arbiterVersion: "0.2.0-beta.7", sessions: [900] });
  stale.files.set(UNIT_PATH, current().replace("0.2.0-beta.8", "0.2.0-beta.7"));
  assert.equal(await runServe(["upgrade"], ENV, deps(stale)), SERVE_EXIT.deferred);
  assert.equal(stale.files.get(UNIT_PATH), current(), "the file is rewritten even when the restart waits");
  assert.ok(stale.calls.includes("daemon-reload"));
  assert.ok(!stale.calls.some((c) => c.startsWith("stop") || c.startsWith("start")), "no restart under the session");
  assert.match(stale.out, /restart deferred \(the service runs other code than this mandu\).*--wait/s);

  // --wait: the session ends after two looks, then the restart.
  let looks = 0;
  const waiting = world({ active: true, arbiterVersion: "0.2.0-beta.7" });
  waiting.files.set(UNIT_PATH, current());
  const d = deps(waiting);
  d.sessions = () => (looks++ < 2 ? [900] : []);
  d.systemctl = ((orig) => (args: string[]) => {
    const r = orig(args);
    if (args[0] === "start") waiting.arbiterVersion = "0.2.0-beta.8";
    return r;
  })(d.systemctl);
  assert.equal(await runServe(["upgrade", "--wait"], ENV, d), SERVE_EXIT.ok, waiting.err);
  assert.match(waiting.out, /waiting for a mandu session \(pid 900\) to end first/);
  const acts = waiting.calls.filter((c) => c.startsWith("stop") || c.startsWith("start"));
  assert.deepEqual(acts, [`stop ${SERVE_UNIT}`, `start ${SERVE_UNIT}`]);

  // --force: now, sessions or not.
  const forced = world({ active: true, arbiterVersion: "0.2.0-beta.7", sessions: [900] });
  forced.files.set(UNIT_PATH, current());
  const fd = deps(forced);
  fd.systemctl = ((orig) => (args: string[]) => {
    const r = orig(args);
    if (args[0] === "start") forced.arbiterVersion = "0.2.0-beta.8";
    return r;
  })(fd.systemctl);
  assert.equal(await runServe(["upgrade", "--force"], ENV, fd), SERVE_EXIT.ok);
  assert.ok(forced.calls.includes(`start ${SERVE_UNIT}`));

  // A restart that comes back on the old code is a failure, said.
  const stuck = world({ active: true, arbiterVersion: "0.2.0-beta.7" });
  stuck.files.set(UNIT_PATH, current());
  assert.equal(await runServe(["upgrade"], ENV, deps(stuck)), SERVE_EXIT.failed);
  assert.match(stuck.err, /its arbiter is Mandu 0\.2\.0-beta\.7, not this mandu \(0\.2\.0-beta\.8\)/);

  const none = world();
  assert.equal(await runServe(["upgrade"], ENV, deps(none)), SERVE_EXIT.deferred);
  assert.match(none.err, /not installed/);
});

test("status: not installed (exit 3); running and healthy (exit 0); its problems named (exit 1); --json", async () => {
  const none = world();
  assert.equal(await runServe(["status"], ENV, deps(none)), SERVE_EXIT.deferred);
  assert.match(none.out, /^Mandu service \(mandu serve\): not installed \(mandu serve install sets it up\)/);
  assert.match(none.out, /arbiter: +not answering at \/run\/user\/1000\/mandu\/current\/arbiter\.sock/);

  const ok = world({ active: true, enabled: true, sessions: [900] });
  ok.files.set(UNIT_PATH, current());
  assert.equal(await runServe(["status"], ENV, deps(ok)), SERVE_EXIT.ok, ok.out);
  assert.match(ok.out, /^Mandu service \(mandu serve\): running\n/);
  assert.match(ok.out, /unit: +mandu\.service, active \(running\), enabled, pid 100, since Sun 2026-10-25 10:00:00 KST/);
  assert.match(ok.out, /unit file: \/home\/u\/\.config\/systemd\/user\/mandu\.service \(current\)/);
  assert.match(ok.out, /arbiter: +answering at \/run\/user\/1000\/mandu\/current\/arbiter\.sock \(Mandu 0\.2\.0-beta\.8, pid 101, the service's own\)/);
  assert.match(ok.out, /versions: +this mandu 0\.2\.0-beta\.8 \(npm package at \/pkg\); the arbiter matches it/);
  assert.match(ok.out, /dashboard: http:\/\/127\.0\.0\.1:4500\//);
  assert.match(ok.out, /sessions: +1 mandu session use/);
  assert.doesNotMatch(ok.out, /problem:/);

  const stale = world({ active: true, arbiterVersion: "0.2.0-beta.7" });
  stale.files.set(UNIT_PATH, current().replace("0.2.0-beta.8", "0.2.0-beta.7"));
  assert.equal(await runServe(["status"], ENV, deps(stale)), SERVE_EXIT.failed);
  assert.match(stale.out, /problem: +the unit file is from another mandu release, install or node: mandu serve upgrade/);
  assert.match(stale.out, /problem: +the service's arbiter is Mandu 0\.2\.0-beta\.7, not this mandu \(0\.2\.0-beta\.8\): mandu serve upgrade/);

  const json = world({ active: true });
  json.files.set(UNIT_PATH, current());
  assert.equal(await runServe(["status", "--json"], ENV, deps(json)), SERVE_EXIT.ok);
  const st = JSON.parse(json.out) as { attachments: unknown; unit: { active: string }; stack: { arbiter: { insideUnit: boolean } } };
  assert.equal(st.attachments, null, "the proxy pool is not built: no attachment sessions to list");
  assert.equal(st.unit.active, "active");
  assert.equal(st.stack.arbiter.insideUnit, true);

  const stopped = world();
  stopped.files.set(UNIT_PATH, current());
  assert.equal(await runServe(["status"], ENV, deps(stopped)), SERVE_EXIT.deferred);
  assert.match(stopped.out, /problem: +the service is inactive \(dead\): mandu serve start/);
});
