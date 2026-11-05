/**
 * serve-route-check (component) — the service's check that an attached
 * OpenClaw config still routes through Mandu (docs/design/agents/
 * openclaw-plugin.md §3.6), over the REAL service stack: a fake systemd
 * (test/lib/fake-systemd.ts) runs the unit `mandu serve install` rendered
 * (the dashboard as the arbiter's supervisor, MANDU_SERVE=1, the proxy pool)
 * on the test's own runtime dir, HOME and Mandu home; never the host's user
 * manager, ~/.mandu or ~/.openclaw. Axes: `secrets` (the service's default
 * mode; the attachment is a gated session whatever the mode).
 *
 * The story:
 *   1. `mandu serve install`, `mandu serve attach openclaw`, then `mandu
 *      openclaw install` writes the plugin and the route into the temp
 *      HOME's openclaw.json and records the config with the service;
 *   2. the pool reads it: routed (the pool record, `mandu serve status`);
 *   3. the agent's programs point the Anthropic provider elsewhere: within
 *      the watch (else the 30 s timer) the service says so loudly: the pool
 *      record `lost`, a `✗` problem line and ROUTE LOST in `mandu serve
 *      status`, the doctor's ✗ with the fix, the service log's ROUTE LOST
 *      line, and a BELIEVED arbiter posture record for the session with
 *      `gated` / `model-route-lost` and the route (sent on the admin
 *      channel while the attachment holds the human plane exposed); the
 *      config is left as it was written;
 *   4. `mandu openclaw install` again (the fix every notice names; it takes
 *      the route back, since Mandu was installed in this file before):
 *      routed, the problem line gone, a new believed record with the kind's
 *      own gap;
 *   5. the model fence (§3.6, "The model fence"): the model allowlist the
 *      install wrote is deleted, then widened (a key of a provider Mandu
 *      does not route): each a lost model context (`model-fence`) in the
 *      pool record, `mandu serve status`, both doctor readings and the
 *      believed record; a third install takes the fence back (the key added
 *      since removed, the missing one written) and the route is back.
 */
import { test } from "node:test";
import "../lib/private-home.js";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stateAxes } from "../axes.js";
import { sweepRuntimeProcesses } from "../lib/runtime-sweep.js";
import { FakeSystemd } from "../lib/fake-systemd.js";
import { realServeDeps, runServe, SERVE_EXIT, type ServeDeps } from "../../src/serve-command.js";
import { SERVE_UNIT } from "../../src/serve-unit.js";
import { Layout } from "../../src/services/layout.js";
import { attachmentDir, parseRouteRecord, type RouteRecord } from "../../src/attachment-contract.js";
import { gatherAttachments, humanPlaneStatusOf, readDeclaredList } from "../../src/serve-attachments.js";
import { gatherOpenclawAttach, runOpenclawAttach, type AttachDeps } from "../../src/openclaw-install-command.js";
import { openclawAttachRows, serveAttachmentRows } from "../../src/doctor.js";
import { ndjsonCall } from "../../src/secret-setup.js";
import { probeIdentity } from "../../src/services/primitives.js";

stateAxes("secrets");

const SESSION = "openclaw:main";

async function until(pred: () => boolean | Promise<boolean>, ms = 60_000): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await pred()) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return pred();
}

function dashboardPidsOf(base: string): number[] {
  const dir = join(base, "dashboards");
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((n) => n.endsWith(".json")).flatMap((f) => {
    try { const m = JSON.parse(readFileSync(join(dir, f), "utf8")) as { pid?: unknown }; return typeof m.pid === "number" ? [m.pid] : []; } catch { return []; }
  });
}

test("mandu serve: an attached OpenClaw config edited to bypass the proxy, or to open its model fence, is said loudly (status, doctor, the believed posture record) and clears after a re-install", {
  timeout: 600_000, skip: process.platform !== "linux" ? "Linux only (/proc, systemd)" : false,
}, async () => {
  const tmp = realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "mdu-rc-")));
  const base = join(tmp, "mandu");
  const manduHome = join(tmp, "mandu-home");
  const home = join(tmp, "home");
  const xdg = join(tmp, "xdg");
  mkdirSync(xdg, { mode: 0o700 });
  mkdirSync(join(home, ".openclaw"), { recursive: true });
  const cfg = join(home, ".openclaw", "openclaw.json");
  writeFileSync(cfg, JSON.stringify({ agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6" } } }, tools: { profile: "coding" } }, null, 2), { mode: 0o600 });
  // The plugin's folder (a load path ending in its name is Mandu's).
  const pluginDir = join(tmp, "src", "interceptors", "openclaw-inspect-plugin");
  mkdirSync(pluginDir, { recursive: true });
  const unitPath = join(tmp, "config", "systemd", "user", SERVE_UNIT);
  const saved = { MANDU_HOME: process.env["MANDU_HOME"], MANDU_ARBITER_SOCK: process.env["MANDU_ARBITER_SOCK"] };
  process.env["MANDU_HOME"] = manduHome;
  delete process.env["MANDU_ARBITER_SOCK"];
  const unitLog = join(tmp, "unit.log");
  const fake = new FakeSystemd(unitPath, { HOME: home, XDG_RUNTIME_DIR: xdg, USER: process.env["USER"] ?? "u" }, unitLog);
  const serveEnv = {
    HOME: home, PATH: process.env["PATH"], TMPDIR: tmp,
    XDG_CONFIG_HOME: join(tmp, "config"),
    MANDU_RUNTIME_DIR: base, MANDU_HOME: manduHome,
    DASHBOARD_PORT: "0",
    // Never a real model: nothing here makes a model call.
    MANDU_UPSTREAM: "http://127.0.0.1:9",
  };
  const layout = Layout.detect(new URL("../../src/run.ts", import.meta.url).href, {});
  let out = "";
  let err = "";
  const deps: ServeDeps = {
    ...realServeDeps(layout, serveEnv),
    systemctl: fake.run,
    unitOfPid: (pid) => (fake.inUnit(pid) ? SERVE_UNIT : null),
    otherService: () => null,
    linger: () => true,
    attachWaitMs: 180_000,
    out: (s) => { out += s; },
    err: (s) => { err += s; },
  };
  const serve = async (...args: string[]): Promise<number> => {
    out = ""; err = "";
    return runServe(args, serveEnv, deps);
  };
  const env = { HOME: home, MANDU_HOME: manduHome, MANDU_RUNTIME_DIR: base };
  let iout = "";
  const attachDeps: AttachDeps = {
    pluginDir, uid: process.getuid?.(), probe: (port) => probeIdentity("127.0.0.1", port),
    out: (s) => { iout += s; }, err: (s) => { iout += s; }, now: () => new Date(),
    serviceWaitMs: 60_000, poolRunning: () => true, sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  };
  const install = async (): Promise<number> => { iout = ""; return runOpenclawAttach("install", [], env, attachDeps); };
  const log = (): string => (existsSync(unitLog) ? readFileSync(unitLog, "utf8").slice(-6000) : "");
  const route = (): RouteRecord | null => {
    try { return parseRouteRecord(readFileSync(join(attachmentDir(base, SESSION), "pool.json"), "utf8")); } catch { return null; }
  };
  const postures = async (): Promise<Array<Record<string, unknown>>> => {
    const hello = await ndjsonCall<{ humanSock: string }>(join(base, "current", "arbiter.sock"), "hello", {}, 3_000);
    const r = await ndjsonCall<{ events: Array<Record<string, unknown>> }>(hello.humanSock, "events", { sessionId: SESSION, sinceSeq: 0 }, 5_000);
    return r.events.filter((e) => e["kind"] === "launch_posture" && e["emitter"] === "arbiter");
  };
  /** The newest believed arbiter record, as the dashboard reads it. */
  const newestBelieved = async (): Promise<Record<string, unknown> | undefined> => (await postures()).filter((e) => e["claimed"] !== true).at(-1);
  const gapOf = (e: Record<string, unknown> | undefined): unknown => (e?.["secrets"] as { gap?: unknown } | undefined)?.gap;
  const doctorRows = async (): Promise<string> => serveAttachmentRows(await gatherAttachments(env, {
    uid: process.getuid?.(), probe: (port) => probeIdentity("127.0.0.1", port), humanPlaneStatus: (e) => humanPlaneStatusOf(e),
  })).join("\n");
  try {
    // 1. The service, the declaration, the install.
    assert.equal(await serve("install"), SERVE_EXIT.ok, `install: ${out}${err}\n${log()}`);
    assert.equal(await serve("attach", "openclaw"), SERVE_EXIT.ok, `attach: ${out}${err}\n${log()}`);
    assert.equal(await install(), 0, `openclaw install: ${iout}\n${log()}`);
    assert.match(iout, /installed the OpenClaw plugin/);
    assert.match(iout, /checks this file every 30 seconds and on every change/);
    assert.equal(readDeclaredList(env).attachments[0]!.config, cfg, "the install recorded the config with the service");

    // 2. Routed.
    assert.ok(await until(() => route()?.state === "routed"), `routed: ${JSON.stringify(route())}\n${log()}`);
    assert.equal(route()!.config, cfg);
    assert.equal(await serve("status"), SERVE_EXIT.ok, `${out}${err}`);
    assert.match(out, /openclaw:main: proxy on 127\.0\.0\.1:\d+, answering, registered, .*the OpenClaw config routes through it, posture gated \(gap openclaw-plugin\)/);
    assert.doesNotMatch(out, /✗/);
    assert.equal(gapOf(await newestBelieved()), "openclaw-plugin");

    // 3. The agent's programs point the provider elsewhere (an atomic replace, as an editor does).
    const doc = JSON.parse(readFileSync(cfg, "utf8")) as { models: { providers: { anthropic: { baseUrl: string } } } };
    doc.models.providers.anthropic.baseUrl = "https://evil.example";
    const bypassed = JSON.stringify(doc, null, 2);
    writeFileSync(`${cfg}.tmp`, bypassed);
    renameSync(`${cfg}.tmp`, cfg);
    assert.ok(await until(() => route()?.state === "lost", 90_000), `lost: ${JSON.stringify(route())}\n${log()}`);
    assert.deepEqual(route()!.problems.map((p) => p.code), ["route-elsewhere"]);
    assert.ok(await until(async () => gapOf(await newestBelieved()) === "model-route-lost", 30_000), `the believed record: ${JSON.stringify(await postures())}\n${log()}`);
    const rec = (await newestBelieved())!;
    assert.notEqual(rec["claimed"], true, "believed: the admin channel, while the human socket is exposed by the attachment");
    const ar = rec["attachmentRoute"] as { state: string; problems: Array<{ code: string; detail: string }>; config: string };
    assert.equal(ar.state, "lost");
    assert.match(ar.problems[0]!.detail, /Anthropic calls go to https:\/\/evil\.example, not Mandu's service proxy/);
    assert.equal(ar.config, cfg);
    assert.deepEqual((rec["attachment"] as { coverage: { modelContext: string } }).coverage.modelContext, "none");
    assert.notEqual(await serve("status"), SERVE_EXIT.ok, "a lost route is a problem: status says \"running, with problems\" and exits non-zero");
    assert.match(out, /Mandu service \(mandu serve\): running, with problems/);
    assert.match(out, /openclaw:main: .*ROUTE LOST \(see the problem below\), posture gated \(gap model-route-lost\)/);
    assert.match(out, /problem: +✗ openclaw:main: the OpenClaw config no longer routes through Mandu \(.*openclaw\.json, since .*\): Anthropic calls go to https:\/\/evil\.example/);
    assert.match(out, /fix: mandu openclaw install, then openclaw gateway restart/);
    const rows = await doctorRows();
    assert.match(rows, /✗ openclaw:main: the OpenClaw config no longer routes through Mandu/);
    assert.match(rows, /fix: mandu openclaw install, then openclaw gateway restart/);
    assert.match(log(), /attachment openclaw:main: ROUTE LOST: .*openclaw\.json no longer routes it through Mandu/);
    assert.equal(readFileSync(cfg, "utf8"), bypassed, "the service never rewrites the user's config");

    // 4. Re-installed: routed again, the problem gone, the kind's own gap on a newer believed record.
    assert.equal(await install(), 0, `re-install: ${iout}`);
    // Route 1: the address the install recorded (Anthropic's own) is kept,
    // not the one written since.
    assert.match(iout, /took the anthropic route back from https:\/\/evil\.example \(it changed after Mandu's install; the backup keeps it\): Mandu keeps sending anthropic to the address the install recorded, its built-in address/,
      "the fix the notices name works over the tampered file (installed here before: no refusal)");
    assert.ok(await until(() => route()?.state === "routed", 90_000), `back: ${JSON.stringify(route())}\n${log()}`);
    assert.ok(await until(async () => gapOf(await newestBelieved()) === "openclaw-plugin", 30_000), JSON.stringify(await postures()));
    assert.equal(((await newestBelieved())!["attachmentRoute"] as { state: string }).state, "routed");
    assert.equal(await serve("status"), SERVE_EXIT.ok, `${out}${err}`);
    assert.doesNotMatch(out, /ROUTE LOST|✗/);
    assert.doesNotMatch(await doctorRows(), /no longer routes/);
    assert.match(log(), /attachment openclaw:main: the route is back/);

    // 5. The model fence (openclaw-plugin.md §3.6, "The model fence"): the
    //    install wrote OpenClaw's model allowlist and recorded its keys.
    const fence = readDeclaredList(env).attachments[0]!.allowlist!;
    assert.deepEqual([...fence].sort(), ["anthropic/*", "anthropic/claude-sonnet-4-6", "openai/*"], "the install recorded the fence");
    const write = (d: unknown): string => {
      const text = JSON.stringify(d, null, 2);
      writeFileSync(`${cfg}.tmp`, text);
      renameSync(`${cfg}.tmp`, cfg);
      return text;
    };
    const fenced = JSON.parse(readFileSync(cfg, "utf8")) as { agents: { defaults: { models?: Record<string, unknown> } } };
    assert.deepEqual(Object.keys(fenced.agents.defaults.models ?? {}).sort(), [...fence].sort());
    // 5a. The allowlist deleted: any model is one switch away.
    const noFence = JSON.parse(JSON.stringify(fenced));
    delete noFence.agents.defaults.models;
    write(noFence);
    assert.ok(await until(() => route()?.state === "lost", 90_000), `fence gone: ${JSON.stringify(route())}\n${log()}`);
    assert.deepEqual(route()!.problems.map((p) => p.code), ["model-fence"]);
    assert.ok(await until(async () => gapOf(await newestBelieved()) === "model-route-lost", 30_000), `the believed record: ${JSON.stringify(await postures())}\n${log()}`);
    const far = (await newestBelieved())!["attachmentRoute"] as { state: string; problems: Array<{ code: string; detail: string }> };
    assert.equal(far.problems[0]!.code, "model-fence");
    assert.match(far.problems[0]!.detail, /the model allowlist \(agents\.defaults\.models\) Mandu wrote at the install is gone/);
    assert.notEqual(await serve("status"), SERVE_EXIT.ok);
    assert.match(out, /openclaw:main: .*ROUTE LOST/);
    assert.match(out, /problem: +✗ openclaw:main: the OpenClaw config no longer routes through Mandu .*: the model allowlist \(agents\.defaults\.models\) Mandu wrote at the install is gone/);
    assert.match(await doctorRows(), /✗ openclaw:main: the OpenClaw config no longer routes through Mandu/);
    const doctorFacts = await gatherOpenclawAttach(env, { uid: process.getuid?.(), probe: (port) => probeIdentity("127.0.0.1", port), pluginDir });
    const oc = openclawAttachRows(doctorFacts).join("\n");
    assert.match(oc, /✗ the model allowlist \(agents\.defaults\.models\) Mandu wrote at the install is gone/, "the doctor's own read of the file says the same");
    assert.match(oc, /fix: mandu openclaw install, then openclaw gateway restart \(the install puts the fence back/);
    // 5b. Widened instead: a key of a provider Mandu does not route, beside
    //     the fence with one of its keys gone.
    const widened = JSON.parse(JSON.stringify(fenced));
    delete widened.agents.defaults.models["openai/*"];
    widened.agents.defaults.models["mistral/*"] = {};
    const widenedText = write(widened);
    assert.ok(await until(() => /names mistral\/\*/.test(route()?.problems[0]?.detail ?? ""), 90_000), `widened: ${JSON.stringify(route())}\n${log()}`);
    assert.equal(route()!.state, "lost");
    assert.match(route()!.problems[0]!.detail, /so a model switch can reach provider mistral, which Mandu does not route/);
    assert.equal(readFileSync(cfg, "utf8"), widenedText, "the service never rewrites the user's config");
    // 5c. Re-installed: the fence taken back (the key added since removed,
    //     the missing one written again), routed, the kind's own gap again.
    assert.equal(await install(), 0, `re-install over the fence: ${iout}`);
    assert.match(iout, /took the model fence back: removed mistral\/\* from agents\.defaults\.models/);
    const restored = JSON.parse(readFileSync(cfg, "utf8")) as { agents: { defaults: { models: Record<string, unknown> } } };
    assert.deepEqual(Object.keys(restored.agents.defaults.models).sort(), [...fence].sort(), "the fence is back, key for key");
    assert.deepEqual([...readDeclaredList(env).attachments[0]!.allowlist!].sort(), [...fence].sort());
    assert.ok(await until(() => route()?.state === "routed", 90_000), `fence back: ${JSON.stringify(route())}\n${log()}`);
    assert.ok(await until(async () => gapOf(await newestBelieved()) === "openclaw-plugin", 30_000), JSON.stringify(await postures()));
    assert.equal(await serve("status"), SERVE_EXIT.ok, `${out}${err}`);
    assert.doesNotMatch(out, /ROUTE LOST|✗/);
    assert.equal(await serve("stop"), SERVE_EXIT.ok, err);
  } finally {
    fake.stopAll();
    for (const pid of dashboardPidsOf(base)) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
    await sweepRuntimeProcesses(base);
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    rmSync(tmp, { recursive: true, force: true });
  }
});
