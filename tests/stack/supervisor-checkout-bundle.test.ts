/**
 * supervisor-checkout-bundle — the dashboard's supervisor starts the REAL
 * arbiter and proxies of a checkout from that checkout's prebuilt bundle while
 * the bundle is fresh, and from source as one node process when it is not
 * (packaging.md §5.1; dashboard.md §4.8 "How a service is started"). Never
 * `npm run serve`.
 *
 *   - the two tables of the services' sources (the dashboard's
 *     CHECKOUT_SOURCES, the launcher's SERVICE_SOURCES) agree;
 *   - a private build of the real bundle (build-bundle.mjs --outdir; the
 *     checkout's own launcher/dist, which other suites and sessions use, is
 *     never touched): fresh → the arbiter, the Anthropic proxy and the net
 *     proxy start from it (cwd the build's parent, the log names the build),
 *     each spawned pid the service itself (it leads its group; no npm, shell
 *     or tsx binary in it), and the proxies SERVE: a request through
 *     the Anthropic proxy reaches a local upstream, the net proxy answers;
 *   - the bundled arbiter's policy classifier (inspect-mcp's classify-main)
 *     is the build's own bundle, never tsx + source, and a names-only model
 *     run through the arbiter reaches the policy's declared mock model;
 *   - the build goes stale (an input's recorded mtime moves): a RESTART of
 *     the proxy starts it from source (cwd its package, the log says why) and
 *     it serves again; a stale bundle is never started;
 *   - stopping reaps every process the supervisor started (no pid survives);
 *   - the resident dashboard from the same build (a dist/ beside src/run.ts)
 *     knows a checkout's build, never takes itself for an installed package,
 *     and serves its product page.
 *
 * The production definitions are used as built (buildDefinitions), with one
 * change: the proxies' readiness is the port-file kind on port 0
 * (test-organization.md §8.4) so no port is picked and raced for.
 * Axes stated: secrets (the arbiter decides nothing here; it must start).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readlinkSync, rmSync, writeFileSync } from "node:fs";
import { createServer, request, type Server } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { Supervisor } from "../../dashboard/src/supervisor/supervisor.js";
import {
  buildDefinitions, CHECKOUT_SOURCES, DEFAULTS, type ResolvedSupervisorOptions, type ServiceDefinition, type ServiceId,
} from "../../dashboard/src/supervisor/supervisor-defs.js";
import { SERVICE_SOURCES } from "../../launcher/src/services/layout.js";
import { stateAxes } from "../lib/axes.js";
import { tmpDir } from "../lib/tmp-dir.js";

stateAxes("secrets");

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const BUILD = join(REPO, "launcher", "scripts", "build-bundle.mjs");
const STAMP = join(REPO, "launcher", "scripts", "bundle-stamp.mjs");
const SAVED = ["MANDU_HOME", "MANDU_RUNTIME_DIR", "MANDU_POLICY_FILE"] as const;
const saved = Object.fromEntries(SAVED.map((k) => [k, process.env[k]]));
const cleanups: Array<() => Promise<void> | void> = [];
after(async () => {
  for (const c of cleanups.reverse()) await c();
  for (const k of SAVED) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
});

test("the dashboard's table of service sources is the launcher's", () => {
  for (const [name, s] of Object.entries(CHECKOUT_SOURCES)) {
    assert.equal(s.entry, SERVICE_SOURCES[name as keyof typeof SERVICE_SOURCES], name);
    assert.ok(s.entry.startsWith(`${s.pkg}/`), `${name}: the entry lives in its package`);
  }
});

/** One HTTP request; resolves with the status and body, rejects on a
 *  connection error. `path` may be an absolute URL (a proxy request). */
function get(port: number, path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const r = request({ host: "127.0.0.1", port, path, method: "GET", timeout: 15_000 }, (res) => {
      let body = "";
      res.on("data", (c) => { body += c; });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
    r.on("timeout", () => r.destroy(new Error("timeout")));
    r.on("error", reject);
    r.end();
  });
}

const groupOf = (pid: number): number => Number(readFileSync(`/proc/${pid}/stat`, "utf8").replace(/^.*\) /, "").split(" ")[2]);
const membersOf = (pgid: number): number[] => {
  const r = spawnSync("ps", ["-eo", "pid=,pgid="], { encoding: "utf8" });
  return r.stdout.split("\n").map((l) => l.trim().split(/\s+/).map(Number)).filter(([, g]) => g === pgid).map(([p]) => p!);
};
/** /proc/<pid>/stat after the comm field ([0] state, [1] ppid, [2] pgid);
 *  [] for a process gone since it was listed. */
const statOf = (pid: number): string[] => {
  try { return readFileSync(`/proc/${pid}/stat`, "utf8").replace(/^.*\) /, "").split(" "); } catch { return []; }
};
const commOf = (pid: number): string => { try { return readFileSync(`/proc/${pid}/comm`, "utf8").trim(); } catch { return "?"; } };
/**
 * The spawned process IS the service: it leads its own group (the supervisor
 * spawns it detached, so a wrapper in front would lead instead), no member of
 * the group is npm, a shell or the tsx binary, and any other member is a
 * child the service started itself (from source, tsx's esbuild service; a
 * probe the service runs). Counting the group's members is not the property:
 * CI saw such a child beside the source form.
 */
function assertNoWrapper(pid: number, what: string): void {
  assert.equal(groupOf(pid), pid, `${what}: the spawned pid leads its group (nothing in front of it)`);
  const members = membersOf(pid);
  const desc = members.map((m) => `${m}:${commOf(m)}:ppid ${statOf(m)[1] ?? "?"}`).join(", ");
  for (const m of members) {
    assert.doesNotMatch(commOf(m), /^(npm|npm exec|sh|bash|dash|tsx)$/, `${what}: no npm, shell or tsx binary in the group (${desc})`);
    const st = statOf(m);
    if (m !== pid && st.length > 0) {
      assert.equal(Number(st[1]), pid, `${what}: any other member is the service's own child (${desc})`);
    }
  }
}
const alive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch { return false; } };

test("checkout supervisor: the real services start from a fresh bundle and serve; a stale bundle is never started (the restart runs the source); stop reaps every one",
  { timeout: 600_000 }, async () => {
  const dir = tmpDir("mdu-sup-bundle-");
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  const dist = join(dir, "build", "dist");
  const b = spawnSync(process.execPath, [BUILD, `--outdir=${dist}`, "--no-native", "--quiet"], { cwd: join(REPO, "launcher"), encoding: "utf8", timeout: 300_000 });
  assert.equal(b.status, 0, `the private build: ${b.stdout}\n${b.stderr}`);
  assert.equal(spawnSync(process.execPath, [STAMP, `--root=${REPO}`, dist]).status, 0, "the private build is fresh");

  // A local upstream for the Anthropic proxy: proof a request went through.
  let upstreamHits = 0;
  const upstream: Server = createServer((req, res) => {
    upstreamHits++;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ data: [], path: req.url }));
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
  cleanups.push(() => new Promise<void>((r) => upstream.close(() => r())));
  const upstreamUrl = `http://127.0.0.1:${(upstream.address() as { port: number }).port}`;

  // A mock "cloud" model the policy declares: the classifier's destination.
  let modelHits = 0;
  const model: Server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      modelHits++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ content: [{ type: "text", text: '{"rules":[]}' }] }));
    });
  });
  await new Promise<void>((r) => model.listen(0, "127.0.0.1", () => r()));
  cleanups.push(() => new Promise<void>((r) => model.close(() => r())));
  const modelUrl = `http://127.0.0.1:${(model.address() as { port: number }).port}`;
  const proj = join(dir, "user", "proj"); // the user's project, outside the Mandu home
  mkdirSync(join(proj, "docs"), { recursive: true });
  mkdirSync(join(dir, "home"), { recursive: true });
  writeFileSync(join(proj, "README.md"), "a readme\n");
  writeFileSync(join(proj, "docs", "notes.md"), "notes\n");
  writeFileSync(join(dir, "home", "policy.yaml"), `version: 1\nmodels:\n  - name: mock-cloud\n    url: ${modelUrl}\n    wire: anthropic\n    model: m-1\n    local: false\n`);

  process.env.MANDU_HOME = join(dir, "home");
  process.env.MANDU_RUNTIME_DIR = join(dir, "rt");
  // Named outright: the suite runner points every test at no policy file.
  process.env.MANDU_POLICY_FILE = join(dir, "home", "policy.yaml");
  const sock = join(dir, "run", "arbiter.sock");
  const resolved: ResolvedSupervisorOptions = {
    repoRoot: REPO, arbiterSock: sock, ...DEFAULTS, upstreamAnthropic: upstreamUrl, autoStartArbiter: true,
    startTimeoutMs: 120_000, checkoutDist: dist,
    axisEnv: () => ({ MANDU_INTEGRITY: "0", MANDU_CONFIDENTIALITY: "1" }), log: () => {}, gitRev: () => "nogit",
    gitChangedInRange: () => [], procCmdline: () => null, killPid: () => {}, discoverSocketOwner: () => null,
    bundleFresh: async () => ({ fresh: false, reason: "unused" }),
    ownArbiterBuild: () => ({ version: null, bundle: null, installed: false }),
  };
  const prod = buildDefinitions(resolved);
  const portFile = (id: string): string => join(dir, "ports", `${id}.port`);
  const viaPortFile = (id: ServiceId, portVar: string): ServiceDefinition => {
    const d = prod[id];
    const ready = { kind: "port-file" as const, path: portFile(id), host: "127.0.0.1" };
    return {
      ...d, ready, env: { ...d.env, [portVar]: "0" },
      ...(d.checkoutBundle ? { checkoutBundle: d.checkoutBundle } : {}),
    };
  };
  for (const id of ["arbiter", "anthropic-proxy", "net-proxy"] as const) {
    assert.ok(prod[id].checkoutBundle, `${id}: the production definition carries the bundled form`);
    assert.notEqual(prod[id].command, "npm", `${id}: never npm run serve`);
  }
  const logs: string[] = [];
  const sup = new Supervisor({
    repoRoot: REPO, arbiterSock: sock, checkoutDist: dist, startTimeoutMs: 120_000, stopGraceMs: 4000,
    axisEnv: () => ({ MANDU_INTEGRITY: "0", MANDU_CONFIDENTIALITY: "1" }),
    log: (m) => logs.push(m),
    definitions: {
      "anthropic-proxy": viaPortFile("anthropic-proxy", "MANDU_PROXY_PORT"),
      "net-proxy": viaPortFile("net-proxy", "MANDU_NET_PROXY_PORT"),
    },
  });
  cleanups.push(() => sup.shutdownAll());
  const pidOf = (id: ServiceId): number => sup.status().find((s) => s.id === id)!.pid!;
  const portOf = (id: ServiceId): number => Number(readFileSync(portFile(id), "utf8").trim());
  const started: number[] = [];

  // ── fresh: everything from the build ──
  await sup.start("arbiter");
  await sup.start("anthropic-proxy");
  await sup.start("net-proxy");
  for (const id of ["arbiter", "anthropic-proxy", "net-proxy"] as const) {
    const pid = pidOf(id);
    started.push(pid);
    assert.equal(readlinkSync(`/proc/${pid}/cwd`), dirname(dist), `${id}: runs from the build (cwd its parent); logs:\n${logs.join("\n")}`);
    assert.ok(logs.includes(`${id}: starting from the checkout's bundle (${dist})`), `${id}: the log names the build`);
    assertNoWrapper(pid, id);
  }
  const through = await get(portOf("anthropic-proxy"), "/v1/models");
  assert.equal(through.status, 200, `the Anthropic proxy serves from the bundle: ${through.body}`);
  assert.ok(upstreamHits >= 1, "the request reached the upstream through the proxy");
  const egress = await get(portOf("net-proxy"), "http://127.0.0.1:9/");
  assert.ok(egress.status >= 200 && egress.status < 600, `the net proxy answers from the bundle (${egress.status})`);

  // ── the bundled arbiter runs inspect-mcp's policy classifier from the same
  // build, never through tsx, and a names-only run through it reaches the
  // declared (mock) model ──
  // (The arbiter's own /proc cmdline is its ps title, so the argv read here is
  // the production definition's bundled form, the one the log above says the
  // supervisor started.)
  const arbArgv = prod.arbiter.checkoutBundle!.args;
  assert.ok(arbArgv.includes("--classifier"), `the arbiter is given its classifier: ${arbArgv.join(" ")}`);
  assert.deepEqual(JSON.parse(arbArgv[arbArgv.indexOf("--classifier") + 1]!), [process.execPath, "--no-warnings=ExperimentalWarning", join(dist, "policy-classifier.mjs")],
    "the classifier is the build's bundle");
  const client = new ArbiterClient(sock);
  await client.connect();
  try {
    const preview = await client.modelSuggestPreview([proj], { endpoint: "mock-cloud", home: join(dir, "user") });
    assert.ok(preview.requests >= 1, `the preview holds names to send: ${JSON.stringify(preview)}`);
    const run = await client.modelSuggest(preview.digest);
    assert.equal(run.error, null, run.error ?? "");
    assert.equal(run.counts.failedRequests, 0, "every request answered");
    assert.ok(modelHits >= 1, "the bundled classifier reached the declared model");
  } finally {
    client.close();
  }

  // ── stale: an input changed since the build; the restart runs the source ──
  const recPath = join(dist, ".bundle-stamp.json");
  const rec = JSON.parse(readFileSync(recPath, "utf8")) as { inputs: Record<string, [number, number]> };
  const rel = "interceptors/anthropic-proxy/src/server-main.ts";
  assert.ok(rec.inputs[rel], `${rel} is a recorded input`);
  rec.inputs[rel] = [rec.inputs[rel]![0] - 1000, rec.inputs[rel]![1]];
  writeFileSync(recPath, JSON.stringify(rec));
  await sup.restart("anthropic-proxy");
  const src = pidOf("anthropic-proxy");
  started.push(src);
  assert.equal(readlinkSync(`/proc/${src}/cwd`), join(REPO, CHECKOUT_SOURCES["anthropic-proxy"].pkg), "the restart runs the source, in its package");
  assert.ok(logs.some((m) => m.startsWith("anthropic-proxy: starting from source (") && m.includes(`${rel} changed since the build`)),
    `the log says why: ${logs.join("\n")}`);
  assertNoWrapper(src, "the source form");
  const hits = upstreamHits;
  const again = await get(portOf("anthropic-proxy"), "/v1/models");
  assert.equal(again.status, 200, `the Anthropic proxy serves from source: ${again.body}`);
  assert.ok(upstreamHits > hits);

  // ── stop: every process the supervisor started is gone ──
  await sup.shutdownAll();
  for (const pid of started) {
    for (let i = 0; i < 100 && alive(pid); i++) await new Promise((r) => setTimeout(r, 100));
    assert.equal(alive(pid), false, `pid ${pid} reaped`);
  }

  // ── the resident dashboard from the same build ──
  // A dist/ beside src/run.ts is a checkout's build: the dashboard bundle
  // takes itself for the dev layout (not an installed package) and serves.
  mkdirSync(join(dirname(dist), "src"), { recursive: true });
  writeFileSync(join(dirname(dist), "src", "run.ts"), "export {};\n");
  const dashPort = join(dir, "ports", "dashboard.port");
  let dashErr = "";
  const dash = spawn(process.execPath, ["--no-warnings=ExperimentalWarning", join(dist, "dashboard.mjs")], {
    cwd: dirname(dist), detached: true, stdio: ["ignore", "ignore", "pipe"],
    env: { ...process.env, DASHBOARD_PORT: "0", MANDU_PORT_FILE: dashPort, DASHBOARD_CONTROL: "0", MANDU_ARBITER_SOCK: join(dir, "none.sock") },
  });
  cleanups.push(() => { try { process.kill(-dash.pid!, "SIGKILL"); } catch { /* gone */ } });
  dash.stderr!.on("data", (d) => { dashErr += d; });
  for (let i = 0; i < 600 && !(existsSync(dashPort) && /\d/.test(readFileSync(dashPort, "utf8"))); i++) await new Promise((r) => setTimeout(r, 100));
  const page = await get(Number(readFileSync(dashPort, "utf8").trim()), "/");
  assert.equal(page.status, 200, `the dashboard from the build serves its product page; stderr:\n${dashErr}`);
  assert.match(dashErr, /layout: a checkout's build/, "it knows a checkout's build");
  assert.doesNotMatch(dashErr, /layout: installed/, "it never takes itself for an installed package");
});
