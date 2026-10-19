/**
 * demo.test (e2e) — `mandu demo` end to end, offline, through the REAL
 * services (docs/design/distribution/mandu-demo.md §6): the arbiter, both
 * model proxies (anthropic-proxy for Claude Code's wire, openai-proxy for
 * Codex's, each reaching the demo's loopback stand-in model over the
 * plain-http loopback transport), the egress proxy with TLS inspection
 * (net-proxy, its host routes dialing the demo's loopback stand-in sites),
 * the reply filter, and a real `curl`.
 *
 * The CLI runs twice: from source (dev layout) and from a freshly built
 * bundle (installed layout, `node dist/mandu.mjs`), the shape a user's
 * tarball runs. The invariant (secrets mode, confidentiality ON) is read
 * back from the kept sandbox, not from the demo's own summary: every request
 * body the stand-in model received (run/model-requests.jsonl, both wires)
 * holds no form of the fake key, and the `.env` read reached it as a `$MDU:`
 * placeholder; the human-facing output carries the key.
 *
 * Sabotage (in-process, real services, one dependency broken each): a model
 * proxy that is bypassed (the AI gets the key), a reply filter that does not
 * restore, an egress proxy that cannot resolve (no release at the bound
 * host), a policy that binds the unbound host too (the send gets through).
 * Each must fail the run with exit 1 and say why: a check that cannot fail
 * proves nothing.
 *
 * The guard (mandu-demo.md §3): where this host runs Mandu's whole-agent
 * guard (the bin resolves and seccomp user notification attaches, probed
 * here independently of the demo), every command the agent runs is inside
 * it, and Codex's `cat .env` reaches the model per key (the arbiter's
 * exec-output twin rule, released on the guard's record of the call's
 * processes); a run with the guard turned off (MANDU_NET_GUARD=0, the
 * launch's own opt-out) shows the whole file and says why in plain words.
 * A guard whose reports the arbiter cannot believe (the data socket only)
 * leaves the read whole, and the run FAILS: the release rests on the
 * guard's attested record, not on the text.
 *
 * Offline: a run inside a network namespace that holds only loopback
 * (`unshare -rn`, skipped where unprivileged user namespaces are not
 * allowed) passes too, so nothing the demo does needs the network.
 *
 * Isolation: the child runs with a temp HOME / XDG roots / runtime dir; the
 * test asserts the demo wrote nothing into that HOME and left no process
 * behind. ^C-safe cleanup (mandu-demo.md §3 "Signals"): a run presses ^C
 * through a deliberately slow cleanup and asserts the demo still exits on its
 * own, the sandbox removed and no service left.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { stateAxes } from "../axes.js";
import { runDemo, realDemoDeps, type DemoDeps } from "../../src/demo/demo.js";
import { Layout } from "../../src/services/layout.js";
import { basicAuth, secretForms, SYMBOL_RE } from "../../src/demo/fixture.js";
import { PLAIN } from "../../src/demo/render.js";
import { pickTempBase } from "../../src/demo/sandbox.js";
import { guardServed, wholeFileWhy } from "../../src/demo/guard.js";
import { resolveNativeBin } from "../../src/services/native-bins.js";

// The demo pins `secrets` inside its sandbox; this suite states the same axes.
stateAxes("secrets");

const PKG = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const REPO = join(PKG, "..");
const has = (cmd: string, args: string[]): boolean => spawnSync(cmd, args, { stdio: "ignore" }).status === 0;
const NETWORK_TOOLS = has("curl", ["--version"]) && has("openssl", ["version"]);
const INTERNALS = ["arbiter", "proxy", "reply filter", "$MDU", "bytes"];

/** Does this host run Mandu's guard? The bin a launch resolves, attached for
 *  real once (its status file is written only when it supervises the tree).
 *  Probed apart from the demo, so a demo that silently ran without it fails. */
function guardAttaches(): boolean {
  if (process.platform !== "linux") return false;
  const bin = resolveNativeBin("mandu-net-guard");
  if (bin === null) return false;
  const dir = mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "md-guard-"));
  try {
    const status = join(dir, "status");
    spawnSync(bin, ["--allow", "127.0.0.0/8:1", "--skip-unsupported", "--", "true"], { env: { ...process.env, MANDU_NET_GUARD_STATUS: status }, stdio: "ignore", timeout: 20_000 });
    return guardServed(existsSync(status) ? readFileSync(status, "utf8") : null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const GUARD = guardAttaches();

let tmp: string;
before(() => {
  // SHORT: the arbiter's human-plane socket lives under TMPDIR, and the
  // demo falls back to /tmp when it would not fit sun_path (sandbox.ts).
  tmp = mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "md-"));
});
after(() => { if (tmp) rmSync(tmp, { recursive: true, force: true }); });

interface Ran { code: number; stdout: string; stderr: string; home: string; base: string; ms: number }

let worlds = 0;
/** A private caller world under `tmp/<n>` (`label` names it in failures):
 *  HOME, XDG roots, TMPDIR short enough for the demo to use. */
function callerWorld(label: string): { home: string; base: string; env: Record<string, string | undefined> } {
  const dir = join(tmp, String(++worlds));
  const home = join(dir, "home");
  const base = join(dir, "t");
  mkdirSync(home, { recursive: true });
  mkdirSync(base, { recursive: true });
  assert.equal(pickTempBase(base), base, `${label}: the test's TMPDIR is too long for the demo's sockets`);
  return {
    home,
    base,
    env: {
      PATH: process.env["PATH"],
      HOME: home,
      XDG_CONFIG_HOME: join(home, ".config"),
      XDG_STATE_HOME: join(home, ".local", "state"),
      XDG_DATA_HOME: join(home, ".local", "share"),
      XDG_RUNTIME_DIR: join(dir, "run"),
      TMPDIR: base,
      MANDU_HOME: join(dir, "mandu-home"),
      COLUMNS: "100",
      NPM_CONFIG_UPDATE_NOTIFIER: "false",
      // Keys and a proxy in the caller's env must not matter (and must not travel).
      ANTHROPIC_API_KEY: "sk-ant-e2e-must-not-travel",
      OPENAI_API_KEY: "sk-openai-e2e-must-not-travel",
      HTTPS_PROXY: "http://127.0.0.1:9/never-used",
    },
  };
}

/** Processes still running with this sandbox's arbiter socket in their
 *  environment (the demo's services all carry it), after a grace for one
 *  still exiting: the demo signals its services and returns, and a node
 *  service may take a moment to finish its SIGTERM handler (CI 2026-10-05).
 *  One still there after 10 s outlived the demo. */
function servicesUnder(sb: string): string[] {
  let left = servicesNow(sb);
  for (let i = 0; i < 100 && left.length > 0; i++) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
    left = servicesNow(sb);
  }
  return left;
}

/** The same, once. Linux /proc; elsewhere, the command lines. */
function servicesNow(sb: string): string[] {
  const needle = `MANDU_ARBITER_SOCK=${join(sb, "run", "a.sock")}`;
  if (existsSync("/proc/self/environ")) {
    const left: string[] = [];
    for (const pid of readdirSync("/proc").filter((d) => /^\d+$/.test(d))) {
      try {
        if (readFileSync(`/proc/${pid}/environ`, "latin1").split("\0").includes(needle)) left.push(pid);
      } catch { /* gone, or not ours */ }
    }
    return left;
  }
  const ps = spawnSync("ps", ["-eo", "args="], { encoding: "utf8" }).stdout ?? "";
  return ps.split("\n").filter((l) => l.includes(sb));
}

function runCli(argv: string[], label: string, extra: string[] = [], extraEnv: Record<string, string> = {}): Ran {
  const { home, base, env: world } = callerWorld(label);
  const env = { ...world, ...extraEnv };
  const t0 = Date.now();
  const r = spawnSync(argv[0]!, [...argv.slice(1), "demo", "--keep", ...extra], { cwd: PKG, env, encoding: "utf8", timeout: 120_000 });
  return { code: r.status ?? -1, stdout: r.stdout ?? "", stderr: (r.stderr ?? "") + (r.error ? String(r.error) : ""), home, base, ms: Date.now() - t0 };
}

interface Kept { sb: string; key: string; bodies: Array<{ agent: string; scene: number; wire: string; body: string }> }

function kept(r: Ran): Kept {
  const names = readdirSync(r.base).filter((n) => n.startsWith("mandu-demo-"));
  assert.equal(names.length, 1, `one kept sandbox under TMPDIR, got ${names.join(",")}`);
  const sb = join(r.base, names[0]!);
  const envText = readFileSync(join(sb, "project", ".env"), "utf8");
  const key = /^STRIPE_KEY=(.+)$/m.exec(envText)?.[1];
  assert.ok(key && /^sk_live_demo_fake_[a-z2-9]{16}$/.test(key), envText);
  const bodies = readFileSync(join(sb, "run", "model-requests.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l) as Kept["bodies"][number]);
  return { sb, key, bodies };
}

/** The tool result text of a captured body's LAST tool result. */
function lastResult(body: string): string {
  const j = JSON.parse(body) as { messages?: Array<{ content?: unknown }>; input?: Array<Record<string, unknown>> };
  let found = "";
  for (const m of j.messages ?? []) for (const b of Array.isArray(m.content) ? m.content as Array<Record<string, unknown>> : []) if (b["type"] === "tool_result") found = JSON.stringify(b["content"]);
  for (const it of j.input ?? []) if (it["type"] === "custom_tool_call_output") found = JSON.stringify(it["output"]);
  return found;
}

/** The guard's status file for one agent's scene, from the kept sandbox. */
function guardStatus(k: Kept, agent: string, scene: number): string | null {
  const f = join(k.sb, "run", `net-guard-${agent}-${scene}.status`);
  return existsSync(f) ? readFileSync(f, "utf8") : null;
}

/** `guard`: whether Codex's commands must have run under the guard (true),
 *  must not have (false). */
function assertInvariant(r: Ran, agents: Array<"claude" | "codex">, guard: boolean = GUARD): Kept {
  assert.equal(r.code, 0, `demo failed:\n${r.stdout}\n${r.stderr}`);
  const k = kept(r);

  // (1) THE MODEL SIDE: every request the stand-in model received, verbatim.
  assert.deepEqual([...new Set(k.bodies.map((b) => b.agent))], agents);
  assert.equal(k.bodies.length, agents.length * 6, "two model calls per scene, three scenes per agent");
  for (const b of k.bodies) {
    for (const v of secretForms({ stripeKey: k.key })) assert.ok(!b.body.includes(v), `${b.agent} scene ${b.scene}: the model received ${v}`);
    for (const callerKey of ["sk-ant-e2e-must-not-travel", "sk-openai-e2e-must-not-travel"]) assert.ok(!b.body.includes(callerKey), "the caller's key reached the model");
  }
  for (const agent of agents) {
    const wire = agent === "claude" ? "anthropic" : "openai";
    const mine = k.bodies.filter((b) => b.agent === agent);
    assert.ok(mine.every((b) => b.wire === wire), `${agent} spoke its own wire`);
    // Scene 1's read reached the model as a placeholder the arbiter minted.
    const read = lastResult(mine.filter((b) => b.scene === 1).pop()!.body);
    assert.match(read, new RegExp(SYMBOL_RE.source), `${agent}: the .env read reached the model as a placeholder: ${read}`);
    if (agent === "claude") assert.match(read, /STRIPE_KEY='\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY'/, "Claude Code's Read of the copy: keys, field placeholders");
    if (agent === "codex") {
      // Codex's `cat .env`: per key only on the guard's record (plan 10 §11.8).
      const scenes = NETWORK_TOOLS ? [1, 2, 3] : [1];
      for (const sc of scenes) assert.equal(guardServed(guardStatus(k, agent, sc)), guard, `Codex step ${sc} ${guard ? "ran without" : "ran under"} the guard`);
      if (guard) {
        assert.match(read, /STRIPE_KEY='\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY'/, `Codex's cat .env under the guard: keys, field placeholders: ${read}`);
        assert.match(read, /\[mandu:secret\] twin: /, "and the twin note");
      } else {
        assert.doesNotMatch(read, /\.STRIPE_KEY'/, `Codex's cat .env with no guard is one placeholder: ${read}`);
        assert.match(r.stdout, /‹hidden› \(the whole file\)\n {22}the keys show only under Mandu's guard, /, r.stdout);
      }
    }
  }

  // (2) THE HUMAN SIDE: the terminal shows the key, in plain words.
  assert.ok(r.stdout.includes(`STRIPE_KEY='${k.key}'`), `the terminal lacks the key:\n${r.stdout}`);
  assert.match(r.stdout, /^ {6}the AI got {6}STRIPE_KEY=‹hidden›$/m);
  if (NETWORK_TOOLS) {
    assert.match(r.stdout, /sent {12}api\.stripe\.com got the real key, filled in on the way out ✓/);
    assert.match(r.stdout, /stopped {9}nothing was sent to paste\.example;/);
    assert.match(r.stdout, /✓ The AI never got the key\. It went only to api\.stripe\.com, and you saw it\./);
  } else {
    assert.match(r.stdout, /skipped\s+this step needs/);
  }
  assert.ok(r.stdout.trimEnd().endsWith("Next: try it with your own agent → https://github.com/mandusec/mandu/blob/main/docs/first-session.md"), r.stdout);

  // Isolation: nothing written into the caller's HOME; no service outlives the demo.
  assert.deepEqual(readdirSync(r.home), [], "the demo wrote into the caller's HOME");
  const left = servicesUnder(k.sb);
  assert.deepEqual(left, [], `a demo service is still running: ${left.join(",")}`);
  return k;
}

test("mandu demo from source: both agents, plain words, the key hidden from the AI, used at its host, stopped elsewhere", { timeout: 150_000 }, () => {
  const r = runCli([join(PKG, "node_modules", ".bin", "tsx"), join(PKG, "src", "run.ts")], "dev");
  assertInvariant(r, ["claude", "codex"]);
  // The default output: no internals, Codex folded into one line.
  for (const w of INTERNALS) assert.ok(!r.stdout.includes(w), `the default output names ${w}:\n${r.stdout}`);
  if (GUARD) assert.match(r.stdout, /^Codex ─+\n 1 · 2 · 3 +the same three steps, through Codex {2}[✓–] [✓–] [✓–]$/m);
  else assert.match(r.stdout, /^Codex ─+\n 1 {2}The agent reads \.env$/m, "no guard: Codex's different step 1 is shown in full");
  assert.ok(!r.stdout.includes("\x1b["), "no color on a pipe");
  // No wall-clock budget here: from source, every service and every reply
  // filter is a tsx process that transpiles its package on start, and this
  // test is the first of its file, run beside the suite's other files. Its
  // time followed the guest's load, not the demo (CI 2026-10-11: 53 s in a
  // run whose concurrent doctor test also took its longest, 64 s against a
  // median of 33; 142 runs: median 23 s, p99 36 s), while the demo alone
  // under 20 busy CPUs took 5 to 8 s with no stalled step. The user's
  // shape, the bundle, keeps its budget below.
});

test("mandu demo from the installed bundle (node dist/mandu.mjs), --verbose: the bound host got the key exactly as curl sends it", { timeout: 240_000 }, () => {
  // A private dir named `dist` so Layout.detect picks the installed layout.
  const dist = join(tmp, "pkg", "dist");
  const b = spawnSync("node", [join(PKG, "scripts", "build-bundle.mjs"), `--outdir=${dist}`], { cwd: PKG, encoding: "utf8", timeout: 180_000 });
  assert.equal(b.status, 0, `build-bundle failed:\n${b.stdout}\n${b.stderr}`);
  const r = runCli(["node", join(dist, "mandu.mjs")], "installed", ["--verbose"]);
  const k = assertInvariant(r, ["claude", "codex"]);
  assert.match(r.stdout, /· started the protection service \(arbiter\)/);
  assert.match(r.stdout, /· started the model-API proxy for Codex \(openai-proxy\)/);
  assert.match(r.stdout, /· the AI's placeholder: \$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/);
  if (NETWORK_TOOLS) {
    const want = `Authorization: ${basicAuth(k.key)}`;
    assert.equal(r.stdout.split(`api.stripe.com received 1 request(s): ${want}`).length - 1, 2, `each agent's curl reached the bound host with the real key:\n${r.stdout}`);
    assert.match(r.stdout, /answered on this machine: egress withheld 1 symbol\(s\) → block \(fail-closed\) \[egress:secret-unbound\]/);
    assert.match(r.stdout, /Approvals row egr-\d+: \$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY → paste\.example, pending, asked 2 time\(s\)/);
  }
  assert.ok(r.ms < 30_000, `the installed demo took ${r.ms} ms`);
});

test("mandu demo with the guard turned off (MANDU_NET_GUARD=0): Codex's read is hidden whole, the screen says why, Codex is shown in full", { timeout: 150_000 }, () => {
  const r = runCli([join(PKG, "node_modules", ".bin", "tsx"), join(PKG, "src", "run.ts")], "guard-off", [], { MANDU_NET_GUARD: "0" });
  assertInvariant(r, ["claude", "codex"], false);
  assert.ok(r.stdout.includes(`      the AI got      ‹hidden› (the whole file)\n                      ${wholeFileWhy(process.platform === "linux" ? "turned-off" : "linux-only")}\n`), r.stdout);
  assert.match(r.stdout, /^Codex ─+\n 1 {2}The agent reads \.env$/m);
  for (const w of INTERNALS) assert.ok(!r.stdout.includes(w), `the default output names ${w}:\n${r.stdout}`);
});

test("mandu demo: a ^C during its cleanup is ignored, the sandbox is removed, no service is left", { timeout: 150_000 }, async () => {
  const { base, env } = callerWorld("sigint");
  // `node --import tsx`, not the tsx CLI: the ^C must reach the demo's own
  // process, not a wrapper relaying (or acting on) it.
  const child = spawn(process.execPath, ["--import", "tsx", join(PKG, "src", "run.ts"), "demo", "--agent", "claude"], {
    cwd: PKG, env, stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (c: string) => (stdout += c));
  child.stderr.setEncoding("utf8").on("data", (c: string) => (stderr += c));

  // No test hook in the demo: make its cleanup slow instead. Once the sandbox
  // exists, fill it with many small files, so the synchronous removal (the
  // window a ^C used to kill) takes a while. Then, once the run's last scene
  // is out, press ^C every few ms for as long as the sandbox still exists.
  let sb: string | null = null;
  let presses = 0;
  const lastScene = NETWORK_TOOLS ? "in a real session the dashboard asks you" : "skipped";
  const tick = setInterval(() => {
    if (sb === null) {
      const n = readdirSync(base).find((x) => x.startsWith("mandu-demo-"));
      // mkdtemp comes before the sandbox's own mkdirs: wait for project/.
      if (n === undefined || !existsSync(join(base, n, "project"))) return;
      sb = join(base, n);
      const bulk = join(sb, "project", "bulk");
      mkdirSync(bulk);
      for (let i = 0; i < 20_000; i++) writeFileSync(join(bulk, `f${i}`), "x");
      return;
    }
    if (stdout.includes(lastScene) && existsSync(sb)) {
      child.kill("SIGINT");
      presses++;
    }
  }, 5);
  const [code, signal] = await new Promise<[number | null, NodeJS.Signals | null]>((resolve) => {
    child.on("close", (c, s) => resolve([c, s]));
  });
  clearInterval(tick);

  assert.equal(signal, null, `the demo was killed by ${signal} (a ^C during cleanup took the default action)\n${stdout}\n${stderr}`);
  assert.equal(code, 0, `demo failed:\n${stdout}\n${stderr}`);
  assert.ok(sb !== null, "the sandbox was seen");
  assert.ok(presses > 0, "at least one ^C landed while the sandbox still existed (the cleanup window)");
  assert.ok(!existsSync(sb), `the sandbox ${sb} was left behind`);
  assert.deepEqual(readdirSync(base).filter((n) => n.startsWith("mandu-demo-")), []);
  assert.match(stdout, /The AI never got the key/, "the result still printed");
  // At most one plain line, however many presses.
  assert.ok((stderr.match(/\^C is ignored/g) ?? []).length <= 1, stderr);
  const left = servicesUnder(sb);
  assert.deepEqual(left, [], `a demo service is still running: ${left.join(",")}`);
});

// ── sabotage: each check must be able to fail ───────────────────────────────

/** Run the demo in this process over the real services, with `wrap`
 *  replacing some of its dependencies. */
async function sabotaged(label: string, agent: "claude" | "codex", wrap: (d: DemoDeps) => Partial<DemoDeps>): Promise<{ code: number; text: string; base: string }> {
  const { base, env } = callerWorld(label);
  const layout = Layout.dev(REPO, PKG);
  const real = realDemoDeps(layout, env);
  let text = "";
  const signals = { on: () => undefined, off: () => undefined, pid: process.pid };
  const deps: DemoDeps = { ...real, tmpBase: () => pickTempBase(base), out: (s) => { text += s; }, style: PLAIN, signals, ...wrap(real) };
  const code = await runDemo(["--agent", agent], env, layout, deps);
  return { code, text, base };
}

function assertFailed(r: { code: number; text: string; base: string }, why: RegExp): void {
  assert.equal(r.code, 1, `the sabotaged demo passed:\n${r.text}`);
  assert.match(r.text, why);
  assert.match(r.text, /✗ FAILED: /);
  const left = readdirSync(r.base).filter((n) => n.startsWith("mandu-demo-"));
  assert.deepEqual(left, [], `the sandbox is removed on a failed run too; left: ${left.flatMap((n) => treeOf(join(r.base, n))).join(", ")}\n${r.text}`);
}

// The demo's own stop of a real detached service: it resolves only once the
// process has exited, so a service that writes into the sandbox while it
// shuts down (the arbiter's event log re-creates its directory) cannot
// re-create the sandbox after its removal. Before 2026-10-09 the stop only
// signalled, and "the sandbox is removed on a failed run too" failed on
// loaded CI guests. Deterministic: the stand-in service writes 300 ms after
// its SIGTERM.
test("the demo's service stop waits for the exit: a service writing into the sandbox while it shuts down leaves nothing behind", { timeout: 60_000 }, async () => {
  const { base, env } = callerWorld("late-writer");
  const sandbox = join(base, "mandu-demo-late");
  const late = join(sandbox, "mandu", "events");
  mkdirSync(late, { recursive: true });
  const script = `process.on("SIGTERM", () => setTimeout(() => { const fs = require("node:fs"); fs.mkdirSync(process.env.LATE, { recursive: true }); fs.writeFileSync(process.env.LATE + "/late.ndjson", "{}\\n"); process.exit(0); }, 300)); setInterval(() => {}, 1000);`;
  const layout = { daemon: () => ({ cmd: process.execPath, args: ["-e", script], cwd: base, env: {} }) } as unknown as Layout;
  const svc = realDemoDeps(layout, env).startService("arbiter", { ...process.env, LATE: late } as Record<string, string>, join(base, "late.log"));
  await new Promise((r) => setTimeout(r, 300)); // its SIGTERM handler is set
  await svc.stop();
  rmSync(sandbox, { recursive: true, force: true });
  await new Promise((r) => setTimeout(r, 600));
  assert.equal(existsSync(sandbox), false, `the service wrote into the sandbox after the stop resolved: ${treeOf(sandbox).join(", ")}`);
});

/** Every path under `dir` (what a run left behind, for its failure). */
function treeOf(dir: string): string[] {
  try {
    return readdirSync(dir, { recursive: true, encoding: "utf8" }).map((p) => join(dir, p));
  } catch (e) { return [`${dir} (${(e as Error).message})`]; }
}

for (const agent of ["claude", "codex"] as const) {
  test(`sabotage (${agent}): with the model proxy bypassed and no placeholder copy, the AI gets the key and the run FAILS`, { timeout: 120_000 }, async () => {
    let modelOrigin = "";
    const r = await sabotaged(`leak-${agent}`, agent, (d) => ({
      startModel: async (project) => { const m = await d.startModel(project); modelOrigin = m.origin; return m; },
      // The agent talks to the model directly, as with no Mandu in between…
      postModel: (_port, wire, body, session) => d.postModel(Number(new URL(modelOrigin).port), wire, body, session),
      // …and its .env is the real one.
      writeFile: (path, text) => d.writeFile(path, path.endsWith(join("agent-view", ".env")) ? (d.readText(path.replace(join("agent-view", ".env"), join("project", ".env"))) ?? text) : text),
    }));
    assertFailed(r, new RegExp(`${agent === "claude" ? "Claude Code" : "Codex"} step 1: the AI received the real key`));
  });
}

test("sabotage: a reply filter that does not restore fails the run (your screen did not show the key)", { timeout: 120_000 }, async () => {
  const r = await sabotaged("no-restore", "claude", (d) => ({
    runReplyFilter: async (_env, file) => ({ code: 0, stdout: d.readText(file) ?? "", stderr: "" }),
  }));
  assertFailed(r, /Claude Code step 1: your screen did not show the real key/);
});

test("sabotage: an egress proxy that cannot resolve the key releases nothing, and the run FAILS", { skip: !NETWORK_TOOLS && "curl or openssl is not installed", timeout: 120_000 }, async () => {
  const r = await sabotaged("no-release", "claude", (d) => ({
    startService: (name, env, log) => {
      if (name !== "net-proxy") return d.startService(name, env, log);
      const { MANDU_ARBITER_HUMAN_SOCK: _drop, ...rest } = env;
      return d.startService(name, rest, log);
    },
  }));
  assertFailed(r, /Claude Code step 2: api\.stripe\.com received nothing/);
});

test("sabotage: a guard whose reports the arbiter cannot believe (the data socket only) leaves Codex's read whole, and the run FAILS", { skip: !GUARD && "this host does not run Mandu's guard (not built, or no seccomp user notification)", timeout: 120_000 }, async () => {
  // The guard still runs and serves the tree (its status file), but an
  // explicit human socket that does not answer as the human plane makes it
  // report on the data socket, where every report is a claim (plan 13 D9):
  // no call is bound, so no twin release.
  const r = await sabotaged("guard-claims", "codex", (d) => ({
    runCommand: (argv, cwd, env) => d.runCommand(argv, cwd, argv[0] === "sh" ? env : { ...env, MANDU_ARBITER_HUMAN_SOCK: env["MANDU_ARBITER_SOCK"]! }),
  }));
  assertFailed(r, /Codex step 1: the AI got the whole file, not each key, under Mandu's guard/);
});

test("sabotage: a policy that binds paste.example too lets the send through, and the run FAILS", { skip: !NETWORK_TOOLS && "curl or openssl is not installed", timeout: 120_000 }, async () => {
  const r = await sabotaged("unbound-through", "codex", (d) => ({
    writeFile: (path, text) => d.writeFile(path, text.replace("bindings: [api.stripe.com]", "bindings: [api.stripe.com, paste.example]")),
  }));
  assertFailed(r, /Codex step 3: paste\.example received the request; no approval was raised for you/);
});

// ── offline ──────────────────────────────────────────────────────────────────

/** A way to run a command in a fresh network namespace holding only a
 *  loopback that is up: bwrap (`--unshare-net` brings `lo` up), else
 *  `unshare -rn` + `ip link set lo up`. Both need unprivileged user
 *  namespaces; null where neither runs. */
function loopbackOnly(): ((argv: string[]) => string[]) | null {
  if (process.platform !== "linux") return null;
  if (spawnSync("bwrap", ["--unshare-net", "--dev-bind", "/", "/", "true"], { stdio: "ignore" }).status === 0) {
    return (argv) => ["bwrap", "--unshare-net", "--dev-bind", "/", "/", "--", ...argv];
  }
  if (spawnSync("unshare", ["-rn", "sh", "-c", "ip link set lo up"], { stdio: "ignore" }).status === 0) {
    return (argv) => ["unshare", "-rn", "sh", "-c", 'ip link set lo up && exec "$0" "$@"', ...argv];
  }
  return null;
}
const NETNS = loopbackOnly();

test("offline: the whole demo passes in a network namespace that holds only loopback (no route out, no DNS)", { skip: NETNS === null && "neither bwrap --unshare-net nor unshare -rn runs here (unprivileged user namespaces)", timeout: 150_000 }, () => {
  const { home, base, env } = callerWorld("netns");
  // The namespace really is cut off: no interface but lo.
  const probe = NETNS!(["cat", "/proc/net/dev"]);
  const dev = spawnSync(probe[0]!, probe.slice(1), { encoding: "utf8" }).stdout ?? "";
  assert.deepEqual(dev.split("\n").slice(2).map((l) => l.split(":")[0]!.trim()).filter(Boolean), ["lo"], dev);
  const argv = NETNS!([join(PKG, "node_modules", ".bin", "tsx"), join(PKG, "src", "run.ts"), "demo", "--keep"]);
  const r = spawnSync(argv[0]!, argv.slice(1), { cwd: PKG, env, encoding: "utf8", timeout: 120_000 });
  assertInvariant({ code: r.status ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "", home, base, ms: 0 }, ["claude", "codex"]);
  if (NETWORK_TOOLS) assert.match(r.stdout, /It went only to api\.stripe\.com/);
});
