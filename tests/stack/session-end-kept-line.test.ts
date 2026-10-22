/**
 * session-end-kept-line — the line a `mandu <agent>` session ends with, what
 * Mandu kept from the AI, across the REAL components (packaging.md §5 *The
 * session's last line*; dashboard.md §4.25ah). Mandu-new.
 *
 * The REAL launcher (`tsx launcher/src/run.ts`, its own process, stdout and
 * stderr captured apart) runs a stand-in `claude`: a script that sends one
 * Messages request through the launch's autostarted anthropic-proxy, with a
 * Read of a `.env` in its history, as Claude Code does, prints a word of its
 * own on stdout and exits. The model is a stand-in on loopback (no key, no
 * network). A real ArbiterServer at the `secrets` axes keeps the record; a
 * real DashboardServer over the production event source serves the
 * human-plane socket (sign-in.ts serveSignInChannel, the production deps
 * `signInDepsFor`) and is registered in the launch's runtime registry as a
 * dashboard daemon registers itself.
 *
 *   L1  the line: on stderr, after the agent's own output, the session's
 *       last line; its count and name are Home's for that session (the
 *       agent page's tile, served by the same dashboard); never on stdout,
 *       which holds only the agent's word;
 *   L2  the oracle: the model never got the `.env` value, and neither
 *       stream nor any served answer carries it;
 *   L3  opt-out: MANDU_SESSION_SUMMARY=0 and --no-session-summary print no
 *       line, and the session runs the same;
 *   L4  best-effort: with the dashboard's socket gone, the session ends
 *       cleanly and prints no line (observability is off the security path).
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). No kernel
 * layer (MANDU_NO_KERNEL=1): the subject is the launcher's teardown and the
 * dashboard's projection, not the guard.
 *
 * Two hosts, one test. With no guard, the launch is walled off from the
 * human plane only by the bind wrap, which needs a bubblewrap that can make
 * a user namespace (`WALLED`, the launcher's own facts: confinement-posture
 * resolveHostPosture's `bwrap && userns`). A walled launch's record is
 * believed, and the line counts the `.env` (L1 as above). GitHub's
 * ubuntu-24.04 runner restricts unprivileged user namespaces (AppArmor;
 * continuous-integration.md §12.2), so there the launch is GATED with no
 * wall: every report on the human socket is a claim
 * (arbiter-human-plane.md §10.1), Home counts no claim, and the line says
 * what Home says. There L1 asserts that instead: the posture's gap is the
 * host's, EVERY event of the launch is stored as a claim (a believed one
 * would be the §10.1 regression), and the line is still stderr's last line
 * with Home's count. The branch is chosen by the probe, never by what the
 * launch printed, so a walled host whose launch lost its wall fails.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { serveSignInChannel, signInDepsFor, signInSockPath } from "../../dashboard/src/sign-in.js";
import { registerDashboard } from "../../dashboard/src/registry.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { runChildToExit } from "../lib/child-run.js";
import { LAUNCHER_MAIN, LAUNCHER_TSX, REPO_ROOT, STACK_TENANT } from "../lib/launcher-live.js";
import { assertStackPackages } from "../lib/stack-preflight.js";
import { stateAxes } from "../lib/axes.js";
import { systemBwrapBin } from "../../launcher/src/bwrap-path.js";
import { probeUserns } from "../../launcher/src/userns.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, the axis under test

/** The bind wrap can go up here, so a launch with no guard is walled off
 *  from the human plane (see the header). The launcher's own facts. */
const WALLED = systemBwrapBin() !== null && probeUserns();
/** The gaps of a host whose bubblewrap cannot make the namespace. */
const UNWALLED_GAPS = ["apparmor-userns", "userns-off", "no-bwrap"];

const VALUE = `sk_live_keptLine_${process.pid}_0000000000`;
const AGENT_WORD = "STAND-IN-AGENT-DONE";
// The launch's secret walk finds the file in the home folder, so the AI's
// copy of it is masked whole ("the file …"); a key-level mask names the key.
const LINE_RE = /^mandu: in this session: 1 secret masked before the AI saw it \((?:STRIPE_KEY in |the file )~\/elsewhere\/\.env\) · details: `mandu dashboard`$/;

let tmp: string;
let base: string; // the launch's runtime base: <XDG_RUNTIME_DIR>/mandu
let home: string;
let workspace: string;
let envFile: string;
let arbiter: ArbiterServer;
let dashboard: DashboardServer;
let dashUrl: string;
let channel: { path: string; close: () => Promise<void> } | null = null;
let model: Server;
let modelOrigin: string;
const seen: string[] = [];

before(async () => {
  assertStackPackages(REPO_ROOT, "session-end-kept-line");
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-kept-line-")));
  base = join(tmp, "mandu");
  mkdirSync(join(base, "human"), { recursive: true, mode: 0o700 });
  chmodSync(base, 0o700);
  home = join(tmp, "home");
  workspace = join(home, "work");
  mkdirSync(workspace, { recursive: true });
  // The secret file the agent reads: in the home folder (so its name reads
  // `~/…`), outside the workspace.
  mkdirSync(join(home, "elsewhere"));
  envFile = join(home, "elsewhere", ".env");
  writeFileSync(envFile, `STRIPE_KEY=${VALUE}\n`, { mode: 0o600 });
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(base, "human", "arbiter.sock");
  arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(tmp, "arbiter-admin.sock"), humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, tenant: STACK_TENANT,
  });
  await arbiter.listen();
  dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    configEnv: { MANDU_HOME: join(tmp, "dash-home") }, fileBrowserHome: home, log: () => {},
  } as ConstructorParameters<typeof DashboardServer>[0]);
  const port = await dashboard.listen(0);
  dashUrl = `http://127.0.0.1:${port}`;
  // The human-plane socket and the registry entry, as server-main makes them.
  channel = await serveSignInChannel(signInSockPath(base), signInDepsFor(dashboard));
  registerDashboard(base, {
    pid: process.pid, port, host: "127.0.0.1", startedAt: new Date().toISOString(), gitRev: "test",
    ownerPid: null, repoRoot: REPO_ROOT, basePath: "", signInSock: channel.path,
  } as Parameters<typeof registerDashboard>[1]);
  // The stand-in model: every request recorded, a short text answer.
  model = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      seen.push(b);
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(buildTextSse("Done.", { deltas: 1 }));
    });
  });
  await new Promise<void>((r) => model.listen(0, "127.0.0.1", r));
  modelOrigin = `http://127.0.0.1:${(model.address() as AddressInfo).port}`;
});

after(async () => {
  await channel?.close();
  await dashboard?.close();
  model?.close();
  await arbiter?.close();
  rmSync(tmp, { recursive: true, force: true });
});

/** The stand-in `claude`: one request through the proxy the launcher put in
 *  ANTHROPIC_BASE_URL, a Read of the `.env` in its history, the scope id to
 *  `out`, a word on stdout. */
function standInClaude(out: string): string {
  const dir = join(tmp, "bin");
  mkdirSync(dir, { recursive: true });
  const p = join(dir, "claude");
  const result = readFileSync(envFile, "utf8").split("\n").filter(Boolean).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";
  writeFileSync(p, `#!${process.execPath}
const fs = require("node:fs");
const messages = [
  { role: "user", content: "What is in my .env?" },
  { role: "assistant", content: [{ type: "tool_use", id: "toolu_kept_1", name: "Read", input: { file_path: ${JSON.stringify(envFile)} } }] },
  { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_kept_1", content: ${JSON.stringify(result)} }] },
];
(async () => {
  const r = await fetch(process.env.ANTHROPIC_BASE_URL.replace(/\\/+$/, "") + "/v1/messages", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": process.env.ANTHROPIC_API_KEY || "", "anthropic-version": "2023-06-01" },
    body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 64, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
  });
  await r.text();
  fs.writeFileSync(${JSON.stringify(out)}, JSON.stringify({ scope: process.env.MANDU_SCOPE_ID || "", status: r.status }));
  process.stdout.write(${JSON.stringify(AGENT_WORD)} + "\\n");
})().catch((e) => { fs.writeFileSync(${JSON.stringify(out)}, JSON.stringify({ error: String(e) })); process.exit(1); });
`, { mode: 0o755 });
  return p;
}

interface Launch { code: number; stdout: string; stderr: string; scope: string; status?: number; error?: string }

async function launch(name: string, extraArgs: string[] = [], extraEnv: Record<string, string> = {}): Promise<Launch> {
  const out = join(tmp, `${name}.json`);
  const agent = standInClaude(out);
  const r = await runChildToExit(LAUNCHER_TSX, [LAUNCHER_MAIN, "--target", "claude", "--no-mcp", ...extraArgs, "--", agent], {
    cwd: workspace, timeoutMs: 110_000, label: "launcher",
    env: {
      HOME: home, PATH: process.env["PATH"], PWD: workspace,
      MANDU_HOME: join(tmp, "mandu-home"), XDG_RUNTIME_DIR: tmp,
      MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_TENANT: STACK_TENANT, MANDU_NO_ARBITER_AUTOSTART: "1",
      MANDU_MODE: "secrets", MANDU_PROXY_PORT: "0", MANDU_OPENAI_PROXY_PORT: "0", MANDU_UPSTREAM: modelOrigin,
      MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_FS_SYNC: "0", MANDU_NO_KERNEL: "1", MANDU_EGRESS_HOLD_MS: "0",
      ANTHROPIC_API_KEY: "sk-ant-mdu-dummy", CLAUDE_CONFIG_DIR: join(tmp, "cc-config"),
      ...extraEnv,
    },
  });
  const got = existsSync(out) ? JSON.parse(readFileSync(out, "utf8")) as { scope?: string; status?: number; error?: string } : { error: "the agent never ran" };
  return { code: r.code, stdout: r.stdout, stderr: r.stderr, scope: got.scope ?? "", ...(got.status !== undefined ? { status: got.status } : {}), ...(got.error ? { error: got.error } : {}) };
}

const lastLine = (s: string): string => s.split("\n").filter((l) => l.trim() !== "").at(-1) ?? "";
const noValue = (text: string, where: string): void => assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the .env value`);

test("L1+L2: the session ends with what Mandu kept, on stderr only, in Home's count and words; the model never got the value (secrets axes, explicit)", { timeout: 150_000 }, async () => {
  seen.length = 0;
  const r = await launch("kept");
  const diag = `stdout:\n${r.stdout}\nstderr:\n${r.stderr}\nagent: ${r.error ?? r.status}`;
  assert.equal(r.code, 0, diag);
  assert.equal(r.status, 200, diag);
  assert.ok(seen.length >= 1, `the request reached the stand-in model: ${diag}`);
  // L2: the oracle.
  noValue(seen.join("\n"), "a request the model got");
  assert.match(seen.join("\n"), /\$MDU:[A-Za-z]+_Read\[[0-9a-f]+\]/, "the model got the key's placeholder");
  noValue(r.stdout, "stdout");
  noValue(r.stderr, "stderr");
  assert.equal(r.stdout.trim(), AGENT_WORD, "stdout holds only the agent's own output");
  assert.doesNotMatch(r.stdout, /mandu:|masked before the AI/);
  // The launch's record, as the dashboard serves it: the posture and whether
  // each event is believed.
  assert.match(r.scope, /^\d+-\d+$/);
  const evRes = await pageFetch(`${dashUrl}/api/events?session=${encodeURIComponent(r.scope)}`);
  assert.equal(evRes.status, 200);
  const evText = await evRes.text();
  noValue(evText, "/api/events");
  const events = (JSON.parse(evText) as { events: { kind: string; claimed?: boolean; secrets?: { posture?: string; gap?: string } }[] }).events;
  const posture = events.find((e) => e.kind === "launch_posture")?.secrets;
  assert.ok(posture, `the launch recorded its posture: ${diag}`);
  // Home's count for the same session: the agent page's tile, served by the same dashboard.
  const page = await pageFetch(`${dashUrl}/api/home/agent?session=${encodeURIComponent(r.scope)}`);
  assert.equal(page.status, 200);
  const text = await page.text();
  noValue(text, "/api/home/agent");
  const vm = JSON.parse(text) as AgentPageVM;
  if (WALLED) {
    // The bind wrap is up (no guard: gated, gap guard-off) and walls the
    // human plane, so the record is believed.
    assert.deepEqual(posture, { posture: "gated", gap: "guard-off" }, `this host can mount the bind wrap: ${diag}`);
    assert.deepEqual(events.filter((e) => e.claimed === true).map((e) => e.kind), [], "a walled launch's reports are believed");
    // L1: on stderr, the session's last line; never on stdout.
    assert.match(lastLine(r.stderr), LINE_RE, diag);
    assert.deepEqual(vm.secrets.counts, { masked: 1, early: 0 }, "the line's count is the page's tile");
  } else {
    // No wall (GitHub's runner): every report is a claim, Home believes
    // none, and the line says Home's count, still stderr's last line.
    assert.equal(posture.posture, "gated", diag);
    assert.ok(UNWALLED_GAPS.includes(posture.gap ?? ""), `the host's gap, not the guard's: ${JSON.stringify(posture)}`);
    assert.ok(events.length >= 2, `the proxy's reports are in the record: ${events.map((e) => e.kind).join(" ")}`);
    assert.deepEqual(events.filter((e) => e.claimed !== true).map((e) => e.kind), [],
      "an unwalled launch's reports are all claims (arbiter-human-plane.md §10.1)");
    assert.deepEqual(vm.secrets.counts, { masked: 0, early: 0 }, "Home counts no claim");
    assert.equal(lastLine(r.stderr), "mandu: no secret came up in this session, so Mandu had nothing to mask", diag);
  }
});

test("L3: opt-out by env and by flag: no line, the same session", { timeout: 250_000 }, async () => {
  for (const [name, args, env] of [["env", [], { MANDU_SESSION_SUMMARY: "0" }], ["flag", ["--no-session-summary"], {}]] as const) {
    const r = await launch(`optout-${name}`, [...args], { ...env });
    const diag = `stderr:\n${r.stderr}`;
    assert.equal(r.code, 0, diag);
    assert.equal(r.status, 200, diag);
    assert.doesNotMatch(r.stderr, /in this session|nothing to mask/, `${name}: no line`);
    assert.equal(r.stdout.trim(), AGENT_WORD);
  }
});

test("L4: the dashboard's socket gone: the session ends cleanly, no line", { timeout: 150_000 }, async () => {
  await channel!.close();
  channel = null;
  const r = await launch("no-dashboard");
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.status, 200, r.stderr);
  assert.doesNotMatch(r.stderr, /in this session|nothing to mask/);
  assert.equal(r.stdout.trim(), AGENT_WORD);
});
