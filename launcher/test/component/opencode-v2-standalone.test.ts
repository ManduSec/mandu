/**
 * opencode-v2-standalone.test — E2E: by default (MANDU_OPENCODE2=0 turns it off),
 * `mandu opencode …` launches OpenCode 2 with `--standalone`, so every model
 * call stays in the wrapped process tree and goes to Mandu's routing, even
 * when the user's background service is running; the shapes that join or
 * drive a server outside the launch are refused before the agent starts
 * (src/opencode-argv.ts, src/agent-versions.ts; supported-agents.md §2.3,
 * part 1 of "What full OpenCode 2 support needs").
 *
 * Two layers:
 *   - stand-ins NAMED `opencode` / `opencode2` that print an OpenCode 2
 *     version (every push): the argv each allowed shape reaches the agent
 *     with, the refused shapes never running it, OpenCode 1's TUI and run
 *     argv untouched and its server and management commands refused too
 *     (opencode1LaunchArgv);
 *   - the REAL OpenCode 2 binary (MANDU_OPENCODE_V2_BIN, else `opencode2` on
 *     PATH; SKIP with the reason otherwise). Keyless and offline: a dummy key,
 *     two scripted local Anthropic upstreams, hermetic XDG dirs. A user
 *     service is started OUTSIDE Mandu, pointed at the "vendor" upstream;
 *     the launch through main() is pointed at the "proxy" upstream (what
 *     Mandu's routing names; the context proxy itself is off in this lane).
 *     Every model request must reach the proxy upstream with the session
 *     header, none the vendor; no service registration is written or
 *     replaced; no process of the launch outlives it; refused shapes never
 *     touch the service.
 *
 * Axes: MANDU_MODE "off" for every launch (as in opencode-v2-refusal.test.ts:
 * the shapes and the routing are decided before the arbiter is asked
 * anything, so the test does not depend on an axis; the confidentiality
 * oracle for OpenCode 2 comes with parts 2-5). The kernel rungs are off
 * (MANDU_NO_KERNEL=1): this file pins the argv and the routing; OpenCode 2
 * under the real guard and landlock-net wrap is
 * tests/sandbox/guard/opencode2-own-server.test.ts (supported-agents.md §2.3.1).
 *
 * PROJECT INVARIANT: the model traffic of a routed agent goes through Mandu's
 * routing, or the launch does not happen.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { reservePort } from "../lib/reserve-port.js";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";
import { runCli } from "../lib/run-cli.js";
import { createServer, type AddressInfo, type Server } from "node:net";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { once } from "node:events";
import { setTimeout as sleep } from "node:timers/promises";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { parseAgentVersion, probeAgentVersion } from "../../src/agent-versions.js";

interface Hit { path: string; session: string | undefined }
interface Upstream { url: string; hits: Hit[]; close: () => void }

/** A scripted Anthropic Messages upstream: records every request, answers one
 *  text turn (streamed or not). */
async function upstream(name: string): Promise<Upstream> {
  const hits: Hit[] = [];
  const srv = createHttpServer((req: IncomingMessage, res: ServerResponse) => {
    let body = "";
    req.on("data", (c: Buffer) => { body += c.toString("utf8"); });
    req.on("end", () => {
      const h = req.headers["x-mandu-session-id"];
      hits.push({ path: req.url ?? "", session: typeof h === "string" ? h : undefined });
      if (!(req.url ?? "").includes("/messages")) { res.writeHead(404); res.end("{}"); return; }
      let stream = false;
      try { stream = (JSON.parse(body) as { stream?: boolean }).stream === true; } catch { /* not JSON */ }
      const text = `hello from ${name}`;
      const message = { id: "msg_1", type: "message", role: "assistant", model: "claude-sonnet-4-5", stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } };
      if (!stream) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ...message, content: [{ type: "text", text }], stop_reason: "end_turn" }));
        return;
      }
      res.writeHead(200, { "content-type": "text/event-stream" });
      const ev = (t: string, d: unknown): void => { res.write(`event: ${t}\ndata: ${JSON.stringify(d)}\n\n`); };
      ev("message_start", { type: "message_start", message: { ...message, content: [], stop_reason: null } });
      ev("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } });
      ev("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text } });
      ev("content_block_stop", { type: "content_block_stop", index: 0 });
      ev("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } });
      ev("message_stop", { type: "message_stop" });
      res.end();
    });
  });
  srv.listen(0, "127.0.0.1");
  await once(srv, "listening");
  return { url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, hits, close: () => { srv.closeAllConnections(); srv.close(); } };
}

interface Rig { dir: string; sock: string; up: Upstream }

async function withRig(fn: (r: Rig) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-opencode-v2-solo-"));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  const up = await upstream("proxy-upstream");
  try { await fn({ dir, sock, up }); } finally {
    srv.close(); up.close(); rmSync(dir, { recursive: true, force: true });
  }
}

const env = (r: Rig, extra: Record<string, string> = {}): Record<string, string | undefined> => ({
  HOME: r.dir, PWD: r.dir, MANDU_ARBITER_SOCK: r.sock, PATH: process.env["PATH"], XDG_RUNTIME_DIR: r.dir,
  MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", MANDU_UPSTREAM: r.up.url,
  MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0",
  ...extra,
});

/** A stand-in named `name` that prints `version` on `--version` and
 *  otherwise records the argv it was started with. */
function standIn(dir: string, name: string, version: string): { bin: string; report: string } {
  const bin = join(dir, name);
  const report = join(dir, `${name}-report.json`);
  writeFileSync(bin, `#!/usr/bin/env node
if (process.argv[2] === "--version") { console.log(${JSON.stringify(version)}); process.exit(0); }
require("fs").writeFileSync(${JSON.stringify(report)}, JSON.stringify({ argv: process.argv.slice(2), configPath: process.env.OPENCODE_CONFIG ?? null }));
`, { mode: 0o755 });
  return { bin, report };
}

async function expectRefused(run: () => Promise<number>, re: RegExp): Promise<void> {
  let err: unknown; let code: number | undefined;
  try { code = await run(); } catch (e) { err = e; }
  assert.ok(err !== undefined, `refused (got exit ${String(code)})`);
  assert.match(String(err), re);
}

test("by default: each allowed OpenCode 2 shape reaches the agent with --standalone, routed; opencode2 too", async () => {
  await withRig(async (r) => {
    for (const [name, args, want] of [
      ["opencode", ["run", "hi"], ["run", "--standalone", "hi"]],
      ["opencode", [], ["--standalone"]],
      ["opencode", [".", "--auto"], ["--standalone", ".", "--auto"]],
      ["opencode", ["mini", "-m", "anthropic/claude-sonnet-4-5"], ["mini", "--standalone", "-m", "anthropic/claude-sonnet-4-5"]],
      ["opencode2", ["run", "-c", "go on"], ["run", "--standalone", "-c", "go on"]],
    ] as const) {
      const sub = mkdtempSync(join(r.dir, "s-"));
      const { bin, report } = standIn(sub, name, "opencode v2.0.23");
      const code = await main(["--no-scope", "--no-mcp", "--", bin, ...args], env(r));
      assert.equal(code, 0, `${name} ${args.join(" ")}`);
      const got = JSON.parse(readFileSync(report, "utf8")) as { argv: string[]; configPath: string | null };
      assert.deepEqual(got.argv, want, `${name} ${args.join(" ")}`);
      assert.ok(got.configPath, "the routing reached the agent");
    }
  });
});

test("by default: the shapes that join or drive a server outside the launch are REFUSED before the agent starts; nothing reaches the upstream", async () => {
  await withRig(async (r) => {
    const { bin, report } = standIn(r.dir, "opencode", "opencode v2.0.23");
    for (const [args, re] of [
      [["run", "--server", "http://127.0.0.1:49374", "hi"], /refusing `opencode run`: --server joins that OpenCode server/],
      [["--server=http://127.0.0.1:49374"], /refusing `opencode`: --server/],
      [["serve", "--port", "4096"], /refusing `opencode serve`: .*other clients/],
      [["serve", "--service"], /refusing `opencode serve`/],
      [["service", "start"], /refusing `opencode service`: .*background service/],
      [["pair"], /refusing `opencode pair`/],
      [["api", "GET", "/api/info"], /refusing `opencode api`/],
      [["acp"], /refusing `opencode acp`/],
      [["auth", "export"], /refusing `opencode auth`: .*credentials/],
      [["session", "export", "ses_1"], /refusing `opencode session`/],
      [["--wizard"], /refusing `opencode`: --wizard/],
      [["run", "--port", "1", "hi"], /--port is not a flag Mandu knows/],
      [["--auto", "serve"], /`serve` comes after other arguments/],
    ] as const) {
      await expectRefused(() => main(["--no-scope", "--no-mcp", "--", bin, ...args], env(r)), re);
      assert.equal(existsSync(report), false, `the agent never ran (${args.join(" ")})`);
    }
    assert.equal(r.up.hits.length, 0, "nothing reached the upstream");
  });
});

test("MANDU_OPENCODE2=0 refuses OpenCode 2 (opencode2 never run); the old opt-in MANDU_EXPERIMENTAL_OPENCODE2 changes nothing; OpenCode 1's argv is untouched (no --standalone: 1.x has no service)", async () => {
  await withRig(async (r) => {
    const v2 = standIn(mkdtempSync(join(r.dir, "v2-")), "opencode", "opencode v2.0.23");
    for (const extra of [{ MANDU_OPENCODE2: "0" }, { MANDU_OPENCODE2: "off", MANDU_EXPERIMENTAL_OPENCODE2: "1" }] as Record<string, string>[]) {
      await expectRefused(
        () => main(["--no-scope", "--no-mcp", "--", v2.bin, "run", "hi"], env(r, extra)),
        /^Error: mandu: refusing to launch OpenCode 2\.0\.23: MANDU_OPENCODE2=0 turns OpenCode 2 off\. Unset MANDU_OPENCODE2 to run it, or use OpenCode 1/,
      );
    }
    assert.equal(existsSync(v2.report), false);
    const own = standIn(mkdtempSync(join(r.dir, "v2b-")), "opencode2", "opencode v2.0.23");
    await expectRefused(() => main(["--no-scope", "--no-mcp", "--", own.bin, "run", "hi"], env(r, { MANDU_OPENCODE2: "0" })), /opencode2: it is OpenCode 2's command, and MANDU_OPENCODE2=0 turns OpenCode 2 off/);
    assert.equal(existsSync(own.report), false, "never run, not even for --version");
    // The old opt-in set to no does not turn OpenCode 2 off: it is not read.
    assert.equal(await main(["--no-scope", "--no-mcp", "--", v2.bin, "run", "hi"], env(r, { MANDU_EXPERIMENTAL_OPENCODE2: "0" })), 0);
    assert.deepEqual((JSON.parse(readFileSync(v2.report, "utf8")) as { argv: string[] }).argv, ["run", "--standalone", "hi"]);
    const v1 = standIn(mkdtempSync(join(r.dir, "v1-")), "opencode", "1.18.13");
    assert.equal(await main(["--no-scope", "--no-mcp", "--", v1.bin, "run", "--port", "4096", "hi"], env(r)), 0);
    assert.deepEqual((JSON.parse(readFileSync(v1.report, "utf8")) as { argv: string[] }).argv, ["run", "--port", "4096", "hi"]);
    // Still refused: a prerelease (0.0.0-*) and a later major.
    for (const [version, re] of [["opencode v0.0.0-beta-19507", /OpenCode 0\.0\.0-beta-19507/], ["opencode v3.0.0", /OpenCode 3\.0\.0/]] as const) {
      const s = standIn(mkdtempSync(join(r.dir, "vx-")), "opencode", version);
      await expectRefused(() => main(["--no-scope", "--no-mcp", "--", s.bin, "run", "hi"], env(r)), re);
      assert.equal(existsSync(s.report), false);
    }
    assert.equal(r.up.hits.length, 0);
  });
});

test("OpenCode 1: the TUI and run launch with their argv unchanged; its server and management commands are REFUSED before the agent starts, as on OpenCode 2", async () => {
  await withRig(async (r) => {
    for (const args of [[], ["./proj", "--prompt", "serve"], ["run", "hi"], ["run", "--port", "4096", "hi"]]) {
      const v1 = standIn(mkdtempSync(join(r.dir, "v1-")), "opencode", "1.18.13");
      assert.equal(await main(["--no-scope", "--no-mcp", "--", v1.bin, ...args], env(r)), 0, args.join(" "));
      const got = JSON.parse(readFileSync(v1.report, "utf8")) as { argv: string[]; configPath: string | null };
      assert.deepEqual(got.argv, args, "unchanged: no --standalone on 1.x");
      assert.ok(got.configPath, "the routing reached the agent");
    }
    const { bin, report } = standIn(mkdtempSync(join(r.dir, "v1r-")), "opencode", "1.18.13");
    for (const [args, re] of [
      [["serve"], /^Error: mandu: refusing `opencode serve`: .*other clients.*Run it without `mandu`/],
      [["serve", "--port", "4096"], /refusing `opencode serve`/],
      [["web"], /refusing `opencode web`/],
      [["attach", "http://127.0.0.1:4096"], /refusing `opencode attach`: .*running OpenCode server/],
      [["run", "--attach", "http://127.0.0.1:4096", "hi"], /refusing `opencode run`: --attach/],
      [["auth", "list"], /^Error: mandu: refusing `opencode auth`: .*credentials.*Run it without `mandu`\.$/],
      [["providers", "login"], /refusing `opencode providers`/],
      [["acp"], /refusing `opencode acp`/],
      [["export", "ses_1"], /refusing `opencode export`/],
      [["db", "select 1"], /refusing `opencode db`/],
      [["--print-logs", "serve"], /refusing `opencode serve`/],
      // The TUI flags that make its built-in server listen.
      [["--port", "4096"], /^Error: mandu: refusing `opencode`: --port makes OpenCode's built-in server listen on a network port/],
      [["--hostname=0.0.0.0"], /refusing `opencode`: --hostname makes/],
      [[".", "--mdns"], /refusing `opencode`: --mdns makes/],
    ] as const) {
      await expectRefused(() => main(["--no-scope", "--no-mcp", "--", bin, ...args], env(r)), re);
      assert.equal(existsSync(report), false, `the agent never ran (${args.join(" ")})`);
    }
    assert.equal(r.up.hits.length, 0, "nothing reached the upstream");
  });
});

/** A stand-in guard bin (MANDU_NET_GUARD_BIN): the launcher's seccomp probe
 *  (`<guard> -- true`) gets `probeCode`; any other run execs what follows
 *  `--`, as the real guard does once it supervises. */
function stubGuard(dir: string, probeCode: number): string {
  const bin = join(dir, `stub-guard-${probeCode}`);
  writeFileSync(bin, `#!/bin/sh
while [ $# -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift
if [ "$*" = "true" ]; then exit ${probeCode}; fi
exec "$@"
`, { mode: 0o755 });
  return bin;
}

test("confidentiality ON (mode secrets): OpenCode 2 is REFUSED, naming what is missing and the fix, unless the guards are in force; OpenCode 1 meets no such rule (axis: secrets)", async () => {
  await withRig(async (r) => {
    const v2 = standIn(mkdtempSync(join(r.dir, "v2-")), "opencode", "opencode v2.0.23");
    const SECRETS = { MANDU_MODE: "secrets" };
    if (process.platform !== "linux") {
      // Off Linux there is no connect guard at all, so every mode-secrets
      // launch of OpenCode 2 is refused for that one reason, whatever the
      // switches say (opencode2-confidentiality.ts, its unit test; the Linux
      // reasons below).
      const offLinux = /refusing OpenCode 2 in mode secrets: .*connect guard .* is Linux only \(fix: on this system run OpenCode 2 with `--mode off`, or use OpenCode 1\)/;
      await expectRefused(() => main(["--no-scope", "--no-mcp", "--", v2.bin, "run", "hi"], env(r, SECRETS)), offLinux);
      assert.equal(existsSync(v2.report), false, "the agent never ran");
      const v1 = standIn(mkdtempSync(join(r.dir, "v1-")), "opencode", "1.18.13");
      let err: unknown = null;
      try { await main(["--no-scope", "--no-mcp", "--", v1.bin, "run", "hi"], env(r, SECRETS)); } catch (e) { err = e; }
      assert.doesNotMatch(String(err), /refusing OpenCode 2/);
      assert.equal(r.up.hits.length, 0);
      return;
    }
    // The kernel layer off (the rig's MANDU_NO_KERNEL=1): no connect guard.
    await expectRefused(
      () => main(["--no-scope", "--no-mcp", "--", v2.bin, "run", "hi"], env(r, SECRETS)),
      /refusing OpenCode 2 in mode secrets: .*the kernel-layer connect guard is turned off .*\(fix: launch without that switch\)/,
    );
    await expectRefused(
      () => main(["--no-scope", "--no-mcp", "--mode", "secrets", "--no-net-guard", "--", v2.bin], env(r, { MANDU_NO_KERNEL: "0" })),
      /refusing OpenCode 2 in mode secrets: .*connect guard is turned off/,
    );
    // The guard on, but this kernel gives it no seccomp user notification
    // (the stand-in guard's probe exits 71, as mandu-net-guard does there).
    const kernelOn = { ...SECRETS, MANDU_NO_KERNEL: "0" };
    await expectRefused(
      () => main(["--no-scope", "--no-mcp", "--", v2.bin, "run", "hi"], env(r, { ...kernelOn, MANDU_NET_GUARD_BIN: stubGuard(r.dir, 71) })),
      /refusing OpenCode 2 in mode secrets: .*no seccomp user notification/,
    );
    // The guard can run, but the write-protect guard is off.
    await expectRefused(
      () => main(["--no-scope", "--no-mcp", "--", v2.bin, "run", "hi"], env(r, { ...kernelOn, MANDU_NET_GUARD_BIN: stubGuard(r.dir, 0), MANDU_WRITE_PROTECT: "0" })),
      /refusing OpenCode 2 in mode secrets: .*MANDU_WRITE_PROTECT=0 turns off the write-protect guard.*\(fix: unset MANDU_WRITE_PROTECT\).*`--mode off`/,
    );
    // Several at once: each named.
    await expectRefused(
      () => main(["--no-scope", "--no-mcp", "--", v2.bin, "run", "hi"], env(r, { ...SECRETS, MANDU_WRITE_PROTECT: "0" })),
      /lacks some: .*connect guard is turned off.*; MANDU_WRITE_PROTECT=0/,
    );
    assert.equal(existsSync(v2.report), false, "the agent never ran");
    // Every condition the launch can meet before anything starts is met: the
    // early check passes (whatever stops this rig's launch later, its
    // unanswering arbiter, is not this refusal's first form).
    let err: unknown = null;
    try { await main(["--no-scope", "--no-mcp", "--", v2.bin, "run", "hi"], env(r, { ...kernelOn, MANDU_NET_GUARD_BIN: stubGuard(r.dir, 0) })); } catch (e) { err = e; }
    assert.doesNotMatch(String(err), /refusing OpenCode 2 in mode secrets: .*(turned off|not built|seccomp|could not find|MANDU_WRITE_PROTECT)/);
    // OpenCode 1 meets no such rule: its launch gets past this point and runs.
    const v1 = standIn(mkdtempSync(join(r.dir, "v1-")), "opencode", "1.18.13");
    err = null;
    try { await main(["--no-scope", "--no-mcp", "--", v1.bin, "run", "hi"], env(r, SECRETS)); } catch (e) { err = e; }
    assert.doesNotMatch(String(err), /refusing OpenCode 2/);
    assert.equal(r.up.hits.length, 0);
  });
});

// ─── The real OpenCode 2 binary ──────────────────────────────────────────────

/** The OpenCode 2 binary: MANDU_OPENCODE_V2_BIN, else `opencode2` on PATH. */
function realV2(): { bin: string } | { skip: string } {
  const fromEnv = process.env["MANDU_OPENCODE_V2_BIN"];
  const candidates = fromEnv ? [fromEnv] : (process.env["PATH"] ?? "").split(delimiter).filter(Boolean).map((d) => join(d, "opencode2"));
  const bin = candidates.find((c) => existsSync(c));
  if (bin === undefined) {
    return { skip: "no OpenCode 2 binary: set MANDU_OPENCODE_V2_BIN (npm i --prefix <dir> @opencode/cli; <dir>/node_modules/.bin/opencode) or put `opencode2` on PATH" };
  }
  const v = parseAgentVersion(probeAgentVersion(bin));
  if (v === null || v.parts[0] !== 2) return { skip: `${bin} is not OpenCode 2 (its --version: ${v?.raw ?? "unreadable"})` };
  return { bin };
}

/** Linux: the pids whose environment carries `marker` (a launch's children
 *  inherit it). Null where /proc cannot say. */
function pidsWithMarker(marker: string): number[] | null {
  if (process.platform !== "linux") return null;
  const out: number[] = [];
  for (const d of readdirSync("/proc")) {
    if (!/^\d+$/.test(d) || Number(d) === process.pid) continue;
    try { if (readFileSync(`/proc/${d}/environ`, "latin1").includes(marker)) out.push(Number(d)); } catch { /* gone, or not ours */ }
  }
  return out;
}

test("REAL OpenCode 2: the user's running service is NOT joined; every model request reaches Mandu's routing with the session header; nothing outlives the launch", async (t) => {
  const found = realV2();
  if ("skip" in found) { t.skip(found.skip); return; }
  await withRig(async (r) => {
    const vendor = await upstream("vendor");
    const home = join(r.dir, "user");
    const proj = join(r.dir, "proj");
    mkdirSync(join(home, ".config", "opencode"), { recursive: true });
    mkdirSync(proj, { recursive: true });
    // The user's own OpenCode setting: the vendor endpoint (a stand-in for
    // api.anthropic.com), in OpenCode 2's own spelling.
    writeFileSync(join(home, ".config", "opencode", "opencode.json"),
      JSON.stringify({ providers: { anthropic: { settings: { baseURL: `${vendor.url}/v1` } } } }));
    const xdg: Record<string, string> = {
      XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local", "share"),
      XDG_STATE_HOME: join(home, ".local", "state"), XDG_CACHE_HOME: join(home, ".cache"),
      ANTHROPIC_API_KEY: "sk-ant-test-dummy", OPENCODE_DISABLE_MODELS_FETCH: "1", OPENCODE_DISABLE_AUTOUPDATE: "1",
    };
    const registration = join(xdg["XDG_STATE_HOME"]!, "opencode", "service.json");
    // `opencode` itself, outside Mandu (the user's shell). Asynchronous: the
    // upstreams answer from this process's event loop.
    const oc = (args: string[]): Promise<{ status: number | null; stderr: string }> =>
      new Promise((done) => {
        const child = spawn(found.bin, args, {
          cwd: proj, env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: home, ...xdg },
          stdio: ["ignore", "pipe", "pipe"], timeout: 90_000,
        });
        let stderr = "";
        child.stdout.resume();
        child.stderr.on("data", (c: Buffer) => { stderr += c.toString("utf8"); });
        child.on("error", (e) => done({ status: null, stderr: String(e) }));
        child.on("close", (status) => done({ status, stderr }));
      });
    // Under the name `opencode`, as `npm i -g @opencode/cli` installs it.
    const link = join(r.dir, "opencode");
    writeFileSync(link, `#!/bin/sh\nexec ${JSON.stringify(found.bin)} "$@"\n`, { mode: 0o755 });
    const marker = `MANDU_TEST_OC2_LAUNCH=${randomUUID()}`;
    const [mk, mv] = marker.split("=") as [string, string];
    // The routing names the out-of-band proxy's port (MANDU_NO_CONTEXT_PROXY=1
    // + MANDU_PROXY_PORT): the "proxy" upstream stands in for it.
    const launchEnv = env(r, { ...xdg, HOME: home, PWD: proj, [mk]: mv, MANDU_PROXY_PORT: new URL(r.up.url).port });
    // The real CLI entry in a child (run.ts → main()) with stdin closed:
    // `opencode run` reads a piped stdin to its end before it starts, and the
    // test runner's stdin never ends.
    const launch = async (args: string[]): Promise<number> => {
      const res = await runCli(["--no-scope", "--no-mcp", "--", link, ...args], launchEnv);
      if (res.code !== 0) console.error(res.stderr);
      return res.code;
    };
    // A refused shape: main() in this process throws before anything starts.
    const refusedLaunch = (args: string[]): Promise<number> => main(["--no-scope", "--no-mcp", "--", link, ...args], launchEnv);
    const model = ["-m", "anthropic/claude-sonnet-4-5", "--format", "json"];
    const messages = (u: Upstream) => u.hits.filter((h) => h.path.startsWith("/v1/messages"));
    const cwd = process.cwd();
    process.chdir(proj);
    try {
      // 1. No service running: the launch starts none (a private server only).
      assert.equal(await launch(["run", ...model, "say hi"]), 0);
      assert.ok(messages(r.up).length > 0, "the turn reached Mandu's routing");
      assert.ok(messages(r.up).every((h) => h.session !== undefined && h.session !== ""), "every request carries the session header");
      assert.equal(existsSync(registration), false, "no background service was registered");
      r.up.hits.length = 0;

      // 2. The user's own service, started without Mandu, on a reserved port.
      const port = await reservePort();
      assert.equal((await oc(["service", "set", "port", String(port)])).status, 0);
      const started = await oc(["service", "start"]);
      assert.equal(started.status, 0, started.stderr);
      const before = readFileSync(registration, "utf8");
      assert.match(before, new RegExp(`127\\.0\\.0\\.1:${port}`));
      // Control: outside Mandu a plain run joins it, and its turn goes to the vendor.
      const control = await oc(["run", ...model, "say hi"]);
      assert.equal(control.status, 0, control.stderr);
      assert.ok(messages(vendor).length > 0, "control: the service is live and joined");
      vendor.hits.length = 0;

      // 3. Through Mandu (OpenCode 2 is on by default), the same run with the service up.
      assert.equal(await launch(["run", ...model, "say hi"]), 0);
      assert.ok(messages(r.up).length > 0, "the turn reached Mandu's routing");
      const sessions = new Set(messages(r.up).map((h) => h.session));
      assert.equal(sessions.size, 1, "one session");
      assert.ok([...sessions][0], "every request carries the session header");
      assert.equal(vendor.hits.length, 0, "nothing reached the service's endpoint: the service was not joined");
      assert.equal(readFileSync(registration, "utf8"), before, "the user's service registration is untouched");
      assert.equal((await oc(["service", "status"])).status, 0, "the user's service still runs");

      // 4. The refused shapes never reach the binary: the service is not
      // stopped, restarted or re-pointed, and nothing reaches either upstream.
      r.up.hits.length = 0;
      for (const args of [["service", "stop"], ["service", "restart"], ["serve", "--service"], ["run", "--server", `http://127.0.0.1:${port}`, "hi"], ["api", "GET", "/api/info"]]) {
        await expectRefused(() => refusedLaunch(args), /^Error: mandu: refusing `opencode/);
      }
      assert.equal(readFileSync(registration, "utf8"), before);
      assert.equal(r.up.hits.length + vendor.hits.length, 0);

      // 5. Nothing the launches started outlives them (the private server is
      // the client's child and stops with it).
      const pids = pidsWithMarker(marker);
      if (pids !== null) {
        let left = pids;
        for (let i = 0; i < 50 && left.length > 0; i++) { await sleep(100); left = pidsWithMarker(marker) ?? []; }
        assert.deepEqual(left, [], "no process of the launches is left");
      }
    } finally {
      process.chdir(cwd);
      await oc(["service", "stop"]);
      vendor.close();
    }
  });
});
