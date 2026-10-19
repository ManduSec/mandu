/**
 * opencode-v2-refusal.test — E2E: `mandu opencode …` through main() REFUSES
 * an OpenCode it cannot route: one whose version cannot be read, OpenCode 2's
 * `0.0.0-*` prereleases, and OpenCode 2 (npm `@opencode/cli`) when the user
 * turned it off with MANDU_OPENCODE2=0; OpenCode 1 still launches
 * (src/agent-versions.ts opencodeLaunchRefusal; supported-agents.md §2.3).
 * OpenCode 2 launches by default with its argv rewritten
 * (opencode-v2-standalone.test.ts).
 *
 * WHY THE VERSION DECIDES: OpenCode 2's `opencode` / `opencode run` hand the
 * session to a background service (`opencode service`, found through
 * `$XDG_STATE_HOME/opencode/service.json`) that runs the model calls and the
 * tools with the configuration IT was started with. A service started outside
 * Mandu never sees the per-run routing (OPENCODE_CONFIG,
 * OPENCODE_CONFIG_CONTENT), so the turn leaves for the service's own endpoint,
 * around the model proxy: tool results unmasked, the confidentiality
 * invariant broken. So a 2.x launch must get `--standalone`, and only the
 * probed major tells Mandu which rule applies. The last test pins the service
 * fact on the real binary.
 *
 * Two layers:
 *   - stand-ins NAMED `opencode` / `opencode2` (every push): the refused
 *     launches never run the agent and the counting upstream sees nothing;
 *     OpenCode 1 launches routed;
 *   - the REAL OpenCode 2 binary (MANDU_OPENCODE_V2_BIN, else `opencode2` on
 *     PATH): the MANDU_OPENCODE2=0 refusal against its own `--version`, and
 *     the service bypass `--standalone` exists for. Without the binary both
 *     SKIP with the reason, never a green.
 *
 * Axes: stated per launch (MANDU_MODE "off" for the stand-ins, as in
 * agent-model-route.test.ts: the refusal is axis-independent, it happens
 * before the arbiter is asked anything). The bypass pin runs no Mandu at all.
 *
 * PROJECT INVARIANT: the model traffic of a routed agent goes through the
 * context proxy, or the launch does not happen.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { createServer, type Server } from "node:net";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { parseAgentVersion, probeAgentVersion } from "../../src/agent-versions.js";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";
import { reservePort } from "../lib/reserve-port.js";

interface Hit { path: string; session: string | undefined }
interface Upstream { url: string; hits: Hit[]; close: () => void }

/** A scripted Anthropic Messages upstream that records every request and
 *  answers one text turn (streamed or not, as asked). */
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
  const dir = mkdtempSync(join(tmpdir(), "mandu-opencode-v2-"));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  const up = await upstream("proxy-upstream");
  try { await fn({ dir, sock, up }); } finally {
    srv.close(); up.close(); rmSync(dir, { recursive: true, force: true });
  }
}

const env = (r: Rig) => ({
  HOME: r.dir, PWD: r.dir, MANDU_ARBITER_SOCK: r.sock, PATH: process.env["PATH"], XDG_RUNTIME_DIR: r.dir,
  MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", MANDU_UPSTREAM: r.up.url,
  MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0",
});

/** A stand-in named `name` that prints `version` (or fails) on `--version`
 *  and otherwise records that it ran, with the routing it was handed. */
function standIn(dir: string, name: string, version: string | null): { bin: string; report: string } {
  const bin = join(dir, name);
  const report = join(dir, `${name}-report.json`);
  const onVersion = version === null ? `process.exit(2);` : `console.log(${JSON.stringify(version)}); process.exit(0);`;
  writeFileSync(bin, `#!/usr/bin/env node
if (process.argv[2] === "--version") { ${onVersion} }
require("fs").writeFileSync(${JSON.stringify(report)}, JSON.stringify({ argv: process.argv.slice(2),
  configPath: process.env.OPENCODE_CONFIG ?? null, content: process.env.OPENCODE_CONFIG_CONTENT ?? null }));
`, { mode: 0o755 });
  return { bin, report };
}

async function expectRefused(run: () => Promise<number>, re: RegExp): Promise<void> {
  let err: unknown; let code: number | undefined;
  try { code = await run(); } catch (e) { err = e; }
  assert.ok(err !== undefined, `refused (got exit ${String(code)})`);
  assert.match(String(err), re);
}

test("a prerelease, another major and an unreadable version are REFUSED before anything starts; so is OpenCode 2 under MANDU_OPENCODE2=0; nothing reaches the upstream", async () => {
  await withRig(async (r) => {
    for (const [version, extra, re] of [
      ["opencode v0.0.0-beta-19507", {}, /refusing to launch OpenCode 0\.0\.0-beta-19507\. Mandu supports OpenCode 1 .* and OpenCode 2/],
      ["opencode v3.0.0", {}, /refusing to launch OpenCode 3\.0\.0/],
      [null, {}, /could not read its version .*cannot tell OpenCode 1 from OpenCode 2/],
      ["opencode v2.0.22", { MANDU_OPENCODE2: "0" }, /refusing to launch OpenCode 2\.0\.22: MANDU_OPENCODE2=0 turns OpenCode 2 off\. Unset MANDU_OPENCODE2 to run it/],
    ] as const) {
      const sub = mkdtempSync(join(r.dir, "v-"));
      const { bin, report } = standIn(sub, "opencode", version);
      // Inferred from the basename and with --target: both refused.
      await expectRefused(() => main(["--no-scope", "--", bin, "run", "hi"], { ...env(r), ...extra }), re);
      await expectRefused(() => main(["--target", "opencode", "--no-scope", "--", bin], { ...env(r), ...extra }), re);
      assert.equal(existsSync(report), false, `the stand-in never ran (${String(version)})`);
    }
    assert.equal(r.up.hits.length, 0, "nothing reached the upstream");
  });
});

test("`opencode2` (OpenCode 2's own command) is inferred as opencode: it launches as OpenCode 2 (--standalone), and is REFUSED by name under MANDU_OPENCODE2=0", async () => {
  await withRig(async (r) => {
    const off = standIn(mkdtempSync(join(r.dir, "off-")), "opencode2", "opencode v2.0.22");
    await expectRefused(() => main(["--no-scope", "--", off.bin, "run", "hi"], { ...env(r), MANDU_OPENCODE2: "0" }), /refusing to launch .*opencode2: it is OpenCode 2's command, and MANDU_OPENCODE2=0 turns OpenCode 2 off/);
    assert.equal(existsSync(off.report), false, "the stand-in never ran, not even for --version");
    assert.equal(r.up.hits.length, 0);
    const on = standIn(mkdtempSync(join(r.dir, "on-")), "opencode2", "opencode v2.0.22");
    assert.equal(await main(["--no-scope", "--no-mcp", "--", on.bin, "run", "hi"], env(r)), 0);
    const got = JSON.parse(readFileSync(on.report, "utf8")) as { argv: string[]; configPath: string | null };
    assert.deepEqual(got.argv, ["run", "--standalone", "hi"]);
    assert.ok(got.configPath, "OPENCODE_CONFIG reached the agent");
  });
});

test("OpenCode 1 still launches, routed (the refusal costs a supported OpenCode nothing)", async () => {
  await withRig(async (r) => {
    const { bin, report } = standIn(r.dir, "opencode", "1.18.13");
    const code = await main(["--no-scope", "--", bin, "run", "hi"], env(r));
    assert.equal(code, 0);
    const got = JSON.parse(readFileSync(report, "utf8")) as { argv: string[]; configPath: string | null; content: string | null };
    assert.deepEqual(got.argv, ["run", "hi"]);
    assert.ok(got.configPath, "OPENCODE_CONFIG reached the agent");
    const content = JSON.parse(got.content ?? "{}") as { enabled_providers?: string[]; provider?: { anthropic?: { options?: { baseURL?: string } } } };
    assert.deepEqual(content.enabled_providers, ["anthropic"]);
    assert.match(content.provider?.anthropic?.options?.baseURL ?? "", /^http:\/\/127\.0\.0\.1:\d+\/v1$/);
  });
});

// ─── The real OpenCode 2 binary ──────────────────────────────────────────────

/** The OpenCode 2 binary to test against: MANDU_OPENCODE_V2_BIN, else
 *  `opencode2` on PATH (only OpenCode 2 installs that name). Null with the
 *  reason when there is none, or it is not OpenCode 2. */
function realV2(): { bin: string } | { skip: string } {
  const fromEnv = process.env["MANDU_OPENCODE_V2_BIN"];
  const candidates = fromEnv ? [fromEnv] : (process.env["PATH"] ?? "").split(delimiter).filter(Boolean).map((d) => join(d, "opencode2"));
  const bin = candidates.find((c) => existsSync(c));
  if (bin === undefined) {
    return { skip: "no OpenCode 2 binary: set MANDU_OPENCODE_V2_BIN (npm i --prefix <dir> @opencode/cli; <dir>/node_modules/.bin/opencode) or put `opencode2` on PATH" };
  }
  const v = parseAgentVersion(probeAgentVersion(bin));
  if (v === null || v.parts[0] < 2) return { skip: `${bin} is not OpenCode 2 (its --version: ${v?.raw ?? "unreadable"})` };
  return { bin };
}

test("REAL OpenCode 2 under MANDU_OPENCODE2=0: `mandu` refuses it from its own --version; the upstream sees nothing", async (t) => {
  const found = realV2();
  if ("skip" in found) { t.skip(found.skip); return; }
  await withRig(async (r) => {
    // Under the name `opencode`, as `npm i -g @opencode/cli` installs it.
    const link = join(r.dir, "opencode");
    writeFileSync(link, `#!/bin/sh\nexec ${JSON.stringify(found.bin)} "$@"\n`, { mode: 0o755 });
    await expectRefused(() => main(["--no-scope", "--", link, "run", "hi"], { ...env(r), MANDU_OPENCODE2: "0" }), /refusing to launch OpenCode 2\.\d+\.\d+: MANDU_OPENCODE2=0/);
    assert.equal(r.up.hits.length, 0);
  });
});

test("REAL OpenCode 2 (the reason for --standalone): a background service started outside Mandu ignores the per-run routing; the turn goes around the proxy", async (t) => {
  const found = realV2();
  if ("skip" in found) { t.skip(found.skip); return; }
  const dir = mkdtempSync(join(tmpdir(), "mandu-opencode-v2-svc-"));
  const proxy = await upstream("proxy");
  const vendor = await upstream("vendor");
  const home = join(dir, "home");
  const proj = join(dir, "proj");
  mkdirSync(join(home, ".config", "opencode"), { recursive: true });
  mkdirSync(proj, { recursive: true });
  // The user's own OpenCode setting: the vendor endpoint (a stand-in for
  // api.anthropic.com), in OpenCode 2's own spelling.
  writeFileSync(join(home, ".config", "opencode", "opencode.json"),
    JSON.stringify({ providers: { anthropic: { settings: { baseURL: `${vendor.url}/v1` } } } }));
  // Mandu's per-run routing, exactly the shape the launcher hands OpenCode 1
  // (services/agent-config.ts buildOpencodeWrapDoc / opencodeRoutingContent).
  const routing = { enabled_providers: ["anthropic"], provider: { anthropic: { options: { baseURL: `${proxy.url}/v1`, headers: { "x-mandu-session-id": "sess-v2-probe" } } } } };
  const mandu = join(dir, "mandu-opencode.json");
  writeFileSync(mandu, JSON.stringify(routing));
  const base: Record<string, string> = {
    PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: home,
    XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local", "share"),
    XDG_STATE_HOME: join(home, ".local", "state"), XDG_CACHE_HOME: join(home, ".cache"),
    ANTHROPIC_API_KEY: "sk-ant-test-dummy", OPENCODE_DISABLE_MODELS_FETCH: "1", OPENCODE_DISABLE_AUTOUPDATE: "1",
  };
  // Asynchronous: the two upstreams answer from this process's event loop.
  const oc = (args: string[], extra: Record<string, string> = {}): Promise<{ status: number | null; stderr: string }> =>
    new Promise((done) => {
      const child = spawn(found.bin, args, { cwd: proj, env: { ...base, ...extra }, stdio: ["ignore", "pipe", "pipe"], timeout: 90_000 });
      let stderr = "";
      child.stdout.resume();
      child.stderr.on("data", (c: Buffer) => { stderr += c.toString("utf8"); });
      child.on("error", (e) => done({ status: null, stderr: String(e) }));
      child.on("close", (status) => done({ status, stderr }));
    });
  try {
    // Control: a private (standalone) server takes the per-run routing. The
    // V1-shaped keys are normalized by OpenCode 2 and reach the proxy.
    const solo = await oc(["run", "--standalone", "-m", "anthropic/claude-sonnet-4-5", "--format", "json", "say hi"],
      { OPENCODE_CONFIG: mandu, OPENCODE_CONFIG_CONTENT: JSON.stringify(routing) });
    assert.equal(solo.status, 0, solo.stderr);
    assert.ok(proxy.hits.some((h) => h.path.startsWith("/v1/messages") && h.session === "sess-v2-probe"), "standalone: the turn reached the proxy");
    assert.equal(vendor.hits.length, 0, "standalone: nothing went around it");
    proxy.hits.length = 0;

    // The user's own service, started without Mandu, on a reserved port (the
    // default, 49374, is fixed: a service any other OpenCode 2 on the host
    // left running would hold it).
    assert.equal((await oc(["service", "set", "port", String(await reservePort())])).status, 0);
    const started = await oc(["service", "start"]);
    assert.equal(started.status, 0, started.stderr);
    // A run carrying Mandu's routing, in the default (service) mode.
    const run = await oc(["run", "-m", "anthropic/claude-sonnet-4-5", "--format", "json", "say hi"],
      { OPENCODE_CONFIG: mandu, OPENCODE_CONFIG_CONTENT: JSON.stringify(routing) });
    assert.equal(run.status, 0, run.stderr);
    assert.equal(proxy.hits.length, 0, "the per-run routing never reached the service");
    assert.ok(vendor.hits.some((h) => h.path.startsWith("/v1/messages") && h.session === undefined),
      "the turn went to the service's own endpoint, without the session header: around the proxy");
  } finally {
    await oc(["service", "stop"]);
    proxy.close(); vendor.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
