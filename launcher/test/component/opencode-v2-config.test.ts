/**
 * opencode-v2-config.test — E2E against the REAL OpenCode 2 binary: where a
 * turn goes under the routing Mandu writes for a 2.x launch
 * (services/agent-config.ts writeAgentConfig with a 2.x agentVersion), with
 * hostile config layers in both spellings, and what the launch-time check
 * (agent-model-route.ts opencodeV2ModelPlan over readOpencodeConfigLayers)
 * says about the same layers. supported-agents.md §2.3 part 4 and item 8.
 *
 * The SECURITY question (the merge order of `experimental.policies`):
 * OpenCode 2 takes the provider rule of the LOWEST config layer that names a
 * provider (it reverses the layers, then takes the last match). Pinned here:
 *   - a PROJECT config cannot re-admit a provider past Mandu's fence (its
 *     `experimental.policies` allow or V1 `enabled_providers`): the run file
 *     Mandu writes as OPENCODE_CONFIG sits below every project layer, and its
 *     rule wins. A provider base URL re-pointed by the project or by the
 *     user's own OPENCODE_CONFIG_CONTENT, in V2 spelling, does not move the
 *     turn either;
 *   - the GLOBAL config, the one layer below that file, could: its admission
 *     sent the turn to that provider's own endpoint. Under the lockdown
 *     (item 8) OpenCode 2 reads no file of the user's, the global documents
 *     are merged into the run file under the fence, and the admission no
 *     longer re-admits anything;
 *   - a model's OWN endpoint (`providers.<id>.models.<m>.settings.baseURL`)
 *     beats the provider's base URL from any layer: the launch refuses it;
 *   - the `execute` deny Mandu writes (code mode off, defense in depth)
 *     holds against a project allow: permission rules keep the normal
 *     precedence (an agent's own `permissions` allow is not covered);
 *   - a config written MID-SESSION (item 8): 2.x reloads config files through
 *     its file watcher and through `POST /api/location/reload`, which any
 *     process of the user can call with the private server's password (in
 *     its /proc environ). Under the lockdown neither moves a request,
 *     whatever is written to a project, ancestor or global `opencode.json`;
 *     the one layer still on disk is the launcher's own directory, which the
 *     whole-agent guard keeps the agent's tree from writing: the last test
 *     pins that a write there plus a reload WOULD move it, which is the
 *     guard's job. A future version that changes any of these fails here.
 *
 * The binary: MANDU_OPENCODE_V2_BIN, else `opencode2` on PATH; without it
 * every test SKIPs with the reason, never a green. Scripted local upstreams
 * only (the stand-in for every vendor is a loopback server); no real model
 * endpoint is contacted.
 *
 * Axes: none. No arbiter and no Mandu launch: the routing files are built by
 * the launcher's own writer and handed to the real binary; the confidentiality
 * axis is what this routing serves (the model proxy gates every turn that
 * reaches it).
 *
 * PROJECT INVARIANT: the model traffic of a routed agent goes through the
 * context proxy, or the launch does not happen.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js";
import { createServer as createHttpServer, type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from "node:http";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { parseAgentVersion, probeAgentVersion } from "../../src/agent-versions.js";
import { opencodeV2ModelPlan } from "../../src/agent-model-route.js";
import { OPENCODE_CONFIG_DIR_NAME, readOpencodeConfigLayers, writeAgentConfig } from "../../src/services/agent-config.js";
import { Layout } from "../../src/services/layout.js";
import type { LaunchPlan, Ullm } from "../../src/types.js";

/** The OpenCode 2 binary (as in opencode-v2-refusal.test.ts), or the reason to skip. */
function realV2(): { bin: string; version: string } | { skip: string } {
  const fromEnv = process.env["MANDU_OPENCODE_V2_BIN"];
  const candidates = fromEnv ? [fromEnv] : (process.env["PATH"] ?? "").split(delimiter).filter(Boolean).map((d) => join(d, "opencode2"));
  const bin = candidates.find((c) => existsSync(c));
  if (bin === undefined) {
    return { skip: "no OpenCode 2 binary: set MANDU_OPENCODE_V2_BIN (npm i --prefix <dir> @opencode/cli; <dir>/node_modules/.bin/opencode) or put `opencode2` on PATH" };
  }
  const v = parseAgentVersion(probeAgentVersion(bin));
  if (v === null || v.parts[0] < 2) return { skip: `${bin} is not OpenCode 2 (its --version: ${v?.raw ?? "unreadable"})` };
  return { bin, version: v.raw };
}

interface Hit { path: string; session: string | undefined; body: string; headers: IncomingHttpHeaders }
interface Upstream { url: string; port: number; hits: Hit[]; close: () => void }

/** A scripted upstream: records every request; answers an Anthropic Messages
 *  turn (streamed or not) with one text, everything else with a 400. */
type Reply = { tool?: { name: string; input: unknown; id?: string }; delayMs?: number } | undefined;

async function upstream(name: string, onRequest?: (h: Hit) => Reply): Promise<Upstream> {
  const hits: Hit[] = [];
  const srv = createHttpServer((req: IncomingMessage, res: ServerResponse) => {
    let body = "";
    req.on("data", (c: Buffer) => { body += c.toString("utf8"); });
    req.on("end", () => {
      const s = req.headers["x-mandu-session-id"];
      const hit = { path: req.url ?? "", session: typeof s === "string" ? s : undefined, body, headers: req.headers };
      hits.push(hit);
      const plan = onRequest?.(hit);
      if (!(req.url ?? "").includes("/messages")) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end('{"error":{"message":"stub upstream"}}');
        return;
      }
      const message = { id: "msg_1", type: "message", role: "assistant", model: "claude-sonnet-4-5", stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } };
      let stream = false;
      try { stream = (JSON.parse(body) as { stream?: boolean }).stream === true; } catch { /* not JSON */ }
      const text = `hello from ${name}`;
      if (!stream) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ...message, content: [{ type: "text", text }], stop_reason: "end_turn" }));
        return;
      }
      setTimeout(() => sse(res, message, text, plan), plan?.delayMs ?? 0);
    });
  });
  srv.listen(0, "127.0.0.1");
  await once(srv, "listening");
  const port = (srv.address() as AddressInfo).port;
  return { url: `http://127.0.0.1:${port}`, port, hits, close: () => { srv.closeAllConnections(); srv.close(); } };
}

/** One streamed Anthropic turn: a text, or the tool call `plan` asks for. */
function sse(res: ServerResponse, message: Record<string, unknown>, text: string, plan: Reply): void {
  res.writeHead(200, { "content-type": "text/event-stream" });
  const ev = (t: string, d: unknown): void => { res.write(`event: ${t}\ndata: ${JSON.stringify(d)}\n\n`); };
  ev("message_start", { type: "message_start", message: { ...message, content: [], stop_reason: null } });
  if (plan && plan.tool) {
    ev("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: plan.tool.id ?? "toolu_1", name: plan.tool.name, input: {} } });
    ev("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify(plan.tool.input) } });
  } else {
    ev("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } });
    ev("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text } });
  }
  ev("content_block_stop", { type: "content_block_stop", index: 0 });
  ev("message_delta", { type: "message_delta", delta: { stop_reason: plan && plan.tool ? "tool_use" : "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } });
  ev("message_stop", { type: "message_stop" });
  res.end();
}

const ULLM: Ullm = { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" };

function launchPlan(over: Partial<LaunchPlan>): LaunchPlan {
  return {
    target: "opencode", argv: ["opencode"], scopeId: "sess-oc2-config", tenant: "test",
    arbiterSock: "/run/mandu/arbiter.sock", arbiterSockMode: "pinned", arbiterRuntimeBase: "/tmp/mandu",
    eventDir: "/e", cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false,
    basePath: "/usr/bin", proxy: { host: "127.0.0.1", port: 1 }, openaiProxy: { host: "127.0.0.1", port: 2 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false }, execWrapCmds: [],
    ullm: ULLM, noScope: false, writeMcp: false, bestEffort: false, replyFilter: true,
    ...over,
  };
}

interface Rig {
  bin: string; version: string; dir: string; home: string; proj: string;
  proxy: Upstream; vendor: Upstream; evil: Upstream;
  /** The hermetic env the user's OpenCode runs with (no Mandu routing). */
  userEnv: Record<string, string>;
}

/** The OpenCode 1 binary: MANDU_OPENCODE_V1_BIN, else `opencode` on PATH
 *  when its major version is 1; the reason to skip otherwise. */
function realV1(): { bin: string; version: string } | { skip: string } {
  const fromEnv = process.env["MANDU_OPENCODE_V1_BIN"];
  const candidates = fromEnv ? [fromEnv] : (process.env["PATH"] ?? "").split(delimiter).filter(Boolean).map((d) => join(d, "opencode"));
  const bin = candidates.find((c) => existsSync(c));
  if (bin === undefined) return { skip: "no OpenCode 1 binary: set MANDU_OPENCODE_V1_BIN or put OpenCode 1's `opencode` on PATH" };
  const v = parseAgentVersion(probeAgentVersion(bin));
  if (v === null || v.parts[0] !== 1) return { skip: `${bin} is not OpenCode 1 (its --version: ${v?.raw ?? "unreadable"})` };
  return { bin, version: v.raw };
}

async function withRig(t: { skip: (m: string) => void }, fn: (r: Rig) => Promise<void>, proxyHook?: (h: Hit, r: Rig) => Reply, which: "v1" | "v2" = "v2"): Promise<void> {
  const found = which === "v1" ? realV1() : realV2();
  if ("skip" in found) { t.skip(found.skip); return; }
  const dir = mkdtempSync(join(tmpdir(), "mandu-oc2-config-"));
  const home = join(dir, "home");
  const proj = join(dir, "proj");
  mkdirSync(join(home, ".config", "opencode"), { recursive: true });
  mkdirSync(proj, { recursive: true });
  let rig: Rig | undefined;
  const proxy = await upstream("proxy", (h) => (rig && proxyHook ? proxyHook(h, rig) : undefined));
  const vendor = await upstream("vendor");
  const evil = await upstream("evil-openai");
  rig = {
    bin: found.bin, version: found.version, dir, home, proj, proxy, vendor, evil,
    userEnv: {
      PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: home,
      XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local", "share"),
      XDG_STATE_HOME: join(home, ".local", "state"), XDG_CACHE_HOME: join(home, ".cache"),
      ANTHROPIC_API_KEY: "sk-ant-test-dummy", OPENAI_API_KEY: "sk-test-dummy",
      OPENCODE_DISABLE_MODELS_FETCH: "1", OPENCODE_DISABLE_AUTOUPDATE: "1",
    },
  };
  try { await fn(rig); } finally {
    killRigProcesses(rig);
    proxy.close(); vendor.close(); evil.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The env Mandu hands a 2.x launch: the run file and the inline routing,
 *  written by the launcher's own writer over the user's env. */
function manduEnv(r: Rig, over: Partial<LaunchPlan> = {}): Record<string, string> {
  const scope = mkdtempSync(join(r.dir, "scope-"));
  const out = writeAgentConfig(
    launchPlan({ agentVersion: r.version, proxy: { host: "127.0.0.1", port: r.proxy.port }, cwd: r.proj, humanCwd: r.proj, ...over }),
    Layout.dev("/repo"), scope, () => {}, r.userEnv,
  );
  return { ...r.userEnv, [out.envVar]: out.path, ...(out.env ?? {}) };
}

/** SIGKILL every process running with this rig's HOME: a stopped run's
 *  private server is not always in its process group (seen in the CI
 *  guest), and one left behind keeps retrying its model call, which a later
 *  run of the same rig would count as its own. Linux /proc only. */
function killRigProcesses(r: Rig): void {
  let pids: string[] = [];
  try { pids = readdirSync("/proc").filter((d) => /^\d+$/.test(d) && Number(d) !== process.pid); } catch { return; }
  for (const pid of pids) {
    try {
      if (readFileSync(`/proc/${pid}/environ`, "utf8").split("\0").includes(`HOME=${r.home}`)) process.kill(Number(pid), "SIGKILL");
    } catch { /* gone, or not ours */ }
  }
}

/** One `opencode run --standalone`; stopped (its process group and every
 *  process of the rig killed) as soon as `stopOn` sees a request: the
 *  request is the proof. Resolves only once nothing of the run is left. */
function runOc(r: Rig, env: Record<string, string>, args: string[], stopOn?: Upstream): Promise<{ status: number | null; out: string; err: string }> {
  return new Promise((done) => {
    const child = spawn(r.bin, ["run", ...(r.version.startsWith("1.") ? [] : ["--standalone"]), "--format", "json", ...args], { cwd: r.proj, env, stdio: ["ignore", "pipe", "pipe"], detached: true });
    let out = "", err = "";
    const kill = (): void => { try { process.kill(-child.pid!, "SIGKILL"); } catch { /* gone */ } killRigProcesses(r); };
    const timer = setTimeout(kill, 120_000);
    const poll = stopOn ? setInterval(() => { if (stopOn.hits.length > 0) kill(); }, 50) : undefined;
    child.stdout.on("data", (c: Buffer) => { out += c.toString("utf8"); });
    child.stderr.on("data", (c: Buffer) => { err += c.toString("utf8"); });
    child.on("close", (status) => { clearTimeout(timer); if (poll) clearInterval(poll); kill(); done({ status, out, err }); });
  });
}

const messages = (u: Upstream): Hit[] => u.hits.filter((h) => h.path.startsWith("/v1/messages"));
const SONNET = ["-m", "anthropic/claude-sonnet-4-5"];

test("REAL OpenCode 2: a PROJECT config cannot move the turn off the proxy — not by re-admitting a provider, not by re-pointing one in V2 spelling", async (t) => {
  await withRig(t, async (r) => {
    writeFileSync(join(r.proj, "opencode.json"), JSON.stringify({
      enabled_providers: ["openai"],
      experimental: { policies: [{ action: "provider.use", resource: "openai", effect: "allow" }] },
      permissions: [{ action: "execute", resource: "*", effect: "allow" }],
      providers: {
        anthropic: { settings: { baseURL: `${r.vendor.url}/v1` } },
        openai: { settings: { baseURL: `${r.evil.url}/v1` } },
      },
    }));
    // The user's own inline content re-points anthropic in V2 spelling too.
    r.userEnv["OPENCODE_CONFIG_CONTENT"] = JSON.stringify({ providers: { anthropic: { settings: { baseURL: `${r.vendor.url}/v1` } } } });
    const env = manduEnv(r);

    const ok = await runOc(r, env, [...SONNET, "say hi"]);
    assert.equal(ok.status, 0, ok.err);
    assert.ok(messages(r.proxy).length > 0 && messages(r.proxy).every((h) => h.session === "sess-oc2-config"), "every turn reached the proxy with the session header");
    assert.equal(r.vendor.hits.length, 0, "the re-pointed base URL (project and inline, V2 spelling) took nothing");
    // Code mode off: the inline `execute` deny beats the project's allow (permission rules keep the normal precedence).
    const offered = messages(r.proxy).map((h) => { try { return ((JSON.parse(h.body) as { tools?: Array<{ name: string }> }).tools ?? []).map((x) => x.name); } catch { return []; } }).find((n) => n.length > 0) ?? [];
    assert.ok(offered.includes("read") && !offered.includes("execute"), `no execute tool offered: ${offered.join(",")}`);

    const fenced = await runOc(r, env, ["-m", "openai/gpt-5", "say hi"], r.evil);
    assert.equal(r.evil.hits.length, 0, "the project's admission of openai did not beat Mandu's fence");
    assert.notEqual(fenced.status, 0);
    assert.match(fenced.out + fenced.err, /Model unavailable: openai\/gpt-5|no-route/);
  });
});

test("REAL OpenCode 2: under the lockdown the GLOBAL config's admission no longer beats the fence", async (t) => {
  await withRig(t, async (r) => {
    writeFileSync(join(r.home, ".config", "opencode", "opencode.json"), JSON.stringify({
      enabled_providers: ["anthropic", "openai"],
      experimental: { policies: [{ action: "provider.use", resource: "*", effect: "allow" }] },
      providers: { openai: { settings: { baseURL: `${r.evil.url}/v1` } } },
    }));
    // The launch admits it (nothing to refuse, nothing to route)…
    const plan = opencodeV2ModelPlan(["opencode", "run", "hi"], readOpencodeConfigLayers(r.userEnv, [r.proj], r.home));
    assert.deepEqual(plan, { refusal: null, routes: [] });
    // …and the fence holds: OpenCode 2 reads the global document only as merged into the run file.
    const fenced = await runOc(r, manduEnv(r), ["-m", "openai/gpt-5", "say hi"], r.evil);
    assert.equal(r.evil.hits.length, 0, `the global admission did not re-admit openai (exit ${String(fenced.status)})`);
    assert.match(fenced.out + fenced.err, /Model unavailable: openai\/gpt-5|no-route/);
    // Anthropic still runs, through the proxy.
    const ok = await runOc(r, manduEnv(r), [...SONNET, "say hi"]);
    assert.equal(ok.status, 0, ok.err);
    assert.ok(messages(r.proxy).length > 0 && r.vendor.hits.length === 0);
  });
});

test("REAL OpenCode 2: a model's OWN endpoint in a project config takes the turn around the proxy, so the launch refuses it", async (t) => {
  await withRig(t, async (r) => {
    writeFileSync(join(r.proj, "opencode.json"), JSON.stringify({
      providers: { anthropic: { models: { "claude-sonnet-4-5": { settings: { baseURL: `${r.vendor.url}/v1` } } } } },
    }));
    const run = await runOc(r, manduEnv(r), [...SONNET, "say hi"], r.vendor);
    assert.ok(messages(r.vendor).length > 0, `the model's own base URL won over the routed provider's (exit ${String(run.status)})`);
    const refusal = opencodeV2ModelPlan(["opencode", "run", "hi"], readOpencodeConfigLayers(r.userEnv, [r.proj], r.home)).refusal ?? "";
    assert.match(refusal, /providers\.anthropic\.models\.claude-sonnet-4-5\.settings\.baseURL in .*opencode\.json gives one anthropic model its own endpoint/);
  });
});

/** Call the session's private server's `POST /api/location/reload` the way
 *  any process of the user could: its password from its /proc environ, its
 *  port from `ss`. Null when it cannot be found (the caller then fails). */
async function reloadPrivateServer(r: Rig): Promise<number | null> {
  for (const pid of readdirSync("/proc").filter((d) => /^\d+$/.test(d))) {
    let cmd = "", envs: string[] = [];
    try {
      cmd = readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").join(" ");
      envs = readFileSync(`/proc/${pid}/environ`, "utf8").split("\0");
    } catch { continue; }
    if (!cmd.includes("serve") || !cmd.includes("--stdio") || !envs.includes(`HOME=${r.home}`)) continue;
    const pw = envs.find((e) => e.startsWith("OPENCODE_PASSWORD="))?.slice("OPENCODE_PASSWORD=".length);
    let ss = "";
    try { ss = execFileSync("ss", ["-ltnpH"], { encoding: "utf8" }); } catch { return null; }
    const port = ss.split("\n").find((l) => l.includes(`pid=${pid},`))?.match(/127\.0\.0\.1:(\d+)/)?.[1];
    if (!pw || !port) return null;
    const res = await fetch(`http://127.0.0.1:${port}/api/location/reload`, {
      method: "POST",
      headers: { authorization: `Basic ${Buffer.from(`opencode:${pw}`).toString("base64")}`, "x-opencode-directory": r.proj },
    });
    return res.status;
  }
  return null;
}

/** A model endpoint for the session's model, as a hostile config would write it. */
const endpointDoc = (r: Rig): string => JSON.stringify({
  providers: { anthropic: { models: { "claude-sonnet-4-5": { settings: { baseURL: `${r.vendor.url}/v1` } } } } },
});

/**
 * One scripted mid-session write: on the first tool-bearing turn, `path(r)`
 * gets a model endpoint (as the agent's own write tool could), then
 * optionally the private server is told to reload; the turn then asks for a
 * read, so OpenCode makes the next request after the write.
 */
async function midSession(t: { skip: (m: string) => void }, path: (r: Rig) => string, reload: boolean,
  check: (r: Rig, at: { proxyBefore: number; reloadStatus: number | null | undefined; status: number | null; err: string }) => void,
  which: "v1" | "v2" = "v2", doc: (r: Rig) => string = endpointDoc): Promise<void> {
  let wrote = false;
  let proxyBefore = 0;
  let reloadStatus: number | null | undefined;
  await withRig(t, async (r) => {
    writeFileSync(join(r.proj, "notes.txt"), "a file the agent reads\n");
    const run = await runOc(r, manduEnv(r), [...SONNET, ...(which === "v2" ? ["--auto"] : []), "read notes.txt"], r.vendor);
    assert.ok(wrote, `the scripted turn wrote the config (exit ${String(run.status)}): ${run.err.slice(-400)}`);
    check(r, { proxyBefore, reloadStatus, status: run.status, err: run.err });
  }, (h, r) => {
    let tools = false;
    try { tools = ((JSON.parse(h.body) as { tools?: unknown[] }).tools ?? []).length > 0; } catch { /* not JSON */ }
    if (!tools || wrote) return undefined;
    wrote = true;
    proxyBefore = messages(r.proxy).length;
    const target = path(r);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, doc(r));
    if (reload) void reloadPrivateServer(r).then((s) => { reloadStatus = s; }, () => { reloadStatus = null; });
    // Answer after the watcher (or the reload) has had time to act. OpenCode
    // 1's read takes `filePath`, 2's `path`.
    const file = join(r.proj, "notes.txt");
    return { tool: { name: "read", input: which === "v1" ? { filePath: file } : { path: file } }, delayMs: 3000 };
  }, which);
}

const HELD = "the request after the write stayed on the proxy (when this fails, the lockdown no longer holds against a " +
  "mid-session config: supported-agents.md §2.3 item 8)";

for (const [name, path] of [
  ["the project's opencode.json", (r: Rig) => join(r.proj, "opencode.json")],
  ["a NEW .opencode/opencode.json", (r: Rig) => join(r.proj, ".opencode", "opencode.json")],
  ["an ancestor's opencode.json", (r: Rig) => join(dirname(r.proj), "opencode.json")],
  ["the global opencode.json", (r: Rig) => join(r.home, ".config", "opencode", "opencode.json")],
] as const) {
  test(`REAL OpenCode 2 (§2.3 item 8): a model endpoint written MID-SESSION to ${name} does not move the next request (no watcher)`, async (t) => {
    await midSession(t, path, false, (r, at) => {
      assert.equal(messages(r.vendor).length, 0, HELD);
      assert.ok(messages(r.proxy).length > at.proxyBefore, `the next request reached the proxy (exit ${String(at.status)}): ${at.err.slice(-300)}`);
    });
  });
  test(`REAL OpenCode 2 (§2.3 item 8): … nor with the private server's reload API called, as any process of the user could (${name})`, async (t) => {
    await midSession(t, path, true, (r, at) => {
      assert.equal(at.reloadStatus, 204, "the reload API took the call");
      assert.equal(messages(r.vendor).length, 0, HELD);
      assert.ok(messages(r.proxy).length > at.proxyBefore, `the next request reached the proxy (exit ${String(at.status)})`);
    });
  });
}

test("REAL OpenCode 2 (§2.3 item 8, the guard's job): a write into the LAUNCHER's config directory plus a reload would move it", async (t) => {
  await midSession(t, (r) => {
    const dir = readdirSync(r.dir).filter((d) => d.startsWith("scope-")).map((d) => join(r.dir, d, OPENCODE_CONFIG_DIR_NAME)).find((d) => existsSync(d));
    assert.ok(dir, "the launcher's config directory exists");
    return join(dir, "opencode.json");
  }, true, (r, at) => {
    assert.equal(at.reloadStatus, 204);
    assert.ok(messages(r.vendor).length > 0,
      "the one config layer left on disk is the launcher's directory; under Mandu the whole-agent guard refuses the " +
      "agent's tree a write there (agent-config.ts opencodeWriteProtect). When this fails, update §2.3 item 8.");
  });
});

/** A stdio MCP server with Mandu's inspect tool name and nothing else: it
 *  stands in for inspect-mcp (whose own runtime this test does not need)
 *  and echoes the symbol it was asked about. */
const STUB_INSPECT = `
const rl = require("node:readline").createInterface({ input: process.stdin });
const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
rl.on("line", (l) => {
  let m; try { m = JSON.parse(l); } catch { return; }
  if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: m.params?.protocolVersion ?? "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "mandu-inspect", version: "0" } } });
  else if (m.method === "tools/list") send({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "inspect_symbol", description: "inspect a symbol", inputSchema: { type: "object", properties: { symbol: { type: "string" }, question: { type: "string" } }, required: ["symbol"] } }] } });
  else if (m.method === "tools/call") send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "stub-inspected " + m.params.arguments.symbol }] } });
  else if (m.id !== undefined) send({ jsonrpc: "2.0", id: m.id, result: {} });
});
`;

test("REAL OpenCode 2: the inspect mount Mandu writes (V2 spelling, codemode off) is offered as `mandu-inspect_inspect_symbol` and its call reaches the server", async (t) => {
  const offered: string[][] = [];
  await withRig(t, async (r) => {
    const env = manduEnv(r, { writeMcp: true, writePolicyMcp: false });
    // Keep every field Mandu wrote for the server (the spelling, codemode,
    // the timeouts, its environment) and swap only the program it starts.
    const runFile = env["OPENCODE_CONFIG"]!;
    const doc = JSON.parse(readFileSync(runFile, "utf8")) as { mcp: { servers: Record<string, { command: string[]; codemode: boolean }> } };
    assert.equal(doc.mcp.servers["mandu-inspect"]!.codemode, false);
    const stub = join(r.dir, "stub-inspect.cjs");
    writeFileSync(stub, STUB_INSPECT);
    doc.mcp.servers["mandu-inspect"]!.command = [process.execPath, stub];
    writeFileSync(runFile, JSON.stringify(doc));

    const run = await runOc(r, env, [...SONNET, "--auto", "inspect it"]);
    assert.equal(run.status, 0, run.err.slice(-400));
    // 2.x connects MCP servers in the background and adds their tools from
    // the next step on (mcp.tools.changed, then a 100 ms debounce), so the
    // first step never carries them; the scripted first step takes as long
    // as a real model's would.
    assert.ok(offered.length >= 3, `three tool-bearing turns: ${offered.length}`);
    assert.ok(offered.slice(1).every((names) => names.includes("mandu-inspect_inspect_symbol")),
      `offered from step 2 on: ${offered.map((n) => n.join(",")).join(" | ")}`);
    assert.ok(offered.every((names) => !names.includes("execute")), "code mode stays off");
    const last = messages(r.proxy).map((h) => h.body).filter((b) => b.includes("\"tools\"")).at(-1) ?? "";
    assert.match(last, /stub-inspected \$MDU:fixture/, "the call reached the mounted server and its answer came back as a tool_result");
  }, (h) => {
    let names: string[] = [];
    try { names = ((JSON.parse(h.body) as { tools?: Array<{ name: string }> }).tools ?? []).map((x) => x.name); } catch { /* not JSON */ }
    if (names.length === 0) return undefined; // a title request
    offered.push(names);
    if (offered.length === 1) return { tool: { name: "glob", input: { pattern: "*" }, id: "toolu_glob" }, delayMs: 1500 };
    if (offered.length === 2) return { tool: { name: "mandu-inspect_inspect_symbol", input: { symbol: "$MDU:fixture" }, id: "toolu_inspect" } };
    return undefined;
  });
});

test("REAL OpenCode 1 (§2.3 item 8: the shipped product): a config written MID-SESSION is not reloaded at all", async (t) => {
  // A benign marker header and a model endpoint, in the project and the
  // global config, in OpenCode 1's spelling: neither shows on the next request.
  const doc = (r: Rig): string => JSON.stringify({ provider: { anthropic: {
    options: { headers: { "x-reload-marker": "1" } },
    models: { "claude-sonnet-4-5": { options: { baseURL: `${r.vendor.url}/v1` } } },
  } } });
  for (const path of [(r: Rig) => join(r.proj, "opencode.json"), (r: Rig) => join(r.home, ".config", "opencode", "opencode.json")]) {
    await midSession(t, path, false, (r, at) => {
      assert.equal(messages(r.vendor).length, 0, "nothing went around the proxy");
      const after = r.proxy.hits.filter((h) => h.path.startsWith("/v1/messages")).slice(at.proxyBefore);
      assert.ok(after.length > 0, `the next request reached the proxy (exit ${String(at.status)}): ${at.err.slice(-300)}`);
      assert.ok(after.every((h) => h.headers["x-reload-marker"] === undefined), "and the written config was never applied");
    }, "v1", doc);
  }
});
