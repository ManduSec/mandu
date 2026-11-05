/**
 * The confined-commands tier's backend against a fake OpenClaw caller
 * (src/sandbox/*, box/*; docs/design/agents/openclaw-plugin.md §10).
 *
 * The box host (box/host.mjs) runs here as a plain process, NOT inside a
 * Mandu launch: what is pinned is the plugin's half — the registration
 * through the SDK seam, the handle OpenClaw calls (buildExecSpec, whose argv
 * is spawned exactly as OpenClaw spawns it; runShellCommand; the fs bridge),
 * the exec relay's streams, exit codes and signals, and every fail-closed
 * branch (no box, a refused ticket, a box that reports itself unconfined, a
 * platform that is not Linux, the `mandu` backend replaced by another
 * plugin). The confinement itself (placeholders, the egress proxy, Mandu's
 * state out of reach) is the launcher's, proved on a real Gateway by the
 * drill suite's sandbox-backend lane.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter, once } from "node:events";
import { PassThrough } from "node:stream";

import { BoxClient } from "../../src/sandbox/box-client.js";
import { HOST_SCRIPT, RELAY_SCRIPT, registerSandboxTier, type FactoryParams, type SandboxSdk } from "../../src/sandbox/backend.js";
import { ManduBox, boxLaunchArgv, boxLaunchEnv, probeFileIn } from "../../src/sandbox/box.js";
import { ManduFsBridge, type HostFs } from "../../src/sandbox/fs-bridge.js";

const silent = { info: () => {}, warn: () => {}, error: () => {} };

/** A box host started as a plain process (no launch) on a socket in `dir`. */
async function startHost(dir: string, env: NodeJS.ProcessEnv = process.env): Promise<{ client: BoxClient; child: ChildProcess; ready: Record<string, unknown> }> {
  const sock = join(dir, "box.sock");
  const child = spawn(process.execPath, [HOST_SCRIPT, "--socket", sock], { env, stdio: ["pipe", "pipe", "pipe"] });
  let out = "";
  const ready = await new Promise<Record<string, unknown>>((resolve, reject) => {
    child.stdout!.on("data", (d: Buffer) => {
      out += d.toString();
      const nl = out.indexOf("\n");
      if (nl >= 0) resolve(JSON.parse(out.slice(0, nl)) as Record<string, unknown>);
    });
    child.once("exit", (c) => reject(new Error(`host exited ${c}`)));
  });
  return { client: new BoxClient(sock), child, ready };
}

function runArgv(argv: string[], opts: { cwd?: string; stdin?: string; env?: NodeJS.ProcessEnv } = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const c = spawn(argv[0]!, argv.slice(1), { cwd: opts.cwd, env: opts.env ?? process.env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    c.stdout.on("data", (d: Buffer) => { stdout += d.toString(); });
    c.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });
    if (opts.stdin !== undefined) c.stdin.end(opts.stdin); else c.stdin.end();
    c.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

/** A fake SDK seam that records the registration, as OpenClaw's registry does. */
function fakeSdk(): SandboxSdk & { factories: Map<string, (p: FactoryParams) => Promise<unknown>> } {
  const factories = new Map<string, (p: FactoryParams) => Promise<unknown>>();
  return {
    factories,
    registerSandboxBackend: (id, reg) => { factories.set(id, reg.factory); return () => factories.delete(id); },
    getSandboxBackendFactory: (id) => factories.get(id) ?? null,
  };
}

test("the box host: the host reports its facts, prepare → relay runs the command with its stdin, output, exit and env", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mocsb-c-"));
  const { client, child, ready } = await startHost(dir, { ...process.env, HTTPS_PROXY: "http://127.0.0.1:9", MANDU_NET_GUARD_PROXY_PORTS: "9", GH_TOKEN: "$MDU:nomodel_Env[ab12]" });
  try {
    assert.equal(ready["ready"], true);
    assert.deepEqual(Object.keys(ready["facts"] as object).sort(), ["egressProxy", "guardPorts", "manduHome", "seccomp"]);
    assert.equal((ready["facts"] as { egressProxy: boolean }).egressProxy, true);
    assert.equal(await client.ping(), true);
    const ticket = await client.prepare({
      command: "read line; echo \"got:$line\"; echo \"$FOO|$GH_TOKEN|$HTTPS_PROXY\"; pwd; echo oops >&2; exit 7",
      cwd: dir, env: { FOO: "bar", GH_TOKEN: "ghp_raw", HTTPS_PROXY: "" }, pty: false,
    });
    const r = await runArgv([process.execPath, RELAY_SCRIPT, client.socketPath, ticket], { stdin: "hello\n" });
    assert.equal(r.code, 7, "the relay exits with the command's status");
    assert.match(r.stdout, /got:hello/, "stdin reached the command");
    assert.match(r.stdout, /bar\|\$MDU:nomodel_Env\[ab12\]\|http:\/\/127\.0\.0\.1:9/, "the request adds FOO, but a masked or protected variable keeps the box's value");
    assert.ok(r.stdout.includes(dir), "the command ran in the folder it was given");
    assert.match(r.stderr, /oops/);
    // A ticket is good once.
    const again = await runArgv([process.execPath, RELAY_SCRIPT, client.socketPath, ticket]);
    assert.equal(again.code, 126, "a used ticket runs nothing");
    assert.match(again.stderr, /did not run/);
  } finally {
    child.kill("SIGTERM");
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the relay fails closed: no box, no ticket — exit 126 and nothing runs", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mocsb-c-"));
  try {
    const marker = join(dir, "ran");
    const r = await runArgv([process.execPath, RELAY_SCRIPT, join(dir, "nobox.sock"), "0".repeat(32)]);
    assert.equal(r.code, 126);
    assert.match(r.stderr, /did not run.*not reachable/s);
    const noArgs = await runArgv([process.execPath, RELAY_SCRIPT]);
    assert.equal(noArgs.code, 126);
    assert.equal(readFileOr(marker), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function readFileOr(p: string): string | null {
  try { return readFileSync(p, "utf8"); } catch { return null; }
}

test("the relay passes a signal to the command's group, and a killed relay kills the command", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mocsb-c-"));
  const { client, child } = await startHost(dir);
  try {
    const t1 = await client.prepare({ command: "trap 'echo TERMED; exit 3' TERM; echo started; while :; do sleep 0.1; done", cwd: dir, env: {}, pty: false });
    const relay = spawn(process.execPath, [RELAY_SCRIPT, client.socketPath, t1], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    relay.stdout.on("data", (d: Buffer) => { out += d.toString(); });
    while (!out.includes("started")) await new Promise((r) => setTimeout(r, 50));
    relay.kill("SIGTERM");
    const [code] = await once(relay, "close") as [number];
    assert.equal(code, 3, "the trap ran and its status came back");
    assert.match(out, /TERMED/);

    const pidFile = join(dir, "pid");
    const t2 = await client.prepare({ command: `echo $$ > ${pidFile}; while :; do sleep 0.1; done`, cwd: dir, env: {}, pty: false });
    const relay2 = spawn(process.execPath, [RELAY_SCRIPT, client.socketPath, t2], { stdio: ["pipe", "pipe", "pipe"] });
    while (readFileOr(pidFile) === null) await new Promise((r) => setTimeout(r, 50));
    const pid = Number(readFileOr(pidFile)!.trim());
    relay2.kill("SIGKILL");
    await once(relay2, "close");
    const deadline = Date.now() + 5_000;
    let alive = true;
    while (alive && Date.now() < deadline) {
      try { process.kill(pid, 0); await new Promise((r) => setTimeout(r, 100)); } catch { alive = false; }
    }
    assert.equal(alive, false, "the command died with its relay");
  } finally {
    child.kill("SIGTERM");
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the backend: registered as `mandu` through the seam; OpenClaw's calls run in the box; the fs bridge reads and writes there", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mocsb-c-"));
  const ws = join(dir, "ws");
  mkdirSync(ws);
  const { client, child } = await startHost(dir);
  const sdk = fakeSdk();
  const tier = registerSandboxTier({ launcher: ["/usr/bin/mandu"], writeProtect: [] }, {
    env: process.env, arbiterSock: "/run/a.sock", logger: silent, loadSdk: async () => sdk, platform: "linux",
    makeBox: () => ({ ready: async () => client, stop: () => {} }),
  });
  try {
    await tier.ready;
    const factory = sdk.factories.get("mandu");
    assert.ok(factory, "the backend registered as mandu");
    const handle = await factory!({ workspaceDir: ws, agentWorkspaceDir: ws, scopeKey: "agent:main", cfg: { workspaceAccess: "rw" } }) as {
      id: string; workdir: string;
      buildExecSpec(p: { command: string; workdir?: string; env: Record<string, string>; usePty: boolean }): Promise<{ argv: string[]; env: Record<string, string>; stdinMode: string }>;
      runShellCommand(p: { script: string; args?: string[]; allowFailure?: boolean }): Promise<{ stdout: Buffer; stderr: Buffer; code: number }>;
      createFsBridge(p: { sandbox: unknown }): ManduFsBridge;
    };
    assert.equal(handle.id, "mandu");
    assert.equal(handle.workdir, ws);
    const spec = await handle.buildExecSpec({ command: "echo in-box:$OPENCLAW_SHELL; pwd", workdir: ws, env: { OPENCLAW_SHELL: "exec" }, usePty: false });
    assert.deepEqual(spec.argv.slice(1, 3), [RELAY_SCRIPT, client.socketPath], "OpenClaw spawns the relay, never the command itself");
    assert.equal(spec.stdinMode, "pipe-closed");
    assert.deepEqual(Object.keys(spec.env).filter((k) => !["PATH", "HOME", "LANG", "TERM", "TZ"].includes(k)), [], "the relay gets no Gateway variable beyond the basics");
    const r = await runArgv(spec.argv, { env: spec.env });
    assert.equal(r.code, 0);
    assert.match(r.stdout, new RegExp(`in-box:exec\\n${ws}`));
    const sh = await handle.runShellCommand({ script: 'echo "$1-$2"', args: ["a", "b"] });
    assert.equal(sh.stdout.toString(), "a-b\n");
    await assert.rejects(handle.runShellCommand({ script: "echo bad >&2; exit 4" }), /bad/, "a failing script throws unless allowFailure");
    assert.equal((await handle.runShellCommand({ script: "exit 4", allowFailure: true })).code, 4);

    // The fs bridge: every operation in the box, inside the mounts.
    const bridge = handle.createFsBridge({ sandbox: { workspaceDir: ws, agentWorkspaceDir: ws, workspaceAccess: "rw" } });
    await bridge.writeFile({ filePath: "notes/a.txt", data: "one\n", mkdir: true });
    assert.equal(readFileSync(join(ws, "notes", "a.txt"), "utf8"), "one\n");
    assert.equal((await bridge.readFile({ filePath: join(ws, "notes", "a.txt") })).toString(), "one\n");
    assert.deepEqual(await bridge.stat({ filePath: "notes/a.txt" }).then((s) => s?.type), "file");
    assert.equal(await bridge.stat({ filePath: "notes/none.txt" }), null);
    assert.deepEqual((await bridge.readDirectory({ filePath: "notes" })).map((e) => e.name), ["a.txt"]);
    assert.equal(await bridge.createFileExclusive({ filePath: "notes/a.txt", data: "x" }), "exists");
    assert.equal(await bridge.createFileExclusive({ filePath: "notes/b.txt", data: "two" }), "created");
    await bridge.rename({ from: "notes/b.txt", to: "notes/c.txt" });
    await bridge.copyFile({ sourcePath: "notes/c.txt", destinationPath: "notes/d.txt" });
    assert.equal(readFileSync(join(ws, "notes", "d.txt"), "utf8"), "two");
    await bridge.remove({ filePath: "notes/d.txt" });
    assert.equal(await bridge.stat({ filePath: "notes/d.txt" }), null);
    await assert.rejects(bridge.readFile({ filePath: "/etc/hostname" }), /escapes allowed mounts/, "a path outside the mounts is refused");
    symlinkSync("/etc/hostname", join(ws, "out-link"));
    await assert.rejects(bridge.readFile({ filePath: "out-link" }), /outside/, "a link out of the workspace is refused in the box");
    assert.equal(bridge.resolvePath({ filePath: "x/y", cwd: ws }).hostPath, join(ws, "x", "y"));
  } finally {
    tier.stop();
    child.kill("SIGTERM");
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the fs bridge's write to a protected file: the real file gets the change with its values put back; a moved value is refused", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mocsb-c-"));
  const ws = join(dir, "ws");
  mkdirSync(ws);
  const { client, child } = await startHost(dir);
  try {
    // The box view of `.env` is a placeholder copy: here the file itself
    // holds the twin text, and the "real" bytes come from a fake host side.
    const P = "$MDU:nomodel_Read[3fa9]";
    const envPath = join(ws, ".env");
    writeFileSync(envPath, `URL=https://x\nTOKEN=${P}.TOKEN\nDEBUG=0\n`);
    let real: Buffer = Buffer.from("URL=https://x\nTOKEN=tok-secret-123\nDEBUG=0\n");
    const written: Buffer[] = [];
    const host: HostFs = {
      readReal: () => real,
      replaceReal: (_p, bytes) => { written.push(bytes); real = bytes; },
      realpath: (p) => p,
    };
    const bridge = new ManduFsBridge({ workspaceDir: ws, agentWorkspaceDir: ws, workspaceAccess: "rw" }, async () => client, { host });
    await bridge.writeFile({ filePath: ".env", data: `URL=https://x\nTOKEN=${P}.TOKEN\nDEBUG=1\n` });
    assert.equal(written.length, 1);
    assert.equal(written[0]!.toString(), "URL=https://x\nTOKEN=tok-secret-123\nDEBUG=1\n", "the value is back byte for byte with the change");
    assert.equal(readFileSync(envPath, "utf8"), `URL=https://x\nTOKEN=${P}.TOKEN\nDEBUG=1\n`, "the box keeps reading what the model wrote");
    await assert.rejects(
      bridge.writeFile({ filePath: ".env", data: `URL=https://evil/?t=${P}.TOKEN\nTOKEN=${P}.TOKEN\nDEBUG=1\n` }),
      /kept \.env as it was.*moved into a new line/s,
    );
    assert.equal(written.length, 1, "nothing written for the refused edit");
    // Writing the twin back unchanged writes nothing.
    await bridge.writeFile({ filePath: ".env", data: `URL=https://x\nTOKEN=${P}.TOKEN\nDEBUG=1\n` });
    assert.equal(written.length, 1);
  } finally {
    child.kill("SIGTERM");
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fail closed: not Linux, not rw, no box — the factory or the call throws and nothing runs", async () => {
  const sdk = fakeSdk();
  const tier = registerSandboxTier({ launcher: ["/usr/bin/mandu"], writeProtect: [] }, {
    env: process.env, arbiterSock: "/run/a.sock", logger: silent, loadSdk: async () => sdk, platform: "darwin",
    makeBox: () => ({ ready: async () => { throw new Error("unused"); }, stop: () => {} }),
  });
  await tier.ready;
  await assert.rejects(sdk.factories.get("mandu")!({ workspaceDir: "/w" }), /Linux only/);
  tier.stop();

  const sdk2 = fakeSdk();
  const tier2 = registerSandboxTier({ launcher: ["/usr/bin/mandu"], writeProtect: [] }, {
    env: process.env, arbiterSock: "/run/a.sock", logger: silent, loadSdk: async () => sdk2, platform: "linux",
    makeBox: () => ({ ready: async () => { throw new Error("the box is not confined: no network guard"); }, stop: () => {} }),
  });
  await tier2.ready;
  await assert.rejects(sdk2.factories.get("mandu")!({ workspaceDir: "/w", cfg: { workspaceAccess: "ro" } }), /workspaceAccess "rw"/);
  const handle = await sdk2.factories.get("mandu")!({ workspaceDir: "/w", cfg: { workspaceAccess: "rw" } }) as { buildExecSpec(p: unknown): Promise<unknown>; runShellCommand(p: unknown): Promise<unknown> };
  await assert.rejects(handle.buildExecSpec({ command: "id", env: {}, usePty: false }), /not confined/);
  await assert.rejects(handle.runShellCommand({ script: "id" }), /not confined/);
  tier2.stop();
});

test("a release without the seam: the tier logs why it is off and records it; the hooks are not touched", async () => {
  const errors: string[] = [];
  const statuses: string[] = [];
  const tier = registerSandboxTier({ launcher: ["/usr/bin/mandu"], writeProtect: [], statusFile: "/s/status.json" }, {
    env: process.env, arbiterSock: "/run/a.sock", logger: { ...silent, error: (m) => errors.push(m) },
    loadSdk: async () => { throw new Error("Cannot find module 'openclaw/plugin-sdk/sandbox'"); },
    writeStatus: (_p, t) => statuses.push(t),
  });
  await tier.ready;
  assert.match(errors.join("\n"), /confined-commands tier is OFF.*2026\.7/s);
  const s = JSON.parse(statuses[0]!) as { sdk: boolean; registered: boolean; error: string };
  assert.equal(s.sdk, false);
  assert.equal(s.registered, false);
  assert.match(s.error, /Cannot find module/);
  tier.stop();
});

test("last writer wins: another plugin's `mandu` is reported in the status and the log", async () => {
  const sdk = fakeSdk();
  const errors: string[] = [];
  const statuses: string[] = [];
  const tier = registerSandboxTier({ launcher: ["/usr/bin/mandu"], writeProtect: [], statusFile: "/s/status.json" }, {
    env: process.env, arbiterSock: "/run/a.sock", logger: { ...silent, error: (m) => errors.push(m) },
    loadSdk: async () => sdk, writeStatus: (_p, t) => statuses.push(t), platform: "linux",
    makeBox: () => ({ ready: async () => { throw new Error("unused"); }, stop: () => {} }),
  });
  await tier.ready;
  assert.equal((JSON.parse(statuses.at(-1)!) as { ours: boolean }).ours, true);
  sdk.registerSandboxBackend("mandu", { factory: async () => ({}) });
  // The timer's next check, run now.
  (tier as unknown as { stop: () => void }).stop();
  const tier2 = registerSandboxTier({ launcher: ["/usr/bin/mandu"], writeProtect: [], statusFile: "/s/status.json" }, {
    env: process.env, arbiterSock: "/run/a.sock", logger: { ...silent, error: (m) => errors.push(m) },
    loadSdk: async () => ({ registerSandboxBackend: () => () => {}, getSandboxBackendFactory: () => async () => ({}) }),
    writeStatus: (_p, t) => statuses.push(t), platform: "linux",
  });
  await tier2.ready;
  assert.equal((JSON.parse(statuses.at(-1)!) as { ours: boolean }).ours, false);
  assert.match(errors.join("\n"), /no longer Mandu's/);
  tier2.stop();
});

/** A fake launcher child for ManduBox: what it prints, when it exits. */
function fakeChild(): ChildProcess & { stdoutW: PassThrough; stderrW: PassThrough } {
  const ee = new EventEmitter() as ChildProcess & { stdoutW: PassThrough; stderrW: PassThrough };
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  Object.assign(ee, { stdout, stderr, stdin: new PassThrough(), stdoutW: stdout, stderrW: stderr, kill: () => true, unref: () => {} });
  return ee;
}

test("ManduBox: ready only on a confined report; an unconfined box, an early exit or a timeout is an error", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mocsb-c-"));
  const spec = {
    launcher: ["/opt/mandu/bin/mandu", "--from-source"], nodePath: "/usr/bin/node", hostScript: "/p/box/host.mjs", workspaceDir: dir,
    env: { PATH: "/usr/bin", HOME: "/h", OPENAI_API_KEY: "sk-raw", MANDU_HOME: "/h/.mandu", XDG_RUNTIME_DIR: "/run/user/1" }, arbiterSock: "/run/a.sock",
    manduHome: join(dir, "nohome"), writeProtect: ["/h/.openclaw/openclaw.json"], socketParent: dir, readyTimeoutMs: 300,
  };
  // The box's own timers are unref'd (a guest never holds its Gateway
  // open); the test holds the loop while it waits on them.
  const keep = setInterval(() => {}, 1_000);
  try {
    const calls: Array<{ cmd: string; args: readonly string[]; env: Record<string, string> }> = [];
    let child = fakeChild();
    const good = new ManduBox(spec, { spawn: (cmd, args, o) => { calls.push({ cmd, args, env: o.env as Record<string, string> }); return child; } });
    const p = good.ready();
    child.stdoutW.write(`noise\n${JSON.stringify({ manduBox: 1, ready: true, facts: { seccomp: "2", manduHome: "hidden", egressProxy: true, guardPorts: true } })}\n`);
    const client = await p;
    assert.ok(client.socketPath.startsWith(dir));
    assert.equal(calls[0]!.cmd, "/opt/mandu/bin/mandu");
    assert.deepEqual(calls[0]!.args.slice(0, 7), ["--from-source", "--target", "shell", "--no-reply-filter", "--require-own-confinement", "--write-protect", "/h/.openclaw/openclaw.json"]);
    assert.equal(calls[0]!.env["OPENAI_API_KEY"], undefined, "the Gateway's own keys stay in the Gateway");
    assert.equal(calls[0]!.env["MANDU_ARBITER_SOCK"], "/run/a.sock");
    assert.equal(calls[0]!.env["XDG_RUNTIME_DIR"], "/run/user/1");

    child = fakeChild();
    const bad = new ManduBox(spec, { spawn: () => child });
    const pb = bad.ready();
    child.stdoutW.write(`${JSON.stringify({ manduBox: 1, ready: true, facts: { seccomp: "0", manduHome: "visible", egressProxy: false, guardPorts: false } })}\n`);
    await assert.rejects(pb, /not confined: no network guard/);
    await assert.rejects(bad.ready(), /not confined/, "a refused box is not retried at once");

    child = fakeChild();
    const early = new ManduBox(spec, { spawn: () => child });
    const pe = early.ready();
    child.stderrW.write("mandu: refusing to launch: secrets cannot be confined\n");
    setTimeout(() => child.emit("exit", 1, null), 20);
    await assert.rejects(pe, /ended before it was ready.*refusing to launch/s);

    child = fakeChild();
    const slow = new ManduBox(spec, { spawn: () => child });
    await assert.rejects(slow.ready(), /did not come up/);
  } finally {
    clearInterval(keep);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("box launch argv, env and the Mandu-home probe are pure", () => {
  assert.deepEqual(boxLaunchArgv({ launcher: ["/m"], nodePath: "/n", hostScript: "/h.mjs", writeProtect: [] }, "/s.sock", null),
    ["--target", "shell", "--no-reply-filter", "--require-own-confinement", "--", "/n", "/h.mjs", "--socket", "/s.sock"]);
  assert.deepEqual(boxLaunchArgv({ launcher: ["/m"], nodePath: "/n", hostScript: "/h.mjs", writeProtect: [] }, "/s.sock", "/home/.mandu/x").slice(-2), ["--probe-file", "/home/.mandu/x"]);
  const env = boxLaunchEnv({ PATH: "/b", LC_ALL: "C", TELEGRAM_BOT_TOKEN: "t", MANDU_MODE: "off", MANDU_NET_GUARD: "0", MANDU_HOME: "/h/.mandu" }, "/a.sock");
  assert.deepEqual(env, { PATH: "/b", LC_ALL: "C", MANDU_HOME: "/h/.mandu", MANDU_ARBITER_SOCK: "/a.sock", MANDU_NO_ARBITER_AUTOSTART: "1" }, "no mode, no opt-out switch, no Gateway token");
  const tree: Record<string, string[]> = { "/m": ["state", "a-dir"], "/m/state": ["f.json"], "/m/a-dir": [] };
  assert.equal(probeFileIn("/m", (p) => tree[p] ?? [], (p) => p.endsWith(".json")), "/m/state/f.json");
  assert.equal(probeFileIn("/none", () => { throw new Error("ENOENT"); }), null);
});
