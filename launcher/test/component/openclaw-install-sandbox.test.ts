/**
 * `mandu openclaw install --sandbox` / `--no-sandbox` / uninstall, the
 * confined-commands tier (src/openclaw-install-command.ts, openclaw-sandbox.ts;
 * docs/design/agents/openclaw-plugin.md §10), over a temp HOME, the real file
 * system and a real identity endpoint standing in for the service proxy.
 * Never the real ~/.openclaw.
 *
 * Pinned: the tier is refused off Linux and without user namespaces, writing
 * nothing; with it, install writes the sandbox keys, the tool gate, elevated
 * off, takes `tools.exec.host: gateway` out, writes the plugin's block (the
 * launcher argv, the read-only paths, the status file) and records what it
 * replaced; a plain re-install keeps the tier; `--no-sandbox` and uninstall
 * give the user's own sandbox settings back key for key; an agent's own
 * entry that overrides the sandbox makes install refuse (the post-check);
 * the doctor reads the tier, and the plugin's report of a replaced backend.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { gatherOpenclawAttach, runOpenclawAttach, type AttachDeps } from "../../src/openclaw-install-command.js";
import { anthropicProxyPortFile } from "../../src/openclaw-attach.js";
import { readDeclaredList } from "../../src/serve-attachments.js";
import { sandboxStatusFile } from "../../src/attachment-contract.js";
import { probeIdentity } from "../../src/services/primitives.js";
import { tmpDir } from "../lib/tmp-dir.js";

const SESSION = "openclaw:main";
const OURS = { mandu: true, service: "anthropic-proxy", sessionKey: SESSION, arbiterSock: "/run/user/1000/mandu/instances/x/arbiter.sock" };
const LAUNCHER = ["/opt/mandu/launcher/mandu-run.sh"];

const USER = {
  agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6" }, sandbox: { mode: "non-main", docker: { image: "my:img" } } } },
  channels: { telegram: { botToken: "tg-secret-123" } },
  tools: { exec: { host: "gateway" }, elevated: { enabled: true, allowFrom: { telegram: ["42"] } } },
};

interface Stand { root: string; env: Record<string, string>; configPath: string; pluginDir: string; deps: AttachDeps; out: string[]; err: string[] }

function stand(over: Partial<AttachDeps> = {}, user: unknown = USER): Stand {
  const root = tmpDir("mandu-oc-sandbox-");
  const home = join(root, "home");
  const stateDir = join(home, ".openclaw");
  mkdirSync(stateDir, { recursive: true });
  const run = join(root, "run");
  mkdirSync(run, { mode: 0o700 });
  chmodSync(run, 0o700);
  const pluginDir = join(root, "src", "interceptors", "openclaw-inspect-plugin");
  mkdirSync(pluginDir, { recursive: true });
  const configPath = join(stateDir, "openclaw.json");
  writeFileSync(configPath, JSON.stringify(user, null, 2) + "\n", { mode: 0o600 });
  const env: Record<string, string> = { HOME: home, MANDU_HOME: join(root, "mandu"), MANDU_RUNTIME_DIR: run };
  const out: string[] = [];
  const err: string[] = [];
  let t = Date.parse("2026-10-26T10:00:00Z");
  const deps: AttachDeps = {
    pluginDir, uid: process.getuid?.(), probe: (port) => probeIdentity("127.0.0.1", port),
    out: (s) => out.push(s), err: (s) => err.push(s), now: () => new Date((t += 1000)),
    launcher: LAUNCHER, platform: "linux", usernsOk: () => true, usernsHint: () => "ok",
    ...over,
  };
  return { root, env, configPath, pluginDir, deps, out, err };
}

async function identityServer(): Promise<{ server: Server; port: number }> {
  const server = createServer((req, res) => {
    if (req.url === "/_mandu/identity") { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(OURS)); }
    else { res.statusCode = 404; res.end(); }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return { server, port: (server.address() as { port: number }).port };
}

function writePortFile(s: Stand, port: number): void {
  const file = anthropicProxyPortFile(s.env["MANDU_RUNTIME_DIR"]!, SESSION);
  mkdirSync(join(file, ".."), { recursive: true, mode: 0o700 });
  writeFileSync(file, `${port}\n`, { mode: 0o600 });
}

const read = (s: Stand): any => JSON.parse(readFileSync(s.configPath, "utf8"));

test("--sandbox is refused off Linux, without user namespaces, and with --no-sandbox beside it, writing nothing", async () => {
  for (const [over, re] of [
    [{ platform: "darwin" }, /Linux only/],
    [{ usernsOk: () => false, usernsHint: () => "kernel.apparmor_restrict_unprivileged_userns=1" }, /user namespaces.*apparmor_restrict/],
  ] as const) {
    const s = stand(over);
    const svc = await identityServer();
    try {
      writePortFile(s, svc.port);
      const before = readFileSync(s.configPath, "utf8");
      assert.equal(await runOpenclawAttach("install", ["--sandbox"], s.env, s.deps), 1);
      assert.match(s.err.join(""), re);
      assert.match(s.err.join(""), /Nothing was written/);
      assert.equal(readFileSync(s.configPath, "utf8"), before);
    } finally {
      svc.server.close();
    }
  }
  const s = stand();
  assert.equal(await runOpenclawAttach("install", ["--sandbox", "--no-sandbox"], s.env, s.deps), 2);
});

test("install --sandbox writes the tier and records what it replaced; a plain re-install keeps it; --no-sandbox and uninstall give the user's settings back", async () => {
  const s = stand();
  const svc = await identityServer();
  try {
    writePortFile(s, svc.port);
    assert.equal(await runOpenclawAttach("install", ["--sandbox"], s.env, s.deps), 0, s.err.join(""));
    assert.match(s.out.join(""), /confined commands \(--sandbox\)/);
    let doc = read(s);
    assert.deepEqual(doc.agents.defaults.sandbox, { mode: "all", docker: { image: "my:img" }, backend: "mandu", scope: "agent", workspaceAccess: "rw" });
    assert.deepEqual(doc.tools.sandbox.tools.alsoAllow, ["message", "group:web", "group:plugins"]);
    assert.deepEqual(doc.tools.elevated, { enabled: false, allowFrom: { telegram: ["42"] } });
    assert.equal(doc.tools.exec?.host, undefined, "the gateway exec host is taken out");
    const block = doc.plugins.entries["mandu-inspect"].config.sandbox;
    assert.deepEqual(block.launcher, LAUNCHER);
    assert.ok(block.writeProtect.includes(s.configPath), "the OpenClaw config is read-only in the box");
    assert.ok(block.writeProtect.includes(s.pluginDir), "and the plugin");
    assert.equal(block.statusFile, sandboxStatusFile(s.env["MANDU_RUNTIME_DIR"]!, SESSION));
    const decl = readDeclaredList(s.env).attachments[0]!;
    assert.deepEqual(decl.sandbox, { original: { sandbox: USER.agents.defaults.sandbox, alsoAllow: null, elevated: USER.tools.elevated, execHost: "gateway" } });

    // The doctor: the tier holds; no fresh report from a Gateway yet.
    const facts = await gatherOpenclawAttach(s.env, s.deps);
    assert.deepEqual(facts!.sandbox, { problems: [], status: null });
    // The plugin reports another plugin took `mandu`.
    const st = sandboxStatusFile(s.env["MANDU_RUNTIME_DIR"]!, SESSION);
    writeFileSync(st, JSON.stringify({ version: 1, pid: process.pid, checkedAt: new Date().toISOString(), sdk: true, registered: true, ours: false }) + "\n");
    const hijacked = await gatherOpenclawAttach(s.env, s.deps);
    assert.deepEqual(hijacked!.sandbox!.problems.map((p) => p.kind), ["backend-replaced"]);

    // A plain re-install keeps the tier and its record.
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 0, s.err.join(""));
    assert.equal(read(s).agents.defaults.sandbox.backend, "mandu");
    assert.deepEqual(readDeclaredList(s.env).attachments[0]!.sandbox?.original.execHost, "gateway");

    // --no-sandbox: the user's own sandbox, elevated and exec host come back.
    s.out.length = 0;
    assert.equal(await runOpenclawAttach("install", ["--no-sandbox"], s.env, s.deps), 0, s.err.join(""));
    assert.match(s.out.join(""), /confined commands taken out/);
    doc = read(s);
    assert.deepEqual(doc.agents.defaults.sandbox, USER.agents.defaults.sandbox);
    assert.deepEqual(doc.tools.elevated, USER.tools.elevated);
    assert.equal(doc.tools.exec.host, "gateway");
    assert.equal(doc.tools.sandbox, undefined);
    assert.equal(doc.plugins.entries["mandu-inspect"].config.sandbox, undefined);
    assert.equal(readDeclaredList(s.env).attachments[0]!.sandbox, undefined);

    // Again, then uninstall: the same, with the plugin gone too.
    assert.equal(await runOpenclawAttach("install", ["--sandbox"], s.env, s.deps), 0, s.err.join(""));
    assert.equal(await runOpenclawAttach("uninstall", [], s.env, s.deps), 0, s.err.join(""));
    doc = read(s);
    assert.deepEqual(doc.agents.defaults.sandbox, USER.agents.defaults.sandbox);
    assert.deepEqual(doc.tools, USER.tools);
    assert.equal(doc.plugins, undefined);
    assert.deepEqual(doc.channels, USER.channels);
  } finally {
    svc.server.close();
  }
});

test("an agent's own entry that keeps the sandbox off makes install --sandbox refuse (the post-check), writing nothing", async () => {
  const user = { ...USER, agents: { ...USER.agents, list: [{ id: "main", sandbox: { mode: "off" } }] } };
  const s = stand({}, user);
  const svc = await identityServer();
  try {
    writePortFile(s, svc.port);
    const before = readFileSync(s.configPath, "utf8");
    assert.equal(await runOpenclawAttach("install", ["--sandbox"], s.env, s.deps), 1);
    assert.match(s.err.join(""), /would still not run commands in Mandu's box.*not "all"/s);
    assert.equal(readFileSync(s.configPath, "utf8"), before);
  } finally {
    svc.server.close();
  }
});
