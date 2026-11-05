/**
 * openclaw-install — `mandu openclaw install|uninstall` over a temp HOME, the
 * real file system and a real HTTP identity endpoint standing in for the
 * service proxy (src/openclaw-install-command.ts; docs/design/agents/
 * openclaw-plugin.md §8). Never the real ~/.openclaw.
 *
 * Pinned: install refuses and writes NOTHING when the service proxy is not
 * running (no port file, a port file others can write, another session's
 * proxy, a non-Mandu server); with it, it backs the file up, writes the
 * plugin and the route, keeps the user's other content and `$include`, and
 * a second run writes nothing; it refuses a config whose models the service
 * does not route; $OPENCLAW_CONFIG_PATH and a symlinked config are honoured;
 * the doctor facts read the route and see a moved service as stale;
 * uninstall removes exactly what install added.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:http";
import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  gatherOpenclawAttach,
  openclawAttachmentInstalled,
  openclawAttachVerb,
  runOpenclawAttach,
  type AttachDeps,
} from "../../src/openclaw-install-command.js";
import { anthropicProxyPortFile } from "../../src/openclaw-attach.js";
import { readDeclaredList } from "../../src/serve-attachments.js";
import { providersKey } from "../../src/attachment-contract.js";
import { probeIdentity } from "../../src/services/primitives.js";
import { parseJson5 } from "../../src/services/json5.js";
import { tmpDir } from "../lib/tmp-dir.js";

const SESSION = "openclaw:main";
const USER_JSON5 = `// my OpenClaw config
{
  agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6" } } },
  channels: { telegram: { botToken: "tg-secret-123" } },
  plugins: { entries: { brave: { enabled: true } } },
  $include: "./extra.json5",
}
`;
const EXTRA_JSON5 = `{ gateway: { port: 18789 } }\n`;

interface Stand {
  root: string;
  env: Record<string, string>;
  configPath: string;
  pluginDir: string;
  deps: AttachDeps;
  out: string[];
  err: string[];
}

function stand(opts: { configPathEnv?: boolean } = {}): Stand {
  const root = tmpDir("mandu-oc-install-");
  const home = join(root, "home");
  const stateDir = join(home, ".openclaw");
  mkdirSync(stateDir, { recursive: true });
  const run = join(root, "run");
  mkdirSync(run, { mode: 0o700 });
  chmodSync(run, 0o700);
  const pluginDir = join(root, "src", "interceptors", "openclaw-inspect-plugin");
  mkdirSync(pluginDir, { recursive: true });
  const configPath = opts.configPathEnv ? join(root, "elsewhere", "gw.json5") : join(stateDir, "openclaw.json");
  mkdirSync(join(configPath, ".."), { recursive: true });
  writeFileSync(configPath, USER_JSON5, { mode: 0o600 });
  writeFileSync(join(configPath, "..", "extra.json5"), EXTRA_JSON5);
  const env: Record<string, string> = { HOME: home, MANDU_HOME: join(root, "mandu"), MANDU_RUNTIME_DIR: run };
  if (opts.configPathEnv) env["OPENCLAW_CONFIG_PATH"] = configPath;
  const out: string[] = [];
  const err: string[] = [];
  let t = Date.parse("2026-10-25T10:00:00Z");
  const deps: AttachDeps = {
    pluginDir,
    uid: process.getuid?.(),
    probe: (port) => probeIdentity("127.0.0.1", port),
    out: (s) => out.push(s),
    err: (s) => err.push(s),
    now: () => new Date((t += 1000)),
  };
  return { root, env, configPath, pluginDir, deps, out, err };
}

async function identityServer(identity: Record<string, unknown>): Promise<{ server: Server; port: number }> {
  const server = createServer((req, res) => {
    if (req.url === "/_mandu/identity") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(identity));
    } else {
      res.statusCode = 404;
      res.end();
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return { server, port: (server.address() as { port: number }).port };
}

const OURS = { mandu: true, service: "anthropic-proxy", sessionKey: SESSION, arbiterSock: "/run/user/1000/mandu/instances/x/arbiter.sock" };

function writePortFile(s: Stand, port: number | string, mode = 0o600): string {
  const file = anthropicProxyPortFile(s.env["MANDU_RUNTIME_DIR"]!, SESSION);
  mkdirSync(join(file, ".."), { recursive: true, mode: 0o700 });
  writeFileSync(file, `${port}\n`, { mode });
  chmodSync(file, mode);
  return file;
}

function writePoolRecord(s: Stand, providers: string): void {
  const dir = join(anthropicProxyPortFile(s.env["MANDU_RUNTIME_DIR"]!, SESSION), "..");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(join(dir, "pool.json"), JSON.stringify({ pid: process.pid, proxyPid: null, session: SESSION, providers }) + "\n", { mode: 0o600 });
}

function backups(s: Stand): string[] {
  const dir = join(s.configPath, "..");
  return readdirSync(dir).filter((n) => n.includes(".mandu-backup-"));
}

test("refuses, writing nothing, when the service proxy is not running or is not this session's", async () => {
  const s = stand();
  const before = readFileSync(s.configPath, "utf8");

  assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 1);
  assert.match(s.err.join(""), /service proxy for openclaw:main is not running .*is absent.*mandu serve start/s);
  assert.match(s.err.join(""), /Nothing was written/);

  const wrong = await identityServer({ ...OURS, sessionKey: "openclaw:work" });
  const notMandu = await identityServer({ hello: "world" });
  try {
    writePortFile(s, wrong.port);
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 1);
    assert.match(s.err.join(""), /session openclaw:work, not openclaw:main/);
    writePortFile(s, notMandu.port);
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 1);
    assert.match(s.err.join(""), /non-Mandu server/);
    writePortFile(s, wrong.port, 0o666);
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 1);
    assert.match(s.err.join(""), /can be written by others/);
    writePortFile(s, "not-a-port");
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 1);
    assert.match(s.err.join(""), /holds no port/);
  } finally {
    wrong.server.close();
    notMandu.server.close();
  }
  assert.equal(readFileSync(s.configPath, "utf8"), before, "the config is untouched");
  assert.deepEqual(backups(s), [], "no backup either");
});

test("install: backup, plugin and route written, the user's content and $include kept; a second run writes nothing; uninstall undoes it", async () => {
  const s = stand();
  const svc = await identityServer(OURS);
  try {
    writePortFile(s, svc.port);
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 0, s.err.join(""));
    const out = s.out.join("");
    assert.match(out, /installed the OpenClaw plugin/);
    assert.match(out, new RegExp(`session openclaw:main: model calls go through Mandu's service proxy at http://127\\.0\\.0\\.1:${svc.port}`));
    assert.match(out, /anthropic \(Anthropic Messages\): .* → https:\/\/api\.anthropic\.com \(its own\)/);
    assert.match(out, /openai \(OpenAI Responses\): .*\/_mandu\/openai\/openai → https:\/\/api\.openai\.com\/v1 \(its own\)/);
    assert.match(out, /was JSON5; it is now plain JSON/);
    assert.match(out, /openclaw gateway restart/);
    assert.match(out, /policy against obvious attempts, not a boundary/);

    const [backup] = backups(s);
    assert.ok(backup, "one backup");
    assert.equal(readFileSync(join(s.configPath, "..", backup!), "utf8"), USER_JSON5, "the backup is the original, comments and all");
    assert.equal(statSync(s.configPath).mode & 0o777, 0o600, "the file's mode is kept");

    const doc = JSON.parse(readFileSync(s.configPath, "utf8"));
    assert.equal(doc.$include, "./extra.json5");
    assert.deepEqual(doc.channels, { telegram: { botToken: "tg-secret-123" } });
    assert.deepEqual(doc.plugins.entries.brave, { enabled: true });
    assert.deepEqual(doc.plugins.load.paths, [s.pluginDir]);
    const entry = doc.plugins.entries["mandu-inspect"];
    assert.equal(entry.enabled, true);
    assert.deepEqual(entry.config, {
      arbiterSock: OURS.arbiterSock, scopeId: SESSION, attachment: true, agentId: "main",
      manduPaths: [join(s.root, "mandu"), join(s.root, "run")],
    });
    assert.equal(entry.hooks, undefined, "no conversation access");
    assert.deepEqual(doc.tools.alsoAllow, ["inspect_symbol", "declassify_symbol"]);
    assert.deepEqual(doc.models.providers.anthropic, {
      baseUrl: `http://127.0.0.1:${svc.port}`, api: "anthropic-messages",
      headers: { "x-mandu-session-id": SESSION, "x-mandu-tenant": "live" }, models: [],
    });
    // Route 1: the built-in openai provider is routed too (its own wire, its
    // proxy route), so a /model switch to it mid-session still crosses Mandu.
    assert.deepEqual(doc.models.providers.openai, {
      baseUrl: `http://127.0.0.1:${svc.port}/_mandu/openai/openai`, api: "openai-responses",
      headers: { "x-mandu-session-id": SESSION, "x-mandu-tenant": "live" }, models: [],
    });
    assert.deepEqual(readDeclaredList(s.env).attachments[0]!.providers!.map((p) => [p.id, p.wire, p.upstream]),
      [["anthropic", "anthropic-messages", null], ["openai", "openai-responses", null]]);
    assert.equal(openclawAttachmentInstalled(s.env), true);

    // Idempotent: nothing written, no second backup.
    s.out.length = 0;
    const text = readFileSync(s.configPath, "utf8");
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 0);
    assert.match(s.out.join(""), /already installed .*nothing written/);
    assert.equal(readFileSync(s.configPath, "utf8"), text);
    assert.equal(backups(s).length, 1);

    // The doctor facts: healthy.
    const facts = await gatherOpenclawAttach(s.env, s.deps);
    assert.ok(facts);
    assert.equal(facts!.session, SESSION);
    assert.equal(facts!.state!.plugin, "enabled");
    assert.equal(facts!.state!.route, "service");
    assert.equal(facts!.service!.ok, true);

    // The service moved to another port: the doctor sees the route stale, and
    // a reinstall moves it (Mandu's own old route is not a foreign endpoint).
    const moved = await identityServer(OURS);
    try {
      writePortFile(s, moved.port);
      const stale = await gatherOpenclawAttach(s.env, s.deps);
      assert.equal(stale!.state!.route, "other");
      assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 0, s.err.join(""));
      assert.equal(JSON.parse(readFileSync(s.configPath, "utf8")).models.providers.anthropic.baseUrl, `http://127.0.0.1:${moved.port}`);
      assert.equal(backups(s).length, 2);
    } finally {
      moved.server.close();
    }

    // Uninstall: what install added goes; the rest stays.
    s.out.length = 0;
    assert.equal(await runOpenclawAttach("uninstall", [], s.env, s.deps), 0, s.err.join(""));
    assert.match(s.out.join(""), /removed the OpenClaw plugin/);
    const after = JSON.parse(readFileSync(s.configPath, "utf8"));
    assert.equal(after.plugins.entries["mandu-inspect"], undefined);
    assert.deepEqual(after.plugins.entries.brave, { enabled: true });
    assert.equal(after.plugins.load, undefined);
    assert.equal(after.tools, undefined);
    // The user's config had no `models` block: the provider install created
    // goes with it (it used to stay as `{api, models: []}`).
    assert.equal(after.models, undefined);
    assert.deepEqual(after.channels, { telegram: { botToken: "tg-secret-123" } });
    assert.equal(after.$include, "./extra.json5");
    assert.equal(openclawAttachmentInstalled(s.env), false);
    assert.equal(await gatherOpenclawAttach(s.env, s.deps), null, "no attachment, no doctor row");
    s.out.length = 0;
    assert.equal(await runOpenclawAttach("uninstall", [], s.env, s.deps), 0);
    assert.match(s.out.join(""), /not installed .*nothing written/);
  } finally {
    svc.server.close();
  }
});

test("Route 1, Gemini (model-wires.md §5): the built-in google provider is routed at /_mandu/google/google with its api pinned and its key kept; the doctor sees it served; uninstall gives the entry back exactly", async () => {
  const s = stand();
  const svc = await identityServer(OURS);
  try {
    writePortFile(s, svc.port);
    const user = {
      agents: { defaults: { model: { primary: "google/gemini-2.5-flash" } } },
      models: { providers: { google: { apiKey: "AIza-user-key" } } },
    };
    writeFileSync(s.configPath, JSON.stringify(user));
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 0, s.err.join(""));
    assert.match(s.out.join(""), /google \(Google Gemini\): .*\/_mandu\/google\/google → https:\/\/generativelanguage\.googleapis\.com\/v1beta \(its own\)/);
    const doc = JSON.parse(readFileSync(s.configPath, "utf8"));
    assert.deepEqual(doc.models.providers.google, {
      apiKey: "AIza-user-key",
      baseUrl: `http://127.0.0.1:${svc.port}/_mandu/google/google`, api: "google-generative-ai",
      headers: { "x-mandu-session-id": SESSION, "x-mandu-tenant": "live" }, models: [],
    });
    assert.deepEqual(readDeclaredList(s.env).attachments[0]!.providers!.map((p) => [p.id, p.wire, p.upstream]),
      [["anthropic", "anthropic-messages", null], ["openai", "openai-responses", null], ["google", "google-generative-ai", null]]);
    const facts = await gatherOpenclawAttach(s.env, s.deps);
    assert.equal(facts!.verdict!.routed, true, "every provider, google included, goes through the service proxy");
    assert.equal(await runOpenclawAttach("uninstall", [], s.env, s.deps), 0, s.err.join(""));
    const after = JSON.parse(readFileSync(s.configPath, "utf8"));
    assert.deepEqual(after.models.providers.google, user.models.providers.google, "the user's google entry, exactly");
  } finally {
    svc.server.close();
  }
});

test("Route 1, Azure OpenAI and a ChatGPT sign-in (model-wires.md §9): each routed at /_mandu/openai/<id> with its api pinned and its key kept, its real upstream recorded; the doctor sees them served; uninstall gives the entries back exactly", async () => {
  const s = stand();
  const svc = await identityServer(OURS);
  try {
    writePortFile(s, svc.port);
    const user = {
      agents: { defaults: { model: { primary: "azure/gpt-5-deploy", fallbacks: ["openai/gpt-5.5"] } } },
      models: { providers: {
        azure: { api: "azure-openai-responses", baseUrl: "https://res-mandu.openai.azure.com", apiKey: "azure-user-key", models: [{ id: "gpt-5-deploy" }] },
        openai: { api: "openai-chatgpt-responses" },
      } },
    };
    writeFileSync(s.configPath, JSON.stringify(user));
    // The pool's record: the service forwards each provider where install declares it.
    const o = { existed: true, headers: false };
    writePoolRecord(s, providersKey([
      { id: "anthropic", wire: "anthropic-messages", upstream: null, original: o },
      { id: "openai", wire: "openai-chatgpt-responses", upstream: "https://chatgpt.com/backend-api/codex", original: o },
      { id: "azure", wire: "azure-openai-responses", upstream: "https://res-mandu.openai.azure.com/openai/v1", original: o },
    ]));
    // The Gateway's own environment reads as verified and clean: this case is
    // the routing. The reader itself (no /proc on macOS: never verified, so
    // install refuses Azure there) is the next case's and the unit tests'.
    const clean = { gatewayEnv: () => ({ verified: true, set: [] }) };
    const withPool: AttachDeps = { ...s.deps, ...clean, poolRunning: () => true, serviceWaitMs: 0, hasZstd: true };
    assert.equal(await runOpenclawAttach("install", [], s.env, withPool), 0, s.err.join(""));
    const out = s.out.join("");
    assert.match(out, /azure \(Azure OpenAI Responses\): .*\/_mandu\/openai\/azure → https:\/\/res-mandu\.openai\.azure\.com\/openai\/v1/);
    assert.match(out, /openai \(OpenAI Responses \(ChatGPT sign-in\)\): .*\/_mandu\/openai\/openai → https:\/\/chatgpt\.com\/backend-api\/codex/);
    const doc = JSON.parse(readFileSync(s.configPath, "utf8"));
    assert.deepEqual(doc.models.providers.azure, {
      api: "azure-openai-responses", baseUrl: `http://127.0.0.1:${svc.port}/_mandu/openai/azure`, apiKey: "azure-user-key",
      models: [{ id: "gpt-5-deploy" }], headers: { "x-mandu-session-id": SESSION, "x-mandu-tenant": "live" },
    });
    assert.equal(doc.models.providers.openai.baseUrl, `http://127.0.0.1:${svc.port}/_mandu/openai/openai`);
    assert.equal(doc.models.providers.openai.api, "openai-chatgpt-responses");
    assert.deepEqual(readDeclaredList(s.env).attachments[0]!.providers!.map((p) => [p.id, p.wire, p.upstream]), [
      ["anthropic", "anthropic-messages", null],
      ["openai", "openai-chatgpt-responses", "https://chatgpt.com/backend-api/codex"],
      ["azure", "azure-openai-responses", "https://res-mandu.openai.azure.com/openai/v1"],
    ]);
    const facts = await gatherOpenclawAttach(s.env, { ...s.deps, ...clean });
    assert.equal(facts!.verdict!.routed, true, "every provider, Azure and ChatGPT included, goes through the service proxy");
    assert.equal(await runOpenclawAttach("uninstall", [], s.env, withPool), 0, s.err.join(""));
    const after = JSON.parse(readFileSync(s.configPath, "utf8"));
    assert.deepEqual(after.models.providers, user.models.providers, "the user's entries, exactly");
  } finally {
    svc.server.close();
  }
});

test("Route 1, Azure OpenAI fail-closed (model-wires.md §9.1): AZURE_OPENAI_BASE_URL in OpenClaw's state-dir .env, or in install's own environment, is refused by name, writing nothing", async () => {
  const s = stand();
  const svc = await identityServer(OURS);
  try {
    writePortFile(s, svc.port);
    const user = {
      agents: { defaults: { model: { primary: "azure/gpt-5-deploy" } } },
      models: { providers: { azure: { api: "azure-openai-responses", baseUrl: "https://res-mandu.openai.azure.com", models: [] } } },
    };
    const text = JSON.stringify(user);
    writeFileSync(s.configPath, text);
    const dotenv = join(s.configPath, "..", ".env");
    writeFileSync(dotenv, "# OpenClaw's own\nexport AZURE_OPENAI_BASE_URL=\"https://elsewhere.openai.azure.com/openai/v1\"\n");
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 1);
    assert.match(s.err.join(""), /azure \(OpenClaw's Azure OpenAI client sends every Azure call to AZURE_OPENAI_BASE_URL \(.*\.env\)/);
    assert.equal(readFileSync(s.configPath, "utf8"), text, "nothing was written");
    rmSync(dotenv);
    s.err.length = 0;
    assert.equal(await runOpenclawAttach("install", [], { ...s.env, AZURE_OPENAI_RESOURCE_NAME: "other" }, s.deps), 1);
    assert.match(s.err.join(""), /AZURE_OPENAI_RESOURCE_NAME \(the environment of mandu openclaw install\)/);
    assert.equal(readFileSync(s.configPath, "utf8"), text, "nothing was written");
    // Left unprotected by name: installed, the Azure entry untouched.
    s.err.length = 0;
    assert.equal(await runOpenclawAttach("install", ["--leave-unprotected", "azure"], { ...s.env, AZURE_OPENAI_RESOURCE_NAME: "other" }, s.deps), 0, s.err.join(""));
    assert.deepEqual(JSON.parse(readFileSync(s.configPath, "utf8")).models.providers.azure, user.models.providers.azure);
  } finally {
    svc.server.close();
  }
});

test("two writes in the same second keep both backups (-2), never refusing on the name", async () => {
  const s = stand();
  const fixed = new Date("2026-10-25T03:25:06Z");
  s.deps.now = () => fixed;
  const svc = await identityServer(OURS);
  const moved = await identityServer(OURS);
  try {
    writePortFile(s, svc.port);
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 0, s.err.join(""));
    writePortFile(s, moved.port);
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 0, s.err.join(""));
    assert.deepEqual(backups(s).sort(), ["openclaw.json.mandu-backup-20261025T032506Z", "openclaw.json.mandu-backup-20261025T032506Z-2"]);
  } finally {
    svc.server.close();
    moved.server.close();
  }
});

test("Route 1: a provider Mandu cannot route is refused by name, writing nothing, unless --leave-unprotected names it; an address no pool record vouches for is refused", async () => {
  const s = stand();
  const svc = await identityServer(OURS);
  try {
    writePortFile(s, svc.port);
    const google = {
      agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6", fallbacks: ["xai/grok-4"] } } },
      models: { providers: { vertex: { api: "google-vertex", baseUrl: "https://vertex.example", models: [] } } },
    };
    writeFileSync(s.configPath, JSON.stringify(google));
    const before = readFileSync(s.configPath, "utf8");
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 1);
    const err = s.err.join("");
    assert.match(err, /vertex \(OpenClaw 2026\.3\.x \(the Mandu plugin's oldest supported release\) sends Vertex AI calls to Google's own host whatever the provider's baseUrl/);
    assert.match(err, /xai \(it is not declared in models\.providers.*named by agents\.defaults\.model\.fallbacks\[0\]\)/);
    assert.match(err, /--leave-unprotected vertex,xai/);
    assert.equal(readFileSync(s.configPath, "utf8"), before, "nothing written");
    assert.deepEqual(readDeclaredList(s.env).attachments, [], "nothing declared");
    // Naming only one of them is still a refusal; naming a provider the
    // config does not have is one too.
    s.err.length = 0;
    assert.equal(await runOpenclawAttach("install", ["--leave-unprotected", "vertex"], s.env, s.deps), 1);
    assert.match(s.err.join(""), /xai/);
    assert.equal(await runOpenclawAttach("install", ["--leave-unprotected=vertex,xai,nope"], s.env, s.deps), 1);
    assert.match(s.err.join(""), /names nope, which is not a provider of your config/);
    // Both named: installed, the two left exactly as they were, and recorded.
    s.out.length = 0;
    assert.equal(await runOpenclawAttach("install", ["--leave-unprotected", "vertex", "--leave-unprotected=xai"], s.env, s.deps), 0, s.err.join(""));
    assert.match(s.out.join(""), /vertex: LEFT AS IS, NOT PROTECTED/);
    const doc = JSON.parse(readFileSync(s.configPath, "utf8"));
    assert.deepEqual(doc.models.providers.vertex, google.models.providers.vertex, "the unprotected provider is untouched");
    assert.deepEqual(readDeclaredList(s.env).attachments[0]!.unprotected, ["vertex", "xai"]);
    const facts = await gatherOpenclawAttach(s.env, s.deps);
    assert.equal(facts!.verdict!.routed, true, "a provider left on purpose is no lost route");
    assert.deepEqual(facts!.unprotected, ["vertex", "xai"]);
    assert.equal(await runOpenclawAttach("uninstall", [], s.env, s.deps), 0, s.err.join(""));
    assert.deepEqual(JSON.parse(readFileSync(s.configPath, "utf8")), google, "uninstall gives the config back exactly");

    // A provider at an address of its own, through a proxy no pool record
    // describes (an older service): nothing says where it would forward.
    const t = stand();
    writePortFile(t, svc.port);
    writeFileSync(t.configPath, JSON.stringify({
      agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6" } } },
      models: { providers: { anthropic: { baseUrl: "https://gw.corp.example", models: [] } } },
    }));
    assert.equal(await runOpenclawAttach("install", [], t.env, t.deps), 1);
    assert.match(t.err.join(""), /does not say where it forwards each provider .*anthropic .*mandu serve upgrade/);
    // A credential in a base URL is never recorded.
    t.err.length = 0;
    writeFileSync(t.configPath, JSON.stringify({
      models: { providers: { lite: { api: "openai-completions", baseUrl: "https://me:pw@lite.example/v1", models: [] } } },
    }));
    assert.equal(await runOpenclawAttach("install", [], t.env, t.deps), 1);
    assert.match(t.err.join(""), /lite \(its baseUrl carries a user or password; Mandu records base URLs only/);
    assert.deepEqual(backups(t), []);
  } finally {
    svc.server.close();
  }
});

test("Route 1, GitHub Copilot (openclaw-plugin.md §8.1): refused by name on the OpenAI wire it names, nothing written, its route never claimed; left unprotected on request, untouched", async () => {
  const s = stand();
  const svc = await identityServer(OURS);
  try {
    writePortFile(s, svc.port);
    const user = {
      agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6", fallbacks: ["github-copilot/gpt-5.4-mini"] } } },
      models: { providers: { "github-copilot": { api: "openai-completions", baseUrl: "https://api.individual.githubcopilot.com", models: [{ id: "gpt-5.4-mini", name: "GPT" }] } } },
    };
    writeFileSync(s.configPath, JSON.stringify(user));
    const before = readFileSync(s.configPath, "utf8");
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 1);
    const err = s.err.join("");
    assert.match(err, /github-copilot \(OpenClaw sends GitHub Copilot's model calls to the endpoint its Copilot sign-in answers with/);
    assert.match(err, /--leave-unprotected github-copilot/);
    assert.equal(readFileSync(s.configPath, "utf8"), before, "nothing written");
    assert.deepEqual(readDeclaredList(s.env).attachments, [], "nothing declared");
    s.out.length = 0;
    assert.equal(await runOpenclawAttach("install", ["--leave-unprotected", "github-copilot"], s.env, s.deps), 0, s.err.join(""));
    assert.match(s.out.join(""), /github-copilot: LEFT AS IS, NOT PROTECTED/);
    const doc = JSON.parse(readFileSync(s.configPath, "utf8"));
    assert.deepEqual(doc.models.providers["github-copilot"], user.models.providers["github-copilot"], "Copilot's entry is untouched: no route Mandu cannot keep");
    assert.equal(readDeclaredList(s.env).attachments[0]!.providers!.some((p) => p.id === "github-copilot"), false);
    assert.equal(await runOpenclawAttach("uninstall", [], s.env, s.deps), 0, s.err.join(""));
    assert.deepEqual(JSON.parse(readFileSync(s.configPath, "utf8")), user, "uninstall gives the config back exactly");
  } finally {
    svc.server.close();
  }
});

test("the model fence (openclaw-plugin.md §8.1): install writes OpenClaw's model allowlist when the user keeps none and records it; uninstall removes it; a user's own allowlist is left, and an unlisted openrouter model or wildcard in it is refused", async () => {
  const s = stand();
  const svc = await identityServer(OURS);
  try {
    writePortFile(s, svc.port);
    writeFileSync(s.configPath, JSON.stringify({ agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6" } } } }));
    const before = readFileSync(s.configPath, "utf8");
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 0, s.err.join(""));
    const doc = JSON.parse(readFileSync(s.configPath, "utf8"));
    assert.deepEqual(Object.keys(doc.agents.defaults.models).sort(), ["anthropic/*", "anthropic/claude-sonnet-4-6", "openai/*"]);
    assert.match(s.out.join(""), /model fence: OpenClaw's model allowlist \(agents\.defaults\.models\) names/);
    assert.deepEqual(readDeclaredList(s.env).attachments[0]!.allowlist!.sort(), ["anthropic/*", "anthropic/claude-sonnet-4-6", "openai/*"]);
    // a second install writes nothing
    s.out.length = 0;
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 0, s.err.join(""));
    assert.match(s.out.join(""), /already installed .*nothing written/);
    assert.equal(await runOpenclawAttach("uninstall", [], s.env, s.deps), 0, s.err.join(""));
    assert.deepEqual(JSON.parse(readFileSync(s.configPath, "utf8")), JSON.parse(before), "uninstall removes the fence key for key");

    // The user's own allowlist: left as it is; the declaration records an
    // empty fence (the user's allowlist is it, which the route check holds).
    const own = { agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6" }, models: { "anthropic/claude-sonnet-4-6": { alias: "sonnet" } } } } };
    writeFileSync(s.configPath, JSON.stringify(own));
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 0, s.err.join(""));
    assert.deepEqual(JSON.parse(readFileSync(s.configPath, "utf8")).agents.defaults.models, own.agents.defaults.models);
    assert.deepEqual(readDeclaredList(s.env).attachments[0]!.allowlist, []);
    assert.equal(await runOpenclawAttach("uninstall", [], s.env, s.deps), 0, s.err.join(""));
    assert.deepEqual(JSON.parse(readFileSync(s.configPath, "utf8")), own);

    // An openrouter model the user's allowlist names but the provider does
    // not list, or an openrouter wildcard: OpenClaw before 2026.3.22 would
    // send it to openrouter.ai whatever the route.
    for (const [key, want] of [["openrouter/qwen/qwen3", /list "qwen\/qwen3" in models\.providers\.openrouter\.models/], ["openrouter/*", /replace "openrouter\/\*" in agents\.defaults\.models/]] as const) {
      s.err.length = 0;
      writeFileSync(s.configPath, JSON.stringify({
        agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6" }, models: { "anthropic/*": {}, [key]: {} } } },
        models: { providers: { openrouter: { api: "openai-completions", baseUrl: "https://openrouter.ai/api/v1", apiKey: "sk-or", models: [{ id: "deepseek/x" }] } } },
      }));
      const text = readFileSync(s.configPath, "utf8");
      assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 1, key);
      assert.match(s.err.join(""), /openrouter \(OpenClaw before 2026\.3\.22 sends/);
      assert.match(s.err.join(""), want);
      assert.equal(readFileSync(s.configPath, "utf8"), text, "nothing written");
    }
  } finally {
    svc.server.close();
  }
});

test("$OPENCLAW_CONFIG_PATH is the file edited; a symlinked config is written through, the link kept", async () => {
  const s = stand({ configPathEnv: true });
  const svc = await identityServer(OURS);
  try {
    writePortFile(s, svc.port);
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 0, s.err.join(""));
    assert.equal(JSON.parse(readFileSync(s.configPath, "utf8")).plugins.entries["mandu-inspect"].enabled, true);
    assert.ok(!existsSync(join(s.env["HOME"]!, ".openclaw", "openclaw.json")), "the default path is not touched");

    const t = stand();
    writePortFile(t, svc.port);
    const real = join(t.root, "dotfiles", "openclaw.json");
    mkdirSync(join(real, ".."), { recursive: true });
    writeFileSync(real, readFileSync(t.configPath, "utf8"), { mode: 0o600 });
    writeFileSync(join(real, "..", "extra.json5"), EXTRA_JSON5);
    const link = t.configPath;
    rmSync(link);
    symlinkSync(real, link);
    assert.equal(await runOpenclawAttach("install", [], t.env, t.deps), 0, t.err.join(""));
    assert.ok(lstatSync(link).isSymbolicLink(), "the link is kept");
    assert.equal(JSON.parse(readFileSync(real, "utf8")).plugins.entries["mandu-inspect"].enabled, true);
  } finally {
    svc.server.close();
  }
});

test("--agent names the session; usage and unknown options", async () => {
  const s = stand();
  const work = await identityServer({ ...OURS, sessionKey: "openclaw:work" });
  try {
    const file = anthropicProxyPortFile(s.env["MANDU_RUNTIME_DIR"]!, "openclaw:work");
    mkdirSync(join(file, ".."), { recursive: true, mode: 0o700 });
    writeFileSync(file, `${work.port}\n`, { mode: 0o600 });
    assert.equal(await runOpenclawAttach("install", ["--agent", "Work"], s.env, s.deps), 0, s.err.join(""));
    const doc = parseJson5(readFileSync(s.configPath, "utf8")) as any;
    assert.equal(doc.models.providers.anthropic.headers["x-mandu-session-id"], "openclaw:work");
    assert.equal(doc.plugins.entries["mandu-inspect"].config.agentId, "work");
  } finally {
    work.server.close();
  }
  assert.equal(await runOpenclawAttach("install", ["--help"], s.env, s.deps), 0);
  assert.match(s.out.join(""), /usage: mandu openclaw install/);
  assert.equal(await runOpenclawAttach("install", ["--force"], s.env, s.deps), 2);
  assert.equal(await runOpenclawAttach("install", ["--agent"], s.env, s.deps), 1);
  assert.equal(await runOpenclawAttach("uninstall", ["--agent", "x"], s.env, s.deps), 2);
});

test("the CLI verbs: `mandu openclaw install|uninstall` only", () => {
  assert.equal(openclawAttachVerb(["openclaw", "install"], 0), "install");
  assert.equal(openclawAttachVerb(["--verbose", "openclaw", "uninstall", "x"], 1), "uninstall");
  assert.equal(openclawAttachVerb(["openclaw", "chat"], 0), null);
  assert.equal(openclawAttachVerb(["claude", "install"], 0), null);
  assert.equal(openclawAttachVerb(["openclaw"], 0), null);
});

test("one command (openclaw-plugin.md §3.2): install declares the session with the service and waits for its proxy; a refusal takes the declaration back; uninstall detaches it", async () => {
  const s = stand();
  const declared = (): string[] => readDeclaredList(s.env).attachments.map((a) => `${a.session}:${a.port}`);
  // A running pool, but a config the service cannot route: refused, nothing left declared.
  writeFileSync(s.configPath, `{ agents: { defaults: { model: { primary: "google/gemini-2.5-pro" } } } }`);
  const withPool: AttachDeps = { ...s.deps, poolRunning: () => true, serviceWaitMs: 0 };
  assert.equal(await runOpenclawAttach("install", [], s.env, withPool), 1);
  assert.deepEqual(declared(), [], "nothing declared by a refused install");
  // The pool does not serve it in time: refused, the declaration taken back.
  writeFileSync(s.configPath, USER_JSON5);
  assert.equal(await runOpenclawAttach("install", [], s.env, withPool), 1);
  assert.match(s.err.join(""), /it runs, but did not serve the session in time/);
  assert.deepEqual(declared(), [], "the declaration it added is taken back");

  // The pool serves the session a moment after install declares it.
  const svc = await identityServer(OURS);
  try {
    let looks = 0;
    const waiting: AttachDeps = {
      ...withPool,
      serviceWaitMs: 10_000,
      sleep: async () => {
        if (++looks !== 3) return;
        writePortFile(s, svc.port);
        // The pool's record names the providers its proxy was started with
        // (Route 1): install waits for exactly the ones it declared.
        writePoolRecord(s, providersKey(readDeclaredList(s.env).attachments[0]!.providers));
      },
    };
    s.out.length = 0;
    assert.equal(await runOpenclawAttach("install", [], s.env, waiting), 0, s.err.join(""));
    assert.match(s.out.join(""), /waiting for the Mandu service to start the proxy of openclaw:main/);
    assert.match(s.out.join(""), /a plugin session is running .*lost their guard's attestation/);
    assert.equal(declared().length, 1);
    assert.match(declared()[0]!, /^openclaw:main:\d+$/);
    // uninstall removes the route and the declaration.
    s.out.length = 0;
    assert.equal(await runOpenclawAttach("uninstall", [], s.env, s.deps), 0);
    assert.match(s.out.join(""), /detached openclaw:main from the Mandu service: its proxy stops/);
    assert.deepEqual(declared(), []);
  } finally {
    svc.server.close();
  }
});

test("a proxy already serving the session with no pool record (an older service): install declares it on that port", async () => {
  const s = stand();
  const svc = await identityServer(OURS);
  try {
    writePortFile(s, svc.port);
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 0, s.err.join(""));
    assert.deepEqual(readDeclaredList(s.env).attachments.map((a) => [a.session, a.port]), [[SESSION, svc.port]]);
  } finally {
    svc.server.close();
  }
});

/** A stand-in OpenClaw Gateway: a real process whose argv is `node
 *  …/openclaw.mjs gateway run` and whose environment is `env`, so
 *  /proc/<pid>/cmdline and environ read as a Gateway's do. */
function fakeGateway(dir: string, env: Record<string, string>): ChildProcess {
  const script = join(dir, "openclaw.mjs");
  writeFileSync(script, "setInterval(() => {}, 1000);\n");
  return spawn(process.execPath, [script, "gateway", "run", "--port", "18789"], { env, stdio: "ignore" });
}

test("Route 1, Azure OpenAI and the Gateway's own environment (model-wires.md §9.1): a running Gateway, or its systemd user unit, setting AZURE_OPENAI_BASE_URL is refused at install and lost in the doctor's verdict", { skip: existsSync("/proc/self/environ") ? false : "no /proc on this system" }, async () => {
  const s = stand();
  const svc = await identityServer(OURS);
  const children: ChildProcess[] = [];
  try {
    writePortFile(s, svc.port);
    const user = {
      agents: { defaults: { model: { primary: "azure/gpt-5-deploy" } } },
      models: { providers: { azure: { api: "azure-openai-responses", baseUrl: "https://res-mandu.openai.azure.com", apiKey: "k", models: [] } } },
    };
    const text = JSON.stringify(user);
    writeFileSync(s.configPath, text);
    const home = s.env["HOME"]!;
    const gwEnv = { PATH: process.env["PATH"] ?? "", HOME: home, OPENCLAW_CONFIG_PATH: s.configPath, AZURE_OPENAI_BASE_URL: "https://elsewhere.openai.azure.com/openai/v1" };

    // A running Gateway of this config with the variable: install refuses, naming it.
    const gw = fakeGateway(s.root, gwEnv);
    children.push(gw);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 1);
    assert.match(s.err.join(""), new RegExp(`AZURE_OPENAI_BASE_URL \\(the running Gateway's environment, pid ${gw.pid}\\)`));
    assert.ok(!s.err.join("").includes("elsewhere.openai.azure.com"), "the value is never said");
    assert.equal(readFileSync(s.configPath, "utf8"), text, "nothing was written");
    gw.kill("SIGKILL");
    await new Promise((r) => gw.once("exit", r));

    // Its systemd user unit, not running: refused too.
    const unitDir = join(home, ".config", "systemd", "user");
    mkdirSync(unitDir, { recursive: true });
    const unit = join(unitDir, "openclaw-gateway.service");
    writeFileSync(unit, `[Service]\nExecStart=/usr/bin/openclaw gateway run\nEnvironment=OPENCLAW_CONFIG_PATH=${s.configPath} AZURE_OPENAI_RESOURCE_NAME=other\n`);
    s.err.length = 0;
    assert.equal(await runOpenclawAttach("install", [], s.env, s.deps), 1);
    assert.match(s.err.join(""), /AZURE_OPENAI_RESOURCE_NAME \(.*openclaw-gateway\.service, Environment=\)/);
    rmSync(unit);

    // Nothing set: installed. Then a Gateway started with the variable: the
    // doctor's verdict (what the service's route check says too) is lost.
    const o = { existed: true, headers: false };
    writePoolRecord(s, providersKey([
      { id: "anthropic", wire: "anthropic-messages", upstream: null, original: o },
      { id: "openai", wire: "openai-responses", upstream: null, original: o },
      { id: "azure", wire: "azure-openai-responses", upstream: "https://res-mandu.openai.azure.com/openai/v1", original: o },
    ]));
    const withPool: AttachDeps = { ...s.deps, poolRunning: () => true, serviceWaitMs: 0 };
    s.err.length = 0;
    assert.equal(await runOpenclawAttach("install", [], s.env, withPool), 0, s.err.join(""));
    assert.equal((await gatherOpenclawAttach(s.env, s.deps))!.verdict!.routed, true);
    const gw2 = fakeGateway(s.root, gwEnv);
    children.push(gw2);
    await new Promise((r) => setTimeout(r, 300));
    const v = (await gatherOpenclawAttach(s.env, s.deps))!.verdict!;
    assert.equal(v.routed, false);
    assert.deepEqual(v.problems.map((p) => p.code), ["route-direct"]);
    assert.match(v.problems[0]!.detail, new RegExp(`Azure OpenAI provider azure go to AZURE_OPENAI_BASE_URL \\(the running Gateway's environment, pid ${gw2.pid}\\)`));
  } finally {
    for (const c of children) if (c.exitCode === null && c.signalCode === null) c.kill("SIGKILL");
    svc.server.close();
  }
});
