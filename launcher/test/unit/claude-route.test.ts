/**
 * claude-route.test — Claude Code's settings sources must not re-point its
 * model traffic around the model proxy (claude-route.ts; supported-agents.md
 * §2.1 "Settings files"). The overlay the launch's last `--settings`
 * carries, where it goes on the command line, what is refused, and the
 * layers read. Pure: no process, no file system (injected readers).
 *
 * PROJECT INVARIANT: Claude Code's model traffic reaches the model only
 * through the launch's proxy, or the launch does not start.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CLAUDE_CLOUD_SWITCHES, CLAUDE_ROUTE_ENV_KEYS, claudeEnvRefusal, claudeRouteArgs, claudeRouteConflicts, claudeRouteEnv,
  claudeRouteOverlay, claudeRouteRefusal, claudeSwitchOn, readClaudeRouteLayers, type ClaudeRouteLayer,
} from "../../src/claude-route.js";

// Axes: none. Routing is axis-independent and nothing here starts a service.

const PROXY = "http://127.0.0.1:41234";
const NET = "http://127.0.0.1:41235";
const ENV = {
  ANTHROPIC_BASE_URL: PROXY,
  ANTHROPIC_CUSTOM_HEADERS: "x-mandu-session-id: s1",
  HTTPS_PROXY: NET, https_proxy: NET, HTTP_PROXY: NET, http_proxy: NET,
  NO_PROXY: "127.0.0.1,localhost", no_proxy: "127.0.0.1,localhost",
};

test("the overlay re-imposes every routing variable with the launch's value, empty where unset, and the cloud switches off", () => {
  const env = claudeRouteEnv(ENV);
  for (const k of CLAUDE_ROUTE_ENV_KEYS) assert.ok(k in env, `${k} is pinned`);
  assert.equal(env["ANTHROPIC_BASE_URL"], PROXY);
  assert.equal(env["HTTPS_PROXY"], NET);
  assert.equal(env["no_proxy"], "127.0.0.1,localhost");
  assert.equal(env["ALL_PROXY"], "", "an unset proxy variable is pinned empty (no proxy)");
  assert.equal(env["all_proxy"], "");
  assert.equal(env["CLAUDE_CODE_API_BASE_URL"], "");
  for (const k of CLAUDE_CLOUD_SWITCHES) assert.equal(env[k], "0", `${k} is off`);
  assert.equal(env["CLAUDE_CODE_USE_GATEWAY"], "0");
  assert.equal(claudeRouteEnv({ ...ENV, CLAUDE_CODE_USE_GATEWAY: "1" })["CLAUDE_CODE_USE_GATEWAY"], "1", "the gateway login (it sends to ANTHROPIC_BASE_URL) is kept as launched");
});

test("switch values read as Claude Code reads them", () => {
  for (const v of ["1", "true", "TRUE", " yes ", "on"]) assert.equal(claudeSwitchOn(v), true, v);
  for (const v of [undefined, "", "0", "false", "off", "2"]) assert.equal(claudeSwitchOn(v), false, String(v));
});

test("a cloud provider switch or a Unix socket in the launch environment is refused", () => {
  assert.equal(claudeEnvRefusal(ENV), null);
  assert.equal(claudeEnvRefusal({ ...ENV, CLAUDE_CODE_USE_BEDROCK: "0" }), null);
  for (const k of CLAUDE_CLOUD_SWITCHES) assert.match(claudeEnvRefusal({ ...ENV, [k]: "true" }) ?? "", new RegExp(`refusing.*${k}`), k);
  assert.match(claudeEnvRefusal({ ...ENV, ANTHROPIC_UNIX_SOCKET: "/tmp/s.sock" }) ?? "", /ANTHROPIC_UNIX_SOCKET/);
  assert.equal(claudeEnvRefusal({ ...ENV, ANTHROPIC_UNIX_SOCKET: "" }), null);
});

const OVERLAY = claudeRouteOverlay(ENV);

function settingsValues(argv: readonly string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--settings") out.push(argv[i + 1]!);
    else if (argv[i]!.startsWith("--settings=")) out.push(argv[i]!.slice("--settings=".length));
  }
  return out;
}

test("no --settings anywhere: one is added at the head of the prefix", () => {
  const r = claudeRouteArgs(["claude", "-p", "hi"], ["--mcp-config", "{}"], OVERLAY);
  assert.ok(!("refusal" in r));
  assert.deepEqual(r.argv, ["claude", "-p", "hi"]);
  assert.deepEqual(r.prefix.slice(0, 2), ["--settings", JSON.stringify(OVERLAY)]);
  assert.deepEqual(r.prefix.slice(2), ["--mcp-config", "{}"]);
});

test("the launch's own inline --settings (the TUI pin) is merged into, never doubled", () => {
  const r = claudeRouteArgs(["claude"], ["--settings", '{"tui":"default"}', "--mcp-config", "{}"], OVERLAY);
  assert.ok(!("refusal" in r));
  assert.equal(settingsValues(r.prefix).length, 1);
  const doc = JSON.parse(settingsValues(r.prefix)[0]!) as { tui: string; env: Record<string, string> };
  assert.equal(doc.tui, "default");
  assert.equal(doc.env["ANTHROPIC_BASE_URL"], PROXY);
});

test("the run's own inline --settings (both spellings) gets the overlay, the overlay winning over its env", () => {
  const user = JSON.stringify({ model: "x", env: { ANTHROPIC_BASE_URL: "https://elsewhere.example", FOO: "1" } });
  for (const argv of [["claude", "--settings", user, "-p", "hi"], ["claude", `--settings=${user}`, "-p", "hi"]]) {
    const r = claudeRouteArgs(argv, ["--settings", '{"tui":"default"}'], OVERLAY);
    assert.ok(!("refusal" in r));
    const own = settingsValues(r.argv);
    assert.equal(own.length, 1);
    const doc = JSON.parse(own[0]!) as { model: string; env: Record<string, string> };
    assert.equal(doc.model, "x", "the run's own settings are kept");
    assert.equal(doc.env["FOO"], "1");
    assert.equal(doc.env["ANTHROPIC_BASE_URL"], PROXY, "Mandu's routing wins");
    assert.deepEqual(r.prefix, ["--settings", '{"tui":"default"}'], "the prefix is untouched (the run's last one is the one read)");
  }
});

test("only the LAST --settings of the run is the one changed; one after `--` is not an option", () => {
  const a = JSON.stringify({ a: 1 });
  const b = JSON.stringify({ b: 2 });
  const r = claudeRouteArgs(["claude", "--settings", a, "--settings", b, "--", "--settings", "/x.json"], [], OVERLAY);
  assert.ok(!("refusal" in r));
  assert.equal(r.argv[2], a);
  assert.match(r.argv[4]!, /"b":2/);
  assert.match(r.argv[4]!, /ANTHROPIC_BASE_URL/);
  assert.equal(r.argv[7], "/x.json");
});

test("the run's own --settings FILE is refused, naming the way out", () => {
  for (const argv of [["claude", "--settings", "/home/u/s.json"], ["claude", "--settings=./s.json", "-p", "x"], ["claude", "--settings", "{not json"]]) {
    const r = claudeRouteArgs(argv, [], OVERLAY);
    assert.ok("refusal" in r, argv.join(" "));
    assert.match(r.refusal, /refusing to launch Claude Code with --settings/);
    assert.match(r.refusal, /inline/);
  }
});

const layer = (scope: ClaudeRouteLayer["scope"], path: string, env: Record<string, string>): ClaudeRouteLayer =>
  ({ path, scope, text: JSON.stringify({ env }) });

test("conflicts: every routing variable a source sets to another value, exact names, switches only when on", () => {
  const c = claudeRouteConflicts([
    layer("user", "/h/.claude/settings.json", { ANTHROPIC_BASE_URL: "https://x.example", FOO: "1" }),
    layer("local", "/w/.claude/settings.local.json", { http_proxy: "http://evil:8080", ANTHROPIC_BASE_URL: PROXY }),
    layer("project", "/w/.claude/settings.json", { CLAUDE_CODE_USE_BEDROCK: "1", CLAUDE_CODE_USE_VERTEX: "0" }),
    layer("global", "/h/.claude.json", { ALL_PROXY: "socks5://evil:1080" }),
    { path: "/broken.json", scope: "user", text: "{not json" },
    { path: "/absent.json", scope: "user", text: null },
  ], OVERLAY.env);
  assert.deepEqual(c.map((x) => `${x.path}:${x.key}`), [
    "/h/.claude/settings.json:ANTHROPIC_BASE_URL",
    "/w/.claude/settings.local.json:http_proxy",
    "/w/.claude/settings.json:CLAUDE_CODE_USE_BEDROCK",
    "/h/.claude.json:ALL_PROXY",
  ]);
});

test("the launch verdict: lower sources are named in a note; a managed source, unreadable managed settings and the environment are refused", () => {
  const argv = ["claude", "-p", "hi"];
  const user = layer("user", "/h/.claude/settings.json", { ANTHROPIC_BASE_URL: "https://x.example" });
  const ok = claudeRouteRefusal(argv, ENV, [user]);
  assert.ok("notes" in ok);
  assert.equal(ok.notes.length, 1);
  assert.match(ok.notes[0]!, /\/h\/\.claude\/settings\.json sets env\.ANTHROPIC_BASE_URL; under Mandu it does not apply/);
  assert.match(ok.notes[0]!, /models: in policy\.yaml/);

  const quiet = claudeRouteRefusal(argv, ENV, [layer("user", "/h/s.json", { ANTHROPIC_BASE_URL: PROXY })]);
  assert.ok("notes" in quiet && quiet.notes.length === 0, "a source setting the launch's own value is no conflict");

  const managed = claudeRouteRefusal(argv, ENV, [user, layer("managed", "/etc/claude-code/managed-settings.json", { HTTPS_PROXY: "http://corp:3128" })]);
  assert.ok("refusal" in managed);
  assert.match(managed.refusal, /managed settings \(\/etc\/claude-code\/managed-settings\.json\) set env\.HTTPS_PROXY/);

  const unread = claudeRouteRefusal(argv, ENV, [{ path: "/Library/Managed Preferences/com.anthropic.claudecode.plist", scope: "managed", text: null, unreadable: true }]);
  assert.ok("refusal" in unread);
  assert.match(unread.refusal, /cannot read/);

  const envRef = claudeRouteRefusal(argv, { ...ENV, CLAUDE_CODE_USE_VERTEX: "1" }, []);
  assert.ok("refusal" in envRef);
  assert.match(envRef.refusal, /CLAUDE_CODE_USE_VERTEX/);

  const file = claudeRouteRefusal(["claude", "--settings", "/s.json"], ENV, []);
  assert.ok("refusal" in file);

  const managedArg = claudeRouteRefusal(["claude", "--managed-settings", JSON.stringify({ env: { ANTHROPIC_BASE_URL: "https://x" } })], ENV, []);
  assert.ok("refusal" in managedArg);
  assert.match(managedArg.refusal, /--managed-settings sets env\.ANTHROPIC_BASE_URL/);
  const managedArgOk = claudeRouteRefusal(["claude", "--managed-settings", JSON.stringify({ permissions: { deny: ["Bash"] } })], ENV, []);
  assert.ok("notes" in managedArgOk);
});

test("the layers read: the global config (in CLAUDE_CONFIG_DIR when set), then every settings source", () => {
  const seen: string[] = [];
  const readFile = (p: string): string | null => { seen.push(p); return p.endsWith("settings.local.json") ? '{"env":{"ANTHROPIC_BASE_URL":"x"}}' : null; };
  const layers = readClaudeRouteLayers({ env: {}, home: "/h", cwd: "/w", platform: "linux", locations: {}, readFile, exists: () => false });
  assert.equal(layers[0]!.path, "/h/.claude.json");
  assert.equal(layers[0]!.scope, "global");
  const paths = layers.map((l) => l.path);
  for (const p of ["/h/.claude/settings.json", "/w/.claude/settings.json", "/w/.claude/settings.local.json", "/etc/claude-code/managed-settings.json"]) {
    assert.ok(paths.includes(p), p);
  }
  assert.equal(layers.find((l) => l.path === "/w/.claude/settings.local.json")!.text, '{"env":{"ANTHROPIC_BASE_URL":"x"}}');
  const moved = readClaudeRouteLayers({ env: { CLAUDE_CONFIG_DIR: "/cfg" }, home: "/h", cwd: "/w", platform: "linux", locations: { configDir: "/cfg" }, readFile, exists: () => false });
  assert.equal(moved[0]!.path, "/cfg/.claude.json");
});
