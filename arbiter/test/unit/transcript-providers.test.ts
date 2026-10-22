/**
 * transcript-providers.test — where a past session's requests went, from
 * the agents' own settings (arbiter/policy/transcript-providers.ts;
 * confidentiality-plan-17 §3 item 4): Claude Code's settings files' `env`
 * blocks (user, under CLAUDE_CONFIG_DIR, managed, a project's) and the
 * environment; Codex's config.toml (`model_provider`, a profile's, a
 * provider's `base_url`, `openai_base_url`, under CODEX_HOME) and
 * OPENAI_BASE_URL, and a project's trusted `.codex/config.toml` layers
 * (root to the session's directory, each by its trust, as Codex 0.162
 * reads them; only ever making the answer `other`); what the
 * record names still wins; and the answer is a kind only, never a URL or
 * a provider id.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  claudeCodeSetting, codexProjectDirs, codexProjectSetting, codexRootMarkers, codexSetting, codexTrust, mergeSetting, projectProviderReader, providerSettingsOf, resolveProvider, settingsEnv, tomlStrings,
  CLAUDE_MANAGED_SETTINGS,
} from "../../policy/transcript-providers.js";
import { TranscriptScanner, claudeCodeSentTexts, providersFromEnv, type SessionMeta } from "../../policy/transcript-scan.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the provider reading is pure or read-only; no axis is read

const files = (m: Record<string, string>) => (p: string): string | null => m[p] ?? null;

test("Claude Code: Bedrock, Vertex, Foundry or a base URL off anthropic.com send its requests elsewhere; a flag that is off does not", () => {
  for (const env of [{ CLAUDE_CODE_USE_BEDROCK: "1" }, { CLAUDE_CODE_USE_VERTEX: "true" }, { CLAUDE_CODE_USE_FOUNDRY: "yes" }, { ANTHROPIC_BASE_URL: "https://llm-gateway.corp.dev" }, { ANTHROPIC_BASE_URL: "not a url" }]) {
    assert.deepEqual(claudeCodeSetting(env), { elsewhere: true }, JSON.stringify(env));
  }
  for (const env of [{}, { CLAUDE_CODE_USE_BEDROCK: "0" }, { CLAUDE_CODE_USE_VERTEX: "false" }, { CLAUDE_CODE_USE_BEDROCK: "" }, { ANTHROPIC_BASE_URL: "https://api.anthropic.com" }, { ANTHROPIC_BASE_URL: "" }]) {
    assert.equal(claudeCodeSetting(env), undefined, JSON.stringify(env));
  }
  // A look-alike domain is not Anthropic's.
  assert.deepEqual(claudeCodeSetting({ ANTHROPIC_BASE_URL: "https://anthropic.com.proxy.dev" }), { elsewhere: true });
});

test("settingsEnv: a settings file's env block as strings; not an object reads as nothing", () => {
  assert.deepEqual(settingsEnv(JSON.stringify({ env: { CLAUDE_CODE_USE_BEDROCK: 1, AWS_REGION: "us-east-1", X: true, Y: { no: 1 } } })), { CLAUDE_CODE_USE_BEDROCK: "1", AWS_REGION: "us-east-1", X: "true" });
  assert.deepEqual(settingsEnv(JSON.stringify({ model: "opus" })), {});
  assert.equal(settingsEnv("{ not json"), null);
  assert.equal(settingsEnv("[1]"), null);
});

test("Codex: another model_provider is other unless its base_url is OpenAI's; a profile's provider counts; OPENAI_BASE_URL or an openai table elsewhere", () => {
  assert.equal(codexSetting(null, {}), undefined, "no config: OpenAI, its own");
  assert.equal(codexSetting('model = "gpt-5"\nmodel_provider = "openai"\n', {}), undefined);
  assert.deepEqual(codexSetting('model_provider = "azure"\n\n[model_providers.azure]\nname = "Azure"\nbase_url = "https://corp.openai.azure.com/openai"\n', {}), { pick: "other" });
  assert.deepEqual(codexSetting("model_provider = 'ollama'\n", {}), { pick: "other" }, "a provider with no base_url here");
  assert.deepEqual(codexSetting('model_provider = "mine"\n[model_providers.mine]\nbase_url = "https://api.openai.com/v1"  # direct\n', {}), { pick: "openai" });
  assert.deepEqual(codexSetting('profile = "work"\n[profiles.work]\nmodel_provider = "bedrock"\n', {}), { pick: "other" }, "the active profile's provider");
  assert.deepEqual(codexSetting('model_providers.gw.base_url = "https://gw.corp.dev/v1"\nmodel_provider = "gw"\n', {}), { pick: "other" }, "a dotted key");
  assert.deepEqual(codexSetting(null, { OPENAI_BASE_URL: "https://llm.corp.internal/v1" }), { elsewhere: true });
  assert.deepEqual(codexSetting('[model_providers.openai]\nbase_url = "https://gw.corp.dev"\n', {}), { elsewhere: true });
  // An array table's pairs are no provider's.
  assert.equal(codexSetting('[[notify]]\nmodel_provider = "x"\n', {}), undefined);
  assert.equal(tomlStrings('a = "x\\"y"\n[t.u]\nb = \'lit\'\nc = 3\n').get("t.u.b"), "lit");
});

test("resolveProvider: the record wins where it names a provider; the settings pick for a record that names none; elsewhere makes the agent's own other", () => {
  assert.equal(resolveProvider("claude-code", undefined), "anthropic");
  assert.equal(resolveProvider("claude-code", "anthropic", { elsewhere: true }), "other", "claude-* names a model, not where it was served");
  assert.equal(resolveProvider("claude-code", "other"), "other");
  assert.equal(resolveProvider("codex", "openai", { pick: "other" }), "openai", "the session's record over today's config");
  assert.equal(resolveProvider("codex", undefined, { pick: "other" }), "other");
  assert.equal(resolveProvider("codex", "openai", { elsewhere: true }), "other");
  assert.equal(resolveProvider("codex", "other", { pick: "openai" }), "other");
  assert.equal(resolveProvider("opencode", "anthropic", { elsewhere: true }), "anthropic", "another agent's own is none");
  assert.equal(resolveProvider("goose", undefined), "other");
  assert.equal(resolveProvider("claude-code", undefined, undefined, { elsewhere: true }), "other", "any of the settings");
  assert.deepEqual(mergeSetting({ pick: "openai" }, { pick: "other", elsewhere: true }), { pick: "openai", elsewhere: true });
  assert.equal(mergeSetting(undefined, undefined), undefined);
});

test("providerSettingsOf: the user's settings.json (under CLAUDE_CONFIG_DIR when set), the managed settings for this HOME only, config.toml under CODEX_HOME", () => {
  const home = "/home/u";
  const bedrock = JSON.stringify({ env: { CLAUDE_CODE_USE_BEDROCK: "1", AWS_REGION: "us-west-2" } });
  assert.deepEqual(providerSettingsOf({ home, env: {}, read: files({ "/home/u/.claude/settings.json": bedrock }) }), { "claude-code": { elsewhere: true } });
  assert.deepEqual(providerSettingsOf({ home, env: { CLAUDE_CONFIG_DIR: "/cfg/claude" }, read: files({ "/home/u/.claude/settings.json": bedrock }) }), {}, "the other directory is the one read");
  assert.deepEqual(providerSettingsOf({ home, env: { CLAUDE_CONFIG_DIR: "/cfg/claude" }, read: files({ "/cfg/claude/settings.json": bedrock }) }), { "claude-code": { elsewhere: true } });
  const managed = files({ [CLAUDE_MANAGED_SETTINGS[0]!]: JSON.stringify({ env: { ANTHROPIC_BASE_URL: "https://gw.corp.dev" } }) });
  assert.deepEqual(providerSettingsOf({ home, env: {}, read: managed }), {}, "another HOME: no managed settings");
  assert.deepEqual(providerSettingsOf({ home, env: {}, system: true, read: managed }), { "claude-code": { elsewhere: true } });
  assert.deepEqual(providerSettingsOf({ home, env: { CODEX_HOME: "/cx" }, read: files({ "/cx/config.toml": 'model_provider = "azure"\n' }) }), { codex: { pick: "other" } });
  assert.deepEqual(providerSettingsOf({ home, env: { ANTHROPIC_BASE_URL: "https://gw.corp.dev" }, read: files({}) }), { "claude-code": { elsewhere: true } }, "the environment too");
  // A settings file that does not parse, or says nothing of the provider, gives nothing.
  assert.deepEqual(providerSettingsOf({ home, env: {}, read: files({ "/home/u/.claude/settings.json": "{", "/home/u/.codex/config.toml": "[[[" }) }), {});
});

test("providerSettingsOf over real files: only kinds come back, never a URL, a host or a provider id", () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-providers-"));
  try {
    mkdirSync(join(tmp, ".claude"), { recursive: true });
    mkdirSync(join(tmp, ".codex"), { recursive: true });
    writeFileSync(join(tmp, ".claude", "settings.json"), JSON.stringify({ env: { ANTHROPIC_BASE_URL: "https://secret-gateway.corp-xyz.dev/v1?team=blue" } }));
    writeFileSync(join(tmp, ".codex", "config.toml"), 'model_provider = "corpgw"\n[model_providers.corpgw]\nbase_url = "https://secret-gateway.corp-xyz.dev/openai"\n');
    mkdirSync(join(tmp, ".claude", "settings.d"), { recursive: true });
    const got = providerSettingsOf({ home: tmp, env: {} });
    assert.deepEqual(got, { "claude-code": { elsewhere: true }, codex: { pick: "other" } });
    const text = JSON.stringify(got);
    for (const word of ["secret-gateway", "corp-xyz", "corpgw", "blue", "http"]) assert.ok(!text.includes(word), `"${word}" is not in the answer`);
    // A directory where a settings file would be is no file.
    rmSync(join(tmp, ".claude", "settings.json"));
    mkdirSync(join(tmp, ".claude", "settings.json"));
    assert.deepEqual(providerSettingsOf({ home: tmp, env: {} }), { codex: { pick: "other" } });
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("projectProviderReader: a Claude Code session's project settings, each folder read once; other agents and relative folders read nothing", () => {
  const reads: string[] = [];
  const read = (p: string): string | null => {
    reads.push(p);
    return p === "/w/app/.claude/settings.local.json" ? JSON.stringify({ env: { CLAUDE_CODE_USE_VERTEX: "1" } }) : null;
  };
  const of = projectProviderReader({ read });
  assert.deepEqual(of("claude-code", "/w/app"), { elsewhere: true });
  assert.deepEqual(of("claude-code", "/w/app"), { elsewhere: true });
  assert.equal(of("claude-code", "/w/other"), undefined);
  assert.equal(of("codex", "/w/app"), undefined, "no Codex directory given: Codex's layers are not read");
  assert.equal(of("claude-code", "rel/dir"), undefined);
  assert.equal(of("claude-code", undefined), undefined);
  assert.equal(of("opencode", "/w/app"), undefined);
  assert.deepEqual(reads, ["/w/app/.claude/settings.json", "/w/app/.claude/settings.local.json", "/w/other/.claude/settings.json", "/w/other/.claude/settings.local.json"]);
});

test("Codex: openai_base_url in the user's config.toml sends the built-in provider's requests elsewhere (Codex 0.162 follows it)", () => {
  assert.deepEqual(codexSetting('openai_base_url = "https://gw.corp.dev/v1"\n', {}), { elsewhere: true });
  assert.equal(codexSetting('openai_base_url = "https://api.openai.com/v1"\n', {}), undefined);
});

test("codexRootMarkers and codexTrust: the user's project_root_markers (else .git) and each project's trust_level", () => {
  assert.deepEqual(codexRootMarkers(null), [".git"]);
  assert.deepEqual(codexRootMarkers('project_root_markers = [".hg", \'.jj\']  # mine\n'), [".hg", ".jj"]);
  assert.deepEqual(codexRootMarkers("project_root_markers = []\n"), [], "none: the session's directory is the root");
  assert.deepEqual(codexRootMarkers("project_root_markers = [1]\n"), [".git"], "not names: Codex's default");
  assert.deepEqual([...codexTrust('[projects."/w/app"]\ntrust_level = "trusted"\n[projects."/w/x.y"]\ntrust_level = "untrusted"\n')], [["/w/app", "trusted"], ["/w/x.y", "untrusted"]]);
});

test("codexProjectDirs: from the root (the nearest marker up) to the session's directory, each layer by its own trust, else the root's; no marker, the directory alone", () => {
  const marks = new Set(["/w/app/.git"]);
  const exists = (p: string): boolean => marks.has(p);
  const trust = (o: Record<string, string>) => new Map(Object.entries(o));
  assert.deepEqual(codexProjectDirs("/w/app/svc/api", [".git"], trust({ "/w/app": "trusted" }), exists), ["/w/app", "/w/app/svc", "/w/app/svc/api"]);
  // Probed on Codex 0.162: a layer's own entry wins over the root's, either way.
  assert.deepEqual(codexProjectDirs("/w/app/svc", [".git"], trust({ "/w/app": "trusted", "/w/app/svc": "untrusted" }), exists), ["/w/app"]);
  assert.deepEqual(codexProjectDirs("/w/app/svc", [".git"], trust({ "/w/app/svc": "trusted" }), exists), ["/w/app/svc"]);
  assert.deepEqual(codexProjectDirs("/w/app/svc", [".git"], trust({}), exists), [], "an untrusted project: no layer");
  assert.deepEqual(codexProjectDirs("/w/app/svc", [".git"], trust({ "/w": "trusted" }), exists), [], "a trusted folder above the root does not reach into it");
  assert.deepEqual(codexProjectDirs("/t/one/two", [".git"], trust({ "/t/one": "trusted", "/t/one/two": "trusted" }), exists), ["/t/one/two"], "no marker: the directory alone");
  assert.deepEqual(codexProjectDirs("/w/app/svc", [], trust({ "/w/app/svc": "trusted" }), exists), ["/w/app/svc"]);
});

test("codexProjectSetting: trusted layers that turn the user's setting away from OpenAI count (another provider as a pick, a base URL as elsewhere); never OpenAI; the closer layer wins", () => {
  assert.deepEqual(codexProjectSetting(null, ['model_provider = "azure"\n']), { pick: "other" }, "a pick: a record that names its provider still wins");
  assert.deepEqual(codexProjectSetting(null, ['openai_base_url = "https://gw.corp.dev/v1"\n']), { elsewhere: true });
  assert.equal(codexProjectSetting(null, ['model = "gpt-5"\n']), undefined, "no provider key: nothing");
  assert.equal(codexProjectSetting(null, ['model_provider = "azure"\n', 'model_provider = "openai"\n']), undefined, "the closer layer puts it back");
  assert.equal(codexProjectSetting('model_provider = "azure"\n', ['model_provider = "openai"\n']), undefined, "a project never makes it OpenAI");
  assert.equal(codexProjectSetting('model_provider = "azure"\n', ['model = "x"\n']), undefined, "the user's own pick is the user's setting's");
  assert.equal(codexProjectSetting('model_provider = "azure"\n', ['model_provider = "labgw"\n']), undefined, "another provider off OpenAI over the user's: the same answer");
  assert.deepEqual(codexProjectSetting('model_provider = "azure"\n', ['openai_base_url = "https://gw.corp.dev/v1"\n']), { elsewhere: true });
  // A project's profile naming one of the user's profiles.
  assert.deepEqual(codexProjectSetting('[profiles.work]\nmodel_provider = "bedrock"\n', ['profile = "work"\n']), { pick: "other" });
  assert.equal(codexProjectSetting(null, ['model_provider = "mine"\n[model_providers.mine]\nbase_url = "https://api.openai.com/v1"\n']), undefined, "OpenAI's own URL");
});

test("projectProviderReader: a Codex session's trusted project layers from the user's config.toml under the Codex directory, read once per directory", () => {
  const reads: string[] = [];
  const fs: Record<string, string> = {
    "/cx/config.toml": '[projects."/w/app"]\ntrust_level = "trusted"\n[projects."/w/lab"]\ntrust_level = "untrusted"\n',
    "/w/app/.codex/config.toml": 'model_provider = "azure"\n[model_providers.azure]\nbase_url = "https://corp.openai.azure.com/openai"\n',
    "/w/lab/.codex/config.toml": 'model_provider = "azure"\n',
    "/home/u/.codex/config.toml": "",
  };
  const read = (p: string): string | null => { reads.push(p); return fs[p] ?? null; };
  const exists = (p: string): boolean => p === "/w/app/.git" || p === "/w/lab/.git";
  const of = projectProviderReader({ read, exists, codexDir: "/cx" });
  assert.deepEqual(of("codex", "/w/app/svc"), { pick: "other" });
  assert.deepEqual(of("codex", "/w/app/svc"), { pick: "other" });
  assert.equal(of("codex", "/w/lab"), undefined, "an untrusted project's layer is not Codex's");
  assert.equal(of("codex", "/elsewhere"), undefined);
  assert.equal(of("claude-code", "/w/app/svc"), undefined, "a Claude Code session reads Claude Code's files");
  assert.deepEqual(reads.filter((p) => p.endsWith("config.toml")), ["/cx/config.toml", "/w/app/.codex/config.toml", "/w/app/svc/.codex/config.toml"], "the user's config once, then only trusted layers");
  // The user's own directory is no project layer; no trusted project reads none.
  const home = projectProviderReader({ read: (p) => (p === "/home/u/.codex/config.toml" ? '[projects."/home/u"]\ntrust_level = "trusted"\nmodel_provider = "openai"\n' : null), exists: () => false, codexDir: "/home/u/.codex" });
  assert.equal(home("codex", "/home/u"), undefined);
  const none: string[] = [];
  const quiet = projectProviderReader({ read: (p) => { none.push(p); return null; }, codexDir: "/cx" });
  assert.equal(quiet("codex", "/w/app"), undefined);
  assert.deepEqual(none, ["/cx/config.toml"]);
});

test("projectProviderReader over real files: a trusted repository's .codex/config.toml makes a session's OpenAI other; an untrusted one's does not", () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-cx-proj-"));
  try {
    const cx = join(tmp, ".codex");
    mkdirSync(cx, { recursive: true });
    for (const p of ["trusted-repo", "untrusted-repo"]) {
      mkdirSync(join(tmp, p, ".git"), { recursive: true });
      mkdirSync(join(tmp, p, ".codex"), { recursive: true });
      writeFileSync(join(tmp, p, ".codex", "config.toml"), 'model_provider = "corpgw"\nopenai_base_url = "https://secret-gateway.corp.dev/v1"\n[model_providers.corpgw]\nbase_url = "https://secret-gateway.corp.dev/v1"\n');
    }
    mkdirSync(join(tmp, "trusted-repo", "pkg"), { recursive: true });
    writeFileSync(join(cx, "config.toml"), `[projects."${join(tmp, "trusted-repo")}"]\ntrust_level = "trusted"\n`);
    const of = projectProviderReader({ codexDir: cx });
    assert.deepEqual(of("codex", join(tmp, "trusted-repo", "pkg")), { pick: "other", elsewhere: true });
    assert.equal(of("codex", join(tmp, "untrusted-repo")), undefined);
    assert.equal(resolveProvider("codex", "openai", of("codex", join(tmp, "trusted-repo")), undefined), "other");
    assert.equal(resolveProvider("codex", undefined, of("codex", join(tmp, "trusted-repo")), undefined), "other");
    assert.equal(resolveProvider("codex", "openai", of("codex", join(tmp, "untrusted-repo")), undefined), "openai");
    assert.equal(resolveProvider("codex", undefined, of("codex", join(tmp, "untrusted-repo")), undefined), "openai");
    assert.ok(!JSON.stringify(of("codex", join(tmp, "trusted-repo"))).includes("gateway"), "a kind only");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("the scanner: a Bedrock setting makes a claude-* session's example say other; a project's setting only its own sessions'", () => {
  const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8Nb4C`;
  const recs = (cwd: string) => [
    { type: "assistant", cwd, timestamp: "2026-10-01T10:00:00Z", message: { model: "claude-opus-4-1", content: [{ type: "tool_use", id: "t1", name: "Bash", input: { command: "cat .env" } }] } },
    { type: "user", cwd, timestamp: "2026-10-01T10:00:01Z", message: { content: [{ type: "tool_result", tool_use_id: "t1", content: `KEY=${STRIPE}` }] } },
  ];
  const providerOf = (s: TranscriptScanner): string | undefined => s.result().findings[0]?.examples?.[0]?.provider;
  const add = (s: TranscriptScanner, cwd: string, file: string) => {
    const meta: SessionMeta = {};
    const texts = [...claudeCodeSentTexts(recs(cwd), meta)];
    s.addSession("claude-code", file, texts, meta);
  };
  const plain = new TranscriptScanner({ home: "/home/u" });
  add(plain, "/home/u/shop", "/a.jsonl");
  assert.equal(providerOf(plain), "anthropic");
  const bedrock = new TranscriptScanner({ home: "/home/u", providers: { "claude-code": { elsewhere: true } } });
  add(bedrock, "/home/u/shop", "/a.jsonl");
  assert.equal(providerOf(bedrock), "other");
  const project = new TranscriptScanner({ home: "/home/u", projectProviders: (_a, cwd) => (cwd === "/home/u/vertex-app" ? { elsewhere: true } : undefined) });
  add(project, "/home/u/vertex-app", "/b.jsonl");
  assert.equal(providerOf(project), "other");
  const other = new TranscriptScanner({ home: "/home/u", projectProviders: (_a, cwd) => (cwd === "/home/u/vertex-app" ? { elsewhere: true } : undefined) });
  add(other, "/home/u/shop", "/c.jsonl");
  assert.equal(providerOf(other), "anthropic");
  // providersFromEnv is the environment's part of the same settings.
  assert.deepEqual(providersFromEnv({ CLAUDE_CODE_USE_BEDROCK: "1", OPENAI_BASE_URL: "https://gw.corp.dev" }), { "claude-code": { elsewhere: true }, codex: { elsewhere: true } });
});
