/**
 * opencode-global-code.test — the user's OWN OpenCode code extensions under
 * Mandu (src/opencode-global-code.ts; supported-agents.md §2.3 item 12;
 * maintainer decision 2026-10-07 "Off + Approvals"): which files count, per
 * generation; the launch decision for both origins on both generations; the
 * OpenCode 1 switch (`OPENCODE_PURE=1`) and run file, the OpenCode 2 config
 * directory and run file, through writeAgentConfig; the write-protect
 * entries for the user's OpenCode settings files; OpenCode 1's `$schema`
 * edit made before the launch.
 *
 * WHY: a plugin runs inside OpenCode and writes the model request itself
 * (measured with a project plugin, item 11: a pinned reader's raw output
 * and another agent's credential store in the system prompt). The user's
 * global folder and an npm plugin a global `opencode.json` names are the same
 * code from another place, and an injected agent could plant one there for
 * the next session. tests/sandbox/guard/opencode-project-plugins.test.ts is
 * the end-to-end form on the real binaries.
 *
 * Axes: none stated by a launch here; the rule's axis gate (confidentiality
 * ON) is passed explicitly (`effectiveAxes`) where writeAgentConfig reads it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  addOpencodeSchema, findOpencodeGlobalCode, globalOpencodeConfigDocs, globalOpencodeDirs, OPENCODE_GLOBAL_PLUGINS_ENV,
  opencodeCodeDecision, opencodeGlobalCodeAllowed, opencodeGlobalCodeNotice, opencodeGlobalCodeOptInWarning,
  opencodeGlobalToolsRefusal, opencodeSettingFiles, opencodeV1PluginSplitRefusal, opencodeV1Pure, withOpencodeSchema,
} from "../../src/opencode-global-code.js";
import { OPENCODE_PROJECT_PLUGINS_ENV, opencodeProjectCodeRefusal, userOpencodeCodeDirs, type ProjectCodeFinding } from "../../src/opencode-project-code.js";
import { OPENCODE_RUN_FILE, opencodeRoutingContent, writeAgentConfig } from "../../src/services/agent-config.js";
import { laterRunFiles, WRITE_PROTECT_LABELS, writeProtectList } from "../../src/write-protect.js";
import { Layout } from "../../src/services/layout.js";
import type { LaunchPlan, Ullm } from "../../src/types.js";

interface Tree { root: string; home: string; repo: string; gdir: string }

/** A home whose global OpenCode dir holds a plugin file, a custom tool and an
 *  `opencode.json` naming an npm plugin, a `~/.opencode` plugin, and a clean
 *  repository under the home. */
function tree(opts: { tool?: boolean } = {}): Tree {
  const root = mkdtempSync(join(tmpdir(), "mdu-oc-globalcode-"));
  const home = join(root, "home");
  const gdir = join(home, ".config", "opencode");
  const repo = join(home, "work", "repo");
  for (const d of [join(gdir, "plugin"), join(home, ".opencode", "plugins"), join(repo, ".git")]) mkdirSync(d, { recursive: true });
  writeFileSync(join(gdir, "plugin", "mine.ts"), "export const Mine = async () => ({})\n");
  writeFileSync(join(gdir, "opencode.json"), JSON.stringify({ model: "anthropic/claude-sonnet-4-5", plugin: ["oh-my-opencode"] }));
  writeFileSync(join(home, ".opencode", "plugins", "home.js"), "export const Home = async () => ({})\n");
  if (opts.tool) {
    mkdirSync(join(gdir, "tool"), { recursive: true });
    writeFileSync(join(gdir, "tool", "mytool.ts"), "export default {}\n");
  }
  return { root, home, repo, gdir };
}

const ENV = (t: Tree): Record<string, string> => ({ HOME: t.home, XDG_CONFIG_HOME: join(t.home, ".config") });

test("the opt-in: only an explicit yes", () => {
  for (const v of ["1", "true", "TRUE", "yes", "on", " 1 "]) assert.equal(opencodeGlobalCodeAllowed({ [OPENCODE_GLOBAL_PLUGINS_ENV]: v }), true, v);
  for (const v of [undefined, "", "0", "false", "no", "off", "please"]) assert.equal(opencodeGlobalCodeAllowed({ [OPENCODE_GLOBAL_PLUGINS_ENV]: v }), false, String(v));
  assert.equal(OPENCODE_GLOBAL_PLUGINS_ENV, "MANDU_OPENCODE_GLOBAL_PLUGINS");
});

test("the user's directories per generation: 1.x reads XDG whatever OPENCODE_CONFIG_DIR says (that one is extra); 2.x's global is OPENCODE_CONFIG_DIR, else XDG", () => {
  assert.deepEqual(globalOpencodeDirs(1, { HOME: "/h" }), ["/h/.config/opencode", "/h/.opencode"]);
  assert.deepEqual(globalOpencodeDirs(1, { HOME: "/h", OPENCODE_CONFIG_DIR: "/oc" }), ["/h/.config/opencode", "/oc", "/h/.opencode"]);
  assert.deepEqual(globalOpencodeDirs(2, { HOME: "/h", OPENCODE_CONFIG_DIR: "/oc" }), ["/oc", "/h/.opencode"]);
  assert.deepEqual(globalOpencodeDirs(2, { HOME: "/h", XDG_CONFIG_HOME: "/x" }), ["/x/opencode", "/h/.opencode"]);
  const d1 = globalOpencodeConfigDocs(1, { HOME: "/h", OPENCODE_CONFIG: "/c/my.json", OPENCODE_TUI_CONFIG: "/c/tui.json" });
  for (const p of ["/h/.config/opencode/config.json", "/h/.config/opencode/opencode.json", "/h/.config/opencode/tui.json", "/h/.opencode/opencode.jsonc", "/c/my.json", "/c/tui.json"]) assert.ok(d1.includes(p), p);
  const d2 = globalOpencodeConfigDocs(2, { HOME: "/h", OPENCODE_TUI_CONFIG: "/c/tui.json" });
  assert.ok(!d2.some((p) => p.endsWith("tui.json") || p.endsWith("config.json")), "2.x: opencode.json(c) only");
});

test("findOpencodeGlobalCode: modules of the user's plugin and tool folders, documents naming plugins (npm ones too), the inline content; never a project's", () => {
  const t = tree({ tool: true });
  try {
    mkdirSync(join(t.repo, ".opencode", "plugin"), { recursive: true });
    writeFileSync(join(t.repo, ".opencode", "plugin", "proj.ts"), "x");
    writeFileSync(join(t.gdir, "plugin", "README.md"), "not a module");
    writeFileSync(join(t.gdir, "tui.json"), JSON.stringify({ plugin: ["a-tui-plugin"] }));
    const rel = (fs: ProjectCodeFinding[]): string[] => fs.map((f) => `${f.kind}:${f.path.slice(t.home.length)}`).sort();
    assert.deepEqual(rel(findOpencodeGlobalCode(1, ENV(t))), [
      "config:/.config/opencode/opencode.json", "config:/.config/opencode/tui.json", "plugin:/.config/opencode/plugin/mine.ts",
      "plugin:/.opencode/plugins/home.js", "tool:/.config/opencode/tool/mytool.ts",
    ]);
    assert.deepEqual(rel(findOpencodeGlobalCode(2, ENV(t))), [
      "config:/.config/opencode/opencode.json", "plugin:/.config/opencode/plugin/mine.ts",
      "plugin:/.opencode/plugins/home.js", "tool:/.config/opencode/tool/mytool.ts",
    ], "2.x: no tui.json");
    const inline = findOpencodeGlobalCode(2, { ...ENV(t), OPENCODE_CONFIG_CONTENT: JSON.stringify({ plugin: ["x"] }) });
    assert.ok(inline.some((f) => f.path === "OPENCODE_CONFIG_CONTENT" && f.kind === "config"));
    const empty = findOpencodeGlobalCode(2, { ...ENV(t), OPENCODE_CONFIG_CONTENT: JSON.stringify({ plugin: [] }) });
    assert.ok(!empty.some((f) => f.path === "OPENCODE_CONFIG_CONTENT"), "an empty list names none");
    // A user document Mandu cannot parse counts.
    writeFileSync(join(t.gdir, "opencode.jsonc"), "{ nope");
    assert.ok(findOpencodeGlobalCode(1, ENV(t)).some((f) => f.path === join(t.gdir, "opencode.jsonc")));
  } finally {
    rmSync(t.root, { recursive: true, force: true });
  }
});

test("the launch decision, both origins x both generations x both opt-ins", () => {
  const gPlugin: ProjectCodeFinding = { path: "/h/.config/opencode/opencode.json", kind: "config" };
  const gTool: ProjectCodeFinding = { path: "/h/.config/opencode/tool/t.ts", kind: "tool" };
  const pPlugin: ProjectCodeFinding = { path: "/w/.opencode/plugin/p.ts", kind: "plugin" };
  const pTool: ProjectCodeFinding = { path: "/w/.opencode/tool/t.ts", kind: "tool" };
  const d = (generation: 1 | 2, project: ProjectCodeFinding[], global: ProjectCodeFinding[], projectAllowed = false, globalAllowed = false) =>
    opencodeCodeDecision({ generation, mode: "secrets", project, global, projectAllowed, globalAllowed, projectRefusal: opencodeProjectCodeRefusal });
  // OpenCode 2: never refused; the opt-in warns.
  assert.equal(d(2, [pPlugin, pTool], [gPlugin, gTool]).refusal, null);
  assert.match(d(2, [], [gPlugin], false, true).warnings.join("\n"), /^WARNING: MANDU_OPENCODE_GLOBAL_PLUGINS=1 .*opencode\.json \(names a plugin\)/);
  // OpenCode 1, the switch on: plugins of both origins are left out; tools refuse.
  assert.equal(d(1, [pPlugin], [gPlugin]).refusal, null, "1.x: plugins are left out by OPENCODE_PURE, not refused");
  assert.match(d(1, [], [gPlugin, gTool]).refusal ?? "", /^refusing OpenCode in mode secrets: your OpenCode folders hold a custom tool.*tool\/t\.ts.*MANDU_OPENCODE_GLOBAL_PLUGINS=1/);
  assert.doesNotMatch(d(1, [], [gPlugin, gTool]).refusal ?? "", /opencode\.json/, "only the tool is named");
  assert.match(d(1, [pPlugin, pTool], []).refusal ?? "", /this project brings OpenCode code.*\/w\/\.opencode\/tool\/t\.ts/);
  assert.doesNotMatch(d(1, [pPlugin, pTool], []).refusal ?? "", /p\.ts/, "the project's plugin is left out, only its tool refuses");
  // OpenCode 1, the global opt-in alone: the switch is off; a project's code refuses (item 11).
  const g = d(1, [pPlugin], [gPlugin, gTool], false, true);
  assert.match(g.refusal ?? "", /this project brings OpenCode code.*p\.ts/);
  assert.equal(g.warnings.length, 1);
  assert.equal(d(1, [], [gPlugin, gTool], false, true).refusal, null);
  // OpenCode 1, the project opt-in alone: the user's own plugins refuse (all or none).
  assert.match(d(1, [pPlugin], [gPlugin], true, false).refusal ?? "", /OpenCode 1 can only run every plugin or none.*opencode\.json.*MANDU_OPENCODE_GLOBAL_PLUGINS=1/);
  assert.match(d(1, [pPlugin], [gTool], true, false).refusal ?? "", /custom tool/);
  assert.equal(d(1, [pPlugin], [], true, false).refusal, null);
  // Both opt-ins: nothing refused.
  assert.equal(d(1, [pPlugin, pTool], [gPlugin, gTool], true, true).refusal, null);
  // The switch: exactly when no plugin may run.
  assert.equal(opencodeV1Pure(false, false), true);
  assert.equal(opencodeV1Pure(true, false), false);
  assert.equal(opencodeV1Pure(false, true), false);
});

test("the wording names each file, why, and the opt-in", () => {
  const f: ProjectCodeFinding[] = [{ path: "/h/.config/opencode/plugin/x.ts", kind: "plugin" }, { path: "OPENCODE_CONFIG_CONTENT", kind: "config" }];
  assert.match(opencodeGlobalCodeNotice(f), /^OpenCode — your own OpenCode plugins and custom tools are left out of this session \(.*not checked\): \/h\/\.config\/opencode\/plugin\/x\.ts, OPENCODE_CONFIG_CONTENT \(names a plugin\)\. MANDU_OPENCODE_GLOBAL_PLUGINS=1 runs them unchecked\.$/);
  assert.match(opencodeGlobalCodeOptInWarning(f), /not checked/);
  assert.match(opencodeGlobalToolsRefusal("secrets", f), /OpenCode 2/);
  assert.match(opencodeV1PluginSplitRefusal("full", f), new RegExp(`^refusing OpenCode in mode full: ${OPENCODE_PROJECT_PLUGINS_ENV}=1`));
});

const ULLM: Ullm = { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" };

function plan(gen: 1 | 2, cwd: string, confidentiality: boolean | undefined): LaunchPlan {
  return {
    target: "opencode", argv: gen === 2 ? ["opencode2", "run", "--standalone", "hi"] : ["opencode", "run", "hi"],
    agentVersion: gen === 2 ? "opencode v2.0.23" : "1.18.13", scopeId: "sid-1", tenant: "live",
    arbiterSock: "/run/mandu/arbiter.sock", arbiterSockMode: "pinned", arbiterRuntimeBase: "/tmp/mandu",
    eventDir: "/e", cwd, humanCwd: cwd, noContextProxy: true, fsSync: false,
    basePath: "/usr/bin", proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false }, execWrapCmds: [],
    ullm: ULLM, noScope: false, writeMcp: false, bestEffort: false, replyFilter: true,
    ...(confidentiality === undefined ? {} : { effectiveAxes: { confidentiality, integrity: false } }),
  };
}

test("writeAgentConfig (1.x): confidentiality ON or unknown sets OPENCODE_PURE=1, drops the user's plugin lists from the run file and inline content, and says what it left out; an opt-in or OFF does not", () => {
  const t = tree();
  try {
    mkdirSync(join(t.repo, ".opencode", "plugin"), { recursive: true });
    writeFileSync(join(t.repo, ".opencode", "plugin", "proj.ts"), "x");
    const layout = Layout.dev("/repo");
    const run = (confidentiality: boolean | undefined, extra: Record<string, string> = {}) => {
      const scope = mkdtempSync(join(t.root, "scope-"));
      const warns: string[] = [];
      const r = writeAgentConfig(plan(1, t.repo, confidentiality), layout, scope, (m) => warns.push(m),
        { ...ENV(t), OPENCODE_CONFIG_CONTENT: JSON.stringify({ plugin: ["inline-plugin"], theme: "x" }), ...extra });
      const runFile = JSON.parse(readFileSync(r.path, "utf8")) as Record<string, unknown>;
      const inline = JSON.parse(r.env?.["OPENCODE_CONFIG_CONTENT"] ?? "{}") as Record<string, unknown>;
      return { warns, pure: r.env?.["OPENCODE_PURE"], runFile, inline };
    };
    for (const c of [true, undefined]) {
      const on = run(c);
      assert.equal(on.pure, "1", `INVARIANT: confidentiality ${String(c)}: OpenCode 1 runs with no external plugin`);
      assert.equal(on.runFile["plugin"], undefined, "the run file carries no user plugin list");
      assert.equal(on.runFile["model"], "anthropic/claude-sonnet-4-5", "the rest of the user's document is carried");
      assert.equal(on.inline["plugin"], undefined, "nor the inline content");
      assert.equal(on.inline["theme"], "x");
      assert.ok(on.warns.some((w) => /your own OpenCode plugins and custom tools are left out .*mine\.ts.*opencode\.json \(names a plugin\)/.test(w)), on.warns.join("\n"));
      assert.ok(on.warns.some((w) => /this project's plugins are left out .*proj\.ts/.test(w)), on.warns.join("\n"));
    }
    assert.match(readFileSync(join(t.gdir, "opencode.json"), "utf8"), /"\$schema": "https:\/\/opencode\.ai\/config\.json"/,
      "the launcher made OpenCode 1's own $schema edit (the file is held from OpenCode's start)");
    const off = run(false);
    assert.equal(off.pure, undefined, "mode off: nothing is kept from the model");
    assert.deepEqual(off.runFile["plugin"], ["oh-my-opencode"]);
    const own = run(true, { [OPENCODE_GLOBAL_PLUGINS_ENV]: "1" });
    assert.equal(own.pure, undefined, "the global opt-in: the switch is off");
    assert.deepEqual(own.runFile["plugin"], ["oh-my-opencode"]);
    assert.deepEqual(own.inline["plugin"], ["inline-plugin"]);
    assert.ok(!own.warns.some((w) => /left out/.test(w)), own.warns.join("\n"));
    assert.equal(run(true, { [OPENCODE_PROJECT_PLUGINS_ENV]: "1" }).pure, undefined, "the project opt-in (run.ts refuses it when the user has plugins)");
  } finally {
    rmSync(t.root, { recursive: true, force: true });
  }
});

test("writeAgentConfig (2.x): confidentiality ON or unknown links no global plugin and merges no user plugin list, and says so; the opt-in or OFF keeps them", () => {
  const t = tree();
  try {
    const layout = Layout.dev("/repo");
    const run = (confidentiality: boolean | undefined, extra: Record<string, string> = {}) => {
      const scope = mkdtempSync(join(t.root, "scope-"));
      const warns: string[] = [];
      const r = writeAgentConfig(plan(2, t.repo, confidentiality), layout, scope, (m) => warns.push(m), { ...ENV(t), ...extra });
      assert.equal(r.path, join(scope, "opencode-config", OPENCODE_RUN_FILE));
      assert.equal(r.env?.["OPENCODE_PURE"], undefined, "2.x has no such switch; the launcher builds its configuration");
      const runFile = JSON.parse(readFileSync(r.path, "utf8")) as Record<string, unknown>;
      return { warns, runFile, linked: existsSync(join(scope, "opencode-config", "plugin", "mine.ts")), home: existsSync(join(scope, "opencode-config", "plugins", "home.js")) };
    };
    for (const c of [true, undefined]) {
      const on = run(c);
      assert.equal(on.linked, false, `INVARIANT: confidentiality ${String(c)}: the global plugin is not linked`);
      assert.equal(on.home, false, "nor ~/.opencode's");
      assert.equal(on.runFile["plugin"], undefined, "INVARIANT: the npm plugin the global document names is not in the run file");
      assert.ok(on.warns.some((w) => /your own OpenCode plugins .*left out .*mine\.ts/.test(w)), on.warns.join("\n"));
    }
    const off = run(false);
    assert.equal(off.linked, true);
    assert.deepEqual(off.runFile["plugin"], ["oh-my-opencode"]);
    const own = run(true, { [OPENCODE_GLOBAL_PLUGINS_ENV]: "1" });
    assert.equal(own.linked, true, "the opt-in");
    assert.ok(own.home);
    assert.deepEqual(own.runFile["plugin"], ["oh-my-opencode"]);
    assert.ok(!own.warns.some((w) => /your own OpenCode plugins .*left out/.test(w)));
  } finally {
    rmSync(t.root, { recursive: true, force: true });
  }
});

test("opencodeRoutingContent: the user's inline plugin list is dropped unless the global opt-in", () => {
  const ours = { enabled_providers: ["anthropic"], provider: { anthropic: { options: { baseURL: "http://127.0.0.1:1" } } } };
  const user = JSON.stringify({ plugin: ["p"], plugins: [{ package: "q" }], theme: "t" });
  const closed = JSON.parse(opencodeRoutingContent(ours, user, () => {})) as Record<string, unknown>;
  assert.equal(closed["plugin"], undefined);
  assert.equal(closed["plugins"], undefined);
  assert.equal(closed["theme"], "t");
  const open = JSON.parse(opencodeRoutingContent(ours, user, () => {}, { globalCode: true })) as Record<string, unknown>;
  assert.deepEqual(open["plugin"], ["p"]);
});

test("write-protect: the user's OpenCode settings files wait for the human (label \"an OpenCode setting\"); the code folders cover XDG and OPENCODE_CONFIG_DIR both", () => {
  assert.ok((WRITE_PROTECT_LABELS as readonly string[]).includes("an OpenCode setting"));
  const env = { HOME: "/h", OPENCODE_CONFIG_DIR: "/oc", OPENCODE_CONFIG: "/c/my.json" };
  const settings = laterRunFiles(env).filter((e) => e.label === "an OpenCode setting");
  assert.ok(settings.every((e) => e.answer === "ask"));
  const paths = settings.map((e) => e.path);
  assert.deepEqual(paths, opencodeSettingFiles(env));
  for (const p of [
    "/h/.config/opencode/opencode.json", "/h/.config/opencode/opencode.jsonc", "/h/.config/opencode/config.json", "/h/.config/opencode/tui.json",
    "/oc/opencode.json", "/h/.opencode/opencode.json", "/c/my.json",
  ]) assert.ok(paths.includes(p), p);
  assert.ok(!paths.some((p) => p.endsWith("package.json")), "not OpenCode's own package files");
  const code = userOpencodeCodeDirs(env);
  for (const p of ["/oc/plugin", "/h/.config/opencode/plugin", "/h/.config/opencode/tools", "/h/.opencode/plugins"]) assert.ok(code.includes(p), p);
  // A relative OPENCODE_CONFIG is not a path the guard can hold.
  assert.ok(!opencodeSettingFiles({ HOME: "/h", OPENCODE_CONFIG: "rel.json" }).includes("rel.json"));
  // In the launch's list, and policy.yaml `unprotect` drops one.
  const list = writeProtectList({ HOME: "/h" }, "/w");
  assert.ok(list.some((e) => e.path === "/h/.config/opencode/opencode.json" && e.answer === "ask" && e.label === "an OpenCode setting"));
  const dropped = writeProtectList({ HOME: "/h" }, "/w", undefined, undefined, { deny: [], ask: [], unprotect: ["/h/.config/opencode/opencode.json"] });
  assert.ok(!dropped.some((e) => e.path === "/h/.config/opencode/opencode.json"));
});

test("OpenCode 1's $schema edit: made as OpenCode makes it, only where missing, before the launch", () => {
  assert.equal(withOpencodeSchema(`{\n  "model": "m"\n}\n`), `{\n  "$schema": "https://opencode.ai/config.json",\n  "model": "m"\n}\n`);
  assert.equal(withOpencodeSchema(`{ "$schema": "https://opencode.ai/config.json" }`), null, "already there");
  assert.equal(withOpencodeSchema("{ nope"), null, "does not parse: left for OpenCode");
  assert.equal(withOpencodeSchema("[]"), null);
  const t = tree();
  try {
    writeFileSync(join(t.home, ".opencode", "opencode.json"), `{ "$schema": "https://opencode.ai/config.json" }`);
    const changed = addOpencodeSchema(ENV(t));
    assert.deepEqual(changed, [join(t.gdir, "opencode.json")]);
    const doc = JSON.parse(readFileSync(join(t.gdir, "opencode.json"), "utf8")) as Record<string, unknown>;
    assert.equal(doc["$schema"], "https://opencode.ai/config.json");
    assert.deepEqual(doc["plugin"], ["oh-my-opencode"], "nothing else changes");
    assert.deepEqual(addOpencodeSchema(ENV(t)), [], "idempotent");
    assert.equal(existsSync(join(t.gdir, "opencode.jsonc")), false, "never creates a file");
    assert.ok(!lstatSync(join(t.gdir, "opencode.json")).isSymbolicLink());
  } finally {
    rmSync(t.root, { recursive: true, force: true });
  }
});
