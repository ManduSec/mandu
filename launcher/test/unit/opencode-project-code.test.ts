/**
 * opencode-project-code.test — a project's OpenCode code extensions under
 * Mandu (src/opencode-project-code.ts; supported-agents.md §2.3 item 11):
 * which files count, per generation; the user's own directories never do;
 * the opt-out; the refusal and notice wording; the OpenCode 2 config
 * directory and run file built without them; the write-protect entries.
 *
 * WHY (measured 2026-10-06, OpenCode 1.18.13 and 2.0.23 under the real
 * launcher in `secrets`): a project plugin copied a pinned reader's raw
 * output and another agent's credential store into the system prompt, and a
 * project custom tool returned the store's key in its result; the scripted
 * model received both raw. tests/sandbox/guard/opencode-project-plugins.test.ts
 * is the end-to-end form.
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
  findOpencodeProjectCode, OPENCODE_PROJECT_PLUGINS_ENV, opencodeProjectCodeAllowed, opencodeProjectCodeNotice,
  opencodeProjectCodeOptOutWarning, opencodeProjectCodeRefusal, opencodeProjectDirs, opencodeStartDirs,
  projectOpencodeCodeDirs, userOpencodeCodeDirs, userOpencodeDirs, withoutPlugins,
} from "../../src/opencode-project-code.js";
import { buildOpencodeConfigDir, opencodeV2UserDoc, OPENCODE_RUN_FILE, writeAgentConfig } from "../../src/services/agent-config.js";
import { laterRunFiles, WRITE_PROTECT_LABELS, writeProtectList } from "../../src/write-protect.js";
import { Layout } from "../../src/services/layout.js";
import type { LaunchPlan, Ullm } from "../../src/types.js";

interface Tree { root: string; home: string; repo: string; sub: string; gdir: string }

/** A home with the user's global OpenCode dir and `~/.opencode`, and a
 *  repository under the home with a project `.opencode` at its root and in
 *  a subdirectory. */
function tree(): Tree {
  const root = mkdtempSync(join(tmpdir(), "mdu-oc-projcode-"));
  const home = join(root, "home");
  const gdir = join(home, ".config", "opencode");
  const repo = join(home, "work", "repo");
  const sub = join(repo, "pkg");
  for (const d of [join(gdir, "plugin"), join(home, ".opencode", "plugins"), join(repo, ".git"), join(sub, ".opencode")]) mkdirSync(d, { recursive: true });
  writeFileSync(join(gdir, "plugin", "mine.ts"), "export const Mine = async () => ({})\n");
  writeFileSync(join(home, ".opencode", "plugins", "home.js"), "export const Home = async () => ({})\n");
  return { root, home, repo, sub, gdir };
}

const ENV = (t: Tree): Record<string, string> => ({ HOME: t.home });

test("the opt-out: only an explicit yes", () => {
  for (const v of ["1", "true", "TRUE", "yes", "on", " 1 "]) assert.equal(opencodeProjectCodeAllowed({ [OPENCODE_PROJECT_PLUGINS_ENV]: v }), true, v);
  for (const v of [undefined, "", "0", "false", "no", "off", "please"]) assert.equal(opencodeProjectCodeAllowed({ [OPENCODE_PROJECT_PLUGINS_ENV]: v }), false, String(v));
});

test("the user's own directories: the global config dir (OPENCODE_CONFIG_DIR, else XDG) and ~/.opencode", () => {
  assert.deepEqual(userOpencodeDirs({ HOME: "/h" }), ["/h/.config/opencode", "/h/.opencode"]);
  assert.deepEqual(userOpencodeDirs({ HOME: "/h", XDG_CONFIG_HOME: "/x" }), ["/x/opencode", "/h/.opencode"]);
  assert.deepEqual(userOpencodeDirs({ HOME: "/h", OPENCODE_CONFIG_DIR: "/oc" }), ["/oc", "/h/.opencode"]);
});

test("project directories: OpenCode 1 walks to the repository root, OpenCode 2 to /; 1.x's own project switch empties them", () => {
  const t = tree();
  try {
    const d1 = opencodeProjectDirs([t.sub], 1, ENV(t));
    assert.deepEqual(d1, [t.sub, t.repo], "1.x: up to the repository root");
    const d2 = opencodeProjectDirs([t.sub], 2, ENV(t));
    assert.equal(d2[0], t.sub);
    assert.equal(d2.at(-1), "/", "2.x: every ancestor");
    assert.deepEqual(opencodeProjectDirs([t.sub], 1, { ...ENV(t), OPENCODE_DISABLE_PROJECT_CONFIG: "1" }), []);
    assert.deepEqual(opencodeProjectDirs([t.gdir], 1, ENV(t)), [], "started in the global config dir: no project");
  } finally {
    rmSync(t.root, { recursive: true, force: true });
  }
});

test("findOpencodeProjectCode: plugin and tool modules of every project .opencode, and config documents naming plugins; never the user's own", () => {
  const t = tree();
  try {
    assert.deepEqual(findOpencodeProjectCode([t.sub], 1, ENV(t)), [], "a project with no code: nothing (the user's global and ~/.opencode plugins are theirs)");
    assert.deepEqual(findOpencodeProjectCode([t.sub], 2, ENV(t)), []);
    mkdirSync(join(t.repo, ".opencode", "plugin"), { recursive: true });
    mkdirSync(join(t.sub, ".opencode", "tools"), { recursive: true });
    mkdirSync(join(t.sub, ".opencode", "plugins", "pkg-dir"), { recursive: true });
    writeFileSync(join(t.repo, ".opencode", "plugin", "leak.ts"), "x");
    writeFileSync(join(t.repo, ".opencode", "plugin", "README.md"), "not a module");
    writeFileSync(join(t.sub, ".opencode", "tools", "t.js"), "x");
    writeFileSync(join(t.repo, "opencode.json"), JSON.stringify({ plugin: ["some-npm-plugin"] }));
    writeFileSync(join(t.sub, ".opencode", "opencode.jsonc"), "{ // no plugins here\n \"model\": \"anthropic/x\", \"plugin\": [] }");
    writeFileSync(join(t.repo, "tui.json"), JSON.stringify({ plugin: ["a-tui-plugin"] }));
    const v1 = findOpencodeProjectCode([t.sub], 1, ENV(t));
    assert.deepEqual(v1.map((f) => `${f.kind}:${f.path.slice(t.repo.length)}`).sort(), [
      "config:/opencode.json", "config:/tui.json", "plugin:/.opencode/plugin/leak.ts", "tool:/pkg/.opencode/tools/t.js",
    ], "1.x: *.ts/*.js modules (not a README, not a directory), opencode.json and tui.json naming plugins; an empty list names none");
    const v2 = findOpencodeProjectCode([t.sub], 2, ENV(t));
    assert.deepEqual(v2.map((f) => `${f.kind}:${f.path.slice(t.repo.length)}`).sort(), [
      "config:/opencode.json", "plugin:/.opencode/plugin/leak.ts", "plugin:/pkg/.opencode/plugins/pkg-dir", "tool:/pkg/.opencode/tools/t.js",
    ], "2.x: a package directory counts too; tui.json is not 2.x's");
    // A document Mandu cannot parse counts (OpenCode's reader may take it).
    writeFileSync(join(t.sub, "opencode.json"), "{ nope");
    assert.ok(findOpencodeProjectCode([t.sub], 1, ENV(t)).some((f) => f.path === join(t.sub, "opencode.json")));
  } finally {
    rmSync(t.root, { recursive: true, force: true });
  }
});

test("the start directories: cwd, the bare `opencode <dir>` form and `--dir`", () => {
  const t = tree();
  try {
    assert.deepEqual(opencodeStartDirs(["opencode", "run", "hi"], t.repo), [t.repo]);
    assert.deepEqual(opencodeStartDirs(["opencode", "pkg"], t.repo), [t.repo, t.sub]);
    assert.deepEqual(opencodeStartDirs(["opencode", "run", "--dir", "pkg", "hi"], t.repo), [t.repo, t.sub]);
    assert.deepEqual(opencodeStartDirs(["opencode", "run", `--dir=${t.sub}`], t.repo), [t.repo, t.sub]);
    assert.deepEqual(opencodeStartDirs(["opencode", "not-a-dir"], t.repo), [t.repo]);
  } finally {
    rmSync(t.root, { recursive: true, force: true });
  }
});

test("the wording: the refusal names each file, why, and every way out; the notice and the opt-out warning name the files", () => {
  const f = [{ path: "/w/.opencode/plugin/x.ts", kind: "plugin" as const }, { path: "/w/opencode.json", kind: "config" as const }];
  const r = opencodeProjectCodeRefusal("secrets", f);
  assert.match(r, /^refusing OpenCode in mode secrets: this project brings OpenCode code/);
  assert.match(r, /\/w\/\.opencode\/plugin\/x\.ts, \/w\/opencode\.json \(names a plugin\)/);
  assert.match(r, /not checked/);
  assert.match(r, /OpenCode 2/);
  assert.match(r, /MANDU_OPENCODE_PROJECT_PLUGINS=1/);
  assert.match(opencodeProjectCodeNotice(f), /left out .*x\.ts.*MANDU_OPENCODE_PROJECT_PLUGINS=1 runs them unchecked/);
  assert.match(opencodeProjectCodeOptOutWarning(f), /^WARNING: MANDU_OPENCODE_PROJECT_PLUGINS=1 .*not checked: \/w\/\.opencode\/plugin\/x\.ts/);
});

test("withoutPlugins drops both spellings and nothing else", () => {
  assert.deepEqual(withoutPlugins({ model: "m", plugin: ["a"], plugins: [{ package: "b" }] }), { doc: { model: "m" }, dropped: true });
  const same = { model: "m" };
  assert.equal(withoutPlugins(same).doc, same);
  assert.equal(withoutPlugins(same).dropped, false);
});

test("OpenCode 2 config dir: a project's plugin and tool dirs are not linked, nor the user's own (item 12); each opt-in links its own", () => {
  const t = tree();
  try {
    mkdirSync(join(t.repo, ".opencode", "plugin"), { recursive: true });
    mkdirSync(join(t.repo, ".opencode", "agents"), { recursive: true });
    mkdirSync(join(t.sub, ".opencode", "tool"), { recursive: true });
    writeFileSync(join(t.repo, ".opencode", "plugin", "leak.ts"), "x");
    writeFileSync(join(t.repo, ".opencode", "agents", "a.md"), "agent");
    writeFileSync(join(t.sub, ".opencode", "tool", "t.ts"), "x");
    const out = join(t.root, "out");
    buildOpencodeConfigDir(out, ENV(t), t.sub, () => {}, t.home);
    assert.equal(readFileSync(join(out, "agents", "a.md"), "utf8"), "agent", "a project agent is still linked");
    assert.equal(existsSync(join(out, "plugin", "leak.ts")), false, "INVARIANT: the project's plugin is not linked");
    assert.equal(existsSync(join(out, "tool")), false, "nor its custom tool");
    assert.equal(existsSync(join(out, "plugin", "mine.ts")), false, "INVARIANT (item 12): the user's global plugin is not linked by default");
    assert.equal(existsSync(join(out, "plugins")), false, "nor ~/.opencode's (the user's own; an ancestor of the repo here)");
    // The controls: each opt-in links its own origin's, not the other's.
    const allowed = join(t.root, "allowed");
    buildOpencodeConfigDir(allowed, ENV(t), t.sub, () => {}, t.home, { projectCode: true });
    assert.ok(lstatSync(join(allowed, "plugin", "leak.ts")).isSymbolicLink());
    assert.ok(lstatSync(join(allowed, "tool", "t.ts")).isSymbolicLink());
    assert.equal(existsSync(join(allowed, "plugin", "mine.ts")), false, "the project opt-in does not run the user's own");
    const own = join(t.root, "own");
    buildOpencodeConfigDir(own, ENV(t), t.sub, () => {}, t.home, { globalCode: true });
    assert.ok(lstatSync(join(own, "plugin", "mine.ts")).isSymbolicLink(), "the global opt-in links the user's global plugin");
    assert.ok(lstatSync(join(own, "plugins", "home.js")).isSymbolicLink(), "and ~/.opencode's");
    assert.equal(existsSync(join(own, "plugin", "leak.ts")), false, "but not the project's");
  } finally {
    rmSync(t.root, { recursive: true, force: true });
  }
});

test("OpenCode 2 run file: a project document's plugin list is dropped, and the user's global one (item 12); each opt-in keeps its own", () => {
  const t = tree();
  try {
    writeFileSync(join(t.gdir, "opencode.json"), JSON.stringify({ plugin: ["oh-my-plugin"] }));
    writeFileSync(join(t.repo, "opencode.json"), JSON.stringify({ model: "anthropic/claude-sonnet-4-5", plugins: ["evil-pkg"] }));
    writeFileSync(join(t.sub, ".opencode", "opencode.json"), JSON.stringify({ plugin: ["./local.ts"] }));
    const doc = opencodeV2UserDoc(ENV(t), t.sub, () => {}, t.home);
    assert.equal(doc["plugin"], undefined, "INVARIANT (item 12): the global document's list does not reach the run file by default");
    assert.equal(doc["plugins"], undefined, "INVARIANT: no project list reaches the run file");
    assert.equal(doc["model"], "anthropic/claude-sonnet-4-5", "the rest of the project document is merged");
    const allowed = opencodeV2UserDoc(ENV(t), t.sub, () => {}, t.home, { projectCode: true });
    assert.deepEqual(allowed["plugins"], ["evil-pkg"]);
    assert.deepEqual(allowed["plugin"], ["./local.ts"], "the project opt-in keeps the project's, not the user's oh-my-plugin");
    const own = opencodeV2UserDoc(ENV(t), t.sub, () => {}, t.home, { globalCode: true });
    assert.deepEqual(own["plugin"], ["oh-my-plugin"], "the global opt-in keeps the user's");
    assert.equal(own["plugins"], undefined);
  } finally {
    rmSync(t.root, { recursive: true, force: true });
  }
});

const ULLM: Ullm = { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" };

/** A 2.x launch plan for writeAgentConfig (opencode-v2-config.test.ts's
 *  fullPlan), with the effective axes when given. */
function v2Plan(cwd: string, confidentiality: boolean | undefined): LaunchPlan {
  return {
    target: "opencode", argv: ["opencode2", "run", "--standalone", "hi"], agentVersion: "opencode v2.0.23", scopeId: "sid-1", tenant: "live",
    arbiterSock: "/run/mandu/arbiter.sock", arbiterSockMode: "pinned", arbiterRuntimeBase: "/tmp/mandu",
    eventDir: "/e", cwd, humanCwd: cwd, noContextProxy: true, fsSync: false,
    basePath: "/usr/bin", proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false }, execWrapCmds: [],
    ullm: ULLM, noScope: false, writeMcp: false, bestEffort: false, replyFilter: true,
    ...(confidentiality === undefined ? {} : { effectiveAxes: { confidentiality, integrity: false } }),
  };
}

test("writeAgentConfig (2.x): confidentiality ON or unknown leaves the project's plugins out and says so; OFF, or the opt-out, keeps them", () => {
  const t = tree();
  try {
    mkdirSync(join(t.repo, ".opencode", "plugin"), { recursive: true });
    writeFileSync(join(t.repo, ".opencode", "plugin", "leak.ts"), "x");
    const layout = Layout.dev("/repo");
    const run = (confidentiality: boolean | undefined, extra: Record<string, string> = {}): { warns: string[]; linked: boolean } => {
      const scope = mkdtempSync(join(t.root, "scope-"));
      const warns: string[] = [];
      const r = writeAgentConfig(v2Plan(t.sub, confidentiality), layout, scope, (m) => warns.push(m), { ...ENV(t), ...extra });
      assert.equal(r.path, join(scope, "opencode-config", OPENCODE_RUN_FILE));
      return { warns, linked: existsSync(join(scope, "opencode-config", "plugin", "leak.ts")) };
    };
    for (const c of [true, undefined]) {
      const on = run(c);
      assert.equal(on.linked, false, `INVARIANT: confidentiality ${String(c)}: not linked`);
      assert.ok(on.warns.some((w) => /left out .*leak\.ts/.test(w)), on.warns.join("\n"));
    }
    assert.equal(run(false).linked, true, "mode off: nothing is kept from the model, the project's plugins run");
    const opted = run(true, { [OPENCODE_PROJECT_PLUGINS_ENV]: "1" });
    assert.equal(opted.linked, true, "the opt-out");
    assert.ok(!opted.warns.some((w) => /this project's plugins .*left out/.test(w)));
  } finally {
    rmSync(t.root, { recursive: true, force: true });
  }
});

test("write-protect: the user's and the project's OpenCode plugin and tool dirs are held for the human (files that run later)", () => {
  assert.ok((WRITE_PROTECT_LABELS as readonly string[]).includes("an OpenCode plugin or tool"));
  const user = laterRunFiles({ HOME: "/h" }).filter((e) => e.label === "an OpenCode plugin or tool").map((e) => e.path);
  assert.deepEqual(user, userOpencodeCodeDirs({ HOME: "/h" }));
  for (const p of ["/h/.config/opencode/plugin", "/h/.config/opencode/plugins", "/h/.config/opencode/tool", "/h/.config/opencode/tools", "/h/.opencode/plugin", "/h/.opencode/tools"]) {
    assert.ok(user.includes(p), p);
  }
  const t = tree();
  try {
    const project = projectOpencodeCodeDirs(t.sub);
    assert.ok(project.includes(join(t.sub, ".opencode", "plugin")) && project.includes(join(t.repo, ".opencode", "tools")), "cwd up to the repository root");
    assert.ok(!project.some((p) => p.startsWith(join(t.home, "work", ".opencode"))), "not above the repository");
    const list = writeProtectList(ENV(t), t.sub);
    for (const p of project) assert.ok(list.some((e) => e.path === p && e.answer === "ask" && e.label === "an OpenCode plugin or tool"), p);
    // Outside a repository: cwd's own only.
    const loose = join(t.root, "loose");
    mkdirSync(loose);
    assert.deepEqual(projectOpencodeCodeDirs(loose), ["plugin", "plugins", "tool", "tools"].map((s) => join(loose, ".opencode", s)));
    // policy.yaml `unprotect` drops one, as any built-in ask entry.
    const dropped = writeProtectList(ENV(t), t.sub, undefined, undefined, { deny: [], ask: [], unprotect: [join(t.repo, ".opencode", "plugin")] });
    assert.ok(!dropped.some((e) => e.path === join(t.repo, ".opencode", "plugin")));
  } finally {
    rmSync(t.root, { recursive: true, force: true });
  }
});
