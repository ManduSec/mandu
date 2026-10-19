/**
 * codex-shell-network.test — when a `mandu codex` launch turns the network of
 * Codex's own command sandbox on (src/codex-shell-network.ts,
 * supported-agents.md §6.5). Pure over injected argv, config layers and the
 * launch's posture; the e2e is tests/sandbox/launcher/codex-shell-network.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CODEX_MANAGED_FILES,
  CODEX_SHELL_NETWORK_OVERRIDE,
  CODEX_SYSTEM_CONFIG,
  OPEN_NOTE,
  codexArgvSandbox,
  codexConfigNetworkSetting,
  codexShellNetworkDecision,
  readCodexNetworkLayers,
  type CodexConfigLayer,
  type CodexShellNetworkInput,
} from "../../src/codex-shell-network.js";
import { compactNotice, isAttentionNote, NOTICE_PREFIX } from "../../src/launch-banner.js";
import { codexSpliceOverrides } from "../../src/codex-argv.js";
import { parse as parseIn } from "../../src/parse.js";
import { hermetic } from "../lib/test-runtime.js";
import { applyConfigDefaults } from "../../src/config.js";

/** parse with this file's own runtime dir when the env names none (test-runtime.ts). */
const parse = hermetic(parseIn, 1);

const base: CodexShellNetworkInput = { wanted: undefined, argv: ["codex"], layers: [], guarded: true, confidentiality: true, linux: true };
const user = (path: string, text: string | null): CodexConfigLayer => ({ path, kind: "user", text });
const managed = (path: string, text: string | null): CodexConfigLayer => ({ path, kind: "managed", text });

test("default: a codex launch under the guard opens Codex's sandbox network and says so", () => {
  const d = codexShellNetworkDecision(base);
  assert.deepEqual(d, { open: true, note: OPEN_NOTE });
  assert.deepEqual([...CODEX_SHELL_NETWORK_OVERRIDE], ["-c", "sandbox_workspace_write.network_access=true"]);
  // the same for an explicit --codex-shell-network and for a workspace-write command line
  assert.equal(codexShellNetworkDecision({ ...base, wanted: true }).open, true);
  for (const argv of [["codex", "--full-auto"], ["codex", "-s", "workspace-write"], ["codex", "--sandbox=workspace-write"], ["codex", "exec", "-c", 'sandbox_mode="workspace-write"', "hi"]]) {
    assert.equal(codexShellNetworkDecision({ ...base, argv }).open, true, argv.join(" "));
  }
});

test("opted out: --no-codex-shell-network keeps Codex's default, silently", () => {
  assert.deepEqual(codexShellNetworkDecision({ ...base, wanted: false }), { open: false, reason: "opted-out", note: null });
});

test("the user's own command line wins: any network or permission-profile -c, and no announcement of an open network", () => {
  for (const kv of [
    "sandbox_workspace_write.network_access=false",
    "sandbox_workspace_write.network_access=true",
    "sandbox_workspace_write={network_access=false}",
    '"sandbox_workspace_write".network_access=false',
    "profiles.work.sandbox_workspace_write.network_access=false",
    'default_permissions="locked"',
    "permissions.locked.network=false",
  ]) {
    for (const argv of [["codex", "-c", kv], ["codex", `--config=${kv}`], ["codex", "exec", "-c", kv, "prompt"]]) {
      const d = codexShellNetworkDecision({ ...base, argv });
      assert.equal(d.open, false, argv.join(" "));
      assert.equal(d.open === false && d.reason, "user-setting", argv.join(" "));
      assert.match(d.note ?? "", /left as your command line sets it/, argv.join(" "));
    }
  }
  // prompt text after `--` is not an option
  assert.equal(codexShellNetworkDecision({ ...base, argv: ["codex", "--", "-c", "sandbox_workspace_write.network_access=false"] }).open, true);
  // nor is the value of another flag
  assert.equal(codexShellNetworkDecision({ ...base, argv: ["codex", "-m", "network_access"] }).open, true);
});

test("a sandbox where the key does nothing: no splice and no line", () => {
  for (const argv of [
    ["codex", "-s", "read-only"], ["codex", "--sandbox", "danger-full-access"], ["codex", "--sandbox=read-only"],
    ["codex", "--dangerously-bypass-approvals-and-sandbox"], ["codex", "--yolo"], ["codex", "-c", 'sandbox_mode="read-only"'],
  ]) {
    assert.deepEqual(codexShellNetworkDecision({ ...base, argv }), { open: false, reason: "sandbox-mode", note: null }, argv.join(" "));
  }
});

test("the user's config files win: a network setting or a permission profile in any layer Codex reads", () => {
  const hits = [
    "[sandbox_workspace_write]\nnetwork_access = false\n",
    "[sandbox_workspace_write]\nnetwork_access = true\n",
    "sandbox_workspace_write.network_access = false\n",
    "sandbox_workspace_write = { network_access = false }\n",
    "[profiles.work.sandbox_workspace_write]\nnetwork_access = false\n",
    'default_permissions = "locked"\n',
    "[permissions.locked]\nnetwork = false\n",
  ];
  for (const text of hits) {
    const d = codexShellNetworkDecision({ ...base, layers: [user("/h/.codex/config.toml", 'model = "o3"\n'), user("/w/.codex/config.toml", text)] });
    assert.equal(d.open, false, text);
    assert.equal(d.open === false && d.reason, "user-setting", text);
    assert.equal(d.note, "mandu: Codex's command sandbox network left as /w/.codex/config.toml sets it", text);
  }
  // a commented-out line, other settings, and absent files do not count
  const misses = [
    "# [sandbox_workspace_write]\n# network_access = false\n",
    'model = "o3"\n[sandbox_workspace_write]\nwritable_roots = ["/x"]\n',
    'approval_policy = "on-request"\n',
  ];
  for (const text of misses) assert.equal(codexShellNetworkDecision({ ...base, layers: [user("/h/c.toml", text), user("/x", null)] }).open, true, text);
});

test("an administrator's managed file that mentions the sandbox or the network decides", () => {
  for (const text of ['allowed_sandbox_modes = ["read-only"]\n', "[sandbox_workspace_write]\nwritable_roots = []\n", "network = false\n"]) {
    const d = codexShellNetworkDecision({ ...base, layers: [managed("/etc/codex/requirements.toml", text)] });
    assert.equal(d.open === false && d.reason, "managed", text);
    assert.match(d.note ?? "", /administrator's \/etc\/codex\/requirements\.toml/);
  }
  assert.equal(codexShellNetworkDecision({ ...base, layers: [managed("/etc/codex/managed_config.toml", 'model = "o3"\n# sandbox off\n')] }).open, true);
  assert.equal(codexConfigNetworkSetting([managed("/etc/codex/requirements.toml", null)]), null);
});

test("Mandu's walls must stand in: no guard, the `off` mode, or another platform keep Codex's default", () => {
  const noGuard = codexShellNetworkDecision({ ...base, guarded: false });
  assert.equal(noGuard.open === false && noGuard.reason, "no-guard");
  assert.match(noGuard.note ?? "", /connect guard is not running/);
  const off = codexShellNetworkDecision({ ...base, confidentiality: false });
  assert.equal(off.open === false && off.reason, "off-axis");
  assert.deepEqual(codexShellNetworkDecision({ ...base, linux: false }), { open: false, reason: "not-linux", note: null });
  // the user's choice is still named first, guard or not
  assert.equal(codexShellNetworkDecision({ ...base, guarded: false, argv: ["codex", "-c", "sandbox_workspace_write.network_access=false"] }).open === false
    && codexShellNetworkDecision({ ...base, guarded: false, argv: ["codex", "-c", "sandbox_workspace_write.network_access=false"] }).note?.includes("command line"), true);
});

test("codexArgvSandbox: the profile and the sandbox, at any command level", () => {
  assert.deepEqual(codexArgvSandbox(["codex", "-p", "work", "exec", "-s", "read-only", "hi"]), { networkSet: null, sandbox: "read-only", profile: "work" });
  assert.deepEqual(codexArgvSandbox(["codex", "--profile=work"]), { networkSet: null, sandbox: null, profile: "work" });
  assert.deepEqual(codexArgvSandbox(["codex"]), { networkSet: null, sandbox: null, profile: null });
});

test("the launch line: shown in the compact display as one short notice, not as a warning", () => {
  assert.equal(compactNotice(OPEN_NOTE), `${NOTICE_PREFIX}Codex's commands may use the network (Mandu decides where they connect); --no-codex-shell-network keeps Codex's default`);
  assert.equal(isAttentionNote(OPEN_NOTE), false);
  // the other lines stay in launch.log / --verbose
  for (const d of [codexShellNetworkDecision({ ...base, guarded: false }), codexShellNetworkDecision({ ...base, argv: ["codex", "-c", "sandbox_workspace_write.network_access=false"] })]) {
    assert.equal(compactNotice(d.note!), null);
    assert.equal(isAttentionNote(d.note!), false);
  }
});

test("the override reaches every Codex command level (a user's `exec -c` does not drop it)", () => {
  const out = codexSpliceOverrides(["codex", "exec", "-c", "model=o3", "hi"], [...CODEX_SHELL_NETWORK_OVERRIDE]);
  assert.deepEqual(out, ["codex", ...CODEX_SHELL_NETWORK_OVERRIDE, "exec", ...CODEX_SHELL_NETWORK_OVERRIDE, "-c", "model=o3", "hi"]);
});

test("readCodexNetworkLayers: the user's file, the named profile's, each project .codex up to /, the system and managed files", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-cxnet-layers-"));
  try {
    const home = join(dir, "home");
    const ws = join(dir, "work", "repo");
    mkdirSync(join(home, ".codex"), { recursive: true });
    mkdirSync(join(dir, "work", ".codex"), { recursive: true });
    mkdirSync(ws, { recursive: true });
    writeFileSync(join(home, ".codex", "config.toml"), 'model = "o3"\n');
    writeFileSync(join(dir, "work", ".codex", "config.toml"), "[sandbox_workspace_write]\nnetwork_access = false\n");
    const layers = readCodexNetworkLayers({ home, cwds: [ws, ws], profile: "work" });
    const paths = layers.map((l) => l.path);
    assert.ok(paths.includes(join(home, ".codex", "config.toml")));
    assert.ok(paths.includes(join(home, ".codex", "work.config.toml")));
    assert.ok(paths.includes(join(ws, ".codex", "config.toml")));
    assert.ok(paths.includes(join(dir, "work", ".codex", "config.toml")));
    assert.ok(paths.includes("/.codex/config.toml"));
    assert.ok(paths.includes(CODEX_SYSTEM_CONFIG));
    for (const m of CODEX_MANAGED_FILES) assert.equal(layers.find((l) => l.path === m)?.kind, "managed");
    assert.equal(new Set(paths).size, paths.length, "each file once");
    // the parent's project file holds the setting, so the launch leaves it alone
    const hit = codexConfigNetworkSetting(layers.filter((l) => l.kind === "user"));
    assert.equal(hit?.path, join(dir, "work", ".codex", "config.toml"));
    // CODEX_HOME replaces ~/.codex; a profile name that is not a plain word is not a path
    const ch = readCodexNetworkLayers({ home, codexHome: join(dir, "ch"), cwds: [], profile: "../x" }).map((l) => l.path);
    assert.ok(ch.includes(join(dir, "ch", "config.toml")) && !ch.includes(join(home, ".codex", "config.toml")));
    assert.ok(!ch.some((p) => p.includes("..")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("parse: --codex-shell-network / --no-codex-shell-network + MANDU_CODEX_SHELL_NETWORK; tri-state, flag beats env", () => {
  assert.equal(parse(["codex"], {}).codexShellNetwork, undefined);
  assert.equal(parse(["--no-codex-shell-network", "codex"], {}).codexShellNetwork, false);
  assert.equal(parse(["--codex-shell-network", "codex"], {}).codexShellNetwork, true);
  assert.equal(parse(["codex"], { MANDU_CODEX_SHELL_NETWORK: "0" }).codexShellNetwork, false);
  assert.equal(parse(["--codex-shell-network", "codex"], { MANDU_CODEX_SHELL_NETWORK: "0" }).codexShellNetwork, true);
});

test("config.toml: codex-shell-network = false seeds MANDU_CODEX_SHELL_NETWORK=0", () => {
  const env: Record<string, string | undefined> = { MANDU_HOME: "/cfg" };
  applyConfigDefaults(env, (p) => (p === "/cfg/config.toml" ? "codex-shell-network = false\n" : null));
  assert.equal(env["MANDU_CODEX_SHELL_NETWORK"], "0");
  assert.equal(parse(["codex"], env).codexShellNetwork, false);
  // an exported env var beats the file
  const exported: Record<string, string | undefined> = { MANDU_HOME: "/cfg", MANDU_CODEX_SHELL_NETWORK: "1" };
  applyConfigDefaults(exported, () => "codex-shell-network = false\n");
  assert.equal(parse(["codex"], exported).codexShellNetwork, true);
});


test("macOS: configured network keys do not produce a claim that Codex's possibly disabled sandbox keeps them", () => {
  for (const over of [
    { argv: ["codex", "-c", "sandbox_workspace_write.network_access=false"] },
    { layers: [user("/h/.codex/config.toml", "[sandbox_workspace_write]\nnetwork_access = false\n")] },
    { layers: [managed("/etc/codex/requirements.toml", "network = false\n")] },
  ]) {
    assert.deepEqual(codexShellNetworkDecision({ ...base, ...over, linux: false }), { open: false, reason: "not-linux", note: null });
  }
});
