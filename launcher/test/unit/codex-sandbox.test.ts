/**
 * codex-sandbox.test — can Codex's own command sandbox run here
 * (src/codex-sandbox.ts; os-test-matrix.md §10.14.1 item 4)? The decision
 * is pure over injected facts; the doctor row and the launch line render it.
 * The cases are the hosts the fresh-agents VM suite met: stock 24.04 / 26.04
 * (no bubblewrap, AppArmor restriction on), 24.04 after `apt install
 * bubblewrap` but before `mandu setup`, and a host with the grant.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  APT_BUBBLEWRAP,
  CODEX_BWRAP_PROBE_ARGV,
  CODEX_DARWIN_ADMIN_FIX,
  CODEX_DARWIN_CONFIG_FIX,
  CODEX_DARWIN_FIX,
  CODEX_SANDBOX_OFF_ARGS,
  CODEX_REMOTE_NOTE,
  CODEX_SANDBOX_OFF_NOTE,
  CODEX_SANDBOX_OFF_NOTE_NO_CREDS,
  CODEX_APP_SERVER_OFF_NOTE,
  CODEX_APP_SERVER_OFF_NOTE_NO_CREDS,
  CODEX_DARWIN_PROXY_FIX,
  CODEX_PROXY_OFF_ARGS,
  CODEX_MANAGED_CONFIG_PATH,
  CODEX_SYSTEM_CONFIG_PATH,
  codexAllConfigLayers,
  codexConfigLayers,
  codexLayersNetworkProxy,
  codexLayersSandboxOff,
  assessCodexSandbox,
  codexArgvNetworkProxy,
  codexConfigDefaultPermissions,
  codexNetworkProxySetting,
  realCodexSandboxDeps,
  codexArgvProfile,
  codexNetworkProxyOn,
  codexAdminSandboxLock,
  codexArgvSandboxChoice,
  codexConfigKeeps,
  codexManagedConfigLock,
  codexRequirementsLock,
  codexSandboxLaunch,
  codexArgvSandboxOff,
  codexConfigPath,
  codexConfigSandboxOff,
  codexSandboxLaunchNote,
  codexSandboxRow,
  gatherCodexSandbox,
  launchCodexSandboxNote,
  type CodexSandboxFacts,
  type CodexSandboxProbeDeps,
} from "../../src/codex-sandbox.js";
import { isAttentionNote } from "../../src/launch-banner.js";
import { codexSpliceOverrides } from "../../src/codex-argv.js";
import { APPARMOR_USERNS_SYSCTL, USERNS_CLONE_SYSCTL } from "../../src/userns.js";
import { SANDBOX_EXEC, sandboxExecAvailable } from "../../src/seatbelt-profile.js";

const stock: CodexSandboxFacts = {
  platform: "linux", codex: true, systemBwrap: false, systemBwrapOk: null,
  apparmorRestrict: "1", usernsClone: "1", maxUserNamespaces: "63000",
};

test("the probe is Codex's own: user + net namespace over a read-only root", () => {
  assert.deepEqual(CODEX_BWRAP_PROBE_ARGV, ["--unshare-user", "--unshare-net", "--ro-bind", "/", "/", "/bin/true"]);
});

test("stock Ubuntu (no bubblewrap, AppArmor restriction on): no-bwrap, fix = apt install then mandu setup", () => {
  const a = assessCodexSandbox(stock);
  assert.equal(a.state, "no-bwrap");
  assert.equal(a.fix, `${APT_BUBBLEWRAP}, then mandu setup (it asks for sudo only if this host needs the grant)`);
});

test("no bubblewrap but no AppArmor restriction: Codex's bundled copy runs, ok", () => {
  assert.equal(assessCodexSandbox({ ...stock, apparmorRestrict: "0" }).state, "ok");
  assert.equal(assessCodexSandbox({ ...stock, apparmorRestrict: null }).state, "ok", "no knob file = no restriction");
});

test("24.04 after apt install bubblewrap, before mandu setup: the probe fails under the restriction → mandu setup", () => {
  const a = assessCodexSandbox({ ...stock, systemBwrap: true, systemBwrapOk: false });
  assert.equal(a.state, "bwrap-denied");
  assert.match(a.fix!, /^mandu setup /);
  assert.doesNotMatch(a.fix!, /apt install/, "bubblewrap is already there");
});

test("a system bubblewrap whose probe passes (26.04's own grant, or 24.04 after mandu setup): ok", () => {
  assert.deepEqual(assessCodexSandbox({ ...stock, systemBwrap: true, systemBwrapOk: true }), { state: "ok", fix: null });
});

test("a failing probe with no AppArmor restriction: probe-failed, no guessed fix", () => {
  const a = assessCodexSandbox({ ...stock, apparmorRestrict: "0", systemBwrap: true, systemBwrapOk: false });
  assert.deepEqual(a, { state: "probe-failed", fix: null });
});

test("unprivileged user namespaces switched off: userns-off names the sysctl, whatever bubblewrap does", () => {
  assert.equal(assessCodexSandbox({ ...stock, usernsClone: "0" }).state, "userns-off");
  assert.match(assessCodexSandbox({ ...stock, usernsClone: "0" }).fix!, /unprivileged_userns_clone=1/);
  assert.match(assessCodexSandbox({ ...stock, maxUserNamespaces: "0", systemBwrap: true, systemBwrapOk: false }).fix!, /max_user_namespaces/);
});

test("not Linux, or no codex: not-applicable, and neither the row nor the launch line appears", () => {
  for (const f of [
    { ...stock, platform: "win32" as const },
    { ...stock, codex: false },
    // macOS with no Mandu profile around the launch: nothing nests
    { ...stock, platform: "darwin" as const },
    { ...stock, platform: "darwin" as const, outerSeatbelt: false },
    { ...stock, platform: "darwin" as const, outerSeatbelt: true, codex: false },
  ]) {
    const a = assessCodexSandbox(f);
    assert.equal(a.state, "not-applicable");
    assert.equal(codexSandboxRow(a), null);
    assert.equal(codexSandboxLaunchNote(a), null);
  }
});

test("doctor row: ✓ when ok, ✗ with the cause and the exact fix otherwise", () => {
  assert.equal(codexSandboxRow({ state: "ok", fix: null }), "  ✓ Codex can run commands in its own sandbox (bubblewrap)");
  const row = codexSandboxRow(assessCodexSandbox(stock))!;
  assert.equal(
    row,
    "  ✗ Codex cannot run any command here, with or without Mandu: bubblewrap is not installed, and the copy Codex " +
      "bundles cannot run under this host's AppArmor rules; fix: sudo apt install bubblewrap, then mandu setup (it asks " +
      "for sudo only if this host needs the grant)",
  );
  assert.doesNotMatch(codexSandboxRow({ state: "probe-failed", fix: null })!, /fix:/);
});

test("launch line: ONE WARNING line the compact display shows, naming the fix; none when ok", () => {
  const n = codexSandboxLaunchNote(assessCodexSandbox(stock))!;
  assert.match(n, /^mandu: WARNING — Codex's own sandbox cannot run commands on this machine \(bubblewrap is not installed/);
  assert.match(n, /fix: sudo apt install bubblewrap, then mandu setup/);
  assert.equal(n.includes("\n"), false);
  assert.equal(isAttentionNote(n), true, "shown by the default compact display");
  assert.match(codexSandboxLaunchNote({ state: "probe-failed", fix: null })!, /run `mandu doctor` for details/);
  assert.equal(codexSandboxLaunchNote({ state: "ok", fix: null }), null);
});

function probeDeps(over: { path?: string[]; knobs?: Record<string, string>; probe?: boolean; platform?: "linux" | "darwin" } = {}): CodexSandboxProbeDeps & { probed: () => number } {
  let n = 0;
  const path = new Set(over.path ?? ["codex"]);
  // "sandbox-exec" in the fake PATH stands for the system copy: the launch
  // checks /usr/bin/sandbox-exec by path, never a PATH lookup (seatbelt-profile.ts).
  if (path.has("sandbox-exec")) path.add("/usr/bin/sandbox-exec");
  return {
    platform: () => over.platform ?? "linux",
    commandExists: (c) => path.has(c),
    readKnob: (p) => (over.knobs ?? { [APPARMOR_USERNS_SYSCTL]: "1\n", [USERNS_CLONE_SYSCTL]: "1\n" })[p] ?? null,
    bwrapProbe: () => { n++; return over.probe ?? true; },
    probed: () => n,
  };
}

test("gather: the bwrap probe runs only with codex AND a system bwrap; knobs are trimmed", () => {
  const d1 = probeDeps({ path: ["codex"] });
  const f1 = gatherCodexSandbox(d1);
  assert.equal(d1.probed(), 0);
  assert.equal(f1.apparmorRestrict, "1");
  assert.equal(f1.systemBwrapOk, null);
  const d2 = probeDeps({ path: ["codex", "bwrap"], probe: false });
  assert.equal(gatherCodexSandbox(d2).systemBwrapOk, false);
  assert.equal(d2.probed(), 1);
  const d3 = probeDeps({ path: ["bwrap"] });
  assert.equal(gatherCodexSandbox(d3).codex, false);
  assert.equal(d3.probed(), 0, "no codex, no probe");
  // macOS: no bwrap probe and no Linux knobs; the outer profile is sandbox-exec's presence
  const mac = probeDeps({ platform: "darwin", path: ["codex", "sandbox-exec"] });
  const fm = gatherCodexSandbox(mac);
  assert.equal(mac.probed(), 0);
  assert.deepEqual([fm.codex, fm.outerSeatbelt, fm.codexSandboxOff, fm.apparmorRestrict], [true, true, false, null]);
  assert.equal(gatherCodexSandbox(probeDeps({ platform: "darwin", path: ["codex"] })).outerSeatbelt, false, "no sandbox-exec, no profile");
  assert.equal(gatherCodexSandbox(probeDeps({ platform: "darwin", path: ["sandbox-exec"] })).codex, false);
  assert.equal(gatherCodexSandbox(mac, true, { outerSeatbelt: false }).outerSeatbelt, false, "a launch that protects no secrets says so");
});

// ── macOS (decided 2026-10-02): Mandu turns Codex's own sandbox off for the session ──

const darwin: CodexSandboxFacts = { ...stock, platform: "darwin", outerSeatbelt: true };

test("macOS inside Mandu's profile: Mandu turns Codex's sandbox off (seatbelt-mandu-off), a ✓ row and ONE attention line naming what it gives up", () => {
  const a = assessCodexSandbox(darwin);
  assert.deepEqual(a, { state: "seatbelt-mandu-off", fix: null });
  assert.equal(codexSandboxRow(a), "  ✓ Codex runs commands under mandu on macOS: Mandu turns its own sandbox off for each session (macOS cannot " +
    "start it inside Mandu's profile), and in mode secrets Mandu's profile keeps those commands from your credential files");
  // the doctor knows the host, not the mode: the clause names mode secrets
  assert.doesNotMatch(codexSandboxRow({ ...a, noCreds: true })!, /credential files/);
  const n = codexSandboxLaunchNote(a)!;
  assert.equal(n, CODEX_SANDBOX_OFF_NOTE);
  assert.match(n, /^mandu: Codex's own sandbox is OFF for this session: macOS cannot start it inside Mandu's profile\./);
  assert.match(n, /still keeps your credential files from the commands Codex runs, but Codex's own limits on where they write and connect do not apply/);
  assert.equal(n.includes("\n"), false);
  assert.equal(isAttentionNote(n), true, "the compact display shows it");
  assert.doesNotMatch(n, /WARNING/, "a decision, not a failure");
  assert.deepEqual(CODEX_SANDBOX_OFF_ARGS, ["-c", 'sandbox_mode="danger-full-access"']);
});

test("macOS: the sandbox stays (seatbelt-nests, ✗ row, WARNING) when an administrator requires it, the run asks for it, or the config relies on it; the admin wins over everything", () => {
  const admin = assessCodexSandbox({ ...darwin, adminLock: "/etc/codex/requirements.toml: deny_read", codexSandboxOff: true, explicitOn: "--sandbox read-only" });
  assert.equal(admin.state, "seatbelt-nests");
  assert.equal(admin.fix, CODEX_DARWIN_ADMIN_FIX);
  assert.match(codexSandboxRow(admin)!, /^ {2}✗ Codex cannot run commands under mandu on macOS: your organization's Codex settings require its own sandbox \(\/etc\/codex\/requirements\.toml: deny_read\), and macOS cannot start it inside Mandu's profile \(sandbox_apply: Operation not permitted\), so every command Codex runs fails; fix: ask your administrator/);
  const explicit = assessCodexSandbox({ ...darwin, explicitOn: "--sandbox workspace-write" });
  assert.deepEqual([explicit.state, explicit.fix], ["seatbelt-nests", CODEX_DARWIN_FIX]);
  const n = codexSandboxLaunchNote(explicit)!;
  assert.match(n, /^mandu: WARNING — Codex cannot run commands inside Mandu on macOS \(this run asks for Codex's own sandbox \(--sandbox workspace-write\), and macOS cannot start it/);
  assert.match(n, /fix: drop that option and Mandu turns Codex's own sandbox off for the session/);
  assert.equal(isAttentionNote(n), true);
  const keeps = assessCodexSandbox({ ...darwin, configKeeps: "a permission profile of your own" });
  assert.deepEqual([keeps.state, keeps.fix], ["seatbelt-nests", CODEX_DARWIN_CONFIG_FIX]);
  assert.match(codexSandboxRow(keeps)!, /your Codex config relies on its own sandbox \(a permission profile of your own\)/);
  // off already (argv or config.toml): nothing to do; no profile, no codex: not applicable
  assert.deepEqual(assessCodexSandbox({ ...darwin, codexSandboxOff: true }), { state: "seatbelt-sandbox-off", fix: null });
  assert.equal(codexSandboxRow(assessCodexSandbox({ ...darwin, codexSandboxOff: true })), "  ✓ Codex runs commands under mandu on macOS: its own sandbox is off, and in mode secrets Mandu's profile keeps them from your credential files");
  assert.equal(assessCodexSandbox({ ...darwin, outerSeatbelt: false }).state, "not-applicable");
  assert.equal(assessCodexSandbox({ ...darwin, codex: false }).state, "not-applicable");
  for (const a of [admin, explicit, keeps]) assert.doesNotMatch(codexSandboxRow(a)!, /killed|exit 137|with or without Mandu|bubblewrap/);
});

test("codexArgvSandboxChoice: every form a run asks for or turns off Codex's sandbox (0.159.3), with Codex's precedence; every level; nothing past --", () => {
  const ch = (argv: string[], profiles: Record<string, string> = {}) => codexArgvSandboxChoice(argv, (n) => profiles[n] ?? null);
  // typed -s / --sandbox / --sandbox= / -s<mode>, at the root or a subcommand level
  assert.deepEqual(ch(["codex", "-s", "workspace-write"]), { kind: "on", by: "-s workspace-write" });
  assert.deepEqual(ch(["codex", "exec", "--sandbox", "read-only", "hi"]), { kind: "on", by: "--sandbox read-only" });
  assert.deepEqual(ch(["codex", "--sandbox=workspace-write"]), { kind: "on", by: "--sandbox workspace-write" });
  assert.deepEqual(ch(["codex", "-sdanger-full-access"]), { kind: "off", by: "-s danger-full-access" });
  // a typed mode beats any -c, in either order
  assert.equal(ch(["codex", "-c", 'sandbox_mode="danger-full-access"', "-s", "read-only"]).kind, "on");
  assert.equal(ch(["codex", "-s", "danger-full-access", "-c", 'sandbox_mode="read-only"']).kind, "off");
  // the bypass flag (and its alias) always off
  assert.deepEqual(ch(["codex", "--sandbox", "read-only", "--yolo"]), { kind: "off", by: "--yolo" });
  assert.equal(ch(["codex", "--dangerously-bypass-approvals-and-sandbox"]).kind, "off");
  // flags that keep a sandbox: --approve-for-me (workspace-write), --remote, the network proxy
  assert.deepEqual(ch(["codex", "--approve-for-me"]), { kind: "on", by: "--approve-for-me" });
  assert.deepEqual(ch(["codex", "--remote", "ws://h:1"]), { kind: "remote", by: "--remote" });
  assert.deepEqual(ch(["codex", "--not-so-yolo"]), { kind: "on", by: "--not-so-yolo" }, "the 0.159.3 alias of --approve-for-me");
  assert.deepEqual(ch(["codex", "exec", "--not-so-yolo", "hi"]), { kind: "on", by: "--not-so-yolo" });
  // clap's `=` and attached spellings (one leading `=` stripped)
  assert.deepEqual(ch(["codex", '-c=sandbox_mode="workspace-write"']), { kind: "on", by: "-c sandbox_mode=workspace-write" });
  assert.deepEqual(ch(["codex", "-s=danger-full-access"]), { kind: "off", by: "-s danger-full-access" });
  assert.deepEqual(ch(["codex", "-pro"], { ro: 'sandbox_mode = "read-only"\n' }), { kind: "on", by: "--profile ro (sandbox_mode read-only)" });
  assert.deepEqual(ch(["codex", "-p=ro"], { ro: 'sandbox_mode = "read-only"\n' }), { kind: "on", by: "--profile ro (sandbox_mode read-only)" });
  assert.deepEqual(ch(["codex", "--enable=network_proxy"]), { kind: "on", by: "--enable network_proxy" });
  assert.equal(ch(["codex", "-c", "features.network_proxy.enabled=true"]).kind, "on");
  assert.equal(ch(["codex", "-c", "features.network_proxy={enabled=true}"]).kind, "on");
  // the network proxy keeps a Seatbelt wrap even with the bypass flag
  assert.deepEqual(ch(["codex", "--yolo", "--enable", "network_proxy"]), { kind: "on", by: "--enable network_proxy" });
  assert.equal(codexArgvProfile(["codex", "-p", "a", "exec", "--profile=b", "hi"]), "b");
  assert.equal(codexArgvProfile(["codex", "-pc", "--", "-p", "x"]), "c");
  assert.equal(codexArgvProfile(["codex"]), null);
  assert.deepEqual(ch(["codex", "--enable", "network_proxy"]), { kind: "on", by: "--enable network_proxy" });
  assert.equal(ch(["codex", "--enable", "shell_snapshot"]).kind, "none");
  assert.deepEqual(ch(["codex", "-c", "features.network_proxy=true"]), { kind: "on", by: "-c features.network_proxy=true" });
  // -c / --config / --config= / -c<kv>: sandbox_mode (last wins) and default_permissions
  assert.deepEqual(ch(["codex", "-c", 'sandbox_mode="workspace-write"']), { kind: "on", by: "-c sandbox_mode=workspace-write" });
  assert.equal(ch(["codex", "-c", 'sandbox_mode="read-only"', "exec", "-c", "sandbox_mode='danger-full-access'"]).kind, "off");
  assert.equal(ch(["codex", "--config=sandbox_mode=danger-full-access"]).kind, "off");
  assert.equal(ch(["codex", '-csandbox_mode="workspace-write"']).kind, "on");
  assert.deepEqual(ch(["codex", "-c", 'default_permissions=":workspace"']), { kind: "on", by: "-c default_permissions" });
  assert.equal(ch(["codex", "-c", 'model="o4"', "-c", "model_reasoning_effort=low"]).kind, "none");
  // -p / --profile: the profile file's sandbox_mode or default_permissions
  assert.deepEqual(ch(["codex", "-p", "fast"], { fast: 'model = "o4"\nsandbox_mode = "read-only"\n' }), { kind: "on", by: "--profile fast (sandbox_mode read-only)" });
  // a profile that turns it off is not the run's own "off" (project layers sit above it): Mandu checks the layers and says so
  assert.equal(ch(["codex", "--profile", "yolo"], { yolo: 'sandbox_mode = "danger-full-access"\n' }).kind, "none");
  assert.deepEqual(ch(["codex", "--profile=p"], { p: 'default_permissions = ":workspace"\n' }), { kind: "on", by: "--profile p (default_permissions)" });
  assert.equal(ch(["codex", "-p", "plain"], { plain: 'model = "o4"\n' }).kind, "none");
  assert.equal(ch(["codex", "-p", "missing"]).kind, "none", "an unreadable profile says nothing");
  // a profile with both keys: default_permissions outranks sandbox_mode
  assert.deepEqual(ch(["codex", "-p", "b"], { b: 'sandbox_mode = "danger-full-access"\ndefault_permissions = "p"\n' }), { kind: "on", by: "--profile b (default_permissions)" });
  assert.equal(ch(["codex", "-p", "d"], { d: 'default_permissions = ":danger-full-access"\n' }).kind, "none");
  assert.equal(ch(["codex", "-c", 'default_permissions=":danger-full-access"']).kind, "off");
  // --remote wins over everything the run asks for (the server applies it)
  for (const argv of [["codex", "--remote", "ws://h:1", "-s", "workspace-write"], ["codex", "--remote", "ws://h:1", "--yolo"], ["codex", "--yolo", "--remote=ws://h:1", "--enable", "network_proxy"]]) {
    assert.deepEqual(ch(argv), { kind: "remote", by: "--remote" }, JSON.stringify(argv));
  }
  // within the innermost command level with a sandbox -c: default_permissions
  // outranks --approve-for-me, which outranks sandbox_mode (0.159.3, codex
  // debug prompt-input); a typed -s / --yolo still beats them all
  const DP = (v: string) => `default_permissions="${v}"`;
  assert.equal(ch(["codex", "-c", DP(":workspace"), "-c", 'sandbox_mode="danger-full-access"']).kind, "on");
  assert.equal(ch(["codex", "-c", 'sandbox_mode="danger-full-access"', "-c", DP(":workspace")]).kind, "on");
  assert.equal(ch(["codex", "-c", DP(":danger-full-access"), "-c", 'sandbox_mode="read-only"']).kind, "off");
  assert.equal(ch(["codex", "--approve-for-me", "-c", DP(":danger-full-access")]).kind, "off");
  assert.deepEqual(ch(["codex", "--approve-for-me", "-c", 'sandbox_mode="danger-full-access"']), { kind: "on", by: "--approve-for-me" });
  assert.equal(ch(["codex", "-s", "danger-full-access", "-c", DP(":workspace")]).kind, "off");
  assert.equal(ch(["codex", "--yolo", "-c", DP(":workspace")]).kind, "off");
  // across levels the innermost wins (Codex reads only its list)
  assert.equal(ch(["codex", "-c", DP(":workspace"), "exec", "-c", 'sandbox_mode="danger-full-access"', "hi"]).kind, "off");
  assert.equal(ch(["codex", "-c", 'sandbox_mode="danger-full-access"', "exec", "-c", DP(":workspace"), "hi"]).kind, "on");
  assert.equal(ch(["codex", "-c", DP(":workspace"), "-m", "exec", "-c", 'sandbox_mode="danger-full-access"']).kind, "on", "a flag value is no level: both -c at the root, where default_permissions wins");
  // a -c after the prompt belongs to the innermost level (review 4)
  assert.equal(ch(["codex", "-c", DP(":danger-full-access"), "exec", "fix tests", "-c", 'sandbox_mode="workspace-write"']).kind, "on");
  assert.equal(ch(["codex", "-c", DP(":workspace"), "exec", "hi", "-c", 'sandbox_mode="danger-full-access"']).kind, "off");
  // an outer -c that turns it off is dropped by Codex: --approve-for-me then decides
  assert.equal(ch(["codex", "--approve-for-me", "-c", DP(":danger-full-access"), "exec", "hi"]).kind, "on");
  assert.equal(ch(["codex", "-c", 'sandbox_mode="danger-full-access"', "exec", "hi"]).kind, "none");
  // the run turning the network proxy off is marked (it cancels a config's)
  assert.deepEqual(ch(["codex", "--disable", "network_proxy"]), { kind: "none", netProxy: "off" });
  assert.deepEqual(ch(["codex", "--disable", "network_proxy", "--yolo"]), { kind: "off", by: "--yolo", netProxy: "off" });
  assert.deepEqual(ch(["codex", "--enable", "network_proxy", "--disable", "network_proxy"]), { kind: "none", netProxy: "off" }, "disable wins");
  // nothing after --, and a prompt that merely mentions a flag is a prompt
  assert.equal(ch(["codex", "--", "--sandbox", "read-only"]).kind, "none");
  assert.equal(ch(["codex", "exec", "please use --sandbox read-only"]).kind, "none");
  assert.equal(ch(["codex"]).kind, "none");
});

test("codexRequirementsLock / codexManagedConfigLock / codexConfigKeeps: what keeps Codex's sandbox on (conservative; comments ignored)", () => {
  assert.equal(codexRequirementsLock('allowed_sandbox_modes = ["read-only", "workspace-write"]\n'), "allowed_sandbox_modes leaves out danger-full-access");
  assert.equal(codexRequirementsLock('allowed_sandbox_modes = [\n  "read-only",\n  "danger-full-access",\n]\n'), null);
  assert.equal(codexRequirementsLock('[[remote_sandbox_config]]\nhostname_patterns = ["*"]\n'), "remote_sandbox_config");
  assert.equal(codexRequirementsLock('default_permissions = ":workspace"\n'), "permission profiles");
  assert.equal(codexRequirementsLock("[allowed_permission_profiles]\n"), "permission profiles");
  assert.equal(codexRequirementsLock('[permissions.filesystem]\ndeny_read = ["~/.ssh"]\n'), "deny_read");
  assert.equal(codexRequirementsLock("[experimental_network]\nallow = []\n"), "experimental_network");
  assert.equal(codexRequirementsLock("[features]\nnetwork_proxy = true\n"), "network_proxy");
  assert.equal(codexRequirementsLock('# allowed_sandbox_modes = ["read-only"]\nallowed_approval_policies = ["never"]\n'), null, "a comment is no rule");
  assert.equal(codexManagedConfigLock('sandbox_mode = "workspace-write"\n'), 'sandbox_mode = "workspace-write"');
  assert.equal(codexManagedConfigLock('sandbox_mode = "danger-full-access"\nmodel = "o4"\n'), null);
  assert.equal(codexManagedConfigLock("[features]\nnetwork_proxy = true\n"), "network_proxy");
  assert.equal(codexConfigKeeps(null), null);
  assert.equal(codexConfigKeeps('sandbox_mode = "workspace-write"\n'), null, "a plain default is overridden, not kept");
  // Codex 0.159.3's real spelling of a read-deny: a path whose access is "deny" (or "none")
  // A permission profile of the user's own, defined or selected, in any spelling: every filesystem
  // restriction beyond Codex's built-ins lives there (an allowlist of reads, a "deny" / "none" entry;
  // review 4), and the built-ins cannot be edited. Conservative: a network-only profile counts too.
  const PROFILE = "a permission profile of your own";
  for (const t of [
    '[permissions.p.filesystem]\n":minimal" = "read"\n"/Users/u/prod-keys" = "deny"\n',
    'default_permissions = "p"\n[permissions.p.filesystem]\n":minimal" = "read"\n":project_roots" = "write"\n', // an allowlist, no deny
    "[permissions.p.filesystem]\n'/Users/u/keys' = 'none'\n",
    '[permissions.p.filesystem.":project_roots"]\n"**/*.env" = "deny"\n',
    '[permissions."my team"]\nfilesystem = { ":minimal" = "read", "/k" = "deny" }\n',
    'permissions.p.filesystem."/k" = "deny"\n',
    '[permissions]\np.filesystem."/k" = "none"\n',
    'permissions = {\n  p = { filesystem = { "/k" = "deny" } }\n}\n', // a multi-line inline table
    '[permissions.network.filesystem]\n"/k#1" = """deny"""\n', // a profile named network, a # in a path, a triple-quoted value
    '[ permissions . p ]\nextends = ":workspace"\n',
    '"default_permissions" = "team"\n',
    '[permissions.p.network]\n"evil.example" = "deny"\n',
    '[permissions.mine.filesystem]\ndeny_read = ["secrets/"]\n', // requirements' spelling: counted too
  ]) assert.equal(codexConfigKeeps(t), PROFILE, t);
  for (const t of [
    'default_permissions = ":workspace"\n',
    'sandbox_mode = "workspace-write"\n[projects."/x"]\ntrust_level = "trusted"\n',
    '# [permissions.p.filesystem]\n# "/k" = "deny"\n',
    '[tools]\nmode = "deny"\n',
  ]) assert.equal(codexConfigKeeps(t), null, t);
  assert.equal(codexConfigKeeps("[features]\nnetwork_proxy = true\n"), null, "the network proxy has its own check");
  for (const t of ["[features]\nnetwork_proxy = true\n", "[features]\nnetwork_proxy.enabled = true\n", "[features]\nnetwork_proxy = { enabled = true, mode = \"x\" }\n",
    "[features.network_proxy]\nmode = \"limited\"\nenabled = true\n", "[profiles.p.features.network_proxy]\nenabled = true\n"]) {
    assert.equal(codexNetworkProxyOn(t), true, t);
  }
  for (const t of ["[features]\nnetwork_proxy = false\n", "[features.network_proxy]\nenabled = false\n[other]\nenabled = true\n", "# network_proxy = true\n"]) {
    assert.equal(codexNetworkProxyOn(t), false, t);
  }
  assert.equal(codexRequirementsLock("[features.network_proxy]\nenabled = true\n"), "network_proxy", "its table form locks too");
});

test("codexAdminSandboxLock: the system requirements, the legacy managed config, forced MDM preferences (unreadable counts), the cloud cache; none → null", () => {
  const files: Record<string, string> = {};
  const plists: Record<string, string | null> = {};
  const r = () => codexAdminSandboxLock({
    readFile: (p) => files[p] ?? null,
    readPlistJson: (p) => plists[p] ?? null,
    exists: (p) => p in plists,
    user: "u",
    codexHome: "/Users/u/.codex",
  });
  assert.equal(r(), null);
  files["/etc/codex/requirements.toml"] = 'allowed_sandbox_modes = ["read-only"]\n';
  assert.equal(r(), "/etc/codex/requirements.toml: allowed_sandbox_modes leaves out danger-full-access");
  delete files["/etc/codex/requirements.toml"];
  files["/etc/codex/managed_config.toml"] = 'sandbox_mode = "read-only"\n';
  assert.equal(r(), '/etc/codex/managed_config.toml: sandbox_mode = "read-only"');
  delete files["/etc/codex/managed_config.toml"];
  const b64 = (t: string): string => Buffer.from(t, "utf8").toString("base64");
  plists["/Library/Managed Preferences/u/com.openai.codex.plist"] = JSON.stringify({ requirements_toml_base64: b64('allowed_sandbox_modes = ["read-only"]') });
  assert.equal(r(), "/Library/Managed Preferences/u/com.openai.codex.plist (requirements): allowed_sandbox_modes leaves out danger-full-access");
  plists["/Library/Managed Preferences/u/com.openai.codex.plist"] = JSON.stringify({ config_toml_base64: b64('model = "o4"') });
  assert.equal(r(), null, "a managed config that does not touch the sandbox");
  plists["/Library/Managed Preferences/com.openai.codex.plist"] = null;
  assert.equal(r(), "/Library/Managed Preferences/com.openai.codex.plist: unreadable managed preferences", "fail-safe");
  delete plists["/Library/Managed Preferences/com.openai.codex.plist"];
  files["/Users/u/.codex/cloud-config-bundle-cache.json"] = JSON.stringify({ signed_payload: { bundle: { requirements_toml: { enterprise_managed: '[permissions.filesystem]\ndeny_read = ["x"]' } } } });
  assert.match(r()!, /^your organization's cloud requirements \(cached in \/Users\/u\/\.codex\/cloud-config-bundle-cache\.json\): deny_read$/);
  files["/Users/u/.codex/cloud-config-bundle-cache.json"] = "{not json";
  assert.equal(r(), null, "a broken cache is best effort");
});

test("codexSandboxLaunch on macOS: injects the override for a model run inside the profile; not for login / sandbox / --version, an explicit choice, a bypass, outside the profile, or a wrapper", () => {
  const mac = (over: Partial<CodexSandboxProbeDeps> = {}): CodexSandboxProbeDeps => ({ ...probeDeps({ platform: "darwin", path: ["codex", "sandbox-exec"] }), ...over });
  const run = (argv: string[], d = mac(), outer = true) => codexSandboxLaunch("codex", argv, d, { outerSeatbelt: outer });
  for (const argv of [["codex"], ["codex", "exec", "hi"], ["codex", "review"], ["codex", "resume", "--last"], ["codex", "-m", "o4", "e", "x"]]) {
    assert.deepEqual(run(argv), { note: CODEX_SANDBOX_OFF_NOTE, inject: CODEX_SANDBOX_OFF_ARGS }, JSON.stringify(argv));
  }
  for (const argv of [["codex", "login"], ["codex", "--version"], ["codex", "mcp", "list"], ["codex", "exec", "--help"], ["codex", "app-server", "daemon", "start"],
    // app-server's own options before its subcommand, and help
    ["codex", "app-server", "--strict-config", "generate-ts", "--out", "d"], ["codex", "app-server", "-c", "x=1", "daemon", "start"],
    ["codex", "app-server", "--enable", "foo", "proxy"], ["codex", "app-server", "--stdio", "proxy"], ["codex", "app-server", "--help"],
    ["codex", "--help", "app-server"], ["codex", "app-server", "--stdio", "help"]]) {
    assert.deepEqual(run(argv), { note: null, inject: [] }, JSON.stringify(argv));
  }
  // a bare app-server (an IDE's backend) runs sessions: the same decision,
  // with its own line (a client's per-thread sandbox overrides the default;
  // app-server takes no --sandbox)
  assert.deepEqual(run(["codex", "app-server"]), { note: CODEX_APP_SERVER_OFF_NOTE, inject: CODEX_SANDBOX_OFF_ARGS });
  assert.deepEqual(run(["codex", "-c", "x=1", "app-server", "--listen", "stdio://"]).inject, CODEX_SANDBOX_OFF_ARGS);
  assert.equal(run(["codex", "app-server", "--listen", "ws://127.0.0.1:1", "--analytics-default-enabled"]).note, CODEX_APP_SERVER_OFF_NOTE, "options only: still bare");
  for (const n of [CODEX_APP_SERVER_OFF_NOTE, CODEX_APP_SERVER_OFF_NOTE_NO_CREDS]) {
    assert.match(n, /A client that picks a sandbox for a thread overrides that default, and that thread's commands then fail/);
    assert.doesNotMatch(n, /--sandbox/);
    assert.equal(isAttentionNote(n), true);
  }
  assert.equal(codexSandboxLaunch("codex", ["codex", "app-server"], mac(), { outerSeatbelt: true, credsBlocked: false }).note, CODEX_APP_SERVER_OFF_NOTE_NO_CREDS);
  assert.doesNotMatch(CODEX_APP_SERVER_OFF_NOTE_NO_CREDS, /still keeps your credential files/);
  // codex sandbox / exec-server run commands in Codex's own sandbox: the WARNING, no override
  for (const sub of ["sandbox", "exec-server"]) {
    const r = run(["codex", sub, "--", "ls"]);
    assert.deepEqual(r.inject, []);
    assert.match(r.note!, new RegExp(`^mandu: WARNING — \`codex ${sub}\` runs commands in Codex's own sandbox, which macOS cannot start inside Mandu's profile`));
  }
  assert.deepEqual(run(["codex", "sandbox", "--", "ls"], mac(), false), { note: null, inject: [] }, "no profile: Codex's sandbox works");
  // --remote: the commands run on that server, outside Mandu's profile,
  // whatever else the run asks for (the server applies it)
  assert.deepEqual(run(["codex", "--remote", "ws://h:1"]), { note: CODEX_REMOTE_NOTE, inject: [] });
  for (const argv of [["codex", "--remote", "ws://h:1", "-s", "workspace-write"], ["codex", "--remote", "ws://h:1", "--yolo"],
    ["codex", "--remote=ws://h:1", "-s", "workspace-write"], ["codex", "--remote", "ws://h:1", "--enable", "network_proxy"]]) {
    assert.deepEqual(run(argv), { note: CODEX_REMOTE_NOTE, inject: [] }, JSON.stringify(argv));
  }
  assert.match(CODEX_REMOTE_NOTE, /runs this session's commands on that app server, outside Mandu's profile/);
  // mode off: the line does not claim credential files are blocked
  assert.deepEqual(codexSandboxLaunch("codex", ["codex"], mac(), { outerSeatbelt: true, credsBlocked: false }), { note: CODEX_SANDBOX_OFF_NOTE_NO_CREDS, inject: CODEX_SANDBOX_OFF_ARGS });
  assert.match(CODEX_SANDBOX_OFF_NOTE_NO_CREDS, /own sandbox is OFF for this session: .*In this mode Mandu's profile does not block your credential files either/);
  assert.equal(isAttentionNote(CODEX_SANDBOX_OFF_NOTE_NO_CREDS), true);
  assert.doesNotMatch(CODEX_SANDBOX_OFF_NOTE_NO_CREDS, /still keeps your credential files/);
  const explicit = run(["codex", "--sandbox", "workspace-write"]);
  assert.deepEqual(explicit.inject, []);
  assert.match(explicit.note!, /WARNING — Codex cannot run commands inside Mandu on macOS \(this run asks for Codex's own sandbox \(--sandbox workspace-write\)/);
  // off already by the run itself: no line, but the same override, since
  // Codex drops a root -c once a subcommand has its own
  assert.deepEqual(run(["codex", "--yolo"]), { note: null, inject: CODEX_SANDBOX_OFF_ARGS }, "already off: nothing to say");
  assert.deepEqual(run(["codex", "exec", "-c", 'sandbox_mode="danger-full-access"', "hi"]), { note: null, inject: CODEX_SANDBOX_OFF_ARGS }, "at the level Codex reads");
  assert.deepEqual(run(["codex", "-c", 'sandbox_mode="danger-full-access"', "exec", "hi"]), { note: CODEX_SANDBOX_OFF_NOTE, inject: CODEX_SANDBOX_OFF_ARGS }, "a root -c Codex drops: Mandu's override holds it, and says so");
  assert.deepEqual(run(["codex", "--config=sandbox_mode=danger-full-access", "exec", "hi"]).inject, CODEX_SANDBOX_OFF_ARGS);
  // a config that turns it off: the same override and the launch line (which layer Codex applies is not Mandu's to guess)
  assert.deepEqual(run(["codex"], mac({ codexConfigSandboxOff: () => true })), { note: CODEX_SANDBOX_OFF_NOTE, inject: CODEX_SANDBOX_OFF_ARGS }, "config.toml turns it off");
  assert.deepEqual(run(["codex", "-p", "yolo"], mac({ readCodexProfile: (n) => (n === "yolo" ? 'sandbox_mode = "danger-full-access"' : null), codexConfigKeeps: () => "a permission profile of your own (/repo/.codex/config.toml)" })).inject, [],
    "a -p profile that turns it off does not skip the project layers' profile (review 4)");
  assert.deepEqual(run(["codex"], mac(), false), { note: null, inject: [] }, "no profile applied: Codex's own sandbox works and stays");
  const admin = run(["codex"], mac({ codexAdminLock: () => "/etc/codex/requirements.toml: deny_read" }));
  assert.deepEqual(admin.inject, []);
  assert.match(admin.note!, /your organization's Codex settings require its own sandbox/);
  const keeps = run(["codex", "exec", "hi"], mac({ codexConfigKeeps: () => "a permission profile of your own" }));
  assert.deepEqual(keeps.inject, []);
  assert.match(keeps.note!, /your Codex config relies on its own sandbox \(a permission profile of your own\)/);
  assert.deepEqual(run(["codex", "-s", "danger-full-access"], mac({ codexConfigKeeps: () => "a permission profile of your own" })).inject, CODEX_SANDBOX_OFF_ARGS, "the run turned it off itself with a typed flag, which outranks the profile in Codex too");
  // the network proxy (config.toml or the run's profile) wins even over the run's own off
  const proxy = run(["codex", "--yolo", "-p", "np"], mac({ codexNetworkProxy: (p) => (p === "np" ? "profile np" : null) }));
  assert.deepEqual(proxy.inject, []);
  assert.match(proxy.note!, /Codex's network proxy is on \(profile np\), which runs every command in its own sandbox/);
  assert.deepEqual(run(["codex", "-p", "ro"], mac({ readCodexProfile: (n) => (n === "ro" ? 'sandbox_mode = "read-only"' : null) })).inject, []);
  // the run turning the proxy off cancels a config that turns it on
  const cfgProxy = mac({ codexNetworkProxy: () => "/Users/u/.codex/config.toml" });
  assert.match(run(["codex"], cfgProxy).note!, /Codex's network proxy is on \(\/Users\/u\/\.codex\/config\.toml\)/);
  assert.match(run(["codex"], cfgProxy).note!, /fix: pass --disable network_proxy/);
  assert.equal(CODEX_DARWIN_PROXY_FIX.startsWith("pass --disable network_proxy"), true);
  // …and the run's own "off" goes into the override, spliced at every level
  // (Codex drops a root -c once Mandu gives the subcommand its own)
  const withProxyOff = [...CODEX_SANDBOX_OFF_ARGS, ...CODEX_PROXY_OFF_ARGS];
  for (const argv of [["codex", "--disable", "network_proxy"], ["codex", "-c", "features.network_proxy=false"], ["codex", "--enable", "network_proxy", "--disable=network_proxy"],
    ["codex", "-c", "features.network_proxy=false", "exec", "hi"], ["codex", "exec", "-c", "features.network_proxy=false", "hi"]]) {
    assert.deepEqual(run(argv, cfgProxy), { note: CODEX_SANDBOX_OFF_NOTE, inject: withProxyOff }, JSON.stringify(argv));
  }
  assert.deepEqual(CODEX_PROXY_OFF_ARGS, ["-c", "features.network_proxy=false"]);
  const spliced = codexSpliceOverrides(["codex", "-c", "features.network_proxy=false", "exec", "hi"], withProxyOff);
  assert.deepEqual(spliced.slice(spliced.indexOf("exec")), ["exec", ...withProxyOff, "hi"], "the exec level, the one Codex reads, carries it");
  assert.deepEqual(run(["codex", "--disable", "network_proxy", "--yolo"], cfgProxy), { note: null, inject: withProxyOff });
  assert.deepEqual(run(["codex"], mac()).inject, CODEX_SANDBOX_OFF_ARGS, "no proxy setting: the override alone");
  // config.toml with both sandbox_mode = "danger-full-access" and a
  // default_permissions: the profile applies (it outranks the mode), so the
  // sandbox is kept, and nothing is injected
  const both = 'sandbox_mode = "danger-full-access"\ndefault_permissions = "p"\n[permissions.p.filesystem]\n":minimal" = "read"\n"/Users/u/prod-keys" = "deny"\n';
  const bothRun = run(["codex"], mac({ codexConfigSandboxOff: () => codexConfigSandboxOff(both), codexConfigKeeps: () => codexConfigKeeps(both) }));
  assert.deepEqual(bothRun.inject, []);
  assert.match(bothRun.note!, /your Codex config relies on its own sandbox \(a permission profile of your own\)/);
  // a selected profile of the user's own keeps it even with no deny entry (an allowlist of reads, review 4)
  const bothNoDeny = 'sandbox_mode = "danger-full-access"\ndefault_permissions = "p"\n';
  assert.deepEqual(run(["codex"], mac({ codexConfigSandboxOff: () => codexConfigSandboxOff(bothNoDeny), codexConfigKeeps: () => codexConfigKeeps(bothNoDeny) })).inject, []);
  // a built-in profile reads everything: Mandu turns it off and says so
  const builtin = 'default_permissions = ":workspace"\n';
  assert.deepEqual(run(["codex"], mac({ codexConfigKeeps: () => codexConfigKeeps(builtin) })), { note: CODEX_SANDBOX_OFF_NOTE, inject: CODEX_SANDBOX_OFF_ARGS });
  assert.deepEqual(codexSandboxLaunch("codex", ["./my-codex-wrapper.sh"], mac(), { outerSeatbelt: true }), { note: null, inject: [] }, "a wrapper's argv cannot be read");
  assert.deepEqual(codexSandboxLaunch("claude", ["claude"], mac(), { outerSeatbelt: true }), { note: null, inject: [] });
  // Linux: never an injection; the line as before
  const linux = codexSandboxLaunch("codex", ["codex", "exec", "hi"], probeDeps({ path: ["codex"] }));
  assert.deepEqual(linux.inject, []);
  assert.match(linux.note!, /WARNING — Codex's own sandbox cannot run commands on this machine/);
});

test("codexArgvNetworkProxy / codexNetworkProxySetting: the run's and a file's own proxy setting (disable over enable over -c; last -c wins)", () => {
  const np = codexArgvNetworkProxy;
  assert.equal(np(["codex"]), null);
  assert.deepEqual(np(["codex", "--enable", "network_proxy"]), { state: "on", by: "--enable network_proxy" });
  assert.deepEqual(np(["codex", "--disable=network_proxy"]), { state: "off", by: "--disable network_proxy" });
  assert.deepEqual(np(["codex", "--disable", "network_proxy", "--enable", "network_proxy"]), { state: "off", by: "--disable network_proxy" });
  assert.deepEqual(np(["codex", "-c", "features.network_proxy=false", "--enable", "network_proxy"]), { state: "on", by: "--enable network_proxy" }, "a toggle beats any -c");
  assert.deepEqual(np(["codex", "-c", "features.network_proxy=true", "exec", "-c", "features.network_proxy.enabled=false"]), { state: "off", by: "-c features.network_proxy.enabled=false" });
  assert.equal(np(["codex", "-c", "features.network_proxy={ enabled = false }"])!.state, "off");
  assert.equal(np(["codex", "--disable", "shell_snapshot"]), null);
  assert.equal(np(["codex", "--", "--disable", "network_proxy"]), null);
  assert.equal(np(["codex", "-s", "--disable"]), null, "a value is not a flag");
  assert.equal(codexNetworkProxySetting("[features]\nnetwork_proxy = false\n"), false);
  assert.equal(codexNetworkProxySetting("[features.network_proxy]\nenabled = false\n"), false);
  assert.equal(codexNetworkProxySetting("[features]\nnetwork_proxy = true\n"), true);
  assert.equal(codexNetworkProxySetting('model = "o4"\n'), null);
});

test("realCodexSandboxDeps (macOS readers over Codex's config layers): any layer that turns the proxy on, or has a permission profile of the user's own, keeps the sandbox, the project's .codex/config.toml (every ancestor) and a -C directory's included", () => {
  const home = mkdtempSync(join(tmpdir(), "mdu-codex-home-"));
  const repo = mkdtempSync(join(tmpdir(), "mdu-codex-repo-"));
  try {
    writeFileSync(join(home, "config.toml"), "[features]\nnetwork_proxy = true\n");
    writeFileSync(join(home, "quiet.config.toml"), "[features]\nnetwork_proxy = false\n");
    writeFileSync(join(home, "keys.config.toml"), 'default_permissions = "p"\n[permissions.p.filesystem]\n":minimal" = "read"\n"/Users/u/k" = "none"\n');
    const d = realCodexSandboxDeps({ CODEX_HOME: home, HOME: home }, home);
    assert.equal(d.codexNetworkProxy!(null), join(home, "config.toml"));
    // conservative: a higher layer that turns it off does not cancel a lower one (Codex may not apply it);
    // only the run's own "off" does
    assert.equal(d.codexNetworkProxy!("quiet"), join(home, "config.toml"));
    assert.equal(d.codexConfigKeeps!("keys"), `a permission profile of your own (${join(home, "keys.config.toml")})`);
    assert.equal(d.codexConfigKeeps!(null), null);
    assert.equal(d.codexConfigKeeps!("../x"), null, "a name with a path reads nothing");
    // a project's .codex/config.toml (Codex applies it in a trusted project, which Mandu's launch may make it): read from the repository root down to the cwd
    mkdirSync(join(repo, ".git"));
    mkdirSync(join(repo, "sub", ".codex"), { recursive: true });
    mkdirSync(join(repo, ".codex"));
    writeFileSync(join(repo, ".codex", "config.toml"), 'default_permissions = "team"\n[permissions.team.filesystem]\n":minimal" = "read"\n"/Users/u/prod-keys" = "deny"\n');
    writeFileSync(join(repo, "sub", ".codex", "config.toml"), "[features]\nnetwork_proxy = false\n");
    const p = realCodexSandboxDeps({ CODEX_HOME: home, HOME: home }, join(repo, "sub"));
    assert.equal(p.codexConfigKeeps!(null), `a permission profile of your own (${join(repo, ".codex", "config.toml")})`);
    assert.equal(p.codexNetworkProxy!(null), join(home, "config.toml"), "the cwd's layer turning it off does not cancel the user's");
    assert.equal(p.codexConfigSandboxOff!(), false, "the project's default_permissions applies");
    // a run's -C: that directory's layers too (review 4)
    const plain = mkdtempSync(join(tmpdir(), "mdu-codex-plain-"));
    try {
      assert.equal(realCodexSandboxDeps({ CODEX_HOME: plain }, plain).codexConfigKeeps!(null), null);
      assert.equal(realCodexSandboxDeps({ CODEX_HOME: plain }, plain, [join(repo, "sub")]).codexConfigKeeps!(null), `a permission profile of your own (${join(repo, ".codex", "config.toml")})`);
    } finally {
      rmSync(plain, { recursive: true, force: true });
    }
    const layers = codexConfigLayers({ CODEX_HOME: home, HOME: home }, join(repo, "sub"), "quiet", { readFile: (f) => { try { return readFileSync(f, "utf8"); } catch { return null; } }, exists: existsSync });
    assert.deepEqual(layers.map((l) => l.path), [join(home, "config.toml"), join(home, "quiet.config.toml"), join(repo, ".codex", "config.toml"), join(repo, "sub", ".codex", "config.toml")], "lowest first: user, profile, project root, cwd");
    // every ancestor's layer, from / down (Codex's project root may sit above the nearest .git: project_root_markers)
    assert.deepEqual(codexConfigLayers({ CODEX_HOME: home }, "/no/such/dir", null, { readFile: () => "x" }).map((l) => l.path),
      [CODEX_SYSTEM_CONFIG_PATH, join(home, "config.toml"), "/.codex/config.toml", "/no/.codex/config.toml", "/no/such/.codex/config.toml", "/no/such/dir/.codex/config.toml"]);
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(repo, { recursive: true, force: true });
  }
});

test("codexLayersSandboxOff: the highest layer that sets it decides, within one layer default_permissions wins; codexLayersNetworkProxy: any layer that turns it on", () => {
  const L = (...texts: string[]) => texts.map((text, i) => ({ path: `/l${i}`, text }));
  assert.equal(codexLayersSandboxOff(L('sandbox_mode = "danger-full-access"\n')), true);
  assert.equal(codexLayersSandboxOff(L('sandbox_mode = "danger-full-access"\n', 'default_permissions = ":workspace"\n')), false, "a higher layer's profile");
  assert.equal(codexLayersSandboxOff(L('default_permissions = ":workspace"\n', 'sandbox_mode = "danger-full-access"\n')), true, "a higher layer's mode");
  assert.equal(codexLayersSandboxOff(L('default_permissions = ":danger-full-access"\nsandbox_mode = "read-only"\n')), true);
  assert.equal(codexLayersSandboxOff(L('model = "o4"\n')), false);
  assert.equal(codexLayersNetworkProxy(L("[features]\nnetwork_proxy = true\n", 'model = "x"\n')), "/l0");
  assert.equal(codexLayersNetworkProxy(L("[features]\nnetwork_proxy = true\n", "[features]\nnetwork_proxy = false\n")), "/l0", "conservative: any layer that turns it on");
  assert.equal(codexLayersNetworkProxy(L("[features]\nnetwork_proxy = false\n", "[features]\nnetwork_proxy = true\n")), "/l1");
});

test("codex argv: the explicit ways to turn its sandbox off; the last mode wins; nothing past --", () => {
  const off = [
    ["codex", "--sandbox", "danger-full-access"],
    ["codex", "exec", "-s", "danger-full-access", "hi"],
    ["codex", "--sandbox=danger-full-access"],
    ["codex", "-c", "sandbox_mode=\"danger-full-access\""],
    ["codex", "--config", "sandbox_mode = 'danger-full-access'"],
    ["codex", "--config=sandbox_mode=danger-full-access"],
    ["codex", "--dangerously-bypass-approvals-and-sandbox"],
    ["codex", "--sandbox", "read-only", "--yolo"],
  ];
  for (const argv of off) assert.equal(codexArgvSandboxOff(argv), true, JSON.stringify(argv));
  const on = [
    ["codex"],
    ["codex", "--sandbox", "workspace-write"],
    ["codex", "--sandbox", "danger-full-access", "--sandbox", "read-only"],
    ["codex", "-c", "model=\"o4\""],
    ["codex", "--", "--sandbox", "danger-full-access"],
    ["codex", "exec", "please use --sandbox danger-full-access"],
  ];
  for (const argv of on) assert.equal(codexArgvSandboxOff(argv), false, JSON.stringify(argv));
});

test("codex config.toml: only a top-level sandbox_mode = \"danger-full-access\" turns it off; a profile's does not", () => {
  assert.equal(codexConfigSandboxOff(null), false);
  // a default_permissions outranks sandbox_mode in the same file
  assert.equal(codexConfigSandboxOff('sandbox_mode = "danger-full-access"\ndefault_permissions = "p"\n'), false);
  assert.equal(codexConfigSandboxOff('default_permissions = ":danger-full-access"\n'), true);
  assert.equal(codexConfigSandboxOff('default_permissions = ":workspace"\nsandbox_mode = "danger-full-access"\n'), false);
  assert.equal(codexConfigDefaultPermissions('[permissions.p]\ndefault_permissions = "x"\n'), null, "top-level only");
  assert.equal(codexConfigSandboxOff('model = "o4"\nsandbox_mode = "danger-full-access"\n'), true);
  assert.equal(codexConfigSandboxOff("sandbox_mode = 'danger-full-access'  # yes\n"), true);
  assert.equal(codexConfigSandboxOff('sandbox_mode = "workspace-write"\n'), false);
  assert.equal(codexConfigSandboxOff('# sandbox_mode = "danger-full-access"\n'), false);
  assert.equal(codexConfigSandboxOff('[profiles.fast]\nsandbox_mode = "danger-full-access"\n'), false);
  assert.equal(codexConfigPath({ CODEX_HOME: "/c", HOME: "/h" }), "/c/config.toml");
  assert.equal(codexConfigPath({ HOME: "/h" }), "/h/.codex/config.toml");
});

test("macOS: the launch and the doctor answer outerSeatbelt from /usr/bin/sandbox-exec by path; a bare `sandbox-exec` on PATH is never asked (review 2026-09-29, docs-tests-11)", () => {
  // run.ts and doctor.ts pass outerSeatbelt = sandboxExecAvailable(commandExists),
  // so the gather's own fallback lookup of the bare name never runs.
  for (const [onDisk, wantNote] of [[false, false], [true, true]] as const) {
    const asked: string[] = [];
    const d: CodexSandboxProbeDeps = {
      ...probeDeps({ platform: "darwin" }),
      commandExists: (c) => { asked.push(c); return c === "codex" || c === "sandbox-exec" || (onDisk && c === SANDBOX_EXEC); },
    };
    const outer = sandboxExecAvailable(d.commandExists);
    assert.equal(outer, onDisk, "only the absolute path counts; a PATH-only sandbox-exec is no profile");
    const note = launchCodexSandboxNote("codex", ["codex"], d, { outerSeatbelt: outer });
    assert.equal(note !== null, wantNote, String(note));
    assert.ok(!asked.includes("sandbox-exec"), asked.join(","));
  }
});

test("launch note: only for a real codex argv[0] under the codex target, and not for login / --version", () => {
  const d = probeDeps({ path: ["codex"] });
  assert.match(launchCodexSandboxNote("codex", ["codex", "exec", "hi"], d)!, /WARNING/);
  assert.match(launchCodexSandboxNote("codex", ["/usr/local/bin/codex"], d)!, /WARNING/);
  assert.equal(launchCodexSandboxNote("codex", ["./my-codex-wrapper.sh"], d), null);
  assert.equal(launchCodexSandboxNote("claude", ["claude"], d), null);
  assert.equal(launchCodexSandboxNote("codex", ["codex", "login"], d), null);
  assert.equal(launchCodexSandboxNote("codex", ["codex", "--version"], d), null);
  assert.equal(launchCodexSandboxNote("codex", ["codex"], probeDeps({ path: ["codex", "bwrap"], probe: true })), null);
});

test("Mandu's own bubblewrap in force counts as the bwrap Codex gets under mandu (a launch puts it first on PATH)", () => {
  const deps = (inForce: boolean, probe: boolean): CodexSandboxProbeDeps => ({
    platform: () => "linux",
    commandExists: (c) => c === "codex", // no system bwrap on PATH
    readKnob: (p) => (p === APPARMOR_USERNS_SYSCTL ? "1\n" : null),
    bwrapProbe: () => probe,
    manduBwrapInForce: () => inForce,
  });
  const f = gatherCodexSandbox(deps(true, true));
  assert.equal(f.systemBwrap, true);
  assert.equal(assessCodexSandbox(f).state, "ok");
  assert.equal(assessCodexSandbox(gatherCodexSandbox(deps(false, true))).state, "no-bwrap");
  // the fix for a denied system bwrap names Mandu's own, never a grant for /usr/bin/bwrap
  const denied = assessCodexSandbox({ ...stock, systemBwrap: true, systemBwrapOk: false });
  assert.match(denied.fix!, /Mandu's own bubblewrap/);
  assert.doesNotMatch(denied.fix!, /\/usr\/bin\/bwrap/);
});

test("codexAllConfigLayers: the run's -p profile and -C directory layers, plus the managed config above the command line", () => {
  const files: Record<string, string> = {
    [CODEX_SYSTEM_CONFIG_PATH]: "s",
    "/h/config.toml": "u",
    "/h/work.config.toml": "p",
    "/w/.codex/config.toml": "proj",
    "/w/sub/.codex/config.toml": "cd",
    [CODEX_MANAGED_CONFIG_PATH]: "m",
  };
  const read = (f: string): string | null => files[f] ?? null;
  const layers = codexAllConfigLayers({ CODEX_HOME: "/h" }, "/w", ["codex", "-p", "work", "exec", "-C", "sub", "hi"], read);
  assert.deepEqual(layers.map((l) => l.text), ["s", "u", "p", "proj", "cd", "m"]);
  assert.deepEqual(codexAllConfigLayers({ CODEX_HOME: "/h" }, "/w", ["codex"], read).map((l) => l.text), ["s", "u", "proj", "m"]);
});
