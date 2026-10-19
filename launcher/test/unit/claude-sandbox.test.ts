/**
 * claude-sandbox.test — plan 10 §12.3: coexistence with Claude Code's own
 * sandbox and credential mask. Pure functions over fixture settings files.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  assessClaudeSandbox, checkClaudeSandbox, claudeArgvSettings, claudeArgvSettingSources, claudeRunsSession, claudeSettingsFiles,
  CLAUDE_MANAGED_SETTINGS_DARWIN, CLAUDE_SANDBOX_OFF_NOTE, CLAUDE_SANDBOX_OFF_NOTE_NO_CREDS, claudeConfigDir, expandClaudeSettingsPath,
  findGitRoot, mergeClaudeSettingsArg, mergeSettings, claudeCanonicalRoot, claudeMdmPlists, claudeSettingsLocations, claudeStatusProbeAllowed,
  readClaudeSettingsSources, CLAUDE_SANDBOX_STATUS_SINCE, claudeArgvSettingsMoves, claudeReadDenyPath, claudeRuleContent,
  parseClaudeSandboxStatus, parseClaudeSettingsValue, planDarwinClaudeSandbox, readClaudeSandbox, unixSocketSpellings,
  type ClaudeSandboxStatus, type ClaudeSandboxView,
} from "../../src/claude-sandbox.js";
import { isAttentionNote } from "../../src/launch-banner.js";
import { userInfo } from "node:os";
import { postureFindings } from "../../src/services/observe.js";

const HOME = "/home/u";
const CWD = "/home/u/proj";
// Pinned to Linux (the managed file and the notes are platform-specific);
// the macOS cases below pass "darwin".
const files = claudeSettingsFiles(HOME, CWD, "linux");
const byScope = (scope: string) => files.find((f) => f.scope === scope)!;

function withTexts(texts: Partial<Record<"user" | "project" | "local" | "managed", string>>) {
  return files.map((f) => ({ ...f, text: texts[f.scope] ?? null }));
}

test("settings files: user, project, local, managed; paths expand per the file's prefix rules", () => {
  assert.deepEqual(files.map((f) => f.path), ["/home/u/.claude/settings.json", "/home/u/proj/.claude/settings.json", "/home/u/proj/.claude/settings.local.json", "/etc/claude-code/managed-settings.json"]);
  assert.equal(expandClaudeSettingsPath("~/.aws/credentials", byScope("user"), HOME, CWD), "/home/u/.aws/credentials");
  assert.equal(expandClaudeSettingsPath("./secrets.json", byScope("project"), HOME, CWD), "/home/u/proj/secrets.json");
  assert.equal(expandClaudeSettingsPath("./x.json", byScope("user"), HOME, CWD), "/home/u/.claude/x.json");
  assert.equal(expandClaudeSettingsPath("/etc/token", byScope("managed"), HOME, CWD), "/etc/token");
  // a launch from HOME: the project file IS the user file — read once, as the user scope
  const fromHome = claudeSettingsFiles(HOME, HOME, "linux");
  assert.deepEqual(fromHome.map((f) => [f.scope, f.path]), [["user", "/home/u/.claude/settings.json"], ["local", "/home/u/.claude/settings.local.json"], ["managed", "/etc/claude-code/managed-settings.json"]]);
});

test("read: enabled by any file, mask entries only from user/managed, lists merged, a broken file named", () => {
  const v = readClaudeSandbox(withTexts({
    user: JSON.stringify({ sandbox: { enabled: true, network: { allowUnixSockets: ["/run/a.sock"] }, credentials: {
      files: [{ path: "~/.aws/credentials", mode: "mask" }, { path: "~/.netrc", mode: "deny" }],
      envVars: [{ name: "GH_TOKEN", mode: "mask" }, { name: "NPM_TOKEN" }],
    } } }),
    project: JSON.stringify({ sandbox: { credentials: { files: [{ path: "./.env", mode: "mask" }, { path: "./id_rsa", mode: "deny" }] }, network: { allowUnixSockets: ["/run/a.sock", "/run/b.sock"] } } }),
    local: "{ not json",
  }), HOME, CWD);
  assert.equal(v.enabled, true);
  assert.deepEqual(v.enabledBy, ["/home/u/.claude/settings.json"]);
  assert.deepEqual(v.files.map((f) => [f.resolved, f.mode]), [["/home/u/.aws/credentials", "mask"], ["/home/u/.netrc", "deny"], ["/home/u/proj/id_rsa", "deny"]], "the project's mask entry is ignored, as Claude Code ignores it");
  assert.deepEqual(v.envVars.map((e) => [e.name, e.mode]), [["GH_TOKEN", "mask"], ["NPM_TOKEN", "deny"]]);
  assert.deepEqual(v.allowUnixSockets, ["/run/a.sock", "/run/b.sock"]);
  assert.equal(v.errors.length, 1);
  assert.match(v.errors[0]!, /settings\.local\.json/);
  // no sandbox anywhere
  const off = readClaudeSandbox(withTexts({ user: JSON.stringify({ model: "opus" }) }), HOME, CWD);
  assert.equal(off.enabled, false);
  assert.deepEqual([off.files, off.envVars, off.errors], [[], [], []]);
});

test("assess: a file masked by both sides is a WARNING naming the setting file; a deny is a note; the overlay carries the arbiter socket", () => {
  const v = readClaudeSandbox(withTexts({
    user: JSON.stringify({ sandbox: { enabled: true, credentials: {
      files: [{ path: "~/.aws/credentials", mode: "mask" }, { path: "~/.pgpass", mode: "deny" }, { path: "~/other", mode: "mask" }],
      envVars: [{ name: "GH_TOKEN", mode: "mask" }, { name: "UNRELATED", mode: "mask" }],
    } } }),
  }), HOME, CWD);
  const a = assessClaudeSandbox(v, { confined: ["/home/u/.aws/credentials", "/home/u/.pgpass"], maskedEnv: ["GH_TOKEN"], arbiterSock: "/run/user/1/mandu/arbiter.sock", platform: "linux" });
  assert.deepEqual(a.doubleMaskedFiles, [{ path: "~/.aws/credentials", source: "/home/u/.claude/settings.json" }]);
  assert.deepEqual(a.doubleMaskedEnv, [{ name: "GH_TOKEN", source: "/home/u/.claude/settings.json" }]);
  const text = a.notes.join("\n");
  assert.match(text, /^mandu: Claude Code's own sandbox is ON \(\/home\/u\/\.claude\/settings\.json\)/m);
  assert.match(text, /WARNING: mandu: 1 credential file is masked TWICE — by Claude Code's sandbox\.credentials\.files in \/home\/u\/\.claude\/settings\.json \(~\/\.aws\/credentials\)/);
  assert.match(text, /Remove that entry from \/home\/u\/\.claude\/settings\.json/);
  assert.match(text, /DENIES 1 file Mandu confines \(~\/\.pgpass/);
  assert.match(text, /WARNING: mandu: 1 environment variable is masked TWICE .*\(GH_TOKEN\)/);
  assert.doesNotMatch(text, /UNRELATED|~\/other/);
  assert.deepEqual(a.settingsOverlay, { sandbox: { network: { allowUnixSockets: ["/run/user/1/mandu/arbiter.sock"] } } });
  // sandbox off: no overlay, no ON line, but a mask overlap still warns (Claude Code honors credentials without the sandbox? no —
  // it does not, but the entry is a latent double mask the moment /sandbox is turned on, so the user hears about it once)
  const off = assessClaudeSandbox({ ...v, enabled: false, enabledBy: [] }, { confined: ["/home/u/.aws/credentials"], maskedEnv: [], arbiterSock: "/s", platform: "linux" });
  assert.equal(off.settingsOverlay, null);
  assert.ok(!off.notes.some((n) => /own sandbox is ON/.test(n)));
  assert.ok(off.notes.some((n) => /masked TWICE/.test(n)));
});

test("mergeSettings and the --settings splice: merged into an inline JSON, appended otherwise; a file argument is left alone", () => {
  assert.deepEqual(mergeSettings({ tui: "default", sandbox: { network: { allowUnixSockets: ["/a"] } } }, { sandbox: { network: { allowUnixSockets: ["/a", "/b"] } } }),
    { tui: "default", sandbox: { network: { allowUnixSockets: ["/a", "/b"] } } });
  const overlay = { sandbox: { network: { allowUnixSockets: ["/s"] } } };
  const a = ["--settings", JSON.stringify({ tui: "default" }), "--mcp-config", "x.json"];
  mergeClaudeSettingsArg(a, overlay);
  assert.deepEqual(a, ["--settings", JSON.stringify({ tui: "default", sandbox: { network: { allowUnixSockets: ["/s"] } } }), "--mcp-config", "x.json"], "one --settings, the TUI pin kept");
  const b = ["--mcp-config", "x.json"];
  mergeClaudeSettingsArg(b, overlay);
  assert.deepEqual(b, ["--mcp-config", "x.json", "--settings", JSON.stringify(overlay)]);
  const c = ["--settings", "/home/u/mine.json"];
  mergeClaudeSettingsArg(c, overlay);
  assert.deepEqual(c, ["--settings", "/home/u/mine.json", "--settings", JSON.stringify(overlay)]);
});

test("checkClaudeSandbox: the I/O wrapper reads the four files through the injected reader; a missing file is not an error", () => {
  const seen: string[] = [];
  const r = checkClaudeSandbox({
    home: HOME, cwd: CWD, confined: ["/home/u/.netrc"], maskedEnv: [], arbiterSock: "/s", platform: "linux",
    readFile: (p) => { seen.push(p); return p.endsWith("/.claude/settings.json") && p.startsWith("/home/u/.claude") ? JSON.stringify({ sandbox: { enabled: true, credentials: { files: [{ path: "~/.netrc", mode: "mask" }] } } }) : null; },
  });
  assert.deepEqual(seen, files.map((f) => f.path));
  assert.equal(r.view.enabled, true);
  assert.equal(r.doubleMaskedFiles.length, 1);
  assert.deepEqual(r.view.errors, []);
});

// ── macOS (2026-09-29): a sandbox inside Mandu's Seatbelt profile cannot start ──

const MAC_HOME = "/Users/u";
const MAC_SOCK = "/var/folders/gc/x/T/mandu/current/arbiter.sock";
const MAC_REAL = "/private/var/folders/gc/x/T/mandu/instances/20260929-0216-335883df-p1/arbiter.sock";
const macOn = () => readClaudeSandbox(
  claudeSettingsFiles(MAC_HOME, "/Users/u/proj", "darwin").map((f) => ({
    ...f, text: f.scope === "user" ? JSON.stringify({ sandbox: { enabled: true } }) : null,
  })),
  MAC_HOME, "/Users/u/proj",
);

test("macOS settings files: the managed file is /Library/Application Support/ClaudeCode's", () => {
  const mac = claudeSettingsFiles(MAC_HOME, "/Users/u/proj", "darwin");
  assert.equal(mac.find((f) => f.scope === "managed")!.path, CLAUDE_MANAGED_SETTINGS_DARWIN);
  assert.equal(CLAUDE_MANAGED_SETTINGS_DARWIN, "/Library/Application Support/ClaudeCode/managed-settings.json");
});

test("macOS, sandbox ON inside Mandu's profile: ONE WARNING line naming the file and the setting; no 'bubblewrap'", () => {
  const a = assessClaudeSandbox(macOn(), { confined: [], maskedEnv: [], arbiterSock: MAC_SOCK, platform: "darwin", realpath: () => MAC_REAL });
  assert.equal(a.notes.length, 1);
  const n = a.notes[0]!;
  assert.match(n, /^WARNING: mandu: Claude Code's own sandbox is ON \(\/Users\/u\/\.claude\/settings\.json\), and on macOS it cannot start inside Mandu's Seatbelt profile/);
  assert.match(n, /sandbox_apply: Operation not permitted/);
  assert.match(n, /set "sandbox": \{ "enabled": false \} in \/Users\/u\/\.claude\/settings\.json \(or run \/sandbox in Claude Code\)/);
  assert.doesNotMatch(n, /bubblewrap|seccomp/);
  assert.equal(n.includes("\n"), false);
  assert.equal(isAttentionNote(n), true, "the compact launch display shows it");
  assert.deepEqual(postureFindings([n]).dropped, [], "a user setting, not a dropped rung: doctor --live L1 does not grade it");
});

test("macOS allowUnixSockets: the given spelling, its realpath, and the /private forms; Linux keeps the one literal path", () => {
  const a = assessClaudeSandbox(macOn(), { confined: [], maskedEnv: [], arbiterSock: MAC_SOCK, platform: "darwin", realpath: () => MAC_REAL });
  assert.deepEqual(a.settingsOverlay, { sandbox: { network: { allowUnixSockets: [MAC_SOCK, MAC_REAL, "/private" + MAC_SOCK] } } });
  assert.deepEqual(unixSocketSpellings("/tmp/a.sock", "darwin", () => null), ["/tmp/a.sock", "/private/tmp/a.sock"]);
  assert.deepEqual(unixSocketSpellings("/Users/u/a.sock", "darwin", (p) => p), ["/Users/u/a.sock"], "a canonical path is itself");
  assert.deepEqual(unixSocketSpellings("/run/user/1/mandu/arbiter.sock", "linux", () => "/elsewhere"), ["/run/user/1/mandu/arbiter.sock"]);
  assert.deepEqual(unixSocketSpellings("", "darwin", () => "/x"), [""]);
});

test("macOS with no Mandu profile around the launch (outerSeatbelt false): a plain note, the socket spellings still passed", () => {
  const a = assessClaudeSandbox(macOn(), { confined: [], maskedEnv: [], arbiterSock: MAC_SOCK, platform: "darwin", outerSeatbelt: false, realpath: () => MAC_REAL });
  assert.equal(a.notes.length, 1);
  assert.match(a.notes[0]!, /^mandu: Claude Code's own sandbox is ON .*its own Seatbelt sandbox/);
  assert.equal(isAttentionNote(a.notes[0]!), false);
  assert.doesNotMatch(a.notes[0]!, /bubblewrap/);
  assert.equal((a.settingsOverlay!.sandbox as { network: { allowUnixSockets: string[] } }).network.allowUnixSockets.length, 3);
});

test("checkClaudeSandbox on macOS: reads the macOS managed file and defaults to the outer-profile WARNING", () => {
  const seen: string[] = [];
  const r = checkClaudeSandbox({
    home: MAC_HOME, cwd: "/Users/u/proj", confined: [], maskedEnv: [], arbiterSock: MAC_SOCK, platform: "darwin", realpath: () => null,
    readFile: (p) => { seen.push(p); return p === "/Users/u/.claude/settings.json" ? JSON.stringify({ sandbox: { enabled: true } }) : null; },
  });
  assert.ok(seen.includes(CLAUDE_MANAGED_SETTINGS_DARWIN));
  assert.match(r.notes[0]!, /^WARNING: mandu: Claude Code's own sandbox is ON/);
});

// ── macOS (decided 2026-10-02): Mandu turns Claude Code's own sandbox off for the session ──

test("the last --settings (split or = form) before --, its --setting-sources, and a value read as Claude Code reads it", () => {
  assert.equal(claudeArgvSettings(["claude", "-p", "hi"]), null);
  assert.deepEqual(claudeArgvSettings(["claude", "--settings", "{\"a\":1}", "--settings=/x.json", "-p", "hi"]), { index: 3, form: "eq", value: "/x.json" });
  assert.deepEqual(claudeArgvSettings(["claude", "--settings=/x.json", "--settings", "{}"]), { index: 2, form: "split", value: "{}" });
  assert.equal(claudeArgvSettings(["claude", "--", "--settings", "{}"]), null, "nothing after --");
  // the whole argv (Claude Code may take a `--` as an option's value), and the options that move a source
  assert.deepEqual(claudeArgvSettingSources(["claude", "--setting-sources", "user,project", "--setting-sources=local", "--managed-settings", "{}", "--project-config-root=/w", "-p", "hi"]),
    ["--setting-sources", "user,project", "--setting-sources=local", "--managed-settings", "{}", "--project-config-root=/w"]);
  assert.deepEqual(claudeArgvSettingSources(["claude", "--append-system-prompt", "--", "--managed-settings", "{}"]), ["--managed-settings", "{}"]);
  const files: Record<string, string> = { "/s.json": '{"model":"opus"}', "/arr.json": "[1]" };
  const read = (p: string): string | null => files[p] ?? null;
  assert.deepEqual(parseClaudeSettingsValue(' {"tui":"default"} ', read), { tui: "default" });
  assert.deepEqual(parseClaudeSettingsValue("/s.json", read), { model: "opus" });
  assert.equal(parseClaudeSettingsValue("/arr.json", read), null, "not an object");
  assert.equal(parseClaudeSettingsValue("/missing.json", read), null);
  assert.equal(parseClaudeSettingsValue("{broken", read), null);
});

test("the status probe's answer: its last JSON line with a statusVersion and a boolean enabled; anything else is no answer", () => {
  const line = (o: object): string => JSON.stringify(o);
  assert.deepEqual(parseClaudeSandboxStatus(`noise\n${line({ statusVersion: 3, enabled: true, enabledSource: "settings" })}\n`), { enabled: true, source: "settings" });
  assert.deepEqual(parseClaudeSandboxStatus(line({ statusVersion: 3, enabled: false })), { enabled: false, source: null });
  assert.equal(parseClaudeSandboxStatus(line({ enabled: true })), null, "no statusVersion");
  assert.equal(parseClaudeSandboxStatus(line({ statusVersion: 3, enabled: "yes" })), null);
  assert.equal(parseClaudeSandboxStatus("error: unknown command 'sandbox'"), null, "not the status JSON (an error line)");
});

test("claudeRunsSession: the TUI and -p are sessions; --version / --help and the non-session subcommands are not", () => {
  for (const a of [["claude"], ["claude", "-p", "hi"], ["claude", "--model", "opus", "fix it"], ["claude", "-p", "--", "--help"]]) assert.equal(claudeRunsSession(a), true, JSON.stringify(a));
  for (const a of [["claude", "--version"], ["claude", "-v"], ["claude", "--help"], ["claude", "mcp", "list"], ["claude", "doctor"], ["claude", "update"], ["claude", "upgrade"], ["claude", "import"], ["claude", "sandbox", "status"]]) assert.equal(claudeRunsSession(a), false, JSON.stringify(a));
});

const VIEW_OFF: ClaudeSandboxView = { enabled: false, enabledBy: [], files: [], envVars: [], allowUnixSockets: [], sources: [], errors: [] };
const VIEW_ON: ClaudeSandboxView = { ...VIEW_OFF, enabled: true, enabledBy: ["/Users/u/.claude/settings.json"] };

/** A fake `claude sandbox status`: on from the settings files unless the
 *  given --settings says otherwise; `managed` keeps it on whatever it says. */
function fakeProbe(o: { fileOn: boolean; managed?: boolean; absent?: boolean }) {
  const calls: string[][] = [];
  const probe = (args: string[]): ClaudeSandboxStatus | null => {
    calls.push(args);
    if (o.absent) return null;
    if (o.managed) return { enabled: true, source: "policy" };
    const s = claudeArgvSettings(["claude", ...args]);
    type S = { sandbox?: { enabled?: boolean } };
    const parse = (t: string): S | null => { try { return JSON.parse(t) as S; } catch { return null; } };
    const v = s && s.value.trim().startsWith("{") ? parse(s.value) : null;
    if (v?.sandbox?.enabled !== undefined) return { enabled: v.sandbox.enabled, source: "policy" };
    return { enabled: o.fileOn, source: o.fileOn ? "settings" : "off" };
  };
  return { probe, calls };
}

const plan = (o: Partial<Parameters<typeof planDarwinClaudeSandbox>[0]> & { probe: Parameters<typeof planDarwinClaudeSandbox>[0]["probe"] }) =>
  planDarwinClaudeSandbox({ argv: ["claude"], argvPrefix: ["--mcp-config", "/m.json"], view: VIEW_ON, confined: [], maskedEnv: [], readFile: () => null, realpath: (p) => p, isDir: () => false, hasContent: () => true, ...o });

test("macOS plan: off by default → nothing; on from the settings files → Mandu adds enabled:false to its own --settings (merged with the TUI pin), probes it off, ONE attention line", () => {
  const off = fakeProbe({ fileOn: false });
  assert.deepEqual(plan({ probe: off.probe, view: VIEW_OFF }), { notes: [], off: false });
  assert.deepEqual(off.calls, [[]], "one probe, the run's own settings only");
  const on = fakeProbe({ fileOn: true });
  const r = plan({ probe: on.probe, argvPrefix: ["--settings", '{"tui":"default"}', "--mcp-config", "/m.json"] });
  assert.equal(r.off, true);
  assert.deepEqual(r.notes, [CLAUDE_SANDBOX_OFF_NOTE]);
  assert.deepEqual(r.argvPrefix, ["--settings", JSON.stringify({ tui: "default", sandbox: { enabled: false } }), "--mcp-config", "/m.json"]);
  assert.deepEqual(r.argv, ["claude"]);
  assert.deepEqual(on.calls[1], ["--settings", JSON.stringify({ tui: "default", sandbox: { enabled: false } })], "the second probe sees exactly the final --settings");
  assert.equal(isAttentionNote(CLAUDE_SANDBOX_OFF_NOTE), true);
  assert.match(CLAUDE_SANDBOX_OFF_NOTE, /own sandbox is OFF for this session: macOS cannot start it inside Mandu's profile\. Mandu's profile still keeps your credential files/);
  assert.deepEqual(postureFindings([CLAUDE_SANDBOX_OFF_NOTE]), { live: [], dropped: [] }, "not read as a dropped rung");
  const plain = plan({ probe: fakeProbe({ fileOn: true }).probe });
  assert.deepEqual(plain.argvPrefix, ["--mcp-config", "/m.json", "--settings", '{"sandbox":{"enabled":false}}'], "appended when Mandu has no --settings of its own");
});

test("macOS plan: the user's own inline --settings (Claude Code reads only the last) gets enabled:false merged in, split or = form; Mandu's prefix is left as is", () => {
  const p1 = fakeProbe({ fileOn: true });
  const r1 = plan({ probe: p1.probe, argv: ["claude", "--settings", '{"model":"opus"}', "-p", "hi"] });
  assert.equal(r1.off, true);
  assert.deepEqual(r1.argv, ["claude", "--settings", JSON.stringify({ model: "opus", sandbox: { enabled: false } }), "-p", "hi"]);
  assert.deepEqual(r1.argvPrefix, ["--mcp-config", "/m.json"]);
  assert.deepEqual(p1.calls[0], ["--settings", '{"model":"opus"}']);
  const r2 = plan({ probe: fakeProbe({ fileOn: true }).probe, argv: ["claude", "--setting-sources", "user", '--settings={"permissions":{"allow":["Bash(ls:*)"]}}'] });
  assert.deepEqual(r2.argv, ["claude", "--setting-sources", "user", `--settings=${JSON.stringify({ permissions: { allow: ["Bash(ls:*)"] }, sandbox: { enabled: false } })}`]);
});

test("macOS plan: the sandbox stays, with a WARNING, when the run's --settings turns it on, is a FILE (never copied onto the command line), is not an object, or managed settings keep it on", () => {
  const explicit = plan({ probe: fakeProbe({ fileOn: true }).probe, argv: ["claude", "--settings", '{"sandbox":{"enabled":true}}'] });
  assert.equal(explicit.off, false);
  assert.match(explicit.notes[0]!, /^WARNING: mandu: Claude Code's own sandbox is ON for this run \(your --settings\), and on macOS it cannot start inside Mandu's Seatbelt profile .*\. Drop sandbox\.enabled from that --settings/);
  assert.equal(explicit.argv, undefined, "nothing changed");
  const read: string[] = [];
  const file = plan({ probe: fakeProbe({ fileOn: true }).probe, argv: ["claude", "--settings", "/s.json"], readFile: (p) => { read.push(p); return '{"model":"opus"}'; } });
  assert.equal(file.off, false);
  assert.match(file.notes[0]!, /This run's --settings is a file \(\/s\.json\): Mandu does not copy a settings file onto the command line, where every program the AI runs could read it/);
  assert.equal(file.argv, undefined);
  const fileOn = plan({ probe: fakeProbe({ fileOn: true }).probe, argv: ["claude", "--settings", "/on.json"], readFile: () => '{"sandbox":{"enabled":true}}' });
  assert.match(fileOn.notes[0]!, /for this run \(your --settings\)/, "a file that turns it on is the run's choice");
  // Mandu never turns it off for a --settings FILE: the advice names both steps
  assert.match(fileOn.notes[0]!, /Drop sandbox\.enabled from that settings file \(\/on\.json\) and pass its settings inline/);
  const notObject = plan({ probe: fakeProbe({ fileOn: true }).probe, argv: ["claude", "--settings", "{broken}"] });
  assert.match(notObject.notes[0]!, /could not add its setting to this run's --settings \(not a JSON object\)/);
  const managed = plan({ probe: fakeProbe({ fileOn: true, managed: true }).probe });
  assert.equal(managed.off, false);
  assert.match(managed.notes[0]!, /^WARNING: mandu: Claude Code's own sandbox is ON by your organization's managed settings, .*Mandu cannot turn managed settings off/);
  for (const r of [explicit, file, notObject, managed]) assert.equal(isAttentionNote(r.notes[0]!), true);
});

test("macOS plan: Claude Code says on but no settings file Mandu reads turns it on (another config dir, a worktree's main checkout): rules unknown, the sandbox stays", () => {
  const r = plan({ probe: fakeProbe({ fileOn: true }).probe, view: VIEW_OFF });
  assert.equal(r.off, false);
  assert.match(r.notes[0]!, /own sandbox is ON from settings Mandu cannot read, .*Mandu cannot check what their sandbox rules protect, so it leaves it on/);
});

test("macOS plan: sandbox rules Mandu does not cover keep the sandbox (credentials, denyRead, in the files or the run's own --settings); covered ones (same file by realpath, a masked variable) do not; mode off covers nothing", () => {
  const view: ClaudeSandboxView = {
    ...VIEW_ON,
    files: [{ path: "~/.aws/credentials", resolved: "/Users/u/.aws/credentials", mode: "deny", source: "/Users/u/.claude/settings.json" }],
    envVars: [{ name: "GH_TOKEN", mode: "mask", source: "/Users/u/.claude/settings.json" }],
  };
  const kept = plan({ probe: fakeProbe({ fileOn: true }).probe, view });
  assert.equal(kept.off, false);
  assert.match(kept.notes[0]!, /Mandu leaves it on because its sandbox rules \(sandbox\.credentials, sandbox\.filesystem\.denyRead, permissions\.deny Read rules\) protect ~\/\.aws\/credentials, \$GH_TOKEN, which Mandu does not protect: label them in Mandu's policy/);
  const covered = plan({
    probe: fakeProbe({ fileOn: true }).probe, view,
    confined: ["/private/aws-real"], maskedEnv: ["GH_TOKEN"],
    realpath: (p) => (p === "/Users/u/.aws/credentials" || p === "/private/aws-real" ? "/private/aws-real" : p),
  });
  assert.equal(covered.off, true, "Mandu blocks the same file (by its real path) and masks the variable");
  // mode off: the profile blocks nothing, so nothing is covered, and the fix names mode secrets
  const off = plan({ probe: fakeProbe({ fileOn: true }).probe, view, confined: ["/Users/u/.aws/credentials"], maskedEnv: ["GH_TOKEN"], credsBlocked: false });
  assert.match(off.notes[0]!, /in mode secrets, label them in Mandu's policy/);
  // a read-deny Mandu does not confine; a folder or glob can never count as
  // covered, so its advice is not "label it" alone
  const deny = plan({ probe: fakeProbe({ fileOn: true }).probe, view: { ...VIEW_ON, denyRead: [{ path: "~/secrets/", resolved: "/Users/u/secrets", source: "/Users/u/.claude/settings.json" }] } });
  assert.equal(deny.off, false);
  assert.match(deny.notes[0]!, /protect ~\/secrets\/, which is not a single file Mandu can protect: list the files themselves instead \(and label those in Mandu's policy\), or remove that entry for sessions under mandu/);
  assert.doesNotMatch(deny.notes[0]!, /~\/secrets\/, which Mandu does not protect: label/);
  // mode off: labelling covers nothing, so the advice names mode secrets
  const denyOff = plan({ probe: fakeProbe({ fileOn: true }).probe, credsBlocked: false, view: { ...VIEW_ON, denyRead: [{ path: "~/secrets/", resolved: "/Users/u/secrets", source: "/Users/u/.claude/settings.json" }] } });
  assert.match(denyOff.notes[0]!, /not a single file Mandu can protect: in mode secrets, list the files themselves instead/);
  const dir = plan({ probe: fakeProbe({ fileOn: true }).probe, isDir: (p) => p === "/Users/u/.ssh", confined: ["/Users/u/.ssh"],
    view: { ...VIEW_ON, denyRead: [{ path: "~/.ssh", resolved: "/Users/u/.ssh", source: "/Users/u/.claude/settings.json" }] } });
  assert.match(dir.notes[0]!, /protect ~\/\.ssh, which is not a single file/, "a folder (by stat) is never covered");
  const glob = plan({ probe: fakeProbe({ fileOn: true }).probe, view: { ...VIEW_ON, denyRead: [{ path: "~/.aws/*", resolved: "/Users/u/.aws/*", source: "/Users/u/.claude/settings.json" }] } });
  assert.match(glob.notes[0]!, /protect ~\/\.aws\/\*, which is not a single file/);
  // the run's own --settings: its rules count too (a relative path never counts as covered)
  const flag = plan({ probe: fakeProbe({ fileOn: true }).probe, home: "/Users/u", argv: ["claude", "--settings", JSON.stringify({ sandbox: { credentials: { files: [{ path: "~/.npmrc", mode: "mask" }], envVars: [{ name: "NPM_TOKEN" }] }, filesystem: { denyRead: ["./keys", "secret.pem"] } } })] });
  assert.equal(flag.off, false);
  assert.match(flag.notes[0]!, /protect ~\/\.npmrc, \$NPM_TOKEN, which Mandu does not protect: label them in Mandu's policy \(policy\.yaml\); and \.\/keys, secret\.pem, which are relative paths Mandu does not resolve: write them as an absolute path/);
  assert.doesNotMatch(flag.notes[0]!, /secret\.pem[^;]*not a single file/, "a relative single file is not called a folder");
  // a relative rule in a settings FILE never counts as covered either: Claude
  // Code resolves it against its own root (review 3: "../.env" in a project
  // file protects the folder above, not the confined cwd/.env)
  const rel = plan({ probe: fakeProbe({ fileOn: true }).probe, confined: ["/Users/u/work/app/.env"],
    view: { ...VIEW_ON, denyRead: [{ path: "../.env", resolved: "/Users/u/work/.env", source: "/Users/u/work/app/.claude/settings.json" }] } });
  assert.equal(rel.off, false);
  assert.match(rel.notes[0]!, /\.\.\/\.env, which is a relative path Mandu does not resolve/);
  // a missing or empty file cannot be labelled: the advice is to remove it
  const absent = plan({ probe: fakeProbe({ fileOn: true }).probe, hasContent: () => false,
    view: { ...VIEW_ON, denyRead: [{ path: "~/.netrc", resolved: "/Users/u/.netrc", source: "/Users/u/.claude/settings.json" }] } });
  assert.equal(absent.off, false);
  assert.match(absent.notes[0]!, /~\/\.netrc, which is missing or empty on this Mac \(Mandu protects only files that exist when the session starts, so a label cannot help\): remove that entry/);
  assert.doesNotMatch(absent.notes[0]!, /label them/);
  const flagCovered = plan({ probe: fakeProbe({ fileOn: true }).probe, home: "/Users/u", confined: ["/Users/u/.npmrc"], argv: ["claude", "--settings", JSON.stringify({ sandbox: { credentials: { files: [{ path: "~/.npmrc", mode: "deny" }] } } })] });
  assert.equal(flagCovered.off, true);
});

test("macOS plan in mode off (no credential file blocked): the OFF line says so instead of claiming protection", () => {
  const r = plan({ probe: fakeProbe({ fileOn: true }).probe, credsBlocked: false });
  assert.deepEqual(r.notes, [CLAUDE_SANDBOX_OFF_NOTE_NO_CREDS]);
  assert.match(CLAUDE_SANDBOX_OFF_NOTE_NO_CREDS, /own sandbox is OFF for this session: .*In this mode Mandu's profile does not block your credential files either/);
  assert.equal(isAttentionNote(CLAUDE_SANDBOX_OFF_NOTE_NO_CREDS), true);
});

test("settings locations: CLAUDE_CONFIG_DIR moves the user file (and its ./ paths); the repository root's local file is read from a subfolder; findGitRoot walks up", () => {
  assert.equal(claudeConfigDir({ CLAUDE_CONFIG_DIR: " /cfg/cc " }, "/Users/u"), "/cfg/cc");
  assert.equal(claudeConfigDir({}, "/Users/u"), "/Users/u/.claude");
  const fs = claudeSettingsFiles("/Users/u", "/r/sub", "darwin", { configDir: "/cfg/cc", gitRoot: "/r" });
  assert.deepEqual(fs.map((f) => [f.scope, f.path]), [
    ["user", "/cfg/cc/settings.json"], ["project", "/r/sub/.claude/settings.json"], ["local", "/r/.claude/settings.local.json"],
    ["local", "/r/sub/.claude/settings.local.json"], ["managed", CLAUDE_MANAGED_SETTINGS_DARWIN],
  ]);
  assert.equal(expandClaudeSettingsPath("./x.json", fs[0]!, "/Users/u", "/r/sub"), "/cfg/cc/x.json");
  assert.equal(claudeSettingsFiles("/Users/u", "/r", "darwin", { gitRoot: "/r" }).filter((f) => f.scope === "local").length, 1, "the root itself: one local file");
  const dirs = new Set(["/r/.git"]);
  assert.equal(findGitRoot("/r/a/b", (p) => dirs.has(p)), "/r");
  assert.equal(findGitRoot("/x/y", (p) => dirs.has(p)), null);
});

test("macOS plan when the probe is skipped (a Claude Code below CLAUDE_SANDBOX_STATUS_SINCE): the settings files decide; a managed file that turns it on keeps it", () => {
  const absent = fakeProbe({ fileOn: true, absent: true });
  assert.deepEqual(plan({ probe: absent.probe, view: VIEW_OFF }), { notes: [], off: false });
  const r = plan({ probe: absent.probe });
  assert.equal(r.off, true);
  const managed = plan({ probe: absent.probe, view: { ...VIEW_ON, enabledBy: [CLAUDE_MANAGED_SETTINGS_DARWIN] }, managedPath: CLAUDE_MANAGED_SETTINGS_DARWIN });
  assert.equal(managed.off, false);
  assert.match(managed.notes[0]!, /managed settings/);
});


test("claudeStatusProbeAllowed: the status probe only on a Claude Code known to have it (an older one takes the words for a prompt); unknown = no", () => {
  assert.equal(CLAUDE_SANDBOX_STATUS_SINCE, "2.1.284");
  for (const v of [null, undefined, "", "garbage", "2.1.273 (Claude Code)", "2.1.283", "2.1.284-beta.1"]) assert.equal(claudeStatusProbeAllowed(v), false, String(v));
  for (const v of ["2.1.284", "2.1.286 (Claude Code)", "2.2.0", "3.0.0"]) assert.equal(claudeStatusProbeAllowed(v), true, v);
});

/** A fake file tree for the worktree checks: path → text (a folder = no entry). */
function fakeTree(files: Record<string, string>) {
  return { readFile: (p: string): string | null => files[p] ?? null, exists: (p: string): boolean => p in files || Object.keys(files).some((k) => k.startsWith(`${p}/`)) };
}

test("claudeCanonicalRoot: a linked worktree's main checkout, checked the way Claude Code checks it; anything else is the root itself", () => {
  const linked = {
    "/repo/.claude/worktrees/feat/.git": "gitdir: /repo/.git/worktrees/feat\n",
    "/repo/.git/worktrees/feat/commondir": "../..\n",
    "/repo/.git/worktrees/feat/gitdir": "/repo/.claude/worktrees/feat/.git\n",
    "/repo/.git/HEAD": "ref: refs/heads/master\n",
  };
  const t = fakeTree(linked);
  const id = (p: string): string => p;
  assert.equal(claudeCanonicalRoot("/repo/.claude/worktrees/feat", t.readFile, id), "/repo");
  assert.equal(claudeCanonicalRoot("/repo", t.readFile, id), "/repo", "a main checkout (.git is a folder)");
  // a relative gitdir resolves against the worktree
  assert.equal(claudeCanonicalRoot("/w", fakeTree({ "/w/.git": "gitdir: ../repo/.git/worktrees/w", "/repo/.git/worktrees/w/commondir": "../..", "/repo/.git/worktrees/w/gitdir": "/w/.git" }).readFile, id), "/repo");
  // the back-pointer must name this .git, and the gitdir must sit under <common>/worktrees
  assert.equal(claudeCanonicalRoot("/repo/.claude/worktrees/feat", fakeTree({ ...linked, "/repo/.git/worktrees/feat/gitdir": "/elsewhere/.git" }).readFile, id), "/repo/.claude/worktrees/feat");
  assert.equal(claudeCanonicalRoot("/x", fakeTree({ "/x/.git": "gitdir: /evil/gd", "/evil/gd/commondir": "/repo/.git", "/evil/gd/gitdir": "/x/.git" }).readFile, id), "/x");
  assert.equal(claudeCanonicalRoot("/y", fakeTree({ "/y/.git": "not a gitdir line" }).readFile, id), "/y");
});

test("settings sources beyond the fixed files: the main checkout's local file, the managed drop-ins (sorted .json, no dot files), the server-managed cache, the MDM preferences (macOS)", () => {
  const fs = claudeSettingsFiles("/Users/u", "/repo/.claude/worktrees/feat", "darwin", {
    configDir: "/Users/u/.claude", gitRoot: "/repo/.claude/worktrees/feat", canonicalRoot: "/repo",
    dropIns: ["20-b.json", ".hidden.json", "10-a.json", "notes.txt"], remote: true, mdmUser: "u",
  });
  assert.deepEqual(fs.map((f) => [f.scope, f.path, f.format ?? "json"]), [
    ["user", "/Users/u/.claude/settings.json", "json"],
    ["project", "/repo/.claude/worktrees/feat/.claude/settings.json", "json"],
    ["local", "/repo/.claude/settings.local.json", "json"],
    ["local", "/repo/.claude/worktrees/feat/.claude/settings.local.json", "json"],
    ["managed", "/Users/u/.claude/remote-settings.json", "json"],
    ["managed", "/Library/Managed Preferences/u/com.anthropic.claudecode.plist", "plist"],
    ["managed", "/Library/Managed Preferences/com.anthropic.claudecode.plist", "plist"],
    ["managed", CLAUDE_MANAGED_SETTINGS_DARWIN, "json"],
    ["managed", "/Library/Application Support/ClaudeCode/managed-settings.d/10-a.json", "json"],
    ["managed", "/Library/Application Support/ClaudeCode/managed-settings.d/20-b.json", "json"],
  ]);
  assert.deepEqual(claudeMdmPlists(""), ["/Library/Managed Preferences/com.anthropic.claudecode.plist"]);
  // Linux: no MDM preferences; its drop-ins sit next to /etc/claude-code's file
  const lx = claudeSettingsFiles("/home/u", "/p", "linux", { dropIns: ["a.json"], mdmUser: "u" });
  assert.equal(lx.some((f) => f.format === "plist"), false);
  assert.equal(lx.at(-1)!.path, "/etc/claude-code/managed-settings.d/a.json");
  // the I/O side: CLAUDE_CONFIG_DIR, the roots, the drop-in listing, the MDM user
  const t = fakeTree({
    "/repo/.claude/worktrees/feat/.git": "gitdir: /repo/.git/worktrees/feat",
    "/repo/.git/worktrees/feat/commondir": "../..",
    "/repo/.git/worktrees/feat/gitdir": "/repo/.claude/worktrees/feat/.git",
  });
  const loc = claudeSettingsLocations({ CLAUDE_CONFIG_DIR: "/cfg", USER: "someone-else" }, "/Users/u", "/repo/.claude/worktrees/feat/src", "darwin", {
    exists: t.exists, readFile: t.readFile, realpath: (p) => p, user: "u", listDir: (d) => (d === "/Library/Application Support/ClaudeCode/managed-settings.d" ? ["x.json"] : null),
  });
  assert.deepEqual(loc, { configDir: "/cfg", gitRoot: "/repo/.claude/worktrees/feat", canonicalRoot: "/repo", dropIns: ["x.json"], remote: true, mdmUser: "u" });
  // the MDM user is the account's name (Claude Code: os.userInfo()), never $USER
  assert.equal(claudeSettingsLocations({ USER: "not-me" }, "/Users/u", "/x", "darwin", { exists: () => false, listDir: () => null }).mdmUser, userInfo().username);
  // CLAUDE_CODE_USE_COWORK_PLUGINS: Claude Code reads cowork_settings.json as the user file
  assert.deepEqual(claudeSettingsLocations({ CLAUDE_CODE_USE_COWORK_PLUGINS: "1" }, "/Users/u", "/x", "linux", { exists: () => false, listDir: () => null }).userFiles, ["cowork_settings.json"]);
  assert.deepEqual(claudeSettingsLocations({ CLAUDE_CODE_USE_COWORK_PLUGINS: "maybe" }, "/Users/u", "/x", "linux", { exists: () => false, listDir: () => null }).userFiles, ["settings.json", "cowork_settings.json"]);
  assert.equal(claudeSettingsLocations({ CLAUDE_CODE_USE_COWORK_PLUGINS: "0" }, "/Users/u", "/x", "linux", { exists: () => false, listDir: () => null }).userFiles, undefined);
  assert.deepEqual(claudeSettingsFiles("/Users/u", "/p", "linux", { userFiles: ["cowork_settings.json"] })[0], { path: "/Users/u/.claude/cowork_settings.json", scope: "user" });
  // an MDM property list that exists but cannot be converted is unreadable (Claude Code may read it)
  const read = readClaudeSettingsSources(claudeSettingsFiles("/Users/u", "/p", "darwin", { mdmUser: "u" }), {
    readFile: () => null, exists: (p) => p.endsWith(".plist"),
    readPlistJson: (p) => (p.includes("/u/") ? null : JSON.stringify({ sandbox: { filesystem: { denyRead: ["/k"] } } })),
  });
  const plists = read.filter((f) => f.format === "plist");
  assert.deepEqual(plists.map((f) => [f.unreadable === true, f.text !== null]), [[true, false], [false, true]]);
  const v = readClaudeSandbox(read, "/Users/u", "/p");
  assert.deepEqual(v.unreadable, ["/Library/Managed Preferences/u/com.anthropic.claudecode.plist"]);
  assert.deepEqual(v.denyRead?.map((d) => d.path), ["/k"]);
});

test("macOS plan: rules in a source Claude Code reads must not be dropped (review 2: a linked worktree's main-checkout local file, a managed drop-in, the server-managed cache); a source Mandu cannot read keeps it on", () => {
  const home = "/Users/u";
  const cwd = "/repo/.claude/worktrees/feat";
  const texts: Record<string, string> = {
    "/Users/u/.claude/settings.json": JSON.stringify({ sandbox: { enabled: true } }),
    "/repo/.claude/settings.local.json": JSON.stringify({ sandbox: { filesystem: { denyRead: ["/Users/u/prod-keys"] } } }),
  };
  const viewOf = (t: Record<string, string>, opts: Parameters<typeof claudeSettingsFiles>[3]) =>
    readClaudeSandbox(claudeSettingsFiles(home, cwd, "darwin", opts).map((f) => ({ ...f, text: t[f.path] ?? null })), home, cwd);
  // the worktree's own root only (the old reading): the rule is never seen, and the sandbox would go off
  assert.equal(plan({ probe: fakeProbe({ fileOn: true }).probe, view: viewOf(texts, { gitRoot: cwd }) }).off, true);
  // with the main checkout read, the rule keeps it on
  const wt = plan({ probe: fakeProbe({ fileOn: true }).probe, view: viewOf(texts, { gitRoot: cwd, canonicalRoot: "/repo" }) });
  assert.equal(wt.off, false);
  assert.match(wt.notes[0]!, /protect \/Users\/u\/prod-keys, which Mandu does not protect/);
  // …and off again once Mandu protects that file itself
  assert.equal(plan({ probe: fakeProbe({ fileOn: true }).probe, view: viewOf(texts, { gitRoot: cwd, canonicalRoot: "/repo" }), confined: ["/Users/u/prod-keys"] }).off, true);
  // an administrator's drop-in, and the server-managed cache
  const dropIn = { ...texts, "/Library/Application Support/ClaudeCode/managed-settings.d/10-x.json": JSON.stringify({ sandbox: { credentials: { files: [{ path: "/etc/corp.pem", mode: "deny" }] } } }) };
  assert.equal(plan({ probe: fakeProbe({ fileOn: true }).probe, view: viewOf(dropIn, { dropIns: ["10-x.json"] }) }).off, false);
  const remote = { ...texts, "/Users/u/.claude/remote-settings.json": JSON.stringify({ sandbox: { filesystem: { denyRead: ["/etc/corp.pem"] } } }) };
  assert.equal(plan({ probe: fakeProbe({ fileOn: true }).probe, view: viewOf(remote, { remote: true }) }).off, false);
  // a source Mandu reads but cannot convert or parse keeps it on, named
  const unread = plan({ probe: fakeProbe({ fileOn: true }).probe, view: { ...VIEW_ON, unreadable: ["/Library/Managed Preferences/com.anthropic.claudecode.plist"] } });
  assert.equal(unread.off, false);
  assert.match(unread.notes[0]!, /Mandu cannot read \/Library\/Managed Preferences\/com\.anthropic\.claudecode\.plist, so it cannot check what its sandbox rules protect and leaves it on/);
  const broken = plan({ probe: fakeProbe({ fileOn: true }).probe, view: { ...VIEW_ON, errors: ["/repo/.claude/settings.json: Unexpected token"] } });
  assert.match(broken.notes[0]!, /Mandu cannot read \/repo\/\.claude\/settings\.json, so/);
});

test("settings text as Claude Code reads it: a blank file is {}, a leading byte-order mark is dropped; only what it rejects is an error", () => {
  const files = claudeSettingsFiles("/Users/u", "/p", "darwin").map((f) => ({
    ...f, text: f.scope === "user" ? "\uFEFF" + JSON.stringify({ sandbox: { enabled: true } }) : f.path === "/p/.claude/settings.local.json" ? "  \n" : f.scope === "project" ? "{ not json" : null,
  }));
  const v = readClaudeSandbox(files, "/Users/u", "/p");
  assert.deepEqual([v.enabled, v.enabledBy], [true, ["/Users/u/.claude/settings.json"]]);
  assert.equal(v.errors.length, 1, "only the broken one");
  assert.match(v.errors[0]!, /^\/p\/\.claude\/settings\.json: /);
  const ok = readClaudeSandbox(files.map((f) => (f.scope === "project" ? { ...f, text: null } : f)), "/Users/u", "/p");
  assert.equal(plan({ probe: fakeProbe({ fileOn: true }).probe, view: ok }).off, true, "a BOM and a blank file do not keep the sandbox");
});

test("macOS plan: what else keeps the sandbox on (review 3): an administrator's policy helper, a run that moves its settings, Read deny rules and blockReadsOutsideWorkingDirectories, a managed source without the probe", () => {
  const read = (texts: Record<string, string>, scopeOf: Record<string, "user" | "managed" | "project" | "local"> = {}) =>
    readClaudeSandbox(Object.entries(texts).map(([path, text]) => ({ path, text, scope: scopeOf[path] ?? "user" })), "/Users/u", "/p");
  const user = { "/Users/u/.claude/settings.json": JSON.stringify({ sandbox: { enabled: true } }) };
  // a policy helper computes managed settings Mandu cannot see
  const helper = read({ ...user, "/Library/Application Support/ClaudeCode/managed-settings.json": JSON.stringify({ policyHelper: { path: "/usr/local/bin/acme" } }) },
    { "/Library/Application Support/ClaudeCode/managed-settings.json": "managed" });
  assert.deepEqual(helper.unreadable, ["/Library/Application Support/ClaudeCode/managed-settings.json (its policyHelper)"]);
  const h = plan({ probe: fakeProbe({ fileOn: true }).probe, view: helper });
  assert.equal(h.off, false);
  assert.match(h.notes[0]!, /Mandu cannot read .*\(its policyHelper\)/);
  assert.equal(read({ "/x.json": JSON.stringify({ policyHelper: {} }) }).unreadable, undefined, "ignored (as by Claude Code) outside managed sources");
  // --managed-settings / --project-config-root: sources Mandu does not read
  assert.deepEqual(claudeArgvSettingsMoves(["claude", "--managed-settings", "{}", "--project-config-root=/w", "--", "--managed-settings"]), ["--managed-settings", "--project-config-root"]);
  for (const argv of [["claude", "--managed-settings", '{"sandbox":{"filesystem":{"denyRead":["/k"]}}}'], ["claude", "--project-config-root", "/work/cfg"]]) {
    const r = plan({ probe: fakeProbe({ fileOn: true }).probe, argv });
    assert.equal(r.off, false, JSON.stringify(argv));
    assert.match(r.notes[0]!, /This run passes --(managed-settings|project-config-root), settings Mandu does not read/);
  }
  // Read(...) deny rules join the read-denies (resolved with Claude Code's spelling: //x absolute, ~/ the home, else relative)
  assert.deepEqual(claudeReadDenyPath("Read(//etc/acme.pem)", "/Users/u"), { written: "Read(//etc/acme.pem)", resolved: "/etc/acme.pem" });
  assert.deepEqual(claudeReadDenyPath("Read(~/k.pem)", "/Users/u"), { written: "Read(~/k.pem)", resolved: "/Users/u/k.pem" });
  assert.deepEqual(claudeReadDenyPath("Read(/src/x)", "/Users/u"), { written: "Read(/src/x)", resolved: null }, "a /x rule is relative to the settings root");
  assert.equal(claudeReadDenyPath("Edit(/x)", "/Users/u"), null);
  const perm = read({ "/Users/u/.claude/settings.json": JSON.stringify({ sandbox: { enabled: true }, permissions: { deny: ["Read(~/clients/**)", "Read(~/k.pem)", "Bash(rm:*)", "Read"] } }) });
  assert.deepEqual(perm.denyRead?.map((d) => [d.path, d.resolved, d.permission]), [["Read(~/clients/**)", "/Users/u/clients/**", true], ["Read(~/k.pem)", "/Users/u/k.pem", true]]);
  const pr = plan({ probe: fakeProbe({ fileOn: true }).probe, view: perm });
  assert.equal(pr.off, false);
  assert.match(pr.notes[0]!, /Read\(~\/clients\/\*\*\), which is not a single file/);
  assert.match(pr.notes[0]!, /Read\(~\/k\.pem\), which Mandu does not protect/);
  assert.equal(plan({ probe: fakeProbe({ fileOn: true }).probe, view: read({ "/Users/u/.claude/settings.json": JSON.stringify({ sandbox: { enabled: true }, permissions: { deny: ["Read(~/k.pem)"] } }) }), confined: ["/Users/u/k.pem"] }).off, true, "covered");
  // blockReadsOutsideWorkingDirectories: Mandu has nothing like it
  const block = read({ "/Users/u/.claude/settings.json": JSON.stringify({ sandbox: { enabled: true }, permissions: { blockReadsOutsideWorkingDirectories: true } }) });
  assert.deepEqual(block.blockReadsOutside, ["/Users/u/.claude/settings.json"]);
  const b = plan({ probe: fakeProbe({ fileOn: true }).probe, view: block });
  assert.equal(b.off, false);
  assert.match(b.notes[0]!, /Its permissions\.blockReadsOutsideWorkingDirectories \(\/Users\/u\/\.claude\/settings\.json\) keeps the commands Claude runs from reading any home or volume outside the working directories/);
  const bFlag = plan({ probe: fakeProbe({ fileOn: true }).probe, argv: ["claude", "--settings", JSON.stringify({ permissions: { blockReadsOutsideWorkingDirectories: true, deny: ["Read(//k)"] } })] });
  assert.match(bFlag.notes[0]!, /\(this run's --settings\)/);
  // without the probe, a managed source other than managed-settings.json that turns it on (a drop-in) keeps it
  const dropIn = read({ "/Library/Application Support/ClaudeCode/managed-settings.d/10.json": JSON.stringify({ sandbox: { enabled: true } }) },
    { "/Library/Application Support/ClaudeCode/managed-settings.d/10.json": "managed" });
  assert.deepEqual(dropIn.enabledByManaged, ["/Library/Application Support/ClaudeCode/managed-settings.d/10.json"]);
  const noProbe = plan({ probe: () => null, view: dropIn, managedPath: CLAUDE_MANAGED_SETTINGS_DARWIN });
  assert.equal(noProbe.off, false);
  assert.match(noProbe.notes[0]!, /by your organization's managed settings/);
});

test("macOS plan (review 4): the options that move a settings source reach both probes; without the probe they get a WARNING; a `--` taken as a value does not hide them", () => {
  // the probe sees --managed-settings turning it on: the WARNING names the option
  const seen: string[][] = [];
  const probe = (args: string[]): ClaudeSandboxStatus => { seen.push(args); return { enabled: args.includes("--managed-settings"), source: "policy" }; };
  const r = plan({ probe, view: VIEW_OFF, argv: ["claude", "--managed-settings", '{"sandbox":{"enabled":true}}', "-p", "hi"] });
  assert.equal(r.off, false);
  assert.deepEqual(seen[0], ["--managed-settings", '{"sandbox":{"enabled":true}}']);
  assert.match(r.notes[0]!, /This run passes --managed-settings, settings Mandu does not read/);
  // no probe: Mandu cannot tell, and says what would happen
  const blind = plan({ probe: () => null, view: VIEW_OFF, argv: ["claude", "--project-config-root=/work/cfg"] });
  assert.equal(blind.off, false);
  assert.match(blind.notes[0]!, /^WARNING: mandu: this run passes --project-config-root, settings Mandu does not read: if they turn Claude Code's own sandbox on, on macOS it cannot start inside Mandu's Seatbelt profile/);
  // a `--` taken as an option's value
  assert.deepEqual(claudeArgvSettingsMoves(["claude", "--append-system-prompt", "--", "--managed-settings", "{}"]), ["--managed-settings"]);
  const dashed = plan({ probe: fakeProbe({ fileOn: true }).probe, argv: ["claude", "--append-system-prompt", "--", "--managed-settings", '{"sandbox":{"filesystem":{"denyRead":["/k"]}}}'] });
  assert.equal(dashed.off, false);
});

test("macOS plan (review 4): a Read rule as Claude Code saves it (escaped parentheses) names the real file; a file outside where Mandu looks for secrets cannot be labelled", () => {
  assert.equal(claudeRuleContent("//Users/u/Downloads/sa \\(1\\).json"), "//Users/u/Downloads/sa (1).json");
  assert.equal(claudeRuleContent("~/x\\*y"), "~/x\\*y", "an escaped glob character keeps its backslash");
  const view = { ...VIEW_ON, denyRead: [{ path: "Read(//Users/u/Downloads/sa \\(1\\).json)", resolved: claudeReadDenyPath("Read(//Users/u/Downloads/sa \\(1\\).json)", "/Users/u")!.resolved!, source: "/Users/u/.claude/settings.json", permission: true }] };
  assert.equal(view.denyRead[0]!.resolved, "/Users/u/Downloads/sa (1).json");
  const seenPaths: string[] = [];
  const exists = plan({ probe: fakeProbe({ fileOn: true }).probe, view, hasContent: (p) => { seenPaths.push(p); return true; }, scanRoots: ["/Users/u", "/Users/u/proj"] });
  assert.deepEqual(seenPaths, ["/Users/u/Downloads/sa (1).json"]);
  assert.match(exists.notes[0]!, /which Mandu does not protect: label them/);
  assert.equal(plan({ probe: fakeProbe({ fileOn: true }).probe, view, confined: ["/Users/u/Downloads/sa (1).json"] }).off, true, "labelled and confined: covered");
  // outside HOME and the launch folder, or deeper than discovery walks: remove it
  const far = (p: string) => plan({ probe: fakeProbe({ fileOn: true }).probe, scanRoots: ["/Users/u", "/Users/u/proj"],
    view: { ...VIEW_ON, denyRead: [{ path: p, resolved: p, source: "/Library/Application Support/ClaudeCode/managed-settings.d/x.json" }] } });
  for (const p of ["/etc/corp.pem", "/Users/u/a/b/c/d/e/deep.pem"]) {
    const r = far(p);
    assert.equal(r.off, false, p);
    assert.match(r.notes[0]!, /lies outside where Mandu looks for files to protect \(your home folder and this launch's folder, 4 folders deep\), so a label cannot help: remove that entry/, p);
  }
  assert.match(far("/Users/u/a/b/c/d/ok.pem").notes[0]!, /which Mandu does not protect: label them/, "four folders deep is still walked");
});
