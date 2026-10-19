/**
 * doctor.test — `mandu doctor` (packaging.md §7): the tier-honesty surface.
 * renderDoctor is pure (tested directly); gatherFacts is driven with mock probes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hermetic } from "../lib/test-runtime.js";
import { gatherClaudeSandbox, gatherConfinement as gatherConfinementIn, gatherFacts as gatherFactsIn, gitSandboxFacts, gooseSubagentLoginRow, guardOptedOut as guardOptedOutIn, loginRow, ptraceScopeFacts, ptraceScopeRow, realGitSandboxFacts, renderDoctor, wslRows, wslVersion, YAMA_PTRACE_SCOPE, type DoctorDeps, type DoctorFacts } from "../../src/doctor.js";
import type { WslFacts } from "../../src/wsl.js";
import { CLAUDE_LOGIN_HOWTO, CODEX_LOGIN_HOWTO } from "../../src/agent-login.js";
import { APPARMOR_USERNS_SYSCTL, USERNS_CLONE_SYSCTL } from "../../src/userns.js";
import { Layout } from "../../src/services/layout.js";
import { SANDBOX_EXEC } from "../../src/seatbelt-profile.js";
import { CLAUDE_MANAGED_SETTINGS_DARWIN } from "../../src/claude-sandbox.js";
import type { GitSandboxProbe } from "../../src/hardened-git.js";

/** gatherFacts with this file's own runtime dir when the env names none (test-runtime.ts). */
const gatherFacts = hermetic(gatherFactsIn, 0);
const gatherConfinement = hermetic(gatherConfinementIn, 1);
/** guardOptedOut parses a launch, which resolves the runtime base too. */
const guardOptedOut = hermetic(guardOptedOutIn, 0);

const wrapperFacts: DoctorFacts = {
  node: { version: "22.22.1", ok: true },
  git: "2.50.1",
  agents: { claude: true, codex: false },
  layout: { mode: "installed", root: "/opt/mandu" },
  arbiter: { sock: "/run/mandu/arbiter.sock", reachable: false },
  kernel: { "net-supervisor": false, "fs-supervisor": false, "exec-supervisor": false },
  confinement: { posture: "confined" },
  claudeSandbox: null,
};

test("render: an install with no native bins states COOPERATIVE enforcement + the wrapper tier alone", () => {
  const out = renderDoctor(wrapperFacts);
  assert.match(out, /Node\.js 22\.22\.1 \(22\.13\.0 or newer\)/);
  assert.match(out, /from the npm package:/);
  // every wrapper chokepoint reports its native supervisor as absent
  assert.match(out, /kernel connect guard: not installed \(net-supervisor\)/);
  assert.match(out, /kernel file guard: not installed \(fs-supervisor\)/);
  assert.match(out, /kernel command box: not installed \(exec-supervisor\)/);
  assert.match(out, /AI requests\s+Mandu's model proxy/);
  assert.match(out, /sits between the AI and its model service/);
  assert.match(out, /kernel guards are not installed here/);
  assert.match(out, /npm package includes them for\s+Linux x64/); // the npm user is told what the package covers, never `cargo build`
  assert.doesNotMatch(out, /cargo build/);
});

test("render: a checkout says whether it runs its prebuilt bundle or tsx (packaging.md §5.1)", () => {
  const bundled = renderDoctor({ ...wrapperFacts, layout: { mode: "dev", root: "/repo", bundled: true } });
  assert.match(bundled, /from a source checkout \(its prebuilt bundle, rebuilt when the source changes\): \/repo/);
  const src = renderDoctor({ ...wrapperFacts, layout: { mode: "dev", root: "/repo", bundled: false } });
  assert.match(src, /from a source checkout \(run with tsx\): \/repo/);
});

test("render: node too old is flagged loudly", () => {
  const out = renderDoctor({ ...wrapperFacts, node: { version: "20.10.0", ok: false } });
  assert.match(out, /Node\.js 20\.10\.0 is TOO OLD/);
});

test("render: native bins PRESENT change the verdict: they attach WITHOUT root, on by default", () => {
  const out = renderDoctor({
    ...wrapperFacts,
    layout: { mode: "dev", root: "/repo" },
    kernel: { "net-supervisor": true, "fs-supervisor": false, "exec-supervisor": false },
  });
  assert.match(out, /kernel connect guard: installed \(net-supervisor\), on without root/);
  assert.match(out, /runs without root/);
  assert.doesNotMatch(out, /needs root/); // the pre-2026-09-24 claim: the guard and the box never needed it
  assert.doesNotMatch(out, /not installed here/); // the "absent" verdict must not also show
});

test("gatherFacts: assembles from the probes; node>=22 ok; kernel per-crate; arbiter reachability", async () => {
  const present = new Set(["/repo/interceptors/target/release/fs-supervisor"]);
  const deps: DoctorDeps = {
    nodeVersion: () => "22.13.0",
    gitVersion: () => "2.9.9",
    commandExists: (c) => c === "claude",
    socketReachable: async () => true,
    fileExists: (p) => present.has(p),
    platform: () => "linux",
    usernsOk: () => true,
    readKnob: () => null,
    nativeBin: () => null,
  };
  const facts = await gatherFacts({ MANDU_ARBITER_SOCK: "/tmp/a.sock" }, Layout.dev("/repo"), deps);
  assert.equal(facts.node.ok, true);
  assert.equal(facts.git, "2.9.9");
  assert.deepEqual(facts.agents, { claude: true, codex: false });
  assert.equal(facts.layout.mode, "dev");
  assert.equal(facts.arbiter.sock, "/tmp/a.sock");
  assert.equal(facts.arbiter.reachable, true);
  // only fs-supervisor's binary exists in the mock
  assert.equal(facts.kernel["fs-supervisor"], true);
  assert.equal(facts.kernel["net-supervisor"], false);
});

test("gatherFacts: a native bin the resolver finds (the npm bundle's prebuilt, or PATH) marks its crate present", async () => {
  const deps: DoctorDeps = {
    nodeVersion: () => "22.13.0",
    gitVersion: () => null,
    commandExists: () => false,
    socketReachable: async () => false,
    fileExists: () => false,
    platform: () => "linux",
    usernsOk: () => false,
    readKnob: () => null,
    nativeBin: (name) => (name === "mandu-net-guard" ? "/opt/mandu/dist/native/linux-x64/mandu-net-guard" : null),
  };
  const facts = await gatherFacts({}, Layout.installed("/opt/mandu"), deps);
  assert.equal(facts.kernel["net-supervisor"], true, "the guard's crate is present through the bundled bin");
  assert.equal(facts.kernel["exec-supervisor"], false);
  assert.equal(facts.kernel["fs-supervisor"], false);
});

test("gatherFacts: node below the 22.13.0 floor → node.ok false (22.12 included — node:sqlite is still flagged there)", async () => {
  for (const tooOld of ["20.11.0", "22.12.0"]) {
  const deps: DoctorDeps = {
    nodeVersion: () => tooOld,
    gitVersion: () => null,
    commandExists: () => false,
    socketReachable: async () => false,
    fileExists: () => false,
    platform: () => "linux",
    usernsOk: () => false,
    readKnob: () => null,
    nativeBin: () => null,
  };
  const facts = await gatherFacts({}, Layout.installed("/opt/mandu"), deps);
  assert.equal(facts.node.ok, false, tooOld);
  assert.equal(facts.git, null);
  }
});

// ── the Secrets row (rootless-confinement-ubuntu-2404.md §3.3) ────────────────

const knobs = (m: Record<string, string>) => (p: string): string | null => (p in m ? m[p]! : null);
const confDeps = (o: Partial<DoctorDeps>): DoctorDeps => ({
  nodeVersion: () => "22.0.0",
  gitVersion: () => null,
  commandExists: (c) => c === "bwrap",
  socketReachable: async () => false,
  fileExists: () => false,
  platform: () => "linux",
  usernsOk: () => false,
  readKnob: () => null,
  nativeBin: () => null,
  ...o,
});

// ── plan 10 §11.7 / phase 6: the guard alone confines a no-userns host ──────
test("confinement row: no userns but the guard bin resolves → confined by the guard, the bind gap named, setup offered as a second layer", () => {
  const c = gatherConfinement(confDeps({
    readKnob: knobs({ [APPARMOR_USERNS_SYSCTL]: "1\n" }),
    nativeBin: (name) => (name === "mandu-net-guard" ? "/opt/mandu/dist/native/linux-x64/mandu-net-guard" : null),
  }));
  assert.equal(c.posture, "confined");
  assert.equal(c.gap, undefined, "not a gap in the guarantee");
  assert.equal(c.bindGap, "apparmor-userns");
  const out = renderDoctor({ ...wrapperFacts, confinement: c });
  assert.match(out, /✓ credential files are protected \(posture: confined, by the guard alone\)/);
  assert.match(out, /placeholder copy of each credential file/);
  assert.match(out, /protected by Mandu's file guard alone/);
  assert.match(out, /mount layer unavailable: Ubuntu restricts unprivileged user namespaces/);
  assert.match(out, /optional second layer: mandu setup/);
  assert.doesNotMatch(out, /NOT confined/);
  assert.doesNotMatch(out, /--require-confinement/); // nothing to refuse over
});

test("confinement row (§14.1 item 6): the bind would stop nested sandboxes → confined by the guard alone, the mount layer OFF, `mandu setup` (Mandu's own bubblewrap) offered as the second layer; the probe runs only where the bind could mount", () => {
  const guard = (name: string): string | null => (name === "mandu-net-guard" ? "/opt/mandu/dist/native/linux-x64/mandu-net-guard" : null);
  const c = gatherConfinement(confDeps({ usernsOk: () => true, nestingOk: () => false, readKnob: knobs({ [APPARMOR_USERNS_SYSCTL]: "1\n" }), nativeBin: guard }));
  assert.deepEqual(c, { posture: "confined", bindGap: "bwrap-nesting" });
  const out = renderDoctor({ ...wrapperFacts, confinement: c });
  assert.match(out, /posture: confined, by the guard alone/);
  assert.match(out, /mount layer off: this host's bubblewrap AppArmor profile lets no sandbox start inside another/);
  // Mandu's own bubblewrap lets a sandbox nest (rootless-confinement-ubuntu-2404.md §12.3)
  assert.match(out, /optional second layer: mandu setup/);
  assert.doesNotMatch(out, /^ *fix:/m, "a confined host is never told it needs a fix");
  // a fixture without the probe, or a host that cannot bind at all, never runs it
  assert.deepEqual(gatherConfinement(confDeps({ usernsOk: () => true, nativeBin: guard })), { posture: "confined" });
  let probed = 0;
  gatherConfinement(confDeps({ usernsOk: () => false, nestingOk: () => { probed++; return false; }, nativeBin: guard }));
  assert.equal(probed, 0);
});

test("confinement row: the guard is consulted only on Linux and only through the injected resolver", () => {
  let asked = 0;
  const mac = gatherConfinement(confDeps({ platform: () => "darwin", commandExists: (x) => x === SANDBOX_EXEC, nativeBin: () => { asked++; return "/x"; } }));
  assert.deepEqual(mac, { posture: "read-blocked" });
  assert.equal(asked, 0, "macOS never asks for the Linux guard");
  const withBind = gatherConfinement(confDeps({ usernsOk: () => true, nativeBin: () => "/x" }));
  assert.deepEqual(withBind, { posture: "confined" }, "with a bind the guard adds nothing to the posture name");
});

test("confinement row: sysctl=1 + probe fails → gated, AppArmor cause, `mandu setup` fix", () => {
  const c = gatherConfinement(confDeps({ readKnob: knobs({ [APPARMOR_USERNS_SYSCTL]: "1\n" }) }));
  assert.deepEqual({ posture: c.posture, gap: c.gap }, { posture: "gated", gap: "apparmor-userns" });
  const out = renderDoctor({ ...wrapperFacts, confinement: c });
  assert.match(out, /✗ credential files are NOT protected from programs the AI runs \(posture: gated\)/);
  assert.match(out, /can still read your credential files/);
  assert.match(out, /cause: Ubuntu restricts unprivileged user namespaces/);
  assert.match(out, /fix: mandu setup/);
  assert.match(out, /--require-confinement/);
  // gated never borrows the confined claim
  assert.doesNotMatch(out, /placeholder copy of each credential file/);
});

test("confinement row: sysctl=1 but the probe PASSES (profile installed) + the guard → confined, no fix line", () => {
  const c = gatherConfinement(confDeps({ usernsOk: () => true, readKnob: knobs({ [APPARMOR_USERNS_SYSCTL]: "1\n" }), nativeBin: () => "/x" }));
  assert.deepEqual(c, { posture: "confined" });
  const out = renderDoctor({ ...wrapperFacts, confinement: c });
  assert.match(out, /✓ credential files are protected \(posture: confined\)/);
  assert.doesNotMatch(out, /fix:/);
  assert.doesNotMatch(out, /partial layer/);
});

test("confinement row (finding 7): the bind can mount but no guard → GATED (no-guard), the partial layer named, --require-confinement offered", () => {
  const c = gatherConfinement(confDeps({ usernsOk: () => true, readKnob: knobs({ [APPARMOR_USERNS_SYSCTL]: "1\n" }) }));
  assert.deepEqual(c, { posture: "gated", gap: "no-guard" });
  const out = renderDoctor({ ...wrapperFacts, confinement: c });
  assert.match(out, /✗ credential files are NOT protected from programs the AI runs \(posture: gated\)/);
  assert.match(out, /partial layer in use: the mount layer puts a placeholder copy over each credential file found at launch/);
  assert.match(out, /not covered without the file guard: a credential file replaced while the AI runs/);
  assert.match(out, /cause: Mandu's file guard \(mandu-net-guard\) is not available here/);
  assert.doesNotMatch(out, /^ *fix:/m, "no one-command fix");
  assert.match(out, /--require-confinement/);
});

test("confinement row (finding 7): a guard the user turned off (env or config.toml) is guard-off, even with the binary present", () => {
  const withBin = { usernsOk: () => true, nativeBin: () => "/x" } as const;
  assert.deepEqual(gatherConfinement(confDeps(withBin), { MANDU_NET_GUARD: "0" }), { posture: "gated", gap: "guard-off" });
  assert.deepEqual(gatherConfinement(confDeps(withBin), { MANDU_NO_KERNEL: "1" }), { posture: "gated", gap: "guard-off" });
  // config.toml `net-guard = false`, read through the same reader as the knobs
  const cfg = confDeps({ ...withBin, readKnob: knobs({ "/cfg/config.toml": "net-guard = false\n" }) });
  assert.deepEqual(gatherConfinement(cfg, { MANDU_HOME: "/cfg" }), { posture: "gated", gap: "guard-off" });
  // env beats config (the launch's precedence)
  assert.deepEqual(gatherConfinement(cfg, { MANDU_HOME: "/cfg", MANDU_NET_GUARD: "1" }), { posture: "confined" });
  // no opt-out: the guard counts
  assert.deepEqual(gatherConfinement(confDeps(withBin), {}), { posture: "confined" });
  // turned off where the bind cannot mount: the host's own reason stays the gap
  const noBind = gatherConfinement(confDeps({ nativeBin: () => "/x" }), { MANDU_NET_GUARD: "0" });
  assert.deepEqual({ posture: noBind.posture, gap: noBind.gap }, { posture: "gated", gap: "userns-off" });
  assert.equal(guardOptedOut({ MANDU_NET_GUARD: "" }), false);
  assert.equal(guardOptedOut({ MANDU_NET_GUARD: "0", MANDU_HOME: "/dev/null/mandu-test-home" }), true);
});

test("confinement row: sysctl 0/absent + probe fails → gated, userns-off, the knob detail, no setup offer", () => {
  const c = gatherConfinement(confDeps({ readKnob: knobs({ [APPARMOR_USERNS_SYSCTL]: "0\n", [USERNS_CLONE_SYSCTL]: "0\n" }) }));
  assert.equal(c.gap, "userns-off");
  assert.match(c.detail ?? "", /unprivileged_userns_clone=0/);
  assert.doesNotMatch(renderDoctor({ ...wrapperFacts, confinement: c }), /fix: mandu setup/);
});

test("confinement row: no bwrap → gated with the apt fix; the userns probe is not consulted", () => {
  let probed = false;
  const c = gatherConfinement(confDeps({ commandExists: () => false, usernsOk: () => { probed = true; return true; } }));
  assert.equal(c.gap, "no-bwrap");
  assert.equal(probed, false);
  assert.match(renderDoctor({ ...wrapperFacts, confinement: c }), /fix: sudo apt install bubblewrap/);
});

test("confinement row: macOS with /usr/bin/sandbox-exec → read-blocked", () => {
  const c = gatherConfinement(confDeps({ platform: () => "darwin", commandExists: (x) => x === SANDBOX_EXEC }));
  assert.deepEqual(c, { posture: "read-blocked" });
  assert.match(renderDoctor({ ...wrapperFacts, confinement: c }), /a read fails instead of returning a placeholder/);
});

test("confinement row: macOS asks for /usr/bin/sandbox-exec by path; a bare `sandbox-exec` on PATH alone is gated", () => {
  const asked: string[] = [];
  const c = gatherConfinement(confDeps({ platform: () => "darwin", commandExists: (x) => { asked.push(x); return x === "sandbox-exec"; } }));
  assert.deepEqual(c, { posture: "gated", gap: "no-sandbox-exec" });
  assert.ok(asked.includes(SANDBOX_EXEC), asked.join(","));
  assert.ok(!asked.includes("sandbox-exec"), "the bare name is never looked up");
});

// ── plan 10 §12.3: Claude Code's own sandbox ──────────────────────────────────
test("Claude Code sandbox row: absent → off; configured → named with its own mask counts and what a launch does about it", () => {
  assert.match(renderDoctor(wrapperFacts), /· Claude Code's own sandbox: off \(no sandbox section in its settings\)/);
  const on = renderDoctor({ ...wrapperFacts, claudeSandbox: { enabled: true, enabledBy: ["/home/u/.claude/settings.json"], maskedFiles: 2, maskedEnvVars: 1, sources: ["/home/u/.claude/settings.json"] } });
  assert.match(on, /Claude Code's own sandbox: ON \(\/home\/u\/\.claude\/settings\.json\): 2 credential files and 1 environment variable masked by Claude Code itself/);
  assert.match(on, /a launch warns when both mask the same file/);
  assert.match(on, /sandbox\.network\.allowUnixSockets so the two work together/);
  const off = renderDoctor({ ...wrapperFacts, claudeSandbox: { enabled: false, enabledBy: [], maskedFiles: 0, maskedEnvVars: 1, sources: ["/x"] } });
  assert.match(off, /Claude Code's own sandbox: configured but off: 0 credential files and 1 environment variable masked/);
});

test("gatherClaudeSandbox reads the user/project/local/managed files through readKnob; nothing sandbox-shaped → null", () => {
  const deps = (texts: Record<string, string>): DoctorDeps => ({
    nodeVersion: () => "22.0.0", gitVersion: () => null, commandExists: () => false, socketReachable: async () => false,
    fileExists: () => false, platform: () => "linux", usernsOk: () => true, readKnob: (p) => texts[p] ?? null,
  });
  assert.equal(gatherClaudeSandbox({ HOME: "/home/u" }, deps({ "/home/u/.claude/settings.json": JSON.stringify({ model: "opus" }) }), "/home/u/proj"), null);
  const got = gatherClaudeSandbox({ HOME: "/home/u" }, deps({
    "/home/u/.claude/settings.json": JSON.stringify({ sandbox: { enabled: true, credentials: { files: [{ path: "~/.netrc", mode: "mask" }, { path: "~/.ssh", mode: "deny" }], envVars: [{ name: "GH_TOKEN", mode: "mask" }] } } }),
    "/home/u/proj/.claude/settings.json": JSON.stringify({ sandbox: { credentials: { files: [{ path: "./.env", mode: "mask" }] } } }),
  }), "/home/u/proj");
  assert.deepEqual(got, { enabled: true, enabledBy: ["/home/u/.claude/settings.json"], maskedFiles: 1, maskedEnvVars: 1, sources: ["/home/u/.claude/settings.json", "/home/u/proj/.claude/settings.json"], rules: 3 });
  // sandbox.filesystem.denyRead counts as a rule (a launch keeps the sandbox for it), alone too
  const deny = gatherClaudeSandbox({ HOME: "/home/u" }, deps({ "/home/u/.claude/settings.json": JSON.stringify({ sandbox: { enabled: true, filesystem: { denyRead: ["~/.ssh"] } } }) }), "/home/u/proj");
  assert.equal(deny?.rules, 1);
  const denyOnly = gatherClaudeSandbox({ HOME: "/home/u" }, deps({ "/home/u/.claude/settings.json": JSON.stringify({ sandbox: { filesystem: { denyRead: ["~/.ssh"] } } }) }), "/home/u/proj");
  assert.equal(denyOnly?.rules, 1, "a denyRead alone is a sandbox section");
  // the sources a launch reads: the server-managed cache, the managed drop-ins (listDir)
  const remote = gatherClaudeSandbox({ HOME: "/home/u" }, { ...deps({ "/home/u/.claude/remote-settings.json": JSON.stringify({ sandbox: { filesystem: { denyRead: ["/k"] } } }), "/etc/claude-code/managed-settings.d/x.json": JSON.stringify({ sandbox: { enabled: true } }) }), listDir: (d) => (d === "/etc/claude-code/managed-settings.d" ? ["x.json"] : null) }, "/home/u/proj");
  assert.deepEqual([remote?.enabled, remote?.rules, remote?.enabledBy], [true, 1, ["/etc/claude-code/managed-settings.d/x.json"]]);
  // an administrator's policy helper alone is still a sandbox section (a launch keeps the sandbox for it; review 4)
  const helper = gatherClaudeSandbox({ HOME: "/home/u" }, deps({ "/etc/claude-code/managed-settings.json": JSON.stringify({ policyHelper: { path: "/usr/local/bin/acme" } }) }), "/home/u/proj");
  assert.deepEqual(helper?.unreadable, ["/etc/claude-code/managed-settings.json (its policyHelper)"]);
});

test("WSL: the kernel release names the generation; doctor says what it means", () => {
  assert.equal(wslVersion("5.15.167.4-microsoft-standard-WSL2"), 2);
  assert.equal(wslVersion("4.4.0-19041-Microsoft"), 1);
  assert.equal(wslVersion("6.8.0-139-generic"), null);
  assert.equal(wslVersion(null), null);
  assert.match(renderDoctor({ ...wrapperFacts, wsl: 2 }), /Linux on WSL2: a real Linux kernel/);
  assert.match(renderDoctor({ ...wrapperFacts, wsl: 1 }), /WSL1: not a Linux kernel.* wsl --set-version <distro> 2/);
  assert.doesNotMatch(renderDoctor({ ...wrapperFacts, wsl: null }), /WSL/);
});

test("WSL2 detail rows: kernel gate, Windows interop against the guard, systemd, a Windows-drive folder", () => {
  const w: WslFacts = {
    version: 2, kernel: "6.6.36.6-microsoft-standard-WSL2", landlock: true, landlockNet: false,
    interop: "enabled", systemd: true, workspaceDrive: null,
  };
  const guarded = renderDoctor({ ...wrapperFacts, wsl: 2, wslDetail: w, kernel: { ...wrapperFacts.kernel, "net-supervisor": true } });
  assert.match(guarded, /✓ kernel 6\.6\.36\.6-microsoft-standard-WSL2: Landlock for files \(TCP rules need 6\.7\)/);
  assert.match(guarded, /✓ Windows interop is on; Mandu keeps it from the AI/);
  assert.match(guarded, /✓ systemd is running/);
  assert.doesNotMatch(guarded, /Windows drive/);
  const open = renderDoctor({
    ...wrapperFacts, wsl: 2,
    wslDetail: { ...w, landlock: false, kernel: "5.10.102.1-microsoft-standard-WSL2", systemd: false, workspaceDrive: { path: "/mnt/c/p", mountPoint: "/mnt/c" } },
  });
  assert.match(open, /✗ kernel 5\.10\.102\.1-microsoft-standard-WSL2 predates Landlock \(5\.13\).*wsl --update/);
  assert.match(open, /✗ Windows interop is on and the connect guard is not installed.*\[interop\] enabled=false/);
  assert.match(open, /· systemd is off.*\[boot\] systemd=true/);
  assert.match(open, /✗ this folder is on a Windows drive \(\/mnt\/c\).*Linux file system/);
  assert.match(renderDoctor({ ...wrapperFacts, wsl: 2, wslDetail: { ...w, interop: "disabled" } }), /✓ Windows interop is off/);
  // WSL1 and off-WSL: no detail rows.
  assert.deepEqual(wslRows({ ...w, version: 1 }, true), []);
  assert.deepEqual(wslRows(null, true), []);
});

test("login rows (agent-login.ts): found names the source, missing names the fix, codex only matters with codex installed", () => {
  const found = renderDoctor({
    ...wrapperFacts,
    logins: {
      claude: { agent: "claude", state: "found", via: "/home/u/.claude/.credentials.json", howTo: "x" },
      codex: { agent: "codex", state: "found", via: "OPENAI_API_KEY", howTo: "y" },
    },
  });
  assert.match(found, /✓ claude login: found \(\/home\/u\/\.claude\/\.credentials\.json\)/);
  assert.match(found, /✓ codex login: found \(OPENAI_API_KEY\)/);

  const missingLogins = {
    claude: { agent: "claude" as const, state: "missing" as const, howTo: CLAUDE_LOGIN_HOWTO },
    codex: { agent: "codex" as const, state: "missing" as const, howTo: CODEX_LOGIN_HOWTO },
  };
  const missing = renderDoctor({ ...wrapperFacts, agents: { claude: true, codex: false }, logins: missingLogins });
  assert.match(missing, /✗ claude login: none found; run `claude` once/);
  assert.match(missing, /· codex login: none found \(only needed for `mandu codex`: run `codex login` once without mandu \(a ChatGPT plan\), or set CODEX_API_KEY/);
  assert.match(
    renderDoctor({ ...wrapperFacts, agents: { claude: true, codex: true }, logins: missingLogins }),
    /✗ codex login: none found; run `codex login`.*CODEX_API_KEY/,
    "codex installed → its missing login is a ✗",
  );
  // Signed in with `codex login` only (a ChatGPT sign-in or a saved key):
  // a ✓ that says the model proxy relays it (agent-sign-in.md §2.6).
  const signedIn = { ...missingLogins, codex: { agent: "codex" as const, state: "found" as const, via: "/home/u/.codex/auth.json", signIn: true, howTo: CODEX_LOGIN_HOWTO } };
  const withCodex = renderDoctor({ ...wrapperFacts, agents: { claude: true, codex: true }, logins: signedIn });
  assert.match(withCodex, /✓ codex login: signed in \(\/home\/u\/\.codex\/auth\.json\); `mandu codex` passes that sign-in through its model proxy/);
  assert.doesNotMatch(withCodex, /✗ codex login/);
  const keyed = { ...missingLogins, codex: { agent: "codex" as const, state: "found" as const, via: "CODEX_API_KEY", howTo: CODEX_LOGIN_HOWTO } };
  assert.match(renderDoctor({ ...wrapperFacts, agents: { claude: true, codex: true }, logins: keyed }), /✓ codex login: found \(CODEX_API_KEY\)/);
  assert.match(
    loginRow("claude", { agent: "claude", state: "unknown", howTo: CLAUDE_LOGIN_HOWTO }, true),
    /· claude login: cannot tell \(Claude Code keeps it in the macOS Keychain\)/,
  );
  // Older fixtures without `logins` render no login row.
  assert.doesNotMatch(renderDoctor(wrapperFacts), /login:/);
});

test("gatherFacts: the login probe reads HOME from the env and only asks whether files exist", async () => {
  const asked: string[] = [];
  const deps: DoctorDeps = {
    nodeVersion: () => "22.13.0",
    gitVersion: () => null,
    commandExists: () => false,
    socketReachable: async () => false,
    fileExists: (p) => { asked.push(p); return p === "/h/.codex/auth.json"; },
    platform: () => "linux",
    usernsOk: () => false,
    readKnob: () => null,
    nativeBin: () => null,
  };
  const facts = await gatherFacts({ HOME: "/h", MANDU_ARBITER_SOCK: "/tmp/a.sock" }, Layout.dev("/repo"), deps);
  assert.equal(facts.logins?.claude.state, "missing");
  assert.equal(facts.logins?.codex.via, "/h/.codex/auth.json");
  assert.ok(asked.includes("/h/.claude/.credentials.json"));
});

test("goose login row (supported-agents.md §5.6.1): only with goose installed; the keyring is said to be out of reach; never a value", async () => {
  const base: DoctorDeps = {
    nodeVersion: () => "22.13.0", gitVersion: () => null, socketReachable: async () => false,
    platform: () => "linux", usernsOk: () => false, readKnob: () => null, nativeBin: () => null,
    commandExists: (c) => c === "goose",
    fileExists: () => false,
  };
  // A runtime dir the developer's shell names is kept (a host whose /tmp/mandu is another user's).
  const H = { HOME: "/h", MANDU_ARBITER_SOCK: "/tmp/a.sock", ...(process.env["MANDU_RUNTIME_DIR"] ? { MANDU_RUNTIME_DIR: process.env["MANDU_RUNTIME_DIR"] } : {}) };
  const asked: Array<Record<string, string>> = [];
  const keyring = await gatherFacts(H, Layout.dev("/repo"), {
    ...base, gooseLogin: () => ({ readGooseConfig: () => null, keyringItem: (a) => { asked.push({ ...a }); return true; } }),
  });
  assert.deepEqual([keyring.logins?.goose?.state, keyring.logins?.goose?.keyring], ["found", true]);
  assert.deepEqual(asked, [{ service: "goose", username: "secrets" }]);
  const row = loginRow("goose", keyring.logins!.goose!, true);
  assert.match(row, /✗ goose login: in the system keyring, which `mandu goose` keeps out of the agent's reach/);
  assert.match(row, /ANTHROPIC_API_KEY, or run `GOOSE_DISABLE_KEYRING=1 goose configure`/);
  // The file: a ✓ that says Goose reads it and its values are masked.
  const file = await gatherFacts(H, Layout.dev("/repo"), {
    ...base, fileExists: (p) => p === "/h/.config/goose/secrets.yaml",
  });
  assert.match(renderDoctor({ ...wrapperFacts, logins: file.logins! }), /✓ goose login: found \(\/h\/\.config\/goose\/secrets\.yaml\); `mandu goose` lets Goose read it/);
  // The variable: its NAME only.
  const env = await gatherFacts({ ...H, ANTHROPIC_API_KEY: "sk-ant-SECRETVALUE" }, Layout.dev("/repo"), base);
  const envRow = loginRow("goose", env.logins!.goose!, true);
  assert.equal(envRow, "  ✓ goose login: found (ANTHROPIC_API_KEY)");
  // Nothing: a ✗ with the fix; the keyring not asked: a · that says where it could be.
  const none = await gatherFacts({ ...H, GOOSE_DISABLE_KEYRING: "1" }, Layout.dev("/repo"), base);
  assert.match(loginRow("goose", none.logins!.goose!, true), /✗ goose login: none found; set ANTHROPIC_API_KEY/);
  const notAsked = await gatherFacts(H, Layout.dev("/repo"), base);
  assert.match(loginRow("goose", notAsked.logins!.goose!, true), /· goose login: no key variable and no secrets\.yaml, and the system keyring was not asked/);
  // On the openai provider the variable is OPENAI_API_KEY (goose-route.ts gooseRoutePlan).
  const openai = await gatherFacts({ ...H, GOOSE_PROVIDER: "openai", OPENAI_API_KEY: "sk-SECRETVALUE" }, Layout.dev("/repo"), base);
  assert.equal(loginRow("goose", openai.logins!.goose!, true), "  ✓ goose login: found (OPENAI_API_KEY)");
  const openaiNone = await gatherFacts({ ...H, GOOSE_PROVIDER: "openai", ANTHROPIC_API_KEY: "k", GOOSE_DISABLE_KEYRING: "1" }, Layout.dev("/repo"), base);
  assert.match(loginRow("goose", openaiNone.logins!.goose!, true), /✗ goose login: none found; set OPENAI_API_KEY/);
  // Goose not installed: no row.
  const noGoose = await gatherFacts(H, Layout.dev("/repo"), { ...base, commandExists: () => false });
  assert.equal(noGoose.logins?.goose, undefined);
  assert.doesNotMatch(renderDoctor({ ...wrapperFacts, logins: noGoose.logins! }), /goose login/);
  for (const f of [keyring, file, env, none]) assert.doesNotMatch(renderDoctor({ ...wrapperFacts, logins: f.logins! }), /SECRETVALUE/);
  // The subagents' provider (GOOSE_SUBAGENT_PROVIDER): its own row, only when its variable differs.
  assert.equal(gooseSubagentLoginRow(env.logins!.goose!), null, "the same provider: no second row");
  assert.doesNotMatch(renderDoctor({ ...wrapperFacts, logins: env.logins! }), /goose subagent login/);
  const sub = await gatherFacts({ ...H, ANTHROPIC_API_KEY: "sk-ant-SECRETVALUE", GOOSE_SUBAGENT_PROVIDER: "openai", GOOSE_DISABLE_KEYRING: "1" }, Layout.dev("/repo"), base);
  const subOut = renderDoctor({ ...wrapperFacts, logins: sub.logins! });
  assert.match(subOut, /✓ goose login: found \(ANTHROPIC_API_KEY\)\n {2}✗ goose subagent login \(openai, from GOOSE_SUBAGENT_PROVIDER\): none found; set OPENAI_API_KEY/);
  assert.doesNotMatch(subOut, /SECRETVALUE/);
  const subOk = await gatherFacts({ ...H, ANTHROPIC_API_KEY: "k", OPENAI_API_KEY: "sk-SECRETVALUE", GOOSE_SUBAGENT_PROVIDER: "openai" }, Layout.dev("/repo"), base);
  assert.equal(gooseSubagentLoginRow(subOk.logins!.goose!), "  ✓ goose subagent login (openai, from GOOSE_SUBAGENT_PROVIDER): found (OPENAI_API_KEY)");
});

test("goose login row on macOS: the login Keychain is asked (existence only) and said to stay reachable", async () => {
  const base: DoctorDeps = {
    nodeVersion: () => "22.13.0", gitVersion: () => null, socketReachable: async () => false,
    platform: () => "darwin", usernsOk: () => false, readKnob: () => null, nativeBin: () => null,
    commandExists: (c) => c === "goose",
    fileExists: () => false,
  };
  const H = { HOME: "/Users/u", MANDU_ARBITER_SOCK: "/tmp/a.sock", ...(process.env["MANDU_RUNTIME_DIR"] ? { MANDU_RUNTIME_DIR: process.env["MANDU_RUNTIME_DIR"] } : {}) };
  const asked: Array<Record<string, string>> = [];
  const found = await gatherFacts(H, Layout.dev("/repo"), {
    ...base, gooseLogin: () => ({ readGooseConfig: () => null, keyringItem: (a) => { asked.push({ ...a }); return true; } }),
  });
  assert.deepEqual(asked, [{ service: "goose", username: "secrets" }]);
  assert.deepEqual([found.logins?.goose?.state, found.logins?.goose?.via, found.logins?.goose?.keyring], ["found", "the macOS Keychain", undefined]);
  assert.match(loginRow("goose", found.logins!.goose!, true), /^ {2}✓ goose login: found \(the macOS Keychain\); `mandu goose` leaves the Keychain reachable/);
  const none = await gatherFacts(H, Layout.dev("/repo"), { ...base, gooseLogin: () => ({ readGooseConfig: () => null, keyringItem: () => false }) });
  assert.match(loginRow("goose", none.logins!.goose!, true), /✗ goose login: none found; set ANTHROPIC_API_KEY/);
});

test("the default report speaks the product's words, not the architecture's (release checklist d5)", () => {
  for (const facts of [wrapperFacts, { ...wrapperFacts, kernel: { "net-supervisor": true, "fs-supervisor": false, "exec-supervisor": true } }]) {
    const out = renderDoctor(facts);
    for (const jargon of [/\btier\b/i, /chokepoint/i, /\barbiter\b(?!\.sock)/i, /\brung\b/i, /symboli[sz]ed/i, /AgentView/, /plan 10/, /§/]) {
      assert.doesNotMatch(out, jargon, `doctor output says ${jargon}`);
    }
  }
});

test("gatherFacts + render: codex installed on a stock Ubuntu with no bubblewrap → the ✗ Codex sandbox row with the apt fix", async () => {
  const deps: DoctorDeps = {
    nodeVersion: () => "22.13.0",
    gitVersion: () => "2.9.9",
    commandExists: (c) => c === "codex" || c === "claude",
    socketReachable: async () => false,
    fileExists: () => false,
    platform: () => "linux",
    usernsOk: () => false,
    readKnob: (p) => (p === APPARMOR_USERNS_SYSCTL ? "1\n" : null),
    nativeBin: () => null,
  };
  const facts = await gatherFacts({}, Layout.installed("/opt/mandu"), deps);
  assert.equal(facts.codexSandbox?.state, "no-bwrap");
  assert.match(renderDoctor(facts), /✗ Codex cannot run any command here, with or without Mandu: .*fix: sudo apt install bubblewrap, then mandu setup/);
  // bubblewrap installed and granted: the row flips to ✓
  const ok = await gatherFacts({}, Layout.installed("/opt/mandu"), { ...deps, commandExists: () => true, codexBwrapProbe: () => true });
  assert.equal(ok.codexSandbox?.state, "ok");
  assert.match(renderDoctor(ok), /✓ Codex can run commands in its own sandbox \(bubblewrap\)/);
  // no codex: no row at all
  const none = await gatherFacts({}, Layout.installed("/opt/mandu"), { ...deps, commandExists: (c) => c === "claude" });
  assert.doesNotMatch(renderDoctor(none), /Codex can|Codex cannot/);
});

test("CVE-2026-87766 row (finding 14): a vulnerable bwrap is a ✗ warning row under Your secrets; fixed is ✓; unknown or absent says nothing", () => {
  const confinement = { posture: "confined" as const };
  const out = renderDoctor({ ...wrapperFacts, confinement, bwrapSymlink: { bwrap: "bwrap", verdict: "vulnerable" } });
  const secrets = out.slice(out.indexOf("Your secrets"));
  assert.match(secrets, /✗ bubblewrap on this host follows symlinks while it sets up a sandbox \(CVE-2026-87766\)/);
  assert.match(secrets, /fix: a bubblewrap with the fix/);
  assert.match(renderDoctor({ ...wrapperFacts, confinement, bwrapSymlink: { bwrap: "/usr/lib/mandu/bin/bwrap", verdict: "fixed" } }), /✓ bubblewrap \(\/usr\/lib\/mandu\/bin\/bwrap\) refuses to mount onto a symlink/);
  for (const f of [{ bwrap: "bwrap", verdict: "unknown" as const }, { bwrap: "bwrap", verdict: "unknown" as const, version: "0.12.0" }, undefined]) {
    assert.doesNotMatch(renderDoctor({ ...wrapperFacts, confinement, ...(f ? { bwrapSymlink: f } : {}) }), /CVE-2026-87766/);
  }
  // 2026-10-07: the installed version is named, and a probe that could not
  // run on a pre-0.12.0 bubblewrap is a ✗ row too (version-affected).
  const named = renderDoctor({ ...wrapperFacts, confinement, bwrapSymlink: { bwrap: "bwrap", verdict: "vulnerable", version: "0.11.1" } });
  assert.match(named.slice(named.indexOf("Your secrets")), /✗ bubblewrap on this host follows symlinks while it sets up a sandbox \(CVE-2026-87766\) \(bwrap, version 0\.11\.1\)/);
  const old = renderDoctor({ ...wrapperFacts, confinement, bwrapSymlink: { bwrap: "bwrap", verdict: "version-affected", version: "0.11.1", detail: "bwrap: setting up uid map: Permission denied" } });
  assert.match(old.slice(old.indexOf("Your secrets")), /✗ bubblewrap 0\.11\.1 \(bwrap\) reports a version older than 0\.12\.0, the first upstream release with the fix for CVE-2026-87766/);
});

test("git sandbox row (write-protection.md): on names its bubblewrap; MANDU_GIT_SANDBOX=0 is a ·; unavailable is a ✗ with the fix; no probe, no row", () => {
  const enforced = (out: string): string => out.slice(out.indexOf("What Mandu enforces"));
  const on = enforced(renderDoctor({ ...wrapperFacts, gitSandbox: { state: "on", bwrap: "/usr/lib/mandu/bin/bwrap" } }));
  assert.match(on, /✓ Mandu's background and launch-prep git on folders the AI can change: hardened, and run in a sandbox with no network and a read-only view \(\/usr\/lib\/mandu\/bin\/bwrap\)/);
  const off = enforced(renderDoctor({ ...wrapperFacts, gitSandbox: { state: "off" } }));
  assert.match(off, /· Mandu's background and launch-prep git on folders the AI can change: hardened; its sandbox is turned off \(MANDU_GIT_SANDBOX=0\)/);
  const none = enforced(renderDoctor({ ...wrapperFacts, gitSandbox: { state: "unavailable" } }));
  assert.match(none, /✗ Mandu's background and launch-prep git on folders the AI can change: hardened, but not in a sandbox: no bubblewrap here can start one\n\s+fix: a bubblewrap that can create a user namespace/);
  assert.doesNotMatch(renderDoctor(wrapperFacts), /launch-prep git/);
  for (const out of [on, off, none]) {
    for (const jargon of [/\btier\b/i, /chokepoint/i, /\barbiter\b/i, /§/]) assert.doesNotMatch(out, jargon);
  }
});

test("gatherFacts: the git sandbox facts get doctor's env; off (MANDU_GIT_SANDBOX=0) or unavailable; asked on every platform, only when there is a git; never the host's without an injected probe", async () => {
  const base: DoctorDeps = {
    nodeVersion: () => "22.13.0", gitVersion: () => "2.9.9", commandExists: () => false,
    socketReachable: async () => false, fileExists: () => false, platform: () => "linux",
    usernsOk: () => true, readKnob: () => null, nativeBin: () => null,
  };
  const seen: Array<string | undefined> = [];
  const probe = (on: boolean) => (env: Record<string, string | undefined>) => {
    seen.push(env["MANDU_GIT_SANDBOX"]);
    const sandbox = on && env["MANDU_GIT_SANDBOX"] !== "0" ? { bwrap: "bwrap", flags: [] } : null;
    return gitSandboxFacts({ env, platform: "linux", probe: { sandbox, transient: false } });
  };
  const layout = Layout.installed("/opt/mandu");
  assert.deepEqual((await gatherFacts({}, layout, { ...base, gitSandbox: probe(true) })).gitSandbox, { state: "on", bwrap: "bwrap" });
  assert.deepEqual((await gatherFacts({ MANDU_GIT_SANDBOX: "0" }, layout, { ...base, gitSandbox: probe(true) })).gitSandbox, { state: "off" });
  assert.deepEqual((await gatherFacts({}, layout, { ...base, gitSandbox: probe(false) })).gitSandbox, { state: "unavailable" });
  assert.deepEqual(seen, [undefined, "0", undefined]);
  const mac = { state: "seatbelt", sandboxExec: SANDBOX_EXEC, git: "/Library/Developer/CommandLineTools/usr/bin/git" } as const;
  assert.deepEqual((await gatherFacts({}, layout, { ...base, platform: () => "darwin", gitSandbox: () => mac })).gitSandbox, mac, "macOS has its own sandbox");
  assert.equal((await gatherFacts({}, layout, { ...base, gitVersion: () => null, gitSandbox: probe(true) })).gitSandbox, undefined, "no git: nothing to sandbox");
  assert.equal((await gatherFacts({}, layout, base)).gitSandbox, undefined, "no probe injected: never the host's bwrap");
});

// ── macOS (2026-09-29): kernel guards are Linux only; nested sandboxes cannot start ──

const macFacts: DoctorFacts = {
  ...wrapperFacts,
  platform: "darwin",
  arbiter: { sock: "/var/folders/x/T/mandu/current/arbiter.sock", reachable: false },
  confinement: { posture: "read-blocked" },
};

test("render on macOS: the kernel guards are Linux only, the Seatbelt profile is named, never 'built from source' or cargo", () => {
  const out = renderDoctor(macFacts);
  assert.match(out, /kernel connect guard: Linux only \(net-supervisor\)/);
  assert.match(out, /kernel file guard: Linux only \(fs-supervisor\); a Seatbelt profile blocks reads of your credential files/);
  assert.match(out, /kernel command box: Linux only \(exec-supervisor\)/);
  assert.match(out, /The kernel guards are Linux only; macOS has none of them\./);
  assert.match(out, /On macOS a Seatbelt profile \(sandbox-exec\) keeps every program the AI starts from\s+reading your credential files \(posture: read-blocked\)/);
  assert.doesNotMatch(out, /built from source|npm package includes them|cargo|guard: not installed|box: not installed/);
  // the same words, gated (no sandbox-exec): nothing holds a program that ignores Mandu
  const gated = renderDoctor({ ...macFacts, confinement: { posture: "gated", gap: "no-sandbox-exec" } });
  assert.match(gated, /kernel file guard: Linux only \(fs-supervisor\)\n/);
  assert.match(gated, /can read your credential files/);
  assert.doesNotMatch(gated, /Seatbelt profile \(sandbox-exec\) keeps/);
  // the product's words on macOS too
  for (const jargon of [/\btier\b/i, /chokepoint/i, /\barbiter\b(?!\.sock)/i, /\brung\b/i, /symboli[sz]ed/i, /AgentView/, /§/]) {
    assert.doesNotMatch(out, jargon, `doctor output says ${jargon}`);
  }
  // Linux stays pinned: an explicit linux platform renders exactly the old report
  assert.equal(renderDoctor({ ...wrapperFacts, platform: "linux" }), renderDoctor(wrapperFacts));
});

test("render on macOS: Claude Code's own sandbox ON is a ✓ (Mandu turns it off for each session), a ✗ only when managed settings keep it on; off is a ✓", () => {
  const on = renderDoctor({ ...macFacts, claudeSandbox: { enabled: true, enabledBy: ["/Users/u/.claude/settings.json"], maskedFiles: 0, maskedEnvVars: 0, sources: ["/Users/u/.claude/settings.json"], rules: 0 } });
  assert.match(on, /✓ Claude Code's own sandbox: ON \(\/Users\/u\/\.claude\/settings\.json\): under mandu on macOS Mandu turns it off for each session,/);
  assert.match(on, /since it cannot start inside Mandu's Seatbelt profile; Mandu's profile still keeps your credential files from the commands the AI runs/);
  assert.doesNotMatch(on, /work together|keeps it on and warns instead/);
  const rules = renderDoctor({ ...macFacts, claudeSandbox: { enabled: true, enabledBy: ["/Users/u/.claude/settings.json"], maskedFiles: 1, maskedEnvVars: 0, sources: [], rules: 2 } });
  assert.match(rules, /a launch keeps it on and warns instead when its rules \(sandbox\.credentials, sandbox\.filesystem\.denyRead,\n {4}permissions\.deny Read, blockReadsOutsideWorkingDirectories\) protect what Mandu does not/);
  const unread = renderDoctor({ ...macFacts, claudeSandbox: { enabled: true, enabledBy: ["/Users/u/.claude/settings.json"], maskedFiles: 0, maskedEnvVars: 0, sources: [], rules: 0, unreadable: ["/Library/Managed Preferences/com.anthropic.claudecode.plist"] } });
  assert.match(unread, /a launch keeps it on and warns instead: Mandu cannot read \/Library\/Managed Preferences\/com\.anthropic\.claudecode\.plist/);
  const managed = renderDoctor({ ...macFacts, claudeSandbox: { enabled: true, enabledBy: [CLAUDE_MANAGED_SETTINGS_DARWIN], maskedFiles: 0, maskedEnvVars: 0, sources: [], rules: 0 } });
  assert.match(managed, /✗ Claude Code's own sandbox: ON by your organization's managed settings \(\/Library\/Application Support\/ClaudeCode\/managed-settings\.json\): on macOS it cannot/);
  assert.match(managed, /fix: ask your administrator to allow it off for sessions under mandu \(Mandu cannot turn managed settings off\)/);
  // any managed source, a drop-in too (review 3)
  const dropIn = "/Library/Application Support/ClaudeCode/managed-settings.d/10.json";
  const managedDrop = renderDoctor({ ...macFacts, claudeSandbox: { enabled: true, enabledBy: [dropIn], managedOn: [dropIn], maskedFiles: 0, maskedEnvVars: 0, sources: [], rules: 0 } });
  assert.match(managedDrop, /✗ Claude Code's own sandbox: ON by your organization's managed settings \(\/Library\/Application Support\/ClaudeCode\/managed-settings\.d\/10\.json\)/);
  const off = renderDoctor({ ...macFacts, claudeSandbox: { enabled: false, enabledBy: [], maskedFiles: 1, maskedEnvVars: 0, sources: ["/Users/u/.claude/settings.json"], rules: 1 } });
  assert.match(off, /✓ Claude Code's own sandbox: configured but off: 1 credential file and 0 environment variables masked/);
  assert.match(off, /if it is turned on, Mandu turns it off for each session under mandu \(on macOS it cannot start inside Mandu's profile\)/);
  // …and says when a launch would keep it instead (review 3)
  assert.match(off, /a launch keeps it on and warns instead when its rules/);
  const offUnread = renderDoctor({ ...macFacts, claudeSandbox: { enabled: false, enabledBy: [], maskedFiles: 0, maskedEnvVars: 0, sources: [], rules: 0, unreadable: ["/x.json"] } });
  assert.match(offUnread, /a launch keeps it on and warns instead: Mandu cannot read \/x\.json/);
  assert.doesNotMatch(renderDoctor({ ...macFacts, claudeSandbox: { enabled: false, enabledBy: [], maskedFiles: 0, maskedEnvVars: 0, sources: [], rules: 0 } }), /keeps it on and warns instead/);
  // Linux keeps its wording (the two sandboxes stack there)
  const linuxOn = renderDoctor({ ...wrapperFacts, claudeSandbox: { enabled: true, enabledBy: ["/h/.claude/settings.json"], maskedFiles: 0, maskedEnvVars: 0, sources: [] } });
  assert.match(linuxOn, /· Claude Code's own sandbox: ON \(\/h\/\.claude\/settings\.json\)/);
  assert.match(linuxOn, /so the two work together/);
});

test("gatherFacts on macOS: the platform rides the facts; codex installed → Mandu turns its sandbox off (✓), off in config.toml (✓), an administrator's lock or a config that relies on it (✗)", async () => {
  const deps: DoctorDeps = {
    nodeVersion: () => "22.13.0",
    gitVersion: () => "2.9.9",
    commandExists: (c) => c === "codex" || c === "claude" || c === SANDBOX_EXEC,
    socketReachable: async () => false,
    fileExists: () => false,
    platform: () => "darwin",
    usernsOk: () => false,
    readKnob: () => null,
    nativeBin: () => null,
  };
  const facts = await gatherFacts({ HOME: "/Users/u" }, Layout.installed("/opt/mandu"), deps);
  assert.equal(facts.platform, "darwin");
  assert.equal(facts.confinement.posture, "read-blocked");
  assert.equal(facts.codexSandbox?.state, "seatbelt-mandu-off");
  const out = renderDoctor(facts);
  assert.match(out, /✓ Codex runs commands under mandu on macOS: Mandu turns its own sandbox off for each session \(macOS cannot start it inside Mandu's profile\)/);
  const locked = await gatherFacts({ HOME: "/Users/u" }, Layout.installed("/opt/mandu"), { ...deps, codexAdminLock: () => "/etc/codex/requirements.toml: deny_read" });
  assert.equal(locked.codexSandbox?.state, "seatbelt-nests");
  assert.match(renderDoctor(locked), /✗ Codex cannot run commands under mandu on macOS: your organization's Codex settings require its own sandbox \(\/etc\/codex\/requirements\.toml: deny_read\).*fix: ask your administrator/);
  const keeps = await gatherFacts({ HOME: "/Users/u" }, Layout.installed("/opt/mandu"), { ...deps, readKnob: (p: string) => (p === "/Users/u/.codex/config.toml" ? "[features]\nnetwork_proxy = true\n" : null) });
  assert.equal(keeps.codexSandbox?.state, "seatbelt-nests");
  assert.match(renderDoctor(keeps), /Codex's network proxy is on \(\/Users\/u\/\.codex\/config\.toml\), which runs every command in its own sandbox/);
  // Codex 0.159.3's real read-deny spelling (review 3)
  const denyRead = await gatherFacts({ HOME: "/Users/u" }, Layout.installed("/opt/mandu"), { ...deps, readKnob: (p: string) => (p === "/Users/u/.codex/config.toml" ? 'default_permissions = "p"\n[permissions.p.filesystem]\n":minimal" = "read"\n"/Users/u/k" = "deny"\n' : null) });
  assert.match(renderDoctor(denyRead), /your Codex config relies on its own sandbox \(a permission profile of your own \(\/Users\/u\/\.codex\/config\.toml\)\)/);
  // a project's .codex/config.toml is one of Codex's layers too
  const projectLayer = join(process.cwd(), ".codex", "config.toml");
  const project = await gatherFacts({ HOME: "/Users/u" }, Layout.installed("/opt/mandu"), { ...deps, readKnob: (p: string) => (p === projectLayer ? "[features]\nnetwork_proxy = true\n" : null) });
  assert.equal(project.codexSandbox?.state, "seatbelt-nests");
  assert.ok(renderDoctor(project).includes(`Codex's network proxy is on (${projectLayer})`));
  // config.toml turning its own sandbox off: the same ✓ row as Mandu turning it off (read through the same reader, at $HOME/.codex/config.toml)
  const read: string[] = [];
  const offDeps = { ...deps, readKnob: (p: string) => { read.push(p); return p === "/Users/u/.codex/config.toml" ? 'sandbox_mode = "danger-full-access"\n' : null; } };
  const off = await gatherFacts({ HOME: "/Users/u" }, Layout.installed("/opt/mandu"), offDeps);
  assert.equal(off.codexSandbox?.state, "seatbelt-mandu-off");
  assert.match(renderDoctor(off), /✓ Codex runs commands under mandu on macOS: Mandu turns its own sandbox off for each session/);
  // the doctor knows the host, not the mode a launch runs in: the
  // credential-file clause names mode secrets (review 2), also under MANDU_MODE=off
  const modeOff = await gatherFacts({ HOME: "/Users/u", MANDU_MODE: "off" }, Layout.installed("/opt/mandu"), deps);
  assert.match(renderDoctor(modeOff), /Mandu turns its own sandbox off for each session \(macOS cannot start it inside Mandu's profile\), and in mode secrets Mandu's profile keeps those commands from your credential files/);
  assert.doesNotMatch(renderDoctor(modeOff), /\), and Mandu's profile keeps those commands from your credential files/);
  assert.doesNotMatch(renderDoctor(off), /Codex cannot run/);
  assert.ok(read.includes("/Users/u/.codex/config.toml"));
  assert.ok(read.includes("/Library/Application Support/ClaudeCode/managed-settings.json"), "Claude Code's macOS managed settings are read");
});

// ── Mandu's own git sandbox (git-hardening.md §5) ───────────────────────────

test("gitSandboxFacts: off by MANDU_GIT_SANDBOX=0; the probe's kind (bubblewrap / Seatbelt); Linux without one is unavailable; a macOS miss gives a reason that claims only what was established", () => {
  const found = (sandbox: GitSandboxProbe["sandbox"]): GitSandboxProbe => ({ sandbox, transient: false });
  const none = found(null);
  const bwrap = { bwrap: "/usr/lib/mandu/bin/bwrap", flags: ["--unshare-net"] };
  const seatbelt = { sandboxExec: SANDBOX_EXEC, git: "/Library/Developer/CommandLineTools/usr/bin/git" };
  const mac = { sandboxExec: true, nested: false, git: "/opt/homebrew/Cellar/git/2.51.0/bin/git" };
  const why = (f: ReturnType<typeof gitSandboxFacts>): string => (f.state === "none" ? `${f.gap ? "gap" : "no gap"}: ${f.why}${f.fix !== undefined ? ` | fix: ${f.fix}` : ""}` : `(${f.state})`);
  assert.deepEqual(gitSandboxFacts({ env: { MANDU_GIT_SANDBOX: "0" }, platform: "darwin", probe: none }), { state: "off" });
  assert.deepEqual(gitSandboxFacts({ env: { MANDU_GIT_SANDBOX: "0" }, platform: "linux", probe: found(bwrap) }), { state: "off" });
  assert.deepEqual(gitSandboxFacts({ env: {}, platform: "linux", probe: found(bwrap) }), { state: "on", bwrap: "/usr/lib/mandu/bin/bwrap" });
  assert.deepEqual(gitSandboxFacts({ env: {}, platform: "darwin", probe: found(seatbelt) }), { state: "seatbelt", ...seatbelt });
  assert.deepEqual(gitSandboxFacts({ env: {}, platform: "linux", probe: none }), { state: "unavailable" });
  // A probe that could not finish, on either platform: said so, nothing more, and no ✗.
  for (const platform of ["linux", "darwin"]) {
    assert.match(why(gitSandboxFacts({ env: {}, platform, probe: { sandbox: null, transient: true } })), /^no gap: the probe could not finish/);
  }
  // macOS: each reason from its own fact.
  assert.equal(why(gitSandboxFacts({ env: {}, platform: "darwin", probe: none, darwin: { ...mac, sandboxExec: false } })), "gap: no /usr/bin/sandbox-exec here");
  const nested = why(gitSandboxFacts({ env: {}, platform: "darwin", probe: none, darwin: { ...mac, nested: true } }));
  assert.equal(nested, "no gap: this command runs inside another sandbox profile, which macOS cannot nest a second one in");
  assert.doesNotMatch(nested, /confine/, "no claim in the row that the outer profile confines git");
  assert.equal(why(gitSandboxFacts({ env: {}, platform: "darwin", probe: none, darwin: { ...mac, git: null } })), "gap: no git found on PATH");
  assert.match(why(gitSandboxFacts({ env: {}, platform: "darwin", probe: none, darwin: { ...mac, git: "transient" } })), /^no gap: the probe could not finish/);
  assert.equal(why(gitSandboxFacts({ env: {}, platform: "darwin", probe: none, darwin: { ...mac, git: "/usr/bin/git" } })),
    "gap: /usr/bin/git named no real git to run | fix: xcode-select --install (the Command Line Tools)");
  const other = why(gitSandboxFacts({ env: {}, platform: "darwin", probe: none, darwin: mac }));
  assert.equal(other, "gap: /usr/bin/sandbox-exec could not run /opt/homebrew/Cellar/git/2.51.0/bin/git under the git profile");
  assert.doesNotMatch(other, /nest/, "nesting is claimed only when established");
  assert.match(why(gitSandboxFacts({ env: {}, platform: "win32", probe: none })), /^no gap: .*Linux and macOS/);
});

test("render: the git sandbox row under What Mandu enforces, scoped to the git that gets it; Seatbelt names sandbox-exec and the git; a macOS gap is a ✗ (with its fix when there is one), a probe that could not finish or a nested command a ·", () => {
  const enforced = (out: string): string => out.slice(out.indexOf("What Mandu enforces"));
  const who = "Mandu's background and launch-prep git on folders the AI can change";
  const seatbelt = enforced(renderDoctor({ ...wrapperFacts, gitSandbox: { state: "seatbelt", sandboxExec: SANDBOX_EXEC, git: "/Library/Developer/CommandLineTools/usr/bin/git" } }));
  assert.ok(seatbelt.includes(`  ✓ ${who}: hardened, and run in a sandbox with no network, a read-only view and no other program (/usr/bin/sandbox-exec, git /Library/Developer/CommandLineTools/usr/bin/git)\n`), seatbelt);
  const shim = enforced(renderDoctor({ ...wrapperFacts, gitSandbox: { state: "none", why: "/usr/bin/git named no real git to run", gap: true, fix: "xcode-select --install (the Command Line Tools)" } }));
  assert.ok(shim.includes(`  ✗ ${who}: hardened, but not in a sandbox: /usr/bin/git named no real git to run\n    fix: xcode-select --install (the Command Line Tools)\n`), shim);
  const gap = enforced(renderDoctor({ ...wrapperFacts, gitSandbox: { state: "none", why: "no /usr/bin/sandbox-exec here", gap: true } }));
  const gapRow = `  ✗ ${who}: hardened, but not in a sandbox: no /usr/bin/sandbox-exec here\n`;
  assert.ok(gap.includes(gapRow) && !gap.includes(`${gapRow}    fix:`), gap);
  const nested = enforced(renderDoctor({ ...wrapperFacts, gitSandbox: { state: "none", why: "this command runs inside another sandbox profile, which macOS cannot nest a second one in", gap: false } }));
  assert.ok(nested.includes(`  · ${who}: hardened, not in a sandbox here: this command runs inside another sandbox profile`), nested);
  for (const g of [{ state: "seatbelt", sandboxExec: SANDBOX_EXEC, git: "/x/git" }, { state: "none", why: "x", gap: true }, { state: "none", why: "x", gap: false }] as const) {
    const out = renderDoctor({ ...wrapperFacts, gitSandbox: g });
    assert.doesNotMatch(out, /Mandu's own git/, "never a present-tense claim about all of Mandu's git");
    for (const jargon of [/\btier\b/i, /chokepoint/i, /\barbiter\b/i, /§/]) assert.doesNotMatch(enforced(out), jargon);
  }
});

test("realGitSandboxFacts: the real probe here, and MANDU_GIT_SANDBOX=0 is off on every host", () => {
  assert.deepEqual(realGitSandboxFacts({ ...process.env, MANDU_GIT_SANDBOX: "0" }), { state: "off" });
  const here = realGitSandboxFacts({ ...process.env, MANDU_GIT_SANDBOX: undefined });
  assert.ok(["on", "seatbelt", "unavailable", "none"].includes(here.state), JSON.stringify(here));
  if (process.platform === "darwin" && here.state === "seatbelt") assert.equal(here.sandboxExec, SANDBOX_EXEC);
  if (process.platform !== "linux" && process.platform !== "darwin") assert.equal(here.state, "none");
});

// ── Yama ptrace_scope (rootless-confinement-ubuntu-2404.md §3.3) ─────────────

test("ptraceScopeFacts: Yama's value through the injected reader; null when the file is absent or holds no number", () => {
  const read = (v: string | null) => (p: string): string | null => (p === YAMA_PTRACE_SCOPE ? v : null);
  assert.equal(YAMA_PTRACE_SCOPE, "/proc/sys/kernel/yama/ptrace_scope");
  assert.deepEqual(ptraceScopeFacts(read("1\n")), { value: 1 });
  assert.deepEqual(ptraceScopeFacts(read("0\n")), { value: 0 });
  assert.deepEqual(ptraceScopeFacts(read("3")), { value: 3 });
  assert.deepEqual(ptraceScopeFacts(read(null)), { value: null }, "no Yama in this kernel");
  assert.deepEqual(ptraceScopeFacts(read("")), { value: null });
  assert.deepEqual(ptraceScopeFacts(read("-1\n")), { value: null });
});

test("ptraceScopeRow: ok at 1 or more; a warning at 0 and with no Yama, naming what is weaker and the fix", () => {
  assert.equal(ptraceScopeRow(undefined), null, "not checked (off Linux): no row");
  const one = ptraceScopeRow({ value: 1 })!;
  assert.match(one, /^ {2}✓ Yama ptrace_scope 1: a program can read the memory only of the programs it started/);
  assert.match(ptraceScopeRow({ value: 2 })!, /^ {2}✓ Yama ptrace_scope 2: only an administrator/);
  assert.match(ptraceScopeRow({ value: 3 })!, /^ {2}✓ Yama ptrace_scope 3: no program can read another's memory/);
  const zero = ptraceScopeRow({ value: 0 })!;
  assert.match(zero, /^ {2}✗ Yama ptrace_scope is 0: any program running as you, the AI's included, can read the memory of your other programs/);
  assert.match(zero, /dashboard and its sign-in links/);
  assert.match(zero, /A warning only\./);
  assert.match(zero, /fix: sudo sysctl kernel\.yama\.ptrace_scope=1/);
  const none = ptraceScopeRow({ value: null })!;
  assert.match(none, /^ {2}✗ Yama is not in this kernel \(no \/proc\/sys\/kernel\/yama\/ptrace_scope\)/);
  assert.match(none, /fix: a kernel built with Yama/);
});

test("gatherFacts + render: the Yama row in the secrets section on Linux, read through readKnob; none on macOS", async () => {
  const rt = mkdtempSync(join(tmpdir(), "mandu-doctor-yama-"));
  try {
    const deps = (platform: "linux" | "darwin", scope: string | null): DoctorDeps => ({
      nodeVersion: () => "22.13.0", gitVersion: () => null, commandExists: () => false,
      socketReachable: async () => false, fileExists: () => false, platform: () => platform,
      usernsOk: () => true, readKnob: (p) => (p === YAMA_PTRACE_SCOPE ? scope : null), nativeBin: () => null,
    });
    const env = { MANDU_ARBITER_SOCK: join(rt, "a.sock"), MANDU_RUNTIME_DIR: rt, HOME: rt };
    const weak = await gatherFacts(env, Layout.dev("/repo"), deps("linux", "0\n"));
    assert.deepEqual(weak.ptraceScope, { value: 0 });
    const out = renderDoctor(weak);
    const secrets = out.slice(out.indexOf("Your secrets"), out.indexOf("What Mandu enforces"));
    assert.match(secrets, /✗ Yama ptrace_scope is 0/);
    const ok = await gatherFacts(env, Layout.dev("/repo"), deps("linux", "1\n"));
    assert.match(renderDoctor(ok), /✓ Yama ptrace_scope 1/);
    const mac = await gatherFacts(env, Layout.dev("/repo"), deps("darwin", "0\n"));
    assert.equal(mac.ptraceScope, undefined, "macOS has no Yama: no row");
    assert.doesNotMatch(renderDoctor(mac), /Yama/);
  } finally {
    rmSync(rt, { recursive: true, force: true });
  }
});
