/**
 * doctor-live.test — `mandu doctor --live` over canned launcher runs.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  gatherLive as gatherLiveIn, gradeLaunch, isLinuxOnlyRungLine, livePtyArgv, livePtyFlavor, livePtyScript, livePtyStdin, liveTrueCommand, realDoctorLiveDeps, renderLive, wantsLive,
  type DoctorLiveDeps, type RunResult,
} from "../../src/doctor-live.js";
import { hermetic } from "../lib/test-runtime.js";

/** gatherLive with this file's own runtime dir when the env names none (test-runtime.ts). */
const gatherLive = hermetic(gatherLiveIn, 0);

const FULL_BANNERS = [
  "mandu: fs rung ACTIVE: cooperative — CWD→AgentView worktree",
  "mandu: net-proxy LIVE — cooperative egress gate",
  "mandu: exec-box LIVE — boxing [cat]",
  "mandu: landlock-net LIVE — whole-agent TCP confined (--skip-unsupported degrades on kernel < 6.7)",
  "reply-filter LIVE — the agent's stdout is desymbolized for the human",
].join("\n");

const TOKEN = "$MDU:doctor[1a2b]";

function deps(over: Partial<{ launchCode: number; launchStderr: string; resolve: boolean; leak: boolean; ptyNote: boolean; symbol: string | null; hasScript: boolean; hasCodex: boolean; claudeVersion: string }> = {}): DoctorLiveDeps {
  const o = { launchCode: 0, launchStderr: FULL_BANNERS, resolve: true, leak: false, ptyNote: true, symbol: TOKEN, hasScript: true, hasCodex: true, claudeVersion: "2.1.258 (Claude Code)", ...over };
  let probeValue = ""; // what the doctor asked the arbiter to symbolize
  return {
    launcher: async (args, _env, opts): Promise<RunResult> => {
      const tail = args[args.length - 1] ?? "";
      // L1's no-op, the platform's own (liveTrueCommand): either spelling.
      if (tail === "/usr/bin/true" || tail === "/bin/true") return { code: o.launchCode, stdout: "", stderr: o.launchStderr };
      if (args.includes("/bin/echo")) {
        // The child echoes the TOKEN; a working reply-filter turns it back
        // into the probe value on the way to stdout.
        const out = o.leak ? `${TOKEN}\n` : o.resolve ? `${probeValue}\n` : "\n";
        const note = opts?.pty && o.ptyNote ? "mandu-reply-filter: … PTY RELAY (util-linux script) …\n" : "";
        return { code: 0, stdout: out, stderr: FULL_BANNERS + "\n" + note };
      }
      if (args.includes("--version")) {
        const agent = args[args.indexOf("--target") + 1];
        return { code: 0, stdout: agent === "codex" ? "codex-cli 0.136.0\n" : `${o.claudeVersion}\n`, stderr: FULL_BANNERS };
      }
      if (args.includes("-p")) return { code: 0, stdout: "OK\n", stderr: FULL_BANNERS };
      return { code: 127, stdout: "", stderr: "unexpected" };
    },
    symbolize: async (_sock, value) => { probeValue = value; return o.symbol; },
    commandExists: (cmd) => (cmd === "script" || cmd === "/usr/bin/script" ? o.hasScript : cmd === "codex" ? o.hasCodex : true),
    // Pinned: the Linux grading is the default fixture whatever the host is;
    // the macOS cases below override it.
    platform: "linux",
  };
}

test("every live launch asks for the full banner (MANDU_VERBOSE=1): the default display prints only the mode line (release checklist a6)", async () => {
  const seen: Array<Record<string, string | undefined>> = [];
  const d = deps();
  const inner = d.launcher;
  d.launcher = async (args, env, opts) => { seen.push(env); return inner(args, env, opts); };
  await gatherLive({ HOME: "/h", MANDU_VERBOSE: "0" }, d, { model: true });
  assert.ok(seen.length >= 4, `every check launched: ${seen.length}`);
  for (const env of seen) {
    assert.equal(env["MANDU_VERBOSE"], "1");
    assert.equal(env["HOME"], "/h", "the user's own env is otherwise kept");
  }
});

test("a healthy machine: every check green, model turn skipped unless asked", async () => {
  const rep = await gatherLive({}, deps());
  assert.equal(rep.ok, true);
  const byId = Object.fromEntries(rep.checks.map((c) => [c.id, c]));
  assert.equal(byId["launch"]!.ok, true);
  assert.equal(byId["relay-pipe"]!.ok, true);
  assert.equal(byId["relay-pty"]!.ok, true);
  assert.match(byId["relay-pty"]!.summary, /PTY RELAY/);
  assert.equal(byId["agent-claude"]!.ok, true);
  assert.match(byId["agent-claude"]!.summary, /2\.1\.258/);
  assert.equal(byId["agent-codex"]!.ok, true);
  assert.equal(byId["model"]!.ok, null);
  const withModel = await gatherLive({}, deps(), { model: true });
  assert.equal(withModel.checks.find((c) => c.id === "model")!.ok, true);
  assert.match(renderLive(rep), /Verdict: Mandu works/);
});

test("the bricked launch: a non-zero launch is the only check that runs, and it fails with the last stderr lines", async () => {
  const rep = await gatherLive({}, deps({ launchCode: 1, launchStderr: "mandu: x\nbwrap: Can't mkdir parents for /home/u/tools/linux/x: No such file or directory" }));
  assert.equal(rep.ok, false);
  assert.equal(rep.checks.length, 1);
  assert.match(rep.checks[0]!.summary, /launch FAILED \(exit 1\)/);
  assert.ok(rep.checks[0]!.detail!.some((l) => /Can't mkdir parents/.test(l)));
  assert.match(renderLive(rep), /Verdict: something a real session would hit is broken/);
});

test("a dropped default-on rung fails the launch check even though the process exited 0", async () => {
  const rep = await gatherLive({}, deps({ launchStderr: FULL_BANNERS + "\nmandu: service 'net-proxy' is on by default but failed to start: 127.0.0.1:8790 is occupied — proceeding WITHOUT it" }));
  const launch = rep.checks.find((c) => c.id === "launch")!;
  assert.equal(launch.ok, false);
  assert.match(launch.summary, /1 default-on rung\(s\) dropped/);
  assert.match(launch.detail![0]!, /net-proxy/);
});

test("the relay checks: a raw symbol on the terminal fails; no arbiter fails the pipe check and skips the pty one", async () => {
  const leak = await gatherLive({}, deps({ leak: true }));
  assert.equal(leak.checks.find((c) => c.id === "relay-pipe")!.ok, false);
  assert.match(leak.checks.find((c) => c.id === "relay-pipe")!.summary, /RAW/);
  const noArb = await gatherLive({}, deps({ symbol: null }));
  assert.equal(noArb.checks.find((c) => c.id === "relay-pipe")!.ok, false);
  assert.equal(noArb.checks.find((c) => c.id === "relay-pty")!.ok, null);
  const noScript = await gatherLive({}, deps({ hasScript: false }));
  assert.equal(noScript.checks.find((c) => c.id === "relay-pty")!.ok, null);
});

test("codex absent is a skip, not a failure; --live is the dispatch flag", async () => {
  const rep = await gatherLive({}, deps({ hasCodex: false }));
  assert.equal(rep.checks.find((c) => c.id === "agent-codex")!.ok, null);
  assert.equal(rep.ok, true);
  assert.ok(wantsLive(["--live"]));
  assert.ok(!wantsLive([]));
});

// ── macOS (2026-09-29): the L3 argv per script(1) flavor, and L1 keyed on the platform ──

// The Linux-only rungs as a darwin launch prints them today (older wording:
// "not built … proceeding WITHOUT it", a cargo hint) and as the platform gate
// prints them (newer, informational wording).
const DARWIN_OLD_RUNG_LINES = [
  "mandu: exec-box is on by default, but the mandu-exec-box bin is not built. build with: cd interceptors && cargo build — proceeding WITHOUT it (the listed commands run normally; --no-exec-box silences this).",
  "mandu: the default-on whole-agent TCP confine is unavailable — the mandu-landlock-apply bin is not built; proceeding WITHOUT it (all TCP stays reachable). build with: …",
  "mandu: the default-on whole-agent connect-guard is unavailable — the mandu-net-guard bin is not built; proceeding WITHOUT it (the landlock-net port wrap / netns stay the boundary). build with: …",
  "mandu: the inspect_symbol network confine is unavailable: the mandu-landlock-apply bin is not built; inspect-mcp keeps the agent's TCP allow set",
];
const DARWIN_NEW_RUNG_LINES = [
  "mandu: exec-box: Linux only (not part of the macOS posture)",
  "mandu: landlock-net: Linux only (not part of the macOS posture)",
  "mandu: net-guard: Linux only (not part of the macOS posture)",
];
const DARWIN_BANNERS = [
  "mandu: confidentiality — 3 secret(s) confined via Seatbelt read-deny (raw bytes are absent from the agent's world)",
  "mandu: net-proxy LIVE — cooperative egress gate",
  "reply-filter LIVE — the agent's stdout is desymbolized for the human",
].join("\n");

test("L3 argv per flavor: util-linux gets one quoted -c string, BSD gets the argv after /dev/null (no -e/-f/-c, which BSD rejects)", () => {
  assert.equal(livePtyFlavor("linux"), "util-linux");
  assert.equal(livePtyFlavor("darwin"), "bsd");
  assert.equal(livePtyFlavor("win32"), null);
  const cmd = ["/usr/bin/node", "/x/mandu.ts", "--", "/bin/echo", "it's " + TOKEN];
  // BSD script by absolute path (a PATH entry cannot stand in for it); util-linux on PATH, as before
  assert.deepEqual(livePtyArgv(cmd, "bsd"), ["/usr/bin/script", "-q", "/dev/null", ...cmd]);
  assert.equal(livePtyScript("bsd"), "/usr/bin/script");
  assert.equal(livePtyScript("util-linux"), "script");
  // util-linux: the relay shell execs the command with the user's SHELL
  // handed back (pty-relay.ts buildPtyArgv), or none when there was none.
  assert.deepEqual(livePtyArgv(cmd, "util-linux", "/bin/zsh"), [
    "script", "-qefc", "exec env SHELL='/bin/zsh' '/usr/bin/node' '/x/mandu.ts' '--' '/bin/echo' 'it'\\''s " + TOKEN + "'", "/dev/null",
  ]);
  assert.match(livePtyArgv(cmd, "util-linux", null)[2]!, /^exec env -u SHELL '\/usr\/bin\/node'/);
  // BSD script dies on a piped stdin ("tcgetattr/ioctl: Operation not supported on socket"): /dev/null there
  assert.equal(livePtyStdin("bsd"), "ignore");
  assert.equal(livePtyStdin("util-linux"), "pipe", "Linux keeps spawnSync's empty pipe, as before");
});

test("parity: the doctor's script(1) argv is reply-filter's pty-relay argv, both flavors", async () => {
  const path = "../../../interceptors/reply-filter/src/pty-relay.ts";
  const relay = await import(path) as {
    ptyFlavor: (p: NodeJS.Platform) => string | null;
    buildPtyArgv: (cmd: string[], flavor: string | null) => string[];
  };
  for (const p of ["linux", "darwin", "win32", "freebsd"] as NodeJS.Platform[]) assert.equal(livePtyFlavor(p), relay.ptyFlavor(p), p);
  const cases = [["claude"], ["/bin/echo", "a b", "it's", TOKEN], ["sh", "-c", "exit 3"]];
  for (const flavor of ["util-linux", "bsd"] as const) {
    for (const cmd of cases) assert.deepEqual(livePtyArgv(cmd, flavor), relay.buildPtyArgv(cmd, flavor), `${flavor} ${JSON.stringify(cmd)}`);
  }
});

test("realDoctorLiveDeps carries the platform it was built for (the grading and the flavor key on it)", () => {
  const layout = { mode: "dev", repoRoot: "/r" } as unknown as Parameters<typeof realDoctorLiveDeps>[0];
  assert.equal(realDoctorLiveDeps(layout, "darwin").platform, "darwin");
  assert.equal(realDoctorLiveDeps(layout, "linux").platform, "linux");
});

test("L1 on macOS: the Linux-only rungs are not graded, in the old wording or the new; a real drop still fails", async () => {
  for (const lines of [DARWIN_OLD_RUNG_LINES, DARWIN_NEW_RUNG_LINES]) {
    const rep = await gatherLive({}, { ...deps({ launchStderr: DARWIN_BANNERS + "\n" + lines.join("\n") }), platform: "darwin" });
    const launch = rep.checks.find((c) => c.id === "launch")!;
    assert.equal(launch.ok, true, JSON.stringify(launch));
    assert.match(launch.summary, /launched at the full macOS posture \(2 rung\(s\) live; \d line\(s\) about Linux-only rungs not graded on macOS\)/);
    assert.deepEqual(launch.detail, []);
  }
  // the SAME old-wording lines on Linux are dropped rungs (pinned)
  const linux = await gatherLive({}, { ...deps({ launchStderr: FULL_BANNERS + "\n" + DARWIN_OLD_RUNG_LINES.join("\n") }), platform: "linux" });
  const l1 = linux.checks.find((c) => c.id === "launch")!;
  assert.equal(l1.ok, false);
  assert.match(l1.summary, /3 default-on rung\(s\) dropped\/degraded$/);
  // a macOS drop that is not a Linux-only rung still fails L1
  for (const drop of [
    "mandu: service 'net-proxy' is on by default but failed to start: 127.0.0.1:8790 is occupied — proceeding WITHOUT it",
    "mandu: confidentiality — secrets are GATED (no-sandbox-exec)",
  ]) {
    const rep = await gatherLive({}, { ...deps({ launchStderr: DARWIN_BANNERS + "\n" + DARWIN_OLD_RUNG_LINES.join("\n") + "\n" + drop }), platform: "darwin" });
    const launch = rep.checks.find((c) => c.id === "launch")!;
    assert.equal(launch.ok, false, drop);
    assert.deepEqual(launch.detail, [drop]);
    assert.match(launch.summary, /1 default-on rung\(s\) dropped\/degraded; 3 line\(s\) about Linux-only rungs not graded on macOS/);
  }
});

test("gradeLaunch: pure; on Linux it is postureFindings, off Linux only the Linux-only rung lines move", () => {
  const lines = [...DARWIN_OLD_RUNG_LINES, "mandu: net-proxy LIVE — x", "mandu: service 'fs-view' is on by default but failed to start: y"];
  const onLinux = gradeLaunch(lines, "linux");
  assert.equal(onLinux.dropped.length, 4);
  assert.deepEqual(onLinux.linuxOnly, []);
  const onMac = gradeLaunch(lines, "darwin");
  assert.deepEqual(onMac.dropped, ["mandu: service 'fs-view' is on by default but failed to start: y"]);
  assert.equal(onMac.linuxOnly.length, 3, "the inspect confine line never read as dropped, and it carries no 'Linux only' either");
  assert.equal(gradeLaunch(DARWIN_NEW_RUNG_LINES, "darwin").linuxOnly.length, 3);
  assert.ok(isLinuxOnlyRungLine(DARWIN_OLD_RUNG_LINES[3]!));
  assert.ok(!isLinuxOnlyRungLine("mandu: service 'net-proxy' is on by default but failed to start"));
  // a macOS rung that shares a name but failed in ITS OWN mechanism is a real drop
  const macDrop = "mandu: the default-on whole-agent TCP confine (Seatbelt network rules) could not write its profile — proceeding WITHOUT it";
  assert.equal(isLinuxOnlyRungLine(macDrop), false);
  assert.deepEqual(gradeLaunch([macDrop], "darwin").dropped, [macDrop]);
  // a rung name alone, with no Linux cause, is not enough either
  assert.equal(isLinuxOnlyRungLine("mandu: exec-box is on by default, but the arbiter socket /x is absent — proceeding WITHOUT it"), false);
  assert.ok(isLinuxOnlyRungLine("mandu: exec-box is on by default, but `bwrap` (bubblewrap) is not installed, so the box cannot run — proceeding WITHOUT it"));
});

test("L3 on macOS runs (BSD script is the relay there); a platform with no relay skips it by name", async () => {
  const mac = await gatherLive({}, { ...deps({ launchStderr: DARWIN_BANNERS }), platform: "darwin" });
  assert.equal(mac.checks.find((c) => c.id === "relay-pty")!.ok, true);
  const macNoScript = await gatherLive({}, { ...deps({ launchStderr: DARWIN_BANNERS, hasScript: false }), platform: "darwin" });
  assert.match(macNoScript.checks.find((c) => c.id === "relay-pty")!.summary, /skipped: \/usr\/bin\/script is not there/);
  // macOS asks for /usr/bin/script by path, never the bare name on PATH
  const asked: string[] = [];
  const onPathOnly: DoctorLiveDeps = { ...deps({ launchStderr: DARWIN_BANNERS }), platform: "darwin", commandExists: (c) => { asked.push(c); return c !== "/usr/bin/script"; } };
  const shadow = await gatherLive({}, onPathOnly);
  assert.equal(shadow.checks.find((c) => c.id === "relay-pty")!.ok, null);
  assert.ok(asked.includes("/usr/bin/script") && !asked.includes("script"), asked.join(","));
  // Linux keeps the util-linux PATH lookup and its wording
  const linuxNoScript = await gatherLive({}, deps({ hasScript: false }));
  assert.match(linuxNoScript.checks.find((c) => c.id === "relay-pty")!.summary, /skipped: util-linux script\(1\) not on PATH/);
  let ptyAsked = false;
  const d: DoctorLiveDeps = { ...deps(), platform: "win32" };
  const inner = d.launcher;
  d.launcher = async (args, env, opts) => { if (opts?.pty) ptyAsked = true; return inner(args, env, opts); };
  const win = await gatherLive({}, d);
  const pty = win.checks.find((c) => c.id === "relay-pty")!;
  assert.equal(pty.ok, null);
  assert.match(pty.summary, /no PTY relay on win32/);
  assert.equal(ptyAsked, false);
});

test("L1's no-op is the platform's own: /usr/bin/true on macOS (no /bin/true there), /bin/true elsewhere (a split-/usr Linux has only that)", async () => {
  assert.equal(liveTrueCommand("darwin"), "/usr/bin/true");
  assert.equal(liveTrueCommand("linux"), "/bin/true");
  for (const [platform, want] of [["linux", "/bin/true"], ["darwin", "/usr/bin/true"]] as const) {
    const launched: string[][] = [];
    const d: DoctorLiveDeps = { ...deps({ launchStderr: platform === "darwin" ? DARWIN_BANNERS : FULL_BANNERS }), platform };
    const inner = d.launcher;
    d.launcher = async (args, env, opts) => { launched.push(args); return inner(args, env, opts); };
    const rep = await gatherLive({}, d);
    assert.deepEqual(launched[0], ["--no-scope", "--target", "claude", "--", want], platform);
    assert.equal(rep.checks.find((c) => c.id === "launch")!.ok, true, platform);
  }
});
