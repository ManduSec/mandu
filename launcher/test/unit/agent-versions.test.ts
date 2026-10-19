/**
 * agent-versions.test — the tested agent-version ranges and the check a launch
 * and `mandu doctor` run against them (release checklist e4;
 * docs/design/agents/supported-agents.md). Parsing tolerates every shape the agents
 * print, a prerelease sorts below its release, and a missing binary or an
 * unreadable output is "unknown" (a warning), never a crash or a refusal.
 * The one refusal is OpenCode's (opencodeLaunchRefusal, supported-agents.md
 * §2.3): OpenCode 1 and 2 (`opencode2` too) launch by default; OpenCode 2's
 * prereleases, other majors and an unreadable `opencode` version are refused;
 * MANDU_OPENCODE2=0 refuses OpenCode 2, and the old opt-in
 * MANDU_EXPERIMENTAL_OPENCODE2 changes nothing. Goose, OpenCode 2 and (since
 * 2026-10-09) OpenCode 1 are previews (SupportStatus, supported-agents.md
 * §2.0): one notice line per launch, never a refusal, MANDU_PREVIEW_NOTICE=0
 * hides it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  TESTED_AGENT_GENERATIONS,
  TESTED_AGENT_VERSIONS,
  checkAgentVersion,
  compareAgentVersions,
  OPENCODE2_ENV,
  launchVersionCheck,
  opencode2Enabled,
  opencodeGeneration,
  opencodeInstall,
  opencodeLaunchRefusal,
  opencodeTested,
  testedRangeOf,
  parseAgentVersion,
  probeAgentVersion,
  probeAgentVersionLooking,
  probeAgentVersionWhy,
  VERSION_PROBE_MAX_MS,
  VERSION_PROBE_TIMEOUT_MS,
  versionProbeTimeoutMs,
  rangeWords,
  versionWarning,
  versionedAgentOf,
  ISSUES_URL,
  isPreviewNotice,
  launchPreviewNotice,
  previewNotice,
  rangeLabel,
  supportStatusOf,
} from "../../src/agent-versions.js";
import { AGENTS, LINES, isAgent } from "../../src/generated/agents.js";
import { isAttentionNote } from "../../src/launch-banner.js";

test("parse: every shape the agents print", () => {
  assert.equal(parseAgentVersion("2.1.281 (Claude Code)")?.raw, "2.1.281");
  assert.equal(parseAgentVersion("codex-cli 0.154.0")?.raw, "0.154.0");
  assert.equal(parseAgentVersion("🦞 OpenClaw 2026.3.12 (a712433)")?.raw, "2026.3.12");
  assert.equal(parseAgentVersion("v1.18.13\n")?.raw, "1.18.13");
  // A numeric-only suffix is a packaging revision (openclaw 2026.7.1-2): ignored.
  assert.deepEqual(parseAgentVersion("2026.7.1-2")?.parts, [2026, 7, 1]);
  assert.equal(parseAgentVersion("2026.7.1-2")?.prerelease, null);
  // A lettered suffix is a prerelease.
  assert.equal(parseAgentVersion("2.1.290-beta.1 (Claude Code)")?.prerelease, "beta.1");
  assert.equal(parseAgentVersion("2.1.290-beta.1")?.raw, "2.1.290-beta.1");
});

test("parse: odd or missing output is null, not a guess", () => {
  for (const s of [null, undefined, "", "Claude Code", "version 2.1", "{\"base_url\":\"\"}", "error: unknown option --version"]) {
    assert.equal(parseAgentVersion(s), null, String(s));
  }
});

test("compare: numeric per part, a prerelease sorts below its release", () => {
  const v = (s: string) => parseAgentVersion(s)!;
  assert.equal(compareAgentVersions(v("2.1.281"), v("2.1.273")), 1);
  assert.equal(compareAgentVersions(v("2.1.99"), v("2.1.273")), -1, "numeric, not lexical");
  assert.equal(compareAgentVersions(v("2.1.281"), v("2.1.281")), 0);
  assert.equal(compareAgentVersions(v("2.1.281-rc1"), v("2.1.281")), -1);
  assert.equal(compareAgentVersions(v("2.1.281"), v("2.1.281-rc1")), 1);
  assert.equal(compareAgentVersions(v("2.1.281-alpha"), v("2.1.281-beta")), -1);
});

test("the table: every range parses and min <= max", () => {
  for (const [agent, r] of Object.entries(TESTED_AGENT_VERSIONS)) {
    const lo = parseAgentVersion(r.min);
    const hi = parseAgentVersion(r.max);
    assert.ok(lo && hi, agent);
    assert.ok(compareAgentVersions(lo!, hi!) <= 0, `${agent}: min > max`);
    assert.ok(r.evidence.length > 0, `${agent}: a range carries its evidence`);
  }
});

test("check: tested / newer / older / unknown, boundaries inclusive", () => {
  const { min, max } = TESTED_AGENT_VERSIONS.claude;
  assert.equal(checkAgentVersion("claude", `${min} (Claude Code)`).verdict, "tested");
  assert.equal(checkAgentVersion("claude", `${max} (Claude Code)`).verdict, "tested");
  assert.equal(checkAgentVersion("claude", "9.0.0 (Claude Code)").verdict, "newer");
  // The raised edge (2026-10-09, supported-agents.md §2): 2.1.295 is tested, the next patch is not.
  assert.equal(checkAgentVersion("claude", "2.1.285 (Claude Code)").verdict, "tested");
  assert.equal(checkAgentVersion("claude", "2.1.287 (Claude Code)").verdict, "tested");
  assert.equal(checkAgentVersion("claude", "2.1.292 (Claude Code)").verdict, "tested");
  assert.equal(checkAgentVersion("claude", "2.1.293 (Claude Code)").verdict, "tested");
  assert.equal(checkAgentVersion("claude", "2.1.294 (Claude Code)").verdict, "tested");
  assert.equal(checkAgentVersion("claude", "2.1.295 (Claude Code)").verdict, "tested");
  assert.equal(checkAgentVersion("claude", "2.1.296 (Claude Code)").verdict, "newer");
  assert.equal(checkAgentVersion("claude", "2.1.100 (Claude Code)").verdict, "older");
  // A prerelease of the lowest tested version is older than it.
  assert.equal(checkAgentVersion("claude", `${min}-beta (Claude Code)`).verdict, "older");
  const u = checkAgentVersion("codex", null);
  assert.equal(u.verdict, "unknown");
  assert.equal(u.version, null);
  assert.equal(checkAgentVersion("codex", "codex-cli 0.154.0").verdict, "tested");
  assert.equal(checkAgentVersion("codex", "codex-cli 0.159.1").verdict, "tested");
  assert.equal(checkAgentVersion("codex", "codex-cli 0.160.0").verdict, "tested");
  assert.equal(checkAgentVersion("codex", "codex-cli 0.160.1").verdict, "tested");
  assert.equal(checkAgentVersion("codex", "codex-cli 0.162.0").verdict, "tested");
  assert.equal(checkAgentVersion("codex", "codex-cli 0.162.1").verdict, "newer");
  assert.equal(checkAgentVersion("codex", "codex-cli 0.163.0").verdict, "newer");
  assert.equal(checkAgentVersion("codex", "codex-cli 0.200.0").verdict, "newer");
  // OpenClaw's raised edge (2026-10-09): 2026.9.9 is tested, the next release is not.
  assert.equal(checkAgentVersion("openclaw", "OpenClaw 2026.9.6 (abc)").verdict, "tested");
  assert.equal(checkAgentVersion("openclaw", "OpenClaw 2026.9.9 (abc)").verdict, "tested");
  assert.equal(checkAgentVersion("openclaw", "OpenClaw 2026.9.10 (abc)").verdict, "newer");
  assert.equal(checkAgentVersion("opencode", "1.18.13").verdict, "tested");
  assert.equal(checkAgentVersion("opencode", "1.18.35").verdict, "tested");
  assert.equal(checkAgentVersion("opencode", "1.18.36").verdict, "newer");
});

test("generations: OpenCode 2 is judged against its own tested range, OpenCode 1 against 1.x's", () => {
  // Every generation's range parses, min <= max, carries evidence, and keeps the agent's name.
  for (const [agent, gens] of Object.entries(TESTED_AGENT_GENERATIONS)) {
    for (const g of gens ?? []) {
      const lo = parseAgentVersion(g.min)!;
      const hi = parseAgentVersion(g.max)!;
      assert.ok(lo && hi && compareAgentVersions(lo, hi) <= 0, `${agent} ${g.major}`);
      assert.equal(lo.parts[0], g.major, "a generation's range lies in its major");
      assert.equal(hi.parts[0], g.major);
      assert.ok(g.evidence.length > 0);
      assert.equal(g.name, TESTED_AGENT_VERSIONS[agent as keyof typeof TESTED_AGENT_VERSIONS].name);
    }
  }
  assert.deepEqual([opencodeTested(1).min, opencodeTested(1).max], ["1.18.13", "1.18.35"]);
  assert.deepEqual([opencodeTested(2).min, opencodeTested(2).max], ["2.0.23", "2.0.26"]);
  // 2.0.23 is tested (it used to read "newer than tested" against 1.18.13).
  const v2 = checkAgentVersion("opencode", "opencode v2.0.23");
  assert.deepEqual(v2, { agent: "opencode", name: "OpenCode", min: "2.0.23", max: "2.0.26", version: "2.0.23", verdict: "tested" });
  assert.equal(checkAgentVersion("opencode", "opencode v2.0.26").verdict, "tested");
  assert.equal(versionWarning(v2), null);
  assert.equal(checkAgentVersion("opencode", "2.0.22").verdict, "older");
  const newer = checkAgentVersion("opencode", "opencode v2.0.27");
  assert.equal(newer.verdict, "newer");
  assert.match(versionWarning(newer)!, /^mandu: WARNING — OpenCode 2\.0\.27 is newer than tested \(Mandu was tested with OpenCode 2\.0\.23 to 2\.0\.26\)/);
  // A 1.x past 1.18.35 is newer than 1.x's range, never "older" than 2.x's.
  assert.equal(checkAgentVersion("opencode", "1.18.36").verdict, "newer");
  assert.equal(checkAgentVersion("opencode", "1.18.36").max, "1.18.35");
  // A major with no generation of its own falls back to the agent's range (and is refused at launch).
  assert.equal(checkAgentVersion("opencode", "0.0.0-beta-1").max, "1.18.35");
  assert.equal(checkAgentVersion("opencode", "3.0.0").verdict, "newer");
  // Other agents have no generations.
  assert.equal(testedRangeOf("claude", parseAgentVersion("3.0.0")), TESTED_AGENT_VERSIONS.claude);
  assert.equal(testedRangeOf("opencode", null), TESTED_AGENT_VERSIONS.opencode);
});

test("warning: in range → none; outside → ONE attention line naming the range and the real cost", () => {
  assert.equal(versionWarning(checkAgentVersion("claude", TESTED_AGENT_VERSIONS.claude.max)), null);
  const newer = versionWarning(checkAgentVersion("claude", "9.0.0 (Claude Code)"))!;
  assert.match(newer, /^mandu: WARNING — Claude Code 9\.0\.0 is newer than tested \(Mandu was tested with Claude Code 2\.1\.273 to 2\.1\.295\)/);
  // The truthful risk: unknown tools fail closed (masked), not "unprotected".
  assert.match(newer, /treated as untrusted \(their output is masked/);
  assert.doesNotMatch(newer, /unprotected|not protected/);
  const older = versionWarning(checkAgentVersion("codex", "codex-cli 0.100.0"))!;
  assert.match(older, /Codex 0\.100\.0 is older than tested/);
  const unknown = versionWarning(checkAgentVersion("claude", null))!;
  assert.match(unknown, /could not read the Claude Code version/);
  for (const line of [newer, older, unknown]) {
    assert.ok(isAttentionNote(line), `the compact display must print it: ${line}`);
    assert.ok(!line.includes("\n"), "one line");
    assert.doesNotMatch(line, /login/, "never mistaken for the login note");
  }
});

test("rangeWords: a single tested version reads as one", () => {
  assert.equal(rangeWords({ min: "1.18.13", max: "1.18.13" }), "1.18.13");
  assert.equal(rangeWords({ min: "0.136.0", max: "0.154.0" }), "0.136.0 to 0.154.0");
});

test("which launches are probed: the target's own binary only", () => {
  assert.equal(versionedAgentOf("claude", ["/usr/bin/claude"]), "claude");
  assert.equal(versionedAgentOf("codex", ["codex", "exec"]), "codex");
  assert.equal(versionedAgentOf("claude", ["bash", "-c", "claude"]), null, "a wrapper is not run with --version");
  assert.equal(versionedAgentOf("shell", ["claude"]), null);
  // The versioned agents are the agent registry's (generated/agents.ts), as they were.
  assert.deepEqual([...AGENTS], ["claude", "codex", "openclaw", "opencode", "goose"]);
  assert.deepEqual([...LINES], ["claude", "codex", "openclaw", "opencode", "opencode2", "goose"]);
  assert.deepEqual(Object.keys(TESTED_AGENT_VERSIONS), [...AGENTS]);
  for (const a of AGENTS) assert.equal(versionedAgentOf(a, [`/usr/local/bin/${a}`]), a, a);
  for (const t of ["opencode2", "aider", ""]) assert.equal(versionedAgentOf(t, [t]), null, t);
  assert.equal(isAgent("shell"), false);
  assert.equal(versionedAgentOf("claude", []), null);
});

test("launch check: uses the injected probe, skips `--version` launches, never throws on a failing probe", () => {
  let asked = "";
  const r = launchVersionCheck("claude", ["/x/claude", "-p", "hi"], (bin) => { asked = bin; return "9.9.9 (Claude Code)"; });
  assert.equal(asked, "/x/claude");
  assert.equal(r?.check.verdict, "newer");
  assert.match(r!.note!, /newer than tested/);
  assert.equal(launchVersionCheck("claude", ["claude", "--version"], () => { throw new Error("must not probe"); }), null);
  assert.equal(launchVersionCheck("claude", ["claude"], () => null)?.check.verdict, "unknown");
  assert.equal(launchVersionCheck("claude", ["claude"], () => `${TESTED_AGENT_VERSIONS.claude.max} (Claude Code)`)?.note, null);
});

test("probe: a real binary's output; a missing binary, a failing one and a hung one are null", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-agent-ver-"));
  try {
    const ok = join(dir, "claude");
    writeFileSync(ok, "#!/bin/sh\n[ \"$1\" = --version ] && echo '2.1.281 (Claude Code)'\n");
    chmodSync(ok, 0o755);
    assert.equal(probeAgentVersion(ok), "2.1.281 (Claude Code)");
    const fails = join(dir, "codex");
    writeFileSync(fails, "#!/bin/sh\necho 'error: unknown flag' >&2\nexit 2\n");
    chmodSync(fails, 0o755);
    assert.equal(probeAgentVersion(fails), null);
    assert.equal(probeAgentVersion(join(dir, "definitely-absent")), null);
    const hangs = join(dir, "opencode");
    writeFileSync(hangs, "#!/bin/sh\nexec sleep 30\n");
    chmodSync(hangs, 0o755);
    const t0 = Date.now();
    assert.equal(probeAgentVersion(hangs, undefined, 1_000), null);
    assert.ok(Date.now() - t0 < 10_000, "time-bounded");
    // Why there is no version: the refusal says it.
    assert.deepEqual(probeAgentVersionWhy(ok), { version: "2.1.281 (Claude Code)", why: null });
    assert.deepEqual(probeAgentVersionWhy(fails), { version: null, why: "exit 2: error: unknown flag" });
    assert.deepEqual(probeAgentVersionWhy(hangs, undefined, 500), { version: null, why: "timed out after 500 ms" });
    assert.match(probeAgentVersionWhy(join(dir, "definitely-absent")).why!, /ENOENT/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("probeAgentVersionLooking: codex gets a throwaway CODEX_HOME, removed after, so the user's ~/.codex is untouched; another agent runs as is", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-agent-ver-look-"));
  try {
    const home = join(dir, "home");
    mkdirSync(home);
    const seen = join(dir, "seen");
    // What codex-cli 0.155.1 does at every start: helper links under $CODEX_HOME/tmp/arg0.
    const codex = join(dir, "codex");
    writeFileSync(codex, `#!/bin/sh\nh="\${CODEX_HOME:-$HOME/.codex}"\nmkdir -p "$h/tmp/arg0" && echo "$h" > "${seen}"\necho 'codex-cli 0.155.1'\n`);
    chmodSync(codex, 0o755);
    const env = { PATH: process.env["PATH"], HOME: home };
    assert.equal(probeAgentVersion(codex, env), "codex-cli 0.155.1");
    assert.ok(existsSync(join(home, ".codex", "tmp", "arg0")), "control: the plain probe writes the user's ~/.codex");
    rmSync(join(home, ".codex"), { recursive: true });
    assert.equal(probeAgentVersionLooking(codex, env), "codex-cli 0.155.1");
    assert.deepEqual(readdirSync(home), [], "nothing under HOME");
    const used = readFileSync(seen, "utf8").trim();
    assert.notEqual(used, join(home, ".codex"));
    assert.equal(existsSync(used), false, "the throwaway CODEX_HOME is removed");
    const claude = join(dir, "claude");
    writeFileSync(claude, `#!/bin/sh\necho "\${CODEX_HOME:-unset} (Claude Code)"\n`);
    chmodSync(claude, 0o755);
    assert.equal(probeAgentVersionLooking(claude, env), "unset (Claude Code)", "only codex gets one");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("probeAgentVersionLooking: opencode and opencode2 get throwaway XDG folders, removed after (OpenCode makes its folders and a log even for --version)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-agent-ver-look-oc-"));
  try {
    const home = join(dir, "home");
    mkdirSync(home);
    const seen = join(dir, "seen");
    for (const name of ["opencode", "opencode2"]) {
      // What OpenCode 2.0.23 does at every start: its XDG folders, and a log.
      const bin = join(dir, name);
      writeFileSync(bin, `#!/bin/sh\nd="\${XDG_DATA_HOME:-$HOME/.local/share}/opencode/log"\nmkdir -p "$d" "\${XDG_STATE_HOME:-$HOME/.local/state}/opencode" && touch "$d/opencode.log" && echo "$d" > "${seen}"\necho 'opencode v2.0.23'\n`);
      chmodSync(bin, 0o755);
      assert.equal(probeAgentVersionLooking(bin, { PATH: process.env["PATH"], HOME: home }), "opencode v2.0.23", name);
      assert.deepEqual(readdirSync(home), [], `nothing under HOME (${name})`);
      const used = readFileSync(seen, "utf8").trim();
      assert.ok(!used.startsWith(home), name);
      assert.equal(existsSync(used), false, `the throwaway folders are removed (${name})`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("probeAgentVersionLooking: goose gets throwaway XDG folders, removed after (goose 1.53.0 writes a log under $XDG_STATE_HOME even for --version)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-agent-ver-look-goose-"));
  try {
    const home = join(dir, "home");
    mkdirSync(home);
    const seen = join(dir, "seen");
    // What goose 1.53.0 does on --version: a CLI log under its state folder, and " 1.53.0".
    const bin = join(dir, "goose");
    writeFileSync(bin, `#!/bin/sh\nd="\${XDG_STATE_HOME:-$HOME/.local/state}/goose/logs/cli"\nmkdir -p "$d" && touch "$d/v.log" && echo "$d" > "${seen}"\necho ' 1.53.0'\n`);
    chmodSync(bin, 0o755);
    const env = { PATH: process.env["PATH"], HOME: home };
    assert.equal(probeAgentVersion(bin, env), "1.53.0");
    assert.ok(existsSync(join(home, ".local", "state", "goose")), "control: the plain probe writes the user's state folder");
    rmSync(join(home, ".local"), { recursive: true });
    assert.equal(probeAgentVersionLooking(bin, env), "1.53.0");
    assert.deepEqual(readdirSync(home), [], "nothing under HOME");
    const used = readFileSync(seen, "utf8").trim();
    assert.ok(!used.startsWith(home));
    assert.equal(existsSync(used), false, "the throwaway folders are removed");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("goose: probed as its own binary and judged against its range; a wrapper is not probed", () => {
  const { min, max } = TESTED_AGENT_VERSIONS.goose;
  assert.equal(versionedAgentOf("goose", ["goose", "session"]), "goose");
  assert.equal(versionedAgentOf("goose", ["/opt/bin/goose", "run", "-t", "hi"]), "goose");
  assert.equal(versionedAgentOf("goose", ["my-goose-wrapper"]), null);
  assert.equal(launchVersionCheck("goose", ["goose", "session"], () => ` ${max}`)?.note, null, "the tested version says nothing");
  assert.equal(launchVersionCheck("goose", ["goose", "--version"], () => { throw new Error("not probed"); }), null);
  const newer = launchVersionCheck("goose", ["goose", "session"], () => " 1.55.0");
  assert.equal(newer?.check.verdict, "newer");
  assert.match(newer?.note ?? "", /WARNING — Goose 1\.55\.0 is newer than tested \(Mandu was tested with Goose 1\.53\.0 to 1\.54\.0\)/);
  assert.equal(checkAgentVersion("goose", min).verdict, "tested");
  // A warning, never a refusal: only OpenCode's version decides its routing.
  assert.equal(opencodeLaunchRefusal("goose", ["goose", "session"], newer!.check), null);
});

test("opencode refusal: OpenCode 1 and 2 launch by default; prereleases, other majors and an unreadable version are refused", () => {
  const probes: string[] = [];
  const decide = (argv: string[], out: string | null, opts: { opencode2?: boolean } = {}) => {
    const check = launchVersionCheck("opencode", argv, (bin) => { probes.push(bin); return out; }, opts)?.check ?? null;
    return { refusal: opencodeLaunchRefusal("opencode", argv, check, opts), generation: opencodeGeneration("opencode", argv, check) };
  };
  // OpenCode 1: every 1.x launches (newer / older are the version WARNING's job), generation 1 (argv untouched).
  for (const out of ["1.18.13", "v1.18.13\n", "1.18.34", "1.0.142"]) {
    assert.deepEqual(decide(["opencode", "run", "hi"], out), { refusal: null, generation: 1 }, out);
  }
  // OpenCode 2, as `opencode` or `opencode2`, launches by default and is generation 2 (its argv is then rewritten, opencode-argv.ts).
  assert.deepEqual(decide(["/usr/local/bin/opencode", "run", "hi"], "opencode v2.0.23"), { refusal: null, generation: 2 });
  assert.deepEqual(decide(["opencode"], "opencode v2.0.22"), { refusal: null, generation: 2 });
  assert.deepEqual(decide(["opencode"], "opencode v2.1.0-beta.1"), { refusal: null, generation: 2 });
  probes.length = 0;
  assert.deepEqual(decide(["/opt/bin/opencode2", "run", "hi"], "opencode v2.0.23"), { refusal: null, generation: 2 });
  assert.deepEqual(probes, ["/opt/bin/opencode2"], "opencode2 is probed like opencode");
  // Still refused: an unreadable version, OpenCode 2's 0.0.0-* prereleases, majors other than 1 and 2.
  const unreadable = decide(["opencode", "run", "x"], null).refusal!;
  assert.match(unreadable, /^mandu: refusing to launch opencode: could not read its version .*cannot tell OpenCode 1 from OpenCode 2/);
  assert.match(unreadable, /Mandu supports OpenCode 1 \(npm opencode-ai; tested with 1\.18\.13 to 1\.18\.35\) and OpenCode 2 \(npm @opencode\/cli; tested with 2\.0\.23 to 2\.0\.26\)/);
  assert.match(unreadable, /npm i -g opencode-ai@1\.18\.35, or npm i -g @opencode\/cli@2\.0\.26/);
  assert.match(opencodeLaunchRefusal("opencode", ["opencode"], null)!, /could not read its version/);
  assert.match(
    opencodeLaunchRefusal("opencode", ["opencode"], null, { probeWhy: "timed out after 10000 ms" })!,
    /could not read its version \(`opencode --version`: timed out after 10000 ms\), so Mandu/,
  );
  for (const [argv, out, re] of [
    [["opencode2", "run", "x"], null, /could not read its version/],
    [["opencode", "run", "x"], "opencode v0.0.0-beta-19507", /^mandu: refusing to launch OpenCode 0\.0\.0-beta-19507\. Mandu supports OpenCode 1 .* and OpenCode 2/],
    [["opencode", "run", "x"], "0.0.0-dev-20538", /refusing to launch OpenCode 0\.0\.0-dev-20538/],
    [["opencode"], "3.1.0", /refusing to launch OpenCode 3\.1\.0/],
    [["opencode2"], "opencode v3.0.0", /refusing to launch OpenCode 3\.0\.0/],
    // opencode2 must really be OpenCode 2.
    [["opencode2"], "1.18.13", /refusing to launch OpenCode 1\.18\.13 \(opencode2 is OpenCode 2's command, so it must report version 2\)/],
  ] as const) {
    const r = decide([...argv], out).refusal ?? "";
    assert.match(r, re, `${argv.join(" ")} / ${String(out)}`);
    assert.ok(!r.includes("\n"), "one line");
    assert.doesNotMatch(r, /experimental|opt-in|MANDU_EXPERIMENTAL/i, "OpenCode 2 is no longer behind an opt-in");
  }
  // A `--version` launch makes no model call; another target is not this check's.
  assert.equal(opencodeLaunchRefusal("opencode", ["opencode", "--version"], null), null);
  assert.equal(opencodeLaunchRefusal("opencode", ["opencode2", "--version"], null), null);
  assert.equal(opencodeLaunchRefusal("claude", ["claude"], null), null);
  assert.equal(opencodeLaunchRefusal("shell", ["opencode2"], null), null);
  // A wrapper launched with --target opencode is not probed and not refused here.
  assert.equal(opencodeLaunchRefusal("opencode", ["node", "oc-wrapper.mjs"], null), null);
  // The generation is OpenCode's only; a wrapper or an unprobed launch has none.
  assert.equal(opencodeGeneration("claude", ["claude"], null), null);
  assert.equal(opencodeGeneration("opencode", ["node", "oc-wrapper.mjs"], null), null);
  assert.equal(opencodeGeneration("opencode", ["opencode"], null), null);
  assert.equal(opencodeGeneration("opencode", ["opencode2"], null), 2);
  // versionedAgentOf: opencode2 counts as the opencode binary.
  assert.equal(versionedAgentOf("opencode", ["opencode2"]), "opencode");
  assert.equal(versionedAgentOf("claude", ["opencode2"]), null);
  assert.equal(opencodeInstall(1), "npm i -g opencode-ai@1.18.35");
  assert.equal(opencodeInstall(2), "npm i -g @opencode/cli@2.0.26");
});

test("MANDU_OPENCODE2=0 turns OpenCode 2 off; MANDU_EXPERIMENTAL_OPENCODE2 is no longer read", () => {
  assert.equal(OPENCODE2_ENV, "MANDU_OPENCODE2");
  // On unless an explicit no.
  for (const v of [undefined, "", "1", "true", "on", "yes", "2"]) assert.equal(opencode2Enabled({ MANDU_OPENCODE2: v }), true, String(v));
  for (const v of ["0", "false", "off", "no", " NO "]) assert.equal(opencode2Enabled({ MANDU_OPENCODE2: v }), false, v);
  // The old opt-in is a no-op either way.
  assert.equal(opencode2Enabled({ MANDU_EXPERIMENTAL_OPENCODE2: "0" }), true);
  assert.equal(opencode2Enabled({ MANDU_EXPERIMENTAL_OPENCODE2: "1", MANDU_OPENCODE2: "0" }), false);

  const off = { opencode2: false };
  const probes: string[] = [];
  const decide = (argv: string[], out: string | null) => {
    const check = launchVersionCheck("opencode", argv, (bin) => { probes.push(bin); return out; }, off)?.check ?? null;
    return opencodeLaunchRefusal("opencode", argv, check, off);
  };
  // Off: OpenCode 2 is refused with a plain line naming the variable.
  const v2 = decide(["opencode", "run", "hi"], "opencode v2.0.23")!;
  assert.equal(v2, "mandu: refusing to launch OpenCode 2.0.23: MANDU_OPENCODE2=0 turns OpenCode 2 off. Unset MANDU_OPENCODE2 to run it, or use OpenCode 1 (npm i -g opencode-ai@1.18.35).");
  probes.length = 0;
  assert.match(decide(["/opt/bin/opencode2", "run", "hi"], "opencode v2.0.23")!, /^mandu: refusing to launch \/opt\/bin\/opencode2: it is OpenCode 2's command, and MANDU_OPENCODE2=0 turns OpenCode 2 off\./);
  assert.deepEqual(probes, [], "opencode2 is never run when OpenCode 2 is off, not even for --version");
  assert.equal(versionedAgentOf("opencode", ["opencode2"], off), null);
  assert.match(opencodeLaunchRefusal("opencode", ["opencode2", "--version"], null, off)!, /MANDU_OPENCODE2=0/);
  // OpenCode 1 is unchanged; the unreadable / other-major refusals name only OpenCode 1 as the way out.
  assert.equal(decide(["opencode", "run", "hi"], "1.18.13"), null);
  const unreadable = decide(["opencode", "run", "x"], null)!;
  assert.match(unreadable, /could not read its version .*MANDU_OPENCODE2=0 turns OpenCode 2 off\. Install OpenCode 1 \(npm i -g opencode-ai@1\.18\.35\)\.$/);
  assert.match(decide(["opencode"], "3.0.0")!, /refusing to launch OpenCode 3\.0\.0\. .*Install OpenCode 1/);
});

test("support status: Goose, OpenCode 1 and OpenCode 2 are previews; Claude Code, Codex and OpenClaw are supported", () => {
  const status = Object.fromEntries(Object.entries(TESTED_AGENT_VERSIONS).map(([a, r]) => [a, r.status]));
  assert.deepEqual(status, { claude: "supported", codex: "supported", openclaw: "supported", opencode: "preview", goose: "preview" });
  assert.deepEqual(TESTED_AGENT_GENERATIONS.opencode?.map((g) => [rangeLabel(g), g.status]), [["OpenCode 2", "preview"]]);
  assert.equal(rangeLabel(TESTED_AGENT_VERSIONS.opencode), "OpenCode");
  // The status follows the line the version belongs to (testedRangeOf).
  assert.equal(supportStatusOf("opencode", "opencode v2.0.23"), "preview");
  assert.equal(supportStatusOf("opencode", "2.0.99"), "preview", "outside 2.x's range is still OpenCode 2");
  assert.equal(supportStatusOf("opencode", "1.18.13"), "preview", "OpenCode 1 is a preview since 2026-10-09");
  assert.equal(supportStatusOf("opencode", "1.19.0"), "preview", "outside 1.x's range is still OpenCode 1");
  assert.equal(supportStatusOf("opencode", null), "preview", "unreadable: the first line's");
  assert.equal(supportStatusOf("goose", null), "preview");
  assert.equal(supportStatusOf("claude", "2.1.295"), "supported");
});

test("preview notice: one short line for Goose and OpenCode (1, 2, or a wrapper: both lines agree); not for a supported agent, --version, or under MANDU_PREVIEW_NOTICE=0", () => {
  const goose = launchPreviewNotice("goose", ["goose", "session"], null, {});
  assert.equal(goose, `mandu: ! Goose support is a preview: tested less than Claude Code and Codex; report problems at ${ISSUES_URL}`);
  assert.equal(goose, previewNotice("Goose"));
  assert.ok(isPreviewNotice(goose!));
  assert.equal(isAttentionNote(goose!), false, "advice, not a degrade: it never reads as a warning");
  // Keyed on the target: a wrapper script started as --target goose is still Goose.
  assert.equal(launchPreviewNotice("goose", ["/opt/bin/my-goose"], null, {}), goose);
  assert.equal(launchPreviewNotice("opencode", ["opencode", "run", "--standalone", "hi"], 2, {}), previewNotice("OpenCode 2"));
  assert.equal(launchPreviewNotice("opencode", ["opencode2"], 2, {}), previewNotice("OpenCode 2"));
  assert.equal(launchPreviewNotice("opencode", ["opencode", "run", "hi"], 1, {}), previewNotice("OpenCode"), "OpenCode 1, under its README name");
  assert.equal(launchPreviewNotice("opencode", ["opencode", "--version"], 1, {}), null);
  // A wrapper (generation unknown): every OpenCode line is a preview, so the
  // claim holds whichever it starts, under the agent's plain name.
  assert.equal(launchPreviewNotice("opencode", ["my-wrapper"], null, {}), previewNotice("OpenCode"));
  for (const v of ["0", "off"]) {
    for (const gen of [1, 2, null] as const) assert.equal(launchPreviewNotice("opencode", ["opencode"], gen, { MANDU_PREVIEW_NOTICE: v }), null, `${v} ${String(gen)}`);
  }
  for (const t of ["claude", "codex", "openclaw", "shell", "bash"]) assert.equal(launchPreviewNotice(t, [t], null, {}), null, t);
  assert.equal(launchPreviewNotice("goose", ["goose", "--version"], null, {}), null);
  for (const v of ["0", "false", "off", "no", " OFF "]) assert.equal(launchPreviewNotice("goose", ["goose"], null, { MANDU_PREVIEW_NOTICE: v }), null, v);
  for (const v of ["1", "true", ""]) assert.equal(launchPreviewNotice("goose", ["goose"], null, { MANDU_PREVIEW_NOTICE: v }), goose, v);
  // The other launch lines are not mistaken for it.
  assert.equal(isPreviewNotice(versionWarning(checkAgentVersion("goose", "9.0.0"))!), false);
});

test("versionProbeTimeoutMs: the idle budget, stretched by load per CPU, capped (a loaded CI guest missed the old 3 s)", () => {
  assert.equal(versionProbeTimeoutMs({ load1: 0.5, ncpu: 16 }), VERSION_PROBE_TIMEOUT_MS);
  assert.equal(versionProbeTimeoutMs({ load1: 16, ncpu: 16 }), VERSION_PROBE_TIMEOUT_MS);
  assert.equal(versionProbeTimeoutMs({ load1: 48, ncpu: 16 }), 3 * VERSION_PROBE_TIMEOUT_MS);
  assert.equal(versionProbeTimeoutMs({ load1: 1000, ncpu: 16 }), VERSION_PROBE_MAX_MS);
  assert.equal(versionProbeTimeoutMs({ load1: Number.NaN, ncpu: 16 }), VERSION_PROBE_TIMEOUT_MS);
  assert.equal(versionProbeTimeoutMs({ load1: 4, ncpu: 0 }), VERSION_PROBE_TIMEOUT_MS);
});
