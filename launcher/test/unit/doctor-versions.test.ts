/**
 * doctor-versions.test — `mandu doctor`'s agent-version rows (release
 * checklist e4; agent-versions.ts). An installed agent gets one row: ✓ inside
 * the tested range, ✗ outside it with what it costs, · when its version could
 * not be read. An agent that is not installed gets none, and a fixture
 * without a probe never runs the host's real agent.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { hermetic } from "../lib/test-runtime.js";
import { gatherFacts as gatherFactsIn, opencodeVersionRow, PREVIEW_WORDS, renderDoctor, versionRow, type DoctorDeps } from "../../src/doctor.js";
import { checkAgentVersion, TESTED_AGENT_VERSIONS } from "../../src/agent-versions.js";
import { Layout } from "../../src/services/layout.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** gatherFacts with this file's own runtime dir when the env names none (test-runtime.ts). */
const gatherFacts = hermetic(gatherFactsIn, 0);

const base = (o: Partial<DoctorDeps>): DoctorDeps => ({
  nodeVersion: () => "22.13.0",
  gitVersion: () => "2.43.0",
  commandExists: () => true,
  socketReachable: async () => false,
  fileExists: () => false,
  platform: () => "linux",
  usernsOk: () => true,
  readKnob: () => null,
  nativeBin: () => null,
  ...o,
});

test("versionRow: tested / newer / older / unknown", () => {
  const max = TESTED_AGENT_VERSIONS.claude.max;
  assert.equal(versionRow(checkAgentVersion("claude", max)), `  ✓ Claude Code ${max}: a tested version (tested: 2.1.273 to ${max})`);
  assert.match(versionRow(checkAgentVersion("claude", "3.0.0")), /^ {2}✗ Claude Code 3\.0\.0: newer than tested \(tested: 2\.1\.273 to .*\); tools it adds that Mandu does not know are masked whole/);
  assert.match(versionRow(checkAgentVersion("codex", "codex-cli 0.90.0")), /^ {2}✗ Codex 0\.90\.0: older than tested/);
  assert.match(versionRow(checkAgentVersion("codex", null)), /^ {2}· Codex: could not read its version \(tested: 0\.136\.0 to 0\.162\.0\)/);
});

test("versionRow: a preview agent's row (Goose, OpenCode 1 and 2) says so in every verdict; a supported agent's never does", () => {
  const { min: gmin, max: gmax } = TESTED_AGENT_VERSIONS.goose;
  assert.equal(versionRow(checkAgentVersion("goose", ` ${gmax}`)), `  ✓ Goose ${gmax}: a tested version (tested: ${gmin} to ${gmax}); ${PREVIEW_WORDS}`);
  for (const out of [" 9.0.0", " 0.1.0", null, "opencode v2.0.23", "2.0.99", "opencode 1.18.35", "opencode 1.19.0", "opencode 1.0.0"]) {
    const agent = out !== null && out.includes("opencode") || out === "2.0.99" ? "opencode" : "goose";
    assert.ok(versionRow(checkAgentVersion(agent, out)).endsWith(`; ${PREVIEW_WORDS}`), `${agent} ${String(out)}`);
  }
  for (const [agent, out] of [["claude", "2.1.295"], ["codex", "0.200.0"], ["openclaw", null]] as const) {
    assert.ok(!versionRow(checkAgentVersion(agent, out)).includes("preview"), `${agent} ${String(out)}`);
  }
});

test("gatherFacts + render: each installed agent is probed once and gets its row; a missing one gets none", async () => {
  const asked: string[] = [];
  const deps = base({
    commandExists: (c) => c === "claude",
    agentVersion: (bin) => { asked.push(bin); return "9.0.0 (Claude Code)"; },
  });
  const facts = await gatherFacts({ MANDU_ARBITER_SOCK: "/tmp/none.sock" }, Layout.dev("/repo"), deps);
  assert.deepEqual(asked, ["claude"], "codex is not installed, so it is not run");
  assert.equal(facts.versions?.claude?.verdict, "newer");
  assert.equal(facts.versions?.codex, null);
  const out = renderDoctor(facts);
  assert.match(out, /✗ Claude Code 9\.0\.0: newer than tested/);
  assert.doesNotMatch(out, /Codex: could not read/);
});

test("gatherFacts: no probe injected ⇒ the row says it could not read the version (the host's agent is never run)", async () => {
  const facts = await gatherFacts({}, Layout.installed("/opt/mandu"), base({}));
  assert.equal(facts.versions?.claude?.verdict, "unknown");
  assert.equal(facts.versions?.codex?.verdict, "unknown");
  assert.match(renderDoctor(facts), /· Claude Code: could not read its version/);
});

test("the OpenCode row: OpenCode 1 and 2 are version rows against their own ranges; OpenCode 2 off, an unreadable version and the rest are refused", () => {
  const row = (bin: "opencode" | "opencode2", out: string | null, opencode2 = true) => opencodeVersionRow({ bin, check: checkAgentVersion("opencode", out), opencode2 });
  assert.equal(row("opencode", "1.18.13"), `  ✓ OpenCode 1.18.13: a tested version (tested: 1.18.13 to 1.18.35); ${PREVIEW_WORDS}`);
  assert.match(row("opencode", "1.18.36"), /^ {2}✗ OpenCode 1\.18\.36: newer than tested \(tested: 1\.18\.13 to 1\.18\.35\).*; a preview: tested less than Claude Code and Codex$/);
  // OpenCode 2, as `opencode` or `opencode2`: judged against 2.x's range, with what its launches get.
  for (const bin of ["opencode", "opencode2"] as const) {
    assert.match(
      row(bin, "opencode v2.0.23"),
      /^ {2}✓ OpenCode 2\.0\.23: a tested version \(tested: 2\.0\.23 to 2\.0\.26\); a preview: tested less than Claude Code and Codex; OpenCode 2: each launch gets a private server \(--standalone\) that only OpenCode itself can reach, and secrets mode runs only where the kernel connect guard, the write-protect guard and its config lockdown all run/,
    );
  }
  assert.match(row("opencode", "opencode v2.0.27"), /^ {2}✗ OpenCode 2\.0\.27: newer than tested \(tested: 2\.0\.23 to 2\.0\.26\).*; a preview: tested less than Claude Code and Codex; OpenCode 2: each launch gets a private server/);
  // MANDU_OPENCODE2=0: refused, and the row says how to turn it back on.
  assert.equal(
    row("opencode", "opencode v2.0.23", false),
    "  ✗ OpenCode 2.0.23 is OpenCode 2: MANDU_OPENCODE2=0 turns it off, so `mandu opencode` refuses it; unset MANDU_OPENCODE2 to run it",
  );
  assert.match(row("opencode", null), /^ {2}· OpenCode \(opencode\): could not read its version, so `mandu opencode` refuses it/);
  assert.match(
    row("opencode", "opencode v0.0.0-beta-19507"),
    /^ {2}✗ OpenCode 0\.0\.0-beta-19507 \(opencode\): `mandu opencode` refuses it \(Mandu supports OpenCode 1, tested: 1\.18\.13 to 1\.18\.35, and OpenCode 2, tested: 2\.0\.23 to 2\.0\.26\); install one of them \(npm i -g opencode-ai@1\.18\.35, or npm i -g @opencode\/cli@2\.0\.26\)$/,
  );
  assert.match(row("opencode2", "1.18.13"), /^ {2}✗ OpenCode 1\.18\.13 \(opencode2\): `mandu opencode` refuses it/);
  for (const r of [row("opencode", "opencode v2.0.23"), row("opencode", "opencode v2.0.23", false), row("opencode", "3.0.0")]) {
    assert.doesNotMatch(r, /experimental|opt-in|MANDU_EXPERIMENTAL/i, r);
  }
});

test("gatherFacts + render: an installed OpenCode (opencode, else opencode2) is probed and gets its row; MANDU_OPENCODE2=0 shows; none when absent", async (t) => {
  // A private runtime dir: the default one (/tmp/mandu without
  // XDG_RUNTIME_DIR) may belong to another user on a shared host.
  const RT = { MANDU_RUNTIME_DIR: mkdtempSync(join(tmpdir(), "mandu-doctor-oc-")) };
  t.after(() => rmSync(RT.MANDU_RUNTIME_DIR, { recursive: true, force: true }));
  const asked: string[] = [];
  const probe = (out: string) => (bin: string): string => { asked.push(bin); return bin === "claude" ? "9.0.0 (Claude Code)" : out; };
  const only = (...names: string[]) => (c: string): boolean => names.includes(c);
  let facts = await gatherFacts({ ...RT }, Layout.dev("/repo"), base({ commandExists: only("claude", "opencode"), agentVersion: probe("1.18.13") }));
  assert.deepEqual(asked, ["claude", "opencode"]);
  assert.match(renderDoctor(facts), /✓ OpenCode 1\.18\.13: a tested version/);
  asked.length = 0;
  facts = await gatherFacts({ ...RT }, Layout.dev("/repo"), base({ commandExists: only("claude", "opencode2"), agentVersion: probe("opencode v2.0.23") }));
  assert.deepEqual(asked, ["claude", "opencode2"]);
  assert.equal(facts.versions?.opencode?.bin, "opencode2");
  assert.equal(facts.versions?.opencode?.opencode2, true);
  assert.match(renderDoctor(facts), /✓ OpenCode 2\.0\.23: a tested version \(tested: 2\.0\.23 to 2\.0\.26\); a preview: tested less than Claude Code and Codex; OpenCode 2: each launch gets a private server/);
  facts = await gatherFacts({ ...RT, MANDU_OPENCODE2: "0" }, Layout.dev("/repo"), base({ commandExists: only("claude", "opencode"), agentVersion: probe("opencode v2.0.23") }));
  assert.equal(facts.versions?.opencode?.opencode2, false);
  assert.match(renderDoctor(facts), /✗ OpenCode 2\.0\.23 is OpenCode 2: MANDU_OPENCODE2=0 turns it off/);
  facts = await gatherFacts({ ...RT }, Layout.dev("/repo"), base({ commandExists: only("claude"), agentVersion: probe("x") }));
  assert.equal(facts.versions?.opencode, null);
  assert.doesNotMatch(renderDoctor(facts), /OpenCode/);
});

test("gatherFacts + render: an installed Goose is probed and gets its version row, marked a preview; none when absent", async (t) => {
  const RT = { MANDU_RUNTIME_DIR: mkdtempSync(join(tmpdir(), "mandu-doctor-goose-")) };
  t.after(() => rmSync(RT.MANDU_RUNTIME_DIR, { recursive: true, force: true }));
  const asked: string[] = [];
  const probe = (out: string) => (bin: string): string => { asked.push(bin); return bin === "claude" ? "9.0.0 (Claude Code)" : out; };
  const only = (...names: string[]) => (c: string): boolean => names.includes(c);
  const { min, max } = TESTED_AGENT_VERSIONS.goose;
  let facts = await gatherFacts({ ...RT }, Layout.dev("/repo"), base({ commandExists: only("claude", "goose"), agentVersion: probe(` ${max}`) }));
  assert.deepEqual(asked, ["claude", "goose"]);
  assert.ok(renderDoctor(facts).includes(`✓ Goose ${max}: a tested version (tested: ${min} to ${max}); a preview: tested less than Claude Code and Codex`));
  facts = await gatherFacts({ ...RT }, Layout.dev("/repo"), base({ commandExists: only("claude", "goose"), agentVersion: probe(" 1.55.0") }));
  assert.match(renderDoctor(facts), /✗ Goose 1\.55\.0: newer than tested/);
  facts = await gatherFacts({ ...RT }, Layout.dev("/repo"), base({ commandExists: only("claude"), agentVersion: probe("x") }));
  assert.equal(facts.versions?.goose, null);
  assert.doesNotMatch(renderDoctor(facts), /Goose/);
});
