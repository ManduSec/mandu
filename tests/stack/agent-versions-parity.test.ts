/**
 * agent-versions-parity — ONE tested-version table (release checklist e4;
 * docs/design/agents/supported-agents.md). The launcher (launch warning, doctor row)
 * and the dashboard (health chip, product notice) ship standalone, so the
 * table is mirrored; this test keeps the mirrors equal, the two checks
 * answering alike, and the published README table (ranges and support
 * status: supported / preview), the design doc's status table and the user
 * guide's preview paragraph in step with both.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import * as launcher from "../../launcher/src/agent-versions.js";
import * as dash from "../../dashboard/src/agent-versions.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("the tested-version table is the same in the launcher and the dashboard, generations included", () => {
  assert.deepEqual(dash.TESTED_AGENT_VERSIONS, launcher.TESTED_AGENT_VERSIONS);
  assert.deepEqual(dash.TESTED_AGENT_GENERATIONS, launcher.TESTED_AGENT_GENERATIONS);
});

test("both checks give the same verdict for the same version string", () => {
  const samples = [
    null, "", "garbage", "2.1.272", "2.1.273", "2.1.281 (Claude Code)", "2.1.282", "2.1.285 (Claude Code)", "2.1.286", "2.1.287 (Claude Code)", "2.1.288", "2.1.292 (Claude Code)", "2.1.293", "2.1.294 (Claude Code)", "2.1.295 (Claude Code)", "2.1.296", "2.1.285-beta.1", "9.0.0",
    "codex-cli 0.135.9", "codex-cli 0.154.0", "0.155.0", "codex-cli 0.159.1", "0.159.2", "codex-cli 0.160.0", "0.160.1", "codex-cli 0.162.0", "0.162.1", "OpenClaw 2026.7.1-2 (abc)", "2026.8.0", "OpenClaw 2026.9.6", "2026.9.9", "OpenClaw 2026.9.10", "1.18.13", "v1.18.14", "1.18.35", "1.18.36",
    // OpenCode 2's own range (a generation): below, at and above it, as it prints itself, and its prerelease spelling.
    "2.0.22", "2.0.23", "2.0.24", "2.0.26", "2.0.27", "opencode v2.0.23", "0.0.0-beta-1",
    // Goose prints its version with a leading space.
    " 1.52.9", " 1.53.0", "1.53.1", " 1.54.0", "1.54.1",
  ];
  for (const agent of Object.keys(launcher.TESTED_AGENT_VERSIONS) as launcher.VersionedAgent[]) {
    for (const s of samples) {
      assert.deepEqual(dash.checkAgentVersion(agent, s), launcher.checkAgentVersion(agent, s), `${agent} ${String(s)}`);
    }
  }
});

test("both sides give the same support status for the same version string, the same line labels and the same report address", () => {
  const samples = [null, "", "garbage", "2.1.295 (Claude Code)", "codex-cli 0.162.0", "OpenClaw 2026.9.9", "2026.9.10", "1.18.35", "opencode v2.0.26", "2.0.99", "3.0.0", " 1.54.0", "1.55.0"];
  for (const agent of Object.keys(launcher.TESTED_AGENT_VERSIONS) as launcher.VersionedAgent[]) {
    for (const s of samples) assert.equal(dash.supportStatusOf(agent, s), launcher.supportStatusOf(agent, s), `${agent} ${String(s)}`);
  }
  for (const r of [...Object.values(launcher.TESTED_AGENT_VERSIONS), ...Object.values(launcher.TESTED_AGENT_GENERATIONS).flatMap((g) => g ?? [])]) {
    assert.equal(dash.rangeLabel(r), launcher.rangeLabel(r));
  }
  assert.equal(dash.ISSUES_URL, launcher.ISSUES_URL, "the dashboard's tag links where the launch notice sends problem reports");
  // The dashboard names a preview line exactly as the launch notice does.
  assert.equal(launcher.previewNotice(dash.previewLineOf("goose", " 1.53.0")!), launcher.launchPreviewNotice("goose", ["goose"], null, {}));
  assert.equal(launcher.previewNotice(dash.previewLineOf("opencode", "2.0.23")!), launcher.launchPreviewNotice("opencode", ["opencode2"], 2, {}));
  assert.equal(launcher.previewNotice(dash.previewLineOf("opencode", "1.18.13")!), launcher.launchPreviewNotice("opencode", ["opencode"], 1, {}));
});

/** Every tested line: each agent's first, then each generation. */
const LINES = [
  ...Object.values(launcher.TESTED_AGENT_VERSIONS),
  ...Object.values(launcher.TESTED_AGENT_GENERATIONS).flatMap((g) => g ?? []),
];

test("the README's Supported agents table states the same ranges and support status", () => {
  const readme = readFileSync(join(REPO, "README.md"), "utf8");
  // A generation has its own row, `<name> <major>` ("OpenCode 2").
  for (const r of LINES) {
    const label = launcher.rangeLabel(r);
    const row = readme.split("\n").find((l) => l.startsWith(`| ${label} |`));
    assert.ok(row, `README lists ${label}`);
    assert.equal(row, `| ${label} | ${launcher.rangeWords(r)} | ${r.status} |`, `README row for ${label}`);
  }
});

test("supported-agents.md's status table and the user docs name the same preview agents as the code", () => {
  const previews = LINES.filter((r) => r.status === "preview").map((r) => launcher.rangeLabel(r));
  assert.ok(previews.length > 0);
  const design = readFileSync(join(REPO, "docs/design/agents/supported-agents.md"), "utf8");
  for (const r of LINES) {
    const label = launcher.rangeLabel(r);
    const row = design.split("\n").find((l) => l.startsWith(`| ${label} | `) && /\| (supported|preview) \|$/.test(l));
    assert.ok(row, `supported-agents.md §2.0 lists ${label} with its status`);
    assert.ok(row!.endsWith(`| ${r.status} |`), `supported-agents.md says ${label} is ${r.status}: ${row}`);
  }
  // The user guide names every preview agent where it says what a preview is.
  const usage = readFileSync(join(REPO, "docs/usage.md"), "utf8");
  const at = usage.indexOf("MANDU_PREVIEW_NOTICE=0");
  assert.ok(at > 0, "usage.md explains the preview notice");
  const para = usage.slice(usage.lastIndexOf("\n**", at), at);
  for (const label of previews) assert.ok(para!.includes(label), `usage.md's preview paragraph names ${label}`);
});

test("the OpenCode 2 samples land in 2.x's range on both sides, not 1.x's", () => {
  for (const check of [launcher.checkAgentVersion, dash.checkAgentVersion]) {
    assert.deepEqual(
      ["2.0.22", "2.0.23", "2.0.26", "2.0.27", "opencode v2.0.23", "0.0.0-beta-1"].map((s) => [check("opencode", s).verdict, check("opencode", s).max]),
      [["older", "2.0.26"], ["tested", "2.0.26"], ["tested", "2.0.26"], ["newer", "2.0.26"], ["tested", "2.0.26"], ["older", "1.18.35"]],
    );
  }
});
