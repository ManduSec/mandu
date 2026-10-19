/** Real local HTTPS observer -> real CLI -> real launcher/arbiter/inspection.
 * No provider calls. Default suite covers preparation and the paid-call gate;
 * MANDU_PAIRED_E2E=1 runs the six-rollout scripted component check explicitly.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { runPaired } from "./paired-runner.js";
import { PAID_MODEL } from "./paired-budget.js";
import { approvedBody } from "./paired-provider.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const config = { repoRoot, agentBinary: "claude", model: PAID_MODEL, inspectionModel: PAID_MODEL, timeoutMs: 90000 };

test("preparation writes all six planned legs and manual checks without launching an agent", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "paired-prepare-"));
  try {
    const report = await runPaired({ ...config, agentBinary: "/definitely/missing-agent" }, "prepare", join(tmp, "run"));
    assert.equal(report.results.length, 6);
    assert.ok(report.results.every((r) => r.status === "not-run" && r.costUsd === null));
    assert.ok(report.results.every((r) => !existsSync(join(r.artifactDir, "process.json"))));
    const analysis = JSON.parse(readFileSync(join(tmp, "run", "analysis.json"), "utf8"));
    assert.equal(analysis.queue.length, 6);
    assert.ok(analysis.queue.every((e: any) => e.kind === "not-run"));
    assert.match(readFileSync(join(tmp, "run", "REVIEW.md"), "utf8"), /Approve or amend the task\/check digest/);
    await assert.rejects(runPaired(config, "prepare", join(tmp, "run")), /EEXIST/);
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});

test("the CLI writes to a new run dir under <MANDU_HOME>/runs/eval without --out, prints it first, and --out still wins", { timeout: 120000 }, () => {
  const tmp = mkdtempSync(join(tmpdir(), "paired-cli-out-"));
  try {
    const manduHome = join(tmp, "mandu");
    const cli = (extra: string[]) => spawnSync(join(repoRoot, "eval/node_modules/.bin/tsx"),
      [join(repoRoot, "eval/run-paired.ts"), "--model", PAID_MODEL, "--inspection-model", PAID_MODEL, "--agent", "/definitely/missing-agent", ...extra],
      { cwd: tmp, env: { PATH: process.env.PATH, HOME: join(tmp, "home"), MANDU_HOME: manduHome }, encoding: "utf8", timeout: 110000 });

    const def = cli([]);
    assert.equal(def.status, 0, def.stderr);
    const first = def.stdout.split("\n")[0];
    const m = /^Output: (\S+) \(default; pass --out <dir> to choose\)$/.exec(first);
    assert.ok(m, `first line names the output dir: ${first}`);
    const runDir = m![1];
    assert.equal(dirname(runDir), join(manduHome, "runs", "eval"));
    assert.match(basename(runDir), /^\d{8}T\d{6}Z-paired-[0-9a-f]{6}$/);
    for (const d of [manduHome, join(manduHome, "runs"), join(manduHome, "runs", "eval"), runDir]) assert.equal(statSync(d).mode & 0o777, 0o700, d);
    assert.ok(existsSync(join(runDir, "report.md")));
    assert.match(def.stdout, new RegExp(`Report: ${runDir}/report.md`));
    assert.equal(existsSync(join(tmp, "home", ".mandu")), false, "MANDU_HOME, not HOME, places it");

    const mine = join(tmp, "mine");
    const explicit = cli(["--out", mine]);
    assert.equal(explicit.status, 0, explicit.stderr);
    assert.equal(explicit.stdout.split("\n")[0], `Output: ${mine}`);
    assert.ok(existsSync(join(mine, "report.md")));
    assert.equal(readdirSync(join(manduHome, "runs", "eval")).length, 1, "--out adds no default run dir");
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});

test("real-model execution refuses before creating artifacts or spawning processes", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "paired-budget-"));
  try {
    await assert.rejects(runPaired(config, "real", join(tmp, "run")), /separate budget/);
    assert.equal(existsSync(join(tmp, "run")), false);
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});

test("scripted paired tasks exercise real product components with no raw marker at the model boundary", { skip: process.env.MANDU_PAIRED_E2E !== "1" ? "set MANDU_PAIRED_E2E=1 for real-CLI offline checks" : false, timeout: 600000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "paired-components-"));
  let passed = false;
  try {
    const report = await runPaired(config, "scripted", join(tmp, "run"));
    assert.equal(report.results.length, 6);
    assert.deepEqual(report.results.map((r) => [r.taskId, r.side, r.status, r.reason]), report.results.map((r) => [r.taskId, r.side, "pass", null]));
    assert.ok(report.results.every((r) => r.evidence.status === "pass"));
    const analysis = JSON.parse(readFileSync(join(tmp, "run", "analysis.json"), "utf8"));
    assert.equal(analysis.queue.length, 2);
    assert.equal(analysis.latencyPairs.length, 3);
    for (const row of report.results) {
      const requests = JSON.parse(readFileSync(join(row.artifactDir, "requests.json"), "utf8"));
      for (const r of requests) assert.doesNotThrow(() => approvedBody(r.body, 4096, r.path.includes("count_tokens")));
      if (row.taskId === "BP-02" && row.side === "wrapped-default") {
        const messages = requests.filter((r: any) => r.channel === "model").flatMap((r: any) => r.body.messages ?? []);
        const calls = messages.flatMap((m: any) => Array.isArray(m.content) ? m.content : []);
        assert.ok(calls.some((b: any) => b.name === "mcp__mandu-inspect__inspect_symbol" && b.input?.symbols?.length === 2), "real CLI must accept the multi-input MCP tool and pass both handles");
      }
      const trajectory = JSON.parse(readFileSync(join(row.artifactDir, "trajectory.json"), "utf8"));
      assert.equal(trajectory.filter((t: any) => t.status === "error").length, row.taskId === "BP-03" ? 1 : 0);
      assert.ok(trajectory.every((t: any) => ["success", "error"].includes(t.status)));
      for (const t of trajectory) {
        const block = t.callPointer.split("/").slice(1).reduce((v: any, key: string) => v[key], requests);
        assert.equal(block.id, t.id);
      }
    }
    passed = true;
  } finally {
    if (passed) rmSync(tmp, { recursive: true, force: true });
    else console.error(`Paired component artifacts retained: ${tmp}`);
  }
});
