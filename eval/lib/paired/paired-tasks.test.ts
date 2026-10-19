import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SMOKE_TASKS, checkTask, digest, TASK_SUITE_DIGEST } from "./paired-tasks.js";
import { launchSpec, pairOrder } from "./paired-config.js";

test("each independent oracle rejects initial state and accepts its reference output", () => {
  for (const task of SMOKE_TASKS) {
    const dir = mkdtempSync(join(tmpdir(), "paired-task-"));
    try {
      for (const [p, body] of Object.entries(task.inputs)) writeFileSync(join(dir, p), body);
      assert.equal(checkTask(task, dir).every((c) => c.passed), false);
      writeFileSync(join(dir, task.outputPath), JSON.stringify(task.expected));
      assert.equal(checkTask(task, dir).every((c) => c.passed), true);
      writeFileSync(join(dir, task.outputPath), JSON.stringify({ ...task.expected as object, extra: "unexpected" }));
      assert.equal(checkTask(task, dir)[0].passed, false, "extra fields must fail");
      writeFileSync(join(dir, task.outputPath), JSON.stringify(task.expected));
      writeFileSync(join(dir, Object.keys(task.inputs)[0]), "changed");
      assert.equal(checkTask(task, dir).every((c) => c.passed), false, "input modification must fail");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
});

test("checker rejects symlinks, oversized and malformed output, and invented fallback inputs", () => {
  const task = SMOKE_TASKS[2];
  const dir = mkdtempSync(join(tmpdir(), "paired-invalid-"));
  try {
    writeFileSync(join(dir, "backup.json"), task.inputs["backup.json"]);
    writeFileSync(join(dir, "reference.json"), JSON.stringify(task.expected));
    symlinkSync("reference.json", join(dir, task.outputPath));
    assert.equal(checkTask(task, dir)[0].passed, false);
    rmSync(join(dir, task.outputPath));
    for (const bad of ["{", " ".repeat(65 * 1024)]) {
      writeFileSync(join(dir, task.outputPath), bad);
      assert.equal(checkTask(task, dir)[0].passed, false);
    }
    writeFileSync(join(dir, task.outputPath), JSON.stringify(task.expected));
    writeFileSync(join(dir, "current.json"), "{}");
    assert.equal(checkTask(task, dir).at(-1)?.passed, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("acceptance approval digest changes when the task or oracle changes", () => {
  assert.equal(TASK_SUITE_DIGEST, digest(SMOKE_TASKS));
  assert.notEqual(TASK_SUITE_DIGEST, digest(SMOKE_TASKS.map((t) => ({ ...t, expected: null }))));
  assert.notEqual(TASK_SUITE_DIGEST, digest(SMOKE_TASKS.map((t) => ({ ...t, prompt: "new task" }))));
});

test("true baseline bypasses launcher; wrapped keeps all defaults and inspection; no ambient leakage", () => {
  const config = { model: "fixed-main", inspectionModel: "fixed-inspect", agentBinary: "/bin/claude", repoRoot: "/repo", timeoutMs: 1000 };
  const w = "/tmp/mdu-e-x";
  const paths = { root: "/run", work: w, workspace: `${w}/workspace`, home: `${w}/home`, manduHome: `${w}/mandu-home`, runtime: `${w}/runtime`, tmp: `${w}/tmp`, sock: `${w}/a.sock` };
  const endpoints = { model: "https://127.0.0.1:1001", inspection: "https://127.0.0.1:1002", arbiterSock: paths.sock };
  const ambient = { PATH: "/bin", ANTHROPIC_API_KEY: "PRIVATE", MANDU_NO_KERNEL: "1", MANDU_INTEGRITY: "0", ANTHROPIC_BASE_URL: "https://wrong", HTTP_PROXY: "http://wrong" };
  const base = launchSpec(config, "unwrapped", paths, "task", endpoints, ambient);
  const wrapped = launchSpec(config, "wrapped-default", paths, "task", endpoints, ambient);
  assert.equal(base.command, "/bin/claude");
  assert.equal(base.env.ANTHROPIC_BASE_URL, endpoints.model);
  assert.ok(Object.keys(base.env).every((key) => !key.startsWith("MANDU_")));
  assert.ok(wrapped.command.endsWith("/tsx"));
  assert.deepEqual(wrapped.args.slice(wrapped.args.indexOf("/bin/claude") + 1), base.args);
  assert.equal(wrapped.env.ANTHROPIC_BASE_URL, undefined);
  assert.equal(wrapped.env.MANDU_ULLM_MODEL, "fixed-inspect");
  // A per-run Mandu home isolates config and view state; no retired per-path override.
  assert.equal(wrapped.env.MANDU_HOME, paths.manduHome);
  for (const retired of ["MANDU_CONFIG", "MANDU_VIEW_STATE", "MANDU_SYMBOL_DB", "MANDU_EVENT_DIR"]) {
    assert.equal(wrapped.env[retired], undefined, retired);
  }
  for (const spec of [base, wrapped]) {
    assert.equal(spec.env.HTTP_PROXY, undefined);
    assert.equal(spec.env.MANDU_NO_KERNEL, undefined);
    assert.equal(spec.env.MANDU_INTEGRITY, undefined);
    assert.ok(!JSON.stringify(spec).includes("PRIVATE"));
    assert.ok(!spec.args.includes("--no-mcp"));
    assert.ok(!spec.args.includes("--no-kernel"));
    // Every agent-facing dir is the leg's work dir, never its results dir (leg-work.ts).
    assert.equal(spec.env.TMPDIR, paths.tmp);
    assert.equal(spec.env.XDG_RUNTIME_DIR, paths.runtime);
    assert.equal(spec.env.HOME, paths.home);
    assert.equal(spec.env.PWD, paths.workspace);
    assert.ok(!JSON.stringify(spec.env).includes(paths.root + "/"), "no agent-facing path under the results dir");
  }
  assert.equal(wrapped.env.MANDU_ARBITER_SOCK, paths.sock);
  assert.ok(wrapped.env.MANDU_RUNTIME_DIR.startsWith(paths.runtime + "/"));
  assert.deepEqual(pairOrder(0), ["unwrapped", "wrapped-default"]);
  assert.deepEqual(pairOrder(1), ["wrapped-default", "unwrapped"]);
});
