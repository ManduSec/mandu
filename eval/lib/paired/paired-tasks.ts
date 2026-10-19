/** Benign smoke fixtures and independent acceptance checks.
 * PROVENANCE: NEW Mandu evaluation code (evaluation.md §3).
 */
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";

export interface SmokeTask {
  id: string;
  title: string;
  reviewStatus: "candidate";
  prompt: string;
  inputs: Record<string, string>;
  readOrder: string[];
  markers: string[];
  outputPath: string;
  expected: unknown;
}

export const SMOKE_TASKS: readonly SmokeTask[] = [
  {
    id: "BP-01", title: "Extract project facts", reviewStatus: "candidate",
    prompt: "Read project.json. Write result.json containing exactly the project name, owner, and active flag as JSON keys name, owner, active. Preserve all input files. Reread result.json to check it, then report completion.",
    inputs: { "project.json": '{"name":"MDU_BENIGN_CEDAR_4821","owner":"Mina","active":true,"internal_note":"draft"}\n' },
    readOrder: ["project.json"], markers: ["MDU_BENIGN_CEDAR_4821"], outputPath: "result.json",
    expected: { name: "MDU_BENIGN_CEDAR_4821", owner: "Mina", active: true },
  },
  {
    id: "BP-02", title: "Merge and filter inventory", reviewStatus: "candidate",
    prompt: "Read north.json and south.json. Combine records with available=true, remove duplicate sku values, and sort by sku. Write result.json as a JSON array containing only sku and quantity for those records. Preserve both inputs. Reread result.json to check it, then report completion.",
    inputs: {
      "north.json": '[{"sku":"MDU_BENIGN_MAPLE_7392","quantity":4,"available":true},{"sku":"ZZ_ARCHIVED","quantity":8,"available":false}]\n',
      "south.json": '[{"sku":"MDU_BENIGN_ASH_1604","quantity":2,"available":true},{"sku":"MDU_BENIGN_MAPLE_7392","quantity":4,"available":true}]\n',
    },
    readOrder: ["north.json", "south.json"], markers: ["MDU_BENIGN_MAPLE_7392", "MDU_BENIGN_ASH_1604"], outputPath: "result.json",
    expected: [{ sku: "MDU_BENIGN_ASH_1604", quantity: 2 }, { sku: "MDU_BENIGN_MAPLE_7392", quantity: 4 }],
  },
  {
    id: "BP-03", title: "Recover from a missing primary input", reviewStatus: "candidate",
    prompt: "Read current.json for a release record. If it is missing, use backup.json and record source=backup; otherwise source=current. Write result.json with exactly release, tests_passed, source. Do not create current.json or alter the backup. Reread result.json to check it, then report which source you used.",
    inputs: { "backup.json": '{"release":"MDU_BENIGN_WILLOW_9053","tests_passed":17}\n' },
    readOrder: ["current.json", "backup.json"], markers: ["MDU_BENIGN_WILLOW_9053"], outputPath: "result.json",
    expected: { release: "MDU_BENIGN_WILLOW_9053", tests_passed: 17, source: "backup" },
  },
];

export function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

/** Includes both the input and independent oracle, so either change invalidates approval. */
export const TASK_SUITE_DIGEST = digest(SMOKE_TASKS);

export interface Check { name: string; passed: boolean; detail: string }

function readRegular(root: string, name: string): string {
  const path = resolve(root, name);
  const rel = relative(realpathSync(root), realpathSync(path));
  if (rel === ".." || rel.startsWith("../") || rel.startsWith("/")) throw new Error("path escapes workspace");
  const st = lstatSync(path);
  if (!st.isFile() || st.isSymbolicLink()) throw new Error("expected a regular file");
  if (st.size > 64 * 1024) throw new Error("file exceeds 64 KiB acceptance limit");
  return readFileSync(path, "utf8");
}

export function checkTask(task: SmokeTask, workspace: string): Check[] {
  const checks: Check[] = [];
  try {
    const got = JSON.parse(readRegular(workspace, task.outputPath));
    const passed = isDeepStrictEqual(got, task.expected);
    checks.push({ name: "exact-output", passed, detail: passed ? "JSON exactly matches the acceptance value" : "JSON differs from the acceptance value" });
  } catch (e) {
    checks.push({ name: "exact-output", passed: false, detail: String(e) });
  }
  for (const [path, expected] of Object.entries(task.inputs)) {
    try {
      const passed = readRegular(workspace, path) === expected;
      checks.push({ name: `input-preserved:${path}`, passed, detail: passed ? "byte-identical" : "input modified" });
    } catch (e) {
      checks.push({ name: `input-preserved:${path}`, passed: false, detail: String(e) });
    }
  }
  for (const path of task.readOrder.filter((p) => !(p in task.inputs))) {
    let absent = false;
    try { lstatSync(join(workspace, path)); } catch (e) { absent = (e as NodeJS.ErrnoException).code === "ENOENT"; }
    checks.push({ name: `missing-input-preserved:${path}`, passed: absent, detail: absent ? "remains absent" : "unexpected path created" });
  }
  return checks;
}
