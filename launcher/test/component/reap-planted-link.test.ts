/**
 * reap-planted-link e2e — `mandu reap` through the real CLI entry (run.ts →
 * runSubcommand → runReap with realReapDeps) on a runtime base where links
 * and a forged entry were planted (runtime-instances.md §2 "planted paths",
 * §10): every planted link leads to a CANARY folder holding what reap would
 * take for garbage, and the canaries must survive whole.
 *
 *   - `instances/` → a project folder with old subdirectories (each read as
 *     a manifest-less, abandoned instance through the link);
 *   - `dashboards/` → a folder with a `package.json` (an "unreadable entry");
 *   - `vm-guests/` (real) holding a forged entry whose dead owner and guest
 *     name a scratch dir that is a link to a canary, one reached through a
 *     linked folder, and one outside every scratch root (`~/Documents`);
 *   - a real dead instance and a real stale scope dir beside them are still
 *     collected (the control), and `--dry-run` / the run name what was
 *     refused.
 *
 * Before the fix reap walked all three registries through their links and
 * removed what they named.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runCli } from "../lib/run-cli.js";
import { scratchRoots } from "../../src/reap.js";

const PKG = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("mandu reap walks and deletes nothing through a planted link, and refuses a forged guest's ~/Documents", async () => {
  const root = mkdtempSync(join(tmpdir(), "mdu-reap-planted-"));
  // A folder outside every scratch root (/tmp, the caches): the package dir.
  const outside = mkdtempSync(join(PKG, ".reap-e2e-"));
  try {
    const base = join(root, "mandu");
    const home = join(outside, "home");
    mkdirSync(join(home, "Documents"), { recursive: true });
    writeFileSync(join(home, "Documents", "thesis.tex"), "mine\n");
    mkdirSync(base);
    const old = new Date(Date.now() - 3_600_000);

    // instances/ → a project with old subdirectories.
    const project = join(root, "project");
    for (const d of ["src", "docs"]) {
      mkdirSync(join(project, d), { recursive: true });
      writeFileSync(join(project, d, "x"), "work\n");
      utimesSync(join(project, d), old, old);
    }
    symlinkSync(project, join(base, "instances"));

    // dashboards/ → a folder with a package.json.
    const app = join(root, "app");
    mkdirSync(app);
    writeFileSync(join(app, "package.json"), `{"name":"app"}`);
    symlinkSync(app, join(base, "dashboards"));

    // vm-guests/ (real) with forged entries; the pids are far past pid_max.
    mkdirSync(join(base, "vm-guests"));
    const canary = join(root, "canary");
    mkdirSync(canary);
    writeFileSync(join(canary, "keep"), "mine\n");
    const scratch = join(root, "scratch");
    mkdirSync(scratch);
    symlinkSync(canary, join(scratch, "work-link"));
    symlinkSync(root, join(scratch, "via"));
    const guest = (id: string, workDir: string): void =>
      writeFileSync(join(base, "vm-guests", `${id}.json`), JSON.stringify({ pid: 2147480100, pidStart: 1, ownerPid: 2147480101, ownerStart: 1, workDir }));
    guest("g-link", join(scratch, "work-link"));
    guest("g-via", join(scratch, "via", "canary"));
    guest("g-docs", join(home, "Documents"));

    // The control: a real stale scope dir (dead launcher pid) is still collected.
    const scope = join(base, "1700000000-2147480102");
    mkdirSync(join(scope, "exec-shims"), { recursive: true });

    const env = { HOME: home, MANDU_RUNTIME_DIR: base, MANDU_CONFIG: "/dev/null" };
    const dry = await runCli(["reap", "--dry-run"], env);
    assert.equal(dry.code, 0, dry.stderr);
    assert.match(dry.stdout, /refused: instances\/ not walked: .*symbolic link/);
    assert.match(dry.stdout, /refused: dashboards\/ not walked: .*symbolic link/);
    // The package dir is outside every scratch root in a normal checkout; a
    // checkout under /tmp (a scratch worktree) makes ~/Documents one, so the
    // leg is judged only where it means something.
    const docsOutside = !scratchRoots({ HOME: home }, home).some((r) => home.startsWith(`${r}/`));
    if (docsOutside) assert.match(dry.stdout, /refuse to remove .*Documents \(not a scratch path\)/);
    assert.doesNotMatch(dry.stdout, /rm-dead-instance|rm-dead-dashboard-entry/, "nothing behind a linked registry is planned");

    const run = await runCli(["reap"], env);
    assert.deepEqual(readdirSync(project).sort(), ["docs", "src"], `the linked-to project is untouched:\n${run.stdout}`);
    assert.ok(existsSync(join(app, "package.json")), "the linked-to app keeps its package.json");
    assert.ok(existsSync(join(canary, "keep")), "a scratch dir that is a link, or under one, is never deleted through it");
    if (docsOutside) assert.ok(existsSync(join(home, "Documents", "thesis.tex")), "a forged entry's ~/Documents survives");
    assert.ok(!existsSync(scope), "the real stale scope dir is collected (the control)");
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});
