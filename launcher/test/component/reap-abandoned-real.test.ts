/**
 * reap-abandoned-real e2e — `mandu reap --dry-run` through the real CLI lists
 * a REAL resident daemon of another stack whose code folder was deleted and
 * that nothing owns (abandoned-stacks.ts, runtime-instances.md §10.5): a
 * process titled `mandu-arbiter`, `MANDU_OWNER_PID=none`, its runtime folder
 * another than the one reap walks, started in a folder the test then
 * removes. The same daemon in a folder that still exists is not listed.
 *
 * Only the dry run is driven here: a real `--other-stacks` run would stop
 * every abandoned daemon of this user on the host, not just the stand-in
 * (its stopping is proven over mocks in test/unit/reap-abandoned.test.ts).
 * Linux only (/proc).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCli } from "../lib/run-cli.js";

const LINUX = process.platform === "linux" || "reads /proc";

async function standIn(cwd: string, stack: string): Promise<ChildProcess> {
  const child = spawn(process.execPath, ["-e", `process.title = "mandu-arbiter"; console.log("up"); setInterval(() => {}, 1e9);`], {
    cwd, stdio: ["ignore", "pipe", "ignore"],
    env: { PATH: process.env["PATH"], HOME: process.env["HOME"], MANDU_RUNTIME_DIR: stack, MANDU_OWNER_PID: "none" },
  });
  await new Promise<void>((resolve, reject) => {
    child.stdout!.once("data", () => resolve());
    child.once("exit", () => reject(new Error("stand-in exited early")));
  });
  return child;
}

test("reap --dry-run lists another stack's ownerless daemon whose code folder is gone, and not one whose folder is there", { skip: LINUX === true ? false : LINUX, timeout: 120_000 }, async () => {
  const root = mkdtempSync(join(tmpdir(), "mdu-reap-ab-"));
  const gone = join(root, "removed-install");
  const kept = join(root, "kept-install");
  mkdirSync(gone);
  mkdirSync(kept);
  const a = await standIn(gone, join(root, "other-stack"));
  const b = await standIn(kept, join(root, "other-stack-2"));
  try {
    rmSync(gone, { recursive: true, force: true }); // the install is removed under it
    const env = { ...process.env, MANDU_RUNTIME_DIR: join(root, "walked"), MANDU_HOME: join(root, "home") };
    const dry = await runCli(["reap", "--dry-run"], env);
    assert.equal(dry.code, 0, dry.stdout + dry.stderr);
    assert.match(dry.stdout, new RegExp(`would stop \\(with --other-stacks\\) pid ${a.pid} mandu-arbiter of the stack at ${join(root, "other-stack")}: its code folder ${gone} is gone`), dry.stdout);
    assert.doesNotMatch(dry.stdout, new RegExp(`pid ${b.pid} `), "its install is still there");
    assert.equal(a.exitCode, null, "a dry run stops nothing");
  } finally {
    a.kill("SIGKILL");
    b.kill("SIGKILL");
    rmSync(root, { recursive: true, force: true });
  }
});
