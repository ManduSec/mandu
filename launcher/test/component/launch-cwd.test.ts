/**
 * launch-cwd.test — E2E: the real launcher (`node src/run.ts`, its own
 * process) launches for its REAL working directory, not for a `$PWD` that
 * names another folder (src/launch-cwd.ts; packaging.md §1, "The launch
 * directory").
 *
 * The parent here is what a script that `chdir`s without exporting PWD is
 * (Python's `subprocess.run(cwd=…)`, a non-shell parent): the child's cwd is
 * the project, its PWD another folder. Before the fix the launcher took the
 * PWD, so the agent ran in the other folder and the confinement, the twins
 * and the secret scan were for the wrong directory. A fake agent records the
 * kernel's cwd and the PWD it was handed.
 *
 * Asserted: the agent runs in the real cwd and its PWD agrees with it; a PWD
 * that is a symlinked spelling of the same folder is kept as the spelling.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer, type Server } from "node:net";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { once } from "node:events";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";
import { axesEnv, stateAxes } from "../axes.js";

// This suite STATES its axes (protection-modes.md §4): `off`. The subject is
// which folder the launch is for, not what a mode does there.
stateAxes("off");

const LAUNCHER_ROOT = resolve(fileURLToPath(import.meta.url), "..", "..", "..");
const TSX_LOADER = pathToFileURL(join(LAUNCHER_ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;

interface Seen { code: number | null; cwd: string; pwd: string; stderr: string }

/** Launch the real CLI with the child's cwd `cwd` and its env PWD `pwd`. */
async function launch(dir: string, sock: string, cwd: string, pwd: string): Promise<Seen> {
  const record = join(dir, `record-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  const fake = join(dir, "fake-agent.sh");
  writeFileSync(fake, [
    "#!/bin/bash",
    // The kernel's cwd (physical) and the PWD the agent was handed, before
    // bash could re-derive it (bash keeps an inherited PWD naming its cwd).
    `printf '%s\\n' "$(/bin/pwd -P)" > ${record}`,
    `printf '%s\\n' "$PWD" >> ${record}`,
    "exit 0",
    "",
  ].join("\n"));
  chmodSync(fake, 0o755);
  const child = spawn(process.execPath, [
    "--import", TSX_LOADER, join(LAUNCHER_ROOT, "src", "run.ts"),
    "--target", "claude", "--no-net-proxy", "--no-scope", "--no-reply-filter", "--no-mcp", "--", "bash", fake,
  ], {
    cwd,
    stdio: ["ignore", "ignore", "pipe"],
    env: {
      HOME: process.env["HOME"], PATH: process.env["PATH"], PWD: pwd, XDG_RUNTIME_DIR: dir,
      MANDU_ARBITER_SOCK: sock, MANDU_NO_ARBITER_AUTOSTART: "1", MANDU_PROXY_PORT: "0",
      MANDU_HOME: join(dir, "mandu-home"), ...axesEnv("off"),
    },
  });
  let stderr = "";
  child.stderr!.on("data", (d) => { stderr += String(d); });
  const [code] = await once(child, "exit") as [number | null];
  let lines: string[] = [];
  try { lines = readFileSync(record, "utf8").split("\n"); } catch { /* the agent never ran */ }
  return { code, cwd: lines[0] ?? "", pwd: lines[1] ?? "", stderr };
}

async function withMockArbiter(fn: (dir: string, sock: string) => Promise<void>): Promise<void> {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mandu-launch-cwd-")));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  try {
    await fn(dir, sock);
  } finally {
    srv.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test("a PWD naming ANOTHER folder: the launch is for the real cwd, and the agent's PWD agrees with it", { timeout: 120_000 }, async () => {
  await withMockArbiter(async (dir, sock) => {
    const proj = join(dir, "proj");
    const elsewhere = join(dir, "elsewhere");
    mkdirSync(proj);
    mkdirSync(elsewhere);
    const r = await launch(dir, sock, proj, elsewhere);
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.cwd, proj, `the agent runs in the real cwd, not the stale PWD's folder\n${r.stderr}`);
    assert.equal(r.pwd, proj, "the agent's PWD names the folder it runs in");
  });
});

test("a PWD that is a symlinked spelling of the real cwd: kept as the human's spelling", { timeout: 120_000 }, async () => {
  await withMockArbiter(async (dir, sock) => {
    const proj = join(dir, "proj");
    mkdirSync(proj);
    const link = join(dir, "link");
    symlinkSync(proj, link);
    const r = await launch(dir, sock, proj, link);
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.cwd, proj, "physically the same folder");
    assert.equal(r.pwd, link, "the logical spelling the user typed is kept");
  });
});

test("a relative PWD is ignored: the real cwd", { timeout: 120_000 }, async () => {
  await withMockArbiter(async (dir, sock) => {
    const proj = join(dir, "proj");
    mkdirSync(proj);
    mkdirSync(join(dir, "proj", "sub"));
    const r = await launch(dir, sock, proj, "sub");
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.cwd, proj);
    assert.equal(r.pwd, proj);
  });
});
