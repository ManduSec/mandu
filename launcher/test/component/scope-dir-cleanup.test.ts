/**
 * scope-dir-cleanup.test — E2E: the real launcher (`node --import tsx
 * src/run.ts`, its own process, so the minted scope id carries its own pid)
 * removes its scope run dir when the launch ends cleanly, and keeps it
 * otherwise (src/scope-dir-cleanup.ts; runtime-instances.md §10.1;
 * os-test-matrix.md §10.16.2).
 *
 * Each launch runs a fake agent that records its scope id and a listing of
 * `<runtime base>/<scope id>` WHILE it runs, so "gone afterwards" is never
 * vacuous: the dir provably existed, with the launch's files in it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer, type Server } from "node:net";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { once } from "node:events";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";

const LAUNCHER_ROOT = resolve(fileURLToPath(import.meta.url), "..", "..", "..");
// The launch runs in its folder (cwd = PWD = dir), as a shell starts it: the
// launcher launches for its real cwd (launch-cwd.ts), so tsx is imported by path.
const TSX_LOADER = pathToFileURL(join(LAUNCHER_ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;

interface Launch { code: number | null; scopeId: string; during: string[]; stderr: string }

/** Launch the real CLI over a fake agent that exits `agentCode`. */
async function launch(dir: string, sock: string, agentCode: number, extraArgs: string[] = [], extraEnv: Record<string, string> = {}): Promise<Launch> {
  const base = join(dir, "mandu");
  const record = join(dir, `record-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  const fake = join(dir, "fake-agent.sh");
  writeFileSync(fake, [
    "#!/usr/bin/env bash",
    `printf '%s\\n' "\${MANDU_SCOPE_ID:-}" > ${record}`,
    `ls -A "${base}/\${MANDU_SCOPE_ID:-none}" >> ${record} 2>&1`,
    `exit ${agentCode}`,
    "",
  ].join("\n"));
  chmodSync(fake, 0o755);
  const child = spawn(process.execPath, [
    "--import", TSX_LOADER, join(LAUNCHER_ROOT, "src", "run.ts"),
    "--target", "claude", "--no-net-proxy", "--no-scope", "--no-reply-filter", ...extraArgs, "--", "bash", fake,
  ], {
    cwd: dir,
    stdio: ["ignore", "ignore", "pipe"],
    env: {
      HOME: process.env["HOME"], PATH: process.env["PATH"], PWD: dir, XDG_RUNTIME_DIR: dir,
      MANDU_ARBITER_SOCK: sock, MANDU_PROXY_PORT: "0",
      MANDU_HOME: join(dir, "mandu-home"), MANDU_MODE: "off",
      ...extraEnv,
    },
  });
  let stderr = "";
  child.stderr!.on("data", (d) => { stderr += String(d); });
  const [code] = await once(child, "exit") as [number | null];
  let lines: string[] = [];
  try { lines = readFileSync(record, "utf8").split("\n").filter(Boolean); } catch { /* the agent never ran */ }
  return { code, scopeId: lines[0] ?? "", during: lines.slice(1), stderr };
}

async function withMockArbiter(fn: (dir: string, sock: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-scope-dir-"));
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

test("a clean exit (the agent's 0) removes the launch's own scope dir, and only it", { timeout: 120_000 }, async () => {
  await withMockArbiter(async (dir, sock) => {
    const base = join(dir, "mandu");
    // Neighbours in the runtime base: another launch's scope dir, a file.
    mkdirSync(join(base, "1700000000-1", "events"), { recursive: true });
    writeFileSync(join(base, "neighbour.txt"), "x");
    const r = await launch(dir, sock, 0, [], { MANDU_NO_ARBITER_AUTOSTART: "1" });
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.scopeId, /^\d+-\d+$/, "a minted scope id");
    assert.ok(r.during.includes("launch.log"), `the scope dir existed with the launch's files while the agent ran: ${r.during.join(",")}`);
    assert.equal(existsSync(join(base, r.scopeId)), false, "removed at the clean exit");
    assert.ok(existsSync(join(base, "1700000000-1", "events")), "another launch's scope dir is untouched");
    assert.ok(existsSync(join(base, "neighbour.txt")), "the runtime base's other files are untouched");
  });
});

test("kept: a failed session (the agent's 3), a named scope (--id), MANDU_KEEP_SCOPE_DIR=1", { timeout: 180_000 }, async () => {
  await withMockArbiter(async (dir, sock) => {
    const base = join(dir, "mandu");
    const noAuto = { MANDU_NO_ARBITER_AUTOSTART: "1" };
    const failed = await launch(dir, sock, 3, [], noAuto);
    assert.equal(failed.code, 3, failed.stderr);
    assert.ok(existsSync(join(base, failed.scopeId, "launch.log")), "a failed session keeps its scope dir for diagnosis");

    const named = await launch(dir, sock, 0, ["--id", "named-scope"], noAuto);
    assert.equal(named.code, 0, named.stderr);
    assert.equal(named.scopeId, "named-scope");
    assert.ok(existsSync(join(base, "named-scope", "launch.log")), "a named scope dir is the caller's");

    const kept = await launch(dir, sock, 0, [], { ...noAuto, MANDU_KEEP_SCOPE_DIR: "1" });
    assert.equal(kept.code, 0, kept.stderr);
    assert.match(kept.scopeId, /^\d+-\d+$/);
    assert.ok(existsSync(join(base, kept.scopeId, "launch.log")), "MANDU_KEEP_SCOPE_DIR keeps it");
  });
});

test("kept: the scope dir a pinned arbiter this launch started writes into (it outlives the launch)", { timeout: 180_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-scope-dir-"));
  const base = join(dir, "mandu");
  let arbiterPid: number | undefined;
  try {
    // A pinned socket with nothing on it: the launch starts the arbiter AT it,
    // with --event-dir <scope dir>/events (run.ts, on-disk-layout.md §5).
    const sock = join(dir, "pinned", "arbiter.sock");
    const r = await launch(dir, sock, 0);
    for (const id of existsSync(join(base, "instances")) ? readdirSync(join(base, "instances")) : []) {
      try { arbiterPid = (JSON.parse(readFileSync(join(base, "instances", id, "manifest.json"), "utf8")) as { pid?: number }).pid; } catch { /* no manifest */ }
    }
    assert.equal(r.code, 0, r.stderr);
    assert.ok(existsSync(sock), "the launch started the pinned arbiter");
    assert.ok(existsSync(join(base, r.scopeId, "events")), "its event dir, inside the scope dir, is kept");
  } finally {
    if (arbiterPid) { try { process.kill(arbiterPid, "SIGTERM"); } catch { /* gone */ } }
    await new Promise((res) => setTimeout(res, 500));
    rmSync(dir, { recursive: true, force: true });
  }
});
