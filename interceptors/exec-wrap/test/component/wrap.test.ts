/**
 * wrap.test — E2E tests for the exec-chokepoint SHIM (src/wrap.ts), spawned as a
 * real process against a real Unix-domain-socket mock arbiter.
 *
 * The unit tests (test/unit/gate.test.ts) drive the pure decision logic with an
 * in-memory arbiter and never spawn anything. These e2e tests close that gap: they
 * launch the ACTUAL shim entrypoint (src/wrap.ts under tsx, the same way
 * `npm run wrap` / the launcher's shim runs it) and assert the FAIL-CLOSED
 * contract on the process boundary — the exit code and whether the real command
 * actually ran — exactly as the system behaves in production.
 *
 * PROJECT INVARIANT (fail-closed): if the arbiter is unreachable, or the decision
 * requires approval, the exec gate MUST BLOCK (exit 77, BLOCK_EXIT_CODE) and MUST
 * NOT run the raw command. The mirror case: a clean ALLOW must actually exec the
 * arbiter-resolved argv.
 *
 * Mirrors the net-proxy e2e idiom (test/component/*.test.ts): a real server over a
 * real socket + assertions on the wire / on observable side effects, not mocks of
 * the transport.
 *
 * Scenarios:
 *   (a) MANDU_ARBITER_SOCK unset            → exit 77, command NOT run.
 *   (b) MANDU_ARBITER_SOCK → dead socket    → exit 77, command NOT run.
 *   (c) mock arbiter returns an approval/block verdict → exit 77, command NOT run.
 *   (d) mock arbiter returns a clean ALLOW    → real command RUNS (sentinel file +
 *                                              stdout marker observed), exit 0.
 *   (e) MANDU_EXECWRAP_PROBE=1 (the launcher's load probe) → prints the ok line,
 *       exit 0, asks the arbiter nothing and runs nothing, even under an ALLOW.
 *
 * "command NOT run" is proven by asserting the ALLOW-only side effect (a sentinel
 * file the resolved argv would write, and a stdout marker) is ABSENT, AND that the
 * exit code is exactly 77 (so a block is distinguished from any other failure).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type Socket } from "node:net";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

/** The fail-closed BLOCK exit code (must match BLOCK_EXIT_CODE in src/wrap.ts). */
const BLOCK_EXIT_CODE = 77;

const HERE = dirname(fileURLToPath(import.meta.url));
/** interceptors/exec-wrap (this package root). */
const PKG_ROOT = join(HERE, "..", "..");
/** The shim entrypoint we spawn. */
const WRAP_TS = join(PKG_ROOT, "src", "wrap.ts");
/**
 * Run the shim via THIS package's local tsx binary directly. We deliberately do
 * NOT use `npx tsx` — npx re-resolves the binary on every spawn and, when the
 * test itself already runs under tsx, the nested `npx tsx` cold-start can stall.
 * The on-disk `.bin/tsx` is the exact interpreter `npm run wrap` uses.
 */
const TSX_BIN = join(PKG_ROOT, "node_modules", ".bin", "tsx");

/**
 * A real Unix-domain-socket NDJSON mock arbiter (mirrors arbiter/ipc wire format:
 * one JSON request per line `{id, op, ...}` → one JSON reply per line
 * `{id, ok, result}`). It answers only the two exec ops the gate uses.
 *
 * mode:
 *   "allow" → resolveExecArgv returns NO approvals + an argv that runs `node -e`
 *             to write a sentinel file and print a stdout marker (the observable
 *             "real command ran" side effect).
 *   "block" → resolveExecArgv returns an approval item (symbol-as-command) → the
 *             gate must BLOCK fail-closed.
 */
function startMockArbiter(
  sockPath: string,
  mode: "allow" | "block",
  sentinel: string,
  marker: string,
): { server: Server; calls: string[] } {
  const calls: string[] = [];
  const server = createServer((c: Socket) => {
    let buf = "";
    c.setEncoding("utf8");
    c.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.trim() === "") continue;
        const req = JSON.parse(line) as { id: number | string; op: string; argv: string[] };
        calls.push(req.op);
        let result: unknown;
        if (req.op === "processLineage") {
          // Best-effort spawn-lineage edge (Plan 4, design §3.2): ack it and move on.
          // wrap.ts emits this off the blocking path; a failure would be swallowed anyway.
          result = { ok: true };
        } else if (req.op === "classifyExec") {
          // curl/wget/nc need the real net → HumanShell (where the argv is
          // subject to desymbolization). The gate hints needsNetwork:true.
          result = { shell: "HumanShell", identifier: req.argv[0] ?? null, reason: "mock e2e" };
        } else if (req.op === "resolveExecArgv") {
          if (mode === "block") {
            // A symbol sitting in a command/arg position the egress gate withheld:
            // exactly the injected-exfil signal → BLOCK.
            result = {
              argv: req.argv,
              approvals: [
                {
                  kind: "symbol_as_command",
                  symbols: ["$MDU:web_fetch[a1b2]"],
                  reason: "untrusted symbol used as command/arg → human approval required",
                },
              ],
              reason: "withheld",
            };
          } else {
            // Clean ALLOW: rewrite the argv to a harmless, observable command.
            const js =
              `require('fs').writeFileSync(${JSON.stringify(sentinel)}, 'RAN');` +
              `process.stdout.write(${JSON.stringify(marker + "\n")});`;
            result = { argv: ["node", "-e", js], approvals: [], reason: "no withheld symbols" };
          }
        } else {
          c.write(JSON.stringify({ id: req.id, ok: false, error: `unexpected op ${req.op}` }) + "\n");
          continue;
        }
        c.write(JSON.stringify({ id: req.id, ok: true, result }) + "\n");
      }
    });
    // Swallow the expected ECONNRESET when the shim closes its end.
    c.on("error", () => {});
  });
  server.on("error", () => {});
  server.listen(sockPath);
  return { server, calls };
}

interface RunResult {
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

/**
 * Spawn the shim with the given env overrides; resolve with exit code + stdio.
 *
 * ASYNC (not spawnSync) on purpose: the mock arbiter runs IN THIS process, so a
 * blocking spawnSync would freeze the event loop and the arbiter could never
 * answer the shim's request → the shim would hang. Async spawn keeps the loop
 * live so the in-process arbiter responds while the child runs.
 */
async function runWrap(
  env: Record<string, string>,
  argv: string[] = ["http://dest.example/"],
): Promise<RunResult> {
  const child = spawn(TSX_BIN, [WRAP_TS, ...argv], {
    cwd: PKG_ROOT,
    // Start from a clean-ish env but DROP any inherited MANDU_ARBITER_SOCK so a
    // stray ambient socket can't mask the "unset" scenario.
    env: { ...stripArbiterEnv(process.env), ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (c: string) => (stdout += c));
  child.stderr.on("data", (c: string) => (stderr += c));

  const watchdog = setTimeout(() => child.kill("SIGKILL"), 30000);
  try {
    const [status, signal] = (await once(child, "close")) as [number | null, NodeJS.Signals | null];
    return { status, signal, stdout, stderr };
  } finally {
    clearTimeout(watchdog);
  }
}

function stripArbiterEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) continue;
    if (k === "MANDU_ARBITER_SOCK" || k === "MANDU_EXECWRAP_CMD" || k === "MANDU_EXECWRAP_SHIM_DIR" || k === "MANDU_EXECWRAP_PROBE") {
      continue;
    }
    out[k] = v;
  }
  return out;
}

/** A fresh temp dir per test (also serves as the shim dir to exclude). */
function freshDir(): { dir: string; sock: string; sentinel: string } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-execwrap-e2e-"));
  return { dir, sock: join(dir, "arbiter.sock"), sentinel: join(dir, "ran.sentinel") };
}

test("(a) MANDU_ARBITER_SOCK unset → exit 77 (fail-closed), command NOT run", async () => {
  const { dir, sentinel } = freshDir();
  try {
    const r = await runWrap({
      // Command name is provided (launcher sets it); the ONLY missing thing is the
      // arbiter socket, so we exercise the sock-required fail-closed branch.
      MANDU_EXECWRAP_CMD: "curl",
      MANDU_EXECWRAP_SHIM_DIR: dir,
      // MANDU_ARBITER_SOCK intentionally absent.
    });
    assert.equal(r.status, BLOCK_EXIT_CODE, `expected fail-closed exit ${BLOCK_EXIT_CODE}, got ${r.status} (signal ${r.signal}); stderr=${r.stderr}`);
    assert.match(r.stderr, /MANDU_ARBITER_SOCK is required/);
    assert.equal(existsSync(sentinel), false, "real command must NOT have run");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("(b) MANDU_ARBITER_SOCK → nonexistent socket → exit 77 (fail-closed), command NOT run", async () => {
  const { dir, sock, sentinel } = freshDir();
  try {
    // `sock` is never bound → connect() fails ENOENT → fail-closed block.
    assert.equal(existsSync(sock), false);
    const r = await runWrap({
      MANDU_EXECWRAP_CMD: "curl",
      MANDU_EXECWRAP_SHIM_DIR: dir,
      MANDU_ARBITER_SOCK: sock,
    });
    assert.equal(r.status, BLOCK_EXIT_CODE, `expected fail-closed exit ${BLOCK_EXIT_CODE}, got ${r.status} (signal ${r.signal}); stderr=${r.stderr}`);
    assert.match(r.stderr, /arbiter unreachable/);
    assert.equal(existsSync(sentinel), false, "real command must NOT have run");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("(c) mock arbiter returns an approval/block verdict → exit 77 (fail-closed), command NOT run", async () => {
  const { dir, sock, sentinel } = freshDir();
  const marker = "EXECWRAP_E2E_MARKER_C";
  const { server, calls } = startMockArbiter(sock, "block", sentinel, marker);
  await once(server, "listening");
  try {
    const r = await runWrap({
      MANDU_EXECWRAP_CMD: "curl",
      MANDU_EXECWRAP_SHIM_DIR: dir,
      MANDU_ARBITER_SOCK: sock,
    });
    assert.equal(r.status, BLOCK_EXIT_CODE, `expected fail-closed exit ${BLOCK_EXIT_CODE}, got ${r.status} (signal ${r.signal}); stderr=${r.stderr}`);
    // Plain words first (what, why, what to do), the machine reason after.
    assert.match(r.stderr, /mandu-exec-wrap: blocked curl, nothing ran\./);
    assert.match(r.stderr, /why: text from an untrusted source .* would run as a command/);
    assert.match(r.stderr, /what to do: if you trust that text, run the command yourself, outside the agent/);
    assert.match(r.stderr, /detail: symbol_as_command/);
    // The shim DID consult the arbiter (so this is a real BLOCK verdict, not a
    // crash before the gate ran). wrap.ts also emits a best-effort processLineage
    // edge before the gate (off the blocking path, design §3.2 / Plan 4).
    assert.deepEqual(calls, ["processLineage", "classifyExec", "resolveExecArgv"]);
    // The withheld command never executed.
    assert.equal(existsSync(sentinel), false, "real command must NOT have run on a block verdict");
    assert.equal(r.stdout.includes(marker), false, "no allow-path stdout marker on a block");
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("(d) mock arbiter returns a clean ALLOW → real command RUNS (sentinel + marker), exit 0", async () => {
  const { dir, sock, sentinel } = freshDir();
  const marker = "EXECWRAP_E2E_MARKER_D";
  const { server, calls } = startMockArbiter(sock, "allow", sentinel, marker);
  await once(server, "listening");
  try {
    const r = await runWrap({
      MANDU_EXECWRAP_CMD: "curl",
      MANDU_EXECWRAP_SHIM_DIR: dir,
      MANDU_ARBITER_SOCK: sock,
    });
    assert.equal(r.status, 0, `expected the real command to run and exit 0, got ${r.status} (signal ${r.signal}); stderr=${r.stderr}`);
    // The real (arbiter-resolved) command actually ran — proven two ways.
    assert.equal(existsSync(sentinel), true, "the resolved command must have run and written the sentinel");
    assert.equal(readFileSync(sentinel, "utf8"), "RAN");
    assert.match(r.stdout, new RegExp(marker), "the resolved command's stdout marker must be visible");
    // wrap.ts emits processLineage before the gate (best-effort, off the blocking
    // path, design §3.2 / Plan 4).
    assert.deepEqual(calls, ["processLineage", "classifyExec", "resolveExecArgv"]);
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("(e) the launcher's load probe: ok line, exit 0, no arbiter call, nothing run (even under an ALLOW)", async () => {
  const { dir, sock, sentinel } = freshDir();
  const marker = "EXECWRAP_E2E_MARKER_E";
  const { server, calls } = startMockArbiter(sock, "allow", sentinel, marker);
  await once(server, "listening");
  try {
    const r = await runWrap({
      MANDU_EXECWRAP_CMD: "curl",
      MANDU_EXECWRAP_SHIM_DIR: dir,
      MANDU_ARBITER_SOCK: sock,
      MANDU_EXECWRAP_PROBE: "1",
    });
    assert.equal(r.status, 0, `probe exit ${r.status}; stderr=${r.stderr}`);
    // launcher/src/services/exec-shims.ts EXEC_WRAP_PROBE_OK
    assert.match(r.stdout, /^mandu-exec-wrap: probe ok$/m);
    assert.deepEqual(calls, [], "the probe connects to nothing");
    assert.equal(existsSync(sentinel), false, "the probe runs nothing");
    assert.equal(r.stdout.includes(marker), false);
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
