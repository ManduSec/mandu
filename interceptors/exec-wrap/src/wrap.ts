#!/usr/bin/env tsx
/**
 * wrap — the Mandu exec chokepoint CLI (cooperative Tier-2 PATH shim).
 *
 * The launcher (`mandu-run.sh --exec-wrap`) creates a temp shim dir on the
 * AGENT's PATH containing one executable per HIGH-RISK shadowed command (default
 * curl/wget/nc). Each shim execs THIS file with argv0 = the command name (via
 * bash `exec -a`). So when the agent's Bash tool runs `curl …`, it hits our shim,
 * which runs us as `curl`.
 *
 * We learn WHICH command we are from our OWN argv0 basename (process.argv[1] is
 * this script under tsx; the launcher's shim sets argv0 via `exec -a <cmd>`, and
 * also passes the canonical name in MANDU_EXECWRAP_CMD as a robust fallback).
 * The full observed argv is [cmdName, ...process.argv.slice(2)].
 *
 * Flow (all FAIL-CLOSED — any arbiter error blocks, never runs the raw command):
 *   1. require MANDU_ARBITER_SOCK; build the real arbiter client.
 *   2. decideExec(arbiter, argv, cwd) (src/gate.ts) → allow(resolved argv) | block.
 *   3. BLOCK → print "mandu-exec-wrap: blocked …" to stderr, exit 77.
 *      ALLOW → find the REAL command on PATH (EXCLUDING the shim dir, so we never
 *      re-enter our own shim → no infinite recursion) and exec it with the
 *      arbiter-RESOLVED argv, propagating its exit code.
 *
 * Env:
 *   MANDU_ARBITER_SOCK        path to the arbiter Unix socket (REQUIRED).
 *   MANDU_EXECWRAP_SHIM_DIR  the shim dir to EXCLUDE from the real-command PATH
 *                              search (REQUIRED to avoid shim recursion).
 *   MANDU_EXECWRAP_CMD       canonical shadowed command name (fallback if argv0
 *                              basename is not the command, e.g. "tsx").
 *   MANDU_EXECWRAP_PROBE     "1" = the launcher's load probe: load every module
 *                              the gate needs (this file's imports and the
 *                              arbiter client), print EXEC_WRAP_PROBE_OK, exit 0.
 *                              Runs nothing and connects to nothing.
 */

import { spawnSync } from "node:child_process";
import { basename } from "node:path";

import { blockMessage, decideExec, unreachableMessage } from "./gate.js";
import { findRealCommand } from "./path-resolve.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "./arbiter-client.js";
import { recordSpawnLineage, provisionalProcKey } from "./lineage.js";

/** Distinct exit code for a fail-closed BLOCK (so callers/tests can tell a gate
 * refusal apart from the real command's own non-zero exits). */
const BLOCK_EXIT_CODE = 77;

function die(message: string, code: number): never {
  process.stderr.write(`mandu-exec-wrap: ${message}\n`);
  process.exit(code);
}

/**
 * Determine the shadowed command name this invocation stands in for.
 *
 * Prefer MANDU_EXECWRAP_CMD (the launcher sets it per shim, unambiguous). Else
 * fall back to argv0's basename — under `exec -a <cmd> tsx wrap.ts …` Node sees
 * process.argv0 === "<cmd>" while process.argv[1] is this script's path. We must
 * NOT use argv[1]'s basename ("wrap") as the command.
 */
function resolveCommandName(): string {
  const fromEnv = process.env["MANDU_EXECWRAP_CMD"];
  if (fromEnv && fromEnv.trim() !== "") return fromEnv.trim();
  // process.argv0 is the argv[0] the process was launched with (honors exec -a).
  const a0 = process.argv0 ? basename(process.argv0) : "";
  if (a0 && a0 !== "node" && a0 !== "tsx") return a0;
  die(
    "cannot determine the shadowed command name (set MANDU_EXECWRAP_CMD or launch via `exec -a <cmd>`)",
    BLOCK_EXIT_CODE,
  );
}

/**
 * Build the REAL arbiter client over the Unix socket in MANDU_ARBITER_SOCK. The
 * specifier is assembled at runtime so the arbiter package is not statically
 * resolved into this program (mirrors fs-sync/src/fs-sync-cli.ts).
 */
async function buildArbiter(sock: string): Promise<{
  arbiter: ArbiterClientAdapter;
  close: () => void;
}> {
  const arbiterMod = (await import(arbiterClientSpecifier())) as {
    ArbiterClient: new (sock: string) => RealArbiterClient;
  };
  const client: RealArbiterClient = new arbiterMod.ArbiterClient(sock);
  await client.connect();
  const arbiter = new ArbiterClientAdapter(client);
  return { arbiter, close: () => client.close() };
}

/** What the load probe prints on success (launcher services/exec-shims.ts
 *  probeExecShim reads it). */
const EXEC_WRAP_PROBE_OK = "mandu-exec-wrap: probe ok";

/** The arbiter client module's specifier. A BUNDLED build (packaging.md §5)
 *  sets MANDU_ARBITER_CLIENT_MODULE to the co-located dist/arbiter-client.mjs
 *  (import.meta.url has moved to launcher/dist/, so the relative fallback would
 *  resolve wrong); unset in dev/tsx and tests → the from-source relative path.
 *  Assembled at runtime so the arbiter package is not statically resolved into
 *  this program (mirrors fs-sync/src/fs-sync-cli.ts). */
function arbiterClientSpecifier(): string {
  return process.env["MANDU_ARBITER_CLIENT_MODULE"] ?? ["..", "..", "..", "arbiter", "ipc", "client.js"].join("/");
}

async function main(): Promise<void> {
  if (process.env["MANDU_EXECWRAP_PROBE"] === "1") {
    // The launcher's load probe (exec-routing / launcher status truth): a shim
    // whose runtime cannot load fails every call closed, so the launcher must
    // not report it LIVE. Reaching this line proves the static imports loaded;
    // the arbiter client is imported the way buildArbiter imports it.
    await import(arbiterClientSpecifier());
    process.stdout.write(`${EXEC_WRAP_PROBE_OK}\n`);
    process.exit(0);
  }
  const cmdName = resolveCommandName();
  process.title = "mandu-exec-shim"; // canonical ps title (runtime-instances.md §7)
  const argv = [cmdName, ...process.argv.slice(2)];
  const cwd = process.cwd();
  const shimDir = process.env["MANDU_EXECWRAP_SHIM_DIR"];

  const sock = process.env["MANDU_ARBITER_SOCK"];
  if (!sock) {
    // FAIL CLOSED: without the arbiter we cannot gate, so we refuse — never run raw.
    die(
      `blocked ${cmdName}, nothing ran: this command wrapper is not connected to Mandu, so it cannot check the command (MANDU_ARBITER_SOCK is required)`,
      BLOCK_EXIT_CODE,
    );
  }

  // FAIL CLOSED: a arbiter that is unreachable must REFUSE the exec, not run raw.
  let arbiter: ArbiterClientAdapter;
  let closeArbiter: () => void;
  try {
    ({ arbiter, close: closeArbiter } = await buildArbiter(sock));
  } catch (err) {
    // EPERM / EACCES = a sandbox's filter or an access rule (Codex's sandbox,
    // network off, says so in its env), not a dead service: still a block,
    // with the true reason (unreachableMessage).
    die(unreachableMessage(cmdName, sock, err as NodeJS.ErrnoException, {
      codexNetworkOff: process.env["CODEX_SANDBOX_NETWORK_DISABLED"] === "1",
    }), BLOCK_EXIT_CODE);
  }

  // BEST-EFFORT spawn-lineage edge (design §3.2), OFF the blocking path: record
  // this shim (child) under its launching process (parent) so the arbiter's
  // transitive taint walk knows the lineage. A failure is swallowed inside
  // recordSpawnLineage — it must NEVER block or alter the gate/exec below.
  //
  // PROVISIONAL proc-key format (pid / pid-starttime) — the cross-layer
  // attribution co-design is DEFERRED, so these keys are not yet correlated with
  // the net/fs layers and the taint CHAIN is not live end-to-end (see lineage.ts).
  const childKey = provisionalProcKey(process.pid);
  const parentKey = provisionalProcKey(process.ppid);
  await recordSpawnLineage(arbiter, childKey, parentKey);

  let decision;
  try {
    decision = await decideExec(arbiter, argv, cwd);
  } finally {
    closeArbiter();
  }

  if (decision.action === "block") {
    die(blockMessage(cmdName, decision), BLOCK_EXIT_CODE);
  }

  // ALLOW: run the REAL command with the arbiter-resolved argv.
  const resolvedArgv = decision.argv.length > 0 ? decision.argv : argv;
  const realCmdName = resolvedArgv[0] ?? cmdName;
  const real = findRealCommand(realCmdName, { shimDir });
  if (!real) {
    die(
      `blocked ${cmdName}, nothing ran: the real '${realCmdName}' is not on PATH (outside Mandu's wrapper folder)`,
      BLOCK_EXIT_CODE,
    );
  }

  // execvp-style: spawnSync with inherited stdio + argv0 = the command name, then
  // propagate the child's exit code (or 128+signal on a signal death).
  const child = spawnSync(real, resolvedArgv.slice(1), {
    stdio: "inherit",
    argv0: realCmdName,
  });
  if (child.error) {
    die(`failed to exec real '${realCmdName}' (${real}): ${child.error.message}`, BLOCK_EXIT_CODE);
  }
  if (typeof child.status === "number") {
    process.exit(child.status);
  }
  if (child.signal) {
    // Mirror shell semantics: 128 + signal number is not portable here, so just
    // surface a generic non-zero.
    process.exit(1);
  }
  process.exit(0);
}

main().catch((err) => {
  die(`fatal (fail-closed block): ${(err as Error).message}`, BLOCK_EXIT_CODE);
});
