/**
 * plugin-probe — which confinement legs work on this host, found by running
 * them (confidentiality-plan-15-prompt-filter.md §4.3, §12 2026-10-03;
 * privilege-model.md §0: on by default where the kernel supports it,
 * probe-gated). Mandu-new (no reference origin).
 *
 * The probe opens two loopback listeners, A and B, and runs a tiny node
 * program that connects to both, under the composed wrap with `--allow` for A
 * only. A leg counts as working when the program exits 0: it reached A (the
 * guard connected for it, through every inner leg) and NOT B. The ladder:
 *
 *   1. the guard alone: REQUIRED; without it no plugin runs;
 *   2. the guard + Landlock (clean) + the seccomp deny filter; else Landlock
 *      alone; else the deny filter alone (`--seccomp-only`);
 *   3. bubblewrap around 2 (the namespaces).
 *
 * Each leg that fails is named in `notes`. The answer is memoized for the
 * arbiter's life by the caller (`memoProbe`).
 */
import { spawn } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { dirname, join } from "node:path";

import { NO_LEGS, planPluginArgv, PROBE_SCRIPT, pluginEnv, type ConfineLegs, type ConfineTools } from "./plugin-confine.js";

const PROBE_TIMEOUT_MS = 10_000;

function listen(): Promise<{ server: Server; port: number }> {
  return new Promise((resolve, reject) => {
    const server = createServer((s) => s.destroy());
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, port: typeof a === "object" && a ? a.port : 0 });
    });
  });
}

function runArgv(argv: readonly string[], env: NodeJS.ProcessEnv, cwd: string): Promise<number | null> {
  return new Promise((resolve) => {
    let done = false;
    const child = spawn(argv[0]!, argv.slice(1), { stdio: ["ignore", "ignore", "ignore"], env, cwd, detached: true });
    const finish = (code: number | null): void => { if (!done) { done = true; clearTimeout(t); resolve(code); } };
    const t = setTimeout(() => { try { if (child.pid) process.kill(-child.pid, "SIGKILL"); } catch { /* gone */ } finish(null); }, PROBE_TIMEOUT_MS);
    t.unref?.();
    child.on("error", () => finish(null));
    child.on("close", (code) => finish(code));
  });
}

/** Probe the legs with the real tools. Never throws. */
export async function probeConfinement(tools: ConfineTools, scratchRoot: string): Promise<ConfineLegs> {
  if (tools.netGuard === null) return { ...NO_LEGS, notes: ["mandu-net-guard is not installed (scripts/build-native.sh builds it)"] };
  let a: { server: Server; port: number } | null = null;
  let b: { server: Server; port: number } | null = null;
  let scratch: string | null = null;
  try {
    a = await listen();
    b = await listen();
    scratch = mkdtempSync(join(scratchRoot, "probe-"));
    const node = realpathSync(process.execPath);
    const target = [node, "-e", PROBE_SCRIPT, String(a.port), String(b.port)];
    const env = pluginEnv({ scratch, hostEnv: process.env });
    const allow = [`tcp:127.0.0.1:${a.port}`];
    const works = async (legs: ConfineLegs): Promise<boolean> =>
      (await runArgv(planPluginArgv({ legs, tools, allow, readDirs: [dirname(node)], scratch: scratch!, target }), env, scratch!)) === 0;
    const notes: string[] = [];
    let legs: ConfineLegs = { guard: true, landlock: false, seccomp: false, namespaces: false, notes };
    if (!(await works(legs))) {
      return { ...NO_LEGS, notes: ["mandu-net-guard could not confine a test program on this host (seccomp user notification, kernel 5.6 or later)"] };
    }
    if (tools.landlockApply === null) {
      notes.push("mandu-landlock-apply is not installed: no Landlock and no seccomp deny filter");
    } else if (await works({ ...legs, landlock: true, seccomp: true })) {
      legs = { ...legs, landlock: true, seccomp: true };
    } else if (await works({ ...legs, landlock: true })) {
      legs = { ...legs, landlock: true };
      notes.push("the seccomp deny filter is off: mandu-landlock-apply could not install it here");
    } else if (await works({ ...legs, seccomp: true })) {
      legs = { ...legs, seccomp: true };
      notes.push("Landlock is off: this kernel cannot enforce it (5.13 or later)");
    } else {
      notes.push("Landlock and the seccomp deny filter are off: mandu-landlock-apply failed here");
    }
    if (tools.bwrap === null) {
      notes.push("the PID/IPC/UTS namespaces are off: bubblewrap is not installed");
    } else if (await works({ ...legs, namespaces: true })) {
      legs = { ...legs, namespaces: true };
    } else {
      notes.push("the PID/IPC/UTS namespaces are off: under bubblewrap the network guard could not connect for a test program on this host");
    }
    return { ...legs, notes };
  } catch (err) {
    return { ...NO_LEGS, notes: [`the confinement probe failed: ${(err as Error).message}`] };
  } finally {
    a?.server.close();
    b?.server.close();
    if (scratch !== null) rmSync(scratch, { recursive: true, force: true });
  }
}

/** The probe, run once and shared. */
export function memoProbe(tools: ConfineTools, scratchRoot: string, probe = probeConfinement): () => Promise<ConfineLegs> {
  let p: Promise<ConfineLegs> | null = null;
  return () => (p ??= probe(tools, scratchRoot));
}
