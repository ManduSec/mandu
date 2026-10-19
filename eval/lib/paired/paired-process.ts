/** Bounded child lifetime and capture.
 * PROVENANCE: adapted from tests/lib/child-run.ts; keeps its
 * process-group cleanup and exit/close grace, adds retained timeout evidence.
 */
import { spawn } from "node:child_process";
import type { LaunchSpec } from "./paired-config.js";

export interface ProcessResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  truncated: boolean;
  error: string | null;
  durationMs: number;
}

export function runCaptured(spec: LaunchSpec, cwd: string, timeoutMs: number): Promise<ProcessResult> {
  return new Promise((resolve) => {
    const started = Date.now();
    const r: ProcessResult = { code: null, stdout: "", stderr: "", timedOut: false, truncated: false, error: null, durationMs: 0 };
    const child = spawn(spec.command, spec.args, { cwd, env: spec.env, detached: true, stdio: ["ignore", "pipe", "pipe"] });
    const cap = 4 * 1024 * 1024;
    for (const name of ["stdout", "stderr"] as const) child[name].on("data", (data: Buffer) => {
      if (r[name].length + data.length > cap) r.truncated = true;
      r[name] = (r[name] + data.toString()).slice(0, cap);
    });
    let settled = false;
    let grace: NodeJS.Timeout | undefined;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline); clearTimeout(grace);
      if (child.pid) { try { process.kill(-child.pid, "SIGKILL"); } catch { /* exited */ } }
      child.stdout.destroy(); child.stderr.destroy();
      r.durationMs = Date.now() - started;
      resolve(r);
    };
    const deadline = setTimeout(() => { r.timedOut = true; finish(); }, timeoutMs);
    child.once("error", (e) => { r.error = e.message; finish(); });
    child.once("exit", (code) => { if (!settled) { r.code = code; grace = setTimeout(finish, 2000); } });
    child.once("close", (code) => { if (!settled) { r.code = code; finish(); } });
  });
}
