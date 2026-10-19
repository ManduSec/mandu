/**
 * services/exec-shims — write the PATH-shadow exec-wrap shim dir.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Adapted from launcher/mandu-run.sh exec-wrap block (L968-1042): a
 *   <scopeRunDir>/exec-shims dir with one bash shim per HIGH-RISK command that
 *   `exec -a <cmd>`s the package-local tsx wrap.ts (arbiter-gated, exit 77 on a
 *   symbol-as-command). The composer prepends this dir to the agent's PATH.
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, realpathSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import type { Layout } from "./layout.js";
import { publishFile } from "../safe-file.js";
import { cachedProbeAsync, realProbeCacheIo, type ProbeCacheIo, type ProbeInputs } from "../probe-cache.js";

/** What exec-wrap's load probe prints on success (interceptors/exec-wrap/src/
 *  wrap.ts, MANDU_EXECWRAP_PROBE=1). No runtime import of that file: importing
 *  it would run the wrapper. */
export const EXEC_WRAP_PROBE_OK = "mandu-exec-wrap: probe ok";

/** How long the probe may take: one node start plus the module load (tsx
 *  transpiles from source in a checkout). */
const PROBE_TIMEOUT_MS = 20_000;

type ShimRuntime = { tokens: string[]; env: Record<string, string> };

/** One shim script. Every value sits in a double-quoted bash string. The
 *  layout resolves the runtime: dev = the package-local tsx over wrap.ts;
 *  installed = `node dist/exec-shim.mjs` (+ the arbiter client module,
 *  emitted as extra `export`s). */
function shimBody(cmd: string, shimDir: string, arbiterSock: string, runtime: ShimRuntime): string {
  const execTokens = runtime.tokens.map((t) => `"${t}"`).join(" ");
  const layoutExports = Object.entries(runtime.env)
    .map(([k, v]) => `export ${k}="${v}"\n`)
    .join("");
  // Default-preserving arbiter-sock (parity: mandu-run.sh L1010-1016) so a
  // shim invoked outside the wrapper still finds the socket the launcher baked in.
  return (
    `#!/usr/bin/env bash\n` +
    `export MANDU_EXECWRAP_CMD="${cmd}"\n` +
    `export MANDU_EXECWRAP_SHIM_DIR="${shimDir}"\n` +
    `export MANDU_ARBITER_SOCK="\${MANDU_ARBITER_SOCK:-${arbiterSock}}"\n` +
    layoutExports +
    `exec -a "$MANDU_EXECWRAP_CMD" ${execTokens} "$@"\n`
  );
}

export function writeExecShims(cmds: string[], layout: Layout, arbiterSock: string, scopeRunDir: string): string {
  const clean = cmds.map((c) => c.trim()).filter(Boolean);
  if (clean.length === 0) throw new Error("mandu: --exec-wrap given no commands to shadow");

  const shimDir = join(scopeRunDir, "exec-shims");
  mkdirSync(shimDir, { recursive: true });
  const runtime = layout.execShim();
  for (const cmd of clean) {
    // Never through a link planted at the shim's name or a linked shim dir
    // (safe-file.ts); the mode is set on the descriptor, not by path.
    publishFile(join(shimDir, cmd), shimBody(cmd, shimDir, arbiterSock, runtime), { mode: 0o755 });
  }
  return shimDir;
}

/**
 * Run one written shim in exec-wrap's probe mode (portable-wrapper.md §5):
 * the real shim, its runtime and the arbiter client module load, and nothing
 * runs or connects. Rejects with the reason when it does not print
 * {@link EXEC_WRAP_PROBE_OK} and exit 0. A shim that cannot load fails every
 * call closed (exit 77 or a crash), so the launcher must not report exec-wrap
 * LIVE over it: the caller treats a rejection as a failed start (degrade with
 * a warning by default, refuse when exec-wrap was asked for explicitly).
 */
export function probeExecShim(shimDir: string, cmd: string, timeoutMs = PROBE_TIMEOUT_MS): Promise<void> {
  const shim = join(shimDir, cmd);
  return new Promise((resolve, reject) => {
    execFile(shim, [], {
      env: { ...process.env, MANDU_EXECWRAP_PROBE: "1" },
      timeout: timeoutMs,
      killSignal: "SIGKILL",
      maxBuffer: 1024 * 1024,
    }, (err, stdout, stderr) => {
      if (!err && String(stdout).includes(EXEC_WRAP_PROBE_OK)) { resolve(); return; }
      const why = probeFailureDetail(err, String(stderr));
      reject(new Error(`the exec-wrap shim cannot load (${why}); a shim that cannot load would block every '${cmd}' call`));
    });
  });
}

// ── The probe, kept for the boot (portable-wrapper.md §5; packaging.md §5.4) ──

/** What the launch knows about the shims it wrote: the probe's key is built
 *  from these, never read back from the written file. */
export interface ExecShimProbeContext {
  layout: Layout;
  arbiterSock: string;
}

/** A value that is inert inside the shim's double-quoted bash strings: no
 *  `"`, `$`, backquote, backslash or newline. Only then is the script with
 *  this launch's per-session paths the same program as the key's template. */
const INERT = /^[^"$`\\\n]*$/;

/** What the probe's processes read before exec-wrap's own code runs: bash's
 *  startup variables, the dynamic loader's (every `LD_*`) and the
 *  allocator's, node's (every `NODE_*` and `UV_*`), and PATH (which bash,
 *  which node). The per-session values (the arbiter socket, the shim dir)
 *  are not read in probe mode. */
const LOADER_ENV = new Set(["PATH", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "GLIBC_TUNABLES", "MALLOC_CONF"]);
const LOADER_PREFIXES = ["LD_", "NODE_", "UV_"];
function loaderEnv(env: NodeJS.ProcessEnv): string {
  const keys = Object.keys(env).filter((k) => LOADER_ENV.has(k) || LOADER_PREFIXES.some((p) => k.startsWith(p))).sort();
  return JSON.stringify(keys.map((k) => [k, env[k] ?? null]));
}

/**
 * The mount a path is on, as /proc/self/mountinfo lists it: the mount point,
 * its per-mount options (`noexec` among them), the filesystem type and its
 * super options. The longest mount point that holds `path`; of two at the
 * same point, the later (the one mounted on top). `null` when none matches.
 * Pure.
 */
export function mountOf(path: string, mountinfo: string): string | null {
  const unescape = (s: string): string => s.replace(/\\([0-7]{3})/g, (_m, o: string) => String.fromCharCode(parseInt(o, 8)));
  let best: { point: string; desc: string } | null = null;
  for (const line of mountinfo.split("\n")) {
    const f = line.split(" ");
    const dash = f.indexOf("-");
    if (dash < 6 || f.length < dash + 4) continue;
    const point = unescape(f[4]!);
    const holds = point === "/" || path === point || path.startsWith(point + "/");
    if (!holds || (best !== null && point.length < best.point.length)) continue;
    best = { point, desc: [point, f[5], f[dash + 1], f[dash + 3]].join(" ") };
  }
  return best?.desc ?? null;
}

/**
 * Whether this launch's shim probe may be answered from the per-boot probe
 * cache, and the key's inputs when it may (a thunk: nothing is read unless
 * the cache is on). Never cacheable, so always probed afresh: the source
 * form (tsx loads wrap.ts and every module it imports out of the checkout,
 * which no fixed list of files keys), a host other than Linux (no mountinfo
 * to key the shim dir's `noexec` on), and a path, command or token that is
 * not {@link INERT}.
 *
 * The key is everything the probe's answer depends on: the script (as a
 * template, the per-session shim dir and arbiter socket replaced, which the
 * probe does not read), the identity of `/usr/bin/env`, of the bash it finds
 * on PATH, of the runtime (`node` on PATH), of every file it loads by path
 * (the exec-shim bundle, the arbiter client module) and of the loader cache
 * (`/etc/ld.so.cache`: a shared library node links was replaced), the mount
 * the shim dir is on (`noexec`), and the loader environment; plus the shared
 * context every kept probe is keyed on (probe-cache.ts: the boot, the uid,
 * the launcher's namespaces, seccomp and AppArmor label, PATH, the launcher's
 * own file).
 */
export function execShimProbeInputs(
  cmd: string,
  shimDir: string,
  ctx: ExecShimProbeContext,
  opts: { io?: ProbeCacheIo; env?: NodeJS.ProcessEnv; platform?: string } = {},
): (() => ProbeInputs) | null {
  if (!ctx.layout.bundled || (opts.platform ?? process.platform) !== "linux") return null;
  const runtime = ctx.layout.execShim();
  const values = [cmd, shimDir, ctx.arbiterSock, ...runtime.tokens, ...Object.keys(runtime.env), ...Object.values(runtime.env)];
  if (cmd === "" || !values.every((v) => INERT.test(v))) return null;
  const io = opts.io ?? realProbeCacheIo;
  const env = opts.env ?? process.env;
  return () => {
    const template = shimBody(cmd, "<shim-dir>", "<arbiter-sock>", runtime);
    let real = shimDir;
    try { real = realpathSync(shimDir); } catch { /* keep the spelling */ }
    const files = [...runtime.tokens.filter((t) => !t.startsWith("-")), ...Object.values(runtime.env).filter((v) => isAbsolute(v))];
    return {
      bins: ["/usr/bin/env", "bash", ...files, "/etc/ld.so.cache"],
      argv: [cmd],
      extra: {
        template: createHash("sha256").update(template).digest("hex"),
        shimMount: mountOf(real, io.readText("/proc/self/mountinfo") ?? ""),
        env: loaderEnv(env),
      },
    };
  };
}

/**
 * {@link probeExecShim} through the launch's per-boot probe cache
 * (probe-cache.ts, packaging.md §5.4): a pass kept earlier this boot for the
 * exact same inputs answers without the node start; anything else probes,
 * and only a pass is kept. A failure rejects exactly as {@link probeExecShim}
 * does and is never kept. Outside a launch (no enabled cache) and for inputs
 * that are not cacheable ({@link execShimProbeInputs}), a plain probe.
 */
export async function probeExecShimCached(
  shimDir: string,
  cmd: string,
  ctx: ExecShimProbeContext,
  deps: { probe?: (shimDir: string, cmd: string) => Promise<void>; io?: ProbeCacheIo; env?: NodeJS.ProcessEnv; platform?: string } = {},
): Promise<void> {
  const probe = deps.probe ?? probeExecShim;
  const inputs = execShimProbeInputs(cmd, shimDir, ctx, deps);
  if (inputs === null) return probe(shimDir, cmd);
  await cachedProbeAsync("exec-shim", inputs, async () => { await probe(shimDir, cmd); return true; });
}

/** One line on why the probe failed: the first error-looking line of its
 *  stderr (a missing module names the package), else the exit status. */
function probeFailureDetail(err: (Error & { code?: unknown; signal?: unknown; killed?: boolean }) | null, stderr: string): string {
  const lines = stderr.split("\n").map((l) => l.trim()).filter(Boolean);
  // Node's own report line ("Error [ERR_MODULE_NOT_FOUND]: Cannot find …")
  // before the source excerpt it prints above it ("throw new ERR_…(").
  const line = lines.find((l) => /^[A-Za-z]*Error\b/.test(l))
    ?? lines.find((l) => /cannot|not found|mandu-exec-wrap:/i.test(l))
    ?? lines[0];
  if (line) return line.length > 240 ? `${line.slice(0, 240)}…` : line;
  if (!err) return "the probe printed no ok line";
  if (err.killed) return "the probe timed out";
  return `exit ${String(err.code ?? err.signal ?? "unknown")}`;
}
