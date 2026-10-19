/**
 * checkout-launch.mjs — a dev checkout's launch prelude, run inside the
 * launcher's own node (packaging.md §5.1).
 *
 * launcher/mandu-run.sh used to start two node processes before the launcher:
 * `source scripts/mandu-env.sh` (node secrets-to-env.mjs, to load the secrets
 * file into the shell) and `node bundle-stamp.mjs` (is the bundle fresh?),
 * about 0.2 s each on a host whose node starts slowly. It now execs
 * `node bin/mandu.mjs` with MANDU_SHIM_CHECKOUT=<repo root>, and bin/mandu.mjs
 * runs `checkoutPrelude` before it imports the bundle, doing the same two
 * steps in process:
 *
 *   1. the secrets file: `applySecretsEnv` (scripts/secrets-to-env.mjs) sets
 *      in process.env exactly the variables the shell's `eval` set (never one
 *      already set non-empty), its informational lines only for a verbose
 *      launch (`--verbose` before any `--`, or MANDU_VERBOSE). Best effort:
 *      nothing here aborts the launch. Skipped, as before, when the checkout
 *      has no scripts/mandu-env.sh.
 *   2. the bundle: `checkStamp` over launcher/dist; stale → `build-bundle.mjs
 *      --if-stale --no-native --quiet` (its output on stderr, as the shim
 *      sent it) and the check again; still stale → the source through tsx,
 *      with the shim's own warning, by execve (the launcher's process is
 *      replaced, as the shim's `exec` did). A stale bundle never runs.
 *
 * Returns only when the bundle is fresh; the caller then imports it.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { checkStamp } from "./bundle-stamp.mjs";

/** The shim's own words when the bundle cannot be made fresh. */
export const STALE_FALLBACK_MESSAGE =
  "mandu-run.sh: the launcher bundle is out of date and could not be rebuilt; running from source (slower). Rebuild: cd launcher && npm run build:bundle";

/**
 * Is this launch quiet about the secrets load? Yes unless MANDU_VERBOSE is set
 * to anything but "", 0 or false, or `--verbose` comes before the first `--`
 * (the shim's own rule, which the launcher's parse follows).
 */
export function secretsQuiet(argv, env) {
  const v = env.MANDU_VERBOSE ?? "";
  if (!["", "0", "false", "FALSE", "False"].includes(v)) return false;
  for (const a of argv) {
    if (a === "--") break;
    if (a === "--verbose") return false;
  }
  return true;
}

/** Load the checkout's secrets file into `env` (step 1). Never throws. */
export async function loadCheckoutSecrets(repoRoot, argv, env) {
  if (!existsSync(join(repoRoot, "scripts", "mandu-env.sh"))) return [];
  const log = (m) => process.stderr.write(`[mandu-secrets] ${m}\n`);
  try {
    const mod = await import(pathToFileURL(join(repoRoot, "scripts", "secrets-to-env.mjs")).href);
    return mod.applySecretsEnv(env, { quiet: secretsQuiet(argv, env), log });
  } catch (e) {
    log(`could not load the secrets file: ${e instanceof Error ? e.message : String(e)} — nothing loaded`);
    return [];
  }
}

/** Is the checkout's bundle fresh? Any error reads as stale. */
export function bundleFresh(distDir, repoRoot) {
  try {
    return checkStamp(distDir, { repoRoot }).fresh === true;
  } catch {
    return false;
  }
}

/**
 * Run the source through tsx in place of this process: execve where node has
 * it (22.15 and later), else a child that holds the terminal, gets SIGTERM and
 * SIGHUP relayed (SIGINT reaches it from the terminal itself), and whose exit
 * this process mirrors. Does not return.
 */
function runSource(tsx, run, argv, env) {
  if (typeof process.execve === "function") {
    process.execve(tsx, [tsx, run, ...argv], env);
  }
  const child = spawn(tsx, [run, ...argv], { stdio: "inherit", env });
  for (const sig of ["SIGTERM", "SIGHUP"]) process.on(sig, () => child.kill(sig));
  process.on("SIGINT", () => {});
  return new Promise(() => {
    child.on("exit", (code, signal) => {
      if (signal) {
        process.removeAllListeners(signal);
        process.kill(process.pid, signal);
      }
      process.exit(code ?? 1);
    });
    child.on("error", (e) => {
      process.stderr.write(`mandu-run.sh: could not start ${tsx}: ${e.message}\n`);
      process.exit(127);
    });
  });
}

/**
 * The prelude (steps 1 and 2 above). `repoRoot` is the shim's REPO_ROOT; the
 * launcher package is its `launcher/`. Resolves when the bundle is fresh.
 */
export async function checkoutPrelude({ repoRoot, argv, env = process.env }) {
  const pkg = join(repoRoot, "launcher");
  const dist = join(pkg, "dist");
  await loadCheckoutSecrets(repoRoot, argv, env);
  if (bundleFresh(dist, repoRoot)) return;
  const build = spawnSync(process.execPath, [join(pkg, "scripts", "build-bundle.mjs"), "--if-stale", "--no-native", "--quiet"], {
    stdio: ["inherit", 2, "inherit"], env,
  });
  if (build.status === 0 && bundleFresh(dist, repoRoot)) return;
  process.stderr.write(`${STALE_FALLBACK_MESSAGE}\n`);
  await runSource(join(pkg, "node_modules", ".bin", "tsx"), join(pkg, "src", "run.ts"), argv, env);
}
