/**
 * gnu-coreutil — GNU's copy of a coreutils program, for a test that needs a
 * plain leaf program (one binary, one program) and not just "whatever `tee`
 * is on PATH".
 *
 * Why: where uutils coreutils owns the names (Ubuntu 26.04: `/usr/bin/tee` →
 * `/usr/lib/cargo/bin/coreutils/tee`), every program is the one multi-call
 * binary that picks what to run from its argv[0], which the caller sets
 * (`exec -a env …/coreutils/tee` runs `env`). Mandu therefore counts every
 * file in that directory as a printer and as running code (arbiter
 * `flow-taint.ts` MULTICALL_PRINTER_DIRS; confidentiality-plan-13-reader-set-labels.md
 * items (3) and (3a)): a listed
 * uutils `sha256sum` reads no byte of a secret, and an Always for uutils'
 * `tee` covers one run (`write:<exe>#<sha256>#run:<proc>`), never the binary.
 * A test whose control is "a leaf reader reads the real file" or "an Always
 * names the binary" needs GNU's program; on such hosts the distribution
 * keeps it as `gnu<name>` (package gnu-coreutils).
 */
import { existsSync, realpathSync } from "node:fs";

/** The directory uutils' multi-call programs resolve into (flow-taint.ts). */
export const UUTILS_DIR = "/usr/lib/cargo/";

/** Is `path` (resolved) one of uutils' multi-call programs? */
export function isUutils(path: string): boolean {
  try { return realpathSync(path).startsWith(UUTILS_DIR); } catch { return false; }
}

/**
 * GNU's `name`: its resolved path and the basename a policy names it by
 * (`gnusha256sum` where uutils owns `sha256sum`, else `sha256sum`), or
 * undefined when no GNU copy is installed (the caller SKIPs, saying so).
 */
export function gnuCoreutil(name: string): { path: string; app: string } | undefined {
  for (const p of [`/usr/bin/gnu${name}`, `/bin/gnu${name}`, `/usr/bin/${name}`, `/bin/${name}`]) {
    if (!existsSync(p) || isUutils(p)) continue;
    const path = realpathSync(p);
    return { path, app: path.slice(path.lastIndexOf("/") + 1) };
  }
  return undefined;
}
