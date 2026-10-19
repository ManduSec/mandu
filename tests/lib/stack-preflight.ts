/**
 * stack-preflight — the package preflight every launch of the real stack
 * makes before anything starts: are the packages of every service the
 * launcher spawns installed? Pure given its deps.
 *
 * Why (test-organization.md §8.12): a launch from source runs each Mandu
 * service with its own package's tsx (the launcher's dev layout,
 * launcher/src/services/layout.ts). A package without its node_modules does
 * not refuse the launch: the service dies when it is first spawned, and a
 * check graded on what that service did NOT do then passes. The exec-wrap
 * shim crashed at load that way on every curl (ERR_MODULE_NOT_FOUND,
 * 2026-10-04) and the sink checks passed on a gate that never ran. The
 * drill replays and live runs refused it first (!516); the shared
 * `withStack` (launcher-live.ts) now refuses it for every suite that
 * launches the stack, with MissingStackPackagesError naming each package and
 * the install command.
 *
 * Moved here from the drill suite's preflight module (2026-10-18), which
 * re-exports these names, so a public suite can use them.
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export interface PackageProbeDeps {
  read?: (p: string) => string;
  exists?: (p: string) => boolean;
}

/** The source packages of the services the launcher spawns (bundle-manifest.json
 *  `services`, the map the layout resolver spawns from), repo-root-relative:
 *  the nearest directory above each entry holding a package.json. */
export function manduServicePackages(repoRoot: string, deps: PackageProbeDeps = {}): string[] {
  const read = deps.read ?? ((p: string) => readFileSync(p, "utf8"));
  const exists = deps.exists ?? existsSync;
  const manifest = JSON.parse(read(join(repoRoot, "launcher", "bundle-manifest.json"))) as { services?: Record<string, string> };
  const out = new Set<string>();
  for (const entry of Object.values(manifest.services ?? {})) {
    let dir = dirname(entry);
    while (dir !== "." && dir !== "" && dir !== "/" && !exists(join(repoRoot, dir, "package.json"))) dir = dirname(dir);
    if (dir === "." || dir === "" || dir === "/") throw new Error(`bundle-manifest.json: no package.json above ${entry}`);
    out.add(dir);
  }
  return [...out].sort();
}

/** The file whose presence says a package is installed: its own tsx, the
 *  dev layout's loader (layout.ts devTsx). */
export const INSTALLED_MARKER = join("node_modules", "tsx", "dist", "esm", "index.mjs");

/** The Mandu-side packages not installed: no `node_modules/tsx` (the dev
 *  layout's loader, layout.ts devTsx). Empty when all are. */
export function missingManduPackages(repoRoot: string, deps: PackageProbeDeps = {}): string[] {
  const exists = deps.exists ?? existsSync;
  return manduServicePackages(repoRoot, deps).filter((pkg) => !exists(join(repoRoot, pkg, INSTALLED_MARKER)));
}

/** The refusal for missing packages, or null: names each one and the install. */
export function manduPackagesRefusal(missing: string[]): string | null {
  if (missing.length === 0) return null;
  const one = missing.length === 1;
  return `the side under Mandu cannot run: ${missing.join(", ")} ${one ? "is" : "are"} not installed (no node_modules/tsx), so ${one ? "its service dies" : "their services die"} when spawned and a check graded on what it did not do would pass. ` +
    `Install with: ${missing.map((p) => `node scripts/install-deps.mjs ${p}`).join(" && ")} (or scripts/test-all.sh, which installs every package)`;
}

/** The named refusal of a launch whose checkout lacks a service package. */
export class MissingStackPackagesError extends Error {
  constructor(readonly missing: readonly string[], readonly who: string, readonly repoRoot: string) {
    super(`${who}: ${manduPackagesRefusal([...missing])} [checkout ${repoRoot}]`);
    this.name = "MissingStackPackagesError";
  }
}

/** A stub checkout for the preflight's own tests, made in `dir`: `repoRoot`'s
 *  bundle-manifest.json, a package.json per service package, and each
 *  installed (its marker) except those in `missing`. Never the real tree. */
export function writeStubCheckout(dir: string, missing: readonly string[], repoRoot: string): string {
  mkdirSync(join(dir, "launcher"), { recursive: true });
  copyFileSync(join(repoRoot, "launcher", "bundle-manifest.json"), join(dir, "launcher", "bundle-manifest.json"));
  for (const pkg of manduServicePackages(repoRoot)) {
    mkdirSync(join(dir, pkg), { recursive: true });
    writeFileSync(join(dir, pkg, "package.json"), "{}\n");
    if (!missing.includes(pkg)) markInstalled(dir, pkg);
  }
  return dir;
}

/** Mark `pkg` of a stub checkout installed. */
export function markInstalled(dir: string, pkg: string): void {
  const marker = join(dir, pkg, INSTALLED_MARKER);
  mkdirSync(dirname(marker), { recursive: true });
  writeFileSync(marker, "");
}

/** Throw MissingStackPackagesError when a service package of `repoRoot` is
 *  not installed; return quietly when all are. `who` prefixes the message
 *  (the lane that refused). */
export function assertStackPackages(repoRoot: string, who: string, deps: PackageProbeDeps = {}): void {
  const missing = missingManduPackages(repoRoot, deps);
  if (missing.length > 0) throw new MissingStackPackagesError(missing, who, repoRoot);
}
