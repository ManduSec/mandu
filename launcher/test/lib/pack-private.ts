/**
 * pack-private — `npm pack` the launcher package WITHOUT touching the shared
 * launcher/dist. A plain `npm pack` in launcher/ runs prepack, which wipes and
 * rebuilds launcher/dist; two test files doing that at once (npm-pack and
 * install-sh run in parallel under `npm test`) raced, and one packed a dist the
 * other was half-way through rebuilding. Here the packable files are staged in
 * a private dir, prepack's own build runs into the stage (build-bundle.mjs
 * --outdir, the same pattern bundle-smoke and installed-spawn use), and the
 * stage is packed with --ignore-scripts. The tarball is what `npm pack` in
 * launcher/ would produce: same package.json (so the same `files` filter), same
 * build command. The pack runs with npm's cache inside `tmp` (npmEnv).
 */
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** The prepack this helper reproduces. A change to prepack must change this helper too. */
export const PREPACK = "node scripts/build-bundle.mjs";

/** The npm cache a test under `tmp` uses: `tmp/npm-cache`, removed with `tmp`. */
export function npmCacheDir(tmp: string): string {
  return join(tmp, "npm-cache");
}

/** The env for an npm child of a test under `tmp`: npm's cache (and its
 *  `_logs`, which live in the cache) point into `tmp`, never the real
 *  `~/.npm`, so parallel suites neither share nor litter it
 *  (test-organization.md §8.4). */
export function npmEnv(tmp: string, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return { ...process.env, npm_config_cache: npmCacheDir(tmp), ...extra };
}

/** Pack the package into `tmp` (stage under `tmp/stage`); returns the tarball path. */
export function packPrivate(tmp: string): string {
  const pkg = JSON.parse(readFileSync(join(PKG_ROOT, "package.json"), "utf8")) as { files?: string[]; scripts?: Record<string, string> };
  if (pkg.scripts?.prepack !== PREPACK) {
    throw new Error(`launcher prepack is now '${pkg.scripts?.prepack}', pack-private reproduces '${PREPACK}': update test/lib/pack-private.ts`);
  }

  // What npm would ship, minus dist/: package.json, the files npm always adds,
  // and every `files` entry but dist/. Nothing here reads launcher/dist (an
  // `npm pack --dry-run` listing would walk it, and a concurrent rebuild can
  // delete a file mid-walk). The pack below applies npm's own filter to the
  // stage, so a copied file that npm would not ship is dropped there.
  const stage = join(tmp, "stage");
  mkdirSync(stage, { recursive: true });
  const always = readdirSync(PKG_ROOT).filter((n) => /^(package\.json|(readme|licen[cs]e|notice|changelog)(\..*)?)$/i.test(n));
  // A `!pattern` entry is a filter npm applies at pack time, not a file to copy.
  const entries = (pkg.files ?? []).map((f) => f.replace(/\/+$/, ""))
    .filter((f) => f !== "dist" && !f.startsWith("dist/") && !f.startsWith("!"));
  for (const rel of [...always, ...entries]) {
    cpSync(join(PKG_ROOT, rel), join(stage, rel), { recursive: true });
  }

  // prepack's build, into the stage's dist.
  const build = spawnSync("node", [join(PKG_ROOT, "scripts", "build-bundle.mjs"), `--outdir=${join(stage, "dist")}`], {
    cwd: PKG_ROOT, encoding: "utf8", timeout: 180_000,
  });
  if (build.status !== 0) throw new Error(`build-bundle failed:\n${build.stdout}\n${build.stderr}`);

  const r = spawnSync("npm", ["pack", "--silent", "--ignore-scripts", "--pack-destination", tmp], {
    cwd: stage, encoding: "utf8", timeout: 180_000, env: npmEnv(tmp),
  });
  if (r.status !== 0) throw new Error(`npm pack failed:\n${r.stdout}\n${r.stderr}`);
  const tarball = join(tmp, r.stdout.trim().split("\n").pop()!.trim());
  if (!existsSync(tarball)) throw new Error(`tarball not found at ${tarball} (npm pack said: ${r.stdout.trim()})`);
  return tarball;
}
