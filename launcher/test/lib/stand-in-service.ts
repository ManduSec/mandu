/**
 * stand-in-service — a fake service package where the dev layout runs it
 * (services/layout.ts, packaging.md §5.1): `node --import <pkg>/node_modules/
 * tsx/dist/esm/index.mjs <repo>/<entry.ts>`. A test that points MANDU_DEV_REPO
 * at a throwaway repo writes its misbehaving proxy, arbiter or dashboard here.
 *
 * `body` is plain JavaScript (valid TypeScript) in an ES module package; the
 * package-local tsx is a link to this launcher's own, so the real loader runs.
 */
import { copyFileSync, existsSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ASSET_SOURCES, SERVICE_SOURCES, type ServiceName } from "../../src/services/layout.js";

const LAUNCHER_TSX = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "node_modules", "tsx");
const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

/** The assets every claude or shell launch needs where a `claude` is on PATH
 *  (the `claude` shim: the SDK route's preload and its permission-mode rule,
 *  agent-sdks.md §3.5), copied from this checkout into a throwaway repo. A
 *  real install always ships them; without them the launch refuses (fail
 *  closed: the session's own `claude` would run unrouted). */
export const CLAUDE_SHIM_ASSETS = ["sdk-route-preload.cjs", "claude-permission-rule.cjs"] as const;

/** Copy CLAUDE_SHIM_ASSETS into `repo` where the dev layout reads them. */
export function withClaudeShimAssets(repo: string): void {
  for (const key of CLAUDE_SHIM_ASSETS) {
    const rel = ASSET_SOURCES[key]!;
    mkdirSync(dirname(join(repo, rel)), { recursive: true });
    copyFileSync(join(REPO, rel), join(repo, rel));
  }
}

/** Write `<repo>/<pkgSubdir>` as a stand-in for service `name`; returns the
 *  entry path. */
export function standInService(repo: string, name: ServiceName, pkgSubdir: string, body: string): string {
  const pkg = join(repo, pkgSubdir);
  const entry = join(repo, SERVICE_SOURCES[name]);
  mkdirSync(dirname(entry), { recursive: true });
  writeFileSync(join(pkg, "package.json"), JSON.stringify({ name: `stand-in-${name}`, private: true, type: "module" }));
  writeFileSync(entry, body);
  mkdirSync(join(pkg, "node_modules"), { recursive: true });
  if (!existsSync(join(pkg, "node_modules", "tsx"))) symlinkSync(LAUNCHER_TSX, join(pkg, "node_modules", "tsx"));
  withClaudeShimAssets(repo);
  return entry;
}
