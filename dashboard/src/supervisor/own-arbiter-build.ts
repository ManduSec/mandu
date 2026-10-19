/**
 * own-arbiter-build — the release and arbiter build this dashboard would
 * start, for the STALE flag on an adopted arbiter (supervisor-defs.ts
 * arbiterReleaseStaleness; runtime-instances.md §4, §4.1).
 *
 *   - version: the package.json one level above this module (from source,
 *     `dashboard/package.json`; in the bundle, the package root beside
 *     `dist/`). One version for the product (packaging.md §11.2).
 *   - bundle: the first 16 hex digits of the SHA-256 of the arbiter bundle
 *     this dashboard spawns (installed: `<pkg>/dist/arbiter.mjs`; a checkout:
 *     its `launcher/dist/arbiter.mjs`), the same digest the arbiter reports
 *     for itself (arbiter/ipc/build-identity.ts). Cached by size and mtime,
 *     so a status poll re-hashes only after a rebuild.
 *
 * Standalone (no arbiter import), like the rest of this package.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { OwnArbiterBuild } from "./supervisor-defs.js";

let versionCache: string | null | undefined;

/** This dashboard's release, or null when its package.json cannot be read. */
export function dashboardVersion(): string | null {
  if (versionCache !== undefined) return versionCache;
  try {
    // src/supervisor/ (source) is two levels below the package; dist/ (the
    // bundle) one. Try the bundle's shape first, then the source's.
    const here = dirname(fileURLToPath(import.meta.url));
    const candidates = [resolve(here, "..", "package.json"), resolve(here, "..", "..", "package.json")];
    versionCache = null;
    for (const c of candidates) {
      try {
        const v = (JSON.parse(readFileSync(c, "utf8")) as { version?: unknown }).version;
        if (typeof v === "string" && v.trim() !== "") { versionCache = v.trim(); break; }
      } catch { /* next */ }
    }
  } catch {
    versionCache = null;
  }
  return versionCache;
}

const hashCache = new Map<string, { key: string; digest: string }>();

/** The digest of the bundle at `path` (cached by size + mtime), or null. */
export function bundleDigestOf(path: string): string | null {
  try {
    const st = statSync(path);
    const key = `${st.size}:${st.mtimeMs}`;
    const hit = hashCache.get(path);
    if (hit && hit.key === key) return hit.digest;
    const digest = createHash("sha256").update(readFileSync(path)).digest("hex").slice(0, 16);
    hashCache.set(path, { key, digest });
    return digest;
  } catch {
    return null;
  }
}

/** What the supervisor with these options would start for the arbiter. */
export function ownArbiterBuildOf(o: { repoRoot: string; layout?: { mode: "installed"; pkgRoot: string }; checkoutDist?: string }): OwnArbiterBuild {
  const installed = o.layout?.mode === "installed";
  const dist = installed ? join(o.layout!.pkgRoot, "dist") : (o.checkoutDist ?? join(o.repoRoot, "launcher", "dist"));
  return { version: dashboardVersion(), bundle: bundleDigestOf(join(dist, "arbiter.mjs")), installed };
}
