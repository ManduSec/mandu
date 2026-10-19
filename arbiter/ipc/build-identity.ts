/**
 * build-identity — WHICH build of a Mandu release this arbiter's code is, for
 * the `hello` handshake (runtime-instances.md §4.1).
 *
 * `version` (release-version.ts) orders two releases; it cannot tell two
 * commits of one version apart (the S8 miss, reply-row-reservation.md §18).
 * The build identity says "same code or not", from what the code already
 * carries, with no network and no git at run time for an install:
 *
 *   - `bundle`: when the arbiter runs from a bundle (`dist/arbiter.mjs`, an
 *     install or a checkout's own build), the first 16 hex digits of the
 *     SHA-256 of that file, read once when the process starts (a rebuild that
 *     renames a new file over it later does not change what this process
 *     loaded). esbuild's output is a function of its inputs, so two builds
 *     of the same arbiter code hash alike, whatever else the commit changed.
 *   - `rev`: the short git rev of the checkout the code was loaded from
 *     (server-main's gitRevOf, the instance id's rev), reported only from
 *     source or from a checkout's own build (`dist/` beside `../src/run.ts`).
 *     An installed bundle reports none: the directory that holds the package
 *     can sit inside an unrelated work tree (a Homebrew prefix), whose rev
 *     says nothing about this code.
 *
 * Either may be null; both null = no evidence (an embedded test server).
 * The launcher and the dashboard supervisor compare it with the build they
 * would start themselves (launcher/src/arbiter-version.ts `buildVerdict`).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** The build identity `hello` reports (HelloResult.build). */
export interface BuildIdentity {
  /** SHA-256 prefix (16 hex) of the bundle file this process runs, or null from source. */
  bundle: string | null;
  /** Short git rev of the checkout this code came from, or null (an install, no git). */
  rev: string | null;
}

/** The hash prefix a build identity carries (both sides compute it alike). */
export function bundleDigest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex").slice(0, 16);
}

/** Is `distDir` a checkout's own build (`launcher/dist` beside `launcher/src`)?
 *  Mirrors launcher/src/services/layout.ts isCheckoutBuild. */
export function isCheckoutBuildDir(distDir: string, exists: (p: string) => boolean = existsSync): boolean {
  return basename(distDir) === "dist" && exists(join(distDir, "..", "src", "run.ts"));
}

/** The build identity of code loaded from `modulePath` at checkout rev
 *  `gitRev` ("nogit" = none). Pure but for the one read of a bundle. */
export function buildIdentityOf(
  modulePath: string,
  gitRev: string,
  deps: { readFile?: (p: string) => Uint8Array; exists?: (p: string) => boolean } = {},
): BuildIdentity {
  const rev = gitRev && gitRev !== "nogit" ? gitRev : null;
  if (modulePath.endsWith(".ts")) return { bundle: null, rev };
  let bundle: string | null = null;
  try {
    bundle = bundleDigest((deps.readFile ?? readFileSync)(modulePath));
  } catch {
    bundle = null;
  }
  return { bundle, rev: isCheckoutBuildDir(dirname(modulePath), deps.exists) ? rev : null };
}

let own: { bundle: string | null; revApplies: boolean } | undefined;

/** This process's own build, at checkout rev `gitRev`. The bundle is hashed
 *  on the first call (server-main makes it at start-up) and cached. */
export function arbiterBuild(gitRev: string): BuildIdentity {
  if (own === undefined) {
    const self = fileURLToPath(import.meta.url);
    const fromSource = self.endsWith(".ts");
    own = {
      bundle: fromSource ? null : buildIdentityOf(self, "nogit").bundle,
      revApplies: fromSource || isCheckoutBuildDir(dirname(self)),
    };
  }
  return { bundle: own.bundle, rev: own.revApplies && gitRev && gitRev !== "nogit" ? gitRev : null };
}
