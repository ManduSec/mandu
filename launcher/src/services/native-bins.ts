/**
 * services/native-bins — resolve a committed Rust bin (exec-supervisor's
 * `mandu-exec-box` / `mandu-landlock-apply`) for the TS launcher to wire
 * (docs/design/integrity/exec-routing.md §7).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code. The bins are built by
 *   `cd interceptors && cargo build -p exec-supervisor --features kernel --bins`
 * and land under interceptors/target/{release,debug}/. This helper does NOT
 * modify them — it only locates the artifact so the launcher can prepend the net
 * wrap / write a box shim, and returns null (→ the caller degrades gracefully)
 * when nothing is built.
 *
 * Resolution order (first EXISTING candidate wins):
 *   1. the per-bin env override (MANDU_EXEC_BOX_BIN / MANDU_LANDLOCK_APPLY);
 *   2. the PREBUILT bin the npm package ships (packaging.md §5, since
 *      2026-09-24): <pkgRoot>/dist/native/<platform>-<arch>/<name>, present
 *      only when running from an installed bundle (this module lives in dist/
 *      then). A checkout running its own launcher/dist (§5.1) is NOT installed:
 *      a copy there would be as old as the last full build and has no `.d`
 *      for the freshness check below, so it keeps resolving target/;
 *      one tarball carries linux-x64 and linux-arm64 side by side and the
 *      running process's own tag picks (packaging.md §11.3);
 *   3. <repoRoot>/interceptors/target/release/<name>;
 *   4. <repoRoot>/interceptors/target/debug/<name>;
 *   5. in a git worktree with neither, the MAIN checkout's bin (release, then
 *      debug), only when its provenance record proves it was built from
 *      exactly this worktree's native sources (native-provenance.ts,
 *      packaging.md §5.2, 2026-10-04): a worktree launch is then confined
 *      instead of gated, so it no longer voids every launch's git-history
 *      caches while it runs (plan 14 §11.2.1). A bin with no record, changed
 *      since, or built from other sources is refused and the hint says why;
 *   6. a plain PATH lookup.
 * repoRoot is the launcher package's parent (Layout.repoRoot in dev). In
 * installed mode the target/ tree is absent; the bundled bin (2) is the path,
 * and it is what makes a stock Ubuntu 24.04 `confined` with no sudo (the
 * whole-agent guard serves the secret twins by descriptor, plan 10 §11.7).
 *
 * FRESHNESS (2026-09-17). A resolved bin can be OLDER than the source it was
 * built from: a fixed `sandbox.rs` plus a never-rebuilt target/debug bin
 * looked healthy at launch and poisoned every boxed command for a whole
 * session (`bwrap: --disable-userns requires --unshare-user` × 191 — the
 * pairing fix had landed twelve days earlier, the bin predated it).
 * `nativeBinStaleness` reads cargo's own dep-info file next to the artifact
 * (`<bin>.d`: `<bin>: <src.rs> <src.rs> …`, every in-tree source the bin was
 * compiled from, in-workspace path deps included) and compares the newest
 * source mtime with the bin's. A bin with no `.d` beside it (an installed /
 * PATH / override copy) cannot be judged and is reported as unknown, never
 * stale. The setups WARN (attention note → printed even in the compact launch
 * display) and proceed: mtime is a heuristic (a checkout touches files), so it
 * names the rebuild rather than refusing the launch.
 *
 * LINUX ONLY (2026-09-29). The bins are Linux kernel guards; no macOS build
 * exists or can be made (`cargo build --features kernel` on a Mac produces
 * nothing the launcher can use). The build hints are platform-aware: off
 * Linux they say "Linux only" and name what macOS uses instead (the Seatbelt
 * read-block profile), never a cargo line (packaging.md §6).
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { docsUrl } from "../docs-url.js";
import { isCheckoutBuild } from "./layout.js";
import { sharedBinRefusal, sharedCheckoutBin, verifiedSharedBin } from "./native-provenance.js";

/** `<platform>-<arch>`, the key under which the installed package keeps its
 *  prebuilt native bins (`dist/native/<tag>/<name>`; build-bundle.mjs). */
export function nativePlatformTag(platform: string = process.platform, arch: string = process.arch): string {
  return `${platform}-${arch}`;
}

/** This module's directory: `launcher/src/services` in a checkout, `<pkgRoot>/dist`
 *  in the installed bundle (every bundle is flat under dist/, layout.ts). */
function selfDir(): string {
  return dirname(fileURLToPath(import.meta.url));
}

/** True when running from the esbuild bundle of the installed
 *  @mandusec/mandu, not from a source checkout's own launcher/dist. */
export function isInstalledLayout(dir: string = selfDir(), exists: (p: string) => boolean = existsSync): boolean {
  return basename(dir) === "dist" && !isCheckoutBuild(dir, exists);
}

/** The source tree's root, from this module's directory: up from
 *  launcher/src/services in a checkout, up from launcher/dist in its build. */
export function defaultRepoRoot(dir: string = selfDir()): string {
  return basename(dir) === "dist" ? resolve(dir, "..", "..") : resolve(dir, "..", "..", "..");
}

/** Where the installed package keeps its prebuilt native bins; null in a checkout. */
export function installedNativeDir(dir: string = selfDir(), tag: string = nativePlatformTag()): string | null {
  return isInstalledLayout(dir) ? join(dir, "native", tag) : null;
}

/** The tags this installed package carries prebuilt bins for (the
 *  directories under `dist/native/`, sorted): `linux-x64` and `linux-arm64`
 *  for a release tarball (launcher/scripts/native-targets.mjs). [] in a
 *  checkout, or when the package was packed with none. */
export function shippedNativeTags(dir: string = selfDir(), list: (p: string) => string[] = (p) => readdirSync(p)): string[] {
  if (!isInstalledLayout(dir)) return [];
  try { return list(join(dir, "native")).sort(); } catch { return []; }
}

function shipsPhrase(what: "them" | "it", tags: string[]): string {
  return tags.length > 0 ? `it ships ${what} for ${tags.join(", ")}` : "it was packed without native bins";
}

export type NativeBinName =
  | "mandu-exec-box"
  | "mandu-landlock-apply"
  | "mandu-net-guard";

/** The env var that overrides each bin's resolved path. */
const ENV_OVERRIDE: Record<NativeBinName, string> = {
  "mandu-exec-box": "MANDU_EXEC_BOX_BIN",
  "mandu-landlock-apply": "MANDU_LANDLOCK_APPLY",
  "mandu-net-guard": "MANDU_NET_GUARD_BIN",
};

/** The crate each bin is built from (they land in the SHARED interceptors/target
 *  tree, so resolution is identical — this only shapes the build hint). */
const BIN_CRATE: Record<NativeBinName, string> = {
  "mandu-exec-box": "exec-supervisor",
  "mandu-landlock-apply": "exec-supervisor",
  "mandu-net-guard": "net-supervisor",
};

/** The one-line build hint the caller surfaces when resolution returns null
 *  (a source checkout). Installed users get `nativeBinBuildHint()` instead. */
export const NATIVE_BIN_BUILD_HINT =
  "build with: cd interceptors && cargo build -p exec-supervisor -p net-supervisor --features kernel --bins";

/** The native bins are Linux kernel guards (bubblewrap, Landlock, seccomp):
 *  there is no macOS (or Windows) build to point at, from npm or from a
 *  checkout, so a cargo hint there is advice that cannot be followed
 *  (packaging.md §6 and §9; the macOS posture is the Seatbelt read-block). */
export function nativeBinsExistFor(platform: string = process.platform): boolean {
  return platform === "linux";
}

/** The hint off Linux: say the guard is Linux only and name what the platform
 *  uses instead. Never a `cargo build` line. */
function linuxOnlyHint(what: string, platform: string): string {
  const instead = platform === "darwin"
    ? "on macOS Mandu blocks programs the AI runs from reading your credential files with a Seatbelt profile (sandbox-exec) instead"
    : `there is no ${platform} build`;
  return `${what} Linux only (a Linux kernel guard); ${instead} (see ${docsUrl("docs/guarantees.md")})`;
}

/** In a git worktree whose main checkout's bins were refused (built from
 *  other sources, or with no provenance record; native-provenance.ts), why,
 *  and the one command that confines this worktree's launches. "" otherwise. */
function sharedRefusalHint(names: readonly NativeBinName[]): string {
  const why = names.map((n) => sharedBinRefusal(n)).filter((w): w is string => w !== null);
  if (why.length === 0) return "";
  return `. The main checkout's bins were not used (${why.join("; ")}): run scripts/build-native.sh in this worktree to launch confined`;
}

/** The hint for the layout the launcher actually runs in: an npm user has no
 *  `interceptors/` to `cargo build` in (os-test-matrix.md §10.11 finding 3),
 *  so the installed form names the package gap instead of a directory they do
 *  not have. Off Linux there is nothing to build: the hint says so. */
export function nativeBinBuildHint(installed: boolean = isInstalledLayout(), tags: string[] = shippedNativeTags(), platform: string = process.platform): string {
  if (!nativeBinsExistFor(platform)) return linuxOnlyHint("the native bins are", platform);
  if (!installed) return NATIVE_BIN_BUILD_HINT + sharedRefusalHint(Object.keys(ENV_OVERRIDE) as NativeBinName[]);
  return `this @mandusec/mandu package has no prebuilt native bins for ${nativePlatformTag(platform)} (${shipsPhrase("them", tags)}); ` +
    `a source checkout builds them (see ${docsUrl("docs/design/distribution/packaging.md")} §5)`;
}

/** A per-bin build hint (names the right crate for that one artifact), in the
 *  form for the running layout (see `nativeBinBuildHint`). */
export function buildHintFor(name: NativeBinName, installed: boolean = isInstalledLayout(), tags: string[] = shippedNativeTags(), platform: string = process.platform): string {
  if (!nativeBinsExistFor(platform)) return linuxOnlyHint(`${name} is`, platform);
  if (installed) {
    return `this @mandusec/mandu package has no prebuilt ${name} for ${nativePlatformTag(platform)} (${shipsPhrase("it", tags)}); ` +
      `a source checkout builds it: cd interceptors && cargo build -p ${BIN_CRATE[name]} --features kernel --bins`;
  }
  return `build with: cd interceptors && cargo build -p ${BIN_CRATE[name]} --features kernel --bins${sharedRefusalHint([name])}`;
}

export interface ResolveNativeBinDeps {
  env?: Record<string, string | undefined>;
  /** Source-tree root (Layout.repoRoot). Defaults to the launcher package's
   *  parent, derived from this module's location. */
  repoRoot?: string;
  /** Existence probe (injectable for tests). */
  exists?: (p: string) => boolean;
  /** The installed package's native dir (`dist/native/<tag>`), or null in a
   *  checkout. Defaults to `installedNativeDir()`; a test passes a fixture. */
  installedDir?: string | null;
  /** false: never use another checkout's bin (tests of the other steps). */
  shared?: boolean;
  /** The shared-checkout step (default: native-provenance.ts sharedCheckoutBin). */
  sharedBin?: (name: NativeBinName, repoRoot: string) => string | null;
}

/** Resolve a committed Rust bin, or null when no candidate exists. */
export function resolveNativeBin(name: NativeBinName, deps: ResolveNativeBinDeps = {}): string | null {
  const env = deps.env ?? process.env;
  const exists = deps.exists ?? existsSync;
  const repoRoot = deps.repoRoot ?? defaultRepoRoot();

  const candidates: string[] = [];
  const override = env[ENV_OVERRIDE[name]];
  if (override) candidates.push(override);
  const installed = deps.installedDir === undefined ? installedNativeDir() : deps.installedDir;
  if (installed) candidates.push(join(installed, name));
  candidates.push(join(repoRoot, "interceptors", "target", "release", name));
  candidates.push(join(repoRoot, "interceptors", "target", "debug", name));
  const own = candidates.find((c) => exists(c));
  if (own !== undefined) return own;
  // A git worktree with no bins of its own: the main checkout's, only when
  // built from exactly this worktree's native sources (native-provenance.ts,
  // packaging.md §5.2). Never in an installed package.
  if (!installed && deps.shared !== false) {
    const shared = (deps.sharedBin ?? sharedCheckoutBin)(name, repoRoot);
    if (shared !== null) return shared;
  }
  for (const dir of (env["PATH"] ?? "").split(":").filter(Boolean)) {
    const c = join(dir, name);
    if (exists(c)) return c;
  }
  return null;
}

/** What `nativeBinStaleness` learned about a resolved bin. */
export interface NativeBinStaleness {
  /** The bin's mtime (ms since epoch). */
  binMtimeMs: number;
  /** The newest source the bin was built from (absolute path). */
  newestSource: string;
  /** That source's mtime (ms since epoch). */
  newestSourceMtimeMs: number;
  /** Number of dep-info sources that still exist and were compared. */
  sources: number;
}

export interface NativeBinStalenessDeps {
  /** File reader for the `.d` dep-info (injectable for tests). */
  readFile?: (p: string) => string;
  /** mtime probe in ms, or null when the path is absent (injectable). */
  mtimeMs?: (p: string) => number | null;
}

/** cargo dep-info: `<target>: <dep> <dep> …` on one line, a space inside a
 *  path escaped as `\ `. Returns the dep paths; [] when unparseable. */
export function parseDepInfoSources(text: string): string[] {
  const line = text.split("\n").find((l) => l.includes(": ")) ?? text;
  const idx = line.indexOf(": ");
  if (idx < 0) return [];
  const rest = line.slice(idx + 2).trim();
  if (!rest) return [];
  // Split on UNESCAPED spaces, then unescape.
  return rest
    .split(/(?<!\\) /)
    .map((t) => t.replace(/\\ /g, " ").trim())
    .filter(Boolean);
}

const defaultMtimeMs = (p: string): number | null => {
  try { return statSync(p).mtimeMs; } catch { return null; }
};

/**
 * Is `binPath` older than a source it was compiled from? Returns the
 * comparison when the bin IS stale, `null` when it is fresh OR cannot be
 * judged (no readable `.d` beside it, no surviving sources). Never throws.
 */
export function nativeBinStaleness(binPath: string, deps: NativeBinStalenessDeps = {}): NativeBinStaleness | null {
  const readFile = deps.readFile ?? ((p: string) => readFileSync(p, "utf8"));
  const mtimeMs = deps.mtimeMs ?? defaultMtimeMs;
  let text: string;
  try { text = readFile(`${binPath}.d`); } catch { return null; }
  const binMtimeMs = mtimeMs(binPath);
  if (binMtimeMs === null) return null;
  let newestSource: string | null = null;
  let newestSourceMtimeMs = -Infinity;
  let sources = 0;
  for (const src of parseDepInfoSources(text)) {
    const m = mtimeMs(src);
    if (m === null) continue; // a moved/deleted source cannot date the bin
    sources += 1;
    if (m > newestSourceMtimeMs) { newestSourceMtimeMs = m; newestSource = src; }
  }
  if (newestSource === null || newestSourceMtimeMs <= binMtimeMs) return null;
  return { binMtimeMs, newestSource, newestSourceMtimeMs, sources };
}

/** The WARNING line a setup logs for a stale bin (null when fresh/unknown). */
export function staleNativeBinNote(name: NativeBinName, binPath: string, deps: NativeBinStalenessDeps = {}): string | null {
  // Another checkout's bin was verified source by source against this
  // checkout (native-provenance.ts): its own sources' mtimes say nothing here.
  if (verifiedSharedBin(binPath)) return null;
  const s = nativeBinStaleness(binPath, deps);
  if (!s) return null;
  const when = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
  // The REBUILD line, on every platform: a staleness verdict needs cargo's
  // dep-info beside the bin, so this bin was built by cargo from this tree,
  // and the command that made it is the one that refreshes it (unlike
  // buildHintFor, which answers "nothing resolved" and is Linux only).
  return (
    `mandu: WARNING — ${name} at ${binPath} is STALE: built ${when(s.binMtimeMs)}, ` +
    `but ${s.newestSource} changed ${when(s.newestSourceMtimeMs)}; the launch uses the OLD bin ` +
    `(a fixed source is not in effect until rebuilt). build with: cd interceptors && cargo build -p ${BIN_CRATE[name]} --features kernel --bins`
  );
}
