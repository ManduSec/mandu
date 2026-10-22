/**
 * update-notice — whether a newer Mandu is out, for Settings › About Mandu
 * and, when it fixes security problems, a notice on Home (dashboard.md
 * §4.25 *About Mandu*, *A newer release*; packaging.md §11.5).
 *
 * The dashboard makes NO network request for this. Once a day the
 * launcher's update check stores GitHub's release list in the path table's
 * `update-check` (`<home>/cache/update-check.json`); the dashboard only
 * reads that file, with the launcher's own rules: O_NOFOLLOW, a regular
 * file of this user, closed to group and other writes, under 256 KiB, and
 * well-formed. The install line is built only from a version that parses
 * as semver, and the channel (npm, or the release's install.sh) is the
 * launcher's `updateChannel` rule.
 *
 * The dashboard ships standalone and does not import the launcher package,
 * so the pure parts are mirrored here (as release-version.ts mirrors
 * launcher/src/docs-url.ts); tests/stack/update-notice-parity keeps them
 * equal to launcher/src/update-check.ts.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code; mirrors
 * launcher/src/update-check.ts (`parseVersion`, `compareVersions`,
 * `newerRelease`, `updateChannel`, `installLine`, `cacheFresh`,
 * `readUpdateCache`) and the installed/dev decision of
 * launcher/src/services/layout.ts `Layout.detect`.
 */
import { closeSync, constants as fsc, existsSync, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type Env = Record<string, string | undefined>;

/** The release repository (packaging.md §11.4). */
export const RELEASE_REPO = "ManduSec/mandu";
/** A larger cache file is not Mandu's: a miss. */
export const MAX_CACHE_BYTES = 256 * 1024;
/** Releases kept in the cache. */
export const MAX_RELEASES = 100;
/** The launcher checks at most once a day. */
export const UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
/** A clock this far ahead of a recorded time is tolerated. */
export const CLOCK_SKEW_MS = 5 * 60 * 1000;
const CACHE_VERSION = 1;

// ── versions ─────────────────────────────────────────────────────────────────

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  /** Prerelease identifiers ("beta", 3); empty for a release. */
  pre: Array<string | number>;
}

const SEMVER_RE = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$/;

/** A semver 2.0 version (a leading `v` and build metadata allowed), or null. Pure. */
export function parseVersion(s: string): SemVer | null {
  const m = SEMVER_RE.exec(s.trim());
  if (!m) return null;
  const pre = m[4] === undefined ? [] : m[4].split(".").map((id) => (/^\d+$/.test(id) ? Number(id) : id));
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]), pre };
}

/** Semver precedence: <0, 0, >0. A prerelease sorts before its release;
 *  numeric identifiers numerically, below alphanumeric ones; a shorter
 *  identifier list first when the rest is equal. Pure. */
export function compareVersions(a: SemVer, b: SemVer): number {
  for (const k of ["major", "minor", "patch"] as const) if (a[k] !== b[k]) return a[k] < b[k] ? -1 : 1;
  if (a.pre.length === 0 || b.pre.length === 0) return a.pre.length === b.pre.length ? 0 : a.pre.length === 0 ? 1 : -1;
  for (let i = 0; i < Math.max(a.pre.length, b.pre.length); i++) {
    const x = a.pre[i], y = b.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    if (typeof x === "number" && typeof y === "number") return x < y ? -1 : 1;
    if (typeof x === "number") return -1;
    if (typeof y === "number") return 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

// ── releases ─────────────────────────────────────────────────────────────────

export interface ReleaseInfo {
  /** Without the tag's `v`. */
  version: string;
  security: boolean;
}

export interface UpdateAnswer {
  newest: string;
  /** Some release after the running one, up to the newest, is a security release. */
  security: boolean;
}

/** The newest release `current` should move to, or null when it is up to
 *  date (or its own version is not semver: nothing to compare). A
 *  prerelease is offered only to a prerelease user. Pure. */
export function newerRelease(current: string, releases: readonly ReleaseInfo[]): UpdateAnswer | null {
  const cur = parseVersion(current);
  if (cur === null) return null;
  let newest: { v: SemVer; version: string } | null = null;
  let security = false;
  for (const r of releases) {
    const v = parseVersion(r.version);
    if (v === null || compareVersions(v, cur) <= 0) continue;
    if (v.pre.length > 0 && cur.pre.length === 0) continue;
    if (r.security) security = true;
    if (newest === null || compareVersions(v, newest.v) > 0) newest = { v, version: r.version };
  }
  return newest === null ? null : { newest: newest.version, security };
}

export type UpdateChannel = "npm" | "release";
export type LayoutMode = "installed" | "dev";

/** Keep the update in the current distribution channel: an installed
 *  package the curl installer did not mark came from npm; the installer's
 *  packages and source checkouts keep the release's install.sh. Pure but
 *  for `exists`. */
export function updateChannel(layout: { mode: LayoutMode; pkgRoot: string }, exists: (path: string) => boolean = existsSync): UpdateChannel {
  return layout.mode === "installed" && !exists(resolve(layout.pkgRoot, ".mandu-installer")) ? "npm" : "release";
}

/** How to install `version`: the npm line pinned to it, or its own
 *  release copy of install.sh (packaging.md §11.4). Pure. */
export function installLine(version: string, channel: UpdateChannel = "release"): string {
  if (channel === "npm") return `npm install -g @mandusec/mandu@${version}`;
  return `curl -fsSL https://github.com/${RELEASE_REPO}/releases/download/v${version}/install.sh | sh`;
}

/** The layout this dashboard's code runs in, by the launcher's rule
 *  (`Layout.detect`): MANDU_LAYOUT=installed forces installed, =dev or
 *  MANDU_DEV_REPO the dev form; a module in `dist/` is installed unless it
 *  is a checkout's own build (a `src/run.ts` beside that `dist/`);
 *  anything else (source) is dev. Pure but for `exists`. */
export function layoutOf(moduleUrl: string, env: Env, exists: (p: string) => boolean = existsSync): { mode: LayoutMode; pkgRoot: string } {
  const selfDir = dirname(fileURLToPath(moduleUrl));
  const pkgRoot = resolve(selfDir, "..");
  const forced = env["MANDU_LAYOUT"];
  if (forced === "installed") return { mode: "installed", pkgRoot };
  if (forced === "dev" || env["MANDU_DEV_REPO"]) return { mode: "dev", pkgRoot };
  if (basename(selfDir) === "dist" && !exists(join(selfDir, "..", "src", "run.ts"))) return { mode: "installed", pkgRoot };
  return { mode: "dev", pkgRoot };
}

/** The channel of the package this dashboard runs from. */
export function dashboardChannel(env: Env, exists: (p: string) => boolean = existsSync): UpdateChannel {
  return updateChannel(layoutOf(import.meta.url, env, exists), exists);
}

// ── the cache ────────────────────────────────────────────────────────────────

export interface UpdateCache {
  v: typeof CACHE_VERSION;
  /** When the last check was made (ms since the epoch), successful or not. */
  checkedAt: number;
  /** Whether that check got a release list. */
  ok: boolean;
  /** The last list a check got (kept across a failed check). */
  releases: ReleaseInfo[];
  /** When `releases` was fetched; null when no check ever succeeded. */
  releasesAt: number | null;
}

/** The answer is younger than a day (and not from the future). Pure. */
export function cacheFresh(c: UpdateCache, now: number): boolean {
  return c.checkedAt <= now + CLOCK_SKEW_MS && now - c.checkedAt < UPDATE_CHECK_INTERVAL_MS;
}

function validCache(x: unknown): UpdateCache | null {
  if (typeof x !== "object" || x === null) return null;
  const o = x as Record<string, unknown>;
  if (o["v"] !== CACHE_VERSION || typeof o["checkedAt"] !== "number" || typeof o["ok"] !== "boolean") return null;
  if (!Array.isArray(o["releases"])) return null;
  const releases: ReleaseInfo[] = [];
  for (const r of o["releases"].slice(0, MAX_RELEASES)) {
    if (typeof r !== "object" || r === null) return null;
    const { version, security } = r as Record<string, unknown>;
    if (typeof version !== "string" || parseVersion(version) === null || typeof security !== "boolean") return null;
    releases.push({ version, security });
  }
  const at = o["releasesAt"];
  if (at !== null && typeof at !== "number") return null;
  return { v: CACHE_VERSION, checkedAt: o["checkedAt"], ok: o["ok"], releases, releasesAt: at };
}

/** The cache, or null on any doubt: absent, a link, not a regular file,
 *  not this user's, writable by group or others, too large, unparseable. */
export function readUpdateCache(path: string, uid: number | undefined = process.getuid?.()): UpdateCache | null {
  let fd: number;
  try { fd = openSync(path, fsc.O_RDONLY | fsc.O_NOFOLLOW | fsc.O_NONBLOCK); } catch { return null; }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > MAX_CACHE_BYTES || (st.mode & 0o022) !== 0) return null;
    if (uid !== undefined && st.uid !== uid) return null;
    const buf = Buffer.alloc(st.size);
    let n = 0;
    while (n < st.size) {
      const r = readSync(fd, buf, n, st.size - n, n);
      if (r === 0) break;
      n += r;
    }
    return validCache(JSON.parse(buf.subarray(0, n).toString("utf8")));
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
}

/** The cache as Home's poll reads it: one `lstat` per call, and a read
 *  (readUpdateCache, every check again) only when the file is another one
 *  or changed (its inode, size, mode, owner, mtime or ctime), so a poll
 *  every few seconds costs a stat. Never throws. */
export class UpdateCacheReader {
  private key: string | null = null;
  private last: UpdateCache | null = null;

  constructor(private readonly path: string, private readonly read: (path: string) => UpdateCache | null = readUpdateCache) {}

  get(): UpdateCache | null {
    let key: string;
    try {
      const st = lstatSync(this.path);
      key = [st.dev, st.ino, st.size, st.mode, st.uid, st.mtimeMs, st.ctimeMs].join(":");
    } catch {
      this.key = null;
      this.last = null;
      return null;
    }
    if (key !== this.key) {
      this.last = this.read(this.path);
      this.key = key;
    }
    return this.last;
  }
}
