/**
 * update-check — the "a newer Mandu is out" notice (packaging.md §11.5).
 *
 * WHY. Mandu ships security releases (0.2.0-beta.3 fixed real leaks), and a
 * user on an old build learned of a new one only from us. A launch now says
 * so in one line, and `mandu doctor` reports it.
 *
 * THE RULES:
 *   - NEVER IN THE WAY. A launch prints the answer the PREVIOUS check left
 *     in the cache (no network wait), and when that answer is older than a
 *     day it asks again in the background (one request, a 5 s budget, its
 *     socket unref'd so it never holds the process). Any failure (offline,
 *     a 404 while the repository is private, a rate limit, a bad body) is
 *     silent: the attempt is recorded so the next one waits a day too, and
 *     the last good list of releases is kept.
 *   - WHAT IS SENT: one HTTPS GET to api.github.com for the repository's
 *     release list, with `Accept` and a fixed `User-Agent` (no version, no
 *     session, no machine or user identifier, no cookie, no token). It is
 *     made by the launcher, outside the agent's confinement, on its own
 *     fresh agent (no proxy from the environment), so it neither goes
 *     through nor opens any egress path of the session. Redirects are not
 *     followed.
 *   - WHO IS TOLD WHAT. Semver precedence, prereleases included
 *     (0.2.0-beta.3 < 0.2.0-beta.4 < 0.2.0). A prerelease user hears of the
 *     next prerelease and of the release; a release user hears of releases
 *     only. "SECURITY" when any release between the running version and the
 *     newest carries the marker SECURITY_MARKER in its notes.
 *   - WHEN. `MANDU_UPDATE_CHECK=0` (config `update-check = false`) turns it
 *     off; `=1` turns it on wherever it runs. Unset, it runs only for an
 *     installed package (not a source checkout), outside CI, at a terminal
 *     (stderr for a launch, stdout for doctor).
 *   - THE CACHE is the path table's `update-check`
 *     (`<home>/cache/update-check.json`), inside the Mandu home the agent
 *     can neither read nor write in every mode but `off` (on-disk-layout.md
 *     §4). Read through O_NOFOLLOW, refused unless a regular file of this
 *     user, closed to group and other writes, under 256 KiB; written by
 *     safe-file's rename. A `checkedAt` in the future counts as stale, so a
 *     forged entry silences the notice for at most a day; `mandu doctor`
 *     always asks afresh. The residual is in packaging.md §11.5. The
 *     dashboard reads the same file for Settings › About Mandu through a
 *     mirror of the pure parts and this reader
 *     (dashboard/src/update-notice.ts); tests/stack/update-notice-parity
 *     keeps the two equal, so change both together.
 *
 * Mandu-new (no reference origin).
 */
import { existsSync, closeSync, constants as fsc, fstatSync, mkdirSync, openSync, readFileSync, readSync } from "node:fs";
import { request as httpRequest, Agent as HttpAgent } from "node:http";
import { request as httpsRequest, Agent as HttpsAgent } from "node:https";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { manduPath } from "./generated/mandu-paths.js";
import { publishFile } from "./safe-file.js";
import type { Layout } from "./services/layout.js";

type Env = Record<string, string | undefined>;

/** The release repository (packaging.md §11.4). */
export const RELEASE_REPO = "ManduSec/mandu";
/** The one request: the newest releases, prereleases and their notes included. */
export const RELEASES_URL = `https://api.github.com/repos/${RELEASE_REPO}/releases?per_page=30`;
export const UPDATE_CHECK_ENV = "MANDU_UPDATE_CHECK";
/** Tests point the check at a local server: any https URL, or http on a
 *  loopback address only. Anything else falls back to RELEASES_URL. */
export const UPDATE_CHECK_URL_ENV = "MANDU_UPDATE_CHECK_URL";
/** At most one check a day. */
export const UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
/** A launch's background request gives up after this. */
export const LAUNCH_FETCH_TIMEOUT_MS = 5_000;
/** `mandu doctor` waits this long for a fresh answer. */
export const DOCTOR_FETCH_TIMEOUT_MS = 4_000;
/** A larger response is not a release list: a failure. */
export const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
/** A larger cache file is not Mandu's: a miss. */
export const MAX_CACHE_BYTES = 256 * 1024;
/** Releases kept in the cache. */
export const MAX_RELEASES = 100;
/** A clock this far ahead of `checkedAt` is tolerated. */
const CLOCK_SKEW_MS = 5 * 60 * 1000;
/** The fixed request headers: nothing about the user, the machine or the session. */
export const REQUEST_HEADERS: Readonly<Record<string, string>> = {
  "Accept": "application/vnd.github+json",
  "User-Agent": "mandu-update-check",
};
/** The line a release's notes carry when it fixes a security problem
 *  (private release notes checklist; invisible on the rendered page). */
export const SECURITY_MARKER = "<!-- mandu: security-release -->";
const SECURITY_RE = /<!--\s*mandu:\s*security-release\s*-->/i;
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

/** The releases in a GitHub release-list body: drafts and tags that are not
 *  `v<semver>` dropped. Null when the body is not a list. Pure. */
export function parseReleases(body: unknown): ReleaseInfo[] | null {
  if (!Array.isArray(body)) return null;
  const out: ReleaseInfo[] = [];
  for (const r of body) {
    if (out.length >= MAX_RELEASES) break;
    if (typeof r !== "object" || r === null) continue;
    const o = r as Record<string, unknown>;
    if (o["draft"] === true || typeof o["tag_name"] !== "string") continue;
    const tag = o["tag_name"];
    if (!tag.startsWith("v") || parseVersion(tag) === null) continue;
    out.push({ version: tag.slice(1), security: typeof o["body"] === "string" && SECURITY_RE.test(o["body"]) });
  }
  return out;
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

/** Keep the update in the current distribution channel. The curl installer
 * marks its package; unmarked installed packages come from npm. Source
 * checkouts retain the release installer advice when checks are opted in. */
export function updateChannel(layout: Pick<Layout, "mode" | "pkgRoot">, exists: (path: string) => boolean = existsSync): UpdateChannel {
  return layout.mode === "installed" && !exists(resolve(layout.pkgRoot, ".mandu-installer")) ? "npm" : "release";
}

/** How to install `version`: its own release copy of install.sh, which
 *  installs exactly that release's tarball after checking its SHA-256
 *  (packaging.md §11.4). Pure. */
export function installLine(version: string, channel: UpdateChannel = "release"): string {
  if (channel === "npm") return `npm install -g @mandusec/mandu@${version}`;
  return `curl -fsSL https://github.com/${RELEASE_REPO}/releases/download/v${version}/install.sh | sh`;
}

/** The launch's one notice line (launch-banner.ts passes it through as is). Pure. */
export function updateNotice(current: string, a: UpdateAnswer, channel: UpdateChannel = "release"): string {
  return a.security
    ? `mandu: ! Mandu ${a.newest} is out with SECURITY fixes (you have ${current}); update now: ${installLine(a.newest, channel)}`
    : `mandu: ! Mandu ${a.newest} is out (you have ${current}); to update: ${installLine(a.newest, channel)}`;
}

/** Does `note` come from updateNotice? (launch-banner.ts compactNotice) */
export function isUpdateNotice(note: string): boolean {
  return /^mandu: ! Mandu \S+ is out (with SECURITY fixes )?\(you have /.test(note);
}

// ── when ─────────────────────────────────────────────────────────────────────

export type UpdateCheckGate = { on: true } | { on: false; why: string; optedOut: boolean };

const OFF = new Set(["0", "false", "off", "no"]);

/** Does this run look like CI: `CI` set to anything but an off word (GitLab,
 *  GitHub Actions and most runners export CI=true). The launcher's one CI
 *  test: the update check and the egress hold's default (egress-hold.ts)
 *  both ask it. Pure. */
export function runsInCi(env: Env): boolean {
  const ci = (env["CI"] ?? "").trim().toLowerCase();
  return ci !== "" && !OFF.has(ci);
}

/** Whether to check. `installed`: the launcher runs from an installed
 *  package (Layout mode `installed`); `interactive`: the stream the answer
 *  goes to is a terminal. Pure. */
export function updateCheckGate(env: Env, ctx: { installed: boolean; interactive: boolean }): UpdateCheckGate {
  const v = (env[UPDATE_CHECK_ENV] ?? "").trim().toLowerCase();
  if (OFF.has(v)) return { on: false, why: `turned off (${UPDATE_CHECK_ENV}=0)`, optedOut: true };
  if (v !== "") return { on: true };
  if (runsInCi(env)) return { on: false, why: "not checked in CI", optedOut: false };
  if (!ctx.installed) return { on: false, why: `not checked from a source checkout (${UPDATE_CHECK_ENV}=1 checks)`, optedOut: false };
  if (!ctx.interactive) return { on: false, why: `not checked when the output is not a terminal (${UPDATE_CHECK_ENV}=1 checks)`, optedOut: false };
  return { on: true };
}

/** The URL to ask: RELEASES_URL, or a test's MANDU_UPDATE_CHECK_URL when it
 *  is https, or http on a loopback address. Pure. */
export function releasesUrl(env: Env): string {
  const raw = env[UPDATE_CHECK_URL_ENV];
  if (!raw) return RELEASES_URL;
  try {
    const u = new URL(raw);
    if (u.protocol === "https:") return u.href;
    if (u.protocol === "http:" && ["127.0.0.1", "[::1]", "localhost"].includes(u.hostname)) return u.href;
  } catch { /* not a URL */ }
  return RELEASES_URL;
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

/** `<home>/cache/update-check.json` (the path table's `update-check`). */
export function updateCachePath(env: Env): string {
  return manduPath("update-check", env, env["HOME"] || homedir());
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

/** Write the cache (its directory made 0700 if missing); false on any failure. */
export function writeUpdateCache(path: string, c: UpdateCache): boolean {
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    publishFile(path, JSON.stringify(c) + "\n", { mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}

// ── the request ──────────────────────────────────────────────────────────────

/** GET `url`: the body on a 200, null on anything else. Never throws.
 *  `background`: the request must not keep the process alive. */
export type FetchReleases = (url: string, timeoutMs: number, background: boolean) => Promise<string | null>;

/** The real GET: node's own client on a fresh agent (no proxy from the
 *  environment, no keep-alive), the fixed headers only, no redirect
 *  followed, the body capped, the whole exchange cut at `timeoutMs`; in the
 *  background the socket and the timer are unref'd, so a pending check
 *  never keeps the launcher alive (doctor, which awaits it, keeps them). */
export const realFetchReleases: FetchReleases = (url, timeoutMs, background) => new Promise((done) => {
  let settled = false;
  let req: ReturnType<typeof httpsRequest> | undefined;
  const timer = setTimeout(() => { req?.destroy(); finish(null); }, timeoutMs);
  if (background) timer.unref();
  const finish = (v: string | null): void => { if (!settled) { settled = true; clearTimeout(timer); done(v); } };
  try {
    const u = new URL(url);
    const https = u.protocol === "https:";
    const make = https ? httpsRequest : httpRequest;
    req = make(u, {
      method: "GET",
      headers: { ...REQUEST_HEADERS },
      agent: https ? new HttpsAgent({ keepAlive: false }) : new HttpAgent({ keepAlive: false }),
    }, (res) => {
      if (res.statusCode !== 200) { res.resume(); finish(null); return; }
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (c: Buffer) => {
        size += c.length;
        if (size > MAX_RESPONSE_BYTES) { req?.destroy(); finish(null); return; }
        chunks.push(c);
      });
      res.on("end", () => finish(Buffer.concat(chunks).toString("utf8")));
      res.on("error", () => finish(null));
    });
    if (background) req.on("socket", (s) => s.unref());
    req.on("error", () => finish(null));
    req.end();
  } catch {
    finish(null);
  }
});

export interface UpdateCheckDeps {
  fetch: FetchReleases;
  now: () => number;
  read: (path: string) => UpdateCache | null;
  write: (path: string, c: UpdateCache) => boolean;
}

export const realUpdateCheckDeps: UpdateCheckDeps = {
  fetch: realFetchReleases,
  now: () => Date.now(),
  read: (p) => readUpdateCache(p),
  write: writeUpdateCache,
};

/** Ask once and record the outcome. A failure keeps the previous list and
 *  still stamps `checkedAt`, so the next attempt waits a day too. Returns
 *  the new cache entry. Never throws. */
export async function refreshUpdateCache(
  env: Env, timeoutMs: number, deps: UpdateCheckDeps = realUpdateCheckDeps, previous: UpdateCache | null = null,
  background = false,
): Promise<UpdateCache> {
  const now = deps.now();
  let releases: ReleaseInfo[] | null = null;
  try {
    const body = await deps.fetch(releasesUrl(env), timeoutMs, background);
    if (body !== null) releases = parseReleases(JSON.parse(body));
  } catch { releases = null; }
  const entry: UpdateCache = releases !== null
    ? { v: CACHE_VERSION, checkedAt: now, ok: true, releases, releasesAt: now }
    : { v: CACHE_VERSION, checkedAt: now, ok: false, releases: previous?.releases ?? [], releasesAt: previous?.releasesAt ?? null };
  try { deps.write(updateCachePath(env), entry); } catch { /* best effort */ }
  return entry;
}

// ── the launch ───────────────────────────────────────────────────────────────

export interface LaunchUpdateCheck {
  /** The notice line from the previous check's answer, or null. */
  notice: string | null;
  /** The background refresh, when one was started (tests await it; the
   *  launch does not). Never rejects. */
  refresh: Promise<void> | null;
}

/** A launch's update check: the notice from the cache, and a background
 *  refresh when the cache is older than a day. Never throws, never waits. */
export function launchUpdateCheck(
  opts: { env: Env; version: string; installed: boolean; interactive: boolean; channel?: UpdateChannel },
  deps: UpdateCheckDeps = realUpdateCheckDeps,
): LaunchUpdateCheck {
  try {
    if (!updateCheckGate(opts.env, opts).on) return { notice: null, refresh: null };
    const cache = deps.read(updateCachePath(opts.env));
    const answer = cache !== null && cache.releasesAt !== null ? newerRelease(opts.version, cache.releases) : null;
    const notice = answer === null ? null : updateNotice(opts.version, answer, opts.channel);
    const refresh = cache !== null && cacheFresh(cache, deps.now())
      ? null
      : refreshUpdateCache(opts.env, LAUNCH_FETCH_TIMEOUT_MS, deps, cache, true).then(() => undefined, () => undefined);
    return { notice, refresh };
  } catch {
    return { notice: null, refresh: null };
  }
}

// ── mandu doctor ─────────────────────────────────────────────────────────────

export type UpdateFacts =
  | { version: string; state: "off"; why: string }
  | { version: string; state: "current"; fresh: boolean; at: number }
  | { version: string; state: "newer"; fresh: boolean; at: number; answer: UpdateAnswer; channel?: UpdateChannel }
  | { version: string; state: "unknown" };

/** Doctor's answer: always a fresh check (so a forged cache cannot hide a
 *  release from it), falling back to the cached list when the check fails.
 *  `interactive`: doctor's stdout is a terminal. */
export async function doctorUpdateFacts(
  opts: { env: Env; version: string; installed: boolean; interactive: boolean; channel?: UpdateChannel },
  deps: UpdateCheckDeps = realUpdateCheckDeps,
): Promise<UpdateFacts> {
  const { version } = opts;
  const gate = updateCheckGate(opts.env, opts);
  if (!gate.on) return { version, state: "off", why: gate.why };
  const previous = deps.read(updateCachePath(opts.env));
  const entry = await refreshUpdateCache(opts.env, DOCTOR_FETCH_TIMEOUT_MS, deps, previous);
  if (entry.releasesAt === null) return { version, state: "unknown" };
  const fresh = entry.ok;
  const answer = newerRelease(version, entry.releases);
  return answer === null
    ? { version, state: "current", fresh, at: entry.releasesAt }
    : { version, state: "newer", fresh, at: entry.releasesAt, answer, channel: opts.channel };
}

/** Doctor's rows for the facts (glyphs as doctor.ts draws them). Pure. */
export function updateRows(f: UpdateFacts, glyph: { ok: string; no: string; dot: string }): string[] {
  const when = (at: number): string => new Date(at).toISOString().slice(0, 10);
  const stale = (fresh: boolean, at: number): string => (fresh ? "" : ` (GitHub did not answer now; as of ${when(at)})`);
  switch (f.state) {
    case "off": return [`  ${glyph.dot} newer release: ${f.why}`];
    case "unknown": return [`  ${glyph.dot} newer release: could not ask GitHub (offline, or the release list is not public yet)`];
    case "current": return [`  ${glyph.ok} Mandu ${f.version} is the newest release${stale(f.fresh, f.at)}`];
    case "newer": return f.answer.security
      ? [`  ${glyph.no} Mandu ${f.answer.newest} is out with SECURITY fixes (you have ${f.version})${stale(f.fresh, f.at)}; update now: ${installLine(f.answer.newest, f.channel)}`]
      : [`  ${glyph.dot} Mandu ${f.answer.newest} is out (you have ${f.version})${stale(f.fresh, f.at)}; to update: ${installLine(f.answer.newest, f.channel)}`];
  }
}

// ── the running version ──────────────────────────────────────────────────────

/** The launcher package's version. package.json sits one level above both
 *  src/ (dev) and dist/ (installed bundle); "unknown" if it cannot be read. */
export function launcherVersion(): string {
  try {
    const pkg = resolve(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
    return String((JSON.parse(readFileSync(pkg, "utf8")) as { version?: unknown }).version ?? "unknown");
  } catch {
    return "unknown";
  }
}
