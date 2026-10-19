/**
 * trust-category — named origin classifiers (URL / CHANNEL / DIR).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/policy/trust-category.ts
 *   Purpose: the *origin rules* half of the data-trust policy. Each category
 *   classifies a key value (a URL, a channel id, a filesystem path) as
 *   TRUSTED / UNTRUSTED via a per-category list + default mode. These are the
 *   classifiers the schema resolver consults for `role: "data"` leaves.
 *
 *   Adaptation for Mandu: NONE of substance. This module is pure (no OpenClaw
 *   runtime coupling — only `node:path`), so it is lifted byte-for-byte aside
 *   from this header. The classification logic is evaluated security code and is
 *   preserved exactly.
 *
 *   One DELIBERATE behavioral change from the reference (2026-07-16, see
 *   createDirTrustCategory): relative DIR `key` values were resolved against
 *   `process.cwd()` AT EVAL TIME — in OpenClaw that matched the agent-workspace
 *   chdir, but the Mandu arbiter is a long-lived daemon whose cwd is
 *   unrelated to any workspace, so the resolution was nondeterministic and
 *   could FALSELY TRUST (allowlist mode: a relative key resolved under a
 *   trusted dir the arbiter merely happened to be started in; blocklist mode:
 *   a listed dir dodged because the key resolved elsewhere). Relative keys now
 *   classify fail-closed UNTRUSTED in both modes. Callers (the proxies) pass
 *   the tool's own path params, which Claude Code supplies absolute; a
 *   relative key is the anomaly, and over-symbolizing it is the safe answer.
 *   (LIST entries are unaffected: they still resolve once, at construction,
 *   against the explicit basePath.)
 *
 * ── Modes ──
 *   - "allowlist"  → default UNTRUSTED; keys matching `list` are TRUSTED
 *   - "blocklist"  → default TRUSTED;   keys matching `list` are UNTRUSTED
 *
 * Adding a new category:
 *   1. implement createXTrustCategory({ mode, list, basePath? }) below,
 *      returning a TrustCategory.
 *   2. wire it into createPolicyEngine() in policy-engine.ts.
 *   3. write tool schemas that reference its id via
 *      { category: "X", role: "key" | "data", ... }.
 */

import { isAbsolute, resolve, sep } from "node:path";

export type Trust = "TRUSTED" | "UNTRUSTED";
export type ListMode = "allowlist" | "blocklist";

/** Public interface: a classifier from key value → Trust. */
export interface TrustCategory {
  id: string;
  mode: ListMode;
  /** Number of entries in the list (for logging). */
  listSize: number;
  /** Classify a raw key value. Null/undefined/empty keys take the
   * category's default (= the inverse of its list mode's hit). */
  classify(key: string | null | undefined): Trust;
}

function defaultTrust(mode: ListMode): Trust {
  return mode === "allowlist" ? "UNTRUSTED" : "TRUSTED";
}
function hitTrust(mode: ListMode): Trust {
  return mode === "allowlist" ? "TRUSTED" : "UNTRUSTED";
}

// ─── URL category ────────────────────────────────────────────────────────
//
// Key format: absolute URL. List entries are hostname/path patterns:
//   "example.com"           — exact hostname, any path
//   "*.example.com"         — wildcard subdomain
//   "api.github.com/repos"  — hostname + path prefix
// Matching is case-insensitive on hostname. A leading scheme (`https://`) is
// IGNORED (2026-09-25, policy-surface.md §8.5.2 "URL pattern finding"):
// before, `https://pypi.org/` parsed as the host "https:" and never matched,
// so a trusted entry trusted nothing and, worse, an UNTRUSTED entry in
// blocklist mode never applied. The law's own views (relaxationsOf, the
// Relaxations list, the tighten/relax delta) always read such an entry as
// naming its host; the matcher now agrees with them.

interface ParsedUrlPattern {
  wildcardSuffix?: string;  // ".example.com"
  hostname: string;
  pathPrefix: string;
}

function parseUrlPattern(pattern: string): ParsedUrlPattern {
  const norm = pattern.trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  if (norm.startsWith("*.")) {
    return { wildcardSuffix: norm.slice(1), hostname: "", pathPrefix: "/" };
  }
  const slash = norm.indexOf("/");
  if (slash === -1) return { hostname: norm, pathPrefix: "/" };
  return { hostname: norm.slice(0, slash), pathPrefix: norm.slice(slash) };
}

function urlMatches(url: string, patterns: ParsedUrlPattern[]): boolean {
  let hostname: string;
  let pathname: string;
  try {
    const parsed = new URL(url);
    hostname = parsed.hostname.toLowerCase();
    pathname = parsed.pathname.toLowerCase();
  } catch {
    return false;
  }
  for (const p of patterns) {
    if (p.wildcardSuffix) {
      if (hostname.endsWith(p.wildcardSuffix) || hostname === p.wildcardSuffix.slice(1)) {
        return true;
      }
      continue;
    }
    if (hostname !== p.hostname) continue;
    if (pathname.startsWith(p.pathPrefix)) return true;
  }
  return false;
}

export function createUrlTrustCategory(opts: { mode: ListMode; list: string[] }): TrustCategory {
  const patterns = opts.list.map(parseUrlPattern);
  const def = defaultTrust(opts.mode);
  const hit = hitTrust(opts.mode);
  return {
    id: "URL",
    mode: opts.mode,
    listSize: opts.list.length,
    classify(key) {
      if (!key) return def;
      return urlMatches(key, patterns) ? hit : def;
    },
  };
}

// ─── Channel category ────────────────────────────────────────────────────
//
// Key format: a channel identifier, with or without the "platform:" prefix
// (e.g. "discord:123456", "agent:bot:telegram:some-chat", or just
// "123456"). List entries:
//   "discord:123456"  — exact (substring) match on the id portion
//   "telegram:*"      — wildcard: any key containing "telegram:"
// Matching is case-insensitive.

interface ChannelMatcher {
  exactIds: string[];          // ["123456", ...]
  platformWildcards: string[]; // ["telegram", ...]
}

function buildChannelMatcher(list: string[]): ChannelMatcher {
  const exactIds: string[] = [];
  const platformWildcards: string[] = [];
  for (const pattern of list) {
    const colon = pattern.indexOf(":");
    if (colon > 0 && pattern.slice(colon + 1) === "*") {
      platformWildcards.push(pattern.slice(0, colon).toLowerCase());
    } else if (colon > 0) {
      exactIds.push(pattern.slice(colon + 1).toLowerCase());
    } else {
      exactIds.push(pattern.toLowerCase());
    }
  }
  return { exactIds, platformWildcards };
}

function channelMatches(key: string, m: ChannelMatcher): boolean {
  const lower = key.toLowerCase();
  if (m.platformWildcards.some((p) => lower.includes(p + ":"))) return true;
  if (m.exactIds.some((id) => lower.includes(id))) return true;
  return false;
}

export function createChannelTrustCategory(opts: { mode: ListMode; list: string[] }): TrustCategory {
  const matcher = buildChannelMatcher(opts.list);
  const def = defaultTrust(opts.mode);
  const hit = hitTrust(opts.mode);
  return {
    id: "CHANNEL",
    mode: opts.mode,
    listSize: opts.list.length,
    classify(key) {
      if (!key) return def;
      return channelMatches(key, matcher) ? hit : def;
    },
  };
}

// ─── Dir category ────────────────────────────────────────────────────────
//
// Key format: an absolute or relative filesystem path. List entries are
// directory or file paths; entries ending in `/*` are treated as directory
// containment shorthand. A key matches if its resolved absolute path equals a
// listed entry (exact file match) or lies inside a listed directory
// (containment match). POSIX-sensitive.

function stripTrailingDirWildcard(dir: string): string {
  if (dir.endsWith("/*") || dir.endsWith("\\*")) return dir.slice(0, -2);
  return dir;
}

function normalizeDir(dir: string, basePath: string): string {
  const pattern = stripTrailingDirWildcard(dir);
  const abs = isAbsolute(pattern) ? pattern : resolve(basePath, pattern);
  return abs.endsWith(sep) ? abs.slice(0, -sep.length) : abs;
}

export function createDirTrustCategory(opts: {
  mode: ListMode;
  list: string[];
  basePath?: string;
}): TrustCategory {
  // Normalize list entries once at creation against the supplied basePath
  // (or cwd at init time) so relative entries from a YAML policy resolve
  // against the policy file directory.
  const base = opts.basePath ?? process.cwd();
  const dirs = opts.list
    .filter((d) => typeof d === "string" && d.length > 0)
    .map((d) => normalizeDir(d, base));
  const def = defaultTrust(opts.mode);
  const hit = hitTrust(opts.mode);
  return {
    id: "DIR",
    mode: opts.mode,
    listSize: opts.list.length,
    classify(key) {
      if (!key) return def;
      // Relative `key` values arrive at eval time from tool params (e.g. the
      // model passes `inbox/email_01.txt` to `Read`). The reference resolved
      // them against process.cwd() AT EVAL TIME — nondeterministic in the
      // arbiter daemon (its cwd is unrelated to any workspace) and unsafe in
      // BOTH modes: allowlist could falsely trust when the daemon's cwd sits
      // inside a trusted dir; blocklist could miss a listed dir. FAIL-CLOSED
      // instead (2026-07-16): a key that cannot be anchored to an absolute
      // path is UNTRUSTED. Over-symbolizing a relative-path read is safe;
      // silently trusting one is not. (Header note has the full rationale.)
      if (!isAbsolute(key)) return "UNTRUSTED";
      // Normalize dot-segments (an already-absolute arg never consults cwd),
      // so `/ws/src/../untrusted/x` cannot dodge a blocklisted `/ws/untrusted`.
      const abs = resolve(key);
      for (const dir of dirs) {
        if (abs === dir) return hit;
        if (abs.startsWith(dir + sep)) return hit;
      }
      return def;
    },
  };
}
