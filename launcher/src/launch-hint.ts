/**
 * launch-hint — what the last launch from a workspace read of git, so the
 * next one can start the same reads at launch start (twin-prefetch.ts;
 * confidentiality.md §7.2a "Cost on a relaunch").
 *
 * The hint names the work trees whose history state the git-object twins
 * read, grouped as one object store each, and the sanitized packs they
 * served (their cache keys). It is ONLY a hint: nothing in it is trusted.
 * A prefetched state is used only for exactly the same work trees, after
 * its inputs are checked unchanged, and a prefetched hash only for the
 * same unchanged file (file-hashes.ts). A hint that is absent, torn,
 * oversized or of another shape means no prefetch. It lives in the Mandu
 * home's state (`object-walks/launch-hints/`, which the agent can neither
 * read nor write), one file per workspace.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { createHash } from "node:crypto";
import { closeSync, fstatSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync, constants } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";

export interface LaunchHint {
  /** Work trees of one object store each (sorted, as RepoReads asks). */
  stores: string[][];
  /** Cache keys of the sanitized packs served (`cache/object-twins/<key>`). */
  packs: string[];
}

export const HINT_MAX_BYTES = 256 * 1024;
export const HINT_MAX_STORES = 16;
export const HINT_MAX_ROOTS = 64;
export const HINT_MAX_PACKS = 256;
const HINT_VERSION = 1;
const PACK_KEY = /^[0-9a-f]{32}$/;

/** The hint file of a launch from `workspaceRoots` under the walk cache dir
 *  (the path table's `object-walks`). Pure. */
export function launchHintFile(walkCacheDir: string, workspaceRoots: readonly string[]): string {
  const key = createHash("sha256").update(JSON.stringify([...workspaceRoots])).digest("hex").slice(0, 32);
  return join(walkCacheDir, "launch-hints", `${key}.json`);
}

function okRoot(r: unknown): r is string {
  return typeof r === "string" && r.length > 1 && r.length <= 4096 && isAbsolute(r) && !r.includes("\0");
}

/** The hint in `text`, or null when it is not one (a bounded, exact
 *  shape; roots sorted and unique per store). Pure. */
export function parseLaunchHint(text: string): LaunchHint | null {
  if (text.length > HINT_MAX_BYTES) return null;
  let o: unknown;
  try { o = JSON.parse(text); } catch { return null; }
  const h = o as { v?: unknown; stores?: unknown; packs?: unknown } | null;
  if (h === null || typeof h !== "object" || h.v !== HINT_VERSION || !Array.isArray(h.stores) || !Array.isArray(h.packs)) return null;
  if (h.stores.length > HINT_MAX_STORES || h.packs.length > HINT_MAX_PACKS) return null;
  const stores: string[][] = [];
  for (const s of h.stores) {
    if (!Array.isArray(s) || s.length === 0 || s.length > HINT_MAX_ROOTS || !s.every(okRoot)) return null;
    const sorted = [...new Set(s as string[])].sort();
    if (sorted.length !== s.length || sorted.some((r, i) => r !== s[i])) return null;
    stores.push(sorted);
  }
  if (!h.packs.every((k) => typeof k === "string" && PACK_KEY.test(k))) return null;
  return { stores, packs: [...new Set(h.packs as string[])] };
}

/** The hint at `file`, or null (absent, unreadable, not a regular file,
 *  not a hint). Never throws. */
export function readLaunchHint(file: string): LaunchHint | null {
  let fd: number;
  try { fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch { return null; }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > HINT_MAX_BYTES) return null;
    return parseLaunchHint(readFileSync(fd, "utf8"));
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
}

/** Leave the hint for the next launch (atomic: a temp file renamed; the
 *  bounds applied by truncation). Best effort: never throws. */
export function writeLaunchHint(file: string, hint: LaunchHint): void {
  const stores = hint.stores.filter((s) => s.length > 0 && s.length <= HINT_MAX_ROOTS && s.every(okRoot)).slice(0, HINT_MAX_STORES);
  const packs = hint.packs.filter((k) => PACK_KEY.test(k)).slice(0, HINT_MAX_PACKS);
  const text = JSON.stringify({ v: HINT_VERSION, stores: stores.map((s) => [...new Set(s)].sort()), packs });
  if (text.length > HINT_MAX_BYTES) return;
  const tmp = `${file}.${process.pid}.tmp`;
  try {
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    writeFileSync(tmp, text, { mode: 0o600 });
    renameSync(tmp, file);
  } catch {
    try { rmSync(tmp, { force: true }); } catch { /* best effort */ }
  }
}
