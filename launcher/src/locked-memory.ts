/**
 * locked-memory — a version once found protected stays protected while its
 * file is (security fix 2026-10-21; confidentiality.md §7.2a "A version once
 * locked stays locked").
 *
 * The history step (git-object-twins.ts) finds a file's protected versions
 * from what git can REACH: every ref, the reflogs, the index, the working
 * copy. An agent can write `.git` in a confined session, so it can make a
 * version unreachable while its objects stay in the store: a branch reset
 * and the reflogs expired, a commit object deleted (the walk then stops at
 * a shallow boundary the shallow rule must believe, or fails), a pack of
 * commits deleted. The walk cache kept a version whose tips went away, but
 * only until the cache was walked anew (a new seal epoch, a new walk rule,
 * a git upgrade); then the version left the twins and the store served it
 * to `git cat-file -p <id>` (its id read from a surviving tree, or seen in
 * the session's own `git log --raw`).
 *
 * So the step REMEMBERS: per object store, every (version, path) it found
 * protected, by path or by label, in the history, the index or a working
 * copy, in `<walk cache>/locked-memory/<key>.json` (the Mandu home's state,
 * which the agent can neither read nor write). At every launch each
 * remembered version whose path is protected NOW (a protected file of a
 * work tree of the store, or a path a label above `public` decides) joins
 * the versions the walk found, so it is excluded from the sanitized packs,
 * its loose copy made unreadable and its id handed to the guard's backstop,
 * whether or not anything still reaches it. A path no longer protected (the
 * human took the label or the registration away) brings nothing back.
 *
 * The memory is only ever ADDED to, and a version it names only hides more,
 * so it needs no seal: a record something outside Mandu removed or garbled
 * is read as empty, which leaves exactly the walk's own answer (the
 * behaviour before this memory), never less. It is not trusted to stand in
 * for a walk.
 *
 * A version no launch's walk ever found (history rewritten before Mandu
 * first walked that repository with that file protected, a tree in no ref,
 * a blob written by plumbing) is found by the store scan instead
 * (store-scan.ts, confidentiality.md §7.2a "Every stored object is checked
 * once"), whose finds join this memory too.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** A memory file over this is not read (read as empty: the walk's answer). */
export const LOCKED_MEMORY_MAX_BYTES = 64 * 1024 * 1024;
const NAME = /^[0-9a-f]{40}([0-9a-f]{24})?$/;

/** The memory of the object store whose real common dir is `commonDir`. */
export function lockedMemoryFile(walkCacheDir: string, commonDir: string): string {
  return join(walkCacheDir, "locked-memory", `${createHash("sha256").update(commonDir).digest("hex").slice(0, 32)}.json`);
}

/** path (relative to a work tree of the store) → the versions found there. */
export type LockedMemory = Map<string, Set<string>>;

/** A memory file's text, or null when it is not exactly one of
 *  `commonDir` (read as empty). Pure. */
export function parseLockedMemory(text: string, commonDir: string): LockedMemory | null {
  let j: unknown;
  try { j = JSON.parse(text); } catch { return null; }
  if (j === null || typeof j !== "object") return null;
  const e = j as Record<string, unknown>;
  if (e["v"] !== 1 || e["commonDir"] !== commonDir || e["paths"] === null || typeof e["paths"] !== "object" || Array.isArray(e["paths"])) return null;
  const m: LockedMemory = new Map();
  for (const [p, names] of Object.entries(e["paths"] as Record<string, unknown>)) {
    if (p === "" || p.startsWith("/") || p.includes("\0")) return null;
    if (!Array.isArray(names) || !names.every((n) => typeof n === "string" && NAME.test(n))) return null;
    m.set(p, new Set(names as string[]));
  }
  return m;
}

/** The memory on disk (opened without following a link, a regular file
 *  within the cap); empty on any problem. Never throws. */
export function readLockedMemory(file: string, commonDir: string): LockedMemory {
  let fd: number;
  try { fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch { return new Map(); }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > LOCKED_MEMORY_MAX_BYTES) return new Map();
    return parseLockedMemory(readFileSync(fd, "utf8"), commonDir) ?? new Map();
  } catch {
    return new Map();
  } finally {
    closeSync(fd);
  }
}

/** The remembered versions of every path `isProtected` says is protected
 *  now (sorted). Pure. */
export function rememberedVersions(mem: LockedMemory, isProtected: (rel: string) => boolean): string[] {
  const out = new Set<string>();
  for (const [p, names] of mem) if (isProtected(p)) for (const n of names) out.add(n);
  return [...out].sort();
}

/** Add `found` (version, path) pairs to the memory on disk: read again just
 *  before the write (another launch's additions kept), the union written
 *  atomically. Best effort: a memory not written leaves the next launch the
 *  walk's answer and what was remembered before. Never throws. */
export function rememberLocked(file: string, commonDir: string, found: ReadonlyArray<readonly [string, string]>): void {
  try {
    const mem = readLockedMemory(file, commonDir);
    let added = 0;
    for (const [name, p] of found) {
      if (!NAME.test(name) || p === "" || p.startsWith("/") || p.includes("\0")) continue;
      let s = mem.get(p);
      if (s === undefined) { s = new Set(); mem.set(p, s); }
      if (!s.has(name)) { s.add(name); added++; }
    }
    if (added === 0) return;
    const paths: Record<string, string[]> = {};
    for (const p of [...mem.keys()].sort()) paths[p] = [...mem.get(p)!].sort();
    const text = JSON.stringify({ v: 1, commonDir, paths });
    if (text.length > LOCKED_MEMORY_MAX_BYTES) return;
    mkdirSync(join(file, ".."), { recursive: true, mode: 0o700 });
    const tmp = `${file}.tmp-${process.pid}`;
    rmSync(tmp, { force: true });
    writeFileSync(tmp, text, { mode: 0o600, flag: "wx" });
    renameSync(tmp, file);
  } catch { /* best effort */ }
}
