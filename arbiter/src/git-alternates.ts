/**
 * git-alternates — every object directory a git repository reads: its own
 * and, through `objects/info/alternates`, every alternate it reaches
 * (docs/design/confidentiality/confidentiality.md §7.2a "Stores shared
 * through alternates").
 *
 * Two readers must agree on it exactly: the launcher's object twins
 * (git-object-twins.ts, which plans one twin per real object directory) and
 * the arbiter's copies prepared ahead of time (policy/prepared-copies.ts,
 * which builds the sanitized packs a launch binds for a repository it did
 * not prepare). A pack one of them reaches and the other does not is a pack
 * with no sanitized copy, so the closure is ONE implementation.
 *
 * ONE FILE, TWO COPIES: launcher/src and arbiter/src each ship this file
 * byte-identical (the packages ship standalone and do not import each
 * other). tests/stack/prepared-copies-parity.test.ts holds the copies equal
 * and runs one alternates chain through both. Change the launcher's copy
 * and copy it out.
 *
 * Fail closed: an alternates file that cannot be read or parsed as git
 * would, a resolution failure other than "nothing there", a chain deeper
 * than ALTERNATES_MAX_DEPTH links or more than ALTERNATES_MAX_STORES
 * directories throw an AlternatesError, never a shorter list (a directory
 * left out would keep its raw packs readable). Each caller maps the error
 * to its own refusal.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference
 * origin); moved out of launcher/src/git-object-twins.ts (2026-10-04).
 */
import { closeSync, constants as fsConstants, fstatSync, openSync, readSync, realpathSync, statSync } from "node:fs";
import { join } from "node:path";

/** How far the alternates are followed (objectStoreClosure). Git itself
 *  reads an alternate's alternates down to six levels and ignores what lies
 *  deeper; Mandu follows further (an extra store inventoried only hides
 *  more) and refuses past its own bound. */
export const ALTERNATES_MAX_DEPTH = 16;
export const ALTERNATES_MAX_STORES = 256;
/** An `info/alternates` file larger than this is refused. */
export const ALTERNATES_MAX_BYTES = 1024 * 1024;

/** Why the object directories of a store cannot be told (the caller fails
 *  closed: no twin, no prepared copy, never the raw store). */
export class AlternatesError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AlternatesError";
  }
}

const C_ESCAPES: Readonly<Record<string, number>> = { a: 7, b: 8, f: 12, n: 10, r: 13, t: 9, v: 11, "\\": 92, "\"": 34 };

/** A C-quoted entry (`"..."`, git's quote.c `unquote_c_style`); it must be
 *  the whole line. Throws on anything git would not unquote. */
function unquoteC(line: string): string {
  const bytes: number[] = [];
  let i = 1;
  for (;;) {
    if (i >= line.length) throw new Error("a quoted entry without its closing quote");
    const ch = line[i]!;
    if (ch === "\"") { i++; break; }
    if (ch !== "\\") {
      const c = String.fromCodePoint(line.codePointAt(i)!);
      bytes.push(...Buffer.from(c, "utf8"));
      i += c.length;
      continue;
    }
    const e = line[i + 1];
    if (e === undefined) throw new Error("a quoted entry ending in a backslash");
    const named = C_ESCAPES[e];
    if (named !== undefined) { bytes.push(named); i += 2; continue; }
    const oct = /^[0-3][0-7][0-7]/.exec(line.slice(i + 1, i + 4));
    if (oct === null) throw new Error(`an unknown escape in a quoted entry`);
    bytes.push(parseInt(oct[0], 8));
    i += 4;
  }
  if (i !== line.length) throw new Error("text after a quoted entry's closing quote");
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(bytes));
  } catch {
    throw new Error("a quoted entry that is not UTF-8");
  }
}

/**
 * The entries of an `objects/info/alternates` file as git reads them (odb.c
 * `parse_alt_odb_entry`): one per line, a line starting with `#` a comment,
 * an empty line skipped, a line starting with `"` C-quoted, nothing trimmed.
 * An entry that differs from its trimmed spelling yields both (a store
 * inventoried that git would not use only hides more). Throws on what it
 * cannot read as git would: a NUL, a quoted entry git would not unquote
 * (git would then take it literally) or with text after its closing quote.
 * Pure.
 */
export function parseAlternates(text: string): string[] {
  if (text.includes("\0")) throw new Error("a NUL byte");
  const out: string[] = [];
  for (const line of text.split("\n")) {
    if (line === "" || line.startsWith("#")) continue;
    const entry = line.startsWith("\"") ? unquoteC(line) : line;
    if (entry === "") continue;
    out.push(entry);
    const t = entry.trim();
    if (t !== "" && t !== entry) out.push(t);
  }
  return [...new Set(out)];
}

/** What objectStoreClosure reads. */
export interface AlternatesIo {
  /** The text of `<objectsDir>/info/alternates`; null when there is none.
   *  Throws when it exists but is not a regular file it can read whole. */
  read(objectsDir: string): string | null;
  /** The real path of a directory; null when nothing (or no directory) is
   *  there, an entry git skips too. Throws on any other failure. */
  realDir(p: string): string | null;
}

function errCode(e: unknown): string {
  return (e as NodeJS.ErrnoException | undefined)?.code ?? "";
}

/** The production AlternatesIo: the file opened `O_NONBLOCK` (a FIFO never
 *  blocks the caller) and checked regular on the descriptor, at most
 *  ALTERNATES_MAX_BYTES, UTF-8; a path resolved by the C library's
 *  `realpath` (physically, as git resolves it). */
export const defaultAlternatesIo: AlternatesIo = {
  read(objectsDir) {
    const p = join(objectsDir, "info", "alternates");
    let fd: number;
    try {
      fd = openSync(p, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK);
    } catch (e) {
      if (errCode(e) === "ENOENT" || errCode(e) === "ENOTDIR") return null;
      throw new Error(`${p} cannot be opened (${errCode(e) || (e as Error).message})`);
    }
    try {
      if (!fstatSync(fd).isFile()) throw new Error(`${p} is not a regular file`);
      const buf = Buffer.alloc(ALTERNATES_MAX_BYTES + 1);
      let n = 0;
      for (;;) {
        const got = readSync(fd, buf, n, buf.length - n, null);
        if (got === 0) break;
        n += got;
        if (n > ALTERNATES_MAX_BYTES) throw new Error(`${p} is larger than ${ALTERNATES_MAX_BYTES} bytes`);
      }
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(buf.subarray(0, n));
      } catch {
        throw new Error(`${p} is not UTF-8`);
      }
    } finally {
      closeSync(fd);
    }
  },
  realDir(p) {
    let r: string;
    try {
      r = realpathSync.native(p);
    } catch (e) {
      if (errCode(e) === "ENOENT" || errCode(e) === "ENOTDIR") return null;
      throw new Error(`the alternate ${p} cannot be resolved (${errCode(e) || (e as Error).message})`);
    }
    try { return statSync(r).isDirectory() ? r : null; } catch { return null; }
  },
};

/**
 * Every object directory a repository reads (confidentiality.md §7.2a
 * "Stores shared through alternates"): its own first, then, breadth first,
 * every alternate reachable from it through `info/alternates` files, an
 * alternate's own alternates included, each once by its real path (a cycle
 * ends). A relative entry resolves against the object directory whose file
 * names it, as git's does. An entry naming nothing is skipped (git skips it
 * too). Fail closed: an alternates file that cannot be read or parsed, a
 * chain deeper than `maxDepth` or more than `maxStores` directories throw an
 * AlternatesError, never a shorter list (a store left out would keep its
 * raw packs readable). Pure given `io`.
 */
export function objectStoreClosure(
  own: string, io: AlternatesIo = defaultAlternatesIo, maxDepth = ALTERNATES_MAX_DEPTH, maxStores = ALTERNATES_MAX_STORES,
): string[] {
  const fail = (m: string): never => { throw new AlternatesError(m); };
  let ownReal: string;
  try { ownReal = io.realDir(own) ?? own; } catch (e) { return fail((e as Error).message); }
  const out = [ownReal];
  const seen = new Set(out);
  let level = [ownReal];
  for (let depth = 0; level.length > 0; depth++) {
    const next: string[] = [];
    for (const dir of level) {
      let entries: string[];
      try {
        const text = io.read(dir);
        if (text === null) continue;
        entries = parseAlternates(text);
      } catch (e) {
        return fail(`the alternates of ${dir} cannot be read (${(e as Error).message}), so the stores they name cannot be sanitized`);
      }
      if (entries.length === 0) continue;
      if (depth >= maxDepth) return fail(`${dir}/info/alternates: alternates nested deeper than ${maxDepth} levels`);
      for (const e of entries) {
        let real: string | null;
        try { real = io.realDir(e.startsWith("/") ? e : `${dir}/${e}`); } catch (err) { return fail((err as Error).message); }
        if (real === null || seen.has(real)) continue;
        if (out.length >= maxStores) return fail(`${own}: more than ${maxStores} object directories through its alternates`);
        seen.add(real);
        out.push(real);
        next.push(real);
      }
    }
    level = next;
  }
  return out;
}
