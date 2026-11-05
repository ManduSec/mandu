/**
 * path-kinds — which rule paths are files on this computer, so a rule that
 * reaches "everything inside" is worded as the file it names when there is
 * nothing inside (dashboard.md §4.25f *A rule on a file reads as a file*),
 * and which have nothing at all there, so a misspelt or moved path says so
 * (§4.25f *A rule on nothing says so*). Mandu-new.
 *
 * A `paths:` entry with no `recursive:` key reaches everything inside its
 * path, folder or not (a saved Keys Mandu found suggestion writes one on a
 * file). The rule is unchanged by this: the projections keep its reach
 * (`covers`), and only their words and icon follow the disk.
 *
 * Read only, display only: a path that is unreadable, a pattern, relative,
 * or not answered within `timeoutMs` (a hung mount) is in neither set, so it
 * keeps the folder words it had and is never called missing. Only `ENOENT`
 * (and `ENOTDIR`, a parent that is a file) counts as missing. A link counts
 * as what it points to, as the guard judges an open.
 */
import { stat } from "node:fs/promises";
import { isAbsolute } from "node:path";

const GLOB = /[*?[]/;
/** The stat errors that mean nothing is at the path. */
const NOTHING_THERE = new Set(["ENOENT", "ENOTDIR"]);

export interface PathKindOptions {
  timeoutMs?: number;
  /** The stat to use (a test's stand-in for a hung mount or EACCES). */
  look?: (path: string) => Promise<{ isDirectory(): boolean }>;
}

/** Among `paths`: those on disk that are not folders (`files`), and those
 *  with nothing on disk (`missing`). */
export async function pathKinds(
  paths: Iterable<string>,
  opts: PathKindOptions = {},
): Promise<{ files: ReadonlySet<string>; missing: ReadonlySet<string> }> {
  const look = opts.look ?? stat;
  const wanted = [...new Set([...paths].filter((p) => typeof p === "string" && isAbsolute(p) && !GLOB.test(p)))];
  const files = new Set<string>();
  const missing = new Set<string>();
  if (!wanted.length) return { files, missing };
  const each = wanted.map(async (p) => {
    try {
      if (!(await look(p)).isDirectory()) files.add(p);
    } catch (e) {
      // Unreadable (EACCES, …): neither, never called missing.
      if (NOTHING_THERE.has((e as NodeJS.ErrnoException | null)?.code ?? "")) missing.add(p);
    }
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, opts.timeoutMs ?? 500);
  });
  await Promise.race([Promise.all(each), late]);
  clearTimeout(timer);
  // Copies: a stat that answers after the timer changes nothing already sent.
  return { files: new Set(files), missing: new Set(missing) };
}

/** The paths among `paths` that are on disk and are not folders. */
export async function filePaths(paths: Iterable<string>, opts: PathKindOptions = {}): Promise<ReadonlySet<string>> {
  return (await pathKinds(paths, opts)).files;
}
