/**
 * path-kinds — which rule paths are files on this computer, so a rule that
 * reaches "everything inside" is worded as the file it names when there is
 * nothing inside (dashboard.md §4.25f *A rule on a file reads as a file*).
 * Mandu-new.
 *
 * A `paths:` entry with no `recursive:` key reaches everything inside its
 * path, folder or not (a saved Keys Mandu found suggestion writes one on a
 * file). The rule is unchanged by this: the projections keep its reach
 * (`covers`), and only their words and icon follow the disk.
 *
 * Read only, display only: a path that is missing, unreadable, a pattern,
 * relative, or not answered within `timeoutMs` (a hung mount) is not listed,
 * so it keeps the folder words it had. A link counts as what it points to,
 * as the guard judges an open.
 */
import { stat } from "node:fs/promises";
import { isAbsolute } from "node:path";

const GLOB = /[*?[]/;

/** The paths among `paths` that are on disk and are not folders. `look`
 *  is the stat to use (a test's stand-in for a hung mount). */
export async function filePaths(
  paths: Iterable<string>,
  opts: { timeoutMs?: number; look?: (path: string) => Promise<{ isDirectory(): boolean }> } = {},
): Promise<ReadonlySet<string>> {
  const look = opts.look ?? stat;
  const wanted = [...new Set([...paths].filter((p) => typeof p === "string" && isAbsolute(p) && !GLOB.test(p)))];
  const found = new Set<string>();
  if (!wanted.length) return found;
  const each = wanted.map(async (p) => {
    try {
      if (!(await look(p)).isDirectory()) found.add(p);
    } catch {
      // Missing or unreadable: not known to be a file.
    }
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, opts.timeoutMs ?? 500);
  });
  await Promise.race([Promise.all(each), late]);
  clearTimeout(timer);
  // A copy: a stat that answers after the timer changes nothing already sent.
  return new Set(found);
}
