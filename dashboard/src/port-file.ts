/**
 * port-file — publish the port this server bound (DASHBOARD_PORT=0: the
 * kernel picked it) to whoever started it, through MANDU_PORT_FILE
 * (runtime-instances.md §8; `mandu dashboard` passes
 * `<runtime base>/dashboard-<pid>.port`).
 *
 * Atomic: the digits go to `<file>.tmp` and rename(2) puts them in place, so
 * a reader never sees a half-written value.
 *
 * Never through something planted (runtime-instances.md §2, "planted paths",
 * 2026-09-30): the file sits in the runtime base, which the agent may write,
 * its name is predictable (the CLI's pid), and this process runs outside the
 * agent's confinement. A plain write of `<file>.tmp` followed a link there
 * and replaced the linked file's contents with the port number. So the temp
 * name is unlinked first (unlink never follows a link) and then created
 * exclusively (`wx`: O_CREAT|O_EXCL refuses any entry at the name, a link
 * included); one re-planted in between fails the write, never follows it.
 * The rename replaces whatever stands at `<file>` itself, a link included,
 * never what it names.
 *
 * Mandu-new (no reference origin).
 */
import { renameSync, unlinkSync, writeFileSync } from "node:fs";

/** Write `port` to `portFile` (tmp + rename, the tmp created exclusively). */
export function publishPortFile(portFile: string, port: number): void {
  const tmp = `${portFile}.tmp`;
  try { unlinkSync(tmp); } catch { /* none left over */ }
  try {
    writeFileSync(tmp, String(port), { flag: "wx" });
    renameSync(tmp, portFile);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* never created, or already renamed */ }
    throw e;
  }
}
