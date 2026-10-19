/**
 * entrypoint — "is this module the process entry?", for the guard at the
 * bottom of server-main.ts (tests import its pure exports and must not start
 * the server).
 *
 * Node resolves the main module through realpath, so its import.meta.url is
 * the REAL file, while process.argv[1] keeps the spelling it was typed with.
 * Comparing the two literally made every symlinked spelling a silent no-op
 * (exit 0, no output): on darwin /tmp and /var are symlinks to /private/…, so
 * `node /tmp/…/dist/mandu.mjs` did nothing, and so did a checkout reached
 * through a symlinked directory (the bootstrap `mandu` shim execs tsx on a
 * logical `pwd`). The literal comparison stays first; realpaths decide the
 * rest, and anything that cannot be resolved is "not the entry".
 *
 * For this MCP server the same miss is an exit 0 before it serves anything:
 * the agent sees a tool server that never answers.
 *
 * PROVENANCE: a copy of launcher/src/entrypoint.ts (each package stays
 * standalone).
 */
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function isEntrypoint(metaUrl: string, argv1: string | undefined = process.argv[1]): boolean {
  if (!argv1) return false;
  try {
    const self = fileURLToPath(metaUrl);
    const entry = resolve(argv1);
    return self === entry || realpathSync(self) === realpathSync(entry);
  } catch {
    return false;
  }
}
