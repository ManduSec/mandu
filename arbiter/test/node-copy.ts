/**
 * node-copy — can this node start from a copy of its binary?
 *
 * A prompt-filter plugin runs from a verified private COPY of its program
 * (prompt-filter/plugin-pin.ts), and the plugin suites pin `node`. A node
 * that loads its runtime from a library beside it cannot start from a copy:
 * Homebrew's macOS node links `@rpath/libnode.<n>.dylib`, so the copy dies in
 * dyld (SIGABRT) and every plugin run fails closed. On such a host those
 * suites would prove nothing, so they skip with this reason. macOS runs no
 * plugin anyway (plugin-probe.ts noGuardNote); a node from nodejs.org (one
 * binary) starts from a copy, and the suites run.
 */
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function probe(): string | false {
  const dir = mkdtempSync(join(tmpdir(), "mdu-node-copy-"));
  try {
    const copy = join(dir, "node");
    copyFileSync(realpathSync(process.execPath), copy);
    const r = spawnSync(copy, ["--version"], { encoding: "utf8", timeout: 10_000 });
    if (r.status === 0) return false;
    return `this node cannot start from a copy of its binary (${r.signal ?? `exit ${r.status}`}; a plugin runs from a verified copy)`;
  } catch (err) {
    return `this node cannot be copied (${(err as Error).message})`;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A skip reason when this node cannot run from a copy, else false. */
export const NODE_COPY_SKIP: string | false = probe();
