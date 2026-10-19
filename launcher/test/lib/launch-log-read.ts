/**
 * launch-log-read — the launch's own log (src/launch-log.ts) for a test that
 * runs a launch in-process: the default display prints one banner line and a
 * short line per warning, and the full lines (each notice, each warning in
 * full, each layer) land in that log (packaging.md §5 "Launch display
 * policy"). A test asserting a producer's full text reads it here:
 *
 *   const before = launchLogs(env);   // BEFORE main(): a launch may change env
 *   await main(argv, env);
 *   const full = before.newLines();
 *
 * By name, not by time: two launches in one second cannot be told apart by
 * a file's time.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { launchLogDir } from "../../src/launch-log.js";

type Env = Record<string, string | undefined>;

function names(dir: string): string[] {
  try {
    return readdirSync(dir).filter((n) => n.endsWith(".log"));
  } catch {
    return [];
  }
}

export interface LaunchLogsBefore {
  /** The log folder `env` named when this was taken. */
  dir: string;
  /** The path of the one launch log written since; throws unless exactly one. */
  newPath(): string;
  /** Its lines. */
  newLines(): string[];
  /** Its lines, or [] when the launch wrote none (it stopped before its log
   *  was opened: a parse error, a subcommand). */
  newLinesIfAny(): string[];
}

/** The launch logs under `env`'s Mandu home now, to find the one a launch writes. */
export function launchLogs(env: Env): LaunchLogsBefore {
  // As run.ts resolves it: the launch env's MANDU_HOME, else this process's.
  const dir = launchLogDir(!env["MANDU_HOME"] && process.env["MANDU_HOME"] ? { ...env, MANDU_HOME: process.env["MANDU_HOME"] } : { ...env });
  const before = new Set(names(dir));
  const newPath = (): string => {
    const added = names(dir).filter((n) => !before.has(n));
    if (added.length !== 1) throw new Error(`expected one new launch log in ${dir}, found ${added.length}: ${added.join(", ")}`);
    return join(dir, added[0]!);
  };
  return {
    dir,
    newPath,
    newLines: () => readFileSync(newPath(), "utf8").split("\n").filter((l) => l !== ""),
    newLinesIfAny: () => (names(dir).some((n) => !before.has(n)) ? readFileSync(newPath(), "utf8").split("\n").filter((l) => l !== "") : []),
  };
}
