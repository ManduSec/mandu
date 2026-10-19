/**
 * doctor-home — the `mandu doctor` rows about Mandu's folder
 * (docs/design/architecture/on-disk-layout.md §3): anything in the folder that other
 * users can open (the folder, `state/`, `events/`, the database files, …),
 * with the `chmod` fix.
 *
 * Built on the `mandu paths` report (paths-command.ts); the reads are
 * injected. Mandu-new (no reference origin).
 */
import { MANDU_PATHS, manduPath, type ManduPathEnv } from "./generated/mandu-paths.js";
import {
  chmodCommands,
  gatherPaths,
  homeOf,
  isLoose,
  octal,
  realPathsDeps,
  tilde,
  type PathsDeps,
  type PathsReport,
} from "./paths-command.js";

type Env = Record<string, string | undefined>;

export interface HomeFacts {
  report: PathsReport;
  /** Paths other users can open, that only the owner should. */
  loose: { path: string; mode: number; dir: boolean }[];
}

// The owner lock is no secret, but it sits in the home, which only you may
// open; a lock written before it was created 0600 shows here with its fix.
const DB_SIDE_FILES = ["-wal", "-shm", "-journal", ".owner"];

export function gatherHomeFacts(env: Env, home: string, deps: PathsDeps): HomeFacts {
  const report = gatherPaths(env, home, deps);
  const loose: HomeFacts["loose"] = report.rows
    .filter((r) => r.loose && r.mode !== null)
    .map((r) => ({ path: r.path, mode: r.mode!, dir: MANDU_PATHS[r.name].kind === "dir" }));
  // SQLite's side files carry the database's contents too.
  for (const db of ["symbol-db", "symbol-db-test"] as const) {
    const base = manduPath(db, env as ManduPathEnv, home);
    for (const suf of DB_SIDE_FILES) {
      const st = deps.stat(base + suf);
      if (st !== null && isLoose(st.mode)) loose.push({ path: base + suf, mode: st.mode, dir: false });
    }
  }
  return { report, loose };
}

const OK = "✓";
const NO = "✗";
const DOT = "·";

/** The doctor rows. Pure. */
export function homeRows(f: HomeFacts): string[] {
  const L: string[] = [];
  const r = f.report;
  const t = (p: string): string => tilde(p, r.userHome);
  const homeRow = r.rows.find((x) => x.name === "mandu-home");
  // A dangling symlink is there but broken (on-disk-layout.md §5); a broken
  // home is no "only you can open it".
  const broken = r.rows.filter((x) => x.brokenLink);
  if (homeRow !== undefined && !homeRow.exists) {
    L.push(`  ${DOT} ${t(r.home)} does not exist yet: the first launch creates it`);
  } else if (f.loose.length === 0 && !homeRow?.brokenLink) {
    L.push(`  ${OK} ${t(r.home)}: only you can open it`);
  }
  if (broken.length > 0) {
    L.push(`  ${NO} ${broken.length === 1 ? "this is a link" : "these are links"} to something that is not there; Mandu cannot use ${broken.length === 1 ? "it" : "them"}:`);
    for (const b of broken) L.push(`      ${t(b.path)}`);
    L.push("    fix: bring the link's target back (a disk not mounted?) or remove the link");
  }

  if (f.loose.length > 0) {
    L.push(`  ${NO} other users on this machine can open these; only you should:`);
    for (const l of f.loose) L.push(`      ${t(l.path)} (${octal(l.mode)})`);
    L.push("    fix:");
    for (const c of chmodCommands(f.loose, r.userHome)) L.push(`      ${c}`);
  }
  return L;
}

/** Gather for this process's env (the default doctor probe). */
export function realHomeFacts(env: Env): HomeFacts {
  return gatherHomeFacts(env, homeOf(env), realPathsDeps);
}
