/**
 * history-tips — what the arbiter's history readers start from, without
 * `git --reflog` (docs/design/confidentiality/confidentiality.md §7.2a "Cost
 * on a relaunch", the arbiter's readers).
 *
 * The background lock resolution (lock-resolution.ts) and the git-history
 * secret scan (secret-history-scan.ts) start from every ref and every reflog
 * entry. `git … --all --reflog` answers that, but git enumerates every
 * reflog of the common directory once PER WORKTREE (2.7 s on a repository
 * with ~180 worktrees, for every repository the registry knows, each
 * cycle): background work, but it competes with a launch for the CPU and
 * the ref store. Here the reflogs are read ONCE, from their files
 * (../src/reflog-tips.ts, the launcher's reader, byte-identical), and handed
 * to git as object names on its stdin:
 *
 *   - tips (`historyTipsOf`): each `rev-list --all --no-walk` plus
 *     `rev-list --no-walk --ignore-missing --stdin` of the reflogs' names
 *     (git keeps the objects it has and peels each to its commit, as
 *     `--reflog` does): the launcher's `historyStateOfRoots` for one work
 *     tree, so the lock resolution's key is the one the launcher computes;
 *   - a walk (`reflogRevArgs`): `--all --ignore-missing --stdin` with the
 *     reflogs' names in place of `--all --reflog` (a name git no longer has
 *     is skipped, as `--reflog` skips a pruned entry).
 *
 * SECURITY: the commits these readers see must NEVER be fewer than `--all
 * --reflog` names (a reflog-only commit left out would leave its secret
 * unscanned, its labelled version unlocked). The reader's answer is git's
 * set or a superset; on ANY doubt (a ref storage other than files, a config
 * git could not read, a failed rev-parse, a symlink or a FIFO in the logs, a
 * line that is not an entry, the caps) the old `--all --reflog` form runs
 * instead, the same fallback as the launcher's.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference
 * origin); the decisions mirror launcher/src/git-object-twins.ts
 * `reflogTipsOf` / `historyStateOfRoots` (the packages ship standalone).
 */
import { resolve } from "node:path";
import { readReflogOids } from "../src/reflog-tips.js";

/** One git call in the work tree the caller is reading (cwd, deadline and
 *  hardening bound by the caller). A call that did not finish is reported
 *  with a non-zero code. */
export type TipsGit = (args: string[], input?: string) => Promise<{ code: number; stdout: string; stderr: string }>;

/** The object names the reflogs hold (`oids`, sorted, unique), or why git's
 *  own `--reflog` must answer instead (`fallback`). */
export type ReflogNames = { oids: string[]; fallback: null } | { oids: null; fallback: string };

const HEX = /^[0-9a-f]{40}([0-9a-f]{24})?$/;

/** The 40/64-hex lines of git output, trimmed. Pure. */
export function hexLines(out: string): string[] {
  return out.split("\n").map((l) => l.trim()).filter((l) => HEX.test(l));
}

/** extensions.refStorage of `git config -z --get-regexp` output: "" when
 *  unset (the files backend); the last value wins, a bare key is "true".
 *  Pure. */
export function refStorageOf(out: string): string {
  let v = "";
  for (const rec of out.split("\0")) {
    if (rec === "") continue;
    const nl = rec.indexOf("\n");
    if ((nl < 0 ? rec : rec.slice(0, nl)).toLowerCase() === "extensions.refstorage") v = nl < 0 ? "true" : rec.slice(nl + 1);
  }
  return v;
}

/** The arguments of the two calls reflogNamesOf makes. */
export const REFLOG_FACTS_ARGS: readonly string[] = ["rev-parse", "--show-object-format", "--git-common-dir"];
export const REFLOG_CONFIG_ARGS: readonly string[] = ["config", "-z", "--get-regexp", "^extensions\\.refstorage$"];

/**
 * The names in every reflog of the repository the work tree `root` belongs
 * to (`<common>/logs/**`, `<common>/worktrees/*\/logs/**`), read from the
 * files once; `{fallback}` on any doubt. Two small git calls, concurrent.
 */
export async function reflogNamesOf(git: TipsGit, root: string): Promise<ReflogNames> {
  const [rp, cfg] = await Promise.all([git([...REFLOG_FACTS_ARGS]), git([...REFLOG_CONFIG_ARGS])]);
  if (rp.code !== 0) return { oids: null, fallback: "git rev-parse failed" };
  const [fmt, common] = rp.stdout.split("\n").map((l) => l.trim());
  if ((fmt !== "sha1" && fmt !== "sha256") || !common) return { oids: null, fallback: "a rev-parse answer it cannot read" };
  // Exit 1 is "none set": the files backend.
  if (cfg.code !== 0 && cfg.code !== 1) return { oids: null, fallback: "the config could not be read" };
  const storage = cfg.code === 0 ? refStorageOf(cfg.stdout) : "";
  if (storage !== "" && storage.toLowerCase() !== "files") return { oids: null, fallback: `extensions.refStorage is ${storage}` };
  const got = readReflogOids(resolve(root, common), fmt === "sha256" ? 64 : 40);
  return "oids" in got ? { oids: got.oids, fallback: null } : { oids: null, fallback: got.fallback };
}

/**
 * The commit tips `rev-list --all --reflog --no-walk` names, read the fast
 * way: `rev-list --all --no-walk` (strict: a ref naming a missing object
 * fails, as before) and the reflogs' names kept and peeled by git. With a
 * fallback, git's own command. Sorted, unique; `{error}` when a call failed.
 */
export async function historyTipsOf(git: TipsGit, names: ReflogNames): Promise<{ tips: string[] } | { error: string }> {
  const fromLogs = names.oids === null
    ? git(["rev-list", "--all", "--reflog", "--no-walk"])
    : names.oids.length === 0
      ? Promise.resolve({ code: 0, stdout: "", stderr: "" })
      : git(["rev-list", "--no-walk", "--ignore-missing", "--stdin"], `${names.oids.join("\n")}\n`);
  const [all, logs] = await Promise.all([git(["rev-list", "--all", "--no-walk"]), fromLogs]);
  for (const r of [all, logs]) {
    if (r.code !== 0) return { error: `git rev-list: ${r.stderr.trim().split("\n").slice(-1)[0] || `exit ${r.code}`}` };
  }
  return { tips: [...new Set([...hexLines(all.stdout), ...hexLines(logs.stdout)])].sort() };
}

/**
 * What a walk takes in place of `--all --reflog`: `--all` and the reflogs'
 * names on stdin (`--ignore-missing`: a name git no longer has is skipped,
 * as `--reflog` skips a pruned entry), or, on a fallback, `--all --reflog`
 * itself. `input` is the stdin to send (undefined: none).
 */
export function reflogRevArgs(names: ReflogNames): { args: string[]; input?: string } {
  if (names.oids === null) return { args: ["--all", "--reflog"] };
  if (names.oids.length === 0) return { args: ["--all"] };
  return { args: ["--all", "--ignore-missing", "--stdin"], input: `${names.oids.join("\n")}\n` };
}
