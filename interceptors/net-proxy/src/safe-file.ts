/**
 * safe-file — write a file by name where someone else may have planted a
 * link (runtime-instances.md §2, "planted paths").
 *
 * Mandu's launcher and services run OUTSIDE the agent's confinement and
 * write files at predictable names in places the agent may write too: a
 * session's scope dir under the runtime base (the proxies' port files, the
 * agent and MCP configs, the guard policy, the shims, `launch.log`) and
 * temp names beside a config file. A plain `writeFileSync(name)` follows a
 * symbolic link planted at that name (or at a directory on its way) and
 * writes into whatever it names: a shell startup file, a project file.
 *
 * `publishFile` never does:
 *   - the directory must be a real directory (lstat: not a link) owned by
 *     this user, unless the caller passes `dirMayBeLink` for a directory the
 *     user configured (a dotfile manager's linked `~/.claude`); even then
 *     the directory it resolves to must be this user's;
 *   - the content goes to a fresh temp name in that directory
 *     (`<name>.<pid>.<random>.tmp`, so it keeps the name's prefix), created
 *     with O_CREAT|O_EXCL|O_NOFOLLOW: open(2) refuses any entry already at
 *     the name, a link included, and the random part makes the name
 *     unpredictable, so a planted entry makes the write fail, never follow;
 *   - the mode is set on the descriptor (fchmod: exact, not narrowed by the
 *     umask, and never through a path);
 *   - rename(2) puts it at `<name>`: it replaces whatever stands there, a
 *     link included, and never writes through it. A reader sees no file or
 *     the whole one.
 *
 * One file, byte-identical in every package that writes such a file (the
 * launcher, anthropic-proxy, openai-proxy, net-proxy; each package stays
 * standalone): tests/stack/safe-file-parity.test.ts holds the copies equal.
 *
 * Mandu-new (no reference origin).
 */
import { closeSync, constants, fchmodSync, lstatSync, openSync, realpathSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { basename, dirname, join } from "node:path";

export interface PublishOptions {
  /** The file's mode (default 0600). */
  mode?: number;
  /** The directory may be a link (one the user made); its target must still
   *  be a directory this user owns. Default false: a link is refused. */
  dirMayBeLink?: boolean;
  /** This user's uid (tests); default process.getuid(). */
  uid?: number;
}

/** Why `dir` may not receive a file, or null when it may. */
export function dirProblem(dir: string, opts: PublishOptions = {}): string | null {
  const uid = opts.uid ?? process.getuid?.();
  let st;
  try { st = lstatSync(dir); } catch (e) { return `${dir}: ${(e as NodeJS.ErrnoException).code ?? "unreadable"}`; }
  if (st.isSymbolicLink()) {
    if (opts.dirMayBeLink !== true) return `${dir} is a symbolic link, not a real directory`;
    try { st = statSync(realpathSync(dir)); } catch (e) { return `${dir}: ${(e as NodeJS.ErrnoException).code ?? "unreadable"}`; }
  }
  if (!st.isDirectory()) return `${dir} is not a directory`;
  if (uid !== undefined && st.uid !== uid) return `${dir} is not yours (owner uid ${st.uid})`;
  return null;
}

/**
 * Write `data` to `path` atomically, never through a link (see the header).
 * Throws when the directory is refused or any step fails; the temp file is
 * removed then.
 */
export function publishFile(path: string, data: string | Uint8Array, opts: PublishOptions = {}): void {
  const dir = dirname(path);
  const problem = dirProblem(dir, opts);
  if (problem !== null) throw new Error(`refusing to write ${path}: ${problem}`);
  const tmp = join(dir, `${basename(path)}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  let created = true;
  try {
    try {
      fchmodSync(fd, opts.mode ?? 0o600);
      const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
      for (let off = 0; off < buf.length;) off += writeSync(fd, buf, off, buf.length - off);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
    created = false;
  } finally {
    if (created) {
      try { unlinkSync(tmp); } catch { /* already gone */ }
    }
  }
}
