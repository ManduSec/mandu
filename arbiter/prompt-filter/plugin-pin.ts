/**
 * plugin-pin — a prompt filter plugin's pin, checked at every spawn
 * (confidentiality-plan-15-prompt-filter.md §4.3, §12 2026-10-03).
 * Mandu-new (no reference origin).
 *
 * A plugin pack pins its program by path and SHA-256 (`exec`, `sha256`),
 * for an interpreter the script it runs (`script`, `script_sha256`), and
 * every other file it loads (`modules:`, each `{path, sha256}` under the
 * script's directory, else the program's), as readers are pinned (Plan 13
 * D8, R5). Before EVERY run:
 *
 *   1. each pinned file is read and hashed, every time, and compared with
 *      its pin: a mismatch is a filter error ("changed since it was
 *      pinned"), which the policy's `on_error` decides. (No stat-keyed
 *      shortcut: a same-size rewrite within one timestamp tick keeps every
 *      stat field, which the first build's cache missed.)
 *   2. the verified BYTES are copied into the arbiter's private directory
 *      (`<dir>/<sha256>/<name>`, the directory 0700, the file 0500/0400,
 *      written to a temporary name from the very bytes the check hashed,
 *      renamed, hashed again), and the plugin runs from that copy. A file
 *      swapped at its pinned path between the check and the exec therefore
 *      never runs: the copy is what was hashed, and the private directory is
 *      out of the agent's reach (the Mandu state directory, on-disk-layout.md
 *      §4). The copy is re-hashed only when its stat changes (only the
 *      arbiter writes there).
 *   3. with `modules:`, the file that loads them (the script, else the
 *      program) and the modules are copied into ONE tree,
 *      `<dir>/tree/<id>/`, at their paths below that file's directory, so a
 *      relative import resolves to the verified copy; `<id>` hashes every
 *      name and pin in it, so two module sets never share a tree.
 *
 * The plugin may read its copies and nothing of the directory it was
 * installed in (plugin-confine.ts reads only the system roots and the copy
 * directories): a module it did not pin is not there to load, and one it
 * pinned that changed fails the check. (Before 2026-10-07 the installed
 * directory stayed readable and its other files loaded unpinned.)
 *
 * The check NEVER holds the arbiter's event loop (§13.5 item 6): a pinned
 * program may be an interpreter of 100 MB and more (node is ~120 MB), and a
 * synchronous read-and-hash of it held every other client's call and
 * `filterPrompt`'s own progress frames (§13.5 item 11) for its whole length,
 * so a loaded machine failed the proxy's 5 s idle deadline closed (CI
 * pipeline #8373). It reads `PIN_CHUNK_BYTES` per awaited read, and checks
 * run one at a time (two cold runs would rename a copy over the one the
 * other is hashing).
 *
 * Stated limits (§13.5): what the plugin loads from the system roots
 * (`/usr`, `/etc`, …: an interpreter's standard library, a package
 * installed there) is not pinned; those are the system's, not writable to
 * the agent. A file over MAX_PINNED_BYTES (a large model's weights) cannot
 * be pinned, so it cannot be loaded either: such a plugin serves its model
 * over its endpoint instead (§5).
 */
import { createHash, randomBytes } from "node:crypto";
import { type Stats } from "node:fs";
import { chmod, mkdir, open, rename, stat, unlink } from "node:fs/promises";
import { basename, dirname, join, relative } from "node:path";

/** The largest program or script a pin covers (larger is a filter error). */
export const MAX_PINNED_BYTES = 512 * 1024 * 1024;

/** The pin check's read size: the event loop runs between two reads. */
export const PIN_CHUNK_BYTES = 1024 * 1024;

export interface PluginPinSpec {
  exec: string;
  sha256: string;
  script?: string;
  scriptSha256?: string;
  /** Every other file the plugin loads (packs.ts checks each is under the
   *  script's directory, else the program's). */
  modules?: ReadonlyArray<{ path: string; sha256: string }>;
}

export interface VerifiedPlugin {
  /** The verified copy of the program, to exec. */
  exec: string;
  /** The verified copy of the script, if any. */
  script?: string;
  /** The directories holding the copies: the ONLY directories besides the
   *  system roots the plugin may read (and execute from). */
  copyDirs: string[];
}

interface Seen { key: string; sha: string }

const statKey = (st: Stats): string => [st.dev, st.ino, st.size, st.mtimeMs, st.ctimeMs, st.mode].join(":");

export class PluginPinError extends Error {}

/**
 * The pins' checker and the private copies. One per arbiter; `dir` is the
 * arbiter's private directory for plugin copies (created 0700).
 */
export class PluginPins {
  private readonly seen = new Map<string, Seen>();
  /** The checks, one at a time (see the header). */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private readonly dir: string) {}

  /** The SHA-256 of `path`'s bytes. `cached`: from the stat-keyed cache when
   *  nothing about the file changed (the private copies only). `copyTo`:
   *  also write the bytes read, the very bytes hashed, to that new file.
   *  Rejects with PluginPinError. */
  private async hashOf(path: string, o: { cached?: boolean; copyTo?: string } = {}): Promise<string> {
    let st: Stats;
    try {
      st = await stat(path);
    } catch (err) {
      throw new PluginPinError(`${path} cannot be read (${(err as NodeJS.ErrnoException).code ?? (err as Error).message})`);
    }
    if (!st.isFile()) throw new PluginPinError(`${path} is not a regular file`);
    if (st.size > MAX_PINNED_BYTES) throw new PluginPinError(`${path} is larger than ${MAX_PINNED_BYTES} bytes`);
    const key = statKey(st);
    const hit = o.cached ? this.seen.get(path) : undefined;
    if (hit && hit.key === key) return hit.sha;
    const { sha, st: after } = await hashFile(path, o.copyTo);
    // A file that changed while it was read is not trusted this time.
    if (statKey(after) !== key) throw new PluginPinError(`${path} changed while it was checked`);
    this.seen.set(path, { key, sha });
    return sha;
  }

  /** Check one pinned file and return its private copy (`copy`: where in
   *  the private directory; default `<dir>/<pin>/<name>`). */
  private async verifyOne(path: string, pin: string, mode: number, at?: string): Promise<string> {
    const copy = at ?? join(this.dir, pin, basename(path) || "plugin");
    const dir = dirname(copy);
    let copied = false;
    try {
      copied = (await this.hashOf(copy, { cached: true })) === pin;
    } catch { /* absent or unreadable: written below */ }
    if (copied) {
      const sha = await this.hashOf(path);
      if (sha !== pin) throw mismatch(path, sha, pin);
      return copy;
    }
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    await chmod(this.dir, 0o700);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const tmp = `${copy}.tmp-${process.pid}-${randomBytes(6).toString("hex")}`;
    try {
      const sha = await this.hashOf(path, { copyTo: tmp });
      if (sha !== pin) throw mismatch(path, sha, pin);
      await chmod(tmp, mode);
      await rename(tmp, copy);
    } catch (err) {
      await unlink(tmp).catch(() => { /* never written, or renamed */ });
      throw err;
    }
    this.seen.delete(copy);
    if ((await this.hashOf(copy, { cached: true })) !== pin) throw new PluginPinError(`the private copy of ${path} does not match its pin`);
    return copy;
  }

  /** Check every pin of `spec` and return the copies to run. Rejects with
   *  PluginPinError on any mismatch (a filter error). */
  verify(spec: PluginPinSpec): Promise<VerifiedPlugin> {
    const run = this.queue.then(() => this.verifyNow(spec));
    this.queue = run.catch(() => { /* the caller has it */ });
    return run;
  }

  private async verifyNow(spec: PluginPinSpec): Promise<VerifiedPlugin> {
    const hasScript = spec.script !== undefined && spec.scriptSha256 !== undefined;
    const modules = spec.modules ?? [];
    // With modules: the file that loads them and the modules share one tree.
    let tree: { root: string; base: string } | null = null;
    if (modules.length > 0) {
      const main = hasScript ? spec.script! : spec.exec;
      const base = dirOf(main);
      const entries: Array<[string, string]> = [[basename(main), hasScript ? spec.scriptSha256! : spec.sha256]];
      for (const m of modules) {
        const rel = relative(base, m.path);
        if (rel === "" || rel.startsWith("..") || rel.startsWith("/")) throw new PluginPinError(`${m.path} is not under ${base}, the directory of ${main}`);
        entries.push([rel, m.sha256]);
      }
      entries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
      const id = createHash("sha256").update(JSON.stringify(entries)).digest("hex");
      tree = { root: join(this.dir, "tree", id), base };
    }
    const inTree = (path: string): string | undefined => (tree ? join(tree.root, relative(tree.base, path)) : undefined);
    const exec = await this.verifyOne(spec.exec, spec.sha256, 0o500, hasScript ? undefined : inTree(spec.exec));
    const copyDirs = [hasScript || !tree ? dirOf(exec) : tree.root];
    let script: string | undefined;
    if (hasScript) {
      script = await this.verifyOne(spec.script!, spec.scriptSha256!, 0o400, inTree(spec.script!));
      copyDirs.push(tree ? tree.root : dirOf(script));
    }
    for (const m of modules) {
      // A module keeps its execute bit (a helper the plugin runs).
      let mode = 0o400;
      try { if ((await stat(m.path)).mode & 0o111) mode = 0o500; } catch { /* verifyOne names it */ }
      await this.verifyOne(m.path, m.sha256, mode, inTree(m.path));
    }
    return { exec, ...(script ? { script } : {}), copyDirs: [...new Set(copyDirs)] };
  }
}

const mismatch = (path: string, sha: string, pin: string): PluginPinError =>
  new PluginPinError(`${path} changed since it was pinned (sha256 ${sha.slice(0, 12)}…, pinned ${pin.slice(0, 12)}…)`);

function dirOf(p: string): string {
  const i = p.lastIndexOf("/");
  return i <= 0 ? "/" : p.slice(0, i);
}

/** Hash a file through one descriptor, `PIN_CHUNK_BYTES` per awaited read
 *  (the event loop runs in between); with `copyTo`, each chunk hashed is
 *  also written to that new file (created exclusively, 0700). Returns the
 *  descriptor's stat after the read. */
async function hashFile(path: string, copyTo?: string): Promise<{ sha: string; st: Stats }> {
  const fh = await open(path, "r");
  try {
    const out = copyTo === undefined ? null : await open(copyTo, "wx", 0o700);
    try {
      const h = createHash("sha256");
      const buf = Buffer.allocUnsafe(PIN_CHUNK_BYTES);
      let total = 0;
      for (;;) {
        const { bytesRead: n } = await fh.read(buf, 0, buf.length, null);
        if (n <= 0) break;
        total += n;
        if (total > MAX_PINNED_BYTES) throw new PluginPinError(`${path} is larger than ${MAX_PINNED_BYTES} bytes`);
        h.update(buf.subarray(0, n));
        for (let off = 0; out && off < n;) off += (await out.write(buf, off, n - off)).bytesWritten;
      }
      return { sha: h.digest("hex"), st: await fh.stat() };
    } finally {
      await out?.close();
    }
  } finally {
    await fh.close();
  }
}
