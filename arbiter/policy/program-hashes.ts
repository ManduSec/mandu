/**
 * program-hashes — the content hashes of this host's printer binaries and of
 * its programs that run code they are given (Plan 13 D8, "printers admit
 * nothing", the !437 leftover (2), and Plan 13 §8 decision (b) by content,
 * 2026-10-03). Was `printer-hashes.ts` (!451), generalized to the
 * code-running list.
 *
 * A printer is recognized by its name (`readerPrints`, flow-taint.ts), and so
 * is a shell, an interpreter, a launcher or an editor (`readerRunsCode`). A
 * copy of one under another name that the human pins by path and hash (`{
 * app: mytool, path: /opt/x/mytool, sha256 }`: a GNU cat, or `cp
 * /usr/bin/python3 ~/bin/mytool`) was that pin's program, so it got the raw
 * bytes and handed them to whatever read its output, or ran whatever code
 * the agent handed it. The fix: the arbiter hashes the printers and the
 * code-running programs installed on this host, and a binary with one of
 * those hashes is that program under any name (`hashPrints`,
 * `hashRunsCode`): as an entry it admits nothing, as an opener it gets what
 * a non-reader gets.
 *
 * What is hashed: every file in the system bin directories (`SCAN_DIRS`, a
 * fixed list, never `$PATH`, which can hold a directory the agent writes)
 * whose name or path `readerPrints` or `readerRunsCode` names (the prefixes
 * and the uutils multi-call directory included, so busybox, toybox and
 * uutils' one binary are), resolved through links (`python3` → the
 * `python3.12` it names). Each file is hashed once per (device, inode,
 * mtime, size): a re-scan stats, it does not re-read. Not covered, stated:
 * such a program that is not byte-identical to one installed here (another
 * version, a static build the human downloaded, an interpreter installed
 * outside these directories such as a version manager's under $HOME, one
 * installed after the last scan until the next one), and a script that
 * prints (the interpreter is the opener; a pinned script is the human's to
 * vouch for).
 */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, join } from "node:path";

import { addHostProgramHashes, readerPrints, readerRunsCode, type HostProgramKind } from "./flow-taint.js";

/** The system bin directories, uutils coreutils' multi-call directory, and
 *  git's exec path (Debian, Ubuntu and Arch: /usr/lib/git-core; Fedora:
 *  /usr/libexec/git-core; plan 13 §4.9, 2026-10-04). Every builtin there
 *  (`git-diff`, `git-credential-store`, …) is a link of `git`, the one
 *  binary picking its job from argv[0], so it hashes as git, a printer,
 *  whatever name it was run by; on a host where that `git` is not
 *  byte-identical to /usr/bin/git it is hashed in its own right. Not every
 *  file there is a link of git: git builds a few programs of their own, and
 *  each one that is a printer by name is hashed in its own right too, git's
 *  HTTP transport (`git-remote-http`) and, since 2026-10-07,
 *  `git-http-fetch`, `git-http-push`, `git-imap-send` (libcurl reads
 *  `.netrc` for them) and `git-http-backend` (flow-taint.ts
 *  `PRINTER_READERS` says why). */
export const SCAN_DIRS: readonly string[] = [
  "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
  "/usr/lib/cargo/bin/coreutils",
  "/usr/lib/git-core", "/usr/libexec/git-core",
];

/** What a name says a program is, by kind. */
const KINDS: ReadonlyArray<{ kind: HostProgramKind; names: (path: string) => boolean }> = [
  { kind: "prints", names: readerPrints },
  { kind: "runsCode", names: readerRunsCode },
];

/** By inode (`dev:ino`): uutils' one binary is hard-linked under every name,
 *  so it is read once. */
const cache = new Map<string, { stamp: string; sha256: string }>();

/** sha256 of each binary of each kind under `dirs`, with the name of the
 *  file it resolves to. Unreadable entries are skipped (a program the
 *  arbiter cannot read is still that program by name). */
export function scanProgramHashes(dirs: readonly string[] = SCAN_DIRS): Record<HostProgramKind, Map<string, string>> {
  const out: Record<HostProgramKind, Map<string, string>> = { prints: new Map(), runsCode: new Map() };
  const seen: Record<HostProgramKind, Set<string>> = { prints: new Set(), runsCode: new Set() };
  for (const dir of dirs) {
    let names: string[];
    try { names = readdirSync(dir); } catch { continue; }
    for (const name of names) {
      const path = join(dir, name);
      const kinds = KINDS.filter((k) => k.names(path)).map((k) => k.kind);
      if (kinds.length === 0) continue;
      try {
        const real = realpathSync(path);
        const st = statSync(real);
        if (!st.isFile()) continue;
        const inode = `${st.dev}:${st.ino}`;
        const todo = kinds.filter((k) => !seen[k].has(inode));
        if (todo.length === 0) continue;
        const stamp = `${st.mtimeMs}:${st.size}`;
        let hit = cache.get(inode);
        if (hit === undefined || hit.stamp !== stamp) {
          hit = { stamp, sha256: createHash("sha256").update(readFileSync(real)).digest("hex") };
          cache.set(inode, hit);
        }
        for (const k of todo) {
          seen[k].add(inode);
          if (!out[k].has(hit.sha256)) out[k].set(hit.sha256, basename(real));
        }
      } catch { /* vanished or unreadable: skip */ }
    }
  }
  return out;
}

/** sha256 of each printer binary under `dirs` (`scanProgramHashes`'s
 *  printers). */
export function scanPrinterHashes(dirs: readonly string[] = SCAN_DIRS): Set<string> {
  return new Set(scanProgramHashes(dirs).prints.keys());
}

let lastScan = 0;

/** Scan and add the result to flow-taint's sets (`addHostProgramHashes`),
 *  at most once per `minIntervalMs` (0: now). The arbiter calls it at start
 *  and before each secret open it decides (every ten minutes at most), so a
 *  program installed later is known by its hash within ten minutes. */
export function refreshProgramHashes(opts: { minIntervalMs?: number; dirs?: readonly string[]; now?: number } = {}): void {
  const now = opts.now ?? Date.now();
  if (lastScan !== 0 && now - lastScan < (opts.minIntervalMs ?? 60_000)) return;
  lastScan = now;
  const found = scanProgramHashes(opts.dirs);
  addHostProgramHashes("prints", found.prints);
  addHostProgramHashes("runsCode", found.runsCode);
}
