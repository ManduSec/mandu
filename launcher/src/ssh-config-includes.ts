/**
 * ssh-config-includes — the files ssh reads as its configuration through an
 * `Include`, for the write-protect list (P0 (D), 2026-10-07;
 * docs/design/architecture/write-protection.md §2, confidentiality plan 13
 * §3 D8 "a configuration file the reader reads"). Mandu-new.
 *
 * `ssh` is the program that reads a secret's real bytes by default (a key
 * under `~/.ssh`, plan 13 D8 (12): vetted not to print a file it is pointed
 * at). Its configuration decides what it opens and how: an agent that can
 * write a file ssh reads as configuration can make ssh print its key
 * (`Include ~/.ssh/id_ed25519` makes ssh report every line of the key as a
 * bad keyword, probed with OpenSSH 10.2), or load a library into it. So every
 * file ssh reads as configuration waits for the human, as `~/.ssh/config`
 * itself does: the files that config, and `/etc/ssh/ssh_config`, `Include`,
 * followed to ssh's own depth.
 *
 * ssh's rules (readconf.c, `oInclude`): the keyword is case-insensitive,
 * takes one or more words (quoted or not) and may sit in any `Host` or
 * `Match` block (taken here wherever it is: fail-closed); `~/` is the home;
 * a relative word lives in `~/.ssh` for the user's file and in `/etc/ssh`
 * for the system's; each word is a glob(3) pattern; an included file is
 * read in turn, up to 16 levels.
 *
 * What is protected: a word with no glob character, the file it names
 * (existing or not: the agent could create it); a pattern, the deepest
 * directory before its first glob character (a new file there could match).
 * A directory that broad protection cannot hold without stopping ordinary
 * work (the home itself or one above it, a top-level directory such as
 * `/tmp`) is not protected and is reported in `unprotectable`, which the
 * launcher prints as a warning (write-protection.md §4).
 *
 * Pure but for the injected file reads.
 */
import { dirname, isAbsolute, join, normalize } from "node:path";

export interface IncludeFs {
  /** The file's text, or null (missing, unreadable, a directory). */
  read: (p: string) => string | null;
  /** The names in a directory, or null. Absent: patterns are not expanded
   *  (the directory is still protected; nested includes are not followed). */
  list?: (dir: string) => string[] | null;
}

export interface SshIncludeTargets {
  /** Absolute paths to put on the write-protect list, each once. */
  paths: string[];
  /** Include words whose protection would be too broad, with the file that
   *  names them (`~`-relative for the home's). Never the file's text. */
  unprotectable: Array<{ file: string; word: string }>;
}

/** ssh's READCONF_MAX_DEPTH. */
const MAX_DEPTH = 16;

/** The words of an `Include` line's argument (ssh's argv_split): quoted with
 *  `"` or `'`, a backslash escaping the next character; an unquoted word
 *  starting with `#` ends the line. */
export function includeWords(rest: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < rest.length) {
    while (i < rest.length && /\s/.test(rest[i]!)) i++;
    if (i >= rest.length) break;
    if (rest[i] === "#") break;
    let word = "";
    let quote: string | null = null;
    while (i < rest.length) {
      const c = rest[i]!;
      if (quote === null && /\s/.test(c)) break;
      if (c === "\\" && i + 1 < rest.length) { word += rest[i + 1]!; i += 2; continue; }
      if (quote === null && (c === '"' || c === "'")) { quote = c; i++; continue; }
      if (quote !== null && c === quote) { quote = null; i++; continue; }
      word += c;
      i++;
    }
    out.push(word);
  }
  return out;
}

/** The `Include` arguments of a config text, in order. */
export function includeLines(text: string): string[][] {
  const out: string[][] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*include(?:\s*=\s*|\s+)(.*)$/i.exec(line);
    if (m) out.push(includeWords(m[1]!));
  }
  return out;
}

const GLOB = /[*?[]/;

/** Is `dir` too broad to hold: `/`, a top-level directory, the home or a
 *  directory above it? */
function tooBroad(dir: string, homes: readonly string[]): boolean {
  const d = dir.replace(/\/+$/, "") || "/";
  if (d.split("/").filter((s) => s !== "").length < 2) return true;
  return homes.some((h) => h === d || h.startsWith(`${d}/`));
}

/** A glob(3) path component as a regular expression (`*`, `?`, `[…]`, `[!…]`). */
function componentRe(pat: string): RegExp {
  let re = "";
  for (let i = 0; i < pat.length; i++) {
    const c = pat[i]!;
    if (c === "*") re += "[^/]*";
    else if (c === "?") re += "[^/]";
    else if (c === "[") {
      const close = pat.indexOf("]", i + 2);
      if (close < 0) { re += "\\["; continue; }
      let body = pat.slice(i + 1, close);
      if (body.startsWith("!")) body = `^${body.slice(1)}`;
      re += `[${body.replace(/\\/g, "\\\\")}]`;
      i = close;
    } else re += c.replace(/[.+^${}()|\\\]]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

/** The existing paths a pattern names (glob(3), each component matched in
 *  turn; a hidden name matches too: fail-closed for the walk). */
function expand(pattern: string, fs: IncludeFs): string[] {
  if (!fs.list) return [];
  const parts = pattern.split("/").filter((s) => s !== "");
  let found = ["/"];
  for (const part of parts) {
    const next: string[] = [];
    for (const parent of found) {
      if (!GLOB.test(part)) { next.push(join(parent, part)); continue; }
      const re = componentRe(part);
      for (const name of fs.list(parent) ?? []) if (re.test(name)) next.push(join(parent, name));
    }
    found = next;
    if (found.length === 0) break;
  }
  return found;
}

/**
 * Every path ssh may read as configuration through an `Include`, starting at
 * each home's `~/.ssh/config` (the user's, `~` its home) and at the system
 * file (relative words in `/etc/ssh`). `homes`: the launch's `$HOME` and the
 * account's home (ssh expands `~` from the password database, not `$HOME`).
 * `user`: the account's name, so `~<user>/…` is that home too.
 */
export function sshIncludeTargets(
  homes: readonly string[],
  fs: IncludeFs,
  systemConfig = "/etc/ssh/ssh_config",
  user?: string,
): SshIncludeTargets {
  const paths = new Set<string>();
  const unprotectable: SshIncludeTargets["unprotectable"] = [];
  const seenFiles = new Set<string>();
  const queue: Array<{ file: string; home: string | null; depth: number; shown: string }> = [
    ...[...new Set(homes)].filter((h) => isAbsolute(h)).map((h) => ({ file: join(h, ".ssh", "config"), home: h, depth: 0, shown: "~/.ssh/config" })),
    { file: systemConfig, home: null, depth: 0, shown: systemConfig },
  ];
  const absHomes = homes.filter((h) => isAbsolute(h)).map((h) => normalize(h).replace(/\/+$/, ""));
  while (queue.length > 0) {
    const { file, home, depth, shown } = queue.shift()!;
    if (depth > MAX_DEPTH || seenFiles.has(file)) continue;
    seenFiles.add(file);
    const text = fs.read(file);
    if (text === null) continue;
    for (const words of includeLines(text)) {
      for (const word of words) {
        if (word === "") continue;
        let abs: string;
        const own = user !== undefined && (word === `~${user}` || word.startsWith(`~${user}/`)) ? `~${word.slice(1 + user.length)}` : word;
        if (own === "~" || own.startsWith("~/")) {
          // ssh refuses `~` in the system file; a user file's is the home.
          if (home === null) continue;
          abs = join(home, own.slice(1));
        } else if (word.startsWith("~")) {
          // `~user/…`: another account's home; Mandu cannot say which
          // directory that is for the agent, so it reports the word.
          unprotectable.push({ file: shown, word });
          continue;
        } else if (isAbsolute(word)) abs = word;
        else abs = home !== null ? join(home, ".ssh", word) : join(dirname(systemConfig), word);
        abs = normalize(abs);
        const comps = abs.split("/");
        const firstGlob = comps.findIndex((c) => GLOB.test(c));
        const target = firstGlob < 0 ? abs : comps.slice(0, firstGlob).join("/") || "/";
        const broad = tooBroad(target, absHomes);
        if (broad) unprotectable.push({ file: shown, word });
        else paths.add(target);
        const next = firstGlob < 0 ? [abs] : expand(abs, fs);
        for (const f of next) queue.push({ file: f, home, depth: depth + 1, shown: home !== null && f.startsWith(`${home}/`) ? `~${f.slice(home.length)}` : f });
      }
    }
  }
  return { paths: [...paths], unprotectable };
}
