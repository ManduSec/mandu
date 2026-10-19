/**
 * reader-runs-code — MIRROR of arbiter/policy/flow-taint.ts
 * `CODE_RUNNING_READERS` / `readerRunsCode` (Plan 13 D8,
 * docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md §3): a reader of a
 * secret file that is a shell, an interpreter or a command launcher runs
 * whatever code the agent writes. Since 2026-10-02 (plan 13 §8 decision
 * (b)) such an entry admits nothing unless it pins the script the
 * interpreter runs; the dashboard marks it and warns, naming the script
 * form. The two packages (and the guard's secret_open.rs) ship standalone;
 * tests/stack/reader-identity.test.ts pins the copies to one table.
 *
 * Also the mirror of flow-taint.ts `PRINTER_READERS` / `readerPrints` (Plan
 * 13 D8, printers admit nothing, 2026-10-03): a program that prints or
 * copies a file's bytes hands them to whatever reads its output, so as a
 * reader it admits nothing, in any form; the page marks it and says so.
 *
 * These lists judge NAMES. The arbiter also judges a pin's hash (a renamed
 * copy of an installed printer or interpreter is that program), so where it
 * sends its own per-entry judgment (`ArbiterReaderJudgment`: `whyPath`,
 * `confidentialityState`) the page shows that, and the name rule here is the
 * fallback (Plan 13 D8 (8), 2026-10-03).
 */

export const CODE_RUNNING_READERS: ReadonlySet<string> = new Set<string>([
  // exec-identifier.ts INTERPRETERS
  "node", "bun", "deno", "bunx", "npx", "yarn", "pnpm", "tsx", "ts-node",
  "python", "python2", "python3", "ruby", "perl", "sh", "bash", "zsh",
  // shells
  "dash", "ash", "ksh", "mksh", "fish", "csh", "tcsh", "busybox",
  // language runtimes
  "php", "lua", "luajit", "tclsh", "wish", "Rscript", "R", "julia", "java", "jshell", "guile", "racket", "pwsh", "osascript",
  // programs that run another program, or a script, from their arguments
  "env", "xargs", "find", "make", "awk", "gawk", "mawk", "nawk", "nohup", "timeout", "nice", "stdbuf", "setsid", "watch", "script", "sudo", "doas",
  // editors, debuggers, tracers and shells of a command language that run
  // what they are given or load (an rc file, -c, a plugin, `.shell`), Plan 13
  // D8 "code by argument" (2026-10-02)
  "vi", "vim", "nvim", "ex", "view", "rvim", "rview", "vimdiff", "gvim", "gview", "evim", "vimx", "emacs", "emacsclient", "ed", "red",
  "gdb", "lldb", "strace", "ltrace", "sqlite3", "expect", "m4",
  // more launchers
  "time", "parallel", "flock", "chroot", "unshare", "nsenter", "bwrap", "firejail", "systemd-run", "su", "runuser", "pkexec", "taskset", "ionice", "chrt", "prlimit",
  // multi-call binaries that carry a shell or a launcher, beside busybox
  "toybox", "coreutils",
  // relays that run a program from their arguments and hand it the socket
  "nc", "ncat", "netcat", "socat",
  // fetch and transfer clients that run a command (ftp's `!cmd`, aria2c's
  // `--on-download-*` hooks, `--use-askpass`, `gio launch`, a text
  // browser's `!` and mailcap viewers, …), 2026-10-03
  "ftp", "tnftp", "netkit-ftp", "pftp", "inetutils-ftp", "aria2c", "lftp", "sftp", "wget", "wget2", "rclone",
  "gio", "kioclient", "kioclient5", "kioclient6", "lynx", "w3m", "elinks", "links", "links2", "http", "https", "httpie",
  // more editors that run a command or load code from an rc file
  "nvi", "elvis", "vis", "kak", "hx", "helix", "joe", "jstar", "jmacs", "jpico", "rjoe", "jed", "mg", "zile", "jove",
  "mcedit", "mc", "ne", "xemacs",
  // more launchers
  "valgrind", "perf", "rr", "setpriv", "sg", "unbuffer", "faketime", "torsocks", "proxychains", "proxychains4",
  "fakeroot", "eatmydata", "xvfb-run", "dbus-run-session", "tmux", "screen", "entr",
  // build tools and task runners that run the commands of a build file or of
  // their arguments (2026-10-04, probed): `cmake -P <script>` and `cmake -E
  // env <cmd>`, `ctest -S`, `ninja -f`, `go run` / `go generate`, `cargo
  // build` (the package's build.rs), `rustup run`, `run-parts <dir>`, and
  // the like; `npm` and `cargo` are consumer-table programs (`.npmrc`,
  // `.cargo/credentials`) that run the package's code, served the twin as
  // node is (decision (b))
  "cmake", "ctest", "cpack", "ninja", "samu", "go", "cargo", "rustup", "bazel", "bazelisk", "buck", "buck2", "please",
  "just", "task", "mage", "xmake", "premake", "qmake", "qtchooser", "bmake", "pmake", "remake", "gn",
  "scons", "meson", "muon", "gradle", "mvn", "ant", "sbt", "rake", "npm", "corepack", "pnpx",
  "nix", "nix-shell", "nix-build", "nix-instantiate", "guix", "dotnet", "terraform", "tofu", "packer", "podman", "buildah",
  "run-parts", "at", "batch",
  // more language runtimes and REPLs
  "nodejs", "pypy", "pypy3", "jython", "ipython", "irb", "erb", "jruby", "php-cgi", "php-fpm", "raku", "rakudo", "perl6", "hy",
  "erl", "erlexec", "beam", "escript", "elixir", "iex", "mix", "ocaml", "ocamlrun", "utop", "swipl", "gprolog",
  "sbcl", "clisp", "ecl", "csi", "gsi", "scheme", "chez", "chezscheme", "petite", "raco",
  "kotlin", "scala", "groovy", "clojure", "clj", "bb", "jrunscript", "mono", "runghc", "runhaskell", "ghci",
  "nim", "crystal", "zig", "dart", "swift", "tcc", "qjs", "gjs", "gforth", "wasmtime", "wasmer",
  "dc", "bc", "octave", "octave-cli", "gnuplot", "maxima",
  // more shells
  "rbash", "yash", "posh", "elvish", "nushell", "xonsh", "osh", "ysh",
  // the names these install as (P0 item 14, 2026-10-07): nushell's binary,
  // the public-domain ksh line (OpenBSD's ksh ported), Racket's two builds
  "nu", "oksh", "loksh", "pdksh", "racketbc", "racketcs",
  // TeX engines (`\write18`, `\directlua`)
  "tex", "etex", "pdftex", "xetex", "luatex", "luahbtex", "luajittex", "latex", "pdflatex", "xelatex", "lualatex", "mpost", "context", "mtxrun",
]);

/** flow-taint.ts appNameMatches: exactly, or a version / alternatives suffix. */
function nameMatches(base: string, name: string): boolean {
  return base === name || (base.startsWith(name) && /^(\.[A-Za-z0-9]+)+$/.test(base.slice(name.length)));
}

/** flow-taint.ts MULTICALL_PRINTER_DIRS: uutils coreutils picks its program
 *  from argv[0], so every file there is `cat` and `env` too. */
const MULTICALL_PRINTER_DIRS: readonly string[] = ["/usr/lib/cargo/bin/coreutils/"];

/** flow-taint.ts READER_NAME_PREFIXES: `gnucat`, `gsed`, `uu-cat`, `gnuenv`. */
const READER_NAME_PREFIXES: readonly string[] = ["gnu", "g", "uu-", "uu_"];

/** flow-taint.ts withoutVersion: `php8.5` → `php`, `gcc-15` → `gcc`, or null. */
function withoutVersion(name: string): string | null {
  const m = /^(.*[A-Za-z+])[-_]?\d+(?:\.\d+)*$/.exec(name);
  return m ? m[1]! : null;
}

/** flow-taint.ts readerNameForms: the basename and what it stands for under
 *  a prefix or without a trailing version. */
function readerNameForms(app: string): string[] {
  const base = app.slice(app.lastIndexOf("/") + 1);
  // A prefix alone names no program (`gnu` is not `g` + `nu`).
  const forms = [base, ...READER_NAME_PREFIXES.filter((p) => !READER_NAME_PREFIXES.includes(base) && base.length > p.length && base.startsWith(p)).map((p) => base.slice(p.length))];
  return [...forms, ...forms.map(withoutVersion).filter((n): n is string => n !== null)];
}

/** Does this reader name run code it is given? Also under a distribution's
 *  prefix (`gnuenv`), and any file of a multi-call binary's directory. */
export function readerRunsCode(app: string): boolean {
  if (MULTICALL_PRINTER_DIRS.some((d) => app.startsWith(d))) return true;
  for (const n of readerNameForms(app)) {
    if (CODE_RUNNING_READERS.has(n)) return true;
    for (const name of CODE_RUNNING_READERS) if (nameMatches(n, name)) return true;
  }
  return false;
}

/** Plan 13 D8, printers admit nothing (2026-10-03): MIRROR of flow-taint.ts
 *  `PRINTER_READERS` (pinned equal by tests/stack/reader-identity.test.ts). */
export const PRINTER_READERS: ReadonlySet<string> = new Set<string>([
  // print or page a file
  "cat", "tac", "head", "tail", "less", "more", "most", "pg", "nl", "rev", "pr", "pv", "bat", "batcat",
  "zless", "zmore", "bzless", "bzmore", "xzless", "xzmore", "zstdless", "lzless", "lzmore",
  // copy a file
  "tee", "dd", "cp", "install", "rsync", "socat", "xclip", "xsel", "wl-copy",
  // encode or dump its bytes
  "base64", "base32", "basenc", "uuencode", "uudecode", "xxd", "od", "hexdump", "hd", "hexyl", "strings",
  // filter, reorder or reshape its lines
  "sed", "awk", "gawk", "mawk", "nawk", "cut", "paste", "join", "sort", "uniq", "shuf", "tr", "fold", "fmt", "column",
  "expand", "unexpand", "look", "tsort", "ptx", "split", "csplit",
  "grep", "egrep", "fgrep", "rg", "ag", "ack", "zgrep", "zegrep", "zfgrep", "xzgrep", "bzgrep", "zstdgrep",
  // compare (prints the differing lines or bytes)
  "diff", "diff3", "sdiff", "cmp", "comm", "colordiff", "wdiff", "zdiff", "zcmp", "xzdiff", "xzcmp", "bzdiff", "bzcmp",
  // convert its encoding or line ends
  "iconv", "recode", "uconv", "dos2unix", "unix2dos", "mac2unix", "unix2mac",
  // compress or archive (the archive holds the bytes, `-c` prints them)
  "gzip", "gunzip", "zcat", "pigz", "unpigz", "bzip2", "bunzip2", "bzcat", "pbzip2", "xz", "unxz", "xzcat", "pixz",
  "lzma", "unlzma", "lzcat", "lzip", "lzop", "lz4", "unlz4", "lz4cat", "zstd", "unzstd", "zstdcat", "zstdmt", "brotli",
  "tar", "gtar", "bsdtar", "bsdcat", "bsdcpio", "zip", "unzip", "funzip", "7z", "7za", "7zr", "cpio", "pax", "ar",
  // structured data processors (print a value, or the document)
  "jq", "gojq", "jaq", "yq", "xq", "tomlq", "dasel", "gron", "mlr", "xmllint", "xmlstarlet", "envsubst",
  // crypto tools that print or transform a file (`openssl enc -base64 -in`,
  // `gpg --store`); neither is a consumer-table program
  "openssl", "gpg", "gpg2",
  // editors with no code-running list entry, which show the file on the
  // terminal the agent reads
  "nano", "pico", "micro",
  // multi-call binaries: every printer above under one name
  "busybox", "toybox", "coreutils",
  // fetch or transfer a URL or a file, a local one included (`curl
  // file:///…`, `wget -i <file>`, `scp a b`, `gio cat`, `lynx -dump file://…`)
  "curl", "curlie", "wget", "wget2", "aria2c", "http", "https", "xh", "xhs", "lftp", "rclone", "scp", "sftp",
  "gio", "gvfs-cat", "gvfs-copy", "kioclient", "kioclient5", "kioclient6", "lynx", "w3m", "links", "links2", "elinks",
  // the Postgres client tools that print a file (probed 2026-10-04 against a
  // throwaway server: `psql -f <file>` and `\i <file>` / `\copy t from
  // <file>` on its standard input print the file's lines; `pg_restore -f -
  // <dump>` prints the dump as SQL): plan 13 D8 (12). psql also runs a shell
  // command it is given (`\!`, a backquoted `\set`). pg_dump prints no file
  // (a `--filter` file's well-formed patterns echo when unmatched only).
  "psql", "pg_restore",
  // the other SQL and database shells (2026-10-07, P0 (D)), by their
  // documented commands: each prints a file it is pointed at and runs a
  // command or code it is given, from its command line, its standard input
  // or an rc file the agent can write (`~/.my.cnf`'s `[mysql] pager=`,
  // `~/.duckdbrc`, `~/.mongoshrc.js`), as psql does: mysql's and mariadb's
  // `source <file>` (the server's error quotes the lines) and `\!` / `pager`;
  // mysqlsh's `\source` and `\system`; duckdb's `.read`, `.shell` and
  // `read_text('<file>')`; usql's `\i` and `\!`; sqlcmd's `:r` and `!!`;
  // sqlplus's `@<file>` and `HOST`; clickhouse's `file('<file>')` table
  // function; the MongoDB shells' `cat('<file>')` and `load()` (JavaScript).
  // Unprobed (none installed on the probe host): listed fail-closed
  "mysql", "mariadb", "mysqlsh", "duckdb", "usql", "sqlcmd", "sqlplus", "clickhouse", "clickhouse-client", "clickhouse-local",
  "mongosh", "mongo",
  // read names, dates or hosts from a file and print each one it cannot
  // use (2026-10-04): `file -f <file>` ("<line>: cannot open"), `date -f`,
  // `wc` / `du --files0-from=<file>`, `logger -s -f`, `ssh-keyscan -f`
  "file", "date", "wc", "du", "logger", "ssh-keyscan",
  // typeset or format a document or a manual page, whose text is the
  // output (`nroff <file>`, `man -l <file>`, `ul`), or echo the lines they
  // reject (`tic <file>`, `whatis -C <file>`); `scriptreplay` replays one
  "groff", "nroff", "troff", "preconv", "soelim", "zsoelim", "tbl", "eqn", "neqn", "pic", "refer", "grn", "grotty", "mandoc",
  "man", "whatis", "apropos", "lexgrog", "ul", "colcrt", "tic", "scriptreplay",
  // compile, assemble or link: `cpp <file>` and `cc -E` print it, an
  // `@<file>` response file comes back word by word in the errors (gcc,
  // clang, binutils), `objcopy -I binary <file> /dev/stdout` copies it,
  // `objdump -s -b binary` dumps it, a parser generator quotes what it
  // rejects; gettext's catalog tools print the catalog (`msgcat <file>`)
  "cpp", "cc", "c++", "gcc", "g++", "cc1", "cc1plus", "collect2", "clang", "clang++", "clang-cpp", "rustc",
  "as", "ld", "gold", "nm", "ranlib", "c++filt", "objcopy", "objdump", "readelf", "size", "strip", "elfedit", "gprof", "addr2line",
  "bison", "yacc", "byacc", "rpcgen",
  "msgcat", "msguniq", "msgconv", "msggrep", "msgattrib", "msgen", "msgmerge", "msginit", "msgcomm", "msgfilter", "msgexec",
  "msgfmt", "msgunfmt", "xgettext",
  // git (plan 13 §4.9 option (a), 2026-10-04): `git diff --no-index
  // /dev/null <file>`, `git grep --no-index`, `git config -f <file>
  // --list`; its credential helper (git itself under that name), its
  // HTTP transport, and (2026-10-07) the programs git builds on their own
  // that read `.netrc` through libcurl or send a file named by a request
  "git", "git-credential-store", "git-remote-http", "git-remote-https", "git-remote-ftp", "git-remote-ftps",
  "git-http-fetch", "git-http-push", "git-imap-send", "git-http-backend",
]);

/** MIRROR of flow-taint.ts `PRINTER_NAME_PREFIXES` (2026-10-07): a git
 *  credential helper of any name prints the password it reads. */
export const PRINTER_NAME_PREFIXES: readonly string[] = ["git-credential-"];

function printerPrefixed(base: string): boolean {
  return PRINTER_NAME_PREFIXES.some((p) => base.length > p.length && base.startsWith(p));
}

/** flow-taint.ts `scriptPrints`: a script named as a printer
 *  (`…/git-credential-netrc`). */
export function scriptPrints(path: string | undefined): boolean {
  return path !== undefined && printerPrefixed(path.slice(path.lastIndexOf("/") + 1));
}

/** Does this reader name (or pinned path) print or copy a file's bytes? */
export function readerPrints(app: string): boolean {
  if (MULTICALL_PRINTER_DIRS.some((d) => app.startsWith(d))) return true;
  for (const n of readerNameForms(app)) {
    if (PRINTER_READERS.has(n) || printerPrefixed(n)) return true;
    for (const name of PRINTER_READERS) if (nameMatches(n, name)) return true;
  }
  return false;
}

/** Plan 13 R5: a reader entry that pins the script its interpreter runs
 *  (`{ app: python3, script: /opt/tools/report.py }`) names that program,
 *  not the interpreter: it admits only that file, run as the arbiter checks
 *  it (out of the agent's reach, no inline code, isolated, not traced). */
export function pinsScript(r: unknown): r is { app: string; script: string } {
  return !!r && typeof r === "object" && typeof (r as { app?: unknown }).app === "string" && typeof (r as { script?: unknown }).script === "string";
}

/** Plan 13 §8 decision (b), mirror of flow-taint.ts `entryAdmitsNothing`: a
 *  reader entry naming a program that runs code, with no `script:` pin
 *  (`bash`, `{ app: python3, path, sha256 }`), lets no program read the
 *  file. */
export function entryAdmitsNothing(r: unknown): boolean {
  if (entryPrints(r)) return true;
  if (pinsScript(r)) return false;
  if (typeof r === "string") return readerRunsCode(r);
  if (!r || typeof r !== "object") return false;
  const o = r as { app?: unknown; path?: unknown };
  return (typeof o.app === "string" && readerRunsCode(o.app)) || (typeof o.path === "string" && readerRunsCode(o.path));
}

/** Plan 13 D8, printers admit nothing: a reader entry naming a printer, by
 *  name or pinned path, in any form (a pin by path and hash, a script). */
export function entryPrints(r: unknown): boolean {
  if (typeof r === "string") return readerPrints(r);
  if (!r || typeof r !== "object") return false;
  const o = r as { app?: unknown; path?: unknown; script?: unknown };
  return (typeof o.app === "string" && readerPrints(o.app)) || (typeof o.path === "string" && readerPrints(o.path))
    || (typeof o.script === "string" && scriptPrints(o.script));
}

/** What an inert entry's name carries on the page. */
export const ADMITS_NOTHING = " (admits nothing)";

/** Plan 13 D8 (12), the allow-list (2026-10-04): MIRROR of flow-taint.ts
 *  `VETTED_READERS` (pinned equal by tests/stack/reader-identity.test.ts):
 *  the programs probed not to print a file, the only ones that read a
 *  secret raw without the human's word (`prints: nothing`). */
export const VETTED_READERS: ReadonlySet<string> = new Set<string>(["ssh", "ssh-add"]);

/** flow-taint.ts `readerVetted`: a vetted reader by its basename, never a
 *  printer or a program that runs code. */
export function readerVetted(app: string): boolean {
  if (readerPrints(app) || readerRunsCode(app)) return false;
  const base = app.slice(app.lastIndexOf("/") + 1);
  for (const name of VETTED_READERS) if (nameMatches(base, name)) return true;
  return false;
}

/** flow-taint.ts `entryReadsTwin`: an entry whose program reads the
 *  placeholder copy, neither vetted nor vouched for (`prints: nothing`); an
 *  entry that admits nothing has its own mark. */
export function entryReadsTwin(r: unknown): boolean {
  if (entryAdmitsNothing(r)) return false;
  if (typeof r === "string") return !readerVetted(r);
  if (!r || typeof r !== "object") return false;
  const o = r as { app?: unknown; path?: unknown; prints?: unknown; script?: unknown };
  if (o.prints === "nothing") return false;
  if (typeof o.script === "string") return true;
  const name = typeof o.path === "string" ? o.path : typeof o.app === "string" ? o.app : null;
  return name === null || !readerVetted(name);
}

/** What an entry whose program reads the placeholder carries on the page. */
export const READS_PLACEHOLDER = " (reads the placeholder copy)";

/** The interpreters whose script an entry may pin (flow-taint.ts
 *  SCRIPT_FAMILIES); the warning names the script form only for these. */
const PINNABLE = ["python", "python2", "python3", "pypy", "pypy3", "node", "nodejs", "sh", "bash", "dash", "ash", "ksh", "mksh", "zsh", "perl"];

/** Plan 13 D8 (2026-10-03): the ARBITER's judgment of a reader list, per
 *  entry and in its order: `whyPath`'s `readersAdmitNothing`,
 *  `readersPrint` and `readersCopyOf`, `confidentialityState`'s
 *  `readersAdmitNothing`. The arbiter judges an entry by its name, its path
 *  and a pin's hash (a renamed copy of an installed printer or interpreter
 *  is that program), as it decides an open; this file's lists judge names
 *  only. So a judgment present wins, and the name rule above is the
 *  fallback for an older arbiter. The rule list's snapshot carries the same
 *  judgment per path since P0 item 14 (Plan 13 D8 (13), 2026-10-07). */
export interface ArbiterReaderJudgment {
  admitNothing?: ReadonlyArray<boolean>;
  print?: ReadonlyArray<boolean>;
  copyOf?: ReadonlyArray<string | null>;
  /** Plan 13 D8 (12): `readersReadTwin`. */
  readTwin?: ReadonlyArray<boolean>;
}

/** Entry `i` (`r`) reads the placeholder copy (D8 (12)): the arbiter's
 *  word, else the name rule. */
export function judgedReadsTwin(r: unknown, i: number, j?: ArbiterReaderJudgment): boolean {
  const v = j?.readTwin?.[i];
  return typeof v === "boolean" ? v : entryReadsTwin(r);
}

/** Entry `i` (`r`) admits nothing: the arbiter's word, else the name rule. */
export function judgedAdmitsNothing(r: unknown, i: number, j?: ArbiterReaderJudgment): boolean {
  const v = j?.admitNothing?.[i];
  return typeof v === "boolean" ? v : entryAdmitsNothing(r);
}

/** Entry `i` (`r`) names a printer: the arbiter's word, else the name rule. */
export function judgedPrints(r: unknown, i: number, j?: ArbiterReaderJudgment): boolean {
  const v = j?.print?.[i];
  return typeof v === "boolean" ? v : entryPrints(r);
}

/** The installed program entry `i` is a renamed copy of, by the arbiter's
 *  hash (`python3.12`), or null. */
export function judgedCopyOf(i: number, j?: ArbiterReaderJudgment): string | null {
  const v = j?.copyOf?.[i];
  return typeof v === "string" && v !== "" ? v : null;
}

/** The warning a reader list earns, or null: names the entries that admit
 *  nothing (a code-running reader with no script pin, Plan 13 §8 decision
 *  (b); a printer in any form, Plan 13 D8 of 2026-10-03; a renamed copy of
 *  either, by the arbiter's hash) and what to write instead. */
export function codeRunningReadersWarning(readers: ReadonlyArray<unknown> | undefined, judged?: ArbiterReaderJudgment): string | null {
  const parts = [codeWarning(readers, judged), printerWarning(readers, judged), unvettedWarning(readers, judged)].filter((w): w is string => w !== null);
  return parts.length ? parts.join(" ") : null;
}

/** An inert entry's name on the page, with what it is a copy of. */
function inertName(r: unknown, i: number, j?: ArbiterReaderJudgment): string | null {
  const app = typeof r === "string" ? r : (r as { app?: unknown } | null)?.app;
  if (typeof app !== "string") return null;
  const of = judgedCopyOf(i, j);
  return of !== null ? `${app} (a copy of ${of})` : app;
}

/** Plan 13 D8 (12): the programs a list names that read the placeholder
 *  copy, and the fix. */
function unvettedWarning(readers: ReadonlyArray<unknown> | undefined, j?: ArbiterReaderJudgment): string | null {
  const unique = [...new Set((readers ?? [])
    .map((r, i) => (judgedReadsTwin(r, i, j) && !judgedAdmitsNothing(r, i, j) ? inertName(r, i, j) : null))
    .filter((n): n is string => n !== null))];
  if (unique.length === 0) return null;
  const list = unique.join(", ");
  return unique.length === 1
    ? `${list} is not a program Mandu knows keeps a file's contents out of what it prints, so it reads the placeholder copy. If you are sure it does, write { app: ${unique[0]}, prints: nothing }.`
    : `${list} are not programs Mandu knows keep a file's contents out of what they print, so each reads the placeholder copy. If you are sure one does, write { app: <its name>, prints: nothing }.`;
}

/** Plan 13 D8, printers admit nothing (2026-10-03): the printers a list names. */
function printerWarning(readers: ReadonlyArray<unknown> | undefined, j?: ArbiterReaderJudgment): string | null {
  const unique = [...new Set((readers ?? [])
    .map((r, i) => (judgedPrints(r, i, j) ? inertName(r, i, j) : null))
    .filter((n): n is string => n !== null))];
  if (unique.length === 0) return null;
  const list = unique.join(", ");
  // Plan 13 §4.9 option (a) (2026-10-04): git is a printer (`git diff
  // --no-index` prints any file); say what still works.
  const git = unique.some((n) => /^git(-|\.|$|\s)/.test(n))
    ? " git prints any file it is pointed at (git diff --no-index); with TLS inspection on it still logs in to an HTTPS remote with the masked copy, and ssh (not git) reads an ssh key."
    : "";
  return unique.length === 1
    ? `${list} prints or copies what it reads to whatever reads its output, which can be the AI's own code, so it reads nothing here: ${list} gets the masked copy (or is refused), even pinned. Name the program that uses the secret instead (e.g. pg_dump, aws), not one that prints it.${git}`
    : `${list} print or copy what they read to whatever reads their output, which can be the AI's own code, so they read nothing here: each gets the masked copy (or is refused), even pinned. Name the program that uses the secret instead (e.g. pg_dump, aws), not one that prints it.${git}`;
}

/** Plan 13 §8 decision (b): the code-running entries a list names. */
function codeWarning(readers: ReadonlyArray<unknown> | undefined, j?: ArbiterReaderJudgment): string | null {
  const rows: Array<{ name: string; base: string; app: string }> = [];
  (readers ?? []).forEach((r, i) => {
    if (!judgedAdmitsNothing(r, i, j) || judgedPrints(r, i, j)) return;
    const name = inertName(r, i, j);
    const app = typeof r === "string" ? r : (r as { app?: unknown } | null)?.app;
    if (name !== null && typeof app === "string") rows.push({ name, base: judgedCopyOf(i, j) ?? app, app });
  });
  if (rows.length === 0) return null;
  const unique = [...new Set(rows.map((x) => x.name))];
  const list = unique.join(", ");
  const pinnable = rows.map((x) => x.base).find((n) => { const b = n.slice(n.lastIndexOf("/") + 1); return PINNABLE.some((p) => nameMatches(b, p)); });
  const instead = `Name the program that needs the file instead${pinnable ? `, or pin a script of your own, out of the agent's reach, with its interpreter: { app: ${pinnable}, script: /absolute/path/of/the/script }` : ""}.`;
  return unique.length === 1
    ? `${list} runs any code it is given, so it reads nothing here: no ${list} gets the real file through this entry, inline code (${rows[0]!.app} -c …) included. ${instead}`
    : `${list} run any code they are given, so they read nothing here: none of them gets the real file through these entries, inline code included. ${instead}`;
}
