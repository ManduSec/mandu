//! script_identity — which script an interpreter that opens a secret runs
//! (confidentiality plan 13 §9 R5, the `(interpreter, script)` pin;
//! docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md §3 D8).
//!
//! A reader is matched by its executable and that file's hash (Plan 13 D8).
//! For an interpreter (`python3`, `node`, `sh`, `perl`) that names the
//! interpreter, not the program: `readers: [python3]` admits any code the
//! agent hands python. R5 lets the policy name the script too,
//! `{ app: python3, script: /opt/tools/report.py }`, and the arbiter matches
//! such an entry only on the facts computed here, which the guard sends with
//! `decideSecretOpen` (on the human-plane socket, D9):
//!
//! - **the script operand** (`parse_script_run`, pure): `/proc/<pid>/cmdline`
//!   read with the family's own option grammar. Inline code (`-c`, `-e`,
//!   `-E`, `-p`, `--eval`, `--print`), a module or a preload (`-m`, `-r`,
//!   `--require`, `--import`, `--loader`, `-M`, `-I`), standard input (`-`,
//!   `-s`, no operand), an interactive or login shell, and any option not on
//!   the family's short allowlist are NO script. A relative operand is no
//!   script either: the interpreter resolved it against the cwd of its
//!   start, and a script can `chdir` before it opens the secret, so the guard
//!   reading the cwd at the open could name a pinned file the process never
//!   ran. A path that is not already canonical (`.`, `..`, `//`, a symlink on
//!   the way) is no script: the pinned spelling must be the file's own.
//! - **isolation** (`parse_script_run`): the interpreter must not load code
//!   from per-user places the agent can write. Python's user site-packages
//!   (`~/.local/lib/pythonX.Y/site-packages`, its `.pth` files and
//!   `usercustomize`) is on by default: only `-I`, `-s`, or
//!   `PYTHONNOUSERSITE` in the process environment (not overridden by `-E`)
//!   isolate it. Node's CommonJS resolver falls back to `~/.node_modules`
//!   and `~/.node_libraries`: only `--no-global-search-paths` (in argv or
//!   the process's `NODE_OPTIONS`) isolates it. zsh reads `~/.zshenv` for
//!   every script: only `-f` / `--no-rcs` / `-o norcs`. The other shells and
//!   perl read no per-user file for a script (their variables, `BASH_ENV`,
//!   `ENV`, `BASH_FUNC_*`, `PERL5LIB`, `PERL5OPT`, are D8's `openerEnv`).
//! - **out of reach** (`script_facts`): the script file and every directory
//!   above it are unwritable by the agent's uid (`reader_identity`'s reach
//!   rule), so the agent can neither have written it nor swap it.
//! - **its hash**: sha256 of the file, cached by inode and change time like
//!   the executable's.
//! - **traced**: `TracerPid` in `/proc/<pid>/status`. A process another one
//!   ptraces runs whatever code its tracer puts into it, so a traced opener
//!   is no script reader (an ancestor, under Yama's default scope, may trace
//!   its descendants).
//!
//! Utility cost, stated in plan 13: `python3 /opt/tools/report.py` with no
//! `-s` / `-I` is no script reader; a script run by a relative path (or
//! `./report.py`) is none; a symlinked script path must be pinned by its
//! canonical spelling.
//!
//! Decision logic is pure and unit-tested with no privilege; the `/proc`
//! reads are thin (no `kernel` feature needed: they read the guard's own
//! tree).
//!
//! `Mandu-new`.

use std::fs;

use crate::reader_identity::{dirs_out_of_reach, writable_by, HashCache, Perm, Who};

/// An interpreter family that runs a script file (R5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Python,
    Node,
    /// A POSIX-style shell; `zsh` reads `~/.zshenv` for every script.
    Shell { zsh: bool },
    Perl,
}

const PYTHON: &[&str] = &["python", "python2", "python3", "pypy", "pypy3"];
const NODE: &[&str] = &["node", "nodejs"];
const SHELLS: &[&str] = &["sh", "bash", "dash", "ash", "ksh", "mksh", "zsh"];
const PERL: &[&str] = &["perl"];

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// The family of the executable `exe` (by basename, `python3` covering
/// `python3.12`), or None for a program that is no script interpreter here
/// (ruby: its user gem directory loads code; busybox: its applets parse
/// options their own way).
pub fn family_of(exe: &str) -> Option<Family> {
    let base = basename(exe);
    let m = |names: &[&str]| names.iter().any(|n| crate::secret_open::app_name_matches(base, n));
    if m(PYTHON) {
        Some(Family::Python)
    } else if m(NODE) {
        Some(Family::Node)
    } else if m(SHELLS) {
        Some(Family::Shell { zsh: crate::secret_open::app_name_matches(base, "zsh") })
    } else if m(PERL) {
        Some(Family::Perl)
    } else {
        None
    }
}

/// What a process's argv says it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptRun {
    /// A script file, by the absolute path the interpreter was given;
    /// `isolated`: the interpreter loads no per-user code (module docs).
    Script { path: String, isolated: bool },
    /// No script R5 can pin, and why.
    NoScript(String),
}

fn no(why: impl Into<String>) -> ScriptRun {
    ScriptRun::NoScript(why.into())
}

/// Is `p` an absolute path already in its lexical normal form (no `.` or
/// `..` component, no empty one, no trailing slash)?
pub fn lexically_normal(p: &str) -> bool {
    p.starts_with('/') && p.len() > 1 && !p.ends_with('/') && p[1..].split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

/// The script operand, checked: absolute and lexically normal.
fn operand(arg: &str, isolated: bool) -> ScriptRun {
    if arg == "-" {
        return no("the program comes from standard input");
    }
    if !arg.starts_with('/') {
        return no(format!("the script is named by a relative path ({arg}): run it by its absolute path"));
    }
    if !lexically_normal(arg) {
        return no(format!("the script path {arg} is not in its normal form"));
    }
    ScriptRun::Script { path: arg.to_string(), isolated }
}

/// Python's `-X` values that change nothing about which code runs.
const PY_X_OK: &[&str] = &[
    "utf8", "utf8=0", "utf8=1", "dev", "faulthandler", "importtime", "tracemalloc", "warn_default_encoding",
    "no_debug_ranges", "frozen_modules=on", "frozen_modules=off", "showrefcount",
];

fn py_x_ok(v: &str) -> bool {
    PY_X_OK.contains(&v) || v.strip_prefix("tracemalloc=").is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit())) || v.strip_prefix("int_max_str_digits=").is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
}

fn parse_python(args: &[String], env_nousersite: bool) -> ScriptRun {
    let (mut big_i, mut s, mut big_e) = (false, false, false);
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            return match args.get(i + 1) {
                Some(op) => operand(op, big_i || s || (env_nousersite && !big_e)),
                None => no("no script operand"),
            };
        }
        if a == "-" || !a.starts_with('-') {
            return operand(a, big_i || s || (env_nousersite && !big_e));
        }
        if a.starts_with("--") {
            return no(format!("python option {a} is not one a pinned script may run with"));
        }
        // A cluster of one-letter options; `W` and `X` take a value (the
        // rest of the cluster, or the next argument).
        let cluster = &a[1..];
        let chars = cluster.char_indices();
        for (at, c) in chars {
            match c {
                'I' => big_i = true,
                's' => s = true,
                'E' => big_e = true,
                'b' | 'B' | 'd' | 'O' | 'P' | 'q' | 'R' | 'S' | 'u' | 'v' | 'x' => {}
                'W' | 'X' => {
                    let rest = &cluster[at + c.len_utf8()..];
                    let value = if rest.is_empty() {
                        i += 1;
                        match args.get(i) {
                            Some(v) => v.as_str(),
                            None => return no(format!("python -{c} without a value")),
                        }
                    } else {
                        rest
                    };
                    if c == 'X' && !py_x_ok(value) {
                        return no(format!("python -X {value} is not one a pinned script may run with"));
                    }
                    break;
                }
                'c' => return no("inline code (python -c)"),
                'm' => return no("a module, not a script (python -m)"),
                'i' => return no("an interactive interpreter (python -i)"),
                other => return no(format!("python option -{other} is not one a pinned script may run with")),
            }
        }
        i += 1;
    }
    no("no script operand")
}

/// Node options that load no code (as reader_identity's `NODE_OPTIONS`
/// allowlist), and the isolation flag.
const NODE_OK_EXACT: &[&str] = &[
    "--no-global-search-paths", "--no-warnings", "--no-deprecation", "--enable-source-maps", "--use-openssl-ca",
    "--use-bundled-ca", "--use-system-ca", "--trace-warnings", "--trace-deprecation", "--trace-uncaught",
];
const NODE_OK_PREFIX: &[&str] = &[
    "--disable-warning=", "--max-old-space-size=", "--max-semi-space-size=", "--dns-result-order=",
    "--unhandled-rejections=", "--stack-trace-limit=",
];
const NODE_ISOLATE: &str = "--no-global-search-paths";

fn node_ok(a: &str) -> bool {
    NODE_OK_EXACT.contains(&a) || NODE_OK_PREFIX.iter().any(|p| a.starts_with(p) && a.len() > p.len())
}

fn parse_node(args: &[String], node_options: &str) -> ScriptRun {
    let mut isolated = node_options.split_whitespace().any(|t| t == NODE_ISOLATE);
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            return match args.get(i + 1) {
                Some(op) => operand(op, isolated),
                None => no("no script operand"),
            };
        }
        if a == "-" || !a.starts_with('-') {
            return operand(a, isolated);
        }
        match a {
            "-e" | "-p" | "-pe" | "--eval" | "--print" => return no(format!("inline code (node {a})")),
            "-i" | "--interactive" => return no("an interactive interpreter (node -i)"),
            "-r" | "--require" | "--import" | "--loader" | "--experimental-loader" => return no(format!("code preloaded before the script (node {a})")),
            _ => {}
        }
        if a.starts_with("--eval=") || a.starts_with("--print=") {
            return no("inline code (node --eval)");
        }
        if !node_ok(a) {
            return no(format!("node option {a} is not one a pinned script may run with"));
        }
        if a == NODE_ISOLATE {
            isolated = true;
        }
        i += 1;
    }
    no("no script operand")
}

/// `set -o` names a pinned shell script may run with.
const SHELL_O_OK: &[&str] = &["errexit", "nounset", "pipefail", "xtrace", "noglob", "noclobber", "verbose", "allexport", "noexec", "posix"];

fn parse_shell(argv0: &str, args: &[String], zsh: bool) -> ScriptRun {
    if argv0.starts_with('-') {
        return no("a login shell (it reads the user's profile)");
    }
    let mut norcs = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            return match args.get(i + 1) {
                Some(op) => operand(op, !zsh || norcs),
                None => no("no script operand (the program comes from standard input)"),
            };
        }
        if a == "-" {
            return no("the program comes from standard input");
        }
        if a.starts_with("--") {
            match a {
                "--norc" | "--noprofile" | "--posix" | "--noediting" => {}
                "--no-rcs" | "--norcs" if zsh => norcs = true,
                "--login" => return no("a login shell (it reads the user's profile)"),
                _ => return no(format!("shell option {a} is not one a pinned script may run with")),
            }
            i += 1;
            continue;
        }
        if !(a.starts_with('-') || a.starts_with('+')) || a.len() == 1 {
            return operand(a, !zsh || norcs);
        }
        let set = a.starts_with('-');
        for c in a[1..].chars() {
            match c {
                'c' => return no("inline code (sh -c)"),
                's' => return no("the program comes from standard input (sh -s)"),
                'i' => return no("an interactive shell (sh -i)"),
                'l' => return no("a login shell (it reads the user's profile)"),
                'o' | 'O' => {
                    i += 1;
                    let Some(v) = args.get(i) else { return no(format!("shell -{c} without a value")) };
                    if c == 'O' {
                        // bash shopt names change parsing, not which code runs
                        if !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                            return no(format!("shell -O {v}"));
                        }
                    } else if zsh && set && (v == "norcs" || v == "no_rcs") {
                        norcs = true;
                    } else if !SHELL_O_OK.contains(&v.as_str()) {
                        return no(format!("shell -o {v} is not one a pinned script may run with"));
                    }
                }
                'f' if zsh && set => norcs = true,
                'a' | 'b' | 'e' | 'f' | 'h' | 'm' | 'n' | 'u' | 'v' | 'x' | 'B' | 'C' | 'E' | 'H' | 'P' | 'T' | 'p' => {}
                other => return no(format!("shell option -{other} is not one a pinned script may run with")),
            }
        }
        i += 1;
    }
    no("no script operand (the program comes from standard input)")
}

fn parse_perl(args: &[String]) -> ScriptRun {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            return match args.get(i + 1) {
                Some(op) => operand(op, true),
                None => no("no script operand (the program comes from standard input)"),
            };
        }
        if a == "-" {
            return no("the program comes from standard input");
        }
        if !a.starts_with('-') {
            return operand(a, true);
        }
        let b = a.as_bytes();
        let mut j = 1;
        while j < b.len() {
            match b[j] {
                b'e' | b'E' => return no("inline code (perl -e)"),
                b'M' | b'm' => return no("a module loaded before the script (perl -M)"),
                b'I' => return no("an include path given on the command line (perl -I)"),
                b'x' => return no("a script extracted from other input (perl -x)"),
                b'd' | b'D' => return no("a debugger (perl -d)"),
                b'S' => return no("a script looked up on PATH (perl -S)"),
                b'w' | b'W' | b'X' | b'T' | b't' | b'a' | b'n' | b'p' | b's' => j += 1,
                // `-0[octal]`, `-l[octal]`, `-C[number]`: the digits are theirs
                b'0' | b'l' | b'C' => {
                    j += 1;
                    while j < b.len() && (b[j].is_ascii_hexdigit() || b[j] == b'x') {
                        j += 1;
                    }
                }
                other => return no(format!("perl option -{} is not one a pinned script may run with", other as char)),
            }
        }
        i += 1;
    }
    no("no script operand (the program comes from standard input)")
}

/// What `argv` (the interpreter's whole command line, argv[0] first) runs,
/// read with `family`'s grammar. `env`: the process's environment, for the
/// variables that isolate it (`PYTHONNOUSERSITE`, `NODE_OPTIONS`). Pure.
pub fn parse_script_run(family: Family, argv: &[String], env: &[(String, String)]) -> ScriptRun {
    let Some(argv0) = argv.first() else { return no("no command line") };
    let rest = &argv[1..];
    let var = |n: &str| env.iter().rev().find(|(k, _)| k == n).map(|(_, v)| v.as_str()).unwrap_or("");
    match family {
        Family::Python => parse_python(rest, !var("PYTHONNOUSERSITE").is_empty()),
        Family::Node => parse_node(rest, var("NODE_OPTIONS")),
        Family::Shell { zsh } => parse_shell(argv0, rest, zsh),
        Family::Perl => parse_perl(rest),
    }
}

/// `/proc/<pid>/cmdline` bytes as arguments.
pub fn parse_cmdline(bytes: &[u8]) -> Vec<String> {
    let trimmed = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    if trimmed.is_empty() {
        return Vec::new();
    }
    trimmed.split(|b| *b == 0).map(|a| String::from_utf8_lossy(a).into_owned()).collect()
}

/// The `TracerPid:` of `/proc/<pid>/status` text: Some(true) when another
/// process traces it. None when the line is missing.
pub fn status_traced(status: &str) -> Option<bool> {
    let v = status.lines().find_map(|l| l.strip_prefix("TracerPid:"))?;
    v.trim().parse::<i64>().ok().map(|p| p != 0)
}

/// The facts R5 sends about the script an interpreter runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptFacts {
    /// The script operand, absolute, canonical.
    pub path: String,
    /// sha256 of the file, hex (None: it could not be read).
    pub sha256: Option<String>,
    /// The file and every directory above it are out of the agent's reach.
    pub system: bool,
    /// The interpreter loads no per-user code (module docs).
    pub isolated: bool,
    /// Another process ptraces the opener.
    pub traced: bool,
}

/// Is the regular file `path` and every directory above it out of `who`'s
/// reach? `stat` reads the file's permissions (`Perm`, its ACLs included)
/// and whether it is a regular file; `stat_dir` as `dirs_out_of_reach`'s.
/// Pure.
pub fn script_out_of_reach(
    path: &str,
    who: &Who,
    stat: impl Fn(&str) -> Option<(Perm, bool)>,
    stat_dir: impl Fn(&str) -> Option<(Perm, bool)>,
) -> bool {
    match stat(path) {
        Some((perm, true)) if !writable_by(perm, who) => dirs_out_of_reach(path, who, stat_dir),
        _ => false,
    }
}

/// The R5 facts for `pid`, running the interpreter `exe`: None when `exe` is
/// no script interpreter (nothing is sent); `Some(Err(why))` when it runs no
/// script R5 can pin; `Some(Ok(facts))` otherwise. `who` and `hashes` are
/// the guard's identity context.
pub fn script_facts(pid: i32, exe: &str, who: &Who, hashes: &HashCache) -> Option<Result<ScriptFacts, String>> {
    use std::os::unix::fs::MetadataExt;
    let family = family_of(exe)?;
    let Ok(cmd) = fs::read(format!("/proc/{pid}/cmdline")) else { return Some(Err("its command line could not be read".into())) };
    let Ok(environ) = fs::read(format!("/proc/{pid}/environ")) else { return Some(Err("its environment could not be read".into())) };
    let env = crate::reader_identity::parse_environ(&environ);
    let (path, isolated) = match parse_script_run(family, &parse_cmdline(&cmd), &env) {
        ScriptRun::Script { path, isolated } => (path, isolated),
        ScriptRun::NoScript(why) => return Some(Err(why)),
    };
    // The spelling must be the file's own: a symlink on the way could be
    // pointed elsewhere between the interpreter's open and this look.
    match fs::canonicalize(&path).ok().and_then(|c| c.to_str().map(String::from)) {
        Some(c) if c == path => {}
        Some(c) => return Some(Err(format!("the script path {path} is a link to {c}: pin and run the file by its own path"))),
        None => return Some(Err(format!("the script {path} cannot be found"))),
    }
    let traced = match fs::read_to_string(format!("/proc/{pid}/status")).ok().as_deref().and_then(status_traced) {
        Some(t) => t,
        None => return Some(Err("its trace state could not be read".into())),
    };
    let stat_file = |p: &str| fs::metadata(p).ok().map(|m| (crate::reader_identity::perm_of(p, &m), m.is_file()));
    let system = script_out_of_reach(&path, who, stat_file, crate::reader_identity::lstat_dir);
    let sha256 = fs::metadata(&path).ok().and_then(|m| {
        hashes.get_or((m.dev(), m.ino(), m.ctime(), m.ctime_nsec(), m.size()), || crate::reader_identity::sha256_file(&path))
    });
    Some(Ok(ScriptFacts { path, sha256, system, isolated, traced }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split(' ').map(String::from).collect()
    }
    fn run(fam: Family, s: &str) -> ScriptRun {
        parse_script_run(fam, &argv(s), &[])
    }
    fn script(path: &str, isolated: bool) -> ScriptRun {
        ScriptRun::Script { path: path.into(), isolated }
    }
    fn is_no(r: &ScriptRun) -> bool {
        matches!(r, ScriptRun::NoScript(_))
    }

    #[test]
    fn families_by_basename() {
        assert_eq!(family_of("/usr/bin/python3.12"), Some(Family::Python));
        assert_eq!(family_of("/usr/bin/node"), Some(Family::Node));
        assert_eq!(family_of("/usr/bin/bash"), Some(Family::Shell { zsh: false }));
        assert_eq!(family_of("/usr/bin/zsh"), Some(Family::Shell { zsh: true }));
        assert_eq!(family_of("/usr/bin/perl"), Some(Family::Perl));
        assert_eq!(family_of("/usr/bin/ruby"), None, "ruby is no script interpreter here (user gems)");
        assert_eq!(family_of("/usr/bin/cat"), None);
        assert_eq!(family_of("/usr/bin/python3-config"), None);
    }

    #[test]
    fn python_script_and_isolation() {
        assert_eq!(run(Family::Python, "python3 -I /opt/t/r.py x"), script("/opt/t/r.py", true));
        assert_eq!(run(Family::Python, "python3 -s /opt/t/r.py"), script("/opt/t/r.py", true));
        assert_eq!(run(Family::Python, "python3 -Bs /opt/t/r.py"), script("/opt/t/r.py", true));
        assert_eq!(run(Family::Python, "python3 -W ignore -I /opt/t/r.py"), script("/opt/t/r.py", true));
        assert_eq!(run(Family::Python, "python3 -Xutf8 -s -- /opt/t/r.py"), script("/opt/t/r.py", true));
        // the user site-packages is on: not isolated
        assert_eq!(run(Family::Python, "python3 /opt/t/r.py"), script("/opt/t/r.py", false));
        assert_eq!(run(Family::Python, "python3 -E /opt/t/r.py"), script("/opt/t/r.py", false));
        // PYTHONNOUSERSITE isolates, unless -E makes python ignore it
        let env = vec![("PYTHONNOUSERSITE".to_string(), "1".to_string())];
        assert_eq!(parse_script_run(Family::Python, &argv("python3 /opt/t/r.py"), &env), script("/opt/t/r.py", true));
        assert_eq!(parse_script_run(Family::Python, &argv("python3 -E /opt/t/r.py"), &env), script("/opt/t/r.py", false));
    }

    #[test]
    fn python_inline_module_stdin_and_unknown_options_are_no_script() {
        for s in [
            "python3 -c print(1)",
            "python3 -Ic print(1)",
            "python3 -I -c print(1) /opt/t/r.py",
            "python3 -m http.server",
            "python3 -i /opt/t/r.py",
            "python3 -",
            "python3 -I",
            "python3",
            "python3 -X pycache_prefix=/tmp/p /opt/t/r.py",
            "python3 --check-hash-based-pycs never /opt/t/r.py",
            "python3 -I r.py",
            "python3 -I ./r.py",
            "python3 -I /opt/t/../t/r.py",
            "python3 -I /opt//t/r.py",
        ] {
            assert!(is_no(&run(Family::Python, s)), "{s}: {:?}", run(Family::Python, s));
        }
    }

    #[test]
    fn node_script_and_isolation() {
        assert_eq!(run(Family::Node, "node --no-global-search-paths /opt/t/r.js a"), script("/opt/t/r.js", true));
        assert_eq!(run(Family::Node, "node /opt/t/r.js"), script("/opt/t/r.js", false));
        assert_eq!(run(Family::Node, "node --no-warnings -- /opt/t/r.js"), script("/opt/t/r.js", false));
        let env = vec![("NODE_OPTIONS".to_string(), "--no-global-search-paths".to_string())];
        assert_eq!(parse_script_run(Family::Node, &argv("node /opt/t/r.js"), &env), script("/opt/t/r.js", true));
        for s in ["node -e x", "node --eval=x", "node -p x", "node -r /tmp/x.js /opt/t/r.js", "node --import /tmp/x.mjs /opt/t/r.js", "node --inspect /opt/t/r.js", "node -", "node", "node r.js", "node -i"] {
            assert!(is_no(&run(Family::Node, s)), "{s}");
        }
    }

    #[test]
    fn shell_script_and_isolation() {
        assert_eq!(run(Family::Shell { zsh: false }, "bash /opt/t/r.sh a b"), script("/opt/t/r.sh", true));
        assert_eq!(run(Family::Shell { zsh: false }, "sh -eu /opt/t/r.sh"), script("/opt/t/r.sh", true));
        assert_eq!(run(Family::Shell { zsh: false }, "bash -o pipefail --norc /opt/t/r.sh"), script("/opt/t/r.sh", true));
        assert_eq!(run(Family::Shell { zsh: true }, "zsh /opt/t/r.sh"), script("/opt/t/r.sh", false), "zsh reads ~/.zshenv");
        assert_eq!(run(Family::Shell { zsh: true }, "zsh -f /opt/t/r.sh"), script("/opt/t/r.sh", true));
        assert_eq!(run(Family::Shell { zsh: true }, "zsh -o norcs /opt/t/r.sh"), script("/opt/t/r.sh", true));
        for s in ["bash -c . .env", "sh -ec x", "bash -s", "bash -i /opt/t/r.sh", "bash -l /opt/t/r.sh", "bash --login /opt/t/r.sh", "bash --rcfile /tmp/x /opt/t/r.sh", "bash", "bash -", "bash r.sh", "bash -o vi /opt/t/r.sh"] {
            assert!(is_no(&run(Family::Shell { zsh: false }, s)), "{s}");
        }
        assert!(is_no(&run(Family::Shell { zsh: false }, "-bash /opt/t/r.sh")), "a login shell by argv[0]");
    }

    #[test]
    fn perl_script() {
        assert_eq!(run(Family::Perl, "perl -wT /opt/t/r.pl"), script("/opt/t/r.pl", true));
        assert_eq!(run(Family::Perl, "perl -l -0777 /opt/t/r.pl"), script("/opt/t/r.pl", true));
        for s in ["perl -e print", "perl -wE say", "perl -MFoo /opt/t/r.pl", "perl -I/tmp /opt/t/r.pl", "perl -x /opt/t/r.pl", "perl -d /opt/t/r.pl", "perl -S r.pl", "perl", "perl r.pl"] {
            assert!(is_no(&run(Family::Perl, s)), "{s}");
        }
    }

    #[test]
    fn cmdline_status_and_normal_form() {
        assert_eq!(parse_cmdline(b"python3\0-I\0/opt/r.py\0"), vec!["python3", "-I", "/opt/r.py"]);
        assert_eq!(parse_cmdline(b""), Vec::<String>::new());
        assert_eq!(status_traced("Name:\tx\nTracerPid:\t0\n"), Some(false));
        assert_eq!(status_traced("TracerPid:\t4242\n"), Some(true));
        assert_eq!(status_traced("Name:\tx\n"), None);
        assert!(lexically_normal("/opt/t/r.py"));
        for p in ["opt/r.py", "/", "/opt/", "/opt/./r.py", "/opt/../r.py", "/opt//r.py", "/opt/t/.."] {
            assert!(!lexically_normal(p), "{p}");
        }
    }

    #[test]
    fn a_script_is_out_of_reach_only_with_every_directory() {
        let who = Who { uid: 1000, groups: vec![1000], ns_overflow: None, caps: 0 };
        let root_dir = |_: &str| Some((Perm::bits(0, 0, 0o755), true));
        let root_file = |_: &str| Some((Perm::bits(0, 0, 0o644), true));
        assert!(script_out_of_reach("/opt/t/r.py", &who, root_file, root_dir));
        // the agent owns the file
        assert!(!script_out_of_reach("/opt/t/r.py", &who, |_| Some((Perm::bits(1000, 1000, 0o644), true)), root_dir));
        // world-writable file
        assert!(!script_out_of_reach("/opt/t/r.py", &who, |_| Some((Perm::bits(0, 0, 0o666), true)), root_dir));
        // a directory above it is the agent's
        assert!(!script_out_of_reach("/opt/t/r.py", &who, root_file, |p: &str| Some(if p == "/opt/t" { (Perm::bits(1000, 1000, 0o755), true) } else { (Perm::bits(0, 0, 0o755), true) })));
        // a directory: not a script file
        assert!(!script_out_of_reach("/opt/t", &who, |_| Some((Perm::bits(0, 0, 0o755), false)), root_dir));
        // gone
        assert!(!script_out_of_reach("/opt/t/r.py", &who, |_| None, root_dir));
    }

    /// The `/proc` half on live children (no privilege: our own children):
    /// a shell running a script file is reported with it; a script the agent
    /// could write (ours) is not out of reach unless we are root of the
    /// initial namespace (which reaches everything: then nothing is); inline
    /// code is a reason.
    #[test]
    fn live_children_are_read_from_proc() {
        let dir = std::env::temp_dir().join(format!("mandu-script-id-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();
        let script = dir.join("r.sh");
        fs::write(&script, "sleep 5\n").unwrap();
        let who = Who::current();
        let hashes = HashCache::default();
        let mut child = std::process::Command::new("/bin/sh").arg(&script).spawn().unwrap();
        let pid = child.id() as i32;
        let mut got = None;
        for _ in 0..2000 {
            // Until the exec, the child's command line is this test binary's.
            let cmd = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            if parse_cmdline(&cmd).get(1).map(String::as_str) == script.to_str() {
                got = script_facts(pid, "/bin/sh", &who, &hashes);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let _ = child.kill();
        let _ = child.wait();
        let facts = got.expect("sh is a script interpreter").expect("sh runs a script file");
        assert_eq!(facts.path, script.to_str().unwrap());
        assert!(facts.isolated && !facts.traced);
        assert!(!facts.system, "a file this test (the agent's uid) wrote is never out of reach");
        assert_eq!(facts.sha256.as_deref(), crate::reader_identity::sha256_file(script.to_str().unwrap()).as_deref());

        let mut inline = std::process::Command::new("/bin/sh").args(["-c", "sleep 5"]).spawn().unwrap();
        let pid = inline.id() as i32;
        let mut why = None;
        for _ in 0..2000 {
            let cmd = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            if parse_cmdline(&cmd) == ["/bin/sh", "-c", "sleep 5"] {
                why = script_facts(pid, "/bin/sh", &who, &hashes);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let _ = inline.kill();
        let _ = inline.wait();
        assert!(matches!(why, Some(Err(_))), "inline code is no script: {why:?}");
        assert!(script_facts(std::process::id() as i32, "/usr/bin/cat", &who, &hashes).is_none(), "no facts for a program that is no interpreter");
        let _ = fs::remove_dir_all(&dir);
    }
}
