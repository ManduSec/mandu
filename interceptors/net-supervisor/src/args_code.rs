//! args_code — a reader whose command line or environment hands it code
//! (confidentiality plan 13 §3 D8, "Code by argument", 2026-10-02;
//! docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md).
//!
//! A reader of a secret is the program a human named (or a known consumer),
//! pinned by its binary (D8). Some of those programs run code they are given
//! on their command line or in their environment: `git -c alias.x='!sh'`,
//! `git -c core.pager=…`, `ssh -o ProxyCommand=…` / `-o LocalCommand=…` /
//! `-F <agent config>` / a PKCS#11 library, `scp -S <program>`, `sftp -b
//! <batch>` (`!command`), `psql -f <file>` / a `\!` meta-command, `less
//! +<command>` / `LESSOPEN`, `sed` with an `e` command or `s///e`, `tar
//! --to-command` / `--checkpoint-action=exec` / `-I`, `rsync -e`. The pin
//! says which binary runs, not what that binary is told to run, so such an
//! invocation is the agent's program, not the human's: like an interpreter
//! running inline code (decision (b)), it is no reader, is never prompted
//! for, is no trusted `from:` parent and no socket reader.
//!
//! What is computed here is a list of FINDINGS, `args:<program> <what>`:
//! the option or variable NAME, never its value (a value may be a secret).
//! `reader_identity::IdentityCtx::findings` appends them to D8's loader
//! findings; the arbiter reads `args:` entries as "runs code it is given"
//! (`argsCodeProblem`, flow-taint.ts).
//!
//! Rules, fail-closed where the program's grammar allows it:
//! - **git** (and a `git-*` helper's environment): `-c` / `--config-env`
//!   keys outside an allowlist of keys that run nothing (a `core.sshCommand`
//!   that is plain `ssh` with inert options, a `core.pager` / `pager.<cmd>`
//!   that is plain `less` / `cat` / `more`, are inert); `--exec-path=`;
//!   `--upload-pack` / `--receive-pack` / `--exec` / `clone -u`; an `ext::`
//!   transport; `rebase -x`, `submodule foreach`, `bisect run`,
//!   `filter-branch`, `difftool -x`. Variables (unless the launch gave the
//!   same value): `GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT`/`KEY_n`
//!   judged key by key as `-c`; `GIT_SSH_COMMAND`, `GIT_SSH`, `GIT_PAGER`,
//!   `PAGER` judged as their config twins; `GIT_CONFIG`,
//!   `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `GIT_EXEC_PATH`,
//!   `GIT_EDITOR`, `GIT_SEQUENCE_EDITOR`, `EDITOR`, `VISUAL`, `GIT_ASKPASS`,
//!   `SSH_ASKPASS`, `GIT_EXTERNAL_DIFF`, `GIT_PROXY_COMMAND`,
//!   `GIT_TEMPLATE_DIR` set at all.
//! - **ssh, scp, sftp, ssh-add**: `-o` with a key that runs a command or
//!   loads code (`ProxyCommand`, `LocalCommand`, `PermitLocalCommand yes`,
//!   `KnownHostsCommand`, `PKCS11Provider`, `SecurityKeyProvider`,
//!   `SmartcardDevice`, `XAuthLocation`, `Include`, `Match`); `-F` other
//!   than `none` / `/dev/null`; `-I`; scp `-S` / `-D`; sftp `-S` / `-D` /
//!   `-b`; ssh-add `-S` / `-s`; `SSH_ASKPASS`, `SSH_SK_PROVIDER`,
//!   `SSH_SK_HELPER`. (ssh_config(5) is a closed list: these are every
//!   keyword that runs a program or loads a library.)
//! - **psql**: `-f` / `--file`; a `-c` / `--command` carrying a
//!   meta-command (`\`); `PSQLRC`.
//! - **less**: a `+` initial command; `-k` / `--lesskey-*`; `LESSOPEN`,
//!   `LESSCLOSE`, `LESSKEY*`, `LESSEDIT`, and a `LESS` carrying either.
//! - **sed** (GNU): a script with an `e` command or an `s///e` flag, a
//!   script it cannot parse, or `-f` (a script file); never under
//!   `--sandbox`, which refuses `e`, `r` and `w`.
//! - **tar**: `--to-command`, `--checkpoint-action=exec`,
//!   `--use-compress-program` / `-I`, `--info-script` /
//!   `--new-volume-script` / `-F`, `--rsh-command`, `--rmt-command`, a
//!   remote archive (`-f host:path` without `--force-local`, which runs a
//!   remote shell); `TAR_OPTIONS`.
//! - **rsync**: `-e` / `--rsh` other than plain `ssh` with inert options;
//!   `RSYNC_RSH` the same; `RSYNC_CONNECT_PROG`.
//!
//! Not here: a configuration FILE the program reads that the agent can write
//! (plan 13 §3 D8, "a configuration file the reader reads", 2026-10-07). git,
//! psql, less and the other SQL shells are printers, which never read raw, so
//! their `.git/config`, `~/.psqlrc`, `~/.lesskey` or `~/.my.cnf` steers a
//! process holding placeholders only; ssh's files (`~/.ssh/config` and every
//! file it includes) are on the launcher's write-protect list. Programs that
//! always run code (editors, interpreters) are on `CODE_RUNNING_READERS`.
//!
//! Pure: argv and environment in, findings out; unit-tested with no
//! privilege. `Mandu-new` (no reference origin).

use crate::reader_identity::EnvBaseline;
use crate::secret_open::app_name_matches;

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// The variables a rule below reads: the launch's own values of these are
/// kept in the baseline (`EnvBaseline::from_vars`), so a value the human's
/// environment gave (an `EDITOR`, a Debian `LESSOPEN`) counts as theirs.
const RULE_VARS: &[&str] = &[
    "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_SSH_COMMAND", "GIT_SSH", "GIT_PAGER", "PAGER",
    "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_EXEC_PATH", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR",
    "EDITOR", "VISUAL", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_EXTERNAL_DIFF", "GIT_PROXY_COMMAND", "GIT_TEMPLATE_DIR",
    "SSH_SK_PROVIDER", "SSH_SK_HELPER", "PSQLRC", "LESSOPEN", "LESSCLOSE", "LESSKEY", "LESSKEYIN", "LESSKEY_CONTENT",
    "LESSKEYIN_SYSTEM", "LESSKEY_SYSTEM", "LESSEDIT", "LESS", "TAR_OPTIONS", "RSYNC_RSH", "RSYNC_CONNECT_PROG",
];
const RULE_VAR_PREFIXES: &[&str] = &["GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"];

/// Is `name` a variable some rule here reads (its launch value is kept)?
pub fn is_rule_var(name: &str) -> bool {
    RULE_VARS.contains(&name) || RULE_VAR_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// The program families with argument rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prog {
    Git,
    /// A `git-*` program (`git-credential-store`, `git-remote-https`): git's
    /// environment rules only.
    GitHelper,
    Ssh,
    Scp,
    Sftp,
    SshAdd,
    Psql,
    Less,
    Sed,
    Tar,
    Rsync,
}

fn prog_of(exe: &str) -> Option<Prog> {
    let base = basename(exe);
    let m = |n: &str| app_name_matches(base, n);
    if m("git") {
        Some(Prog::Git)
    } else if base.starts_with("git-") {
        Some(Prog::GitHelper)
    } else if m("ssh") || m("slogin") {
        Some(Prog::Ssh)
    } else if m("scp") {
        Some(Prog::Scp)
    } else if m("sftp") {
        Some(Prog::Sftp)
    } else if m("ssh-add") {
        Some(Prog::SshAdd)
    } else if m("psql") {
        Some(Prog::Psql)
    } else if m("less") {
        Some(Prog::Less)
    } else if m("sed") || m("gsed") {
        Some(Prog::Sed)
    } else if m("tar") || m("gtar") || m("bsdtar") {
        Some(Prog::Tar)
    } else if m("rsync") {
        Some(Prog::Rsync)
    } else {
        None
    }
}

/// Does this program have argument rules (the guard must read its command
/// line to judge it)?
pub fn has_rules(exe: &str) -> bool {
    prog_of(exe).is_some()
}

/// The findings for `exe` run as `argv` with `env`: `args:<program> <what>`,
/// sorted and deduplicated. Empty: its arguments and environment hand it no
/// code. Names only, never a value. Pure.
pub fn code_by_arguments(exe: &str, argv: &[String], env: &[(String, String)], launch: &EnvBaseline) -> Vec<String> {
    let Some(prog) = prog_of(exe) else { return Vec::new() };
    let name = basename(exe);
    let args: &[String] = if argv.is_empty() { argv } else { &argv[1..] };
    let agent_set = |n: &str| agent_set_var(env, launch, n);
    let mut what: Vec<String> = Vec::new();
    match prog {
        Prog::Git | Prog::GitHelper => {
            if prog == Prog::Git {
                git_args(args, env, &mut what);
            }
            git_env(exe, env, launch, &mut what);
        }
        Prog::Ssh => ssh_args(args, SshTool::Ssh, &mut what),
        Prog::Scp => ssh_args(args, SshTool::Scp, &mut what),
        Prog::Sftp => ssh_args(args, SshTool::Sftp, &mut what),
        Prog::SshAdd => ssh_args(args, SshTool::SshAdd, &mut what),
        Prog::Psql => {
            psql_args(args, &mut what);
            if agent_set("PSQLRC").is_some() {
                what.push("$PSQLRC".into());
            }
        }
        Prog::Less => {
            less_args(args, &mut what);
            for n in ["LESSOPEN", "LESSCLOSE", "LESSKEY", "LESSKEYIN", "LESSKEY_CONTENT", "LESSKEYIN_SYSTEM", "LESSKEY_SYSTEM", "LESSEDIT"] {
                if agent_set(n).is_some() {
                    what.push(format!("${n}"));
                }
            }
            if let Some(v) = agent_set("LESS") {
                let words: Vec<String> = v.split_whitespace().map(String::from).collect();
                let mut inner = Vec::new();
                less_args(&words, &mut inner);
                if !inner.is_empty() {
                    what.push("$LESS".into());
                }
            }
        }
        Prog::Sed => sed_args(args, &mut what),
        Prog::Tar => {
            tar_args(args, &mut what);
            if agent_set("TAR_OPTIONS").is_some() {
                what.push("$TAR_OPTIONS".into());
            }
        }
        Prog::Rsync => {
            rsync_args(args, &mut what);
            if let Some(v) = agent_set("RSYNC_RSH") {
                if !inert_ssh_command(v) {
                    what.push("$RSYNC_RSH".into());
                }
            }
            if agent_set("RSYNC_CONNECT_PROG").is_some() {
                what.push("$RSYNC_CONNECT_PROG".into());
            }
        }
    }
    if matches!(prog, Prog::Ssh | Prog::Scp | Prog::Sftp | Prog::SshAdd) {
        for n in ["SSH_ASKPASS", "SSH_SK_PROVIDER", "SSH_SK_HELPER"] {
            if agent_set(n).is_some() {
                what.push(format!("${n}"));
            }
        }
    }
    let mut out: Vec<String> = what.into_iter().map(|w| format!("args:{name} {w}")).collect();
    out.sort();
    out.dedup();
    out
}

/// The last value of `n` in `env`.
fn env_var<'a>(env: &'a [(String, String)], n: &str) -> Option<&'a str> {
    env.iter().rev().find(|(k, _)| k == n).map(|(_, v)| v.as_str())
}

/// A variable the agent set: present, not empty, and not the launch's own
/// value.
fn agent_set_var<'a>(env: &'a [(String, String)], launch: &EnvBaseline, n: &str) -> Option<&'a str> {
    env_var(env, n).filter(|v| !v.is_empty() && launch.get(n) != Some(*v))
}

// ── shell words and inert commands ──────────────────────────────────────────

/// A command value split as a shell would split plain words: single and
/// double quotes and backslash escapes; None when it uses anything else a
/// shell would interpret (`;`, `|`, `&`, `<`, `>`, `(`, `)`, `$`, a
/// backquote, a glob, braces, `!`, a newline, `#`, `=` in the first word;
/// a `~` is kept, its expansion runs nothing), so a
/// value that is not a plain command is never judged inert.
pub fn shell_words(s: &str) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(x) => cur.push(x),
                        None => return None,
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(x @ ('"' | '\\')) => cur.push(x),
                            _ => return None,
                        },
                        Some('$' | '`') | None => return None,
                        Some(x) => cur.push(x),
                    }
                }
            }
            '\\' => {
                in_word = true;
                match chars.next() {
                    Some('\n') | None => return None,
                    Some(x) => cur.push(x),
                }
            }
            ';' | '|' | '&' | '<' | '>' | '(' | ')' | '$' | '`' | '*' | '?' | '[' | '\n' | '#' | '{' | '}' | '!' => return None,
            _ => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    // `VAR=value cmd`: an environment assignment in front of the command.
    if out.first().is_some_and(|w| w.contains('=')) {
        return None;
    }
    Some(out)
}

/// Is `value` a plain `ssh` command whose options run nothing
/// (`ssh -i ~/.ssh/deploy -o IdentitiesOnly=yes`)? The program must be
/// named `ssh` (by path or name); an empty value runs nothing.
pub fn inert_ssh_command(value: &str) -> bool {
    let Some(w) = shell_words(value) else { return false };
    let Some(first) = w.first() else { return true };
    if !app_name_matches(basename(first), "ssh") {
        return false;
    }
    let mut what = Vec::new();
    ssh_args(&w[1..], SshTool::Ssh, &mut what);
    what.is_empty()
}

/// Is `value` a plain pager (`less` with inert options, `cat`, `more`), or
/// empty (no pager)?
pub fn inert_pager(value: &str) -> bool {
    let Some(w) = shell_words(value) else { return false };
    let Some(first) = w.first() else { return true };
    let base = basename(first);
    if app_name_matches(base, "less") {
        let mut what = Vec::new();
        less_args(&w[1..], &mut what);
        return what.is_empty();
    }
    app_name_matches(base, "cat") || app_name_matches(base, "more")
}

// ── git ─────────────────────────────────────────────────────────────────────

/// Sections whose every key runs nothing (any subsection, any name).
const GIT_INERT_SECTIONS: &[&str] = &[
    "user", "author", "committer", "color", "advice", "i18n", "status", "column", "log", "init", "safe", "feature",
    "versionsort", "gc", "maintenance", "pack", "index", "transfer", "fetch", "push", "pull", "rebase", "branch", "http",
    "commit", "tag", "blame", "grep", "checkout", "clone", "worktree", "stash", "format", "apply", "rerere", "reset", "add",
    "mailmap", "fsck", "repack", "uploadarchive", "trace2",
];
/// `core.<name>` keys that run nothing.
const GIT_CORE_INERT: &[&str] = &[
    "quotepath", "autocrlf", "safecrlf", "eol", "abbrev", "filemode", "ignorecase", "precomposeunicode", "longpaths",
    "symlinks", "compression", "loosecompression", "bigfilethreshold", "untrackedcache", "preloadindex", "commentchar",
    "commentstring", "logallrefupdates", "checkstat", "trustctime", "splitindex", "multipackindex", "fsync",
    "fsyncmethod", "sharedrepository", "warnambiguousrefs", "deltabasecachelimit", "packedgitlimit",
    "packedgitwindowsize", "whitespace", "notesref", "sparsecheckout", "sparsecheckoutcone", "protecthfs", "protectntfs",
    "fsmonitorhookversion", "restrictinheritedhandles", "unsetenvvars", "createobject", "checkroundtripencoding",
    "maxtreedepth", "bare", "worktree", "repositoryformatversion", "attributesfile", "excludesfile",
];

/// Does the git config key (and value) run nothing? `key` as written; a
/// boolean key with no `=` has no value.
fn git_key_inert(key: &str, value: Option<&str>) -> bool {
    let Some((section, rest)) = key.split_once('.') else { return false };
    let section = section.to_ascii_lowercase();
    let (sub, name) = match rest.rsplit_once('.') {
        Some((s, n)) => (Some(s), n.to_ascii_lowercase()),
        None => (None, rest.to_ascii_lowercase()),
    };
    if name.is_empty() {
        return false;
    }
    if GIT_INERT_SECTIONS.contains(&section.as_str()) {
        return true;
    }
    match (section.as_str(), sub) {
        ("core", None) => match name.as_str() {
            "sshcommand" => value.is_some_and(inert_ssh_command),
            "pager" => value.is_some_and(inert_pager),
            n => GIT_CORE_INERT.contains(&n),
        },
        // `pager.<cmd>`: a boolean, or a pager command.
        ("pager", None) => value.map_or(true, |v| is_git_bool(v) || inert_pager(v)),
        ("diff", None) => !matches!(name.as_str(), "external" | "tool" | "guitool"),
        ("merge", None) => !matches!(name.as_str(), "tool" | "guitool"),
        // A helper is a program, except git's builtin `store` and `cache`
        // (`git credential-store`, no PATH lookup) and the empty value that
        // resets the list.
        ("credential", _) => name != "helper" || value.map_or(false, builtin_credential_helper),
        ("protocol", None) => name == "version",
        ("submodule", None) => true,
        _ => false,
    }
}

/// `credential.helper` naming git's builtin store or cache, with plain
/// `--option[=value]` arguments (`store --file=~/.creds`, `cache
/// --timeout=3600`), or empty. Anything else (a name git looks up as
/// `git-credential-<name>` on the PATH, a path, `!command`) runs a program.
fn builtin_credential_helper(v: &str) -> bool {
    let Some(w) = shell_words(v) else { return false };
    match w.split_first() {
        None => true,
        Some((h, rest)) => (h == "store" || h == "cache") && rest.iter().all(|a| a.starts_with("--")),
    }
}

fn is_git_bool(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "true" | "false" | "yes" | "no" | "on" | "off" | "1" | "0" | "")
}

/// `key=value` (or a bare boolean `key`) as `-c` and the environment carry
/// it: `Some(key)` when it may run something.
fn git_kv_problem(kv: &str) -> Option<String> {
    let (key, value) = match kv.split_once('=') {
        Some((k, v)) => (k, Some(v)),
        None => (kv, None),
    };
    if git_key_inert(key, value) {
        None
    } else {
        Some(key.to_ascii_lowercase())
    }
}

/// Subcommands whose arguments name a program to run on the remote side
/// of a local transport (`--upload-pack`, `--receive-pack`, `--exec`).
const GIT_TRANSPORT_SUBCOMMANDS: &[&str] = &["clone", "fetch", "pull", "ls-remote", "push", "archive", "send-pack", "fetch-pack", "remote", "submodule"];

fn git_args(args: &[String], env: &[(String, String)], what: &mut Vec<String>) {
    let mut i = 0;
    let mut sub: Option<&str> = None;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-c" {
            match args.get(i + 1) {
                Some(kv) => {
                    if let Some(k) = git_kv_problem(kv) {
                        what.push(format!("-c {k}"));
                    }
                }
                None => what.push("-c".into()),
            }
            i += 2;
            continue;
        }
        if let Some(kv) = a.strip_prefix("-c").filter(|r| !r.is_empty() && !a.starts_with("--")) {
            if let Some(k) = git_kv_problem(kv) {
                what.push(format!("-c {k}"));
            }
            i += 1;
            continue;
        }
        if a == "--config-env" || a.starts_with("--config-env=") {
            let spec = if a == "--config-env" {
                i += 1;
                args.get(i).map(String::as_str)
            } else {
                a.split_once('=').map(|(_, v)| v)
            };
            // `<key>=<envvar>`: the value is that variable's.
            match spec.and_then(|s| s.split_once('=')) {
                Some((key, envvar)) => {
                    if !git_key_inert(key, env_var(env, envvar)) {
                        what.push(format!("--config-env {}", key.to_ascii_lowercase()));
                    }
                }
                None => what.push("--config-env".into()),
            }
            i += 1;
            continue;
        }
        if a.starts_with("--exec-path=") {
            what.push("--exec-path".into());
            i += 1;
            continue;
        }
        if matches!(a, "-C" | "--git-dir" | "--work-tree" | "--namespace" | "--super-prefix" | "--list-cmds" | "--attr-source") {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        sub = Some(a);
        i += 1;
        break;
    }
    let Some(sub) = sub else { return };
    let rest = &args[i..];
    if GIT_TRANSPORT_SUBCOMMANDS.contains(&sub) {
        for a in rest {
            let a = a.as_str();
            for opt in ["--upload-pack", "--receive-pack", "--exec"] {
                if a == opt || a.strip_prefix(opt).is_some_and(|r| r.starts_with('=')) {
                    what.push(opt.into());
                }
            }
            if (sub == "clone" || sub == "ls-remote") && (a == "-u" || (a.starts_with("-u") && !a.starts_with("--"))) {
                what.push("-u".into());
            }
        }
    }
    if rest.iter().any(|a| a.starts_with("ext::")) {
        what.push("ext::".into());
    }
    let has = |opts: &[&str]| rest.iter().any(|a| opts.iter().any(|o| a == o || a.strip_prefix(o).is_some_and(|r| r.starts_with('='))));
    match sub {
        "rebase" if has(&["-x", "--exec"]) || rest.iter().any(|a| a.starts_with("-x") && !a.starts_with("--")) => what.push("rebase --exec".into()),
        "submodule" if rest.iter().any(|a| a == "foreach") => what.push("submodule foreach".into()),
        "bisect" if rest.first().is_some_and(|a| a == "run") => what.push("bisect run".into()),
        "filter-branch" => what.push("filter-branch".into()),
        "difftool" | "mergetool" if has(&["-x", "--extcmd", "--tool", "-t"]) => what.push(format!("{sub} --extcmd")),
        _ => {}
    }
}

/// `GIT_CONFIG_PARAMETERS` as git writes it: shell-single-quoted
/// `'key'='value'` pairs (or `'key=value'`, the older form), separated by
/// spaces. None when it does not parse.
pub fn parse_git_config_parameters(s: &str) -> Option<Vec<String>> {
    fn quoted(chars: &mut std::iter::Peekable<std::str::Chars>) -> Option<String> {
        if chars.next()? != '\'' {
            return None;
        }
        let mut out = String::new();
        loop {
            match chars.next()? {
                '\'' => {
                    // `'\''` and `'\!'` continue the string with a quote or
                    // a `!` (git's sq_quote_buf).
                    if chars.peek() == Some(&'\\') {
                        chars.next();
                        let x = chars.next()?;
                        if !matches!(x, '\'' | '!') || chars.next()? != '\'' {
                            return None;
                        }
                        out.push(x);
                    } else {
                        return Some(out);
                    }
                }
                c => out.push(c),
            }
        }
    }
    let mut chars = s.chars().peekable();
    let mut out = Vec::new();
    loop {
        while chars.peek() == Some(&' ') {
            chars.next();
        }
        if chars.peek().is_none() {
            return Some(out);
        }
        let key = quoted(&mut chars)?;
        if chars.peek() == Some(&'=') {
            chars.next();
            let value = quoted(&mut chars)?;
            out.push(format!("{key}={value}"));
        } else {
            out.push(key);
        }
    }
}

fn git_env(exe: &str, env: &[(String, String)], launch: &EnvBaseline, what: &mut Vec<String>) {
    let agent_set = |n: &str| agent_set_var(env, launch, n);
    if let Some(v) = agent_set("GIT_CONFIG_PARAMETERS") {
        match parse_git_config_parameters(v) {
            Some(kvs) => {
                for kv in kvs {
                    if let Some(k) = git_kv_problem(&kv) {
                        what.push(format!("$GIT_CONFIG_PARAMETERS {k}"));
                    }
                }
            }
            None => what.push("$GIT_CONFIG_PARAMETERS".into()),
        }
    }
    // GIT_CONFIG_COUNT and its numbered pairs: judged unless every one of
    // them is the launch's own.
    let numbered: Vec<&(String, String)> = env
        .iter()
        .filter(|(k, _)| k == "GIT_CONFIG_COUNT" || RULE_VAR_PREFIXES.iter().any(|p| k.starts_with(p)))
        .collect();
    let launch_given = numbered.iter().all(|(k, v)| launch.get(k) == Some(v.as_str()));
    if !numbered.is_empty() && !launch_given {
        let var = |n: &str| env_var(env, n);
        match var("GIT_CONFIG_COUNT").map(str::parse::<usize>) {
            Some(Ok(n)) => {
                for i in 0..n.min(1000) {
                    match var(&format!("GIT_CONFIG_KEY_{i}")) {
                        Some(key) => {
                            let value = var(&format!("GIT_CONFIG_VALUE_{i}"));
                            if !git_key_inert(key, value) {
                                what.push(format!("$GIT_CONFIG_KEY {}", key.to_ascii_lowercase()));
                            }
                        }
                        None => what.push("$GIT_CONFIG_COUNT".into()),
                    }
                }
            }
            Some(Err(_)) => what.push("$GIT_CONFIG_COUNT".into()),
            None => {}
        }
    }
    if let Some(v) = agent_set("GIT_SSH_COMMAND") {
        if !inert_ssh_command(v) {
            what.push("$GIT_SSH_COMMAND".into());
        }
    }
    if let Some(v) = agent_set("GIT_SSH") {
        // A program path, run with no shell: one named ssh is that program
        // (and is judged as an opener in its own right).
        if !app_name_matches(basename(v), "ssh") {
            what.push("$GIT_SSH".into());
        }
    }
    for n in ["GIT_PAGER", "PAGER"] {
        if let Some(v) = agent_set(n) {
            if !inert_pager(v) {
                what.push(format!("${n}"));
            }
        }
    }
    // git sets GIT_EXEC_PATH for every git it starts (its credential helper
    // included) to the directory its own programs live in: that value, the
    // directory of the opener's own executable, runs nothing new.
    if let Some(v) = agent_set("GIT_EXEC_PATH") {
        let own_dir = exe.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        if v.trim_end_matches('/') != own_dir || own_dir.is_empty() {
            what.push("$GIT_EXEC_PATH".into());
        }
    }
    for n in [
        "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "EDITOR", "VISUAL",
        "GIT_ASKPASS", "SSH_ASKPASS", "GIT_EXTERNAL_DIFF", "GIT_PROXY_COMMAND", "GIT_TEMPLATE_DIR",
    ] {
        if agent_set(n).is_some() {
            what.push(format!("${n}"));
        }
    }
}

// ── ssh, scp, sftp, ssh-add ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SshTool {
    Ssh,
    Scp,
    Sftp,
    SshAdd,
}

/// The ssh_config(5) keywords that run a program or load a library.
fn ssh_option_problem(opt: &str) -> Option<String> {
    let opt = opt.trim_start();
    let split = opt.find(|c: char| c == '=' || c.is_whitespace()).unwrap_or(opt.len());
    let key = opt[..split].to_ascii_lowercase();
    let value = opt[split..].trim_start_matches(|c: char| c == '=' || c.is_whitespace()).trim();
    let none = value.eq_ignore_ascii_case("none");
    let code = match key.as_str() {
        "proxycommand" | "knownhostscommand" | "pkcs11provider" | "smartcarddevice" => !none,
        "localcommand" => !value.is_empty(),
        "permitlocalcommand" => !matches!(value.to_ascii_lowercase().as_str(), "no" | "false"),
        "securitykeyprovider" => !value.eq_ignore_ascii_case("internal"),
        "xauthlocation" | "include" | "match" => true,
        _ => false,
    };
    code.then(|| format!("-o {key}"))
}

fn ssh_args(args: &[String], tool: SshTool, what: &mut Vec<String>) {
    // The option letters that take a value, per program (OpenSSH getopt).
    let takes: &str = match tool {
        SshTool::Ssh => "bceilmopBDEFIJLOPQRSwW",
        SshTool::Scp => "DFJMPSXcilo",
        SshTool::Sftp => "BDFJPRSXbcilos",
        SshTool::SshAdd => "EeHhMmSst",
    };
    let mut host_seen = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            break;
        }
        if !a.starts_with('-') || a == "-" {
            // ssh takes options after the destination too; the second word
            // that is no option starts the remote command.
            if tool == SshTool::Ssh {
                if host_seen {
                    break;
                }
                host_seen = true;
            }
            i += 1;
            continue;
        }
        let letters: Vec<char> = a[1..].chars().collect();
        let mut j = 0;
        while j < letters.len() {
            let c = letters[j];
            if takes.contains(c) {
                let attached: String = letters[j + 1..].iter().collect();
                let value = if attached.is_empty() {
                    i += 1;
                    args.get(i).cloned()
                } else {
                    Some(attached)
                };
                let value = value.unwrap_or_default();
                match (tool, c) {
                    (SshTool::Ssh | SshTool::Scp | SshTool::Sftp, 'o') => {
                        if let Some(p) = ssh_option_problem(&value) {
                            what.push(p);
                        }
                    }
                    (SshTool::Ssh | SshTool::Scp | SshTool::Sftp, 'F') => {
                        if value != "none" && value != "/dev/null" {
                            what.push("-F".into());
                        }
                    }
                    (SshTool::Ssh, 'I') => what.push("-I".into()),
                    (SshTool::Scp | SshTool::Sftp, 'S' | 'D') => what.push(format!("-{c}")),
                    (SshTool::Sftp, 'b') => what.push("-b".into()),
                    (SshTool::SshAdd, 'S' | 's') => what.push(format!("-{c}")),
                    _ => {}
                }
                break;
            }
            j += 1;
        }
        i += 1;
    }
}

// ── psql ────────────────────────────────────────────────────────────────────

fn psql_args(args: &[String], what: &mut Vec<String>) {
    let takes = "cdfhLopPRTUvF";
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            let takes_value = matches!(
                name,
                "command" | "dbname" | "file" | "host" | "log-file" | "output" | "port" | "pset" | "record-separator" | "table-attr" | "username" | "set" | "variable" | "field-separator"
            );
            let value = if takes_value && value.is_none() {
                i += 1;
                args.get(i).cloned()
            } else {
                value
            };
            match name {
                "file" => what.push("--file".into()),
                "command" if value.as_deref().is_some_and(|v| v.contains('\\')) => what.push("--command \\".into()),
                _ => {}
            }
            i += 1;
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            let letters: Vec<char> = a[1..].chars().collect();
            for (j, c) in letters.iter().enumerate() {
                if takes.contains(*c) {
                    let attached: String = letters[j + 1..].iter().collect();
                    let value = if attached.is_empty() {
                        i += 1;
                        args.get(i).cloned()
                    } else {
                        Some(attached)
                    };
                    match c {
                        'f' => what.push("-f".into()),
                        'c' if value.as_deref().is_some_and(|v| v.contains('\\')) => what.push("-c \\".into()),
                        _ => {}
                    }
                    break;
                }
            }
        }
        i += 1;
    }
}

// ── less ────────────────────────────────────────────────────────────────────

fn less_args(args: &[String], what: &mut Vec<String>) {
    // Option letters whose value is the rest of the word (or the next one).
    let takes = "bhjkoOpPtTxyz#";
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            break;
        }
        if a.starts_with('+') {
            what.push("+".into());
        } else if let Some(long) = a.strip_prefix("--") {
            if long.starts_with("lesskey") {
                what.push("--lesskey".into());
            }
        } else if let Some(opts) = a.strip_prefix('-') {
            for (j, c) in opts.char_indices() {
                if c == 'k' {
                    what.push("-k".into());
                }
                if takes.contains(c) {
                    if opts[j + c.len_utf8()..].is_empty() {
                        i += 1;
                    }
                    break;
                }
            }
        }
        i += 1;
    }
}

// ── sed ─────────────────────────────────────────────────────────────────────

/// Does a GNU sed script run a command (`e`, `s///e`), or not parse? Pure.
pub fn sed_script_runs_code(script: &str) -> bool {
    let b: Vec<char> = script.chars().collect();
    let mut i = 0;
    let n = b.len();
    let skip_to_eol = |i: &mut usize| {
        while *i < n && b[*i] != '\n' {
            *i += 1;
        }
    };
    // A delimited part (`/re/`, `\cREc`, a `s` field): index after the
    // closing delimiter, or None.
    let delimited = |mut i: usize, d: char| -> Option<usize> {
        while i < n {
            if b[i] == '\\' {
                i += 2;
                continue;
            }
            if b[i] == d {
                return Some(i + 1);
            }
            if b[i] == '\n' && d != '\n' {
                return None;
            }
            i += 1;
        }
        None
    };
    let address = |mut i: usize| -> Option<usize> {
        if i < n && b[i] == '$' {
            return Some(i + 1);
        }
        if i < n && b[i].is_ascii_digit() {
            while i < n && (b[i].is_ascii_digit() || b[i] == '~') {
                i += 1;
            }
            return Some(i);
        }
        if i < n && b[i] == '/' {
            i = delimited(i + 1, '/')?;
        } else if i + 1 < n && b[i] == '\\' {
            i = delimited(i + 2, b[i + 1])?;
        } else {
            return Some(i);
        }
        while i < n && (b[i] == 'I' || b[i] == 'M') {
            i += 1;
        }
        Some(i)
    };
    while i < n {
        let c = b[i];
        if c.is_whitespace() || c == ';' || c == '}' {
            i += 1;
            continue;
        }
        if c == '#' {
            skip_to_eol(&mut i);
            continue;
        }
        let Some(mut j) = address(i) else { return true };
        if j < n && b[j] == ',' {
            j += 1;
            if j < n && (b[j] == '+' || b[j] == '~') {
                j += 1;
            }
            let Some(k) = address(j) else { return true };
            j = k;
        }
        while j < n && (b[j].is_whitespace() || b[j] == '!') {
            j += 1;
        }
        if j >= n {
            return j != i;
        }
        let cmd = b[j];
        j += 1;
        match cmd {
            '{' => i = j,
            'e' => return true,
            ':' | 'b' | 't' | 'T' => {
                while j < n && b[j] != '\n' && b[j] != ';' {
                    j += 1;
                }
                i = j;
            }
            'r' | 'R' | 'w' | 'W' => {
                i = j;
                skip_to_eol(&mut i);
            }
            // Text to the end of the line; a line ending in `\` goes on.
            'a' | 'i' | 'c' => {
                i = j;
                loop {
                    skip_to_eol(&mut i);
                    if i < n && i > 0 && b[i - 1] == '\\' {
                        i += 1;
                        continue;
                    }
                    break;
                }
            }
            's' | 'y' => {
                if j >= n || b[j] == '\n' || b[j] == '\\' {
                    return true;
                }
                let d = b[j];
                let Some(k) = delimited(j + 1, d) else { return true };
                let Some(mut k) = delimited(k, d) else { return true };
                if cmd == 's' {
                    while k < n && (b[k].is_ascii_alphanumeric()) {
                        match b[k] {
                            'e' => return true,
                            'w' => {
                                skip_to_eol(&mut k);
                                break;
                            }
                            _ => k += 1,
                        }
                    }
                }
                i = k;
            }
            '=' | 'd' | 'D' | 'g' | 'G' | 'h' | 'H' | 'n' | 'N' | 'p' | 'P' | 'x' | 'z' | 'F' => i = j,
            'l' | 'q' | 'Q' | 'L' => {
                while j < n && (b[j] == ' ' || b[j].is_ascii_digit()) {
                    j += 1;
                }
                i = j;
            }
            'v' => {
                while j < n && b[j] != '\n' && b[j] != ';' {
                    j += 1;
                }
                i = j;
            }
            _ => return true,
        }
    }
    false
}

fn sed_args(args: &[String], what: &mut Vec<String>) {
    let mut scripts: Vec<&str> = Vec::new();
    let mut file = false;
    let mut sandbox = false;
    let mut first_operand: Option<&str> = None;
    let mut i = 0;
    let mut opts_done = false;
    while i < args.len() {
        let a = args[i].as_str();
        if !opts_done && a == "--" {
            opts_done = true;
            i += 1;
            continue;
        }
        if !opts_done && a.starts_with("--") {
            let (name, value) = match a[2..].split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (&a[2..], None),
            };
            match name {
                "sandbox" => sandbox = true,
                "expression" => match value {
                    Some(v) => scripts.push(v),
                    None => {
                        i += 1;
                        if let Some(v) = args.get(i) {
                            scripts.push(v);
                        }
                    }
                },
                "file" => file = true,
                "line-length" if value.is_none() => i += 1,
                _ => {}
            }
            i += 1;
            continue;
        }
        if !opts_done && a.starts_with('-') && a.len() > 1 {
            for (j, c) in a[1..].char_indices() {
                let rest = &a[1 + j + c.len_utf8()..];
                match c {
                    'e' => {
                        if rest.is_empty() {
                            i += 1;
                            if let Some(v) = args.get(i) {
                                scripts.push(v);
                            }
                        } else {
                            scripts.push(rest);
                        }
                        break;
                    }
                    'f' => {
                        file = true;
                        if rest.is_empty() {
                            i += 1;
                        }
                        break;
                    }
                    'l' => {
                        if rest.is_empty() {
                            i += 1;
                        }
                        break;
                    }
                    // `-i[SUFFIX]`: the suffix is attached.
                    'i' => break,
                    _ => {}
                }
            }
            i += 1;
            continue;
        }
        if first_operand.is_none() {
            first_operand = Some(a);
        }
        i += 1;
    }
    if sandbox {
        return;
    }
    if file {
        what.push("-f".into());
    }
    if scripts.is_empty() {
        if let Some(s) = first_operand {
            scripts.push(s);
        }
    }
    if scripts.iter().any(|s| sed_script_runs_code(s)) {
        what.push("e".into());
    }
}

// ── tar ─────────────────────────────────────────────────────────────────────

fn tar_args(args: &[String], what: &mut Vec<String>) {
    // GNU tar's short options that take a value.
    let takes = "bCfFgHIKLNTVX";
    let force_local = args.iter().any(|a| a == "--force-local");
    let remote = |v: &str| !force_local && v.split_once(':').is_some_and(|(host, _)| !host.is_empty() && !host.contains('/'));
    let mut pending: Vec<char> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        // Values owed to an old-style cluster (`tar cIf prog x.tar`), in order.
        if let Some(c) = pending.first().copied() {
            pending.remove(0);
            match c {
                'I' => what.push("-I".into()),
                'F' => what.push("-F".into()),
                'f' if remote(a) => what.push("-f host:".into()),
                _ => {}
            }
            i += 1;
            continue;
        }
        if a == "--" {
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            let value_or_next = |i: &mut usize| value.clone().or_else(|| {
                *i += 1;
                args.get(*i).cloned()
            });
            match name {
                "to-command" | "use-compress-program" | "info-script" | "new-volume-script" | "rsh-command" | "rmt-command" => {
                    what.push(format!("--{name}"));
                    if value.is_none() {
                        i += 1;
                    }
                }
                "checkpoint-action" => {
                    let v = value_or_next(&mut i).unwrap_or_default();
                    if v.contains("exec") {
                        what.push("--checkpoint-action=exec".into());
                    }
                }
                "file" => {
                    let v = value_or_next(&mut i).unwrap_or_default();
                    if remote(&v) {
                        what.push("--file host:".into());
                    }
                }
                _ => {}
            }
            i += 1;
            continue;
        }
        let (cluster, old_style) = match a.strip_prefix('-') {
            Some(c) => (c, false),
            None if i == 0 && !a.is_empty() => (a, true),
            None => {
                i += 1;
                continue;
            }
        };
        let letters: Vec<char> = cluster.chars().collect();
        for (j, c) in letters.iter().enumerate() {
            if !takes.contains(*c) {
                continue;
            }
            if old_style {
                pending.push(*c);
                continue;
            }
            let attached: String = letters[j + 1..].iter().collect();
            let value = if attached.is_empty() {
                i += 1;
                args.get(i).cloned().unwrap_or_default()
            } else {
                attached
            };
            match c {
                'I' => what.push("-I".into()),
                'F' => what.push("-F".into()),
                'f' if remote(&value) => what.push("-f host:".into()),
                _ => {}
            }
            break;
        }
        i += 1;
    }
}

// ── rsync ───────────────────────────────────────────────────────────────────

fn rsync_args(args: &[String], what: &mut Vec<String>) {
    let takes = "BefMT@";
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            if long == "rsh" || long.starts_with("rsh=") {
                let v = match long.split_once('=') {
                    Some((_, v)) => Some(v.to_string()),
                    None => {
                        i += 1;
                        args.get(i).cloned()
                    }
                };
                if !v.as_deref().is_some_and(inert_ssh_command) {
                    what.push("--rsh".into());
                }
            }
            i += 1;
            continue;
        }
        if let Some(opts) = a.strip_prefix('-').filter(|o| !o.is_empty()) {
            for (j, c) in opts.char_indices() {
                if takes.contains(c) {
                    let attached = &opts[j + c.len_utf8()..];
                    let value = if attached.is_empty() {
                        i += 1;
                        args.get(i).cloned()
                    } else {
                        Some(attached.to_string())
                    };
                    if c == 'e' && !value.as_deref().is_some_and(inert_ssh_command) {
                        what.push("-e".into());
                    }
                    break;
                }
            }
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test command line: words, with '…' and "…" grouping (no other
    /// shell syntax, so `!`, `$` and `|` stay literal).
    fn argv(s: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut q: Option<char> = None;
        let mut in_word = false;
        for c in s.chars() {
            match (q, c) {
                (Some(d), c) if c == d => q = None,
                (Some(_), c) => cur.push(c),
                (None, '\'' | '"') => {
                    q = Some(c);
                    in_word = true;
                }
                (None, ' ') => {
                    if in_word {
                        out.push(std::mem::take(&mut cur));
                        in_word = false;
                    }
                }
                (None, c) => {
                    cur.push(c);
                    in_word = true;
                }
            }
        }
        if in_word {
            out.push(cur);
        }
        out
    }
    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }
    fn found(exe: &str, cmd: &str) -> Vec<String> {
        code_by_arguments(exe, &argv(cmd), &[], &EnvBaseline::default())
    }
    fn found_env(exe: &str, cmd: &str, e: &[(&str, &str)], launch: &[(&str, &str)]) -> Vec<String> {
        code_by_arguments(exe, &argv(cmd), &env(e), &EnvBaseline::from_vars(env(launch)))
    }
    fn clean(exe: &str, cmd: &str) {
        assert!(found(exe, cmd).is_empty(), "{cmd}: {:?}", found(exe, cmd));
    }
    fn code(exe: &str, cmd: &str) {
        assert!(!found(exe, cmd).is_empty(), "{cmd} should be code");
    }

    #[test]
    fn shell_words_split_plain_words_and_refuse_shell_syntax() {
        assert_eq!(shell_words("ssh -i '/k y' -o \"A=b\"").unwrap(), vec!["ssh", "-i", "/k y", "-o", "A=b"]);
        assert_eq!(shell_words("").unwrap(), Vec::<String>::new());
        assert_eq!(shell_words("ssh -i ~/.ssh/k").unwrap(), vec!["ssh", "-i", "~/.ssh/k"]);
        for s in ["ssh; sh", "ssh | nc", "ssh $(x)", "ssh `x`", "ssh > /tmp/x", "ssh && x", "A=b ssh", "ssh \"$X\"", "ssh 'x", "ssh *", "ssh !x"] {
            assert!(shell_words(s).is_none(), "{s}");
        }
    }

    #[test]
    fn programs_without_rules_are_never_judged() {
        assert!(found("/usr/bin/cat", "cat -c alias.x=!sh +!sh -e x").is_empty());
        assert!(found("/usr/bin/psql2", "psql2 -f x").is_empty(), "a name is matched as app_name_matches does");
        assert!(has_rules("/usr/bin/git") && has_rules("/usr/lib/git-core/git-credential-store") && !has_rules("/usr/bin/python3"));
    }

    #[test]
    fn git_config_on_the_command_line_runs_nothing_only_from_the_allowlist() {
        for ok in [
            "git push",
            "git -c user.name=x -c user.email=y commit -m z",
            "git -c color.ui=always -c http.extraHeader=X-A:b fetch",
            "git -c core.quotepath=off -c init.defaultBranch=main log",
            "git -c core.sshCommand='ssh -i /k -o IdentitiesOnly=yes' fetch",
            "git -c core.pager=cat log",
            "git -c core.pager='less -FRX' log",
            "git -c pager.log=false log",
            "git -c credential.username=me fetch",
            "git -c credential.helper=store credential fill",
            "git -c credential.helper='store --file=/h/.creds' credential fill",
            "git -c credential.helper='cache --timeout=3600' push",
            "git -c credential.helper= push",
            "git -c credential.https://h.example.useHttpPath=true fetch",
            "git -C /w --git-dir /w/.git status",
            "git --exec-path",
            "git clone https://h/r.git",
            "git push -u origin main",
            "git credential-store get",
        ] {
            clean("/usr/bin/git", ok);
        }
        for bad in [
            "git -c alias.x=!sh x",
            "git -c core.pager='sh -c id' log",
            "git -c core.pager='less +!id' log",
            "git -c core.sshCommand='ssh -o ProxyCommand=nc' fetch",
            "git -c core.sshCommand='sh -c id' fetch",
            "git -c core.editor=vim commit",
            "git -c core.fsmonitor=/w/x status",
            "git -c core.hooksPath=/w/h commit",
            "git -c credential.helper=!sh fill",
            "git -c credential.https://h.helper=x fill",
            "git -c credential.helper=storex fill",
            "git -c credential.helper='store x' fill",
            "git -c credential.helper=/w/helper fill",
            "git -c include.path=/w/c status",
            "git -c includeIf.gitdir:/w/.path=/w/c status",
            "git -c protocol.ext.allow=always fetch",
            "git -c url.ext::sh.insteadOf=https:// fetch",
            "git -c diff.external=/w/d diff",
            "git -c diff.x.textconv=/w/t diff",
            "git -c filter.x.smudge=/w/s checkout",
            "git -c gpg.program=/w/g commit",
            "git -c remote.origin.uploadpack=/w/u fetch",
            "git -c submodule.x.update=!sh submodule update",
            "git -c sequence.editor=x rebase -i",
            "git -c pager.log='sh -c id' log",
            "git -calias.x=!sh x",
            "git --config-env=core.pager=P log",
            "git --exec-path=/w/libexec push",
            "git clone --upload-pack=/w/x h:r",
            "git clone -u /w/x h:r",
            "git fetch --upload-pack /w/x",
            "git push --receive-pack=/w/x",
            "git ls-remote -u /w/x h:r",
            "git fetch ext::sh",
            "git rebase -x id main",
            "git rebase --exec=id main",
            "git submodule foreach id",
            "git bisect run /w/t",
            "git filter-branch --tree-filter id",
            "git difftool -x id",
            "git -c unknown.key=v status",
        ] {
            code("/usr/bin/git", bad);
        }
        assert_eq!(found("/usr/bin/git", "git -c alias.Secret-Name=!echo-secret-value x"), vec!["args:git -c alias.secret-name"], "the key, never the value");
        // --config-env reads the value from a variable: an inert key with a
        // plain pager there is inert.
        assert!(code_by_arguments("/usr/bin/git", &argv("git --config-env=core.pager=P log"), &env(&[("P", "cat")]), &EnvBaseline::default()).is_empty());
    }

    #[test]
    fn git_environment_is_judged_like_its_config_and_against_the_launch() {
        let g = "/usr/bin/git";
        assert!(found_env(g, "git push", &[("GIT_SSH_COMMAND", "ssh -i /k -o IdentitiesOnly=yes")], &[]).is_empty());
        assert_eq!(found_env(g, "git push", &[("GIT_SSH_COMMAND", "ssh -o ProxyCommand='sh -c x'")], &[]), vec!["args:git $GIT_SSH_COMMAND"]);
        assert!(found_env(g, "git push", &[("GIT_SSH", "/usr/bin/ssh"), ("GIT_PAGER", "cat"), ("PAGER", "less -R")], &[]).is_empty());
        assert_eq!(found_env(g, "git push", &[("GIT_SSH", "/w/x")], &[]), vec!["args:git $GIT_SSH"]);
        assert_eq!(found_env(g, "git log", &[("GIT_PAGER", "sh -c id")], &[]), vec!["args:git $GIT_PAGER"]);
        for n in ["GIT_CONFIG_GLOBAL", "GIT_EXEC_PATH", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_EXTERNAL_DIFF", "GIT_PROXY_COMMAND", "GIT_EDITOR", "EDITOR", "GIT_TEMPLATE_DIR"] {
            assert_eq!(found_env(g, "git push", &[(n, "/w/x")], &[]), vec![format!("args:git ${n}")], "{n}");
            assert!(found_env(g, "git push", &[(n, "/w/x")], &[(n, "/w/x")]).is_empty(), "{n}: the launch's own value is the human's");
            assert!(found_env(g, "git push", &[(n, "")], &[]).is_empty(), "{n}: empty runs nothing");
        }
        // git hands its children its own exec path: that is no finding.
        assert!(found_env("/usr/lib/git-core/git", "git credential-store get", &[("GIT_EXEC_PATH", "/usr/lib/git-core")], &[]).is_empty());
        assert!(found_env("/usr/lib/git-core/git", "git credential-store get", &[("GIT_EXEC_PATH", "/usr/lib/git-core/")], &[]).is_empty());
        assert_eq!(found_env("/usr/lib/git-core/git", "git credential-store get", &[("GIT_EXEC_PATH", "/w/libexec")], &[]), vec!["args:git $GIT_EXEC_PATH"]);
        // -c as git hands it to its children.
        let child = "/usr/bin/git";
        assert!(found_env(child, "git credential-store get", &[("GIT_CONFIG_PARAMETERS", "'user.name'='a b' 'color.ui'='always'")], &[]).is_empty());
        assert_eq!(
            found_env(child, "git credential-store get", &[("GIT_CONFIG_PARAMETERS", "'user.name'='x' 'alias.y'='!sh -c '\\''id'\\'''")], &[]),
            vec!["args:git $GIT_CONFIG_PARAMETERS alias.y"]
        );
        assert_eq!(found_env(child, "git credential-store get", &[("GIT_CONFIG_PARAMETERS", "'core.pager=sh'")], &[]), vec!["args:git $GIT_CONFIG_PARAMETERS core.pager"], "the older form");
        assert_eq!(found_env(child, "git credential-store get", &[("GIT_CONFIG_PARAMETERS", "garbage")], &[]), vec!["args:git $GIT_CONFIG_PARAMETERS"], "unparsed is code");
        let helper = "/usr/lib/git-core/git-credential-store";
        assert_eq!(found_env(helper, "git-credential-store get", &[("GIT_CONFIG_COUNT", "1"), ("GIT_CONFIG_KEY_0", "core.pager"), ("GIT_CONFIG_VALUE_0", "sh -c id")], &[]), vec!["args:git-credential-store $GIT_CONFIG_KEY core.pager"]);
        assert!(found_env(helper, "git-credential-store get", &[("GIT_CONFIG_COUNT", "1"), ("GIT_CONFIG_KEY_0", "user.name"), ("GIT_CONFIG_VALUE_0", "x")], &[]).is_empty());
        let given = [("GIT_CONFIG_COUNT", "1"), ("GIT_CONFIG_KEY_0", "credential.helper"), ("GIT_CONFIG_VALUE_0", "store")];
        assert!(found_env(helper, "git-credential-store get", &given, &given).is_empty(), "the launch's own numbered config is the human's");
        assert_eq!(found_env(helper, "x", &[("GIT_CONFIG_COUNT", "2"), ("GIT_CONFIG_KEY_0", "user.name")], &[]).len(), 1, "a missing numbered key is code");
        // A helper's argv is not git's grammar: only the environment counts.
        assert!(found(helper, "git-credential-store -c alias.x=!sh").is_empty());
    }

    #[test]
    fn git_config_parameters_parse_as_git_writes_them() {
        assert_eq!(parse_git_config_parameters("'a.b'='c' 'd.e'='it'\\''s'").unwrap(), vec!["a.b=c", "d.e=it's"]);
        assert_eq!(parse_git_config_parameters("'a.b=c'").unwrap(), vec!["a.b=c"]);
        assert_eq!(parse_git_config_parameters("'alias.x'=''\\!'sh'").unwrap(), vec!["alias.x=!sh"], "git writes ! as '\\!'");
        assert_eq!(parse_git_config_parameters("'a.b'").unwrap(), vec!["a.b"]);
        assert_eq!(parse_git_config_parameters("").unwrap(), Vec::<String>::new());
        assert!(parse_git_config_parameters("a.b=c").is_none());
        assert!(parse_git_config_parameters("'a.b'='c").is_none());
    }

    #[test]
    fn ssh_options_that_run_a_program_or_load_a_library() {
        for ok in [
            "ssh host",
            "ssh -i /k -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -p 2222 git@h",
            "ssh -J bastion h",
            "ssh -o ProxyJump=bastion h",
            "ssh -o ProxyCommand=none h",
            "ssh -o PermitLocalCommand=no h",
            "ssh -o SecurityKeyProvider=internal h",
            "ssh -F none h",
            "ssh -vvv -4 -A h ls -o ProxyCommand=x",
            "ssh h git-upload-pack 'r.git'",
        ] {
            clean("/usr/bin/ssh", ok);
        }
        for bad in [
            "ssh -o ProxyCommand='nc %h %p' h",
            "ssh -oProxyCommand=x h",
            "ssh -o 'ProxyCommand x' h",
            "ssh -o proxycommand=x h",
            "ssh -o LocalCommand=id -o PermitLocalCommand=yes h",
            "ssh -o KnownHostsCommand=/w/k h",
            "ssh -o PKCS11Provider=/w/p.so h",
            "ssh -o SecurityKeyProvider=/w/sk.so h",
            "ssh -o XAuthLocation=/w/x h",
            "ssh -F /w/config h",
            "ssh -I /w/p.so h",
            "ssh h -o ProxyCommand=x",
            "ssh -vo ProxyCommand=x h",
        ] {
            code("/usr/bin/ssh", bad);
        }
        clean("/usr/bin/scp", "scp -i /k -P 2222 -o IdentitiesOnly=yes a h:b");
        code("/usr/bin/scp", "scp -S /w/x a h:b");
        code("/usr/bin/scp", "scp -D /w/sftp-server a h:b");
        code("/usr/bin/scp", "scp -o ProxyCommand=x a h:b");
        code("/usr/bin/scp", "scp a h:b -F /w/c");
        clean("/usr/bin/sftp", "sftp -i /k h");
        code("/usr/bin/sftp", "sftp -b /w/batch h");
        code("/usr/bin/sftp", "sftp -b - h");
        code("/usr/bin/sftp", "sftp -S /w/x h");
        clean("/usr/bin/ssh-add", "ssh-add /k");
        code("/usr/bin/ssh-add", "ssh-add -S /w/sk.so /k");
        code("/usr/bin/ssh-add", "ssh-add -s /w/p.so");
        assert_eq!(found_env("/usr/bin/ssh", "ssh h", &[("SSH_ASKPASS", "/w/a")], &[]), vec!["args:ssh $SSH_ASKPASS"]);
        assert_eq!(found_env("/usr/bin/ssh", "ssh h", &[("SSH_SK_PROVIDER", "/w/sk.so")], &[]), vec!["args:ssh $SSH_SK_PROVIDER"]);
        assert!(found_env("/usr/bin/ssh", "ssh h", &[("SSH_ASKPASS", "/usr/lib/ssh/x11-ssh-askpass")], &[("SSH_ASKPASS", "/usr/lib/ssh/x11-ssh-askpass")]).is_empty());
        assert_eq!(found("/usr/bin/ssh", "ssh -o ProxyCommand=secret-value h"), vec!["args:ssh -o proxycommand"], "names only");
    }

    #[test]
    fn psql_meta_commands_and_files() {
        for ok in ["psql -h db -U app -c 'select 1' prod", "psql --command='select 1'", "psql -X -v x=1 -d prod", "psql postgres://h/db"] {
            clean("/usr/bin/psql", ok);
        }
        for bad in ["psql -f /w/x.sql", "psql --file=/w/x.sql", "psql -c '\\! id'", "psql --command '\\i /w/x'", "psql -Xc '\\lo_import x'", "psql -f -"] {
            code("/usr/bin/psql", bad);
        }
        assert_eq!(found_env("/usr/bin/psql", "psql", &[("PSQLRC", "/w/rc")], &[]), vec!["args:psql $PSQLRC"]);
    }

    #[test]
    fn less_initial_commands_and_key_files() {
        for ok in ["less /f", "less -R -S /f", "less -p pattern /f", "less -- +x"] {
            clean("/usr/bin/less", ok);
        }
        for bad in ["less +!id /f", "less ++/x /f", "less -k /w/keys /f", "less -R -k/w/keys /f", "less --lesskey-src=/w/k /f", "less --lesskey-content=x /f"] {
            code("/usr/bin/less", bad);
        }
        assert_eq!(found_env("/usr/bin/less", "less /f", &[("LESSOPEN", "|/w/x %s")], &[]), vec!["args:less $LESSOPEN"]);
        assert!(found_env("/usr/bin/less", "less /f", &[("LESSOPEN", "| /usr/bin/lesspipe %s")], &[("LESSOPEN", "| /usr/bin/lesspipe %s")]).is_empty(), "Debian's own LESSOPEN, from the launch");
        assert_eq!(found_env("/usr/bin/less", "less /f", &[("LESS", "-R +!id")], &[]), vec!["args:less $LESS"]);
        assert!(found_env("/usr/bin/less", "less /f", &[("LESS", "-FRX")], &[]).is_empty());
        assert_eq!(found_env("/usr/bin/less", "less /f", &[("LESSKEY_CONTENT", "x")], &[]), vec!["args:less $LESSKEY_CONTENT"]);
    }

    #[test]
    fn sed_scripts_that_run_a_command() {
        for s in ["s/a/b/", "s/e/x/g", "/re/d", "1,$p", "s|e|x|gI", "y/abc/xyz/", "/x/{s/a/b/;p}", "$!N;P;D", "s/a/b/w /tmp/o", "a text with e", "1i\\\ne line\\\ne too", "a\\\ne x", ":a;N;ba", "#comment e\np", "\\%x%d", "q5", "l 40", "0~3d", "2,+3p"] {
            assert!(!sed_script_runs_code(s), "{s}");
        }
        for s in ["e id", "1e id", "s/x/id/e", "s/x/id/ge", "/x/e", "p;e", "s/x", "k", "{e}", "s|a|b|e"] {
            assert!(sed_script_runs_code(s), "{s}");
        }
        clean("/usr/bin/sed", "sed -n s/^KEY=//p /f");
        clean("/usr/bin/sed", "sed -i.bak -e s/a/b/ /f");
        clean("/usr/bin/sed", "sed --expression=s/a/b/ /f");
        code("/usr/bin/sed", "sed s/x/id/e /f");
        code("/usr/bin/sed", "sed -ne 1eid /f");
        code("/usr/bin/sed", "sed -e p -e 1eid /f");
        code("/usr/bin/sed", "sed -f /w/script /f");
        code("/usr/bin/sed", "sed --file=/w/script /f");
        clean("/usr/bin/sed", "sed --sandbox -f /w/script /f");
        clean("/usr/bin/sed", "sed --sandbox s/x/id/e /f");
    }

    #[test]
    fn tar_options_that_run_a_program() {
        for ok in ["tar czf /o.tgz /f", "tar -czf /o.tgz /f", "tar --create --file=/o.tar /f", "tar -C /w -xf a.tar", "tar --checkpoint-action=dot -cf x /f", "tar --force-local -cf h:x /f", "tar cf ./a:b /f"] {
            clean("/usr/bin/tar", ok);
        }
        for bad in [
            "tar --to-command=/w/x -xf a.tar",
            "tar --to-command /w/x -xf a.tar",
            "tar --checkpoint=1 --checkpoint-action=exec=id -cf x /f",
            "tar -I /w/zip -cf x /f",
            "tar cIf /w/zip x /f",
            "tar --use-compress-program=/w/x -cf x /f",
            "tar -cf h:x /f",
            "tar cf h:x /f",
            "tar --file=h:x -c /f",
            "tar -F /w/s -cf x /f",
            "tar --rsh-command=/w/x -cf h:x /f",
            "tar --info-script=/w/x -cf x /f",
        ] {
            code("/usr/bin/tar", bad);
        }
        assert_eq!(found_env("/usr/bin/tar", "tar cf x /f", &[("TAR_OPTIONS", "--to-command=x")], &[]), vec!["args:tar $TAR_OPTIONS"]);
    }

    #[test]
    fn rsync_remote_shells() {
        for ok in ["rsync -av /f h:/b", "rsync -e ssh /f h:/b", "rsync -avze 'ssh -p 2222 -i /k' /f h:/b", "rsync --rsh='ssh -o IdentitiesOnly=yes' /f h:/b"] {
            clean("/usr/bin/rsync", ok);
        }
        for bad in ["rsync -e 'sh -c x' /f h:/b", "rsync -avze /w/x /f h:/b", "rsync --rsh=/w/x /f h:/b", "rsync -e 'ssh -o ProxyCommand=x' /f h:/b"] {
            code("/usr/bin/rsync", bad);
        }
        assert_eq!(found_env("/usr/bin/rsync", "rsync /f h:/b", &[("RSYNC_RSH", "sh -c x")], &[]), vec!["args:rsync $RSYNC_RSH"]);
        assert!(found_env("/usr/bin/rsync", "rsync /f h:/b", &[("RSYNC_RSH", "ssh -p 22")], &[]).is_empty());
        assert_eq!(found_env("/usr/bin/rsync", "rsync /f h:/b", &[("RSYNC_CONNECT_PROG", "x")], &[]), vec!["args:rsync $RSYNC_CONNECT_PROG"]);
    }

    #[test]
    fn rule_variables_are_kept_in_the_launch_baseline() {
        assert!(is_rule_var("GIT_SSH_COMMAND") && is_rule_var("GIT_CONFIG_KEY_3") && is_rule_var("LESSOPEN") && !is_rule_var("HOME"));
    }
}
