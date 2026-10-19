//! launch_wrap — which Landlock layer of the agent tree governs no file
//! access, so an open the guard performs for a task under it needs no mirror
//! thread (confidentiality-plan-10-flow-taint.md §4.1a, "The cost of the
//! mirror").
//!
//! The guard performs every open that can read, and a task in a Landlock
//! sandbox has that access run on a mirror thread restricted like it
//! (`landlock_mirror`). The whole agent tree is in one such sandbox: the
//! launch's own wrap, `mandu-landlock-apply --net-only`, which handles TCP
//! and NOTHING on the filesystem (`plan_net_confine`: `handled_access_fs` is
//! 0). A Landlock domain whose every layer handles no filesystem access
//! decides every file access "allowed", exactly as no domain does, so the
//! guard's own thread reopens the file it resolved the same way, without
//! the two cross-thread handoffs the mirror costs (about 0.2 ms of every
//! open, measured 2026-10-05). Any other layer (a box's applier, a program
//! that sandboxes itself, a second wrap) keeps the mirror; so do a
//! pseudo-filesystem file (the context helper reopens it under the whole
//! domain: Landlock's ptrace scoping decides `/proc/<pid>/…` in every
//! domain), the mutating steps and the connects.
//!
//! Which layer is the wrap's is decided from what the guard itself knows,
//! never from what a tracee says: the guard's own target argv (the program
//! it execs, `-- <argv…>`) must be the applier in `--net-only` mode, and the
//! restriction must be the launch's (the guard's direct child's first, while
//! its image is the applier: `LandlockMirror::is_launch_restriction`), made
//! by a process whose command line is exactly that argv and whose
//! executable is the very file the argv names. Fail-closed: anything else
//! (a relative path, an unreadable `/proc`, another argv) leaves the layer
//! governing files, and the mirror runs as before.
//!
//! Pure (no privilege): `net_only_wrap`, `restriction_is_wrap`,
//! `layers_govern_files`. `Mandu-new`.

/// The applier's file name (`interceptors/exec-supervisor`'s bin).
pub const APPLIER: &str = "mandu-landlock-apply";

/// The applier's options that take a value (the next argument is never an
/// option of its own).
const VALUE_OPTIONS: &[&str] = &["--rw", "--read", "--write-only", "--allow-tcp-port", "--allow-tcp-bind-port", "--ready-fd"];

/// Is `argv` (the guard's own target) the whole-agent net-only wrap: the
/// applier by an absolute path, whose options, up to its own `--`, carry
/// `--net-only` and neither `--clean` nor `--seccomp-only` (the applier
/// refuses both with it; refused here too, so a combination it might accept
/// one day is not assumed to govern no file)?
pub fn net_only_wrap(argv: &[String]) -> bool {
    let Some(exe) = argv.first() else { return false };
    if !exe.starts_with('/') || exe.rsplit('/').next() != Some(APPLIER) {
        return false;
    }
    let mut net_only = false;
    let mut it = argv[1..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--" => return net_only,
            "--net-only" => net_only = true,
            "--clean" | "--seccomp-only" => return false,
            v if VALUE_OPTIONS.contains(&v) => {
                if it.next().is_none() {
                    return false;
                }
            }
            _ => {}
        }
    }
    // No `--` (the applier refuses to run without a target): not a wrap.
    false
}

/// The wrap as the guard recorded it at its start: its argv and the
/// `(st_dev, st_ino)` of the file `argv[0]` named then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchWrap {
    pub argv: Vec<String>,
    pub exe: (u64, u64),
}

impl LaunchWrap {
    /// The wrap for the guard's target, or None when it is not one
    /// (`net_only_wrap`) or its file cannot be identified.
    pub fn of(argv: &[String], identify: impl Fn(&str) -> Option<(u64, u64)>) -> Option<LaunchWrap> {
        if !net_only_wrap(argv) {
            return None;
        }
        let exe = identify(&argv[0])?;
        Some(LaunchWrap { argv: argv.to_vec(), exe })
    }
}

/// Is a restriction made by a process with this command line and this
/// executable `(st_dev, st_ino)` the wrap's? Its exact argv, and the very
/// file. An unknown executable is not.
pub fn restriction_is_wrap(wrap: &LaunchWrap, cmdline: &[String], exe: Option<(u64, u64)>) -> bool {
    exe == Some(wrap.exe) && cmdline == wrap.argv.as_slice()
}

/// `/proc/<pid>/cmdline` as arguments (NUL-separated, the trailing NUL
/// dropped).
pub fn parse_cmdline(raw: &[u8]) -> Vec<String> {
    let raw = raw.strip_suffix(&[0]).unwrap_or(raw);
    if raw.is_empty() {
        return Vec::new();
    }
    raw.split(|b| *b == 0).map(|a| String::from_utf8_lossy(a).into_owned()).collect()
}

/// Does a domain with these layers (each: is it the net-only wrap's?)
/// govern file access? Only a domain with at least one layer, every one the
/// wrap's, does not. A domain with no layer at all is the refusing one
/// (`Domain::refusing`): it governs everything.
pub fn layers_govern_files(wrap_layers: &[bool]) -> bool {
    wrap_layers.is_empty() || !wrap_layers.iter().all(|w| *w)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    const APPLY: &str = "/opt/mandu/target/release/mandu-landlock-apply";

    #[test]
    fn the_launchers_net_only_wrap_is_one() {
        assert!(net_only_wrap(&v(&[APPLY, "--net-only", "--allow-tcp-port", "22", "--allow-tcp-port", "443", "--skip-unsupported", "--", "claude"])));
        assert!(net_only_wrap(&v(&[APPLY, "--allow-tcp-bind-port", "4000", "--net-only", "--seccomp-deny", "--", "a", "--net-only"])));
    }

    #[test]
    fn anything_else_governs_files() {
        // the box's FS overlay, the clean box, seccomp only
        assert!(!net_only_wrap(&v(&[APPLY, "--rw", "/tmp", "--deny-tcp", "--", "head"])));
        assert!(!net_only_wrap(&v(&[APPLY, "--net-only", "--clean", "--", "x"])));
        assert!(!net_only_wrap(&v(&[APPLY, "--seccomp-only", "--net-only", "--", "x"])));
        // `--net-only` only after the applier's own `--` is the target's
        assert!(!net_only_wrap(&v(&[APPLY, "--rw", "/w", "--", "prog", "--net-only"])));
        // a value that reads like the flag is a value
        assert!(!net_only_wrap(&v(&[APPLY, "--rw", "--net-only", "--", "x"])));
        // a relative path, another program, no target, an empty argv
        assert!(!net_only_wrap(&v(&["mandu-landlock-apply", "--net-only", "--", "x"])));
        assert!(!net_only_wrap(&v(&["/usr/bin/mandu-landlock-applyx", "--net-only", "--", "x"])));
        assert!(!net_only_wrap(&v(&["/bin/claude", "--net-only", "--", "x"])));
        assert!(!net_only_wrap(&v(&[APPLY, "--net-only"])));
        assert!(!net_only_wrap(&v(&[APPLY, "--net-only", "--allow-tcp-port"])));
        assert!(!net_only_wrap(&[]));
    }

    #[test]
    fn the_wrap_is_recorded_with_its_files_identity() {
        let argv = v(&[APPLY, "--net-only", "--", "claude"]);
        let w = LaunchWrap::of(&argv, |p| (p == APPLY).then_some((7, 42))).expect("a wrap");
        assert_eq!(w.exe, (7, 42));
        assert_eq!(LaunchWrap::of(&argv, |_| None), None, "a file that cannot be identified: no wrap");
        assert_eq!(LaunchWrap::of(&v(&[APPLY, "--rw", "/", "--", "x"]), |_| Some((7, 42))), None);
    }

    #[test]
    fn a_restriction_is_the_wraps_only_with_its_exact_argv_and_file() {
        let argv = v(&[APPLY, "--net-only", "--allow-tcp-port", "443", "--", "claude"]);
        let w = LaunchWrap { argv: argv.clone(), exe: (7, 42) };
        assert!(restriction_is_wrap(&w, &argv, Some((7, 42))));
        assert!(!restriction_is_wrap(&w, &argv, Some((7, 43))), "another file of the same name");
        assert!(!restriction_is_wrap(&w, &argv, None), "an executable that cannot be read");
        // a second applier further down the chain (its argv is the rest)
        assert!(!restriction_is_wrap(&w, &v(&[APPLY, "--rw", "/w", "--", "claude"]), Some((7, 42))));
        assert!(!restriction_is_wrap(&w, &argv[..argv.len() - 1], Some((7, 42))));
    }

    #[test]
    fn cmdline_parses_as_arguments() {
        assert_eq!(parse_cmdline(b"/a/b\0--net-only\0--\0x\0"), v(&["/a/b", "--net-only", "--", "x"]));
        assert_eq!(parse_cmdline(b"a\0\0b\0"), v(&["a", "", "b"]));
        assert_eq!(parse_cmdline(b""), Vec::<String>::new());
    }

    #[test]
    fn only_a_domain_of_wrap_layers_alone_governs_no_file() {
        assert!(!layers_govern_files(&[true]));
        assert!(layers_govern_files(&[true, false]), "a box's applier under the wrap");
        assert!(layers_govern_files(&[false]));
        assert!(layers_govern_files(&[]), "the refusing domain");
    }
}
