//! wsl — Windows Subsystem for Linux detection and the Windows interop surface
//! (os-test-matrix.md `wsl2` row; exec-routing.md §4.1 "WSL2: the interop door").
//!
//! PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
//!
//! WSL2 runs a real Linux kernel, so every Linux mechanism applies unchanged.
//! What WSL2 ADDS is a door out of every Linux box: Windows interop. The kernel
//! has a binfmt_misc entry (`WSLInterop`, interpreter `/init`) that turns an
//! `execve` of any PE file (`cmd.exe`, `powershell.exe`, a copied `.exe`) into a
//! request over the interop Unix socket named by `$WSL_INTEROP`
//! (`/run/WSL/<pid>_interop`); the Windows side then starts the program as the
//! Windows user, OUTSIDE every Linux namespace, Landlock domain and seccomp
//! filter. Such a program can read the real Linux files through
//! `\\wsl.localhost\<distro>\…` (the distro's 9p server lives in init's mount
//! namespace, not the box's) and reach any network host. It also has a second
//! channel: `AF_VSOCK` (Hyper-V sockets) to the Windows host, which a Linux
//! network namespace does not cut on the 6.6 WSL kernels.
//!
//! The capability is the SOCKET, not the `.exe`: the binfmt entry carries the
//! `F` flag, so the kernel opened `/init` at registration and runs it without a
//! path lookup (hiding `/init` or denying execute on `/mnt/*` does not stop a
//! PE copied elsewhere). With the socket unreachable the interop client has
//! nobody to ask. So the closures are:
//!   - AgentShell box (exec-supervisor): a fresh tmpfs over `/run/WSL` (and
//!     `/mnt/wslg`), `/dev/null` over `/init` and over the `$WSL_INTEROP` path,
//!     `WSL_INTEROP` unset, and `socket(AF_VSOCK)` + io_uring denied by the
//!     seccomp filter. Mount-based, so race-free.
//!   - whole agent (net-guard): refuse `connect(2)` to the interop socket and
//!     to any `AF_VSOCK` address; the secret-twin bwrap wrap also hides
//!     `/run/WSL` where it runs.
//!
//! This module is PURE detection + constants, shared by exec-supervisor and
//! net-supervisor so both answer "is this WSL?" the same way (and the same way
//! as the launcher's `launcher/src/wsl.ts`). `probe_host` does the three small
//! reads; everything else takes its inputs as arguments.

/// The env var naming this session's interop socket.
pub const INTEROP_ENV: &str = "WSL_INTEROP";
/// Where WSL puts the interop sockets (`<pid>_interop`).
pub const INTEROP_DIR: &str = "/run/WSL";
/// WSLg's sockets (X11, Wayland, PulseAudio, the RDP channel to Windows).
pub const WSLG_DIR: &str = "/mnt/wslg";
/// The WSL init, which doubles as the interop client.
pub const INIT_PATH: &str = "/init";
/// The binfmt_misc entry that routes PE execs to `/init`.
pub const BINFMT_INTEROP: &str = "/proc/sys/fs/binfmt_misc/WSLInterop";
/// The kernel release string.
pub const OSRELEASE: &str = "/proc/sys/kernel/osrelease";
/// `AF_VSOCK` (Hyper-V sockets on WSL2), Linux UAPI.
pub const AF_VSOCK: u16 = 40;

/// WSL generation from the kernel release: WSL2 kernels carry
/// `-microsoft-standard` (`-microsoft-standard-WSL2` since 5.10; the first
/// 4.19 ones had no suffix), WSL1 reports `…-Microsoft`. `None` = not WSL.
/// Mirrors `wslVersion` in `launcher/src/wsl.ts` (parity-tested on the same
/// strings there and here).
pub fn wsl_version(osrelease: &str) -> Option<u8> {
    let lower = osrelease.to_ascii_lowercase();
    if lower.contains("microsoft-standard") || lower.contains("wsl2") {
        Some(2)
    } else if lower.contains("microsoft") {
        Some(1)
    } else {
        None
    }
}

/// What the host says about WSL. Any ONE signal is enough (`is_wsl`): the
/// hiding only ever removes WSL-only paths, so a false positive costs nothing
/// and a missed signal would leave the door open.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WslSignals {
    /// `/proc/sys/kernel/osrelease`, when readable.
    pub osrelease: Option<String>,
    /// `$WSL_INTEROP`, when set and non-empty.
    pub interop_env: Option<String>,
    /// Does `/proc/sys/fs/binfmt_misc/WSLInterop` exist?
    pub binfmt_interop: bool,
}

impl WslSignals {
    /// Is this a WSL host (either generation)?
    pub fn is_wsl(&self) -> bool {
        self.osrelease.as_deref().and_then(wsl_version).is_some()
            || self.interop_env.is_some()
            || self.binfmt_interop
    }
}

/// Read the three signals from the running host. Never fails: an unreadable
/// signal is just absent.
pub fn probe_host() -> WslSignals {
    WslSignals {
        osrelease: std::fs::read_to_string(OSRELEASE).ok().map(|s| s.trim().to_string()),
        interop_env: std::env::var(INTEROP_ENV).ok().filter(|v| !v.is_empty()),
        binfmt_interop: std::path::Path::new(BINFMT_INTEROP).exists(),
    }
}

/// Is `p` at or under `root`? Both are absolute paths; component-exact
/// (`/run/WSLx` is not under `/run/WSL`).
pub fn at_or_under(p: &str, root: &str) -> bool {
    let root = root.trim_end_matches('/');
    p == root || (p.starts_with(root) && p.as_bytes().get(root.len()) == Some(&b'/'))
}

/// Is `path` (already canonical: absolute, symlinks resolved) an interop
/// socket? Anything under `/run/WSL`, or the socket `$WSL_INTEROP` names
/// (`interop_env`, also canonical) wherever it lives.
pub fn is_interop_path(path: &str, interop_env: Option<&str>) -> bool {
    at_or_under(path, INTEROP_DIR) || interop_env.map(|e| path == e).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kernel_release_names_the_generation() {
        assert_eq!(wsl_version("5.15.167.4-microsoft-standard-WSL2"), Some(2));
        assert_eq!(wsl_version("6.6.36.6-microsoft-standard-WSL2+"), Some(2));
        assert_eq!(wsl_version("4.19.104-microsoft-standard"), Some(2));
        assert_eq!(wsl_version("4.4.0-19041-Microsoft"), Some(1));
        assert_eq!(wsl_version("6.8.0-139-generic"), None);
        assert_eq!(wsl_version(""), None);
    }

    #[test]
    fn any_one_signal_makes_a_wsl_host() {
        assert!(!WslSignals::default().is_wsl());
        assert!(!WslSignals { osrelease: Some("6.8.0-139-generic".into()), ..Default::default() }.is_wsl());
        assert!(WslSignals { osrelease: Some("5.15.1-microsoft-standard-WSL2".into()), ..Default::default() }.is_wsl());
        assert!(WslSignals { interop_env: Some("/run/WSL/8_interop".into()), ..Default::default() }.is_wsl());
        assert!(WslSignals { binfmt_interop: true, ..Default::default() }.is_wsl());
    }

    #[test]
    fn interop_paths_are_component_exact() {
        assert!(is_interop_path("/run/WSL/8_interop", None));
        assert!(is_interop_path("/run/WSL", None));
        assert!(!is_interop_path("/run/WSLx/8_interop", None));
        assert!(!is_interop_path("/run/user/1000/bus", None));
        assert!(is_interop_path("/srv/x/1_interop", Some("/srv/x/1_interop")));
        assert!(!is_interop_path("/srv/x/2_interop", Some("/srv/x/1_interop")));
    }
}
