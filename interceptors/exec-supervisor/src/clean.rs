//! clean — PURE helpers for the exec-output-trust §4 rung-2 CLEAN box
//! (docs/design/integrity/exec-routing.md §8; the enforce-clean family A).
//!
//! Privilege-free and unit-tested by default, per the crate's HARD environment
//! constraint. The kernel backend (`kernel::supervise_exec`) composes these into
//! the live clean-attempt: verify the trusted-read grants pre-fork, run the
//! command under the clean Landlock plan with its stdout captured, and — on a
//! clean completion — report `sha256(stdout)` to the arbiter keyed by the
//! correlated tool_use callId. Everything DECIDABLE without privileges lives
//! here; kernel.rs holds only the fork/pipe/fstat plumbing.

use sha2::{Digest, Sha256};

/// One hash-verified extra read grant for the clean box: `path` becomes
/// readable ONLY if its on-disk bytes hash to `sha256` at plan-build time —
/// the §3 TOCTOU closure (the verdict is resolved against the CONTENT, so a
/// mid-run relabel of the registry entry cannot retroactively bless different
/// bytes). No production source mints these yet: the taint registry records
/// only untrusted-by-origin files, and orphan/unlabeled ⇒ fail-closed
/// untrusted (§5) — so the default grant list is EMPTY and the clean box reads
/// system roots only. The machinery ships so the registry can feed it the day
/// affirmative TRUSTED verdicts exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedRead {
    /// Absolute path of the file to admit into the read-allow set.
    pub path: String,
    /// Lowercase sha256 hex the file's bytes must equal.
    pub sha256: String,
}

/// sha256 of `bytes` as lowercase hex — the hash the clean-verdict store binds
/// the tool_result to. MUST stay byte-exact with the arbiter's consumption
/// (`classifyExecCleanUpgrade` hashes the classified value with node's
/// createHash("sha256")): both sides hash the raw bytes, no normalization.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Resolve `grants` to the paths whose CURRENT content matches the granted
/// hash. Unreadable / missing / mismatched files are DROPPED — dropping a
/// read ALLOWANCE only denies more (restrictive, fail-closed; the command then
/// fails in the box and falls back un-upgraded). Case-insensitive on the
/// grant's hex (hashes are minted by humans/tools in either case), byte-exact
/// on the content.
pub fn verify_trusted_reads(grants: &[TrustedRead]) -> Vec<String> {
    let mut out = Vec::new();
    for g in grants {
        let Ok(bytes) = std::fs::read(&g.path) else { continue };
        if sha256_hex(&bytes) == g.sha256.to_ascii_lowercase() {
            out.push(g.path.clone());
        }
    }
    out
}

/// Cap on the clean attempt's CAPTURED stdout. Output is buffered (not
/// streamed) so a failed attempt can be discarded invisibly before the
/// ordinary-box fallback rerun; past this the attempt aborts. Far above any
/// harness-consumable tool_result (Claude Code truncates long outputs, and a
/// truncated body can never hash-match the verdict anyway).
pub const CLEAN_STDOUT_CAP: usize = 4 * 1024 * 1024;
/// Cap on the captured stderr (diagnostics only — never hashed).
pub const CLEAN_STDERR_CAP: usize = 256 * 1024;

/// Linux dev_t decomposition (the glibc/kernel 64-bit encoding — low 8 + high
/// 12 bits of major interleaved with minor). Local so the PURE build needs no
/// libc; the kernel backend feeds `st_rdev` through these.
pub fn dev_major(rdev: u64) -> u32 {
    (((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfffu64)) as u32
}
pub fn dev_minor(rdev: u64) -> u32 {
    ((rdev & 0xff) | ((rdev >> 12) & !0xffu64)) as u32
}

/// Is this `st_rdev` the `/dev/null` character device (1:3)? Half of the
/// stdin gate: a clean verdict requires stdin to be provably influence-free —
/// closed, or /dev/null — because a PIPE or file could carry bytes from an
/// upstream process the box never saw (`cat evil.md | tool` runs the tool leaf
/// with attacker-influenced stdin; upgrading its output would break the T-LLM
/// invariant, not just utility). The caller checks S_ISCHR separately.
pub fn dev_is_dev_null(rdev: u64) -> bool {
    dev_major(rdev) == 1 && dev_minor(rdev) == 3
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn tmpfile(name: &str, content: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "mandu-clean-test-{}-{name}",
            std::process::id()
        ));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content).unwrap();
        p
    }

    #[test]
    fn sha256_hex_matches_the_known_vector() {
        // Empty input — the canonical vector; pins the hex casing + length the
        // arbiter's node-side createHash comparison depends on.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn verify_trusted_reads_admits_only_hash_matching_files() {
        let good = tmpfile("good", b"trusted bytes\n");
        let bad = tmpfile("bad", b"tampered bytes\n");
        let grants = vec![
            TrustedRead {
                path: good.to_string_lossy().into_owned(),
                sha256: sha256_hex(b"trusted bytes\n"),
            },
            // Grant minted for DIFFERENT bytes than what is on disk → dropped
            // (this is the TOCTOU closure: content, not label, is what's vouched).
            TrustedRead {
                path: bad.to_string_lossy().into_owned(),
                sha256: sha256_hex(b"the bytes the verdict was about\n"),
            },
            // Missing file → dropped (restrictive).
            TrustedRead {
                path: "/nonexistent/mandu-clean-test".into(),
                sha256: sha256_hex(b"x"),
            },
        ];
        let admitted = verify_trusted_reads(&grants);
        assert_eq!(admitted, vec![good.to_string_lossy().into_owned()]);
        let _ = std::fs::remove_file(&good);
        let _ = std::fs::remove_file(&bad);
    }

    #[test]
    fn verify_trusted_reads_is_case_insensitive_on_the_grant_hex_only() {
        let f = tmpfile("case", b"payload");
        let upper = sha256_hex(b"payload").to_ascii_uppercase();
        let admitted = verify_trusted_reads(&[TrustedRead {
            path: f.to_string_lossy().into_owned(),
            sha256: upper,
        }]);
        assert_eq!(admitted.len(), 1, "an uppercase grant hex still verifies");
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn dev_null_rdev_decodes_as_1_3() {
        // makedev(1,3) in the common encoding: major<<8 | minor for small devs.
        let rdev: u64 = (1 << 8) | 3;
        assert_eq!(dev_major(rdev), 1);
        assert_eq!(dev_minor(rdev), 3);
        assert!(dev_is_dev_null(rdev));
        // /dev/zero is 1:5 — near miss must not pass.
        assert!(!dev_is_dev_null((1 << 8) | 5));
        // A pty (136:0) — not even close.
        assert!(!dev_is_dev_null(136 << 8));
    }
}
