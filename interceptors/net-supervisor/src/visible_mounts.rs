//! visible_mounts — confidentiality plan 13 §4.9, the lookups and read
//! offsets a holder sends to a network or FUSE mount (decided 2026-10-07:
//! "refuse raw if visible").
//!
//! A program holding a secret puts bytes on a mount's server without any
//! write: every name it LOOKS UP (a `stat`, an `open` of a name that does not
//! exist, a `getxattr`, any path walk: up to 255 bytes a component) and the
//! offsets of its reads there. No seccomp filter can judge every path walk.
//! So the guard judges the moment a program would become a holder: a raw
//! open of a secret is refused (the program gets the placeholder twin, as a
//! program that is no reader does) while a mount that would see its lookups
//! is visible in its mount namespace and is neither a binding of what it
//! would hold (`mount:<fstype>:<source>`, by equality, as for a write) nor
//! named in policy.yaml `remote_mounts.trust_lookups` (by mount point and
//! type: "this mount may see holders' lookups").
//!
//! Which mounts count (`counts_for_lookups`): the network and FUSE types of
//! `local_exits::remote_fstype`, every FUSE type included (a user-space
//! server may send what it is asked anywhere), and an automount point
//! (`autofs`: a lookup under it mounts, and for `/net/<host>` resolves, what
//! the name says), except
//!   - a host share of the machine's own hypervisor or of WSL (`virtiofs`, a
//!     `9p` mount over `trans=virtio`, `trans=xen` or `trans=fd`, `drvfs`):
//!     the server is this machine's host, not another machine; a `9p` mount
//!     over a network or a socket counts;
//!   - systemd's local automount points (`binfmt_misc`, the EFI and boot
//!     partitions).
//! Writes there are judged as before (`local_exits`): a host share stays a
//! destination for a holder's write.
//!
//! The check is cheap: the rows are read once per mount namespace and kept
//! with the open `mountinfo` (`MountViews`); a `poll` of that descriptor
//! says whether the table changed since (proc(5): `POLLPRI | POLLERR`), and
//! only then is it read again. A namespace whose table cannot be read
//! counts as one with such a mount (fail-closed).
//!
//! Pure classification plus `/proc` reads (no privilege). `Mandu-new`.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::local_exits::{mount_bound, mount_destination, remote_fstype, superopt, MountRow};

/// policy.yaml `remote_mounts.trust_lookups` as the launcher writes it into
/// the guard's policy file (`trustLookups`): a mount whose server may see
/// the names and offsets a holder looks up there. Matched by its mount
/// point (exact, as the holder's mount namespace names it) and its type
/// (case-insensitive). Writes there are still judged (`local_exits`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TrustLookup {
    pub mount: String,
    #[serde(rename = "type")]
    pub fstype: String,
}

/// One mount that sees lookups, as found in a namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisibleMount {
    pub mount_point: String,
    pub fstype: String,
    pub source: String,
    /// `st_dev` of the mount (the `major:minor` field, encoded as glibc
    /// encodes `makedev`).
    pub dev: u64,
}

impl VisibleMount {
    /// The destination it is bound by (`mount:<fstype>:<source>`), as a
    /// write there is named.
    pub fn destination(&self) -> String {
        mount_destination(&self.fstype, &self.source)
    }
}

/// systemd's automount points of local file systems (binfmt_misc, the
/// partitions `systemd-gpt-auto-generator` mounts on first access).
pub const LOCAL_AUTOMOUNTS: &[&str] = &["/proc/sys/fs/binfmt_misc", "/boot", "/efi", "/boot/efi"];

/// Does a mount of this type (and these super options, at this point) see
/// the lookups made under it from another machine or a user-space server?
/// Pure; the module docs say which count.
pub fn counts_for_lookups(fstype: &str, superopts: &str, mount_point: &str) -> bool {
    let t = fstype.to_ascii_lowercase();
    if t == "autofs" {
        return !LOCAL_AUTOMOUNTS.contains(&mount_point.trim_end_matches('/'));
    }
    if t == "virtiofs" || t == "drvfs" {
        return false;
    }
    if t == "9p" {
        return !matches!(superopt(superopts, "trans").as_deref().map(str::to_ascii_lowercase).as_deref(), Some("virtio" | "xen" | "fd"));
    }
    remote_fstype(&t)
}

/// `major:minor` → `st_dev`, as glibc's `makedev` encodes it.
pub fn makedev(major: u64, minor: u64) -> u64 {
    ((major & 0xffff_f000) << 32) | ((major & 0x0000_0fff) << 8) | ((minor & 0xffff_ff00) << 12) | (minor & 0x0000_00ff)
}

/// The `major:minor` field of a `mountinfo` line, as `st_dev`.
pub fn mountinfo_dev(line: &str) -> Option<u64> {
    let mut f = line.split(' ');
    let (_, _, dev) = (f.next()?, f.next()?, f.next()?);
    let (ma, mi) = dev.split_once(':')?;
    Some(makedev(ma.parse().ok()?, mi.parse().ok()?))
}

/// One parsed row: the fields `local_exits` reads, and its device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub row: MountRow,
    pub dev: u64,
}

/// Every row of a `mountinfo` text (malformed lines skipped).
pub fn parse_rows(mountinfo: &str) -> Vec<Row> {
    mountinfo
        .lines()
        .filter_map(|l| Some(Row { row: crate::local_exits::parse_mountinfo_line(l)?, dev: mountinfo_dev(l)? }))
        .collect()
}

/// The mounts among `rows` that see lookups. `extra_devs`: file systems (by
/// `st_dev`) a test counts as remote (`GuardConfig::extra_remote_devs`;
/// empty in production).
pub fn visible(rows: &[Row], extra_devs: &[u64]) -> Vec<VisibleMount> {
    rows.iter()
        .filter(|r| counts_for_lookups(&r.row.fstype, &r.row.superopts, &r.row.mount_point) || extra_devs.contains(&r.dev))
        .map(|r| VisibleMount { mount_point: r.row.mount_point.clone(), fstype: r.row.fstype.clone(), source: r.row.source.clone(), dev: r.dev })
        .collect()
}

fn trim_mount(p: &str) -> &str {
    if p.len() > 1 { p.trim_end_matches('/') } else { p }
}

/// Is this mount named in `trust_lookups` (mount point exact, type
/// case-insensitive)?
pub fn trusted(m: &VisibleMount, trust: &[TrustLookup]) -> bool {
    trust.iter().any(|t| trim_mount(&t.mount) == trim_mount(&m.mount_point) && t.fstype.eq_ignore_ascii_case(&m.fstype))
}

/// The mounts that are not trusted for lookups: the candidates before any
/// binding is asked for (none ⇒ no arbiter round trip).
pub fn untrusted(found: Vec<VisibleMount>, trust: &[TrustLookup]) -> Vec<VisibleMount> {
    found.into_iter().filter(|m| !trusted(m, trust)).collect()
}

/// The mounts that withhold a raw open: the untrusted ones that are not a
/// binding of what the opener would hold. `bindings` `None` (the arbiter
/// could not say): every candidate withholds (fail-closed).
pub fn withholding(candidates: &[VisibleMount], bindings: Option<&[String]>) -> Vec<VisibleMount> {
    candidates.iter().filter(|m| !bindings.is_some_and(|b| mount_bound(b, &m.destination()))).cloned().collect()
}

/// The sentence a withheld raw open is explained by (the event's reason,
/// the guard's log).
pub fn withheld_reason(file: &str, mounts: &[VisibleMount]) -> String {
    let names: Vec<String> = mounts.iter().map(|m| format!("{} ({}, {})", m.mount_point, m.fstype, m.source)).collect();
    format!(
        "{file}: the real file is withheld (the placeholder copy is served) while {} {} visible: a program holding a secret sends every name it looks up there to {}. Bind the secret to the mount ({}) or name it in policy.yaml remote_mounts.trust_lookups",
        names.join(", "),
        if mounts.len() == 1 { "is" } else { "are" },
        if mounts.len() == 1 { "its server" } else { "their servers" },
        mounts.iter().map(|m| m.destination()).collect::<Vec<_>>().join(", ")
    )
}

// ── the per-namespace cache (`/proc` reads, no privilege) ──────────────────

/// One mount namespace's table: the open `mountinfo` (it holds the
/// namespace, so its identity cannot be reused while cached) and its rows.
struct View {
    file: std::fs::File,
    rows: Vec<Row>,
}

/// The most namespaces kept; past it the cache starts over.
const MAX_VIEWS: usize = 64;

/// The mount tables of the namespaces the guard has judged an open in,
/// keyed by the namespace's identity (`/proc/<pid>/ns/mnt`).
#[derive(Default)]
pub struct MountViews {
    views: Mutex<HashMap<(u64, u64), View>>,
}

fn ns_id(pid: i32) -> Option<(u64, u64)> {
    std::fs::metadata(format!("/proc/{pid}/ns/mnt")).ok().map(|m| (m.dev(), m.ino()))
}

/// Has the table behind this `mountinfo` descriptor changed since the last
/// poll (or the open)? A poll that fails says yes.
fn changed(file: &std::fs::File) -> bool {
    let mut p = libc::pollfd { fd: file.as_raw_fd(), events: libc::POLLPRI, revents: 0 };
    // SAFETY: one pollfd, no wait.
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    n != 0 && (n < 0 || p.revents & (libc::POLLPRI | libc::POLLERR | libc::POLLNVAL) != 0)
}

fn read_all(file: &mut std::fs::File) -> Option<String> {
    file.seek(SeekFrom::Start(0)).ok()?;
    let mut s = String::new();
    file.read_to_string(&mut s).ok()?;
    Some(s)
}

impl MountViews {
    pub fn new() -> Self {
        Self::default()
    }

    /// The mounts that see lookups in `pid`'s mount namespace. `Err`: the
    /// table could not be read (the caller withholds).
    pub fn visible_for(&self, pid: i32, extra_devs: &[u64]) -> Result<Vec<VisibleMount>, String> {
        let Some(id) = ns_id(pid) else { return Err(format!("the mount namespace of process {pid} could not be read")) };
        let mut views = self.views.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(v) = views.get_mut(&id) {
            if changed(&v.file) {
                match read_all(&mut v.file) {
                    Some(t) => v.rows = parse_rows(&t),
                    None => {
                        views.remove(&id);
                        return Err("the mount table could not be read again".into());
                    }
                }
            }
            return Ok(visible(&v.rows, extra_devs));
        }
        let mut file = std::fs::File::open(format!("/proc/{pid}/mountinfo")).map_err(|e| format!("/proc/{pid}/mountinfo: {e}"))?;
        // The process may have moved to another namespace between the two
        // looks: then this table is not the one keyed (refuse; the next open
        // looks again).
        if ns_id(pid) != Some(id) {
            return Err(format!("process {pid} changed its mount namespace while the guard looked"));
        }
        let text = read_all(&mut file).ok_or_else(|| format!("/proc/{pid}/mountinfo could not be read"))?;
        let rows = parse_rows(&text);
        let out = visible(&rows, extra_devs);
        if views.len() >= MAX_VIEWS {
            views.clear();
        }
        views.insert(id, View { file, rows });
        Ok(out)
    }

    /// How many namespaces are cached (tests).
    pub fn cached(&self) -> usize {
        self.views.lock().map(|v| v.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Case {
        line: String,
        counts: bool,
        #[serde(default)]
        dest: Option<String>,
    }
    #[derive(Deserialize)]
    struct Cases {
        cases: Vec<Case>,
    }

    /// The table shared with the launcher's `remote-mounts.ts` test.
    #[test]
    fn the_shared_cases_classify_as_listed() {
        let cases: Cases = serde_json::from_str(include_str!("visible_mounts.json")).unwrap();
        assert!(cases.cases.len() >= 20);
        for c in cases.cases {
            let rows = parse_rows(&c.line);
            assert_eq!(rows.len(), 1, "{}", c.line);
            let v = visible(&rows, &[]);
            assert_eq!(!v.is_empty(), c.counts, "{}", c.line);
            if let Some(d) = c.dest {
                assert_eq!(v[0].destination(), d);
            }
        }
    }

    #[test]
    fn nine_p_counts_unless_its_transport_is_the_host() {
        assert!(counts_for_lookups("9p", "rw,trans=tcp", "/m"));
        assert!(counts_for_lookups("9p", "rw,trans=rdma", "/m"));
        assert!(counts_for_lookups("9p", "rw", "/m"));
        assert!(!counts_for_lookups("9p", "rw,trans=virtio", "/m"));
        assert!(!counts_for_lookups("9P", "rw,trans=VIRTIO", "/m"));
        assert!(!counts_for_lookups("9p", "rw,trans=xen", "/m"));
        assert!(!counts_for_lookups("9p", "rw,trans=fd,rfd=3", "/m"));
        // The last value counts, as the kernel keeps it.
        assert!(counts_for_lookups("9p", "trans=virtio,trans=tcp", "/m"));
    }

    #[test]
    fn automounts_count_except_systemds_local_ones() {
        assert!(counts_for_lookups("autofs", "fd=7", "/net"));
        assert!(counts_for_lookups("autofs", "fd=7", "/home"));
        assert!(!counts_for_lookups("autofs", "fd=7", "/proc/sys/fs/binfmt_misc"));
        assert!(!counts_for_lookups("autofs", "fd=7", "/boot/efi/"));
    }

    #[test]
    fn devices_decode_as_glibc_encodes() {
        assert_eq!(makedev(0, 26), 26);
        assert_eq!(makedev(8, 1), 0x801);
        assert_eq!(crate::local_exits::dev_major_minor(makedev(259, 1_048_575)), (259, 1_048_575));
        assert_eq!(mountinfo_dev("23 22 0:26 / /dev/shm rw - tmpfs tmpfs rw"), Some(26));
        assert_eq!(mountinfo_dev("garbage"), None);
    }

    #[test]
    fn a_test_device_counts_a_local_mount() {
        let rows = parse_rows("23 22 0:26 / /dev/shm rw - tmpfs tmpfs rw\n22 1 8:1 / / rw - ext4 /dev/sda1 rw\n");
        assert!(visible(&rows, &[]).is_empty());
        let v = visible(&rows, &[26]);
        assert_eq!(v.len(), 1);
        assert_eq!((v[0].mount_point.as_str(), v[0].destination().as_str()), ("/dev/shm", "mount:tmpfs:tmpfs"));
    }

    fn nfs() -> VisibleMount {
        VisibleMount { mount_point: "/home".into(), fstype: "nfs4".into(), source: "nas:/home".into(), dev: 51 }
    }
    fn sshfs() -> VisibleMount {
        VisibleMount { mount_point: "/mnt/s".into(), fstype: "fuse.sshfs".into(), source: "u@h:/".into(), dev: 52 }
    }

    #[test]
    fn a_trusted_mount_is_named_by_its_point_and_its_type() {
        let t = vec![TrustLookup { mount: "/home/".into(), fstype: "NFS4".into() }];
        assert!(trusted(&nfs(), &t));
        assert!(!trusted(&sshfs(), &t));
        // The same point with another type is another mount.
        assert!(!trusted(&nfs(), &[TrustLookup { mount: "/home".into(), fstype: "nfs".into() }]));
        assert!(!trusted(&nfs(), &[TrustLookup { mount: "/".into(), fstype: "nfs4".into() }]));
        assert_eq!(untrusted(vec![nfs(), sshfs()], &t), vec![sshfs()]);
        assert!(untrusted(vec![], &t).is_empty());
    }

    #[test]
    fn a_raw_open_is_withheld_by_every_unbound_untrusted_mount_and_by_an_unknown_answer() {
        let c = vec![nfs(), sshfs()];
        // No binding: both withhold.
        assert_eq!(withholding(&c, Some(&[])), c);
        // Bound to one: the other still withholds.
        assert_eq!(withholding(&c, Some(&["mount:nfs4:nas:/home".into(), "api.example.com".into()])), vec![sshfs()]);
        // Bound to both: none.
        assert!(withholding(&c, Some(&["mount:nfs4:nas:/home".into(), "mount:fuse.sshfs:u@h:/".into()])).is_empty());
        // A host binding never admits a mount; a prefix is no binding.
        assert_eq!(withholding(&[nfs()], Some(&["nas".into(), "mount:nfs4:nas".into()])), vec![nfs()]);
        // The arbiter could not say: every candidate withholds.
        assert_eq!(withholding(&c, None), c);
        // No candidate: nothing withholds, whatever the answer.
        assert!(withholding(&[], None).is_empty());
    }

    #[test]
    fn the_reason_names_each_mount_and_how_to_admit_it() {
        let r = withheld_reason("/s/.env", &[nfs()]);
        assert!(r.contains("/home (nfs4, nas:/home) is visible"), "{r}");
        assert!(r.contains("mount:nfs4:nas:/home"), "{r}");
        assert!(r.contains("remote_mounts.trust_lookups"), "{r}");
        assert!(withheld_reason("/s/.env", &[nfs(), sshfs()]).contains("are visible"));
    }

    #[test]
    fn the_policy_file_spelling_parses() {
        let t: Vec<TrustLookup> = serde_json::from_str(r#"[{"mount":"/home","type":"nfs4"}]"#).unwrap();
        assert_eq!(t, vec![TrustLookup { mount: "/home".into(), fstype: "nfs4".into() }]);
    }

    #[test]
    fn the_own_namespace_is_read_once_and_kept_until_it_changes() {
        let v = MountViews::new();
        let me = std::process::id() as i32;
        let a = v.visible_for(me, &[]).expect("own mount table");
        assert_eq!(v.cached(), 1);
        // A second look reuses the kept table (nothing mounted meanwhile).
        let b = v.visible_for(me, &[]).unwrap();
        assert_eq!(a, b);
        assert_eq!(v.cached(), 1);
        // The test hook counts the root's own device.
        let root_dev = std::fs::metadata("/").unwrap().dev();
        let own = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        if parse_rows(&own).iter().any(|r| r.dev == root_dev) {
            assert!(v.visible_for(me, &[root_dev]).unwrap().iter().any(|m| m.dev == root_dev));
        }
        // A process that is gone: an error, never an empty list.
        assert!(v.visible_for(i32::MAX, &[]).is_err());
    }
}
