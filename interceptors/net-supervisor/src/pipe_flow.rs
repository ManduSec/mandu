//! pipe_flow — what a process's descriptors can carry when it becomes a
//! holder (confidentiality-plan-13 D5, §4.5 "source after sink").
//!
//! The filesystem exit labels a file at the write-intent OPEN by a process
//! that already holds a secret (`guard_kernel::label_tainted_write`). A file
//! opened for writing BEFORE the taint was never labeled: in
//! `python3 reader.py > out.txt` the shell opens `out.txt` in the forked child
//! before `exec`, and python reads the secret after, so `out.txt` received
//! the bytes and stayed unlabeled (plan 13 D5). The same held for any
//! descriptor opened before the first raw read (a log file the program opened
//! at start).
//!
//! The fix is the later of the two events (plan 13 §4.5): at the taint (the
//! raw open the arbiter answered `raw`), the guard's taint-time sweep
//! (`guard_send::sweep_before_taint`, which already judges the sockets the
//! reader and its descendants hold) also lists the REGULAR files each of them
//! holds open for writing, and each takes a derived label at the taint's level
//! before the reader gets a byte. A file opened after the taint is labeled at
//! its open, as before.
//!
//! Plan 13 D2 (2026-10-02): the same sweep follows the bytes along a
//! descriptor to a process that is not a descendant. In
//! `reader | curl --data-binary @- …` and `reader | tee copy.txt` the second
//! stage is the reader's SIBLING, so the parent walk never made it a holder:
//! it connected anywhere and wrote unlabeled files. A taint now travels from
//! a process holding the WRITE end of a pipe, a FIFO or an unnamed socket
//! pair to every process holding the READ end (found by the descriptor's
//! `/proc` link: `pipe:[ino]`, the FIFO's path, the peer's `socket:[ino]`),
//! at two events (§4.5): at the taint (the sweep, which then sweeps the
//! reader too: its sockets, files and further pipes), and at the reader's own
//! connect, send or write-open (a pipe or FIFO joined after the taint:
//! `guard_kernel::holder`). The agent itself is never made a holder this
//! way: it reads every tool call's output, and its channel to the model is
//! the model exit's (`pick_agent`). Nor, at the sweep, is a fork of the
//! agent that receives only through close-on-exec descriptors and drops them
//! by its exec (`receives_only_until_exec`, `guard_flow::flow_readers`).
//!
//! This module reads `/proc/<pid>/fd` and `/proc/<pid>/fdinfo` of processes
//! in the guard's own tree (no privilege) and decides with pure functions:
//! which descriptor names a file a label can attach to, and whether its
//! access mode writes.
//!
//! Not labelled here (stated in plan 13 §3 D5): an unlinked file or an
//! `O_TMPFILE` (no path to label), a memfd. Since 2026-10-02 the taint
//! follows such an object (and every file object, shared memory included)
//! to the processes that read it instead (`object_flow`, plan 13 §9 R1's
//! file shapes). Not covered: a thread with a descriptor table of its own
//! (the sweep reads the thread group leader's table; the socket half refuses
//! such a table, this half does not see it).
//!
//! `Mandu-new`.

use std::os::unix::io::RawFd;

/// The access mode (`O_RDONLY`, `O_WRONLY`, `O_RDWR`) of a descriptor, from
/// the `flags:` line of `/proc/<pid>/fdinfo/<fd>` (octal).
pub fn fdinfo_accmode(fdinfo: &str) -> Option<i32> {
    let line = fdinfo.lines().find_map(|l| l.strip_prefix("flags:"))?;
    let flags = i64::from_str_radix(line.trim(), 8).ok()?;
    Some((flags as i32) & libc::O_ACCMODE)
}

/// Does a descriptor with this access mode write?
pub fn accmode_writes(acc: i32) -> bool {
    acc == libc::O_WRONLY || acc == libc::O_RDWR
}

/// The path a descriptor's `/proc/<pid>/fd/<n>` link names when a label can
/// attach to it: an absolute path, not unlinked (`" (deleted)"`), and not on
/// a pseudo filesystem that holds no copy (`/proc`, `/sys`). `/dev/shm` and
/// every other real filesystem are kept. `socket:[…]`, `pipe:[…]` and
/// `anon_inode:…` are no path.
pub fn labelable_target(link: &str) -> Option<&str> {
    if !link.starts_with('/') || link.ends_with(" (deleted)") {
        return None;
    }
    for pseudo in ["/proc", "/sys"] {
        if link == pseudo || link.starts_with(&format!("{pseudo}/")) {
            return None;
        }
    }
    Some(link)
}

/// One descriptor of a process, as the sweep needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldFd {
    pub fd: RawFd,
    /// The `/proc/<pid>/fd/<fd>` link text.
    pub link: String,
}

/// The descriptors of `pid`'s thread group leader table (`/proc/<pid>/fd`),
/// with their link text, once any exec `pid` is inside has ended
/// (`fd_table_read`, 2026-10-17: a table read inside an exec was "holds
/// nothing" to every caller, which for each of them is the lenient side:
/// fewer holders, receivers, writers, channels, files to label). Empty when
/// the process is gone or unreadable with no exec in progress (another
/// user's, non-dumpable on purpose: as before), and when an exec does not
/// end within `EXEC_SETTLE_WAIT` (the yes/no questions below answer "holds"
/// then; a list cannot, and the taint-time sweep refuses such a process).
pub fn fd_table(pid: i32) -> Vec<HeldFd> {
    match fd_table_read(pid) {
        TableRead::Read(t) => t,
        TableRead::Unseen | TableRead::Unsettled => fd_table_partial(pid),
    }
}

/// What `fd_table_read` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableRead {
    /// The table, read whole (after any exec it was inside ended).
    Read(Vec<HeldFd>),
    /// It cannot be read and no exec is in progress: gone, another user's,
    /// non-dumpable on purpose (the documented gap, plan 13 §4.5.1), or a
    /// set-id image its exec ended in. Judged as before (what a partial
    /// reading shows).
    Unseen,
    /// Still inside an exec at `EXEC_SETTLE_WAIT`: only a process faking one
    /// (an emptied argv, `PR_SET_MM_MAP`, and non-dumpable) stays there; the
    /// strict side, per caller.
    Unsettled,
}

/// How long `fd_table_read` waits for an exec to end.
pub const EXEC_SETTLE_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Is the process whose `/proc/<pid>/cmdline` is `cmdline` and whose stat
/// is `st` inside an exec: `exec_in_progress`, and not a kernel thread (no
/// argv, and a table no user reads, for good: `PF_KTHREAD`)? Pure.
pub fn inside_exec(cmdline: &[u8], st: &crate::lineage::ProcStat) -> bool {
    const PF_KTHREAD: u64 = 0x0020_0000;
    exec_in_progress(cmdline, st.state) && st.flags & PF_KTHREAD == 0
}

/// `pid`'s start time while it is inside an exec (`inside_exec`), else None.
/// The argv first: a process with one is never inside, one read.
pub fn inside_exec_start(pid: i32) -> Option<u64> {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if !cmdline.is_empty() {
        return None;
    }
    let st = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok().as_deref().and_then(crate::lineage::parse_stat)?;
    inside_exec(&cmdline, &st).then_some(st.start)
}

/// One look of `fd_table_read`'s wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleStep {
    /// The table was read, of the process found inside the exec: use it.
    Read,
    /// The exec ended before the table could be read: read it once more.
    Final,
    /// Another process has the pid (another start time), or none: the one
    /// looked for holds nothing any more.
    Gone,
    /// The bound passed with it still inside.
    Unsettled,
    /// Look again after `exec_wait_pause`.
    Again,
}

/// `fd_table_read`'s decision on one look at a process found inside an
/// exec: `readable` the table was read on this look, `same` the pid still
/// has the start time it had when found (read after the table), `inside`
/// it is still inside an exec, `past_deadline` the bound passed. Never a
/// table read of another process, never "holds nothing" for a table that
/// was not read. Pure.
pub fn settle_step(readable: bool, same: bool, inside: bool, past_deadline: bool) -> SettleStep {
    if !same {
        SettleStep::Gone
    } else if readable {
        SettleStep::Read
    } else if !inside {
        SettleStep::Final
    } else if past_deadline {
        SettleStep::Unsettled
    } else {
        SettleStep::Again
    }
}

/// `pid`'s table (`fd_table_look`), waiting, when it cannot be read while
/// `pid` is inside an exec, for that exec to end (`settle_step`, looks
/// backing off as `exec_wait_pause`, bound `EXEC_SETTLE_WAIT`). The kernel
/// hides the table from the switch to the new image until the exec has
/// closed the close-on-exec descriptors and marked the process dumpable
/// again; the table it ends with holds the descriptors that survive the
/// exec, which a look inside missed (2026-10-17).
pub fn fd_table_read(pid: i32) -> TableRead {
    if let Some(t) = fd_table_look(pid) {
        return TableRead::Read(t);
    }
    let Some(start) = inside_exec_start(pid) else { return TableRead::Unseen };
    let deadline = std::time::Instant::now() + EXEC_SETTLE_WAIT;
    let start_now = |p: i32| std::fs::read_to_string(format!("/proc/{p}/stat")).ok().as_deref().and_then(crate::lineage::parse_stat).map(|s| s.start);
    let mut n: u32 = 0;
    loop {
        std::thread::sleep(exec_wait_pause(n));
        n = n.saturating_add(1);
        let t = fd_table_look(pid);
        let same = start_now(pid) == Some(start);
        let inside = t.is_none() && inside_exec_start(pid) == Some(start);
        match settle_step(t.is_some(), same, inside, std::time::Instant::now() >= deadline) {
            SettleStep::Read => return TableRead::Read(t.unwrap_or_default()),
            SettleStep::Final => {
                return match (fd_table_look(pid), start_now(pid) == Some(start)) {
                    (Some(t), true) => TableRead::Read(t),
                    (_, false) => TableRead::Read(Vec::new()),
                    (None, true) => TableRead::Unseen,
                }
            }
            SettleStep::Gone => return TableRead::Read(Vec::new()),
            SettleStep::Unsettled => return TableRead::Unsettled,
            SettleStep::Again => {}
        }
    }
}

/// The table as far as it can be read (the descriptors whose links could
/// be): what `fd_table` read before 2026-10-17, kept for a table that
/// cannot be read with no exec in progress.
fn fd_table_partial(pid: i32) -> Vec<HeldFd> {
    let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { return Vec::new() };
    rd.flatten()
        .filter_map(|e| {
            let fd = e.file_name().to_str()?.parse::<RawFd>().ok()?;
            let link = std::fs::read_link(e.path()).ok()?.to_str()?.to_string();
            Some(HeldFd { fd, link })
        })
        .collect()
}

/// `fd_table`, telling a table that could not be read (None) from an empty
/// one: the process is gone, another user's, non-dumpable, or INSIDE an
/// exec. 2026-10-17: from the switch to the new image until the kernel marks
/// the process dumpable again (after it closed the close-on-exec
/// descriptors), `/proc/<pid>/fd` belongs to root, mode 0500, and a reader
/// of the process's own user gets EACCES: `fd_table` reads that as "holds
/// nothing" (measured on Linux 7.0: about 1 look in 10 at a child that a
/// 256 MiB process forks and that execs at once). A guard that is root in
/// the tree's user namespace (the kernel tests) reads the table there and
/// sees the new image holding every descriptor of the old. A link denied
/// for want of permission (the exec began between the listing and the
/// link) makes the whole table unreadable; one that went meanwhile (closed)
/// is skipped.
pub fn fd_table_look(pid: i32) -> Option<Vec<HeldFd>> {
    let rd = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
    let mut out = Vec::new();
    for e in rd {
        let e = e.ok()?;
        let Some(fd) = e.file_name().to_str().and_then(|s| s.parse::<RawFd>().ok()) else { continue };
        match std::fs::read_link(e.path()) {
            Ok(l) => {
                if let Some(link) = l.to_str() {
                    out.push(HeldFd { fd, link: link.to_string() });
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(_) => {}
        }
    }
    Some(out)
}

/// The processes (`/proc/<tgid>`, the caller's pid namespace) holding a
/// descriptor that reads the FIFO `(dev, ino)`, by the file's identity (the
/// magic link followed), so a reader in another mount namespace, which
/// names the FIFO by another path, is found too; `skip` names the ones not
/// to look at. A process whose descriptor table the caller cannot read
/// (another user's) is not listed; a descriptor whose access mode cannot be
/// read counts as one that reads. P0 1a (2026-10-07).
pub fn fifo_readers(dev: u64, ino: u64, skip: &dyn Fn(i32) -> bool) -> Vec<i32> {
    outside_receivers(&[], &[(dev, ino)], skip).into_iter().map(|(p, _)| p).collect()
}

/// P0 2b (2026-10-09): one channel a holder writes into, for the
/// outside-reader rule: `own`, the link of the holder's own end (a pipe's
/// `pipe:[ino]`, a socket pair end's `socket:[ino]`); `target`, the link a
/// process that RECEIVES what the holder writes holds (the same pipe link;
/// the pair's other end, `socket:[peer]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenChannel {
    pub own: String,
    pub target: String,
}

/// P0 2b: the links the outside-reader rule looks for, from the channels a
/// holder writes into: each target once, without the channels whose own
/// end is the session's human plane (`human`: the links of the guard's own
/// standard input, output and error, which the launch handed the agent's
/// tree: its stdio toward the human, by design). Pure.
pub fn outside_rule_targets(channels: &[WrittenChannel], human: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in channels {
        if human.contains(&c.own) || out.contains(&c.target) {
            continue;
        }
        out.push(c.target.clone());
    }
    out
}

/// P0 2b: does a descriptor (`link`, its access mode when it could be read)
/// receive what is written into one of `targets`? A pipe link open for
/// reading (a mode that cannot be read counts as reading: the strict side),
/// and a socket link whatever its mode (a socket pair end reads and
/// writes). A path never matches here (a FIFO is matched by its identity,
/// `outside_receivers`). Pure.
pub fn fd_receives(link: &str, acc: Option<i32>, targets: &[String]) -> bool {
    if !targets.iter().any(|t| t == link) {
        return false;
    }
    match flow_kind(link) {
        FlowKind::Pipe => acc.map(accmode_reads).unwrap_or(true),
        FlowKind::Socket(_) => true,
        FlowKind::Path | FlowKind::None => false,
    }
}

/// Could a descriptor whose link reads `link` be a FIFO? An anonymous pipe,
/// a socket and an anonymous inode never are (a link that could not be read,
/// empty, may be). Pure.
pub fn may_be_fifo(link: &str) -> bool {
    !(link.starts_with("pipe:[") || link.starts_with("socket:[") || link.starts_with("anon_inode:"))
}

/// P0 2b (2026-10-09), and P0 1a's FIFO look (`fifo_readers`): the
/// processes (`/proc/<tgid>`, the caller's pid namespace) other than `skip`
/// holding a descriptor that receives what is written into `targets` (a
/// pipe link open for reading, a socket link: `fd_receives`) or that reads
/// one of `fifos` (by the FIFO's device and inode, the magic link followed,
/// so a reader in another mount namespace, which names it by another path,
/// is found too), each with the link it was found by. A process whose
/// descriptor table the caller cannot read is not listed: another user's,
/// and a non-dumpable one of the same user's (`ssh-agent`, `gpg-agent`:
/// its `/proc/<pid>/fd` belongs to root), as the FIFO rule treats it since
/// 2026-10-07 (disclosed; counting it would refuse every holder's write
/// while one runs, a decision left to the maintainer). One whose table only
/// the exec it is inside hides is looked at once that exec ends
/// (`fd_table_read`, 2026-10-17), and listed when it does not end.
pub fn outside_receivers(targets: &[String], fifos: &[(u64, u64)], skip: &dyn Fn(i32) -> bool) -> Vec<(i32, String)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    if targets.is_empty() && fifos.is_empty() {
        return Vec::new();
    }
    let Ok(rd) = std::fs::read_dir("/proc") else { return Vec::new() };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
        if skip(pid) {
            continue;
        }
        // 2026-10-17: a table the kernel hides inside an exec is read once
        // that exec has ended (`fd_table_read`); one still hidden at the
        // bound is a receiver (the strict side: the event is refused); one
        // that cannot be read with no exec in progress is not seen, as
        // before. A readable table is scanned link by link as it is read.
        let entries: Vec<(RawFd, std::path::PathBuf, String)> = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(fds) => fds
                .flatten()
                .filter_map(|f| {
                    let fd = f.file_name().to_str().and_then(|s| s.parse::<RawFd>().ok())?;
                    let link = std::fs::read_link(f.path()).ok().and_then(|l| l.to_str().map(String::from)).unwrap_or_default();
                    Some((fd, f.path(), link))
                })
                .collect(),
            Err(_) => match fd_table_read(pid) {
                TableRead::Read(t) => t.into_iter().map(|h| (h.fd, std::path::PathBuf::from(format!("/proc/{pid}/fd/{}", h.fd)), h.link)).collect(),
                TableRead::Unsettled => {
                    out.push((pid, "a descriptor table hidden by an exec that does not end".to_string()));
                    continue;
                }
                TableRead::Unseen => continue,
            },
        };
        let found = entries.into_iter().find_map(|(fd, path, link)| {
            // The access mode is read only for a link looked for (one
            // `fdinfo` read per descriptor would double the scan).
            if targets.contains(&link) && fd_receives(&link, accmode_of(pid, fd), targets) {
                return Some(link);
            }
            if !fifos.is_empty() && may_be_fifo(&link) {
                let m = std::fs::metadata(&path).ok()?;
                if m.file_type().is_fifo() && fifos.contains(&(m.dev(), m.ino())) && accmode_of(pid, fd).map(accmode_reads).unwrap_or(true) {
                    return Some(link);
                }
            }
            None
        });
        if let Some(link) = found {
            out.push((pid, link));
        }
    }
    out
}

/// The access mode of `pid`'s descriptor `fd`; None when it is gone.
pub fn accmode_of(pid: i32, fd: RawFd) -> Option<i32> {
    std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")).ok().as_deref().and_then(fdinfo_accmode)
}

/// How many times `fd_file` reads a descriptor before it takes the last
/// reading as it is.
pub const FD_READ_TRIES: usize = 3;

/// One descriptor's file, read as one: its link text, the open file's
/// identity and type (the magic link followed), and its access mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdFile {
    pub link: String,
    pub id: (u64, u64),
    pub is_file: bool,
    pub acc: i32,
}

/// Were two readings of a descriptor, its link and its file's identity
/// before and after the identity and the access mode were read, of ONE open
/// file (2026-10-17)? The link alone, read before the rest, named the file
/// a descriptor HAD when the number was closed and reused in between: the
/// sweep then labelled a file the process no longer wrote (an over-label)
/// and missed the one it did. Pure.
pub fn same_reading(link_before: &str, id_before: (u64, u64), link_after: &str, id_after: (u64, u64)) -> bool {
    link_before == link_after && id_before == id_after
}

/// `pid`'s descriptor `fd`, whose link read `link` a moment ago, read so its
/// link, identity, type and access mode belong to one open file: re-read
/// until two readings agree (`same_reading`), at most `FD_READ_TRIES`
/// times; then the last reading as it is (never fewer files listed than the
/// link alone gave: a process renaming its output in a loop must not keep it
/// unlabelled). None: the descriptor is gone.
pub fn fd_file(pid: i32, fd: RawFd, link: &str) -> Option<FdFile> {
    use std::os::unix::fs::MetadataExt;
    let at = format!("/proc/{pid}/fd/{fd}");
    let mut link = link.to_string();
    let mut last = None;
    for _ in 0..FD_READ_TRIES {
        let md = std::fs::metadata(&at).ok()?;
        let acc = accmode_of(pid, fd)?;
        let after = std::fs::read_link(&at).ok()?.to_str()?.to_string();
        let md2 = std::fs::metadata(&at).ok()?;
        let reading = FdFile { link: after.clone(), id: (md2.dev(), md2.ino()), is_file: md2.is_file(), acc };
        if same_reading(&link, (md.dev(), md.ino()), &after, reading.id) {
            return Some(reading);
        }
        link = after;
        last = Some(reading);
    }
    last
}

/// A regular file a process holds open for writing (plan 13 D5): the path
/// its descriptor names and the file's identity, read as one (`fd_file`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenFile {
    pub path: String,
    pub id: (u64, u64),
}

/// The regular files `pid` holds open for writing (plan 13 D5), each path
/// once. A descriptor closed while the guard looks is simply not listed.
pub fn written_files(pid: i32) -> Vec<WrittenFile> {
    let mut out: Vec<WrittenFile> = Vec::new();
    for h in fd_table(pid) {
        if labelable_target(&h.link).is_none() {
            continue;
        }
        let Some(f) = fd_file(pid, h.fd, &h.link) else { continue };
        let Some(path) = labelable_target(&f.link) else { continue };
        if !f.is_file || !accmode_writes(f.acc) || out.iter().any(|w| w.path == path) {
            continue;
        }
        out.push(WrittenFile { path: path.to_string(), id: f.id });
    }
    out
}

/// What a descriptor's link says it is, for the flow of plan 13 D2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowKind {
    /// An anonymous pipe: its link (`pipe:[ino]`) names both ends.
    Pipe,
    /// A socket: `socket:[ino]` names this end only (the peer is found with
    /// `sock_diag`).
    Socket(u64),
    /// An absolute path: a FIFO when the file's type says so.
    Path,
    /// Anything else (`anon_inode:…`, an unlinked file): no flow.
    None,
}

pub fn flow_kind(link: &str) -> FlowKind {
    if link.starts_with("pipe:[") {
        return FlowKind::Pipe;
    }
    if let Some(ino) = link.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')).and_then(|n| n.parse::<u64>().ok()) {
        return FlowKind::Socket(ino);
    }
    if link.starts_with('/') && !link.ends_with(" (deleted)") {
        return FlowKind::Path;
    }
    FlowKind::None
}

/// Does a descriptor with this access mode read?
pub fn accmode_reads(acc: i32) -> bool {
    acc == libc::O_RDONLY || acc == libc::O_RDWR
}

/// Is `pid`'s descriptor `fd` (link `link`) a FIFO, by the file's own type?
pub fn is_fifo(pid: i32, fd: RawFd) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(format!("/proc/{pid}/fd/{fd}")).map(|m| m.file_type().is_fifo()).unwrap_or(false)
}

/// The pipe and FIFO links `pid` can WRITE to (`pipe:[ino]`, a FIFO's
/// path), each once; and its socket inodes (the caller asks `sock_diag`
/// for their unnamed peers).
pub fn write_ends(pid: i32) -> (Vec<String>, Vec<u64>) {
    let mut links: Vec<String> = Vec::new();
    let mut socks: Vec<u64> = Vec::new();
    for h in fd_table(pid) {
        match flow_kind(&h.link) {
            FlowKind::Socket(ino) => {
                if !socks.contains(&ino) {
                    socks.push(ino);
                }
            }
            k @ (FlowKind::Pipe | FlowKind::Path) => {
                if links.contains(&h.link) || !accmode_of(pid, h.fd).map(accmode_writes).unwrap_or(false) {
                    continue;
                }
                if k == FlowKind::Path && !is_fifo(pid, h.fd) {
                    continue;
                }
                links.push(h.link);
            }
            FlowKind::None => {}
        }
    }
    (links, socks)
}

/// Does `pid` hold one of `targets` in a way that RECEIVES what the other
/// end writes: a pipe or FIFO link open for reading, or a socket link (a
/// socket pair's peer end, which reads and writes)?
pub fn reads_any(pid: i32, targets: &[String]) -> bool {
    !targets.is_empty() && settled_any(pid, |h| receives_through(pid, h, targets))
}

/// Does one of `pid`'s descriptors satisfy `hit`, judged on its table once
/// any exec it is inside has ended (`fd_table_read`)? A process still inside
/// at the bound answers yes (the strict side for every "does it hold"
/// question here); one whose table cannot be read with no exec in progress
/// is judged as before, on what can be read.
fn settled_any(pid: i32, hit: impl Fn(&HeldFd) -> bool) -> bool {
    match fd_table_read(pid) {
        TableRead::Read(t) => t.iter().any(&hit),
        TableRead::Unsettled => true,
        TableRead::Unseen => fd_table_partial(pid).iter().any(&hit),
    }
}

/// The descriptors through which `pid` receives from `targets`, on ONE look
/// at its table, no wait (`receives_only_until_exec`: the fork-window waits
/// look again themselves). An unreadable table lists none.
fn receiving_fds(pid: i32, targets: &[String]) -> Vec<HeldFd> {
    if targets.is_empty() {
        return Vec::new();
    }
    fd_table_look(pid).unwrap_or_default().into_iter().filter(|h| receives_through(pid, h, targets)).collect()
}

/// Does `pid` receive from `targets` through its descriptor `h` (see
/// `reads_any`)?
fn receives_through(pid: i32, h: &HeldFd, targets: &[String]) -> bool {
    targets.iter().any(|t| *t == h.link)
        && match flow_kind(&h.link) {
            FlowKind::Socket(_) => true,
            FlowKind::Pipe | FlowKind::Path => accmode_of(pid, h.fd).map(accmode_reads).unwrap_or(true),
            FlowKind::None => false,
        }
}

/// `reads_any` on a table that could be read (`fd_table_look`); None: it
/// could not, which says nothing of what the process holds.
pub fn reads_any_look(pid: i32, targets: &[String]) -> Option<bool> {
    if targets.is_empty() {
        return Some(false);
    }
    Some(fd_table_look(pid)?.iter().any(|h| receives_through(pid, h, targets)))
}

/// `holds_any` on a table that could be read (`fd_table_look`); None: it
/// could not, which says nothing of what the process holds.
pub fn holds_any_look(pid: i32, links: &[String]) -> Option<bool> {
    if links.is_empty() {
        return Some(false);
    }
    Some(fd_table_look(pid)?.iter().any(|h| links.iter().any(|l| *l == h.link)))
}

/// Is the close-on-exec bit set, from the `flags:` line of
/// `/proc/<pid>/fdinfo/<fd>` (octal; the kernel adds `O_CLOEXEC` there for a
/// descriptor marked close-on-exec)? None without a readable line.
pub fn fdinfo_cloexec(fdinfo: &str) -> Option<bool> {
    let line = fdinfo.lines().find_map(|l| l.strip_prefix("flags:"))?;
    let flags = i64::from_str_radix(line.trim(), 8).ok()?;
    Some(flags & libc::O_CLOEXEC as i64 != 0)
}

/// May a child of the agent, on the agent's image, still be the fork of a
/// spawn that has not exec'd (FORK_EXEC_WAIT applies)? Only while its
/// command line (`/proc/<pid>/cmdline`, `child`) is still its parent's
/// (`parent`): a fork keeps the parent's argv until its exec replaces it.
/// Different (it exec'd, even the agent's own binary under another argv),
/// or unreadable (empty: gone, a zombie): no, and it is judged at once,
/// never more leniently. A process that rewrites its own argv can only make
/// itself judged sooner. Pure.
pub fn not_yet_execd(child: &[u8], parent: &[u8]) -> bool {
    !child.is_empty() && child == parent
}

/// Is a process with this command line (`/proc/<pid>/cmdline`) and state
/// (`/proc/<pid>/stat`) in the middle of an exec: past the switch to the
/// new image, whose memory holds no argv yet, and before the kernel closed
/// its close-on-exec descriptors? An empty command line of a live process
/// (not a zombie, not dead) says so. A process can fake it (an unprivileged
/// `prctl(PR_SET_MM, PR_SET_MM_MAP)` with `arg_end == arg_start` empties its
/// own command line, measured 2026-10-17 on Linux 7.0), and being taken for
/// one only makes the guard wait for its descriptors to go, until the same
/// deadline, never trust that they went. Pure.
pub fn exec_in_progress(cmdline: &[u8], state: char) -> bool {
    cmdline.is_empty() && !matches!(state, 'Z' | 'X' | 'x')
}

/// One look of the wait for an exec in progress to end
/// (`guard_flow::wait_exec_done`, `exec_wait_step`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecWaitStep {
    /// It holds none of the links any more (or is gone): no holder.
    Dropped,
    /// The exec ended, or another process has the pid now: the descriptor
    /// table is final, judged by one more look (a link still held keeps it
    /// a holder).
    Settled,
    /// The deadline passed with it still inside: a holder (fail-closed).
    Refuse,
    /// Still the same process, still inside its exec: look again after
    /// `exec_wait_pause`.
    Again,
}

/// The wait's decision on one look at a process found inside its exec:
/// `first_key` its proc key (`<tgid>-<start>`) when it was found, `key` the
/// key now (another start time: the pid was reused), `held` whether it holds
/// one of the links (`holds_any_look`, `reads_any_look`; None: its table
/// could not be read, as inside an exec), `inside` whether it is still
/// inside an exec (`exec_in_progress`), `past_deadline` whether the wait's
/// bound passed. It never admits a process still inside its exec: the wait
/// ends with no holder only on a look that read the table and found the
/// links gone, and an unreadable table is never taken for an empty one.
/// Pure.
pub fn exec_wait_step(first_key: &str, key: &str, held: Option<bool>, inside: bool, past_deadline: bool) -> ExecWaitStep {
    if held == Some(false) {
        ExecWaitStep::Dropped
    } else if key != first_key || !inside {
        ExecWaitStep::Settled
    } else if past_deadline {
        ExecWaitStep::Refuse
    } else {
        ExecWaitStep::Again
    }
}

/// The pause before the wait's look number `look` (0 = the first look
/// again): 100 us, doubling to 2 ms. An exec past its image switch ends
/// within microseconds unless its task is preempted (the old image's
/// teardown, `exec_mmap`'s `mmput`, runs in that window and grows with the
/// image's memory), so the first looks come quickly, and a long one costs
/// at most one look per 2 ms until the shared `FORK_EXEC_WAIT` bound.
pub fn exec_wait_pause(look: u32) -> std::time::Duration {
    std::time::Duration::from_micros((100u64 << look.min(5)).min(2000))
}

/// Does `pid` receive from `targets`, and only through descriptors marked
/// close-on-exec (each goes at its next exec)? A descriptor whose flags
/// cannot be read counts as one that stays.
pub fn receives_only_until_exec(pid: i32, targets: &[String]) -> bool {
    let fds = receiving_fds(pid, targets);
    !fds.is_empty()
        && fds.iter().all(|h| {
            std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{}", h.fd)).ok().as_deref().and_then(fdinfo_cloexec).unwrap_or(false)
        })
}

/// The pipe and FIFO links `pid` holds open for READING (the later-event
/// check: does a holder write into one of them?).
pub fn read_ends(pid: i32) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for h in fd_table(pid) {
        let k = flow_kind(&h.link);
        if !matches!(k, FlowKind::Pipe | FlowKind::Path) || out.contains(&h.link) {
            continue;
        }
        if !accmode_of(pid, h.fd).map(accmode_reads).unwrap_or(false) {
            continue;
        }
        if k == FlowKind::Path && !is_fifo(pid, h.fd) {
            continue;
        }
        out.push(h.link);
    }
    out
}

/// Does `pid` hold one of `links` open for WRITING?
pub fn writes_any(pid: i32, links: &[String]) -> bool {
    if links.is_empty() {
        return false;
    }
    settled_any(pid, |h| links.iter().any(|l| *l == h.link) && accmode_of(pid, h.fd).map(accmode_writes).unwrap_or(false))
}

/// What a descriptor passed over `SCM_RIGHTS` is, for the flow it opens
/// (plan 13 §9 R1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassKind {
    /// A Unix socket with a peer. `own_named`: the passed end is bound to a
    /// name (a server's accepted end); `peer_named`: its peer is.
    Socket { own_named: bool, peer_named: bool },
    /// A pipe or FIFO end, with the access the receiver gets.
    Pipe { reads: bool, writes: bool },
}

/// Which ways a passed descriptor joins its receivers to the processes at
/// its other end: `(into, out)`. `into`: the receivers take what the other
/// side writes (a pipe's read end; a socket whose own end is not a named
/// server's); `out`: the other side takes what the receivers write (a
/// pipe's write end; a socket whose peer is not a named server, since a
/// holder's connection to a named server is an exit its connect judged
/// against the bindings, never a flow into the server: the rule of the
/// taint-time sweep, `guard_flow::unnamed_unix_peer`).
pub fn pass_directions(kind: PassKind) -> (bool, bool) {
    match kind {
        PassKind::Socket { own_named, peer_named } => (!own_named, !peer_named),
        PassKind::Pipe { reads, writes } => (reads, writes),
    }
}

/// Does `pid` hold one of `links` at all (a socket end, which reads and
/// writes whatever its access mode; plan 13 §9 R1)?
pub fn holds_any(pid: i32, links: &[String]) -> bool {
    if links.is_empty() {
        return false;
    }
    settled_any(pid, |h| links.iter().any(|l| *l == h.link))
}

/// A live process of the guard's tree that runs the agent's executable:
/// as its image, or as the script an interpreter runs (`node …/cli.js`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCandidate {
    pub key: String,
    pub start: u64,
    /// Matched as an interpreter's script, not as the image.
    pub by_script: bool,
}

/// Which processes are the agent: of the candidates, the one that started
/// FIRST. A program the agent later starts from the same executable (an
/// injected `node -e …`, Codex re-running itself as its sandbox helper)
/// starts after it, so a name or an executable alone never earns the
/// exemption. Empty when there is no candidate.
///
/// Only that one process (2026-10-09). Before, an interpreter running the
/// agent's script also made its first-started child the agent, for npm's
/// `codex` script, which runs the real binary as its child. That was wrong
/// both ways: the guard cached the agent set the first time it was asked,
/// which came before the script had started its child, so npm's Codex was
/// never the agent (a listed reader's raw read in one call made it a holder:
/// its model connection refused, its own session file labelled); and for an
/// agent that IS its script (OpenClaw's `openclaw.mjs`, an npm Claude Code
/// `cli.js`) a set first asked later would have exempted whatever it had
/// started first (a tool's shell, an MCP server). The launcher now names the
/// real binary a wrapper runs as the agent's executable (launcher
/// `resolveAgentExe`), so no child is ever taken on trust.
pub fn pick_agent(candidates: &[AgentCandidate]) -> Vec<String> {
    candidates.iter().min_by_key(|c| c.start).map(|a| vec![a.key.clone()]).unwrap_or_default()
}

/// The script an interpreter's command line runs: the first argument after
/// argv[0] that is not an option. None when there is none.
pub fn script_arg(cmdline: &[u8]) -> Option<String> {
    cmdline
        .split(|b| *b == 0)
        .skip(1)
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .find(|a| !a.is_empty() && !a.starts_with('-'))
}

/// What a holder's socket is, for plan 13 §4.5.1 (the agent's own
/// connection to a holder): the facts the guard reads from its copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HolderSocket {
    /// A TCP connection whose other end is a socket of this machine (found
    /// in `/proc/net` by the connection's two ends): its inode, and whether
    /// the holder's end is on a listening port (the holder accepted it: the
    /// agent dialled the holder, not the other way round).
    TcpLocal { other: u64, holder_serves: bool },
    /// A Unix connection: whether the holder's end is bound to a name (it
    /// was accepted on the holder's listener) and its peer's inode.
    Unix { own_named: bool, peer: Option<u64> },
    /// Anything else: a listener, a TCP peer elsewhere, another family.
    Other,
}

/// Plan 13 §4.5.1 (decision 2026-10-02: mask, do not refuse): the agent's
/// link (`socket:[ino]`) when a holder's socket is a CONNECTION whose other
/// end the agent itself holds (`agent_holds`): a TCP connection on this
/// machine, or a Unix connection the holder accepted on its named listener.
/// What the holder writes on it reaches the agent, and through the agent the
/// model, so the guard records it at the arbiter instead of judging it as an
/// exit, and the model exit masks it. A socket pair (both ends unnamed: the
/// tool call's own output, which the call tree's fold answers) is none, and
/// so is a holder's connection to a server the agent runs (TCP or a named
/// Unix one: an exit, judged by the bindings as before; the agent's server
/// may hand what it receives to the model by a road no tool result folds).
pub fn agent_channel(s: &HolderSocket, agent_holds: impl Fn(&str) -> bool) -> Option<String> {
    let link = match s {
        HolderSocket::TcpLocal { other, holder_serves: true } => format!("socket:[{other}]"),
        HolderSocket::Unix { own_named: true, peer: Some(p) } => format!("socket:[{p}]"),
        _ => return None,
    };
    agent_holds(&link).then_some(link)
}

/// Plan 13 §4.5.1, the proxy leg (2026-10-02): the link of the client end
/// of a connection a holder ACCEPTED on this machine when the session's
/// net-proxy holds it (`proxy_holds`). The net-proxy re-originates the
/// tree's proxied requests (an address of this machine that `NO_PROXY` does
/// not name: its LAN address, a hostname resolving to it, `127.0.0.2`) from
/// outside the guard's tree and hands the reply to whichever process asked,
/// over a pool of upstream connections the guard cannot attribute: such a
/// connection is refused at the holder (its accept reset, its raw open
/// refused), never recorded as a flow. A holder's own connection to the
/// proxy (it dialled the proxy port) is not one: the proxy judges that
/// sender itself (D6). Pure.
pub fn relayed_channel(s: &HolderSocket, proxy_holds: impl Fn(&str) -> bool) -> Option<String> {
    let HolderSocket::TcpLocal { other, holder_serves: true } = s else { return None };
    let link = format!("socket:[{other}]");
    proxy_holds(&link).then_some(link)
}

/// The agent flows the guard watches that the agent no longer holds: each is
/// reported closed (plan 13 §4.5.1), and kept watched until the report
/// lands. A dead agent holds nothing.
pub fn closed_agent_links(open: &[String], agent_holds: impl Fn(&str) -> bool) -> Vec<String> {
    open.iter().filter(|l| !agent_holds(l)).cloned().collect()
}

#[cfg(test)]
mod fifo_reader_tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn a_process_reading_a_fifo_is_found_by_the_fifos_identity() {
        let dir = std::env::temp_dir().join(format!("mandu-fifo-readers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f");
        let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let m = std::fs::metadata(&p).unwrap();
        let me = std::process::id() as i32;
        let only_me = |q: i32| q != me;
        assert!(fifo_readers(m.dev(), m.ino(), &only_me).is_empty(), "nobody has it open");
        // A write end alone is no reader (O_RDWR keeps the open from blocking,
        // so the write-only end is opened beside it, then the O_RDWR closed).
        let rw = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        let w = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
        assert!(rw >= 0 && w >= 0);
        assert_eq!(fifo_readers(m.dev(), m.ino(), &only_me), vec![me], "O_RDWR reads");
        unsafe { libc::close(rw) };
        assert!(fifo_readers(m.dev(), m.ino(), &only_me).is_empty(), "a write-only end is no reader");
        let r = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        assert!(r >= 0);
        assert_eq!(fifo_readers(m.dev(), m.ino(), &only_me), vec![me], "a read end is a reader");
        assert!(fifo_readers(m.dev(), m.ino(), &|_| true).is_empty(), "skipped");
        assert!(fifo_readers(m.dev(), m.ino() + 1, &only_me).is_empty(), "another inode");
        unsafe {
            libc::close(r);
            libc::close(w);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// P0 2b (2026-10-09): the outside-reader rule for pipes and socket pairs.
#[cfg(test)]
mod outside_reader_tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn ch(own: &str, target: &str) -> WrittenChannel {
        WrittenChannel { own: own.into(), target: target.into() }
    }

    #[test]
    fn the_human_plane_is_left_out_and_each_target_is_looked_for_once() {
        let human = vec!["pipe:[1]".to_string(), "socket:[10]".to_string()];
        let chans = [ch("pipe:[1]", "pipe:[1]"), ch("pipe:[2]", "pipe:[2]"), ch("socket:[10]", "socket:[11]"), ch("socket:[20]", "socket:[21]"), ch("pipe:[2]", "pipe:[2]")];
        assert_eq!(outside_rule_targets(&chans, &human), vec!["pipe:[2]".to_string(), "socket:[21]".to_string()]);
        // The OTHER end of the human plane's socket pair is no exemption: only
        // the end the launch handed the tree is.
        assert_eq!(outside_rule_targets(&[ch("socket:[11]", "socket:[10]")], &human), vec!["socket:[10]".to_string()]);
        assert!(outside_rule_targets(&[], &human).is_empty());
    }

    #[test]
    fn a_pipe_is_received_through_a_read_end_and_a_socket_through_any_end() {
        let t = vec!["pipe:[5]".to_string(), "socket:[9]".to_string()];
        assert!(fd_receives("pipe:[5]", Some(libc::O_RDONLY), &t));
        assert!(fd_receives("pipe:[5]", Some(libc::O_RDWR), &t));
        assert!(!fd_receives("pipe:[5]", Some(libc::O_WRONLY), &t), "a write end receives nothing");
        assert!(fd_receives("pipe:[5]", None, &t), "a mode that cannot be read counts as reading");
        assert!(fd_receives("socket:[9]", Some(libc::O_RDWR), &t));
        assert!(fd_receives("socket:[9]", None, &t));
        assert!(!fd_receives("pipe:[6]", Some(libc::O_RDONLY), &t), "another pipe");
        assert!(!fd_receives("socket:[8]", None, &t), "another socket");
        assert!(!fd_receives("/tmp/f", Some(libc::O_RDONLY), &["/tmp/f".to_string()]), "a path is matched by identity, never here");
        assert!(may_be_fifo("/tmp/f") && may_be_fifo("") && !may_be_fifo("pipe:[1]") && !may_be_fifo("socket:[1]") && !may_be_fifo("anon_inode:[eventfd]"));
    }

    fn link_of(fd: RawFd) -> String {
        std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap().to_str().unwrap().to_string()
    }

    /// A real process (a fork that waits) holding a pipe's read end, another
    /// pipe's write end and a socket pair's end: found by what receives,
    /// never by a write end, and not when skipped. Unprivileged.
    #[test]
    fn a_process_holding_a_pipes_read_end_or_a_pairs_end_is_found() {
        let mut data = [0 as RawFd; 2];
        let mut wonly = [0 as RawFd; 2];
        let mut ctl = [0 as RawFd; 2];
        let mut pair = [0 as RawFd; 2];
        unsafe {
            assert_eq!(libc::pipe2(data.as_mut_ptr(), libc::O_CLOEXEC), 0);
            assert_eq!(libc::pipe2(wonly.as_mut_ptr(), libc::O_CLOEXEC), 0);
            assert_eq!(libc::pipe2(ctl.as_mut_ptr(), libc::O_CLOEXEC), 0);
            assert_eq!(libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, pair.as_mut_ptr()), 0);
        }
        let (data_link, wonly_link) = (link_of(data[0]), link_of(wonly[1]));
        let (mine, theirs) = (link_of(pair[0]), link_of(pair[1]));
        // SAFETY: the child only closes, reads and exits (async-signal-safe).
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe {
                libc::close(data[1]);
                libc::close(wonly[0]);
                libc::close(pair[0]);
                libc::close(ctl[1]);
                let mut b = [0u8; 1];
                libc::read(ctl[0], b.as_mut_ptr() as *mut libc::c_void, 1);
                libc::_exit(0);
            }
        }
        // Only the child is looked at (the test harness forks and threads).
        let only_child = |q: i32| q != child;
        // The child's closes race this look: wait until its write end of
        // `data` is gone (then its table is the one the test means).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            let t = fd_table(child);
            if !t.is_empty() && t.iter().filter(|h| h.link == data_link).count() == 1 && !t.iter().any(|h| h.link == mine) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(outside_receivers(std::slice::from_ref(&data_link), &[], &only_child), vec![(child, data_link.clone())], "the read end of a pipe");
        assert!(outside_receivers(std::slice::from_ref(&wonly_link), &[], &only_child).is_empty(), "a write end alone receives nothing");
        assert_eq!(outside_receivers(std::slice::from_ref(&theirs), &[], &only_child), vec![(child, theirs.clone())], "the other end of a socket pair");
        assert!(outside_receivers(std::slice::from_ref(&mine), &[], &only_child).is_empty(), "the end it closed");
        assert!(outside_receivers(&[data_link.clone(), theirs.clone()], &[], &|_| true).is_empty(), "skipped");
        assert!(outside_receivers(&[], &[], &only_child).is_empty(), "nothing to look for");
        // A FIFO identity that is no FIFO of the child's: none.
        let m = std::fs::metadata(format!("/proc/self/fd/{}", data[0])).unwrap();
        assert!(outside_receivers(&[], &[(m.dev(), m.ino() + 1)], &only_child).is_empty());
        unsafe {
            libc::write(ctl[1], b"x".as_ptr() as *const libc::c_void, 1);
            let mut st = 0;
            libc::waitpid(child, &mut st, 0);
            for fd in data.iter().chain(wonly.iter()).chain(ctl.iter()).chain(pair.iter()) {
                libc::close(*fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_fork_with_its_parents_argv_may_still_be_on_its_way_to_an_exec() {
        let agent = b"codex\0exec\0--json\0".to_vec();
        assert!(not_yet_execd(&agent, &agent), "a fork keeps its parent's argv");
        // Codex runs each command through itself under another name: exec'd
        assert!(!not_yet_execd(b"codex-linux-sandbox\0--sandbox-policy-cwd\0/w\0", &agent));
        assert!(!not_yet_execd(b"", &agent), "gone or a zombie: judged at once");
        assert!(!not_yet_execd(&agent, b""), "the parent unreadable: judged at once");
    }

    #[test]
    fn a_live_process_with_no_argv_yet_is_inside_its_exec() {
        assert!(exec_in_progress(b"", 'R'), "the new image, no argv yet");
        assert!(exec_in_progress(b"", 'S'));
        assert!(exec_in_progress(b"", 'D'));
        assert!(!exec_in_progress(b"", 'Z'), "a zombie's command line is empty too");
        assert!(!exec_in_progress(b"", 'X'));
        assert!(!exec_in_progress(b"bash\0-c\0true\0", 'R'), "the exec is done");
    }

    #[test]
    fn the_wait_for_an_exec_admits_only_a_look_where_the_links_are_gone() {
        use ExecWaitStep::*;
        let k = "300-9";
        let (held, lacks, unread) = (Some(true), Some(false), None);
        // Inside, holding: look again, until the bound, then refuse.
        assert_eq!(exec_wait_step(k, k, held, true, false), Again);
        assert_eq!(exec_wait_step(k, k, held, true, true), Refuse, "never settles: a holder at the bound");
        // Inside, its table unreadable (root's, mode 0500, until the exec is
        // done): never taken for an empty table.
        assert_eq!(exec_wait_step(k, k, unread, true, false), Again);
        assert_eq!(exec_wait_step(k, k, unread, true, true), Refuse);
        // The links went (the kernel closed the close-on-exec ones): no holder,
        // also on the look past the bound.
        assert_eq!(exec_wait_step(k, k, lacks, true, false), Dropped);
        assert_eq!(exec_wait_step(k, k, lacks, false, true), Dropped);
        // The exec ended still holding one (a descriptor without the flag),
        // or ended before its table could be read: the table is final, one
        // more look judges it, never a wait.
        assert_eq!(exec_wait_step(k, k, held, false, false), Settled);
        assert_eq!(exec_wait_step(k, k, unread, false, false), Settled);
        // Another process on the pid (another start time): never waited for
        // as the one found inside its exec.
        assert_eq!(exec_wait_step(k, "300-12", held, true, false), Settled);
        assert_eq!(exec_wait_step(k, "300", unread, true, false), Settled, "its key unreadable: gone");
    }

    #[test]
    fn a_kernel_thread_is_never_inside_an_exec() {
        let st = |state: char, flags: u64| crate::lineage::ProcStat { state, ppid: 2, flags, start: 9 };
        assert!(inside_exec(b"", &st('R', 0x0040_0100)), "a user task, no argv yet");
        assert!(!inside_exec(b"", &st('I', 0x0420_8040)), "kworker: PF_KTHREAD, no argv for good");
        assert!(!inside_exec(b"", &st('S', 0x0020_0000)));
        assert!(!inside_exec(b"", &st('Z', 0x0040_0100)), "a zombie");
        assert!(!inside_exec(b"sh\0", &st('R', 0x0040_0100)), "the exec is done");
    }

    #[test]
    fn the_settle_wait_reads_only_the_process_it_found_and_never_an_unread_table_as_empty() {
        use SettleStep::*;
        // (readable, same process, still inside, past the bound)
        assert_eq!(settle_step(false, true, true, false), Again);
        assert_eq!(settle_step(false, true, true, true), Unsettled, "a faked exec: the strict side at the bound");
        assert_eq!(settle_step(true, true, false, false), Read, "the exec ended: its table");
        assert_eq!(settle_step(true, true, true, true), Read, "readable is readable, even at the bound");
        assert_eq!(settle_step(false, true, false, false), Final, "ended, not read yet: one more look");
        assert_eq!(settle_step(true, false, false, false), Gone, "another start time on the pid: not its table");
        assert_eq!(settle_step(false, false, true, true), Gone);
    }

    #[test]
    fn a_readable_table_needs_no_wait() {
        let me = std::process::id() as i32;
        let t0 = std::time::Instant::now();
        assert!(matches!(fd_table_read(me), TableRead::Read(t) if !t.is_empty()));
        assert!(t0.elapsed() < EXEC_SETTLE_WAIT / 4);
        // Gone: no exec to wait for, nothing held.
        assert_eq!(fd_table_read(i32::MAX), TableRead::Unseen);
        assert!(!holds_any(i32::MAX, &["pipe:[1]".to_string()]));
    }

    #[test]
    fn an_unreadable_table_is_told_from_an_empty_one() {
        // This process's own table: readable.
        let me = std::process::id() as i32;
        assert!(fd_table_look(me).is_some(), "this process's table is readable");
        let (r, w) = {
            let mut fds = [0 as RawFd; 2];
            assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            (fds[0], fds[1])
        };
        let link = std::fs::read_link(format!("/proc/self/fd/{r}")).unwrap().to_str().unwrap().to_string();
        assert_eq!(holds_any_look(me, std::slice::from_ref(&link)), Some(true));
        assert_eq!(reads_any_look(me, std::slice::from_ref(&link)), Some(true));
        assert_eq!(holds_any_look(me, &["pipe:[1]".to_string()]), Some(false));
        assert_eq!(holds_any_look(me, &[]), Some(false), "nothing to hold: no look needed");
        unsafe {
            libc::close(r);
            libc::close(w);
        }
        // A process that is not there: unreadable, never "holds nothing" by a look.
        assert_eq!(fd_table_look(i32::MAX), None);
        assert_eq!(holds_any_look(i32::MAX, &[link.clone()]), None);
        assert_eq!(reads_any_look(i32::MAX, &[link]), None);
        assert!(fd_table(i32::MAX).is_empty(), "fd_table keeps reading it as empty");
    }

    #[test]
    fn the_wait_for_an_exec_looks_soon_then_backs_off_to_2_ms() {
        let us = |n: u32| exec_wait_pause(n).as_micros();
        assert_eq!((us(0), us(1), us(2), us(3), us(4)), (100, 200, 400, 800, 1600));
        assert_eq!(us(5), 2000);
        assert_eq!(us(40), 2000, "capped, no overflow");
        // Within FORK_EXEC_WAIT (2 s) the wait looks at least 990 times.
        let mut t = 0u128;
        let mut looks = 0;
        while t < 2_000_000 {
            t += us(looks);
            looks += 1;
        }
        assert!(looks >= 990, "{looks}");
    }

    #[test]
    fn the_agents_own_connection_to_a_holder_is_a_channel_a_socket_pair_is_not() {
        // Plan 13 §4.5.1: the agent fetches a holder's listener over TCP.
        let agent = |l: &str| l == "socket:[77]";
        assert_eq!(agent_channel(&HolderSocket::TcpLocal { other: 77, holder_serves: true }, agent), Some("socket:[77]".into()));
        // A TCP client of this machine that is not the agent: no agent flow
        // (the accept and the sweep judge it as before).
        assert_eq!(agent_channel(&HolderSocket::TcpLocal { other: 78, holder_serves: true }, agent), None);
        // The holder dialled a server the AGENT runs: an exit, judged by the
        // bindings as before (the agent's server may hand what it receives to
        // the model by a road no tool result folds).
        assert_eq!(agent_channel(&HolderSocket::TcpLocal { other: 77, holder_serves: false }, agent), None);
        // The agent's Unix connection to the holder's NAMED listener.
        assert_eq!(agent_channel(&HolderSocket::Unix { own_named: true, peer: Some(77) }, agent), Some("socket:[77]".into()));
        // A socket pair with the agent (a tool call's stdout): the call's tree
        // folds it, no agent flow.
        assert_eq!(agent_channel(&HolderSocket::Unix { own_named: false, peer: Some(77) }, agent), None);
        assert_eq!(agent_channel(&HolderSocket::Unix { own_named: true, peer: None }, agent), None);
        assert_eq!(agent_channel(&HolderSocket::Other, |_| true), None);
    }

    #[test]
    fn a_holders_accepted_connection_the_net_proxy_holds_is_a_relayed_channel() {
        // Plan 13 §4.5.1, the proxy leg: the net-proxy dialled the holder.
        let proxy = |l: &str| l == "socket:[90]";
        assert_eq!(relayed_channel(&HolderSocket::TcpLocal { other: 90, holder_serves: true }, proxy), Some("socket:[90]".into()));
        // Another local client (the user's browser): not relayed.
        assert_eq!(relayed_channel(&HolderSocket::TcpLocal { other: 91, holder_serves: true }, proxy), None);
        // The holder dialled the proxy itself: its own proxied request, which
        // the proxy judges (D6), not a relay into the tree.
        assert_eq!(relayed_channel(&HolderSocket::TcpLocal { other: 90, holder_serves: false }, proxy), None);
        assert_eq!(relayed_channel(&HolderSocket::Unix { own_named: true, peer: Some(90) }, |_| true), None);
        assert_eq!(relayed_channel(&HolderSocket::Other, |_| true), None);
    }

    #[test]
    fn an_agent_flow_is_closed_once_the_agent_no_longer_holds_its_channel() {
        let open = vec!["socket:[1]".to_string(), "socket:[2]".to_string()];
        assert_eq!(closed_agent_links(&open, |l| l == "socket:[2]"), vec!["socket:[1]".to_string()]);
        assert_eq!(closed_agent_links(&open, |_| true), Vec::<String>::new());
        // A dead agent holds nothing: every flow closes.
        assert_eq!(closed_agent_links(&open, |_| false), open);
    }

    #[test]
    fn a_passed_end_joins_its_receivers_to_the_other_side_in_the_ways_it_carries() {
        // Plan 13 §9 R1: a socket pair end carries both ways.
        assert_eq!(pass_directions(PassKind::Socket { own_named: false, peer_named: false }), (true, true));
        // A client's end of a connection to a NAMED server: the receiver takes
        // the server's bytes; what it writes to the server is an exit (judged
        // against its bindings at the connect), never a flow into the server.
        assert_eq!(pass_directions(PassKind::Socket { own_named: false, peer_named: true }), (true, false));
        // The server's accepted end: the client's writes to it were an exit.
        assert_eq!(pass_directions(PassKind::Socket { own_named: true, peer_named: false }), (false, true));
        // A pipe: one way, by the access the receiver gets.
        assert_eq!(pass_directions(PassKind::Pipe { reads: true, writes: false }), (true, false));
        assert_eq!(pass_directions(PassKind::Pipe { reads: false, writes: true }), (false, true));
        assert_eq!(pass_directions(PassKind::Pipe { reads: true, writes: true }), (true, true), "a FIFO opened O_RDWR");
    }

    #[test]
    fn the_access_mode_is_read_from_the_octal_flags_line() {
        let wronly_append_cloexec = "pos:\t0\nflags:\t02102001\nmnt_id:\t31\nino:\t4242\n";
        assert_eq!(fdinfo_accmode(wronly_append_cloexec), Some(libc::O_WRONLY));
        assert_eq!(fdinfo_accmode("pos:\t0\nflags:\t0100002\n"), Some(libc::O_RDWR));
        assert_eq!(fdinfo_accmode("pos:\t0\nflags:\t0100000\n"), Some(libc::O_RDONLY));
        assert_eq!(fdinfo_accmode("pos:\t0\n"), None, "no flags line: unknown, never a guess");
        assert_eq!(fdinfo_accmode("flags:\tzz\n"), None);
    }

    #[test]
    fn the_close_on_exec_bit_is_read_from_the_octal_flags_line() {
        assert_eq!(fdinfo_cloexec("pos:\t0\nflags:\t02000002\n"), Some(true), "O_RDWR | O_CLOEXEC (a socket pair's end in a fork)");
        assert_eq!(fdinfo_cloexec("pos:\t0\nflags:\t02102001\n"), Some(true));
        assert_eq!(fdinfo_cloexec("pos:\t0\nflags:\t0100002\n"), Some(false), "an inherited descriptor without the bit stays across exec");
        assert_eq!(fdinfo_cloexec("pos:\t0\n"), None, "no flags line: unknown, never a guess");
    }

    #[test]
    fn this_process_receives_through_a_close_on_exec_end_only_until_exec() {
        // A pipe made close-on-exec (as libuv and posix_spawn make the
        // parent's ends), then the same read end without the bit.
        let mut p = [0; 2];
        assert_eq!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let me = std::process::id() as i32;
        let target = std::fs::read_link(format!("/proc/self/fd/{}", p[0])).unwrap().to_str().unwrap().to_string();
        let targets = vec![target];
        assert!(reads_any(me, &targets));
        assert!(receives_only_until_exec(me, &targets), "a close-on-exec read end goes at the next exec");
        let kept = unsafe { libc::dup(p[0]) };
        assert!(kept >= 0);
        assert!(!receives_only_until_exec(me, &targets), "a second end without the bit stays: the process keeps receiving");
        for fd in [p[0], p[1], kept] {
            unsafe { libc::close(fd) };
        }
        assert!(!receives_only_until_exec(me, &targets), "nothing held: no receiver");
    }

    #[test]
    fn only_a_writing_mode_writes() {
        assert!(accmode_writes(libc::O_WRONLY));
        assert!(accmode_writes(libc::O_RDWR));
        assert!(!accmode_writes(libc::O_RDONLY));
    }

    #[test]
    fn a_label_attaches_to_a_real_path_only() {
        assert_eq!(labelable_target("/home/u/proj/out.txt"), Some("/home/u/proj/out.txt"));
        assert_eq!(labelable_target("/dev/shm/drop"), Some("/dev/shm/drop"), "/dev/shm is a real tmpfs file");
        assert_eq!(labelable_target("/tmp/x (deleted)"), None, "an unlinked file has no path to label");
        assert_eq!(labelable_target("pipe:[1234]"), None);
        assert_eq!(labelable_target("socket:[1234]"), None);
        assert_eq!(labelable_target("anon_inode:[eventfd]"), None);
        assert_eq!(labelable_target("/proc/self/attr/current"), None);
        assert_eq!(labelable_target("/sys/fs/cgroup/x/cgroup.procs"), None);
        assert_eq!(labelable_target("/process.log"), Some("/process.log"), "a prefix of a word is not /proc");
    }

    #[test]
    fn a_descriptors_link_says_what_can_flow_through_it() {
        assert_eq!(flow_kind("pipe:[4026532]"), FlowKind::Pipe);
        assert_eq!(flow_kind("socket:[812]"), FlowKind::Socket(812));
        assert_eq!(flow_kind("socket:[x]"), FlowKind::None);
        assert_eq!(flow_kind("/tmp/fifo"), FlowKind::Path);
        assert_eq!(flow_kind("/tmp/fifo (deleted)"), FlowKind::None);
        assert_eq!(flow_kind("anon_inode:[eventfd]"), FlowKind::None);
        assert!(accmode_reads(libc::O_RDONLY) && accmode_reads(libc::O_RDWR) && !accmode_reads(libc::O_WRONLY));
    }

    #[test]
    fn the_agent_is_the_first_started_process_of_its_executable() {
        assert!(pick_agent(&[]).is_empty());
        let c = |k: &str, start: u64, by_script: bool| AgentCandidate { key: k.into(), start, by_script };
        let cands = vec![c("900-5000", 5000, false), c("120-1000", 1000, false), c("777-9000", 9000, false)];
        assert_eq!(pick_agent(&cands), vec!["120-1000".to_string()], "a later `node` is never the agent");
        // An agent that is its interpreter's script (OpenClaw's openclaw.mjs):
        // that one process, never a child it started (2026-10-09: a tool's
        // shell or an MCP server is no agent).
        let cands = vec![c("50-100", 100, true), c("60-700", 700, false)];
        assert_eq!(pick_agent(&cands), vec!["50-100".to_string()]);
    }

    #[test]
    fn an_interpreters_script_is_its_first_plain_argument() {
        assert_eq!(script_arg(b"node\0--max-old-space-size=4096\0/opt/claude/cli.js\0--resume\0"), Some("/opt/claude/cli.js".into()));
        assert_eq!(script_arg(b"/usr/bin/codex\0"), None);
        assert_eq!(script_arg(b"node\0-e\0"), None);
    }

    #[test]
    fn this_process_sees_the_two_ends_of_its_own_pipe() {
        let mut p = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        let me = std::process::id() as i32;
        let link = std::fs::read_link(format!("/proc/self/fd/{}", p[1])).unwrap().to_string_lossy().to_string();
        let (w, _) = write_ends(me);
        assert!(w.contains(&link), "the write end: {w:?}");
        assert!(read_ends(me).contains(&link), "the read end, same link");
        assert!(reads_any(me, &[link.clone()]) && writes_any(me, &[link.clone()]));
        unsafe { libc::close(p[0]) };
        assert!(!read_ends(me).contains(&link), "the read end closed");
        assert!(!reads_any(me, &[link.clone()]), "only a write end left: nothing received");
        unsafe { libc::close(p[1]) };
        assert!(!writes_any(me, &[link]));
    }

    #[test]
    fn two_readings_are_one_file_only_when_link_and_identity_agree() {
        assert!(same_reading("/w/out.txt", (1, 10), "/w/out.txt", (1, 10)));
        assert!(!same_reading("/w/old.txt", (1, 10), "/w/new.txt", (1, 10)), "the number reused for another path");
        assert!(!same_reading("/w/out.txt", (1, 10), "/w/out.txt", (1, 11)), "the same path, another file (renamed over, reopened)");
    }

    #[test]
    fn a_descriptor_whose_number_was_reused_is_read_as_the_file_it_holds_now() {
        // The sweep read the link of fd N (`fd_table`) while N named one
        // file; N was closed and reused for another before the rest was
        // read. The reading is the file N holds NOW, its path and identity
        // together: never the old path with the new file's facts.
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::AsRawFd;
        let dir = std::env::temp_dir().join(format!("mandu-fd-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let now = dir.join("now.txt");
        let f = std::fs::OpenOptions::new().create(true).append(true).open(&now).unwrap();
        let me = std::process::id() as i32;
        let stale = dir.join("closed-before.txt");
        let got = fd_file(me, f.as_raw_fd(), stale.to_str().unwrap()).expect("the descriptor is open");
        let m = std::fs::metadata(&now).unwrap();
        assert_eq!(std::path::Path::new(&got.link), std::fs::canonicalize(&now).unwrap(), "the link read again, not the stale one");
        assert_eq!(got.id, (m.dev(), m.ino()));
        assert!(got.is_file && accmode_writes(got.acc));
        assert!(fd_file(me, 987_654, "/x").is_none(), "a closed descriptor: none");
        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn this_process_lists_a_file_it_holds_for_writing_and_not_one_it_reads() {
        let dir = std::env::temp_dir().join(format!("mandu-pipe-flow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let w = dir.join("out.txt");
        let r = dir.join("in.txt");
        std::fs::write(&r, "x").unwrap();
        let wf = std::fs::OpenOptions::new().create(true).append(true).open(&w).unwrap();
        let rf = std::fs::File::open(&r).unwrap();
        let me = std::process::id() as i32;
        let got = written_files(me);
        let wc = std::fs::canonicalize(&w).unwrap();
        let rc = std::fs::canonicalize(&r).unwrap();
        use std::os::unix::fs::MetadataExt;
        let wm = std::fs::metadata(&w).unwrap();
        assert!(got.iter().any(|f| std::path::Path::new(&f.path) == wc && f.id == (wm.dev(), wm.ino())), "the file open for writing, with its identity: {got:?}");
        assert!(!got.iter().any(|f| std::path::Path::new(&f.path) == rc), "a file open for reading only: {got:?}");
        drop(wf);
        drop(rf);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
