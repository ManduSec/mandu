//! object_flow — a taint follows a FILE OBJECT two processes share
//! (confidentiality-plan-13 §9 R1, the file shapes; 2026-10-02).
//!
//! Plan 13 D2 made the taint follow a pipe, a FIFO and an unnamed socket pair
//! from its writer to its reader; §9 R1 made it follow a socket joined after
//! the taint. A file object shared by two processes is the same kind of
//! channel and was followed by neither:
//!
//!   - a reader that ALREADY holds a file open when a holder writes it
//!     (`tail -f /tmp/x | curl … &` started before; a holder then appends to
//!     `/tmp/x`): D4 labels the file at the holder's write-open, but the
//!     reader opened it before the label existed and its `read(2)` is no
//!     event, so it never became a holder;
//!   - shared memory: a `/dev/shm` file (POSIX `shm_open`), a `MAP_SHARED`
//!     mapping of any file, an anonymous shared mapping inherited across a
//!     fork, a SysV segment (`shmget`/`shmat`);
//!   - an object with no path to label: an unlinked file, an `O_TMPFILE`, a
//!     memfd, written by a holder and held, passed (`SCM_RIGHTS`) or reopened
//!     (`/proc/<pid>/fd/N`) by another process.
//!
//! The rule is D2's, keyed by the object instead of a descriptor link: a
//! process of the guard's tree that can READ an object (a descriptor whose
//! access mode reads, or any mapping of it) receives what a holder that can
//! WRITE it (a descriptor whose access mode writes, or a writable SHARED
//! mapping) writes. It is applied at the later of the two events (§4.5):
//!
//!   - at the taint (the sweep): the objects the swept processes can write
//!     are listed (`written_objects`), and every reader of one becomes a
//!     holder flowing from them, swept in turn;
//!   - at a holder's write-capable open of a regular file (D4's event): the
//!     readers that hold it already;
//!   - at a holder's `shmat` of a SysV segment (trapped under a secret
//!     policy), and at a pass over `SCM_RIGHTS` of a regular file;
//!   - at a holder's `memfd_create` (trapped under a secret policy, P0 1b):
//!     the guard makes the memfd and marks it before handing it over;
//!   - at a later open, `shmat` or event of an untainted process: an object
//!     a holder wrote is MARKED (`TaintedSet::mark_link` with the object's
//!     key) and the mark is kept after the writer exits, so a reopen of an
//!     unlinked or `O_TMPFILE` object by its new name, a later `shmat` of a
//!     segment a holder left, makes the opener a holder.
//!
//! An object is named by keys (`file_key`: the device and inode the kernel
//! reports; `sysv_key`: the IPC namespace and the segment id) and, for a
//! file that still has one, its path. Two views of one object can carry
//! different devices (an overlay file's descriptor reports the overlay's
//! inode, its mapping the backing file's), so a reader matches a target by a
//! shared key OR the same real path; either only ever over-approximates,
//! which makes a process a holder too many (it restricts), never one too few.
//!
//! The race between a reader's open and a holder's write is closed by
//! `ObjectOpens`: a reading open of a regular file the guard performs is
//! registered (in flight) before its descriptor is handed over, under the
//! same lock that marks a written object, so the writer either sees the
//! reader in flight or the reader sees the mark. The registry keeps every
//! reading open (and every regular file passed) for `RECENT` after it, so
//! a holder's write to a file born less than `FRESH` ago that nothing is
//! listed for needs no look at the tree (`born_recently`).
//!
//! PURE (always compiled, unit-tested): the keys, the `maps` parser, the
//! matching, the registry. The `/proc` readers here need no privilege (the
//! guard's own tree); the enactment is `guard_flow`'s (feature `kernel`).
//!
//! `Mandu-new`.

use std::os::unix::io::RawFd;

/// The key of a file object: the device and inode the kernel reports for it.
pub fn file_key(dev: u64, ino: u64) -> String {
    format!("file:[{dev}:{ino}]")
}

/// The `(dev, ino)` a `file_key` names; None for any other key. Pure.
pub fn file_id_of_key(key: &str) -> Option<(u64, u64)> {
    let (d, i) = key.strip_prefix("file:[")?.strip_suffix(']')?.split_once(':')?;
    Some((d.parse().ok()?, i.parse().ok()?))
}

/// Do an object's keys name the file a path's descriptor stats as `(dev,
/// ino)`? By the whole key, or by the inode alone: a shared mapping of a
/// file on an overlay is listed in `/proc/<pid>/maps` with the backing
/// layer's device (Linux 6.6 and later), while `stat` of the overlay path
/// gives the overlay's (plan 13 §9 R4 (b), 2026-10-04: the sweep narrows a
/// mapped file only when its path still names it). Pure.
pub fn key_names_file(keys: &[String], dev: u64, ino: u64) -> bool {
    let whole = file_key(dev, ino);
    let tail = format!(":{ino}]");
    keys.iter().any(|k| *k == whole || (k.starts_with("file:[") && k.ends_with(&tail)))
}

/// The key of a SysV shared memory segment: its IPC namespace (the inode of
/// `/proc/<pid>/ns/ipc`) and its id (which `/proc/<pid>/maps` shows as the
/// mapping's inode).
pub fn sysv_key(ipc_ns: u64, shmid: u64) -> String {
    format!("sysv:[{ipc_ns}:{shmid}]")
}

/// Is a mark key one of this module's (a file object or a SysV segment)?
pub fn is_object_key(k: &str) -> bool {
    k.starts_with("file:[") || k.starts_with("sysv:[")
}

/// `makedev(major, minor)` as glibc encodes it (the `dev_t` `stat` returns).
pub fn makedev(major: u64, minor: u64) -> u64 {
    ((major & 0xffff_f000) << 32) | ((major & 0xfff) << 8) | ((minor & 0xffff_ff00) << 12) | (minor & 0xff)
}

/// One line of `/proc/<pid>/maps` that maps an object (inode not 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapLine {
    pub dev: u64,
    pub ino: u64,
    pub read: bool,
    pub write: bool,
    pub shared: bool,
    /// The pathname column, as the kernel prints it (`/x`, `/x (deleted)`,
    /// `/memfd:n (deleted)`, `/SYSV0000002a (deleted)`, `/dev/zero (deleted)`).
    pub path: String,
}

/// The mappings of `/proc/<pid>/maps` text that map an object: inode not 0
/// (anonymous memory, the heap and the stack have none).
pub fn parse_maps(text: &str) -> Vec<MapLine> {
    let mut out = Vec::new();
    for line in text.lines() {
        // range perms offset dev inode [path]: the path may hold spaces.
        let mut it = line.splitn(6, ' ');
        let (Some(_range), Some(perms), Some(_off), Some(dev), Some(ino)) = (it.next(), it.next(), it.next(), it.next(), it.next()) else { continue };
        let Ok(ino) = ino.parse::<u64>() else { continue };
        if ino == 0 {
            continue;
        }
        let Some((maj, min)) = dev.split_once(':') else { continue };
        let (Ok(maj), Ok(min)) = (u64::from_str_radix(maj, 16), u64::from_str_radix(min, 16)) else { continue };
        let p = perms.as_bytes();
        if p.len() < 4 {
            continue;
        }
        let path = it.next().unwrap_or("").trim_start().to_string();
        out.push(MapLine { dev: makedev(maj, min), ino, read: p[0] == b'r', write: p[1] == b'w', shared: p[3] == b's', path });
    }
    out
}

/// Is a mapping's path a SysV segment (`/SYSV<key> (deleted)`)?
pub fn is_sysv_mapping(path: &str) -> bool {
    path.starts_with("/SYSV") && path.ends_with(" (deleted)")
}

/// Does a mapping map a DATA object two processes can share: a file, a
/// `/dev/shm` file, a memfd, a SysV segment, anonymous shared memory (the
/// kernel names it `/dev/zero (deleted)`)? A device's mapping (a GPU's
/// buffer, `/dev/mem`) is none: what it carries is no file's bytes, and
/// counting it would make every GUI process sharing a device a holder.
pub fn maps_object(m: &MapLine) -> bool {
    if !m.path.starts_with('/') {
        return false;
    }
    if m.path.starts_with("/dev/") {
        return m.path.starts_with("/dev/shm/") || m.path == "/dev/zero (deleted)";
    }
    true
}

/// A descriptor link or mapping path that is a real path still: absolute,
/// not unlinked, not a memfd, not on `/proc` or `/sys`.
pub fn real_path(link: &str) -> Option<&str> {
    if !link.starts_with('/') || link.ends_with(" (deleted)") || link.starts_with("/memfd:") {
        return None;
    }
    for pseudo in ["/proc", "/sys"] {
        if link == pseudo || link.starts_with(&format!("{pseudo}/")) {
            return None;
        }
    }
    Some(link)
}

/// A descriptor link that can name a shared data object: absolute (a path,
/// an unlinked file, a memfd), not on `/proc` or `/sys` (a pseudo file holds
/// no copy). `pipe:`, `socket:` and `anon_inode:` links are D2's or none.
pub fn object_link(link: &str) -> bool {
    if !link.starts_with('/') {
        return false;
    }
    for pseudo in ["/proc", "/sys"] {
        if link == pseudo || link.starts_with(&format!("{pseudo}/")) {
            return false;
        }
    }
    true
}

/// An object a process can reach: the keys it is known by, its real path
/// (when it has one), and whether the process can read and write it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldObject {
    pub keys: Vec<String>,
    pub path: Option<String>,
    pub reads: bool,
    pub writes: bool,
}

/// An object a holder can write, as the readers are matched against it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjectTarget {
    pub keys: Vec<String>,
    pub path: Option<String>,
}

impl ObjectTarget {
    pub fn of(h: &HeldObject) -> ObjectTarget {
        ObjectTarget { keys: h.keys.clone(), path: h.path.clone() }
    }
}

/// Is `h` the object `t` names: a key in common, or the same real path?
pub fn same_object(h: &HeldObject, t: &ObjectTarget) -> bool {
    h.keys.iter().any(|k| t.keys.contains(k)) || (h.path.is_some() && h.path == t.path)
}

/// The objects a mapping line stands for (`ipc_ns`: the process's IPC
/// namespace, for a SysV segment's key).
pub fn mapping_object(m: &MapLine, ipc_ns: Option<u64>) -> Option<HeldObject> {
    if !maps_object(m) {
        return None;
    }
    let mut keys = vec![file_key(m.dev, m.ino)];
    if is_sysv_mapping(&m.path) {
        if let Some(ns) = ipc_ns {
            keys.push(sysv_key(ns, m.ino));
        }
    }
    Some(HeldObject { keys, path: real_path(&m.path).map(str::to_string), reads: m.read, writes: m.write && m.shared })
}

/// Fold `o` into `out`: one entry per object (a file mapped in pieces, or
/// held by a descriptor and mapped, is one object; its access is the union).
pub fn add_object(out: &mut Vec<HeldObject>, o: HeldObject) {
    if let Some(e) = out.iter_mut().find(|e| e.keys.iter().any(|k| o.keys.contains(k)) || (e.path.is_some() && e.path == o.path)) {
        for k in o.keys {
            if !e.keys.contains(&k) {
                e.keys.push(k);
            }
        }
        if e.path.is_none() {
            e.path = o.path;
        }
        e.reads |= o.reads;
        e.writes |= o.writes;
        return;
    }
    out.push(o);
}

// ── /proc readers (no privilege; the guard's own tree) ──────────────────────

/// The inode of `pid`'s IPC namespace (`ipc:[n]`).
pub fn ipc_ns_of(pid: i32) -> Option<u64> {
    let l = std::fs::read_link(format!("/proc/{pid}/ns/ipc")).ok()?;
    l.to_str()?.strip_prefix("ipc:[")?.strip_suffix(']')?.parse().ok()
}

/// Every data object `pid` can reach through its descriptor table (the
/// thread group leader's) and its mappings: regular files, unlinked files,
/// memfds, `/dev/shm` files, SysV segments, anonymous shared memory. A
/// descriptor closed or a mapping unmapped while the guard looks is simply
/// not listed.
pub fn held_objects(pid: i32) -> Vec<HeldObject> {
    let mut out: Vec<HeldObject> = Vec::new();
    for h in crate::pipe_flow::fd_table(pid) {
        if !object_link(&h.link) {
            continue;
        }
        // The magic link followed: the file's own type and identity, read
        // with its link and access mode as one (`pipe_flow::fd_file`), so a
        // number reused in between never pairs one file's path with
        // another's identity (2026-10-17).
        let Some(f) = crate::pipe_flow::fd_file(pid, h.fd, &h.link) else { continue };
        if !f.is_file || !object_link(&f.link) {
            continue;
        }
        add_object(
            &mut out,
            HeldObject {
                keys: vec![file_key(f.id.0, f.id.1)],
                path: real_path(&f.link).map(str::to_string),
                reads: crate::pipe_flow::accmode_reads(f.acc),
                writes: crate::pipe_flow::accmode_writes(f.acc),
            },
        );
    }
    if let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/maps")) {
        let ns = ipc_ns_of(pid);
        for m in parse_maps(&text) {
            if let Some(o) = mapping_object(&m, ns) {
                add_object(&mut out, o);
            }
        }
    }
    out
}

/// The objects `pid` can WRITE (a descriptor that writes, a writable shared
/// mapping), as targets.
pub fn written_objects(pid: i32) -> Vec<ObjectTarget> {
    held_objects(pid).iter().filter(|o| o.writes).map(ObjectTarget::of).collect()
}

/// The objects `pid` has mapped shared and writable (`/proc/<pid>/maps`
/// alone, no descriptor), as targets.
pub fn written_mappings(pid: i32) -> Vec<ObjectTarget> {
    // `maps` is hidden inside an exec as the descriptor table is: read once
    // any exec `pid` is inside has ended (2026-10-17, `pipe_flow::fd_table_read`).
    let _ = crate::pipe_flow::fd_table_read(pid);
    let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else { return Vec::new() };
    let ns = ipc_ns_of(pid);
    let mut out: Vec<HeldObject> = Vec::new();
    for m in parse_maps(&text) {
        if let Some(o) = mapping_object(&m, ns) {
            add_object(&mut out, o);
        }
    }
    out.iter().filter(|o| o.writes).map(ObjectTarget::of).collect()
}

/// Does `pid` hold one of `targets` in a way that READS it?
pub fn reads_object(pid: i32, targets: &[ObjectTarget]) -> bool {
    if targets.is_empty() {
        return false;
    }
    held_objects(pid).iter().any(|o| o.reads && targets.iter().any(|t| same_object(o, t)))
}

/// The keys of every object `pid` can read (the later-event and open-time
/// look against the marks).
pub fn read_keys(pid: i32) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for o in held_objects(pid).into_iter().filter(|o| o.reads) {
        for k in o.keys {
            if !out.contains(&k) {
                out.push(k);
            }
        }
    }
    out
}

/// The object a descriptor the guard holds names (its own copy, or the file
/// it opened for a tracee): a regular file only.
pub fn fd_object(fd: RawFd) -> Option<ObjectTarget> {
    // SAFETY: fstat into a zeroed stat buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    let link = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok();
    object_of(&st, link.as_deref())
}

/// `fd_object` from a `fstat` and a `/proc/self/fd` link the caller already
/// read of that descriptor (`None`: the link could not be read, and there
/// is no object, as there `read_link` failing was). Pure.
pub fn object_of(st: &libc::stat, link: Option<&std::path::Path>) -> Option<ObjectTarget> {
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return None;
    }
    Some(ObjectTarget { keys: vec![file_key(st.st_dev, st.st_ino)], path: link?.to_str().and_then(real_path).map(str::to_string) })
}

// ── SysV shared memory and message queues ───────────────────────────────────

/// The IPC calls the guard judges under a secret policy: `shmat` (a SysV
/// segment joins two processes, `ObjectTarget` keyed by `sysv_key`), and the
/// message queue sends (`msgsnd`, `mq_timedsend`, which glibc's `mq_send`
/// is), refused to a holder. The rest of SysV and POSIX IPC carries no
/// bytes (`shmget`, `shmctl`, `msgget`, `mq_open`, …) or receives them
/// (`msgrcv`, `mq_timedreceive`), and runs at full speed.
pub fn ipc_nrs() -> [libc::c_long; 3] {
    [libc::SYS_shmat, libc::SYS_msgsnd, libc::SYS_mq_timedsend]
}

pub fn is_ipc_nr(nr: i64) -> bool {
    ipc_nrs().iter().any(|n| *n as i64 == nr)
}

/// What a trapped IPC call does, from its registers (no memory is read, so
/// nothing a thread can rewrite after the look).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcCall {
    /// `shmat(shmid, addr, shmflg)`: `writes` unless `SHM_RDONLY`.
    Attach { shmid: i32, writes: bool },
    /// `msgsnd` or `mq_timedsend`: bytes into a queue another process reads.
    QueueSend,
}

/// P0 1c (2026-10-07): is the thread whose `/proc/<tgid>/task/<tid>/syscall`
/// reads `line` possibly still inside the queue send `nr` it was let go on
/// (so the kernel may not have copied its buffer yet)? `None`: the file
/// could not be read; `exists`: the thread is still there. A thread on a
/// CPU reads `running` (inside the send or past it: the kernel cannot
/// say), one inside a syscall its number, one blocked outside any `-1`.
/// Only another number, `-1`, or a thread gone settle it; an unreadable
/// file of a live thread does not (fail-closed). Pure.
pub fn still_in_send(line: Option<&str>, exists: bool, nr: i64) -> bool {
    let Some(line) = line else { return exists };
    let first = line.split_whitespace().next().unwrap_or("");
    if first == "running" {
        return true;
    }
    match first.parse::<i64>() {
        Ok(n) => n == nr,
        // Unparsable: not settled.
        Err(_) => true,
    }
}

/// P0 1c (2026-10-07): the queue sends the guard let go (CONTINUE) for a
/// process that held no secret, each keeping its process's egress gate
/// (`send_guard::EgressGate`) entered until the sending thread is seen out
/// of the call (`still_in_send`), so a taint of that process (another
/// thread's raw open) waits until the kernel has copied the buffer: the
/// bytes it copies were in the buffer before the secret was. One entry per
/// sending thread (a thread is in one syscall at a time: a new send by it
/// settles the last).
#[derive(Default)]
pub struct QueueSends {
    held: std::sync::Mutex<std::collections::HashMap<i32, (u64, crate::send_guard::InFlightEgress)>>,
    seq: std::sync::atomic::AtomicU64,
}

impl QueueSends {
    /// Keep `gate` until thread `tid` of `tgid` has left the send `nr`; a
    /// thread of the guard watches it (`still_in_send`).
    pub fn hold(self: &std::sync::Arc<Self>, tgid: i32, tid: i32, nr: i64, gate: crate::send_guard::InFlightEgress) {
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let old = self.held.lock().ok().and_then(|mut m| m.insert(tid, (seq, gate)));
        drop(old);
        let me = self.clone();
        std::thread::spawn(move || {
            let start = std::time::Instant::now();
            let task = format!("/proc/{tgid}/task/{tid}");
            loop {
                let waited = start.elapsed();
                let pause = if waited < std::time::Duration::from_millis(50) {
                    1
                } else if waited < std::time::Duration::from_secs(2) {
                    10
                } else {
                    50
                };
                std::thread::sleep(std::time::Duration::from_millis(pause));
                // A later send by the same thread replaced this one: settled.
                if !me.held.lock().map(|m| m.get(&tid).map(|e| e.0) == Some(seq)).unwrap_or(false) {
                    return;
                }
                let line = std::fs::read_to_string(format!("{task}/syscall")).ok();
                let exists = line.is_some() || std::path::Path::new(&task).exists();
                if !still_in_send(line.as_deref(), exists, nr) {
                    break;
                }
            }
            me.release(tid, seq);
        });
    }

    /// Thread `tid` is in a new queue send: the last one it was let go on
    /// is over (a thread is in one syscall at a time).
    pub fn settle(&self, tid: i32) {
        let done = self.held.lock().ok().and_then(|mut m| m.remove(&tid));
        drop(done);
    }

    fn release(&self, tid: i32, seq: u64) {
        let done = self.held.lock().ok().and_then(|mut m| if m.get(&tid).map(|e| e.0) == Some(seq) { m.remove(&tid) } else { None });
        drop(done);
    }

    /// The threads with a send still held (tests).
    pub fn held_count(&self) -> usize {
        self.held.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Is a send of thread `tid` held (tests: the guard let it go and keeps
    /// its gate)?
    pub fn holds(&self, tid: i32) -> bool {
        self.held.lock().map(|m| m.contains_key(&tid)).unwrap_or(false)
    }
}

pub fn ipc_call(nr: i64, args: &[u64; 6]) -> Option<IpcCall> {
    if nr == libc::SYS_shmat as i64 {
        return Some(IpcCall::Attach { shmid: args[0] as u32 as i32, writes: (args[2] as u32 as i32) & libc::SHM_RDONLY == 0 });
    }
    if nr == libc::SYS_msgsnd as i64 || nr == libc::SYS_mq_timedsend as i64 {
        return Some(IpcCall::QueueSend);
    }
    None
}

// ── memfd_create (P0 triage 1b, 2026-10-07) ─────────────────────────────────

/// `memfd_create` is trapped under a secret policy: a memfd a holder
/// creates after its taint produced no event, so no mark named it (the
/// taint-time sweep lists only the memfds a process holds at its taint).
/// For a holder the guard performs the call and marks the new object's key
/// before the descriptor is handed over (`guard_flow::handle_memfd_notif`),
/// as a holder's write-capable open marks a file; for anyone else it runs
/// as it was (CONTINUE). Not refused: V8 and other JIT runtimes use memfds.
pub fn is_memfd_nr(nr: i64) -> bool {
    nr == libc::SYS_memfd_create as i64
}

/// `MFD_NAME_MAX_LEN` (`mm/memfd.c`): the longest name, NUL excluded.
pub const MFD_NAME_MAX_LEN: usize = 249;

/// The name `memfd_create` copies, from up to `MFD_NAME_MAX_LEN + 1` bytes
/// read at its pointer (a read that ran into unmapped memory gives fewer):
/// the bytes before the first NUL. EFAULT when nothing could be read, EINVAL
/// when no NUL ends it in time (the kernel's own answers). Pure.
pub fn memfd_name(read: &[u8]) -> Result<Vec<u8>, i32> {
    if read.is_empty() {
        return Err(libc::EFAULT);
    }
    match read.iter().take(MFD_NAME_MAX_LEN + 1).position(|b| *b == 0) {
        Some(n) => Ok(read[..n].to_vec()),
        None if read.len() > MFD_NAME_MAX_LEN => Err(libc::EINVAL),
        // The string runs into memory the read could not reach.
        None => Err(libc::EFAULT),
    }
}

/// The flags the guard creates a holder's memfd with (the caller's, plus
/// `MFD_CLOEXEC` for the guard's own copy, which it closes once handed
/// over) and the descriptor flags the caller's copy gets (`O_CLOEXEC` when
/// it asked for `MFD_CLOEXEC`). Every other bit is the caller's: the kernel
/// judges it again when the guard makes the call. Pure.
pub fn memfd_flags(flags: u64) -> (libc::c_uint, i32) {
    let f = flags as u32;
    (f | libc::MFD_CLOEXEC, if f & libc::MFD_CLOEXEC != 0 { libc::O_CLOEXEC } else { 0 })
}

// ── the race between a reader's open and a holder's write ───────────────────

/// How long a finished reading open stays listed (`ObjectOpens::end`).
pub const RECENT: std::time::Duration = std::time::Duration::from_secs(5);

/// A file born less than this ago (`born_recently`) has all its readers
/// listed (`RECENT` is longer by four seconds: the coarse clock, the open's
/// own time, and a wall clock stepped back within that), so a holder's
/// write to a file it just created needs no look at every process
/// (`guard_flow::object_written`).
pub const FRESH: std::time::Duration = std::time::Duration::from_secs(1);

/// The reading opens of regular files the guard performs (and the `shmat`s
/// it continues, and the regular files it passes over `SCM_RIGHTS`), and the
/// lock under which a written object is marked.
///
/// The order that closes the race: the READER (`begin`), under the lock,
/// checks the mark and, when there is none, registers itself IN FLIGHT; once
/// its descriptor is in its table (`end`) it stays listed as RECENT for
/// `RECENT`. The WRITER (`mark_then`), under the same lock, marks the object
/// and takes the readers listed for it. So a reader either sees the mark
/// (and becomes a holder at its open) or is seen by the writer: in flight
/// (counted whatever `/proc` shows yet), recent (counted when it, or a
/// process it forked, still holds the object), or in `/proc`.
#[derive(Debug, Default)]
pub struct ObjectOpens {
    inner: std::sync::Mutex<OpensInner>,
    next: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Default)]
struct OpensInner {
    /// key → (ticket, pid, state).
    by_key: std::collections::HashMap<String, Vec<(u64, i32, Listed)>>,
    /// ticket → the keys it is listed under.
    tickets: std::collections::HashMap<u64, Vec<String>>,
    last_prune: Option<std::time::Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Listed {
    /// The descriptor is not in the tracee's table yet.
    InFlight,
    /// Counted as a reader whatever `/proc` shows, until then (a continued
    /// `shmat`, which the kernel completes after the guard answered).
    Until(std::time::Instant),
    /// Done; counted when it still holds the object, until then.
    Recent(std::time::Instant),
}

/// What `ObjectOpens::begin` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenLook {
    /// The object is marked: what it carries (the opener becomes a holder).
    Marked(Vec<String>),
    /// Not marked; registered under this ticket until `end`.
    InFlight(u64),
}

/// The readers a writer's `mark_then` found listed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListedReaders {
    /// Readers to count whatever `/proc` shows (in flight, or in grace).
    pub now: Vec<i32>,
    /// Readers that opened it lately: counted when they (or a process they
    /// forked) still hold it.
    pub recent: Vec<i32>,
}

impl ObjectOpens {
    fn prune(g: &mut OpensInner, now: std::time::Instant) {
        if g.last_prune.map(|t| now.duration_since(t) < std::time::Duration::from_millis(500)).unwrap_or(false) {
            return;
        }
        g.last_prune = Some(now);
        let mut gone: Vec<u64> = Vec::new();
        g.by_key.retain(|_, v| {
            v.retain(|(t, _, s)| {
                let keep = match s {
                    Listed::InFlight => true,
                    Listed::Until(u) | Listed::Recent(u) => *u > now,
                };
                if !keep {
                    gone.push(*t);
                }
                keep
            });
            !v.is_empty()
        });
        for t in gone {
            g.tickets.remove(&t);
        }
    }

    fn add(g: &mut OpensInner, t: u64, pid: i32, keys: &[String], s: Listed) {
        for k in keys {
            g.by_key.entry(k.clone()).or_default().push((t, pid, s));
        }
        g.tickets.entry(t).or_default().extend(keys.iter().cloned());
    }

    fn set(g: &mut OpensInner, ticket: u64, s: Listed) {
        let keys = g.tickets.get(&ticket).cloned().unwrap_or_default();
        for k in keys {
            for e in g.by_key.get_mut(&k).into_iter().flatten().filter(|e| e.0 == ticket) {
                e.2 = s;
            }
        }
    }

    /// A reader (`pid`) is about to receive a descriptor of the object
    /// `keys` names; `marked` reads the marks (under the lock).
    pub fn begin(&self, pid: i32, keys: &[String], marked: impl FnOnce(&[String]) -> Vec<String>) -> OpenLook {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let m = marked(keys);
        if !m.is_empty() {
            return OpenLook::Marked(m);
        }
        let now = std::time::Instant::now();
        Self::prune(&mut g, now);
        let t = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self::add(&mut g, t, pid, keys, Listed::InFlight);
        OpenLook::InFlight(t)
    }

    /// The reader's descriptor is in its table (or the open failed): listed
    /// as recent for `RECENT`.
    pub fn end(&self, ticket: u64) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::set(&mut g, ticket, Listed::Recent(std::time::Instant::now() + RECENT));
    }

    /// The guard answered, and the kernel completes the call after (a
    /// continued `shmat`): counted as a reader for `grace` whatever `/proc`
    /// shows, then as recent. An extra entry only makes a reader a holder
    /// too many.
    pub fn end_after(&self, ticket: u64, grace: std::time::Duration) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::set(&mut g, ticket, Listed::Until(std::time::Instant::now() + grace));
    }

    /// `pid` received the object `keys` names another way the guard saw (a
    /// regular file passed over `SCM_RIGHTS`): listed as recent.
    pub fn note(&self, pid: i32, keys: &[String]) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        Self::prune(&mut g, now);
        let t = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self::add(&mut g, t, pid, keys, Listed::Recent(now + RECENT));
    }

    /// A writer marks the object `keys` names (`mark`, under the lock) and
    /// takes the readers listed for it.
    pub fn mark_then(&self, keys: &[String], mark: impl FnOnce()) -> ListedReaders {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        mark();
        let now = std::time::Instant::now();
        let mut out = ListedReaders::default();
        for k in keys {
            for (_, p, s) in g.by_key.get(k).into_iter().flatten() {
                let into = match s {
                    Listed::InFlight => Some(&mut out.now),
                    Listed::Until(u) if *u > now => Some(&mut out.now),
                    Listed::Until(_) => Some(&mut out.recent),
                    Listed::Recent(u) if *u > now => Some(&mut out.recent),
                    Listed::Recent(_) => None,
                };
                if let Some(v) = into {
                    if !v.contains(p) {
                        v.push(*p);
                    }
                }
            }
        }
        out.recent.retain(|p| !out.now.contains(p));
        out
    }
}

/// Was the file a descriptor names born less than `FRESH` ago (its birth
/// time, `statx`)? False when the filesystem keeps none, or it cannot be
/// read, or the birth lies ahead of the clock: the caller then looks at
/// every process.
pub fn born_recently(fd: RawFd) -> bool {
    // SAFETY: statx into a zeroed buffer, on our own descriptor.
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let empty = b"\0";
    let rc = unsafe { libc::statx(fd, empty.as_ptr() as *const libc::c_char, libc::AT_EMPTY_PATH, libc::STATX_BTIME, &mut stx) };
    if rc != 0 || stx.stx_mask & libc::STATX_BTIME == 0 {
        return false;
    }
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime into a local.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    let now = ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128;
    let born = stx.stx_btime.tv_sec as i128 * 1_000_000_000 + stx.stx_btime.tv_nsec as i128;
    // A birth in the future (a clock stepped back): not recent, look at all.
    let age = now - born;
    (0..FRESH.as_nanos() as i128).contains(&age)
}

#[cfg(test)]
mod queue_send_tests {
    use super::*;

    #[test]
    fn a_thread_is_out_of_the_send_only_when_the_kernel_says_so() {
        let nr = libc::SYS_msgsnd as i64;
        assert!(still_in_send(Some(&format!("{nr} 0x3 0x7ffd 0x40 0x0 0x0 0x0 0x7ffd 0x7f12\n")), true, nr), "inside it (or waiting for the guard)");
        assert!(still_in_send(Some("running\n"), true, nr), "on a CPU: inside it or past it, unknown");
        assert!(!still_in_send(Some("0 0x3 0x0 0x0 0x0 0x0 0x0 0x0 0x0\n"), true, nr), "in another syscall (read): done");
        assert!(!still_in_send(Some("-1 0x7ffd 0x55aa\n"), true, nr), "blocked outside any syscall: done");
        assert!(!still_in_send(None, false, nr), "the thread is gone");
        assert!(still_in_send(None, true, nr), "a live thread whose file cannot be read: not settled (fail-closed)");
        assert!(still_in_send(Some(""), true, nr), "an empty read: not settled");
        let mq = libc::SYS_mq_timedsend as i64;
        assert!(!still_in_send(Some(&format!("{nr} 0x3\n")), true, mq), "msgsnd is not mq_timedsend");
    }

    #[test]
    fn a_held_send_keeps_the_gate_until_its_thread_is_out_of_it() {
        let gate = std::sync::Arc::new(crate::send_guard::EgressGate::default());
        let sends = std::sync::Arc::new(QueueSends::default());
        let me = std::process::id() as i32;
        // The process's main thread (it waits for the test threads, never
        // in `msgsnd`): settled at the first look.
        sends.hold(me, me, libc::SYS_msgsnd as i64, gate.enter(me));
        assert!(gate.wait_idle(&[me], std::time::Duration::from_secs(5)), "the thread is in another call: the gate is released");
        assert_eq!(sends.held_count(), 0);
        // A thread that does not exist: settled too.
        sends.hold(me, i32::MAX - 7, libc::SYS_msgsnd as i64, gate.enter(me));
        assert!(gate.wait_idle(&[me], std::time::Duration::from_secs(5)));
        // A second send of one thread replaces the first (one entry).
        let parked = std::sync::Arc::new(std::sync::Barrier::new(2));
        let p2 = parked.clone();
        let (tx, rx) = std::sync::mpsc::channel::<i32>();
        let h = std::thread::spawn(move || {
            // SAFETY: gettid has no failure mode.
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
            tx.send(tid).unwrap();
            p2.wait();
        });
        let tid = rx.recv().unwrap();
        // The parked thread waits in `futex`, never in `mq_timedsend`.
        sends.hold(me, tid, libc::SYS_mq_timedsend as i64, gate.enter(me));
        assert!(gate.wait_idle(&[me], std::time::Duration::from_secs(5)));
        assert!(!sends.holds(tid));
        parked.wait();
        h.join().unwrap();
    }

    #[test]
    fn holds_names_the_thread_whose_send_is_held() {
        // A thread parked in `futex`, held as if `futex` were its send: held
        // while it stays in that call, released once it is gone.
        let gate = std::sync::Arc::new(crate::send_guard::EgressGate::default());
        let sends = std::sync::Arc::new(QueueSends::default());
        let me = std::process::id() as i32;
        let parked = std::sync::Arc::new(std::sync::Barrier::new(2));
        let p2 = parked.clone();
        let (tx, rx) = std::sync::mpsc::channel::<i32>();
        let h = std::thread::spawn(move || {
            // SAFETY: gettid has no failure mode.
            tx.send(unsafe { libc::syscall(libc::SYS_gettid) } as i32).unwrap();
            p2.wait();
        });
        let tid = rx.recv().unwrap();
        // Parked once its syscall file shows `futex`.
        let task = format!("/proc/{me}/task/{tid}/syscall");
        let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::fs::read_to_string(&task).ok().and_then(|s| s.split_whitespace().next().map(String::from)) != Some(libc::SYS_futex.to_string()) {
            assert!(std::time::Instant::now() < end, "the thread parks in futex");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        sends.hold(me, tid, libc::SYS_futex as i64, gate.enter(me));
        assert!(sends.holds(tid) && !sends.holds(tid + 1));
        assert!(!gate.wait_idle(&[me], std::time::Duration::from_millis(100)), "still in the call: the gate is kept");
        parked.wait();
        h.join().unwrap();
        assert!(gate.wait_idle(&[me], std::time::Duration::from_secs(5)), "the thread is gone: released");
        assert!(!sends.holds(tid));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_key_gives_back_its_identity_and_no_other_key_does() {
        assert_eq!(file_id_of_key(&file_key(7, 42)), Some((7, 42)));
        assert_eq!(file_id_of_key("file:[7]"), None);
        assert_eq!(file_id_of_key("shm:[7:42]"), None);
        assert_eq!(file_id_of_key("file:[x:42]"), None);
    }

    #[test]
    fn an_objects_keys_name_a_file_by_device_and_inode_or_by_inode_alone() {
        let keys = vec![file_key(2049, 77), sysv_key(9, 77)];
        assert!(key_names_file(&keys, 2049, 77));
        // An overlay path: the overlay's device, the backing file's inode.
        assert!(key_names_file(&keys, 55, 77));
        // Another file at the path.
        assert!(!key_names_file(&keys, 2049, 78));
        assert!(!key_names_file(&keys, 2049, 7));
        assert!(!key_names_file(&[sysv_key(9, 77)], 2049, 77), "a SysV key names no file");
        assert!(!key_names_file(&[], 2049, 77));
    }

    #[test]
    fn a_maps_line_names_the_object_it_maps() {
        let text = "\
55d0c0a00000-55d0c0a02000 r--p 00000000 08:01 1835023                    /usr/bin/cat
7f00aa000000-7f00aa001000 rw-s 00000000 00:1a 4242                       /dev/shm/mandu-x
7f00ab000000-7f00ab001000 r--s 00000000 00:01 98307                      /SYSV0000002a (deleted)
7f00ac000000-7f00ac001000 rw-s 00000000 00:01 1029                       /memfd:drop (deleted)
7f00ad000000-7f00ad001000 rw-s 00000000 00:01 2048                       /dev/zero (deleted)
7f00ae000000-7f00ae001000 rw-s 00000000 00:05 77                         /dev/dri/card0
7f00af000000-7f00af001000 rw-p 00000000 00:00 0                          [heap]
7f00b0000000-7f00b0001000 rw-p 00000000 00:00 0
7f00b1000000-7f00b1001000 r--p 00000000 08:01 1234                       /tmp/a name with spaces
";
        let m = parse_maps(text);
        assert_eq!(m.len(), 7, "inode 0 (anonymous, heap) is no object: {m:?}");
        assert_eq!(m[0], MapLine { dev: makedev(8, 1), ino: 1835023, read: true, write: false, shared: false, path: "/usr/bin/cat".into() });
        assert!(m[1].write && m[1].shared && m[1].path == "/dev/shm/mandu-x");
        assert!(is_sysv_mapping(&m[2].path) && !m[2].write && m[2].shared);
        assert_eq!(m[6].path, "/tmp/a name with spaces", "a path keeps its spaces");
        let objs: Vec<bool> = m.iter().map(maps_object).collect();
        assert_eq!(objs, vec![true, true, true, true, true, false, true], "a device's mapping is no data object; /dev/shm and /dev/zero (shared anonymous memory) are");
    }

    #[test]
    fn an_ipc_call_is_read_from_its_registers() {
        let a = |x: [u64; 3]| [x[0], x[1], x[2], 0, 0, 0];
        assert_eq!(ipc_call(libc::SYS_shmat as i64, &a([7, 0, 0])), Some(IpcCall::Attach { shmid: 7, writes: true }));
        assert_eq!(ipc_call(libc::SYS_shmat as i64, &a([7, 0, libc::SHM_RDONLY as u64])), Some(IpcCall::Attach { shmid: 7, writes: false }));
        // Only the low 32 bits of an int argument count.
        assert_eq!(ipc_call(libc::SYS_shmat as i64, &a([0xffff_ffff_0000_0009, 0, 0xdead_0000_0000_0000])), Some(IpcCall::Attach { shmid: 9, writes: true }));
        assert_eq!(ipc_call(libc::SYS_msgsnd as i64, &a([1, 0, 0])), Some(IpcCall::QueueSend));
        assert_eq!(ipc_call(libc::SYS_mq_timedsend as i64, &a([3, 0, 0])), Some(IpcCall::QueueSend));
        assert_eq!(ipc_call(libc::SYS_msgrcv as i64, &a([1, 0, 0])), None, "a receive carries nothing out");
        assert!(is_ipc_nr(libc::SYS_shmat as i64) && !is_ipc_nr(libc::SYS_shmget as i64) && !is_ipc_nr(libc::SYS_shmdt as i64));
    }

    #[test]
    fn a_memfd_name_and_flags_are_the_kernels() {
        // P0 triage 1b: the guard performs a holder's memfd_create.
        assert!(is_memfd_nr(libc::SYS_memfd_create as i64) && !is_memfd_nr(libc::SYS_memfd_secret as i64) && !is_memfd_nr(libc::SYS_openat as i64));
        assert_eq!(memfd_name(b"v8-jit\0junk"), Ok(b"v8-jit".to_vec()));
        assert_eq!(memfd_name(b"\0"), Ok(Vec::new()), "an empty name is the kernel's too");
        let mut longest = vec![b'n'; MFD_NAME_MAX_LEN];
        longest.push(0);
        assert_eq!(memfd_name(&longest), Ok(vec![b'n'; MFD_NAME_MAX_LEN]));
        assert_eq!(memfd_name(&[b'n'; MFD_NAME_MAX_LEN + 1]), Err(libc::EINVAL), "too long");
        assert_eq!(memfd_name(b"cut"), Err(libc::EFAULT), "ends in memory the read could not reach");
        assert_eq!(memfd_name(b""), Err(libc::EFAULT));
        assert_eq!(memfd_flags(0), (libc::MFD_CLOEXEC, 0), "the guard's own copy is close-on-exec; the caller's is not");
        assert_eq!(memfd_flags((libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) as u64), (libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING, libc::O_CLOEXEC));
        assert_eq!(memfd_flags(0xffff_ffff_0000_0002), (libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING, 0), "the kernel reads an unsigned int");
        assert_eq!(memfd_flags(0x8000).0 & 0x8000, 0x8000, "an unknown bit is passed on for the kernel to refuse");
    }

    #[test]
    fn makedev_matches_the_libc_encoding() {
        assert_eq!(makedev(8, 1), libc::makedev(8, 1) as u64);
        assert_eq!(makedev(259, 3), libc::makedev(259, 3) as u64);
        assert_eq!(makedev(0, 0x1a), libc::makedev(0, 0x1a) as u64);
        assert_eq!(makedev(4095, 1_048_575), libc::makedev(4095, 1_048_575) as u64);
    }

    #[test]
    fn a_sysv_segment_is_keyed_by_its_ipc_namespace_and_id() {
        let m = MapLine { dev: 1, ino: 98307, read: true, write: true, shared: true, path: "/SYSV0000002a (deleted)".into() };
        let o = mapping_object(&m, Some(4026531839)).unwrap();
        assert!(o.keys.contains(&sysv_key(4026531839, 98307)));
        assert!(o.writes && o.reads);
        assert_eq!(o.path, None, "a segment has no path");
        // A private writable mapping writes nothing back.
        let p = MapLine { shared: false, path: "/tmp/x".into(), ..m.clone() };
        assert!(!mapping_object(&p, None).unwrap().writes);
        assert!(is_object_key(&sysv_key(1, 2)) && is_object_key(&file_key(1, 2)) && !is_object_key("pipe:[3]"));
    }

    #[test]
    fn a_reader_matches_by_a_shared_key_or_the_same_real_path() {
        let t = ObjectTarget { keys: vec![file_key(40, 7)], path: Some("/tmp/x".into()) };
        let by_key = HeldObject { keys: vec![file_key(40, 7)], path: None, reads: true, writes: false };
        // An overlay file: its descriptor's device differs from its mapping's.
        let by_path = HeldObject { keys: vec![file_key(8, 99)], path: Some("/tmp/x".into()), reads: true, writes: false };
        let other = HeldObject { keys: vec![file_key(8, 7)], path: Some("/tmp/y".into()), reads: true, writes: false };
        assert!(same_object(&by_key, &t) && same_object(&by_path, &t));
        assert!(!same_object(&other, &t), "the same inode number on another device, another path: another file");
        // An unlinked object has no path: matched by key only.
        let gone = HeldObject { keys: vec![file_key(40, 8)], path: None, reads: true, writes: false };
        assert!(!same_object(&gone, &ObjectTarget { keys: vec![file_key(40, 7)], path: None }));
    }

    #[test]
    fn a_link_names_an_object_and_a_real_path_only_when_it_can() {
        assert_eq!(real_path("/tmp/x"), Some("/tmp/x"));
        assert_eq!(real_path("/tmp/x (deleted)"), None);
        assert_eq!(real_path("/memfd:drop (deleted)"), None);
        assert_eq!(real_path("/proc/self/status"), None);
        assert!(object_link("/memfd:drop (deleted)") && object_link("/tmp/#123 (deleted)") && object_link("/dev/shm/x"));
        assert!(!object_link("pipe:[3]") && !object_link("socket:[3]") && !object_link("anon_inode:[eventfd]") && !object_link("/proc/1/fd/3"));
    }

    #[test]
    fn one_object_held_two_ways_is_one_entry_with_both_accesses() {
        let mut out = Vec::new();
        add_object(&mut out, HeldObject { keys: vec![file_key(1, 2)], path: Some("/x".into()), reads: true, writes: false });
        add_object(&mut out, HeldObject { keys: vec![file_key(9, 2)], path: Some("/x".into()), reads: true, writes: true });
        add_object(&mut out, HeldObject { keys: vec![file_key(1, 3)], path: None, reads: true, writes: false });
        assert_eq!(out.len(), 2);
        assert!(out[0].writes && out[0].keys.len() == 2);
    }

    #[test]
    fn a_reader_in_flight_is_seen_by_the_writer_or_sees_the_mark() {
        let opens = ObjectOpens::default();
        let marks = std::sync::Mutex::new(Vec::<String>::new());
        let k = vec![file_key(1, 2)];
        let look = |ks: &[String]| -> Vec<String> { if marks.lock().unwrap().iter().any(|m| ks.contains(m)) { vec!["holder".into()] } else { Vec::new() } };
        // The reader first: in flight, so the writer takes it.
        let OpenLook::InFlight(t) = opens.begin(41, &k, look) else { panic!("not marked yet") };
        let seen = opens.mark_then(&k, || marks.lock().unwrap().push(k[0].clone()));
        assert_eq!(seen, ListedReaders { now: vec![41], recent: vec![] }, "in flight: counted whatever /proc shows");
        opens.end(t);
        assert_eq!(opens.mark_then(&k, || {}), ListedReaders { now: vec![], recent: vec![41] }, "done: recent, counted when it still holds it");
        // The writer first: the reader sees the mark.
        assert_eq!(opens.begin(42, &k, look), OpenLook::Marked(vec!["holder".into()]));
        // Another object: neither.
        let other = vec![file_key(1, 3)];
        let OpenLook::InFlight(t2) = opens.begin(43, &other, look) else { panic!() };
        assert_eq!(opens.mark_then(&k, || {}).now, Vec::<i32>::new());
        opens.end(t2);
        // A continued attach: counted for its grace, then recent.
        let seg = vec![sysv_key(1, 7)];
        let OpenLook::InFlight(t3) = opens.begin(44, &seg, |_| Vec::new()) else { panic!() };
        opens.end_after(t3, std::time::Duration::from_millis(50));
        assert_eq!(opens.mark_then(&seg, || {}).now, vec![44], "within its grace");
        std::thread::sleep(std::time::Duration::from_millis(60));
        assert_eq!(opens.mark_then(&seg, || {}), ListedReaders { now: vec![], recent: vec![44] }, "after it");
        // A file passed: recent.
        let passed = vec![file_key(5, 6)];
        opens.note(45, &passed);
        assert_eq!(opens.mark_then(&passed, || {}).recent, vec![45]);
    }

    #[test]
    fn a_file_created_just_now_is_born_recently_and_an_old_one_is_not() {
        let dir = std::env::temp_dir().join(format!("mandu-object-born-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("new.txt");
        let f = std::fs::File::create(&p).unwrap();
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&f);
        // SAFETY: statx into a zeroed buffer.
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        let has_btime = unsafe { libc::statx(fd, b"\0".as_ptr() as *const libc::c_char, libc::AT_EMPTY_PATH, libc::STATX_BTIME, &mut stx) } == 0 && stx.stx_mask & libc::STATX_BTIME != 0;
        if has_btime {
            assert!(born_recently(fd), "a file created just now");
        } else {
            assert!(!born_recently(fd), "no birth time: never recent (every process is looked at)");
        }
        let old = std::fs::File::open("/etc/hostname").or_else(|_| std::fs::File::open("/etc/passwd")).unwrap();
        assert!(!born_recently(std::os::unix::io::AsRawFd::as_raw_fd(&old)), "a file older than FRESH");
        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn this_process_reads_and_writes_the_objects_it_holds() {
        use std::io::Write;
        let me = std::process::id() as i32;
        let dir = std::env::temp_dir().join(format!("mandu-object-flow-{me}"));
        std::fs::create_dir_all(&dir).unwrap();
        let w = dir.join("w.txt");
        let r = dir.join("r.txt");
        std::fs::write(&r, "x").unwrap();
        let mut wf = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(&w).unwrap();
        wf.write_all(b"y").unwrap();
        let rf = std::fs::File::open(&r).unwrap();
        // An unlinked file held open for reading and writing.
        let u = dir.join("u.txt");
        let uf = std::fs::OpenOptions::new().create(true).read(true).write(true).truncate(true).open(&u).unwrap();
        std::fs::remove_file(&u).unwrap();
        let written = written_objects(me);
        let wc = std::fs::canonicalize(&w).unwrap().to_str().unwrap().to_string();
        let rc = std::fs::canonicalize(&r).unwrap().to_str().unwrap().to_string();
        assert!(written.iter().any(|t| t.path.as_deref() == Some(wc.as_str())), "{written:?}");
        assert!(!written.iter().any(|t| t.path.as_deref() == Some(rc.as_str())), "a file only read is not written: {written:?}");
        let ut = fd_object(std::os::unix::io::AsRawFd::as_raw_fd(&uf)).unwrap();
        assert_eq!(ut.path, None, "an unlinked file has no path");
        assert!(written.iter().any(|t| t.keys == ut.keys), "the unlinked file is written, by key: {written:?}");
        assert!(reads_object(me, &[ut.clone()]), "and read");
        let rt = fd_object(std::os::unix::io::AsRawFd::as_raw_fd(&rf)).unwrap();
        assert!(reads_object(me, &[rt.clone()]));
        assert!(read_keys(me).contains(&rt.keys[0]));
        drop((wf, rf, uf));
        assert!(!reads_object(me, &[rt]), "closed: not held");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn this_process_reads_a_shared_mapping_after_its_descriptor_is_closed() {
        // A memfd mapped shared, then its descriptor closed: the mapping alone.
        let name = std::ffi::CString::new("mandu-object-flow").unwrap();
        let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
        assert!(fd >= 0);
        assert_eq!(unsafe { libc::ftruncate(fd, 4096) }, 0);
        let t = fd_object(fd).unwrap();
        let p = unsafe { libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, 0) };
        assert_ne!(p, libc::MAP_FAILED);
        unsafe { libc::close(fd) };
        let me = std::process::id() as i32;
        assert!(reads_object(me, &[t.clone()]), "the mapping reads it");
        assert!(written_objects(me).iter().any(|w| w.keys.iter().any(|k| t.keys.contains(k))), "a writable shared mapping writes it");
        unsafe { libc::munmap(p, 4096) };
        assert!(!reads_object(me, &[t]));
    }
}
