//! landlock_mirror — perform a Landlock-restricted tracee's opens under the
//! same restrictions (confidentiality-plan-10-flow-taint.md §4.1a).
//!
//! The guard performs every open that can read (a CONTINUE would let the
//! kernel re-read and re-resolve the path). An open performed by the guard
//! would escape the tracee's own Landlock domain: the enforce-clean box
//! (exec-output-trust §4 rung 2) reads only its verified roots through
//! Landlock alone, and a program the agent runs may sandbox itself. So the
//! guard traps `landlock_restrict_self`, copies the ruleset descriptor
//! (`pidfd_getfd`), and keeps threads that restricted THEMSELVES with the same
//! stack of rulesets. A restricted tracee's path is resolved `O_PATH` by an
//! ordinary guard thread (Landlock does not restrict `O_PATH`, and checks
//! access on the file finally opened, whatever the walk), and the access
//! itself (the reopen, or the create) runs on a mirror thread, where Landlock
//! decides it exactly as it would for the tracee.
//!
//! The mirror is applied before the tracee's own call runs, so it is never
//! looser: a rule added to the ruleset afterwards widens only the tracee's
//! domain. A stack the guard cannot build (the ruleset cannot be copied, the
//! mirror cannot restrict itself) refuses the tracee's call: the guard never
//! bypasses a sandbox it cannot mirror.
//!
//! Which tasks are restricted: a task's own record, else its nearest
//! recorded ancestor's, cached per task (proc key: pid + start time, so a
//! reused pid is another task) and recorded at every exec too. A restriction
//! applies to the calling thread; it is recorded for its process as well, so
//! a child forked from any thread inherits it (stricter than the kernel for
//! the process's other threads, never looser). A double fork loses that
//! lineage, so a sandbox set up in a pid namespace of its own is recorded for
//! the namespace too (the command box's are): an orphan re-parented to the
//! namespace's init still gets it, and a namespace with two sandboxes gives
//! its orphans a deny-all domain. Residue: a sandbox without a pid namespace
//! of its own keeps the lineage gap (its double-forked orphan's opens run
//! unrestricted by it; registered secrets are still matched by the file
//! opened).
//!
//! CONNECTS (confidentiality-plan-11 §8 item 5). The guard also performs
//! every allowed INET connect itself (on its copy of the tracee's socket), so
//! a program that confined its own TCP with Landlock would be widened to the
//! guard's allow set. A supervised connect therefore runs on a mirror thread
//! too, restricted by the tracee's NESTED layers: every layer except the one
//! the launch's own wrap chain installed (`set_launch_root`: the first
//! restriction by the guard's direct child while it runs
//! `mandu-landlock-apply`, i.e. the whole-agent `--net-only` port wrap). That
//! launch layer is what the guard's destination-aware allow list supersedes
//! by design (exec-routing.md §7.5: an allowed :443 stays reachable under
//! `--landlock-net-strict`); a sandbox set up inside the agent tree (the
//! launcher's inspect-mcp confine, a program that sandboxes itself) only
//! narrows, as it would without the guard.
//!
//! OPENS UNDER THE LAUNCH'S NET-ONLY WRAP ALONE (2026-10-05). That launch
//! layer, when it is `mandu-landlock-apply --net-only` (`launch_wrap`),
//! handles no filesystem access, so for a task whose domain is that layer
//! alone (the whole agent tree outside a nested sandbox) the guard reopens
//! a file it resolved on its own thread (`Domain::governs_files`):
//! Landlock would allow that access, as for no domain, and the mirror's two
//! cross-thread handoffs cost about 0.2 ms of every open (plan 10 §4.1a,
//! "The cost of the mirror"). Everything else keeps the mirror: a
//! pseudo-filesystem file is reopened by the context helper under the whole
//! domain (Landlock's ptrace scoping decides `/proc/<pid>/…` for every
//! domain), and so are the mutating steps and the connects.
//!
//! `Mandu-new`.

#![cfg(all(feature = "kernel", target_os = "linux"))]

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

/// `landlock_restrict_self`: the same number on x86_64 and aarch64.
pub const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

/// A copied ruleset descriptor, closed with the last domain that uses it.
/// `launch`: installed by the launch's own wrap chain (the guard's direct
/// child), so a supervised connect does not apply it (see the header).
struct Layer {
    fd: RawFd,
    launch: bool,
    /// The launch's net-only wrap (`launch_wrap`): handles no file access.
    net_only_wrap: bool,
}

impl Drop for Layer {
    fn drop(&mut self) {
        // SAFETY: our own copy of the tracee's ruleset descriptor.
        unsafe { libc::close(self.fd) };
    }
}

type Job = Box<dyn FnOnce() + Send>;

/// Mirror threads alive now, the most ever alive at once, and the domains
/// built: written at exit to the guard's open-stats file (a test's proof
/// that the records of gone tasks are let go, `mirror_records`; no
/// decision depends on them).
pub static MIRROR_THREADS_LIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
pub static MIRROR_THREADS_PEAK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
pub static MIRROR_DOMAINS_BUILT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A mirrored Landlock domain: its ruleset layers, innermost last, and the
/// threads restricted by them.
pub struct Domain {
    layers: Vec<Arc<Layer>>,
    tx: SyncSender<Job>,
    rx: Arc<Mutex<std::sync::mpsc::Receiver<Job>>>,
    threads: std::sync::atomic::AtomicUsize,
    /// The connect mirror (`connect_domain`), built on first use when this
    /// domain stacks both launch and nested layers. A failed build is not
    /// kept: the next connect tries again (and is refused meanwhile).
    connect: Mutex<Option<Arc<Domain>>>,
}

/// How a supervised connect of a task runs (`connect_domain`).
pub enum ConnectVia {
    /// No nested layer: the guard connects on its own thread, as before.
    Guard,
    /// On a mirror thread of this domain (its nested layers only).
    Mirror(Arc<Domain>),
}

impl Domain {
    const MAX_THREADS: usize = 4;

    /// Build the domain and its first mirror thread. Err = the errno the
    /// mirror could not restrict itself with.
    fn new(layers: Vec<Arc<Layer>>) -> Result<Arc<Domain>, i32> {
        let (tx, rx) = sync_channel::<Job>(0);
        let d = Arc::new(Domain {
            layers,
            tx,
            rx: Arc::new(Mutex::new(rx)),
            threads: std::sync::atomic::AtomicUsize::new(0),
            connect: Mutex::new(None),
        });
        d.spawn_thread()?;
        MIRROR_DOMAINS_BUILT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(d)
    }

    /// A mirror thread: `no_new_privs`, every layer applied to itself, then
    /// jobs until the domain is dropped.
    fn spawn_thread(self: &Arc<Self>) -> Result<(), i32> {
        let fds: Vec<RawFd> = self.layers.iter().map(|l| l.fd).collect();
        let layers = self.layers.clone();
        let rx = self.rx.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), i32>>();
        let spawned = std::thread::Builder::new().name("guard-landlock".into()).spawn(move || {
            let _keep = layers;
            // SAFETY: per-thread prctl and landlock_restrict_self on ourselves.
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                let _ = ready_tx.send(Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EPERM)));
                return;
            }
            for fd in fds {
                if unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0) } != 0 {
                    let _ = ready_tx.send(Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EPERM)));
                    return;
                }
            }
            let live = MIRROR_THREADS_LIVE.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            MIRROR_THREADS_PEAK.fetch_max(live, std::sync::atomic::Ordering::Relaxed);
            let _ = ready_tx.send(Ok(()));
            loop {
                let next = rx.lock().unwrap_or_else(|p| p.into_inner()).recv();
                let Ok(job) = next else { break };
                job();
            }
            MIRROR_THREADS_LIVE.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
        if spawned.is_err() {
            return Err(libc::EAGAIN);
        }
        ready_rx.recv().unwrap_or(Err(libc::EAGAIN))?;
        self.threads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Run `f` on a mirror thread and wait for it. A busy domain grows a
    /// thread (up to `MAX_THREADS`), then waits for a free one.
    pub fn run<R: Send + 'static>(self: &Arc<Self>, f: impl FnOnce() -> R + Send + 'static) -> Result<R, i32> {
        let (done_tx, done_rx) = std::sync::mpsc::channel::<R>();
        let job: Job = Box::new(move || {
            let _ = done_tx.send(f());
        });
        let job = match self.tx.try_send(job) {
            Ok(()) => None,
            Err(TrySendError::Full(job)) => Some(job),
            Err(TrySendError::Disconnected(_)) => return Err(if self.layers.is_empty() { libc::EACCES } else { libc::EIO }),
        };
        if let Some(job) = job {
            if self.threads.load(std::sync::atomic::Ordering::SeqCst) < Self::MAX_THREADS {
                self.spawn_thread()?;
            }
            self.tx.send(job).map_err(|_| if self.layers.is_empty() { libc::EACCES } else { libc::EIO })?;
        }
        done_rx.recv().map_err(|_| libc::EIO)
    }

    /// A domain with no mirror thread: every access through it is refused
    /// (`run` answers EACCES). For an orphan of an ambiguous namespace on a
    /// host where a deny-all ruleset cannot be built.
    fn refusing() -> Domain {
        let (tx, rx) = sync_channel::<Job>(0);
        drop(rx);
        let (_, keep) = sync_channel::<Job>(0);
        Domain {
            layers: Vec::new(),
            tx,
            rx: Arc::new(Mutex::new(keep)),
            threads: std::sync::atomic::AtomicUsize::new(Self::MAX_THREADS),
            connect: Mutex::new(None),
        }
    }

    /// Where a supervised connect of a task in this domain runs. Only the
    /// launch's layers ⇒ `Guard` (the guard's allow list supersedes them);
    /// only nested ones ⇒ this domain; both ⇒ a mirror of the nested ones,
    /// built once (retried after a failed build). The refusing domain (no layers, no thread) is returned as
    /// is, so the connect is refused like its opens (fail-closed). Err = the
    /// errno the mirror could not be built with: the caller refuses the
    /// connect with it (the guard never bypasses a sandbox it cannot mirror).
    pub fn connect_domain(self: &Arc<Self>) -> Result<ConnectVia, i32> {
        if self.layers.is_empty() {
            return Ok(ConnectVia::Mirror(self.clone()));
        }
        let nested: Vec<Arc<Layer>> = self.layers.iter().filter(|l| !l.launch).cloned().collect();
        if nested.is_empty() {
            return Ok(ConnectVia::Guard);
        }
        if nested.len() == self.layers.len() {
            return Ok(ConnectVia::Mirror(self.clone()));
        }
        let mut slot = self.connect.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(d) = slot.as_ref() {
            return Ok(ConnectVia::Mirror(d.clone()));
        }
        let d = Domain::new(nested)?;
        *slot = Some(d.clone());
        Ok(ConnectVia::Mirror(d))
    }

    /// Does Landlock restrict this domain's file accesses? Not when its
    /// layers are the launch's net-only wrap alone (`launch_wrap::
    /// layers_govern_files`); the refusing domain always does.
    pub fn governs_files(&self) -> bool {
        let wraps: Vec<bool> = self.layers.iter().map(|l| l.net_only_wrap).collect();
        crate::launch_wrap::layers_govern_files(&wraps)
    }

    /// How many rulesets this domain stacks.
    pub fn depth(&self) -> usize {
        self.layers.len()
    }

    /// The copied ruleset descriptors, innermost last (valid while the
    /// domain lives), for a process that must apply the same stack
    /// (`context_helper`).
    pub fn layer_fds(&self) -> Vec<RawFd> {
        self.layers.iter().map(|l| l.fd).collect()
    }
}

/// What a pid namespace's record says about a task in it whose lineage is
/// lost (a double fork re-parented it to the namespace's init).
enum NsDomain {
    /// One sandbox was set up in this namespace, by this process (tgid).
    One { tgid: i32, domain: Arc<Domain> },
    /// More than one: which one an orphan belongs to is unknown, so it gets
    /// a domain that denies every file access (fail-closed).
    Ambiguous,
}

/// A pid namespace a sandbox was set up in, alive as long as its init is.
struct NsRecord {
    init: RawFd,
    what: NsDomain,
}

impl Drop for NsRecord {
    fn drop(&mut self) {
        // SAFETY: our pidfd of the namespace's init.
        unsafe { libc::close(self.init) };
    }
}

impl NsRecord {
    fn alive(&self) -> bool {
        let mut p = libc::pollfd { fd: self.init, events: libc::POLLIN, revents: 0 };
        // SAFETY: a zero-timeout poll of our pidfd: readable once init exited.
        unsafe { libc::poll(&mut p, 1, 0) == 0 }
    }
}

/// The restricted tasks of the tree and their mirrored domains.
#[derive(Default)]
pub struct LandlockMirror {
    /// Per task (proc key): its domain, or `None` = known unrestricted.
    tasks: Mutex<HashMap<String, Option<Arc<Domain>>>>,
    /// When `tasks` is next swept of gone tasks (`mirror_records`): a
    /// record holds its domain's threads and descriptors.
    sweep_at: Mutex<crate::mirror_records::SweepSchedule>,
    /// Per pid namespace (`(dev, ino)` of `/proc/<pid>/ns/pid`) other than
    /// the guard's: the sandbox set up in it. A process that outlives its
    /// parents (a double fork) is re-parented to the namespace's init and
    /// its lineage lost, but it never leaves the namespace; the command box
    /// runs every command in one of its own (bwrap `--unshare-pid`).
    namespaces: Mutex<HashMap<(u64, u64), NsRecord>>,
    /// The deny-everything domain (`NsDomain::Ambiguous`), built once.
    deny_all: std::sync::OnceLock<Option<Arc<Domain>>>,
    /// Set once any task restricted itself: until then no lookup is paid.
    any: std::sync::atomic::AtomicBool,
    /// The guard's direct child (tgid), whose first restriction under the
    /// applier is the launch's own wrap (`Layer::launch`). 0 = none (every
    /// layer is nested).
    launch_root: std::sync::atomic::AtomicI32,
    /// Set once the launch layer was recorded: any later restriction, even
    /// by the root process, is nested.
    launch_taken: std::sync::atomic::AtomicBool,
    /// The guard's own target when it is the net-only wrap
    /// (`set_launch_wrap`): the launch layer it installs governs no file.
    wrap: std::sync::OnceLock<crate::launch_wrap::LaunchWrap>,
}

fn pid_ns(pid: i32) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(format!("/proc/{pid}/ns/pid")).ok().map(|m| (m.dev(), m.ino()))
}

impl LandlockMirror {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(pid: i32) -> Option<String> {
        mandu_arbiter::proc::proc_key_for_pid(pid)
    }

    fn tgid_of(tid: i32) -> i32 {
        std::fs::read_to_string(format!("/proc/{tid}/status"))
            .ok()
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix("Tgid:").and_then(|v| v.trim().parse().ok())))
            .unwrap_or(tid)
    }

    fn own_ns() -> Option<(u64, u64)> {
        static OURS: std::sync::OnceLock<Option<(u64, u64)>> = std::sync::OnceLock::new();
        // SAFETY: getpid cannot fail.
        *OURS.get_or_init(|| pid_ns(unsafe { libc::getpid() }))
    }

    /// A domain that refuses every file access: a ruleset handling the
    /// filesystem rights of Landlock ABI 1 with no rule granting any.
    fn deny_all(&self) -> Option<Arc<Domain>> {
        self.deny_all
            .get_or_init(|| {
                #[repr(C)]
                struct Attr {
                    handled_access_fs: u64,
                }
                let attr = Attr { handled_access_fs: 0x1fff };
                // SAFETY: landlock_create_ruleset(attr, size, 0).
                let fd = unsafe { libc::syscall(444, &attr as *const Attr, std::mem::size_of::<Attr>(), 0u32) };
                if fd < 0 {
                    return None;
                }
                Domain::new(vec![Arc::new(Layer { fd: fd as RawFd, launch: false, net_only_wrap: false })]).ok()
            })
            .clone()
    }

    /// The domain a pid namespace's record gives a task whose lineage left
    /// the namespace without meeting a record. `None`: no live record.
    fn ns_domain(&self, ns: (u64, u64)) -> Option<Arc<Domain>> {
        let mut namespaces = self.namespaces.lock().unwrap_or_else(|p| p.into_inner());
        let alive = namespaces.get(&ns).map(|r| r.alive())?;
        if !alive {
            namespaces.remove(&ns);
            return None;
        }
        match &namespaces.get(&ns)?.what {
            NsDomain::One { domain, .. } => Some(domain.clone()),
            NsDomain::Ambiguous => {
                drop(namespaces);
                // Without Landlock to build it, the orphan cannot be served.
                Some(self.deny_all().unwrap_or_else(|| Arc::new(Domain::refusing())))
            }
        }
    }

    /// The mirrored domain of task `tid`, if it (or an ancestor) restricted
    /// itself under the guard, or its pid namespace holds a sandbox its
    /// lineage no longer shows.
    pub fn domain_of(&self, tid: i32) -> Option<Arc<Domain>> {
        if !self.any.load(std::sync::atomic::Ordering::SeqCst) {
            return None;
        }
        let with_ns = !self.namespaces.lock().unwrap_or_else(|p| p.into_inner()).is_empty();
        let ours = if with_ns { Self::own_ns() } else { None };
        let mut walked: Vec<String> = Vec::new();
        let mut found: Option<Option<Arc<Domain>>> = None;
        let mut cur = tid;
        let mut cur_ns = if with_ns { pid_ns(tid) } else { None };
        for _ in 0..64 {
            let Some(k) = Self::key(cur) else { break };
            if let Some(d) = self.tasks.lock().unwrap_or_else(|p| p.into_inner()).get(&k) {
                found = Some(d.clone());
                break;
            }
            walked.push(k);
            // A thread's own record first, then its process's, then the parent.
            let tgid = Self::tgid_of(cur);
            let next = if tgid != cur {
                tgid
            } else {
                match crate::secret_open::parent_pid_of(cur) {
                    Some(pp) if pp > 0 => pp,
                    _ => break,
                }
            };
            // Leaving a pid namespace without a record inside it: the
            // namespace's own record decides (the lineage may be lost).
            if with_ns {
                let next_ns = pid_ns(next);
                if cur_ns.is_some() && next_ns != cur_ns && cur_ns != ours {
                    if let Some(d) = self.ns_domain(cur_ns.unwrap()) {
                        found = Some(Some(d));
                        break;
                    }
                }
                cur_ns = next_ns;
            }
            cur = next;
        }
        let d = found.unwrap_or(None);
        if walked.is_empty() {
            return d;
        }
        let mut tasks = self.tasks.lock().unwrap_or_else(|p| p.into_inner());
        for k in walked {
            tasks.insert(k, d.clone());
        }
        self.sweep(&mut tasks);
        d
    }

    /// Task `tid` calls `landlock_restrict_self(ruleset_fd)`: copy the
    /// ruleset and build the mirror (its inherited layers + this one) BEFORE
    /// the tracee's own call runs. Err = the errno to refuse the call with.
    pub fn on_restrict(&self, tid: i32, ruleset_fd: RawFd) -> Result<(), i32> {
        let copy = fs_supervisor::tracee::tracee_fd(tid, ruleset_fd).map_err(|e| e.raw_os_error().unwrap_or(libc::EPERM))?;
        let tgid = Self::tgid_of(tid);
        let launch = self.is_launch_restriction(tgid);
        let net_only_wrap = launch && self.is_wrap(tgid);
        let layer = Arc::new(Layer { fd: copy, launch, net_only_wrap });
        let mut layers = self.domain_of(tid).map(|d| d.layers.clone()).unwrap_or_default();
        layers.push(layer);
        let domain = Domain::new(layers)?;
        // Inside a pid namespace of its own: the namespace remembers it too.
        if let Some(ns) = pid_ns(tid).filter(|ns| Some(*ns) != Self::own_ns()) {
            self.record_ns(ns, tgid, &domain)?;
        }
        let mut tasks = self.tasks.lock().unwrap_or_else(|p| p.into_inner());
        for k in [Self::key(tid), Self::key(tgid)].into_iter().flatten() {
            tasks.insert(k, Some(domain.clone()));
        }
        self.any.store(true, std::sync::atomic::Ordering::SeqCst);
        self.sweep(&mut tasks);
        Ok(())
    }

    /// Record the sandbox `domain`, set up by process `tgid`, for its pid
    /// namespace `ns`. A second one by another process makes the namespace
    /// ambiguous. Err: the namespace's init cannot be held (the record could
    /// outlive it and name another namespace): refuse the restriction.
    fn record_ns(&self, ns: (u64, u64), tgid: i32, domain: &Arc<Domain>) -> Result<(), i32> {
        let mut namespaces = self.namespaces.lock().unwrap_or_else(|p| p.into_inner());
        namespaces.retain(|_, r| r.alive());
        if let Some(r) = namespaces.get_mut(&ns) {
            r.what = match &r.what {
                NsDomain::One { tgid: t, .. } if *t == tgid => NsDomain::One { tgid, domain: domain.clone() },
                _ => NsDomain::Ambiguous,
            };
            return Ok(());
        }
        // The namespace's init: the topmost ancestor still inside it.
        let mut init = tgid;
        for _ in 0..64 {
            match crate::secret_open::parent_pid_of(init) {
                Some(pp) if pp > 0 && pid_ns(pp) == Some(ns) => init = pp,
                _ => break,
            }
        }
        let pidfd = fs_supervisor::tracee::pidfd_open(init).map_err(|_| libc::EPERM)?;
        if pid_ns(init) != Some(ns) {
            // SAFETY: our pidfd; init went away while we looked.
            unsafe { libc::close(pidfd) };
            return Err(libc::EPERM);
        }
        namespaces.insert(ns, NsRecord { init: pidfd, what: NsDomain::One { tgid, domain: domain.clone() } });
        Ok(())
    }

    /// Name the guard's direct child: its first restriction while it runs
    /// the applier is the launch's own wrap (the whole-agent port wrap), which
    /// the guard's allow list supersedes for the connects it performs.
    pub fn set_launch_root(&self, tgid: i32) {
        self.launch_root.store(tgid, std::sync::atomic::Ordering::SeqCst);
    }

    /// Name the launch's net-only wrap: the guard's own target argv and the
    /// identity of its file (`launch_wrap::LaunchWrap::of`). Set once, before
    /// the tree runs.
    pub fn set_launch_wrap(&self, wrap: crate::launch_wrap::LaunchWrap) {
        let _ = self.wrap.set(wrap);
    }

    /// Is the launch restriction by `tgid` the net-only wrap's: made by a
    /// process running that very file with exactly its argv?
    fn is_wrap(&self, tgid: i32) -> bool {
        use std::os::unix::fs::MetadataExt;
        let Some(wrap) = self.wrap.get() else { return false };
        let Ok(raw) = std::fs::read(format!("/proc/{tgid}/cmdline")) else { return false };
        let exe = std::fs::metadata(format!("/proc/{tgid}/exe")).ok().map(|m| (m.dev(), m.ino()));
        crate::launch_wrap::restriction_is_wrap(wrap, &crate::launch_wrap::parse_cmdline(&raw), exe)
    }

    /// Is a restriction by process `tgid` the launch's own wrap? Only the
    /// first one by the launch root while its image is `mandu-landlock-apply`
    /// (the wrap chain execs the applier first); every other one is nested.
    fn is_launch_restriction(&self, tgid: i32) -> bool {
        use std::sync::atomic::Ordering::SeqCst;
        let root = self.launch_root.load(SeqCst);
        if root == 0 || tgid != root || self.launch_taken.load(SeqCst) {
            return false;
        }
        let applier = std::fs::read_link(format!("/proc/{tgid}/exe"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n == "mandu-landlock-apply"))
            .unwrap_or(false);
        applier && self.launch_taken.compare_exchange(false, true, SeqCst, SeqCst).is_ok()
    }

    /// How a supervised connect of task `tid` runs: on the guard's thread
    /// when it has no nested Landlock layer, else on a mirror of those
    /// layers, so the kernel decides the port as it would for the tracee.
    /// Err = the errno to refuse the connect with.
    pub fn connect_via(&self, tid: i32) -> Result<ConnectVia, i32> {
        match self.domain_of(tid) {
            None => Ok(ConnectVia::Guard),
            Some(d) => d.connect_domain(),
        }
    }

    /// Task `tid` is about to exec: remember its domain under its own key
    /// (a later reparenting must not lose it).
    pub fn on_exec(&self, tid: i32) {
        let _ = self.domain_of(tid);
    }

    /// Forget the records of tasks that are gone (their proc key no longer
    /// names a live task), and with them the domains only they held (each
    /// a mirror thread and its ruleset descriptors), once `tasks` holds
    /// twice what the last sweep left (`mirror_records`: amortized O(1) per
    /// record added). Called with `tasks` locked.
    fn sweep(&self, tasks: &mut HashMap<String, Option<Arc<Domain>>>) {
        let mut at = self.sweep_at.lock().unwrap_or_else(|p| p.into_inner());
        crate::mirror_records::sweep_gone(tasks, &mut at, |k| crate::mirror_records::key_is_live(k, Self::key));
    }
}
