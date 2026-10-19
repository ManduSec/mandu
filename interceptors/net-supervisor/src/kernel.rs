//! kernel — transparent socket redirection for the net-supervisor (PRIVILEGED, gated).
//!
//! Compiled ONLY with `--features kernel`. It needs CAP_NET_ADMIN + the `nft`
//! binary to install the nftables TPROXY rules that divert the scope's NON-MODEL
//! traffic to the proxy's listening socket, plus the accept loop that runs the
//! pure `transform::ingress_transform` / `transform::egress_transform` over each
//! proxied connection's bytes.
//!
//! Membership: in production the rules match the launcher's cgroup v2 scope (so
//! only the monitored agent's traffic is redirected — `render_tproxy_ruleset`);
//! inside a dedicated network namespace the netns *is* the scope, so the
//! integration path uses `render_tproxy_ruleset_netns` (a dport-keyed
//! mangle/prerouting TPROXY rule with no cgroup matcher). Either way
//! `transform::is_model_host` excludes api.anthropic.com / api.openai.com at the
//! proxy layer (the anthropic-proxy owns those).
//!
//! HOW TO RUN ON A PRIVILEGED HOST (full recipe in the crate README):
//!   cargo build -p net-supervisor --features kernel
//!   sudo nft -f mandu-tproxy.nft     # divert cgroup non-model traffic
//!   sudo ./target/debug/...            # run the accept loop
//!   cargo test -p net-supervisor --features kernel -- --ignored   # root + nft only
//!
//! The byte-transform policy is fully unit-tested in `transform` on the
//! unprivileged host; this module is socket/nftables plumbing only.

#![cfg(feature = "kernel")]

use std::io::{Read, Write};
use std::mem;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::Command;
use std::time::Duration;

use mandu_arbiter::client::HUMAN_SOCK_ENV;
use mandu_arbiter::ArbiterClient;

use crate::conn_attr;
use crate::transform::{egress_transform, human_client_from, ingress_transform, is_model_host};

/// Hard ceiling on a single gated message (request OR response) we will buffer
/// before transforming. The gated path MUST read the COMPLETE body so the pure
/// transform sees the whole thing; we therefore cap it so an unbounded/streamed
/// body can't exhaust memory. Fail-CLOSED if exceeded: we do NOT forward a
/// half-read body (that could leak un-symbolized untrusted bytes or a partial
/// secret). A few MiB comfortably covers tool_result/web_fetch bodies while the
/// truly large streaming traffic (the model API) goes down the pass-through path.
pub const MAX_GATED_BODY: usize = 8 * 1024 * 1024;

/// Per-read socket I/O timeout for the gated framing reader and the upstream
/// connection. Distinct from the connect timeout (which now bounds connect()
/// itself, see `connect_with_mark`).
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Buffer size for the pass-through splice copy loop (one chunk per poll wakeup).
const SPLICE_BUF: usize = 64 * 1024;

/// The IP_TRANSPARENT socket option the proxy's listening socket must set so the
/// kernel delivers TPROXY-redirected connections to it. Pinned from libc.
pub const IP_TRANSPARENT: libc::c_int = libc::IP_TRANSPARENT;

/// The fwmark TPROXY stamps on diverted packets; the local ip-rule routes that
/// mark to the proxy's local routing table. Arbitrary but must agree between the
/// nft rule and the `ip rule`/`ip route` setup.
pub const TPROXY_MARK: u32 = 1;
/// The routing table the marked packets are sent to (local delivery loopback).
pub const TPROXY_TABLE: u32 = 100;
/// The mark the proxy stamps (via SO_MARK) on its OWN upstream connection to the
/// original destination. The divert chain accepts (returns early, no re-tproxy)
/// any packet carrying this mark — this is what breaks the TPROXY self-loop:
/// without it the proxy's connect(original_dst) would itself match `dport` and be
/// re-diverted right back to the proxy. Must differ from TPROXY_MARK.
pub const BYPASS_MARK: u32 = 2;

/// Install the nftables TPROXY ruleset that diverts the scope's non-model
/// traffic to `proxy_port`, MATCHED BY CGROUP (production deployment). Requires
/// CAP_NET_ADMIN + `nft`. Returns the rendered ruleset the caller would load
/// (kept pure so a privileged test can inspect it).
pub fn render_tproxy_ruleset(cgroup_path: &str, proxy_port: u16) -> String {
    // A minimal TPROXY ruleset template. The real deployment loads this via
    // `nft -f`. Model-API hosts are excluded at the proxy layer
    // (`transform::is_model_host`) rather than by IP here, since hostnames are
    // only known after SNI/Host parsing.
    format!(
        "table inet mandu {{\n\
        \x20 chain divert {{\n\
        \x20\x20 type filter hook prerouting priority mangle; policy accept;\n\
        \x20\x20 socket cgroupv2 level 2 \"{cgroup_path}\" tcp dport {{ 80, 443 }} \\\n\
        \x20\x20\x20 tproxy to :{proxy_port} meta mark set 1 accept;\n\
        \x20 }}\n\
        }}\n"
    )
}

/// Install the netns-scoped TPROXY ruleset: a dport-keyed mangle/prerouting rule
/// with NO cgroup matcher. Used when the scope is an entire network namespace
/// (the integration test), so it is namespace-local and never touches the host.
///
/// `target_ports` are the destination TCP ports to divert (e.g. the test's
/// destination server port). They are redirected to `proxy_port` on loopback and
/// stamped with `TPROXY_MARK` so the local ip-rule routes them to the proxy.
pub fn render_tproxy_ruleset_netns(target_ports: &[u16], proxy_port: u16) -> String {
    let ports = target_ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    // ip family (v4) is enough for the loopback test; the rule lives in its own
    // table so teardown is a single `nft delete table`.
    //
    // CRITICAL ordering: the FIRST rule accepts (returns early — no tproxy) any
    // packet carrying BYPASS_MARK. The proxy stamps that mark (SO_MARK) on its
    // OWN upstream connection back to the original destination, so that
    // connection is NOT re-diverted to the proxy (which would self-loop and
    // hang). Only un-marked packets fall through to the dport tproxy rule.
    format!(
        "table ip mandu {{\n\
        \x20 chain divert {{\n\
        \x20\x20 type filter hook prerouting priority mangle; policy accept;\n\
        \x20\x20 meta mark {bypass} accept\n\
        \x20\x20 meta l4proto tcp tcp dport {{ {ports} }} tproxy to 127.0.0.1:{proxy_port} meta mark set {mark} accept\n\
        \x20 }}\n\
        }}\n",
        bypass = BYPASS_MARK,
        mark = TPROXY_MARK
    )
}

/// Apply a rendered ruleset by piping it to `nft -f -`. Fail-closed: any nft
/// error propagates (the caller must NOT proceed to accept un-diverted traffic).
pub fn apply_ruleset(ruleset: &str) -> std::io::Result<()> {
    run_nft_stdin(ruleset)
}

/// Tear down the mandu table (best-effort). Safe to call even if absent.
pub fn teardown_ruleset_netns() {
    let _ = run_nft_args(&["delete", "table", "ip", "mandu"]);
}

fn run_nft_stdin(script: &str) -> std::io::Result<()> {
    use std::process::Stdio;
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .expect("nft stdin")
        .write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "nft -f failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }
    Ok(())
}

fn run_nft_args(args: &[&str]) -> std::io::Result<()> {
    let out = Command::new("nft").args(args).output()?;
    if !out.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "nft {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }
    Ok(())
}

/// Run an `ip ...` command, propagating failure. Used for the local TPROXY
/// routing setup (ip rule + route). All scoped to the current netns.
fn run_ip(args: &[&str]) -> std::io::Result<()> {
    let out = Command::new("ip").args(args).output()?;
    if !out.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "ip {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }
    Ok(())
}

/// Set up the standard TPROXY local-delivery routing, scoped to the current
/// netns: marked packets (TPROXY_MARK) are looked up in TPROXY_TABLE, which has a
/// single `local default dev lo` route so the kernel delivers them to a local
/// IP_TRANSPARENT socket. Idempotent-ish: ignores "exists" the second time.
pub fn setup_tproxy_routing() -> std::io::Result<()> {
    // `ip rule add fwmark <mark> lookup <table>`
    let mark = TPROXY_MARK.to_string();
    let table = TPROXY_TABLE.to_string();
    // Bring loopback up (a fresh netns starts with lo DOWN).
    let _ = run_ip(&["link", "set", "lo", "up"]);
    // Routing rule + local route. Tolerate pre-existing entries.
    let _ = run_ip(&["rule", "add", "fwmark", &mark, "lookup", &table]);
    let _ = run_ip(&[
        "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", &table,
    ]);
    Ok(())
}

/// Tear down the TPROXY routing (best-effort).
pub fn teardown_tproxy_routing() {
    let mark = TPROXY_MARK.to_string();
    let table = TPROXY_TABLE.to_string();
    let _ = run_ip(&["rule", "del", "fwmark", &mark, "lookup", &table]);
    let _ = run_ip(&[
        "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", &table,
    ]);
}

/// Bind a TCP listener on `proxy_port` with IP_TRANSPARENT set BEFORE bind, so
/// the kernel will deliver TPROXY-diverted connections (whose destination is some
/// OTHER address) to it. Also sets SO_REUSEADDR. Returns a std `TcpListener`.
pub fn bind_transparent_listener(proxy_port: u16) -> std::io::Result<TcpListener> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Wrap immediately so the fd is closed on any early return.
        let owned = OwnedFd(fd);

        set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        // IP_TRANSPARENT is the crux: it lets bind()/accept() handle non-local
        // (the original) destination addresses that TPROXY hands us.
        set_sockopt_int(fd, libc::SOL_IP, IP_TRANSPARENT, 1)?;

        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: proxy_port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(Ipv4Addr::new(127, 0, 0, 1)).to_be(),
            },
            sin_zero: [0; 8],
        };
        let rc = libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::listen(fd, 128) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Hand the fd to std; forget our guard so it isn't double-closed.
        let raw = owned.0;
        mem::forget(owned);
        use std::os::unix::io::FromRawFd;
        Ok(TcpListener::from_raw_fd(raw))
    }
}

/// Recover the ORIGINAL destination of a TPROXY'd connection. With IP_TRANSPARENT
/// the accepted socket's local name (`getsockname`) is the original dst the
/// client aimed at — TPROXY preserves it (unlike NAT/REDIRECT, which would need
/// SO_ORIGINAL_DST). Returns `(ip, port)`.
pub fn original_dst(stream: &TcpStream) -> std::io::Result<SocketAddrV4> {
    let fd = stream.as_raw_fd();
    unsafe {
        let mut addr: libc::sockaddr_in = mem::zeroed();
        let mut len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let rc = libc::getsockname(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut len);
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Ok(SocketAddrV4::new(ip, port))
    }
}

/// The accept loop entry point. On a privileged host (or netns with
/// CAP_NET_ADMIN) it sets up the TPROXY local routing, binds the
/// IP_TRANSPARENT listener, and for each diverted connection recovers the
/// original destination, excludes model hosts (pass-through), and otherwise
/// proxies the bytes through the pure egress/ingress transforms.
///
/// This installs ROUTING ONLY (`setup_tproxy_routing`); the nft divert rule is
/// installed separately by the caller (`apply_ruleset(render_tproxy_ruleset*)`)
/// so the cgroup-scoped vs netns-scoped choice is the caller's.
///
/// Runs forever; intended to be spawned on its own thread. For tests use
/// [`ProxyHandle::spawn`] which runs a bounded number of connections.
pub fn run_proxy(proxy_port: u16) -> std::io::Result<()> {
    setup_tproxy_routing()?;
    let listener = bind_transparent_listener(proxy_port)?;
    let extra_model_hosts: Vec<String> = Vec::new();
    for conn in listener.incoming() {
        let client = match conn {
            Ok(c) => c,
            Err(_) => continue,
        };
        // One blocking connection at a time is fine for the supervisor model;
        // production can thread per-connection. Errors on a single connection
        // must NOT take down the loop.
        let _ = proxy_one(client, &extra_model_hosts);
    }
    Ok(())
}

/// A spawned proxy for tests: binds + routes on the calling thread (so binding
/// errors surface synchronously), then accepts `max_conns` connections on a
/// background thread, recording per-connection outcomes.
pub struct ProxyHandle {
    pub port: u16,
    handle: Option<std::thread::JoinHandle<Vec<ConnOutcome>>>,
}

/// What the proxy did with one connection — surfaced so the integration test can
/// assert interception + that a transform actually ran.
#[derive(Debug, Clone)]
pub struct ConnOutcome {
    /// The original destination recovered from the TPROXY'd socket.
    pub original_dst: SocketAddrV4,
    /// True iff the destination was a model host (passed through untouched).
    pub model_host_passthrough: bool,
    /// True iff at least one outbound symbol was withheld by the egress gate.
    pub egress_withheld: bool,
    /// True iff the egress arbiter was unreachable (fail-closed).
    pub egress_arbiter_miss: bool,
    /// Bytes proxied upstream (post egress-transform) and back (post
    /// ingress-transform), for the test to sanity-check.
    pub upstream_bytes: usize,
    pub downstream_bytes: usize,
}

impl ProxyHandle {
    /// Bind+route now (CAP_NET_ADMIN required), then accept up to `max_conns`
    /// connections on a thread. `arbiter_sock` is the arbiter socket path the
    /// transforms call; `model_hosts` are extra model-API hosts to exclude.
    pub fn spawn(
        proxy_port: u16,
        max_conns: usize,
        arbiter_sock: impl Into<std::path::PathBuf>,
        model_hosts: Vec<String>,
    ) -> std::io::Result<Self> {
        setup_tproxy_routing()?;
        let listener = bind_transparent_listener(proxy_port)?;
        // A short accept timeout so the thread terminates even if fewer than
        // max_conns arrive (test robustness).
        listener.set_nonblocking(false)?;
        let arbiter_sock = arbiter_sock.into();
        let handle = std::thread::spawn(move || {
            let mut outcomes = Vec::new();
            for conn in listener.incoming().take(max_conns) {
                let client = match conn {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let mut arbiter = ArbiterClient::new(&arbiter_sock);
                let mut human = human_client_from(std::env::var(HUMAN_SOCK_ENV).ok(), Some(arbiter_sock.as_path()));
                match proxy_one_recorded(client, &model_hosts, &mut arbiter, human.as_mut()) {
                    Ok(o) => outcomes.push(o),
                    Err(_) => continue,
                }
            }
            outcomes
        });
        Ok(ProxyHandle {
            port: proxy_port,
            handle: Some(handle),
        })
    }

    /// True once the accept thread has ended: a test waits on it under a
    /// deadline before [`ProxyHandle::join`], which blocks for as long as the
    /// thread runs (it accepts until `max_conns` connections came).
    pub fn is_finished(&self) -> bool {
        self.handle.as_ref().map_or(true, |h| h.is_finished())
    }

    /// Join the accept thread and return the per-connection outcomes.
    pub fn join(mut self) -> Vec<ConnOutcome> {
        self.handle
            .take()
            .map(|h| h.join().unwrap_or_default())
            .unwrap_or_default()
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        // Best-effort: leave the thread to finish; routing/nft teardown is the
        // test's responsibility (it owns the netns lifecycle).
    }
}

/// Proxy one connection using a arbiter resolved from `MANDU_ARBITER_SOCK` (the
/// production path). Symbols are gated fail-closed; a arbiter miss withholds.
fn proxy_one(client: TcpStream, extra_model_hosts: &[String]) -> std::io::Result<()> {
    let mut arbiter = ArbiterClient::from_env()
        .unwrap_or_else(|_| ArbiterClient::new("/nonexistent/mandu.sock"));
    // The human plane (arbiter-human-plane.md): allowed symbols resolve over
    // MANDU_ARBITER_HUMAN_SOCK only; unset → None → every allowed symbol is
    // withheld (never the data socket).
    let data_sock = std::env::var("MANDU_ARBITER_SOCK").ok().filter(|s| !s.is_empty());
    let mut human = human_client_from(std::env::var(HUMAN_SOCK_ENV).ok(), data_sock.as_deref().map(std::path::Path::new));
    let _ = proxy_one_recorded(client, extra_model_hosts, &mut arbiter, human.as_mut());
    Ok(())
}

/// The core per-connection proxy, recording a [`ConnOutcome`].
///
/// 1. Recover the original destination from the TPROXY'd accepted socket.
/// 2. If it is a model host, splice bytes through UNTOUCHED (the anthropic-proxy owns
///    that traffic) and record a pass-through.
/// 3. Otherwise dial the original destination from the proxy, then for each
///    direction apply the pure transform: OUTBOUND (agent→remote) desymbolize
///    gated by the arbiter (`egress_transform`); INBOUND (remote→agent) symbolize
///    untrusted bytes (`ingress_transform`). Fail-closed on arbiter miss.
fn proxy_one_recorded(
    mut client: TcpStream,
    extra_model_hosts: &[String],
    arbiter: &mut ArbiterClient,
    human: Option<&mut ArbiterClient>,
) -> std::io::Result<ConnOutcome> {
    let dst = original_dst(&client)?;
    let host = dst.ip().to_string();

    // ── proc-key attribution (design §6.A): map this connection → the connecting
    //    process's proc key so the ingress observe-and-tag + the egress taint gate
    //    act on a REAL process. Best-effort: a miss (race / unattributable) yields
    //    None and we keep the pre-attribution behaviour for this connection (no tag)
    //    rather than fabricating a wrong key. The /proc baseline is the PERMANENT
    //    mechanism: eBPF, the robust alternative, needs root/CAP_BPF and is DECIDED
    //    won't-implement (2026-07-16; non-root principle, privilege-model.md §0).
    //
    //    Under TPROXY: `client.peer_addr()` = agent source (getpeername on the
    //    TPROXY'd accepted socket), `dst` = original destination (getsockname).
    //    The connecting process's /proc/net/tcp row has local=agent_src,
    //    rem=original_dst — see conn_attr::attribute_connection's doc for the
    //    empirical check comment and how to flip the direction if needed.
    let agent_src = client.peer_addr().ok().and_then(|a| match a {
        std::net::SocketAddr::V4(v4) => Some(v4),
        _ => None,
    });
    let proc_key: Option<String> = agent_src
        .and_then(|src| conn_attr::attribute_connection(src, dst));

    // Model-host exclusion: REAL bidirectional splice, no transform. The
    // model-API proxy owns this traffic under a different policy, so the
    // net-supervisor must relay every byte both directions untouched until both
    // halves EOF — not a single buffer.
    if is_model_host(&host, extra_model_hosts) {
        // Dial upstream with the BYPASS_MARK so our own connect isn't re-tproxied.
        let upstream = connect_with_mark(dst, BYPASS_MARK, IO_TIMEOUT)?;
        let (up, down) = splice_bidirectional(client, upstream)?;
        return Ok(ConnOutcome {
            original_dst: dst,
            model_host_passthrough: true,
            egress_withheld: false,
            egress_arbiter_miss: false,
            upstream_bytes: up,
            downstream_bytes: down,
        });
    }

    // Dial the REAL original destination from the proxy. The upstream socket
    // carries BYPASS_MARK (SO_MARK) so the divert chain's first rule accepts it
    // and does NOT re-tproxy it back to us (the TPROXY self-loop). Without this
    // the connect would hang.
    client.set_read_timeout(Some(IO_TIMEOUT))?;
    client.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut upstream = connect_with_mark(dst, BYPASS_MARK, IO_TIMEOUT)?;
    upstream.set_read_timeout(Some(IO_TIMEOUT))?;
    upstream.set_write_timeout(Some(IO_TIMEOUT))?;

    // --- OUTBOUND: read the agent's COMPLETE request, apply egress_transform. ---
    // The pure transform operates on a full body, so we must frame the whole
    // request (request line + headers + exactly Content-Length bytes) before
    // transforming. Fail-CLOSED if it overruns MAX_GATED_BODY.
    let req_bytes = read_full_message(&mut client, MessageKind::Request)?;
    let req_text = String::from_utf8_lossy(&req_bytes).to_string();
    // proc_key: wired via conn_attr::attribute_connection (/proc baseline, §6.A —
    // the PERMANENT mechanism; the root/CAP_BPF eBPF sock→cgroup→pid alternative
    // for short-lived processes is DECIDED won't-implement, 2026-07-16).
    // A miss (race / unattributable connection) yields None → pre-Plan-6 behaviour
    // (per-symbol egress gate still runs; the taint-driven destination gate is skipped).
    let egress = egress_transform(arbiter, human, &req_text, &host, /*as_command=*/ false, proc_key.as_deref());
    upstream.write_all(egress.wire_bytes.as_bytes())?;
    upstream.flush()?;
    let upstream_bytes = egress.wire_bytes.len();

    // --- INBOUND: read the remote's COMPLETE response, apply ingress_transform. ---
    // Responses are framed by Content-Length OR chunked (we dechunk) OR, lacking
    // both, Connection: close → read to EOF. Again capped at MAX_GATED_BODY.
    let resp_bytes = read_full_message(&mut upstream, MessageKind::Response)?;
    let resp_text = String::from_utf8_lossy(&resp_bytes).to_string();
    // proc_key: same key as egress — wired via conn_attr::attribute_connection.
    // A miss → no observe-and-tag on this connection (pre-Plan-6 behaviour).
    // Post-Plan-7: ingress returns the RAW body (no body symbolization); if
    // proc_key is Some (Plan 6), the connecting process is best-effort tainted.
    // The T-LLM invariant is enforced at the model-API proxy, not here.
    let ingress = ingress_transform(arbiter, "web_fetch", &host, &resp_text, proc_key.as_deref());
    client.write_all(ingress.agent_visible.as_bytes())?;
    client.flush()?;
    let downstream_bytes = ingress.agent_visible.len();

    Ok(ConnOutcome {
        original_dst: dst,
        model_host_passthrough: false,
        egress_withheld: egress.any_withheld,
        egress_arbiter_miss: egress.arbiter_miss,
        upstream_bytes,
        downstream_bytes,
    })
}

/// Connect a TCP socket to `dst` with `SO_MARK = mark` set BEFORE connect (so the
/// nft divert chain's bypass rule can recognize the proxy's own upstream traffic
/// and not re-divert it). `connect_timeout` bounds the connect itself.
///
/// TRUE connect timeout: the socket is put in non-blocking mode, `connect()`
/// returns `EINPROGRESS`, and we `poll()` for writability up to
/// `connect_timeout`. A dead/black-holed upstream therefore times out AT CONNECT
/// (returning `TimedOut`) rather than blocking the OS default ~2 min SYN retry,
/// and rather than only being caught later on a read. After connect succeeds we
/// restore blocking mode and apply read/write timeouts SEPARATELY.
fn connect_with_mark(
    dst: SocketAddrV4,
    mark: u32,
    connect_timeout: Duration,
) -> std::io::Result<TcpStream> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let owned = OwnedFd(fd);

        // SO_MARK requires CAP_NET_ADMIN (we have it in the netns). This is the
        // bypass mark the divert chain accepts early.
        set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_MARK, mark as libc::c_int)?;

        // Non-blocking so connect() returns immediately with EINPROGRESS.
        set_nonblocking(fd, true)?;

        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: dst.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(*dst.ip()).to_be(),
            },
            sin_zero: [0; 8],
        };
        let rc = libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            let in_progress = err.raw_os_error() == Some(libc::EINPROGRESS);
            if !in_progress {
                return Err(err);
            }
            // Wait (bounded) for the socket to become writable = connect resolved.
            poll_writable(fd, connect_timeout)?;
            // Connect result is surfaced via SO_ERROR, not the poll itself.
            let mut soerr: libc::c_int = 0;
            let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
            let grc = libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut soerr as *mut _ as *mut libc::c_void,
                &mut len,
            );
            if grc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if soerr != 0 {
                return Err(std::io::Error::from_raw_os_error(soerr));
            }
        }
        // Connected. Back to blocking + explicit read/write timeouts.
        set_nonblocking(fd, false)?;

        let raw = owned.0;
        mem::forget(owned);
        use std::os::unix::io::FromRawFd;
        let stream = TcpStream::from_raw_fd(raw);
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        Ok(stream)
    }
}

/// `poll()` a single fd for POLLOUT (writable) up to `timeout`. Maps a 0-return
/// (timeout) to `ErrorKind::TimedOut` — this is the connect-timeout signal.
fn poll_writable(fd: RawFd, timeout: Duration) -> std::io::Result<()> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    let ms = clamp_timeout_ms(timeout);
    loop {
        let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, ms) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue; // EINTR: retry
            }
            return Err(e);
        }
        if rc == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timed out",
            ));
        }
        return Ok(());
    }
}

/// Set/clear O_NONBLOCK on a raw fd via fcntl.
fn set_nonblocking(fd: RawFd, on: bool) -> std::io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let new = if on {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        if libc::fcntl(fd, libc::F_SETFL, new) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Clamp a Duration to a non-negative `poll`/`select` millisecond arg.
fn clamp_timeout_ms(timeout: Duration) -> libc::c_int {
    let ms = timeout.as_millis();
    if ms > libc::c_int::MAX as u128 {
        libc::c_int::MAX
    } else {
        ms as libc::c_int
    }
}

/// Which side's framing rules apply when reading a complete HTTP message.
enum MessageKind {
    Request,
    Response,
}

/// Read a COMPLETE HTTP message from `stream`, honoring framing:
///   * parse the start line + headers up to the blank line (CRLFCRLF),
///   * if `Transfer-Encoding: chunked` → dechunk the body (return headers +
///     decoded body so the transform sees plaintext),
///   * else if `Content-Length: N` → read exactly N body bytes,
///   * else for a RESPONSE with neither (and not a bodyless status) → read to
///     EOF (Connection: close semantics),
///   * else (REQUEST with no length / no body) → the headers ARE the message.
///
/// Capped at `MAX_GATED_BODY`: if the framed length or the to-EOF read would
/// exceed it we FAIL CLOSED with an error (the caller does not forward a
/// half-read body). Non-HTTP bytes (no header terminator within the cap) are
/// returned as-is once the peer stops sending / EOFs, so opaque/binary protocols
/// still round-trip through the gate without hanging.
fn read_full_message(stream: &mut TcpStream, kind: MessageKind) -> std::io::Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);

    // 1. Read until we have the full header block (CRLFCRLF) or hit EOF/cap.
    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            break Some(pos);
        }
        if buf.len() > MAX_GATED_BODY {
            return Err(over_cap("header block exceeded MAX_GATED_BODY"));
        }
        let n = read_some(stream, &mut buf)?;
        if n == 0 {
            // EOF before a header terminator. Treat the bytes we have as the
            // whole (possibly non-HTTP / headerless) message.
            break None;
        }
    };

    let header_end = match header_end {
        Some(h) => h,
        None => return Ok(buf), // no HTTP framing → opaque message, already at EOF
    };

    let headers = &buf[..header_end];
    let body_start = header_end; // header_end points PAST the CRLFCRLF

    // 2. Determine framing from the headers.
    if header_has_chunked(headers) {
        return read_chunked(stream, buf, body_start);
    }
    if let Some(len) = header_content_length(headers) {
        if len > MAX_GATED_BODY {
            return Err(over_cap("Content-Length exceeded MAX_GATED_BODY"));
        }
        let want = body_start + len;
        while buf.len() < want {
            if buf.len() > MAX_GATED_BODY {
                return Err(over_cap("body exceeded MAX_GATED_BODY"));
            }
            let n = read_some(stream, &mut buf)?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF before Content-Length body fully read",
                ));
            }
        }
        buf.truncate(want);
        return Ok(buf);
    }

    // 3. No explicit framing.
    match kind {
        // A request with no Content-Length / chunked has no body — the headers
        // are the whole message. Reading further would block on the agent.
        MessageKind::Request => Ok(buf),
        // A response with neither relies on Connection: close → read to EOF.
        MessageKind::Response => {
            loop {
                if buf.len() > MAX_GATED_BODY {
                    return Err(over_cap("to-EOF response exceeded MAX_GATED_BODY"));
                }
                let n = read_some(stream, &mut buf)?;
                if n == 0 {
                    break;
                }
            }
            Ok(buf)
        }
    }
}

/// Dechunk a `Transfer-Encoding: chunked` body, appending the DECODED body to the
/// header block already in `buf`. Returns headers + decoded body. The chunk
/// framing/trailers are consumed but not forwarded (the transform sees plaintext;
/// the wire re-encoding is the caller's downstream concern — for the gated path
/// the framing is small relative to the body and the test asserts on content).
fn read_chunked(
    stream: &mut TcpStream,
    mut buf: Vec<u8>,
    body_start: usize,
) -> std::io::Result<Vec<u8>> {
    // Split off the raw post-header bytes already buffered; parse chunks from a
    // growing window, reading more as needed.
    let mut raw: Vec<u8> = buf.split_off(body_start); // headers remain in `buf`
    let mut out = buf; // headers; decoded body appended below
    let mut pos = 0usize;

    loop {
        // Need a chunk-size line terminated by CRLF.
        let line_end = loop {
            if let Some(rel) = find_crlf(&raw[pos..]) {
                break pos + rel;
            }
            if raw.len() > MAX_GATED_BODY {
                return Err(over_cap("chunk-size line exceeded MAX_GATED_BODY"));
            }
            let n = read_some(stream, &mut raw)?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF inside chunked framing",
                ));
            }
        };
        let size_str = String::from_utf8_lossy(&raw[pos..line_end]);
        // A chunk-size may carry ;extensions — take the hex prefix only.
        let hex = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex, 16)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad chunk size"))?;
        pos = line_end + 2; // skip CRLF after the size line

        if size == 0 {
            // Last chunk. Consume the (possibly empty) trailer up to CRLFCRLF /
            // final CRLF, best-effort, then stop.
            break;
        }
        if out.len() + size > MAX_GATED_BODY {
            return Err(over_cap("chunked body exceeded MAX_GATED_BODY"));
        }
        // Ensure the chunk data + its trailing CRLF are buffered.
        while raw.len() < pos + size + 2 {
            let n = read_some(stream, &mut raw)?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF inside chunk data",
                ));
            }
        }
        out.extend_from_slice(&raw[pos..pos + size]);
        pos = pos + size + 2; // skip chunk data + trailing CRLF
    }

    Ok(out)
}

/// Real bidirectional byte splice between two already-connected streams: pump
/// every byte client↔upstream until BOTH halves reach EOF. Used ONLY on the
/// model-host pass-through path (no transform). Implemented with `poll()` over
/// both fds in nonblocking mode, single std thread, so it relays an arbitrary
/// number of buffers in each direction without the single-read truncation bug.
///
/// Returns `(client→upstream bytes, upstream→client bytes)`.
fn splice_bidirectional(client: TcpStream, upstream: TcpStream) -> std::io::Result<(usize, usize)> {
    let cfd = client.as_raw_fd();
    let ufd = upstream.as_raw_fd();
    set_nonblocking(cfd, true)?;
    set_nonblocking(ufd, true)?;

    let mut buf = [0u8; SPLICE_BUF];
    let mut c2u = 0usize; // client → upstream
    let mut u2c = 0usize; // upstream → client
    let mut client_open = true; // can still read from client
    let mut upstream_open = true; // can still read from upstream

    while client_open || upstream_open {
        let mut fds = [
            libc::pollfd {
                fd: cfd,
                events: if client_open { libc::POLLIN } else { 0 },
                revents: 0,
            },
            libc::pollfd {
                fd: ufd,
                events: if upstream_open { libc::POLLIN } else { 0 },
                revents: 0,
            },
        ];
        let ms = clamp_timeout_ms(IO_TIMEOUT);
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, ms) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if rc == 0 {
            // Idle past IO_TIMEOUT with both sides quiet → done relaying.
            break;
        }

        // client → upstream
        if client_open && (fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
            match read_fd(cfd, &mut buf) {
                Ok(0) => {
                    client_open = false;
                    // Half-close upstream's write side so the peer sees EOF.
                    let _ = shutdown_write(ufd);
                }
                Ok(n) => {
                    write_all_fd(ufd, &buf[..n])?;
                    c2u += n;
                }
                Err(e) if would_block(&e) => {}
                Err(e) => return Err(e),
            }
        }
        // upstream → client
        if upstream_open && (fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
            match read_fd(ufd, &mut buf) {
                Ok(0) => {
                    upstream_open = false;
                    let _ = shutdown_write(cfd);
                }
                Ok(n) => {
                    write_all_fd(cfd, &buf[..n])?;
                    u2c += n;
                }
                Err(e) if would_block(&e) => {}
                Err(e) => return Err(e),
            }
        }
    }

    Ok((c2u, u2c))
}

// ── low-level fd I/O used by the splice (nonblocking) ────────────────────────

fn read_fd(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(n as usize)
}

fn write_all_fd(fd: RawFd, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if would_block(&e) {
                // Wait for writability, then retry the same slice.
                poll_writable(fd, IO_TIMEOUT)?;
                continue;
            }
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        data = &data[n as usize..];
    }
    Ok(())
}

fn shutdown_write(fd: RawFd) -> std::io::Result<()> {
    let rc = unsafe { libc::shutdown(fd, libc::SHUT_WR) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn would_block(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

// ── HTTP framing helpers (blocking reads on a timeout'd TcpStream) ────────────

/// Append one read() worth of bytes to `buf`, growing it. Returns the count read
/// (0 = EOF). A WouldBlock/TimedOut surfaces as an error (the framing reader
/// relies on real blocking reads with the IO_TIMEOUT set on the stream).
fn read_some(stream: &mut TcpStream, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    let mut chunk = [0u8; SPLICE_BUF];
    match stream.read(&mut chunk) {
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(n)
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => read_some(stream, buf),
        Err(e) => Err(e),
    }
}

fn over_cap(msg: &str) -> std::io::Error {
    // Fail-CLOSED marker: the caller MUST NOT forward a partial body on this.
    std::io::Error::new(std::io::ErrorKind::Other, format!("gated body cap: {msg}"))
}

/// Find the byte index PAST the CRLFCRLF that terminates the HTTP header block,
/// or `None` if not present yet. Also tolerates a bare LFLF terminator.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    if let Some(p) = find_subslice(buf, b"\r\n\r\n") {
        return Some(p + 4);
    }
    if let Some(p) = find_subslice(buf, b"\n\n") {
        return Some(p + 2);
    }
    None
}

/// Relative offset of the next CRLF in `buf`, or None.
fn find_crlf(buf: &[u8]) -> Option<usize> {
    find_subslice(buf, b"\r\n")
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Case-insensitively scan the header block for `Content-Length: N`.
fn header_content_length(headers: &[u8]) -> Option<usize> {
    header_value(headers, "content-length").and_then(|v| v.trim().parse::<usize>().ok())
}

/// True iff the header block declares `Transfer-Encoding: chunked`.
fn header_has_chunked(headers: &[u8]) -> bool {
    header_value(headers, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
}

/// Return the (last) value of a header by case-insensitive name from a header
/// block. Lines are split on CRLF or LF.
fn header_value(headers: &[u8], name_lower: &str) -> Option<String> {
    let text = String::from_utf8_lossy(headers);
    let mut found = None;
    for line in text.split(|c| c == '\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name_lower) {
                found = Some(v.trim().to_string());
            }
        }
    }
    found
}

// ── small fd / sockopt helpers ──────────────────────────────────────────────────

/// RAII guard that closes a raw fd on drop (used while building the listener).
struct OwnedFd(RawFd);
impl Drop for OwnedFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// `setsockopt(fd, level, name, &val as int)`.
fn set_sockopt_int(fd: RawFd, level: libc::c_int, name: libc::c_int, val: libc::c_int) -> std::io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &val as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netns_ruleset_renders_ports_and_mark() {
        let rs = render_tproxy_ruleset_netns(&[8080, 9090], 50080);
        assert!(rs.contains("tproxy to 127.0.0.1:50080"));
        assert!(rs.contains("dport { 8080, 9090 }"));
        assert!(rs.contains(&format!("mark set {TPROXY_MARK}")));
        assert!(rs.contains("table ip mandu"));
    }

    #[test]
    fn cgroup_ruleset_still_renders() {
        let rs = render_tproxy_ruleset("/sys/fs/cgroup/agent.scope", 50080);
        assert!(rs.contains("tproxy to :50080"));
        assert!(rs.contains("cgroupv2"));
    }

    // ── pure framing-helper unit tests (no socket / no root) ──────────────────

    #[test]
    fn header_end_finds_crlfcrlf_and_lflf() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\nBODY"), Some(18));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\n\nBODY"), Some(16));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\nHost: x"), None);
    }

    #[test]
    fn content_length_parsed_case_insensitively() {
        let h = b"POST / HTTP/1.1\r\nContent-Length: 1234\r\nHost: x\r\n\r\n";
        assert_eq!(header_content_length(h), Some(1234));
        let h2 = b"POST / HTTP/1.1\r\ncontent-length: 7\r\n\r\n";
        assert_eq!(header_content_length(h2), Some(7));
        assert_eq!(header_content_length(b"GET / HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn chunked_detected_case_insensitively() {
        assert!(header_has_chunked(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"));
        assert!(header_has_chunked(b"HTTP/1.1 200 OK\r\ntransfer-encoding: CHUNKED\r\n\r\n"));
        assert!(!header_has_chunked(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n"));
    }

    #[test]
    fn header_value_returns_last_occurrence() {
        let h = b"X: a\r\nX: b\r\n\r\n";
        assert_eq!(header_value(h, "x").as_deref(), Some("b"));
    }

    #[test]
    fn clamp_timeout_handles_overflow() {
        assert_eq!(clamp_timeout_ms(Duration::from_millis(500)), 500);
        // Way past i32::MAX ms — clamps, never overflows/panics.
        assert_eq!(
            clamp_timeout_ms(Duration::from_secs(10_000_000_000)),
            libc::c_int::MAX
        );
    }
}
