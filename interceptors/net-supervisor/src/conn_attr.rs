//! conn_attr — map a TCP connection (local+remote endpoint) to the connecting
//! process's proc key, the load-bearing socket→process attribution (design §6.A).
//!
//! BASELINE = `/proc` scan (this module): parse `/proc/net/tcp{,6}` to map the
//! connection's 4-tuple → the socket INODE, then scan `/proc/<pid>/fd/*` for a
//! `socket:[inode]` symlink to find the owning pid, then `proc_key_for_pid`. This
//! is privilege-free to PARSE (pure string math, unit-tested on fixtures) and
//! privilege-free to READ live (`/proc/net/tcp` + our own/again-readable fds), but
//! the LIVE scan + the kernel accept-loop wiring is `#[cfg(feature = "kernel")]`
//! (it belongs to the TPROXY path) + `#[ignore]`d (needs a real connection).
//!
//! HONEST LIMITS (design §6.A): the `/proc` scan RACES short-lived processes (the
//! connection may be gone from `/proc/net/tcp`, or the fd closed, before we scan)
//! and is O(#fds). This baseline is the PERMANENT mechanism: eBPF (sock→cgroup→pid,
//! attached at connect) would be robust against the race, but it needs root/CAP_BPF
//! on the host and is DECIDED — WILL NOT IMPLEMENT (2026-07-16; permanently out of
//! scope under the non-root principle, privilege-model.md §0 — not deferred work).
//! On attribution failure we return `None`; the
//! caller then keeps TODAY's behaviour (no supplementary tag on this connection) —
//! explicitly weaker than the eBPF "taint the whole invocation" escalation (also
//! out of scope with it), and documented as such. We never fabricate a wrong key.
//!
//! TPROXY endpoint-direction note (critical for the match): under TPROXY the
//! accepted socket's `getsockname` = original destination, `getpeername` = agent
//! source. The connecting process's `/proc/net/tcp` row has local = agent_src and
//! rem = original_dst. So `attribute_connection` takes `(agent_src, original_dst)`
//! and matches the row where `(local == agent_src) AND (rem == original_dst)`.
//! The `#[ignore]`d integration test in `tests/kernel_integration.rs` (function
//! `attribute_connection_resolves_own_socket_to_self_proc_key`) is the empirical
//! check — if the live test fails due to swapped endpoints, flip the comparison in
//! `attribute_connection` (not the test).

use std::net::Ipv4Addr;

/// A parsed `/proc/net/tcp` row (the fields we need for attribution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcNetTcpRow {
    pub local_ip: [u8; 4],
    pub local_port: u16,
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
    pub inode: u64,
}

/// Parse ONE `/proc/net/tcp` data line into a row. Returns `None` for the header
/// line, a blank line, or any line missing the fields we need. PURE (no I/O).
///
/// Line shape (whitespace-separated):
///   sl: local_address rem_address st tx:rx tr tm->when retrnsmt uid timeout inode ...
/// `local_address`/`rem_address` are `HHHHHHHH:PPPP` (IP hex little-endian per
/// 32-bit word, port hex big-endian). `inode` is the 10th token AFTER the `sl:`.
pub fn parse_proc_net_tcp_line(line: &str) -> Option<ProcNetTcpRow> {
    let mut toks = line.split_whitespace();
    let sl = toks.next()?; // "0:" — the slot index; the header's first tok is "sl"
    if !sl.ends_with(':') {
        return None; // header / garbage
    }
    let local = toks.next()?;
    let remote = toks.next()?;
    let _st = toks.next()?;        // connection state (hex)
    let _txrx = toks.next()?;     // tx_queue:rx_queue (one token, colon-joined)
    let _tr_tmwhen = toks.next()?; // tr:tm->when (one token, colon-joined)
    let _retrnsmt = toks.next()?; // retransmit count
    let _uid = toks.next()?;      // owner uid
    let _timeout = toks.next()?;  // probe timeout
    let inode = toks.next()?.parse::<u64>().ok()?; // socket inode

    let (local_ip, local_port) = parse_hex_endpoint_v4(local)?;
    let (remote_ip, remote_port) = parse_hex_endpoint_v4(remote)?;
    Some(ProcNetTcpRow {
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        inode,
    })
}

/// Parse a `HHHHHHHH:PPPP` IPv4 endpoint from `/proc/net/tcp`. The IP is a 32-bit
/// word in HOST (little-endian) byte order, so the dotted quad is the bytes
/// reversed; the port is big-endian hex. Returns `([a,b,c,d], port)`.
fn parse_hex_endpoint_v4(s: &str) -> Option<([u8; 4], u16)> {
    let (ip_hex, port_hex) = s.split_once(':')?;
    if ip_hex.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(ip_hex, 16).ok()?;
    // /proc/net/tcp stores the address as a little-endian 32-bit word, so the
    // network-order octets are the LE bytes of `raw`.
    let ip = Ipv4Addr::from(raw.swap_bytes());
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((ip.octets(), port))
}

/// Extract the inode from a `/proc/<pid>/fd/<n>` socket symlink target
/// (`socket:[12345]`). `None` for non-socket targets (files/pipes/anon_inode).
pub fn inode_from_socket_link(target: &str) -> Option<u64> {
    let inner = target.strip_prefix("socket:[")?.strip_suffix(']')?;
    if inner.is_empty() {
        return None;
    }
    inner.parse::<u64>().ok()
}

/// Given an iterator of `(pid, fd_symlink_target)` pairs, return the FIRST pid that
/// owns a `socket:[inode]` fd matching `inode`. PURE (the caller supplies the fd
/// table — production scans `/proc/*/fd/*` live; tests pass a fixture).
pub fn pid_for_inode<'a, I>(inode: u64, fds: I) -> Option<i32>
where
    I: IntoIterator<Item = (i32, &'a str)>,
{
    for (pid, target) in fds {
        if inode_from_socket_link(target) == Some(inode) {
            return Some(pid);
        }
    }
    None
}

// ── LIVE scan + kernel wiring (privileged path: belongs to the TPROXY loop) ──
#[cfg(feature = "kernel")]
mod live {
    use super::*;
    use mandu_arbiter::proc::proc_key_for_pid;
    use std::fs;
    use std::net::SocketAddrV4;

    /// Scan `/proc/net/tcp` (+ `tcp6`) for the row whose endpoints match the given
    /// connection, then resolve its inode → owning pid → proc key. Returns `None`
    /// on any miss (no matching row, no owning fd, race) — the caller keeps the
    /// pre-Plan-6 behaviour (no tag) rather than fabricating a wrong key.
    ///
    /// Attribution direction: from the PROXY's view of an accepted connection, the
    /// AGENT's socket is the REMOTE end of OUR accepted socket — but with TPROXY the
    /// accepted socket's getpeername is the agent's source addr:port and getsockname
    /// is the ORIGINAL destination. The connecting process's entry in
    /// `/proc/net/tcp` has local = agent_src and rem = original_dst. So we match the
    /// row by (local == agent_src) AND (rem == original_dst). The caller passes both.
    ///
    /// EMPIRICAL CHECK: the `#[ignore]`d test
    /// `attribute_connection_resolves_own_socket_to_self_proc_key` in
    /// `tests/kernel_integration.rs` confirms this direction against a live socket.
    /// If the test fails due to swapped endpoints, flip the `want_local`/`want_rem`
    /// comparison here (not in the test).
    pub fn attribute_connection(
        agent_src: SocketAddrV4,
        original_dst: SocketAddrV4,
    ) -> Option<String> {
        let want_local = (agent_src.ip().octets(), agent_src.port());
        let want_rem = (original_dst.ip().octets(), original_dst.port());

        let inode = scan_tcp_files()?
            .into_iter()
            .find(|r| {
                (r.local_ip, r.local_port) == want_local
                    && (r.remote_ip, r.remote_port) == want_rem
            })
            .map(|r| r.inode)?;

        let pid = scan_fd_owner(inode)?;
        proc_key_for_pid(pid)
    }

    /// Read + parse `/proc/net/tcp` and `/proc/net/tcp6`. (tcp6 lines have a 32-hex
    /// IP; `parse_proc_net_tcp_line` keys on token positions, so a v4-mapped v6
    /// endpoint still parses its inode — endpoint match may miss for true v6, an
    /// accepted limitation of the /proc baseline.)
    fn scan_tcp_files() -> Option<Vec<ProcNetTcpRow>> {
        let mut rows = Vec::new();
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(text) = fs::read_to_string(path) {
                for line in text.lines() {
                    if let Some(r) = parse_proc_net_tcp_line(line) {
                        rows.push(r);
                    }
                }
            }
        }
        Some(rows)
    }

    /// Scan `/proc/<pid>/fd/*` for the first pid owning `socket:[inode]`.
    fn scan_fd_owner(inode: u64) -> Option<i32> {
        let proc = fs::read_dir("/proc").ok()?;
        for ent in proc.flatten() {
            let name = ent.file_name();
            let pid: i32 = match name.to_str().and_then(|s| s.parse().ok()) {
                Some(p) => p,
                None => continue, // not a pid dir
            };
            // A table an exec in progress hides is read once the exec ends
            // (2026-10-17, `pipe_flow::fd_table`); unreadable otherwise:
            // skipped, as before (no attribution, never a wrong one).
            if crate::pipe_flow::fd_table(pid).iter().any(|h| inode_from_socket_link(&h.link) == Some(inode)) {
                return Some(pid);
            }
        }
        None
    }
}

#[cfg(feature = "kernel")]
pub use live::attribute_connection;

#[cfg(test)]
mod tests {
    use super::*;

    // A real `/proc/net/tcp` line. Columns:
    //   sl  local_address rem_address st ... inode ...
    // local/rem are HEX `IP:PORT` with IP little-endian per 32-bit word.
    // Here local = 127.0.0.1:80 (0100007F:0050), rem = 127.0.0.1:54321
    // (0100007F:D431), state 01 (ESTABLISHED), inode = 123456 (the 10th field,
    // index 9 after the leading "sl:").
    const TCP_LINE: &str = "   0: 0100007F:0050 0100007F:D431 01 00000000:00000000 \
        00:00000000 00000000  1000        0 123456 1 0000000000000000 100 0 0 10 0";

    #[test]
    fn parse_tcp_line_extracts_endpoints_and_inode() {
        let row = parse_proc_net_tcp_line(TCP_LINE).expect("parses");
        assert_eq!(row.local_port, 80);
        assert_eq!(row.remote_port, 0xD431);
        assert_eq!(row.inode, 123456);
        // IPv4 little-endian word 0100007F → 127.0.0.1.
        assert_eq!(row.local_ip, [127, 0, 0, 1]);
        assert_eq!(row.remote_ip, [127, 0, 0, 1]);
    }

    #[test]
    fn parse_tcp_skips_header_and_garbage() {
        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
        assert!(parse_proc_net_tcp_line(header).is_none());
        assert!(parse_proc_net_tcp_line("").is_none());
        assert!(parse_proc_net_tcp_line("   0: notenoughfields").is_none());
    }

    #[test]
    fn match_inode_to_pid_finds_owner() {
        // Synthetic fd table: pid 4242 owns socket:[123456]; pid 99 owns a pipe.
        let fds = vec![
            (4242, "socket:[123456]".to_string()),
            (4242, "/dev/null".to_string()),
            (99, "pipe:[7]".to_string()),
        ];
        assert_eq!(
            pid_for_inode(123456, fds.iter().map(|(p, l)| (*p, l.as_str()))),
            Some(4242)
        );
        assert_eq!(
            pid_for_inode(999, fds.iter().map(|(p, l)| (*p, l.as_str()))),
            None
        );
    }

    #[test]
    fn inode_from_socket_link_parses() {
        assert_eq!(inode_from_socket_link("socket:[123456]"), Some(123456));
        assert_eq!(inode_from_socket_link("socket:[0]"), Some(0));
        assert_eq!(inode_from_socket_link("/dev/null"), None);
        assert_eq!(inode_from_socket_link("pipe:[7]"), None);
        assert_eq!(inode_from_socket_link("socket:[]"), None);
    }
}
