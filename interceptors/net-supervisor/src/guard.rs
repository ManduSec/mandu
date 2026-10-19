//! guard — the PURE, IP/domain-aware egress DECISION for the connect-guard.
//!
//! This is the answer to the "our live kernel net teeth are port-only" gap: the
//! Landlock TCP wrap (`mandu-landlock-apply --net-only`) can only allow/deny by
//! PORT (ABI ≥ 4 has no host/CIDR predicate), so allowing 443 for one destination
//! allows `:443` to EVERY host. This module carries a destination-aware allow-list
//! — protocol × IP / CIDR / hostname × port — that the kernel leg
//! (`guard_kernel`, feature `kernel`) enacts by trapping `connect(2)` via
//! seccomp-unotify, reading the target `sockaddr` out of the tracee, and asking
//! `GuardPolicy::decide`. It is UNPRIVILEGED (the same userns seccomp path the
//! fs-supervisor already uses) and mutates NO global host state — so it lives
//! INSIDE the non-root privilege boundary (privilege-model.md §0), unlike the
//! TPROXY `net-supervisor::kernel` (root + host-global nftables — DECIDED
//! won't-implement 2026-07-16 under the non-root principle, not deferred).
//!
//! WHY A CONNECT CHOKEPOINT SEES ONLY IPs. `connect(2)` carries a `sockaddr` —
//! an IP + port, never a hostname (the agent's `getaddrinfo` already resolved the
//! name). So "domain-aware" here means: a HOSTNAME rule is resolved (by the
//! supplied `HostResolver`) to the IP set it currently maps to, and a connect is
//! allowed iff its IP is in that set. That covers stable-IP services
//! (api.anthropic.com, a corp CIDR) exactly the way IP/CIDR egress allow-lists in
//! the wild do; true SNI/domain identity (and DNS-rebind immunity) needs the
//! TLS-terminating net-proxy (the root+nftables TPROXY layer that could also
//! have provided it is decided won't-implement — privilege-model.md §0) — see
//! the honest bounds in `decide`'s docs and exec-routing.md §7.5.
//!
//! PURE + fail-closed: default-DENY. Everything here is `std`-only, no libc, no
//! syscalls — fully unit-tested on the unprivileged host. `Mandu-new`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Transport protocol a rule (or a live connect) targets. A rule may pin one
/// protocol, or match `Any` (both). The kernel leg learns a connect's protocol
/// from the socket's `SO_TYPE`; the pure tests supply it directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    /// A rule that does not care about the protocol (matches TCP and UDP).
    Any,
    /// A live socket of another transport: an unprivileged ICMP echo socket
    /// (`SOCK_DGRAM` + `IPPROTO_ICMP`, open to every group in Ubuntu's
    /// `ping_group_range`), UDP-Lite, SCTP, a `SOCK_RAW`. Its "port" is not a
    /// port, so only a protocol-agnostic rule covers it: a `udp:*:53` rule
    /// must not admit an ICMP echo carrying data to any host (exec-routing.md
    /// §7.5, "sends", 2026-10-01). Never parsed from a rule.
    Other,
}

impl Proto {
    /// Does a rule for `self` cover a live connect of protocol `other`? `Any` on
    /// either side matches; otherwise they must be equal. A live `Other` is
    /// covered by an `Any` rule only.
    fn covers(self, other: Proto) -> bool {
        matches!(self, Proto::Any) || matches!(other, Proto::Any) || self == other
    }

    /// The protocol's name in a rule or an event.
    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Any => "any",
            Proto::Other => "other",
        }
    }
}

/// How a rule matches the destination host of a connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMatch {
    /// `*` — any host. (Paired with a port this is the port-only equivalent of a
    /// Landlock `--allow-tcp-port`, kept so the guard is a strict superset.)
    Any,
    /// A single literal IP (v4 or v6).
    Ip(IpAddr),
    /// A CIDR block `net/prefix` (v4 or v6). `prefix` is bits (0..=32 / 0..=128).
    Cidr { net: IpAddr, prefix: u8 },
    /// A DNS name, resolved at decision time to the IP set it maps to; a connect
    /// matches iff its IP is in that set (see the module note on why connect is
    /// IP-only).
    Host(String),
}

/// One allow rule: `proto` × `host` × `port` (None = any port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowRule {
    pub proto: Proto,
    pub host: HostMatch,
    /// The destination port, or `None` for any port.
    pub port: Option<u16>,
}

/// The destination of a live `connect(2)`, decoded from its `sockaddr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
    pub proto: Proto,
}

/// The compiled allow-list. Default-DENY: a connect is allowed only if some rule
/// matches. An EMPTY policy therefore denies ALL network connects (loopback
/// included) — the launcher always seeds at least the model-proxy loopback rule.
///
/// Before any rule is consulted, the always-denied destinations
/// (`blocked_destination`: cloud metadata + link-local) are refused, so no
/// allow rule (`*:443`, a law `destinations:` entry, a curated `--net-allow`)
/// can admit them. `allow_metadata` (from `ALLOW_METADATA_ENV`) is the one
/// opt-out, for an agent that must use a cloud instance role on purpose.
///
/// Then the DENY rules (`mandu-net-guard --deny <spec>`, the same spec syntax
/// as an allow): a destination any of them matches is refused whatever allow
/// rule would admit it, so a deny beats the permissive `tcp:*:443` fallback.
/// The launcher passes the hosts an agent would upload a transcript or a
/// trace to (launcher `upload-deny.ts`; supported-agents.md §5.3.4 rule 1).
#[derive(Debug, Clone, Default)]
pub struct GuardPolicy {
    pub rules: Vec<AllowRule>,
    /// Destinations refused before any allow rule is consulted (`--deny`).
    pub deny: Vec<AllowRule>,
    /// Skip the always-denied destination check (default false = deny them).
    pub allow_metadata: bool,
}

/// The opt-out for the always-denied destinations: `MANDU_NET_ALLOW_METADATA=1`
/// in the guard's own environment (the net-proxy reads the same name).
pub const ALLOW_METADATA_ENV: &str = "MANDU_NET_ALLOW_METADATA";

/// Is `ip:port` an always-denied destination (docs/design/confidentiality/comparisons.md
/// §3.6, net-guard-connect-egress.md)? Returns what it is, for the deny reason.
///
/// - Cloud metadata and credential endpoints, every port: `169.254.169.254`
///   (AWS, GCP, Azure, OCI), `fd00:ec2::254` (AWS IPv6), `169.254.170.2` (ECS
///   task credentials), `169.254.170.23` / `fd00:ec2::23` (EKS pod identity),
///   `100.100.100.200` (Alibaba Cloud).
/// - The rest of link-local (`169.254.0.0/16`, `fe80::/10`), every port but 53:
///   a VPC resolver can sit at `169.254.169.253`, and DNS must keep working.
///
/// The IP is normalized first (v4-mapped `::ffff:a.b.c.d` and NAT64
/// `64:ff9b::a.b.c.d` become plain v4), so neither form slips past a v4 entry.
pub fn blocked_destination(ip: IpAddr, port: u16) -> Option<&'static str> {
    let ip = match normalize_ip(ip) {
        IpAddr::V6(v6) if u128::from(v6) >> 32 == 0x0064_ff9b_0000_0000_0000_0000 => {
            IpAddr::V4(Ipv4Addr::from(u128::from(v6) as u32))
        }
        other => other,
    };
    match ip {
        IpAddr::V4(v4) => match v4.octets() {
            [169, 254, 169, 254] => Some("cloud metadata endpoint"),
            [169, 254, 170, 2] => Some("container credentials endpoint (ECS)"),
            [169, 254, 170, 23] => Some("pod identity endpoint (EKS)"),
            [100, 100, 100, 200] => Some("cloud metadata endpoint (Alibaba Cloud)"),
            [169, 254, _, _] if port != 53 => Some("link-local address"),
            _ => None,
        },
        IpAddr::V6(v6) => {
            if v6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254) {
                Some("cloud metadata endpoint (AWS IPv6)")
            } else if v6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x23) {
                Some("pod identity endpoint (EKS IPv6)")
            } else if v6.segments()[0] & 0xffc0 == 0xfe80 && port != 53 {
                Some("link-local address")
            } else {
                None
            }
        }
    }
}

/// The verdict for one decoded connect target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// A rule matched — let the connect reach this destination.
    Allow,
    /// No rule matched — deny (the kernel leg returns `-EACCES` to the tracee).
    Deny,
}

/// Resolve a DNS name to the IP set it currently maps to (empty on failure). The
/// kernel leg passes a caching, `getaddrinfo`-backed impl; tests pass a fixed map.
///
/// A miss (empty result) makes a `Host` rule match NOTHING for this connect —
/// fail-closed: an unresolvable allow-rule never widens the allow-set.
pub trait HostResolver {
    fn resolve(&self, host: &str) -> Vec<IpAddr>;
}

/// A resolver that never resolves anything — every `Host` rule matches nothing.
/// Used where only IP/CIDR rules are in play (and by some unit tests).
pub struct NoResolver;
impl HostResolver for NoResolver {
    fn resolve(&self, _host: &str) -> Vec<IpAddr> {
        Vec::new()
    }
}

impl GuardPolicy {
    pub fn new(rules: Vec<AllowRule>) -> Self {
        GuardPolicy { rules, deny: Vec::new(), allow_metadata: false }
    }

    /// The same policy with these deny rules (checked before every allow rule).
    pub fn with_deny(mut self, deny: Vec<AllowRule>) -> Self {
        self.deny = deny;
        self
    }

    /// The deny rule `target` matches, or `None`. A host rule resolves as an
    /// allow's does (at decision time, every answer).
    pub fn denied_by<'a>(&'a self, target: &Endpoint, resolver: &dyn HostResolver) -> Option<&'a AllowRule> {
        let ip = normalize_ip(target.ip);
        self.deny.iter().find(|rule| rule_matches(rule, target, ip, resolver))
    }

    /// The same policy with the always-denied destination check switched off.
    pub fn with_metadata_allowed(mut self, allow: bool) -> Self {
        self.allow_metadata = allow;
        self
    }

    /// Why this policy refuses `target` before any rule is consulted (an
    /// always-denied destination), or `None`. Used for the deny event's reason.
    pub fn blocked_reason(&self, target: &Endpoint) -> Option<&'static str> {
        if self.allow_metadata {
            return None;
        }
        blocked_destination(target.ip, target.port)
    }

    /// Decide a decoded connect target against the allow-list (default-DENY).
    /// An always-denied destination (`blocked_reason`) is refused first.
    ///
    /// The destination IP is normalized FIRST (a v4-mapped IPv6 `::ffff:a.b.c.d`
    /// becomes the plain v4 `a.b.c.d`) so a v4 rule matches a v4-mapped connect and
    /// a `::ffff:*` sockaddr cannot slip past a v4 CIDR rule. Then the first rule
    /// whose protocol covers, whose host matches, and whose port matches wins.
    ///
    /// HONEST BOUNDS (also exec-routing.md §7.5): (1) `Host` rules resolve at
    /// decision time — a service whose DNS changes between resolution and the
    /// connect, or an attacker-controlled name (DNS rebinding), is only as tight
    /// as the resolver's current answer; pin critical destinations by IP/CIDR.
    /// (2) The connect chokepoint sees the resolved IP, never the SNI/hostname the
    /// agent intended — two names sharing an IP (CDN/anycast) are indistinguishable
    /// here.
    pub fn decide(&self, target: &Endpoint, resolver: &dyn HostResolver) -> Decision {
        self.decide_matched(target, resolver).0
    }

    /// Like `decide`, but also returns the matched rule (for observability — the
    /// connect-guard event names it): on ALLOW the allow rule that admitted the
    /// connect; on DENY the deny rule that refused it (`--deny`), or `None` when
    /// the destination is always-denied or nothing matched.
    pub fn decide_matched<'a>(
        &'a self,
        target: &Endpoint,
        resolver: &dyn HostResolver,
    ) -> (Decision, Option<&'a AllowRule>) {
        if self.blocked_reason(target).is_some() {
            return (Decision::Deny, None);
        }
        if let Some(rule) = self.denied_by(target, resolver) {
            return (Decision::Deny, Some(rule));
        }
        let ip = normalize_ip(target.ip);
        for rule in &self.rules {
            if rule_matches(rule, target, ip, resolver) {
                return (Decision::Allow, Some(rule));
            }
        }
        (Decision::Deny, None)
    }
}

/// Does `rule` cover this (normalized) destination: protocol, port, host?
fn rule_matches(rule: &AllowRule, target: &Endpoint, ip: IpAddr, resolver: &dyn HostResolver) -> bool {
    if !rule.proto.covers(target.proto) {
        return false;
    }
    if let Some(p) = rule.port {
        if p != target.port {
            return false;
        }
    }
    host_matches(&rule.host, ip, resolver)
}

impl std::fmt::Display for AllowRule {
    /// Render back to the `[proto:]host:port` spec form (round-trips `parse_rule`
    /// for the common cases; used in observability event reasons).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto = self.proto.name();
        let host = match &self.host {
            HostMatch::Any => "*".to_string(),
            HostMatch::Ip(IpAddr::V6(a)) => format!("[{a}]"),
            HostMatch::Ip(a) => a.to_string(),
            HostMatch::Cidr { net: IpAddr::V6(n), prefix } => format!("[{n}]/{prefix}"),
            HostMatch::Cidr { net, prefix } => format!("{net}/{prefix}"),
            HostMatch::Host(h) => h.clone(),
        };
        let port = match self.port {
            Some(p) => p.to_string(),
            None => "*".to_string(),
        };
        write!(f, "{proto}:{host}:{port}")
    }
}

/// Normalize a destination IP for matching: unwrap a v4-mapped IPv6
/// (`::ffff:a.b.c.d`) to its v4 form. Everything else is returned unchanged.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn host_matches(host: &HostMatch, ip: IpAddr, resolver: &dyn HostResolver) -> bool {
    match host {
        HostMatch::Any => true,
        HostMatch::Ip(a) => normalize_ip(*a) == ip,
        HostMatch::Cidr { net, prefix } => cidr_contains(*net, *prefix, ip),
        HostMatch::Host(name) => resolver
            .resolve(name)
            .into_iter()
            .any(|r| normalize_ip(r) == ip),
    }
}

/// Is `ip` inside the CIDR `net/prefix`? A v4 net only matches v4 ips (and vice
/// versa) — after `normalize_ip` a v4-mapped connect is already plain v4, so a v4
/// CIDR catches it. An out-of-range prefix is clamped defensively.
pub fn cidr_contains(net: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let bits = prefix.min(32);
            let mask: u32 = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(net) & mask) == (u32::from(ip) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let bits = prefix.min(128);
            let mask: u128 = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(net) & mask) == (u128::from(ip) & mask)
        }
        // Mixed families never match.
        _ => false,
    }
}

// ── spec parsing ────────────────────────────────────────────────────────────

/// Parse one allow-spec into a rule. Grammar (matches the `--allow` CLI + the
/// launcher's emitted specs):
///
///   [proto:]host:port
///
///   proto  = "tcp" | "udp" | "any"          (default "tcp" when omitted)
///   host   = IPv4 | "[" IPv6 "]" | CIDR | dns-name | "*"
///   port   = 1..=65535 | "*"                (any port)
///
/// IPv6 literals MUST be bracketed so the colon delimiter is unambiguous
/// (`tcp:[2001:db8::1]:443`, `[::1]:*`). A bare v4/host uses the last colon as the
/// port delimiter. Examples:
///   `tcp:1.2.3.4:443` · `10.0.0.0/8:*` · `api.anthropic.com:443` ·
///   `udp:*:53` · `127.0.0.1:8788` · `*:443`
pub fn parse_rule(spec: &str) -> Result<AllowRule, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("empty spec".into());
    }

    // Split an optional leading `proto:`. We only strip it when the token before
    // the first colon is a known protocol keyword — otherwise the first colon
    // belongs to the host (an IPv6 literal is bracketed, so a bare colon here is
    // either proto or the host:port split).
    let (proto, rest) = match spec.split_once(':') {
        Some((head, tail)) if is_proto_kw(head) => (proto_from(head), tail),
        _ => (Proto::Tcp, spec),
    };

    // Split host and port from the RIGHT so a bracketed IPv6 host keeps its colons.
    let (host_str, port_str) = rest
        .rsplit_once(':')
        .ok_or_else(|| format!("spec {spec:?} missing :port (use :* for any port)"))?;
    if host_str.is_empty() {
        return Err(format!("spec {spec:?} has an empty host"));
    }

    let port = match port_str {
        "*" => None,
        p => Some(
            p.parse::<u16>()
                .ok()
                .filter(|&n| n != 0)
                .ok_or_else(|| format!("spec {spec:?} has a bad port {p:?} (want 1..=65535 or *)"))?,
        ),
    };

    let host = parse_host(host_str)?;
    Ok(AllowRule { proto, host, port })
}

/// Parse many specs (one rule each), collecting the first error with its index.
pub fn parse_rules(specs: &[String]) -> Result<Vec<AllowRule>, String> {
    let mut out = Vec::with_capacity(specs.len());
    for (i, s) in specs.iter().enumerate() {
        out.push(parse_rule(s).map_err(|e| format!("allow spec #{i}: {e}"))?);
    }
    Ok(out)
}

fn is_proto_kw(s: &str) -> bool {
    matches!(s, "tcp" | "udp" | "any")
}

fn proto_from(s: &str) -> Proto {
    match s {
        "udp" => Proto::Udp,
        "any" => Proto::Any,
        _ => Proto::Tcp,
    }
}

fn parse_host(host: &str) -> Result<HostMatch, String> {
    if host == "*" {
        return Ok(HostMatch::Any);
    }
    // Bracketed IPv6 literal / IPv6 CIDR: `[2001:db8::1]` or `[2001:db8::]/48`.
    if let Some(inner) = host.strip_prefix('[') {
        let (addr, after) = inner
            .split_once(']')
            .ok_or_else(|| format!("host {host:?} has an unclosed '['"))?;
        if let Some(pfx) = after.strip_prefix('/') {
            let net: Ipv6Addr = addr
                .parse()
                .map_err(|_| format!("bad IPv6 in CIDR {host:?}"))?;
            let prefix = parse_prefix(pfx, 128)?;
            return Ok(HostMatch::Cidr { net: IpAddr::V6(net), prefix });
        }
        if !after.is_empty() {
            return Err(format!("trailing junk after ']' in {host:?}"));
        }
        let ip: Ipv6Addr = addr.parse().map_err(|_| format!("bad IPv6 literal {host:?}"))?;
        return Ok(HostMatch::Ip(IpAddr::V6(ip)));
    }
    // CIDR (v4, or an unbracketed v6 CIDR like `2001:db8::/32`).
    if let Some((net_str, pfx_str)) = host.split_once('/') {
        if let Ok(net) = net_str.parse::<Ipv4Addr>() {
            let prefix = parse_prefix(pfx_str, 32)?;
            return Ok(HostMatch::Cidr { net: IpAddr::V4(net), prefix });
        }
        if let Ok(net) = net_str.parse::<Ipv6Addr>() {
            let prefix = parse_prefix(pfx_str, 128)?;
            return Ok(HostMatch::Cidr { net: IpAddr::V6(net), prefix });
        }
        return Err(format!("bad CIDR network in {host:?}"));
    }
    // A bare IP literal, else a DNS name.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(HostMatch::Ip(ip));
    }
    Ok(HostMatch::Host(host.to_string()))
}

fn parse_prefix(s: &str, max: u8) -> Result<u8, String> {
    let n: u8 = s.parse().map_err(|_| format!("bad CIDR prefix {s:?}"))?;
    if n > max {
        return Err(format!("CIDR prefix /{n} exceeds /{max}"));
    }
    Ok(n)
}

// ── sockaddr decode ─────────────────────────────────────────────────────────

/// What a `connect(2)` sockaddr decoded to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnTarget {
    /// A decodable IPv4/IPv6 endpoint (proto filled in by the kernel leg from
    /// `SO_TYPE`; `decode_sockaddr` returns `Proto::Tcp` as a placeholder).
    Inet(Endpoint),
    /// A non-IP family (AF_UNIX, AF_NETLINK, …) — the guard PASSES IT THROUGH
    /// untouched (the arbiter's own AF_UNIX socket must keep working).
    Passthrough,
}

// Address families (from <sys/socket.h>); pinned so the pure decoder needs no libc.
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const AF_UNIX: u16 = 1;

/// Decode a `connect(2)` target `sockaddr` (the exact bytes the tracee passed,
/// truncated to its `addrlen`). Returns `Passthrough` for any non-INET family or a
/// too-short / malformed INET address — a connect with a malformed sockaddr fails
/// in the kernel anyway, and passing it through never reaches a network peer.
///
/// `sa_family` is host-endian (kernel ABI); the port and address bytes are network
/// byte order (big-endian), matching `sockaddr_in{,6}`.
pub fn decode_sockaddr(buf: &[u8]) -> ConnTarget {
    if buf.len() < 2 {
        return ConnTarget::Passthrough;
    }
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    match family {
        AF_INET => {
            // struct sockaddr_in { u16 family; u16 port(BE); u32 addr(BE); … } — 8+.
            if buf.len() < 8 {
                return ConnTarget::Passthrough;
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            ConnTarget::Inet(Endpoint {
                ip: IpAddr::V4(ip),
                port,
                proto: Proto::Tcp,
            })
        }
        AF_INET6 => {
            // struct sockaddr_in6 { u16 family; u16 port(BE); u32 flowinfo;
            //   u8 addr[16]; u32 scope; } — the addr starts at offset 8, needs 24+.
            if buf.len() < 24 {
                return ConnTarget::Passthrough;
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[8..24]);
            let ip = Ipv6Addr::from(octets);
            ConnTarget::Inet(Endpoint {
                ip: IpAddr::V6(ip),
                port,
                proto: Proto::Tcp,
            })
        }
        _ => ConnTarget::Passthrough,
    }
}

/// WSL2's Windows interop door, whole-agent leg (mandu_arbiter::wsl has the
/// threat; exec-routing.md §4.1). The AgentShell box hides the socket by
/// mount; the whole agent is not boxed, so here the guard REFUSES the two
/// connects that would start or reach a Windows program outside every Linux
/// wrap: a Unix connect to the interop socket, and any `AF_VSOCK` connect
/// (Hyper-V sockets to the Windows host, which the guard cannot judge by
/// destination). Built only on a WSL host (`from_signals`), so no other
/// host's AF_UNIX / vsock traffic is touched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WslGuard {
    /// The canonical path `$WSL_INTEROP` named when the guard started (a socket
    /// outside `/run/WSL` is refused by name).
    pub interop_env: Option<String>,
    /// That socket's identity `(st_dev, st_ino)` when the guard started
    /// (`with_interop_identity`): a hardlink to it, or the socket after its
    /// name was unlinked, is still the door.
    pub interop_id: Option<(u64, u64)>,
}

impl WslGuard {
    /// `Some` on a WSL host (any one signal), else `None`. `canon` resolves the
    /// `$WSL_INTEROP` path (symlinks) on the host; an unresolvable one is kept
    /// verbatim.
    pub fn from_signals(s: &mandu_arbiter::wsl::WslSignals, canon: impl Fn(&str) -> Option<String>) -> Option<Self> {
        if !s.is_wsl() {
            return None;
        }
        Some(WslGuard { interop_env: s.interop_env.as_deref().map(|e| canon(e).unwrap_or_else(|| e.to_string())), interop_id: None })
    }

    /// Record the interop socket's identity (the caller stats `interop_env`).
    pub fn with_interop_identity(mut self, id: Option<(u64, u64)>) -> Self {
        self.interop_id = id;
        self
    }

    /// The race-free check (exec-routing.md §4.1): the guard opened the
    /// connect's target itself, in the tracee's view, and asks about THAT
    /// inode. Refused when its identity is the recorded interop socket or one
    /// of `interop_ids` (every entry of `/run/WSL`, and the `$WSL_INTEROP`
    /// socket, stat'ed at check time), or when the path the kernel reports for
    /// the opened file (`seen`) is an interop path. A hardlink elsewhere has
    /// the same inode, so it is refused by identity; a symlink swapped in
    /// after the open changes nothing, because the guard connects the opened
    /// inode, not the path.
    pub fn refusal_by_identity(&self, id: (u64, u64), seen: Option<&str>, interop_ids: &[(u64, u64)]) -> Option<&'static str> {
        let by_id = self.interop_id == Some(id) || interop_ids.contains(&id);
        let by_path = seen.map(|p| mandu_arbiter::wsl::is_interop_path(p, self.interop_env.as_deref())).unwrap_or(false);
        (by_id || by_path).then_some("wsl-interop: the Windows interop socket starts programs outside every Linux wrap")
    }

    /// Why this connect is refused, or `None` to leave it to the rest of the
    /// guard. `family` is the sockaddr's; `unix_path` the Unix target already
    /// resolved against the tracee's cwd and canonicalized (`@…` = abstract,
    /// never an interop socket).
    pub fn refusal(&self, family: u16, unix_path: Option<&str>) -> Option<&'static str> {
        if family == mandu_arbiter::wsl::AF_VSOCK {
            return Some("wsl-interop: AF_VSOCK reaches the Windows host outside the guard");
        }
        match unix_path {
            Some(p) if !p.starts_with('@') && mandu_arbiter::wsl::is_interop_path(p, self.interop_env.as_deref()) => {
                Some("wsl-interop: the Windows interop socket starts programs outside every Linux wrap")
            }
            _ => None,
        }
    }
}

/// How the guard reaches a Unix connect's target in the TRACEE's view, so it
/// can check the inode and then connect exactly that inode (guard_kernel's
/// supervised Unix connect). Shared with the command box's socket allow-list
/// (exec-routing.md §4.2), so it lives in fs-supervisor.
pub use fs_supervisor::tracee::{plan_unix_lookup, UnixLookup};

/// The raw path bytes of a PATHNAME `AF_UNIX` sockaddr (up to the first NUL),
/// or `None` for another family, an abstract (`sun_path[0] == 0`) or an
/// unnamed address. Unlike `secret_open::unix_path_of` it keeps non-UTF-8
/// bytes exact: the guard resolves these bytes, not a lossy spelling of them.
pub fn unix_pathname_bytes(raw: &[u8]) -> Option<&[u8]> {
    if raw.len() < 3 || u16::from_ne_bytes([raw[0], raw[1]]) != AF_UNIX {
        return None;
    }
    let p = &raw[2..];
    if p[0] == 0 {
        return None;
    }
    Some(&p[..p.iter().position(|b| *b == 0).unwrap_or(p.len())])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn tcp(host: &str, port: u16) -> Endpoint {
        Endpoint { ip: ip(host), port, proto: Proto::Tcp }
    }

    /// A fixed-map resolver for hostname-rule tests.
    struct MapResolver(Vec<(&'static str, Vec<IpAddr>)>);
    impl HostResolver for MapResolver {
        fn resolve(&self, host: &str) -> Vec<IpAddr> {
            self.0
                .iter()
                .find(|(h, _)| *h == host)
                .map(|(_, ips)| ips.clone())
                .unwrap_or_default()
        }
    }

    #[test]
    fn deny_rules_beat_the_star_fallback() {
        let allow = parse_rules(&["tcp:*:443".into(), "udp:*:53".into()]).unwrap();
        let deny = parse_rules(&["tcp:9.9.9.9:*".into(), "10.1.0.0/16:443".into(), "tcp:upload.example:*".into()]).unwrap();
        let r = MapResolver(vec![("upload.example", vec![ip("5.6.7.8"), ip("2001:db8::5")])]);
        let p = GuardPolicy::new(allow.clone()).with_deny(deny);
        // by IP, every port of a `*` deny
        assert_eq!(p.decide(&tcp("9.9.9.9", 443), &r), Decision::Deny);
        // by CIDR, on the deny's port only
        assert_eq!(p.decide(&tcp("10.1.2.3", 443), &r), Decision::Deny);
        assert_eq!(p.decide(&tcp("10.2.2.3", 443), &r), Decision::Allow);
        // by host, every resolved answer (and v4-mapped dress)
        assert_eq!(p.decide(&tcp("5.6.7.8", 443), &r), Decision::Deny);
        assert_eq!(p.decide(&tcp("::ffff:5.6.7.8", 443), &r), Decision::Deny);
        assert_eq!(p.decide(&tcp("2001:db8::5", 443), &r), Decision::Deny);
        // a tcp deny leaves udp alone
        let dns = Endpoint { ip: ip("9.9.9.9"), port: 53, proto: Proto::Udp };
        assert_eq!(p.decide(&dns, &r), Decision::Allow);
        // the event names the deny rule
        let (d, m) = p.decide_matched(&tcp("9.9.9.9", 443), &r);
        assert_eq!(d, Decision::Deny);
        assert_eq!(m.map(|x| x.to_string()).as_deref(), Some("tcp:9.9.9.9:*"));
        // the always-denied set still comes first (no rule named)
        assert_eq!(p.decide_matched(&tcp("169.254.169.254", 80), &r), (Decision::Deny, None));
        // no deny rules: unchanged
        let plain = GuardPolicy::new(allow);
        assert_eq!(plain.decide(&tcp("9.9.9.9", 443), &r), Decision::Allow);
        assert_eq!(plain.decide(&tcp("5.6.7.8", 443), &r), Decision::Allow);
        assert!(plain.denied_by(&tcp("9.9.9.9", 443), &r).is_none());
    }

    #[test]
    fn metadata_endpoints_denied_under_any_host_rules() {
        // `*:*` admits everything a rule can express; the always-denied set
        // still wins, on every port.
        let p = GuardPolicy::new(vec![parse_rule("any:*:*").unwrap()]);
        for (host, port) in [
            ("169.254.169.254", 80),
            ("169.254.169.254", 443),
            ("169.254.170.2", 80),
            ("169.254.170.23", 80),
            ("100.100.100.200", 80),
            ("fd00:ec2::254", 80),
            ("fd00:ec2::23", 80),
            // The same endpoint in v4-mapped and NAT64 dress.
            ("::ffff:169.254.169.254", 80),
            ("64:ff9b::a9fe:a9fe", 80),
            // Link-local off DNS.
            ("169.254.1.1", 8080),
            ("fe80::1", 443),
        ] {
            assert_eq!(p.decide(&tcp(host, port), &NoResolver), Decision::Deny, "{host}:{port}");
            assert!(p.blocked_reason(&tcp(host, port)).is_some(), "{host}:{port}");
        }
        // Ordinary hosts still pass the same rule.
        assert_eq!(p.decide(&tcp("1.2.3.4", 443), &NoResolver), Decision::Allow);
        assert_eq!(p.decide(&tcp("100.100.100.201", 80), &NoResolver), Decision::Allow);
    }

    #[test]
    fn link_local_dns_survives() {
        // A VPC resolver at 169.254.169.253:53 must keep answering.
        let p = GuardPolicy::new(vec![parse_rule("any:*:53").unwrap()]);
        let udp = Endpoint { ip: ip("169.254.169.253"), port: 53, proto: Proto::Udp };
        assert_eq!(p.decide(&udp, &NoResolver), Decision::Allow);
        assert_eq!(p.decide(&tcp("fe80::53", 53), &NoResolver), Decision::Allow);
        // The metadata IP itself is denied even on :53.
        assert_eq!(p.decide(&tcp("169.254.169.254", 53), &NoResolver), Decision::Deny);
    }

    #[test]
    fn metadata_opt_out_restores_the_rules() {
        let p = GuardPolicy::new(vec![parse_rule("tcp:169.254.169.254:80").unwrap()]).with_metadata_allowed(true);
        assert_eq!(p.decide(&tcp("169.254.169.254", 80), &NoResolver), Decision::Allow);
        assert_eq!(p.blocked_reason(&tcp("169.254.169.254", 80)), None);
        // Opted out, it is still default-deny: no rule, no connect.
        assert_eq!(p.decide(&tcp("169.254.170.2", 80), &NoResolver), Decision::Deny);
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = GuardPolicy::default();
        assert_eq!(p.decide(&tcp("127.0.0.1", 8788), &NoResolver), Decision::Deny);
        assert_eq!(p.decide(&tcp("1.2.3.4", 443), &NoResolver), Decision::Deny);
    }

    #[test]
    fn exact_ip_and_port() {
        let p = GuardPolicy::new(vec![parse_rule("tcp:1.2.3.4:443").unwrap()]);
        assert_eq!(p.decide(&tcp("1.2.3.4", 443), &NoResolver), Decision::Allow);
        // Same ip, wrong port → deny.
        assert_eq!(p.decide(&tcp("1.2.3.4", 80), &NoResolver), Decision::Deny);
        // Wrong ip, right port → deny (THE port-only gap this closes).
        assert_eq!(p.decide(&tcp("9.9.9.9", 443), &NoResolver), Decision::Deny);
    }

    #[test]
    fn any_port_wildcard() {
        let p = GuardPolicy::new(vec![parse_rule("tcp:10.0.0.5:*").unwrap()]);
        assert_eq!(p.decide(&tcp("10.0.0.5", 22), &NoResolver), Decision::Allow);
        assert_eq!(p.decide(&tcp("10.0.0.5", 65000), &NoResolver), Decision::Allow);
        assert_eq!(p.decide(&tcp("10.0.0.6", 22), &NoResolver), Decision::Deny);
    }

    #[test]
    fn any_host_is_the_port_only_equivalent() {
        // `*:443` == a Landlock --allow-tcp-port 443 (any host on 443).
        let p = GuardPolicy::new(vec![parse_rule("*:443").unwrap()]);
        assert_eq!(p.decide(&tcp("1.2.3.4", 443), &NoResolver), Decision::Allow);
        assert_eq!(p.decide(&tcp("5.6.7.8", 443), &NoResolver), Decision::Allow);
        assert_eq!(p.decide(&tcp("1.2.3.4", 444), &NoResolver), Decision::Deny);
    }

    #[test]
    fn cidr_v4() {
        let p = GuardPolicy::new(vec![parse_rule("10.0.0.0/8:*").unwrap()]);
        assert_eq!(p.decide(&tcp("10.255.1.1", 443), &NoResolver), Decision::Allow);
        assert_eq!(p.decide(&tcp("11.0.0.1", 443), &NoResolver), Decision::Deny);
        // /32 is a single host.
        let p32 = GuardPolicy::new(vec![parse_rule("10.0.0.1/32:*").unwrap()]);
        assert_eq!(p32.decide(&tcp("10.0.0.1", 1), &NoResolver), Decision::Allow);
        assert_eq!(p32.decide(&tcp("10.0.0.2", 1), &NoResolver), Decision::Deny);
        // /0 matches all v4.
        let p0 = GuardPolicy::new(vec![parse_rule("0.0.0.0/0:443").unwrap()]);
        assert_eq!(p0.decide(&tcp("203.0.113.7", 443), &NoResolver), Decision::Allow);
    }

    #[test]
    fn loopback_cidr() {
        let p = GuardPolicy::new(vec![parse_rule("127.0.0.0/8:8788").unwrap()]);
        assert_eq!(p.decide(&tcp("127.0.0.1", 8788), &NoResolver), Decision::Allow);
        assert_eq!(p.decide(&tcp("127.9.9.9", 8788), &NoResolver), Decision::Allow);
        assert_eq!(p.decide(&tcp("128.0.0.1", 8788), &NoResolver), Decision::Deny);
    }

    #[test]
    fn ipv6_literal_and_cidr() {
        let p = GuardPolicy::new(vec![parse_rule("tcp:[2001:db8::1]:443").unwrap()]);
        assert_eq!(p.decide(&tcp("2001:db8::1", 443), &NoResolver), Decision::Allow);
        assert_eq!(p.decide(&tcp("2001:db8::2", 443), &NoResolver), Decision::Deny);

        let pc = GuardPolicy::new(vec![parse_rule("[2001:db8::]/32:*").unwrap()]);
        assert_eq!(pc.decide(&tcp("2001:db8:dead:beef::9", 1), &NoResolver), Decision::Allow);
        assert_eq!(pc.decide(&tcp("2001:db9::1", 1), &NoResolver), Decision::Deny);
        // Unbracketed v6 CIDR also parses.
        assert_eq!(parse_rule("2001:db8::/32:*").unwrap().host, pc.rules[0].host);
    }

    #[test]
    fn v4_mapped_v6_normalizes_to_v4_rule() {
        // A connect whose sockaddr is ::ffff:1.2.3.4 must match a plain v4 rule…
        let p = GuardPolicy::new(vec![parse_rule("tcp:1.2.3.4:443").unwrap()]);
        assert_eq!(p.decide(&tcp("::ffff:1.2.3.4", 443), &NoResolver), Decision::Allow);
        // …and must NOT slip past a v4 CIDR deny by wearing a v6 coat.
        let pc = GuardPolicy::new(vec![parse_rule("10.0.0.0/8:*").unwrap()]);
        assert_eq!(pc.decide(&tcp("::ffff:11.0.0.1", 1), &NoResolver), Decision::Deny);
        assert_eq!(pc.decide(&tcp("::ffff:10.1.2.3", 1), &NoResolver), Decision::Allow);
    }

    #[test]
    fn proto_matching() {
        let tcp_rule = GuardPolicy::new(vec![parse_rule("tcp:1.2.3.4:443").unwrap()]);
        let udp_conn = Endpoint { ip: ip("1.2.3.4"), port: 443, proto: Proto::Udp };
        assert_eq!(tcp_rule.decide(&udp_conn, &NoResolver), Decision::Deny);

        let udp_dns = GuardPolicy::new(vec![parse_rule("udp:*:53").unwrap()]);
        let dns = Endpoint { ip: ip("8.8.8.8"), port: 53, proto: Proto::Udp };
        assert_eq!(udp_dns.decide(&dns, &NoResolver), Decision::Allow);
        // A TCP:53 connect is NOT covered by a udp:*:53 rule.
        assert_eq!(udp_dns.decide(&tcp("8.8.8.8", 53), &NoResolver), Decision::Deny);

        // `any:` covers both.
        let anyp = GuardPolicy::new(vec![parse_rule("any:1.2.3.4:443").unwrap()]);
        assert_eq!(anyp.decide(&tcp("1.2.3.4", 443), &NoResolver), Decision::Allow);
        assert_eq!(anyp.decide(&udp_conn, &NoResolver), Decision::Allow);
    }

    #[test]
    fn hostname_rule_resolves_to_ip_set() {
        let resolver = MapResolver(vec![("api.anthropic.com", vec![ip("160.79.104.10")])]);
        let p = GuardPolicy::new(vec![parse_rule("api.anthropic.com:443").unwrap()]);
        assert_eq!(p.decide(&tcp("160.79.104.10", 443), &resolver), Decision::Allow);
        // A different IP for that port is denied…
        assert_eq!(p.decide(&tcp("1.2.3.4", 443), &resolver), Decision::Deny);
        // …and a resolver MISS (empty) fails closed (rule matches nothing).
        assert_eq!(p.decide(&tcp("160.79.104.10", 443), &NoResolver), Decision::Deny);
    }

    #[test]
    fn first_matching_rule_wins() {
        let p = GuardPolicy::new(vec![
            parse_rule("127.0.0.0/8:8788").unwrap(),
            parse_rule("*:443").unwrap(),
        ]);
        assert_eq!(p.decide(&tcp("127.0.0.1", 8788), &NoResolver), Decision::Allow);
        assert_eq!(p.decide(&tcp("1.2.3.4", 443), &NoResolver), Decision::Allow);
        assert_eq!(p.decide(&tcp("1.2.3.4", 22), &NoResolver), Decision::Deny);
    }

    // ── spec parse errors ────────────────────────────────────────────────────

    #[test]
    fn parse_defaults_and_errors() {
        // Default proto is tcp.
        assert_eq!(parse_rule("1.2.3.4:443").unwrap().proto, Proto::Tcp);
        // Missing port.
        assert!(parse_rule("1.2.3.4").is_err());
        // Bad port.
        assert!(parse_rule("1.2.3.4:0").is_err());
        assert!(parse_rule("1.2.3.4:70000").is_err());
        assert!(parse_rule("1.2.3.4:http").is_err());
        // Empty host.
        assert!(parse_rule("tcp::443").is_err());
        // Unclosed bracket.
        assert!(parse_rule("[::1:443").is_err());
        // Bad CIDR prefix.
        assert!(parse_rule("10.0.0.0/33:*").is_err());
        // Empty spec.
        assert!(parse_rule("   ").is_err());
    }

    #[test]
    fn allow_rule_display_round_trips() {
        for spec in ["tcp:1.2.3.4:443", "udp:*:53", "any:10.0.0.0/8:22", "tcp:[2001:db8::1]:443", "tcp:[2001:db8::]/32:*", "tcp:api.anthropic.com:443"] {
            let rule = parse_rule(spec).unwrap();
            // Display renders a spec that re-parses to the same rule.
            assert_eq!(parse_rule(&rule.to_string()).unwrap(), rule, "round-trip {spec}");
        }
    }

    #[test]
    fn decide_matched_names_the_rule() {
        let p = GuardPolicy::new(vec![parse_rule("tcp:1.2.3.4:443").unwrap()]);
        let (d, rule) = p.decide_matched(&tcp("1.2.3.4", 443), &NoResolver);
        assert_eq!(d, Decision::Allow);
        assert_eq!(rule.unwrap().to_string(), "tcp:1.2.3.4:443");
        let (d2, rule2) = p.decide_matched(&tcp("9.9.9.9", 443), &NoResolver);
        assert_eq!(d2, Decision::Deny);
        assert!(rule2.is_none());
    }

    #[test]
    fn parse_rules_reports_index() {
        let err = parse_rules(&["1.2.3.4:443".into(), "bogus".into()]).unwrap_err();
        assert!(err.contains("#1"), "error names the bad index: {err}");
    }

    // ── sockaddr decode ──────────────────────────────────────────────────────

    #[test]
    fn decode_v4_sockaddr() {
        // family=AF_INET(ne), port=443(be), addr=1.2.3.4.
        let mut buf = vec![0u8; 16];
        buf[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        buf[2..4].copy_from_slice(&443u16.to_be_bytes());
        buf[4..8].copy_from_slice(&[1, 2, 3, 4]);
        match decode_sockaddr(&buf) {
            ConnTarget::Inet(e) => {
                assert_eq!(e.ip, ip("1.2.3.4"));
                assert_eq!(e.port, 443);
            }
            other => panic!("expected Inet, got {other:?}"),
        }
    }

    #[test]
    fn decode_v6_sockaddr() {
        let mut buf = vec![0u8; 28];
        buf[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        buf[2..4].copy_from_slice(&8443u16.to_be_bytes());
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        buf[8..24].copy_from_slice(&addr.octets());
        match decode_sockaddr(&buf) {
            ConnTarget::Inet(e) => {
                assert_eq!(e.ip, IpAddr::V6(addr));
                assert_eq!(e.port, 8443);
            }
            other => panic!("expected Inet, got {other:?}"),
        }
    }

    #[test]
    fn decode_non_inet_is_passthrough() {
        // AF_UNIX (1) — the arbiter socket family. MUST pass through.
        let mut buf = vec![0u8; 16];
        buf[0..2].copy_from_slice(&1u16.to_ne_bytes());
        assert_eq!(decode_sockaddr(&buf), ConnTarget::Passthrough);
        // Too short.
        assert_eq!(decode_sockaddr(&[2]), ConnTarget::Passthrough);
        // AF_INET but truncated.
        let mut short = vec![0u8; 6];
        short[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        assert_eq!(decode_sockaddr(&short), ConnTarget::Passthrough);
    }

    // ── WSL interop (whole-agent leg) ────────────────────────────────────────

    use mandu_arbiter::wsl::WslSignals;

    #[test]
    fn the_wsl_guard_exists_only_on_wsl() {
        let plain = WslSignals { osrelease: Some("6.8.0-139-generic".into()), ..Default::default() };
        assert_eq!(WslGuard::from_signals(&plain, |_| None), None);
        let wsl = WslSignals { osrelease: Some("5.15.1-microsoft-standard-WSL2".into()), ..Default::default() };
        assert_eq!(WslGuard::from_signals(&wsl, |_| None), Some(WslGuard { interop_env: None, interop_id: None }));
        let env = WslSignals { interop_env: Some("/run/WSL/8_interop".into()), ..Default::default() };
        let canon = |p: &str| (p == "/run/WSL/8_interop").then(|| "/run/WSL/8_interop".to_string());
        assert_eq!(WslGuard::from_signals(&env, canon).unwrap().interop_env.as_deref(), Some("/run/WSL/8_interop"));
    }

    #[test]
    fn the_wsl_guard_refuses_the_interop_socket_and_vsock_only() {
        let g = WslGuard { interop_env: Some("/srv/odd/1_interop".into()), interop_id: None };
        let unix = libc_af_unix();
        assert!(g.refusal(unix, Some("/run/WSL/8_interop")).is_some());
        assert!(g.refusal(unix, Some("/srv/odd/1_interop")).is_some(), "the socket $WSL_INTEROP named");
        assert!(g.refusal(40, None).is_some(), "AF_VSOCK");
        // Everything else is left to the rest of the guard.
        assert!(g.refusal(unix, Some("/run/user/1000/mandu/arbiter.sock")).is_none());
        assert!(g.refusal(unix, Some("/run/WSLx/8_interop")).is_none());
        assert!(g.refusal(unix, Some("@/run/WSL/8_interop")).is_none(), "abstract namespace");
        assert!(g.refusal(unix, None).is_none());
        assert!(g.refusal(AF_INET, None).is_none() && g.refusal(AF_INET6, None).is_none());
    }

    fn libc_af_unix() -> u16 {
        1
    }

    #[test]
    fn the_identity_check_refuses_the_door_by_inode_and_by_path() {
        let g = WslGuard { interop_env: Some("/srv/odd/1_interop".into()), interop_id: None }.with_interop_identity(Some((7, 70)));
        // The recorded socket, under any name (a hardlink elsewhere).
        assert!(g.refusal_by_identity((7, 70), Some("/home/u/innocent.sock"), &[]).is_some());
        // A socket found in /run/WSL at check time (a later session's).
        assert!(g.refusal_by_identity((9, 3), Some("/tmp/x"), &[(9, 3), (9, 4)]).is_some());
        // The path the kernel reports for the opened inode.
        assert!(g.refusal_by_identity((1, 1), Some("/run/WSL/12_interop"), &[]).is_some());
        assert!(g.refusal_by_identity((1, 1), Some("/srv/odd/1_interop"), &[]).is_some());
        // Anything else is left to the rest of the guard.
        assert!(g.refusal_by_identity((1, 1), Some("/run/user/1000/bus"), &[(9, 3)]).is_none());
        assert!(g.refusal_by_identity((7, 71), None, &[]).is_none());
        assert!(g.refusal_by_identity((8, 70), Some("/run/WSLx/1"), &[]).is_none(), "dev and ino both count");
    }


    #[test]
    fn pathname_bytes_skip_abstract_and_other_families() {
        let mut raw = vec![1u8, 0];
        raw.extend_from_slice(b"/run/WSL/8_interop\0junk");
        assert_eq!(unix_pathname_bytes(&raw), Some(&b"/run/WSL/8_interop"[..]));
        let mut abs = vec![1u8, 0, 0];
        abs.extend_from_slice(b"/run/WSL/8_interop");
        assert_eq!(unix_pathname_bytes(&abs), None, "abstract");
        assert_eq!(unix_pathname_bytes(&[1, 0]), None, "unnamed");
        assert_eq!(unix_pathname_bytes(&[2, 0, 0, 80, 127, 0, 0, 1]), None, "AF_INET");
        let mut bin = vec![1u8, 0];
        bin.extend_from_slice(b"/tmp/\xfe");
        assert_eq!(unix_pathname_bytes(&bin), Some(&b"/tmp/\xfe"[..]), "non-UTF-8 kept, no NUL needed");
    }
}
