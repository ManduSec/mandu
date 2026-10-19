/**
 * blocked-destinations — the destinations this proxy never dials for a
 * client, checked on every destination it dials, in every mode:
 *
 *   - the ALWAYS-DENIED set: cloud metadata and link-local
 *     (docs/design/confidentiality/comparisons.md §3.6, confidentiality.md);
 *   - THIS MACHINE (2026-10-05): loopback (127.0.0.0/8, ::1, and their
 *     v4-mapped and v4-compatible spellings), the unspecified address
 *     (0.0.0.0/8, ::), the `localhost` names, every address of this
 *     machine's own interfaces, and (2026-10-17) on Linux every address its
 *     routing tables deliver to itself: an interface that is down or has no
 *     carrier (which `os.networkInterfaces()` leaves out), a `local` route
 *     with no interface address (docs/design/integrity/exec-routing.md §7.5,
 *     with the special-purpose ranges classified there).
 *
 * Why the proxy needs its own copy of the connect guard's rules: the agent may
 * reach this proxy over loopback, and the proxy dials upstream from OUTSIDE the
 * guard, so `http://169.254.169.254/latest/meta-data/iam/...` sent through
 * HTTP_PROXY would otherwise fetch an instance role's credentials on the
 * agent's behalf, and `curl -x "$HTTP_PROXY" http://127.0.0.1:4500/...` would
 * read a loopback service the guard refuses the agent's direct connect to
 * (the Mandu dashboard, a database, a dev server's admin port). The
 * always-denied set is a TWIN of `net-supervisor/src/guard.rs::
 * blocked_destination`; the this-machine set mirrors `guard_flow.rs::
 * this_machine` (loopback, the wildcard, an address a socket here can bind),
 * with this machine's interface list standing in for the bind test. KEEP IN
 * SYNC (the packages build independently). A local service is reached
 * DIRECTLY (loopback is in the session's NO_PROXY), where the connect guard
 * decides; the proxy relays only off the machine.
 *
 * Two checks, so a name cannot rebind between check and dial:
 *   1. `dialRefusal` on the host as written (a literal IP, a metadata name, a
 *      `localhost` name), before anything is dialed. Node never calls a
 *      `lookup` for a literal IP, so for a literal this is the check, and
 *      every dial site makes it (`guardDial`) on the host it actually dials;
 *   2. `guardedLookup` as the dial's `lookup`: the name is resolved HERE, every
 *      answer is checked, and the socket connects to the address that was
 *      checked (Node dials what the lookup returns).
 *
 * Opt-outs: `MANDU_NET_ALLOW_METADATA=1` lifts the always-denied set, for an
 * agent that must use a cloud instance role on purpose. The this-machine set
 * has NO environment opt-out: only a mock-sites host route's own dial (an
 * operator-configured loopback test listener, mock-sites.ts; `mandu demo`'s
 * stand-in sites) and in-process tests (`DialPolicy.allowThisMachine`) skip
 * it. Mandu-new (no reference origin).
 */
import { lookup as dnsLookup, type LookupAddress, type LookupAllOptions, type LookupOneOptions } from "node:dns";
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { networkInterfaces } from "node:os";

/** The opt-out variable (the connect guard reads the same name). */
export const ALLOW_METADATA_ENV = "MANDU_NET_ALLOW_METADATA";

/** Which list refused a dial: the always-denied set (metadata, link-local)
 *  or this machine. */
export type BlockedKind = "always-denied" | "this-machine";

/** What a dial may skip. Both default false (refuse). */
export interface DialPolicy {
  /** `MANDU_NET_ALLOW_METADATA=1`: skip the always-denied set. */
  allowMetadata?: boolean;
  /** Skip the this-machine set. Set ONLY for a mock-sites host route's own
   *  dial and by in-process tests; no environment variable reaches it. */
  allowThisMachine?: boolean;
}

/** A refusal: which list, and what the destination is. */
export interface DialRefusal {
  kind: BlockedKind;
  reason: string;
}

/** The error code a refused dial carries, so callers can answer 403, not 502. */
export const BLOCKED_DESTINATION_CODE = "EMANDU_BLOCKED_DESTINATION";

/** Metadata service names; they resolve to a blocked IP on their cloud and
 *  nowhere else, but are refused by name so the answer does not depend on DNS. */
const BLOCKED_NAMES: ReadonlyMap<string, string> = new Map([
  ["metadata.google.internal", "cloud metadata endpoint (GCP)"],
  ["metadata.goog", "cloud metadata endpoint (GCP)"],
  ["metadata.azure.internal", "cloud metadata endpoint (Azure)"],
  ["instance-data", "cloud metadata endpoint (AWS)"],
  ["instance-data.ec2.internal", "cloud metadata endpoint (AWS)"],
]);

/** Parse a dotted-quad into its four octets, or null. */
function v4Octets(ip: string): [number, number, number, number] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const n = parts.map((p) => Number(p));
  if (n.some((x, i) => !/^\d{1,3}$/.test(parts[i]!) || x > 255)) return null;
  return n as [number, number, number, number];
}

/** Expand an IPv6 literal to its eight 16-bit groups, or null. Handles `::`
 *  and a trailing dotted-quad (`::ffff:1.2.3.4`). */
function v6Groups(ip: string): number[] | null {
  let s = ip.toLowerCase();
  const pct = s.indexOf("%");
  if (pct >= 0) s = s.slice(0, pct); // zone id (fe80::1%eth0)
  // A trailing dotted-quad becomes its two hex groups.
  const lastColon = s.lastIndexOf(":");
  const maybeV4 = s.slice(lastColon + 1);
  if (maybeV4.includes(".")) {
    const o = v4Octets(maybeV4);
    if (!o) return null;
    s = `${s.slice(0, lastColon + 1)}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parse = (h: string): number[] | null => {
    if (h === "") return [];
    const out: number[] = [];
    for (const g of h.split(":")) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = parse(halves[0]!);
  const rest = halves.length === 2 ? parse(halves[1]!) : [];
  if (!head || !rest) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;
  const fill = 8 - head.length - rest.length;
  if (fill < 0) return null;
  return [...head, ...new Array<number>(fill).fill(0), ...rest];
}

function v4Reason(o: [number, number, number, number], port: number): string | null {
  const [a, b, c, d] = o;
  if (a === 169 && b === 254 && c === 169 && d === 254) return "cloud metadata endpoint";
  if (a === 169 && b === 254 && c === 170 && d === 2) return "container credentials endpoint (ECS)";
  if (a === 169 && b === 254 && c === 170 && d === 23) return "pod identity endpoint (EKS)";
  if (a === 100 && b === 100 && c === 100 && d === 200) return "cloud metadata endpoint (Alibaba Cloud)";
  if (a === 169 && b === 254 && port !== 53) return "link-local address";
  return null;
}

/**
 * Is `ip:port` always denied? Returns what it is (for the refusal), else null.
 * Mirrors guard.rs: metadata / credential endpoints on every port, the rest of
 * link-local on every port but 53. v4-mapped (`::ffff:a.b.c.d`) and NAT64
 * (`64:ff9b::a.b.c.d`) forms are unwrapped first. A string that is not an IP
 * literal returns null (names go through `blockedHostReason` / the lookup).
 */
export function blockedAddressReason(ip: string, port: number): string | null {
  const bare = ip.startsWith("[") && ip.endsWith("]") ? ip.slice(1, -1) : ip;
  const kind = isIP(bare.split("%")[0]!);
  if (kind === 4) {
    const o = v4Octets(bare);
    return o ? v4Reason(o, port) : null;
  }
  if (kind !== 6) return null;
  const g = v6Groups(bare);
  if (!g) return null;
  const embedded = (): [number, number, number, number] => [g[6]! >> 8, g[6]! & 0xff, g[7]! >> 8, g[7]! & 0xff];
  // ::ffff:a.b.c.d (v4-mapped) and 64:ff9b::a.b.c.d (NAT64 well-known prefix).
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return v4Reason(embedded(), port);
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return v4Reason(embedded(), port);
  const isAwsV6 = g[0] === 0xfd00 && g[1] === 0xec2 && g.slice(2, 7).every((x) => x === 0);
  if (isAwsV6 && g[7] === 0x254) return "cloud metadata endpoint (AWS IPv6)";
  if (isAwsV6 && g[7] === 0x23) return "pod identity endpoint (EKS IPv6)";
  if ((g[0]! & 0xffc0) === 0xfe80 && port !== 53) return "link-local address";
  return null;
}

// ── this machine (2026-10-05) ───────────────────────────────────────────────

/** Names that mean this machine on every resolver (RFC 6761 §6.3: `localhost`
 *  and every name under it; the Debian/Ubuntu `/etc/hosts` aliases). Refused
 *  by name so the answer does not depend on the resolver; any other name
 *  that resolves here is caught by the lookup. */
const THIS_MACHINE_NAMES = new Set(["localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"]);

/** The host as a socket dials it: an IPv6 literal without its `[brackets]`
 *  (Node's `net.connect` and `http.request` take the bare address and look a
 *  bracketed one up as a name, which fails), anything else unchanged. The
 *  always-denied and this-machine checks read either form. Pure. */
export function dialHostOf(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

/** Strip `[brackets]` and a zone id. */
function bareIp(ip: string): string {
  return (ip.startsWith("[") && ip.endsWith("]") ? ip.slice(1, -1) : ip).split("%")[0]!;
}

/** A canonical key for an address, so `::FFFF:7f00:1` and `::ffff:127.0.0.1`
 *  compare equal: a v4 (or v4-mapped) address as its dotted quad, any other
 *  v6 address as its eight groups. null = not an IP literal. */
export function addressKey(ip: string): string | null {
  const bare = bareIp(ip);
  const kind = isIP(bare);
  if (kind === 4) {
    const o = v4Octets(bare);
    return o ? o.join(".") : null;
  }
  if (kind !== 6) return null;
  const g = v6Groups(bare);
  if (!g) return null;
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
    return [g[6]! >> 8, g[6]! & 0xff, g[7]! >> 8, g[7]! & 0xff].join(".");
  }
  return g.map((x) => x.toString(16)).join(":");
}

/** A range this machine delivers to itself: 16 bytes (an IPv4 range in its
 *  v4-mapped form, `::ffff:a.b.c.d`, its length + 96) and a prefix length. */
export interface LocalRange {
  bytes: readonly number[];
  len: number;
}

/** This machine, for one address family: its addresses (`addressKey`s) and
 *  the ranges its routing tables deliver to itself. */
export interface LocalAddresses {
  keys: ReadonlySet<string>;
  ranges: readonly LocalRange[];
}

/** The source of `LocalAddresses` (injectable for tests), asked for the
 *  family of the address being checked (4 for a v4-mapped or v4-compatible
 *  one). Throwing = it cannot be read. */
export type LocalAddressSource = (family: 4 | 6) => LocalAddresses;

/** The addresses of this machine's interfaces as `os.networkInterfaces()`
 *  lists them. libuv lists only an interface that is up AND running, so the
 *  address of one that is down, or up with no carrier (a container bridge
 *  with no container), is not here: on Linux the routing tables add it
 *  (`liveLocalAddresses`). */
export function localInterfaceKeys(): Set<string> {
  const out = new Set<string>();
  for (const list of Object.values(networkInterfaces())) {
    for (const a of list ?? []) {
      const k = addressKey(a.address);
      if (k) out.add(k);
    }
  }
  return out;
}

/** The 16 bytes of eight 16-bit groups. */
function groupBytes(g: readonly number[]): number[] {
  return g.flatMap((x) => [x >> 8, x & 0xff]);
}

/** The 16 bytes of an IPv4 address in its v4-mapped form. */
function mappedBytes(o: readonly number[]): number[] {
  return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ...o];
}

/** The 16 bytes of a 32-hex address in network byte order (`/proc/net/
 *  if_inet6`, `/proc/net/ipv6_route`), or null. */
function hexBytes(hex: string): number[] | null {
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) return null;
  const out: number[] = [];
  for (let i = 0; i < 32; i += 2) out.push(Number.parseInt(hex.slice(i, i + 2), 16));
  return out;
}

/** The `addressKey` of 16 address bytes (a v4-mapped one as its quad). */
export function bytesKey(b: readonly number[]): string {
  if (b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff) return b.slice(12).join(".");
  const g: number[] = [];
  for (let i = 0; i < 16; i += 2) g.push((b[i]! << 8) | b[i + 1]!);
  return g.map((x) => x.toString(16)).join(":");
}

/** Do the first `r.len` bits of `b` equal `r`'s? */
function inRange(b: readonly number[], r: LocalRange): boolean {
  let bits = r.len;
  for (let i = 0; i < 16 && bits > 0; i++, bits -= 8) {
    const mask = bits >= 8 ? 0xff : (0xff << (8 - bits)) & 0xff;
    if ((b[i]! & mask) !== (r.bytes[i]! & mask)) return false;
  }
  return true;
}

/** The fib_trie tables an ordinary connect consults (the default rules:
 *  local, main, default). A `local` route in any other table applies only
 *  through a policy rule (a firewall mark, a source address): a transparent
 *  proxy's `local 0.0.0.0/0 dev lo table 100` is one, and counting it would
 *  make every address this machine. */
const CONSULTED_TABLE = /^(Local|Main|Id 253):$/;

/**
 * The ranges `/proc/net/fib_trie` says this machine delivers to itself: every
 * prefix of type LOCAL in the local, main and default tables. That is every
 * IPv4 address of every interface, up or down, every `127.0.0.0/8`-style
 * route, and a `local` route with no interface address (`ip route add local
 * 10.99.0.0/16 dev lo`, AnyIP). The local table is what the kernel asks when
 * a socket binds (`inet_addr_type`), so this is the connect guard's bind test
 * (`guard_flow.rs::this_machine`) read as a table. Throws when the text names
 * none of those tables (not a format this parser knows: fail-closed). PURE.
 *
 * Shape: a table header at column 0 (`Local:`, `Main:`, `Id 52:`), indented
 * `+-- a.b.c.d/n ...` inner nodes, `|-- a.b.c.d` leaves, each followed by
 * one line per prefix of that key: `/len scope TYPE [tos=..]`.
 */
export function localRangesFromFibTrie(text: string): LocalRange[] {
  const out: LocalRange[] = [];
  let sawTable = false;
  let consulted = false;
  let leaf: [number, number, number, number] | null = null;
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    if (/^\S/.test(line)) {
      consulted = CONSULTED_TABLE.test(line.trim());
      if (consulted) sawTable = true;
      leaf = null;
      continue;
    }
    const l = /^\s*\|-- (\S+)\s*$/.exec(line);
    if (l) {
      leaf = v4Octets(l[1]!);
      continue;
    }
    const a = /^\s*\/(\d+) \S+ ([A-Z]+)\b/.exec(line);
    if (a) {
      const len = Number(a[1]);
      if (consulted && leaf && a[2] === "LOCAL" && len <= 32) out.push({ bytes: mappedBytes(leaf), len: len + 96 });
      continue;
    }
    leaf = null; // an inner node (`+-- ...`) ends the leaf
  }
  if (!sawTable) throw new Error("/proc/net/fib_trie lists no local or main table");
  return out;
}

const RTF_ANYCAST = 0x00100000;
const RTF_LOCAL = 0x80000000;

/**
 * The ranges `/proc/net/ipv6_route` says this machine delivers to itself:
 * every route flagged RTF_LOCAL (an address of an interface, a `local` route
 * such as `ip -6 route add local 2001:db8::/64 dev lo`) or RTF_ANYCAST (the
 * subnet-router anycast address of a prefix on an interface, delivered
 * here). The file has no table column, so a catch-all `local ::/0` (only a
 * transparent proxy's policy table holds one) is left out rather than
 * making every address this machine. PURE.
 *
 * Shape: `dest(32 hex, network order) dest_len(hex) src src_len next_hop
 * metric refcnt use flags(hex) dev`.
 */
export function localRangesFromIpv6Route(text: string): LocalRange[] {
  const out: LocalRange[] = [];
  for (const line of text.split("\n")) {
    const t = line.trim().split(/\s+/);
    if (t.length < 10) continue;
    const bytes = hexBytes(t[0]!);
    const len = Number.parseInt(t[1]!, 16);
    const flags = Number.parseInt(t[8]!, 16);
    if (!bytes || !Number.isFinite(len) || len < 1 || len > 128 || !Number.isFinite(flags)) continue;
    if ((flags & (RTF_LOCAL | RTF_ANYCAST)) === 0) continue;
    out.push({ bytes, len });
  }
  return out;
}

/** Every address `/proc/net/if_inet6` lists (every interface, up or down,
 *  tentative ones included), as `addressKey`s. PURE. Shape: `addr(32 hex,
 *  network order) ifindex prefix_len scope flags dev`. */
export function keysFromIfInet6(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split("\n")) {
    const b = hexBytes(line.trim().split(/\s+/)[0] ?? "");
    if (b) out.push(bytesKey(b));
  }
  return out;
}

/**
 * The live source, read on every check (interfaces and routes come and go;
 * each /proc read is ~0.1 ms, the interface list ~2 ms on a host with many
 * container interfaces). The interface list everywhere; on Linux also, for
 * an IPv4 address, `/proc/net/fib_trie`'s local prefixes, and for an IPv6
 * one, every address in `/proc/net/if_inet6` and `/proc/net/ipv6_route`'s
 * local and anycast routes. FAIL-CLOSED: an unreadable table throws (every
 * address of that family is then refused), except a missing `if_inet6`,
 * which means this kernel has no IPv6 stack (`ipv6.disable=1`), where no
 * IPv6 address reaches anything. Other systems: the interface list alone
 * (exec-routing.md §7.5, residuals).
 */
export const liveLocalAddresses: LocalAddressSource = (family) => {
  const keys = localInterfaceKeys();
  if (process.platform !== "linux") return { keys, ranges: [] };
  if (family === 4) return { keys, ranges: localRangesFromFibTrie(readFileSync("/proc/net/fib_trie", "latin1")) };
  let inet6: string;
  try {
    inet6 = readFileSync("/proc/net/if_inet6", "latin1");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return { keys, ranges: [] };
    throw err;
  }
  for (const k of keysFromIfInet6(inet6)) keys.add(k);
  return { keys, ranges: localRangesFromIpv6Route(readFileSync("/proc/net/ipv6_route", "latin1")) };
};

/**
 * Is the IP literal `ip` this machine? Returns what it is, else null:
 * loopback (127.0.0.0/8, ::1), the unspecified address and the rest of
 * 0.0.0.0/8 (Linux dials 0.0.0.0 as loopback), each in plain, v4-mapped
 * (`::ffff:127.0.0.1`) and v4-compatible (`::127.0.0.1`) dress, any address
 * of this machine's interfaces (its LAN address, a container bridge's
 * gateway, in any of those dresses), and any address in a range its routing
 * tables deliver to itself (`liveLocalAddresses`: a down interface's
 * address, a `local` route). FAIL-CLOSED: when this machine's addresses
 * cannot be read, every address is refused (the proxy cannot tell this
 * machine from another). A string that is not an IP literal returns null.
 * The special-purpose ranges, one by one: exec-routing.md §7.5.
 */
export function thisMachineAddressReason(ip: string, local: LocalAddressSource = liveLocalAddresses): string | null {
  const bare = bareIp(ip);
  const kind = isIP(bare);
  let v4: [number, number, number, number] | null = null;
  let g: number[] | null = null;
  if (kind === 4) {
    v4 = v4Octets(bare);
    if (!v4) return null;
  } else if (kind === 6) {
    g = v6Groups(bare);
    if (!g) return null;
    if (g.every((x) => x === 0)) return "the unspecified address";
    if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return "loopback address";
    if (g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0)) {
      v4 = [g[6]! >> 8, g[6]! & 0xff, g[7]! >> 8, g[7]! & 0xff];
    }
  } else {
    return null;
  }
  if (v4 && v4[0] === 127) return "loopback address";
  if (v4 && v4[0] === 0) return "the unspecified address";
  let here: LocalAddresses;
  try {
    here = local(v4 ? 4 : 6);
  } catch (err) {
    return `this machine's addresses cannot be listed (${(err as Error).message}), so no address can be told apart from them`;
  }
  const key = addressKey(bare);
  if ((key !== null && here.keys.has(key)) || (v4 && here.keys.has(v4.join(".")))) return "an address of this machine's own interfaces";
  const bytes = v4 ? mappedBytes(v4) : groupBytes(g!);
  if (here.ranges.some((r) => inRange(bytes, r))) return "an address this machine's routing table delivers to itself";
  return null;
}

/** The host as written, for the this-machine set: a `localhost` name (case
 *  and a trailing dot ignored, any name under `.localhost`) or an IP literal
 *  of this machine. null = not refused here (a name still goes through the
 *  lookup). */
export function thisMachineHostReason(host: string, local: LocalAddressSource = liveLocalAddresses): string | null {
  const h = host.trim().toLowerCase().replace(/\.$/, "");
  if (THIS_MACHINE_NAMES.has(h) || h.endsWith(".localhost")) return "a name for this machine";
  return thisMachineAddressReason(h, local);
}

/** The refusal of `host:port` as written under `policy`, else null: the
 *  always-denied set first, then this machine. */
export function dialRefusal(
  host: string,
  port: number,
  policy: DialPolicy = {},
  local: LocalAddressSource = liveLocalAddresses,
): DialRefusal | null {
  if (!policy.allowMetadata) {
    const why = blockedHostReason(host, port);
    if (why) return { kind: "always-denied", reason: why };
  }
  if (!policy.allowThisMachine) {
    const why = thisMachineHostReason(host, local);
    if (why) return { kind: "this-machine", reason: why };
  }
  return null;
}

/** The refusal of one RESOLVED address under `policy`, else null. */
function addressRefusal(ip: string, port: number, policy: DialPolicy, local: LocalAddressSource): DialRefusal | null {
  if (!policy.allowMetadata) {
    const why = blockedAddressReason(ip, port);
    if (why) return { kind: "always-denied", reason: why };
  }
  if (!policy.allowThisMachine) {
    const why = thisMachineAddressReason(ip, local);
    if (why) return { kind: "this-machine", reason: why };
  }
  return null;
}

/** The host as written in a request line or CONNECT target: a literal IP (v6
 *  bracketed or bare) or a known metadata name. Case and a trailing dot are
 *  ignored. null = not refused here (a name still goes through the lookup). */
export function blockedHostReason(host: string, port: number): string | null {
  const h = host.trim().toLowerCase().replace(/\.$/, "");
  return BLOCKED_NAMES.get(h) ?? blockedAddressReason(h, port);
}

/** A refusal of one dial, carrying `BLOCKED_DESTINATION_CODE`. */
export class BlockedDestinationError extends Error {
  readonly code = BLOCKED_DESTINATION_CODE;
  constructor(readonly host: string, readonly reason: string, readonly kind: BlockedKind = "always-denied") {
    super(
      kind === "this-machine"
        ? `destination ${host} is this machine (${reason}): the egress proxy does not relay to this machine's ` +
            "own services; a local service is reached directly, where the connect guard decides"
        : `destination ${host} is always denied (${reason}); set ${ALLOW_METADATA_ENV}=1 to allow it for this launch`,
    );
  }

  /** The fixed kind the refusal note carries (arbiter EGRESS_REFUSAL_KINDS). */
  get refusalKind(): "blocked-destination" | "this-machine" {
    return this.kind === "this-machine" ? "this-machine" : "blocked-destination";
  }

  static of(host: string, r: DialRefusal): BlockedDestinationError {
    return new BlockedDestinationError(host, r.reason, r.kind);
  }
}

export function isBlockedDestinationError(err: unknown): err is BlockedDestinationError {
  return (err as { code?: unknown } | null)?.code === BLOCKED_DESTINATION_CODE;
}

type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

/**
 * A `lookup` for `net.connect` / `tls.connect` / `http.request` that resolves
 * the name, refuses the dial if ANY answer is refused under `policy` (an
 * always-denied address or this machine: a name that points even partly at
 * one is hostile), and otherwise hands Node exactly the answers it checked.
 * Handles both the one-address and the `all: true` callback shapes (Node ≥ 20
 * asks for all when it races families). A resolver error fails the dial:
 * nothing is dialed.
 */
export function guardedLookup(
  port: number,
  policy: DialPolicy = {},
  local: LocalAddressSource = liveLocalAddresses,
): (
  hostname: string,
  options: LookupOneOptions | LookupAllOptions,
  callback: LookupCallback,
) => void {
  return (hostname, options, callback) => {
    const named = dialRefusal(hostname, port, policy, local);
    if (named) {
      callback(BlockedDestinationError.of(hostname, named) as NodeJS.ErrnoException, "", 4);
      return;
    }
    dnsLookup(hostname, { ...options, all: true }, (err, addrs) => {
      if (err) return callback(err, "", 4);
      for (const a of addrs) {
        const why = addressRefusal(a.address, port, policy, local);
        if (why) return callback(BlockedDestinationError.of(`${hostname} (${a.address})`, why) as NodeJS.ErrnoException, "", 4);
      }
      if ((options as LookupAllOptions).all) return callback(null, addrs);
      const first = addrs[0];
      if (!first) return callback(Object.assign(new Error(`no address for ${hostname}`), { code: "ENOTFOUND" }), "", 4);
      callback(null, first.address, first.family);
    });
  };
}

/**
 * What every dial site calls on the host it ACTUALLY dials (after any
 * rewrite): throws `BlockedDestinationError` when the host as written is
 * refused under `policy` (a literal IP never reaches a `lookup`, so this is
 * its only check), else returns the options to spread into the dial: the
 * checking `lookup`, or nothing when the policy skips both sets.
 */
export function guardDial(
  host: string,
  port: number,
  policy: DialPolicy = {},
): { lookup?: ReturnType<typeof guardedLookup> } {
  const refused = dialRefusal(host, port, policy);
  if (refused) throw BlockedDestinationError.of(host, refused);
  if (policy.allowMetadata && policy.allowThisMachine) return {};
  return { lookup: guardedLookup(port, policy) };
}
