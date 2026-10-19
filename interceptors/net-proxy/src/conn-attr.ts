/**
 * conn-attr — map a TCP connection (clientSrc + proxyAddr endpoints) to the
 * CONNECTING process's proc key, for the UNPRIVILEGED net-proxy taint backstop.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): a faithful TypeScript port of
 * interceptors/net-supervisor/src/conn_attr.rs (the Rust /proc baseline). The
 * pure parsers (parseProcNetTcpLine / inodeForSocketLink / pidForInode) mirror
 * the Rust functions of the same names; attributeConnection mirrors the Rust
 * `attribute_connection`. provisionalProcKey REPLICATES the `${pid}-${starttime}`
 * format from interceptors/exec-wrap/src/lineage.ts (net-proxy is a separate
 * package and must not cross-import exec-wrap).
 *
 * BASELINE = /proc scan: parse /proc/net/tcp (and /proc/net/tcp6, 2026-10-17)
 * for the row whose (local == clientSrc) AND (rem == proxyAddr) → socket INODE →
 * scan /proc/<pid>/fd/* for `socket:[inode]` → owning pid → `${pid}-${starttime}`.
 * Privilege-free: /proc/net/tcp{,6} are world-readable; /proc/<pid>/fd is
 * readable for SAME-USER processes (the agent's curl is same-user as the proxy).
 *
 * IPv6 (2026-10-17): a client on an AF_INET6 socket has its row in tcp6
 * only, whether it dialed `::1` or a v4-mapped `::ffff:127.0.0.1` (the proxy
 * then sees a plain IPv4 peer). Both tables are read, the IPv4 one first for
 * an IPv4 peer, and addresses compare by `addressKey` (a v4-mapped address
 * as its dotted quad), so either spelling of either end matches. The
 * inode → pid half is family-blind: the same descriptor-table scan, the same
 * owner checks. Before this a v6 client was never attributed, so it was
 * refused while the session held a secret (fail-closed) and a program could
 * make its connection unattributable on purpose.
 *
 * DIRECTION (load-bearing — mirrors conn_attr.rs): the proxy accept()s a
 * connection FROM the client. req.socket.remoteAddress:remotePort = the client's
 * source endpoint (clientSrc); req.socket.localAddress:localPort = this proxy's
 * accept endpoint (proxyAddr). The connecting process's /proc/net/tcp row has
 * local == clientSrc and rem == proxyAddr. (In conn_attr.rs the proxy endpoint is
 * called `original_dst` because TPROXY rewrites it; here, as a FORWARD proxy, the
 * proxy's own accept endpoint IS the destination from the client's view.)
 *
 * HONEST LIMITS (design §6.A): the /proc scan RACES short-lived clients (the row
 * or fd may be gone before we scan) and is O(#fds). On ANY miss we return
 * undefined and the caller keeps today's behaviour (no tag / no taint query) — we
 * NEVER fabricate a wrong key. This baseline is the PERMANENT mechanism: eBPF
 * (sock→pid at connect), the robust alternative, needs root/CAP_BPF and is
 * DECIDED — WILL NOT IMPLEMENT (2026-07-16; non-root principle,
 * privilege-model.md §0 — not deferred work).
 */

import { closeSync, openSync, readFileSync, readSync, readdirSync, readlinkSync, statSync } from "node:fs";
import { endianness } from "node:os";

import { addressKey, bytesKey } from "./blocked-destinations.js";

/** Does this host print /proc/net/tcp{,6} words little-endian? (The kernel
 *  prints each 32-bit address word as a host-order integer.) */
const HOST_LE = endianness() === "LE";

/** An IP:port endpoint (an IPv4 dotted quad or an IPv6 literal, as Node
 *  reports a socket's address, + numeric port). */
export interface Endpoint {
  ip: string;
  port: number;
}

/** A parsed /proc/net/tcp{,6} row (only the fields attribution needs). An
 *  address is its `addressKey` (blocked-destinations.ts): a v4 or v4-mapped
 *  one as its dotted quad, any other v6 one as its eight hex groups. */
export interface ProcNetTcpRow {
  localIp: string;
  localPort: number;
  remIp: string;
  remPort: number;
  inode: number;
}

/** A (pid, fd-symlink-target) pair from a /proc/<pid>/fd scan. */
export interface FdEntry {
  pid: number;
  target: string;
}

/**
 * Parse ONE /proc/net/tcp or /proc/net/tcp6 data line into a row. Returns null
 * for the header, a blank line, or any line missing the fields we need. PURE
 * (no I/O). Line shape (whitespace-separated):
 *   sl: local_address rem_address st tx:rx tr tm->when retrnsmt uid timeout inode ...
 * local/rem are `HHHHHHHH:PPPP` (tcp) or `HHHHHHHH×4:PPPP` (tcp6): each 32-bit
 * address word in HOST byte order (`littleEndian`, default this host's), the
 * port big-endian hex. inode is the 10th token AFTER the `sl:`.
 */
export function parseProcNetTcpLine(line: string, littleEndian = HOST_LE): ProcNetTcpRow | null {
  const toks = line.trim().split(/\s+/);
  // toks[0] = "0:" (slot index, colon-suffixed). The header's first token is "sl".
  if (toks.length < 10) return null;
  const sl = toks[0];
  if (!sl || !sl.endsWith(":")) return null; // header / garbage
  const local = toks[1];
  const rem = toks[2];
  // toks[3]=st, [4]=tx:rx, [5]=tr:tm->when, [6]=retrnsmt, [7]=uid, [8]=timeout,
  // [9]=inode.
  const inodeTok = toks[9];
  const inode = Number.parseInt(inodeTok, 10);
  if (!Number.isFinite(inode)) return null;
  const localEp = parseHexEndpoint(local, littleEndian);
  const remEp = parseHexEndpoint(rem, littleEndian);
  if (!localEp || !remEp) return null;
  return {
    localIp: localEp.ip,
    localPort: localEp.port,
    remIp: remEp.ip,
    remPort: remEp.port,
    inode,
  };
}

/** The four bytes of one /proc/net address word (8 hex), in address order:
 *  a host-order integer, so little-endian means the low byte first. */
function wordBytes(hex: string, littleEndian: boolean): number[] | null {
  if (!/^[0-9a-fA-F]{8}$/.test(hex)) return null;
  const raw = Number.parseInt(hex, 16);
  const be = [(raw >>> 24) & 0xff, (raw >>> 16) & 0xff, (raw >>> 8) & 0xff, raw & 0xff];
  return littleEndian ? be.reverse() : be;
}

/**
 * Parse a /proc/net/tcp{,6} endpoint: `HHHHHHHH:PPPP` (IPv4: one word) or
 * 32 hex `:PPPP` (IPv6: four words, each in host byte order, so `::1` prints
 * `00000000000000000000000001000000` on a little-endian host and
 * `::ffff:127.0.0.1` prints `0000000000000000FFFF00000100007F`). The address
 * comes back as its `addressKey` (a v4-mapped one as its dotted quad). The
 * port is big-endian hex. null for anything else.
 */
export function parseHexEndpoint(s: string | undefined, littleEndian = HOST_LE): Endpoint | null {
  if (!s) return null;
  const idx = s.indexOf(":");
  if (idx < 0) return null;
  const ipHex = s.slice(0, idx);
  const portHex = s.slice(idx + 1);
  if (!/^[0-9a-fA-F]{1,4}$/.test(portHex)) return null;
  const port = Number.parseInt(portHex, 16);
  let ip: string;
  if (ipHex.length === 8) {
    const b = wordBytes(ipHex, littleEndian);
    if (!b) return null;
    ip = b.join(".");
  } else if (ipHex.length === 32) {
    const bytes: number[] = [];
    for (let w = 0; w < 4; w++) {
      const b = wordBytes(ipHex.slice(w * 8, w * 8 + 8), littleEndian);
      if (!b) return null;
      bytes.push(...b);
    }
    ip = bytesKey(bytes);
  } else {
    return null;
  }
  return { ip, port };
}

/**
 * Extract the inode from a /proc/<pid>/fd/<n> socket symlink target
 * (`socket:[12345]`). null for non-socket targets (files / pipes / anon_inode).
 */
export function inodeForSocketLink(target: string): number | null {
  const m = /^socket:\[(\d+)\]$/.exec(target);
  if (!m) return null;
  const n = Number.parseInt(m[1], 10);
  return Number.isFinite(n) ? n : null;
}

/**
 * Given fd entries, return the FIRST pid owning a `socket:[inode]` fd matching
 * `inode`. PURE (the caller supplies the fd table; production scans /proc live).
 */
export function pidForInode(inode: number, fds: Iterable<FdEntry>): number | null {
  for (const { pid, target } of fds) {
    if (inodeForSocketLink(target) === inode) return pid;
  }
  return null;
}

/**
 * Derive the proc key `${pid}-${starttime}` for `pid` (starttime = field 22 of
 * /proc/<pid>/stat, in clock ticks; defeats pid reuse). The `comm` field (field
 * 2) is parenthesized and may contain spaces/parens, so we split AFTER the last
 * ')'. On ANY failure, fall back to the bare `${pid}`.
 *
 * FORMAT CONTRACT: byte-identical to interceptors/exec-wrap/src/lineage.ts
 * `provisionalProcKey`, and must stay in sync with the Rust
 * mandu_arbiter::proc::proc_key_from (the kernel-side key). REPLICATED, not
 * imported (net-proxy is a standalone package). `readStat` is injectable for unit
 * tests; production reads /proc/<pid>/stat.
 */
export function provisionalProcKey(
  pid: number,
  readStat: (pid: number) => string = (p) => readFileSync(`/proc/${p}/stat`, "utf8"),
): string {
  try {
    const stat = readStat(pid);
    // Split AFTER the last ')'. Fields after that are space-separated; starttime
    // is field 22 overall → index 19 of the post-')' remainder (state is 1st).
    const afterComm = stat.slice(stat.lastIndexOf(")") + 2);
    const fields = afterComm.split(" ");
    const starttime = fields[19]; // field 22 overall (1-based)
    if (starttime !== undefined && starttime !== "") return `${pid}-${starttime}`;
  } catch {
    // fall through to the bare-pid key
  }
  return `${pid}`;
}

/** Injectable /proc accessors so attributeConnection is unit-testable without
 * real /proc. Production defaults read /proc live (same-user, privilege-free). */
export interface ProcDeps {
  /** Read /proc/net/tcp (the IPv4 table). */
  readTcp: () => string;
  /** Read /proc/net/tcp6 (an AF_INET6 client's row, a v4-mapped one
   *  included). Absent: only `readTcp` is searched. */
  readTcp6?: () => string;
  /** List every (pid, fd-target) across /proc/<pid>/fd/*. */
  listFds: () => FdEntry[];
  /** Read /proc/<pid>/stat for provisionalProcKey. */
  readStat: (pid: number) => string;
  /** The client end's socket inode, found without reading the whole table
   *  (the live form stops at the row). Absent: parsed from `readTcp()`. */
  socketInode?: (clientSrc: Endpoint, proxyAddr: Endpoint) => number | null;
}

/** An endpoint's address as a row carries it (`addressKey`; the string as
 *  given when it is not an IP literal, which then matches no row). */
function endpointKey(ip: string): string {
  return addressKey(ip) ?? ip;
}

/** Is an address key an IPv4 one (a dotted quad)? */
function isV4Key(key: string): boolean {
  return key.includes(".");
}

/** A test for the client's end of a proxied connection (local ==
 *  clientSrc, rem == proxyAddr), each address compared by `addressKey`. */
function clientRowTest(clientSrc: Endpoint, proxyAddr: Endpoint): (row: ProcNetTcpRow) => boolean {
  const c = endpointKey(clientSrc.ip);
  const p = endpointKey(proxyAddr.ip);
  return (row) => row.localPort === clientSrc.port && row.remPort === proxyAddr.port && row.localIp === c && row.remIp === p;
}

/** The client end's inode from a /proc/net/tcp or tcp6 text: the first
 *  matching row's inode, null when no row matches or the row has inode 0
 *  (TIME_WAIT / orphaned, owned by no descriptor). PURE. */
export function inodeFromTcpText(text: string, clientSrc: Endpoint, proxyAddr: Endpoint, littleEndian = HOST_LE): number | null {
  const isClient = clientRowTest(clientSrc, proxyAddr);
  for (const line of text.split("\n")) {
    const row = parseProcNetTcpLine(line, littleEndian);
    if (row && isClient(row)) return row.inode === 0 ? null : row.inode;
  }
  return null;
}

/** The client end's inode from the two tables' texts: the IPv4 table first
 *  for an IPv4 client (its usual place), then tcp6 (an AF_INET6 socket, a
 *  v4-mapped one included); tcp6 alone for an IPv6 client. PURE given the
 *  readers; a reader that throws fails the lookup (the callers: null). */
function inodeFromTables(readTcp: () => string, readTcp6: (() => string) | undefined, clientSrc: Endpoint, proxyAddr: Endpoint): number | null {
  if (isV4Key(endpointKey(clientSrc.ip))) {
    const v4 = inodeFromTcpText(readTcp(), clientSrc, proxyAddr);
    if (v4 !== null) return v4;
  }
  return readTcp6 ? inodeFromTcpText(readTcp6(), clientSrc, proxyAddr) : null;
}

/** A /proc/net table read whole, "" when missing or unreadable (no row:
 *  unattributed, fail-soft). */
function liveReadTable(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

/** One live table, read in chunks and stopped at the client's row. Throws
 *  when the table cannot be opened. */
function liveTableInode(path: string, clientSrc: Endpoint, proxyAddr: Endpoint): number | null {
  const fd = openSync(path, "r");
  try {
    const buf = Buffer.allocUnsafe(64 * 1024);
    return inodeFromTcpChunks(() => {
      const n = readSync(fd, buf, 0, buf.length, null);
      return n > 0 ? buf.toString("latin1", 0, n) : "";
    }, clientSrc, proxyAddr);
  } finally {
    closeSync(fd);
  }
}

/**
 * The client end's inode from the live /proc/net/tcp and tcp6, each read in
 * chunks and stopped at the matching row. The kernel builds each table by
 * walking its whole established-hash table (~5 ms on a 128-CPU host,
 * whatever the row count), so stopping at the row saves half of that on
 * average, and an IPv4 client found in tcp (the usual case) never costs the
 * tcp6 read. The answer is the full read's: the first matching row (one row
 * per 4-tuple). Throws when a table it needs cannot be opened (tcp6 missing:
 * no IPv6 stack; socketInodeFor: null).
 */
function liveSocketInode(clientSrc: Endpoint, proxyAddr: Endpoint): number | null {
  if (isV4Key(endpointKey(clientSrc.ip))) {
    const v4 = liveTableInode("/proc/net/tcp", clientSrc, proxyAddr);
    if (v4 !== null) return v4;
  }
  return liveTableInode("/proc/net/tcp6", clientSrc, proxyAddr);
}

/** inodeFromTcpText over a table read in chunks (`next()` → the next chunk,
 *  "" at the end), stopping at the first matching row: a row split across
 *  two chunks is joined first. Same answer as the text form on the whole
 *  table. PURE given `next`. */
export function inodeFromTcpChunks(next: () => string, clientSrc: Endpoint, proxyAddr: Endpoint): number | null {
  const isClient = clientRowTest(clientSrc, proxyAddr);
  let carry = "";
  for (;;) {
    const chunk = next();
    if (chunk === "") break;
    const lines = (carry + chunk).split("\n");
    carry = lines.pop() ?? "";
    for (const line of lines) {
      const row = parseProcNetTcpLine(line);
      if (row && isClient(row)) return row.inode === 0 ? null : row.inode;
    }
  }
  return inodeFromTcpText(carry, clientSrc, proxyAddr);
}

/**
 * Whose descriptor tables a scan by this process can open: `euid` when the
 * process holds no effective capability (`CapEff` all zero in `status`, its
 * /proc/self/status), else null (every table is tried). PURE.
 *
 * WHY SKIPPING THE OTHERS READS THE SAME TABLES: /proc/<pid>/fd is a
 * mode-0500 directory owned by the task's dump owner (its effective uid, or
 * the root of its mm's user namespace when it is not dumpable). For a
 * caller with no capability, generic_permission admits only the owner (no
 * group or other bits, no CAP_DAC_* to override), and proc_fd_permission
 * adds only the caller's own thread group. So a table not owned by our euid
 * is one the full scan failed to open with EACCES. A stat of the directory
 * (~2 µs) answers that instead of a failed open (~10 µs in the kernel, for
 * each of ~1500 other users' processes on a shared host). The owner of
 * /proc/<pid> is NOT the test: a non-dumpable process of another uid inside
 * a user namespace we own has /proc/<pid> owned by its uid but an fd
 * directory owned by ours, and we can read it.
 */
export function fdScanOwner(status: string, euid: number): number | null {
  const m = /^CapEff:\s*([0-9a-fA-F]+)\s*$/m.exec(status);
  if (!m || !/^0+$/.test(m[1]!)) return null;
  return euid;
}

let liveOwner: number | null | undefined;
/** fdScanOwner for this process, probed once (an unprivileged process gains
 *  no capability later; a failed probe tries every table). */
function liveFdScanOwner(): number | null {
  if (liveOwner === undefined) {
    try {
      liveOwner = typeof process.geteuid === "function" ? fdScanOwner(readFileSync("/proc/self/status", "utf8"), process.geteuid()) : null;
    } catch {
      liveOwner = null;
    }
  }
  return liveOwner;
}

/**
 * Should a scan limited to `owner`'s tables (fdScanOwner; null = not
 * limited) open /proc/<pid>/fd? `dirUid` reads the directory's owner
 * (undefined = the process is gone; a throw = cannot tell). false only when
 * the owner is known to be another uid and `pid` is not this process. PURE
 * given `dirUid`.
 */
export function fdTableOpenable(pid: number, owner: number | null, dirUid: (pid: number) => number | undefined, self = process.pid): boolean {
  if (owner === null || pid === self) return true;
  let uid: number | undefined;
  try {
    uid = dirUid(pid);
  } catch {
    return true; // cannot tell: try it, as the full scan did
  }
  return uid === undefined ? false : uid === owner;
}

/** The owner of /proc/<pid>/fd, undefined when the process is gone. */
function liveFdDirUid(pid: number): number | undefined {
  return statSync(`/proc/${pid}/fd`, { throwIfNoEntry: false })?.uid;
}

/** The default, live /proc accessors (privilege-free for same-user processes). */
export const liveProcDeps: ProcDeps = {
  readTcp: () => liveReadTable("/proc/net/tcp"),
  readTcp6: () => liveReadTable("/proc/net/tcp6"),
  socketInode: liveSocketInode,
  listFds() {
    const out: FdEntry[] = [];
    let pidDirs: string[];
    try {
      pidDirs = readdirSync("/proc");
    } catch {
      return out;
    }
    const owner = liveFdScanOwner();
    for (const name of pidDirs) {
      const pid = Number.parseInt(name, 10);
      if (!Number.isFinite(pid) || String(pid) !== name) continue; // not a pid dir
      if (!fdTableOpenable(pid, owner, liveFdDirUid)) continue; // gone, or another user's
      let fds: string[];
      try {
        fds = readdirSync(`/proc/${pid}/fd`);
      } catch {
        continue; // EACCES (different user) / gone → skip
      }
      for (const fd of fds) {
        try {
          const target = readlinkSync(`/proc/${pid}/fd/${fd}`);
          out.push({ pid, target });
        } catch {
          // fd closed mid-scan → skip
        }
      }
    }
    return out;
  },
  readStat(pid: number) {
    return readFileSync(`/proc/${pid}/stat`, "utf8");
  },
};

/**
 * Resolve the connecting process's proc key from the two socket endpoints, or
 * undefined on ANY miss (fail-soft — NEVER a wrong key). Mirrors
 * conn_attr.rs::attribute_connection: match the /proc/net/tcp{,6} row where
 * (local == clientSrc) AND (rem == proxyAddr), then inode → pid → proc key.
 *
 * @param clientSrc the client's source endpoint (req.socket.remoteAddress:port)
 * @param proxyAddr this proxy's accept endpoint (req.socket.localAddress:port)
 * @param deps injectable /proc accessors (default: live reads)
 */
export function attributeConnection(
  clientSrc: Endpoint,
  proxyAddr: Endpoint,
  deps: ProcDeps = liveProcDeps,
): string | undefined {
  try {
    const inode = inodeFromTables(deps.readTcp, deps.readTcp6, clientSrc, proxyAddr);
    if (inode === null) return undefined;
    const pid = pidForInode(inode, deps.listFds());
    if (pid === null) return undefined;
    return provisionalProcKey(pid, deps.readStat);
  } catch {
    return undefined; // any unexpected error → fail-soft
  }
}

// ── every holder, with its ancestors (plan 13 D6) ─────────────────────────────

/** One process holding the client's end of a proxied connection: its proc
 *  key and its ancestor chain (nearest first), the shape the arbiter's
 *  `taintedProcessBindings` takes so a fork-only child's lineage edges are
 *  recorded before the lookup (the guard does the same with
 *  `ancestor_keys_of`, net-supervisor secret_open.rs). */
export interface ProcHolder {
  procKey: string;
  ancestors: string[];
}

/** How far up the parent chain a holder's ancestors are read: the guard's
 *  `ancestor_keys_of(pid, 16)`. */
export const ANCESTOR_DEPTH = 16;

/** Every pid owning a `socket:[inode]` fd matching `inode`, each once, in
 *  table order. PURE. A socket is held by every process that inherited the
 *  descriptor (a fork) or received it (SCM_RIGHTS), and any of them may write
 *  the request, so every one is judged (plan 13 D6). */
export function pidsForInode(inode: number, fds: Iterable<FdEntry>): number[] {
  const out: number[] = [];
  for (const { pid, target } of fds) {
    if (inodeForSocketLink(target) === inode && !out.includes(pid)) out.push(pid);
  }
  return out;
}

/** The parent pid from a `/proc/<pid>/stat` line (field 4), or null. */
export function ppidFromStat(stat: string): number | null {
  const after = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
  const ppid = Number.parseInt(after[1] ?? "", 10);
  return Number.isFinite(ppid) ? ppid : null;
}

/** The proc keys of `pid`'s ancestors, nearest first, at most `depth`, up to
 *  (not including) pid 1. Stops at the first unreadable stat. */
export function ancestorKeys(pid: number, readStat: (pid: number) => string, depth = ANCESTOR_DEPTH): string[] {
  const out: string[] = [];
  let cur = pid;
  for (let i = 0; i < depth; i++) {
    let stat: string;
    try {
      stat = readStat(cur);
    } catch {
      break;
    }
    const ppid = ppidFromStat(stat);
    if (ppid === null || ppid <= 1) break;
    out.push(provisionalProcKey(ppid, readStat));
    cur = ppid;
  }
  return out;
}

/**
 * Every process holding the client's end of a proxied connection, each with
 * its ancestor chain. `[]` when the connection cannot be attributed (no row,
 * no holder found, any error): the CALLER decides what an unattributed leg
 * may do (plan 13 D6: refused while any process of the session holds a
 * secret). NEVER a wrong key.
 */
export function attributeHolders(clientSrc: Endpoint, proxyAddr: Endpoint, deps: ProcDeps = liveProcDeps): ProcHolder[] {
  try {
    const inode = deps.socketInode ? deps.socketInode(clientSrc, proxyAddr) : inodeFromTables(deps.readTcp, deps.readTcp6, clientSrc, proxyAddr);
    return inode === null ? [] : holdersOfInode(inode, deps);
  } catch {
    return [];
  }
}

/**
 * Every process holding socket `inode`, each with its ancestor chain: the
 * second half of `attributeHolders`, for a caller that already knows the
 * client end's inode (proxy.ts keeps it per connection: fixed for the
 * connection's life). Nothing about a process is kept between calls: every
 * descriptor table and every stat is read again, so a holder that appeared
 * since, or a pid that now names another process, is seen as it is now.
 * `[]` on any error (unattributed; never a wrong key).
 */
export function holdersOfInode(inode: number, deps: Pick<ProcDeps, "listFds" | "readStat"> = liveProcDeps): ProcHolder[] {
  try {
    return pidsForInode(inode, deps.listFds()).map((pid) => ({
      procKey: provisionalProcKey(pid, deps.readStat),
      ancestors: ancestorKeys(pid, deps.readStat),
    }));
  } catch {
    return [];
  }
}

// ── a tunnel's holders, looked for among the processes holding a secret ──────
// (plan 13 D6, a blind tunnel's chunks, 2026-10-07)

/** The socket inode of the client's end of a proxied connection (its
 *  /proc/net/tcp or tcp6 row: local == clientSrc, rem == proxyAddr), or null
 *  (no row, a TIME_WAIT row with inode 0, any error). Fixed for the life of
 *  the connection, so a caller may keep it. `readTcp` / `readTcp6` replace
 *  the live tables (tests). */
export function socketInodeFor(clientSrc: Endpoint, proxyAddr: Endpoint, readTcp?: () => string, readTcp6?: () => string): number | null {
  try {
    return readTcp ? inodeFromTables(readTcp, readTcp6, clientSrc, proxyAddr) : liveSocketInode(clientSrc, proxyAddr);
  } catch {
    return null;
  }
}

/** The /proc reads `holdersAmong` makes (injectable for unit tests). */
export interface TaintedScanDeps {
  /** /proc/<pid>/stat; throws an ENOENT-coded error when the process is gone. */
  readStat: (pid: number) => string;
  /** The link targets of /proc/<pid>/fd/*; throws when gone or unreadable. */
  readFdsOf: (pid: number) => string[];
  /** The children of every thread of `pid` (/proc/<pid>/task/<tid>/children,
   *  CONFIG_PROC_CHILDREN), `[]` when it is gone; null when this kernel
   *  does not list children at all. */
  childrenOf: (pid: number) => number[] | null;
}

let childrenListed: boolean | undefined;
/** Does this kernel list a task's children (CONFIG_PROC_CHILDREN)? Probed
 *  once, on this process's own main thread. */
function kernelListsChildren(): boolean {
  if (childrenListed === undefined) {
    try {
      readFileSync(`/proc/${process.pid}/task/${process.pid}/children`, "utf8");
      childrenListed = true;
    } catch {
      childrenListed = false;
    }
  }
  return childrenListed;
}

/** The live /proc reads for `holdersAmong` (same-user, privilege-free). */
export const liveTaintedScanDeps: TaintedScanDeps = {
  readStat: (pid) => readFileSync(`/proc/${pid}/stat`, "utf8"),
  readFdsOf(pid) {
    const out: string[] = [];
    for (const fd of readdirSync(`/proc/${pid}/fd`)) {
      try {
        out.push(readlinkSync(`/proc/${pid}/fd/${fd}`));
      } catch {
        // closed mid-scan
      }
    }
    return out;
  },
  childrenOf(pid) {
    if (!kernelListsChildren()) return null;
    let tids: string[];
    try {
      tids = readdirSync(`/proc/${pid}/task`);
    } catch {
      return []; // gone
    }
    const out: number[] = [];
    for (const tid of tids) {
      let text: string;
      try {
        text = readFileSync(`/proc/${pid}/task/${tid}/children`, "utf8");
      } catch {
        continue; // the thread exited
      }
      for (const t of text.split(/\s+/)) {
        const c = Number.parseInt(t, 10);
        if (Number.isFinite(c) && c > 0 && !out.includes(c)) out.push(c);
      }
    }
    return out;
  },
};

/** The pid and start time a proc key names (`${pid}-${starttime}`, or the
 *  bare `${pid}` provisionalProcKey falls back to), or null. */
export function parseProcKey(key: string): { pid: number; starttime?: string } | null {
  const m = /^(\d+)(?:-(\d+))?$/.exec(key);
  if (!m) return null;
  const pid = Number.parseInt(m[1]!, 10);
  if (!Number.isFinite(pid) || pid <= 0) return null;
  return m[2] !== undefined ? { pid, starttime: m[2] } : { pid };
}

function isGone(err: unknown): boolean {
  const code = (err as { code?: string } | null)?.code;
  return code === "ENOENT" || code === "ESRCH";
}

/**
 * The processes holding socket `inode` among `candidates` (proc keys the
 * arbiter answers tainted: `secretTaintedProcesses`) and every live
 * descendant of one (a child forked from a holder of a secret inherits its
 * taint before the arbiter has an edge for it), each with its ancestor
 * chain. The cheap form of `attributeHolders` for a caller that judges only
 * holders of a secret: it reads the fd tables of those processes, not of
 * every process. A candidate whose process is gone (or whose pid now names
 * another process: another start time) is added to `dead`, which the caller
 * keeps across calls: a `${pid}-${starttime}` key never comes back.
 *
 * null when this cannot answer (the kernel lists no children, a stat read
 * failed for another reason than the process being gone): the caller then
 * falls back to the full scan, never to fewer holders. A process whose fd
 * table is unreadable (another user's) is skipped, as the full scan skips
 * it.
 */
export function holdersAmong(
  inode: number,
  candidates: Iterable<string>,
  dead: Set<string>,
  deps: TaintedScanDeps = liveTaintedScanDeps,
): ProcHolder[] | null {
  const roots: number[] = [];
  for (const key of candidates) {
    if (dead.has(key)) continue;
    const parsed = parseProcKey(key);
    if (!parsed) continue; // not a process this host's /proc names
    let stat: string;
    try {
      stat = deps.readStat(parsed.pid);
    } catch (err) {
      if (!isGone(err)) return null;
      if (parsed.starttime !== undefined) dead.add(key);
      continue;
    }
    if (parsed.starttime !== undefined && provisionalProcKey(parsed.pid, () => stat) !== key) {
      dead.add(key); // the pid was reused: that process is gone
      continue;
    }
    if (!roots.includes(parsed.pid)) roots.push(parsed.pid);
  }
  if (roots.length === 0) return [];
  // The live subtree under each root (a fork-only child of a holder of a
  // secret inherits it before any edge is on record).
  const seen = new Set<number>();
  const queue = [...roots];
  while (queue.length > 0) {
    const pid = queue.shift()!;
    if (seen.has(pid)) continue;
    seen.add(pid);
    const kids = deps.childrenOf(pid);
    if (kids === null) return null;
    for (const c of kids) if (!seen.has(c)) queue.push(c);
  }
  const want = `socket:[${inode}]`;
  const out: ProcHolder[] = [];
  for (const pid of seen) {
    let targets: string[];
    try {
      targets = deps.readFdsOf(pid);
    } catch {
      continue; // gone, or another user's (the full scan skips it too)
    }
    if (!targets.includes(want)) continue;
    out.push({ procKey: provisionalProcKey(pid, deps.readStat), ancestors: ancestorKeys(pid, deps.readStat) });
  }
  return out;
}
