/**
 * conn-attr.test — unit tests for the /proc→pid connection-attribution port
 * (src/conn-attr.ts), ported from net-supervisor/src/conn_attr.rs's tests.
 *
 * PURE parsing is tested on synthetic fixtures (the TCP_LINE fixture is lifted
 * VERBATIM from the Rust test so the two impls agree). The live /proc reads in
 * attributeConnection are tested via INJECTED file-reader + fd-lister stubs — no
 * real /proc, no root.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, connect } from "node:net";
import { once } from "node:events";
import { readFileSync, readdirSync, statSync } from "node:fs";

import {
  fdScanOwner,
  fdTableOpenable,
  holdersOfInode,
  inodeFromTcpChunks,
  inodeFromTcpText,
  parseProcNetTcpLine,
  inodeForSocketLink,
  pidForInode,
  provisionalProcKey,
  attributeConnection,
  attributeHolders,
  pidsForInode,
  ppidFromStat,
  ancestorKeys,
  holdersAmong,
  parseProcKey,
  socketInodeFor,
} from "../../src/conn-attr.js";

// A real /proc/net/tcp line, lifted from conn_attr.rs's TCP_LINE so the two
// implementations parse identically. local = 127.0.0.1:80 (0100007F:0050),
// rem = 127.0.0.1:54321 (0100007F:D431), state 01, inode 123456 (10th field
// after the leading "sl:").
const TCP_LINE =
  "   0: 0100007F:0050 0100007F:D431 01 00000000:00000000 " +
  "00:00000000 00000000  1000        0 123456 1 0000000000000000 100 0 0 10 0";

test("parseProcNetTcpLine extracts endpoints + inode (matches the Rust fixture)", () => {
  const row = parseProcNetTcpLine(TCP_LINE);
  assert.ok(row, "line parses");
  assert.equal(row!.localIp, "127.0.0.1"); // 0100007F little-endian → 127.0.0.1
  assert.equal(row!.localPort, 80);
  assert.equal(row!.remIp, "127.0.0.1");
  assert.equal(row!.remPort, 0xd431); // 54321
  assert.equal(row!.inode, 123456);
});

test("parseProcNetTcpLine skips the header and garbage", () => {
  const header =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
  assert.equal(parseProcNetTcpLine(header), null);
  assert.equal(parseProcNetTcpLine(""), null);
  assert.equal(parseProcNetTcpLine("   0: notenoughfields"), null);
});

test("inodeForSocketLink parses socket:[N], rejects non-sockets", () => {
  assert.equal(inodeForSocketLink("socket:[123456]"), 123456);
  assert.equal(inodeForSocketLink("socket:[0]"), 0);
  assert.equal(inodeForSocketLink("/dev/null"), null);
  assert.equal(inodeForSocketLink("pipe:[7]"), null);
  assert.equal(inodeForSocketLink("socket:[]"), null);
});

test("pidForInode finds the first owning pid in a synthetic fd table", () => {
  const fds = [
    { pid: 4242, target: "socket:[123456]" },
    { pid: 4242, target: "/dev/null" },
    { pid: 99, target: "pipe:[7]" },
  ];
  assert.equal(pidForInode(123456, fds), 4242);
  assert.equal(pidForInode(999, fds), null);
});

test("provisionalProcKey is `${pid}-${starttime}` (field 22, comm-parens-safe)", () => {
  // A synthetic /proc/<pid>/stat with a comm that contains spaces AND a ')':
  // "(weird )proc)" — proves the parse splits after the LAST ')'.
  const pid = 4242;
  // Build fields 3..52 ("R" state then placeholders); starttime is field 22
  // overall → index 19 of the post-')' remainder. Set it to 99887766.
  const post = ["R"];
  for (let i = 0; i < 60; i++) post.push("0");
  post[19] = "99887766"; // field 22 overall (state is field 3 / index 0 here)
  const stat = `${pid} (weird )proc) ${post.join(" ")}\n`;
  const readStat = (p: number): string => {
    assert.equal(p, pid);
    return stat;
  };
  assert.equal(provisionalProcKey(pid, readStat), `${pid}-99887766`);
});

test("provisionalProcKey falls back to bare pid when stat is unreadable", () => {
  const readStat = (): string => {
    throw new Error("ENOENT");
  };
  assert.equal(provisionalProcKey(4242, readStat), "4242");
});

test("attributeConnection resolves clientSrc/proxyAddr → row → inode → pid → key", () => {
  // The connecting process's /proc/net/tcp row: local == clientSrc, rem == proxyAddr.
  const clientSrc = { ip: "127.0.0.1", port: 0xd431 }; // 54321
  const proxyAddr = { ip: "127.0.0.1", port: 80 };
  // Synthetic /proc/net/tcp: the matching row has local=clientSrc, rem=proxyAddr,
  // inode 123456. (Reverse of TCP_LINE's local/rem so local==clientSrc.)
  // local = 127.0.0.1:54321 (0100007F:D431), rem = 127.0.0.1:80 (0100007F:0050)
  const tcpText =
    "  sl  local_address rem_address ...\n" +
    "   0: 0100007F:D431 0100007F:0050 01 00000000:00000000 " +
    "00:00000000 00000000  1000        0 123456 1 0000000000000000 100 0 0 10 0\n";
  // Build a stat where field 22 (index 19 post-')') is 555
  const post = ["R"];
  for (let i = 0; i < 60; i++) post.push("0");
  post[19] = "555";
  const statStr = `4242 (curl) ${post.join(" ")}`;
  const deps = {
    readTcp: () => tcpText,
    listFds: () => [{ pid: 4242, target: "socket:[123456]" }],
    readStat: (_p: number) => statStr,
  };
  const key = attributeConnection(clientSrc, proxyAddr, deps);
  assert.equal(key, "4242-555");
});

test("attributeConnection misses (no matching row) → undefined (fail-soft)", () => {
  const deps = {
    readTcp: () => "  sl ...\n   0: 0A0A0A0A:1234 0B0B0B0B:5678 01 00000000:00000000 00:00000000 00000000 1 0 777 1\n",
    listFds: () => [{ pid: 1, target: "socket:[777]" }],
    readStat: (p: number) => `${p} (x) R ${Array(60).fill("0").join(" ")}`,
  };
  assert.equal(attributeConnection({ ip: "127.0.0.1", port: 80 }, { ip: "127.0.0.1", port: 443 }, deps), undefined);
});

test("attributeConnection swallows a /proc read error → undefined (fail-soft)", () => {
  const deps = {
    readTcp: () => {
      throw new Error("EACCES");
    },
    listFds: () => [],
    readStat: () => "",
  };
  assert.equal(attributeConnection({ ip: "1.2.3.4", port: 1 }, { ip: "5.6.7.8", port: 2 }, deps), undefined);
});

// ── plan 13 D6: every holder, with its ancestors ─────────────────────────────

/** A /proc/<pid>/stat line with ppid `ppid` and starttime `start`. */
function statLine(pid: number, comm: string, ppid: number, start: string): string {
  const post = ["S", String(ppid)];
  for (let i = 0; i < 60; i++) post.push("0");
  post[19] = start;
  return `${pid} (${comm}) ${post.join(" ")}`;
}

test("pidsForInode lists EVERY holder of the socket once (a fork shares the descriptor)", () => {
  const fds = [
    { pid: 10, target: "socket:[55]" },
    { pid: 10, target: "socket:[55]" },
    { pid: 11, target: "pipe:[3]" },
    { pid: 12, target: "socket:[55]" },
  ];
  assert.deepEqual(pidsForInode(55, fds), [10, 12]);
  assert.deepEqual(pidsForInode(56, fds), []);
});

test("ppidFromStat / ancestorKeys walk the parent chain (comm-parens-safe), nearest first, stopping before pid 1", () => {
  const stats: Record<number, string> = {
    300: statLine(300, "curl (x)", 200, "3000"),
    200: statLine(200, "bash", 100, "2000"),
    100: statLine(100, "sh", 1, "1000"),
  };
  const readStat = (p: number): string => {
    const s = stats[p];
    if (!s) throw new Error("ENOENT");
    return s;
  };
  assert.equal(ppidFromStat(stats[300]!), 200);
  assert.deepEqual(ancestorKeys(300, readStat), ["200-2000", "100-1000"]);
  assert.deepEqual(ancestorKeys(300, readStat, 1), ["200-2000"], "the depth bound holds");
  assert.deepEqual(ancestorKeys(999, readStat), [], "an unreadable stat ends the chain");
});

test("attributeHolders: row → inode → every holder, each with its ancestors; a miss or an error is [] (never a wrong key)", () => {
  const tcpText =
    "  sl  local_address rem_address ...\n" +
    "   0: 0100007F:D431 0100007F:0050 01 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 100 0 0 10 0\n";
  const stats: Record<number, string> = {
    20: statLine(20, "python3", 10, "222"),
    21: statLine(21, "python3", 20, "333"),
    10: statLine(10, "bash", 1, "111"),
  };
  const deps = {
    readTcp: () => tcpText,
    listFds: () => [{ pid: 20, target: "socket:[123456]" }, { pid: 21, target: "socket:[123456]" }],
    readStat: (p: number) => {
      const s = stats[p];
      if (!s) throw new Error("ENOENT");
      return s;
    },
  };
  assert.deepEqual(attributeHolders({ ip: "127.0.0.1", port: 0xd431 }, { ip: "127.0.0.1", port: 80 }, deps), [
    { procKey: "20-222", ancestors: ["10-111"] },
    { procKey: "21-333", ancestors: ["20-222", "10-111"] },
  ]);
  assert.deepEqual(attributeHolders({ ip: "127.0.0.1", port: 1 }, { ip: "127.0.0.1", port: 80 }, deps), [], "no row");
  assert.deepEqual(attributeHolders({ ip: "127.0.0.1", port: 0xd431 }, { ip: "127.0.0.1", port: 80 }, { ...deps, listFds: () => [] }), [], "no holder");
  assert.deepEqual(attributeHolders({ ip: "1.2.3.4", port: 1 }, { ip: "5.6.7.8", port: 2 }, { ...deps, readTcp: () => { throw new Error("EACCES"); } }), []);
});

// ── holdersAmong (plan 13 D6, a blind tunnel's chunks) ────────────────────

const gone = (): never => {
  throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
};

/** A synthetic process table: pid → { ppid, start, fds }. */
function procTable(t: Record<number, { comm?: string; ppid: number; start: string; fds: string[]; unreadable?: boolean }>) {
  const reads = { stat: 0, fds: 0 };
  const deps = {
    readStat: (p: number): string => {
      reads.stat++;
      const e = t[p];
      if (!e) return gone();
      return statLine(p, e.comm ?? "x", e.ppid, e.start);
    },
    readFdsOf: (p: number): string[] => {
      reads.fds++;
      const e = t[p];
      if (!e) return gone();
      if (e.unreadable) throw Object.assign(new Error("EACCES"), { code: "EACCES" });
      return e.fds;
    },
    childrenOf: (p: number): number[] =>
      t[p] ? Object.entries(t).filter(([, e]) => e.ppid === p).map(([k]) => Number(k)) : [],
  };
  return { deps, reads };
}

test("parseProcKey: `${pid}-${starttime}` and the bare pid; anything else is no process", () => {
  assert.deepEqual(parseProcKey("4242-99"), { pid: 4242, starttime: "99" });
  assert.deepEqual(parseProcKey("4242"), { pid: 4242 });
  for (const k of ["", "x-1", "0-1", "12-ab", "-3", "1-2-3"]) assert.equal(parseProcKey(k), null, k);
});

test("socketInodeFor: the client's row → its inode; no row or a TIME_WAIT row (inode 0) → null", () => {
  const row = (inode: number) =>
    `   0: 0100007F:D431 0100007F:0050 01 00000000:00000000 00:00000000 00000000  1000        0 ${inode} 1 0000000000000000 100 0 0 10 0\n`;
  const c = { ip: "127.0.0.1", port: 0xd431 };
  const p = { ip: "127.0.0.1", port: 80 };
  assert.equal(socketInodeFor(c, p, () => row(123456)), 123456);
  assert.equal(socketInodeFor(c, p, () => row(0)), null);
  assert.equal(socketInodeFor({ ip: "127.0.0.1", port: 1 }, p, () => row(123456)), null);
  assert.equal(socketInodeFor(c, p, () => { throw new Error("EACCES"); }), null);
});

test("holdersAmong: a tainted candidate holding the socket, and a fork-only child of one, are found with their chains; others are not read", () => {
  const S = "socket:[777]";
  const { deps, reads } = procTable({
    10: { ppid: 1, start: "100", fds: [S] }, // the CONNECT's holder (untainted)
    20: { ppid: 10, start: "200", fds: [S] }, // its child, forked after the CONNECT, read a secret
    30: { ppid: 20, start: "300", fds: [S] }, // a fork-only grandchild (no edge on record yet)
    40: { ppid: 1, start: "400", fds: ["pipe:[1]"] }, // a holder of a secret not holding this socket
    50: { ppid: 1, start: "500", fds: [S] }, // an untainted holder: never read
  });
  const dead = new Set<string>();
  const found = holdersAmong(777, ["20-200", "40-400"], dead, deps);
  assert.deepEqual(found, [
    { procKey: "20-200", ancestors: ["10-100"] },
    { procKey: "30-300", ancestors: ["20-200", "10-100"] },
  ]);
  assert.equal(reads.fds, 3, "only the candidates and their subtrees' descriptor tables are read (20, 30, 40)");
  assert.equal(dead.size, 0);
});

test("holdersAmong: a gone candidate or a reused pid is remembered dead and skipped next time; none live → [] with no fd read", () => {
  const { deps, reads } = procTable({ 60: { ppid: 1, start: "999", fds: ["socket:[1]"] } });
  const dead = new Set<string>();
  assert.deepEqual(holdersAmong(1, ["61-100", "60-600"], dead, deps), [], "61 is gone, 60 is another process now");
  assert.deepEqual([...dead].sort(), ["60-600", "61-100"]);
  assert.equal(reads.fds, 0);
  const before = reads.stat;
  assert.deepEqual(holdersAmong(1, ["61-100", "60-600"], dead, deps), []);
  assert.equal(reads.stat, before, "a dead key costs nothing the second time");
  assert.deepEqual(holdersAmong(1, ["60"], dead, deps), [{ procKey: "60-999", ancestors: [] }], "a bare-pid key names whatever process has the pid");
  assert.ok(!dead.has("60"));
});

test("holdersAmong FAIL-CLOSED: no children listing, or a stat error other than gone → null (the caller rescans every holder); an unreadable fd table is skipped like the full scan", () => {
  const { deps } = procTable({ 70: { ppid: 1, start: "7", fds: ["socket:[5]"] }, 71: { ppid: 70, start: "8", fds: ["socket:[5]"], unreadable: true } });
  assert.equal(holdersAmong(5, ["70-7"], new Set(), { ...deps, childrenOf: () => null }), null);
  assert.equal(holdersAmong(5, ["70-7"], new Set(), { ...deps, readStat: () => { throw Object.assign(new Error("EMFILE"), { code: "EMFILE" }); } }), null);
  assert.deepEqual(holdersAmong(5, ["70-7"], new Set(), deps), [{ procKey: "70-7", ancestors: [] }]);
});

test("holdersAmong LIVE: this process holding a real TCP client socket is found by its own key; with no candidate nothing is", async () => {
  if (process.platform !== "linux") return;
  const server = createServer(() => {});
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = (server.address() as { port: number }).port;
  const sock = connect(port, "127.0.0.1");
  await once(sock, "connect");
  try {
    const inode = socketInodeFor({ ip: "127.0.0.1", port: sock.localPort! }, { ip: "127.0.0.1", port });
    assert.ok(inode, "the client's row is in /proc/net/tcp");
    const self = provisionalProcKey(process.pid);
    const found = holdersAmong(inode!, [self], new Set());
    assert.ok(found, "this kernel lists children");
    assert.deepEqual(found!.map((h) => h.procKey), [self]);
    assert.deepEqual(holdersAmong(inode!, [], new Set()), []);
  } finally {
    sock.destroy();
    server.close();
  }
});

// ── the full scan's cost (plan 13 D6, "the full scan's cost") ───────────────

const ROW = (local: string, inode: number): string =>
  `   0: ${local} 0100007F:0050 01 00000000:00000000 00:00000000 00000000  1000        0 ${inode} 1 0000000000000000 100 0 0 10 0`;

test("inodeFromTcpText / inodeFromTcpChunks: the same first matching row, whatever the chunking (a row split across chunks is joined)", () => {
  const c = { ip: "127.0.0.1", port: 0xd431 };
  const p = { ip: "127.0.0.1", port: 80 };
  const lines = ["  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"];
  for (let i = 0; i < 300; i++) {
    if (i === 150) lines.push(ROW("0100007F:D431", 123456)); // mid-table
    lines.push(ROW(`0100007F:${(0x1000 + i).toString(16).toUpperCase()}`, 9000 + i));
  }
  lines.push(ROW("0100007F:D431", 777)); // a later duplicate: the first match wins
  const table = lines.join("\n") + "\n";
  assert.equal(inodeFromTcpText(table, c, p), 123456);
  for (const size of [1, 7, 149, 150, 4096, table.length, table.length + 10]) {
    let at = 0;
    const got = inodeFromTcpChunks(() => {
      const s = table.slice(at, at + size);
      at += size;
      return s;
    }, c, p);
    assert.equal(got, 123456, `chunk ${size}`);
    if (size === 4096) assert.ok(at < table.length, "stops at the row, before the end of the table");
  }
  // No trailing newline: the last row is still read. A TIME_WAIT row: null.
  assert.equal(inodeFromTcpChunks(((done = false) => () => (done ? "" : ((done = true), ROW("0100007F:D431", 5))))(), c, p), 5);
  assert.equal(inodeFromTcpText(ROW("0100007F:D431", 0), c, p), null);
  assert.equal(inodeFromTcpText(table, { ip: "127.0.0.1", port: 1 }, p), null);
});

test("attributeHolders uses the deps' own inode lookup when given one (the live form stops at the row), the table text otherwise", () => {
  const deps = {
    readTcp: (): string => { throw new Error("the table is not read when socketInode is given"); },
    socketInode: () => 42,
    listFds: () => [{ pid: 20, target: "socket:[42]" }],
    readStat: (p: number) => statLine(p, "curl", 1, "5"),
  };
  assert.deepEqual(attributeHolders({ ip: "127.0.0.1", port: 1 }, { ip: "127.0.0.1", port: 2 }, deps), [{ procKey: "20-5", ancestors: [] }]);
  assert.deepEqual(attributeHolders({ ip: "127.0.0.1", port: 1 }, { ip: "127.0.0.1", port: 2 }, { ...deps, socketInode: () => null }), [], "no row → unattributed");
});

test("holdersOfInode keeps nothing between calls: a holder that appears, and a pid reused by another process, are seen as they are now", () => {
  const S = "socket:[555]";
  let table: Record<number, { start: string; ppid: number; fds: string[] }> = {
    20: { start: "222", ppid: 10, fds: [S] },
    10: { start: "111", ppid: 1, fds: [] },
  };
  const deps = {
    listFds: () => Object.entries(table).flatMap(([pid, e]) => e.fds.map((target) => ({ pid: Number(pid), target }))),
    readStat: (p: number) => {
      const e = table[p];
      if (!e) throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      return statLine(p, "x", e.ppid, e.start);
    },
  };
  assert.deepEqual(holdersOfInode(555, deps).map((h) => h.procKey), ["20-222"]);
  // A child forks and keeps the socket (a holder between two requests).
  table[21] = { start: "300", ppid: 20, fds: [S] };
  assert.deepEqual(holdersOfInode(555, deps), [
    { procKey: "20-222", ancestors: ["10-111"] },
    { procKey: "21-300", ancestors: ["20-222", "10-111"] },
  ]);
  // Both exit; pid 20 is reused by an unrelated process that received the
  // socket (SCM_RIGHTS): it is judged by its own start time, never 20-222.
  table = { 20: { start: "999", ppid: 1, fds: [S] } };
  assert.deepEqual(holdersOfInode(555, deps), [{ procKey: "20-999", ancestors: [] }]);
  // Nobody holds it any more: unattributed.
  table = {};
  assert.deepEqual(holdersOfInode(555, deps), []);
  assert.deepEqual(holdersOfInode(555, { ...deps, listFds: () => { throw new Error("EMFILE"); } }), [], "an error is unattributed, never a wrong key");
});

test("fdScanOwner: owner-limited only with no effective capability; any capability, or no CapEff line, tries every table", () => {
  const status = (cap: string) => `Name:\tnode\nUid:\t1000\t1000\t1000\t1000\nCapInh:\t0000000000000000\nCapEff:\t${cap}\nCapBnd:\t000001ffffffffff\n`;
  assert.equal(fdScanOwner(status("0000000000000000"), 1000), 1000);
  assert.equal(fdScanOwner(status("0000000000080000"), 1000), null, "CAP_SYS_PTRACE");
  assert.equal(fdScanOwner(status("000001ffffffffff"), 0), null, "root");
  assert.equal(fdScanOwner("Name:\tnode\n", 1000), null);
});

test("fdTableOpenable: skips only another uid's table, never this process's, and tries one it cannot tell", () => {
  const uid = (u: number | undefined) => () => u;
  assert.equal(fdTableOpenable(50, null, uid(0)), true, "not owner-limited");
  assert.equal(fdTableOpenable(50, 1000, uid(1000)), true, "ours");
  assert.equal(fdTableOpenable(50, 1000, uid(0)), false, "another uid's");
  assert.equal(fdTableOpenable(50, 1000, uid(undefined)), false, "gone");
  assert.equal(fdTableOpenable(50, 1000, uid(0), 50), true, "this process");
  assert.equal(fdTableOpenable(50, 1000, () => { throw new Error("EIO"); }), true, "cannot tell → try it");
});

test("LIVE: the owner-limited scan skips only tables the full scan could not open, and finds this process's client socket by the streamed row", async () => {
  if (process.platform !== "linux" || typeof process.geteuid !== "function") return;
  const owner = fdScanOwner(readFileSync("/proc/self/status", "utf8"), process.geteuid());
  // Every table the filter skips fails to open (EACCES, or the process is
  // gone): the skipped set is a subset of what the full scan skipped.
  let skipped = 0;
  for (const name of readdirSync("/proc")) {
    if (!/^\d+$/.test(name)) continue;
    const pid = Number(name);
    if (fdTableOpenable(pid, owner, (p) => statSync(`/proc/${p}/fd`, { throwIfNoEntry: false })?.uid)) continue;
    skipped++;
    assert.throws(() => readdirSync(`/proc/${pid}/fd`), (e: NodeJS.ErrnoException) => e.code === "EACCES" || e.code === "ENOENT", `pid ${pid}`);
  }
  void skipped;
  const server = createServer(() => {});
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = (server.address() as { port: number }).port;
  const sock = connect(port, "127.0.0.1");
  await once(sock, "connect");
  try {
    const c = { ip: "127.0.0.1", port: sock.localPort! };
    const p = { ip: "127.0.0.1", port };
    const streamed = socketInodeFor(c, p);
    assert.ok(streamed, "the client's row is found");
    assert.equal(streamed, socketInodeFor(c, p, () => readFileSync("/proc/net/tcp", "utf8")), "the streamed row is the whole table's");
    assert.deepEqual(attributeHolders(c, p).map((h) => h.procKey), [provisionalProcKey(process.pid)]);
    assert.deepEqual(holdersOfInode(streamed!).map((h) => h.procKey), [provisionalProcKey(process.pid)]);
  } finally {
    sock.destroy();
    server.close();
  }
});

// ── IPv6: /proc/net/tcp6 (2026-10-17) ───────────────────────────────────────

/** A tcp6 row: each address four 32-bit words printed as host-order
 *  integers (here little-endian, as on x86 and arm64). */
const ROW6 = (local: string, rem: string, inode: number): string =>
  `   3: ${local} ${rem} 01 00000000:00000000 00:00000000 00000000  1000        0 ${inode} 2 0000000000000000 20 0 0 10 -1`;
const LOOP6 = "00000000000000000000000001000000"; // ::1
const MAPPED_LOOP = "0000000000000000FFFF00000100007F"; // ::ffff:127.0.0.1
const GLOBAL6 = "B80D0120000000000000000005000000"; // 2001:db8::5

test("parseProcNetTcpLine reads tcp6 rows: ::1, a v4-mapped address as its dotted quad, a global address as its eight groups", () => {
  const loop = parseProcNetTcpLine(ROW6(`${LOOP6}:D1DA`, `${LOOP6}:AD05`, 684814037));
  assert.deepEqual(loop, { localIp: "0:0:0:0:0:0:0:1", localPort: 0xd1da, remIp: "0:0:0:0:0:0:0:1", remPort: 0xad05, inode: 684814037 });
  const mapped = parseProcNetTcpLine(ROW6(`${MAPPED_LOOP}:C5FE`, `${MAPPED_LOOP}:94B5`, 684814033));
  assert.deepEqual(mapped, { localIp: "127.0.0.1", localPort: 0xc5fe, remIp: "127.0.0.1", remPort: 0x94b5, inode: 684814033 });
  const global = parseProcNetTcpLine(ROW6(`${GLOBAL6}:0050`, `${LOOP6}:1F90`, 9));
  assert.equal(global!.localIp, "2001:db8:0:0:0:0:0:5");
  // A 32-hex address that is not hex, or a v6 address of the wrong length.
  assert.equal(parseProcNetTcpLine(ROW6(`${"G".repeat(32)}:0050`, `${LOOP6}:1F90`, 9)), null);
  assert.equal(parseProcNetTcpLine(ROW6(`${"0".repeat(31)}:0050`, `${LOOP6}:1F90`, 9)), null);
});

test("byte order: each address word is a host-order integer, so a big-endian host's spelling parses to the same address", () => {
  // The same rows a big-endian kernel prints: each word's bytes in address order.
  const be4 = parseProcNetTcpLine("   0: 7F000001:D431 7F000001:0050 01 00000000:00000000 00:00000000 00000000 1000 0 5 1", false);
  assert.deepEqual([be4!.localIp, be4!.localPort], ["127.0.0.1", 0xd431]);
  const be6 = parseProcNetTcpLine(ROW6("00000000000000000000000000000001:D1DA", "00000000000000000000FFFF7F000001:0050", 6), false);
  assert.equal(be6!.localIp, "0:0:0:0:0:0:0:1");
  assert.equal(be6!.remIp, "127.0.0.1");
  const beGlobal = parseProcNetTcpLine(ROW6("20010DB8000000000000000000000005:0050", `${"0".repeat(32)}:0000`, 7), false);
  assert.equal(beGlobal!.localIp, "2001:db8:0:0:0:0:0:5");
  // Read in the wrong order, the little-endian ::1 is another address: the
  // order is load-bearing.
  assert.notEqual(parseProcNetTcpLine(ROW6(`${LOOP6}:D1DA`, `${LOOP6}:AD05`, 1), false)!.localIp, "0:0:0:0:0:0:0:1");
});

test("inodeFromTcpText matches a tcp6 row whatever the endpoint's spelling (::1, its long form, a v4-mapped peer as Node reports it or normalized)", () => {
  const table = ["  sl  local_address                         remote_address                        st", ROW6(`${LOOP6}:D1DA`, `${LOOP6}:AD05`, 41), ROW6(`${MAPPED_LOOP}:C5FE`, `${MAPPED_LOOP}:94B5`, 42)].join("\n");
  assert.equal(inodeFromTcpText(table, { ip: "::1", port: 0xd1da }, { ip: "::1", port: 0xad05 }), 41);
  assert.equal(inodeFromTcpText(table, { ip: "0:0:0:0:0:0:0:1", port: 0xd1da }, { ip: "[::1]", port: 0xad05 }), 41);
  assert.equal(inodeFromTcpText(table, { ip: "127.0.0.1", port: 0xc5fe }, { ip: "127.0.0.1", port: 0x94b5 }), 42);
  assert.equal(inodeFromTcpText(table, { ip: "::ffff:127.0.0.1", port: 0xc5fe }, { ip: "::FFFF:7f00:1", port: 0x94b5 }), 42);
  // Wrong direction (the proxy's own end), another port, another address: none.
  assert.equal(inodeFromTcpText(table, { ip: "::1", port: 0xad05 }, { ip: "::1", port: 0xd1da }), null);
  assert.equal(inodeFromTcpText(table, { ip: "::1", port: 0xd1db }, { ip: "::1", port: 0xad05 }), null);
  assert.equal(inodeFromTcpText(table, { ip: "::2", port: 0xd1da }, { ip: "::1", port: 0xad05 }), null);
  assert.equal(inodeFromTcpText(table, { ip: "not-an-ip", port: 0xd1da }, { ip: "::1", port: 0xad05 }), null);
});

test("socketInodeFor / attributeHolders search tcp then tcp6 for an IPv4 peer (an AF_INET6 socket on a mapped address), tcp6 alone for an IPv6 one", () => {
  const tcp = `   0: 0100007F:D431 0100007F:0050 01 00000000:00000000 00:00000000 00000000  1000        0 7 1\n`;
  const tcp6 = `${ROW6(`${MAPPED_LOOP}:C5FE`, `${MAPPED_LOOP}:0050`, 8)}\n${ROW6(`${LOOP6}:D1DA`, `${LOOP6}:0050`, 9)}\n`;
  const p4 = { ip: "127.0.0.1", port: 80 };
  const p6 = { ip: "::1", port: 80 };
  assert.equal(socketInodeFor({ ip: "127.0.0.1", port: 0xd431 }, p4, () => tcp, () => tcp6), 7, "an AF_INET client: tcp");
  assert.equal(socketInodeFor({ ip: "127.0.0.1", port: 0xc5fe }, p4, () => tcp, () => tcp6), 8, "an AF_INET6 client on a mapped address: tcp6");
  assert.equal(socketInodeFor({ ip: "127.0.0.1", port: 0xc5fe }, p4, () => tcp), null, "without tcp6, as before: unattributed");
  let tcpReads = 0;
  const countTcp = (): string => {
    tcpReads++;
    return tcp;
  };
  assert.equal(socketInodeFor({ ip: "::1", port: 0xd1da }, p6, countTcp, () => tcp6), 9, "an IPv6 client: tcp6");
  assert.equal(tcpReads, 0, "the IPv4 table is not read for an IPv6 client");
  assert.equal(socketInodeFor({ ip: "::1", port: 0xd1da }, p6, () => tcp, () => { throw new Error("ENOENT"); }), null, "an unreadable tcp6: null (unattributed)");
  // The same inode → pid → key half as an IPv4 client: one holder, its chain.
  const post = ["S"];
  for (let i = 0; i < 60; i++) post.push("0");
  post[1] = "1";
  post[19] = "77";
  const deps = {
    readTcp: () => tcp,
    readTcp6: () => tcp6,
    listFds: () => [{ pid: 4242, target: "socket:[9]" }, { pid: 99, target: "socket:[7]" }],
    readStat: () => `4242 (curl) ${post.join(" ")}`,
  };
  assert.deepEqual(attributeHolders({ ip: "::1", port: 0xd1da }, p6, deps), [{ procKey: "4242-77", ancestors: [] }]);
  assert.equal(attributeConnection({ ip: "::1", port: 0xd1da }, p6, deps), "4242-77");
  assert.deepEqual(attributeHolders({ ip: "::1", port: 0xd1da }, p6, { ...deps, readTcp6: undefined }), [], "no tcp6 reader: unattributed, never a wrong key");
});

/** Can this host listen on `host`? (No IPv6 stack, or no ::1: skip.) */
async function canListen(host: string): Promise<boolean> {
  const s = createServer(() => {});
  try {
    await new Promise<void>((resolve, reject) => {
      s.once("error", reject);
      s.listen(0, host, () => resolve());
    });
    return true;
  } catch {
    return false;
  } finally {
    s.close();
  }
}

test("LIVE: an AF_INET6 client (::1, and a v4-mapped address at an IPv4 listener) is found in /proc/net/tcp6 and attributed to this process", async (t) => {
  if (process.platform !== "linux") return t.skip("live /proc is Linux-only");
  const cases: Array<{ listen: string; dial: string }> = [{ listen: "127.0.0.1", dial: "::ffff:127.0.0.1" }];
  if (await canListen("::1")) cases.push({ listen: "::1", dial: "::1" });
  else t.diagnostic("no ::1 on this host: only the v4-mapped case runs");
  for (const { listen, dial } of cases) {
    const server = createServer(() => {});
    server.listen(0, listen);
    await once(server, "listening");
    const port = (server.address() as { port: number }).port;
    const client = connect({ port, host: dial });
    const [accepted] = await Promise.all([once(server, "connection"), once(client, "connect")]);
    const sock = accepted[0] as import("node:net").Socket;
    try {
      // The proxy's view: the accepted socket's two ends, normalized as proxy.ts does.
      const norm = (a: string | undefined): string => (a ?? "").replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i, "$1");
      const c = { ip: norm(sock.remoteAddress), port: sock.remotePort! };
      const p = { ip: norm(sock.localAddress), port: sock.localPort! };
      const inode = socketInodeFor(c, p);
      assert.ok(inode, `${dial} → ${listen}: the client's row is found (${JSON.stringify(c)} → ${JSON.stringify(p)})`);
      assert.equal(socketInodeFor(c, p, () => readFileSync("/proc/net/tcp", "utf8")), null, "it is not in the IPv4 table");
      assert.equal(inode, socketInodeFor(c, p, () => readFileSync("/proc/net/tcp", "utf8"), () => readFileSync("/proc/net/tcp6", "utf8")), "the streamed row is the whole table's");
      assert.deepEqual(attributeHolders(c, p).map((h) => h.procKey), [provisionalProcKey(process.pid)], "the connecting process is this one");
    } finally {
      client.destroy();
      sock.destroy();
      server.close();
    }
  }
});
