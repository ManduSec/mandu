/**
 * this-machine.test — the egress proxy's this-machine set
 * (blocked-destinations.ts, 2026-10-05): loopback in every spelling, the
 * unspecified address, the `localhost` names, this machine's own interface
 * addresses, and a name that resolves to any of them. The proxy dials from
 * outside the connect guard, so without this set `curl -x "$HTTP_PROXY"
 * http://127.0.0.1:<port>/` reached any loopback service the guard refuses
 * the agent's direct connect to (the Mandu dashboard among them). Mirrors
 * `net-supervisor/src/guard_flow.rs::this_machine`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { networkInterfaces } from "node:os";

import {
  BlockedDestinationError,
  addressKey,
  bytesKey,
  dialRefusal,
  guardDial,
  guardedLookup,
  isBlockedDestinationError,
  keysFromIfInet6,
  liveLocalAddresses,
  localInterfaceKeys,
  localRangesFromFibTrie,
  localRangesFromIpv6Route,
  thisMachineAddressReason,
  thisMachineHostReason,
  type DialPolicy,
  type LocalAddressSource,
} from "../../src/blocked-destinations.js";

/** No interface addresses: only the fixed forms decide. */
const none: LocalAddressSource = () => ({ keys: new Set(), ranges: [] });
/** A machine whose interfaces carry one v4 and one v6 address. */
const lan: LocalAddressSource = () => ({ keys: new Set([addressKey("10.9.8.7")!, addressKey("2001:db8::42")!]), ranges: [] });

test("loopback is this machine in every spelling", () => {
  for (const ip of [
    "127.0.0.1",
    "127.1.2.3",
    "127.255.255.254",
    "::1",
    "[::1]",
    "0:0:0:0:0:0:0:1",
    // v4-mapped: the socket dials 127.0.0.1.
    "::ffff:127.0.0.1",
    "[::ffff:127.0.0.1]",
    "::FFFF:7f00:1",
    "0:0:0:0:0:ffff:7f00:0001",
    // v4-compatible (deprecated), refused rather than guessed about.
    "::127.0.0.1",
  ]) {
    assert.equal(thisMachineAddressReason(ip, none), "loopback address", ip);
  }
});

test("the unspecified address and the rest of 0.0.0.0/8 are this machine", () => {
  for (const ip of ["0.0.0.0", "0.1.2.3", "::", "[::]", "0:0:0:0:0:0:0:0", "::ffff:0.0.0.0"]) {
    assert.equal(thisMachineAddressReason(ip, none), "the unspecified address", ip);
  }
});

test("an address of this machine's interfaces is this machine, in either v6 spelling", () => {
  assert.equal(thisMachineAddressReason("10.9.8.7", lan), "an address of this machine's own interfaces");
  assert.equal(thisMachineAddressReason("::ffff:10.9.8.7", lan), "an address of this machine's own interfaces");
  assert.equal(thisMachineAddressReason("2001:DB8:0::42", lan), "an address of this machine's own interfaces");
  assert.equal(thisMachineAddressReason("[2001:db8:0:0:0:0:0:42]", lan), "an address of this machine's own interfaces");
  // A neighbour on the same network is not this machine.
  assert.equal(thisMachineAddressReason("10.9.8.6", lan), null);
  assert.equal(thisMachineAddressReason("2001:db8::43", lan), null);
});

test("this machine's REAL interface addresses are refused by the default source", (t) => {
  const real = Object.values(networkInterfaces()).flatMap((l) => l ?? []).filter((a) => !a.internal);
  if (real.length === 0) {
    t.skip("no non-loopback interface on this host");
    return;
  }
  for (const a of real) {
    assert.ok(thisMachineAddressReason(a.address), `${a.address} (${a.family})`);
    assert.ok(dialRefusal(a.address, 4500), `${a.address} as a dial target`);
  }
});

test("ordinary addresses and names are not this machine", () => {
  for (const ip of ["1.2.3.4", "10.0.0.1", "192.0.2.7", "2001:db8::1", "64:ff9b::7f00:1", "128.0.0.1", "126.255.255.255"]) {
    assert.equal(thisMachineAddressReason(ip, lan), null, ip);
  }
  assert.equal(thisMachineAddressReason("example.com", lan), null, "a name is not an address");
  for (const h of ["example.com", "localhost.example.com", "notlocalhost", "mylocalhost"]) {
    assert.equal(thisMachineHostReason(h, lan), null, h);
  }
});

test("FAIL-CLOSED: an unreadable interface list refuses every address it cannot rule out", () => {
  const broken: LocalAddressSource = () => {
    throw new Error("getifaddrs: EPERM");
  };
  const why = thisMachineAddressReason("1.2.3.4", broken);
  assert.ok(why, "an address that might be this machine's is refused");
  assert.match(why!, /cannot be listed/);
  // The fixed forms do not need the list.
  assert.equal(thisMachineAddressReason("127.0.0.1", broken), "loopback address");
});

test("the localhost names are refused by name, case and a trailing dot ignored", () => {
  for (const h of ["localhost", "LOCALHOST", "localhost.", "dash.localhost", "a.b.LocalHost.", "localhost.localdomain", "ip6-localhost", "ip6-loopback"]) {
    assert.equal(thisMachineHostReason(h, none), "a name for this machine", h);
  }
  assert.equal(thisMachineHostReason("[::ffff:127.0.0.1]", none), "loopback address");
});

test("dialRefusal: the always-denied set first, then this machine; each opt-out lifts only its own set", () => {
  assert.deepEqual(dialRefusal("169.254.169.254", 80, {}, none), { kind: "always-denied", reason: "cloud metadata endpoint" });
  assert.deepEqual(dialRefusal("127.0.0.1", 4500, {}, none), { kind: "this-machine", reason: "loopback address" });
  // MANDU_NET_ALLOW_METADATA does NOT open this machine.
  assert.deepEqual(dialRefusal("localhost", 4500, { allowMetadata: true }, none), { kind: "this-machine", reason: "a name for this machine" });
  // A route's own dial (allowThisMachine) still refuses metadata.
  assert.equal(dialRefusal("127.0.0.1", 4500, { allowThisMachine: true }, none), null);
  assert.equal(dialRefusal("169.254.169.254", 80, { allowThisMachine: true }, none)?.kind, "always-denied");
  assert.equal(dialRefusal("example.com", 443, {}, none), null);
});

test("guardDial throws on a refused literal (Node never asks a lookup about one) and arms the lookup otherwise", () => {
  for (const host of ["127.0.0.1", "[::1]", "::1", "::ffff:127.0.0.1", "0.0.0.0", "localhost"]) {
    assert.throws(() => guardDial(host, 4500), (e: unknown) => isBlockedDestinationError(e) && (e as BlockedDestinationError).kind === "this-machine", host);
  }
  assert.equal(typeof guardDial("example.com", 443).lookup, "function");
  assert.equal(typeof guardDial("127.0.0.1", 4500, { allowThisMachine: true }).lookup, "function", "a route still gets the metadata lookup");
  assert.deepEqual(guardDial("127.0.0.1", 4500, { allowThisMachine: true, allowMetadata: true }), {});
});

test("a this-machine refusal names its kind for the refusal note, and says the local route is direct", () => {
  const e = BlockedDestinationError.of("127.0.0.1", { kind: "this-machine", reason: "loopback address" });
  assert.equal(e.refusalKind, "this-machine");
  assert.match(e.message, /is this machine \(loopback address\)/);
  assert.match(e.message, /reached directly, where the connect guard decides/);
  assert.doesNotMatch(e.message, /MANDU_NET_ALLOW_METADATA/, "no opt-out is offered");
  const m = BlockedDestinationError.of("169.254.169.254", { kind: "always-denied", reason: "cloud metadata endpoint" });
  assert.equal(m.refusalKind, "blocked-destination");
});

function lookupOnce(host: string, all: boolean, policy: DialPolicy = {}, local: LocalAddressSource = none): Promise<{ err: NodeJS.ErrnoException | null; address: unknown }> {
  return new Promise((resolve) => {
    guardedLookup(4500, policy, local)(host, all ? { all: true } : {}, (err, address) => resolve({ err, address }));
  });
}

test("guardedLookup refuses a NAME that resolves to this machine, on the address it resolved to (no rebinding window)", async () => {
  // getaddrinfo reads these inet_aton spellings with no network: names as
  // written, 127.0.0.1 once resolved.
  for (const name of ["2130706433", "127.1", "0x7f000001"]) {
    for (const all of [false, true]) {
      const r = await lookupOnce(name, all);
      assert.ok(isBlockedDestinationError(r.err), `${name} (all=${all}): ${String(r.err)}`);
      assert.equal((r.err as unknown as BlockedDestinationError).kind, "this-machine");
      assert.match(r.err!.message, /127\.0\.0\.1/, "the refusal names the address it resolved to");
      assert.equal(r.address, "", "nothing is handed to the dial");
    }
  }
  // A name that resolves to an interface address of this machine.
  const viaLan = await lookupOnce("168364039", false, {}, lan); // = 10.9.8.7
  assert.ok(isBlockedDestinationError(viaLan.err), String(viaLan.err));
  // `localhost` is refused by name, before any resolver is asked.
  const named = await lookupOnce("localhost", true);
  assert.ok(isBlockedDestinationError(named.err));
  assert.match(named.err!.message, /a name for this machine/);
  // The route's own dial resolves loopback normally.
  const routed = await lookupOnce("2130706433", false, { allowThisMachine: true });
  assert.equal(routed.err, null);
  assert.equal(routed.address, "127.0.0.1");
});

// ── addresses this machine owns on no running interface (2026-10-17) ───────

/** A /proc/net/fib_trie as the kernel prints it: the main table with a
 *  `local` route in it, the local table (loopback, an AnyIP `local` route,
 *  the address of a DOWN interface, a broadcast entry), and a transparent
 *  proxy's policy table whose `local 0.0.0.0/0` applies only to marked
 *  packets. */
const FIB_TRIE = `Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 10.5.0.0/16 2 0 2
        |-- 10.5.0.0
           /16 host LOCAL
        |-- 10.6.0.0
           /16 link UNICAST
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 10.99.0.0
        /16 host LOCAL
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     |-- 192.168.98.1
        /32 host LOCAL
     |-- 192.168.98.255
        /32 link BROADCAST
Id 100:
  +-- 0.0.0.0/0 2 0 2
     |-- 0.0.0.0
        /0 host LOCAL
     |-- 172.30.0.0
        /16 host LOCAL
`;

/** /proc/net/ipv6_route: ::1, an AnyIP `local 2001:db8:5::/64 dev lo`, two
 *  anycast routes, a transparent proxy's `local ::/0`, a plain prefix route,
 *  a reject route. Addresses in network byte order. */
const R6 = (dest: string, len: string, flags: string, dev: string): string =>
  `${dest} ${len} 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 ${flags} ${dev}`;
const IPV6_ROUTE = [
  R6("00000000000000000000000000000001", "80", "80200001", "lo"),
  R6("20010db8000500000000000000000000", "40", "80200001", "lo"),
  R6("fe800000000000000000000000000000", "80", "00300001", "eth0"),
  R6("20010db8000900000000000000000000", "80", "00300001", "eth0"),
  R6("00000000000000000000000000000000", "00", "80200001", "lo"),
  R6("20010db8000700000000000000000000", "40", "00000001", "eth0"),
  R6("00000000000000000000000000000000", "00", "00200200", "lo"),
].join("\n");

/** /proc/net/if_inet6: the address of a DOWN dummy interface, and eth0's. */
const IF_INET6 = `20010db8000a00000000000000000042 03 40 00 80       d0
fe80000000000000a00b0cfffe0d0e0f 02 40 20 80     eth0
`;

/** The machine those three tables describe, with no running interface. */
const tables: LocalAddressSource = (family) =>
  family === 4
    ? { keys: new Set(), ranges: localRangesFromFibTrie(FIB_TRIE) }
    : { keys: new Set(keysFromIfInet6(IF_INET6)), ranges: localRangesFromIpv6Route(IPV6_ROUTE) };

const ROUTED = "an address this machine's routing table delivers to itself";
const IFACE = "an address of this machine's own interfaces";

test("fib_trie: every LOCAL prefix of the local, main and default tables, and nothing else", () => {
  const got = localRangesFromFibTrie(FIB_TRIE).map((r) => `${bytesKey(r.bytes)}/${r.len - 96}`);
  assert.deepEqual(got.sort(), ["10.5.0.0/16", "10.99.0.0/16", "127.0.0.0/8", "127.0.0.1/32", "192.168.98.1/32"]);
  assert.throws(() => localRangesFromFibTrie(""), /no local or main table/, "a text it cannot read fails closed");
  assert.throws(() => localRangesFromFibTrie("Id 100:\n  |-- 10.0.0.1\n     /32 host LOCAL\n"), /no local or main table/);
});

test("ipv6_route: local and anycast routes; a catch-all local ::/0, a prefix route and a reject route are not this machine", () => {
  const got = localRangesFromIpv6Route(IPV6_ROUTE).map((r) => `${bytesKey(r.bytes)}/${r.len}`);
  assert.deepEqual(got, ["0:0:0:0:0:0:0:1/128", "2001:db8:5:0:0:0:0:0/64", "fe80:0:0:0:0:0:0:0/128", "2001:db8:9:0:0:0:0:0/128"]);
  assert.deepEqual(keysFromIfInet6(IF_INET6), ["2001:db8:a:0:0:0:0:42", "fe80:0:0:0:a00b:cff:fe0d:e0f"]);
});

test("an address this machine owns on no running interface is this machine: a local route, a down interface's address, an anycast address", () => {
  // IPv4: an AnyIP `local` route (any spelling), the main table's local route,
  // a down interface's address.
  for (const ip of ["10.99.0.1", "10.99.255.254", "::ffff:10.99.3.4", "[::ffff:10.99.3.4]", "::10.99.3.4", "10.5.1.1", "192.168.98.1"]) {
    assert.equal(thisMachineAddressReason(ip, tables), ROUTED, ip);
  }
  // IPv6: the AnyIP /64, an anycast address, a down interface's address.
  assert.equal(thisMachineAddressReason("2001:db8:5::77", tables), ROUTED);
  assert.equal(thisMachineAddressReason("2001:db8:9::", tables), ROUTED);
  assert.equal(thisMachineAddressReason("2001:db8:a::42", tables), IFACE);
  // Not this machine: the next range over, a neighbour on the down interface's
  // network, a unicast route's prefix, the policy table's ranges, the
  // broadcast address.
  for (const ip of ["10.98.255.255", "10.100.0.0", "10.6.0.1", "192.168.98.2", "172.30.0.1", "8.8.8.8", "192.168.98.255", "2001:db8:5:1::77", "2001:db8:7::1", "2001:db8:9::1", "2001:db8:a::43"]) {
    assert.equal(thisMachineAddressReason(ip, tables), null, ip);
  }
  // Through the dial check: the this-machine kind, after the always-denied set.
  assert.deepEqual(dialRefusal("10.99.0.1", 8080, {}, tables), { kind: "this-machine", reason: ROUTED });
  assert.deepEqual(dialRefusal("fe80::", 53, {}, tables), { kind: "this-machine", reason: ROUTED }, "the link's anycast address on :53 is this machine (the always-denied set exempts :53)");
});

test("FAIL-CLOSED per family: an unreadable IPv6 table refuses IPv6 addresses, not IPv4 ones", () => {
  const noV6: LocalAddressSource = (family) => {
    if (family === 6) throw new Error("EACCES /proc/net/ipv6_route");
    return { keys: new Set(), ranges: [] };
  };
  assert.match(thisMachineAddressReason("2001:db8::1", noV6)!, /cannot be listed \(EACCES/);
  assert.equal(thisMachineAddressReason("::ffff:8.8.8.8", noV6), null, "a v4-mapped address is checked as IPv4");
  assert.equal(thisMachineAddressReason("8.8.8.8", noV6), null);
});

/**
 * The special-purpose address registries (IANA ipv4- and
 * ipv6-special-registry, RFC 6890 and later), one sample each, and what the
 * egress proxy does with it on a machine that owns none of them (no
 * interface address, no local route): the decision table of
 * exec-routing.md §7.5. `null` = relayed (a real destination, or one the
 * kernel itself cannot reach over TCP: multicast and broadcast fail the
 * connect with ENETUNREACH). Over-refusing a real remote range is the
 * failure this table guards against as much as under-refusing a local one.
 */
const SPECIAL: Array<[range: string, sample: string, port: number, expect: "this-machine" | "always-denied" | null]> = [
  // IPv4
  ["0.0.0.0/8 this network", "0.0.0.0", 80, "this-machine"],
  ["0.0.0.0/8 this network", "0.12.0.1", 80, "this-machine"],
  ["10.0.0.0/8 private", "10.1.2.3", 80, null],
  ["100.64.0.0/10 shared (CGN, Tailscale)", "100.64.0.1", 80, null],
  ["100.64.0.0/10: Alibaba Cloud metadata", "100.100.100.200", 80, "always-denied"],
  ["127.0.0.0/8 loopback", "127.0.0.1", 80, "this-machine"],
  ["127.0.0.0/8 loopback", "127.200.0.9", 80, "this-machine"],
  ["169.254.0.0/16 link-local", "169.254.1.1", 80, "always-denied"],
  ["169.254.0.0/16: cloud metadata", "169.254.169.254", 80, "always-denied"],
  ["169.254.0.0/16 on :53", "169.254.1.1", 53, null],
  ["172.16.0.0/12 private", "172.20.0.5", 80, null],
  ["192.0.0.0/24 IETF protocol assignments", "192.0.0.8", 80, null],
  ["192.0.0.0/29 DS-Lite", "192.0.0.2", 80, null],
  ["192.0.0.170/31 NAT64 discovery", "192.0.0.170", 80, null],
  ["192.0.2.0/24 TEST-NET-1", "192.0.2.7", 80, null],
  ["192.31.196.0/24 AS112-v4", "192.31.196.1", 80, null],
  ["192.52.193.0/24 AMT", "192.52.193.1", 80, null],
  ["192.88.99.0/24 6to4 relay anycast (deprecated)", "192.88.99.1", 80, null],
  ["192.168.0.0/16 private", "192.168.1.1", 80, null],
  ["192.175.48.0/24 AS112 direct delegation", "192.175.48.1", 80, null],
  ["198.18.0.0/15 benchmarking", "198.18.0.1", 80, null],
  ["198.51.100.0/24 TEST-NET-2", "198.51.100.1", 80, null],
  ["203.0.113.0/24 TEST-NET-3", "203.0.113.1", 80, null],
  ["224.0.0.0/4 multicast (no TCP)", "224.0.0.251", 80, null],
  ["240.0.0.0/4 reserved", "240.0.0.1", 80, null],
  ["255.255.255.255/32 limited broadcast (no TCP)", "255.255.255.255", 80, null],
  // IPv6
  ["::/128 unspecified", "::", 80, "this-machine"],
  ["::1/128 loopback", "::1", 80, "this-machine"],
  ["::ffff:0:0/96 v4-mapped: loopback", "::ffff:127.0.0.1", 80, "this-machine"],
  ["::ffff:0:0/96 v4-mapped: metadata", "::ffff:169.254.169.254", 80, "always-denied"],
  ["::ffff:0:0/96 v4-mapped: remote", "::ffff:8.8.8.8", 80, null],
  ["::/96 v4-compatible (deprecated): loopback", "::127.0.0.1", 80, "this-machine"],
  ["64:ff9b::/96 NAT64: metadata", "64:ff9b::a9fe:a9fe", 80, "always-denied"],
  ["64:ff9b::/96 NAT64: loopback (a translator never relays it)", "64:ff9b::7f00:1", 80, null],
  ["64:ff9b:1::/48 local-use NAT64", "64:ff9b:1::1", 80, null],
  ["100::/64 discard-only", "100::1", 80, null],
  ["2001::/32 Teredo", "2001:0:4136:e378::1", 80, null],
  ["2001:2::/48 benchmarking", "2001:2::1", 80, null],
  ["2001:20::/28 ORCHIDv2", "2001:20::1", 80, null],
  ["2001:db8::/32 documentation", "2001:db8::1", 80, null],
  ["2002::/16 6to4", "2002:c000:201::1", 80, null],
  ["2620:4f:8000::/48 AS112", "2620:4f:8000::1", 80, null],
  ["3fff::/20 documentation", "3fff::1", 80, null],
  ["5f00::/16 SRv6 SIDs", "5f00::1", 80, null],
  ["fc00::/7 unique-local", "fd12:3456::1", 80, null],
  ["fd00:ec2::254 AWS metadata (IPv6)", "fd00:ec2::254", 80, "always-denied"],
  ["fe80::/10 link-local", "fe80::1", 80, "always-denied"],
  ["fe80::/10 link-local on :53", "fe80::1", 53, null],
  ["fec0::/10 site-local (deprecated)", "fec0::1", 80, null],
  ["ff00::/8 multicast (no TCP)", "ff02::1", 80, null],
];

test("the special-purpose ranges, one by one: what reaches this machine is refused as this machine, the local link as always-denied, the rest relayed", () => {
  const nothingOwned: LocalAddressSource = () => ({ keys: new Set(), ranges: [] });
  for (const [range, sample, port, expect] of SPECIAL) {
    assert.equal(dialRefusal(sample, port, {}, nothingOwned)?.kind ?? null, expect, `${range}: ${sample}:${port}`);
  }
});

test("LIVE: every address this machine's routing tables deliver to itself is refused by the default source, listed by the interface list or not", (t) => {
  if (process.platform !== "linux") return t.skip("the routing tables are read on Linux");
  const listed = localInterfaceKeys();
  const owned = new Set<string>();
  for (const r of localRangesFromFibTrie(readFileSync("/proc/net/fib_trie", "latin1"))) owned.add(bytesKey(r.bytes));
  let inet6 = "";
  try {
    inet6 = readFileSync("/proc/net/if_inet6", "latin1");
  } catch {
    t.diagnostic("no IPv6 stack");
  }
  for (const k of keysFromIfInet6(inet6)) owned.add(k);
  if (inet6) for (const r of localRangesFromIpv6Route(readFileSync("/proc/net/ipv6_route", "latin1"))) owned.add(bytesKey(r.bytes));
  const unlisted: string[] = [];
  for (const ip of owned) {
    if (ip.startsWith("127.") || ip === "0:0:0:0:0:0:0:1") continue;
    assert.ok(thisMachineAddressReason(ip), `${ip} is this machine's`);
    if (!listed.has(ip)) unlisted.push(ip);
  }
  // On a host with a down interface or a carrier-less bridge, these were
  // relayed before 2026-10-17 (os.networkInterfaces() lists neither).
  t.diagnostic(`${owned.size} owned addresses, ${unlisted.length} not in os.networkInterfaces(): ${unlisted.slice(0, 8).join(", ")}`);
  assert.equal(liveLocalAddresses(4).ranges.length > 0, true, "the local table lists at least loopback");
});
