/**
 * netns-dns-peer.fixture — a DNS server on "the other machine" (the peer
 * namespace of tests/lib/netns.ts) or on this side's 127.0.0.1 (a resolver
 * forwarding on loopback, as dnsmasq or unbound do): UDP and TCP port 53 on
 * every address of its namespace.
 *
 * Every datagram and every TCP stream it receives is appended to DNS_LOG as
 * one JSON line (the local address it arrived on, the transport, the bytes
 * as latin1): the oracle for "what left the machine". It answers each query
 * NXDOMAIN, so a resolver gives up at once instead of waiting.
 *
 * env: DNS_LOG, DNS_READY, DNS_HOST (optional: the address to bind; every
 * address when unset).
 * PROVENANCE: NEW Mandu test code (exec-routing.md §7.5, 2026-10-01).
 */
import { appendFileSync, writeFileSync } from "node:fs";
import { createSocket } from "node:dgram";
import { createServer } from "node:net";

const env = (k: string): string => {
  const v = process.env[k];
  if (!v) throw new Error(`${k} is required`);
  return v;
};
const LOG = env("DNS_LOG");
const host = process.env["DNS_HOST"] || undefined;

const log = (local: string, proto: string, bytes: Buffer): void => {
  appendFileSync(LOG, JSON.stringify({ local, proto, data: bytes.toString("latin1") }) + "\n");
};

/** NXDOMAIN for a query: its id and question, QR + RA + RCODE 3. */
const nxdomain = (q: Buffer): Buffer => {
  if (q.length < 12) return Buffer.alloc(0);
  const r = Buffer.from(q);
  r[2] = 0x81;
  r[3] = 0x83;
  r.writeUInt16BE(0, 6);
  r.writeUInt16BE(0, 8);
  r.writeUInt16BE(0, 10);
  return r;
};

const udp = createSocket("udp4");
udp.on("message", (msg, rinfo) => {
  log(udp.address().address, "udp", msg);
  const a = nxdomain(msg);
  if (a.length) udp.send(a, rinfo.port, rinfo.address);
});

const tcp = createServer((c) => {
  let got = Buffer.alloc(0);
  c.on("data", (d) => {
    got = Buffer.concat([got, d]);
    if (got.length >= 2 && got.length >= 2 + got.readUInt16BE(0)) {
      const q = got.subarray(2, 2 + got.readUInt16BE(0));
      const a = nxdomain(q);
      const len = Buffer.alloc(2);
      len.writeUInt16BE(a.length);
      c.end(Buffer.concat([len, a]));
    }
  });
  c.on("end", () => log(c.localAddress ?? "?", "tcp", got));
  c.on("close", () => { if (got.length && !c.readableEnded) log(c.localAddress ?? "?", "tcp", got); });
  c.on("error", () => {});
});

let up = 0;
const ready = (): void => {
  if (++up === 2) writeFileSync(env("DNS_READY"), "up\n");
};
udp.bind(53, host, ready);
tcp.listen(53, host, ready);
