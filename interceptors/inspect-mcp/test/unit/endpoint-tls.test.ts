/**
 * endpoint-tls unit (plan 12 D3, D4): the pure parts of the connection-time
 * checks, and the perimeter lookup over a fixture resolver (all inside, one
 * outside, an empty answer). The handshake legs are in
 * test/component/endpoint-tls.test.ts.
 *
 * Axes: none read here (transport).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";

import {
  asTlsConfig, chainPins, checkHostInPerimeter, checkLiteralHost, hasIdentityChecks, hasTlsConfig, inNetworks, loadTlsMaterial, makeCheckServerIdentity,
  PerimeterError, perimeterLookup, tlsFailureWords, tlsFetch, tlsOptions, type BaseLookup,
} from "../../src/endpoint-tls.js";
import { mintTlsFixtures, spkiPin } from "../helpers/tls-fixtures.js";

const fx = mintTlsFixtures();
const skip = fx === null ? "openssl is not on PATH" : false;
process.on("exit", () => fx?.cleanup());
const PIN = Buffer.alloc(32, 1).toString("base64");

test("asTlsConfig: strict on the wire (absolute paths, 32-byte pins, the client pair together)", () => {
  assert.deepEqual(asTlsConfig({ caFile: "/etc/ca.pem", pinSha256: [PIN] }), { caFile: "/etc/ca.pem", pinSha256: [PIN] });
  assert.equal(asTlsConfig({ caFile: "ca.pem" }), null, "relative path");
  assert.equal(asTlsConfig({ pinSha256: [] }), null);
  assert.equal(asTlsConfig({ pinSha256: ["short="] }), null);
  assert.equal(asTlsConfig({ clientCert: "/c.pem" }), null, "half a pair");
  assert.equal(asTlsConfig("yes"), null);
  assert.deepEqual(asTlsConfig({}), {});
  assert.equal(hasTlsConfig({}), false);
  assert.equal(hasTlsConfig({ pinSha256: [PIN] }), true);
});

test("loadTlsMaterial: reads the files, prefers the key bytes handed in, refuses bytes that are not a key", () => {
  const files: Record<string, string> = { "/ca.pem": "CA", "/c.pem": "CERT", "/k.pem": "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n" };
  const read = (p: string): string => { if (!(p in files)) throw new Error("ENOENT"); return files[p]!; };
  assert.deepEqual(loadTlsMaterial({ caFile: "/ca.pem", pinSha256: [PIN] }, { read }), { ca: "CA", pins: [PIN] });
  assert.equal(loadTlsMaterial({ clientCert: "/c.pem", clientKey: "/k.pem" }, { read }).key, files["/k.pem"]);
  assert.equal(loadTlsMaterial({ clientCert: "/c.pem", clientKey: "/nope" }, { read, keyPem: files["/k.pem"] }).key, files["/k.pem"], "handed-in bytes win over the (masked) file");
  assert.throws(() => loadTlsMaterial({ caFile: "/missing.pem" }, { read }), /tls\.ca_file: cannot read \/missing\.pem/);
  assert.throws(() => loadTlsMaterial({ clientCert: "/c.pem", clientKey: "/k.pem" }, { read, keyPem: "$MDU:nomodel_x[1]" }), /not a PEM private key here/);
});

test("tlsOptions: the extra CA joins Node's roots, never replaces them; no CA leaves the default store", () => {
  const withCa = tlsOptions({ ca: "PEM" });
  assert.ok(Array.isArray(withCa.ca) && (withCa.ca as string[]).length > 1 && (withCa.ca as string[]).at(-1) === "PEM");
  assert.equal("ca" in tlsOptions({}), false);
  assert.equal(typeof tlsOptions({}).checkServerIdentity, "function");
});

test("chainPins / makeCheckServerIdentity: pins over the whole chain; the host check runs first", { skip }, () => {
  const leaf = new X509Certificate(fx!.serverCertPem);
  const ca = new X509Certificate(fx!.caCertPem);
  // A peer certificate as Node hands it to checkServerIdentity (detailed).
  const caPeer = { ...ca.toLegacyObject(), fingerprint256: ca.fingerprint256, pubkey: ca.publicKey.export({ type: "spki", format: "der" }) } as never as { issuerCertificate?: unknown };
  caPeer.issuerCertificate = caPeer; // a root issues itself
  const peer = { ...leaf.toLegacyObject(), subjectaltname: "IP Address:127.0.0.1, DNS:localhost", fingerprint256: leaf.fingerprint256,
    pubkey: leaf.publicKey.export({ type: "spki", format: "der" }), issuerCertificate: caPeer } as never;
  assert.deepEqual(chainPins(peer), [spkiPin(fx!.serverCertPem), spkiPin(fx!.caCertPem)]);
  assert.equal(makeCheckServerIdentity([fx!.caPin])("127.0.0.1", peer), undefined, "the CA's pin is in the chain");
  assert.equal(makeCheckServerIdentity(undefined)("localhost", peer), undefined);
  const mismatch = makeCheckServerIdentity([fx!.otherPin])("localhost", peer);
  assert.equal((mismatch as { code?: string } | undefined)?.code, "MANDU_PIN_MISMATCH");
  const wrongHost = makeCheckServerIdentity([fx!.serverPin])("llm.example.com", peer);
  assert.equal((wrongHost as { code?: string } | undefined)?.code, "ERR_TLS_CERT_ALTNAME_INVALID", "the host check runs before the pins");
});

test("tlsFailureWords: each refusal in plain words, never a certificate dump", () => {
  assert.match(tlsFailureWords({ code: "MANDU_PIN_MISMATCH" }), /not one of the pinned keys/);
  assert.match(tlsFailureWords({ code: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" }), /not trusted \(add your organization's CA as tls\.ca_file\)/);
  assert.match(tlsFailureWords({ code: "SELF_SIGNED_CERT_IN_CHAIN" }), /not trusted/);
  assert.match(tlsFailureWords({ code: "ERR_TLS_CERT_ALTNAME_INVALID" }), /does not name this host/);
  assert.match(tlsFailureWords({ code: "ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED", message: "alert number 116" }), /require a client certificate/);
  assert.match(tlsFailureWords(new Error("boom")), /^TLS failed \(boom\)$/);
});

// ── plan 12 D4: the perimeter ────────────────────────────────────────────────

const NETS = ["10.0.0.0/8", "fd00:1234::/32"];
/** A fixture resolver: name → addresses (IPv4 or IPv6), counted. */
function resolver(answers: Record<string, string[]>): BaseLookup & { asked: string[] } {
  const asked: string[] = [];
  const f = ((host: string, _o: unknown, cb: (e: NodeJS.ErrnoException | null, a: Array<{ address: string; family: number }>) => void) => {
    asked.push(host);
    const list = answers[host];
    if (list === undefined) { cb(Object.assign(new Error(`getaddrinfo ENOTFOUND ${host}`), { code: "ENOTFOUND" }), []); return; }
    cb(null, list.map((address) => ({ address, family: address.includes(":") ? 6 : 4 })));
  }) as BaseLookup & { asked: string[] };
  f.asked = asked;
  return f;
}
const lookupOnce = (base: BaseLookup, host: string, options: object) =>
  new Promise<{ err: unknown; address: unknown; family?: number }>((res) => perimeterLookup(NETS, base)(host, options, (err, address, family) => res({ err, address, family })));

test("perimeter: CIDR membership across families, IPv4-mapped IPv6, a bare address is one host; asTlsConfig carries it strictly", () => {
  assert.ok(inNetworks("10.200.1.1", NETS));
  assert.ok(inNetworks("::ffff:10.0.0.1", NETS), "mapped IPv4");
  assert.ok(inNetworks("fd00:1234:ffff::1", NETS));
  assert.ok(!inNetworks("fd00:1235::1", NETS));
  assert.ok(!inNetworks("11.0.0.1", NETS));
  assert.ok(!inNetworks("not-an-address", NETS));
  assert.ok(inNetworks("192.0.2.7", ["192.0.2.7"]) && !inNetworks("192.0.2.8", ["192.0.2.7"]));
  assert.deepEqual(asTlsConfig({ perimeter: NETS }), { perimeter: NETS });
  for (const bad of [[], ["10.0.0.0/33"], ["corp.example"], "10.0.0.0/8", [7]]) assert.equal(asTlsConfig({ perimeter: bad }), null, JSON.stringify(bad));
  assert.equal(hasTlsConfig({ perimeter: NETS }), true);
  assert.equal(hasIdentityChecks(loadTlsMaterial({ perimeter: NETS })), false, "a perimeter alone is not an identity check");
});

test("perimeterLookup over a fixture resolver: all inside → the checked addresses; one outside → PerimeterError naming it; empty → refused; the caller's family is drawn from the checked list", async () => {
  const r = resolver({ "llm.corp.example": ["10.1.2.3", "fd00:1234::9"], "drift.corp.example": ["10.1.2.4", "203.0.113.9"], "empty.corp.example": [] });
  const all = await lookupOnce(r, "llm.corp.example", { all: true });
  assert.equal(all.err, null);
  assert.deepEqual((all.address as Array<{ address: string }>).map((a) => a.address), ["10.1.2.3", "fd00:1234::9"]);
  const v6 = await lookupOnce(r, "llm.corp.example", { family: 6 });
  assert.deepEqual([v6.address, v6.family], ["fd00:1234::9", 6]);

  const out = await lookupOnce(r, "drift.corp.example", { family: 4 });
  assert.ok(out.err instanceof PerimeterError);
  assert.equal((out.err as PerimeterError).address, "203.0.113.9", "every address is checked, not only the family asked for");
  assert.equal((out.err as Error).message, "drift.corp.example resolves to 203.0.113.9, outside perimeter.networks");
  assert.equal(tlsFailureWords(out.err), "drift.corp.example resolves to 203.0.113.9, outside perimeter.networks");

  const none = await lookupOnce(r, "empty.corp.example", {});
  assert.ok(none.err instanceof PerimeterError && (none.err as PerimeterError).address === null);
  const nx = await lookupOnce(r, "nx.corp.example", {});
  assert.match(String((nx.err as Error).message), /ENOTFOUND/);
  assert.deepEqual(r.asked, ["llm.corp.example", "llm.corp.example", "drift.corp.example", "empty.corp.example", "nx.corp.example"], "one resolution per connection");
});

test("checkLiteralHost / checkHostInPerimeter: a literal is its own answer (Node never looks one up); a name goes through the lookup", async () => {
  assert.equal(checkLiteralHost("10.0.0.5", NETS), null);
  assert.equal(checkLiteralHost("[fd00:1234::1]", NETS), null);
  assert.equal(checkLiteralHost("203.0.113.9", NETS)?.message, "203.0.113.9 is outside perimeter.networks");
  assert.equal(checkLiteralHost("llm.corp.example", NETS), null, "a name is the lookup's job");
  assert.equal(checkLiteralHost("203.0.113.9", undefined), null, "no perimeter, no check");
  const r = resolver({ "llm.corp.example": ["10.1.2.3"], "drift.corp.example": ["52.1.2.3"] });
  assert.deepEqual(await checkHostInPerimeter("llm.corp.example", NETS, r), { ok: true, addresses: ["10.1.2.3"] });
  assert.deepEqual(await checkHostInPerimeter("drift.corp.example", NETS, r), { ok: false, reason: "drift.corp.example resolves to 52.1.2.3, outside perimeter.networks", address: "52.1.2.3" });
  assert.deepEqual(await checkHostInPerimeter("203.0.113.9", NETS, r), { ok: false, reason: "203.0.113.9 is outside perimeter.networks", address: "203.0.113.9" });
  assert.deepEqual(await checkHostInPerimeter("10.9.9.9", NETS, r), { ok: true, addresses: ["10.9.9.9"] });
});

test("tlsOptions carries the perimeter lookup; tlsFetch refuses an outside literal before any connection and accepts plain http only without identity checks", async () => {
  assert.equal(typeof tlsOptions({ perimeter: NETS }).lookup, "function");
  assert.equal(tlsOptions({}).lookup, undefined);
  const r = resolver({});
  await assert.rejects(tlsFetch({ perimeter: NETS }, r)("https://203.0.113.9:8443/v1/models"), PerimeterError);
  await assert.rejects(tlsFetch({ perimeter: NETS }, r)("http://203.0.113.9:8000/v1/models"), PerimeterError);
  await assert.rejects(tlsFetch({ ca: "x", perimeter: NETS }, r)("http://10.0.0.5:8000/"), /is not https/);
  await assert.rejects(tlsFetch({ perimeter: NETS }, r)("http://nx.corp.example:8000/"), /ENOTFOUND/);
  assert.deepEqual(r.asked, ["nx.corp.example"], "the literals were never looked up");
});
