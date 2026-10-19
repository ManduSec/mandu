/**
 * inbound — what Chrome sends the agent (devtools-relay.md §3.1): credential
 * headers withheld, unreadable bytes refused, every string (value and key)
 * filtered, and every failure withholds (secrets axes, explicit).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { stateAxes } from "../axes.js";
import { collectStrings, maskMessage, replaceStrings, replacementsFrom, stripCredentials, stripHeaderLines, MIN_SCAN_LEN } from "../../src/inbound.js";
import { WITHHELD_HEADER } from "../../src/policy.js";
import { MockArbiter } from "../mock-arbiter.js";

stateAxes("secrets");

const KEY = "sk_live_51HxQz8Yv3kT9mN2pL4rB6wE";
const SYM = "$MDU:nomodel_STRIPE_KEY[7f3a]";
const arbiter = () => new MockArbiter([{ value: KEY, symbol: SYM, bindings: ["stripe.com"] }]);

test("credential headers are withheld in every form Chrome sends them", () => {
  const { value, unreadable } = stripCredentials({
    request: { headers: { Cookie: "sid=abc", Accept: "text/html", authorization: "Bearer t0ken" } },
    responseHeaders: [{ name: "Set-Cookie", value: "sid=new" }, { name: "Content-Type", value: "text/html" }],
    associatedCookies: [{ cookie: { name: "sid", value: "abc", domain: "x.com" } }],
    headersText: "HTTP/1.1 200 OK\r\nSet-Cookie: sid=new\r\nContent-Type: text/html\r\n",
  });
  assert.equal(unreadable, false);
  const v = value as any;
  assert.equal(v.request.headers.Cookie, WITHHELD_HEADER);
  assert.equal(v.request.headers.authorization, WITHHELD_HEADER);
  assert.equal(v.request.headers.Accept, "text/html");
  assert.equal(v.responseHeaders[0].value, WITHHELD_HEADER);
  assert.equal(v.responseHeaders[1].value, "text/html");
  assert.equal(v.associatedCookies[0].cookie.value, WITHHELD_HEADER);
  assert.equal(v.associatedCookies[0].cookie.name, "sid");
  assert.equal(v.headersText, `HTTP/1.1 200 OK\r\nSet-Cookie: ${WITHHELD_HEADER}\r\nContent-Type: text/html\r\n`);
});

test("bytes the relay cannot read make the message unreadable", () => {
  assert.equal(stripCredentials({ body: "aGk=", base64Encoded: true }).unreadable, true);
  assert.equal(stripCredentials({ response: { opcode: 2, payloadData: "AAEC" } }).unreadable, true);
  assert.equal(stripCredentials({ response: { opcode: 1, payloadData: "hello" } }).unreadable, false);
  assert.equal(stripCredentials({ body: "hi", base64Encoded: false }).unreadable, false);
});

test("header lines keep their names and lose credential values only", () => {
  assert.equal(stripHeaderLines("Authorization: Basic x\nHost: a"), `Authorization: ${WITHHELD_HEADER}\nHost: a`);
});

test("strings are collected as values and keys, de-duplicated, from the floor up", () => {
  const got = collectStrings({ short: "1234567", [KEY]: 1, a: [KEY, { b: "long enough" }] });
  assert.deepEqual(got.sort(), [KEY, "long enough"].sort());
  assert.equal(MIN_SCAN_LEN, 8);
  const replaced = replaceStrings({ [KEY]: KEY, list: [KEY] }, new Map([[KEY, SYM]]));
  assert.deepEqual(replaced, { [SYM]: SYM, list: [SYM] });
});

test("the filter's answers: pass keeps, rewrite replaces, hold or a textless block withholds", () => {
  assert.deepEqual([...(replacementsFrom(["aaaaaaaa"], [{ id: "s0", action: "rewrite", text: "bbbbbbbb" }]) as Map<string, string>)], [["aaaaaaaa", "bbbbbbbb"]]);
  assert.equal((replacementsFrom(["aaaaaaaa"], [{ id: "s0", action: "pass" }]) as Map<string, string>).size, 0);
  assert.equal(typeof replacementsFrom(["aaaaaaaa"], [{ id: "s0", action: "hold" }]), "string");
  assert.equal(typeof replacementsFrom(["aaaaaaaa"], [{ id: "s0", action: "block" }]), "string");
  assert.equal(typeof replacementsFrom(["aaaaaaaa"], []), "string", "a segment with no answer withholds");
  const blocked = replacementsFrom(["key aaaaaaaa"], [{ id: "s0", action: "block", text: "key [blocked: x]" }]) as Map<string, string>;
  assert.equal(blocked.get("key aaaaaaaa"), "key [blocked: x]");
});

test("a registered value in a script result reaches the agent only as its symbol", async () => {
  const a = arbiter();
  const v = await maskMessage({ result: { result: { type: "string", value: `Your secret key: ${KEY}` } } }, { arbiter: a });
  assert.equal(v.kind, "forward");
  const out = JSON.stringify(v.kind === "forward" ? v.message : null);
  assert.ok(!out.includes(KEY), "no raw value");
  assert.ok(out.includes(SYM), "the symbol in its place");
});

test("an unreachable arbiter, a held finding or unreadable bytes withhold the message", async () => {
  const down = arbiter();
  down.filterDown = true;
  assert.equal((await maskMessage({ params: { text: `x ${KEY}` } }, { arbiter: down })).kind, "withhold");
  const held = arbiter();
  held.holdOn = "codename";
  assert.equal((await maskMessage({ params: { text: "the codename falcon" } }, { arbiter: held })).kind, "withhold");
  assert.equal((await maskMessage({ result: { body: "aGk=", base64Encoded: true } }, { arbiter: arbiter() })).kind, "withhold");
});

test("a message with nothing to scan does not call the arbiter", async () => {
  const a = arbiter();
  a.filterDown = true; // would withhold if asked
  const v = await maskMessage({ params: { frameId: "F1", ok: true } }, { arbiter: a });
  assert.equal(v.kind, "forward");
});
