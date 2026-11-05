/**
 * host-check.test — Rules' "Check a host" box in words (dashboard.md
 * §4.25aa *Check a host*): the arbiter's `whyHost` answer as the page's
 * sentences (view-model/host-check.ts), every branch, and the host a person
 * types checked before it is asked. The answer never carries a value nor a
 * `$MDU:` placeholder: the earlier answers are counted, not sent.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { checkedHost, hostCheckWords, HOST_REFUSED, type WhyHostWire } from "../../../src/view-model/host-check.js";

const HOME = "/home/u";
const ASK = { decision: { allow: false, requiresApproval: true }, stage: "built-in" };
const BLOCK = { decision: { allow: false, requiresApproval: false }, stage: "built-in" };
const ALLOW = { decision: { allow: true }, stage: "built-in" };
const SYMBOL = "$MDU:nomodel_Read[0123abcd].STRIPE_KEY";
const VALUE = "sk_live_hostCheckNeverShown";

const answer = (over: Partial<WhyHostWire> = {}): WhyHostWire => ({
  host: "api.stripe.com",
  axis: true,
  bound: [],
  release: { bound: ALLOW, unbound: ASK },
  destinations: [],
  verdicts: [],
  ...over,
});
const texts = (a: WhyHostWire) => hostCheckWords(a, HOME).lines.map((l) => l.text);
const kinds = (a: WhyHostWire) => hostCheckWords(a, HOME).lines.map((l) => l.kind);

test("bound: each secret by its name, a file as ~/…, a value of a file as ~/…: KEY, a variable by its name, each once, with its rule's path", () => {
  const vm = hostCheckWords(answer({
    bound: [
      { path: "/home/u/app/.env", level: "no-model", binding: ["api.stripe.com"], source: "label" },
      { path: "/home/u/ws/.env", level: "no-model", binding: ["STRIPE_KEY: api.stripe.com", "STRIPE_KEY: *.stripe.com"], source: "label" },
      { path: "/home/u/app/.env", level: "no-model", binding: ["api.stripe.com"], source: "registry" },
      { path: "env:STRIPE_KEY", level: "no-model", binding: ["api.stripe.com"], source: "registry" },
      { path: "/srv/key.pem", level: "local-model", binding: ["api.stripe.com"], source: "registry" },
    ],
  }), HOME);
  const bound = vm.lines[0]!;
  assert.equal(bound.kind, "bound");
  assert.equal(bound.text, "4 of your secrets may be sent there: ~/app/.env, ~/ws/.env: STRIPE_KEY, STRIPE_KEY, /srv/key.pem.");
  assert.deepEqual(bound.parts.filter((p) => p.kind === "code").map((p) => p.text), ["~/app/.env", "~/ws/.env: STRIPE_KEY", "STRIPE_KEY", "/srv/key.pem"], "every name is code");
  assert.deepEqual(bound.files, [
    { name: "~/app/.env", rule: "/home/u/app/.env" },
    { name: "~/ws/.env: STRIPE_KEY", rule: "/home/u/ws/.env" },
    { name: "STRIPE_KEY", rule: null },
    { name: "/srv/key.pem", rule: "/srv/key.pem" },
  ], "each code part's file, in order");
  assert.equal(vm.host, "api.stripe.com");
});

test("none bound: None of your secrets may be sent there", () => {
  assert.deepEqual(texts(answer({ host: "pastebin.com" })), [
    "None of your secrets may be sent there.",
    "Any other secret sent there: Mandu asks you first.",
  ]);
});

test("any other secret: asks, blocks or goes out, and says when an earlier answer or a rule of yours decided it; an unknown answer says so", () => {
  const other = (unbound: WhyHostWire["release"]["unbound"]) => hostCheckWords(answer({ release: { bound: null, unbound } }), HOME).lines.find((l) => l.kind === "other")!.text;
  assert.equal(other(ASK), "Any other secret sent there: Mandu asks you first.");
  assert.equal(other(BLOCK), "Any other secret sent there: Mandu blocks it.");
  assert.equal(other(ALLOW), "Any other secret sent there: it goes out.");
  assert.equal(other({ ...BLOCK, stage: "verdict" }), "Any other secret sent there: Mandu blocks it, as an earlier answer of yours says.");
  assert.equal(other({ ...ALLOW, stage: "verdict" }), "Any other secret sent there: it goes out, as an earlier answer of yours says.");
  assert.equal(other({ ...BLOCK, stage: "user-rule" }), "Any other secret sent there: Mandu blocks it, as a rule of yours says.");
  assert.equal(other({ ...ASK, stage: "user-rule" }), "Any other secret sent there: Mandu asks you first, as a rule of yours says.");
  assert.equal(other(null), "Mandu could not work out what happens to any other secret sent there.");
});

test("an issuer's API host, on and off, in #72's words", () => {
  const on = answer({ issuer: { id: "stripe", name: "Stripe", shapes: ["sk_live_"], on: true } });
  assert.equal(hostCheckWords(on, HOME).lines.find((l) => l.kind === "issuer")!.text, "This is Stripe's API host: a Stripe key goes here without asking.");
  const off = answer({ issuer: { id: "stripe", name: "Stripe", shapes: ["sk_live_"], on: false } });
  assert.equal(hostCheckWords(off, HOME).lines.find((l) => l.kind === "issuer")!.text, "This is Stripe's API host: a Stripe key sent here asks you first.");
  assert.ok(!hostCheckWords(on, HOME).lines.some((l) => l.text.includes("sk_live_")), "the key formats are not named");
});

test("a connect row of destinations: per port, any port, UDP, every host; a deny row says nothing", () => {
  const vm = answer({
    destinations: [
      { host: "api.stripe.com", port: 443, proto: "tcp", connect: "allow" },
      { host: "api.stripe.com", port: "*", proto: "tcp", connect: "allow", reason: "ci" },
      { host: "api.stripe.com", port: 53, proto: "udp", connect: "allow" },
      { host: "*", port: 443, proto: "tcp", connect: "allow" },
      { host: "api.stripe.com", port: 22, proto: "tcp", connect: "deny" },
    ],
  });
  assert.deepEqual(hostCheckWords(vm, HOME).lines.filter((l) => l.kind === "connect").map((l) => l.text), [
    "Your agent's programs may connect to it on port 443 (your rule).",
    "Your agent's programs may connect to it on any port (your rule).",
    "Your agent's programs may connect to it on port 53 over UDP (your rule).",
    "Your agent's programs may connect to every host on port 443 (your rule).",
  ]);
});

test("earlier answers are a count with a link to Approvals found by the host; a send still waiting is not counted", () => {
  const vm = hostCheckWords(answer({
    verdicts: [
      { symbol: SYMBOL, status: "approved", scope: "always" },
      { symbol: "$MDU:nomodel_Read[99]", status: "denied", scope: "once" },
      { symbol: "$MDU:nomodel_Read[98]", status: "approved", scope: "once" },
      { symbol: "$MDU:nomodel_Read[97]", status: "pending", scope: "always" },
    ],
  }), HOME);
  const l = vm.lines.find((x) => x.kind === "answered")!;
  assert.equal(l.text, "You answered 3 earlier sends to this host. Find them in Approvals.");
  assert.deepEqual(l.parts[1], { kind: "link", text: "Find them in Approvals", to: "approvals", q: "api.stripe.com" });
  const one = hostCheckWords(answer({ verdicts: [{ symbol: SYMBOL, status: "denied", scope: "once" }] }), HOME);
  assert.equal(one.lines.find((x) => x.kind === "answered")!.text, "You answered 1 earlier send to this host. Find them in Approvals.");
  assert.ok(!kinds(answer({ verdicts: [{ symbol: SYMBOL, status: "pending", scope: "always" }] })).includes("answered"));
  assert.ok(!kinds(answer()).includes("answered"), "none: no line");
});

test("a send waiting now: counted, linked to Approvals with no search; never in the answered count; a prompt hold not counted", () => {
  const waiting = (verdicts: WhyHostWire["verdicts"]) => hostCheckWords(answer({ verdicts }), HOME).lines.find((l) => l.kind === "waiting");
  assert.equal(waiting([]), undefined, "none: no line");
  assert.equal(waiting([{ symbol: SYMBOL, status: "approved", scope: "always" }]), undefined, "an answered send is not waiting");
  const one = waiting([{ symbol: SYMBOL, status: "pending", scope: "always" }])!;
  assert.equal(one.text, "1 send to this host waits for your answer in Approvals.");
  assert.deepEqual(one.parts[1], { kind: "link", text: "Approvals", to: "approvals" }, "Approvals, its Waiting first: no q (Answered earlier's search finds no waiting card)");
  assert.equal(one.parts.filter((p) => p.kind === "link").length, 1);
  const vm = hostCheckWords(answer({
    verdicts: [
      { symbol: SYMBOL, status: "pending", scope: "always" },
      { symbol: "$MDU:nomodel_Read[99]", status: "pending", scope: "always" },
      { symbol: "$MDU:nomodel_Env[98]", status: "pending", scope: "once" },
      { symbol: "prompt:sess-1:abc", status: "pending", scope: "once" },
      { symbol: "$MDU:nomodel_Read[97]", status: "denied", scope: "once" },
    ],
  }), HOME);
  assert.equal(vm.lines.find((l) => l.kind === "waiting")!.text, "3 sends to this host wait for your answer in Approvals.", "the prompt hold is not a send");
  assert.equal(vm.lines.find((l) => l.kind === "answered")!.text, "You answered 1 earlier send to this host. Find them in Approvals.", "a waiting send is not an answer");
  assert.equal(waiting([{ symbol: "prompt:sess-1:abc", status: "pending", scope: "once" }]), undefined, "a prompt hold alone: no line");
  for (const l of vm.lines) assert.ok(!l.text.includes("$MDU:") && !l.text.includes("prompt:"), l.text);
});

test("a rule change waiting in Approvals would change this, linked to Approvals", () => {
  const one = hostCheckWords(answer({ pending: [{ id: "pc-1", from: "file" }] }), HOME).lines.find((l) => l.kind === "pending")!;
  assert.equal(one.text, "A rule change waiting in Approvals would change this.");
  assert.deepEqual(one.parts[1], { kind: "link", text: "Approvals", to: "approvals" });
  const two = hostCheckWords(answer({ pending: [{ id: "pc-1" }, { id: "pp-2" }] }), HOME).lines.find((l) => l.kind === "pending")!;
  assert.equal(two.text, "2 rule changes waiting in Approvals would change this.");
  assert.ok(!kinds(answer({ pending: [] })).includes("pending"));
  assert.ok(!kinds(answer()).includes("pending"), "an older arbiter sends none");
});

test("protection off: one line, then the connect rows; nothing about secrets", () => {
  const off = answer({
    axis: false,
    bound: [{ path: "/home/u/app/.env", level: "no-model", binding: ["api.stripe.com"], source: "label" }],
    destinations: [{ host: "api.stripe.com", port: 443, proto: "tcp", connect: "allow" }],
    issuer: { id: "stripe", name: "Stripe", shapes: [], on: true },
    verdicts: [{ symbol: SYMBOL, status: "approved", scope: "always" }],
  });
  assert.deepEqual(texts(off), [
    "Protection is off: nothing is held back from any host.",
    "Your agent's programs may connect to it on port 443 (your rule).",
  ]);
});

test("the order: bound, any other, issuer, connect, answered, waiting, pending", () => {
  assert.deepEqual(kinds(answer({
    bound: [{ path: "/home/u/app/.env", level: "no-model", binding: ["api.stripe.com"], source: "label" }],
    issuer: { id: "stripe", name: "Stripe", shapes: [], on: true },
    destinations: [{ host: "api.stripe.com", port: 443, proto: "tcp", connect: "allow" }],
    verdicts: [{ symbol: "$MDU:nomodel_Read[2]", status: "pending", scope: "always" }, { symbol: SYMBOL, status: "approved", scope: "always" }],
    pending: [{ id: "pc-1" }],
  })), ["bound", "other", "issuer", "connect", "answered", "waiting", "pending"]);
});

test("INVARIANT: no $MDU: placeholder and no value in any output, whatever the answer holds", () => {
  const seeded = answer({
    bound: [{ path: "/home/u/app/.env", level: "no-model", binding: ["api.stripe.com"], source: "label" }],
    verdicts: [
      { symbol: SYMBOL, status: "approved", scope: "always" },
      { symbol: `$MDU:nomodel_Read[1]`, status: "denied", scope: "once" },
      { symbol: `$MDU:nomodel_Read[2]`, status: "pending", scope: "always" },
    ],
    pending: [{ id: "pc-1", from: "agent", bindings: ["api.stripe.com"], rule: SYMBOL }],
    issuer: { id: "stripe", name: "Stripe", shapes: [VALUE], on: true },
  });
  assert.ok(kinds(seeded).includes("answered") && kinds(seeded).includes("waiting"), "both counts are drawn from the placeholders");
  for (const a of [seeded, { ...seeded, axis: false }]) {
    const out = JSON.stringify(hostCheckWords(a, HOME));
    assert.ok(!out.includes("$MDU:"), `CONFIDENTIALITY VIOLATION: a placeholder in ${out}`);
    assert.ok(!out.includes(VALUE), `a value in ${out}`);
  }
});

test("the copy keeps the product's plain words", () => {
  const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter|symbol|binding|bindings|verdict|probe|unbound)\b|\$MDU:/i;
  const all = [
    answer({ bound: [{ path: "/home/u/a", level: "no-model", binding: ["x"], source: "label" }], verdicts: [{ symbol: SYMBOL, status: "approved", scope: "always" }, { symbol: SYMBOL, status: "pending", scope: "always" }], pending: [{}], issuer: { id: "s", name: "Stripe", shapes: [], on: true }, destinations: [{ host: "*", port: "*", proto: "udp", connect: "allow" }] }),
    answer({ release: { bound: null, unbound: null }, issuer: { id: "s", name: "Stripe", shapes: [], on: false } }),
    answer({ release: { bound: null, unbound: { ...BLOCK, stage: "verdict" } } }),
    answer({ release: { bound: null, unbound: { ...ALLOW, stage: "user-rule" } } }),
    answer({ axis: false }),
    answer({ verdicts: [1, 2].map((i) => ({ symbol: `$MDU:nomodel_Read[${i}]`, status: "pending", scope: "always" })) }),
  ];
  for (const a of all) for (const t of texts(a)) assert.doesNotMatch(t, FORBIDDEN, t);
  assert.doesNotMatch(HOST_REFUSED, FORBIDDEN);
});

test("checkedHost: trimmed and lowercased; a pasted https://, port, path, query and trailing dot stripped", () => {
  assert.deepEqual(checkedHost("  API.Stripe.com "), { host: "api.stripe.com" });
  assert.deepEqual(checkedHost("https://api.stripe.com/v1/charges?x=1#y"), { host: "api.stripe.com" });
  assert.deepEqual(checkedHost("http://pastebin.com:8080/raw"), { host: "pastebin.com" });
  assert.deepEqual(checkedHost("pastebin.com/raw/abc"), { host: "pastebin.com" });
  assert.deepEqual(checkedHost("api.example.com."), { host: "api.example.com" });
  assert.deepEqual(checkedHost("127.0.0.1:443"), { host: "127.0.0.1" });
  assert.deepEqual(checkedHost("localhost"), { host: "localhost" });
});

test("checkedHost refuses in words: empty, a space, a user name, brackets, a wildcard, too long, not text", () => {
  assert.deepEqual(checkedHost(""), { error: "Type a host name, like api.example.com." });
  assert.deepEqual(checkedHost("   "), { error: "Type a host name, like api.example.com." });
  assert.deepEqual(checkedHost(null), { error: "Type a host name, like api.example.com." });
  for (const bad of ["api stripe.com", "user@api.stripe.com", "[::1]", "*.stripe.com", "-bad.com", "a..b", "https://", "a_b.com", Array.from({ length: 5 }, () => "a".repeat(60)).join(".")]) {
    assert.deepEqual(checkedHost(bad), { error: HOST_REFUSED }, bad);
  }
  assert.equal(HOST_REFUSED, "Type a host name, like api.example.com: no https://, no path.");
});
