/**
 * egress-box.test — the bypass oracle's recorder and judge
 * (tests/lib/egress-box.ts; docs/design/agents/model-wires.md §11).
 *
 * NEW Mandu test code. The judge, pure: a bridged proxy connection is the
 * route; a dial to a scripted upstream's own port, a model-API host or a
 * model-API path is a bypass; other egress is unknown (fails) unless named
 * benign. The box, on every tier this host allows (the strongest namespace
 * tier, and the in-process fallback, which always runs): a plain Node client
 * inside it reaches the allowed "proxy" through the bridge; its request
 * straight to the "upstream" never reaches it (namespace tiers) and is
 * recorded with its path; in the caps tier its dial to api.openai.com is
 * recorded with the name and SNI, its lookup by the DNS stub, and a literal
 * public address lands on the catch-all; a program spawned through the shim
 * runs inside the box (another network namespace) with its exit status
 * relayed. A box that recorded nothing would fail here, so the oracle that
 * leans on it (the drill suite's OpenClaw bypass oracle) cannot pass by
 * going blind.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import { readlinkSync } from "node:fs";
import { tmpdir } from "node:os";

import { stateAxes } from "../lib/axes.js";
import {
  describeVerdict, egressNamespaceUnavailable, isModelApiHost, isModelApiPath, judgeEgress, startEgressBox,
  type EgressRecord, type EgressTier,
} from "../lib/egress-box.js";

stateAxes("secrets"); // the confidentiality oracle's machinery: the axis the bypass oracle runs on

const rec = (r: Partial<EgressRecord> & Pick<EgressRecord, "via">): EgressRecord => ({ t: 0, ...r });

test("judgeEgress: the proxy bridge is the route; an upstream's own port, a model-API host or path is a bypass; other egress is unknown unless benign", () => {
  const v = judgeEgress([
    rec({ via: "bridge", port: 4000, http: { method: "POST", path: "/_mandu/openai/x/chat/completions", host: "127.0.0.1:4000" } }),
    rec({ via: "catch", laddr: "127.0.0.1", lport: 5001, http: { method: "POST", path: "/api/v1/chat/completions", host: "127.0.0.1:5001" } }),
    rec({ via: "catch", laddr: "127.77.0.3", lport: 443, name: "openrouter.ai", sni: "openrouter.ai" }),
    rec({ via: "catch", laddr: "127.77.0.4", lport: 80, name: "example.net", http: { method: "POST", path: "/v1/responses", host: "example.net" } }),
    rec({ via: "catch", laddr: "127.77.0.5", lport: 443, name: "registry.npmjs.org", sni: "registry.npmjs.org" }),
    rec({ via: "catch", laddr: "127.77.0.6", lport: 443, name: "telemetry.example", sni: "telemetry.example" }),
    rec({ via: "dns", name: "api.openai.com", qtype: 1, answer: "127.77.0.7" }),
    rec({ via: "inproc", host: "127.0.0.1", port: 4000 }),
    rec({ via: "inproc", host: "127.0.0.1", port: 18789 }),
    rec({ via: "inproc", host: "127.0.0.1", port: 5001 }),
    rec({ via: "proxy-env", host: "api.githubcopilot.com", port: 443, sni: "api.githubcopilot.com" }),
  ], { proxyPorts: [4000], upstreamPorts: { 5001: "openrouter" }, benignHosts: { "registry.npmjs.org": "OpenClaw's update check: no model call" } });
  assert.equal(v.proxied.length, 2, describeVerdict(v));
  assert.equal(v.bypass.length, 5, describeVerdict(v));
  assert.match(v.bypass[0]!.why, /openrouter provider's own address directly/);
  assert.match(v.bypass[1]!.why, /model-API host .*openrouter\.ai/);
  assert.match(v.bypass[2]!.why, /model-API request/);
  assert.match(v.bypass[3]!.why, /openrouter provider's own address/);
  assert.match(v.bypass[4]!.why, /githubcopilot/);
  assert.equal(v.benign.length, 1);
  assert.equal(v.unknown.length, 1);
  assert.match(v.unknown[0]!.why, /telemetry\.example/);
  assert.equal(v.lookups.length, 1);
  // A bridge that is not the proxy's is no route.
  assert.equal(judgeEgress([rec({ via: "bridge", port: 9 })], { proxyPorts: [4000] }).unknown.length, 1);
});

test("judgeEgress: a bodiless GET or HEAD to a model-API host that names no model API is provider-side; a POST, a body or an unread TLS session is a bypass", () => {
  const v = judgeEgress([
    rec({ via: "catch", laddr: "127.77.1.4", lport: 443, name: "openrouter.ai", sni: "openrouter.ai", http: { method: "GET", path: "/api/v1/models", host: "openrouter.ai" }, body: "" }),
    rec({ via: "catch", laddr: "127.77.1.1", lport: 443, name: "api.anthropic.com", sni: "api.anthropic.com", http: { method: "HEAD", path: "/api/hello", host: "api.anthropic.com" }, body: "" }),
    rec({ via: "catch", laddr: "127.77.1.1", lport: 443, name: "api.anthropic.com", sni: "api.anthropic.com", http: { method: "POST", path: "/v1/messages/count_tokens", host: "api.anthropic.com" }, body: "{\"messages\":[]}" }),
    rec({ via: "catch", laddr: "127.77.1.1", lport: 443, name: "api.anthropic.com", sni: "api.anthropic.com", http: { method: "GET", path: "/v1/messages", host: "api.anthropic.com" }, body: "" }),
    rec({ via: "catch", laddr: "127.77.1.1", lport: 443, name: "api.anthropic.com", sni: "api.anthropic.com", tls: "ECONNRESET" }),
  ], { proxyPorts: [4000] });
  assert.equal(v.providerSide.length, 2, describeVerdict(v));
  assert.equal(v.bypass.length, 3, describeVerdict(v));
  assert.match(v.bypass[2]!.why, /\[TLS: ECONNRESET\]/);
  // A program named benign by its command line: benign on any path but a model API's.
  const dialer = { pid: 7, chain: ["claude auth status --json", "openclaw-gateway"] };
  const d = judgeEgress([
    rec({ via: "catch", laddr: "127.77.1.1", lport: 443, name: "api.anthropic.com", sni: "api.anthropic.com", tls: "ECONNRESET", dialer }),
    rec({ via: "catch", laddr: "127.77.1.1", lport: 443, name: "api.anthropic.com", sni: "api.anthropic.com", http: { method: "POST", path: "/v1/messages", host: "api.anthropic.com" }, body: "{}", dialer }),
  ], { proxyPorts: [4000], benignDialers: [{ command: /^claude auth status\b/, why: "a sign-in check" }] });
  assert.equal(d.benign.length, 1, describeVerdict(d));
  assert.match(d.benign[0]!.why, /by pid 7: claude auth status --json <- openclaw-gateway\]: a sign-in check/);
  assert.equal(d.bypass.length, 1, "the same program's model call is still a bypass");
  // A dialer gone before the read: named by the processes that looked the address up, all of them.
  const gone = rec({ via: "catch", laddr: "127.77.1.1", lport: 443, name: "api.anthropic.com", sni: "api.anthropic.com", tls: "ECONNRESET" });
  const asked = rec({ via: "dns", name: "api.anthropic.com", qtype: 1, answer: "127.77.1.1", dialer });
  const opts = { proxyPorts: [4000], benignDialers: [{ command: /^claude auth status\b/, why: "a sign-in check" }] };
  assert.equal(judgeEgress([asked, gone], opts).benign.length, 1);
  const other = rec({ via: "dns", name: "api.anthropic.com", qtype: 1, answer: "127.77.1.1", dialer: { pid: 8, chain: ["openclaw-gateway"] } });
  assert.equal(judgeEgress([asked, other, gone], opts).bypass.length, 1, "another program also looked it up: a bypass");
  assert.equal(judgeEgress([rec({ ...asked, dialer: undefined }), gone], opts).bypass.length, 1, "an unnamed lookup: a bypass");
  // A holder that hid its descriptors (non-dumpable): benign only when every
  // process it can be is a benign program.
  const hidden = (cmds: string[]) => ({ pid: null, chain: [], why: "socket:[9] is held by a process whose descriptors cannot be read",
    candidates: cmds.map((c, i) => ({ pid: 40 + i, chain: [c, "openclaw-gateway"] })) });
  const conn = (d: ReturnType<typeof hidden>) => rec({ via: "catch", laddr: "127.77.1.1", lport: 443, name: "api.anthropic.com", sni: "api.anthropic.com", tls: "ECONNRESET", dialer: d });
  const ok = judgeEgress([conn(hidden(["claude auth status --json", "claude auth status --json"]))], opts);
  assert.equal(ok.benign.length, 1, describeVerdict(ok));
  assert.match(ok.benign[0]!.why, /by one of pid 40: claude auth status --json; pid 41: claude auth status --json \(socket:\[9\]/);
  const mixed = judgeEgress([conn(hidden(["claude auth status --json", "openclaw-gateway"]))], opts);
  assert.equal(mixed.bypass.length, 1, `a hidden holder that may be another program: a bypass\n${describeVerdict(mixed)}`);
  assert.equal(judgeEgress([conn(hidden([]))], opts).bypass.length, 1, "no candidate at all: a bypass");
  // And a connection the box could name nothing for says why.
  assert.match(describeVerdict(judgeEgress([rec({ ...gone, dialerWhy: "no tcp socket for port 5" })], opts)), /\[no dialer: no tcp socket for port 5\]/);
});

test("isModelApiHost / isModelApiPath: the provider families and wires", () => {
  for (const h of ["api.openai.com", "openrouter.ai", "acme.openai.azure.com", "us-east5-aiplatform.googleapis.com", "api.githubcopilot.com",
    "api.individual.githubcopilot.com", "bedrock-runtime.eu-west-1.amazonaws.com", "generativelanguage.googleapis.com:443", "ollama.com"]) {
    assert.ok(isModelApiHost(h), h);
  }
  for (const h of ["registry.npmjs.org", "example.net", null, "127.0.0.1"]) assert.ok(!isModelApiHost(h), String(h));
  for (const p of ["/v1/chat/completions", "/v1/responses?api-version=1", "/v1/messages", "/v1beta/models/gemini-2.5-flash:streamGenerateContent",
    "/api/chat", "/backend-api/codex/responses", "/model/anthropic.claude/converse-stream", "/v1beta/interactions"]) {
    assert.ok(isModelApiPath(p), p);
  }
  for (const p of ["/", "/api/tags", "/healthz", undefined]) assert.ok(!isModelApiPath(p), String(p));
});

/** A recording HTTP server on loopback. */
async function recorder(answer: string): Promise<{ server: Server; port: number; seen: string[] }> {
  const seen: string[] = [];
  const server = createServer((req, res) => {
    seen.push(`${req.method} ${req.url}`);
    req.resume();
    req.on("end", () => { res.writeHead(200, { "content-type": "text/plain" }); res.end(answer); });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return { server, port: (server.address() as { port: number }).port, seen };
}

// The client inside the box: the proxy, the upstream straight, a model-API
// host by name over TLS, a literal public address; each outcome printed.
const CLIENT = `
const http = require("node:http"); const tls = require("node:tls"); const net = require("node:net");
const [proxy, upstream, outside] = process.argv.slice(1).map(Number);
const out = {};
const get = (port, path) => new Promise((res) => {
  const r = http.request({ host: "127.0.0.1", port, path, method: "POST", headers: { "content-type": "application/json" } }, (resp) => {
    let b = ""; resp.on("data", (d) => b += d); resp.on("end", () => res(resp.statusCode + " " + b.trim()));
  });
  r.on("error", (e) => res("error " + e.code)); r.setTimeout(5000, () => { r.destroy(); res("timeout"); });
  r.end("{}");
});
const dialTls = (host) => new Promise((res) => {
  const s = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false }, () => { s.destroy(); res("connected"); });
  s.on("error", (e) => res("error " + (e.code || e.message))); s.setTimeout(5000, () => { s.destroy(); res("timeout"); });
});
const postTls = (host) => new Promise((res) => {
  const r = require("node:https").request({ host, path: "/v1/responses", method: "POST", headers: { "content-type": "application/json" } }, (resp) => { resp.resume(); resp.on("end", () => res(String(resp.statusCode))); });
  r.on("error", (e) => res("error " + (e.code || e.message))); r.setTimeout(5000, () => { r.destroy(); res("timeout"); });
  r.end(JSON.stringify({ input: "MDU_BOX_PEEK" }));
});
// Every outcome settles the promise: 'close' is heard from the start (a
// connection the catch-all answers and ends at once closes before a late
// listener), and a ref'd timer keeps the loop alive until the last step.
const dialRaw = (host, port) => new Promise((res) => {
  const s = net.connect({ host, port }, () => { s.end("GET /v1/models HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n"); });
  s.on("close", () => res("closed"));
  s.on("error", (e) => res("error " + e.code)); s.setTimeout(5000, () => { s.destroy(); res("timeout"); });
});
const keep = setTimeout(() => { console.log(JSON.stringify({ ...out, hung: true })); process.exit(3); }, 40000);
process.on("exit", (c) => { if (c === 0 && !out.done) process.stderr.write("client: the event loop emptied before the last step: " + JSON.stringify(out) + "\\n"); });
(async () => {
  out.proxy = await get(proxy, "/_mandu/openai/x/chat/completions");
  out.upstream = await get(upstream, "/api/v1/chat/completions");
  // Only where nothing can leave: the fallback blocks nothing.
  if (outside) { out.openai = await dialTls("api.openai.com"); out.post = await postTls("api.openai.com"); out.literal = await dialRaw("203.0.113.9", 443); }
  out.done = "yes";
  clearTimeout(keep);
  console.log(JSON.stringify(out));
})();
`;

const namespaceSkip = egressNamespaceUnavailable();

for (const tier of ["netns", "inproc"] as const) {
  const skip = tier === "netns" && namespaceSkip !== null ? namespaceSkip : false;
  test(`the egress box (${tier === "netns" ? "the strongest namespace tier here" : "the in-process fallback"}): the proxy is reached through the bridge; a request straight to the upstream is recorded as a bypass${tier === "netns" ? " and never reaches it" : ""} (secrets axes, explicit)`,
    { skip, timeout: 120_000 }, async (t) => {
      const proxy = await recorder("from-the-proxy");
      const upstream = await recorder("from-the-upstream");
      const tiers: EgressTier[] = tier === "netns" ? ["netns+caps", "netns"] : ["inproc"];
      const box = await startEgressBox({ allow: [proxy.port], catchPorts: [upstream.port], tiers });
      try {
        t.diagnostic(`tier ${box.tier}${box.why ? ` (not stronger: ${box.why})` : ""}; facts ${JSON.stringify(box.facts)}`);
        const r = await box.run([process.execPath, "-e", CLIENT, String(proxy.port), String(upstream.port), tier === "netns" ? "1" : "0"], {
          env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: tmpdir() }, cwd: tmpdir(), timeoutMs: 60_000,
        });
        assert.equal(r.code, 0, `the client ran in the box: ${r.stderr}`);
        const last = r.stdout.trim().split("\n").pop() ?? "";
        assert.ok(last.startsWith("{"), `the client printed its outcomes (exit ${r.code}): ${JSON.stringify(r.stdout)} ${JSON.stringify(r.stderr.slice(-600))}`);
        const out = JSON.parse(last) as Record<string, string>;
        assert.equal(out["done"], "yes", `the client finished every step: ${last}`);
        t.diagnostic(`client: ${JSON.stringify(out)}`);
        assert.equal(out["proxy"], "200 from-the-proxy", "the bridge reaches the proxy");
        assert.deepEqual(proxy.seen, ["POST /_mandu/openai/x/chat/completions"]);
        const v = judgeEgress(box.records(), { proxyPorts: [proxy.port], upstreamPorts: { [upstream.port]: "the-upstream" } });
        t.diagnostic(describeVerdict(v));
        assert.ok(v.proxied.length >= 1, `the proxy connection is recorded as the route:\n${describeVerdict(v)}`);
        assert.ok(v.bypass.some((f) => /the-upstream provider's own address/.test(f.why)),
          `the direct request to the upstream is a bypass:\n${describeVerdict(v)}`);
        if (box.tier === "inproc") {
          // The fallback blocks nothing: the request DID reach the upstream.
          assert.deepEqual(upstream.seen, ["POST /api/v1/chat/completions"], "the in-process fallback records but does not block");
          return;
        }
        assert.deepEqual(upstream.seen, [], "SECURITY: nothing inside the box reached the upstream directly");
        assert.match(out["upstream"]!, /^503 mandu egress box/, "the catch-all answered the direct request");
        const direct = box.records().find((x) => x.via === "catch" && x.lport === upstream.port);
        assert.equal(direct?.http?.path, "/api/v1/chat/completions", "the catch-all recorded the direct request's path");
        assert.match((direct?.dialer?.chain ?? []).join(" "), /MDU_BOX_PEEK|-e/, `the catch-all named the program that dialed: ${JSON.stringify(direct?.dialer)}`);
        // (With the peek certificate the catch-all completes the handshake itself: it reads, never forwards.)
        if (!(box.tier === "netns+caps" && box.facts?.["tlsPeek"] === true)) assert.notEqual(out["openai"], "connected", "no TLS session to a model-API host completes in the box");
        if (box.tier === "netns+caps") {
          assert.ok(v.bypass.some((f) => f.record.sni === "api.openai.com"), `the dial to api.openai.com is recorded with its SNI:\n${describeVerdict(v)}`);
          assert.ok(v.lookups.some((x) => x.name === "api.openai.com"), "the DNS stub recorded the lookup");
          if (box.facts?.["tlsPeek"] === true) {
            const peeked = box.records().find((x) => x.via === "catch" && x.sni === "api.openai.com" && x.http !== undefined);
            assert.equal(peeked?.http?.path, "/v1/responses", "the peek certificate read the request's path inside TLS");
            assert.match(peeked?.body ?? "", /MDU_BOX_PEEK/, "and the head of its body");
          }
          if (box.facts?.["route"] === true) {
            assert.ok(box.records().some((x) => x.via === "catch" && x.laddr === "203.0.113.9" && x.lport === 443), "a literal public address lands on the catch-all");
          }
        } else {
          t.diagnostic(`tier netns: the dial to api.openai.com:443 was ${out["openai"]} (refused, not attributed: no port below 1024 without capabilities)`);
        }
      } finally {
        await box.close();
        proxy.server.close();
        upstream.server.close();
      }
    });
}

test("the egress box's shim: a program spawned by name from outside runs inside the box, its output and exit status relayed (secrets axes, explicit)",
  { skip: namespaceSkip ?? false, timeout: 60_000 }, async () => {
    const box = await startEgressBox({ allow: [], tiers: ["netns+caps", "netns"] });
    try {
      const dir = box.shimDir("probe", process.execPath);
      const child = spawn(`${dir}/probe`, ["-e", "console.log(require('fs').readlinkSync('/proc/self/ns/net')); process.exit(7)"], { stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      child.stdout.on("data", (d) => { out += String(d); });
      const code = await new Promise<number | null>((r) => child.on("close", (c) => r(c)));
      assert.equal(code, 7, "the exit status is relayed");
      assert.match(out, /^net:\[\d+\]/);
      assert.notEqual(out.trim(), readlinkSync("/proc/self/ns/net"), "the program ran in the box's own network namespace");
    } finally {
      await box.close();
    }
  });
