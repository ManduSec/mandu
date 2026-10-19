/**
 * prompt-classifier-plugin.test — Mandu's reference classifier plugin
 * (prompt-filter/plugins/local-classifier.mjs) against a FAKE local model on
 * loopback, never a real one (confidentiality-plan-15-prompt-filter.md
 * §4.3, §5, §13.5). Mandu-new.
 *
 * Proves:
 *   - each wire's call (an OpenAI-compatible `/v1/chat/completions`, as
 *     Ollama serves; `/v1/messages` for an `anthropic` wire): the model and
 *     the token from the request, temperature 0, ONE user turn holding the
 *     segment's text under a fixed system prompt, no tools;
 *   - a bad reply is retried once, then fails the run (no answer, a nonzero
 *     exit): the arbiter's `on_error` decides; an HTTP error fails at once;
 *     the request's deadline bounds the run;
 *   - through a REAL ArbiterServer (the pack written by
 *     local-classifier-pack.mjs, the test stand-in guard): the span the model
 *     names is redacted on the human's text and the harness's, and a
 *     registered value in the same prompt never reaches the model.
 *
 * Axes: secrets (stated; the server's confidentiality option pinned ON).
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createServer, type IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
// @ts-expect-error -- a plain .mjs plugin (no types): it runs from a pinned copy
import { classify } from "../../prompt-filter/plugins/local-classifier.mjs";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const HERE = dirname(fileURLToPath(import.meta.url));
const PLUGINS = join(HERE, "..", "..", "prompt-filter", "plugins");
const GUARD = join(HERE, "..", "fixtures", "prompt-plugin", "fake-guard.sh");
const KEY = "sk-live-Zq81Hc0vNw3PpL6tYb4R";

const dirs: string[] = [];
const closers: Array<() => void> = [];
after(() => {
  for (const c of closers) c();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
  resetCurrentPolicyForTests();
});

interface Seen { url: string; headers: IncomingHttpHeaders; body: Record<string, unknown> }

/** A fake model: answers each call with `reply(body)` (a string: the
 *  model's text; a number: an HTTP status). */
async function fakeModel(reply: (body: Record<string, unknown>, n: number) => string | number, wire: "openai-chat" | "anthropic" = "openai-chat"): Promise<{ url: string; seen: Seen[] }> {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const body = JSON.parse(raw) as Record<string, unknown>;
      seen.push({ url: req.url ?? "", headers: req.headers, body });
      const r = reply(body, seen.length);
      if (typeof r === "number") { res.writeHead(r); res.end("{}"); return; }
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(wire === "anthropic" ? { content: [{ type: "text", text: r }] } : { choices: [{ message: { role: "assistant", content: r } }] }));
    });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  closers.push(() => server.close());
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen };
}

const ans = (...f: Array<[string, string]>): string => JSON.stringify({ findings: f.map(([category, text]) => ({ category, text })) });
const req = (url: string, segs: Array<[string, string]>, o: { wire?: string; deadlineMs?: number; tokenEnv?: string } = {}) => ({
  protocol: "mandu-prompt-filter/1", filter: "local-classifier", deadlineMs: o.deadlineMs ?? 5000,
  categories: ["pii.person", "acme.codename"],
  endpoint: { name: "ollama", url, wire: o.wire ?? "openai-chat", model: "qwen2.5:7b", ...(o.tokenEnv ? { tokenEnv: o.tokenEnv } : {}) },
  segments: segs.map(([id, text]) => ({ id, origin: "human", text })),
});

test("the OpenAI-compatible call (Ollama): one user turn under the fixed system prompt, temperature 0, no tools; offsets computed here", async () => {
  const m = await fakeModel(() => ans(["pii.person", "Kim Lee"], ["acme.codename", "Falcon"], ["pii.email", "ask"]));
  const out = await classify(req(`${m.url}/v1`, [["s1", "ask Kim Lee about Falcon"], ["s2", "x"]], { tokenEnv: "OLLAMA_TOKEN" }), { OLLAMA_TOKEN: "t0k" });
  assert.deepEqual(out, { findings: [
    { segment: "s1", start: 4, end: 11, category: "pii.person" },
    { segment: "s1", start: 18, end: 24, category: "acme.codename" },
  ] });
  assert.equal(m.seen.length, 1, "a segment too short to hold anything is not sent");
  const s = m.seen[0]!;
  assert.equal(s.url, "/v1/chat/completions");
  assert.equal(s.headers.authorization, "Bearer t0k");
  assert.equal(s.body.model, "qwen2.5:7b");
  assert.equal(s.body.temperature, 0);
  assert.equal(s.body.tools, undefined);
  const msgs = s.body.messages as Array<{ role: string; content: string }>;
  assert.deepEqual(msgs.map((x) => x.role), ["system", "user"]);
  assert.equal(msgs[1]!.content, "ask Kim Lee about Falcon");
  assert.match(msgs[0]!.content, /- pii\.person\n- acme\.codename/);
});

// P0 item 13 (a): a span cut by the 6000-character chunk boundary reached
// the model as two halves, and neither half was found.
test("a span across the chunk cut is found once, at its offset in the segment; a span inside the overlap is not reported twice", async () => {
  const span = "Blue Osprey";
  // 5990 characters of 10-character words, "Kim Lee" at 5500 (inside the
  // overlap: both chunks read it); the first cut falls inside the span.
  const filler = `${"lorem ips ".repeat(550)}Kim Lee x ${"lorem ips ".repeat(48)}`;
  const text = `${filler}${span} ${"tail word ".repeat(700)}`;
  const at = text.indexOf(span);
  assert.ok(at < 6000 && at + span.length > 6000);
  const m = await fakeModel((body) => {
    const user = (body.messages as Array<{ role: string; content: string }>)[1]!.content;
    const f: Array<[string, string]> = [];
    if (user.includes(span)) f.push(["acme.codename", span]);
    if (user.includes("Kim Lee")) f.push(["pii.person", "Kim Lee"]);
    return ans(...f);
  });
  const out = await classify(req(m.url, [["s", text]]));
  assert.ok(m.seen.length >= 2, "the segment went in more than one chunk");
  const users = m.seen.map((x) => (x.body.messages as Array<{ content: string }>)[1]!.content);
  assert.ok(users.filter((u) => u.includes("Kim Lee")).length >= 2, "two chunks both read the name");
  assert.deepEqual(out.findings.filter((f: { category: string }) => f.category === "acme.codename"), [{ segment: "s", start: at, end: at + span.length, category: "acme.codename" }]);
  const kim = text.indexOf("Kim Lee");
  assert.deepEqual(out.findings.filter((f: { category: string }) => f.category === "pii.person"), [{ segment: "s", start: kim, end: kim + 7, category: "pii.person" }], "a span two chunks both hold is one finding");
});

test("the anthropic wire: /v1/messages with x-api-key", async () => {
  const m = await fakeModel(() => ans(["pii.person", "Kim Lee"]), "anthropic");
  const out = await classify(req(m.url, [["s", "ask Kim Lee"]], { wire: "anthropic", tokenEnv: "K" }), { K: "kk" });
  assert.equal(out.findings.length, 1);
  assert.equal(m.seen[0]!.url, "/v1/messages");
  assert.equal(m.seen[0]!.headers["x-api-key"], "kk");
  assert.equal(typeof m.seen[0]!.body.system, "string");
});

test("a bad reply is retried once, then fails the run; an HTTP error fails at once; the deadline bounds the run", async () => {
  const flaky = await fakeModel((_, n) => (n === 1 ? "sorry, no" : ans(["pii.person", "Kim Lee"])));
  assert.equal((await classify(req(flaky.url, [["s", "ask Kim Lee"]]))).findings.length, 1);
  assert.equal(flaky.seen.length, 2);
  const bad = await fakeModel(() => "never json");
  await assert.rejects(() => classify(req(bad.url, [["s", "ask Kim Lee"]])), /not \{findings/);
  assert.equal(bad.seen.length, 2);
  const down = await fakeModel(() => 500);
  await assert.rejects(() => classify(req(down.url, [["s", "ask Kim Lee"]])), /HTTP 500/);
  assert.equal(down.seen.length, 1);
  const slow = createServer(() => { /* never answers */ });
  await new Promise<void>((ok) => slow.listen(0, "127.0.0.1", ok));
  closers.push(() => slow.close());
  const t0 = Date.now();
  await assert.rejects(() => classify(req(`http://127.0.0.1:${(slow.address() as AddressInfo).port}`, [["s", "ask Kim Lee"]], { deadlineMs: 600 })));
  assert.ok(Date.now() - t0 < 3000, "the deadline bounds the run");
  // As a program: no answer, a nonzero exit.
  const r = spawnSync(process.execPath, [join(PLUGINS, "local-classifier.mjs")], { input: JSON.stringify(req(down.url, [["s", "ask Kim Lee"]])), encoding: "utf8" });
  assert.notEqual(r.status, 0);
  assert.equal(r.stdout, "");
});

test("through a real arbiter (the generated pack): the model's span is redacted on human and harness text; a registered value never reaches the model", async () => {
  const m = await fakeModel((body) => {
    const user = (body.messages as Array<{ role: string; content: string }>)[1]!.content;
    return user.includes("Osprey") ? ans(["org.confidential", "Osprey"]) : ans();
  });
  const dir = mkdtempSync(join(tmpdir(), "mdu-classifier-plugin-"));
  dirs.push(dir);
  const packs = join(dir, "prompt-filters");
  mkdirSync(packs);
  const gen = spawnSync(process.execPath, [join(PLUGINS, "local-classifier-pack.mjs"), "--deadline-ms", "8000"], { encoding: "utf8" });
  assert.equal(gen.status, 0, gen.stderr);
  assert.match(gen.stdout, new RegExp(`exec: ${realpathSync(process.execPath).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
  writeFileSync(join(packs, "local-classifier.yaml"), gen.stdout);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\nmodels:\n  - name: ollama\n    url: ${m.url}\n    wire: openai-chat\n    model: qwen2.5:7b\n    local: true\nprompt_filters:\n  filters:\n    local-classifier: { on: true, endpoint: ollama }\n`);
  const sock = join(dir, "a.sock");
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0, packDir: null,
    promptPackDir: packs, adminPromptPackDir: null, adminPolicyDir: null,
    promptPlugins: { netGuard: GUARD, landlockApply: null, bwrap: null, dir: join(dir, "plugins"), probe: async () => ({ guard: true, landlock: false, seccomp: false, namespaces: false, notes: [] }) },
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  try {
    await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    const out = await data.filterPrompt({ agent: "claude-code", segments: [
      { id: "h", origin: "human", text: `ship Osprey with ${KEY}` },
      { id: "r", origin: "harness", text: "<system-reminder>Osprey ships Friday</system-reminder>" },
    ] });
    const [h, r] = out.segments;
    assert.match(h!.text!, /^ship \[redacted: org\.confidential\] with \$MDU:/);
    assert.equal(r!.text, "<system-reminder>[redacted: org.confidential] ships Friday</system-reminder>");
    assert.ok(m.seen.length >= 2);
    for (const s of m.seen) assert.ok(!JSON.stringify(s.body).includes(KEY), "CONFIDENTIALITY VIOLATION: a registered value reached the classifier model");
  } finally {
    data.close();
    await server.close();
  }
});
