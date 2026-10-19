/**
 * prompt-filter-plugin-op.test — prompt filter plugins over the arbiter's
 * real sockets (confidentiality-plan-15-prompt-filter.md §4.3, §5, §12
 * 2026-10-03, phase 3). Mandu-new.
 *
 * A listening ArbiterServer with a policy file (a `local: true` model, a
 * plugin switched on with its `endpoint:`) and the person's pack directory
 * holding PLUGIN packs pinned to node and the test plugin
 * (fixtures/prompt-plugin/fake-plugin.mjs). The network guard is the TEST
 * stand-in (fixtures/prompt-plugin/fake-guard.sh, through the probe seam):
 * this suite proves the arbiter's side; prompt-filter-plugin-confine.test.ts
 * proves the confinement with the real bins. Through ArbiterClient:
 *   - a plugin's finding is redacted (and masked where the action says so,
 *     at the PACK's level), on human AND harness text (§5 as amended), in
 *     one plugin run per request, and cached;
 *   - the plugin runs from the private copy with the allowlisted
 *     environment only;
 *   - every failure blocks with no text under the default `on_error`: a
 *     changed pin, a timeout, a nonzero exit, a bad answer, a category the
 *     pack does not declare, an endpoint that is not `local: true`, no
 *     guard; `on_error: pass` lets the prompt through unfiltered by it;
 *   - the panel's projection names the plugin, its pin, its model, its last
 *     run and the legs, and never a prompt; the plugin pack is not
 *     editable.
 *
 * Axes: secrets (stated; the server's confidentiality option pinned ON).
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { NO_ADMIN_LAYER, setAdminLayer } from "../../policy/admin-layer.js";
import type { ConfineLegs } from "../../prompt-filter/plugin-confine.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const FIX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "prompt-plugin");
const PLUGIN = join(FIX, "fake-plugin.mjs");
const GUARD = join(FIX, "fake-guard.sh");
const NODE = realpathSync(process.execPath);
const sha = (p: string): string => createHash("sha256").update(readFileSync(p)).digest("hex");
const LEGS: ConfineLegs = { guard: true, landlock: false, seccomp: false, namespaces: false, notes: ["test stand-in guard"] };

const dirs: string[] = [];
after(() => {
  setAdminLayer(NO_ADMIN_LAYER);
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function pluginPack(id: string, args: string[], o: { endpoint?: "required"; deadline?: number; cats?: string; scriptSha?: string } = {}): string {
  return [
    `pack: ${id}`, "version: 1", "plugin:",
    `  exec: ${NODE}`, `  sha256: "${sha(NODE)}"`,
    `  script: ${PLUGIN}`, `  script_sha256: "${o.scriptSha ?? sha(PLUGIN)}"`,
    `  args: ${JSON.stringify(args)}`,
    ...(o.endpoint ? [`  endpoint: ${o.endpoint}`] : []),
    ...(o.deadline ? [`  deadline_ms: ${o.deadline}`] : []),
    "categories:", o.cats ?? "  - { category: acme.codename, level: local-model }\n  - pii.person",
    "",
  ].join("\n");
}

async function rig(policyYaml: string, packs: Record<string, string>, o: { guard?: string | null; legs?: ConfineLegs } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "mdu-prompt-plugin-"));
  dirs.push(dir);
  const packDir = join(dir, "prompt-filters");
  mkdirSync(packDir);
  for (const [name, text] of Object.entries(packs)) writeFileSync(join(packDir, `${name}.yaml`), text);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, policyYaml);
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0, packDir: null,
    promptPackDir: packDir, adminPromptPackDir: join(dir, "admin-packs"), adminPolicyDir: null, packKeysDir: join(dir, "keys"),
    promptPlugins: { netGuard: o.guard === undefined ? GUARD : o.guard, landlockApply: null, bwrap: null, dir: join(dir, "plugins"), probe: async () => o.legs ?? LEGS },
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  const human = new ArbiterClient(humanSock);
  return { dir, packDir, server, data, human, close: async () => { data.close(); human.close(); await server.close(); } };
}

const POLICY = (filters: string, actions = "  actions:\n    acme.codename: mask\n"): string =>
  `version: 1\nmodels:\n  - name: ollama\n    url: http://127.0.0.1:11434\n    wire: openai-chat\n    model: llama3.2\n    local: true\n  - name: remote\n    url: https://api.example.com\n    wire: openai-chat\n    model: x\nprompt_filters:\n  filters:\n${filters}${actions}`;

test("a plugin's findings act on human AND harness text, at the pack's level; one run per request; cached", async () => {
  const r = await rig(POLICY("    acme-cls: on\n"), { acme: pluginPack("acme-cls", ["--find", "Falcon", "acme.codename", "--find", "Kim Lee", "pii.person"]) });
  try {
    const out = await r.data.filterPrompt({ session: "s1", agent: "claude-code", segments: [
      { id: "h", origin: "human", text: "ask Kim Lee about Falcon" },
      { id: "r", origin: "harness", text: "<system-reminder>Falcon is due</system-reminder>" },
      { id: "q", origin: "human", text: "nothing here" },
    ] });
    const [h, rr, q] = out.segments;
    assert.equal(h!.action, "rewrite");
    assert.match(h!.text!, /^ask \[redacted: pii\.person\] about \$MDU:/);
    assert.ok(!h!.text!.includes("Falcon") && !h!.text!.includes("Kim Lee"));
    const masked = h!.findings.find((f) => f.category === "acme.codename")!;
    assert.equal(masked.filterId, "acme-cls");
    assert.equal(masked.action, "mask");
    assert.equal(rr!.action, "rewrite", "harness text runs the plugin too (§5 as amended)");
    assert.ok(!rr!.text!.includes("Falcon"));
    assert.equal(q!.action, "pass");
    const pf = await r.data.promptFilters();
    const row = pf.filters.find((f) => f.id === "acme-cls")!;
    assert.equal(row.kind, "plugin");
    assert.equal(row.plugin!.runs, 1, "one plugin run for the whole request");
    // A resend: the mint changed the registered set, so it rescans once
    // (§13.1 item 4) with the same symbol; the next one is cached, no run.
    const seg = [{ id: "h", origin: "human" as const, text: "ask Kim Lee about Falcon" }];
    const again = await r.data.filterPrompt({ session: "s1", agent: "claude-code", segments: seg });
    assert.equal(again.segments[0]!.text, h!.text, "the same symbol on a resend");
    const third = await r.data.filterPrompt({ session: "s1", agent: "claude-code", segments: seg });
    assert.equal(third.segments[0]!.cached, true);
    assert.equal(third.segments[0]!.text, h!.text);
    assert.equal((await r.data.promptFilters()).filters.find((f) => f.id === "acme-cls")!.plugin!.runs, 2);
    // The panel's projection: the pin, the legs, never a prompt; the pack is not editable.
    assert.equal(row.plugin!.script, PLUGIN);
    assert.equal(row.plugin!.scriptSha256, sha(PLUGIN));
    assert.deepEqual(row.plugin!.confinement, { guard: true, landlock: false, seccomp: false, namespaces: false, notes: ["test stand-in guard"] });
    assert.ok(!JSON.stringify(pf).includes("Falcon") && !JSON.stringify(pf).includes("Kim Lee"));
    const packs = await r.human.promptFilterPacks();
    const p = packs.packs.find((x) => x.id === "acme-cls")!;
    assert.equal(p.editable, false);
    assert.equal(p.plugin!.exec, NODE);
  } finally {
    await r.close();
  }
});

test("the plugin runs from the private copy, with the allowlisted environment only", async () => {
  const r0 = mkdtempSync(join(tmpdir(), "mdu-prompt-plugin-env-"));
  dirs.push(r0);
  const envFile = join(r0, "env.json");
  const r = await rig(POLICY("    acme-cls: on\n"), { acme: pluginPack("acme-cls", ["--log-env", envFile]) });
  try {
    process.env.MANDU_TEST_SECRET_ENV = "should-not-pass";
    await r.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: "hello" }] });
    // The stand-in guard is a shell, which adds its own: PWD (every sh),
    // SHLVL (bash, macOS's /bin/sh) and __CF_USER_TEXT_ENCODING (macOS's
    // /bin/sh trampoline). The real guard execs the plugin directly.
    const SHELL_ADDED = new Set(["PWD", "SHLVL", "__CF_USER_TEXT_ENCODING"]);
    assert.deepEqual((JSON.parse(readFileSync(envFile, "utf8")) as string[]).filter((k) => !SHELL_ADDED.has(k)), process.env.LC_ALL ? ["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"] : ["HOME", "LANG", "PATH", "TMPDIR"]);
    assert.ok(existsSync(join(r.dir, "plugins", "pinned", sha(PLUGIN), "fake-plugin.mjs")), "the verified copy");
  } finally {
    delete process.env.MANDU_TEST_SECRET_ENV;
    await r.close();
  }
});

test("every failure blocks with no text under the default on_error; on_error: pass lets the prompt through", async () => {
  const cases: Array<{ name: string; filters: string; pack: string; why: RegExp; guard?: string | null; legs?: ConfineLegs }> = [
    { name: "a changed pin", filters: "    acme-cls: on\n", pack: pluginPack("acme-cls", [], { scriptSha: "0".repeat(64) }), why: /its pin: .*fake-plugin\.mjs changed since it was pinned/ },
    { name: "a timeout", filters: "    acme-cls: on\n", pack: pluginPack("acme-cls", ["--sleep", "3000"], { deadline: 300 }), why: /did not answer within 300 ms/ },
    { name: "a nonzero exit", filters: "    acme-cls: on\n", pack: pluginPack("acme-cls", ["--exit", "4"]), why: /exited with 4/ },
    { name: "a bad answer", filters: "    acme-cls: on\n", pack: pluginPack("acme-cls", ["--raw", "{\"findings\":[],\"x\":1}"]), why: /key the protocol does not know/ },
    { name: "an undeclared category", filters: "    acme-cls: on\n", pack: pluginPack("acme-cls", ["--find", "hello", "pii.email"]), why: /category the pack does not declare/ },
    { name: "no endpoint named", filters: "    acme-cls: on\n", pack: pluginPack("acme-cls", [], { endpoint: "required" }), why: /needs a model, and the policy names none/ },
    { name: "no guard", filters: "    acme-cls: on\n", pack: pluginPack("acme-cls", []), why: /network guard \(mandu-net-guard\) is not available/, guard: null },
    { name: "a guard that cannot confine", filters: "    acme-cls: on\n", pack: pluginPack("acme-cls", []), why: /network guard .* not available/, legs: { guard: false, landlock: false, seccomp: false, namespaces: false, notes: ["no seccomp"] } },
  ];
  for (const c of cases) {
    const r = await rig(POLICY(c.filters), { acme: c.pack }, { ...(c.guard !== undefined ? { guard: c.guard } : {}), ...(c.legs ? { legs: c.legs } : {}) });
    try {
      const out = await r.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: "hello Falcon" }] });
      const [h] = out.segments;
      assert.equal(h!.action, "block", c.name);
      assert.equal(h!.text, undefined, `${c.name}: nothing of the segment may go`);
      assert.match(h!.reason!, /prompt filter acme-cls/, c.name);
      const pf = await r.data.promptFilters();
      const row = pf.filters.find((f) => f.id === "acme-cls");
      assert.ok(row?.plugin, `${c.name}: ${JSON.stringify(pf.filters)} ${JSON.stringify(pf.packProblems)}`);
      assert.match(row.plugin.lastError ?? "", c.why, c.name);
    } finally {
      await r.close();
    }
  }
  // A model that is not local: true: the policy file is refused at load
  // (the validator; the spawn-time check is unit-tested).
  await assert.rejects(() => rig(POLICY("    acme-cls: { on: true, endpoint: remote }\n"), { acme: pluginPack("acme-cls", [], { endpoint: "required" }) }),
    /prompt_filters\.filters\.acme-cls\.endpoint: 'remote' is not declared local: true/);
  const pass = await rig(POLICY("    acme-cls: { on: true, on_error: pass }\n"), { acme: pluginPack("acme-cls", ["--exit", "4"]) });
  try {
    const out = await pass.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: "hello Falcon" }] });
    assert.equal(out.segments[0]!.action, "pass");
  } finally {
    await pass.close();
  }
});

/** A plugin in two files: `main.mjs` imports the word it finds from
 *  `./lib/words.mjs`. Written to a fresh directory (the test tampers with it). */
function modularPlugin(): { app: string; main: string; words: string } {
  const app = mkdtempSync(join(tmpdir(), "mdu-prompt-plugin-app-"));
  dirs.push(app);
  mkdirSync(join(app, "lib"));
  const main = join(app, "main.mjs");
  const words = join(app, "lib", "words.mjs");
  writeFileSync(main, [
    "import { readFileSync } from 'node:fs';",
    "import { WORD, CATEGORY } from './lib/words.mjs';",
    "const req = JSON.parse(readFileSync(0, 'utf8'));",
    "const findings = [];",
    "for (const s of req.segments) for (let i = s.text.indexOf(WORD); i >= 0; i = s.text.indexOf(WORD, i + 1)) findings.push({ segment: s.id, start: i, end: i + WORD.length, category: CATEGORY });",
    "process.stdout.write(JSON.stringify({ findings }));",
    "",
  ].join("\n"));
  writeFileSync(words, "export const WORD = 'Falcon';\nexport const CATEGORY = 'acme.codename';\n");
  return { app, main, words };
}

function modularPack(main: string, modules: Array<{ path: string; sha256: string }>): string {
  return [
    "pack: acme-cls", "version: 1", "plugin:",
    `  exec: ${NODE}`, `  sha256: "${sha(NODE)}"`,
    `  script: ${main}`, `  script_sha256: "${sha(main)}"`,
    ...(modules.length > 0 ? ["  modules:", ...modules.map((m) => `    - { path: ${m.path}, sha256: "${m.sha256}" }`)] : []),
    "categories:", "  - { category: acme.codename, level: local-model }", "",
  ].join("\n");
}

// P0 item 13 (b): a plugin's imports loaded unpinned from the directory it
// was installed in. Now they are pinned (`modules:`) and loaded from the
// verified copy; nothing else of that directory is there to load.
test("a plugin's modules: a pinned one loads from the verified tree; a tampered one, or one it did not pin, blocks the prompt (fail closed)", async () => {
  const p = modularPlugin();
  const pinned = { path: p.words, sha256: sha(p.words) };
  const r = await rig(POLICY("    acme-cls: on\n"), { acme: modularPack(p.main, [pinned]) });
  try {
    const ok = await r.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: "launch Falcon" }] });
    assert.equal(ok.segments[0]!.action, "rewrite", JSON.stringify((await r.data.promptFilters()).filters.find((f) => f.id === "acme-cls")?.plugin?.lastError));
    assert.ok(!ok.segments[0]!.text!.includes("Falcon"));
    const row = (await r.data.promptFilters()).filters.find((f) => f.id === "acme-cls")!;
    assert.deepEqual(row.plugin!.modules, [pinned], "the panel shows the module pins");
    // The module changes (the agent's write, say) to find nothing: refused.
    writeFileSync(p.words, "export const WORD = 'zzzzzz';\nexport const CATEGORY = 'acme.codename';\n");
    const out = await r.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: "launch Falcon again" }] });
    assert.equal(out.segments[0]!.action, "block", "a tampered module fails the run, and the default on_error blocks");
    assert.equal(out.segments[0]!.text, undefined, "nothing of the segment may go");
    assert.match((await r.data.promptFilters()).filters.find((f) => f.id === "acme-cls")!.plugin!.lastError ?? "", /its pin: .*words\.mjs changed since it was pinned/);
  } finally {
    await r.close();
  }
  // The same plugin with its import NOT pinned: the copy has no lib/, so it
  // cannot load it from the directory it was installed in.
  const q = modularPlugin();
  const r2 = await rig(POLICY("    acme-cls: on\n"), { acme: modularPack(q.main, []) });
  try {
    const out = await r2.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: "launch Falcon" }] });
    assert.equal(out.segments[0]!.action, "block");
    assert.match((await r2.data.promptFilters()).filters.find((f) => f.id === "acme-cls")!.plugin!.lastError ?? "", /exited with/);
  } finally {
    await r2.close();
  }
});

test("a plugin slower than the client's idle timeout: progress frames keep the call alive; a client that did not ask gets none", async () => {
  const r = await rig(POLICY("    acme-cls: on\n"), { acme: pluginPack("acme-cls", ["--sleep", "2500", "--find", "Falcon", "acme.codename"], { deadline: 8000 }) });
  const sock = join(r.dir, "a.sock");
  const quick = new ArbiterClient(sock, { requestTimeoutMs: 1800 });
  try {
    const out = await quick.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: "launch Falcon" }] });
    assert.equal(out.segments[0]!.action, "rewrite", "answered after 2.5 s through a 1.8 s idle timeout");
    // A raw request without `progress: true` gets the answer and nothing else.
    const { createConnection } = await import("node:net");
    const lines = await new Promise<string[]>((resolve) => {
      const c = createConnection(sock);
      let buf = "";
      c.on("data", (d) => { buf += d.toString(); if (buf.includes("\"ok\"")) { c.end(); resolve(buf.trim().split("\n")); } });
      c.write(JSON.stringify({ id: 7, op: "filterPrompt", agent: "claude-code", segments: [{ id: "h", origin: "human", text: "launch Falcon again" }] }) + "\n");
    });
    assert.equal(lines.length, 1, `no progress frame unless asked: ${lines.join(" | ")}`);
  } finally {
    quick.close();
    await r.close();
  }
});

test("the endpoint: a local: true model is told to the plugin, which reaches it", async () => {
  const { createServer } = await import("node:http");
  let seen = "";
  const model = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen += body;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify([{ word: "Falcon", category: "acme.codename" }]) } }] }));
    });
  });
  await new Promise<void>((ok) => model.listen(0, "127.0.0.1", ok));
  const port = (model.address() as { port: number }).port;
  const policy = POLICY("    acme-cls: { on: true, endpoint: ollama }\n").replace("http://127.0.0.1:11434", `http://127.0.0.1:${port}`);
  const r = await rig(policy, { acme: pluginPack("acme-cls", ["--model"], { endpoint: "required" }) });
  try {
    const out = await r.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: "launch Falcon today" }] });
    assert.equal(out.segments[0]!.action, "rewrite");
    assert.ok(!out.segments[0]!.text!.includes("Falcon"));
    assert.match(seen, /launch Falcon today/, "the local model read the prompt (it is cleared for it)");
    const row = (await r.data.promptFilters()).filters.find((f) => f.id === "acme-cls")!;
    assert.equal(row.endpoint, "ollama");
    assert.equal(row.plugin!.lastEndpoint, "ollama");
    assert.equal(row.plugin!.needsEndpoint, true);
  } finally {
    await r.close();
    model.close();
  }
});
