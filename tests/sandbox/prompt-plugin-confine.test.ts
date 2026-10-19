/**
 * prompt-plugin-confine — a prompt filter plugin's confinement with the real
 * bins (confidentiality-plan-15-prompt-filter.md §4.3, §12 2026-10-03).
 *
 * A real ArbiterServer given the real `mandu-net-guard` and
 * `mandu-landlock-apply` (and the system's bubblewrap), probing the legs
 * itself. A plugin pack pinned to node and the test plugin
 * (arbiter/test/fixtures/prompt-plugin/fake-plugin.mjs):
 *
 *   - the probe finds the guard (required) and, on a Landlock kernel, the
 *     Landlock and seccomp legs; the panel's projection names them;
 *   - a classifier plugin with a `local: true` endpoint reaches THAT model
 *     (the guard connects for it) and finds the codename, while its attempt
 *     to reach another loopback port and to read a file outside its read
 *     roots both fail (the plugin would exit 9 and the prompt would block);
 *     the other port records no connection;
 *   - a plugin with no model reaches no port at all, the endpoint's either;
 *   - the directory a plugin was installed in is not readable to it (its
 *     unpinned files cannot load), while a module it pinned (`modules:`)
 *     loads from the verified copy under every leg (P0 item 13);
 *   - control: the same plugin under the test stand-in guard (no
 *     confinement) does reach the other port and blocks the prompt, so the
 *     check above is not vacuous; and the real probe, given the stand-in,
 *     finds that it confines nothing (no plugin would run under it).
 *
 * Kernel-gated: self-SKIPs without the native bins or when the guard cannot
 * confine on this host. Axes stated: secrets.
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer as createHttp, type Server as HttpServer } from "node:http";
import { createServer as createTcp, type AddressInfo, type Server as TcpServer } from "node:net";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { resolveNativeBin } from "../../launcher/src/services/native-bins.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const FIX = join(REPO_ROOT, "arbiter", "test", "fixtures", "prompt-plugin");
const PLUGIN = join(FIX, "fake-plugin.mjs");
const NODE = realpathSync(process.execPath);
const sha = (p: string): string => createHash("sha256").update(readFileSync(p)).digest("hex");

const dirs: string[] = [];
const closers: Array<() => void> = [];
after(() => {
  for (const c of closers) c();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
  resetCurrentPolicyForTests();
});

async function fakeModel(): Promise<{ server: HttpServer; port: number; bodies: string[] }> {
  const m = { server: undefined as unknown as HttpServer, port: 0, bodies: [] as string[] };
  m.server = createHttp((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      m.bodies.push(body);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify([{ word: "Falcon", category: "acme.codename" }]) } }] }));
    });
  });
  await new Promise<void>((r) => m.server.listen(0, "127.0.0.1", r));
  m.port = (m.server.address() as AddressInfo).port;
  closers.push(() => m.server.close());
  return m;
}

async function counter(): Promise<{ server: TcpServer; port: number; hits: () => number }> {
  let n = 0;
  const server = createTcp((s) => { n++; s.destroy(); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  closers.push(() => server.close());
  return { server, port: (server.address() as AddressInfo).port, hits: () => n };
}

function pack(args: string[], endpoint: boolean): string {
  return [
    "pack: acme-cls", "version: 1", "plugin:",
    `  exec: ${NODE}`, `  sha256: "${sha(NODE)}"`,
    `  script: ${PLUGIN}`, `  script_sha256: "${sha(PLUGIN)}"`,
    `  args: ${JSON.stringify(args)}`,
    ...(endpoint ? ["  endpoint: required"] : []),
    "  deadline_ms: 8000",
    "categories:", "  - acme.codename", "",
  ].join("\n");
}

async function rig(modelPort: number, packText: string, filters: string, guard: string, opts: { trustGuard?: boolean } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "mdu-plugin-confine-"));
  dirs.push(dir);
  const packDir = join(dir, "prompt-filters");
  mkdirSync(packDir);
  writeFileSync(join(packDir, "acme.yaml"), packText);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\nmodels:\n  - name: ollama\n    url: http://127.0.0.1:${modelPort}\n    wire: openai-chat\n    model: llama3.2\n    local: true\nprompt_filters:\n  filters:\n${filters}  actions:\n    acme.codename: redact\n`);
  const sock = join(dir, "a.sock");
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0, packDir: null,
    promptPackDir: packDir, adminPromptPackDir: join(dir, "admin-packs"), adminPolicyDir: null, packKeysDir: join(dir, "keys"),
    promptPlugins: {
      netGuard: guard, landlockApply: resolveNativeBin("mandu-landlock-apply"),
      bwrap: ["/usr/bin/bwrap"].find((p) => { try { readFileSync(p); return true; } catch { return false; } }) ?? null,
      dir: join(dir, "plugins"),
      // The control only: skip the probe, which (rightly) finds that the
      // stand-in guard confines nothing.
      ...(opts.trustGuard ? { probe: async () => ({ guard: true, landlock: false, seccomp: false, namespaces: false, notes: [] }) } : {}),
    },
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  return { dir, data, close: async () => { data.close(); await server.close(); } };
}

test("a plugin reaches only its cleared model, reads nothing outside its roots, and the probe names its legs", async (t) => {
  const guard = resolveNativeBin("mandu-net-guard");
  if (!guard) { t.skip("the mandu-net-guard bin is not built (scripts/build-native.sh)"); return; }
  const model = await fakeModel();
  const other = await counter();
  const outside = mkdtempSync(join(tmpdir(), "mdu-plugin-outside-"));
  dirs.push(outside);
  const secretFile = join(outside, "not-yours.txt");
  writeFileSync(secretFile, "outside the plugin's read roots\n");
  const r = await rig(model.port, pack(["--probe", String(other.port), secretFile, "--model"], true), "    acme-cls: { on: true, endpoint: ollama }\n", guard);
  try {
    const out = await r.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: "launch Falcon today" }] });
    const row = (await r.data.promptFilters()).filters.find((f) => f.id === "acme-cls")!;
    const legs = row.plugin!.confinement;
    if (legs && !legs.guard) { t.skip(`the guard cannot confine here: ${legs.notes.join("; ")}`); return; }
    assert.equal(out.segments[0]!.action, "rewrite", `the plugin answered (it reached neither the other port nor the file): ${row.plugin!.lastError ?? ""}`);
    assert.equal(out.segments[0]!.text, "launch [redacted: acme.codename] today");
    assert.equal(model.bodies.length, 1, "the cleared model was reached once");
    assert.match(model.bodies[0]!, /launch Falcon today/);
    assert.equal(other.hits(), 0, "the other port saw no connection");
    assert.ok(legs!.guard);
    if (legs!.landlock) assert.ok(legs!.seccomp, `the applier of this tree installs the deny filter: ${legs!.notes.join("; ")}`);
    t.diagnostic(`legs: landlock=${legs!.landlock} seccomp=${legs!.seccomp} namespaces=${legs!.namespaces}; notes: ${legs!.notes.join(" | ")}`);
  } finally {
    await r.close();
  }
});

test("the reference classifier (local-classifier.mjs, its generated pack) runs under every leg and reaches its local model", async (t) => {
  const guard = resolveNativeBin("mandu-net-guard");
  if (!guard) { t.skip("the mandu-net-guard bin is not built (scripts/build-native.sh)"); return; }
  const bodies: string[] = [];
  const model = createHttp((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      bodies.push(body);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ findings: body.includes("Falcon") ? [{ category: "acme.codename", text: "Falcon" }] : [] }) } }] }));
    });
  });
  await new Promise<void>((r) => model.listen(0, "127.0.0.1", r));
  closers.push(() => model.close());
  const port = (model.address() as AddressInfo).port;
  const { spawnSync } = await import("node:child_process");
  const gen = spawnSync(process.execPath, [join(REPO_ROOT, "arbiter", "prompt-filter", "plugins", "local-classifier-pack.mjs"), "--id", "acme-cls", "--categories", "acme.codename", "--deadline-ms", "10000"], { encoding: "utf8" });
  assert.equal(gen.status, 0, gen.stderr);
  const r = await rig(port, gen.stdout, "    acme-cls: { on: true, endpoint: ollama }\n", guard);
  try {
    const out = await r.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: "launch Falcon today" }] });
    const row = (await r.data.promptFilters()).filters.find((f) => f.id === "acme-cls")!;
    if (row.plugin!.confinement && !row.plugin!.confinement.guard) { t.skip("the guard cannot confine here"); return; }
    assert.equal(out.segments[0]!.text, "launch [redacted: acme.codename] today", row.plugin!.lastError ?? "");
    assert.equal(bodies.length, 1);
  } finally {
    await r.close();
  }
});

test("the plugin's install directory is not readable to it; a module it pinned loads from the verified copy (every leg)", async (t) => {
  const guard = resolveNativeBin("mandu-net-guard");
  if (!guard) { t.skip("the mandu-net-guard bin is not built (scripts/build-native.sh)"); return; }
  const other = await counter();
  // 1. The test plugin tries to read a file BESIDE it (its install
  //    directory, never pinned): denied, so it answers (exit 9 otherwise).
  const sibling = join(FIX, "fake-guard.sh");
  const r = await rig(1, pack(["--probe", String(other.port), sibling], false), "    acme-cls: on\n", guard);
  try {
    const out = await r.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: "launch Falcon today" }] });
    const row = (await r.data.promptFilters()).filters.find((f) => f.id === "acme-cls")!;
    const legs = row.plugin!.confinement;
    if (legs && !legs.guard) { t.skip(`the guard cannot confine here: ${legs.notes.join("; ")}`); return; }
    if (legs && !legs.landlock && !legs.namespaces) { t.skip(`neither Landlock nor the namespaces confine reads here: ${legs.notes.join("; ")}`); return; }
    assert.equal(out.segments[0]!.action, "pass", `the plugin could not read ${sibling}: ${row.plugin!.lastError ?? ""}`);
  } finally {
    await r.close();
  }
  // 2. A plugin in two files, its import pinned: it loads, confined.
  const app = mkdtempSync(join(tmpdir(), "mdu-plugin-app-"));
  dirs.push(app);
  mkdirSync(join(app, "lib"));
  const main = join(app, "main.mjs");
  const words = join(app, "lib", "words.mjs");
  writeFileSync(main, [
    "import { readFileSync } from 'node:fs';",
    "import { WORD } from './lib/words.mjs';",
    "const req = JSON.parse(readFileSync(0, 'utf8'));",
    "const findings = [];",
    "for (const s of req.segments) { const i = s.text.indexOf(WORD); if (i >= 0) findings.push({ segment: s.id, start: i, end: i + WORD.length, category: 'acme.codename' }); }",
    "process.stdout.write(JSON.stringify({ findings }));", "",
  ].join("\n"));
  writeFileSync(words, "export const WORD = 'Falcon';\n");
  const modular = [
    "pack: acme-cls", "version: 1", "plugin:",
    `  exec: ${NODE}`, `  sha256: "${sha(NODE)}"`,
    `  script: ${main}`, `  script_sha256: "${sha(main)}"`,
    "  modules:", `    - { path: ${words}, sha256: "${sha(words)}" }`,
    "  deadline_ms: 8000", "categories:", "  - acme.codename", "",
  ].join("\n");
  const r2 = await rig(1, modular, "    acme-cls: on\n", guard);
  try {
    const out = await r2.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: "launch Falcon today" }] });
    const row = (await r2.data.promptFilters()).filters.find((f) => f.id === "acme-cls")!;
    assert.equal(out.segments[0]!.text, "launch [redacted: acme.codename] today", row.plugin!.lastError ?? "");
  } finally {
    await r2.close();
  }
});

test("mandu-landlock-apply --seccomp-only installs the AgentShell deny filter: a user namespace is refused, an ordinary program runs", async (t) => {
  const applier = resolveNativeBin("mandu-landlock-apply");
  if (!applier) { t.skip("the mandu-landlock-apply bin is not built (scripts/build-native.sh)"); return; }
  const { spawnSync } = await import("node:child_process");
  const ok = spawnSync(applier, ["--seccomp-only", "--", "/usr/bin/true"], { stdio: "ignore" });
  if (ok.status === 78 || ok.status === 71) { t.skip(`this applier has no --seccomp-only (exit ${ok.status}); rebuild with scripts/build-native.sh`); return; }
  assert.equal(ok.status, 0);
  const userns = spawnSync(applier, ["--seccomp-only", "--", "/usr/bin/unshare", "-U", "/usr/bin/true"], { stdio: "ignore" });
  assert.notEqual(userns.status, 0, "unshare(CLONE_NEWUSER) is denied under the filter");
  const control = spawnSync("/usr/bin/unshare", ["-U", "/usr/bin/true"], { stdio: "ignore" });
  t.diagnostic(`without the filter, unshare -U exits ${control.status}`);
});

test("a plugin with no model reaches no port at all; control: unconfined, the same plugin does and blocks", async (t) => {
  const guard = resolveNativeBin("mandu-net-guard");
  if (!guard) { t.skip("the mandu-net-guard bin is not built (scripts/build-native.sh)"); return; }
  const model = await fakeModel();
  const other = await counter();
  const outside = mkdtempSync(join(tmpdir(), "mdu-plugin-outside-"));
  dirs.push(outside);
  const file = join(outside, "x.txt");
  writeFileSync(file, "x\n");
  // The model's own port, too: without an endpoint the allow list is empty.
  const args = ["--probe", String(model.port), file, "--find", "Falcon", "acme.codename"];
  const r = await rig(model.port, pack(args, false), "    acme-cls: on\n", guard);
  try {
    const out = await r.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: "launch Falcon" }] });
    const row = (await r.data.promptFilters()).filters.find((f) => f.id === "acme-cls")!;
    if (row.plugin!.confinement && !row.plugin!.confinement.guard) { t.skip("the guard cannot confine here"); return; }
    assert.equal(out.segments[0]!.action, "rewrite", row.plugin!.lastError ?? "");
    assert.equal(model.bodies.length, 0);
  } finally {
    await r.close();
  }
  // The real probe sees through a guard that confines nothing.
  const fake = await rig(other.port, pack(["--find", "Falcon", "acme.codename"], false), "    acme-cls: on\n", join(FIX, "fake-guard.sh"));
  try {
    const out = await fake.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: "launch Falcon" }] });
    assert.equal(out.segments[0]!.action, "block");
    const row = (await fake.data.promptFilters()).filters.find((f) => f.id === "acme-cls")!;
    assert.equal(row.plugin!.confinement!.guard, false);
    assert.match(row.plugin!.lastError ?? "", /could not confine a test program/);
  } finally {
    await fake.close();
  }
  // Control: the stand-in guard confines nothing, so the probe connects and the plugin exits 9.
  const c = await rig(other.port, pack(["--probe", String(other.port), file, "--find", "Falcon", "acme.codename"], false), "    acme-cls: on\n", join(FIX, "fake-guard.sh"), { trustGuard: true });
  try {
    const out = await c.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: "launch Falcon" }] });
    assert.equal(out.segments[0]!.action, "block");
    const row = (await c.data.promptFilters()).filters.find((f) => f.id === "acme-cls")!;
    assert.match(row.plugin!.lastError ?? "", /exited with 9/);
    assert.ok(other.hits() >= 1);
  } finally {
    await c.close();
  }
});
