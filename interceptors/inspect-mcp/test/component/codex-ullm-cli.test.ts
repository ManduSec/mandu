/**
 * codex-ullm-cli e2e — the quarantined model (U-LLM) as a real `codex exec`
 * child: `CliUllmClient` with its production subprocess runner
 * (`defaultCliExec`), no seam.
 *
 *   1. A stand-in `codex` on PATH records what the child is given: the
 *      quarantine argv, the fresh temp cwd (removed afterwards), the
 *      instructions file holding the quarantine prompt, the user message on
 *      stdin and nowhere on argv, the env (CODEX_HOME carried, the agent's
 *      OPENAI_BASE_URL dropped).
 *   2. The real `codex` CLI, when one is installed (self-SKIP otherwise),
 *      against a loopback stand-in for the vendor's Responses endpoint whose
 *      FIRST answer calls every tool a Codex model can name (a code-mode
 *      cell running `exec_command`, `shell`, `exec_command`, `view_image`),
 *      each trying to read a marker file: no call runs (the marker never
 *      reaches the endpoint), the model instructions are the quarantine
 *      prompt alone, the one user turn is the data, there is no environment
 *      context, and nothing is written under CODEX_HOME (`--ephemeral`). The
 *      only test-side change to the argv is the provider override that
 *      points Codex at the stand-in (production uses Codex's built-in
 *      provider, the vendor's real endpoint).
 *
 * Before 2026-10-04 every Codex inspect_symbol failed here first: `codex exec`
 * refused the temp cwd ("Not inside a trusted directory and
 * --skip-git-repo-check was not specified").
 *
 * Axes: this package reads no axis (the arbiter decides what is sent).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { CODEX_INSTRUCTIONS_FILE, CliUllmClient, defaultCliExec } from "../../src/ullm-client.js";

const SYSTEM = "QUARANTINE-PROMPT-7f3e: you process the data below and call no tool.";
const USER = "## Instructions\nsummarize\n## Data\nDATA-BODY-91c2";
const MARKER = "MARKER-CONTENT-QX9-5b0d";

const scratch = mkdtempSync(join(tmpdir(), "codex-ullm-e2e-"));
after(() => rmSync(scratch, { recursive: true, force: true }));

/** The temp dirs the client made (mandu-ullm-*) that still exist. */
function leftoverUllmDirs(): string[] {
  return readdirSync(tmpdir()).filter((n) => n.startsWith("mandu-ullm-"));
}

// ── 1. the stand-in codex ────────────────────────────────────────────────────

test("codex U-LLM (stand-in codex on PATH): quarantine argv, prompt file in a fresh cwd, data on stdin only, CODEX_HOME carried, OPENAI_BASE_URL dropped", async () => {
  const bin = join(scratch, "bin");
  const record = join(scratch, "record.json");
  spawnSync("mkdir", ["-p", bin]);
  const standIn = join(bin, "codex");
  writeFileSync(standIn, [
    "#!/usr/bin/env node",
    "const fs = require('node:fs');",
    "const args = process.argv.slice(2);",
    "const k = args.find((a) => a.startsWith('model_instructions_file='));",
    "const file = k ? JSON.parse(k.slice('model_instructions_file='.length)) : null;",
    "const stdin = fs.readFileSync(0, 'utf8');",
    "fs.writeFileSync(process.env.RECORD, JSON.stringify({ args, cwd: process.cwd(), stdin,",
    "  instructions: file ? fs.readFileSync(file, 'utf8') : null, file,",
    "  codexHome: process.env.CODEX_HOME ?? null, openaiBase: process.env.OPENAI_BASE_URL ?? null, tmpdir: process.env.TMPDIR ?? null }));",
    "process.stdout.write(JSON.stringify({ type: 'thread.started' }) + '\\n');",
    "process.stdout.write(JSON.stringify({ type: 'item.completed', item: { type: 'agent_message', text: 'stand-in answer' } }) + '\\n');",
    "",
  ].join("\n"));
  chmodSync(standIn, 0o755);

  const saved = { PATH: process.env.PATH, RECORD: process.env.RECORD, CODEX_HOME: process.env.CODEX_HOME, OPENAI_BASE_URL: process.env.OPENAI_BASE_URL };
  process.env.PATH = `${bin}:${process.env.PATH ?? ""}`;
  process.env.RECORD = record;
  process.env.CODEX_HOME = "/fixture/codex-home";
  process.env.OPENAI_BASE_URL = "http://127.0.0.1:8789/v1";
  const before = new Set(leftoverUllmDirs());
  try {
    const client = new CliUllmClient({ binary: "codex", exec: defaultCliExec });
    const res = await client.complete({ system: SYSTEM, user: USER });
    assert.equal(res.text, "stand-in answer");
    assert.equal(res.model, "codex-default");
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }

  const r = JSON.parse(readFileSync(record, "utf8")) as {
    args: string[]; cwd: string; stdin: string; instructions: string | null; file: string | null;
    codexHome: string | null; openaiBase: string | null; tmpdir: string | null;
  };
  assert.equal(r.args[0], "exec");
  for (const flag of ["--skip-git-repo-check", "--ephemeral", "--ignore-user-config", "--ignore-rules"]) {
    assert.ok(r.args.includes(flag), flag);
  }
  assert.ok(!r.args.includes("-m"), "no model configured: Codex's own default, never the Claude default id");
  assert.equal(r.args.at(-1), "-");
  assert.equal(r.stdin, USER, "the data rides stdin");
  assert.ok(!r.args.some((a) => a.includes("DATA-BODY-91c2") || a.includes("QUARANTINE-PROMPT-7f3e")), "no prompt on argv");
  assert.equal(r.instructions, SYSTEM, "the quarantine prompt is the model instructions file");
  assert.equal(r.file, join(r.cwd, CODEX_INSTRUCTIONS_FILE), "the file sits in the child's own cwd");
  assert.match(r.cwd, /mandu-ullm-/);
  assert.ok(!existsSync(r.cwd), "the temp cwd is removed after the call");
  assert.equal(r.codexHome, "/fixture/codex-home", "the sign-in location rides through");
  assert.equal(r.openaiBase, null, "an inherited OPENAI_BASE_URL never reaches the child");
  assert.equal(r.tmpdir, r.cwd, "the child's temp files go into its own temp cwd, removed with it");
  assert.deepEqual(leftoverUllmDirs().filter((d) => !before.has(d)), []);
});

// ── 2. the real codex ────────────────────────────────────────────────────────

const realCodex = process.env.MANDU_TEST_CODEX_BIN
  || (spawnSync("which", ["codex"], { encoding: "utf8" }).stdout.trim() || null);

interface Recorded { url: string; body: string }

/** A Responses stand-in: the first answer calls every tool on the marker,
 *  the next one is the text answer. */
function startVendor(markerPath: string): Promise<{ server: Server; port: number; seen: Recorded[] }> {
  const seen: Recorded[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      seen.push({ url: req.url ?? "", body });
      if (!(req.url ?? "").includes("/responses")) { res.writeHead(404); res.end(); return; }
      let parsed: { input?: Array<{ type?: string }> } = {};
      try { parsed = JSON.parse(body); } catch { /* recorded as is */ }
      const answered = (parsed.input ?? []).some((i) => /_output$/.test(i.type ?? ""));
      res.writeHead(200, { "content-type": "text/event-stream" });
      const ev = (o: Record<string, unknown>) => res.write(`event: ${String(o.type)}\ndata: ${JSON.stringify(o)}\n\n`);
      ev({ type: "response.created", response: { id: "r1" } });
      if (!answered) {
        ev({ type: "response.output_item.done", item: { type: "custom_tool_call", id: "c1", call_id: "call_cell", name: "exec", status: "completed",
          input: `text(await tools.exec_command({cmd: "cat ${markerPath}"}))` } });
        ev({ type: "response.output_item.done", item: { type: "function_call", id: "f1", call_id: "call_shell", name: "shell", arguments: JSON.stringify({ command: ["cat", markerPath] }) } });
        ev({ type: "response.output_item.done", item: { type: "function_call", id: "f2", call_id: "call_exec", name: "exec_command", arguments: JSON.stringify({ cmd: `cat ${markerPath}` }) } });
        ev({ type: "response.output_item.done", item: { type: "function_call", id: "f3", call_id: "call_image", name: "view_image", arguments: JSON.stringify({ path: markerPath }) } });
      } else {
        ev({ type: "response.output_item.done", item: { type: "message", role: "assistant", id: "m1", content: [{ type: "output_text", text: "VENDOR-ANSWER" }] } });
      }
      ev({ type: "response.completed", response: { id: "r1", usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } } });
      res.end();
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, port: (server.address() as AddressInfo).port, seen })));
}

test("codex U-LLM (the real codex CLI): no tool call the model makes reads the marker, the instructions are the quarantine prompt, no session file", { skip: realCodex ? false : "no codex CLI on PATH (MANDU_TEST_CODEX_BIN names one)" }, async () => {
  const markerPath = join(scratch, "marker.txt");
  writeFileSync(markerPath, `${MARKER}\n`);
  const codexHome = join(scratch, "codex-home");
  spawnSync("mkdir", ["-p", codexHome]);
  const vendor = await startVendor(markerPath);
  const tmpBefore = new Set(readdirSync(tmpdir()));
  const saved = { CODEX_HOME: process.env.CODEX_HOME, STUB_VENDOR_KEY: process.env.STUB_VENDOR_KEY };
  process.env.CODEX_HOME = codexHome;
  process.env.STUB_VENDOR_KEY = "sk-stand-in";
  try {
    const client = new CliUllmClient({
      binary: "codex",
      timeoutMs: 90_000,
      exec: (spec) => defaultCliExec({
        ...spec,
        file: realCodex!,
        // test-only: the stand-in vendor instead of the built-in provider
        args: [spec.args[0]!,
          "-c", 'model_provider="standin"',
          "-c", `model_providers.standin={name="standin",base_url="http://127.0.0.1:${vendor.port}/v1",wire_api="responses",env_key="STUB_VENDOR_KEY",supports_websockets=false}`,
          ...spec.args.slice(1)],
      }),
    });
    const res = await client.complete({ system: SYSTEM, user: USER });
    assert.equal(res.text, "VENDOR-ANSWER");
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    vendor.server.close();
  }

  const turns = vendor.seen.filter((s) => s.url.includes("/responses"));
  assert.equal(turns.length, 2, "the tool-call turn, then the answer turn");
  for (const t of turns) assert.ok(!t.body.includes(MARKER), "no tool read the marker file");
  const first = JSON.parse(turns[0]!.body) as { instructions?: string; input: Array<{ type?: string; role?: string; content?: Array<{ text?: string }> }> };
  const texts = (role: string) => first.input.filter((i) => i.type === "message" && i.role === role)
    .flatMap((i) => (i.content ?? []).map((c) => c.text ?? ""));
  // The quarantine prompt is the instructions: the Responses `instructions`
  // field (older Codex) or the first developer message (code-mode Codex).
  const instr = first.instructions ? [first.instructions] : texts("developer").slice(0, 1);
  assert.equal(instr.join("").trim(), SYSTEM);
  assert.ok(!turns[0]!.body.includes("You are Codex"), "Codex's own agent instructions are replaced");
  assert.deepEqual(texts("user"), [USER], "the one user turn is the data; no environment context");
  assert.ok(!turns[0]!.body.includes("environment_context"));
  assert.ok(!turns[0]!.body.includes("skills_instructions"));
  // the second turn carries each refused call's output
  const second = JSON.parse(turns[1]!.body) as { input: Array<{ type?: string; call_id?: string }> };
  const outputs = second.input.filter((i) => /_output$/.test(i.type ?? "")).map((i) => i.call_id);
  for (const id of ["call_cell", "call_shell", "call_exec", "call_image"]) assert.ok(outputs.includes(id), `${id} answered without running`);
  // the sandbox's mount-target directory and the rest stayed in the call's temp cwd
  assert.deepEqual(readdirSync(tmpdir()).filter((n) => !tmpBefore.has(n) && n.startsWith("codex")), [], "nothing of Codex's left in the shared TMPDIR");
  const sessionFiles = existsSync(join(codexHome, "sessions")) ? readdirSync(join(codexHome, "sessions"), { recursive: true }) : [];
  assert.deepEqual(sessionFiles.filter((f) => String(f).endsWith(".jsonl")), [], "--ephemeral: no session file holds the data");
});
