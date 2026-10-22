/**
 * generate.ts — the past-sessions scan's REAL-STORE fixtures: each agent's
 * own binary writes its session store, driven against a scripted local model
 * (no API key, no live model), and the store is copied out as the fixture the
 * reader tests load
 * (docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md
 * §6 "The readers against real stores").
 *
 *   cd tests && npx tsx transcript-fixtures/generate.ts --out <dir> [--only <id,id>]
 *
 * <id>: opencode (1.x, `opencode`), opencode2 (`opencode2`), goose (`goose`),
 * openclaw (`openclaw`, a JSONL-store release) and openclaw9 (the command in
 * MANDU_FIXTURE_OPENCLAW9_BIN: a 9.x release, which keeps its sessions in
 * SQLite). Run it where the agents are installed, never on a machine whose
 * agents hold a person's sessions: the CI guest image has the pinned ones,
 * and transcript-fixtures/guest-run.sh adds OpenClaw 9.x there and calls this
 * (`scripts/ci/vm-run.sh --worktree --network --exec 'bash
 * tests/transcript-fixtures/guest-run.sh'`). Each agent runs with a private
 * HOME and state root under a fresh temporary directory, its model base URL
 * at the scripted server below.
 *
 * The script (one session per agent, matched on the NUMBER of tool results
 * in the request, never on their content): the agent's shell tool runs a
 * command that prints FIXTURE_CMD_VALUE (the command builds it from two
 * pieces, so the command text never holds it); then its file tool (Goose:
 * its shell, `cat`) reads `.env`, which holds FIXTURE_FILE_VALUE and
 * FIXTURE_PLAIN_VALUE; then a closing text. Every model response carries its
 * own message id (`msg_01MduFixture…`), so the store records the provider's
 * response id where the agent keeps one. The planted values are fake keys,
 * obviously test values (`sk-ant-mdufixture-…`).
 *
 * Each store is written to <out> as `<id>-<version>.jsonl`: a JSONL store's
 * own lines, or a SQLite store's rows of the tables the scan reads, one
 * `{table, ...columns}` record per row with the JSON columns parsed (the
 * format the reader tests turn back into a database). Machine-specific text
 * is replaced: the temporary home by /home/user, the workspace by
 * /home/user/project, the host name and the user name. `manifest.json` in
 * <out> records each agent's version, its store's place, its exit, and the
 * model requests it made.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import http from "node:http";
import type { AddressInfo } from "node:net";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { hostname, tmpdir, userInfo } from "node:os";
import { dirname, join, relative } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  gooseProvisioner, opencode2Provisioner, opencodeProvisioner, openclawProvisioner, type AgentProvisioner,
} from "../lib/agent-provision.js";
import { runChildToExit } from "../lib/child-run.js";
import { textTurn, toolUseTurn, writeSse, type SseEvent } from "../lib/model-wire.js";

/** The planted values, each built from pieces so no source file holds one
 *  whole (the reader tests build them the same way). */
export const FIXTURE_CMD_VALUE = `${"sk-ant-"}mdufixture-cmd-Qz7Kp2Lm9Xw3Rt6Yv8Nb4C`;
export const FIXTURE_FILE_VALUE = `${"sk-ant-"}mdufixture-file-Hf0Gp2Ae7Wq5Cs1Nb6Yv9R`;
export const FIXTURE_PLAIN_VALUE = "mdu-fixture-plain-T4kW9qZr2Lx7";
export const FIXTURE_PROMPT = "MDU-FIXTURE-PROMPT run the key check, then read .env and tell me whether the key is set.";
export const FIXTURE_FINAL = "MDU-FIXTURE-DONE the key is set.";
/** The response id of the script's step `n` (1: the shell call, 2: the file
 *  read, 3: the closing text) for agent `id`. */
export const fixtureResponseId = (id: string, n: number): string => `msg_01MduFixture${id.replace(/[^A-Za-z0-9]/g, "")}Step${n}`;

const FAKE_HOME = "/home/user";
const FAKE_WS = "/home/user/project";
const MODEL = "claude-sonnet-4-5";

interface AgentRun {
  id: string;
  provisioner: AgentProvisioner;
  /** The command to run (with the provisioner's argv after `prefix`). */
  binary: string;
  prefix: string[];
  shell: { name: string; input: (command: string) => Record<string, unknown> };
  read: { name: string; input: (path: string) => Record<string, unknown> };
  /** Change the provisioner's argv (Goose's `--no-session` keeps no session). */
  argv?: (argv: string[]) => string[];
  /** The model id, when the agent's catalog wants its own (OpenClaw 2026.7
   *  refuses a model it has no output limit for). */
  model?: string;
}

const PRINT_CMD = `printf '%s%s\\n' 'sk-ant-' '${FIXTURE_CMD_VALUE.slice("sk-ant-".length)}'`;

function runs(): AgentRun[] {
  const out: AgentRun[] = [
    {
      id: "opencode", provisioner: opencodeProvisioner, binary: "opencode", prefix: [],
      shell: { name: "bash", input: (command) => ({ command, description: "Run the key check" }) },
      read: { name: "read", input: (filePath) => ({ filePath }) },
    },
    {
      id: "opencode2", provisioner: opencode2Provisioner, binary: "opencode2", prefix: [],
      shell: { name: "shell", input: (command) => ({ command }) },
      read: { name: "read", input: (path) => ({ path }) },
    },
    {
      id: "goose", provisioner: gooseProvisioner, binary: "goose", prefix: [],
      shell: { name: "shell", input: (command) => ({ command }) },
      read: { name: "shell", input: (path) => ({ command: `cat ${path}` }) },
      argv: (a) => a.filter((x) => x !== "--no-session"),
    },
    {
      id: "openclaw", provisioner: openclawProvisioner, binary: "openclaw", prefix: [], model: "claude-opus-4-6",
      shell: { name: "exec", input: (command) => ({ command }) },
      read: { name: "read", input: (path) => ({ path }) },
    },
  ];
  const oc9 = process.env["MANDU_FIXTURE_OPENCLAW9_BIN"];
  if (oc9) out.push({ ...out[3]!, id: "openclaw9", binary: oc9 });
  return out;
}

/** The scripted model for one agent run. */
async function startModel(run: AgentRun, envFile: string): Promise<{ origin: string; requests: string[]; close: () => Promise<void> }> {
  const requests: string[] = [];
  let side = 0;
  const withId = (events: SseEvent[], id: string): SseEvent[] => events.map(([name, data]) => {
    if (name !== "message_start") return [name, data];
    const d = data as { message: Record<string, unknown> };
    return [name, { ...d, message: { ...d.message, id, model: run.model ?? MODEL } }];
  });
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const url = req.url ?? "";
      if (req.method === "POST" && url.includes("count_tokens")) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ input_tokens: 10 }));
        return;
      }
      if (req.method !== "POST" || !url.includes("/messages")) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ data: [] }));
        return;
      }
      requests.push(url);
      const results = body.split('"tool_result"').length - 1;
      // A side call (a title) advertises none of the agent's tools.
      const agentic = body.includes(`"name":"${run.shell.name}"`);
      let events: SseEvent[];
      if (!agentic && results === 0) events = withId(textTurn("Key check"), `msg_01MduFixtureSideCall${++side}`);
      else if (results === 0) events = withId(toolUseTurn(`toolu_01MduFixture${run.id}Shell`, run.shell.name, run.shell.input(PRINT_CMD)), fixtureResponseId(run.id, 1));
      else if (results === 1) events = withId(toolUseTurn(`toolu_01MduFixture${run.id}Read`, run.read.name, run.read.input(envFile)), fixtureResponseId(run.id, 2));
      else events = withId(textTurn(FIXTURE_FINAL), fixtureResponseId(run.id, 3));
      void writeSse(res, events, 0);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return { origin: `http://127.0.0.1:${port}`, requests, close: () => new Promise<void>((r) => server.close(() => r())) };
}

/** The tables of each store the scan reads (scripts/transcript-shapes.mjs). */
const STORE_TABLES = ["session", "session_v2", "message", "part", "session_message", "sessions", "messages", "session_windows", "transcript_events"];
/** A SQLite column holding JSON. */
const JSON_COLUMNS = new Set(["data", "content_json", "metadata_json", "event_json", "permission", "extension_data", "model_config_json", "recipe_json", "entry_json"]);

/** A SQLite store's rows of the tables the scan reads; a blob as `{$base64}`. */
function dbRows(file: string): Array<Record<string, unknown>> {
  const db = new DatabaseSync(file, { readOnly: true });
  try {
    const have = new Set((db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>).map((r) => r.name));
    const out: Array<Record<string, unknown>> = [];
    for (const table of STORE_TABLES) {
      if (!have.has(table)) continue;
      for (const row of db.prepare(`SELECT * FROM "${table}"`).all() as Array<Record<string, unknown>>) {
        const rec: Record<string, unknown> = { table };
        for (const [k, v] of Object.entries(row)) {
          if (v instanceof Uint8Array) rec[k] = { $base64: Buffer.from(v).toString("base64") };
          else if (typeof v === "bigint") rec[k] = Number(v);
          else if (JSON_COLUMNS.has(k) && typeof v === "string") { try { rec[k] = JSON.parse(v); } catch { rec[k] = v; } }
          else rec[k] = v;
        }
        out.push(rec);
      }
    }
    return out;
  } finally {
    db.close();
  }
}

/** Every file under `dir`. */
function walk(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else if (e.isFile()) out.push(p);
  }
  return out;
}

/** The stores a run left under its home: [kind, file]. OpenClaw's
 *  `<session>.trajectory.jsonl` beside a session is its run trace, not a
 *  session (the scan skips it, transcript-stores.ts isStoreFile): listed as
 *  `trace`, not copied (it holds the whole compiled context, ~600 kB). */
function storesUnder(home: string): Array<{ kind: string; file: string }> {
  const out: Array<{ kind: string; file: string }> = [];
  for (const f of walk(home)) {
    const b = f.slice(dirname(f).length + 1);
    if (b.endsWith(".trajectory.jsonl")) out.push({ kind: "trace", file: f });
    else if (b === "opencode.db") out.push({ kind: "opencode-db", file: f });
    else if (b === "sessions.db") out.push({ kind: "goose-db", file: f });
    else if (b === "openclaw-agent.sqlite") out.push({ kind: "openclaw-db", file: f });
    else if (/^llm_request\.[^/]+\.jsonl$/.test(b)) out.push({ kind: "goose-request-log", file: f });
    else if (b.endsWith(".jsonl") && dirname(f).endsWith("/sessions")) out.push({ kind: f.includes("/agents/") ? "openclaw-jsonl" : "goose-jsonl", file: f });
  }
  return out;
}

/** Replace the machine's own text in every string of `v`. */
function scrubber(root: string, home: string, ws: string): (v: unknown) => unknown {
  const pairs: Array<[string, string]> = [];
  for (const [real, fake] of [[ws, FAKE_WS], [home, FAKE_HOME], [root, "/tmp/mandu-fixture"]] as Array<[string, string]>) {
    pairs.push([real, fake]);
    try { const r = realpathSync(real); if (r !== real) pairs.push([r, fake]); } catch { /* gone */ }
  }
  // A path the agent shows relative to `/` (OpenCode 1.x's tool title).
  for (const [real, fake] of [...pairs]) pairs.push([real.slice(1), fake.slice(1)]);
  const user = userInfo().username;
  pairs.push([`/home/${user}`, FAKE_HOME]);
  const host = hostname();
  const words: Array<[RegExp, string]> = [];
  if (host.length >= 3) words.push([new RegExp(`\\b${host.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "g"), "fixture-host"]);
  if (user.length >= 3 && user !== "user") words.push([new RegExp(`\\b${user.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "g"), "user"]);
  const s = (x: string): string => {
    let t = x;
    for (const [a, b] of pairs) t = t.split(a).join(b);
    for (const [re, b] of words) t = t.replace(re, b);
    return t;
  };
  const go = (v: unknown): unknown => {
    if (typeof v === "string") return s(v);
    if (Array.isArray(v)) return v.map(go);
    if (v !== null && typeof v === "object") return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [s(k), go(x)]));
    return v;
  };
  return go;
}

function versionOf(binary: string, prefix: string[], env: Record<string, string>): string {
  const r = spawnSync(binary, [...prefix, "--version"], { encoding: "utf8", env, timeout: 30_000 });
  const m = /(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)/.exec(`${r.stdout ?? ""}`);
  return m ? m[1]! : "unknown";
}

async function generate(run: AgentRun, out: string): Promise<Record<string, unknown>> {
  const root = mkdtempSync(join(tmpdir(), "mdu-fx-"));
  const home = join(root, "home");
  const ws = join(root, "ws");
  mkdirSync(home, { recursive: true });
  mkdirSync(ws, { recursive: true });
  const envFile = join(ws, ".env");
  writeFileSync(envFile, `ANTHROPIC_API_KEY=${FIXTURE_FILE_VALUE}\nMDU_FIXTURE_NOTE=${FIXTURE_PLAIN_VALUE}\n`);
  writeFileSync(join(ws, "README.md"), "A workspace for Mandu's transcript fixtures.\n");
  const model = await startModel(run, envFile);
  try {
    const p = run.provisioner.provision({
      agentHome: home, workspace: ws, proxyUrl: model.origin, sessionId: `fixture-${run.id}`, batchId: "fixture",
      model: run.model ?? MODEL, prompt: FIXTURE_PROMPT, timeoutMs: 120_000,
    });
    for (const f of p.files) { mkdirSync(dirname(f.path), { recursive: true }); writeFileSync(f.path, f.content); }
    const env = { ...p.env, LANG: "C.UTF-8" };
    const version = versionOf(run.binary, run.prefix, env);
    const argv = run.argv ? run.argv(p.argv) : p.argv;
    let code: number;
    let tail = "";
    try {
      const r = await runChildToExit(run.binary, [...run.prefix, ...argv], { cwd: ws, env, timeoutMs: 180_000, label: run.id });
      code = r.code;
      tail = `${r.stdout}\n${r.stderr}`.slice(-2000);
    } catch (e) {
      code = -2;
      tail = String(e).slice(-2000);
    }
    const scrub = scrubber(root, home, ws);
    const stores = storesUnder(home);
    const written: Array<Record<string, unknown>> = [];
    for (const s of stores) {
      if (s.kind === "trace") { written.push({ kind: "trace", store: relative(home, s.file), bytes: statSync(s.file).size }); continue; }
      const recs = s.kind.endsWith("-db")
        ? dbRows(s.file)
        : readFileSync(s.file, "utf8").split("\n").filter((l) => l.trim() !== "").map((l) => JSON.parse(l) as unknown);
      // Goose writes one request log file per request (`llm_request.<n>.jsonl`).
      const n = /^llm_request\.([^/]+)\.jsonl$/.exec(s.file.slice(dirname(s.file).length + 1))?.[1];
      const suffix = s.kind === "goose-request-log" ? `-request-log.${n}` : "";
      const name = `${run.id}-${version}${suffix}.jsonl`;
      writeFileSync(join(out, name), recs.map((r) => JSON.stringify(scrub(r))).join("\n") + "\n");
      written.push({ fixture: name, kind: s.kind, store: relative(home, s.file), records: recs.length, bytes: statSync(s.file).size });
    }
    return { id: run.id, version, model: run.model ?? MODEL, exit: code, modelRequests: model.requests.length, stores: written, ...(code !== 0 || written.length === 0 ? { tail: scrub(tail) } : {}) };
  } finally {
    await model.close();
    rmSync(root, { recursive: true, force: true });
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const at = (k: string): string | undefined => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : undefined; };
  const out = at("--out");
  if (!out) { process.stderr.write("usage: generate.ts --out <dir> [--only <id,id>]\n"); process.exit(2); }
  const only = at("--only")?.split(",");
  mkdirSync(out, { recursive: true });
  const results: Array<Record<string, unknown>> = [];
  for (const run of runs()) {
    if (only && !only.includes(run.id)) continue;
    if (!existsSync(run.binary) && spawnSync("sh", ["-c", `command -v ${run.binary}`]).status !== 0) {
      results.push({ id: run.id, skipped: `${run.binary} not found` });
      continue;
    }
    process.stderr.write(`generate: ${run.id}\n`);
    results.push(await generate(run, out));
    process.stderr.write(`generate: ${JSON.stringify(results.at(-1))}\n`);
  }
  writeFileSync(join(out, "manifest.json"), JSON.stringify({
    generatedAt: new Date().toISOString().slice(0, 10),
    generator: "tests/transcript-fixtures/generate.ts",
    model: "a scripted local Anthropic Messages endpoint (no API key, no live model)",
    agents: results,
  }, null, 2) + "\n");
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(new URL(import.meta.url).pathname)) await main();
