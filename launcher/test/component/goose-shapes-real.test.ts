/**
 * goose-shapes-real.test — the Goose launch shapes beyond `session` / `run`
 * (supported-agents.md §5.6 "Recipes, review and ACP"): the REAL goose
 * binary under the REAL launcher (`main()`), the REAL arbiter daemon in
 * `secrets` mode with a file labelled `no-model`, the autostarted
 * anthropic-proxy, and a scripted model upstream that records every request.
 * Needs a goose binary (MANDU_GOOSE_BIN, else `goose` on PATH; the CI guest
 * pins 1.53.0); without one the suite SKIPS with that reason, never a green.
 *
 *   recipe   `mandu goose run --recipe r.yaml`: the recipe's turns reach the
 *            model only through the proxy, and the labelled file the model
 *            makes it `cat` reaches the model only as a symbol (THE
 *            INVARIANT); a recipe naming another provider is refused and
 *            nothing reaches the upstream;
 *   review   `mandu goose review`: every `goose run` child it starts (the
 *            main pass per file and each `.agents/checks/*.md` check) reaches
 *            the model only through the proxy, and the labelled file in the
 *            diff (an untracked file Goose inlines into the prompt) reaches
 *            the model only as a symbol; `review --provider google` (a
 *            provider Mandu does not route) is refused before anything
 *            starts.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../axes.js";
import { stopGroup } from "../lib/tmp-dir.js";
import { sourceArbiterArgs, waitForPaths } from "../lib/arbiter-ready.js";

stateAxes("secrets"); // the shipped default: the labelled file must reach the model only as a symbol

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
const ARBITER_DIR = join(REPO_ROOT, "arbiter");

/** The goose binary, or null. */
function findGoose(): string | null {
  const pinned = process.env["MANDU_GOOSE_BIN"];
  if (pinned) return existsSync(pinned) ? pinned : null;
  for (const d of (process.env["PATH"] ?? "").split(delimiter)) {
    const p = join(d, "goose");
    if (d && existsSync(p)) return p;
  }
  return null;
}
const GOOSE = findGoose();
const SKIP = GOOSE === null
  ? "no goose binary: set MANDU_GOOSE_BIN or put goose on PATH (the CI guest image pins it; scripts/ci/pins.env)"
  : (spawnSync(GOOSE, ["--version"], { encoding: "utf8", timeout: 20_000 }).status !== 0 ? `${GOOSE} --version failed` : false);

const MODEL = "claude-sonnet-4-5";
const CANARY = "GOOSE-SHAPES-CANARY-7731";
const SECRET_BODY = `ACME_API_KEY=sk-live-${CANARY}\n`;

let tmp: string;
let work: string;
let secretFile: string;
let arbiter: ChildProcess | undefined;
let upstream: Server;
let upstreamOrigin = "";
let script: "recipe" | "review" = "recipe";
const reqs: Array<{ path: string; raw: string; body: Record<string, unknown> | null }> = [];
let passed = 0;

function sse(events: Array<[string, unknown]>): string {
  return events.map(([e, d]) => `event: ${e}\ndata: ${JSON.stringify(d)}\n\n`).join("");
}
const start = (id: string): [string, unknown] => ["message_start", { type: "message_start", message: { id, type: "message", role: "assistant", model: MODEL, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 5, output_tokens: 1 } } }];
const textTurn = (t: string): string => sse([
  start("msg_t"),
  ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }],
  ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: t } }],
  ["content_block_stop", { type: "content_block_stop", index: 0 }],
  ["message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } }],
  ["message_stop", { type: "message_stop" }],
]);
const shellTurn = (command: string): string => sse([
  start("msg_u"),
  ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_goose_shapes_1", name: "shell", input: {} } }],
  ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ command }) } }],
  ["content_block_stop", { type: "content_block_stop", index: 0 }],
  ["message_delta", { type: "message_delta", delta: { stop_reason: "tool_use", stop_sequence: null }, usage: { output_tokens: 1 } }],
  ["message_stop", { type: "message_stop" }],
]);

/** The scripted model. `recipe`: the first tools-bearing request of a run
 *  gets a shell call that cats the labelled file, the one carrying its
 *  result the closing text; a tool-less request (a title) gets a title.
 *  `review`: every request (each reviewer child, tool-less under
 *  `--no-profile`) answers no findings. */
function scripted(req: IncomingMessage, res: ServerResponse): void {
  let buf = "";
  req.setEncoding("utf8");
  req.on("data", (c) => (buf += c));
  req.on("end", () => {
    let body: Record<string, unknown> | null = null;
    try { body = JSON.parse(buf) as Record<string, unknown>; } catch { /* not JSON */ }
    reqs.push({ path: req.url ?? "", raw: buf, body });
    const tools = Array.isArray(body?.["tools"]) ? (body!["tools"] as unknown[]) : [];
    const msgs = Array.isArray(body?.["messages"]) ? (body!["messages"] as Array<{ content?: unknown }>) : [];
    const hasResult = msgs.some((m) => Array.isArray(m.content) && (m.content as Array<{ type?: string }>).some((b) => b.type === "tool_result"));
    res.writeHead(200, { "content-type": "text/event-stream" });
    // A reviewer child runs `goose run --no-profile`: no extensions, no tools.
    if (script === "review") return void res.end(textTurn('{"findings": []}'));
    if (tools.length === 0) return void res.end(textTurn("Title"));
    res.end(hasResult ? textTurn("MANDU_GOOSE_RECIPE_DONE") : shellTurn(`cat ${secretFile}`));
  });
}

function git(args: string[]): void {
  const r = spawnSync("git", args, { cwd: work, encoding: "utf8", env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" } });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
}

before(async () => {
  if (SKIP) return;
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-goose-shapes-")));
  work = join(tmp, "work");
  mkdirSync(join(work, "vault"), { recursive: true });
  secretFile = join(work, "vault", "api.env");
  writeFileSync(secretFile, SECRET_BODY);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(work, "vault")}\n    level: no-model\n`);
  const logFd = openSync(join(tmp, "arbiter.log"), "a");
  arbiter = spawn(process.execPath, sourceArbiterArgs(join(tmp, "arbiter.sock")), {
    cwd: ARBITER_DIR,
    env: { ...process.env, HOME: tmp, MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_HOME: join(tmp, "mandu-home"), MANDU_RUNTIME_DIR: join(tmp, "mandu"), MANDU_POLICY_FILE: policy },
    stdio: ["ignore", logFd, logFd], detached: true,
  });
  closeSync(logFd);
  await waitForPaths(join(tmp, "arbiter.sock"), { what: "the arbiter", child: arbiter, logPath: join(tmp, "arbiter.log") });
  upstream = createHttpServer(scripted);
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
  upstreamOrigin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  process.env["MANDU_UPSTREAM"] = upstreamOrigin;
});

after(async () => {
  delete process.env["MANDU_UPSTREAM"];
  upstream?.close();
  if (arbiter) await stopGroup(arbiter);
  if (!tmp) return;
  if (passed < 4) {
    try { console.error(`goose-shapes-real: arbiter log tail:\n${readFileSync(join(tmp, "arbiter.log"), "utf8").split("\n").slice(-30).join("\n")}`); } catch { /* none */ }
  }
  rmSync(tmp, { recursive: true, force: true });
});

/** The launch env: a throwaway Goose home and a key; no kernel layer (the
 *  model-context chokepoint is what is under test). */
function launchEnv(home: string, extra: Record<string, string> = {}): Record<string, string | undefined> {
  return {
    HOME: tmp, PATH: process.env["PATH"], PWD: work,
    MANDU_HOME: PRIVATE_MANDU_HOME, XDG_RUNTIME_DIR: tmp,
    MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_PROXY_PORT: "0", MANDU_MODE: "secrets",
    MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0",
    GOOSE_PATH_ROOT: home, GOOSE_DISABLE_KEYRING: "1", GOOSE_MODE: "auto", GOOSE_MODEL: MODEL,
    ANTHROPIC_API_KEY: "sk-ant-mandu-test",
    GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
    ...extra,
  };
}

/** `main()` from the workspace, as `mandu` started there runs: the launch's
 *  secret discovery walks the process's working directory, which is how the
 *  labelled file becomes a registered value the prompt filter masks. */
async function launchIn(argv: string[], env: Record<string, string | undefined>): Promise<number> {
  const was = process.cwd();
  process.chdir(work);
  try { return await main(argv, env); } finally { process.chdir(was); }
}

function assertNoRawSecret(): void {
  for (const q of reqs) {
    assert.ok(!q.raw.includes(CANARY), `INVARIANT: the labelled value never reaches the model raw (request to ${q.path})`);
  }
}

test("`mandu goose run --recipe`: the recipe's turns go through the proxy, and the labelled file it reads reaches the model only as a symbol", { skip: SKIP, timeout: 180_000 }, async () => {
  reqs.length = 0;
  script = "recipe";
  const recipe = join(work, "audit.yaml");
  writeFileSync(recipe, [
    "version: 1.0.0",
    "title: Audit",
    "description: Read the env file",
    "instructions: You audit files with your shell.",
    "prompt: Read the api env file and summarize it.",
    "settings:",
    `  goose_model: ${MODEL}`,
    "",
  ].join("\n"));
  const code = await launchIn(["--no-scope", "--", GOOSE!, "run", "--no-session", "--recipe", "audit.yaml"], launchEnv(join(tmp, "goose-recipe")));
  assert.equal(code, 0, "the recipe ran under Mandu");
  const tooled = reqs.filter((q) => Array.isArray(q.body?.["tools"]) && (q.body!["tools"] as unknown[]).length > 0);
  assert.ok(tooled.length >= 2, `the proxy forwarded the recipe's turns (${reqs.length} requests)`);
  for (const q of reqs) assert.match(q.path, /\/v1\/messages$/);
  assert.ok(JSON.stringify(tooled[0]!.body).includes("You audit files with your shell."), "the recipe's instructions reached the model");
  const last = JSON.stringify(tooled.at(-1)!.body);
  assert.ok(last.includes("tool_result"), "the shell result came back through the proxy");
  assert.match(last, /\$MDU:/, "the labelled file's content reached the model as a symbol");
  assertNoRawSecret();
  passed++;
});

test("`mandu goose run --recipe` naming another provider: refused, goose never starts, the upstream sees nothing", { skip: SKIP, timeout: 60_000 }, async () => {
  reqs.length = 0;
  writeFileSync(join(work, "elsewhere.yaml"), "version: 1.0.0\ntitle: X\ndescription: Y\nprompt: hi\nsettings:\n  goose_provider: openai\n  goose_model: gpt-4o\n");
  await assert.rejects(
    () => main(["--no-scope", "--", GOOSE!, "run", "--recipe", "elsewhere.yaml"], launchEnv(join(tmp, "goose-recipe-refused"))),
    /refusing `goose run --recipe elsewhere\.yaml`.*goose_provider names the provider `openai`/,
  );
  assert.equal(reqs.length, 0, "nothing reached the upstream");
  passed++;
});

test("`mandu goose review`: every reviewer child goes through the proxy, and the labelled file in the diff reaches the model only as a symbol", { skip: SKIP, timeout: 300_000 }, async () => {
  reqs.length = 0;
  script = "review";
  git(["init", "-q", "-b", "main"]);
  git(["config", "user.email", "t@example.com"]);
  git(["config", "user.name", "t"]);
  writeFileSync(join(work, "app.js"), "export const x = 1;\n");
  git(["add", "app.js"]);
  git(["commit", "-q", "-m", "init"]);
  writeFileSync(join(work, "app.js"), "export const x = 2;\n");
  // a check: a `goose run` child of its own, with a model of its own
  mkdirSync(join(work, ".agents", "checks"), { recursive: true });
  writeFileSync(join(work, ".agents", "checks", "secrets.md"), `---\nname: secrets\ndescription: Flag secrets\nmodel: ${MODEL}\n---\nFlag any committed secret.\n`);
  const code = await launchIn(["--no-scope", "--", GOOSE!, "review", "--severity", "low"], launchEnv(join(tmp, "goose-review")));
  assert.equal(code, 0, "the review ran under Mandu");
  // the main pass (one child per touched file: app.js, the check, the
  // untracked vault/api.env and the recipe tests' files) and the check
  assert.ok(reqs.length >= 3, `the reviewer children reached the model through the proxy (${reqs.length} requests)`);
  for (const q of reqs) assert.match(q.path, /\/v1\/messages$/);
  assert.ok(reqs.some((q) => q.raw.includes("Flag any committed secret.")), "the check's own child ran");
  assert.ok(reqs.some((q) => q.raw.includes("vault/api.env")), "the labelled file was in the reviewed diff");
  assert.ok(reqs.some((q) => /\$MDU:/.test(q.raw)), "it reached the model as a symbol");
  assertNoRawSecret();
  passed++;
});

test("`mandu goose review --provider google`: refused before anything starts", { skip: SKIP, timeout: 60_000 }, async () => {
  reqs.length = 0;
  await assert.rejects(
    () => main(["--no-scope", "--", GOOSE!, "review", "--provider", "google"], launchEnv(join(tmp, "goose-review-refused"))),
    /--provider names the provider `google`/,
  );
  assert.equal(reqs.length, 0, "nothing reached the upstream");
  passed++;
});
