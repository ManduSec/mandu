/**
 * CliUllmClient unit tests — the SUBPROCESS U-LLM (src/ullm-client.ts).
 *
 * Mandu M4 (interceptors/inspect-mcp). The CLI client reuses the user's
 * logged-in Claude Code auth by spawning a fresh `claude -p` (or `codex exec`)
 * child. These tests are OFFLINE: the subprocess + temp-dir seams are injected,
 * so NO real claude/codex runs and NO key is needed. They assert:
 *   - the argv (-p, --model, --tools "" to DISABLE ALL TOOLS, --output-format json),
 *   - the user message is delivered on STDIN (claude and codex), never argv;
 *     codex's quarantine prompt is a file in the temp cwd (its model
 *     instructions) and its argv is the tool-less, config-less quarantine,
 *   - the child runs in a fresh temp cwd (cleaned up after),
 *   - the child env's ANTHROPIC_BASE_URL is the REAL endpoint (never a proxy)
 *     while inherited auth env carries through,
 *   - {text, model} parsing for claude-json and codex-jsonl,
 *   - FAIL-CLOSED on non-zero exit / spawn error / timeout signal / bad JSON.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CliUllmClient,
  buildCliArgs,
  codexStderrDetail,
  codexForwarderProvider,
  CODEX_ULLM_PROVIDER,
  CODEX_DISABLED_FEATURES,
  CODEX_INSTRUCTIONS_FILE,
  CODEX_SOFT_DISABLED_FEATURES,
  defaultCliExec,
  resolveCliBinary,
  parseClaudeCliJson,
  parseCodexCliJsonl,
  type CliExecResult,
  type CliExecSpec,
} from "../../src/ullm-client.js";

const SYSTEM = "QUARANTINE SYSTEM PROMPT";
const USER = "## Instructions\nsummarize\n## Data\nthe untrusted page body";

/** A canned claude `-p --output-format json` payload. */
function claudeJson(result: string, model = "claude-haiku-4-5"): string {
  return JSON.stringify({ type: "result", is_error: false, result, model, usage: { input_tokens: 3, output_tokens: 5 } });
}

/** A canned codex `exec --json` JSONL event stream. */
function codexJsonl(text: string, model = "gpt-5.4-mini"): string {
  return [
    JSON.stringify({ type: "thread.started" }),
    JSON.stringify({ type: "item.completed", item: { type: "agent_message", text }, model }),
    JSON.stringify({ type: "turn.completed", usage: { input_tokens: 3, output_tokens: 5 } }),
  ].join("\n");
}

/** Build a CliUllmClient whose exec + temp-dir seams are recorded. */
function makeClient(
  opts: {
    binary?: "claude" | "codex" | "auto";
    model?: string;
    baseUrl?: string;
    execResult?: CliExecResult;
    execImpl?: (spec: CliExecSpec) => CliExecResult | Promise<CliExecResult>;
  } = {},
) {
  const specs: CliExecSpec[] = [];
  const made: string[] = [];
  const removed: string[] = [];
  const written: Array<{ path: string; content: string }> = [];
  const defaultResult: CliExecResult = opts.execResult ?? {
    status: 0,
    signal: null,
    stdout: claudeJson("a benign summary"),
    stderr: "",
  };
  const client = new CliUllmClient({
    binary: opts.binary,
    model: opts.model,
    baseUrl: opts.baseUrl,
    exec: (spec) => {
      specs.push(spec);
      return opts.execImpl ? opts.execImpl(spec) : defaultResult;
    },
    mkTempDir: () => {
      const dir = `/tmp/fake-ullm-${made.length}`;
      made.push(dir);
      return dir;
    },
    rmTempDir: (dir) => removed.push(dir),
    writeTempFile: (path, content) => written.push({ path, content }),
  });
  return { client, specs, made, removed, written };
}

// ── pure helpers ──────────────────────────────────────────────────────────────

test("resolveCliBinary: auto picks codex for OpenAI/gpt/o* ids, claude otherwise", () => {
  assert.equal(resolveCliBinary("auto", "claude-haiku-4-5"), "claude");
  assert.equal(resolveCliBinary("auto", "gpt-5.4-mini"), "codex");
  assert.equal(resolveCliBinary("auto", "openai/gpt-5"), "codex");
  assert.equal(resolveCliBinary("auto", "o3-mini"), "codex");
  // An explicit binary always wins over the model heuristic.
  assert.equal(resolveCliBinary("claude", "gpt-5"), "claude");
  assert.equal(resolveCliBinary("codex", "claude-haiku-4-5"), "codex");
});

test("buildCliArgs(claude): -p, --model, --output-format json, --tools \"\" to disable ALL tools, --setting-sources project,local, --system-prompt; user message on stdin", () => {
  const { args, useStdin, input } = buildCliArgs("claude", "claude-haiku-4-5", "SYSTEM", "USER");
  assert.deepEqual(args, [
    "-p", "--model", "claude-haiku-4-5", "--output-format", "json",
    "--tools", "", "--setting-sources", "project,local",
    "--system-prompt", "SYSTEM",
  ]);
  assert.equal(useStdin, true);
  assert.equal(input, "USER");
  // The empty --tools value is the verified tool-disabling flag.
  const i = args.indexOf("--tools");
  assert.ok(i >= 0 && args[i + 1] === "", "--tools must be followed by an empty string");
});

test("buildCliArgs(claude): the quarantine prompt rides the REAL system slot, not user text", () => {
  // Delivered as user text, "you are a quarantined data processor" reads to a
  // live Claude as a role-override jailbreak and triggers refusals (the U-LLM
  // refusal utility gap). --system-prompt REPLACES CC's own system prompt, so
  // the child boots as the processor. The untrusted DATA must stay OFF argv.
  const { args, input } = buildCliArgs("claude", "claude-haiku-4-5", "SYSTEM", "USER");
  const i = args.indexOf("--system-prompt");
  assert.ok(i >= 0, "claude argv must carry --system-prompt");
  assert.equal(args[i + 1], "SYSTEM", "the system slot carries the quarantine prompt");
  assert.ok(!args.includes("USER"), "the user message (untrusted DATA) must not be argv");
  assert.ok(!input.includes("SYSTEM"), "the system prompt must not be duplicated on stdin");
});

test("buildCliArgs(claude): pins --setting-sources project,local so a user-global apiKeyHelper can't override the subscription", () => {
  // apiKeyHelper outranks OAuth in CC's auth order and lives in USER settings.
  // Loading only project,local (which don't exist in the fresh temp cwd) excludes
  // it, so the quarantined child falls through to the logged-in subscription.
  const { args } = buildCliArgs("claude", "claude-haiku-4-5", "SYSTEM", "USER");
  const i = args.indexOf("--setting-sources");
  assert.ok(i >= 0, "claude argv must pin --setting-sources");
  assert.equal(args[i + 1], "project,local", "must exclude the user source (apiKeyHelper lives there)");
});

test("buildCliArgs(codex): the quarantine argv; the prompt as a file in the work dir, the user message on stdin; strips openai/ prefix", () => {
  const inv = buildCliArgs("codex", "openai/gpt-5.4-mini", "SYSTEM", "USER", "/tmp/w");
  assert.equal(inv.args[0], "exec");
  for (const flag of ["--skip-git-repo-check", "--ephemeral", "--ignore-user-config", "--ignore-rules", "--json"]) {
    assert.ok(inv.args.includes(flag), `codex argv must carry ${flag}`);
  }
  const val = (k: string) => inv.args[inv.args.indexOf(k) + 1];
  assert.equal(val("-s"), "read-only");
  assert.equal(val("-m"), "gpt-5.4-mini");
  assert.equal(inv.args.at(-1), "-", "the prompt is read from stdin");
  const overrides = inv.args.filter((_, i) => inv.args[i - 1] === "-c");
  assert.ok(overrides.includes('approval_policy="never"'));
  assert.ok(overrides.includes(`model_instructions_file=${JSON.stringify(`/tmp/w/${CODEX_INSTRUCTIONS_FILE}`)}`));
  for (const k of ["include_environment_context=false", "project_doc_max_bytes=0", "skills.bundled.enabled=false", 'web_search="disabled"']) {
    assert.ok(overrides.includes(k), k);
  }
  for (const f of CODEX_SOFT_DISABLED_FEATURES) assert.ok(overrides.includes(`features.${f}=false`), f);
  const disabled = inv.args.filter((_, i) => inv.args[i - 1] === "--disable");
  assert.deepEqual(disabled, [...CODEX_DISABLED_FEATURES]);
  for (const f of ["shell_tool", "unified_exec", "apps", "plugins", "multi_agent"]) assert.ok(disabled.includes(f as never), f);
  assert.equal(inv.useStdin, true);
  assert.equal(inv.input, "USER");
  assert.deepEqual(inv.files, [{ name: CODEX_INSTRUCTIONS_FILE, content: "SYSTEM" }]);
  assert.ok(!inv.args.some((a) => a.includes("USER") || a.includes("SYSTEM")), "neither prompt rides argv");
});

test("buildCliArgs(codex): no model → no -m (Codex picks its own; the Claude default id is never sent to Codex)", () => {
  const inv = buildCliArgs("codex", undefined, "SYSTEM", "USER", "/tmp/w");
  assert.ok(!inv.args.includes("-m"));
});

test("buildCliArgs(codex): no forwarder → Codex's built-in provider (no provider override); analytics off either way", () => {
  const inv = buildCliArgs("codex", undefined, "SYSTEM", "USER", "/tmp/w");
  assert.ok(!inv.args.some((a) => a.startsWith("model_provider")));
  assert.ok(inv.args.includes("analytics.enabled=false"));
});

test("buildCliArgs(codex) behind the launcher's forwarder: the child's provider is the forwarder's /v1, with Codex's own sign-in (requires_openai_auth), SSE", () => {
  const inv = buildCliArgs("codex", undefined, "SYSTEM", "USER", "/tmp/w", "http://127.0.0.1:43210");
  const overrides = inv.args.filter((_, i) => inv.args[i - 1] === "-c");
  assert.ok(overrides.includes(`model_provider="${CODEX_ULLM_PROVIDER}"`));
  const table = overrides.find((o) => o.startsWith(`model_providers.${CODEX_ULLM_PROVIDER}=`))!;
  assert.match(table, /base_url="http:\/\/127\.0\.0\.1:43210\/v1"/);
  assert.match(table, /wire_api="responses"/);
  assert.match(table, /requires_openai_auth=true/);
  assert.match(table, /supports_websockets=false/);
  assert.ok(!/env_key/.test(table), "no key variable: Codex sends its own sign-in");
  // a path or trailing slash on the pin is reduced to its origin
  assert.match(codexForwarderProvider("http://127.0.0.1:43210/")[3]!, /base_url="http:\/\/127\.0\.0\.1:43210\/v1"/);
});

test("SECURITY: a forwarder pin that is not an http(s) URL fails the codex call closed", () => {
  assert.throws(() => codexForwarderProvider("not a url"), /fail closed/);
  assert.throws(() => codexForwarderProvider("file:///tmp/x"), /fail closed/);
});

test("complete(codex): the forwarder pin reaches the child's argv", async () => {
  const { specs } = await (async () => {
    const made: string[] = [];
    const specs: CliExecSpec[] = [];
    const client = new CliUllmClient({
      binary: "codex", forwarderUrl: "http://127.0.0.1:43210",
      exec: (spec) => { specs.push(spec); return { status: 0, signal: null, stdout: codexJsonl("ok"), stderr: "" }; },
      mkTempDir: () => { made.push("/tmp/fake-fwd"); return "/tmp/fake-fwd"; },
      rmTempDir: () => {}, writeTempFile: () => {},
    });
    await client.complete({ system: SYSTEM, user: USER });
    return { specs };
  })();
  assert.ok(specs[0]!.args.some((a) => a.includes('base_url="http://127.0.0.1:43210/v1"')));
});

test("codexStderrDetail drops Codex's stdin notice and keeps the rest", () => {
  assert.equal(codexStderrDetail("Reading additional input from stdin...\nNot inside a trusted directory"), "Not inside a trusted directory");
});

// ── output parsing ────────────────────────────────────────────────────────────

test("parseClaudeCliJson: extracts {text, model} from the result payload", () => {
  const r = parseClaudeCliJson(claudeJson("hello world", "claude-sonnet"), "fallback");
  assert.equal(r.text, "hello world");
  assert.equal(r.model, "claude-sonnet");
});

test("parseClaudeCliJson: throws on empty / non-JSON / error payloads (fail-closed)", () => {
  assert.throws(() => parseClaudeCliJson("", "m"), /empty/i);
  assert.throws(() => parseClaudeCliJson("not json", "m"), /not valid JSON/i);
  assert.throws(
    () => parseClaudeCliJson(JSON.stringify({ is_error: true, result: "boom" }), "m"),
    /reported an error.*boom/i,
  );
});

test("parseCodexCliJsonl: extracts the last agent_message text + model", () => {
  const r = parseCodexCliJsonl(codexJsonl("codex summary", "gpt-5.4-mini"), "fallback");
  assert.equal(r.text, "codex summary");
  assert.equal(r.model, "gpt-5.4-mini");
});

test("parseCodexCliJsonl: throws when there are no JSON events (fail-closed)", () => {
  assert.throws(() => parseCodexCliJsonl("", "m"), /no JSON events/i);
});

// ── complete(): argv, stdin, cwd, env ─────────────────────────────────────────

test("complete(claude): spawns claude with the tool-disabling argv, prompt on stdin, in a fresh temp cwd", async () => {
  const { client, specs, made, removed } = makeClient({ binary: "claude", model: "claude-haiku-4-5" });
  const res = await client.complete({ system: SYSTEM, user: USER });

  assert.equal(res.text, "a benign summary");
  assert.equal(res.model, "claude-haiku-4-5");

  assert.equal(specs.length, 1);
  const spec = specs[0];
  assert.equal(spec.file, "claude");
  assert.deepEqual(spec.args, [
    "-p", "--model", "claude-haiku-4-5", "--output-format", "json",
    "--tools", "", "--setting-sources", "project,local",
    "--system-prompt", SYSTEM,
  ]);
  // The system prompt rides argv (--system-prompt, fixed text); the user
  // message (untrusted DATA) is delivered on STDIN, never argv.
  assert.equal(spec.input, USER);
  assert.ok(!spec.args.some((a) => a.includes(USER)), "user message must not be passed as an argv element");

  // Clean temp cwd: created, used, removed.
  assert.equal(spec.cwd, made[0]);
  assert.deepEqual(removed, [made[0]], "temp cwd must be cleaned up after the call");
});

test("complete(codex): the quarantine argv, the prompt file written in the fresh temp cwd, the user message on stdin, never argv", async () => {
  const { client, specs, made, removed, written } = makeClient({
    binary: "codex",
    model: "gpt-5.4-mini",
    execResult: { status: 0, signal: null, stdout: codexJsonl("codex says hi"), stderr: "" },
  });
  const res = await client.complete({ system: SYSTEM, user: USER });
  assert.equal(res.text, "codex says hi");

  const spec = specs[0];
  assert.equal(spec.file, "codex");
  assert.deepEqual(spec.args, buildCliArgs("codex", "gpt-5.4-mini", SYSTEM, USER, made[0]).args);
  assert.equal(spec.cwd, made[0]);
  assert.equal(spec.input, USER);
  assert.ok(!spec.args.some((a) => a.includes(USER) || a.includes(SYSTEM)), "no prompt on argv");
  assert.deepEqual(written, [{ path: `${made[0]}/${CODEX_INSTRUCTIONS_FILE}`, content: SYSTEM }]);
  assert.equal(spec.env.TMPDIR, made[0], "codex's temp files land in the call's own temp cwd");
  assert.deepEqual(removed, [made[0]]);
});

test("complete(codex): no model configured → no -m, and the answer is labelled codex-default when Codex names none", async () => {
  const { client, specs } = makeClient({
    binary: "codex",
    execResult: {
      status: 0, signal: null, stderr: "",
      stdout: JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "ok" } }),
    },
  });
  const res = await client.complete({ system: SYSTEM, user: USER });
  assert.ok(!specs[0].args.includes("-m"));
  assert.equal(res.model, "codex-default");
});

test("SECURITY: a failed codex call reports stderr only, never its stdout event stream (the model's untrusted answer)", async () => {
  const { client } = makeClient({
    binary: "codex",
    execResult: {
      status: 1, signal: null,
      stdout: JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "RAW-ANSWER-TEXT" } }),
      stderr: "Reading additional input from stdin...\nturn failed",
    },
  });
  await assert.rejects(() => client.complete({ system: SYSTEM, user: USER }), (e: Error) => {
    assert.match(e.message, /codex exited 1: turn failed/);
    assert.ok(!e.message.includes("RAW-ANSWER-TEXT"));
    assert.ok(!e.message.includes("Reading additional input"));
    return true;
  });
});

test("SECURITY: the codex child never inherits OPENAI_BASE_URL (it would re-point Codex's built-in provider)", async () => {
  process.env.OPENAI_BASE_URL = "http://127.0.0.1:8789/v1";
  try {
    const { client, specs } = makeClient({
      binary: "codex",
      execResult: { status: 0, signal: null, stdout: codexJsonl("x"), stderr: "" },
    });
    await client.complete({ system: SYSTEM, user: USER });
    assert.equal(specs[0].env.OPENAI_BASE_URL, undefined);
  } finally {
    delete process.env.OPENAI_BASE_URL;
  }
});

test("SECURITY: with a custom baseUrl the child env's ANTHROPIC_BASE_URL is the REAL endpoint, not a proxy; auth env is inherited", async () => {
  // Simulate the parent being pointed at the anthropic-proxy (the dangerous case).
  process.env.ANTHROPIC_BASE_URL = "http://127.0.0.1:8788";
  process.env.MANDU_FAKE_AUTH = "carry-me-through";
  try {
    const { client, specs } = makeClient({
      binary: "claude",
      baseUrl: "https://api.anthropic.com", // the configured REAL ullm base
    });
    await client.complete({ system: SYSTEM, user: USER });
    const env = specs[0].env;
    // The default real endpoint means we DELETE the inherited (proxy) base URL so
    // claude uses its own logged-in config — the child is NEVER on the proxy.
    assert.equal(env.ANTHROPIC_BASE_URL, undefined, "must not inherit the 127.0.0.1 proxy base URL");
    assert.ok(!String(env.ANTHROPIC_BASE_URL ?? "").includes("8788"));
    // Inherited auth/other env carries through (that's the whole point).
    assert.equal(env.MANDU_FAKE_AUTH, "carry-me-through");
  } finally {
    delete process.env.ANTHROPIC_BASE_URL;
    delete process.env.MANDU_FAKE_AUTH;
  }
});

test("SECURITY: cli-mode DROPS ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN from the child so the logged-in SUBSCRIPTION is used, not a stray key", async () => {
  // CC's auth order puts ANTHROPIC_AUTH_TOKEN and ANTHROPIC_API_KEY ABOVE the
  // OAuth/keychain login. cli-mode means "reuse the subscription, no key", so an
  // inherited key/token MUST be scrubbed — otherwise the "subscription" U-LLM
  // would silently bill the metered API instead.
  process.env.ANTHROPIC_API_KEY = "sk-ant-should-not-leak";
  process.env.ANTHROPIC_AUTH_TOKEN = "bearer-should-not-leak";
  process.env.MANDU_FAKE_AUTH = "carry-me-through";
  try {
    const { client, specs } = makeClient({ binary: "claude" });
    await client.complete({ system: SYSTEM, user: USER });
    const env = specs[0].env;
    assert.equal(env.ANTHROPIC_API_KEY, undefined, "API key must not reach the child");
    assert.equal(env.ANTHROPIC_AUTH_TOKEN, undefined, "auth token must not reach the child");
    // Non-Anthropic env still passes through (the login credentials ride along).
    assert.equal(env.MANDU_FAKE_AUTH, "carry-me-through");
  } finally {
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_AUTH_TOKEN;
    delete process.env.MANDU_FAKE_AUTH;
  }
});

test("SECURITY: a non-default ullm baseUrl is set verbatim on the child (real endpoint override), never derived from a proxy", async () => {
  process.env.ANTHROPIC_BASE_URL = "http://127.0.0.1:8788"; // parent proxy
  try {
    const { client, specs } = makeClient({
      binary: "claude",
      baseUrl: "https://corp-anthropic.example.com",
    });
    await client.complete({ system: SYSTEM, user: USER });
    assert.equal(specs[0].env.ANTHROPIC_BASE_URL, "https://corp-anthropic.example.com");
  } finally {
    delete process.env.ANTHROPIC_BASE_URL;
  }
});

// ── fail-closed ───────────────────────────────────────────────────────────────

test("FAIL-CLOSED: non-zero exit throws (and cleans up the temp cwd)", async () => {
  const { client, removed, made } = makeClient({
    execResult: { status: 2, signal: null, stdout: "", stderr: "boom: not logged in" },
  });
  await assert.rejects(
    () => client.complete({ system: SYSTEM, user: USER }),
    /exited 2.*boom/i,
  );
  assert.deepEqual(removed, [made[0]], "temp cwd cleaned up even on failure");
});

test("FAIL-CLOSED: a spawn error (binary missing) throws", async () => {
  const { client } = makeClient({
    execResult: { status: null, signal: null, stdout: "", stderr: "", error: new Error("spawn claude ENOENT") },
  });
  await assert.rejects(() => client.complete({ system: SYSTEM, user: USER }), /spawn failed.*ENOENT/i);
});

test("FAIL-CLOSED: a timeout signal throws", async () => {
  const { client } = makeClient({
    execResult: { status: null, signal: "SIGTERM", stdout: "", stderr: "" },
  });
  await assert.rejects(() => client.complete({ system: SYSTEM, user: USER }), /SIGTERM.*timeout/i);
});

test("FAIL-CLOSED: malformed JSON output throws", async () => {
  const { client } = makeClient({
    execResult: { status: 0, signal: null, stdout: "definitely not json", stderr: "" },
  });
  await assert.rejects(() => client.complete({ system: SYSTEM, user: USER }), /not valid JSON/i);
});

test("FAIL-CLOSED: a zero-exit but empty result text throws (no usable response)", async () => {
  const { client } = makeClient({
    execResult: { status: 0, signal: null, stdout: claudeJson(""), stderr: "" },
  });
  await assert.rejects(() => client.complete({ system: SYSTEM, user: USER }), /no response text/i);
});

test("auto binary: a claude-family model drives `claude`", async () => {
  const { client, specs } = makeClient({ binary: "auto", model: "claude-haiku-4-5" });
  await client.complete({ system: SYSTEM, user: USER });
  assert.equal(specs[0].file, "claude");
});

// ── the async exec seam ──────────────────────────────────────────────────────

test("complete(): an exec seam returning a Promise is awaited (async runners are first-class)", async () => {
  const { client } = makeClient({
    binary: "claude",
    model: "claude-haiku-4-5",
    execImpl: async () => {
      await new Promise((r) => setTimeout(r, 10));
      return { status: 0, signal: null, stdout: claudeJson("async summary"), stderr: "" };
    },
  });
  const res = await client.complete({ system: SYSTEM, user: USER });
  assert.equal(res.text, "async summary");
});

// ── defaultCliExec (the REAL runner, driven with plain `node` children) ───────
// These are the regression tests for the 2026-07-14 live failure: the old
// spawnSync default froze the event loop for the child's whole runtime, so an
// arbiter IPC reply buffered during a `claude -p` lost the loop-resume race to
// its own expired fail-closed deadline and a HEALTHY arbiter read as timed out.

const NODE = process.execPath;
const SPEC_BASE = {
  cwd: process.cwd(),
  env: process.env,
  timeoutMs: 5_000,
  maxBuffer: 1024 * 1024,
};

test("defaultCliExec: REGRESSION — the event loop stays live while the child runs (never spawnSync)", async () => {
  let ticks = 0;
  const interval = setInterval(() => ticks++, 20);
  try {
    const r = await defaultCliExec({
      ...SPEC_BASE,
      file: NODE,
      args: ["-e", "setTimeout(() => process.stdout.write('done'), 300)"],
      input: "",
    });
    assert.equal(r.status, 0);
    assert.equal(r.stdout, "done");
  } finally {
    clearInterval(interval);
  }
  // A blocking runner yields 0 ticks; the async runner must keep timers firing.
  assert.ok(ticks >= 5, `event loop starved: only ${ticks} timer tick(s) fired during a 300ms child`);
});

test("defaultCliExec: stdin carries the prompt; stdout/stderr are captured separately", async () => {
  const r = await defaultCliExec({
    ...SPEC_BASE,
    file: NODE,
    args: [
      "-e",
      "let b='';process.stdin.on('data',d=>b+=d).on('end',()=>{process.stdout.write(b);process.stderr.write('warn');})",
    ],
    input: "THE PROMPT",
  });
  assert.equal(r.status, 0);
  assert.equal(r.stdout, "THE PROMPT");
  assert.equal(r.stderr, "warn");
  assert.equal(r.error, undefined);
});

test("defaultCliExec: a hung child is SIGTERM-killed at timeoutMs and reports the signal (fail-closed upstream)", async () => {
  const r = await defaultCliExec({
    ...SPEC_BASE,
    file: NODE,
    args: ["-e", "setInterval(() => {}, 1000)"],
    input: "",
    timeoutMs: 200,
  });
  assert.equal(r.signal, "SIGTERM");
  assert.notEqual(r.status, 0);
});

test("defaultCliExec: a missing binary settles with `error` (never hangs, never throws)", async () => {
  const r = await defaultCliExec({
    ...SPEC_BASE,
    file: "mandu-no-such-binary-a8f3",
    args: [],
    input: "",
  });
  assert.ok(r.error, "spawn failure must surface via the error field");
  assert.equal(r.status, null);
});

test("defaultCliExec: output past maxBuffer kills the child and surfaces an error", async () => {
  const r = await defaultCliExec({
    ...SPEC_BASE,
    file: NODE,
    args: ["-e", "const c='x'.repeat(64*1024); setInterval(() => process.stdout.write(c), 5)"],
    input: "",
    maxBuffer: 256 * 1024,
    timeoutMs: 5_000,
  });
  assert.ok(r.error, "overflow must surface via the error field");
  assert.match(r.error!.message, /maxBuffer/);
});
