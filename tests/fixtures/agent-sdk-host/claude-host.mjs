// claude-host.mjs — a minimal product built on the Claude Agent SDK
// (@anthropic-ai/claude-agent-sdk), the shape agent-sdk.test.ts
// runs under `mandu --target claude -- node claude-host.mjs "<prompt>"`.
//
// The SDK starts the Claude Code CLI as a child with stream-json on stdio.
// What the test varies, by environment:
//   SDK_HOST_BIN        the CLI to start (pathToClaudeCodeExecutable); unset =
//                       the SDK's own bundled binary
//   SDK_HOST_ENV        "replace": pass the SDK an `env` WITHOUT spreading
//                       process.env (the SDK then REPLACES the child's
//                       environment), the shape that drops Mandu's routing
//   SDK_HOST_EXTRA_ENV  JSON merged into that replaced env (e.g. a base URL
//                       pointing straight at the model, the bypass attempt)
//   SDK_HOST_SETTING_SOURCES  comma-separated `settingSources` (default none)
//   SDK_HOST_SETTINGS   JSON for the SDK's `settings` option
import { query } from "@anthropic-ai/claude-agent-sdk";

const prompt = process.argv[2] ?? "hello";
const options = {
  model: "claude-haiku-4-5",
  permissionMode: "bypassPermissions",
  allowDangerouslySkipPermissions: true,
  maxTurns: 8,
  settingSources: [],
  cwd: process.cwd(),
  stderr: (s) => process.stderr.write(`[claude] ${s}`),
};
if (process.env.SDK_HOST_BIN) options.pathToClaudeCodeExecutable = process.env.SDK_HOST_BIN;
// The settings knobs (claude-route.ts): which settings files the CLI reads
// (comma-separated `settingSources`), and the SDK's own `settings` object.
if (process.env.SDK_HOST_SETTING_SOURCES !== undefined) {
  options.settingSources = process.env.SDK_HOST_SETTING_SOURCES.split(",").filter(Boolean);
}
if (process.env.SDK_HOST_SETTINGS) options.settings = JSON.parse(process.env.SDK_HOST_SETTINGS);
if (process.env.SDK_HOST_ENV === "replace") {
  const keep = ["HOME", "PATH", "ANTHROPIC_API_KEY", "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_MAX_RETRIES"];
  const env = {};
  for (const k of keep) if (process.env[k] !== undefined) env[k] = process.env[k];
  Object.assign(env, JSON.parse(process.env.SDK_HOST_EXTRA_ENV ?? "{}"));
  options.env = env;
}

let result = null;
try {
  for await (const m of query({ prompt, options })) {
    if (m.type === "result") result = m;
  }
} catch (e) {
  console.log(`SDK_HOST_ERROR ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
}
console.log(`SDK_HOST_RESULT ${JSON.stringify({ subtype: result?.subtype ?? null, isError: result?.is_error ?? null, text: result?.result ?? null })}`);
process.exit(result && !result.is_error ? 0 : 1);
