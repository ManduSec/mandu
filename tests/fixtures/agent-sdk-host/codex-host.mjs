// codex-host.mjs — a minimal product built on the Codex SDK (@openai/codex-sdk),
// the shape agent-sdk.test.ts runs under
// `mandu --target codex -- node codex-host.mjs "<prompt>"`.
//
// The SDK starts `codex exec --experimental-json` as a child. What the test
// varies, by environment:
//   SDK_HOST_BIN        the CLI to start (codexPathOverride); unset = the
//                       SDK's own bundled binary
//   SDK_HOST_ENV        "replace": pass the SDK an `env` (it REPLACES the
//                       child's environment), the shape that drops Mandu's
//                       routing
//   SDK_HOST_EXTRA_ENV  JSON merged into that replaced env
//   SDK_HOST_BASE_URL   the SDK's `baseUrl` (it becomes
//                       `--config openai_base_url=…`), pointed straight at
//                       the model: the bypass attempt
//   SDK_HOST_CONFIG     JSON for the SDK's `config` (more `--config` pairs)
import { Codex } from "@openai/codex-sdk";

const prompt = process.argv[2] ?? "hello";
const opts = {};
if (process.env.SDK_HOST_BIN) opts.codexPathOverride = process.env.SDK_HOST_BIN;
if (process.env.SDK_HOST_BASE_URL) opts.baseUrl = process.env.SDK_HOST_BASE_URL;
if (process.env.SDK_HOST_CONFIG) opts.config = JSON.parse(process.env.SDK_HOST_CONFIG);
if (process.env.SDK_HOST_ENV === "replace") {
  const keep = ["HOME", "PATH", "OPENAI_API_KEY", "CODEX_HOME"];
  const env = {};
  for (const k of keep) if (process.env[k] !== undefined) env[k] = process.env[k];
  Object.assign(env, JSON.parse(process.env.SDK_HOST_EXTRA_ENV ?? "{}"));
  opts.env = env;
}

try {
  const thread = new Codex(opts).startThread({
    model: "gpt-4o",
    sandboxMode: "danger-full-access",
    approvalPolicy: "never",
    skipGitRepoCheck: true,
    workingDirectory: process.cwd(),
  });
  const turn = await thread.run(prompt);
  console.log(`SDK_HOST_RESULT ${JSON.stringify({ text: turn.finalResponse, items: turn.items.length })}`);
  process.exit(0);
} catch (e) {
  console.log(`SDK_HOST_ERROR ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
}
