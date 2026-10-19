/**
 * classify-main — the policy classifier process
 * (docs/design/confidentiality/confidentiality-plan-14-policy-suggestions.md §14.3). The
 * arbiter spawns it once per model run: ONE JSON request on stdin, ONE JSON
 * answer on stdout, nothing on stderr that carries a model's text. No
 * arbiter socket, no tools, no history. Mandu-new (no reference origin).
 *
 *   {"v":1,"op":"describe"}
 *     → {"ok":true,"destination":{name, vendor, mode, binary?, model?, port}}
 *       what the helper's DEFAULT model is (inspect-mcp's selectUllmConfig);
 *       no request to any model
 *   {"v":1,"op":"classify","tier":"names","promptVersion":"names-1",
 *    "endpoint":{kind:"declared", entry, all} | {kind:"default", expect},
 *    "batches":[text, …], "requestTimeoutMs", "runTimeoutMs"}
 *     → {"ok":true,"answers":[{batch, rules:[…]} | {batch, failed:"<category>"}],"dropped":n}
 *   {"v":1,"op":"classify","tier":"contents","promptVersion":"contents-1",
 *    "endpoint":{kind:"declared", entry (local: true), all},
 *    "batches":[document text, …], "requestTimeoutMs", "runTimeoutMs"}
 *     → {"ok":true,"answers":[{batch, answer:{level, reason?}|null} | {batch, failed}],"dropped":n}
 *       (plan 14 §14.11: one request per document; only a declared local
 *       entry, refused before any request otherwise)
 *
 * It reuses the helper's clients and guards, not a copy of them:
 * `buildEndpointUllmClient` (the declared entry: its url checked by the
 * endpoint guard, `endpointFetch` for TLS, pins and the perimeter), and for
 * the default the api/cli selection of `selectUllmConfig` with its loopback
 * refusal. The arbiter wraps this process in `mandu-landlock-apply
 * --net-only` with only the endpoint's port where the kernel allows.
 *
 * Bounds: one request per batch, in order; `requestTimeoutMs` (30 s) per
 * request (a CLI transport gets CLI_REQUEST_TIMEOUT_MS, 120 s: the CLI's own
 * start costs about a minute); after `runTimeoutMs` (5 min) no further request starts and the
 * rest are reported "not sent". A request that fails reports a fixed
 * category; the run continues with the next.
 */
import { pathToFileURL } from "node:url";
import {
  CLASSIFY_PROMPT_VERSION,
  CLI_REQUEST_TIMEOUT_MS,
  CONTENTS_PROMPT_VERSION,
  CONTENTS_SYSTEM_PROMPT,
  NAMES_SYSTEM_PROMPT,
  batchIds,
  failureCategory,
  parseClassifyRequest,
  parseContentsAnswer,
  parseNamesAnswer,
  type ClassifyRequest,
  type ContentsVerdict,
  type ModelRule,
} from "./classify.js";
import { AnthropicUllmClient, CliUllmClient, resolveCliBinary, type UllmClient } from "./ullm-client.js";
import { buildEndpointUllmClient, endpointGuardFromEnv, isOnPath, selectUllmConfig, type UllmConfig } from "./ullm-config.js";

type Env = Record<string, string | undefined>;

export interface ClassifyDeps {
  env: Env;
  cliAvailable: (binary: "claude" | "codex") => boolean;
  /** Build the client for a declared entry or the default (a test injects
   *  a fake; production uses the helper's builders). */
  client?: (req: Extract<ClassifyRequest, { op: "classify" }>, env: Env) => UllmClient;
  now?: () => number;
}

/** The port a URL dials (explicit, else by scheme); null when unparsable. */
function urlPort(url: string): number | null {
  try {
    const u = new URL(url);
    if (u.port !== "") return Number(u.port);
    return u.protocol === "https:" ? 443 : u.protocol === "http:" ? 80 : null;
  } catch {
    return null;
  }
}

/** The default helper's selection, in words. */
export function describeDefault(cfg: UllmConfig): { name: string; vendor: string; mode: string; binary?: string; model?: string; port: number } {
  if (cfg.mode === "api") {
    const base = cfg.forwarderUrl ?? cfg.baseUrl ?? "https://api.anthropic.com";
    return { name: `Claude (${cfg.model ?? "the helper's default model"})`, vendor: "Anthropic", mode: "api", ...(cfg.model ? { model: cfg.model } : {}), port: urlPort(base) ?? 443 };
  }
  const bin = resolveCliBinary(cfg.binary, cfg.model ?? "");
  return bin === "codex"
    ? { name: `Codex (codex exec${cfg.model ? `, ${cfg.model}` : ""})`, vendor: "OpenAI", mode: "cli", binary: "codex", ...(cfg.model ? { model: cfg.model } : {}), port: 443 }
    : { name: `Claude (claude -p${cfg.model ? `, ${cfg.model}` : ""})`, vendor: "Anthropic", mode: "cli", binary: "claude", ...(cfg.model ? { model: cfg.model } : {}), port: urlPort(cfg.baseUrl ?? "https://api.anthropic.com") ?? 443 };
}

/** The production client for a classify request. Throws (a refusal before
 *  any request) when the entry or the selection is unusable. */
export function buildClassifyClient(req: Extract<ClassifyRequest, { op: "classify" }>, env: Env, cliAvailable: (b: "claude" | "codex") => boolean): UllmClient {
  if (req.endpoint.kind === "declared") {
    // The per-request timeout rides the helper's own knob (this process only).
    const e: Env = { ...env, MANDU_ULLM_ENDPOINT_TIMEOUT_MS: String(req.requestTimeoutMs) };
    return buildEndpointUllmClient(req.endpoint.entry, req.endpoint.all, endpointGuardFromEnv(e), e);
  }
  const cfg = selectUllmConfig(env, cliAvailable);
  const d = describeDefault(cfg);
  // Consent named a destination: refuse if the selection moved since.
  if (d.mode !== req.endpoint.expect.mode || (req.endpoint.expect.binary !== undefined && req.endpoint.expect.binary !== d.binary)) {
    throw new Error("the helper's default model changed since the preview; look again");
  }
  if (cfg.mode === "api") {
    return new AnthropicUllmClient({ apiKey: cfg.apiKey, baseUrl: cfg.baseUrl, forwarderUrl: cfg.forwarderUrl, model: cfg.model, timeoutMs: req.requestTimeoutMs });
  }
  return new CliUllmClient({ binary: cfg.binary, baseUrl: cfg.baseUrl, model: cfg.model, timeoutMs: Math.max(req.requestTimeoutMs, CLI_REQUEST_TIMEOUT_MS) });
}

/** Run one request object; returns the stdout JSON. Never throws. */
export async function runClassify(input: string, deps: ClassifyDeps): Promise<Record<string, unknown>> {
  let req: ClassifyRequest;
  try {
    req = parseClassifyRequest(input);
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
  if (req.op === "describe") {
    try {
      return { ok: true, destination: describeDefault(selectUllmConfig(deps.env, deps.cliAvailable)) };
    } catch (e) {
      return { ok: false, error: (e as Error).message };
    }
  }
  let client: UllmClient;
  try {
    client = deps.client ? deps.client(req, deps.env) : buildClassifyClient(req, deps.env, deps.cliAvailable);
  } catch (e) {
    // A refusal before any request: our own guards' words (never a response).
    return { ok: false, error: (e as Error).message.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").slice(0, 300) };
  }
  const now = deps.now ?? (() => Date.now());
  const deadline = now() + req.runTimeoutMs;
  if (req.tier === "contents") {
    // T2 (§14.11): one tool-less, history-less request per document; the
    // answer rebuilt from the two enums, or null (dropped, counted).
    const out: Array<{ batch: number; answer: ContentsVerdict | null } | { batch: number; failed: string }> = [];
    let droppedC = 0;
    for (let i = 0; i < req.batches.length; i++) {
      if (now() >= deadline) { out.push({ batch: i, failed: "not sent" }); continue; }
      try {
        const r = await client.complete({ system: CONTENTS_SYSTEM_PROMPT, user: req.batches[i]! });
        const answer = parseContentsAnswer(r.text);
        if (answer === null) droppedC++;
        out.push({ batch: i, answer });
      } catch (e) {
        out.push({ batch: i, failed: failureCategory(e) });
      }
    }
    return { ok: true, promptVersion: CONTENTS_PROMPT_VERSION, answers: out, dropped: droppedC };
  }
  const answers: Array<{ batch: number; rules: ModelRule[] } | { batch: number; failed: string }> = [];
  let dropped = 0;
  for (let i = 0; i < req.batches.length; i++) {
    if (now() >= deadline) { answers.push({ batch: i, failed: "not sent" }); continue; }
    const batch = req.batches[i]!;
    try {
      const r = await client.complete({ system: NAMES_SYSTEM_PROMPT, user: batch });
      const parsed = parseNamesAnswer(r.text, batchIds(batch));
      dropped += parsed.dropped;
      answers.push({ batch: i, rules: parsed.rules });
    } catch (e) {
      answers.push({ batch: i, failed: failureCategory(e) });
    }
  }
  return { ok: true, promptVersion: CLASSIFY_PROMPT_VERSION, answers, dropped };
}

async function readStdin(max: number): Promise<string> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of process.stdin) {
    const b = typeof c === "string" ? Buffer.from(c) : (c as Buffer);
    n += b.length;
    if (n > max) throw new Error("the request is too large");
    chunks.push(b);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function main(): Promise<void> {
  process.title = "mandu-policy-classifier";
  let out: Record<string, unknown>;
  try {
    const input = await readStdin(16 * 1024 * 1024);
    out = await runClassify(input, { env: process.env, cliAvailable: isOnPath });
  } catch (e) {
    out = { ok: false, error: (e as Error).message };
  }
  process.stdout.write(JSON.stringify(out) + "\n", () => process.exit(0));
}

function isEntrypoint(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(entry).href;
  } catch {
    return false;
  }
}

if (isEntrypoint()) {
  main().catch(() => {
    process.stdout.write(JSON.stringify({ ok: false, error: "the classifier failed" }) + "\n", () => process.exit(1));
  });
}
