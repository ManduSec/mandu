/**
 * openclaw-vertex-real.test — the REAL `openclaw agent --local` on its
 * `google-vertex` provider (Vertex AI's Gemini models) under the REAL launcher
 * (`src/run.ts`, its own process), the REAL arbiter daemon and the
 * autostarted model proxy, against a scripted Vertex model on loopback
 * (model-wires.md §4.1, "Vertex AI at the root"). No key is spent and no
 * provider is dialed: the user's config points the provider's `baseUrl` at
 * the scripted model, which is this process. One test per OpenClaw it finds:
 * `openclaw` (the CI guest's pin, 2026.7.1-2) and `openclaw-<version>` on
 * PATH for each version of the OpenClaw plugin lane (scripts/ci/pins.env
 * OPENCLAW_PLUGIN_LANE_VERSIONS: 2026.3.12, 2026.9.9, 2026.10.7), or
 * MANDU_OPENCLAW_BIN; without one it SKIPS with the reason, never a green.
 *
 *   routing   (2026.7.1 and later) the launcher points the provider's baseUrl
 *             at the proxy's ORIGIN and hands the proxy the user's address
 *             (MANDU_VERTEX_UPSTREAMS): every model request reaches the
 *             scripted model THROUGH the proxy, on OpenClaw's own Vertex path
 *             (`/v1/projects/{p}/locations/{l}/publishers/google/models/
 *             {m}:streamGenerateContent?alt=sse`), with the handling prompt
 *             in it and none of Mandu's own headers on it;
 *   invariant (SECURITY) the scripted model asks for a `read` of a labelled
 *             (no-model) file: its output reaches the model ONLY as a
 *             `$MDU:` symbol; no request carries the value;
 *   bypass    OpenClaw's HTTPS_PROXY is a recorder that refuses every
 *             CONNECT: nothing went toward a Google host, and every request
 *             the model received came from the proxy (an OpenClaw request
 *             sent around it would carry Mandu's session header and no
 *             handling prompt, and fail the test);
 *   refused   (2026.3.12, whose Vertex calls go to Google whatever the
 *             baseUrl) the launch is refused before anything starts, naming
 *             the release, and the model receives nothing.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { once } from "node:events";
import { stateAxes } from "../axes.js";
import { stopGroup } from "../lib/tmp-dir.js";
import { sourceArbiterArgs, waitForPaths } from "../lib/arbiter-ready.js";

stateAxes("secrets"); // the shipped default mode: the labelled file must reach the model only as a symbol

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
const ARBITER_DIR = join(REPO_ROOT, "arbiter");
const LAUNCHER_ROOT = join(REPO_ROOT, "launcher");
const TSX_LOADER = pathToFileURL(join(LAUNCHER_ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;

/** The OpenClaws to run: MANDU_OPENCLAW_BIN alone, else `openclaw` and each
 *  plugin-lane `openclaw-<version>` on PATH. */
function findOpenclaws(): Array<{ bin: string; version: string }> {
  const out: Array<{ bin: string; version: string }> = [];
  const add = (bin: string): void => {
    const home = mkdtempSync(join(tmpdir(), "mdu-ocv-ver-"));
    try {
      const r = spawnSync(bin, ["--version"], { encoding: "utf8", timeout: 60_000, env: { ...process.env, HOME: home } });
      const v = /\b(\d{4}\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)\b/.exec(`${r.stdout ?? ""}`)?.[1];
      if (r.status === 0 && v && !out.some((o) => o.version === v)) out.push({ bin, version: v });
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  };
  const pinned = process.env["MANDU_OPENCLAW_BIN"];
  if (pinned) { if (existsSync(pinned)) add(pinned); return out; }
  const pins = existsSync(join(REPO_ROOT, "scripts", "ci", "pins.env")) ? readFileSync(join(REPO_ROOT, "scripts", "ci", "pins.env"), "utf8") : "";
  const lane = (/^OPENCLAW_PLUGIN_LANE_VERSIONS=(.*)$/m.exec(pins)?.[1] ?? "").split(":").filter(Boolean);
  for (const name of ["openclaw", ...lane.map((v) => `openclaw-${v}`)]) {
    for (const d of (process.env["PATH"] ?? "").split(delimiter)) {
      const p = join(d, name);
      if (d && existsSync(p)) { add(p); break; }
    }
  }
  return out;
}
const OPENCLAWS = findOpenclaws();
const SKIP = OPENCLAWS.length === 0
  ? "no openclaw binary: set MANDU_OPENCLAW_BIN, or put openclaw / openclaw-<version> on PATH (the CI guest image installs them; scripts/ci/pins.env)"
  : false;

/** Does this release take the route (agent-model-route.ts OPENCLAW_VERTEX_BASEURL_SINCE)? */
const routes = (v: string): boolean => {
  const [y, m, d] = v.split(/[.-]/).map(Number) as [number, number, number];
  return y > 2026 || (y === 2026 && (m > 7 || (m === 7 && d >= 1)));
};

const CANARY = "OPENCLAW-VERTEX-REAL-CANARY-5182";
const SECRET_BODY = `ACME_API_KEY=sk-live-${CANARY}\n`;
const SYMBOL_RE = /\$MDU:nomodel_[A-Za-z0-9_]*\[[0-9a-f]+\]/;
const MODEL = "gemini-2.5-flash";
const VERTEX_PATH = new RegExp(`^/v1/projects/acme-vertex-test/locations/us-central1/publishers/google/models/${MODEL.replace(/\./g, "\\.")}:streamGenerateContent$`);

let tmp: string;
let arbiter: ChildProcess | undefined;
let upstream: Server;
let recorder: Server;
let origin = "";
let proxyUrl = "";
const seen: Array<{ method: string; path: string; headers: IncomingMessage["headers"]; body: string }> = [];
const connects: string[] = [];
let readPath = "";

const chunk = (parts: unknown[], finish?: string): string =>
  `data: ${JSON.stringify({ candidates: [{ content: { role: "model", parts }, index: 0, ...(finish ? { finishReason: finish } : {}) }], modelVersion: MODEL, responseId: "resp-ocv-1", usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1, totalTokenCount: 2 } })}\r\n\r\n`;

/** One agentic turn: a request without a function response gets a `read` of
 *  the labelled file; the one carrying its result the closing text. */
function scripted(req: IncomingMessage, res: ServerResponse): void {
  let buf = "";
  req.setEncoding("utf8");
  req.on("data", (c) => (buf += c));
  req.on("end", () => {
    seen.push({ method: req.method ?? "", path: req.url ?? "", headers: req.headers, body: buf });
    if (req.method !== "POST") { res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); return; }
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.end(buf.includes('"functionResponse"')
      ? chunk([{ text: "MANDU_OC_VERTEX_DONE" }], "STOP")
      : chunk([{ functionCall: { name: "read", args: { path: readPath } } }], "STOP"));
  });
}

before(async () => {
  if (SKIP) return;
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-oc-vertex-")));
  mkdirSync(join(tmp, "work", "vault"), { recursive: true });
  readPath = join(tmp, "work", "vault", "api-notes.txt");
  writeFileSync(readPath, SECRET_BODY);
  writeFileSync(join(tmp, "policy.yaml"), `version: 1\npaths:\n  - path: ${join(tmp, "work", "vault")}\n    level: no-model\n`);
  const logFd = openSync(join(tmp, "arbiter.log"), "a");
  arbiter = spawn(process.execPath, sourceArbiterArgs(join(tmp, "arbiter.sock")), {
    cwd: ARBITER_DIR,
    env: { ...process.env, MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_HOME: join(tmp, "mandu-home"), MANDU_RUNTIME_DIR: join(tmp, "mandu"), MANDU_POLICY_FILE: join(tmp, "policy.yaml") },
    stdio: ["ignore", logFd, logFd], detached: true,
  });
  closeSync(logFd);
  await waitForPaths(join(tmp, "arbiter.sock"), { what: "the arbiter", child: arbiter, logPath: join(tmp, "arbiter.log") });
  upstream = createHttpServer(scripted);
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
  origin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  // The bypass recorder: OpenClaw's HTTPS_PROXY, refusing every tunnel.
  recorder = createHttpServer((req, res) => { connects.push(`${req.method} ${req.url}`); res.writeHead(403); res.end(); });
  recorder.on("connect", (req: IncomingMessage, sock: Socket) => { connects.push(`CONNECT ${req.url}`); sock.end("HTTP/1.1 403 Forbidden\r\n\r\n"); });
  await new Promise<void>((r) => recorder.listen(0, "127.0.0.1", () => r()));
  proxyUrl = `http://127.0.0.1:${(recorder.address() as AddressInfo).port}`;
});

after(async () => {
  upstream?.close();
  recorder?.close();
  if (arbiter) await stopGroup(arbiter);
  if (!tmp) return;
  rmSync(tmp, { recursive: true, force: true });
});

/** `declared`: the user declares the provider with its api and a model;
 *  `catalog`: only its address and key, the model from OpenClaw's own
 *  google-vertex catalog (whose entries name Google's host), so the route
 *  must win over the catalog's address too. */
type Shape = "declared" | "catalog";

async function launch(oc: { bin: string; version: string }, shape: Shape): Promise<{ code: number | null; out: string }> {
  const run = join(tmp, `run-${oc.version}-${shape}`);
  mkdirSync(join(run, "bin"), { recursive: true });
  mkdirSync(join(run, "state"), { recursive: true });
  mkdirSync(join(run, "mandu-launch"), { recursive: true, mode: 0o700 });
  // The launcher knows OpenClaw by its command name.
  symlinkSync(oc.bin, join(run, "bin", "openclaw"));
  // The user's own config: Vertex AI's Gemini on their own endpoint (here,
  // the scripted model), an express-mode key, the workspace.
  const config = join(run, "openclaw.json");
  writeFileSync(config, JSON.stringify({
    agents: { defaults: { model: { primary: `google-vertex/${MODEL}` }, workspace: join(tmp, "work") } },
    models: { providers: { "google-vertex": shape === "declared"
      ? {
        api: "google-vertex", baseUrl: origin, apiKey: "vertex-express-not-a-key",
        models: [{ id: MODEL, name: "Stand-in", input: ["text"], reasoning: false, contextWindow: 128000, maxTokens: 4096 }],
      }
      : { baseUrl: origin, apiKey: "vertex-express-not-a-key" } } },
  }));
  const env: Record<string, string | undefined> = {
    HOME: run, PATH: `${join(run, "bin")}${delimiter}${process.env["PATH"] ?? ""}`, PWD: join(tmp, "work"),
    MANDU_HOME: PRIVATE_MANDU_HOME, XDG_RUNTIME_DIR: run, MANDU_RUNTIME_DIR: join(run, "mandu-launch"),
    MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_PROXY_PORT: "0", MANDU_MODE: "secrets",
    MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0", MANDU_NO_MCP: "1",
    OPENCLAW_CONFIG_PATH: config, OPENCLAW_STATE_DIR: join(run, "state"), OPENCLAW_HOME: run,
    GOOGLE_CLOUD_PROJECT: "acme-vertex-test", GOOGLE_CLOUD_LOCATION: "us-central1",
    HTTPS_PROXY: proxyUrl, HTTP_PROXY: proxyUrl, https_proxy: proxyUrl, http_proxy: proxyUrl, NO_PROXY: "127.0.0.1,localhost", no_proxy: "127.0.0.1,localhost",
    NO_COLOR: "1", TERM: "dumb",
  };
  const child = spawn(process.execPath, [
    "--import", TSX_LOADER, join(LAUNCHER_ROOT, "src", "run.ts"),
    "--no-scope", "--no-mcp", "--", "openclaw", "agent", "--local", "--session-id", `vx-${oc.version}-${shape}`, "--message", "check the api key file",
  ], { cwd: join(tmp, "work"), env: env as NodeJS.ProcessEnv, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  child.stdout!.on("data", (d) => { out += String(d); });
  child.stderr!.on("data", (d) => { out += String(d); });
  const timer = setTimeout(() => child.kill("SIGKILL"), 240_000);
  const [code] = await once(child, "exit") as [number | null];
  clearTimeout(timer);
  return { code, out };
}

if (SKIP) test("openclaw-vertex-real", { skip: SKIP }, () => {});
for (const oc of OPENCLAWS) {
  if (routes(oc.version)) for (const shape of ["declared", "catalog"] as const) {
    test(`\`mandu openclaw agent\` on google-vertex (${shape} model), OpenClaw ${oc.version}: every request through the proxy on OpenClaw's own Vertex path, nothing around it, the labelled file's content reaches the model ONLY as a symbol`, { timeout: 300_000 }, async () => {
      seen.length = 0;
      connects.length = 0;
      const { code, out } = await launch(oc, shape);
      const posts = seen.filter((q) => q.method === "POST");
      if (code !== 0) console.error(`openclaw-vertex-real ${oc.version}: launch output:\n${out.slice(-3000)}`);
      assert.equal(code, 0, `openclaw under Mandu exited 0 (requests: ${seen.map((q) => `${q.method} ${q.path}`).join(", ")})`);
      assert.ok(posts.length >= 2, `the proxy forwarded OpenClaw's turns (${seen.map((q) => `${q.method} ${q.path}`).join(", ")})`);
      for (const q of posts) {
        assert.match(q.path.split("?")[0]!, VERTEX_PATH, "OpenClaw's own Vertex path, at the origin the user configured");
        assert.equal(q.headers["x-goog-api-key"], "vertex-express-not-a-key", "the user's key is relayed as sent");
        // BYPASS ORACLE: a request OpenClaw sent around the proxy would carry
        // Mandu's session header (the run config sets it) and no handling prompt.
        assert.equal(q.headers["x-mandu-session-id"], undefined, `SECURITY REGRESSION: a request reached the model without crossing the proxy (${q.path})`);
        assert.match(q.body, /\$MDU:/, `SECURITY REGRESSION: a request without the proxy's handling prompt (its symbol contract) reached the model (${q.path})`);
      }
      assert.deepEqual(connects.filter((c) => /google|aiplatform/i.test(c)), [], `SECURITY REGRESSION: OpenClaw ${oc.version} sent a request toward Google around the route: ${connects.join(", ")}`);
      const withResult = posts.filter((q) => q.body.includes('"functionResponse"'));
      assert.ok(withResult.length >= 1, `the read ran and its result came back through the proxy (launch output: ${out.slice(-1500)})`);
      assert.match(withResult.at(-1)!.body, SYMBOL_RE, "the result reached the model as a nomodel symbol (only the proxy mints one)");
      for (const q of seen) assert.ok(!q.body.includes(CANARY), `INVARIANT: no request carries the labelled secret (${q.path})`);
      assert.match(out, /MANDU_OC_VERTEX_DONE/, "the turn finished on the scripted model's answer");
    });
  } else {
    test(`\`mandu openclaw agent\` on google-vertex, OpenClaw ${oc.version}: refused before anything starts (this release sends Vertex AI calls to Google whatever the baseUrl); the model receives nothing`, { timeout: 120_000 }, async () => {
      seen.length = 0;
      const { code, out } = await launch(oc, "catalog");
      assert.notEqual(code, 0);
      assert.match(out, new RegExp(`refusing to launch openclaw with a google-vertex model: OpenClaw ${oc.version.replace(/\./g, "\\.")} sends Vertex AI calls to Google's own host whatever the provider's baseUrl`));
      assert.equal(seen.length, 0, "the model received nothing");
    });
  }
}
