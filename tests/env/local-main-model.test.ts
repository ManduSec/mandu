/**
 * local-main-model.test.ts — plan 11 phase 3 LIVE: the agent's MAIN
 * model (T-LLM) is the user's own model
 * (docs/design/confidentiality/model-endpoints.md §1.7, §1.7.1).
 *
 * `models:` declares the Ollama on THIS host with `wire: anthropic` and
 * `local: true`, and the REAL launcher (`launcher/src/run.ts`, what `mandu`
 * runs) wraps the REAL `claude -p` with `ANTHROPIC_BASE_URL` set to exactly
 * that entry's url, as usage.md tells a user to. Ollama serves the Anthropic
 * Messages API from 0.14 on (this host ran 0.9.6, which has no
 * `/v1/messages`, until 2026-09-28). A file labeled `local-model` sits in
 * the workspace and the agent is asked to summarize it. Asserted:
 *
 *   HARD
 *   1. the launch binds the session's upstream to the declared entry, at a
 *      LOCAL location (the arbiter's `sessionUpstream`, §7.1);
 *   2. the model proxy stays in front of the local model: every main-model
 *      request on the local wire carries the proxy's handling prompt
 *      (`[mandu:handling-prompt]`), so masking stayed on;
 *   3. nothing reaches the vendor: `MANDU_UPSTREAM` points at a TRAP relay
 *      (the declared entry must override it) and the default helper's
 *      forwarder at another; the file's canary is on neither, and the trap
 *      sees no request at all;
 *   4. the Claude Code subscription token never leaves for the local model:
 *      the launch carries a dummy ANTHROPIC_API_KEY, and no request on any
 *      wire carries the subscription's bearer;
 *   5. the launcher exits 0.
 *   SOFT (llama3.2 under Claude Code's long system prompt is noisy)
 *   6. the reply names a fact of the file.
 *
 * GATED (no vendor budget: every model call is the local Ollama):
 *   MANDU_LIVE_LOCAL_MAIN_MODEL=1 npm run test:env:local-main-model   # in tests/
 * Self-SKIPs (with the reason) unless: the gate is set, Linux, `claude` on
 * PATH, the launcher's deps are installed, and the Ollama answers
 * POST /v1/messages with the model loaded (the probe also warms it).
 *
 * Knobs:
 *   MANDU_LIVE_LOCAL_MODEL_URL    Ollama origin      (default http://127.0.0.1:11434)
 *   MANDU_LIVE_LOCAL_MODEL_NAME   the declared model (default llama3.2)
 *   MANDU_LIVE_LOCAL_MODEL_KEEP=1 keep the artifacts on a green run too
 *
 * Mandu-new (no reference origin). Plumbing shared with local-model.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { LAUNCHER_MAIN, LAUNCHER_TSX, git } from "../lib/launcher-live.js";
import { runChildToExit } from "../lib/child-run.js";
import { startRecordingRelay, wireText } from "../lib/recording-relay.js";
import { axesEnv, stateAxes } from "../lib/axes.js";
import { installExitGuard } from "../lib/exit-guard.js";

installExitGuard("local-main-model", { graceMs: 5_000 });

const OLLAMA = (process.env["MANDU_LIVE_LOCAL_MODEL_URL"] ?? "http://127.0.0.1:11434").replace(/\/$/, "");
const MODEL = process.env["MANDU_LIVE_LOCAL_MODEL_NAME"] ?? "llama3.2";
const ENDPOINT_NAME = "drill-local-main";
const VENDOR = "https://api.anthropic.com";
const HANDLING_MARKER = "[mandu:handling-prompt]"; // anthropic-proxy rewrite-request.ts
const DUMMY_KEY = "sk-ollama-local-dummy";

// The product default: confidentiality ON, integrity OFF. local-model is a
// confidentiality level.
stateAxes("secrets");

async function probe(): Promise<string | false> {
  try {
    const r = await fetch(`${OLLAMA}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "anthropic-version": "2023-06-01", "x-api-key": DUMMY_KEY },
      body: JSON.stringify({ model: MODEL, max_tokens: 8, messages: [{ role: "user", content: "Reply with the word ready." }] }),
      signal: AbortSignal.timeout(180_000),
    });
    if (r.status === 404) return `the Ollama at ${OLLAMA} has no /v1/messages (Ollama 0.14 or newer serves it; \`ollama --version\`)`;
    if (!r.ok) return `the Ollama at ${OLLAMA} answered ${r.status} on /v1/messages (is ${MODEL} pulled?)`;
    const j = (await r.json()) as { content?: unknown };
    if (!Array.isArray(j.content)) return `the Ollama at ${OLLAMA} returned no Messages content`;
  } catch (e) {
    return `no Ollama answers /v1/messages at ${OLLAMA} (${e instanceof Error ? e.message : String(e)})`;
  }
  return false;
}

async function gate(): Promise<string | false> {
  if (process.env["MANDU_LIVE_LOCAL_MAIN_MODEL"] !== "1") {
    return "set MANDU_LIVE_LOCAL_MAIN_MODEL=1 to run: drives the real launcher + claude with the Ollama on this host as the main model";
  }
  if (process.platform !== "linux") return "Linux only (the launcher's confinement)";
  if (spawnSync("claude", ["--version"], { encoding: "utf8", timeout: 15_000 }).status !== 0) return "`claude` not on PATH";
  if (!existsSync(LAUNCHER_TSX)) return `launcher deps not installed (${LAUNCHER_TSX}); run \`npm install\` in launcher/`;
  return probe();
}

const SKIP: string | false = await gate();

/** The subscription's OAuth access token, when one is on disk: it must never
 *  appear on any wire of this drill (the launch uses a dummy key instead). */
function subscriptionToken(): string | null {
  const dir = process.env["CLAUDE_CONFIG_DIR"] || join(homedir(), ".claude");
  try {
    const j = JSON.parse(readFileSync(join(dir, ".credentials.json"), "utf8")) as { claudeAiOauth?: { accessToken?: unknown } };
    const t = j.claudeAiOauth?.accessToken;
    return typeof t === "string" && t.length > 16 ? t : null;
  } catch {
    return null;
  }
}

test(
  "local-main-model-e2e[main-model]: LIVE plan 11 phase 3: the main model is the declared local Ollama; the proxy stays in front and nothing reaches the vendor",
  { skip: SKIP, timeout: 900_000 },
  async () => {
    const canary = `LMMAIN_${randomBytes(8).toString("hex")}`;
    const runRoot = realpathSync(mkdtempSync(join(tmpdir(), "mandu-lmm-")));
    mkdirSync(join(homedir(), ".cache"), { recursive: true });
    const docRoot = realpathSync(mkdtempSync(join(homedir(), ".cache", "mandu-live-local-main-")));
    const workspace = join(docRoot, "workspace");
    const docPath = join(workspace, "notes", "plan.md");
    mkdirSync(join(workspace, "notes"), { recursive: true });
    writeFileSync(join(workspace, "README.md"), "# scratch workspace\n");
    writeFileSync(docPath, [
      `PRIVATE PLANNING NOTE (ref ${canary})`,
      "",
      "The team offsite is in Gyeongju on 12 December 2026. Budget: 3.2 million KRW.",
      "",
    ].join("\n"));
    git(workspace, ["init", "-q"]);
    git(workspace, ["add", "-A"]);
    git(workspace, ["commit", "-qm", "seed"]);

    const local = await startRecordingRelay(OLLAMA);
    const trapT = await startRecordingRelay(VENDOR); // MANDU_UPSTREAM: must see nothing
    const vendorU = await startRecordingRelay(VENDOR);
    const relays = [local, trapT, vendorU];

    const policyPath = join(runRoot, "policy.yaml");
    writeFileSync(policyPath, [
      "version: 1",
      "paths:",
      `  - path: ${JSON.stringify(docPath)}`,
      "    level: local-model",
      "    recursive: false",
      "models:",
      `  - name: ${ENDPOINT_NAME}`,
      `    url: ${local.url}`,
      "    wire: anthropic",
      `    model: ${JSON.stringify(MODEL)}`,
      "    local: true",
      "",
    ].join("\n"));

    const sock = join(runRoot, "arbiter.sock");
    const arbiter = new ArbiterServer({
      socketPath: sock, dbPath: join(runRoot, "symbols.sqlite"), eventDir: join(runRoot, "events"), log: () => {},
      integrity: false, confidentiality: true, policyPath, policyPollMs: 0, tenant: "test",
    });
    await arbiter.listen();
    const client = new ArbiterClient(sock);
    // `<class>-<scenario>-<ms>`: the dashboard badges it LMM1 (registry.ts).
    const scopeId = `local-main-model-e2e-main-model-${Date.now()}`;
    let out = { code: -1, stdout: "", stderr: "" };
    let upstream: unknown = null;
    let passed = false;
    try {
      await client.connect();
      assert.ok((await client.modelEndpoints()).some((e) => e.name === ENDPOINT_NAME && e.local), "the law is in force before launch");
      const env: Record<string, string | undefined> = {
        HOME: homedir(),
        PATH: process.env["PATH"],
        USER: process.env["USER"],
        LOGNAME: process.env["LOGNAME"],
        LANG: process.env["LANG"] ?? "C.UTF-8",
        SHELL: process.env["SHELL"],
        TERM: "dumb",
        PWD: workspace,
        XDG_RUNTIME_DIR: runRoot,
        // Its own Mandu home (no config.toml; the view state is its state/),
        // under HOME where the exec box's /tmp tmpfs does not hide it.
        MANDU_HOME: join(docRoot, "mandu-home"),
        MANDU_POLICY_FILE: policyPath,
        MANDU_ARBITER_SOCK: sock,
        MANDU_NO_ARBITER_AUTOSTART: "1",
        MANDU_PROXY_PORT: "0",
        MANDU_NET_PROXY_PORT: "0",
        MANDU_OPENAI_PROXY_PORT: "0",
        MANDU_VERBOSE: "1",
        MANDU_TENANT: "test",
        MANDU_UPSTREAM: trapT.url,          // the declared entry must win over this
        MANDU_ULLM_BASE_URL: vendorU.url,   // the default helper, if anything asks it
        // The user's step (usage.md "Your own model as the AI's main model"):
        ANTHROPIC_BASE_URL: local.url,
        ANTHROPIC_API_KEY: DUMMY_KEY,       // never the subscription's token
        ANTHROPIC_DEFAULT_HAIKU_MODEL: MODEL, // Claude Code's side calls stay on the local model
        ...axesEnv("secrets"),
      };
      const argv = [
        // --best-effort: this drill is about the main model's route, and a
        // developer HOME can hold a protected file whose git history is over
        // the sanitize cap, which refuses the launch before any model call
        // (secret-setup.ts). The refusal is covered by its own suites.
        LAUNCHER_MAIN, "--no-scope", "--id", scopeId, "--mode", "secrets", "--verbose", "--best-effort", "--",
        "claude", "-p", "Read notes/plan.md and tell me in one sentence where and when the offsite is.",
        "--model", MODEL,
        "--output-format", "text",
        "--permission-mode", "acceptEdits",
        "--setting-sources", "project,local",
        "--allowedTools", "Read,mcp__mandu-inspect__inspect_symbol,mcp__mandu-inspect__declassify_symbol",
        "--session-id", randomUUID(),
      ];
      out = await runChildToExit(LAUNCHER_TSX, argv, { cwd: workspace, env, timeoutMs: 600_000, label: "launcher" });
      await Promise.all(relays.map((r) => r.settle()));
      upstream = await client.sessionUpstream(scopeId);

      const messages = local.records.filter((r) => r.method === "POST" && /\/v1\/messages(\?|$)/.test(r.path));
      const report = {
        exit: out.code, upstream,
        local: local.records.map((r) => `${r.method} ${r.path} ${r.status}`),
        trap: trapT.records.length, vendorU: vendorU.records.length,
        marked: messages.filter((r) => r.reqBody.includes(HANDLING_MARKER)).length,
        reply: out.stdout.trim().slice(0, 800),
      };
      console.error(`local-main-model drill: ${JSON.stringify(report, null, 2)}`);

      assert.equal(out.code, 0, `the launcher exits 0\n${out.stderr.split("\n").slice(-40).join("\n")}`);
      const bound = upstream as { endpoint: string | null; location: string };
      assert.deepEqual([bound.endpoint, bound.location], [ENDPOINT_NAME, "local"], "the session is bound to the declared local entry");
      assert.ok(messages.length > 0, "the main model's requests reached the local wire");
      for (const r of messages) {
        assert.ok(r.reqBody.includes(HANDLING_MARKER), `every main-model request passed the model proxy (${r.path})`);
      }
      assert.equal(trapT.records.length, 0, "MANDU_UPSTREAM (the vendor) saw no request: the declared entry won");
      assert.ok(!wireText(vendorU.records).includes(canary), "the default helper's vendor wire never carried the file");
      const token = subscriptionToken();
      if (token !== null) {
        for (const r of relays) assert.ok(!JSON.stringify(r.records).includes(token), "the subscription token is on no wire");
      }
      if (!/Gyeongju|12 December|December 12/i.test(out.stdout)) {
        console.error("local-main-model drill: SOFT: the reply names no fact of the file (llama3.2 under Claude Code's system prompt is noisy)");
      }
      passed = true;
    } finally {
      client.close();
      await arbiter.close();
      for (const r of relays) await r.close();
      if (!passed || process.env["MANDU_LIVE_LOCAL_MODEL_KEEP"] === "1") {
        const art = join(runRoot, "drill-artifacts");
        mkdirSync(art, { recursive: true });
        writeFileSync(join(art, "wire-local.json"), JSON.stringify(local.records, null, 2));
        writeFileSync(join(art, "wire-trap.json"), JSON.stringify(trapT.records, null, 2));
        writeFileSync(join(art, "launcher.stdout"), out.stdout);
        writeFileSync(join(art, "launcher.stderr"), out.stderr);
        console.error(`local-main-model drill: artifacts kept at ${art} (workspace ${docRoot})`);
      } else {
        rmSync(runRoot, { recursive: true, force: true });
        rmSync(docRoot, { recursive: true, force: true });
      }
    }
  },
);
