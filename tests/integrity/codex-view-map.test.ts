/**
 * codex-view-map.test.ts — LIVE end-to-end proof of the fs prefix map (P4)
 * with a REAL `codex exec` process (fs-sync.md §1.3).
 *
 * FROZEN LANE (docs/design/architecture/protection-modes.md §10.5, §10.7; test-organization.md
 * §7.1, 2026-09-29): the integrity form of this suite, moved verbatim from
 * test/live/ when the agent-fake tier moved to `secrets`. It runs only when the
 * integrity axis is revived (`npm run test:integrity`). The default-lane
 * codex-view-map.test.ts proves the confidentiality form.
 *
 *     codex exec  ──►  real ArbiterServer + real OpenAiProxy (WITH a view map)  ──►  fake OpenAI Responses
 *
 * The fake upstream tells codex to run `cat <HumanView>/notes.md` — an ABSOLUTE
 * HumanView path. The proxy's P4 forward map rewrites that command in the SSE
 * before codex sees it, so the REAL codex process executes
 * `cat <AgentView>/notes.md` instead. The two dirs hold DISTINCT content, so the
 * bytes that flow back prove which file codex actually opened.
 *
 * Proven with the real client, both directions:
 *   forward  codex executes against the AgentView copy — arbiter.resolve() of the
 *            symbolized function_call_output returns the AGENTVIEW marker, never
 *            the HumanView one;
 *   reverse  the model (fake upstream) only ever sees HumanView paths — the
 *            echoed function_call command in codex's turn-2 request is
 *            reverse-mapped, and the AgentView prefix appears in NO forwarded body.
 *
 * No API key / no network. SKIPS when `codex` is not on PATH (run via
 * `npm run test:integrity` in tests/).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";
import type { Readable } from "node:stream";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { OpenAiProxy, type UpstreamFetcher } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { ViewMap } from "../../interceptors/openai-proxy/src/view-map.js";

import { startFakeResponses } from "../lib/fake-responses.js";
import { runChildToExit } from "../lib/child-run.js";
import { openaiBridge } from "../lib/live-shared.js";
import { installExitGuard } from "../lib/exit-guard.js";
import { humanSockIn } from "../lib/human-plane.js";

// Exit-guard backstop (tests/lib/exit-guard.ts): if a leaked handle still
// holds this runner's event loop after the tests complete, dump it to stderr
// and force-exit instead of hanging the suite forever.
installExitGuard("codex-view-map");


function httpForwarder(origin: string): UpstreamFetcher {
  const url = new URL(origin);
  return async ({ method, path, headers, body }) => {
    const http = await import("node:http");
    return new Promise((resolve, reject) => {
      const r = http.request(
        { protocol: url.protocol, hostname: url.hostname, port: url.port, method, path, headers: { ...headers, host: url.host } },
        (up) => resolve({ status: up.statusCode ?? 502, headers: up.headers, body: up as unknown as Readable }),
      );
      r.on("error", reject);
      r.end(body);
    });
  };
}

const CODEX_AVAILABLE = (() => {
  try {
    return spawnSync("codex", ["--version"], { encoding: "utf8", timeout: 15000 }).status === 0;
  } catch {
    return false;
  }
})();

const HUMAN_MARKER = "HUMANVIEW_ONLY_DO_NOT_READ_a1b2";
const AGENT_MARKER = "AGENTVIEW_COPY_MARKER_9x2y";

test(
  "LIVE: real `codex exec` — a HumanView path in the model's command is forward-mapped; codex reads the AgentView copy",
  { skip: CODEX_AVAILABLE ? false : "`codex` binary not on PATH — run where Codex CLI is installed", timeout: 180_000 },
  async () => {
    const tmp = mkdtempSync(join(tmpdir(), "mandu-codex-map-"));
    // Two sibling trees with DISTINCT content — same relative file.
    const humanDir = join(tmp, "human-repo");
    const agentDir = join(tmp, "agent-view");
    mkdirSync(humanDir, { recursive: true });
    mkdirSync(agentDir, { recursive: true });
    const humanNotes = join(humanDir, "notes.md");
    const agentNotes = join(agentDir, "notes.md");
    writeFileSync(humanNotes, `# Human\n${HUMAN_MARKER}\n`);
    writeFileSync(agentNotes, `# Agent\n${AGENT_MARKER}\n`);

    const socketPath = join(tmp, "arbiter.sock");
    const codexHome = mkdtempSync(join(homedir(), ".mandu-codex-map-"));

    const arbiter = new ArbiterServer({
      socketPath, humanSocketPath: humanSockIn(tmp), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
      // This suite STATES its axes (protection-modes.md §4): the invariant it
      // proves is the integrity axis's, never the built-in default's.
      integrity: true, confidentiality: false,
    });
    await arbiter.listen();
    const proxyClient = new ArbiterClient(socketPath);
    await proxyClient.connect();
    const readClient = new ArbiterClient(humanSockIn(tmp)); // reads of originals: the human plane
    await readClient.connect();

    // The model "decides" to read the HumanView ABSOLUTE path.
    const fake = await startFakeResponses({ readFilePath: humanNotes, promptMarker: "MDU_MAP_MARKER" });
    const proxy = new OpenAiProxy({
      arbiter: new OpenAiProxyArbiterAdapter(openaiBridge(proxyClient)),
      upstream: httpForwarder(fake.origin),
      viewMap: new ViewMap([{ human: humanDir, agent: agentDir }], { dialect: "posix" }),
      log: () => {},
    });
    const proxyPort = await proxy.listen(0);

    try {
      const baseUrl = `http://127.0.0.1:${proxyPort}/v1`;
      // runChildToExit SIGKILLs the whole process group and rejects on timeout.
      const { code, stderr } = await runChildToExit(
        "codex",
        [
          "exec", "--dangerously-bypass-approvals-and-sandbox", "--skip-git-repo-check",
          "--ephemeral", "--ignore-user-config",
          "-c", "model_provider=fake",
          "-c", `model_providers.fake={name="fake",base_url="${baseUrl}",wire_api="responses",env_key="OPENAI_API_KEY"}`,
          "-c", "model=gpt-4o",
          "-C", humanDir,
          "MDU_MAP_MARKER Read notes.md with your shell tool and reply with its content.",
        ],
        { cwd: humanDir, env: { HOME: process.env["HOME"] ?? tmp, PATH: process.env["PATH"] ?? "", CODEX_HOME: codexHome, OPENAI_API_KEY: "dummy" }, timeoutMs: 160_000, label: "codex" },
      );
      assert.equal(code, 0, `codex exited 0 (stderr=${JSON.stringify(stderr.slice(0, 600))})`);

      const fcoReqs = fake.functionCallOutputRequests();
      assert.ok(fcoReqs.length > 0, "codex ran exec_command and returned a function_call_output");

      // ── FORWARD MAP (the live proof): codex executed `cat <AgentView>/notes.md`,
      //    NOT the HumanView path the model named. The proxy symbolized codex's
      //    command output; the arbiter holds the original bytes behind the symbol —
      //    they are the AGENTVIEW copy, never the HumanView one. ──
      const symFromOutput = (body: string): string | undefined => {
        const req = JSON.parse(body) as { input?: Array<{ type?: string; output?: unknown }> };
        for (const item of req.input ?? []) {
          if (item.type === "function_call_output" && typeof item.output === "string") {
            const m = item.output.match(/\$MDU:[A-Za-z0-9_]+\[[0-9a-f]+\](?:\.[A-Za-z0-9_]+)?/);
            if (m) return m[0];
          }
        }
        return undefined;
      };
      let sym: string | undefined;
      for (const r of fcoReqs) { sym = symFromOutput(r.body); if (sym) break; }
      assert.ok(sym, "codex's command output was symbolized");
      const resolved = await readClient.resolve(sym!);
      assert.ok(resolved !== null, "arbiter holds the original bytes behind the symbol");
      assert.ok(resolved!.includes(AGENT_MARKER), `codex read the AgentView copy (forward map). resolved=${JSON.stringify(resolved!.slice(0, 200))}`);
      assert.ok(!resolved!.includes(HUMAN_MARKER), "codex did NOT read the HumanView file");

      // ── REVERSE MAP: the model (fake upstream) only ever sees HumanView paths.
      //    The echoed function_call command in codex's turn-2 request is
      //    reverse-mapped; the AgentView prefix appears in NO forwarded body. ──
      const turn2 = fcoReqs[0]!.body;
      assert.ok(turn2.includes(humanNotes), "the echoed command is reverse-mapped to the HumanView path");
      for (const r of fake.requests) {
        assert.ok(!r.body.includes(agentDir), `AgentView prefix must never reach the model (url=${r.url})`);
      }
    } finally {
      await proxy.close();
      proxyClient.close();
      readClient.close();
      await fake.close();
      await arbiter.close();
      rmSync(tmp, { recursive: true, force: true });
      rmSync(codexHome, { recursive: true, force: true });
    }
  },
);
