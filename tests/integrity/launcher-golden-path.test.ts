/**
 * launcher-golden-path.test.ts — the TRUE golden path: the real `mandu`
 * launcher (tsx run.ts) wraps the real `claude -p` on Linux; the launcher
 * autostarts the real anthropic-proxy and seeds the AgentView worktree; the
 * model endpoint is the scripted fake-anthropic (no key, no network).
 *
 * FROZEN LANE (docs/design/architecture/protection-modes.md §10.5, §10.7; test-organization.md
 * §7.1, 2026-09-29): the integrity form of this suite, moved verbatim from
 * test/live/ when the agent-fake tier moved to `secrets`. It runs only when the
 * integrity axis is revived (`npm run test:integrity`). The default-lane
 * launcher-golden-path.test.ts proves the confidentiality form;
 * scenario B (the AgentView fs chokepoint) has no `secrets` counterpart, since
 * the fs rung is off by mode there.
 *
 * Scenario A (context backstop): claude Reads a poisoned ABSOLUTE path OUTSIDE
 *   the workspace → raw bytes enter the tool_result → the PROXY symbolizes.
 * Scenario B (fs chokepoint): claude Reads the workspace's poisoned notes.md
 *   inside the AgentView → the on-disk content is ALREADY a symbol.
 * Both assert the §9 predicate: no raw payload in ANY forwarded model request.
 *
 * HTTPS upstream: the autostarted anthropic-proxy (server-main.ts, spawned via
 * `npm run serve` by launcher/src/services/context-proxy.ts) defaults its
 * UpstreamFetcher to a real `node:https` client UNCONDITIONALLY (src/proxy.ts
 * `makeHttpsFetcher`) — an `http://` MANDU_UPSTREAM makes it throw Node's
 * "Protocol 'http:' not supported. Expected 'https:'" and the proxy replies 502
 * (see launcher/test/component/golden-path.test.ts's file header, commit daa8676, for
 * the same constraint against the deterministic fake agent). fake-anthropic.ts
 * (this package's shared live-test helper) serves plain HTTP, so it is fronted
 * here by a throwaway self-signed-cert HTTPS shim that just forwards bytes; the
 * launcher env carries NODE_TLS_REJECT_UNAUTHORIZED=0 so the proxy child (which
 * inherits the launcher's env via context-proxy.ts's `...process.env` spread)
 * trusts our cert.
 *
 * `--no-mcp` is passed to the launcher: workspace-trust for a project .mcp.json
 * is skipped in `-p`/non-TTY mode (claude --help), so it would not hang, but
 * these two scenarios only exercise the fs + context chokepoints — the U-LLM/
 * inspect-mcp path is out of scope here (covered by tests/stack/), so
 * we keep the run narrow rather than depend on incidental MCP behavior.
 *
 * GATED: skips when `claude` is not on PATH. Zero real API budget.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { ViewLayout } from "../../fs-sync/src/layout.js";
import { startFakeAnthropic } from "../lib/fake-anthropic.js";
import { CLAUDE_AVAILABLE } from "../lib/live-shared.js";
import { INJECTION, withStack, startHttpsShim, runLauncher } from "../lib/launcher-live.js";
import { installExitGuard } from "../lib/exit-guard.js";

// Exit-guard backstop (tests/lib/exit-guard.ts): if a leaked handle still
// holds this runner's event loop after the tests complete, dump it to stderr
// and force-exit instead of hanging the suite forever.
installExitGuard("launcher-golden-path");

const CLAUDE_ARGS = ["--model", "claude-haiku-4-5", "--output-format", "text", "--permission-mode", "bypassPermissions"];

test(
  "LIVE golden path A: launcher-wrapped claude reads a poisoned OUTSIDE file — context proxy backstops",
  { skip: CLAUDE_AVAILABLE ? false : "`claude` binary not on PATH", timeout: 120_000 },
  async () => {
    await withStack(async ({ tmp, workspace, viewState, launcherEnv }) => {
      const outside = join(tmp, "outside-notes.md");
      writeFileSync(outside, `# Outside notes\n${INJECTION}\n`);
      const fake = await startFakeAnthropic({ readFilePath: outside, promptMarker: "MDU_GP_A" });
      const shim = await startHttpsShim(fake.origin, tmp);
      const proxyPort = 0; // port 0: the launcher adopts the proxy's published port (test-organization.md §8.4)

      try {
        const r = await runLauncher(
          ["--no-scope", "--no-mcp", "--", "claude", "-p", `MDU_GP_A Read the file ${outside} and reply with its first heading.`, ...CLAUDE_ARGS],
          launcherEnv(shim.origin, proxyPort), workspace,
        );
        assert.equal(r.code, 0, `launcher+claude exited 0; output:\n${r.out.slice(0, 800)}`);
        // Relies on fake-anthropic's SINGLE-SHOT tool_use scripting: a claude
        // retry of the tool-issuing turn would fall through to the ACK branch
        // and never produce a tool_result — known, accepted.
        assert.ok(fake.toolResultRequests().length > 0, "claude executed Read and returned a tool_result");
        for (const req of fake.requests) {
          assert.ok(!req.body.includes(INJECTION), "INVARIANT: raw payload reached the model");
          assert.ok(!req.body.includes("IGNORE ALL PREVIOUS INSTRUCTIONS"), "no raw fragment reached the model");
          assert.ok(!req.body.includes("~/.ssh/id_rsa"), "no exfil-path fragment reached the model");
        }
        assert.ok(fake.toolResultRequests().some((q) => /\$MDU:/.test(q.body)),
          "the poisoned tool_result was forwarded as a symbol");
      } finally {
        await shim.close();
        await fake.close();
      }
    });
  },
);

test(
  "LIVE golden path B: launcher-wrapped claude reads the workspace file INSIDE the AgentView — fs chokepoint symbolizes on disk",
  { skip: CLAUDE_AVAILABLE ? false : "`claude` binary not on PATH", timeout: 120_000 },
  async () => {
    await withStack(async ({ tmp, workspace, viewState, launcherEnv }) => {
      const layout = new ViewLayout(workspace, viewState);
      const agentNotes = join(layout.agentViewPath, "notes.md");
      // fake-anthropic never reads readFilePath itself (it only scripts a
      // tool_use whose `input.file_path` is this string) — it's fine that the
      // AgentView worktree doesn't exist yet; the launcher seeds it below.
      const fake = await startFakeAnthropic({ readFilePath: agentNotes, promptMarker: "MDU_GP_B" });
      const shim = await startHttpsShim(fake.origin, tmp);
      const proxyPort = 0; // port 0: the launcher adopts the proxy's published port (test-organization.md §8.4)

      try {
        const r = await runLauncher(
          ["--no-scope", "--no-mcp", "--", "claude", "-p", `MDU_GP_B Read the file ${agentNotes} and reply with its first heading.`, ...CLAUDE_ARGS],
          launcherEnv(shim.origin, proxyPort), workspace,
        );
        assert.equal(r.code, 0, `launcher+claude exited 0; output:\n${r.out.slice(0, 800)}`);

        // fs chokepoint: the AgentView twin was symbolized ON DISK before claude read it.
        const onDisk = readFileSync(agentNotes, "utf8");
        assert.ok(onDisk.includes("$MDU:"), "AgentView notes.md holds a symbol");
        assert.ok(!onDisk.includes(INJECTION), "AgentView notes.md holds no raw payload");
        // HumanView remains raw for the human.
        assert.ok(readFileSync(join(workspace, "notes.md"), "utf8").includes(INJECTION));
        // Positive oracle first — without it the wire check below is vacuously
        // true when claude never issues a tool_result at all.
        assert.ok(fake.toolResultRequests().length > 0, "claude executed Read and returned a tool_result");
        assert.ok(fake.toolResultRequests().some((q) => /\$MDU:/.test(q.body)),
          "the AgentView symbol flowed to the model");
        // §9 predicate over the wire.
        for (const req of fake.requests) {
          assert.ok(!req.body.includes(INJECTION), "INVARIANT: raw payload reached the model");
        }
      } finally {
        await shim.close();
        await fake.close();
      }
    });
  },
);
