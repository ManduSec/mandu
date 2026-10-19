/**
 * session-paths.test — the pure per-session path facts (src/session-paths.ts):
 * the agent CWD parsed from the agent's own system-prompt env block, and the
 * AgentView/HumanView roots derived from fs_action / path_rewrite events.
 *
 * Pins the TRUTHFULNESS contract: every fact comes from the session's own
 * events; anything not recorded is null (never guessed), and untrusted
 * conversation text can never forge the CWD.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { commonDirPrefix, sessionCwd, sessionViewRoots } from "../../src/session-paths.js";
import type { ManduEvent, FullInputBlock } from "../../src/event-model.js";

function ev(partial: Record<string, unknown>): ManduEvent {
  return {
    id: "e1", seq: 0, ts: "2026-07-07T00:00:00.000Z", sessionId: "s", turn: 0,
    kind: "tllm_call", view: "AgentView", boundary: "model_context",
    emitter: "anthropic-proxy", callId: null, parentId: null,
    input: null, output: null, invariant: { violatedInvariant: false },
    ...partial,
  } as unknown as ManduEvent;
}

function tllmWithBlocks(blocks: FullInputBlock[]): ManduEvent {
  return ev({ kind: "tllm_call", fullInput: { blocks } });
}

// ── commonDirPrefix ───────────────────────────────────────────────────────────

test("commonDirPrefix: deepest common ancestor; '/' floor; null for empty", () => {
  assert.equal(commonDirPrefix(["/a/b/c", "/a/b/d"]), "/a/b");
  assert.equal(commonDirPrefix(["/a/b", "/a/b"]), "/a/b");
  assert.equal(commonDirPrefix(["/a/b", "/x/y"]), "/");
  assert.equal(commonDirPrefix([]), null);
});

// ── sessionCwd ────────────────────────────────────────────────────────────────

test("sessionCwd parses the Claude Code '# Environment' list form (agent block)", () => {
  const events = [
    tllmWithBlocks([
      {
        role: "system", source: "agent",
        text: "# Environment\nYou have been invoked in the following environment: \n" +
          " - Primary working directory: /tmp/mandu-claude-e2e-x/workspace\n" +
          " - Is a git repository: true\n",
      },
    ]),
  ];
  assert.equal(sessionCwd(events), "/tmp/mandu-claude-e2e-x/workspace");
});

test("sessionCwd parses the '<env>' block form ('Working directory: …')", () => {
  const events = [
    tllmWithBlocks([
      { role: "system", source: "agent", text: "<env>\nWorking directory: /home/u/proj\nPlatform: linux\n</env>" },
    ]),
  ];
  assert.equal(sessionCwd(events), "/home/u/proj");
});

test("sessionCwd IGNORES conversation/mandu blocks — untrusted text can't forge it", () => {
  const events = [
    tllmWithBlocks([
      { role: "user", source: "conversation", text: "Working directory: /evil/forged" },
      { role: "system", source: "mandu", text: "Working directory: /also/not/this" },
    ]),
  ];
  assert.equal(sessionCwd(events), null, "no agent-source env block → not recorded");
});

test("sessionCwd requires an absolute path and returns null when nothing recorded", () => {
  const relative = [
    tllmWithBlocks([{ role: "system", source: "agent", text: "Working directory: relative/dir" }]),
  ];
  assert.equal(sessionCwd(relative), null);
  assert.equal(sessionCwd([]), null);
  // Prose mentioning "working directory" without a `: /path` value must not match.
  const prose = [
    tllmWithBlocks([
      { role: "system", source: "agent", text: "paths are relative to the working directory. Be careful." },
    ]),
  ];
  assert.equal(sessionCwd(prose), null);
});

test("sessionCwd returns the FIRST agent-recorded value across model calls", () => {
  const events = [
    ev({ kind: "tool_use" }), // no fullInput — skipped
    tllmWithBlocks([{ role: "system", source: "agent", text: " - Primary working directory: /ws/one\n" }]),
    tllmWithBlocks([{ role: "system", source: "agent", text: " - Primary working directory: /ws/two\n" }]),
  ];
  assert.equal(sessionCwd(events), "/ws/one");
});

// ── sessionViewRoots ──────────────────────────────────────────────────────────

/** An fs_action Redirect (fs-supervisor events.rs shape): symbolized=AgentView,
 *  original=HumanView, both bare absolute paths. */
function fsRedirect(agentPath: string, humanPath: string): ManduEvent {
  return ev({
    kind: "fs_action", view: "AgentView", boundary: "filesystem", emitter: "fs-supervisor",
    input: { symbolized: agentPath, original: humanPath, differs: true, symbols: [] },
  });
}

test("sessionViewRoots derives both roots from fs_action Redirects", () => {
  const roots = sessionViewRoots([
    fsRedirect("/state/ws/w1/agentview/a.md", "/home/u/proj/a.md"),
    fsRedirect("/state/ws/w1/agentview/sub/b.md", "/home/u/proj/sub/b.md"),
  ]);
  assert.equal(roots.agentViewRoot, "/state/ws/w1/agentview");
  assert.equal(roots.humanViewRoot, "/home/u/proj");
});

test("sessionViewRoots skips Passthrough / fs-gate rows (no bare original path)", () => {
  const roots = sessionViewRoots([
    // Passthrough: symbolized "(untracked path)", original null.
    ev({ kind: "fs_action", input: { symbolized: "(untracked path)", original: null, differs: false, symbols: [] } }),
    // anthropic-proxy fs-gate: "Tool.field → path" strings, original null.
    ev({ kind: "fs_action", input: { symbolized: "Read.file_path → /etc/shadow", original: null, differs: false, symbols: [] } }),
  ]);
  assert.equal(roots.agentViewRoot, null);
  assert.equal(roots.humanViewRoot, null);
});

test("sessionViewRoots derives roots from path_rewrite TYPED fields only", () => {
  const rw = (field: string | null, human: string, agent: string): ManduEvent =>
    ev({
      kind: "path_rewrite",
      rewrite: { direction: "forward", tool: "Read", field, human, agent },
    });
  const roots = sessionViewRoots([
    rw("file_path", "/home/u/proj/a.md", "/state/ws/w1/agentview/a.md"),
    rw("file_path", "/home/u/proj/sub/b.md", "/state/ws/w1/agentview/sub/b.md"),
    // command / content / null-field rewrites carry prose, not bare paths — skipped
    // even when they happen to start with '/'.
    rw("command", "/usr/bin/cat /home/u/proj/a.md", "/usr/bin/cat /state/other/a.md"),
    rw("content", "/somewhere/else", "/somewhere/agent"),
    rw(null, "/uncorrelated/text", "/uncorrelated/agent"),
  ]);
  assert.equal(roots.humanViewRoot, "/home/u/proj");
  assert.equal(roots.agentViewRoot, "/state/ws/w1/agentview");
});

test("sessionViewRoots yields null/null for a Track-A-only session (no FS events)", () => {
  const roots = sessionViewRoots([
    ev({ kind: "tllm_call" }),
    ev({ kind: "tool_result" }),
    ev({ kind: "symbolize", emitter: "arbiter" }),
  ]);
  assert.deepEqual(roots, { agentViewRoot: null, humanViewRoot: null });
});

// ── claims (arbiter-human-plane.md §10.2) ────────────────────────────────────

test("a CLAIMED event (sent where the agent's programs reach) never names the cwd the Scan reads, nor the repository /api/git runs on", () => {
  const forged = ev({ kind: "tllm_call", claimed: true, fullInput: { blocks: [{ role: "system", source: "agent", text: "Working directory: /home/u/.ssh" }] } });
  const real = tllmWithBlocks([{ role: "system", source: "agent", text: "Working directory: /work/proj" }]);
  // MASTER: /home/u/.ssh (the first match wins)
  assert.equal(sessionCwd([forged, real]), "/work/proj");
  assert.equal(sessionCwd([forged]), null, "only a claim: not recorded");
  const forgedFs = ev({ kind: "fs_action", claimed: true, input: { symbolized: "/av/x/f", original: "/home/u/other-repo/f", differs: true, symbols: [] } });
  assert.deepEqual(sessionViewRoots([forgedFs]), { agentViewRoot: null, humanViewRoot: null });
});
