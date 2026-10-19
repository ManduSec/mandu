/**
 * agent-kind.test.ts — the per-session agent-CLI derivation (event-source.ts
 * deriveAgentKind) and its exposure as SessionRef.agent by FileEventSource.
 *
 * Mandu dashboard. A session's Track A emitter identifies which agent CLI
 * drove it: `anthropic-proxy` = Claude Code, `openai-proxy` = Codex CLI. The
 * sidebar badges every row with it (app.js agentBadge); OS-interceptor-only
 * traces yield undefined so the badge never guesses.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";

import { FileEventSource, deriveAgentKind, deriveBatchMember, deriveBrowserAgent, deriveRuntime } from "../../src/event-source.js";
import { coerceEvent, type ManduEvent } from "../../src/event-model.js";
import { tmpDir } from "./tmp-dir.js";

let n = 0;
function raw(sessionId: string, kind: string, emitter?: string): Record<string, unknown> {
  return {
    id: `e-${n++}`, sessionId, turn: 0, ts: "2026-07-08T10:00:00.000Z", seq: n,
    callId: null, parentId: null, kind, view: "AgentView",
    boundary: "model_context", input: null, output: null,
    invariant: { violatedInvariant: false }, ...(emitter ? { emitter } : {}),
  };
}
function ev(sessionId: string, kind: string, emitter?: string): ManduEvent {
  const coerced = coerceEvent(raw(sessionId, kind, emitter));
  assert.ok(coerced, "fixture must coerce");
  return coerced;
}

test("deriveAgentKind maps the Track A emitter to the agent CLI", () => {
  assert.equal(deriveAgentKind([ev("s", "tllm_call", "anthropic-proxy")]), "claude");
  assert.equal(deriveAgentKind([ev("s", "tllm_call", "openai-proxy")]), "codex");
});

test("deriveAgentKind is undefined without a model-proxy event (no guessing)", () => {
  assert.equal(deriveAgentKind([]), undefined);
  assert.equal(deriveAgentKind([
    ev("s", "classify", "arbiter"),
    ev("s", "fs_action", "fs-supervisor"),
  ]), undefined);
});

test("an explicit openai-proxy event outweighs anthropic-proxy in a mixed session", () => {
  // coerceEvent repairs a MISSING emitter on model-context kinds to
  // "anthropic-proxy" (EMITTER_BY_KIND), so a codex session containing one such
  // repaired event must still read as codex.
  const repaired = ev("s", "tool_result"); // no emitter → repaired to anthropic-proxy
  assert.equal(repaired.emitter, "anthropic-proxy", "precondition: repair applies");
  assert.equal(deriveAgentKind([repaired, ev("s", "tllm_call", "openai-proxy")]), "codex");
});

test("deriveRuntime reads the harness `runtime` tag off any event; undefined without one", () => {
  const dockerEv = coerceEvent({ ...raw("s", "assertion", "test-harness"), runtime: "docker" })!;
  const hostEv = coerceEvent({ ...raw("s", "assertion", "test-harness"), runtime: "host" })!;
  assert.equal(deriveRuntime([ev("s", "tllm_call", "anthropic-proxy"), dockerEv]), "docker");
  assert.equal(deriveRuntime([hostEv]), "host");
  assert.equal(deriveRuntime([ev("s", "tllm_call", "anthropic-proxy")]), undefined, "no tag → no runtime");
  assert.equal(deriveRuntime([]), undefined);
});

test("FileEventSource.listSessions exposes SessionRef.runtime from the harness tag", async () => {
  const dir = tmpDir("mandu-evsrc-runtime-");
  try {
    const line = (o: Record<string, unknown>): string => JSON.stringify(o) + "\n";
    // A docker session: the tllm_call carries no runtime, the emitted assertion does.
    writeFileSync(join(dir, "s-docker.ndjson"),
      line(raw("s-docker", "tllm_call", "anthropic-proxy")) +
      line({ ...raw("s-docker", "assertion", "test-harness"), runtime: "docker" }));
    writeFileSync(join(dir, "s-host.ndjson"),
      line({ ...raw("s-host", "assertion", "test-harness"), runtime: "host" }));
    writeFileSync(join(dir, "s-untagged.ndjson"),
      line(raw("s-untagged", "tllm_call", "anthropic-proxy")));

    const refs = await new FileEventSource(dir).listSessions();
    const byId = new Map(refs.map((r) => [r.id, r]));
    assert.equal(byId.get("s-docker")?.runtime, "docker");
    assert.equal(byId.get("s-host")?.runtime, "host");
    assert.equal(byId.get("s-untagged")?.runtime, undefined, "untagged session carries no runtime");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("FileEventSource.listSessions exposes SessionRef.agent from the events", async () => {
  const dir = tmpDir("mandu-evsrc-agent-");
  try {
    const line = (o: Record<string, unknown>): string => JSON.stringify(o) + "\n";
    writeFileSync(join(dir, "s-claude.ndjson"),
      line(raw("s-claude", "tllm_call", "anthropic-proxy")));
    writeFileSync(join(dir, "s-codex.ndjson"),
      line(raw("s-codex", "classify", "arbiter")) + line(raw("s-codex", "tllm_call", "openai-proxy")));
    writeFileSync(join(dir, "s-os-only.ndjson"),
      line(raw("s-os-only", "fs_action", "fs-supervisor")));

    const refs = await new FileEventSource(dir).listSessions();
    const byId = new Map(refs.map((r) => [r.id, r]));
    assert.equal(byId.get("s-claude")?.agent, "claude");
    assert.equal(byId.get("s-codex")?.agent, "codex");
    assert.equal(byId.get("s-os-only")?.agent, undefined, "OS-only trace carries no agent");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("coerceEvent preserves a tool_result's twinNote verbatim (symbol-twin-shell-blindness.md §4.6)", () => {
  const note = { paths: ["notes.md", "release-notes-alpha.md"], tokens: 2 };
  const e = coerceEvent({ ...raw("s-twin", "tool_result", "anthropic-proxy"), twinNote: note })!;
  assert.ok(e, "a tool_result with twinNote coerces");
  assert.deepEqual((e as unknown as { twinNote?: unknown }).twinNote, note);
  // and its absence stays absent — no default is invented
  const plain = coerceEvent(raw("s-twin", "tool_result", "anthropic-proxy"))!;
  assert.equal("twinNote" in plain, false);
});

test("deriveAgentKind falls back to the launcher's launch_posture.target when no model-proxy event exists (2026-09-25)", () => {
  // a drill that timed out before its first model call: launcher + net events only
  const posture = (target: unknown): ManduEvent =>
    coerceEvent({ ...raw("s", "launch_posture", "launcher"), view: "HumanView", boundary: "shell", target })!;
  assert.equal(deriveAgentKind([posture("claude"), ev("s", "net_action", "net-proxy")]), "claude");
  assert.equal(deriveAgentKind([posture("codex")]), "codex");
  assert.equal(deriveAgentKind([posture("opencode")]), "opencode");
  assert.equal(deriveAgentKind([posture("vim")]), undefined, "an unknown target is no agent kind");
  assert.equal(deriveAgentKind([posture(undefined)]), undefined);
  // proxy traffic outranks the requested target, and the test-id class outranks both
  assert.equal(deriveAgentKind([posture("claude"), ev("s", "tllm_call", "openai-proxy")]), "codex");
  assert.equal(deriveAgentKind([posture("claude")], "openclaw-e2e-reasoning-1751950000000"), "openclaw");
});

test("FileEventSource: a launcher session with no model call still gets its agent badge", async () => {
  const dir = tmpDir("mandu-evsrc-posture-");
  try {
    writeFileSync(join(dir, "watch-9-s4-haiku.ndjson"),
      JSON.stringify({ ...raw("watch-9-s4-haiku", "launch_posture", "launcher"), view: "HumanView", boundary: "shell", target: "claude", argv0: "claude", live: [], dropped: [] }) + "\n" +
      JSON.stringify(raw("watch-9-s4-haiku", "session_exit", "launcher")) + "\n");
    const refs = await new FileEventSource(dir).listSessions();
    assert.equal(refs.find((r) => r.id === "watch-9-s4-haiku")?.agent, "claude");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deriveAgentKind: an OpenClaw/OpenCode launch posture outranks the anthropic-proxy emitter", () => {
  // Found 2026-09-28: every live OpenClaw session was badged "claude" — its
  // traffic IS anthropic-proxy traffic, so only the launcher knows the agent.
  const posture = (target: string): ManduEvent =>
    coerceEvent({ ...raw("s", "launch_posture", "launcher"), boundary: "shell", target })!;
  assert.equal(deriveAgentKind([posture("openclaw"), ev("s", "tllm_call", "anthropic-proxy")]), "openclaw");
  assert.equal(deriveAgentKind([posture("opencode"), ev("s", "tllm_call", "anthropic-proxy")]), "opencode");
  // A claude posture changes nothing; openai-proxy traffic still reads as codex.
  assert.equal(deriveAgentKind([posture("claude"), ev("s", "tllm_call", "anthropic-proxy")]), "claude");
  assert.equal(deriveAgentKind([posture("openclaw"), ev("s", "tllm_call", "openai-proxy")]), "codex");
});

test("deriveAgentKind: the local-model drill's class says claude (it drives `claude -p`)", () => {
  assert.equal(deriveAgentKind([], "local-model-e2e-local-model-1790555000000"), "claude");
  assert.equal(deriveAgentKind([], "local-main-model-e2e-main-model-1790555200000"), "claude", "the phase 3 drill too");
});

test("deriveBatchMember: the launch_posture's batchMember, shape-checked; nothing else is guessed", () => {
  const posture = (batchMember: unknown): ManduEvent => {
    const c = coerceEvent({ ...raw("s", "launch_posture", "launcher"), boundary: "shell", view: "HumanView", batchMember });
    assert.ok(c, "fixture must coerce");
    return c;
  };
  assert.deepEqual(deriveBatchMember([posture({ kind: "scenario", key: "U1" })]), { kind: "scenario", key: "U1" });
  assert.deepEqual(deriveBatchMember([posture({ kind: "posture", key: "S1" })]), { kind: "posture", key: "S1" });
  assert.deepEqual(deriveBatchMember([posture({ kind: "scenario", key: "S3@haiku#2" })]), { kind: "scenario", key: "S3@haiku#2" });
  for (const bad of [undefined, null, "S1", { kind: "group", key: "S1" }, { kind: "scenario" }, { kind: "scenario", key: "<b>x</b>" }, { kind: "scenario", key: "" }]) {
    assert.equal(deriveBatchMember([posture(bad)]), undefined, JSON.stringify(bad));
  }
  assert.equal(deriveBatchMember([ev("s", "tllm_call", "anthropic-proxy")]), undefined, "no posture event: none");
});

// A browser agent (2026-10-19, dashboard.md §4.10.7): a program behind the
// DevTools relay, launched `--target shell`, so it has no AgentKind.
const posture = (live: string[]): ManduEvent =>
  coerceEvent({ ...raw("s", "launch_posture", "launcher"), view: "HumanView", boundary: "shell", target: "shell", argv0: "python", live, dropped: [] })!;

test("deriveBrowserAgent: the browser-jev class says jev; a launch with the relay live says browser; anything else nothing", () => {
  assert.equal(deriveBrowserAgent([], "browser-jev-e2e-settings-rename-1790555000000"), "jev");
  assert.equal(deriveBrowserAgent([posture(["net-proxy", "cdp-relay"])]), "browser");
  assert.equal(deriveBrowserAgent([posture(["cdp-relay"])], "browser-jev-e2e-field-value-1790555000000"), "jev", "the class wins");
  assert.equal(deriveBrowserAgent([posture(["net-proxy"])]), undefined, "no relay: not a browser agent");
  assert.equal(deriveBrowserAgent([], "claude-e2e-bash-ipi-1751950000000"), undefined);
  assert.equal(deriveBrowserAgent([ev("s", "tllm_call", "anthropic-proxy")]), undefined);
  assert.equal(deriveAgentKind([posture(["cdp-relay"])]), undefined, "and no AgentKind is guessed for it");
});

test("FileEventSource: a session behind the relay lists browserAgent; an ordinary one none", async () => {
  const dir = tmpDir("mandu-evsrc-browser-");
  try {
    writeFileSync(join(dir, "s-browser.ndjson"),
      JSON.stringify({ ...raw("s-browser", "launch_posture", "launcher"), view: "HumanView", boundary: "shell", target: "shell", argv0: "python", live: ["cdp-relay"], dropped: [] }) + "\n");
    writeFileSync(join(dir, "s-plain.ndjson"), JSON.stringify(raw("s-plain", "tllm_call", "anthropic-proxy")) + "\n");
    const refs = await new FileEventSource(dir).listSessions();
    assert.equal(refs.find((r) => r.id === "s-browser")?.browserAgent, "browser");
    assert.equal(refs.find((r) => r.id === "s-plain")?.browserAgent, undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
