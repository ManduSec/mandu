/**
 * session-spec-registry — the session→spec bindings are a registry an arbiter
 * owns (tool-inbound.ts SessionSpecs; agent-e2e-harness.md §4, 2026-10-09),
 * not module state: two registries in one process bind the same session key
 * independently, each is bind-once for its life, `clear()` releases it, and
 * every session-keyed lookup (inbound spec, outbound destination kind, gate
 * surface, the relative-path base, unknown-tool health) resolves against the
 * registry it is handed. The process registry, the default for direct
 * callers, is a separate object no other registry writes.
 *
 * The real-server half (two ArbiterServers in one process, over the IPC):
 * test/component/session-spec-scope.test.ts.
 */
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";

import {
  SessionSpecs,
  bindSessionSpec,
  clearSessionSpecs,
  getToolInboundSpec,
  inboundSpecNamesInput,
  processSessionSpecs,
  resolveInboundSpecId,
  sessionSpecBindings,
  sessionSpecOf,
  unknownToolNames,
} from "../../policy/tool-inbound.js";
import { destinationKind } from "../../policy/tool-outbound.js";
import { gateSurfaceFor } from "../../policy/tool-gate-surface.js";
import { relativePathBase } from "../../policy/policy-interface.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the spec tables and their resolution are axis-independent

afterEach(() => clearSessionSpecs());

const S = "diff-fidelity-two-turn-prose-wrapped";

test("SessionSpecs is bind-once: the first binding wins, the same id again is a no-op, another id is refused and changes nothing", () => {
  const r = new SessionSpecs();
  assert.deepEqual(r.bind(S, "openclaw-agent"), { ok: true, already: false });
  assert.deepEqual(r.bind(S, "openclaw-agent"), { ok: true, already: true });
  assert.deepEqual(r.bind(S, "claude-code"), { ok: false, prior: "openclaw-agent" });
  assert.deepEqual(r.bind(S, "fail-closed"), { ok: false, prior: "openclaw-agent" }, "not even toward the stricter spec: a bound session never moves");
  assert.equal(r.specOf(S), "openclaw-agent");
  assert.deepEqual([...r.bindings()], [[S, "openclaw-agent"]]);
});

test("two registries bind the same session key to different specs, independently", () => {
  const a = new SessionSpecs();
  const b = new SessionSpecs();
  assert.equal(a.bind(S, "openclaw-agent").ok, true);
  assert.equal(b.bind(S, "opencode").ok, true, "the 2026-10-09 refusal is gone: b never saw a's binding");
  assert.equal(a.specOf(S), "openclaw-agent");
  assert.equal(b.specOf(S), "opencode");
  assert.equal(processSessionSpecs.specOf(S), undefined, "neither wrote the process registry");
  assert.equal(sessionSpecBindings().size, 0);
});

test("clear() releases a registry's bindings, and only its own", () => {
  const a = new SessionSpecs();
  const b = new SessionSpecs();
  a.bind(S, "openclaw-agent");
  b.bind(S, "opencode");
  a.clear();
  assert.equal(a.specOf(S), undefined);
  assert.equal(a.bind(S, "goose").ok, true, "after its release, the key binds from scratch");
  assert.equal(b.specOf(S), "opencode", "b is untouched");
});

test("every session-keyed lookup resolves against the registry it is handed", () => {
  const a = new SessionSpecs();
  const b = new SessionSpecs();
  a.bind(S, "openclaw-agent");
  b.bind(S, "opencode");

  assert.equal(resolveInboundSpecId(S, a), "openclaw-agent");
  assert.equal(resolveInboundSpecId(S, b), "opencode");
  assert.equal(resolveInboundSpecId(S), "claude-code", "the process registry: unbound, the boot spec");
  assert.equal(resolveInboundSpecId(S, new SessionSpecs()), "claude-code", "a fresh registry: unbound, the boot spec");

  // inbound: OpenCode maps `glob`, OpenClaw does not (fail-closed for it)
  assert.ok(getToolInboundSpec("glob", S, b));
  assert.equal(getToolInboundSpec("glob", S, a), undefined);
  assert.equal(inboundSpecNamesInput("glob", S, b), true);
  assert.equal(inboundSpecNamesInput("glob", S, a), false);
  assert.deepEqual(unknownToolNames(["glob", "exec"], S, a), ["glob"]);
  assert.deepEqual(unknownToolNames(["glob", "exec"], S, b), ["exec"]);

  // outbound: the same binding keys the outbound maps
  assert.equal(destinationKind("bash", "command", S, b), "resolve", "OpenCode's bash command goes to the live shell");
  assert.equal(destinationKind("bash", "command", S, a), "not_resolve", "OpenClaw has no `bash`: unknown sink, symbols stay");

  // the gate surface and the relative-path base follow it too
  assert.equal(gateSurfaceFor(S, a).spec, "openclaw-agent");
  assert.equal(gateSurfaceFor(S, b).spec, "opencode");
  const req = { tool: "read", relativeBase: "/home/u/proj", sessionKey: S };
  assert.deepEqual(relativePathBase(req, a), { dir: "/home/u/proj", fields: ["path", "file_path"] }, "OpenClaw's `read` fields");
  assert.deepEqual(relativePathBase(req, b), { dir: "/home/u/proj", fields: ["filePath", "path"] }, "OpenCode's `read` fields");
  assert.equal(relativePathBase(req, new SessionSpecs()), undefined, "unbound: Claude Code's surface names no such base");
});

test("the process registry (direct callers) keeps the same bind-once rule", () => {
  bindSessionSpec(S, "goose");
  bindSessionSpec(S, "goose"); // the same spec: a no-op
  assert.throws(() => bindSessionSpec(S, "claude-code"), /already bound to 'goose' — specs are bind-once/);
  assert.equal(sessionSpecOf(S), "goose");
  clearSessionSpecs();
  assert.equal(sessionSpecOf(S), undefined);
});
