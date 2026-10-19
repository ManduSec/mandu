/**
 * session-upstreams.test — the per-session main-model binding (plan 11
 * phase 3): bind-once, refused after traffic, persisted, and the handling
 * prompt's localmodel_ line follows the location.
 *
 * Pure store + prompt logic: the confidentiality axis is what the binding
 * serves, so the suite states `secrets`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SessionUpstreamStore } from "../../policy/session-upstreams.js";
import { buildSymbolSystemPrompt } from "../../symbol-table/handling-prompt.js";
import { getActiveFormat } from "../../symbol-table/symbol-format.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

function withStore(fn: (open: () => SessionUpstreamStore) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "mandu-upstreams-"));
  const opened: SessionUpstreamStore[] = [];
  try {
    fn(() => {
      const s = new SessionUpstreamStore({ dbPath: join(dir, "m.db") });
      opened.push(s);
      return s;
    });
  } finally {
    for (const s of opened) s.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test("the first binding wins; the same one again is a no-op; a different one is refused", () => {
  withStore((open) => {
    const s = open();
    assert.equal(s.get("a"), undefined);
    const first = s.bind("a", "ollama", "launcher", false);
    assert.ok(first.ok && first.changed && first.binding.endpoint === "ollama");
    const again = s.bind("a", "ollama", "someone", false);
    assert.ok(again.ok && !again.changed);
    assert.equal(s.get("a")?.requestedBy, "launcher", "the idempotent re-bind does not rewrite the record");
    const other = s.bind("a", null, "x", false);
    assert.ok(!other.ok);
    assert.match(other.error, /already bound to 'ollama' \(asked the default vendor\); the main model is bind-once/);
  });
});

test("a default-vendor binding (null) pins the session as firmly as a named one", () => {
  withStore((open) => {
    const s = open();
    assert.ok(s.bind("b", null, "launcher", false).ok);
    const claim = s.bind("b", "ollama", "agent", false);
    assert.ok(!claim.ok, "a later claim of a local main model is refused");
    assert.equal(s.get("b")?.endpoint, null);
  });
});

test("a session that has already carried traffic cannot be bound at all", () => {
  withStore((open) => {
    const s = open();
    const r = s.bind("c", "ollama", "agent", true);
    assert.ok(!r.ok);
    assert.match(r.error, /already carried traffic/);
    assert.equal(s.get("c"), undefined, "nothing was recorded");
  });
});

test("bindings survive a reopen of the same DB (an arbiter restart does not reopen the window)", () => {
  withStore((open) => {
    const s1 = open();
    assert.ok(s1.bind("d", "ollama", "launcher", false).ok);
    assert.ok(s1.bind("e", null, "launcher", false).ok);
    s1.close();
    const s2 = open();
    assert.equal(s2.get("d")?.endpoint, "ollama");
    assert.equal(s2.get("e")?.endpoint, null);
    assert.ok(!s2.bind("e", "ollama", "agent", false).ok, "still bind-once after the restart");
    assert.equal(s2.get(undefined), undefined);
  });
});

test("the handling prompt's localmodel_ line follows the location; external is byte-identical to absent", () => {
  const fmt = getActiveFormat();
  const absent = buildSymbolSystemPrompt(fmt, { confidentiality: true });
  const external = buildSymbolSystemPrompt(fmt, { confidentiality: true, tllmLocation: "external" });
  const local = buildSymbolSystemPrompt(fmt, { confidentiality: true, tllmLocation: "local" });
  assert.equal(external, absent);
  assert.match(absent, /`declassify_symbol` is refused\*\* for this level: the model reading this\n  conversation is not the user's own model\./);
  assert.match(local, /`declassify_symbol` works for this level here\*\*, because the model reading\n  this conversation is the user's own\./);
  assert.doesNotMatch(local, /is not the user's own model/);
  assert.ok(!local.includes("\\`"), "no stray escapes in the rendered text");
  // Without an inspect tool the localmodel_ block is not rendered at all, so the
  // location changes nothing there.
  const noInspect = { confidentiality: true, capabilities: { inspect: false } };
  assert.equal(
    buildSymbolSystemPrompt(fmt, { ...noInspect, tllmLocation: "local" }),
    buildSymbolSystemPrompt(fmt, noInspect),
  );
});
