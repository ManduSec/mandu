/**
 * start-commands — the command a sentence tells you to start your agent
 * with names the agents you use (dashboard.md §4.25, *Protection is off when
 * nothing runs*):
 *
 *   - nothing known (no scan, no recorded session): `mandu claude` (or
 *     `mandu codex`), today's words;
 *   - the sessions recorded under Mandu first, newest first, then the last
 *     scan's by session count, highest first; at most two;
 *   - the scan's `claude-code` is `mandu claude`; an agent Mandu does not
 *     run (Gemini CLI, Copilot CLI, Cursor) is never a command, and a kind
 *     Mandu does not know or none is skipped;
 *   - the parts: `a`, or `a` (or `b`), each command as code; tagged, every
 *     part carries `start` (the Scan page draws them from Home's list).
 * Axes: none (display only: fixed command words, no session data). Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { START_FALLBACK, startCommandParts, startCommands } from "../../../src/view-model/start-commands.js";

test("nothing known: mandu claude and mandu codex, today's two", () => {
  assert.deepEqual(startCommands(null, []), ["mandu claude", "mandu codex"]);
  assert.deepEqual(startCommands(undefined, []), ["mandu claude", "mandu codex"]);
  assert.deepEqual(startCommands({}, []), ["mandu claude", "mandu codex"]);
  assert.deepEqual(startCommands({ "claude-code": 0, goose: 0 }, [undefined]), ["mandu claude", "mandu codex"], "no session counted, no kind known");
  assert.deepEqual(START_FALLBACK, ["mandu claude", "mandu codex"]);
});

test("a scan of Goose sessions only: mandu goose alone", () => {
  assert.deepEqual(startCommands({ goose: 40 }, []), ["mandu goose"]);
});

test("a recorded OpenCode session, then a scan of Claude Code: opencode, then claude", () => {
  assert.deepEqual(startCommands({ "claude-code": 812 }, ["opencode"]), ["mandu opencode", "mandu claude"]);
  // The scan alone: claude-code is mandu claude.
  assert.deepEqual(startCommands({ "claude-code": 3 }, []), ["mandu claude"]);
});

test("recorded sessions newest first, each kind once, before any scan count", () => {
  assert.deepEqual(startCommands({ codex: 900 }, ["goose", "goose", "openclaw", "claude"]), ["mandu goose", "mandu openclaw"]);
  assert.deepEqual(startCommands({ codex: 900, opencode: 5 }, ["claude", "claude"]), ["mandu claude", "mandu codex"]);
});

test("the scan by session count, highest first; ties in the agents' order", () => {
  assert.deepEqual(startCommands({ "claude-code": 2, goose: 40, codex: 16 }, []), ["mandu goose", "mandu codex"]);
  assert.deepEqual(startCommands({ goose: 5, codex: 5 }, []), ["mandu codex", "mandu goose"]);
});

test("an agent Mandu does not run is never a command; never more than two", () => {
  assert.deepEqual(startCommands({ gemini: 30 }, []), ["mandu claude", "mandu codex"], "Gemini CLI only: the fallback, never mandu gemini");
  assert.deepEqual(startCommands({ gemini: 30, copilot: 9, cursor: 4, goose: 1 }, []), ["mandu goose"]);
  assert.deepEqual(startCommands(null, ["gemini", "mystery", undefined]), ["mandu claude", "mandu codex"]);
  const all = startCommands({ "claude-code": 5, codex: 4, openclaw: 3, opencode: 2, goose: 1 }, ["goose", "opencode", "openclaw"]);
  assert.deepEqual(all, ["mandu goose", "mandu opencode"]);
  for (const c of all) assert.doesNotMatch(c, /gemini|copilot|cursor/);
});

test("a count that is not a number counts nothing", () => {
  assert.deepEqual(startCommands({ goose: Number.NaN, opencode: -3, codex: "7" as unknown as number }, []), ["mandu claude", "mandu codex"]);
});

test("the parts: one command, or the first (or the second), each as code", () => {
  assert.deepEqual(startCommandParts(["mandu goose"]), [{ kind: "code", text: "mandu goose" }]);
  assert.deepEqual(startCommandParts(["mandu opencode", "mandu claude"]), [
    { kind: "code", text: "mandu opencode" }, { kind: "text", text: " (or " }, { kind: "code", text: "mandu claude" }, { kind: "text", text: ")" },
  ]);
  assert.deepEqual(startCommandParts([]).filter((p) => p.kind === "code").map((p) => p.text), ["mandu claude", "mandu codex"]);
});

test("tagged parts: every part, the codes and the (or …) words, carries start; the text is the same", () => {
  const plain = startCommandParts(["mandu opencode", "mandu claude"]);
  const tagged = startCommandParts(["mandu opencode", "mandu claude"], true);
  assert.deepEqual(tagged, plain.map((p) => ({ ...p, start: true })));
  assert.deepEqual(startCommandParts(["mandu goose"], true), [{ kind: "code", text: "mandu goose", start: true }]);
  assert.ok(plain.every((p) => !("start" in p)), "untagged by default");
});
