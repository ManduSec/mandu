/**
 * codex-trust.test — the AgentView twin inherits the human's codex directory
 * trust (services/codex-trust.ts), appended as new `[projects."…"]` tables
 * without ever duplicating one or granting trust the human did not give.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { codexPathHasTable, codexPathTrusted, inheritCodexTrust } from "../../src/services/codex-trust.js";

const HUMAN = "/home/u/project/app";
const STATE = "/home/u/.mandu/workspaces/app-0123456789ab";
const AGENT = `${STATE}/agentview`;

function withHome(fn: (home: string) => void): void {
  const home = mkdtempSync(join(tmpdir(), "mandu-codex-trust-"));
  try { fn(home); } finally { rmSync(home, { recursive: true, force: true }); }
}

const BASE = `model = "gpt-5.5"\n\n[projects.${JSON.stringify(HUMAN)}]\ntrust_level = "trusted"\n\n[projects."/other"]\ntrust_level = "untrusted"\n`;

test("inherits: a trusted human root trusts the twin's state dir AND the AgentView path, appended as new tables", () => {
  withHome((home) => {
    writeFileSync(join(home, "config.toml"), BASE);
    const r = inheritCodexTrust({ codexHome: home, humanRoot: HUMAN, agentPaths: [STATE, AGENT] });
    assert.equal(r.action, "inherited");
    assert.deepEqual((r as { added: string[] }).added, [STATE, AGENT]);
    const text = readFileSync(join(home, "config.toml"), "utf8");
    assert.ok(text.startsWith(BASE), "the existing file is untouched — tables are appended");
    assert.ok(codexPathTrusted(text, STATE));
    assert.ok(codexPathTrusted(text, AGENT));
    assert.ok(!codexPathTrusted(text, "/other"), "an untrusted table stays untrusted");
    assert.ok(!existsSync(join(home, `config.toml.mandu-${process.pid}.tmp`)));
    // Idempotent: never a duplicate table (codex refuses duplicate keys).
    assert.equal(inheritCodexTrust({ codexHome: home, humanRoot: HUMAN, agentPaths: [STATE, AGENT] }).action, "already-trusted");
    assert.equal(text.split(`[projects.${JSON.stringify(STATE)}]`).length, 2, "exactly one table for the state dir");
  });
});

test("never grants trust the human did not give; an existing untrusted table is not overwritten", () => {
  withHome((home) => {
    writeFileSync(join(home, "config.toml"), `[projects.${JSON.stringify(HUMAN)}]\ntrust_level = "untrusted"\n`);
    const before = readFileSync(join(home, "config.toml"), "utf8");
    assert.equal(inheritCodexTrust({ codexHome: home, humanRoot: HUMAN, agentPaths: [STATE] }).action, "human-not-trusted");
    assert.equal(readFileSync(join(home, "config.toml"), "utf8"), before);
    // Human trusted, but the twin already has a table (untrusted by the
    // human's own hand): left alone — the human's explicit answer wins.
    writeFileSync(join(home, "config.toml"), BASE + `\n[projects.${JSON.stringify(STATE)}]\ntrust_level = "untrusted"\n`);
    const r = inheritCodexTrust({ codexHome: home, humanRoot: HUMAN, agentPaths: [STATE] });
    assert.equal(r.action, "already-trusted");
    assert.ok(codexPathHasTable(readFileSync(join(home, "config.toml"), "utf8"), STATE));
    assert.ok(!codexPathTrusted(readFileSync(join(home, "config.toml"), "utf8"), STATE), "not flipped to trusted");
  });
});

test("missing config → no-op (never created); single-quoted keys are recognized", () => {
  withHome((home) => {
    assert.equal(inheritCodexTrust({ codexHome: home, humanRoot: HUMAN, agentPaths: [STATE] }).action, "no-config");
    assert.ok(!existsSync(join(home, "config.toml")));
    assert.ok(codexPathTrusted(`[projects.'${HUMAN}']\ntrust_level = 'trusted'\n`, HUMAN));
  });
});
