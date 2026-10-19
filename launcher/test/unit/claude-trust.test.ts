/**
 * claude-trust.test — the AgentView twin inherits the human's workspace
 * trust, and ONLY that (services/claude-trust.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inheritApiKeyApproval, inheritWorkspaceTrust, claudeJsonPath } from "../../src/services/claude-trust.js";

const HUMAN = "/home/u/project/app";
const AGENT = "/home/u/.mandu/workspaces/app-0123456789ab/agentview";

function withDir(fn: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "mandu-trust-"));
  try { fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

test("inherits: a trusted human cwd trusts its AgentView twin; nothing else changes", () => {
  withDir((dir) => {
    const file = claudeJsonPath(dir);
    writeFileSync(file, JSON.stringify({
      hasCompletedOnboarding: true,
      projects: { [HUMAN]: { hasTrustDialogAccepted: true, allowedTools: ["Bash(ls:*)"] }, "/other": { hasTrustDialogAccepted: true } },
      customApiKeyResponses: { approved: ["x"] },
    }));
    const r = inheritWorkspaceTrust({ configDir: dir, humanCwd: HUMAN, agentCwd: AGENT });
    assert.equal(r.action, "inherited");
    const doc = JSON.parse(readFileSync(file, "utf8"));
    assert.equal(doc.projects[AGENT].hasTrustDialogAccepted, true);
    assert.deepEqual(doc.projects[HUMAN], { hasTrustDialogAccepted: true, allowedTools: ["Bash(ls:*)"] }, "the human entry is untouched");
    assert.equal(doc.hasCompletedOnboarding, true);
    assert.deepEqual(doc.customApiKeyResponses, { approved: ["x"] }, "unrelated keys survive the rewrite");
    assert.ok(!existsSync(`${file}.mandu-${process.pid}.tmp`), "the temp file was renamed away");
    // Idempotent.
    assert.equal(inheritWorkspaceTrust({ configDir: dir, humanCwd: HUMAN, agentCwd: AGENT }).action, "already-trusted");
  });
});

test("never grants trust the human did not give: untrusted human cwd, absent entry, missing file", () => {
  withDir((dir) => {
    const file = claudeJsonPath(dir);
    writeFileSync(file, JSON.stringify({ projects: { [HUMAN]: { hasTrustDialogAccepted: false } } }));
    const before = readFileSync(file, "utf8");
    assert.equal(inheritWorkspaceTrust({ configDir: dir, humanCwd: HUMAN, agentCwd: AGENT }).action, "human-not-trusted");
    assert.equal(readFileSync(file, "utf8"), before, "file not rewritten");
    writeFileSync(file, JSON.stringify({ projects: {} }));
    assert.equal(inheritWorkspaceTrust({ configDir: dir, humanCwd: HUMAN, agentCwd: AGENT }).action, "human-not-trusted");
    rmSync(file);
    assert.equal(inheritWorkspaceTrust({ configDir: dir, humanCwd: HUMAN, agentCwd: AGENT }).action, "no-config");
    assert.ok(!existsSync(file), "a missing .claude.json is never created");
  });
});

test("same path (fs rung off) is a no-op; a corrupt file is an error, not a crash", () => {
  withDir((dir) => {
    assert.equal(inheritWorkspaceTrust({ configDir: dir, humanCwd: HUMAN, agentCwd: HUMAN }).action, "same-path");
    writeFileSync(claudeJsonPath(dir), "{not json");
    const r = inheritWorkspaceTrust({ configDir: dir, humanCwd: HUMAN, agentCwd: AGENT });
    assert.equal(r.action, "error");
  });
});

// ── the API-key dialog's answer, carried to the placeholder (agent-sign-in.md §3.8) ──

const REAL = "sk-ant-api03-MANDUFAKEtrustKEY0123456789abcdef";
const PH = "$MDU:nomodel_Env[3f2a].ANTHROPIC_API_KEY";

test("inheritApiKeyApproval: an approved key approves its placeholder; a rejected one rejects it; a key never answered is left alone; no key material written", () => {
  withDir((dir) => {
    const file = claudeJsonPath(dir);
    writeFileSync(file, JSON.stringify({ customApiKeyResponses: { approved: [REAL.slice(-20)], rejected: [] }, other: 1 }));
    assert.equal(inheritApiKeyApproval({ configDir: dir, realKey: REAL, placeholder: PH }).action, "approved");
    const doc = JSON.parse(readFileSync(file, "utf8"));
    assert.deepEqual(doc.customApiKeyResponses.approved, [REAL.slice(-20), PH.slice(-20)]);
    assert.equal(doc.other, 1, "unrelated keys survive");
    assert.ok(!readFileSync(file, "utf8").includes(REAL), "never the key itself");
    assert.equal(inheritApiKeyApproval({ configDir: dir, realKey: REAL, placeholder: PH }).action, "already");

    writeFileSync(file, JSON.stringify({ customApiKeyResponses: { approved: [], rejected: [REAL.slice(-20)] } }));
    assert.equal(inheritApiKeyApproval({ configDir: dir, realKey: REAL, placeholder: PH }).action, "rejected");
    assert.deepEqual(JSON.parse(readFileSync(file, "utf8")).customApiKeyResponses.rejected, [REAL.slice(-20), PH.slice(-20)]);

    const before = JSON.stringify({ projects: {} });
    writeFileSync(file, before);
    assert.equal(inheritApiKeyApproval({ configDir: dir, realKey: REAL, placeholder: PH }).action, "never-answered");
    assert.equal(readFileSync(file, "utf8"), before, "untouched");
  });
  withDir((dir) => {
    assert.equal(inheritApiKeyApproval({ configDir: dir, realKey: REAL, placeholder: PH }).action, "no-config");
    assert.equal(existsSync(claudeJsonPath(dir)), false);
    writeFileSync(claudeJsonPath(dir), "{");
    assert.equal(inheritApiKeyApproval({ configDir: dir, realKey: REAL, placeholder: PH }).action, "error");
  });
});
