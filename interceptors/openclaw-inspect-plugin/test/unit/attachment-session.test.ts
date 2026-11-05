/**
 * attachment-session tests — `openclaw:<agentId>` (src/attachment-session.ts,
 * docs/design/agents/openclaw-plugin.md §3.3). Pure.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  agentIdOfSessionKey,
  attachmentSession,
  normalizeAgentId,
  SESSION_ID_RE,
} from "../../src/attachment-session.js";

test("normalizeAgentId follows OpenClaw's rule", () => {
  assert.equal(normalizeAgentId("main"), "main");
  assert.equal(normalizeAgentId("  Work "), "work");
  assert.equal(normalizeAgentId("My Agent!"), "my-agent");
  assert.equal(normalizeAgentId("--x--"), "x");
  assert.equal(normalizeAgentId("ops_bot-2"), "ops_bot-2");
  assert.equal(normalizeAgentId(""), "main");
  assert.equal(normalizeAgentId(undefined), "main");
  assert.equal(normalizeAgentId("!!!"), "main");
  assert.equal(normalizeAgentId("a".repeat(100)), "a".repeat(64));
  assert.equal(normalizeAgentId("../../etc"), "etc");
  assert.equal(normalizeAgentId("agent:main"), "agent-main");
});

test("attachmentSession is always inside the arbiter's session-id form", () => {
  for (const id of ["main", "Work", "x/y", "../..", "", "a".repeat(300), "ünï", "a:b", "😀"]) {
    const s = attachmentSession(id);
    assert.ok(s.startsWith("openclaw:"), s);
    assert.ok(SESSION_ID_RE.test(s), s);
    assert.ok(!s.includes("/"), s);
  }
  assert.equal(attachmentSession("main"), "openclaw:main");
  assert.equal(attachmentSession(undefined), "openclaw:main");
});

test("agentIdOfSessionKey reads OpenClaw's agent:<id>:… keys", () => {
  assert.equal(agentIdOfSessionKey("agent:main:telegram:12345"), "main");
  assert.equal(agentIdOfSessionKey("agent:Work:main"), "work");
  assert.equal(agentIdOfSessionKey("agent:ops"), "ops");
  assert.equal(agentIdOfSessionKey("cron:nightly"), null);
  assert.equal(agentIdOfSessionKey(""), null);
  assert.equal(agentIdOfSessionKey(undefined), null);
});
