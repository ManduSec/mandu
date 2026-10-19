/**
 * model-host-paths — the model-host deny's decision (agent-sdks.md §4, "The
 * model-host deny"): which hosts are model hosts, and which paths on them a
 * program in the agent's tree may call directly. Pure; no proxy, no network.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  MODEL_HOST_NAMES,
  MODEL_HOST_RULES,
  modelHostRule,
  modelPathDecision,
  pathMatches,
  requestPath,
} from "../../src/model-host-paths.js";

function decide(host: string, target: string, method = "GET"): boolean {
  const rule = modelHostRule(host);
  assert.ok(rule, `${host} is a model host`);
  return modelPathDecision(rule, method, target).allowed;
}

test("the model hosts: the vendors' API hosts (and below them), platform.claude.com and chatgpt.com; claude.ai and the rest are not", () => {
  assert.deepEqual([...MODEL_HOST_NAMES], ["api.anthropic.com", "platform.claude.com", "api.openai.com", "chatgpt.com"]);
  for (const h of ["api.anthropic.com", "API.Anthropic.COM.", "api.anthropic.com:443", "x.api.anthropic.com", "api.openai.com", "eu.api.openai.com", "platform.claude.com", "chatgpt.com"]) {
    assert.ok(modelHostRule(h), h);
  }
  for (const h of ["claude.ai", "anthropic.com", "auth.openai.com", "ab.chatgpt.com", "x.platform.claude.com", "example.com", "api.anthropic.com.evil.example", "", "[::1]"]) {
    assert.equal(modelHostRule(h), null, h);
  }
});

test("a model call is refused on every model host, whatever the method or query", () => {
  for (const [host, target] of [
    ["api.anthropic.com", "/v1/messages"],
    ["api.anthropic.com", "/v1/messages?beta=true"],
    ["api.anthropic.com", "/v1/messages/count_tokens"],
    ["api.anthropic.com", "/v1/messages/batches"],
    ["api.anthropic.com", "/v1/complete"],
    ["api.anthropic.com", "/v1/files"],
    ["api.anthropic.com", "/v1/models"],
    ["api.anthropic.com", "/v1/code/sessions"],
    ["api.anthropic.com", "/v1/sessions/abc/events"],
    ["api.anthropic.com", "/v1/environments/bridge"],
    ["api.anthropic.com", "/api/ws/speech_to_text/voice_stream"],
    ["api.anthropic.com", "/api/event_logging/v2/batch"],
    ["api.anthropic.com", "/api/claude_code_shared_session_transcripts"],
    ["api.anthropic.com", "/api/frame/evil"],
    ["platform.claude.com", "/v1/messages"],
    ["api.openai.com", "/v1/responses"],
    ["api.openai.com", "/v1/chat/completions"],
    ["api.openai.com", "/v1/models"],
    ["chatgpt.com", "/backend-api/codex/responses"],
    ["chatgpt.com", "/backend-api/codex/responses/compact"],
    ["chatgpt.com", "/backend-api/conversation"],
    ["chatgpt.com", "/backend-api/wham/tasks"],
    ["chatgpt.com", "/backend-api/ps/mcp"],
    ["chatgpt.com", "/"],
  ] as const) {
    assert.equal(decide(host, target, "POST"), false, `${host}${target}`);
    assert.equal(decide(host, target, "GET"), false, `${host}${target} (GET)`);
  }
});

test("the listed account, sign-in and gated upload calls pass", () => {
  for (const [host, target] of [
    ["api.anthropic.com", "/api/oauth/profile"],
    ["api.anthropic.com", "/api/hello"],
    ["api.anthropic.com", "/api/hello/"],
    ["api.anthropic.com", "/api/oauth/usage?at_wall=1&skip_spend=1"],
    ["api.anthropic.com", "/api/oauth/claude_cli/roles"],
    ["api.anthropic.com", "/api/claude_code/settings"],
    ["api.anthropic.com", "/api/eval/sdk-abc123"],
    ["api.anthropic.com", "/api/web/domain_info?domain=example.com"],
    ["api.anthropic.com", "/api/organizations/0f1e/model_selector/claude-code"],
    ["api.anthropic.com", "/v1/mcp_servers?limit=1000&include_additional_installs=true"],
    ["api.anthropic.com", "/v1/design/mcp"],
    ["api.anthropic.com", "/api/artifacts/mcp"],
    ["api.anthropic.com", "/api/artifacts/mcp/upload/a/b/c"],
    ["api.anthropic.com", "/api/frame/sync?slug=x"],
    ["api.anthropic.com", "/api/frame/deploy/direct?attempt_id=1"],
    ["platform.claude.com", "/v1/oauth/token"],
    ["platform.claude.com", "/docs/en/api/messages"],
    ["platform.claude.com", "/llms.txt"],
    ["chatgpt.com", "/backend-api/wham/usage"],
    ["chatgpt.com", "/backend-api/wham/accounts/check"],
    ["chatgpt.com", "/backend-api/ps/plugins/list"],
    ["chatgpt.com", "/backend-api/ps/plugins/suggested/codex"],
    ["chatgpt.com", "/backend-api/plugins/featured"],
  ] as const) {
    assert.equal(decide(host, target), true, `${host}${target}`);
  }
});

test("absolute-form targets are judged by their path; other forms are refused", () => {
  assert.equal(requestPath("https://api.anthropic.com/v1/messages?x=1"), "/v1/messages");
  assert.equal(requestPath("http://api.anthropic.com"), "/");
  assert.equal(requestPath("http://api.anthropic.com?x"), "/");
  assert.equal(requestPath("/api/hello#frag"), null, "a fragment is never part of a request target");
  assert.equal(requestPath("*"), null);
  assert.equal(requestPath("api.anthropic.com:443"), null);
  assert.equal(decide("api.anthropic.com", "https://api.anthropic.com/api/oauth/profile"), true);
  assert.equal(decide("api.anthropic.com", "https://api.anthropic.com/v1/messages"), false);
  assert.equal(decide("api.anthropic.com", "*", "OPTIONS"), false);
});

test("a path the server could normalize into another endpoint is refused, even below an allowed prefix", () => {
  for (const target of [
    "/api/oauth/profile/../../v1/messages",
    "/api/artifacts/mcp/upload/../../../v1/messages",
    "/api/frame/sync/./x",
    "/api/frame/sync/%2e%2e/%2e%2e/%2e%2e/v1/messages",
    "/api/artifacts/mcp/upload/..%2f..%2f..%2fv1%2fmessages",
    "/api/oauth/profile;/v1/messages",
    "/api/oauth/profile\\..\\..\\v1\\messages",
    "//v1/messages",
    "/api//oauth/profile",
    "/api/oauth/profile%20",
    "/api/hello#/../../v1/messages",
    // A placeholder never sits in an allowed path (its brackets), so no
    // value the gate puts back can turn one into another path.
    "/api/eval/$MDU:nomodel_Read[0f3a].KEY",
    "https://api.anthropic.com/api/hello#/../../v1/messages",
  ]) {
    const rule = modelHostRule("api.anthropic.com")!;
    const d = modelPathDecision(rule, "POST", target);
    assert.equal(d.allowed, false, target);
  }
});

test("the refusal names the host and the path, never the query", () => {
  const d = modelPathDecision(modelHostRule("api.anthropic.com")!, "POST", "/v1/messages?secret=sk-ant-NEVER-SHOWN");
  assert.equal(d.allowed, false);
  if (!d.allowed) {
    assert.match(d.reason, /POST \/v1\/messages on model host api\.anthropic\.com is refused/);
    assert.ok(!d.reason.includes("NEVER-SHOWN"));
  }
});

test("pathMatches: `*` is one segment, a final `**` any number", () => {
  assert.equal(pathMatches("/a/*/c", "/a/b/c"), true);
  assert.equal(pathMatches("/a/*/c", "/a/c"), false);
  assert.equal(pathMatches("/a/*/c", "/a/b/x/c"), false);
  assert.equal(pathMatches("/a/**", "/a"), true);
  assert.equal(pathMatches("/a/**", "/a/b/c"), true);
  assert.equal(pathMatches("/a/**", "/ab"), false);
  assert.equal(pathMatches("/a", "/a/"), true);
  assert.equal(pathMatches("/a", "/a/b"), false);
});

test("every entry names its evidence, and no entry admits a Messages or Responses path", () => {
  for (const r of MODEL_HOST_RULES) {
    for (const a of r.allow) {
      assert.ok(a.source.length > 10, `${r.host}${a.pattern} names where it was read`);
      assert.ok(a.pattern.startsWith("/"), a.pattern);
      for (const model of ["/v1/messages", "/v1/complete", "/v1/responses", "/backend-api/codex/responses", "/v1/chat/completions"]) {
        assert.equal(pathMatches(a.pattern, model), false, `${r.host}${a.pattern} admits ${model}`);
      }
    }
  }
});
