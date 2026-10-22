/**
 * session-logins — what the launcher tells this proxy about the AI agents'
 * login files its session leaves raw (src/session-logins.ts;
 * secret-discovery.md §1.10). A malformed value exempts nothing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { parseSessionLogins, SESSION_LOGINS_ENV } from "../../src/session-logins.js";

test("parseSessionLogins keeps the known fields; absent or malformed is null (nothing exempt), with the reason for a malformed one", () => {
  assert.equal(SESSION_LOGINS_ENV, "MANDU_NET_PROXY_SESSION_LOGINS");
  assert.deepEqual(parseSessionLogins(undefined), { logins: null });
  assert.deepEqual(parseSessionLogins("  "), { logins: null });
  assert.deepEqual(
    parseSessionLogins(JSON.stringify({ home: "/home/u", target: "codex", ullmBinary: "codex", otherLoginsRaw: false, loginEnv: { CODEX_HOME: "/srv/cx", N: 3 }, extra: "dropped" })),
    { logins: { home: "/home/u", target: "codex", ullmBinary: "codex", loginEnv: { CODEX_HOME: "/srv/cx" } } },
  );
  assert.deepEqual(parseSessionLogins(JSON.stringify({ home: "/h", target: "claude", otherLoginsRaw: true })).logins, { home: "/h", target: "claude", otherLoginsRaw: true });
  for (const bad of ["{", "[]", "\"codex\"", JSON.stringify({ target: "codex" }), JSON.stringify({ home: "relative" })]) {
    const r = parseSessionLogins(bad);
    assert.equal(r.logins, null, bad);
    assert.ok(typeof r.error === "string" && r.error.length > 0, `${bad}: a reason`);
  }
});

test("parseSessionLogins carries the project MCP configs the session's agent reads (secret-discovery.md §2.10): absolute paths, bounded", () => {
  const r = parseSessionLogins(JSON.stringify({ home: "/h", target: "claude", mcpConfigs: ["/w/p/.mcp.json", "relative/.mcp.json", 7, "/w/q/.mcp.json"] }));
  assert.deepEqual(r.logins, { home: "/h", target: "claude", mcpConfigs: ["/w/p/.mcp.json", "/w/q/.mcp.json"] });
  assert.equal(parseSessionLogins(JSON.stringify({ home: "/h", mcpConfigs: "/w/p/.mcp.json" })).logins?.mcpConfigs, undefined, "not a list: none");
  const many = Array.from({ length: 40 }, (_, i) => `/w${i}/.mcp.json`);
  assert.equal(parseSessionLogins(JSON.stringify({ home: "/h", mcpConfigs: many })).logins?.mcpConfigs?.length, 16, "bounded as the arbiter bounds it");
});
