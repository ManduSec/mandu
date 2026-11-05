/**
 * openclaw-attach-session-parity — the launcher's copy of the attachment
 * session rule (launcher/src/openclaw-attach.ts, the session `mandu openclaw
 * install` routes `openclaw.json` to and names the service proxy's port file
 * by) equals the plugin's (interceptors/openclaw-inspect-plugin/src/
 * attachment-session.ts, the session the plugin's events and declassify go
 * to). The two packages cannot import each other (no workspace), so this
 * holds them equal (docs/design/agents/openclaw-plugin.md §3.3).
 *
 * Also: the attachment config install writes is one the plugin's own config
 * resolver reads as an attachment of that session.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  attachmentSession as launcherSession,
  normalizeAgentId as launcherNormalize,
  planInstall,
} from "../../launcher/src/openclaw-attach.js";
import {
  attachmentSession as pluginSession,
  normalizeAgentId as pluginNormalize,
  SESSION_ID_RE,
} from "../../interceptors/openclaw-inspect-plugin/src/attachment-session.js";
import { resolvePluginConfig } from "../../interceptors/openclaw-inspect-plugin/src/plugin-config.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // no arbiter here; the default mode, stated

const IDS = ["main", "Work", "My Agent!", "", "  x  ", "../..", "a".repeat(200), "ops_bot-2", "ünï", "a:b", undefined];

test("the launcher's session rule equals the plugin's", () => {
  for (const id of IDS) {
    assert.equal(launcherNormalize(id), pluginNormalize(id), String(id));
    assert.equal(launcherSession(id), pluginSession(id), String(id));
    assert.ok(SESSION_ID_RE.test(launcherSession(id)), launcherSession(id));
  }
});

test("the arbiter's attachmentSessionId, given the normalized agent id, builds the same session (the pool registers by it)", async () => {
  const { attachmentSessionId } = await import("../../arbiter/policy/confinement-posture.js");
  for (const id of IDS) {
    assert.equal(attachmentSessionId("openclaw-plugin", launcherNormalize(id)), launcherSession(id), String(id));
  }
});

test("the plugin reads the config install writes as an attachment of that session", () => {
  const { doc } = planInstall({}, {
    pluginDir: "/src/interceptors/openclaw-inspect-plugin",
    agentId: "Work",
    session: launcherSession("Work"),
    proxyUrl: "http://127.0.0.1:41234",
    arbiterSock: "/run/user/1000/mandu/instances/x/arbiter.sock",
    manduPaths: ["/home/u/.mandu", "/run/user/1000/mandu"],
  });
  const entry = (doc as any).plugins.entries["mandu-inspect"];
  const cfg = resolvePluginConfig(entry.config, {});
  assert.equal(cfg.attachment, true);
  assert.equal(cfg.scopeId, "openclaw:work");
  assert.equal(pluginSession(cfg.agentId), cfg.scopeId);
  assert.equal(cfg.arbiterSock, "/run/user/1000/mandu/instances/x/arbiter.sock");
  assert.deepEqual(cfg.manduPaths, ["/home/u/.mandu", "/run/user/1000/mandu"]);
  assert.equal((doc as any).models.providers.anthropic.headers["x-mandu-session-id"], cfg.scopeId);
});
