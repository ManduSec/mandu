/**
 * env-mask-agent-vars e2e (release checklist d9) — which of the AGENT's own
 * variables reach it raw, over the PRODUCTION wiring: the launcher's
 * applyEnvSecrets + socket adapter against a real ArbiterServer.
 *
 * CLAUDE_CODE_MESSAGING_TOKEN is the credential a Claude Code session hands
 * its children for its local messaging socket; an agent launched from inside
 * another Claude Code session inherits it. It used to pass raw under a blanket
 * `CLAUDE_*` exemption. Now: masked like any `*_TOKEN`; the agent's own login
 * credential and its config switches still reach it as they are.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { applyEnvSecrets, socketSecretArbiter } from "../../launcher/src/secret-setup.js";
import { emptyMutation } from "../../launcher/src/backend/types.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { stateAxes } from "../../arbiter/test/axes.js";

stateAxes("secrets"); // confidentiality ON

const MSG_TOKEN = "3d6aa8f0c1d2e3f4a5b6c7d8e9f0a1b2";
const OAUTH = "sk-ant-oat01-own-login-e2e";

test("a launch masks CLAUDE_CODE_MESSAGING_TOKEN; the agent's own login and its switches stay raw", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-envagent-"));
  const sock = join(dir, "a.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  try {
    const mut = emptyMutation();
    const logs: string[] = [];
    const env = {
      PATH: process.env["PATH"],
      CLAUDE_CODE_MESSAGING_TOKEN: MSG_TOKEN,
      CLAUDE_CODE_MESSAGING_SOCKET: "/tmp/claude-msg.sock",
      CLAUDE_CODE_OAUTH_TOKEN: OAUTH,
      CLAUDE_CODE_SKIP_BEDROCK_AUTH: "1",
    };
    const res = await applyEnvSecrets({ confidentiality: true } as LaunchPlan, env, mut, {
      arbiter: socketSecretArbiter(sock), log: (m) => logs.push(m),
    });
    const masked = mut.env["CLAUDE_CODE_MESSAGING_TOKEN"];
    assert.ok(masked?.startsWith("$MDU:nomodel_Env[") && masked.endsWith(".CLAUDE_CODE_MESSAGING_TOKEN"), `${masked} (${logs.join(" | ")})`);
    assert.ok(!JSON.stringify(mut.env).includes(MSG_TOKEN), "the token never enters the agent's environment");
    assert.deepEqual(res.masked, ["CLAUDE_CODE_MESSAGING_TOKEN"]);
    // Untouched: the agent's own login (it must authenticate), a switch, the socket path.
    for (const name of ["CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_SKIP_BEDROCK_AUTH", "CLAUDE_CODE_MESSAGING_SOCKET"]) {
      assert.equal(mut.env[name], undefined, `${name} is not rewritten`);
    }
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
