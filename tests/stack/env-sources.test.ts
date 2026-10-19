/**
 * env-sources e2e — policy.yaml `env.sources` (comparisons.md §3.4) over
 * the PRODUCTION wiring: the launcher's socket adapter and its real source
 * resolver (a `cmd:` source) against a real ArbiterServer holding the law.
 * The agent's environment gets the placeholder, never the value; the egress
 * gate releases the value at the source's bound host and asks anywhere else.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { loadPolicyFileStrict } from "../../arbiter/policy/policy-file-validate.js";
import { applyEnvSecrets, socketSecretArbiter } from "../../launcher/src/secret-setup.js";
import { emptyMutation } from "../../launcher/src/backend/types.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { stateAxes } from "../../arbiter/test/axes.js";

stateAxes("secrets"); // confidentiality ON

const VALUE = "gho_ENVSOURCE_e2e_7731";

test("a cmd: source fills the agent's environment with a placeholder that is released only at its bound host", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-envsrc-"));
  const file = join(dir, "policy.yaml");
  writeFileSync(file, `version: 1
env:
  sources:
    - name: MY_SERVICE_CREDENTIAL_FROM_CMD
      source: "cmd:printf '%s\\\\n' ${VALUE}"
      bindings: [api.github.com]
`);
  const sock = join(dir, "a.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0, policyDocument: loadPolicyFileStrict(file).config,
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  try {
    await client.connect();
    const mut = emptyMutation();
    const logs: string[] = [];
    const res = await applyEnvSecrets({ confidentiality: true } as LaunchPlan, { PATH: process.env["PATH"] }, mut, {
      arbiter: socketSecretArbiter(sock), log: (m) => logs.push(m),
    });
    const placeholder = mut.env["MY_SERVICE_CREDENTIAL_FROM_CMD"];
    assert.ok(placeholder && placeholder.startsWith("$MDU:nomodel_Env["), `${placeholder} (${logs.join(" | ")})`);
    assert.ok(!JSON.stringify(mut.env).includes(VALUE), "the value never enters the agent's environment");
    assert.deepEqual(res.masked, ["MY_SERVICE_CREDENTIAL_FROM_CMD"]);

    const at = async (destination: string) =>
      await client.desymbolizationDecision({ symbol: placeholder!, boundary: "network", destination });
    assert.equal((await at("api.github.com")).allow, true, "released at the bound host");
    const elsewhere = await at("pastebin.com");
    assert.equal(elsewhere.allow, false, "not released elsewhere");
    assert.equal("requiresApproval" in elsewhere && elsewhere.requiresApproval, true);
  } finally {
    client.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
