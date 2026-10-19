/**
 * e2e — the `read-blocked` posture section through the REAL arbiter IPC op
 * (docs/design/agents/handling-prompt.md §2; macOS, 2026-09-29).
 *
 * The proxy reports the session's secret posture as
 * `capabilities.secretPosture`; the arbiter's `handlingPrompt` op hands the
 * capabilities to the prompt builder as they came. This pins that wire: a
 * real ArbiterServer in the `secrets` mode renders the "blocked credential
 * files" section for `read-blocked` and nothing else for any other posture,
 * and an arbiter with the confidentiality axis OFF never renders it (no file
 * is blocked when nothing protects secrets).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

async function withArbiter(confidentiality: boolean, fn: (c: ArbiterClient) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mdu-hp-"));
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, integrity: false, confidentiality,
  });
  await server.listen();
  const c = new ArbiterClient(join(dir, "a.sock"));
  await c.connect();
  try {
    await fn(c);
  } finally {
    c.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

// The proxy's report, typed as the proxy sends it (the client's own
// parameter type predates the field; the op forwards capabilities whole).
const caps = (secretPosture?: string): { inspect: boolean; exec: boolean } =>
  ({ inspect: true, exec: true, ...(secretPosture ? { secretPosture } : {}) });

test("secrets mode over IPC: read-blocked adds the section once; confined, gated and no report are byte-identical", async () => {
  await withArbiter(true, async (c) => {
    const base = await c.handlingPrompt("full", caps());
    assert.match(base, /## Secret-labeled symbols/, "the confidentiality axis is on");
    const mac = await c.handlingPrompt("full", caps("read-blocked"));
    assert.equal(mac.split("## Blocked credential files").length, 2);
    assert.match(mac, /Operation not\npermitted/);
    assert.match(mac, /\$MDU:nomodel_Env\[e1e1\]\.GITHUB_TOKEN/);
    for (const p of ["confined", "gated", "unknown-posture"]) assert.equal(await c.handlingPrompt("full", caps(p)), base, p);
  });
});

test("secrets mode over IPC: the no-model subsection carries the one-file rule once, in every posture (handling-prompt.md §10)", async () => {
  await withArbiter(true, async (c) => {
    for (const p of [undefined, "confined", "read-blocked"]) {
      const prompt = await c.handlingPrompt("full", caps(p));
      assert.equal(prompt.split("**Keep a command that names a secret file to that file alone**").length, 2, String(p));
      assert.match(prompt, /read other files \(a `\.env\.example`, a\s+listing, a log\) with separate commands\./);
    }
  });
});

test("confidentiality OFF: no section even for read-blocked (and both axes off is the empty prompt)", async () => {
  await withArbiter(false, async (c) => {
    assert.equal(await c.handlingPrompt("full", caps("read-blocked")), "");
  });
});

test("secrets mode over IPC: a browser agent's capabilities add the Web pages section once; without browser it is absent (handling-prompt.md §11)", async () => {
  const browser = { inspect: false, policyTools: false, exec: false, fsView: false };
  await withArbiter(true, async (c) => {
    const base = await c.handlingPrompt(undefined, browser);
    assert.ok(!base.includes("## Web pages"));
    const web = await c.handlingPrompt(undefined, { ...browser, browser: true });
    assert.equal(web.split("## Web pages").length, 2);
    assert.match(web, /fill or type the placeholder itself/);
    assert.ok(!web.includes("## Data Trust Policy"), "no policy tools");
  });
  await withArbiter(false, async (c) => {
    assert.equal(await c.handlingPrompt(undefined, { ...browser, browser: true }), "");
  });
});
