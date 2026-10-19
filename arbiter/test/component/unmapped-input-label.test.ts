/**
 * unmapped-input-label.test.ts — plan 10 §11.11 over the real IPC: `classify`
 * for a tool the session's spec does not map reads every string of its input
 * for labeled paths; a mapped tool keeps reading only its named params; the
 * confidentiality axis OFF adds nothing.
 *
 * Mandu-new test. A real ArbiterServer on a temp socket, the real client.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const CREDS = join(homedir(), ".aws", "credentials"); // the catalog's no-model prefix

async function stack(confidentiality: boolean) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-unmapped-label-"));
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({ socketPath: sock, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality, integrity: false });
  await s.listen();
  const c = new ArbiterClient(sock);
  await c.connect();
  const session = `oc-${process.pid}-${confidentiality ? 1 : 0}`;
  await c.setSessionSpec({ sessionKey: session, spec: "openclaw-agent", requestedBy: "unmapped-input-label e2e" });
  return { c, session, done: async () => { c.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("an unmapped tool naming a secret path under any key classifies secret; a mapped tool reads only its named params", async () => {
  const k = await stack(true);
  try {
    const unmapped = await k.c.classify({
      tool: "acme_blob_reader", value: "[default]\naws_secret_access_key = …", boundary: "model_context",
      sessionKey: k.session, params: { job: { inputs: [{ target: CREDS }] } },
    });
    assert.equal(unmapped.confidentiality, "no-model", unmapped.reason);
    assert.match(unmapped.reason, /unmapped tool/);

    const quiet = await k.c.classify({
      tool: "acme_blob_reader", value: "hello", boundary: "model_context",
      sessionKey: k.session, params: { target: "/tmp/notes.md", query: "weather" },
    });
    assert.equal(quiet.confidentiality, "public", quiet.reason);

    const mapped = await k.c.classify({
      tool: "read", value: "hello", boundary: "model_context",
      sessionKey: k.session, params: { path: "/tmp/notes.md", note: CREDS },
    });
    assert.equal(mapped.confidentiality, "public", "a mapped tool's unrelated key is not read (unchanged)");
  } finally {
    await k.done();
  }
});

test("confidentiality axis OFF: an unmapped tool's input adds no level", async () => {
  const k = await stack(false);
  try {
    const r = await k.c.classify({
      tool: "acme_blob_reader", value: "x", boundary: "model_context",
      sessionKey: k.session, params: { target: CREDS },
    });
    assert.equal(r.confidentiality, undefined);
  } finally {
    await k.done();
  }
});
