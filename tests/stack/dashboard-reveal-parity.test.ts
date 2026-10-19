/**
 * dashboard-reveal-parity — the dashboard ArbiterEventSource's `resolveSymbol`
 * over a REAL ArbiterServer (the production wiring, no mock), CONTRIBUTING.md
 * parity rule. The product page's "show what was hidden" (dashboard.md
 * §4.25b) relies on it being ONE level: agent-page checks every nested token
 * for a secret before it asks for that token, which only works if the
 * arbiter hands nested tokens back unexpanded. The dashboard e2e pins the
 * route over a mock socket; this pins that the real op behaves the way the
 * mock claims.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("full"); // both axes: a secret level is recorded on mint

test("ArbiterEventSource.resolveSymbol against the real arbiter: one level, nested tokens stay tokens, unknown → null", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-integ-reveal-"));
  const socketPath = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({ socketPath, humanSocketPath: humanSockIn(tmp), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {} });
  await arbiter.listen();
  const client = new ArbiterClient(socketPath);
  await client.connect();
  const source = new ArbiterEventSource({ socketPath });
  try {
    const secret = await client.symbolize({ tool: "Read", value: "API_KEY=sk-live-parity", field: "env", confidentiality: "any-model", sessionKey: "s" });
    const inner = await client.symbolize({ tool: "Read", value: "# Notes: ship it", field: "notes", sessionKey: "s" });
    const outerValue = `1\t${inner}\n2\t${secret}`;
    const outer = await client.symbolize({ tool: "Read", value: outerValue, sessionKey: "s" });

    const shallow = await source.resolveSymbol(outer);
    assert.equal(shallow, outerValue, "one level: the nested tokens come back unexpanded");
    assert.doesNotMatch(String(shallow), /sk-live-parity/, "a nested secret is not expanded by the shallow op");
    assert.equal(await source.resolveSymbol(inner), "# Notes: ship it");
    assert.equal(await source.resolveSymbol("$MDU:Read[ffff].nope"), null, "an unknown symbol is null");

    // Contrast: the deep op the /dev/ inspector uses DOES expand the secret,
    // which is exactly why the product page must not use it.
    assert.match(await source.desymbolize(outer), /sk-live-parity/);
  } finally {
    source.close();
    client.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
