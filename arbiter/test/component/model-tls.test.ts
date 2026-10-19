/**
 * e2e — plan 12 D3 through the REAL arbiter over its socket:
 *   - a policy file with `tls:` loads, and `modelEndpoints` carries the
 *     compiled `tls` (absolute paths, pins) to the clients that dial it;
 *   - the declared client key is a secret file: `discoverSecrets` returns it
 *     even though it lies outside every root the caller walks (outside HOME),
 *     at `no-model`, and `pathConfidentiality`-style lookups say the same;
 *   - a hand edit that names a key that does not match its certificate is
 *     refused at reload, and the law in force keeps the old `tls`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { mintTlsFixtures } from "../helpers/tls-fixtures.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the client key is masked under the confidentiality axis

const fx = mintTlsFixtures();

const law = (key: string): string => `version: 1
models:
  - name: corp
    url: https://llm.corp.example/v1
    wire: openai-chat
    model: q
    local: true
    tls:
      ca_file: ${fx!.caCert}
      pin_sha256: [ "${fx!.serverPin}" ]
      client_cert: ${fx!.clientCert}
      client_key: ${key}
`;

async function waitFor(pred: () => boolean | Promise<boolean>, ms: number, what: string): Promise<void> {
  const deadline = Date.now() + ms;
  while (!(await pred())) {
    if (Date.now() > deadline) assert.fail(`timed out: ${what}`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

test("tls rides modelEndpoints; the client key is a no-model secret wherever it lives; a mismatched key is refused at reload", { skip: fx === null ? "openssl is not on PATH" : false }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-model-tls-e2e-"));
  const home = mkdtempSync(join(tmpdir(), "mandu-model-tls-home-"));
  const file = join(dir, "policy.yaml");
  writeFileSync(file, law(fx!.clientKey));
  const sock = join(dir, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: file, policyPollMs: 40,
  });
  await arbiter.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  try {
    const [corp] = await client.modelEndpoints();
    assert.deepEqual(corp!.tls, { caFile: fx!.caCert, pinSha256: [fx!.serverPin], clientCert: fx!.clientCert, clientKey: fx!.clientKey });

    // The key lies in the fixture dir: outside `home`, the only root walked.
    const found = await client.discoverSecrets([home], home);
    const key = found.find((f) => f.path === fx!.clientKey);
    assert.ok(key, `the declared client key is discovered: ${JSON.stringify(found)}`);
    assert.equal(key!.level, "no-model");
    assert.ok(!found.some((f) => f.path === fx!.clientCert), "the certificate is not a secret");

    // A reload naming a key that does not match: refused; the law keeps the old tls.
    writeFileSync(file, law(fx!.strayKey));
    const t = new Date(Date.now() + 5_000);
    utimesSync(file, t, t);
    await waitFor(() => {
      const s = arbiter["policyDocs"].status;
      return !s.valid && s.problems.join("\n").includes("client_key does not match client_cert");
    }, 10_000, "the refused reload was never reported");
    assert.equal((await client.modelEndpoints())[0]!.tls?.clientKey, fx!.clientKey, "the law in force is kept");
  } finally {
    client.close();
    await arbiter.close();
    rmSync(dir, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
    fx?.cleanup();
  }
});
