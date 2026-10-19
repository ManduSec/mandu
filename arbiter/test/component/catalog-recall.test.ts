/**
 * catalog-recall e2e — the credential corpus through the REAL ArbiterServer
 * and ArbiterClient (docs/design/confidentiality/secret-discovery.md §2): `discoverSecrets`
 * over a synthetic HOME registers every corpus file, and `registerSecret`
 * mints a symbol for each whose twin (what the agent reads in its place)
 * carries no secret byte. The wire carries paths only; no content comes back
 * but the twin.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";
import { CREDENTIAL_CORPUS } from "../fixtures/credential-corpus.js";

stateAxes("secrets"); // confidentiality ON: the twins exist only on this axis

test("every corpus credential is discovered and registered over the wire, and no twin carries its secret", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-recall-e2e-"));
  const home = join(dir, "home");
  for (const e of CREDENTIAL_CORPUS) {
    const p = join(home, e.path);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, e.content);
  }
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, policyPollMs: 0,
  });
  await server.listen();
  const client = new ArbiterClient(join(dir, "a.sock"));
  try {
    await client.connect();
    const report = await client.discoverSecretsReport([home], home);
    assert.ok(!JSON.stringify(report).includes("CANARY"), "discovery returns paths, never contents");
    const found = new Set(report.files.map((f) => f.path));
    const missed = CREDENTIAL_CORPUS.filter((e) => !found.has(join(home, e.path))).map((e) => e.path);
    assert.deepEqual(missed, []);
    for (const e of CREDENTIAL_CORPUS) {
      const r = await client.registerSecret({ path: join(home, e.path), home });
      assert.ok(r.symbol, `${e.path}: registered (${r.reason})`);
      // A structured twin comes back as `twin`; a whole-file twin IS the symbol.
      const twin = r.twin ?? r.symbol!;
      assert.ok(!twin.includes(e.secret), `${e.path}: the twin carries no secret byte [${r.shape ?? "whole"}]`);
      // A URL's user or password in pip.conf is percent-encoded (pip decodes
      // it; plan 10 §11.13.1), and npm's _password is base64: decode both forms.
      const decoded = [twin, decodeURIComponent(twin), ...[...twin.matchAll(/_password=([A-Za-z0-9+/=]+)/g)].map((m) => Buffer.from(m[1]!, "base64").toString("utf8"))];
      assert.ok(decoded.some((t) => /\$MDU:nomodel_/.test(t)), `${e.path}: the twin holds a placeholder:\n${twin}`);
    }
  } finally {
    client.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a documentation page named for credentials is not a credential file; one labelled in policy.yaml is, and reaches the model only as a secret symbol", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-recall-doc-e2e-"));
  const home = join(dir, "home");
  const put = (rel: string, body: string) => {
    const p = join(home, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, body);
    return p;
  };
  const kernelDoc = put("src/linux/Documentation/security/credentials.rst", "Credentials in Linux\n====\n");
  const siteDoc = put("proj/site/credentials.html", "<h1>How we store credentials</h1>\n");
  const labelled = put("proj/notes/credentials.md", "prod db password: DOC_LABELLED_CANARY_91\n");
  const store = put("proj/credentials.txt", "token=TXT_STORE_CANARY_92\n");
  const aws = put(".aws/credentials", "[default]\naws_secret_access_key=AWS_CANARY_93\n");
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, policyPollMs: 0,
    policyDocument: { paths: [{ path: "**/notes/credentials.md", level: "no-model" }] },
  });
  await server.listen();
  const client = new ArbiterClient(join(dir, "a.sock"));
  try {
    await client.connect();
    const found = new Set((await client.discoverSecretsReport([home], home)).files.map((f) => f.path));
    assert.ok(!found.has(kernelDoc), "the kernel's credentials.rst is documentation");
    assert.ok(!found.has(siteDoc), "so is a credentials.html page");
    for (const p of [labelled, store, aws]) assert.ok(found.has(p), `${p} is discovered`);
    assert.equal((await client.pathLevel(kernelDoc)).level, "public");
    assert.deepEqual(await client.pathLevel(labelled), { level: "no-model", bindings: [], axis: true, rule: "label:**/notes/credentials.md" });
    const r = await client.symbolizeFull({ tool: "Read", value: "prod db password: DOC_LABELLED_CANARY_91\n", field: "content", origin: labelled });
    assert.match(r.symbol, /\$MDU:nomodel_/, "the labelled page's content is a secret symbol");
    assert.ok(!r.symbol.includes("DOC_LABELLED_CANARY_91"), "the token is opaque");
  } finally {
    client.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
