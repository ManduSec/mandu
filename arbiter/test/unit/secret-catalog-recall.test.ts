/**
 * secret-catalog-recall.test — the catalog recall audit as a regression gate
 * (docs/design/confidentiality/secret-discovery.md §2). Every entry of the credential corpus
 * is laid out in a synthetic HOME; the launch-time walk must register it, and
 * the twin the arbiter renders from it must not contain its secret. A file the
 * catalog must NOT register (source code, templates, public certificates, a
 * project `.npmrc`) is the precision half.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { CREDENTIAL_CORPUS } from "../fixtures/credential-corpus.js";
import { discoverSecretsReport } from "../../policy/secret-discovery.js";
import { secretPathConfidentiality } from "../../policy/secret-catalog.js";
import { extractSecretSpans, renderStructuredTwin, shapeIsExhaustive } from "../../policy/secret-extract.js";

function plantCorpus(): { home: string; cleanup: () => void } {
  const home = mkdtempSync(join(tmpdir(), "mdu-recall-"));
  for (const e of CREDENTIAL_CORPUS) {
    const p = join(home, e.path);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, e.content);
  }
  return { home, cleanup: () => rmSync(home, { recursive: true, force: true }) };
}

test("every corpus credential is registered by the walk (recall 100%)", () => {
  const { home, cleanup } = plantCorpus();
  try {
    const r = discoverSecretsReport([home], home);
    const found = new Set(r.files.map((f) => f.path));
    const missed = CREDENTIAL_CORPUS.filter((e) => !found.has(join(home, e.path))).map((e) => `${e.path} (${e.tool})`);
    assert.deepEqual(missed, [], `${CREDENTIAL_CORPUS.length - missed.length}/${CREDENTIAL_CORPUS.length} registered`);
    assert.equal(r.truncated, false);
  } finally {
    cleanup();
  }
});

test("every corpus credential's twin carries no secret byte", () => {
  const leaks: string[] = [];
  for (const e of CREDENTIAL_CORPUS) {
    const x = extractSecretSpans(`/h/${e.path}`, e.content);
    // No spans ⇒ the registry twins the whole file, except an EXHAUSTIVE
    // shape, whose twin is then its own text (registry.ts mintFields).
    const twin = x.spans.length
      ? renderStructuredTwin(e.content, x.spans, () => "$MDU:nomodel_T[0]")
      : shapeIsExhaustive(x.shape) ? e.content : "$MDU:nomodel_T[0]";
    if (twin.includes(e.secret)) leaks.push(`${e.path} [${x.shape}]`);
  }
  assert.deepEqual(leaks, []);
});

test("the pruned cache directory is still skipped, except the credential the catalog names in it", () => {
  const { home, cleanup } = plantCorpus();
  try {
    mkdirSync(join(home, ".cache", "pip", "wheels"), { recursive: true });
    writeFileSync(join(home, ".cache", "pip", "wheels", "credentials.json"), '{"token":"not-walked"}');
    const r = discoverSecretsReport([home], home);
    const paths = r.files.map((f) => f.path);
    assert.ok(paths.includes(join(home, ".cache", "huggingface", "token")));
    assert.ok(!paths.some((p) => p.includes("/.cache/pip/")), "the rest of ~/.cache stays pruned");
  } finally {
    cleanup();
  }
});

test("an extension-less name ending in secret(s) is a secret", () => {
  for (const p of ["w/jwt-secret", "w/client_secret", "w/secrets", "w/secret"]) {
    assert.equal(secretPathConfidentiality(`/home/u/${p}`, "/home/u").rule, "shape:*secret*", p);
  }
});

test("precision: source files, templates, public certificates and project config are not registered", () => {
  const H = "/home/u";
  for (const p of [
    "w/src/secrets.ts", "w/src/secret_manager.py", "w/lib/secret.go", "w/docs/secrets.md",
    "w/.npmrc", "w/.yarnrc.yml", "w/package.json", "w/Cargo.toml", "w/pyproject.toml", "w/settings.xml",
    "w/certs/ca.pem", "w/certs/server.crt", "w/monkey.json", "w/keyboard.json", "w/hotkey.json",
    "w/.env.example", "w/.env.dist", "w/secrets.example.yaml", "w/prod.env.sample", "w/config/app.yaml",
    "w/src/keys.ts", "w/terraform.tf", "w/Documentation/securityfs-secrets-coco",
  ]) {
    assert.equal(secretPathConfidentiality(`${H}/${p}`, H).rule, null, p);
  }
});
