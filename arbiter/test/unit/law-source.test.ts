/**
 * law-source.test — describeLawSource (policy-surface.md §9.8 "law source").
 *
 * The invariant: the reported law source matches what the loader would
 * actually enforce — a missing or unparseable file reports kind "builtin"
 * (the built-ins ARE the law in force), never a claimed "file"; a loaded file
 * reports which sections it set, so the panel can say what the YAML layered
 * on without re-reading it browser-side.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { describeLawSource } from "../../policy/load-policy.js";

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "mandu-lawsource-"));
});
after(() => {
  rmSync(dir, { recursive: true, force: true });
});

test("no policyPath → builtin, no path fields", () => {
  assert.deepEqual(describeLawSource(undefined, "/anywhere"), { kind: "builtin" });
});

test("configured but missing file → builtin with found:false (the built-ins ARE the law)", () => {
  const src = describeLawSource("no-such.yaml", dir);
  assert.equal(src.kind, "builtin");
  assert.equal(src.found, false);
  assert.equal(src.configuredPath, "no-such.yaml");
  assert.equal(src.resolvedPath, resolve(dir, "no-such.yaml"));
  assert.equal(src.sections, undefined);
});

test("loaded file → kind file with the sections it actually set", () => {
  writeFileSync(join(dir, "policy.yaml"), [
    "inbound:",
    "  url:",
    "    default: UNTRUSTED",
    "    trustedList: [api.example]",
    "  command:",
    "    - id: git-status",
    "tools:",
    "  WebFetch:",
    "    inbound: UNTRUSTED",
    "  Read:",
    "    outbound: not_resolve",
  ].join("\n"));
  const src = describeLawSource("policy.yaml", dir);
  assert.equal(src.kind, "file");
  assert.equal(src.found, true);
  assert.equal(src.resolvedPath, resolve(dir, "policy.yaml"));
  assert.deepEqual(src.sections, {
    url: true,
    channel: false,
    dir: false,
    commandEntries: 1,
    toolOverrides: 2,
  });
});

test("unparseable file → builtin with found:false, never a throw", () => {
  writeFileSync(join(dir, "broken.yaml"), "inbound: [unclosed");
  const src = describeLawSource("broken.yaml", dir);
  assert.equal(src.kind, "builtin");
  assert.equal(src.found, false);
});
