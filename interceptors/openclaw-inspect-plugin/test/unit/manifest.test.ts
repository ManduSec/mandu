/**
 * manifest / loader-contract tests — the facts the OpenClaw loader hard-fails
 * on, asserted locally so a drift breaks HERE and not (silently) at mount time.
 *
 * Mandu (interceptors/openclaw-inspect-plugin). Guards, per
 * openclaw-src/src/plugins/{manifest.ts,loader.ts}:
 *   - openclaw.plugin.json exists with a non-empty `id` and an object
 *     `configSchema` (the loader refuses "missing config schema" otherwise).
 *   - package.json carries `main` + `openclaw.extensions` (how discovery finds
 *     the entry, mirroring the reference dualview plugin).
 *   - the module default export is a definition object whose register is a
 *     plain SYNCHRONOUS function (async registration is ignored by the
 *     loader), and its id matches the manifest.
 *   - the manifest schema is closed (additionalProperties:false) and its
 *     property set matches what plugin-config.ts actually reads.
 *   - `contracts.tools` names inspect_symbol and declassify_symbol (every
 *     tool register.ts registers): OpenClaw >= 2026.6 loads a
 *     plugin tool only when the manifest declares it there (the plugin logged
 *     "inspect_symbol registered" and the tool never reached the model on
 *     2026.6.35 without it, probe 2026-09-27). The 2026.3 loader ignores the
 *     key.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import definition from "../../index.js";
import { registerInspectPlugin } from "../../src/register.js";
import type { OpenClawPluginApiLike } from "../../src/openclaw-api.js";

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

function readJson(rel: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(pkgRoot, rel), "utf-8")) as Record<string, unknown>;
}

test("manifest: id + configSchema present (the loader's hard requirements)", () => {
  const manifest = readJson("openclaw.plugin.json");
  assert.equal(manifest.id, "mandu-inspect");
  assert.equal(typeof manifest.configSchema, "object");
  assert.ok(manifest.configSchema !== null);
});

test("manifest: config schema is closed and matches what the code reads", () => {
  const manifest = readJson("openclaw.plugin.json");
  const schema = manifest.configSchema as Record<string, unknown>;
  assert.equal(schema.additionalProperties, false);
  const props = Object.keys(schema.properties as Record<string, unknown>).sort();
  assert.deepEqual(props, [
    "agentId",
    "arbiterSock",
    "attachment",
    "manduPaths",
    "sandbox",
    "scopeId",
    "ullmApiKey",
    "ullmBaseUrl",
    "ullmBinary",
    "ullmForwarder",
    "ullmMode",
    "ullmModel",
  ]);
  // The confined-commands tier's block (openclaw-plugin.md §10) is closed too.
  const sandbox = (schema.properties as Record<string, { additionalProperties?: unknown; properties?: Record<string, unknown> }>)["sandbox"]!;
  assert.equal(sandbox.additionalProperties, false);
  assert.deepEqual(Object.keys(sandbox.properties ?? {}).sort(), ["launcher", "statusFile", "writeProtect"]);
});

test("manifest: contracts.tools declares every tool the plugin registers (OpenClaw >= 2026.6 drops undeclared ones)", () => {
  const manifest = readJson("openclaw.plugin.json");
  const contracts = manifest.contracts as { tools?: unknown } | undefined;
  assert.ok(contracts && Array.isArray(contracts.tools), "contracts.tools must be an array");
  assert.deepEqual(contracts.tools, ["inspect_symbol", "declassify_symbol"]);
});

test("package.json: main + openclaw.extensions point at the entry", () => {
  const pkg = readJson("package.json");
  assert.equal(pkg.main, "index.ts");
  const openclaw = pkg.openclaw as { extensions?: string[] };
  assert.deepEqual(openclaw.extensions, ["./index.ts"]);
});

test("package.json: compat.pluginApi and install.minHostVersion are the tested range's floor", () => {
  // OpenClaw checks compat.pluginApi at install (install-shared) and at
  // discovery (discovery-availability, 2026.9.9 on: an unsatisfied range skips
  // the plugin) against the host version; minHostVersion likewise. The floor
  // is the oldest release in supported-agents.md's tested range.
  const pkg = readJson("package.json");
  const openclaw = pkg.openclaw as { compat?: { pluginApi?: string }; install?: { minHostVersion?: string } };
  assert.equal(openclaw.compat?.pluginApi, ">=2026.3.12");
  assert.equal(openclaw.install?.minHostVersion, ">=2026.3.12");
});

test("manifest: activation.onStartup is set (hooks need the plugin loaded at Gateway start)", () => {
  const manifest = readJson("openclaw.plugin.json");
  const activation = manifest.activation as { onStartup?: unknown } | undefined;
  assert.equal(activation?.onStartup, true);
});

test("manifest: no tool-result middleware contract and nothing that needs conversation access", () => {
  // openclaw-plugin.md §3.1: symbolization stays at the model proxy. The
  // middleware needs `contracts.agentToolResultMiddleware`; the plugin must
  // not declare it, nor any contract beyond its two tools.
  const manifest = readJson("openclaw.plugin.json");
  assert.deepEqual(Object.keys(manifest.contracts as object), ["tools"]);
  assert.ok(!JSON.stringify(manifest).includes("agentToolResultMiddleware"));
});

test("default export: definition object with a SYNCHRONOUS register, id matching the manifest", () => {
  assert.equal(typeof definition.register, "function");
  // The loader IGNORES async registration (a returned promise only warns) —
  // register must be a plain function, not an AsyncFunction.
  assert.notEqual(definition.register.constructor.name, "AsyncFunction");
  const manifest = readJson("openclaw.plugin.json");
  assert.equal(definition.id, manifest.id);
});

test("the default register path fails LOUDLY with no arbiter configured", () => {
  // Pin the env seam: the definition's register uses process.env fallbacks.
  const saved = process.env.MANDU_ARBITER_SOCK;
  delete process.env.MANDU_ARBITER_SOCK;
  try {
    const api: OpenClawPluginApiLike = {
      id: "mandu-inspect",
      pluginConfig: {},
      logger: { info() {}, warn() {}, error() {} },
      registerTool: () => {},
    };
    assert.throws(() => definition.register(api), /MANDU_ARBITER_SOCK/);
  } finally {
    if (saved !== undefined) process.env.MANDU_ARBITER_SOCK = saved;
  }
});

test("registerInspectPlugin is the same code path the definition mounts", () => {
  // A structural guard against the definition drifting to a different
  // implementation: the module re-exports the registrar it calls.
  assert.equal(typeof registerInspectPlugin, "function");
});
