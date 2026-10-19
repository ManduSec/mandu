/**
 * classifier-pack-command.test — `mandu policy classifier-pack`
 * (confidentiality-plan-15-prompt-filter.md §13.5 item 15). Mandu-new.
 *
 * Proves: the command runs the pack writer THIS install ships (the layout's
 * asset, the checkout's source here) under the running node and prints its
 * pack, which pins that node and the shipped classifier; an option the
 * writer does not take is refused before anything runs; a package that does
 * not ship the classifier says so and fails (never an empty pack); the
 * dispatch of `mandu policy` reaches it. The built package is proved by
 * test/component/bundle-smoke.test.ts.
 *
 * Axes: secrets (stated; nothing here reads the axis).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { CLASSIFIER_ASSET, CLASSIFIER_PACK_ASSET, realClassifierPackDeps, runClassifierPack, type ClassifierPackDeps } from "../../src/classifier-pack-command.js";
import { ASSET_SOURCES, Layout } from "../../src/services/layout.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const sha = (p: string): string => createHash("sha256").update(readFileSync(p)).digest("hex");

function capture(over: Partial<ClassifierPackDeps> = {}): { deps: ClassifierPackDeps; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return { deps: { ...realClassifierPackDeps(), out: (s) => out.push(s), err: (s) => err.push(s), ...over }, out, err };
}

test("the classifier and its pack writer are package assets (the manifest and the layout agree)", () => {
  const manifest = JSON.parse(readFileSync(join(REPO, "launcher", "bundle-manifest.json"), "utf8")) as { assets: Record<string, string> };
  for (const key of [CLASSIFIER_ASSET, CLASSIFIER_PACK_ASSET]) {
    assert.equal(manifest.assets[key], ASSET_SOURCES[key], `${key}: bundle-manifest.json and ASSET_SOURCES name the same source`);
    assert.ok(ASSET_SOURCES[key]!.startsWith("arbiter/prompt-filter/plugins/"));
  }
});

test("it prints the pack the shipped writer makes: node and the shipped classifier pinned by SHA-256", () => {
  const layout = Layout.dev(REPO, join(REPO, "launcher"));
  const c = capture();
  assert.equal(runClassifierPack(["--id", "acme-cls", "--categories", "acme.codename"], layout, c.deps), 0, c.err.join(""));
  const pack = c.out.join("");
  const classifier = realpathSync(join(REPO, "arbiter", "prompt-filter", "plugins", "local-classifier.mjs"));
  assert.match(pack, /^pack: acme-cls$/m);
  assert.match(pack, new RegExp(`^  script: ${classifier.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"));
  assert.match(pack, new RegExp(`^  script_sha256: "${sha(classifier)}"$`, "m"));
  assert.match(pack, new RegExp(`^  exec: ${realpathSync(process.execPath).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"));
  assert.match(pack, /category: acme\.codename, level: no-model/);
});

test("an option the writer does not take is refused before anything runs", () => {
  const layout = Layout.dev(REPO, join(REPO, "launcher"));
  let ran = false;
  for (const args of [["--write"], ["--id"], ["--id", "--categories"], ["x"]]) {
    const c = capture({ run: () => { ran = true; return { status: 0, stdout: "", stderr: "" }; } });
    assert.equal(runClassifierPack(args, layout, c.deps), 2, args.join(" "));
    assert.match(c.err.join(""), /classifier-pack: /);
  }
  assert.equal(ran, false);
});

test("a package that does not ship the classifier says so and prints no pack; a failing writer prints none either", () => {
  const layout = { asset: (k: string) => `/pkg/dist/${k}` };
  const missing = capture({ exists: (p) => !p.endsWith("/local-classifier.mjs") });
  assert.equal(runClassifierPack([], layout, missing.deps), 1);
  assert.match(missing.err.join(""), /does not ship the reference classifier \(\/pkg\/dist\/prompt-filters\/local-classifier\.mjs is missing\)/);
  assert.deepEqual(missing.out, []);
  const failing = capture({ exists: () => true, run: () => ({ status: 3, stdout: "pack: half", stderr: "boom\nmore" }) });
  assert.equal(runClassifierPack([], layout, failing.deps), 1);
  assert.match(failing.err.join(""), /pack writer failed \(exit 3\): boom/);
  assert.deepEqual(failing.out, []);
});

test("`mandu policy classifier-pack` reaches it (an unknown option is its refusal, exit 2)", async () => {
  const { runPolicy } = await import("../../src/policy-suggest.js");
  const errs: string[] = [];
  const orig = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((s: string) => { errs.push(String(s)); return true; }) as typeof process.stderr.write;
  try {
    assert.equal(await runPolicy(["classifier-pack", "--bogus"], {}, Layout.dev(REPO, join(REPO, "launcher"))), 2);
  } finally {
    process.stderr.write = orig;
  }
  assert.match(errs.join(""), /mandu policy classifier-pack: unknown option '--bogus'/);
});
