#!/usr/bin/env node
/**
 * bin/mandu — the published @mandusec/mandu entry (packaging.md §5). Runs the
 * bundled launcher (dist/mandu.mjs) with plain node: the bundle's
 * Layout.detect sees it under dist/ → installed mode → spawns the sibling
 * service bundles. No tsx, no repo checkout, no per-package node_modules.
 *
 * Dev note: a source checkout reaches this bin through launcher/mandu-run.sh,
 * which sets MANDU_SHIM_CHECKOUT=<repo root>: before anything else this node
 * then runs the checkout prelude (scripts/checkout-launch.mjs, packaging.md
 * §5.1), which loads the secrets file into process.env and runs the bundle
 * only when its dist/ is fresh (rebuilt first if not; tsx over src/ when it
 * cannot be). The bundle's Layout.detect then picks the dev layout's bundled
 * form, not installed. The variable is the shim's alone and is removed before
 * anything reads the environment. If the bundle is absent it says how to
 * build it rather than failing obscurely.
 */
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const bundle = join(here, "..", "dist", "mandu.mjs");

const checkout = process.env["MANDU_SHIM_CHECKOUT"];
if (checkout !== undefined) {
  delete process.env["MANDU_SHIM_CHECKOUT"];
  let prelude;
  try {
    prelude = (await import(pathToFileURL(join(here, "..", "scripts", "checkout-launch.mjs")).href)).checkoutPrelude;
  } catch (err) {
    // A checkout with no prelude must not run its bundle unchecked.
    console.error(`mandu: MANDU_SHIM_CHECKOUT is set but this is not a checkout's launcher (${err instanceof Error ? err.message : String(err)}).`);
    process.exit(2);
  }
  await prelude({ repoRoot: checkout, argv: process.argv.slice(2) });
}

if (!existsSync(bundle)) {
  console.error(
    `mandu: bundle missing (${bundle}) — run 'npm run build:bundle' in a dev checkout, ` +
    `or reinstall @mandusec/mandu.`,
  );
  process.exit(2);
}

// Node >= 22.13.0 floor (the arbiter bundle uses node:sqlite, unflagged since
// 22.13). Fail early with an actionable message rather than a cryptic runtime
// error. This runs BEFORE the bundle loads, so it cannot import
// src/node-floor.ts; the constant is duplicated and test/unit/node-floor.test.ts
// pins it to NODE_FLOOR.
const NODE_FLOOR = "22.13.0";
const nodeMeetsFloor = (version, floor) => {
  const v = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version);
  const f = /^v?(\d+)\.(\d+)\.(\d+)/.exec(floor);
  if (!v || !f) return false;
  for (let i = 1; i <= 3; i++) {
    if (Number(v[i]) > Number(f[i])) return true;
    if (Number(v[i]) < Number(f[i])) return false;
  }
  return true;
};
if (!nodeMeetsFloor(process.versions.node, NODE_FLOOR)) {
  console.error(
    `mandu: Node ${process.versions.node} is too old — Mandu needs Node >= ${NODE_FLOOR} ` +
    `(node:sqlite is unflagged from 22.13; try: nvm install 22).`,
  );
  process.exit(2);
}

process.title = "mandu"; // canonical ps title (runtime-instances.md §7)
const { main } = await import(pathToFileURL(bundle).href);
main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => { console.error(err instanceof Error ? err.message : String(err)); process.exit(2); },
);
