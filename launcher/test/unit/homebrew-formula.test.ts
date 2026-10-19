/**
 * homebrew-formula — packaging/homebrew/mandu.rb stays in step with the
 * package: valid Ruby, the package's license, a Node formula at or past the
 * floor's major, and the version the tarball URL names. (Its url/sha256 are
 * placeholders until the public host exists; the formula says so.)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { NODE_FLOOR } from "../../src/node-floor.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const FORMULA = join(ROOT, "packaging", "homebrew", "mandu.rb");
const PKG = JSON.parse(readFileSync(join(ROOT, "launcher", "package.json"), "utf8")) as { version: string; license: string };

test("the Homebrew formula matches the package: license, Node floor, version", () => {
  const src = readFileSync(FORMULA, "utf8");
  assert.match(src, new RegExp(`license "${PKG.license.replace(/[.+]/g, "\\$&")}"`));
  const node = /depends_on "node@(\d+)"/.exec(src)?.[1];
  assert.ok(node && Number(node) >= Number(NODE_FLOOR.split(".")[0]), `node@${node} vs floor ${NODE_FLOOR}`);
  assert.match(src, new RegExp(`mandusec-mandu-${PKG.version.replace(/\./g, "\\.")}\\.tgz`), "the url names the current version");
  assert.match(src, /TODO\(first public tag\)/, "the placeholders are marked");
});

test("the formula is valid Ruby", { skip: spawnSync("sh", ["-c", "command -v ruby"]).status !== 0 && "ruby not installed" }, () => {
  const r = spawnSync("ruby", ["-c", FORMULA], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
});
