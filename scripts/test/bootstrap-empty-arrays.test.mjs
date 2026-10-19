// bootstrap-empty-arrays — scripts/bootstrap.sh runs under `set -u`, and the
// bash macOS ships (3.2) treats `${arr[*]}` / `${arr[@]}` of an EMPTY array as
// an unbound variable: the bootstrap died at its launcher-bundle step on every
// clean macOS install (GitHub's macOS wrapper suite, 2026-10-08:
// "INSTALL_FAIL[*]: unbound variable"). An array the script starts empty
// (`NAME=()`) may be expanded only with a default (`${NAME[*]-}`) or on a line
// that first checks it is non-empty (`${#NAME[@]}" -gt 0`).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SRC = readFileSync(join(ROOT, "scripts", "bootstrap.sh"), "utf8");

/** Each `${NAME[*]}` / `${NAME[@]}` of an array the script starts empty,
 *  on a line that neither gives it a default nor checks its length first. */
export function unguardedEmptyArrayExpansions(src) {
  const empty = [...src.matchAll(/^\s*([A-Z_][A-Z0-9_]*)=\(\)\s*$/gm)].map((m) => m[1]);
  const out = [];
  src.split("\n").forEach((line, i) => {
    if (/^\s*#/.test(line)) return;
    for (const name of empty) {
      const uses = [...line.matchAll(new RegExp(`\\$\\{${name}\\[[*@]\\]([^}]*)\\}`, "g"))];
      const guarded = new RegExp(`\\$\\{#${name}\\[@\\]\\}"?\\s*-gt\\s*0`).test(line);
      for (const u of uses) if (!u[1].startsWith("-") && !guarded) out.push(`${i + 1}: ${line.trim()}`);
    }
  });
  return out;
}

test("bootstrap.sh expands no empty-able array without a default or a length check (bash 3.2 under set -u)", () => {
  assert.deepEqual(unguardedEmptyArrayExpansions(SRC), []);
});

test("the rule catches the 2026-10-08 line and passes its fix", () => {
  const before = 'INSTALL_FAIL=()\nif [[ " ${INSTALL_FAIL[*]} " != *" launcher "* ]]; then :; fi\n';
  assert.equal(unguardedEmptyArrayExpansions(before).length, 1);
  assert.deepEqual(unguardedEmptyArrayExpansions(before.replace("[*]}", "[*]-}")), []);
  assert.deepEqual(unguardedEmptyArrayExpansions('X=()\nif [ "${#X[@]}" -gt 0 ]; then echo "${X[*]}"; fi\n'), []);
});

test("the fixed form is safe under set -u with an empty array (the shell this host has)", () => {
  const r = spawnSync("bash", ["-c", 'set -u; A=(); if [[ " ${A[*]-} " != *" launcher "* ]]; then echo ok; fi'], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), "ok");
});
