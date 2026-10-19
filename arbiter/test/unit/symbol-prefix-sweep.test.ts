/**
 * symbol-prefix-sweep.test — the retired symbol token prefixes stay retired.
 *
 * The symbol token was renamed twice on 2026-09-27: first away from the
 * agentOS-era prefix to the DualView one, then to `$MDU:`, the product name
 * (docs/design/confidentiality/confidentiality.md). Every
 * scanner, desymbolizer, reply-filter hold, sentinel-imitation guard and egress
 * gate matches the CURRENT prefix only, so a stray old-prefix literal left in shipped
 * code would be a detector that silently matches nothing: an ingress that no
 * longer symbolizes, or an egress gate that no longer sees the token. This sweep
 * fails on either old-prefix literal anywhere in the tree outside `private/`.
 *
 * There are NO allowed spots: nothing resolves the old prefix (an old token
 * arriving in untrusted data is plain text and is symbolized like any other).
 * The only legacy READ path is the fs-sync shadow-repo commit tag, whose
 * namespaces are bare words (`LEGACY_TAG_NAMESPACES` in fs-sync/src/git.ts) and
 * never the dollar-token spelling.
 *
 * The needles are built from parts so this file does not match itself, and the
 * file carries the rename script's keep marker (mandu-rename: keep-legacy) so a
 * re-run of the mechanical rename leaves it alone.
 *
 * Pure file sweep: no protection axis is involved.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4); none is exercised

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const RETIRED = [["$", "A", "O", "S"].join(""), ["$", "D", "V"].join("")];
/** A retired needle followed by a letter is a different word (`$DVX` in a
 *  negative test is not the token); every real spelling continues with `:`,
 *  `_` or a non-letter. */
const isToken = (text: string, end: number) => !/[A-Za-z]/.test(text[end] ?? "");

const SKIP_DIRS = new Set([".git", "node_modules", "target", "dist", "private", ".venv", "__pycache__"]);
const BINARY_EXT = /\.(png|jpe?g|gif|ico|webp|pdf|pptx|docx|xlsx|zip|gz|tgz|tar|woff2?|ttf|otf|so|a|o|bin|wasm|sqlite|db)$/i;

/** The tree's files: the tracked ones when this is a git checkout (untracked
 *  scratch such as other agents' worktrees is not shipped), else a walk. */
function treeFiles(): string[] {
  const r = spawnSync("git", ["-C", REPO_ROOT, "ls-files", "-z"], { encoding: "utf8" });
  if (r.status === 0 && r.stdout.length > 0) {
    return r.stdout
      .split("\0")
      .filter((p) => p !== "" && !p.startsWith("private/") && !BINARY_EXT.test(p))
      .map((p) => join(REPO_ROOT, p))
      .filter((p) => {
        try {
          return statSync(p).isFile();
        } catch {
          return false; // deleted in the working tree
        }
      });
  }
  return [...walk(REPO_ROOT)];
}

function* walk(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const p = join(dir, name);
    let st;
    try {
      st = statSync(p);
    } catch {
      continue; // a dangling link or a file removed mid-walk
    }
    if (st.isDirectory()) yield* walk(p);
    else if (st.isFile() && !BINARY_EXT.test(name) && st.size < 64 * 1024 * 1024) yield p;
  }
}

test("no retired symbol-prefix literal anywhere in the tree (outside private/)", () => {
  const hits: string[] = [];
  let scanned = 0;
  for (const file of treeFiles()) {
    scanned++;
    const text = readFileSync(file, "latin1");
    for (const needle of RETIRED) {
      let at = text.indexOf(needle);
      while (at !== -1) {
        if (isToken(text, at + needle.length)) {
          const line = text.slice(0, at).split("\n").length;
          hits.push(`${relative(REPO_ROOT, file)}:${line}: ${text.slice(at, at + 24).split("\n")[0]}`);
        }
        at = text.indexOf(needle, at + 1);
      }
    }
  }
  assert.ok(scanned > 200, `the sweep walked the tree (scanned ${scanned} files from ${REPO_ROOT})`);
  assert.deepEqual(hits, [], `retired symbol prefix found; use $MDU: instead:\n${hits.join("\n")}`);
});

test("the sweep's needles really are the retired prefixes and the current one is distinct", () => {
  assert.deepEqual(RETIRED.map((n) => n.length), [4, 3]);
  for (const n of RETIRED) assert.ok(!"$MDU:".startsWith(n), n);
  assert.ok(isToken(":", 0) && isToken("_", 0) && isToken("", 0) && !isToken("X", 0));
});
