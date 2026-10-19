/**
 * clean-tree-release.test.ts — the pure parts of the path-derived mask's
 * clean-tree release (docs/design/confidentiality/clean-tree-release.md):
 * the tools (R1), the placeholder test (R2), the counterfactual lookup and
 * the word directories (R4), and the content checks beyond the value-only
 * release's (R7c, R7d).
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  PATH_RELEASE_TOOLS, bareCredentialToken, callHoldsPlaceholder, counterfactualLookup, pathReleaseContentProblem, wordDirectories,
} from "../../policy/clean-tree-release.js";
import { commandDirsReached } from "../../policy/claude-code-inbound.js";
import { directoryMayChange, unresolvedDirChange, type LabelLookup } from "../../policy/secret-catalog.js";
import type { LabelDecision } from "../../policy/path-labels.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const ENV = "/ws/storefront/.env";
const DOC = "/ws/memo/plan.md";
const label = (level: "no-model" | "public", via: string): LabelDecision => ({ level, bindings: [], via });
/** The engine's own lookup: the document and the `.env` labelled. */
const base: LabelLookup = Object.assign(
  (p: string): LabelDecision | null => p === DOC ? label("no-model", DOC) : p === ENV ? label("no-model", ENV) : p === "/ws/public.env" ? label("public", p) : null,
  { roots: () => [{ path: DOC, level: "no-model" as const }, { path: ENV, level: "no-model" as const }] },
);
const onDisk = new Set([ENV, DOC, "/ws/memo/.env", "/ws/public.env"]);
const places = (o: { sources?: string[]; dirs?: string[] | null; words?: string[] } = {}) => ({
  words: new Set(o.words ?? ["Stop tracking .env", "old creds/../../memo/.env", "HEAD:my creds.env"]),
  credentialFiles: new Set([ENV]), registered: new Set([ENV, DOC]), exists: (p: string) => onDisk.has(p),
  sources: new Set(o.sources ?? []), dirs: o.dirs === undefined ? ["/ws", "/ws/storefront"] : o.dirs,
});

test("R1: shell command tools only", () => {
  for (const t of ["Bash", "bash", "shell", "exec_command", "local_shell", "exec"]) assert.ok(PATH_RELEASE_TOOLS.has(t), t);
  for (const t of ["Read", "read", "view", "BashOutput", "mcp__x__run", "WebFetch"]) assert.ok(!PATH_RELEASE_TOOLS.has(t), t);
});

test("R2: a placeholder anywhere in the call, any case", () => {
  assert.equal(callHoldsPlaceholder(["git status", { command: "git status" }]), false);
  assert.equal(callHoldsPlaceholder(["echo $MDU:nomodel_Read[abcd]"]), true);
  assert.equal(callHoldsPlaceholder([undefined, { command: ["sh", "-c", "echo mdu:x"] }]), true);
  const loop: Record<string, unknown> = {};
  loop["self"] = loop;
  assert.equal(callHoldsPlaceholder([loop]), true, "an input that cannot be serialized is held to carry one");
});

test("R4: the counterfactual answers C, empty places and relative tokens read only there; never a source, a document, a ~ token", () => {
  const f = counterfactualLookup(base, places({ sources: ["cat .env memo/plan.md"] }));
  assert.equal(f(ENV)?.level, "public", "a file in C");
  assert.equal(f(DOC)?.level, "no-model", "a document keeps its label");
  assert.equal(f("/ws/.env")?.level, "public", "an empty place where a token naming C is also read");
  assert.equal(f("/ws/config/.env.production"), null, "an empty place no token links to C (review round 3: git history)");
  assert.equal(f("old/.env"), null, "a relative token that names no file in C anywhere");
  assert.equal(f("/ws/memo/.env"), null, "an unregistered file on disk keeps the catalog's reading");
  assert.equal(f("cat .env memo/plan.md"), null, "a source string is never answered");
  assert.equal(f(".env")?.level, "public", "read in /ws (empty) and /ws/storefront (C)");
  assert.equal(f("x.env"), null, "empty in both: no link to C (review round 3)");
  assert.equal(f("~/.env"), null);
  assert.equal(f("a\nb"), null);
  assert.equal(f("/ws/a/../.env"), null, "an unnormalized absolute path is no empty place");
  const memo = counterfactualLookup(base, places({ dirs: ["/ws/storefront", "/ws/memo"] }));
  assert.equal(memo(".env"), null, "read in /ws/memo too, where an unregistered .env lies");
  assert.equal(memo("plan.md"), null, "read in /ws/memo, where the document lies");
  const unknown = counterfactualLookup(base, places({ dirs: null }));
  assert.equal(unknown(".env"), null, "no known directories: the token keeps its reading");
  const pub = counterfactualLookup(base, places({ dirs: ["/ws"] }));
  assert.equal(pub("public.env"), null, "a place a label calls public, but no link to C (review round 3)");
  const both = counterfactualLookup(base, places({ dirs: ["/ws", "/ws/storefront"] }));
  assert.equal(both("Stop tracking .env")?.level, "public", "a blank-holding message, empty everywhere");
  assert.equal(both("cat x --y z.env"), null, "a blank-holding string that is no word of the command (the whole command, spelled otherwise)");
  // each guard alone (exclusion-flags.md, implementation round 3): a source
  // that is also a word is still never answered
  const both2 = counterfactualLookup(base, places({ dirs: ["/ws", "/ws/storefront"], sources: ["grep x memo z.env"], words: ["grep x memo z.env"] }));
  assert.equal(both2("grep x memo z.env"), null, "a never-answered string, even as a word");
  assert.equal(both("/ws/storefront/Stop tracking .env")?.level, "public", "its absolute reading");
  assert.equal(both("old creds/../../memo/.env"), null, "a blank-holding token that reaches a file on disk");
  assert.equal(both("HEAD:my creds.env"), null, "a blank-holding REV:path token (git reads its store, not the disk)");
  assert.equal(both("/ws/HEAD:my creds.env"), null, "and its absolute reading");
  assert.deepEqual(f.roots!().map((r) => r.path), [DOC], "C's literal root is dropped, the document's kept");
});

test("R4: word directories follow plain cds only", () => {
  const dirs = (c: string, start: string | null = "/ws") => wordDirectories(c, start, (x, s) => commandDirsReached(x, s), { directoryMayChange, unresolvedDirChange });
  assert.deepEqual(dirs("git status -- .env"), ["/ws"]);
  assert.deepEqual(dirs("(cd storefront && git rm -q --cached .env && git status)"), ["/ws", "/ws/storefront"]);
  assert.deepEqual(dirs("cd storefront && git log -- .env"), ["/ws", "/ws/storefront"], "the start directory is always a place");
  assert.equal(dirs("git status", null), null, "no start directory");
  for (const c of [
    "bash -c 'cd ../memo && cat .env'", "git -C memo show HEAD:.env", "cd storefront; popd; cat .env",
    "cd $X && cat .env", "cd - && cat .env", "cd storefront || cat .env", "eval 'cd memo' && cat .env",
    "\\cd memo && cat .env", "c''d memo && cat .env", "git --work-tree=memo status .env", "a\ncd memo",
    "C=cd; $C memo; cat .env", "cd memo & cat .env", "{ cd memo; cat .env; }",
  ]) assert.equal(dirs(c), null, c);
  assert.deepEqual(dirs("(cd storefront && git log -- .env 2>&1)"), ["/ws", "/ws/storefront"], "a 2>&1 redirection is no background job");
});

test("R7c, R7d: a credential shape or a named file's own value refuses", () => {
  assert.equal(pathReleaseContentProblem("!! .env\nRef 'refs/heads/main' was rewritten\n", ["pa55wd", "sk_test_51x"]), null);
  assert.equal(pathReleaseContentProblem("old: ghp_0123456789abcdefABCDEF0123456789abcd\n", []), "a credential shape");
  assert.equal(pathReleaseContentProblem("db pa55wd ok\n", ["pa55wd"]), "a masked value of a named credential file");
  assert.equal(pathReleaseContentProblem("pin 12345\n", ["12345"]), null, "under 6 characters is not looked for (note §4 item 1)");
});

test("R7e: a bare token that reads as a credential; git's ids, UUIDs, paths and words do not", () => {
  assert.equal(bareCredentialToken("old line: Zx9Kp2mWq8Lr5Tv3Nc7Bd1"), "Zx9Kp2mWq8Lr5Tv3Nc7Bd1");
  for (const t of [
    "Rewrite 196115d0a1b2c3d4e5f60718293a4b5c6d7e8f90 (1/3)", "error: unable to read 0d1f2e3c4b5a69788796a5b4c3d2e1f0a9b8c7d6",
    "uuid 123e4567-e89b-12d3-a456-426614174000", "src/components/CheckoutButtonContainer.tsx | 12 ++--",
    "Ref 'refs/heads/main' was rewritten", " + 3f2a1b9...8c7d6e5 main -> main (forced update)",
  ]) assert.equal(bareCredentialToken(t), null, t);
  assert.equal(pathReleaseContentProblem("x Zx9Kp2mWq8Lr5Tv3Nc7Bd1\n", []), "a bare token that reads as a credential");
});
