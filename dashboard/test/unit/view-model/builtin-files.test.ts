/**
 * builtin-files.test — Rules › Built-in protections' Which files fold
 * (dashboard.md §4.25z): the display copy of the arbiter's catalog is well
 * formed (every kind has words and names, no place repeats, the Windows
 * profile's places and the system files are kept apart from the home
 * folder's), the file browser reads the same words, and the fold's copy
 * passes the product vocabulary sweep. Its parity with the arbiter is
 * tests/stack/builtin-files-parity.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  BUILTIN_AGENT_DATA_RULES, BUILTIN_FILE_KINDS, BUILTIN_HOME_PLACES, BUILTIN_RULE_WORDS, BUILTIN_SYSTEM_PLACES,
  BUILTIN_WINDOWS_PLACES, builtinFiles,
} from "../../../src/view-model/builtin-files.js";
import { builtinWords } from "../../../src/view-model/file-browser.js";
import { RETIRED, THIS_MACHINE } from "./retired-words.js";

const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter|catalog|prefix|shape|twin|taint)\b|\$MDU:/i;

test("every kind has words, at least one name and a rule id; no rule id is in two kinds", () => {
  const seen = new Set<string>();
  for (const k of BUILTIN_FILE_KINDS) {
    assert.ok(k.words.trim() !== "", JSON.stringify(k));
    assert.ok(k.names.length > 0 && k.names.every((n) => n.trim() !== "" && !/\s/.test(n)), k.words);
    assert.ok(k.rules.length > 0 && k.rules.every((r) => r.startsWith("shape:")), k.words);
    for (const r of k.rules) { assert.ok(!seen.has(r), `${r} is in two kinds`); seen.add(r); }
    assert.equal(new Set(k.names).size, k.names.length, `${k.words}: a name repeats`);
  }
  for (const r of BUILTIN_AGENT_DATA_RULES) assert.ok(!seen.has(r), r);
});

test("no place repeats; the home folder's are under ~/, the Windows profile's and the system files apart", () => {
  const all = [...BUILTIN_HOME_PLACES, ...BUILTIN_SYSTEM_PLACES, ...BUILTIN_WINDOWS_PLACES];
  assert.equal(new Set(all).size, all.length, "a place repeats");
  const windows = (p: string) => p === "~/_netrc" || p.startsWith("~/AppData/");
  assert.ok(BUILTIN_HOME_PLACES.every((p) => p.startsWith("~/") && !windows(p)), "the home list holds only home places");
  assert.ok(BUILTIN_WINDOWS_PLACES.every(windows), "the Windows list holds only the profile's stores");
  assert.ok(BUILTIN_SYSTEM_PLACES.every((p) => p.startsWith("/")), "system files are absolute");
  assert.ok(BUILTIN_HOME_PLACES.length > 60, "the home folder's places are all there");
});

test("the fold: kinds with a capital and every name, the places, the closing lines, and Your rules as a link", () => {
  const f = builtinFiles();
  assert.deepEqual(f.kinds.map((k) => k.names), BUILTIN_FILE_KINDS.map((k) => [...k.names]));
  assert.equal(f.kinds[0]!.words, "Environment files");
  assert.deepEqual(f.kinds[0]!.names, [".env", ".env.*", "*.env", ".envrc"]);
  assert.ok(f.kinds.every((k) => /^[A-Z]/.test(k.words)), "each kind starts with a capital");
  assert.equal(f.kinds.find((k) => k.words === "A tool's saved sign-in")!.where, "in a tool's own folder");
  assert.deepEqual(f.places, [...BUILTIN_HOME_PLACES]);
  assert.deepEqual(f.system, [...BUILTIN_SYSTEM_PLACES]);
  assert.ok(!f.places.some((p) => p.includes("AppData")), "the Windows places are one line, not chips");
  assert.deepEqual(f.also.map((a) => a.text), [
    "In ~/.ssh, its public files are not: *.pub, known_hosts, authorized_keys, allowed_signers.",
    "And the same stores in a Windows profile, under WSL.",
    "And OpenCode's and Goose's own data, wherever it is kept.",
  ]);
  assert.deepEqual(f.also[0]!.parts.filter((p) => p.kind === "code").map((p) => p.text), ["~/.ssh", "*.pub", "known_hosts", "authorized_keys", "allowed_signers"]);
  assert.equal(f.change.text, "To make one of these readable by the AI, give it a rule of your own under Your rules: your rules are checked first.");
  assert.deepEqual(f.change.parts.filter((p) => p.kind === "link"), [{ kind: "link", text: "Your rules", to: "your-rules" }]);
  assert.notEqual(builtinFiles(), builtinFiles(), "a fresh object each time");
});

test("the fold's words pass the product vocabulary sweep", () => {
  const f = builtinFiles();
  const copy = [...f.kinds.flatMap((k) => [k.words, k.where ?? ""]), ...f.also.map((a) => a.text), f.found, f.change.text].join("\n");
  assert.doesNotMatch(copy, FORBIDDEN, copy.match(FORBIDDEN)?.[0]);
  assert.doesNotMatch(copy, RETIRED, copy.match(RETIRED)?.[0]);
  assert.doesNotMatch(copy, THIS_MACHINE);
});

test("the file browser says each built-in rule in the fold's words (one set)", () => {
  for (const k of BUILTIN_FILE_KINDS) for (const r of k.rules) assert.equal(builtinWords(r, "/home/u"), `Built in: ${k.words}`, r);
  assert.equal(BUILTIN_RULE_WORDS["shape:.env*"], "environment files");
  assert.equal(builtinWords("content:secret-key", "/home/u"), "Built in: a saved password or key Mandu found in it");
  assert.equal(builtinWords("content:personal-document", "/home/u"), "Built in: a personal document Mandu recognised");
  assert.equal(builtinWords("prefix:~/.aws", "/home/u"), "Built in: ~/.aws");
});
