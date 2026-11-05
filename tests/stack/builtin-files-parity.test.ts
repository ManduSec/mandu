/**
 * builtin-files-parity — Rules › Built-in protections' Which files fold
 * (dashboard/src/view-model/builtin-files.ts, dashboard.md §4.25z) names
 * what the arbiter's default-secret catalog (arbiter/policy/secret-catalog.ts)
 * matches, no more and no less.
 *
 * The dashboard does not import the arbiter (the arbiter-client
 * convention), so it keeps a display copy. A drift would make the page
 * promise a file Mandu leaves readable, or miss one it keeps secret:
 *
 *   1. the home folder's places, the system files and the Windows profile's
 *      stores are the arbiter's `SECRET_PREFIXES`, in order;
 *   2. each example name of each kind, under a temp folder, gets one of that
 *      kind's rule ids from `secretPathConfidentiality`;
 *   3. every basename shape the arbiter has is a kind: a name built from
 *      each of the arbiter's own name anchors (`catalogNameAnchors`, which
 *      every shape must have) is probed, so a new shape fails here until
 *      the copy names it;
 *   4. the agents' data line covers the agents' data shapes; the template
 *      names and the `~/.ssh` public files the fold says are left out are
 *      left out.
 *
 * Axes explicit: secrets (the catalog is a confidentiality rule; no axis is
 * read).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SECRET_PREFIXES, catalogNameAnchors, secretPathConfidentiality, type NameAnchor } from "../../arbiter/policy/secret-catalog.js";
import {
  BUILTIN_AGENT_DATA_RULES, BUILTIN_FILE_KINDS, BUILTIN_HOME_PLACES, BUILTIN_SYSTEM_PLACES, BUILTIN_TEMPLATE_EXAMPLES,
  BUILTIN_WINDOWS_PLACES, SSH_PUBLIC_EXAMPLES,
} from "../../dashboard/src/view-model/builtin-files.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

/** A temp home (the catalog's `~`) and a project folder under it. */
function withHome(fn: (home: string) => void): void {
  const home = mkdtempSync(join(tmpdir(), "mandu-builtin-files-"));
  try { fn(home); } finally { rmSync(home, { recursive: true, force: true }); }
}

/** An example name as a file name: each `*` stands for "x". */
const concrete = (name: string): string => name.replace(/\*/g, "x");

test("the places are the arbiter's SECRET_PREFIXES, in order: home folder, system files, Windows profile", () => {
  const windows = (p: string) => p === "~/_netrc" || p.startsWith("~/AppData/");
  assert.deepEqual([...BUILTIN_HOME_PLACES], SECRET_PREFIXES.filter((p) => p.startsWith("~/") && !windows(p)), "copy the home places into builtin-files.ts");
  assert.deepEqual([...BUILTIN_SYSTEM_PLACES], SECRET_PREFIXES.filter((p) => !p.startsWith("~/")), "copy the system files");
  assert.deepEqual([...BUILTIN_WINDOWS_PLACES], SECRET_PREFIXES.filter(windows), "copy the Windows profile's stores");
  assert.equal(BUILTIN_HOME_PLACES.length + BUILTIN_SYSTEM_PLACES.length + BUILTIN_WINDOWS_PLACES.length, SECRET_PREFIXES.length);
});

test("each example name of each kind gets that kind's rule from the arbiter", () => {
  withHome((home) => {
    for (const k of BUILTIN_FILE_KINDS) {
      for (const name of k.names) {
        const path = join(home, "proj", k.inToolFolder ? ".tool" : "", concrete(name));
        const rule = secretPathConfidentiality(path, home).rule;
        assert.ok(rule !== null && k.rules.includes(rule), `${k.words}: ${name} → ${rule}`);
      }
    }
  });
});

/** File names the conditions of `a` admit, the parts it leaves open empty
 *  or "x", so a shape that wants more than its anchor (`.tfstate` at the
 *  end) still meets one of them. */
function namesFor(a: NameAnchor): string[] {
  if (a.exact !== undefined) return [a.exact];
  const names = new Set<string>();
  for (const x of ["", "x"]) for (const y of ["", "x"]) names.add(`${a.prefix ?? ""}${x}${a.contains ?? ""}${y}${a.suffix ?? ""}`);
  return [...names].filter((n) => n !== "");
}

test("every basename shape of the arbiter is a kind of the copy (a name from each of its anchors, in and out of a tool's folder)", () => {
  const copied = new Set(BUILTIN_FILE_KINDS.flatMap((k) => k.rules));
  const found = new Set<string>();
  withHome((home) => {
    for (const name of catalogNameAnchors().flatMap(namesFor)) {
      for (const dir of [join(home, "proj"), join(home, "proj", ".tool"), join(home, ".config", "tool")]) {
        const rule = secretPathConfidentiality(join(dir, name), home).rule;
        if (rule?.startsWith("shape:")) found.add(rule);
      }
    }
  });
  const missing = [...found].filter((r) => !copied.has(r));
  assert.deepEqual(missing, [], "a shape the arbiter matches has no kind in builtin-files.ts: add one");
  assert.deepEqual([...copied].filter((r) => !found.has(r)), [], "a kind names a rule the arbiter no longer has");
});

test("the agents' data line, the templates and ~/.ssh's public files say what the arbiter does", () => {
  withHome((home) => {
    const rules = [
      secretPathConfidentiality(join(home, "xdg", "opencode", "opencode.db"), home).rule,
      secretPathConfidentiality(join(home, "xdg", "goose", "history.txt"), home).rule,
    ];
    assert.deepEqual(rules, [...BUILTIN_AGENT_DATA_RULES]);
    for (const t of BUILTIN_TEMPLATE_EXAMPLES) assert.equal(secretPathConfidentiality(join(home, "proj", t), home).rule, null, t);
    for (const n of SSH_PUBLIC_EXAMPLES) assert.equal(secretPathConfidentiality(join(home, ".ssh", concrete(n)), home).rule, null, n);
    assert.equal(secretPathConfidentiality(join(home, ".ssh", "id_ed25519"), home).rule, "prefix:~/.ssh", "the rest of ~/.ssh stays secret");
  });
});
