/**
 * policy-yaml-splice.test — a changed policy document written INTO the
 * person's own policy.yaml text, comments and layout kept
 * (policy-surface.md §8.4.6 "Comments are kept"; first-session tour item 17:
 * a held hand edit re-saved with the agent's lock lost its comments).
 *
 * Pins:
 *   - what did not change is copied byte for byte, comments included;
 *   - a new sequence item is added at the end of its list, a removed one goes
 *     with the comment lines directly above it, a changed item is spliced in
 *     place (its comments kept) when matched by its id / path;
 *   - a new top-level key is added, a removed one dropped;
 *   - the compact sequence form (`paths:` then `- …` at column 0) works;
 *   - a text this does not understand (flow style at the top, a document
 *     marker, an anchor, CRLF, tabs, a text that does not read as `before`)
 *     answers null, never a wrong file;
 *   - THE PROPERTY: over a corpus of commented files and every edit op,
 *     every answer reads back as exactly the edited document (or is null).
 *
 * No privilege, no axis read; stated for the manifest.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { isDeepStrictEqual } from "node:util";
import yaml from "js-yaml";

import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { applyEdits } from "../../policy/policy-edit.js";
import { POLICY_DUMP_OPTIONS, spliceYaml } from "../../policy/policy-yaml-splice.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // states its axes (protection-modes.md §4); none is read

const read = (t: string): PolicyFileConfig => (yaml.load(t) ?? {}) as PolicyFileConfig;
const same = (a: unknown, b: unknown): boolean =>
  isDeepStrictEqual(yaml.load(yaml.dump(a, POLICY_DUMP_OPTIONS)), yaml.load(yaml.dump(b, POLICY_DUMP_OPTIONS)));

const HAND = [
  "# Our policy. Ask Dana before loosening anything.",
  "version: 1",
  "",
  "paths:",
  "  # deploy secrets",
  "  - path: ~/repo/.env   # prod",
  "    level: no-model",
  "    bindings: [api.stripe.com]  # billing only",
  "  - path: ~/repo/id_rsa",
  "    level: no-model",
  "",
  "# temporary",
  "user_rules:",
  "  - { id: hand, kind: release, to: { host: paste.example }, mode: allow }   # until Friday",
  "lists:",
  "  vendors: [a.example, b.example]  # our vendors",
  "",
].join("\n");

function edit(text: string, edits: unknown[]): { doc: PolicyFileConfig; out: string | null } {
  const before = read(text);
  const r = applyEdits(before, edits, { now: Date.parse("2026-10-09T00:00:00Z") });
  assert.ok(r.ok, JSON.stringify(r));
  return { doc: r.document, out: spliceYaml(text, before, r.document) };
}

test("nothing changed: the text back byte for byte", () => {
  assert.equal(spliceYaml(HAND, read(HAND), read(HAND)), HAND);
});

test("a new lock is added at the end of paths:, every other line as written", () => {
  const { doc, out } = edit(HAND, [{ op: "lock-path", path: "~/repo/**/*.pem", level: "no-model" }]);
  assert.ok(out !== null);
  assert.ok(same(read(out), doc));
  const added = yaml.dump([doc.paths!.at(-1)], POLICY_DUMP_OPTIONS).replace(/^/gm, "  ").trimEnd();
  assert.equal(out, HAND.replace("    level: no-model\n\n# temporary", `    level: no-model\n${added}\n\n# temporary`));
});

test("a changed lock is spliced in place: the comments inside it and above it stay", () => {
  const { doc, out } = edit(HAND, [{ op: "lock-path", path: "~/repo/.env", level: "no-model", bindings: ["api.stripe.com", "api.example"] }]);
  assert.ok(out !== null);
  assert.ok(same(read(out), doc));
  assert.match(out, /  # deploy secrets\n  - path: ~\/repo\/\.env   # prod\n    level: no-model\n/);
  // The changed line is rewritten; the comment at its end stays on it
  // (tour 17 after !1095: a pinned reader kept `# the backup job`).
  assert.match(out, /\n    bindings:  # billing only\n      - api\.stripe\.com\n      - api\.example\n/, "the changed line is rewritten, its comment kept");
  assert.match(out, /api\.example/);
  assert.match(out, /# until Friday/);
});

test("a removed lock goes with the comments directly above it; the rest stays", () => {
  const { doc, out } = edit(HAND, [{ op: "unlock-path", path: "~/repo/.env" }]);
  assert.ok(out !== null);
  assert.ok(same(read(out), doc));
  assert.doesNotMatch(out, /deploy secrets|# prod/);
  assert.match(out, /^paths:\n  - path: ~\/repo\/id_rsa\n/m);
  assert.ok(out.startsWith("# Our policy."));
});

test("a removed rule drops its key; a new key is added", () => {
  const { doc, out } = edit(HAND, [{ op: "retire-rule", id: "hand" }, { op: "allow-connect", host: "registry.npmjs.org" }]);
  assert.ok(out !== null, "spliced");
  assert.ok(same(read(out), doc));
  assert.match(out, /# Our policy\./);
  assert.match(out, /vendors: \[a\.example, b\.example\]  # our vendors/);
});

test("the compact sequence form (items at their key's indent) is spliced too", () => {
  const text = "version: 1\npaths:\n# mine\n- path: /a   # one\n  level: no-model\n";
  const { doc, out } = edit(text, [{ op: "lock-path", path: "/b", level: "no-model" }]);
  assert.ok(out !== null);
  assert.ok(same(read(out), doc));
  assert.ok(out.startsWith(text), out);
});

test("shapes it does not splice answer null: flow at the top, markers, anchors, CRLF, tabs, a text that is not `before`", () => {
  const doc = read(HAND);
  const after = { ...doc, version: 1, destinations: [{ host: "x.example", connect: "allow" }] } as PolicyFileConfig;
  assert.equal(spliceYaml("{ version: 1 }\n", { version: 1 }, { version: 1, paths: [] }), null);
  assert.equal(spliceYaml("---\n" + HAND, doc, after), null);
  assert.equal(spliceYaml(HAND.replace(/\n/g, "\r\n"), doc, after), null);
  assert.equal(spliceYaml(HAND.replace("# temporary", "#\ttemporary"), doc, after), null);
  assert.equal(spliceYaml(HAND, { version: 1 }, after), null, "the text does not read as before");
  const anchored = "version: 1\nlists:\n  v: &v [a.example]\n  w: *v\n";
  const out = spliceYaml(anchored, read(anchored), { ...read(anchored), lists: { v: ["a.example"], w: ["c.example"] } });
  assert.ok(out === null || same(read(out), { version: 1, lists: { v: ["a.example"], w: ["c.example"] } }));
});

test("THE PROPERTY: over commented files and every edit op, an answer always reads back as exactly the edited document", () => {
  const files = [
    HAND,
    "version: 1\npaths:\n- path: /a\n  level: no-model\n# end\n",
    "# only a comment\nversion: 1\n",
    "version: 1\npaths:\n  - { path: /a, level: no-model }   # flow item\n  - path: /b\n    level: any-model\n    recursive: false\ninbound:\n  url:\n    trustedList: [docs.example]  # docs\n",
    "version: 1\nrules:\n  egress:untrusted-destination: ask   # ask me\ndestinations:\n  - host: registry.npmjs.org\n    connect: allow\n",
  ];
  const edits: unknown[][] = [
    [{ op: "lock-path", path: "/a", level: "no-model", bindings: ["x.example"] }],
    [{ op: "lock-path", path: "/b", level: "no-model" }],
    [{ op: "lock-path", path: "/new", level: "any-model", recursive: false }],
    [{ op: "release", to: { host: "paste.example" }, mode: "block" }],
    [{ op: "trust-origin", kind: "url", pattern: "wiki.example" }],
    [{ op: "distrust-origin", kind: "url", pattern: "docs.example" }],
    [{ op: "allow-connect", host: "pypi.org" }],
    [{ op: "remove-connect", host: "registry.npmjs.org" }],
    [{ op: "set-disposition", rule: "egress:untrusted-destination", mode: "block" }],
    [{ op: "list", name: "vendors", add: ["c.example"], remove: ["a.example"] }],
    [{ op: "tool-inbound", tool: "WebFetch", trust: "UNTRUSTED" }],
  ];
  let spliced = 0;
  for (const f of files) {
    const before = read(f);
    for (const e of edits) {
      const r = applyEdits(before, e, { now: Date.parse("2026-10-09T00:00:00Z") });
      if (!r.ok) continue;
      const out = spliceYaml(f, before, r.document);
      if (out === null) continue;
      spliced++;
      assert.ok(same(read(out), r.document), `${JSON.stringify(e)} over:\n${f}\n→\n${out}`);
      // Every comment of the original whose line was not rewritten survives
      // when nothing was removed: at least the first line's comment.
      if (f.startsWith("#")) assert.ok(out.startsWith(f.split("\n")[0]!));
    }
  }
  assert.ok(spliced >= 20, `most edits splice (${spliced})`);
});
