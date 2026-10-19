/**
 * rule-source — "Show in policy.yaml" finds the person's own lines for each
 * Rules row id (dashboard.md §4.25g): exact text, line numbers, the comment
 * directly above an entry, and the same identity the compiled law uses.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { locateRule } from "../../src/rule-source.js";

const HOME = "/home/u";
const FILE = [
  "# my law",                                              // 1
  "version: 1",                                            // 2
  "lists:",                                                // 3
  "  my-services: [api.github.com]",                       // 4
  "paths:",                                                // 5
  "  - { path: \"~/proj\", level: no-model }",        // 6
  "  # the test env is fake",                              // 7
  "  - path: ~/proj/test/.env/",                           // 8
  "    level: public",                                     // 9
  "    recursive: false",                                  // 10
  "",                                                      // 11
  "  - { path: \"**/ws-*/memo/**\", level: any-model, bindings: [example.com] }", // 12
  "#  - { path: \"/home/u/old\", level: public }",         // 13
  "inbound:",                                              // 14
  "  url: { default: UNTRUSTED, trustedList: [pypi.org, docs.python.org] }", // 15
  "  dir:",                                                // 16
  "    trustedList:",                                      // 17
  "      - /srv/docs",                                     // 18
  "user_rules:",                                           // 19
  "  - id: r-0001",                                        // 20
  "    kind: release",                                     // 21
  "    to: { host: api.example.com }",                     // 22
  "    mode: allow",                                       // 23
  "  - { id: r-0002, kind: release, to: { host: \"*.pastebin.com\" }, mode: block }", // 24
  "destinations:",                                         // 25
  "  - { host: Registry.Example, connect: allow }",        // 26
  "  - { host: db.example, port: 5432, connect: allow }",  // 27
  "rules:",                                                // 28
  "  egress:untrusted-destination: { mode: block }",       // 29
  "apps:",                                                 // 30
  "  - { app: psql, output: clear }",                      // 31
  "",
].join("\n");

const at = (id: string) => locateRule(FILE, id, HOME);

test("a lock is found by the compiled path: `~` expanded, trailing slash dropped, block or flow style", () => {
  assert.deepEqual(at("lock:/home/u/proj"), { found: true, start: 6, lines: ['  - { path: "~/proj", level: no-model }'], mark: [6] });
  const env = at("lock:/home/u/proj/test/.env");
  assert.equal(env.found, true);
  assert.ok(env.found);
  assert.equal(env.start, 7, "the comment directly above is shown with it");
  assert.deepEqual(env.lines, ["  # the test env is fake", "  - path: ~/proj/test/.env/", "    level: public", "    recursive: false"], "no trailing blank line");
  assert.deepEqual(env.mark, [8, 9, 10], "the comment is context, not the rule");
  const pat = at("lock:**/ws-*/memo/**");
  assert.ok(pat.found);
  assert.deepEqual([pat.start, pat.mark], [12, [12]]);
  assert.equal(at("lock:/home/u/old").found, false, "a commented-out entry is not a rule");
});

test("user rules, destinations, dispositions and program rules each find their own lines", () => {
  const r1 = at("r-0001");
  assert.ok(r1.found);
  assert.deepEqual([r1.start, r1.lines.length], [20, 4]);
  const r2 = at("r-0002");
  assert.ok(r2.found);
  assert.equal(r2.start, 24);
  const reg = at("connect:tcp:registry.example:443");
  assert.ok(reg.found, "host lower-cased, port 443 by default, as the compiled id");
  assert.equal(reg.start, 26);
  const db = at("connect:tcp:db.example:5432");
  assert.ok(db.found);
  assert.equal(db.start, 27);
  const d = at("disposition:egress:untrusted-destination");
  assert.ok(d.found);
  assert.deepEqual([d.start, d.mark], [29, [29]]);
  const app = at("app:psql");
  assert.ok(app.found);
  assert.equal(app.start, 31);
});

test("a trusted source shows its category with the line that names it marked", () => {
  const url = at("trusted-origin:url:docs.python.org");
  assert.ok(url.found);
  assert.deepEqual([url.start, url.mark], [15, [15]]);
  const dir = at("trusted-origin:dir:/srv/docs");
  assert.ok(dir.found);
  assert.deepEqual([dir.start, dir.lines.length, dir.mark], [16, 3, [18]]);
});

test("a rule not written in the file says where it comes from instead", () => {
  const miss = at("r-0099");
  assert.deepEqual(miss, { found: false, reason: "This rule is not written in policy.yaml. It comes from Mandu's built-in settings." });
  assert.equal(locateRule("version: 1\n", "lock:/x", HOME).found, false, "no paths section at all");
  assert.equal(locateRule("paths:\n  - { path: [broken\n", "lock:/x", HOME).found, false, "an item that does not parse is skipped, never thrown");
});

test("the guard's host lists (unix_sockets:, write_protect:) sit between rules without breaking their lines", () => {
  // sandbox-security-review-2026-09-28: keys with no Rules row of their own.
  const text = [
    "apps:",                                                  // 1
    "  - { app: psql, output: clear }",                       // 2
    "unix_sockets:",                                          // 3
    "  allow: [~/.local/run/helper.sock, \"@my-helper\"]",      // 4
    "write_protect:",                                         // 5
    "  deny: [~/bin]",                                        // 6
    "  unprotect: [~/.gitconfig]",                            // 7
    "user_rules:",                                            // 8
    "  - { id: r-0001, kind: release, to: { host: api.example.com }, mode: allow }", // 9
    "",
  ].join("\n");
  const app = locateRule(text, "app:psql", HOME);
  assert.ok(app.found);
  assert.deepEqual([app.start, app.lines], [2, ["  - { app: psql, output: clear }"]], "the app's lines end at the next key");
  const r = locateRule(text, "r-0001", HOME);
  assert.ok(r.found);
  assert.equal(r.start, 9);
  assert.equal(locateRule(text, "lock:/home/u/bin", HOME).found, false, "a write_protect path is not a lock");
});
