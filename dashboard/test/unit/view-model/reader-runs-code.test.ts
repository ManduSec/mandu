/**
 * reader-runs-code: the dashboard's mirror of the printer rule marks a git
 * credential helper of any name (the `git-credential-` prefix class, the
 * maintainer's decision of 2026-10-07) and a script pin so named as
 * admitting nothing, as the arbiter decides (parity with the arbiter's
 * table: tests/stack/reader-identity.test.ts). Red before: only
 * `git-credential-store` was named. Pure view-model logic, no axis.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { entryAdmitsNothing, entryPrints, entryReadsTwin, readerPrints, scriptPrints } from "../../../src/view-model/reader-runs-code.js";

test("a git credential helper of any name is a printer; an entry naming it, or a script pin so named, admits nothing", () => {
  for (const n of ["git-credential-libsecret", "/usr/local/bin/git-credential-manager", "git-credential-osxkeychain", "git-credential-store"]) {
    assert.ok(readerPrints(n), n);
    assert.ok(entryAdmitsNothing({ app: n, prints: "nothing" }), n);
  }
  for (const n of ["git-credential-", "mygit-credential-x", "credential-helper"]) assert.equal(readerPrints(n), false, n);
  const netrc = { app: "perl", script: "/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc", prints: "nothing" };
  assert.ok(scriptPrints(netrc.script));
  assert.ok(entryPrints(netrc) && entryAdmitsNothing(netrc), "the script pin admits nothing");
  assert.equal(entryReadsTwin(netrc), false, "marked as admitting nothing, not as reading the placeholder");
  const other = { app: "perl", script: "/opt/tools/load.pl", prints: "nothing" };
  assert.equal(entryAdmitsNothing(other), false, "a script of another name, vouched for, still reads");
});
