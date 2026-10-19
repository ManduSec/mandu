/**
 * printer-git-credential-prefix — every git credential helper is a printer
 * (plan 13 D8 (11), the `git-credential-` prefix class: the maintainer's
 * decision of 2026-10-07).
 *
 * A git credential helper prints `password=<secret>` on `get`: that is its
 * protocol (gitcredentials(7)). The ones git builds in (`git-credential-store`,
 * `-cache`) are links of git, a printer by name or hash, but the standalone
 * ones are programs of their own, under no printer name: libsecret's,
 * `-osxkeychain`, the Credential Manager (`git-credential-manager`, a .NET
 * program), `git-credential-netrc` (a Perl script in git's contrib), and
 * any third party's (`git-credential-oauth`, `-1password`, …). So any program
 * whose name starts with `git-credential-` is a printer, in the three copies
 * (arbiter, dashboard, guard), and so is a script pin naming such a script
 * (`{ app: perl, script: …/git-credential-netrc }`): it admits nothing, its
 * opener is no reader, and `prints: nothing` cannot lift it.
 *
 * Each NEW test was red on the code before (only `git-credential-store` was
 * named). The CONTROL tests (`git-credential-store`, and a script pin of
 * another name) were green. Axes: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decideOpen, entryAdmitsNothing, matchReader, printerOpenVerdict, readerPrints, trustVerdictSubject } from "../../policy/flow-taint.js";
import { scanProgramHashes } from "../../policy/program-hashes.js";
import { policyWarnings } from "../../policy/policy-file-validate.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const H = "b".repeat(64);
const SYS = { exeSystem: true, loaderEnv: [] as string[] };
const ENV = "/w/.env";
/** Standalone helpers, as packages and third parties install them. */
const HELPERS = [
  "git-credential-libsecret", "/usr/lib/git-core/git-credential-libsecret",
  "/usr/share/doc/git/contrib/credential/libsecret/git-credential-libsecret",
  "git-credential-manager", "/usr/local/bin/git-credential-manager", "git-credential-manager-core",
  "git-credential-osxkeychain", "git-credential-netrc", "git-credential-gnome-keyring", "git-credential-oauth", "git-credential-1password",
];
const NETRC_SCRIPT = "/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc";
const script = (path: string) => ({ path, sha256: H, system: true, isolated: true, traced: false });
const perl = (path: string) => ({ exe: "/usr/bin/perl", sha256: H, ...SYS, script: script(path) });

test("NEW: any program named git-credential-* is a printer, by name or path, and admits nothing even vouched for", () => {
  for (const n of HELPERS) {
    assert.ok(readerPrints(n), n);
    assert.ok(entryAdmitsNothing(n), n);
    assert.ok(entryAdmitsNothing({ app: n, prints: "nothing" }), `${n}: the human's word cannot lift it`);
    assert.ok(entryAdmitsNothing({ app: "helper", path: n.startsWith("/") ? n : `/usr/bin/${n}`, sha256: H }), `${n}: by its pinned path`);
  }
});
test("CONTROL: git-credential-store (git itself) is a printer; names that only resemble the prefix are not", () => {
  assert.ok(readerPrints("git-credential-store") && entryAdmitsNothing("git-credential-store"));
  for (const n of ["git-credential-", "mygit-credential-x", "credential-helper", "git-lfs", "gh"]) assert.equal(readerPrints(n), false, n);
});

test("NEW: { app: git-credential-libsecret, prints: nothing } (or -manager) reads no file raw under any ask mode, never asked; policyWarnings names it a printer", () => {
  for (const app of ["git-credential-libsecret", "git-credential-manager"]) {
    const o = { exe: `/usr/lib/git-core/${app}`, sha256: H, ...SYS };
    for (const ask of ["never", "known", "always"] as const) {
      const d = decideOpen(ENV, { readers: [{ app, prints: "nothing" }] }, o, { ask });
      assert.equal(d.verdict, "deny", `${app} ${ask}: ${d.why}`);
      assert.match(d.why, /prints or copies/);
      assert.equal(decideOpen(ENV, { readers: [{ app, prints: "nothing" }], others: "twin" }, o, { ask }).verdict, "twin", `${app} ${ask}`);
    }
    const w = policyWarnings({ version: 1, paths: [{ path: ENV, level: "no-model", readers: [{ app, prints: "nothing" }] }] });
    assert.ok(w.some((l) => l.startsWith(`paths[0].readers[0]: ${app} is a printer`) && /password=/.test(l) && /prints: nothing cannot change that/.test(l)), w.join("\n"));
  }
});

test("NEW: a script pin named git-credential-* admits nothing: perl running git-credential-netrc reads no file raw, is never asked, and no answer about it counts", () => {
  const pin = { app: "perl", script: NETRC_SCRIPT, prints: "nothing" as const };
  assert.ok(entryAdmitsNothing(pin), "the pin admits nothing");
  const o = perl(NETRC_SCRIPT);
  assert.equal(matchReader([pin], o), null, "no entry names it");
  for (const ask of ["never", "known", "always"] as const) {
    const d = decideOpen(ENV, { readers: [pin] }, o, { ask });
    assert.equal(d.verdict, "deny", `${ask}: ${d.why}`);
    assert.match(d.why, /git-credential-netrc/);
    assert.equal(decideOpen(ENV, {}, o, { ask }).verdict, "twin", `${ask}: unlisted, the twin every program gets, never asked`);
  }
  const subject = trustVerdictSubject("/usr/bin/perl", H, { script: NETRC_SCRIPT, scriptSha256: H });
  assert.ok(subject !== null && printerOpenVerdict(subject), `an answer about it applies to nothing: ${subject}`);
  const w = policyWarnings({ version: 1, paths: [{ path: ENV, level: "no-model", readers: [pin] }] });
  assert.ok(w.some((l) => l.startsWith("paths[0].readers[0]: perl is a printer") || (l.startsWith("paths[0].readers[0]:") && /git-credential-netrc/.test(l) && /admits nothing/.test(l))), w.join("\n"));
});
test("CONTROL: a script pin of another name, vouched for, still reads raw", () => {
  const path = "/opt/tools/load.pl";
  const pin = { app: "perl", script: path, prints: "nothing" as const };
  assert.equal(entryAdmitsNothing(pin), false);
  assert.equal(decideOpen(ENV, { readers: [pin] }, perl(path)).verdict, "raw");
});

test("NEW: the hash scan picks up a helper installed under the prefix", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-gcred-"));
  try {
    writeFileSync(join(dir, "git-credential-libsecret"), "LIBSECRET-HELPER-BYTES");
    writeFileSync(join(dir, "credential-helper"), "OTHER-BYTES");
    const found = scanProgramHashes([dir]);
    assert.deepEqual([...found.prints.keys()], [createHash("sha256").update("LIBSECRET-HELPER-BYTES").digest("hex")]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
