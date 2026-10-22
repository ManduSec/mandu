/**
 * dashboard-account-parity — the launcher's `mandu dashboard --set-password`
 * writer (launcher/src/dashboard-account.ts) and the dashboard's account
 * reader (dashboard/src/account.ts) agree on the file (dashboard.md §6.z).
 * The launcher ships standalone, so the record's format and the hash are
 * mirrored; a drift would leave a person with an account no dashboard
 * accepts, or one the launcher reports wrongly.
 *
 * Pins: a launcher-written account is one the dashboard reads and verifies
 * (right password yes, wrong no); a dashboard-written one (the
 * DASHBOARD_BASIC_AUTH migration) is one the launcher names; the two agree
 * on the constants and the file's place; both refuse the same unsafe file.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as launcher from "../../launcher/src/dashboard-account.js";
import * as dashboard from "../../dashboard/src/account.js";
import { manduPath } from "../../dashboard/src/generated/mandu-paths.js";

test("a launcher-written account verifies in the dashboard, and the other way round", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-acct-parity-"));
  try {
    const a = join(dir, "a", "dashboard-account.json");
    launcher.writeAccount(a, await launcher.makeAccount("alice", "launcher password"));
    const read = dashboard.readAccount(a);
    assert.equal(read.kind, "ok", JSON.stringify(read));
    if (read.kind === "ok") {
      assert.equal(await dashboard.verifyAccount(read.account, "alice", "launcher password"), true);
      assert.equal(await dashboard.verifyAccount(read.account, "alice", "launcher passwor"), false);
    }

    const b = join(dir, "b", "dashboard-account.json");
    dashboard.writeAccount(b, await dashboard.makeAccount("bob", "dashboard password"));
    assert.deepEqual(launcher.accountState(b), { user: "bob" });

    chmodSync(b, 0o644);
    assert.equal(dashboard.readAccount(b).kind, "unsafe");
    assert.ok(launcher.accountState(b) !== null && "unsafe" in launcher.accountState(b)!);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the two copies share the constants and the file's place", () => {
  for (const k of ["ACCOUNT_VERSION", "SCRYPT_N", "SCRYPT_R", "SCRYPT_P", "KEY_LENGTH", "SALT_BYTES", "MIN_PASSWORD_LENGTH", "MAX_FIELD_LENGTH"] as const) {
    assert.equal(launcher[k], dashboard[k], k);
  }
  for (const u of ["", "a:b", " a", "alice", "x".repeat(2000)]) assert.equal(launcher.usernameProblem(u), dashboard.usernameProblem(u), JSON.stringify(u));
  for (const p of ["short", "long enough", "x".repeat(2000)]) assert.equal(launcher.passwordProblem(p), dashboard.passwordProblem(p));
  const env = { MANDU_HOME: "/m" };
  assert.equal(launcher.accountPath(env), manduPath("dashboard-account", env, "/h"));
  assert.equal(launcher.accountPath({ HOME: "/h" }), "/h/.mandu/state/dashboard-account.json");
});
