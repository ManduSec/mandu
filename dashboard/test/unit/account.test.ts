/**
 * account.test — the Mandu dashboard account file (src/account.ts,
 * dashboard.md §6.z): what is on disk, what is refused, how a change is seen.
 *
 * Pins:
 *   - only a salted scrypt hash is written (the password nowhere in the
 *     file, in any encoding), mode 0600, in a 0700 directory; two accounts
 *     with one password get different salts and hashes;
 *   - verify: the right pair passes, a wrong user or password fails, scrypt
 *     runs either way;
 *   - read refuses (`unsafe`) a symlink, a group/world-readable file, a hard
 *     link, another user's file, a non-record, out-of-range parameters;
 *   - a write replaces a planted link instead of following it;
 *   - AccountFile: the first read is the baseline; a later change (a new
 *     hash, a removal, a bad mode) is a change, reported once.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, linkSync, lstatSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { AccountFile, makeAccount, passwordProblem, readAccount, usernameProblem, verifyAccount, writeAccount, type AccountRecord } from "../../src/account.js";
import { tmpDir } from "./tmp-dir.js";

const PASSWORD = "correct horse battery staple";

test("only a salted scrypt hash is written, 0600 in a 0700 directory", async () => {
  const dir = tmpDir("mandu-account-");
  const path = join(dir, "state", "dashboard-account.json");
  const rec = await makeAccount("alice", PASSWORD);
  writeAccount(path, rec);
  const text = readFileSync(path, "utf8");
  for (const form of [PASSWORD, Buffer.from(PASSWORD).toString("base64"), Buffer.from(PASSWORD).toString("hex"), encodeURIComponent(PASSWORD)]) {
    assert.ok(!text.includes(form), `the password is not in the file (${form.slice(0, 8)}…)`);
  }
  const parsed = JSON.parse(text) as AccountRecord;
  assert.equal(parsed.kdf, "scrypt");
  assert.equal(parsed.user, "alice");
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.equal(statSync(join(dir, "state")).mode & 0o777, 0o700);
  const other = await makeAccount("alice", PASSWORD);
  assert.notEqual(other.salt, rec.salt, "a per-account random salt");
  assert.notEqual(other.hash, rec.hash);
  const read = readAccount(path);
  assert.equal(read.kind, "ok");
});

test("verify: the right pair passes; a wrong user or password fails", async () => {
  const rec = await makeAccount("alice", PASSWORD);
  assert.equal(await verifyAccount(rec, "alice", PASSWORD), true);
  assert.equal(await verifyAccount(rec, "alice", PASSWORD + " "), false);
  assert.equal(await verifyAccount(rec, "Alice", PASSWORD), false);
  assert.equal(await verifyAccount(rec, "", ""), false);
  assert.equal(await verifyAccount(rec, "alice", "x".repeat(5000)), false, "an oversized field is refused before scrypt");
});

test("set-time rules: a short password, an empty or ':' username are refused", async () => {
  assert.match(passwordProblem("short") ?? "", /at least 8/);
  assert.equal(passwordProblem(PASSWORD), null);
  assert.match(usernameProblem("") ?? "", /empty/);
  assert.match(usernameProblem("a:b") ?? "", /':'/);
  assert.match(usernameProblem(" a") ?? "", /space/);
  await assert.rejects(makeAccount("alice", "short"), /at least 8/);
  // The migration of DASHBOARD_BASIC_AUTH keeps the password it already had.
  const migrated = await makeAccount("alice", "pw", new Date(), { minPassword: false });
  assert.equal(await verifyAccount(migrated, "alice", "pw"), true);
});

test("read refuses a file that is not this user's own private regular file", async () => {
  const dir = tmpDir("mandu-account-bad-");
  const good = join(dir, "good.json");
  writeAccount(good, await makeAccount("alice", PASSWORD));
  assert.equal(readAccount(join(dir, "absent.json")).kind, "none");

  const link = join(dir, "link.json");
  symlinkSync(good, link);
  assert.match(unsafeWhy(readAccount(link)), /symbolic link/);

  const loose = join(dir, "loose.json");
  writeFileSync(loose, readFileSync(good));
  chmodSync(loose, 0o644);
  assert.match(unsafeWhy(readAccount(loose)), /readable or writable by others/);

  const hard = join(dir, "hard.json");
  const twin = join(dir, "twin.json");
  writeFileSync(hard, readFileSync(good), { mode: 0o600 });
  linkSync(hard, twin);
  assert.match(unsafeWhy(readAccount(hard)), /hard link/);

  assert.match(unsafeWhy(readAccount(good, (process.getuid?.() ?? 0) + 1)), /another user/);

  const junk = join(dir, "junk.json");
  writeFileSync(junk, "not json", { mode: 0o600 });
  assert.match(unsafeWhy(readAccount(junk)), /not a Mandu account record/);

  const rec = JSON.parse(readFileSync(good, "utf8")) as AccountRecord;
  for (const [what, bad] of [
    ["N too small (a planted weak hash)", { ...rec, N: 2 }],
    ["N too large (a planted slow hash)", { ...rec, N: 2 ** 24 }],
    ["another version", { ...rec, version: 2 }],
    ["no hash", { ...rec, hash: "" }],
    ["a ':' user", { ...rec, user: "a:b" }],
  ] as const) {
    const p = join(dir, `bad-${what.length}.json`);
    writeFileSync(p, JSON.stringify(bad), { mode: 0o600 });
    assert.equal(readAccount(p).kind, "unsafe", what);
  }
  assert.equal(readAccount(join(dir, "")).kind, "unsafe", "a directory is not an account file");
});

test("a write replaces a planted link instead of following it", async () => {
  const dir = tmpDir("mandu-account-link-");
  const target = join(dir, "elsewhere.txt");
  writeFileSync(target, "untouched\n");
  const path = join(dir, "dashboard-account.json");
  symlinkSync(target, path);
  writeAccount(path, await makeAccount("alice", PASSWORD));
  assert.equal(readFileSync(target, "utf8"), "untouched\n", "the link's target is untouched");
  assert.ok(!lstatSync(path).isSymbolicLink(), "the account is a file of its own now");
  assert.equal(readAccount(path).kind, "ok");
});

test("AccountFile: the first read is the baseline; each later change is reported once", async () => {
  const dir = tmpDir("mandu-account-watch-");
  const path = join(dir, "dashboard-account.json");
  const seen: string[] = [];
  let t = 0;
  const f = new AccountFile(path, { onChange: (w) => seen.push(w), now: () => new Date(++t * 1000) });
  assert.equal(f.read().kind, "none");
  assert.equal(f.changedAt(), null);
  writeAccount(path, await makeAccount("alice", PASSWORD));
  assert.equal(f.read().kind, "ok");
  assert.equal(seen.length, 1, "created while running: a change");
  f.read();
  assert.equal(seen.length, 1, "no change: nothing reported");
  writeAccount(path, await makeAccount("mallory", PASSWORD));
  const r = f.read();
  assert.equal(r.kind === "ok" && r.account.user, "mallory");
  assert.equal(seen.length, 2);
  assert.match(seen[1]!, /now for user mallory/);
  chmodSync(path, 0o644);
  assert.equal(f.read().kind, "unsafe");
  assert.match(seen[2]!, /now refused/);
  assert.ok(f.changedAt() instanceof Date);

  // A dashboard that starts with the file there takes it as the baseline.
  const g = new AccountFile(path, { onChange: () => assert.fail("not a change") });
  g.read();
  assert.equal(g.changedAt(), null);
});

function unsafeWhy(r: ReturnType<typeof readAccount>): string {
  assert.equal(r.kind, "unsafe", JSON.stringify(r));
  return r.kind === "unsafe" ? r.why : "";
}
