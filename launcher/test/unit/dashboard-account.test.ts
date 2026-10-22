/**
 * dashboard-account.test — `mandu dashboard --set-password`
 * (src/dashboard-account.ts; dashboard.md §6.z).
 *
 * Pins:
 *   - on a terminal it asks a username and a password twice and writes ONLY
 *     a salted scrypt hash, mode 0600 (the password nowhere in the file, the
 *     output or the errors);
 *   - a short password, a mismatch, a ':' username are asked again;
 *   - not a terminal: exit 2, nothing written (never a password from an
 *     argument or the environment);
 *   - an existing account: its username is the default; an unusable file
 *     (wrong mode) says so and is written again, as 0600;
 *   - accountState: none / the user / unsafe (a link, a loose mode).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { accountPath, accountState, runSetPassword, type SetPasswordDeps } from "../../src/dashboard-account.js";

const PASSWORD = "a password of mine";

function harness(lines: Array<string | null>, secrets: Array<string | null>, over: Partial<SetPasswordDeps> = {}) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-setpw-"));
  const out: string[] = [];
  const err: string[] = [];
  const prompts: string[] = [];
  const deps: SetPasswordDeps = {
    isTTY: true,
    path: join(dir, "home", "state", "dashboard-account.json"),
    askLine: async (p) => { prompts.push(p); return lines.length ? lines.shift()! : null; },
    askSecret: async (p) => { prompts.push(p); return secrets.length ? secrets.shift()! : null; },
    out: (s) => out.push(s),
    err: (s) => err.push(s),
    ...over,
  };
  return { dir, deps, out, err, prompts, done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("--set-password writes only a scrypt hash, 0600; the password is never printed", async () => {
  const h = harness(["alice"], [PASSWORD, PASSWORD]);
  try {
    assert.equal(await runSetPassword(h.deps), 0);
    const text = readFileSync(h.deps.path, "utf8");
    assert.ok(!text.includes(PASSWORD) && !text.includes(Buffer.from(PASSWORD).toString("base64")), "no password on disk");
    const rec = JSON.parse(text) as { user: string; kdf: string; salt: string; hash: string };
    assert.equal(rec.user, "alice");
    assert.equal(rec.kdf, "scrypt");
    assert.ok(rec.salt.length > 0 && rec.hash.length > 0);
    assert.equal(statSync(h.deps.path).mode & 0o777, 0o600);
    assert.equal(statSync(join(h.dir, "home", "state")).mode & 0o777, 0o700);
    assert.ok(![...h.out, ...h.err].join("").includes(PASSWORD), "never printed");
    assert.match(h.out.join(""), /Saved your dashboard account \(user alice\)/);
    assert.deepEqual(h.prompts, ["Username: ", "Password: ", "Password again: "]);
  } finally {
    h.done();
  }
});

test("a short password, a mismatch and a ':' username are asked again", async () => {
  const h = harness(["a:b", "alice"], ["short", PASSWORD, "different!!", PASSWORD, PASSWORD]);
  try {
    assert.equal(await runSetPassword(h.deps), 0);
    const errs = h.err.join("");
    assert.match(errs, /cannot contain ':'/);
    assert.match(errs, /at least 8 characters/);
    assert.match(errs, /the two passwords differ/);
    assert.ok(!errs.includes("short") && !errs.includes("different!!"), "the typed passwords are not echoed in errors");
  } finally {
    h.done();
  }
});

test("not a terminal: exit 2 and nothing written", async () => {
  const h = harness(["alice"], [PASSWORD, PASSWORD], { isTTY: false });
  try {
    assert.equal(await runSetPassword(h.deps), 2);
    assert.ok(!existsSync(h.deps.path));
    assert.match(h.err.join(""), /in your own terminal/);
  } finally {
    h.done();
  }
});

test("input that ends (Ctrl-D) writes nothing", async () => {
  const h = harness(["alice"], [PASSWORD, null]);
  try {
    assert.equal(await runSetPassword(h.deps), 2);
    assert.ok(!existsSync(h.deps.path));
  } finally {
    h.done();
  }
});

test("an existing account: its username is the default; an unusable file is written again as 0600", async () => {
  const h = harness(["alice", ""], [PASSWORD, PASSWORD, PASSWORD, PASSWORD, PASSWORD, PASSWORD]);
  try {
    assert.equal(await runSetPassword({ ...h.deps, askLine: async () => "alice" }), 0);
    chmodSync(h.deps.path, 0o644);
    assert.equal(await runSetPassword(h.deps), 0);
    assert.match(h.out.join(""), /cannot be used now \(the account file is readable or writable by others\)/);
    assert.equal(statSync(h.deps.path).mode & 0o777, 0o600, "written again as 0600");
    // A usable account: Enter keeps its username.
    assert.equal(await runSetPassword(h.deps), 0);
    assert.match(h.prompts.join("|"), /Username \[alice\]: /);
    assert.deepEqual(accountState(h.deps.path), { user: "alice" });
    assert.equal(statSync(h.deps.path).mode & 0o777, 0o600);
  } finally {
    h.done();
  }
});

test("accountState: none, the user, or why it cannot be used", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-acctstate-"));
  try {
    const p = join(dir, "a.json");
    assert.equal(accountState(p), null);
    writeFileSync(p, JSON.stringify({ user: "alice", kdf: "scrypt" }), { mode: 0o600 });
    assert.deepEqual(accountState(p), { user: "alice" });
    chmodSync(p, 0o640);
    assert.match((accountState(p) as { unsafe: string }).unsafe, /readable or writable by others/);
    const l = join(dir, "l.json");
    symlinkSync(p, l);
    assert.match((accountState(l) as { unsafe: string }).unsafe, /symbolic link/);
    assert.equal(accountPath({ MANDU_HOME: "/m" }), "/m/state/dashboard-account.json");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
