/**
 * guard-settings.test — policy.yaml `unix_sockets:` and `write_protect:` at
 * launch (sandbox-security-review-2026-09-28 findings 1, 2, 6;
 * arbiter/policy/guard-settings.ts):
 *   - readGuardSettings: the arbiter's answer, shape-checked; a failed read
 *     is the built-in lists (no extras, no opt-outs) with a warning;
 *   - unixPolicy: policy.yaml extras UNIONED with MANDU_UNIX_ALLOW, `~`
 *     expanded, `@name` as an abstract name (`@*` and `/` ignored);
 *   - writeProtectList: deny paths ahead of the built-in asks (the guard takes
 *     the first entry a path falls under), ask paths added, `unprotect`
 *     drops exactly the named built-in ask entry, and NEVER an entry of
 *     Mandu's own files or the arbiter socket.
 *
 * No privilege, no guard. The lists are handed to the guard only under the
 * axes run.ts checks (write protection: every mode but `off`; the socket
 * list: the confidentiality axis); the suite states `secrets`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { NO_GUARD_SETTINGS, readGuardSettings } from "../../src/guard-policy-file.js";
import { unixPolicy } from "../../src/unix-policy.js";
import { writeProtectList } from "../../src/write-protect.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const ENV = { HOME: "/h", XDG_RUNTIME_DIR: "/run/user/7" };
const NO_REPO = { exists: () => false, isDir: () => false, read: () => null };

test("readGuardSettings: the arbiter's answer, shape-checked; a failed read is the built-ins, with a warning", async () => {
  const logs: string[] = [];
  const good = await readGuardSettings("/s", (m) => logs.push(m), async (_s, op) => {
    assert.equal(op, "guardSettings");
    return {
      unixAllow: ["~/a.sock", 7], writeProtect: { deny: ["~/bin"], ask: "nope", unprotect: ["~/.gitconfig"] },
      trustLookups: [{ mount: "/home", type: "nfs4" }, { mount: "/x" }, "nope", { mount: 3, type: "nfs" }],
    };
  });
  assert.deepEqual(good, { unixAllow: ["~/a.sock"], writeProtect: { deny: ["~/bin"], ask: [], unprotect: ["~/.gitconfig"] }, trustLookups: [{ mount: "/home", type: "nfs4" }] });
  assert.equal(logs.length, 0);
  // An older arbiter (no trustLookups): none trusted.
  const older = await readGuardSettings("/s", () => {}, async () => ({ unixAllow: [], writeProtect: { deny: [], ask: [], unprotect: [] } }));
  assert.deepEqual(older.trustLookups, []);
  const bad = await readGuardSettings("/s", (m) => logs.push(m), async (): Promise<unknown> => { throw new Error("unknown op: guardSettings"); });
  assert.deepEqual(bad, NO_GUARD_SETTINGS);
  assert.deepEqual(bad.trustLookups, [], "a failed read trusts no mount (tighter)");
  assert.match(logs.join("\n"), /WARNING: mandu: policy\.yaml unix_sockets: \/ write_protect: \/ remote_mounts: not read \(unknown op/);
});

test("unixPolicy: policy.yaml extras and MANDU_UNIX_ALLOW are unioned; ~ expanded; @names are abstract", () => {
  const p = unixPolicy(
    { ...ENV, MANDU_UNIX_ALLOW: "/srv/app.sock:@env-name:~/env.sock" },
    { extra: ["~/.local/run/helper.sock", "/run/pg/", "@my-helper", "@/tmp/pfx*", "@*", "@", "/", "relative.sock", "/srv/app.sock"] },
  );
  const byPath = new Map(p.allow.map((a) => [a.path, a.label]));
  assert.equal(byPath.get("/h/.local/run/helper.sock"), "policy.yaml unix_sockets");
  assert.equal(byPath.get("/run/pg"), "policy.yaml unix_sockets", "trailing / trimmed");
  assert.equal(byPath.get("/srv/app.sock"), "policy.yaml unix_sockets", "listed in both: once");
  assert.equal(byPath.get("/h/env.sock"), "MANDU_UNIX_ALLOW");
  assert.ok(!byPath.has("/"), "`/` would allow every socket");
  assert.ok(![...byPath.keys()].some((k) => k.includes("relative")));
  assert.deepEqual(p.abstractAllow, ["/tmp/.X11-unix/X*", "my-helper", "/tmp/pfx*", "env-name"], "`@*` and `@` never widen the abstract list");
  // No HOME: a `~` extra adds nothing (never a path under 'undefined').
  const bare = unixPolicy({}, { extra: ["~/x.sock"] });
  assert.ok(!bare.allow.some((a) => a.path.includes("x.sock")));
});

test("writeProtectList: deny paths go ahead of the built-in asks, ask paths are added", () => {
  const list = writeProtectList(ENV, "/w", NO_REPO, undefined, { deny: ["~/bin/", "~/.bashrc"], ask: ["~/.config/nvim/init.lua"], unprotect: [] });
  const i = (path: string, answer: string) => list.findIndex((e) => e.path === path && e.answer === answer);
  assert.ok(i("/h/bin", "deny") >= 0);
  assert.equal(list[i("/h/bin", "deny")]!.label, "a file you protected in policy.yaml");
  assert.ok(i("/h/.config/nvim/init.lua", "ask") >= 0);
  // The guard takes the FIRST entry: the human's deny wins over the built-in ask.
  assert.ok(i("/h/.bashrc", "deny") >= 0 && i("/h/.bashrc", "deny") < i("/h/.bashrc", "ask"));
  // Mandu's own files come first of all.
  assert.ok(i("/h/.config/mandu", "deny") < i("/h/bin", "deny"));
});

test("writeProtectList: unprotect drops exactly the named built-in ask entry, the repo hooks included", () => {
  const repo = { exists: (p: string) => p === "/w/.git", isDir: (p: string) => p === "/w/.git", read: () => null };
  const logs: string[] = [];
  const list = writeProtectList(ENV, "/w", repo, undefined, { deny: [], ask: [], unprotect: ["~/.gitconfig", "/w/.git/hooks/", "~/.config/fish/config.fish"] }, (m) => logs.push(m));
  const paths = list.map((e) => e.path);
  assert.ok(!paths.includes("/h/.gitconfig"));
  assert.ok(!paths.includes("/w/.git/hooks"));
  assert.ok(paths.includes("/h/.config/git/config"), "only the named entry");
  assert.ok(paths.includes("/h/.config/fish"), "a path under a built-in directory entry does not carve it out");
  assert.match(logs.join("\n"), /\/h\/\.config\/fish\/config\.fish, which is not on the built-in list/);
});

test("writeProtectList: an unprotect naming Mandu's own files or the arbiter socket removes nothing", () => {
  const logs: string[] = [];
  const sock = "/run/user/7/mandu/current/arbiter.sock";
  const env = { ...ENV, MANDU_HOME: "/data/mh" };
  const baseline = writeProtectList(env, "/w", NO_REPO, sock);
  const list = writeProtectList(env, "/w", NO_REPO, sock, {
    deny: [], ask: [],
    unprotect: ["/data/mh/config.toml", "/data/mh/events", "/data/mh/state/mandu.db", "/data/mh/state/mandu.db-wal", sock],
  }, (m) => logs.push(m));
  const denies = (l: typeof list) => l.filter((e) => e.answer === "deny").map((e) => e.path).sort();
  assert.deepEqual(denies(list), denies(baseline), "every own-files entry stays");
  assert.equal(list.length, baseline.length);
  assert.equal(logs.filter((m) => /one of Mandu's own files; it stays protected/.test(m)).length, 5);
});

test("writeProtectList without settings is the built-in list (the pre-policy.yaml behavior)", () => {
  assert.deepEqual(writeProtectList(ENV, "/w", NO_REPO), writeProtectList(ENV, "/w", NO_REPO, undefined, NO_GUARD_SETTINGS.writeProtect));
});
