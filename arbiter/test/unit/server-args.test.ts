/**
 * server-args.test.ts — the arbiter daemon's command line (Mandu-new, no
 * reference origin; ipc/server-args.ts, on-disk-layout.md §5).
 *
 * Pins:
 *   - `--symbol-db` / `--event-dir` in both `--flag value` and `--flag=value`
 *     forms, made absolute against the cwd;
 *   - the first other argument is the socket path, as before the flags;
 *   - a flag with no value, an empty one, or given twice is refused;
 *   - absent flags default to the path table's `symbol-db` and `events` under
 *     MANDU_HOME (else $HOME/.mandu), and the retired MANDU_SYMBOL_DB /
 *     MANDU_EVENT_DIR move nothing.
 *
 * Pure: no axis is read (axes: none).
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { parseServerArgs, resolveStorePaths, ServerArgsError } from "../../ipc/server-args.js";

test("no arguments: no socket, no store flags", () => {
  assert.deepEqual(parseServerArgs([]), {});
});

test("a lone argument is the socket path, verbatim (today's behaviour)", () => {
  assert.deepEqual(parseServerArgs(["/run/x/arbiter.sock"]), { socketPath: "/run/x/arbiter.sock" });
  assert.deepEqual(parseServerArgs(["rel.sock"], "/cwd"), { socketPath: "rel.sock" }, "the socket is not resolved");
});

test("--symbol-db and --event-dir, spaced and with =, beside a socket in any position", () => {
  assert.deepEqual(
    parseServerArgs(["--symbol-db", "/a/x.db", "/s.sock", "--event-dir=/a/ev"]),
    { socketPath: "/s.sock", symbolDb: "/a/x.db", eventDir: "/a/ev" },
  );
  assert.deepEqual(
    parseServerArgs(["/s.sock", "--event-dir", "/a/ev", "--symbol-db=/a/x.db"]),
    { socketPath: "/s.sock", symbolDb: "/a/x.db", eventDir: "/a/ev" },
  );
  assert.deepEqual(parseServerArgs(["--event-dir", "/a/ev"]), { eventDir: "/a/ev" }, "flags alone: instance mode");
});

test("relative store paths resolve against the cwd", () => {
  assert.deepEqual(parseServerArgs(["--symbol-db", "st/x.db", "--event-dir=ev"], "/cwd"), { symbolDb: "/cwd/st/x.db", eventDir: "/cwd/ev" });
});

test("a flag without a value, with an empty one, or followed by the other flag is refused", () => {
  for (const argv of [
    ["--symbol-db"],
    ["--event-dir="],
    ["--symbol-db", ""],
    ["--symbol-db", "--event-dir", "/e"],
    ["/s.sock", "--event-dir"],
  ]) {
    assert.throws(() => parseServerArgs(argv), ServerArgsError, JSON.stringify(argv));
  }
});

test("a flag given twice is refused (no silent last-wins)", () => {
  assert.throws(() => parseServerArgs(["--symbol-db", "/a", "--symbol-db=/b"]), /given twice/);
});

test("other arguments keep their old meaning: the first one is the socket", () => {
  assert.deepEqual(parseServerArgs(["--symbol-dbx", "/a"]), { socketPath: "--symbol-dbx" });
  assert.deepEqual(parseServerArgs(["/s.sock", "extra"]), { socketPath: "/s.sock" });
});

test("defaults: the path table's symbol-db and events under MANDU_HOME, else $HOME/.mandu", () => {
  assert.deepEqual(resolveStorePaths({}, { HOME: "/h" }), { symbolDb: "/h/.mandu/state/mandu.db", eventDir: "/h/.mandu/events" });
  assert.deepEqual(resolveStorePaths({}, { HOME: "/h", MANDU_HOME: "/mh" }), { symbolDb: "/mh/state/mandu.db", eventDir: "/mh/events" });
  assert.deepEqual(resolveStorePaths({}, {}, "/pw"), { symbolDb: "/pw/.mandu/state/mandu.db", eventDir: "/pw/.mandu/events" });
});

test("flags win over the defaults, each on its own", () => {
  assert.deepEqual(resolveStorePaths({ symbolDb: "/x.db" }, { HOME: "/h" }), { symbolDb: "/x.db", eventDir: "/h/.mandu/events" });
  assert.deepEqual(resolveStorePaths({ eventDir: "/ev" }, { HOME: "/h" }), { symbolDb: "/h/.mandu/state/mandu.db", eventDir: "/ev" });
});

test("--net-guard (plan 15 §4.3): an absolute path, once", () => {
  assert.equal(parseServerArgs(["--net-guard", "/b/mandu-net-guard"]).netGuard, "/b/mandu-net-guard");
  assert.equal(parseServerArgs(["--net-guard=/b/ng", "/s.sock"]).netGuard, "/b/ng");
  assert.throws(() => parseServerArgs(["--net-guard", "rel"]), /absolute path/);
  assert.throws(() => parseServerArgs(["--net-guard", "/a", "--net-guard", "/b"]), /given twice/);
  assert.equal(parseServerArgs(["/s.sock"]).netGuard, undefined);
});

test("--seed-from / --seed-policy (mandu why's temporary arbiter, db/store-seed.ts): made absolute, once; --seed-policy needs --seed-from", () => {
  const a = parseServerArgs(["--seed-from", "/h/.mandu/state/mandu.db", "--seed-policy=/h/.mandu/policy.yaml", "/t/a.sock"]);
  assert.equal(a.seedFrom, "/h/.mandu/state/mandu.db");
  assert.equal(a.seedPolicy, "/h/.mandu/policy.yaml");
  assert.equal(a.socketPath, "/t/a.sock");
  assert.equal(parseServerArgs(["--seed-from", "rel.db"], "/w").seedFrom, "/w/rel.db");
  assert.throws(() => parseServerArgs(["--seed-policy", "/p.yaml"]), /--seed-policy needs --seed-from/);
  assert.throws(() => parseServerArgs(["--seed-from", "/a.db", "--seed-from", "/b.db"]), /given twice/);
  assert.throws(() => parseServerArgs(["--seed-from"]), ServerArgsError);
  assert.equal(parseServerArgs(["/s.sock"]).seedFrom, undefined);
});

test("the retired MANDU_SYMBOL_DB / MANDU_EVENT_DIR move nothing", () => {
  const env = { HOME: "/h", MANDU_SYMBOL_DB: "/elsewhere/x.db", MANDU_EVENT_DIR: "/elsewhere/ev" };
  assert.deepEqual(resolveStorePaths({}, env), { symbolDb: "/h/.mandu/state/mandu.db", eventDir: "/h/.mandu/events" });
});
