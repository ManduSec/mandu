/**
 * resolve-health.test — the reply filter's record of its own lookups, and the
 * S8 miss's hypotheses at the stream filter (docs/design/ui/reply-row-
 * reservation.md §18).
 *
 * The miss (2026-09-30, live drill S8): the human's terminal showed a raw
 * `$MDU:nomodel_Bash[66b7]` on its own reply row; the arbiter logged nine
 * `refused on data channel: desymbolize` and the session had no
 * `desymbolize` event. Cause: the run's own arbiter came from a worktree
 * with the human plane, the `mandu` it launched from a main checkout that
 * predated it, whose reply filter still asked the DATA socket. Every lookup
 * was refused and the filter passed the token through, silently.
 *
 * Here, with an in-memory resolver:
 *   - H1-H5: the token family itself is not the cause. `nomodel_Bash`
 *     (underscore, a tool-name suffix) resolves whole, Markdown-escaped, one
 *     byte per write, hard-wrapped mid-token, and restyled at its `_`.
 *   - H8: a resolver that REFUSES leaves the token byte-exact (never a blank,
 *     never a part), and `WatchedResolver` reports the state change once,
 *     the recovery once, and says it at exit.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { ReplyStreamFilter, placeholderNames, SYMBOL_TOKEN_RE, type ReplyResolver } from "../../src/filter.js";
import {
  RESOLVE_HEALTH_EVENTS_MAX,
  RESOLVE_REASON_MAX,
  WatchedResolver,
  resolveFailureReason,
} from "../../src/resolve-health.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

/** The S8 shape: one whole-result no-model symbol for a tainted Bash call. */
const TOKEN = "$MDU:nomodel_Bash[66b7]";
const VALUE = "mdu-digest sha256=3f1c9a7e5b2d4c6e8f0a1b3c5d7e9f1a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d0e .env";
/** The arbiter's refusal of desymbolize on the data socket, verbatim
 *  (arbiter/ipc/server.ts humanPlaneOnlyError). */
const REFUSAL = "human-plane: 'desymbolize' returns originals and is accepted only on the human socket (or the admin channel), never on the data socket";

class MapResolver implements ReplyResolver {
  calls: string[] = [];
  async desymbolize(text: string): Promise<string> {
    this.calls.push(text);
    return text.split(TOKEN).join(VALUE);
  }
}

class RefusingResolver implements ReplyResolver {
  calls = 0;
  constructor(private refuseFirst = Infinity) {}
  async desymbolize(text: string): Promise<string> {
    this.calls += 1;
    if (this.calls <= this.refuseFirst) throw new Error(REFUSAL);
    return text.split(TOKEN).join(VALUE);
  }
}

/** Every write's output, concatenated, then the final flush. */
async function feed(f: ReplyStreamFilter, chunks: readonly string[]): Promise<string> {
  let out = "";
  for (const c of chunks) out += await f.write(c);
  return out + (await f.flush());
}

// ── H1-H5: the token family resolves in every shape the stream carries ───────

test("H1 grammar: `nomodel_Bash` is one token, canonical and Markdown-escaped", () => {
  SYMBOL_TOKEN_RE.lastIndex = 0;
  assert.deepEqual(`row ${TOKEN} end`.match(SYMBOL_TOKEN_RE), [TOKEN]);
  assert.deepEqual(placeholderNames("\\$MDU:nomodel\\_Bash[66b7]"), [TOKEN], "the escaped spelling names the same token");
});

for (const eager of [false, true]) {
  const mode = eager ? "EAGER (PTY)" : "pipe";

  test(`H2 ${mode}: the S8 reply row resolves; the human never sees the token`, async () => {
    const r = new MapResolver();
    const reply = "● It printed the following (Mandu masked it from me as a secret):\r\n  " + TOKEN + "\r\n";
    const out = await feed(new ReplyStreamFilter(r, { eager }), [reply]);
    assert.ok(out.includes(VALUE), JSON.stringify(out));
    assert.doesNotMatch(out, /\$MDU/);
  });

  test(`H3 ${mode}: one byte per write (a token straddling every chunk boundary) resolves`, async () => {
    const r = new MapResolver();
    const out = await feed(new ReplyStreamFilter(r, { eager }), [...`  ${TOKEN}\r\n`]);
    assert.ok(out.includes(VALUE), JSON.stringify(out));
    assert.doesNotMatch(out, /\$MDU/);
  });

  test(`H4 ${mode}: a hard wrap inside the token (CRLF + indent after \`nomodel_\`) resolves`, async () => {
    const r = new MapResolver();
    const out = await feed(new ReplyStreamFilter(r, { eager }), [`  $MDU:nomodel_\r\n  Bash[66b7]\r\n`]);
    assert.ok(out.includes(VALUE), JSON.stringify(out));
    assert.doesNotMatch(out, /\$MDU|nomodel/);
  });

  test(`H5 ${mode}: the Markdown-escaped spelling (\\$MDU:nomodel\\_Bash) resolves`, async () => {
    const r = new MapResolver();
    const out = await feed(new ReplyStreamFilter(r, { eager }), ["  \\$MDU:nomodel\\_Bash[66b7]\r\n"]);
    assert.ok(out.includes(VALUE), JSON.stringify(out));
    assert.doesNotMatch(out, /MDU|nomodel/);
  });
}

test("H5b EAGER: a restyle at the `_` (an SGR inside the token) resolves", async () => {
  const r = new MapResolver();
  const out = await feed(new ReplyStreamFilter(r, { eager: true }), ["  \x1b[1m$MDU:nomodel\x1b[22m_Bash[66b7]\x1b[0m\r\n"]);
  assert.ok(out.includes(VALUE), JSON.stringify(out));
  assert.doesNotMatch(out, /\$MDU|nomodel/);
});

// ── H8: the refused lookup (the cause) ────────────────────────────────────────

for (const eager of [false, true]) {
  test(`H8 ${eager ? "EAGER" : "pipe"}: a refused lookup leaves the token byte-exact, and the watch records it`, async () => {
    const inner = new RefusingResolver();
    const degraded: string[] = [];
    const w = new WatchedResolver(inner, { onDegraded: (why) => degraded.push(why) });
    const out = await feed(new ReplyStreamFilter(w, { eager }), [`  ${TOKEN}\r\n`, `again ${TOKEN}\r\n`]);
    assert.ok(out.includes(`  ${TOKEN}\r\n`) && out.includes(`again ${TOKEN}\r\n`), `the token stays whole: ${JSON.stringify(out)}`);
    assert.ok(!out.includes(VALUE));
    assert.ok(inner.calls >= 2, "each reply asked");
    assert.equal(w.failures, inner.calls);
    assert.deepEqual(degraded, [REFUSAL], "one record for the state change, with the refusal");
    assert.equal(w.isDegraded, true);
    assert.match(w.exitNote() ?? "", new RegExp(`^${w.failures} placeholder lookups failed \\(first: human-plane: 'desymbolize'`));
    assert.match(w.exitNote() ?? "", /nothing leaked/);
  });
}

test("WatchedResolver: a healthy session says nothing; results and errors pass through unchanged", async () => {
  const w = new WatchedResolver(new MapResolver(), {
    onDegraded: () => assert.fail("no failure"),
    onRecovered: () => assert.fail("nothing to recover from"),
  });
  assert.equal(await w.desymbolize(`a ${TOKEN}`), `a ${VALUE}`);
  assert.equal(w.successes, 1);
  assert.equal(w.exitNote(), null);
  const bad = new WatchedResolver(new RefusingResolver());
  await assert.rejects(bad.desymbolize(TOKEN), (e: Error) => e.message === REFUSAL, "the caller's own fallback still sees the error");
});

test("WatchedResolver: degraded, then recovered, then degraded again — one record per change", async () => {
  const seen: string[] = [];
  const inner = new RefusingResolver(1);
  const w = new WatchedResolver(inner, {
    onDegraded: (why) => seen.push(`down:${why.slice(0, 11)}`),
    onRecovered: () => seen.push("up"),
  });
  await assert.rejects(w.desymbolize(TOKEN));
  assert.equal(await w.desymbolize(TOKEN), VALUE);
  assert.equal(await w.desymbolize(TOKEN), VALUE);
  assert.deepEqual(seen, ["down:human-plane", "up"]);
  assert.equal(w.isDegraded, false);
  assert.match(w.exitNote() ?? "", /^1 placeholder lookup failed/, "the note counts the session's failures even after a recovery");
});

test("WatchedResolver: a success on a re-learned endpoint (the epoch moved) is a recovery even with no failure in between", async () => {
  let epoch = 0;
  const seen: string[] = [];
  const w = new WatchedResolver(new MapResolver(), {
    epoch: () => epoch,
    onDegraded: () => seen.push("down"),
    onRecovered: () => seen.push("up"),
  });
  assert.equal(await w.desymbolize(TOKEN), VALUE);
  assert.deepEqual(seen, [], "the first endpoint is not a move");
  epoch = 1; // the client re-learned a restarted arbiter's human socket
  assert.equal(await w.desymbolize(TOKEN), VALUE);
  assert.equal(await w.desymbolize(TOKEN), VALUE);
  assert.deepEqual(seen, ["up"], "one recovery per move");
  assert.equal(w.moves, 1);
  assert.equal(w.exitNote(), null, "no lookup failed");
  // a throwing epoch is ignored
  const odd = new WatchedResolver(new MapResolver(), { epoch: () => { throw new Error("x"); }, onRecovered: () => assert.fail("no move") });
  assert.equal(await odd.desymbolize(TOKEN), VALUE);
});

test("WatchedResolver: a flapping arbiter is reported at most RESOLVE_HEALTH_EVENTS_MAX times; a throwing hook is swallowed", async () => {
  let n = 0;
  let calls = 0;
  const flappy: ReplyResolver = {
    async desymbolize(t: string) {
      calls += 1;
      if (calls % 2 === 1) throw new Error("socket closed");
      return t;
    },
  };
  const w = new WatchedResolver(flappy, {
    onDegraded: () => { n += 1; throw new Error("hook broke"); },
    onRecovered: () => { n += 1; },
  });
  for (let i = 0; i < 100; i++) await w.desymbolize("x").catch(() => {});
  assert.equal(n, RESOLVE_HEALTH_EVENTS_MAX);
  assert.equal(w.failures, 50);
});

test("resolveFailureReason: one line, clipped, never empty", () => {
  assert.equal(resolveFailureReason(new Error("a\n  b")), "a b");
  assert.equal(resolveFailureReason("plain"), "plain");
  assert.equal(resolveFailureReason({}), "unknown error");
  assert.equal(resolveFailureReason(new Error("")), "unknown error");
  const long = resolveFailureReason(new Error("x".repeat(1000)));
  assert.equal(long.length, RESOLVE_REASON_MAX);
  assert.ok(long.endsWith("…"));
});
