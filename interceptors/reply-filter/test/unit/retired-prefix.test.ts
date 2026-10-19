/**
 * retired-prefix.test — the reply filter matches the CURRENT symbol prefix only.
 *
 * The token prefix became `$MDU:` on 2026-09-27. An old-prefix token in the
 * agent's reply is plain text: it is not a candidate (no IPC round-trip), not
 * held as a possible token head, and passes through byte-for-byte. The old
 * prefix is built from parts so the repo-wide sweep
 * (arbiter/test/unit/symbol-prefix-sweep.test.ts) stays meaningful.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ReplyStreamFilter, mayContainSymbol, couldBeSymbolPrefix, type ReplyResolver } from "../../src/filter.js";

const OLD = ["$", "AOS:"].join("");

class CountingResolver implements ReplyResolver {
  calls: string[] = [];
  async desymbolize(text: string): Promise<string> {
    this.calls.push(text);
    return text.split("$MDU:Read[9b0a]").join("RAW");
  }
}

test("an old-prefix token is not a candidate nor a held token head", () => {
  assert.equal(mayContainSymbol(`x ${OLD}Read[9b0a] y`), false);
  assert.equal(mayContainSymbol(`x \\${OLD}Read[9b0a] y`), false);
  assert.equal(couldBeSymbolPrefix(`${OLD}Read`), false);
  assert.equal(couldBeSymbolPrefix("$MDU:Read"), true);
});

test("an old-prefix token passes through verbatim; a current one beside it resolves", async () => {
  const r = new CountingResolver();
  const f = new ReplyStreamFilter(r);
  let out = await f.write(`old ${OLD}Read[9b0a] new $MDU:Read[9b0a]\n`);
  out += await f.flush();
  assert.equal(out, `old ${OLD}Read[9b0a] new RAW\n`);

  const r2 = new CountingResolver();
  const f2 = new ReplyStreamFilter(r2);
  let out2 = await f2.write(`only ${OLD}Read[9b0a] here\n`);
  out2 += await f2.flush();
  assert.equal(out2, `only ${OLD}Read[9b0a] here\n`);
  assert.deepEqual(r2.calls, [], "no resolver round-trip for old-prefix text");
});
