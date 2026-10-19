/**
 * The confidentiality label on the emitted event stream (confidentiality.md §2,
 * plan 5). This is what the dashboard badges and what the §12 oracle asserts on.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  makeSymbolize,
  makeToolResult,
  type EventContext,
} from "../../src/events.js";

const CTX: EventContext = { sessionId: "s1", turn: 1 };

test("a TRUSTED×secret result carries the level on BOTH the symbolize and tool_result events", () => {
  const sym = makeSymbolize({
    ctx: CTX,
    callId: "toolu_1",
    tool: "Read",
    symbol: "$MDU:nomodel_Read[3fa9]",
    original: "API_KEY=AKIA-REAL",
    origin: "/workspace/.env",
    confidentiality: "no-model",
  });
  assert.equal(sym.output?.symbols[0]?.confidentiality, "no-model");
  assert.equal(sym.output?.symbols[0]?.origin, "/workspace/.env");

  const tr = makeToolResult({
    ctx: CTX,
    callId: "toolu_1",
    tool: "Read",
    original: "API_KEY=AKIA-REAL",
    symbolized: "$MDU:nomodel_Read[3fa9]",
    symbols: sym.output!.symbols,
    // TRUSTED integrity + a secret level: symbolized by PROVENANCE, not distrust.
    trust: "TRUSTED",
    confidentiality: "no-model",
    violatedInvariant: false,
  });
  assert.equal(tr.policy?.trust, "TRUSTED");
  assert.equal(tr.policy?.confidentiality, "no-model");
});

test("OFF-dual: no level ⇒ no confidentiality field anywhere on the events", () => {
  const sym = makeSymbolize({
    ctx: CTX, callId: "toolu_2", tool: "Read",
    symbol: "$MDU:Read[aaaa]", original: "notes", origin: "/workspace/notes.md",
  });
  assert.equal("confidentiality" in (sym.output!.symbols[0] as object), false);

  const tr = makeToolResult({
    ctx: CTX, callId: "toolu_2", tool: "Read", original: "notes",
    symbolized: "$MDU:Read[aaaa]", symbols: sym.output!.symbols,
    trust: "UNTRUSTED", violatedInvariant: false,
  });
  assert.equal("confidentiality" in (tr.policy as object), false);
});

test("an explicit public level is never carried (no churn on ordinary symbols)", () => {
  const sym = makeSymbolize({
    ctx: CTX, callId: "toolu_3", tool: "web_fetch",
    symbol: "$MDU:web_fetch[bbbb]", original: "page", origin: "https://x.test",
    confidentiality: "public",
  });
  assert.equal("confidentiality" in (sym.output!.symbols[0] as object), false);
});

test("plan 10: a tool_result event carries the process-tree taint and the [mandu:secret] note, never content", () => {
  const tr = makeToolResult({
    ctx: CTX,
    callId: "toolu_p10",
    tool: "Bash",
    original: "count\n1204\n",
    symbolized: "$MDU:nomodel_Bash[1a2b]",
    symbols: [],
    trust: "TRUSTED",
    confidentiality: "no-model",
    violatedInvariant: false,
    secretTaint: { level: "no-model", files: ["/h/.pgpass"], apps: ["psql"], rule: "secret", maskWhole: true, denied: [] },
    secretNote: "[mandu:secret] masked: psql read /h/.pgpass; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Say so rather than retrying.",
  });
  const e = tr as unknown as { secretTaint?: { apps: string[]; maskWhole: boolean }; secretNote?: string };
  assert.deepEqual(e.secretTaint?.apps, ["psql"]);
  assert.equal(e.secretTaint?.maskWhole, true);
  assert.match(e.secretNote ?? "", /^\[mandu:secret\] masked: psql read/);
  const plain = makeToolResult({ ctx: CTX, callId: "toolu_p11", tool: "Bash", original: "ok", symbolized: "ok", symbols: [], trust: "TRUSTED", violatedInvariant: false });
  assert.equal((plain as unknown as { secretTaint?: unknown }).secretTaint, undefined);
});
