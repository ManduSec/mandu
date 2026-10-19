/**
 * openclaw-redaction.test.ts — OpenClaw's history redaction of a result the
 * proxy forwarded in clear is put back before it is judged
 * (openclaw-redaction.ts; confidentiality.md §6, 2026-10-11).
 *
 * Live (the first-session tour on OpenClaw): the `.env` twin went to the
 * model per key on the turn of the read; OpenClaw keeps tool results in its
 * history through its own redaction (`maskToken`: first 6, `…`, last 4), so
 * the next turn re-sent `STRIPE_KEY='$MDU:n…_KEY'`, which the arbiter
 * masked whole "after the fact" and the key could no longer be routed.
 *
 * Across a relaunch (2026-10-11): the placeholder record kept by the
 * arbiter (`placeholderMapOf`, `rebuildFromPlaceholders`, the memory's
 * `prime` / `flush`), on the redactions OpenClaw itself makes of twins
 * (recorded from the installed 2026.7.1 and 2026.9.9 builds), and the
 * forgeries that must rebuild nothing.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { ForwardedResultMemory, arbiterPlaceholderStore, forwardedDigest, isOpenclawRedactionOf, isOpenclawSurface, placeholderMapOf, rebuildFromPlaceholders } from "../../src/openclaw-redaction.js";
import { rewriteRequest } from "../../src/rewrite-request.js";
import { ClearResultLedger } from "../../src/after-the-fact.js";
import { CLAUDE_CODE_GATE_SURFACE, type GateSurface } from "../../src/gate-surface.js";
import type { ClassifyRequest, ClassifyResult } from "../../src/arbiter-client.js";
import type { Message, MessagesRequest } from "../../src/messages-types.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

/** OpenClaw's own mask (openclaw src/logging/redact.ts `maskToken`, 2026.7.1). */
const mask = (v: string): string => (v.length < 18 ? "***" : `${v.slice(0, 6)}…${v.slice(-4)}`);

const TOK = "$MDU:nomodel_Read[e7f3].STRIPE_KEY";
const TWIN = `STRIPE_KEY='${TOK}'\nDEBUG=1\n`;
const LIVE_REDACTED = "STRIPE_KEY='$MDU:n…_KEY'\nDEBUG=1\n"; // the bytes OpenClaw re-sent, live

test("isOpenclawRedactionOf: OpenClaw's masks of a forwarded text, the live sample first", () => {
  assert.equal(mask(TOK), "$MDU:n…_KEY");
  assert.ok(isOpenclawRedactionOf(LIVE_REDACTED, TWIN));
  const pw = "$MDU:nomodel_Read[9bbd].DATABASE_URL.password";
  const twin2 = `PORT=3000\n${TWIN}DATABASE_URL='postgres://app:${pw}@db:5432/prod'\nPASSWORD='short'\n`;
  const red2 = `PORT=3000\nSTRIPE_KEY='${mask(TOK)}'\nDEBUG=1\nDATABASE_URL='postgres://app:${mask(pw)}@db:5432/prod'\nPASSWORD='${mask("short")}'\n`;
  assert.ok(isOpenclawRedactionOf(red2, twin2), "two token masks and a short `***`");
  assert.ok(isOpenclawRedactionOf(`x ${mask(TOK)}`, `x ${TOK}`), "a mask at the end");
  assert.ok(isOpenclawRedactionOf(`${mask(TOK)} y`, `${TOK} y`), "a mask at the start");
});

test("isOpenclawRedactionOf: anything else is not one", () => {
  const no: Array<[string, string, string]> = [
    [TWIN, TWIN, "identical: nothing to put back"],
    ["STRIPE_KEY='$MDU:n_KEY'\nDEBUG=1\n", TWIN, "no mask"],
    ["STRIPE_KEY='$MDU:n…_KEY'\nDEBUG=2\n", TWIN, "a literal differs after the mask"],
    ["STRIPE_KEY='$MDU:x…_KEY'\nDEBUG=1\n", TWIN, "the kept head differs"],
    ["STRIPE_KEY='$MDU:n…_KEY'\nDEBUG=1\nEXTRA=1\n", TWIN, "text added"],
    ["STRIPE_KEY='$MDU:n…_KEY'\n", TWIN, "text removed"],
    ["abcdef…wxyz", "abcdefXwxyz", "fewer than 8 characters hidden"],
    ["ab…wxyz", "abXXXXXXXXXXwxyz", "fewer than 6 kept before the ellipsis"],
    ["abcdef…yz", "abcdefXXXXXXXXXXyz", "fewer than 4 kept after it"],
    [`K=***`, `K=`, "`***` hides at least one character"],
    ["", TWIN, "empty"],
  ];
  for (const [red, orig, why] of no) assert.equal(isOpenclawRedactionOf(red, orig), false, why);
  assert.equal(isOpenclawRedactionOf(42 as unknown as string, TWIN), false);
});

test("ForwardedResultMemory: restores only a redaction of what it remembered, bounded", () => {
  const m = new ForwardedResultMemory(2, 1000);
  m.remember("a", TWIN);
  assert.equal(m.restore("a", LIVE_REDACTED), TWIN);
  assert.equal(m.restore("a", TWIN), undefined, "unchanged: nothing to restore");
  assert.equal(m.restore("b", LIVE_REDACTED), undefined, "another id");
  m.remember("b", "x");
  m.remember("c", "y");
  assert.equal(m.get("a"), undefined, "the oldest goes first past the entry bound");
  const small = new ForwardedResultMemory(10, 5);
  small.remember("p", "1234");
  small.remember("q", "1234");
  assert.equal(small.get("p"), undefined, "and past the character bound");
  assert.ok(isOpenclawSurface({ spec: "openclaw-agent" }) && isOpenclawSurface({ spec: "openclaw" }));
  assert.ok(!isOpenclawSurface({ spec: "claude-code" }) && !isOpenclawSurface(undefined));
});

const OPENCLAW: GateSurface = {
  ...CLAUDE_CODE_GATE_SURFACE,
  spec: "openclaw-agent",
  exec: { exec: "command" },
  execOutput: { exec: "command" },
  paths: { read: { fields: ["path", "file_path"], mode: "read" } },
  relativeBase: "launch",
};

/** The arbiter's twin rule, mocked: the twin is public, anything else that
 *  names `.env` is no-model (the live verdicts). */
function twinArbiter(seen: string[]): MockArbiter {
  return new MockArbiter({
    classifyFn: (r: ClassifyRequest): ClassifyResult => {
      seen.push(r.value);
      return r.value === TWIN
        ? { trust: "TRUSTED", category: null, reason: "mock: structured read-twin", confidentiality: "public" }
        : { trust: "TRUSTED", category: null, reason: "mock: .env", confidentiality: "no-model" };
    },
  });
}
const u = (content: Message["content"]): Message => ({ role: "user", content } as Message);
const a = (content: Message["content"]): Message => ({ role: "assistant", content } as Message);
const turn = (out: string, more: Message[] = []): MessagesRequest => ({
  model: "claude-haiku-4-5",
  messages: [
    u("What is in .env?"),
    a([{ type: "tool_use", id: "toolu_r", name: "read", input: { path: ".env" } }] as Message["content"]),
    u([{ type: "tool_result", tool_use_id: "toolu_r", content: [{ type: "text", text: out }] }] as Message["content"]),
    ...more,
  ],
} as MessagesRequest);
const next = [a([{ type: "text", text: "It has STRIPE_KEY and DEBUG." }] as Message["content"]), u("Use the key with curl.")];
const resultOf = (r: MessagesRequest): string => {
  const c = (r.messages[2]!.content as Array<{ content: Array<{ text: string }> | string }>)[0]!.content;
  return typeof c === "string" ? c : c.map((b) => b.text).join("");
};

test("rewriteRequest, OpenClaw: the next turn's redacted twin goes back to the model as the twin; it is judged as the twin", async () => {
  const seen: string[] = [];
  const arbiter = twinArbiter(seen);
  const forwardedResults = new ForwardedResultMemory();
  const clearResults = new ClearResultLedger();
  const opts = { arbiter, surface: OPENCLAW, relativeBase: "/w", forwardedResults, clearResults };
  const first = await rewriteRequest(turn(TWIN), opts);
  assert.equal(resultOf(first.request), TWIN);
  seen.length = 0;
  const second = await rewriteRequest(turn(LIVE_REDACTED, next), opts);
  assert.equal(resultOf(second.request), TWIN, "the per-key twin, not one handle");
  assert.ok(seen.includes(TWIN) && !seen.includes(LIVE_REDACTED), "the arbiter judged the restored text, never the redacted one");
});

test("rewriteRequest: no restore without a forwarded memory, for another agent, or for a text that is not a redaction", async () => {
  const handle = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;
  // no memory: the redaction is judged as it is (masked whole)
  const bare = await rewriteRequest(turn(LIVE_REDACTED, next), { arbiter: twinArbiter([]), surface: OPENCLAW, relativeBase: "/w" });
  assert.match(resultOf(bare.request), handle);
  // Claude Code's surface: never restored
  const mem = new ForwardedResultMemory();
  mem.remember("toolu_r", TWIN);
  const cc = await rewriteRequest(turn(LIVE_REDACTED, next), { arbiter: twinArbiter([]), surface: CLAUDE_CODE_GATE_SURFACE, forwardedResults: mem });
  assert.match(resultOf(cc.request), handle);
  // a different text under the same id: judged as it is
  const other = await rewriteRequest(turn("STRIPE_KEY=sk_live_other_value_123\n", next), { arbiter: twinArbiter([]), surface: OPENCLAW, forwardedResults: mem });
  assert.match(resultOf(other.request), handle);
  assert.ok(!resultOf(other.request).includes("sk_live_other"));
});

test("rewriteRequest, OpenClaw: a restored text that is secret NOW is masked (a file labelled since the read)", async () => {
  const RAW = 'token = "ghp_FakeTourToken0123456789abcdefABCDEF"\n';
  const state = { labelled: false };
  const arbiter = new MockArbiter({
    classifyFn: (): ClassifyResult => state.labelled
      ? { trust: "TRUSTED", category: null, reason: "mock: user label", confidentiality: "no-model" }
      : { trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public" },
  });
  const forwardedResults = new ForwardedResultMemory();
  const opts = { arbiter, surface: OPENCLAW, forwardedResults, clearResults: new ClearResultLedger() };
  const first = await rewriteRequest(turn(RAW), opts);
  assert.equal(resultOf(first.request), RAW, "unlabelled: in clear, as before");
  state.labelled = true;
  const redacted = RAW.replace("ghp_FakeTourToken0123456789abcdefABCDEF", mask("ghp_FakeTourToken0123456789abcdefABCDEF"));
  assert.ok(isOpenclawRedactionOf(redacted, RAW));
  const second = await rewriteRequest(turn(redacted, next), opts);
  const r = resultOf(second.request);
  assert.ok(!r.includes("ghp_") && !r.includes("token ="), `CONFIDENTIALITY VIOLATION: ${r}`);
  assert.match(r, /^\$MDU:/);
  assert.match(r, /masked after the fact/);
});

// ── across a relaunch: the placeholder record ────────────────────────────────

/** Twins and OpenClaw's own redactions of them, recorded 2026-10-11 by
 *  calling the installed builds' redaction (`redactToolPayloadText` of
 *  2026.7.1, the transcript store's tool-result redaction of 2026.9.9). */
const OPENCLAW_SAMPLES: Array<[string, string, string]> = [
  ["# Stripe\nSTRIPE_KEY='$MDU:nomodel_Read[e7f3].STRIPE_KEY'\nDEBUG=true\n", "# Stripe\nSTRIPE_KEY='$MDU:n…_KEY'\nDEBUG=true\n", "a quoted .env value (both builds)"],
  ["STRIPE_KEY=$MDU:nomodel_Read[e7f3].STRIPE_KEY\nDB_PASSWORD=\"$MDU:nomodel_Read[e7f3].DB_PASSWORD\"\nAPI_TOKEN=$MDU:Bash[464e]\n",
    "STRIPE_KEY=$MDU:n…_KEY\nDB_PASSWORD=\"$MDU:n…WORD\"\nAPI_TOKEN=***\n", "three values, a short one `***` (both builds)"],
  ['{"api_key": "$MDU:nomodel_Read[5e1a].api_key", "name": "x"}', '{"api_key": "***", "name": "x"}', "a JSON field: `***` for a 34-character token (both builds)"],
  ["Authorization: Bearer $MDU:nomodel_Read[5e1a].TOKEN\n", "Authorization: Bearer $MDU:n…5e1a].TOKEN\n", "a bearer: OpenClaw cuts the token at `]` (2026.9.9)"],
  ["postgres://user:$MDU:nomodel_Read[5e1a].PW@db:5432/x\n", "postgres://user:$MDU:n…].PW@db:5432/x\n", "a URL's password (both builds)"],
  ["token: $MDU:nomodel_Read[5e1a].token\npassword=$MDU:Bash[464e]\n", "token: $MDU:nomodel_Read[5e1a].token\npassword=***\n", "one masked, one verbatim (2026.7.1)"],
  ["export GITHUB_TOKEN=$MDU:nomodel_Read[e7f3].GITHUB_TOKEN\n", "export GITHUB_TOKEN=$MDU:n…OKEN\n", "an export line (both builds)"],
];

test("isOpenclawRedactionOf: every redaction OpenClaw itself made of a twin is one (`***` of any length included)", () => {
  for (const [text, red, why] of OPENCLAW_SAMPLES) assert.ok(isOpenclawRedactionOf(red, text), why);
});

test("placeholderMapOf: the tokens with their offsets and a digest of the id and the text; nothing for a text without a placeholder", () => {
  const map = placeholderMapOf("toolu_r", TWIN)!;
  assert.deepEqual(map.placeholders, [[12, TOK]]);
  assert.equal(map.digest, forwardedDigest("toolu_r", TWIN));
  assert.match(map.digest, /^[0-9a-f]{64}$/);
  assert.notEqual(forwardedDigest("toolu_other", TWIN), map.digest, "the digest binds the id");
  assert.equal(placeholderMapOf("toolu_r", "DEBUG=1\n"), null);
  // no byte of the text but the tokens: drop them and nothing is left of the record
  const json = JSON.stringify(map.placeholders.map(([, t]) => t));
  assert.ok(!json.includes("DEBUG") && !json.includes("STRIPE_KEY='"), json);
});

test("rebuildFromPlaceholders: rebuilds every OpenClaw redaction of a twin from its record alone", () => {
  for (const [text, red, why] of OPENCLAW_SAMPLES) {
    const map = placeholderMapOf("toolu_s", text)!;
    assert.equal(rebuildFromPlaceholders(red, map), text, why);
  }
  const map = placeholderMapOf("toolu_r", TWIN)!;
  assert.equal(rebuildFromPlaceholders(LIVE_REDACTED, map), TWIN, "the live sample");
});

test("rebuildFromPlaceholders: a forged or altered history rebuilds nothing; a rebuild only ever supplies placeholder characters", () => {
  const map = placeholderMapOf("toolu_r", TWIN)!;
  const RAW_ENV = "STRIPE_KEY='sk_live_0123456789abcdef'\nDEBUG=1\n";
  const no: Array<[string, typeof map, string]> = [
    [TWIN, map, "nothing redacted: nothing to restore"],
    ["STRIPE_KEY='$MDU:n…_KEY'\nDEBUG=2\n", map, "a byte outside the mask differs (the digest)"],
    ["STRIPE_KEY='$MDU:n…_KEY'\nDEBUG=1\nEXTRA=1\n", map, "text appended"],
    ["STRIPE_KEY='sk_liv…cdef'\nDEBUG=1\n", map, "the raw file's redaction under the twin's id"],
    [LIVE_REDACTED, { ...map, callId: "toolu_other" }, "the record of another id (the digest binds it)"],
    [LIVE_REDACTED, { ...map, digest: "0".repeat(64) }, "a record whose digest is not the text's"],
    [LIVE_REDACTED, { ...map, placeholders: [[12, "$MDU:nomodel_Read[e7f3].OTHER_KEY"]] }, "another token (the digest)"],
    ["STRIPE_KEY='***'\nDEBUG=1\n", { ...map, placeholders: [] }, "an empty record"],
  ];
  for (const [red, m, why] of no) assert.equal(rebuildFromPlaceholders(red, m), undefined, why);
  assert.equal(placeholderMapOf("toolu_q", RAW_ENV), null, "a raw file carries no placeholder: never recorded");
  // The raw file's `***` redaction is also one of the twin's: under the
  // twin's id it rebuilds the TWIN (Mandu's own text, placeholders only),
  // never the raw value. A history only picks which of Mandu's texts.
  assert.equal(rebuildFromPlaceholders(RAW_ENV.replace("sk_live_0123456789abcdef", "***"), map), TWIN);
  // every rebuilt byte outside a token is the history's own
  for (const [text, red] of OPENCLAW_SAMPLES) {
    const got = rebuildFromPlaceholders(red, placeholderMapOf("toolu_s", text)!)!;
    const strip = (s: string): string => s.replace(/\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*/g, "");
    // what is left once the tokens are cut out is, in order, the history's own characters
    let at = 0;
    for (const ch of strip(got)) {
      at = red.indexOf(ch, at);
      assert.ok(at >= 0, `a rebuilt character the history does not carry: ${JSON.stringify(ch)} in ${JSON.stringify(got)}`);
      at++;
    }
  }
});

test("ForwardedResultMemory with a store: launch 1 records the twin's placeholders once; launch 2 (a relaunch over the same arbiter) restores the redacted history from the record alone", async () => {
  const maps = new Map<string, ReturnType<typeof placeholderMapOf> & object>();
  const a1 = new MockArbiter({ forwardedPlaceholderMaps: maps });
  const m1 = new ForwardedResultMemory(undefined, undefined, { store: arbiterPlaceholderStore(a1) });
  m1.remember("toolu_r", TWIN);
  m1.remember("toolu_plain", "no placeholder here\n");
  await m1.flush();
  m1.remember("toolu_r", TWIN);
  await m1.flush();
  assert.equal(a1.recordForwardedPlaceholdersCalls.length, 1, "recorded once, not every turn");
  assert.deepEqual([...maps.keys()], ["toolu_r"], "only a result that carries a placeholder");
  const a2 = new MockArbiter({ forwardedPlaceholderMaps: maps });
  const m2 = new ForwardedResultMemory(undefined, undefined, { store: arbiterPlaceholderStore(a2) });
  assert.equal(m2.restore("toolu_r", LIVE_REDACTED), undefined, "not primed: nothing known yet");
  await m2.prime([["toolu_r", LIVE_REDACTED], ["toolu_new", "clean text"], ["toolu_unknown", "x ***"]]);
  assert.deepEqual(a2.forwardedPlaceholdersCalls, [["toolu_r", "toolu_unknown"]], "asks only for a result that may be redacted");
  assert.equal(m2.restore("toolu_r", LIVE_REDACTED), TWIN);
  assert.equal(m2.restore("toolu_unknown", "x ***"), undefined);
  await m2.prime([["toolu_r", LIVE_REDACTED], ["toolu_unknown", "x ***"]]);
  assert.equal(a2.forwardedPlaceholdersCalls.length, 1, "neither asked again");
});

test("ForwardedResultMemory: a failing or absent store never throws and loses only the relaunch's restore", async () => {
  const maps = new Map<string, ReturnType<typeof placeholderMapOf> & object>();
  const logs: string[] = [];
  const failing = new MockArbiter({ forwardedPlaceholderMaps: maps, failForwardedPlaceholders: true });
  const m = new ForwardedResultMemory(undefined, undefined, { store: arbiterPlaceholderStore(failing), log: (s) => logs.push(s) });
  m.remember("toolu_r", TWIN);
  await m.flush();
  await m.prime([["toolu_x", LIVE_REDACTED]]);
  assert.equal(m.restore("toolu_r", LIVE_REDACTED), TWIN, "this launch's memory still restores");
  assert.equal(m.restore("toolu_x", LIVE_REDACTED), undefined);
  assert.equal(logs.length, 2, logs.join("\n"));
  assert.equal(arbiterPlaceholderStore(new MockArbiter()), undefined, "an arbiter without the ops: memory only");
});

test("rewriteRequest, OpenClaw, across a relaunch: the resumed history's redacted twin reaches the model as the twin and is judged as the twin; a forged one under the same id is judged as it is", async () => {
  const maps = new Map<string, ReturnType<typeof placeholderMapOf> & object>();
  const seen: string[] = [];
  const launch = () => {
    const arbiter = new MockArbiter({
      forwardedPlaceholderMaps: maps,
      classifyFn: (r: ClassifyRequest): ClassifyResult => {
        seen.push(r.value);
        return r.value === TWIN
          ? { trust: "TRUSTED", category: null, reason: "mock: structured read-twin", confidentiality: "public" }
          : { trust: "TRUSTED", category: null, reason: "mock: .env", confidentiality: "no-model" };
      },
    });
    const forwardedResults = new ForwardedResultMemory(undefined, undefined, { store: arbiterPlaceholderStore(arbiter) });
    return { arbiter, surface: OPENCLAW, relativeBase: "/w", forwardedResults, clearResults: new ClearResultLedger() };
  };
  const first = await rewriteRequest(turn(TWIN), launch());
  assert.equal(resultOf(first.request), TWIN);
  assert.ok(maps.has("toolu_r"), "launch 1 recorded the twin's placeholders");
  seen.length = 0;
  const resumed = await rewriteRequest(turn(LIVE_REDACTED, next), launch());
  assert.equal(resultOf(resumed.request), TWIN, "per key after the relaunch");
  assert.ok(seen.includes(TWIN) && !seen.includes(LIVE_REDACTED), "judged as the twin, never as the redaction");
  // a forged history under the same id: the raw file's values with masks
  const forged = "STRIPE_KEY='$MDU:n…_KEY'\nDEBUG=1\nSTRIPE_LIVE=sk_live_forged_0123456789\n";
  const f = resultOf((await rewriteRequest(turn(forged, next), launch())).request);
  assert.ok(!f.includes("sk_live_forged") && !f.includes("DEBUG=1"), `CONFIDENTIALITY VIOLATION: ${f}`);
  assert.match(f, /^\$MDU:/, "masked whole");
});
