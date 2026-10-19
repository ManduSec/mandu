/**
 * typing — a placeholder typed a key at a time (typing.ts; devtools-relay.md
 * §3.3): which texts can still grow into a placeholder, which are exactly
 * one, which key events type, and the run: held from its `$`, a run that is
 * a placeholder ends as a release (the textless keys after its last
 * character forwarded after it), anything else ends as every held command
 * forwarded as sent, in order (secrets axes, explicit: no arbiter here). A
 * lookalike (a code no placeholder has, such as a UUID) is held, decided on
 * the key that closes its code (`decide`, for the relay to refuse on that
 * key), and ends dropped; a placeholder's code is checked on that same key
 * (`check`, for the relay to ask the arbiter), and a run the relay refuses
 * there (`refuse()`) ends dropped; a run is bounded.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { stateAxes } from "../axes.js";
import { KeyRun, MAX_RUN_KEYS, MAX_RUN_TEXT, heldPrefix, placeholderPrefix, typedText, wholePlaceholder, type KeyCommand } from "../../src/typing.js";
import { LOOKALIKE_MAX_CODE } from "../../src/symbols.js";

stateAxes("secrets");

const SYM = "$MDU:nomodel_Read[062f].STRIPE_SECRET_KEY";

test("placeholderPrefix: every start of a placeholder, and nothing that cannot become one", () => {
  for (let i = 1; i <= SYM.length; i++) assert.ok(placeholderPrefix(SYM.slice(0, i)), SYM.slice(0, i));
  assert.ok(placeholderPrefix("$MDU:nomodel_STRIPE_KEY[7f3a]"), "a placeholder with no name part");
  assert.ok(placeholderPrefix(`${SYM}.sub`), "a name goes on with dots");
  for (const no of ["5", "$5", "$M5", "$MDU;", "$MDU:1x", "$MDU:k[0g", "$MDU:k[012]", "$MDU:k[0123456789]", "$MDU:k[0123]x", "$MDU:k[0123].1", `${SYM} `, `${SYM}-`]) {
    assert.equal(placeholderPrefix(no), false, no);
  }
  assert.ok(placeholderPrefix("$MDU:k["), "an open hash may still come");
  assert.equal(placeholderPrefix("$MDU:k[012]"), false, "a hash has 4 to 8 digits");
});

test("wholePlaceholder: exactly one placeholder, no more, no less", () => {
  assert.ok(wholePlaceholder(SYM));
  assert.ok(wholePlaceholder("$MDU:nomodel_STRIPE_KEY[7f3a]"));
  for (const no of ["$MDU:", "$MDU:nomodel_Read[062f", ` ${SYM}`, `${SYM} x`, `${SYM}${SYM}`]) assert.equal(wholePlaceholder(no), false, no);
});

test("typedText: keyDown and char type their text; keyUp, rawKeyDown and textless keys type nothing", () => {
  const k = (params: Record<string, unknown>): KeyCommand => ({ id: 1, method: "Input.dispatchKeyEvent", params });
  assert.equal(typedText(k({ type: "char", text: "$" })), "$");
  assert.equal(typedText(k({ type: "keyDown", key: "a", text: "a" })), "a");
  assert.equal(typedText(k({ type: "keyDown", key: "a" })), null);
  assert.equal(typedText(k({ type: "keyUp", key: "a", text: "a" })), null);
  assert.equal(typedText(k({ type: "rawKeyDown", key: "a", text: "a" })), null);
  assert.equal(typedText({ id: 1, method: "Input.insertText", params: { text: "a" } }), null);
});

let seq = 0;
/** browser-use's three events per character: keyDown (no text), char, keyUp. */
function browserUseKeys(text: string, sessionId?: string): KeyCommand[] {
  return [...text].flatMap((ch) => [
    { id: ++seq, method: "Input.dispatchKeyEvent", params: { type: "keyDown", key: ch }, ...(sessionId ? { sessionId } : {}) },
    { id: ++seq, method: "Input.dispatchKeyEvent", params: { type: "char", text: ch, key: ch }, ...(sessionId ? { sessionId } : {}) },
    { id: ++seq, method: "Input.dispatchKeyEvent", params: { type: "keyUp", key: ch }, ...(sessionId ? { sessionId } : {}) },
  ]);
}

test("a placeholder typed browser-use's way is held from its $ and ends as one release; the keys after it (an Enter's keyDown) follow it", () => {
  const run = new KeyRun();
  const keys = [...browserUseKeys("a"), ...browserUseKeys(SYM, "S1")];
  const enterDown: KeyCommand = { id: ++seq, method: "Input.dispatchKeyEvent", params: { type: "keyDown", key: "Enter" }, sessionId: "S1" };
  const enterChar: KeyCommand = { id: ++seq, method: "Input.dispatchKeyEvent", params: { type: "char", text: "\r" }, sessionId: "S1" };
  const steps = [...keys, enterDown].map((k) => run.key(k).kind);
  // "a": 3 forwarded; "$": its keyDown forwarded (it types nothing), then held from its char on
  assert.deepEqual(steps.slice(0, 4), ["forward", "forward", "forward", "forward"]);
  const check = 3 + SYM.indexOf("]") * 3 + 1;
  assert.equal(steps[check], "check", "the ]'s char that closes the code asks for a check (held too: the relay answers it)");
  assert.ok(steps.slice(4).every((s, i) => i + 4 === check || s === "hold"), "everything else from the $ on is held");
  const step = run.key(enterChar);
  assert.equal(step.kind, "ended");
  const end = (step as { end: unknown }).end as { kind: string; text: string; sessionId: string; after: KeyCommand[] };
  assert.equal(end.kind, "release");
  assert.equal(end.text, SYM);
  assert.equal(end.sessionId, "S1");
  assert.deepEqual(end.after.map((c) => c.params!["type"] + ":" + (c.params!["key"] ?? "")), [`keyUp:${SYM.at(-1)}`, "keyDown:Enter"], "the textless keys after the last character, in order");
  assert.equal(run.holding, false);
  assert.equal(run.key(enterChar).kind, "forward", "the breaking key is taken again, outside the run");
});

test("a run that is not a placeholder ends as every held command forwarded as sent, in order", () => {
  const run = new KeyRun();
  const keys = browserUseKeys("$5");
  for (const k of keys.slice(0, 4)) run.key(k);
  const step = run.key(keys[4]!); // the "5" char: "$5" cannot become a placeholder
  assert.equal(step.kind, "ended");
  const end = (step as { end: { kind: string; commands: KeyCommand[] } }).end;
  assert.equal(end.kind, "forward");
  assert.deepEqual(end.commands.map((c) => c.id), keys.slice(1, 4).map((c) => c.id), "the $'s char, its keyUp, the 5's keyDown");
  assert.equal(run.key(keys[4]!).kind, "forward");
});

test("Puppeteer's way (keyDown with text, keyUp); the run ended by another command or the agent going quiet (end); a prefix only is forwarded", () => {
  const run = new KeyRun();
  for (const ch of SYM) {
    run.key({ id: ++seq, method: "Input.dispatchKeyEvent", params: { type: "keyDown", key: ch, text: ch } });
    run.key({ id: ++seq, method: "Input.dispatchKeyEvent", params: { type: "keyUp", key: ch } });
  }
  const end = run.end();
  assert.equal(end?.kind, "release");
  assert.equal((end as { text: string }).text, SYM);
  assert.equal(run.end(), null, "nothing held: nothing to end");
  for (const k of browserUseKeys("$MDU:nomodel_Read[06")) run.key(k);
  const partial = run.end();
  assert.equal(partial?.kind, "forward", "an unfinished placeholder is the agent's literal text");
});

test("a key on another target ends the run first", () => {
  const run = new KeyRun();
  for (const k of browserUseKeys(SYM, "S1")) run.key(k);
  const other = browserUseKeys("x", "S2");
  const step = run.key(other[1]!);
  assert.equal(step.kind, "ended");
  assert.equal((step as { end: { kind: string } }).end.kind, "release");
});

test("a placeholder-shaped run the arbiter may not know still ends as a release: the gate (release.ts), not the run, tells it unknown", () => {
  const run = new KeyRun();
  const madeUp = "$MDU:nomodel_Read[062e].STRIPE_SECRET_KEY";
  for (const k of browserUseKeys(madeUp)) run.key(k);
  const end = run.end();
  assert.equal(end?.kind, "release", "never forwarded as typed: its characters would reach the page");
  assert.equal(end?.kind === "release" ? end.text : null, madeUp);
});

// ── A lookalike typed a key at a time (§3.3) ──────────────────────────────

/** What the live expense-report demo's model typed into the card field. */
const UUID_LOOKALIKE = "$MDU:nomodel_Read[e213b2c2-8419-4809-b684-297d264f3319].number";

test("heldPrefix: every start of a placeholder or of a lookalike, bounded; placeholderPrefix stays the placeholder's own", () => {
  for (const s of [SYM, UUID_LOOKALIKE, "$MDU:k[5958-ab]", "$MDU:k[7F3A].x", "$MDU:k[0123456789]", "$MDU:k[zz]"]) {
    for (let i = 1; i <= s.length; i++) assert.ok(heldPrefix(s.slice(0, i)), s.slice(0, i));
  }
  for (const no of ["5", "$5", "$MDU;", "$MDU:1x", "$MDU:k[]", "$MDU:k[ab ", "$MDU:k[0123]x", "$MDU:k[0123].1", `${UUID_LOOKALIKE} `, `$MDU:k[${"z".repeat(LOOKALIKE_MAX_CODE + 1)}`]) {
    assert.equal(heldPrefix(no), false, no);
  }
  assert.ok(heldPrefix(`$MDU:k[${"z".repeat(LOOKALIKE_MAX_CODE)}]`), "a code of the bound itself");
  assert.equal(heldPrefix(`$MDU:${"k".repeat(MAX_RUN_TEXT)}`), false, "no run holds more than MAX_RUN_TEXT characters");
  assert.equal(placeholderPrefix("$MDU:k[0g"), false, "the placeholder's own grammar is unchanged");
});

test("a lookalike typed browser-use's way is decided on the key that closes its code, the rest of it held, and the run ends dropped; the keys after it follow", () => {
  for (const look of [UUID_LOOKALIKE, "$MDU:nomodel_Read[5958-ab].extract_1", "$MDU:nomodel_Read[5958A]", "$MDU:nomodel_Read[595812345].extract_1", "$MDU:nomodel_Read[012].x"]) {
    const run = new KeyRun();
    const keys = browserUseKeys(look, "S1");
    const steps = keys.map((k) => run.key(k));
    const close = look.indexOf("]");
    const decided = steps.findIndex((s) => s.kind === "decide");
    assert.equal(decided, close * 3 + 1, `${look}: decided on the char event of the "]" that closes the code`);
    const d = steps[decided] as { kind: "decide"; text: string; sessionId?: string };
    assert.equal(d.text, look.slice(0, close + 1), "the lookalike as far as it went");
    assert.equal(d.sessionId, "S1");
    assert.ok(steps.slice(1).every((s, i) => i + 1 === decided || s.kind === "hold"), `${look}: every other key from the $ on is held, none reaches the page`);
    const space = browserUseKeys(" ", "S1");
    run.key(space[0]!); // the space's keyDown types nothing: held
    const step = run.key(space[1]!);
    assert.equal(step.kind, "ended", look);
    const end = (step as { end: { kind: string; after?: KeyCommand[] } }).end;
    assert.equal(end.kind, "dropped", `${look}: never forwarded as typed, never released`);
    assert.deepEqual(end.after?.map((c) => c.params!["type"]), ["keyUp", "keyDown"], "the textless keys after its last character");
  }
});

test("a lookalike is decided once; a run decided that grows into no lookalike at all (a trailing dot) still ends dropped; a placeholder is never decided on its way", () => {
  const run = new KeyRun();
  const steps = browserUseKeys("$MDU:k[ab-c].x[0]").map((k) => run.key(k).kind);
  assert.equal(steps.filter((s) => s === "decide").length, 1, "decided at the first ] only");
  assert.equal(run.end()?.kind, "dropped");
  for (const k of browserUseKeys("$MDU:k[ab-c].")) run.key(k);
  const step = run.key(browserUseKeys("-")[1]!);
  assert.equal(step.kind, "ended");
  assert.equal((step as { end: { kind: string } }).end.kind, "dropped", "the dot it grew is dropped too");
  const sym = new KeyRun();
  const kinds = browserUseKeys(`${SYM}.a[0]`).map((k) => sym.key(k).kind);
  assert.ok(!kinds.includes("decide"), "a placeholder (a ] in its name included) is decided when it ends, by the gate");
  assert.equal(kinds.filter((k) => k === "check").length, 1, "its code is checked once, at the ] that closes it (not at the field's own ])");
  assert.equal(sym.end()?.kind, "release");
});

test("a placeholder's code is checked on the key that closes it (browser-use's char, Puppeteer's keyDown); the relay's refuse() makes the run end dropped whatever it grows into, and the next run starts afresh", () => {
  // browser-use's way: the ]'s char event
  const run = new KeyRun();
  const steps = browserUseKeys(SYM, "S1").map((k) => run.key(k));
  const close = SYM.indexOf("]");
  const at = steps.findIndex((s) => s.kind === "check");
  assert.equal(at, close * 3 + 1, "the char event of the ] that closes the code");
  assert.deepEqual(steps[at], { kind: "check", base: SYM.slice(0, close + 1), sessionId: "S1" }, "the base, as far as it went");
  assert.equal(run.end()?.kind, "release", "known (refuse() not called): decided at its end by the gate, as before");

  // refused on the check: the field typed after it and a key after it
  const refused = new KeyRun();
  for (const k of browserUseKeys(SYM.slice(0, close + 1), "S1")) refused.key(k);
  refused.refuse();
  for (const k of browserUseKeys(SYM.slice(close + 1), "S1")) assert.equal(refused.key(k).kind, "hold", "the rest of it is held, never forwarded");
  const space = browserUseKeys(" ", "S1");
  refused.key(space[0]!);
  const step = refused.key(space[1]!);
  assert.equal(step.kind, "ended");
  const end = (step as { end: { kind: string; after?: KeyCommand[] } }).end;
  assert.equal(end.kind, "dropped", "none of it goes, never released");
  assert.deepEqual(end.after?.map((c) => c.params!["type"]), ["keyUp", "keyDown"]);
  assert.equal(refused.key(space[1]!).kind, "forward", "the space goes, outside the run");
  assert.equal(refused.key(browserUseKeys("$")[1]!).kind, "hold");
  assert.equal(refused.end()?.kind, "forward", "the refusal did not carry over to the next run");
  refused.refuse();
  assert.equal(refused.holding, false, "refuse() with nothing held is nothing");
  assert.equal(refused.key(browserUseKeys("$")[1]!).kind, "hold");
  assert.equal(refused.end()?.kind, "forward", "and leaves no refusal behind");

  // Puppeteer's way: the ]'s keyDown carries the text
  const pup = new KeyRun();
  const kinds: string[] = [];
  for (const ch of SYM) {
    kinds.push(pup.key({ id: ++seq, method: "Input.dispatchKeyEvent", params: { type: "keyDown", key: ch, text: ch } }).kind);
    pup.key({ id: ++seq, method: "Input.dispatchKeyEvent", params: { type: "keyUp", key: ch } });
  }
  assert.equal(kinds.indexOf("check"), close);
  assert.equal(kinds.filter((k) => k === "check").length, 1);

  // a lookalike is decided, never checked (it names nothing: no lookup)
  const look = new KeyRun();
  const lk = browserUseKeys(UUID_LOOKALIKE).map((k) => look.key(k).kind);
  assert.ok(!lk.includes("check") && lk.includes("decide"));
});

test("a lookalike run ended by quiet or another command ends dropped too; Puppeteer's way (keyDown with the text) is decided on the ] keyDown", () => {
  const run = new KeyRun();
  const kinds: string[] = [];
  for (const ch of UUID_LOOKALIKE) {
    kinds.push(run.key({ id: ++seq, method: "Input.dispatchKeyEvent", params: { type: "keyDown", key: ch, text: ch } }).kind);
    run.key({ id: ++seq, method: "Input.dispatchKeyEvent", params: { type: "keyUp", key: ch } });
  }
  assert.equal(kinds.indexOf("decide"), UUID_LOOKALIKE.indexOf("]"));
  const end = run.end();
  assert.equal(end?.kind, "dropped");
  assert.equal(run.holding, false);
  assert.equal(run.key(browserUseKeys("$")[1]!).kind, "hold", "the next run starts afresh");
  assert.equal(run.end()?.kind, "forward", "a lone $ is typed as it was: the refusal did not carry over");
});

test("text that is neither a placeholder nor a lookalike is forwarded as typed, in order: whitespace in the code, an unclosed or too-long code, prose", () => {
  for (const text of ["$MDU docs", "$MDU:", "$MDU:foo", "$MDU:k[ab cd]", "$MDU:k[e213b2c2-8419", `$MDU:k[${"z".repeat(LOOKALIKE_MAX_CODE + 1)}]`]) {
    const run = new KeyRun();
    const keys = browserUseKeys(text);
    const forwarded: number[] = [];
    for (const k of keys) {
      const step = run.key(k);
      if (step.kind === "forward") forwarded.push(k.id);
      if (step.kind === "ended") {
        assert.equal(step.end.kind, "forward", text);
        if (step.end.kind === "forward") forwarded.push(...step.end.commands.map((c) => c.id));
        const again = run.key(k);
        if (again.kind === "forward") forwarded.push(k.id);
      }
    }
    const last = run.end();
    if (last !== null) {
      assert.equal(last.kind, "forward", text);
      if (last.kind === "forward") forwarded.push(...last.commands.map((c) => c.id));
    }
    assert.deepEqual(forwarded, keys.map((k) => k.id), `${text}: every key forwarded, in order`);
  }
});

test("a run holds at most MAX_RUN_KEYS events: a stream of textless keys cannot hold forever", () => {
  const run = new KeyRun();
  for (const k of browserUseKeys("$MDU:k[ab")) run.key(k);
  let ended = false;
  for (let i = 0; i < MAX_RUN_KEYS + 1 && !ended; i++) {
    const step = run.key({ id: ++seq, method: "Input.dispatchKeyEvent", params: { type: "keyUp", key: "Shift" } });
    if (step.kind === "ended") {
      ended = true;
      assert.equal(step.end.kind, "forward", "an unfinished lookalike is the agent's literal text");
    }
  }
  assert.ok(ended, "the run ended at the bound");
  assert.equal(run.holding, false);
});
