/**
 * secret-note.test.ts — dashboard.md §4.25b "A refused read is a block, not a
 * mask": the `[mandu:secret]` note rule the product's session page and the
 * inspector share (view-model/secret-note.ts), and where the inspector's
 * projection carries it: the tool step's `readRefused` (dual-lanes.ts, read
 * by session-counts.ts and dev/js/app.js) and the paired row's `refusedRead`
 * sentence (paired-rows.ts). Pure: notes and events in, counts and words out.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { toSessionViewModel } from "../../../src/view-model.js";
import { refusedReadNote } from "../../../src/view-model/agent-page.js";
import type { DualToolStep } from "../../../src/view-model/dual-lanes.js";
import type { PairedToolRow } from "../../../src/view-model/paired-rows.js";
import { maskCause, noteMasks, readRefusals, refusedReadWords } from "../../../src/view-model/secret-note.js";
import { walkthroughEvents } from "./walkthrough-fixture.js";

// rewrite-request.ts `buildSecretNote`'s forms.
const REFUSED = "[mandu:secret] refused: curl tried to connect out and Mandu refused the connection, nothing was sent: the request carried a masked value ($MDU placeholder) that may not be sent to that host.";
const DENIED = "[mandu:secret] denied: cat is not a reader of /home/dev/app/.env (no reader rule names cat). The user can allow it in policy.yaml (paths[].readers).";
const HELD = "[mandu:secret] held: mytool waited for the user to allow it to read /home/dev/app/.env (held for 60 s, nobody answered; the approval is still waiting in the dashboard). Tell the user the request is waiting on the Mandu dashboard's Approvals page; once they allow it, the same command succeeds without a new prompt. Do not retry before that.";
const MASKED = "[mandu:secret] masked: sh read /home/dev/app/.env; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Say so rather than retrying.";
const RELEASED = "[mandu:secret] note: psql read /home/dev/.pgpass (a listed reader); the output is released by the program's rule.";

test("readRefusals: the reads a note refused, only when refusing them is all it says", () => {
  assert.deepEqual(readRefusals(DENIED), { denied: 1, held: 0 });
  assert.deepEqual(readRefusals(HELD), { denied: 0, held: 1 });
  assert.deepEqual(readRefusals(`${DENIED}\n${HELD}\n${HELD}\n`), { denied: 1, held: 2 }, "several lines, a trailing newline");
  assert.deepEqual(readRefusals(`${REFUSED}\n${DENIED}`), { denied: 1, held: 0 }, "a refused connection beside it is no read");
  // A note that masks anything keeps the masked reading: no refused read.
  assert.equal(readRefusals(`${MASKED}\n${HELD}`), null);
  assert.equal(readRefusals(`${RELEASED}\n${DENIED}`), null, "a form this rule does not read: as before");
  assert.equal(readRefusals(REFUSED), null, "a refused connection alone refused no read");
  assert.equal(readRefusals("secret masked"), null);
  assert.equal(readRefusals(null), null);
  assert.equal(readRefusals(""), null);
  assert.equal(noteMasks(DENIED), false);
  assert.equal(noteMasks(`${MASKED}\n${DENIED}`), true);
});

test("refusedReadWords: the session page's words, counts only (never a program or a path)", () => {
  for (const note of [DENIED, HELD, `${DENIED}\n${DENIED}`, `${HELD}\n${HELD}`, `${DENIED}\n${HELD}`, `${DENIED}\n${HELD}\n${HELD}`]) {
    const words = refusedReadWords(readRefusals(note)!);
    assert.equal(words, refusedReadNote(note), "the product's step note is this sentence");
    assert.doesNotMatch(words, /\/home|\.env|\bcat\b|mytool/);
  }
  assert.equal(refusedReadWords({ denied: 1, held: 0 }), "Mandu stopped a program from reading a secret file, so the AI got the command's output without it.");
  assert.equal(refusedReadWords({ denied: 0, held: 1 }), "Mandu held a program's read of a secret file and asked for your OK. Nobody answered in time, so the AI got the command's output without it.");
});

test("the inspector's projection: a refused read's tool step carries readRefused, and its paired row the session page's sentence", () => {
  const vm = toSessionViewModel("walk", walkthroughEvents({ session: "walk", readRefusals: true }));
  const tools = vm.dualLanes.steps.filter((s): s is DualToolStep => s.step === "tool");
  const byCall = new Map(tools.map((t) => [t.callId, t]));
  assert.deepEqual(byCall.get("c7")!.readRefused, { denied: 1, held: 0 });
  assert.deepEqual(byCall.get("c8")!.readRefused, { denied: 0, held: 1 });
  for (const t of tools) {
    if (t.callId !== "c7" && t.callId !== "c8") assert.equal("readRefused" in t, false, `${t.callId}: no field on a step that refused no read`);
  }
  const rows = vm.paired.turns.flatMap((t) => t.rows).filter((r): r is PairedToolRow => r.row === "tool");
  const row = (callId: string) => rows.find((r) => r.stepId === `tool:${callId}`)!;
  assert.equal(row("c7").refusedRead, refusedReadNote(byCall.get("c7")!.secretNote));
  assert.equal(row("c8").refusedRead, refusedReadNote(byCall.get("c8")!.secretNote));
  assert.equal(row("c7").masked, false, "the program's own output: nothing masked");
  for (const r of rows) {
    if (r.stepId !== "tool:c7" && r.stepId !== "tool:c8") assert.equal("refusedRead" in r, false, `${r.stepId}: no sentence`);
  }
  // The same session without the refused reads: no field anywhere.
  const plain = toSessionViewModel("walk", walkthroughEvents({ session: "walk" }));
  assert.ok(plain.dualLanes.steps.every((s) => !("readRefused" in s)));
});

test("a re-sent result keeps what the AI got at its own turn: readRefused is read off the first delivery", () => {
  const events = walkthroughEvents({ session: "walk", readRefusals: true });
  const first = events.find((e) => e.kind === "tool_result" && e.callId === "c7")!;
  // A later request re-sends the same result with a note that masks.
  const resent = { ...first, id: "walk-resent", seq: 999, ts: "2026-10-04T14:00:00.000Z", secretNote: MASKED };
  const vm = toSessionViewModel("walk", [...events, resent]);
  const c7 = vm.dualLanes.steps.find((s): s is DualToolStep => s.step === "tool" && s.callId === "c7")!;
  assert.deepEqual(c7.readRefused, { denied: 1, held: 0 });
  assert.equal(c7.repeats, 2, "the re-send folded");
});

// rewrite-request.ts `pathDerivedLine`'s forms (confidentiality.md §7.1).
const pathDerived = (named: string): string => `[mandu:secret] masked: the command names ${named}, so its whole output is hidden from you, including whether it succeeded; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Everything else it printed is hidden with it: to read another file, a listing or a log, run that part again as a command of its own that names no secret file. Do not assume it worked: if you still cannot tell, say you cannot see the result, or ask the user what it printed.`;
const TWIN = "[mandu:secret] twin: this is /home/dev/app/.env as you see it: the keys as written, each secret value a symbol. Use the symbol where the value belongs (a command that sends it is checked against the file's rules); the user sees the real values.";
/** The key listing form (plan 10 §11.8, 2026-10-16): a release, no mask cause. */
const TWIN_KEYS = "[mandu:secret] twin: these are the key names in /home/dev/app/.env, and the lines of it that hold no masked value, as you see the file; no masked value is in this output. Read the file (or cat it) to see each masked value as a symbol, and use the symbol where the value belongs (a command that sends it is checked against the file's rules); the user sees the real values.";
/** The folder-names form (plan 10 §11.8 "A folder's names", 2026-10-17): a release, no mask cause. */
const LISTING = "[mandu:secret] listing: these are the names in /home/dev/ws/bank, /home/dev/ws/mail/inbox as ls printed them, and nothing else: no file's content, size or date. The files there may still be secret: reading one shows you a symbol where its secret content is.";
const FAIL_CLOSED = "[mandu:secret] masked: the process taint could not be read: masked (fail-closed). The user does not see this output unless your reply quotes the symbol (they then see its real value).";
const SESSION = "[mandu:secret] masked: plan 13 D7: Mandu could not tie this Bash call to the processes that ran it, and programs in this session read .env raw; the whole output is secret. The user does not see this output unless your reply quotes the symbol (they then see its real value).";

test("maskCause: why the proxy masked a command's whole output, from its two `masked:` forms (§4.25b *A command's masked output says why*)", () => {
  // The command names secret files: the model's own tokens, as written.
  assert.deepEqual(maskCause(pathDerived("a secret file (./.env)")), { kind: "names", paths: ["./.env"] });
  assert.deepEqual(maskCause(pathDerived("secret files (./.env, ~/.aws/credentials, /etc/app/key.pem)")), { kind: "names", paths: ["./.env", "~/.aws/credentials", "/etc/app/key.pem"] });
  assert.deepEqual(maskCause(pathDerived("a secret file")), { kind: "names", paths: [] }, "no token of the command held a path: none named");
  assert.deepEqual(maskCause(pathDerived("a secret file (./conf (old), a.env)")), { kind: "names", paths: ["./conf (old), a.env"] }, "one path is never split, a `)` or `, ` in it");
  // The way to the file itself (confidentiality.md §7.1, 2026-10-19): the
  // sentence after it, with its own parentheses, changes nothing.
  const withTwin = pathDerived("a secret file (taxes/2025/*)").replace(" Do not assume", " To use each secret file taxes/2025/* matches itself, read it on its own (a file read of that one file, or `cat` with that file alone): you see each line's label as written and its value as a symbol you can pass to a command (a command that sends it is checked against the file's rules). Do not assume");
  assert.deepEqual(maskCause(withTwin), { kind: "names", paths: ["taxes/2025/*"] });
  // Programs of the command read secret files: apps as recorded, files absolute.
  assert.deepEqual(maskCause(MASKED), { kind: "read", apps: ["sh"], files: ["/home/dev/app/.env"] });
  const two = "[mandu:secret] masked: sh, psql read /home/dev/.pgpass, /home/dev/My Files, old/.env; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Say so rather than retrying.";
  assert.deepEqual(maskCause(two), { kind: "read", apps: ["sh", "psql"], files: ["/home/dev/.pgpass", "/home/dev/My Files, old/.env"] }, "a file splits only before an absolute path");
  assert.deepEqual(maskCause(MASKED.replace("masked: sh read", "masked:  read")), { kind: "read", apps: [], files: ["/home/dev/app/.env"] }, "no program recorded");
  // Beside other lines: the first reason; a refusal or a twin line changes nothing.
  assert.deepEqual(maskCause(`${TWIN}\n${MASKED}\n${HELD}\n`), { kind: "read", apps: ["sh"], files: ["/home/dev/app/.env"] });
  assert.deepEqual(maskCause(`${pathDerived("a secret file (./.env)")}\n${REFUSED}`), { kind: "names", paths: ["./.env"] });
  // Any other form gives no reason: the page keeps its own words.
  for (const note of [REFUSED, DENIED, HELD, RELEASED, TWIN, TWIN_KEYS, LISTING, FAIL_CLOSED, SESSION, "secret masked", "", null, undefined]) {
    assert.equal(maskCause(note), null, String(note));
  }
  assert.equal(maskCause(`[mandu:secret] masked after the fact: when you first read this result, earlier in this conversation, it showed you its real content; …`), null);
});
