/**
 * secret-path.test — where a secret went, on its card and in the developer
 * view's *Where each went* (dashboard.md §4.25b *Where it went*,
 * symbol-lineage.md §5.6). Contracts:
 *   - a registered secret's placeholder printed by a command is named by
 *     the file the registry says it stands for, never by the command (the
 *     2026-10-28 card "`ORDERHUB_PASSPHRASE` in `DEBUG=1 sh …`" and its
 *     Rules link to a file of that name); with no registry answer, "in a
 *     file", and no Rules link;
 *   - the step that held it says where it is kept ("… from `~/app/.env`");
 *   - the card's path: where it is kept, how it came in (the step's own
 *     sentence and time, the time opening the step), what the AI got, and
 *     that it left this computer never with its real value, only where the
 *     card's lines say Mandu filled it in nowhere; a host Mandu sent the
 *     real value to is off this computer (`side: "off"`), its stops and
 *     the rest on it;
 *   - an earlier leak: the kept scan's finding for the same file and the
 *     same key, in a session without Mandu, as one line; another key,
 *     another file or sessions all under Mandu say nothing;
 *   - an unchecked record: no card and no count, and each secret its
 *     events tell of under `recorded`, with its path and no "never" node;
 *   - names, paths and times only: never the value, never a token.
 *
 * Axes: none (a pure projection; the mode is read from the recorded events).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { buildAgentPage } from "../../../src/view-model/agent-page.js";
import { believedEvents, recordUnchecked } from "../../../src/event-model.js";
import { toSessionViewModel } from "../../../src/view-model.js";
import { baseSymbol, earlierLeak, earlierParts, lineageNotes, registeredFileOf, registeredFiles } from "../../../src/view-model/secret-path.js";
import type { LastScanWire, ScanFindingWire } from "../../../src/view-model/last-scan.js";
import { BASE, CMD, events, FILE, HOME, SENT_HOST, SESSION, STOPPED_HOST, TWIN, VALUE } from "./plugin-path-fixture.js";

const words = (parts: { text: string }[]) => parts.map((p) => p.text).join("");

function scanOf(findings: ScanFindingWire[]): LastScanWire {
  return {
    version: 1, ranAt: "2026-10-28T08:00:00.000Z", sessions: { openclaw: 2 }, duringMandu: 0, known: findings.length, findings, dropped: 0,
    capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 }, suggestions: null,
  };
}
const LEAK: ScanFindingWire = {
  kind: "known", preview: "Ju…en", source: { path: "~/app/.env", name: "ORDERHUB_PASSPHRASE" }, sessions: 1, agents: ["openclaw"],
  how: { "command-output": 1 }, projects: ["~/app"], duringMandu: 0,
  examples: [{ at: "2026-10-27T00:37:00.000Z", agent: "openclaw", how: "command-output", command: CMD, mandu: "without" }],
};

function page(o: { claimed?: boolean; sent?: boolean; files?: Map<string, string>; scan?: LastScanWire | null } = {}) {
  const all = events(o);
  const vm = toSessionViewModel(SESSION, all);
  const believed = believedEvents(all);
  const believedVm = believed.length === all.length ? vm : believed.length ? toSessionViewModel(SESSION, believed) : null;
  return buildAgentPage({
    session: null, id: SESSION, vm, cwd: `${HOME}/app`, waiting: [], events: believed, believedVm, home: HOME, dev: false,
    unchecked: recordUnchecked(all),
    ...(o.files ? { secretFiles: o.files } : {}),
    ...(o.scan !== undefined ? { scan: o.scan } : {}),
  });
}
const FILES = new Map([[BASE, FILE]]);

test("the registry's answer: base symbols to absolute files; a relative or malformed row is left out", () => {
  const files = registeredFiles([
    { path: FILE, symbol: BASE },
    { path: "app/.env", symbol: "$MDU:nomodel_Read[0aaa]" },
    { path: "/x", symbol: "not a symbol" },
  ]);
  assert.deepEqual([...files], [[BASE, FILE]]);
  assert.equal(baseSymbol(TWIN), BASE);
  assert.equal(registeredFileOf(TWIN, files), FILE);
  assert.equal(registeredFileOf("$MDU:nomodel_Read[0bbb].X", files), null);
  assert.equal(registeredFileOf(TWIN, undefined), null);
  assert.equal(registeredFiles(null).size, 0);
});

test("a twin printed by a command is never named by the command; the registry names its file", () => {
  const without = page().secrets.secrets[0]!;
  assert.equal(words(without.what), "ORDERHUB_PASSPHRASE in a file");
  assert.equal(without.file, undefined, "no Rules link to a file named like the command");
  const withFiles = page({ files: FILES }).secrets.secrets[0]!;
  assert.equal(words(withFiles.what), "ORDERHUB_PASSPHRASE in ~/app/.env");
  assert.equal(withFiles.file, "~/app/.env");
});

test("the step that held it says where it is kept", () => {
  const steps = page({ files: FILES }).story.flatMap((t) => t.steps).filter((s) => s.kind === "action" && s.split);
  const real = steps.map((s) => (s.kind === "action" ? words(s.split!.real) : ""));
  assert.deepEqual(real, ["The result held your secret ORDERHUB_PASSPHRASE from ~/app/.env."]);
  const plain = page().story.flatMap((t) => t.steps).filter((s) => s.kind === "action" && s.split);
  assert.equal(plain.map((s) => (s.kind === "action" ? words(s.split!.real) : ""))[0], "The result held your secret ORDERHUB_PASSPHRASE.");
});

test("the card's path: kept in, how it came in (its time opening the step), what the AI got, never left with its real value", () => {
  const card = page({ files: FILES }).secrets.secrets[0]!;
  assert.deepEqual(card.path!.map((n) => [n.side, n.label, words(n.parts), n.tone]), [
    ["computer", "Kept in", "~/app/.env", "plain"],
    ["computer", "How it came in", `Ran ${CMD}, at 2026-10-28T09:11:32.000Z`, "plain"],
    ["ai", "The AI got", "its masked version, in 1 request", "good"],
    ["computer", "Left this computer", "never with its real value", "good"],
  ]);
  const time = card.path![1]!.parts.find((p) => p.kind === "time")!;
  assert.equal(time.step, "tool:c1", "the time opens the step that shows it");
  // No file known: no "Kept in" node, the rest as before.
  assert.deepEqual(page().secrets.secrets[0]!.path!.map((n) => n.label), ["How it came in", "The AI got", "Left this computer"]);
});

test("a send of the real value is off this computer; its stop and the rest stay on it", () => {
  const card = page({ files: FILES, sent: true }).secrets.secrets[0]!;
  assert.deepEqual(card.path!.map((n) => [n.side, n.label, words(n.parts), n.tone]), [
    ["computer", "Kept in", "~/app/.env", "plain"],
    ["computer", "How it came in", `Ran ${CMD}, at 2026-10-28T09:11:32.000Z`, "plain"],
    ["ai", "The AI got", "its masked version, in 1 request", "good"],
    ["off", "Sent with its real value to", SENT_HOST, "plain"],
    ["computer", "Stopped on its way to", STOPPED_HOST, "good"],
  ]);
  // An unchecked record draws the same path: the send is off it there too.
  const r = page({ claimed: true, files: FILES, sent: true }).secrets.recorded![0]!;
  assert.deepEqual(r.path.filter((n) => n.label.startsWith("Sent") || n.label.startsWith("Stopped")).map((n) => [n.side, n.label]), [
    ["off", "Sent with its real value to"],
    ["computer", "Stopped on its way to"],
  ]);
  for (const claimed of [false, true]) {
    const json = JSON.stringify(page({ claimed, files: FILES, sent: true }).secrets);
    assert.equal(json.includes(VALUE), false);
    assert.equal(json.includes("$MDU:"), false);
  }
});

test("an earlier leak: the same file's same key, without Mandu, as one line; anything else says nothing", () => {
  const card = page({ files: FILES, scan: scanOf([LEAK]) }).secrets.secrets[0]!;
  assert.equal(words(card.earlier!), `Without Mandu, OpenClaw gave the AI its real value on 2026-10-27T00:37:00.000Z: ${CMD} printed it. mandu scan found it in 1 session without Mandu; the AI's provider still has it, so change it where it was issued.`);
  assert.deepEqual(card.earlier!.find((p) => p.kind === "time"), { kind: "time", text: "2026-10-27T00:37:00.000Z", clock: true });
  assert.equal(card.scanItem, "f0", "its row on the Scan page, which the line's link opens");
  const none = (f: ScanFindingWire) => page({ files: FILES, scan: scanOf([f]) }).secrets.secrets[0]!.earlier;
  assert.equal(none({ ...LEAK, source: { path: "~/app/.env", name: "ORDERHUB_USER" } }), undefined, "another key");
  assert.equal(none({ ...LEAK, source: { path: "~/other/.env", name: "ORDERHUB_PASSPHRASE" } }), undefined, "another file");
  assert.equal(none({ ...LEAK, sessionsUnderMandu: 1 }), undefined, "every session under Mandu");
  assert.equal(none({ ...LEAK, kind: "shape" }), undefined, "not one of your secrets");
  // Without the registry the file is not known, so nothing is joined.
  assert.equal(page({ scan: scanOf([LEAK]) }).secrets.secrets[0]!.earlier, undefined);
});

test("earlierLeak: the earliest of several, a whole file matching any key, and the words without a command", () => {
  const later = { ...LEAK, examples: [{ ...LEAK.examples![0]!, at: "2026-10-27T05:00:00.000Z" }] };
  const read = { ...LEAK, source: { path: "~/app/.env", name: "ORDERHUB_USER" }, how: { "read-file": 2 }, sessions: 2, examples: [{ at: "2026-10-26T10:00:00.000Z", agent: "claude-code", how: "read-file", mandu: "without" as const }] };
  assert.equal(earlierLeak(FILE, "ORDERHUB_PASSPHRASE", scanOf([later, LEAK]), HOME)!.at, "2026-10-27T00:37:00.000Z");
  const whole = earlierLeak(FILE, null, scanOf([LEAK, read]), HOME)!;
  assert.equal(whole.at, "2026-10-26T10:00:00.000Z");
  assert.equal(whole.item, "f1", "the earliest one's row, numbered as the Scan page numbers your secrets");
  assert.equal(words(earlierParts(whole)), "Without Mandu, Claude Code gave the AI its real value on 2026-10-26T10:00:00.000Z: the agent read the file. mandu scan found it in 2 sessions without Mandu; the AI's provider still has it, so change it where it was issued.");
  assert.equal(earlierLeak(null, "X", scanOf([LEAK]), HOME), null);
  assert.equal(earlierLeak(FILE, "ORDERHUB_PASSPHRASE", null, HOME), null);
});

test("an unchecked record: no card and no count; its secret under `recorded`, with its path and no \"never\" node", () => {
  const { secrets } = page({ claimed: true, files: FILES, scan: scanOf([LEAK]) });
  assert.equal(secrets.unchecked, true);
  assert.deepEqual(secrets.secrets, []);
  assert.deepEqual(secrets.counts, { masked: 0, early: 0 });
  assert.equal(secrets.recorded!.length, 1);
  const r = secrets.recorded![0]!;
  assert.equal(words(r.what), "ORDERHUB_PASSPHRASE in ~/app/.env");
  assert.equal(r.file, "~/app/.env");
  assert.deepEqual(r.path.map((n) => n.label), ["Kept in", "How it came in", "The AI got"]);
  assert.ok(r.earlier, "the earlier leak is the scan's, checked or not");
  assert.equal("ref" in r, false, "no real value to show");
  // A checked record has no `recorded`.
  assert.equal("recorded" in page({ files: FILES }).secrets, false);
});

test("never the value or a token in the page's data", () => {
  for (const claimed of [false, true]) {
    const json = JSON.stringify(page({ claimed, files: FILES, scan: scanOf([LEAK]) }).secrets);
    assert.equal(json.includes(VALUE), false);
    assert.equal(json.includes("$MDU:"), false);
  }
});

test("the developer view's notes: each placed root's file and earlier leak, nothing for an unplaced one", () => {
  const notes = lineageNotes([TWIN, "$MDU:nomodel_exec[0423]"], { files: FILES, scan: scanOf([LEAK]), home: HOME });
  assert.deepEqual(Object.keys(notes), [TWIN]);
  assert.equal(notes[TWIN]!.file, "~/app/.env");
  assert.match(words(notes[TWIN]!.earlier!), /^Without Mandu, OpenClaw gave the AI its real value/);
  assert.deepEqual(lineageNotes([TWIN], { files: FILES, scan: null, home: HOME }), { [TWIN]: { file: "~/app/.env" } });
});
