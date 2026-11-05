/**
 * discarded-writes — the session page's "Changes Mandu did not apply to
 * your files" (dashboard.md §4.25b, view-model/discarded-writes.ts): the
 * secret files the launcher's last believed `session_exit` names in
 * `discardedWrites`, `~/…` under home, control and format characters as
 * `?`, at most DISCARDED_CAP then a count; nothing from a claimed exit, an
 * exit without the field, or a running session; signed out the same.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { ManduEvent } from "../../../src/event-model.js";
import { DISCARDED_CAP, discardedWritesOf } from "../../../src/view-model/discarded-writes.js";
import { buildAgentPage } from "../../../src/view-model/agent-page.js";
import { redactEvents } from "../../../src/view-model/redact.js";

const HOME = "/home/u";

function exit(ts: string, extra: Record<string, unknown> = {}): ManduEvent {
  return {
    id: `ev_exit_${ts}`, sessionId: "s1", turn: 0, ts, seq: 0, callId: null, parentId: null, kind: "session_exit", view: "HumanView",
    boundary: "shell", emitter: "launcher", invariant: { violatedInvariant: false },
    input: { symbolized: "agent exited 0 after 9s", original: null, differs: false, symbols: [] }, output: null,
    code: 0, durationMs: 9000, ...extra,
  } as unknown as ManduEvent;
}

test("no session_exit, or one without the field: nothing", () => {
  assert.equal(discardedWritesOf([], HOME), null);
  assert.equal(discardedWritesOf([exit("2026-10-21T01:00:09.000Z")], HOME), null);
  assert.equal(discardedWritesOf([exit("2026-10-21T01:00:09.000Z", { discardedWrites: [] })], HOME), null);
  assert.equal(discardedWritesOf([exit("2026-10-21T01:00:09.000Z", { discardedWrites: "/home/u/.env" })], HOME), null, "not a list");
});

test("the files, ~/… under home, else absolute; another account's home stays as it is", () => {
  assert.deepEqual(discardedWritesOf([exit("2026-10-21T01:00:09.000Z", { discardedWrites: ["/home/u/app/.env", "/etc/app.conf", "/home/other/.npmrc"] })], HOME),
    { files: ["~/app/.env", "/etc/app.conf", "/home/other/.npmrc"], more: 0 });
  assert.deepEqual(discardedWritesOf([exit("2026-10-21T01:00:09.000Z", { discardedWrites: ["/home/u/app/.env"] })], ""), { files: ["/home/u/app/.env"], more: 0 }, "no home: as recorded");
});

test("two exits: the last one's", () => {
  const events = [
    exit("2026-10-21T01:00:09.000Z", { discardedWrites: ["/home/u/a/.env"] }),
    exit("2026-10-21T02:00:09.000Z", { discardedWrites: ["/home/u/b/.env"] }),
  ];
  assert.deepEqual(discardedWritesOf(events, HOME)?.files, ["~/b/.env"]);
  assert.deepEqual(discardedWritesOf([...events].reverse(), HOME)?.files, ["~/b/.env"], "by time, not by order");
});

test("a claimed exit (sent from the agent's own tree) lists nothing, nor counts as the last one; another emitter's neither", () => {
  assert.equal(discardedWritesOf([exit("2026-10-21T01:00:09.000Z", { claimed: true, discardedWrites: ["/home/u/app/.env"] })], HOME), null);
  const real = exit("2026-10-21T01:00:09.000Z", { discardedWrites: ["/home/u/app/.env"] });
  const forged = exit("2026-10-21T02:00:09.000Z", { claimed: true, discardedWrites: ["/home/u/forged"] });
  assert.deepEqual(discardedWritesOf([real, forged], HOME)?.files, ["~/app/.env"]);
  assert.equal(discardedWritesOf([exit("2026-10-21T01:00:09.000Z", { emitter: "anthropic-proxy", discardedWrites: ["/home/u/app/.env"] })], HOME), null);
});

test("a non-string or empty entry is dropped, the same path twice is one", () => {
  assert.deepEqual(discardedWritesOf([exit("2026-10-21T01:00:09.000Z", { discardedWrites: [42, "", null, { p: 1 }, "/home/u/app/.env", "/home/u/app/.env"] })], HOME),
    { files: ["~/app/.env"], more: 0 });
  assert.equal(discardedWritesOf([exit("2026-10-21T01:00:09.000Z", { discardedWrites: [42, ""] })], HOME), null);
});

test("control and format characters show as ?, so a folder name cannot reorder the line", () => {
  const odd = "/home/u/in\u202Ev\u2028oice\n/\u001b[31m.env\u200B";
  const got = discardedWritesOf([exit("2026-10-21T01:00:09.000Z", { discardedWrites: [odd] })], HOME)!;
  assert.deepEqual(got.files, ["~/in?v?oice?/?[31m.env?"]);
  assert.doesNotMatch(got.files[0]!, /[\u0000-\u001f\u007f-\u009f\u2028\u2029\p{Cf}]/u);
});

test("25 files: the first 20, then a count of 5", () => {
  const paths = Array.from({ length: 25 }, (_, i) => `/home/u/p${i}/.env`);
  const got = discardedWritesOf([exit("2026-10-21T01:00:09.000Z", { discardedWrites: paths })], HOME)!;
  assert.equal(DISCARDED_CAP, 20);
  assert.equal(got.files.length, 20);
  assert.equal(got.files[19], "~/p19/.env");
  assert.equal(got.more, 5);
});

test("on the agent page: the field once the session ended, signed out the same; none while it runs", () => {
  const events = [exit("2026-10-21T01:00:09.000Z", { discardedWrites: ["/home/u/app/.env"] })];
  const page = buildAgentPage({ session: null, id: "s1", vm: null, cwd: null, waiting: [], events, home: HOME });
  assert.deepEqual(page.discardedWrites, { files: ["~/app/.env"], more: 0 });
  const out = buildAgentPage({ session: null, id: "s1", vm: null, cwd: null, waiting: [], events: redactEvents(events), valuesShown: false, home: HOME });
  assert.deepEqual(out.discardedWrites, page.discardedWrites, "signed out: the paths stay (they are no value)");
  assert.equal(buildAgentPage({ session: null, id: "s1", vm: null, cwd: null, waiting: [] }).discardedWrites, null);
  // A session that went on after its exit (resumed in the same log) runs.
  const session = { id: "s1", status: "running", firstTs: "2026-10-21T01:00:00.000Z", lastTs: "2026-10-21T01:05:00.000Z" };
  const resumed = [...events, { ...exit("2026-10-21T01:05:00.000Z"), id: "ev_call", kind: "tllm_call", emitter: "anthropic-proxy" } as unknown as ManduEvent];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const running = buildAgentPage({ session: session as any, id: "s1", vm: null, cwd: null, waiting: [], events: resumed, home: HOME });
  assert.equal(running.running, true);
  assert.equal(running.discardedWrites, null, "a running session shows no block");
});
