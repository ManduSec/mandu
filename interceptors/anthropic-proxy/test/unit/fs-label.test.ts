/**
 * fs-label.test.ts — the DERIVED ON-DISK LABEL hook (Plan 9, confidentiality.md
 * §4/§8): a HIGH session's write is labeled at the watermark BEFORE the bytes
 * land, so the NEXT session classifies the derived file at that level instead of
 * `public`.
 *
 * The three things worth pinning here are the three ways this could be shipped
 * broken:
 *   · it must run with NO VIEW MAP (the default posture) — a hook hidden behind
 *     the view map would be DEAD where everyone runs;
 *   · a PUBLIC session must be byte-identical to today (no rewrite, no noise);
 *   · an UNREACHABLE arbiter must DENY the write — "we could not check" may never
 *     resolve to "write it unlabeled", which is the laundering hole with extra
 *     steps.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { labelWrittenPaths, UNLABELABLE_SENTINEL_ROOT } from "../../src/fs-label.js";
import { DENIED_NAMESPACE } from "../../src/fs-gate.js";
import { ViewMap } from "../../src/view-map.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const HUMAN = "/home/u/project/webapp";
const AGENT = "/home/u/.mandu/workspaces/wid/agentview";
const SESSION = "sess-A";

/** An arbiter whose session is HIGH: every write is labeled at the watermark. */
function highArbiter(level = "any-model"): MockArbiter {
  return new MockArbiter({
    labelWrittenPathFn: (req) => ({
      labeled: true,
      refused: false,
      level,
      bindings: [],
      reason: `mock: on-disk label recorded at the watermark for ${req.path}`,
    }),
  });
}

test("HIGH session: a Write is labeled on disk — with NO view map (the default posture)", async () => {
  const arbiter = highArbiter();
  const r = await labelWrittenPaths(
    "Write",
    { file_path: "/home/u/notes/summary.md", content: "the buyer pays 4.2M on close" },
    { arbiter, sessionKey: SESSION },
  );
  assert.ok(r);
  assert.equal(r!.writes.length, 1);
  assert.equal(r!.writes[0]!.labeled, true);
  assert.equal(r!.writes[0]!.level, "any-model");
  assert.equal(r!.writes[0]!.path, "/home/u/notes/summary.md");
  // The path itself is untouched: this hook LABELS, it does not gate.
  assert.equal(r!.input["file_path"], "/home/u/notes/summary.md");
  // …and the arbiter was told which session and which tool (§8's provenance).
  assert.equal(arbiter.labelWrittenPathCalls.length, 1);
  assert.equal(arbiter.labelWrittenPathCalls[0]!.sessionKey, SESSION);
  assert.equal(arbiter.labelWrittenPathCalls[0]!.tool, "Write");
});

test("PUBLIC session: nothing is labeled, nothing is rewritten (the no-regression fold)", async () => {
  const arbiter = new MockArbiter(); // default: session is not high
  const input = { file_path: "/home/u/notes/ordinary.md", content: "hello" };
  const r = await labelWrittenPaths("Write", input, { arbiter, sessionKey: SESSION });
  assert.ok(r);
  assert.equal(r!.writes.length, 0);
  assert.equal(r!.input, input); // the SAME object — no copy, no change
});

test("FAIL-CLOSED: an unreachable arbiter DENIES the write (it cannot be labeled)", async () => {
  const arbiter = new MockArbiter({ failLabelWrittenPath: true });
  const r = await labelWrittenPaths(
    "Write",
    { file_path: "/home/u/notes/summary.md", content: "…" },
    { arbiter, sessionKey: SESSION },
  );
  assert.ok(r);
  assert.equal(r!.writes.length, 1);
  assert.equal(r!.writes[0]!.labeled, false);
  assert.equal(
    r!.input["file_path"],
    `${UNLABELABLE_SENTINEL_ROOT}/home/u/notes/summary.md`,
    "an unlabelable write must be denied, not written unlabeled",
  );
  assert.match(r!.writes[0]!.reason, /fail closed/);
  assert.equal(r!.writes[0]!.sentinel, `${UNLABELABLE_SENTINEL_ROOT}/home/u/notes/summary.md`);
  // The sentinel must be unwriteable BY THE FILESYSTEM, not by the agent's lack of
  // privilege: /dev/null is a character device, so nothing can ever be created
  // below it — ENOTDIR for root and non-root alike. (The fs gate's
  // `/mandu/denied/…` is a deny only because the agent cannot write to `/`; an
  // agent running as root would create it, and these bytes are secret-derived.)
  assert.match(r!.input["file_path"] as string, /^\/dev\/null\//);
});

test("a wedged arbiter (no answer) is treated as unreachable — it can DENY, never stall", async () => {
  const arbiter = new MockArbiter({
    labelWrittenPathFn: () => { throw new Error("unused"); },
  });
  // Replace with a hang: the hook's own timeout is the fail-closed valve.
  (arbiter as unknown as { labelWrittenPath: () => Promise<never> }).labelWrittenPath =
    () => new Promise<never>(() => { /* never settles */ });

  const r = await labelWrittenPaths(
    "Write",
    { file_path: "/home/u/notes/summary.md", content: "…" },
    { arbiter, sessionKey: SESSION, timeoutMs: 20 },
  );
  assert.ok(r);
  assert.equal(r!.input["file_path"], `${UNLABELABLE_SENTINEL_ROOT}/home/u/notes/summary.md`);
  assert.match(r!.writes[0]!.reason, /timed out/);
});

test("READ-mode tools are not labeled — a read derives nothing", async () => {
  const arbiter = highArbiter();
  assert.equal(await labelWrittenPaths("Read", { file_path: "/home/u/x.md" }, { arbiter, sessionKey: SESSION }), null);
  assert.equal(await labelWrittenPaths("Grep", { path: "/home/u" }, { arbiter, sessionKey: SESSION }), null);
  assert.equal(arbiter.labelWrittenPathCalls.length, 0);
});

test("Bash is not labeled here — a redirect is the exec chokepoint's turf", async () => {
  const arbiter = highArbiter();
  const r = await labelWrittenPaths(
    "Bash", { command: "echo secret > /home/u/out.txt" }, { arbiter, sessionKey: SESSION },
  );
  assert.equal(r, null);
  assert.equal(arbiter.labelWrittenPathCalls.length, 0);
});

test("Edit and NotebookEdit are labeled too — every mediated write path", async () => {
  const arbiter = highArbiter();
  const e = await labelWrittenPaths(
    "Edit",
    { file_path: "/home/u/notes/summary.md", old_string: "a", new_string: "b" },
    { arbiter, sessionKey: SESSION },
  );
  assert.equal(e!.writes.length, 1);
  const n = await labelWrittenPaths(
    "NotebookEdit",
    { notebook_path: "/home/u/analysis.ipynb", new_source: "x" },
    { arbiter, sessionKey: SESSION },
  );
  assert.equal(n!.writes.length, 1);
  assert.deepEqual(
    arbiter.labelWrittenPathCalls.map((c) => c.path),
    ["/home/u/notes/summary.md", "/home/u/analysis.ipynb"],
  );
});

test("a path the fs GATE already denied is not labeled (nothing will be written there)", async () => {
  const arbiter = highArbiter();
  const r = await labelWrittenPaths(
    "Write",
    { file_path: `${DENIED_NAMESPACE}/policy/home/u/.ssh/id_rsa`, content: "…" },
    { arbiter, sessionKey: SESSION },
  );
  assert.ok(r);
  assert.equal(r!.writes.length, 0);
  assert.equal(arbiter.labelWrittenPathCalls.length, 0);
});

test("REFUSED: a HIGH session writing a path the arbiter cannot key is DENIED, not skipped", async () => {
  // A relative path has no stable identity, so it cannot be labeled — and a write
  // we cannot label, from a session that has read a secret, is the hole. The old
  // shape of this bug is a `continue` that looks like the fs gate's "CWD scoping's
  // job" skip: same code, opposite meaning.
  const arbiter = new MockArbiter({
    labelWrittenPathFn: () => ({
      labeled: false, refused: true, level: "public", bindings: [],
      reason: "REFUSED: the session is HIGH and this path has no stable identity",
    }),
  });
  const r = await labelWrittenPaths(
    "Write", { file_path: "notes/summary.md", content: "…" }, { arbiter, sessionKey: SESSION },
  );
  assert.ok(r);
  assert.equal(r!.writes.length, 1);
  assert.equal(r!.writes[0]!.labeled, false);
  assert.equal(r!.input["file_path"], `${UNLABELABLE_SENTINEL_ROOT}/notes/summary.md`);
  // …and it DID reach the arbiter: the proxy does not decide unilaterally that a
  // path is unlabelable — only the arbiter knows whether the session is high.
  assert.equal(arbiter.labelWrittenPathCalls.length, 1);
});

test("a `~/…` write is labeled, not silently dropped (the arbiter expands it)", async () => {
  // With no view map the raw string reaches the arbiter, which normalizes `~`. A
  // proxy-side `startsWith("/")` pre-filter used to drop these on the floor: no
  // label, no deny, no event — in exactly the posture this hook was built for.
  const arbiter = highArbiter();
  const r = await labelWrittenPaths(
    "Write", { file_path: "~/notes/summary.md", content: "…" }, { arbiter, sessionKey: SESSION },
  );
  assert.ok(r);
  assert.equal(r!.writes.length, 1);
  assert.equal(r!.writes[0]!.labeled, true);
  assert.equal(arbiter.labelWrittenPathCalls[0]!.path, "~/notes/summary.md");
});

test("no session key ⇒ no watermark to attribute ⇒ the hook is inert", async () => {
  const arbiter = highArbiter();
  const r = await labelWrittenPaths("Write", { file_path: "/home/u/x.md", content: "…" }, { arbiter });
  assert.equal(r, null);
  assert.equal(arbiter.labelWrittenPathCalls.length, 0);
});

test("with a view map, the label is keyed on the HUMANVIEW path — the arbiter's world", async () => {
  const arbiter = highArbiter();
  const viewMap = new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix", home: "/home/u" });
  await labelWrittenPaths(
    "Write", { file_path: `${HUMAN}/src/out.ts`, content: "…" },
    { arbiter, sessionKey: SESSION, viewMap },
  );
  assert.equal(arbiter.labelWrittenPathCalls[0]!.path, `${HUMAN}/src/out.ts`);
});

test("an arbiter predating Plan 9 no-ops (the label cannot exist — we did not fail to write it)", async () => {
  const arbiter = new MockArbiter();
  delete (arbiter as unknown as { labelWrittenPath?: unknown }).labelWrittenPath;
  // The method lives on the prototype, so also mask it there for this instance.
  Object.defineProperty(arbiter, "labelWrittenPath", { value: undefined, configurable: true });
  const input = { file_path: "/home/u/notes/summary.md", content: "…" };
  const r = await labelWrittenPaths("Write", input, { arbiter, sessionKey: SESSION });
  assert.equal(r, null);
  assert.equal(input.file_path, "/home/u/notes/summary.md"); // NOT denied
});

test("a relative write joins the agent's launch directory when the agent resolves against it (the label names the file the bytes land in); otherwise it goes as written", async () => {
  const tools = { write: { fields: ["filePath"], mode: "write" as const } };
  const known = highArbiter();
  await labelWrittenPaths("write", { filePath: "../notes/out.md", content: "…" }, { arbiter: known, sessionKey: SESSION, pathTools: tools, relativeBase: `${HUMAN}/src` });
  assert.equal(known.labelWrittenPathCalls[0]!.path, `${HUMAN}/notes/out.md`);
  const unknown = highArbiter();
  await labelWrittenPaths("write", { filePath: "../notes/out.md", content: "…" }, { arbiter: unknown, sessionKey: SESSION, pathTools: tools });
  assert.equal(unknown.labelWrittenPathCalls[0]!.path, "../notes/out.md", "unchanged without a base (the arbiter refuses a relative path in a high session)");
  const tilde = highArbiter();
  await labelWrittenPaths("write", { filePath: "~/x.md" }, { arbiter: tilde, sessionKey: SESSION, pathTools: tools, relativeBase: "/elsewhere" });
  assert.equal(tilde.labelWrittenPathCalls[0]!.path, "~/x.md", "`~` is not relative (the arbiter expands it)");
});
