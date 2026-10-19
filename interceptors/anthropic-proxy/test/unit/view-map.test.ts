/**
 * view-map.test.ts — unit tests for the bidirectional HumanView↔AgentView
 * prefix map (fs-sync.md §1.3; P2 test matrix: normalization,
 * idempotency, Windows dialect, field-level registry rules).
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ViewMap, parseViewMapEnv, reverseMapRequestPaths, CLAUDE_CODE_PATH_FIELDS } from "../../src/view-map.js";
import type { MessagesRequest } from "../../src/messages-types.js";

const HUMAN = "/home/u/project/webapp";
const AGENT = "/home/u/.mandu/workspaces/wid/agentview";

function makeMap(): ViewMap {
  return new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix", home: "/home/u" });
}

// ── mapPath: forward / reverse / idempotency (rule 1) ─────────────────────────

test("forward maps a HumanView absolute path into the AgentView root", () => {
  const m = makeMap();
  assert.equal(m.mapPath(`${HUMAN}/vendor/notes.txt`, "forward"), `${AGENT}/vendor/notes.txt`);
  assert.equal(m.mapPath(HUMAN, "forward"), AGENT); // the root itself
});

test("reverse maps an AgentView absolute path back to the HumanView root", () => {
  const m = makeMap();
  assert.equal(m.mapPath(`${AGENT}/src/a.ts`, "reverse"), `${HUMAN}/src/a.ts`);
  assert.equal(m.mapPath(AGENT, "reverse"), HUMAN);
});

test("forward is IDEMPOTENT: an AgentView-prefixed input passes through unchanged", () => {
  const m = makeMap();
  const p = `${AGENT}/vendor/notes.txt`;
  assert.equal(m.mapPath(p, "forward"), p);
  // Round trip: forward(reverse(p)) returns to the agent view.
  assert.equal(m.mapPath(m.mapPath(p, "reverse"), "forward"), p);
});

test("a path under NEITHER root passes through unchanged, original spelling kept", () => {
  const m = makeMap();
  assert.equal(m.mapPath("/etc/passwd", "forward"), "/etc/passwd");
  // Unmatched paths keep their original (un-normalized) spelling.
  assert.equal(m.mapPath("/etc//passwd", "forward"), "/etc//passwd");
});

test("relative paths are never touched (CWD scoping owns them)", () => {
  const m = makeMap();
  assert.equal(m.mapPath("vendor/notes.txt", "forward"), "vendor/notes.txt");
  assert.equal(m.mapPath("./a/../b", "reverse"), "./a/../b");
});

test("segment-aware prefix match: /…/webapp does not match /…/webapp2", () => {
  const m = makeMap();
  assert.equal(m.mapPath(`${HUMAN}2/file`, "forward"), `${HUMAN}2/file`);
});

// ── normalization before matching (rule 4) ────────────────────────────────────

test("normalization: ~, .., doubled separators resolve before matching", () => {
  const m = makeMap();
  assert.equal(m.mapPath("~/project/webapp/notes.md", "forward"), `${AGENT}/notes.md`);
  assert.equal(m.mapPath(`${HUMAN}/a/../vendor//notes.txt`, "forward"), `${AGENT}/vendor/notes.txt`);
  assert.equal(m.mapPath("/home/u/project/other/../webapp/x", "forward"), `${AGENT}/x`);
  // A `..` escape OUT of the root does not match.
  assert.equal(m.mapPath(`${HUMAN}/../elsewhere/f`, "forward"), `${HUMAN}/../elsewhere/f`);
});

test("trailing separators are tolerated on roots and inputs", () => {
  const m = new ViewMap([{ human: `${HUMAN}/`, agent: `${AGENT}//` }], {
    dialect: "posix",
    home: "/home/u",
  });
  assert.equal(m.mapPath(`${HUMAN}/f`, "forward"), `${AGENT}/f`);
});

// ── Windows dialect (rule 4) ──────────────────────────────────────────────────

test("win32 dialect: drive letters, backslashes, case-insensitive matching", () => {
  const m = new ViewMap(
    [{ human: "C:\\Users\\u\\ws", agent: "C:\\view-state\\agentview" }],
    { dialect: "win32", home: "C:\\Users\\u" },
  );
  assert.equal(m.mapPath("C:\\Users\\u\\ws\\a.txt", "forward"), "C:\\view-state\\agentview\\a.txt");
  // Case-insensitive prefix match.
  assert.equal(m.mapPath("c:\\users\\U\\WS\\a.txt", "forward"), "C:\\view-state\\agentview\\a.txt");
  // Forward slashes on the wire normalize into the local dialect.
  assert.equal(m.mapPath("C:/Users/u/ws/b/c.txt", "forward"), "C:\\view-state\\agentview\\b\\c.txt");
  // Idempotent.
  assert.equal(
    m.mapPath("C:\\view-state\\agentview\\a.txt", "forward"),
    "C:\\view-state\\agentview\\a.txt",
  );
});

test("win32 dialect: UNC roots map like any other root", () => {
  const m = new ViewMap(
    [{ human: "\\\\srv\\share\\ws", agent: "C:\\dv\\agentview" }],
    { dialect: "win32", home: "C:\\Users\\u" },
  );
  assert.equal(m.mapPath("\\\\srv\\share\\ws\\f.txt", "forward"), "C:\\dv\\agentview\\f.txt");
  assert.equal(m.mapPath("\\\\srv\\share\\other\\f.txt", "forward"), "\\\\srv\\share\\other\\f.txt");
});

// ── degenerate maps are refused ───────────────────────────────────────────────

test("degenerate pairs (identical, filesystem root, nested) deactivate, not rewrite", () => {
  const home = "/home/u";
  assert.equal(new ViewMap([{ human: "/w", agent: "/w" }], { dialect: "posix", home }).active, false);
  assert.equal(new ViewMap([{ human: "/", agent: "/a" }], { dialect: "posix", home }).active, false);
  assert.equal(
    new ViewMap([{ human: "/w", agent: "/w/agentview" }], { dialect: "posix", home }).active,
    false,
  );
  assert.equal(new ViewMap([], { dialect: "posix", home }).active, false);
  assert.equal(makeMap().active, true);
});

// ── mapText (Bash.command forward; tool_result content reverse) ───────────────

test("mapText substitutes every root-prefixed path in free text, segment-aware", () => {
  const m = makeMap();
  const cmd = `cat ${HUMAN}/a.txt ${HUMAN}/b/c.txt ${HUMAN}2/nope`;
  assert.equal(
    m.mapText(cmd, "forward"),
    `cat ${AGENT}/a.txt ${AGENT}/b/c.txt ${HUMAN}2/nope`,
  );
});

test("mapText reverse: an error message naming the worktree maps back to HumanView", () => {
  const m = makeMap();
  const err = `ENOENT: no such file or directory, open '${AGENT}/vendor/notes.txt'`;
  assert.equal(
    m.mapText(err, "reverse"),
    `ENOENT: no such file or directory, open '${HUMAN}/vendor/notes.txt'`,
  );
});

test("mapText forward catches the ~-spelled root and is idempotent", () => {
  const m = makeMap();
  assert.equal(m.mapText("ls ~/project/webapp/src", "forward"), `ls ${AGENT}/src`);
  const once = m.mapText(`cat ${HUMAN}/a`, "forward");
  assert.equal(m.mapText(once, "forward"), once);
});

test("mapText forward does NOT rewrite the root as an INFIX of a longer path", () => {
  const m = makeMap();
  // The workspace root spelled inside another absolute path (a backup tree)
  // must be left untouched — it is not a fresh path start.
  assert.equal(
    m.mapText(`cp -r /backup${HUMAN} /tmp/restore`, "forward"),
    `cp -r /backup${HUMAN} /tmp/restore`,
  );
  // Root glued to a preceding token (relative `./` prefix) is also an infix.
  assert.equal(m.mapText(`cat .${HUMAN}/a`, "forward"), `cat .${HUMAN}/a`);
});

test("mapText forward does NOT rewrite a ~-root after a host: (scp/rsync remote)", () => {
  const m = makeMap();
  // `~/project/webapp` here is a REMOTE home path — rewriting it to a local
  // AgentView absolute path would corrupt the command.
  assert.equal(
    m.mapText("scp host:~/project/webapp/file .", "forward"),
    "scp host:~/project/webapp/file .",
  );
  // But a genuine local ~-path (space-bounded) still maps.
  assert.equal(m.mapText("cat ~/project/webapp/a", "forward"), `cat ${AGENT}/a`);
});

test("mapText reverse does NOT rewrite the AgentView root as an infix", () => {
  const m = makeMap();
  assert.equal(
    m.mapText(`saved a copy under /mnt${AGENT}/x`, "reverse"),
    `saved a copy under /mnt${AGENT}/x`,
  );
});

test("mapText reverse: sentence punctuation after the bare root is a boundary (CLI CWD-note leak)", () => {
  const m = makeMap();
  // The live leak shape: Claude Code's tool_use_error prose names its CWD (the
  // AgentView root) at a sentence end. The period must not read as a token char.
  assert.equal(
    m.mapText(`Note: your current working directory is ${AGENT}.`, "reverse"),
    `Note: your current working directory is ${HUMAN}.`,
  );
  assert.equal(
    m.mapText(`retry from ${AGENT}. Then stop`, "reverse"),
    `retry from ${HUMAN}. Then stop`,
  );
  assert.equal(m.mapText(`searching ${AGENT}...`, "reverse"), `searching ${HUMAN}...`);
  // A period that CONTINUES a longer name is still no boundary: a sibling dir…
  assert.equal(m.mapText(`see ${AGENT}.bak/f`, "reverse"), `see ${AGENT}.bak/f`);
  // …and a dot-run opening a separator is a different directory, not punctuation.
  assert.equal(m.mapText(`see ${AGENT}./sub`, "reverse"), `see ${AGENT}./sub`);
});

test("mapText forward keeps the strict token rule: a trailing period can spell a real file", () => {
  const m = makeMap();
  // In a shell command `${HUMAN}.` names a file literally called `webapp.` —
  // rewriting it would run the command against the wrong file, so the
  // punctuation boundary is reverse-only.
  assert.equal(m.mapText(`cat ${HUMAN}.`, "forward"), `cat ${HUMAN}.`);
});

// ── registry-driven tool_use input rewrite (rules 2 + 3) ──────────────────────

test("path-typed fields of registry tools are rewritten; the input object is fresh", () => {
  const m = makeMap();
  const input = { file_path: `${HUMAN}/notes.md`, limit: 5 };
  const r = m.rewriteToolUseInput("Read", input, "forward");
  assert.ok(r && r.changed);
  assert.equal(r.input["file_path"], `${AGENT}/notes.md`);
  assert.equal(r.input["limit"], 5);
  assert.equal(input.file_path, `${HUMAN}/notes.md`); // caller's object untouched
});

test("content-typed fields are NEVER rewritten (use-vs-mention, gap class 4)", () => {
  const m = makeMap();
  const mention = `see ${HUMAN}/README.md for details`;
  const r = m.rewriteToolUseInput(
    "Write",
    { file_path: `${HUMAN}/doc.md`, content: mention },
    "forward",
  );
  assert.ok(r && r.changed);
  assert.equal(r.input["file_path"], `${AGENT}/doc.md`);
  assert.equal(r.input["content"], mention); // the path IN the content is a mention
  const e = m.rewriteToolUseInput(
    "Edit",
    { file_path: `${HUMAN}/a.ts`, old_string: `${HUMAN}/x`, new_string: `${HUMAN}/y` },
    "forward",
  );
  assert.ok(e && e.changed);
  assert.equal(e.input["old_string"], `${HUMAN}/x`);
  assert.equal(e.input["new_string"], `${HUMAN}/y`);
});

test("Bash.command gets textual prefix substitution", () => {
  const m = makeMap();
  const r = m.rewriteToolUseInput("Bash", { command: `grep -r x ${HUMAN}/src` }, "forward");
  assert.ok(r && r.changed);
  assert.equal(r.input["command"], `grep -r x ${AGENT}/src`);
});

test("unknown tool ⇒ null (no rewrite — fall back to CWD + backstop)", () => {
  const m = makeMap();
  assert.equal(m.rewriteToolUseInput("mcp__foo__bar", { path: `${HUMAN}/f` }, "forward"), null);
  assert.equal(m.rewriteToolUseInput("WebFetch", { url: "https://x" }, "forward"), null);
});

test("malformed input ⇒ null (conservative pass-through)", () => {
  const m = makeMap();
  assert.equal(m.rewriteToolUseInput("Read", "not-an-object", "forward"), null);
  assert.equal(m.rewriteToolUseInput("Read", null, "forward"), null);
  assert.equal(m.rewriteToolUseInput("Read", [1, 2], "forward"), null);
});

test("registry covers the same tools originFor maps (keep the two in sync)", () => {
  // Guard: every path-registry tool has at least one field, and the canonical
  // Claude Code file tools are present.
  for (const t of ["Read", "Write", "Edit", "NotebookEdit", "Glob", "Grep"]) {
    assert.ok((CLAUDE_CODE_PATH_FIELDS[t] ?? []).length > 0, `${t} missing from registry`);
  }
});

// ── parseViewMapEnv ───────────────────────────────────────────────────────────

test("parseViewMapEnv: unset/empty → [], valid JSON parses, junk THROWS (loud)", () => {
  assert.deepEqual(parseViewMapEnv(undefined), []);
  assert.deepEqual(parseViewMapEnv("  "), []);
  assert.deepEqual(parseViewMapEnv(`[{"human":"/h","agent":"/a"}]`), [
    { human: "/h", agent: "/a" },
  ]);
  assert.throws(() => parseViewMapEnv("not json"), /not valid JSON/);
  assert.throws(() => parseViewMapEnv(`{"human":"/h"}`), /must be a JSON array/);
  assert.throws(() => parseViewMapEnv(`[{"human":"/h"}]`), /must be \{human: string, agent: string\}/);
  assert.throws(() => parseViewMapEnv(`[{"human":"","agent":"/a"}]`), /must be \{human/);
});

// ── reverseMapRequestPaths: conversation free text (the E28 @-mention leak) ──

test("reverse request walk: @-mention pre-read reminder in USER text maps to HumanView (E28 leak shape)", () => {
  const m = makeMap();
  // Claude Code parses an @-mention in the typed prompt and pre-reads the file
  // CLIENT-side against its CWD — the AgentView worktree — then records the
  // call as a <system-reminder> USER text block spelling the twin path. Caught
  // live 2026-07-14 (net-exfil-blocked, no-agentview-path-in-model).
  const req = {
    model: "m",
    messages: [
      {
        role: "user",
        content: [
          {
            type: "text",
            text: `<system-reminder>\nCalled the Read tool with the following input: {"file_path":"${AGENT}/notes.md"}\n</system-reminder>`,
          },
          { type: "text", text: "Back up the notes file now." },
        ],
      },
    ],
  } as unknown as MessagesRequest;
  const changes = reverseMapRequestPaths(req, m);
  const text0 = (req.messages[0]!.content as Array<{ text: string }>)[0]!.text;
  assert.ok(!text0.includes(AGENT), "AgentView spelling must not survive in user text");
  assert.ok(text0.includes(`${HUMAN}/notes.md`), "HumanView spelling substituted");
  assert.deepEqual(changes, [
    { block: "text", callId: null, tool: null, field: "text", agent: AGENT, human: HUMAN },
  ]);
});

test("reverse request walk: STRING-body message and assistant text echo both map; report is per root pair", () => {
  const m = makeMap();
  const req = {
    model: "m",
    messages: [
      { role: "user", content: `the file lives at ${AGENT}/a.md` },
      { role: "assistant", content: [{ type: "text", text: `I read ${AGENT}/a.md and ${AGENT}/b.md.` }] },
    ],
  } as unknown as MessagesRequest;
  const changes = reverseMapRequestPaths(req, m);
  assert.equal(req.messages[0]!.content, `the file lives at ${HUMAN}/a.md`);
  const echoed = (req.messages[1]!.content as Array<{ text: string }>)[0]!.text;
  assert.equal(echoed, `I read ${HUMAN}/a.md and ${HUMAN}/b.md.`);
  // One record per root pair per span — the two hits in the assistant block dedup.
  assert.equal(changes.length, 2);
  assert.ok(changes.every((c) => c.block === "text" && c.agent === AGENT && c.human === HUMAN));
});

test("reverse request walk: thinking blocks and clean text are untouched (no spurious records)", () => {
  const m = makeMap();
  const thinking = { type: "thinking", thinking: `notes live under ${AGENT}/x`, signature: "sig" };
  const req = {
    model: "m",
    messages: [
      { role: "assistant", content: [thinking, { type: "text", text: "done — no paths here." }] },
      { role: "user", content: [{ type: "text", text: "thanks" }] },
    ],
  } as unknown as MessagesRequest;
  const changes = reverseMapRequestPaths(req, m);
  // Mutating a thinking block would invalidate its signature — it must ride verbatim.
  assert.equal((req.messages[0]!.content as Array<{ thinking?: string }>)[0]!.thinking, `notes live under ${AGENT}/x`);
  assert.deepEqual(changes, []);
});

// ── the OpenClaw gate-surface residue: array fields, workdir, patch headers ──

const OPENCLAW_FIELDS = {
  paths: {
    exec: { fields: ["workdir"] },
    browser: { fields: ["path", "paths"] },
  },
  exec: { exec: "command" },
  patch: { apply_patch: { field: "input" } },
};

test("an array path field maps each string element; exec.workdir maps with its command text", () => {
  const m = makeMap();
  const up = m.rewriteToolUseInput("browser", { action: "upload", paths: [`${HUMAN}/a.png`, "rel.png", 4] }, "forward", OPENCLAW_FIELDS);
  assert.deepEqual(up?.input["paths"], [`${AGENT}/a.png`, "rel.png", 4]);
  const back = m.rewriteToolUseInput("browser", up!.input, "reverse", OPENCLAW_FIELDS);
  assert.deepEqual(back?.input["paths"], [`${HUMAN}/a.png`, "rel.png", 4]);
  const ex = m.rewriteToolUseInput("exec", { command: `ls ${HUMAN}/src`, workdir: `${HUMAN}/src` }, "forward", OPENCLAW_FIELDS);
  assert.deepEqual(ex?.input, { command: `ls ${AGENT}/src`, workdir: `${AGENT}/src` });
});

test("apply_patch: only the header paths move between the views; content lines naming the same paths are untouched", () => {
  const m = makeMap();
  const patch = [
    "*** Begin Patch",
    `*** Update File: ${HUMAN}/src/a.ts`,
    `*** Move to: ${HUMAN}/src/b.ts`,
    "@@",
    `-// see ${HUMAN}/src/a.ts`,
    `+// see ${HUMAN}/src/b.ts`,
    "*** Add File: notes/rel.md",
    "+x",
    "*** End Patch",
  ].join("\n");
  const fwd = m.rewriteToolUseInput("apply_patch", { input: patch }, "forward", OPENCLAW_FIELDS);
  assert.ok(fwd?.changed);
  const text = String(fwd!.input["input"]);
  assert.ok(text.includes(`*** Update File: ${AGENT}/src/a.ts`));
  assert.ok(text.includes(`*** Move to: ${AGENT}/src/b.ts`));
  assert.ok(text.includes(`-// see ${HUMAN}/src/a.ts`) && text.includes(`+// see ${HUMAN}/src/b.ts`), "content is content");
  assert.ok(text.includes("*** Add File: notes/rel.md"), "a relative header is CWD scoping's");
  const rev = m.rewriteToolUseInput("apply_patch", fwd!.input, "reverse", OPENCLAW_FIELDS);
  assert.equal(rev?.input["input"], patch, "reverse restores the HumanView spelling byte for byte");
  // a patch that does not parse passes through unchanged (the gate refused it already)
  const bad = m.rewriteToolUseInput("apply_patch", { input: `*** Update File: ${HUMAN}/x` }, "forward", OPENCLAW_FIELDS);
  assert.equal(bad?.changed, false);
  // without the patch table apply_patch is an unknown tool
  assert.equal(m.rewriteToolUseInput("apply_patch", { input: patch }, "forward", { paths: {}, exec: {} }), null);
});
