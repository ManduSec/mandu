/**
 * view-map.test.ts — unit tests for the Codex HumanView↔AgentView prefix map
 * (fs-sync.md §1.3, P4). The core path-math is copied from the proven
 * anthropic-proxy module (provenance in view-map.ts); these tests focus on the
 * CODEX-SPECIFIC surface: command-string mapping in function_call arguments
 * (both `cmd` string and `command` argv array) and the reverse request walker.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ViewMap, reverseMapRequestPaths, parseViewMapEnv } from "../../src/view-map.js";
import type { ResponsesRequest } from "../../src/responses-types.js";

const HUMAN = "/home/u/project/webapp";
const AGENT = "/home/u/.mandu/workspaces/wid/agentview";

function makeMap(): ViewMap {
  return new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix", home: "/home/u" });
}

test("mapText forward/reverse over a shell command, segment-aware", () => {
  const m = makeMap();
  assert.equal(m.mapText(`cat ${HUMAN}/notes.md`, "forward"), `cat ${AGENT}/notes.md`);
  assert.equal(m.mapText(`open ${AGENT}/a`, "reverse"), `open ${HUMAN}/a`);
  assert.equal(m.mapText(`cat ${HUMAN}2/x`, "forward"), `cat ${HUMAN}2/x`); // not a prefix
  assert.equal(m.mapText("ls ~/project/webapp/src", "forward"), `ls ${AGENT}/src`);
});

test("mapText leaves the root untouched as an INFIX or a host:~ remote", () => {
  const m = makeMap();
  // Infix inside a longer absolute path (backup tree) — not a fresh path.
  assert.equal(
    m.mapText(`cp -r /backup${HUMAN} /tmp/restore`, "forward"),
    `cp -r /backup${HUMAN} /tmp/restore`,
  );
  // `~/…` after `host:` is a remote path (scp/rsync) — must not become local.
  assert.equal(
    m.mapText("scp host:~/project/webapp/f .", "forward"),
    "scp host:~/project/webapp/f .",
  );
  // …but the genuine local forms still map.
  assert.equal(m.mapText("cat ~/project/webapp/a", "forward"), `cat ${AGENT}/a`);
  assert.equal(m.mapText(`saved /mnt${AGENT}/x`, "reverse"), `saved /mnt${AGENT}/x`);
});

test("mapText reverse: sentence punctuation after the bare root is a boundary (CLI CWD-note leak)", () => {
  const m = makeMap();
  // The live leak shape: a failed command's output names the CWD (the AgentView
  // root) at a sentence end. The period must not read as a token char.
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

test("rewriteFunctionCallArguments maps the `cmd` string; leaves other keys alone", () => {
  const m = makeMap();
  const args = JSON.stringify({ cmd: `grep x ${HUMAN}/src`, timeout: 5 });
  const out = m.rewriteFunctionCallArguments(args, "forward");
  assert.ok(out);
  assert.deepEqual(JSON.parse(out!), { cmd: `grep x ${AGENT}/src`, timeout: 5 });
});

test("rewriteFunctionCallArguments maps a `command` argv array element-wise", () => {
  const m = makeMap();
  const args = JSON.stringify({ command: ["bash", "-lc", `cat ${HUMAN}/a`] });
  const out = m.rewriteFunctionCallArguments(args, "forward");
  assert.ok(out);
  assert.deepEqual(JSON.parse(out!).command, ["bash", "-lc", `cat ${AGENT}/a`]);
});

test("rewriteFunctionCallArguments returns null when nothing changes / unparseable", () => {
  const m = makeMap();
  assert.equal(m.rewriteFunctionCallArguments(JSON.stringify({ cmd: "ls -la" }), "forward"), null);
  assert.equal(m.rewriteFunctionCallArguments(JSON.stringify({ cmd: `cat ${AGENT}/a` }), "forward"), null); // idempotent
  assert.equal(m.rewriteFunctionCallArguments("{not json", "forward"), null);
  assert.equal(m.rewriteFunctionCallArguments("", "forward"), null);
});

test("reverse request walker maps function_call_output text + echoed function_call args", () => {
  const m = makeMap();
  const req: ResponsesRequest = {
    model: "gpt-x",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "go" }] },
      { type: "function_call", call_id: "c1", name: "exec_command", arguments: JSON.stringify({ cmd: `cat ${AGENT}/a` }) },
      { type: "function_call_output", call_id: "c1", output: `error: cannot open ${AGENT}/a` },
    ],
  };
  reverseMapRequestPaths(req, m);
  const fc = req.input![1] as { arguments: string };
  const out = req.input![2] as { output: string };
  assert.deepEqual(JSON.parse(fc.arguments), { cmd: `cat ${HUMAN}/a` });
  assert.equal(out.output, `error: cannot open ${HUMAN}/a`);
  // The path-free user message rides through byte-identical.
  assert.deepEqual((req.input![0] as { content: unknown }).content, [{ type: "input_text", text: "go" }]);
});

test("reverse request walker maps user/assistant MESSAGE text; system stays untouched (E28 dual)", () => {
  const m = makeMap();
  // The anthropic dual's live catch (E28, 2026-07-14): the client machine-
  // generates conversation text carrying the twin spelling (@-mention pre-read
  // reminders). Same contract here: user/assistant message text reverse-maps;
  // system text (the agent's own environment note naming its real CWD) does not.
  const req: ResponsesRequest = {
    model: "gpt-x",
    input: [
      { type: "message", role: "system", content: [{ type: "input_text", text: `cwd: ${AGENT}` }] },
      { type: "message", role: "user", content: [{ type: "input_text", text: `see ${AGENT}/notes.md` }] },
      { type: "message", role: "user", content: `also ${AGENT}/plain.md` },
      { type: "message", role: "assistant", content: [{ type: "output_text", text: `I read ${AGENT}/notes.md.` }] },
    ],
  };
  reverseMapRequestPaths(req, m);
  assert.deepEqual((req.input![0] as { content: unknown }).content, [{ type: "input_text", text: `cwd: ${AGENT}` }]);
  assert.deepEqual((req.input![1] as { content: unknown }).content, [{ type: "input_text", text: `see ${HUMAN}/notes.md` }]);
  assert.equal((req.input![2] as { content: unknown }).content, `also ${HUMAN}/plain.md`);
  assert.deepEqual((req.input![3] as { content: unknown }).content, [{ type: "output_text", text: `I read ${HUMAN}/notes.md.` }]);
});

test("an inactive map (degenerate/empty) leaves the request untouched", () => {
  const m = new ViewMap([], { dialect: "posix", home: "/home/u" });
  assert.equal(m.active, false);
  const req: ResponsesRequest = {
    input: [{ type: "function_call_output", call_id: "c", output: `${AGENT}/x` }],
  };
  reverseMapRequestPaths(req, m);
  assert.equal((req.input![0] as { output: string }).output, `${AGENT}/x`);
});

test("parseViewMapEnv: unset → [], valid parses, junk THROWS (loud)", () => {
  assert.deepEqual(parseViewMapEnv(undefined), []);
  assert.deepEqual(parseViewMapEnv(`[{"human":"/h","agent":"/a"}]`), [{ human: "/h", agent: "/a" }]);
  assert.throws(() => parseViewMapEnv("nope"), /not valid JSON/);
  assert.throws(() => parseViewMapEnv(`[{"human":"/h"}]`), /must be \{human/);
});
