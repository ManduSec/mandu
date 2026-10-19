/**
 * own-write-notice.test.ts — confidentiality-plan-15-prompt-filter.md §13.10,
 * "A Write's own result"; confidentiality.md §7.1, "The write notice".
 *
 * A HIGH session's Write is labelled at its watermark on disk at the
 * tool_use (Plan 9), and the Write's own result, classified by its path,
 * came back to the model as `$MDU:anymodel_Write[…]` (live drill
 * conf-derived-label-next-session). The result is the agent's fixed success
 * sentence around the model's own path: no byte of the file, nothing the
 * model did not write. A result that is EXACTLY such a notice for the call is
 * public; anything else a write of a secret path answers keeps the mask.
 *
 * Unit level: the predicate (`isOwnWriteNotice`) and the engine's classify
 * verdict. The real-proxy half: tests/stack/write-notice-raw.test.ts.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm run test:unit
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";

import { createEngineBackedPolicy } from "../../policy/policy-interface.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import { isOwnWriteNotice, ownWriteNotices } from "../../policy/own-write-notice.js";
import type { InboundSpecId } from "../../policy/tool-inbound.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");
after(() => resetCurrentPolicyForTests("claude-code"));

const SECRET = "/ws/.env"; // a catalog secret path: no-model by the path alone
const KEY = "sk_live_FakeOwnWrite0123456789abcdef";
const CONTENT = `STRIPE_KEY=${KEY}\n`;
const CREATED = `File created successfully at: ${SECRET}`;
const UPDATED = `The file ${SECRET} has been updated successfully.`;
const MODIFIED = " The user modified your proposed content before accepting it.";
const CURRENT = " (file state is current in your context — no need to Read it back)";
const BUDGET = "<system-reminder>\n<total_tokens>14000 tokens left</total_tokens>\n</system-reminder>";
const MCP_REMINDER = "<system-reminder>\n# MCP Server Instructions\nsome server text\n</system-reminder>";
/** Claude Code before 2.x answered an overwrite with a snippet of the file. */
const OLD_UPDATE = `The file ${SECRET} has been updated. Here's the result of running \`cat -n\` on a snippet of the edited file:\n     1\tSTRIPE_KEY=${KEY}`;

const cc = { file_path: SECRET, content: CONTENT };

test("isOwnWriteNotice (claude-code): each Write notice for the call's own path, with its fixed suffixes and the budget tail", () => {
  for (const v of [
    CREATED, UPDATED, CREATED + CURRENT, UPDATED + CURRENT, CREATED + MODIFIED, UPDATED + MODIFIED,
    `${CREATED}\n`, `\n${CREATED + CURRENT}\n\n`, `${CREATED + CURRENT}\n\n${BUDGET}`, `${UPDATED}\n\n${BUDGET}\n${BUDGET}`,
  ]) {
    assert.equal(isOwnWriteNotice("claude-code", v, cc), true, JSON.stringify(v));
  }
  assert.equal(ownWriteNotices("claude-code", cc).length, 8, "two heads × four suffix forms, a closed set");
});

test("isOwnWriteNotice (claude-code): a file byte, another path, a lookalike, any other tail, no content → false", () => {
  const no: Array<[string, Record<string, unknown> | undefined]> = [
    [OLD_UPDATE, cc],
    [`${CREATED}\n${CONTENT}`, cc],
    [`${CONTENT}${CREATED}`, cc],
    [`${CREATED} ${KEY}`, cc],
    [`${CREATED}\n\n${MCP_REMINDER}`, cc],
    [`${CREATED}\n\n${BUDGET}\n${MCP_REMINDER}`, cc],
    [`${CREATED}\n\n${BUDGET}${BUDGET}${BUDGET}`, cc],
    [`${CREATED}\n\n${BUDGET.replace("14000", "1234567890123")}`, cc],
    [`${BUDGET}\n${CREATED}`, cc],
    [BUDGET, cc],
    [CREATED.replace("successfully", "Successfully"), cc],
    [CREATED + CURRENT.replace("—", "-"), cc],
    [`File created successfully at: /ws/other.env`, cc],
    [CREATED, { file_path: "/ws/other.env", content: CONTENT }],
    [CREATED, { file_path: SECRET }],
    [CREATED, { file_path: SECRET, content: 7 }],
    [CREATED, { content: CONTENT }],
    [CREATED, undefined],
    ["File created successfully at: ", { file_path: "", content: "" }],
    ["", cc],
  ];
  for (const [v, params] of no) assert.equal(isOwnWriteNotice("claude-code", v, params), false, `${JSON.stringify(v)} ${JSON.stringify(params)}`);
});

test("isOwnWriteNotice (opencode, goose): their pinned notice for the call's own path; Goose's count is the content's", () => {
  assert.equal(isOwnWriteNotice("opencode", "Created file successfully: out.txt", { path: "out.txt", content: "written\n" }), true);
  assert.equal(isOwnWriteNotice("opencode", "Created file successfully: out.txt", { filePath: "out.txt", content: "written\n" }), false, "OpenCode 2's sentence under OpenCode 1's field");
  assert.equal(isOwnWriteNotice("opencode", "Created file successfully: out.txt", { path: "other.txt", content: "x" }), false);
  assert.equal(isOwnWriteNotice("opencode", "Created file successfully: out.txt\n\nLSP errors detected in other files:\n<diagnostics file=\"/ws/a.ts\">\nERROR [1:1] secret_identifier\n</diagnostics>", { path: "out.txt", content: "x" }), false, "diagnostics name other files' content");
  assert.equal(isOwnWriteNotice("opencode", `${CREATED}`, cc), false, "Claude Code's sentence is not OpenCode's");
  assert.equal(isOwnWriteNotice("opencode", "Created file successfully: out.txt\n\n" + BUDGET, { path: "out.txt", content: "x" }), false, "no budget tail outside Claude Code");

  const g = { path: "/ws/notes.md", content: "a\nb\n" };
  assert.equal(isOwnWriteNotice("goose", "Created /ws/notes.md (2 lines)", g), true);
  assert.equal(isOwnWriteNotice("goose", "Created /ws/notes.md (3 lines)", g), true, "the plain split's count of the same content");
  assert.equal(isOwnWriteNotice("goose", "Created /ws/notes.md (4 lines)", g), false, "a count that is not the content's");
  assert.equal(isOwnWriteNotice("goose", "Created /ws/notes.md (0 lines)", { path: "/ws/notes.md", content: "" }), true);
  assert.equal(isOwnWriteNotice("goose", "Created /ws/other.md (2 lines)", g), false);
  assert.equal(isOwnWriteNotice("goose", "Created /ws/notes.md (2 lines)", { path: "/ws/notes.md" }), false, "no content: not a whole-content write");
});

/** OpenCode 1.18.13's `write` (the compiled tool in the opencode-ai binary):
 *  `let b="Wrote file successfully."`, then LSP diagnostics appended. */
const OC1 = "Wrote file successfully.";
const OC1_DIAG = `${OC1}\n\nLSP errors detected in this file, please fix:\n<diagnostics file="${SECRET}">\nERROR [1:1] ${KEY}\n</diagnostics>`;

test("isOwnWriteNotice (opencode 1): its fixed sentence, only for a whole-content write under its own `filePath` field", () => {
  const oc1 = { filePath: SECRET, content: CONTENT };
  for (const v of [OC1, `${OC1}\n`, `\n${OC1}\n\n`]) assert.equal(isOwnWriteNotice("opencode", v, oc1), true, JSON.stringify(v));
  assert.deepEqual(ownWriteNotices("opencode", oc1), [OC1], "one fixed sentence, no free span");
  const no: Array<[string, Record<string, unknown> | undefined]> = [
    [OC1_DIAG, oc1],
    [`${OC1}\n\nLSP errors detected in other files:\n<diagnostics file="/ws/a.ts">\nERROR [1:1] secret_identifier\n</diagnostics>`, oc1],
    [`${OC1}\n${CONTENT}`, oc1],
    [`${CONTENT}${OC1}`, oc1],
    [`${OC1} ${KEY}`, oc1],
    ["Wrote file successfully", oc1],
    ["wrote file successfully.", oc1],
    [`${OC1}\n\n${BUDGET}`, oc1],
    [OC1, { filePath: SECRET }],
    [OC1, { filePath: SECRET, content: 7 }],
    [OC1, { filePath: "", content: CONTENT }],
    [OC1, { content: CONTENT }],
    [OC1, { path: SECRET, content: CONTENT }],
    [OC1, undefined],
  ];
  for (const [v, params] of no) assert.equal(isOwnWriteNotice("opencode", v, params), false, `${JSON.stringify(v)} ${JSON.stringify(params)}`);
  assert.equal(isOwnWriteNotice("claude-code", OC1, { file_path: SECRET, content: CONTENT }), false, "not Claude Code's sentence");
  assert.equal(isOwnWriteNotice("goose", OC1, { path: SECRET, content: CONTENT }), false, "not Goose's sentence");
});

/** OpenClaw 2026.7.1-2's `write` (dist/sessions-*.js, createWriteToolDefinition):
 *  `Successfully wrote ${content.length} bytes to ${path}`; 2026.9.9 prints
 *  `Buffer.byteLength(content, "utf8")` in the same sentence. */
const ocl = (n: number, path = SECRET) => `Successfully wrote ${n} bytes to ${path}`;
const NO_CHANGE = `No changes made to ${SECRET}. The file already has identical content.`;

test("isOwnWriteNotice (openclaw): its sentence for the call's own `path`, the count the content's length or UTF-8 byte length", () => {
  const p = { path: SECRET, content: CONTENT };
  for (const v of [ocl(CONTENT.length), `${ocl(CONTENT.length)}\n`, `\n${ocl(CONTENT.length)}\n`]) assert.equal(isOwnWriteNotice("openclaw", v, p), true, JSON.stringify(v));
  assert.deepEqual(ownWriteNotices("openclaw", p), [ocl(CONTENT.length)], "ASCII: one count");
  // non-ASCII content: 2026.7.1-2's UTF-16 length and 2026.9.9's UTF-8 length both match
  const wide = { path: "/ws/notes.md", content: "café ☕ 😀\n" };
  assert.equal(wide.content.length, 10);
  assert.equal(Buffer.byteLength(wide.content, "utf8"), 15);
  assert.equal(isOwnWriteNotice("openclaw", ocl(10, "/ws/notes.md"), wide), true, "2026.7.1-2: the string length");
  assert.equal(isOwnWriteNotice("openclaw", ocl(15, "/ws/notes.md"), wide), true, "2026.9.9: the UTF-8 byte length");
  assert.equal(isOwnWriteNotice("openclaw", ocl(11, "/ws/notes.md"), wide), false, "any other count");
  assert.equal(isOwnWriteNotice("openclaw", ocl(0, "/ws/e.md"), { path: "/ws/e.md", content: "" }), true, "empty content: 0 bytes");

  const no: Array<[string, Record<string, unknown> | undefined]> = [
    [NO_CHANGE, p], // the other answer: a choice on the file's bytes, kept masked
    [ocl(CONTENT.length + 1), p],
    [ocl(CONTENT.length, "/ws/other.env"), p],
    [ocl(CONTENT.length), { path: "/ws/other.env", content: CONTENT }],
    [`${ocl(CONTENT.length)}\n${CONTENT}`, p],
    [`${CONTENT}${ocl(CONTENT.length)}`, p],
    [`${ocl(CONTENT.length)} ${KEY}`, p],
    [`${ocl(CONTENT.length)}\n\n${BUDGET}`, p],
    [`Write verification failed for ${SECRET}: the persisted regular file does not match the requested content. Inspect the target and retry.`, p],
    [ocl(CONTENT.length).replace("Successfully", "successfully"), p],
    [ocl(CONTENT.length), { file_path: SECRET, content: CONTENT }], // not OpenClaw's field
    [ocl(CONTENT.length), { path: SECRET }],
    [ocl(CONTENT.length), { path: SECRET, content: 7 }],
    [ocl(CONTENT.length), undefined],
    [ocl(0, ""), { path: "", content: "" }],
  ];
  for (const [v, params] of no) assert.equal(isOwnWriteNotice("openclaw", v, params), false, `${JSON.stringify(v)} ${JSON.stringify(params)}`);
  assert.equal(isOwnWriteNotice("opencode", ocl(CONTENT.length), p), false, "not OpenCode's sentence");
});

const policy = (tools?: Record<string, unknown>, specs?: Record<string, InboundSpecId>) =>
  createEngineBackedPolicy({
    policyFileOverride: tools ? ({ tools } as never) : {},
    confidentiality: true, integrity: false,
    ...(specs ? { sessionSpecs: { specOf: (k: string) => specs[k] } } : {}),
  });
const classify = (p: ReturnType<typeof policy>, tool: string, value: string, params: Record<string, unknown>, extra: Record<string, unknown> = {}) =>
  p.classify({ tool, value, boundary: "model_context", origin: String(params["file_path"] ?? params["path"] ?? params["filePath"] ?? ""), params, ...extra });

test("classify (secrets): a Write of a secret path answered by its own notice is public; the reason names the rule", () => {
  const p = policy();
  for (const v of [CREATED, UPDATED + CURRENT, `${CREATED + CURRENT}\n\n${BUDGET}`]) {
    const r = classify(p, "Write", v, cc);
    assert.equal(r.confidentiality, "public", JSON.stringify(v));
    assert.match(r.reason, /write notice/);
  }
});

test("classify (secrets): every other result of a write of a secret path keeps the path-derived mask (fail-closed)", () => {
  const p = policy();
  for (const v of [OLD_UPDATE, `${CREATED}\n${CONTENT}`, `${CREATED}\n\n${MCP_REMINDER}`, `File created successfully at: /ws/other.env`, CONTENT]) {
    assert.equal(classify(p, "Write", v, cc).confidentiality, "no-model", JSON.stringify(v));
  }
  assert.equal(classify(p, "Write", CREATED, { file_path: SECRET }).confidentiality, "no-model", "no content in the input");
  // an Edit's notice: the file keeps bytes the model may never have read raw
  assert.equal(classify(p, "Edit", UPDATED, { file_path: SECRET, old_string: "a", new_string: "b" }).confidentiality, "no-model", "Edit is not released");
  // the same sentence from a tool that is not the agent's write
  assert.equal(p.classify({ tool: "Bash", value: CREATED, boundary: "model_context", params: { command: `cat ${SECRET}` } }).confidentiality, "no-model");
  assert.equal(classify(p, "mcp__fs__Write", CREATED, cc).confidentiality, "no-model", "an MCP tool named like Write");
  // field-addressed: never the whole result
  assert.equal(classify(p, "Write", CREATED, cc, { field: "content" }).confidentiality, "no-model");
});

test("classify (secrets): a policy.yaml rule for Write wins over the release (spec identity)", () => {
  const p = policy({ Write: { inbound: "TRUSTED" } });
  assert.equal(classify(p, "Write", CREATED, cc).confidentiality, "no-model");
});

test("classify (secrets): OpenCode's and Goose's write notices in their own sessions only", () => {
  const p = policy(undefined, { oc: "opencode", gs: "goose", cl: "claude-code" });
  const oc = { path: SECRET, content: CONTENT };
  assert.equal(classify(p, "write", `Created file successfully: ${SECRET}`, oc, { sessionKey: "oc" }).confidentiality, "public");
  assert.equal(classify(p, "write", `Created file successfully: ${SECRET}\n\n${CONTENT}`, oc, { sessionKey: "oc" }).confidentiality, "no-model");
  assert.equal(classify(p, "write", `Created ${SECRET} (1 lines)`, oc, { sessionKey: "gs" }).confidentiality, "public");
  assert.equal(classify(p, "write", `Created ${SECRET} (9 lines)`, oc, { sessionKey: "gs" }).confidentiality, "no-model");
  // another agent's sentence in a session that is not that agent's
  assert.equal(classify(p, "write", `Created file successfully: ${SECRET}`, oc, { sessionKey: "gs" }).confidentiality, "no-model");
  assert.equal(classify(p, "Write", `Created file successfully: ${SECRET}`, cc, { sessionKey: "cl" }).confidentiality, "no-model");
});

test("classify (secrets): OpenCode 1's and OpenClaw's write notices in their own sessions only; every other answer keeps the mask", () => {
  const p = policy(undefined, { oc: "opencode", ocl: "openclaw-agent", ref: "openclaw", gs: "goose", cl: "claude-code" });
  const oc1 = { filePath: SECRET, content: CONTENT };
  const oclIn = { path: SECRET, content: CONTENT };
  const okOcl = ocl(CONTENT.length);
  // OpenCode 1, session spec `opencode`
  const r1 = classify(p, "write", OC1, oc1, { sessionKey: "oc" });
  assert.equal(r1.confidentiality, "public");
  assert.match(r1.reason, /write notice/);
  for (const v of [OC1_DIAG, `${OC1}\n${CONTENT}`, CONTENT]) assert.equal(classify(p, "write", v, oc1, { sessionKey: "oc" }).confidentiality, "no-model", JSON.stringify(v));
  assert.equal(classify(p, "write", OC1, { filePath: SECRET }, { sessionKey: "oc" }).confidentiality, "no-model", "no content");
  assert.equal(classify(p, "edit", OC1, { filePath: SECRET, oldString: "a", newString: "b" }, { sessionKey: "oc" }).confidentiality, "no-model", "an edit is not released");
  assert.equal(classify(p, "write", OC1, oc1, { sessionKey: "oc", field: "output" }).confidentiality, "no-model", "field-addressed");
  // OpenClaw, the defended agent's spec `openclaw-agent`
  const r2 = classify(p, "write", okOcl, oclIn, { sessionKey: "ocl" });
  assert.equal(r2.confidentiality, "public");
  assert.match(r2.reason, /write notice/);
  for (const v of [NO_CHANGE, ocl(CONTENT.length + 3), `${okOcl}\n${CONTENT}`, ocl(CONTENT.length, "/ws/other.env"), CONTENT]) {
    assert.equal(classify(p, "write", v, oclIn, { sessionKey: "ocl" }).confidentiality, "no-model", JSON.stringify(v));
  }
  assert.equal(classify(p, "edit", okOcl, { path: SECRET, edits: [{ oldText: "a", newText: "b" }] }, { sessionKey: "ocl" }).confidentiality, "no-model", "an edit is not released");
  assert.equal(classify(p, "tool_call", okOcl, { name: "write", args: oclIn }, { sessionKey: "ocl", origin: SECRET }).confidentiality, "no-model", "a dispatched call is not the built-in entry");
  // each sentence only in its own agent's session
  assert.equal(classify(p, "write", okOcl, oclIn, { sessionKey: "ref" }).confidentiality, "no-model", "the lifted reference spec is not the defended agent");
  assert.equal(classify(p, "write", okOcl, oclIn, { sessionKey: "oc" }).confidentiality, "no-model", "OpenClaw's sentence in an OpenCode session");
  assert.equal(classify(p, "write", OC1, oc1, { sessionKey: "ocl" }).confidentiality, "no-model", "OpenCode 1's sentence in an OpenClaw session");
  assert.equal(classify(p, "write", OC1, oc1, { sessionKey: "gs" }).confidentiality, "no-model", "OpenCode 1's sentence in a Goose session");
  assert.equal(classify(p, "Write", OC1, cc, { sessionKey: "cl" }).confidentiality, "no-model", "OpenCode 1's sentence from Claude Code's Write");
});

test("classify (secrets): the release is confidentiality-only; with the axis off the verdict carries no level", () => {
  const off = createEngineBackedPolicy({ policyFileOverride: {}, confidentiality: false, integrity: false });
  const r = off.classify({ tool: "Write", value: CREATED, boundary: "model_context", origin: SECRET, params: cc });
  assert.equal(r.confidentiality, undefined);
});
