/**
 * pdf-document-block — a PDF a tool result carries as a `document` block
 * (Claude Code's `Read` of a `.pdf`; secret-discovery.md §2.8, "A document
 * block"): the proxy asks the arbiter for its text and forwards that text in
 * place of the block, so what reaches the model is what the classify judges;
 * with no text, an image beside it, no op or a throw, the block stays and
 * the result is masked whole, as every non-text result was.
 *
 * Mock arbiter (no daemon, no network). The real arbiter's answers are
 * `tests/stack/content-tier-document-files.test.ts`.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { isPdfDocumentBlock, pdfBlocksAsText, rewriteRequest } from "../../src/rewrite-request.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";


const SYM_RE = /^\$MDU:/;
const PDF_DATA = Buffer.from("%PDF-1.4 a statement with ACCOUNT-0042-118833-77").toString("base64");
const pdfBlock = (data = PDF_DATA) => ({ type: "document", source: { type: "base64", media_type: "application/pdf", data } });
const fresh = (tag: string): string => Buffer.from(`%PDF-1.4 ${tag} ACCOUNT-0042-118833-77`).toString("base64");
const imageBlock = { type: "image", source: { type: "base64", media_type: "image/png", data: "iVBORw0KGgo=" } };

function readRequest(content: unknown[], id = "toolu_pdf", path = "/home/u/bank/statement.pdf"): MessagesRequest {
  return {
    model: "m",
    messages: [
      { role: "user", content: "read my statement" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "Read", input: { file_path: path } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: content as any }] },
    ],
  };
}

test("isPdfDocumentBlock: an inline PDF only", () => {
  assert.equal(isPdfDocumentBlock(pdfBlock()), true);
  assert.equal(isPdfDocumentBlock({ type: "document", source: { type: "base64", media_type: "Application/PDF", data: "x" } }), true);
  assert.equal(isPdfDocumentBlock({ type: "document", source: { type: "url", url: "https://x/y.pdf" } }), false);
  assert.equal(isPdfDocumentBlock({ type: "document", source: { type: "text", media_type: "text/plain", data: "x" } }), false);
  assert.equal(isPdfDocumentBlock(imageBlock), false);
  assert.equal(isPdfDocumentBlock(null), false);
});

test("a Claude Code Read of a PDF reaches the model as the arbiter's text, in the harness's text rendering, and the classify judges that text", async () => {
  const twin = "Account number: $MDU:nomodel_Read[a1b2].extract_2\nClosing balance: $MDU:nomodel_Read[a1b2].extract_9";
  const arbiter = new MockArbiter({ trustedTools: ["Read"], documentTextFn: () => ({ text: twin, twinOf: "/home/u/bank/statement.pdf", reason: "twin" }) });
  const { request, rewrites } = await rewriteRequest(readRequest([{ type: "text", text: "PDF file read: /home/u/bank/statement.pdf (2.1 KB)" }, pdfBlock()]), { arbiter });
  const tr = (request.messages[2]!.content as any[])[0];
  assert.deepEqual(tr.content, [{ type: "text", text: "     1\tAccount number: $MDU:nomodel_Read[a1b2].extract_2\n     2\tClosing balance: $MDU:nomodel_Read[a1b2].extract_9" }]);
  assert.ok(!JSON.stringify(request).includes(PDF_DATA), "the block's bytes never reach the model");
  assert.equal(arbiter.documentTextCalls.length, 1);
  assert.deepEqual(arbiter.documentTextCalls[0], { data: PDF_DATA, mediaType: "application/pdf", origin: "/home/u/bank/statement.pdf" });
  // the classify saw exactly the forwarded text
  const asked = arbiter.classifyCalls.find((c) => c.tool === "Read");
  assert.equal(asked?.value, tr.content[0].text);
  assert.equal(rewrites[0]!.symbolized, false);
});

test("a PDF's text the classify distrusts or finds secret is masked as any text: never the block", async () => {
  const arbiter = new MockArbiter({ documentTextFn: () => ({ text: "Account number: 0042-118833-77", reason: "the PDF's text layer" }) });
  const { request, rewrites } = await rewriteRequest(readRequest([pdfBlock(fresh("raw"))], "toolu_raw"), { arbiter });
  const tr = (request.messages[2]!.content as any[])[0];
  assert.equal(rewrites[0]!.symbolized, true);
  assert.match(tr.content[0].text, SYM_RE);
  assert.ok(!JSON.stringify(request).includes("0042-118833-77") && !JSON.stringify(request).includes(PDF_DATA));
});

test("fail closed: no text, an image beside the PDF, no op, a throw: the result is masked whole", async () => {
  const cases: Array<[string, MockArbiter, unknown[]]> = [
    ["no text (a scan)", new MockArbiter({ trustedTools: ["Read"], documentTextFn: () => ({ text: null, reason: "no-text" }) }), [pdfBlock(fresh("scan"))]],
    ["an empty text", new MockArbiter({ trustedTools: ["Read"], documentTextFn: () => ({ text: "", reason: "x" }) }), [pdfBlock(fresh("empty"))]],
    ["an image beside it", new MockArbiter({ trustedTools: ["Read"], documentTextFn: () => ({ text: "hello", reason: "x" }) }), [pdfBlock(fresh("image")), imageBlock]],
    ["no op", new MockArbiter({ trustedTools: ["Read"] }), [pdfBlock(fresh("noop"))]],
    ["a throw", new MockArbiter({ trustedTools: ["Read"], documentTextFn: () => { throw new Error("arbiter down"); } }), [pdfBlock(Buffer.from("other bytes").toString("base64"))]],
  ];
  for (const [why, arbiter, content] of cases) {
    const { request, rewrites } = await rewriteRequest(readRequest(content, `toolu_${why.replace(/\W/g, "")}`), { arbiter });
    const tr = (request.messages[2]!.content as any[])[0];
    assert.equal(rewrites[0]!.symbolized, true, why);
    assert.equal(tr.content.length, 1, why);
    assert.match(tr.content[0].text, SYM_RE, why);
    assert.ok(!JSON.stringify(request).includes("JVBERi0xLjQg"), `${why}: the block's bytes never reach the model`);
  }
});

test("another tool keeps its text blocks, each PDF replaced in place by its text", async () => {
  const arbiter = new MockArbiter({ documentTextFn: (r) => ({ text: `text of ${r.data.length} chars`, reason: "x" }) });
  const out = await pdfBlocksAsText([{ type: "text", text: "two files:" }, pdfBlock(), pdfBlock("JVBERi0xLjQ=")], arbiter, { claudeRead: false });
  assert.deepEqual(out, [{ type: "text", text: "two files:" }, { type: "text", text: `text of ${PDF_DATA.length} chars` }, { type: "text", text: "text of 12 chars" }]);
  // the same block again is answered from the cache
  const before = arbiter.documentTextCalls.length;
  await pdfBlocksAsText([pdfBlock()], arbiter, { claudeRead: false });
  assert.equal(arbiter.documentTextCalls.length, before);
});
