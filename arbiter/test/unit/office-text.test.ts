/**
 * office-text.test — the Office text extractor of the contents model
 * (confidentiality-plan-14 §14.13; arbiter/policy/office-text.ts), over
 * OOXML fixtures built at run time (test/helpers/office-zip.ts), never
 * committed binaries.
 *
 * Pins:
 *   - Word: the body's `<w:t>` runs, paragraph breaks as newlines, `<w:tab/>`
 *     and `<w:br/>`, tab stops (`w:tabs`), deleted text, field codes,
 *     comments and CDATA not text, a `>` inside a quoted attribute, the
 *     five entities and numeric references (an invalid code point dropped,
 *     no other entity expanded), control characters dropped, core.xml's
 *     author never read;
 *   - Excel: the shared strings one per line, then the first sheets' inline
 *     strings; numbers, formulas, phonetic runs and the ninth sheet's inline
 *     strings not read;
 *   - PowerPoint: slides by number, not archive order; `<a:br/>`; more than
 *     200 slides is too long;
 *   - the caps: the text cap (`too-long`), a part that inflates past its
 *     limit (a bomb: `unreadable`, and no 16 MiB buffer), the per-file
 *     inflate total, the caller's byte budget (`over-budget`);
 *   - refused archives: Zip64 (markers, locator), multi-disk, an encrypted
 *     container (CFB), an encrypted entry, not a zip, a missing part, no
 *     text; every truncation and 500 random byte flips of a real fixture
 *     (never a throw, never past the budget, never the XML markup as text);
 *   - a sensitivity label (LabelInfo or custom.xml, enabled, mapped or not)
 *     is `labelled` and the text is not read; a disabled or removed label
 *     is not;
 *   - the families, and the extension lists held equal with 4a's.
 *
 * No privilege, no network.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  OFFICE_TEXT_LIMITS, OFFICE_TEXT_READER_VERSION, TextSink, decodeXmlEntities, extractXmlText, officeFamily, readOfficeText,
  type OfficeFamily, type OfficeTextRead,
} from "../../policy/office-text.js";
import { OFFICE_EXTENSIONS, type OfficeByteReader } from "../../policy/sensitivity-labels.js";
import { OFFICE_DOCUMENT_EXTENSIONS } from "../../policy/policy-model.js";
import { buildDocx, buildEncryptedContainer, buildPptx, buildXlsx, buildZip, docxBodyXml, slideXml } from "../helpers/office-zip.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const ID = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const SITE = "5b3c1a2e-0000-4000-8000-00000000abcd";

/** A reader over a buffer, recording how much it was asked for. */
function reader(buf: Buffer): OfficeByteReader & { asked: number } {
  const r = {
    size: buf.length,
    asked: 0,
    async read(offset: number, length: number) {
      r.asked += length;
      return buf.subarray(offset, offset + length);
    },
  };
  return r;
}

const read = (buf: Buffer, family: OfficeFamily, o: { maxBytes?: number; textMax?: number } = {}): Promise<OfficeTextRead> => readOfficeText(reader(buf), family, o);
const textOf = (r: OfficeTextRead): string => {
  assert.equal(r.kind, "text", JSON.stringify(r));
  return r.kind === "text" ? r.text : "";
};

// ── Word ─────────────────────────────────────────────────────────────────────

test("Word: the body's runs, one paragraph per line; tabs and breaks; entities decoded; nothing but visible text", async () => {
  assert.equal(textOf(await read(buildDocx(["First paragraph.", "Second & <third> \"quoted\" 'x'"]), "word")),
    "First paragraph.\nSecond & <third> \"quoted\" 'x'");

  const body = [
    `<?xml version="1.0" encoding="UTF-8"?><!-- a comment <w:t>NOT-COMMENT</w:t> -->`,
    `<w:document xmlns:w="w"><w:body>`,
    `<w:p><w:pPr><w:tabs><w:tab w:val="left" w:pos="720"/></w:tabs></w:pPr>`,
    `<w:r><w:t>A</w:t></w:r><w:r><w:tab/><w:t>B</w:t><w:br/><w:t xml:space="preserve">C </w:t></w:r>`,
    `<w:r><w:instrText> HYPERLINK "x" </w:instrText></w:r>`,
    `<w:del><w:r><w:delText>DELETED-TEXT</w:delText></w:r></w:del>`,
    `<w:r><w:t>&lt;&amp;&gt;&quot;&apos;&#65;&#x42;&#x1F600;&#0;&#xD800;&#1;&unknown;&amp;lt;</w:t></w:r></w:p>`,
    `<w:p/><w:p></w:p><w:p></w:p>`,
    `<w:p><w:r><w:rPr><w:rFonts w:ascii="a>b"/></w:rPr><w:t>after a quoted gt</w:t></w:r></w:p>`,
    `<w:p><w:r><w:t><![CDATA[CDATA-TEXT]]>kept\u0007 \u001b[31m</w:t></w:r></w:p>`,
    `<w:p><w:r><w:t/></w:r><m:oMath xmlns:m="m"><m:r><m:t>x=1</m:t></m:r></m:oMath></w:p>`,
    `</w:body></w:document>`,
  ].join("");
  const t = textOf(await read(buildDocx([], { body }), "word"));
  assert.equal(t, "A\tB\nC <&>\"'AB\u{1F600}&unknown;&lt;\nafter a quoted gt\nkept [31m\nx=1");
  for (const hidden of ["NOT-COMMENT", "DELETED-TEXT", "HYPERLINK", "CDATA-TEXT", "CORE-AUTHOR-NOT-TEXT", "w:t", "<w:", "pos="]) {
    assert.ok(!t.includes(hidden), hidden);
  }
});

test("the entity decoder: the five, decimal and hex references, one pass, invalid code points dropped, nothing else", () => {
  assert.equal(decodeXmlEntities("a &amp;amp; b"), "a &amp; b");
  assert.equal(decodeXmlEntities("&#9;&#10;&#x20;&#x10FFFF;"), "\t\n \u{10FFFF}");
  assert.equal(decodeXmlEntities("&#x110000;&#xFFFE;&#8;&#12345678;"), "&#12345678;");
  assert.equal(decodeXmlEntities("&nbsp; &copy; & &;"), "&nbsp; &copy; & &;");
  assert.equal(decodeXmlEntities("plain"), "plain");
});

test("the sink: at most one blank line in a row, none leading or trailing; false past its cap", () => {
  const s = new TextSink(100);
  s.newline(2);
  s.text("a");
  s.newline(1); s.newline(1); s.newline(2); s.newline(2);
  s.text("\n\n\n");
  s.text("b");
  s.newline(2);
  assert.equal(s.done(), "a\n\nb");
  const small = new TextSink(4);
  assert.equal(small.text("abcd"), true);
  assert.equal(small.text("e"), false);
  const x = new TextSink(10);
  assert.equal(extractXmlText(`<w:p><w:t>${"z".repeat(11)}</w:t></w:p>`, "word", x), false);
});

// ── Excel ────────────────────────────────────────────────────────────────────

test("Excel: the shared strings one per line, then the inline strings; no number, formula or phonetic run", async () => {
  const x = buildXlsx([["Name", "Salary"], ["A. Person", "Band 4"]], { inline: ["an inline note"] });
  assert.equal(textOf(await read(x, "sheet")), "Name\nSalary\nA. Person\nBand 4\n\nan inline note");
  const t = textOf(await read(x, "sheet"));
  for (const n of ["1007", "SUM(", "<v>"]) assert.ok(!t.includes(n), n);

  const phonetic = `<sst xmlns="s"><si><r><t>東京</t></r><rPh sb="0" eb="2"><t>トウキョウ</t></rPh></si><si><t>plain</t></si></sst>`;
  const withRph = buildZip([{ name: "xl/sharedStrings.xml", data: phonetic }]);
  assert.equal(textOf(await read(withRph, "sheet")), "東京\nplain");

  // Only the first eight sheets' inline strings are read.
  const nine = buildZip([
    ...Array.from({ length: 9 }, (_, i) => ({
      name: `xl/worksheets/sheet${i + 1}.xml`,
      data: `<worksheet><sheetData><row><c t="inlineStr"><is><t>sheet ${i + 1} text</t></is></c><c><v>42</v></c></row></sheetData></worksheet>`,
    })),
  ]);
  const t9 = textOf(await read(nine, "sheet"));
  assert.ok(t9.includes("sheet 8 text"));
  assert.ok(!t9.includes("sheet 9 text"), "the ninth sheet is not read");
  assert.ok(!t9.includes("42"));
  assert.equal(OFFICE_TEXT_LIMITS.sheetsMax, 8);
});

// ── PowerPoint ───────────────────────────────────────────────────────────────

test("PowerPoint: slides by their number, whatever the archive order; a:br; more than 200 slides is too long", async () => {
  const p = buildPptx([["third slide"], ["first slide", "line two"], ["second slide"]], { order: [3, 1, 2] });
  assert.equal(textOf(await read(p, "slides")), "first slide\nline two\n\nsecond slide\n\nthird slide");
  const br = buildZip([{ name: "ppt/slides/slide1.xml", data: `<p:sld><a:p><a:r><a:t>up</a:t></a:r><a:br/><a:r><a:t>down</a:t></a:r></a:p><a:tabLst><a:tab pos="1"/></a:tabLst></p:sld>` }]);
  assert.equal(textOf(await read(br, "slides")), "up\ndown");
  const deck = buildPptx(Array.from({ length: 201 }, (_, i) => [`s${i}`]));
  assert.equal((await read(deck, "slides")).kind, "too-long");
  assert.equal(textOf(await read(buildPptx(Array.from({ length: 200 }, (_, i) => [`s${i}`])), "slides")).split("\n\n").length, 200);
  // Not a slide: layouts, masters, notes.
  const other = buildZip([
    { name: "ppt/slideLayouts/slideLayout1.xml", data: slideXml(["LAYOUT"]) },
    { name: "ppt/notesSlides/notesSlide1.xml", data: slideXml(["NOTES"]) },
    { name: "ppt/slides/slide1.xml", data: slideXml(["real"]) },
  ]);
  assert.equal(textOf(await read(other, "slides")), "real");
});

// ── the caps ─────────────────────────────────────────────────────────────────

test("the caps: more text than the cap is too long; a bomb stops at its limit; the per-file total; the caller's budget", async () => {
  const long = buildDocx(["a".repeat(3000), "b".repeat(3000)]);
  assert.equal((await read(long, "word", { textMax: 5000 })).kind, "too-long");
  assert.equal(textOf(await read(long, "word", { textMax: 6001 })).length, 6001);
  assert.equal(OFFICE_TEXT_LIMITS.textMax, 256 * 1024);
  assert.equal((await read(buildDocx(["x".repeat(OFFICE_TEXT_LIMITS.textMax + 1)]), "word")).kind, "too-long");

  // A body that inflates to 16 MiB (a bomb): stops at 4 MiB, unreadable.
  const bomb = buildDocx([], { body: `<w:document><w:body><w:p><w:t>${" ".repeat(16 * 1024 * 1024)}</w:t></w:p></w:body></w:document>` });
  const before = process.memoryUsage().arrayBuffers;
  const b = await read(bomb, "word");
  assert.deepEqual(b.kind === "unreadable" && b.reason, "a text part that inflates past its limit");
  assert.ok(process.memoryUsage().arrayBuffers - before < 12 * 1024 * 1024, "no 16 MiB buffer was made");
  assert.ok(bomb.length < 64 * 1024, "the bomb is small on disk");

  // Five slides of 3.5 MiB each: the fifth passes the 16 MiB per-file total.
  const fat = buildZip(Array.from({ length: 5 }, (_, i) => ({ name: `ppt/slides/slide${i + 1}.xml`, data: `<p:sld>${" ".repeat(3.5 * 1024 * 1024)}<a:p><a:t>s${i}</a:t></a:p></p:sld>` })));
  assert.notEqual((await read(fat, "slides")).kind, "text");

  // A stored part over 4 MiB, a compressed one over 4 MiB.
  const stored = buildDocx([], { body: `<w:document>${" ".repeat(4 * 1024 * 1024 + 1)}</w:document>`, stored: true });
  const st = await read(stored, "word");
  assert.deepEqual(st.kind === "unreadable" && st.reason, "a text part over its size limit");

  // The caller's budget: a few bytes is over budget, never more read.
  const doc = buildDocx(["budget"]);
  const r = reader(doc);
  const o = await readOfficeText(r, "word", { maxBytes: 100 });
  assert.equal(o.kind, "over-budget");
  assert.ok(r.asked <= 100);
  assert.ok(OFFICE_TEXT_LIMITS.fileReadMax >= OFFICE_TEXT_LIMITS.fileOutMax);
});

// ── refused archives ─────────────────────────────────────────────────────────

test("refused: Zip64, multi-disk, an encrypted container or entry, not a zip, a missing part, no text", async () => {
  const unreadable = async (b: Buffer, fam: OfficeFamily, reason: string): Promise<void> => {
    const r = await read(b, fam);
    assert.deepEqual(r.kind === "unreadable" && r.reason, reason, JSON.stringify(r));
  };
  await unreadable(buildDocx(["x"], { zip: { zip64Markers: true } }), "word", "a Zip64 archive");
  await unreadable(buildDocx(["x"], { zip: { zip64Locator: true } }), "word", "a Zip64 archive");
  await unreadable(buildDocx(["x"], { zip: { multiDisk: true } }), "word", "a multi-disk archive");
  assert.equal((await read(buildEncryptedContainer(), "word")).kind, "encrypted");
  assert.equal((await read(buildEncryptedContainer(16), "word")).kind, "encrypted");
  await unreadable(buildZip([{ name: "word/document.xml", data: docxBodyXml(["x"]), flags: 1 }]), "word", "an encrypted entry");
  await unreadable(Buffer.from("just some text, not a zip archive at all"), "word", "not a zip archive");
  await unreadable(buildDocx(["x"], { noMain: true }), "word", "a missing part");
  await unreadable(buildXlsx([["x"]], { noMain: true }), "sheet", "a missing part");
  await unreadable(buildPptx([["x"]], { noMain: true }), "slides", "a missing part");
  // The right family's part only: a Word body is not a deck.
  await unreadable(buildDocx(["x"]), "slides", "a missing part");
  await unreadable(buildDocx([]), "word", "no text");
  await unreadable(buildDocx(["   ", ""]), "word", "no text");
});

test("every truncation and 500 random byte flips: never a throw, never past the budget, never markup as text", async () => {
  const doc = buildDocx(["The quarterly figures stay internal.", "Second paragraph."]);
  for (let n = 0; n < doc.length; n++) {
    const r = await read(doc.subarray(0, n), "word", { maxBytes: 2 * doc.length });
    assert.notEqual(r.kind, "text", `a truncation at ${n} is not read`);
  }
  let seed = 7;
  const rnd = (): number => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed; };
  for (let k = 0; k < 500; k++) {
    const b = Buffer.from(doc);
    for (let j = 0; j < 1 + (k % 4); j++) b[rnd() % b.length] = rnd() & 0xff;
    const rd = reader(b);
    const r = await readOfficeText(rd, "word", { maxBytes: 4 * doc.length });
    assert.ok(rd.asked <= 4 * doc.length);
    assert.ok(["text", "unreadable", "over-budget", "too-long", "labelled", "encrypted"].includes(r.kind));
    if (r.kind === "text") {
      assert.ok(Buffer.byteLength(r.text) <= OFFICE_TEXT_LIMITS.textMax);
      assert.ok(!r.text.includes("<w:t") && !r.text.includes("xmlns"), "never the markup");
    }
  }
});

// ── sensitivity labels ───────────────────────────────────────────────────────

test("a sensitivity label ends the read: enabled in LabelInfo or custom.xml, mapped or not; disabled or removed is read", async () => {
  const body = ["LABELLED-BODY-TEXT"];
  for (const f of [{ labelInfo: [{ id: ID, site: SITE }] }, { custom: [{ id: ID, site: SITE, name: "Highly Confidential" }] }, { labelInfo: [{ id: ID, enabled: false }], custom: [{ id: ID }] }]) {
    for (const r of [await read(buildDocx(body, f), "word"), await read(buildXlsx([["LABELLED-BODY-TEXT"]], f), "sheet"), await read(buildPptx([body], f), "slides")]) {
      assert.equal(r.kind, "labelled", JSON.stringify(f));
      assert.ok(!JSON.stringify(r).includes("LABELLED-BODY-TEXT"));
    }
  }
  assert.equal(textOf(await read(buildDocx(body, { labelInfo: [{ id: ID, enabled: false }] }), "word")), "LABELLED-BODY-TEXT");
  assert.equal(textOf(await read(buildDocx(body, { labelInfo: [{ id: ID, removed: true }] }), "word")), "LABELLED-BODY-TEXT");
  assert.equal(textOf(await read(buildDocx(body, { custom: [{ id: ID, enabled: false }] }), "word")), "LABELLED-BODY-TEXT");
  // A label part that cannot be read is not a document to send.
  const bombLabel = buildDocx(body, { extra: [{ name: "docMetadata/LabelInfo.xml", data: Buffer.alloc(2 * 1024 * 1024, 0x20) }] });
  const r = await read(bombLabel, "word");
  assert.deepEqual(r.kind === "unreadable" && r.reason, "a label entry that inflates past 256 KiB");
});

// ── the families and the lists ───────────────────────────────────────────────

test("the families by extension, any case; the lists are 4a's; a stored part reads as a deflated one", async () => {
  const fam: Array<[string, OfficeFamily | null]> = [
    ["a.docx", "word"], ["/x/b.DOCM", "word"], ["c.dotx", "word"], ["d.dotm", "word"],
    ["e.xlsx", "sheet"], ["f.XLSM", "sheet"], ["g.xltx", "sheet"], ["h.xltm", "sheet"],
    ["i.pptx", "slides"], ["j.pptm", "slides"], ["k.potx", "slides"], ["l.potm", "slides"],
    ["m.doc", null], ["n.md", null], [".docx", null], ["/x/.docx", null], ["o.docx.bak", null], ["docx", null], ["p.", null],
  ];
  for (const [n, f] of fam) assert.equal(officeFamily(n), f, n);
  assert.deepEqual([...OFFICE_DOCUMENT_EXTENSIONS].sort(), [...OFFICE_EXTENSIONS].sort());
  assert.equal(OFFICE_TEXT_READER_VERSION, "ooxml-text-1");
  // Deflate is what Office writes; the stored form reads the same.
  assert.equal(textOf(await read(buildDocx(["same"], { stored: true }), "word")), "same");
  // OPC part names are compared without regard to case.
  assert.equal(textOf(await read(buildZip([{ name: "WORD/Document.XML", data: docxBodyXml(["case"]) }]), "word")), "case");
});
