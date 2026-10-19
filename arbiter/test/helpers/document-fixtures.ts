/**
 * document-fixtures — PDF and Office personal documents built at run time
 * for the content tier's PDF and Office reader (secret-discovery.md §2.8;
 * arbiter/policy/document-text.ts, pdf-text.ts): a PDF of placed text (a
 * simple Helvetica font, or a composite Identity-H font with a ToUnicode
 * CMap; `TJ` arrays with kerning; compressed or not; objects in an object
 * stream; RC4 or AES-128 encryption with the empty user password, or a user
 * password; a scanned page; form fields), a `.docx` with a table, an
 * `.xlsx` with money and date formats, an `.odt` and an `.ods`. Every value
 * is invented; nothing is a real person's. Test-only.
 */
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { deflateSync } from "node:zlib";

import { buildZip, xmlEscape, type ZipEntryInput } from "./office-zip.js";

// ── PDF ──────────────────────────────────────────────────────────────────────

/** One string placed on a page (PDF user space: y up). */
export interface PdfItem { x: number; y: number; text: string; size?: number }

export interface PdfOptions {
  /** FlateDecode content streams (default true). */
  compress?: boolean;
  /** A composite font (Type0, Identity-H, ToUnicode) instead of Helvetica. */
  type0?: boolean;
  /** Each item as a `TJ` array, its words apart by kerning (-300). */
  tj?: boolean;
  /** The fonts, pages and contents inside an object stream. */
  objStm?: boolean;
  /** Encryption with the empty user password (`rc4`: R3 128-bit; `aes`:
   *  V4 AESV2), or one needing `password` (R3, RC4). */
  encrypt?: "rc4" | "aes" | "password";
  /** A page that is only an image (a scan). */
  scanned?: boolean;
  /** Filled-in form fields (`TU`, `V`). */
  fields?: ReadonlyArray<{ tu: string; v: string }>;
}

const PAD = Buffer.from("28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A", "hex");

function rc4(key: Buffer, data: Buffer): Buffer {
  const S = Array.from({ length: 256 }, (_, i) => i);
  for (let i = 0, j = 0; i < 256; i++) { j = (j + S[i]! + key[i % key.length]!) & 255; [S[i], S[j]] = [S[j]!, S[i]!]; }
  const out = Buffer.alloc(data.length);
  for (let k = 0, i = 0, j = 0; k < data.length; k++) {
    i = (i + 1) & 255; j = (j + S[i]!) & 255; [S[i], S[j]] = [S[j]!, S[i]!];
    out[k] = data[k]! ^ S[(S[i]! + S[j]!) & 255]!;
  }
  return out;
}
const md5 = (...p: Buffer[]): Buffer => { const h = createHash("md5"); for (const b of p) h.update(b); return h.digest(); };

/** A literal string's body for WinAnsi text (ASCII here). */
function lit(s: string): string {
  return s.replace(/[\\()]/g, "\\$&");
}

/** A PDF of `pages` (each a list of placed strings). */
export function buildPdf(pages: ReadonlyArray<readonly PdfItem[]>, o: PdfOptions = {}): Buffer {
  const compress = o.compress !== false;
  // objects: 1 catalog, 2 pages, 3 font, 4 ToUnicode (type0) / unused, then pages
  const objs: Array<{ dict: string; stream?: Buffer }> = [];
  const glyph = (ch: string): number => ch.charCodeAt(0) + 100; // a composite font's glyph ids
  const pageIds: number[] = [];
  let next = 6;
  const pageObjs: Array<{ id: number; content: number }> = [];
  for (let i = 0; i < pages.length; i++) { pageObjs.push({ id: next, content: next + 1 }); pageIds.push(next); next += 2; }
  const imageId = next++;
  const fieldIds = (o.fields ?? []).map(() => next++);
  objs[1] = { dict: `<< /Type /Catalog /Pages 2 0 R${o.fields ? ` /AcroForm << /Fields [${fieldIds.map((f) => `${f} 0 R`).join(" ")}] >>` : ""} >>` };
  objs[2] = { dict: `<< /Type /Pages /Kids [${pageIds.map((p) => `${p} 0 R`).join(" ")}] /Count ${pages.length} >>` };
  if (o.type0) {
    objs[3] = { dict: `<< /Type /Font /Subtype /Type0 /BaseFont /DemoSans /Encoding /Identity-H /DescendantFonts [5 0 R] /ToUnicode 4 0 R >>` };
    const cmap = [
      "/CIDInit /ProcSet findresource begin", "12 dict begin", "begincmap", "1 begincodespacerange", "<0000> <FFFF>", "endcodespacerange",
      "1 beginbfrange", `<${(32 + 100).toString(16).padStart(4, "0")}> <${(126 + 100).toString(16).padStart(4, "0")}> <0020>`, "endbfrange",
      "1 beginbfchar", "<0300> <00E9>", "endbfchar", "endcmap", "CMapName currentdict /CMap defineresource pop", "end", "end",
    ].join("\n");
    objs[4] = { dict: "<< >>", stream: Buffer.from(cmap, "latin1") };
    objs[5] = { dict: `<< /Type /Font /Subtype /CIDFontType2 /BaseFont /DemoSans /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /DW 556 >>` };
  } else {
    objs[3] = { dict: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>" };
    objs[4] = { dict: "<< /Unused true >>" };
    objs[5] = { dict: "<< /Unused true >>" };
  }
  const show = (text: string): string => {
    if (o.type0) {
      const hex = (s: string): string => [...s].map((ch) => (ch === "é" ? 0x300 : glyph(ch)).toString(16).padStart(4, "0")).join("");
      if (o.tj) return `[${text.split(" ").map((w) => `<${hex(w)}>`).join(" -300 ")}] TJ`;
      return `<${hex(text)}> Tj`;
    }
    if (o.tj) return `[${text.split(" ").map((w) => `(${lit(w)})`).join(" -300 ")}] TJ`;
    return `(${lit(text)}) Tj`;
  };
  pages.forEach((items, i) => {
    const body: string[] = [];
    if (o.scanned) body.push("q 612 0 0 792 0 0 cm /Im1 Do Q");
    for (const it of items) body.push(`BT /F1 ${it.size ?? 10} Tf ${it.x} ${it.y} Td ${show(it.text)} ET`);
    const raw = Buffer.from(body.join("\n"), "latin1");
    objs[pageObjs[i]!.id] = {
      dict: `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> /XObject << /Im1 ${imageId} 0 R >> >> /Contents ${pageObjs[i]!.content} 0 R >>`,
    };
    objs[pageObjs[i]!.content] = { dict: compress ? "<< /Filter /FlateDecode >>" : "<< >>", stream: compress ? deflateSync(raw) : raw };
  });
  objs[imageId] = { dict: "<< /Type /XObject /Subtype /Image /Width 8 /Height 8 /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /DCTDecode >>", stream: randomBytes(64) };
  (o.fields ?? []).forEach((f, k) => { objs[fieldIds[k]!] = { dict: `<< /FT /Tx /T (f${k}) /TU (${lit(f.tu)}) /V (${lit(f.v)}) >>` }; });

  // Encryption.
  const id0 = Buffer.from("0123456789abcdef0123456789abcdef", "hex");
  let key: Buffer | null = null;
  let aes = false;
  let encDict = "";
  if (o.encrypt) {
    aes = o.encrypt === "aes";
    const O = Buffer.alloc(32, 0x41);
    const P = -3904;
    const p = Buffer.alloc(4);
    p.writeInt32LE(P, 0);
    const userPw = o.encrypt === "password" ? Buffer.from("secret-user-pw", "latin1") : Buffer.alloc(0);
    const padded = Buffer.concat([userPw, PAD]).subarray(0, 32);
    key = md5(padded, O, p, id0).subarray(0, 16);
    for (let i = 0; i < 50; i++) key = md5(key).subarray(0, 16);
    let x = rc4(key, md5(PAD, id0));
    for (let i = 1; i <= 19; i++) x = rc4(Buffer.from(key.map((b) => b ^ i)), x);
    const U = Buffer.concat([x, Buffer.alloc(16)]);
    encDict = aes
      ? `<< /Filter /Standard /V 4 /R 4 /Length 128 /CF << /StdCF << /CFM /AESV2 /AuthEvent /DocOpen /Length 16 >> >> /StmF /StdCF /StrF /StdCF /O <${O.toString("hex")}> /U <${U.toString("hex")}> /P ${P} >>`
      : `<< /Filter /Standard /V 2 /R 3 /Length 128 /O <${O.toString("hex")}> /U <${U.toString("hex")}> /P ${P} >>`;
  }
  const encrypt = (num: number, data: Buffer): Buffer => {
    if (!key) return data;
    const ext = Buffer.from([num & 255, (num >> 8) & 255, (num >> 16) & 255, 0, 0]);
    const k = md5(key, ext, aes ? Buffer.from("sAlT") : Buffer.alloc(0)).subarray(0, 16);
    if (!aes) return rc4(k, data);
    const iv = randomBytes(16);
    const c = createCipheriv("aes-128-cbc", k, iv);
    return Buffer.concat([iv, c.update(data), c.final()]);
  };
  // A form field's strings are encrypted too.
  if (key) {
    (o.fields ?? []).forEach((f, k) => {
      const num = fieldIds[k]!;
      const enc = (s: string): string => `<${encrypt(num, Buffer.from(s, "latin1")).toString("hex")}>`;
      objs[num] = { dict: `<< /FT /Tx /T ${enc(`f${k}`)} /TU ${enc(f.tu)} /V ${enc(f.v)} >>` };
    });
  }

  const chunks: Buffer[] = [Buffer.from("%PDF-1.5\n%\xe2\xe3\xcf\xd3\n", "latin1")];
  let len = chunks[0]!.length;
  const put = (s: string | Buffer): void => { const b = typeof s === "string" ? Buffer.from(s, "latin1") : s; chunks.push(b); len += b.length; };
  const offsets: number[] = [];
  const inStm = new Set<number>();
  if (o.objStm) for (const n of [3, 4, 5, ...pageIds]) if (!objs[n]!.stream) inStm.add(n);
  let stmId = 0;
  if (inStm.size > 0) {
    stmId = objs.length;
    const parts: string[] = [];
    const head: string[] = [];
    let off = 0;
    for (const n of inStm) { const body = `${objs[n]!.dict}\n`; head.push(`${n} ${off}`); parts.push(body); off += body.length; }
    const headStr = `${head.join(" ")}\n`;
    const data = Buffer.from(headStr + parts.join(""), "latin1");
    objs[stmId] = { dict: `<< /Type /ObjStm /N ${inStm.size} /First ${headStr.length} /Filter /FlateDecode >>`, stream: deflateSync(data) };
  }
  let encId = 0;
  if (o.encrypt) { encId = objs.length; objs[encId] = { dict: encDict }; }
  for (let n = 1; n < objs.length; n++) {
    if (inStm.has(n) || !objs[n]) continue;
    offsets[n] = len;
    const ob = objs[n]!;
    if (ob.stream) {
      const data = n === encId ? ob.stream : encrypt(n, ob.stream);
      const dict = ob.dict.replace(/>>\s*$/, ` /Length ${data.length} >>`);
      put(`${n} 0 obj\n${dict}\nstream\n`);
      put(data);
      put("\nendstream\nendobj\n");
    } else {
      put(`${n} 0 obj\n${ob.dict}\nendobj\n`);
    }
  }
  const xref = len;
  put(`xref\n0 ${objs.length}\n0000000000 65535 f \n`);
  for (let n = 1; n < objs.length; n++) put(`${String(offsets[n] ?? 0).padStart(10, "0")} 00000 ${offsets[n] !== undefined ? "n" : "f"} \n`);
  put(`trailer\n<< /Size ${objs.length} /Root 1 0 R /ID [<${id0.toString("hex")}> <${id0.toString("hex")}>]${encId ? ` /Encrypt ${encId} 0 R` : ""} >>\nstartxref\n${xref}\n%%EOF\n`);
  return Buffer.concat(chunks);
}

/** A statement's page, laid out as a bank's PDF lays it out: a title,
 *  label and value columns, a transactions table. */
export function statementPdfItems(v: { account: string; holder: string; iban?: string; closing: string }): PdfItem[] {
  const items: PdfItem[] = [
    { x: 50, y: 740, text: "Maple Bank - Statement, September 2026", size: 16 },
    { x: 50, y: 710, text: "Account number" }, { x: 200, y: 710, text: v.account },
    { x: 50, y: 696, text: "Account holder" }, { x: 200, y: 696, text: v.holder },
  ];
  if (v.iban) items.push({ x: 50, y: 682, text: "IBAN" }, { x: 200, y: 682, text: v.iban });
  const rows: Array<[string, string, string, string]> = [
    ["Date", "Description", "Amount", "Balance"],
    ["2026-09-01", "Salary ACME Ltd", "+3,200.00", "4,646.47"],
    ["2026-09-03", "Rent", "-1,250.00", "3,396.47"],
    ["2026-09-12", "Groceries", "-84.10", "3,312.37"],
  ];
  rows.forEach((r, i) => {
    const y = 650 - 14 * i;
    items.push({ x: 50, y, text: r[0] }, { x: 150, y, text: r[1] }, { x: 400, y, text: r[2] }, { x: 480, y, text: r[3] });
  });
  items.push({ x: 50, y: 580, text: "Opening balance" }, { x: 200, y: 580, text: "1,446.47" });
  items.push({ x: 50, y: 566, text: "Closing balance" }, { x: 200, y: 566, text: v.closing });
  return items;
}

// ── Office ───────────────────────────────────────────────────────────────────

const W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const S_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

function wp(text: string): string {
  return `<w:p><w:r><w:t xml:space="preserve">${xmlEscape(text)}</w:t></w:r></w:p>`;
}

/** A `.docx` of paragraphs and tables (a table: rows of cells). */
export function buildDocxDocument(blocks: ReadonlyArray<string | ReadonlyArray<readonly string[]>>): Buffer {
  const body = blocks.map((b) => typeof b === "string" ? wp(b)
    : `<w:tbl><w:tblPr/>${b.map((row) => `<w:tr>${row.map((c) => `<w:tc><w:tcPr/>${wp(c)}</w:tc>`).join("")}</w:tr>`).join("")}</w:tbl>`).join("");
  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<w:document xmlns:w="${W_NS}" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"><w:body>${body}<w:p><w:r><w:delText>DELETED-NOT-TEXT</w:delText></w:r></w:p><w:sectPr/></w:body></w:document>`;
  return buildZip([
    { name: "[Content_Types].xml", data: `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>` },
    { name: "word/document.xml", data: xml },
  ]);
}

/** One spreadsheet cell: text (a shared string), or a number with a
 *  format (`money`: `#,##0.00`; `date`: `yyyy-mm-dd`; none: as stored). */
export type XCell = string | { n: number; fmt?: "money" | "date" };

/** A `.xlsx` of one sheet of `rows`. */
export function buildXlsxDocument(rows: ReadonlyArray<readonly XCell[]>): Buffer {
  const strings: string[] = [];
  const idx = new Map<string, number>();
  const col = (c: number): string => String.fromCharCode(65 + c);
  const cells = rows.map((row, r) => `<row r="${r + 1}">${row.map((v, c) => {
    const ref = `${col(c)}${r + 1}`;
    if (typeof v === "string") {
      let i = idx.get(v);
      if (i === undefined) { i = strings.length; strings.push(v); idx.set(v, i); }
      return `<c r="${ref}" t="s"><v>${i}</v></c>`;
    }
    const s = v.fmt === "money" ? 1 : v.fmt === "date" ? 2 : 0;
    return `<c r="${ref}" s="${s}"><v>${v.n}</v></c>`;
  }).join("")}</row>`).join("");
  const styles = `<?xml version="1.0"?><styleSheet xmlns="${S_NS}"><numFmts count="1"><numFmt numFmtId="164" formatCode="yyyy\\-mm\\-dd"/></numFmts><cellXfs count="3"><xf numFmtId="0"/><xf numFmtId="4" applyNumberFormat="1"/><xf numFmtId="164" applyNumberFormat="1"/></cellXfs></styleSheet>`;
  const shared = `<?xml version="1.0"?><sst xmlns="${S_NS}">${strings.map((s) => `<si><t xml:space="preserve">${xmlEscape(s)}</t><rPh><t>PHONETIC</t></rPh></si>`).join("")}</sst>`;
  return buildZip([
    { name: "[Content_Types].xml", data: `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>` },
    { name: "xl/sharedStrings.xml", data: shared },
    { name: "xl/styles.xml", data: styles },
    { name: "xl/worksheets/sheet1.xml", data: `<?xml version="1.0"?><worksheet xmlns="${S_NS}"><sheetData>${cells}</sheetData></worksheet>` },
  ]);
}

const ODF_NS = 'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0"';

function odfZip(mime: string, content: string, encrypted = false): Buffer {
  const entries: ZipEntryInput[] = [
    { name: "mimetype", data: mime, method: 0 },
    { name: "META-INF/manifest.xml", data: `<?xml version="1.0"?><manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"><manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml">${encrypted ? "<manifest:encryption-data manifest:checksum-type=\"SHA1/1K\"/>" : ""}</manifest:file-entry></manifest:manifest>` },
    { name: "content.xml", data: content },
  ];
  return buildZip(entries);
}

function odfTable(rows: ReadonlyArray<readonly string[]>): string {
  return `<table:table table:name="Sheet1">${rows.map((r) => `<table:table-row>${r.map((c) => c === "" ? "<table:table-cell/>" : `<table:table-cell office:value-type="string"><text:p>${xmlEscape(c)}</text:p></table:table-cell>`).join("")}</table:table-row>`).join("")}<table:table-row table:number-rows-repeated="1048000"><table:table-cell table:number-columns-repeated="1024"/></table:table-row></table:table>`;
}

/** An `.odt` of paragraphs and tables. */
export function buildOdtDocument(blocks: ReadonlyArray<string | ReadonlyArray<readonly string[]>>, opts: { encrypted?: boolean } = {}): Buffer {
  const body = blocks.map((b) => typeof b === "string" ? `<text:p>${xmlEscape(b).replace(/  /g, " <text:s/>")}</text:p>` : odfTable(b)).join("");
  const content = `<?xml version="1.0" encoding="UTF-8"?><office:document-content ${ODF_NS}><office:body><office:text>${body}<text:p>kept<text:note><text:note-body><text:p>NOTE-NOT-TEXT</text:p></text:note-body></text:note></text:p></office:text></office:body></office:document-content>`;
  return odfZip("application/vnd.oasis.opendocument.text", content, opts.encrypted);
}

/** An `.ods` of one sheet of `rows`. */
export function buildOdsDocument(rows: ReadonlyArray<readonly string[]>): Buffer {
  const content = `<?xml version="1.0" encoding="UTF-8"?><office:document-content ${ODF_NS}><office:body><office:spreadsheet>${odfTable(rows)}</office:spreadsheet></office:body></office:document-content>`;
  return odfZip("application/vnd.oasis.opendocument.spreadsheet", content);
}
