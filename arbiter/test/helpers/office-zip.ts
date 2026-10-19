/**
 * office-zip — build OOXML (zip) fixtures at run time for the sensitivity
 * label tests (confidentiality plan 14 §14.1, §14.7 "4a"): a document with
 * `docMetadata/LabelInfo.xml`, with the older `docProps/custom.xml`
 * properties, both, a disabled label, another tenant's label, a Purview
 * encrypted container (an OLE compound file), a zip bomb and a Zip64
 * archive. For the contents model's Office text (§14.13): a `.docx`,
 * `.xlsx` and `.pptx` of given text (`buildDocx`, `buildXlsx`,
 * `buildPptx`), with or without labels, parts left out or replaced. Nothing
 * here is committed as a binary: every fixture is built by the test (or the
 * T2 eval runner) that uses it. Test-only.
 */
import { crc32, deflateRawSync } from "node:zlib";

export interface ZipEntryInput {
  name: string;
  data: Buffer | string;
  /** 0 stored, 8 deflate (default). */
  method?: 0 | 8;
  /** General-purpose flags (bit 0: encrypted). */
  flags?: number;
}

export interface ZipOptions {
  /** An archive comment after the EOCD. */
  comment?: string;
  /** Write 0xFFFF / 0xFFFFFFFF in the EOCD (the Zip64 markers). */
  zip64Markers?: boolean;
  /** Put a Zip64 EOCD locator right before the EOCD. */
  zip64Locator?: boolean;
  /** Claim the archive spans disks. */
  multiDisk?: boolean;
}

/** A minimal, valid zip archive (PKWARE APPNOTE 4.3) of `entries`. */
export function buildZip(entries: readonly ZipEntryInput[], opts: ZipOptions = {}): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const raw = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data, "utf8");
    const method = e.method ?? 8;
    const body = method === 8 ? deflateRawSync(raw) : raw;
    const name = Buffer.from(e.name, "utf8");
    const crc = crc32(raw) >>> 0;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(e.flags ?? 0, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(body.length, 18);
    lh.writeUInt32LE(raw.length, 22);
    lh.writeUInt16LE(name.length, 26);
    lh.writeUInt16LE(0, 28);
    locals.push(lh, name, body);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(e.flags ?? 0, 8);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(body.length, 20);
    ch.writeUInt32LE(raw.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(offset, 42);
    centrals.push(ch, name);
    offset += 30 + name.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const comment = Buffer.from(opts.comment ?? "", "utf8");
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(opts.multiDisk ? 1 : 0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(opts.zip64Markers ? 0xffff : entries.length, 8);
  eocd.writeUInt16LE(opts.zip64Markers ? 0xffff : entries.length, 10);
  eocd.writeUInt32LE(opts.zip64Markers ? 0xffffffff : cd.length, 12);
  eocd.writeUInt32LE(opts.zip64Markers ? 0xffffffff : offset, 16);
  eocd.writeUInt16LE(comment.length, 20);
  const locator = Buffer.alloc(opts.zip64Locator ? 20 : 0);
  if (opts.zip64Locator) locator.writeUInt32LE(0x07064b50, 0);
  return Buffer.concat([...locals, cd, locator, eocd, comment]);
}

export interface FixtureLabel {
  id: string;
  site?: string | null;
  enabled?: boolean;
  removed?: boolean;
  /** custom.xml only: the display name Office writes (`MSIP_Label_…_Name`);
   *  a reader must never keep it. */
  name?: string;
}

/** `docMetadata/LabelInfo.xml` as Office writes it (GUIDs in braces). */
export function labelInfoXml(labels: readonly FixtureLabel[]): string {
  const els = labels.map((l) =>
    `<clbl:label id="{${l.id}}" enabled="${l.enabled === false ? 0 : 1}" method="Standard"${l.site ? ` siteId="{${l.site}}"` : ""} contentBits="0" removed="${l.removed ? 1 : 0}" />`,
  ).join("");
  return `<?xml version="1.0" encoding="utf-8" standalone="yes"?>\r\n<clbl:labelList xmlns:clbl="http://schemas.microsoft.com/office/2020/mipLabelMetadata">${els}</clbl:labelList>`;
}

/** `docProps/custom.xml` with the older `MSIP_Label_<guid>_*` properties. */
export function customPropsXml(labels: readonly FixtureLabel[], extra: Record<string, string> = {}): string {
  let pid = 2;
  const prop = (name: string, value: string): string =>
    `<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="${pid++}" name="${name}"><vt:lpwstr>${value}</vt:lpwstr></property>`;
  const props: string[] = [];
  for (const l of labels) {
    props.push(prop(`MSIP_Label_${l.id}_Enabled`, l.enabled === false ? "false" : "true"));
    if (l.site) props.push(prop(`MSIP_Label_${l.id}_SiteId`, l.site));
    if (l.name) props.push(prop(`MSIP_Label_${l.id}_Name`, l.name));
    props.push(prop(`MSIP_Label_${l.id}_Method`, "Standard"));
  }
  for (const [k, v] of Object.entries(extra)) props.push(prop(k, v));
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">${props.join("")}</Properties>`;
}

export interface OfficeFixture {
  /** Labels in `docMetadata/LabelInfo.xml` (omit: no such part). */
  labelInfo?: readonly FixtureLabel[];
  /** Labels in `docProps/custom.xml` (omit: no such part). */
  custom?: readonly FixtureLabel[];
  /** The document's own text (a canary, in `word/document.xml`). */
  body?: string;
  /** Store the document part uncompressed, so its text is in the file's
   *  bytes as written (a canary a raw `cat` shows). */
  stored?: boolean;
  /** Replace the LabelInfo part's bytes (a bomb, garbage). */
  labelInfoRaw?: Buffer;
  zip?: ZipOptions;
}

/** A small `.docx`-shaped archive with the parts asked for. */
export function buildOfficeFile(f: OfficeFixture = {}): Buffer {
  const entries: ZipEntryInput[] = [
    { name: "[Content_Types].xml", data: `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>` },
    { name: "word/document.xml", data: `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>${f.body ?? "hello"}</w:t></w:r></w:p></w:body></w:document>`, ...(f.stored ? { method: 0 as const } : {}) },
  ];
  if (f.custom) entries.push({ name: "docProps/custom.xml", data: customPropsXml(f.custom) });
  if (f.labelInfoRaw) entries.push({ name: "docMetadata/LabelInfo.xml", data: f.labelInfoRaw });
  else if (f.labelInfo) entries.push({ name: "docMetadata/LabelInfo.xml", data: labelInfoXml(f.labelInfo) });
  return buildZip(entries, f.zip);
}

// ── Text documents (plan 14 §14.13: the contents model reads their text) ────

/** The five XML entities, escaped. */
export function xmlEscape(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

export interface OfficeTextFixture {
  /** Labels in `docMetadata/LabelInfo.xml` (omit: no such part). */
  labelInfo?: readonly FixtureLabel[];
  /** Labels in `docProps/custom.xml` (omit: no such part). */
  custom?: readonly FixtureLabel[];
  /** Store every text part uncompressed. */
  stored?: boolean;
  /** Extra entries (a second body, a bomb in place of a part). */
  extra?: readonly ZipEntryInput[];
  /** Leave the main text part out (a "missing part"). */
  noMain?: boolean;
  zip?: ZipOptions;
}

const W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main";
const P_NS = "http://schemas.openxmlformats.org/presentationml/2006/main";
const S_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

function officeEntries(main: ZipEntryInput[], f: OfficeTextFixture): ZipEntryInput[] {
  const entries: ZipEntryInput[] = [
    { name: "[Content_Types].xml", data: `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>` },
    { name: "_rels/.rels", data: `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>` },
    { name: "docProps/core.xml", data: `<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>CORE-AUTHOR-NOT-TEXT</dc:creator></cp:coreProperties>` },
  ];
  if (!f.noMain) for (const m of main) entries.push(f.stored ? { ...m, method: 0 } : m);
  if (f.custom) entries.push({ name: "docProps/custom.xml", data: customPropsXml(f.custom) });
  if (f.labelInfo) entries.push({ name: "docMetadata/LabelInfo.xml", data: labelInfoXml(f.labelInfo) });
  for (const e of f.extra ?? []) entries.push(e);
  return entries;
}

/** `word/document.xml` whose body holds one paragraph per entry, each
 *  escaped into one `<w:t>` run. */
export function docxBodyXml(paragraphs: readonly string[]): string {
  const ps = paragraphs.map((p) => `<w:p><w:pPr><w:tabs><w:tab w:val="left" w:pos="720"/></w:tabs></w:pPr><w:r><w:t xml:space="preserve">${xmlEscape(p)}</w:t></w:r></w:p>`).join("");
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<w:document xmlns:w="${W_NS}"><w:body>${ps}<w:sectPr/></w:body></w:document>`;
}

/** A `.docx` (Word) of `paragraphs`, or of `body` (a raw document.xml). */
export function buildDocx(paragraphs: readonly string[], f: OfficeTextFixture & { body?: string } = {}): Buffer {
  return buildZip(officeEntries([{ name: "word/document.xml", data: f.body ?? docxBodyXml(paragraphs) }], f), f.zip);
}

/** A `.xlsx` (Excel) whose first sheet holds `rows`: every cell a shared
 *  string (with `numbers`, a cell that is a number is written as one, as
 *  Excel does), plus `inline` strings in the sheet itself. */
export function buildXlsx(rows: readonly (readonly string[])[], f: OfficeTextFixture & { inline?: readonly string[]; sheets?: number; numbers?: boolean } = {}): Buffer {
  const strings: string[] = [];
  const index = new Map<string, number>();
  const cells = rows.map((row, r) => `<row r="${r + 1}">${row.map((v, c) => {
    if (f.numbers && /^-?[0-9]+(\.[0-9]+)?$/.test(v)) return `<c r="${String.fromCharCode(65 + (c % 26))}${r + 1}"><v>${v}</v></c>`;
    let i = index.get(v);
    if (i === undefined) { i = strings.length; strings.push(v); index.set(v, i); }
    return `<c r="${String.fromCharCode(65 + (c % 26))}${r + 1}" t="s"><v>${i}</v></c>`;
  }).join("")}<c r="Z${r + 1}"><v>${r * 1000 + 7}</v><f>SUM(A1:A2)</f></c></row>`).join("");
  const inline = (f.inline ?? []).map((s, k) => `<row r="${rows.length + k + 1}"><c r="A${rows.length + k + 1}" t="inlineStr"><is><t>${xmlEscape(s)}</t></is></c></row>`).join("");
  const shared = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<sst xmlns="${S_NS}" count="${strings.length}" uniqueCount="${strings.length}">${strings.map((s) => `<si><t xml:space="preserve">${xmlEscape(s)}</t></si>`).join("")}</sst>`;
  const main: ZipEntryInput[] = [{ name: "xl/sharedStrings.xml", data: shared }];
  const sheets = Math.max(1, f.sheets ?? 1);
  for (let n = 1; n <= sheets; n++) {
    main.push({ name: `xl/worksheets/sheet${n}.xml`, data: `<?xml version="1.0"?><worksheet xmlns="${S_NS}"><sheetData>${n === 1 ? cells + inline : ""}</sheetData></worksheet>` });
  }
  return buildZip(officeEntries(main, f), f.zip);
}

/** `ppt/slides/slideN.xml` holding one DrawingML paragraph per entry. */
export function slideXml(paragraphs: readonly string[]): string {
  const ps = paragraphs.map((p) => `<a:p><a:r><a:rPr lang="en-US"/><a:t>${xmlEscape(p)}</a:t></a:r></a:p>`).join("");
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<p:sld xmlns:a="${A_NS}" xmlns:p="${P_NS}"><p:cSld><p:spTree><p:sp><p:txBody><a:bodyPr/>${ps}</p:txBody></p:sp></p:spTree></p:cSld></p:sld>`;
}

/** A `.pptx` (PowerPoint), one slide per entry of `slides`, written to the
 *  archive in the order given (`order`: the slide numbers, default 1..n). */
export function buildPptx(slides: readonly (readonly string[])[], f: OfficeTextFixture & { order?: readonly number[] } = {}): Buffer {
  const nums = f.order ?? slides.map((_, i) => i + 1);
  const main = slides.map((s, i) => ({ name: `ppt/slides/slide${nums[i]}.xml`, data: slideXml(s) }));
  return buildZip(officeEntries(main, f), f.zip);
}

/** A Purview-encrypted file: an OLE compound file (CFB) header. */
export function buildEncryptedContainer(size = 4096): Buffer {
  const b = Buffer.alloc(size);
  Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).copy(b, 0);
  // The directory entry name Purview uses, UTF-16LE, somewhere in the file.
  Buffer.from("EncryptedPackage", "utf16le").copy(b, 1024);
  return b;
}

/** A LabelInfo part that inflates to `mib` MiB of spaces (a zip bomb). */
export function bombLabelInfo(mib = 16): Buffer {
  return Buffer.alloc(mib * 1024 * 1024, 0x20);
}
