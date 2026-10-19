/**
 * office-text — the visible text of an Office document (OOXML: `.docx`,
 * `.xlsx`, `.pptx` and their macro and template forms), for the contents
 * model (T2) of confidentiality plan 14 (§14.4 "OOXML text", §14.13). This
 * module READS; it opens no file itself (the caller hands it a bounded range
 * reader over a file it opened safely, secret-workspace-scan.ts
 * `readOfficeFileText`), keeps nothing, and sends nothing: the arbiter's
 * contents gate decides what of the text may leave (policy-model.ts
 * `officeTextHead`, `buildContentsPayload`).
 *
 * THE ZIP. 4a's bounded reader (sensitivity-labels.ts `openOfficeZip`,
 * `readZipEntry`): the CFB magic is Purview's encrypted container
 * (`encrypted`, never read); the EOCD in the last 64 KiB + 22 bytes; Zip64
 * and multi-disk archives, a central directory over 1 MiB, an entry outside
 * the archive or encrypted, and a method other than stored or deflate are
 * `unreadable`. Every byte read counts against the caller's budget.
 *
 * WHICH PARTS (a bounded subset, in this order):
 *   - Word (`docx docm dotx dotm`): `word/document.xml`, the body. Headers,
 *     footers, footnotes, comments and text boxes kept in other parts are
 *     not read (so neither checked nor sent).
 *   - Excel (`xlsx xlsm xltx xltm`): `xl/sharedStrings.xml` (the workbook's
 *     strings, one per line), then the inline strings (`<is>`) of
 *     `xl/worksheets/sheet1.xml` … `sheet8.xml` by number. Numbers,
 *     formulas and the inline strings of later sheets are not read.
 *   - PowerPoint (`pptx pptm potx potm`): `ppt/slides/slideN.xml` by N (the
 *     file order, not `presentation.xml`'s list), at most 200 slides; a deck
 *     with more is `too-long` (not read whole). Speaker notes are not read.
 * A document without its main part (no body, no strings and no sheet, no
 * slide) is `unreadable` ("a missing part").
 *
 * SENSITIVITY LABELS FIRST. `docMetadata/LabelInfo.xml` and
 * `docProps/custom.xml` are read (4a's parsers, 4a's bounds) before any text
 * part: a file carrying ANY enabled label, in either part, mapped or not, is
 * `labelled` and its text is not read. The organization already classified
 * it; whether the label admits a model is the mapping's call, not a model's
 * (§14.13).
 *
 * THE TEXT. Visible text runs only: `<w:t>` (Word), `<a:t>` (DrawingML:
 * slides), `<t>` (Excel's strings); `<w:tab/>` a tab, `<w:br/>`, `<w:cr/>`
 * and `<a:br/>` a line break, the end of a paragraph (`</w:p>`, `</a:p>`) or
 * of a string (`</si>`, `</is>`) a newline, never more than one blank line
 * in a row. Deleted revisions (`w:delText`), field codes (`w:instrText`),
 * tab stops (`w:tabs`), phonetic runs (`rPh`), comments, processing
 * instructions and CDATA are not text. The five XML entities and numeric
 * character references are decoded (an invalid code point is dropped); no
 * other entity is expanded (no DTD is read), and C0 control characters other
 * than tab and newline are dropped. No general XML parser: one linear scan
 * that honours quoted attribute values.
 *
 * THE BOUNDS. Each part at most 4 MiB compressed and 4 MiB inflated
 * (`maxOutputLength`: a zip bomb stops there, `unreadable`), 16 MiB inflated
 * per file, 24 MiB read per file; the text at most `textMax` (default
 * 256 KiB, the walk's per-file cap for a text file): past it the document was
 * not read whole (`too-long`). The contents tier sends at most its first
 * 16 KiB, but the detectors see all of it first (§14.11: "the detectors must
 * have seen all of it before any of it leaves").
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import {
  CUSTOM_PROPS_PART, LABEL_INFO_PART, ZipBadError, ZipBudgetError, boundedRead, decodeXml, openOfficeZip, parseCustomPropsXml,
  parseLabelInfoXml, readLabelPart, readZipEntry, type EntryWords, type OfficeByteReader, type OpenZip, type ZipEntryRef,
} from "./sensitivity-labels.js";

/** The extractor's version (what it reads and how it writes the text). */
export const OFFICE_TEXT_READER_VERSION = "ooxml-text-1";

/** The bounded read's limits. */
export const OFFICE_TEXT_LIMITS = {
  /** The text, at most (UTF-8 bytes): past it, `too-long`. */
  textMax: 256 * 1024,
  /** One part's compressed bytes. */
  partInMax: 4 * 1024 * 1024,
  /** One part inflated (`maxOutputLength`). */
  partOutMax: 4 * 1024 * 1024,
  /** Every part of one file, inflated. */
  fileOutMax: 16 * 1024 * 1024,
  /** Bytes read from one file. */
  fileReadMax: 24 * 1024 * 1024,
  /** Slides read; a deck with more is `too-long`. */
  slidesMax: 200,
  /** Worksheets whose inline strings are read. */
  sheetsMax: 8,
} as const;

/** The three kinds of Office document, by extension. */
export type OfficeFamily = "word" | "sheet" | "slides";

const FAMILY: Readonly<Record<string, OfficeFamily>> = {
  docx: "word", docm: "word", dotx: "word", dotm: "word",
  xlsx: "sheet", xlsm: "sheet", xltx: "sheet", xltm: "sheet",
  pptx: "slides", pptm: "slides", potx: "slides", potm: "slides",
};

/** A file name's Office family (any case), or null. Pure. */
export function officeFamily(name: string): OfficeFamily | null {
  const dot = name.lastIndexOf(".");
  const slash = name.lastIndexOf("/");
  if (dot <= slash + 1 || dot === name.length - 1) return null;
  return FAMILY[name.slice(dot + 1).toLowerCase()] ?? null;
}

export const WORD_BODY_PART = "word/document.xml";
export const SHARED_STRINGS_PART = "xl/sharedstrings.xml";
const SHEET_RE = /^xl\/worksheets\/sheet([1-9][0-9]{0,4})\.xml$/;
const SLIDE_RE = /^ppt\/slides\/slide([1-9][0-9]{0,4})\.xml$/;

export type OfficeTextRead =
  /** The document's text (never empty), and how many parts it came from. */
  | { kind: "text"; text: string; parts: number; bytes: number }
  /** An enabled sensitivity label: the text was not read. */
  | { kind: "labelled"; bytes: number }
  /** Purview's encrypted container (an OLE compound file): not read. */
  | { kind: "encrypted"; bytes: number }
  | { kind: "unreadable"; reason: string; bytes: number }
  /** More text than `textMax`, or more slides than read: not read whole. */
  | { kind: "too-long"; bytes: number }
  /** The caller's byte budget ran out first. */
  | { kind: "over-budget"; bytes: number };

const TEXT_WORDS: EntryWords = {
  overSize: "a text part over its size limit",
  bomb: "a text part that inflates past its limit",
  inflate: "a text part that cannot be inflated",
};

class TooLong extends Error {}

/**
 * Read the visible text of one OOXML file of `family` through `reader`,
 * reading at most `maxBytes` (and never more than `fileReadMax`). Never
 * throws: what cannot be read is `unreadable` with a short reason (no file
 * text in it).
 */
export async function readOfficeText(
  reader: OfficeByteReader,
  family: OfficeFamily,
  opts: { maxBytes?: number; textMax?: number } = {},
): Promise<OfficeTextRead> {
  const r = boundedRead(reader, Math.min(opts.maxBytes ?? Number.POSITIVE_INFINITY, OFFICE_TEXT_LIMITS.fileReadMax));
  const textMax = opts.textMax ?? OFFICE_TEXT_LIMITS.textMax;
  try {
    const zip = await openOfficeZip(r, (name) => name === LABEL_INFO_PART || name === CUSTOM_PROPS_PART || isTextPart(family, name));
    if (zip === "encrypted") return { kind: "encrypted", bytes: r.bytes() };

    // A sensitivity label, enabled in either part, ends the read.
    const info = zip.entries.get(LABEL_INFO_PART);
    if (info && parseLabelInfoXml(await readLabelPart(r, zip, info)).some((l) => l.enabled)) return { kind: "labelled", bytes: r.bytes() };
    const custom = zip.entries.get(CUSTOM_PROPS_PART);
    if (custom && parseCustomPropsXml(await readLabelPart(r, zip, custom)).some((l) => l.enabled)) return { kind: "labelled", bytes: r.bytes() };

    const plan = textParts(family, zip);
    if (plan === "too-many") return { kind: "too-long", bytes: r.bytes() };
    if (plan.length === 0) return { kind: "unreadable", reason: "a missing part", bytes: r.bytes() };

    const sink = new TextSink(textMax);
    let inflated = 0;
    for (const part of plan) {
      const left = OFFICE_TEXT_LIMITS.fileOutMax - inflated;
      if (left <= 0) throw new TooLong();
      const raw = await readZipEntry(r, zip, part.entry, { inMax: OFFICE_TEXT_LIMITS.partInMax, outMax: Math.min(OFFICE_TEXT_LIMITS.partOutMax, left) }, TEXT_WORDS);
      inflated += raw.length;
      if (!sink.gap() || !extractXmlText(decodeXml(raw), part.mode, sink)) throw new TooLong();
    }
    const text = sink.done();
    if (text === "") return { kind: "unreadable", reason: "no text", bytes: r.bytes() };
    return { kind: "text", text, parts: plan.length, bytes: r.bytes() };
  } catch (err) {
    if (err instanceof TooLong) return { kind: "too-long", bytes: r.bytes() };
    if (err instanceof ZipBudgetError) return { kind: "over-budget", bytes: r.bytes() };
    if (err instanceof ZipBadError) return { kind: "unreadable", reason: err.message, bytes: r.bytes() };
    return { kind: "unreadable", reason: "the file could not be read", bytes: r.bytes() };
  }
}

function isTextPart(family: OfficeFamily, name: string): boolean {
  if (family === "word") return name === WORD_BODY_PART;
  if (family === "sheet") return name === SHARED_STRINGS_PART || SHEET_RE.test(name);
  return SLIDE_RE.test(name);
}

export type XmlMode = "word" | "slide" | "shared" | "sheet";

/** The parts to read, in order; `too-many` for a deck past `slidesMax`. */
function textParts(family: OfficeFamily, zip: OpenZip): Array<{ entry: ZipEntryRef; mode: XmlMode }> | "too-many" {
  const numbered = (re: RegExp): Array<{ n: number; name: string }> => {
    const out: Array<{ n: number; name: string }> = [];
    for (const name of zip.entries.keys()) {
      const m = re.exec(name);
      if (m) out.push({ n: Number(m[1]), name });
    }
    return out.sort((a, b) => a.n - b.n);
  };
  if (family === "word") {
    const body = zip.entries.get(WORD_BODY_PART);
    return body ? [{ entry: body, mode: "word" }] : [];
  }
  if (family === "slides") {
    const slides = numbered(SLIDE_RE);
    if (slides.length > OFFICE_TEXT_LIMITS.slidesMax) return "too-many";
    return slides.map((s) => ({ entry: zip.entries.get(s.name)!, mode: "slide" as const }));
  }
  const parts: Array<{ entry: ZipEntryRef; mode: XmlMode }> = [];
  const shared = zip.entries.get(SHARED_STRINGS_PART);
  if (shared) parts.push({ entry: shared, mode: "shared" });
  for (const s of numbered(SHEET_RE).slice(0, OFFICE_TEXT_LIMITS.sheetsMax)) parts.push({ entry: zip.entries.get(s.name)!, mode: "sheet" });
  return parts;
}

// ── The text, by one linear scan ─────────────────────────────────────────────

/** Collects the text up to `max` UTF-8 bytes; at most one blank line in a
 *  row; no leading or trailing blank lines. */
export class TextSink {
  private readonly parts: string[] = [];
  private bytes = 0;
  /** Newlines at the end of what is kept (at most 2 counted). */
  private nl = 0;
  /** Newlines owed before the next text (a break is written only when text
   *  follows it, so a trailing break costs nothing). */
  private pending = 0;

  constructor(private readonly max: number) {}

  /** Text as found (entities already decoded). False: past the cap. */
  text(s: string): boolean {
    const clean = s.replace(CONTROL_RE, "");
    if (clean === "") return true;
    if (/^\n+$/.test(clean)) return this.newline(clean.length >= 2 ? 2 : 1);
    const owe = this.bytes === 0 ? 0 : Math.max(0, this.pending - this.nl);
    const add = owe + Buffer.byteLength(clean, "utf8");
    if (this.bytes + add > this.max) return false;
    this.bytes += add;
    if (owe > 0) this.parts.push("\n".repeat(owe));
    this.parts.push(clean);
    this.pending = 0;
    this.nl = Math.min(2, /\n*$/.exec(clean)![0].length);
    return true;
  }

  /** A structural break: a line (`n` 1) or a paragraph gap (`n` 2). */
  newline(n: 1 | 2 = 1): boolean {
    this.pending = Math.max(this.pending, n);
    return true;
  }

  /** Between parts: a paragraph gap. */
  gap(): boolean {
    return this.newline(2);
  }

  done(): string {
    return this.parts.join("").replace(/^\n+/, "").replace(/\s+$/u, "");
  }
}

/** C0 controls other than tab, newline and carriage return, and DEL. */
const CONTROL_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;

const ENTITY_RE = /&(?:(lt|gt|amp|quot|apos)|#([0-9]{1,7})|#[xX]([0-9a-fA-F]{1,6}));/g;
const NAMED: Readonly<Record<string, string>> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };

/** An XML 1.0 character (tab, newline, CR, and the ranges the spec allows). */
function xmlChar(cp: number): boolean {
  return cp === 0x9 || cp === 0xa || cp === 0xd || (cp >= 0x20 && cp <= 0xd7ff) || (cp >= 0xe000 && cp <= 0xfffd) || (cp >= 0x10000 && cp <= 0x10ffff);
}

/** The five XML entities and numeric character references, decoded in one
 *  pass (`&amp;lt;` is `&lt;`); an invalid code point is dropped; any other
 *  `&` is kept as written (no DTD, no other entity). Pure. */
export function decodeXmlEntities(s: string): string {
  if (!s.includes("&")) return s;
  return s.replace(ENTITY_RE, (_all, name: string | undefined, dec: string | undefined, hex: string | undefined) => {
    if (name !== undefined) return NAMED[name]!;
    const cp = dec !== undefined ? Number(dec) : parseInt(hex!, 16);
    return xmlChar(cp) ? String.fromCodePoint(cp) : "";
  });
}

/**
 * The visible text of one OOXML part into `sink` (see the module comment for
 * what counts as text in each mode). False when the sink is full. Pure.
 */
export function extractXmlText(xml: string, mode: XmlMode, sink: TextSink): boolean {
  const n = xml.length;
  let i = 0;
  let inText = 0; // inside a text element (`t`)
  let skip = 0; // inside `tabs` (Word) or `rPh` (Excel strings)
  let inIs = 0; // inside an inline string (Excel sheets)
  while (i < n) {
    const lt = xml.indexOf("<", i);
    const end = lt < 0 ? n : lt;
    if (end > i && inText > 0 && skip === 0 && (mode !== "sheet" || inIs > 0)) {
      if (!sink.text(decodeXmlEntities(xml.slice(i, end)))) return false;
    }
    if (lt < 0) break;
    if (xml.startsWith("<!--", lt)) { const c = xml.indexOf("-->", lt + 4); i = c < 0 ? n : c + 3; continue; }
    if (xml.startsWith("<![CDATA[", lt)) { const c = xml.indexOf("]]>", lt + 9); i = c < 0 ? n : c + 3; continue; }
    // The tag's end: the first `>` outside a quoted attribute value.
    let j = lt + 1;
    let q = 0;
    for (; j < n; j++) {
      const c = xml.charCodeAt(j);
      if (q !== 0) { if (c === q) q = 0; }
      else if (c === 0x22 || c === 0x27) q = c;
      else if (c === 0x3e) break;
    }
    if (j >= n) break;
    const tag = xml.slice(lt + 1, j);
    i = j + 1;
    const first = tag.charCodeAt(0);
    if (first === 0x3f || first === 0x21) continue; // `<?…?>`, `<!…>`
    const closing = first === 0x2f;
    const selfClosing = !closing && tag.endsWith("/");
    const nameEnd = tag.search(/[\s/]/);
    const raw = closing ? tag.slice(1).trim() : nameEnd < 0 ? tag : tag.slice(0, nameEnd);
    const local = raw.slice(raw.lastIndexOf(":") + 1);
    if (closing) {
      if (local === "t") inText = Math.max(0, inText - 1);
      else if ((local === "tabs" && mode === "word") || (local === "rPh" && mode === "shared")) skip = Math.max(0, skip - 1);
      else if (local === "p" && (mode === "word" || mode === "slide")) { if (!sink.newline(1)) return false; }
      else if (local === "si" && mode === "shared") { if (!sink.newline(1)) return false; }
      else if (local === "is" && mode === "sheet") { inIs = Math.max(0, inIs - 1); if (!sink.newline(1)) return false; }
      continue;
    }
    if (local === "t") { if (!selfClosing) inText++; continue; }
    if (local === "tabs" && mode === "word") { if (!selfClosing) skip++; continue; }
    if (local === "rPh" && mode === "shared") { if (!selfClosing) skip++; continue; }
    if (local === "is" && mode === "sheet") { if (!selfClosing) inIs++; continue; }
    if (skip > 0) continue;
    if (local === "tab" && mode === "word") { if (!sink.text("\t")) return false; continue; }
    if ((local === "br" || local === "cr") && (mode === "word" || mode === "slide")) { if (!sink.text("\n")) return false; continue; }
  }
  return true;
}
