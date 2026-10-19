/**
 * document-text — the text of a personal document kept as a PDF or an Office
 * file (2026-10-19, docs/design/confidentiality/secret-discovery.md §2.8):
 * what the content tier reads to decide whether a `statement.pdf`, a
 * `payslip.docx`, a `transactions.xlsx`, a `tax-return.odt` or a
 * `results.ods` is a personal document (personal-documents.ts), and what the
 * registry twins it from (registry.ts `registeredFileValue`). Synchronous and
 * bounded: the launch walk and the registry are synchronous, and a planted
 * file must not stall either.
 *
 * ── THE FORMATS ─────────────────────────────────────────────────────────────
 *
 *   pdf        the text layer (pdf-text.ts), reading order, form fields;
 *   docx docm  `word/document.xml`: paragraphs as lines, a table row as one
 *              line of cells; headers, footers, notes, comments, deleted
 *              text and field codes are not read;
 *   xlsx xlsm  the worksheets in order (`sheet1.xml` …, at most 16): each row
 *              one line of its cells, a shared string as its text, a number
 *              as its cell format shows it where the format is a money one
 *              (`0.00`, `#,##0.00`, a currency, accounting) or a date (an
 *              ISO date), else as stored;
 *   odt ods    `content.xml`: paragraphs and headings as lines, a table row
 *              (a spreadsheet's too) as one line of cells, the cell's text
 *              as the file shows it; notes, annotations and tracked deletions
 *              are not read.
 *
 * Not read: the legacy binary formats (`.doc`, `.xls`: an OLE compound file,
 * which is also what an encrypted OOXML file is), `.pptx` and `.odp` (not
 * where a person keeps these documents), `.rtf`, `.pages`, `.numbers`. A
 * password-protected file is `encrypted` (an OOXML in its CFB container, an
 * ODF whose manifest names encryption, a PDF that needs a user password).
 *
 * ── A ROW (renderRow) ───────────────────────────────────────────────────────
 *
 * A table row, a spreadsheet row or a PDF line of separated columns is one
 * line: two cells whose first is a short label (a letter first, at most 48
 * characters, no colon but a final one) read `Label: value`, so the twin
 * keeps the label and the detectors read the pair as the Markdown tier reads
 * `Account: …`; any other row is its non-empty cells joined by ` | `.
 *
 * ── THE BOUNDS ──────────────────────────────────────────────────────────────
 *
 * A file of at most DOCUMENT_FILE_LIMITS.fileMax bytes is read (whole, into
 * memory); a zip's central directory at most 4 MiB and 10,000 entries; each
 * part inflates to at most 8 MiB and a file's parts to 32 MiB in all (a zip
 * bomb stops there, `unreadable`); the text at most `textMax` (past it,
 * `too-long`). Never throws.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference
 * origin). The XML entity decoding is office-text.ts's.
 */
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { inflateRawSync } from "node:zlib";

import { decodeXmlEntities } from "./office-text.js";
import { readPdfText } from "./pdf-text.js";

/** The formats read, by extension. */
export type DocumentFormat = "pdf" | "docx" | "xlsx" | "odt" | "ods";

const FORMAT_BY_EXT: Readonly<Record<string, DocumentFormat>> = {
  pdf: "pdf", docx: "docx", docm: "docx", xlsx: "xlsx", xlsm: "xlsx", odt: "odt", ods: "ods",
};

/** The extensions of the formats read (personal-documents.ts reads them as
 *  candidates). */
export const DOCUMENT_FILE_EXT_RE = /\.(?:pdf|docx|docm|xlsx|xlsm|odt|ods)$/i;

/** A path's document format (any case), or null. Pure. */
export function documentFormatOf(path: string): DocumentFormat | null {
  const m = /\.([A-Za-z]{3,4})$/.exec(path);
  return m ? FORMAT_BY_EXT[m[1]!.toLowerCase()] ?? null : null;
}

/** The bounds (module comment). */
export const DOCUMENT_FILE_LIMITS = {
  /** A file's bytes, at most: a statement, a payslip or a lab report is a
   *  few hundred KiB; a larger PDF is a scan or a book. */
  fileMax: 8 * 1024 * 1024,
  /** The text, at most (UTF-8 bytes): personal-documents.ts reads no more. */
  textMax: 256 * 1024,
  cdMax: 4 * 1024 * 1024,
  entriesMax: 10_000,
  partOutMax: 8 * 1024 * 1024,
  fileOutMax: 32 * 1024 * 1024,
  sheetsMax: 16,
} as const;

export type DocumentTextRead =
  | { kind: "text"; text: string }
  /** No text: a scanned PDF (images only), an empty document. */
  | { kind: "no-text" }
  /** Password-protected: not read. */
  | { kind: "encrypted" }
  | { kind: "too-long" }
  | { kind: "unreadable"; reason: string };

// ── A row ────────────────────────────────────────────────────────────────────

const ROW_LABEL_RE = /^[A-Za-z][^:|\n]{0,46}:?$/;

/** One table row's cells as one line (module comment, "A row"). Pure. */
export function renderRow(cells: readonly string[]): string {
  const c = cells.map((x) => x.replace(/\s+/g, " ").trim()).filter((x) => x !== "");
  if (c.length === 0) return "";
  if (c.length === 2 && ROW_LABEL_RE.test(c[0]!)) return `${c[0]!.replace(/\s*:$/, "")}: ${c[1]}`;
  return c.join(" | ");
}

// ── Reading a file ───────────────────────────────────────────────────────────

/**
 * The bytes of the regular file `p`, or null: not a regular file (decided on
 * `lstat` and again on the descriptor, so a FIFO is never waited on and a
 * symlink never followed), empty, larger than `max`, or unreadable.
 */
export function readDocumentBytes(p: string, max: number = DOCUMENT_FILE_LIMITS.fileMax): Buffer | null {
  let fd: number | null = null;
  try {
    const st = lstatSync(p, { throwIfNoEntry: false });
    if (!st || !st.isFile() || st.size > max || st.size === 0) return null;
    fd = openSync(p, constants.O_RDONLY | constants.O_NONBLOCK | (constants.O_NOFOLLOW ?? 0));
    const fst = fstatSync(fd);
    if (!fst.isFile() || fst.size > max || fst.size === 0) return null;
    const buf = Buffer.alloc(fst.size);
    let off = 0;
    while (off < buf.length) {
      const n = readSync(fd, buf, off, buf.length - off, off);
      if (n <= 0) break;
      off += n;
    }
    return buf.subarray(0, off);
  } catch {
    return null;
  } finally {
    if (fd !== null) try { closeSync(fd); } catch { /* closed */ }
  }
}

/** The text of the document at `path` (by its extension), or null: not a
 *  format read, unreadable, no text, encrypted, too long. */
export function documentFileText(path: string, opts: { textMax?: number } = {}): string | null {
  const format = documentFormatOf(path);
  if (format === null) return null;
  const bytes = readDocumentBytes(path);
  if (bytes === null) return null;
  const r = extractDocumentText(bytes, format, opts);
  return r.kind === "text" ? r.text : null;
}

/** The text of a document of `format` held in `bytes` (module comment).
 *  Never throws. */
export function extractDocumentText(bytes: Buffer, format: DocumentFormat, opts: { textMax?: number } = {}): DocumentTextRead {
  const textMax = opts.textMax ?? DOCUMENT_FILE_LIMITS.textMax;
  try {
    if (format === "pdf") {
      const r = readPdfText(bytes, { renderRow, textMax });
      return r.kind === "text" ? { kind: "text", text: r.text } : r.kind === "no-text" ? { kind: "no-text" } : r;
    }
    if (bytes.length >= 8 && bytes.readUInt32BE(0) === 0xd0cf11e0 && bytes.readUInt32BE(4) === 0xa1b11ae1) return { kind: "encrypted" };
    const zip = openZip(bytes);
    const sink = new LineSink(textMax);
    if (format === "docx") {
      const body = zip.read("word/document.xml");
      if (body === null) return { kind: "unreadable", reason: "a missing part" };
      wordText(body, sink);
    } else if (format === "xlsx") {
      const shared = zip.read("xl/sharedstrings.xml");
      const strings = shared === null ? [] : sharedStrings(shared);
      const styles = zip.read("xl/styles.xml");
      const formats = styles === null ? [] : cellFormats(styles);
      const sheets = zip.names().map((n) => ({ n, m: /^xl\/worksheets\/sheet([1-9]\d{0,4})\.xml$/.exec(n) })).filter((x) => x.m !== null)
        .sort((a, b) => Number(a.m![1]) - Number(b.m![1])).slice(0, DOCUMENT_FILE_LIMITS.sheetsMax);
      if (sheets.length === 0) return { kind: "unreadable", reason: "a missing part" };
      for (const s of sheets) {
        sheetText(zip.read(s.n) ?? "", strings, formats, sink);
        sink.blank();
      }
    } else {
      const manifest = zip.read("meta-inf/manifest.xml");
      if (manifest !== null && /encryption-data/.test(manifest)) return { kind: "encrypted" };
      const content = zip.read("content.xml");
      if (content === null) return { kind: "unreadable", reason: "a missing part" };
      odfText(content, sink);
    }
    const text = sink.done();
    return (text.match(/[\p{L}\p{N}]/gu) ?? []).length === 0 ? { kind: "no-text" } : { kind: "text", text };
  } catch (err) {
    if (err instanceof TooLong) return { kind: "too-long" };
    if (err instanceof ZipError) return { kind: "unreadable", reason: err.message };
    return { kind: "unreadable", reason: "the file could not be read" };
  }
}

class TooLong extends Error {}
class ZipError extends Error {}

/** Lines up to `max` UTF-8 bytes; at most one blank line in a row; control
 *  characters (but tab), NUL and the replacement character dropped. */
class LineSink {
  private readonly lines: string[] = [];
  private bytes = 0;
  constructor(private readonly max: number) {}
  line(s: string): void {
    // eslint-disable-next-line no-control-regex
    const l = s.replace(/[\u0000-\u0008\u000a-\u001f\u007f�﻿]/g, "").replace(/\s+$/u, "");
    if (l === "" && (this.lines.length === 0 || this.lines[this.lines.length - 1] === "")) return;
    this.bytes += Buffer.byteLength(l, "utf8") + 1;
    if (this.bytes > this.max) throw new TooLong();
    this.lines.push(l);
  }
  blank(): void { this.line(""); }
  done(): string { return this.lines.join("\n").trim(); }
}

// ── The zip ──────────────────────────────────────────────────────────────────

interface ZipEntry { name: string; method: number; comp: number; size: number; local: number; flags: number }

/** The archive in `buf`: its entries by lower-case name, each read once,
 *  inflated within the bounds. Zip64, multi-disk and encrypted entries are
 *  refused. */
function openZip(buf: Buffer): { names(): string[]; read(name: string): string | null } {
  const tailFrom = Math.max(0, buf.length - (65535 + 22));
  let eocd = -1;
  for (let i = buf.length - 22; i >= tailFrom; i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new ZipError("not a zip archive");
  if (buf.readUInt16LE(eocd + 4) !== 0 || buf.readUInt16LE(eocd + 6) !== 0) throw new ZipError("a multi-disk archive");
  const count = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOff = buf.readUInt32LE(eocd + 16);
  if (count === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff) throw new ZipError("a Zip64 archive");
  if (cdSize > DOCUMENT_FILE_LIMITS.cdMax || count > DOCUMENT_FILE_LIMITS.entriesMax || cdOff + cdSize > buf.length) throw new ZipError("a central directory out of bounds");
  const entries = new Map<string, ZipEntry>();
  let p = cdOff;
  for (let i = 0; i < count; i++) {
    if (p + 46 > cdOff + cdSize || buf.readUInt32LE(p) !== 0x02014b50) throw new ZipError("a broken central directory");
    const n = buf.readUInt16LE(p + 28);
    const x = buf.readUInt16LE(p + 30);
    const c = buf.readUInt16LE(p + 32);
    const name = buf.subarray(p + 46, p + 46 + n).toString("utf8").replace(/\\/g, "/").toLowerCase();
    const e: ZipEntry = { name, flags: buf.readUInt16LE(p + 8), method: buf.readUInt16LE(p + 10), comp: buf.readUInt32LE(p + 20), size: buf.readUInt32LE(p + 24), local: buf.readUInt32LE(p + 42) };
    if (!entries.has(name)) entries.set(name, e);
    p += 46 + n + x + c;
  }
  let inflated = 0;
  return {
    names: () => [...entries.keys()],
    read: (name: string): string | null => {
      const e = entries.get(name);
      if (!e) return null;
      if (e.flags & 1) throw new ZipError("an encrypted entry");
      if (e.local + 30 > buf.length || buf.readUInt32LE(e.local) !== 0x04034b50) throw new ZipError("an entry outside the archive");
      const at = e.local + 30 + buf.readUInt16LE(e.local + 26) + buf.readUInt16LE(e.local + 28);
      if (at + e.comp > buf.length) throw new ZipError("an entry outside the archive");
      const data = buf.subarray(at, at + e.comp);
      const left = Math.min(DOCUMENT_FILE_LIMITS.partOutMax, DOCUMENT_FILE_LIMITS.fileOutMax - inflated);
      let out: Buffer;
      if (e.method === 0) out = data;
      else if (e.method === 8) {
        try { out = inflateRawSync(data, { maxOutputLength: Math.max(1, left) }); } catch { throw new ZipError("a part that inflates past its limit, or cannot be inflated"); }
      } else throw new ZipError("an unknown compression method");
      if (out.length > left) throw new ZipError("a part that inflates past its limit");
      inflated += out.length;
      return out.toString("utf8");
    },
  };
}

// ── XML ──────────────────────────────────────────────────────────────────────

interface XmlEvents {
  open(local: string, tag: string, self: boolean): void;
  close(local: string): void;
  text(s: string): void;
}

/** One linear scan of `xml`: tags (a `>` inside a quoted attribute value is
 *  no end), text between them (entities decoded); comments, CDATA,
 *  processing instructions and declarations are not text. */
function scanXml(xml: string, on: XmlEvents): void {
  const n = xml.length;
  let i = 0;
  while (i < n) {
    const lt = xml.indexOf("<", i);
    const end = lt < 0 ? n : lt;
    if (end > i) on.text(decodeXmlEntities(xml.slice(i, end)));
    if (lt < 0) break;
    if (xml.startsWith("<!--", lt)) { const c = xml.indexOf("-->", lt + 4); i = c < 0 ? n : c + 3; continue; }
    if (xml.startsWith("<![CDATA[", lt)) { const c = xml.indexOf("]]>", lt + 9); i = c < 0 ? n : c + 3; continue; }
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
    if (first === 0x3f || first === 0x21) continue;
    if (first === 0x2f) { const raw = tag.slice(1).trim(); on.close(raw.slice(raw.lastIndexOf(":") + 1)); continue; }
    const self = tag.endsWith("/");
    const nameEnd = tag.search(/[\s/]/);
    const raw = nameEnd < 0 ? tag : tag.slice(0, nameEnd);
    const local = raw.slice(raw.lastIndexOf(":") + 1);
    // A self-closing tag is an open with `self` (no close follows).
    on.open(local, tag, self);
  }
}

/** An attribute's value in a tag (`name` with its prefix, e.g. `text:c`). */
function attr(tag: string, name: string): string | null {
  const m = new RegExp(`\\s${name.replace(/[.:]/g, "\\$&")}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`).exec(tag);
  return m ? decodeXmlEntities(m[1] ?? m[2] ?? "") : null;
}

/** Collects one table's rows (the outermost table only; a nested table's
 *  text joins its outer cell). */
class Table {
  depth = 0;
  private row: string[] | null = null;
  private cell: string | null = null;
  inCell(): boolean { return this.depth > 0 && this.cell !== null; }
  put(s: string): void { if (this.cell !== null) this.cell += s; }
  openTable(): void { this.depth++; }
  closeTable(): void { this.depth = Math.max(0, this.depth - 1); }
  openRow(): void { if (this.depth === 1) this.row = []; }
  closeRow(sink: LineSink): void { if (this.depth === 1 && this.row !== null) { sink.line(renderRow(this.row)); this.row = null; this.cell = null; } }
  openCell(): void { if (this.depth === 1) this.cell = ""; }
  closeCell(): void { if (this.depth === 1 && this.row !== null && this.cell !== null) { this.row.push(this.cell); this.cell = null; } }
}

/** Word's body (module comment). */
function wordText(xml: string, sink: LineSink): void {
  let inT = 0;
  let skip = 0;
  let para = "";
  const table = new Table();
  const put = (s: string): void => { if (table.inCell()) table.put(s); else para += s; };
  scanXml(xml, {
    open(local, _tag, self) {
      if (local === "t") { if (!self) inT++; return; }
      if (local === "tabs" || local === "Fallback" || local === "delText" || local === "instrText") { if (!self) skip++; return; }
      if (skip > 0) return;
      if (local === "p" && self) { if (table.inCell()) table.put(" "); else sink.line(""); return; }
      if (self && (local === "tbl" || local === "tr" || local === "tc")) return;
      if (local === "tab") put("\t");
      else if (local === "br" || local === "cr") put(table.inCell() ? " " : "\n");
      else if (local === "noBreakHyphen") put("-");
      else if (local === "tbl") table.openTable();
      else if (local === "tr") table.openRow();
      else if (local === "tc") table.openCell();
    },
    close(local) {
      if (local === "t") { inT = Math.max(0, inT - 1); return; }
      if (local === "tabs" || local === "Fallback" || local === "delText" || local === "instrText") { skip = Math.max(0, skip - 1); return; }
      if (skip > 0) return;
      if (local === "p") {
        if (table.inCell()) table.put(" ");
        else { for (const l of para.split("\n")) sink.line(l); para = ""; }
      } else if (local === "tc") table.closeCell();
      else if (local === "tr") table.closeRow(sink);
      else if (local === "tbl") table.closeTable();
    },
    text(s) { if (inT > 0 && skip === 0) put(s); },
  });
  if (para !== "") sink.line(para);
}

/** Excel's shared strings: each `si`'s text runs (phonetic runs not). */
function sharedStrings(xml: string): string[] {
  const out: string[] = [];
  let cur: string | null = null;
  let inT = 0;
  let skip = 0;
  scanXml(xml, {
    open(local, _tag, self) {
      if (local === "si") { if (self) out.push(""); else cur = ""; }
      else if (local === "t" && !self) inT++;
      else if (local === "rPh" && !self) skip++;
    },
    close(local) {
      if (local === "si") { out.push(cur ?? ""); cur = null; }
      else if (local === "t") inT = Math.max(0, inT - 1);
      else if (local === "rPh") skip = Math.max(0, skip - 1);
    },
    text(s) { if (cur !== null && inT > 0 && skip === 0 && out.length < 1_000_000) cur += s; },
  });
  return out;
}

/** How a cell format shows a number: money (2 decimals, grouped or not),
 *  a date, or as stored. */
type NumberShow = { kind: "money"; grouped: boolean; decimals: number } | { kind: "date" } | { kind: "plain" };

const BUILTIN_FORMATS: Readonly<Record<number, NumberShow>> = {
  2: { kind: "money", grouped: false, decimals: 2 }, 4: { kind: "money", grouped: true, decimals: 2 },
  7: { kind: "money", grouped: true, decimals: 2 }, 8: { kind: "money", grouped: true, decimals: 2 },
  39: { kind: "money", grouped: true, decimals: 2 }, 40: { kind: "money", grouped: true, decimals: 2 },
  43: { kind: "money", grouped: true, decimals: 2 }, 44: { kind: "money", grouped: true, decimals: 2 },
  14: { kind: "date" }, 15: { kind: "date" }, 16: { kind: "date" }, 17: { kind: "date" }, 22: { kind: "date" },
};

/** A number format code's show (its first section; quoted text and
 *  escapes set aside). */
function showOfCode(code: string): NumberShow {
  const first = code.split(";")[0]!.replace(/"[^"]*"|\\.|\[[^\]]*\]/g, "");
  if (/[yd]/i.test(first) && !/[hs]/i.test(first.replace(/[yd]/gi, ""))) return { kind: "date" };
  const dec = /0\.(0+)/.exec(first);
  if (dec && dec[1]!.length === 2) return { kind: "money", grouped: /#,##|0,0/.test(first), decimals: 2 };
  return { kind: "plain" };
}

/** The workbook's cell formats (`cellXfs`, by index) as shows. */
function cellFormats(xml: string): NumberShow[] {
  const custom = new Map<number, NumberShow>();
  const xfs: NumberShow[] = [];
  let inXfs = 0;
  scanXml(xml, {
    open(local, tag, self) {
      if (local === "numFmt") {
        const id = Number(attr(tag, "numFmtId"));
        const code = attr(tag, "formatCode");
        if (Number.isFinite(id) && code !== null) custom.set(id, showOfCode(code));
      } else if (local === "cellXfs" && !self) inXfs++;
      else if (local === "xf" && inXfs > 0 && xfs.length < 100_000) {
        const id = Number(attr(tag, "numFmtId") ?? "0");
        xfs.push(custom.get(id) ?? BUILTIN_FORMATS[id] ?? { kind: "plain" });
      }
    },
    close(local) { if (local === "cellXfs") inXfs = Math.max(0, inXfs - 1); },
    text() { /* none */ },
  });
  return xfs;
}

/** A number as its show renders it. Pure. */
export function showNumber(v: string, show: NumberShow): string {
  const s = v.trim();
  if (!/^-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?$/.test(s)) return s;
  const x = Number(s);
  if (!Number.isFinite(x)) return s;
  if (show.kind === "date") {
    // The 1900 date system (Excel's serial, the 1900 leap-year bug and all).
    if (x < 1 || x > 2958465) return s;
    const days = Math.floor(x);
    const ms = Date.UTC(1899, 11, 30) + (days < 61 ? days + 1 : days) * 86400000;
    return new Date(ms).toISOString().slice(0, 10);
  }
  if (show.kind === "money") {
    const fixed = Math.abs(x).toFixed(show.decimals);
    const [int, frac] = fixed.split(".");
    const grouped = show.grouped ? int!.replace(/\B(?=(\d{3})+(?!\d))/g, ",") : int!;
    return `${x < 0 ? "-" : ""}${grouped}.${frac}`;
  }
  if (/^-?\d+$/.test(s)) return s;
  // An amount stored as is (no money format): two decimals where it has
  // at most two, thousands grouped, as a statement prints it.
  const cents = Math.round(x * 100);
  if (Math.abs(x * 100 - cents) < 1e-6 && Math.abs(x) < 1e13) return showNumber(s, { kind: "money", grouped: true, decimals: 2 });
  return String(x);
}

/** One worksheet: a line per row. */
function sheetText(xml: string, shared: readonly string[], formats: readonly NumberShow[], sink: LineSink): void {
  let row: string[] | null = null;
  let cell: { t: string | null; s: number; v: string; is: string } | null = null;
  let inV = 0;
  let inIs = 0;
  let inT = 0;
  let skip = 0;
  scanXml(xml, {
    open(local, tag, self) {
      if (local === "row") row = self ? null : [];
      else if (local === "c") {
        if (!self) cell = { t: attr(tag, "t"), s: Number(attr(tag, "s") ?? "0"), v: "", is: "" };
      } else if (local === "v" && !self) inV++;
      else if (local === "is" && !self) inIs++;
      else if (local === "t" && !self) inT++;
      else if (local === "rPh" && !self) skip++;
    },
    close(local) {
      if (local === "row") { if (row !== null) sink.line(renderRow(row)); row = null; }
      else if (local === "c") {
        if (row !== null && cell !== null) {
          const c = cell as { t: string | null; s: number; v: string; is: string };
          let text: string;
          if (c.t === "s") text = shared[Number(c.v.trim())] ?? "";
          else if (c.t === "inlineStr") text = c.is;
          else if (c.t === "str" || c.t === "e" || c.t === "d") text = c.v;
          else if (c.t === "b") text = c.v.trim() === "1" ? "TRUE" : "FALSE";
          else text = c.v === "" ? "" : showNumber(c.v, formats[c.s] ?? { kind: "plain" });
          (row as string[]).push(text);
        }
        cell = null;
      } else if (local === "v") inV = Math.max(0, inV - 1);
      else if (local === "is") inIs = Math.max(0, inIs - 1);
      else if (local === "t") inT = Math.max(0, inT - 1);
      else if (local === "rPh") skip = Math.max(0, skip - 1);
    },
    text(s) {
      if (cell === null) return;
      const c = cell as { v: string; is: string };
      if (inV > 0) c.v += s;
      else if (inIs > 0 && inT > 0 && skip === 0) c.is += s;
    },
  });
}

/** An ODF document's or spreadsheet's `content.xml` (module comment). */
function odfText(xml: string, sink: LineSink): void {
  let inP = 0;
  let skip = 0;
  let para = "";
  const table = new Table();
  const put = (s: string): void => { if (table.inCell()) table.put(s); else para += s; };
  const SKIP = new Set(["note", "annotation", "tracked-changes", "title", "desc", "deletion"]);
  scanXml(xml, {
    open(local, tag, self) {
      if (SKIP.has(local)) { if (!self) skip++; return; }
      if (skip > 0) return;
      if (local === "p" || local === "h") { if (!self) inP++; else if (!table.inCell()) sink.line(""); return; }
      if (local === "s") { const c = Number(attr(tag, "text:c") ?? "1"); put(" ".repeat(Math.max(1, Math.min(64, Number.isFinite(c) ? c : 1)))); }
      else if (local === "tab") put("\t");
      else if (local === "line-break") put(table.inCell() ? " " : "\n");
      else if (self) return;
      else if (local === "table") table.openTable();
      else if (local === "table-row") table.openRow();
      else if (local === "table-cell") table.openCell();
    },
    close(local) {
      if (SKIP.has(local)) { skip = Math.max(0, skip - 1); return; }
      if (skip > 0) return;
      if (local === "p" || local === "h") {
        inP = Math.max(0, inP - 1);
        if (table.inCell()) table.put(" ");
        else { for (const l of para.split("\n")) sink.line(l); para = ""; }
      } else if (local === "table-cell") table.closeCell();
      else if (local === "table-row") table.closeRow(sink);
      else if (local === "table") { table.closeTable(); if (table.depth === 0) sink.blank(); }
    },
    text(s) { if (inP > 0 && skip === 0) put(s); },
  });
  if (para !== "") sink.line(para);
}
