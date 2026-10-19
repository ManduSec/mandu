/**
 * document-twin-pdf — the twin of a personal document kept as a PDF
 * (2026-10-19, docs/design/confidentiality/secret-discovery.md §2.8): the
 * document twin's TEXT (its labels as written, every value a placeholder,
 * personal-documents.ts DOCUMENT_TWIN_EXTRACT) set as a plain PDF, so what
 * the guard serves at `statement.pdf` is still a PDF: Claude Code's `Read`
 * (which refuses a file with no `%PDF-` header) sends it as a document, and
 * `pdftotext`, `pypdf` or `mutool` read the placeholders from it.
 *
 * The file is ASCII (it travels as the registry's `twin` text, and the
 * launcher writes it as written): one font (Courier, WinAnsiEncoding, so a
 * character outside it is `?`), uncompressed content streams, one line of
 * the twin per line of the page, a size small enough for the longest line
 * to fit (between 4 and 10 points), a page break where the page is full, and
 * a cross-reference table. Deterministic: the same text renders the same
 * bytes (no date, no id), so the model proxy can tell the twin from the
 * document by its bytes (document-text ops, `documentText`).
 *
 * What it holds is what the twin's text holds: no value, no byte of the
 * original file.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { WIN_ANSI_HIGH } from "./pdf-text.js";

const PAGE_W = 612;
const PAGE_H = 792;
const MARGIN = 50;

/** One character as a WinAnsi byte (`?` when it has none; a tab a blank). */
function winAnsiByte(ch: string): number {
  const c = ch.codePointAt(0)!;
  if (c === 0x09) return 0x20;
  if (c >= 0x20 && c < 0x7f) return c;
  if (c >= 0xa0 && c <= 0xff) return c;
  const i = WIN_ANSI_HIGH.indexOf(ch);
  return i >= 0 && ch !== "" ? 0x80 + i : 0x3f;
}

/** A line as a PDF literal string's body: `(`, `)` and `\` escaped, every
 *  byte past ASCII as an octal escape. */
function pdfString(line: string): string {
  let out = "";
  for (const ch of line) {
    const b = winAnsiByte(ch);
    if (b === 0x28 || b === 0x29 || b === 0x5c) out += `\\${String.fromCharCode(b)}`;
    else if (b >= 0x80) out += `\\${b.toString(8).padStart(3, "0")}`;
    else out += String.fromCharCode(b);
  }
  return out;
}

/** The twin text `text` as a PDF (module comment). Pure. */
export function renderTwinPdf(text: string): string {
  const lines = text.replace(/\r\n?/g, "\n").replace(/\n+$/, "").split("\n");
  const longest = Math.max(1, ...lines.map((l) => [...l].length));
  const size = Math.max(4, Math.min(10, Math.floor(((PAGE_W - 2 * MARGIN) / (longest * 0.6)) * 100) / 100));
  const leading = Math.round(size * 125) / 100;
  const perPage = Math.max(1, Math.floor((PAGE_H - 2 * MARGIN) / leading));
  const pages: string[][] = [];
  for (let i = 0; i < lines.length; i += perPage) pages.push(lines.slice(i, i + perPage));
  if (pages.length === 0) pages.push([""]);

  const objs: string[] = [];
  const pageIds = pages.map((_, i) => 5 + 2 * i);
  objs[1] = "<< /Type /Catalog /Pages 2 0 R >>";
  objs[2] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${pages.length} >>`;
  objs[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>";
  objs[4] = "<< /Producer (Mandu) /Title (A protected copy: the values are placeholders) >>";
  pages.forEach((pl, i) => {
    const body = [`BT`, `/F1 ${size} Tf`, `${leading} TL`, `${MARGIN} ${Math.round((PAGE_H - MARGIN - size) * 100) / 100} Td`];
    for (const l of pl) body.push(l === "" ? "T*" : `(${pdfString(l)}) Tj T*`);
    body.push("ET");
    const stream = `${body.join("\n")}\n`;
    objs[pageIds[i]!] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] /Resources << /Font << /F1 3 0 R >> >> /Contents ${pageIds[i]! + 1} 0 R >>`;
    objs[pageIds[i]! + 1] = `<< /Length ${stream.length} >>\nstream\n${stream}endstream`;
  });

  let out = "%PDF-1.4\n";
  const offsets: number[] = [];
  for (let n = 1; n < objs.length; n++) {
    offsets[n] = out.length;
    out += `${n} 0 obj\n${objs[n]}\nendobj\n`;
  }
  const xref = out.length;
  out += `xref\n0 ${objs.length}\n0000000000 65535 f \n`;
  for (let n = 1; n < objs.length; n++) out += `${String(offsets[n]).padStart(10, "0")} 00000 n \n`;
  out += `trailer\n<< /Size ${objs.length} /Root 1 0 R /Info 4 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return out;
}
