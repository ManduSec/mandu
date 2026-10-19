/**
 * document-blocks — what the model reads of a PDF a tool result carries as
 * a `document` block (2026-10-19, docs/design/confidentiality/
 * secret-discovery.md §2.8, "A document block"): Claude Code's `Read` of a
 * `.pdf` sends the whole file, base64, after a `PDF file read:` line.
 *
 * The model proxy masked every result carrying a block other than text
 * whole (rewrite-request.ts `hasNonTextBlock`): the text-only classify
 * cannot vouch for bytes it does not read. So a PDF reached the model as one
 * placeholder: safe, and of no use, even for a personal document's twin,
 * which holds nothing secret. Now the proxy asks the arbiter for the block's
 * TEXT and forwards that text in place of the block, so what reaches the
 * model is exactly what the classify then judges (the path's label, the
 * value backstop, the read-twin rule); the block itself never does.
 *
 * THE ANSWER (`documentBlockText`, pure):
 *   - not `application/pdf`, larger than the reader reads, or no text
 *     (a scan, a password, unreadable): null, and the proxy masks the result
 *     whole, as before (fail closed);
 *   - the bytes of the twin the guard serves for the Read's path (a personal
 *     document's twin PDF, document-twin-pdf.ts, rendered again from the
 *     registry and compared byte for byte): the twin's TEXT, which the
 *     read-twin rule releases (labels and placeholders);
 *   - the bytes of the document itself, unchanged since it was registered
 *     (an unconfined session, where no guard served the twin): its text is
 *     the registered text, and the answer is the twin's text too, so the
 *     model reads the labels and placeholders, never the values;
 *   - any other PDF: its text layer (pdf-text.ts), which the classify judges
 *     as it judges any text: a labelled path's level masks it, the value
 *     backstop masks a registered value in it. Images and anything else in
 *     the file are not forwarded.
 *
 * Mandu-new (no reference origin).
 */
import { DOCUMENT_FILE_LIMITS, extractDocumentText } from "./document-text.js";
import { renderTwinPdf } from "./document-twin-pdf.js";

/** The registered document behind the Read's path: its twin text and its
 *  registered text (registry.ts `registeredDocumentTwin`). */
export interface DocumentTwinRef {
  path: string;
  /** The document twin's text (labels kept, every value a placeholder). */
  text: string;
  /** The text the document was registered by (its extracted text). */
  base: string;
}

export interface DocumentBlockAnswer {
  /** What the model reads in place of the block, or null: the result stays
   *  masked whole. */
  text: string | null;
  /** The registered document whose twin `text` is. */
  twinOf?: string;
  /** Why, for the audit (never file text). */
  reason: string;
}

/** The base64 length of the largest file the reader reads. */
export const DOCUMENT_BLOCK_MAX_BASE64 = Math.ceil(DOCUMENT_FILE_LIMITS.fileMax / 3) * 4;

/** The text a `document` block of `mediaType` holding base64 `data` is
 *  forwarded as (module comment). `twin`: the registered document at the
 *  Read's path, when there is one. Pure; never throws. */
export function documentBlockText(data: unknown, mediaType: unknown, twin: DocumentTwinRef | null): DocumentBlockAnswer {
  if (typeof mediaType !== "string" || mediaType.trim().toLowerCase() !== "application/pdf") return { text: null, reason: "not a PDF" };
  if (typeof data !== "string" || data === "") return { text: null, reason: "no data" };
  if (data.length > DOCUMENT_BLOCK_MAX_BASE64) return { text: null, reason: "larger than the reader reads" };
  if (!/^[A-Za-z0-9+/=\s]*$/.test(data)) return { text: null, reason: "not base64" };
  const bytes = Buffer.from(data, "base64");
  if (twin !== null && bytes.toString("latin1") === renderTwinPdf(twin.text)) {
    return { text: twin.text, twinOf: twin.path, reason: "the twin of a personal document, as the guard serves it" };
  }
  const r = extractDocumentText(bytes, "pdf");
  if (r.kind !== "text") return { text: null, reason: r.kind === "unreadable" ? `unreadable: ${r.reason}` : r.kind };
  if (twin !== null && r.text === twin.base) {
    return { text: twin.text, twinOf: twin.path, reason: "a personal document as registered: its twin's text" };
  }
  return { text: r.text, reason: "the PDF's text layer" };
}
