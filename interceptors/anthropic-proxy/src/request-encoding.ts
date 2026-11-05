/**
 * request-encoding — a compressed request body read as the bytes it carries,
 * before a wire adapter reads it (model-wires.md §9.3).
 *
 * Mandu-new (no reference origin). OpenClaw's `openai-chatgpt-responses`
 * transport (a ChatGPT sign-in, @openclaw/ai 2026.10.7
 * `streamOpenAICodexResponses`) compresses the request body with zstd and
 * sends `content-encoding: zstd` whenever the provider is the built-in
 * `openai` and Node has zstd. A body the proxy cannot read is refused (400,
 * nothing sent), so without this every turn of that sign-in would fail. The
 * proxy decodes the body, gates the plain JSON, and sends the provider the
 * plain JSON with no `content-encoding` (an identity body is always
 * accepted).
 *
 * FAIL-CLOSED: an encoding this module does not know, a body that does not
 * decode, or one that decodes past the proxy's body limit is refused before
 * anything is read or sent. Pure (no I/O).
 */
import * as zlib from "node:zlib";

export type DecodedBody =
  | { ok: true; body: Buffer; decoded: boolean }
  | { ok: false; status: 400 | 413 | 415; message: string };

type Decoder = (buf: Buffer, opts: { maxOutputLength: number }) => Buffer;

/** The decoders by coding name; zstd only where this Node has it (22.15+). */
function decoderFor(coding: string): Decoder | null {
  const z = zlib as unknown as Record<string, unknown>;
  switch (coding) {
    case "gzip":
    case "x-gzip":
      return (b, o) => zlib.gunzipSync(b, o);
    case "deflate":
      return (b, o) => zlib.inflateSync(b, o);
    case "br":
      return (b, o) => zlib.brotliDecompressSync(b, o);
    case "zstd":
      return typeof z["zstdDecompressSync"] === "function"
        ? (b, o) => (z["zstdDecompressSync"] as Decoder)(b, o)
        : null;
    default:
      return null;
  }
}

/**
 * The body a request with `content-encoding` carries, decoded (codings are
 * undone last-applied first), or why it cannot be read. No header, or only
 * `identity`: the body as it came, `decoded: false`.
 */
export function decodeRequestBody(contentEncoding: string | string[] | undefined, body: Buffer, maxBytes: number): DecodedBody {
  const raw = Array.isArray(contentEncoding) ? contentEncoding.join(",") : contentEncoding ?? "";
  const codings = raw.split(",").map((c) => c.trim().toLowerCase()).filter((c) => c !== "" && c !== "identity");
  if (codings.length === 0) return { ok: true, body, decoded: false };
  let out = body;
  for (const coding of [...codings].reverse()) {
    const decode = decoderFor(coding);
    if (decode === null) {
      return {
        ok: false, status: 415,
        message: coding === "zstd"
          ? `the request body is zstd-compressed, and the Node.js running Mandu's model proxy (${process.version}) has no zstd (Node.js 22.15 or later has it), so Mandu cannot read the body to mask what it carries`
          : `the request body is encoded as ${JSON.stringify(coding)}, which Mandu cannot read, so it cannot mask what it carries`,
      };
    }
    try {
      out = decode(out, { maxOutputLength: maxBytes });
    } catch (err) {
      const e = err as NodeJS.ErrnoException;
      if (e.code === "ERR_BUFFER_TOO_LARGE" || e instanceof RangeError) {
        return { ok: false, status: 413, message: `the ${coding} request body decodes past the proxy's limit (${maxBytes} bytes)` };
      }
      return { ok: false, status: 400, message: `the ${coding} request body does not decode (${e.message})` };
    }
  }
  return { ok: true, body: out, decoded: true };
}
