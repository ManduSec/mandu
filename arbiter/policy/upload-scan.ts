/**
 * upload-scan — read a local file in chunks and look for registered secret
 * values in its bytes, never holding the whole file (the upload gate's rule
 * 6–7, file-upload.ts; confidentiality.md §7, "A tool that uploads a local
 * file"). Mandu-new (no reference origin).
 *
 * WHAT IS MATCHED. Exactly what the value backstop matches in a text
 * (`RegisteredValueIndex.hits`, the server's `secretValueHits`): each
 * secret row's whole value and its pieces (long lines, credential-shaped
 * spans, a registered file's bare tokens), verbatim, in the file's bytes
 * decoded as UTF-8 the way `readFileSync(path, "utf8")` decodes them
 * (invalid bytes become U+FFFD, a byte-order mark is kept). No encoded form
 * (base64, URL) is looked for: the backstop looks for none, and the gate
 * keeps its coverage. The decoder is streamed (`TextDecoder` with
 * `stream: true`), so a character split across two reads is decoded whole,
 * and the index's stream matches each piece with the tail of the one before
 * it, so a value split across two reads is found (`ValueHitStream`).
 *
 * BOUNDS. A file past `maxBytes` is not read (the caller holds it for the
 * person); a scan past its deadline stops and answers unreadable (held). A
 * read error is unreadable (held): fail-closed is unchanged. The file is
 * opened non-blocking (a FIFO swapped in after the caller's stat never
 * stalls a thread) and judged by the descriptor's own stat.
 *
 * NOT ON THE EVENT LOOP FOR LONG. Every chunk is one asynchronous read, so
 * the arbiter's other clients are answered between chunks; the CPU work per
 * chunk (decode and match) is the only stall (about 10 ms per 256 KiB read of
 * binary, confidentiality.md §7).
 */

import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";

import type { ValueHitStream, ValueHow } from "../prompt-filter/registered-values.js";

/** What the scan found. */
export type UploadScanResult =
  | { kind: "read"; bytes: number; hits: Array<{ symbol: string; how: ValueHow }> }
  | { kind: "unreadable"; why: string };

export interface UploadScanOptions {
  /** A file larger than this is not read. */
  maxBytes: number;
  /** Bytes per read. */
  chunkBytes: number;
  /** The scan stops (unreadable) when `now()` passes this. */
  deadline: number;
  now?: () => number;
  /** Called after every chunk (the server's progress frame, a test). */
  onChunk?: (bytesSoFar: number) => void;
}

/**
 * Scan the regular file at `path` with `stream` (a fresh
 * `RegisteredValueIndex.stream()`). Never rejects.
 */
export async function scanFileForValues(path: string, stream: ValueHitStream, opts: UploadScanOptions): Promise<UploadScanResult> {
  const now = opts.now ?? Date.now;
  let fh: Awaited<ReturnType<typeof open>> | undefined;
  try {
    fh = await open(path, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK);
    const st = await fh.stat();
    if (!st.isFile()) return { kind: "unreadable", why: "not a regular file" };
    if (st.size > opts.maxBytes) return { kind: "unreadable", why: `larger than ${opts.maxBytes} bytes` };
    // A window of the stream's overlap is matched again with every chunk:
    // keep a chunk well above it, so a long registered value does not make
    // the scan re-walk mostly old text.
    const chunk = Math.max(opts.chunkBytes, 4 * stream.overlap);
    const buf = Buffer.allocUnsafe(chunk);
    const decoder = new TextDecoder("utf-8", { ignoreBOM: true });
    let total = 0;
    for (;;) {
      if (now() > opts.deadline) return { kind: "unreadable", why: "the check did not finish in time" };
      const { bytesRead } = await fh.read(buf, 0, chunk, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      // The file grew past the bound while it was read: unchecked bytes.
      if (total > opts.maxBytes) return { kind: "unreadable", why: `larger than ${opts.maxBytes} bytes` };
      stream.push(decoder.decode(buf.subarray(0, bytesRead), { stream: true }));
      opts.onChunk?.(total);
    }
    stream.push(decoder.decode());
    return { kind: "read", bytes: total, hits: stream.hits() };
  } catch (err) {
    return { kind: "unreadable", why: (err as NodeJS.ErrnoException).code ?? "read failed" };
  } finally {
    await fh?.close().catch(() => {});
  }
}
