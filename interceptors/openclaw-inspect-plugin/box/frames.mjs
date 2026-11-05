// frames.mjs — the wire of Mandu's confined-commands box (the OpenClaw
// sandbox backend, docs/design/agents/openclaw-plugin.md §10).
//
// Mandu-new (no reference origin). Plain JavaScript on purpose: the box host
// (host.mjs) runs inside the Mandu launch that confines it and the exec relay
// (relay.mjs) runs as the program OpenClaw spawns for each command, both on
// a bare `node` with no TypeScript loader. The plugin (TypeScript, loaded by
// OpenClaw through jiti) imports this module too; frames.d.mts types it.
//
// One frame: a type byte, a big-endian u32 payload length, the payload.
// A request is one `Q` frame of JSON; the streams that follow it are bytes.
//
//   client → host   Q request (JSON)   I stdin bytes   E stdin closed   K signal (JSON {signal})
//   host → client   O stdout bytes     e stderr bytes  X exit (JSON {code, signal})
//                   A answer (JSON)    D data bytes    F failure (JSON {error, code?})

/** The largest payload one frame may carry (a file the bridge writes is
 *  sent in chunks below this; a frame announcing more ends the connection). */
export const MAX_FRAME = 16 * 1024 * 1024;
/** The chunk size streams are cut into. */
export const CHUNK = 64 * 1024;

/** Every frame type, by name. */
export const T = Object.freeze({
  REQUEST: "Q",
  STDIN: "I",
  STDIN_END: "E",
  SIGNAL: "K",
  STDOUT: "O",
  STDERR: "e",
  EXIT: "X",
  ANSWER: "A",
  DATA: "D",
  FAIL: "F",
});

const KNOWN = new Set(Object.values(T));

/**
 * Encode one frame. `payload` is a Buffer, a string (UTF-8) or a value to
 * send as JSON (any other type).
 * @param {string} type
 * @param {Buffer | string | unknown} [payload]
 * @returns {Buffer}
 */
export function encodeFrame(type, payload) {
  if (typeof type !== "string" || type.length !== 1 || !KNOWN.has(type)) throw new Error(`unknown frame type ${JSON.stringify(type)}`);
  const body = payload === undefined ? Buffer.alloc(0)
    : Buffer.isBuffer(payload) ? payload
    : typeof payload === "string" ? Buffer.from(payload, "utf8")
    : Buffer.from(JSON.stringify(payload), "utf8");
  if (body.length > MAX_FRAME) throw new Error(`frame of ${body.length} bytes is over ${MAX_FRAME}`);
  const head = Buffer.alloc(5);
  head.write(type, 0, 1, "latin1");
  head.writeUInt32BE(body.length, 1);
  return Buffer.concat([head, body]);
}

/**
 * An incremental decoder: push bytes as they arrive, get whole frames back.
 * A frame of an unknown type or over MAX_FRAME is an error (the caller
 * closes the connection: a peer that speaks something else is not ours).
 */
export class FrameDecoder {
  constructor() {
    /** @type {Buffer} */
    this.buf = Buffer.alloc(0);
  }

  /**
   * @param {Buffer} chunk
   * @returns {Array<{type: string, payload: Buffer}>}
   */
  push(chunk) {
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
    const out = [];
    for (;;) {
      if (this.buf.length < 5) break;
      const type = this.buf.toString("latin1", 0, 1);
      if (!KNOWN.has(type)) throw new Error(`unknown frame type ${JSON.stringify(type)}`);
      const len = this.buf.readUInt32BE(1);
      if (len > MAX_FRAME) throw new Error(`frame of ${len} bytes is over ${MAX_FRAME}`);
      if (this.buf.length < 5 + len) break;
      out.push({ type, payload: this.buf.subarray(5, 5 + len) });
      this.buf = this.buf.subarray(5 + len);
    }
    return out;
  }
}

/**
 * A frame's payload as JSON, or null when it is not JSON.
 * @param {Buffer} payload
 * @returns {any}
 */
export function frameJson(payload) {
  try { return JSON.parse(payload.toString("utf8")); } catch { return null; }
}

/**
 * Cut `data` into STDIN-style frames of `type`, each at most CHUNK bytes.
 * @param {string} type
 * @param {Buffer} data
 * @returns {Buffer[]}
 */
export function chunkFrames(type, data) {
  const out = [];
  for (let i = 0; i < data.length; i += CHUNK) out.push(encodeFrame(type, data.subarray(i, i + CHUNK)));
  return out;
}
