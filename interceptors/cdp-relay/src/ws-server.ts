/**
 * ws-server — the server half of a WebSocket (RFC 6455), enough for the
 * DevTools protocol: text messages, fragmentation, ping/pong, close.
 * Mandu-new (no reference origin). The relay's other half (to Chrome) is
 * Node's built-in client; a dependency was not worth a new package in
 * every install (and in the CI image's offline cache).
 *
 * Not supported, by design: extensions (no permessage-deflate; the offer
 * is declined), subprotocols, binary messages (closed with 1003: the
 * DevTools protocol is JSON text).
 */
import { createHash } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/** The accept key for a client's `Sec-WebSocket-Key`. */
export function acceptKey(key: string): string {
  return createHash("sha1").update(key + GUID).digest("base64");
}

export interface WsServerOptions {
  /** The largest message accepted (bytes); larger closes with 1009. */
  maxPayload: number;
}

/** One accepted connection. */
export class WsConnection {
  private buf: Buffer = Buffer.alloc(0);
  private fragments: Buffer[] = [];
  private fragmentBytes = 0;
  private open = true;
  private readonly messageHandlers: Array<(text: string) => void> = [];
  private readonly closeHandlers: Array<() => void> = [];

  constructor(private readonly socket: Duplex, private readonly opts: WsServerOptions) {
    socket.on("data", (chunk: Buffer) => this.onData(chunk));
    socket.on("close", () => this.closed());
    socket.on("error", () => this.closed());
  }

  get isOpen(): boolean {
    return this.open;
  }

  onMessage(fn: (text: string) => void): void {
    this.messageHandlers.push(fn);
  }

  onClose(fn: () => void): void {
    this.closeHandlers.push(fn);
  }

  send(text: string): void {
    if (!this.open) return;
    this.socket.write(frame(0x1, Buffer.from(text, "utf8")));
  }

  close(code = 1000): void {
    if (!this.open) return;
    const body = Buffer.alloc(2);
    body.writeUInt16BE(code);
    this.socket.write(frame(0x8, body));
    this.socket.end();
    this.closed();
  }

  private closed(): void {
    if (!this.open) return;
    this.open = false;
    this.socket.destroy();
    for (const fn of this.closeHandlers) fn();
  }

  private onData(chunk: Buffer): void {
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
    for (;;) {
      if (this.buf.length < 2) return;
      const b0 = this.buf[0]!;
      const b1 = this.buf[1]!;
      const fin = (b0 & 0x80) !== 0;
      const opcode = b0 & 0x0f;
      if ((b0 & 0x70) !== 0) return this.close(1002); // no extension was agreed
      if ((b1 & 0x80) === 0) return this.close(1002); // a client's frames are masked
      let len = b1 & 0x7f;
      let at = 2;
      if (len === 126) {
        if (this.buf.length < 4) return;
        len = this.buf.readUInt16BE(2);
        at = 4;
      } else if (len === 127) {
        if (this.buf.length < 10) return;
        const big = this.buf.readBigUInt64BE(2);
        if (big > BigInt(this.opts.maxPayload)) return this.close(1009);
        len = Number(big);
        at = 10;
      }
      if (len > this.opts.maxPayload) return this.close(1009);
      if (this.buf.length < at + 4 + len) return;
      const mask = this.buf.subarray(at, at + 4);
      const payload = Buffer.from(this.buf.subarray(at + 4, at + 4 + len));
      for (let i = 0; i < payload.length; i++) payload[i]! ^= mask[i & 3]!;
      this.buf = this.buf.subarray(at + 4 + len);
      if (!this.open) return;
      if (opcode === 0x8) return this.close(1000);
      if (opcode === 0x9) { this.socket.write(frame(0xa, payload)); continue; }
      if (opcode === 0xa) continue;
      if (opcode === 0x2) return this.close(1003);
      if (opcode !== 0x1 && opcode !== 0x0) return this.close(1002);
      if (opcode === 0x1 && this.fragments.length > 0) return this.close(1002);
      if (opcode === 0x0 && this.fragments.length === 0) return this.close(1002);
      this.fragments.push(payload);
      this.fragmentBytes += payload.length;
      if (this.fragmentBytes > this.opts.maxPayload) return this.close(1009);
      if (!fin) continue;
      const text = Buffer.concat(this.fragments).toString("utf8");
      this.fragments = [];
      this.fragmentBytes = 0;
      for (const fn of this.messageHandlers) fn(text);
    }
  }
}

/** Complete the handshake on an HTTP upgrade, or refuse it (null). */
export function acceptUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer, opts: WsServerOptions): WsConnection | null {
  const key = req.headers["sec-websocket-key"];
  if (req.headers.upgrade?.toLowerCase() !== "websocket" || typeof key !== "string" || key === "") {
    socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    return null;
  }
  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${acceptKey(key)}\r\n\r\n`,
  );
  const conn = new WsConnection(socket, opts);
  if (head.length > 0) socket.unshift(head);
  return conn;
}

/** One unfragmented, unmasked server frame. */
export function frame(opcode: number, payload: Buffer): Buffer {
  const len = payload.length;
  const header = len < 126 ? Buffer.alloc(2) : len < 65536 ? Buffer.alloc(4) : Buffer.alloc(10);
  header[0] = 0x80 | opcode;
  if (len < 126) header[1] = len;
  else if (len < 65536) { header[1] = 126; header.writeUInt16BE(len, 2); }
  else { header[1] = 127; header.writeBigUInt64BE(BigInt(len), 2); }
  return Buffer.concat([header, payload]);
}
