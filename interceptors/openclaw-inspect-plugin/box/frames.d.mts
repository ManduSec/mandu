// Types for frames.mjs (the box's wire; docs/design/agents/openclaw-plugin.md §10).
export declare const MAX_FRAME: number;
export declare const CHUNK: number;
export declare const T: Readonly<{
  REQUEST: "Q";
  STDIN: "I";
  STDIN_END: "E";
  SIGNAL: "K";
  STDOUT: "O";
  STDERR: "e";
  EXIT: "X";
  ANSWER: "A";
  DATA: "D";
  FAIL: "F";
}>;
export declare function encodeFrame(type: string, payload?: unknown): Buffer;
export declare class FrameDecoder {
  buf: Buffer;
  push(chunk: Buffer): Array<{ type: string; payload: Buffer }>;
}
export declare function frameJson(payload: Buffer): any;
export declare function chunkFrames(type: string, data: Buffer): Buffer[];
