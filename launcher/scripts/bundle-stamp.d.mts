/** Types for bundle-stamp.mjs (imported by its tests). */
export type FileStat = [mtimeMs: number, size: number];
export declare const STAMP_NAME: string;
export declare const BUILD_SCRIPT_INPUTS: string[];
export declare function stampInputs(repoRoot: string, metaInputs: Iterable<string>, exists?: (p: string) => boolean): string[];
export declare function fsClockMs(dir: string): number;
export declare function clearStamp(distDir: string): void;
export declare function writeStamp(distDir: string, opts: {
  repoRoot: string;
  inputs: string[];
  outputs: string[];
  startMs: number;
  stat?: (p: string) => FileStat | null;
}): string | null;
export declare function checkStamp(distDir: string, opts?: {
  repoRoot?: string;
  stat?: (p: string) => FileStat | null;
  readFile?: (p: string) => string;
}): { fresh: true; inputs: number } | { fresh: false; reason: string };
