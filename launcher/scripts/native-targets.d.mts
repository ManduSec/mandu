/** Types for native-targets.mjs (imported by its unit test). */
export interface NativeTarget {
  triple: string;
  elfMachine: number;
  strip: string[];
}
export declare const NATIVE_TARGETS: Record<string, NativeTarget>;
export declare function parseNativeBinDirs(spec: string): Record<string, string>;
export declare function nativeSources(opts: {
  env: Record<string, string | undefined>;
  repoRoot: string;
  hostTag: string;
}): Array<{ tag: string; dir: string }>;
export declare function elfMachine(buf: Uint8Array | null | undefined): number | null;
export declare function nativeBinMismatch(tag: string, buf: Uint8Array | null | undefined): string | null;
export declare function stripCandidates(tag: string, hostTag: string): string[];
