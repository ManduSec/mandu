/** Types for mandu-paths.mjs (imported by the cross-package parity test). */
export type PathEnv = Readonly<Record<string, string | undefined>>;
export interface BaseDef {
  chain: string[];
  fallback: ["home" | "abs", string];
}
export interface PathDef {
  name: string;
  base: string;
  rel: string;
  kind: "dir" | "file";
  mode: number | null;
  agentReadable: boolean;
  env: string | null;
  note: string;
}
export declare const BASES: Record<string, BaseDef>;
export declare const PATHS: PathDef[];
export declare const FIXTURES: Array<[string, Record<string, string>, string]>;
export declare const COPIES: Array<{ lang: "ts" | "rust" | "sh"; path: string }>;
export declare function resolveBase(name: string, env: PathEnv, home: string): string;
export declare function resolvePath(name: string, env: PathEnv, home: string): string;
export declare function tableProblems(): string[];
export declare function generateTs(): string;
export declare function generateRust(): string;
export declare function generateSh(): string;
export declare function expectedCopies(): Array<{ lang: "ts" | "rust" | "sh"; path: string; text: string }>;
export declare function staleCopies(root?: string): string[];
