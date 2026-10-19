/** Types for build-info.mjs (imported by src/version-report.ts and its tests). */
export interface BuildInfo {
  version: string | null;
  /** The source repository's commit, or null when not recorded. */
  sourceCommit: string | null;
  /** The public repository's commit, or null when not recorded. */
  publicCommit: string | null;
  /** Commits on top of that public snapshot (a public clone with local work). */
  publicAhead: number;
  /** Uncommitted changes in the built tree; null when there was no git. */
  dirty: boolean | null;
}
export interface GitFacts {
  repo: "source" | "public";
  sourceCommit: string;
  publicCommit: string | null;
  publicAhead: number;
  dirty: boolean | null;
}
export type GitRun = (dir: string, args: string[]) => string | null;
export declare const BUILD_INFO_NAME: string;
export declare const SNAPSHOT_TRAILER: string;
export declare function commitOrNull(v: unknown): string | null;
export declare function gitFacts(dir: string, git?: GitRun, same?: (a: string, b: string) => boolean): GitFacts | null;
export declare function resolveBuildInfo(opts: {
  repoRoot: string;
  env?: Record<string, string | undefined>;
  git?: GitRun;
  readFile?: (p: string) => string;
}): BuildInfo;
export declare function writeBuildInfo(distDir: string, info: BuildInfo): void;
export declare function readBuildInfo(distDir: string, readFile?: (p: string) => string): BuildInfo | null;
