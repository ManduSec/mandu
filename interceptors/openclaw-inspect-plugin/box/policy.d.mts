// Types for policy.mjs (the box's pure decisions; docs/design/agents/openclaw-plugin.md §10).
export declare const PROTECTED_ENV: ReadonlySet<string>;
export declare function mergeCommandEnv(base: Record<string, string | undefined>, requested: Record<string, unknown> | undefined): Record<string, string>;
export declare function commandArgv(command: string, pty: boolean, scriptBin: string | null): string[];
export declare function isInside(root: string, p: string): boolean;
export interface BoxFacts {
  seccomp?: string;
  manduHome?: "hidden" | "absent" | "visible";
  egressProxy?: boolean;
  guardPorts?: boolean;
}
export declare function boxFactsProblems(f: BoxFacts | null | undefined): string[];
