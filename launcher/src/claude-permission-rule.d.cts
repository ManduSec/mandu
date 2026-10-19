/** Types for claude-permission-rule.cjs (the one copy of the rule; its header). */
export type FileScope = "user" | "project" | "local";
export type ModeDecision = { inject: true } | { inject: false; reason: string };

export declare const DEFAULT_PERMISSION_ARGS: readonly string[];
export declare const FILE_SCOPES: readonly FileScope[];
export declare const NO_MODE_SUBCOMMANDS: ReadonlySet<string>;
export declare function takesPermissionMode(args: readonly string[]): boolean;
export declare function argvModeFlag(args: readonly string[]): string | null;
export declare function argvFileScopes(args: readonly string[]): FileScope[];
export declare function settingsDefaultMode(doc: unknown): string | null;
export declare function optionValues(args: readonly string[], name: string): string[];
export declare function argvModeChoice(args: readonly string[], parseValue: (value: string) => unknown): string | null;
export declare function permissionModeDecision(
  args: readonly string[],
  parseValue: (value: string) => unknown,
  scopeChoice: (fileScopes: readonly FileScope[]) => string | null,
): ModeDecision;
export declare function withPermissionMode(args: readonly string[], decision: ModeDecision): string[];
export declare function realExecutable(
  name: string, pathValue: string | undefined, skipDir: string, fs: typeof import("node:fs"), path: typeof import("node:path"),
): string | null;
