/** Types for checkout-launch.mjs (imported by its tests). */
export declare const STALE_FALLBACK_MESSAGE: string;
export declare function secretsQuiet(argv: readonly string[], env: Record<string, string | undefined>): boolean;
export declare function loadCheckoutSecrets(repoRoot: string, argv: readonly string[], env: Record<string, string | undefined>): Promise<string[]>;
export declare function bundleFresh(distDir: string, repoRoot: string): boolean;
export declare function checkoutPrelude(opts: { repoRoot: string; argv: readonly string[]; env?: Record<string, string | undefined> }): Promise<void>;
