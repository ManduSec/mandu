/**
 * release-version — the Mandu release this arbiter's code belongs to, for the
 * `hello` handshake (runtime-instances.md §4.1).
 *
 * The product carries ONE version in every manifest (packaging.md §11.2,
 * `launcher/test/unit/version-parity.test.ts`). The arbiter reads it from the
 * package.json one level above its own module: from source that is
 * `arbiter/package.json` (this file is `arbiter/ipc/release-version.ts`); in
 * the bundle it is the package root beside `dist/` (`dist/arbiter.mjs` →
 * `<pkg>/package.json`; in a checkout's own build, `launcher/package.json`).
 * The launcher compares it with its own version before it uses the arbiter,
 * so an arbiter left running across an upgrade is restarted or refused,
 * never silently used. "unknown" when the file cannot be read: the launcher
 * treats that as a mismatch, never as a match.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code; mirrors
 * launcher/src/update-check.ts `launcherVersion`.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

let cached: string | undefined;

/** The release version (`0.2.0-beta.5`), or "unknown". Read once. */
export function releaseVersion(): string {
  if (cached !== undefined) return cached;
  try {
    const pkg = resolve(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
    const v = (JSON.parse(readFileSync(pkg, "utf8")) as { version?: unknown }).version;
    cached = typeof v === "string" && v.trim() !== "" ? v.trim() : "unknown";
  } catch {
    cached = "unknown";
  }
  return cached;
}
