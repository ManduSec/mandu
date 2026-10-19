/**
 * classifier-pack-command — `mandu policy classifier-pack`
 * (docs/design/confidentiality/confidentiality-plan-15-prompt-filter.md
 * §13.5 item 15): writes, on stdout, the pack that installs Mandu's
 * reference classifier plugin, pinning `node` and the classifier THIS
 * install ships by their SHA-256.
 *
 * The classifier and its pack writer are package assets
 * (bundle-manifest.json `assets`, `prompt-filters/…`): `dist/prompt-filters/`
 * in an installed package, `arbiter/prompt-filter/plugins/` in a checkout
 * (Layout.asset). Before 2026-10-07 a release did not ship them: the
 * documented command named a checkout path, so an installed user could not
 * write the pack, and the classifier did nothing (no pack, no filter; a
 * switch turned on without its pack fails per its `on_error`, engine.ts).
 *
 * The pack writer runs under the node running this command (its pin is that
 * node's real path). Its options pass through: `--id`, `--categories`,
 * `--deadline-ms`, `--node`.
 *
 * Mandu-new (no reference origin).
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import type { Layout } from "./services/layout.js";

export const CLASSIFIER_ASSET = "prompt-filters/local-classifier.mjs";
export const CLASSIFIER_PACK_ASSET = "prompt-filters/local-classifier-pack.mjs";

/** The options the pack writer takes (each with one value). */
const OPTIONS = new Set(["--id", "--categories", "--deadline-ms", "--node"]);

export interface ClassifierPackDeps {
  exists: (p: string) => boolean;
  run: (cmd: string, args: string[]) => { status: number | null; stdout: string; stderr: string };
  out: (s: string) => void;
  err: (s: string) => void;
  node: string;
}

export const realClassifierPackDeps = (): ClassifierPackDeps => ({
  exists: existsSync,
  run: (cmd, args) => {
    const r = spawnSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? (r.error ? String(r.error.message) : "") };
  },
  out: (s) => { process.stdout.write(s); },
  err: (s) => { process.stderr.write(s); },
  node: process.execPath,
});

/** `mandu policy classifier-pack [--id <id>] [--categories a,b] [--deadline-ms N] [--node <path>]`. */
export function runClassifierPack(rest: string[], layout: Pick<Layout, "asset">, deps: ClassifierPackDeps = realClassifierPackDeps()): number {
  for (let i = 0; i < rest.length; i += 2) {
    const a = rest[i]!;
    if (!OPTIONS.has(a) || rest[i + 1] === undefined || rest[i + 1]!.startsWith("--")) {
      deps.err(`mandu policy classifier-pack: ${OPTIONS.has(a) ? `${a} needs a value` : `unknown option '${a.replace(/[^\x20-\x7e]/g, "?")}'`} (see \`mandu policy --help\`)\n`);
      return 2;
    }
  }
  let pack: string;
  let classifier: string;
  try {
    pack = layout.asset(CLASSIFIER_PACK_ASSET);
    classifier = layout.asset(CLASSIFIER_ASSET);
  } catch (e) {
    deps.err(`mandu policy classifier-pack: ${(e as Error).message}\n`);
    return 1;
  }
  for (const p of [pack, classifier]) {
    if (!deps.exists(p)) {
      deps.err(`mandu policy classifier-pack: this install does not ship the reference classifier (${p} is missing); reinstall Mandu\n`);
      return 1;
    }
  }
  const r = deps.run(deps.node, [pack, ...rest]);
  if (r.status !== 0) {
    deps.err(`mandu policy classifier-pack: the pack writer failed (exit ${r.status ?? "on a signal"})${r.stderr ? `: ${r.stderr.trim().split("\n")[0]}` : ""}\n`);
    return 1;
  }
  deps.out(r.stdout);
  return 0;
}
