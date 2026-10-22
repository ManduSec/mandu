#!/usr/bin/env node
/**
 * release-assets.mjs — the files a GitHub release carries beside the tarball
 * release-pack.sh built (docs/design/distribution/packaging.md §11.3; run by
 * .github/workflows/release.yml after the pack).
 *
 * From release-pack's output directory (mandusec-mandu-<v>.tgz, SHA256SUMS) it
 *   - checks the tarball against SHA256SUMS;
 *   - writes <dir>/install.sh, a RELEASE COPY of scripts/install.sh whose
 *     default package is that release's tarball URL with its SHA-256, so
 *     `curl …/releases/latest/download/install.sh | sh` (or `sh install.sh`
 *     beside the tarball) installs exactly the published file or nothing;
 *   - with --notes-in, writes the release notes: the release tag's message
 *     (a PGP signature block dropped) and a last line naming the tarball and
 *     its SHA-256;
 *   - prints `key=value` lines (version, tag, tarball, sha256, sha1) for
 *     $GITHUB_OUTPUT. `sha1` is what npm records as `dist.shasum`.
 *
 * Usage:
 *   node scripts/ci/release-assets.mjs --dir DIR [--repo OWNER/NAME]
 *        [--notes-in FILE --notes-out FILE] [--install FILE]
 *
 *   --repo     the GitHub repository whose release the URL names
 *              (default $GITHUB_REPOSITORY, else ManduSec/mandu)
 *   --install  the install.sh to copy (default scripts/install.sh of this tree)
 *
 * Exit: 0 written; 1 refused (bad checksum, no tarball, no hook lines); 2 usage.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_REPO = "ManduSec/mandu";

/** The tarball URL a release's install.sh downloads (an immutable, versioned path). */
export function tarballUrl(repo, version) {
  return `https://github.com/${repo}/releases/download/v${version}/mandusec-mandu-${version}.tgz`;
}

/** install.sh with its default package set to `url` and `sha256`; throws if the hook lines moved. */
export function releaseInstaller(src, url, sha256) {
  if (!/^[0-9a-f]{64}$/.test(sha256)) throw new Error(`not a SHA-256: ${sha256}`);
  let n = 0;
  const out = src
    .replace(/^PACKAGE_DEFAULT=".*"$/m, () => (n++, `PACKAGE_DEFAULT="${url}"`))
    .replace(/^PACKAGE_DEFAULT_SHA256=".*"$/m, () => (n++, `PACKAGE_DEFAULT_SHA256="${sha256}"`));
  if (n !== 2) throw new Error("install.sh has no PACKAGE_DEFAULT / PACKAGE_DEFAULT_SHA256 lines to set");
  return out;
}

/** The one tarball in a release-pack dir, its version, and its checked SHA-256 (and SHA-1). */
export function readBuild(dir) {
  const tgz = readdirSync(dir).filter((f) => /^mandusec-mandu-.+\.tgz$/.test(f));
  if (tgz.length !== 1) throw new Error(`${dir}: expected one mandusec-mandu-<v>.tgz, found ${tgz.length}`);
  const name = tgz[0];
  const version = name.slice("mandusec-mandu-".length, -".tgz".length);
  const sums = join(dir, "SHA256SUMS");
  if (!existsSync(sums)) throw new Error(`${dir}: no SHA256SUMS`);
  const listed = readFileSync(sums, "utf8").split("\n").map((l) => l.trim().split(/\s+/)).find((p) => p[1] === name)?.[0];
  const bytes = readFileSync(join(dir, name));
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  if (listed !== sha256) throw new Error(`${name}: SHA256SUMS says ${listed ?? "nothing"}, the file is ${sha256}`);
  return { name, version, sha256, sha1: createHash("sha1").update(bytes).digest("hex") };
}

/**
 * The release notes: the tag's message without a trailing PGP signature, then
 * the tarball line. An empty message is refused: the notes are what a reader
 * of the release page gets, and the tag is where the maintainer wrote them.
 */
export function releaseNotes(tagMessage, name, sha256) {
  const body = tagMessage.replace(/\n?-----BEGIN PGP SIGNATURE-----[\s\S]*$/, "").trimEnd();
  if (!body.trim()) throw new Error("the release tag has no message: write the release notes into the annotated tag");
  return `${body}\n\n\`${name}\` sha256 \`${sha256}\`\n`;
}

export function parseArgs(argv, env = process.env) {
  const o = { repo: env.GITHUB_REPOSITORY || DEFAULT_REPO, install: resolve(HERE, "..", "install.sh") };
  const takes = { "--dir": "dir", "--repo": "repo", "--notes-in": "notesIn", "--notes-out": "notesOut", "--install": "install" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (takes[a] && argv[i + 1] !== undefined) o[takes[a]] = argv[++i];
    else throw new Error(`unknown or incomplete argument: ${a}`);
  }
  if (!o.dir) throw new Error("--dir is required");
  if (!/^[\w.-]+\/[\w.-]+$/.test(o.repo)) throw new Error(`--repo takes OWNER/NAME, not ${o.repo}`);
  if (!o.notesIn !== !o.notesOut) throw new Error("--notes-in and --notes-out go together");
  return o;
}

export function main(argv) {
  let o;
  try { o = parseArgs(argv); } catch (e) { console.error(`release-assets: ${e.message}`); return 2; }
  try {
    const b = readBuild(o.dir);
    writeFileSync(join(o.dir, "install.sh"),
      releaseInstaller(readFileSync(o.install, "utf8"), tarballUrl(o.repo, b.version), b.sha256), { mode: 0o755 });
    if (o.notesIn) writeFileSync(o.notesOut, releaseNotes(readFileSync(o.notesIn, "utf8"), b.name, b.sha256));
    console.log([`version=${b.version}`, `tag=v${b.version}`, `tarball=${b.name}`, `sha256=${b.sha256}`, `sha1=${b.sha1}`].join("\n"));
    return 0;
  } catch (e) {
    console.error(`release-assets: ${e.message}`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exitCode = main(process.argv.slice(2));
}
