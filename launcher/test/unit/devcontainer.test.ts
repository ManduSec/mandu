/**
 * devcontainer.test — the "Try Mandu" container (.devcontainer/, what the
 * README's "Open in GitHub Codespaces" opens; packaging.md §3.1).
 *
 * Read as text, as node-floor.test.ts reads the other gates: the config is
 * JSONC that parses, it asks for no privilege (Mandu's non-root principle),
 * the image's Node satisfies the package's `engines` and is the installer's
 * pin, the image installs this package, and the attach line points at
 * `mandu demo`. The build itself is scripts/test/devcontainer-demo.test.sh
 * (it needs Docker and the network).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { NODE_FLOOR, nodeMeetsFloor } from "../../src/node-floor.js";

const here = dirname(fileURLToPath(import.meta.url));
const launcherRoot = join(here, "..", "..");
const repoRoot = join(launcherRoot, "..");
const dcDir = join(repoRoot, ".devcontainer");

/** JSONC as devcontainer.json allows it: `//` and block comments, trailing
 *  commas. String-aware, so a `//` inside a value (a URL) stays. */
function parseJsonc(text: string): unknown {
  let out = "";
  let i = 0;
  while (i < text.length) {
    const c = text[i]!;
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
    } else if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      if (end < 0) throw new SyntaxError("unterminated block comment");
      i = end + 2;
    } else {
      out += c;
      i++;
    }
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
}

interface DevContainer {
  name?: string;
  image?: string;
  build?: { dockerfile?: string; context?: string; args?: Record<string, string> };
  remoteUser?: string;
  containerUser?: string;
  runArgs?: string[];
  privileged?: boolean;
  capAdd?: string[];
  securityOpt?: string[];
  postAttachCommand?: string | string[];
  [k: string]: unknown;
}

const config = (): DevContainer => parseJsonc(readFileSync(join(dcDir, "devcontainer.json"), "utf8")) as DevContainer;
const dockerfile = (): string => readFileSync(join(dcDir, config().build?.dockerfile ?? "Dockerfile"), "utf8");
const launcherPkg = (): { name: string; engines?: { node?: string } } =>
  JSON.parse(readFileSync(join(launcherRoot, "package.json"), "utf8"));

test("parseJsonc: comments and trailing commas go, strings stay", () => {
  assert.deepEqual(parseJsonc('// a\n{ "u": "https://x//y", /* b */ "n": [1, 2,], }'), { u: "https://x//y", n: [1, 2] });
  assert.deepEqual(parseJsonc('{ "q": "a \\" // not a comment" }'), { q: 'a " // not a comment' });
  assert.throws(() => parseJsonc("{ /* open"));
});

test("devcontainer.json parses and builds from its Dockerfile", () => {
  const c = config();
  assert.equal(typeof c.name, "string");
  assert.equal(c.image, undefined, "one source of the image: the Dockerfile");
  assert.equal(c.build?.dockerfile, "Dockerfile");
  assert.ok(existsSync(join(dcDir, "Dockerfile")));
});

test("the container asks for no privilege: no runArgs, no privileged, no added capability or security option", () => {
  const c = config();
  assert.equal(c.runArgs, undefined);
  assert.notEqual(c.privileged, true);
  assert.equal(c.capAdd, undefined);
  assert.equal(c.securityOpt, undefined);
  assert.equal(c.mounts, undefined, "no host socket or directory mounted in");
  for (const u of [c.remoteUser, c.containerUser]) assert.notEqual(u, "root");
  assert.equal(c.remoteUser, "node");
  // The image's own last USER is the same non-root user.
  const users = [...dockerfile().matchAll(/^USER\s+(\S+)/gm)].map((m) => m[1]);
  assert.equal(users.at(-1), "node");
});

test("the image's Node satisfies the package's engines and is the installer's pin", () => {
  const from = /^FROM\s+node:(\d+\.\d+\.\d+)-\S+\s*$/m.exec(dockerfile());
  assert.ok(from, "FROM node:<major.minor.patch>-<variant>: an exact version, so it can be checked");
  const version = from[1]!;
  const engines = launcherPkg().engines?.node ?? "";
  const floor = /^>=(\d+\.\d+\.\d+)$/.exec(engines)?.[1];
  assert.ok(floor, `engines.node is a >= floor (${engines})`);
  assert.equal(floor, NODE_FLOOR);
  assert.ok(nodeMeetsFloor(version, floor), `node ${version} satisfies engines ${engines}`);
  const pin = /^NODE_PIN="([0-9.]+)"$/m.exec(readFileSync(join(repoRoot, "scripts", "install.sh"), "utf8"))?.[1];
  assert.equal(version, pin, "the devcontainer's Node moves with scripts/install.sh's NODE_PIN");
});

test("the image installs this package, the published one, as root at build time only", () => {
  const df = dockerfile();
  const name = launcherPkg().name;
  assert.match(df, new RegExp(`npm install -g "${name.replace("/", "\\/")}@\\$\\{MANDU_VERSION\\}"`));
  assert.match(df, /^ARG MANDU_VERSION=latest$/m);
  // The install runs before the switch to the non-root user.
  assert.ok(df.indexOf("npm install -g") < df.search(/^USER node$/m));
});

test("on attach it says, in one line, to run mandu demo and mandu doctor", () => {
  const cmd = config().postAttachCommand;
  assert.equal(typeof cmd, "string");
  assert.match(cmd as string, /^echo '[^'\n]+'$/);
  assert.match(cmd as string, /mandu demo/);
  assert.match(cmd as string, /mandu doctor/);
});

test("the README's Get started links the codespace", () => {
  const readme = readFileSync(join(repoRoot, "README.md"), "utf8");
  const start = readme.indexOf("## Get started");
  const end = readme.indexOf("\n## ", start + 1);
  assert.ok(start >= 0);
  assert.match(readme.slice(start, end), /https:\/\/codespaces\.new\/mandusec\/mandu\?quickstart=1/);
});
