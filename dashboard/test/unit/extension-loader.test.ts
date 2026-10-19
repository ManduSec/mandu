/**
 * extension-loader.test — how server-main finds the developer view
 * (src/extension-loader.ts, dashboard.md §4.25ac): a bundle's sibling
 * `dashboard-dev.mjs` first, else from source the module package.json names
 * in `mandu.devExtension`; nothing else (no environment variable names a
 * module). A module that is missing, fails to load or exports no factory
 * costs the developer view only: the server gets no extensions and the log
 * says why. And server-main's static imports never reach the developer
 * view's code, so a tree without it still builds and serves the product.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { loadExtensions, resolveExtensionModule, type ExtensionBootContext } from "../../src/extension-loader.js";
import { tmpDir } from "./tmp-dir.js";

const SRC = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "src");

const files = (m: Record<string, string>) => ({
  exists: (p: string) => p in m,
  read: (p: string) => {
    if (!(p in m)) throw new Error(`ENOENT ${p}`);
    return m[p]!;
  },
});

test("a bundle's dashboard-dev.mjs beside it wins", () => {
  const f = files({ "/pkg/dist/dashboard-dev.mjs": "" });
  assert.equal(resolveExtensionModule("/pkg/dist", f.exists, f.read), "/pkg/dist/dashboard-dev.mjs");
  assert.equal(resolveExtensionModule("/pkg/dist", files({}).exists, files({}).read), null, "a bundle without it: none");
});

test("from source: the module package.json names, when it exists; nothing else", () => {
  const pkg = JSON.stringify({ mandu: { devExtension: "src/devview/index.ts" } });
  const f = files({ "/r/dashboard/package.json": pkg, "/r/dashboard/src/devview/index.ts": "" });
  assert.equal(resolveExtensionModule("/r/dashboard/src", f.exists, f.read), "/r/dashboard/src/devview/index.ts");
  const gone = files({ "/r/dashboard/package.json": pkg });
  assert.equal(resolveExtensionModule("/r/dashboard/src", gone.exists, gone.read), null, "named but absent (the public tree)");
  for (const body of [JSON.stringify({ mandu: {} }), JSON.stringify({}), "{not json", JSON.stringify({ mandu: { devExtension: 3 } })]) {
    const g = files({ "/r/dashboard/package.json": body, "/r/dashboard/src/devview/index.ts": "" });
    assert.equal(resolveExtensionModule("/r/dashboard/src", g.exists, g.read), null, body);
  }
});

test("the real package names the inspector's entry, and it is there in this tree or not at all", () => {
  const path = resolveExtensionModule(SRC);
  const declared = (JSON.parse(readFileSync(join(SRC, "..", "package.json"), "utf8")) as { mandu?: { devExtension?: string } }).mandu?.devExtension;
  if (declared && existsSync(resolve(SRC, "..", declared))) assert.equal(path, resolve(SRC, "..", declared));
  else assert.equal(path, null);
});

function ctx(log: string[]): ExtensionBootContext {
  return { repoRoot: "/r", arbiterSock: "/s", testArbiterSock: "/t", testEventDir: "/e", publicDir: "/p", env: {}, log: (m) => log.push(m) };
}

test("a bundle without the module: no extensions, and the log says the product page only", async () => {
  const log: string[] = [];
  assert.deepEqual(await loadExtensions(tmpDir("ext-none-"), ctx(log)), []);
  assert.match(log.join("\n"), /product page only/);
});

test("a module that throws, or exports no factory, costs the developer view only", async () => {
  for (const [body, why] of [
    ["throw new Error('boom');", /boom/],
    ["export const x = 1;", /createDashboardExtensions/],
    ["export function createDashboardExtensions() { throw new Error('no pages'); }", /no pages/],
  ] as const) {
    const dir = tmpDir("ext-bad-");
    writeFileSync(join(dir, "dashboard-dev.mjs"), body);
    const log: string[] = [];
    assert.deepEqual(await loadExtensions(dir, ctx(log)), [], body);
    assert.match(log.join("\n"), why, body);
    assert.match(log.join("\n"), /product page only/, body);
  }
});

test("a module's extensions are handed back, built from the context", async () => {
  const dir = tmpDir("ext-ok-");
  writeFileSync(join(dir, "dashboard-dev.mjs"), "export function createDashboardExtensions(c) { return [{ name: 'probe', mount: '/probe', handle() {}, repo: c.repoRoot }]; }");
  const log: string[] = [];
  const got = await loadExtensions(dir, ctx(log)) as unknown as Array<{ name: string; repo: string }>;
  assert.deepEqual(got.map((x) => [x.name, x.repo]), [["probe", "/r"]]);
});

// ── server-main's static imports never reach the developer view ────────────

/** Every module `entry` imports, statically, transitively (type imports too:
 *  tsc needs them). Only relative imports inside this package. */
function staticClosure(entry: string): Set<string> {
  const seen = new Set<string>();
  const re = /(?:^|\n)\s*(?:import|export)\s[^;]*?from\s*["']([^"']+)["']|(?:^|\n)\s*import\s*["']([^"']+)["']/g;
  const stack = [entry];
  while (stack.length) {
    const f = stack.pop()!;
    if (seen.has(f)) continue;
    seen.add(f);
    for (const m of readFileSync(f, "utf8").matchAll(re)) {
      const spec = m[1] ?? m[2]!;
      if (!spec.startsWith(".")) continue;
      const base = resolve(dirname(f), spec);
      const hit = [base.replace(/\.js$/, ".ts"), base.replace(/\.mjs$/, ".mts"), base].find((p) => existsSync(p));
      if (hit) stack.push(hit);
    }
  }
  return seen;
}

/** The developer view's code: its extension, its runners and run stores,
 *  and the recorded sources only its session list joins. */
const DEV_ONLY = [
  /\/src\/inspector\//, /\/src\/test-runs\//, /\/src\/drill-runs\.ts$/, /\/src\/drill-run-store\.ts$/, /\/src\/drill-matrix\.ts$/,
  /\/src\/drill-tree\.ts$/, /\/src\/coverage-view\.ts$/, /\/src\/matrix-runs\.ts$/, /\/src\/ci-runs\.ts$/, /\/src\/replay-run-store\.ts$/,
  /\/src\/listing-cache-file\.ts$/, /\/src\/scenario-cache-file\.ts$/, /\/src\/agent-runner\.ts$/, /\/src\/fs-view\.ts$/, /\/src\/git\.ts$/,
  /\/src\/final-state\.ts$/, /\/src\/run-samples\.ts$/, /\/src\/context-pack\.ts$/, /\/src\/view-model\/why-symbol\.ts$/,
  /\/src\/event-source\/(recorded|ci-live|own-arbiter)-source\.ts$/,
];

test("nothing server-main imports, however indirectly, is the developer view's code", () => {
  const reached = [...staticClosure(join(SRC, "server-main.ts"))];
  assert.ok(reached.length > 40, `the walk found the server (${reached.length})`);
  const dev = reached.filter((f) => DEV_ONLY.some((re) => re.test(f))).map((f) => f.slice(SRC.length + 1));
  assert.deepEqual(dev, [], "a public module imports the developer view's code: move the import behind the extension (dashboard.md §4.25ac)");
});
