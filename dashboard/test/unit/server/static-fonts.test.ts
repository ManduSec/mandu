/**
 * static-fonts.test — the self-hosted fonts route of serveStatic
 * (server/static-routes.ts, dashboard.md §4.25k). The shared mandu.css names
 * url(fonts/<file>.woff2); both front-ends resolve that to <base>/fonts/…,
 * which serveStatic answers from public/fonts/.
 *
 * Mandu-new test (NO reference origin). Drives serveStatic directly over a
 * temp directory with a recording response, and pins:
 *   - a .woff2 under fonts/ is served as font/woff2 with a max-age (a font file
 *     never changes under its name), while an unversioned css/js is
 *     revalidated (no-cache; static-cache.test.ts covers the versioned rule);
 *   - only MIME-known files are served from fonts/ (the license .txt beside
 *     the fonts is not an asset), and nothing deeper than fonts/<file>;
 *   - traversal out of the directory 404s.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ServerResponse } from "node:http";

import { serveStatic } from "../../../src/server/static-routes.js";
import { tmpDir } from "../tmp-dir.js";

const DIR = tmpDir("mandu-static-fonts-");
mkdirSync(join(DIR, "fonts", "sub"), { recursive: true });
writeFileSync(join(DIR, "fonts", "face-400-normal.woff2"), Buffer.from("wOF2-fake-font-bytes"));
writeFileSync(join(DIR, "fonts", "LICENSE-face.txt"), "SIL Open Font License");
writeFileSync(join(DIR, "fonts", "sub", "deep.woff2"), Buffer.from("wOF2"));
writeFileSync(join(DIR, "mandu.css"), ":root{}");
writeFileSync(join(DIR, "face.woff2"), Buffer.from("wOF2-root"));

interface Recorded { status: number; headers: Record<string, string>; body: Buffer | string }

function call(urlPath: string): Recorded {
  const rec: Recorded = { status: 0, headers: {}, body: "" };
  const res = {
    writeHead(status: number, headers: Record<string, string> = {}) {
      rec.status = status;
      rec.headers = headers;
      return this;
    },
    end(body?: Buffer | string) {
      rec.body = body ?? "";
    },
  } as unknown as ServerResponse;
  serveStatic(DIR, urlPath, res);
  return rec;
}

test("a font under fonts/ is served as font/woff2 and may be cached", () => {
  const r = call("/fonts/face-400-normal.woff2");
  assert.equal(r.status, 200);
  assert.equal(r.headers["Content-Type"], "font/woff2");
  assert.match(r.headers["Cache-Control"] ?? "", /^private, max-age=\d+$/);
  assert.equal(String(r.body), "wOF2-fake-font-bytes");
});

test("an unversioned stylesheet is revalidated beside the cached fonts", () => {
  const r = call("/mandu.css");
  assert.equal(r.status, 200);
  assert.equal(r.headers["Cache-Control"], "no-cache");
  assert.match(r.headers["ETag"] ?? "", /^W\/"/, "with a validator to revalidate against");
});

test("fonts/ serves only MIME-known files, one level deep, and never traverses out", () => {
  assert.equal(call("/fonts/LICENSE-face.txt").status, 404, "the license beside the fonts is not an asset");
  assert.equal(call("/fonts/sub/deep.woff2").status, 404, "nothing deeper than fonts/<file>");
  assert.equal(call("/fonts/../mandu.css").status, 404, "no .. segments");
  assert.equal(call("/fonts/missing.woff2").status, 404);
  assert.equal(call("/face.woff2").status, 200, "a root-level asset of a known type still serves");
});
