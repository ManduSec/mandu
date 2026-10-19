/**
 * server/static-routes — static UI + slides serving (extracted VERBATIM from
 * src/server.ts in the server.ts decomposition; adapted originally from the
 * reference server.ts — see the src/server.ts provenance header). All routes
 * sit behind the source-IP gate + isAuthed in server.ts.
 */

import { type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, extname } from "node:path";

import { etagMatches, sendBody } from "./http-util.js";

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".woff2": "font/woff2",
};

export function serveIndex(
  publicDir: string,
  basePath: string,
  res: ServerResponse,
  meta: Record<string, string> = {},
  /** Further asset dirs the page links into (the inspector links the
   *  product's shared ../mandu.css, §4.25k): their mtimes bump the token too. */
  versionDirs: string[] = [],
  /** The front-end's directory under the base path (`/` for the product,
   *  `/dev/` for the inspector): the injected `<base href>`, so the page's
   *  relative asset and link URLs resolve from a nested route such as
   *  `/agents/<id>` exactly as they do from the front-end's root (§4.25v). */
  baseDir = "/",
): void {
  const htmlPath = join(publicDir, "index.html");
  if (!existsSync(htmlPath)) {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("index.html not found");
    return;
  }
  let html = readFileSync(htmlPath, "utf-8");
  // Inject the base path so client fetches resolve under a reverse proxy.
  // Extra flags (e.g. slides=on) and the product's home folder ride along as
  // <meta> tags the client reads; a value is escaped (a folder name may hold
  // `"` or `<`).
  const extra = Object.entries(meta).map(([k, v]) => `\n<meta name="${k}" content="${attr(v)}">`).join("");
  // The <base> comes FIRST in <head>, before any element with a relative URL.
  html = html.replace("<head>", `<head>\n<base href="${attr(basePath + baseDir)}">\n<meta name="base-path" content="${basePath}">${extra}`);
  // Cache-bust the static assets: append ?v=<token> (the newest asset mtime) to
  // every local css/js reference. The URL changes whenever an asset changes,
  // so a normal refresh always loads the latest UI, and serveStatic may let
  // the browser keep a versioned asset (assetCacheControl). (urlPath strips
  // the query, so the versioned URL still routes to serveStatic.)
  const v = assetVersion([publicDir, ...versionDirs]);
  html = html.replace(/\b(href|src)="((?:\.\.\/|js\/)?[A-Za-z0-9_.-]+\.(?:css|js))"/g, `$1="$2?v=${v}"`);
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(html);
}

/** A cache-busting token: the newest mtime (base-36) across the served static
 *  assets (index.html + every css/js at the root and under js/). Recomputed
 *  per index request, so any UI edit bumps every asset URL. Works for both
 *  front-ends (§4.25): neither directory's file list is hard-coded. */
function assetVersion(roots: string[]): string {
  let max = 0;
  const consider = (p: string): void => {
    try {
      max = Math.max(max, statSync(p).mtimeMs);
    } catch { /* ignore an unreadable asset */ }
  };
  for (const dir of roots.flatMap((r) => [r, join(r, "js")])) {
    let names: string[] = [];
    try {
      names = readdirSync(dir);
    } catch {
      continue;
    }
    for (const f of names) if (/\.(?:html|css|js)$/.test(f)) consider(join(dir, f));
  }
  return Math.floor(max).toString(36) || "0";
}

/** `/dev` (no slash) → `/dev/`, query kept: the inspector's root (§4.25). */
export function redirectToDir(basePath: string, dir: string, rawUrl: string, res: ServerResponse): void {
  const q = rawUrl.includes("?") ? rawUrl.slice(rawUrl.indexOf("?")) : "";
  redirectTo(basePath, `${dir}/${q}`, res);
}

/** A 302 to a base-stripped location under the base path (also the retired
 *  query-string page URLs, page-routes.ts legacyRedirect). */
export function redirectTo(basePath: string, location: string, res: ServerResponse): void {
  res.writeHead(302, { Location: `${basePath}${location}`, "Cache-Control": "no-store" });
  res.end();
}

/** An HTML attribute value: the base path is operator config, escaped anyway. */
function attr(v: string): string {
  return v.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
}

/**
 * GET /slides/<file> — a prepared deck from the configured slides directory
 * (MANDU_SLIDES_DIR), linked from the Settings drawer. Read-only and OFF the
 * security path: a flat-filename whitelist (no traversal), only MIME-known
 * extensions (html), and 404 when no directory is configured or the file is
 * missing.
 */
export function serveSlides(slidesDir: string, urlPath: string, res: ServerResponse): void {
  const name = urlPath.slice("/slides/".length);
  const mime = MIME_TYPES[extname(name)];
  if (slidesDir && mime && /^[a-zA-Z0-9_.-]+$/.test(name)) {
    const filePath = join(slidesDir, name);
    if (existsSync(filePath)) {
      res.writeHead(200, { "Content-Type": mime, "Cache-Control": "no-store" });
      res.end(readFileSync(filePath));
      return;
    }
  }
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
}

/** The developer view's mount, in a build that does not carry it. */
export const DEV_MOUNT = "/dev";

/** Is this a page under `/dev` (the mount, or a path whose last segment
 *  names no file)? Its files (`/dev/js/app.js`) are not pages. */
export function isDevPagePath(urlPath: string): boolean {
  if (urlPath !== DEV_MOUNT && !urlPath.startsWith(DEV_MOUNT + "/")) return false;
  return extname(urlPath.slice(urlPath.lastIndexOf("/") + 1)) === "";
}

/**
 * A page under `/dev` in a build without the developer view (dashboard.md
 * §4.25ac *A page under `/dev` without it*): still a 404, but a page that
 * says what is missing, that the developer view is available on request, and
 * where this build shows a session's trace. It wears the product's
 * stylesheets and links back to the product page; it carries no script.
 */
export function serveDevAbsent(basePath: string, res: ServerResponse): void {
  const base = attr(basePath + "/");
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<base href="${base}">
<title>Developer view not included · Mandu</title>
<link rel="stylesheet" href="mandu.css">
<link rel="stylesheet" href="app.css">
</head>
<body>
<header id="top"><div class="top-inner"><a class="brand" href="./">Mandu</a></div></header>
<main id="main">
  <section class="block card" id="dev-absent" aria-labelledby="dev-absent-title">
    <h1 id="dev-absent-title">The developer view is not included in this version</h1>
    <p>This Mandu dashboard is the public version. The developer view, with every session's full event log, the test tools and the drill runner, is available on request: write to <a href="mailto:hello@mandusecurity.com">hello@mandusecurity.com</a>.</p>
    <p>What happened in a session is on its own page here: open it from Home or History, and it shows what the AI saw beside what really happened.</p>
    <p><a class="btn link-btn" href="./">Back to Mandu</a></p>
  </section>
</main>
</body>
</html>
`;
  res.writeHead(404, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(html);
}

export function serveStatic(publicDir: string, urlPath: string, res: ServerResponse, req?: IncomingMessage): void | Promise<void> {
  const ext = extname(urlPath);
  const mime = MIME_TYPES[ext];
  const relPath = urlPath.slice(1); // strip leading /
  // Allow files at root, in js/, the self-hosted fonts/ (§4.25k), and one
  // vendored library dir under vendor/ (asciinema-player for the Watch area);
  // reject traversal.
  if (mime && relPath && /^(js\/|fonts\/|vendor\/[a-zA-Z0-9_.-]+\/)?[a-zA-Z0-9_.-]+$/.test(relPath)) {
    const filePath = join(publicDir, relPath);
    let st;
    try { st = statSync(filePath, { throwIfNoEntry: false }); } catch { st = undefined; }
    if (st?.isFile()) {
      const versioned = req !== undefined && /[?&]v=/.test(req.url ?? "");
      const cache = assetCacheControl(ext, versioned);
      const etag = `W/"${st.size.toString(36)}-${Math.floor(st.mtimeMs).toString(36)}"`;
      if (req && etagMatches(req, etag)) {
        res.writeHead(304, { ETag: etag, "Cache-Control": cache, Vary: "Accept-Encoding" });
        res.end();
        return;
      }
      const headers = { "Content-Type": mime, "Cache-Control": cache, ETag: etag };
      if (!req || ext === ".woff2") {
        res.writeHead(200, headers);
        res.end(readFileSync(filePath));
        return;
      }
      return sendBody(req, res, 200, headers, readFileSync(filePath), `${filePath}\u0000${etag}`);
    }
  }
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
}

/**
 * The asset caching rule (dashboard.md §4.30). serveIndex stamps every css/js
 * URL it writes with `?v=<newest asset mtime>`, so a VERSIONED request names
 * bytes that never change under that URL: the browser keeps it a year without
 * asking. An unversioned one (a module's own relative import, a hand-typed
 * URL) is revalidated on every use (`no-cache` + the ETag: a 304 when
 * unchanged). A font never changes under its name (the weight and subset are
 * in it). index.html itself stays no-store (serveIndex), so a refresh always
 * picks up the newest token.
 */
export function assetCacheControl(ext: string, versioned: boolean): string {
  if (ext === ".woff2") return "private, max-age=604800";
  return versioned ? "private, max-age=31536000, immutable" : "no-cache";
}
