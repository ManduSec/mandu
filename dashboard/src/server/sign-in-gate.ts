/**
 * server/sign-in-gate — the dashboard's sign-in page, its sessions and its
 * throttle (dashboard.md §6.z "The sign-in page"). Mandu-new.
 *
 * The pieces server.ts `handle()` puts together as the third gate (after the
 * source-IP allowlist and the Host check, before every route):
 *   - `SignInSessions`: random session ids held in this process (a restart
 *     ends them), 12 h idle and 7 days at most, ended by Sign out and by a
 *     change of the account file;
 *   - `SignInThrottle`: failed sign-ins counted for the whole dashboard, not
 *     per address (a tunnel's requests all come from loopback);
 *   - `signInPage`: the page itself, self-contained (inline CSS, no script,
 *     no app data);
 *   - the request helpers: is it a browser navigation, is a POST from this
 *     dashboard's own page (login CSRF), where to go after (no open
 *     redirect), did it arrive over HTTPS (the cookie's Secure).
 */

import { createHash, randomBytes } from "node:crypto";
import { type IncomingMessage } from "node:http";

/** The sign-in session's cookie. Not `mandu_session` (the password and
 *  one-time-link session's), so DASHBOARD_PASSWORD set beside the account
 *  keeps its own cookie. */
export const SIGN_IN_COOKIE = "mandu_signin";

export const SESSION_IDLE_MS = 12 * 3_600_000;
export const SESSION_MAX_MS = 7 * 24 * 3_600_000;
/** Sessions held at once; the oldest goes first. */
export const SESSION_CAP = 64;

/** The throttle: this many failures within the window lock sign-in. */
export const THROTTLE_FAILURES = 5;
export const THROTTLE_WINDOW_MS = 60_000;
/** The first lock; each further one doubles, up to the cap. */
export const THROTTLE_FIRST_LOCK_MS = 30_000;
export const THROTTLE_MAX_LOCK_MS = 15 * 60_000;
/** An hour without a failure forgets the earlier locks. */
export const THROTTLE_FORGET_MS = 3_600_000;

const idKey = (id: string): string => createHash("sha256").update(id).digest("hex");

/** The sign-in sessions of this process. Ids are held by their digest, so
 *  a lookup never compares the secret itself. */
export class SignInSessions {
  private readonly byKey = new Map<string, { created: number; seen: number }>();
  constructor(private readonly now: () => number = Date.now) {}

  /** A new session; its id is the cookie's value. */
  create(): string {
    const id = randomBytes(32).toString("base64url");
    const t = this.now();
    this.byKey.set(idKey(id), { created: t, seen: t });
    while (this.byKey.size > SESSION_CAP) {
      const oldest = this.byKey.keys().next().value as string;
      this.byKey.delete(oldest);
    }
    return id;
  }

  /** Is `id` a live session? A live one is touched (its idle time restarts). */
  valid(id: string): boolean {
    if (!/^[A-Za-z0-9_-]{43}$/.test(id)) return false;
    const k = idKey(id);
    const s = this.byKey.get(k);
    if (!s) return false;
    const t = this.now();
    if (t - s.seen > SESSION_IDLE_MS || t - s.created > SESSION_MAX_MS) {
      this.byKey.delete(k);
      return false;
    }
    s.seen = t;
    return true;
  }

  drop(id: string): void {
    this.byKey.delete(idKey(id));
  }

  dropAll(): void {
    this.byKey.clear();
  }

  get size(): number {
    return this.byKey.size;
  }
}

/** The sign-in cookie's value in a request, or null. */
export function signInCookieOf(req: IncomingMessage): string | null {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === SIGN_IN_COOKIE) return v.join("=");
  }
  return null;
}

/** Failed sign-ins for the whole dashboard. Never locks for good: the
 *  longest lock is THROTTLE_MAX_LOCK_MS. */
export class SignInThrottle {
  private failures: number[] = [];
  private lockedUntil = 0;
  private strikes = 0;
  private lastFailure = 0;
  constructor(private readonly now: () => number = Date.now) {}

  /** Milliseconds left of a lock; 0 when a sign-in may be tried. */
  waitMs(): number {
    return Math.max(0, this.lockedUntil - this.now());
  }

  /** Count a failure; answers the lock it started (0: none). */
  fail(): number {
    const t = this.now();
    if (t - this.lastFailure > THROTTLE_FORGET_MS) this.strikes = 0;
    this.lastFailure = t;
    this.failures = this.failures.filter((f) => t - f < THROTTLE_WINDOW_MS);
    this.failures.push(t);
    if (this.failures.length < THROTTLE_FAILURES) return 0;
    const lock = Math.min(THROTTLE_MAX_LOCK_MS, THROTTLE_FIRST_LOCK_MS * 2 ** this.strikes);
    this.strikes += 1;
    this.failures = [];
    this.lockedUntil = t + lock;
    return lock;
  }

  /** How many failures the current window holds (the log line says it). */
  recent(): number {
    const t = this.now();
    return this.failures.filter((f) => t - f < THROTTLE_WINDOW_MS).length;
  }

  succeed(): void {
    this.failures = [];
    this.strikes = 0;
  }
}

/** A browser navigation (a page the person opens), as opposed to a fetch, an
 *  EventSource or a script: GET/HEAD that accepts HTML. */
export function isNavigation(req: IncomingMessage): boolean {
  const m = (req.method ?? "GET").toUpperCase();
  if (m !== "GET" && m !== "HEAD") return false;
  const dest = req.headers["sec-fetch-dest"];
  if (typeof dest === "string" && dest !== "document") return false;
  return /text\/html/i.test(String(req.headers.accept ?? ""));
}

/** Did the request reach the front over HTTPS? The socket's own TLS, or the
 *  `X-Forwarded-Proto` a front sets (the source-IP gate already admitted
 *  the peer). Only the cookie's Secure flag reads it: a forged value can
 *  only make a cookie the forger's own browser then drops. */
export function arrivedOverHttps(req: IncomingMessage): boolean {
  if ((req.socket as { encrypted?: boolean }).encrypted === true) return true;
  const xfp = req.headers["x-forwarded-proto"];
  const first = (Array.isArray(xfp) ? xfp[0] : xfp ?? "").split(",")[0]!.trim().toLowerCase();
  return first === "https";
}

/**
 * Is this POST from this dashboard's own page (login CSRF)? The browser's
 * `Sec-Fetch-Site`, when sent, must say same-origin; then the `Origin` (or,
 * without one, the `Referer`) must name this dashboard: the request's own
 * Host, or a name `hostOk` admits (server.ts: the Host check's names). A
 * POST that carries neither is refused (every browser sends Origin on a
 * form POST; a script signs in with a Basic header instead).
 */
export function fromOwnPage(req: IncomingMessage, hostOk: (hostHeader: string) => boolean): boolean {
  const site = req.headers["sec-fetch-site"];
  if (typeof site === "string" && site !== "same-origin") return false;
  const origin = req.headers.origin;
  let src: string | undefined;
  if (typeof origin === "string" && origin !== "") {
    if (origin === "null") return false;
    src = origin;
  } else if (typeof req.headers.referer === "string" && req.headers.referer !== "") {
    src = req.headers.referer;
  }
  if (src === undefined) return false;
  let u: URL;
  try {
    u = new URL(src);
  } catch {
    return false;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  const host = (req.headers.host ?? "").trim().toLowerCase();
  if (host !== "" && u.host.toLowerCase() === host) return true;
  const port = u.port || (u.protocol === "https:" ? "443" : "80");
  return hostOk(`${u.hostname}:${port}`);
}

/** Where to send the person after signing in: `next` when it is a path of
 *  this dashboard (one leading '/', no second '/' or '\\' after it, no
 *  control character, no scheme), else Home. Never another site. */
export function safeNext(next: string | null | undefined): string {
  if (typeof next !== "string" || next.length === 0 || next.length > 2048) return "/";
  if (!next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return "/";
  if (/[\\\u0000- \u007f]/.test(next)) return "/";
  const path = next.split(/[?#]/)[0]!;
  if (path === "/login" || path === "/logout") return "/";
  return next;
}

/** Read a small form body; null when it is larger than `max` bytes. */
export function readSmallBody(req: IncomingMessage, max = 8192): Promise<string | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let over = false;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > max) over = true;
      else chunks.push(c);
    });
    req.on("end", () => resolve(over ? null : Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => resolve(null));
  });
}

const esc = (s: string): string =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

/** What the page says above the form. */
export type SignInNotice =
  | { kind: "none" }
  | { kind: "wrong" }
  | { kind: "wait"; seconds: number }
  | { kind: "other-site" }
  | { kind: "no-account" }
  | { kind: "unsafe" }
  | { kind: "signed-out" };

/** The headers every answer of the gate carries: nothing cached, nothing
 *  framed, no script, the form posting only here. */
export const SIGN_IN_PAGE_HEADERS: Record<string, string> = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "same-origin",
};

/**
 * The sign-in page: Username, Password, Sign in; the notice above them; the
 * page the person asked for in a hidden field. Self-contained (the CSS is
 * inline, there is no script), so nothing past the gate is fetched for it.
 * With no usable account there is no form, only what to run; why the file
 * cannot be used is in the log and `--set-password`'s output, never on a
 * page a stranger behind a tunnel can open.
 */
export function signInPage(basePath: string, next: string, notice: SignInNotice, user = ""): string {
  const msg = (() => {
    switch (notice.kind) {
      case "wrong": return `<p class="err" role="alert">Wrong username or password.</p>`;
      case "wait": return `<p class="err" role="alert">Too many wrong tries. Wait ${notice.seconds} second${notice.seconds === 1 ? "" : "s"}, then try again.</p>`;
      case "other-site": return `<p class="err" role="alert">This sign-in did not come from the dashboard's own page. Open the dashboard and sign in there.</p>`;
      case "signed-out": return `<p class="ok" role="status">You are signed out.</p>`;
      default: return "";
    }
  })();
  const body =
    notice.kind === "no-account"
      ? `<p>No account yet. To make one, run <code>mandu dashboard --set-password</code> in your own terminal, then reload this page.</p>`
      : notice.kind === "unsafe"
        ? `<p class="err" role="alert">The dashboard account cannot be used: its file is not as Mandu wrote it (the dashboard's log says why).</p><p>To set it again, run <code>mandu dashboard --set-password</code> in your own terminal, then reload this page.</p>`
        : `${msg}<form method="POST" action="${esc(basePath)}/login">
<input type="hidden" name="next" value="${esc(next)}">
<label for="u">Username</label>
<input id="u" name="user" autocomplete="username" autocapitalize="none" spellcheck="false" required value="${esc(user)}"${user ? "" : " autofocus"}>
<label for="p">Password</label>
<input id="p" name="password" type="password" autocomplete="current-password" required${user ? " autofocus" : ""}>
<button type="submit">Sign in</button>
</form>
<p class="hint">Your Mandu dashboard account. Forgot it? Run <code>mandu dashboard --set-password</code> in your own terminal to set a new one.</p>`;
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mandu: Sign in</title>
<style>
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--ink:#1d2433;--sub:#5b6474;--line:#d7dbe2;--accent:#1f6feb;--err:#b42318;--ok:#067647}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--ink:#e6edf3;--sub:#9aa4b2;--line:#30363d;--accent:#58a6ff;--err:#ff7b72;--ok:#3fb950}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}
main{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:28px;width:100%;max-width:360px}
h1{font-size:1.25rem;margin:0 0 4px}
.sub{color:var(--sub);margin:0 0 20px;font-size:.95rem}
label{display:block;font-weight:600;font-size:.9rem;margin:12px 0 4px}
input{width:100%;padding:10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);font:inherit}
input:focus{outline:2px solid var(--accent);outline-offset:1px}
button{margin-top:20px;width:100%;padding:10px;border:0;border-radius:6px;background:var(--accent);color:#fff;font:inherit;font-weight:600;cursor:pointer}
.err{color:var(--err);margin:0 0 8px}.ok{color:var(--ok);margin:0 0 8px}
.hint{color:var(--sub);font-size:.85rem;margin:16px 0 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;background:var(--bg);padding:1px 4px;border-radius:4px;word-break:break-word}
</style></head><body><main>
<h1>Mandu</h1>
<p class="sub">Sign in to your dashboard.</p>
${body}
</main></body></html>`;
}
