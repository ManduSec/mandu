/**
 * dashboard-sign-in — how the launcher says to sign in to the dashboard
 * (policy-surface.md §2.6 "Signing in", dashboard.md §6.z; the dashboard's
 * half is dashboard/src/sign-in.ts). Mandu-new (no reference origin).
 *
 * A person signs in with the Mandu dashboard account (since 2026-10-22).
 * The dashboard's human-plane socket (`<runtime>/human/dashboard-<pid>.sock`,
 * named in its registry entry as `signInSock`), behind the same walls as the
 * arbiter's human socket, answers how it signs a person in: with the
 * account, or "no account yet" (the launch line then says to set one with
 * `mandu dashboard --set-password`), or an account that cannot be used. The
 * launcher asks it before the agent exists and says it on its dashboard
 * line; `mandu dashboard` asks it too.
 *
 * An OLDER dashboard still answers with a one-time sign-in link (a
 * credential), or refuses one; both are still read, and the link is printed
 * to the terminal only, never into launch.log, the posture event or any
 * other file. Hence the TTY rule: a launch whose stderr is not a terminal (a
 * script, a harness writing a log) asks nothing unless
 * MANDU_PRINT_SIGNIN_LINK=1.
 *
 * Pure but for `requestSignInLink` (one round trip on a Unix socket).
 */
import { connect } from "node:net";
import { dirname, resolve } from "node:path";
import { humanPlaneDir } from "./human-plane.js";

/** The op the dashboard's sign-in socket answers (sign-in.ts SIGN_IN_OP). */
export const SIGN_IN_OP = "signInLink";
/** How long the launcher waits for a link: never long, the launch goes on
 *  without one. */
export const SIGN_IN_TIMEOUT_MS = 3_000;

/** The one sentence that tells a person how to sign in (the dashboard's
 *  refusal says the same, sign-in.ts SIGN_IN_REMEDY). */
export const SIGN_IN_HOW = "sign in with your Mandu dashboard account (no account yet: run `mandu dashboard --set-password` in your own terminal)";

/** What the launcher got for its dashboard line. */
export type SignInOutcome =
  /** An OLDER dashboard's one-time link (a credential: printed to the
   *  terminal only). */
  | { kind: "link"; url: string }
  /** The dashboard asks before any page: the Mandu dashboard account
   *  (`account`, dashboard.md §6.z), none yet (`no-account`), one whose file
   *  cannot be used (`account-unusable`), a username and password held only
   *  in its environment (`basic`), or an older dashboard's password
   *  (DASHBOARD_PASSWORD; no `with`). */
  | { kind: "password"; with?: SignInWith }
  /** Not asked: stderr is not a terminal. */
  | { kind: "not-asked" }
  /** The dashboard declined: an agent with no wall runs, or it could not
   *  check. `why` is the dashboard's own sentence. */
  | { kind: "refused"; why: string }
  /** No channel: an older dashboard, a socket outside the human-plane
   *  directory, or no answer (inside an agent's sandbox it is walled off). */
  | { kind: "unavailable"; why: string };

/** What a dashboard that asks before any page signs a person in with. */
export type SignInWith = "account" | "basic" | "no-account" | "account-unusable";

/** A registered dashboard, as the launcher reads its entry. */
export interface SignInDashboard {
  host: string;
  port: number;
  signInSock?: string;
}

/** Ask for a link when a person reads this output: stderr (or stdout, for
 *  `mandu dashboard`) is a terminal, or MANDU_PRINT_SIGNIN_LINK=1 says the
 *  output goes somewhere only the person reads. */
export function wantsSignInLink(isTTY: boolean | undefined, env: Record<string, string | undefined>): boolean {
  return isTTY === true || env["MANDU_PRINT_SIGNIN_LINK"] === "1";
}

/** One NDJSON round trip on the sign-in socket; resolves with the raw
 *  answer, rejects on a connect error, a timeout or a garbled reply. */
export function signInCall(sock: string, timeoutMs: number = SIGN_IN_TIMEOUT_MS): Promise<unknown> {
  return dashboardSocketCall(sock, { op: SIGN_IN_OP }, timeoutMs);
}

/** The dashboard's socket in this runtime's human-plane directory, or why it
 *  is not asked: a registry entry is a file the agent's world may be able to
 *  write, so a socket anywhere else is never asked. */
export function trustedDashboardSock(dash: SignInDashboard, runtimeBase: string): { sock: string } | { why: string } {
  const sock = dash.signInSock;
  if (typeof sock !== "string" || sock === "") {
    return { why: "this dashboard is older than its human-plane socket; restart the stack (`mandu stop`) and launch again" };
  }
  const dir = resolve(humanPlaneDir(runtimeBase));
  if (!sock.startsWith("/") || dirname(resolve(sock)) !== dir) {
    return { why: `its sign-in socket ${sock} is not in Mandu's private directory ${dir}` };
  }
  return { sock };
}

/** One NDJSON round trip on the dashboard's human-plane socket (`req`, one
 *  line; one answer line back): the sign-in op, or `sessionKept`
 *  (session-kept-line.ts). Rejects on a connect error, a timeout or a
 *  garbled reply. */
export function dashboardSocketCall(sock: string, req: Record<string, unknown>, timeoutMs: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const c = connect(sock);
    let buf = "";
    let settled = false;
    const done = (err: Error | null, val?: unknown): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      c.destroy();
      if (err) reject(err);
      else resolve(val);
    };
    const timer = setTimeout(() => done(new Error(`no answer within ${timeoutMs} ms`)), timeoutMs);
    c.setEncoding("utf8");
    c.on("error", (e) => done(e));
    c.on("connect", () => c.write(JSON.stringify(req) + "\n"));
    c.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      try { done(null, JSON.parse(buf.slice(0, nl))); } catch (e) { done(e as Error); }
    });
    c.on("end", () => done(new Error("the dashboard closed the sign-in socket without an answer")));
  });
}

/** `http://<host>:<port>` for a dashboard entry: loopback for a wildcard bind. */
function originOf(d: SignInDashboard): string {
  const host = d.host === "0.0.0.0" || d.host === "::" || d.host === "" ? "127.0.0.1" : d.host;
  return `http://${host}:${d.port}`;
}

/**
 * Ask `dash` for a one-time sign-in link. The socket must lie in this
 * runtime's human-plane directory: a registry entry is a file the agent's
 * world may be able to write, so a socket anywhere else is not asked.
 */
export async function requestSignInLink(
  dash: SignInDashboard,
  runtimeBase: string,
  call: (sock: string) => Promise<unknown> = (s) => signInCall(s),
): Promise<SignInOutcome> {
  const trusted = trustedDashboardSock(dash, runtimeBase);
  if ("why" in trusted) return { kind: "unavailable", why: trusted.why };
  const sock = trusted.sock;
  let answer: unknown;
  try {
    answer = await call(sock);
  } catch (e) {
    return { kind: "unavailable", why: `the dashboard's human-plane socket did not answer (${(e as Error).message})` };
  }
  const a = (answer ?? {}) as { ok?: unknown; path?: unknown; reason?: unknown; error?: unknown };
  if (a.ok === true && typeof a.path === "string" && a.path.startsWith("/")) {
    return { kind: "link", url: originOf(dash) + a.path };
  }
  if (a.reason === "password") return { kind: "password" };
  if (a.reason === "account") return { kind: "password", with: "account" };
  if (a.reason === "basic-auth") return { kind: "password", with: "basic" };
  if (a.reason === "no-account") return { kind: "password", with: "no-account" };
  if (a.reason === "account-unusable") return { kind: "password", with: "account-unusable" };
  const why = typeof a.error === "string" && a.error !== "" ? a.error : "the dashboard gave no reason";
  return { kind: "refused", why };
}

/** How a dashboard that asks before any page is signed in to, in the
 *  launch line's words (dashboard.md §6.z): "sign in with your Mandu
 *  dashboard account", or, with none yet, "no account yet; set one: mandu
 *  dashboard --set-password". `mandu scan`'s dashboard line says the same
 *  (scan-command.ts). Pure. */
export function signInWords(outcome: { with?: SignInWith }): string {
  if (outcome.with === "account") return "sign in with your Mandu dashboard account";
  if (outcome.with === "no-account") return "no account yet; set one: mandu dashboard --set-password";
  if (outcome.with === "account-unusable") return "its account cannot be used; set it again: mandu dashboard --set-password";
  if (outcome.with === "basic") return "sign in with its username and password";
  return "sign in with its password";
}

/**
 * The dashboard's part of the default display's one banner line
 * (launch-banner.ts bannerLine, packaging.md §5): `dashboard <url>`, the
 * one-time sign-in link in place of the URL when there is one (terminal
 * only, like terminalDashboardLines), `no dashboard …` when none runs. `notes`: what the
 * full display would print on a line of its own (no link could be made),
 * for the launch to keep and count as a notice. Pure.
 */
export function bannerDashboard(url: string | null, outcome: SignInOutcome | null): { part: string; notes: string[] } {
  if (url === null) return { part: "no dashboard (start one: `mandu dashboard`)", notes: [] };
  if (outcome === null) return { part: `dashboard ${url}`, notes: [] };
  switch (outcome.kind) {
    case "link": return { part: `dashboard ${outcome.url} (the link signs this browser in, once)`, notes: [] };
    case "password": return { part: `dashboard ${url} (${signInWords(outcome)})`, notes: [] };
    case "not-asked": return { part: `dashboard ${url}`, notes: [] };
    case "refused": return { part: `dashboard ${url}`, notes: [`mandu: ! no dashboard sign-in link: ${outcome.why}`] };
    case "unavailable": return { part: `dashboard ${url}`, notes: [`mandu: ! could not ask the dashboard how to sign in: ${outcome.why}; ${SIGN_IN_HOW}`] };
  }
}

/**
 * The dashboard line(s) for the TERMINAL under `--verbose`. `plainLine` is
 * the line kept in the logs and the posture event (launch-banner.ts
 * dashboardLine), which never carries a link; this is what the person sees
 * instead.
 */
export function terminalDashboardLines(plainLine: string, outcome: SignInOutcome | null): string[] {
  if (outcome === null) return [plainLine];
  switch (outcome.kind) {
    case "link": {
      const m = /^mandu: dashboard (\S+) \((.*)\)$/.exec(plainLine);
      return m
        ? [`mandu: dashboard ${outcome.url} (${m[2]}; the link signs this browser in, once)`]
        : [plainLine, `mandu: sign in to the dashboard (the link works once): ${outcome.url}`];
    }
    case "password":
      return [plainLine.replace(/\)$/, `; ${signInWords(outcome)})`)];
    case "not-asked":
      return [plainLine];
    case "refused":
      return [plainLine, `mandu: ! no dashboard sign-in link: ${outcome.why}`];
    case "unavailable":
      return [plainLine, `mandu: ! could not ask the dashboard how to sign in: ${outcome.why}; ${SIGN_IN_HOW}`];
  }
}
