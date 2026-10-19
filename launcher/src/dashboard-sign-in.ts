/**
 * dashboard-sign-in — the launcher's half of the dashboard's one-time sign-in
 * links (policy-surface.md §2.6 "Signing in"; the dashboard's half is
 * dashboard/src/sign-in.ts). Mandu-new (no reference origin).
 *
 * The dashboard's approve / block / rule buttons need an admin session. The
 * dashboard serves a sign-in socket in the arbiter's human-plane directory
 * (`<runtime>/human/dashboard-<pid>.sock`, named in its registry entry as
 * `signInSock`), behind the same walls as the arbiter's human socket, so only
 * a process OUTSIDE an agent's sandbox can ask it for a link. The launcher
 * asks it in the human's terminal before the agent exists and prints the link
 * on its dashboard line; `mandu dashboard` asks it on request.
 *
 * The link is printed to the terminal only: never into launch.log, the
 * posture event or any other file (a log is readable by the agent's uid).
 * Hence the TTY rule: a launch whose stderr is not a terminal (a script, a
 * harness writing a log) asks for no link unless MANDU_PRINT_SIGNIN_LINK=1.
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

/** The one sentence that tells a person how to sign in (also the dashboard's
 *  refusal, sign-in.ts SIGN_IN_REMEDY). */
export const SIGN_IN_HOW = "run `mandu dashboard` in your own terminal and open the sign-in link it prints";

/** What the launcher got for its dashboard line. */
export type SignInOutcome =
  /** A one-time link (a credential: printed to the terminal only). */
  | { kind: "link"; url: string }
  /** The dashboard signs in with its password or Basic credentials. */
  | { kind: "password" }
  /** Not asked: stderr is not a terminal. */
  | { kind: "not-asked" }
  /** The dashboard declined: an agent with no wall runs, or it could not
   *  check. `why` is the dashboard's own sentence. */
  | { kind: "refused"; why: string }
  /** No channel: an older dashboard, a socket outside the human-plane
   *  directory, or no answer (inside an agent's sandbox it is walled off). */
  | { kind: "unavailable"; why: string };

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
    c.on("connect", () => c.write(JSON.stringify({ op: SIGN_IN_OP }) + "\n"));
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
  const sock = dash.signInSock;
  if (typeof sock !== "string" || sock === "") {
    return { kind: "unavailable", why: "this dashboard predates sign-in links; restart the stack (`mandu stop`) and launch again" };
  }
  const dir = resolve(humanPlaneDir(runtimeBase));
  if (!sock.startsWith("/") || dirname(resolve(sock)) !== dir) {
    return { kind: "unavailable", why: `its sign-in socket ${sock} is not in Mandu's private directory ${dir}` };
  }
  let answer: unknown;
  try {
    answer = await call(sock);
  } catch (e) {
    return { kind: "unavailable", why: `the dashboard's sign-in channel did not answer (${(e as Error).message})` };
  }
  const a = (answer ?? {}) as { ok?: unknown; path?: unknown; reason?: unknown; error?: unknown };
  if (a.ok === true && typeof a.path === "string" && a.path.startsWith("/")) {
    return { kind: "link", url: originOf(dash) + a.path };
  }
  if (a.reason === "password" || a.reason === "basic-auth") return { kind: "password" };
  const why = typeof a.error === "string" && a.error !== "" ? a.error : "the dashboard gave no reason";
  return { kind: "refused", why };
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
    case "password": return { part: `dashboard ${url} (sign in with its password)`, notes: [] };
    case "not-asked": return { part: `dashboard ${url}`, notes: [] };
    case "refused": return { part: `dashboard ${url}`, notes: [`mandu: ! no dashboard sign-in link: ${outcome.why}`] };
    case "unavailable": return { part: `dashboard ${url}`, notes: [`mandu: ! no dashboard sign-in link: ${outcome.why}; to sign in later, ${SIGN_IN_HOW}`] };
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
      return [plainLine.replace(/\)$/, "; sign in with its password)")];
    case "not-asked":
      return [plainLine];
    case "refused":
      return [plainLine, `mandu: ! no dashboard sign-in link: ${outcome.why}`];
    case "unavailable":
      return [plainLine, `mandu: ! no dashboard sign-in link: ${outcome.why}; to sign in later, ${SIGN_IN_HOW}`];
  }
}
