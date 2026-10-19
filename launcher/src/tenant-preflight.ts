/**
 * tenant-preflight — refuse to launch against an arbiter of the OTHER tenant
 * (docs/design/ui/policy-surface.md §2.7).
 *
 * The launcher knows which tenant this session is (`plan.tenant`: live for a
 * human's run, test for a suite / harness / dev rig). The arbiter's `hello`
 * declares its own tenant. If both are explicit and differ, starting would put
 * a test session's symbols, verdicts and events into the live store (or a real
 * run into the test store) — the exact mixing tenancy exists to end — so the
 * launch stops here with the remedy, before a single event is emitted.
 *
 * An UNTENANTED arbiter (hello.tenant null/absent — a legacy or unconfigured
 * daemon) accepts any tenant, so the check passes; the arbiter also refuses
 * mismatched emits itself, so this preflight is the early, legible half of a
 * two-sided guard, not the enforcement. A hello that cannot be read within the
 * deadline is reported and the launch proceeds: tenancy is hygiene, not the
 * security invariant, and ensureArbiter has just proven the socket answers.
 *
 * Raw NDJSON over node:net, like secret-setup.ts — the launcher deliberately
 * does not import the arbiter package (no repo workspace).
 */
import { connect } from "node:net";

export type Tenant = "live" | "test";

export interface TenantPreflightResult {
  /** The arbiter's declared tenant; null = untenanted; undefined = hello unreadable. */
  arbiterTenant: Tenant | null | undefined;
}

export class TenantMismatchError extends Error {
  constructor(readonly launchTenant: Tenant, readonly arbiterTenant: Tenant, sock: string) {
    super(
      `mandu: tenant mismatch — this launch is the '${launchTenant}' tenant but the arbiter at ${sock} ` +
        `is the '${arbiterTenant}' tenant. ` +
        (launchTenant === "test"
          ? "Run tests against a test-tenant arbiter (MANDU_TENANT=test on the arbiter, e.g. scripts/dev-arbiter.sh), never the live one."
          : "A human's run must not land in the test store: point MANDU_ARBITER_SOCK at the live arbiter, or drop --tenant test."),
    );
    this.name = "TenantMismatchError";
  }
}

/** One `hello` round-trip, resolving the declared tenant (undefined on any failure). */
export function readArbiterTenant(sock: string, timeoutMs = 3000): Promise<Tenant | null | undefined> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (v: Tenant | null | undefined): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { s.destroy(); } catch { /* already gone */ }
      resolve(v);
    };
    const timer = setTimeout(() => finish(undefined), timeoutMs);
    const s = connect(sock);
    let buf = "";
    s.setEncoding("utf8");
    s.once("connect", () => s.write(JSON.stringify({ id: "tenant-preflight", op: "hello" }) + "\n"));
    s.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      try {
        const resp = JSON.parse(buf.slice(0, nl)) as { ok?: boolean; result?: { tenant?: unknown } };
        if (!resp.ok) return finish(undefined);
        const t = resp.result?.tenant;
        finish(t === "live" || t === "test" ? t : null);
      } catch {
        finish(undefined);
      }
    });
    s.once("error", () => finish(undefined));
  });
}

/**
 * Throw {@link TenantMismatchError} when the arbiter declares the other tenant.
 * Returns what it learned so run.ts can log it ("arbiter tenant: live").
 */
export async function assertArbiterTenant(
  sock: string,
  launchTenant: Tenant,
  opts: { timeoutMs?: number; warn?: (msg: string) => void } = {},
): Promise<TenantPreflightResult> {
  const arbiterTenant = await readArbiterTenant(sock, opts.timeoutMs);
  if (arbiterTenant === undefined) {
    opts.warn?.(`mandu: could not read the arbiter's tenant from ${sock} (hello unanswered) — proceeding as '${launchTenant}'`);
    return { arbiterTenant };
  }
  if (arbiterTenant !== null && arbiterTenant !== launchTenant) {
    throw new TenantMismatchError(launchTenant, arbiterTenant, sock);
  }
  return { arbiterTenant };
}
