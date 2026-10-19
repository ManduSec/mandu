/**
 * net-guard-law — read the law's REACHABILITY allowances for this launch
 * (policy-surface.md §2.3, stage 4b).
 *
 * policy.yaml `destinations:` entries with `connect: allow` compile (in the
 * arbiter) to connect-guard specs `proto:host:port`; the data-plane op
 * `netConnectAllow` returns them from the law IN FORCE (a hot-reloaded file
 * reaches the next launch with no arbiter restart). run.ts appends them to the
 * guard set as EXTRA allows that never narrow (net-guard.ts `extraAllow`).
 *
 * FAIL-SOFT TOWARD TIGHTER: an unreachable/slow arbiter, a pre-4b arbiter that
 * does not know the op, or a malformed answer all yield [] — no extra allow.
 * That is the safe direction (the guard admits less, never more), so this is
 * not a preflight gate; the launch proceeds and the banner says nothing
 * extra. Same raw NDJSON pattern as tenant-preflight.ts (the launcher keeps
 * no arbiter-client dependency).
 *
 * Mandu-new (no reference origin).
 */
import { connect } from "node:net";

/** Accept only well-formed guard specs from the wire: `proto:host:port`, with
 *  proto tcp|udp, a non-empty host token free of whitespace/quotes, and a port
 *  1–65535 or `*`. Anything else is dropped (the arbiter validated the file,
 *  but the launcher hands these to a kernel-side bin — stay strict). */
export function isGuardSpec(s: unknown): s is string {
  if (typeof s !== "string") return false;
  const m = /^(tcp|udp):([^\s:"']+|\[[0-9a-fA-F:.]+\]):(\*|[0-9]{1,5})$/.exec(s);
  if (!m) return false;
  if (m[3] === "*") return true;
  const port = Number(m[3]);
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

export function readConnectAllowances(sock: string, timeoutMs = 3000): Promise<string[]> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (v: string[]): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { s.destroy(); } catch { /* already gone */ }
      resolve(v);
    };
    const timer = setTimeout(() => finish([]), timeoutMs);
    const s = connect(sock);
    let buf = "";
    s.setEncoding("utf8");
    s.once("connect", () => s.write(JSON.stringify({ id: "net-guard-law", op: "netConnectAllow" }) + "\n"));
    s.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      try {
        const resp = JSON.parse(buf.slice(0, nl)) as { ok?: boolean; result?: { specs?: unknown } };
        if (!resp.ok || !Array.isArray(resp.result?.specs)) return finish([]);
        const out: string[] = [];
        for (const spec of resp.result.specs) if (isGuardSpec(spec) && !out.includes(spec)) out.push(spec);
        finish(out);
      } catch {
        finish([]);
      }
    });
    s.once("error", () => finish([]));
  });
}
