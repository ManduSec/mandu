/** Subscription evaluation: first-party Claude Code owns authentication.
 * PROVENANCE: relay header rules adapted from launcher/src/services/ullm-forwarder.ts;
 * bounded capture adapted from paired-provider.ts. No originated OAuth calls.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, request } from "node:https";
import type { AddressInfo } from "node:net";
import type { IncomingHttpHeaders } from "node:http";
import type { TlsMaterial } from "../tls.js";
import type { CapturedModelRequest } from "./paired-observer.js";
import type { TokenUsage } from "./paired-budget.js";
import { PAID_MODEL } from "./paired-budget.js";
import { replyUsage } from "./paired-provider.js";

export interface SubscriptionLimits {
  maxRequests: number; maxOutputTokens: number; maxLegMs: number; maxBatchMs: number; rollouts: number;
}
export const UTILITY_SUBSCRIPTION_LIMITS: Readonly<SubscriptionLimits> = Object.freeze({
  maxRequests: 1440, maxOutputTokens: 4096, maxLegMs: 360_000, maxBatchMs: 8 * 3600_000, rollouts: 72,
});
export const SUBSCRIPTION_LIMITS = { maxRequests: 120, maxOutputTokens: 4096, maxLegMs: 180_000, maxBatchMs: 1200_000, rollouts: 6 } as const;
export interface SubscriptionRequest {
  leg: string; channel: "model" | "inspection"; countOnly: boolean;
  state: "reserved" | "settled" | "uncertain"; usage?: TokenUsage; status?: number;
}
export interface SubscriptionSnapshot {
  limits: SubscriptionLimits; stopped: string | null; requests: SubscriptionRequest[];
}
export class SubscriptionBudget {
  private entries: SubscriptionRequest[] = [];
  private reason: string | null = null;
  private deadline: number;
  private readonly limits: Readonly<SubscriptionLimits>;
  constructor(private persist: (s: SubscriptionSnapshot) => void = () => {}, private now = () => Date.now(), limits: SubscriptionLimits = SUBSCRIPTION_LIMITS) {
    for (const key of Object.keys(UTILITY_SUBSCRIPTION_LIMITS) as (keyof SubscriptionLimits)[]) {
      if (!Number.isSafeInteger(limits[key]) || limits[key] < 1 || limits[key] > UTILITY_SUBSCRIPTION_LIMITS[key]) throw new Error(`Invalid subscription limit: ${key}`);
    }
    this.limits = Object.freeze({ ...limits });
    this.deadline = now() + this.limits.maxBatchMs;
  }
  remainingMs(): number { return Math.max(0, this.deadline - this.now()); }
  snapshot(): SubscriptionSnapshot { return { limits: { ...this.limits }, stopped: this.reason, requests: structuredClone(this.entries) }; }
  stop(reason: string): void { this.reason ??= reason; this.persist(this.snapshot()); }
  reserve(leg: string, channel: SubscriptionRequest["channel"], body: Record<string, unknown>, countOnly: boolean): number {
    if (this.reason) throw new Error(this.reason);
    if (!this.remainingMs()) throw new Error("Subscription batch deadline reached");
    if (this.entries.length >= this.limits.maxRequests) throw new Error("Subscription request limit reached");
    const legs = new Set(this.entries.map((entry) => entry.leg));
    if (!legs.has(leg) && legs.size >= this.limits.rollouts) throw new Error("Subscription rollout limit reached");
    if (body.model !== PAID_MODEL) throw new Error("Subscription model must remain pinned");
    if (!countOnly && (!Number.isSafeInteger(body.max_tokens) || (body.max_tokens as number) < 1 || (body.max_tokens as number) > this.limits.maxOutputTokens)) throw new Error("Subscription output allowance exceeded");
    const id = this.entries.length;
    this.entries.push({ leg, channel, countOnly, state: "reserved" });
    this.persist(this.snapshot());
    return id;
  }
  settle(id: number, raw: unknown, status: number): void {
    const entry = this.entries[id];
    if (!entry || entry.state !== "reserved") throw new Error("Invalid subscription settlement");
    const u = raw as Record<string, unknown> | undefined;
    const usage = { uncachedInput: u?.input_tokens, cacheWrite: u?.cache_creation_input_tokens ?? 0,
      cacheRead: u?.cache_read_input_tokens ?? 0, output: entry.countOnly ? 0 : u?.output_tokens };
    if (Object.values(usage).some((n) => !Number.isSafeInteger(n) || (n as number) < 0) || (usage.output as number) > this.limits.maxOutputTokens) throw new Error("Subscription usage missing or invalid");
    entry.status = status; entry.state = "settled";
    if (!entry.countOnly) entry.usage = usage as TokenUsage;
    this.persist(this.snapshot());
  }
  uncertain(id: number, status?: number): void {
    const entry = this.entries[id];
    if (entry?.state === "reserved") { entry.state = "uncertain"; entry.status = status; }
    this.stop("Subscription response incomplete or refused; batch stopped");
  }
}

/** Only a private, disposable CLI login store; never copy user settings or put
 * credentials in the artifact tree. Claude Code reads/refreshes its own login.
 */
export function isolatedSubscriptionLogin(source = process.env.CLAUDE_CONFIG_DIR ?? join(homedir(), ".claude")): { configDir: string; close(): void } {
  let oauth: Record<string, unknown>;
  try { oauth = JSON.parse(readFileSync(join(source, ".credentials.json"), "utf8")).claudeAiOauth; }
  catch { throw new Error("Claude subscription login unavailable; run claude auth login first"); }
  if (!oauth || typeof oauth.accessToken !== "string" || !["max", "pro"].includes(String(oauth.subscriptionType))) throw new Error("A Claude Pro/Max CLI login is required");
  const configDir = mkdtempSync(join(tmpdir(), "mdu-paired-login-"));
  try { writeFileSync(join(configDir, ".credentials.json"), JSON.stringify({ claudeAiOauth: oauth }), { mode: 0o600 }); }
  catch (e) { rmSync(configDir, { recursive: true, force: true }); throw e; }
  return { configDir, close: () => rmSync(configDir, { recursive: true, force: true }) };
}

export function checkSubscriptionLogin(binary: string, env: Record<string, string>, cwd: string): void {
  let status: any;
  try { status = JSON.parse(execFileSync(binary, ["auth", "status"], { env, cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 10000 })); }
  catch { throw new Error("Isolated Claude subscription authentication check failed"); }
  if (!status.loggedIn || status.authMethod !== "claude.ai" || !["max", "pro"].includes(status.subscriptionType)) throw new Error("Isolated CLI is not using a Pro/Max subscription");
}

const DROP = new Set(["host", "connection", "proxy-connection", "keep-alive", "upgrade", "transfer-encoding", "te", "trailer", "accept-encoding"]);
export function subscriptionHeaders(headers: IncomingHttpHeaders): IncomingHttpHeaders {
  if (!headers.authorization?.startsWith("Bearer ") || headers["x-api-key"]) throw new Error("Subscription observer requires native OAuth; API keys refused");
  return Object.fromEntries(Object.entries(headers).filter(([key, value]) => value !== undefined && !DROP.has(key)));
}

/** Forward received CLI bytes/identity verbatim to the pinned provider. The
 * optional endpoint is a loopback TLS test fixture, never a CLI option.
 */
export async function startSubscriptionObserver(tls: TlsMaterial, budget: SubscriptionBudget, leg: string,
  channel: CapturedModelRequest["channel"], fixture?: { origin: string; ca: Buffer },
): Promise<{ origin: string; requests: CapturedModelRequest[]; errors: string[]; close(): Promise<void> }> {
  const upstream = new URL(fixture?.origin ?? "https://api.anthropic.com");
  if (upstream.protocol !== "https:" || (fixture && upstream.hostname !== "127.0.0.1")) throw new Error("Subscription test provider must be loopback HTTPS");
  const requests: CapturedModelRequest[] = [], errors: string[] = [];
  const active = new Set<AbortController>(), handlers = new Set<Promise<void>>();
  const server = createServer(tls, (req, res) => {
    const handle = async () => {
      let id: number | undefined, status: number | undefined;
      const control = new AbortController(); active.add(control);
      const timer = setTimeout(() => control.abort(), Math.max(1, Math.min(60000, budget.remainingMs())));
      res.once("close", () => { if (!res.writableEnded) control.abort(); });
      try {
        // Non-inference metadata routes are unavailable in the isolated profile.
        if (req.method !== "POST" || !/^\/v1\/messages(?:\/count_tokens)?(?:\?[^#]*)?$/.test(req.url ?? "")) { res.writeHead(404); res.end(); return; }
        const headers = subscriptionHeaders(req.headers);
        const chunks: Buffer[] = []; let size = 0;
        for await (const b of req) { size += b.length; if (size > 2 * 1024 * 1024) throw new Error("Subscription request capture too large"); chunks.push(Buffer.from(b)); }
        const bytes = Buffer.concat(chunks);
        const body = JSON.parse(bytes.toString("utf8"));
        if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Invalid subscription request");
        requests.push({ channel, path: req.url!, body });
        const countOnly = req.url!.split("?")[0].endsWith("/count_tokens");
        id = budget.reserve(leg, channel, body, countOnly);
        const reply = await new Promise<{ status: number; contentType: string; text: string }>((resolve, reject) => {
          const up = request({ hostname: upstream.hostname, port: upstream.port || 443, path: req.url,
            method: "POST", headers, ca: fixture?.ca, signal: control.signal }, (response) => {
            const parts: Buffer[] = []; let length = 0;
            response.on("data", (b: Buffer) => { length += b.length; if (length > 16 * 1024 * 1024) response.destroy(); else parts.push(b); });
            response.on("error", () => reject(new Error("Subscription response interrupted")));
            response.on("end", () => resolve({ status: response.statusCode ?? 0, contentType: String(response.headers["content-type"] ?? ""), text: Buffer.concat(parts).toString("utf8") }));
          });
          up.on("error", () => reject(new Error("Subscription transport failed or timed out")));
          up.end(bytes);
        });
        status = reply.status;
        const usage = replyUsage(reply, countOnly);
        budget.settle(id, usage, status);
        res.writeHead(status, { "content-type": reply.contentType }); res.end(reply.text);
      } catch {
        if (id !== undefined) budget.uncertain(id, status);
        else budget.stop("Subscription observer refused request before forwarding");
        errors.push(status ? `Subscription provider status ${status}; batch stopped` : "Subscription request refused, interrupted, or usage invalid; batch stopped");
        if (!res.destroyed) { res.writeHead(502, { "content-type": "application/json" }); res.end('{"type":"error","error":{"type":"api_error","message":"Subscription evaluation stopped; inspect local artifacts"}}'); }
      } finally { clearTimeout(timer); active.delete(control); }
    };
    const promise = handle().catch(() => { errors.push("Subscription evidence persistence failed"); res.destroy(); });
    handlers.add(promise); void promise.finally(() => handlers.delete(promise));
  });
  server.requestTimeout = 15000;
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  return { origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, requests, errors,
    close: async () => { for (const c of active) c.abort(); await new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }); await Promise.allSettled([...handlers]); } };
}
