/**
 * symbolize — read-time ingress symbolization + sync-time egress desymbolization.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code, but the BEHAVIOUR is lifted from two adfi-openclaw places:
 *     - the file-tool read path (which symbolized untrusted file content before
 *       the agent saw it — that lived in the OpenClaw hook, not the fs-* files,
 *       so it is re-expressed here against the arbiter), and
 *     - adfi-filecommit-{worktree,ondemand}.ts steps 5-6 (`resolveAllSymbols`
 *       over synced files), re-expressed as a arbiter `desymbolize` call.
 *   adfi-openclaw did this in-process via the symbol table; Mandu routes every
 *   allocation/resolution through the arbiter (src/arbiter-client.ts). The
 *   binary-file null-byte guard and the "skip if no symbols" fast paths are
 *   preserved from the reference.
 *
 * SECURITY INVARIANT (the whole point of this module):
 *   `symbolizeContent` is the ingress: it converts raw HumanView bytes into
 *   AgentView content where every UNTRUSTED span is an opaque `$MDU:*`.
 *   It FAILS CLOSED — if the arbiter cannot mint a symbol, it throws rather than
 *   return raw content, so un-symbolized untrusted bytes can never land in the
 *   AgentView worktree.
 */

import type { SymbolArbiter } from "./arbiter-client.js";
import { hasSymbols } from "./arbiter-client.js";
import { emitBirth } from "./events.js";

/** First 8 KiB null-byte test — same binary detection as the reference. */
export function isBinary(buf: Buffer): boolean {
  return buf.subarray(0, 8192).includes(0);
}

export interface SymbolizeContentOptions {
  /** Logical tool / source name recorded with the symbol (provenance). For a
   * file read this is conventionally "Read" (Claude Code) / "read" (OpenClaw). */
  tool?: string;
  /** Origin hint (the HumanView path, a URL, etc.) recorded with the symbol. */
  origin?: string;
  /** Field path recorded with the symbol (e.g. the relative file path). */
  field?: string;
  sessionKey?: string;
  callId?: string;
  /** Parent symbol for a derived mint (symbol-lineage.md G2). */
  derivedFrom?: string;
  /** End-exclusive `start:end` line span within the parent value. */
  lineRange?: string;
  /** Mint even when the text already carries a symbol-shaped token. The
   *  ignored-file seed (ignored.ts) uses it: a HumanView file is raw by
   *  definition, so a `$MDU:` string inside it is data, and the idempotent
   *  shortcut would otherwise hand the rest of the file to the AgentView raw. */
  force?: boolean;
}

/**
 * Symbolize raw HumanView file content for the AgentView.
 *
 * v1 policy: whole-file symbolization for untrusted content (the conservative
 * fail-closed default the design calls for at the FS layer — see
 * docs/design/architecture/mandu.md §6.2 "coarser classification"; per-field/per-region
 * classification is the Track A schema path, not the FS layer). The whole file
 * becomes ONE symbol. Binary files are passed through untouched (the reference
 * skips symbol resolution for binaries; they carry no injectable text the
 * privileged model would read as instructions).
 *
 * Already-symbolized content (an AgentView file round-tripping) is returned
 * unchanged so re-symbolization is idempotent.
 *
 * FAILS CLOSED: a arbiter symbolize rejection propagates.
 */
export async function symbolizeContent(
  arbiter: SymbolArbiter,
  raw: Buffer,
  opts: SymbolizeContentOptions = {},
): Promise<{ content: Buffer; symbol: string | null }> {
  if (isBinary(raw)) return { content: raw, symbol: null };

  const text = raw.toString("utf8");

  // Idempotent: if the content is already symbolic, do not re-symbolize.
  if (!opts.force && hasSymbols(text)) return { content: raw, symbol: null };

  // Empty / whitespace-only content carries no injectable payload.
  if (text.trim() === "") return { content: raw, symbol: null };

  const symbol = await arbiter.symbolize({
    tool: opts.tool ?? "Read",
    value: text,
    field: opts.field,
    origin: opts.origin,
    sessionKey: opts.sessionKey,
    callId: opts.callId,
    derivedFrom: opts.derivedFrom,
    lineRange: opts.lineRange,
  });

  // Birth event (symbol-lineage.md G1): the ONLY record that this mint
  // happened at the FS chokepoint. Best-effort — never fails the mint.
  await emitBirth(arbiter, {
    sessionKey: opts.sessionKey,
    symbol,
    original: text,
    tool: opts.tool ?? "Read",
    field: opts.field,
    origin: opts.origin,
    callId: opts.callId,
    derivedFrom: opts.derivedFrom,
    lineRange: opts.lineRange,
  });

  // The AgentView line is exactly the symbol (matches the line-map contract in
  // human-edit.ts: a symbol occupies a single trusted line whose resolved value
  // may span N human-view lines). Preserve a trailing newline if the source had
  // one so the file shape round-trips.
  const trailingNl = text.endsWith("\n") ? "\n" : "";
  return { content: Buffer.from(symbol + trailingNl, "utf8"), symbol };
}

/**
 * Desymbolize AgentView text back to raw HumanView content via the arbiter.
 * Used on the AgentView -> HumanView sync (the [MDU-UNTRUSTED] step). Fast path
 * if the text carries no symbols. Binary content is returned untouched.
 *
 * Note: unknown/obsoleted symbols are left in place by the arbiter (`desymbolize`
 * only replaces what it can resolve); callers that require full resolution
 * should assert with `hasSymbols` afterward.
 */
export async function desymbolizeContent(
  arbiter: SymbolArbiter,
  raw: Buffer,
): Promise<Buffer> {
  if (isBinary(raw)) return raw;
  const text = raw.toString("utf8");
  if (!hasSymbols(text)) return raw;
  const resolved = await arbiter.desymbolize(text);
  return Buffer.from(resolved, "utf8");
}
