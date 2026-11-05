/**
 * aws-signing — the default catalog's AWS SIGNING RELEASE
 * (docs/design/confidentiality/aws-sigv4-resign.md; confidentiality.md
 * §2.3, the issuer bindings' AWS row, 2026-10-24).
 *
 * AWS was left out of the issuer table because SigV4 signs with the secret
 * access key on this machine: a placeholder cannot be put back into a
 * signature. The egress proxy now re-signs (net-proxy `sigv4.ts`): the
 * agent's `aws` or SDK signs with the key's PLACEHOLDER, the proxy proves
 * which placeholder signed the request (it recomputes the signature), and
 * signs the request it forwards with the real key. The real key never
 * enters a request; only an HMAC made with it does.
 *
 * The release, every condition required (`awsSigningRelease`):
 *
 *   - the row is one an issuer release may read (current-bindings.ts
 *     `issuerSourceOf`: a registered file's own field row or a masked
 *     environment variable, the user's own, trusted);
 *   - its name says which AWS credential it is (`awsCredentialRole`): the
 *     secret access key, the access key id, or the session token, by the
 *     names the CLI and the SDKs read (`aws_secret_access_key` in a profile
 *     of `~/.aws/credentials` or `~/.aws/config`, `AWS_SECRET_ACCESS_KEY` in
 *     the environment or a `.env`, and the id's and token's names);
 *   - the destination is an AWS endpoint (`isAwsEndpoint`): a name under
 *     `amazonaws.com`, `amazonaws.com.cn` or `api.aws`, on port 443 or no
 *     stated port, never an address;
 *   - the request is HTTPS;
 *   - the positions: the SECRET only at `signature` (a key the proxy signs
 *     with, nowhere in the request), the id and the token only in the
 *     request's credential headers (`authorization`: the proxy states the
 *     `X-Amz-Security-Token` of a SigV4 request so);
 *   - the switch is on (policy.yaml `issuer_bindings`, not `aws` under
 *     `issuers_off`, the value's name not under `values_off`).
 *
 * Why a suffix and not exact hosts (the issuer table's rule): AWS's API
 * hosts are per service and region (and per bucket), so no fixed list
 * exists. Anyone can own a name under `amazonaws.com` (a bucket, an EC2
 * host, an API Gateway stage), so what reaches such a host must be useless
 * to its owner: the signature (an HMAC under a key derived for one day,
 * region and service, over a request that names its own Host: the proxy
 * re-signs only when the signed Host is the host it sends to), the access
 * key id (an identifier) and the session token (which signs nothing
 * without the secret). The secret itself is never released at a suffix
 * host as bytes: any other position asks, as an unbound secret does.
 *
 * Pure. Mandu-new (no reference origin).
 */

import { issuerDestinationHost } from "./issuer-catalog.js";
import type { IssuerBindingSettings } from "./issuer-bindings.js";
import { valueKeyMatches } from "./value-bindings.js";

/** The id `issuer_bindings.issuers_off` turns this release off by. */
export const AWS_SIGNING_ISSUER_ID = "aws";

/** The domains AWS serves its APIs under (global, China, the dual-stack
 *  `api.aws`). */
export const AWS_ENDPOINT_DOMAINS: readonly string[] = ["amazonaws.com", "amazonaws.com.cn", "api.aws"];

/** Which AWS credential a value is. */
export type AwsCredentialRole = "secret" | "id" | "token";

const ROLE_BY_NAME: Readonly<Record<string, AwsCredentialRole>> = {
  aws_secret_access_key: "secret",
  aws_access_key_id: "id",
  aws_session_token: "token",
  // The older name botocore still reads.
  aws_security_token: "token",
};

/** The role a value's name gives it: its last dotted piece (a profile's
 *  field is `<profile>.aws_secret_access_key`), case folded. Null when no
 *  name is an AWS credential's, or two disagree. Pure. */
export function awsCredentialRole(names: readonly string[]): AwsCredentialRole | null {
  let role: AwsCredentialRole | null = null;
  for (const n of names) {
    const last = n.slice(n.lastIndexOf(".") + 1).toLowerCase();
    const r = ROLE_BY_NAME[last];
    if (r === undefined) continue;
    if (role !== null && role !== r) return null;
    role = r;
  }
  return role;
}

/** Is `destination` (`host`, `host:443`, `https://host/…`) an AWS endpoint
 *  name: under one of `AWS_ENDPOINT_DOMAINS`, by whole labels, port 443 or
 *  none, never an address? Pure. */
export function isAwsEndpoint(destination: unknown): boolean {
  const host = issuerDestinationHost(destination);
  if (host === null) return false;
  return AWS_ENDPOINT_DOMAINS.some((d) => host.endsWith(`.${d}`));
}

export interface AwsSigningInput {
  /** The names the value goes by (its field, its variable). */
  names: readonly string[];
  destination: unknown;
  scheme?: unknown;
  positions?: unknown;
}

/** Why the release did not apply, for tests and `mandu why`. */
export type AwsSigningMiss = "off" | "not-aws" | "value-off" | "host" | "scheme" | "position";

/** The role this send releases, or why it does not. Pure. */
export function awsSigningRelease(input: AwsSigningInput, settings: IssuerBindingSettings): { role: AwsCredentialRole } | { miss: AwsSigningMiss } {
  if (!settings.enabled || settings.issuersOff.includes(AWS_SIGNING_ISSUER_ID)) return { miss: "off" };
  const role = awsCredentialRole(input.names);
  if (role === null) return { miss: "not-aws" };
  if (input.names.some((n) => settings.valuesOff.some((p) => valueKeyMatches(p, n)))) return { miss: "value-off" };
  if (!isAwsEndpoint(input.destination)) return { miss: "host" };
  if (input.scheme !== "https") return { miss: "scheme" };
  const positions: unknown[] = Array.isArray(input.positions) ? input.positions : [];
  const want = role === "secret" ? "signature" : "authorization";
  if (positions.length === 0 || !positions.every((p) => p === want)) return { miss: "position" };
  return { role };
}
