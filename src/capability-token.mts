// Signed capability tokens: `base64url(JSON payload) + "." + HMAC-SHA256(secret, purpose + ":" + body)`. This is the shape
// both apps already issue (Campaign unsubscribe links with a base64url signature; Discover replay, heatmap and retention
// tokens with a hex signature), so existing tokens keep verifying. Callers check the payload's shape and any expiry.
import { createHmac, timingSafeEqual } from 'node:crypto';

/** Signature text encoding: `base64url` (43 characters) or `hex` (64 characters). */
export type CapabilityEncoding = 'base64url' | 'hex';

const SIGNATURE: Record<CapabilityEncoding, RegExp> = { base64url: /^[A-Za-z0-9_-]{43}$/u, hex: /^[a-f0-9]{64}$/u };

function check(purpose: string, secret: string, encoding: CapabilityEncoding): void {
  if (typeof purpose !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(purpose)) throw new TypeError('purpose must be 1 to 128 letters, digits, dots, hyphens or underscores.');
  if (typeof secret !== 'string' || secret.length < 32) throw new TypeError('secret must contain at least 32 characters.');
  if (!Object.hasOwn(SIGNATURE, encoding)) throw new TypeError("encoding must be 'base64url' or 'hex'.");
}

const digest = (purpose: string, body: string, secret: string) => createHmac('sha256', secret).update(`${purpose}:${body}`).digest();

/** Signs a JSON-serialisable payload for one purpose. Different purposes never accept each other's tokens. */
export function signCapability(purpose: string, payload: unknown, secret: string, { encoding = 'base64url' }: { encoding?: CapabilityEncoding } = {}): string {
  check(purpose, secret, encoding);
  const json = JSON.stringify(payload);
  if (json === undefined) throw new TypeError('payload must be JSON-serialisable.');
  const body = Buffer.from(json, 'utf8').toString('base64url');
  return `${body}.${digest(purpose, body, secret).toString(encoding)}`;
}

/**
 * The payload of a token signed for `purpose`, or null when the token is not a string, is longer than `maxLength`, is not
 * exactly `body.signature`, uses non-canonical base64url, has a wrong signature (compared in constant time) or does not
 * hold JSON. Configuration errors (purpose, secret, encoding) throw instead.
 */
export function readCapability(purpose: string, token: unknown, secret: string, { maxLength = 4096, encoding = 'base64url' }: { maxLength?: number; encoding?: CapabilityEncoding } = {}): unknown {
  check(purpose, secret, encoding);
  if (!Number.isSafeInteger(maxLength) || maxLength < 1) throw new TypeError('maxLength must be a positive safe integer.');
  if (typeof token !== 'string' || token.length > maxLength) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, signature] = parts as [string, string];
  if (!/^[A-Za-z0-9_-]+$/u.test(body) || !SIGNATURE[encoding].test(signature)) return null;
  const signed = Buffer.from(signature, encoding);
  // The last base64url character carries spare bits; only the canonical spelling is the signature.
  if (signed.toString(encoding) !== signature || !timingSafeEqual(signed, digest(purpose, body, secret))) return null;
  const raw = Buffer.from(body, 'base64url');
  if (raw.toString('base64url') !== body) return null;
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)); } catch { return null; }
}
