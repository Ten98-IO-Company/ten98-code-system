// Shopify wire format and signature-base adaptation: every-app/open-seo@89e5a00717cdf049b7c2b4e29646edb3a7d4995b.
// See THIRD_PARTY_NOTICES.md. Credential authority, key lookup, storage and crawl transport remain app-owned.
import { webcrypto } from 'node:crypto';
import { normalizePublicHostname } from './public-hostname.mjs';

export interface ShopifyCrawlerAccess {
  readonly origin: string;
  readonly signatureInput: string;
  readonly signature: string;
  readonly label: string;
  readonly keyId: string;
  /** Exact signed bytes after the dictionary label and equals sign. */
  readonly parameters: string;
  readonly expiresAt: string;
  readonly createdAt?: string;
}

/** Accepts platform CryptoKey values without tying consumers to Node's extended usage union. */
export type ShopifyVerificationKey = Omit<CryptoKey, 'usages'> & { readonly usages: readonly string[] };

const signatureAgent = '"https://shopify.com"';
const dictionaryKey = '[a-z*][a-z0-9_.*-]*';
const inputPattern = new RegExp(`^(${dictionaryKey})=(\\( *"@authority" +"signature-agent" *\\).*)$`);
const signaturePattern = new RegExp(`^(${dictionaryKey})=:([A-Za-z0-9+/]+={0,2}):$`);
const parameterPattern = new RegExp(`; *(${dictionaryKey})=`, 'y');

function boundedAscii(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 4096 && !/[^\x20-\x7e]/u.test(value);
}

function canonicalOrigin(value: string): URL | null {
  const parsed = URL.parse(value);
  return parsed && parsed.protocol === 'https:' && parsed.origin === value && !parsed.port
    && normalizePublicHostname(parsed.hostname) === parsed.hostname ? parsed : null;
}

function timestamp(seconds: number): string | null {
  if (!Number.isSafeInteger(seconds)) return null;
  const date = new Date(seconds * 1000);
  return Number.isFinite(date.getTime()) ? date.toISOString() : null;
}

/** Parses the supported Shopify signature subset, including expired credentials for metadata display. */
export function parseShopifyCrawlerAccess(input: unknown): ShopifyCrawlerAccess | null {
  try {
    if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
    const { origin, signatureInput, signature } = input as Record<string, unknown>;
    if (!boundedAscii(origin) || !boundedAscii(signatureInput) || !boundedAscii(signature) || !canonicalOrigin(origin)) return null;
    const signedInput = inputPattern.exec(signatureInput);
    const signedValue = signaturePattern.exec(signature);
    if (!signedInput || !signedValue || signedInput[1] !== signedValue[1]) return null;
    const bytes = Buffer.from(signedValue[2], 'base64');
    if (bytes.length !== 64 || bytes.toString('base64') !== signedValue[2]) return null;

    const [, label, parameters] = signedInput;
    let cursor = parameters.indexOf(')') + 1;
    let keyId: string | undefined;
    let expires: number | undefined;
    let created: number | undefined;
    const seen = new Set<string>();
    while (cursor < parameters.length) {
      parameterPattern.lastIndex = cursor;
      const parameter = parameterPattern.exec(parameters);
      if (!parameter || seen.has(parameter[1])) return null;
      const name = parameter[1];
      seen.add(name);
      cursor = parameterPattern.lastIndex;
      if (name === 'expires' || name === 'created') {
        const integer = /^-?[0-9]+/.exec(parameters.slice(cursor));
        if (!integer) return null;
        const seconds = Number(integer[0]);
        if (!timestamp(seconds)) return null;
        if (name === 'expires') expires = seconds;
        else created = seconds;
        cursor += integer[0].length;
      } else {
        if (!['keyid', 'nonce', 'tag', 'alg'].includes(name) || parameters[cursor++] !== '"') return null;
        let decoded = '';
        let closed = false;
        while (cursor < parameters.length) {
          let character = parameters[cursor++];
          if (character === '"') { closed = true; break; }
          if (character === '\\') {
            character = parameters[cursor++];
            if (character !== '"' && character !== '\\') return null;
          }
          decoded += character;
        }
        if (!closed || (name === 'keyid' && !decoded) || (name === 'alg' && decoded !== 'ed25519')) return null;
        if (name === 'keyid') keyId = decoded;
      }
    }
    if (!keyId || expires === undefined || expires <= 0 || (created !== undefined && created >= expires)) return null;
    return {
      origin, signatureInput, signature, label, keyId, parameters,
      expiresAt: timestamp(expires)!,
      ...(created === undefined ? {} : { createdAt: timestamp(created)! }),
    };
  } catch {
    // Untrusted objects (including accessors) and malformed values never escape into error messages.
    return null;
  }
}

/** Selects only the fixed signature headers for the credential's exact HTTPS origin before expiry. */
export function shopifyCrawlerHeadersFor(url: string, input: unknown, now = Date.now()): Readonly<Record<string, string>> {
  const access = parseShopifyCrawlerAccess(input);
  if (!access || !Number.isFinite(now) || now >= Date.parse(access.expiresAt) || typeof url !== 'string'
    || /[\u0000-\u0020\u007f\\]/u.test(url)) return {};
  const authority = /^https:\/\/([^/?#]*)/i.exec(url);
  const target = URL.parse(url);
  if (!authority || authority[1].includes('@') || !target || target.protocol !== 'https:'
    || target.username || target.password || target.origin !== access.origin) return {};
  return { 'Signature-Input': access.signatureInput, Signature: access.signature, 'Signature-Agent': signatureAgent };
}

/** Verifies signed authority bytes with a caller-supplied Ed25519 public key; performs no key lookup or expiry check. */
export async function verifyShopifyCrawlerAccess(input: unknown, key: ShopifyVerificationKey): Promise<'valid' | 'wrong_domain' | 'invalid'> {
  try {
    const access = parseShopifyCrawlerAccess(input);
    if (!access || key.type !== 'public' || key.algorithm.name !== 'Ed25519' || !key.usages.includes('verify')) return 'invalid';
    const hostname = new URL(access.origin).hostname;
    const signature = Buffer.from(access.signature.slice(access.label.length + 2, -1), 'base64');
    const verify = (host: string) => webcrypto.subtle.verify('Ed25519', key as webcrypto.CryptoKey, signature, Buffer.from(
      `"@authority": ${host}\n"signature-agent": ${signatureAgent}\n"@signature-params": ${access.parameters}`,
    ));
    if (await verify(hostname)) return 'valid';
    const twin = hostname.startsWith('www.') ? hostname.slice(4) : `www.${hostname}`;
    return normalizePublicHostname(twin) === twin && await verify(twin) ? 'wrong_domain' : 'invalid';
  } catch {
    return 'invalid';
  }
}
