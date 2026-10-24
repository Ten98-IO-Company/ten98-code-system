// Client address behind trusted reverse proxies, for per-client rate limits and similar keys.
// Promoted from ten98-discover src/server/analytics-network.ts @ 61c3154 (normalizeIp, addressList, the X-Forwarded-For walk).
// Callers retain what the address is used for; it is ephemeral input, never something to log or store.
import { createHmac } from 'node:crypto';
import { BlockList, isIP, SocketAddress } from 'node:net';

/** Parsed proxy list. Structural, so the public declarations need no Node type definitions. */
export interface TrustedProxies { check(address: string, type?: 'ipv4' | 'ipv6'): boolean }

function configError(): never {
  throw Object.assign(new Error('Invalid trusted proxy configuration.'), { code: 'CLIENT_ADDRESS_CONFIG' });
}

/** Canonical IPv4 or IPv6 text, with IPv4-mapped IPv6 unwrapped; null for anything else, including zone ids and brackets. */
export function normalizeClientAddress(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 64 || /[%\s\[\]"']/.test(value)) return null;
  const version = isIP(value);
  if (!version) return null;
  try {
    const address = new SocketAddress({ address: value, family: version === 4 ? 'ipv4' : 'ipv6', port: 0 }).address;
    return address.startsWith('::ffff:') && isIP(address.slice(7)) === 4 ? address.slice(7) : address;
  } catch {
    return null;
  }
}

/** Parse a comma-separated list of addresses and CIDR subnets, such as a TRUSTED_PROXIES setting. Invalid input throws CLIENT_ADDRESS_CONFIG without echoing it. */
export function parseTrustedProxies(raw: unknown): TrustedProxies {
  if (raw === undefined) raw = '';
  if (typeof raw !== 'string' || raw.length > 4096) configError();
  const entries = raw.trim() ? raw.split(',').map(value => value.trim()) : [];
  if (entries.length > 32) configError();
  const list = new BlockList();
  for (const entry of entries) {
    const parts = entry.split('/');
    if (parts.length > 2) configError();
    const address = normalizeClientAddress(parts[0]);
    if (address === null) configError();
    const family = isIP(address) === 4 ? 'ipv4' : 'ipv6';
    try {
      if (parts.length === 1) list.addAddress(address, family);
      else {
        if (!/^(0|[1-9]\d{0,2})$/.test(parts[1])) configError();
        let prefix = Number(parts[1]);
        const originalFamily = isIP(parts[0]);
        if (prefix > (originalFamily === 4 ? 32 : 128)) configError();
        // A mapped IPv6 subnet describes IPv4 only within its 96-bit mapped prefix.
        if (originalFamily === 6 && family === 'ipv4') {
          if (prefix < 96) configError();
          prefix -= 96;
        }
        list.addSubnet(address, prefix, family);
      }
    } catch {
      configError();
    }
  }
  return list;
}

/**
 * The connecting client's address. A peer outside `trustedProxies` is the client itself and its headers are ignored.
 * A trusted peer yields the right-most X-Forwarded-For hop that is not itself trusted. The walk goes right to left
 * through trusted hops and stops at that client hop, so entries further left (which the client itself controls) are
 * never read. Returns null when the address is unknown: an invalid peer, or a trusted peer whose chain is missing,
 * oversized, all-trusted, or malformed at or before the client hop.
 * Callers must give null a conservative key of their own rather than sharing one bucket across clients.
 */
export function resolveClientAddress(peerAddress: unknown, forwardedFor: string | null | undefined, trustedProxies: TrustedProxies): string | null {
  const peer = normalizeClientAddress(peerAddress);
  if (peer === null) return null;
  const isTrusted = (address: string) => trustedProxies.check(address, isIP(address) === 4 ? 'ipv4' : 'ipv6');
  if (!isTrusted(peer)) return peer;
  if (typeof forwardedFor !== 'string' || !forwardedFor || Buffer.byteLength(forwardedFor, 'utf8') > 4096) return null;
  const parts = forwardedFor.split(',');
  if (parts.length > 20) return null;
  for (let index = parts.length - 1; index >= 0; index--) {
    const address = normalizeClientAddress(parts[index]!.replace(/^[ \t]+|[ \t]+$/g, ''));
    if (address === null) return null;
    if (!isTrusted(address)) return address;
  }
  return null;
}

// The leading `prefix` bits of an IPv6 address as hex, with the remaining bits dropped.
function ipv6Network(address: string, prefix: number): string {
  let text = address;
  const dotted = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/u.exec(text);
  if (dotted) {
    const [a, b, c, d] = dotted.slice(1).map(Number) as [number, number, number, number];
    text = `${text.slice(0, dotted.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, tail] = text.includes('::') ? text.split('::') as [string, string] : [text, undefined];
  const left = head ? head.split(':') : [], right = tail ? tail.split(':') : [];
  const groups = tail === undefined ? left : [...left, ...Array<string>(8 - left.length - right.length).fill('0'), ...right];
  const bits = groups.map(group => parseInt(group, 16).toString(2).padStart(16, '0')).join('').slice(0, prefix);
  return BigInt(`0b${bits}`).toString(16);
}

/**
 * A rate-limit key for one client within `scope`, derived with HMAC so the stored key never reveals the address.
 * Pass the result of {@link resolveClientAddress}. IPv4 clients are keyed per address; IPv6 clients per network of
 * `ipv6Prefix` bits (default 56, allowed 48 to 64), because one IPv6 host normally controls at least a /64.
 * A null (unresolved) address gets the dedicated key `<scope>:unresolved`, kept apart from every resolved client;
 * give it its own, stricter limit rather than letting it share a client's bucket.
 */
export function clientLimitKey(scope: string, address: string | null, secret: string, { ipv6Prefix = 56 }: { ipv6Prefix?: number } = {}): string {
  if (typeof scope !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,63}$/u.test(scope)) throw new TypeError('scope must be 1 to 64 lowercase letters, digits, dots, hyphens or underscores.');
  if (typeof secret !== 'string' || secret.length < 32) throw new TypeError('secret must contain at least 32 characters.');
  if (!Number.isInteger(ipv6Prefix) || ipv6Prefix < 48 || ipv6Prefix > 64) throw new TypeError('ipv6Prefix must be an integer from 48 to 64.');
  if (address === null) return `${scope}:unresolved`;
  const canonical = normalizeClientAddress(address);
  if (canonical === null) throw new TypeError('address must be a client address from resolveClientAddress, or null.');
  const client = isIP(canonical) === 6 ? `v6/${ipv6Prefix}:${ipv6Network(canonical, ipv6Prefix)}` : `v4:${canonical}`;
  return `${scope}:${createHmac('sha256', secret).update(`${scope}\0${client}`).digest('base64url')}`;
}
