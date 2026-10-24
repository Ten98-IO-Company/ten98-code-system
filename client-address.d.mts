/** Parsed proxy list. Structural, so the public declarations need no Node type definitions. */
export interface TrustedProxies {
    check(address: string, type?: 'ipv4' | 'ipv6'): boolean;
}
/** Canonical IPv4 or IPv6 text, with IPv4-mapped IPv6 unwrapped; null for anything else, including zone ids and brackets. */
export declare function normalizeClientAddress(value: unknown): string | null;
/** Parse a comma-separated list of addresses and CIDR subnets, such as a TRUSTED_PROXIES setting. Invalid input throws CLIENT_ADDRESS_CONFIG without echoing it. */
export declare function parseTrustedProxies(raw: unknown): TrustedProxies;
/**
 * The connecting client's address. A peer outside `trustedProxies` is the client itself and its headers are ignored.
 * A trusted peer yields the right-most X-Forwarded-For hop that is not itself trusted.
 * Returns null when the address is unknown: an invalid peer, or a trusted peer with a missing, malformed, oversized or all-trusted chain.
 * Callers must give null a conservative key of their own rather than sharing one bucket across clients.
 */
export declare function resolveClientAddress(peerAddress: unknown, forwardedFor: string | null | undefined, trustedProxies: TrustedProxies): string | null;
/**
 * A rate-limit key for one client within `scope`, derived with HMAC so the stored key never reveals the address.
 * Pass the result of {@link resolveClientAddress}. A null (unresolved) address gets the dedicated key `<scope>:unresolved`,
 * kept apart from every resolved client; give it its own, stricter limit rather than letting it share a client's bucket.
 */
export declare function clientLimitKey(scope: string, address: string | null, secret: string): string;
