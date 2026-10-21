// Client address behind trusted reverse proxies, for per-client rate limits and similar keys.
// Promoted from ten98-discover src/server/analytics-network.ts @ 61c3154 (normalizeIp, addressList, the X-Forwarded-For walk).
// Callers retain what the address is used for; it is ephemeral input, never something to log or store.
import { BlockList, isIP, SocketAddress } from 'node:net';
function configError() {
    throw Object.assign(new Error('Invalid trusted proxy configuration.'), { code: 'CLIENT_ADDRESS_CONFIG' });
}
/** Canonical IPv4 or IPv6 text, with IPv4-mapped IPv6 unwrapped; null for anything else, including zone ids and brackets. */
export function normalizeClientAddress(value) {
    if (typeof value !== 'string' || value.length > 64 || /[%\s\[\]"']/.test(value))
        return null;
    const version = isIP(value);
    if (!version)
        return null;
    try {
        const address = new SocketAddress({ address: value, family: version === 4 ? 'ipv4' : 'ipv6', port: 0 }).address;
        return address.startsWith('::ffff:') && isIP(address.slice(7)) === 4 ? address.slice(7) : address;
    }
    catch {
        return null;
    }
}
/** Parse a comma-separated list of addresses and CIDR subnets, such as a TRUSTED_PROXIES setting. Invalid input throws CLIENT_ADDRESS_CONFIG without echoing it. */
export function parseTrustedProxies(raw) {
    if (raw === undefined)
        raw = '';
    if (typeof raw !== 'string' || raw.length > 4096)
        configError();
    const entries = raw.trim() ? raw.split(',').map(value => value.trim()) : [];
    if (entries.length > 32)
        configError();
    const list = new BlockList();
    for (const entry of entries) {
        const parts = entry.split('/');
        if (parts.length > 2)
            configError();
        const address = normalizeClientAddress(parts[0]);
        if (address === null)
            configError();
        const family = isIP(address) === 4 ? 'ipv4' : 'ipv6';
        try {
            if (parts.length === 1)
                list.addAddress(address, family);
            else {
                if (!/^(0|[1-9]\d{0,2})$/.test(parts[1]))
                    configError();
                let prefix = Number(parts[1]);
                const originalFamily = isIP(parts[0]);
                if (prefix > (originalFamily === 4 ? 32 : 128))
                    configError();
                // A mapped IPv6 subnet describes IPv4 only within its 96-bit mapped prefix.
                if (originalFamily === 6 && family === 'ipv4') {
                    if (prefix < 96)
                        configError();
                    prefix -= 96;
                }
                list.addSubnet(address, prefix, family);
            }
        }
        catch {
            configError();
        }
    }
    return list;
}
/**
 * The connecting client's address. A peer outside `trustedProxies` is the client itself and its headers are ignored.
 * A trusted peer yields the right-most X-Forwarded-For hop that is not itself trusted.
 * Returns null when the address is unknown: an invalid peer, or a trusted peer with a missing, malformed, oversized or all-trusted chain.
 * Callers must give null a conservative key of their own rather than sharing one bucket across clients.
 */
export function resolveClientAddress(peerAddress, forwardedFor, trustedProxies) {
    const peer = normalizeClientAddress(peerAddress);
    if (peer === null)
        return null;
    const isTrusted = (address) => trustedProxies.check(address, isIP(address) === 4 ? 'ipv4' : 'ipv6');
    if (!isTrusted(peer))
        return peer;
    if (typeof forwardedFor !== 'string' || !forwardedFor || Buffer.byteLength(forwardedFor, 'utf8') > 4096)
        return null;
    const parts = forwardedFor.split(',');
    if (parts.length > 20)
        return null;
    const chain = parts.map(value => normalizeClientAddress(value.replace(/^[ \t]+|[ \t]+$/g, '')));
    if (chain.some(value => value === null))
        return null;
    for (let index = chain.length - 1; index >= 0; index--) {
        const address = chain[index];
        if (!isTrusted(address))
            return address;
    }
    return null;
}
