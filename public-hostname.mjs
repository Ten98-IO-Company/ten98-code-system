// Public DNS hostnames typed by users. Promoted from Discover src/server/domains.ts normalizePublicHostname and
// src/server/context-input.ts contextHost (v0.7.4), which applied the same rule; apps keep their error messages and any
// extra length budget, such as Discover's ownership-proof record prefix.
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
// Special-use and non-public names (RFC 6761, 6762, 7686, 8375 and 9476) and every name below them.
const specialSuffixes = ['localhost', 'local', 'internal', 'invalid', 'test', 'example', 'onion', 'home.arpa', 'alt'];
/**
 * The lowercase ASCII (punycode) form of a public hostname, or null. Refuses anything that is not a bare DNS name: a
 * scheme, path, port, credentials, wildcard, percent escape, whitespace, control character or lone surrogate; an IP
 * address in any spelling; a single label; a special-use name; an all-numeric top-level label; a label outside
 * 1 to 63 letters, digits and inner hyphens; or more than 253 characters. One trailing dot is accepted and removed.
 */
export function normalizePublicHostname(input) {
    // The length cap only keeps huge input away from domainToASCII; anything over 253 characters fails below anyway.
    if (typeof input !== 'string' || !input || input.length > 1024 || /[\s\u0000-\u001f\u007f%/\\:@?#*]/u.test(input))
        return null;
    // domainToASCII returns '' for invalid input, including lone surrogates.
    const ascii = domainToASCII(input.endsWith('.') ? input.slice(0, -1) : input).toLowerCase();
    if (!ascii || ascii.length > 253 || specialSuffixes.some(suffix => ascii === suffix || ascii.endsWith(`.${suffix}`)))
        return null;
    const labels = ascii.split('.');
    if (labels.length < 2 || labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)))
        return null;
    // WHATWG URL parsing treats a numeric or hex last label as IPv4: a malformed one fails, which refuses all-numeric
    // top-level labels, and any IPv4 spelling (dotted, integer, hex, octal) becomes an address.
    const parsed = URL.parse(`https://${ascii}`);
    if (!parsed || isIP(parsed.hostname))
        return null;
    return ascii;
}
