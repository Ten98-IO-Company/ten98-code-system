/**
 * The lowercase ASCII (punycode) form of a public hostname, or null. Refuses anything that is not a bare DNS name: a
 * scheme, path, port, credentials, wildcard, percent escape, whitespace, control character or lone surrogate; an IP
 * address in any spelling; a single label; a special-use name; an all-numeric top-level label; a label outside
 * 1 to 63 letters, digits and inner hyphens; or more than 253 characters. One trailing dot is accepted and removed.
 */
export declare function normalizePublicHostname(input: unknown): string | null;
