export type PublicHostnameOptions = {
    /** Tests only: accept a name whose suffix is not in the Public Suffix List's ICANN section. Never set in production. */
    allowUnlistedSuffixForTesting?: boolean;
};
/**
 * The lowercase ASCII (punycode) form of a public hostname, or null. Refuses anything that is not a bare DNS name: a
 * scheme, path, port, credentials, wildcard, percent escape, whitespace, control character or lone surrogate; an IP
 * address in any spelling; a single label; a special-use name or anything under arpa; an all-numeric top-level label; a
 * label outside 1 to 63 letters, digits and inner hyphens; or more than 253 characters. The name must end in a suffix
 * from the Public Suffix List's ICANN section, with at least one label to its left, so a suffix itself (com, co.uk) and
 * a name on an unlisted suffix (corp, home, a top-level domain newer than the shipped list) are refused. One trailing
 * dot is accepted and removed.
 */
export declare function normalizePublicHostname(input: unknown, options?: PublicHostnameOptions): string | null;
