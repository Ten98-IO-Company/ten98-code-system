/** Signature text encoding: `base64url` (43 characters) or `hex` (64 characters). */
export type CapabilityEncoding = 'base64url' | 'hex';
/** Signs a JSON-serialisable payload for one purpose. Different purposes never accept each other's tokens. */
export declare function signCapability(purpose: string, payload: unknown, secret: string, { encoding }?: {
    encoding?: CapabilityEncoding;
}): string;
/**
 * The payload of a token signed for `purpose`, or null when the token is not a string, is longer than `maxLength`, is not
 * exactly `body.signature`, uses non-canonical base64url, has a wrong signature (compared in constant time) or does not
 * hold JSON. Configuration errors (purpose, secret, encoding) throw instead.
 */
export declare function readCapability(purpose: string, token: unknown, secret: string, { maxLength, encoding }?: {
    maxLength?: number;
    encoding?: CapabilityEncoding;
}): unknown;
