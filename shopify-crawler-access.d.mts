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
export type ShopifyVerificationKey = Omit<CryptoKey, 'usages'> & {
    readonly usages: readonly string[];
};
/** Parses the supported Shopify signature subset, including expired credentials for metadata display. */
export declare function parseShopifyCrawlerAccess(input: unknown): ShopifyCrawlerAccess | null;
/** Selects only the fixed signature headers for the credential's exact HTTPS origin before expiry. */
export declare function shopifyCrawlerHeadersFor(url: string, input: unknown, now?: number): Readonly<Record<string, string>>;
/** Verifies signed authority bytes with a caller-supplied Ed25519 public key; performs no key lookup or expiry check. */
export declare function verifyShopifyCrawlerAccess(input: unknown, key: ShopifyVerificationKey): Promise<'valid' | 'wrong_domain' | 'invalid'>;
