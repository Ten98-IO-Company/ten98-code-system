/** File name of the generated token inside the app's data directory. */
export declare const BOOTSTRAP_TOKEN_FILE = "bootstrap-token";
/** The shared token rule: 32 to 512 characters with no whitespace. */
export declare function isValidBootstrapToken(value: unknown): value is string;
/**
 * Returns the operator's `BOOTSTRAP_TOKEN` when set, otherwise the token saved in `<dataDir>/bootstrap-token`,
 * creating it exclusively with mode 0600 on first use (a concurrent creator's file wins). An invalid configured or
 * saved token throws with `code: 'BOOTSTRAP_TOKEN_INVALID'`; it is never replaced silently.
 */
export declare function loadBootstrapToken(dataDir: string, provided?: string): {
    token: string;
    source: 'environment' | 'file' | 'generated';
    path?: string;
};
/** Compares a submitted token with the expected one in constant time, whatever their lengths. */
export declare function bootstrapTokenMatches(expected: string, supplied: unknown): boolean;
