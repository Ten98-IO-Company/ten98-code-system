export declare function addressKey(address: string): string;
export declare function publicNetworkAddress(address: string): boolean;
/** Socket evidence permits IPv4-mapped IPv6 equivalence, without admitting mapped DNS targets. */
export declare function pinnedNetworkPeer(remote: unknown, pinned: string): boolean;
export type NetworkAddress = {
    address: string;
    family: 4 | 6;
};
/** Resolve both families completely. The caller must admit the entire answer set before connecting. */
export declare function resolveNetworkHost(hostname: string, signal: AbortSignal): Promise<NetworkAddress[]>;
export type OwnershipTxtOptions = {
    /** Resolver addresses, each an IP with an optional port. Defaults to Cloudflare and Google public DNS. Override only
     * with resolvers that answer from the public DNS, never from an internal view. */
    servers?: readonly string[];
    signal?: AbortSignal;
};
/** TXT records for an ownership proof, from pinned public resolvers rather than the system resolver. One try per server,
 * at most 5 seconds, 64 records, 256 strings per record and 64 KiB in all; a larger answer rejects with code ETXTLIMIT,
 * the deadline with ETIMEOUT. DNS errors keep their codes (ENODATA, ENOTFOUND). An abort rejects with the signal's reason. */
export declare function resolveOwnershipTxt(name: string, options?: OwnershipTxtOptions): Promise<string[][]>;
