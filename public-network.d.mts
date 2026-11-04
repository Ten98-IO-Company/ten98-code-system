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
