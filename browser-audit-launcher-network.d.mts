export interface BrowserAuditNamespaceIdentity {
    dev: string;
    ino: string;
}
export interface BrowserAuditContainerIdentity {
    id: string;
    image: string;
    pid: number;
    startTicks: string;
    startedAt: string;
    restartCount: number;
    running: boolean;
    labels: Record<string, string>;
    networks: Record<string, {
        ipv4: string;
        ipv6: string;
    }>;
}
export interface BrowserAuditNetworkIdentity {
    networkId: string;
    capsule: BrowserAuditContainerIdentity;
    worker: BrowserAuditContainerIdentity;
}
export interface BrowserAuditNetworkPolicy {
    ipv4: string;
    ipv6: string;
    sha256: string;
}
export interface BrowserAuditNamespaceCommand {
    executable: '/usr/bin/nsenter';
    args: readonly string[];
    fd: number;
    input: string;
    environment: Readonly<Record<string, string>>;
    timeoutMs: 2000;
    maxOutputBytes: 65536;
    shell: false;
}
/** inspect must supply a fresh snapshot from the host's fixed local Docker authority. */
export interface BrowserAuditNetworkAdapter {
    inspect(signal: AbortSignal): Promise<BrowserAuditNetworkIdentity>;
    processStart(pid: number): string;
    namespace(pid: number | 'self'): BrowserAuditNamespaceIdentity;
    openNamespace(pid: number): number;
    descriptor(fd: number): BrowserAuditNamespaceIdentity;
    close(fd: number): void;
    execute(command: BrowserAuditNamespaceCommand): Promise<string>;
}
export declare function createBrowserAuditNetworkPolicy(capsuleAddress: string, workerAddress: string): BrowserAuditNetworkPolicy;
export declare function verifyBrowserAuditNetworkPolicy(policy: BrowserAuditNetworkPolicy, ipv4: string, ipv6: string, nftRuleset: string): void;
/** Native filesystem/process adapter; constructing it performs no host operation. */
export declare function createBrowserAuditNetworkAdapter(inspect: BrowserAuditNetworkAdapter['inspect']): BrowserAuditNetworkAdapter;
/** The passive gate must remain closed until apply() and the caller's final verify() both succeed. */
export declare function pinBrowserAuditNetwork(expected: BrowserAuditNetworkIdentity, adapter: BrowserAuditNetworkAdapter): Promise<{
    policy: BrowserAuditNetworkPolicy;
    prepareDockerDns: () => Promise<{
        removed: boolean;
    }>;
    apply: () => Promise<{
        policySha256: string;
        namespace: {
            dev: string;
            ino: string;
        };
    }>;
    verify: () => Promise<{
        policySha256: string;
        namespace: {
            dev: string;
            ino: string;
        };
    }>;
    close: () => void;
}>;
