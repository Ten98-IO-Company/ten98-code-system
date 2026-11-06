type Json = Record<string, unknown>;
export interface NativeBrowserResource {
    status: number | null;
    body: Uint8Array | null;
    headers?: Readonly<Record<string, string>>;
}
export interface ObserverTransport {
    onmessage?: (message: string) => void;
    onclose?: () => void;
    send(message: string): void;
    close(): void;
}
export interface BrowserControlOptions {
    endpoint: string;
    signal: AbortSignal;
    closeCapability: string;
    origin: string;
    proxyOrigin: string;
    proxyToken: string;
    /** Must synchronously stop admission and destroy forwarding sockets before returning its closure promise. */
    stopEgress(): Promise<void>;
    authorize(url: URL): Promise<Readonly<Record<string, string>>>;
    maxRequests?: number;
    sensitiveHeaderNames?: readonly string[];
    /** Stateless native reader: caller owns DNS admission, post-DNS authorization and bounded decoding; no browser cookies. */
    loadResource?(url: URL, signal: AbortSignal): Promise<NativeBrowserResource>;
}
type DenialReason = 'network-identity-unavailable' | 'unsupported-url' | 'unsupported-method' | 'main-origin-changed';
declare const resourceTypes: readonly ['Document', 'Stylesheet', 'Image', 'Media', 'Font', 'Script', 'TextTrack', 'XHR', 'Fetch', 'Prefetch', 'EventSource', 'WebSocket', 'Manifest', 'SignedExchange', 'Ping', 'CSPViolationReport', 'Preflight', 'Other'];
export interface BrowserRequestDenial {
    reason: DenialReason;
    resourceType: (typeof resourceTypes)[number] | 'Unknown';
    method: 'GET' | 'HEAD' | 'POST' | 'Other';
    targetType: 'page' | 'iframe' | 'worker' | 'other';
}
export interface BrowserControlTrace {
    at: number;
    event: string;
    method?: string;
    session?: string;
    targetType?: string;
    phase?: string;
    requestId?: string;
}
/** The caller owns the isolated capsule, current authority and proxy lifetime. Observers are trusted pinned clients. */
export declare function createBrowserAuditControl(options: BrowserControlOptions): Promise<{
    send: (method: string, params?: Json, sessionId?: string) => Promise<Json>;
    createObserverTransport: () => Promise<ObserverTransport>;
    close: () => Promise<void>;
    signal: AbortSignal;
    sessionForTarget: (id: string) => Promise<string>;
    readonly stats: {
        physicalConnections: number;
        requests: number;
        admissions: number;
        denials: number;
        protocolDenials: number;
        proxyChallenges: number;
        commands: number;
        nativeResourceRequests: number;
        nativeResourceBytes: number;
        mainTargetId: string | undefined;
        closed: boolean;
        socketClosed: boolean;
        failure: string | undefined;
        reportIncomplete: boolean;
        deniedRequests: {
            reason: DenialReason;
            resourceType: (typeof resourceTypes)[number] | 'Unknown';
            method: 'GET' | 'HEAD' | 'POST' | 'Other';
            targetType: 'page' | 'iframe' | 'worker' | 'other';
        }[];
        deniedCommands: {
            method: 'Network.loadNetworkResource';
            reason: 'unmediated-resource-loader';
        }[];
        recentObserverMethods: string[];
        trace: {
            at: number;
            event: string;
            method?: string;
            session?: string;
            targetType?: string;
            phase?: string;
            requestId?: string;
        }[];
        nativeResourceReading: string;
        activeStreams: number;
        streamBytes: number;
        pendingResourceLoads: number;
        targets: {
            targetId: string;
            sessionId: string;
            type: string;
            ready: boolean;
            detached: boolean;
        }[];
    };
}>;
export {};
