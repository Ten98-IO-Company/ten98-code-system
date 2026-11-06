import http from 'node:http';
export type PublicEgressOptions = {
    token: string;
    signal: AbortSignal;
    expiresAt: number;
    authorize?: (targetUrl: string, signal: AbortSignal) => boolean | Promise<boolean>;
};
/** Job-local transport only. The caller creates one random 32-byte token and owns native access checks. */
export declare function createPublicEgressProxy(options: PublicEgressOptions): {
    server: http.Server<typeof http.IncomingMessage, typeof http.ServerResponse>;
    close: () => Promise<void>;
    stats: Readonly<{
        limits: Readonly<{
            connections: 32;
            admissions: 1000;
            forwardedBytes: number;
            headerBytes: number;
            dialMs: 5000;
            idleMs: 15000;
            lifetimeMs: 120000;
        }>;
        readonly admissions: number;
        readonly activeConnections: number;
        readonly forwardedBytes: number;
        readonly networkBytesRead: number;
        readonly networkBytesWritten: number;
        readonly stopped: boolean;
    }>;
};
