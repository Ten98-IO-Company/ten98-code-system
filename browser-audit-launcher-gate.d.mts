import type { Readable } from 'node:stream';
export interface BrowserAuditGateOptions {
    input?: Readable;
    environment?: NodeJS.ProcessEnv;
    run?: () => Promise<void>;
    terminate?: (released: boolean) => void;
    forceExit?: () => void;
}
/** Trusted process entry: the host alone supplies readiness through stdin after verifying isolation. */
export declare function runBrowserAuditLauncherGate(options?: BrowserAuditGateOptions): {
    readonly phase: "failed" | "released" | "waiting";
};
