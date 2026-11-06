export declare function createCapsuleCloseIntent(capability: string): {
    readonly phase: "active" | "armed" | "exited" | "failed";
    prepare(provided: unknown, identity: unknown, expected: string, connections: number, now?: number): void;
    disconnected(now?: number): boolean;
    exit(code: number | null, signal: NodeJS.Signals | null, now?: number): boolean;
    fail(): void;
};
export declare function runCapsule(): Promise<void>;
