/** The subset of a `pg` client or pool that the ledger uses. */
export interface MigrationClient {
    query<R extends Record<string, unknown> = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{
        rows: R[];
    }>;
}
export interface Migration {
    readonly version: string;
    readonly filename: string;
    readonly sql: string;
    readonly checksum: string;
}
type AppliedMigration = Readonly<{
    version: string;
    checksum: string;
}>;
/** A pooled connection: `release(error)` discards it, which also ends its session locks and any open transaction. */
export interface MigrationPoolClient extends MigrationClient {
    release(error?: Error | boolean): void;
}
export interface MigrationPool {
    connect(): Promise<MigrationPoolClient>;
}
/** Startup failures carry operator-safe text only: never SQL, parameters, connection strings or credentials. */
export type MigrationStartupError = Error & {
    code: 'MIGRATION_TIMEOUT' | 'MIGRATION_FAILED';
    sqlState?: string;
};
/** MIGRATE_ON_START: unset, empty, `true` or `1` migrates at startup; `false` or `0` waits for an operator migration. */
export declare function migrateOnStart(value: string | undefined): boolean;
/**
 * Ordered, checksummed SQL migrations recorded in a `schema_version(version, checksum)` table.
 * `files` lists the migration filenames in application order; the first four characters of each are its version.
 * Apps keep their file list, directory, lock key, authorization and any post-migration data work.
 */
export declare function createMigrationLedger({ directory, files, lockKey }: {
    directory: string | URL;
    files: readonly string[];
    lockKey: readonly [number, number];
}): {
    sources: () => Promise<readonly Migration[]>;
    pending: (applied: readonly AppliedMigration[]) => Promise<readonly Migration[]>;
    assertCurrent: (client: MigrationClient) => Promise<void>;
    migrate: (client: MigrationClient, { afterApply, lockTimeoutMs }?: {
        afterApply?(client: MigrationClient, applied: readonly string[]): Promise<void>;
        lockTimeoutMs?: number;
    }) => Promise<readonly string[]>;
    migrateWithDeadline: (pool: MigrationPool, { timeoutMs, retryIntervalMs, progressIntervalMs, log, afterApply }?: {
        timeoutMs?: number;
        retryIntervalMs?: number;
        progressIntervalMs?: number;
        log?(message: string): void;
        afterApply?(client: MigrationClient, applied: readonly string[]): Promise<void>;
    }) => Promise<readonly string[]>;
    waitForCurrent: (client: MigrationClient, { timeoutMs, intervalMs, progressIntervalMs, log }?: {
        timeoutMs?: number;
        intervalMs?: number;
        progressIntervalMs?: number;
        log?(message: string): void;
    }) => Promise<void>;
};
export {};
