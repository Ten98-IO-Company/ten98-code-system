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
};
export {};
