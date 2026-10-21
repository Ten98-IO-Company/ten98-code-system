// Ported from Ten98 Discover (MIT), commit e36503c: src/server/db.ts:22-54 (migration sources, checksum,
// ordering and SCHEMA_MISMATCH) and src/server/cli.ts:38-65 (single-transaction advisory-locked migrate).
// The caller supplies a PostgreSQL client, so this package keeps no runtime dependency on `pg`.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The subset of a `pg` client or pool that the ledger uses. */
export interface MigrationClient {
  query<R = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: R[] }>;
}
export interface Migration { readonly version: string; readonly name: string; readonly sql: string; readonly checksum: string }
type AppliedMigration = Readonly<{ version: string; checksum: string }>;

function schemaMismatch(): Error {
  return Object.assign(new Error('Database schema is incompatible with this application. Use the matching image and migrations.'), { code: 'SCHEMA_MISMATCH' });
}

/**
 * Ordered, checksummed SQL migrations recorded in a `schema_version(version, checksum)` table.
 * `files` lists the migration filenames in application order; the first four characters of each are its version.
 * Apps keep their file list, directory, lock key, authorization and any post-migration data work.
 */
export function createMigrationLedger({ directory, files, lockKey }: {
  directory: string | URL; files: readonly string[]; lockKey: readonly [number, number];
}) {
  let migrations: Promise<readonly Migration[]> | undefined;
  const folder = typeof directory === 'string' ? directory : fileURLToPath(directory);

  function sources(): Promise<readonly Migration[]> {
    if (!migrations) migrations = Promise.all(files.map(async (name): Promise<Migration> => {
      // Git line-ending conversion must not change a migration's identity across host operating systems.
      const sql = (await readFile(join(folder, name), 'utf8')).replace(/\r\n?/g, '\n');
      return Object.freeze({ version: name.slice(0, 4), name, sql, checksum: createHash('sha256').update(sql).digest('hex') });
    })).then(loaded => Object.freeze(loaded)).catch(error => { migrations = undefined; throw error; });
    return migrations;
  }

  /** Returns the unapplied suffix; applied rows must be an exact prefix of the sources by version and checksum. */
  async function pending(applied: readonly AppliedMigration[]): Promise<readonly Migration[]> {
    const all = await sources();
    if (applied.length > all.length || applied.some((row, index) => row.version !== all[index]!.version || row.checksum !== all[index]!.checksum)) {
      throw schemaMismatch();
    }
    return all.slice(applied.length);
  }

  async function assertCurrent(client: MigrationClient): Promise<void> {
    const { rows } = await client.query<AppliedMigration>('SELECT version, checksum FROM schema_version ORDER BY version');
    if ((await pending(rows)).length !== 0) throw schemaMismatch();
  }

  /**
   * Applies every pending migration in one locked transaction and returns the applied versions.
   * `client` must be a dedicated connection (such as `pool.connect()`), never a pool, because BEGIN/COMMIT must share a session.
   * `afterApply` runs inside the transaction, only when something was applied; its failure rolls everything back.
   */
  async function migrate(client: MigrationClient, { afterApply }: {
    afterApply?(client: MigrationClient, applied: readonly string[]): Promise<void>;
  } = {}): Promise<readonly string[]> {
    await sources();
    const applied: string[] = [];
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock($1, $2)', [lockKey[0], lockKey[1]]);
      await client.query('CREATE TABLE IF NOT EXISTS schema_version (version text PRIMARY KEY, checksum text NOT NULL)');
      const current = await client.query<AppliedMigration>('SELECT version, checksum FROM schema_version ORDER BY version');
      for (const migration of await pending(current.rows)) {
        await client.query(migration.sql);
        await client.query('INSERT INTO schema_version(version, checksum) VALUES ($1, $2)', [migration.version, migration.checksum]);
        applied.push(migration.version);
      }
      if (applied.length > 0) await afterApply?.(client, Object.freeze([...applied]));
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    }
    return Object.freeze(applied);
  }

  return { sources, pending, assertCurrent, migrate };
}
