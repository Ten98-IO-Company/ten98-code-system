// Ported from Ten98 Discover (MIT), commit e36503c: src/server/db.ts:22-54 (migration sources, checksum,
// ordering and SCHEMA_MISMATCH) and src/server/cli.ts:38-65 (single-transaction advisory-locked migrate).
// The caller supplies a PostgreSQL client, so this package keeps no runtime dependency on `pg`.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The subset of a `pg` client or pool that the ledger uses. */
export interface MigrationClient {
  // R is bounded like pg's QueryResultRow so a pg Client or PoolClient is assignable without a cast.
  query<R extends Record<string, unknown> = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: R[] }>;
}
export interface Migration { readonly version: string; readonly filename: string; readonly sql: string; readonly checksum: string }
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
    if (!migrations) migrations = Promise.all(files.map(async (filename): Promise<Migration> => {
      // Git line-ending conversion must not change a migration's identity across host operating systems.
      const sql = (await readFile(join(folder, filename), 'utf8')).replace(/\r\n?/g, '\n');
      return Object.freeze({ version: filename.slice(0, 4), filename, sql, checksum: createHash('sha256').update(sql).digest('hex') });
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
    let rows: readonly AppliedMigration[];
    try { ({ rows } = await client.query<AppliedMigration>('SELECT version, checksum FROM schema_version ORDER BY version')); }
    catch (error) {
      // A database that was never migrated has no ledger table (undefined_table); it is as far behind as an empty ledger.
      if ((error as { code?: unknown } | null)?.code !== '42P01') throw error;
      rows = [];
    }
    if ((await pending(rows)).length !== 0) throw schemaMismatch();
  }

  /**
   * Applies every pending migration in one locked transaction and returns the applied versions.
   * `client` must be a dedicated connection (such as `pool.connect()`), never a pool, because BEGIN/COMMIT must share a session.
   * `afterApply` runs inside the transaction, only when something was applied; its failure rolls everything back.
   * `lockTimeoutMs` bounds only the wait for another instance's migration lock; when it expires, nothing is applied and the
   * error has `code: 'MIGRATION_LOCK_TIMEOUT'`. The connection's own lock_timeout then applies to the migrations themselves.
   * Without it the wait is unbounded, as before.
   */
  async function migrate(client: MigrationClient, { afterApply, lockTimeoutMs }: {
    afterApply?(client: MigrationClient, applied: readonly string[]): Promise<void>;
    lockTimeoutMs?: number;
  } = {}): Promise<readonly string[]> {
    // PostgreSQL's lock_timeout is an int of milliseconds.
    if (lockTimeoutMs !== undefined && (!Number.isInteger(lockTimeoutMs) || lockTimeoutMs < 1 || lockTimeoutMs > 2147483647)) {
      throw new TypeError('lockTimeoutMs must be an integer from 1 to 2147483647.');
    }
    await sources();
    const applied: string[] = [];
    try {
      await client.query('BEGIN');
      let previous: string | undefined;
      if (lockTimeoutMs !== undefined) {
        previous = (await client.query<{ lock_timeout: string }>("SELECT current_setting('lock_timeout') AS lock_timeout")).rows[0]!.lock_timeout;
        // is_local: the value lasts only until COMMIT or ROLLBACK, so it never leaks into the connection's later use.
        await client.query("SELECT set_config('lock_timeout', $1, true)", [String(lockTimeoutMs)]);
      }
      try { await client.query('SELECT pg_advisory_xact_lock($1, $2)', [lockKey[0], lockKey[1]]); }
      catch (error) {
        // lock_not_available: another instance still holds the migration lock.
        if (lockTimeoutMs !== undefined && (error as { code?: unknown } | null)?.code === '55P03') {
          throw Object.assign(new Error('Another instance is still applying migrations.'), { code: 'MIGRATION_LOCK_TIMEOUT' });
        }
        throw error;
      }
      // The bound covers only the advisory lock; migration statements wait for table locks as they did before.
      if (previous !== undefined) await client.query("SELECT set_config('lock_timeout', $1, true)", [previous]);
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
