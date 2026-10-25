// Ported from Ten98 Discover (MIT), commit e36503c: src/server/db.ts:22-54 (migration sources, checksum,
// ordering and SCHEMA_MISMATCH) and src/server/cli.ts:38-65 (single-transaction advisory-locked migrate).
// The startup runner (migrateWithDeadline, waitForCurrent, migrateOnStart) is from Discover src/server/startup-migrate.ts
// (dev, 2026-10-25), with Campaign's statement_timeout lift from server/database.ts.
// The caller supplies a PostgreSQL client, so this package keeps no runtime dependency on `pg`.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
const startupError = (code, message, sqlState) => Object.assign(new Error(message), { code, ...(sqlState ? { sqlState } : {}) });
const seconds = (ms) => `${Math.round(ms / 1000)} seconds`;
const positive = (value, name) => { if (!Number.isSafeInteger(value) || value < 1)
    throw new TypeError(`${name} must be a positive safe integer.`); };
/** MIGRATE_ON_START: unset, empty, `true` or `1` migrates at startup; `false` or `0` waits for an operator migration. */
export function migrateOnStart(value) {
    const setting = value?.trim().toLowerCase();
    if (setting === undefined || setting === '' || setting === 'true' || setting === '1')
        return true;
    if (setting === 'false' || setting === '0')
        return false;
    throw new TypeError('MIGRATE_ON_START must be true or false.');
}
function schemaMismatch() {
    return Object.assign(new Error('Database schema is incompatible with this application. Use the matching image and migrations.'), { code: 'SCHEMA_MISMATCH' });
}
/**
 * Ordered, checksummed SQL migrations recorded in a `schema_version(version, checksum)` table.
 * `files` lists the migration filenames in application order; the first four characters of each are its version.
 * Apps keep their file list, directory, lock key, authorization and any post-migration data work.
 */
export function createMigrationLedger({ directory, files, lockKey }) {
    let migrations;
    const folder = typeof directory === 'string' ? directory : fileURLToPath(directory);
    function sources() {
        if (!migrations)
            migrations = Promise.all(files.map(async (filename) => {
                // Git line-ending conversion must not change a migration's identity across host operating systems.
                const sql = (await readFile(join(folder, filename), 'utf8')).replace(/\r\n?/g, '\n');
                return Object.freeze({ version: filename.slice(0, 4), filename, sql, checksum: createHash('sha256').update(sql).digest('hex') });
            })).then(loaded => Object.freeze(loaded)).catch(error => { migrations = undefined; throw error; });
        return migrations;
    }
    /** Returns the unapplied suffix; applied rows must be an exact prefix of the sources by version and checksum. */
    async function pending(applied) {
        const all = await sources();
        if (applied.length > all.length || applied.some((row, index) => row.version !== all[index].version || row.checksum !== all[index].checksum)) {
            throw schemaMismatch();
        }
        return all.slice(applied.length);
    }
    async function assertCurrent(client) {
        let rows;
        try {
            ({ rows } = await client.query('SELECT version, checksum FROM schema_version ORDER BY version'));
        }
        catch (error) {
            // A database that was never migrated has no ledger table (undefined_table); it is as far behind as an empty ledger.
            if (error?.code !== '42P01')
                throw error;
            rows = [];
        }
        if ((await pending(rows)).length !== 0)
            throw schemaMismatch();
    }
    /**
     * Applies every pending migration in one locked transaction and returns the applied versions.
     * `client` must be a dedicated connection (such as `pool.connect()`), never a pool, because BEGIN/COMMIT must share a session.
     * `afterApply` runs inside the transaction, only when something was applied; its failure rolls everything back.
     * `lockTimeoutMs` bounds only the wait for another instance's migration lock; when it expires, nothing is applied and the
     * error has `code: 'MIGRATION_LOCK_TIMEOUT'`. The connection's own lock_timeout then applies to the migrations themselves.
     * Without it the wait is unbounded, as before.
     */
    async function migrate(client, { afterApply, lockTimeoutMs } = {}) {
        // PostgreSQL's lock_timeout is an int of milliseconds.
        if (lockTimeoutMs !== undefined && (!Number.isInteger(lockTimeoutMs) || lockTimeoutMs < 1 || lockTimeoutMs > 2147483647)) {
            throw new TypeError('lockTimeoutMs must be an integer from 1 to 2147483647.');
        }
        await sources();
        const applied = [];
        try {
            await client.query('BEGIN');
            let previous;
            if (lockTimeoutMs !== undefined) {
                previous = (await client.query("SELECT current_setting('lock_timeout') AS lock_timeout")).rows[0].lock_timeout;
                // is_local: the value lasts only until COMMIT or ROLLBACK, so it never leaks into the connection's later use.
                await client.query("SELECT set_config('lock_timeout', $1, true)", [String(lockTimeoutMs)]);
            }
            try {
                await client.query('SELECT pg_advisory_xact_lock($1, $2)', [lockKey[0], lockKey[1]]);
            }
            catch (error) {
                // lock_not_available: another instance still holds the migration lock.
                if (lockTimeoutMs !== undefined && error?.code === '55P03') {
                    throw Object.assign(new Error('Another instance is still applying migrations.'), { code: 'MIGRATION_LOCK_TIMEOUT' });
                }
                throw error;
            }
            // The bound covers only the advisory lock; migration statements wait for table locks as they did before.
            if (previous !== undefined)
                await client.query("SELECT set_config('lock_timeout', $1, true)", [previous]);
            await client.query('CREATE TABLE IF NOT EXISTS schema_version (version text PRIMARY KEY, checksum text NOT NULL)');
            const current = await client.query('SELECT version, checksum FROM schema_version ORDER BY version');
            for (const migration of await pending(current.rows)) {
                await client.query(migration.sql);
                await client.query('INSERT INTO schema_version(version, checksum) VALUES ($1, $2)', [migration.version, migration.checksum]);
                applied.push(migration.version);
            }
            if (applied.length > 0)
                await afterApply?.(client, Object.freeze([...applied]));
            await client.query('COMMIT');
        }
        catch (error) {
            await client.query('ROLLBACK').catch(() => undefined);
            throw error;
        }
        return Object.freeze(applied);
    }
    /**
     * The startup path: takes the session advisory lock, retrying an unavailable database or a lock another instance holds,
     * then applies pending migrations with the connection's statement_timeout lifted, so a pool default (such as 10 s)
     * cannot fail a long migration. `timeoutMs` bounds the lock wait plus the migration. At the deadline the connection is
     * discarded, so the transaction never commits, and the call rejects with `MIGRATION_TIMEOUT`. Other failures reject
     * with `MIGRATION_FAILED` (and the SQLSTATE in `sqlState`); `SCHEMA_MISMATCH` is rethrown as it is.
     */
    async function migrateWithDeadline(pool, { timeoutMs = 300_000, retryIntervalMs = 1000, progressIntervalMs = 15_000, log = () => { }, afterApply } = {}) {
        positive(timeoutMs, 'timeoutMs');
        positive(retryIntervalMs, 'retryIntervalMs');
        positive(progressIntervalMs, 'progressIntervalMs');
        await sources();
        const deadline = Date.now() + timeoutMs;
        let client;
        for (let nextLog = 0; !client;) {
            let waiting = 'the database to accept connections';
            let candidate;
            try {
                candidate = await pool.connect();
                const { rows } = await candidate.query('SELECT pg_try_advisory_lock($1, $2) AS locked', [lockKey[0], lockKey[1]]);
                if (rows[0]?.locked) {
                    client = candidate;
                    break;
                }
                candidate.release();
                waiting = 'another process to finish database migrations';
            }
            catch {
                candidate?.release(true);
            }
            if (Date.now() >= deadline)
                throw startupError('MIGRATION_TIMEOUT', `Database migrations could not start within ${seconds(timeoutMs)} while waiting for ${waiting}. Nothing was applied.`);
            if (Date.now() >= nextLog) {
                log(`Waiting for ${waiting} before applying database migrations.`);
                nextLog = Date.now() + progressIntervalMs;
            }
            await delay(Math.min(retryIntervalMs, Math.max(0, deadline - Date.now())));
        }
        const held = client;
        let released = false, timedOut = false;
        const release = (error) => { if (!released) {
            released = true;
            held.release(error);
        } };
        // Discarding the dedicated connection aborts the in-flight statement's transaction; it can never reach COMMIT.
        const timer = setTimeout(() => { timedOut = true; release(new Error('Migration deadline reached.')); }, Math.max(0, deadline - Date.now()));
        try {
            await held.query('SET statement_timeout = 0');
            return await migrate(held, afterApply ? { afterApply } : {});
        }
        catch (error) {
            if (timedOut)
                throw startupError('MIGRATION_TIMEOUT', `Database migrations did not finish within ${seconds(timeoutMs)}; the migration transaction was abandoned and rolls back.`);
            if (error?.code === 'SCHEMA_MISMATCH')
                throw error;
            const code = error?.code;
            const sqlState = typeof code === 'string' && /^[0-9A-Z]{5}$/.test(code) ? code : undefined;
            throw startupError('MIGRATION_FAILED', `Database migration failed${sqlState ? ` (PostgreSQL error ${sqlState})` : ''} and was rolled back; nothing was applied.`, sqlState);
        }
        finally {
            clearTimeout(timer);
            if (!released) {
                // The connection returns to the pool with the pool's own statement_timeout and without the lock.
                try {
                    await held.query('SELECT pg_advisory_unlock($1, $2)', [lockKey[0], lockKey[1]]);
                    await held.query('RESET statement_timeout');
                    release();
                }
                catch {
                    release(new Error('Migration lock release failed.'));
                }
            }
        }
    }
    /** The opt-out path (MIGRATE_ON_START=false): polls `assertCurrent` without writing until the schema is current, or rejects with `MIGRATION_TIMEOUT`. */
    async function waitForCurrent(client, { timeoutMs = 300_000, intervalMs = 2000, progressIntervalMs = 15_000, log = () => { } } = {}) {
        positive(timeoutMs, 'timeoutMs');
        positive(intervalMs, 'intervalMs');
        positive(progressIntervalMs, 'progressIntervalMs');
        const deadline = Date.now() + timeoutMs;
        for (let nextLog = 0;;) {
            try {
                await assertCurrent(client);
                return;
            }
            catch { /* Not migrated yet, or the database is still starting. */ }
            if (Date.now() >= deadline)
                throw startupError('MIGRATION_TIMEOUT', `The database schema was not current within ${seconds(timeoutMs)}. Run the migrate command, or enable MIGRATE_ON_START.`);
            if (Date.now() >= nextLog) {
                log('Waiting for an operator to apply database migrations.');
                nextLog = Date.now() + progressIntervalMs;
            }
            await delay(Math.min(intervalMs, Math.max(0, deadline - Date.now())));
        }
    }
    return { sources, pending, assertCurrent, migrate, migrateWithDeadline, waitForCurrent };
}
