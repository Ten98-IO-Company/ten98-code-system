import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createMigrationLedger } from '../index.mjs';

type Row = Record<string, string>;
const pgError = (code: string, message = 'pg error') => Object.assign(new Error(message), { code });
const SHOW_TIMEOUT = "SELECT current_setting('lock_timeout') AS lock_timeout";
const SET_TIMEOUT = "SELECT set_config('lock_timeout', $1, true)";
const LOCK = 'SELECT pg_advisory_xact_lock($1, $2)';

function ledgerFor(files: Record<string, string>) {
  const directory = mkdtempSync(join(tmpdir(), 'ten98-ledger-guards-'));
  for (const [name, text] of Object.entries(files)) writeFileSync(join(directory, name), text);
  return { ledger: createMigrationLedger({ directory, files: Object.keys(files), lockKey: [7, 8] }), cleanup: () => rmSync(directory, { recursive: true, force: true }) };
}

// Answers the session's lock_timeout as '2s'; `handler` may override any statement.
function client(handler: (sql: string) => { rows: Row[] } | Error | undefined = () => undefined) {
  const calls: string[] = [];
  const params: (unknown[] | undefined)[] = [];
  return {
    calls,
    params,
    async query<R extends Record<string, unknown> = Record<string, unknown>>(sql: string, values?: unknown[]): Promise<{ rows: R[] }> {
      calls.push(sql);
      params.push(values);
      const result = handler(sql) ?? { rows: sql === SHOW_TIMEOUT ? [{ lock_timeout: '2s' }] : [] };
      if (result instanceof Error) throw result;
      return result as unknown as { rows: R[] };
    },
  };
}

test('assertCurrent reports a missing schema_version table as SCHEMA_MISMATCH', async () => {
  const { ledger, cleanup } = ledgerFor({ '0001_a.sql': 'CREATE TABLE a();\n' });
  try {
    const fresh = client(sql => sql.startsWith('SELECT version') ? pgError('42P01', 'relation "schema_version" does not exist') : undefined);
    await assert.rejects(ledger.assertCurrent(fresh), (error: unknown) => (error as { code?: string }).code === 'SCHEMA_MISMATCH');
    // Other driver errors still surface as they are.
    const down = client(() => pgError('57P01', 'terminating connection'));
    await assert.rejects(ledger.assertCurrent(down), (error: unknown) => (error as { code?: string }).code === '57P01');
  } finally { cleanup(); }
});

test('migrate with lockTimeoutMs bounds only the lock wait and reports MIGRATION_LOCK_TIMEOUT', async () => {
  const { ledger, cleanup } = ledgerFor({ '0001_a.sql': 'CREATE TABLE a();\n' });
  try {
    const busy = client(sql => sql === LOCK ? pgError('55P03', 'canceling statement due to lock timeout') : undefined);
    await assert.rejects(ledger.migrate(busy, { lockTimeoutMs: 5000 }), (error: unknown) => (error as { code?: string }).code === 'MIGRATION_LOCK_TIMEOUT');
    assert.deepEqual(busy.calls.slice(0, 4), ['BEGIN', SHOW_TIMEOUT, SET_TIMEOUT, LOCK]);
    assert.deepEqual(busy.params[2], ['5000']);
    assert.equal(busy.calls.at(-1), 'ROLLBACK');
    assert.equal(busy.calls.some(sql => sql.startsWith('CREATE TABLE a')), false);

    // Once the lock is held, the session's own timeout is back before any migration runs.
    const held = client();
    assert.deepEqual(await ledger.migrate(held, { lockTimeoutMs: 5000 }), ['0001']);
    const restore = held.calls.indexOf(SET_TIMEOUT, held.calls.indexOf(LOCK));
    assert.equal(restore, held.calls.indexOf(LOCK) + 1);
    assert.deepEqual(held.params[restore], ['2s']);
    assert.ok(restore < held.calls.indexOf('CREATE TABLE a();\n'));

    // Without the option the wait is unbounded and the timeout is never touched, as before.
    const free = client();
    assert.deepEqual(await ledger.migrate(free), ['0001']);
    assert.equal(free.calls.some(sql => sql.includes('lock_timeout')), false);
    // A lock error without the option is not relabelled.
    const odd = client(sql => sql === LOCK ? pgError('55P03') : undefined);
    await assert.rejects(ledger.migrate(odd), (error: unknown) => (error as { code?: string }).code === '55P03');
    for (const lockTimeoutMs of [0, -1, 1.5, Number.NaN, 2147483648]) await assert.rejects(ledger.migrate(free, { lockTimeoutMs }), TypeError);
    assert.deepEqual(await ledger.migrate(client(), { lockTimeoutMs: 2147483647 }), ['0001']);
  } finally { cleanup(); }
});
