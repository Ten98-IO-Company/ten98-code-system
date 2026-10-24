import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createMigrationLedger } from '../index.mjs';

type Row = { version: string; checksum: string };
const pgError = (code: string, message = 'pg error') => Object.assign(new Error(message), { code });

function ledgerFor(files: Record<string, string>) {
  const directory = mkdtempSync(join(tmpdir(), 'ten98-ledger-guards-'));
  for (const [name, text] of Object.entries(files)) writeFileSync(join(directory, name), text);
  return { ledger: createMigrationLedger({ directory, files: Object.keys(files), lockKey: [7, 8] }), cleanup: () => rmSync(directory, { recursive: true, force: true }) };
}

function client(handler: (sql: string) => { rows: Row[] } | Error) {
  const calls: string[] = [];
  return {
    calls,
    async query<R extends Record<string, unknown> = Record<string, unknown>>(sql: string): Promise<{ rows: R[] }> {
      calls.push(sql);
      const result = handler(sql);
      if (result instanceof Error) throw result;
      return result as unknown as { rows: R[] };
    },
  };
}

test('assertCurrent reports a missing schema_version table as SCHEMA_MISMATCH', async () => {
  const { ledger, cleanup } = ledgerFor({ '0001_a.sql': 'CREATE TABLE a();\n' });
  try {
    const fresh = client(sql => sql.startsWith('SELECT version') ? pgError('42P01', 'relation "schema_version" does not exist') : { rows: [] });
    await assert.rejects(ledger.assertCurrent(fresh), (error: unknown) => (error as { code?: string }).code === 'SCHEMA_MISMATCH');
    // Other driver errors still surface as they are.
    const down = client(() => pgError('57P01', 'terminating connection'));
    await assert.rejects(ledger.assertCurrent(down), (error: unknown) => (error as { code?: string }).code === '57P01');
  } finally { cleanup(); }
});

test('migrate with lockTimeoutMs bounds the lock wait and reports MIGRATION_LOCK_TIMEOUT', async () => {
  const { ledger, cleanup } = ledgerFor({ '0001_a.sql': 'CREATE TABLE a();\n' });
  try {
    const busy = client(sql => sql.startsWith('SELECT pg_advisory_xact_lock') ? pgError('55P03', 'canceling statement due to lock timeout') : { rows: [] });
    await assert.rejects(ledger.migrate(busy, { lockTimeoutMs: 5000 }), (error: unknown) => (error as { code?: string }).code === 'MIGRATION_LOCK_TIMEOUT');
    assert.deepEqual(busy.calls.slice(0, 3), ['BEGIN', 'SET LOCAL lock_timeout = 5000', 'SELECT pg_advisory_xact_lock($1, $2)']);
    assert.equal(busy.calls.at(-1), 'ROLLBACK');
    assert.equal(busy.calls.some(sql => sql.startsWith('CREATE TABLE a')), false);
    // Without the option the wait is unbounded and no timeout is set, as before.
    const free = client(() => ({ rows: [] }));
    assert.deepEqual(await ledger.migrate(free), ['0001']);
    assert.equal(free.calls.some(sql => sql.includes('lock_timeout')), false);
    // A lock error without the option is not relabelled.
    const odd = client(sql => sql.startsWith('SELECT pg_advisory_xact_lock') ? pgError('55P03') : { rows: [] });
    await assert.rejects(ledger.migrate(odd), (error: unknown) => (error as { code?: string }).code === '55P03');
    for (const lockTimeoutMs of [0, -1, 1.5, Number.NaN]) await assert.rejects(ledger.migrate(free, { lockTimeoutMs }), TypeError);
  } finally { cleanup(); }
});
