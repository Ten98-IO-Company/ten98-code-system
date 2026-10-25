import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { createMigrationLedger, migrateOnStart } from '../index.mjs';
import type { MigrationPoolClient } from '../index.mjs';

// A scripted pool, not PostgreSQL: each connection enforces a 10 ms statement_timeout unless it is set to 0, the way
// the apps' pools default to 10 s. A statement containing "slow" takes 30 ms.
type Script = { locks?: boolean[]; connectFailures?: number; slowMs?: number; fail?: { code: string; message: string }; applied?: { version: string; checksum: string }[] };
function pool(script: Script = {}) {
  const calls: string[] = [];
  const releases: (Error | boolean | undefined)[] = [];
  let connectFailures = script.connectFailures ?? 0;
  const locks = [...(script.locks ?? [true])];
  const connect = async (): Promise<MigrationPoolClient> => {
    if (connectFailures-- > 0) throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
    let statementTimeout = 10, discarded = false;
    const ended = () => { if (discarded) throw new Error('Connection terminated.'); };
    return {
      async query<R extends Record<string, unknown> = Record<string, unknown>>(sql: string): Promise<{ rows: R[] }> {
        ended();
        calls.push(sql);
        if (sql === 'SET statement_timeout = 0') statementTimeout = 0;
        if (sql === 'RESET statement_timeout') statementTimeout = 10;
        if (sql.startsWith('SELECT pg_try_advisory_lock')) return { rows: [{ locked: locks.length > 1 ? locks.shift()! : locks[0]! }] as unknown as R[] };
        if (sql.startsWith('SELECT version')) return { rows: (script.applied ?? []) as unknown as R[] };
        if (sql.includes('slow')) {
          const took = script.slowMs ?? 30;
          if (statementTimeout && took > statementTimeout) { await delay(statementTimeout); throw Object.assign(new Error('canceling statement due to statement timeout'), { code: '57014' }); }
          await delay(took);
          ended();
        }
        if (script.fail && sql.includes('fail')) throw Object.assign(new Error(script.fail.message), { code: script.fail.code });
        return { rows: [] };
      },
      // A discarded connection ends its session, as pg does: its statements and open transaction fail.
      release(error?: Error | boolean) { releases.push(error); if (error) discarded = true; },
    };
  };
  return { calls, releases, pool: { connect } };
}
function ledgerWith(sql: string) {
  const directory = mkdtempSync(join(tmpdir(), 'ten98-deadline-'));
  writeFileSync(join(directory, '0001_a.sql'), sql);
  return { ledger: createMigrationLedger({ directory, files: ['0001_a.sql'], lockKey: [7, 8] }), cleanup: () => rmSync(directory, { recursive: true, force: true }) };
}

test('migrateWithDeadline lifts statement_timeout, so a statement longer than the pool default succeeds', async () => {
  const { ledger, cleanup } = ledgerWith('CREATE TABLE slow_a();\n');
  try {
    const fake = pool();
    assert.deepEqual(await ledger.migrateWithDeadline(fake.pool), ['0001']);
    const at = (sql: string) => fake.calls.indexOf(sql);
    assert.ok(at('SET statement_timeout = 0') < at('BEGIN'));
    assert.ok(at('COMMIT') < at('SELECT pg_advisory_unlock($1, $2)'));
    assert.ok(at('SELECT pg_advisory_unlock($1, $2)') < at('RESET statement_timeout'));
    assert.deepEqual(fake.releases, [undefined]);
    // The same migration through plain migrate on a pool connection hits the pool's timeout.
    const plain = pool();
    await assert.rejects(ledger.migrate(await plain.pool.connect()), (error: unknown) => (error as { code?: string }).code === '57014');
  } finally { cleanup(); }
});

test('migrateWithDeadline waits for another instance and an unavailable database, then gives up at the deadline', async () => {
  const { ledger, cleanup } = ledgerWith('CREATE TABLE a();\n');
  try {
    const logs: string[] = [];
    const busy = pool({ locks: [false, false, true], connectFailures: 1 });
    assert.deepEqual(await ledger.migrateWithDeadline(busy.pool, { retryIntervalMs: 5, progressIntervalMs: 1, log: message => logs.push(message) }), ['0001']);
    assert.ok(logs.some(line => line.includes('accept connections')) && logs.some(line => line.includes('another process')));
    // Candidates that did not get the lock go back to the pool intact; the one that held it is released last.
    assert.deepEqual(busy.releases, [undefined, undefined, undefined]);
    const held = pool({ locks: [false] });
    const started = Date.now();
    await assert.rejects(ledger.migrateWithDeadline(held.pool, { timeoutMs: 60, retryIntervalMs: 10 }), (error: unknown) =>
      (error as { code?: string }).code === 'MIGRATION_TIMEOUT' && /Nothing was applied/.test((error as Error).message));
    assert.ok(Date.now() - started < 1000);
    assert.equal(held.calls.includes('BEGIN'), false);
  } finally { cleanup(); }
});

test('migrateWithDeadline abandons a migration that passes the deadline and never commits it', async () => {
  const { ledger, cleanup } = ledgerWith('CREATE TABLE slow_a();\n');
  try {
    const fake = pool({ slowMs: 300 });
    await assert.rejects(ledger.migrateWithDeadline(fake.pool, { timeoutMs: 40 }), (error: unknown) => (error as { code?: string }).code === 'MIGRATION_TIMEOUT');
    assert.equal(fake.calls.includes('COMMIT'), false);
    assert.equal(fake.releases.length, 1);
    assert.ok(fake.releases[0] instanceof Error);
  } finally { cleanup(); }
});

test('migrateWithDeadline reports failures without SQL and rethrows SCHEMA_MISMATCH', async () => {
  const { ledger, cleanup } = ledgerWith('CREATE TABLE fail_secret_table();\n');
  try {
    const fake = pool({ fail: { code: '42P07', message: 'relation "fail_secret_table" already exists' } });
    await assert.rejects(ledger.migrateWithDeadline(fake.pool), (error: unknown) => {
      const e = error as { code?: string; sqlState?: string; message: string };
      return e.code === 'MIGRATION_FAILED' && e.sqlState === '42P07' && e.message.includes('42P07') && !e.message.includes('secret');
    });
    assert.ok(fake.calls.includes('ROLLBACK'));
    assert.deepEqual(fake.releases, [undefined]);
    const drifted = pool({ applied: [{ version: '0001', checksum: 'other' }] });
    await assert.rejects(ledger.migrateWithDeadline(drifted.pool), (error: unknown) => (error as { code?: string }).code === 'SCHEMA_MISMATCH');
    for (const options of [{ timeoutMs: 0 }, { retryIntervalMs: 1.5 }]) await assert.rejects(ledger.migrateWithDeadline(fake.pool, options), TypeError);
  } finally { cleanup(); }
});

test('waitForCurrent polls until the schema is current, and migrateOnStart reads the switch', async () => {
  const { ledger, cleanup } = ledgerWith('CREATE TABLE a();\n');
  try {
    const checksum = (await ledger.sources())[0]!.checksum;
    let polls = 0;
    const becoming = { async query<R extends Record<string, unknown> = Record<string, unknown>>(): Promise<{ rows: R[] }> {
      return { rows: (++polls < 3 ? [] : [{ version: '0001', checksum }]) as unknown as R[] };
    } };
    await ledger.waitForCurrent(becoming, { intervalMs: 5 });
    assert.equal(polls, 3);
    const never = { async query<R extends Record<string, unknown> = Record<string, unknown>>(): Promise<{ rows: R[] }> { return { rows: [] }; } };
    await assert.rejects(ledger.waitForCurrent(never, { timeoutMs: 30, intervalMs: 5 }), (error: unknown) => (error as { code?: string }).code === 'MIGRATION_TIMEOUT');
  } finally { cleanup(); }
  for (const value of [undefined, '', 'true', 'TRUE', ' 1 ']) assert.equal(migrateOnStart(value), true, String(value));
  for (const value of ['false', '0', 'False']) assert.equal(migrateOnStart(value), false, value);
  for (const value of ['yes', 'off']) assert.throws(() => migrateOnStart(value), TypeError);
});
