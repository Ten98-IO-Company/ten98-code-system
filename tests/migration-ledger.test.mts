import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import { createMigrationLedger, type Migration, type MigrationClient } from '../index.mjs';

const sha = (text: string) => createHash('sha256').update(text).digest('hex');
const SELECT_APPLIED = 'SELECT version, checksum FROM schema_version ORDER BY version';

function fixture(contents: Record<string, string> = { '0001_a.sql': 'CREATE TABLE a();\n', '0002_b.sql': 'CREATE TABLE b();\n', '0003_c.sql': 'CREATE TABLE c();\n' }) {
  const directory = mkdtempSync(join(tmpdir(), 'ten98-ledger-'));
  for (const [name, text] of Object.entries(contents)) writeFileSync(join(directory, name), text);
  const ledger = createMigrationLedger({ directory, files: Object.keys(contents), lockKey: [109857, 1] });
  return { directory, ledger, cleanup: () => rmSync(directory, { recursive: true, force: true }) };
}

function fakeClient({ applied = [], failOn }: { applied?: readonly { version: string; checksum: string }[]; failOn?: (sql: string) => boolean } = {}) {
  const calls: ([string] | [string, unknown[]])[] = [];
  return {
    calls,
    async query<R>(sql: string, params?: unknown[]) {
      calls.push(params === undefined ? [sql] : [sql, params]);
      if (failOn?.(sql)) throw new Error('statement failed');
      return { rows: (sql === SELECT_APPLIED ? applied : []) as R[] };
    },
  };
}

test('sources are ordered as listed, versioned by prefix and checksummed over LF-normalised SQL', async () => {
  const { ledger, cleanup } = fixture({ '0001_a.sql': 'one\r\ntwo\r\n', '0002_b.sql': 'three\n' });
  try {
    const sources = await ledger.sources();
    assert.deepEqual(sources.map(({ version, filename }) => [version, filename]), [['0001', '0001_a.sql'], ['0002', '0002_b.sql']]);
    assert.equal(sources[0].sql, 'one\ntwo\n');
    assert.equal(sources[0].checksum, sha('one\ntwo\n'));
    assert.equal(Object.isFrozen(sources), true);
    assert.equal(await ledger.sources(), sources);
  } finally { cleanup(); }
});

test('CRLF, CR and LF variants of a migration share one checksum', async () => {
  const lf = fixture({ '0001_a.sql': 'a\nb\n' });
  const crlf = fixture({ '0001_a.sql': 'a\r\nb\r\n' });
  const cr = fixture({ '0001_a.sql': 'a\rb\r' });
  try {
    const [first, second, third] = await Promise.all([lf, crlf, cr].map(item => item.ledger.sources()));
    assert.equal(first[0].checksum, second[0].checksum);
    assert.equal(first[0].checksum, third[0].checksum);
  } finally { lf.cleanup(); crlf.cleanup(); cr.cleanup(); }
});

test('a URL directory is accepted and a missing file is not cached', async () => {
  const { directory, cleanup } = fixture({ '0001_a.sql': 'x' });
  try {
    const ledger = createMigrationLedger({ directory: pathToFileURL(directory + '/'), files: ['0001_a.sql', '0002_late.sql'], lockKey: [1, 2] });
    await assert.rejects(ledger.sources(), { code: 'ENOENT' });
    writeFileSync(join(directory, '0002_late.sql'), 'y');
    assert.equal((await ledger.sources()).length, 2);
  } finally { cleanup(); }
});

test('pending returns the unapplied suffix and rejects any applied row that is not an exact prefix', async () => {
  const { ledger, cleanup } = fixture();
  try {
    const [a, b, c] = await ledger.sources();
    const row = (migration: Migration) => ({ version: migration.version, checksum: migration.checksum });
    assert.deepEqual((await ledger.pending([])).map(item => item.version), ['0001', '0002', '0003']);
    assert.deepEqual((await ledger.pending([row(a), row(b)])).map(item => item.version), ['0003']);
    assert.deepEqual(await ledger.pending([row(a), row(b), row(c)]), []);
    const mismatch = { code: 'SCHEMA_MISMATCH', message: 'Database schema is incompatible with this application. Use the matching image and migrations.' };
    await assert.rejects(ledger.pending([{ ...row(a), checksum: 'changed' }]), mismatch);
    await assert.rejects(ledger.pending([row(b)]), mismatch);
    await assert.rejects(ledger.pending([row(a), { version: '0099', checksum: 'x' }]), mismatch);
    await assert.rejects(ledger.pending([row(a), row(b), row(c), { version: '0004', checksum: 'x' }]), mismatch);
  } finally { cleanup(); }
});

test('migrate runs lock, ledger table, read, apply, record, hook and commit in order', async () => {
  const { ledger, cleanup } = fixture();
  try {
    const [a, b, c] = await ledger.sources();
    const client = fakeClient({ applied: [{ version: a.version, checksum: a.checksum }] });
    let hook: { received: MigrationClient; versions: readonly string[] } | undefined;
    const applied = await ledger.migrate(client, { async afterApply(received, versions) {
      hook = { received, versions };
      await received.query('SELECT hook');
    } });
    assert.deepEqual(applied, ['0002', '0003']);
    assert.equal(hook!.received, client);
    assert.deepEqual(hook!.versions, ['0002', '0003']);
    assert.deepEqual(client.calls, [
      ['BEGIN'],
      ['SELECT pg_advisory_xact_lock($1, $2)', [109857, 1]],
      ['CREATE TABLE IF NOT EXISTS schema_version (version text PRIMARY KEY, checksum text NOT NULL)'],
      [SELECT_APPLIED],
      [b.sql],
      ['INSERT INTO schema_version(version, checksum) VALUES ($1, $2)', ['0002', b.checksum]],
      [c.sql],
      ['INSERT INTO schema_version(version, checksum) VALUES ($1, $2)', ['0003', c.checksum]],
      ['SELECT hook'],
      ['COMMIT'],
    ]);
  } finally { cleanup(); }
});

test('a failing migration statement rolls back and reports nothing applied', async () => {
  const { ledger, cleanup } = fixture();
  try {
    const [, b] = await ledger.sources();
    const client = fakeClient({ failOn: sql => sql === b.sql });
    let hooked = false;
    await assert.rejects(ledger.migrate(client, { afterApply: async () => { hooked = true; } }), /statement failed/);
    assert.equal(hooked, false);
    assert.equal(client.calls.at(-1)![0], 'ROLLBACK');
    assert.equal(client.calls.some(([sql]) => sql === 'COMMIT'), false);
  } finally { cleanup(); }
});

test('a failing afterApply hook rolls back every migration and the original error is thrown', async () => {
  const { ledger, cleanup } = fixture();
  try {
    const client = fakeClient();
    await assert.rejects(ledger.migrate(client, { afterApply: async () => { throw new Error('hook failed'); } }), /hook failed/);
    assert.equal(client.calls.at(-1)![0], 'ROLLBACK');
    assert.equal(client.calls.some(([sql]) => sql === 'COMMIT'), false);
  } finally { cleanup(); }
});

test('a schema mismatch inside migrate rolls back and a failing rollback does not mask the error', async () => {
  const { ledger, cleanup } = fixture();
  try {
    const client = fakeClient({ applied: [{ version: '0001', checksum: 'changed' }], failOn: sql => sql === 'ROLLBACK' });
    await assert.rejects(ledger.migrate(client), { code: 'SCHEMA_MISMATCH' });
    assert.equal(client.calls.at(-1)![0], 'ROLLBACK');
    assert.equal(client.calls.some(([sql]) => sql === 'COMMIT'), false);
  } finally { cleanup(); }
});

test('migrate with nothing pending still verifies checksums, commits, skips the hook and returns an empty list', async () => {
  const { ledger, cleanup } = fixture();
  try {
    const applied = (await ledger.sources()).map(({ version, checksum }) => ({ version, checksum }));
    const client = fakeClient({ applied });
    let hooked = false;
    assert.deepEqual(await ledger.migrate(client, { afterApply: async () => { hooked = true; } }), []);
    assert.equal(hooked, false);
    assert.deepEqual(client.calls.map(([sql]) => sql), ['BEGIN', 'SELECT pg_advisory_xact_lock($1, $2)',
      'CREATE TABLE IF NOT EXISTS schema_version (version text PRIMARY KEY, checksum text NOT NULL)', SELECT_APPLIED, 'COMMIT']);
  } finally { cleanup(); }
});

test('migration files that cannot be read fail before any SQL is sent', async () => {
  const ledger = createMigrationLedger({ directory: join(tmpdir(), 'ten98-ledger-missing'), files: ['0001_a.sql'], lockKey: [1, 2] });
  const client = fakeClient();
  await assert.rejects(ledger.migrate(client), { code: 'ENOENT' });
  assert.deepEqual(client.calls, []);
});

test('assertCurrent reads the ledger and throws SCHEMA_MISMATCH while migrations are pending or applied rows differ', async () => {
  const { ledger, cleanup } = fixture();
  try {
    const rows = (await ledger.sources()).map(({ version, checksum }) => ({ version, checksum }));
    const current = fakeClient({ applied: rows });
    await ledger.assertCurrent(current);
    assert.deepEqual(current.calls, [[SELECT_APPLIED]]);
    await assert.rejects(ledger.assertCurrent(fakeClient({ applied: rows.slice(0, 2) })), { code: 'SCHEMA_MISMATCH' });
    await assert.rejects(ledger.assertCurrent(fakeClient({ applied: [{ ...rows[0], checksum: 'changed' }, ...rows.slice(1)] })), { code: 'SCHEMA_MISMATCH' });
  } finally { cleanup(); }
});
