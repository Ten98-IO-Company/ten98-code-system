import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { getTableConfig } from 'drizzle-orm/pg-core';
import pg from 'pg';
import { createPool, pgTypes, sharedDatabase, teamSchema } from '../db.mjs';

test('pgTypes reads int8 as bigint and DATE as its text, leaving other and binary parsing to pg', () => {
  const { INT8, DATE, INT4, TIMESTAMPTZ } = pg.types.builtins;
  assert.equal(pgTypes.getTypeParser(INT8, 'text')('9007199254740993'), 9007199254740993n);
  assert.equal(pgTypes.getTypeParser(INT8)('-12'), -12n);
  assert.equal(pgTypes.getTypeParser(DATE, 'text')('2026-01-02'), '2026-01-02');
  assert.equal(pgTypes.getTypeParser(INT4, 'text')('42'), 42);
  assert.ok(pgTypes.getTypeParser(TIMESTAMPTZ, 'text')('2026-01-02 03:04:05+00') instanceof Date);
  assert.equal(pgTypes.getTypeParser(INT8, 'binary'), pg.types.getTypeParser(INT8, 'binary'));
  assert.equal(pgTypes.getTypeParser(DATE, 'binary'), pg.types.getTypeParser(DATE, 'binary'));
});

test('createPool applies the bounded defaults and pgTypes, lets options override them, and logs errors without details', async t => {
  const pool = createPool('postgres://secret-user:secret-pass@127.0.0.1:1/never');
  const custom = createPool('postgres://127.0.0.1:1/never', { max: 2, statement_timeout: 500 });
  try {
    const options = pool.options as pg.PoolConfig & { max: number };
    assert.deepEqual([options.max, options.connectionTimeoutMillis, options.idleTimeoutMillis, options.statement_timeout, options.types],
      [10, 5000, 10000, 10000, pgTypes]);
    assert.deepEqual([(custom.options as { max: number }).max, custom.options.statement_timeout, custom.options.connectionTimeoutMillis], [2, 500, 5000]);
    const logged = t.mock.method(console, 'error', () => undefined);
    pool.emit('error', new Error('connect ECONNREFUSED secret-user:secret-pass'));
    assert.deepEqual(logged.mock.calls.map(call => call.arguments), [['Database connection failed; check database availability.']]);
  } finally { await pool.end(); await custom.end(); }
});

test('sharedDatabase keeps one pool per key across copies, opens lazily and closes once', async () => {
  const key = `ten98-runtime.test.${randomUUID()}`;
  let reads = 0, opened = 0;
  const options = { key, connectionString: () => { reads += 1; return 'postgres://127.0.0.1:1/never'; }, schema: teamSchema, onOpen: () => { opened += 1; } };
  // Two slots with one key stand for two bundled copies of the app's module.
  const first = sharedDatabase(options), second = sharedDatabase(options);
  assert.equal(reads, 0, 'nothing is read or opened before first use');
  const database = first.get();
  assert.equal(second.get(), database);
  assert.equal(first.get().db, database.db);
  assert.deepEqual([reads, opened], [1, 1]);
  const other = sharedDatabase({ key: `${key}.other`, connectionString: 'postgres://127.0.0.1:1/never', schema: teamSchema });
  assert.notEqual(other.get().pool, database.pool, 'another key has its own pool');
  await other.close();

  let ends = 0;
  const end = database.pool.end.bind(database.pool);
  database.pool.end = (() => { ends += 1; return end(); }) as typeof database.pool.end;
  await Promise.all([first.close(), second.close(), first.close()]);
  assert.equal(ends, 1, 'concurrent closes end the pool once');
  await second.close();
  assert.equal(ends, 1, 'a later close is a no-op');

  const reopened = second.get();
  assert.notEqual(reopened, database, 'use after close opens a new pool');
  assert.deepEqual([reads, opened], [2, 2]);
  await first.close();
  assert.throws(() => sharedDatabase({ ...options, key: '' }), TypeError);
});

test('the team schema names the tables and columns of workspace-team.sql', () => {
  const columns = Object.fromEntries(Object.values(teamSchema).map(table => {
    const config = getTableConfig(table);
    return [config.name, config.columns.map(column => column.name).sort()];
  }));
  assert.deepEqual(columns, {
    user: ['closed_at', 'createdAt', 'email', 'emailVerified', 'id', 'image', 'name', 'twoFactorEnabled', 'updatedAt'],
    session: ['createdAt', 'expiresAt', 'id', 'ipAddress', 'oidcProvider', 'token', 'updatedAt', 'userAgent', 'userId'],
    account: ['accountId', 'createdAt', 'id', 'password', 'providerId', 'updatedAt', 'userId'],
    workspace: ['created_at', 'id', 'name'],
    membership: ['role', 'user_id', 'workspace_id'],
    workspace_invitation: ['created_at', 'email', 'expires_at', 'id', 'inviter_id', 'role', 'token_hash', 'workspace_id'],
    workspace_two_factor_requirement: ['workspace_id'],
    instance_operator: ['granted_at', 'source', 'user_id'],
    instance_operator_audit: ['action', 'created_at', 'id', 'scope', 'user_id'],
  });
  assert.deepEqual(getTableConfig(teamSchema.membership).primaryKeys.map(key => key.getName()), ['membership_pkey']);
  assert.deepEqual(getTableConfig(teamSchema.user).checks.map(item => item.name), ['user_email_lowercase']);
});
