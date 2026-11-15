import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { eq, sql, type SQL } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { getTableConfig, PgDialect, pgTable, serial, text, timestamp } from 'drizzle-orm/pg-core';
import pg from 'pg';
import { createPool, teamSchema } from '../db.mjs';
import * as tenancyEntry from '../tenancy.mjs';
import { createTenancy, DatabaseRoleError, InvalidWorkspaceIdError, ScopeNestingError, UnlockedScopeError, WorkspaceAccessError } from '../tenancy.mjs';
import * as systemEntry from '../tenancy-system.mjs';
import { createSystemScope } from '../tenancy-system.mjs';
import { requireScopeForTesting, setScopeForTesting } from '../tenancy-testing.mjs';

const suffix = randomBytes(6).toString('hex');
const roles = { app: `rs_app_${suffix}`, owner: `rs_owner_${suffix}`, resolver: `rs_resolver_${suffix}` };
const resolvers = {
  workspace_for_token: { parameter: { name: 'token_hash', type: 'text' }, table: 'contact', match: 'token_hash' },
  api_key_principal: { parameter: { name: 'key_hash', type: 'text' }, table: 'api_key', match: 'key_hash', principal: { kind: 'api_key', id: 'id' }, touch: ['last_used_at'] },
  share_principal: { parameter: { name: 'share_id', type: 'uuid' }, table: 'contact', match: 'share_id', principal: { kind: 'share', id: 'token_hash' } },
} as const;
const tenancy = createTenancy({ setting: 'app.workspace_ids', column: 'workspace_id', tables: ['note', 'api_key', 'contact'], resolverOwner: roles.resolver, resolvers });
const note = pgTable('note', { id: serial('id').primaryKey(), workspaceId: text('workspace_id').notNull(), body: text('body').notNull() }, () => [tenancy.policy('note_scope')]).enableRLS();
const apiKey = pgTable('api_key', { id: text('id').primaryKey(), workspaceId: text('workspace_id').notNull(), keyHash: text('key_hash').notNull(),
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }) }, () => [tenancy.policy('api_key_scope')]).enableRLS();
const render = (value: SQL | undefined) => new PgDialect().sqlToQuery(value!).sql;
const scopeSql = render(getTableConfig(note).policies[0]!.using);
const fakeWorkspace = '00000000-0000-4000-8000-000000000001';
const sqlState = (error: unknown) => (error as { code?: string }).code ?? (error as { cause?: { code?: string } }).cause?.code;
const refused = (error: unknown) => error instanceof WorkspaceAccessError && error.status === 404;
const nested = (error: unknown) => error instanceof ScopeNestingError && error.code === 'TENANCY_SCOPE_NESTED';

// A pool that records statements and answers nothing, for refusals that must come before any statement.
class RecordingPool {
  readonly sent: string[] = [];
  readonly totalCount = 0;
  async connect() {
    return { query: async (config: string | { text: string }) => { this.sent.push(typeof config === 'string' ? config : config.text); return { rows: [], fields: [] }; }, release: () => undefined, on: () => undefined, off: () => undefined };
  }
}

test('createTenancy refuses resolver declarations that are not safe identifiers or a complete shape', () => {
  const base = { setting: 'app.workspace_ids', column: 'workspace_id', tables: ['note'] };
  const valid = { parameter: { name: 'token_hash', type: 'text' }, table: 'contact', match: 'token_hash' } as const;
  for (const change of [
    { resolverOwner: undefined, resolvers: { r: valid } },
    { resolverOwner: 'Owner', resolvers: { r: valid } },
    { resolverOwner: 'o', resolvers: { 'r; DROP': valid } },
    { resolverOwner: 'o', resolvers: { r: { ...valid, parameter: { name: 'token_hash', type: 'integer' } } } },
    { resolverOwner: 'o', resolvers: { r: { ...valid, table: 'public.contact' } } },
    { resolverOwner: 'o', resolvers: { r: { ...valid, match: 'token_hash = token_hash OR true' } } },
    { resolverOwner: 'o', resolvers: { r: { ...valid, principal: { kind: "x' OR '1", id: 'id' } } } },
    { resolverOwner: 'o', resolvers: { r: { ...valid, touch: ['last_used_at'] } } },
    { resolverOwner: 'o', resolvers: [valid] },
  ]) {
    assert.throws(() => createTenancy({ ...base, ...change } as never), TypeError, JSON.stringify(change));
  }
});

test('resolverFunctions writes one narrow SECURITY DEFINER lookup per resolver, owned by the owner role and executable by the application role only', () => {
  assert.equal(tenancy.resolverFunctions('app'), [
    `CREATE OR REPLACE FUNCTION public."workspace_for_token"("token_hash" text) RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $resolver$SELECT "workspace_id"::uuid FROM public."contact" WHERE "token_hash" = $1 LIMIT 1$resolver$;`,
    `ALTER FUNCTION public."workspace_for_token"(text) OWNER TO "${roles.resolver}";`,
    'REVOKE ALL ON FUNCTION public."workspace_for_token"(text) FROM PUBLIC;',
    'GRANT EXECUTE ON FUNCTION public."workspace_for_token"(text) TO "app";',
    `CREATE OR REPLACE FUNCTION public."api_key_principal"("key_hash" text, OUT workspace_id uuid, OUT principal_kind text, OUT principal_id text) LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $resolver$UPDATE public."api_key" SET "last_used_at" = now() WHERE "id" = (SELECT "id" FROM public."api_key" WHERE "key_hash" = $1 LIMIT 1) RETURNING "workspace_id"::uuid, 'api_key'::text, "id"::text$resolver$;`,
    `ALTER FUNCTION public."api_key_principal"(text) OWNER TO "${roles.resolver}";`,
    'REVOKE ALL ON FUNCTION public."api_key_principal"(text) FROM PUBLIC;',
    'GRANT EXECUTE ON FUNCTION public."api_key_principal"(text) TO "app";',
    `CREATE OR REPLACE FUNCTION public."share_principal"("share_id" uuid, OUT workspace_id uuid, OUT principal_kind text, OUT principal_id text) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $resolver$SELECT "workspace_id"::uuid, 'share'::text, "token_hash"::text FROM public."contact" WHERE "share_id" = $1 LIMIT 1$resolver$;`,
    `ALTER FUNCTION public."share_principal"(uuid) OWNER TO "${roles.resolver}";`,
    'REVOKE ALL ON FUNCTION public."share_principal"(uuid) FROM PUBLIC;',
    'GRANT EXECUTE ON FUNCTION public."share_principal"(uuid) TO "app";',
  ].join('\n--> statement-breakpoint\n'));
  for (const role of [roles.resolver, 'App', '"app"', '']) assert.throws(() => tenancy.resolverFunctions(role), TypeError, role);
});

test('the system scope is a separate entry, absent from ./tenancy, the tenancy object and the package root', async () => {
  assert.deepEqual(Object.keys(systemEntry).sort(), ['InvalidWorkspaceIdError', 'ScopeNestingError', 'UnlockedScopeError', 'WorkspaceAccessError', 'createSystemScope']);
  const runtime = await import('../index.mjs');
  for (const name of ['createSystemScope', 'withSystemWorkspace', 'withVerifiedWorkspace']) {
    assert.equal(name in tenancyEntry || name in runtime || name in tenancy, false, name);
  }
});

test('createSystemScope takes only a tenancy from createTenancy and a cache lifetime of 1 to 60 seconds', () => {
  assert.throws(() => createSystemScope({ ...tenancy }), /needs a tenancy from createTenancy/);
  assert.throws(() => createSystemScope({ setting: 'app.workspace_ids' } as never), /needs a tenancy from createTenancy/);
  for (const seconds of [0, 61, 3600, 1.5, -1, Number.POSITIVE_INFINITY, '30']) {
    assert.throws(() => createSystemScope(tenancy, { cache: { seconds: seconds as number } }), /whole number of seconds from 1 to 60/, String(seconds));
  }
  assert.doesNotThrow(() => createSystemScope(tenancy, { cache: { seconds: 60 } }));
});

test('a reason is required, and a workspace id that is not a UUID throws, before any statement', async () => {
  const pool = new RecordingPool(), db = drizzle(pool as never), system = createSystemScope(tenancy);
  let ran = false;
  for (const reason of [undefined, '', ' ', ' job', 'job ', 'line\nbreak', 'x'.repeat(201), 7]) {
    await assert.rejects(system.withSystemWorkspace(db, { workspaceId: fakeWorkspace, reason: reason as string }, async () => { ran = true; }), /needs a reason/, String(reason));
    await assert.rejects(system.withVerifiedWorkspace(db, { resolver: 'api_key_principal', credential: 'k', reason: reason as string }, async () => { ran = true; }), /needs a reason/, String(reason));
  }
  for (const workspaceId of ['not-a-uuid', `${fakeWorkspace},${fakeWorkspace}`, '', undefined]) {
    await assert.rejects(system.withSystemWorkspace(db, { workspaceId: workspaceId as string, reason: 'job' }, async () => { ran = true; }),
      (error: unknown) => error instanceof InvalidWorkspaceIdError && error.code === 'TENANCY_WORKSPACE_ID_INVALID', String(workspaceId));
  }
  // An undeclared resolver, a workspace resolver used as a verified one and the reverse, and an unknown mode.
  await assert.rejects(system.withVerifiedWorkspace(db, { resolver: 'nope' as never, credential: 'k', reason: 'api' }, async () => { ran = true; }), /not a declared verified resolver/);
  await assert.rejects(system.withVerifiedWorkspace(db, { resolver: 'workspace_for_token', credential: 'k', reason: 'api' }, async () => { ran = true; }), /not a declared verified resolver/);
  await assert.rejects(system.resolveWorkspace(db, 'api_key_principal', 'k'), /not a declared workspace resolver/);
  await assert.rejects(system.withVerifiedWorkspace(db, { resolver: 'api_key_principal', credential: 'k', reason: 'api', mode: 'admin' as never }, async () => { ran = true; }), /read or write/);
  assert.deepEqual([pool.sent, ran], [[], false]);
});

// Integration tests on real PostgreSQL, opt-in like the other tenancy tests: TEN98_TEST_DATABASE_URL names a disposable
// server as a superuser; the run creates and drops its own database and roles.
const admin = process.env.TEN98_TEST_DATABASE_URL;
const skip = admin ? false : 'set TEN98_TEST_DATABASE_URL to a disposable PostgreSQL to run the system scope integration tests';
const database = `ten98_system_${suffix}`;
const password = randomBytes(12).toString('hex');
const schema = { ...teamSchema, note, apiKey };
let root: pg.Pool | undefined;
const pools: pg.Pool[] = [];
const fixture = { a: '', b: '', c: '', user: '', keyA: '', share: '' };
const urlFor = (role?: string) => {
  const url = new URL(admin!);
  url.pathname = `/${database}`;
  if (role) { url.username = role; url.password = password; }
  return url.href;
};
const appPool = () => { const pool = createPool(urlFor(roles.app), { max: 2 }); pools.push(pool); return pool; };
let app: ReturnType<typeof drizzle<typeof schema>>;
const bodies = async (tx: Pick<typeof app, 'select'>) => (await tx.select({ id: note.workspaceId, body: note.body }).from(note).orderBy(note.id)).map(row => `${row.id === fixture.a ? 'A' : row.id === fixture.b ? 'B' : '?'}:${row.body}`);

test.before(async () => {
  if (!admin) return;
  const server = new pg.Client({ connectionString: admin });
  await server.connect();
  try {
    await server.query(`CREATE DATABASE ${database}`);
    await server.query(`CREATE ROLE ${roles.app} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '${password}'`);
    await server.query(`CREATE ROLE ${roles.owner} NOLOGIN NOSUPERUSER NOBYPASSRLS`);
    await server.query(`CREATE ROLE ${roles.resolver} NOLOGIN NOSUPERUSER BYPASSRLS`);
  } finally { await server.end(); }
  root = new pg.Pool({ connectionString: urlFor(), max: 3 });
  await root.query(readFileSync(new URL('../workspace-team.sql', import.meta.url), 'utf8'));
  const scoped = (table: string, columns: string) => `CREATE TABLE ${table} (${columns});
    ALTER TABLE ${table} OWNER TO ${roles.owner};
    CREATE POLICY ${table}_scope ON ${table} AS PERMISSIVE FOR ALL TO public USING (${scopeSql}) WITH CHECK (${scopeSql});
    ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;`;
  await root.query(`${scoped('note', 'id serial PRIMARY KEY, workspace_id text NOT NULL REFERENCES workspace(id), body text NOT NULL')}
    ${scoped('api_key', 'id text PRIMARY KEY, workspace_id text NOT NULL, key_hash text NOT NULL UNIQUE, last_used_at timestamptz')}
    ${scoped('contact', 'token_hash text PRIMARY KEY, share_id uuid UNIQUE, workspace_id text NOT NULL')}
    ${tenancy.forceRowLevelSecurity().split('--> statement-breakpoint').join('')}
    GRANT SELECT, INSERT, UPDATE, DELETE ON note, api_key, contact, "user", account, workspace, membership TO ${roles.app};
    GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ${roles.app};
    GRANT SELECT ON contact TO ${roles.resolver};
    GRANT SELECT, UPDATE ON api_key TO ${roles.resolver};
    ${tenancy.resolverFunctions(roles.app).split('--> statement-breakpoint').join('')}`);
  for (const key of ['a', 'b', 'c'] as const) {
    fixture[key] = randomUUID();
    await root.query('INSERT INTO workspace(id, name) VALUES ($1, $2)', [fixture[key], key.toUpperCase()]);
  }
  fixture.user = randomUUID();
  await root.query('INSERT INTO "user"(id, name, email) VALUES ($1, $2, $3)', [fixture.user, 'u', `u-${fixture.user}@example.com`]);
  await root.query("INSERT INTO membership(workspace_id, user_id, role) VALUES ($1, $3, 'owner'), ($2, $3, 'owner')", [fixture.a, fixture.b, fixture.user]);
  await root.query("INSERT INTO note(workspace_id, body) VALUES ($1, 'one'), ($2, 'two')", [fixture.a, fixture.b]);
  fixture.keyA = randomUUID(); fixture.share = randomUUID();
  await root.query("INSERT INTO api_key(id, workspace_id, key_hash) VALUES ($1, $2, 'key-a')", [fixture.keyA, fixture.a]);
  await root.query("INSERT INTO contact(token_hash, share_id, workspace_id) VALUES ('token-b', $1, $2)", [fixture.share, fixture.b]);
  app = drizzle(appPool(), { schema });
});

test.after(async () => {
  if (!admin) return;
  await Promise.all(pools.map(pool => pool.end()));
  await root?.end();
  const server = new pg.Client({ connectionString: admin });
  await server.connect();
  try {
    await server.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    for (const role of Object.values(roles)) await server.query(`DROP ROLE IF EXISTS ${role}`);
  } finally { await server.end(); }
});

test('the application role with declared resolvers passes the boot assertion', { skip }, async () => {
  await tenancy.assertDatabaseRoles(pools[0]!);
});

test('a system scope for workspace A reads and writes A only, and records its reason for the transaction', { skip }, async () => {
  const system = createSystemScope(tenancy);
  await system.withSystemWorkspace(app, { workspaceId: fixture.a.toUpperCase(), reason: 'nightly-digest' }, async (tx, access) => {
    assert.deepEqual(access, { workspaceId: fixture.a, reason: 'nightly-digest' });
    assert.deepEqual(await bodies(tx), ['A:one']);
    assert.equal((await tx.update(note).set({ body: 'x' }).where(eq(note.workspaceId, fixture.b)).returning()).length, 0);
    await tx.insert(note).values({ workspaceId: fixture.a, body: 'job' });
    const { rows } = await tx.execute<{ reason: string; principal: string; scope: string }>(sql`SELECT current_setting(${tenancy.reasonSetting}) AS reason,
      current_setting(${tenancy.principalSetting}) AS principal, current_setting(${tenancy.setting}) AS scope`);
    assert.deepEqual(rows[0], { reason: 'nightly-digest', principal: '', scope: fixture.a });
  });
  await assert.rejects(system.withSystemWorkspace(app, { workspaceId: fixture.a, reason: 'job' }, tx => tx.insert(note).values({ workspaceId: fixture.b, body: 'intruder' })),
    (error: unknown) => sqlState(error) === '42501');
  await assert.rejects(system.withSystemWorkspace(app, { workspaceId: fixture.a, reason: 'job' }, tx => tx.update(note).set({ workspaceId: fixture.b })),
    (error: unknown) => sqlState(error) === '42501');
  assert.deepEqual((await root!.query('SELECT workspace_id, body FROM note ORDER BY id')).rows,
    [{ workspace_id: fixture.a, body: 'one' }, { workspace_id: fixture.b, body: 'two' }, { workspace_id: fixture.a, body: 'job' }]);
  await root!.query("DELETE FROM note WHERE body = 'job'");
});

test('a missing or deleted workspace is refused before the callback runs', { skip }, async () => {
  const system = createSystemScope(tenancy), gone = randomUUID();
  await root!.query('INSERT INTO workspace(id, name) VALUES ($1, $2)', [gone, 'Gone']);
  await root!.query('DELETE FROM workspace WHERE id = $1', [gone]);
  let ran = false;
  for (const workspaceId of [gone, randomUUID()]) {
    await assert.rejects(system.withSystemWorkspace(app, { workspaceId, reason: 'job' }, async () => { ran = true; }), refused);
  }
  assert.equal(ran, false);
});

test('a workspace deletion waits for an open system scope on that workspace', { skip }, async () => {
  const system = createSystemScope(tenancy);
  const remove = async () => {
    const client = await root!.connect();
    try {
      await client.query('BEGIN');
      await client.query("SET LOCAL lock_timeout = '300ms'");
      await client.query('DELETE FROM workspace WHERE id = $1', [fixture.c]);
      await client.query('ROLLBACK');
    } catch (error) { await client.query('ROLLBACK').catch(() => undefined); throw error; } finally { client.release(); }
  };
  await remove(); // with no scope open, the deletion takes its lock at once
  await system.withSystemWorkspace(app, { workspaceId: fixture.c, reason: 'job' }, async () => {
    await assert.rejects(remove(), (error: unknown) => sqlState(error) === '55P03');
  });
  await system.withVerifiedWorkspace(app, { resolver: 'share_principal', credential: fixture.share, reason: 'share-link' }, async () => {
    const client = await root!.connect();
    try {
      await client.query('BEGIN');
      await client.query("SET LOCAL lock_timeout = '300ms'");
      await assert.rejects(client.query('DELETE FROM workspace WHERE id = $1', [fixture.b]), (error: unknown) => sqlState(error) === '55P03');
    } finally { await client.query('ROLLBACK').catch(() => undefined); client.release(); }
  });
});

test('user and system scopes never nest in each other, and a nested system scope cannot be widened', { skip }, async () => {
  const system = createSystemScope(tenancy);
  let ran = false;
  const mark = async () => { ran = true; };
  // A system scope inside a user scope: as a savepoint, inside the caller's own Drizzle savepoint, and in an empty user scope.
  await tenancy.withWorkspace(app, fixture.user, fixture.a, 'write', async tx => {
    await assert.rejects(system.withSystemWorkspace(tx, { workspaceId: fixture.a, reason: 'job' }, mark), nested);
    await assert.rejects(tx.transaction(own => system.withSystemWorkspace(own, { workspaceId: fixture.a, reason: 'job' }, mark)), nested);
    await assert.rejects(system.withVerifiedWorkspace(tx, { resolver: 'api_key_principal', credential: 'key-a', reason: 'api' }, mark), nested);
  });
  await tenancy.withWorkspaces(app, randomUUID(), [fixture.a], async tx => {
    await assert.rejects(system.withSystemWorkspace(tx, { workspaceId: fixture.a, reason: 'job' }, mark), nested);
  });
  // A user scope inside a system scope: as a savepoint, joined as outer, across workspaces, and in the caller's own savepoint.
  await system.withSystemWorkspace(app, { workspaceId: fixture.a, reason: 'job' }, async tx => {
    await assert.rejects(tenancy.withWorkspace(tx, fixture.user, fixture.a, 'read', mark), nested);
    await assert.rejects(tenancy.withWorkspace(app, fixture.user, fixture.a, 'write', mark, tx), nested);
    await assert.rejects(tenancy.withWorkspaces(tx, fixture.user, [fixture.a, fixture.b], mark), nested);
    await assert.rejects(tx.transaction(own => tenancy.withWorkspace(own, fixture.user, fixture.a, 'read', mark)), nested);
    // Widening to another workspace is refused; the same workspace nests and gives the caller its reason back.
    await assert.rejects(system.withSystemWorkspace(tx, { workspaceId: fixture.b, reason: 'other' }, mark), nested);
    assert.deepEqual(await system.withSystemWorkspace(tx, { workspaceId: fixture.a, reason: 'inner' }, async inner =>
      (await inner.execute<{ reason: string }>(sql`SELECT current_setting(${tenancy.reasonSetting}) AS reason`)).rows[0]!.reason), 'inner');
    assert.equal((await tx.execute<{ reason: string }>(sql`SELECT current_setting(${tenancy.reasonSetting}) AS reason`)).rows[0]!.reason, 'job');
    assert.deepEqual(await bodies(tx), ['A:one']);
  });
  assert.equal(ran, false);
  // A system scope in a READ ONLY transaction admits only the workspace its own top-level call locked.
  await system.withVerifiedWorkspace(app, { resolver: 'share_principal', credential: fixture.share, reason: 'share-link' }, async tx => {
    assert.deepEqual(await system.withSystemWorkspace(tx, { workspaceId: fixture.b, reason: 'inner' }, bodies), ['B:two']);
  });
  await assert.rejects(app.transaction(outer => system.withSystemWorkspace(outer, { workspaceId: fixture.a, reason: 'job' }, mark), { accessMode: 'read only' }),
    (error: unknown) => error instanceof UnlockedScopeError);
});

test('a resolver returns one workspace id and nothing else, and only through its declared signature', { skip }, async () => {
  const client = await pools[0]!.connect();
  try {
    assert.deepEqual((await client.query("SELECT * FROM workspace_for_token('token-b')")).rows, [{ workspace_for_token: fixture.b }]);
    assert.deepEqual((await client.query("SELECT workspace_for_token('unknown') AS id")).rows, [{ id: null }]);
    // Without a scope the application role still sees no row of the table the resolver read.
    assert.deepEqual((await client.query('SELECT count(*)::int AS n FROM contact')).rows, [{ n: 0 }]);
    for (const call of ['SELECT workspace_for_token(1)', "SELECT workspace_for_token('a', 'b')", "SELECT api_key_principal('key-a', 'x')", 'SELECT share_principal(1)']) {
      await assert.rejects(client.query(call), (error: unknown) => sqlState(error) === '42883', call);
    }
    await assert.rejects(client.query(`SET ROLE ${roles.resolver}`), (error: unknown) => sqlState(error) === '42501');
  } finally { client.release(); }
  const system = createSystemScope(tenancy);
  assert.equal(await system.resolveWorkspace(app, 'workspace_for_token', 'token-b'), fixture.b);
  assert.equal(await system.resolveWorkspace(app, 'workspace_for_token', 'unknown'), undefined);
  // A workspace resolver feeds a system scope.
  const workspaceId = (await system.resolveWorkspace(app, 'workspace_for_token', 'token-b'))!;
  assert.deepEqual(await system.withSystemWorkspace(app, { workspaceId, reason: 'unsubscribe' }, bodies), ['B:two']);
});

test('a verified scope admits the resolved workspace only, records its principal, and is read-only unless asked to write', { skip }, async () => {
  const system = createSystemScope(tenancy);
  await root!.query('UPDATE api_key SET last_used_at = NULL');
  assert.deepEqual(await system.withVerifiedWorkspace(app, { resolver: 'api_key_principal', credential: 'key-a', reason: 'api' }, async (tx, access) => {
    assert.deepEqual(access, { workspaceId: fixture.a, reason: 'api', principal: { kind: 'api_key', id: fixture.keyA } });
    assert.equal((await tx.execute<{ principal: string }>(sql`SELECT current_setting(${tenancy.principalSetting}) AS principal`)).rows[0]!.principal, `api_key:${fixture.keyA}`);
    await assert.rejects(tx.transaction(inner => inner.update(note).set({ body: 'x' })), (error: unknown) => sqlState(error) === '25006');
    return bodies(tx);
  }), ['A:one']);
  // Use was recorded by the resolver, inside the transaction, before it turned READ ONLY.
  assert.equal((await root!.query('SELECT last_used_at IS NOT NULL AS used FROM api_key WHERE id = $1', [fixture.keyA])).rows[0].used, true);
  await assert.rejects(system.withVerifiedWorkspace(app, { resolver: 'api_key_principal', credential: 'key-a', reason: 'api' }, tx => tx.insert(note).values({ workspaceId: fixture.a, body: 'x' })),
    (error: unknown) => sqlState(error) === '25006');
  // Write mode writes its own workspace and still not another.
  await system.withVerifiedWorkspace(app, { resolver: 'api_key_principal', credential: 'key-a', reason: 'api', mode: 'write' }, async tx => {
    await tx.insert(note).values({ workspaceId: fixture.a, body: 'api' });
    await assert.rejects(tx.transaction(inner => inner.insert(note).values({ workspaceId: fixture.b, body: 'intruder' })), (error: unknown) => sqlState(error) === '42501');
  });
  assert.equal((await root!.query("DELETE FROM note WHERE body = 'api' RETURNING workspace_id")).rows[0].workspace_id, fixture.a);
  // A share link (uuid credential) for B reaches B only.
  assert.deepEqual(await system.withVerifiedWorkspace(app, { resolver: 'share_principal', credential: fixture.share.toUpperCase(), reason: 'share-link' }, bodies), ['B:two']);
});

test('an unresolved, unusable or orphaned credential gets one uniform refusal before any scoped statement', { skip }, async () => {
  const system = createSystemScope(tenancy), orphan = randomUUID();
  await root!.query("INSERT INTO api_key(id, workspace_id, key_hash) VALUES ($1, $2, 'key-orphan')", [orphan, randomUUID()]);
  let ran = false;
  const attempts = [
    system.withVerifiedWorkspace(app, { resolver: 'api_key_principal', credential: 'unknown', reason: 'api' }, async () => { ran = true; }),
    system.withVerifiedWorkspace(app, { resolver: 'api_key_principal', credential: '', reason: 'api' }, async () => { ran = true; }),
    system.withVerifiedWorkspace(app, { resolver: 'api_key_principal', credential: 'k'.repeat(1025), reason: 'api' }, async () => { ran = true; }),
    system.withVerifiedWorkspace(app, { resolver: 'api_key_principal', credential: 'key-orphan', reason: 'api' }, async () => { ran = true; }),
    system.withVerifiedWorkspace(app, { resolver: 'share_principal', credential: 'not-a-uuid', reason: 'share-link' }, async () => { ran = true; }),
    system.withVerifiedWorkspace(app, { resolver: 'share_principal', credential: randomUUID(), reason: 'share-link' }, async () => { ran = true; }),
  ];
  const errors = await Promise.all(attempts.map(attempt => attempt.then(() => undefined, (error: unknown) => error)));
  for (const error of errors) assert.ok(refused(error), String(error));
  assert.equal(new Set(errors.map(error => JSON.stringify([(error as Error).name, (error as Error).message]))).size, 1);
  assert.equal(ran, false);
  await root!.query('DELETE FROM api_key WHERE id = $1', [orphan]);
});

test('a cached resolution lasts at most its lifetime, and invalidate drops it at once', { skip }, async () => {
  const revoked = randomUUID(), cached = createSystemScope(tenancy, { cache: { seconds: 60 } }), uncached = createSystemScope(tenancy);
  await root!.query("INSERT INTO api_key(id, workspace_id, key_hash) VALUES ($1, $2, 'key-revoked')", [revoked, fixture.a]);
  const use = (system: typeof cached) => system.withVerifiedWorkspace(app, { resolver: 'api_key_principal', credential: 'key-revoked', reason: 'api' }, async (_tx, access) => access.principal.id);
  assert.equal(await use(cached), revoked);
  // A callback that changes its access object leaves the cached resolution as it was.
  await cached.withVerifiedWorkspace(app, { resolver: 'api_key_principal', credential: 'key-revoked', reason: 'api' }, async (_tx, access) => { access.principal.id = 'changed'; });
  assert.equal(await use(uncached), revoked);
  await root!.query('DELETE FROM api_key WHERE id = $1', [revoked]);
  await assert.rejects(use(uncached), refused, 'without a cache the revocation is immediate');
  assert.equal(await use(cached), revoked, 'within its lifetime the cached resolution still admits');
  cached.invalidate('key-revoked');
  await assert.rejects(use(cached), refused, 'invalidate takes effect at once');
});

test('the boot assertion refuses a resolver of another shape, an unsafe owner role and an undeclared function the owner owns', { skip }, async () => {
  const check = (expected: RegExp) => assert.rejects(tenancy.assertDatabaseRoles(pools[0]!), (error: unknown) => error instanceof DatabaseRoleError && expected.test(error.message), String(expected));
  const changes: [string, string, RegExp][] = [
    [`CREATE FUNCTION public.extra_lookup(t text) RETURNS uuid LANGUAGE sql SECURITY DEFINER AS $$ SELECT NULL::uuid $$; ALTER FUNCTION public.extra_lookup(text) OWNER TO ${roles.resolver}`,
      'DROP FUNCTION public.extra_lookup(text)', /resolver owner \S+ owns undeclared functions public\.extra_lookup\(t text\)/],
    [`GRANT EXECUTE ON FUNCTION workspace_for_token(text) TO PUBLIC`, 'REVOKE EXECUTE ON FUNCTION workspace_for_token(text) FROM PUBLIC', /resolver workspace_for_token is executable by PUBLIC/],
    [`REVOKE EXECUTE ON FUNCTION workspace_for_token(text) FROM ${roles.app}`, `GRANT EXECUTE ON FUNCTION workspace_for_token(text) TO ${roles.app}`, /resolver workspace_for_token is not executable by this role/],
    ['ALTER FUNCTION workspace_for_token(text) SET search_path = public', 'ALTER FUNCTION workspace_for_token(text) SET search_path = pg_catalog, pg_temp', /resolver workspace_for_token does not fix search_path/],
    ['ALTER FUNCTION workspace_for_token(text) SET work_mem = \'4MB\'', 'ALTER FUNCTION workspace_for_token(text) RESET work_mem', /resolver workspace_for_token does not fix search_path/],
    ['ALTER FUNCTION workspace_for_token(text) SECURITY INVOKER', 'ALTER FUNCTION workspace_for_token(text) SECURITY DEFINER', /resolver workspace_for_token is not SECURITY DEFINER/],
    [`ALTER FUNCTION workspace_for_token(text) OWNER TO ${roles.owner}`, `ALTER FUNCTION workspace_for_token(text) OWNER TO ${roles.resolver}`, /resolver workspace_for_token is not owned by/],
    [`CREATE FUNCTION public.workspace_for_token(t uuid) RETURNS uuid LANGUAGE sql AS $$ SELECT NULL::uuid $$`, 'DROP FUNCTION public.workspace_for_token(uuid)', /resolver workspace_for_token is overloaded/],
    [`ALTER FUNCTION share_principal(uuid) RENAME TO share_principal_old`, 'ALTER FUNCTION share_principal_old(uuid) RENAME TO share_principal', /resolver share_principal is missing.*owns undeclared functions public\.share_principal_old/],
    [`ALTER ROLE ${roles.resolver} LOGIN`, `ALTER ROLE ${roles.resolver} NOLOGIN`, /resolver owner \S+ can log in/],
    [`ALTER ROLE ${roles.resolver} NOBYPASSRLS`, `ALTER ROLE ${roles.resolver} BYPASSRLS`, /resolver owner \S+ lacks BYPASSRLS/],
    [`CREATE TABLE resolver_owned (id int); ALTER TABLE resolver_owned OWNER TO ${roles.resolver}`, 'DROP TABLE resolver_owned', /resolver owner \S+ owns resolver_owned/],
    [`GRANT ${roles.resolver} TO ${roles.app}`, `REVOKE ${roles.resolver} FROM ${roles.app}`, /resolver owner \S+ is a role the application role is a member of/],
  ];
  for (const [change, undo, expected] of changes) {
    await root!.query(change);
    try { await check(expected); } finally { await root!.query(undo); }
  }
  // A function of another shape under the declared name: a set-returning one.
  await root!.query(`DROP FUNCTION workspace_for_token(text);
    CREATE FUNCTION public.workspace_for_token(token_hash text) RETURNS SETOF uuid LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT workspace_id::uuid FROM public.contact $$;
    ALTER FUNCTION public.workspace_for_token(text) OWNER TO ${roles.resolver}; REVOKE ALL ON FUNCTION public.workspace_for_token(text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.workspace_for_token(text) TO ${roles.app};`);
  try { await check(/resolver workspace_for_token has another signature or return/); }
  finally { await root!.query(`DROP FUNCTION workspace_for_token(text); ${tenancy.resolverFunctions(roles.app).split('--> statement-breakpoint').slice(0, 4).join('')}`); }
  await tenancy.assertDatabaseRoles(pools[0]!);
});

test('the test-only switch makes a query with no scope set raise, while a scope set on purpose still admits only its workspaces', { skip }, async () => {
  const loud = createTenancy({ setting: 'app.loud_ids', column: 'workspace_id', tables: ['loud'] });
  const loudScope = render(loud.policy('loud_scope').using);
  await root!.query(`CREATE TABLE loud (id serial PRIMARY KEY, workspace_id text NOT NULL); ALTER TABLE loud OWNER TO ${roles.owner};
    CREATE POLICY loud_scope ON loud FOR ALL TO public USING (${loudScope}) WITH CHECK (${loudScope});
    ALTER TABLE loud ENABLE ROW LEVEL SECURITY; ALTER TABLE loud FORCE ROW LEVEL SECURITY; GRANT SELECT, INSERT, UPDATE, DELETE ON loud TO ${roles.app};
    INSERT INTO loud(workspace_id) VALUES ('${fixture.a}'), ('${fixture.b}');`);
  const client = await root!.connect();
  try { await requireScopeForTesting(client, loud); } finally { client.release(); }
  // Connections opened from here read the unscoped default.
  const fresh = await appPool().connect();
  try {
    await assert.rejects(fresh.query('SELECT * FROM loud'), /No tenancy scope is set for app\.loud_ids/);
    await assert.rejects(fresh.query('UPDATE loud SET workspace_id = workspace_id'), /No tenancy scope is set/);
    await assert.rejects(fresh.query('DELETE FROM loud'), /No tenancy scope is set/);
    await fresh.query('BEGIN');
    await setScopeForTesting(fresh, loud, []);
    assert.equal((await fresh.query('SELECT * FROM loud')).rowCount, 0, 'an empty scope set on purpose admits nothing, quietly');
    await setScopeForTesting(fresh, loud, [fixture.b]);
    assert.deepEqual((await fresh.query('SELECT workspace_id FROM loud')).rows, [{ workspace_id: fixture.b }]);
    await fresh.query('COMMIT');
    await assert.rejects(fresh.query('SELECT * FROM loud'), /No tenancy scope is set/, 'after the transaction the scope is missing again');
    // Tables of a tenancy the switch was not run for keep their silent empty result.
    assert.equal((await fresh.query('SELECT * FROM note')).rowCount, 0);
  } finally { await fresh.query('ROLLBACK').catch(() => undefined); fresh.release(); }
  await assert.rejects(loud.assertDatabaseRoles(pools.at(-1)!), /workspace policy is missing, altered or accompanied by another policy on loud/);
});
